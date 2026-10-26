# Step 3 - run from the management computer (Windows PowerShell 5.1) as a Domain Admin / GPO creator.
# Chooses what the servers in the target OUs run, by enabling exactly ONE of the two GPO links (the other is disabled first,
# so the two policies are never merged):
#   -Mode Audit    Audit GPO link enabled,   Enforce GPO link disabled    (logs only)
#   -Mode Enforce  Enforce GPO link enabled, Audit GPO link disabled      (BLOCKS what the rules do not allow)
#   -Mode Off      both links disabled                                    (AppLocker rules are removed at the next refresh)
# -Refresh also runs gpupdate (twice) on every server in the target OUs over WinRM; otherwise servers pick it up at their next
# Group Policy refresh (every 90-120 minutes on member servers, 5 minutes on domain controllers) or at boot.
# Rolling back from Enforce is the same command with -Mode Audit.
param(
    [Parameter(Mandatory)][ValidateSet('Audit', 'Enforce', 'Off')][string]$Mode,
    [string]$SettingsFile,
    [string[]]$TargetOU,
    [switch]$Refresh,
    [switch]$NoConfirm
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName "3_AL_set_mode-$Mode" -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Targets = Get-ALTargetComputers $Ous $Domain
    $Audit = Get-GPO -Name $Cfg.AuditGpoName -Server $Domain.PDC -ErrorAction SilentlyContinue
    $Enforce = Get-GPO -Name $Cfg.EnforceGpoName -Server $Domain.PDC -ErrorAction SilentlyContinue
    if (-not $Audit -or -not $Enforce) { throw 'STOP: the Audit and/or Enforce GPO does not exist. Run 2_AL_create_gpos.ps1 first.' }

    $Detail = switch ($Mode) {
        'Audit' { @('AuditOnly: every execution is logged, nothing is blocked.') }
        'Enforce' { @('Programs, scripts and installers that the rules do not allow are BLOCKED for non-admin users and for services running as non-admin accounts.',
                'Run 5_AL_review_events.ps1 first and be sure the Audit period showed no events you still need (MECM, backup, monitoring agents).',
                "Roll back with: 3_AL_set_mode.ps1 -Mode Audit -Refresh$(if ($SettingsFile) { " -SettingsFile '$SettingsFile'" })") }
        'Off' { @('AppLocker rules are removed from the servers at the next refresh. The STIG item WN25-00-000080 is a finding again.') }
    }
    Confirm-ALChange -NoConfirm:$NoConfirm -Action "set AppLocker mode to $($Mode.ToUpper()) on the servers in $($Ous -join '; ')" -Detail (@("Servers in scope: $(if ($Targets.Count) { $Targets -join ', ' } else { 'none found' })") + $Detail)

    foreach ($Ou in $Ous) {
        # Disable first, then enable: the two policies are never active together
        $Plan = @(
            @{ Gpo = $Audit; Name = $Cfg.AuditGpoName; Want = ($Mode -eq 'Audit') },
            @{ Gpo = $Enforce; Name = $Cfg.EnforceGpoName; Want = ($Mode -eq 'Enforce') }
        ) | Sort-Object { [int]$_.Want }
        foreach ($P in $Plan) {
            $State = Get-ALLinkState $P.Gpo.Id $Ou $Domain
            $Flag = if ($P.Want) { 'Yes' } else { 'No' }
            if ($null -eq $State) { New-GPLink -Name $P.Name -Target $Ou -LinkEnabled $Flag -Server $Domain.PDC | Out-Null; Write-Host "linked '$($P.Name)' to $Ou (enabled: $($P.Want))" }
            elseif ($State -ne $P.Want) { Set-GPLink -Name $P.Name -Target $Ou -LinkEnabled $Flag -Server $Domain.PDC | Out-Null; Write-Host "'$($P.Name)' on ${Ou}: enabled = $($P.Want)" }
            else { Write-Host "'$($P.Name)' on ${Ou}: already enabled = $($P.Want)" }
        }
    }
    if ($Refresh) {
        if (-not $Targets.Count) { Write-Warning 'No servers found in the target OUs to refresh.' }
        Invoke-ALRefresh $Targets | ForEach-Object { Write-Host $_ }
    }
    Write-Host "Mode is now $($Mode.ToUpper()). Verify with 4_AL_validate.ps1." -ForegroundColor Green
}
finally { Stop-ALTranscript }
