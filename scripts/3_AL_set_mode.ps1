# Step 3 - run from the management computer (Windows PowerShell 5.1 or PowerShell 7) as a Domain Admin / GPO creator.
# Chooses what the servers in the target OUs run, by enabling exactly ONE of the two GPO links (the other is disabled first,
# so the two policies are never merged):
#   -Mode Audit    Audit GPO link enabled,   Enforce GPO link disabled    (logs only)
#   -Mode Enforce  Enforce GPO link enabled, Audit GPO link disabled      (BLOCKS what the rules do not allow)
#   -Mode Off      both links disabled                                    (AppLocker rules are removed at the next refresh)
# -Refresh also runs gpupdate (twice) on every server in the target OUs over WinRM; otherwise servers pick it up at their next
# Group Policy refresh (every 5 minutes on domain controllers, 90-120 minutes on member servers) or at boot.
# Already in that mode: nothing changes and there is no prompt. -WhatIf shows the link changes without making them.
# Rolling back from Enforce is the same command with -Mode Audit.
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
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

    # Plan: per OU, disable first, then enable - the two policies are never active together
    $Steps = foreach ($Ou in $Ous) {
        $Pair = @(
            @{ Gpo = $Audit; Name = $Cfg.AuditGpoName; Want = ($Mode -eq 'Audit') },
            @{ Gpo = $Enforce; Name = $Cfg.EnforceGpoName; Want = ($Mode -eq 'Enforce') }
        ) | Sort-Object { [int]$_.Want }
        foreach ($P in $Pair) {
            $State = Get-ALLinkState $P.Gpo.Id $Ou $Domain
            if ($State -eq $P.Want -and $null -ne $State) { Write-Host "'$($P.Name)' on ${Ou}: already enabled = $($P.Want)"; continue }
            [pscustomobject]@{ Ou = $Ou; Name = $P.Name; Want = $P.Want; New = ($null -eq $State) }
        }
    }
    if (-not @($Steps).Count) {
        Write-Host "Mode is already $($Mode.ToUpper()) - no link changes." -ForegroundColor Green
    }
    else {
        $Detail = switch ($Mode) {
            'Audit' { @('AuditOnly: every execution is logged, nothing is blocked.') }
            'Enforce' { @('Programs, scripts and installers that the rules do not allow are BLOCKED for non-admin users and for every non-elevated session.',
                    'Run 5_AL_review_events.ps1 first and be sure the Audit period showed no events you still need (MECM, Nessus, backup, monitoring agents, C:\Admin tools).',
                    "Roll back with: 3_AL_set_mode.ps1 -Mode Audit -Refresh$(if ($SettingsFile) { " -SettingsFile '$SettingsFile'" })") }
            'Off' { @('AppLocker rules are removed from the servers at the next refresh. The STIG item WN25-00-000080 is a finding again.') }
        }
        $Changes = @($Steps | ForEach-Object { "  link '$($_.Name)' on $($_.Ou): $(if ($_.New) { 'create, ' })$(if ($_.Want) { 'ENABLE' } else { 'disable' })" })
        if (-not $WhatIfPreference) {
            Confirm-ALChange -NoConfirm:$NoConfirm -Action "set AppLocker mode to $($Mode.ToUpper()) on the servers in $($Ous -join '; ')" -Detail (@("Servers in scope: $(if ($Targets.Count) { $Targets -join ', ' } else { 'none found' })") + $Changes + $Detail)
            $ConfirmPreference = 'None'
        }
        foreach ($S in $Steps) {
            $Flag = if ($S.Want) { 'Yes' } else { 'No' }
            if (-not $PSCmdlet.ShouldProcess("$($S.Ou)", "$(if ($S.New) { 'link' } else { 'set link' }) '$($S.Name)' enabled = $($S.Want)")) { continue }
            if ($S.New) { New-GPLink -Name $S.Name -Target $S.Ou -LinkEnabled $Flag -Server $Domain.PDC -ErrorAction Stop | Out-Null; Write-Host "linked '$($S.Name)' to $($S.Ou) (enabled: $($S.Want))" }
            else { Set-GPLink -Name $S.Name -Target $S.Ou -LinkEnabled $Flag -Server $Domain.PDC -ErrorAction Stop | Out-Null; Write-Host "'$($S.Name)' on $($S.Ou): enabled = $($S.Want)" }
        }
    }
    if ($Refresh -and -not $WhatIfPreference) {
        if (-not $Targets.Count) { Write-Warning 'No servers found in the target OUs to refresh.' }
        Invoke-ALRefresh $Targets | ForEach-Object { Write-Host $_ }
    }
    if (-not $WhatIfPreference) { Write-Host "Mode is now $($Mode.ToUpper()). Verify with 4_AL_validate.ps1." -ForegroundColor Green }
}
finally { Stop-ALTranscript }
