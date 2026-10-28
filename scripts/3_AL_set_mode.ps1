<#
.SYNOPSIS
    Steps 6 and 8 - switches the servers in the target OUs to Audit, Enforce or Off by enabling exactly one of the two GPO links.

.DESCRIPTION
    Run from the management computer as a Domain Admin (or GPO creator). Exactly ONE of the two GPO links is enabled; the other is
    disabled first, so the two policies are never merged:
      -Mode Audit    Audit GPO link enabled,   Enforce GPO link disabled   (logs only, blocks nothing)
      -Mode Enforce  Enforce GPO link enabled, Audit GPO link disabled     (BLOCKS what the rules do not allow)
      -Mode Off      both links disabled                                   (the AppLocker rules are removed at the next refresh)
    -Refresh then runs gpupdate /target:computer /force twice on every server in the target OUs over WinRM (the rules load on the
    second pass) and records the result for every mode: the full gpupdate output, gpresult /scope computer (which GPOs applied, which
    were filtered out and why, whether the Registry and Security extensions ran without error), Application Identity, the effective
    AppLocker policy and the newest policy event (8001 applied / 8000 conversion failed). The verdict is judged against the mode just
    set (OK / WARN / FAIL table, Logs\3_AL_set_mode-<Mode>-<timestamp>.csv); the raw gpupdate and gpresult output of every server is
    kept in Logs\3_AL_set_mode-<Mode>-<timestamp>-gpresult\. Without -Refresh the servers pick the change up at their next Group Policy
    refresh (every 5 minutes on domain controllers, 90-120 minutes on member servers) or at boot. Already in that mode: no link
    changes and no prompt (the refresh still runs). -WhatIf shows the link changes without making them. Rolling back from Enforce
    is the same command with -Mode Audit.

.PARAMETER Mode
    Audit, Enforce or Off (see above). Required.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER TargetOU
    Distinguished names of the OUs whose links are switched. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER Refresh
    Run gpupdate twice on every server in the target OUs after the links are switched, then gpresult; show and log the results.

.PARAMETER NoConfirm
    Skip the yellow Y/N prompt (automation). A non-interactive session without -NoConfirm stops before any change.

.PARAMETER WhatIf
    Show the link changes without making them (no refresh either).

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: the link change per OU ("enabled = True/False"); with -Refresh, per server, the output of both
    gpupdate passes and a Status / Check / Detail table (gpupdate, GPO applied, GPO processing, AppLocker policy events, Group Policy,
    AppIDSvc, Effective policy) ending in "Refresh (<MODE>): PASSED" or "FAILED"; then "Mode is now AUDIT / ENFORCE / OFF". Files:
    Logs\3_AL_set_mode-<Mode>-<timestamp>.csv (the table), Logs\3_AL_set_mode-<Mode>-<timestamp>-gpresult\<server>-gpresult.txt (the
    raw gpupdate output and the gpresult /r report) and <server>-gpresult.xml (gpresult /x), transcript in
    Logs\3_AL_set_mode-<Mode>-<timestamp>.log. Exit code 1 on a STOP.

.EXAMPLE
    .\3_AL_set_mode.ps1 -Mode Audit -Refresh
    Enables the Audit link, disables the Enforce link, refreshes the servers (asks Y/N).

.EXAMPLE
    .\3_AL_set_mode.ps1 -Mode Enforce -Refresh -NoConfirm
    Switches to Enforce without a prompt (automation) and refreshes the servers.

.EXAMPLE
    .\3_AL_set_mode.ps1 -Mode Audit -Refresh
    Rolls back from Enforce to Audit.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-27
    Version  : 1.1 (-Refresh keeps the gpupdate output and records gpresult, judged against the mode)
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT GroupPolicy and ActiveDirectory modules; link GPOs; WinRM for -Refresh.
    Changes  : domain - the enabled state of the two GPO links on the target OUs. With -Refresh: a gpupdate on the servers.
    Undo     : run again with the previous -Mode.
    README   : section 7, steps 6 and 8; section 13 (rollback).
#>
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
        # Per server: gpupdate twice with its output kept, then gpresult - which AppLocker GPO applied, the Registry and Security
        # extensions, the newest policy event, Application Identity and the effective policy. Table + CSV; raw output in a folder.
        $R = New-ALResults
        $Folder = Join-Path $Cfg.LogDir "$($Cfg.ScriptName)-$($Cfg.Stamp)-gpresult"
        foreach ($C in $Targets) {
            Write-Host "`n$C : gpupdate /target:computer /force (two passes), then gpresult /scope computer ..." -ForegroundColor Cyan
            try { $Raw = Invoke-ALGpRefresh -ComputerName $C -Refresh $true }
            catch { Add-ALResult $R 'FAIL' "Refresh $C" "WinRM: $($_.Exception.Message)"; continue }
            $File = Save-ALGpResult $Raw $Folder
            foreach ($G in @($Raw.Gpupdate)) { Write-Host ('  ' + ($G -replace '\r?\n', "`r`n  ")) }
            $Bad = @($Raw.GpupdateExit | Where-Object { $_ -ne 0 })
            $Said = @($Raw.Gpupdate | ForEach-Object { @(($_ -split '\r?\n') | Select-Object -Skip 1 | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^Updating policy' }) -join ' ' })
            Add-ALResult $R $(if ($Bad.Count) { 'FAIL' } else { 'OK' }) "gpupdate $C" "$(@($Raw.Gpupdate).Count) passes, exit codes $($Raw.GpupdateExit -join ', '): $($Said -join ' | ')"
            $Report = Resolve-ALGpoNames (ConvertFrom-ALGpResult $Raw.GpresultXml $Raw.GpresultText) @{ "$($Audit.Id)" = $Cfg.AuditGpoName; "$($Enforce.Id)" = $Cfg.EnforceGpoName }
            Add-ALGpResults $R $C $Raw $Report $Mode $Cfg.AuditGpoName $Cfg.EnforceGpoName $File
            if ($Mode -eq 'Off') { Add-ALResult $R 'INFO' "AppIDSvc $C" $Raw.AppIdSvc }
            elseif ($Raw.AppIdSvc -eq 'Running/Auto') { Add-ALResult $R 'OK' "AppIDSvc $C" $Raw.AppIdSvc }
            else { Add-ALResult $R 'WARN' "AppIDSvc $C" "$($Raw.AppIdSvc) - expected Running/Auto; run again with -Refresh or reboot, then 4_AL_validate.ps1" }
            $Eff = $null
            try { if ($Raw.EffectiveXml) { $Eff = [xml]$Raw.EffectiveXml } } catch { }
            if ($Mode -eq 'Off') { Add-ALResult $R 'INFO' "Effective policy $C" "$($Raw.Effective) - the rules of the AppLocker GPOs go away with the refresh after both links are disabled (4_AL_validate.ps1 -Mode Off checks)" }
            elseif (-not $Eff) { Add-ALResult $R 'WARN' "Effective policy $C" $Raw.Effective }
            else {
                $Mismatch = @(Get-ALPolicyMismatch $Eff $Mode ([bool]$Cfg.EnableDllRules) ([bool]$Cfg.EnableAppxRules))
                if ($Mismatch.Count) { Add-ALResult $R 'WARN' "Effective policy $C" "not as expected for ${Mode}: $($Mismatch -join '; ') - effective: $($Raw.Effective). Run again with -Refresh or wait for the next refresh; if it stays, 7_AL_diagnose.ps1" }
                else { Add-ALResult $R 'OK' "Effective policy $C" "$($Raw.Effective) - as expected for $Mode" }
            }
        }
        if ($Targets.Count) { [void](Write-ALResults $R $Cfg "Refresh ($($Mode.ToUpper()))"); Write-Host "Raw gpupdate and gpresult output per server: $Folder" }
    }
    elseif (-not $WhatIfPreference) { Write-Host 'No -Refresh: the servers apply the link change at their next Group Policy refresh (every 5 minutes on domain controllers, 90-120 minutes on member servers). Run with -Refresh to run gpupdate now and record gpresult, or 4_AL_validate.ps1 to check.' }
    if (-not $WhatIfPreference) { Write-Host "Mode is now $($Mode.ToUpper()). Verify with 4_AL_validate.ps1." -ForegroundColor Green }
}
finally { Stop-ALTranscript }
