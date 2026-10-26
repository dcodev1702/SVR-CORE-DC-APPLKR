<#
.SYNOPSIS
    Step 5 - creates or updates the Audit and Enforce AppLocker GPOs from the newest build and links both, disabled, to every target OU.

.DESCRIPTION
    Run from the management computer as a Domain Admin (or GPO creator). From the newest build (or -OutputFolder) it prepares two
    deployable rule files and writes them into two GPOs:
      <AuditGpoName>    every collection AuditOnly  - logs what WOULD be blocked, blocks nothing
      <EnforceGpoName>  every collection Enabled    - blocks what the rules do not allow
    Both GPOs carry the rules (Set-AppLockerPolicy -Ldap) and the System Services setting Application Identity = Automatic. The DLL
    collection is switched off unless EnableDllRules is $true. New links are created DISABLED and an existing link keeps its state, so
    nothing reaches a server until 3_AL_set_mode.ps1 enables one link (an ENABLED existing link applies the updated rules at the next
    refresh). Safety: an existing GPO is backed up first (Outputs\<profile>\gpo-backups\<timestamp>, restorable with Restore-GPO), the
    rules are read back from the GPO and compared with the file, and the deployed files are recorded with their SHA-256 in
    <build>\deploy-<timestamp>.json. The AppLocker event logs of the servers in scope are enlarged to EventLogSizesMB.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER OutputFolder
    A build folder (Outputs\<profile>\<timestamp>). Default: the newest build (Outputs\<profile>\latest.txt).

.PARAMETER TargetOU
    Distinguished names of the OUs to link the GPOs to. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER SkipLogSize
    Leave the AppLocker event log sizes on the servers as they are.

.PARAMETER NoConfirm
    Skip the yellow Y/N prompt (automation). A non-interactive session without -NoConfirm stops before any change.

.PARAMETER WhatIf
    Show which build would go into which GPOs, and the link and log-size changes, without changing anything (the *-Deploy.xml files
    are still prepared in the build folder).

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: the build used, per GPO "created" or "backed up, then updated", the rules read back from the GPO,
    the GPO computer version, the links, the event log sizes, and the link states at the end. Files: <build>\*-Deploy.xml,
    <build>\deploy-<timestamp>.json, Outputs\<profile>\gpo-backups\<timestamp>\ for an existing GPO. Transcript in
    Logs\2_AL_create_gpos-<timestamp>.log. Exit code 1 on a STOP.

.EXAMPLE
    .\2_AL_create_gpos.ps1 -WhatIf
    Shows which build would be deployed into which GPOs, without changing anything.

.EXAMPLE
    .\2_AL_create_gpos.ps1
    Deploys the newest build (asks Y/N).

.EXAMPLE
    .\2_AL_create_gpos.ps1 -OutputFolder ..\Outputs\default\20261026-192905 -NoConfirm
    Deploys a specific build without a prompt (automation).

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT GroupPolicy and ActiveDirectory modules and the AppLocker module;
               create/link GPOs and write SYSVOL; WinRM to the servers for the event log sizes.
    Changes  : domain - the two GPOs (rules, System Services, links); servers - AppLocker event log sizes.
    Undo     : Restore-GPO -BackupId <id> -Path Outputs\<profile>\gpo-backups\<timestamp> for an updated GPO; a new GPO is linked disabled.
    README   : section 7, step 5; section 13 (rollback).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$SettingsFile,
    # A build folder (Outputs\<profile>\<timestamp>); default: the newest build
    [string]$OutputFolder,
    [string[]]$TargetOU,
    [switch]$SkipLogSize,
    # Skip the Y/N confirmation (automation); default: ask
    [switch]$NoConfirm
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '2_AL_create_gpos' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory; Import-ALModule AppLocker
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Targets = Get-ALTargetComputers $Ous $Domain

    # Plan (read-only apart from the *-Deploy.xml files written into the build folder)
    $Build = Get-ALBuildFolder $Cfg $OutputFolder
    Write-Host "Build: $Build"
    $Plan = foreach ($Mode in 'Audit', 'Enforce') {
        $Src = Get-ChildItem -LiteralPath $Build -Filter "AppLockerRules-*-$Mode.xml" | Sort-Object Name | Select-Object -Last 1
        if (-not $Src) { throw "STOP: no AppLockerRules-*-$Mode.xml in $Build. Run 1_AL_build_policy.ps1." }
        $Out = Join-Path $Build ($Src.BaseName + '-Deploy.xml')
        $Summary = New-ALDeployXml -SourceXml $Src.FullName -Mode $Mode -DllRules ([bool]$Cfg.EnableDllRules) -OutFile $Out
        $Name = if ($Mode -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }
        [pscustomobject]@{ Mode = $Mode; Gpo = $Name; Existing = (Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue); Xml = $Out; Sha256 = (Get-ALSha256 $Out); Summary = $Summary }
    }
    foreach ($P in $Plan) { Write-Host "$($P.Mode): $($P.Xml)`n  $($P.Summary)`n  GPO '$($P.Gpo)': $(if ($P.Existing) { "exists ($($P.Existing.Id)) - backed up, then updated" } else { 'does not exist - created' })" }

    if (-not $WhatIfPreference) {
        Confirm-ALChange -NoConfirm:$NoConfirm -Action "create/update the AppLocker GPOs '$($Cfg.AuditGpoName)' and '$($Cfg.EnforceGpoName)'" -Detail @(
            "Target OUs: $($Ous -join '; ')",
            "Servers in scope: $(if ($Targets.Count) { $Targets -join ', ' } else { 'none found' })",
            'New links are created DISABLED and existing links keep their state, so nothing new reaches a server until 3_AL_set_mode.ps1.',
            'An ENABLED existing link applies the updated rules to its servers at the next policy refresh.',
            "Undo: an existing GPO is backed up first to $(Join-Path $Cfg.OutRoot "gpo-backups\$($Cfg.Stamp)") (Restore-GPO -BackupId <id> -Path <folder>)."
        )
        $ConfirmPreference = 'None'
    }

    # Client-side extensions: Registry (AppLocker rules) and Security (System Services)
    $Cse = @(
        '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
        '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    )
    # ---- per GPO: back up or create, write the rules and read them back, System Services, GPO version, link disabled where not linked
    $Deployed = New-Object System.Collections.Generic.List[object]
    foreach ($P in $Plan) {
        if (-not $PSCmdlet.ShouldProcess("GPO '$($P.Gpo)'", "write the $($P.Mode) rules ($($P.Summary)) and Application Identity = Automatic; link it DISABLED to $($Ous -join '; ') where not linked")) { continue }
        $Gpo = $P.Existing
        $Backup = $null
        if ($Gpo) {
            $Backup = Backup-ALGpo $Gpo $Cfg $Domain
            Write-Host "GPO exists: $($Gpo.DisplayName) $($Gpo.Id) - backed up (backup ID $($Backup.BackupId)) to $($Backup.Folder); updating"
        }
        else {
            $Gpo = New-GPO -Name $P.Gpo -Server $Domain.PDC -Comment "AaronLocker baseline, $($P.Mode.ToUpper()). Application Identity service = Automatic. Managed by the SVR-CORE-DC-APPLKR scripts." -ErrorAction Stop
            Write-Host "Created GPO $($Gpo.DisplayName) $($Gpo.Id)"
        }
        $Paths = Get-ALGpoPaths $Gpo.Id $Domain
        $Ldap = "LDAP://$($Domain.PDC)/$($Gpo.Path)"

        Set-AppLockerPolicy -XmlPolicy $P.Xml -Ldap $Ldap -ErrorAction Stop
        # Verify from the GPO, not from the file that was written
        $Now = Get-ALPolicySummary ([xml](Get-AppLockerPolicy -Domain -Ldap $Ldap -Xml))
        if ($Now -ne $P.Summary) { throw "STOP: GPO '$($P.Gpo)' was written but reads '$Now' instead of '$($P.Summary)'. $(if ($Backup) { "Restore it from $($Backup.Folder) (backup ID $($Backup.BackupId))" } else { 'It is a new GPO with no links yet' }) or run this script again; the other GPO was not changed by this step." }
        Write-Host "  $($P.Mode) rules written and verified: $Now"

        # System Services (Security CSE): Application Identity = Automatic. A GPP 'Services' item cannot change this protected service.
        $SecDir = Join-Path $Paths.SysvolPdc 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -Path $SecDir -ItemType Directory -Force | Out-Null
        $Inf = "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n[Service General Setting]`r`n`"AppIDSvc`",2,`"`"`r`n"
        [System.IO.File]::WriteAllText((Join-Path $SecDir 'GptTmpl.inf'), $Inf, [System.Text.Encoding]::Unicode)

        $AdObj = Get-ADObject -Identity $Paths.AdPath -Properties gPCMachineExtensionNames -Server $Domain.PDC
        Set-ADObject -Identity $Paths.AdPath -Replace @{ gPCMachineExtensionNames = (Merge-ALExtensionNames ([string]$AdObj.gPCMachineExtensionNames) $Cse) } -Server $Domain.PDC
        $Ver = Step-ALGpoVersion $Paths $Domain
        Write-Host "  GPO computer version now $Ver"

        foreach ($Ou in $Ous) {
            if ($null -eq (Get-ALLinkState $Gpo.Id $Ou $Domain)) {
                New-GPLink -Name $P.Gpo -Target $Ou -LinkEnabled No -Server $Domain.PDC | Out-Null
                Write-Host "  linked to $Ou (DISABLED)"
            }
        }
        $Deployed.Add([ordered]@{ Mode = $P.Mode; Gpo = $P.Gpo; GpoId = "$($Gpo.Id)"; File = (Split-Path -Leaf $P.Xml); Sha256 = $P.Sha256; Rules = $Now; ComputerVersion = $Ver; Backup = $(if ($Backup) { "$($Backup.Folder) (backup ID $($Backup.BackupId))" } else { '' }) })
    }
    if ($Deployed.Count) {
        $Record = Join-Path $Build "deploy-$($Cfg.Stamp).json"
        [ordered]@{ Deployed = (Get-Date).ToString('s'); By = "$env:USERDOMAIN\$env:USERNAME"; From = $env:COMPUTERNAME; Domain = $Domain.DnsRoot; TargetOUs = $Ous; Gpos = $Deployed } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Record -Encoding UTF8
        Write-Host "Deployment record (files + SHA-256): $Record"
    }

    # ---- AppLocker event log sizes on the servers in scope (the 1 MB default wraps in minutes)
    if (-not $SkipLogSize) {
        $Servers = @(@($Cfg.ReferenceServer) + $Targets | Where-Object { $_ } | Sort-Object -Unique)
        if ($Servers.Count -and $PSCmdlet.ShouldProcess("$($Servers.Count) server(s)", 'set the AppLocker event log sizes')) {
            Write-Host "AppLocker event log sizes on: $($Servers -join ', ')"
            Set-ALEventLogSize $Servers $Cfg.EventLogSizesMB | ForEach-Object { Write-Host "  $_" }
        }
    }

    Write-Host "`nLinks now:"
    foreach ($Ou in $Ous) {
        foreach ($P in $Plan) {
            $G = Get-GPO -Name $P.Gpo -Server $Domain.PDC -ErrorAction SilentlyContinue
            $S = if ($G) { Get-ALLinkState $G.Id $Ou $Domain } else { $null }
            Write-Host ('  {0,-8} {1,-10} {2}' -f $P.Mode, $(if ($null -eq $S) { 'not linked' } elseif ($S) { 'ENABLED' } else { 'disabled' }), $Ou)
        }
    }
    Write-Host 'Next: 3_AL_set_mode.ps1 -Mode Audit -Refresh' -ForegroundColor Green
}
finally { Stop-ALTranscript }
