<#
.SYNOPSIS
    Removes this toolkit's AppLocker deployment: backs up, unlinks and deletes the Audit and Enforce GPOs, then resets what they and
    the toolkit left on the servers - the AppLocker policy, Application Identity, the AppLocker log sizes, the permissions of the
    SecureFolders entries (C:\Admin) and leftover build folders.

.DESCRIPTION
    Run from the management computer as a Domain Admin, or on a DC itself (SERVER-2022.md, "Before you start"). It surveys first
    (read-only), shows the plan in yellow and asks Y/N; -WhatIf shows the plan and changes nothing.
    Domain:
      - the two GPOs named in the settings (AuditGpoName, EnforceGpoName): each is backed up (Backup-GPO, to
        Outputs\<profile>\gpo-backups\<timestamp>), unlinked from every OU, domain or site whose gPLink names it - not only the target
        OUs - and deleted (-KeepGpos: unlinked only)
    Every server in scope (ReferenceServer + the target OUs, or -ComputerName), over WinRM or in-process on this computer:
      - gpupdate /target:computer /force, so the rules the deleted GPOs delivered leave the registry and the effective policy
      - with -ClearLogs: every AppLocker log exported (.evtx + message resources) and cleared; always: the AppLocker log sizes set back
        to the Windows default (1052672 bytes) that 2_AL_create_gpos.ps1 raised
      - Application Identity back to the Windows default, Manual, and stopped. Group Policy's security extension normally restores
        Manual itself during the refresh once the GPO's System Services setting is gone (seen in the lab: event 7040 "changed from auto
        start to demand start"); otherwise sc.exe sets it, and where the protected service refuses that, the registry (effective at
        the next restart)
      - the SecureFolders entries (C:\Admin) set back to permissions inherited from their parent (icacls /reset /T): the explicit
        SYSTEM + Administrators permissions that 0_AL_secure_folders.ps1 sets are removed. The folders and their files stay
        (-KeepFolderPermissions: not touched)
      - leftover build folders C:\AaronLocker and C:\AaronLocker-<n> (the build normally deletes them)
    Then it verifies: the GPOs gone, no link left, no rule of the deleted GPOs effective on any server, the folders inherited. A local
    AppLocker policy (for example MECM's managed installer) is reported, never removed. Running it again is safe: what is done is
    skipped. With several DCs, a DC that has not received the deletion yet (replication) still shows the rules: run again later.
    Not touched: the toolkit folder, Logs and Outputs, firewall rules, any other GPO.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER TargetOU
    Distinguished names of the OUs whose servers are reset. Overrides the TargetOUs setting. Default: the Domain Controllers OU. The
    GPO links are searched domain-wide regardless.

.PARAMETER ComputerName
    Servers to reset. Default: the reference server plus every Windows Server computer in the target OUs.

.PARAMETER KeepGpos
    Unlink the two GPOs but do not delete them.

.PARAMETER ClearLogs
    Export every AppLocker log (.evtx with its message resources) and clear it. The export goes to Outputs\<profile>\reset-<timestamp>\
    for this computer and to %SystemRoot%\Temp\AL-reset-<timestamp>\ on a remote server.

.PARAMETER KeepFolderPermissions
    Leave the permissions of the SecureFolders entries as they are.

.PARAMETER NoConfirm
    Skip the yellow Y/N prompt (automation, remote sessions). A non-interactive session without -NoConfirm stops before any change.

.PARAMETER WhatIf
    Survey and show the plan without changing anything.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: the survey, the plan, then a Status / Check / Detail table and "Reset: PASSED" or "FAILED". The same
    rows as CSV in Logs\8_AL_reset-<timestamp>.csv; transcript in Logs\8_AL_reset-<timestamp>.log; GPO backups in
    Outputs\<profile>\gpo-backups\<timestamp>\. Exit code 1 on any FAIL.

.EXAMPLE
    .\8_AL_reset.ps1 -WhatIf
    Shows what would be removed and reset, changes nothing.

.EXAMPLE
    .\8_AL_reset.ps1 -ClearLogs
    Removes the deployment, exports and clears the AppLocker logs (asks Y/N).

.EXAMPLE
    .\8_AL_reset.ps1 -KeepGpos -KeepFolderPermissions -NoConfirm
    Only unlinks the GPOs and resets the servers' AppLocker state; keeps the GPOs and C:\Admin's permissions.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-28
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT GroupPolicy and ActiveDirectory modules and the AppLocker module; delete
               and link GPOs; WinRM administrator on the servers (or run on the server itself).
    Changes  : domain - the two GPOs (backed up, unlinked, deleted); servers - Group Policy refresh, AppLocker log sizes (and contents
               with -ClearLogs), Application Identity start type, SecureFolders permissions, leftover build folders.
    Undo     : Restore-GPO -BackupId <id> -Path Outputs\<profile>\gpo-backups\<timestamp> (or build and deploy again: 1_ and 2_), link
               with 3_AL_set_mode.ps1; 0_AL_secure_folders.ps1 -Fix for C:\Admin.
    README   : section 13 (rollback).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$SettingsFile,
    [string[]]$TargetOU,
    [string[]]$ComputerName,
    [switch]$KeepGpos,
    [switch]$ClearLogs,
    [switch]$KeepFolderPermissions,
    [switch]$NoConfirm
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '8_AL_reset' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
$R = New-ALResults
$Failed = 1
# The Windows default size of the AppLocker channels (1 MB + 4 KB); 2_AL_create_gpos.ps1 raises them to EventLogSizesMB
$DefaultLogBytes = [int64]1052672

# Runs on a server: what there is to reset (read-only)
$Survey = {
    param([string[]]$Folders)
    $WhatIfPreference = $false   # read-only; keeps -WhatIf from reporting module loads as changes
    $o = [ordered]@{ Computer = $env:COMPUTERNAME }
    $Srp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    $o.GpoRules = 0
    if (Test-Path -LiteralPath $Srp) { $o.GpoRules = [int](@(Get-ChildItem -LiteralPath $Srp -ErrorAction SilentlyContinue | ForEach-Object { $_.SubKeyCount }) | Measure-Object -Sum).Sum }
    $o.Effective = ''; $o.LocalRules = 0
    try {
        [xml]$Eff = Get-AppLockerPolicy -Effective -Xml
        $o.Effective = (@($Eff.AppLockerPolicy.RuleCollection | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count))" }) -join ', ')
        [xml]$Loc = Get-AppLockerPolicy -Local -Xml
        $o.LocalRules = @($Loc.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
    }
    catch { $o.Effective = "could not be read: $($_.Exception.Message)" }
    if (-not $o.Effective) { $o.Effective = 'empty' }
    $Svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $o.AppId = "$($Svc.State)/$($Svc.StartMode)"
    $o.Logs = @(Get-WinEvent -ListLog 'Microsoft-Windows-AppLocker/*' -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Log = ($_.LogName -replace '^.*/', ''); Records = [int64]$_.RecordCount; MaxBytes = [int64]$_.MaximumSizeInBytes } })
    $o.Folders = @(foreach ($F in $Folders) {
            if (Test-Path -LiteralPath $F -PathType Container) {
                $A = Get-Acl -LiteralPath $F
                $Children = @(Get-ChildItem -LiteralPath $F -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { @((Get-Acl -LiteralPath $_.FullName).Access | Where-Object { -not $_.IsInherited }).Count })
                [pscustomobject]@{ Path = $F; Exists = $true; Protected = [bool]$A.AreAccessRulesProtected; Explicit = @($A.Access | Where-Object { -not $_.IsInherited }).Count; ChildrenExplicit = $Children.Count; Sddl = $A.Sddl }
            }
            else { [pscustomobject]@{ Path = $F; Exists = $false; Protected = $false; Explicit = 0; ChildrenExplicit = 0; Sddl = '' } }
        })
    $o.WorkFolders = @(Get-ChildItem -LiteralPath "$env:SystemDrive\" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^AaronLocker(-\d+)?$' } | ForEach-Object { $_.FullName })
    [pscustomobject]$o
}

# Runs on a server after the GPOs are gone: refresh, logs, Application Identity, folder permissions, build folders, verification.
# Returns Status / Check / Detail rows.
$Cleanup = {
    param([bool]$ClearLogs, [string]$ExportDir, [string[]]$ResetFolders, [string[]]$OurIds, [int64]$LogBytes)
    $Rows = New-Object System.Collections.Generic.List[object]
    # 1. Group Policy refresh: the rules of the deleted GPOs leave the registry (SrpV2) and the effective policy
    $Text = (& "$env:windir\System32\gpupdate.exe" /target:computer /force 2>&1 | Out-String)
    $Exit = $LASTEXITCODE
    $Said = @($Text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^Updating policy' }) -join ' '
    $Rows.Add([pscustomobject]@{ Status = $(if ($Exit) { 'WARN' } else { 'OK' }); Check = 'gpupdate'; Detail = "exit code ${Exit}: $Said" })
    # 2. AppLocker logs: export and clear (-ClearLogs), size back to the Windows default
    $Dir = [Environment]::ExpandEnvironmentVariables($ExportDir)
    foreach ($L in @(Get-WinEvent -ListLog 'Microsoft-Windows-AppLocker/*' -ErrorAction SilentlyContinue)) {
        $Short = $L.LogName -replace '^.*/', ''
        $Notes = @()
        $Status = 'OK'
        if ($ClearLogs) {
            New-Item -Path $Dir -ItemType Directory -Force | Out-Null
            $File = Join-Path $Dir ("$env:COMPUTERNAME-AppLocker-" + ($Short -replace '[^A-Za-z0-9]+', '-') + '.evtx')
            & wevtutil.exe epl $L.LogName $File /ow:true 2>&1 | Out-Null
            $E1 = $LASTEXITCODE
            if ($E1 -eq 0) {
                & wevtutil.exe al $File /l:en-US 2>&1 | Out-Null
                & wevtutil.exe cl $L.LogName 2>&1 | Out-Null
                if ($LASTEXITCODE) { $Status = 'FAIL'; $Notes += "exported to $File but NOT cleared (wevtutil exit $LASTEXITCODE)" } else { $Notes += "$($L.RecordCount) event(s) exported to $File, then cleared" }
            }
            else { $Status = 'FAIL'; $Notes += "export FAILED (wevtutil exit $E1) - not cleared" }
        }
        if ([int64]$L.MaximumSizeInBytes -ne $LogBytes) {
            & wevtutil.exe sl $L.LogName /ms:$LogBytes 2>&1 | Out-Null
            $Now = [int64](Get-WinEvent -ListLog $L.LogName).MaximumSizeInBytes
            if ($Now -eq $LogBytes) { $Notes += "size $([int64]$L.MaximumSizeInBytes) -> $LogBytes bytes (Windows default)" }
            else { if ($Status -eq 'OK') { $Status = 'WARN' }; $Notes += "size still $Now bytes (wanted $LogBytes; a log larger than the new size keeps its size until it is cleared - use -ClearLogs)" }
        }
        else { $Notes += "size already $LogBytes bytes (Windows default)" }
        $Rows.Add([pscustomobject]@{ Status = $Status; Check = "Log $Short"; Detail = ($Notes -join '; ') })
    }
    # 3. Application Identity back to the Windows default (Manual, stopped). Group Policy's security extension usually restores Manual
    # during the refresh above, once the GPO's System Services setting is gone. If not: sc.exe, and where the protected service refuses
    # (it does when stopped, even for a change to the value it has), the registry, which the Service Control Manager reads at boot.
    $Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc'
    $Before = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $How = ''
    if ($Before.StartMode -eq 'Manual') { $How = 'Manual already (Group Policy restored it when the GPO setting went away)' }
    else {
        $ScOut = (& sc.exe config AppIDSvc start= demand 2>&1 | Out-String).Trim() -replace '\s+', ' '
        if ($LASTEXITCODE -eq 0) { $How = 'set to Manual with sc.exe' }
        else {
            try { Set-ItemProperty -LiteralPath $Key -Name Start -Value 3 -ErrorAction Stop; $How = "sc.exe refused ($ScOut); start type 3 (Manual) written to the registry - effective at the next restart" }
            catch { $How = "sc.exe refused ($ScOut) and the registry could not be written ($($_.Exception.Message))" }
        }
    }
    if ((Get-Service -Name AppIDSvc).Status -ne 'Stopped') {
        & sc.exe stop AppIDSvc 2>&1 | Out-Null
        for ($I = 0; $I -lt 20 -and (Get-Service -Name AppIDSvc).Status -ne 'Stopped'; $I++) { Start-Sleep -Seconds 1 }
        if ((Get-Service -Name AppIDSvc).Status -ne 'Stopped') { $How += '; still running now - with start type Manual it stays stopped after the next restart' }
    }
    $After = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $RegStart = [int](Get-ItemProperty -LiteralPath $Key).Start
    $Ok = ($After.StartMode -eq 'Manual' -or $RegStart -eq 3)
    $Rows.Add([pscustomobject]@{ Status = $(if ($Ok) { 'OK' } else { 'FAIL' }); Check = 'Application Identity'; Detail = "$($Before.State)/$($Before.StartMode) -> $($After.State)/$($After.StartMode) (registry Start=$RegStart): $How" })
    # 4. SecureFolders entries: permissions inherited from the parent again (explicit permissions removed); the content stays
    foreach ($F in @($ResetFolders | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $F -PathType Container)) { $Rows.Add([pscustomobject]@{ Status = 'INFO'; Check = "Folder $F"; Detail = 'does not exist - nothing to reset' }); continue }
        $Sddl = (Get-Acl -LiteralPath $F).Sddl
        $Out = (& icacls.exe $F /reset /T /C /Q 2>&1 | Out-String).Trim()
        $IcaclsExit = $LASTEXITCODE
        $A = Get-Acl -LiteralPath $F
        $Left = @(@($F) + @(Get-ChildItem -LiteralPath $F -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) | Where-Object { @((Get-Acl -LiteralPath $_).Access | Where-Object { -not $_.IsInherited }).Count })
        $Ok = ($IcaclsExit -eq 0 -and -not $A.AreAccessRulesProtected -and -not $Left.Count)
        $Rows.Add([pscustomobject]@{ Status = $(if ($Ok) { 'OK' } else { 'FAIL' }); Check = "Folder $F"; Detail = "permissions inherited from the parent again (icacls /reset /T: $Out)$(if ($Left.Count) { "; still explicit: $($Left -join ', ')" }). Before: $Sddl | now: $($A.Sddl)" })
    }
    # 5. Leftover build folders (the build deletes them; a build that was interrupted may not have)
    foreach ($W in @(Get-ChildItem -LiteralPath "$env:SystemDrive\" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^AaronLocker(-\d+)?$' })) {
        if ((Get-Location).Path.StartsWith($W.FullName, [StringComparison]::OrdinalIgnoreCase)) { Set-Location -LiteralPath $env:SystemRoot }
        try { Remove-Item -LiteralPath $W.FullName -Recurse -Force -ErrorAction Stop; $Rows.Add([pscustomobject]@{ Status = 'OK'; Check = 'Build folder'; Detail = "removed $($W.FullName)" }) }
        catch { $Rows.Add([pscustomobject]@{ Status = 'WARN'; Check = 'Build folder'; Detail = "$($W.FullName) could not be removed: $($_.Exception.Message)" }) }
    }
    # 6. Verify: no rule of the deleted GPOs in the registry or the effective policy
    $Srp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
    $RegRules = 0
    if (Test-Path -LiteralPath $Srp) { $RegRules = [int](@(Get-ChildItem -LiteralPath $Srp -ErrorAction SilentlyContinue | ForEach-Object { $_.SubKeyCount }) | Measure-Object -Sum).Sum }
    $Ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($Id in @($OurIds | Where-Object { $_ })) { [void]$Ids.Add($Id) }
    try {
        [xml]$Eff = Get-AppLockerPolicy -Effective -Xml
        $Effective = (@($Eff.AppLockerPolicy.RuleCollection | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count))" }) -join ', ')
        $LeftRules = @($Eff.SelectNodes('//*[@Id]') | Where-Object { $Ids.Contains($_.GetAttribute('Id')) }).Count
        [xml]$Loc = Get-AppLockerPolicy -Local -Xml
        $LocalRules = @($Loc.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
        if (-not $Effective) { $Effective = 'empty' }
        $Status = if ($LeftRules) { 'WARN' } else { 'OK' }
        $Detail = if ($LeftRules) { "$LeftRules rule(s) of the deleted GPOs still effective ($Effective; $RegRules in the registry) - this server has not received the deletion yet (replication): run 8_AL_reset.ps1 again later" }
        else { "no rule of the deleted GPOs effective; effective policy: $Effective; Group Policy rules in the registry: $RegRules$(if ($LocalRules) { "; the LOCAL AppLocker policy has $LocalRules rule(s) - not removed (MECM managed installer or set by hand)" })" }
        $Rows.Add([pscustomobject]@{ Status = $Status; Check = 'AppLocker policy'; Detail = $Detail })
    }
    catch { $Rows.Add([pscustomobject]@{ Status = 'WARN'; Check = 'AppLocker policy'; Detail = "could not be read: $($_.Exception.Message)" }) }
    $Rows.ToArray()
}

try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory; Import-ALModule AppLocker
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    if (-not $ComputerName) { $ComputerName = @(@($Cfg.ReferenceServer) + @(Get-ALTargetComputers $Ous $Domain) | Where-Object { $_ } | Sort-Object -Unique) }
    $Folders = @($Cfg.SecureFolders | Where-Object { $_ })

    # ---- survey (read-only): the GPOs, every link, their rule IDs; then each server
    $Gpos = @(foreach ($Name in $Cfg.AuditGpoName, $Cfg.EnforceGpoName) {
            $G = Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue
            if (-not $G) { Add-ALResult $R 'INFO' "GPO $Name" 'does not exist - nothing to remove'; continue }
            $Links = @(Get-ALGpoLinkTargets $G.Id $Domain)
            $Ids = @()
            try { [xml]$X = Get-AppLockerPolicy -Domain -Ldap "LDAP://$($Domain.PDC)/$($G.Path)" -Xml -ErrorAction Stop; $Ids = @($X.SelectNodes('//*[@Id]') | ForEach-Object { $_.GetAttribute('Id') }) } catch { }
            Add-ALResult $R 'INFO' "GPO $Name" "{$("$($G.Id)".ToUpper())}, computer version $($G.Computer.DSVersion), $($Ids.Count) AppLocker rule(s); linked to: $(if ($Links.Count) { ($Links | ForEach-Object { "$($_.Target) ($(if ($_.Enabled) { 'enabled' } else { 'disabled' }))" }) -join '; ' } else { 'nothing' })"
            [pscustomobject]@{ Name = $Name; Gpo = $G; Links = $Links; Ids = $Ids }
        })
    $OurIds = @($Gpos | ForEach-Object { $_.Ids } | Select-Object -Unique)
    $Servers = @(foreach ($C in $ComputerName) {
            try { $S = Invoke-ALOn $C $Survey (, [string[]]$Folders) }
            catch { Add-ALResult $R 'FAIL' "WinRM $C" $_.Exception.Message; continue }
            $FolderText = @($S.Folders | ForEach-Object { if (-not $_.Exists) { "$($_.Path) missing" } elseif ($_.Protected -or $_.Explicit -or $_.ChildrenExplicit) { "$($_.Path) has explicit permissions$(if ($_.Protected) { ', inheritance removed' })$(if ($_.ChildrenExplicit) { ", $($_.ChildrenExplicit) item(s) inside with their own" })" } else { "$($_.Path) inherited already" } }) -join '; '
            $LogText = @($S.Logs | ForEach-Object { "$($_.Log) $($_.Records) events / $($_.MaxBytes) bytes" }) -join ', '
            Add-ALResult $R 'INFO' "Server $C" "effective AppLocker policy: $($S.Effective); Group Policy rules in the registry: $($S.GpoRules); local policy rules: $($S.LocalRules); Application Identity $($S.AppId); logs: $LogText; $(if ($FolderText) { $FolderText } else { 'no SecureFolders' }); build folders: $(if ($S.WorkFolders.Count) { $S.WorkFolders -join ', ' } else { 'none' })"
            [pscustomobject]@{ Computer = $C; Survey = $S }
        })

    # ---- plan
    $Plan = New-Object System.Collections.Generic.List[string]
    foreach ($P in $Gpos) { $Plan.Add("GPO '$($P.Name)': back up, unlink from $(if ($P.Links.Count) { ($P.Links | ForEach-Object { $_.Target }) -join '; ' } else { '(no link)' })$(if ($KeepGpos) { ', KEEP the GPO' } else { ', DELETE the GPO' })") }
    foreach ($S in $Servers) { $Plan.Add("$($S.Computer): gpupdate; AppLocker logs $(if ($ClearLogs) { 'exported and CLEARED, ' })size $DefaultLogBytes bytes; Application Identity Manual + stopped; $(if ($KeepFolderPermissions -or -not $Folders.Count) { 'folder permissions kept' } else { "permissions of $($Folders -join ', ') inherited from the parent again (explicit SYSTEM + Administrators permissions removed)" }); leftover C:\AaronLocker* removed") }
    Write-Host "`nPlan:"; $Plan | ForEach-Object { Write-Host "  $_" }

    if ($WhatIfPreference) { Add-ALResult $R 'INFO' 'WhatIf' 'nothing was changed' }
    else {
        Confirm-ALChange -NoConfirm:$NoConfirm -Action 'remove the AppLocker GPOs and reset AppLocker on the servers' -Detail (@($Plan) + @(
                'Every server stops applying the AppLocker rules: nothing is audited or enforced any more. The STIG item becomes a finding (Open).',
                "Undo: the GPOs are backed up first to $(Join-Path $Cfg.OutRoot "gpo-backups\$($Cfg.Stamp)") (Restore-GPO -BackupId <id> -Path <folder>), or deploy again with 1_ and 2_; C:\Admin: 0_AL_secure_folders.ps1 -Fix."))
        $ConfirmPreference = 'None'

        # ---- domain: back up, unlink, delete
        foreach ($P in $Gpos) {
            if (-not $PSCmdlet.ShouldProcess("GPO '$($P.Name)'", 'back up, unlink and delete')) { continue }
            try {
                $B = Backup-ALGpo $P.Gpo $Cfg $Domain
                Add-ALResult $R 'OK' "Backup $($P.Name)" "backup ID $($B.BackupId) in $($B.Folder)"
                foreach ($L in $P.Links) { Remove-GPLink -Guid $P.Gpo.Id -Target $L.Target -Server $Domain.PDC -ErrorAction Stop | Out-Null; Add-ALResult $R 'OK' "Unlink $($P.Name)" "removed from $($L.Target)" }
                if (-not $KeepGpos) { Remove-GPO -Guid $P.Gpo.Id -Server $Domain.PDC -Confirm:$false -ErrorAction Stop; Add-ALResult $R 'OK' "Delete $($P.Name)" "GPO {$("$($P.Gpo.Id)".ToUpper())} deleted" }
            }
            catch { Add-ALResult $R 'FAIL' "GPO $($P.Name)" $_.Exception.Message }
        }
        # Verify the domain side from AD, not from what was done
        foreach ($P in $Gpos) {
            $Still = Get-GPO -Guid $P.Gpo.Id -Server $Domain.PDC -ErrorAction SilentlyContinue
            $Linked = @(Get-ALGpoLinkTargets $P.Gpo.Id $Domain)
            if ($Linked.Count) { Add-ALResult $R 'FAIL' "Verify $($P.Name)" "still linked to $(($Linked | ForEach-Object { $_.Target }) -join '; ')" }
            elseif ($Still -and -not $KeepGpos) { Add-ALResult $R 'FAIL' "Verify $($P.Name)" 'the GPO still exists' }
            else { Add-ALResult $R 'OK' "Verify $($P.Name)" "$(if ($Still) { 'kept, ' } else { 'deleted, ' })linked nowhere" }
        }

        # ---- servers
        foreach ($S in $Servers) {
            $C = $S.Computer
            if (-not $PSCmdlet.ShouldProcess($C, 'reset AppLocker')) { continue }
            $Export = if (Test-ALLocalComputer $C) { Join-Path $Cfg.OutRoot "reset-$($Cfg.Stamp)\$($S.Survey.Computer)" } else { "%SystemRoot%\Temp\AL-reset-$($Cfg.Stamp)" }
            $Reset = if ($KeepFolderPermissions) { @() } else { $Folders }
            try { foreach ($Row in @(Invoke-ALOn $C $Cleanup ([bool]$ClearLogs, $Export, [string[]]$Reset, [string[]]$OurIds, $DefaultLogBytes))) { Add-ALResult $R $Row.Status "$($Row.Check) $C" $Row.Detail } }
            catch { Add-ALResult $R 'FAIL' "Reset $C" $_.Exception.Message }
        }
        Write-Host "`nTo deploy again: 0_AL_secure_folders.ps1 (C:\Admin), 1_AL_build_policy.ps1, 2_AL_create_gpos.ps1, 3_AL_set_mode.ps1 -Mode Audit -Refresh." -ForegroundColor Cyan
    }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R $Cfg 'Reset'
    Write-Host "Transcript: $($Cfg.Transcript)"
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
