<#
.SYNOPSIS
    Step 3 - creates a missing SecureFolders entry (default C:\Admin) administrators-only on every server in scope; reports a writable one.

.DESCRIPTION
    The only script in this toolkit that sets permissions. Run from the management computer as a Domain Admin, before the build.
    For each SecureFolders entry, on the reference server and every server in the target OUs (or -ComputerName):
      missing folder                     -> created: SYSTEM + Administrators full control only, inheritance removed
      existing, administrators-only      -> left alone
      existing, writable by a non-admin  -> only REPORTED; its permissions are replaced only with -Fix
    Why: the policy allows everything under C:\Admin\* for every account, and any user may create a folder directly under C:\ (and owns
    what they create there). Until an administrator creates C:\Admin with locked-down permissions, a user could create it first and
    plant code in it. Nothing outside SecureFolders is ever touched (not C:\Temp, not C:\Sysmon); system folders are refused by the
    settings check. The servers are surveyed read-only first: when nothing has to change there is no prompt. Before -Fix replaces
    permissions, the previous ones are printed as SDDL and kept in the transcript so they can be restored. -WhatIf shows the plan
    without changing anything. Every change is verified from the server afterwards.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER ComputerName
    Servers to handle. Default: the reference server plus every Windows Server computer in the target OUs.

.PARAMETER Folder
    Folders to handle. Overrides the SecureFolders setting (local folders such as C:\Admin; a system folder is refused).

.PARAMETER Fix
    Also REPLACE the permissions of an existing folder that a non-admin can change. Without -Fix such a folder is only reported.

.PARAMETER NoConfirm
    Skip the yellow Y/N prompt (automation). A non-interactive session without -NoConfirm stops before any change.

.PARAMETER WhatIf
    Survey only: show what would be created or replaced without changing anything.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: per server and folder "missing - will be created", "WRITABLE by non-admins" or "administrators-only
    - OK", then the result of every change as read back from the server ("created; verified SYSTEM + Administrators only").
    Transcript: Logs\0_AL_secure_folders-<timestamp>.log.

.EXAMPLE
    .\0_AL_secure_folders.ps1 -WhatIf
    Survey only: what would be created, what is writable.

.EXAMPLE
    .\0_AL_secure_folders.ps1
    Creates a missing C:\Admin administrators-only on every server in scope (asks Y/N).

.EXAMPLE
    .\0_AL_secure_folders.ps1 -Fix -NoConfirm
    Also replaces the permissions of an existing writable folder, without a prompt (the previous SDDL is printed first).

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT ActiveDirectory module; WinRM administrator on the servers.
    Changes  : only the SecureFolders entries on the servers in scope - a missing folder, or with -Fix an existing one.
    Undo     : delete a created folder; restore a replaced ACL from the SDDL printed before the change.
    README   : section 7, step 3 (C:\Admin).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$SettingsFile,
    [string[]]$ComputerName,
    [string[]]$Folder,
    [switch]$Fix,
    [switch]$NoConfirm
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_secure_folders' -SettingsFile $SettingsFile -Overrides @{ SecureFolders = $Folder }
$Apply = {
    param([string[]]$Create, [string[]]$Repair)
    $Sys = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
    $Adm = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    foreach ($Path in @($Create) + @($Repair)) {
        if (-not $Path) { continue }
        if ($Create -contains $Path) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
        else { "$env:COMPUTERNAME $Path : previous permissions (SDDL, to restore: `$a = Get-Acl '$Path'; `$a.SetSecurityDescriptorSddlForm('<SDDL>'); Set-Acl '$Path' `$a): $((Get-Acl -LiteralPath $Path).Sddl)" }
        $Acl = New-Object System.Security.AccessControl.DirectorySecurity
        $Acl.SetAccessRuleProtection($true, $false)
        foreach ($Sid in $Sys, $Adm) { $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))) }
        Set-Acl -LiteralPath $Path -AclObject $Acl
        # Verify from the system, not from what was written
        $Now = @((Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
        $Ok = ($Now.Count -eq 2 -and $Now -contains 'S-1-5-18' -and $Now -contains 'S-1-5-32-544')
        "$env:COMPUTERNAME $Path : $(if ($Create -contains $Path) { 'created' } else { 'permissions replaced' }); $(if ($Ok) { 'verified SYSTEM + Administrators only' } else { "CHECK FAILED - now: $($Now -join ', ')" })"
    }
}
try {
    Import-ALModule ActiveDirectory
    $Domain = Get-ALDomainInfo
    $Folders = @($Cfg.SecureFolders | Where-Object { $_ })
    if (-not $Folders.Count) { throw 'STOP: no folders - set SecureFolders in the settings or pass -Folder.' }
    if (-not $ComputerName) { $ComputerName = @($Cfg.ReferenceServer | Where-Object { $_ }) + (Get-ALTargetComputers (Resolve-ALTargetOUs $Cfg $Domain) $Domain) }
    $ComputerName = @($ComputerName | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $ComputerName.Count) { throw 'STOP: no servers - none in the target OUs, no ReferenceServer and no -ComputerName.' }

    # 1. Survey (read-only)
    $Plan = foreach ($C in $ComputerName) {
        try { $Found = @(Invoke-ALWritableCheck -Paths $Folders -Cfg $Cfg -ComputerName $C) }
        catch { Write-Host "$C : FAILED - $($_.Exception.Message)" -ForegroundColor Red; continue }
        $Missing = @($Found | Where-Object { $_.Kind -eq 'NOTFOUND' } | ForEach-Object { $_.Path })
        $BadTop = @($Folders | Where-Object { $F = $_; @($Found | Where-Object { $_.Kind -eq 'WRITABLE' -and (Test-ALPathUnder $_.Path $F) }).Count })
        foreach ($F in $Folders) {
            if ($F -in $Missing) { Write-Host "$C $F : missing - will be created administrators-only" -ForegroundColor Yellow }
            elseif ($F -in $BadTop) {
                Write-Host "$C $F : WRITABLE by non-admins:" -ForegroundColor Red
                $Found | Where-Object { $_.Kind -eq 'WRITABLE' -and (Test-ALPathUnder $_.Path $F) } | ForEach-Object { Write-Host "    $($_.Path) <- $($_.Account)" -ForegroundColor Red }
                if ($Fix) { Write-Host "    -Fix: the permissions of $F will be REPLACED (children with their own entries are not touched)" -ForegroundColor Yellow }
                else { Write-Host '    not changed - fix the permissions yourself, or run again with -Fix to replace them' -ForegroundColor Red }
            }
            else { Write-Host "$C $F : administrators-only - OK" }
        }
        $Found | Where-Object { $_.Kind -in 'UNREADABLE', 'UNRESOLVED' } | ForEach-Object { Write-Host "$C : $($_.Kind) $($_.Path)" -ForegroundColor Yellow }
        [pscustomobject]@{ Computer = $C; Create = $Missing; Repair = $(if ($Fix) { $BadTop } else { @() }) }
    }
    $Work = @($Plan | Where-Object { $_.Create.Count -or $_.Repair.Count })
    if (-not $Work.Count) { Write-Host 'Nothing to change.' -ForegroundColor Green; return }

    # 2. Confirm (yellow Y/N; -NoConfirm; never hangs non-interactively), 3. apply and verify
    if (-not $WhatIfPreference) {
        Confirm-ALChange -NoConfirm:$NoConfirm -Action "set permissions on $($Work.Count) server(s): SYSTEM + Administrators only" -Detail (@($Work | ForEach-Object { "$($_.Computer): create $(if ($_.Create.Count) { $_.Create -join ', ' } else { '-' }); replace $(if ($_.Repair.Count) { $_.Repair -join ', ' } else { '-' })" }) + 'Undo: a created folder can simply be deleted; for a replaced one the previous permissions (SDDL) are printed first and kept in the transcript.')
        $ConfirmPreference = 'None'
    }
    foreach ($W in $Work) {
        if (-not $PSCmdlet.ShouldProcess($W.Computer, "SYSTEM + Administrators only on: $(@($W.Create) + @($W.Repair) -join ', ')")) { continue }
        try { Invoke-Command -ComputerName $W.Computer -ScriptBlock $Apply -ArgumentList @($W.Create), @($W.Repair) -ErrorAction Stop | ForEach-Object { Write-Host $_ -ForegroundColor $(if ("$_" -match 'CHECK FAILED') { 'Red' } else { 'Green' }) } }
        catch { Write-Host "$($W.Computer) : FAILED - $($_.Exception.Message)" -ForegroundColor Red }
    }
}
finally { Stop-ALTranscript }
