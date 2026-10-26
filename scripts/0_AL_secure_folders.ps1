# Step 0 (third script) - run from the management computer (Windows PowerShell 5.1 or PowerShell 7) as a Domain Admin, BEFORE the build.
# The ONLY script in this toolkit that sets permissions. For each SecureFolders entry (default C:\Admin) on the reference server and every
# server in the target OUs:
#   missing folder             -> created, SYSTEM + Administrators full control only (inheritance removed)
#   existing, admin-only       -> left alone
#   existing, writable by a non-admin -> only REPORTED; its permissions are replaced only when you add -Fix
# Why: AppLocker allows everything under C:\Admin\* for every account, and any user may create a folder under C:\ (and owns what they
# create there) - until an administrator creates C:\Admin with locked-down permissions, a user could create it first and plant code.
# Before -Fix replaces permissions, the previous ones are printed as SDDL (kept in the transcript) so they can be restored.
# Nothing outside SecureFolders is ever touched (not C:\Temp, not C:\Sysmon); system folders are refused by the settings check.
# The servers are surveyed read-only first: with nothing to change there is no prompt. -WhatIf shows the plan without changing anything.
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
