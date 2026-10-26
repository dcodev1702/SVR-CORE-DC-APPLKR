# Step 0 (third script) - run from the management computer (Windows PowerShell 5.1) as a Domain Admin, BEFORE the build.
# Creates the SecureFolders (default C:\Admin) on the reference server and every server in the target OUs when missing, and
# restricts them to SYSTEM + Administrators (inheritance removed). Why: AppLocker allows everything under C:\Admin\* for every user,
# but any authenticated user may create a folder under C:\ - until an administrator creates C:\Admin with a locked-down ACL,
# a user could create it first and run code from it.
# An existing folder is only reported; add -Fix to replace its permissions (children with their own explicit ACEs are not touched -
# pre-flight / 4_AL_validate.ps1 flag those).
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
        $Acl = New-Object System.Security.AccessControl.DirectorySecurity
        $Acl.SetAccessRuleProtection($true, $false)
        foreach ($Sid in $Sys, $Adm) { $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($Sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))) }
        Set-Acl -LiteralPath $Path -AclObject $Acl
        "$env:COMPUTERNAME $Path : $(if ($Create -contains $Path) { 'created' } else { 'permissions replaced' }); now SYSTEM + Administrators only"
    }
}
try {
    Import-ALModule ActiveDirectory
    $Domain = Get-ALDomainInfo
    $Folders = @($Cfg.SecureFolders | Where-Object { $_ })
    if (-not $Folders.Count) { throw 'STOP: no folders - set SecureFolders in the settings or pass -Folder.' }
    if (-not $ComputerName) { $ComputerName = @($Cfg.ReferenceServer) + (Get-ALTargetComputers (Resolve-ALTargetOUs $Cfg $Domain) $Domain) }
    $ComputerName = @($ComputerName | Sort-Object -Unique)
    Confirm-ALChange -NoConfirm:$NoConfirm -Action "create / lock down $($Folders -join ', ') on $($ComputerName.Count) server(s)" -Detail @(
        "Servers: $($ComputerName -join ', ')",
        'Missing folders are created with SYSTEM + Administrators full control only. Existing folders are only changed with -Fix.'
    )
    foreach ($C in $ComputerName) {
        try {
            $Found = @(Invoke-Command -ComputerName $C -ScriptBlock $ALWritableCheck -ArgumentList (, $Folders) -ErrorAction Stop)
            $Missing = @($Found | Where-Object { "$_" -like 'NOTFOUND|*' } | ForEach-Object { ("$_" -split '\|')[1] })
            $Bad = @($Found | Where-Object { "$_" -like 'WRITABLE|*' } | ForEach-Object { ("$_" -split '\|')[1] })
            $BadTop = @($Folders | Where-Object { $F = $_; $Bad | Where-Object { $_ -eq $F -or $_.StartsWith($F.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) } })
            foreach ($F in @($Folders | Where-Object { $_ -notin $Missing -and $_ -notin $BadTop })) { Write-Host "$C $F : already administrators-only - OK" }
            if ($BadTop.Count -and -not $Fix) { foreach ($F in $BadTop) { Write-Host "$C $F : WRITABLE by non-admins (or a child is) - run again with -Fix to replace its permissions" -ForegroundColor Red } }
            $Repair = if ($Fix) { $BadTop } else { @() }
            if ($Missing.Count -or $Repair.Count) { Invoke-Command -ComputerName $C -ScriptBlock $Apply -ArgumentList (, $Missing), (, $Repair) -ErrorAction Stop | ForEach-Object { Write-Host $_ -ForegroundColor Green } }
        }
        catch { Write-Host "$C : FAILED - $($_.Exception.Message)" -ForegroundColor Red }
    }
}
finally { Stop-ALTranscript }
