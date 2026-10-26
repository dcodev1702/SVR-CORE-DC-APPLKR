# Settings shared by every script in this folder. Edit them once here; a script parameter with the same name overrides a value.
# Several server classes (domain controllers, MECM site systems, other member servers)? Copy this file
# (for example AL-Settings.mecm.psd1), change it, and pass -SettingsFile to every script. Each settings file keeps its own
# Outputs\<profile> folder, so the classes never overwrite each other.
@{
    # The two GPOs. Both are linked to every target OU; only one link is enabled at a time (3_AL_set_mode.ps1).
    AuditGpoName      = 'JMSC-DC-AppLocker - Audit'
    EnforceGpoName    = 'JMSC-DC-AppLocker - Enforce'

    # OUs (distinguished names) whose computers receive the policy. Empty = the Domain Controllers OU.
    # Example: @('OU=MECM Servers,OU=Servers,DC=contoso,DC=com')
    TargetOUs         = @()

    # The server the baseline is built ON (FQDN). It must look like the servers in TargetOUs: same roles, same software,
    # and the MECM client installed. The rules depend on what is on its disk. (Build one policy per server class.)
    ReferenceServer   = 'DC25-1.skynet-home.local'

    # Folders or files that NON-admin accounts must be able to run from, outside C:\Windows and C:\Program Files*
    # (services running as NETWORK SERVICE, LOCAL SERVICE, NT SERVICE\..., gMSAs - SYSTEM and local admins never need this).
    # Typical MECM / SQL examples when they are installed on another drive:
    #   'D:\Program Files\Microsoft Configuration Manager\*', 'D:\Program Files\Microsoft SQL Server\*'
    # Every entry MUST be writable by administrators only. A new folder under C:\ inherits Authenticated Users: Modify, so
    # C:\Admin must be locked down (see README, "C:\Admin"). 1_AL_build_policy.ps1, 0_AL_pre-flight.ps1 and 4_AL_validate.ps1 check it.
    ExtraAllowedPaths = @('C:\Admin\*')

    # Folders that 0_AL_secure_folders.ps1 creates (when missing) and restricts to SYSTEM + Administrators on every server in scope.
    # Every ExtraAllowedPaths folder that you create yourself (C:\Admin) belongs here.
    SecureFolders     = @('C:\Admin')

    # Optional: pin the SHA-256 of the AccessChk.exe you brought in (Get-FileHash). Empty = only the Microsoft signature is required.
    # The servers have no Internet, so AccessChk.exe is staged by hand in <toolkit>\AccessChk.exe (see README, "No Internet").
    AccessChkSha256   = ''

    # DLL rules are not needed for the STIG item (WN25-00-000080) and are switched off. $true keeps AaronLocker's DLL rules.
    EnableDllRules    = $false

    # AppLocker logs allowed executions too; the 1 MB default wraps in minutes on a busy server. Sizes in MB.
    EventLogSizesMB   = @{ 'EXE and DLL' = 100; 'MSI and Script' = 20; 'Packaged app-Execution' = 20; 'Packaged app-Deployment' = 20 }
}
