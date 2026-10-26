# Settings shared by every script in this folder. Edit them once here; a script parameter with the same name overrides a value.
# Several server classes (domain controllers, MECM site systems, other member servers)? Copy this file
# (for example AL-Settings.mecm.psd1), change it, and pass -SettingsFile to every script. Each settings file keeps its own
# Outputs\<profile> folder, so the classes never overwrite each other. The scripts refuse values that would widen the policy.
@{
    # The two GPOs. Both are linked to every target OU; only one link is enabled at a time (3_AL_set_mode.ps1).
    AuditGpoName      = 'JSLC_AppLocker_AUDIT_Domain_Controller'
    EnforceGpoName    = 'JSLC_AppLocker_ENFORCE_Domain_Controller'

    # OUs (distinguished names) whose computers receive the policy. Empty = the Domain Controllers OU.
    # Example: @('OU=MECM Servers,OU=Servers,DC=contoso,DC=com')
    TargetOUs         = @()

    # REQUIRED before 1_AL_build_policy.ps1: the server the baseline is built ON (FQDN), e.g. 'dc01.contoso.com'. It must look like the
    # servers in TargetOUs (same roles, same software, the MECM client and Nessus Agent if they have them) - for the Domain Controllers OU,
    # any DC (the PDC emulator is a good choice). The rules depend on what is on its disk. (Build one policy per server class.)
    ReferenceServer   = 'DC25-1.skynet-home.local'

    # Folders or files that every account may run from, outside C:\Windows and C:\Program Files* (admin tools in C:\Admin; programs a
    # non-admin account or a non-elevated session starts). Fixed local or UNC paths only; a folder ends in \*.
    # Typical MECM / SQL examples when they are installed on another drive (site systems - a separate settings file):
    #   'D:\Program Files\Microsoft Configuration Manager\*', 'D:\Program Files\Microsoft SQL Server\*'
    # Each entry should be changeable by administrators only. 1_AL_build_policy.ps1 checks every folder and file in it on EVERY server in
    # scope and never stops on what it finds: an entry a non-admin can change is left out of the policy, and items inside it that a
    # non-admin can change become exceptions - so the policy never allows them (README, "C:\Admin"). 0_AL_pre-flight.ps1 warns ahead of
    # time; 4_AL_validate.ps1 fails only if a DC still allows such an item. Never add C:\Temp, C:\Sysmon, a user profile or a writable share.
    ExtraAllowedPaths = @('C:\Admin\*')

    # Folders that 0_AL_secure_folders.ps1 creates (when missing) administrators-only on every server in scope. An existing folder is only
    # reported - its permissions are replaced only with -Fix. Every ExtraAllowedPaths folder that you create yourself (C:\Admin) belongs here.
    SecureFolders     = @('C:\Admin')

    # Groups (DOMAIN\Name or SID) that are administrators in your organisation although they are not in the built-in Administrators group,
    # e.g. 'CONTOSO\Tier0-Server-Admins'. Their write access does not count as "user-writable" - in AaronLocker's scan and in the
    # ExtraAllowedPaths check. Empty = only the built-in administrators (README, "Who counts as an administrator").
    # Only a group that holds write access on a folder under C:\Windows, Program Files or an ExtraAllowedPaths entry, and is not in
    # Administrators, needs an entry. Not needed: SYSTEM, Administrators, Administrator, Domain Admins, Enterprise Admins, Server/Print/
    # Backup Operators - they already count. Not needed either: the user accounts in an admin OU - permissions name groups, not people.
    # Never list Domain Users, Authenticated Users or another group every account belongs to - the scripts refuse those.
    # Survey the OU of your administrator accounts (writes nothing, shows the groups each account belongs to):
    #   0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-User-Accounts/DA'
    # Then write the groups that 0_AL_pre-flight.ps1 / ScanResults\Writable_*.txt name as writers (README, section 11):
    #   0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-Groups/Tier0-Server-Admins' -Update
    KnownAdmins       = @()

    # SHA-256 of the AccessChk.exe that ships in AaronLocker\AaronLocker (Sysinternals AccessChk 6.15, 64-bit). Every script refuses a file
    # with another hash. When you replace AccessChk, verify the new file (README, "Updating AccessChk") and update this value.
    AccessChkSha256   = '843B6B1D275946F2C4569169C10C50EEC0968C4B2F0BED68C50E79F828FAB9F3'

    # DLL rules are not needed for the STIG item (WN25-00-000080) and are switched off. $true keeps AaronLocker's DLL rules.
    EnableDllRules    = $false

    # AppLocker logs allowed executions too; the 1 MB default wraps in minutes on a busy server. Sizes in MB (1-4096).
    EventLogSizesMB   = @{ 'EXE and DLL' = 100; 'MSI and Script' = 100; 'Packaged app-Execution' = 100; 'Packaged app-Deployment' = 100 }
}
