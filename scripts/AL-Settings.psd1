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

    # The DC the baseline is built ON. Leave 'PDC' - nothing to change on your end: at run time the scripts find the PDC emulator of the
    # domain they run in (.NET, or the RSAT ActiveDirectory module as the fallback), and pre-flight prints which DC that is. Set an FQDN
    # (e.g. 'dc01.contoso.com') only for another server class, in its own settings file. The rules depend on what is on that DC's disk.
    ReferenceServer   = 'PDC'

    # Servers in scope that run ANOTHER Windows Server version than ReferenceServer (FQDNs), one per version - e.g. a Server 2022 DC next
    # to Server 2025 DCs: @('dc22-01.contoso.com'). 1_AL_build_policy.ps1 scans each one too and merges every user-writable folder and
    # every denied tool that any of them finds into the rules (stricter only, never wider). 0_AL_pre-flight.ps1 warns when a server in
    # scope runs a version no reference server runs. Empty = every server runs the version of ReferenceServer (SERVER-2022.md).
    ExtraReferenceServers = @()

    # Folders or files that every account may run from, outside C:\Windows and C:\Program Files* (admin tools in C:\Admin; programs a
    # non-admin account or a non-elevated session starts). Fixed local or UNC paths only; a folder ends in \*.
    # Typical MECM / SQL examples when they are installed on another drive (site systems - a separate settings file):
    #   'D:\Program Files\Microsoft Configuration Manager\*', 'D:\Program Files\Microsoft SQL Server\*'
    # Each entry should be changeable by administrators only. 1_AL_build_policy.ps1 checks every folder and file in it on EVERY server in
    # scope and never stops on what it finds: an entry a non-admin can change is left out of the policy, and items inside it that a
    # non-admin can change become exceptions - so the policy never allows them (README, "C:\Admin"). 0_AL_pre-flight.ps1 warns ahead of
    # time; 4_AL_validate.ps1 fails only if a DC still allows such an item. Never add C:\Temp, C:\Sysmon, a user profile or a writable share.
    #ExtraAllowedPaths = @('C:\Admin\*')
    ExtraAllowedPaths = @()

    # Folders that 0_AL_secure_folders.ps1 creates (when missing) administrators-only on every server in scope. An existing folder is only
    # reported - its permissions are replaced only with -Fix. Every ExtraAllowedPaths folder that you create yourself (C:\Admin) belongs here.
    #SecureFolders     = @('C:\Admin')
    SecureFolders     = @()

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

    # DLL rules are not needed for the STIG item (WN25-00-000080 / WN22-00-000080) and are switched off. $true keeps AaronLocker's DLL rules.
    EnableDllRules    = $false

    # Packaged app (Appx) rules: AaronLocker's default rule allows every signed packaged app; not required by the STIG items. $false empties
    # the Appx collection (NotConfigured) in both GPOs - for Server Core installations without packaged-app support, where a policy that
    # carries an Appx collection may fail to convert (AppLocker event 8000; 7_AL_diagnose.ps1, SERVER-2022.md section 7).
    EnableAppxRules   = $false

    # Allow-rule exceptions that are collapsed into one: every user-writable folder the scan found under such a root is replaced by
    # the root itself as the one exception, so the rule only gets stricter. AppLocker converts a rule collection into ONE access
    # control list of at most 64 KB, one entry per rule, and the %WINDIR%\* rule carries every user-writable folder as part of its
    # entry. On a DC, SYSVOL holds one such folder per GPO whose creator or delegated editor is not an administrator - hundreds in a
    # large domain - and the whole policy is then rejected by every DC (event 8000, status 1336). Non-admins never run from a DC's
    # local SYSVOL folder; logon scripts come through \\<domain>\SYSVOL and \\<domain>\NETLOGON, which stay allowed. The build prints
    # what it collapsed, and the conversion check names the folders that make a rule big: add others here when needed
    # (%WINDIR%\CCM\* ...), or list their writers in KnownAdmins when they are an administrators group. Core Windows folders are refused.
    CollapseExceptionsUnder = @('%WINDIR%\SYSVOL\*')

    # AppLocker logs allowed executions too; the 1 MB default wraps in minutes on a busy server. Sizes in MB (1-4096).
    EventLogSizesMB   = @{ 'EXE and DLL' = 100; 'MSI and Script' = 100; 'Packaged app-Execution' = 100; 'Packaged app-Deployment' = 100 }
}
