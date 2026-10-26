<#
.SYNOPSIS
Outputs a list of known administrative users or groups that should be ignored when scanning for "user-writable" directories.

.DESCRIPTION
Outputs a list of zero or more administrative users or groups that Enum-WritableDirs.ps1 does not know about (e.g., custom domain or local groups or users), one to a line.

The script framework scans for "user-writable" directories, looking for "write" permissions and ignoring permissions granted
to "known administrative" users and groups. The framework might fail to recognize custom domain groups and (in some cases)
local user accounts as administrative. This script enables adding those entities to the list of known administrative users/groups.
Output one entity name or SID per line.

Examples where this might be needed:
* Custom domain groups that have administrative rights.
* On Azure Active Directory joined systems, enumeration of BUILTIN\Administrators might not work correctly - might need to enumerate administrative accounts explicitly.

Examples:

    "DESKTOP-7TPCJ7J\renamedAdmin"
    "CONTOSO\SCCM-Admins"

.INPUTS
    None. Create-Policies.ps1 runs this script on the reference server; it takes no parameters. The local addition reads
    KnownAdmins.txt next to this script (written by 1_AL_build_policy.ps1 from the KnownAdmins setting).

.OUTPUTS
    System.String - one DOMAIN\Name or SID per line that the scan treats as an administrator (empty when the setting is empty).

.EXAMPLE
    & .\CustomizationInputs\KnownAdmins.ps1
    Lists the extra administrators groups for this build (how Create-Policies.ps1 calls it).

.NOTES
    Origin   : microsoft/AaronLocker CustomizationInputs (MIT). Local change for SVR-CORE-DC-APPLKR: the KnownAdmins.txt hook, so
               AaronLocker's scan and the scripts' own ExtraAllowedPaths permission check trust the same groups. Fill the setting with
               0_AL_known_admins.ps1 (README, section 11).
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Date     : 2026-10-26
#>

# Local addition: the KnownAdmins setting (AL-Settings.psd1). 1_AL_build_policy.ps1 writes it to KnownAdmins.txt next to this script,
# so AaronLocker's scan and the scripts' own ExtraAllowedPaths permission check trust the same administrators groups.
$knownAdminsFile = Join-Path $PSScriptRoot 'KnownAdmins.txt'
if (Test-Path -LiteralPath $knownAdminsFile)
{
    Get-Content -LiteralPath $knownAdminsFile | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^#' } | ForEach-Object { $_.Trim() }
}
