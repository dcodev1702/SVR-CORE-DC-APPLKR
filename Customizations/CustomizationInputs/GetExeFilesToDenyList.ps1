<#
.SYNOPSIS
Script used by Create-Policies.ps1 to identify EXE files that should be disallowed by AppLocker for non-admin use. Can be edited if necessary.

.DESCRIPTION
This script outputs a list of file paths under %windir% that need to be specifically disallowed by AllowListing rules.
The list of files is consumed by Create-Policies.ps1, which builds the necessary AppLocker rules to block them.
You can edit this file as needed for your environment, although it is recommended that none of the programs
identified in this script be removed.

Note: the solution also blocks the loading of PowerShell v2 modules - these blocks are hardcoded into the base XML file. This module
as currently designed can block only EXE files, not DLLs.
http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/

.INPUTS
    None. Create-Policies.ps1 runs this script on the reference server; it takes no parameters.

.OUTPUTS
    System.String - one full path per line of an EXE under %windir% to deny for non-admin users (only files that exist).

.EXAMPLE
    & .\CustomizationInputs\GetExeFilesToDenyList.ps1
    Lists the deny-list files present on this server (how Create-Policies.ps1 calls it).

.NOTES
    Origin   : microsoft/AaronLocker CustomizationInputs (MIT). Local change for SVR-CORE-DC-APPLKR: only files that exist are
               emitted, because Server Core lacks some of them (e.g. mshta.exe) and Create-Policies.ps1 fails on a missing entry.
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Date     : 2026-10-26
    Deployed : 1_AL_build_policy.ps1 copies the Customizations folder over the toolkit's own on the reference server for the build.
#>

# --------------------------------------------------------------------------------
# Files used to bypass AllowListing:

# Find the multiple instances of .NET executables that have been identified as AllowList bypasses.
# Create-Policies.ps1 will remove redundant information.
$dotnetProgramsToDenyList =
    "InstallUtil.exe", 
    "IEExec.exe", 
    "RegAsm.exe", 
    "RegSvcs.exe", 
    "MSBuild.exe",
    "Microsoft.Workflow.Compiler.exe"
    
$dotnetProgramsToDenyList | ForEach-Object {
    Get-ChildItem -Path $env:windir\Microsoft.NET -Recurse -Include $_ | ForEach-Object { $_.FullName }
}

# Local change for Server Core: several of these binaries are not installed there (e.g., mshta.exe), and
# Create-Policies.ps1 fails on a deny-list entry that does not exist, so only existing files are emitted.
@(
    "$env:windir\System32\mshta.exe"
    "$env:windir\System32\PresentationHost.exe"
    "$env:windir\System32\wbem\WMIC.exe"
    # Note: also need Code Integrity rules to block other bypasses

    # --------------------------------------------------------------------------------
    # Files used by ransomware
    "$env:windir\System32\cipher.exe"

    # --------------------------------------------------------------------------------
    # Block common credential exposure risk (also need to disable GUI option via registry, and SecondaryLogon service)
    "$env:windir\System32\runas.exe"
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }

