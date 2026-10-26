<#
.SYNOPSIS
    Step 1 - verifies the third-party pieces that ship in this repository: AaronLocker and Sysinternals AccessChk (64-bit, pinned SHA-256).

.DESCRIPTION
    Run first, on the management computer. By default nothing is downloaded and no Internet access is attempted, so the script works
    inside a disconnected network. It checks:
      - AaronLocker (microsoft/AaronLocker, MIT) in <root>\AaronLocker: Create-Policies.ps1 must be present.
      - AccessChk.exe in <root>\AaronLocker\AaronLocker: a valid Microsoft Authenticode signature, the product name Sysinternals
        AccessChk, a 64-bit build and, when AccessChkSha256 is set in the settings, the pinned SHA-256.
    A missing piece can be imported from files carried across the approved transfer path (-AaronLockerZip, -AccessChkPath) or, on an
    Internet-connected computer only, downloaded with -Download. An imported or downloaded AccessChk that fails the checks is removed
    again; the copy that ships in the repository is never deleted.
    The servers never need Internet: 1_AL_build_policy.ps1 copies the toolkit to the reference server over WinRM.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script. One file per server class (README, section 5).

.PARAMETER RepoPath
    Folder that holds, or will hold, the AaronLocker repository. Default: <root>\AaronLocker.

.PARAMETER AaronLockerZip
    Offline import: a GitHub zip of microsoft/AaronLocker (Code > Download ZIP) copied to this computer.

.PARAMETER AccessChkPath
    Offline import: accesschk64.exe taken from https://download.sysinternals.com/files/AccessChk.zip and copied to this computer. It is
    verified before it is copied into the toolkit.

.PARAMETER Download
    Internet-connected computer only: download what is missing (AaronLocker from GitHub, AccessChk from Sysinternals).

.INPUTS
    None. Nothing can be piped to this script; the settings come from the settings file.

.OUTPUTS
    None to the pipeline. Console: the AccessChk verdict (signature, version, SHA-256, pinned or not) and "Toolkit ready".
    Transcript: Logs\0_AL_get_toolkit-<timestamp>.log. Exit code 1 when a piece is missing or rejected (the message starts with STOP).

.EXAMPLE
    .\0_AL_get_toolkit.ps1
    Verifies the files that ship in the repository. Expected: "AccessChk.exe: Microsoft-signed Sysinternals AccessChk 6.15 (64-bit),
    SHA-256 843B6B1D... (pinned)" and "Toolkit ready".

.EXAMPLE
    .\0_AL_get_toolkit.ps1 -AaronLockerZip D:\Media\AaronLocker-main.zip -AccessChkPath D:\Media\accesschk64.exe
    Imports both pieces from media inside the disconnected network.

.EXAMPLE
    .\0_AL_get_toolkit.ps1 -Download
    Internet-connected computer only: fetches whatever is missing.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7 on the management computer. No elevation, no domain access.
    Changes  : nothing, unless -AaronLockerZip, -AccessChkPath or -Download adds a missing piece under <root>\AaronLocker.
    README   : section 4 (bring the repository into the disconnected network), section 12 (updating AccessChk).
#>
param(
    [string]$SettingsFile,
    # Folder that holds / will hold the AaronLocker repository (default <root>\AaronLocker)
    [string]$RepoPath,
    # Offline import: a GitHub zip of microsoft/AaronLocker (Code > Download ZIP) copied to this computer
    [string]$AaronLockerZip,
    # Offline import: accesschk64.exe from https://download.sysinternals.com/files/AccessChk.zip copied to this computer
    [string]$AccessChkPath,
    # Internet-connected computer only: download what is missing (AaronLocker from GitHub, AccessChk from Sysinternals)
    [switch]$Download
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_get_toolkit' -SettingsFile $SettingsFile
$Offline = @'
The repository ships both files; this one is missing or was rejected. To restore it without Internet:
  1. On a computer WITH Internet: download https://github.com/microsoft/AaronLocker/archive/HEAD.zip and/or
     https://download.sysinternals.com/files/AccessChk.zip (extract accesschk64.exe), or run this script there with -Download.
  2. Check accesschk64.exe: Get-AuthenticodeSignature must say Valid / Microsoft Corporation. Compare Get-FileHash with AccessChkSha256
     in AL-Settings.psd1 (a newer AccessChk has a new hash: update the setting after you have verified the file).
  3. Copy the files across your approved transfer path and run:  .\0_AL_get_toolkit.ps1 -AaronLockerZip <zip> -AccessChkPath <accesschk64.exe>
'@
try {
    if (-not $RepoPath) { $RepoPath = Join-Path $Cfg.Root 'AaronLocker' }
    $Toolkit = Join-Path $RepoPath 'AaronLocker'

    # ---- AaronLocker
    if (Test-Path -LiteralPath (Join-Path $Toolkit 'Create-Policies.ps1')) { Write-Host "AaronLocker present: $Toolkit" }
    elseif (-not $AaronLockerZip -and -not $Download) { throw "STOP: AaronLocker not found at $Toolkit.`n$Offline" }
    else {
        $Tmp = Join-Path $env:TEMP "AaronLocker-$($Cfg.Stamp)"
        try {
            if ($AaronLockerZip) {
                if (-not (Test-Path -LiteralPath $AaronLockerZip -PathType Leaf)) { throw "STOP: zip not found: $AaronLockerZip" }
                Expand-Archive -LiteralPath $AaronLockerZip -DestinationPath $Tmp
            }
            elseif (Get-Command git.exe -ErrorAction SilentlyContinue) {
                git.exe clone --depth 1 https://github.com/microsoft/AaronLocker.git $RepoPath
                if ($LASTEXITCODE) { throw 'git clone failed' }
            }
            else {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                $Zip = Join-Path $env:TEMP "AaronLocker-$($Cfg.Stamp).zip"
                Invoke-WebRequest -Uri 'https://github.com/microsoft/AaronLocker/archive/HEAD.zip' -OutFile $Zip -UseBasicParsing
                Expand-Archive -LiteralPath $Zip -DestinationPath $Tmp
                Remove-Item -LiteralPath $Zip -Force
            }
        }
        catch { Remove-Item -LiteralPath $Tmp, $RepoPath -Recurse -Force -ErrorAction SilentlyContinue; if ("$_" -like 'STOP:*') { throw }; throw "STOP: could not get AaronLocker ($($_.Exception.Message)).`n$Offline" }
        if (Test-Path -LiteralPath $Tmp) {
            # A GitHub zip holds one top-level folder (AaronLocker-main) that contains the AaronLocker folder
            $Inner = Get-ChildItem -LiteralPath $Tmp -Directory | Select-Object -First 1
            if (-not $Inner -or -not (Test-Path -LiteralPath (Join-Path $Inner.FullName 'AaronLocker\Create-Policies.ps1'))) { Remove-Item -LiteralPath $Tmp -Recurse -Force; throw 'STOP: the zip does not look like the AaronLocker repository (AaronLocker\Create-Policies.ps1 not found).' }
            Move-Item -LiteralPath $Inner.FullName -Destination $RepoPath
            Remove-Item -LiteralPath $Tmp -Recurse -Force
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Toolkit 'Create-Policies.ps1'))) { throw "STOP: Create-Policies.ps1 not found under $Toolkit." }

    # ---- AccessChk
    $Target = Join-Path $Toolkit 'AccessChk.exe'
    if ($AccessChkPath) {
        $Check = Test-ALAccessChk -Path $AccessChkPath -Sha256 $Cfg.AccessChkSha256
        if (-not $Check.Ok) { throw "STOP: $AccessChkPath rejected - $($Check.Detail). Nothing was copied." }
        Copy-Item -LiteralPath $AccessChkPath -Destination $Target -Force
    }
    elseif (-not (Test-Path -LiteralPath $Target)) {
        if (-not $Download) { throw "STOP: AccessChk.exe not found at $Target.`n$Offline" }
        $Zip = Join-Path $env:TEMP "AccessChk-$($Cfg.Stamp).zip"; $Tmp = Join-Path $env:TEMP "AccessChk-$($Cfg.Stamp)"
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/AccessChk.zip' -OutFile $Zip -UseBasicParsing
            Expand-Archive -LiteralPath $Zip -DestinationPath $Tmp
            Copy-Item -LiteralPath (Join-Path $Tmp 'accesschk64.exe') -Destination $Target -Force
        }
        catch { throw "STOP: could not get AccessChk ($($_.Exception.Message)).`n$Offline" }
        finally { Remove-Item -LiteralPath $Zip, $Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $Check = Test-ALAccessChk -Path $Target -Sha256 $Cfg.AccessChkSha256
    if (-not $Check.Ok) {
        # A file this script just copied or downloaded is removed again; the copy that ships in the repository is never deleted
        if ($AccessChkPath -or $Download) { Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue; throw "STOP: AccessChk.exe rejected and removed - $($Check.Detail)" }
        throw "STOP: AccessChk.exe rejected - $($Check.Detail). Do not use it.`n$Offline"
    }
    Write-Host "AccessChk.exe: $($Check.Detail)" -ForegroundColor Green
    if (-not $Cfg.AccessChkSha256) { Write-Host 'AccessChkSha256 is empty in the settings: pin the hash above so a changed file is refused.' -ForegroundColor Yellow }
    if (Test-Path -LiteralPath (Join-Path $RepoPath '.git')) { Write-Host ('AaronLocker commit: ' + (git.exe -C $RepoPath log -1 --format='%h %ad %s' --date=short)) }
    else { Write-Host 'AaronLocker: vendored copy (upstream commit in THIRD-PARTY-NOTICES.md)' }
    Write-Host "Toolkit ready: $Toolkit" -ForegroundColor Green
}
finally { Stop-ALTranscript }
