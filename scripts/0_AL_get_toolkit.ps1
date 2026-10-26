# Step 0 (first script) - run once on the management computer (Windows PowerShell 5.1). Puts the two third-party pieces in place:
#   - AaronLocker (microsoft/AaronLocker) in <root>\AaronLocker
#   - Sysinternals AccessChk in <toolkit>\AccessChk.exe, verified as Microsoft-signed (and against AccessChkSha256 when pinned)
# The servers and domain controllers never need Internet: this is the only script that can reach out, and only from the management
# computer. With NO Internet there either, bring both files in by hand and import them:
#   .\0_AL_get_toolkit.ps1 -AaronLockerZip D:\Media\AaronLocker-main.zip -AccessChkPath D:\Media\accesschk64.exe
# (or copy the folders into place yourself and run the script with no parameters just to verify them).
param(
    [string]$SettingsFile,
    # Folder that holds / will hold the AaronLocker repository (default <root>\AaronLocker)
    [string]$RepoPath,
    # Offline: a GitHub zip of microsoft/AaronLocker (Code > Download ZIP) copied to this computer
    [string]$AaronLockerZip,
    # Offline: accesschk64.exe (or accesschk.exe) from https://download.sysinternals.com/files/AccessChk.zip copied to this computer
    [string]$AccessChkPath
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_get_toolkit' -SettingsFile $SettingsFile
$Offline = @'
No Internet access from this computer. Bring the files in by hand:
  1. On a computer WITH Internet: download https://github.com/microsoft/AaronLocker/archive/HEAD.zip and
     https://download.sysinternals.com/files/AccessChk.zip (extract accesschk64.exe).
  2. Check accesschk64.exe: Get-AuthenticodeSignature must say Valid / Microsoft Corporation. Note Get-FileHash and, if you want, pin it in AL-Settings.psd1 (AccessChkSha256).
  3. Copy both to this computer and run:  .\0_AL_get_toolkit.ps1 -AaronLockerZip <zip> -AccessChkPath <accesschk64.exe>
'@
try {
    if (-not $RepoPath) { $RepoPath = Join-Path $Cfg.Root 'AaronLocker' }
    $Toolkit = Join-Path $RepoPath 'AaronLocker'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # ---- AaronLocker
    if (Test-Path -LiteralPath (Join-Path $Toolkit 'Create-Policies.ps1')) { Write-Host "AaronLocker already present: $Toolkit" }
    else {
        $Tmp = Join-Path $env:TEMP "AaronLocker-$($Cfg.Stamp)"
        try {
            if ($AaronLockerZip) {
                if (-not (Test-Path -LiteralPath $AaronLockerZip)) { throw "STOP: zip not found: $AaronLockerZip" }
                Expand-Archive -LiteralPath $AaronLockerZip -DestinationPath $Tmp
            }
            elseif (Get-Command git.exe -ErrorAction SilentlyContinue) {
                git.exe clone --depth 1 https://github.com/microsoft/AaronLocker.git $RepoPath
                if ($LASTEXITCODE) { throw 'git clone failed' }
            }
            else {
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
            if (-not $Inner -or -not (Test-Path -LiteralPath (Join-Path $Inner.FullName 'AaronLocker\Create-Policies.ps1'))) { throw 'STOP: the zip does not look like the AaronLocker repository (AaronLocker\Create-Policies.ps1 not found).' }
            Move-Item -LiteralPath $Inner.FullName -Destination $RepoPath
            Remove-Item -LiteralPath $Tmp -Recurse -Force
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Toolkit 'Create-Policies.ps1'))) { throw "STOP: Create-Policies.ps1 not found under $Toolkit." }

    # ---- AccessChk
    $Target = Join-Path $Toolkit 'AccessChk.exe'
    if ($AccessChkPath) {
        $Check = Test-ALAccessChk -Path $AccessChkPath -Sha256 $Cfg.AccessChkSha256
        if (-not $Check.Ok) { throw "STOP: $AccessChkPath rejected - $($Check.Detail)" }
        Copy-Item -LiteralPath $AccessChkPath -Destination $Target -Force
    }
    elseif (-not (Test-Path -LiteralPath $Target)) {
        $Zip = Join-Path $env:TEMP "AccessChk-$($Cfg.Stamp).zip"; $Tmp = Join-Path $env:TEMP "AccessChk-$($Cfg.Stamp)"
        try {
            Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/AccessChk.zip' -OutFile $Zip -UseBasicParsing
            Expand-Archive -LiteralPath $Zip -DestinationPath $Tmp
            Copy-Item -LiteralPath (Join-Path $Tmp 'accesschk64.exe') -Destination $Target -Force
        }
        catch { throw "STOP: could not get AccessChk ($($_.Exception.Message)).`n$Offline" }
        finally { Remove-Item -LiteralPath $Zip, $Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $Check = Test-ALAccessChk -Path $Target -Sha256 $Cfg.AccessChkSha256
    if (-not $Check.Ok) { Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue; throw "STOP: AccessChk.exe rejected and deleted - $($Check.Detail)" }
    Write-Host "AccessChk.exe: $($Check.Detail)" -ForegroundColor Green
    if (Test-Path -LiteralPath (Join-Path $RepoPath '.git')) { Write-Host ('AaronLocker commit: ' + (git.exe -C $RepoPath log -1 --format='%h %ad %s' --date=short)) }
    Write-Host "Toolkit ready: $Toolkit" -ForegroundColor Green
}
finally { Stop-ALTranscript }
