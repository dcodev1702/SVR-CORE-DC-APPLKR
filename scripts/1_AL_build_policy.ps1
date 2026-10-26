# Step 1 - run from the management computer (Windows PowerShell 5.1) as a Domain Admin. Builds the AaronLocker AppLocker baseline
# ON the reference server, because the rules depend on that machine's file system (user-writable folders under Windows and
# Program Files - including the MECM client's folders -, tools present, safe paths).
#   1. checks the AccessChk.exe you brought in (Microsoft signature, optional pinned SHA-256) - nothing is downloaded, the server needs no Internet
#   2. copies the toolkit + Customizations + the ExtraAllowedPaths (C:\Admin ...) to a temporary folder on the reference server over WinRM
#   3. stops if an extra path is writable by non-admins (a path rule there would be a bypass)
#   4. runs Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan on the server (read-only scan; nothing is applied to the server)
#   5. copies the results to <root>\Outputs\<profile>\<timestamp>\ and removes the temporary folder from the server
param(
    [string]$SettingsFile,
    [string]$ComputerName,
    [string[]]$ExtraAllowedPaths,
    [string]$RemoteWork = 'C:\AaronLocker'
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '1_AL_build_policy' -SettingsFile $SettingsFile -Overrides @{ ReferenceServer = $ComputerName; ExtraAllowedPaths = $ExtraAllowedPaths }
if (-not $ComputerName) { $ComputerName = $Cfg.ReferenceServer }
$Session = $null
try {
    $Extra = @($Cfg.ExtraAllowedPaths | Where-Object { $_ })
    $Overlay = Join-Path $Cfg.Root 'Customizations'
    if (-not (Test-Path -LiteralPath (Join-Path $Cfg.ToolkitPath 'Create-Policies.ps1'))) { throw "STOP: AaronLocker not found at $($Cfg.ToolkitPath). Run 0_AL_get_toolkit.ps1." }
    if (-not (Test-Path -LiteralPath $Overlay)) { throw "STOP: $Overlay is missing." }
    $Check = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if (-not $Check.Ok) { throw "STOP: AccessChk.exe - $($Check.Detail)" }
    Write-Host "AccessChk.exe: $($Check.Detail)"

    $Session = New-PSSession -ComputerName $ComputerName
    Invoke-Command -Session $Session -ScriptBlock {
        $os = Get-CimInstance Win32_OperatingSystem
        $it = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType
        "Reference server: $env:COMPUTERNAME | $($os.Caption) $it | PowerShell $($PSVersionTable.PSVersion) | $($ExecutionContext.SessionState.LanguageMode)"
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'STOP: AaronLocker needs FullLanguage mode on the reference server.' }
        Remove-Item -LiteralPath $using:RemoteWork -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $using:RemoteWork -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path (Join-Path $Cfg.ToolkitPath '*') -Destination $RemoteWork -ToSession $Session -Recurse -Force
    # Overlay: Server Core-safe deny list + the ExtraAllowedPaths hook (see Customizations\)
    Copy-Item -Path (Join-Path $Overlay '*') -Destination $RemoteWork -ToSession $Session -Recurse -Force
    # Desktop-only static rules (OneDrive installer, Chrome Flash) have no place on a server; dropped from the server's copy only
    Invoke-Command -Session $Session -ScriptBlock {
        Remove-Item -Path (Join-Path $using:RemoteWork 'MergeRules-Static\OneDrive-*.xml'), (Join-Path $using:RemoteWork 'MergeRules-Static\Allow-GoogleChromeFlashPlayer.xml') -Force -ErrorAction SilentlyContinue
    }

    if ($Extra.Count) {
        $Findings = @(Invoke-Command -Session $Session -ScriptBlock $ALWritableCheck -ArgumentList (, $Extra))
        $Writable = @($Findings | Where-Object { "$_" -like 'WRITABLE|*' })
        if ($Writable.Count) {
            $Writable | ForEach-Object { $F = "$_" -split '\|'; Write-Host "  WRITABLE: $($F[1]) (by $($F[2]))" -ForegroundColor Red }
            throw 'STOP: an ExtraAllowedPaths folder is writable by non-admins. Lock it down first (README, "C:\Admin"), or remove it from the settings.'
        }
        foreach ($Line in @($Findings | Where-Object { "$_" -like 'NOTFOUND|*' })) {
            $Missing = ("$Line" -split '\|')[1]
            Write-Warning "$Missing does not exist on the reference server; the rule is still generated. Restrict that folder to SYSTEM and Administrators when you create it."
        }
        Invoke-Command -Session $Session -ScriptBlock { Set-Content -LiteralPath (Join-Path $using:RemoteWork 'CustomizationInputs\ExtraAllowedPaths.txt') -Value $using:Extra -Encoding UTF8 }
        Write-Host "Extra allowed paths: $($Extra -join ', ')"
    }

    Invoke-Command -Session $Session -ScriptBlock {
        Set-Location -LiteralPath $using:RemoteWork
        & .\Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan
    }

    $Dest = Join-Path $Cfg.OutRoot $Cfg.Stamp
    New-Item -Path $Dest -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $RemoteWork 'Outputs\*') -Destination $Dest -FromSession $Session -Recurse -Force
    Copy-Item -Path (Join-Path $RemoteWork 'ScanResults') -Destination $Dest -FromSession $Session -Recurse -Force
    [ordered]@{ Built = (Get-Date).ToString('s'); ReferenceServer = $ComputerName; ExtraAllowedPaths = $Extra; AccessChk = $Check.Detail; Settings = $Cfg.SettingsFile } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Dest 'build-info.json') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $Cfg.OutRoot 'latest.txt') -Value $Dest -Encoding Ascii

    $Ccm = @(Get-ChildItem -LiteralPath (Join-Path $Dest 'ScanResults') -Filter 'Writable_*.txt' | Select-String -Pattern '\\(ccm|sms)' )
    if ($Ccm.Count) { Write-Host 'MECM folders that are user-writable on the reference server (excluded from the allow rules; SYSTEM/admins are unaffected):'; $Ccm | ForEach-Object { Write-Host "  $($_.Line)" } }
    Get-ChildItem -LiteralPath $Dest -File | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "Results: $Dest" -ForegroundColor Green
}
finally {
    if ($Session) {
        try { Invoke-Command -Session $Session -ScriptBlock { Set-Location -LiteralPath $env:SystemRoot; Remove-Item -LiteralPath $using:RemoteWork -Recurse -Force -ErrorAction Stop } }
        catch { Write-Warning "Could not remove $RemoteWork on ${ComputerName}: $($_.Exception.Message)" }
        Remove-PSSession $Session
    }
    Stop-ALTranscript
}
