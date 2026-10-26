# Step 1 - run from the management computer (Windows PowerShell 5.1 or PowerShell 7) as a Domain Admin. Builds the AaronLocker AppLocker
# baseline ON the reference server, because the rules depend on that machine's file system (user-writable folders under Windows and
# Program Files - including the MECM client's folders -, tools present, safe paths).
#   1. checks the AccessChk.exe that ships with the toolkit (Microsoft signature, 64-bit, pinned SHA-256) - nothing is downloaded
#   2. copies the toolkit + Customizations + ExtraAllowedPaths (C:\Admin ...) + KnownAdmins to a temporary folder on the server over WinRM
#   3. stops if an extra path can be changed by a non-admin (a path rule there would be a bypass)
#   4. runs Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan on the server (it only READS permissions; nothing is applied to the server)
#   5. copies the results to <root>\Outputs\<profile>\<timestamp>\ and removes the temporary folder from the server
param(
    [string]$SettingsFile,
    [string]$ComputerName,
    [string[]]$ExtraAllowedPaths,
    # Temporary work folder on the server; it is DELETED before and after the build, so its name must start with AaronLocker
    [ValidatePattern('^[A-Za-z]:\\(?:[^*?"<>|:]*\\)?AaronLocker[^\\*?"<>|:]*$')][string]$RemoteWork = 'C:\AaronLocker'
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '1_AL_build_policy' -SettingsFile $SettingsFile -Overrides @{ ReferenceServer = $ComputerName; ExtraAllowedPaths = $ExtraAllowedPaths }
if (-not $ComputerName) { $ComputerName = $Cfg.ReferenceServer }
$Session = $null
try {
    if (-not $ComputerName) { throw 'STOP: no reference server. Set ReferenceServer in the settings (a server in scope that looks like the others; for DCs any DC) or pass -ComputerName. Nothing was changed.' }
    $Extra = @($Cfg.ExtraAllowedPaths | Where-Object { $_ })
    $Known = @($Cfg.KnownAdmins | Where-Object { $_ })
    $Overlay = Join-Path $Cfg.Root 'Customizations'
    if (-not (Test-Path -LiteralPath (Join-Path $Cfg.ToolkitPath 'Create-Policies.ps1'))) { throw "STOP: AaronLocker not found at $($Cfg.ToolkitPath). Run 0_AL_get_toolkit.ps1." }
    if (-not (Test-Path -LiteralPath $Overlay)) { throw "STOP: $Overlay is missing." }
    $Check = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if (-not $Check.Ok) { throw "STOP: AccessChk.exe - $($Check.Detail)" }
    Write-Host "AccessChk.exe: $($Check.Detail)"

    $Session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
    Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock {
        $os = Get-CimInstance Win32_OperatingSystem
        $it = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType
        "Reference server: $env:COMPUTERNAME | $($os.Caption) $it | PowerShell $($PSVersionTable.PSVersion) | $($ExecutionContext.SessionState.LanguageMode) | execution policy $(Get-ExecutionPolicy)"
        if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'STOP: AaronLocker needs FullLanguage mode on the reference server.' }
        if ((Get-ExecutionPolicy) -in 'AllSigned', 'Restricted') { throw "STOP: the execution policy on the reference server is $(Get-ExecutionPolicy); AaronLocker's scripts are not signed. Nothing was changed." }
        Remove-Item -LiteralPath $using:RemoteWork -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $using:RemoteWork -ItemType Directory -Force | Out-Null
    }
    Copy-Item -Path (Join-Path $Cfg.ToolkitPath '*') -Destination $RemoteWork -ToSession $Session -Recurse -Force
    # Overlay: Server Core-safe deny list + the ExtraAllowedPaths and KnownAdmins hooks (see Customizations\)
    Copy-Item -Path (Join-Path $Overlay '*') -Destination $RemoteWork -ToSession $Session -Recurse -Force
    # Desktop-only static rules (OneDrive installer, Chrome Flash) have no place on a server; dropped from the server's copy only
    Invoke-Command -Session $Session -ScriptBlock {
        Remove-Item -Path (Join-Path $using:RemoteWork 'MergeRules-Static\OneDrive-*.xml'), (Join-Path $using:RemoteWork 'MergeRules-Static\Allow-GoogleChromeFlashPlayer.xml') -Force -ErrorAction SilentlyContinue
    }

    if ($Known.Count) {
        Invoke-Command -Session $Session -ScriptBlock { Set-Content -LiteralPath (Join-Path $using:RemoteWork 'CustomizationInputs\KnownAdmins.txt') -Value $using:Known -Encoding UTF8 }
        Write-Host "Known administrators groups: $($Known -join ', ')"
    }
    if ($Extra.Count) {
        $Findings = @(Invoke-ALWritableCheck -Paths $Extra -Cfg $Cfg -Session $Session)
        $Writable = @($Findings | Where-Object { $_.Kind -eq 'WRITABLE' })
        if ($Writable.Count) {
            $Writable | ForEach-Object { Write-Host "  WRITABLE: $($_.Path) (by $($_.Account))" -ForegroundColor Red }
            throw 'STOP: an ExtraAllowedPaths entry can be changed by non-admins. Remove that access (README, "C:\Admin"), list the group in KnownAdmins if it is an administrators group, or remove the entry from the settings.'
        }
        foreach ($F in @($Findings | Where-Object { $_.Kind -ne 'WRITABLE' })) {
            if ($F.Kind -eq 'NOTFOUND') { Write-Warning "$($F.Path) does not exist on the reference server; the rule is still generated. Create that folder administrators-only (0_AL_secure_folders.ps1) before the policy is used." }
            else { Write-Warning "$($F.Kind): $($F.Path)" }
        }
        Invoke-Command -Session $Session -ScriptBlock { Set-Content -LiteralPath (Join-Path $using:RemoteWork 'CustomizationInputs\ExtraAllowedPaths.txt') -Value $using:Extra -Encoding UTF8 }
        Write-Host "Extra allowed paths: $($Extra -join ', ')"
    }

    Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock {
        Set-Location -LiteralPath $using:RemoteWork
        & .\Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan
    }

    $Dest = Join-Path $Cfg.OutRoot $Cfg.Stamp
    New-Item -Path $Dest -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $RemoteWork 'Outputs\*') -Destination $Dest -FromSession $Session -Recurse -Force
    Copy-Item -Path (Join-Path $RemoteWork 'ScanResults') -Destination $Dest -FromSession $Session -Recurse -Force
    $Rules = @(Get-ChildItem -LiteralPath $Dest -Filter 'AppLockerRules-*.xml' -File)
    if (-not @($Rules | Where-Object { $_.Name -like '*-Audit.xml' }).Count -or -not @($Rules | Where-Object { $_.Name -like '*-Enforce.xml' }).Count) { throw "STOP: the build produced no Audit/Enforce rules file in $Dest - see the AaronLocker output above." }
    [ordered]@{
        Built = (Get-Date).ToString('s'); ReferenceServer = $ComputerName; ExtraAllowedPaths = $Extra; KnownAdmins = $Known; AccessChk = $Check.Detail
        Rules = @($Rules | ForEach-Object { [ordered]@{ File = $_.Name; Sha256 = (Get-ALSha256 $_.FullName) } })
        Settings = $Cfg.SettingsFile; PowerShell = "$($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Dest 'build-info.json') -Encoding UTF8
    # Only the folder name: the whole tree can be moved or copied to another computer
    Set-Content -LiteralPath (Join-Path $Cfg.OutRoot 'latest.txt') -Value $Cfg.Stamp -Encoding Ascii

    $Watch = @(Get-ChildItem -LiteralPath (Join-Path $Dest 'ScanResults') -Filter 'Writable_*.txt' | Select-String -Pattern '\\(ccm|sms|tenable)' )
    if ($Watch.Count) { Write-Host 'MECM / Tenable folders that are user-writable on the reference server (excluded from the allow rules; SYSTEM/admins are unaffected):'; $Watch | ForEach-Object { Write-Host "  $($_.Line)" } }
    Get-ChildItem -LiteralPath $Dest -File | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "Results: $Dest" -ForegroundColor Green
}
finally {
    if ($Session) {
        try { Invoke-Command -Session $Session -ScriptBlock { Set-Location -LiteralPath $env:SystemRoot; if (Test-Path -LiteralPath $using:RemoteWork) { Remove-Item -LiteralPath $using:RemoteWork -Recurse -Force -ErrorAction Stop } } }
        catch { Write-Warning "Could not remove $RemoteWork on ${ComputerName}: $($_.Exception.Message)" }
        Remove-PSSession $Session
    }
    Stop-ALTranscript
}
