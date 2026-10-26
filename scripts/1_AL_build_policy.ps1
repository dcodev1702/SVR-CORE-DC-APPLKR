<#
.SYNOPSIS
    Step 4 - builds the AaronLocker AppLocker baseline on the reference server and brings the rule files back to Outputs\.

.DESCRIPTION
    Run from the management computer as a Domain Admin. The rules are built ON the reference server because they depend on that
    machine's file system (user-writable folders under Windows and Program Files, including the MECM client's folders, the tools
    present, the safe paths). The steps:
      1. checks the AccessChk.exe that ships with the toolkit (Microsoft signature, 64-bit, pinned SHA-256); nothing is downloaded
      2. copies the toolkit, the Customizations overlay and the KnownAdmins list to a temporary folder on the server over WinRM
      3. checks every ExtraAllowedPaths entry (C:\Admin ...) on the reference server AND every server in the target OUs, and never
         stops on what it finds: an entry a non-admin can change is LEFT OUT of the policy; items inside it that a non-admin can change
         become EXCEPTIONS of its rule. The policy never allows what a non-admin can write, and no permission is ever changed
      4. runs Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan on the server (it only READS permissions; nothing is applied)
      5. copies the results to <root>\Outputs\<profile>\<timestamp>\ with the exceptions from step 3 and the SHA-256 of every rule
         file recorded in build-info.json, and removes the temporary folder from the server
    Outputs\<profile>\latest.txt names the newest build; 2_AL_create_gpos.ps1 deploys it.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER ComputerName
    FQDN of the server to build on. Default: the ReferenceServer setting (required: one of the servers in scope that looks like the
    others; for domain controllers any DC, the PDC emulator is a good choice).

.PARAMETER ExtraAllowedPaths
    Folders (ending in \*) or files that every account may run from, outside Windows and Program Files. Overrides the setting.

.PARAMETER RemoteWork
    Temporary work folder on the server. It is DELETED before and after the build, so its name must start with AaronLocker.
    Default: C:\AaronLocker.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Files in Outputs\<profile>\<timestamp>\: AppLockerRules-<ts>-Audit.xml and -Enforce.xml, ScanResults\
    (Writable_*.txt = the user-writable folders carved out of the rules), build-info.json (settings, the decision for every
    ExtraAllowedPaths entry, SHA-256 of the rule files). Console: the AaronLocker output and "Results: <folder>". Transcript in
    Logs\1_AL_build_policy-<timestamp>.log. Exit code 1 on a STOP (nothing deployed, the temporary folder removed).

.EXAMPLE
    .\1_AL_build_policy.ps1
    Builds on the ReferenceServer named in the settings.

.EXAMPLE
    .\1_AL_build_policy.ps1 -ComputerName dc01.contoso.com
    Builds on another server in scope.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT ActiveDirectory module; WinRM administrator on the servers; FullLanguage
               mode and an execution policy that runs unsigned scripts on the reference server (AaronLocker's scripts are not signed).
    Changes  : a temporary folder on the reference server (created, then deleted). No policy and no permission is changed.
    README   : section 7, step 4; section 8 (C:\Admin); section 11 (who counts as an administrator).
#>
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
    # 1. the AccessChk that ships with the toolkit must be the verified one
    $Check = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if (-not $Check.Ok) { throw "STOP: AccessChk.exe - $($Check.Detail)" }
    Write-Host "AccessChk.exe: $($Check.Detail)"

    # 2. a fresh temporary work folder on the reference server: toolkit + Customizations overlay
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
    # 3. ExtraAllowedPaths: who can change them, on every server the policy will reach (never stops; decides keep / drop / except)
    $Plan = [pscustomobject]@{ Keep = @(); Drop = @(); Exceptions = @{} }
    $Checked = @(); $Unchecked = @()
    if ($Extra.Count) {
        # Every server the policy will reach, not only the reference: the GPO carries one rule set for all of them
        $Findings = New-Object System.Collections.Generic.List[object]
        @(Invoke-ALWritableCheck -Paths $Extra -Cfg $Cfg -Session $Session) | ForEach-Object { $Findings.Add($_) }
        $Checked += $ComputerName
        $Others = @()
        try { Import-ALModule ActiveDirectory; $Domain = Get-ALDomainInfo; $Others = @(Get-ALTargetComputers (Resolve-ALTargetOUs $Cfg $Domain) $Domain | Where-Object { $_ -ne $ComputerName -and $_ -notlike "$ComputerName.*" -and $ComputerName -notlike "$_.*" }) }
        catch { Write-Warning "Could not list the servers in the target OUs ($($_.Exception.Message)); only the reference server was checked." }
        foreach ($C in $Others) {
            try { @(Invoke-ALWritableCheck -Paths $Extra -Cfg $Cfg -ComputerName $C) | ForEach-Object { $Findings.Add($_) }; $Checked += $C }
            catch { $Unchecked += $C; Write-Warning "$C : ExtraAllowedPaths not checked ($($_.Exception.Message)). Run 4_AL_validate.ps1 for it after deployment." }
        }
        $Plan = Get-ALExtraPathPlan $Extra $Findings
        foreach ($F in @($Findings | Where-Object { $_.Kind -in 'NOTFOUND', 'UNRESOLVED' })) {
            if ($F.Kind -eq 'NOTFOUND') { Write-Warning "$($F.Path) does not exist on $($F.Computer); the rule is still generated. Create that folder administrators-only (0_AL_secure_folders.ps1) before the policy is used." }
            else { Write-Warning "KnownAdmins entry '$($F.Path)' could not be resolved on $($F.Computer)." }
        }
        foreach ($E in $Plan.Keep) {
            if ($Plan.Exceptions.ContainsKey($E)) { Write-Host "Extra allowed path: $E - allowed for every account EXCEPT (non-admins can change these): $($Plan.Exceptions[$E] -join ', ')" -ForegroundColor Yellow }
            else { Write-Host "Extra allowed path: $E - allowed for every account (administrators-only on: $($Checked -join ', '))" }
        }
        foreach ($D in $Plan.Drop) { Write-Host "Extra allowed path: $($D.Entry) - LEFT OUT of the policy: $($D.Reason). Non-admins cannot run from it; elevated administrators still can. Fix its permissions (README, C:\Admin) and rebuild to allow it." -ForegroundColor Yellow }
        $Keep = @($Plan.Keep)
        if ($Keep.Count) { Invoke-Command -Session $Session -ScriptBlock { Set-Content -LiteralPath (Join-Path $using:RemoteWork 'CustomizationInputs\ExtraAllowedPaths.txt') -Value $using:Keep -Encoding UTF8 } }
    }

    # 4. AaronLocker builds the rules on the server (it only reads permissions; nothing is applied there)
    Invoke-Command -Session $Session -ErrorAction Stop -ScriptBlock {
        Set-Location -LiteralPath $using:RemoteWork
        & .\Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan
    }

    # 5. bring the results back, add the exceptions from step 3, record the build (build-info.json, latest.txt)
    $Dest = Join-Path $Cfg.OutRoot $Cfg.Stamp
    New-Item -Path $Dest -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $RemoteWork 'Outputs\*') -Destination $Dest -FromSession $Session -Recurse -Force
    Copy-Item -Path (Join-Path $RemoteWork 'ScanResults') -Destination $Dest -FromSession $Session -Recurse -Force
    $Rules = @(Get-ChildItem -LiteralPath $Dest -Filter 'AppLockerRules-*.xml' -File)
    if (-not @($Rules | Where-Object { $_.Name -like '*-Audit.xml' }).Count -or -not @($Rules | Where-Object { $_.Name -like '*-Enforce.xml' }).Count) { throw "STOP: the build produced no Audit/Enforce rules file in $Dest - see the AaronLocker output above." }
    # Exceptions for items inside an extra path that a non-admin can change (step 3), in both rule files
    if ($Plan.Exceptions.Count) {
        foreach ($R in $Rules) { $N = Add-ALPathExceptions $R.FullName $Plan.Exceptions; Write-Host "  $($R.Name): exceptions added to $N rule(s)" }
    }
    [ordered]@{
        Built = (Get-Date).ToString('s'); ReferenceServer = $ComputerName; KnownAdmins = $Known; AccessChk = $Check.Detail
        ExtraAllowedPaths = [ordered]@{
            Requested = $Extra; Allowed = $Plan.Keep; LeftOut = @($Plan.Drop | ForEach-Object { [ordered]@{ Entry = $_.Entry; Reason = $_.Reason } })
            Exceptions = $Plan.Exceptions; CheckedOn = $Checked; NotChecked = $Unchecked
        }
        Rules = @($Rules | ForEach-Object { [ordered]@{ File = $_.Name; Sha256 = (Get-ALSha256 $_.FullName) } })
        Settings = $Cfg.SettingsFile; PowerShell = "$($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Dest 'build-info.json') -Encoding UTF8
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
