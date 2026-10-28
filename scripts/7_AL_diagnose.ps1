<#
.SYNOPSIS
    When a server does not apply the policy - read-only diagnostics of AppLocker on a server: event 8000 (AppID policy conversion
    failed) with its status decoded, the Application Identity service and driver, the AppLocker and packaged-app components of the
    installation, the event provider, what Group Policy delivered against what is effective, gpresult, and the related Group Policy,
    AppID and service events. Evidence files per server.

.DESCRIPTION
    Run from the management computer (every server in the target OUs, or -ComputerName) or ON the server itself with -Local (the
    Server Core console; no RSAT, no domain query, no WinRM - copy the repository folder to the server first). Nothing is changed;
    the server is only read. It collects, judges (OK / WARN / FAIL / INFO) and saves:
      - the installation: Windows version and update level (UBR), Server Core or Desktop Experience, last boot, the newest updates,
        installed roles / features and capabilities
      - the AppLocker components in System32: appid.sys (the driver), appidsvc.dll (the service), appidapi.dll, AppIdPolicyEngineApi.dll
        (the policy engine), AppIdPolicyConverter.exe, appidcertstorecheck.exe, srpapi.dll (also the event provider's message file),
        the AppLocker PowerShell module - and the packaged-app (Appx) components the Appx rule collection depends on. Present or
        missing, with versions
      - the Application Identity service (state, start type, account, protection, service DLL) and the appid driver
      - the Microsoft-Windows-AppLocker event provider and its message file: when it is missing, Event Viewer shows "The description
        for Event ID 8000 from source Microsoft-Windows-AppLocker cannot be found" instead of the message
      - the AppLocker policy events of the last -Days days: 8001 (the policy was applied) and 8000 (AppID policy conversion failed) with
        the Status of every 8000 decoded (2 = The system cannot find the file specified, 126 = The specified module could not be found,
        1168 = Element not found, ...), and the counts of the other AppLocker events per log
      - the policy sources: what the GPO wrote to the registry (SrpV2: collections, modes, rule counts, the rules themselves), the local
        policy, the effective policy - and whether what Group Policy delivered is effective at all
      - gpresult for the computer: the GPOs applied and not applied (with the reason), the Registry and Security extension results
      - the Group Policy operational events of those extensions, the AppID operational events, the Service Control Manager events for
        Application Identity
      - sample rule decisions (cmd.exe and cipher.exe, for Everyone and for Administrators) when an effective policy exists
    A FAIL names what stops the policy on that server; a WARN names a likely cause or something to check; the rest is INFO.
    Evidence: Outputs\<profile>\diag-<timestamp>\<server>\ (CSV, XML and text files, the raw gpresult output). The rows: console and
    Logs\7_AL_diagnose-<timestamp>.csv. README, Appendix D; SERVER-2022.md, section 7 (event 8000 on Server Core 2022).

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER ComputerName
    Servers to diagnose (over WinRM; no module needed). Default: every Windows Server computer in the target OUs (read from Active
    Directory, which needs the ActiveDirectory module).

.PARAMETER Local
    Diagnose this computer: run the script on the server itself (Server Core console). No module, no domain query, no WinRM.

.PARAMETER TargetOU
    Distinguished names of the OUs whose servers are diagnosed. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER Days
    Window of the events collected, in days (1-365). Default: 30.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: a Status / Check / Detail table per server and "Diagnosis: PASSED" or "FAILED". Files:
    Outputs\<profile>\diag-<timestamp>\<server>\ (components.csv, services.csv, applocker-logs.csv, policy-events.csv, events-8000.xml,
    applocker-event-counts.csv, appid-operational.csv, scm-appidsvc.csv, grouppolicy-events.csv, decisions.csv, policy-from-gpo-registry.xml,
    policy-local.xml, policy-effective.xml, system.txt, <server>-gpresult.txt and .xml), Logs\7_AL_diagnose-<timestamp>.csv, transcript
    in Logs\7_AL_diagnose-<timestamp>.log. Exit code 1 on any FAIL.

.EXAMPLE
    .\7_AL_diagnose.ps1
    Every server in the target OUs, from the management computer.

.EXAMPLE
    .\7_AL_diagnose.ps1 -ComputerName dc22-01.contoso.com -Days 7
    One server, the events of the last week.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\7_AL_diagnose.ps1 -Local
    On the server itself (Server Core console), with the repository copied to the server.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-27
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; from the management computer the RSAT ActiveDirectory module and WinRM; with
               -Local nothing beyond an elevated session on the server (gpresult needs it).
    Changes  : nothing (read-only).
    README   : Appendix D (troubleshooting); SERVER-2022.md, section 7.
#>
param(
    [string]$SettingsFile,
    [string[]]$ComputerName,
    [switch]$Local,
    [string[]]$TargetOU,
    [ValidateRange(1, 365)][int]$Days = 30
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '7_AL_diagnose' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
$R = New-ALResults
$Failed = 1

# The components looked for under %windir%. Core: needed for any AppLocker rule collection. Appx: what packaged-app rules and their
# signature checks depend on (not needed for Exe / Msi / Script rules). Mui: English resources - missing ones only affect messages.
$CoreFiles = 'System32\drivers\appid.sys', 'System32\appidsvc.dll', 'System32\appidapi.dll', 'System32\AppIdPolicyEngineApi.dll', 'System32\AppIdPolicyConverter.exe', 'System32\appidcertstorecheck.exe', 'System32\srpapi.dll', 'System32\wintrust.dll', 'System32\WindowsPowerShell\v1.0\Modules\AppLocker\AppLocker.psd1'
$AppxFiles = 'System32\AppxSip.dll', 'System32\AppxPackaging.dll', 'System32\AppxAllUserStore.dll', 'System32\AppXDeploymentClient.dll', 'System32\AppXDeploymentServer.dll', 'System32\AppXDeploymentExtensions.onecore.dll', 'System32\AppXDeploymentExtensions.desktop.dll'
$MuiFiles = 'System32\en-US\srpapi.dll.mui', 'System32\en-US\appidsvc.dll.mui'

# Runs on the server (or here with -Local). Reads only.
$Probe = {
    param([string[]]$Files, [int]$Days)
    $ErrorActionPreference = 'Continue'
    $ProgressPreference = 'SilentlyContinue'
    $o = [ordered]@{}
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $os = Get-CimInstance Win32_OperatingSystem
    $o.Computer = $env:COMPUTERNAME
    $o.Build = [int]$cv.CurrentBuild; $o.Ubr = [int]$cv.UBR; $o.InstallType = "$($cv.InstallationType)"
    $o.Os = "$($os.Caption) $($cv.InstallationType), build $($cv.CurrentBuild).$($cv.UBR) ($($cv.EditionID))"
    $o.LastBoot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
    $o.PsVersion = "$($PSVersionTable.PSVersion)"; $o.Language = "$($ExecutionContext.SessionState.LanguageMode)"
    $o.Hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 10 | ForEach-Object { "$($_.HotFixID) $($_.Description)$(if ($_.InstalledOn) { ' ' + $_.InstalledOn.ToString('yyyy-MM-dd') })" })
    $o.Features = @(); try { $o.Features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed } | ForEach-Object { $_.Name }) } catch { }   # not on a client OS
    $o.Capabilities = @(); try { $o.Capabilities = @(Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Installed' } | ForEach-Object { $_.Name }) } catch { }
    $o.Components = @(foreach ($f in $Files) {
            $p = Join-Path $env:windir $f; $i = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
            [pscustomobject]@{ File = $f; Exists = [bool]$i; Version = $(if ($i -and $i.VersionInfo) { "$($i.VersionInfo.FileVersion)" } else { '' }); Bytes = $(if ($i) { [int64]$i.Length } else { 0 }); Modified = $(if ($i) { $i.LastWriteTime.ToString('yyyy-MM-dd') } else { '' }) }
        })
    $o.Services = @(foreach ($n in 'AppIDSvc', 'CryptSvc', 'RpcSs', 'gpsvc', 'AppXSvc', 'ClipSVC', 'StateRepository') {
            $s = Get-CimInstance Win32_Service -Filter "Name='$n'"
            [pscustomobject]@{ Name = $n; State = $(if ($s) { "$($s.State)" } else { 'ABSENT' }); Start = $(if ($s) { "$($s.StartMode)" } else { '' }); Account = $(if ($s) { "$($s.StartName)" } else { '' }); Path = $(if ($s) { "$($s.PathName)" } else { '' }) }
        })
    $d = Get-CimInstance Win32_SystemDriver -Filter "Name='AppID'"
    $o.Driver = $(if ($d) { "$($d.State)/$($d.StartMode) $($d.PathName)" } else { 'ABSENT' })
    $k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc' -ErrorAction SilentlyContinue
    $kp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc\Parameters' -ErrorAction SilentlyContinue
    $o.AppIdSvcConfig = "Start=$($k.Start) Type=$($k.Type) LaunchProtected=$($k.LaunchProtected) ImagePath=$($k.ImagePath) ServiceDll=$($kp.ServiceDll)"
    try {
        $pr = Get-WinEvent -ListProvider 'Microsoft-Windows-AppLocker' -ErrorAction Stop
        $mf = [Environment]::ExpandEnvironmentVariables("$($pr.MessageFilePath)")
        $o.Provider = [pscustomobject]@{ Registered = $true; MessageFile = $mf; MessageFileExists = [bool]($mf -and (Test-Path -LiteralPath $mf)); Logs = @($pr.LogLinks | ForEach-Object { $_.LogName }); Error = '' }
    }
    catch { $o.Provider = [pscustomobject]@{ Registered = $false; MessageFile = ''; MessageFileExists = $false; Logs = @(); Error = $_.Exception.Message } }
    $o.Logs = @(Get-WinEvent -ListLog 'Microsoft-Windows-AppLocker/*' -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Log = $_.LogName; Enabled = $_.IsEnabled; Records = $_.RecordCount; MaxMB = [int]($_.MaximumSizeInBytes / 1MB); LastWrite = $(if ($_.LastWriteTime) { $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }) } })
    $since = (Get-Date).AddDays(-$Days)
    $o.PolicyEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8000, 8001; StartTime = $since } -MaxEvents 500 -ErrorAction SilentlyContinue | ForEach-Object {
            $x = $_.ToXml(); $st = ''
            if ($_.Id -eq 8000) { try { $st = "$(([xml]$x).Event.EventData.Data | Where-Object { $_.Name -eq 'Status' } | ForEach-Object { $_.'#text' })" } catch { } }
            [pscustomobject]@{ Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $_.Id; Status = $st; Message = ("$($_.Message)".Trim() -replace '\s+', ' '); Xml = $x }
        })
    $o.OtherEvents = @(foreach ($log in 'EXE and DLL', 'MSI and Script', 'Packaged app-Execution', 'Packaged app-Deployment') {
            $ev = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-AppLocker/$log"; StartTime = $since } -ErrorAction SilentlyContinue)
            [pscustomobject]@{ Log = $log; Total = $ev.Count; ById = (($ev | Group-Object Id | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ') }
        })
    $o.AppIdOperational = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppID/Operational'; StartTime = $since } -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $_.Id; Level = "$($_.LevelDisplayName)"; Message = ("$($_.Message)".Trim() -replace '\s+', ' ') } })
    $o.ScmEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; StartTime = $since } -MaxEvents 3000 -ErrorAction SilentlyContinue | Where-Object { "$($_.Message)" -match 'Application Identity|AppIDSvc' } | Select-Object -First 30 | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $_.Id; Level = "$($_.LevelDisplayName)"; Message = ("$($_.Message)".Trim() -replace '\s+', ' ') } })
    $o.GpEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; Id = 4016, 5016, 6016, 7016, 1085, 1125, 1126, 1129; StartTime = $since } -MaxEvents 400 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 1085, 1125, 1126, 1129 -or "$($_.Message)" -match 'Registry|Security' } | Select-Object -First 40 | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $_.Id; Level = "$($_.LevelDisplayName)"; Message = ("$($_.Message)".Trim() -replace '\s+', ' ') } })
    # Policy sources: the GPO's registry keys (EnforcementMode absent = NotConfigured, 0 = AuditOnly, 1 = Enabled), local, effective
    $o.GpoCollections = @(); $o.GpoRules = 0; $o.GpoPolicyXml = ''
    $srp = Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -ErrorAction SilentlyContinue
    if ($srp) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('<AppLockerPolicy Version="1">')
        foreach ($c in @(Get-ChildItem -LiteralPath $srp.PSPath -ErrorAction SilentlyContinue)) {
            $mode = $c.GetValue('EnforcementMode')
            $modeText = if ($null -eq $mode) { 'NotConfigured' } elseif ("$mode" -eq '1') { 'Enabled' } elseif ("$mode" -eq '0') { 'AuditOnly' } else { "EnforcementMode=$mode" }
            $rules = @(Get-ChildItem -LiteralPath $c.PSPath -ErrorAction SilentlyContinue)
            $o.GpoCollections += "$($c.PSChildName)=$modeText($($rules.Count))"
            $o.GpoRules += $rules.Count
            [void]$sb.Append("<RuleCollection Type=`"$($c.PSChildName)`" EnforcementMode=`"$modeText`">")
            foreach ($r in $rules) { [void]$sb.Append("$($r.GetValue('Value'))") }
            [void]$sb.Append('</RuleCollection>')
        }
        [void]$sb.Append('</AppLockerPolicy>')
        $o.GpoPolicyXml = $sb.ToString()
    }
    $o.LocalXml = ''; $o.EffectiveXml = ''; $o.Effective = ''; $o.EffectiveError = ''; $o.EffectiveRules = -1
    try { $o.LocalXml = "$(Get-AppLockerPolicy -Local -Xml)" } catch { $o.LocalXml = '' }
    try {
        $o.EffectiveXml = "$(Get-AppLockerPolicy -Effective -Xml)"
        [xml]$eff = $o.EffectiveXml
        $o.Effective = (@($eff.AppLockerPolicy.RuleCollection | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count))" }) -join ', ')
        if (-not $o.Effective) { $o.Effective = 'empty (no rule collection)' }
        $o.EffectiveRules = @($eff.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
    }
    catch { $o.EffectiveError = $_.Exception.Message }
    $o.SrpGp = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) values: $(($_.GetValueNames()) -join ',')" })
    $o.Decisions = @()
    if ($o.EffectiveRules -gt 0) {
        $pol = Get-AppLockerPolicy -Effective
        foreach ($t in @(@{ Path = "$env:windir\System32\cmd.exe"; User = 'Everyone' }, @{ Path = "$env:windir\System32\cipher.exe"; User = 'Everyone' }, @{ Path = "$env:windir\System32\cipher.exe"; User = 'BUILTIN\Administrators' })) {
            try { $dec = Test-AppLockerPolicy -PolicyObject $pol -Path $t.Path -User $t.User -ErrorAction Stop; $o.Decisions += [pscustomobject]@{ File = $t.Path; User = $t.User; Decision = "$($dec.PolicyDecision)"; Rule = "$($dec.MatchingRule)" } }
            catch { $o.Decisions += [pscustomobject]@{ File = $t.Path; User = $t.User; Decision = 'ERROR'; Rule = $_.Exception.Message } }
        }
    }
    $o.AppxPackages = ''
    try { $o.AppxPackages = "$(@(Get-AppxPackage -AllUsers -ErrorAction Stop).Count) packages (Get-AppxPackage works)" } catch { $o.AppxPackages = "Get-AppxPackage failed: $($_.Exception.Message)" }
    [pscustomobject]$o
}

function Save-ALDiagText([string]$Folder, [string]$Name, [string]$Content) {
    [IO.File]::WriteAllText((Join-Path $Folder $Name), "$Content", (New-Object System.Text.UTF8Encoding $false))
}
function Save-ALDiagCsv([string]$Folder, [string]$Name, $Rows) {
    if (@($Rows).Count) { @($Rows) | Export-Csv -LiteralPath (Join-Path $Folder $Name) -NoTypeInformation -Encoding UTF8 } else { Save-ALDiagText $Folder $Name '' }
}

try {
    $Files = @($CoreFiles + $AppxFiles + $MuiFiles)
    if ($Local) { $ComputerName = @($env:COMPUTERNAME) }
    elseif (-not $ComputerName) {
        # Only the default scope needs Active Directory; a named server is reached over WinRM without any module
        Import-ALModule ActiveDirectory
        $Domain = Get-ALDomainInfo
        $ComputerName = Get-ALTargetComputers (Resolve-ALTargetOUs $Cfg $Domain) $Domain
    }
    if (-not @($ComputerName).Count) { throw 'STOP: no servers - none in the target OUs and no -ComputerName.' }
    $Evidence = Join-Path $Cfg.OutRoot "diag-$($Cfg.Stamp)"
    foreach ($C in $ComputerName) {
        Write-Host "`n$C : collecting (components, service, events of the last $Days days, policy sources, gpresult) ..." -ForegroundColor Cyan
        try {
            if ($Local) { $P = & $Probe $Files $Days; $Gp = Invoke-ALGpRefresh -Refresh $false -Local }
            else { $P = Invoke-ALOn $C $Probe (([string[]]$Files), $Days); $Gp = Invoke-ALGpRefresh -ComputerName $C -Refresh $false }
        }
        catch { Add-ALResult $R 'FAIL' "WinRM $C" $_.Exception.Message; continue }
        $Dir = Join-Path $Evidence ($C -replace '[^A-Za-z0-9.-]', '_')
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null

        # ---- evidence files
        Save-ALDiagCsv $Dir 'components.csv' $P.Components
        Save-ALDiagCsv $Dir 'services.csv' $P.Services
        Save-ALDiagCsv $Dir 'applocker-logs.csv' $P.Logs
        Save-ALDiagCsv $Dir 'policy-events.csv' @($P.PolicyEvents | Select-Object Time, Id, Status, @{ n = 'StatusText'; e = { if ("$($_.Status)" -ne '') { ConvertTo-ALWin32Message $_.Status } else { '' } } }, Message)
        $E8000 = @($P.PolicyEvents | Where-Object { $_.Id -eq 8000 })
        if ($E8000.Count) { Save-ALDiagText $Dir 'events-8000.xml' (($E8000 | ForEach-Object { $_.Xml }) -join "`r`n") }
        Save-ALDiagCsv $Dir 'applocker-event-counts.csv' $P.OtherEvents
        Save-ALDiagCsv $Dir 'appid-operational.csv' $P.AppIdOperational
        Save-ALDiagCsv $Dir 'scm-appidsvc.csv' $P.ScmEvents
        Save-ALDiagCsv $Dir 'grouppolicy-events.csv' $P.GpEvents
        Save-ALDiagCsv $Dir 'decisions.csv' $P.Decisions
        if ($P.GpoPolicyXml) { Save-ALDiagText $Dir 'policy-from-gpo-registry.xml' $P.GpoPolicyXml }
        if ($P.LocalXml) { Save-ALDiagText $Dir 'policy-local.xml' $P.LocalXml }
        if ($P.EffectiveXml) { Save-ALDiagText $Dir 'policy-effective.xml' $P.EffectiveXml }
        Save-ALDiagText $Dir 'system.txt' ((@(
                    "Computer: $($P.Computer)", "OS: $($P.Os)", "Last boot: $($P.LastBoot)", "PowerShell: $($P.PsVersion) ($($P.Language))",
                    "AppIDSvc: $($P.AppIdSvcConfig)", "appid driver: $($P.Driver)",
                    "Event provider Microsoft-Windows-AppLocker: registered=$($P.Provider.Registered) messageFile=$($P.Provider.MessageFile) exists=$($P.Provider.MessageFileExists) logs=$($P.Provider.Logs -join ';') $($P.Provider.Error)",
                    "Packaged apps: $($P.AppxPackages)",
                    "GPO policy in the registry (HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2): $(if ($P.GpoCollections.Count) { $P.GpoCollections -join ', ' } else { 'none' })",
                    "Effective policy: $($P.Effective) $($P.EffectiveError)",
                    'HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp:') + @($P.SrpGp | ForEach-Object { "  $_" }) + @('', 'Newest updates:') + @($P.Hotfixes | ForEach-Object { "  $_" }) + @('', "Features: $($P.Features -join ', ')", '', "Capabilities: $($P.Capabilities -join ', ')")) -join "`r`n")
        $GpFile = Save-ALGpResult $Gp $Dir

        # ---- judgement
        Add-ALResult $R 'INFO' "System $C" "$($P.Os); last boot $($P.LastBoot); PowerShell $($P.PsVersion) $($P.Language); newest updates: $(if ($P.Hotfixes.Count) { ($P.Hotfixes | Select-Object -First 3) -join ', ' } else { 'none listed' })"
        # A file counts as present only when the probe reported it so (a missing row counts as missing, never as present)
        $Present = @($P.Components | Where-Object { "$($_.Exists)" -eq 'True' } | ForEach-Object { "$($_.File)" })
        $MissingCore = @($CoreFiles | Where-Object { $_ -notin $Present })
        $MissingAppx = @($AppxFiles | Where-Object { $_ -notin $Present })
        $MissingMui = @($MuiFiles | Where-Object { $_ -notin $Present })
        $Ver = { param($F) $X = @($P.Components | Where-Object { "$($_.File)" -eq $F }) | Select-Object -First 1; $Leaf = Split-Path $F -Leaf; if ($X -and "$($X.Exists)" -eq 'True') { "$Leaf $("$($X.Version)" -replace ' \(.*\)$', '')" } else { "$Leaf MISSING" } }
        if ($MissingCore.Count) { Add-ALResult $R 'FAIL' "Components $C" "missing under $env:windir\: $($MissingCore -join ', ') - AppLocker cannot convert or enforce a policy without them. Compare with a working server of the same version (components.csv); a cumulative update or an in-place repair restores them" }
        else { Add-ALResult $R 'OK' "Components $C" "all $($CoreFiles.Count) AppLocker components present: $(& $Ver 'System32\drivers\appid.sys'), $(& $Ver 'System32\appidsvc.dll'), $(& $Ver 'System32\AppIdPolicyEngineApi.dll'), $(& $Ver 'System32\srpapi.dll') (components.csv)" }
        if ($MissingAppx.Count) { Add-ALResult $R 'WARN' "Packaged-app components $C" "missing: $($MissingAppx -join ', ') - the Appx (packaged app) rule collection depends on them; $($P.AppxPackages). If the delivered policy carries Appx rules and event 8000 appears here, test a policy without the Appx collection (EnableAppxRules = `$false, SERVER-2022.md section 7)" }
        else { Add-ALResult $R 'INFO' "Packaged-app components $C" "present ($(& $Ver 'System32\AppxSip.dll')); $($P.AppxPackages)" }
        if ($MissingMui.Count) { Add-ALResult $R 'INFO' "Resources $C" "missing: $($MissingMui -join ', ') - only affects how messages are displayed" }
        $Svc = @($P.Services | Where-Object { $_.Name -eq 'AppIDSvc' }) | Select-Object -First 1
        $Delivered = ($P.GpoRules -gt 0)
        if ($Svc.State -eq 'ABSENT') { Add-ALResult $R 'FAIL' "AppIDSvc $C" 'the Application Identity service does not exist on this installation' }
        elseif ($Svc.State -eq 'Running' -and $Svc.Start -eq 'Auto') { Add-ALResult $R 'OK' "AppIDSvc $C" "Running/Auto as $($Svc.Account) ($($P.AppIdSvcConfig))" }
        elseif ($Delivered) { Add-ALResult $R 'FAIL' "AppIDSvc $C" "$($Svc.State)/$($Svc.Start) although Group Policy delivered rules - expected Running/Auto (the GPO sets it; gpupdate twice or reboot; $($P.AppIdSvcConfig))" }
        else { Add-ALResult $R 'INFO' "AppIDSvc $C" "$($Svc.State)/$($Svc.Start) - no AppLocker rules delivered yet, so this is normal ($($P.AppIdSvcConfig))" }
        Add-ALResult $R $(if ($P.Driver -like 'Running/*') { 'OK' } elseif ($Delivered) { 'WARN' } else { 'INFO' }) "appid driver $C" "$($P.Driver)$(if ($P.Driver -notlike 'Running/*') { ' - starts with the Application Identity service' })"
        if ($P.Provider.Registered -and $P.Provider.MessageFileExists) { Add-ALResult $R 'OK' "Event provider $C" "Microsoft-Windows-AppLocker registered, message file $($P.Provider.MessageFile) present; logs: $($P.Provider.Logs.Count)" }
        else { Add-ALResult $R 'WARN' "Event provider $C" "$(if (-not $P.Provider.Registered) { "provider not registered ($($P.Provider.Error))" } else { "message file $($P.Provider.MessageFile) missing" }) - Event Viewer shows 'The description for Event ID ... from source Microsoft-Windows-AppLocker cannot be found' for every AppLocker event; the events still carry their data (the Status of an 8000 is in policy-events.csv / events-8000.xml)" }
        $Off = @($P.Logs | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Log })
        if ($Off.Count) { Add-ALResult $R 'WARN' "AppLocker logs $C" "disabled: $($Off -join ', ')" } else { Add-ALResult $R 'INFO' "AppLocker logs $C" (($P.Logs | ForEach-Object { "$($_.Log -replace '^.*/', '') $($_.Records) records, $($_.MaxMB) MB" }) -join '; ') }
        $E8001 = @($P.PolicyEvents | Where-Object { $_.Id -eq 8001 })
        $Newest = @($P.PolicyEvents) | Select-Object -First 1
        if ($Newest -and $Newest.Id -eq 8000) {
            $First = $E8000[$E8000.Count - 1]
            Add-ALResult $R 'FAIL' "Policy conversion $C" "AppID policy conversion failed (event 8000) $($E8000.Count) time(s) in $Days days, first $($First.Time), newest $($Newest.Time) with status $($Newest.Status) ($(ConvertTo-ALWin32Message $Newest.Status))$(if ($E8001.Count) { "; last success (8001) $($E8001[0].Time)" } else { '; no success (8001) in the window' }). Application Identity rejected the policy it was given: nothing is enforced or audited. See 'Delivered vs effective' below; the raw events are in events-8000.xml"
        }
        elseif ($E8000.Count) { Add-ALResult $R 'WARN' "Policy conversion $C" "$($E8000.Count) older conversion failure(s) (8000) in $Days days, newest $($E8000[0].Time) status $($E8000[0].Status) ($(ConvertTo-ALWin32Message $E8000[0].Status)); the newest event is a success (8001 at $($Newest.Time))" }
        elseif ($E8001.Count) { Add-ALResult $R 'OK' "Policy conversion $C" "no conversion failure (8000) in $Days days; $($E8001.Count) x 8001 (policy applied), newest $($E8001[0].Time)" }
        else { Add-ALResult $R 'INFO' "Policy conversion $C" "no 8000 and no 8001 in $Days days: no AppLocker policy was applied or rejected on this computer in that window" }
        if ($P.EffectiveError) { Add-ALResult $R 'WARN' "Effective policy $C" "Get-AppLockerPolicy -Effective failed: $($P.EffectiveError)" }
        if ($Delivered -and $P.EffectiveRules -eq 0) { Add-ALResult $R 'FAIL' "Delivered vs effective $C" "Group Policy delivered $($P.GpoRules) rule(s) ($($P.GpoCollections -join ', ')) to the registry but the effective policy is empty: Application Identity did not convert them$(if ($Newest -and $Newest.Id -eq 8000) { " (event 8000, status $($Newest.Status): $(ConvertTo-ALWin32Message $Newest.Status))" }). Nothing is enforced or audited" }
        elseif ($Delivered -and $P.EffectiveRules -gt 0) { Add-ALResult $R 'OK' "Delivered vs effective $C" "Group Policy delivered $($P.GpoRules) rule(s) ($($P.GpoCollections -join ', ')); effective: $($P.Effective)" }
        elseif ($P.EffectiveRules -gt 0) { Add-ALResult $R 'INFO' "Delivered vs effective $C" "no AppLocker rules from Group Policy in the registry; the effective policy ($($P.Effective)) comes from the local policy" }
        else { Add-ALResult $R 'INFO' "Delivered vs effective $C" "no AppLocker rules delivered by Group Policy and none effective (see 'GPO applied')" }
        $GpoHasAppx = ($P.GpoPolicyXml -match '<RuleCollection Type="Appx" EnforcementMode="(Enabled|AuditOnly)">\s*<')
        if ($GpoHasAppx -and $P.InstallType -eq 'Server Core' -and ($MissingAppx.Count -or $P.AppxPackages -like 'Get-AppxPackage failed*') -and $Newest -and $Newest.Id -eq 8000) {
            Add-ALResult $R 'WARN' "Hypothesis $C" "the delivered policy carries an Appx (packaged app) rule collection and this Server Core installation lacks packaged-app support ($(if ($MissingAppx.Count) { "missing: $($MissingAppx -join ', ')" } else { $P.AppxPackages })). Test: set EnableAppxRules = `$false in the settings, run 2_AL_create_gpos.ps1 and 3_AL_set_mode.ps1 -Mode <current> -Refresh, then look for 8001 instead of 8000 (SERVER-2022.md, section 7)"
        }
        foreach ($D in $P.Decisions) { Add-ALResult $R 'INFO' "Decision $C" "$($D.User) -> $(Split-Path $D.File -Leaf): $($D.Decision) ($($D.Rule))" }
        Add-ALGpResults $R $C $Gp (ConvertFrom-ALGpResult $Gp.GpresultXml $Gp.GpresultText) 'Any' $Cfg.AuditGpoName $Cfg.EnforceGpoName $GpFile
        $GpErrors = @($P.GpEvents | Where-Object { $_.Id -in 7016, 1085, 1125, 1126, 1129 })
        if ($GpErrors.Count) { Add-ALResult $R 'FAIL' "Group Policy errors $C" "$($GpErrors.Count) error event(s) in $Days days, newest: $($GpErrors[0].Time) event $($GpErrors[0].Id): $($GpErrors[0].Message)" }
        else { Add-ALResult $R 'INFO' "Group Policy events $C" "no extension error (7016 / 1085) for the Registry or Security extension in $Days days; newest: $(if ($P.GpEvents.Count) { "$($P.GpEvents[0].Time) event $($P.GpEvents[0].Id) $($P.GpEvents[0].Message)" } else { 'none' })" }
        Add-ALResult $R 'INFO' "AppID operational $C" $(if ($P.AppIdOperational.Count) { (($P.AppIdOperational | Group-Object Id | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ') + " in $Days days; newest: $($P.AppIdOperational[0].Message)" } else { "no events in $Days days" })
        Add-ALResult $R 'INFO' "Service events $C" $(if ($P.ScmEvents.Count) { "newest: $($P.ScmEvents[0].Time) event $($P.ScmEvents[0].Id) $($P.ScmEvents[0].Message)" } else { "no Service Control Manager event for Application Identity in $Days days" })
        foreach ($E in $P.OtherEvents) { Add-ALResult $R 'INFO' "Events $C" "$($E.Log): $($E.Total) in $Days days $($E.ById)" }
        Add-ALResult $R 'INFO' "Evidence $C" $Dir
    }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R $Cfg 'Diagnosis'
    Write-Host "Transcript: $($Cfg.Transcript)"
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
