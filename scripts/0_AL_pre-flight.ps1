<#
.SYNOPSIS
    Step 2 - read-only pre-flight: checks everything the later steps depend on and reports OK / WARN / FAIL / INFO.

.DESCRIPTION
    Run from the management computer as a Domain Admin (or an account that can read GPOs and use WinRM on the servers). Nothing is
    changed. It checks:
      - the management computer: PowerShell edition, the GroupPolicy, ActiveDirectory and AppLocker modules
      - the domain: PDC emulator, GPO read access, SYSVOL, the target OUs and the servers in them, the reference server and the
        extra reference servers
      - the toolkit: AaronLocker, AccessChk (signature, 64-bit, pinned hash), the Customizations overlay, the KnownAdmins setting
      - the two GPOs: do they exist, which links are enabled
      - on the reference server, every extra reference server and every server in the target OUs, over WinRM: OS, language mode,
        execution policy, the AppLocker module and the Application Identity service, any AppLocker policy already effective (local or
        GPO), PowerShell 2.0 (it bypasses Constrained Language Mode), the Configuration Manager client or site server, SQL Server,
        Tenable Nessus, services and scheduled tasks that run code from outside the folders the baseline allows, and whether every
        ExtraAllowedPaths entry (C:\Admin ...) can be changed by administrators only
      - the Windows Server versions: every server in scope should run the same version and installation type as the reference server
        or one of the extra reference servers - the build only scans those for user-writable folders (SERVER-2022.md)
    A FAIL must be fixed before the build. A WARN says what the build will do about it (README, section 7, step 2).

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER ReferenceServer
    FQDN of the server the baseline will be built on, or PDC (the PDC emulator of this domain). Overrides the setting for this run.

.PARAMETER TargetOU
    Distinguished names of the OUs whose servers are in scope. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER ExtraReferenceServers
    FQDNs of the servers whose scans the build merges in (another Windows Server version in scope). Overrides the setting.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: a Status / Check / Detail table and "Pre-flight: PASSED" or "FAILED". The same rows as CSV in
    Logs\0_AL_pre-flight-<timestamp>.csv; transcript in Logs\0_AL_pre-flight-<timestamp>.log. Exit code 1 on any FAIL.

.EXAMPLE
    .\0_AL_pre-flight.ps1
    Checks the reference server and every server in the target OUs named in the settings.

.EXAMPLE
    .\0_AL_pre-flight.ps1 -ReferenceServer dc01.contoso.com -TargetOU 'OU=Domain Controllers,DC=contoso,DC=com'
    The same, with the scope given on the command line.

.EXAMPLE
    .\0_AL_pre-flight.ps1 -ExtraReferenceServers dc22-01.contoso.com
    Also checks a Server 2022 DC whose scan the build would merge in; every other server's version is compared with both.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-27
    Version  : 1.1 (Windows Server version per server, PowerShell 2.0, ExtraReferenceServers)
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT GroupPolicy and ActiveDirectory modules; WinRM to the servers.
    Changes  : nothing (read-only).
    README   : section 7, step 2 (what each WARN and FAIL means and what to do); SERVER-2022.md (mixed Windows Server versions).
#>
param(
    [string]$SettingsFile,
    [string]$ReferenceServer,
    [string[]]$TargetOU,
    [string[]]$ExtraReferenceServers
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_pre-flight' -SettingsFile $SettingsFile -Overrides @{ ReferenceServer = $ReferenceServer; TargetOUs = $TargetOU; ExtraReferenceServers = $ExtraReferenceServers }
$R = New-ALResults
$Failed = 1

# Runs on a server: facts the policy design depends on. $Extra = the ExtraAllowedPaths setting.
$Probe = {
    param([string[]]$Extra)
    $o = [ordered]@{}
    $ProgressPreference = 'SilentlyContinue'
    $os = Get-CimInstance Win32_OperatingSystem
    $o.InstallType = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType)"
    $o.Os = "$($os.Caption) $($o.InstallType) $($os.Version)"
    $o.Build = [int]$os.BuildNumber
    # PowerShell 2.0 (Windows Server feature PowerShell-V2): Installed / Available / Removed; empty where the feature does not exist
    # (removed from Windows Server 2025) or Get-WindowsFeature cannot run (missing, or a client OS, where it throws)
    $o.PsV2 = ''
    try {
        $f = Get-WindowsFeature -Name PowerShell-V2 -ErrorAction Stop
        if ($f) { $o.PsV2 = "$($f.InstallState)" }
    } catch { }
    $o.Language = "$($ExecutionContext.SessionState.LanguageMode)"
    $o.PsVersion = "$($PSVersionTable.PSVersion)"
    $o.ExecPolicy = "$(Get-ExecutionPolicy)"
    $o.AppLockerModule = [bool](Get-Module -ListAvailable AppLocker)
    $svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $o.AppId = "$($svc.State)/$($svc.StartMode)"
    $o.EffectiveRules = 0; $o.LocalRules = 0; $o.LocalTypes = @(); $o.ServicesEnforcement = ''
    try {
        [xml]$eff = Get-AppLockerPolicy -Effective -Xml
        $o.EffectiveRules = @($eff.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
        $o.ServicesEnforcement = (@($eff.AppLockerPolicy.RuleCollection | ForEach-Object { $_.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode } | Where-Object { $_ } | Select-Object -Unique)) -join ','
        [xml]$loc = Get-AppLockerPolicy -Local -Xml
        $o.LocalRules = @($loc.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
        $o.LocalTypes = @($loc.AppLockerPolicy.RuleCollection | Where-Object { @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count } | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)" })
    } catch { }
    # Configuration Manager
    $ccm = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    $o.MecmClient = if ($ccm) { "CcmExec $($ccm.Status), client $((Get-Item "$env:windir\CCM\CcmExec.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion)" } else { $null }
    $sms = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Setup' -ErrorAction SilentlyContinue
    $o.MecmSiteDir = if ($sms) { $sms.'Installation Directory' } else { $null }
    $o.MecmServices = @(Get-Service -Name 'SMS_*', 'SMSEXEC' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$($_.Status)" })
    $o.Sql = @(Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
    # Tenable Nessus installed on the server (agent or scanner). Agentless credentialed scans leave no service and are not visible here.
    $o.Nessus = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'nessus' -or $_.DisplayName -match 'Tenable|Nessus' } | ForEach-Object { "$($_.Name) ($($_.State), runs as $($_.StartName))" })
    # Folders the baseline lets every account run from: Windows, Program Files, the Defender platform folder, ExtraAllowedPaths
    $allowed = @(@($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:ProgramData\Microsoft\Windows Defender") + @($Extra | ForEach-Object { $_ -replace '\\\*$', '' }) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' })
    $inAllowed = { param([string]$p) foreach ($a in $allowed) { if ($p.StartsWith($a, [StringComparison]::OrdinalIgnoreCase)) { return $true } }; return $false }
    $exeOf = { param([string]$cmd) if ($cmd -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($cmd -match '^\s*(\S+?\.(exe|com))(\s|$)') { $Matches[1] } else { ($cmd.Trim() -split '\s+')[0] } }
    # Running services (other than LocalSystem) whose program is outside those folders
    $o.OutsideServices = @(Get-CimInstance Win32_Service | Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|\.\\LocalSystem)$' -and $_.State -eq 'Running' } | ForEach-Object {
            $exe = [Environment]::ExpandEnvironmentVariables((& $exeOf "$($_.PathName)"))
            if ($exe -and -not (& $inAllowed $exe)) { "$($_.Name) [$($_.StartName)] $exe" }
        })
    # Enabled scheduled tasks (other than SYSTEM) that start a program or script from outside those folders: tasks that run as a user
    # are user-context code, which AppLocker evaluates
    $o.OutsideTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
            $t = $_; $who = "$($t.Principal.UserId)$($t.Principal.GroupId)"
            if ($who -match '^(SYSTEM|S-1-5-18|NT AUTHORITY\\SYSTEM|LocalSystem)$') { return }
            foreach ($a in @($t.Actions | Where-Object { $_.Execute })) {
                $exe = [Environment]::ExpandEnvironmentVariables("$($a.Execute)".Trim('"'))
                $scr = if ("$($a.Arguments)" -match '([A-Za-z]:\\[^"]*?\.(ps1|bat|cmd|vbs|js|wsf))') { [Environment]::ExpandEnvironmentVariables($Matches[1]) } else { '' }
                $bad = @(@($exe, $scr) | Where-Object { $_ -match '^([A-Za-z]:\\|\\\\)' -and -not (& $inAllowed $_) })
                if ($bad.Count) { "$($t.TaskPath)$($t.TaskName) [$who, $($t.Principal.RunLevel)] $($bad -join ' + ')" }
            }
        })
    [pscustomobject]$o
}

try {
    # ---- management computer and domain
    Add-ALResult $R 'INFO' 'Settings' "$($Cfg.SettingsFile) (profile '$($Cfg.Profile)')"
    Add-ALResult $R 'OK' 'PowerShell' "PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition) on $env:COMPUTERNAME"
    foreach ($M in 'GroupPolicy', 'ActiveDirectory', 'AppLocker') {
        if (Test-ALModule $M) { Add-ALResult $R 'OK' "Module $M" 'available' }
        else { Add-ALResult $R 'FAIL' "Module $M" $(if ($M -eq 'AppLocker') { 'missing (built into Windows 10/11 Enterprise and Windows Server)' } else { 'missing - install RSAT from local media (README, Prerequisites): Windows Server: Install-WindowsFeature GPMC, RSAT-AD-PowerShell; Windows 11: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 / Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Source <Features on Demand media> -LimitAccess' }) }
    }
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory
    $Domain = Get-ALDomainInfo
    Add-ALResult $R 'OK' 'Domain' "$($Domain.DnsRoot) ($($Domain.NetBIOS)), PDC emulator $($Domain.PDC)"
    try { Get-GPO -All -Server $Domain.PDC -ErrorAction Stop | Select-Object -First 1 | Out-Null; Add-ALResult $R 'OK' 'GPO read access' 'can read GPOs' } catch { Add-ALResult $R 'FAIL' 'GPO read access' $_.Exception.Message }
    try {
        $Sysvol = "\\$($Domain.PDC)\SYSVOL\$($Domain.DnsRoot)\Policies"
        if (Test-Path -LiteralPath $Sysvol) { Add-ALResult $R 'OK' 'SYSVOL' "$Sysvol reachable" } else { Add-ALResult $R 'FAIL' 'SYSVOL' "$Sysvol not reachable" }
    } catch { Add-ALResult $R 'FAIL' 'SYSVOL' $_.Exception.Message }

    # ---- scope: target OUs, the servers in them, the reference server
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Targets = Get-ALTargetComputers $Ous $Domain
    foreach ($Ou in $Ous) { Add-ALResult $R 'OK' 'Target OU' $Ou }
    if ($Targets.Count) { Add-ALResult $R 'OK' 'Servers in scope' "$($Targets.Count): $($Targets -join ', ')" } else { Add-ALResult $R 'WARN' 'Servers in scope' 'no enabled Windows Server computer accounts in the target OUs' }
    # ReferenceServer = PDC: the PDC emulator of this domain, found now; a lookup that fails is a FAIL and the server is left out below
    try { [void](Resolve-ALReferenceServer $Cfg) } catch { Add-ALResult $R 'FAIL' 'Reference server' "ReferenceServer = PDC, but $($_.Exception.Message)"; $Cfg.ReferenceServer = '' }
    if ($Cfg.ReferenceServerResolved) { Add-ALResult $R 'OK' 'Reference server' "$($Cfg.ReferenceServer) (the PDC emulator of this domain; ReferenceServer = PDC)" }
    elseif ($Cfg.ReferenceServer) { Add-ALResult $R 'OK' 'Reference server' $Cfg.ReferenceServer }
    elseif (@($R | Where-Object { $_.Check -eq 'Reference server' }).Count) { }
    else { Add-ALResult $R 'WARN' 'Reference server' "not set - set ReferenceServer in the settings before 1_AL_build_policy.ps1 (a server in scope that looks like the others; for DCs any DC, e.g. the PDC emulator $($Domain.PDC))" }
    $ExtraRefs = @($Cfg.ExtraReferenceServers | Where-Object { $_ -and $_ -ne $Cfg.ReferenceServer } | Sort-Object -Unique)
    if ($ExtraRefs.Count) { Add-ALResult $R 'INFO' 'Extra reference servers' "$($ExtraRefs -join ', ') - the build scans them too and merges their scans (SERVER-2022.md, section 2)" }

    # ---- toolkit, overlay, KnownAdmins
    if (Test-Path -LiteralPath (Join-Path $Cfg.ToolkitPath 'Create-Policies.ps1')) { Add-ALResult $R 'OK' 'AaronLocker' $Cfg.ToolkitPath } else { Add-ALResult $R 'FAIL' 'AaronLocker' "not found at $($Cfg.ToolkitPath) - it ships in this repository; run 0_AL_get_toolkit.ps1" }
    $Acc = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if ($Acc.Ok) { Add-ALResult $R $(if ($Cfg.AccessChkSha256) { 'OK' } else { 'WARN' }) 'AccessChk.exe' "$($Acc.Detail)$(if (-not $Cfg.AccessChkSha256) { ' - pin it: AccessChkSha256 in the settings' })" }
    else { Add-ALResult $R 'FAIL' 'AccessChk.exe' "$($Acc.Detail) - run 0_AL_get_toolkit.ps1" }
    $Overlay = Join-Path $Cfg.Root 'Customizations\CustomizationInputs'
    if ((Test-Path -LiteralPath (Join-Path $Overlay 'GetSafePathsToAllow.ps1')) -and (Test-Path -LiteralPath (Join-Path $Overlay 'KnownAdmins.ps1'))) { Add-ALResult $R 'OK' 'Customizations' 'overlay folder present' } else { Add-ALResult $R 'FAIL' 'Customizations' "missing or incomplete: $Overlay" }
    if (@($Cfg.KnownAdmins).Count) { Add-ALResult $R 'INFO' 'KnownAdmins' "treated as administrators: $(@($Cfg.KnownAdmins) -join ', ')" }

    # ---- the two GPOs and their links (they may not exist yet)
    foreach ($Pair in @(@('Audit', $Cfg.AuditGpoName), @('Enforce', $Cfg.EnforceGpoName))) {
        $G = Get-GPO -Name $Pair[1] -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $G) { Add-ALResult $R 'INFO' "$($Pair[0]) GPO" "'$($Pair[1])' does not exist yet (created by 2_AL_create_gpos.ps1)"; continue }
        $States = foreach ($Ou in $Ous) { $S = Get-ALLinkState $G.Id $Ou $Domain; "$(if ($null -eq $S) { 'not linked' } elseif ($S) { 'ENABLED' } else { 'disabled' })" }
        Add-ALResult $R 'INFO' "$($Pair[0]) GPO" "'$($Pair[1])' exists; links: $($States -join ', ')"
    }

    # Reference server first, then the extra reference servers, then every target server
    $Seen = @{}
    $Versions = New-Object System.Collections.Generic.List[object]
    foreach ($C in @(@($Cfg.ReferenceServer) + $ExtraRefs + $Targets | Where-Object { $_ })) {
        if ($Seen[$C.ToLower()]) { continue }; $Seen[$C.ToLower()] = $true
        $IsRef = ($C -eq $Cfg.ReferenceServer)
        $IsExtraRef = ($C -in $ExtraRefs)
        $Tag = if ($IsRef) { "$C (reference)" } elseif ($IsExtraRef) { "$C (extra reference)" } else { $C }
        try { $P = Invoke-ALOn $C $Probe (, @($Cfg.ExtraAllowedPaths)) }
        catch { Add-ALResult $R 'FAIL' "WinRM $Tag" $_.Exception.Message; continue }
        Add-ALResult $R 'OK' "Server $Tag" "$($P.Os); PowerShell $($P.PsVersion)"
        $Versions.Add([pscustomobject]@{ Server = $C; Tag = $Tag; IsRef = ($IsRef -or $IsExtraRef); Build = [int]$P.Build; InstallType = "$($P.InstallType)" })
        # AaronLocker runs on the reference server and on every extra reference server
        $BuildsHere = ($IsRef -or $IsExtraRef)
        if ($P.Language -eq 'FullLanguage') { Add-ALResult $R 'OK' "Language mode $Tag" 'FullLanguage (AaronLocker needs it)' } else { Add-ALResult $R 'FAIL' "Language mode $Tag" "$($P.Language) - AaronLocker needs FullLanguage" }
        if ($P.ExecPolicy -in 'AllSigned', 'Restricted') { Add-ALResult $R $(if ($BuildsHere) { 'FAIL' } else { 'INFO' }) "Execution policy $Tag" "$($P.ExecPolicy) - AaronLocker's scripts are not signed and cannot run there$(if ($BuildsHere) { ' (the build runs them on this server)' })" }
        if (-not $P.AppLockerModule) { Add-ALResult $R 'FAIL' "AppLocker module $Tag" 'missing' }
        Add-ALResult $R 'INFO' "Application Identity $Tag" $P.AppId
        # PowerShell 2.0 predates Constrained Language Mode, which AppLocker's script rules rely on; this baseline's DLL rules (which
        # would block the 2.0 engine) are off. Windows Server 2025 no longer has the feature.
        if ($P.PsV2 -eq 'Installed') { Add-ALResult $R 'WARN' "PowerShell 2.0 $Tag" "installed - powershell.exe -Version 2 runs without Constrained Language Mode, around AppLocker's script rules (Windows Server 2022 STIG WN22-00-000410 / V-254278). Remove it: Uninstall-WindowsFeature PowerShell-V2 (SERVER-2022.md, section 3)" }
        elseif ($P.PsV2) { Add-ALResult $R 'OK' "PowerShell 2.0 $Tag" "not installed (PowerShell-V2 $($P.PsV2))" }
        if ($P.LocalRules -gt 0) {
            if (@($P.LocalTypes | Where-Object { $_ -like 'ManagedInstaller=*' }).Count) { Add-ALResult $R 'INFO' "MECM managed installer $Tag" "local AppLocker policy ($($P.LocalTypes -join ', ')) merges with the GPO: expected. Its audit-only DLL rules and services enforcement stay; the GPO decides Exe/Msi/Script/Appx (README, MECM)" }
            else { Add-ALResult $R 'WARN' "Local AppLocker policy $Tag" "$($P.LocalRules) rule(s) in the LOCAL policy ($($P.LocalTypes -join ', ')) merge with the GPO policy - review Get-AppLockerPolicy -Local -Xml" }
        }
        if ($P.EffectiveRules -gt 0) { Add-ALResult $R 'INFO' "Effective AppLocker policy $Tag" "$($P.EffectiveRules) rule(s) already effective (from GPO and/or local policy)" }
        if ($P.ServicesEnforcement -match 'Enabled') { Add-ALResult $R 'INFO' "Services enforcement $Tag" 'on (from the MECM managed-installer policy): services are evaluated too - SYSTEM services and services in the allowed folders are unaffected; any at risk are listed below as WARN' }
        if ($P.MecmClient) { Add-ALResult $R 'INFO' "MECM client $Tag" "$($P.MecmClient) - runs as SYSTEM, not restricted (README, MECM)" }
        if ($P.MecmSiteDir) { Add-ALResult $R 'WARN' "MECM site server $Tag" "installed in '$($P.MecmSiteDir)'; services: $($P.MecmServices -join ', '). Site systems are a separate server class with their own settings file, reference server and GPO pair." }
        if ($P.Sql.Count) { Add-ALResult $R 'INFO' "SQL Server $Tag" "running: $($P.Sql -join ', ')" }
        foreach ($N in $P.Nessus) { Add-ALResult $R 'INFO' "Tenable Nessus $Tag" "$N - a service, not restricted by this policy (README, Nessus)" }
        foreach ($S in $P.OutsideServices) {
            if ($P.ServicesEnforcement -match 'Enabled') { Add-ALResult $R 'WARN' "Service outside allowed folders $Tag" "$S - can be BLOCKED in Enforce because services enforcement is on; add its folder to ExtraAllowedPaths (admin-only!)" }
            else { Add-ALResult $R 'INFO' "Service outside allowed folders $Tag" "$S - services are not evaluated by this policy; anything it starts as a user is (watch the Audit events)" }
        }
        foreach ($T in $P.OutsideTasks) { Add-ALResult $R 'WARN' "Task outside allowed folders $Tag" "$T - for a non-admin or non-elevated account this is BLOCKED in Enforce; add the folder to ExtraAllowedPaths (admin-only!) or move the file" }

        # Every ExtraAllowedPaths entry (C:\Admin, MECM, SQL ...) should be changeable by administrators only on this server. If not, the
        # build does not stop: it leaves the entry out (or excepts the items) so the policy never allows what a non-admin can write.
        if (@($Cfg.ExtraAllowedPaths).Count) {
            try { $Found = @(Invoke-ALWritableCheck -Paths $Cfg.ExtraAllowedPaths -Cfg $Cfg -ComputerName $C) }
            catch { Add-ALResult $R 'WARN' "Extra paths $Tag" "permission check failed: $($_.Exception.Message)"; continue }
            foreach ($F in $Found) {
                $Entry = @($Cfg.ExtraAllowedPaths | Where-Object { Test-ALPathUnder $F.Path $_ }) | Select-Object -First 1
                $Effect = if ($F.Kind -in 'WRITABLE', 'UNREADABLE' -and $Entry -and (ConvertTo-ALComparablePath $F.Path) -eq (ConvertTo-ALComparablePath ($Entry -replace '\\\*$', ''))) { "the build will LEAVE $Entry OUT of the policy (non-admins cannot run from it)" } else { 'the build will EXCLUDE it from the rule (non-admins cannot run it)' }
                switch ($F.Kind) {
                    'WRITABLE' { Add-ALResult $R 'WARN' "Extra path writable $Tag" "$($F.Path) can be changed by $($F.Account) - $Effect. To keep it allowed, remove that access (README, C:\Admin) or add the group to KnownAdmins if it is an administrators group." }
                    'NOTFOUND' { Add-ALResult $R 'WARN' "Extra path missing $Tag" "$($F.Path) does not exist. Create it administrators-only BEFORE the policy is used (README, C:\Admin)." }
                    'UNREADABLE' { Add-ALResult $R 'WARN' "Extra path unreadable $Tag" "$($F.Path): permissions could not be read - $Effect" }
                    'UNRESOLVED' { Add-ALResult $R 'WARN' "KnownAdmins $Tag" "'$($F.Path)' could not be resolved on this server" }
                }
            }
            $Ok = @($Cfg.ExtraAllowedPaths | Where-Object { $E = $_; -not @($Found | Where-Object { $_.Kind -in 'WRITABLE', 'NOTFOUND', 'UNREADABLE' -and (($_.Path -eq $E) -or (Test-ALPathUnder $_.Path $E)) }).Count })
            if ($Ok.Count) { Add-ALResult $R 'OK' "Extra paths admin-only $Tag" ($Ok -join ', ') }
        }
    }

    # Windows Server versions: the build scans only the reference server(s) for user-writable folders, so every server in scope should
    # run the Windows build and installation type (Server Core / Server) of one of them
    $RefVersions = @($Versions | Where-Object { $_.IsRef })
    if ($RefVersions.Count) {
        $RefKeys = @($RefVersions | ForEach-Object { "$($_.Build)|$($_.InstallType)" })
        $RefText = (@($RefVersions | ForEach-Object { "$(Get-ALOsLabel $_.Build) $($_.InstallType)" } | Sort-Object -Unique) -join ', ')
        $Odd = @($Versions | Where-Object { -not $_.IsRef -and "$($_.Build)|$($_.InstallType)" -notin $RefKeys })
        foreach ($V in $Odd) { Add-ALResult $R 'WARN' "Version $($V.Server)" "$(Get-ALOsLabel $V.Build) $($V.InstallType), but the reference server(s) run $RefText. The build scans only those for user-writable folders, so folders that only this version makes user-writable would stay allowed here. Add a server like this one to ExtraReferenceServers (SERVER-2022.md, section 2)" }
        if (-not $Odd.Count) { Add-ALResult $R 'OK' 'Versions' "every server checked runs the version of a reference server: $RefText" }
    }
    elseif ($Versions.Count) { Add-ALResult $R 'INFO' 'Versions' 'not compared - no reference server could be checked' }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R $Cfg 'Pre-flight'
    Write-Host "Transcript: $($Cfg.Transcript)"
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
