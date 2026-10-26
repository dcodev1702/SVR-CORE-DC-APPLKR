# Step 0 (second script) - run from the management computer (Windows PowerShell 5.1 or PowerShell 7) as a Domain Admin / GPO creator.
# Read-only. Checks everything the later steps depend on and reports OK / WARN / FAIL / INFO (console + Logs\0_AL_pre-flight-<ts>.csv):
#   management computer (modules), domain + GPO rights, target OUs and their servers, toolkit, the two GPOs, and - on the reference
#   server and every server in the target OUs - WinRM, language mode, script execution policy, any existing AppLocker policy,
#   Configuration Manager (MECM client / site server), Tenable Nessus, services and scheduled tasks that run code from outside the
#   folders the baseline allows, and whether every ExtraAllowedPaths entry (C:\Admin ...) can be changed by administrators only.
param(
    [string]$SettingsFile,
    [string]$ReferenceServer,
    [string[]]$TargetOU
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_pre-flight' -SettingsFile $SettingsFile -Overrides @{ ReferenceServer = $ReferenceServer; TargetOUs = $TargetOU }
$R = New-ALResults
$Failed = 1

# Runs on a server: facts the policy design depends on. $Extra = the ExtraAllowedPaths setting.
$Probe = {
    param([string[]]$Extra)
    $o = [ordered]@{}
    $os = Get-CimInstance Win32_OperatingSystem
    $o.Os = "$($os.Caption) $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType) $($os.Version)"
    $o.Language = "$($ExecutionContext.SessionState.LanguageMode)"
    $o.PsVersion = "$($PSVersionTable.PSVersion)"
    $o.ExecPolicy = "$(Get-ExecutionPolicy)"
    $o.AppLockerModule = [bool](Get-Module -ListAvailable AppLocker)
    $svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $o.AppId = "$($svc.State)/$($svc.StartMode)"
    $o.EffectiveRules = 0; $o.LocalRules = 0; $o.ServicesEnforcement = ''
    try {
        [xml]$eff = Get-AppLockerPolicy -Effective -Xml
        $o.EffectiveRules = @($eff.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
        $o.ServicesEnforcement = (@($eff.AppLockerPolicy.RuleCollection | ForEach-Object { $_.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode } | Where-Object { $_ } | Select-Object -Unique)) -join ','
        [xml]$loc = Get-AppLockerPolicy -Local -Xml
        $o.LocalRules = @($loc.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
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

    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Targets = Get-ALTargetComputers $Ous $Domain
    foreach ($Ou in $Ous) { Add-ALResult $R 'OK' 'Target OU' $Ou }
    if ($Targets.Count) { Add-ALResult $R 'OK' 'Servers in scope' "$($Targets.Count): $($Targets -join ', ')" } else { Add-ALResult $R 'WARN' 'Servers in scope' 'no enabled Windows Server computer accounts in the target OUs' }
    if ($Cfg.ReferenceServer) { Add-ALResult $R 'OK' 'Reference server' $Cfg.ReferenceServer }
    else { Add-ALResult $R 'WARN' 'Reference server' "not set - set ReferenceServer in the settings before 1_AL_build_policy.ps1 (a server in scope that looks like the others; for DCs any DC, e.g. the PDC emulator $($Domain.PDC))" }

    if (Test-Path -LiteralPath (Join-Path $Cfg.ToolkitPath 'Create-Policies.ps1')) { Add-ALResult $R 'OK' 'AaronLocker' $Cfg.ToolkitPath } else { Add-ALResult $R 'FAIL' 'AaronLocker' "not found at $($Cfg.ToolkitPath) - it ships in this repository; run 0_AL_get_toolkit.ps1" }
    $Acc = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if ($Acc.Ok) { Add-ALResult $R $(if ($Cfg.AccessChkSha256) { 'OK' } else { 'WARN' }) 'AccessChk.exe' "$($Acc.Detail)$(if (-not $Cfg.AccessChkSha256) { ' - pin it: AccessChkSha256 in the settings' })" }
    else { Add-ALResult $R 'FAIL' 'AccessChk.exe' "$($Acc.Detail) - run 0_AL_get_toolkit.ps1" }
    $Overlay = Join-Path $Cfg.Root 'Customizations\CustomizationInputs'
    if ((Test-Path -LiteralPath (Join-Path $Overlay 'GetSafePathsToAllow.ps1')) -and (Test-Path -LiteralPath (Join-Path $Overlay 'KnownAdmins.ps1'))) { Add-ALResult $R 'OK' 'Customizations' 'overlay folder present' } else { Add-ALResult $R 'FAIL' 'Customizations' "missing or incomplete: $Overlay" }
    if (@($Cfg.KnownAdmins).Count) { Add-ALResult $R 'INFO' 'KnownAdmins' "treated as administrators: $(@($Cfg.KnownAdmins) -join ', ')" }

    foreach ($Pair in @(@('Audit', $Cfg.AuditGpoName), @('Enforce', $Cfg.EnforceGpoName))) {
        $G = Get-GPO -Name $Pair[1] -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $G) { Add-ALResult $R 'INFO' "$($Pair[0]) GPO" "'$($Pair[1])' does not exist yet (created by 2_AL_create_gpos.ps1)"; continue }
        $States = foreach ($Ou in $Ous) { $S = Get-ALLinkState $G.Id $Ou $Domain; "$(if ($null -eq $S) { 'not linked' } elseif ($S) { 'ENABLED' } else { 'disabled' })" }
        Add-ALResult $R 'INFO' "$($Pair[0]) GPO" "'$($Pair[1])' exists; links: $($States -join ', ')"
    }

    # Reference server first, then every target server
    $Seen = @{}
    foreach ($C in @(@($Cfg.ReferenceServer) + $Targets | Where-Object { $_ })) {
        if ($Seen[$C.ToLower()]) { continue }; $Seen[$C.ToLower()] = $true
        $IsRef = ($C -eq $Cfg.ReferenceServer)
        $Tag = if ($IsRef) { "$C (reference)" } else { $C }
        try { $P = Invoke-Command -ComputerName $C -ScriptBlock $Probe -ArgumentList (, @($Cfg.ExtraAllowedPaths)) -ErrorAction Stop }
        catch { Add-ALResult $R 'FAIL' "WinRM $Tag" $_.Exception.Message; continue }
        Add-ALResult $R 'OK' "Server $Tag" "$($P.Os); PowerShell $($P.PsVersion)"
        if ($P.Language -eq 'FullLanguage') { Add-ALResult $R 'OK' "Language mode $Tag" 'FullLanguage (AaronLocker needs it)' } else { Add-ALResult $R 'FAIL' "Language mode $Tag" "$($P.Language) - AaronLocker needs FullLanguage" }
        if ($P.ExecPolicy -in 'AllSigned', 'Restricted') { Add-ALResult $R $(if ($IsRef) { 'FAIL' } else { 'INFO' }) "Execution policy $Tag" "$($P.ExecPolicy) - AaronLocker's scripts are not signed and cannot run there$(if ($IsRef) { ' (the build runs them on this server)' })" }
        if (-not $P.AppLockerModule) { Add-ALResult $R 'FAIL' "AppLocker module $Tag" 'missing' }
        Add-ALResult $R 'INFO' "Application Identity $Tag" $P.AppId
        if ($P.LocalRules -gt 0) { Add-ALResult $R 'WARN' "Local AppLocker policy $Tag" "$($P.LocalRules) rule(s) in the LOCAL policy; they merge with the GPO policy (MECM managed-installer rules land here - README, MECM)" }
        if ($P.EffectiveRules -gt 0) { Add-ALResult $R 'INFO' "Effective AppLocker policy $Tag" "$($P.EffectiveRules) rule(s) already effective (from GPO and/or local policy)" }
        if ($P.ServicesEnforcement -match 'Enabled') { Add-ALResult $R 'WARN' "Services enforcement $Tag" 'the effective policy applies AppLocker to services too (usually from an MECM managed-installer policy) - services from outside the allowed folders can be blocked' }
        if ($P.MecmClient) { Add-ALResult $R 'INFO' "MECM client $Tag" "$($P.MecmClient) - runs as SYSTEM, not restricted (README, MECM)" }
        if ($P.MecmSiteDir) { Add-ALResult $R 'WARN' "MECM site server $Tag" "installed in '$($P.MecmSiteDir)'; services: $($P.MecmServices -join ', '). Site systems are a separate server class with their own settings file, reference server and GPO pair." }
        if ($P.Sql.Count) { Add-ALResult $R 'INFO' "SQL Server $Tag" "running: $($P.Sql -join ', ')" }
        foreach ($N in $P.Nessus) { Add-ALResult $R 'INFO' "Tenable Nessus $Tag" "$N - a service, not restricted by this policy (README, Nessus)" }
        foreach ($S in $P.OutsideServices) {
            if ($P.ServicesEnforcement -match 'Enabled') { Add-ALResult $R 'WARN' "Service outside allowed folders $Tag" "$S - can be BLOCKED in Enforce because services enforcement is on; add its folder to ExtraAllowedPaths (admin-only!)" }
            else { Add-ALResult $R 'INFO' "Service outside allowed folders $Tag" "$S - services are not evaluated by this policy; anything it starts as a user is (watch the Audit events)" }
        }
        foreach ($T in $P.OutsideTasks) { Add-ALResult $R 'WARN' "Task outside allowed folders $Tag" "$T - for a non-admin or non-elevated account this is BLOCKED in Enforce; add the folder to ExtraAllowedPaths (admin-only!) or move the file" }

        # Every ExtraAllowedPaths entry (C:\Admin, MECM, SQL ...) must be changeable by administrators only on this server
        if (@($Cfg.ExtraAllowedPaths).Count) {
            try { $Found = @(Invoke-ALWritableCheck -Paths $Cfg.ExtraAllowedPaths -Cfg $Cfg -ComputerName $C) }
            catch { Add-ALResult $R 'FAIL' "Extra paths $Tag" "permission check failed: $($_.Exception.Message)"; continue }
            foreach ($F in $Found) {
                switch ($F.Kind) {
                    'WRITABLE' { Add-ALResult $R 'FAIL' "Extra path writable $Tag" "$($F.Path) can be changed by $($F.Account) - a path rule there is a bypass. Remove that access (README, C:\Admin), or add the group to KnownAdmins if it is an administrators group." }
                    'NOTFOUND' { Add-ALResult $R 'WARN' "Extra path missing $Tag" "$($F.Path) does not exist. Create it administrators-only BEFORE the policy is used (README, C:\Admin)." }
                    'UNREADABLE' { Add-ALResult $R 'WARN' "Extra path unreadable $Tag" "$($F.Path): permissions could not be read" }
                    'UNRESOLVED' { Add-ALResult $R 'WARN' "KnownAdmins $Tag" "'$($F.Path)' could not be resolved on this server" }
                }
            }
            $Ok = @($Cfg.ExtraAllowedPaths | Where-Object { $E = $_; -not @($Found | Where-Object { $_.Kind -in 'WRITABLE', 'NOTFOUND', 'UNREADABLE' -and (($_.Path -eq $E) -or (Test-ALPathUnder $_.Path $E)) }).Count })
            if ($Ok.Count) { Add-ALResult $R 'OK' "Extra paths admin-only $Tag" ($Ok -join ', ') }
        }
    }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R $Cfg 'Pre-flight'
    Write-Host "Transcript: $($Cfg.Transcript)"
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
