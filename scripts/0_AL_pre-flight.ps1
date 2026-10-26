# Step 0 (second script) - run from the management computer (Windows PowerShell 5.1) as a Domain Admin / GPO creator. Read-only.
# Checks everything the later steps depend on and reports OK / WARN / FAIL / INFO:
#   management computer (modules), domain + GPO rights, target OUs and their servers, toolkit, the two GPOs,
#   and - on the reference server and every server in the target OUs - WinRM, language mode, any existing AppLocker policy,
#   Configuration Manager (MECM client / site server) and services that run as NON-admin accounts from outside Windows / Program Files
#   (those need ExtraAllowedPaths, because SYSTEM and local administrators are allowed everywhere by the baseline).
param(
    [string]$SettingsFile,
    [string]$ReferenceServer,
    [string[]]$TargetOU
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '0_AL_pre-flight' -SettingsFile $SettingsFile -Overrides @{ ReferenceServer = $ReferenceServer; TargetOUs = $TargetOU }
$R = New-ALResults
$Failed = 1

# Runs on a server: facts the policy design depends on
$Probe = {
    $o = [ordered]@{}
    $os = Get-CimInstance Win32_OperatingSystem
    $o.Os = "$($os.Caption) $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType) $($os.Version)"
    $o.Language = "$($ExecutionContext.SessionState.LanguageMode)"
    $o.PsVersion = "$($PSVersionTable.PSVersion)"
    $o.AppLockerModule = [bool](Get-Module -ListAvailable AppLocker)
    $svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $o.AppId = "$($svc.State)/$($svc.StartMode)"
    $o.EffectiveRules = 0; $o.LocalRules = 0
    try {
        [xml]$eff = Get-AppLockerPolicy -Effective -Xml
        $o.EffectiveRules = @($eff.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
        [xml]$loc = Get-AppLockerPolicy -Local -Xml
        $o.LocalRules = @($loc.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
    } catch { }
    # Configuration Manager
    $ccm = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    $o.MecmClient = if ($ccm) { "CcmExec $($ccm.Status), client $((Get-Item "$env:windir\CCM\CcmExec.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion)" } else { $null }
    $sms = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Setup' -ErrorAction SilentlyContinue
    $o.MecmSiteDir = if ($sms) { $sms.'Installation Directory' } else { $null }
    $o.MecmServices = @(Get-Service -Name 'SMS_*', 'SMSEXEC' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$($_.Status)" })
    $o.Sql = @(Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
    # Services that run as an account other than LocalSystem from a binary outside Windows / Program Files
    # (the Defender platform folder in ProgramData is already allowed by AaronLocker's baseline)
    $std = @($env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:SystemDrive\ProgramData\Microsoft\Windows Defender") | Where-Object { $_ }
    $o.OutsideServices = @(Get-CimInstance Win32_Service | Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|\.\\LocalSystem)$' -and $_.State -eq 'Running' } | ForEach-Object {
            $exe = if ($_.PathName -match '^\s*"([^"]+)"') { $Matches[1] } elseif ($_.PathName -match '^\s*(\S+\.exe)') { $Matches[1] } else { $_.PathName }
            if ($exe -and -not ($std | Where-Object { $exe.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) { "$($_.Name) [$($_.StartName)] $exe" }
        })
    [pscustomobject]$o
}

try {
    Add-ALResult $R 'INFO' 'Settings' "$($Cfg.SettingsFile) (profile '$($Cfg.Profile)')"
    Add-ALResult $R 'OK' 'PowerShell' "Windows PowerShell $($PSVersionTable.PSVersion) on $env:COMPUTERNAME"
    foreach ($M in 'GroupPolicy', 'ActiveDirectory', 'AppLocker') {
        if (Get-Module -ListAvailable -Name $M) { Add-ALResult $R 'OK' "Module $M" 'available' }
        else { Add-ALResult $R 'FAIL' "Module $M" $(if ($M -eq 'AppLocker') { 'missing (built into Windows 10/11 Enterprise and Server)' } else { 'missing - install RSAT: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 / Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' }) }
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

    if (Test-Path -LiteralPath (Join-Path $Cfg.ToolkitPath 'Create-Policies.ps1')) { Add-ALResult $R 'OK' 'AaronLocker' $Cfg.ToolkitPath } else { Add-ALResult $R 'FAIL' 'AaronLocker' "not found at $($Cfg.ToolkitPath) - run 0_AL_get_toolkit.ps1" }
    $Acc = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if ($Acc.Ok) { Add-ALResult $R 'OK' 'AccessChk.exe' $Acc.Detail } else { Add-ALResult $R 'FAIL' 'AccessChk.exe' "$($Acc.Detail) - run 0_AL_get_toolkit.ps1 (-AccessChkPath when offline)" }
    if (Test-Path -LiteralPath (Join-Path $Cfg.Root 'Customizations\CustomizationInputs\GetSafePathsToAllow.ps1')) { Add-ALResult $R 'OK' 'Customizations' 'overlay folder present' } else { Add-ALResult $R 'FAIL' 'Customizations' "missing $(Join-Path $Cfg.Root 'Customizations')" }

    foreach ($Pair in @(@('Audit', $Cfg.AuditGpoName), @('Enforce', $Cfg.EnforceGpoName))) {
        $G = Get-GPO -Name $Pair[1] -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $G) { Add-ALResult $R 'INFO' "$($Pair[0]) GPO" "'$($Pair[1])' does not exist yet (created by 2_AL_create_gpos.ps1)"; continue }
        $States = foreach ($Ou in $Ous) { $S = Get-ALLinkState $G.Id $Ou $Domain; "$(if ($null -eq $S) { 'not linked' } elseif ($S) { 'ENABLED' } else { 'disabled' })" }
        Add-ALResult $R 'INFO' "$($Pair[0]) GPO" "'$($Pair[1])' exists; links: $($States -join ', ')"
    }

    # Reference server first, then every target server
    $Seen = @{}
    foreach ($C in @($Cfg.ReferenceServer) + $Targets) {
        if ($Seen[$C.ToLower()]) { continue }; $Seen[$C.ToLower()] = $true
        $Tag = if ($C -eq $Cfg.ReferenceServer) { "$C (reference)" } else { $C }
        try { $P = Invoke-Command -ComputerName $C -ScriptBlock $Probe -ErrorAction Stop }
        catch { Add-ALResult $R 'FAIL' "WinRM $Tag" $_.Exception.Message; continue }
        Add-ALResult $R 'OK' "Server $Tag" "$($P.Os); PowerShell $($P.PsVersion)"
        if ($P.Language -eq 'FullLanguage') { Add-ALResult $R 'OK' "Language mode $Tag" 'FullLanguage (AaronLocker needs it)' } else { Add-ALResult $R 'FAIL' "Language mode $Tag" "$($P.Language) - AaronLocker needs FullLanguage" }
        if (-not $P.AppLockerModule) { Add-ALResult $R 'FAIL' "AppLocker module $Tag" 'missing' }
        Add-ALResult $R 'INFO' "Application Identity $Tag" $P.AppId
        if ($P.LocalRules -gt 0) { Add-ALResult $R 'WARN' "Local AppLocker policy $Tag" "$($P.LocalRules) rule(s) in the LOCAL policy; it merges with the GPO policy (Managed-installer rules from MECM are expected here)" }
        if ($P.EffectiveRules -gt 0) { Add-ALResult $R 'INFO' "Effective AppLocker policy $Tag" "$($P.EffectiveRules) rule(s) already effective (from GPO and/or local policy)" }
        if ($P.MecmClient) { Add-ALResult $R 'INFO' "MECM client $Tag" $P.MecmClient }
        if ($P.MecmSiteDir) { Add-ALResult $R 'WARN' "MECM site server $Tag" "installed in '$($P.MecmSiteDir)'; services: $($P.MecmServices -join ', '). If that is not under Program Files, add it to ExtraAllowedPaths; build the policy for this class from a reference that is a site server." }
        if ($P.Sql.Count) { Add-ALResult $R 'INFO' "SQL Server $Tag" "running: $($P.Sql -join ', ')" }
        foreach ($S in $P.OutsideServices) { Add-ALResult $R 'WARN' "Non-admin service outside Windows/Program Files $Tag" "$S  -> its folder needs an ExtraAllowedPaths entry if the account is not a local administrator" }

        # Every ExtraAllowedPaths entry (C:\Admin, MECM, SQL ...) must be admin-only on this server
        if (@($Cfg.ExtraAllowedPaths).Count) {
            $Lines = @(Invoke-Command -ComputerName $C -ScriptBlock $ALWritableCheck -ArgumentList (, @($Cfg.ExtraAllowedPaths)) -ErrorAction Stop)
            foreach ($Line in $Lines) {
                $F = "$Line" -split '\|'
                if ($F[0] -eq 'WRITABLE') { Add-ALResult $R 'FAIL' "Extra path writable $Tag" "$($F[1]) is writable by $($F[2]) - a path rule there is a bypass. Lock it down (0_AL_secure_folders.ps1 -Fix)." }
                elseif ($F[0] -eq 'NOTFOUND') { Add-ALResult $R 'WARN' "Extra path missing $Tag" "$($F[1]) does not exist. Create it locked down with 0_AL_secure_folders.ps1 (C:\Admin) BEFORE the policy is used." }
            }
            $Ok = @($Cfg.ExtraAllowedPaths | Where-Object { $P = $_; -not ($Lines | Where-Object { ("$_" -split '\|')[1] -eq $P -or ("$_" -split '\|')[1].StartsWith(($P -replace '\\\*$', '') + '\', [StringComparison]::OrdinalIgnoreCase) }) })
            if ($Ok.Count) { Add-ALResult $R 'OK' "Extra paths admin-only $Tag" ($Ok -join ', ') }
        }
    }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R
    Write-Host "Transcript: $($Cfg.Transcript)"
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
