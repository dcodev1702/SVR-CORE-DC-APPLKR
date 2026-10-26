# Step 4 - run from the management computer (Windows PowerShell 5.1). Read-only validation of the AppLocker deployment.
# Per OU: both GPOs exist, exactly one link enabled, the rules inside the active GPO have the expected modes.
# Per server (target OUs, or -ComputerName): Application Identity running + Automatic, effective policy modes, ExtraAllowedPaths still
# admin-only, sample rule decisions (Windows tools, MECM client files), core DC services, and AppLocker event counts.
# -Mode Auto (default) expects what the enabled link says; Audit / Enforce / Off assert a specific mode. Exit code 1 on a failure.
param(
    [string]$SettingsFile,
    [ValidateSet('Auto', 'Audit', 'Enforce', 'Off')][string]$Mode = 'Auto',
    [string[]]$TargetOU,
    [string[]]$ComputerName,
    # Event window summarised at the end
    [int]$EventHours = 24
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '4_AL_validate' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
$R = New-ALResults
$Failed = 1

# Runs on a server
$Probe = {
    param([int]$Hours)
    $o = [ordered]@{}
    $o.Svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" | Select-Object State, StartMode
    $o.Policy = [xml](Get-AppLockerPolicy -Effective -Xml)
    $pol = Get-AppLockerPolicy -Effective
    $files = @(
        @{ Path = "$env:windir\System32\cmd.exe"; User = 'Everyone' },
        @{ Path = "$env:windir\System32\cipher.exe"; User = 'Everyone' },
        @{ Path = "$env:windir\System32\cipher.exe"; User = 'BUILTIN\Administrators' }
    )
    # Configuration Manager client / site server binaries, when present
    $mecm = @("$env:windir\CCM\CcmExec.exe", "$env:windir\ccmsetup\ccmsetup.exe")
    $site = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Setup' -ErrorAction SilentlyContinue).'Installation Directory'
    if ($site) { $mecm += (Join-Path $site 'bin\x64\smsexec.exe') }
    foreach ($m in $mecm) { if (Test-Path -LiteralPath $m) { $files += @{ Path = $m; User = 'Everyone' }; $files += @{ Path = $m; User = 'BUILTIN\Administrators' } } }
    $o.Tests = foreach ($t in $files) {
        try { $r = Test-AppLockerPolicy -PolicyObject $pol -Path $t.Path -User $t.User; [pscustomobject]@{ File = $t.Path; User = $t.User; Decision = "$($r.PolicyDecision)"; Rule = "$($r.MatchingRule)" } }
        catch { [pscustomobject]@{ File = $t.Path; User = $t.User; Decision = 'ERROR'; Rule = $_.Exception.Message } }
    }
    $o.Services = foreach ($n in 'NTDS', 'DNS', 'Netlogon', 'KDC', 'DFSR', 'W32Time', 'CcmExec') { $s = Get-Service $n -ErrorAction SilentlyContinue; if ($s) { "$n=$($s.Status)" } }
    $since = (Get-Date).AddHours(-$Hours)
    $o.Events = foreach ($log in 'EXE and DLL', 'MSI and Script', 'Packaged app-Execution') {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-AppLocker/$log"; StartTime = $since } -ErrorAction SilentlyContinue)
        [pscustomobject]@{ Log = $log; Total = $ev.Count; ById = (($ev | Group-Object Id | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ') }
    }
    [pscustomobject]$o
}
# Expected enforcement mode of every collection for a mode
function Get-Expected([string]$M, [string]$Type) {
    if ($Type -eq 'Dll' -and -not $Cfg.EnableDllRules) { return 'NotConfigured' }
    if ($M -eq 'Audit') { return 'AuditOnly' } else { return 'Enabled' }
}

try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory; Import-ALModule AppLocker
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Audit = Get-GPO -Name $Cfg.AuditGpoName -Server $Domain.PDC -ErrorAction SilentlyContinue
    $Enforce = Get-GPO -Name $Cfg.EnforceGpoName -Server $Domain.PDC -ErrorAction SilentlyContinue
    foreach ($G in @(@('Audit', $Audit, $Cfg.AuditGpoName), @('Enforce', $Enforce, $Cfg.EnforceGpoName))) {
        if (-not $G[1]) { Add-ALResult $R 'FAIL' "$($G[0]) GPO" "'$($G[2])' not found. Run 2_AL_create_gpos.ps1."; continue }
        $Gpo = $G[1]
        Add-ALResult $R 'OK' "$($G[0]) GPO" "$($Gpo.DisplayName) $($Gpo.Id) (computer v$($Gpo.Computer.DSVersion) AD / v$($Gpo.Computer.SysvolVersion) SYSVOL)"
        if ($Gpo.Computer.DSVersion -ne $Gpo.Computer.SysvolVersion) { Add-ALResult $R 'FAIL' "$($G[0]) GPO versions" 'AD and SYSVOL versions differ (replication pending?)' }
        $Paths = Get-ALGpoPaths $Gpo.Id $Domain
        $Inf = Join-Path $Paths.SysvolPdc 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        if ((Test-Path -LiteralPath $Inf) -and ((Get-Content -LiteralPath $Inf -Raw) -match '"AppIDSvc",2')) { Add-ALResult $R 'OK' "$($G[0]) GPO System Services" 'Application Identity = Automatic' } else { Add-ALResult $R 'FAIL' "$($G[0]) GPO System Services" 'AppIDSvc startup setting missing in GptTmpl.inf' }
        [xml]$InGpo = Get-AppLockerPolicy -Domain -Ldap "LDAP://$($Domain.PDC)/$($Gpo.Path)" -Xml
        $Bad = @($InGpo.AppLockerPolicy.RuleCollection | Where-Object { $_.EnforcementMode -ne (Get-Expected $G[0] $_.Type) })
        $Txt = @($InGpo.AppLockerPolicy.RuleCollection | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)" }) -join ', '
        if ($Bad.Count -eq 0 -and $InGpo.AppLockerPolicy.RuleCollection) { Add-ALResult $R 'OK' "$($G[0]) rules in GPO" $Txt } else { Add-ALResult $R 'FAIL' "$($G[0]) rules in GPO" "unexpected or empty: $Txt" }
    }

    # Which mode is active? (links)
    $Active = @()
    foreach ($Ou in $Ous) {
        $A = if ($Audit) { Get-ALLinkState $Audit.Id $Ou $Domain } else { $null }
        $E = if ($Enforce) { Get-ALLinkState $Enforce.Id $Ou $Domain } else { $null }
        $Now = if ($A -and $E) { 'BOTH' } elseif ($A) { 'Audit' } elseif ($E) { 'Enforce' } else { 'Off' }
        $Active += $Now
        if ($Now -eq 'BOTH') { Add-ALResult $R 'FAIL' 'Links' "$Ou : BOTH links are enabled - run 3_AL_set_mode.ps1" }
        else { Add-ALResult $R 'OK' 'Links' "$Ou : mode $Now (Audit link $(if ($null -eq $A) { 'missing' } elseif ($A) { 'enabled' } else { 'disabled' }), Enforce link $(if ($null -eq $E) { 'missing' } elseif ($E) { 'enabled' } else { 'disabled' }))" }
    }
    $Expect = if ($Mode -eq 'Auto') { ($Active | Select-Object -Unique) } else { $Mode }
    if (@($Expect).Count -ne 1 -or $Expect -eq 'BOTH') { Add-ALResult $R 'FAIL' 'Mode' "target OUs are not in one consistent mode ($($Active -join ', '))"; $Expect = $null }
    elseif ($Mode -ne 'Auto' -and ($Active | Where-Object { $_ -ne $Mode })) { Add-ALResult $R 'FAIL' 'Mode' "expected $Mode but the links say $($Active -join ', ')" }
    else { Add-ALResult $R 'INFO' 'Mode asserted' $Expect }

    if (-not $ComputerName) { $ComputerName = Get-ALTargetComputers $Ous $Domain }
    if (-not $ComputerName.Count) { Add-ALResult $R 'WARN' 'Servers' 'no servers found in the target OUs' }
    foreach ($C in $ComputerName) {
        try { $Dc = Invoke-Command -ComputerName $C -ScriptBlock $Probe -ArgumentList $EventHours -ErrorAction Stop }
        catch { Add-ALResult $R 'FAIL' "WinRM $C" $_.Exception.Message; continue }
        if ($Expect -eq 'Off') {
            if ($Dc.Policy.AppLockerPolicy.RuleCollection.ChildNodes.Count -gt 0) { Add-ALResult $R 'WARN' "Effective policy $C" 'rules still effective (the server has not refreshed Group Policy yet?)' } else { Add-ALResult $R 'OK' "Effective policy $C" 'none (Off)' }
        }
        else {
            if ($Dc.Svc.State -eq 'Running' -and $Dc.Svc.StartMode -eq 'Auto') { Add-ALResult $R 'OK' "AppIDSvc $C" "$($Dc.Svc.State) / $($Dc.Svc.StartMode)" } else { Add-ALResult $R 'FAIL' "AppIDSvc $C" "$($Dc.Svc.State) / $($Dc.Svc.StartMode) (expected Running / Auto; run gpupdate twice or reboot)" }
            $Cols = @($Dc.Policy.AppLockerPolicy.RuleCollection)
            $Eff = ($Cols | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count))" }) -join ', '
            $EffBad = if ($Expect) { @($Cols | Where-Object { $_.EnforcementMode -ne (Get-Expected $Expect $_.Type) }) } else { @() }
            if ($Cols.Count -and $EffBad.Count -eq 0) { Add-ALResult $R 'OK' "Effective policy $C" $Eff } else { Add-ALResult $R 'FAIL' "Effective policy $C" "not applied or unexpected mode: $Eff" }
        }
        foreach ($T in $Dc.Tests) { Add-ALResult $R 'INFO' "Decision $C" "$($T.User) -> $(Split-Path $T.File -Leaf): $($T.Decision) ($($T.Rule))" }
        $Down = @($Dc.Services | Where-Object { $_ -notmatch '=Running' })
        if ($Down.Count -eq 0) { Add-ALResult $R 'OK' "Services $C" ($Dc.Services -join ', ') } else { Add-ALResult $R 'FAIL' "Services $C" ($Dc.Services -join ', ') }
        if (@($Cfg.ExtraAllowedPaths).Count) {
            foreach ($Line in @(Invoke-Command -ComputerName $C -ScriptBlock $ALWritableCheck -ArgumentList (, @($Cfg.ExtraAllowedPaths)))) {
                $F = "$Line" -split '\|'
                if ($F[0] -eq 'WRITABLE') { Add-ALResult $R 'FAIL' "Extra path writable $C" "$($F[1]) writable by $($F[2]) - bypass risk (0_AL_secure_folders.ps1 -Fix)" }
                elseif ($F[0] -eq 'NOTFOUND') { Add-ALResult $R 'WARN' "Extra path missing $C" "$($F[1]) does not exist (0_AL_secure_folders.ps1 creates C:\Admin)" }
            }
        }
        foreach ($E in $Dc.Events) { Add-ALResult $R 'INFO' "Events ${EventHours}h $C" "$($E.Log): $($E.Total) $($E.ById)" }
    }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
