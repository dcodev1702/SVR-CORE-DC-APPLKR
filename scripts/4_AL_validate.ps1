<#
.SYNOPSIS
    Step 6 (and after every change) - read-only validation of the AppLocker deployment: GPOs, links, rules, service, effective policy.

.DESCRIPTION
    Run from the management computer. Nothing is changed. Per target OU it checks that both GPOs exist with matching AD and SYSVOL
    versions, that each carries Application Identity = Automatic and the rules in the expected modes, and that exactly one link is
    enabled. Per server (the target OUs, or -ComputerName), over WinRM, it checks: Application Identity running and Automatic; the
    effective modes of the collections this baseline manages (Exe, Msi, Script, Appx - other collections such as the MECM managed
    installer's are reported, not judged); that an ExtraAllowedPaths item a non-admin can change is NOT allowed by the policy (that
    would be a bypass); sample rule decisions (Windows tools, the MECM client, Nessus, a file from C:\Admin, for Everyone and for
    Administrators); the core domain controller services; and the AppLocker event counts of the last -EventHours hours.
    Per server it also runs gpresult /scope computer (text and XML) and judges it against the mode: the expected AppLocker GPO must
    be applied and the other one not (with the reason gpresult gives, e.g. Disabled (Link)), the Registry and Security extensions must
    have run without error, and the newest policy event must be 8001 (applied), not 8000 (conversion failed). The raw gpresult output
    of every server is kept in Logs\4_AL_validate-<timestamp>-gpresult\.
    -Mode Auto (default) expects what the enabled link says; Audit, Enforce or Off asserts that mode.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER Mode
    Auto (default: expect what the links say), or assert Audit, Enforce or Off.

.PARAMETER TargetOU
    Distinguished names of the OUs to check. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER ComputerName
    Servers to check. Default: every Windows Server computer in the target OUs.

.PARAMETER EventHours
    Window of the AppLocker event counts shown at the end, in hours (1-8760). Default: 24.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: a Status / Check / Detail table and "Validation: PASSED" or "FAILED". The same rows as CSV in
    Logs\4_AL_validate-<timestamp>.csv; transcript in Logs\4_AL_validate-<timestamp>.log. Exit code 1 on any FAIL.

.EXAMPLE
    .\4_AL_validate.ps1
    Validates against whatever mode the links say.

.EXAMPLE
    .\4_AL_validate.ps1 -Mode Enforce -EventHours 168
    Asserts Enforce and summarises the events of the last week.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-27
    Version  : 1.1 (gpresult per server; EnableAppxRules)
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT GroupPolicy and ActiveDirectory modules and the AppLocker module; WinRM.
    Changes  : nothing (read-only).
    README   : section 7, step 6; appendix D (troubleshooting).
#>
param(
    [string]$SettingsFile,
    [ValidateSet('Auto', 'Audit', 'Enforce', 'Off')][string]$Mode = 'Auto',
    [string[]]$TargetOU,
    [string[]]$ComputerName,
    # Event window summarised at the end
    [ValidateRange(1, 8760)][int]$EventHours = 24
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '4_AL_validate' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
$R = New-ALResults
$Failed = 1
$DllRules = [bool]$Cfg.EnableDllRules
$AppxRules = [bool]$Cfg.EnableAppxRules

# Runs on a server. $Extra = the ExtraAllowedPaths setting (a sample file from each is tested).
$Probe = {
    param([int]$Hours, [string[]]$Extra)
    $o = [ordered]@{}
    $o.Svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'" | Select-Object State, StartMode
    $o.Policy = [xml](Get-AppLockerPolicy -Effective -Xml)
    $o.LocalRules = 0; $o.LocalTypes = @()
    try {
        [xml]$loc = Get-AppLockerPolicy -Local -Xml
        $o.LocalRules = @($loc.AppLockerPolicy.RuleCollection.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count
        $o.LocalTypes = @($loc.AppLockerPolicy.RuleCollection | Where-Object { @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count } | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)" })
    } catch { }
    $o.ServicesEnforcement = (@($o.Policy.AppLockerPolicy.RuleCollection | ForEach-Object { $_.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode } | Where-Object { $_ } | Select-Object -Unique)) -join ','
    $pol = Get-AppLockerPolicy -Effective
    $files = @(
        @{ Path = "$env:windir\System32\cmd.exe"; User = 'Everyone' },
        @{ Path = "$env:windir\System32\cipher.exe"; User = 'Everyone' },
        @{ Path = "$env:windir\System32\cipher.exe"; User = 'BUILTIN\Administrators' }
    )
    # Configuration Manager client / site server and Tenable Nessus binaries, plus one file from each ExtraAllowedPaths folder, when present
    $more = @("$env:windir\CCM\CcmExec.exe", "$env:windir\ccmsetup\ccmsetup.exe", "$env:ProgramFiles\Tenable\Nessus Agent\nessusd.exe", "$env:ProgramFiles\Tenable\Nessus\nessusd.exe")
    $site = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Setup' -ErrorAction SilentlyContinue).'Installation Directory'
    if ($site) { $more += (Join-Path $site 'bin\x64\smsexec.exe') }
    foreach ($e in $Extra) {
        $dir = $e -replace '\\\*$', ''
        # (-Include is ignored with -LiteralPath, so the type filter is a Where-Object: only files AppLocker can evaluate)
        if (Test-Path -LiteralPath $dir -PathType Container) { $more += @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe', '.ps1', '.cmd', '.bat' } | Select-Object -First 1 | ForEach-Object { $_.FullName }) }
    }
    foreach ($m in $more) { if ($m -and (Test-Path -LiteralPath $m)) { $files += @{ Path = $m; User = 'Everyone' }; $files += @{ Path = $m; User = 'BUILTIN\Administrators' } } }
    $o.Tests = foreach ($t in $files) {
        try { $r = Test-AppLockerPolicy -PolicyObject $pol -Path $t.Path -User $t.User -ErrorAction Stop; [pscustomobject]@{ File = $t.Path; User = $t.User; Decision = "$($r.PolicyDecision)"; Rule = "$($r.MatchingRule)" } }
        catch { [pscustomobject]@{ File = $t.Path; User = $t.User; Decision = 'ERROR'; Rule = $_.Exception.Message } }
    }
    # Core DC services, plus MECM client and Nessus Agent when installed (only services that exist are listed)
    $o.Services = foreach ($n in 'NTDS', 'DNS', 'Netlogon', 'KDC', 'DFSR', 'W32Time', 'ADWS', 'CcmExec', 'Tenable Nessus Agent') { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; if ($s) { "$n=$($s.Status)" } }
    $since = (Get-Date).AddHours(-$Hours)
    $o.Events = foreach ($log in 'EXE and DLL', 'MSI and Script', 'Packaged app-Execution') {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-AppLocker/$log"; StartTime = $since } -ErrorAction SilentlyContinue)
        [pscustomobject]@{ Log = $log; Total = $ev.Count; ById = (($ev | Group-Object Id | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ' ') }
    }
    [pscustomobject]$o
}

try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory; Import-ALModule AppLocker
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    # ---- per OU: both GPOs (AD/SYSVOL versions, System Services, rule modes) and which link is enabled
    $Audit = Get-GPO -Name $Cfg.AuditGpoName -Server $Domain.PDC -ErrorAction SilentlyContinue
    $Enforce = Get-GPO -Name $Cfg.EnforceGpoName -Server $Domain.PDC -ErrorAction SilentlyContinue
    $OurIds = @{}   # rule IDs of both GPOs: in Off mode none of them may still be effective
    foreach ($G in @(@('Audit', $Audit, $Cfg.AuditGpoName), @('Enforce', $Enforce, $Cfg.EnforceGpoName))) {
        if (-not $G[1]) { Add-ALResult $R 'FAIL' "$($G[0]) GPO" "'$($G[2])' not found. Run 2_AL_create_gpos.ps1."; continue }
        $Gpo = $G[1]
        Add-ALResult $R 'OK' "$($G[0]) GPO" "$($Gpo.DisplayName) $($Gpo.Id) (computer v$($Gpo.Computer.DSVersion) AD / v$($Gpo.Computer.SysvolVersion) SYSVOL)"
        if ($Gpo.Computer.DSVersion -ne $Gpo.Computer.SysvolVersion) { Add-ALResult $R 'FAIL' "$($G[0]) GPO versions" 'AD and SYSVOL versions differ (replication pending?)' }
        $Paths = Get-ALGpoPaths $Gpo.Id $Domain
        $Inf = Join-Path $Paths.SysvolPdc 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        if ((Test-Path -LiteralPath $Inf) -and ((Get-Content -LiteralPath $Inf -Raw) -match '"AppIDSvc",2')) { Add-ALResult $R 'OK' "$($G[0]) GPO System Services" 'Application Identity = Automatic' } else { Add-ALResult $R 'FAIL' "$($G[0]) GPO System Services" 'AppIDSvc startup setting missing in GptTmpl.inf' }
        [xml]$InGpo = Get-AppLockerPolicy -Domain -Ldap "LDAP://$($Domain.PDC)/$($Gpo.Path)" -Xml
        foreach ($Id in @($InGpo.SelectNodes('//*[@Id]') | ForEach-Object { $_.GetAttribute('Id') })) { $OurIds[$Id] = $true }
        $Bad = @($InGpo.AppLockerPolicy.RuleCollection | Where-Object { $_.EnforcementMode -ne (Get-ALExpectedMode $G[0] $_.Type $DllRules $AppxRules) })
        $Txt = Get-ALPolicySummary $InGpo
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
    else { Add-ALResult $R 'INFO' 'Mode asserted' "$Expect$(if ($Expect -eq 'Enforce') { ' - WN25-00-000080 / V-277992 met' } elseif ($Expect) { ' - WN25-00-000080 / V-277992 NOT met until Enforce' })" }

    # ---- per server, over WinRM: service, effective policy, sample decisions, DC services, extra paths, event counts
    if (-not $ComputerName) { $ComputerName = Get-ALTargetComputers $Ous $Domain }
    if (-not @($ComputerName).Count) { Add-ALResult $R 'WARN' 'Servers' 'no servers found in the target OUs' }
    foreach ($C in $ComputerName) {
        try { $Dc = Invoke-ALOn $C $Probe ($EventHours, @($Cfg.ExtraAllowedPaths)) }
        catch { Add-ALResult $R 'FAIL' "WinRM $C" $_.Exception.Message; continue }
        $IsMi = @($Dc.LocalTypes | Where-Object { $_ -like 'ManagedInstaller=*' }).Count -gt 0
        if ($Expect -eq 'Off') {
            $Left = @($Dc.Policy.SelectNodes('//*[@Id]') | Where-Object { $OurIds.ContainsKey($_.GetAttribute('Id')) }).Count
            if ($Left) { Add-ALResult $R 'WARN' "Effective policy $C" "$Left rule(s) of the AppLocker GPOs still effective (the server has not refreshed Group Policy yet?)" } else { Add-ALResult $R 'OK' "Effective policy $C" "no rules from the AppLocker GPOs (Off)$(if ($IsMi) { '; the local MECM managed-installer policy remains' })" }
        }
        else {
            if ($Dc.Svc.State -eq 'Running' -and $Dc.Svc.StartMode -eq 'Auto') { Add-ALResult $R 'OK' "AppIDSvc $C" "$($Dc.Svc.State) / $($Dc.Svc.StartMode)" } else { Add-ALResult $R 'FAIL' "AppIDSvc $C" "$($Dc.Svc.State) / $($Dc.Svc.StartMode) (expected Running / Auto; run gpupdate twice or reboot)" }
            $Eff = Get-ALPolicySummary $Dc.Policy
            $Mismatch = if ($Expect) { @(Get-ALPolicyMismatch $Dc.Policy $Expect $DllRules $AppxRules) } else { @('mode unknown') }
            if ($Mismatch.Count -eq 0) { Add-ALResult $R 'OK' "Effective policy $C" $Eff } else { Add-ALResult $R 'FAIL' "Effective policy $C" "not applied or unexpected: $($Mismatch -join '; ') - effective: $Eff" }
            # Collections from other policies (the MECM managed installer's): reported, not judged
            $Managed = Get-ALManagedCollections $DllRules $AppxRules
            $Foreign = @($Dc.Policy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -notin $Managed -and @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count } | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)" })
            if ($Foreign.Count) { Add-ALResult $R 'INFO' "Other collections $C" "$($Foreign -join ', ') - not managed by this baseline$(if ($IsMi) { ' (MECM managed installer: DLL rules stay audit-only, nothing is blocked by them)' })" }
        }
        if ($Dc.LocalRules -gt 0) {
            if ($IsMi) { Add-ALResult $R 'INFO' "MECM managed installer $C" "local AppLocker policy ($($Dc.LocalTypes -join ', ')) merges with the GPO: expected (README, MECM)" }
            else { Add-ALResult $R 'WARN' "Local AppLocker policy $C" "$($Dc.LocalRules) rule(s) in the LOCAL policy ($($Dc.LocalTypes -join ', ')) merge with the GPO - review Get-AppLockerPolicy -Local -Xml" }
        }
        if ($Dc.ServicesEnforcement -match 'Enabled') { Add-ALResult $R 'INFO' "Services enforcement $C" 'on (MECM managed installer): services are evaluated too; blocked services would show as 8004 events below' }
        foreach ($T in $Dc.Tests) { Add-ALResult $R 'INFO' "Decision $C" "$($T.User) -> $(Split-Path $T.File -Leaf): $($T.Decision) ($($T.Rule))" }
        $Down = @($Dc.Services | Where-Object { $_ -notmatch '=Running' })
        if ($Down.Count -eq 0) { Add-ALResult $R 'OK' "Services $C" ($Dc.Services -join ', ') } else { Add-ALResult $R 'FAIL' "Services $C" ($Dc.Services -join ', ') }
        # gpresult: which AppLocker GPO Group Policy applied here, whether its Registry and Security extensions ran without error, the
        # newest policy event (8001 applied / 8000 conversion failed), when and from which DC it was applied (README, step 6)
        try {
            $Gp = Invoke-ALGpRefresh -ComputerName $C -Refresh $false
            $GpFile = Save-ALGpResult $Gp (Join-Path $Cfg.LogDir "$($Cfg.ScriptName)-$($Cfg.Stamp)-gpresult")
            $GpIds = @{}
            if ($Audit) { $GpIds["$($Audit.Id)"] = $Cfg.AuditGpoName }
            if ($Enforce) { $GpIds["$($Enforce.Id)"] = $Cfg.EnforceGpoName }
            Add-ALGpResults $R $C $Gp (Resolve-ALGpoNames (ConvertFrom-ALGpResult $Gp.GpresultXml $Gp.GpresultText) $GpIds) $(if ($Expect) { $Expect } else { 'Any' }) $Cfg.AuditGpoName $Cfg.EnforceGpoName $GpFile
        }
        catch { Add-ALResult $R 'WARN' "gpresult $C" "could not be collected: $($_.Exception.Message)" }
        # A non-admin-writable item in an ExtraAllowedPaths folder is only a problem if the policy still allows it (a bypass)
        if (@($Cfg.ExtraAllowedPaths).Count) {
            try {
                foreach ($F in @(Invoke-ALWritableCheck -Paths $Cfg.ExtraAllowedPaths -Cfg $Cfg -ComputerName $C)) {
                    if ($F.Kind -in 'WRITABLE', 'UNREADABLE') {
                        $Entry = @($Cfg.ExtraAllowedPaths | Where-Object { Test-ALPathUnder $F.Path $_ }) | Select-Object -First 1
                        $Ex = Get-ALRuleExceptions $Dc.Policy $Entry
                        $Who = if ($F.Kind -eq 'WRITABLE') { "changeable by $($F.Account)" } else { 'permissions unreadable' }
                        if ($null -eq $Ex) { Add-ALResult $R 'INFO' "Extra path $C" "$($F.Path) is $Who - $Entry is not in the policy (the build left it out)" }
                        elseif (Test-ALCovered $F.Path $Ex) { Add-ALResult $R 'INFO' "Extra path $C" "$($F.Path) is $Who - excluded by the policy (exception)" }
                        else { Add-ALResult $R 'FAIL' "Extra path writable $C" "$($F.Path) is $Who AND allowed for every account - a bypass. Rebuild (1_AL_build_policy.ps1, 2_AL_create_gpos.ps1): the build excludes it." }
                    }
                    elseif ($F.Kind -eq 'NOTFOUND') { Add-ALResult $R 'WARN' "Extra path missing $C" "$($F.Path) does not exist (0_AL_secure_folders.ps1 creates C:\Admin administrators-only)" }
                    else { Add-ALResult $R 'WARN' "Extra path check $C" "$($F.Kind) $($F.Path)" }
                }
            }
            catch { Add-ALResult $R 'FAIL' "Extra paths $C" "permission check failed: $($_.Exception.Message)" }
        }
        foreach ($E in $Dc.Events) { Add-ALResult $R 'INFO' "Events ${EventHours}h $C" "$($E.Log): $($E.Total) $($E.ById)" }
    }
}
catch { Add-ALResult $R 'FAIL' 'Script' $_.Exception.Message }
finally {
    $Failed = Write-ALResults $R $Cfg 'Validation'
    Stop-ALTranscript
}
if ($Failed) { exit 1 }
