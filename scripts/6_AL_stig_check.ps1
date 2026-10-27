<#
.SYNOPSIS
    Step 9 - read-only DISA STIG check "deny-all, permit-by-exception" per server, with evidence files: WN25-00-000080 / V-277992 on
    Windows Server 2025, WN22-00-000080 / V-254245 on Windows Server 2022 (CAT II).

.DESCRIPTION
    Run from the management computer. Nothing is changed. The STIG item: "Windows Server 2025 (2022) must employ a deny-all,
    permit-by-exception policy to allow the execution of authorized software programs." The item is chosen per server from its Windows
    build (26100 = Server 2025, 20348 = Server 2022; from AD when the server cannot be reached). On each server in scope the script
    runs the check text's own command (Get-AppLockerPolicy -Effective -XML) over WinRM and decides:
      NotAFinding  Application Identity is running and the EXE rule collection is ENFORCED (Enabled) with allow rules, so everything
                   the rules do not allow is denied
      Open         AuditOnly (it blocks nothing), no EXE collection, no rules, or a stopped Application Identity service
      Not_Reviewed the server could not be checked, or it runs a Windows version this toolkit has no STIG item for (the AppLocker
                   result is then in the Reason, to record under that version's item)
    Values shown per server: every rule collection with its mode and rule count (DLL rules are not required by the STIG), the
    MECM managed-installer collection and services enforcement when present, Application Identity, the OS, blocked events
    (8004 / 8007) in the last 24 hours, and which AppLocker GPO link is enabled on the OU.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER TargetOU
    Distinguished names of the OUs whose servers are checked. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER ComputerName
    Servers to check. Default: every Windows Server computer in the target OUs.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: the STIG item(s) checked, one block per server (STIG ID, Status, Reason, the collections,
    Application Identity, evidence path) in green (NotAFinding) or red, and a summary line per STIG item. Files:
    Outputs\<profile>\stig-<timestamp>\<server>-effective-applocker.xml (the effective policy, SHA-256 in the results) and
    Logs\6_AL_stig_check-<timestamp>.csv (one row per server with its STIG and vulnerability IDs; every row has every column).
    Transcript in Logs\6_AL_stig_check-<timestamp>.log. Exit code 1 when any server is Open or Not_Reviewed.

.EXAMPLE
    .\6_AL_stig_check.ps1
    Checks every server in the target OUs.

.EXAMPLE
    .\6_AL_stig_check.ps1 -ComputerName dc01.contoso.com, dc22-01.contoso.com
    Checks two servers; a Server 2022 DC is reported under WN22-00-000080 / V-254245.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-27
    Version  : 1.1 (the STIG item per server: Windows Server 2022 and 2025)
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT GroupPolicy and ActiveDirectory modules; WinRM to the servers.
    Changes  : nothing (read-only).
    README   : section 7, step 9; section 12 (audit evidence); SERVER-2022.md, section 4.
#>
param(
    [string]$SettingsFile,
    [string[]]$TargetOU,
    [string[]]$ComputerName
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '6_AL_stig_check' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
$Open = 1
$Links = @()

# Runs on a server: the STIG check command plus the facts the status depends on
$Probe = {
    $Xml = Get-AppLockerPolicy -Effective -Xml
    [xml]$Doc = $Xml
    $Svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $Os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        Computer    = $env:COMPUTERNAME
        Os          = "$($Os.Caption) $($Os.Version)"
        Build       = [int]$Os.BuildNumber
        Xml         = "$Xml"
        SvcState    = "$($Svc.State)"
        SvcStart    = "$($Svc.StartMode)"
        Collections = @($Doc.AppLockerPolicy.RuleCollection | ForEach-Object { [pscustomobject]@{ Type = "$($_.Type)"; Mode = "$($_.EnforcementMode)"; Rules = @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count } })
        Services    = (@($Doc.AppLockerPolicy.RuleCollection | ForEach-Object { $_.RuleCollectionExtensions.ThresholdExtensions.Services.EnforcementMode } | Where-Object { $_ } | Select-Object -Unique)) -join ','
        Blocked24h  = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8004, 8007; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue).Count
        Checked     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz', [Globalization.CultureInfo]::InvariantCulture)
    }
}

# One results row with every column (empty when unknown): Export-Csv takes its columns from the first row, so a short row for an
# unreachable first server would otherwise drop the collection columns of every server after it
function New-ALStigRow([string]$Server, $Item, [string]$Status, [string]$Reason, [hashtable]$Values = @{}) {
    $Row = [ordered]@{ Server = $Server }
    foreach ($K in 'StigId', 'VulnId', 'Severity', 'Title') { $Row[$K] = $(if ($Item) { $Item[$K] } else { '' }) }
    $Row.Status = $Status
    $Row.Reason = $Reason
    foreach ($K in 'Exe', 'Msi', 'Script', 'Appx', 'Dll', 'ManagedInstaller', 'ServicesEnforcement', 'ApplicationIdentity', 'Blocked24h', 'Os', 'Checked', 'Evidence') {
        $Row[$K] = $(if ($Values.ContainsKey($K)) { $Values[$K] } else { '' })
    }
    return [pscustomobject]$Row
}
$NoMapping = 'no STIG item mapped for {0} - this toolkit maps Windows Server 2022 and 2025; record the result under that version''s deny-all, permit-by-exception item'

$Rows = New-Object System.Collections.Generic.List[object]
try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Links = foreach ($Ou in $Ous) {
        $States = foreach ($Name in $Cfg.AuditGpoName, $Cfg.EnforceGpoName) {
            $G = Get-GPO -Name $Name -Server $Domain.PDC -ErrorAction SilentlyContinue
            if ($G -and (Get-ALLinkState $G.Id $Ou $Domain)) { $Name }
        }
        "$Ou -> $(if ($States) { $States -join ' + ' } else { 'no AppLocker GPO link enabled' })"
    }
    if (-not $ComputerName) { $ComputerName = Get-ALTargetComputers $Ous $Domain }
    $Evidence = Join-Path $Cfg.OutRoot "stig-$($Cfg.Stamp)"
    New-Item -Path $Evidence -ItemType Directory -Force | Out-Null

    foreach ($C in $ComputerName) {
        try { $P = Invoke-Command -ComputerName $C -ScriptBlock $Probe -ErrorAction Stop }
        catch {
            # The STIG item still follows the server's version: AD knows it
            $Err = $_.Exception.Message
            $B = Get-ALAdOsBuild $C $Domain
            $Item = Get-ALStigItem $B
            $Why = "could not be checked: $Err$(if (-not $Item -and $B) { ' - ' + ($NoMapping -f (Get-ALOsLabel $B)) })"
            $Rows.Add((New-ALStigRow $C $Item 'Not_Reviewed' $Why @{ Os = $(if ($B) { "$(Get-ALOsLabel $B) (from AD)" } else { 'unknown (not in AD)' }) }))
            continue
        }
        $Col = @{}; foreach ($X in $P.Collections) { $Col[$X.Type] = $X }
        $Exe = $Col['Exe']
        $Reason = if ($P.SvcState -ne 'Running') { "Application Identity is $($P.SvcState) - AppLocker enforces nothing" }
        elseif (-not $Exe) { 'no AppLocker EXE rule collection in the effective policy - no allowlisting in use' }
        elseif ($Exe.Mode -ne 'Enabled') { "EXE rules are $($Exe.Mode) - not enforced (Audit is a staging step, not compliance)" }
        elseif ($Exe.Rules -lt 1) { 'the EXE rule collection is enforced but has no rules' }
        else { '' }
        $Verdict = if ($Reason) { $Reason } else { 'AppLocker enforces a deny-by-default allowlist: EXE rules Enabled with allow rules, Application Identity running' }
        $Item = Get-ALStigItem $P.Build
        $Status = if (-not $Item) { 'Not_Reviewed' } elseif ($Reason) { 'Open' } else { 'NotAFinding' }
        if (-not $Item) { $Verdict = ($NoMapping -f (Get-ALOsLabel $P.Build)) + ". AppLocker result: $Verdict" }
        $File = Join-Path $Evidence "$($P.Computer)-effective-applocker.xml"
        [IO.File]::WriteAllText($File, $P.Xml, (New-Object Text.UTF8Encoding $false))
        $Value = { param($T) if ($Col[$T]) { "$($Col[$T].Mode) ($($Col[$T].Rules) rules)" } else { 'absent' } }
        $Rows.Add((New-ALStigRow $C $Item $Status $Verdict @{
                    Exe                 = & $Value 'Exe'
                    Msi                 = & $Value 'Msi'
                    Script              = & $Value 'Script'
                    Appx                = & $Value 'Appx'
                    Dll                 = "$(& $Value 'Dll')$(if (-not $Cfg.EnableDllRules) { ' - DLL rules off in this baseline (not required by the STIG)' })"
                    ManagedInstaller    = "$(& $Value 'ManagedInstaller')$(if ($Col['ManagedInstaller']) { ' - MECM managed installer (local policy)' })"
                    ServicesEnforcement = $(if ($P.Services -match 'Enabled') { 'Enabled (MECM managed installer)' } else { 'not configured (services are not evaluated)' })
                    ApplicationIdentity = "$($P.SvcState) / $($P.SvcStart)"
                    Blocked24h          = $P.Blocked24h
                    Os                  = $P.Os
                    Checked             = $P.Checked
                    Evidence            = "$File (SHA-256 $(Get-ALSha256 $File))"
                }))
    }
}
catch { $Rows.Add((New-ALStigRow '(script)' $null 'Not_Reviewed' $_.Exception.Message)) }
finally {
    Write-Host ''
    foreach ($I in @($Rows | Where-Object { $_.StigId } | Sort-Object StigId -Unique)) { Write-Host "$($I.StigId) / $($I.VulnId) ($($I.Severity)): $($I.Title)" -ForegroundColor Cyan }
    foreach ($L in @($Links)) { Write-Host "AppLocker GPO link: $L" }
    foreach ($Row in $Rows) {
        $Row | Select-Object -Property * -ExcludeProperty Title | Format-List | Out-String -Width 220 | ForEach-Object { $_.Trim() } | Write-Host -ForegroundColor $(if ($Row.Status -eq 'NotAFinding') { 'Green' } else { 'Red' })
        Write-Host ''
    }
    $Csv = Join-Path $Cfg.LogDir "$($Cfg.ScriptName)-$($Cfg.Stamp).csv"
    $Rows | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8
    $Open = @($Rows | Where-Object { $_.Status -ne 'NotAFinding' }).Count
    $Color = $(if ($Open -or -not $Rows.Count) { 'Red' } else { 'Green' })
    # One summary line per STIG item (servers without one are counted on their own line)
    foreach ($G in @($Rows | Group-Object { if ($_.StigId) { "$($_.StigId) / $($_.VulnId)" } else { 'No STIG item mapped' } } | Sort-Object Name)) {
        $Ok = @($G.Group | Where-Object { $_.Status -eq 'NotAFinding' }).Count
        Write-Host "$($G.Name): $Ok NotAFinding, $($G.Count - $Ok) Open/Not_Reviewed of $($G.Count) server(s)." -ForegroundColor $Color
    }
    if (-not $Rows.Count) { Write-Host 'No server was checked.' -ForegroundColor $Color }
    Write-Host "Results: $Csv" -ForegroundColor $Color
    Stop-ALTranscript
}
if ($Open -or -not $Rows.Count) { exit 1 }
