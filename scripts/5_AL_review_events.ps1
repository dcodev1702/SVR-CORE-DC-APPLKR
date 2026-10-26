<#
.SYNOPSIS
    Step 7 - read-only review of the AppLocker audit (would be blocked) and blocked events on the servers, summarised by file, user and rule.

.DESCRIPTION
    Run from the management computer during the Audit period, before switching to Enforce. Nothing is changed. Over WinRM it collects
    from every server in scope:
      EXE and DLL log: 8003 (audit) / 8004 (blocked)   MSI and Script log: 8006 / 8007   Packaged app-Execution log: 8021 / 8022
    Allowed events (8002 / 8005 / 8020) are not collected. With DLL rules off (EnableDllRules = $false) DLL events are counted but not
    listed: they come from another policy, typically the MECM managed installer's audit-only DLL rules, and need no rule in this
    baseline; the servers filter them before sending anything. The summary lists every distinct file / user / rule, most frequent
    first, with a Tag of MECM, NESSUS, ADMIN (an ExtraAllowedPaths folder such as C:\Admin) or SYSVOL, so each finding can be matched
    to the guidance in the README. Every event is also written to a CSV.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER TargetOU
    Distinguished names of the OUs whose servers are read. Overrides the TargetOUs setting. Default: the Domain Controllers OU.

.PARAMETER ComputerName
    Servers to read. Default: every Windows Server computer in the target OUs.

.PARAMETER Days
    How many days back to collect (1-365). Default: 7.

.PARAMETER Top
    How many summary rows to print (1-1000). Default: 30. The CSV always holds every event.

.PARAMETER MaxEventsPerLog
    Upper bound of events read per log and server (1-1000000). Default: 20000.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: per server the number of events, the top summary table (Count, Result, Tag, User, File, Servers),
    counts by account and by tag. File: Outputs\<profile>\events-<timestamp>.csv with every event. Transcript in
    Logs\5_AL_review_events-<timestamp>.log.

.EXAMPLE
    .\5_AL_review_events.ps1
    The last 7 days on every server in the target OUs.

.EXAMPLE
    .\5_AL_review_events.ps1 -Days 30 -Top 100 -ComputerName dc01.contoso.com
    A longer window, more rows, one server.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT ActiveDirectory module; WinRM and event log read access on the servers.
    Changes  : nothing (read-only).
    README   : section 7, step 7 ("The Audit period": what to do with each finding).
#>
param(
    [string]$SettingsFile,
    [string[]]$TargetOU,
    [string[]]$ComputerName,
    [ValidateRange(1, 365)][int]$Days = 7,
    [ValidateRange(1, 1000)][int]$Top = 30,
    [ValidateRange(1, 1000000)][int]$MaxEventsPerLog = 20000
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '5_AL_review_events' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
# Runs on a server: the audit / blocked events of the last $Days days as objects (DLL events are only counted when DLL rules are off)
$Collect = {
    param([int]$Days, [int]$Max, [bool]$DllRules)
    $Ms = [int64]$Days * 86400000
    $Spec = @(@{ Log = 'EXE and DLL'; Ids = 8003, 8004 }, @{ Log = 'MSI and Script'; Ids = 8006, 8007 }, @{ Log = 'Packaged app-Execution'; Ids = 8021, 8022 })
    foreach ($S in $Spec) {
        $Base = "*[System[($(($S.Ids | ForEach-Object { "EventID=$_" }) -join ' or ')) and TimeCreated[timediff(@SystemTime) <= $Ms]]]"
        $XPath = $Base
        if ($S.Log -eq 'EXE and DLL' -and -not $DllRules) {
            $XPath = "$Base and *[UserData[RuleAndFileData[PolicyName='EXE']]]"
            $Dll = @(Get-WinEvent -LogName "Microsoft-Windows-AppLocker/$($S.Log)" -FilterXPath "$Base and *[UserData[RuleAndFileData[PolicyName='DLL']]]" -MaxEvents $Max -ErrorAction SilentlyContinue).Count
            [pscustomobject]@{ DllSkipped = $Dll; Computer = $env:COMPUTERNAME }
        }
        $Events = @(Get-WinEvent -LogName "Microsoft-Windows-AppLocker/$($S.Log)" -FilterXPath $XPath -MaxEvents $Max -ErrorAction SilentlyContinue)
        foreach ($E in $Events) {
            $D = ([xml]$E.ToXml()).Event.UserData.RuleAndFileData
            $User = "$($D.TargetUser)"
            try { $User = (New-Object System.Security.Principal.SecurityIdentifier $User).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            [pscustomobject]@{
                Time = $E.TimeCreated; Computer = $env:COMPUTERNAME; Log = $S.Log; Collection = "$($D.PolicyName)"; EventId = $E.Id
                Result = $(if ($E.Id -in 8003, 8006, 8021) { 'Audit (would be blocked)' } else { 'BLOCKED' })
                User = $User; File = $(if ($D.FullFilePath) { "$($D.FullFilePath)" } else { "$($D.FilePath)" }); Rule = "$($D.RuleName)"; Publisher = "$($D.Fqbn)"
            }
        }
    }
}
try {
    Import-ALModule ActiveDirectory
    $Domain = Get-ALDomainInfo
    if (-not $ComputerName) { $ComputerName = Get-ALTargetComputers (Resolve-ALTargetOUs $Cfg $Domain) $Domain }
    $All = New-Object System.Collections.Generic.List[object]
    foreach ($C in $ComputerName) {
        try {
            $Out = @(Invoke-Command -ComputerName $C -ScriptBlock $Collect -ArgumentList $Days, $MaxEventsPerLog, ([bool]$Cfg.EnableDllRules) -ErrorAction Stop)
            $Rows = @($Out | Where-Object { $null -eq $_.PSObject.Properties['DllSkipped'] })
            $Rows | ForEach-Object { $All.Add($_) }
            $Dll = (@($Out | Where-Object { $null -ne $_.PSObject.Properties['DllSkipped'] }) | Measure-Object -Property DllSkipped -Sum).Sum
            Write-Host "$C : $($Rows.Count) audit/blocked event(s) in the last $Days day(s)$(if ($Dll) { " (+ $Dll DLL audit event(s) not listed: DLL rules are off in this baseline - they come from another policy, e.g. the MECM managed installer)" })"
        }
        catch { Write-Host "$C : FAILED - $($_.Exception.Message)" -ForegroundColor Red }
    }
    if (-not $All.Count) { Write-Host "`nNo audit or blocked events in the last $Days day(s). (AppLocker only logs these when something runs that no rule allows.)" -ForegroundColor Green }
    else {
        # ---- every event to CSV, then the summary: one row per distinct result / file / user / rule, tagged MECM / NESSUS / ADMIN / SYSVOL
        $Csv = Join-Path $Cfg.OutRoot "events-$($Cfg.Stamp).csv"
        $All | Sort-Object Time | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8
        # Event paths use AppLocker variables (%WINDIR%, %PROGRAMFILES%, %OSDRIVE%) or full paths
        $Mecm = '\\ccm\\|\\ccmcache\\|\\ccmsetup\\|\\microsoft configuration manager\\|\\sms_|\\smsexec|\\cm_'
        $Nessus = '\\tenable\\|\\nessus'
        $Admin = @($Cfg.ExtraAllowedPaths | Where-Object { $_ -match '^[A-Za-z]:\\' } | ForEach-Object { '^(' + [regex]::Escape($_.Substring(0, 2)) + '|%OSDRIVE%)' + [regex]::Escape(($_ -replace '\\\*$', '').Substring(2)) + '(\\|$)' })
        $Summary = $All | Group-Object Result, File, User, Rule | ForEach-Object {
            $F = $_.Group[0]
            $Tag = if ($F.File -match $Mecm) { 'MECM' } elseif ($F.File -match $Nessus) { 'NESSUS' } elseif (@($Admin | Where-Object { $F.File -match $_ }).Count) { 'ADMIN' } elseif ($F.File -match '\\sysvol\\|\\netlogon\\') { 'SYSVOL' } else { '' }
            [pscustomobject]@{
                Count = $_.Count; Result = $F.Result; Tag = $Tag; User = $F.User
                File = $F.File; Rule = $F.Rule; Servers = (($_.Group | Select-Object -ExpandProperty Computer -Unique) -join ',')
            }
        } | Sort-Object Count -Descending
        Write-Host "`nTop $Top by frequency (every distinct file / user / rule):"
        $Summary | Select-Object -First $Top | Format-Table Count, Result, Tag, User, File, Servers -AutoSize -Wrap | Out-String -Width 240 | Write-Host
        $ByUser = $All | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name)=$($_.Count)" }
        Write-Host "By account: $($ByUser -join '; ')"
        foreach ($T in 'MECM', 'NESSUS', 'ADMIN', 'SYSVOL') { $N = @($Summary | Where-Object { $_.Tag -eq $T }).Count; if ($N) { Write-Host "$T-related: $N distinct item(s)" } }
        Write-Host 'What to do with each finding: README, "The Audit period".'
        Write-Host "All events: $Csv" -ForegroundColor Green
    }
}
finally { Stop-ALTranscript }
