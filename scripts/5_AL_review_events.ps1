# Step 5 - run from the management computer (Windows PowerShell 5.1 or PowerShell 7). Read-only. Collects the AppLocker AUDIT (would be
# blocked) and BLOCKED events from the servers and summarises them so you can decide what still needs a rule before Enforce:
#   EXE and DLL log:  8003 (audit) / 8004 (blocked)     MSI and Script log: 8006 / 8007     Packaged app-Execution log: 8021 / 8022
# Output: a summary per file / user / rule (most frequent first; Tag = MECM, NESSUS, ADMIN (an ExtraAllowedPaths folder such as C:\Admin)
# or SYSVOL) and a CSV of every event in <root>\Outputs\<profile>\events-<timestamp>.csv. Allowed events (8002/8005/8020) are not collected.
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
$Collect = {
    param([int]$Days, [int]$Max)
    $Since = (Get-Date).AddDays(-$Days)
    $Spec = @(@{ Log = 'EXE and DLL'; Ids = 8003, 8004 }, @{ Log = 'MSI and Script'; Ids = 8006, 8007 }, @{ Log = 'Packaged app-Execution'; Ids = 8021, 8022 })
    foreach ($S in $Spec) {
        $Events = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-AppLocker/$($S.Log)"; Id = $S.Ids; StartTime = $Since } -MaxEvents $Max -ErrorAction SilentlyContinue)
        foreach ($E in $Events) {
            $D = ([xml]$E.ToXml()).Event.UserData.RuleAndFileData
            $User = "$($D.TargetUser)"
            try { $User = (New-Object System.Security.Principal.SecurityIdentifier $User).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            [pscustomobject]@{
                Time = $E.TimeCreated; Computer = $env:COMPUTERNAME; Log = $S.Log; EventId = $E.Id
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
        try { $Rows = @(Invoke-Command -ComputerName $C -ScriptBlock $Collect -ArgumentList $Days, $MaxEventsPerLog -ErrorAction Stop); $Rows | ForEach-Object { $All.Add($_) }; Write-Host "$C : $($Rows.Count) audit/blocked event(s) in the last $Days day(s)" }
        catch { Write-Host "$C : FAILED - $($_.Exception.Message)" -ForegroundColor Red }
    }
    if (-not $All.Count) { Write-Host "`nNo audit or blocked events in the last $Days day(s). (AppLocker only logs these when something runs that no rule allows.)" -ForegroundColor Green }
    else {
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
