# Step 6 - run from the management computer (Windows PowerShell 5.1 or PowerShell 7). Read-only. DISA STIG check, per server in scope:
#   WN25-00-000080 / V-277992 (CAT II): "Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution
#   of authorized software programs."
# It uses the check text's own command (Get-AppLockerPolicy -Effective -XML) on each server:
#   NotAFinding = Application Identity is running and the EXE rule collection is ENFORCED (Enabled) with allow rules, so everything the
#                 rules do not allow is denied. AuditOnly is a finding (it blocks nothing); so is a stopped Application Identity service.
#   Values shown: every rule collection (mode and rule count; DLL rules are not required by the STIG), Application Identity, which
#   AppLocker GPO link is enabled, and blocked events (8004/8007) in the last 24 hours.
# Evidence: each server's effective policy XML (+ SHA-256) in Outputs\<profile>\stig-<ts>\; results in Logs\6_AL_stig_check-<ts>.csv.
# Exit code 1 when any server is Open.
param(
    [string]$SettingsFile,
    [string[]]$TargetOU,
    [string[]]$ComputerName
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '6_AL_stig_check' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
$Stig = [ordered]@{ StigId = 'WN25-00-000080'; VulnId = 'V-277992'; Severity = 'CAT II'; Title = 'Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.' }
$Open = 1

# Runs on a server: the STIG check command plus the facts the status depends on
$Probe = {
    $Xml = Get-AppLockerPolicy -Effective -Xml
    [xml]$Doc = $Xml
    $Svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $Os = Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{
        Computer    = $env:COMPUTERNAME
        Os          = "$($Os.Caption) $($Os.Version)"
        Xml         = "$Xml"
        SvcState    = "$($Svc.State)"
        SvcStart    = "$($Svc.StartMode)"
        Collections = @($Doc.AppLockerPolicy.RuleCollection | ForEach-Object { [pscustomobject]@{ Type = "$($_.Type)"; Mode = "$($_.EnforcementMode)"; Rules = @($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count } })
        Blocked24h  = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8004, 8007; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue).Count
        Checked     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz', [Globalization.CultureInfo]::InvariantCulture)
    }
}

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
        catch { $Rows.Add([pscustomobject]([ordered]@{ Server = $C } + $Stig + [ordered]@{ Status = 'Not_Reviewed'; Reason = "could not be checked: $($_.Exception.Message)" })); continue }
        $Col = @{}; foreach ($X in $P.Collections) { $Col[$X.Type] = $X }
        $Exe = $Col['Exe']
        $Reason = if ($P.SvcState -ne 'Running') { "Application Identity is $($P.SvcState) - AppLocker enforces nothing" }
        elseif (-not $Exe) { 'no AppLocker EXE rule collection in the effective policy - no allowlisting in use' }
        elseif ($Exe.Mode -ne 'Enabled') { "EXE rules are $($Exe.Mode) - not enforced (Audit is a staging step, not compliance)" }
        elseif ($Exe.Rules -lt 1) { 'the EXE rule collection is enforced but has no rules' }
        else { '' }
        $File = Join-Path $Evidence "$($P.Computer)-effective-applocker.xml"
        [IO.File]::WriteAllText($File, $P.Xml, (New-Object Text.UTF8Encoding $false))
        $Value = { param($T) if ($Col[$T]) { "$($Col[$T].Mode) ($($Col[$T].Rules) rules)" } else { 'absent' } }
        $Rows.Add([pscustomobject]([ordered]@{ Server = $C } + $Stig + [ordered]@{
                    Status            = $(if ($Reason) { 'Open' } else { 'NotAFinding' })
                    Reason            = $(if ($Reason) { $Reason } else { 'AppLocker enforces a deny-by-default allowlist: EXE rules Enabled with allow rules, Application Identity running' })
                    Exe               = & $Value 'Exe'
                    Msi               = & $Value 'Msi'
                    Script            = & $Value 'Script'
                    Appx              = & $Value 'Appx'
                    Dll               = & $Value 'Dll'
                    ApplicationIdentity = "$($P.SvcState) / $($P.SvcStart)"
                    Blocked24h        = $P.Blocked24h
                    Os                = $P.Os
                    Checked           = $P.Checked
                    Evidence          = "$File (SHA-256 $(Get-ALSha256 $File))"
                }))
    }
}
catch { $Rows.Add([pscustomobject]([ordered]@{ Server = '(script)' } + $Stig + [ordered]@{ Status = 'Not_Reviewed'; Reason = $_.Exception.Message })) }
finally {
    Write-Host ''
    Write-Host "$($Stig.StigId) / $($Stig.VulnId) ($($Stig.Severity)): $($Stig.Title)" -ForegroundColor Cyan
    foreach ($L in @($Links)) { Write-Host "AppLocker GPO link: $L" }
    foreach ($Row in $Rows) {
        $Row | Select-Object -Property * -ExcludeProperty Title | Format-List | Out-String -Width 220 | ForEach-Object { $_.Trim() } | Write-Host -ForegroundColor $(if ($Row.Status -eq 'NotAFinding') { 'Green' } else { 'Red' })
        Write-Host ''
    }
    $Csv = Join-Path $Cfg.LogDir "$($Cfg.ScriptName)-$($Cfg.Stamp).csv"
    $Rows | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8
    $Open = @($Rows | Where-Object { $_.Status -ne 'NotAFinding' }).Count
    $Summary = "$($Stig.StigId) / $($Stig.VulnId): $(@($Rows | Where-Object { $_.Status -eq 'NotAFinding' }).Count) NotAFinding, $Open Open/Not_Reviewed of $($Rows.Count) server(s). Results: $Csv"
    Write-Host $Summary -ForegroundColor $(if ($Open -or -not $Rows.Count) { 'Red' } else { 'Green' })
    Stop-ALTranscript
}
if ($Open -or -not $Rows.Count) { exit 1 }
