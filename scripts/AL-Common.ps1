<#
.SYNOPSIS
    Shared helpers for the AppLocker scripts. Dot-sourced by every step script; not run on its own.

.DESCRIPTION
    One library, loaded with  . "$PSScriptRoot\AL-Common.ps1"  at the top of each step script. It holds:
      - settings: New-ALDefaultSettings, Initialize-AL (settings file + overrides, folders, transcript), Assert-ALSettings (refuses
        values that would widen the policy or damage a system folder), Set-ALSettingsArray (writes one array setting back in place)
      - the confirmation gate: Confirm-ALChange (yellow Y/N, -NoConfirm, never hangs in a non-interactive session), Test-ALInteractive
      - results and evidence: New-ALResults, Add-ALResult, Write-ALResults (table + CSV + PASSED / FAILED line), Stop-ALTranscript
      - the domain and GPOs: Get-ALDomainInfo, Resolve-ALTargetOUs, Get-ALTargetComputers, Get-ALGpoPaths, Get-ALLinkState,
        ConvertFrom-ALGpLink, Get-ALGpoLinkTargets, Backup-ALGpo, Step-ALGpoVersion, Merge-ALExtensionNames, Set-ALEventLogSize
      - the servers and this computer: Get-ALLocalNames, Test-ALLocalComputer, Invoke-ALOn (a script block over WinRM, or in this
        process when the server is the computer the script runs on - the toolkit run on a DC itself)
      - Group Policy on the servers: $ALGpRefreshProbe and Invoke-ALGpRefresh (gpupdate with its output kept, gpresult as text and
        XML), Save-ALGpResult, ConvertFrom-ALGpResultText, ConvertFrom-ALGpResult, Resolve-ALGpoNames, Get-ALGpVerdict, Add-ALGpResults,
        ConvertTo-ALWin32Message (the Status of AppLocker event 8000)
      - Windows Server versions and STIG items: ConvertTo-ALOsBuild, Get-ALOsLabel, Get-ALStigItem, Get-ALAdOsBuild
      - the build: Get-ALBuildFolder, New-ALDeployXml, Get-ALPolicySummary, Add-ALPathExceptions, Get-ALRuleExceptions,
        Get-ALExtraPathPlan, Get-ALExpectedMode, Get-ALPolicyMismatch, Get-ALManagedCollections, Merge-ALScanResults,
        ConvertTo-ALAaronLockerPath, Get-ALMissingScanEntries
      - permissions: $ALWritableCheck (runs on a server: who can change an ExtraAllowedPaths / SecureFolders item),
        Invoke-ALWritableCheck, Test-ALPathUnder, Test-ALCovered, ConvertTo-ALComparablePath
      - KnownAdmins: Test-ALNeverAdmin, Test-ALBuiltInAdminSid, Split-ALCanonicalName, ConvertTo-ALLdapFilterValue,
        Get-ALKnownAdminEntry, ConvertTo-ALArrayLiteral
      - the toolkit: Import-ALModule, Test-ALModule (both PowerShell editions), Test-ALAccessChk, Get-ALPeMachine, Get-ALSha256
      - the policy conversion check (the rules as Application Identity converts them - one conditional ACE per rule, one ACL per
        collection, 64 KB each): ConvertTo-ALFqbnVersion, ConvertTo-ALConditionExpression, ConvertTo-ALRuleAce, Test-ALSddlNative,
        Get-ALSddlSupport, Test-ALPolicyConvertible, Add-ALPolicyCheckResults, Get-ALStatusHint (what a Status of event 8000 points at)
      - the policy store on a server: $ALPolicyStoreProbe (the converter task, the permissions of the AppLocker folder and keys, the
        compiled <Collection>.AppLocker files, the collections delivered), Add-ALPolicyStoreResults
    Every function is documented where it is defined. The logic here is covered by tests\Test-AL.ps1 (no network, no domain).

.INPUTS
    None. The file is dot-sourced; it takes no parameters.

.OUTPUTS
    None. Dot-sourcing defines the functions and the $ALWritableCheck script block in the caller's scope.

.EXAMPLE
    . "$PSScriptRoot\AL-Common.ps1"
    $Cfg = Initialize-AL -ScriptName '4_AL_validate' -SettingsFile $SettingsFile
    How every step script starts: load the helpers, read and check the settings, start the transcript.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-28
    Version  : 1.3 (policy conversion check against the 64 KB ACL limit, the policy store probe; 1.2: gpupdate / gpresult helpers,
               EnableAppxRules, scripts run on a server itself without WinRM to itself)
    Requires : Windows PowerShell 5.1 or PowerShell 7. ASCII-only source. Modules are loaded on demand by Import-ALModule.
    Changes  : nothing by itself; the step scripts decide what is changed.
#>


# Loads a Windows module in either edition. PowerShell 7: AppLocker runs in the Windows PowerShell compatibility session (so
# Set-AppLockerPolicy behaves exactly as in 5.1); GroupPolicy and ActiveDirectory load with -SkipEditionCheck.
function Import-ALModule([string]$Name) {
    if (Get-Module -Name $Name) { return }
    $WhatIfPreference = $false   # loading a module is not a change (GroupPolicy's alias script would print What-if lines)
    if ($PSVersionTable.PSEdition -eq 'Core') {
        if ($Name -eq 'AppLocker') { Import-Module AppLocker -UseWindowsPowerShell -WarningAction SilentlyContinue -ErrorAction Stop 3>$null }
        else { Import-Module -Name $Name -SkipEditionCheck -WarningAction SilentlyContinue -ErrorAction Stop 3>$null }
    }
    else { Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue }
}

# True when a module is installed. PowerShell 7 hides Windows PowerShell-only modules (GroupPolicy, AppLocker) without -SkipEditionCheck.
function Test-ALModule([string]$Name) {
    if ($PSVersionTable.PSEdition -eq 'Core') { return [bool](Get-Module -ListAvailable -SkipEditionCheck -Name $Name) }
    return [bool](Get-Module -ListAvailable -Name $Name)
}

# Defaults for every setting a settings file may leave out
function New-ALDefaultSettings {
    return @{
        ReferenceServer   = ''
        ExtraReferenceServers = @()
        TargetOUs         = @()
        ExtraAllowedPaths = @()
        SecureFolders     = @()
        KnownAdmins       = @()
        AccessChkSha256   = ''
        EnableDllRules    = $false
        EnableAppxRules   = $true
        EventLogSizesMB   = @{ 'EXE and DLL' = 100; 'MSI and Script' = 20; 'Packaged app-Execution' = 20; 'Packaged app-Deployment' = 20 }
    }
}

# Settings (AL-Settings.psd1 or -SettingsFile, then script-parameter overrides), checked before anything runs; folders and transcript
function Initialize-AL([string]$ScriptName, [hashtable]$Overrides = @{}, [string]$SettingsFile, [switch]$NoTranscript) {
    if (-not $SettingsFile) { $SettingsFile = Join-Path $PSScriptRoot 'AL-Settings.psd1' }
    if (-not (Test-Path -LiteralPath $SettingsFile)) { throw "STOP: settings file not found: $SettingsFile" }
    $Cfg = New-ALDefaultSettings
    try { $File = Import-PowerShellDataFile -LiteralPath $SettingsFile -ErrorAction Stop }
    catch { throw "STOP: $SettingsFile could not be read ($($_.Exception.Message)). Fix the file and run again." }
    foreach ($Key in $File.Keys) { $Cfg[$Key] = $File[$Key] }
    foreach ($Key in @($Overrides.Keys)) {
        $V = $Overrides[$Key]
        $Set = if ($V -is [string]) { $V -ne '' } elseif ($V -is [array]) { $V.Count -gt 0 } else { $null -ne $V }
        if ($Set) { $Cfg[$Key] = $V }
    }
    Assert-ALSettings $Cfg $SettingsFile

    $Cfg.Root = Split-Path -Parent $PSScriptRoot
    if (-not $Cfg.ToolkitPath) { $Cfg.ToolkitPath = Join-Path $Cfg.Root 'AaronLocker\AaronLocker' }
    $Base = [IO.Path]::GetFileNameWithoutExtension($SettingsFile)
    $Cfg.Profile = ($Base -replace '^AL-Settings\.?', '')
    if (-not $Cfg.Profile) { $Cfg.Profile = 'default' }
    $Cfg.OutRoot = Join-Path (Join-Path $Cfg.Root 'Outputs') $Cfg.Profile
    $Cfg.LogDir = Join-Path $Cfg.Root 'Logs'
    # -WhatIf:$false - evidence (folders, transcript, CSV) is written even when a script runs with -WhatIf
    New-Item -Path $Cfg.LogDir, $Cfg.OutRoot -ItemType Directory -Force -WhatIf:$false | Out-Null
    $Cfg.Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Cfg.ScriptName = $ScriptName
    $Cfg.SettingsFile = $SettingsFile
    if (-not $NoTranscript) {
        $Cfg.Transcript = Join-Path $Cfg.LogDir "$ScriptName-$($Cfg.Stamp).log"
        Start-Transcript -Path $Cfg.Transcript -WhatIf:$false | Out-Null
    }
    return $Cfg
}

# Refuses settings that would widen the policy, damage a system folder or break a check - before anything runs
function Assert-ALSettings($Cfg, [string]$SettingsFile) {
    foreach ($Key in 'AuditGpoName', 'EnforceGpoName') { if (-not $Cfg[$Key]) { throw "STOP: setting '$Key' is empty ($SettingsFile)." } }
    if ($Cfg.AuditGpoName -eq $Cfg.EnforceGpoName) { throw 'STOP: AuditGpoName and EnforceGpoName must be different.' }
    if ($Cfg.ReferenceServer -and $Cfg.ReferenceServer -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw "STOP: ReferenceServer '$($Cfg.ReferenceServer)' is not a computer name. Use the FQDN, e.g. dc01.contoso.com." }
    foreach ($S in @($Cfg.ExtraReferenceServers | Where-Object { $_ })) {
        if ("$S" -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw "STOP: ExtraReferenceServers entry '$S' is not a computer name. Use the FQDN, e.g. dc22-01.contoso.com." }
    }
    foreach ($P in @($Cfg.ExtraAllowedPaths)) {
        if ("$P" -notmatch '^(?:[A-Za-z]:\\[^*?"<>|:]*[^\\*?"<>|:]|\\\\[^\\*?"<>|]+\\[^\\*?"<>|]+(?:\\[^*?"<>|]*[^\\*?"<>|])?)(?:\\\*)?$') {
            throw "STOP: ExtraAllowedPaths entry '$P' is not allowed. Use a fixed local or UNC folder ending in \* (or a single file): no drive root, no other wildcards, no %variables%."
        }
    }
    foreach ($F in @($Cfg.SecureFolders)) {
        if ("$F" -notmatch '^[A-Za-z]:\\[^*?"<>|:]*[^\\*?"<>|:]$') { throw "STOP: SecureFolders entry '$F' must be a local folder such as C:\Admin (no trailing \, no wildcards)." }
        if ("$F" -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|PerfLogs|Recovery|System Volume Information)(\\|$)') {
            throw "STOP: SecureFolders entry '$F' is a system folder. 0_AL_secure_folders.ps1 must never replace its permissions - remove it from SecureFolders."
        }
    }
    foreach ($K in @($Cfg.KnownAdmins)) {
        if ("$K" -notmatch '^(S-1-\d+(-\d+)+|[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+)$') { throw "STOP: KnownAdmins entry '$K' must be a SID (S-1-5-21-...) or DOMAIN\Group." }
        if (Test-ALNeverAdmin "$K") { throw "STOP: KnownAdmins entry '$K' is not an administrators group. Listing it would make every folder its members can write count as administrators-only and WIDEN the policy - remove it." }
    }
    if ($Cfg.AccessChkSha256 -and $Cfg.AccessChkSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'STOP: AccessChkSha256 must be a 64-character SHA-256 hex string (or empty).' }
    foreach ($N in @($Cfg.EventLogSizesMB.Keys)) {
        if ($N -notin 'EXE and DLL', 'MSI and Script', 'Packaged app-Execution', 'Packaged app-Deployment') { throw "STOP: EventLogSizesMB names an unknown AppLocker log '$N'." }
        $V = 0
        if (-not [int]::TryParse("$($Cfg.EventLogSizesMB[$N])", [ref]$V) -or $V -lt 1 -or $V -gt 4096) { throw "STOP: EventLogSizesMB '$N' must be a whole number of MB from 1 to 4096." }
    }
}

# True for a principal that must never be a KnownAdmins entry - every user, computer or guest would count as an administrator:
# Everyone, INTERACTIVE, ANONYMOUS LOGON, Authenticated Users, Users, Guests, Pre-Windows 2000 Compatible Access, Remote Desktop
# Users, and Domain Users / Domain Guests / Domain Computers (RID 513 / 514 / 515) - as a SID or as DOMAIN\Name
function Test-ALNeverAdmin([string]$Entry) {
    if ($Entry -match '^S-1-') {
        if ($Entry -in 'S-1-1-0', 'S-1-5-4', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-32-554', 'S-1-5-32-555') { return $true }
        return ($Entry -match '^S-1-5-21-\d+-\d+-\d+-(513|514|515)$')
    }
    return ($Entry -match '^[^\\]+\\(Domain Users|Domain Guests|Domain Computers|Users|Guests|Everyone|INTERACTIVE|ANONYMOUS LOGON|Authenticated Users|Pre-Windows 2000 Compatible Access|Remote Desktop Users)$')
}

# True for a SID that the AaronLocker scan and $ALWritableCheck already treat as an administrator (listing it in KnownAdmins changes
# nothing): CREATOR OWNER, SERVICE, SYSTEM, LOCAL/NETWORK SERVICE, Administrators, Server/Print/Backup Operators, NT SERVICE\
# accounts, and the domain's Administrator, Domain Admins and Enterprise Admins (RID 500 / 512 / 519)
function Test-ALBuiltInAdminSid([string]$Sid) {
    if ($Sid -in 'S-1-3-0', 'S-1-5-6', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551') { return $true }
    return ($Sid -like 'S-1-5-80-*' -or $Sid -match '^S-1-5-21-\d+-\d+-\d+-(500|512|519)$')
}

# A canonical name as Active Directory Users and Computers shows it (contoso.com/Top OU/Sub OU/Name) -> the domain's DNS name and
# the path segments. A slash inside a name is escaped as \/ there. The domain alone gives no segments.
function Split-ALCanonicalName([string]$Name) {
    $Trimmed = "$Name".Trim()
    if ($Trimmed.EndsWith('/') -and -not $Trimmed.EndsWith('\/')) { $Trimmed = $Trimmed.Substring(0, $Trimmed.Length - 1) }
    $Parts = @([regex]::Split($Trimmed, '(?<!\\)/') | ForEach-Object { $_ -replace '\\/', '/' })
    if ($Parts.Count -lt 1 -or @($Parts | Where-Object { "$_".Trim() -eq '' }).Count -or $Parts[0] -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {
        throw "STOP: '$Name' is not a canonical name. Use the form contoso.com/Top OU/Sub OU/Name (as Active Directory Users and Computers shows it) or a distinguished name (OU=...,DC=...)."
    }
    return [pscustomobject]@{ Domain = $Parts[0]; Segments = @($Parts | Select-Object -Skip 1) }
}

# Escapes a value for use inside an LDAP filter (RFC 4515): \ * ( ) and NUL
function ConvertTo-ALLdapFilterValue([string]$Value) {
    $Sb = New-Object System.Text.StringBuilder
    foreach ($C in "$Value".ToCharArray()) {
        if ($C -eq '\' -or $C -eq '*' -or $C -eq '(' -or $C -eq ')' -or [int]$C -eq 0) { [void]$Sb.Append('\').Append(([int]$C).ToString('x2')) } else { [void]$Sb.Append($C) }
    }
    return $Sb.ToString()
}

# The KnownAdmins entry for a principal: DOMAIN\Name when it is ASCII and passes the settings check, otherwise (or with -AsSid) its SID
function Get-ALKnownAdminEntry([string]$PrincipalName, [string]$Sid, [switch]$AsSid) {
    if (-not $AsSid -and $PrincipalName -match '^[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+$' -and $PrincipalName -notmatch '[^\x20-\x7E]') { return $PrincipalName }
    return $Sid
}

# "@('A', 'B')" as it is written into a settings file (single quotes doubled); an empty list (or $null) gives "@()"
function ConvertTo-ALArrayLiteral([string[]]$Values) {
    $Items = @($Values | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "'" + ("$_" -replace "'", "''") + "'" })
    return ('@(' + ($Items -join ', ') + ')')
}

# Replaces the value of one array setting in a .psd1 in place - comments, layout, line endings and encoding are kept. The new text is
# proven first (it loads as a data file with exactly that value and passes Assert-ALSettings); the file is not touched otherwise. The
# original is copied to $BackupFolder before the write, and the written file is read back. Returns Backup / Before / After (SHA-256).
function Set-ALSettingsArray([string]$SettingsFile, [string]$Key, [string[]]$Values, [string]$BackupFolder) {
    $Values = @($Values | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    $Bytes = [IO.File]::ReadAllBytes($SettingsFile)
    $Bom = ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF)
    $Text = (New-Object System.Text.UTF8Encoding $false).GetString($Bytes, $(if ($Bom) { 3 } else { 0 }), $Bytes.Length - $(if ($Bom) { 3 } else { 0 }))
    $Tokens = $null; $Errors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$Tokens, [ref]$Errors)
    if ($Errors.Count) { throw "STOP: $SettingsFile does not parse: $($Errors[0].Message)" }
    $Table = $Ast.Find({ param($N) $N -is [System.Management.Automation.Language.HashtableAst] }, $false)
    if (-not $Table) { throw "STOP: $SettingsFile contains no settings hashtable." }
    $Pairs = @($Table.KeyValuePairs | Where-Object { $_.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $_.Item1.Value -eq $Key })
    if ($Pairs.Count -ne 1) { throw "STOP: $SettingsFile must contain exactly one '$Key' entry (found $($Pairs.Count)). Add a line  $Key = @()  and run again." }
    if (@($Values | Where-Object { $_ -match '[^\x20-\x7E]' }).Count) { throw "STOP: a '$Key' value contains a character outside ASCII; the settings file is ASCII. Use the SID instead." }
    $Extent = $Pairs[0].Item2.Extent
    $New = $Text.Substring(0, $Extent.StartOffset) + (ConvertTo-ALArrayLiteral $Values) + $Text.Substring($Extent.EndOffset)
    $Encoding = New-Object System.Text.UTF8Encoding $Bom
    # Prove it before the file is touched
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ('AL-settings-' + [guid]::NewGuid().ToString('N') + '.psd1')
    try {
        [IO.File]::WriteAllText($Tmp, $New, $Encoding)
        $Check = Import-PowerShellDataFile -LiteralPath $Tmp -ErrorAction Stop
        if ((@($Check[$Key]) -join "`n") -cne ($Values -join "`n")) { throw "the '$Key' value did not read back as written" }
        $Cfg = New-ALDefaultSettings
        foreach ($K in @($Check.Keys)) { $Cfg[$K] = $Check[$K] }
        Assert-ALSettings $Cfg $SettingsFile
    }
    catch {
        $Msg = "$($_.Exception.Message)"
        if ($Msg -like 'STOP:*') { throw "$Msg ($SettingsFile was not changed.)" }
        throw "STOP: the new settings file would not load ($Msg). $SettingsFile was not changed."
    }
    finally { Remove-Item -LiteralPath $Tmp -Force -ErrorAction SilentlyContinue -WhatIf:$false }
    $Before = Get-ALSha256 $SettingsFile
    New-Item -Path $BackupFolder -ItemType Directory -Force -WhatIf:$false | Out-Null
    $Backup = Join-Path $BackupFolder ([IO.Path]::GetFileNameWithoutExtension($SettingsFile) + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + [IO.Path]::GetExtension($SettingsFile))
    Copy-Item -LiteralPath $SettingsFile -Destination $Backup -Force -WhatIf:$false
    [IO.File]::WriteAllText($SettingsFile, $New, $Encoding)
    $Verify = Import-PowerShellDataFile -LiteralPath $SettingsFile -ErrorAction Stop
    if ((@($Verify[$Key]) -join "`n") -cne ($Values -join "`n")) { throw "STOP: $SettingsFile was written but reads back another '$Key' value. Restore the backup: $Backup" }
    return [pscustomobject]@{ Backup = $Backup; Before = $Before; After = (Get-ALSha256 $SettingsFile) }
}

# PowerShell 7's Stop-Transcript honours -WhatIf (5.1's has no such parameter), so the preference is cleared locally instead
function Stop-ALTranscript { $WhatIfPreference = $false; try { Stop-Transcript | Out-Null } catch { } }

# True when a person can answer Read-Host: an interactive desktop session, not started with -NonInteractive, stdin not redirected
function Test-ALInteractive {
    if (-not [Environment]::UserInteractive) { return $false }
    if (@([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' }).Count -gt 0) { return $false }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { }
    return $true
}

# Yellow Y/N gate before a change; -NoConfirm for automation. A non-interactive session without -NoConfirm stops.
function Confirm-ALChange {
    param([Parameter(Mandatory)][string]$Action, [string[]]$Detail = @(), [switch]$NoConfirm)
    Write-Host ''
    Write-Host "WARNING: this changes AppLocker - $Action" -ForegroundColor Yellow
    foreach ($Line in $Detail) { if ($Line) { Write-Host "  $Line" -ForegroundColor Yellow } }
    if ($NoConfirm) { Write-Host '  -NoConfirm: continuing without a prompt.' -ForegroundColor Yellow; return }
    if (-not (Test-ALInteractive)) { throw 'STOP: this change needs a Y/N confirmation but the session is non-interactive. Nothing was changed. Add -NoConfirm for automation.' }
    for ($Try = 1; $Try -le 3; $Try++) {
        $Answer = "$(Read-Host 'Continue? [Y/N]')".Trim()
        if ($Answer -match '^(y|yes)$') { Write-Host '  Confirmed.' -ForegroundColor Yellow; return }
        if ($Answer -match '^(n|no)$') { break }
        Write-Host '  Please answer Y or N.' -ForegroundColor Yellow
    }
    throw 'STOP: not confirmed - nothing was changed.'
}

function New-ALResults { return , (New-Object System.Collections.Generic.List[object]) }
function Add-ALResult($List, [string]$Status, [string]$Check, [string]$Detail) { $List.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail }) }
# Prints the table, saves it as Logs\<script>-<timestamp>.csv and returns the number of FAIL rows
function Write-ALResults($List, $Cfg, [string]$Title) {
    $Csv = Join-Path $Cfg.LogDir "$($Cfg.ScriptName)-$($Cfg.Stamp).csv"
    $List | Format-Table -AutoSize -Wrap | Out-String -Width 240 | Write-Host
    $List | Export-Csv -LiteralPath $Csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $Failed = @($List | Where-Object Status -eq 'FAIL').Count
    $Warned = @($List | Where-Object Status -eq 'WARN').Count
    if ($Failed) { Write-Host "$($Title): FAILED - $Failed failure(s), $Warned warning(s). Results: $Csv" -ForegroundColor Red }
    elseif ($Warned) { Write-Host "$($Title): PASSED with $Warned warning(s). Results: $Csv" -ForegroundColor Yellow }
    else { Write-Host "$($Title): PASSED. Results: $Csv" -ForegroundColor Green }
    return $Failed
}

function Get-ALDomainInfo {
    Import-ALModule ActiveDirectory
    $D = Get-ADDomain -ErrorAction Stop
    [pscustomobject]@{ DnsRoot = $D.DNSRoot; DN = $D.DistinguishedName; PDC = $D.PDCEmulator; NetBIOS = $D.NetBIOSName; DcOU = $D.DomainControllersContainer }
}

# Target OUs from the settings (default: Domain Controllers); each must exist
function Resolve-ALTargetOUs($Cfg, $Domain) {
    $Ous = @($Cfg.TargetOUs | Where-Object { $_ })
    if ($Ous.Count -eq 0) { $Ous = @($Domain.DcOU) }
    foreach ($Ou in $Ous) { Get-ADObject -Identity $Ou -Server $Domain.PDC -ErrorAction Stop | Out-Null }
    return $Ous
}

# Enabled Windows Server computer accounts in the OUs (sub-OUs included), as FQDNs
function Get-ALTargetComputers([string[]]$Ous, $Domain) {
    $Names = foreach ($Ou in $Ous) {
        Get-ADComputer -SearchBase $Ou -SearchScope Subtree -Filter 'Enabled -eq $true' -Properties DNSHostName, OperatingSystem -Server $Domain.PDC |
            Where-Object { $_.OperatingSystem -like 'Windows Server*' } | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
    }
    return @($Names | Sort-Object -Unique)
}

# Windows build number from a version string: '10.0.26100' (Win32_OperatingSystem) or '10.0 (26100)' (AD operatingSystemVersion);
# 0 when there is none
function ConvertTo-ALOsBuild([string]$Version) {
    $Build = 0
    if ($Version -match '\((\d{1,9})\)' -or $Version -match '^\s*\d+\.\d+\.(\d{1,9})') { [void][int]::TryParse($Matches[1], [ref]$Build) }
    return $Build
}

# 'Windows Server 2025 (build 26100)' for the Windows Server builds this toolkit names, 'Windows build <n>' for any other
function Get-ALOsLabel([int]$Build) {
    if ($Build -le 0) { return 'unknown version' }
    $Name = switch ($Build) { 14393 { 'Windows Server 2016' } 17763 { 'Windows Server 2019' } 20348 { 'Windows Server 2022' } 26100 { 'Windows Server 2025' } default { '' } }
    if ($Name) { return "$Name (build $Build)" }
    return "Windows build $Build"
}

# The DISA STIG item this toolkit meets ("deny-all, permit-by-exception") for a Windows Server build: 26100 = Windows Server 2025,
# 20348 = Windows Server 2022. $null for any other build: no mapping, so the STIG check reports Not_Reviewed instead of a wrong ID.
# Rule IDs (SV-...) change with every STIG revision; the STIG ID and the V-ID do not.
function Get-ALStigItem([int]$Build) {
    $Text = 'must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
    switch ($Build) {
        26100 { return [ordered]@{ StigId = 'WN25-00-000080'; VulnId = 'V-277992'; Severity = 'CAT II'; Title = "Windows Server 2025 $Text" } }
        20348 { return [ordered]@{ StigId = 'WN22-00-000080'; VulnId = 'V-254245'; Severity = 'CAT II'; Title = "Windows Server 2022 $Text" } }
    }
    return $null
}

# Windows build of a computer from its AD account (operatingSystemVersion, e.g. '10.0 (26100)'), found by DNS host name or computer
# name; 0 when there is no single matching account or it carries no version. For servers that cannot be reached over WinRM.
function Get-ALAdOsBuild([string]$ComputerName, $Domain) {
    $Short = ($ComputerName -split '\.')[0]
    $Filter = '(|(dNSHostName={0})(sAMAccountName={1}$))' -f (ConvertTo-ALLdapFilterValue $ComputerName), (ConvertTo-ALLdapFilterValue $Short)
    try { $Found = @(Get-ADComputer -LDAPFilter $Filter -Properties OperatingSystemVersion -Server $Domain.PDC -ErrorAction Stop) } catch { return 0 }
    if ($Found.Count -ne 1) { return 0 }
    return (ConvertTo-ALOsBuild "$($Found[0].OperatingSystemVersion)")
}

# AD and SYSVOL locations of a GPO (writes go to the PDC emulator)
function Get-ALGpoPaths($GpoId, $Domain) {
    $Id = '{' + ("$GpoId".Trim('{}')).ToUpper() + '}'
    [pscustomobject]@{
        Id        = $Id
        AdPath    = "CN=$Id,CN=Policies,CN=System,$($Domain.DN)"
        SysvolPdc = "\\$($Domain.PDC)\SYSVOL\$($Domain.DnsRoot)\Policies\$Id"
    }
}

# Merges client-side-extension entries ([{CSE}{Tool}...]) into gPCMachineExtensionNames, sorted the way GPMC writes them
function Merge-ALExtensionNames([string]$Existing, [string[]]$Add) {
    $Map = @{}
    foreach ($Block in [regex]::Matches("$Existing$($Add -join '')", '\[([^\]]+)\]')) {
        $Guids = @([regex]::Matches($Block.Groups[1].Value, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $_.Value.ToUpper() })
        if ($Guids.Count -eq 0) { continue }
        if (-not $Map.ContainsKey($Guids[0])) { $Map[$Guids[0]] = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
        foreach ($Tool in @($Guids | Select-Object -Skip 1)) { [void]$Map[$Guids[0]].Add($Tool) }
    }
    return (@($Map.Keys | Sort-Object | ForEach-Object { '[' + $_ + (@($Map[$_]) -join '') + ']' }) -join '')
}

# Raises the computer-side version of a GPO by one in AD and GPT.INI so computers reprocess it
function Step-ALGpoVersion($Paths, $Domain) {
    $Obj = Get-ADObject -Identity $Paths.AdPath -Properties versionNumber -Server $Domain.PDC -ErrorAction Stop
    $New = [int]$Obj.versionNumber + 1
    Set-ADObject -Identity $Paths.AdPath -Replace @{ versionNumber = $New } -Server $Domain.PDC -ErrorAction Stop
    $Ini = Join-Path $Paths.SysvolPdc 'GPT.INI'
    $Lines = if (Test-Path -LiteralPath $Ini) { @(Get-Content -LiteralPath $Ini) } else { @('[General]') }
    if ($Lines -match '^Version=') { $Lines = @($Lines | ForEach-Object { if ($_ -match '^Version=') { "Version=$New" } else { $_ } }) } else { $Lines += "Version=$New" }
    Set-Content -LiteralPath $Ini -Value $Lines -Encoding Ascii
    return $New
}

# Backs up a GPO (Backup-GPO) to Outputs\<profile>\gpo-backups\<timestamp> before it is changed. Undo with:
#   Restore-GPO -BackupId <BackupId> -Path <Folder>    (or Import-GPO into another GPO)
function Backup-ALGpo($Gpo, $Cfg, $Domain) {
    $Dir = Join-Path (Join-Path $Cfg.OutRoot 'gpo-backups') $Cfg.Stamp
    New-Item -Path $Dir -ItemType Directory -Force -WhatIf:$false | Out-Null
    $B = Backup-GPO -Guid $Gpo.Id -Path $Dir -Server $Domain.PDC -Comment "Before $($Cfg.ScriptName) $($Cfg.Stamp)" -ErrorAction Stop
    return [pscustomobject]@{ Folder = $Dir; BackupId = "$($B.Id)" }
}

# $true / $false = link enabled / disabled; $null = the GPO is not linked to the OU
function Get-ALLinkState($GpoId, [string]$Ou, $Domain) {
    $Link = (Get-GPInheritance -Target $Ou -Server $Domain.PDC).GpoLinks | Where-Object { $_.GpoId -eq $GpoId }
    if ($Link) { return [bool]$Link.Enabled } else { return $null }
}

# The links in a gPLink attribute value ([LDAP://cn={GUID},cn=policies,cn=system,DC=...;<options>]...): Guid ({UPPER CASE}), Dn,
# Options (bit 1 = link disabled, bit 2 = enforced), Enabled
function ConvertFrom-ALGpLink([string]$GpLink) {
    foreach ($M in [regex]::Matches("$GpLink", '\[LDAP://([^;\]]+);(\d+)\]', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $Dn = $M.Groups[1].Value
        $G = [regex]::Match($Dn, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')
        $Options = [int]$M.Groups[2].Value
        [pscustomobject]@{ Guid = $(if ($G.Success) { $G.Value.ToUpper() } else { '' }); Dn = $Dn; Options = $Options; Enabled = (($Options -band 1) -eq 0) }
    }
}

# Every domain, OU or site whose gPLink names a GPO - not only the target OUs: Target (DN), Enabled, Enforced. Searched in the domain
# partition and under CN=Sites of the configuration partition (when it can be read).
function Get-ALGpoLinkTargets($GpoId, $Domain) {
    $Id = '{' + ("$GpoId".Trim('{}')).ToUpper() + '}'
    $Bases = @($Domain.DN)
    try { $Bases += 'CN=Sites,' + (Get-ADRootDSE -Server $Domain.PDC -ErrorAction Stop).configurationNamingContext } catch { }
    $Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($B in $Bases) {
        foreach ($O in @(Get-ADObject -SearchBase $B -LDAPFilter "(gPLink=*$Id*)" -Properties gPLink -Server $Domain.PDC -ErrorAction Stop)) {
            if (-not $Seen.Add("$($O.DistinguishedName)")) { continue }
            foreach ($L in @(ConvertFrom-ALGpLink "$($O.gPLink)" | Where-Object { $_.Guid -eq $Id })) {
                [pscustomobject]@{ Target = "$($O.DistinguishedName)"; Enabled = $L.Enabled; Enforced = (($L.Options -band 2) -ne 0) }
            }
        }
    }
}

# The build that 2_AL_create_gpos.ps1 deploys: -OutputFolder, else the folder named in Outputs\<profile>\latest.txt, else the newest
# build. Only the last part of latest.txt is used (older builds wrote a full path, which broke when the folder was moved).
function Get-ALBuildFolder($Cfg, [string]$OutputFolder) {
    if ($OutputFolder) {
        if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) { throw "STOP: build folder not found: $OutputFolder" }
        return (Resolve-Path -LiteralPath $OutputFolder).ProviderPath
    }
    $Latest = Join-Path $Cfg.OutRoot 'latest.txt'
    if (Test-Path -LiteralPath $Latest) {
        $Name = Split-Path -Leaf ("$(Get-Content -LiteralPath $Latest -Raw)".Trim())
        if ($Name -and (Test-Path -LiteralPath (Join-Path $Cfg.OutRoot $Name) -PathType Container)) { return (Join-Path $Cfg.OutRoot $Name) }
    }
    $Newest = Get-ChildItem -LiteralPath $Cfg.OutRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d{8}-\d{6}$' -and (Get-ChildItem -LiteralPath $_.FullName -Filter 'AppLockerRules-*.xml') } | Sort-Object Name | Select-Object -Last 1
    if ($Newest) { return $Newest.FullName }
    throw "STOP: no build in $($Cfg.OutRoot). Run 1_AL_build_policy.ps1 first."
}

# Turns an AaronLocker output file into the XML that goes into a GPO: Audit = every collection AuditOnly, Enforce = every collection
# Enabled, the DLL collection emptied and set to NotConfigured unless DLL rules are wanted, and the Appx (packaged app) collection
# emptied the same way when EnableAppxRules is $false (Server Core installations without packaged-app support).
function New-ALDeployXml([string]$SourceXml, [ValidateSet('Audit', 'Enforce')][string]$Mode, [bool]$DllRules, [string]$OutFile, [bool]$AppxRules = $true) {
    $Doc = New-Object System.Xml.XmlDocument
    try { $Doc.Load($SourceXml) } catch { throw "STOP: $SourceXml is not valid XML ($($_.Exception.Message))." }
    if (-not $Doc.AppLockerPolicy) { throw "STOP: $SourceXml is not an AppLocker policy." }
    $Want = if ($Mode -eq 'Audit') { 'AuditOnly' } else { 'Enabled' }
    foreach ($Rc in @($Doc.AppLockerPolicy.RuleCollection)) {
        if ($Rc.Type -eq 'ManagedInstaller') { throw 'STOP: the source contains a ManagedInstaller rule collection; leave that to Configuration Manager.' }
        if ($Rc.Type -eq 'Dll' -and -not $DllRules) { $Rc.RemoveAll(); $Rc.SetAttribute('Type', 'Dll'); $Rc.SetAttribute('EnforcementMode', 'NotConfigured') }
        elseif ($Rc.Type -eq 'Appx' -and -not $AppxRules) { $Rc.RemoveAll(); $Rc.SetAttribute('Type', 'Appx'); $Rc.SetAttribute('EnforcementMode', 'NotConfigured') }
        elseif ($Rc.EnforcementMode -ne $Want) { throw "STOP: $($Rc.Type) collection is '$($Rc.EnforcementMode)' in $SourceXml, expected $Want." }
    }
    $Doc.Save($OutFile)
    return (Get-ALPolicySummary $Doc)
}

# "Exe=Enabled(10), Msi=Enabled(5), ..." for an AppLocker policy document
function Get-ALPolicySummary([xml]$Doc) {
    return (@($Doc.AppLockerPolicy.RuleCollection | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count))" }) -join ', ')
}

# Sets the AppLocker event log sizes (MB) on the computers (over WinRM, or in this process for this computer); one text line each
function Set-ALEventLogSize([string[]]$Computers, [hashtable]$SizesMB) {
    foreach ($C in $Computers) {
        try {
            Invoke-ALOn $C -ArgumentList (, $SizesMB) -ScriptBlock {
                param($Sizes)
                foreach ($N in $Sizes.Keys) {
                    wevtutil.exe sl "Microsoft-Windows-AppLocker/$N" /ms:$([int64]$Sizes[$N] * 1MB)
                    if ($LASTEXITCODE) { throw "wevtutil failed for '$N' (exit $LASTEXITCODE)" }
                }
                "$env:COMPUTERNAME log sizes: " + ((Get-WinEvent -ListLog 'Microsoft-Windows-AppLocker/*' | ForEach-Object { '{0}={1}MB' -f ($_.LogName -replace '^.*/', ''), ($_.MaximumSizeInBytes / 1MB) }) -join ', ')
            }
        }
        catch { "$C : FAILED - $($_.Exception.Message)" }
    }
}

# SHA-256 of a file. Reading is not a change: in Windows PowerShell 5.1 Get-FileHash is a script that -WhatIf would silently skip.
function Get-ALSha256([string]$Path) {
    $WhatIfPreference = $false
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

# PE machine type of an executable: 0x8664 x64, 0xAA64 ARM64, 0x14C x86 (0 = not a PE file)
function Get-ALPeMachine([string]$Path) {
    $Fs = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Path).ProviderPath)
    try {
        $B = New-Object byte[] 4096
        $Len = $Fs.Read($B, 0, $B.Length)
        if ($Len -lt 64 -or $B[0] -ne 0x4D -or $B[1] -ne 0x5A) { return 0 }
        $Pe = [BitConverter]::ToInt32($B, 0x3C)
        if ($Pe -lt 64 -or $Pe -gt ($Len - 6) -or $B[$Pe] -ne 0x50 -or $B[$Pe + 1] -ne 0x45) { return 0 }
        return [int][BitConverter]::ToUInt16($B, $Pe + 4)
    }
    finally { $Fs.Dispose() }
}

# Offline check of AccessChk.exe: present, Authenticode-valid and Microsoft-signed, really Sysinternals AccessChk, 64-bit, and (when
# pinned) equal to AccessChkSha256. No network access: the signature is timestamped, so it stays valid after the certificate expires.
function Test-ALAccessChk([string]$Path, [string]$Sha256) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [pscustomobject]@{ Ok = $false; Detail = "missing: $Path - it ships in this repository; restore it, or import one with 0_AL_get_toolkit.ps1 -AccessChkPath" } }
    $Sig = Get-AuthenticodeSignature -LiteralPath $Path
    $Hash = Get-ALSha256 $Path
    $Info = (Get-Item -LiteralPath $Path).VersionInfo
    if ($Sig.Status -ne 'Valid' -or $Sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { return [pscustomobject]@{ Ok = $false; Detail = "signature is $($Sig.Status), not a valid Microsoft signature (SHA-256 $Hash)" } }
    if ($Info.ProductName -ne 'Sysinternals AccessChk') { return [pscustomobject]@{ Ok = $false; Detail = "is '$($Info.ProductName)' $($Info.OriginalFilename), not Sysinternals AccessChk (SHA-256 $Hash)" } }
    if ((Get-ALPeMachine $Path) -notin 0x8664, 0xAA64) { return [pscustomobject]@{ Ok = $false; Detail = 'is a 32-bit build - use accesschk64.exe from AccessChk.zip, renamed to AccessChk.exe (32-bit programs are subject to WOW64 file-system redirection)' } }
    if ($Sha256 -and $Hash -ne $Sha256.Trim().ToUpper()) { return [pscustomobject]@{ Ok = $false; Detail = "SHA-256 $Hash does not match the pinned AccessChkSha256 $($Sha256.Trim().ToUpper())" } }
    return [pscustomobject]@{ Ok = $true; Detail = "Microsoft-signed Sysinternals AccessChk $($Info.FileVersion) (64-bit), SHA-256 $Hash$(if ($Sha256) { ' (pinned)' } else { ' (not pinned)' })" }
}

# Runs ON a server (through Invoke-ALWritableCheck). For every ExtraAllowedPaths / SecureFolders entry it emits
#   NOTFOUND|<path>                           the path does not exist on that server
#   WRITABLE|<file or folder>|<account>|D/F   an account that is not an administrator may write, delete or re-permission it, so a
#                                             path rule there would let that account plant code that every user may run
#   UNREADABLE|<file or folder>||D/F          its permissions could not be read
#   UNRESOLVED|<KnownAdmins entry>            a KnownAdmins name could not be resolved to a SID on that server
# (D = folder, F = file)
# Administrators = the accounts AaronLocker's scan also ignores (SYSTEM, LOCAL/NETWORK SERVICE, SERVICE, Administrators, Server/Print/
# Backup Operators, TrustedInstaller and other NT SERVICE\ accounts), the direct members of Administrators (on a DC: Administrator,
# Domain Admins, Enterprise Admins) and KnownAdmins. CREATOR OWNER is ignored: it only covers what an account creates, and creating
# needs write access, which is checked. Folders AND files are checked, including entries that only apply to new children.
# Nothing is changed - permissions are only read.
$ALWritableCheck = {
    param([string[]]$Paths, [string[]]$KnownAdmins)
    $Admin = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($S in 'S-1-3-0', 'S-1-5-6', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551') { [void]$Admin.Add($S) }
    try {
        foreach ($M in @(([ADSI]'WinNT://./Administrators,group').Invoke('Members'))) {
            [void]$Admin.Add((New-Object System.Security.Principal.SecurityIdentifier ([byte[]]$M.GetType().InvokeMember('objectSid', 'GetProperty', $null, $M, $null)), 0).Value)
        }
    }
    catch { }
    foreach ($K in @($KnownAdmins | Where-Object { $_ })) {
        if ($K -match '^S-1-') { [void]$Admin.Add($K); continue }
        try { [void]$Admin.Add((New-Object System.Security.Principal.NTAccount $K).Translate([System.Security.Principal.SecurityIdentifier]).Value) } catch { "UNRESOLVED|$K" }
    }
    # Write data / add file, append data / add subfolder, delete child, delete, change permissions, take ownership, generic all, generic write
    $Mask = 0x2 -bor 0x4 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    foreach ($P in $Paths) {
        $Target = $P -replace '\\\*$', ''
        if (-not (Test-Path -LiteralPath $Target)) { "NOTFOUND|$P"; continue }
        $Items = @(Get-Item -LiteralPath $Target -Force)
        if ($Items[0].PSIsContainer) { $Items += @(Get-ChildItem -LiteralPath $Target -Recurse -Force -ErrorAction SilentlyContinue) }
        foreach ($I in $Items) {
            $Type = if ($I.PSIsContainer) { 'D' } else { 'F' }
            try { $Rules = (Get-Acl -LiteralPath $I.FullName -ErrorAction Stop).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) }
            catch { "UNREADABLE|$($I.FullName)||$Type"; continue }
            foreach ($Rule in $Rules) {
                $Sid = $Rule.IdentityReference.Value
                if ($Rule.AccessControlType -ne 'Allow' -or ([int64]$Rule.FileSystemRights -band $Mask) -eq 0) { continue }
                if ($Admin.Contains($Sid) -or $Sid -like 'S-1-5-80-*' -or $Sid -match '^S-1-5-21-.+-(500|512|519)$') { continue }
                $Name = $Sid
                try { $Name = "$($Rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value) ($Sid)" } catch { }
                "WRITABLE|$($I.FullName)|$Name|$Type"
                break
            }
        }
    }
}

# Runs $ALWritableCheck on a server (-ComputerName or -Session; in this process when the server is this computer) with the
# KnownAdmins setting; returns Kind / Path / Account / IsFolder / Computer rows
function Invoke-ALWritableCheck([string[]]$Paths, $Cfg, [string]$ComputerName, $Session) {
    $Name = if ($Session) { $Session.ComputerName } else { $ComputerName }
    $Lines = if ($Session) { @(Invoke-Command -Session $Session -ScriptBlock $ALWritableCheck -ArgumentList @($Paths), @($Cfg.KnownAdmins) -ErrorAction Stop) }
    else { @(Invoke-ALOn $ComputerName $ALWritableCheck (@($Paths), @($Cfg.KnownAdmins))) }
    foreach ($Line in $Lines) {
        $F = "$Line" -split '\|'
        [pscustomobject]@{ Kind = $F[0]; Path = $F[1]; Account = $(if ($F.Count -gt 2) { $F[2] } else { '' }); IsFolder = ($F.Count -gt 3 -and $F[3] -eq 'D'); Computer = $Name }
    }
}

# Compares paths the way AppLocker does: case-insensitive, %OSDRIVE% = C:
function ConvertTo-ALComparablePath([string]$Path) { return ($Path -replace '^%OSDRIVE%', 'C:').TrimEnd('\').ToUpperInvariant() }

# True when a file/folder reported by $ALWritableCheck lies inside an ExtraAllowedPaths / SecureFolders entry
function Test-ALPathUnder([string]$Item, [string]$Entry) {
    $I = ConvertTo-ALComparablePath $Item
    $Base = ConvertTo-ALComparablePath ($Entry -replace '\\\*$', '')
    return ($I -eq $Base -or $I.StartsWith($Base + '\', [StringComparison]::Ordinal))
}

# True when an item is excluded from an allow rule by one of its exception paths (folder\* covers the folder and everything in it;
# a file exception covers exactly that file)
function Test-ALCovered([string]$Item, [string[]]$Exceptions) {
    foreach ($E in @($Exceptions | Where-Object { $_ })) {
        if ($E -match '\\\*$') { if (Test-ALPathUnder $Item $E) { return $true } }
        elseif ((ConvertTo-ALComparablePath $Item) -eq (ConvertTo-ALComparablePath $E)) { return $true }
    }
    return $false
}

# What the build does with each ExtraAllowedPaths entry, from the permission findings of EVERY server it checked. The build never
# stops on permissions and never allows something that a non-admin can change:
#   Keep        allowed for every account
#   Drop        the entry itself (top folder or file) can be changed by a non-admin on some server, or its permissions cannot be
#               read: it is left out of the policy (non-admins cannot run from it; elevated administrators still can)
#   Exceptions  only items inside it can: the entry is allowed, with those items as exceptions (folder\* or file)
function Get-ALExtraPathPlan([string[]]$Entries, $Findings) {
    $Keep = New-Object System.Collections.Generic.List[string]
    $Drop = New-Object System.Collections.Generic.List[object]
    $Except = @{}
    foreach ($E in @($Entries | Where-Object { $_ })) {
        $Base = ConvertTo-ALComparablePath ($E -replace '\\\*$', '')
        $Bad = @($Findings | Where-Object { $_.Kind -in 'WRITABLE', 'UNREADABLE' -and (Test-ALPathUnder $_.Path $E) })
        $Top = @($Bad | Where-Object { (ConvertTo-ALComparablePath $_.Path) -eq $Base })
        if ($Top.Count) {
            $Why = @($Top | ForEach-Object { "$(if ($_.Kind -eq 'WRITABLE') { "changeable by $($_.Account)" } else { 'permissions unreadable' }) on $($_.Computer)" } | Select-Object -Unique)
            $Drop.Add([pscustomobject]@{ Entry = $E; Reason = ($Why -join '; ') })
            continue
        }
        $Keep.Add($E)
        $List = New-Object System.Collections.Generic.List[string]
        foreach ($B in @($Bad | Sort-Object { $_.Path.Length }, Path)) {
            $X = if ($B.IsFolder) { "$($B.Path)\*" } else { $B.Path }
            if (-not (Test-ALCovered $B.Path @($List)) -and $X -notin $List) { $List.Add($X) }
        }
        if ($List.Count) { $Except[$E] = @($List) }
    }
    # .ToArray(): @() around an empty List[object] inside a [pscustomobject] literal throws 'Argument types do not match'
    [pscustomobject]@{ Keep = $Keep.ToArray(); Drop = $Drop.ToArray(); Exceptions = $Except }
}

# Adds exception paths to the allow rules of the given entries (every rule collection) in an AppLocker policy file; returns the number
# of rules changed. Used by the build for items inside ExtraAllowedPaths that a non-admin can change.
function Add-ALPathExceptions([string]$XmlFile, [hashtable]$Exceptions) {
    if (-not $Exceptions -or -not $Exceptions.Count) { return 0 }
    $Doc = New-Object System.Xml.XmlDocument
    $Doc.Load($XmlFile)
    $Changed = 0
    foreach ($Rule in @($Doc.SelectNodes('//FilePathRule'))) {
        $Path = ConvertTo-ALComparablePath "$($Rule.Conditions.FilePathCondition.Path)"
        foreach ($Entry in @($Exceptions.Keys)) {
            if ($Path -ne (ConvertTo-ALComparablePath $Entry)) { continue }
            $Ex = $Rule.SelectSingleNode('Exceptions')
            if (-not $Ex) { $Ex = $Doc.CreateElement('Exceptions'); [void]$Rule.AppendChild($Ex) }
            foreach ($X in @($Exceptions[$Entry])) {
                if (@($Ex.SelectNodes('FilePathCondition') | Where-Object { (ConvertTo-ALComparablePath $_.GetAttribute('Path')) -eq (ConvertTo-ALComparablePath $X) }).Count) { continue }
                $C = $Doc.CreateElement('FilePathCondition')
                $C.SetAttribute('Path', $X)
                [void]$Ex.AppendChild($C)
            }
            $Changed++
        }
    }
    if ($Changed) { $Doc.Save($XmlFile) }
    return $Changed
}

# The EXE allow rule for an ExtraAllowedPaths entry in a policy: $null when the policy has no such rule (the build left the entry out),
# otherwise its exception paths (an empty array when it has none)
function Get-ALRuleExceptions([xml]$Policy, [string]$Entry) {
    $Want = ConvertTo-ALComparablePath $Entry
    $Rules = @($Policy.SelectNodes('//RuleCollection[@Type="Exe"]/FilePathRule') | Where-Object { (ConvertTo-ALComparablePath "$($_.Conditions.FilePathCondition.Path)") -eq $Want })
    if (-not $Rules.Count) { return $null }
    return , @($Rules | ForEach-Object { $_.SelectNodes('Exceptions/FilePathCondition') } | ForEach-Object { $_.GetAttribute('Path') })
}

# Merges the AaronLocker scan results of several servers into $OutFolder: every user-writable folder (Writable_windir/PF/PF86.txt, one
# path per line, ASCII) and every deny-list entry (ExeDenyListData.txt, CSV PublisherName,ProductName,BinaryName, UTF-16) that ANY of
# them found. A union can only take permissions away (more folders excepted, more tools denied); it never allows more. $Scans: one
# @{ Server = <name>; Folder = <its ScanResults copy> } per server, the build's reference server first. Returns Writable (every merged
# path), Deny (every merged entry) and Added (Server / File / Entry for what the other servers add to the first one's scan).
function Merge-ALScanResults([object[]]$Scans, [string]$OutFolder) {
    New-Item -Path $OutFolder -ItemType Directory -Force -WhatIf:$false | Out-Null
    $Added = New-Object System.Collections.Generic.List[object]
    $Writable = New-Object System.Collections.Generic.List[string]
    foreach ($File in 'Writable_windir.txt', 'Writable_PF.txt', 'Writable_PF86.txt') {
        $Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $Lines = New-Object System.Collections.Generic.List[string]
        for ($I = 0; $I -lt $Scans.Count; $I++) {
            $Path = Join-Path $Scans[$I].Folder $File
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "STOP: $File is missing from the scan of $($Scans[$I].Server) ($($Scans[$I].Folder)). Nothing was deployed." }
            foreach ($Line in [IO.File]::ReadAllLines($Path)) {
                if ($Line.Trim() -eq '' -or -not $Seen.Add($Line)) { continue }
                $Lines.Add($Line)
                if ($I -gt 0) { $Added.Add([pscustomobject]@{ Server = $Scans[$I].Server; File = $File; Entry = $Line }) }
            }
        }
        # The same format AaronLocker writes (ASCII, CRLF); an empty list is an empty file
        $Text = if ($Lines.Count) { ($Lines.ToArray() -join "`r`n") + "`r`n" } else { '' }
        [IO.File]::WriteAllText((Join-Path $OutFolder $File), $Text, (New-Object System.Text.ASCIIEncoding))
        $Writable.AddRange($Lines)
    }
    $Seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $Deny = New-Object System.Collections.Generic.List[object]
    for ($I = 0; $I -lt $Scans.Count; $I++) {
        $Path = Join-Path $Scans[$I].Folder 'ExeDenyListData.txt'
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "STOP: ExeDenyListData.txt is missing from the scan of $($Scans[$I].Server) ($($Scans[$I].Folder)). Nothing was deployed." }
        $Text = [IO.File]::ReadAllLines($Path)
        if (@($Text | Where-Object { $_.Trim() }).Count -and $Text[0] -notmatch '^"?PublisherName"?,"?ProductName"?,"?BinaryName"?$') { throw "STOP: ExeDenyListData.txt from $($Scans[$I].Server) is not an AaronLocker deny list (header '$($Text[0])'). Nothing was deployed." }
        foreach ($Row in @($Text | ConvertFrom-Csv)) {
            if (-not $Seen.Add("$($Row.PublisherName)|$($Row.ProductName)|$($Row.BinaryName)")) { continue }
            $Deny.Add([pscustomobject]@{ PublisherName = "$($Row.PublisherName)"; ProductName = "$($Row.ProductName)"; BinaryName = "$($Row.BinaryName)" })
            if ($I -gt 0) { $Added.Add([pscustomobject]@{ Server = $Scans[$I].Server; File = 'ExeDenyListData.txt'; Entry = "$($Row.BinaryName) ($($Row.ProductName))" }) }
        }
    }
    # UTF-16 LE with BOM and every field quoted, as AaronLocker writes it (ConvertTo-Csv quotes every field in both editions)
    $Csv = [string[]]@($Deny | Select-Object PublisherName, ProductName, BinaryName | ConvertTo-Csv -NoTypeInformation)
    [IO.File]::WriteAllLines((Join-Path $OutFolder 'ExeDenyListData.txt'), $Csv, (New-Object System.Text.UnicodeEncoding $false, $true))
    [pscustomobject]@{ Writable = $Writable.ToArray(); Deny = $Deny.ToArray(); Added = $Added.ToArray() }
}

# A user-writable folder from a scan as AaronLocker writes it into the rules: the reference server's System32 / SysWOW64 become
# %SYSTEM32%, its Windows folder %WINDIR%, both Program Files folders %PROGRAMFILES%; any other path stays as it is. $Roots: Windir,
# ProgramFiles, ProgramFilesX86 of the server the rules are generated on. Compare the result case-insensitively (AaronLocker lower-cases).
function ConvertTo-ALAaronLockerPath([string]$Line, $Roots) {
    $Map = New-Object System.Collections.Generic.List[object]
    if ($Roots.Windir) {
        $Map.Add(@(($Roots.Windir.TrimEnd('\') + '\System32\'), '%SYSTEM32%\'))
        $Map.Add(@(($Roots.Windir.TrimEnd('\') + '\SysWOW64\'), '%SYSTEM32%\'))
        $Map.Add(@(($Roots.Windir.TrimEnd('\') + '\'), '%WINDIR%\'))
    }
    foreach ($Pf in @($Roots.ProgramFilesX86, $Roots.ProgramFiles)) { if ($Pf) { $Map.Add(@(($Pf.TrimEnd('\') + '\'), '%PROGRAMFILES%\')) } }
    foreach ($M in $Map) { if ($Line.StartsWith($M[0], [StringComparison]::OrdinalIgnoreCase)) { return $M[1] + $Line.Substring($M[0].Length) } }
    return $Line
}

# What a merged scan holds that an AaronLocker policy does not - empty is the proof that the rules were generated from the merged scan.
# Every user-writable folder must be an exception path in the EXE collection, every deny-list entry a publisher exception there.
function Get-ALMissingScanEntries([xml]$Policy, $Merge, $Roots) {
    $Paths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($C in @($Policy.SelectNodes('//RuleCollection[@Type="Exe"]//Exceptions/FilePathCondition'))) { [void]$Paths.Add($C.GetAttribute('Path')) }
    $Pubs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($C in @($Policy.SelectNodes('//RuleCollection[@Type="Exe"]//Exceptions/FilePublisherCondition'))) { [void]$Pubs.Add("$($C.GetAttribute('PublisherName'))|$($C.GetAttribute('ProductName'))|$($C.GetAttribute('BinaryName'))") }
    foreach ($Line in @($Merge.Writable)) {
        $Want = ConvertTo-ALAaronLockerPath $Line $Roots
        if (-not $Paths.Contains($Want)) { "user-writable folder $Line (expected exception $Want)" }
    }
    foreach ($D in @($Merge.Deny)) {
        if (-not $Pubs.Contains("$($D.PublisherName)|$($D.ProductName)|$($D.BinaryName)")) { "deny-list entry $($D.BinaryName) ($($D.ProductName))" }
    }
}

# Rule collections this baseline manages: Exe, Msi, Script, Appx (unless EnableAppxRules is off), Dll (only when DLL rules are on).
# Others in an effective policy - the DLL collection when DLL rules are off, ManagedInstaller - come from other policies (e.g. the
# local MECM managed-installer policy). A collection that is off must be NotConfigured in the GPOs.
function Get-ALManagedCollections([bool]$DllRules, [bool]$AppxRules = $true) { return @('Exe', 'Msi', 'Script') + @(if ($AppxRules) { 'Appx' }) + @(if ($DllRules) { 'Dll' }) }
function Get-ALExpectedMode([string]$Mode, [string]$Type, [bool]$DllRules, [bool]$AppxRules = $true) {
    if ($Type -eq 'Dll' -and -not $DllRules) { return 'NotConfigured' }
    if ($Type -eq 'Appx' -and -not $AppxRules) { return 'NotConfigured' }
    if ($Mode -eq 'Audit') { return 'AuditOnly' } else { return 'Enabled' }
}
# The managed collections of an effective policy that are missing or in the wrong mode for Audit / Enforce (nothing = as expected)
function Get-ALPolicyMismatch([xml]$Policy, [string]$Mode, [bool]$DllRules, [bool]$AppxRules = $true) {
    $Cols = @{}
    foreach ($Rc in @($Policy.AppLockerPolicy.RuleCollection)) { $Cols["$($Rc.Type)"] = "$($Rc.EnforcementMode)" }
    foreach ($T in Get-ALManagedCollections $DllRules $AppxRules) {
        $Want = Get-ALExpectedMode $Mode $T $DllRules $AppxRules
        if (-not $Cols.ContainsKey($T)) { "$T missing (expected $Want)" }
        elseif ($Cols[$T] -ne $Want) { "$T=$($Cols[$T]) (expected $Want)" }
    }
}

# ---- The policy conversion check -----------------------------------------------------------------------------------------------------
# Application Identity turns every rule collection into ONE security descriptor: each rule is one conditional access control entry
# (allow = XA, deny = XD, the rule's SID, and the rule condition on the APPID://PATH, APPID://FQBN or APPID://SHA256HASH attribute
# of the file - Microsoft, "AppLocker processes and interactions"). An ACL and a single ACE each carry their size in a 16-bit field,
# so neither can exceed 65,535 bytes: a collection, or one rule with its exceptions, that compiles beyond that cannot form a valid
# ACL, and the converter reports event 8000 with status 1336 (ERROR_INVALID_ACL, "The access control list (ACL) structure is
# invalid"). These helpers rebuild the conditional ACE of every rule the way Windows documents it, compile it with Windows' own
# SDDL parser when they run on Windows (ConvertStringSecurityDescriptorToSecurityDescriptor, the parser behind AddConditionalAce)
# and measure the result against the limits. Where that parser is not available, or does not accept a form, the sizes are
# estimated from the binary token layout of conditional expressions (MS-DTYP 2.4.4.17) and reported as estimates.
$script:ALAclMaxBytes = 65535          # an ACL and an ACE each hold their size in a WORD
$script:ALAclWarnPercent = 75          # WARN from this share of the limit
$script:ALAceFixedBytes = 8            # ACE header (4) + access mask (4); the SID and the condition follow
$script:ALConverterExtraBytes = 40     # two plain ACEs the converter adds for app containers (seen in the Exe policy of Windows 10)
$script:ALExistsWord = 'Exists'        # the keyword the SDDL parser of this computer accepts (Get-ALSddlSupport may lower it)

# A file version as AppLocker's BinaryVersionRange writes it ('10.0.19041.1'; '*' = no bound) packed into the 64-bit number a fully
# qualified binary name carries (16 bits per part; a missing or '*' part is 0, or 65535 with -High for an upper bound). $null for
# '*' or empty; a problem text (a string, not a number) for anything else.
function ConvertTo-ALFqbnVersion([string]$Version, [switch]$High) {
    $V = "$Version".Trim()
    if ($V -eq '' -or $V -eq '*') { return $null }
    $Parts = @($V -split '\.')
    if ($Parts.Count -gt 4) { return "the version '$V' has more than four parts" }
    [uint64]$N = 0
    for ($I = 0; $I -lt 4; $I++) {
        $Text = if ($I -lt $Parts.Count) { "$($Parts[$I])".Trim() } else { '*' }
        if ($Text -eq '*') { $Text = if ($High) { '65535' } else { '0' } }
        $P = 0
        if (-not [int]::TryParse($Text, [ref]$P) -or $P -lt 0 -or $P -gt 65535) { return "the version '$V' is not up to four numbers from 0 to 65535" }
        $N = $N * 65536 + [uint64]$P
    }
    return $N
}

# The conditional expression of one AppLocker condition element (FilePathCondition, FilePublisherCondition or FileHashCondition) as
# Application Identity compiles it: Text (the SDDL form), Bytes (estimated size of its binary form: an attribute name or a string is
# 5 bytes + 2 per character, an octet string 5 + 1 per byte, a 64-bit integer 11, a composite 5 + its members, every operator 1; a
# fully qualified binary name is taken as a composite of a string and an integer) and Problems (what the converter cannot express:
# an empty path, a quotation mark or a control character in a string, a malformed hash or version range).
function ConvertTo-ALConditionExpression([System.Xml.XmlElement]$Condition) {
    $Problems = New-Object System.Collections.Generic.List[string]
    $Text = ''; [int64]$Bytes = 0
    $Exists = $script:ALExistsWord
    switch ($Condition.LocalName) {
        'FilePathCondition' {
            $Path = "$($Condition.GetAttribute('Path'))"
            if ($Path.Trim() -eq '') { $Problems.Add('the path is empty') }
            elseif ($Path -match '["\x00-\x1F]') { $Problems.Add("the path contains a quotation mark or a control character ($Path)") }
            $Upper = $Path.ToUpperInvariant()
            $Text = 'APPID://PATH Contains "' + $Upper + '"'
            $Bytes = (5 + 2 * 12) + (5 + 2 * $Upper.Length) + 1
        }
        'FilePublisherCondition' {
            $Pub = "$($Condition.GetAttribute('PublisherName'))"; $Prod = "$($Condition.GetAttribute('ProductName'))"; $Bin = "$($Condition.GetAttribute('BinaryName'))"
            if ($Pub.Trim() -eq '') { $Problems.Add('the publisher name is empty') }
            $Name = "$Pub\$Prod\$Bin"
            if ($Name -match '["\x00-\x1F]') { $Problems.Add("the publisher, product or file name contains a quotation mark or a control character ($Name)") }
            $Range = $Condition.SelectSingleNode('BinaryVersionRange')
            $LowText = if ($Range) { "$($Range.GetAttribute('LowSection'))" } else { '*' }
            $HighText = if ($Range) { "$($Range.GetAttribute('HighSection'))" } else { '*' }
            $Low = ConvertTo-ALFqbnVersion $LowText
            $HighV = ConvertTo-ALFqbnVersion $HighText -High
            if ($Low -is [string]) { $Problems.Add($Low); $Low = $null }
            if ($HighV -is [string]) { $Problems.Add($HighV); $HighV = $null }
            if ($null -ne $Low -and $null -ne $HighV -and $Low -gt $HighV) { $Problems.Add("the version range $LowText - $HighText is reversed") }
            $LowNum = if ($null -eq $Low) { [uint64]0 } else { $Low }
            $Text = "($Exists APPID://FQBN) && (APPID://FQBN >= {`"$Name`", $LowNum})"
            $Bytes = 2 * (5 + 2 * 12) + 1 + (5 + (5 + 2 * $Name.Length) + 11) + 1 + 1
            if ($null -ne $HighV) { $Text += " && (APPID://FQBN <= {`"$Name`", $HighV})"; $Bytes += (5 + 2 * 12) + (5 + (5 + 2 * $Name.Length) + 11) + 1 + 1 }
        }
        'FileHashCondition' {
            $Hashes = @($Condition.SelectNodes('FileHash'))
            if (-not $Hashes.Count) { $Problems.Add('the hash condition holds no hash') }
            $Items = New-Object System.Collections.Generic.List[string]
            foreach ($H in $Hashes) {
                $Data = "$($H.GetAttribute('Data'))".Trim(); $HType = "$($H.GetAttribute('Type'))"
                if ($HType -ne 'SHA256' -or $Data -notmatch '^0[xX][0-9A-Fa-f]{64}$') { $Problems.Add("the hash '$Data' ($HType) is not a SHA-256 hash of 64 hex digits after 0x") }
                $Hex = ($Data -replace '^0[xX]', '').ToLowerInvariant()
                $Items.Add('#' + $Hex)
                $Bytes += 5 + [int][math]::Ceiling($Hex.Length / 2)
            }
            $Text = "($Exists APPID://SHA256HASH) && (APPID://SHA256HASH Any_of {" + ($Items -join ', ') + '})'
            $Bytes += 2 * (5 + 2 * 18) + 1 + 5 + 1 + 1
        }
        default { $Problems.Add("unknown condition element <$($Condition.LocalName)>"); $Text = "($Exists APPID://PATH)"; $Bytes = 5 + 2 * 12 + 1 }
    }
    [pscustomobject]@{ Text = $Text; Bytes = $Bytes; Problems = $Problems.ToArray() }
}

# The conditional ACE of one AppLocker rule (FilePathRule, FilePublisherRule or FileHashRule with its exceptions) as Application
# Identity compiles it: Sddl - (XA;;0x1200a0;;;<SID>;((<condition>) && !(<exception>) ...)), XD for a deny rule, 0x1200a0 =
# execute, read attributes, read control, synchronize - Bytes (estimated size of the ACE: header, access mask, SID, the 'artx'
# signature and the expression, padded to 4), Exceptions (count), Deny, Sid and Problems.
function ConvertTo-ALRuleAce([System.Xml.XmlElement]$Rule) {
    $Problems = New-Object System.Collections.Generic.List[string]
    # A SID string: revision 1, an identifier authority, 1 to 15 sub-authorities; 8 bytes + 4 per sub-authority in binary form
    $Sid = "$($Rule.GetAttribute('UserOrGroupSid'))".Trim()
    $SidBytes = 12
    if ($Sid -match '^S-1-(\d{1,10}|0x[0-9A-Fa-f]{1,12})((?:-\d{1,10}){1,15})$') { $SidBytes = 8 + 4 * ($Matches[2].Split('-').Length - 1) }
    else { $Problems.Add("the SID '$Sid' is not a valid security identifier"); $Sid = 'S-1-1-0' }
    $Action = "$($Rule.GetAttribute('Action'))"
    if ($Action -notin 'Allow', 'Deny') { $Problems.Add("the action '$Action' is neither Allow nor Deny") }
    $AceType = if ($Action -eq 'Deny') { 'XD' } else { 'XA' }
    [int64]$Bytes = $script:ALAceFixedBytes + $SidBytes + 4
    $Conds = @($Rule.SelectNodes('Conditions/*'))
    if ($Conds.Count -ne 1) { $Problems.Add("$($Conds.Count) conditions (exactly one is expected)") }
    $Main = New-Object System.Collections.Generic.List[string]
    foreach ($C in $Conds) {
        $E = ConvertTo-ALConditionExpression $C
        $Main.Add("($($E.Text))"); $Bytes += $E.Bytes
        foreach ($P in $E.Problems) { $Problems.Add($P) }
    }
    if (-not $Main.Count) { $Main.Add("($($script:ALExistsWord) APPID://PATH)"); $Bytes += 5 + 2 * 12 + 1 }
    $Expr = $Main -join ' && '
    $Bytes += $Main.Count - 1
    $Ex = @($Rule.SelectNodes('Exceptions/*'))
    foreach ($X in $Ex) {
        $E = ConvertTo-ALConditionExpression $X
        $Expr += " && !($($E.Text))"; $Bytes += $E.Bytes + 2
        foreach ($P in $E.Problems) { $Problems.Add("exception: $P") }
    }
    $Bytes += (4 - ($Bytes % 4)) % 4
    [pscustomobject]@{ Sddl = "($AceType;;0x1200a0;;;$Sid;($Expr))"; Bytes = $Bytes; Exceptions = $Ex.Count; Deny = ($AceType -eq 'XD'); Sid = $Sid; Problems = $Problems.ToArray() }
}

# Compiles an SDDL security descriptor string with Windows' own parser (ConvertStringSecurityDescriptorToSecurityDescriptor). Returns
# Ok, Error (the Win32 code when it fails: 87 = the parameter is incorrect, 1336 = the ACL structure is invalid, 1337 = the SID is
# invalid ...), Bytes (the binary security descriptor), Aces (the size in bytes of every ACE of its DACL) and DaclBytes. $null when
# the parser is not available: not Windows, or the small helper type could not be compiled (ConstrainedLanguage).
$script:ALSddlNative = $null
function Test-ALSddlNative([string]$Sddl) {
    if ($null -eq $script:ALSddlNative) {
        $script:ALSddlNative = $false
        if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
            try {
                if (-not ('ALSddlNative' -as [type])) {
                    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ALSddlNative {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr handle);
    public static int Convert(string sddl, out byte[] bytes) {
        IntPtr sd; uint size; bytes = null;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) { return Marshal.GetLastWin32Error(); }
        try { bytes = new byte[size]; Marshal.Copy(sd, bytes, 0, (int)size); } finally { LocalFree(sd); }
        return 0;
    }
}
'@
                }
                $script:ALSddlNative = $true
            }
            catch { $script:ALSddlNative = $false }
        }
    }
    if (-not $script:ALSddlNative) { return $null }
    $T = 'ALSddlNative' -as [type]
    $Bytes = $null
    $Err = $T::Convert($Sddl, [ref]$Bytes)
    if ($Err -ne 0) { return [pscustomobject]@{ Ok = $false; Error = [int]$Err; Bytes = $null; Aces = @(); DaclBytes = 0 } }
    $Sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($Bytes, 0)
    $Aces = @(); $Dacl = 0
    if ($Sd.DiscretionaryAcl) { $Aces = @($Sd.DiscretionaryAcl | ForEach-Object { [int]$_.BinaryLength }); $Dacl = [int]$Sd.DiscretionaryAcl.BinaryLength }
    [pscustomobject]@{ Ok = $true; Error = 0; Bytes = $Bytes; Aces = $Aces; DaclBytes = $Dacl }
}

# What the SDDL parser of this computer accepts, tested once with a sample of each rule form: Native (a parser is available), Path /
# Hash / Fqbn (that form compiles), ExistsWord (the spelling of the Exists operator it took). A form the parser does not accept is
# only estimated - never reported as a failed rule.
$script:ALSddlSupport = $null
function Get-ALSddlSupport {
    if ($script:ALSddlSupport) { return $script:ALSddlSupport }
    $S = [pscustomobject]@{ Native = $false; Path = $false; Hash = $false; Fqbn = $false; ExistsWord = 'Exists' }
    $Samples = [ordered]@{
        Path = 'D:(XA;;0x1200a0;;;S-1-1-0;(APPID://PATH Contains "%WINDIR%\*"))'
        Hash = 'D:(XA;;0x1200a0;;;S-1-1-0;((Exists APPID://SHA256HASH) && (APPID://SHA256HASH Any_of {#5bf6ccc91dd715e18d6769af97dd3ad6a15d2b70326e834474d952753118c670})))'
        Fqbn = 'D:(XA;;0x1200a0;;;S-1-1-0;((Exists APPID://FQBN) && (APPID://FQBN >= {"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US\MICROSOFT TEAMS\*", 0})))'
    }
    foreach ($K in @($Samples.Keys)) {
        $Sample = $Samples[$K] -creplace 'Exists', $S.ExistsWord
        $R = Test-ALSddlNative $Sample
        if ($null -eq $R) { break }
        $S.Native = $true
        if (-not $R.Ok -and $K -ne 'Path' -and $S.ExistsWord -eq 'Exists') {
            $R2 = Test-ALSddlNative ($Samples[$K] -creplace 'Exists', 'exists')
            if ($R2 -and $R2.Ok) { $R = $R2; $S.ExistsWord = 'exists' }
        }
        if ($R.Ok) { $S.$K = $true }
    }
    $script:ALExistsWord = $S.ExistsWord
    $script:ALSddlSupport = $S
    return $S
}

# Checks an AppLocker policy the way Application Identity will convert it - before it is deployed (2_AL_create_gpos.ps1), as it sits
# in a GPO (4_AL_validate.ps1) or as it was delivered to a server (7_AL_diagnose.ps1): every rule's SID, action, condition and
# exceptions; the conditional ACE of every rule and its size; the size of every collection's ACL - exact when Windows' SDDL parser
# is available and accepts the rule's form, estimated otherwise - against the 65,535-byte limit of an ACL and of an ACE (FAIL at or
# above it, WARN from ALAclWarnPercent). Returns Status (OK / WARN / FAIL), Native, Exact, Summary (one phrase per collection),
# Largest (the biggest rule), Collections (Type, Mode, Rules, Deny, Exceptions, Bytes, Percent, Exact, Largest, LargestBytes,
# Status) and Problems (Severity, Collection, Rule, Id, Problem).
function Test-ALPolicyConvertible([xml]$Policy) {
    $Support = Get-ALSddlSupport
    $Max = $script:ALAclMaxBytes
    $Cols = New-Object System.Collections.Generic.List[object]
    $Problems = New-Object System.Collections.Generic.List[object]
    function Add-Problem([string]$Sev, [string]$Col, [string]$RuleName, [string]$Id, [string]$Text) { $Problems.Add([pscustomobject]@{ Severity = $Sev; Collection = $Col; Rule = $RuleName; Id = $Id; Problem = $Text }) }
    $Ids = @{}
    if (-not $Policy.AppLockerPolicy) { Add-Problem 'FAIL' '' '' '' 'not an AppLocker policy (no AppLockerPolicy element)' }
    foreach ($Rc in @($Policy.SelectNodes('/AppLockerPolicy/RuleCollection'))) {
        $Type = "$($Rc.GetAttribute('Type'))"; $Mode = "$($Rc.GetAttribute('EnforcementMode'))"
        if ($Mode -eq '') { $Mode = 'NotConfigured' }
        if ($Type -notin 'Exe', 'Dll', 'Script', 'Msi', 'Appx', 'ManagedInstaller') { Add-Problem 'FAIL' $Type '' '' "unknown rule collection type '$Type'" }
        $Rules = @($Rc.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' })
        $Aces = New-Object System.Collections.Generic.List[object]
        $Deny = 0; $Exceptions = 0; $Exact = $true; $Broken = $false
        foreach ($Rule in $Rules) {
            $Name = "$($Rule.GetAttribute('Name'))"; $Id = "$($Rule.GetAttribute('Id'))"
            $Guid = [guid]::Empty
            if (-not [guid]::TryParse($Id, [ref]$Guid)) { Add-Problem 'WARN' $Type $Name $Id "the rule Id '$Id' is not a GUID" }
            elseif ($Ids.ContainsKey($Id.ToLowerInvariant())) { Add-Problem 'WARN' $Type $Name $Id "duplicate rule Id (also used by $($Ids[$Id.ToLowerInvariant()])): Group Policy keeps only one of them" }
            else { $Ids[$Id.ToLowerInvariant()] = "$Type/'$Name'" }
            if ($Rule.LocalName -notin 'FilePathRule', 'FilePublisherRule', 'FileHashRule') { Add-Problem 'FAIL' $Type $Name $Id "unknown rule element <$($Rule.LocalName)>" }
            $Ace = ConvertTo-ALRuleAce $Rule
            foreach ($P in $Ace.Problems) { Add-Problem 'FAIL' $Type $Name $Id $P }
            $EstBytes = [int64]$Ace.Bytes; $Bytes = $EstBytes; $IsExact = $false
            $Form = switch ($Rule.LocalName) { 'FilePathRule' { 'Path' } 'FilePublisherRule' { 'Fqbn' } 'FileHashRule' { 'Hash' } default { '' } }
            $Mixed = (@($Rule.SelectNodes('Exceptions/FilePublisherCondition')).Count -gt 0 -and -not $Support.Fqbn) -or (@($Rule.SelectNodes('Exceptions/FileHashCondition')).Count -gt 0 -and -not $Support.Hash)
            if ($Support.Native -and $Form -and $Support.$Form -and -not $Mixed -and $Ace.Problems.Count -eq 0) {
                $N = Test-ALSddlNative "D:$($Ace.Sddl)"
                if ($N -and $N.Ok -and @($N.Aces).Count -eq 1) { $Bytes = [int64]$N.Aces[0]; $IsExact = $true }
                elseif ($N -and -not $N.Ok) { Add-Problem 'FAIL' $Type $Name $Id "Windows' SDDL parser rejects the conditional ACE of this rule (error $($N.Error): $(ConvertTo-ALWin32Message $N.Error)); $($Ace.Exceptions) exception(s)"; $Broken = $true }
            }
            if (-not $IsExact) { $Exact = $false }
            # The estimate decides too: it follows the binary layout, so a rule it puts beyond the limit is beyond it
            if ($Bytes -gt $Max -or $EstBytes -gt $Max) { $Shown = [math]::Max($Bytes, $EstBytes); Add-Problem 'FAIL' $Type $Name $Id "this rule alone compiles to $($Shown.ToString('N0')) bytes, more than one ACE can hold ($($Max.ToString('N0'))); it has $($Ace.Exceptions) exception(s)$(if (-not $IsExact -or $EstBytes -gt $Bytes) { ' (estimated)' })"; $Broken = $true }
            if ($Ace.Deny) { $Deny++ }
            $Exceptions += $Ace.Exceptions
            $Aces.Add([pscustomobject]@{ Name = $Name; Id = $Id; Bytes = $Bytes; Est = $EstBytes; Exact = $IsExact; Sddl = $Ace.Sddl; Deny = $Ace.Deny })
        }
        [int64]$Total = 0; [int64]$EstTotal = 0
        if ($Rules.Count) {
            $Total = 8 + $script:ALConverterExtraBytes
            foreach ($A in $Aces) { $Total += $A.Bytes; $EstTotal += $A.Est }
            $EstTotal += 8 + $script:ALConverterExtraBytes
            # The whole collection as one ACL, for the exact DACL size (deny ACEs first, as the converter orders them)
            if ($Exact -and -not $Broken -and $Support.Native) {
                $All = 'D:' + ((@($Aces | Where-Object { $_.Deny }) + @($Aces | Where-Object { -not $_.Deny }) | ForEach-Object { $_.Sddl }) -join '')
                $N = Test-ALSddlNative $All
                if ($N -and $N.Ok) { $Total = [int64]$N.DaclBytes + $script:ALConverterExtraBytes }
                elseif ($N -and -not $N.Ok) { Add-Problem 'FAIL' $Type '' '' "the $Type collection does not compile as one ACL although every rule does on its own (error $($N.Error): $(ConvertTo-ALWin32Message $N.Error)) - $($Rules.Count) rules, about $($Total.ToString('N0')) bytes"; $Broken = $true }
            }
        }
        $Largest = $null
        if ($Aces.Count) { $Largest = @($Aces | Sort-Object Bytes -Descending)[0] }
        $Pct = if ($Rules.Count) { [math]::Round(100.0 * $Total / $Max, 1) } else { 0 }
        $Status = 'OK'
        if ($Rules.Count -and ($Total -gt $Max -or $EstTotal -gt $Max)) { $Shown = [math]::Max($Total, $EstTotal); if ($Shown -gt $Total) { $Total = $Shown }; Add-Problem 'FAIL' $Type '' '' "the $Type collection compiles to $($Shown.ToString('N0')) bytes, more than one ACL can hold ($($Max.ToString('N0'))): $($Rules.Count) rules, the largest '$($Largest.Name)' with $($Largest.Bytes.ToString('N0')) bytes$(if (-not $Exact -or $EstTotal -gt $Total) { ' (estimated)' })" }
        elseif ($Rules.Count -and $Pct -ge $script:ALAclWarnPercent) { Add-Problem 'WARN' $Type '' '' "the $Type collection uses $Pct% of the 64 KB an ACL can hold ($($Total.ToString('N0')) bytes, $($Rules.Count) rules): add rules sparingly" }
        $Cols.Add([pscustomobject]@{ Type = $Type; Mode = $Mode; Rules = $Rules.Count; Deny = $Deny; Exceptions = $Exceptions; Bytes = $Total; Percent = $Pct; Exact = ($Exact -and $Rules.Count -gt 0); Largest = $(if ($Largest) { $Largest.Name } else { '' }); LargestBytes = $(if ($Largest) { $Largest.Bytes } else { 0 }); Status = $Status })
    }
    foreach ($C in $Cols) {
        $Own = @($Problems | Where-Object { $_.Collection -eq $C.Type })
        if (@($Own | Where-Object { $_.Severity -eq 'FAIL' }).Count) { $C.Status = 'FAIL' } elseif (@($Own | Where-Object { $_.Severity -eq 'WARN' }).Count) { $C.Status = 'WARN' }
    }
    $Overall = 'OK'
    if (@($Problems | Where-Object { $_.Severity -eq 'FAIL' }).Count) { $Overall = 'FAIL' } elseif (@($Problems | Where-Object { $_.Severity -eq 'WARN' }).Count) { $Overall = 'WARN' }
    $Big = @($Cols | Where-Object { $_.Rules -gt 0 } | Sort-Object LargestBytes -Descending) | Select-Object -First 1
    [pscustomobject]@{
        Status      = $Overall
        Native      = $Support.Native
        Exact       = (@($Cols | Where-Object { $_.Rules -gt 0 -and -not $_.Exact }).Count -eq 0)
        Summary     = (@($Cols | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.Mode) $($_.Rules) rule(s), $($_.Bytes.ToString('N0')) B ($($_.Percent)% of 64 KB$(if ($_.Rules -gt 0 -and -not $_.Exact) { ', estimated' }))" }) -join '; ')
        Largest     = $(if ($Big) { "largest rule: $($Big.Type) '$($Big.Largest)' $($Big.LargestBytes.ToString('N0')) B" } else { 'no rules' })
        Collections = $Cols.ToArray()
        Problems    = $Problems.ToArray()
    }
}

# Adds the rows of a conversion check to a results list: "Policy conversion <label>" (the collections with their sizes) and one
# "Policy rule <label>" row per problem found
function Add-ALPolicyCheckResults($List, [string]$Label, $Check) {
    $How = if ($Check.Exact) { "sizes exact (compiled with Windows' SDDL parser)" } elseif ($Check.Native) { 'sizes partly estimated' } else { 'sizes estimated (no Windows SDDL parser here)' }
    $Tail = if ($Check.Status -eq 'FAIL') { ' - Application Identity would reject this policy (event 8000, status 1336): fix the build before it is deployed' } elseif ($Check.Status -eq 'WARN') { ' - see the Policy rule rows' } else { '' }
    Add-ALResult $List $Check.Status "Policy conversion $Label" "$($Check.Summary); $($Check.Largest); $How$Tail"
    foreach ($P in @($Check.Problems)) { Add-ALResult $List $P.Severity "Policy rule $Label" "$($P.Collection)$(if ($P.Rule) { " '$($P.Rule)'" })$(if ($P.Id) { " ($($P.Id))" }): $($P.Problem)" }
}

# What the Status of AppLocker event 8000 points at, for the codes this toolkit knows; '' for any other
function Get-ALStatusHint([object]$Code) {
    $Text = "$Code".Trim(); $N = [int64]-1
    if ($Text -match '^0[xX]([0-9A-Fa-f]{1,8})$') { $N = [Convert]::ToInt64($Matches[1], 16) } elseif ($Text -match '^-?\d{1,10}$') { $N = [int64]$Text }
    if ($N -ge 2147942400 -and $N -le 2148007935) { $N -= 2147942400 }
    switch ($N) {
        1336 { return "the converted rules did not form a valid ACL - one collection or one rule with its exceptions beyond the 64 KB limit of an ACL or ACE, a rule the converter cannot express, or a damaged ACL on the policy store (4_AL_validate.ps1 rows 'Policy conversion', 'Policy store', 'Compiled policy'; 7_AL_diagnose.ps1; SERVER-2022.md section 7, cause 5)" }
        { $_ -in 2, 3, 126 } { return 'a component of the installation is missing (7_AL_diagnose.ps1: Components)' }
        1168 { return 'something the policy refers to does not exist on this installation (the Appx collection on Server Core: EnableAppxRules)' }
        { $_ -in 13, 87 } { return "the policy content itself (4_AL_validate.ps1 rows 'Policy conversion' / 'Policy rule')" }
        5 { return "the service cannot read or write its policy keys or files (4_AL_validate.ps1 row 'Policy store')" }
    }
    return ''
}

# ---- The policy store on a server --------------------------------------------------------------------------------------------------
# Runs ON a server (read-only; through Invoke-ALOn, or & $ALPolicyStoreProbe on the server itself). For a conversion failure that
# names an ACL or access, the state of AppLocker's policy store: Windows build and update level; the PolicyConverter scheduled
# task (account, state, last run, result); the permissions of %windir%\System32\AppLocker, of every file in it, of
# HKLM\SYSTEM\CurrentControlSet\Control\Srp, Srp\Gp and HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2 (SDDL, owner, canonical
# order, inheritance, an allow entry for SYSTEM and for Administrators, read access for the Application Identity service account
# through LOCAL SERVICE, SERVICE, Authenticated Users, Users or Everyone); the compiled policy files <Collection>.AppLocker (size,
# time, the security descriptor they carry and its ACE count - the file holds a 4-byte signature and, at offset 16, the offset of
# the descriptor); the collections Group Policy delivered (SrpV2: mode and rule count); the newest 8000 / 8001 event.
$ALPolicyStoreProbe = {
    $ErrorActionPreference = 'Continue'
    $o = [ordered]@{}
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $o.Computer = $env:COMPUTERNAME; $o.Build = [int]$cv.CurrentBuild; $o.Ubr = [int]$cv.UBR; $o.InstallType = "$($cv.InstallationType)"
    $o.Task = $null; $o.TaskError = ''
    try {
        $t = Get-ScheduledTask -TaskPath '\Microsoft\Windows\AppID\' -TaskName 'PolicyConverter' -ErrorAction Stop
        $i = $null; try { $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch { }
        $o.Task = [pscustomobject]@{ Principal = "$($t.Principal.UserId)"; LogonType = "$($t.Principal.LogonType)"; State = "$($t.State)"; LastRun = $(if ($i -and $i.LastRunTime -and $i.LastRunTime.Year -gt 1999) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }); LastResult = $(if ($i) { [int64]$i.LastTaskResult } else { [int64]-1 }) }
    }
    catch { $o.TaskError = $_.Exception.Message }
    function Read-ALStoreAcl([string]$Path, [string]$Kind) {
        $r = [ordered]@{ Path = $Path; Kind = $Kind; Exists = $false; Sddl = ''; Owner = ''; Canonical = $true; Protected = $false; SystemAllow = $false; SystemFull = $false; AdminsAllow = $false; ServiceRead = $false; Error = '' }
        if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]$r }
        $r.Exists = $true
        try {
            $a = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $r.Sddl = "$($a.Sddl)"; $r.Owner = "$($a.Owner)"; $r.Canonical = [bool]$a.AreAccessRulesCanonical; $r.Protected = [bool]$a.AreAccessRulesProtected
            foreach ($rule in $a.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -ne 'Allow') { continue }
                $sid = $rule.IdentityReference.Value
                $rights = if ($Kind -eq 'RegistryKey') { [int64]$rule.RegistryRights } else { [int64]$rule.FileSystemRights }
                $generic = ($rights -band 0x10000000) -ne 0
                $full = $generic -or ($Kind -eq 'RegistryKey' -and ($rights -band 0xF003F) -eq 0xF003F) -or ($Kind -ne 'RegistryKey' -and ($rights -band 0x1F01FF) -eq 0x1F01FF)
                $write = $full -or ($Kind -eq 'RegistryKey' -and ($rights -band 0x6) -ne 0) -or ($Kind -ne 'RegistryKey' -and ($rights -band 0x2) -ne 0) -or ($rights -band 0x40000000) -ne 0
                $read = $full -or ($Kind -eq 'RegistryKey' -and ($rights -band 0x1) -ne 0) -or ($Kind -ne 'RegistryKey' -and ($rights -band 0x1) -ne 0) -or ($rights -band 0x80000000) -ne 0
                if ($sid -eq 'S-1-5-18' -and $write) { $r.SystemAllow = $true }
                if ($sid -eq 'S-1-5-18' -and $full) { $r.SystemFull = $true }
                if ($sid -eq 'S-1-5-32-544' -and $write) { $r.AdminsAllow = $true }
                if ($sid -in 'S-1-5-19', 'S-1-5-6', 'S-1-5-11', 'S-1-5-32-545', 'S-1-1-0' -and $read) { $r.ServiceRead = $true }
            }
        }
        catch { $r.Error = $_.Exception.Message }
        [pscustomobject]$r
    }
    $Folder = Join-Path $env:windir 'System32\AppLocker'
    $Store = New-Object System.Collections.Generic.List[object]
    $Store.Add((Read-ALStoreAcl $Folder 'Folder'))
    foreach ($f in @(Get-ChildItem -LiteralPath $Folder -File -Force -ErrorAction SilentlyContinue)) { $Store.Add((Read-ALStoreAcl $f.FullName 'File')) }
    foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Control\Srp', 'HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2') { $Store.Add((Read-ALStoreAcl $k 'RegistryKey')) }
    $o.Store = $Store.ToArray()
    $o.Compiled = @(foreach ($f in @(Get-ChildItem -LiteralPath $Folder -Filter '*.AppLocker' -File -Force -ErrorAction SilentlyContinue)) {
            $c = [ordered]@{ File = $f.Name; Collection = $f.BaseName; Bytes = [int64]$f.Length; Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Magic = ''; SdOffset = -1; SdParsed = $false; Aces = 0; DaclBytes = 0; Error = '' }
            try {
                $b = [IO.File]::ReadAllBytes($f.FullName)
                if ($b.Length -ge 4) { $c.Magic = -join @(0..3 | ForEach-Object { if ($b[$_] -ge 32 -and $b[$_] -lt 127) { [char]$b[$_] } else { '.' } }) }
                if ($b.Length -ge 20) {
                    $off = [BitConverter]::ToInt32($b, 16); $c.SdOffset = $off
                    if ($off -gt 0 -and $off -lt $b.Length) {
                        $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($b, $off)
                        $c.SdParsed = $true
                        if ($sd.DiscretionaryAcl) { $c.Aces = [int]$sd.DiscretionaryAcl.Count; $c.DaclBytes = [int]$sd.DiscretionaryAcl.BinaryLength }
                    }
                }
            }
            catch { $c.Error = $_.Exception.Message }
            [pscustomobject]$c
        })
    $o.Delivered = @(foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2' -ErrorAction SilentlyContinue)) {
            $m = $k.GetValue('EnforcementMode')
            [pscustomobject]@{ Collection = $k.PSChildName; Mode = $(if ($null -eq $m) { 'NotConfigured' } elseif ("$m" -eq '1') { 'Enabled' } elseif ("$m" -eq '0') { 'AuditOnly' } else { "$m" }); Rules = @(Get-ChildItem -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).Count }
        })
    $o.NewestEvent = $null
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8000, 8001 } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($ev) {
        $st = ''
        if ($ev.Id -eq 8000) { try { $st = "$(([xml]($ev.ToXml())).Event.EventData.Data | Where-Object { $_.Name -eq 'Status' } | ForEach-Object { $_.'#text' })" } catch { } }
        $o.NewestEvent = [pscustomobject]@{ Time = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = [int]$ev.Id; Status = $st }
    }
    [pscustomobject]$o
}

# Adds the rows for one server from $ALPolicyStoreProbe: "Windows build" (INFO), "Policy converter" (the task), "Policy store" (one
# OK row when every object is in order, else one row per finding: a non-canonical ACL or no entry for SYSTEM is a FAIL, no entry
# for Administrators, inheritance switched off or no read access for the service account a WARN) and "Compiled policy" (the
# <Collection>.AppLocker files against the collections Group Policy delivered: missing or older than a failed conversion is a FAIL)
function Add-ALPolicyStoreResults($List, [string]$Computer, $Store) {
    Add-ALResult $List 'INFO' "Windows build $Computer" "$(Get-ALOsLabel $Store.Build) $($Store.InstallType), update level $($Store.Build).$($Store.Ubr)"
    $Delivered = @($Store.Delivered | Where-Object { $_.Rules -gt 0 -and $_.Mode -ne 'NotConfigured' })
    $Newest = $Store.NewestEvent
    $Failed = [bool]($Newest -and $Newest.Id -eq 8000)
    $T = $Store.Task
    if ($T) {
        $Hex = '0x' + ([int64]$T.LastResult).ToString('X')
        $Bad = ($T.LastResult -notin 0, 0x41300, 0x41301, 0x41303)   # ready, running, never run
        Add-ALResult $List $(if ($Bad -and $Delivered.Count) { 'WARN' } else { 'INFO' }) "Policy converter $Computer" "the scheduled task \Microsoft\Windows\AppID\PolicyConverter runs as $($T.Principal), $($T.State); last run $(if ($T.LastRun) { $T.LastRun } else { 'never' }), result $Hex$(if ($T.LastResult -ge 0 -and $T.LastResult -lt 65536) { " ($(ConvertTo-ALWin32Message $T.LastResult))" })"
    }
    else { Add-ALResult $List $(if ($Delivered.Count) { 'FAIL' } else { 'WARN' }) "Policy converter $Computer" "the scheduled task \Microsoft\Windows\AppID\PolicyConverter was not found ($($Store.TaskError)) - Application Identity runs it to convert every delivered policy" }
    $Findings = New-Object System.Collections.Generic.List[object]
    $FolderSddl = ''
    foreach ($O in @($Store.Store)) {
        $Where = "$($O.Kind) $($O.Path)"
        if ($O.Kind -eq 'Folder') { $FolderSddl = $O.Sddl }
        if (-not $O.Exists) {
            if ($O.Kind -eq 'RegistryKey' -and $O.Path -like '*\Srp\Gp' -and $Delivered.Count) { $Findings.Add([pscustomobject]@{ Sev = 'WARN'; Text = "$Where does not exist although rules were delivered: no policy has been converted on this server yet" }) }
            elseif ($O.Kind -eq 'Folder') { $Findings.Add([pscustomobject]@{ Sev = 'FAIL'; Text = "$Where does not exist - the folder every converted policy is written to" }) }
            continue
        }
        if ($O.Error) { $Findings.Add([pscustomobject]@{ Sev = 'FAIL'; Text = "$Where - permissions unreadable: $($O.Error)" }); continue }
        if (-not $O.Canonical) { $Findings.Add([pscustomobject]@{ Sev = 'FAIL'; Text = "$Where - the ACL is not in canonical order (SDDL $($O.Sddl))" }) }
        if (-not $O.SystemAllow) { $Findings.Add([pscustomobject]@{ Sev = 'FAIL'; Text = "$Where - no entry lets SYSTEM write (SDDL $($O.Sddl))" }) }
        if (-not $O.AdminsAllow) { $Findings.Add([pscustomobject]@{ Sev = 'WARN'; Text = "$Where - no entry lets Administrators write (SDDL $($O.Sddl))" }) }
        if (-not $O.ServiceRead) { $Findings.Add([pscustomobject]@{ Sev = 'WARN'; Text = "$Where - no read access through LOCAL SERVICE, SERVICE, Authenticated Users, Users or Everyone: the Application Identity service (LOCAL SERVICE) may not read it (SDDL $($O.Sddl))" }) }
        if ($O.Protected -and $O.Kind -ne 'RegistryKey') { $Findings.Add([pscustomobject]@{ Sev = 'WARN'; Text = "$Where - inheritance is switched off (hardened?): compare the SDDL with a server that applies the policy ($($O.Sddl))" }) }
    }
    if ($Findings.Count) { foreach ($F in $Findings) { Add-ALResult $List $F.Sev "Policy store $Computer" $F.Text } }
    else { Add-ALResult $List 'OK' "Policy store $Computer" "permissions in order on $(@($Store.Store | Where-Object { $_.Exists }).Count) object(s) (canonical, SYSTEM and Administrators allowed, readable by the service); System32\AppLocker SDDL $FolderSddl" }
    foreach ($D in $Delivered) {
        $F = @($Store.Compiled | Where-Object { $_.Collection -eq $D.Collection }) | Select-Object -First 1
        if (-not $F) {
            Add-ALResult $List $(if ($Failed) { 'FAIL' } else { 'WARN' }) "Compiled policy $Computer" "$($D.Collection): $($D.Rules) rule(s) delivered ($($D.Mode)) but no $($D.Collection).AppLocker in System32\AppLocker$(if ($Failed) { " - the conversion failed (event 8000 at $($Newest.Time)) and nothing was written" } else { ' - not converted yet (refresh twice), or the converter has not run' })"
            continue
        }
        $Text = "$($F.File) $($F.Bytes.ToString('N0')) B, written $($F.Modified)$(if ($F.SdParsed) { ", carries a security descriptor with $($F.Aces) ACE(s), DACL $($F.DaclBytes.ToString('N0')) B" })"
        if ($Failed -and $F.Modified -lt $Newest.Time) { Add-ALResult $List 'FAIL' "Compiled policy $Computer" "$($D.Collection): $($D.Rules) rule(s) delivered, but $Text - older than the failed conversion (event 8000 at $($Newest.Time)): the converter wrote nothing new" }
        else { Add-ALResult $List 'OK' "Compiled policy $Computer" "$($D.Collection): $($D.Rules) rule(s) delivered ($($D.Mode)); $Text" }
    }
    if (-not $Delivered.Count) { Add-ALResult $List 'INFO' "Compiled policy $Computer" "no rules delivered by Group Policy; compiled files present: $(if (@($Store.Compiled).Count) { (@($Store.Compiled) | ForEach-Object { $_.File }) -join ', ' } else { 'none' })" }
}

# ---- Servers and this computer -----------------------------------------------------------------------------------------------------
# The scripts reach every server over WinRM. When a server IS the computer a script runs on (the toolkit run on a DC itself, which is
# also the reference server), WinRM to itself is not possible from a remote session - a second hop to the same computer is refused
# ("Access is denied", "A specified logon session does not exist") - so the same script blocks run in this process instead. The
# remote behaviour is unchanged.

# The names and addresses this computer answers to: its name, its DNS name, localhost, its IP addresses (computed once)
$script:ALLocalNames = $null
function Get-ALLocalNames {
    if ($script:ALLocalNames) { return , $script:ALLocalNames }
    $Set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($N in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1', '.')) { if ($N) { [void]$Set.Add($N) } }
    try {
        $Cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($Cs.DNSHostName) { [void]$Set.Add("$($Cs.DNSHostName)"); if ($Cs.Domain) { [void]$Set.Add("$($Cs.DNSHostName).$($Cs.Domain)") } }
    }
    catch { }
    try { foreach ($A in @([System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()))) { [void]$Set.Add($A.IPAddressToString) } } catch { }
    try { foreach ($A in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' -ErrorAction Stop | ForEach-Object { $_.IPAddress })) { if ($A) { [void]$Set.Add("$A") } } } catch { }
    $script:ALLocalNames = $Set
    return , $Set   # the comma keeps the set from being unrolled into an array (whose Contains would be case-sensitive)
}

# True when a server name (short name, FQDN, localhost or an IP address) is this computer
function Test-ALLocalComputer([string]$ComputerName) {
    $N = "$ComputerName".Trim().TrimEnd('.')
    if (-not $N) { return $false }
    $Names = Get-ALLocalNames
    return $Names.Contains($N)
}

# Runs a script block on a server over WinRM, or in this process when the server is this computer. $ArgumentList binds to the block's
# parameters the way Invoke-Command -ArgumentList does: one element per parameter (wrap a single array in (, $Array)).
function Invoke-ALOn([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$ArgumentList = @()) {
    if ($null -eq $ArgumentList) { $ArgumentList = @() }
    if (Test-ALLocalComputer $ComputerName) { return (& $ScriptBlock @ArgumentList) }
    return (Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop)
}

# ---- Group Policy refresh and gpresult ---------------------------------------------------------------------------------------------
# Used by 3_AL_set_mode.ps1 (-Refresh), 4_AL_validate.ps1 and 7_AL_diagnose.ps1: gpupdate with its output kept, gpresult as text and
# as XML, and the result rows that say which AppLocker GPO a computer applied and whether its extensions ran.

# Runs ON a server. With $Refresh: gpupdate /target:computer /force twice (the first refresh after a computer receives the GPO starts
# Application Identity, the second makes it load the rules), $WaitSeconds apart, keeping the full output and the exit code of each
# pass. Always: gpresult /scope computer as text (/r) and as XML (/x), Application Identity, the effective AppLocker policy and the
# newest policy events (8001 = applied, 8000 = conversion failed, with its Status). Nothing but a Group Policy refresh is changed.
$ALGpRefreshProbe = {
    param([bool]$Refresh, [int]$WaitSeconds)
    $o = [ordered]@{ Computer = $env:COMPUTERNAME; Started = (Get-Date).ToString('s'); Gpupdate = @(); GpupdateExit = @() }
    if ($Refresh) {
        for ($Pass = 1; $Pass -le 2; $Pass++) {
            $Text = (& "$env:windir\System32\gpupdate.exe" /target:computer /force 2>&1 | Out-String)
            $o.GpupdateExit += [int]$LASTEXITCODE
            $o.Gpupdate += "gpupdate /target:computer /force - pass $Pass of 2 at $((Get-Date).ToString('HH:mm:ss')), exit code $LASTEXITCODE`r`n$($Text.Trim())"
            if ($Pass -eq 1) { Start-Sleep -Seconds $WaitSeconds }
        }
    }
    $o.GpresultText = (& "$env:windir\System32\gpresult.exe" /scope computer /r 2>&1 | Out-String)
    $o.GpresultTextExit = [int]$LASTEXITCODE
    $Tmp = Join-Path $env:TEMP ('AL-gpresult-' + [guid]::NewGuid().ToString('N') + '.xml')
    $null = & "$env:windir\System32\gpresult.exe" /scope computer /x $Tmp /f 2>&1
    $o.GpresultXmlExit = [int]$LASTEXITCODE
    $o.GpresultXml = ''
    if (Test-Path -LiteralPath $Tmp) { $o.GpresultXml = [IO.File]::ReadAllText($Tmp); [IO.File]::Delete($Tmp) }
    $Svc = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $o.AppIdSvc = "$($Svc.State)/$($Svc.StartMode)"
    $o.EffectiveXml = ''; $o.Effective = ''
    try {
        $o.EffectiveXml = "$(Get-AppLockerPolicy -Effective -Xml)"
        [xml]$Eff = $o.EffectiveXml
        $o.Effective = (@($Eff.AppLockerPolicy.RuleCollection | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count))" }) -join ', ')
        if (-not $o.Effective) { $o.Effective = 'empty (no rule collection)' }
    }
    catch { $o.Effective = "could not be read: $($_.Exception.Message)" }
    $o.PolicyEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8000, 8001 } -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object {
            $Status = ''
            if ($_.Id -eq 8000) { try { $Status = "$(([xml]($_.ToXml())).Event.EventData.Data | Where-Object { $_.Name -eq 'Status' } | ForEach-Object { $_.'#text' })" } catch { } }
            [pscustomobject]@{ Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $_.Id; Status = $Status; Message = ("$($_.Message)".Trim() -replace '\s+', ' ') }
        })
    $o.Finished = (Get-Date).ToString('s')
    [pscustomobject]$o
}

# Runs the probe on a server over WinRM, or in this process when the server is this computer (-Local forces that); returns its object
function Invoke-ALGpRefresh([string]$ComputerName, [bool]$Refresh, [int]$WaitSeconds = 10, [switch]$Local) {
    if ($Local -or (Test-ALLocalComputer $ComputerName)) { return (& $ALGpRefreshProbe $Refresh $WaitSeconds) }
    return (Invoke-Command -ComputerName $ComputerName -ScriptBlock $ALGpRefreshProbe -ArgumentList $Refresh, $WaitSeconds -ErrorAction Stop)
}

# Writes the raw outputs for one server to $Folder: <server>-gpresult.txt (Application Identity, the effective policy, the newest
# policy events, every gpupdate pass with its output, the gpresult text report) and <server>-gpresult.xml (the RSoP report, UTF-16
# as gpresult writes it). Returns the text file's path.
function Save-ALGpResult($Raw, [string]$Folder) {
    New-Item -Path $Folder -ItemType Directory -Force -WhatIf:$false | Out-Null
    $Name = "$($Raw.Computer)" -replace '[^A-Za-z0-9.-]', '_'
    $Txt = Join-Path $Folder "$Name-gpresult.txt"
    $Lines = New-Object System.Collections.Generic.List[string]
    $Lines.Add("Computer: $($Raw.Computer)   collected $($Raw.Started) - $($Raw.Finished)")
    $Lines.Add("Application Identity (AppIDSvc): $($Raw.AppIdSvc)")
    $Lines.Add("Effective AppLocker policy: $($Raw.Effective)")
    $Lines.Add('Newest AppLocker policy events (8001 = policy applied, 8000 = AppID policy conversion failed):')
    if (@($Raw.PolicyEvents).Count) { foreach ($E in @($Raw.PolicyEvents)) { $Lines.Add("  $($E.Time) event $($E.Id)$(if ("$($E.Status)" -ne '') { " status $($E.Status) ($(ConvertTo-ALWin32Message $E.Status))" }): $($E.Message)") } }
    else { $Lines.Add('  none') }
    foreach ($G in @($Raw.Gpupdate)) { $Lines.Add(''); $Lines.Add("==== $G") }
    $Lines.Add(''); $Lines.Add("==== gpresult /scope computer /r (exit code $($Raw.GpresultTextExit))"); $Lines.Add("$($Raw.GpresultText)".TrimEnd())
    $Lines.Add(''); $Lines.Add("==== gpresult /scope computer /x (exit code $($Raw.GpresultXmlExit)): $Name-gpresult.xml")
    $Body = (($Lines.ToArray() -join "`r`n") -replace '\r?\n', "`r`n") + "`r`n"
    [IO.File]::WriteAllText($Txt, $Body, (New-Object System.Text.UTF8Encoding $false))
    if ("$($Raw.GpresultXml)".Trim()) { [IO.File]::WriteAllText((Join-Path $Folder "$Name-gpresult.xml"), "$($Raw.GpresultXml)", (New-Object System.Text.UnicodeEncoding $false, $true)) }
    return $Txt
}

# The English text report of gpresult /scope computer /r: the applied GPO names (in the order gpresult lists them), the GPOs that
# were filtered out with their reason, and the "last applied" / "applied from" lines. Everything is empty when the headings are not
# found (another display language, or no report). Only the COMPUTER SETTINGS part is read; the user part has the same headings.
function ConvertFrom-ALGpResultText([string]$Text) {
    $Applied = New-Object System.Collections.Generic.List[string]
    $Not = New-Object System.Collections.Generic.List[object]
    $Last = ''; $From = ''
    $Lines = @("$Text" -split '\r?\n')
    $Start = 0
    for ($I = 0; $I -lt $Lines.Count; $I++) { if ($Lines[$I] -match '^\s*COMPUTER SETTINGS\s*$') { $Start = $I; break } }
    $Section = ''; $Pending = ''
    for ($I = $Start; $I -lt $Lines.Count; $I++) {
        $L = $Lines[$I]
        if ($L -match '^\s*USER SETTINGS\s*$') { break }
        if ($L -match '^\s*Last time Group Policy was applied:\s*(.+?)\s*$') { $Last = $Matches[1]; continue }
        if ($L -match '^\s*Group Policy was applied from:\s*(.+?)\s*$') { $From = $Matches[1]; continue }
        if ($L -match '^\s*Applied Group Policy Objects\s*$') { $Section = 'applied'; continue }
        if ($L -match '^\s*The following GPOs were not applied because they were filtered out\s*$') { $Section = 'not'; continue }
        if ($L -match '^\s*The computer is a part of the following security groups\s*$') { $Section = ''; continue }
        if ($L -match '^\s*-{5,}\s*$') { continue }
        if ($Section -eq 'applied') {
            if ($L.Trim() -eq '') { if ($Applied.Count) { $Section = '' }; continue }
            if ($L -match '^\s*N/A\s*$') { $Section = ''; continue }
            $Applied.Add($L.Trim())
        }
        elseif ($Section -eq 'not') {
            if ($L.Trim() -eq '') { continue }
            if ($L -match '^\s*Filtering:\s*(.+?)\s*$') { if ($Pending) { $Not.Add([pscustomobject]@{ Name = $Pending; Reason = $Matches[1] }); $Pending = '' }; continue }
            $Pending = $L.Trim()
        }
    }
    if ($Pending) { $Not.Add([pscustomobject]@{ Name = $Pending; Reason = '' }) }
    [pscustomobject]@{ Applied = $Applied.ToArray(); NotApplied = $Not.ToArray(); LastApplied = $Last; AppliedFrom = $From }
}

# What gpresult reported for the computer, from the RSoP XML (gpresult /x; language-independent) with the text report (gpresult /r)
# as the fallback and for the "last applied" lines:
#   Gpos        every GPO Group Policy considered: Name, Id, Applied, AppliedOrder, Reason when not applied (Disabled (Link),
#               Disabled (GPO), Denied (Security), Not Applied (Empty) ...), VersionDirectory / VersionSysvol, Link (the OU, domain
#               or site it is linked to), LinkEnabled
#   Applied     the names of the applied GPOs, highest precedence first (the order gpresult lists them)
#   Extensions  the client-side extensions that ran: Name, Id, Error (0 = success), EndTime
#   LastApplied / AppliedFrom   from the text report when it is in English, otherwise empty
#   Source      'xml', 'text' or '' (no readable report)
function ConvertFrom-ALGpResult([string]$Xml, [string]$Text) {
    $Gpos = New-Object System.Collections.Generic.List[object]
    $Ext = New-Object System.Collections.Generic.List[object]
    $Source = ''
    $Doc = $null
    if ("$Xml".Trim()) {
        $Doc = New-Object System.Xml.XmlDocument
        try { $Doc.LoadXml("$Xml".Trim()) } catch { $Doc = $null }
    }
    if ($Doc) {
        $Ns = New-Object System.Xml.XmlNamespaceManager $Doc.NameTable
        $Ns.AddNamespace('r', 'http://www.microsoft.com/GroupPolicy/Rsop')
        $Ns.AddNamespace('t', 'http://www.microsoft.com/GroupPolicy/Types')
        $Val = { param($N, $X) $F = $N.SelectSingleNode($X, $Ns); if ($F) { "$($F.InnerText)".Trim() } else { '' } }
        $Results = $Doc.SelectSingleNode('/r:Rsop/r:ComputerResults', $Ns)
        if ($Results) {
            $Source = 'xml'
            foreach ($G in @($Results.SelectNodes('r:GPO', $Ns))) {
                $Order = 0; [void][int]::TryParse((& $Val $G 'r:Link/r:AppliedOrder'), [ref]$Order)
                $LinkEnabled = ((& $Val $G 'r:Link/r:Enabled') -ne 'false')
                $Enabled = ((& $Val $G 'r:Enabled') -ne 'false')
                $Valid = ((& $Val $G 'r:IsValid') -ne 'false')
                $Filter = ((& $Val $G 'r:FilterAllowed') -ne 'false')
                $Denied = ((& $Val $G 'r:AccessDenied') -eq 'true')
                $VerAd = 0; [void][int]::TryParse((& $Val $G 'r:VersionDirectory'), [ref]$VerAd)
                $VerSysvol = 0; [void][int]::TryParse((& $Val $G 'r:VersionSysvol'), [ref]$VerSysvol)
                $Applied = ($Order -gt 0)
                $Reason = if ($Applied) { '' } elseif (-not $LinkEnabled) { 'Disabled (Link)' } elseif (-not $Enabled) { 'Disabled (GPO)' } elseif ($Denied) { 'Denied (Security)' } elseif (-not $Valid) { 'Not Applied (Invalid)' } elseif (-not $Filter) { 'Denied (WMI Filter)' } elseif ($VerAd -eq 0) { 'Not Applied (Empty)' } else { 'Not Applied (Unknown Reason)' }
                $Gpos.Add([pscustomobject]@{ Name = (& $Val $G 'r:Name'); Id = (& $Val $G 'r:Path/t:Identifier'); Applied = $Applied; AppliedOrder = $Order; Reason = $Reason; VersionDirectory = $VerAd; VersionSysvol = $VerSysvol; Link = (& $Val $G 'r:Link/r:SOMPath'); LinkEnabled = $LinkEnabled })
            }
            foreach ($E in @($Results.SelectNodes('r:ExtensionStatus', $Ns))) {
                $Err = 0; [void][int]::TryParse((& $Val $E 'r:Error'), [ref]$Err)
                $Ext.Add([pscustomobject]@{ Name = (& $Val $E 'r:Name'); Id = (& $Val $E 'r:Identifier'); Error = $Err; EndTime = (& $Val $E 'r:EndTime') })
            }
        }
    }
    $T = ConvertFrom-ALGpResultText $Text
    if ($Source -ne 'xml' -and ($T.Applied.Count -or $T.NotApplied.Count)) {
        $Source = 'text'
        $N = $T.Applied.Count
        foreach ($Name in $T.Applied) { $Gpos.Add([pscustomobject]@{ Name = $Name; Id = ''; Applied = $true; AppliedOrder = $N; Reason = ''; VersionDirectory = 0; VersionSysvol = 0; Link = ''; LinkEnabled = $true }); $N-- }
        foreach ($X in $T.NotApplied) { $Gpos.Add([pscustomobject]@{ Name = $X.Name; Id = ''; Applied = $false; AppliedOrder = 0; Reason = $X.Reason; VersionDirectory = 0; VersionSysvol = 0; Link = ''; LinkEnabled = ($X.Reason -notlike 'Disabled (Link)*') }) }
    }
    [pscustomobject]@{
        Gpos        = $Gpos.ToArray()
        Applied     = @($Gpos | Where-Object { $_.Applied } | Sort-Object AppliedOrder -Descending | ForEach-Object { $_.Name })
        Extensions  = $Ext.ToArray()
        LastApplied = $T.LastApplied
        AppliedFrom = $T.AppliedFrom
        Source      = $Source
    }
}

# A GPO whose link is disabled and that the computer never applied is listed by gpresult under its GUID, not its name (the client has
# never read it). Given the GUIDs of the GPOs this toolkit manages ({GUID} -> name), such entries get their name back, so the rows and
# the verdict can name them. Returns the report (changed in place).
function Resolve-ALGpoNames($Report, [hashtable]$IdToName) {
    if (-not $IdToName -or -not $IdToName.Count) { return $Report }
    $Map = @{}
    foreach ($K in @($IdToName.Keys)) { if ("$K".Trim('{}') -and $IdToName[$K]) { $Map['{' + "$K".Trim('{}').ToUpper() + '}'] = "$($IdToName[$K])" } }
    foreach ($G in @($Report.Gpos)) {
        $Id = '{' + "$($G.Id)".Trim('{}').ToUpper() + '}'
        $ByName = '{' + "$($G.Name)".Trim('{}').ToUpper() + '}'
        if ($Map.ContainsKey($Id) -and ("$($G.Name)" -eq '' -or $ByName -eq $Id)) { $G.Name = $Map[$Id] }
        elseif ($Map.ContainsKey($ByName)) { $G.Name = $Map[$ByName] }
    }
    $Report.Applied = @($Report.Gpos | Where-Object { $_.Applied } | Sort-Object AppliedOrder -Descending | ForEach-Object { $_.Name })
    return $Report
}

# Judges a gpresult report against the AppLocker mode the links are meant to give the computer: Audit = the Audit GPO applied and the
# Enforce GPO not, Enforce = the other way round, Off = neither. Returns Ok, Expected, Found and Problems (one line each).
function Get-ALGpVerdict($Report, [string]$Mode, [string]$AuditName, [string]$EnforceName) {
    $Problems = New-Object System.Collections.Generic.List[string]
    $Applied = @($Report.Applied)
    $Want = @(switch ($Mode) { 'Audit' { $AuditName } 'Enforce' { $EnforceName } })
    $NotWant = @(@($AuditName, $EnforceName) | Where-Object { $_ -notin $Want })
    foreach ($N in $Want) {
        if ($Applied -notcontains $N) {
            $G = @($Report.Gpos | Where-Object { $_.Name -eq $N }) | Select-Object -First 1
            $Problems.Add("'$N' is not applied ($(if ($G) { $G.Reason } else { 'not linked to an OU this computer is in, or the link not replicated yet' }))")
        }
    }
    foreach ($N in $NotWant) {
        if ($Applied -contains $N) { $Problems.Add("'$N' is applied but must not be$(if ($Mode -eq 'Off') { ' (mode Off)' } else { " (both AppLocker GPOs apply - run 3_AL_set_mode.ps1 -Mode $Mode)" })") }
    }
    if (-not $Report.Source) { $Problems.Add('gpresult gave no readable report') }
    [pscustomobject]@{
        Ok       = ($Problems.Count -eq 0)
        Expected = $(if ($Want.Count) { "$($Want -join ', ') applied, $($NotWant -join ', ') not applied" } else { "neither $($NotWant -join ' nor ') applied" })
        Found    = $(if ($Applied.Count) { $Applied -join ', ' } else { 'no GPO applied' })
        Problems = $Problems.ToArray()
    }
}

# The text of a Win32 error code as Windows writes it, for the Status of AppLocker event 8000 and the Error of a client-side extension:
# 2 -> 'The system cannot find the file specified', '0x8007007E' -> 'The specified module could not be found'. An NTSTATUS value
# (0xC...) and a COM HRESULT are named where this toolkit knows them; anything else is returned as given.
function ConvertTo-ALWin32Message([object]$Code) {
    $Text = "$Code".Trim()
    $N = [int64]0
    if ($Text -match '^0[xX]([0-9A-Fa-f]{1,8})$') { $N = [Convert]::ToInt64($Matches[1], 16) }
    elseif ($Text -match '^-?\d{1,10}$') { $N = [int64]$Text; if ($N -lt 0) { $N += 4294967296 } }
    else { return $Text }
    if ($N -eq 0) { return 'The operation completed successfully' }
    if ($N -ge 3221225472 -and $N -le 3489660927) {
        $Known = @{ 'C0000001' = 'STATUS_UNSUCCESSFUL'; 'C0000002' = 'STATUS_NOT_IMPLEMENTED'; 'C000000D' = 'STATUS_INVALID_PARAMETER'; 'C0000017' = 'STATUS_NO_MEMORY'; 'C0000022' = 'STATUS_ACCESS_DENIED'; 'C0000034' = 'STATUS_OBJECT_NAME_NOT_FOUND'; 'C000003A' = 'STATUS_OBJECT_PATH_NOT_FOUND'; 'C00000BB' = 'STATUS_NOT_SUPPORTED'; 'C0000225' = 'STATUS_NOT_FOUND' }
        $Hex = $N.ToString('X8')
        return "NTSTATUS 0x$Hex$(if ($Known.ContainsKey($Hex)) { ' ' + $Known[$Hex] })"
    }
    $Win32 = if ($N -ge 2147942400 -and $N -le 2148007935) { $N - 2147942400 } elseif ($N -lt 65536) { $N } else { -1 }
    if ($Win32 -ge 0) { return (New-Object System.ComponentModel.Win32Exception ([int]$Win32)).Message }
    $Com = @{ '80004001' = 'E_NOTIMPL (Not implemented)'; '80004002' = 'E_NOINTERFACE (No such interface supported)'; '80004003' = 'E_POINTER (Invalid pointer)'; '80004004' = 'E_ABORT (Operation aborted)'; '80004005' = 'E_FAIL (Unspecified error)'; '8000FFFF' = 'E_UNEXPECTED (Catastrophic failure)'; '80090016' = 'NTE_BAD_KEYSET (Keyset does not exist)'; '800B0100' = 'TRUST_E_NOSIGNATURE (No signature was present in the subject)'; '800B0101' = 'CERT_E_EXPIRED (A required certificate is not within its validity period)'; '800B0109' = 'CERT_E_UNTRUSTEDROOT (A certificate chain processed, but terminated in a root certificate which is not trusted)' }
    $Hex = $N.ToString('X8')
    return "HRESULT 0x$Hex$(if ($Com.ContainsKey($Hex)) { ' ' + $Com[$Hex] })"
}

# Adds the gpresult rows for one server to a results list. $Mode = Audit / Enforce / Off judges which AppLocker GPO must be applied
# (FAIL otherwise); 'Any' only reports. Rows: "GPO applied" (every GPO, with the reason for each one not applied), "GPO processing"
# (the Registry extension writes the AppLocker rules, the Security extension the Application Identity service setting), "AppLocker
# policy events" (WARN when the newest is 8000, a conversion failure: the rules are not loaded), "Group Policy" (when and from which
# DC it was last applied, and where the raw gpupdate / gpresult output was saved).
function Add-ALGpResults($List, [string]$Computer, $Raw, $Report, [string]$Mode, [string]$AuditName, [string]$EnforceName, [string]$File) {
    $NotApplied = @($Report.Gpos | Where-Object { -not $_.Applied -and $_.Name -ne 'Local Group Policy' } | ForEach-Object { "$($_.Name) ($($_.Reason))" })
    $Found = "applied: $(if (@($Report.Applied).Count) { $Report.Applied -join ', ' } else { 'none' })$(if ($NotApplied.Count) { "; not applied: $($NotApplied -join ', ')" })"
    if ($Mode -eq 'Any') {
        if ($Report.Source) { Add-ALResult $List 'INFO' "GPO applied $Computer" $Found } else { Add-ALResult $List 'WARN' "GPO applied $Computer" 'gpresult gave no readable report' }
    }
    else {
        $V = Get-ALGpVerdict $Report $Mode $AuditName $EnforceName
        if ($V.Ok) { Add-ALResult $List 'OK' "GPO applied $Computer" "$Found - as expected for $Mode ($($V.Expected))" }
        else { Add-ALResult $List 'FAIL' "GPO applied $Computer" "$($V.Problems -join '; ') - $Found - expected for ${Mode}: $($V.Expected)" }
    }
    $Ours = @($Report.Extensions | Where-Object { $_.Id -in '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}', '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' })
    if ($Ours.Count) {
        $Bad = @($Ours | Where-Object { $_.Error -ne 0 })
        $Status = if (-not $Bad.Count) { 'OK' } elseif ($Mode -eq 'Off') { 'WARN' } else { 'FAIL' }
        Add-ALResult $List $Status "GPO processing $Computer" ((@($Ours | ForEach-Object { "$($_.Name) extension $(if ($_.Error -eq 0) { 'OK' } else { "error $($_.Error) ($(ConvertTo-ALWin32Message $_.Error))" }) at $($_.EndTime)" })) -join '; ')
    }
    elseif ($Report.Source -eq 'xml') { Add-ALResult $List 'INFO' "GPO processing $Computer" 'the Registry and Security extensions have not run on this computer yet (no GPO with such settings has applied so far)' }
    $Newest = @($Raw.PolicyEvents) | Select-Object -First 1
    if (-not $Newest) {
        # Windows Server 2022 logs the 8001 a minute or two after the refresh that loaded the rules (seen in the lab); 2025 logs it at once
        if ("$($Raw.Effective)" -match '=(Enabled|AuditOnly)\([1-9]') { Add-ALResult $List 'INFO' "AppLocker policy events $Computer" "none in the EXE and DLL log yet - the effective policy is loaded ($($Raw.Effective)); the 8001 event can follow the refresh by a minute or two" }
        else { Add-ALResult $List 'INFO' "AppLocker policy events $Computer" 'none in the EXE and DLL log: no AppLocker policy has been applied or rejected on this computer yet' }
    }
    elseif ($Newest.Id -eq 8000) { $Hint = Get-ALStatusHint $Newest.Status; Add-ALResult $List 'WARN' "AppLocker policy events $Computer" "newest is 8000 at $($Newest.Time): AppID policy conversion failed, status $($Newest.Status) ($(ConvertTo-ALWin32Message $Newest.Status)) - the rules are NOT loaded. Run 7_AL_diagnose.ps1 (README, Appendix D)$(if ($Hint) { ". Status $($Newest.Status) points at $Hint" })" }
    else { Add-ALResult $List 'OK' "AppLocker policy events $Computer" "newest is 8001 at $($Newest.Time): the AppLocker policy was applied successfully$(if (@($Raw.PolicyEvents | Where-Object { $_.Id -eq 8000 }).Count) { ' (older 8000 conversion failures are in the log)' })" }
    Add-ALResult $List 'INFO' "Group Policy $Computer" "last applied $(if ($Report.LastApplied) { $Report.LastApplied } else { '(not in the report)' }) from $(if ($Report.AppliedFrom) { $Report.AppliedFrom } else { '(not in the report)' }); raw gpupdate / gpresult output: $File"
}
