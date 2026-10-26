# Shared helpers for the AppLocker scripts (dot-sourced by 0_ to 5_). Windows PowerShell 5.1 and PowerShell 7. ASCII-only.

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
        TargetOUs         = @()
        ExtraAllowedPaths = @()
        SecureFolders     = @()
        KnownAdmins       = @()
        AccessChkSha256   = ''
        EnableDllRules    = $false
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
# Enabled, and the DLL collection emptied and set to NotConfigured unless DLL rules are wanted.
function New-ALDeployXml([string]$SourceXml, [ValidateSet('Audit', 'Enforce')][string]$Mode, [bool]$DllRules, [string]$OutFile) {
    $Doc = New-Object System.Xml.XmlDocument
    try { $Doc.Load($SourceXml) } catch { throw "STOP: $SourceXml is not valid XML ($($_.Exception.Message))." }
    if (-not $Doc.AppLockerPolicy) { throw "STOP: $SourceXml is not an AppLocker policy." }
    $Want = if ($Mode -eq 'Audit') { 'AuditOnly' } else { 'Enabled' }
    foreach ($Rc in @($Doc.AppLockerPolicy.RuleCollection)) {
        if ($Rc.Type -eq 'ManagedInstaller') { throw 'STOP: the source contains a ManagedInstaller rule collection; leave that to Configuration Manager.' }
        if ($Rc.Type -eq 'Dll' -and -not $DllRules) { $Rc.RemoveAll(); $Rc.SetAttribute('Type', 'Dll'); $Rc.SetAttribute('EnforcementMode', 'NotConfigured') }
        elseif ($Rc.EnforcementMode -ne $Want) { throw "STOP: $($Rc.Type) collection is '$($Rc.EnforcementMode)' in $SourceXml, expected $Want." }
    }
    $Doc.Save($OutFile)
    return (Get-ALPolicySummary $Doc)
}

# "Exe=Enabled(10), Msi=Enabled(5), ..." for an AppLocker policy document
function Get-ALPolicySummary([xml]$Doc) {
    return (@($Doc.AppLockerPolicy.RuleCollection | Sort-Object Type | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' -and $_.LocalName -ne 'RuleCollectionExtensions' }).Count))" }) -join ', ')
}

# Sets the AppLocker event log sizes (MB) on the computers; returns one text line per computer
function Set-ALEventLogSize([string[]]$Computers, [hashtable]$SizesMB) {
    foreach ($C in $Computers) {
        try {
            Invoke-Command -ComputerName $C -ArgumentList $SizesMB -ErrorAction Stop -ScriptBlock {
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

# Runs $ALWritableCheck on a server (-ComputerName or -Session) with the KnownAdmins setting; returns Kind / Path / Account /
# IsFolder / Computer rows
function Invoke-ALWritableCheck([string[]]$Paths, $Cfg, [string]$ComputerName, $Session) {
    $Where = if ($Session) { @{ Session = $Session } } else { @{ ComputerName = $ComputerName } }
    $Name = if ($Session) { $Session.ComputerName } else { $ComputerName }
    foreach ($Line in @(Invoke-Command @Where -ScriptBlock $ALWritableCheck -ArgumentList @($Paths), @($Cfg.KnownAdmins) -ErrorAction Stop)) {
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

# Rule collections this baseline manages: Exe, Msi, Script, Appx (+ Dll when DLL rules are on). Others in an effective policy - the DLL
# collection when DLL rules are off, ManagedInstaller - come from other policies (e.g. the local MECM managed-installer policy).
function Get-ALManagedCollections([bool]$DllRules) { return @('Exe', 'Msi', 'Script', 'Appx') + @(if ($DllRules) { 'Dll' }) }
function Get-ALExpectedMode([string]$Mode, [string]$Type, [bool]$DllRules) {
    if ($Type -eq 'Dll' -and -not $DllRules) { return 'NotConfigured' }
    if ($Mode -eq 'Audit') { return 'AuditOnly' } else { return 'Enabled' }
}
# The managed collections of an effective policy that are missing or in the wrong mode for Audit / Enforce (nothing = as expected)
function Get-ALPolicyMismatch([xml]$Policy, [string]$Mode, [bool]$DllRules) {
    $Cols = @{}
    foreach ($Rc in @($Policy.AppLockerPolicy.RuleCollection)) { $Cols["$($Rc.Type)"] = "$($Rc.EnforcementMode)" }
    foreach ($T in Get-ALManagedCollections $DllRules) {
        $Want = Get-ALExpectedMode $Mode $T $DllRules
        if (-not $Cols.ContainsKey($T)) { "$T missing (expected $Want)" }
        elseif ($Cols[$T] -ne $Want) { "$T=$($Cols[$T]) (expected $Want)" }
    }
}

# Group Policy refresh over WinRM. The first refresh after a computer receives the GPO starts Application Identity;
# a second one makes it load the rules - so two passes.
function Invoke-ALRefresh([string[]]$Computers) {
    foreach ($C in $Computers) {
        try {
            Invoke-Command -ComputerName $C -ErrorAction Stop -ScriptBlock {
                gpupdate.exe /target:computer /force | Out-Null
                Start-Sleep -Seconds 10
                gpupdate.exe /target:computer /force | Out-Null
                $s = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
                "$env:COMPUTERNAME refreshed; AppIDSvc $($s.State)/$($s.StartMode)"
            }
        }
        catch { "$C : refresh FAILED - $($_.Exception.Message)" }
    }
}
