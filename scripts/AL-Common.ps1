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

# Settings (AL-Settings.psd1 or -SettingsFile, then script-parameter overrides), checked before anything runs; folders and transcript
function Initialize-AL([string]$ScriptName, [hashtable]$Overrides = @{}, [string]$SettingsFile, [switch]$NoTranscript) {
    if (-not $SettingsFile) { $SettingsFile = Join-Path $PSScriptRoot 'AL-Settings.psd1' }
    if (-not (Test-Path -LiteralPath $SettingsFile)) { throw "STOP: settings file not found: $SettingsFile" }
    $Cfg = @{
        ReferenceServer   = ''
        TargetOUs         = @()
        ExtraAllowedPaths = @()
        SecureFolders     = @()
        KnownAdmins       = @()
        AccessChkSha256   = ''
        EnableDllRules    = $false
        EventLogSizesMB   = @{ 'EXE and DLL' = 100; 'MSI and Script' = 20; 'Packaged app-Execution' = 20; 'Packaged app-Deployment' = 20 }
    }
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
    foreach ($K in @($Cfg.KnownAdmins)) { if ("$K" -notmatch '^(S-1-\d+(-\d+)+|[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+)$') { throw "STOP: KnownAdmins entry '$K' must be a SID (S-1-5-21-...) or DOMAIN\Group." } }
    if ($Cfg.AccessChkSha256 -and $Cfg.AccessChkSha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'STOP: AccessChkSha256 must be a 64-character SHA-256 hex string (or empty).' }
    foreach ($N in @($Cfg.EventLogSizesMB.Keys)) {
        if ($N -notin 'EXE and DLL', 'MSI and Script', 'Packaged app-Execution', 'Packaged app-Deployment') { throw "STOP: EventLogSizesMB names an unknown AppLocker log '$N'." }
        $V = 0
        if (-not [int]::TryParse("$($Cfg.EventLogSizesMB[$N])", [ref]$V) -or $V -lt 1 -or $V -gt 4096) { throw "STOP: EventLogSizesMB '$N' must be a whole number of MB from 1 to 4096." }
    }
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
#   NOTFOUND|<path>                       the path does not exist on that server
#   WRITABLE|<file or folder>|<account>   an account that is not an administrator may write, delete or re-permission it, so a path
#                                         rule there would let that account plant code that every user may run
#   UNREADABLE|<file or folder>           its permissions could not be read
#   UNRESOLVED|<KnownAdmins entry>        a KnownAdmins name could not be resolved to a SID on that server
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
            try { $Rules = (Get-Acl -LiteralPath $I.FullName -ErrorAction Stop).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) }
            catch { "UNREADABLE|$($I.FullName)"; continue }
            foreach ($Rule in $Rules) {
                $Sid = $Rule.IdentityReference.Value
                if ($Rule.AccessControlType -ne 'Allow' -or ([int64]$Rule.FileSystemRights -band $Mask) -eq 0) { continue }
                if ($Admin.Contains($Sid) -or $Sid -like 'S-1-5-80-*' -or $Sid -match '^S-1-5-21-.+-(500|512|519)$') { continue }
                $Name = $Sid
                try { $Name = "$($Rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value) ($Sid)" } catch { }
                "WRITABLE|$($I.FullName)|$Name"
                break
            }
        }
    }
}

# Runs $ALWritableCheck on a server (-ComputerName or -Session) with the KnownAdmins setting; returns Kind / Path / Account rows
function Invoke-ALWritableCheck([string[]]$Paths, $Cfg, [string]$ComputerName, $Session) {
    $Where = if ($Session) { @{ Session = $Session } } else { @{ ComputerName = $ComputerName } }
    foreach ($Line in @(Invoke-Command @Where -ScriptBlock $ALWritableCheck -ArgumentList @($Paths), @($Cfg.KnownAdmins) -ErrorAction Stop)) {
        $F = "$Line" -split '\|'
        [pscustomobject]@{ Kind = $F[0]; Path = $F[1]; Account = $(if ($F.Count -gt 2) { $F[2] } else { '' }) }
    }
}

# True when a file/folder reported by $ALWritableCheck lies inside an ExtraAllowedPaths / SecureFolders entry
function Test-ALPathUnder([string]$Item, [string]$Entry) {
    $Base = ($Entry -replace '\\\*$', '').TrimEnd('\')
    return ($Item -eq $Base -or $Item.StartsWith($Base + '\', [StringComparison]::OrdinalIgnoreCase))
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
