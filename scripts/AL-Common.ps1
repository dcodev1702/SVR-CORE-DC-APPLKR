# Shared helpers for the AppLocker scripts (dot-sourced by 0_ to 5_). Requires Windows PowerShell 5.1 (powershell.exe).

function Import-ALModule([string]$Name) {
    if (Get-Module -Name $Name) { return }
    Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
}

# Settings (AL-Settings.psd1 or -SettingsFile, then script-parameter overrides), folders and transcript
function Initialize-AL([string]$ScriptName, [hashtable]$Overrides = @{}, [string]$SettingsFile, [switch]$NoTranscript) {
    if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'STOP: run these scripts in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }
    if (-not $SettingsFile) { $SettingsFile = Join-Path $PSScriptRoot 'AL-Settings.psd1' }
    if (-not (Test-Path -LiteralPath $SettingsFile)) { throw "STOP: settings file not found: $SettingsFile" }
    $Cfg = @{
        TargetOUs         = @()
        ExtraAllowedPaths = @()
        SecureFolders     = @()
        EnableDllRules    = $false
        EventLogSizesMB   = @{ 'EXE and DLL' = 100; 'MSI and Script' = 20; 'Packaged app-Execution' = 20; 'Packaged app-Deployment' = 20 }
    }
    $File = Import-PowerShellDataFile -LiteralPath $SettingsFile
    foreach ($Key in $File.Keys) { $Cfg[$Key] = $File[$Key] }
    foreach ($Key in @($Overrides.Keys)) {
        $V = $Overrides[$Key]
        $Set = if ($V -is [string]) { $V -ne '' } elseif ($V -is [array]) { $V.Count -gt 0 } else { $null -ne $V }
        if ($Set) { $Cfg[$Key] = $V }
    }
    foreach ($Key in 'AuditGpoName', 'EnforceGpoName', 'ReferenceServer') { if (-not $Cfg[$Key]) { throw "STOP: setting '$Key' is empty ($SettingsFile)." } }
    if ($Cfg.AuditGpoName -eq $Cfg.EnforceGpoName) { throw 'STOP: AuditGpoName and EnforceGpoName must be different.' }

    $Cfg.Root = Split-Path -Parent $PSScriptRoot
    if (-not $Cfg.ToolkitPath) { $Cfg.ToolkitPath = Join-Path $Cfg.Root 'AaronLocker\AaronLocker' }
    $Base = [IO.Path]::GetFileNameWithoutExtension($SettingsFile)
    $Cfg.Profile = ($Base -replace '^AL-Settings\.?', '')
    if (-not $Cfg.Profile) { $Cfg.Profile = 'default' }
    $Cfg.OutRoot = Join-Path (Join-Path $Cfg.Root 'Outputs') $Cfg.Profile
    $Cfg.LogDir = Join-Path $Cfg.Root 'Logs'
    New-Item -Path $Cfg.LogDir, $Cfg.OutRoot -ItemType Directory -Force | Out-Null
    $Cfg.Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Cfg.SettingsFile = $SettingsFile
    if (-not $NoTranscript) {
        $Cfg.Transcript = Join-Path $Cfg.LogDir "$ScriptName-$($Cfg.Stamp).log"
        Start-Transcript -Path $Cfg.Transcript | Out-Null
    }
    return $Cfg
}

function Stop-ALTranscript { try { Stop-Transcript | Out-Null } catch { } }

# Yellow Y/N gate before a change; -NoConfirm for automation. A non-interactive session without -NoConfirm stops.
function Confirm-ALChange {
    param([Parameter(Mandatory)][string]$Action, [string[]]$Detail = @(), [switch]$NoConfirm)
    Write-Host ''
    Write-Host "WARNING: this changes AppLocker - $Action" -ForegroundColor Yellow
    foreach ($Line in $Detail) { if ($Line) { Write-Host "  $Line" -ForegroundColor Yellow } }
    if ($NoConfirm) { Write-Host '  -NoConfirm: continuing without a prompt.' -ForegroundColor Yellow; return }
    $Interactive = [Environment]::UserInteractive -and -not (@([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' }).Count -gt 0)
    try { if ([Console]::IsInputRedirected) { $Interactive = $false } } catch { }
    if (-not $Interactive) { throw 'STOP: this change needs a Y/N confirmation but the session is non-interactive. Nothing was changed. Add -NoConfirm for automation.' }
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
# Prints the table and returns the number of FAIL rows
function Write-ALResults($List) {
    $List | Format-Table -AutoSize -Wrap | Out-String -Width 240 | Write-Host
    $Failed = @($List | Where-Object Status -eq 'FAIL').Count
    $Warned = @($List | Where-Object Status -eq 'WARN').Count
    if ($Failed) { Write-Host "$Failed check(s) FAILED, $Warned warning(s)." -ForegroundColor Red }
    elseif ($Warned) { Write-Host "No failures, $Warned warning(s)." -ForegroundColor Yellow }
    else { Write-Host 'All checks passed.' -ForegroundColor Green }
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

# $true / $false = link enabled / disabled; $null = the GPO is not linked to the OU
function Get-ALLinkState($GpoId, [string]$Ou, $Domain) {
    $Link = (Get-GPInheritance -Target $Ou -Server $Domain.PDC).GpoLinks | Where-Object { $_.GpoId -eq $GpoId }
    if ($Link) { return [bool]$Link.Enabled } else { return $null }
}

# Turns an AaronLocker output file into the XML that goes into a GPO: Audit = every collection AuditOnly, Enforce = every collection
# Enabled, and the DLL collection emptied and set to NotConfigured unless DLL rules are wanted.
function New-ALDeployXml([string]$SourceXml, [ValidateSet('Audit', 'Enforce')][string]$Mode, [bool]$DllRules, [string]$OutFile) {
    [xml]$Doc = Get-Content -LiteralPath $SourceXml -Raw
    $Want = if ($Mode -eq 'Audit') { 'AuditOnly' } else { 'Enabled' }
    foreach ($Rc in @($Doc.AppLockerPolicy.RuleCollection)) {
        if ($Rc.Type -eq 'ManagedInstaller') { throw 'STOP: the source contains a ManagedInstaller rule collection; leave that to Configuration Manager.' }
        if ($Rc.Type -eq 'Dll' -and -not $DllRules) { $Rc.RemoveAll(); $Rc.SetAttribute('Type', 'Dll'); $Rc.SetAttribute('EnforcementMode', 'NotConfigured') }
        elseif ($Rc.EnforcementMode -ne $Want) { throw "STOP: $($Rc.Type) collection is '$($Rc.EnforcementMode)' in $SourceXml, expected $Want." }
    }
    $Doc.Save($OutFile)
    return (@($Doc.AppLockerPolicy.RuleCollection | ForEach-Object { "$($_.Type)=$($_.EnforcementMode)($(@($_.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count))" }) -join ', ')
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

# Offline check of the AccessChk.exe that was brought in: present, Authenticode-valid and Microsoft-signed, and (optional) equal to the pinned SHA-256
function Test-ALAccessChk([string]$Path, [string]$Sha256) {
    if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Ok = $false; Detail = "missing: $Path - bring it in by hand (README, 'No Internet')" } }
    $Sig = Get-AuthenticodeSignature -LiteralPath $Path
    $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($Sig.Status -ne 'Valid' -or $Sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { return [pscustomobject]@{ Ok = $false; Detail = "signature is $($Sig.Status), not a valid Microsoft signature (SHA-256 $Hash)" } }
    if ($Sha256 -and $Hash -ne $Sha256.Trim().ToUpper()) { return [pscustomobject]@{ Ok = $false; Detail = "SHA-256 $Hash does not match the pinned AccessChkSha256" } }
    return [pscustomobject]@{ Ok = $true; Detail = "Microsoft-signed, version $((Get-Item -LiteralPath $Path).VersionInfo.FileVersion), SHA-256 $Hash$(if ($Sha256) { ' (pinned)' } else { ' (not pinned)' })" }
}

# Runs ON a server (Invoke-Command -ScriptBlock $ALWritableCheck -ArgumentList (,$Paths)). For every path from ExtraAllowedPaths it emits
#   NOTFOUND|<path>                        the path does not exist on that server
#   WRITABLE|<folder>|<SID>                Everyone / Users / Authenticated Users / Domain Users can write there (a path rule would be a bypass)
$ALWritableCheck = {
    param([string[]]$Paths)
    $Bad = 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11'
    $Mask = 852038   # WriteData, AppendData, DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership
    foreach ($P in $Paths) {
        $Dir = $P -replace '\\\*$', ''
        if (-not (Test-Path -LiteralPath $Dir)) { "NOTFOUND|$P"; continue }
        $Items = @(Get-Item -LiteralPath $Dir -Force) + @(Get-ChildItem -LiteralPath $Dir -Recurse -Directory -Force -ErrorAction SilentlyContinue)
        foreach ($I in $Items) {
            foreach ($Rule in (Get-Acl -LiteralPath $I.FullName).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                $Sid = $Rule.IdentityReference.Value
                if ($Rule.AccessControlType -eq 'Allow' -and -not ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -and
                    ([int]$Rule.FileSystemRights -band $Mask) -and ($Sid -in $Bad -or $Sid -match '-513$')) { "WRITABLE|$($I.FullName)|$Sid"; break }
            }
        }
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
