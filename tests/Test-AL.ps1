<#
.SYNOPSIS
    Unit tests for scripts\AL-Common.ps1: no network, no domain, nothing changed outside a temporary folder.

.DESCRIPTION
    Runs in Windows PowerShell 5.1 and PowerShell 7 without Pester. It dot-sources AL-Common.ps1 and checks: the settings validation
    (values that would widen the policy or damage a system folder are refused), the build folder lookup, AccessChk verification and
    the PE machine check, the writable-permission check on crafted ACLs, path comparison helpers, the deploy XML conversion, rule
    exceptions, the KnownAdmins helpers (canonical names, LDAP escaping, who counts, who never counts, entry format) and the in-place
    settings write. Every test creates what it needs under a temporary folder that is deleted at the end. With -BuildFolder it also
    compares New-ALDeployXml against a real build and checks that adding exceptions to it changes only the C:\Admin rules.

.PARAMETER BuildFolder
    Optional: a build folder (Outputs\<profile>\<timestamp>) to check the deploy XML conversion against its *-Deploy.xml files.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Console: one PASS / FAIL line per test and "Tests: all N passed" or "Tests: N passed, M FAILED".
    Exit code 1 when any test fails.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-AL.ps1
    Windows PowerShell 5.1.

.EXAMPLE
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-AL.ps1 -BuildFolder ..\Outputs\default\20261026-192905
    PowerShell 7, with the extra checks against a real build.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-26
    Version  : 1.0
    Requires : Windows PowerShell 5.1 or PowerShell 7. No modules, no elevation, no domain.
    Changes  : nothing outside a temporary folder under %TEMP% (created and deleted by the run).
#>
param([string]$BuildFolder)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'scripts\AL-Common.ps1')
$Pass = 0; $Fail = 0
function Assert([string]$Name, [bool]$Ok, [string]$Info = '') {
    if ($Ok) { $script:Pass++; Write-Host "PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "FAIL  $Name $Info" -ForegroundColor Red }
}
function Throws([scriptblock]$Code, [string]$Like = 'STOP:*') { try { & $Code; return $false } catch { return ("$($_.Exception.Message)" -like $Like) } }
function Get-BaseCfg { @{ AuditGpoName = 'A'; EnforceGpoName = 'E'; ReferenceServer = ''; ExtraAllowedPaths = @('C:\Admin\*'); SecureFolders = @('C:\Admin'); KnownAdmins = @(); AccessChkSha256 = ''; EventLogSizesMB = @{ 'EXE and DLL' = 100 } } }
function With([hashtable]$Change) { $C = Get-BaseCfg; foreach ($K in $Change.Keys) { $C[$K] = $Change[$K] }; return $C }
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("AL-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -Path $Tmp -ItemType Directory | Out-Null
Write-Host "PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition) - temp $Tmp"
try {
    # ---- Assert-ALSettings: good values pass, values that widen the policy or could damage a system folder stop
    Assert 'settings: defaults accepted' (-not (Throws { Assert-ALSettings (Get-BaseCfg) 'x' } '*'))
    foreach ($P in 'C:\Admin\*', 'D:\Program Files\Microsoft SQL Server\*', '\\srv\share\*', '\\srv\share\apps\*', 'C:\Admin\tool.exe') { Assert "settings: ExtraAllowedPaths '$P' accepted" (-not (Throws { Assert-ALSettings (With @{ ExtraAllowedPaths = @($P) }) 'x' } '*')) }
    foreach ($P in 'C:\*', 'C:\', '*', 'C:\Admin\*.exe', '%OSDRIVE%\Admin\*', 'Admin\*', 'C:\Admin\', '\\srv\*') { Assert "settings: ExtraAllowedPaths '$P' refused" (Throws { Assert-ALSettings (With @{ ExtraAllowedPaths = @($P) }) 'x' }) }
    foreach ($F in 'C:\Admin', 'D:\Tools\Admin') { Assert "settings: SecureFolders '$F' accepted" (-not (Throws { Assert-ALSettings (With @{ SecureFolders = @($F) }) 'x' } '*')) }
    foreach ($F in 'C:\Windows', 'c:\windows\System32', 'C:\Program Files', 'C:\Program Files (x86)\x', 'C:\ProgramData', 'C:\Users\Public', 'C:\', 'C:\Admin\*', 'Admin') { Assert "settings: SecureFolders '$F' refused" (Throws { Assert-ALSettings (With @{ SecureFolders = @($F) }) 'x' }) }
    foreach ($K in 'S-1-5-21-1-2-3-1105', 'CONTOSO\Tier0 Server Admins') { Assert "settings: KnownAdmins '$K' accepted" (-not (Throws { Assert-ALSettings (With @{ KnownAdmins = @($K) }) 'x' } '*')) }
    foreach ($K in 'Tier0Admins', 'S-1-x', 'A\B\C') { Assert "settings: KnownAdmins '$K' refused" (Throws { Assert-ALSettings (With @{ KnownAdmins = @($K) }) 'x' }) }
    foreach ($K in 'CONTOSO\Domain Users', 'contoso\domain computers', 'CONTOSO\Authenticated Users', 'S-1-5-21-1-2-3-513', 'S-1-5-11', 'S-1-1-0', 'S-1-5-32-545') { Assert "settings: KnownAdmins '$K' (never an administrator) refused" (Throws { Assert-ALSettings (With @{ KnownAdmins = @($K) }) 'x' }) }

    # ---- 0_AL_known_admins.ps1 helpers: canonical names, LDAP escaping, who already counts / never counts, entry format
    $Cn = Split-ALCanonicalName 'contoso.com/Domain Administration/Admin Groups/Tier0 Admins'
    Assert 'canonical: domain + segments' ($Cn.Domain -eq 'contoso.com' -and ($Cn.Segments -join '|') -eq 'Domain Administration|Admin Groups|Tier0 Admins')
    Assert 'canonical: \/ is a slash inside a name' (((Split-ALCanonicalName 'contoso.com/Ops\/Admins/G').Segments -join '|') -eq 'Ops/Admins|G')
    Assert 'canonical: trailing slash ignored' (((Split-ALCanonicalName 'contoso.com/A/').Segments -join '|') -eq 'A')
    Assert 'canonical: domain alone has no segments' (@((Split-ALCanonicalName 'contoso.com').Segments).Count -eq 0)
    foreach ($Bad in '', '/A', 'contoso.com//A', 'con toso/A') { Assert "canonical: '$Bad' refused" (Throws { Split-ALCanonicalName $Bad }) }
    Assert 'ldap filter: \ * ( ) escaped' ((ConvertTo-ALLdapFilterValue 'a*b(c)d\e') -eq 'a\2ab\28c\29d\5ce')
    Assert 'ldap filter: plain name unchanged' ((ConvertTo-ALLdapFilterValue 'Admin-User-Accounts') -eq 'Admin-User-Accounts')
    foreach ($S in 'S-1-5-32-544', 'S-1-5-18', 'S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-519', 'S-1-5-21-1-2-3-500', 'S-1-5-80-1-2-3') { Assert "built-in administrator: $S" (Test-ALBuiltInAdminSid $S) }
    foreach ($S in 'S-1-5-21-1-2-3-1105', 'S-1-5-21-1-2-3-513', 'S-1-5-32-548', 'S-1-5-21-1-2-3-5120') { Assert "not a built-in administrator: $S" (-not (Test-ALBuiltInAdminSid $S)) }
    foreach ($S in 'S-1-5-21-1-2-3-513', 'S-1-5-21-1-2-3-515', 'S-1-5-11', 'S-1-5-32-554', 'CONTOSO\Domain Users', 'CONTOSO\Everyone') { Assert "never an administrator: $S" (Test-ALNeverAdmin $S) }
    foreach ($S in 'S-1-5-21-1-2-3-512', 'S-1-5-21-1-2-3-1105', 'S-1-5-21-1-2-3-5130', 'CONTOSO\Domain Admins', 'CONTOSO\Tier0 Users') { Assert "may be an administrator: $S" (-not (Test-ALNeverAdmin $S)) }
    Assert 'entry: DOMAIN\Name kept' ((Get-ALKnownAdminEntry 'CONTOSO\Tier0 Admins' 'S-1-5-21-1-2-3-1105') -eq 'CONTOSO\Tier0 Admins')
    Assert 'entry: -AsSid gives the SID' ((Get-ALKnownAdminEntry 'CONTOSO\Tier0 Admins' 'S-1-5-21-1-2-3-1105' -AsSid) -eq 'S-1-5-21-1-2-3-1105')
    Assert 'entry: a name the settings refuse falls back to the SID' ((Get-ALKnownAdminEntry 'CONTOSO\Tier0/Admins' 'S-1-5-21-1-2-3-1105') -eq 'S-1-5-21-1-2-3-1105')
    Assert 'entry: a non-ASCII name falls back to the SID' ((Get-ALKnownAdminEntry ('CONTOSO\Admins' + [char]0xE9) 'S-1-5-21-1-2-3-1105') -eq 'S-1-5-21-1-2-3-1105')
    Assert 'array literal: quotes doubled, empty = @()' ((ConvertTo-ALArrayLiteral @('A\B', "C\O'Brien")) -eq "@('A\B', 'C\O''Brien')" -and (ConvertTo-ALArrayLiteral @()) -eq '@()')
    Assert 'array literal: $null and empty strings give @()' ((ConvertTo-ALArrayLiteral $null) -eq '@()' -and (ConvertTo-ALArrayLiteral @('', $null)) -eq '@()' -and (ConvertTo-ALArrayLiteral (@(if ($true) { @() }))) -eq '@()')

    # ---- Set-ALSettingsArray on a copy of the real settings file: value in, everything else untouched, proven before written
    $Psd = Join-Path $Tmp 'AL-Settings.psd1'
    Copy-Item -LiteralPath (Join-Path $Root 'scripts\AL-Settings.psd1') -Destination $Psd
    $Orig = [IO.File]::ReadAllText($Psd)
    $OrigValues = @((Import-PowerShellDataFile -LiteralPath $Psd).KnownAdmins)
    $StripKa = '(?m)^\s*KnownAdmins\s*=.*$'
    $W = Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values @('CONTOSO\Tier0 Admins', "CONTOSO\O'Brien Admins") -BackupFolder (Join-Path $Tmp 'bak')
    $Now = [IO.File]::ReadAllText($Psd)
    Assert 'settings write: the value reads back' (((Import-PowerShellDataFile -LiteralPath $Psd).KnownAdmins -join '|') -eq "CONTOSO\Tier0 Admins|CONTOSO\O'Brien Admins")
    Assert 'settings write: only the KnownAdmins line changed' (($Orig -replace '(?m)^\s*KnownAdmins\s*=.*$', '') -eq ($Now -replace '(?m)^\s*KnownAdmins\s*=.*$', ''))
    Assert 'settings write: CRLF kept, no BOM' ($Now.Contains("`r`n") -and -not $Now.Contains("`r`r") -and ([IO.File]::ReadAllBytes($Psd)[0] -eq 0x23))
    Assert 'settings write: backup is the original, hashes recorded' ((Test-Path -LiteralPath $W.Backup) -and (Get-FileHash -LiteralPath $W.Backup).Hash -eq $W.Before -and $W.Before -ne $W.After -and (Get-FileHash -LiteralPath $Psd).Hash -eq $W.After)
    [void](Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values @() -BackupFolder (Join-Path $Tmp 'bak'))
    Assert 'settings write: an empty list gives @()' ([IO.File]::ReadAllText($Psd) -match '(?m)^\s*KnownAdmins\s*=\s*@\(\)\r?$')
    [void](Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values @('CONTOSO\X') -BackupFolder (Join-Path $Tmp 'bak'))
    [void](Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values $null -BackupFolder (Join-Path $Tmp 'bak'))
    Assert 'settings write: $null gives @() too' ([IO.File]::ReadAllText($Psd) -match '(?m)^\s*KnownAdmins\s*=\s*@\(\)\r?$')
    [void](Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values $OrigValues -BackupFolder (Join-Path $Tmp 'bak'))
    Assert 'settings write: the shipped value written back - same value, rest of the file byte-identical' (((Import-PowerShellDataFile -LiteralPath $Psd).KnownAdmins -join '|') -eq ($OrigValues -join '|') -and (([IO.File]::ReadAllText($Psd) -replace $StripKa, '') -eq ($Orig -replace $StripKa, '')))
    $Hash = (Get-FileHash -LiteralPath $Psd).Hash
    Assert 'settings write: a value the settings refuse stops before the file is touched' ((Throws { Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values @('CONTOSO\Domain Users') -BackupFolder (Join-Path $Tmp 'bak') }) -and (Get-FileHash -LiteralPath $Psd).Hash -eq $Hash)
    Assert 'settings write: a non-ASCII value stops' ((Throws { Set-ALSettingsArray -SettingsFile $Psd -Key 'KnownAdmins' -Values @('CONTOSO\Admins' + [char]0xE9) -BackupFolder (Join-Path $Tmp 'bak') }) -and (Get-FileHash -LiteralPath $Psd).Hash -eq $Hash)
    Assert 'settings write: a missing key stops' (Throws { Set-ALSettingsArray -SettingsFile $Psd -Key 'NoSuchKey' -Values @('A\B') -BackupFolder (Join-Path $Tmp 'bak') })
    Set-Content -LiteralPath (Join-Path $Tmp 'broken.psd1') -Value '@{ KnownAdmins = @( }'
    Assert 'settings write: a file that does not parse stops' (Throws { Set-ALSettingsArray -SettingsFile (Join-Path $Tmp 'broken.psd1') -Key 'KnownAdmins' -Values @('A\B') -BackupFolder (Join-Path $Tmp 'bak') })
    Assert 'settings: 64-hex AccessChkSha256 accepted' (-not (Throws { Assert-ALSettings (With @{ AccessChkSha256 = ('A' * 64) }) 'x' } '*'))
    Assert 'settings: short AccessChkSha256 refused' (Throws { Assert-ALSettings (With @{ AccessChkSha256 = ('A' * 63) }) 'x' })
    Assert 'settings: unknown event log refused' (Throws { Assert-ALSettings (With @{ EventLogSizesMB = @{ 'System' = 10 } }) 'x' })
    foreach ($V in 0, 5000, 'abc') { Assert "settings: log size '$V' refused" (Throws { Assert-ALSettings (With @{ EventLogSizesMB = @{ 'EXE and DLL' = $V } }) 'x' }) }
    Assert 'settings: same GPO names refused' (Throws { Assert-ALSettings (With @{ EnforceGpoName = 'A' }) 'x' })
    Assert 'settings: empty GPO name refused' (Throws { Assert-ALSettings (With @{ AuditGpoName = '' }) 'x' })
    Assert 'settings: ReferenceServer FQDN accepted' (-not (Throws { Assert-ALSettings (With @{ ReferenceServer = 'dc01.contoso.com' }) 'x' } '*'))
    Assert 'settings: ReferenceServer with spaces/semicolons refused' (Throws { Assert-ALSettings (With @{ ReferenceServer = 'dc01; whoami' }) 'x' })
    Assert 'settings: ExtraReferenceServers FQDNs accepted' (-not (Throws { Assert-ALSettings (With @{ ExtraReferenceServers = @('dc22-01.contoso.com', 'DC22-02') }) 'x' } '*'))
    Assert 'settings: ExtraReferenceServers missing, $null or empty entries = not set' (-not (Throws { Assert-ALSettings (Get-BaseCfg) 'x'; Assert-ALSettings (With @{ ExtraReferenceServers = $null }) 'x'; Assert-ALSettings (With @{ ExtraReferenceServers = @('') }) 'x' } '*'))
    foreach ($S in 'dc22; whoami', 'C:\x', '-dc22', 'dc22 .contoso.com') { Assert "settings: ExtraReferenceServers '$S' refused" (Throws { Assert-ALSettings (With @{ ExtraReferenceServers = @($S) }) 'x' }) }
    Assert 'settings: the shipped settings file has EnableAppxRules = $true' ((Import-PowerShellDataFile -LiteralPath (Join-Path $Root 'scripts\AL-Settings.psd1')).EnableAppxRules -eq $true)
    Assert 'settings: the shipped settings file has ExtraReferenceServers (empty)' (@((Import-PowerShellDataFile -LiteralPath (Join-Path $Root 'scripts\AL-Settings.psd1')).ExtraReferenceServers).Count -eq 0 -and (Import-PowerShellDataFile -LiteralPath (Join-Path $Root 'scripts\AL-Settings.psd1')).ContainsKey('ExtraReferenceServers'))

    # ---- Windows Server versions and STIG items
    Assert 'OS build: AD operatingSystemVersion' ((ConvertTo-ALOsBuild '10.0 (26100)') -eq 26100)
    Assert 'OS build: Win32_OperatingSystem Version, with or without a revision' ((ConvertTo-ALOsBuild '10.0.20348') -eq 20348 -and (ConvertTo-ALOsBuild '10.0.20348.4294') -eq 20348)
    Assert 'OS build: nothing usable is 0 (empty, text, an overflowing number)' ((ConvertTo-ALOsBuild '') -eq 0 -and (ConvertTo-ALOsBuild 'Windows') -eq 0 -and (ConvertTo-ALOsBuild '10.0 (99999999999)') -eq 0)
    Assert 'OS label: 2025, 2022, 2019, 2016 named' ((Get-ALOsLabel 26100) -eq 'Windows Server 2025 (build 26100)' -and (Get-ALOsLabel 20348) -eq 'Windows Server 2022 (build 20348)' -and (Get-ALOsLabel 17763) -eq 'Windows Server 2019 (build 17763)' -and (Get-ALOsLabel 14393) -eq 'Windows Server 2016 (build 14393)')
    Assert 'OS label: other builds and 0' ((Get-ALOsLabel 25398) -eq 'Windows build 25398' -and (Get-ALOsLabel 0) -eq 'unknown version')
    $S25 = Get-ALStigItem 26100; $S22 = Get-ALStigItem 20348
    Assert 'STIG item: Server 2025 = WN25-00-000080 / V-277992 CAT II' ($S25.StigId -eq 'WN25-00-000080' -and $S25.VulnId -eq 'V-277992' -and $S25.Severity -eq 'CAT II' -and $S25.Title -eq 'Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.')
    Assert 'STIG item: Server 2022 = WN22-00-000080 / V-254245 CAT II' ($S22.StigId -eq 'WN22-00-000080' -and $S22.VulnId -eq 'V-254245' -and $S22.Severity -eq 'CAT II' -and $S22.Title -eq 'Windows Server 2022 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.')
    Assert 'STIG item: no mapping for 2019, 23H2 or an unknown build' ($null -eq (Get-ALStigItem 17763) -and $null -eq (Get-ALStigItem 25398) -and $null -eq (Get-ALStigItem 0))
    # Get-ALAdOsBuild with Get-ADComputer mocked (mock state in $Global:, see the harness rules)
    function Get-ADComputer { [CmdletBinding()] param([string]$LDAPFilter, [string[]]$Properties, [string]$Server) $Global:ALTestFilter = $LDAPFilter; if ($Global:ALTestAd -eq 'throw') { throw 'AD down' }; $Global:ALTestAd }
    $Dom = [pscustomobject]@{ PDC = 'pdc.contoso.com' }
    $Global:ALTestAd = @([pscustomobject]@{ OperatingSystemVersion = '10.0 (20348)' })
    Assert 'AD build: one account -> its build; filter by DNS name or computer name' ((Get-ALAdOsBuild 'dc22-01.contoso.com' $Dom) -eq 20348 -and $Global:ALTestFilter -eq '(|(dNSHostName=dc22-01.contoso.com)(sAMAccountName=dc22-01$))') $Global:ALTestFilter
    [void](Get-ALAdOsBuild 'dc*(x)' $Dom)
    Assert 'AD build: LDAP special characters escaped' ($Global:ALTestFilter -eq '(|(dNSHostName=dc\2a\28x\29)(sAMAccountName=dc\2a\28x\29$))') $Global:ALTestFilter
    $Global:ALTestAd = @(); $None = Get-ALAdOsBuild 'x' $Dom
    $Global:ALTestAd = @([pscustomobject]@{ OperatingSystemVersion = '10.0 (20348)' }, [pscustomobject]@{ OperatingSystemVersion = '10.0 (26100)' }); $Two = Get-ALAdOsBuild 'x' $Dom
    $Global:ALTestAd = 'throw'; $Down = Get-ALAdOsBuild 'x' $Dom
    Assert 'AD build: no account, two accounts or AD down -> 0' ($None -eq 0 -and $Two -eq 0 -and $Down -eq 0) "$None/$Two/$Down"
    Remove-Item Function:\Get-ADComputer
    Remove-Variable -Name ALTestAd, ALTestFilter -Scope Global

    # ---- Merge-ALScanResults: AaronLocker-format scan folders (written the way AaronLocker writes them), union only
    function New-Scan([string]$Name, [string[]]$Windir, [object[]]$Deny) {
        $D = Join-Path $Tmp "scan-$Name"; New-Item -Path $D -ItemType Directory -Force | Out-Null
        $Windir | Out-File -LiteralPath (Join-Path $D 'Writable_windir.txt') -Encoding ASCII
        @() | Out-File -LiteralPath (Join-Path $D 'Writable_PF.txt') -Encoding ASCII
        @() | Out-File -LiteralPath (Join-Path $D 'Writable_PF86.txt') -Encoding ASCII
        $Deny | Select-Object PublisherName, ProductName, BinaryName | ConvertTo-Csv -NoTypeInformation | Out-File -LiteralPath (Join-Path $D 'ExeDenyListData.txt') -Encoding unicode
        return [pscustomobject]@{ Server = $Name; Folder = $D }
    }
    $Ms = 'O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'; $Os = 'MICROSOFT' + [char]0xAE + ' WINDOWS' + [char]0xAE + ' OPERATING SYSTEM'
    $DenyA = @([pscustomobject]@{ PublisherName = $Ms; ProductName = $Os; BinaryName = 'CIPHER.EXE' }, [pscustomobject]@{ PublisherName = $Ms; ProductName = $Os; BinaryName = 'RUNAS.EXE' })
    $ScanA = New-Scan 'A' @('C:\Windows\Tasks\*', 'C:\Windows\Temp\*', 'C:\Windows\Temp:*') $DenyA
    $ScanSame = New-Scan 'Same' @('C:\Windows\Tasks\*', 'C:\Windows\Temp\*', 'C:\Windows\Temp:*') $DenyA
    $M0 = Merge-ALScanResults @($ScanA, $ScanSame) (Join-Path $Tmp 'merged0')
    Assert 'merge: identical scans add nothing' ($M0.Added.Count -eq 0 -and $M0.Writable.Count -eq 3 -and $M0.Deny.Count -eq 2) "added=$($M0.Added.Count)"
    Assert 'merge: output byte-identical to AaronLocker''s own files when nothing is added' (((Get-FileHash -LiteralPath (Join-Path $Tmp 'merged0\Writable_windir.txt')).Hash -eq (Get-FileHash -LiteralPath (Join-Path $ScanA.Folder 'Writable_windir.txt')).Hash) -and ((Get-FileHash -LiteralPath (Join-Path $Tmp 'merged0\Writable_PF.txt')).Hash -eq (Get-FileHash -LiteralPath (Join-Path $ScanA.Folder 'Writable_PF.txt')).Hash) -and ((Get-FileHash -LiteralPath (Join-Path $Tmp 'merged0\ExeDenyListData.txt')).Hash -eq (Get-FileHash -LiteralPath (Join-Path $ScanA.Folder 'ExeDenyListData.txt')).Hash))
    $DenyB = @([pscustomobject]@{ PublisherName = $Ms; ProductName = $Os.ToLower(); BinaryName = 'cipher.exe' }, [pscustomobject]@{ PublisherName = $Ms; ProductName = $Os; BinaryName = 'MSHTA.EXE' })
    $ScanB = New-Scan 'dc22' @('c:\windows\tasks\*', 'C:\Windows\System32\spool\drivers\color\*', '', 'C:\Windows\Temp\*') $DenyB
    $M1 = Merge-ALScanResults @($ScanA, $ScanB) (Join-Path $Tmp 'merged1')
    $AddedText = @($M1.Added | ForEach-Object { "$($_.Server)|$($_.File)|$($_.Entry)" })
    Assert 'merge: the second server adds only what is new (case-insensitive), blank lines ignored' ($AddedText.Count -eq 2 -and $AddedText -contains 'dc22|Writable_windir.txt|C:\Windows\System32\spool\drivers\color\*' -and $AddedText -contains "dc22|ExeDenyListData.txt|MSHTA.EXE ($Os)") ($AddedText -join '; ')
    $W1 = [IO.File]::ReadAllLines((Join-Path $Tmp 'merged1\Writable_windir.txt'))
    Assert 'merge: union in order, the first server''s spelling kept' (($W1 -join '|') -eq 'C:\Windows\Tasks\*|C:\Windows\Temp\*|C:\Windows\Temp:*|C:\Windows\System32\spool\drivers\color\*') ($W1 -join '|')
    $DenyBytes = [IO.File]::ReadAllBytes((Join-Path $Tmp 'merged1\ExeDenyListData.txt'))
    $DenyRead = @(Get-Content -LiteralPath (Join-Path $Tmp 'merged1\ExeDenyListData.txt') | ConvertFrom-Csv)
    Assert 'merge: deny list is UTF-16 LE with BOM, reads back like AaronLocker reads it (3 tools, (R) intact)' ($DenyBytes[0] -eq 0xFF -and $DenyBytes[1] -eq 0xFE -and $DenyRead.Count -eq 3 -and (@($DenyRead | Where-Object { $_.ProductName -eq $Os }).Count -eq 3) -and (($DenyRead | ForEach-Object BinaryName) -join ',') -eq 'CIPHER.EXE,RUNAS.EXE,MSHTA.EXE') (($DenyRead | ForEach-Object BinaryName) -join ',')
    Assert 'merge: the merged scan files are ASCII text with CRLF' ([IO.File]::ReadAllText((Join-Path $Tmp 'merged1\Writable_windir.txt')).EndsWith("color\*`r`n") -and [IO.File]::ReadAllBytes((Join-Path $Tmp 'merged1\Writable_PF.txt')).Length -eq 0)
    $ScanEmpty = New-Scan 'empty' @() @()
    $M2 = Merge-ALScanResults @($ScanA, $ScanEmpty) (Join-Path $Tmp 'merged2')
    Assert 'merge: a server with an empty scan and an empty deny list adds nothing' ($M2.Added.Count -eq 0 -and $M2.Deny.Count -eq 2)
    Remove-Item -LiteralPath (Join-Path $ScanEmpty.Folder 'Writable_PF86.txt')
    Assert 'merge: a missing scan file stops' (Throws { Merge-ALScanResults @($ScanA, $ScanEmpty) (Join-Path $Tmp 'merged3') } 'STOP:*Writable_PF86.txt is missing*empty*')
    Set-Content -LiteralPath (Join-Path $ScanB.Folder 'ExeDenyListData.txt') -Value 'Name,Path', 'x,y' -Encoding Unicode
    Assert 'merge: a file that is not a deny list stops' (Throws { Merge-ALScanResults @($ScanA, $ScanB) (Join-Path $Tmp 'merged4') } 'STOP:*not an AaronLocker deny list*')

    # ---- ConvertTo-ALAaronLockerPath / Get-ALMissingScanEntries
    $Roots = [pscustomobject]@{ Windir = 'C:\Windows'; ProgramFiles = 'C:\Program Files'; ProgramFilesX86 = 'C:\Program Files (x86)' }
    $Cases = [ordered]@{ 'C:\Windows\System32\Tasks\*' = '%SYSTEM32%\Tasks\*'; 'C:\Windows\SysWOW64\Tasks\*' = '%SYSTEM32%\Tasks\*'; 'c:\windows\Temp:*' = '%WINDIR%\Temp:*'; 'C:\Program Files (x86)\App\x\*' = '%PROGRAMFILES%\App\x\*'; 'C:\Program Files\App\*' = '%PROGRAMFILES%\App\*'; 'D:\Windows\Tasks\*' = 'D:\Windows\Tasks\*'; 'C:\WindowsApps\x\*' = 'C:\WindowsApps\x\*' }
    $Bad = @(foreach ($K in $Cases.Keys) { $Got = ConvertTo-ALAaronLockerPath $K $Roots; if ($Got -ne $Cases[$K]) { "$K -> $Got" } })
    Assert 'AaronLocker path: System32/SysWOW64/Windows/Program Files mapped like AaronLocker; other paths unchanged' ($Bad.Count -eq 0) ($Bad -join '; ')
    Assert 'AaronLocker path: no Program Files (x86) on the server' ((ConvertTo-ALAaronLockerPath 'C:\Program Files\App\*' ([pscustomobject]@{ Windir = 'C:\Windows'; ProgramFiles = 'C:\Program Files'; ProgramFilesX86 = $null })) -eq '%PROGRAMFILES%\App\*')
    $Pol2 = [xml]('<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="1" Name="w" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions><Exceptions><FilePathCondition Path="%WINDIR%\tasks\*" /><FilePathCondition Path="%WINDIR%\temp\*" /><FilePathCondition Path="%WINDIR%\temp:*" /><FilePublisherCondition PublisherName="' + $Ms + '" ProductName="' + $Os + '" BinaryName="CIPHER.EXE"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition><FilePublisherCondition PublisherName="' + $Ms + '" ProductName="' + $Os + '" BinaryName="RUNAS.EXE"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Exceptions></FilePathRule></RuleCollection></AppLockerPolicy>')
    Assert 'missing entries: a policy built from the scan carries all of it' (@(Get-ALMissingScanEntries $Pol2 $M0 $Roots).Count -eq 0) ((Get-ALMissingScanEntries $Pol2 $M0 $Roots) -join '; ')
    $Miss = @(Get-ALMissingScanEntries $Pol2 $M1 $Roots)
    Assert 'missing entries: the folder and the tool another server added are reported' ($Miss.Count -eq 2 -and @($Miss | Where-Object { $_ -like 'user-writable folder C:\Windows\System32\spool\drivers\color\* (expected exception %SYSTEM32%\spool\drivers\color\*)' }).Count -eq 1 -and @($Miss | Where-Object { $_ -like 'deny-list entry MSHTA.EXE*' }).Count -eq 1) ($Miss -join '; ')
    $Pol3 = [xml]($Pol2.OuterXml -replace 'RuleCollection Type="Exe"', 'RuleCollection Type="Script"')
    Assert 'missing entries: exceptions outside the EXE collection do not count' (@(Get-ALMissingScanEntries $Pol3 $M0 $Roots).Count -eq 5)

    # ---- Get-ALBuildFolder: works after the folder tree was moved (old latest.txt held a full path)
    $Out = Join-Path $Tmp 'Outputs\default'
    foreach ($B in '20260101-000000', '20260102-000000') { New-Item -Path (Join-Path $Out $B) -ItemType Directory -Force | Out-Null; Set-Content -LiteralPath (Join-Path $Out "$B\AppLockerRules-x-Audit.xml") -Value '<x/>' }
    $Cfg = @{ OutRoot = $Out }
    Set-Content -LiteralPath (Join-Path $Out 'latest.txt') -Value 'C:\WDAC\AppLocker\Outputs\default\20260101-000000'
    Assert 'build folder: old absolute latest.txt from a moved tree resolves here' ((Get-ALBuildFolder $Cfg) -eq (Join-Path $Out '20260101-000000'))
    Set-Content -LiteralPath (Join-Path $Out 'latest.txt') -Value '20260101-000000'
    Assert 'build folder: relative latest.txt' ((Get-ALBuildFolder $Cfg) -eq (Join-Path $Out '20260101-000000'))
    Set-Content -LiteralPath (Join-Path $Out 'latest.txt') -Value '..\..\..\Windows'
    Assert 'build folder: latest.txt cannot point outside Outputs (falls back to the newest build)' ((Get-ALBuildFolder $Cfg) -eq (Join-Path $Out '20260102-000000'))
    Remove-Item -LiteralPath (Join-Path $Out 'latest.txt')
    Assert 'build folder: no latest.txt -> newest build' ((Get-ALBuildFolder $Cfg) -eq (Join-Path $Out '20260102-000000'))
    Assert 'build folder: explicit -OutputFolder' ((Get-ALBuildFolder $Cfg (Join-Path $Out '20260101-000000')) -eq (Join-Path $Out '20260101-000000'))
    Assert 'build folder: missing -OutputFolder stops' (Throws { Get-ALBuildFolder $Cfg (Join-Path $Tmp 'nope') })
    Assert 'build folder: no build at all stops' (Throws { Get-ALBuildFolder @{ OutRoot = (Join-Path $Tmp 'empty') } })

    # ---- Test-ALAccessChk / Get-ALPeMachine
    $Acc = Join-Path $Root 'AaronLocker\AaronLocker\AccessChk.exe'
    $Pin = (Import-PowerShellDataFile -LiteralPath (Join-Path $Root 'scripts\AL-Settings.psd1')).AccessChkSha256
    Assert 'AccessChk: shipped file passes with the pinned hash' (Test-ALAccessChk $Acc $Pin).Ok ((Test-ALAccessChk $Acc $Pin).Detail)
    Assert 'AccessChk: passes unpinned' (Test-ALAccessChk $Acc '').Ok
    Assert 'AccessChk: wrong pinned hash refused' (-not (Test-ALAccessChk $Acc ('0' * 64)).Ok)
    Assert 'AccessChk: missing file refused' (-not (Test-ALAccessChk (Join-Path $Tmp 'AccessChk.exe') '').Ok)
    $Cmd = Join-Path $env:windir 'System32\cmd.exe'
    Assert 'AccessChk: another Microsoft-signed program is refused (product name)' (-not (Test-ALAccessChk $Cmd '').Ok) ((Test-ALAccessChk $Cmd '').Detail)
    Assert 'PE machine: System32\cmd.exe is x64' ((Get-ALPeMachine $Cmd) -eq 0x8664)
    $Wow = Join-Path $env:windir 'SysWOW64\cmd.exe'
    if (Test-Path -LiteralPath $Wow) { Assert 'PE machine: SysWOW64\cmd.exe is x86' ((Get-ALPeMachine $Wow) -eq 0x14C) }
    Set-Content -LiteralPath (Join-Path $Tmp 'not.exe') -Value 'text'
    Assert 'PE machine: a text file is 0' ((Get-ALPeMachine (Join-Path $Tmp 'not.exe')) -eq 0)

    # ---- $ALWritableCheck on crafted permissions (run locally; KnownAdmins makes the current user count as an administrator)
    $Me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $Dir = Join-Path $Tmp 'Admin'; New-Item -Path $Dir -ItemType Directory | Out-Null
    $Acl = New-Object System.Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true, $false)
    foreach ($S in 'S-1-5-18', 'S-1-5-32-544', $Me) { $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $S), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))) }
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-11'), 'ReadAndExecute', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
    $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-3-0'), 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow')))
    Set-Acl -LiteralPath $Dir -AclObject $Acl
    Set-Content -LiteralPath (Join-Path $Dir 'tool.ps1') -Value '# test'
    $Res = @(& $ALWritableCheck @("$Dir\*") @($Me))
    Assert 'writable check: admin-only folder (read for Authenticated Users, CREATOR OWNER) is clean' ($Res.Count -eq 0) ($Res -join '; ')
    $FileAcl = Get-Acl -LiteralPath (Join-Path $Dir 'tool.ps1')
    $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545'), 'Modify', 'Allow')))
    Set-Acl -LiteralPath (Join-Path $Dir 'tool.ps1') -AclObject $FileAcl
    $Res = @(& $ALWritableCheck @("$Dir\*") @($Me))
    Assert 'writable check: a FILE that Users may modify is found' (@($Res | Where-Object { $_ -like "WRITABLE|*tool.ps1|*S-1-5-32-545*" }).Count -eq 1) ($Res -join '; ')
    $Res = @(& $ALWritableCheck @("$Dir\*") @($Me, 'S-1-5-32-545'))
    Assert 'writable check: KnownAdmins suppresses that group' ($Res.Count -eq 0) ($Res -join '; ')
    $Sub = Join-Path $Dir 'sub'; New-Item -Path $Sub -ItemType Directory | Out-Null
    $SubAcl = Get-Acl -LiteralPath $Sub
    $SubAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier 'S-1-5-11'), 'Modify', 'ObjectInherit', 'InheritOnly', 'Allow')))
    Set-Acl -LiteralPath $Sub -AclObject $SubAcl
    $Res = @(& $ALWritableCheck @("$Dir\*") @($Me, 'S-1-5-32-545'))
    Assert 'writable check: an inherit-only entry for future files is found' (@($Res | Where-Object { $_ -like "WRITABLE|*\sub|*S-1-5-11*" }).Count -eq 1) ($Res -join '; ')
    $Res = @(& $ALWritableCheck @((Join-Path $Tmp 'Missing\*')) @('NOSUCHDOMAIN\nobody'))
    Assert 'writable check: missing path and unresolvable KnownAdmins are reported' ((@($Res | Where-Object { $_ -like 'NOTFOUND|*' }).Count -eq 1) -and (@($Res | Where-Object { $_ -eq 'UNRESOLVED|NOSUCHDOMAIN\nobody' }).Count -eq 1)) ($Res -join '; ')

    $Res = @(& $ALWritableCheck @("$Dir\*") @($Me))
    Assert 'writable check: a file is marked F, a folder D' ((@($Res | Where-Object { $_ -like 'WRITABLE|*tool.ps1|*|F' }).Count -eq 1) -and (@($Res | Where-Object { $_ -like 'WRITABLE|*\sub|*|D' }).Count -eq 1)) ($Res -join '; ')

    # ---- Test-ALPathUnder / ConvertTo-ALComparablePath / Test-ALCovered
    Assert 'path under: folder itself' (Test-ALPathUnder 'C:\Admin' 'C:\Admin\*')
    Assert 'path under: file inside, any case' (Test-ALPathUnder 'c:\admin\Tools\x.exe' 'C:\Admin\*')
    Assert 'path under: sibling with the same prefix is not inside' (-not (Test-ALPathUnder 'C:\Administrator\x.exe' 'C:\Admin\*'))
    Assert 'path under: %OSDRIVE% equals C:' (Test-ALPathUnder 'C:\Admin\x.exe' '%OSDRIVE%\ADMIN\*')
    Assert 'covered: folder exception covers the folder and everything in it' ((Test-ALCovered 'C:\Admin\Shared' @('C:\Admin\Shared\*')) -and (Test-ALCovered 'c:\admin\shared\a\b.exe' @('C:\Admin\Shared\*')))
    Assert 'covered: file exception covers exactly that file' ((Test-ALCovered 'C:\Admin\tool.ps1' @('C:\Admin\tool.ps1')) -and -not (Test-ALCovered 'C:\Admin\tool.ps1x' @('C:\Admin\tool.ps1')))
    Assert 'covered: nothing else' (-not (Test-ALCovered 'C:\Admin\other.exe' @('C:\Admin\Shared\*', 'C:\Admin\tool.ps1')))

    # ---- Get-ALExtraPathPlan: the build never stops and never allows what a non-admin can change
    function F([string]$Kind, [string]$Path, [bool]$Folder, [string]$Computer = 'DC01') { [pscustomobject]@{ Kind = $Kind; Path = $Path; Account = 'BUILTIN\Users (S-1-5-32-545)'; IsFolder = $Folder; Computer = $Computer } }
    $P0 = Get-ALExtraPathPlan @('C:\Admin\*') @()
    Assert 'plan: admin-only everywhere -> allowed, no exceptions' (($P0.Keep -join ',') -eq 'C:\Admin\*' -and $P0.Drop.Count -eq 0 -and $P0.Exceptions.Count -eq 0)
    $P1 = Get-ALExtraPathPlan @('C:\Admin\*') @((F 'WRITABLE' 'C:\Admin' $true 'DC02'))
    Assert 'plan: top folder writable on ONE server -> left out, reason names the server' ($P1.Keep.Count -eq 0 -and $P1.Drop.Count -eq 1 -and $P1.Drop[0].Reason -like '*DC02*')
    $P2 = Get-ALExtraPathPlan @('C:\Admin\*') @((F 'WRITABLE' 'C:\Admin\Shared\x.ps1' $false), (F 'WRITABLE' 'C:\Admin\Shared' $true 'DC02'), (F 'WRITABLE' 'C:\Admin\tool.ps1' $false), (F 'UNREADABLE' 'C:\Admin\Odd' $true))
    Assert 'plan: writable items inside -> allowed with exceptions (parent folder covers its files)' (($P2.Keep -join ',') -eq 'C:\Admin\*' -and (($P2.Exceptions['C:\Admin\*'] | Sort-Object) -join ',') -eq 'C:\Admin\Odd\*,C:\Admin\Shared\*,C:\Admin\tool.ps1') (($P2.Exceptions['C:\Admin\*']) -join ',')
    $P3 = Get-ALExtraPathPlan @('C:\Admin\*', 'D:\Tools\*') @((F 'NOTFOUND' 'C:\Admin\*' $false), (F 'WRITABLE' 'D:\Tools' $true))
    Assert 'plan: missing folder still allowed; writable second entry left out' ((($P3.Keep -join ',') -eq 'C:\Admin\*') -and $P3.Drop[0].Entry -eq 'D:\Tools\*')

    # ---- Add-ALPathExceptions / Get-ALRuleExceptions on AppLocker XML
    $Pol = Join-Path $Tmp 'pol.xml'
    Set-Content -LiteralPath $Pol -Encoding Unicode -Value '<?xml version="1.0" encoding="utf-16"?><AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="a" Name="Additional allowed path: C:\Admin\*" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="C:\Admin\*" /></Conditions></FilePathRule><FilePathRule Id="b" Name="win" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Script" EnforcementMode="Enabled"><FilePathRule Id="c" Name="Additional allowed path: C:\Admin\*" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="C:\Admin\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
    $Map = @{ 'C:\Admin\*' = @('C:\Admin\Shared\*', 'C:\Admin\tool.ps1') }
    $N1 = Add-ALPathExceptions $Pol $Map
    $N2 = Add-ALPathExceptions $Pol $Map
    $X = New-Object System.Xml.XmlDocument; $X.Load($Pol)
    $Exe = Get-ALRuleExceptions $X 'C:\Admin\*'
    Assert 'exceptions: added to the Exe and Script rules (2), idempotent' ($N1 -eq 2 -and $N2 -eq 2 -and @($X.SelectNodes('//FilePathRule[@Id="c"]/Exceptions/FilePathCondition')).Count -eq 2) "first=$N1 second=$N2"
    Assert 'exceptions: read back from the policy' ((@($Exe | Sort-Object) -join ',') -eq 'C:\Admin\Shared\*,C:\Admin\tool.ps1')
    Assert 'exceptions: other rules untouched, rule counts unchanged' (@($X.SelectNodes('//FilePathRule[@Id="b"]/Exceptions')).Count -eq 0 -and (Get-ALPolicySummary $X) -eq 'Exe=Enabled(2), Script=Enabled(1)') (Get-ALPolicySummary $X)
    Assert 'exceptions: no rule for an entry -> $null (left out by the build)' ($null -eq (Get-ALRuleExceptions $X 'D:\Tools\*'))
    $X2 = [xml]'<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="a" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%OSDRIVE%\ADMIN\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
    $Empty = Get-ALRuleExceptions $X2 'C:\Admin\*'
    Assert 'exceptions: rule without exceptions -> empty list, not $null (%OSDRIVE% matched)' ($null -ne $Empty -and @($Empty).Count -eq 0)

    # ---- Get-ALPolicyMismatch: only the collections this baseline manages are judged (MECM managed installer merges in others)
    $Ours = '<RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="1" Name="x" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions /></FilePublisherRule></RuleCollection><RuleCollection Type="Exe" EnforcementMode="Enabled" /><RuleCollection Type="Msi" EnforcementMode="Enabled" /><RuleCollection Type="Script" EnforcementMode="Enabled" />'
    $Mi = '<RuleCollection Type="Dll" EnforcementMode="AuditOnly"><FilePathRule Id="2" Name="Benign DENY Rule" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%OSDRIVE%\ThisWillBeBlocked.dll" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="ManagedInstaller" EnforcementMode="AuditOnly"><FilePathRule Id="3" Name="CCMEXEC" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\CCM\CcmExec.exe" /></Conditions></FilePathRule></RuleCollection>'
    Assert 'mismatch: our Enforce policy alone is as expected' (@(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`">$Ours<RuleCollection Type=`"Dll`" EnforcementMode=`"NotConfigured`" /></AppLockerPolicy>") 'Enforce' $false).Count -eq 0)
    Assert 'mismatch: merged with the MECM managed installer (Dll AuditOnly + ManagedInstaller) is still as expected' (@(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`">$Ours$Mi</AppLockerPolicy>") 'Enforce' $false).Count -eq 0)
    $M1 = @(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`">$($Ours -replace 'Type="Exe" EnforcementMode="Enabled"', 'Type="Exe" EnforcementMode="AuditOnly"')</AppLockerPolicy>") 'Enforce' $false)
    Assert 'mismatch: Exe AuditOnly while Enforce is expected is reported' ($M1.Count -eq 1 -and $M1[0] -like 'Exe=AuditOnly*') ($M1 -join '; ')
    Assert 'mismatch: a missing collection is reported' (@(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`"><RuleCollection Type=`"Exe`" EnforcementMode=`"AuditOnly`" /></AppLockerPolicy>") 'Audit' $false).Count -eq 3)
    Assert 'mismatch: with DLL rules ON, an audit-only DLL collection in Enforce is reported' (@(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`">$Ours$Mi</AppLockerPolicy>") 'Enforce' $true).Count -eq 1)

    # ---- Argument binding used by Invoke-ALWritableCheck (two arrays, either may be empty or hold one item)
    $Bind = { param([string[]]$P, [string[]]$K) "$(@($P).Count)|$(@($K | Where-Object { $_ }).Count)" }
    Assert 'binding: one path, no KnownAdmins' ((Invoke-Command -ScriptBlock $Bind -ArgumentList @('C:\Admin\*'), @()) -eq '1|0')
    Assert 'binding: two paths, one KnownAdmins' ((Invoke-Command -ScriptBlock $Bind -ArgumentList @('a', 'b'), @('S-1-5-32-544')) -eq '2|1')

    # ---- Merge-ALExtensionNames: adds, sorts, idempotent
    $Cse = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]', '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $One = Merge-ALExtensionNames '' $Cse
    Assert 'CSE merge: both extensions present' (($One -like '*{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72*') -and ($One -like '*{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0*'))
    Assert 'CSE merge: idempotent' ((Merge-ALExtensionNames $One $Cse) -eq $One)

    # ---- Confirm-ALChange: -NoConfirm, non-interactive stop, Y / N / three wrong answers (Read-Host and the session test mocked)
    Assert 'confirm: -NoConfirm continues' (-not (Throws { Confirm-ALChange -Action 't' -NoConfirm 6>$null } '*'))
    function Test-ALInteractive { $false }
    Assert 'confirm: non-interactive without -NoConfirm stops' (Throws { Confirm-ALChange -Action 't' 6>$null } 'STOP:*non-interactive*')
    function Test-ALInteractive { $true }
    $script:Answers = New-Object System.Collections.Queue
    function Read-Host { $script:Answers.Dequeue() }
    $script:Answers.Enqueue('y'); Assert 'confirm: Y continues' (-not (Throws { Confirm-ALChange -Action 't' 6>$null } '*'))
    $script:Answers.Enqueue('No'); Assert 'confirm: N stops' (Throws { Confirm-ALChange -Action 't' 6>$null } 'STOP: not confirmed*')
    'x', 'maybe', '' | ForEach-Object { $script:Answers.Enqueue($_) }; Assert 'confirm: three wrong answers stop' (Throws { Confirm-ALChange -Action 't' 6>$null } 'STOP: not confirmed*')
    'x', 'YES' | ForEach-Object { $script:Answers.Enqueue($_) }; Assert 'confirm: wrong answer then YES continues' (-not (Throws { Confirm-ALChange -Action 't' 6>$null } '*'))
    Remove-Item Function:\Read-Host, Function:\Test-ALInteractive

    # ---- New-ALDeployXml: refuses a ManagedInstaller collection and a mode mismatch
    $Xml = Join-Path $Tmp 'p.xml'
    Set-Content -LiteralPath $Xml -Encoding Unicode -Value '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="1" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule><RuleCollectionExtensions><ThresholdExtensions><Services EnforcementMode="NotConfigured" /></ThresholdExtensions><RedstoneExtensions><SystemApps Allow="NotConfigured" /></RedstoneExtensions></RuleCollectionExtensions></RuleCollection><RuleCollection Type="Dll" EnforcementMode="Enabled"><FilePathRule Id="2" Name="d" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'
    $Sum = New-ALDeployXml -SourceXml $Xml -Mode Enforce -DllRules $false -OutFile (Join-Path $Tmp 'd.xml')
    Assert 'deploy XML: DLL emptied + NotConfigured, extensions not counted as rules' ($Sum -eq 'Dll=NotConfigured(0), Exe=Enabled(1)') $Sum
    $Xml2 = Join-Path $Tmp 'p2.xml'
    Set-Content -LiteralPath $Xml2 -Encoding Unicode -Value '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="1" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Appx" EnforcementMode="AuditOnly"><FilePublisherRule Id="2" Name="a" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection></AppLockerPolicy>'
    Assert 'deploy XML: the Appx collection is kept by default' ((New-ALDeployXml -SourceXml $Xml2 -Mode Audit -DllRules $false -OutFile (Join-Path $Tmp 'g.xml')) -eq 'Appx=AuditOnly(1), Exe=AuditOnly(1)')
    Assert 'deploy XML: EnableAppxRules off empties the Appx collection (NotConfigured)' ((New-ALDeployXml -SourceXml $Xml2 -Mode Audit -DllRules $false -OutFile (Join-Path $Tmp 'h.xml') -AppxRules $false) -eq 'Appx=NotConfigured(0), Exe=AuditOnly(1)')
    Assert 'managed collections / expected mode with Appx off' (((Get-ALManagedCollections $false $false) -join ',') -eq 'Exe,Msi,Script' -and (Get-ALExpectedMode 'Enforce' 'Appx' $false $false) -eq 'NotConfigured' -and (Get-ALExpectedMode 'Enforce' 'Appx' $false $true) -eq 'Enabled' -and ((Get-ALManagedCollections $true) -join ',') -eq 'Exe,Msi,Script,Appx,Dll')
    Assert 'mismatch: with Appx off, an Appx collection is neither judged nor required' (@(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`"><RuleCollection Type=`"Exe`" EnforcementMode=`"Enabled`" /><RuleCollection Type=`"Msi`" EnforcementMode=`"Enabled`" /><RuleCollection Type=`"Script`" EnforcementMode=`"Enabled`" /></AppLockerPolicy>") 'Enforce' $false $false).Count -eq 0 -and @(Get-ALPolicyMismatch ([xml]"<AppLockerPolicy Version=`"1`"><RuleCollection Type=`"Exe`" EnforcementMode=`"Enabled`" /><RuleCollection Type=`"Msi`" EnforcementMode=`"Enabled`" /><RuleCollection Type=`"Script`" EnforcementMode=`"Enabled`" /></AppLockerPolicy>") 'Enforce' $false).Count -eq 1)
    Assert 'deploy XML: Enforce source refused for Audit' (Throws { New-ALDeployXml -SourceXml $Xml -Mode Audit -DllRules $false -OutFile (Join-Path $Tmp 'e.xml') })
    (Get-Content -LiteralPath $Xml -Raw) -replace 'Type="Dll"', 'Type="ManagedInstaller"' | Set-Content -LiteralPath $Xml -Encoding Unicode
    Assert 'deploy XML: ManagedInstaller collection refused' (Throws { New-ALDeployXml -SourceXml $Xml -Mode Enforce -DllRules $false -OutFile (Join-Path $Tmp 'f.xml') })
    # ---- this computer vs a server: Test-ALLocalComputer / Invoke-ALOn (the toolkit run on a DC itself)
    $CsInfo = Get-CimInstance Win32_ComputerSystem
    $MyFqdn = "$($CsInfo.DNSHostName).$($CsInfo.Domain)"
    Assert 'local computer: own name, FQDN, localhost, 127.0.0.1, trailing dot' ((Test-ALLocalComputer $env:COMPUTERNAME) -and (Test-ALLocalComputer $env:COMPUTERNAME.ToLower()) -and (Test-ALLocalComputer $MyFqdn) -and (Test-ALLocalComputer "$MyFqdn.") -and (Test-ALLocalComputer 'localhost') -and (Test-ALLocalComputer '127.0.0.1'))
    Assert 'local computer: another name, an empty name, another address are not local' (-not (Test-ALLocalComputer 'dc01.contoso.com') -and -not (Test-ALLocalComputer '') -and -not (Test-ALLocalComputer '203.0.113.7') -and -not (Test-ALLocalComputer "x$env:COMPUTERNAME"))
    Assert 'invoke on: this computer runs the block in-process with positional arguments' ((Invoke-ALOn 'localhost' { param($A, $B) "$A|$($B -join ',')|$env:COMPUTERNAME" } ('x', @('y', 'z'))) -eq "x|y,z|$env:COMPUTERNAME")
    Assert 'invoke on: a single array argument stays one parameter with (, $Array)' ((Invoke-ALOn $env:COMPUTERNAME { param([string[]]$P) $P.Count } (, @('p', 'q'))) -eq 2)
    Assert 'invoke on: no arguments, and an empty array argument' (((Invoke-ALOn 'localhost' { 'ran' }) -eq 'ran') -and ((Invoke-ALOn 'localhost' { param([string[]]$P, [string[]]$K) "$(@($P).Count)|$(@($K | Where-Object { $_ }).Count)" } (@('a', 'b'), @())) -eq '2|0'))
    Assert 'invoke on: a hashtable argument' ((Invoke-ALOn 'localhost' { param($Sizes) $Sizes['EXE and DLL'] } (, @{ 'EXE and DLL' = 100 })) -eq 100)
    Assert 'writable check: this computer is checked in-process (no WinRM)' (@(Invoke-ALWritableCheck -Paths @("$Dir\*") -Cfg @{ KnownAdmins = @($Me) } -ComputerName 'localhost') | Where-Object { $_.Kind -eq 'WRITABLE' -and $_.Computer -eq 'localhost' }).Count -ge 1

    # ---- gpresult: the text report, the RSoP XML, the verdict per mode, the result rows, the Win32 messages, the raw-output file
    $GpText = @"

Microsoft (R) Windows (R) Operating System Group Policy Result tool v2.0
Created on 10/27/2026 at 2:04:19 PM

RSOP data for  on DC25-1 : Logging Mode
----------------------------------------

COMPUTER SETTINGS
------------------
    CN=DC25-1,OU=Domain Controllers,DC=skynet-home,DC=local
    Last time Group Policy was applied: 10/27/2026 at 2:01:37 PM
    Group Policy was applied from:      DC25-1.skynet-home.local
    Domain Name:                        SKYNET

    Applied Group Policy Objects
    -----------------------------
        Default Domain Controllers Policy
        E
        Default Domain Policy

    The following GPOs were not applied because they were filtered out
    -------------------------------------------------------------------
        A
            Filtering:  Disabled (Link)

        Local Group Policy
            Filtering:  Not Applied (Empty)

    The computer is a part of the following security groups
    -------------------------------------------------------
        BUILTIN\Administrators
        Everyone

USER SETTINGS
--------------
    Applied Group Policy Objects
    -----------------------------
        N/A
"@
    $GpT = ConvertFrom-ALGpResultText $GpText
    Assert 'gpresult text: applied GPOs in order' (($GpT.Applied -join '|') -eq 'Default Domain Controllers Policy|E|Default Domain Policy') ($GpT.Applied -join '|')
    Assert 'gpresult text: filtered-out GPOs with their reason' ($GpT.NotApplied.Count -eq 2 -and $GpT.NotApplied[0].Name -eq 'A' -and $GpT.NotApplied[0].Reason -eq 'Disabled (Link)' -and $GpT.NotApplied[1].Name -eq 'Local Group Policy' -and $GpT.NotApplied[1].Reason -eq 'Not Applied (Empty)')
    Assert 'gpresult text: last applied / applied from' ($GpT.LastApplied -eq '10/27/2026 at 2:01:37 PM' -and $GpT.AppliedFrom -eq 'DC25-1.skynet-home.local')
    $GpNone = ConvertFrom-ALGpResultText "COMPUTER SETTINGS`r`n------------------`r`n    Applied Group Policy Objects`r`n    -----------------------------`r`n        N/A`r`n`r`n    The following GPOs were not applied because they were filtered out`r`n    -------------------------------------------------------------------`r`n        Local Group Policy`r`n            Filtering:  Not Applied (Empty)`r`n"
    Assert 'gpresult text: N/A means nothing applied' ($GpNone.Applied.Count -eq 0 -and $GpNone.NotApplied.Count -eq 1)
    Assert 'gpresult text: another language or no report gives nothing' ((ConvertFrom-ALGpResultText 'COMPUTEREINSTELLUNGEN').Applied.Count -eq 0 -and (ConvertFrom-ALGpResultText '').NotApplied.Count -eq 0)
    $Rsop = { param($AuditLink, $EnforceDenied, $SecurityError) @"
<?xml version="1.0" encoding="utf-16"?>
<Rsop xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
  <ReadTime>2026-10-27T21:04:20.8732162Z</ReadTime>
  <ComputerResults>
    <Name>SKYNET\DC25-1$</Name>
    <GPO><Name>Default Domain Controllers Policy</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{6AC1786C-016F-11D2-945F-00C04fB984F9}</Identifier><Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">skynet-home.local</Domain></Path><VersionDirectory>1</VersionDirectory><VersionSysvol>1</VersionSysvol><Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied><Link><SOMPath>skynet-home.local/Domain Controllers</SOMPath><SOMOrder>3</SOMOrder><AppliedOrder>3</AppliedOrder><LinkOrder>5</LinkOrder><Enabled>true</Enabled><NoOverride>false</NoOverride></Link><ExtensionName>Security</ExtensionName></GPO>
    <GPO><Name>Local Group Policy</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">LocalGPO</Identifier></Path><VersionDirectory>0</VersionDirectory><VersionSysvol>0</VersionSysvol><Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied><Link><SOMPath>Local</SOMPath><SOMOrder>1</SOMOrder><AppliedOrder>0</AppliedOrder><LinkOrder>1</LinkOrder><Enabled>true</Enabled><NoOverride>false</NoOverride></Link></GPO>
    <GPO><Name>E</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{815454EA-3B6C-4FE3-9F58-4248F45B450E}</Identifier><Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">skynet-home.local</Domain></Path><VersionDirectory>2</VersionDirectory><VersionSysvol>2</VersionSysvol><Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>$EnforceDenied</AccessDenied><Link><SOMPath>skynet-home.local/Domain Controllers</SOMPath><SOMOrder>1</SOMOrder><AppliedOrder>$(if ($EnforceDenied -eq 'true') { 0 } else { 2 })</AppliedOrder><LinkOrder>3</LinkOrder><Enabled>true</Enabled><NoOverride>false</NoOverride></Link><ExtensionName>Security</ExtensionName><ExtensionName>Registry</ExtensionName></GPO>
    <GPO><Name>Default Domain Policy</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier><Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">skynet-home.local</Domain></Path><VersionDirectory>1</VersionDirectory><VersionSysvol>1</VersionSysvol><Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied><Link><SOMPath>skynet-home.local</SOMPath><SOMOrder>1</SOMOrder><AppliedOrder>1</AppliedOrder><LinkOrder>2</LinkOrder><Enabled>true</Enabled><NoOverride>false</NoOverride></Link><ExtensionName>Security</ExtensionName></GPO>
    <GPO><Name>A</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{90611251-4E0A-441B-8967-84BBA320FDA5}</Identifier><Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">skynet-home.local</Domain></Path><VersionDirectory>2</VersionDirectory><VersionSysvol>2</VersionSysvol><Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied><Link><SOMPath>skynet-home.local/Domain Controllers</SOMPath><SOMOrder>2</SOMOrder><AppliedOrder>$(if ($AuditLink -eq 'true') { 4 } else { 0 })</AppliedOrder><LinkOrder>4</LinkOrder><Enabled>$AuditLink</Enabled><NoOverride>false</NoOverride></Link><ExtensionName>Security</ExtensionName><ExtensionName>Registry</ExtensionName></GPO>
    <ExtensionStatus><Name>Group Policy Infrastructure</Name><Identifier>{00000000-0000-0000-0000-000000000000}</Identifier><BeginTime>2026-10-27T21:01:37</BeginTime><EndTime>2026-10-27T21:01:37</EndTime><LoggingStatus>Complete</LoggingStatus><Error>0</Error></ExtensionStatus>
    <ExtensionStatus><Name>Registry</Name><Identifier>{35378EAC-683F-11D2-A89A-00C04FBBCFA2}</Identifier><BeginTime>2026-10-26T18:36:18</BeginTime><EndTime>2026-10-26T18:36:18</EndTime><LoggingStatus>Complete</LoggingStatus><Error>0</Error></ExtensionStatus>
    <ExtensionStatus><Name>Security</Name><Identifier>{827D319E-6EAC-11D2-A4EA-00C04F79F83A}</Identifier><BeginTime>2026-10-26T18:36:18</BeginTime><EndTime>2026-10-26T18:36:19</EndTime><LoggingStatus>Complete</LoggingStatus><Error>$SecurityError</Error></ExtensionStatus>
  </ComputerResults>
</Rsop>
"@ }
    $Rep = ConvertFrom-ALGpResult (& $Rsop 'false' 'false' 0) $GpText
    Assert 'gpresult xml: applied = AppliedOrder > 0, highest precedence first, like the text report' (($Rep.Applied -join '|') -eq 'Default Domain Controllers Policy|E|Default Domain Policy' -and $Rep.Source -eq 'xml') ($Rep.Applied -join '|')
    $NotA = @($Rep.Gpos | Where-Object { -not $_.Applied })
    Assert 'gpresult xml: a disabled link and an empty local policy are not applied, with the reason' ($NotA.Count -eq 2 -and @($NotA | Where-Object { $_.Name -eq 'A' -and $_.Reason -eq 'Disabled (Link)' -and -not $_.LinkEnabled }).Count -eq 1 -and @($NotA | Where-Object { $_.Name -eq 'Local Group Policy' -and $_.Reason -eq 'Not Applied (Empty)' }).Count -eq 1) (($NotA | ForEach-Object { "$($_.Name):$($_.Reason)" }) -join ';')
    Assert 'gpresult xml: GPO id, versions and link read' (@($Rep.Gpos | Where-Object { $_.Name -eq 'E' -and $_.Id -eq '{815454EA-3B6C-4FE3-9F58-4248F45B450E}' -and $_.VersionDirectory -eq 2 -and $_.VersionSysvol -eq 2 -and $_.Link -eq 'skynet-home.local/Domain Controllers' }).Count -eq 1)
    Assert 'gpresult xml: extensions with their error codes' ($Rep.Extensions.Count -eq 3 -and @($Rep.Extensions | Where-Object { $_.Name -eq 'Registry' -and $_.Id -eq '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -and $_.Error -eq 0 }).Count -eq 1)
    Assert 'gpresult xml: last applied / applied from come from the text' ($Rep.LastApplied -eq '10/27/2026 at 2:01:37 PM' -and $Rep.AppliedFrom -eq 'DC25-1.skynet-home.local')
    $RepDenied = ConvertFrom-ALGpResult (& $Rsop 'false' 'true' 5) ''
    Assert 'gpresult xml: access denied is a reason; a failed extension keeps its code' (@($RepDenied.Gpos | Where-Object { $_.Name -eq 'E' -and -not $_.Applied -and $_.Reason -eq 'Denied (Security)' }).Count -eq 1 -and @($RepDenied.Extensions | Where-Object { $_.Name -eq 'Security' -and $_.Error -eq 5 }).Count -eq 1 -and $RepDenied.LastApplied -eq '')
    $RepText = ConvertFrom-ALGpResult '<not xml' $GpText
    Assert 'gpresult: unreadable XML falls back to the text report' ($RepText.Source -eq 'text' -and ($RepText.Applied -join '|') -eq 'Default Domain Controllers Policy|E|Default Domain Policy' -and @($RepText.Gpos | Where-Object { $_.Name -eq 'A' -and $_.Reason -eq 'Disabled (Link)' -and -not $_.LinkEnabled }).Count -eq 1)
    Assert 'gpresult: nothing readable at all' ((ConvertFrom-ALGpResult '' '').Source -eq '' -and @((ConvertFrom-ALGpResult '' '').Applied).Count -eq 0)
    $RepGuid = ConvertFrom-ALGpResult ((& $Rsop 'false' 'false' 0) -replace '<Name>A</Name>', '<Name>{90611251-4E0A-441B-8967-84BBA320FDA5}</Name>') ''
    Assert 'gpresult names: a never-applied GPO is listed by GUID until the toolkit maps it' (@($RepGuid.Gpos | Where-Object { $_.Name -eq '{90611251-4E0A-441B-8967-84BBA320FDA5}' }).Count -eq 1)
    [void](Resolve-ALGpoNames $RepGuid @{ '90611251-4e0a-441b-8967-84bba320fda5' = 'A'; '{815454EA-3B6C-4FE3-9F58-4248F45B450E}' = 'E' })
    Assert 'gpresult names: mapped back to the GPO names (any GUID case or braces), applied list rebuilt' (@($RepGuid.Gpos | Where-Object { $_.Name -eq 'A' -and -not $_.Applied -and $_.Reason -eq 'Disabled (Link)' }).Count -eq 1 -and ($RepGuid.Applied -join '|') -eq 'Default Domain Controllers Policy|E|Default Domain Policy' -and (Get-ALGpVerdict $RepGuid 'Audit' 'A' 'E').Problems[0] -like "'A' is not applied (Disabled (Link))*")
    Assert 'gpresult names: an empty map changes nothing' (((Resolve-ALGpoNames $Rep @{}).Applied -join '|') -eq 'Default Domain Controllers Policy|E|Default Domain Policy')
    $V = Get-ALGpVerdict $Rep 'Enforce' 'A' 'E'
    Assert 'verdict: Enforce with the Enforce GPO applied and the Audit link disabled is OK' ($V.Ok -and $V.Found -eq 'Default Domain Controllers Policy, E, Default Domain Policy' -and $V.Expected -eq 'E applied, A not applied') ($V.Problems -join '; ')
    $V = Get-ALGpVerdict $Rep 'Audit' 'A' 'E'
    Assert 'verdict: Audit while Enforce applies names both problems' (-not $V.Ok -and $V.Problems.Count -eq 2 -and $V.Problems[0] -like "'A' is not applied (Disabled (Link))*" -and $V.Problems[1] -like "'E' is applied but must not be*3_AL_set_mode.ps1 -Mode Audit*") ($V.Problems -join '; ')
    $V = Get-ALGpVerdict $Rep 'Off' 'A' 'E'
    Assert 'verdict: Off while Enforce applies is a problem' (-not $V.Ok -and $V.Problems.Count -eq 1 -and $V.Problems[0] -like "'E' is applied but must not be (mode Off)*" -and $V.Expected -eq 'neither A nor E applied')
    $V = Get-ALGpVerdict (ConvertFrom-ALGpResult (& $Rsop 'true' 'true' 0) '') 'Audit' 'A' 'E'
    Assert 'verdict: Audit with the Audit GPO applied and the Enforce GPO denied is OK' $V.Ok ($V.Problems -join '; ')
    $V = Get-ALGpVerdict (ConvertFrom-ALGpResult '' '') 'Audit' 'A' 'E'
    Assert 'verdict: no report at all is a problem that names the missing GPO' (-not $V.Ok -and $V.Problems.Count -eq 2 -and $V.Problems[0] -like "'A' is not applied (not linked*" -and $V.Problems[1] -eq 'gpresult gave no readable report' -and $V.Found -eq 'no GPO applied') ($V.Problems -join '; ')
    Assert 'win32 message: a code, a hex HRESULT, zero' (((ConvertTo-ALWin32Message 2) -like 'The system cannot find the file specified*') -and ((ConvertTo-ALWin32Message '0x8007007E') -like 'The specified module could not be found*') -and ((ConvertTo-ALWin32Message 0) -eq 'The operation completed successfully')) ((ConvertTo-ALWin32Message 2) + ' / ' + (ConvertTo-ALWin32Message '0x8007007E'))
    Assert 'win32 message: element not found, access denied' (((ConvertTo-ALWin32Message '1168') -like 'Element not found*') -and ((ConvertTo-ALWin32Message 5) -like 'Access is denied*'))
    Assert 'win32 message: NTSTATUS named, other HRESULT and text passed through' (((ConvertTo-ALWin32Message '0xC0000034') -eq 'NTSTATUS 0xC0000034 STATUS_OBJECT_NAME_NOT_FOUND') -and ((ConvertTo-ALWin32Message '0xC0000999') -eq 'NTSTATUS 0xC0000999') -and ((ConvertTo-ALWin32Message 'n/a') -eq 'n/a') -and ((ConvertTo-ALWin32Message '0x80004005') -eq 'HRESULT 0x80004005 E_FAIL (Unspecified error)') -and ((ConvertTo-ALWin32Message '0x80091234') -eq 'HRESULT 0x80091234'))
    $RawOk = [pscustomobject]@{ Computer = 'DC01'; Started = '2026-10-27T17:00:00'; Finished = '2026-10-27T17:00:30'; Gpupdate = @("gpupdate /target:computer /force - pass 1 of 2 at 17:00:00, exit code 0`r`nUpdating policy...`r`n`r`nComputer Policy update has completed successfully.", "gpupdate /target:computer /force - pass 2 of 2 at 17:00:12, exit code 0`r`nUpdating policy...`r`n`r`nComputer Policy update has completed successfully."); GpupdateExit = @(0, 0); GpresultText = $GpText; GpresultTextExit = 0; GpresultXml = (& $Rsop 'false' 'false' 0); GpresultXmlExit = 0; AppIdSvc = 'Running/Auto'; Effective = 'Exe=Enabled(10)'; EffectiveXml = ''; PolicyEvents = @([pscustomobject]@{ Time = '2026-10-26 11:36:20'; Id = 8001; Status = ''; Message = 'The AppLocker policy was applied successfully to this computer.' }) }
    $Rows = New-ALResults
    Add-ALGpResults $Rows 'DC01' $RawOk $Rep 'Enforce' 'A' 'E' 'C:\x\DC01-gpresult.txt'
    Assert 'gp rows: Enforce as expected -> OK applied, OK processing, OK events, INFO group policy' ((($Rows | ForEach-Object { "$($_.Status) $($_.Check)" }) -join '|') -eq 'OK GPO applied DC01|OK GPO processing DC01|OK AppLocker policy events DC01|INFO Group Policy DC01') (($Rows | ForEach-Object { "$($_.Status) $($_.Check)" }) -join '|')
    Assert 'gp rows: the applied row names what is and is not applied' ($Rows[0].Detail -like 'applied: Default Domain Controllers Policy, E, Default Domain Policy; not applied: A (Disabled (Link)) - as expected for Enforce*') $Rows[0].Detail
    Assert 'gp rows: the group policy row carries the raw file and the last-applied time' ($Rows[3].Detail -like 'last applied 10/27/2026 at 2:01:37 PM from DC25-1.skynet-home.local; raw gpupdate / gpresult output: C:\x\DC01-gpresult.txt')
    $RawNoEvents = [pscustomobject]@{ Computer = 'DC22-2'; Started = ''; Finished = ''; Gpupdate = @(); GpupdateExit = @(); GpresultText = ''; GpresultTextExit = 0; GpresultXml = (& $Rsop 'true' 'true' 0); GpresultXmlExit = 0; AppIdSvc = 'Running/Auto'; Effective = 'Appx=AuditOnly(1), Dll=NotConfigured(0), Exe=AuditOnly(10)'; EffectiveXml = ''; PolicyEvents = @() }
    $Rows = New-ALResults
    Add-ALGpResults $Rows 'DC22-2' $RawNoEvents (ConvertFrom-ALGpResult $RawNoEvents.GpresultXml '') 'Audit' 'A' 'E' 'f'
    Assert 'gp rows: no policy event yet but the policy is effective -> INFO that says so (Server 2022 logs 8001 late)' ($Rows[2].Status -eq 'INFO' -and $Rows[2].Detail -like 'none in the EXE and DLL log yet - the effective policy is loaded (Appx=AuditOnly(1)*minute or two*') $Rows[2].Detail
    $RawNoEvents.Effective = 'empty (no rule collection)'
    $Rows = New-ALResults
    Add-ALGpResults $Rows 'DC22-2' $RawNoEvents (ConvertFrom-ALGpResult $RawNoEvents.GpresultXml '') 'Audit' 'A' 'E' 'f'
    Assert 'gp rows: no policy event and no effective policy -> INFO nothing applied yet' ($Rows[2].Detail -like 'none in the EXE and DLL log: no AppLocker policy has been applied or rejected*')
    $Raw8000 = [pscustomobject]@{ Computer = 'DC22-2'; Started = ''; Finished = ''; Gpupdate = @(); GpupdateExit = @(); GpresultText = ''; GpresultTextExit = 0; GpresultXml = (& $Rsop 'true' 'true' 5); GpresultXmlExit = 0; AppIdSvc = 'Running/Auto'; Effective = 'empty (no rule collection)'; EffectiveXml = ''; PolicyEvents = @([pscustomobject]@{ Time = '2026-10-27 10:00:00'; Id = 8000; Status = '2'; Message = '' }, [pscustomobject]@{ Time = '2026-10-27 09:00:00'; Id = 8001; Status = ''; Message = 'applied' }) }
    $Rows = New-ALResults
    Add-ALGpResults $Rows 'DC22-2' $Raw8000 (ConvertFrom-ALGpResult $Raw8000.GpresultXml '') 'Audit' 'A' 'E' 'C:\x\DC22-2-gpresult.txt'
    Assert 'gp rows: a failed Security extension is a FAIL, a newest 8000 is a WARN with the decoded status' ((($Rows | ForEach-Object { "$($_.Status) $($_.Check)" }) -join '|') -eq 'OK GPO applied DC22-2|FAIL GPO processing DC22-2|WARN AppLocker policy events DC22-2|INFO Group Policy DC22-2') (($Rows | ForEach-Object { "$($_.Status) $($_.Check)" }) -join '|')
    Assert 'gp rows: the processing row decodes the error, the events row the status' ($Rows[1].Detail -like '*Security extension error 5 (Access is denied*' -and $Rows[2].Detail -like 'newest is 8000 at 2026-10-27 10:00:00: AppID policy conversion failed, status 2 (The system cannot find the file specified*7_AL_diagnose.ps1*') "$($Rows[1].Detail) / $($Rows[2].Detail)"
    $Rows = New-ALResults
    Add-ALGpResults $Rows 'DC22-2' $Raw8000 (ConvertFrom-ALGpResult $Raw8000.GpresultXml '') 'Any' 'A' 'E' 'f'
    Assert 'gp rows: mode Any only reports' ($Rows[0].Status -eq 'INFO' -and $Rows[0].Detail -like 'applied: A, Default Domain Controllers Policy, Default Domain Policy; not applied: E (Denied (Security))*' -and $Rows[1].Status -eq 'FAIL') "$($Rows[0].Detail)"
    $Rows = New-ALResults
    Add-ALGpResults $Rows 'DC22-2' $Raw8000 (ConvertFrom-ALGpResult $Raw8000.GpresultXml '') 'Off' 'A' 'E' 'f'
    Assert 'gp rows: mode Off - an applied AppLocker GPO is a FAIL, an extension error only a WARN' ($Rows[0].Status -eq 'FAIL' -and $Rows[1].Status -eq 'WARN')
    $GpDir = Join-Path $Tmp 'gp'
    $GpFile = Save-ALGpResult $RawOk $GpDir
    $GpSaved = [IO.File]::ReadAllText($GpFile)
    $GpXmlBytes = [IO.File]::ReadAllBytes((Join-Path $GpDir 'DC01-gpresult.xml'))
    Assert 'gp raw file: text holds the service, the policy, the events, both gpupdate passes and the gpresult report, CRLF' ($GpFile -eq (Join-Path $GpDir 'DC01-gpresult.txt') -and $GpSaved.Contains('Application Identity (AppIDSvc): Running/Auto') -and $GpSaved.Contains('event 8001: The AppLocker policy was applied successfully') -and ([regex]::Matches($GpSaved, 'Computer Policy update has completed successfully').Count -eq 2) -and $GpSaved.Contains('Applied Group Policy Objects') -and -not ($GpSaved -replace "`r`n", '').Contains("`n"))
    Assert 'gp raw file: the RSoP XML is written UTF-16 with BOM, as gpresult writes it' ($GpXmlBytes[0] -eq 0xFF -and $GpXmlBytes[1] -eq 0xFE -and ([IO.File]::ReadAllText((Join-Path $GpDir 'DC01-gpresult.xml'))).Contains('<ComputerResults>'))
    Assert 'gp raw file: a server without an XML report gets only the text file' ((Save-ALGpResult ([pscustomobject]@{ Computer = 'DC02'; Started = ''; Finished = ''; Gpupdate = @(); GpupdateExit = @(); GpresultText = 'x'; GpresultTextExit = 1; GpresultXml = ''; GpresultXmlExit = 1; AppIdSvc = 'Stopped/Manual'; Effective = ''; EffectiveXml = ''; PolicyEvents = @() }) $GpDir) -eq (Join-Path $GpDir 'DC02-gpresult.txt') -and -not (Test-Path -LiteralPath (Join-Path $GpDir 'DC02-gpresult.xml')))

    if ($BuildFolder) {
        foreach ($M in 'Audit', 'Enforce') {
            $Src = Get-ChildItem -LiteralPath $BuildFolder -Filter "AppLockerRules-*-$M.xml" | Select-Object -First 1
            $Old = Join-Path $BuildFolder ($Src.BaseName + '-Deploy.xml')
            $New = Join-Path $Tmp "$M-Deploy.xml"
            [void](New-ALDeployXml -SourceXml $Src.FullName -Mode $M -DllRules $false -OutFile $New)
            if (Test-Path -LiteralPath $Old) { Assert "deploy XML: real $M build gives the same file as the deployed one" ((Get-FileHash -LiteralPath $New).Hash -eq (Get-FileHash -LiteralPath $Old).Hash) }
        }
        # Exceptions on a real AaronLocker build: only the C:\Admin rules change, the rule counts do not
        $Copy = Join-Path $Tmp 'real-Enforce.xml'
        Copy-Item -LiteralPath (Get-ChildItem -LiteralPath $BuildFolder -Filter 'AppLockerRules-*-Enforce.xml' | Select-Object -First 1).FullName -Destination $Copy
        $Before = Get-ALPolicySummary ([xml](Get-Content -LiteralPath $Copy -Raw))
        $N = Add-ALPathExceptions $Copy @{ 'C:\Admin\*' = @('C:\Admin\Shared\*') }
        $After = New-Object System.Xml.XmlDocument; $After.Load($Copy)
        Assert 'exceptions: real build - C:\Admin rules in Exe + Script excepted, nothing else changed' ($N -ge 2 -and (Get-ALPolicySummary $After) -eq $Before -and ((Get-ALRuleExceptions $After 'C:\Admin\*') -join ',') -eq 'C:\Admin\Shared\*') "rules changed: $N"
        # The merge self-check against a real AaronLocker build: its own scan, mapped like AaronLocker maps it, is entirely in its rules
        $RealScan = Join-Path $BuildFolder 'ScanResults'
        if (Test-Path -LiteralPath (Join-Path $RealScan 'Writable_windir.txt')) {
            $RealMerge = Merge-ALScanResults @([pscustomobject]@{ Server = 'build'; Folder = $RealScan }) (Join-Path $Tmp 'real-merge')
            $RealPol = New-Object System.Xml.XmlDocument; $RealPol.Load((Get-ChildItem -LiteralPath $BuildFolder -Filter 'AppLockerRules-*-Enforce.xml' | Select-Object -First 1).FullName)
            $RealMiss = @(Get-ALMissingScanEntries $RealPol $RealMerge $Roots)
            Assert "merge self-check: real build - all $(@($RealMerge.Writable).Count) excluded folders and $(@($RealMerge.Deny).Count) denied tools found in its rules" ($RealMiss.Count -eq 0 -and @($RealMerge.Writable).Count -gt 0 -and @($RealMerge.Deny).Count -gt 0) ($RealMiss -join '; ')
            $Fake = [pscustomobject]@{ Writable = @($RealMerge.Writable) + 'C:\Windows\NotInThisBuild\*'; Deny = $RealMerge.Deny }
            Assert 'merge self-check: real build - a folder the rules do not carry is reported' (@(Get-ALMissingScanEntries $RealPol $Fake $Roots).Count -eq 1)
            Assert 'merge: real scan merged alone is byte-identical (writable lists and deny list)' (@('Writable_windir.txt', 'Writable_PF.txt', 'Writable_PF86.txt', 'ExeDenyListData.txt' | Where-Object { (Get-FileHash -LiteralPath (Join-Path $RealScan $_)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $Tmp "real-merge\$_")).Hash }).Count -eq 0)
        }
    }
}
finally {
    # Give the current user full control back before deleting (the test folder was made administrators-only)
    & icacls.exe $Tmp /reset /T /C /Q 2>&1 | Out-Null
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ''
if ($Fail) { Write-Host "Tests: $Pass passed, $Fail FAILED" -ForegroundColor Red; exit 1 } else { Write-Host "Tests: all $Pass passed" -ForegroundColor Green }
