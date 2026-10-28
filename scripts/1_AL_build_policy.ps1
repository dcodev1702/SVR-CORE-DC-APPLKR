<#
.SYNOPSIS
    Step 4 - builds the AaronLocker AppLocker baseline on the reference server and brings the rule files back to Outputs\.

.DESCRIPTION
    Run from the management computer as a Domain Admin. The rules are built ON the reference server because they depend on that
    machine's file system (user-writable folders under Windows and Program Files, including the MECM client's folders, the tools
    present, the safe paths). The steps:
      1. checks the AccessChk.exe that ships with the toolkit (Microsoft signature, 64-bit, pinned SHA-256); nothing is downloaded
      2. copies the toolkit, the Customizations overlay and the KnownAdmins list to a temporary folder on the server over WinRM (and on
         every ExtraReferenceServers entry, each in its own folder)
      3. checks every ExtraAllowedPaths entry (C:\Admin ...) on the reference server AND every server in the target OUs, and never
         stops on what it finds: an entry a non-admin can change is LEFT OUT of the policy; items inside it that a non-admin can change
         become EXCEPTIONS of its rule. The policy never allows what a non-admin can write, and no permission is ever changed
      4. runs Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan on the server (it only READS permissions; nothing is applied)
      5. with ExtraReferenceServers (servers of another Windows Server version in scope, e.g. a Server 2022 DC next to 2025 DCs): scans
         each of them the same way, merges every user-writable folder and every deny-list entry that ANY server found (a union, so the
         policy only gets stricter), generates the rules again on the reference server from the merged scan, and proves that the rules
         carry every merged entry - otherwise it stops
      6. copies the results to <root>\Outputs\<profile>\<timestamp>\ with the exceptions from step 3 and the SHA-256 of every rule
         file recorded in build-info.json, removes the temporary folders, and warns about any Windows Server version in the target OUs
         (from AD) that no scanned server runs
    Outputs\<profile>\latest.txt names the newest build; 2_AL_create_gpos.ps1 deploys it.
    The script may run on the reference server itself (the toolkit on a DC): that server is then reached in this process instead of
    over WinRM, with the same steps and the same temporary folder. Every other server is still reached over WinRM.

.PARAMETER SettingsFile
    Settings file to use. Default: AL-Settings.psd1 next to the script.

.PARAMETER ComputerName
    FQDN of the server to build on. Default: the ReferenceServer setting (required: one of the servers in scope that looks like the
    others; for domain controllers any DC, the PDC emulator is a good choice).

.PARAMETER ExtraAllowedPaths
    Folders (ending in \*) or files that every account may run from, outside Windows and Program Files. Overrides the setting.

.PARAMETER RemoteWork
    Temporary work folder on the reference server; extra reference servers use the same name with -1, -2, ... appended. They are
    DELETED before and after the build, so the name must start with AaronLocker. Default: C:\AaronLocker.

.PARAMETER ExtraReferenceServers
    FQDNs of more servers to scan, one per other Windows Server version in scope. Their scans are merged into the reference server's
    (SERVER-2022.md, section 2). Overrides the setting.

.INPUTS
    None. Nothing can be piped to this script.

.OUTPUTS
    None to the pipeline. Files in Outputs\<profile>\<timestamp>\: AppLockerRules-<ts>-Audit.xml and -Enforce.xml, ScanResults\
    (Writable_*.txt = the user-writable folders carved out of the rules; ExeDenyListData.txt = the denied tools), with
    ExtraReferenceServers also ScanResults-<server>\ (each server's own scan; ScanResults\ is then the merged scan the rules were
    built from), build-info.json (settings, the servers scanned and their versions, what the extra servers added, the decision for
    every ExtraAllowedPaths entry, SHA-256 of the rule files). Console: the AaronLocker output and "Results: <folder>". Transcript in
    Logs\1_AL_build_policy-<timestamp>.log. Exit code 1 on a STOP (nothing deployed, latest.txt unchanged, the temporary folders
    removed).

.EXAMPLE
    .\1_AL_build_policy.ps1
    Builds on the ReferenceServer named in the settings (and merges the scans of the ExtraReferenceServers, if any).

.EXAMPLE
    .\1_AL_build_policy.ps1 -ComputerName dc01.contoso.com
    Builds on another server in scope.

.EXAMPLE
    .\1_AL_build_policy.ps1 -ExtraReferenceServers dc22-01.contoso.com
    Builds on the ReferenceServer (a Server 2025 DC) and merges the scan of a Server 2022 DC: one policy for both versions.

.NOTES
    Project  : SVR-CORE-DC-APPLKR - https://github.com/dcodev1702/SVR-CORE-DC-APPLKR
    Author   : dcodev1702
    Date     : 2026-10-27
    Version  : 1.2 (ExtraReferenceServers: merged scans for DCs of more than one Windows Server version; runs on the reference server itself)
    Requires : Windows PowerShell 5.1 or PowerShell 7; RSAT ActiveDirectory module; WinRM administrator on the servers; FullLanguage
               mode and an execution policy that runs unsigned scripts on the reference server and every extra reference server
               (AaronLocker's scripts are not signed).
    Changes  : a temporary folder on the reference server and on each extra reference server (created, then deleted). No policy and
               no permission is changed.
    README   : section 7, step 4; section 8 (C:\Admin); section 11 (who counts as an administrator); SERVER-2022.md (mixed versions).
#>
param(
    [string]$SettingsFile,
    [string]$ComputerName,
    [string[]]$ExtraAllowedPaths,
    # Temporary work folder on the servers (extra reference servers: <name>-1, -2 ...); DELETED before and after the build, so its name must start with AaronLocker
    [ValidatePattern('^[A-Za-z]:\\(?:[^*?"<>|:]*\\)?AaronLocker[^\\*?"<>|:]*$')][string]$RemoteWork = 'C:\AaronLocker',
    [string[]]$ExtraReferenceServers
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '1_AL_build_policy' -SettingsFile $SettingsFile -Overrides @{ ReferenceServer = $ComputerName; ExtraAllowedPaths = $ExtraAllowedPaths; ExtraReferenceServers = $ExtraReferenceServers }
if (-not $ComputerName) { $ComputerName = $Cfg.ReferenceServer }
# Every server the build opens (Name, Role, Work, Local, Session, Info, Prepared); the finally block removes the temporary folder
# from each one and closes whatever session is still open. A server that is this computer (the toolkit run on the reference DC
# itself) has no session: the same commands run in this process, because a remote session cannot open a second hop to its own computer.
$Servers = New-Object System.Collections.Generic.List[object]

# Runs a script block on a build server: in its session, or in this process when it is this computer
function Invoke-ALServer($Server, [scriptblock]$ScriptBlock, [object[]]$ArgumentList = @()) {
    if ($null -eq $ArgumentList) { $ArgumentList = @() }
    if ($Server.Local) { return (& $ScriptBlock @ArgumentList) }
    return (Invoke-Command -Session $Server.Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop)
}
# Copies files to / from a build server (a plain copy when it is this computer)
function Copy-ALToServer($Server, [string]$Path, [string]$Destination, [switch]$Recurse) {
    if ($Server.Local) { Copy-Item -Path $Path -Destination $Destination -Recurse:$Recurse -Force -ErrorAction Stop }
    else { Copy-Item -Path $Path -Destination $Destination -ToSession $Server.Session -Recurse:$Recurse -Force -ErrorAction Stop }
}
function Copy-ALFromServer($Server, [string]$Path, [string]$Destination, [switch]$Recurse) {
    if ($Server.Local) { Copy-Item -Path $Path -Destination $Destination -Recurse:$Recurse -Force -ErrorAction Stop }
    else { Copy-Item -Path $Path -Destination $Destination -FromSession $Server.Session -Recurse:$Recurse -Force -ErrorAction Stop }
}

# Opens a build server - a WinRM session to it, or nothing when it is this computer - and prepares a fresh work folder there
# ($Work): the toolkit, the Customizations overlay and the KnownAdmins list. Every server gets its own folder name (C:\AaronLocker,
# C:\AaronLocker-1, ...), so two names for the same computer cannot delete each other's folder. Stops before anything is written on
# the server unless PowerShell runs in FullLanguage mode and the execution policy lets unsigned scripts run. Returns the server object.
function Open-ALBuildServer([string]$Name, [string]$Role, [string]$Work) {
    $Local = Test-ALLocalComputer $Name
    if ($Local -and (ConvertTo-ALComparablePath $Cfg.Root).StartsWith((ConvertTo-ALComparablePath $Work) + '\', [StringComparison]::Ordinal)) { throw "STOP: the work folder $Work would contain this repository ($($Cfg.Root)); the build deletes it. Pass another -RemoteWork." }
    $S = if ($Local) { $null } else { New-PSSession -ComputerName $Name -ErrorAction Stop }
    $Server = [pscustomobject]@{ Name = $Name; Role = $Role; Work = $Work; Local = $Local; Session = $S; Info = $null; Prepared = $false }
    $Servers.Add($Server)
    $Server.Info = Invoke-ALServer $Server -ArgumentList $Work -ScriptBlock {
        param([string]$Work)
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $o = [pscustomobject]@{
            Computer = $env:COMPUTERNAME; Fqdn = "$($cs.DNSHostName).$($cs.Domain)"; Caption = "$($os.Caption)"; Build = [int]$os.BuildNumber
            InstallationType = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').InstallationType)"
            PowerShell = "$($PSVersionTable.PSVersion)"; Language = "$($ExecutionContext.SessionState.LanguageMode)"; ExecPolicy = "$(Get-ExecutionPolicy)"
            Windir = $env:windir; ProgramFiles = $env:ProgramFiles; ProgramFilesX86 = ${env:ProgramFiles(x86)}; Problem = ''
        }
        if ($o.Language -ne 'FullLanguage') { $o.Problem = "PowerShell runs in $($o.Language) mode; AaronLocker needs FullLanguage" }
        elseif ($o.ExecPolicy -in 'AllSigned', 'Restricted') { $o.Problem = "the execution policy is $($o.ExecPolicy); AaronLocker's scripts are not signed" }
        else {
            Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -Path $Work -ItemType Directory -Force | Out-Null
        }
        $o
    }
    $I = $Server.Info
    Write-Host "$($Role): $($I.Computer) | $($I.Caption) $($I.InstallationType) (build $($I.Build)) | PowerShell $($I.PowerShell) | $($I.Language) | execution policy $($I.ExecPolicy)$(if ($Local) { ' | this computer, no WinRM' })"
    if ($I.Problem) { throw "STOP: $Role $Name - $($I.Problem). Nothing was written on that server and nothing was deployed." }
    $Server.Prepared = $true
    Copy-ALToServer $Server (Join-Path $Cfg.ToolkitPath '*') $Work -Recurse
    # Overlay: Server Core-safe deny list + the ExtraAllowedPaths and KnownAdmins hooks (see Customizations\)
    Copy-ALToServer $Server (Join-Path $Overlay '*') $Work -Recurse
    # Desktop-only static rules (OneDrive installer, Chrome Flash) have no place on a server; dropped from the server's copy only
    Invoke-ALServer $Server -ArgumentList $Work -ScriptBlock {
        param([string]$Work)
        Remove-Item -Path (Join-Path $Work 'MergeRules-Static\OneDrive-*.xml'), (Join-Path $Work 'MergeRules-Static\Allow-GoogleChromeFlashPlayer.xml') -Force -ErrorAction SilentlyContinue
    }
    # KnownAdmins changes the scan (their write access does not count as user-writable), so every scanned server gets the list
    if ($Known.Count) { Invoke-ALServer $Server -ArgumentList $Work, $Known -ScriptBlock { param([string]$Work, [string[]]$Known) Set-Content -LiteralPath (Join-Path $Work 'CustomizationInputs\KnownAdmins.txt') -Value $Known -Encoding UTF8 } }
    return $Server
}

# Runs AaronLocker in the server's work folder. -Rescan scans the server; without it AaronLocker builds the rules from the scan files
# already in its ScanResults folder (the merged scan).
function Invoke-ALAaronLocker($Server, [switch]$Rescan) {
    Invoke-ALServer $Server -ArgumentList $Server.Work, ([bool]$Rescan) -ScriptBlock {
        param([string]$Work, [bool]$Scan)
        Push-Location -LiteralPath $Work
        try { if ($Scan) { & .\Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan } else { & .\Create-Policies.ps1 -AppLockerOrWDAC AppLocker } }
        finally { Pop-Location }
    } | Out-Host
}

# Copies a server's scan results to <build>\ScanResults-<server>\; returns Server / Folder for Merge-ALScanResults
function Save-ALScan($Server) {
    $Folder = Join-Path $Dest "ScanResults-$($Server.Name)"
    New-Item -Path $Folder -ItemType Directory -Force | Out-Null
    Copy-ALFromServer $Server (Join-Path $Server.Work 'ScanResults\*') $Folder -Recurse
    return [pscustomobject]@{ Server = $Server.Name; Folder = $Folder }
}

# Removes the work folder from a server the build prepared (a server it refused is left untouched) and closes its session
function Close-ALBuildServer($Server) {
    if ($Server.Prepared) {
        try {
            Invoke-ALServer $Server -ArgumentList $Server.Work -ScriptBlock {
                param([string]$Work)
                if ((Get-Location).Path.StartsWith($Work, [StringComparison]::OrdinalIgnoreCase)) { Set-Location -LiteralPath $env:SystemRoot }
                if (Test-Path -LiteralPath $Work) { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction Stop }
            }
        }
        catch { Write-Warning "Could not remove $($Server.Work) on $($Server.Name): $($_.Exception.Message)" }
    }
    if ($Server.Session) { Remove-PSSession $Server.Session }
    [void]$Servers.Remove($Server)
}

try {
    if (-not $ComputerName) { throw 'STOP: no reference server. Set ReferenceServer in the settings (a server in scope that looks like the others; for DCs any DC) or pass -ComputerName. Nothing was changed.' }
    $Extra = @($Cfg.ExtraAllowedPaths | Where-Object { $_ })
    $Known = @($Cfg.KnownAdmins | Where-Object { $_ })
    # Only an exact repeat of a name is dropped: a short name and an FQDN may still be two different servers
    $Scanners = @($Cfg.ExtraReferenceServers | Where-Object { $_ -and $_ -ne $ComputerName } | Sort-Object -Unique)
    $Overlay = Join-Path $Cfg.Root 'Customizations'
    if (-not (Test-Path -LiteralPath (Join-Path $Cfg.ToolkitPath 'Create-Policies.ps1'))) { throw "STOP: AaronLocker not found at $($Cfg.ToolkitPath). Run 0_AL_get_toolkit.ps1." }
    if (-not (Test-Path -LiteralPath $Overlay)) { throw "STOP: $Overlay is missing." }
    # 1. the AccessChk that ships with the toolkit must be the verified one
    $Check = Test-ALAccessChk -Path (Join-Path $Cfg.ToolkitPath 'AccessChk.exe') -Sha256 $Cfg.AccessChkSha256
    if (-not $Check.Ok) { throw "STOP: AccessChk.exe - $($Check.Detail)" }
    Write-Host "AccessChk.exe: $($Check.Detail)"

    # 2. a fresh temporary work folder on the reference server (and on every extra reference server, so a server that cannot run
    # AaronLocker stops the build before the first scan): toolkit + Customizations overlay + KnownAdmins
    if ($Known.Count) { Write-Host "Known administrators groups: $($Known -join ', ')" }
    $Ref = Open-ALBuildServer $ComputerName 'Reference server' $RemoteWork
    $RefWhere = if ($Ref.Local) { @{ ComputerName = $ComputerName } } else { @{ Session = $Ref.Session } }
    $ExtraRefs = New-Object System.Collections.Generic.List[object]
    foreach ($N in $Scanners) {
        $X = Open-ALBuildServer $N 'Extra reference server' "$RemoteWork-$($ExtraRefs.Count + 1)"
        $Same = @(@($Ref) + $ExtraRefs.ToArray() | Where-Object { $_.Info.Fqdn -eq $X.Info.Fqdn } | Select-Object -First 1)
        if ($Same.Count) { Write-Warning "$N is $($X.Info.Fqdn), the same computer as $($Same[0].Name): its scan adds nothing. Remove it from ExtraReferenceServers, or name the server you meant." }
        $ExtraRefs.Add($X)
    }
    $ExtraRefs = $ExtraRefs.ToArray()

    # The servers in scope, from AD: for the ExtraAllowedPaths check (step 3) and the version check at the end
    $Domain = $null; $Targets = @()
    try { Import-ALModule ActiveDirectory; $Domain = Get-ALDomainInfo; $Targets = @(Get-ALTargetComputers (Resolve-ALTargetOUs $Cfg $Domain) $Domain) }
    catch { Write-Warning "Could not list the servers in the target OUs ($($_.Exception.Message)); ExtraAllowedPaths is checked on the reference server only and the Windows Server versions in scope are not compared." }

    # 3. ExtraAllowedPaths: who can change them, on every server the policy will reach (never stops; decides keep / drop / except)
    $Plan = [pscustomobject]@{ Keep = @(); Drop = @(); Exceptions = @{} }
    $Checked = @(); $Unchecked = @()
    if ($Extra.Count) {
        # Every server the policy will reach, not only the reference: the GPO carries one rule set for all of them
        $Findings = New-Object System.Collections.Generic.List[object]
        @(Invoke-ALWritableCheck -Paths $Extra -Cfg $Cfg @RefWhere) | ForEach-Object { $Findings.Add($_) }
        $Checked += $ComputerName
        $Others = @($Targets | Where-Object { $_ -ne $ComputerName -and $_ -notlike "$ComputerName.*" -and $ComputerName -notlike "$_.*" })
        foreach ($C in $Others) {
            try { @(Invoke-ALWritableCheck -Paths $Extra -Cfg $Cfg -ComputerName $C) | ForEach-Object { $Findings.Add($_) }; $Checked += $C }
            catch { $Unchecked += $C; Write-Warning "$C : ExtraAllowedPaths not checked ($($_.Exception.Message)). Run 4_AL_validate.ps1 for it after deployment." }
        }
        $Plan = Get-ALExtraPathPlan $Extra $Findings
        foreach ($F in @($Findings | Where-Object { $_.Kind -in 'NOTFOUND', 'UNRESOLVED' })) {
            if ($F.Kind -eq 'NOTFOUND') { Write-Warning "$($F.Path) does not exist on $($F.Computer); the rule is still generated. Create that folder administrators-only (0_AL_secure_folders.ps1) before the policy is used." }
            else { Write-Warning "KnownAdmins entry '$($F.Path)' could not be resolved on $($F.Computer)." }
        }
        foreach ($E in $Plan.Keep) {
            if ($Plan.Exceptions.ContainsKey($E)) { Write-Host "Extra allowed path: $E - allowed for every account EXCEPT (non-admins can change these): $($Plan.Exceptions[$E] -join ', ')" -ForegroundColor Yellow }
            else { Write-Host "Extra allowed path: $E - allowed for every account (administrators-only on: $($Checked -join ', '))" }
        }
        foreach ($D in $Plan.Drop) { Write-Host "Extra allowed path: $($D.Entry) - LEFT OUT of the policy: $($D.Reason). Non-admins cannot run from it; elevated administrators still can. Fix its permissions (README, C:\Admin) and rebuild to allow it." -ForegroundColor Yellow }
        $Keep = @($Plan.Keep)
        if ($Keep.Count) { Invoke-ALServer $Ref -ArgumentList $RemoteWork, $Keep -ScriptBlock { param([string]$Work, [string[]]$Keep) Set-Content -LiteralPath (Join-Path $Work 'CustomizationInputs\ExtraAllowedPaths.txt') -Value $Keep -Encoding UTF8 } }
    }

    # 4. AaronLocker builds the rules on the server (it only reads permissions; nothing is applied there)
    Invoke-ALAaronLocker $Ref -Rescan

    # 5. extra reference servers: scan each one, merge every scan, generate the rules again from the merged scan
    $Dest = Join-Path $Cfg.OutRoot $Cfg.Stamp
    New-Item -Path $Dest -ItemType Directory -Force | Out-Null
    $Merge = $null
    if ($ExtraRefs.Count) {
        $Scans = New-Object System.Collections.Generic.List[object]
        $Scans.Add((Save-ALScan $Ref))
        foreach ($X in $ExtraRefs) {
            Write-Host "Scanning the extra reference server $($X.Name) ..." -ForegroundColor Cyan
            Invoke-ALAaronLocker $X -Rescan
            $Scans.Add((Save-ALScan $X))
            Close-ALBuildServer $X
        }
        $Merge = Merge-ALScanResults $Scans.ToArray() (Join-Path $Dest 'ScanResults')
        if ($Merge.Added.Count) {
            Write-Host "The extra reference servers add $($Merge.Added.Count) entr$(if ($Merge.Added.Count -eq 1) { 'y' } else { 'ies' }) to the scan of ${ComputerName} (excluded folders and denied tools that the rules now carry):" -ForegroundColor Yellow
            $Merge.Added | ForEach-Object { Write-Host "  $($_.Server) | $($_.File) | $($_.Entry)" -ForegroundColor Yellow }
        }
        else { Write-Host "The extra reference servers add nothing to the scan of ${ComputerName}: its scan covers them." }
        # The merged scan replaces the reference server's; AaronLocker without -Rescan builds the rules from it. The first run's rule
        # files are removed so that only rules built from the merged scan come back.
        Copy-ALToServer $Ref (Join-Path (Join-Path $Dest 'ScanResults') '*') (Join-Path $RemoteWork 'ScanResults')
        Invoke-ALServer $Ref -ArgumentList $RemoteWork -ScriptBlock { param([string]$Work) Remove-Item -Path (Join-Path $Work 'Outputs\*') -Recurse -Force -ErrorAction Stop }
        Write-Host "Generating the rules again on $ComputerName from the merged scan ..." -ForegroundColor Cyan
        Invoke-ALAaronLocker $Ref
    }

    # 6. bring the results back, add the exceptions from step 3, record the build (build-info.json, latest.txt)
    Copy-ALFromServer $Ref (Join-Path $RemoteWork 'Outputs\*') $Dest -Recurse
    if (-not $Merge) { Copy-ALFromServer $Ref (Join-Path $RemoteWork 'ScanResults') $Dest -Recurse }
    $Rules = @(Get-ChildItem -LiteralPath $Dest -Filter 'AppLockerRules-*.xml' -File)
    if (-not @($Rules | Where-Object { $_.Name -like '*-Audit.xml' }).Count -or -not @($Rules | Where-Object { $_.Name -like '*-Enforce.xml' }).Count) { throw "STOP: the build produced no Audit/Enforce rules file in $Dest - see the AaronLocker output above." }
    # Prove that the rules were generated from the merged scan: every merged folder and deny-list entry must be in them
    if ($Merge) {
        foreach ($R in $Rules) {
            $Doc = New-Object System.Xml.XmlDocument
            $Doc.Load($R.FullName)
            $Missing = @(Get-ALMissingScanEntries $Doc $Merge $Ref.Info)
            if ($Missing.Count) {
                $Rules | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
                throw "STOP: $($R.Name) does not carry $($Missing.Count) entr$(if ($Missing.Count -eq 1) { 'y' } else { 'ies' }) of the merged scan: $($Missing -join '; '). The rule files were removed from $Dest (the scans stay there for review); nothing was deployed and latest.txt is unchanged."
            }
        }
        Write-Host "Merged scan: all $(@($Merge.Writable).Count) excluded folder(s) and $(@($Merge.Deny).Count) denied tool(s) are in the rules."
    }
    # Exceptions for items inside an extra path that a non-admin can change (step 3), in both rule files
    if ($Plan.Exceptions.Count) {
        foreach ($R in $Rules) { $N = Add-ALPathExceptions $R.FullName $Plan.Exceptions; Write-Host "  $($R.Name): exceptions added to $N rule(s)" }
    }

    # Windows Server versions in scope that no scanned server runs: the folders only that version makes user-writable stay allowed there
    $ScannedBuilds = @(@($Ref) + $ExtraRefs | ForEach-Object { $_.Info.Build })
    $NotScanned = @(foreach ($T in $Targets) {
            $B = Get-ALAdOsBuild $T $Domain
            if ($B -gt 0 -and $B -notin $ScannedBuilds) { [pscustomobject]@{ Server = $T; Os = (Get-ALOsLabel $B) } }
        })
    foreach ($T in $NotScanned) { Write-Warning "$($T.Server) runs $($T.Os), which none of the scanned servers runs ($((@($ScannedBuilds | Sort-Object -Unique) | ForEach-Object { Get-ALOsLabel $_ }) -join ', ')). Folders that only this version makes user-writable stay allowed on it. Add one server of this version to ExtraReferenceServers and rebuild (SERVER-2022.md, section 2)." }

    [ordered]@{
        Built = (Get-Date).ToString('s'); ReferenceServer = $ComputerName; ReferenceOs = "$($Ref.Info.Caption) $($Ref.Info.InstallationType) (build $($Ref.Info.Build))"
        ExtraReferenceServers = @($ExtraRefs | ForEach-Object { [ordered]@{ Server = $_.Name; Os = "$($_.Info.Caption) $($_.Info.InstallationType) (build $($_.Info.Build))" } })
        MergedScan = $(if ($Merge) { [ordered]@{ ExcludedFolders = @($Merge.Writable).Count; DeniedTools = @($Merge.Deny).Count; AddedByExtraServers = @($Merge.Added | ForEach-Object { [ordered]@{ Server = $_.Server; File = $_.File; Entry = $_.Entry } }) } } else { $null })
        VersionsNotScanned = @($NotScanned | ForEach-Object { [ordered]@{ Server = $_.Server; Os = $_.Os } })
        KnownAdmins = $Known; AccessChk = $Check.Detail
        ExtraAllowedPaths = [ordered]@{
            Requested = $Extra; Allowed = $Plan.Keep; LeftOut = @($Plan.Drop | ForEach-Object { [ordered]@{ Entry = $_.Entry; Reason = $_.Reason } })
            Exceptions = $Plan.Exceptions; CheckedOn = $Checked; NotChecked = $Unchecked
        }
        Rules = @($Rules | ForEach-Object { [ordered]@{ File = $_.Name; Sha256 = (Get-ALSha256 $_.FullName) } })
        Settings = $Cfg.SettingsFile; PowerShell = "$($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Dest 'build-info.json') -Encoding UTF8
    # Only the folder name: the whole tree can be moved or copied to another computer
    Set-Content -LiteralPath (Join-Path $Cfg.OutRoot 'latest.txt') -Value $Cfg.Stamp -Encoding Ascii

    $Watch = @(Get-ChildItem -LiteralPath (Join-Path $Dest 'ScanResults') -Filter 'Writable_*.txt' | Select-String -Pattern '\\(ccm|sms|tenable)' )
    if ($Watch.Count) { Write-Host 'MECM / Tenable folders that are user-writable on a scanned server (excluded from the allow rules; SYSTEM/admins are unaffected):'; $Watch | ForEach-Object { Write-Host "  $($_.Line)" } }
    Get-ChildItem -LiteralPath $Dest -File | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "Results: $Dest" -ForegroundColor Green
}
finally {
    foreach ($S in @($Servers.ToArray())) { Close-ALBuildServer $S }
    Stop-ALTranscript
}
