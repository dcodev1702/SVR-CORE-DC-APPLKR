# Step 2 - run from the management computer (Windows PowerShell 5.1) as a Domain Admin / GPO creator.
# Creates (or updates) the two AppLocker GPOs from the newest build and links BOTH to every target OU:
#   <AuditGpoName>    every collection AuditOnly   - logs what WOULD be blocked, blocks nothing
#   <EnforceGpoName>  every collection Enabled     - blocks what the rules do not allow
# New links are created DISABLED; an existing link keeps its state. Nothing reaches a server until 3_AL_set_mode.ps1 enables one link.
# Both GPOs carry the rules (Set-AppLockerPolicy -Ldap) and System Services: Application Identity = Automatic. The DLL collection is
# switched off (EnableDllRules = $false). The AppLocker event logs of the servers in scope are enlarged (-SkipLogSize to leave them).
param(
    [string]$SettingsFile,
    [string]$OutputFolder,
    [string[]]$TargetOU,
    [switch]$SkipLogSize,
    # Skip the Y/N confirmation (automation); default: ask
    [switch]$NoConfirm
)
. "$PSScriptRoot\AL-Common.ps1"
$Cfg = Initialize-AL -ScriptName '2_AL_create_gpos' -SettingsFile $SettingsFile -Overrides @{ TargetOUs = $TargetOU }
try {
    Import-ALModule GroupPolicy; Import-ALModule ActiveDirectory; Import-ALModule AppLocker
    $Domain = Get-ALDomainInfo
    $Ous = Resolve-ALTargetOUs $Cfg $Domain
    $Targets = Get-ALTargetComputers $Ous $Domain

    if (-not $OutputFolder) {
        $Latest = Join-Path $Cfg.OutRoot 'latest.txt'
        if (-not (Test-Path -LiteralPath $Latest)) { throw 'STOP: no build yet. Run 1_AL_build_policy.ps1 first.' }
        $OutputFolder = (Get-Content -LiteralPath $Latest -Raw).Trim()
    }
    $Plan = foreach ($Mode in 'Audit', 'Enforce') {
        $Src = Get-ChildItem -LiteralPath $OutputFolder -Filter "AppLockerRules-*-$Mode.xml" | Sort-Object Name | Select-Object -Last 1
        if (-not $Src) { throw "STOP: no AppLockerRules-*-$Mode.xml in $OutputFolder. Run 1_AL_build_policy.ps1." }
        $Out = Join-Path $OutputFolder ($Src.BaseName + '-Deploy.xml')
        $Summary = New-ALDeployXml -SourceXml $Src.FullName -Mode $Mode -DllRules ([bool]$Cfg.EnableDllRules) -OutFile $Out
        [pscustomobject]@{ Mode = $Mode; Gpo = $(if ($Mode -eq 'Audit') { $Cfg.AuditGpoName } else { $Cfg.EnforceGpoName }); Xml = $Out; Summary = $Summary }
    }
    foreach ($P in $Plan) { Write-Host "$($P.Mode): $($P.Xml)`n  $($P.Summary)" }

    Confirm-ALChange -NoConfirm:$NoConfirm -Action "create/update the AppLocker GPOs '$($Cfg.AuditGpoName)' and '$($Cfg.EnforceGpoName)'" -Detail @(
        "Target OUs: $($Ous -join '; ')",
        "Servers in scope: $(if ($Targets.Count) { $Targets -join ', ' } else { 'none found' })",
        'New links are created DISABLED and existing links keep their state, so nothing new reaches a server until 3_AL_set_mode.ps1.',
        'An ENABLED existing link applies the updated rules to its servers at the next policy refresh.'
    )

    # Client-side extensions: Registry (AppLocker rules) and Security (System Services)
    $Cse = @(
        '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
        '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    )
    foreach ($P in $Plan) {
        $Gpo = Get-GPO -Name $P.Gpo -Server $Domain.PDC -ErrorAction SilentlyContinue
        if (-not $Gpo) {
            $Gpo = New-GPO -Name $P.Gpo -Server $Domain.PDC -Comment "AaronLocker baseline, $($P.Mode.ToUpper()). Application Identity service = Automatic. Managed by AppLocker\scripts."
            Write-Host "Created GPO $($Gpo.DisplayName) $($Gpo.Id)"
        }
        else { Write-Host "GPO exists: $($Gpo.DisplayName) $($Gpo.Id) - updating" }
        $Paths = Get-ALGpoPaths $Gpo.Id $Domain

        Set-AppLockerPolicy -XmlPolicy $P.Xml -Ldap "LDAP://$($Domain.PDC)/$($Gpo.Path)"
        Write-Host "  $($P.Mode) rules written to the GPO."

        # System Services (Security CSE): Application Identity = Automatic. A GPP 'Services' item cannot change this protected service.
        $SecDir = Join-Path $Paths.SysvolPdc 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -Path $SecDir -ItemType Directory -Force | Out-Null
        $Inf = "[Unicode]`r`nUnicode=yes`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n[Service General Setting]`r`n`"AppIDSvc`",2,`"`"`r`n"
        [System.IO.File]::WriteAllText((Join-Path $SecDir 'GptTmpl.inf'), $Inf, [System.Text.Encoding]::Unicode)

        $AdObj = Get-ADObject -Identity $Paths.AdPath -Properties gPCMachineExtensionNames -Server $Domain.PDC
        Set-ADObject -Identity $Paths.AdPath -Replace @{ gPCMachineExtensionNames = (Merge-ALExtensionNames ([string]$AdObj.gPCMachineExtensionNames) $Cse) } -Server $Domain.PDC
        $Ver = Step-ALGpoVersion $Paths $Domain
        Write-Host "  GPO computer version now $Ver"

        foreach ($Ou in $Ous) {
            if ($null -eq (Get-ALLinkState $Gpo.Id $Ou $Domain)) {
                New-GPLink -Name $P.Gpo -Target $Ou -LinkEnabled No -Server $Domain.PDC | Out-Null
                Write-Host "  linked to $Ou (DISABLED)"
            }
        }
    }

    if (-not $SkipLogSize) {
        $Servers = @($Cfg.ReferenceServer) + $Targets | Sort-Object -Unique
        Write-Host "AppLocker event log sizes on: $($Servers -join ', ')"
        Set-ALEventLogSize $Servers $Cfg.EventLogSizesMB | ForEach-Object { Write-Host "  $_" }
    }

    Write-Host "`nLinks now:"
    foreach ($Ou in $Ous) { foreach ($P in $Plan) { $G = Get-GPO -Name $P.Gpo -Server $Domain.PDC; $S = Get-ALLinkState $G.Id $Ou $Domain; Write-Host ('  {0,-8} {1,-9} {2}' -f $P.Mode, $(if ($S) { 'ENABLED' } else { 'disabled' }), $Ou) } }
    Write-Host 'Next: 3_AL_set_mode.ps1 -Mode Audit -Refresh' -ForegroundColor Green
}
finally { Stop-ALTranscript }
