# AppLocker on Server Core 2022 domain controllers

Part of [SVR-CORE-DC-APPLKR](README.md). The README and the lab run use **Windows Server 2025**. This page is for domain controllers that run **Windows Server 2022 (Server Core)**, alone or next to 2025 DCs.

> [!NOTE]
> **The steps in the README are the same on Server 2022:** same AppLocker, same policy format, same two GPOs, same scripts. Three things differ:
> 1. **The reference DC.** The policy is built from one DC's disk, so build it on a DC that runs the same Windows Server version as the DCs it protects ([section 2](#2-build-the-policy-on-a-dc-that-matches)).
> 2. **PowerShell 2.0.** It can still be installed on Server 2022, and it doesn't apply the Constrained Language Mode that AppLocker's script rules rely on. Remove it ([section 3](#3-remove-powershell-20-from-the-2022-dcs)).
> 3. **The STIG IDs.** The Server 2022 item is **WN22-00-000080 / V-254245**, not WN25-00-000080 / V-277992 ([section 4](#4-record-the-server-2022-stig-ids)).

## Contents

1. [Which case are you in?](#1-which-case-are-you-in)
2. [Build the policy on a DC that matches](#2-build-the-policy-on-a-dc-that-matches)
3. [Remove PowerShell 2.0 from the 2022 DCs](#3-remove-powershell-20-from-the-2022-dcs)
4. [Record the Server 2022 STIG IDs](#4-record-the-server-2022-stig-ids)
5. [What stays the same](#5-what-stays-the-same)
6. [AppLocker on Server Core: Microsoft's support statement](#6-applocker-on-server-core-microsofts-support-statement)
7. [Checklist](#7-checklist)
- [Sources](#sources)

---

## 1. Which case are you in?

List your DCs and their versions (on the management computer, with the RSAT Active Directory module):

```powershell
Get-ADDomainController -Filter * | Sort-Object HostName |
    Format-Table HostName, OperatingSystem, OperatingSystemVersion -AutoSize
```

Build **20348** is Windows Server 2022; build **26100** is Windows Server 2025. `0_AL_pre-flight.ps1` also shows each DC's version in its `Server` rows.

| Your DCs | What to do |
|---|---|
| **All Server 2025** | Nothing on this page applies. Follow the [README](README.md). |
| **All Server 2022** | Follow the README with a **2022 DC as `ReferenceServer`** ([section 2](#all-your-dcs-run-server-2022)). Then remove PowerShell 2.0 ([section 3](#3-remove-powershell-20-from-the-2022-dcs)) and record the 2022 STIG IDs ([section 4](#4-record-the-server-2022-stig-ids)). |
| **A mix of 2022 and 2025** | All of this page. The main extra step: [compare a build from each version](#compare-a-2022-build-with-your-2025-build) before you deploy. |

---

## 2. Build the policy on a DC that matches

### Why it matters

For accounts that aren't administrators, the policy allows everything under `C:\Windows` and `C:\Program Files*` **except the folders such an account can write to**. Otherwise anyone could copy a program into one of those folders and run it. AaronLocker finds those folders by scanning **the reference DC only**, and each build keeps the list in `Outputs\<profile>\<timestamp>\ScanResults\Writable_*.txt`.

A 2022 DC can have user-writable folders that a 2025 DC doesn't have, and the other way round. **A folder that is missing from the list stays allowed** on every DC that has it: a non-admin could copy a program there and run it, even in Enforce.

- Nothing breaks, so the **Audit period won't show this gap**.
- `4_AL_validate.ps1` checks the `ExtraAllowedPaths` folders (`C:\Admin`) on every DC, but it doesn't scan `C:\Windows` and `Program Files` on each DC.

**The deny list mostly carries over.** The policy matches the bypass tools it denies (`cipher`, `runas`, `WMIC`, `MSBuild`, ...) by publisher, product and file name, at any version. So a rule built on a 2025 DC also denies the same tool on a 2022 DC. The exception is a tool that isn't on the reference DC: the build only writes rules for the tools it finds. The lab's Server Core 2025 DC has no `mshta.exe` and no `IEExec.exe` (part of .NET Framework 3.5), so its build has no rule for either.

### All your DCs run Server 2022

Set `ReferenceServer` in `scripts\AL-Settings.psd1` to one of your 2022 DCs (the PDC emulator is a good choice) and follow the README as written. The lab verification ([README, Appendix A](README.md#appendix-a--lab-verification-2026-10-26)) ran on Server 2025, so on Server 2022 your Audit period is the proof. Don't shorten it.

### Compare a 2022 build with your 2025 build

All DCs sit in the Domain Controllers OU and get the same GPO, so one policy has to fit both versions. Build once on a DC of each version, then compare what each build excludes. A build changes nothing on the DC except a temporary folder (`C:\AaronLocker`, deleted afterwards): no policy, no permission.

The steps assume your usual reference DC runs 2025. If it runs 2022, swap the roles and make the extra settings file for a 2025 DC.

**Step 1 — Make a settings file for the 2022 build.** In the `scripts` folder:

```powershell
Copy-Item .\AL-Settings.psd1 .\AL-Settings.dc2022.psd1
notepad .\AL-Settings.dc2022.psd1
```

Change three values in the copy and save it:

```powershell
    AuditGpoName      = 'COMPARE-ONLY-2022-AUDIT'      # a name you never deploy
    EnforceGpoName    = 'COMPARE-ONLY-2022-ENFORCE'    # a name you never deploy
    ReferenceServer   = 'dc22-01.contoso.com'          # one of your Server 2022 DCs
```

A settings file named `AL-Settings.<name>.psd1` keeps its builds in their own folder (`Outputs\dc2022\`). The builds that `2_AL_create_gpos.ps1` deploys stay in `Outputs\default\`.

> [!WARNING]
> Use `AL-Settings.dc2022.psd1` **only to build and compare**: never with `2_AL_create_gpos.ps1` or `3_AL_set_mode.ps1`. The compare-only GPO names are a safety net: a mistake would create two new GPOs, linked but disabled, instead of overwriting yours.
>
> Don't make the comparison build with `1_AL_build_policy.ps1 -ComputerName <2022 DC>` and the default settings either. That build would become the newest one in `Outputs\default\`, and the next `2_AL_create_gpos.ps1` run would deploy it.

**Step 2 — Check the 2022 DC and build on it:**

```powershell
.\0_AL_pre-flight.ps1   -SettingsFile .\AL-Settings.dc2022.psd1    # must end with Pre-flight: PASSED
.\1_AL_build_policy.ps1 -SettingsFile .\AL-Settings.dc2022.psd1
```

Pre-flight reports the compare-only GPOs as not existing yet (INFO). That's expected.

Compare against a **recent** 2025 build. If your newest one is old, run `.\1_AL_build_policy.ps1` first.

**Step 3 — Compare the two builds.** Still in the `scripts` folder:

```powershell
$Build2025 = '..\Outputs\default'    # builds made with AL-Settings.psd1
$Build2022 = '..\Outputs\dc2022'     # builds made with AL-Settings.dc2022.psd1
$A = Join-Path $Build2025 (Get-Content -LiteralPath "$Build2025\latest.txt")
$B = Join-Path $Build2022 (Get-Content -LiteralPath "$Build2022\latest.txt")
$Diff = foreach ($File in 'Writable_windir.txt', 'Writable_PF.txt', 'Writable_PF86.txt', 'ExeDenyListData.txt') {
    $L25 = @(Get-Content -LiteralPath "$A\ScanResults\$File")
    $L22 = @(Get-Content -LiteralPath "$B\ScanResults\$File")
    foreach ($Line in $L22) { if ($L25 -notcontains $Line) { [pscustomobject]@{ OnlyIn = '2022 build'; File = $File; Entry = $Line } } }
    foreach ($Line in $L25) { if ($L22 -notcontains $Line) { [pscustomobject]@{ OnlyIn = '2025 build'; File = $File; Entry = $Line } } }
}
if ($Diff) { $Diff | Sort-Object OnlyIn, File | Format-Table -AutoSize -Wrap } else { 'No differences: both builds exclude the same folders and deny the same tools.' }
```

It only reads files. `Writable_*.txt` are the excluded folders. `ExeDenyListData.txt` is the deny list, one line per tool.

**Step 4 — Decide:**

| The comparison shows | Means | Do |
|---|---|---|
| `No differences` | One build fits both versions. | Keep building on your usual reference DC. |
| Lines **only in the 2022 build**, none only in the 2025 build | The 2025 build would leave those folders open, or those tools allowed, on your 2022 DCs. The 2022 build covers both versions. | Deploy a build made on the 2022 DC: set `ReferenceServer` in `AL-Settings.psd1` to that DC, then build and deploy as usual (README steps 4–5; already in Enforce? follow *Rebuild* in [README section 12](README.md#12-ongoing-operations)). |
| Lines **only in the 2025 build**, none only in the 2022 build | The 2025 build covers both versions. | Keep building on the 2025 DC. |
| Lines **on both sides** | Neither build covers both versions. | See below. |

When both sides have lines:

1. **Find out why each line differs.** In each build, `ScanResults\Writable_Full_windir.xml` (also `_PF` and `_PF86`) lists every excluded folder with the accounts that can write to it (`Grantee`). The cause is often software rather than the Windows version:
   - **An agent on only one of the two DCs** (Defender for Endpoint, the MECM client, the Nessus Agent). Build on DCs that have the same agents. A `Package\S-1-15-2-...` grantee is an app container, not a user account. In the lab, those are Defender for Endpoint folders.
   - **A group that really is an administrators group.** List it in `KnownAdmins` ([README, section 11](README.md#11-who-counts-as-an-administrator)) and build again.
2. **If differences remain,** no single build covers both versions, and the toolkit can't combine two scans yet. Build on the version most of your DCs run. Record the other version's "only in" lines as a known gap next to your STIG evidence, and plan to bring the remaining DCs to one version.

When you're done, keep `AL-Settings.dc2022.psd1` and `Outputs\dc2022\` as evidence of the comparison, or delete them.

<details>
<summary>For reference: the 16 folders the lab's Server 2025 build excludes under <code>C:\Windows</code> (2026-10-26)</summary>

```text
C:\Windows\Registration\CRMLog\*
C:\Windows\System32\Com\dmp\*
C:\Windows\System32\config\systemprofile\AppData\Local\Packages\lpacsenseimdscollector\AC\*
C:\Windows\System32\config\systemprofile\AppData\Local\Packages\lpacsensendr\AC\*
C:\Windows\System32\drivers\DriverData\*
C:\Windows\System32\drivers\DriverData:*
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\*
C:\Windows\System32\Tasks\*
C:\Windows\SYSVOL\domain\Policies\*
C:\Windows\SYSVOL\domain\Policies:*
C:\Windows\SysWOW64\Com\dmp\*
C:\Windows\SysWOW64\Tasks\*
C:\Windows\Tasks\*
C:\Windows\Temp\*
C:\Windows\tracing\*
C:\Windows\tracing:*
```

The two `lpacsense...` folders belong to Defender for Endpoint. The entries ending in `:*` cover alternate data streams on a writable folder. `Writable_PF.txt` and `Writable_PF86.txt` were empty.

</details>

---

## 3. Remove PowerShell 2.0 from the 2022 DCs

**Why:**

- For PowerShell, AppLocker's script rules are enforced by PowerShell itself. Windows PowerShell 5.1 runs a script the policy doesn't allow in **Constrained Language Mode**, and for a non-admin it runs the interactive session that way too.
- The **PowerShell 2.0 engine** is older than that behaviour, which arrived with PowerShell 5.0. A session started with `powershell.exe -Version 2` runs in full language mode, so the restriction the script rules rely on is gone.
- AaronLocker ships rules that block the 2.0 engine, but they are **DLL rules**, and this baseline turns DLL rules off (`EnableDllRules = $false`). The deployed policy doesn't block it.
- Server 2025 no longer includes PowerShell 2.0 (since the September 2025 update, KB5065426). **Server 2022 can still have it**, and DISA requires its removal anyway: **WN22-00-000410 / V-254278 (CAT II)**.

The 2.0 engine only runs where .NET Framework 3.5 is installed. Remove it either way: the STIG check looks at the `PowerShell-V2` feature, not at .NET.

**Check** every 2022 DC (on the management computer):

```powershell
$Dc2022 = @(Get-ADDomainController -Filter * | Where-Object OperatingSystem -like '*2022*' | ForEach-Object HostName)
if (-not $Dc2022) { 'No Server 2022 DCs found - nothing to do in this section.' }
else {
    Invoke-Command -ComputerName $Dc2022 -ScriptBlock { Get-WindowsFeature -Name PowerShell-V2, NET-Framework-Core } |
        Sort-Object PSComputerName, Name | Format-Table PSComputerName, Name, InstallState -AutoSize
}
```

If you have no Server 2022 DCs, it says so, and you can skip this section.

| `PowerShell-V2` shows | Means |
|---|---|
| `Installed` | A finding (WN22-00-000410). Remove it (below). |
| `Available` or `Removed` | Not a finding. Nothing to do. |
| No `PowerShell-V2` row | The feature doesn't exist on that DC. A Server 2025 DC shows this. |

**Remove** it from one DC first, then from the rest. `-WhatIf` shows what would happen and changes nothing:

```powershell
Invoke-Command -ComputerName dc22-01.contoso.com -ScriptBlock { Uninstall-WindowsFeature -Name PowerShell-V2 -WhatIf }
Invoke-Command -ComputerName dc22-01.contoso.com -ScriptBlock { Uninstall-WindowsFeature -Name PowerShell-V2 } |
    Format-Table PSComputerName, Success, RestartNeeded, ExitCode -AutoSize
```

- Removing a feature needs no installation media.
- If `RestartNeeded` says `Yes`, restart that DC in your maintenance window, one DC at a time.
- Run the check again. `PowerShell-V2` must now show `Available`.
- Windows PowerShell 5.1 (`powershell.exe`), WinRM and this toolkit keep working. Only a script or tool that starts `powershell.exe -Version 2` stops working.

---

## 4. Record the Server 2022 STIG IDs

| Requirement | Server 2025 | Server 2022 |
|---|---|---|
| Deny-all, permit-by-exception (what this toolkit does) | **WN25-00-000080 / V-277992** (CAT II) | **WN22-00-000080 / V-254245** (CAT II) |
| PowerShell 2.0 not installed ([section 3](#3-remove-powershell-20-from-the-2022-dcs)) | — (PowerShell 2.0 is no longer part of the OS) | **WN22-00-000410 / V-254278** (CAT II) |

- **WN22-00-000080:** *Windows Server 2022 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.*
- **WN22-00-000410:** *Windows Server 2022 must not have Windows PowerShell 2.0 installed.*

The Server 2022 check for the allowlisting item is the same as the 2025 one: run `Get-AppLockerPolicy -Effective -XML` and confirm that the effective policy denies by default. So `6_AL_stig_check.ps1` gives a 2022 DC the **right status**, but its output and CSV always say **WN25-00-000080 / V-277992**. When you fill in the Server 2022 checklist, record each 2022 DC's status under **V-254245**. The CSV's `Os` column shows which DCs run 2022.

Rule IDs (`SV-...`) change when DISA revises a rule, so match on the V-ID.

<details>
<summary>Optional: copy the STIG check CSV with the Server 2022 rows relabelled</summary>

Run this in the `scripts` folder after `6_AL_stig_check.ps1`. It reads the newest result and writes a copy next to it (`...-2022.csv`). The original isn't changed.

```powershell
$Csv = Get-ChildItem -Path ..\Logs -Filter '6_AL_stig_check-*.csv' |
    Where-Object Name -match '^6_AL_stig_check-\d{8}-\d{6}\.csv$' | Sort-Object Name | Select-Object -Last 1
Import-Csv -LiteralPath $Csv.FullName | ForEach-Object {
    if ($_.Os -like '*Server 2022*') {
        $_.StigId = 'WN22-00-000080'
        $_.VulnId = 'V-254245'
        $_.Title  = 'Windows Server 2022 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
    }
    $_
} | Export-Csv -LiteralPath ($Csv.FullName -replace '\.csv$', '-2022.csv') -NoTypeInformation -Encoding UTF8
```

</details>

---

## 5. What stays the same

| Area | Server 2022 and Server 2025 |
|---|---|
| AppLocker | Same feature, rule collections and policy XML. A policy from either version loads on the other; what differs is what the scan found. |
| Deployment | The same two GPOs with one link enabled, and Application Identity set to Automatic through the GPO. |
| Remoting | WinRM is on by default on both, so the scripts reach the DCs the same way. |
| PowerShell on the DCs | Windows PowerShell 5.1 on both. |
| Logs and events | The same AppLocker logs and event IDs ([README, Appendix C](README.md#appendix-c--event-ids)). |
| Server Core deny-list fix | The `Customizations` overlay works on both. |
| The process | Audit before Enforce, the review, rollback and ongoing operations ([README, sections 7, 12 and 13](README.md#7-step-by-step)). |

---

## 6. AppLocker on Server Core: Microsoft's support statement

> [!IMPORTANT]
> Microsoft's AppLocker overview says: *"AppLocker on Server Core installations isn't supported."* This applies to **Server Core 2022 and Server Core 2025 alike**. It isn't a 2022 difference.

What it means for you:

- The lab applied and enforced this policy on a Server Core 2025 DC, and the DC kept working ([README, Appendix A](README.md#appendix-a--lab-verification-2026-10-26)). On your DCs, the Audit period is the proof.
- If you open a Microsoft support case about AppLocker on these DCs, expect this statement to come up.
- Assessors may ask about it. Record it with your accepted risks (for example in the checklist comments or your POA&M), next to the Audit and Enforce evidence.

---

## 7. Checklist

- [ ] DCs and their versions listed ([section 1](#1-which-case-are-you-in)).
- [ ] Only 2022 DCs: `ReferenceServer` is a 2022 DC ([section 2](#all-your-dcs-run-server-2022)).
- [ ] 2022 and 2025 DCs: a 2022 build compared with a recent 2025 build, and the decision made ([section 2](#compare-a-2022-build-with-your-2025-build)).
- [ ] `PowerShell-V2` is `Available` or `Removed` on every 2022 DC ([section 3](#3-remove-powershell-20-from-the-2022-dcs)).
- [ ] 2022 results recorded under **WN22-00-000080 / V-254245** and **WN22-00-000410 / V-254278** ([section 4](#4-record-the-server-2022-stig-ids)).
- [ ] Microsoft's Server Core support statement recorded with your evidence ([section 6](#6-applocker-on-server-core-microsofts-support-statement)).

---

## Sources

Checked on 2026-10-27.

- Microsoft Learn: [AppLocker overview](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview#installing-applocker), *Using AppLocker on Server Core*.
- Microsoft Learn: [Script rules in AppLocker](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/script-rules-in-applocker). The script host enforces script rules; PowerShell runs blocked scripts in Constrained Language Mode.
- PowerShell Team blog: [PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) (2015). PowerShell 5 switches to Constrained Language Mode when an AppLocker policy controls scripts.
- Microsoft Learn: [Features removed in Windows Server](https://learn.microsoft.com/windows-server/get-started/removed-deprecated-features-windows-server#features-removed). Windows PowerShell 2.0 is removed from Server 2025 with the September 2025 update.
- Microsoft Learn (archive): [Installing the Windows PowerShell 2.0 Engine](https://learn.microsoft.com/powershell/scripting/windows-powershell/install/installing-the-windows-powershell-2.0-engine). The engine needs .NET Framework 2.0.50727, which .NET Framework 3.5 provides.
- Lee Holmes: [Detecting and Preventing PowerShell Downgrade Attacks](https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/) (2017). AaronLocker's deny-list script cites it as the reason it blocks the 2.0 engine.
- DISA Windows Server 2022 STIG, via STIG Viewer: [WN22-00-000080 / V-254245](https://www.stigviewer.com/stigs/microsoft_windows_server_2022/2026-05-19/finding/V-254245) and [WN22-00-000410 / V-254278](https://www.stigviewer.com/stigs/microsoft_windows_server_2022/2026-05-19/finding/V-254278).
- This repository: AaronLocker's `Disallow PowerShell v2` rules are in the DLL collection of [`DefaultRulesWithPlaceholders.xml`](AaronLocker/AaronLocker/Support/DefaultRulesWithPlaceholders.xml). `New-ALDeployXml` in [`scripts/AL-Common.ps1`](scripts/AL-Common.ps1) empties that collection when `EnableDllRules` is `$false`. The deny list comes from [`GetExeFilesToDenyList.ps1`](Customizations/CustomizationInputs/GetExeFilesToDenyList.ps1).
