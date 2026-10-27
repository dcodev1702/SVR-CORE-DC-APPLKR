# AppLocker on Server Core 2022 domain controllers

Part of [SVR-CORE-DC-APPLKR](README.md). The README and the lab run use **Windows Server 2025**. This page is for domain controllers that run **Windows Server 2022 (Server Core)**, alone or next to 2025 DCs.

> [!NOTE]
> **The steps in the README are the same on Server 2022:** same AppLocker, same policy format, same two GPOs, same scripts. Three things differ, and the scripts handle each one:
> 1. **The reference DC.** The policy is built from what the build finds on a DC's disk, so the build must scan every Windows Server version it protects. With DCs of both versions, list one DC of the other version in `ExtraReferenceServers`: the build scans it too and merges the scans. Pre-flight warns when a DC runs a version that no reference DC runs ([section 2](#2-cover-every-windows-server-version-in-the-build)).
> 2. **PowerShell 2.0.** It can still be installed on Server 2022, and it doesn't apply the Constrained Language Mode that AppLocker's script rules rely on. Pre-flight warns when it's installed. Remove it ([section 3](#3-remove-powershell-20-from-the-2022-dcs)).
> 3. **The STIG IDs.** The Server 2022 item is **WN22-00-000080 / V-254245**. `6_AL_stig_check.ps1` reports each DC under the item for its version ([section 4](#4-the-server-2022-stig-ids)).

## Contents

1. [Which case are you in?](#1-which-case-are-you-in)
2. [Cover every Windows Server version in the build](#2-cover-every-windows-server-version-in-the-build)
3. [Remove PowerShell 2.0 from the 2022 DCs](#3-remove-powershell-20-from-the-2022-dcs)
4. [The Server 2022 STIG IDs](#4-the-server-2022-stig-ids)
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

Build **20348** is Windows Server 2022; build **26100** is Windows Server 2025. `0_AL_pre-flight.ps1` shows each DC's version in its `Server` rows and compares it with the reference DCs in its `Version` rows.

| Your DCs | What to do |
|---|---|
| **All Server 2025** | Nothing on this page applies. Follow the [README](README.md). |
| **All Server 2022** | Follow the README with a **2022 DC as `ReferenceServer`** ([section 2](#all-your-dcs-run-server-2022)), and remove PowerShell 2.0 ([section 3](#3-remove-powershell-20-from-the-2022-dcs)). |
| **A mix of 2022 and 2025** | Also list one DC of the other version in **`ExtraReferenceServers`** ([section 2](#dcs-of-both-versions)), and remove PowerShell 2.0 from the 2022 DCs. |

---

## 2. Cover every Windows Server version in the build

### Why it matters

For accounts that aren't administrators, the policy allows everything under `C:\Windows` and `C:\Program Files*` **except the folders such an account can write to**. Otherwise anyone could copy a program into one of those folders and run it. AaronLocker finds those folders by scanning a DC's disk, and each build keeps the list in `Outputs\<profile>\<timestamp>\ScanResults\Writable_*.txt`.

A 2022 DC can have user-writable folders that a 2025 DC doesn't have, and the other way round. **A folder that is missing from the list stays allowed** on every DC that has it: a non-admin could copy a program there and run it, even in Enforce. Nothing breaks, so the **Audit period won't show this gap**.

The deny list works the same way. The policy denies the bypass tools (`cipher`, `runas`, `WMIC`, `MSBuild`, ...) by publisher, product and file name, at any version, but only the tools the scan found. The lab's Server Core 2025 DC has no `mshta.exe` and no `IEExec.exe` (part of .NET Framework 3.5), so a build made on it alone has no rule for either.

### All your DCs run Server 2022

Set `ReferenceServer` in `scripts\AL-Settings.psd1` to one of your 2022 DCs (the PDC emulator is a good choice) and follow the README as written. Pre-flight must show `Versions: every server checked runs the version of a reference server`. The lab verification ([README, Appendix A](README.md#appendix-a--lab-verification-2026-10-26)) ran on Server 2025, so on Server 2022 your Audit period is the proof. Don't shorten it.

### DCs of both versions

All DCs sit in the Domain Controllers OU and get the same GPO, so one policy has to fit both versions. Keep your usual `ReferenceServer` and add **one DC of the other version** to `ExtraReferenceServers` in `scripts\AL-Settings.psd1`:

```powershell
    ReferenceServer   = 'dc25-01.contoso.com'                # a Server 2025 DC: the rules are generated here
    ExtraReferenceServers = @('dc22-01.contoso.com')         # a Server 2022 DC: scanned too
```

**Step 1 — Check.** Run `.\0_AL_pre-flight.ps1`. It checks the extra reference DC the same way as the reference DC (WinRM, `FullLanguage`, an execution policy that runs unsigned scripts), then compares every DC's version with both:

| Pre-flight shows | Means | Do |
|---|---|---|
| `Versions` (OK): *every server checked runs the version of a reference server* | The build scans every version in scope | Build |
| `Version <DC>` (WARN) | That DC runs a Windows version, or an installation type (Server Core or Desktop Experience), that no reference DC runs | Add a DC like it to `ExtraReferenceServers` |
| `PowerShell 2.0 <DC>` (WARN) | The `PowerShell-V2` feature is installed on that DC | [Section 3](#3-remove-powershell-20-from-the-2022-dcs) |

To try a DC before you edit the settings: `.\0_AL_pre-flight.ps1 -ExtraReferenceServers dc22-01.contoso.com`.

**Step 2 — Build.** Run `.\1_AL_build_policy.ps1`, or add `-ExtraReferenceServers dc22-01.contoso.com` for a single run. On top of the README's [step 4](README.md#step-4--build-the-baseline), it:

1. Prepares a temporary folder on each extra reference DC too (`C:\AaronLocker-1`, `C:\AaronLocker-2`, ..., deleted afterwards). A DC that can't run AaronLocker stops the build before the first scan.
2. Scans the reference DC and each extra reference DC.
3. Merges the scans: every user-writable folder and every denied tool that **any** of them found. A merge only adds exceptions and deny rules, so the policy can only get stricter.
4. Generates the rules again on the reference DC from the merged scan, and checks that the rules carry every merged entry. If one is missing, it stops: nothing is deployed and `latest.txt` doesn't change.

The output says what the other version added, for example:

```text
Extra reference server: DC22-01 | Microsoft Windows Server 2022 Datacenter Server Core (build 20348) | ...
The extra reference servers add 2 entries to the scan of dc25-01.contoso.com (excluded folders and denied tools that the rules now carry):
  dc22-01.contoso.com | Writable_windir.txt | <a folder that only this DC makes user-writable>
  dc22-01.contoso.com | ExeDenyListData.txt | <a tool that only this DC has>
Merged scan: all 17 excluded folder(s) and 10 denied tool(s) are in the rules.
```

If the other version adds nothing, it says *the extra reference servers add nothing to the scan of …: its scan covers them*, and the rules are the same as a build without them.

| In `Outputs\<profile>\<timestamp>\` | What it is |
|---|---|
| `ScanResults\` | The merged scan the rules were built from |
| `ScanResults-<DC>\` | Each DC's own scan |
| `build-info.json` | `ExtraReferenceServers` (each DC with its version), `MergedScan.AddedByExtraServers`, and `VersionsNotScanned` |

If a DC in the target OUs runs a version that none of the scanned DCs runs, the build ends with a warning that names it (the versions come from AD). Then deploy as usual: README steps 5 and 6. If you're already in Enforce, follow *Rebuild* in [README section 12](README.md#12-ongoing-operations).

**Step 3 — Read what the other version adds.** Each added line is a folder that a non-admin can write to on that DC, or a tool that only that DC has. In `ScanResults-<DC>\Writable_Full_windir.xml` (also `_PF` and `_PF86`), every excluded folder lists the accounts that can write to it (`Grantee`). The cause is often software rather than the Windows version:

- **An agent on only some DCs** (Defender for Endpoint, the MECM client, the Nessus Agent). The merged policy already excepts the folder on every DC. To keep the DCs alike, install the same agents everywhere. A `Package\S-1-15-2-...` grantee is an app container, not a user account. In the lab, those are Defender for Endpoint folders.
- **A group that really is an administrators group.** List it in `KnownAdmins` ([README, section 11](README.md#11-who-counts-as-an-administrator)) and build again.

> [!NOTE]
> **Lab status (2026-10-27):** the lab has one Server 2025 DC and no Server 2022 DC. The merge was verified there end to end with the same DC listed again under its short name, plus a simulated second scan with one extra folder and one extra tool: both ended up in the rules, and the self-check caught a policy that lacked them. A real mix of 2022 and 2025 DCs was not available, so your first merged build and its Audit period are the proof.

The same DC listed twice (for example by its short name and by its FQDN) only costs an extra scan. The build warns that it's the same computer.

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

**Check.** `0_AL_pre-flight.ps1` reports it for every DC:

| Pre-flight shows | Means |
|---|---|
| `PowerShell 2.0 <DC>` (WARN): *installed* | A finding (WN22-00-000410). Remove it (below). |
| `PowerShell 2.0 <DC>` (OK): *not installed (PowerShell-V2 Available)* or *Removed* | Not a finding. Nothing to do. |
| No `PowerShell 2.0` row for that DC | The feature doesn't exist there. Server 2025 DCs show this. |

To check by hand instead (on the management computer):

```powershell
$Dc2022 = @(Get-ADDomainController -Filter * | Where-Object OperatingSystem -like '*2022*' | ForEach-Object HostName)
if (-not $Dc2022) { 'No Server 2022 DCs found - nothing to do in this section.' }
else {
    Invoke-Command -ComputerName $Dc2022 -ScriptBlock { Get-WindowsFeature -Name PowerShell-V2, NET-Framework-Core } |
        Sort-Object PSComputerName, Name | Format-Table PSComputerName, Name, InstallState -AutoSize
}
```

**Remove** it from one DC first, then from the rest. `-WhatIf` shows what would happen and changes nothing:

```powershell
Invoke-Command -ComputerName dc22-01.contoso.com -ScriptBlock { Uninstall-WindowsFeature -Name PowerShell-V2 -WhatIf }
Invoke-Command -ComputerName dc22-01.contoso.com -ScriptBlock { Uninstall-WindowsFeature -Name PowerShell-V2 } |
    Format-Table PSComputerName, Success, RestartNeeded, ExitCode -AutoSize
```

- Removing a feature needs no installation media.
- If `RestartNeeded` says `Yes`, restart that DC in your maintenance window, one DC at a time.
- Run pre-flight again. The DC must now show `PowerShell 2.0` OK.
- Windows PowerShell 5.1 (`powershell.exe`), WinRM and this toolkit keep working. Only a script or tool that starts `powershell.exe -Version 2` stops working.

---

## 4. The Server 2022 STIG IDs

| Requirement | Server 2025 | Server 2022 |
|---|---|---|
| Deny-all, permit-by-exception (what this toolkit does) | **WN25-00-000080 / V-277992** (CAT II) | **WN22-00-000080 / V-254245** (CAT II) |
| PowerShell 2.0 not installed ([section 3](#3-remove-powershell-20-from-the-2022-dcs)) | — (PowerShell 2.0 is no longer part of the OS) | **WN22-00-000410 / V-254278** (CAT II) |

- **WN22-00-000080:** *Windows Server 2022 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.*
- **WN22-00-000410:** *Windows Server 2022 must not have Windows PowerShell 2.0 installed.*

`6_AL_stig_check.ps1` picks the item from each DC's Windows build, read from AD when the DC can't be reached. It reports a 2022 DC under **WN22-00-000080 / V-254245** and a 2025 DC under **WN25-00-000080 / V-277992**, with one summary line per item. The check is the same on both versions: `Get-AppLockerPolicy -Effective -XML`, and an enforced, deny-by-default policy. A DC of any other Windows version gets `Not_Reviewed`, with the AppLocker result in the `Reason` column, so you can record it under that version's own STIG item.

`6_AL_stig_check.ps1` doesn't check WN22-00-000410. Record that one from pre-flight's `PowerShell 2.0` rows or from the check in [section 3](#3-remove-powershell-20-from-the-2022-dcs).

Rule IDs (`SV-...`) change when DISA revises a rule, so match on the V-ID.

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
- [ ] 2022 and 2025 DCs: one DC of the other version is in `ExtraReferenceServers`, and pre-flight shows `Versions` OK ([section 2](#dcs-of-both-versions)).
- [ ] Pre-flight shows no `PowerShell 2.0 … installed` warning ([section 3](#3-remove-powershell-20-from-the-2022-dcs)).
- [ ] 2022 results recorded: **WN22-00-000080 / V-254245** from `6_AL_stig_check.ps1`, **WN22-00-000410 / V-254278** from pre-flight or section 3 ([section 4](#4-the-server-2022-stig-ids)).
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
- This repository: AaronLocker's `Disallow PowerShell v2` rules are in the DLL collection of [`DefaultRulesWithPlaceholders.xml`](AaronLocker/AaronLocker/Support/DefaultRulesWithPlaceholders.xml). `New-ALDeployXml` in [`scripts/AL-Common.ps1`](scripts/AL-Common.ps1) empties that collection when `EnableDllRules` is `$false`. The deny list comes from [`GetExeFilesToDenyList.ps1`](Customizations/CustomizationInputs/GetExeFilesToDenyList.ps1). AaronLocker's [`Create-Policies.ps1`](AaronLocker/AaronLocker/Create-Policies.ps1) builds the rules from the scan files already in `ScanResults` when it runs without `-Rescan` (*"scanned output can be copied to another machine and rules can be maintained without needing to rescan"*); `Merge-ALScanResults` and `Get-ALMissingScanEntries` in `AL-Common.ps1` merge the scans and check the rules against them.
