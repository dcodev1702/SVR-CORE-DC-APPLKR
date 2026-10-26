# AppLocker on Windows Server 2025 (DCs and MECM-managed servers) — Audit / Enforce GPO Deployment with AaronLocker

> [!NOTE]
> This guide builds an **AppLocker baseline with [AaronLocker](https://github.com/microsoft/AaronLocker)** on a reference server and deploys it to every server in one or more OUs with **two GPOs**: one puts the servers in **Audit** (`AuditOnly`), the other in **Enforce**. Only one link is enabled at a time. It covers **Server Core**, works **without a GUI** (PowerShell only), needs **no Internet on the servers**, and accounts for **Microsoft Configuration Manager (MECM)** on the servers.
> STIG item: **WN25-00-000080 / V-277992** — *Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.* **Audit is a staging step, not compliance — the item is met when the Enforce GPO is active.**

> [!IMPORTANT]
> **Everything below was run end to end in the lab** (one Server Core 2025 domain controller, no MECM). The **Enforce** mode and **MECM** were *not* exercised there — the MECM guidance in section 9 is design analysis. **The Audit period is how you validate it in your environment. Do not skip it.**

---

## Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Folder layout and settings](#3-folder-layout-and-settings)
4. [Scripts at a glance — run order](#4-scripts-at-a-glance--run-order)
5. [No Internet — bringing the toolkit in](#5-no-internet--bringing-the-toolkit-in)
6. [Phase 1 — Prepare (Step 0)](#6-phase-1--prepare-step-0)
7. [Phase 2 — Build the baseline (Step 1)](#7-phase-2--build-the-baseline-step-1)
8. [Phase 3 — Create the GPOs and start Audit (Steps 2–4)](#8-phase-3--create-the-gpos-and-start-audit-steps-24)
9. [MECM considerations](#9-mecm-considerations)
10. [Phase 4 — The Audit period and review (Step 5)](#10-phase-4--the-audit-period-and-review-step-5)
11. [Phase 5 — Enforce (Step 3)](#11-phase-5--enforce-step-3)
12. [Ongoing operations](#12-ongoing-operations)
13. [Rollback](#13-rollback)
- [Appendix A — The same thing with plain PowerShell (no scripts)](#appendix-a--the-same-thing-with-plain-powershell-no-scripts)
- [Appendix B — Event IDs](#appendix-b--event-ids)
- [Appendix C — Troubleshooting](#appendix-c--troubleshooting)
- [Appendix D — Design decisions and limits](#appendix-d--design-decisions-and-limits)

---

## 1. Overview

```
 MANAGEMENT COMPUTER (PAW / jump host, Windows PowerShell 5.1, RSAT)         SERVERS (DCs, MECM site systems, member servers)
 ┌──────────────────────────────────────────────┐                           ┌───────────────────────────────────────────┐
 │ 0_AL_get_toolkit   AaronLocker + AccessChk   │                           │ Reference server (looks like the others)  │
 │ 0_AL_pre-flight    checks, MECM detection    │  WinRM: copy toolkit  ──► │  AaronLocker scans C:\Windows + Program   │
 │ 0_AL_secure_folders  C:\Admin (locked down)  │  ◄── rules XML + scan ─── │  Files for user-writable folders, builds  │
 │ 1_AL_build_policy  ─────────────────────────►│                           │  Audit.xml / Enforce.xml, then is deleted │
 │ 2_AL_create_gpos   Audit GPO + Enforce GPO   │                           └───────────────────────────────────────────┘
 │ 3_AL_set_mode      ONE link enabled          │   GPO (SYSVOL/AD)                       ▲ Group Policy refresh
 │ 4_AL_validate / 5_AL_review_events           │ ─────────────────────────────────────────┘
 └──────────────────────────────────────────────┘   Registry policy (SrpV2) + System Services (Application Identity = Automatic)
```

**What the baseline does** (AaronLocker, AppLocker rules, built on the server itself):

| Who | Can run |
|---|---|
| **SYSTEM and local Administrators** | everything (the AppLocker default rule) |
| **Everyone else** (users, `NETWORK SERVICE`, `LOCAL SERVICE`, `NT SERVICE\*`, non-admin service accounts) | files under `C:\Windows` and `C:\Program Files*` — **except** the user-writable subfolders that the scan found and a deny list of bypass tools (`mshta`, `wmic`, `cipher`, `runas`, `InstallUtil`, `MSBuild`, …) — plus SYSVOL/NETLOGON, the Defender platform folder, and `C:\Admin\*` |

**Choices made here:** DLL rules off (not needed for the STIG item) · Windows packaged-app rules left as AaronLocker builds them · two GPOs, exactly one link enabled · the Application Identity service is set to Automatic *by the GPO* (it is a protected service; `sc.exe`/`Set-Service` may be refused) · nothing is downloaded by the servers.

> [!WARNING]
> **Be realistic about what this protects.** Because SYSTEM and local administrators are allowed everywhere, AppLocker here stops *non-admin* and *service-account* code from running unapproved software — it does **not** stop an administrator. It satisfies WN25-00-000080 (an allowlisting program in a deny-by-default configuration), but it is not a hard containment boundary on a DC. Keep the administrative tier tight.

---

## 2. Prerequisites

| Item | Detail |
|---|---|
| **Management computer** | Windows 10/11 or Server with **Windows PowerShell 5.1** (`powershell.exe`; the scripts stop in PowerShell 7), RSAT **Group Policy Management** and **Active Directory** modules, and the built-in `AppLocker` module |
| **Account** | Domain Admin (or rights to create/link GPOs, write SYSVOL, and WinRM-admin on the servers) |
| **WinRM** | Enabled on every server (default on Server 2025). Test: `Invoke-Command -ComputerName <server> { $env:COMPUTERNAME }` |
| **Reference server** | A server that looks like the ones it represents — same roles, same software, **MECM client installed**. Language mode `FullLanguage` (no WDAC/AppLocker already restricting PowerShell) |
| **Toolkit** | AaronLocker repo + Sysinternals **AccessChk.exe** — brought in by hand when there is no Internet (section 5) |
| **Servers** | **No Internet needed.** They only receive a temporary folder over WinRM (`C:\AaronLocker`, deleted at the end) and Group Policy |

---

## 3. Folder layout and settings

```
C:\WDAC\AppLocker\                      (copy this whole folder to the management computer; any path works)
  README.md
  scripts\    AL-Settings.psd1  AL-Common.ps1  0_…  1_…  2_…  3_…  4_…  5_…
  Customizations\CustomizationInputs\   GetExeFilesToDenyList.ps1 (Server Core fix)  GetSafePathsToAllow.ps1 (ExtraAllowedPaths hook)
  AaronLocker\AaronLocker\              the toolkit (+ AccessChk.exe)       ← step 0 / brought in by hand
  Outputs\<profile>\<timestamp>\        rules XML, scan results, build-info.json, *-Deploy.xml, events-*.csv
  Logs\                                 one transcript per script run
```

All scripts read **`scripts\AL-Settings.psd1`**. Edit it once:

| Setting | Meaning |
|---|---|
| `AuditGpoName` / `EnforceGpoName` | The two GPOs (defaults `JMSC-DC-AppLocker - Audit` / `- Enforce`) |
| `TargetOUs` | OUs (distinguished names) whose servers get the policy; empty = **Domain Controllers** |
| `ReferenceServer` | FQDN of the server the baseline is built on |
| `ExtraAllowedPaths` | Extra folders non-admin accounts may run from. **Default `C:\Admin\*`.** Each must be admin-only (checked) |
| `SecureFolders` | Folders `0_AL_secure_folders.ps1` creates and locks down (default `C:\Admin`) |
| `AccessChkSha256` | Optional: pin the hash of the AccessChk you brought in |
| `EnableDllRules` | `$false` (default) = DLL collection off |
| `EventLogSizesMB` | AppLocker log sizes applied to the servers (default EXE and DLL 100 MB, others 20 MB) |

**Several server classes** (DCs, MECM site systems, other servers)? Copy the file (`AL-Settings.mecm.psd1`), change it, and pass **`-SettingsFile`** to every script. Each file keeps its own `Outputs\<profile>` folder and its own GPO pair.

Run the scripts like this (from the `scripts` folder):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\0_AL_pre-flight.ps1
# files copied from a zip / another computer may be blocked:  Get-ChildItem C:\WDAC\AppLocker -Recurse | Unblock-File
```

---

## 4. Scripts at a glance — run order

| Step | Script | What it does | Changes anything? |
|---|---|---|---|
| 0 | `0_AL_get_toolkit.ps1` | Gets/imports AaronLocker + AccessChk, verifies the Microsoft signature (and optional pinned hash) | local files only |
| 0 | `0_AL_pre-flight.ps1` | Modules, domain/GPO rights, OUs and servers, toolkit, existing policy, **MECM detection**, **non-admin services outside Windows/Program Files**, extra-path ACLs | read-only |
| 0 | `0_AL_secure_folders.ps1` | Creates `C:\Admin` (and other `SecureFolders`) on every server and restricts it to SYSTEM + Administrators | servers (folder + ACL) |
| 1 | `1_AL_build_policy.ps1` | Builds the baseline **on the reference server**, brings the XML back, removes its temporary folder | no (read-only scan) |
| 2 | `2_AL_create_gpos.ps1` | Creates/updates the **Audit** and **Enforce** GPOs and links both (**new links disabled**); enlarges the AppLocker logs | domain (GPOs), servers (log size) |
| 3 | `3_AL_set_mode.ps1 -Mode Audit\|Enforce\|Off [-Refresh]` | Enables exactly one link (or none) and optionally refreshes the servers | domain (links) |
| 4 | `4_AL_validate.ps1` | Checks GPOs, links, rules, service, effective policy, decisions, MECM files, extra paths, DC services, events | read-only |
| 5 | `5_AL_review_events.ps1` | Summarises Audit/Blocked events (flags MECM), exports a CSV | read-only |

---

## 5. No Internet — bringing the toolkit in

The servers and domain controllers never need Internet. Only **step 0 (`0_AL_get_toolkit.ps1`) can reach out, and only from the management computer.** If the management computer has no Internet either, stage the two files by hand:

1. **On a computer with Internet**, download
   - AaronLocker: <https://github.com/microsoft/AaronLocker/archive/HEAD.zip>
   - AccessChk: <https://download.sysinternals.com/files/AccessChk.zip> → extract **`accesschk64.exe`**
2. **Verify AccessChk** and record its hash:
   ```powershell
   $s = Get-AuthenticodeSignature .\accesschk64.exe
   $s.Status                      # must be: Valid
   $s.SignerCertificate.Subject   # must contain: O=Microsoft Corporation
   (Get-FileHash .\accesschk64.exe -Algorithm SHA256).Hash     # note it; optionally put it in AL-Settings.psd1 -> AccessChkSha256
   ```
3. **Move both files** across your approved path (removable media, file transfer zone).
4. **On the management computer**, import them (the script re-verifies the signature and the pinned hash, and refuses a bad file):
   ```powershell
   .\0_AL_get_toolkit.ps1 -AaronLockerZip D:\Media\AaronLocker-main.zip -AccessChkPath D:\Media\accesschk64.exe
   ```
   Or copy the folders into place yourself (`AaronLocker\AaronLocker\…` and `AaronLocker\AaronLocker\AccessChk.exe`) and run `.\0_AL_get_toolkit.ps1` with no parameters to verify them.
5. Copying the **entire** `AppLocker` folder (already containing the toolkit) to another management computer works too: run `Unblock-File` on it, then `0_AL_pre-flight.ps1`.

`1_AL_build_policy.ps1` copies `AccessChk.exe` to the reference server over WinRM — there is no download on the server. **Do not run AaronLocker's `Support\DownloadAccesschk.ps1`.**

---

## 6. Phase 1 — Prepare (Step 0)

### 6.1 Toolkit
```powershell
.\0_AL_get_toolkit.ps1            # Internet on the management computer; see section 5 otherwise
```
Expected: `AccessChk.exe: Microsoft-signed, version 6.15 …` and `Toolkit ready`.

### 6.2 Edit the settings
`AL-Settings.psd1`: set `ReferenceServer`, `TargetOUs` (empty = Domain Controllers), the GPO names, and `ExtraAllowedPaths` (section 9.3 for MECM/SQL on another drive).

### 6.3 Pre-flight
```powershell
.\0_AL_pre-flight.ps1
```
Fix every **FAIL**. Read every **WARN**:

| Output | Means | Do |
|---|---|---|
| `MECM client …` / `MECM site server …` | Configuration Manager found on that server | section 9 |
| `Non-admin service outside Windows/Program Files` | A running service under `NETWORK SERVICE`, `NT SERVICE\…` or a service account runs a binary from another folder — it would be **blocked in Enforce** | add its folder to `ExtraAllowedPaths` (admin-only!) |
| `Local AppLocker policy …` | A local policy already exists (merges with the GPO). MECM's managed-installer rules are expected here | section 9.4 |
| `Extra path missing` | e.g. `C:\Admin` does not exist on that server | step 6.4 |
| `Extra path writable` | **FAIL** — a path rule on a writable folder is a bypass | step 6.4 `-Fix` |

### 6.4 C:\Admin (and any other folder you create yourself)
`C:\Admin\*` is allowed for **every user**. Any authenticated user can create a folder directly under `C:\`, and a *new* folder under `C:\` inherits *Authenticated Users: Modify* — so until an administrator creates `C:\Admin` with a locked-down ACL, a user could create it first and run code from it. Create and lock it on every server in scope **before** the policy is used:

```powershell
.\0_AL_secure_folders.ps1            # missing folders: created, SYSTEM + Administrators only; existing ones are reported
.\0_AL_secure_folders.ps1 -Fix       # also replace the permissions of an existing, writable folder
```
By hand, on a server:
```powershell
New-Item C:\Admin -ItemType Directory
icacls C:\Admin /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"     # SYSTEM + Administrators only
```
Never give Users/Authenticated Users any write access under `C:\Admin`; the build and the validation check this on every run.

---

## 7. Phase 2 — Build the baseline (Step 1)

```powershell
.\1_AL_build_policy.ps1                       # uses ReferenceServer from the settings
.\1_AL_build_policy.ps1 -ComputerName srv01.contoso.com
```
What happens: verifies AccessChk → copies the toolkit + `Customizations` to `C:\AaronLocker` on the reference server → writes `ExtraAllowedPaths` and **stops if any is writable by non-admins** → runs `Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan` there (several minutes: it scans `C:\Windows` and `Program Files` with AccessChk) → copies the results to `Outputs\<profile>\<timestamp>\` → deletes `C:\AaronLocker` from the server.

Result files: `AppLockerRules-<ts>-Audit.xml`, `…-Enforce.xml`, `ScanResults\Writable_*.txt` (the user-writable folders excluded from the allow rules), `build-info.json`. Harmless warnings: `FILE SYSTEM OBJECT DOES NOT EXIST …OneDrive` (a desktop-only sample).

> [!NOTE]
> **Server Core / Server 2025:** several desktop binaries on AaronLocker's deny list (e.g. `mshta.exe`) are not installed, which makes the stock script fail. `Customizations\CustomizationInputs\GetExeFilesToDenyList.ps1` lists only files that exist. The scripts overlay that file automatically — do not edit the toolkit copy.

---

## 8. Phase 3 — Create the GPOs and start Audit (Steps 2–4)

```powershell
.\2_AL_create_gpos.ps1            # Y/N confirmation; -NoConfirm for automation
.\3_AL_set_mode.ps1 -Mode Audit -Refresh
.\4_AL_validate.ps1
```
`2_AL_create_gpos.ps1` turns each AaronLocker file into `…-Deploy.xml` (**Audit**: every collection `AuditOnly`; **Enforce**: every collection `Enabled`; DLL collection emptied and `NotConfigured`), writes it into the GPO with `Set-AppLockerPolicy -Ldap`, adds **System Services → Application Identity = Automatic** (`GptTmpl.inf`), fixes the CSE list, raises the GPO version, and links the GPO to every target OU **disabled**. Re-running it after a new build updates both GPOs in place.

`3_AL_set_mode.ps1 -Mode Audit -Refresh` enables the Audit link, disables the Enforce link, and runs `gpupdate` twice on each server (the first refresh makes the server start Application Identity, the second loads the rules). Without `-Refresh`, servers apply it at the next refresh (DCs every 5 minutes, member servers every 90–120 minutes) or at boot.

`4_AL_validate.ps1` should end with **All checks passed**: GPOs and versions, one active link, rules in the GPO, `AppIDSvc Running / Auto`, effective policy `Exe/Msi/Script/Appx = AuditOnly` and `Dll = NotConfigured`, sample decisions, DC services, extra paths admin-only, and event counts.

---

## 9. MECM considerations

> [!NOTE]
> Design analysis, **not lab-tested against a live MECM** (the lab DC has none). The Audit period (section 10) is the proof. Where a statement is a judgement rather than a fact, it says so.

### 9.1 What the baseline already covers
- **Everything MECM runs as SYSTEM** — the client agent (`CcmExec.exe`), application / package / script / configuration-baseline execution out of `C:\Windows\ccmcache`, client install and upgrade (`C:\Windows\ccmsetup`), software-update installs, in-place-upgrade task sequences, and the site-server components that run as LocalSystem. SYSTEM and local Administrators are allowed everywhere. **MECM scripts that run as SYSTEM stay in Full Language mode.**
- **MECM files under `C:\Windows\CCM` and `C:\Program Files\…`** for everyone — except user-writable subfolders, which the scan finds and excludes (they appear in `Writable_windir.txt`; `1_AL_build_policy.ps1` lists any `ccm`/`sms` ones it finds).
- **MSI installers in `C:\Windows\ccmcache`** — AaronLocker ships that path rule.

### 9.2 What can break (accounts that are *not* administrators)
1. **Services running as `NETWORK SERVICE`, `LOCAL SERVICE`, `NT SERVICE\…`, a gMSA or any non-admin account from a folder outside Windows / Program Files.** Typical: MECM, SQL Server, WSUS, or IIS content installed on **`D:\`**. Pre-flight lists them (`Non-admin service outside Windows/Program Files`). Add the folder to `ExtraAllowedPaths` (it must be admin-only).
2. **Software deployed in the *user* context, or run from a distribution point (UNC path)** — uncommon on servers. If you use it, allow the share as an `ExtraAllowedPaths` entry (UNC allowed; must be read-only for users).
3. **Scripts launched by a non-admin account** (monitoring, backup, SQL Agent jobs) — script rules follow the same logic (Windows/Program Files for everyone, anything for admins). They show up as `8006` events in Audit.

### 9.3 How to handle it
1. **Pick the reference server correctly** and have the **MECM client installed** on it. **Site systems (site server, MP, DP, SUP/WSUS, SQL) are a different class** — give them their own `AL-Settings.<class>.psd1`, their own reference server (a site server), their own `TargetOUs` and GPO pair.
2. `ExtraAllowedPaths` example when MECM and SQL live on `D:`:
   ```powershell
   ExtraAllowedPaths = @('C:\Admin\*', 'D:\Program Files\Microsoft Configuration Manager\*', 'D:\Program Files\Microsoft SQL Server\*')
   ```
   Re-run `0_AL_pre-flight.ps1` (checks they are admin-only) and `1_AL_build_policy.ps1`.
3. **Audit across a full cycle**: a patch cycle (software updates), a software deployment, a baseline/CI evaluation, hardware/software inventory, a client upgrade if you can, backup and SQL maintenance jobs, monthly reboot.
4. `5_AL_review_events.ps1` flags MECM-related items. Files run by `NETWORK SERVICE` / `NT SERVICE\…` / gMSA accounts that would be blocked need a path rule; anything run by SYSTEM or an administrator would never be blocked.
5. **Pilot first** on a non-production OU, then production. Do not enforce on the site server or SQL until Audit is clean.

### 9.4 Managed installer (WDAC) — keep one source
MECM's *managed installer* feature (a WDAC feature) works through a **`ManagedInstaller` AppLocker rule collection** on the client. AppLocker merges the **local** policy and **domain GPO** policies into the effective policy. These GPOs contain **no** `ManagedInstaller` collection (`New-ALDeployXml` stops if one appears), so they do not collide with MECM's. Rules:
- If the managed-installer client setting is **on**, leave it to MECM; do not put a `ManagedInstaller` collection in these GPOs.
- These servers get **AppLocker**, not WDAC, so the managed-installer setting is normally off for them.
- Compare sources when in doubt: `Get-AppLockerPolicy -Local -Xml` vs `Get-AppLockerPolicy -Effective -Xml`. Pre-flight warns when a local policy exists.

### 9.5 Nothing to change in MECM
MECM does not manage this policy and needs no client-setting change. The GPO is authoritative; do not also push AppLocker through a compliance setting.

---

## 10. Phase 4 — The Audit period and review (Step 5)

Leave **Audit** on for **at least one full patch/maintenance cycle (2–4 weeks is typical)**. AppLocker logs *allowed* runs too (8002/8005), so the logs are large; the sizes are set by step 2.

```powershell
.\5_AL_review_events.ps1 -Days 14          # summary + Outputs\<profile>\events-<ts>.csv
.\4_AL_validate.ps1                        # health check any time
```
Read the summary (most frequent first): `Result` is `Audit (would be blocked)` (8003/8006/8021) or `BLOCKED` (8004/8007/8022); `User` is the account; `MECM` marks MECM paths. For each item decide:

| Finding | Action |
|---|---|
| Run by a **non-admin account**, from a **fixed admin-only folder** you trust (agent, monitoring, MECM/SQL on `D:`) | add the folder to `ExtraAllowedPaths`, rebuild |
| A **signed** program you trust in a user-writable location | add a publisher rule: `AaronLocker\CustomizationInputs\TrustedSigners.ps1` (copy the edited file into `Customizations\CustomizationInputs\` so it survives a re-download), rebuild |
| Run by **SYSTEM / an administrator** | nothing — never blocked |
| Unknown / unwanted | leave it; that is what Enforce is for |

After any change: `1_AL_build_policy.ps1` → `2_AL_create_gpos.ps1` (updates both GPOs in place; links keep their state) → `3_AL_set_mode.ps1 -Mode Audit -Refresh` → repeat until the review is quiet. `AaronLocker\Compare-Policies.ps1` shows what changed between two builds.

---

## 11. Phase 5 — Enforce (Step 3)

Only after a clean Audit period, on a **pilot OU first**:

```powershell
.\3_AL_set_mode.ps1 -TargetOU 'OU=Pilot,OU=Servers,DC=contoso,DC=com' -Mode Enforce -Refresh   # Y/N prompt lists the servers
.\4_AL_validate.ps1 -TargetOU 'OU=Pilot,OU=Servers,DC=contoso,DC=com' -Mode Enforce
```
Effective policy must now read `Exe/Msi/Script/Appx = Enabled`, `Dll = NotConfigured`. Watch `8004/8007` for a few days (`5_AL_review_events.ps1`), including a reboot and a patch cycle, then repeat for production. **DCs last**, and keep a way back (section 13) — a blocked service on the only DC hurts.

---

## 12. Ongoing operations

| Event | Do |
|---|---|
| **New software / agent / MECM role move** | Audit first if possible, then add its folder or publisher and rebuild (sections 9.3, 10) |
| **Monthly patching** | Nothing — Microsoft-signed content under `C:\Windows` is allowed by path. Watch `5_AL_review_events.ps1` after the first cycle |
| **New server in an OU** | It gets the active GPO at its next refresh (two refreshes or a reboot before the rules load); run `0_AL_secure_folders.ps1` for `C:\Admin`, then `4_AL_validate.ps1` |
| **Rebuild** | `1_AL_build_policy.ps1` → `2_AL_create_gpos.ps1`. Keep the previous `Outputs\<profile>\<ts>` folder |
| **After editing toolkit/customization files** | Nothing special; re-run `0_AL_pre-flight.ps1` |

---

## 13. Rollback

| Situation | Command |
|---|---|
| Enforce blocked something | `.\3_AL_set_mode.ps1 -Mode Audit -Refresh -NoConfirm` (back to log-only) |
| Remove AppLocker entirely | `.\3_AL_set_mode.ps1 -Mode Off -Refresh -NoConfirm` (the STIG item becomes a finding again) |
| Console access to a locked-out server | Administrators and SYSTEM are allowed everywhere, so `gpupdate`, PowerShell and `Invoke-Command` keep working for an admin. Run `3_AL_set_mode.ps1 -Mode Audit -Refresh` (or `Off`) from the management computer; on the server itself, `gpupdate /force` applies it |
| Remove the GPOs | `Remove-GPLink` for both, then `Remove-GPO` — after setting Off and letting the servers refresh |

Administrators and SYSTEM are allowed to run everything, so a policy mistake cannot normally lock an admin out; the AppLocker logs are the first place to look.

---

## Appendix A — The same thing with plain PowerShell (no scripts)

The scripts only wrap these steps. Useful if you have to do one piece by hand.

**1. Build on the reference server** (copy the `AaronLocker\AaronLocker` folder + `AccessChk.exe` there, e.g. to `C:\AaronLocker`):
```powershell
# put your ExtraAllowedPaths (one per line) in C:\AaronLocker\CustomizationInputs\ExtraAllowedPaths.txt, e.g. C:\Admin\*
# copy Customizations\CustomizationInputs\* over C:\AaronLocker\CustomizationInputs\ (Server Core deny-list fix + extra-paths hook)
Set-Location C:\AaronLocker
.\Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan      # -> .\Outputs\AppLockerRules-<ts>-Audit.xml and -Enforce.xml
```
**2. Switch the DLL collection off** (management computer):
```powershell
[xml]$d = Get-Content .\AppLockerRules-<ts>-Audit.xml -Raw
$dll = $d.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'Dll'
$dll.RemoveAll(); $dll.SetAttribute('Type','Dll'); $dll.SetAttribute('EnforcementMode','NotConfigured')
$d.Save('C:\Temp\Audit-Deploy.xml')          # same for the Enforce file (all other collections stay Enabled)
```
**3. Create the GPO and write the rules:**
```powershell
$pdc = (Get-ADDomain).PDCEmulator
$gpo = New-GPO -Name 'JMSC-DC-AppLocker - Audit' -Server $pdc
Set-AppLockerPolicy -XmlPolicy C:\Temp\Audit-Deploy.xml -Ldap "LDAP://$pdc/$($gpo.Path)"
```
**4. Application Identity = Automatic via the GPO** (System Services; write `GptTmpl.inf` in UTF-16 under the GPO's `Machine\Microsoft\Windows NT\SecEdit\`):
```
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Service General Setting]
"AppIDSvc",2,""
```
Then add `[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]` to the GPO's `gPCMachineExtensionNames` and raise `versionNumber` (AD) and `Version=` (GPT.INI) — `Merge-ALExtensionNames` and `Step-ALGpoVersion` in `AL-Common.ps1` do exactly this.
**5. Link and choose the mode:**
```powershell
$ou = (Get-ADDomain).DomainControllersContainer
New-GPLink -Name 'JMSC-DC-AppLocker - Audit'   -Target $ou -LinkEnabled Yes
New-GPLink -Name 'JMSC-DC-AppLocker - Enforce' -Target $ou -LinkEnabled No
Set-GPLink -Name 'JMSC-DC-AppLocker - Enforce' -Target $ou -LinkEnabled No    # disable first, then enable the other
Invoke-Command -ComputerName srv01 { gpupdate /target:computer /force; Start-Sleep 10; gpupdate /target:computer /force }
```
**6. Check a server:**
```powershell
Invoke-Command -ComputerName srv01 {
  Get-Service AppIDSvc | Select-Object Status, StartType
  [xml]$p = Get-AppLockerPolicy -Effective -Xml; $p.AppLockerPolicy.RuleCollection | Select-Object Type, EnforcementMode
  Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-AppLocker/EXE and DLL'; Id=8003,8004 } -MaxEvents 50
  Test-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -Path C:\Windows\System32\cmd.exe -User Everyone
}
```
**Size the logs** (`wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:104857600`).

---

## Appendix B — Event IDs

| Log (`Microsoft-Windows-AppLocker/…`) | Allowed | **Audit** (would be blocked) | **Blocked** |
|---|---|---|---|
| `EXE and DLL` | 8002 | **8003** | **8004** |
| `MSI and Script` | 8005 | **8006** | **8007** |
| `Packaged app-Execution` | 8020 | **8021** | **8022** |

`8001` = *The AppLocker policy was applied successfully to this computer.* Each event carries the file, the rule that matched, the account (SID) and the publisher (FQBN). Also see `Microsoft-Windows-AppID/Operational`.

---

## Appendix C — Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Scripts stop with *run in Windows PowerShell 5.1* | You are in PowerShell 7 — use `powershell.exe` |
| `Cannot find path …\mshta.exe` during the build | The stock deny list on Server Core. The `Customizations` overlay fixes it; make sure the `Customizations` folder is next to `scripts` |
| `AccessChk.exe — missing / signature … / SHA-256 … does not match` | Bring it in by hand and import it (section 5); check `AccessChkSha256` |
| Build stops: *ExtraAllowedPaths folder is writable by non-admins* | Lock it: `0_AL_secure_folders.ps1 -Fix`, or fix the ACL; never allow a writable folder |
| `Application Identity` Stopped / Manual after the GPO applied | Run `gpupdate /force` once or twice, or reboot; check `4_AL_validate.ps1`. A GPP *Services* item does **not** work for this protected service — the GPO must use System Services (the script does) |
| Effective policy empty after the first refresh | The service had just started: refresh again (`3_AL_set_mode.ps1 -Refresh` does it twice) |
| No events at all | Nothing ran that is logged yet, or the service is not running. Run a program on the server and re-check `8001/8002` |
| `Both links enabled` | Run `3_AL_set_mode.ps1 -Mode Audit` (or Enforce): it disables one link before enabling the other |
| `Local AppLocker policy … rule(s)` warning | A local policy merges with the GPO. Expected for MECM managed-installer rules; otherwise review `Get-AppLockerPolicy -Local -Xml` |
| A script in Enforce runs in *Constrained Language* | It was not allowed by a script rule (non-admin, outside Windows/Program Files). Fix via path/publisher rule |
| `WinRM` errors | `Enable-PSRemoting` on the server; firewall 5985; use FQDNs |

---

## Appendix D — Design decisions and limits

- **Built on the server itself** because the rules depend on its disk (user-writable folders, tools present). Build one baseline per server class; the reference must resemble the class.
- **Two GPOs, one enabled link** — the same pattern as the WDAC GPO deployment (`C:\WDAC\GPO`) — so Audit/Enforce never merge and switching is one command. Both GPOs carry the full rule set and the service setting.
- **DLL rules off** — not required by WN25-00-000080; they add overhead and a high rule-maintenance burden. `EnableDllRules = $true` switches them on (`AuditOnly`/`Enabled` like the rest).
- **AaronLocker is not maintained since 2022.** It is only used to *generate XML*; the deployment (GPO, link, service) is plain Group Policy and `Set-AppLockerPolicy`. Pin what you tested: keep each `Outputs\<profile>\<ts>` folder.
- **Administrators are allowed everywhere** (AppLocker default rule), so this does not constrain an admin; it constrains non-admin users and service accounts.
- **Audit mode logs allowed executions too**, which is why the logs are enlarged (`EventLogSizesMB`). Forward the AppLocker logs with Windows Event Forwarding / your SIEM if you need history.
- **Verified in the lab:** pre-flight, build on a Server Core 2025 DC (also the failure on `mshta.exe` and the cleanup), both GPOs, link switching (Audit ⇄ Off), service start via GPO, effective policy, event logging, reboot persistence, the writable-extra-path stop. **Not verified:** Enforce, MECM, more than one server, a non-admin 8003/8004 event.
