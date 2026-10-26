# SVR-CORE-DC-APPLKR — AppLocker on Windows Server 2025 domain controllers (Server Core, no Internet)

> [!NOTE]
> This toolkit builds an **AppLocker allowlist with [AaronLocker](https://github.com/microsoft/AaronLocker)** on a reference domain controller and deploys it to every DC through **two GPOs**: one puts the DCs in **Audit** (`AuditOnly`), the other in **Enforce**. Exactly one link is enabled at a time. It runs on **Server Core**, needs **no GUI**, works in a network that is **disconnected from the Internet** (everything it needs is in this repository), and accounts for **MECM**, **Tenable Nessus** and **`C:\Admin`** on the DCs. **DLL rules stay off.**
>
> STIG item: **WN25-00-000080 / V-277992 (CAT II)** — *Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.* **Audit is a staging step, not compliance: the item is met only while the Enforce GPO is active.**

> [!IMPORTANT]
> **Run end to end in the lab on 2026-10-26** (one Server Core 2025 domain controller): build → GPOs → Audit → review → **Enforce** → STIG check. Result: **WN25-00-000080 / V-277992 = NotAFinding**, `dcdiag` 26/26 passed in Enforce, 0 blocked events ([Appendix A](#appendix-a--lab-verification-2026-10-26)). The lab has **no MECM and no Nessus**: those sections are design analysis checked against Microsoft documentation. **The Audit period in your network is the proof — do not skip it.**

---

## Contents

1. [How it works](#1-how-it-works)
2. [What is in this repository](#2-what-is-in-this-repository)
3. [Prerequisites](#3-prerequisites)
4. [Bring the repository into the disconnected network](#4-bring-the-repository-into-the-disconnected-network)
5. [Configure `AL-Settings.psd1`](#5-configure-al-settingspsd1)
6. [Run order at a glance](#6-run-order-at-a-glance)
7. [Step by step](#7-step-by-step)
8. [Domain controller considerations](#8-domain-controller-considerations)
9. [MECM (Configuration Manager)](#9-mecm-configuration-manager)
10. [Tenable Nessus](#10-tenable-nessus)
11. [Who counts as an administrator](#11-who-counts-as-an-administrator)
12. [Ongoing operations](#12-ongoing-operations)
13. [Rollback](#13-rollback)
- [Appendix A — Lab verification (2026-10-26)](#appendix-a--lab-verification-2026-10-26)
- [Appendix B — The same thing by hand](#appendix-b--the-same-thing-by-hand)
- [Appendix C — Event IDs](#appendix-c--event-ids)
- [Appendix D — Troubleshooting](#appendix-d--troubleshooting)
- [Appendix E — Design decisions and limits](#appendix-e--design-decisions-and-limits)

---

## 1. How it works

![Architecture: the management computer builds the AppLocker baseline on a reference DC and publishes an Audit GPO and an Enforce GPO, both linked to the Domain Controllers OU with one link enabled; the DCs apply the active GPO and the Application Identity service enforces it; the lower panel shows the Audit-to-Enforce methodology and the STIG outcome for WN25-00-000080 / V-277992](images/DC-AppLocker-Architecture.png)

<sub>Source: [`images/DC-AppLocker-Architecture.svg`](images/DC-AppLocker-Architecture.svg) · 1600 × 1853. The PNG is rendered from the SVG at 2x: edit the spec or the SVG, then re-render the PNG, and keep both.</sub>

### What the policy allows

| Who | May run |
|---|---|
| **SYSTEM and elevated administrators** | Everything (AppLocker default rule *All files* for `BUILTIN\Administrators`). |
| **Everyone else** (non-admin accounts, members of Server/Backup/Print/Account Operators, and **non-elevated** administrator sessions) | Files under `C:\Windows` and `C:\Program Files*` — **except** the user-writable subfolders the scan found (e.g. `C:\Windows\Temp`, `C:\Windows\Tasks`, `SYSVOL\domain\Policies`) and a deny list of bypass tools (`cipher`, `runas`, `WMIC`, `MSBuild`, `InstallUtil`, `RegAsm`, `RegSvcs`, `PresentationHost`, `Microsoft.Workflow.Compiler`) — plus `\\<domain>\SYSVOL` / `\\<domain>\NETLOGON`, the Defender platform folder, `C:\Admin\*`, and Microsoft-signed installers and scripts. Nothing else — **not `C:\Temp`, not a user profile, not `C:\Sysmon`**. |

### Who AppLocker restricts here

- **By default, AppLocker only applies to code running in a user's context.** Services started by the Service Control Manager are **not** evaluated unless the policy turns on *services enforcement*, which this baseline does not ([Microsoft Learn — AppLocker rule collection extensions](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/rule-collection-extensions)). That is why the MECM client, a Nessus Agent, Defender, Sysmon and the AD DS / DNS / KDC / DFSR services are not affected.
- A process that a service starts under a **new token** can still be evaluated: the lab logged Defender for Endpoint helpers (`SenseIMDSCollector.exe` as SYSTEM, `SenseNdr.exe` as LOCAL SERVICE) — allowed, because they live in `Program Files`.
- **UAC matters.** A non-elevated administrator session (UAC filtered token) gets the *non-admin* rules. WinRM / `Invoke-Command` and *Run as administrator* sessions are elevated and match the administrator rule.

> [!WARNING]
> **Be realistic about what this protects.** Elevated administrators and SYSTEM may run anything, so AppLocker here stops *non-admin* and *non-elevated* code from running unapproved software — it does **not** contain an administrator. It satisfies WN25-00-000080 (an allowlist in a deny-by-default configuration), but it is not a containment boundary on a DC. Keep the administrative tier tight.

### The deployed baseline (lab build)

| Collection | Mode in Audit / Enforce | Rules | What they are |
|---|---|---|---|
| **Exe** | AuditOnly / **Enabled** | 10 | Administrators: all files · Everyone: `%PROGRAMFILES%\*`, `%WINDIR%\*` (minus user-writable folders and the deny list), `\\<domain>\netlogon\*`, `\\<domain>\sysvol\*`, Defender platform folder, `C:\Admin\*` · Microsoft Teams publisher (AaronLocker default, harmless) · deny old BgInfo · AaronLocker build-timestamp rule (inert) |
| **Msi** | AuditOnly / **Enabled** | 5 | `%WINDIR%\ccmcache\*` (MECM), `%WINDIR%\Installer\*`, Administrators: all, Microsoft-signed MSI, Teams |
| **Script** | AuditOnly / **Enabled** | 9 | Same paths as Exe, Administrators: all, Microsoft-signed scripts, Teams |
| **Appx** | AuditOnly / **Enabled** | 1 | All signed packaged apps (default rule) |
| **Dll** | **NotConfigured** / **NotConfigured** | 0 | **DLL rules off** — not required by the STIG item (`EnableDllRules = $false`) |

Both GPOs also set **System Services → Application Identity = Automatic** (`GptTmpl.inf`). Application Identity is a protected service; `sc.exe` / `Set-Service` / a GPP Services item cannot change it reliably, the System Services setting can.

---

## 2. What is in this repository

```
SVR-CORE-DC-APPLKR\                     copy anywhere on the management computer, e.g. C:\SVR-CORE-DC-APPLKR
  README.md  THIRD-PARTY-NOTICES.md
  scripts\         AL-Settings.psd1  AL-Common.ps1  0_...  1_...  2_...  3_...  4_...  5_...  6_AL_stig_check.ps1
  Customizations\CustomizationInputs\   overlay for AaronLocker (never edit the toolkit itself):
                   GetExeFilesToDenyList.ps1  Server Core fix (lists only deny-list files that exist)
                   GetSafePathsToAllow.ps1    adds ExtraAllowedPaths (C:\Admin\*)
                   KnownAdmins.ps1            adds the KnownAdmins setting
  AaronLocker\     microsoft/AaronLocker (MIT, unmodified)  +  AaronLocker\AccessChk.exe (Sysinternals, 64-bit)
  tests\           Test-AL.ps1 (78 unit tests, no network, both PowerShell editions)
  images\          architecture diagram (spec, SVG, PNG)
  Outputs\<profile>\<timestamp>\        created by the scripts: rules, scan results, hashes, deploy records, GPO backups
  Logs\                                 created by the scripts: one transcript (+ CSV of results) per run
```

`Outputs\` and `Logs\` are environment-specific and are not part of the repository. The whole folder can be moved or copied to another computer: build folders are found by name, not by absolute path.

**Third-party software** — see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md): AaronLocker (MIT, commit `9d3c943`, 2022-08-12) and Sysinternals AccessChk 6.15 (Sysinternals license terms; SHA-256 pinned).

---

## 3. Prerequisites

| Item | Detail |
|---|---|
| **Management computer** | Windows 10/11 or Windows Server, **Windows PowerShell 5.1 or PowerShell 7**, RSAT **Group Policy Management** and **Active Directory** modules, and the built-in `AppLocker` module. |
| **RSAT without Internet** | Windows Server: `Install-WindowsFeature GPMC, RSAT-AD-PowerShell` (the payload is on the server). Windows 11: `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -Source <Features on Demand media> -LimitAccess` (same for `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`), or deploy the capability with MECM/WSUS. |
| **Account** | Domain Admin (or: create/link GPOs, write SYSVOL, WinRM administrator on the DCs). |
| **WinRM** | Enabled on every DC (default on Server 2025). Test: `Invoke-Command -ComputerName <dc> { $env:COMPUTERNAME }`. |
| **Reference DC** | Any DC in scope — DCs are built alike; the PDC emulator is a good choice. It must be in `FullLanguage` mode (no WDAC/AppLocker already restricting PowerShell for admins). If MECM or a Nessus Agent are on your DCs, they must be on the reference DC too. |
| **Execution policy** | AaronLocker's scripts are not signed. If Group Policy sets *Turn on Script Execution* to *Allow only signed scripts* (AllSigned) on the reference DC or the management computer, sign the scripts with your code-signing certificate or run from a host the GPO does not cover. Pre-flight checks the reference DC. |
| **Servers** | **No Internet.** They receive a temporary folder over WinRM during the build (`C:\AaronLocker`, deleted afterwards) and Group Policy. |

---

## 4. Bring the repository into the disconnected network

Everything the toolkit needs is in this repository, including AccessChk. Nothing is downloaded at run time.

1. **On a computer with Internet:** `git clone https://github.com/dcodev1702/SVR-CORE-DC-APPLKR.git`, or *Code → Download ZIP*.
2. Record the hash for your transfer paperwork: `Get-FileHash .\SVR-CORE-DC-APPLKR-main.zip -Algorithm SHA256`.
3. Move it across your approved path (removable media, file transfer zone, scanning station).
4. **On the management computer**, extract it (e.g. `C:\SVR-CORE-DC-APPLKR`) and clear the *downloaded from the Internet* mark:
   ```powershell
   Get-ChildItem C:\SVR-CORE-DC-APPLKR -Recurse | Unblock-File
   ```
5. Verify the toolkit (this also proves AccessChk arrived intact — its SHA-256 is pinned in the settings):
   ```powershell
   cd C:\SVR-CORE-DC-APPLKR\scripts
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\0_AL_get_toolkit.ps1
   ```
   Expected: `AccessChk.exe: Microsoft-signed Sysinternals AccessChk 6.15 (64-bit), SHA-256 843B6B1D...F9F3 (pinned)` and `Toolkit ready`.

> [!TIP]
> Optional: run the unit tests once on the management computer — no network, no domain, nothing outside a temporary folder: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ..\tests\Test-AL.ps1` (or `pwsh.exe`). Expected: `Tests: all 78 passed`.

---

## 5. Configure `AL-Settings.psd1`

Every script reads `scripts\AL-Settings.psd1`. Edit it once; the scripts refuse values that would widen the policy (drive roots, wildcards, `%variables%`) or damage a system folder.

| Setting | Meaning | Default |
|---|---|---|
| `AuditGpoName` / `EnforceGpoName` | The two GPOs | `JMSC-DC-AppLocker - Audit` / `- Enforce` |
| `TargetOUs` | OUs whose servers get the policy | empty = **Domain Controllers** |
| `ReferenceServer` | FQDN of the DC the baseline is built on — **required before step 4** | empty |
| `ExtraAllowedPaths` | Extra folders every account may run from. **Each must be changeable by administrators only** (checked on every run) | `C:\Admin\*` |
| `SecureFolders` | Folders `0_AL_secure_folders.ps1` creates administrators-only when missing | `C:\Admin` |
| `KnownAdmins` | Your own administrators groups (DOMAIN\Group or SID) — see [section 11](#11-who-counts-as-an-administrator) | empty |
| `AccessChkSha256` | Pinned hash of the shipped AccessChk | `843B6B1D...F9F3` |
| `EnableDllRules` | `$false` = DLL collection off | `$false` |
| `EventLogSizesMB` | AppLocker log sizes on the servers | EXE and DLL 100 MB, others 20 MB |

**Several server classes** (DCs, MECM site systems, other servers)? Copy the file (`AL-Settings.mecm.psd1`), change it, and pass **`-SettingsFile`** to every script. Each file keeps its own `Outputs\<profile>` folder and its own GPO pair.

---

## 6. Run order at a glance

Run every script from the `scripts` folder, in **Windows PowerShell 5.1** (`powershell.exe`) or **PowerShell 7** (`pwsh.exe`):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\<script>.ps1 [parameters]
```

| Step | Script | What it does | Changes |
|---|---|---|---|
| 1 | `0_AL_get_toolkit.ps1` | Verifies AaronLocker + AccessChk (signature, 64-bit, pinned SHA-256) | nothing (`-Download` / import only when asked) |
| 2 | `0_AL_pre-flight.ps1` | Modules, rights, OUs, toolkit, WinRM, language mode, execution policy, existing AppLocker policy, **MECM**, **Nessus**, services/tasks outside the allowed folders, **`C:\Admin` permissions** | read-only |
| 3 | `0_AL_secure_folders.ps1` | Creates a missing `C:\Admin` administrators-only; reports a writable one | DCs (only a **missing** folder; an existing one only with `-Fix`) |
| 4 | `1_AL_build_policy.ps1` | Builds the baseline on the reference DC, brings the XML back | temporary folder on the reference DC |
| 5 | `2_AL_create_gpos.ps1` | Backs up, creates/updates the Audit + Enforce GPOs, reads the rules back, links new GPOs **disabled**, sizes the logs | domain (GPOs), DCs (log size) |
| 6 | `3_AL_set_mode.ps1 -Mode Audit -Refresh` | Enables the Audit link, refreshes the DCs | domain (links) |
| 6 | `4_AL_validate.ps1` | GPOs, links, rules, service, effective policy, decisions, DC services, `C:\Admin`, events | read-only |
| 7 | `5_AL_review_events.ps1` | Summarises would-be-blocked events (tags MECM / NESSUS / ADMIN / SYSVOL), CSV | read-only |
| 8 | `3_AL_set_mode.ps1 -Mode Enforce -Refresh` | Disables Audit, enables Enforce, refreshes | domain (links) |
| 9 | `6_AL_stig_check.ps1` | WN25-00-000080 / V-277992 per DC: status + values + evidence XML | read-only |

Every script that changes something shows the change in **yellow** and asks `Continue? [Y/N]`; **`-NoConfirm`** skips the prompt for automation, a non-interactive session without `-NoConfirm` stops before changing anything, and **`-WhatIf`** shows the plan without changing anything. Every run writes a transcript to `Logs\`; the read-only checks also write their results table as CSV and exit with code 1 on a failure.

---

## 7. Step by step

### Step 1 — Verify the toolkit

```powershell
.\0_AL_get_toolkit.ps1
```
Already done in [section 4](#4-bring-the-repository-into-the-disconnected-network). Run it again after you change anything under `AaronLocker\`.

### Step 2 — Pre-flight

Set `ReferenceServer` (and `TargetOUs` if not the DCs) in `AL-Settings.psd1`, then:
```powershell
.\0_AL_pre-flight.ps1
```
It must end with **`Pre-flight: PASSED`**. Fix every **FAIL**; read every **WARN**:

| Output | Means | Do |
|---|---|---|
| `Reference server: not set` | `ReferenceServer` is empty | set it (any DC in scope) |
| `Execution policy … AllSigned` (FAIL on the reference DC) | AaronLocker cannot run there | [section 3](#3-prerequisites) |
| `Extra path writable` (FAIL) | An account that is not an administrator can change something in `C:\Admin` — a path rule there is a bypass | remove that access, or list the group in `KnownAdmins` if it **is** an administrators group ([section 8](#cadmin-ctemp-and-csysmon)) |
| `Extra path missing` | `C:\Admin` does not exist on that DC | step 3 |
| `Task outside allowed folders` | A scheduled task runs a program or script from outside the allowed folders as a non-SYSTEM account — **blocked in Enforce** unless that account is an elevated administrator | move the file, or add its folder to `ExtraAllowedPaths` (administrators-only!) |
| `Service outside allowed folders` (INFO) | A service runs from elsewhere — services are **not** evaluated by this policy | nothing; watch the Audit events for what it starts as a user |
| `Local AppLocker policy` / `Services enforcement` | A local policy merges with the GPO (typically MECM's managed installer) | [section 9](#9-mecm-configuration-manager) |
| `MECM client` / `Tenable Nessus` (INFO) | Found on that DC | sections [9](#9-mecm-configuration-manager) and [10](#10-tenable-nessus) |

### Step 3 — `C:\Admin`

`C:\Admin\*` is allowed for **every** account. On Windows Server, `BUILTIN\Users` may create folders and files directly under `C:\`, and whoever creates a folder owns it (CREATOR OWNER: full control). So until an administrator creates `C:\Admin` with locked-down permissions, a user could create it first and plant code in it.

```powershell
.\0_AL_secure_folders.ps1 -WhatIf     # survey only: what would be created or is writable
.\0_AL_secure_folders.ps1             # creates a MISSING C:\Admin: SYSTEM + Administrators only (asks Y/N)
```
- An **existing** folder is never changed: if it is writable by a non-admin it is only **reported**. Fix it yourself, or run with `-Fix` to replace its permissions (the previous permissions are printed as SDDL first, for undo).
- This is the only script in the toolkit that sets permissions. It touches **only** the `SecureFolders` entries — never `C:\Temp`, `C:\Sysmon` or a system folder (the settings check refuses those).
- By hand, on a DC: `New-Item C:\Admin -ItemType Directory; icacls C:\Admin /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"`.

### Step 4 — Build the baseline

```powershell
.\1_AL_build_policy.ps1                          # uses ReferenceServer
.\1_AL_build_policy.ps1 -ComputerName dc01.contoso.com
```
What happens: checks AccessChk → copies the toolkit + `Customizations` to `C:\AaronLocker` on the reference DC → **stops if anything in `C:\Admin` can be changed by a non-admin** → runs `Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan` there (a few minutes; AccessChk only **reads** permissions under `C:\Windows` and `Program Files`) → copies the results to `Outputs\<profile>\<timestamp>\` → deletes `C:\AaronLocker`.

Results: `AppLockerRules-<ts>-Audit.xml`, `…-Enforce.xml`, `ScanResults\Writable_*.txt` (the user-writable folders excluded from the allow rules), `build-info.json` (settings + SHA-256 of the rule files). Harmless: `FILE SYSTEM OBJECT DOES NOT EXIST …OneDrive` (a desktop-only sample).

> [!NOTE]
> **Server Core:** several desktop binaries on AaronLocker's deny list (e.g. `mshta.exe`) are not installed, which makes the stock script fail. The `Customizations` overlay lists only files that exist — the scripts apply it automatically; do not edit the toolkit copy.

### Step 5 — Create or update the GPOs

```powershell
.\2_AL_create_gpos.ps1 -WhatIf     # the plan, nothing changed
.\2_AL_create_gpos.ps1             # asks Y/N; -NoConfirm for automation
```
It turns each build file into `…-Deploy.xml` (Audit: every collection `AuditOnly`; Enforce: every collection `Enabled`; DLL collection emptied and `NotConfigured`), **backs up** an existing GPO (`Outputs\<profile>\gpo-backups\<ts>`), writes the rules with `Set-AppLockerPolicy -Ldap`, **reads them back and compares**, adds Application Identity = Automatic, raises the GPO version, links a new GPO to the target OUs **disabled**, records the deployed files with their SHA-256 in `<build>\deploy-<ts>.json`, and sizes the AppLocker logs. Existing links keep their state.

### Step 6 — Start Audit and validate

```powershell
.\3_AL_set_mode.ps1 -Mode Audit -Refresh
.\4_AL_validate.ps1
```
`-Refresh` runs `gpupdate` twice on each DC (the first refresh starts Application Identity, the second loads the rules). Without it, DCs apply the change at their next refresh (every **5 minutes**) or at boot.

Validation must end with **`Validation: PASSED`**: both GPOs with AD = SYSVOL version, one active link, Application Identity `Running / Auto`, effective policy `Exe/Msi/Script/Appx = AuditOnly`, `Dll = NotConfigured`, DC services running, `C:\Admin` administrators-only.

### Step 7 — The Audit period and review

Leave **Audit** on for **at least one full patch / maintenance cycle (2–4 weeks is typical)** — include a patch Tuesday, an MECM deployment cycle, a Nessus scan window, a backup, a reboot and your administrators' normal work. AppLocker also logs *allowed* runs (8002/8005), so the logs are large; step 5 sized them.

```powershell
.\5_AL_review_events.ps1 -Days 14      # summary + Outputs\<profile>\events-<ts>.csv
```
Each line is a run that **would be blocked** in Enforce (8003/8006/8021) or **was blocked** (8004/8007/8022), with the account, the file and a **Tag** (`MECM`, `NESSUS`, `ADMIN` = an `ExtraAllowedPaths` folder, `SYSVOL`). For each one:

| Finding | Action |
|---|---|
| A **non-admin account** (or a non-elevated session) needs a program from a fixed folder only administrators can change | add the folder to `ExtraAllowedPaths`, rebuild (steps 4–5) |
| A **signed** program you trust in a user-writable location | publisher rule: copy `AaronLocker\AaronLocker\CustomizationInputs\TrustedSigners.ps1` to `Customizations\CustomizationInputs\`, edit it there, rebuild |
| A **non-elevated administrator** session | elevate (*Run as administrator*), or put the tool in `C:\Admin` |
| Unknown or unwanted | leave it — that is what Enforce is for |

After a change: `1_AL_build_policy.ps1` → `2_AL_create_gpos.ps1` (both GPOs updated in place) → `3_AL_set_mode.ps1 -Mode Audit -Refresh` → review again until it is quiet. `AaronLocker\AaronLocker\Compare-Policies.ps1` shows what changed between two builds.

### Step 8 — Enforce

Only after a clean Audit period. Several DCs? Enforce a **pilot** first (a DC in its own OU, or `-TargetOU`), then the rest.

```powershell
.\3_AL_set_mode.ps1 -Mode Enforce -Refresh     # Y/N prompt lists the DCs and the link changes
.\4_AL_validate.ps1 -Mode Enforce
```
The effective policy must now read `Exe/Msi/Script/Appx = Enabled`, `Dll = NotConfigured`. Then check that the DCs work (`dcdiag`, replication, logons, Group Policy) and watch `5_AL_review_events.ps1` (8004/8007) for a few days, including a reboot and a patch cycle. Keep the way back in mind ([section 13](#13-rollback)).

### Step 9 — STIG check

```powershell
.\6_AL_stig_check.ps1
```
Per DC: **WN25-00-000080 / V-277992 (CAT II)**, status **NotAFinding** or **Open**, and the values behind it — every rule collection (mode and rule count), Application Identity, the enabled AppLocker GPO link, blocked events in the last 24 hours. It runs the STIG's own check command (`Get-AppLockerPolicy -Effective -XML`) and saves each DC's effective policy as evidence (`Outputs\<profile>\stig-<ts>\<DC>-effective-applocker.xml` + SHA-256), with the results in `Logs\6_AL_stig_check-<ts>.csv`. Open = Application Identity not running, or the EXE collection not `Enabled` (Audit is a finding), or no EXE rules.

---

## 8. Domain controller considerations

### Typical DC functions

| Function | Why it keeps working |
|---|---|
| AD DS (`NTDS`), DNS, KDC, Netlogon, DFSR (SYSVOL), W32Time, AD Web Services | Services started by the Service Control Manager — not evaluated by this policy; their binaries are in `C:\Windows` anyway |
| Group Policy processing, startup/shutdown scripts | Run as SYSTEM |
| Logon scripts | `\\<domain>\NETLOGON` and `\\<domain>\SYSVOL` are allowed for everyone |
| Administration (`dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `w32tm`, `gpupdate`, `sconfig`, PowerShell 5.1 and 7) | In `C:\Windows` / `C:\Program Files` — allowed even for non-admins; elevated admins may run anything |
| Defender / Defender for Endpoint, Sysmon | Services; Defender's platform folder in `ProgramData` is allowed for everyone |
| Windows Update / patching | Microsoft-signed content in `C:\Windows`, installed as SYSTEM |

Lab result in **Enforce**: `dcdiag` 26 tests passed, DFSR SYSVOL `Normal`, DNS SRV / LDAP / Kerberos / SYSVOL+NETLOGON shares OK, 0 blocked events ([Appendix A](#appendix-a--lab-verification-2026-10-26)).

- **Server, Backup, Print and Account Operators** may log on to DCs but are **not** administrators to AppLocker: they get the non-admin rules. Microsoft's guidance is to keep these groups empty (they are empty in the lab).
- **UAC:** an administrator at the console without elevation gets the non-admin rules (see [section 1](#who-applocker-restricts-here)).

### C:\Admin, C:\Temp and C:\Sysmon

| Folder | In the policy | Requirement |
|---|---|---|
| **`C:\Admin`** | **Allowed for every account** (`ExtraAllowedPaths`) — admin tools and scripts work even in a non-elevated session | Must be changeable by **administrators only** — every folder **and file** in it, including permissions that only apply to new files. Pre-flight, build and validate check it on every run; the build **stops** if it is not. Lab: `O:BAG:DUD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (SYSTEM + Administrators, inheritance removed). |
| **`C:\Temp`** | **Not allowed** for non-admins | Users can write there (it inherits `C:\`). Never add it to `ExtraAllowedPaths`. Administrators can still run from it — avoid that on a DC. |
| **`C:\Sysmon`** | **Not allowed** for non-admins | Sysmon's archive folder (SYSTEM only) holds copies of deleted executables and scripts. Never allow it. The Sysmon service itself is `C:\Windows\Sysmon64.exe` — allowed. |

The toolkit never sets permissions on `C:\Temp` or `C:\Sysmon`, and on `C:\Admin` only when step 3 creates a missing folder or you run it with `-Fix`.

---

## 9. MECM (Configuration Manager)

> [!NOTE]
> Design analysis — the lab has no MECM. Confirm it in your Audit period.

**On the DCs (MECM client):**
- The client (`CcmExec`) is a **SYSTEM service**: not restricted. So are client push / `ccmsetup`, software updates, application and package installs, scripts, configuration baselines and CMPivot that run as SYSTEM (and PowerShell they start stays in Full Language mode).
- Client files under `C:\Windows\CCM`, `ccmsetup` and `ccmcache` are covered by the Windows rule — except subfolders users can write to, which the build lists (`MECM / Tenable folders that are user-writable`). MSI files in `%WINDIR%\ccmcache` have their own allow rule.
- What can still be blocked: deployments or configuration items that run **as the logged-on user**, and anything run by a non-admin account. They show up in Audit with the tag `MECM`.

**Managed installer — keep it off for these DCs.** MECM's *managed installer* (an App Control/WDAC feature) writes a **local** AppLocker policy with a `ManagedInstaller` collection and **services enforcement**. Local and GPO policies merge, so services would start being evaluated against this baseline. Pre-flight and validate warn on a local policy or services enforcement; `2_AL_create_gpos.ps1` refuses a build that contains a `ManagedInstaller` collection. Compare sources with `Get-AppLockerPolicy -Local -Xml` vs `-Effective -Xml`.

**Site systems** (site server, MP, DP, SUP/WSUS, SQL) are a different server class: give them their own settings file (`AL-Settings.mecm.psd1`), reference server, `TargetOUs` and GPO pair. When MECM or SQL are installed outside `Program Files` (e.g. `D:\Program Files\Microsoft Configuration Manager`), list those folders in `ExtraAllowedPaths` — they must pass the administrators-only check, which may need `KnownAdmins` for your MECM administrators group.

MECM does not manage this policy and needs no client-setting change. The GPO is authoritative; do not also push AppLocker through a compliance setting.

---

## 10. Tenable Nessus

> [!NOTE]
> Design analysis — the lab has no Nessus. Confirm it in your Audit period (tag `NESSUS`, or filter by the scan account).

| Nessus | Effect of this policy |
|---|---|
| **Credentialed (agentless) scans** from a scanner | Run under the scan account. Full Windows credentialed checks need that account in **Administrators** (on DCs: Domain Admins or a group nested in `BUILTIN\Administrators`); what the scan starts on the DC (over SMB, WMI, remote registry) then matches the administrator rule and is **allowed**. Expect bursts of 8002/8005 *allowed* events during scan windows. |
| A **least-privilege** scan account | Treated as a non-admin: what it starts outside the allowed folders is **blocked in Enforce**. It shows up in Audit under that account — make it an administrator as Tenable requires, or add rules. |
| **Nessus Agent** on the DCs | A **SYSTEM service** in `C:\Program Files\Tenable\Nessus Agent` — not restricted; its updates run as SYSTEM. Install it on the reference DC too. Pre-flight lists it; validate checks the `Tenable Nessus Agent` service. |
| **STIG / SCAP audits** run by Nessus | Read the same effective policy as `6_AL_stig_check.ps1`: WN25-00-000080 can only pass while the Enforce GPO is active. |

---

## 11. Who counts as an administrator

AaronLocker decides which folders under `C:\Windows` and `Program Files` are *user-writable* (and therefore carved out of the "everyone may run" rule) by **reading** their permissions with AccessChk. It ignores write access held by accounts that can already run anything:

`SYSTEM` · `LOCAL SERVICE` · `NETWORK SERVICE` · `SERVICE` · `Administrators` · Server / Print / Backup Operators · `TrustedInstaller` and other `NT SERVICE\…` accounts · `CREATOR OWNER` · (on member servers) direct members of the local Administrators group.

- **This changes no permissions.** Neither AaronLocker nor the build sets any ACL; the list only decides which folders become exceptions. Ignoring a privileged writer can never *widen* the policy: a folder only those accounts can write is not a place where a standard user can plant code.
- **It is the normal model** (Microsoft's AaronLocker; AppLocker's own default rules don't even carve these folders out).
- **Enterprise caveat:** your own delegated administrators groups (e.g. `CONTOSO\Tier0-Server-Admins`) are not on the list. A folder they can write gets carved out (more restrictive: Audit noise, never a silent opening). List such groups in **`KnownAdmins`** — the setting feeds AaronLocker's scan and the `C:\Admin` check alike.
- The `C:\Admin` check uses the same model, plus the direct members of `Administrators` (on a DC: `Administrator`, `Domain Admins`, `Enterprise Admins`).

---

## 12. Ongoing operations

| Event | Do |
|---|---|
| **New software / agent / role on the DCs** | Audit first if you can; add its folder or publisher, rebuild (steps 4–5) |
| **Monthly patching** | Nothing — Microsoft-signed content under `C:\Windows`, installed as SYSTEM. Check `5_AL_review_events.ps1` after the first cycle |
| **New DC** | It gets the active GPO at its next refresh (two refreshes or a reboot before the rules load). Run step 3 for `C:\Admin`, then `4_AL_validate.ps1` |
| **Rebuild** | `1_AL_build_policy.ps1` → `2_AL_create_gpos.ps1`. In Enforce, switch to Audit first (`3_AL_set_mode.ps1 -Mode Audit -Refresh`), review, then Enforce again |
| **Updating AccessChk** | On an Internet-connected computer: download AccessChk.zip, take `accesschk64.exe`, check `Get-AuthenticodeSignature` (Valid, Microsoft Corporation) and `Get-FileHash`. Put the new hash in `AccessChkSha256`, then `.\0_AL_get_toolkit.ps1 -AccessChkPath <accesschk64.exe>` (it refuses a file that does not match the pinned hash) |
| **Audit evidence** | `6_AL_stig_check.ps1` (status + evidence XML) and `4_AL_validate.ps1` (CSV in `Logs\`) |

---

## 13. Rollback

| Situation | Command |
|---|---|
| Enforce blocked something | `.\3_AL_set_mode.ps1 -Mode Audit -Refresh -NoConfirm` (back to log-only) |
| Remove AppLocker entirely | `.\3_AL_set_mode.ps1 -Mode Off -Refresh -NoConfirm` — the rules are removed at the next refresh (the STIG item becomes a finding again) |
| A GPO update went wrong | `Restore-GPO -BackupId <id> -Path <Outputs\<profile>\gpo-backups\<ts>>` (IDs are in the step 5 output and in `deploy-<ts>.json`) |
| On a DC itself | Elevated administrators and SYSTEM are always allowed, so `gpupdate /force`, PowerShell and WinRM keep working |
| Remove the GPOs | Set `Off`, let the DCs refresh, then `Remove-GPLink` for both and `Remove-GPO` |

---

## Appendix A — Lab verification (2026-10-26)

One Windows Server 2025 Datacenter **Server Core** DC (`DC25-1`, PDC emulator, AD DS + DNS + Defender for Endpoint + Sysmon, no MECM, no Nessus), management computer Windows 11 with Windows PowerShell 5.1 and PowerShell 7.6. Each step ran in the edition shown; the read-only checks ran in both.

| # | Step | Edition | Result |
|---|---|---|---|
| 1 | `0_AL_get_toolkit` | 5.1 + 7 | AccessChk 6.15 64-bit, pinned SHA-256 matched |
| 2 | `0_AL_pre-flight` | 5.1 + 7 | PASSED, 0 warnings |
| 3 | `0_AL_secure_folders -WhatIf` | 7 | `C:\Admin` administrators-only — nothing to change, no permissions set |
| 4 | `1_AL_build_policy` | 7 | Exe 10 · Msi 5 · Script 9 · Appx 1 rules; temporary folder removed |
| 5 | `3_AL_set_mode -Mode Audit -Refresh` | 5.1 | Enforce link disabled, then Audit enabled |
| 6 | `2_AL_create_gpos` | 7 | Both GPOs backed up, written, read back and verified (Audit v8, Enforce v4) |
| 7 | `4_AL_validate -Mode Audit` | 5.1 + 7 | PASSED (effective policy AuditOnly, Dll NotConfigured) |
| 8 | DC functions in Audit + `5_AL_review_events` | 7 / 5.1 | `dcdiag` 26/26; 0 would-be-blocked events |
| 9 | `3_AL_set_mode -Mode Enforce -Refresh` | 7 | Audit link disabled, then Enforce enabled |
| 10 | `4_AL_validate -Mode Enforce` | 5.1 + 7 | PASSED (Exe/Msi/Script/Appx Enabled, Dll NotConfigured) |
| 11 | DC functions in Enforce | 7 | `dcdiag` 26/26; DFSR SYSVOL Normal; DNS SRV, LDAP, Kerberos, SYSVOL/NETLOGON OK; 0 blocked |
| 12 | `6_AL_stig_check` | 5.1 + 7 | **WN25-00-000080 / V-277992: NotAFinding** |

Also verified: all scripts parse in both editions and are ASCII-only; `tests\Test-AL.ps1` 78/78 in both editions; `-WhatIf` runs and non-interactive runs without `-NoConfirm` changed nothing (state snapshot before = after); the new deploy XML is byte-identical to what the previous version of the scripts deployed.

Policy decisions in Enforce (`Test-AppLockerPolicy`, effective policy):

| File | Non-admin | Administrators |
|---|---|---|
| `dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `w32tm`, `gpupdate`, `powershell.exe`, `pwsh.exe`, `Sysmon64.exe`, `sconfig.cmd`, Defender `MpCmdRun.exe` | Allowed | Allowed |
| `cipher.exe`, `runas.exe`, `WMIC.exe` (deny list) | **Denied** | Allowed |
| `C:\Temp\*.exe`, `C:\Temp\*.ps1` | **Denied** | Allowed |

**Not verified in the lab:** MECM, Nessus, more than one DC, and a real block of a non-admin logon (no non-admin can log on to the lab DC).

---

## Appendix B — The same thing by hand

The scripts only wrap these steps.

**1. Build on the reference DC** (copy `AaronLocker\AaronLocker` incl. `AccessChk.exe` to `C:\AaronLocker`, then copy `Customizations\CustomizationInputs\*` over `C:\AaronLocker\CustomizationInputs\`; put `C:\Admin\*` in `C:\AaronLocker\CustomizationInputs\ExtraAllowedPaths.txt`):
```powershell
Set-Location C:\AaronLocker
.\Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan      # -> .\Outputs\AppLockerRules-<ts>-Audit.xml and -Enforce.xml
```
**2. Switch the DLL collection off** (management computer):
```powershell
$d = New-Object System.Xml.XmlDocument; $d.Load('C:\Temp\AppLockerRules-<ts>-Audit.xml')
$dll = $d.AppLockerPolicy.RuleCollection | Where-Object Type -eq 'Dll'
$dll.RemoveAll(); $dll.SetAttribute('Type', 'Dll'); $dll.SetAttribute('EnforcementMode', 'NotConfigured')
$d.Save('C:\Temp\Audit-Deploy.xml')          # same for the Enforce file
```
**3. Create the GPO and write the rules:**
```powershell
$pdc = (Get-ADDomain).PDCEmulator
Backup-GPO -Name 'JMSC-DC-AppLocker - Audit' -Path C:\Temp\GpoBackup -Server $pdc    # when it already exists
$gpo = New-GPO -Name 'JMSC-DC-AppLocker - Audit' -Server $pdc                         # or Get-GPO
Set-AppLockerPolicy -XmlPolicy C:\Temp\Audit-Deploy.xml -Ldap "LDAP://$pdc/$($gpo.Path)"
```
**4. Application Identity = Automatic in the GPO** (UTF-16 `GptTmpl.inf` under the GPO's `Machine\Microsoft\Windows NT\SecEdit\`):
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

**5. Link and choose the mode** (disable one link before enabling the other):
```powershell
$ou = (Get-ADDomain).DomainControllersContainer
New-GPLink -Name 'JMSC-DC-AppLocker - Enforce' -Target $ou -LinkEnabled No
New-GPLink -Name 'JMSC-DC-AppLocker - Audit'   -Target $ou -LinkEnabled Yes
Invoke-Command -ComputerName dc01 { gpupdate /target:computer /force; Start-Sleep 10; gpupdate /target:computer /force }
```
**6. Check a DC:**
```powershell
Invoke-Command -ComputerName dc01 {
  Get-Service AppIDSvc | Select-Object Status, StartType
  [xml]$p = Get-AppLockerPolicy -Effective -Xml; $p.AppLockerPolicy.RuleCollection | Select-Object Type, EnforcementMode
  Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8003, 8004 } -MaxEvents 50
  Test-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -Path C:\Windows\System32\cmd.exe -User Everyone
}
```
Size the logs: `wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:104857600`.

---

## Appendix C — Event IDs

| Log (`Microsoft-Windows-AppLocker/…`) | Allowed | **Audit** (would be blocked) | **Blocked** |
|---|---|---|---|
| `EXE and DLL` | 8002 | **8003** | **8004** |
| `MSI and Script` | 8005 | **8006** | **8007** |
| `Packaged app-Execution` | 8020 | **8021** | **8022** |

`8001` = *The AppLocker policy was applied successfully to this computer*; `8000` = policy conversion failed. Each event carries the file, the matching rule, the account (SID) and the publisher. Also see `Microsoft-Windows-AppID/Operational` (the lab DC logs recurring `4005 AppID certificate store verification failed` events; they did not affect enforcement).

---

## Appendix D — Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Module GroupPolicy / AppLocker missing` in PowerShell 7 | Fixed: the scripts load Windows PowerShell modules with `-SkipEditionCheck` / the compatibility session. If RSAT is truly missing, see [section 3](#3-prerequisites) |
| Nothing runs: *not digitally signed* | Run `Unblock-File` on the folder; if Group Policy enforces AllSigned, sign the scripts ([section 3](#3-prerequisites)) |
| `Cannot find path …\mshta.exe` during the build | The `Customizations` folder is not next to `scripts` |
| `AccessChk.exe … SHA-256 … does not match the pinned AccessChkSha256` | The file changed or was damaged in transfer. Restore it from the repository, or verify a new one and update the setting ([section 12](#12-ongoing-operations)) |
| `STOP: no build in …Outputs\…` / build folder not found | Run step 4, or pass `-OutputFolder` |
| Build stops: *ExtraAllowedPaths entry can be changed by non-admins* | Remove that access, or list the group in `KnownAdmins` if it is an administrators group; never allow a writable folder |
| `Application Identity` Stopped / Manual after the GPO applied | `gpupdate /force` once or twice, or reboot; `4_AL_validate.ps1`. A GPP *Services* item does **not** work for this protected service — the GPO uses System Services |
| Effective policy empty after the first refresh | The service had just started: refresh again (`-Refresh` does it twice) |
| `Both links enabled` | `3_AL_set_mode.ps1 -Mode Audit` (or Enforce) disables one link before enabling the other |
| `Local AppLocker policy` / `Services enforcement` warning | A local policy merges with the GPO — typically MECM's managed installer ([section 9](#9-mecm-configuration-manager)) |
| A script runs in *Constrained Language* in Enforce | It was not allowed for that account (non-admin or non-elevated, outside the allowed folders). Elevate, move it to `C:\Admin`, or add a rule |
| `STOP: … non-interactive` | The script needs Y/N: run it in a console, or add `-NoConfirm` for automation |
| WinRM errors | `Enable-PSRemoting` on the DC; firewall 5985; use FQDNs |

---

## Appendix E — Design decisions and limits

- **Built on a DC itself**, because the rules depend on its disk (user-writable folders, tools present). Build one baseline per server class; the reference must resemble the class.
- **Two GPOs, one enabled link**, so Audit and Enforce never merge and switching is one command. Both GPOs carry the full rule set and the service setting.
- **DLL rules off** — not required by WN25-00-000080; they add overhead and a high rule-maintenance burden. `EnableDllRules = $true` switches them on (`AuditOnly` / `Enabled` like the rest).
- **No services enforcement** — services are not evaluated (AppLocker's default). Turning it on would need `SystemApps` allowed and a separate Audit cycle.
- **AaronLocker is not maintained since 2022.** It only *generates XML*; the deployment (GPO, links, service) is plain Group Policy and `Set-AppLockerPolicy`. Keep each `Outputs\<profile>\<ts>` folder: it is what you tested.
- **Desktop leftovers** in the baseline (the Microsoft Teams publisher rule, the AaronLocker timestamp rule) are harmless on a DC.
- **`\\<domain>\SYSVOL\*` is allowed for everyone** (AaronLocker default, for GPO logon scripts). Members of *Group Policy Creator Owners* can write their GPO folders there; keep that group administrators-only (in the lab its only member is `Administrator`).
- **Administrators are allowed everywhere** (AppLocker default rule): this constrains non-admin and non-elevated code, not an administrator.
- **Audit mode logs allowed executions too**, which is why the logs are enlarged (`EventLogSizesMB`). Forward the AppLocker logs with Windows Event Forwarding / your SIEM if you need history.
- **Scripts:** Windows PowerShell 5.1 and PowerShell 7, ASCII-only, settings validated before anything runs, changes behind a yellow Y/N gate (`-NoConfirm`, `-WhatIf`), GPO backup before an update, transcripts and CSV results in `Logs\`.
