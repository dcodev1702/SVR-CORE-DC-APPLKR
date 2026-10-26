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
| **Everyone else** (non-admin accounts, members of Server/Backup/Print/Account Operators, and **non-elevated** administrator sessions) | Files under `C:\Windows` and `C:\Program Files*` — **except** the user-writable subfolders the scan found (e.g. `C:\Windows\Temp`, `C:\Windows\Tasks`, `SYSVOL\domain\Policies`) and a deny list of bypass tools (`cipher`, `runas`, `WMIC`, `MSBuild`, `InstallUtil`, `RegAsm`, `RegSvcs`, `PresentationHost`, `Microsoft.Workflow.Compiler`) — plus `\\<domain>\SYSVOL` and `\\<domain>\NETLOGON` (logon scripts), the Defender platform folder, `C:\Admin\*`, and Microsoft-signed installers and scripts. Nothing else — **not `C:\Temp`, not a user profile, not `C:\Sysmon`**. |

### Who AppLocker restricts here

- **By default, AppLocker only applies to code running in a user's context.** Services started by the Service Control Manager are **not** evaluated unless a policy turns on *services enforcement* ([Microsoft Learn — AppLocker rule collection extensions](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/rule-collection-extensions)). This baseline does not — but **MECM's managed installer does** (its local policy merges in, [section 9](#9-mecm-configuration-manager)). Either way the MECM client, the Nessus Agent, Defender, Sysmon and the AD DS / DNS / KDC / DFSR services keep running: they run as SYSTEM (administrator rule) or from `C:\Windows` / `Program Files` / the Defender platform folder.
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
                   GetSafePathsToAllow.ps1    SYSVOL + NETLOGON (AaronLocker defaults) + ExtraAllowedPaths (C:\Admin\*)
                   KnownAdmins.ps1            adds the KnownAdmins setting
  AaronLocker\     microsoft/AaronLocker (MIT, unmodified)  +  AaronLocker\AccessChk.exe (Sysinternals, 64-bit)
  tests\           Test-AL.ps1 (149 unit tests, no network, both PowerShell editions; 152 with -BuildFolder)
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
> Optional: run the unit tests once on the management computer — no network, no domain, nothing outside a temporary folder: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ..\tests\Test-AL.ps1` (or `pwsh.exe`). Expected: `Tests: all 149 passed`.

---

## 5. Configure `AL-Settings.psd1`

Every script reads `scripts\AL-Settings.psd1`. Edit it once; the scripts refuse values that would widen the policy (drive roots, wildcards, `%variables%`) or damage a system folder.

| Setting | Meaning | Default |
|---|---|---|
| `AuditGpoName` / `EnforceGpoName` | The two GPOs | `JSLC_AppLocker_AUDIT_Domain_Controller` / `JSLC_AppLocker_ENFORCE_Domain_Controller` |
| `TargetOUs` | OUs whose servers get the policy | empty = **Domain Controllers** |
| `ReferenceServer` | FQDN of the DC the baseline is built on — **required before step 4**; set it to one of **your** DCs | `DC25-1.skynet-home.local` (the lab DC) |
| `ExtraAllowedPaths` | Extra folders every account may run from. Each should be changeable by administrators only: the build checks every DC and **leaves out or excepts** what a non-admin can change — it never stops on it | `C:\Admin\*` |
| `SecureFolders` | Folders `0_AL_secure_folders.ps1` creates administrators-only when missing | `C:\Admin` |
| `KnownAdmins` | Your own administrators groups (DOMAIN\Group or SID) — `0_AL_known_admins.ps1` fills it from an OU or a group, see [section 11](#11-who-counts-as-an-administrator) | `SKYNET\lorenzo` (the lab's DA account; replace with your groups) |
| `AccessChkSha256` | Pinned hash of the shipped AccessChk | `843B6B1D...F9F3` |
| `EnableDllRules` | `$false` = DLL collection off | `$false` |
| `EventLogSizesMB` | AppLocker log sizes on the servers | 100 MB for each of the four logs |

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
| 2 | `0_AL_known_admins.ps1 -Path <OU or group>` | Optional: turns your own administrators groups (canonical name, as ADUC shows it) into `KnownAdmins` entries; `-Update` writes them | nothing (`-Update`: `AL-Settings.psd1`, after a backup) |
| 2 | `0_AL_pre-flight.ps1` | Modules, rights, OUs, toolkit, WinRM, language mode, execution policy, existing AppLocker policy, **MECM**, **Nessus**, services/tasks outside the allowed folders, **`C:\Admin` permissions** | read-only |
| 3 | `0_AL_secure_folders.ps1` | Creates a missing `C:\Admin` administrators-only; reports a writable one | DCs (only a **missing** folder; an existing one only with `-Fix`) |
| 4 | `1_AL_build_policy.ps1` | Builds the baseline on the reference DC, checks `C:\Admin` on every DC (leaves out / excepts what a non-admin can change), brings the XML back | temporary folder on the reference DC |
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

Set `ReferenceServer` (and `TargetOUs` if not the DCs) in `AL-Settings.psd1` — and `KnownAdmins` if your organisation has its own administrators groups (`0_AL_known_admins.ps1`, [section 11](#11-who-counts-as-an-administrator)) — then:
```powershell
.\0_AL_pre-flight.ps1
```
It must end with **`Pre-flight: PASSED`**. Fix every **FAIL**; read every **WARN**:

| Output | Means | Do |
|---|---|---|
| `Reference server: not set` | `ReferenceServer` is empty | set it (any DC in scope) |
| `Execution policy … AllSigned` (FAIL on the reference DC) | AaronLocker cannot run there | [section 3](#3-prerequisites) |
| `Extra path writable` (WARN) | An account that is not an administrator can change something in `C:\Admin`. The build will **leave `C:\Admin` out** of the policy (if the folder itself is writable) or **except** that item — the policy never allows it, and nothing breaks | to keep it allowed for everyone: remove that access, or list the group in `KnownAdmins` if it **is** an administrators group ([section 8](#cadmin-ctemp-and-csysmon)) |
| `Extra path missing` | `C:\Admin` does not exist on that DC | step 3 |
| `Task outside allowed folders` | A scheduled task runs a program or script from outside the allowed folders as a non-SYSTEM account — **blocked in Enforce** unless that account is an elevated administrator | move the file, or add its folder to `ExtraAllowedPaths` (administrators-only!) |
| `Service outside allowed folders` (INFO) | A service runs from elsewhere — services are **not** evaluated by this policy | nothing; watch the Audit events for what it starts as a user |
| `MECM managed installer` / `Services enforcement` (INFO) | MECM's managed-installer local policy merges with the GPO — expected | nothing; [section 9](#9-mecm-configuration-manager) |
| `Local AppLocker policy` (WARN) | Some other local AppLocker policy merges with the GPO | review `Get-AppLockerPolicy -Local -Xml` |
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
What happens: checks AccessChk → copies the toolkit + `Customizations` to `C:\AaronLocker` on the reference DC → **checks `C:\Admin` on every DC in scope** → runs `Create-Policies.ps1 -AppLockerOrWDAC AppLocker -Rescan` there (a few minutes; AccessChk only **reads** permissions under `C:\Windows` and `Program Files`) → copies the results to `Outputs\<profile>\<timestamp>\` → deletes `C:\AaronLocker`.

**`C:\Admin` never breaks the build.** If a non-admin can change `C:\Admin` itself on any DC, the build **leaves it out** of the policy (non-admins and non-elevated sessions can't run from it; elevated administrators still can). If only items inside it are affected, `C:\Admin\*` stays allowed and those items become **exceptions** of the rule. Either way the policy never allows something a non-admin can write, no permission is changed, and the output says exactly what was decided:
```
Extra allowed path: C:\Admin\* - allowed for every account (administrators-only on: dc01, dc02)
Extra allowed path: C:\Admin\* - allowed for every account EXCEPT (non-admins can change these): C:\Admin\Shared\*
Extra allowed path: C:\Admin\* - LEFT OUT of the policy: changeable by BUILTIN\Users on dc02. ... Fix its permissions and rebuild to allow it.
```

Results: `AppLockerRules-<ts>-Audit.xml`, `…-Enforce.xml`, `ScanResults\Writable_*.txt` (the user-writable folders excluded from the allow rules), `build-info.json` (settings, the `C:\Admin` decision per entry, SHA-256 of the rule files). Harmless: `FILE SYSTEM OBJECT DOES NOT EXIST …OneDrive` (a desktop-only sample).

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

Validation must end with **`Validation: PASSED`**: both GPOs with AD = SYSVOL version, one active link, Application Identity `Running / Auto`, effective policy `Exe/Msi/Script/Appx = AuditOnly`, DC services running, nothing in `C:\Admin` that a non-admin can change is still allowed. The DLL and `ManagedInstaller` collections that MECM's managed installer adds are reported (INFO), not judged.

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
| Logon scripts | `\\<domain>\NETLOGON` and `\\<domain>\SYSVOL` are allowed for everyone — NETLOGON scripts and GPO logon scripts stored in SYSVOL run in any session |
| Administration (`dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `w32tm`, `gpupdate`, `sconfig`, PowerShell 5.1 and 7) | In `C:\Windows` / `C:\Program Files` — allowed even for non-admins; elevated admins may run anything |
| Defender / Defender for Endpoint, Sysmon | Services; Defender's platform folder in `ProgramData` is allowed for everyone |
| Windows Update / patching | Microsoft-signed content in `C:\Windows`, installed as SYSTEM |

Lab result in **Enforce**: `dcdiag` 26 tests passed, DFSR SYSVOL `Normal`, DNS SRV / LDAP / Kerberos / SYSVOL+NETLOGON shares OK, 0 blocked events ([Appendix A](#appendix-a--lab-verification-2026-10-26)).

- **Server, Backup, Print and Account Operators** may log on to DCs but are **not** administrators to AppLocker: they get the non-admin rules. Microsoft's guidance is to keep these groups empty (they are empty in the lab).
- **UAC:** an administrator at the console without elevation gets the non-admin rules (see [section 1](#who-applocker-restricts-here)).

### C:\Admin, C:\Temp and C:\Sysmon

| Folder | In the policy | Requirement |
|---|---|---|
| **`C:\Admin`** | **Allowed for every account** (`ExtraAllowedPaths`) — admin tools and scripts work even in a non-elevated session | Should be changeable by **administrators only** — every folder **and file** in it, including permissions that only apply to new files. The build checks it on **every DC** and never stops: what a non-admin can change is left out of the policy or excepted ([step 4](#step-4--build-the-baseline)); pre-flight warns ahead; validate fails only if a DC still allows such an item. Lab: `O:BAG:DUD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (SYSTEM + Administrators, inheritance removed). |
| **`C:\Temp`** | **Not allowed** for non-admins | Users can write there (it inherits `C:\`). Never add it to `ExtraAllowedPaths`. Administrators can still run from it — avoid that on a DC. |
| **`C:\Sysmon`** | **Not allowed** for non-admins | Sysmon's archive folder (SYSTEM only): with `FileDelete` rules on, it keeps a copy of every deleted file (29 GB on the lab DC). Never allow it. The Sysmon service itself is `C:\Windows\Sysmon64.exe` — allowed. The lab turned file-delete recording and archiving off ([Appendix A](#appendix-a--lab-verification-2026-10-26)). |

The toolkit never sets permissions on `C:\Temp` or `C:\Sysmon`, and on `C:\Admin` only when step 3 creates a missing folder or you run it with `-Fix`.

---

## 9. MECM (Configuration Manager)

> [!NOTE]
> Design analysis — the lab has no MECM. Confirm it in your Audit period.

**On the DCs (MECM client):**
- The client (`CcmExec`) is a **SYSTEM service**: not restricted. So are client push / `ccmsetup`, software updates, application and package installs, scripts, configuration baselines and CMPivot that run as SYSTEM (and PowerShell they start stays in Full Language mode).
- Client files under `C:\Windows\CCM`, `ccmsetup` and `ccmcache` are covered by the Windows rule — except subfolders users can write to, which the build lists (`MECM / Tenable folders that are user-writable`). MSI files in `%WINDIR%\ccmcache` have their own allow rule.
- What can still be blocked: deployments or configuration items that run **as the logged-on user**, and anything run by a non-admin account. They show up in Audit with the tag `MECM`.

**Managed installer (on for the DCs in this environment).** MECM's *managed installer* (an App Control feature) writes a **local** AppLocker policy: a `ManagedInstaller` collection (`CcmExec`, `ccmsetup`), audit-only EXE and DLL collections with a "benign deny" rule, and **services enforcement**. Microsoft designed it to merge with existing AppLocker policies without changing their behavior ([Microsoft Learn — managed installer](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer)). On these DCs that means:

| Effect of the merge | What the toolkit does |
|---|---|
| Exe / Msi / Script / Appx: the **GPO** decides the mode (Group Policy precedence over the local policy) | validate and the STIG check judge exactly these collections |
| **DLL** collection: audit-only from the local policy, because this baseline leaves DLL rules off — it **blocks nothing** but logs DLL audit warnings (8003) in *EXE and DLL* | validate reports it (INFO); `5_AL_review_events.ps1` counts DLL events and leaves them out of the list (the DCs filter them before sending) |
| `ManagedInstaller` collection | reported (INFO); the GPOs never contain one (`2_AL_create_gpos.ps1` refuses such a build) |
| **Services enforcement** on: services are evaluated too | SYSTEM services and services in `C:\Windows`, `Program Files` or the Defender folder stay allowed; pre-flight lists any service at risk as WARN (none on the lab DC) |

Pre-flight and validate recognise the managed-installer policy (INFO); any *other* local AppLocker policy is a WARN. The DLL warnings make the *EXE and DLL* log fill faster: raise `EventLogSizesMB` for it (e.g. 512 MB) if `5_AL_review_events.ps1` should look back further. Compare sources with `Get-AppLockerPolicy -Local -Xml` vs `-Effective -Xml`. If MECM also deploys an **App Control (WDAC) policy** to the DCs, the reference DC must still run PowerShell in `FullLanguage` for the build (pre-flight checks it).

**Site systems** (site server, MP, DP, SUP/WSUS, SQL) are a different server class: give them their own settings file (`AL-Settings.mecm.psd1`), reference server, `TargetOUs` and GPO pair. When MECM or SQL are installed outside `Program Files` (e.g. `D:\Program Files\Microsoft Configuration Manager`), list those folders in `ExtraAllowedPaths` — they must pass the administrators-only check, which may need `KnownAdmins` for your MECM administrators group.

MECM does not manage this policy and needs no client-setting change. The GPO is authoritative; do not also push AppLocker through a compliance setting.

---

## 10. Tenable Nessus

> [!NOTE]
> Design analysis — the lab has no Nessus. Confirm it in your Audit period (tag `NESSUS`, or filter by the scan account).

This environment uses the **Nessus Agent on the DCs** (not agentless scans).

| Nessus | Effect of this policy |
|---|---|
| **Nessus Agent** on the DCs | A **SYSTEM service** in `C:\Program Files\Tenable\Nessus Agent`: allowed by the administrator rule (also with MECM's services enforcement on); the processes it starts and its self-updates run as SYSTEM too. **Install it on the reference DC** so the build scans its folders (writable subfolders under `Program Files\Tenable` are excluded for non-admins and listed by the build). Pre-flight lists it, validate checks that the `Tenable Nessus Agent` service runs and how the policy decides on `nessusd.exe`; in Audit, filter on the tag `NESSUS`. |
| **STIG / SCAP audits** the agent runs | Read the same effective policy as `6_AL_stig_check.ps1`: WN25-00-000080 can only pass while the Enforce GPO is active. |
| Credentialed (agentless) scans, if ever used | Run under the scan account: an account in **Administrators** (Domain Admins on DCs) matches the administrator rule and is allowed; a least-privilege account gets the non-admin rules and shows up in Audit. |

---

## 11. Who counts as an administrator

AaronLocker decides which folders under `C:\Windows` and `Program Files` are *user-writable* (and therefore carved out of the "everyone may run" rule) by **reading** their permissions with AccessChk. It ignores write access held by accounts that can already run anything:

`SYSTEM` · `LOCAL SERVICE` · `NETWORK SERVICE` · `SERVICE` · `Administrators` · Server / Print / Backup Operators · `TrustedInstaller` and other `NT SERVICE\…` accounts · `CREATOR OWNER` · (on member servers) direct members of the local Administrators group.

- **This changes no permissions.** Neither AaronLocker nor the build sets any ACL; the list only decides which folders become exceptions. Ignoring a privileged writer can never *widen* the policy: a folder only those accounts can write is not a place where a standard user can plant code.
- **It is the normal model** (Microsoft's AaronLocker; AppLocker's own default rules don't even carve these folders out).
- **Enterprise caveat:** your own delegated administrators groups (e.g. `CONTOSO\Tier0-Server-Admins`) are not on the list. A folder they can write gets carved out (more restrictive: Audit noise, never a silent opening). List such groups in **`KnownAdmins`** — the setting feeds AaronLocker's scan and the `C:\Admin` check alike.
- The `C:\Admin` check uses the same model, plus the direct members of `Administrators` (on a DC: `Administrator`, `Domain Admins`, `Enterprise Admins`).
- **Filling `KnownAdmins`:** `0_AL_known_admins.ps1` turns an OU or a group into entries, from the canonical name as Active Directory Users and Computers shows it (a distinguished name works too):
  ```powershell
  .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-Groups'            # prints the line to paste
  .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-Groups' -Update    # writes it (Y/N; backup in Outputs\<profile>\settings-backups)
  ```
  It lists every **security group** directly in the OU (`-Recurse` adds the sub-OUs) as `DOMAIN\Name` (`-AsSid` for SIDs) and merges them with the existing entries (`-Replace` discards those). It skips what already counts (`Administrators`, `Domain Admins`, `Enterprise Admins`, Server / Print / Backup Operators), distribution groups, and **user accounts** — an OU that holds only administrator *user accounts* yields nothing, because permissions name the groups those accounts belong to (`-IncludeUsers` lists them anyway). It **refuses** the whole domain and every group that must never count (`Domain Users`, `Domain Computers`, `Authenticated Users`, `Users`, `Everyone`, …); the settings check refuses those entries too. The new value applies at the next build (steps 4–5).

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

One Windows Server 2025 Datacenter **Server Core** DC (`DC25-1`, PDC emulator, AD DS + DNS + Defender for Endpoint + Sysmon; no MECM, no Nessus Agent), management computer Windows 11 with Windows PowerShell 5.1 and PowerShell 7.6. The full cycle ran three times; this is the final run: the baseline with `\\<domain>\SYSVOL` and `NETLOGON` allowed for everyone (logon scripts) and `C:\Admin` checked on every DC. Each step ran in the edition shown; the read-only checks ran in both.

The lab DC also got two changes outside this toolkit: the PDC emulator now syncs time from external NTP sources (NIST, US Naval Observatory, Microsoft) instead of the Hyper-V host, and Sysmon no longer records or archives file deletes (Events 23/26 off; it had archived 29 GB in `C:\Sysmon`). Sysmon 15 runs as a protected process (`ANTIMALWARE LIGHT`): its service cannot be stopped or restarted by an administrator, and `Sysmon64.exe -c <config>` applies a configuration live.

| # | Step | Edition | Result |
|---|---|---|---|
| 1 | `0_AL_pre-flight` | 5.1 + 7 | PASSED |
| 2 | `0_AL_secure_folders -WhatIf` | 5.1 + 7 | `C:\Admin` administrators-only — nothing to change, no permissions set |
| 3 | `1_AL_build_policy` | 7 | Exe 10 · Msi 5 · Script 9 · Appx 1 rules; UNC rules `\\<domain>\netlogon\*` and `\\<domain>\sysvol\*`; `C:\Admin\*` allowed (administrators-only on every DC) |
| 4 | `3_AL_set_mode -Mode Audit -Refresh` | 5.1 | Enforce link disabled, then Audit enabled |
| 5 | `2_AL_create_gpos` | 7 | Both GPOs backed up, written, read back and verified (Audit v12, Enforce v8) |
| 6 | `4_AL_validate -Mode Audit` | 5.1 + 7 | PASSED |
| 7 | DC functions in Audit + `5_AL_review_events` | 7 / 5.1 | `dcdiag` 26/26; 0 would-be-blocked events |
| 8 | `3_AL_set_mode -Mode Enforce -Refresh` | 7 | Audit link disabled, then Enforce enabled |
| 9 | `4_AL_validate -Mode Enforce` | 5.1 + 7 | PASSED (Exe/Msi/Script/Appx Enabled, Dll NotConfigured) |
| 10 | DC functions in Enforce | 7 | `dcdiag` 26/26; DFSR SYSVOL Normal; DNS SRV, LDAP, Kerberos, SYSVOL/NETLOGON shares OK; 0 blocked |
| 11 | `6_AL_stig_check` | 5.1 + 7 | **WN25-00-000080 / V-277992: NotAFinding** |

Also verified: all scripts parse in both editions and are ASCII-only; `tests\Test-AL.ps1` 98/98 in both editions (incl. the `C:\Admin` leave-out / exception logic and an MECM managed-installer merge); `-WhatIf` runs and non-interactive runs without `-NoConfirm` changed nothing (state snapshot before = after); the deploy XML is byte-identical to what the original scripts deployed.

Policy decisions in Enforce (`Test-AppLockerPolicy`, effective policy):

| File | Non-admin | Administrators |
|---|---|---|
| `dcdiag`, `repadmin`, `ntdsutil`, `nltest`, `w32tm`, `gpupdate`, `powershell.exe`, `pwsh.exe`, `Sysmon64.exe`, `sconfig.cmd`, Defender `MpCmdRun.exe` | Allowed | Allowed |
| `cipher.exe`, `runas.exe`, `WMIC.exe` (deny list) | **Denied** | Allowed |
| `C:\Temp\*.exe`, `C:\Temp\*.ps1` | **Denied** | Allowed |
| A script in a GPO folder under `\\<domain>\SYSVOL\<domain>\Policies\` (logon scripts) | Allowed | Allowed |

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
Backup-GPO -Name 'JSLC_AppLocker_AUDIT_Domain_Controller' -Path C:\Temp\GpoBackup -Server $pdc    # when it already exists
$gpo = New-GPO -Name 'JSLC_AppLocker_AUDIT_Domain_Controller' -Server $pdc                         # or Get-GPO
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
New-GPLink -Name 'JSLC_AppLocker_ENFORCE_Domain_Controller' -Target $ou -LinkEnabled No
New-GPLink -Name 'JSLC_AppLocker_AUDIT_Domain_Controller'   -Target $ou -LinkEnabled Yes
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
| Build output: *`C:\Admin\*` - LEFT OUT of the policy* or *… EXCEPT …* | A non-admin can change `C:\Admin` (or items in it) on the DC named. The build continued safely. To allow it again: remove that access (or list the group in `KnownAdmins` if it is an administrators group), then rebuild (steps 4–5) |
| Validation FAIL: *… AND allowed for every account - a bypass* | A DC's `C:\Admin` became writable **after** the build. Rebuild (steps 4–5): the build excludes it |
| Many 8003 warnings for `.dll` files in *EXE and DLL* | MECM's managed installer audits DLLs (DLL rules are off in this baseline). Expected; `5_AL_review_events.ps1` counts and skips them; size the log up ([section 9](#9-mecm-configuration-manager)) |
| `Application Identity` Stopped / Manual after the GPO applied | `gpupdate /force` once or twice, or reboot; `4_AL_validate.ps1`. A GPP *Services* item does **not** work for this protected service — the GPO uses System Services |
| Effective policy empty after the first refresh | The service had just started: refresh again (`-Refresh` does it twice) |
| `Both links enabled` | `3_AL_set_mode.ps1 -Mode Audit` (or Enforce) disables one link before enabling the other |
| `Local AppLocker policy` warning | A local AppLocker policy that is **not** MECM's managed installer merges with the GPO — review `Get-AppLockerPolicy -Local -Xml` ([section 9](#9-mecm-configuration-manager)) |
| A script runs in *Constrained Language* in Enforce | It was not allowed for that account (non-admin or non-elevated, outside the allowed folders). Elevate, move it to `C:\Admin`, or add a rule |
| `STOP: … non-interactive` | The script needs Y/N: run it in a console, or add `-NoConfirm` for automation |
| WinRM errors | `Enable-PSRemoting` on the DC; firewall 5985; use FQDNs |

---

## Appendix E — Design decisions and limits

- **Built on a DC itself**, because the rules depend on its disk (user-writable folders, tools present). Build one baseline per server class; the reference must resemble the class.
- **Two GPOs, one enabled link**, so Audit and Enforce never merge and switching is one command. Both GPOs carry the full rule set and the service setting.
- **DLL rules off** — not required by WN25-00-000080; they add overhead and a high rule-maintenance burden. `EnableDllRules = $true` switches them on (`AuditOnly` / `Enabled` like the rest).
- **No services enforcement in this baseline** — services are not evaluated (AppLocker's default) unless MECM's managed installer turns it on through its local policy; the baseline is safe either way on DCs (services run as SYSTEM or from the allowed folders).
- **AaronLocker is not maintained since 2022.** It only *generates XML*; the deployment (GPO, links, service) is plain Group Policy and `Set-AppLockerPolicy`. Keep each `Outputs\<profile>\<ts>` folder: it is what you tested.
- **Desktop leftovers** in the baseline (the Microsoft Teams publisher rule, the AaronLocker timestamp rule) are harmless on a DC.
- **`\\<domain>\SYSVOL\*` and `\\<domain>\NETLOGON\*` are allowed for everyone** (AaronLocker's default, needed for logon scripts). Members of *Group Policy Creator Owners* and delegated GPO editors can write their own GPO folders under SYSVOL; keep that group administrators-only (in the lab its only member is `Administrator`).
- **`C:\Admin` never breaks the build**: what a non-admin can change is left out or excepted, on the evidence of every DC in scope — the policy stays safe without anyone changing permissions.
- **Administrators are allowed everywhere** (AppLocker default rule): this constrains non-admin and non-elevated code, not an administrator.
- **Audit mode logs allowed executions too**, which is why the logs are enlarged (`EventLogSizesMB`). Forward the AppLocker logs with Windows Event Forwarding / your SIEM if you need history.
- **Scripts:** Windows PowerShell 5.1 and PowerShell 7, ASCII-only, settings validated before anything runs, changes behind a yellow Y/N gate (`-NoConfirm`, `-WhatIf`), GPO backup before an update, transcripts and CSV results in `Logs\`.
