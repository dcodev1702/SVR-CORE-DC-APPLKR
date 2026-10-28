# SVR-CORE-DC-APPLKR — AppLocker on Windows Server 2025 domain controllers (Server Core, no Internet)

> [!NOTE]
> This toolkit builds an **AppLocker allowlist with [AaronLocker](https://github.com/microsoft/AaronLocker)** on a reference domain controller and deploys it to every DC through **two GPOs**: one puts the DCs in **Audit** (`AuditOnly`), the other in **Enforce**. Exactly one link is enabled at a time. It runs on **Server Core**, needs **no GUI**, works in a network that is **disconnected from the Internet** (everything it needs is in this repository), and accounts for **MECM**, **Tenable Nessus** and **`C:\Admin`** on the DCs. **DLL rules stay off.**
>
> STIG item: **WN25-00-000080 / V-277992 (CAT II)** — *Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.* **Audit is a staging step, not compliance: the item is met only while the Enforce GPO is active.**

> [!IMPORTANT]
> **Run end to end in the lab on 2026-10-26** (one Server Core 2025 domain controller): build → GPOs → Audit → review → **Enforce** → STIG check. Result: **WN25-00-000080 / V-277992 = NotAFinding**, `dcdiag` 26/26 passed in Enforce, 0 blocked events ([Appendix A](#appendix-a--lab-verification-2026-10-26)). The lab has **no MECM and no Nessus**: those sections are design analysis checked against Microsoft documentation. **The Audit period in your network is the proof — do not skip it.**

> [!TIP]
> **Server Core 2022 DCs, or a mix of 2022 and 2025?** The steps are the same. With both versions, list one DC of the other version in `ExtraReferenceServers`: the build scans it too and merges the scans. Pre-flight warns about a DC whose version no reference DC runs and about an installed PowerShell 2.0, and the STIG check reports 2022 DCs under **WN22-00-000080 / V-254245**. See **[AppLocker on Server Core 2022 domain controllers](docs/SERVER-2022.md)**.

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
- [Server Core 2022 domain controllers](docs/SERVER-2022.md) — separate page

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
| **Appx** | **NotConfigured** / **NotConfigured** | 0 | **Packaged app rules off** — not required by the STIG item; a Server Core DC runs no packaged apps (`EnableAppxRules = $false`) |
| **Dll** | **NotConfigured** / **NotConfigured** | 0 | **DLL rules off** — not required by the STIG item (`EnableDllRules = $false`) |

Both GPOs also set **System Services → Application Identity = Automatic** (`GptTmpl.inf`). Application Identity is a protected service; `sc.exe` / `Set-Service` / a GPP Services item cannot change it reliably, the System Services setting can.

---

## 2. What is in this repository

```
SVR-CORE-DC-APPLKR\                     copy anywhere on the management computer, e.g. C:\SVR-CORE-DC-APPLKR
  README.md  THIRD-PARTY-NOTICES.md
  docs\           SERVER-2022.md  APPLOCKER-ENTERPRISE-CONSIDERATIONS.md  applocker-8000-acl-invalid-server2022.md
  scripts\         AL-Settings.psd1  AL-Common.ps1  0_...  1_...  2_...  3_...  4_...  5_...  6_...  7_...  8_AL_reset.ps1
  Customizations\CustomizationInputs\   overlay for AaronLocker (never edit the toolkit itself):
                   GetExeFilesToDenyList.ps1  Server Core fix (lists only deny-list files that exist)
                   GetSafePathsToAllow.ps1    SYSVOL + NETLOGON (AaronLocker defaults) + ExtraAllowedPaths (C:\Admin\*)
                   KnownAdmins.ps1            adds the KnownAdmins setting
  AaronLocker\     microsoft/AaronLocker (MIT, unmodified)  +  AaronLocker\AccessChk.exe (Sysinternals, 64-bit)
  tests\           Test-AL.ps1 (291 unit tests, no network, both PowerShell editions; 297 with -BuildFolder)
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
| **Management computer** | Windows 10/11 or Windows Server, **Windows PowerShell 5.1 or PowerShell 7**, RSAT **Group Policy Management** and **Active Directory** modules, and the built-in `AppLocker` module. It must be a member of the DCs' domain (or forest). **Or one of the DCs itself:** every DC already has both modules, and each script runs its per-server steps in-process when the server is the computer it runs on (a remote session cannot open a second WinRM hop to its own computer; the scripts never try). Copy the repository to an administrators-only folder on the DC, e.g. `C:\SVR-CORE-DC-APPLKR`, outside `C:\AaronLocker`: [SERVER-2022.md, *Before you start*](docs/SERVER-2022.md#before-you-start-where-to-run-the-toolkit) copies the zip from the PAW. |
| **RSAT without Internet** | Windows Server: `Install-WindowsFeature GPMC, RSAT-AD-PowerShell` (the payload is on the server). Windows 11: `Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -Source <Features on Demand media> -LimitAccess` (same for `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`), or deploy the capability with MECM/WSUS. |
| **Account** | Domain Admin (or: create/link GPOs, write SYSVOL, WinRM administrator on the DCs). |
| **WinRM** | Enabled on every DC (default on Windows Server 2022 and 2025). Test: `Invoke-Command -ComputerName <dc> { $env:COMPUTERNAME }`. |
| **Reference DC** | Any DC in scope — DCs are built alike; the PDC emulator is a good choice. It must be in `FullLanguage` mode (no WDAC/AppLocker already restricting PowerShell for admins). If MECM or a Nessus Agent are on your DCs, they must be on the reference DC too. It must run the DCs' Windows Server version; with DCs of two versions, list one of the other version in `ExtraReferenceServers` ([SERVER-2022.md](docs/SERVER-2022.md)). |
| **Execution policy** | AaronLocker's scripts are not signed. If Group Policy sets *Turn on Script Execution* to *Allow only signed scripts* (AllSigned) on the reference DC or the management computer, sign the scripts with your code-signing certificate or run from a host the GPO does not cover. Pre-flight checks the reference DC and every extra reference DC. |
| **Servers** | **No Internet.** They receive a temporary folder over WinRM during the build (`C:\AaronLocker` on the reference DC, `C:\AaronLocker-1`, `-2` … on extra reference DCs, deleted afterwards) and Group Policy. |

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

6. **Optional - no management computer in the DCs' domain:** copy the zip from the PAW to a DC and run the toolkit there. [SERVER-2022.md, *Before you start*](docs/SERVER-2022.md#before-you-start-where-to-run-the-toolkit) has the commands (an administrators-only folder on the DC, the copy over WinRM, the hash check, bringing the results back).

> [!TIP]
> Optional: run the unit tests once on the management computer — no network, no domain, nothing outside a temporary folder: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ..\tests\Test-AL.ps1` (or `pwsh.exe`). Expected: `Tests: all 291 passed`.

---

## 5. Configure `AL-Settings.psd1`

Every script reads `scripts\AL-Settings.psd1`. Edit it once; the scripts refuse values that would widen the policy (drive roots, wildcards, `%variables%`) or damage a system folder.

| Setting | Meaning | Default |
|---|---|---|
| `AuditGpoName` / `EnforceGpoName` | The two GPOs | `JSLC_AppLocker_AUDIT_Domain_Controller` / `JSLC_AppLocker_ENFORCE_Domain_Controller` |
| `TargetOUs` | OUs whose servers get the policy | empty = **Domain Controllers** |
| `ReferenceServer` | The DC the baseline is built on. `PDC` = the PDC emulator of the domain the scripts run in, found at run time (pre-flight and the build print which DC it is), so one settings file serves every domain and enclave. Or the FQDN of one of **your** DCs; another server class needs an FQDN in its own settings file | `PDC` |
| `ExtraReferenceServers` | DCs of **another Windows Server version** in scope, one per version (e.g. a Server 2022 DC next to 2025 DCs). The build scans them too and merges every user-writable folder and denied tool they find: stricter only ([SERVER-2022.md](docs/SERVER-2022.md#dcs-of-both-versions)) | empty |
| `ExtraAllowedPaths` | Extra folders every account may run from. Each should be changeable by administrators only: the build checks every DC and **leaves out or excepts** what a non-admin can change — it never stops on it | `C:\Admin\*` |
| `SecureFolders` | Folders `0_AL_secure_folders.ps1` creates administrators-only when missing | `C:\Admin` |
| `KnownAdmins` | Your own administrators groups (DOMAIN\Group or SID) — `0_AL_known_admins.ps1` fills it from an OU or a group, see [section 11](#11-who-counts-as-an-administrator) | empty |
| `AccessChkSha256` | Pinned hash of the shipped AccessChk | `843B6B1D...F9F3` |
| `EnableDllRules` | `$false` = DLL collection off | `$false` |
| `EnableAppxRules` | `$false` = Appx (packaged app) collection off: emptied and `NotConfigured` in both GPOs, like the DLL collection. A Server Core DC runs no packaged apps, and a policy without the collection is the test to make when a Server Core DC logs AppLocker event 8000 ([SERVER-2022.md, section 7](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied)). `$true` keeps AaronLocker's rule that allows every signed packaged app | `$false` |
| `CollapseExceptionsUnder` | Folders whose user-writable subfolders are collapsed into **one** exception of the allow rules (stricter, and small enough to convert). AppLocker converts a collection into one 64 KB ACL with one entry per rule, and the `%WINDIR%\*` rule carries every user-writable folder; a DC's SYSVOL holds one per GPO whose creator or delegated editor is not an administrator ([step 4](#step-4--build-the-baseline)). Core Windows folders are refused | `%WINDIR%\SYSVOL\*` |
| `EventLogSizesMB` | AppLocker log sizes on the servers | 100 MB for each of the four logs |

**Several server classes** (DCs, MECM site systems, other servers)? Copy the file (`AL-Settings.mecm.psd1`), change it, and pass **`-SettingsFile`** to every script. Each file keeps its own `Outputs\<profile>` folder and its own GPO pair.

---

## 6. Run order at a glance

Run every script from the `scripts` folder, in **Windows PowerShell 5.1** (`powershell.exe`) or **PowerShell 7** (`pwsh.exe`):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\<script>.ps1 [parameters]
```

Every script carries comment-based help: `Get-Help .\<script>.ps1 -Full` shows its purpose, parameters, inputs, outputs, examples and what it changes.

| Step | Script | What it does | Changes |
|---|---|---|---|
| 1 | `0_AL_get_toolkit.ps1` | Verifies AaronLocker + AccessChk (signature, 64-bit, pinned SHA-256) | nothing (`-Download` / import only when asked) |
| 2 | `0_AL_known_admins.ps1 -Path <OU or group>` | Optional: surveys the OU of your administrator accounts (shows their groups), or turns your administrators groups (canonical name, as ADUC shows it) into `KnownAdmins` entries; `-Update` writes them | nothing (`-Update`: `AL-Settings.psd1`, after a backup) |
| 2 | `0_AL_pre-flight.ps1` | Modules, rights, OUs, toolkit, WinRM, language mode, execution policy, existing AppLocker policy, **MECM**, **Nessus**, services/tasks outside the allowed folders, **`C:\Admin` permissions**, **Windows Server version of every DC vs the reference DCs**, **PowerShell 2.0** | read-only |
| 3 | `0_AL_secure_folders.ps1` | Creates a missing `C:\Admin` administrators-only; reports a writable one | DCs (only a **missing** folder; an existing one only with `-Fix`) |
| 4 | `1_AL_build_policy.ps1` | Builds the baseline on the reference DC (merging the scans of any `ExtraReferenceServers`), checks `C:\Admin` on every DC (leaves out / excepts what a non-admin can change), brings the XML back, reports how each collection converts (its size against the 64 KB an ACL can hold) | temporary folder on the reference DC (and each extra reference DC) |
| 5 | `2_AL_create_gpos.ps1` | **Checks that both rule sets convert** (stops on one the DCs would reject with event 8000, status 1336), backs up, creates/updates the Audit + Enforce GPOs, reads the rules back, links new GPOs **disabled**, sizes the logs | domain (GPOs), DCs (log size) |
| 6 | `3_AL_set_mode.ps1 -Mode Audit -Refresh` | Enables the Audit link, then on every DC: `gpupdate /force` twice with its output kept, `gpresult` (which GPOs applied, the Registry and Security extensions), Application Identity, the effective policy and the newest policy event, judged against the mode (table + CSV + raw files) | domain (links) |
| 6 | `4_AL_validate.ps1` | GPOs, links, rules, service, effective policy, **gpresult per DC** (the expected GPO applied, the other not, extensions without error, newest policy event 8001), decisions, DC services, `C:\Admin`, events, **policy conversion check** of each GPO's rules, **policy store** and **compiled policy** per DC, update levels | read-only |
| 7 | `5_AL_review_events.ps1` | Summarises would-be-blocked events (tags MECM / NESSUS / ADMIN / SYSVOL), CSV | read-only |
| 8 | `3_AL_set_mode.ps1 -Mode Enforce -Refresh` | Disables Audit, enables Enforce, refreshes | domain (links) |
| 9 | `6_AL_stig_check.ps1` | Per DC, the STIG item for its version (WN25-00-000080 / V-277992 or WN22-00-000080 / V-254245): status + values + evidence XML | read-only |
| - | `7_AL_diagnose.ps1` | When a DC does not apply the policy (AppLocker event **8000**): the status decoded, service and driver, the AppLocker and packaged-app components, delivered vs effective policy, the policy store and the compiled files, the delivered rules checked the way they are converted (status 1336), gpresult, Group Policy / AppID / service events; evidence files per DC. `-Local` runs it on the DC's own console | read-only |
| - | `8_AL_reset.ps1` | Removes the deployment: backs up, unlinks and deletes both GPOs (links searched domain-wide); on every DC refreshes Group Policy, sets Application Identity and the AppLocker log sizes back to the Windows defaults (`-ClearLogs` exports and clears the logs first) and gives `C:\Admin` its inherited permissions back. `-WhatIf` shows the plan | domain (GPOs deleted, backups kept), DCs |

Every script that changes something shows the change in **yellow** and asks `Continue? [Y/N]`; **`-NoConfirm`** skips the prompt for automation, a non-interactive session without `-NoConfirm` stops before changing anything, and **`-WhatIf`** shows the plan without changing anything. Every run writes a transcript to `Logs\`; the read-only checks also write their results table as CSV and exit with code 1 on a failure.

---

## 7. Step by step

### Step 1 — Verify the toolkit

```powershell
.\0_AL_get_toolkit.ps1
```
Already done in [section 4](#4-bring-the-repository-into-the-disconnected-network). Run it again after you change anything under `AaronLocker\`.

### Step 2 — Pre-flight

`ReferenceServer` is `PDC` by default (the PDC emulator of the domain the scripts run in, found at run time); set it to an FQDN only for another server class, and set `TargetOUs` if not the DCs, in `AL-Settings.psd1`. If your organisation has its own administrators groups, survey the OU that holds your administrator accounts first — it writes nothing and shows which groups they belong to; [section 11](#11-who-counts-as-an-administrator) says what to do with the result:
```powershell
.\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-User-Accounts/DA'
```
Then:
```powershell
.\0_AL_pre-flight.ps1
```
It must end with **`Pre-flight: PASSED`**. Fix every **FAIL**; read every **WARN**:

| Output | Means | Do |
|---|---|---|
| `Reference server: <dc> (the PDC emulator of this domain; ReferenceServer = PDC)` | the keyword was resolved | nothing; this DC is scanned by the build |
| `Reference server` FAIL | `ReferenceServer` is `PDC` but the PDC emulator could not be found (not domain-joined, no AD access) | run on a domain-joined computer, or set an FQDN |
| `Reference server: not set` | `ReferenceServer` is empty | set it (`PDC`, or any DC in scope) |
| `Execution policy … AllSigned` (FAIL on the reference DC or an extra reference DC) | AaronLocker cannot run there | [section 3](#3-prerequisites) |
| `Version <DC>` (WARN) | That DC runs a Windows Server version (or installation type) that no reference DC runs. The build scans only the reference DCs for user-writable folders, so a folder only that version makes writable would stay allowed | add a DC like it to `ExtraReferenceServers` ([SERVER-2022.md](docs/SERVER-2022.md#dcs-of-both-versions)) |
| `PowerShell 2.0 <DC>` (WARN) | The `PowerShell-V2` feature is installed (Server 2022): `powershell.exe -Version 2` runs without Constrained Language Mode. STIG WN22-00-000410 | remove it ([SERVER-2022.md, section 3](docs/SERVER-2022.md#3-remove-powershell-20-from-the-2022-dcs)) |
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

Results: `AppLockerRules-<ts>-Audit.xml`, `…-Enforce.xml`, `ScanResults\Writable_*.txt` (the user-writable folders excluded from the allow rules), `build-info.json` (settings, the servers scanned and their versions, the `C:\Admin` decision per entry, what was collapsed, the conversion check, SHA-256 of the rule files). Harmless: `FILE SYSTEM OBJECT DOES NOT EXIST …OneDrive` (a desktop-only sample).

**The size of the rules.** AppLocker converts each rule collection into one access control list of at most 64 KB, one entry per rule, and the `%WINDIR%\*` rule carries every user-writable folder the scan found as part of its entry. The build prints a *conversion check* per rule file: the size of every collection, the largest rule and which folders its exceptions come from, e.g. `exceptions: 212 under %WINDIR%\SYSVOL\* (41,310 B), 31 under %WINDIR%\CCM\* (5,900 B) ...`. On a DC, SYSVOL contributes one folder per GPO whose creator or delegated editor is not an administrator, hundreds in a large domain, and the whole policy is then rejected by every DC (event 8000, status 1336; a first run on such a DC on 2026-10-28: the Windows rule alone 52,720 B, the Exe collection at 83% and the Script collection at 78% of the limit, both refused by Windows' parser). `CollapseExceptionsUnder` (default `%WINDIR%\SYSVOL\*`) turns all of them into one exception, reported as `N exception(s) under %WINDIR%\SYSVOL\* collapsed into one`; the rule only gets stricter. Non-admins never run from a DC's local SYSVOL; logon scripts come through `\\<domain>\SYSVOL`, which stays allowed. If other folders dominate, add them to the setting or, when their writers are an administrators group, to `KnownAdmins`. A rule set that still would not convert is reported here and stops `2_AL_create_gpos.ps1`. The whole story, a lab domain against an enterprise domain with hundreds of GPOs: [APPLOCKER-ENTERPRISE-CONSIDERATIONS.md](docs/APPLOCKER-ENTERPRISE-CONSIDERATIONS.md).

**DCs of more than one Windows Server version** (`ExtraReferenceServers`): the build also scans each extra reference DC, merges every user-writable folder and denied tool that any DC found (stricter only), generates the rules again on the reference DC from the merged scan, and checks that the rules carry every merged entry — otherwise it stops and deploys nothing. It lists what the other DCs added, keeps each DC's own scan in `ScanResults-<DC>\`, and warns when a DC in the target OUs runs a version that no scanned DC runs ([SERVER-2022.md, section 2](docs/SERVER-2022.md#dcs-of-both-versions)).

> [!NOTE]
> **Server Core:** several desktop binaries on AaronLocker's deny list (e.g. `mshta.exe`) are not installed, which makes the stock script fail. The `Customizations` overlay lists only files that exist — the scripts apply it automatically; do not edit the toolkit copy.

### Step 5 — Create or update the GPOs

```powershell
.\2_AL_create_gpos.ps1 -WhatIf     # the plan, nothing changed
.\2_AL_create_gpos.ps1             # asks Y/N; -NoConfirm for automation
```
It turns each build file into `…-Deploy.xml` (Audit: every collection `AuditOnly`; Enforce: every collection `Enabled`; DLL collection emptied and `NotConfigured`), **checks that each rule set converts** the way Application Identity converts it on a DC (one conditional ACE per rule, one ACL per collection, 64 KB each - a rule set beyond that is rejected by every DC with event 8000, status 1336, so the script stops; the sizes are printed and go into the deployment record), **backs up** an existing GPO (`Outputs\<profile>\gpo-backups\<ts>`), writes the rules with `Set-AppLockerPolicy -Ldap`, **reads them back and compares**, adds Application Identity = Automatic, raises the GPO version, links a new GPO to the target OUs **disabled**, records the deployed files with their SHA-256 in `<build>\deploy-<ts>.json`, and sizes the AppLocker logs. Existing links keep their state.

### Step 6 — Start Audit and validate

```powershell
.\3_AL_set_mode.ps1 -Mode Audit -Refresh
.\4_AL_validate.ps1
```
`-Refresh` runs `gpupdate /target:computer /force` twice on each DC (the first refresh starts Application Identity, the second loads the rules) and keeps the output of both passes. It then runs `gpresult /scope computer` on each DC and judges the result against the mode just set, in a table that is also saved as CSV:

| Row | OK means |
|---|---|
| `gpupdate <DC>` | both passes ended with exit code 0 (*Computer Policy update has completed successfully*) |
| `GPO applied <DC>` | the Audit GPO is applied and the Enforce GPO is not (for Enforce the other way round; for Off neither). Every other GPO is listed too, with the reason gpresult gives for one that is not applied (`Disabled (Link)`, `Denied (Security)`, ...) |
| `GPO processing <DC>` | the Registry extension (it writes the AppLocker rules) and the Security extension (the Application Identity service setting) ran without error |
| `AppLocker policy events <DC>` | the newest policy event is **8001** (applied). A newest **8000** (*AppID policy conversion failed*) is a WARN with the status decoded: the rules are not loaded on that DC ([Appendix D](#appendix-d--troubleshooting)). Windows Server 2022 logs the 8001 a minute or two after the refresh; when the policy is already effective the row says so (INFO) |
| `AppIDSvc <DC>` / `Effective policy <DC>` | Application Identity `Running/Auto`; the effective policy in the mode just set |
| `Group Policy <DC>` | when and from which DC Group Policy was last applied, and where the raw output is |
| `Policy conversion <GPO>` / `Policy rule <GPO>` (validate) | the rules in that GPO convert the way the DCs convert them: every rule's SID, condition and exceptions as a conditional ACE, every collection within the 64 KB an ACL can hold (sizes shown). A FAIL names the rule or collection the DCs would reject (event 8000, status 1336) |
| `Policy store <DC>` / `Policy converter <DC>` (validate) | the permissions of `System32\AppLocker` and of the `Srp` / `SrpV2` keys are canonical, with SYSTEM and Administrators allowed and readable by the service (the folder's SDDL is shown, to compare with a DC that applies the policy); the `PolicyConverter` task exists, with its account and last result |
| `Compiled policy <DC>` (validate) | every delivered collection has its `<Collection>.AppLocker` file in `System32\AppLocker`, written after the last conversion (a file older than an 8000 means the converter wrote nothing new) |
| `Windows build <DC>` / `Update levels <version>` (validate) | the build and update level of each DC; DCs of one version at different levels are a WARN |

The raw output (every gpupdate pass, the `gpresult /r` report, the `gpresult /x` XML) is kept per DC in `Logs\3_AL_set_mode-<Mode>-<timestamp>-gpresult\`. The same happens for Enforce and Off. Without `-Refresh`, DCs apply the change at their next refresh (every **5 minutes**) or at boot, and the script says so.

Validation must end with **`Validation: PASSED`**: both GPOs with AD = SYSVOL version, one active link, Application Identity `Running / Auto`, effective policy `Exe/Msi/Script = AuditOnly` (`Appx`, `Dll = NotConfigured`), DC services running, nothing in `C:\Admin` that a non-admin can change is still allowed, and per DC the same gpresult rows as above (`GPO applied`, `GPO processing`, `AppLocker policy events`; raw reports in `Logs\4_AL_validate-<timestamp>-gpresult\`), the rules of both GPOs converting (`Policy conversion`), and per DC the policy store, the compiled files and the update level (`Policy store`, `Policy converter`, `Compiled policy`, `Windows build`, `Update levels` - the rows marked *validate* above). The DLL and `ManagedInstaller` collections that MECM's managed installer adds are reported (INFO), not judged.

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
The effective policy must now read `Exe/Msi/Script = Enabled`, `Appx` and `Dll = NotConfigured`. Then check that the DCs work (`dcdiag`, replication, logons, Group Policy) and watch `5_AL_review_events.ps1` (8004/8007) for a few days, including a reboot and a patch cycle. Keep the way back in mind ([section 13](#13-rollback)).

### Step 9 — STIG check

```powershell
.\6_AL_stig_check.ps1
```
Per DC: the STIG item for its Windows Server version — **WN25-00-000080 / V-277992 (CAT II)** on Server 2025, **WN22-00-000080 / V-254245 (CAT II)** on Server 2022 — status **NotAFinding** or **Open**, and the values behind it — every rule collection (mode and rule count), Application Identity, the enabled AppLocker GPO link, blocked events in the last 24 hours. It runs the STIG's own check command (`Get-AppLockerPolicy -Effective -XML`) and saves each DC's effective policy as evidence (`Outputs\<profile>\stig-<ts>\<DC>-effective-applocker.xml` + SHA-256), with the results in `Logs\6_AL_stig_check-<ts>.csv`. Open = Application Identity not running, or the EXE collection not `Enabled` (Audit is a finding), or no EXE rules.

The version comes from the DC (from AD when it can't be reached). A DC of another Windows version is **Not_Reviewed**, with the AppLocker result in the `Reason` column to record under that version's own STIG item ([SERVER-2022.md, section 4](docs/SERVER-2022.md#4-the-server-2022-stig-ids)).

---

## 8. Domain controller considerations

### Typical DC functions

| Function | Why it keeps working |
|---|---|
| AD DS (`NTDS`), DNS, KDC, Netlogon, DFSR (SYSVOL), W32Time, AD Web Services | Services started by the Service Control Manager — not evaluated by this policy; their binaries are in `C:\Windows` anyway |
| Group Policy processing, startup/shutdown scripts | Run as SYSTEM |
| Logon scripts | `\\<domain>\NETLOGON` and `\\<domain>\SYSVOL` are allowed for everyone — NETLOGON scripts and GPO logon scripts stored in SYSVOL run in any session; the DC's own `C:\Windows\SYSVOL` folder is **not** allowed for non-admins (`CollapseExceptionsUnder`, [step 4](#step-4--build-the-baseline)) |
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

### What `KnownAdmins` is for, and who is affected

The setting answers one question for the scan: *"this account can write here — is it an administrator?"* It never adds an allow rule and never changes a permission. Permissions name **groups**, almost never people, so the setting is a list of groups.

| Principal | In `KnownAdmins`? | Why |
|---|---|---|
| `SYSTEM`, the service accounts, `Administrators`, `Administrator`, `Domain Admins`, `Enterprise Admins`, Server / Print / Backup Operators | **No** — already counts | Listing it changes nothing; the script reports *Already an administrator* and skips it |
| A delegated administrators group that is **not** in `Administrators` but holds write access on a folder under `C:\Windows`, `Program Files` or `C:\Admin` (e.g. `CONTOSO\Tier0-Server-Admins`) | **Yes** | Without the entry that folder is carved out of the policy: non-admin and non-elevated code there is blocked in Enforce and logged in Audit. With it, the folder stays allowed for every account |
| The user accounts in an administrators OU (ten Domain Admins in a `DA` OU, say) | **No** | No permission names them, and as Domain Admins they already count. `-IncludeUsers` exists only for a permission that names a person — rare, and a finding in itself |
| `Domain Users`, `Domain Computers`, `Authenticated Users`, `Users`, `Everyone`, … | **Never** — refused | Every folder those accounts can write would count as administrators-only, so the policy would allow code from user-writable folders. The script and the settings check both refuse these |

A **missing** entry affects nobody's security: a folder that could have stayed allowed is carved out, so a tool a non-admin runs from there is blocked (Enforce) or logged (Audit). A **wrong** entry affects everyone: a too-broad group widens what non-admins may run. When in doubt, leave a group out.

**How to find out what belongs there** — let the evidence decide, in this order:

1. **Survey the OU that holds your administrator accounts** (without `-IncludeUsers`). The script writes nothing; it prints each account with the groups it belongs to, and those groups are the candidates:
   ```powershell
   .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-User-Accounts/DA'
   ```
   ```
   INFO  User not listed  CONTOSO\jsmith at contoso.com/Domain Administration/.../DA/jsmith - KnownAdmins is for groups (direct member of: Domain Admins, Tier0-Server-Admins). -IncludeUsers lists it anyway.
   ...
   Nothing to list: no security group under the given path(s) needs a KnownAdmins entry (10 user account(s) found - KnownAdmins takes groups; see the rows below).
       KnownAdmins       = @()
   ```
2. **Check which of those groups actually hold write access.** `0_AL_pre-flight.ps1` reports `Extra path writable … can be changed by CONTOSO\Tier0-Server-Admins` for `C:\Admin`, and after a build `Outputs\<profile>\<timestamp>\ScanResults\Writable_*.txt` names the trustee behind every carve-out under `C:\Windows` and `Program Files`. A group that appears there **and** is an administrators group belongs in `KnownAdmins`. `Domain Admins` never appears: it already counts.
3. **Add exactly those groups** — one group by name, or every security group in the OU where you keep them (`-Recurse` adds sub-OUs). The DA OU of *accounts* is not that OU; it is the OU of *groups* (or the group itself):
   ```powershell
   .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-Groups/Tier0-Server-Admins' -Update
   .\0_AL_known_admins.ps1 -Path 'contoso.com/Domain Administration/Administration/Admin-Groups' -Recurse -Update
   ```
   `-Update` merges with the existing entries (`-Replace` discards them), backs the file up to `Outputs\<profile>\settings-backups` and asks `Continue? [Y/N]` (`-NoConfirm` for automation, `-WhatIf` to see it). Entries are written as `DOMAIN\Name` (`-AsSid` for SIDs); a distinguished name works instead of a canonical name.
4. **Rebuild** (steps 4–5): the value only applies at the next `1_AL_build_policy.ps1`.

If nothing appears in step 2, leave `KnownAdmins` empty — even with ten accounts in the DA OU.

---

## 12. Ongoing operations

| Event | Do |
|---|---|
| **New software / agent / role on the DCs** | Audit first if you can; add its folder or publisher, rebuild (steps 4–5) |
| **Monthly patching** | Nothing — Microsoft-signed content under `C:\Windows`, installed as SYSTEM. Check `5_AL_review_events.ps1` after the first cycle |
| **New DC** | It gets the active GPO at its next refresh (two refreshes or a reboot before the rules load). Run step 3 for `C:\Admin`, then `4_AL_validate.ps1`. If it runs a Windows Server version the others don't, add it to `ExtraReferenceServers` and rebuild (pre-flight warns: `Version <DC>`) |
| **Rebuild** | `1_AL_build_policy.ps1` → `2_AL_create_gpos.ps1`. In Enforce, switch to Audit first (`3_AL_set_mode.ps1 -Mode Audit -Refresh`), review, then Enforce again |
| **Updating AccessChk** | On an Internet-connected computer: download AccessChk.zip, take `accesschk64.exe`, check `Get-AuthenticodeSignature` (Valid, Microsoft Corporation) and `Get-FileHash`. Put the new hash in `AccessChkSha256`, then `.\0_AL_get_toolkit.ps1 -AccessChkPath <accesschk64.exe>` (it refuses a file that does not match the pinned hash) |
| **Audit evidence** | `6_AL_stig_check.ps1` (status + evidence XML) and `4_AL_validate.ps1` (CSV in `Logs\`, gpresult reports in `Logs\4_AL_validate-<ts>-gpresult\`) |
| **A DC does not apply the policy** | `7_AL_diagnose.ps1 -ComputerName <dc>` (or `-Local` on the DC): event 8000 decoded, components, service, delivered vs effective, gpresult, events; evidence in `Outputs\<profile>\diag-<ts>\` ([Appendix D](#appendix-d--troubleshooting)) |

---

## 13. Rollback

| Situation | Command |
|---|---|
| Enforce blocked something | `.\3_AL_set_mode.ps1 -Mode Audit -Refresh -NoConfirm` (back to log-only) |
| Remove AppLocker entirely | `.\3_AL_set_mode.ps1 -Mode Off -Refresh -NoConfirm` — the rules are removed at the next refresh (the STIG item becomes a finding again) |
| A GPO update went wrong | `Restore-GPO -BackupId <id> -Path <Outputs\<profile>\gpo-backups\<ts>>` (IDs are in the step 5 output and in `deploy-<ts>.json`) |
| On a DC itself | Elevated administrators and SYSTEM are always allowed, so `gpupdate /force`, PowerShell and WinRM keep working |
| Remove the GPOs and reset the DCs | `.\8_AL_reset.ps1 -WhatIf`, then `.\8_AL_reset.ps1 -ClearLogs` - backs up, unlinks and deletes both GPOs, refreshes the DCs, resets Application Identity, the AppLocker log sizes and the `C:\Admin` permissions; `-KeepGpos` only unlinks, `-KeepFolderPermissions` leaves `C:\Admin` alone. Undo: `Restore-GPO` from its backup, or deploy again (steps 3 to 6) |

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

**2026-10-27 — Windows Server version handling** (version-aware STIG check, pre-flight version and PowerShell 2.0 checks, `ExtraReferenceServers`), re-verified on the same lab without changing the DC, its policy or any GPO (before/after snapshot):

| Check | Edition | Result |
|---|---|---|
| `0_AL_pre-flight` | 5.1 + 7 | PASSED; `Versions` OK (Windows Server 2025, build 26100, Server Core); no PowerShell 2.0 row — the feature no longer exists on Server 2025 |
| `0_AL_pre-flight` with a Windows 11 computer as the reference / as an extra reference | 5.1 / 7 | `Version DC25-1` WARN / `Versions` OK; the extra reference's `Restricted` execution policy FAILs |
| `6_AL_stig_check` | 5.1 + 7 | **WN25-00-000080 / V-277992: NotAFinding** (item chosen from build 26100) |
| `6_AL_stig_check` with an unknown host listed first and a Windows 11 computer | 5.1 + 7 | both `Not_Reviewed` (no STIG ID claimed), the DC still NotAFinding, every CSV column kept |
| `1_AL_build_policy` (test profile, no extra reference) | 5.1 | rules identical to the deployed build (62 rules each in Audit and Enforce, ignoring rule IDs and the timestamp rule) |
| `1_AL_build_policy -ExtraReferenceServers DC25-1` (the same DC by its short name) | 7 | same-computer warning; scan, merge, rules generated again from the merged scan, self-check passed (16 folders, 9 tools); rules identical to the deployed build |
| A simulated second scan with one extra folder and one extra tool | 5.1 | both in the regenerated rules; the self-check flags a policy without them |
| `1_AL_build_policy` with an extra reference that can't run AaronLocker | 5.1 | STOP before the first scan; the DC's work folder removed, nothing written on the refused computer, `latest.txt` unchanged |
| `2_AL_create_gpos -WhatIf` on the merged build (compare-only GPO names) | 5.1 + 7 | picks the merged rule files; no GPO created |
| `tests\Test-AL.ps1` | 5.1 + 7 | 182/182; 188/188 with `-BuildFolder` (the real build and the merged build) |

**2026-10-27 (later) - gpupdate / gpresult recorded by `3_AL_set_mode.ps1 -Refresh` and `4_AL_validate.ps1`, `7_AL_diagnose.ps1`, `EnableAppxRules`** - verified against the same Server 2025 DC (in Enforce) from a Windows 11 computer, without changing any GPO or policy:

| Check | Edition | Result |
|---|---|---|
| `Invoke-ALGpRefresh -Refresh $true` on DC25-1 (what `3_AL_set_mode.ps1 -Refresh` runs per DC) | 7 | both gpupdate passes captured (exit code 0, *Computer Policy update has completed successfully*); the DC logged 8001 after each pass; gpresult text and XML read; `GPO applied` OK for Enforce (ENFORCE applied, AUDIT `Disabled (Link)`) and FAIL with both reasons named when judged as Audit; `GPO processing` Registry and Security OK; raw files written |
| `7_AL_diagnose.ps1 -ComputerName DC25-1 -Days 60` | 5.1 + 7 | PASSED: every AppLocker and packaged-app component present with its version, AppIDSvc Running/Auto, appid driver running, event provider and message file present, 38 x 8001 and 0 x 8000, 25 rules delivered = 25 effective, the decisions of the table above, 15 evidence files |
| `7_AL_diagnose.ps1 -Local` on the Windows 11 computer (no domain, no RSAT) | 5.1 | PASSED: the console path a Server Core DC uses; without a delivered policy the stopped service is reported as normal |
| `tests\Test-AL.ps1` | 5.1 + 7 | 230/230 |

**2026-10-27/28 - Server Core 2022, the toolkit run on the DC itself.** `DC22-2`, Windows Server 2022 Standard Server Core, the only DC of a second lab forest (no management computer in it), updated first (2026-10 cumulative update, build 20348.4529 to 20348.5761, installed by a SYSTEM scheduled task and a restart), then every script run on the DC over WinRM in Windows PowerShell 5.1:

| # | Step | Result |
|---|---|---|
| 1 | `0_AL_pre-flight` | PASSED with 1 warning: `C:\Admin` writable by `BUILTIN\Users` (inherited from `C:\`); PowerShell 2.0 feature Removed |
| 2 | `0_AL_secure_folders -Fix` | `C:\Admin` permissions replaced (previous SDDL in the transcript); verified SYSTEM + Administrators only |
| 3 | `1_AL_build_policy` | in-process build on the reference DC (no WinRM to itself); `C:\Admin\*` allowed; Exe 10, Msi 5, Script 9, Appx 1 rules |
| 4 | `2_AL_create_gpos` | both GPOs created (computer version 2), linked disabled, logs 100 MB |
| 5 | `3_AL_set_mode -Mode Audit -Refresh` | Audit link enabled; gpupdate 2 passes exit 0; `GPO applied` Audit applied, Enforce `Disabled (Link)`; `GPO processing` Registry + Security OK; AppIDSvc Running/Auto; effective `Exe/Msi/Script/Appx = AuditOnly`; **Refresh (AUDIT): PASSED** |
| 6 | `4_AL_validate -Mode Audit` | **PASSED** (both GPOs AD = SYSVOL version, one link, service, effective policy, decisions, DC services, gpresult rows) |
| 7 | `7_AL_diagnose` | PASSED: every component present, 25 rules delivered = 25 effective, **no event 8000**; the 8001 was logged 90 s after the refresh (the diagnosis had run 25 s after it) |
| 8 | `5_AL_review_events` | 0 would-be-blocked events; 8002 / 8005 allowed events flowing |
| 9 | `dcdiag /q` | only the DFSREvent and SystemLog tests report events (SYSVOL replication warnings after the promotion of the same day, a Secure Boot certificate notice, an ETW publisher error); nothing AppLocker-related |

On 2026-10-28, after a review that found no would-be-blocked event, the DC went to **Enforce**: `3_AL_set_mode -Mode Enforce -Refresh` PASSED, `4_AL_validate -Mode Enforce` PASSED, `6_AL_stig_check` **WN22-00-000080 / V-254245: NotAFinding**, 0 blocked events, `dcdiag` unchanged ([SERVER-2022.md, section 4](docs/SERVER-2022.md#audit-then-enforce-the-stig-result-after-each-mode), with the STIG result after each mode). The event 8000 seen there in an earlier, unrecorded attempt did not recur ([SERVER-2022.md, section 7](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied)).

**2026-10-28 - `8_AL_reset.ps1`, then a new build to Audit, then a restart** (`DC22-2`, from Enforce):

| Step | Result |
|---|---|
| `8_AL_reset -ClearLogs -WhatIf` | plan shown, nothing changed (checked before and after) |
| `8_AL_reset -ClearLogs` | both GPOs backed up, unlinked and deleted; logs exported (99 + 53 events) and cleared, sizes back to 1052672 bytes; Application Identity Manual and stopped (Group Policy restored Manual itself when the GPO went away); `C:\Admin` inherited again, identical to its original permissions; effective policy empty |
| `8_AL_reset` again | PASSED with nothing left to do |
| Pre-flight, `0_AL_secure_folders -Fix`, `1_AL_build_policy`, `2_AL_create_gpos`, `3_AL_set_mode -Mode Audit -Refresh`, `4_AL_validate -Mode Audit` | all PASSED; two new GPOs; `C:\Admin\*` allowed; STIG item Open (expected in Audit) |
| Restart | back in under a minute; after the boot `4_AL_validate -Mode Audit` and `7_AL_diagnose` PASSED, the 8001 came 2 minutes after the boot, no 8000, 0 would-be-blocked events |
| `3_AL_set_mode -Mode Enforce -Refresh` after a review with no would-be-blocked event | PASSED; `4_AL_validate -Mode Enforce` and `7_AL_diagnose` PASSED; `6_AL_stig_check` **WN22-00-000080 / V-254245: NotAFinding**; 0 blocked events |

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

`8001` = *The AppLocker policy was applied successfully to this computer*. `8000` = *AppID policy conversion failed. Status <code>*: Application Identity rejected the policy it was given, so nothing is enforced or audited on that computer; its only field, `Status`, is a Win32 error code (2 = the system cannot find the file specified, 126 = the specified module could not be found, 1168 = element not found, 5 = access denied, **1336 = the access control list (ACL) structure is invalid**: the converted rules did not form a valid ACL - Application Identity stores a collection as one ACL with one conditional ACE per rule, and neither an ACL nor an ACE can exceed 64 KB - or the ACL on the policy store is damaged; [SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied), cause 5). `3_AL_set_mode.ps1 -Refresh` and `4_AL_validate.ps1` flag a newest 8000; `7_AL_diagnose.ps1` decodes every 8000 and looks for the cause. The 8002-8022 events carry the file, the matching rule, the account (SID) and the publisher. Also see `Microsoft-Windows-AppID/Operational` (the lab DC logs recurring `4005 AppID certificate store verification failed` events; they did not affect enforcement).

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
| Pre-flight WARN `Version <DC>`, or build warning *… runs Windows Server 2022 …, which none of the scanned servers runs* | DCs of more than one version: add one DC of that version to `ExtraReferenceServers` and rebuild ([SERVER-2022.md](docs/SERVER-2022.md#dcs-of-both-versions)) |
| Build warning *… is …, the same computer as …* | An `ExtraReferenceServers` entry is the reference DC (or another entry) under another name: remove it, or name the server you meant |
| `STOP: … does not carry N entries of the merged scan` | AaronLocker did not build the rules from the merged scan. Nothing was deployed; the scans are in the build folder. Run the build again; if it repeats, compare `ScanResults\` with the rules |
| STIG check `Not_Reviewed`: *no STIG item mapped for …* | The DC runs a Windows version this toolkit has no STIG item for. Record the AppLocker result from `Reason` under that version's deny-all, permit-by-exception item |
| Many 8003 warnings for `.dll` files in *EXE and DLL* | MECM's managed installer audits DLLs (DLL rules are off in this baseline). Expected; `5_AL_review_events.ps1` counts and skips them; size the log up ([section 9](#9-mecm-configuration-manager)) |
| `Application Identity` Stopped / Manual after the GPO applied | `gpupdate /force` once or twice, or reboot; `4_AL_validate.ps1`. A GPP *Services* item does **not** work for this protected service — the GPO uses System Services |
| Effective policy empty after the first refresh | The service had just started: refresh again (`-Refresh` does it twice) |
| `Both links enabled` | `3_AL_set_mode.ps1 -Mode Audit` (or Enforce) disables one link before enabling the other |
| `Local AppLocker policy` warning | A local AppLocker policy that is **not** MECM's managed installer merges with the GPO — review `Get-AppLockerPolicy -Local -Xml` ([section 9](#9-mecm-configuration-manager)) |
| A script runs in *Constrained Language* in Enforce | It was not allowed for that account (non-admin or non-elevated, outside the allowed folders). Elevate, move it to `C:\Admin`, or add a rule |
| `STOP: … non-interactive` | The script needs Y/N: run it in a console, or add `-NoConfirm` for automation |
| WinRM errors | `Enable-PSRemoting` on the DC; firewall 5985; use FQDNs |
| `AppLocker policy events … newest is 8000` (set_mode / validate), or event **8000** *AppID policy conversion failed. Status …* in the *EXE and DLL* log | Application Identity could not convert the delivered policy: the rules are **not loaded** on that DC, nothing is audited or enforced. Run `7_AL_diagnose.ps1 -ComputerName <dc>` (or `-Local` on the DC): it decodes the status, checks the AppLocker and packaged-app components, the service and driver, delivered vs effective policy, gpresult and the related events. On a Server Core DC see [SERVER-2022.md, section 7](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied); the status decides the first test: **1336** is the row below, 126 / 1168 on Server Core is `EnableAppxRules = $false` (the default - check that it was not switched on) |
| Event 8000 with status **1336** (*The access control list (ACL) structure is invalid*) | The "ACL" is the converted policy itself, not a folder permission: Application Identity turns every rule collection into one ACL with one conditional ACE per rule, and an ACL or an ACE cannot exceed 64 KB. `4_AL_validate.ps1` (`Policy conversion` / `Policy rule` rows) says whether the rules in each GPO convert and how big every collection is; `2_AL_create_gpos.ps1` now stops on a rule set that would not. If the rules convert, read the `Policy store` and `Compiled policy` rows of that DC (`7_AL_diagnose.ps1` does the same and adds a `Hypothesis` row) and compare its update level with a DC that applies the policy ([SERVER-2022.md, section 7, cause 5](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied)). The full account of the enterprise case, lab versus a large domain: [APPLOCKER-ENTERPRISE-CONSIDERATIONS.md](docs/APPLOCKER-ENTERPRISE-CONSIDERATIONS.md) |
| `Policy conversion …` FAIL / `Policy rule …` | A rule or a collection the DCs would reject: one rule with its exceptions, or a whole collection, beyond 64 KB (too many user-writable folders or deny-list entries in one rule, too many hash rules), or a bad SID, hash or version range. The row names the folders the exceptions come from: collapse them with `CollapseExceptionsUnder` (SYSVOL on a DC, [step 4](#step-4--build-the-baseline)), list their writers in `KnownAdmins` when they are an administrators group, or use fewer hash rules; then rebuild (steps 4-5) |
| *The description for Event ID 8000 (or 8001, 8002, ...) from source Microsoft-Windows-AppLocker cannot be found ... The handle is invalid* | An **Event Viewer window that stayed connected to the DC while the DC restarted** (seen in the lab): its handle to the DC's event log service is no longer valid, so new events still appear but none can be rendered. Close Event Viewer and connect again. The events and the DC are fine; `Get-WinEvent -ComputerName <dc> -LogName 'Microsoft-Windows-AppLocker/EXE and DLL'` renders them meanwhile. An exported `.evtx` opened on a computer without the provider shows the same text unless its `LocaleMetaData` folder is kept with it (`wevtutil epl` + `wevtutil al`). For an 8000 the single number shown is its `Status` ([SERVER-2022.md, section 7](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied), which also shows what a working DC's logs look like) |
| `GPO applied <DC>` FAIL | gpresult on that DC does not show the expected GPO applied; the row names the reason (`Disabled (Link)`, `Denied (Security)`, not linked, both applied). Run `3_AL_set_mode.ps1` again, check replication (`repadmin /syncall`), read the raw report in `Logs\…-gpresult\` |
| `GPO processing <DC>` error N | The Registry (AppLocker rules) or Security (service setting) client-side extension failed on that DC with that Win32 error. Group Policy operational log (events 7016 / 1085); `7_AL_diagnose.ps1` lists them |

---

## Appendix E — Design decisions and limits

- **Built on a DC itself**, because the rules depend on its disk (user-writable folders, tools present). Build one baseline per server class; the reference must resemble the class, down to its Windows Server version. DCs of two versions in one class: `ExtraReferenceServers` merges a scan of each version into one policy — a union, so it only gets stricter ([SERVER-2022.md](docs/SERVER-2022.md)).
- **Two GPOs, one enabled link**, so Audit and Enforce never merge and switching is one command. Both GPOs carry the full rule set and the service setting.
- **DLL rules off** — not required by WN25-00-000080; they add overhead and a high rule-maintenance burden. `EnableDllRules = $true` switches them on (`AuditOnly` / `Enabled` like the rest).
- **Appx (packaged app) rules off by default** — not required by the STIG items; a Server Core DC runs no packaged apps. `EnableAppxRules = $false` empties the collection (`NotConfigured`) in both GPOs, so the policy carries no collection a Server Core DC might fail to convert (event 8000, [SERVER-2022.md, section 7](docs/SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied)). `EnableAppxRules = $true` keeps AaronLocker's *all signed packaged apps* rule (`AuditOnly` / `Enabled` like the rest), as on the lab DC in [Appendix A](#appendix-a--lab-verification-2026-10-26).
- **Every rule set is compiled before it is deployed.** AppLocker stores a collection as one security descriptor, one conditional ACE per rule, and neither an ACL nor an ACE can exceed 64 KB (their size fields are 16-bit). `Test-ALPolicyConvertible` in `AL-Common.ps1` rebuilds every rule's ACE the way Microsoft documents it, compiles it with Windows' own SDDL parser and measures each collection: the build prints it, `2_AL_create_gpos.ps1` stops on a FAIL, `4_AL_validate.ps1` repeats it on the rules read back from each GPO and reads the policy store of every DC.
- **Every refresh is recorded.** `3_AL_set_mode.ps1 -Refresh` keeps the gpupdate output and a gpresult report per DC and judges them; `4_AL_validate.ps1` repeats the gpresult check; `7_AL_diagnose.ps1` is the read-only deep dive when a DC does not apply the policy.
- **The toolkit can run on a DC itself** (no management computer in that domain, as in the lab's second forest). A server that is the computer a script runs on is reached in-process instead of over WinRM (`Test-ALLocalComputer` / `Invoke-ALOn` in `AL-Common.ps1`; the build opens no session to itself). Everything else - the other DCs, the GPOs, SYSVOL - is reached exactly as before.
- **No services enforcement in this baseline** — services are not evaluated (AppLocker's default) unless MECM's managed installer turns it on through its local policy; the baseline is safe either way on DCs (services run as SYSTEM or from the allowed folders).
- **AaronLocker is not maintained since 2022.** It only *generates XML*; the deployment (GPO, links, service) is plain Group Policy and `Set-AppLockerPolicy`. Keep each `Outputs\<profile>\<ts>` folder: it is what you tested.
- **Desktop leftovers** in the baseline (the Microsoft Teams publisher rule, the AaronLocker timestamp rule) are harmless on a DC.
- **`\\<domain>\SYSVOL\*` and `\\<domain>\NETLOGON\*` are allowed for everyone** (AaronLocker's default, needed for logon scripts). Members of *Group Policy Creator Owners* and delegated GPO editors can write their own GPO folders under SYSVOL; keep that group administrators-only (in the lab its only member is `Administrator`).
- **`C:\Admin` never breaks the build**: what a non-admin can change is left out or excepted, on the evidence of every DC in scope — the policy stays safe without anyone changing permissions.
- **Administrators are allowed everywhere** (AppLocker default rule): this constrains non-admin and non-elevated code, not an administrator.
- **Audit mode logs allowed executions too**, which is why the logs are enlarged (`EventLogSizesMB`). Forward the AppLocker logs with Windows Event Forwarding / your SIEM if you need history.
- **Scripts:** Windows PowerShell 5.1 and PowerShell 7, ASCII-only, settings validated before anything runs, changes behind a yellow Y/N gate (`-NoConfirm`, `-WhatIf`), GPO backup before an update, transcripts and CSV results in `Logs\`.
