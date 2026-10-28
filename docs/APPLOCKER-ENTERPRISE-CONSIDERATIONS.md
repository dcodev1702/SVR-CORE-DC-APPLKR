# AppLocker on domain controllers: what breaks between a lab and an enterprise domain

Part of [SVR-CORE-DC-APPLKR](../README.md). Written on 2026-10-28, after the toolkit's first run against a domain controller of a large domain. The lab domain (one Server Core 2025 DC, one Server Core 2022 DC, a handful of GPOs) had applied the same baseline without a problem. The enterprise DC rejected it with AppLocker event 8000, status 1336, *The access control list (ACL) structure is invalid*. This page records what was happening, why the two environments behaved differently, what was changed in the toolkit and why, and how to operate it from here.

> [!NOTE]
> **Outcome.** The cause was the size of the converted policy, not a permission. AppLocker turns every rule collection into one access control list with one entry per rule; the entry of the `%WINDIR%\*` rule carries every user-writable folder the build found under `C:\Windows`, and on an enterprise DC that list runs into the hundreds (SYSVOL holds one such folder per GPO). The toolkit now compiles every rule set before it is deployed, names the folders that make a rule big, and collapses the SYSVOL folders into one exception (`CollapseExceptionsUnder`). With that change the policy converted, and AppLocker runs on the Server Core 2022 and Server Core 2025 DCs (confirmed 2026-10-28).

## Contents

1. [What was happening](#1-what-was-happening)
2. [How AppLocker stores a policy, and where the ACL comes in](#2-how-applocker-stores-a-policy-and-where-the-acl-comes-in)
3. [Lab versus enterprise: why the same build behaves differently](#3-lab-versus-enterprise-why-the-same-build-behaves-differently)
4. [The evidence from the first enterprise run](#4-the-evidence-from-the-first-enterprise-run)
5. [What was changed in the toolkit, and why](#5-what-was-changed-in-the-toolkit-and-why)
6. [Operating the toolkit in an enterprise domain](#6-operating-the-toolkit-in-an-enterprise-domain)
7. [Limits and open points](#7-limits-and-open-points)
8. [Sources](#sources)

---

## 1. What was happening

**The symptom.** The GPO applied (gpresult listed it), the Registry client-side extension wrote the rules to `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2`, and then the DC's *Microsoft-Windows-AppLocker/EXE and DLL* log showed:

> Event 8000: AppID policy conversion failed. Status: The access control list (ACL) structure is invalid.

`Get-AppLockerPolicy -Effective -Xml` was empty. Nothing was audited or enforced. The status text is Win32 error 1336, `ERROR_INVALID_ACL`.

**Why it was hard to read.** The word *ACL* sends every administrator to folder and registry permissions. The one public report of this status (Windows 10 1809, 2020) ended with "run Process Monitor and give SYSTEM access to whatever it cannot reach", and no resolution. The first analysis of this case went the same way: hardening templates, `icacls`, the permissions of the AppLocker policy store. Those remain possible causes of a 1336 and the toolkit checks them now, but they were not the cause here.

**What it actually was.** The ACL in the message is the converted policy itself. Section 2 explains the mechanism; the short version is that one rule had grown to 52,720 bytes and its collections to 78 to 92 percent of the 64 KB an ACL can hold, which the converter could not turn into a valid ACL.

**Why nobody saw it coming.** The build, the deployment and the validation all handled the policy as XML. The XML was valid: every rule had a proper SID, condition and exceptions, `Set-AppLockerPolicy` accepted it, the GPO read it back identically. The size of the *converted* form was never looked at, because nothing in the toolkit, in AaronLocker or in Microsoft's AppLocker documentation says there is a limit. The limit comes from the Windows security model underneath, one level down.

---

## 2. How AppLocker stores a policy, and where the ACL comes in

**One security descriptor per collection, one ACE per rule.** Microsoft's "AppLocker processes and interactions" page states it directly: AppLocker policies are stored in a security descriptor format; each rule is stored as an access control entry (ACE) in the security descriptor, as an allow or deny ACE (`XA` or `XD` in SDDL), with the user or group SID the rule applies to and the rule condition on the *appid* attributes. The example it gives for "allow all files in the Windows folder" is:

```
XA;;FX;;;AU;(APPID://PATH == "%windir%\*")
```

The Application Identity service (`AppIDSvc`) runs the conversion through the `PolicyConverter` scheduled task (`AppIdPolicyConverter.exe`), writes the result to `%windir%\System32\AppLocker\<Collection>.AppLocker` and notifies the `appid.sys` driver. The driver evaluates a file by putting the file's attributes (`APPID://PATH`, `APPID://FQBN` for the publisher, `APPID://SHA256HASH`) into the process token and running an ordinary access check against that descriptor: a deny ACE whose condition is true denies, an allow ACE whose condition is true allows, nothing else is allowed. That is AppLocker's "explicit deny, explicit allow, implicit deny" rule order, implemented with the kernel's own access-check code.

**Where the exceptions go.** A rule with exceptions is still one ACE. Its condition becomes `(<condition>) && !(<exception 1>) && !(<exception 2>) ...`. Every exception adds its path, publisher name or hash to that one entry. AaronLocker's `%WINDIR%\*` rule, which allows everyone to run from the Windows folder, carries as exceptions every folder under `C:\Windows` that a non-administrator can write to (so that nobody can plant code there and run it) and, in the EXE collection, every entry of the deny list (`mshta.exe`, `cipher.exe`, `runas.exe`, the .NET tools). All of it is inside one ACE.

**The limit.** An ACL and an ACE each carry their own size in a 16-bit field (`AclSize` in the `ACL` structure, `AceSize` in `ACE_HEADER`). Microsoft's ACL reference says it in one sentence: *the maximum size for an ACL, including its ACEs, is 64 KB*. Nothing in AppLocker raises that limit, because AppLocker does not own the format: it is the Windows security descriptor, read by the same kernel code that checks file permissions. An ACL that would need more than 65,535 bytes is not an ACL, and the error for "not an ACL" is 1336.

**The limit in practice is lower.** In the first enterprise run (section 4), Windows' own SDDL parser, `ConvertStringSecurityDescriptorToSecurityDescriptor`, accepted every rule on its own and refused each big collection as one ACL with error 122, *the data area passed to a system call is too small*, at 78, 83 and 92 percent of the limit. The parser's internal accounting evidently overflows before the final bytes reach 65,535 (the exact reason is inside Windows and not documented; the pattern, single ACEs accepted and the sum refused, is what the toolkit observed). The converter on the DC reported the same situation as 1336. The working assumption from here is: keep every collection under half of 64 KB.

**What is not the ACL in the message.** The permissions of `C:\Windows\System32\AppLocker`, of the `Srp` and `SrpV2` registry keys, and of the GPO's SYSVOL folder are real objects with real ACLs, and a damaged one would also produce a 1336 or a 5. The toolkit reads them now (section 5), but in this case they were in order.

---

## 3. Lab versus enterprise: why the same build behaves differently

**How AaronLocker builds the Windows rule.** `Create-Policies.ps1 -Rescan` runs Sysinternals AccessChk over `C:\Windows`, `C:\Program Files` and `C:\Program Files (x86)` on the reference DC and lists every directory where an account that is not a known administrator (SYSTEM, Administrators, the Operators groups, `NT SERVICE\` accounts, CREATOR OWNER, plus `KnownAdmins`) holds write permissions. It removes redundant entries (a subfolder of a listed folder is dropped), adds an `:*` entry where the folder also allows an alternate data stream, maps the paths to `%WINDIR%` and `%SYSTEM32%`, and writes each remaining folder as an exception of the Windows rule in the EXE, DLL and Script collections. The result is `ScanResults\Writable_windir.txt` (the list) and `Writable_windir_Full.xml` (the list with the accounts that hold the write permission).

On a freshly installed server that list has twenty to forty entries: `%WINDIR%\Temp`, `%WINDIR%\Tasks`, `%WINDIR%\tracing`, `%WINDIR%\Registration\CRMLog`, `%SYSTEM32%\Tasks`, `%SYSTEM32%\spool\drivers\color`, `%SYSTEM32%\spool\PRINTERS`, `%SYSTEM32%\Com\dmp`, `%SYSTEM32%\FxsTmp`, the `Microsoft.NET` temporary folders and a few more. That is the shape AaronLocker was designed around: a workstation, where the user-writable folders under Windows are a short, stable list.

**What a domain controller adds.** SYSVOL lives under `C:\Windows\SYSVOL`. Every GPO has a folder there, `C:\Windows\SYSVOL\domain\Policies\{GUID}\` (and a second view of it through the `SYSVOL\sysvol` junction). The permissions of that folder are the GPO's permissions. Two things put a non-administrator on them:

- **Delegation.** Any group given *Edit settings* on a GPO, a help desk group, an application team, a site's own administrators, holds write permissions on that GPO's folder. If the group is not in `KnownAdmins`, the scan counts the folder as user-writable.
- **Creation.** When a member of *Group Policy Creator Owners* creates a GPO, the creating account gets an explicit entry on the GPO (visible under *Delegation* in GPMC) and on its SYSVOL folder. User accounts are never administrators to the scan, so every GPO ever created by such an account counts.

One folder per GPO, with its `Machine` and `User` subfolders dropped as redundant. A domain with 300 GPOs and ordinary delegation produces a few hundred entries, each `%WINDIR%\SYSVOL\DOMAIN\POLICIES\{GUID}\*` path 50 to 60 characters long. The MECM client (`C:\Windows\CCM`, `ccmcache`, `CCMSetup`) and other agents add their own, which the build already reports ("MECM / Tenable folders that are user-writable on a scanned server").

**The arithmetic.** Each path exception costs about 37 bytes plus 2 bytes per character inside the ACE. A SYSVOL folder path of 55 characters is about 150 bytes. Three hundred of them are 45 KB, inside one ACE, which is then copied into the EXE, the DLL and the Script collection. Add the deny list to the EXE collection and the trusted-signer rules to the DLL collection and every one of the three collections is past three quarters of the limit.

| | Lab domain (2026-10-26/27) | Enterprise domain (2026-10-28) |
|---|---|---|
| GPOs | a handful, all created by Administrator | hundreds, delegated and created over years |
| User-writable folders under `C:\Windows` | a few dozen | hundreds (SYSVOL, plus CCM) |
| Exceptions in the `%WINDIR%\*` rule | a few dozen | hundreds |
| Size of that rule's ACE | a few KB | 52,720 B |
| EXE collection | small (25 rules delivered in all) | 54,184 B, 82.7% of 64 KB |
| Script collection | small | 51,256 B, 78.2% |
| DLL collection (built, not deployed) | small | 60,292 B, 92% |
| Conversion on the DC | 8001, policy applied | 8000, status 1336 |

Nothing else differed. Same scripts, same AaronLocker, same Windows Server versions, same GPO mechanics. The policy was correct XML in both cases; only the converted size changed, and it changed with the number of GPOs.

**Why this is an enterprise property.** The number of GPOs, the delegation model and the history of who created them are facts about the domain, not about the DC. A reference DC built in a clean lab, or in a domain with few GPOs, cannot show the problem. The toolkit's own lab run was faithful to the scripts and blind to this. The lesson generalises: anything in `C:\Windows` or `Program Files` that grows with the organisation (GPOs, agent caches, per-application folders with delegated permissions) grows the Windows rule, and the Windows rule has a hard ceiling.

---

## 4. The evidence from the first enterprise run

`1_AL_build_policy.ps1` on 2026-10-28, with the conversion check added that morning, printed for both rule files (the Audit file shown; the Enforce file was identical apart from the modes):

```
AppLockerRules-20261028-0800-Audit.xml: conversion check FAIL - Appx=AuditOnly 1 rule(s), 164 B (0.3% of 64 KB);
  Dll=AuditOnly 37 rule(s), 60,292 B (92% of 64 KB); Exe=AuditOnly 9 rule(s), 54,184 B (82.7% of 64 KB);
  Msi=AuditOnly 5 rule(s), 796 B (1.2% of 64 KB); Script=AuditOnly 8 rule(s), 51,256 B (78.2% of 64 KB);
  largest rule: Exe 'All files located in the Windows folder' 52,720 B
    FAIL Exe: the Exe collection does not compile as one ACL although every rule does on its own
         (error 122: The data area passed to a system call is too small.) - 9 rules, about 54,184 bytes
    WARN Exe: the Exe collection uses 82.7% of the 64 KB an ACL can hold (54,184 bytes, 9 rules): add rules sparingly
    FAIL Script: ... (error 122 ...) - 8 rules, about 51,256 bytes
    FAIL Dll: ... (error 122 ...) - 37 rules, about 60,292 bytes
WARNING: A rule file would not convert on the servers (AppLocker event 8000, status 1336: the ACL structure is invalid).
         2_AL_create_gpos.ps1 stops on it: review the FAIL lines, fix the cause (README, Appendix D) and build again.
```

How to read it:

- **No "(estimated)" anywhere.** Every size is exact: Windows' own SDDL parser compiled each rule's conditional ACE. The rules are well-formed; the problem is not a bad SID, hash or version range.
- **One rule is 52,720 B.** The Windows rule's exceptions. At 130 to 240 bytes per folder, that is 200 to 400 user-writable folders under `C:\Windows`.
- **Every collection compiles rule by rule and fails as a whole**, at 78 to 92 percent of the limit. The converter on the DC had reported that same state as 1336.
- **The Appx and Msi collections are tiny.** The limit is per collection. The one rule drags three collections over it because AaronLocker puts the same exceptions into EXE, DLL and Script.
- **The DLL line was noise.** `EnableDllRules` is `$false`, so the deploy step empties that collection; the build was checking a file the DCs would never receive in that form. The build now skips collections the settings switch off.

After the fix (section 5): the build collapsed the SYSVOL folders into one exception, the conversion check passed, `2_AL_create_gpos.ps1` wrote the GPOs, and the Server Core 2022 and 2025 DCs applied the policy (8001, effective policy present, no 8000). The confirmation is the operator's, from 2026-10-28; the post-fix sizes were not recorded on this page.

---

## 5. What was changed in the toolkit, and why

Everything below is on the `policy-conversion-check` branch (commits `33783ca` and `ec6a417`). Each item names the problem it answers.

### 5.1 The conversion check (`Test-ALPolicyConvertible`, `scripts\AL-Common.ps1`)

**Problem.** Nothing looked at the converted form of the policy; a rule set that no DC can convert passed every existing check and was found out only by the event log on the DC.

**Change.** The toolkit rebuilds the conditional ACE of every rule the way Microsoft documents it and Forshaw's analysis of the compiled `Exe.AppLocker` file shows it: a path rule as `APPID://PATH Contains "<path>"`, a hash rule as `(Exists APPID://SHA256HASH) && (APPID://SHA256HASH Any_of {#<hash>})`, a publisher rule as `(Exists APPID://FQBN) && (APPID://FQBN >= {"<publisher>\<product>\<file>", <version>})`, each exception as `&& !(...)`, allow as `XA`, deny as `XD`, with the rule's SID. On Windows it hands every ACE and then every whole collection to `ConvertStringSecurityDescriptorToSecurityDescriptor`, the parser behind `AddConditionalAce`, and reads the exact binary sizes back. Where the parser is not available, or does not accept a form, it estimates the size from the binary token layout of conditional expressions (MS-DTYP) and says so. It checks every rule's SID, action, condition count, hash format and version range on the way. A rule beyond 65,535 bytes, a collection beyond it, a collection the parser refuses as a whole, or a rule the parser rejects is a FAIL; from 50 percent of the limit a WARN. Collections the settings switch off (`-Ignore`) are reported as not deployed and not judged.

**Why 50 percent.** The parser refused collections from 78 percent in the real run. Half is the margin that keeps a growing domain out of that band.

### 5.2 Which folders make the rule big (`Get-ALExceptionBreakdown`)

**Problem.** "52,720 bytes" says how big, not why. The operator had to open the XML or the scan files to find out.

**Change.** For the largest rule of every collection, and for any rule that fails, the check groups the path exceptions by their first two segments and prints count and bytes, biggest first, plus the publisher and hash exceptions: `exceptions: 212 under %WINDIR%\SYSVOL\* (41,310 B), 31 under %WINDIR%\CCM\* (5,900 B), 14 under %SYSTEM32%\SPOOL\* ...`. The same phrase appears in the build output, in `2_AL_create_gpos.ps1`, in the `Policy conversion` row of `4_AL_validate.ps1` and in `7_AL_diagnose.ps1`. When a whole collection fails, the check also bisects the rules and names the one that tips it over ("the parser accepts the first 2 rule(s) (1,464 B) and refuses them with 'All files located in the Windows folder' (52,720 B) added").

### 5.3 Collapsing the exceptions (`Compress-ALRuleExceptions`, setting `CollapseExceptionsUnder`)

**Problem.** Hundreds of SYSVOL folders must stay excluded (a non-administrator can write to them), but as individual exceptions they do not fit.

**Change.** The new setting lists roots; the build removes every exception under a root from every allow rule in every collection and puts the root itself in their place, once. The default is `%WINDIR%\SYSVOL\*`. Three hundred exceptions become one, the rule shrinks by tens of kilobytes, and nothing the scan excluded is allowed again: the root covers all of it. The build prints what it did (`N exception(s) under %WINDIR%\SYSVOL\* collapsed into one, in 3 rule(s) (Exe, Dll, Script)`) and records it in `build-info.json`; the merged-scan proof used with `ExtraReferenceServers` accepts a parent exception as covering its children.

**Why it is safe on a DC.** The collapse only ever takes execution away. Non-administrators have no business running anything from a DC's local `C:\Windows\SYSVOL`; Group Policy logon scripts are started through `\\<domain>\SYSVOL` and `\\<domain>\NETLOGON`, which the baseline allows for everyone, and startup scripts run as SYSTEM. Elevated administrators are allowed everywhere by the default rule. The one visible effect: a non-elevated session on the DC cannot run a script by its local SYSVOL path. That was already true for every delegated GPO folder; it is now true for all of them.

**Why it is not automatic for every folder.** Collapsing `%SYSTEM32%\*` or `%WINDIR%\*` would be "safe" by the same logic and would cut every non-elevated session off from the operating system. The setting refuses `%WINDIR%\SYSTEM32\*`, `%WINDIR%\SYSWOW64\*`, `%WINDIR%\WINSXS\*`, `%WINDIR%\MICROSOFT.NET\*` and `%WINDIR%\SERVICING\*`, and anything that is not a folder under a known root. Other roots (`%WINDIR%\CCM\*` for a large MECM client footprint, for example) are the operator's decision, made from the breakdown.

### 5.4 Stop before the GPO is written (`2_AL_create_gpos.ps1`)

**Problem.** A rule set that no DC can convert used to reach every DC in the OU at once; the first sign was the 8000 on each of them.

**Change.** The deploy step runs the conversion check on both `-Deploy.xml` files, prints the sizes and the breakdown, records the result in `deploy-<timestamp>.json`, and stops on a FAIL. `-SkipPolicyCheck` deploys anyway, for tests.

### 5.5 Validate and diagnose (`4_AL_validate.ps1`, `7_AL_diagnose.ps1`)

**Problem.** A 1336 has three possible causes (the rule content, the DC's policy store, the DC's patch level) and the toolkit could not tell them apart.

**Change.** Validate adds, per GPO, `Policy conversion` and `Policy rule` rows (the rules read back from the GPO, compiled and measured) and, per DC, `Policy store` (the permissions of `System32\AppLocker`, its files and the `Srp` / `SrpV2` keys as SDDL, with canonical order, SYSTEM and Administrators entries and read access for the service account checked), `Policy converter` (the `PolicyConverter` task, its account, last run and result), `Compiled policy` (each delivered collection against its `<Collection>.AppLocker` file and its time, so a file older than an 8000 shows that the converter wrote nothing), `Windows build` and `Update levels` (DCs of one build at different update levels are a WARN). Diagnose does the same on the rules delivered to the DC's registry and adds a `Hypothesis` row for status 1336 that says which cause the evidence supports. Every 8000 row now carries a hint for its status (`Get-ALStatusHint`).

### 5.6 Smaller things

- `1_AL_build_policy.ps1` prints the conversion check for every rule file and records it (`Conversion`, `Collapsed`) in `build-info.json`.
- 48 unit tests in `tests\Test-AL.ps1` cover the ACE forms, the size accounting, the limits, the breakdown, the collapse, the settings validation, the result rows and, on Windows, the parser and the store probe.
- `README.md` (settings, step 4, step 6 rows, appendices C, D, E), `SERVER-2022.md` section 7 (status 1336, cause 5) and the original analysis write-up were updated.

---

## 6. Operating the toolkit in an enterprise domain

**Before the first build.** Count the GPOs and look at how they are delegated. Every GPO with a non-administrator editor or creator will show up as a user-writable folder. If your delegated editors are administrators groups in your organisation's sense (a Tier 0 operations group, for example), list them in `KnownAdmins`: their write access then does not count, and the folders leave the list altogether. If they are not administrators, leave them to the collapse.

**Read the build output.** After `Processing additional safe paths` and the AaronLocker lines, three things matter:

1. `N exception(s) under %WINDIR%\SYSVOL\* collapsed into one` (yellow). Expected on every DC build. A large N is normal.
2. `conversion check OK - ...` with every deployed collection well under 50 percent, and `largest rule: ... (exceptions: ...)`. Note the biggest group after SYSVOL. If it is `%WINDIR%\CCM\*` or another agent folder and the rule is still large, add that root to `CollapseExceptionsUnder` and build again.
3. No `FAIL` line. A WARN at 50 percent or more is a signal to act now, not later: the next GPO, the next agent, the next hash rule pushes it further.

**Deploy and validate as before.** `2_AL_create_gpos.ps1` repeats the check and refuses a failing set. `3_AL_set_mode.ps1 -Mode Audit -Refresh` then `4_AL_validate.ps1`: `Policy conversion` OK for both GPOs, `Policy store`, `Compiled policy` and `AppLocker policy events ... newest is 8001` OK for every DC.

**When a DC still logs 8000.** `7_AL_diagnose.ps1 -ComputerName <dc>` (or `-Local` on the DC). The `Hypothesis` row for a 1336 names the cause the evidence supports: the content (fix the build), the policy store (compare the SDDL with a DC that applies the policy and restore it), or neither (compare the update level with a DC that applies the policy, patch, then trace `AppIdPolicyConverter.exe` with Process Monitor).

**Keep as evidence.** The build folder (`build-info.json` with the collapse and the sizes, `ScanResults\Writable_windir_Full.xml` with the writers), the `deploy-<timestamp>.json`, the validate CSV and the gpresult reports. They show what was excluded, why, and that the DCs applied it.

**What to watch over time.** The `Policy conversion` row of every validate run is the trend line: the size of the EXE and Script collections. It rises with new GPOs that are delegated, with agents that create writable folders under Windows, and with every hash rule added to allow a file in a writable folder. Hash rules are the other way to run out: at about 150 bytes each, a few hundred fill a collection. Prefer publisher rules, and prefer moving a file into `C:\Admin` over allowing it where it is.

---

## 7. Limits and open points

- **The practical ceiling is not documented.** The 64 KB maximum of an ACL is; the point at which the converter and the SDDL parser give up is below it and was observed at 78 percent. The toolkit treats a refusal by the parser as the authoritative test and 50 percent as the planning line. If a future Windows build moves that point, the check moves with it, because it asks the parser rather than a table.
- **Sizes are exact only where the parser accepts a form.** The path and hash forms are documented SDDL; the publisher form with a `{"name", version}` literal is what the compiled policy shows. A parser that rejects one of them makes the check report estimates for those rules, marked as such, never a false failure. The 2026-10-28 run showed exact sizes for every rule, so the parser on Windows Server 2022 accepted all three forms.
- **The original 8000 from the PAW was never decoded.** That DC was reset before its status was read. The size failure found on 2026-10-28 is consistent with it (same toolkit, same domain, same scan), and the fix made the DCs apply the policy, but the first event's status stays unrecorded.
- **The collapse is a policy decision, recorded but not reversible by the scripts.** Removing a root from the setting and building again restores the individual exceptions. The policy only ever gets stricter with a root present.
- **Server Core.** Microsoft's AppLocker overview states that AppLocker on Server Core installations is not supported. The toolkit's lab and the first enterprise deployment run it there; record the statement with your accepted risks, as `SERVER-2022.md` section 6 asks.
- **What the toolkit cannot see.** Rules merged from another GPO or from a local policy on the DC (the MECM managed installer, for example) add their own ACEs to the same per-collection ACL. Validate reports foreign collections; it cannot size what another GPO will add later. Keep one AppLocker GPO per server class.

---

## Sources

- Microsoft Learn: [AppLocker processes and interactions](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions). "AppLocker policies are stored in a security descriptor format ... Each rule is stored as an access control entry (ACE) in the security descriptor"; the `XA;;FX;;;AU;(APPID://PATH == "%windir%\*")` example; the policy converter task notifies `appid.sys`.
- Microsoft Learn: [AppLocker architecture and components](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-architecture-and-components). Policies are conditional ACEs evaluated with `SeAccessCheckWithSecurityAttributes` / `AuthzAccessCheck`; the file's attributes go into the process token.
- Microsoft Learn: [ACL structure (winnt.h)](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-acl) ("The maximum size for an ACL, including its ACEs, is 64 KB"; `AclSize` is a `WORD`) and [ACE_HEADER](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header) (`AceSize` is a `WORD`).
- Microsoft Learn: [Security Descriptor Definition Language for Conditional ACEs](https://learn.microsoft.com/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-). The `XA` / `XD` strings, attributes, literals and operators the check builds.
- Microsoft Learn: [Using Event Viewer with AppLocker](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker). Event 8000, "AppID policy conversion failed. Status"; 8001, the policy was applied.
- James Forshaw, [The Internals of AppLocker - Part 3](https://www.tiraniddo.dev/2019/11/the-internals-of-applocker-part-3.html) (2019). The compiled `Exe.AppLocker` file carries the security descriptor; one callback ACE per rule with `APPID://PATH Contains`, `APPID://SHA256HASH Any_of` and `APPID://FQBN >=` conditions.
- Microsoft TechNet forum (archived): [AppID policy conversion failed. Status The access control list (ACL) structure is invalid](https://learn.microsoft.com/en-us/archive/msdn-technet-forums/9221e2c3-d382-44da-b4c9-b6a47a81d969) (2020, Windows 10 1809). The only other public report; no resolution.
- This repository: `Test-ALPolicyConvertible`, `Get-ALExceptionBreakdown`, `Compress-ALRuleExceptions`, `$ALPolicyStoreProbe` in [`scripts\AL-Common.ps1`](../scripts/AL-Common.ps1); the setting in [`scripts\AL-Settings.psd1`](../scripts/AL-Settings.psd1); [SERVER-2022.md, section 7](SERVER-2022.md#7-applocker-event-8000-on-a-server-core-2022-dc-the-policy-is-delivered-but-not-applied), cause 5; the original analysis in [applocker-8000-acl-invalid-server2022.md](applocker-8000-acl-invalid-server2022.md).
