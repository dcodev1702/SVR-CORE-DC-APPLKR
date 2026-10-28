# AppLocker event 8000 "AppID policy conversion failed – ACL invalid" on Server 2022 (AaronLocker)

Prepared 2026-10-28. Scope: a Windows Server 2022 domain controller where the AppLocker policy built with AaronLocker (via the SVR-CORE-DC-APPLKR toolkit) is delivered by GPO but the DC logs:

> Microsoft-Windows-AppLocker/EXE and DLL, Event ID 8000: AppID policy conversion failed. Status: the access control list (ACL) is invalid.

Nothing was changed on the repo or the DC while preparing this. It is an analysis plus a diagnostic plan.

---

## 1. Bottom line

- I could not find any public source that ties this status to AaronLocker or to Server 2022. The cause is **not documented**, so what follows is evidence plus inference, clearly labeled.
- Event 8000 is a generic wrapper. The numeric/text **Status** inside it carries the real cause, and it varies from case to case.
- AaronLocker only generates XML. The failure happens later, inside the Application Identity service on the DC, when it converts the delivered rules into the form the `appid` driver loads. So the question is: is it the **rule content** or the **DC's own state** (permissions on the policy store, hardening, leftover local policy)?
- The fastest way to find out is a two-part test: apply the same XML on a non-DC Server 2022 machine, and trace the failing operation on the DC with Process Monitor (Section 4).

---

## 2. What the repo documents (and doesn't)

Source: README and SERVER-2022.md of `dcodev1702/SVR-CORE-DC-APPLKR` (I could not read README Appendix D, which was cut off in what I could fetch, nor the script source).

- SERVER-2022.md section 7 covers event 8000 on Server Core 2022. Its status table decodes only: 2, 3, 126, 1168, 13, 87, 5. **The ACL-invalid status (likely ERROR_INVALID_ACL, 1336) is not listed.**
- Its one concrete remedy is `EnableAppxRules = $false` (empty the Appx collection). That targets missing packaged-app components (statuses like 126/1168), which does not match an ACL error. I would test it only after the checks below.
- The repo's only lab 8000 on Server 2022 was never root-caused: the status code was not captured, and the issue did **not** reproduce after the 2026-10 cumulative update (build 20348.4529 to 20348.5761) on a reset DC. There, 8001 was logged about 90 seconds after the refresh.
- The repo notes Microsoft's statement that AppLocker on Server Core is not supported (applies to Server Core 2022 and 2025).

---

## 3. What the research shows

- The only public report of this exact message is a TechNet thread (Windows 10 Enterprise 1809 workstations). It occurred right after `gpupdate /force`. The only reply: run Process Monitor and find which file or folder SYSTEM is denied access to, then fix permissions there. No confirmed resolution.
- Other 8000 reports show different statuses and causes: "transaction no longer active", "access is denied", and "log space exhausted" (the last one traced to a corrupted registry.pol on a Server 2008 R2 DC).
- Microsoft documents 8000 as "AppID policy conversion failed" and says the status text is provided for troubleshooting.

---

## 4. Ranked hypotheses and how to test them (Server 2022 DC)

My ranking is inference, not documented fact.

| # | Hypothesis | Why plausible | Test |
|---|---|---|---|
| 1 | **Damaged or non-canonical ACL on AppLocker's policy store** (hardening GPO/STIG/CIS, earlier `icacls`, security template) | The TechNet advice and the status text both point at access control structures. DCs are often hardened. | Compare SDDL against a working Server 2022 machine (step C) and trace with Procmon (step B) |
| 2 | **Something in the rule content** | AaronLocker output is large and includes Appx, Msi, Script and Exe collections. A bad SID or a rule the converter can't handle is possible, though I consider a bad SID less likely than #1 | Apply the same XML on a non-DC 2022 box (step A) and bisect collections |
| 3 | **Stale local AppLocker policy or MECM managed-installer policy merging badly** | The README says local policies merge with the GPO | `Get-AppLockerPolicy -Local -Xml` vs `-Effective -Xml` |
| 4 | **Patch level / damaged AppLocker components** | The repo's own 2022 lab stopped hitting 8000 after the 2026-10 CU | Check build/UBR; run `7_AL_diagnose.ps1 -Local` |
| 5 | **Corrupted registry.pol / GPO processing problem** | One old report fixed an 8000 this way (different status) | `gpresult /h` and check the Registry extension for errors |

### Step A: policy content or DC environment? (most discriminating)

1. On a **non-DC Server 2022** machine, apply the same AaronLocker Audit XML locally:
   ```powershell
   Set-AppLockerPolicy -XmlPolicy .\AppLockerRules-<ts>-Audit-Deploy.xml
   gpupdate /target:computer /force
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'; Id=8000,8001} -MaxEvents 10 |
       Select-Object TimeCreated, Id, Message
   ```
2. Result 8001: the XML is fine and the problem is the DC's own state (hypotheses 1, 3, 4).
3. Result 8000 again: the rules are the problem. Bisect: apply only default rules, then add the Exe, Script, Msi and Appx collections one at a time.

### Step B: find the failing operation on the DC

Run Process Monitor (Sysinternals) on the DC:

- Filter: Process Name is `AppIdPolicyConverter.exe` or `svchost.exe`; Result is not SUCCESS (hide benign NAME NOT FOUND, NO MORE ENTRIES, BUFFER OVERFLOW).
- Trigger: `gpupdate /target:computer /force`, twice (the repo notes the first pass starts Application Identity and the second loads the rules).
- Look at the last non-success result before the 8000 timestamp. It should name the key or file involved.

Procmon is not part of Server Core, so you would have to bring it in.

### Step C: compare permissions with a working machine

Paths below are from my understanding of AppLocker internals; verify they exist on your build (a key may not exist until a policy has applied):

```powershell
foreach ($p in 'HKLM:\SYSTEM\CurrentControlSet\Control\Srp\Gp',
               'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2') {
    "{0}`n{1}`n" -f $p, (Get-Acl $p).Sddl
}
"{0}`n" -f (Get-Acl "$env:windir\System32\AppLocker").Sddl
```

Run on the failing DC and on a working Server 2022 machine, then diff. Look for non-canonical ACE order, orphaned SIDs, or a missing SYSTEM entry.

### Step D: read-only baseline checks

```powershell
# Is 8000 the newest policy event, or does an 8001 follow it?
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'; Id=8000,8001} -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message

# Is an effective policy loaded at all?
(Get-AppLockerPolicy -Effective -Xml).Length

# Local vs effective policy
Get-AppLockerPolicy -Local -Xml
Get-AppLockerPolicy -Effective -Xml

# OS build / UBR
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
```

The repo's own `7_AL_diagnose.ps1 -Local` (on the DC) captures the decoded Status, components, service and driver state, delivered vs effective policy, and gpresult in one read-only run.

---

## 5. What the repo should account for (Server 2022)

1. Add the ACL-invalid status (1336) to the section 7 status table, with the policy-store permissions as the cause to check.
2. Make `7_AL_diagnose.ps1` dump the SDDL of the policy-store keys and folder, flag non-canonical ACEs and unresolvable SIDs, and compare against a known-good server.
3. Have it compare the DC's build/UBR against the other DCs and against the lab's patched build.
4. Make pre-flight warn about GPOs that apply registry or file-system ACLs to those paths, and about existing local or managed-installer AppLocker policy (today the local-policy warning is generic).
5. Put "patch first, then diagnose" ahead of the Appx test in section 7.
6. Print the raw numeric Status in the diagnose summary, since it decides everything.
7. Document a client-side check that `Get-AppLockerPolicy -Effective -Xml` is non-empty after refresh. `2_AL_create_gpos.ps1` only verifies the GPO side.

---

## 6. Open questions that would narrow the cause

- Is the 8000 the newest AppLocker event, or is there an 8001 after it?
- What build/UBR is the DC on?
- Server Core or Desktop Experience?
- Are STIG/CIS hardening GPOs applied that set registry or file ACLs?
- Did you modify the AaronLocker output (custom rules, `KnownAdmins` changes)?
- What does `7_AL_diagnose.ps1 -Local` report, and what is the exact numeric Status?

---

## 7. Caveats

- I could not read the repo's script source or README Appendix D, so the "repo gaps" list is based on the README and SERVER-2022.md only and may be partly wrong.
- Hypotheses 1 to 3 are my inference. No source confirms any of them for this exact status on Server 2022.
- Registry and folder paths in Step C are from memory of AppLocker internals; verify before relying on them.

---

## Sources

- Repo: https://github.com/dcodev1702/SVR-CORE-DC-APPLKR (README) and https://github.com/dcodev1702/SVR-CORE-DC-APPLKR/blob/main/SERVER-2022.md (section 7)
- TechNet thread (same message, Windows 10 1809): https://learn.microsoft.com/en-us/archive/msdn-technet-forums/9221e2c3-d382-44da-b4c9-b6a47a81d969
- Microsoft, Using Event Viewer with AppLocker: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker
- grouppolicy.biz, How to Troubleshoot AppLocker (8000 with "transaction no longer active"): https://www.grouppolicy.biz/2013/04/how-to-troubleshoot-applocker/
- Server 2008 R2 report (8000 fixed by removing a corrupted registry.pol): https://lightciedoe1.blogspot.com/2012/06/applocker-policy-application-error.html

---

## 8. What the code review found and what the toolkit does about it (2026-10-28)

The review of the scripts and of AaronLocker, with Microsoft's AppLocker documentation, changes the picture in section 4: the "ACL" of status 1336 is most likely **the converted policy itself**, not a folder or key permission. Application Identity stores every rule collection as one security descriptor in which each rule is one conditional ACE (`XA` / `XD`, the rule's SID, the condition on `APPID://PATH`, `APPID://FQBN` or `APPID://SHA256HASH`), and an ACL and an ACE each carry their size in a 16-bit field: 64 KB at most. Nothing in the scripts produces a bad SID or a malformed condition (AaronLocker writes `S-1-1-0`, `S-1-5-32-544` and `S-1-3-0` only, and `Set-AppLockerPolicy` validates the XML against the schema), but the `%WINDIR%\*` rule carries every user-writable folder and every deny-list entry as exceptions in one ACE, and hash rules add up in one ACL. The store permissions (hypothesis 1) and the update level (hypothesis 4) stay possible and are now checked too. Relaxing permissions on folders is not the first move.

Against the list in section 5:

| Item | Done |
|---|---|
| 1. 1336 in the section 7 status table | Yes, with cause 5 (the three sub-causes in the order to rule them out) |
| 2. Dump the SDDL of the policy-store keys and folder, flag non-canonical ACEs | Yes: `4_AL_validate.ps1` and `7_AL_diagnose.ps1` rows `Policy store <DC>` (FAIL on a non-canonical ACL or a missing SYSTEM entry; the folder SDDL printed for a diff with a working DC); `policy-store.csv` in the diagnosis folder |
| 3. Compare the build/UBR across DCs | Yes: rows `Windows build <DC>` and `Update levels <version>` (WARN when DCs of one build differ) |
| 4. Pre-flight warning about GPOs that set ACLs on those paths | Not done - there is no reliable way to tell from the GPO side; the store rows read the result on each DC instead |
| 5. "Patch first" ahead of the Appx test | The order now depends on the status: 1336 is cause 5 (content, store, then the DC's update level); the Appx test stays cause 3 for 126 / 1168 |
| 6. Print the raw numeric Status | It was printed already; every 8000 row now adds what that status points at |
| 7. Client-side check that the effective policy is non-empty after refresh | It existed (`Effective policy <DC>`); the `Compiled policy <DC>` row now also shows whether the converter wrote a new `<Collection>.AppLocker` file |
| (new) Catch a rule set that cannot convert **before** it is deployed | `Test-ALPolicyConvertible` in `scripts\AL-Common.ps1` rebuilds every rule's conditional ACE, compiles it with Windows' own SDDL parser and measures every collection against the 64 KB limit; `1_AL_build_policy.ps1` prints it, `2_AL_create_gpos.ps1` stops on a FAIL, `4_AL_validate.ps1` repeats it on the rules read back from each GPO, `7_AL_diagnose.ps1` on the rules delivered to the DC. 29 unit tests in `tests\Test-AL.ps1` |

Still open: the Server 2022 DC that logged the error from the PAW was reset before its status was captured, so the cause of that one 8000 remains unproven. The next 8000 is decoded, classified and, if the rules are the cause, prevented.
