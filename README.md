# SOUR Workstation Cryptography Hardening — Script Reference

## Overview

This collection of scripts and guides was developed to resolve a software compatibility conflict on the SOUR workstation where the Windows FIPS algorithm policy, along with specific SCHANNEL settings for SHA256 hashing and PKCS key exchange, causes a third-party application to throw a "Security Service is unavailable" error. The overall goal is to disable the FIPS flag on the SOUR workstation's isolated OU while compensating for its absence by incrementally applying the individual strong-cryptography registry settings that FIPS would normally enforce — excluding the three settings confirmed to break the software — and to verify software stability after each change. The scripts cover every phase of this process: initial baseline configuration and rollback, DISA STIG management, domain join procedure, and the final incremental cryptography rollout via both GPO (from the Domain Controller) and direct local registry (on the workstation itself). All SCHANNEL Cipher, Hash, and KeyExchangeAlgorithm `Enabled` values correctly use the `0xffffffff` bitmask rather than `1`; Protocol node `Enabled` and `DisabledByDefault` values correctly use `1` and `0` as boolean flags. FIPS, PKCS key exchange, and the SHA256 SCHANNEL hash registry key are intentionally omitted from all apply scripts due to confirmed software incompatibility.

---

## Reference Guides (HTML)

---

### `GPO_Workstation_FIPS_Guide.html`

**Purpose**
A dual-tab reference guide covering the full procedure for creating a workstation OU, copying and linking a domain GPO, disabling the FIPS flag at the OU level, and applying TLS and cipher compensating controls — with both a GUI walkthrough and a PowerShell/CLI equivalent for every step. Also includes a gap analysis table identifying everything missing from the original baseline script, the correct registry values for each setting, and the reasoning behind each addition. Open in any browser; no server required.

**User Guide**
1. Copy `GPO_Workstation_FIPS_Guide.html` to any accessible location on the Domain Controller or admin workstation.
2. Double-click the file to open it in a browser, or right-click and choose **Open with** to select a specific browser.
3. Use the **GUI** and **PowerShell** tab buttons at the top of each phase section to switch between the two instruction sets.
4. Work through each phase in order: create the OU, copy and link the GPO, disable FIPS, apply compensating controls.
5. Refer to the gap analysis table at the top to understand which settings are covered, which were missing from the original script, and which are intentionally omitted.

---

### `Domain_Join_GPO_Hardening_Guide.html`

**Purpose**
A step-by-step guide covering the complete end-to-end procedure from joining a standalone workstation to the domain through to incremental cryptography policy rollout. Covers domain join with upfront DNS verification (GUI and PowerShell), OU creation and GPO linking, FIPS disablement at the OU level with a mandatory software checkpoint before proceeding, and the same ten incremental policy groups with risk ratings and a software testing checkpoint after each phase. Open in any browser; no server required.

**User Guide**
1. Copy `Domain_Join_GPO_Hardening_Guide.html` to any accessible location.
2. Open it in a browser.
3. Follow **Phase 1** to join the workstation to the domain. Use the GUI tab if working interactively on the workstation, or the PowerShell tab if working remotely. Confirm DNS resolves the domain before attempting the join.
4. After the workstation reboots and joins the domain, move to **Phase 2** on the Domain Controller to create the SOUR OU, move the computer object into it, copy the domain GPO, and link it.
5. Follow **Phase 3** to disable FIPS in the OU GPO. Run `gpupdate /force` on the workstation and reboot.
6. Stop at the checkpoint after Phase 3 and confirm the problem software works before continuing.
7. Follow **Phase 4** one group at a time. After each group, run `gpupdate /force` on the workstation, reboot, and test the software before applying the next group.

---

## Standalone Workstation Scripts

> All scripts in this section are run directly on the workstation in an elevated PowerShell session unless stated otherwise.

---

### `Script1_Baseline_FIPS_Disabled.ps1`

**Purpose**
The starting point for local standalone testing. Disables the FIPS algorithm policy via both direct registry write and `secedit` so the change persists through policy refreshes and is reflected correctly in `secpol.msc`, then applies the original baseline set of TLS and cipher registry settings exactly as originally provided with no additions or modifications. Run this first, reboot, and verify the problem software works with FIPS disabled before applying anything from Script 2. Requires an elevated PowerShell session on the workstation.

**User Guide**
1. Copy `Script1_Baseline_FIPS_Disabled.ps1` to the workstation.
2. Right-click the PowerShell icon and select **Run as Administrator**, or open an existing elevated session.
3. Navigate to the folder containing the script: `cd C:\Path\To\Scripts`
4. If the execution policy blocks the script, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
5. Run the script: `.\Script1_Baseline_FIPS_Disabled.ps1`
6. Watch the console output. Each of the seven steps prints confirmation as it completes.
7. When prompted to restart, enter `Y` and allow the reboot.
8. After the workstation restarts, test the problem software before proceeding to Script 2.
9. Verify FIPS is disabled by running: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" /v Enabled` — the value should be `0x0`.

---

### `Script1_ROLLBACK.ps1`

**Purpose**
Reverses everything `Script1_Baseline_FIPS_Disabled.ps1` applied. Re-enables FIPS via both registry and `secedit`, and removes all SCHANNEL protocol, cipher, hash, and key exchange registry keys by deleting them entirely rather than setting them to specific values — deletion returns Windows to its built-in defaults, which is the correct original state since those keys did not exist before Script 1 created them. Also removes the .NET `SchUseStrongCrypto` values added by Script 1. Prompts for an immediate reboot on completion.

**User Guide**
1. Open an elevated PowerShell session on the workstation.
2. Navigate to the folder containing the script: `cd C:\Path\To\Scripts`
3. If required, bypass execution policy: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
4. Run the script: `.\Script1_ROLLBACK.ps1`
5. The script will work through seven rollback steps and print what it removes or skips for each entry.
6. When prompted to restart, enter `Y`.
7. After the reboot, verify FIPS is re-enabled: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" /v Enabled` — the value should be `0x1`.
8. Confirm the workstation is back to its pre-test state before beginning any further testing.

---

### `Script2_Additional_Policies_OneLiners.ps1`

**Purpose**
Twenty self-contained one-liner commands covering every recommended cryptography setting not included in the original baseline script, ordered from lowest to highest compatibility risk. Each line includes an inline comment explaining what it sets, why it matters, and what to watch for during testing. Intended to be pasted into an elevated PowerShell session one line at a time with a reboot and software test between each. Any line that breaks the software can be skipped independently without affecting the others. Covers `DisabledByDefault` keys for all disabled protocols, TLS 1.3 enablement, the RC2 cipher family, explicit AES enablement, minimum DH key size enforcement, and cipher suite order policy.

**User Guide**
1. Ensure `Script1_Baseline_FIPS_Disabled.ps1` has been run successfully and the software is confirmed working before starting this script.
2. Open the file in a text editor (Notepad, VS Code, or PowerShell ISE) so you can read the comment above each line before running it.
3. Open a separate elevated PowerShell session on the workstation.
4. Read the comment for Line 1 to understand what it does and what to test afterward.
5. Copy Line 1 only and paste it into the elevated PowerShell session. Press Enter to run it.
6. Reboot the workstation: `Restart-Computer -Force`
7. After the reboot, test the problem software thoroughly.
8. If the software still works, return to the file and repeat steps 4–7 for the next line.
9. If the software breaks after a specific line, note that line number as a confirmed incompatible setting and skip it. The remaining lines can still be applied independently.
10. Lines 1–3 (AES and SHA384) are very low risk. Lines 18–20 (DH key size and cipher suite order) carry the highest compatibility risk and should be tested most carefully.

---

### `FIPS_Compensating_Controls_Supplement.ps1`

**Purpose**
A targeted supplemental script that adds only the registry entries identified as missing from the original baseline script through gap analysis. Intended to be run alongside `Script1_Baseline_FIPS_Disabled.ps1` rather than as a replacement for it. Covers six areas in numbered stages with console progress output: `DisabledByDefault` keys for all disabled protocols, TLS 1.3 enablement for Server and Client roles, the RC2 cipher family (128, 56, and 40-bit variants), explicit AES 128 and AES 256 enablement, SHA384 hash and minimum DH key size set to 2048-bit, and cipher suite order policy set to nine strong AES-GCM suites. Each stage prints what it sets so progress is visible. Requires an elevated PowerShell session and a reboot to take effect.

**User Guide**
1. Run `Script1_Baseline_FIPS_Disabled.ps1` first and confirm the software is working after its reboot.
2. Copy `FIPS_Compensating_Controls_Supplement.ps1` to the workstation.
3. Open an elevated PowerShell session and navigate to the script folder.
4. If required: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
5. Run the script: `.\FIPS_Compensating_Controls_Supplement.ps1`
6. Review the console output. Each of the six stages prints every value it sets.
7. When prompted to restart, enter `Y`.
8. After the reboot, test the problem software. If it fails, use `Script1_ROLLBACK.ps1` to clear everything and use `Script2_Additional_Policies_OneLiners.ps1` to identify the specific incompatible setting.

---

### `Apply_Local_TLS_Security_Policy.ps1`

**Purpose**
A complete single-run script for non-domain-joined workstations that applies all strong-cryptography settings in one unattended pass: FIPS disablement, protocol configuration, cipher hardening, hash configuration, key exchange settings, .NET strong crypto for all framework versions and bitness paths, and cipher suite order. Uses `secedit` in addition to direct registry writes so all changes are reflected correctly in `secpol.msc` and survive subsequent policy refreshes. Prints a numbered progress section for each of the nine setting areas as it runs. Prompts for a reboot at the end with a 10-second countdown. Requires an elevated PowerShell session on the workstation.

**User Guide**
1. Confirm the workstation is standalone (not domain-joined). For domain-joined workstations use the DC scripts instead.
2. Copy `Apply_Local_TLS_Security_Policy.ps1` to the workstation.
3. Open an elevated PowerShell session and navigate to the script folder.
4. If required: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
5. Run the script: `.\Apply_Local_TLS_Security_Policy.ps1`
6. The script runs through nine numbered sections. Each section prints what it is setting.
7. At the end, a reboot prompt appears with a 10-second countdown. Enter `N` to cancel if you need to review the output first, or allow the countdown to complete.
8. After the reboot, open `secpol.msc` and navigate to **Security Settings > Local Policies > Security Options** to confirm FIPS shows as Disabled.
9. Test all software and network connectivity after rebooting as this script applies all settings at once with no incremental option.

---

### `SOUR_Crypto_Local_Incremental.ps1` — *v2.0.0*

**Purpose**
An interactive menu-driven script that applies strong-cryptography registry settings directly to the local machine in ten incremental groups without any GPO or LGPO involvement. Run this on the workstation itself in an elevated PowerShell session with no parameters required. The recommended workflow is to take a snapshot with `[S]` before applying any changes, then apply groups one at a time using options `[1]` through `[10]`, rebooting and testing the software between each.

The `[S]` Take Snapshot option records the complete pre-test state of all 47 registry key and value pairs this script can modify, saving the result to `crypto_snapshot.json` in the script directory. The snapshot persists across reboots so it remains available throughout multi-session testing. For each tracked entry it records whether the registry key existed, whether the specific named value existed within it, and if so the original value data and registry type. If a snapshot already exists, the script warns and prompts for confirmation before overwriting it.

The `[RA]` Revert All option reads the snapshot and restores every tracked entry to exactly its pre-test state using three distinct cases: if a key did not exist before testing it is deleted entirely; if a key existed but a value was absent the value is removed; if both the key and value existed the original value and registry type are restored precisely. A per-entry summary is printed during the revert, and a final count of restored, removed, deleted, and skipped entries is shown on completion, followed by an optional reboot prompt.

Per-group rollbacks `[R1]` through `[R10]` remain available for finer-grained control of individual groups without affecting others. A `[V]` verify option displays the current live state of all relevant registry keys and the active OS cipher suite list. The snapshot status — including the timestamp if taken — is shown in the menu header on every screen so it is always clear whether a baseline has been recorded before proceeding.

**User Guide**

*First session — before any changes:*
1. Copy `SOUR_Crypto_Local_Incremental.ps1` to the workstation. Keep it in a stable folder it will not be moved from — `crypto_snapshot.json` is saved alongside it.
2. Open an elevated PowerShell session and navigate to the script folder.
3. If required: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
4. Run the script: `.\SOUR_Crypto_Local_Incremental.ps1`
5. The menu appears. The snapshot status line will show **NOT TAKEN** in yellow.
6. Enter `S` and press Enter to take a snapshot of the current registry state. The script records all 47 tracked entries and saves `crypto_snapshot.json` to the script folder.
7. Confirm the snapshot completes and the status line now shows **TAKEN** with a timestamp.

*Incremental testing:*

8. Enter `1` to apply Group 1 (AES 128/256 — very low risk).
9. When prompted to reboot, enter `Y`.
10. After the workstation restarts, run the script again, enter `V` to verify the group was applied, then test the problem software.
11. If the software works, run the script again and enter `2` to apply the next group.
12. Repeat steps 9–11 for each group in order (1 through 10), rebooting and testing between each.
13. If a group breaks the software, enter `R` followed by the group number (e.g. `R6`) to roll back only that group, reboot, confirm the software works again, and note that group as a known incompatibility to skip.

*Full revert if needed:*

14. If you need to return the workstation to exactly its pre-test state at any point, run the script and enter `RA`.
15. Review the per-entry output to confirm each setting is being handled correctly (restored, removed, deleted, or skipped).
16. When prompted to reboot, enter `Y`.
17. After the reboot, enter `V` in the menu to confirm the registry matches the original snapshot.

---

## DISA STIG Management Scripts

> All scripts in this section are run locally on the workstation in an elevated PowerShell session. LGPO.exe must be present in the same folder as the script for full functionality.

---

### `STIG_Revert_All.ps1`

**Purpose**
Clears all DISA STIG hardening from a standalone workstation in seven steps: clears the Local Group Policy `Registry.pol` files using LGPO.exe if available or direct file deletion as a fallback; resets security policy to Windows defaults via `secedit` and `defltbase.inf` followed by a custom INF that explicitly zeros out key STIG values for password policy, lockout, audit, user rights, UAC, LSA options, and Netlogon; clears all advanced audit policy via `auditpol /clear` and restores the small set of Windows built-in defaults; removes all SCHANNEL and TLS registry keys by deletion; removes .NET `SchUseStrongCrypto` flags; removes approximately twenty-five administrative template registry keys covering AutoPlay, RDP, WDigest, LSASS PPL protection, screen saver lock, Remote Assistance, PowerShell script block logging, SmartScreen, and telemetry; and leaves FIPS disabled rather than re-enabling it. LGPO.exe from Microsoft's Security Compliance Toolkit must be placed in the same folder as the script before running. Requires an elevated PowerShell session and a reboot to take effect.

**User Guide**
1. Download LGPO.exe from the Microsoft Security Compliance Toolkit: `https://www.microsoft.com/en-us/download/details.aspx?id=55319`
2. Place `LGPO.exe` in the same folder as `STIG_Revert_All.ps1`.
3. Open an elevated PowerShell session on the workstation and navigate to the script folder.
4. If required: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
5. Run the script: `.\STIG_Revert_All.ps1`
6. The script works through seven numbered steps. Each step prints what it is removing, clearing, or resetting.
7. If LGPO.exe is found, Step 1 uses it to clear `Registry.pol`. If not found, a warning is printed and direct file deletion is used as a fallback — both achieve the same result.
8. When prompted to restart, enter `Y`.
9. After the reboot, open `secpol.msc` to confirm password policy, lockout, audit, and security options have been reset to Windows defaults.
10. Run `gpresult /r` to confirm no local Group Policy settings are in effect.

---

### `STIG_Incremental_Apply.ps1`

**Purpose**
An interactive menu-driven script that re-applies DISA STIG settings for Windows 10 and 11 in eight logical groups ordered by compatibility risk, enabling software testing between each group to isolate which specific setting causes a failure. Group A covers twenty-five advanced audit policy subcategories via `auditpol` and carries very low risk as it only affects logging. Group B applies account, password, and lockout policy via `secedit` INF. Group C applies LSA and network authentication settings including NTLMv2-only enforcement at level 5, SMB signing, LDAP signing, and NTLM minimum session security. Group D applies UAC consent prompt and elevation settings. Group E covers TLS and SCHANNEL hardening and is split into five sub-groups E1 through E5 for maximum granularity — each sub-group can be applied and tested independently. Group F applies user rights assignments restricting all logon types for anonymous and guest accounts. Group G applies security options including WDigest disablement, LSASS PPL protection, screen lock timeout, and Remote Assistance disablement. Group H covers Administrative Templates and is split into two sub-groups: H1 for AutoPlay, error reporting, and attachment handling; H2 for RDP security layer, PowerShell logging, SmartScreen, CredSSP, and telemetry level. Every group has a built-in rollback option accessible directly from the main menu. Uses `auditpol`, `secedit` INF files, LGPO.exe text format, and direct registry writes depending on the setting type. Requires an elevated PowerShell session and LGPO.exe in the same directory.

**User Guide**
1. Place `LGPO.exe` in the same folder as `STIG_Incremental_Apply.ps1`. Download from: `https://www.microsoft.com/en-us/download/details.aspx?id=55319`
2. Ensure `STIG_Revert_All.ps1` has been run first and the workstation is at a clean baseline.
3. Confirm the problem software works at the clean baseline before starting.
4. Open an elevated PowerShell session and navigate to the script folder.
5. If required: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
6. Run the script: `.\STIG_Incremental_Apply.ps1`
7. The interactive menu appears showing all eight groups with their risk levels.
8. Enter `A` to apply Group A (audit policies — very low risk). No reboot is required for audit policy changes; test the software immediately.
9. For all subsequent groups (B through H), apply the group, reboot the workstation, then test the software.
10. If a group breaks the software, enter the corresponding rollback from the menu (e.g. enter `R` then the group letter when prompted). After rollback, reboot and confirm the software recovers.
11. Group E (TLS/SCHANNEL) should be applied one sub-group at a time. When you select `E` from the menu, a sub-menu appears for E1 through E5. Apply E1, reboot, test, then return and apply E2, and so on.
12. Group H (Admin Templates) similarly presents a sub-menu for H1 and H2.
13. After all groups that pass testing have been applied, run `gpresult /h C:\GPOReport.html` and open the report to confirm all STIG settings are active.

---

## Domain Controller Scripts

> All scripts in this section are run on the Domain Controller in an elevated PowerShell session. The GroupPolicy RSAT module must be installed.

---

### `SOUR_Crypto_Incremental_Push.ps1` — *v1.2.0*

**Purpose**
An interactive menu-driven script that pushes strong-cryptography GPO registry settings to the SOUR workstation OU GPO one group at a time from the Domain Controller. Accepts `-GPOName` and `-SOURHost` as mandatory parameters at invocation; PowerShell will prompt interactively for either if omitted. Uses `Set-GPRegistryValue` to write each setting directly into the GPO's `registry.pol` without requiring GPME or the Group Policy Management Editor to be open, then calls `Invoke-GPUpdate` to force the workstation to pull the change immediately without waiting for the standard 90-minute refresh interval. The ten groups are identical in content to those in the local incremental script. Each group has a corresponding rollback using `Remove-GPRegistryValue`. A `[V]` verify option runs `Invoke-Command` against the workstation to display the live registry state after a reboot, confirming the GPO was applied before testing begins. Correctly uses `0xffffffff` for all Cipher, Hash, and KeyExchangeAlgorithm Enabled values. Intentionally omits FIPS, PKCS, and the SHA256 SCHANNEL hash registry key.

**User Guide**
1. Log on to the Domain Controller with a Domain Admin account or an account with delegated GPO editing rights.
2. Open an elevated PowerShell session.
3. Confirm the GroupPolicy module is available: `Get-Module -ListAvailable GroupPolicy`
4. Confirm the SOUR OU GPO exists and its exact display name: `Get-GPO -All | Where-Object DisplayName -like "*SOUR*"`
5. Confirm the workstation is reachable: `Test-Connection -ComputerName SOUR-WORKSTATION -Count 1`
6. Navigate to the folder containing the script: `cd C:\Path\To\Scripts`
7. Run the script with parameters:
   `.\SOUR_Crypto_Incremental_Push.ps1 -GPOName "SOUR-Workstation-Policy" -SOURHost "SOUR-WORKSTATION"`
8. The menu appears showing all ten groups with apply and rollback options, plus the `[V]` verify option.
9. Enter `1` to apply Group 1. The script writes to the GPO and immediately calls `Invoke-GPUpdate` to push to the workstation.
10. Reboot the workstation: from the DC run `Restart-Computer -ComputerName SOUR-WORKSTATION -Force`
11. After the workstation restarts, return to the script and enter `V` to confirm the live registry on the workstation reflects the change.
12. Test the problem software on the workstation.
13. If the software works, return to the script and enter `2` to apply the next group.
14. If a group breaks the software, enter `R` followed by the group number (e.g. `R6`) to remove those settings from the GPO, push the removal with `Invoke-GPUpdate`, reboot the workstation, and confirm recovery.
15. Continue through all ten groups. Document any skipped groups as known incompatibilities.

---

### `SOUR_Crypto_Apply_All.ps1` — *v1.0.0*

**Purpose**
Applies all ten strong-cryptography GPO settings to the SOUR OU GPO in a single unattended run, then force-pushes to the workstation and displays a full live verification report. Intended for use once incremental testing is complete and all compatible groups have been confirmed. Accepts `-GPOName` and `-SOURHost` as mandatory parameters. Prints a numbered section header and per-value confirmation line for each of the ten groups as it executes so progress is visible. After the push, runs a full `Invoke-Command` verification against the workstation displaying AES cipher state, weak cipher state, protocol configuration, hash configuration, key exchange settings with DH minimum key size, .NET `SchUseStrongCrypto` values across all framework versions and bitness paths, configured cipher suite order, and the live active OS cipher suite list from `Get-TlsCipherSuite`. A reboot on the workstation is required before SCHANNEL settings become active. Intentionally omits FIPS, PKCS, and the SHA256 SCHANNEL hash registry key, with these omissions documented in both the script header and inline comments.

**User Guide**
1. Complete incremental testing with `SOUR_Crypto_Incremental_Push.ps1` first to confirm which groups are compatible with the problem software. Do not run this script before that testing is complete.
2. Log on to the Domain Controller with a Domain Admin account or delegated GPO rights.
3. Open an elevated PowerShell session.
4. Confirm the GroupPolicy module is available: `Get-Module -ListAvailable GroupPolicy`
5. Confirm the workstation is reachable: `Test-Connection -ComputerName SOUR-WORKSTATION -Count 1`
6. Navigate to the script folder: `cd C:\Path\To\Scripts`
7. Run the script with parameters:
   `.\SOUR_Crypto_Apply_All.ps1 -GPOName "SOUR-Workstation-Policy" -SOURHost "SOUR-WORKSTATION"`
8. The script validates the GPO exists before doing any work. If the GPO name is incorrect it exits immediately with an error.
9. Watch the console output as all ten groups are applied in sequence. Each group prints a section header and a confirmation line per value written.
10. After all settings are written, the script calls `Invoke-GPUpdate` to push to the workstation automatically.
11. Reboot the workstation: `Restart-Computer -ComputerName SOUR-WORKSTATION -Force`
12. The live verification report runs automatically after the push — review it to confirm all values are present in the GPO. Note that SCHANNEL values will not appear in the live workstation registry until after the reboot.
13. After the workstation restarts, run the script again and it will display the verification report showing live values from the workstation registry. Alternatively, on the workstation run `Get-TlsCipherSuite | Select-Object Name` to confirm the active cipher suite list.
14. Run the problem software and perform a full functional test to confirm everything is working with the complete set of compatible cryptography settings applied.
