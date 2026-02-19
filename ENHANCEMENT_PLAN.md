# Windows Attack Surface Analyzer - Enhancement Plan

## Overview

This plan tracks enhancements to make the Windows Attack Surface Analyzer more comprehensive for Windows 10 and 11 users.

**Started at:** 0.1.0
**Current:** 0.2.0
**Target:** 1.0.0
**Goal:** Maximum benefit for Windows 10/11 home users, professionals, and enterprises

---

## v0.2.0 — COMPLETED

### Phase 1: Windows 11 Security Features Detection

#### 1.1 Virtualization-Based Security (VBS) - DONE
- [x] VBS enabled/disabled status
- [x] Hypervisor-enforced Code Integrity (HVCI / Memory Integrity)
- [x] Credential Guard status
- [x] Kernel DMA Protection

#### 1.2 TPM and Secure Boot Status - DONE
- [x] TPM version (1.2 vs 2.0)
- [x] TPM enabled and active status
- [x] Secure Boot enabled / UEFI vs Legacy BIOS detection

#### 1.3 BitLocker Encryption Status - DONE
- [x] BitLocker enabled per drive
- [x] Encryption percentage
- [x] Protection type (TPM, PIN, USB key)

#### 1.4 Windows Hello - DONE
- [x] Windows Hello availability / configuration detected

#### 1.5 Smart App Control (Windows 11 22H2+) - DONE
- [x] Smart App Control status: On / Evaluation / Off

### Phase 2: Microsoft Defender Enhancements

#### 2.1 Extended Defender Analysis - DONE
- [x] Tamper Protection status
- [x] Cloud-delivered protection status
- [x] Potentially Unwanted Application (PUA) protection
- [x] Signature / definition age (warns if >3 days old, critical if >7 days)
- [ ] Automatic sample submission setting (deferred to v0.3.0)
- [ ] Last quick/full scan time (deferred to v0.3.0)

#### 2.2 Attack Surface Reduction (ASR) Rules - DONE (partial)
- [x] Active ASR rule count reported (enabled vs total configured)
- [ ] Per-rule breakdown with names (deferred to v0.3.0)

#### 2.3 Exploit Protection - DEP - DONE
- [x] DEP (Data Execution Prevention) AlwaysOn check via bcdedit
- [ ] ASLR, SEHOP, CFG, Heap checks (deferred to v0.3.0)

#### 2.4 Controlled Folder Access (Ransomware Protection) - DONE
- [x] Controlled Folder Access enabled/disabled

#### 2.5 Microsoft Defender Application Guard
- [ ] Deferred to v0.3.0

### Phase 5 (partial): PowerShell Security - DONE
- [x] Execution policy (machine scope)
- [x] Script Block Logging
- [x] Module Logging
- [x] Language Mode (Constrained vs Full)
- [x] PowerShell version reported

### Windows 11 24H2 Features - DONE
- [x] Windows Recall status (24H2+)

### Usability / UX - DONE
- [x] Run-Analysis.bat launcher -- double-click, auto-elevates, auto-picks PS7/PS5.1, opens HTML report
- [x] Live progress bar (Write-Progress) showing current step and percentage
- [x] OS version + build + architecture + PowerShell version shown in banner
- [x] Risk score (0-100) displayed in summary
- [x] HTML report auto-opens in browser after export
- [x] Clear "What to do next" section in summary
- [x] Windows 10 fully preserved -- all original 8 checks unchanged
- [x] All new checks degrade gracefully (try/catch) on older Windows or missing modules

---

## v0.3.0 — NEXT

### Phase 2 (remaining Defender)
- [ ] Per-rule ASR breakdown with friendly names
- [ ] Last scan time (quick/full)
- [ ] Automatic sample submission setting
- [ ] ASLR, SEHOP, CFG via `Get-ProcessMitigation`
- [ ] Microsoft Defender Application Guard status

### Phase 3: Privacy & Data Protection
- [ ] Diagnostic data level (Full / Required / Optional)
- [ ] Advertising ID status
- [ ] Activity history settings
- [ ] Location, camera, microphone access permissions
- [ ] App background permissions

### Phase 4: Network Security Enhancements
- [ ] IPv6 status and implications
- [ ] DNS over HTTPS (DoH) configuration
- [ ] Wi-Fi security profile (WPA3 vs WPA2)
- [ ] Bluetooth enabled / discoverable / paired devices
- [ ] VPN connection status

### Phase 4.4: Remote Access Security
- [ ] RDP Network Level Authentication (NLA)
- [ ] RDP port (default 3389 vs changed)
- [ ] RDP session timeout
- [ ] Remote Assistance status
- [ ] PowerShell Remoting (WinRM) status

### Phase 4.3: WSL Security
- [ ] WSL version (1 vs 2)
- [ ] Installed distributions
- [ ] Network mode (NAT vs mirrored)

### Phase 5 (remaining): Application Security
- [ ] Outdated browser / Adobe / Java detection
- [ ] Applications from unknown publishers
- [ ] Microsoft Edge SmartScreen status
- [ ] Edge Enhanced Security Mode

### Phase 6: Account & Authentication
- [ ] Account lockout threshold/duration
- [ ] Password complexity requirements
- [ ] Password history enforcement
- [ ] Autologon configuration check
- [ ] Cached domain credentials count

---

## v0.4.0

### Phase 7: System Hardening
- [ ] Unsigned driver detection
- [ ] Hosts file modification check
- [ ] Non-Microsoft scheduled tasks (potential persistence)
- [ ] Scheduled tasks running as SYSTEM

### Phase 8: Reporting
- [ ] JSON export format (for SIEM / automation)
- [ ] CSV export format
- [ ] Scan comparison / diff mode (run vs previous baseline)

---

## v1.0.0

### Phase 9: Performance
- [ ] Parallel execution for independent checks
- [ ] Quick scan vs Full scan mode (`-Quick` flag)

### Phase 10: Documentation & Community
- [ ] Windows 11 hardening guide update
- [ ] Remediation scripts library
- [ ] CIS / Microsoft Security Baseline preset comparison
- [ ] Multi-language support structure

---

## Version Roadmap Summary

| Version | Focus | Status |
|---------|-------|--------|
| 0.1.0 | Initial release — 8 core checks | Released |
| **0.2.0** | **Hardware security, Defender deep-dive, Win11 features, UX launcher** | **Released** |
| 0.3.0 | Privacy, Network, Remote access, WSL, Auth | Planned |
| 0.4.0 | System hardening, JSON/CSV export | Planned |
| 1.0.0 | Performance, docs, CIS baselines, full test suite | Planned |
