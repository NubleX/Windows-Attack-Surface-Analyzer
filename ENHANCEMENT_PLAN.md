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

## v0.3.0 — COMPLETED

### Phase 2 (remaining Defender) - DONE
- [x] Per-rule ASR breakdown with friendly names (all 15 known rule GUIDs mapped)
- [x] Last quick scan and full scan age in days
- [x] Automatic sample submission setting
- [x] ASLR, SEHOP, CFG, Bottom-Up ASLR, Heap Terminate via Get-ProcessMitigation
- [x] Microsoft Defender Application Guard status

### Phase 3: Privacy & Data Protection - DONE
- [x] Diagnostic data level (Security/Off, Required, Enhanced, Optional/Full)
- [x] Advertising ID status
- [x] Activity history settings
- [x] Location, camera, microphone access permissions

### Phase 4: Network Security Enhancements - DONE
- [x] IPv6 adapter binding status
- [x] DNS over HTTPS (DoH) configuration
- [x] Wi-Fi authentication type (WPA3 / WPA2 / WEP / Open)
- [x] Bluetooth service status
- [x] VPN connection status and profile count

### Phase 4.4: Remote Access Security - DONE
- [x] RDP Network Level Authentication (NLA)
- [x] RDP port (default 3389 vs custom)
- [x] Remote Assistance status
- [x] PowerShell Remoting (WinRM) service and listener count
- [ ] RDP session timeout (deferred to v0.4.0)

### Phase 4.3: WSL Security - DONE
- [x] WSL version (1 vs 2)
- [x] Installed distributions
- [x] Network mode (NAT vs mirrored via .wslconfig)

### Phase 5 (remaining): Application Security - DONE
- [x] Microsoft Edge SmartScreen policy status
- [x] Edge Enhanced Security Mode policy status
- [x] Adobe Acrobat Reader version detection
- [x] Java Runtime Environment version detection
- [x] Google Chrome version detection
- [x] Mozilla Firefox version detection
- [ ] Application publisher verification (deferred to v0.4.0)

### Phase 6: Account & Authentication - DONE
- [x] Autologon configuration (Critical finding if enabled)
- [x] Cached domain credential count
- [x] Account lockout threshold
- [x] Minimum password length
- [x] Password maximum age / expiry
- [ ] Password history enforcement (deferred to v0.4.0 -- requires secedit)

### CI / Testing - DONE
- [x] GitHub Actions workflow (.github/workflows/test.yml)
  - PSScriptAnalyzer lint (errors fail build, warnings informational)
  - Full analyzer run with HTML report export
  - Report uploaded as build artifact (30 day retention)

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
| 0.1.0 | Initial release -- 8 core checks | Released |
| 0.2.0 | Hardware security, Defender deep-dive, Win11 features, UX launcher | Released |
| 0.3.0 | ASR details, exploit protection, privacy, network, remote access, WSL, apps, auth, CI | Released |
| 0.4.0 | System hardening (drivers, hosts, scheduled tasks), JSON/CSV export | Planned |
| 1.0.0 | Performance (parallel scans, quick mode), CIS baseline comparison, full test suite | Planned |
