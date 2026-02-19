# Windows Attack Surface Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://www.microsoft.com/windows)
[![Version](https://img.shields.io/badge/Version-0.4.0-brightgreen.svg)](https://github.com/NubleX/Windows-Attack-Surface-Analyzer)
[![CI](https://github.com/NubleX/Windows-Attack-Surface-Analyzer/actions/workflows/test.yml/badge.svg)](https://github.com/NubleX/Windows-Attack-Surface-Analyzer/actions/workflows/test.yml)

A comprehensive, open-source PowerShell tool for analyzing Windows security posture and identifying potential attack vectors. Works on Windows 10 and all versions of Windows 11. No installation required.

## What it Does

The Windows Attack Surface Analyzer performs a thorough security assessment of your Windows system across 23 categories:

- **Network Attack Surface** - Open ports, listening services, and network exposure
- **Service Security** - Risky or unnecessary Windows services
- **Firewall Configuration** - Windows Firewall status and rule analysis
- **Network Shares** - SMB shares and file system exposure
- **Windows Features** - Potentially dangerous optional features
- **Startup Security** - Programs with system startup access
- **User Account Security** - Account policies and configurations
- **System Hardening** - Windows Defender, UAC, and update status
- **Hardware Security** - TPM, Secure Boot, VBS, Memory Integrity, Credential Guard, Kernel DMA Protection
- **Disk Encryption** - BitLocker status per drive with protector type
- **Advanced Defender** - Tamper Protection, Cloud Protection, ASR rules, Controlled Folder Access, definition age, DEP
- **Windows 11 Features** - Smart App Control, Windows Hello, Windows Recall (version-gated, skips on Win10)
- **PowerShell Security** - Execution policy, Script Block Logging, Module Logging, Language Mode
- **Defender ASR Rules** - Per-rule breakdown with friendly names, scan age, sample submission, Application Guard
- **Exploit Protection** - ASLR, SEHOP, CFG, Heap Terminate on Corruption via Get-ProcessMitigation
- **Privacy Settings** - Diagnostic data level, Advertising ID, Activity History, camera/mic/location permissions
- **Network Security** - IPv6, DNS over HTTPS (DoH), Wi-Fi authentication (WPA3/WPA2/WEP), Bluetooth, VPN
- **Remote Access Security** - RDP NLA, RDP port, Remote Assistance, WinRM listener status
- **WSL Security** - WSL version, installed distributions, network mode (NAT vs mirrored)
- **Application Security** - Edge SmartScreen/Enhanced Security, Adobe, Java, Chrome, Firefox version reporting
- **Authentication Policy** - Autologon, cached credentials, account lockout threshold, password length and expiry
- **System Hardening** - Driver signature enforcement, known vulnerable drivers, hosts file tampering, password history
- **Scheduled Tasks** - Non-Microsoft tasks, tasks running as SYSTEM/elevated, executables in suspicious paths

## Quick Start

### Option 1: Double-Click (Recommended for most users)

1. Download both files to the same folder:
   - `WindowsAttackSurfaceAnalyzer.ps1`
   - `Run-Analysis.bat`

2. Double-click `Run-Analysis.bat`

That is all. The launcher handles administrator elevation automatically, selects the best available PowerShell version (7 preferred, 5.1 fallback), runs the full scan, and opens the HTML report in your browser when done.

### Option 2: PowerShell Command Line

```powershell
# Basic scan (console output only)
.\WindowsAttackSurfaceAnalyzer.ps1

# Full scan with HTML report
.\WindowsAttackSurfaceAnalyzer.ps1 -Export

# Verbose output with HTML report at custom path
.\WindowsAttackSurfaceAnalyzer.ps1 -Detailed -Export -OutputPath "C:\Reports\security.html"
```

### Prerequisites

- Windows 10 or Windows 11 (all versions)
- PowerShell 5.1 or PowerShell 7+ (auto-detected by the launcher)
- Administrator privileges recommended for complete analysis

## Sample Output

```
================================================
       Windows Attack Surface Analyzer
       Comprehensive Security Assessment Tool

  Author : NubleX / Igor Dunaev
  Version: 0.3.0
  System : Windows 11 Pro (Build 22631, 64-bit)
  Engine : PowerShell 7.4.1 (Core edition)
================================================

  [OK] Running as Administrator - full scan enabled.

9. HARDWARE SECURITY (TPM / SECURE BOOT / VBS)
================================================
  [Good]   TPM - Enabled (v2.0)
  [Good]   Secure Boot - Enabled
  [Medium] Virtualization-Based Security (VBS) - Not Running
  [Medium] Memory Integrity (HVCI) - Disabled
  [Low]    Credential Guard - Not Running

10. DISK ENCRYPTION (BITLOCKER)
=================================
  [Good]   Drive C:\ - Encrypted (100%)
  [High]   Drive D:\ - Not Encrypted

11. ADVANCED DEFENDER ANALYSIS
================================
  [Good]   Tamper Protection - Enabled
  [Good]   Cloud Protection - Enabled
  [Good]   Virus Definitions - Current (0 days old)
  [High]   Controlled Folder Access - Disabled
  [Medium] ASR Rules - Not Configured

================================================
           SECURITY ANALYSIS SUMMARY
================================================
System: Windows 11 Pro (Build 22631)
Total Findings: 61

  Critical Issues : 0
  High Risk Issues: 5
  Medium Issues   : 14
  Low Issues      : 9
  Good Settings   : 33

  Security Score  : 67 / 100

WHAT TO DO NEXT:
  [!]  Fix HIGH risk issues today or tomorrow.
  [~]  Plan to address MEDIUM issues within 30 days.
  Run this scan monthly to stay on top of your security.

  Full report: .\SecurityReport.html
```

## Command Line Options

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-Detailed` | Show verbose descriptions for each finding | `.\script.ps1 -Detailed` |
| `-Export` | Generate HTML report (auto-opens in browser) | `.\script.ps1 -Export` |
| `-OutputPath` | Custom report save location | `.\script.ps1 -Export -OutputPath "C:\Reports\scan.html"` |
| `-ExportJson` | Generate JSON report (SIEM / automation) | `.\script.ps1 -ExportJson` |
| `-JsonPath` | Custom JSON save location | `.\script.ps1 -ExportJson -JsonPath "C:\Reports\scan.json"` |
| `-ExportCsv` | Generate CSV report (spreadsheet analysis) | `.\script.ps1 -ExportCsv` |
| `-CsvPath` | Custom CSV save location | `.\script.ps1 -ExportCsv -CsvPath "C:\Reports\scan.csv"` |

## Security Categories

### Network Attack Surface
- TCP listening ports with process identification
- Risk scoring by port number (Telnet, FTP, RDP, SMB etc.)
- Total port count assessment

### Service Security
- High-risk services: SSH, IIS, UPnP, Telnet, FTP, Remote Registry, RDP, SMB
- Startup type (automatic vs manual vs disabled)
- Total running service count

### Firewall Analysis
- Domain, Private, and Public profile status
- Default inbound/outbound action
- Inbound allow rule count

### Network Shares
- All SMB shares including administrative shares (C$, ADMIN$, IPC$)
- Share paths and descriptions

### Windows Optional Features
- SMB1 (critical ransomware risk)
- Telnet client/server, TFTP, IIS, WSL, Simple TCP/IP services

### Startup Programs
- HKLM and HKCU Run and RunOnce registry keys
- Total startup item count

### User Account Security
- Guest account status
- Password age (flags accounts older than 90 days)
- Administrator group member count
- Accounts with no password set

### System Hardening
- Windows Update recency
- Windows Defender real-time protection and service status
- UAC (User Account Control) status

### Hardware Security
- TPM version and enabled state
- Secure Boot (UEFI) vs Legacy BIOS
- Virtualization-Based Security (VBS) running state
- Memory Integrity / HVCI (Hypervisor-Protected Code Integrity)
- Credential Guard
- Kernel DMA Protection

### Disk Encryption
- BitLocker status and encryption percentage per drive
- Protector types in use (TPM, PIN, USB recovery key)

### Advanced Defender Analysis
- Tamper Protection (prevents attackers disabling Defender)
- Cloud-delivered protection
- Potentially Unwanted Application (PUA) blocking
- Virus definition age
- Controlled Folder Access (ransomware protection)
- Attack Surface Reduction (ASR) rule count
- DEP (Data Execution Prevention) mode

### Windows 11 Security Features
- Smart App Control status: On / Evaluation / Off (22H2 and later)
- Windows Hello passwordless sign-in configuration
- Windows Recall status (24H2 and later)
- All checks silently skip on Windows 10

### PowerShell Security
- Execution policy (machine scope)
- Script Block Logging
- Module Logging
- Constrained Language Mode

## Risk Assessment Framework

| Risk Level | Console Color | Criteria | Recommended Response |
|------------|---------------|----------|----------------------|
| Critical | Red | Immediate security threat | Fix right away |
| High | Magenta | Significant vulnerability | Fix within 24-48 hours |
| Medium | Yellow | Moderate security concern | Fix within 30 days |
| Low | Cyan | Minor security issue | Monitor and plan |
| Good | Green | Proper security configuration | Maintain |
| Info | White | Informational finding | No action needed |

## Use Cases

### For Home Users
- Double-click `Run-Analysis.bat` and review the HTML report
- Follow the "What to do next" guidance in the summary
- Run monthly to track improvements

### For Cybersecurity Professionals
- Initial reconnaissance and attack surface mapping
- Security audits and compliance posture assessment
- Incident response baseline establishment
- Client security assessments

### For System Administrators
- Identify misconfigurations and unnecessary services
- Generate documentation for compliance audits
- Monitor security impact of system changes
- Establish and maintain security baselines

## Automation

```powershell
# Scheduled weekly scan
$action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"C:\Scripts\Run-Analysis.bat`""
$trigger = New-ScheduledTaskTrigger -Weekly -At "02:00AM" -DaysOfWeek Sunday
Register-ScheduledTask -TaskName "Weekly Security Scan" -Action $action -Trigger $trigger -RunLevel Highest

# PowerShell remoting across multiple machines
$computers = "Server1", "Server2", "Workstation1"
Invoke-Command -ComputerName $computers -FilePath ".\WindowsAttackSurfaceAnalyzer.ps1" -ArgumentList "-Export"

# Centralized report storage
.\WindowsAttackSurfaceAnalyzer.ps1 -Export -OutputPath "\\FileServer\SecurityReports\$env:COMPUTERNAME-$(Get-Date -Format 'yyyy-MM-dd').html"
```

## Troubleshooting

**"Execution Policy" error when running the script directly:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Using `Run-Analysis.bat` avoids this entirely.

**Limited results (BitLocker, TPM, user accounts missing):**
Some checks require administrator privileges. Use `Run-Analysis.bat` which handles elevation automatically, or right-click PowerShell and choose "Run as administrator".

**Antivirus flags the script:**
Security scanning tools are sometimes flagged by antivirus heuristics. Add an exception for the script folder or download directly from the official GitHub repository.

## Contributing

Contributions from the security community are welcome.

### Ways to Contribute
- Add new security checks following the existing `Add-Finding` pattern
- Improve risk scoring logic
- Test on different Windows versions and hardware
- Report bugs via GitHub Issues
- Suggest features via GitHub Discussions

### Guidelines
- Follow existing PowerShell style conventions
- Wrap all new checks in try/catch with graceful degradation
- Include accurate risk levels and plain-English descriptions
- Update `ENHANCEMENT_PLAN.md` to reflect completed or planned work
- Test on both Windows 10 and Windows 11 where possible

## Legal and Ethical Use

- Only use on systems you own or have explicit written permission to assess
- Tool provided as-is for educational and legitimate security purposes
- Users are responsible for compliance with local laws and regulations
- Not intended for malicious or unauthorized use

### Responsible Disclosure
To report security vulnerabilities in this tool, email nublexer@hotmail.com rather than creating a public issue. Allow reasonable time for a fix before public disclosure.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Igor Dunaev / NubleX

## Acknowledgments

- Security Community - for continuous feedback and contributions
- Microsoft Security Team - for Windows security documentation
- PowerShell Community - for scripting best practices

## Project Statistics

![GitHub stars](https://img.shields.io/github/stars/NubleX/Windows-Attack-Surface-Analyzer)
![GitHub forks](https://img.shields.io/github/forks/NubleX/Windows-Attack-Surface-Analyzer)
![GitHub issues](https://img.shields.io/github/issues/NubleX/Windows-Attack-Surface-Analyzer)
![GitHub pull requests](https://img.shields.io/github/issues-pr/NubleX/Windows-Attack-Surface-Analyzer)

---

Stay Secure, Stay Vigilant.

Visit https://www.idarti.com
