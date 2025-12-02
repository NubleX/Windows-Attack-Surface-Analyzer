# Windows Attack Surface Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue.svg)](https://www.microsoft.com/windows)

A comprehensive, open-source PowerShell tool for analyzing Windows security posture and identifying potential attack vectors. Perfect for cybersecurity professionals, system administrators, and security-conscious users.

## What it Does

The Windows Attack Surface Analyzer performs a thorough security assessment of your Windows system, identifying:

- **Network Attack Vectors** - Open ports, listening services, and network exposure
- **Service Security** - Risky or unnecessary Windows services
- **Firewall Configuration** - Windows Firewall status and rule analysis
- **Network Shares** - SMB shares and file system exposure
- **Windows Features** - Potentially dangerous optional features
- **Startup Security** - Programs with system startup access
- **User Account Security** - Account policies and configurations
- **System Hardening** - Windows Defender, UAC, and update status

## Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges (recommended for complete analysis)

### Basic Usage

1. **Download the script:**
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/NubleX/Windows-Attack-Surface-Analyzer/main/WindowsAttackSurfaceAnalyzer.ps1" -OutFile "WindowsAttackSurfaceAnalyzer.ps1"
   ```

2. **Run the analysis:**
   ```powershell
   # Basic scan
   .\WindowsAttackSurfaceAnalyzer.ps1
   
   # Detailed output with HTML report
   .\WindowsAttackSurfaceAnalyzer.ps1 -Detailed -Export
   ```

3. **Review results:**
   - Console output shows real-time findings
   - HTML report provides comprehensive documentation
   - Color-coded risk levels guide prioritization

## Sample Output

```
╔══════════════════════════════════════════╗
║       Windows Attack Surface Analyzer    ║
║                                          ║
║  Comprehensive Security Assessment Tool  ║
╚══════════════════════════════════════════╝

1. NETWORK ATTACK SURFACE
================================
  [Medium] Total Listening Ports - 12 ports open
  [High] Port 3389 - Listening (RDP Service)
  [Medium] Port 445 - Listening (SMB Server)
  [Low] Port 135 - Listening (RPC Endpoint Mapper)

2. SERVICES SECURITY ANALYSIS
=================================
  [High] upnphost - Running (UPnP Device Host)
  [Medium] SSDPSRV - Running (UPnP Discovery)
  [Good] sshd - Not Found/Removed

================================
  SECURITY ANALYSIS SUMMARY
================================
Total Findings: 47
Critical Issues: 0
High Risk Issues: 3
Medium Risk Issues: 12
Low Risk Issues: 8
Good Security Settings: 24

RECOMMENDATIONS:
Address critical and high-risk issues immediately!
Plan to address medium-risk issues within 30 days
Run this analysis monthly to monitor your security posture
```

## Command Line Options

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-Detailed` | Show verbose output with descriptions | `.\script.ps1 -Detailed` |
| `-Export` | Generate HTML report | `.\script.ps1 -Export` |
| `-OutputPath` | Custom report location | `.\script.ps1 -Export -OutputPath "C:\Reports\security.html"` |

## Security Categories

### Network Attack Surface
- **TCP/UDP Listening Ports** - Identifies all open network ports
- **Process Association** - Maps ports to running processes
- **Risk Assessment** - Categorizes ports by security risk level
- **Protocol Analysis** - Identifies dangerous protocols (Telnet, FTP, etc.)

### Service Security
- **Critical Services** - SSH, Web servers, Remote access
- **UPnP Services** - Universal Plug and Play risks
- **Legacy Protocols** - Telnet, FTP, and other insecure services
- **Startup Configuration** - Service auto-start settings

### Firewall Analysis
- **Profile Status** - Domain, Private, Public firewall states
- **Rule Analysis** - Inbound/outbound rule assessment
- **Exception Counting** - Quantifies firewall allow rules
- **Default Policies** - Checks restrictive default configurations

### File System Security
- **SMB Shares** - Network file sharing exposure
- **Administrative Shares** - Hidden C$, ADMIN$ share analysis
- **Share Permissions** - Access control assessment

### System Hardening
- **Windows Defender** - Antivirus and real-time protection
- **User Account Control** - UAC privilege escalation protection
- **Windows Updates** - Patch level and update recency
- **Account Security** - Guest accounts, password policies

## Risk Assessment Framework

The tool uses a standardized risk classification system:

| Risk Level | Color | Criteria | Response Time |
|------------|-------|----------|---------------|
| **Critical** | 🔴 Red | Immediate security threat | Fix immediately |
| **High** | 🟣 Magenta | Significant vulnerability | Fix within 24-48 hours |
| **Medium** | 🟡 Yellow | Moderate security concern | Fix within 30 days |
| **Low** | 🔵 Cyan | Minor security issue | Monitor and plan |
| **Good** | 🟢 Green | Proper security configuration | Maintain |

## Use Cases

### For Cybersecurity Professionals
- **Penetration Testing** - Initial reconnaissance and attack surface mapping
- **Security Audits** - Compliance and security posture assessment
- **Incident Response** - Rapid security baseline establishment
- **Client Assessments** - Professional security consulting

### For System Administrators
- **Security Hardening** - Identify misconfigurations and unnecessary services
- **Compliance Reporting** - Generate documentation for audits
- **Change Management** - Monitor security impact of system changes
- **Baseline Security** - Establish and maintain security standards

### For Home Users
- **Personal Security** - Assess home computer security
- **Privacy Protection** - Identify potential data exposure points
- **Performance Optimization** - Remove unnecessary startup programs
- **Education** - Learn about Windows security concepts

## Advanced Features

### HTML Report Generation
- **Professional Formatting** - Clean, printable security reports
- **Executive Summary** - High-level findings overview
- **Detailed Tables** - Complete finding documentation
- **Risk Prioritization** - Color-coded urgency indicators
- **Recommendations** - Specific remediation guidance

### Automation Support
```powershell
# Scheduled security scanning
$TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\WindowsAttackSurfaceAnalyzer.ps1 -Export -OutputPath C:\Reports\Weekly-$(Get-Date -Format 'yyyy-MM-dd').html"
$TaskTrigger = New-ScheduledTaskTrigger -Weekly -At "02:00AM" -DaysOfWeek Sunday
Register-ScheduledTask -TaskName "Weekly Security Scan" -Action $TaskAction -Trigger $TaskTrigger
```

### Integration Examples
```powershell
# PowerShell remoting for multiple machines
$computers = "Server1", "Server2", "Workstation1"
Invoke-Command -ComputerName $computers -FilePath ".\WindowsAttackSurfaceAnalyzer.ps1"

# Export to centralized logging
.\WindowsAttackSurfaceAnalyzer.ps1 -Export -OutputPath "\\FileServer\SecurityReports\$env:COMPUTERNAME-$(Get-Date -Format 'yyyy-MM-dd').html"
```

## Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### Ways to Contribute
- **Security Checks** - Add new vulnerability detection capabilities
- **Risk Assessment** - Improve risk scoring algorithms
- **Documentation** - Enhance guides and examples
- **Bug Reports** - Report issues and edge cases
- **Feature Requests** - Suggest new functionality

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-security-check`
3. Test your changes thoroughly
4. Submit a pull request with detailed description

### Contribution Guidelines
- Follow PowerShell best practices and style conventions
- Include error handling for all new functionality
- Add appropriate risk levels and descriptions
- Update documentation for new features
- Test on multiple Windows versions when possible

## Troubleshooting

### Common Issues

**"Execution Policy" Errors:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Limited Results Without Admin:**
- Some security checks require administrator privileges
- Run PowerShell as Administrator for complete analysis
- The script will warn about limitations and continue

**Antivirus False Positives:**
- Security tools may flag PowerShell security scripts
- Add exception for the script location
- Download from official GitHub repository only

**Network Connectivity Issues:**
- Ensure Windows Firewall allows PowerShell network access
- Check corporate proxy settings if downloading fails
- Use offline installation if needed

### Getting Help
- Check the [Wiki](../../wiki) for detailed documentation
- Report bugs via [GitHub Issues](../../issues)
- Join discussions in [GitHub Discussions](../../discussions)
- Contact maintainers for security-related inquiries

## Educational Resources

### Learning Windows Security
- [Microsoft Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Windows Security](https://www.sans.org/white-papers/windows/)

### PowerShell Security
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/learn/security/overview)
- [Windows Security Cmdlets](https://docs.microsoft.com/en-us/powershell/module/defender/)

## Legal and Ethical Use

### Important Disclaimers
- **Authorization Required** - Only use on systems you own or have explicit permission to test
- **No Warranty** - Tool provided as-is for educational and legitimate security purposes
- **Compliance Responsibility** - Users must ensure compliance with local laws and regulations
- **Ethical Use Only** - Not intended for malicious activities

### Responsible Disclosure
If you discover security vulnerabilities in this tool:
1. **Do not** create public issues for security vulnerabilities
2. Email security concerns to [nublexer@hotmail.com]
3. Allow reasonable time for fixes before public disclosure
4. We appreciate responsible security research

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Igor Dunaev / NubleX

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## Acknowledgments

- **Security Community** - For continuous feedback and contributions
- **Microsoft Security Team** - For Windows security documentation
- **PowerShell Community** - For scripting best practices and examples
- **Cybersecurity Researchers** - For vulnerability research and threat intelligence

## Project Statistics

![GitHub stars](https://img.shields.io/github/stars/NubleX/Windows-Attack-Surface-Analyzer)
![GitHub forks](https://img.shields.io/github/forks/NubleX/Windows-Attack-Surface-Analyzer)
![GitHub issues](https://img.shields.io/github/issues/NubleX/Windows-Attack-Surface-Analyzer)
![GitHub pull requests](https://img.shields.io/github/issues-pr/NubleX/Windows-Attack-Surface-Analyzer)

---

**Stay Secure, Stay Vigilant!**

*This tool is part of the ongoing effort to make cybersecurity accessible to everyone. Together, we can build a more secure digital world.*

Visit https://www.idarti.com
