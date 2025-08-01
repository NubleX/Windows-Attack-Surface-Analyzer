# Windows Security Hardening Guide

This guide provides actionable steps to address common security issues identified by the Windows Attack Surface Analyzer.

## Critical Priority Issues

### SMB1 Protocol Enabled
**Risk:** Critical vulnerability to ransomware attacks (WannaCry, NotPetya)

**Fix:**
```powershell
# Disable SMB1 Protocol
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
# Restart required
```

### Telnet Server Running
**Risk:** Unencrypted remote access, credential theft

**Fix:**
```powershell
# Stop and disable Telnet
Stop-Service TelnetD -Force
Set-Service TelnetD -StartupType Disabled
# Remove Telnet Server feature
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer
```

### Windows Firewall Disabled
**Risk:** Complete network exposure

**Fix:**
```powershell
# Enable all firewall profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# Set secure defaults
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
```

## High Priority Issues

### UPnP Services Running
**Risk:** Automatic port forwarding, NAT bypass attacks

**Fix:**
```powershell
# Disable UPnP services
Stop-Service SSDPSRV, upnphost -Force
Set-Service SSDPSRV, upnphost -StartupType Disabled
```

### Guest Account Enabled
**Risk:** Unauthorized system access

**Fix:**
```powershell
# Disable Guest account
Disable-LocalUser -Name "Guest"
```

### Administrative Shares Exposed
**Risk:** Lateral movement, data exfiltration

**Fix:**
```powershell
# Disable admin shares (affects remote management)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
# Restart required
```

### RDP Exposed to Internet
**Risk:** Brute force attacks, credential theft

**Fix:**
```powershell
# Restrict RDP to local network only
New-NetFirewallRule -DisplayName "RDP Local Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12 -Action Allow
New-NetFirewallRule -DisplayName "Block RDP External" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block
```

## Medium Priority Issues

### SSH Server Configuration
**Risk:** Unauthorized remote access if misconfigured

**Secure SSH Setup:**
```powershell
# Create secure SSH config
$sshConfig = @"
# Secure SSH Configuration
Port 22
ListenAddress 192.168.0.1  # Your local IP
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers yourusername@192.168.0.*
X11Forwarding yes
"@

$sshConfig | Out-File -FilePath "C:\ProgramData\ssh\sshd_config" -Encoding UTF8
Restart-Service sshd
```

### IIS Web Server Running
**Risk:** Web-based attacks, information disclosure

**Hardening Steps:**
```powershell
# If IIS is needed, secure it
# Remove default websites
Remove-IISSite -Name "Default Web Site"

# Disable unnecessary modules
Disable-IISSharedConfig
Remove-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/modules" -Name "."

# Or disable completely if not needed
Stop-Service W3SVC, WAS -Force
Set-Service W3SVC, WAS -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole
```

### NetBIOS Over TCP/IP Enabled
**Risk:** Network reconnaissance, legacy protocol vulnerabilities

**Fix:**
```powershell
# Disable NetBIOS over TCP/IP (requires network adapter configuration)
# Manual steps:
# 1. Network Connections → Adapter Properties
# 2. IPv4 Properties → Advanced → WINS
# 3. Select "Disable NetBIOS over TCP/IP"
# 4. Same for IPv6

# Or via registry (restart required):
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS
}
```

### Multiple Administrator Accounts
**Risk:** Excessive privileges, harder to audit

**Fix:**
```powershell
# Review admin accounts
Get-LocalGroupMember -Group "Administrators"

# Remove unnecessary admin users
Remove-LocalGroupMember -Group "Administrators" -Member "UnneededUser"

# Create standard user accounts for daily use
New-LocalUser -Name "DailyUser" -Password (ConvertTo-SecureString "SecurePassword123!" -AsPlainText -Force)
Add-LocalGroupMember -Group "Users" -Member "DailyUser"
```

## System Hardening Recommendations

### Windows Defender Configuration
```powershell
# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable cloud protection
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Configure scan settings
Set-MpPreference -ScanParameters FullScan
Set-MpPreference -ScanScheduleDay Everyday
Set-MpPreference -ScanScheduleTime 02:00:00
```

### User Account Control (UAC) Hardening
```powershell
# Enable UAC with highest security
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 3
```

### Windows Update Configuration
```powershell
# Enable automatic updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4

# Check for updates
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate -Install -AcceptAll -AutoReboot
```

### Disable Unnecessary Services
```powershell
# Services that can often be safely disabled
$servicesToDisable = @(
    'fax',           # Fax service
    'msiscsi',       # iSCSI Initiator
    'browser',       # Computer Browser
    'remoteregistry', # Remote Registry
    'termservice'    # Terminal Services (if not using RDP)
)

foreach ($service in $servicesToDisable) {
    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "Stopping $service..."
        Stop-Service $service -Force
        Set-Service $service -StartupType Disabled
    }
}
```

## Advanced Security Configurations

### PowerShell Security
```powershell
# Enable PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### Network Security
```powershell
# Disable weak protocols
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0 -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0 -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0 -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0 -PropertyType DWORD

# Enable strong protocols only
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 1 -PropertyType DWORD
```

### File System Security
```powershell
# Remove unnecessary file associations
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.bat" -Name "(Default)" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.cmd" -Name "(Default)" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\.com" -Name "(Default)" -ErrorAction SilentlyContinue

# Enable file system auditing
auditpol /set /category:"Object Access" /success:enable /failure:enable
```

## Monitoring and Maintenance

### Security Monitoring Script
```powershell
# Create security monitoring scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\WindowsAttackSurfaceAnalyzer.ps1 -Export"
$trigger = New-ScheduledTaskTrigger -Weekly -At "02:00AM" -DaysOfWeek Sunday
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "Weekly Security Scan" -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest
```

### Log Review
```powershell
# Check security logs for failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50

# Check for suspicious PowerShell activity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 50
```

### Regular Maintenance Tasks
1. **Monthly**: Run the Windows Attack Surface Analyzer
2. **Weekly**: Check Windows Updates and install patches
3. **Weekly**: Review security event logs
4. **Monthly**: Review user accounts and permissions
5. **Quarterly**: Review and update firewall rules
6. **Quarterly**: Review installed software and remove unused applications

## Defense in Depth Strategy

### Layer 1: Network Security
- Router firewall configuration
- Network segmentation
- VPN for remote access
- Network monitoring

### Layer 2: System Security
- Windows Firewall
- Windows Defender
- System hardening
- Regular patching

### Layer 3: Application Security
- Application whitelisting
- Secure software installation
- Regular software updates
- Privilege management

### Layer 4: Data Security
- File encryption
- Backup strategies
- Access controls
- Data loss prevention

### Layer 5: User Security
- Strong passwords
- Multi-factor authentication
- Security awareness training
- Principle of least privilege

## Additional Resources

### Microsoft Security Resources
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)

### Industry Standards
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [SANS Top 20 Critical Security Controls](https://www.sans.org/critical-security-controls/)

### PowerShell Security
- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/learn/security/overview)
- [PowerShell Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)

---

**Remember**: Security is an ongoing process, not a one-time configuration. Regularly review and update your security posture to address new threats and vulnerabilities.
