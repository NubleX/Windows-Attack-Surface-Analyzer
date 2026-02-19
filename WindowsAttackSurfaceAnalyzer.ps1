# Windows Attack Surface Analyzer
# A comprehensive security assessment tool for Windows systems
# Created by NubleX / Igor Dunaev, 2025
#
# Authors: Security Community
# Version: 0.3.0
# License: MIT
# GitHub: https://github.com/NubleX/Windows-Attack-Surface-Analyzer
#
# USAGE: Double-click Run-Analysis.bat  OR  run as Administrator in PowerShell:
#        .\WindowsAttackSurfaceAnalyzer.ps1 [-Detailed] [-Export] [-OutputPath <path>]
#
# DESCRIPTION:
# This script analyzes your Windows system for potential security vulnerabilities
# and provides recommendations for hardening your attack surface.
# Compatible with Windows 10 and Windows 11 (all versions).
# Works with PowerShell 5.1 and PowerShell 7+.

param(
    [switch]$Detailed,  # Show detailed output
    [switch]$Export,    # Export results to file
    [string]$OutputPath = ".\SecurityReport.html"
)

# ── Detect OS version and PowerShell version ──────────────────────────────────
$script:PSMajor = $PSVersionTable.PSVersion.Major
try {
    $script:_os        = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $script:WinBuild   = [int]$script:_os.BuildNumber
    $script:OSCaption  = $script:_os.Caption
    $script:OSArch     = $script:_os.OSArchitecture
} catch {
    $script:WinBuild  = 0
    $script:OSCaption = "Unknown Windows"
    $script:OSArch    = "Unknown"
}
$script:IsWindows11     = $script:WinBuild -ge 22000   # Windows 11 21H2+
$script:IsWin1122H2Plus = $script:WinBuild -ge 22621   # Windows 11 22H2+ (Smart App Control)
$script:IsWin1124H2Plus = $script:WinBuild -ge 26100   # Windows 11 24H2+ (Recall)
$script:IsWindows10     = ($script:WinBuild -ge 10240) -and (-not $script:IsWindows11)
# ─────────────────────────────────────────────────────────────────────────────

# ── Scan progress tracking ────────────────────────────────────────────────────
$script:ScanStep  = 0
$script:ScanTotal = 21
function Write-ScanProgress {
    param([string]$Section)
    $script:ScanStep++
    $pct = [int](($script:ScanStep / $script:ScanTotal) * 100)
    Write-Progress -Activity "Windows Attack Surface Analyzer" `
                   -Status "[$script:ScanStep/$script:ScanTotal] $Section" `
                   -PercentComplete $pct
}
# ─────────────────────────────────────────────────────────────────────────────

# Color coding for output
$Colors = @{
    'Critical' = 'Red'
    'High' = 'Magenta' 
    'Medium' = 'Yellow'
    'Low' = 'Cyan'
    'Info' = 'White'
    'Good' = 'Green'
    'Header' = 'Blue'
}

# Security findings storage
$SecurityFindings = @()

function Write-ColorOutput {
    param([string]$Message, [string]$Level = 'Info')
    $Color = $Colors[$Level]
    Write-Host $Message -ForegroundColor $Color
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Item,
        [string]$Status,
        [string]$Risk,
        [string]$Description,
        [string]$Recommendation = ""
    )
    
    $Finding = [PSCustomObject]@{
        Category = $Category
        Item = $Item
        Status = $Status
        Risk = $Risk
        Description = $Description
        Recommendation = $Recommendation
        Timestamp = Get-Date
    }
    
    $script:SecurityFindings += $Finding
    
    # Real-time output
    $riskColor = switch($Risk) {
        'Critical' { 'Red' }
        'High' { 'Magenta' }
        'Medium' { 'Yellow' }
        'Low' { 'Cyan' }
        'Info' { 'White' }
        default { 'White' }
    }
    
    Write-Host "  [$Risk] $Item - $Status" -ForegroundColor $riskColor
    if ($Detailed -and $Description) {
        Write-Host "    $Description" -ForegroundColor Gray
    }
}

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NetworkPorts {
    Write-ColorOutput "`n1. NETWORK ATTACK SURFACE" 'Header'
    Write-ColorOutput "================================" 'Header'
    
    try {
        $tcpConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Sort-Object LocalPort
        $portCount = $tcpConnections.Count
        
        if ($portCount -eq 0) {
            Add-Finding "Network" "Listening Ports" "No listening ports found" "Info" "No TCP ports are listening"
            return
        }
        
        # Risk assessment based on port count
        $portRisk = if ($portCount -gt 20) { "High" } elseif ($portCount -gt 10) { "Medium" } else { "Low" }
        Add-Finding "Network" "Total Listening Ports" "$portCount ports open" $portRisk "Multiple open ports increase attack surface"
        
        foreach ($conn in $tcpConnections) {
            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $processName = if ($process) { $process.ProcessName } else { "Unknown" }
                
                # Risk assessment for specific ports
                $risk = switch ($conn.LocalPort) {
                    21 { "High" }      # FTP
                    22 { "Medium" }    # SSH (depends on config)
                    23 { "Critical" }  # Telnet
                    80 { "Medium" }    # HTTP
                    135 { "Low" }      # RPC (Windows essential)
                    139 { "Medium" }   # NetBIOS
                    443 { "Low" }      # HTTPS
                    445 { "Medium" }   # SMB
                    3389 { "High" }    # RDP
                    5357 { "Medium" }  # UPnP
                    default { 
                        if ($conn.LocalPort -lt 1024) { "Medium" } else { "Low" }
                    }
                }
                
                $description = "Port $($conn.LocalPort) listening on $($conn.LocalAddress) - Process: $processName (PID: $($conn.OwningProcess))"
                Add-Finding "Network" "Port $($conn.LocalPort)" "Listening" $risk $description
                
            } catch {
                Add-Finding "Network" "Port $($conn.LocalPort)" "Listening" "Medium" "Could not identify process"
            }
        }
    } catch {
        Add-Finding "Network" "Port Scan" "Failed" "High" "Could not enumerate listening ports: $($_.Exception.Message)"
    }
}

function Get-ServicesSecurity {
    Write-ColorOutput "`n2. SERVICES SECURITY ANALYSIS" 'Header'
    Write-ColorOutput "=================================" 'Header'
    
    # High-risk services to check
    $riskyServices = @{
        'sshd' = @{ Risk = 'Medium'; Description = 'SSH Server - Remote access capability' }
        'W3SVC' = @{ Risk = 'Medium'; Description = 'IIS Web Server - Web attack surface' }
        'SSDPSRV' = @{ Risk = 'Medium'; Description = 'UPnP Discovery - Can be exploited' }
        'upnphost' = @{ Risk = 'High'; Description = 'UPnP Device Host - Security risk' }
        'TelnetD' = @{ Risk = 'Critical'; Description = 'Telnet Server - Unencrypted remote access' }
        'FTPSVC' = @{ Risk = 'High'; Description = 'FTP Server - Often insecure' }
        'RemoteRegistry' = @{ Risk = 'High'; Description = 'Remote Registry - Security risk' }
        'TermService' = @{ Risk = 'Medium'; Description = 'RDP Service - Remote desktop access' }
        'LanmanServer' = @{ Risk = 'Medium'; Description = 'SMB Server - File sharing' }
        'Browser' = @{ Risk = 'Low'; Description = 'Computer Browser - Network discovery' }
    }
    
    foreach ($serviceName in $riskyServices.Keys) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            $serviceInfo = $riskyServices[$serviceName]
            $status = $service.Status
            
            if ($status -eq 'Running') {
                $startupType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue).StartMode
                Add-Finding "Services" $serviceName "Running (Startup: $startupType)" $serviceInfo.Risk $serviceInfo.Description "Consider disabling if not needed"
            } else {
                Add-Finding "Services" $serviceName "Stopped" "Info" $serviceInfo.Description
            }
        }
    }
    
    # Check for unusual running services (some protected services throw on status query)
    $runningServices = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Status -eq 'Running' } catch { $false }
    }
    $serviceCount = $runningServices.Count
    $risk = if ($serviceCount -gt 150) { "Medium" } elseif ($serviceCount -gt 100) { "Low" } else { "Info" }
    Add-Finding "Services" "Total Running Services" "$serviceCount services" $risk "High service count may indicate unnecessary attack surface"
}

function Get-FirewallStatus {
    Write-ColorOutput "`n3. WINDOWS FIREWALL ANALYSIS" 'Header'
    Write-ColorOutput "================================" 'Header'
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $enabledProfiles = ($profiles | Where-Object {$_.Enabled -eq $true}).Count
        
        if ($enabledProfiles -eq 3) {
            Add-Finding "Firewall" "Profile Status" "All profiles enabled" "Good" "Domain, Private, and Public profiles are active"
        } elseif ($enabledProfiles -gt 0) {
            Add-Finding "Firewall" "Profile Status" "$enabledProfiles/3 profiles enabled" "Medium" "Some firewall profiles are disabled"
        } else {
            Add-Finding "Firewall" "Profile Status" "All profiles disabled" "Critical" "Windows Firewall is completely disabled" "Enable Windows Firewall immediately"
        }
        
        foreach ($profile in $profiles) {
            $status = if ($profile.Enabled) { "Enabled" } else { "Disabled" }
            $risk = if ($profile.Enabled) { "Good" } else { "High" }
            Add-Finding "Firewall" "$($profile.Name) Profile" $status $risk "Default In: $($profile.DefaultInboundAction), Out: $($profile.DefaultOutboundAction)"
        }
        
        # Check for risky firewall rules
        $allowRules = Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'} -ErrorAction SilentlyContinue
        $ruleCount = $allowRules.Count
        $risk = if ($ruleCount -gt 50) { "Medium" } elseif ($ruleCount -gt 20) { "Low" } else { "Info" }
        Add-Finding "Firewall" "Inbound Allow Rules" "$ruleCount rules" $risk "Many allow rules may increase attack surface"
        
    } catch {
        Add-Finding "Firewall" "Analysis" "Failed" "High" "Could not analyze firewall: $($_.Exception.Message)"
    }
}

function Get-NetworkShares {
    Write-ColorOutput "`n4. NETWORK SHARES ANALYSIS" 'Header'
    Write-ColorOutput "==============================" 'Header'
    
    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue
        
        foreach ($share in $shares) {
            $risk = switch ($share.Name) {
                'ADMIN$' { 'High' }
                'C$' { 'High' }
                'D$' { 'High' }
                'IPC$' { 'Medium' }
                'print$' { 'Low' }
                default { 'Medium' }
            }
            
            $description = "Share: $($share.Path) - $($share.Description)"
            if ($share.Name -like '*$') {
                $description += " (Administrative share)"
            }
            
            Add-Finding "Shares" $share.Name "Active" $risk $description
        }
        
        if ($shares.Count -eq 0) {
            Add-Finding "Shares" "SMB Shares" "None found" "Good" "No network shares detected"
        }
        
    } catch {
        Add-Finding "Shares" "Analysis" "Failed" "Medium" "Could not enumerate shares: $($_.Exception.Message)"
    }
}

function Get-WindowsFeatures {
    Write-ColorOutput "`n5. WINDOWS FEATURES ANALYSIS" 'Header'
    Write-ColorOutput "===============================" 'Header'
    
    $riskyFeatures = @{
        'IIS-WebServerRole' = @{ Risk = 'Medium'; Description = 'Internet Information Services - Web server' }
        'SMB1Protocol' = @{ Risk = 'Critical'; Description = 'SMB1 Protocol - Known security vulnerabilities' }
        'TelnetClient' = @{ Risk = 'Medium'; Description = 'Telnet Client - Unencrypted communication' }
        'TFTP' = @{ Risk = 'Medium'; Description = 'TFTP Client - Insecure file transfer' }
        'SimpleTCP' = @{ Risk = 'Medium'; Description = 'Simple TCP/IP Services - Legacy protocols' }
        'TelnetServer' = @{ Risk = 'Critical'; Description = 'Telnet Server - Unencrypted remote access' }
        'Subsystem-Linux' = @{ Risk = 'Low'; Description = 'Windows Subsystem for Linux' }
    }
    
    foreach ($featureName in $riskyFeatures.Keys) {
        try {
            $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName -ErrorAction SilentlyContinue
            if ($feature) {
                $featureInfo = $riskyFeatures[$featureName]
                $status = $feature.State
                
                if ($status -eq 'Enabled') {
                    Add-Finding "Features" $featureName "Enabled" $featureInfo.Risk $featureInfo.Description "Consider disabling if not needed"
                } else {
                    Add-Finding "Features" $featureName "Disabled" "Good" $featureInfo.Description
                }
            }
        } catch {
            # Feature not available on this system
        }
    }
}

function Get-StartupPrograms {
    Write-ColorOutput "`n6. STARTUP PROGRAMS ANALYSIS" 'Header'
    Write-ColorOutput "===============================" 'Header'
    
    $startupLocations = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Scope = "System" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Scope = "User" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "System Once" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "User Once" }
    )
    
    $totalStartupItems = 0
    
    foreach ($location in $startupLocations) {
        try {
            $items = Get-ItemProperty -Path $location.Path -ErrorAction SilentlyContinue
            if ($items) {
                $properties = $items.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"}
                $totalStartupItems += $properties.Count
                
                foreach ($prop in $properties) {
                    $risk = "Low"  # Most startup items are legitimate
                    $description = "$($location.Scope) startup: $($prop.Value)"
                    Add-Finding "Startup" $prop.Name "Active" $risk $description
                }
            }
        } catch {
            Add-Finding "Startup" $location.Scope "Failed" "Medium" "Could not read startup location: $($_.Exception.Message)"
        }
    }
    
    $risk = if ($totalStartupItems -gt 20) { "Medium" } elseif ($totalStartupItems -gt 10) { "Low" } else { "Info" }
    Add-Finding "Startup" "Total Startup Items" "$totalStartupItems items" $risk "Many startup programs may slow boot and expand attack surface"
}

function Get-UserSecurity {
    Write-ColorOutput "`n7. USER ACCOUNT SECURITY" 'Header'
    Write-ColorOutput "===========================" 'Header'
    
    try {
        # Check for enabled Guest account
        $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guestAccount -and $guestAccount.Enabled) {
            Add-Finding "Users" "Guest Account" "Enabled" "High" "Guest account is enabled" "Disable guest account"
        } elseif ($guestAccount) {
            Add-Finding "Users" "Guest Account" "Disabled" "Good" "Guest account is properly disabled"
        }
        
        # Check for accounts with empty passwords
        $users = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
        foreach ($user in $users) {
            if ($user.PasswordLastSet -eq $null) {
                Add-Finding "Users" $user.Name "No password set" "Critical" "User account has no password" "Set a strong password"
            } elseif ($user.PasswordLastSet -lt (Get-Date).AddDays(-90)) {
                Add-Finding "Users" $user.Name "Old password" "Medium" "Password is over 90 days old" "Consider password rotation"
            }
        }
        
        # Check administrator accounts
        $adminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $adminCount = $adminUsers.Count
        $risk = if ($adminCount -gt 3) { "Medium" } elseif ($adminCount -gt 1) { "Low" } else { "Info" }
        Add-Finding "Users" "Administrator Accounts" "$adminCount accounts" $risk "Multiple admin accounts increase risk"
        
    } catch {
        Add-Finding "Users" "Analysis" "Failed" "Medium" "Could not analyze user accounts: $($_.Exception.Message)"
    }
}

function Get-SystemSecurity {
    Write-ColorOutput "`n8. SYSTEM SECURITY SETTINGS" 'Header'
    Write-ColorOutput "==============================" 'Header'
    
    try {
        # Check Windows Update status
        $updates = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($updates -and $updates.InstalledOn -lt (Get-Date).AddDays(-30)) {
            Add-Finding "System" "Windows Updates" "Outdated" "High" "Last update over 30 days ago: $($updates.InstalledOn)" "Install Windows updates"
        } elseif ($updates) {
            Add-Finding "System" "Windows Updates" "Recent" "Good" "Last update: $($updates.InstalledOn)"
        }
        
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            if ($defenderStatus.AntivirusEnabled) {
                Add-Finding "System" "Windows Defender" "Enabled" "Good" "Real-time protection active"
            } else {
                Add-Finding "System" "Windows Defender" "Disabled" "High" "Antivirus protection is disabled" "Enable Windows Defender"
            }
            
            if ($defenderStatus.AMServiceEnabled -eq $false) {
                Add-Finding "System" "Defender Service" "Disabled" "High" "Defender service is not running" "Start Windows Defender service"
            }
        }
        
        # Check UAC status
        $uacStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        if ($uacStatus -and $uacStatus.EnableLUA -eq 1) {
            Add-Finding "System" "User Account Control" "Enabled" "Good" "UAC is protecting against privilege escalation"
        } else {
            Add-Finding "System" "User Account Control" "Disabled" "High" "UAC is disabled" "Enable User Account Control"
        }
        
    } catch {
        Add-Finding "System" "Analysis" "Failed" "Medium" "Could not analyze system security: $($_.Exception.Message)"
    }
}

function Export-Results {
    if (-not $Export) { return }
    
    Write-ColorOutput "`nExporting results to $OutputPath..." 'Info'
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Attack Surface Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .category { margin: 20px 0; }
        .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #bdc3c7; }
        .critical { border-left-color: #e74c3c; background-color: #fdf2f2; }
        .high { border-left-color: #e67e22; background-color: #fef9e7; }
        .medium { border-left-color: #f39c12; background-color: #fefbf3; }
        .low { border-left-color: #3498db; background-color: #f4f8fd; }
        .good { border-left-color: #27ae60; background-color: #f1f8f4; }
        .info { border-left-color: #95a5a6; background-color: #f8f9fa; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows Attack Surface Analysis Report</h1>
        <p>Generated on: $(Get-Date)</p>
        <p>Computer: $env:COMPUTERNAME</p>
        <p>User: $env:USERNAME</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Findings:</strong> $($SecurityFindings.Count)</p>
        <p><strong>Critical Issues:</strong> $(($SecurityFindings | Where-Object {$_.Risk -eq 'Critical'}).Count)</p>
        <p><strong>High Risk Issues:</strong> $(($SecurityFindings | Where-Object {$_.Risk -eq 'High'}).Count)</p>
        <p><strong>Medium Risk Issues:</strong> $(($SecurityFindings | Where-Object {$_.Risk -eq 'Medium'}).Count)</p>
        <p><strong>Low Risk Issues:</strong> $(($SecurityFindings | Where-Object {$_.Risk -eq 'Low'}).Count)</p>
    </div>
    
    <h2>Detailed Findings</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Item</th>
            <th>Status</th>
            <th>Risk Level</th>
            <th>Description</th>
            <th>Recommendation</th>
        </tr>
"@
    
    foreach ($finding in $SecurityFindings) {
        $cssClass = $finding.Risk.ToLower()
        $html += @"
        <tr class="$cssClass">
            <td>$($finding.Category)</td>
            <td>$($finding.Item)</td>
            <td>$($finding.Status)</td>
            <td>$($finding.Risk)</td>
            <td>$($finding.Description)</td>
            <td>$($finding.Recommendation)</td>
        </tr>
"@
    }
    
    $html += @"
    </table>
    
    <div class="summary">
        <h3>Recommendations Summary</h3>
        <ul>
            <li><strong>Critical/High Issues:</strong> Address immediately</li>
            <li><strong>Medium Issues:</strong> Plan to address within 30 days</li>
            <li><strong>Low Issues:</strong> Monitor and address as resources allow</li>
            <li><strong>Regular Monitoring:</strong> Run this scan monthly</li>
        </ul>
    </div>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Generated by Windows Attack Surface Analyzer</p>
        <p>For more information and updates, visit: https://github.com/NubleX/Windows-Attack-Surface-Analyzer</p>
    </footer>
</body>
</html>
"@
    
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-ColorOutput "Report saved to: $OutputPath" 'Good'

        # Auto-open in default browser
        try { Start-Process $OutputPath } catch { }
    } catch {
        Write-ColorOutput "Failed to export report: $($_.Exception.Message)" 'Critical'
    }
}

function Get-HardwareSecurity {
    Write-ColorOutput "`n9. HARDWARE SECURITY (TPM / SECURE BOOT / VBS)" 'Header'
    Write-ColorOutput "================================================" 'Header'

    # ── TPM ──────────────────────────────────────────────────────────────────
    try {
        $tpm = Get-CimInstance -Namespace root\CIMv2\Security\MicrosoftTpm `
                               -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            if ($tpm.IsEnabled_InitialValue) {
                # SpecVersion is like "2.0, 1.2, ..." – take the first token
                $tpmVer = ($tpm.SpecVersion -split ',')[0].Trim()
                $tpmRisk = if ($tpmVer -like '2*') { 'Good' } else { 'Medium' }
                Add-Finding 'Hardware' 'TPM' "Enabled (v$tpmVer)" $tpmRisk `
                    "Trusted Platform Module provides hardware-based security root"
            } else {
                Add-Finding 'Hardware' 'TPM' 'Disabled' 'High' `
                    'TPM chip found but disabled in BIOS/UEFI' `
                    'Enable TPM in BIOS/UEFI firmware settings'
            }
        } else {
            Add-Finding 'Hardware' 'TPM' 'Not Found' 'High' `
                'No TPM detected – may be disabled in BIOS/UEFI or not present' `
                'Check BIOS/UEFI for a TPM or PTT (Platform Trust Technology) setting'
        }
    } catch {
        Add-Finding 'Hardware' 'TPM' 'Check Failed' 'Medium' `
            "Could not read TPM status: $($_.Exception.Message)"
    }

    # ── Secure Boot ───────────────────────────────────────────────────────────
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            Add-Finding 'Hardware' 'Secure Boot' 'Enabled' 'Good' `
                'UEFI Secure Boot is active – blocks unsigned boot code'
        } else {
            Add-Finding 'Hardware' 'Secure Boot' 'Disabled' 'High' `
                'Secure Boot is off – bootkits and rootkits can load at startup' `
                'Enable Secure Boot in BIOS/UEFI settings'
        }
    } catch [System.PlatformNotSupportedException] {
        Add-Finding 'Hardware' 'Secure Boot' 'Not Supported' 'Medium' `
            'System is using Legacy BIOS – Secure Boot requires UEFI firmware'
    } catch {
        Add-Finding 'Hardware' 'Secure Boot' 'Check Failed' 'Low' `
            "Could not determine Secure Boot status: $($_.Exception.Message)"
    }

    # ── Virtualization-Based Security / HVCI / Credential Guard ──────────────
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
                              -Namespace root\Microsoft\Windows\DeviceGuard `
                              -ErrorAction SilentlyContinue
        if ($dg) {
            # VBS running states: 0=Off, 1=Configured, 2=Running
            if ($dg.VirtualizationBasedSecurityStatus -eq 2) {
                Add-Finding 'Hardware' 'Virtualization-Based Security (VBS)' 'Running' 'Good' `
                    'VBS isolates sensitive OS processes from the kernel'
            } else {
                Add-Finding 'Hardware' 'Virtualization-Based Security (VBS)' 'Not Running' 'Medium' `
                    'VBS provides strong protection against credential theft and kernel exploits' `
                    'Enable in Windows Security > Device Security > Core isolation'
            }

            # HVCI (Memory Integrity)
            if ($dg.CodeIntegrityPolicyEnforcementStatus -eq 2) {
                Add-Finding 'Hardware' 'Memory Integrity (HVCI)' 'Enabled' 'Good' `
                    'Hypervisor blocks unsigned kernel-mode drivers'
            } else {
                Add-Finding 'Hardware' 'Memory Integrity (HVCI)' 'Disabled' 'Medium' `
                    'Memory Integrity prevents malicious drivers from loading' `
                    'Enable in Windows Security > Device Security > Core isolation details'
            }

            # Credential Guard (service ID 1)
            if ($dg.SecurityServicesRunning -and ($dg.SecurityServicesRunning -contains 1)) {
                Add-Finding 'Hardware' 'Credential Guard' 'Running' 'Good' `
                    'Credential Guard isolates login secrets in a secure enclave'
            } else {
                Add-Finding 'Hardware' 'Credential Guard' 'Not Running' 'Low' `
                    'Credential Guard protects domain credentials from pass-the-hash attacks'
            }

            # Kernel DMA Protection
            if ($dg.KernelDmaProtectionStatus -eq 2) {
                Add-Finding 'Hardware' 'Kernel DMA Protection' 'Enabled' 'Good' `
                    'Blocks DMA attacks via Thunderbolt and other external ports'
            } else {
                Add-Finding 'Hardware' 'Kernel DMA Protection' 'Not Active' 'Low' `
                    'Kernel DMA Protection guards against physical port (e.g. Thunderbolt) attacks'
            }
        } else {
            Add-Finding 'Hardware' 'VBS / Device Guard' 'Unavailable' 'Info' `
                'Device Guard information not accessible on this system'
        }
    } catch {
        Add-Finding 'Hardware' 'VBS / Device Guard' 'Check Failed' 'Medium' `
            "Could not read VBS/Device Guard status: $($_.Exception.Message)"
    }
}

function Get-BitLockerStatus {
    Write-ColorOutput "`n10. DISK ENCRYPTION (BITLOCKER)" 'Header'
    Write-ColorOutput "=================================" 'Header'

    try {
        $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($null -eq $volumes) {
            Add-Finding 'Encryption' 'BitLocker' 'Check Requires Admin' 'Medium' `
                'Run as Administrator to see BitLocker status for all drives' `
                'Right-click PowerShell and choose "Run as administrator"'
            return
        }

        foreach ($vol in $volumes) {
            $mount  = $vol.MountPoint
            $status = $vol.ProtectionStatus   # On / Off / Unknown
            $pct    = $vol.EncryptionPercentage

            if ($status -eq 'On') {
                $protectors = ($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
                Add-Finding 'Encryption' "Drive $mount" "Encrypted ($pct%)" 'Good' `
                    "BitLocker active. Protectors: $protectors"
            } elseif ($pct -gt 0) {
                Add-Finding 'Encryption' "Drive $mount" "Encrypting ($pct%)" 'Low' `
                    'BitLocker encryption is in progress – leave the device on'
            } else {
                $risk = if ($mount -eq 'C:\') { 'High' } else { 'Medium' }
                Add-Finding 'Encryption' "Drive $mount" 'Not Encrypted' $risk `
                    'Anyone with physical access to this drive can read all files' `
                    'Enable BitLocker: Start > Settings > Privacy & Security > Device encryption'
            }
        }

        if ($volumes.Count -eq 0) {
            Add-Finding 'Encryption' 'BitLocker' 'No Volumes Found' 'Medium' `
                'No BitLocker-eligible volumes detected'
        }
    } catch {
        Add-Finding 'Encryption' 'BitLocker' 'Check Failed' 'Medium' `
            "Could not check BitLocker status: $($_.Exception.Message)"
    }
}

function Get-AdvancedDefender {
    Write-ColorOutput "`n11. ADVANCED DEFENDER ANALYSIS" 'Header'
    Write-ColorOutput "================================" 'Header'

    try {
        $pref   = Get-MpPreference    -ErrorAction SilentlyContinue
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue

        if (-not $pref -or -not $status) {
            Add-Finding 'Defender' 'Advanced Analysis' 'Unavailable' 'Medium' `
                'Could not access Defender settings – may not be the active antivirus'
            return
        }

        # Tamper Protection
        if ($status.IsTamperProtected) {
            Add-Finding 'Defender' 'Tamper Protection' 'Enabled' 'Good' `
                'Defender settings are locked against unauthorised changes'
        } else {
            Add-Finding 'Defender' 'Tamper Protection' 'Disabled' 'High' `
                'Malware could silently disable Windows Defender' `
                'Enable Tamper Protection: Windows Security > Virus protection > Manage settings'
        }

        # Cloud-delivered Protection
        if ($pref.MAPSReporting -ne 0) {
            Add-Finding 'Defender' 'Cloud Protection' 'Enabled' 'Good' `
                'Cloud-delivered protection gives near-instant threat intelligence'
        } else {
            Add-Finding 'Defender' 'Cloud Protection' 'Disabled' 'Medium' `
                'Cloud protection significantly improves detection of new threats' `
                'Enable in Windows Security > Virus protection > Manage settings'
        }

        # PUA (Potentially Unwanted App) Protection
        if ($pref.PUAProtection -eq 1) {
            Add-Finding 'Defender' 'PUA Protection' 'Enabled' 'Good' `
                'Potentially Unwanted Application blocking is active'
        } else {
            Add-Finding 'Defender' 'PUA Protection' 'Disabled' 'Low' `
                'PUA protection blocks adware, browser hijackers and bundled software' `
                'Enable via PowerShell: Set-MpPreference -PUAProtection Enabled'
        }

        # Definition (signature) age
        if ($status.AntivirusSignatureLastUpdated) {
            $sigAge = (Get-Date) - $status.AntivirusSignatureLastUpdated
            if ($sigAge.TotalDays -gt 7) {
                Add-Finding 'Defender' 'Virus Definitions' "Outdated ($([int]$sigAge.TotalDays) days old)" 'High' `
                    'Outdated definitions miss recently discovered malware' `
                    'Update now: Windows Security > Virus protection > Check for updates'
            } elseif ($sigAge.TotalDays -gt 3) {
                Add-Finding 'Defender' 'Virus Definitions' "Aging ($([int]$sigAge.TotalDays) days old)" 'Medium' `
                    'Definitions should update automatically every day'
            } else {
                Add-Finding 'Defender' 'Virus Definitions' "Current ($([int]$sigAge.TotalDays) days old)" 'Good' `
                    "Definitions are up to date"
            }
        }

        # Controlled Folder Access (ransomware protection)
        if ($pref.EnableControlledFolderAccess -eq 1) {
            Add-Finding 'Defender' 'Controlled Folder Access' 'Enabled' 'Good' `
                'Built-in ransomware protection is guarding your documents and pictures'
        } else {
            Add-Finding 'Defender' 'Controlled Folder Access' 'Disabled' 'High' `
                'Without this, ransomware can encrypt all your personal files' `
                'Enable: Windows Security > Virus protection > Ransomware protection'
        }

        # Attack Surface Reduction rules
        $asrIds     = $pref.AttackSurfaceReductionRules_Ids
        $asrActions = $pref.AttackSurfaceReductionRules_Actions
        if ($asrIds -and $asrIds.Count -gt 0) {
            # Actions: 0=Off, 1=Block, 2=Audit, 6=Warn
            $activeCount = @($asrActions | Where-Object { $_ -ne 0 }).Count
            $risk = if ($activeCount -ge 5) { 'Good' } elseif ($activeCount -gt 0) { 'Low' } else { 'Medium' }
            Add-Finding 'Defender' 'ASR Rules' "$activeCount/$($asrIds.Count) rules active" $risk `
                'Attack Surface Reduction rules block common attack techniques'
        } else {
            Add-Finding 'Defender' 'ASR Rules' 'Not Configured' 'Medium' `
                'ASR rules block Office macros, script exploits and LSASS credential theft' `
                'Configure via Group Policy or: Set-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions ...'
        }

        # Exploit Protection (DEP / ASLR via system-wide settings)
        try {
            $epXml = [xml](& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
                -Command "Get-ProcessMitigation -System | ConvertTo-Xml" 2>$null -ErrorAction SilentlyContinue)
        } catch { $epXml = $null }

        $depKey = Get-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' `
            -Name 'MoveImages' -ErrorAction SilentlyContinue
        # A simple registry-based DEP check
        $depBoot = (& bcdedit /enum 2>$null | Select-String 'nx').ToString() 2>$null
        if ($depBoot -match 'AlwaysOn') {
            Add-Finding 'Defender' 'DEP (Data Execution Prevention)' 'AlwaysOn' 'Good' `
                'DEP prevents code from running in non-executable memory regions'
        } else {
            Add-Finding 'Defender' 'DEP (Data Execution Prevention)' 'Not AlwaysOn' 'Low' `
                'DEP should be set to AlwaysOn for maximum protection' `
                'Run as admin: bcdedit /set nx AlwaysOn'
        }

    } catch {
        Add-Finding 'Defender' 'Advanced Analysis' 'Failed' 'Medium' `
            "Could not complete advanced Defender check: $($_.Exception.Message)"
    }
}

function Get-Windows11Features {
    # This function only adds findings on Windows 11; silently skips on Windows 10
    if (-not $script:IsWindows11) { return }

    Write-ColorOutput "`n12. WINDOWS 11 SECURITY FEATURES" 'Header'
    Write-ColorOutput "===================================" 'Header'

    # ── Smart App Control (Windows 11 22H2+) ─────────────────────────────────
    if ($script:IsWin1122H2Plus) {
        try {
            $sacKey = Get-ItemProperty `
                -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' `
                -ErrorAction SilentlyContinue
            $sacState = switch ($sacKey.VerifiedAndReputablePolicyState) {
                1       { @{ Status = 'On';         Risk = 'Good'   } }
                2       { @{ Status = 'Evaluation'; Risk = 'Low'    } }
                0       { @{ Status = 'Off';        Risk = 'Medium' } }
                default { @{ Status = 'Unknown';    Risk = 'Info'   } }
            }
            Add-Finding 'Win11' 'Smart App Control' $sacState.Status $sacState.Risk `
                'Blocks apps from untrusted sources – once turned off it cannot be re-enabled without a reset'
        } catch {
            Add-Finding 'Win11' 'Smart App Control' 'Check Failed' 'Low' `
                "Could not determine Smart App Control status: $($_.Exception.Message)"
        }
    }

    # ── Windows Hello ─────────────────────────────────────────────────────────
    try {
        $helloPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
        if (Test-Path $helloPath) {
            Add-Finding 'Win11' 'Windows Hello' 'Available' 'Good' `
                'Passwordless/biometric sign-in is configured on this device'
        } else {
            Add-Finding 'Win11' 'Windows Hello' 'Not Configured' 'Low' `
                'Windows Hello provides phishing-resistant sign-in without a password' `
                'Set up: Settings > Accounts > Sign-in options'
        }
    } catch { }

    # ── Windows Recall (Windows 11 24H2+) ────────────────────────────────────
    if ($script:IsWin1124H2Plus) {
        try {
            $recallVal = (Get-ItemProperty `
                -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' `
                -Name 'DisableAIDataAnalysis' -ErrorAction SilentlyContinue).DisableAIDataAnalysis
            if ($recallVal -eq 1) {
                Add-Finding 'Win11' 'Windows Recall' 'Disabled' 'Good' `
                    'Recall is off – the system is not capturing periodic screenshots'
            } else {
                Add-Finding 'Win11' 'Windows Recall' 'May Be Active' 'Medium' `
                    'Recall stores screenshots of your screen which may contain passwords or sensitive data' `
                    'Review: Settings > Privacy & Security > Recall & snapshots'
            }
        } catch { }
    }
}

function Get-PowerShellSecurity {
    Write-ColorOutput "`n13. POWERSHELL SECURITY" 'Header'
    Write-ColorOutput "=========================" 'Header'

    # PS version info
    Add-Finding 'PowerShell' 'Version' "$($PSVersionTable.PSVersion)" 'Info' `
        "Running on PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition) edition)"

    # Execution Policy
    try {
        $machinePolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        $risk = switch ($machinePolicy) {
            'Restricted'   { 'Good'     }
            'AllSigned'    { 'Good'     }
            'RemoteSigned' { 'Low'      }
            'Unrestricted' { 'High'     }
            'Bypass'       { 'Critical' }
            default        { 'Medium'   }
        }
        $rec = if ($risk -in 'High','Critical') {
            'Set policy: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine'
        } else { '' }
        Add-Finding 'PowerShell' 'Execution Policy (Machine)' $machinePolicy $risk `
            'Controls which PowerShell scripts are allowed to run on this computer' $rec
    } catch {
        Add-Finding 'PowerShell' 'Execution Policy' 'Check Failed' 'Medium' `
            "Could not read execution policy: $($_.Exception.Message)"
    }

    # Script Block Logging
    try {
        $sbl = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
            -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        if ($sbl -eq 1) {
            Add-Finding 'PowerShell' 'Script Block Logging' 'Enabled' 'Good' `
                'All PowerShell activity is recorded – attackers using PS are logged'
        } else {
            Add-Finding 'PowerShell' 'Script Block Logging' 'Disabled' 'Medium' `
                'Without logging, malicious PowerShell scripts run invisibly' `
                'Enable via Group Policy or registry: HKLM:\...\ScriptBlockLogging EnableScriptBlockLogging=1'
        }
    } catch {
        Add-Finding 'PowerShell' 'Script Block Logging' 'Not Configured' 'Medium' `
            'Script Block Logging policy key not found'
    }

    # Module Logging
    try {
        $ml = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
            -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging
        if ($ml -eq 1) {
            Add-Finding 'PowerShell' 'Module Logging' 'Enabled' 'Good' `
                'PowerShell module usage is recorded in the event log'
        } else {
            Add-Finding 'PowerShell' 'Module Logging' 'Disabled' 'Low' `
                'Module logging helps detect malicious use of PowerShell modules'
        }
    } catch { }

    # Constrained Language Mode
    try {
        $langMode = $ExecutionContext.SessionState.LanguageMode
        if ($langMode -eq 'ConstrainedLanguage') {
            Add-Finding 'PowerShell' 'Language Mode' 'Constrained' 'Good' `
                'Constrained Language Mode limits what PowerShell scripts can do'
        } else {
            Add-Finding 'PowerShell' 'Language Mode' $langMode 'Info' `
                'Full Language Mode – PowerShell has no additional script restrictions'
        }
    } catch { }
}

function Get-DefenderExtended {
    Write-ColorOutput "`n14. DEFENDER - ASR RULES AND SCAN STATUS" 'Header'
    Write-ColorOutput "==========================================" 'Header'

    # Friendly names for all known ASR rule GUIDs
    $asrNames = @{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of vulnerable signed drivers'
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0' = 'Block credential stealing from LSASS'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless trusted (machine-learning)'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript/VBScript launching executables'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps injecting code into processes'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from creating executable content'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced ransomware protection'
    }
    $asrActionLabels = @{ 0 = 'Off'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn' }

    try {
        $pref   = Get-MpPreference    -ErrorAction SilentlyContinue
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue

        if ($pref) {
            # Per-rule ASR breakdown
            $ids     = $pref.AttackSurfaceReductionRules_Ids
            $actions = $pref.AttackSurfaceReductionRules_Actions
            if ($ids -and $ids.Count -gt 0) {
                for ($i = 0; $i -lt $ids.Count; $i++) {
                    $id     = $ids[$i].ToLower()
                    $action = if ($i -lt $actions.Count) { $actions[$i] } else { 0 }
                    $label  = if ($asrActionLabels.ContainsKey([int]$action)) { $asrActionLabels[[int]$action] } else { "Unknown ($action)" }
                    $name   = if ($asrNames.ContainsKey($id)) { $asrNames[$id] } else { "Unknown rule ($id)" }
                    $risk   = if ($action -eq 1) { 'Good' } elseif ($action -eq 2) { 'Low' } else { 'Medium' }
                    Add-Finding 'ASR' $name $label $risk "ASR rule state"
                }
            } else {
                Add-Finding 'ASR' 'ASR Rules' 'None configured' 'Medium' `
                    'No Attack Surface Reduction rules are active' `
                    'Configure ASR rules via Group Policy, Intune, or PowerShell Set-MpPreference'
            }

            # Sample submission
            $sampleLabels = @{ 0 = 'Always prompt'; 1 = 'Send safe samples'; 2 = 'Never send'; 3 = 'Send all samples' }
            $sampleVal  = $pref.SubmitSamplesConsent
            $sampleText = if ($sampleLabels.ContainsKey([int]$sampleVal)) { $sampleLabels[[int]$sampleVal] } else { "Unknown ($sampleVal)" }
            $sampleRisk = if ($sampleVal -eq 3) { 'Good' } elseif ($sampleVal -eq 1) { 'Good' } else { 'Low' }
            Add-Finding 'Defender' 'Sample Submission' $sampleText $sampleRisk `
                'Controls whether suspicious files are sent to Microsoft for analysis'
        }

        if ($status) {
            # Last quick scan
            if ($status.QuickScanAge -ge 0) {
                $qAge = $status.QuickScanAge
                $qRisk = if ($qAge -gt 7) { 'Medium' } elseif ($qAge -gt 3) { 'Low' } else { 'Good' }
                Add-Finding 'Defender' 'Last Quick Scan' "$qAge day(s) ago" $qRisk `
                    'Regular quick scans catch active threats early'
            }
            # Last full scan
            if ($status.FullScanAge -ge 0) {
                $fAge = $status.FullScanAge
                $fRisk = if ($fAge -gt 30) { 'Medium' } elseif ($fAge -gt 14) { 'Low' } else { 'Good' }
                Add-Finding 'Defender' 'Last Full Scan' "$fAge day(s) ago" $fRisk `
                    'Monthly full scans find deeply hidden threats'
            }
        }
    } catch {
        Add-Finding 'Defender' 'Extended Analysis' 'Failed' 'Medium' `
            "Could not complete extended Defender check: $($_.Exception.Message)"
    }

    # Defender Application Guard
    try {
        $dag = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard `
               -ErrorAction SilentlyContinue
        if ($dag) {
            if ($dag.State -eq 'Enabled') {
                Add-Finding 'Defender' 'Application Guard' 'Enabled' 'Good' `
                    'Edge and Office open untrusted content in an isolated hardware container'
            } else {
                Add-Finding 'Defender' 'Application Guard' 'Disabled' 'Low' `
                    'Application Guard isolates untrusted websites and Office documents' `
                    'Enable in Windows Security or: Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard'
            }
        }
    } catch { }
}

function Get-ExploitProtection {
    Write-ColorOutput "`n15. EXPLOIT PROTECTION (ASLR / SEHOP / CFG)" 'Header'
    Write-ColorOutput "=============================================" 'Header'

    try {
        $ep = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if ($ep) {
            # ASLR - ForceRelocateImages
            $aslrOn = $ep.ASLR.ForceRelocateImages -eq 'ON'
            Add-Finding 'ExploitProtection' 'ASLR Force Relocate' `
                $(if ($aslrOn) { 'Enabled' } else { 'Disabled' }) `
                $(if ($aslrOn) { 'Good' } else { 'Medium' }) `
                'Address Space Layout Randomization makes memory addresses unpredictable for attackers'

            # BottomUp ASLR
            $buOn = $ep.ASLR.BottomUp -eq 'ON'
            Add-Finding 'ExploitProtection' 'ASLR Bottom-Up Randomisation' `
                $(if ($buOn) { 'Enabled' } else { 'Disabled' }) `
                $(if ($buOn) { 'Good' } else { 'Low' }) `
                'Randomises heap, stack and mapped memory base addresses'

            # SEHOP
            $sehopOn = $ep.SEHOP.Enable -eq 'ON'
            Add-Finding 'ExploitProtection' 'SEHOP' `
                $(if ($sehopOn) { 'Enabled' } else { 'Disabled' }) `
                $(if ($sehopOn) { 'Good' } else { 'Medium' }) `
                'Structured Exception Handler Overwrite Protection blocks SEH chain exploits'

            # CFG
            $cfgOn = $ep.CFG.Enable -eq 'ON'
            Add-Finding 'ExploitProtection' 'Control Flow Guard (CFG)' `
                $(if ($cfgOn) { 'Enabled' } else { 'Disabled' }) `
                $(if ($cfgOn) { 'Good' } else { 'Low' }) `
                'CFG prevents attackers from redirecting code execution to arbitrary locations'

            # Heap Terminate on Corruption
            $heapOn = $ep.Heap.TerminateOnError -eq 'ON'
            Add-Finding 'ExploitProtection' 'Heap Terminate on Corruption' `
                $(if ($heapOn) { 'Enabled' } else { 'Disabled' }) `
                $(if ($heapOn) { 'Good' } else { 'Low' }) `
                'Kills the process immediately when heap corruption is detected'
        } else {
            Add-Finding 'ExploitProtection' 'Get-ProcessMitigation' 'Unavailable' 'Info' `
                'Process mitigation data could not be read on this system'
        }
    } catch {
        Add-Finding 'ExploitProtection' 'Analysis' 'Failed' 'Medium' `
            "Could not read exploit protection settings: $($_.Exception.Message)"
    }
}

function Get-PrivacySettings {
    Write-ColorOutput "`n16. PRIVACY SETTINGS" 'Header'
    Write-ColorOutput "=====================" 'Header'

    # Telemetry / Diagnostic data level
    try {
        $telVal = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' `
            -Name 'AllowTelemetry' -ErrorAction SilentlyContinue).AllowTelemetry
        $telLabels = @{ 0 = 'Security (off)'; 1 = 'Required'; 2 = 'Enhanced'; 3 = 'Optional (Full)' }
        $telText   = if ($telLabels.ContainsKey([int]$telVal)) { $telLabels[[int]$telVal] } else { 'Default (Required)' }
        $telRisk   = if ($telVal -le 1) { 'Good' } elseif ($telVal -eq 2) { 'Low' } else { 'Medium' }
        Add-Finding 'Privacy' 'Diagnostic Data Level' $telText $telRisk `
            'Controls how much system data is sent to Microsoft'
    } catch {
        Add-Finding 'Privacy' 'Diagnostic Data Level' 'Default (not explicitly set)' 'Info' `
            'No policy override found -- Windows default applies'
    }

    # Advertising ID
    try {
        $adId = (Get-ItemProperty `
            -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' `
            -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
        if ($adId -eq 0) {
            Add-Finding 'Privacy' 'Advertising ID' 'Disabled' 'Good' `
                'Apps cannot use your advertising ID to track you across apps'
        } else {
            Add-Finding 'Privacy' 'Advertising ID' 'Enabled' 'Low' `
                'Apps can access your advertising ID for cross-app tracking' `
                'Disable in Settings > Privacy & Security > General'
        }
    } catch { }

    # Activity History
    try {
        $actVal = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
            -Name 'PublishUserActivities' -ErrorAction SilentlyContinue).PublishUserActivities
        if ($actVal -eq 0) {
            Add-Finding 'Privacy' 'Activity History' 'Disabled by policy' 'Good' `
                'Windows Timeline activity is not collected or uploaded'
        } else {
            Add-Finding 'Privacy' 'Activity History' 'Enabled' 'Low' `
                'Activity history is recorded and may be synced to Microsoft' `
                'Disable in Settings > Privacy & Security > Activity history'
        }
    } catch { }

    # Location
    try {
        $locKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        $locVal = (Get-ItemProperty -Path $locKey -Name 'Value' -ErrorAction SilentlyContinue).Value
        $locRisk = if ($locVal -eq 'Deny') { 'Good' } else { 'Low' }
        Add-Finding 'Privacy' 'Location Access' $(if ($locVal -eq 'Deny') { 'Denied' } else { 'Allowed' }) $locRisk `
            'Controls whether apps can access your physical location'
    } catch { }

    # Camera
    try {
        $camKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
        $camVal = (Get-ItemProperty -Path $camKey -Name 'Value' -ErrorAction SilentlyContinue).Value
        $camRisk = if ($camVal -eq 'Deny') { 'Good' } else { 'Low' }
        Add-Finding 'Privacy' 'Camera Access' $(if ($camVal -eq 'Deny') { 'Denied' } else { 'Allowed' }) $camRisk `
            'Controls whether apps can access your webcam'
    } catch { }

    # Microphone
    try {
        $micKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'
        $micVal = (Get-ItemProperty -Path $micKey -Name 'Value' -ErrorAction SilentlyContinue).Value
        $micRisk = if ($micVal -eq 'Deny') { 'Good' } else { 'Low' }
        Add-Finding 'Privacy' 'Microphone Access' $(if ($micVal -eq 'Deny') { 'Denied' } else { 'Allowed' }) $micRisk `
            'Controls whether apps can access your microphone'
    } catch { }
}

function Get-NetworkSecurity {
    Write-ColorOutput "`n17. NETWORK SECURITY (IPv6 / DoH / Wi-Fi / Bluetooth)" 'Header'
    Write-ColorOutput "=======================================================" 'Header'

    # IPv6
    try {
        $ipv6Bindings = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
                        Where-Object { $_.Enabled -eq $true }
        if ($ipv6Bindings) {
            Add-Finding 'Network' 'IPv6' "Enabled on $($ipv6Bindings.Count) adapter(s)" 'Info' `
                'IPv6 is active. Ensure firewall rules cover IPv6 traffic as well as IPv4'
        } else {
            Add-Finding 'Network' 'IPv6' 'Disabled' 'Info' `
                'IPv6 is not bound to any adapter'
        }
    } catch { }

    # DNS over HTTPS (DoH)
    try {
        $dohVal = (Get-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
            -Name 'EnableAutoDoh' -ErrorAction SilentlyContinue).EnableAutoDoh
        if ($dohVal -eq 2) {
            Add-Finding 'Network' 'DNS over HTTPS (DoH)' 'Allowed (auto)' 'Good' `
                'Windows will use DoH when a compatible DNS server is configured'
        } elseif ($dohVal -eq 1) {
            Add-Finding 'Network' 'DNS over HTTPS (DoH)' 'Required' 'Good' `
                'DNS queries are encrypted -- DNS-based eavesdropping is blocked'
        } else {
            Add-Finding 'Network' 'DNS over HTTPS (DoH)' 'Not configured' 'Low' `
                'DNS queries are sent in plaintext by default' `
                'Enable DoH in Settings > Network > Wi-Fi or Ethernet > DNS server assignment'
        }
    } catch { }

    # Wi-Fi security (check active connected profile)
    try {
        $wlanOutput = & netsh wlan show interfaces 2>&1
        if ($wlanOutput -match 'Authentication\s+:\s+(.+)') {
            $auth = $Matches[1].Trim()
            $wifiRisk = if ($auth -match 'WPA3') { 'Good' } `
                        elseif ($auth -match 'WPA2') { 'Low' } `
                        elseif ($auth -match 'WPA[^2]|WEP|Open') { 'High' } `
                        else { 'Info' }
            Add-Finding 'Network' 'Wi-Fi Authentication' $auth $wifiRisk `
                'Wi-Fi security protocol of the currently connected network'
        } elseif ($wlanOutput -match 'There is no wireless interface') {
            Add-Finding 'Network' 'Wi-Fi' 'No wireless adapter' 'Info' `
                'No Wi-Fi adapter detected on this system'
        } else {
            Add-Finding 'Network' 'Wi-Fi' 'Not connected' 'Info' `
                'No active Wi-Fi connection'
        }
    } catch { }

    # Bluetooth
    try {
        $btService = Get-Service -Name bthserv -ErrorAction SilentlyContinue
        if ($btService -and $btService.Status -eq 'Running') {
            Add-Finding 'Network' 'Bluetooth Service' 'Running' 'Low' `
                'Bluetooth is active -- ensure device is not set to discoverable in public places' `
                'Turn off Bluetooth when not in use: Settings > Bluetooth & devices'
        } elseif ($btService) {
            Add-Finding 'Network' 'Bluetooth Service' 'Stopped' 'Good' `
                'Bluetooth service is not running'
        } else {
            Add-Finding 'Network' 'Bluetooth' 'Not present' 'Good' `
                'No Bluetooth service found on this system'
        }
    } catch { }

    # VPN
    try {
        $vpnConnections = Get-VpnConnection -ErrorAction SilentlyContinue
        if ($vpnConnections) {
            $connected = $vpnConnections | Where-Object { $_.ConnectionStatus -eq 'Connected' }
            if ($connected) {
                Add-Finding 'Network' 'VPN' "Connected ($($connected.Name))" 'Good' `
                    'An active VPN connection is encrypting your traffic'
            } else {
                Add-Finding 'Network' 'VPN' "$($vpnConnections.Count) profile(s) configured, not connected" 'Info' `
                    'VPN profiles exist but none are currently active'
            }
        } else {
            Add-Finding 'Network' 'VPN' 'No profiles configured' 'Info' `
                'No VPN connections are configured on this system'
        }
    } catch { }
}

function Get-RemoteAccessSecurity {
    Write-ColorOutput "`n18. REMOTE ACCESS SECURITY (RDP / WinRM)" 'Header'
    Write-ColorOutput "==========================================" 'Header'

    # RDP enabled?
    try {
        $rdpEnabled = (Get-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
            -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdpEnabled -eq 0) {
            # RDP is on -- check NLA
            $nla = (Get-ItemProperty `
                -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'UserAuthenticationRequired' -ErrorAction SilentlyContinue).UserAuthenticationRequired
            if ($nla -eq 1) {
                Add-Finding 'RemoteAccess' 'RDP Network Level Authentication' 'Enabled' 'Good' `
                    'NLA requires authentication before a full remote session is established'
            } else {
                Add-Finding 'RemoteAccess' 'RDP Network Level Authentication' 'Disabled' 'High' `
                    'Without NLA the login screen is exposed to unauthenticated attackers' `
                    'Enable NLA: System Properties > Remote > "Allow connections only from computers running Remote Desktop with NLA"'
            }

            # RDP port
            $rdpPort = (Get-ItemProperty `
                -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'PortNumber' -ErrorAction SilentlyContinue).PortNumber
            if ($rdpPort -and $rdpPort -ne 3389) {
                Add-Finding 'RemoteAccess' 'RDP Port' "$rdpPort (non-default)" 'Good' `
                    'Using a non-default port reduces automated scan hits'
            } elseif ($rdpPort) {
                Add-Finding 'RemoteAccess' 'RDP Port' '3389 (default)' 'Low' `
                    'Default RDP port is targeted by automated internet scanners' `
                    'Consider changing to a high, non-standard port and restricting via firewall'
            }
        } else {
            Add-Finding 'RemoteAccess' 'RDP' 'Disabled' 'Good' `
                'Remote Desktop is turned off -- no RDP attack surface'
        }
    } catch {
        Add-Finding 'RemoteAccess' 'RDP' 'Check Failed' 'Medium' `
            "Could not determine RDP status: $($_.Exception.Message)"
    }

    # Remote Assistance
    try {
        $ra = (Get-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
            -Name 'fAllowToGetHelp' -ErrorAction SilentlyContinue).fAllowToGetHelp
        if ($ra -eq 1) {
            Add-Finding 'RemoteAccess' 'Remote Assistance' 'Enabled' 'Medium' `
                'Remote Assistance allows others to connect to your session when invited' `
                'Disable if not needed: System Properties > Remote > uncheck "Allow Remote Assistance"'
        } else {
            Add-Finding 'RemoteAccess' 'Remote Assistance' 'Disabled' 'Good' `
                'Remote Assistance connections are not allowed'
        }
    } catch { }

    # WinRM (PowerShell Remoting)
    try {
        $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
        if ($winrm -and $winrm.Status -eq 'Running') {
            $winrmListeners = & winrm enumerate winrm/config/listener 2>&1
            $listenerCount  = ([regex]::Matches($winrmListeners, 'Listener')).Count
            Add-Finding 'RemoteAccess' 'WinRM (PowerShell Remoting)' "Running ($listenerCount listener(s))" 'Medium' `
                'WinRM enables remote PowerShell execution -- restrict to trusted hosts if needed' `
                'Restrict: winrm set winrm/config/client @{TrustedHosts="192.168.1.*"}'
        } elseif ($winrm) {
            Add-Finding 'RemoteAccess' 'WinRM (PowerShell Remoting)' 'Stopped' 'Good' `
                'PowerShell Remoting service is not running'
        }
    } catch { }
}

function Get-WSLSecurity {
    Write-ColorOutput "`n19. WINDOWS SUBSYSTEM FOR LINUX (WSL)" 'Header'
    Write-ColorOutput "=======================================" 'Header'

    try {
        $wslFeature = Get-WindowsOptionalFeature -Online `
            -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
        $vmpFeature = Get-WindowsOptionalFeature -Online `
            -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue

        if ($wslFeature -and $wslFeature.State -eq 'Enabled') {
            $wslVer = if ($vmpFeature -and $vmpFeature.State -eq 'Enabled') { '2' } else { '1' }
            Add-Finding 'WSL' 'WSL Version' "WSL$wslVer installed" 'Low' `
                'WSL creates a Linux environment inside Windows -- it expands the attack surface' `
                'Remove if not needed: wsl --unregister <distro>'

            # List installed distributions
            try {
                $distros = & wsl --list --quiet 2>&1 | Where-Object { $_ -and $_.Trim() -ne '' }
                if ($distros) {
                    $distroList = ($distros | ForEach-Object { $_.Trim() }) -join ', '
                    Add-Finding 'WSL' 'Installed Distributions' $distroList 'Info' `
                        'Each installed distribution is a separate Linux environment'
                }
            } catch { }

            # WSL2 network mode (mirrored = more exposure)
            if ($wslVer -eq '2') {
                try {
                    $wslConfigPath = Join-Path $env:USERPROFILE '.wslconfig'
                    if (Test-Path $wslConfigPath) {
                        $wslConfig = Get-Content $wslConfigPath -Raw -ErrorAction SilentlyContinue
                        if ($wslConfig -match 'networkingMode\s*=\s*mirrored') {
                            Add-Finding 'WSL' 'WSL2 Network Mode' 'Mirrored' 'Medium' `
                                'Mirrored mode exposes WSL directly on the host network interfaces'
                        } else {
                            Add-Finding 'WSL' 'WSL2 Network Mode' 'NAT (default)' 'Good' `
                                'WSL2 is behind NAT -- not directly accessible from the network'
                        }
                    } else {
                        Add-Finding 'WSL' 'WSL2 Network Mode' 'NAT (default, no .wslconfig)' 'Good' `
                            'WSL2 uses NAT by default'
                    }
                } catch { }
            }
        } else {
            Add-Finding 'WSL' 'WSL' 'Not installed' 'Good' `
                'Windows Subsystem for Linux is not present'
        }
    } catch {
        Add-Finding 'WSL' 'Analysis' 'Failed' 'Low' `
            "Could not check WSL status: $($_.Exception.Message)"
    }
}

function Get-ApplicationSecurity {
    Write-ColorOutput "`n20. APPLICATION SECURITY (BROWSERS / EDGE / JAVA)" 'Header'
    Write-ColorOutput "===================================================" 'Header'

    # Microsoft Edge SmartScreen
    try {
        $edgeSS = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' `
            -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue).SmartScreenEnabled
        if ($edgeSS -eq 0) {
            Add-Finding 'Application' 'Edge SmartScreen' 'Disabled by policy' 'High' `
                'SmartScreen is off -- Edge will not warn about malicious sites or downloads' `
                'Enable: Edge Settings > Privacy, search, and services > Microsoft Defender SmartScreen'
        } elseif ($null -ne $edgeSS) {
            Add-Finding 'Application' 'Edge SmartScreen' 'Enabled by policy' 'Good' `
                'SmartScreen is enforced via policy'
        } else {
            # Check user-level setting
            Add-Finding 'Application' 'Edge SmartScreen' 'Controlled by user setting' 'Low' `
                'No policy override -- verify SmartScreen is on in Edge settings'
        }
    } catch { }

    # Edge Enhanced Security Mode
    try {
        $edgeESM = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' `
            -Name 'EnhancedSecurityModeEnabled' -ErrorAction SilentlyContinue).EnhancedSecurityModeEnabled
        if ($edgeESM -eq 1) {
            Add-Finding 'Application' 'Edge Enhanced Security Mode' 'Enabled' 'Good' `
                'Enhanced Security Mode disables JIT compilation to reduce exploit risk'
        } else {
            Add-Finding 'Application' 'Edge Enhanced Security Mode' 'Not enforced' 'Low' `
                'Enhanced Security Mode provides extra browser exploit protection' `
                'Enable: Edge Settings > Privacy, search, and services > Enhance your security on the web'
        }
    } catch { }

    # Adobe Reader / Acrobat version (common attack vector)
    try {
        $adobePaths = @(
            'HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer',
            'HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
        )
        $adobeFound = $false
        foreach ($path in $adobePaths) {
            $adobeKey = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($adobeKey) {
                $adobeFound = $true
                $adobeVer  = $adobeKey.ProductVersion
                $installDate = $adobeKey.PSObject.Properties['InstallDate']
                Add-Finding 'Application' 'Adobe Acrobat Reader' "Installed (v$adobeVer)" 'Low' `
                    'Adobe Reader is a frequent exploit target -- keep it updated' `
                    'Update via: Help > Check for Updates'
                break
            }
        }
        if (-not $adobeFound) {
            Add-Finding 'Application' 'Adobe Acrobat Reader' 'Not installed' 'Good' `
                'Adobe Reader not found -- one less high-value attack target'
        }
    } catch { }

    # Java Runtime (common vulnerability)
    try {
        $javaKey = Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment' `
            -ErrorAction SilentlyContinue
        if (-not $javaKey) {
            $javaKey = Get-ItemProperty `
                -Path 'HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Runtime Environment' `
                -ErrorAction SilentlyContinue
        }
        if ($javaKey -and $javaKey.CurrentVersion) {
            Add-Finding 'Application' 'Java Runtime Environment' "Installed (v$($javaKey.CurrentVersion))" 'Medium' `
                'Java is a frequent attack vector -- remove if not actively needed' `
                'Uninstall via: Settings > Apps, or keep fully updated via java.com'
        } else {
            Add-Finding 'Application' 'Java Runtime Environment' 'Not installed' 'Good' `
                'Java not found -- reduces web-based exploit exposure'
        }
    } catch { }

    # Installed browser detection (version reporting only)
    try {
        $chromePath = 'HKLM:\SOFTWARE\Google\Chrome\BLBeacon'
        $chromeVer  = (Get-ItemProperty -Path $chromePath -Name 'version' -ErrorAction SilentlyContinue).version
        if ($chromeVer) {
            Add-Finding 'Application' 'Google Chrome' "Installed (v$chromeVer)" 'Info' `
                'Ensure Chrome is set to update automatically'
        }
    } catch { }

    try {
        $ffPath = 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox'
        $ffVer  = (Get-ItemProperty -Path $ffPath -Name 'CurrentVersion' -ErrorAction SilentlyContinue).CurrentVersion
        if (-not $ffVer) {
            $ffVer = (Get-ItemProperty `
                -Path 'HKLM:\SOFTWARE\Wow6432Node\Mozilla\Mozilla Firefox' `
                -Name 'CurrentVersion' -ErrorAction SilentlyContinue).CurrentVersion
        }
        if ($ffVer) {
            Add-Finding 'Application' 'Mozilla Firefox' "Installed (v$ffVer)" 'Info' `
                'Ensure Firefox is set to update automatically'
        }
    } catch { }
}

function Get-AuthenticationSecurity {
    Write-ColorOutput "`n21. AUTHENTICATION AND ACCOUNT POLICY" 'Header'
    Write-ColorOutput "=======================================" 'Header'

    # Autologon (serious security risk)
    try {
        $autoLogon = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
            -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue).AutoAdminLogon
        if ($autoLogon -eq '1') {
            Add-Finding 'Authentication' 'Autologon' 'ENABLED' 'Critical' `
                'Windows is configured to log in automatically -- anyone with physical access has full access' `
                'Disable: run netplwiz, check "Users must enter a user name and password"'
        } else {
            Add-Finding 'Authentication' 'Autologon' 'Disabled' 'Good' `
                'Automatic logon is off -- login credentials are required at startup'
        }
    } catch { }

    # Cached logon credentials count
    try {
        $cachedVal = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
            -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue).CachedLogonsCount
        $cachedInt = if ($cachedVal) { [int]$cachedVal } else { 10 }
        if ($cachedInt -eq 0) {
            Add-Finding 'Authentication' 'Cached Domain Credentials' 'Disabled (0)' 'Good' `
                'No domain credentials are cached locally'
        } elseif ($cachedInt -gt 5) {
            Add-Finding 'Authentication' 'Cached Domain Credentials' "$cachedInt credentials cached" 'Medium' `
                'Cached credentials can be extracted if the device is compromised' `
                'Reduce to 1-2: HKLM:\...\Winlogon CachedLogonsCount'
        } else {
            Add-Finding 'Authentication' 'Cached Domain Credentials' "$cachedInt credential(s) cached" 'Low' `
                'A small number of cached domain credentials is acceptable'
        }
    } catch { }

    # Account lockout policy via net accounts
    try {
        $netOut = (& net accounts 2>&1) -join "`n"

        if ($netOut -match 'Lockout threshold:\s+(\S+)') {
            $threshold = $Matches[1].Trim()
            if ($threshold -eq 'Never') {
                Add-Finding 'Authentication' 'Account Lockout Threshold' 'Never (disabled)' 'High' `
                    'Accounts are never locked -- brute-force password attacks are unrestricted' `
                    'Set via: Local Security Policy > Account Policies > Account Lockout Policy'
            } elseif ([int]$threshold -le 5) {
                Add-Finding 'Authentication' 'Account Lockout Threshold' "$threshold attempts" 'Good' `
                    'Accounts lock after a small number of failed attempts'
            } else {
                Add-Finding 'Authentication' 'Account Lockout Threshold' "$threshold attempts" 'Medium' `
                    'Consider reducing lockout threshold to 5 or fewer attempts'
            }
        }

        if ($netOut -match 'Minimum password length:\s+(\d+)') {
            $minLen = [int]$Matches[1].Trim()
            if ($minLen -ge 12) {
                Add-Finding 'Authentication' 'Minimum Password Length' "$minLen characters" 'Good' `
                    'Password length policy enforces strong passwords'
            } elseif ($minLen -ge 8) {
                Add-Finding 'Authentication' 'Minimum Password Length' "$minLen characters" 'Low' `
                    'Consider requiring at least 12 characters for stronger passwords'
            } else {
                Add-Finding 'Authentication' 'Minimum Password Length' "$minLen characters" 'Medium' `
                    'Short passwords are vulnerable to brute-force attacks' `
                    'Increase minimum length to at least 12 characters'
            }
        }

        if ($netOut -match 'Maximum password age \(days\):\s+(\S+)') {
            $maxAge = $Matches[1].Trim()
            if ($maxAge -eq 'Unlimited') {
                Add-Finding 'Authentication' 'Password Expiry' 'Never expires' 'Low' `
                    'Passwords never expire -- consider periodic rotation or use of long passphrases'
            } else {
                $maxAgeInt = [int]$maxAge
                $risk = if ($maxAgeInt -le 90) { 'Good' } elseif ($maxAgeInt -le 180) { 'Low' } else { 'Medium' }
                Add-Finding 'Authentication' 'Password Expiry' "Every $maxAgeInt days" $risk `
                    'Password rotation policy'
            }
        }
    } catch {
        Add-Finding 'Authentication' 'Account Policy' 'Check Failed' 'Medium' `
            "Could not read account policy: $($_.Exception.Message)"
    }
}

function Show-Summary {
    Write-Progress -Activity "Windows Attack Surface Analyzer" -Completed

    Write-ColorOutput "`n" 'Info'
    Write-ColorOutput "================================================" 'Header'
    Write-ColorOutput "           SECURITY ANALYSIS SUMMARY           " 'Header'
    Write-ColorOutput "================================================" 'Header'

    $criticalCount = ($SecurityFindings | Where-Object { $_.Risk -eq 'Critical' }).Count
    $highCount     = ($SecurityFindings | Where-Object { $_.Risk -eq 'High'     }).Count
    $mediumCount   = ($SecurityFindings | Where-Object { $_.Risk -eq 'Medium'   }).Count
    $lowCount      = ($SecurityFindings | Where-Object { $_.Risk -eq 'Low'      }).Count
    $goodCount     = ($SecurityFindings | Where-Object { $_.Risk -eq 'Good'     }).Count

    # Simple risk score: start at 100, deduct per issue
    $riskScore = 100 - ($criticalCount * 15) - ($highCount * 8) - ($mediumCount * 3) - ($lowCount * 1)
    $riskScore = [Math]::Max(0, $riskScore)
    $scoreLabel = if ($riskScore -ge 80) { 'Good' } `
                  elseif ($riskScore -ge 60) { 'Medium' } `
                  elseif ($riskScore -ge 40) { 'High' } `
                  else { 'Critical' }

    Write-ColorOutput "System: $script:OSCaption (Build $script:WinBuild)" 'Info'
    Write-ColorOutput "Total Findings: $($SecurityFindings.Count)" 'Info'
    Write-ColorOutput "" 'Info'
    if ($criticalCount -gt 0) { Write-ColorOutput "  Critical Issues : $criticalCount" 'Critical' }
    if ($highCount     -gt 0) { Write-ColorOutput "  High Risk Issues: $highCount"     'High'     }
    if ($mediumCount   -gt 0) { Write-ColorOutput "  Medium Issues   : $mediumCount"   'Medium'   }
    if ($lowCount      -gt 0) { Write-ColorOutput "  Low Issues      : $lowCount"      'Low'      }
    if ($goodCount     -gt 0) { Write-ColorOutput "  Good Settings   : $goodCount"     'Good'     }
    Write-ColorOutput "" 'Info'
    Write-ColorOutput "  Security Score  : $riskScore / 100" $scoreLabel

    Write-ColorOutput "`nWHAT TO DO NEXT:" 'Header'
    if ($criticalCount -gt 0) {
        Write-ColorOutput "  [!!] Fix CRITICAL issues RIGHT NOW - your system is at serious risk!" 'Critical'
    }
    if ($highCount -gt 0) {
        Write-ColorOutput "  [!]  Fix HIGH risk issues today or tomorrow." 'High'
    }
    if ($mediumCount -gt 0) {
        Write-ColorOutput "  [~]  Plan to address MEDIUM issues within 30 days." 'Medium'
    }
    if ($criticalCount -eq 0 -and $highCount -eq 0 -and $mediumCount -eq 0) {
        Write-ColorOutput "  Great job! No critical, high, or medium issues found." 'Good'
    }
    Write-ColorOutput "  Run this scan monthly to stay on top of your security." 'Info'

    if ($Export) {
        Write-ColorOutput "`n  Full report: $OutputPath" 'Good'
    } else {
        Write-ColorOutput "`n  Tip: Double-click Run-Analysis.bat for a full HTML report." 'Info'
    }
}

# Main execution
function Main {
    $osLabel = if ($script:IsWindows11) { "Windows 11" } `
               elseif ($script:IsWindows10) { "Windows 10" } `
               else { $script:OSCaption }
    $psLabel = "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

    Write-ColorOutput @"
================================================
       Windows Attack Surface Analyzer
       Comprehensive Security Assessment Tool

  Author : NubleX / Igor Dunaev
  Version: 0.3.0
  System : $osLabel (Build $script:WinBuild, $script:OSArch)
  Engine : $psLabel
================================================
"@ 'Header'

    # Check admin rights
    if (-not (Test-AdminRights)) {
        Write-ColorOutput "`n  [WARNING] Not running as Administrator." 'Medium'
        Write-ColorOutput "  Some checks (BitLocker, TPM, user accounts) will be limited." 'Medium'
        Write-ColorOutput "  For a complete scan, right-click PowerShell and choose 'Run as administrator'." 'Info'
        Write-ColorOutput "  Or double-click Run-Analysis.bat which handles this automatically.`n" 'Info'
    } else {
        Write-ColorOutput "`n  [OK] Running as Administrator - full scan enabled.`n" 'Good'
    }

    # ── Run all security checks (with progress bar) ───────────────────────────
    Write-ScanProgress "Network attack surface"
    Get-NetworkPorts

    Write-ScanProgress "Services security"
    Get-ServicesSecurity

    Write-ScanProgress "Windows Firewall"
    Get-FirewallStatus

    Write-ScanProgress "Network shares"
    Get-NetworkShares

    Write-ScanProgress "Windows optional features"
    Get-WindowsFeatures

    Write-ScanProgress "Startup programs"
    Get-StartupPrograms

    Write-ScanProgress "User account security"
    Get-UserSecurity

    Write-ScanProgress "System security settings"
    Get-SystemSecurity

    Write-ScanProgress "Hardware security (TPM / Secure Boot / VBS)"
    Get-HardwareSecurity

    Write-ScanProgress "Disk encryption (BitLocker)"
    Get-BitLockerStatus

    Write-ScanProgress "Advanced Defender analysis"
    Get-AdvancedDefender

    Write-ScanProgress "Windows 11 specific features"
    Get-Windows11Features

    Write-ScanProgress "PowerShell security"
    Get-PowerShellSecurity

    Write-ScanProgress "Defender ASR rules and scan status"
    Get-DefenderExtended

    Write-ScanProgress "Exploit protection (ASLR / SEHOP / CFG)"
    Get-ExploitProtection

    Write-ScanProgress "Privacy settings"
    Get-PrivacySettings

    Write-ScanProgress "Network security (IPv6 / DoH / Wi-Fi / Bluetooth)"
    Get-NetworkSecurity

    Write-ScanProgress "Remote access security (RDP / WinRM)"
    Get-RemoteAccessSecurity

    Write-ScanProgress "Windows Subsystem for Linux"
    Get-WSLSecurity

    Write-ScanProgress "Application security (browsers / Java)"
    Get-ApplicationSecurity

    Write-ScanProgress "Authentication and account policy"
    Get-AuthenticationSecurity

    # ── Export and summarise ──────────────────────────────────────────────────
    Export-Results
    Show-Summary

    Write-ColorOutput "`n  Analysis complete!" 'Good'
}

# Execute main function
Main
