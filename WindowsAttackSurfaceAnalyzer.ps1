# Windows Attack Surface Analyzer
# A comprehensive security assessment tool for Windows systems
# Created by NubleX / Igor Dunaev, 2025
# 
# Authors: Security Community
# Version: 0.1.0
# License: MIT
# GitHub: https://github.com/NubleX/Windows-Attack-Surface-Analyzer
#
# USAGE: Run as Administrator in PowerShell
# .\WindowsAttackSurfaceAnalyzer.ps1
#
# DESCRIPTION:
# This script analyzes your Windows system for potential security vulnerabilities
# and provides recommendations for hardening your attack surface.

param(
    [switch]$Detailed,  # Show detailed output
    [switch]$Export,    # Export results to file
    [string]$OutputPath = ".\SecurityReport.html"
)

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
    
    # Check for unusual running services
    $runningServices = Get-Service | Where-Object {$_.Status -eq 'Running'}
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
        Write-ColorOutput "Report exported successfully to: $OutputPath" 'Good'
    } catch {
        Write-ColorOutput "Failed to export report: $($_.Exception.Message)" 'Critical'
    }
}

function Show-Summary {
    Write-ColorOutput "`n" 'Info'
    Write-ColorOutput "================================" 'Header'
    Write-ColorOutput "  SECURITY ANALYSIS SUMMARY" 'Header'
    Write-ColorOutput "================================" 'Header'
    
    $criticalCount = ($SecurityFindings | Where-Object {$_.Risk -eq 'Critical'}).Count
    $highCount = ($SecurityFindings | Where-Object {$_.Risk -eq 'High'}).Count
    $mediumCount = ($SecurityFindings | Where-Object {$_.Risk -eq 'Medium'}).Count
    $lowCount = ($SecurityFindings | Where-Object {$_.Risk -eq 'Low'}).Count
    $goodCount = ($SecurityFindings | Where-Object {$_.Risk -eq 'Good'}).Count
    
    Write-ColorOutput "Total Findings: $($SecurityFindings.Count)" 'Info'
    if ($criticalCount -gt 0) { Write-ColorOutput "Critical Issues: $criticalCount" 'Critical' }
    if ($highCount -gt 0) { Write-ColorOutput "High Risk Issues: $highCount" 'High' }
    if ($mediumCount -gt 0) { Write-ColorOutput "Medium Risk Issues: $mediumCount" 'Medium' }
    if ($lowCount -gt 0) { Write-ColorOutput "Low Risk Issues: $lowCount" 'Low' }
    if ($goodCount -gt 0) { Write-ColorOutput "Good Security Settings: $goodCount" 'Good' }
    
    Write-ColorOutput "`nRECOMMENDATIONS:" 'Header'
    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        Write-ColorOutput "Address critical and high-risk issues immediately!" 'Critical'
    }
    if ($mediumCount -gt 0) {
        Write-ColorOutput "Plan to address medium-risk issues within 30 days" 'Medium'
    }
    Write-ColorOutput "Run this analysis monthly to monitor your security posture" 'Info'
    
    if ($Export) {
        Write-ColorOutput "Detailed HTML report available at: $OutputPath" 'Info'
    } else {
        Write-ColorOutput "Use -Export flag to generate a detailed HTML report" 'Info'
    }
}

# Main execution
function Main {
    Write-ColorOutput @"
╔══════════════════════════════════════════╗
║       Windows Attack Surface Analyzer    ║
║                                          ║
║  Comprehensive Security Assessment Tool  ║
║                                          ║
║  Author: NubleX / Igor Dunaev            ║
║  Version: 0.1.0                          ║
╚══════════════════════════════════════════╝
"@ 'Header'
    
    Write-ColorOutput "`nStarting security analysis..." 'Info'
    
    # Check admin rights
    if (-not (Test-AdminRights)) {
        Write-ColorOutput "Warning: Running without administrator privileges. Some checks may be limited." 'Medium'
        Write-ColorOutput "For complete analysis, run as Administrator." 'Info'
    }
    
    # Run all security checks
    Get-NetworkPorts
    Get-ServicesSecurity  
    Get-FirewallStatus
    Get-NetworkShares
    Get-WindowsFeatures
    Get-StartupPrograms
    Get-UserSecurity
    Get-SystemSecurity
    
    # Export results if requested
    Export-Results
    
    # Show summary
    Show-Summary
    
    Write-ColorOutput "Analysis complete!" 'Good'
}

# Execute main function
Main