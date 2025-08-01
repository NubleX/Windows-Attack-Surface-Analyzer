# Contributing to Windows Attack Surface Analyzer

Thank you for your interest in contributing to the Windows Attack Surface Analyzer! This project thrives on community contributions from cybersecurity professionals, developers, and security enthusiasts.

## Project Vision

Our goal is to create the most comprehensive, user-friendly, and accurate Windows security assessment tool available as open source. We want to make enterprise-level security analysis accessible to everyone.

## How to Contribute

### Types of Contributions We Welcome

#### Security Checks & Detection
- New vulnerability detection methods
- Additional Windows feature assessments
- Network security analysis improvements
- Registry-based security checks
- WMI/CIM security queries

#### User Experience
- Improved output formatting
- Better risk assessment algorithms
- Enhanced HTML report templates
- Command-line interface improvements
- Error handling and user feedback

#### Documentation
- Security hardening guides
- Use case examples
- PowerShell best practices
- Troubleshooting documentation
- Translation to other languages

#### Bug Fixes & Improvements
- Performance optimizations
- Compatibility fixes
- Error handling improvements
- Code refactoring
- Testing coverage

## Getting Started

### Development Environment Setup

1. **Fork the Repository**
   ```bash
   # Clone your fork
   git clone https://github.com/NubleX/Windows-Attack-Surface-Analyzer.git
   cd Windows-Attack-Surface-Analyzer
   ```

2. **Set Up Development Environment**
   - Windows 10/11 or Windows Server 2016+
   - PowerShell 5.1+ (PowerShell 7+ recommended)
   - Visual Studio Code with PowerShell extension
   - Administrator privileges for testing

3. **Install Development Tools**
   ```powershell
   # Install PowerShell development modules
   Install-Module PSScriptAnalyzer -Force
   Install-Module Pester -Force
   Install-Module Microsoft.PowerShell.PlatyPS -Force
   ```

### Testing Your Changes

1. **Static Analysis**
   ```powershell
   # Run PSScriptAnalyzer
   Invoke-ScriptAnalyzer -Path .\WindowsAttackSurfaceAnalyzer.ps1 -Severity Warning,Error
   ```

2. **Functional Testing**
   ```powershell
   # Test basic functionality
   .\WindowsAttackSurfaceAnalyzer.ps1
   
   # Test with all parameters
   .\WindowsAttackSurfaceAnalyzer.ps1 -Detailed -Export -OutputPath ".\test-report.html"
   ```

3. **Cross-Platform Testing**
   - Test on Windows 10 and Windows 11
   - Test on Windows Server editions when possible
   - Test with different PowerShell versions
   - Test with and without administrator privileges

## Contribution Guidelines

### Code Standards

#### PowerShell Best Practices
- Use approved PowerShell verbs (`Get-`, `Set-`, `Test-`, etc.)
- Follow PascalCase for function names
- Use camelCase for variable names
- Include proper error handling with `try/catch/finally`
- Use parameter validation where appropriate
- Include comment-based help for functions

#### Example Function Template
```powershell
function Test-SecurityFeature {
    <#
    .SYNOPSIS
    Tests a specific Windows security feature
    
    .DESCRIPTION
    Detailed description of what this function checks and why it matters for security
    
    .PARAMETER FeatureName
    Name of the Windows feature to test
    
    .EXAMPLE
    Test-SecurityFeature -FeatureName "SMB1Protocol"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FeatureName
    )
    
    try {
        # Implementation here
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
        
        if ($feature.State -eq 'Enabled') {
            Add-Finding "Features" $FeatureName "Enabled" "High" "Security risk description" "Recommended action"
        } else {
            Add-Finding "Features" $FeatureName "Disabled" "Good" "Security benefit description"
        }
    }
    catch {
        Add-Finding "Features" $FeatureName "Error" "Medium" "Could not check feature: $($_.Exception.Message)"
    }
}
```

### Security Check Requirements

When adding new security checks, ensure they:

1. **Have Clear Risk Assessment**
   - Assign appropriate risk levels (Critical, High, Medium, Low, Good)
   - Provide clear descriptions of the security impact
   - Include remediation recommendations

2. **Handle Errors Gracefully**
   - Use proper error handling
   - Provide meaningful error messages
   - Don't break the entire script on individual check failures

3. **Include Proper Documentation**
   - Comment complex logic
   - Explain security implications
   - Reference security standards when applicable

4. **Are Non-Destructive**
   - Only perform read-only operations
   - Never modify system configuration
   - Warn if administrative privileges are needed but don't require them

### Risk Level Guidelines

| Risk Level | Criteria | Examples |
|------------|----------|----------|
| **Critical** | Immediate security threat, active exploitation possible | SMB1 enabled, Telnet server running, Firewall disabled |
| **High** | Significant vulnerability, high attack probability | Guest account enabled, UPnP exposed, Admin shares open |
| **Medium** | Moderate security concern, requires attention | SSH misconfigured, old passwords, excessive services |
| **Low** | Minor security issue, best practice improvement | Many startup programs, high port count, non-critical services |
| **Good** | Proper security configuration | Firewall enabled, features disabled, strong settings |

## Development Workflow

### 1. Create Feature Branch
```bash
git checkout -b feature/new-security-check
git checkout -b bugfix/error-handling-improvement
git checkout -b docs/usage-examples
```

### 2. Make Your Changes
- Follow the coding standards above
- Add appropriate tests
- Update documentation as needed
- Test thoroughly on multiple systems

### 3. Commit Your Changes
```bash
# Use conventional commit format
git commit -m "feat: add registry security checks"
git commit -m "fix: handle WMI query errors gracefully"
git commit -m "docs: add network security examples"
```

### 4. Submit Pull Request
- Provide clear description of changes
- Reference any related issues
- Include testing information
- Request specific reviewers if needed

## Testing Framework

### Unit Testing Example
```powershell
# Tests/SecurityChecks.Tests.ps1
Describe "Security Check Functions" {
    Context "Test-WindowsFeature" {
        It "Should detect enabled SMB1" {
            # Mock the Windows feature check
            Mock Get-WindowsOptionalFeature { 
                return @{ State = 'Enabled'; FeatureName = 'SMB1Protocol' }
            }
            
            # Test the function
            $result = Test-WindowsFeature -FeatureName 'SMB1Protocol'
            
            # Verify results
            $result.Risk | Should -Be 'Critical'
            $result.Status | Should -Be 'Enabled'
        }
    }
}
```

### Integration Testing
```powershell
# Test complete script execution
Describe "Full Script Integration" {
    It "Should run without errors" {
        { .\WindowsAttackSurfaceAnalyzer.ps1 } | Should -Not -Throw
    }
    
    It "Should generate findings" {
        $results = .\WindowsAttackSurfaceAnalyzer.ps1
        $results.Count | Should -BeGreaterThan 0
    }
}
```

## Pull Request Process

### Before Submitting

1. **Self-Review Checklist**
   - [ ] Code follows PowerShell best practices
   - [ ] All functions have proper error handling
   - [ ] Security checks have appropriate risk levels
   - [ ] Documentation is updated
   - [ ] Tests pass locally
   - [ ] No breaking changes without justification

2. **Testing Checklist**
   - [ ] Tested on Windows 10/11
   - [ ] Tested with and without admin privileges
   - [ ] PSScriptAnalyzer warnings addressed
   - [ ] Manual testing completed
   - [ ] Edge cases considered

### Pull Request Template

When submitting a PR, please include:

```markdown
## Description
Brief description of changes and motivation

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to change)
- [ ] Documentation update

## Security Impact
- [ ] Adds new security check
- [ ] Improves existing security detection
- [ ] Changes risk assessment
- [ ] No security impact

## Testing
- [ ] Tested on Windows 10
- [ ] Tested on Windows 11
- [ ] Tested with admin privileges
- [ ] Tested without admin privileges
- [ ] PSScriptAnalyzer passes
- [ ] Manual testing completed

## Screenshots (if applicable)
Include screenshots of new features or significant changes

## Additional Notes
Any additional information reviewers should know
```

### Review Process

1. **Automated Checks**
   - GitHub Actions will run PSScriptAnalyzer
   - Basic functionality tests will execute
   - Documentation generation will be verified

2. **Peer Review**
   - At least one maintainer review required
   - Security-focused changes require security team review
   - Community feedback welcomed on significant changes

3. **Merge Requirements**
   - All automated checks must pass
   - At least one approval from maintainer
   - No unresolved conversations
   - Branch must be up to date with main

## Learning Resources

### PowerShell Development
- [PowerShell Best Practices](https://github.com/PoshCode/PowerShellPracticeAndStyle)
- [Advanced PowerShell Scripting](https://docs.microsoft.com/en-us/powershell/scripting/learn/more-powershell-learning)
- [PowerShell Security](https://docs.microsoft.com/en-us/powershell/scripting/learn/security/overview)

### Windows Security
- [Windows Security Documentation](https://docs.microsoft.com/en-us/windows/security/)
- [Windows Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Cybersecurity Research
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVE Database](https://cve.mitre.org/)
- [Microsoft Security Response Center](https://msrc.microsoft.com/)

## Contribution Ideas

### High-Priority Features
- **Registry Security Analysis** - Check for dangerous registry modifications
- **Certificate Store Analysis** - Verify certificate security
- **Group Policy Assessment** - Analyze applied security policies
- **Event Log Security** - Check logging configurations
- **Credential Protection** - Assess credential security features

### Medium-Priority Features
- **USB Security** - Check USB/removable device policies
- **BitLocker Analysis** - Verify disk encryption status
- **AppLocker Assessment** - Check application control policies
- **Windows Store Security** - Analyze store app permissions
- **Hyper-V Security** - Check virtualization security

### Enhancement Ideas
- **JSON Export** - Add JSON output format for automation
- **Compliance Mapping** - Map findings to compliance frameworks
- **Baseline Comparison** - Compare against security baselines
- **Remediation Scripts** - Generate automated fix scripts
- **Custom Rules** - Allow user-defined security checks

## Security Considerations

### Responsible Development
- Never include actual exploits or attack code
- Focus on detection and assessment, not exploitation
- Ensure all checks are read-only and safe
- Document any system requirements clearly

### Sensitive Information
- Avoid logging sensitive system information
- Don't expose credentials or personal data
- Be careful with system configuration details
- Follow data privacy best practices

### Code Security
- Validate all user inputs
- Use parameterized queries for WMI/CIM
- Avoid code injection vulnerabilities
- Handle exceptions securely

## Recognition

### Hall of Fame
We maintain a [CONTRIBUTORS.md](CONTRIBUTORS.md) file recognizing all contributors:
- **Core Maintainers** - Long-term project stewardship
- **Security Researchers** - Significant security improvements
- **Feature Contributors** - Major feature additions
- **Bug Hunters** - Critical bug fixes and improvements
- **Documentation Heroes** - Substantial documentation contributions

### Contribution Statistics
- GitHub automatically tracks contributions
- Annual "Contributor of the Year" recognition
- Featured contributions in release notes
- Conference presentation opportunities for major contributions

## Getting Help

### Communication Channels
- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - General questions and ideas
- **Security Email** - nublexer@hotmail.com for security issues

### Office Hours
Monthly virtual office hours for:
- Project direction discussions
- Technical questions
- Contribution planning
- Community building

## License and Legal

### Contribution License Agreement
By contributing, you agree that:
- Your contributions will be licensed under the MIT License
- You have the right to contribute the code/content
- Your contributions are your original work
- You understand the project's open-source nature

### Intellectual Property
- All contributions become part of the open-source project
- Contributors retain copyright to their contributions
- The project maintains the right to use, modify, and distribute contributions
- Commercial use is permitted under the MIT License

---

## Thank You!

Every contribution, no matter how small, makes this project better and helps improve Windows security for everyone. Whether you're fixing a typo, adding a new security check, or helping with documentation, your efforts are greatly appreciated.

**Together, we're making cybersecurity more accessible and Windows systems more secure!**

---

*For additional questions or guidance, don't hesitate to reach out through any of our communication channels. We're here to help and excited to work with you!*
