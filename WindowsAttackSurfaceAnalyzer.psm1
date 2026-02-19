# WindowsAttackSurfaceAnalyzer.psm1
# PowerShell module wrapper for Windows Attack Surface Analyzer
# This file exposes the analyzer as a proper importable module function
# for PowerShell Gallery distribution.
#
# Author  : Igor Dunaev / NubleX
# License : MIT
# GitHub  : https://github.com/NubleX/Windows-Attack-Surface-Analyzer

#region Module Internals

$script:ModuleRoot = $PSScriptRoot

function Get-ModuleScriptPath {
    Join-Path $script:ModuleRoot 'WindowsAttackSurfaceAnalyzer.ps1'
}

#endregion

#region Public Functions

function Invoke-WindowsAttackSurfaceAnalyzer {
    <#
    .SYNOPSIS
    Runs a comprehensive Windows security posture analysis.

    .DESCRIPTION
    Invokes the Windows Attack Surface Analyzer, performing security checks
    across 23 categories including hardware security, Defender configuration,
    network exposure, PowerShell hardening, privacy settings, and more.

    Works on Windows 10 and all versions of Windows 11.
    Requires Administrator privileges for a complete scan.

    .PARAMETER Detailed
    Show verbose descriptions for each finding in the console output.

    .PARAMETER Export
    Generate an HTML report. Automatically opens in the default browser.

    .PARAMETER OutputPath
    Path for the HTML report. Defaults to .\SecurityReport.html

    .PARAMETER ExportJson
    Generate a JSON report suitable for SIEM ingestion or automation.

    .PARAMETER JsonPath
    Path for the JSON report. Defaults to .\SecurityReport.json

    .PARAMETER ExportCsv
    Generate a CSV report suitable for spreadsheet analysis.

    .PARAMETER CsvPath
    Path for the CSV report. Defaults to .\SecurityReport.csv

    .EXAMPLE
    Invoke-WindowsAttackSurfaceAnalyzer

    Runs the full scan with console output only.

    .EXAMPLE
    Invoke-WindowsAttackSurfaceAnalyzer -Export

    Runs the full scan and opens an HTML report in your browser.

    .EXAMPLE
    Invoke-WindowsAttackSurfaceAnalyzer -Detailed -Export -OutputPath "C:\Reports\scan.html"

    Runs a verbose scan and saves the HTML report to a custom path.

    .EXAMPLE
    Invoke-WindowsAttackSurfaceAnalyzer -ExportJson -JsonPath "C:\SIEM\scan.json"

    Runs the scan and exports JSON for SIEM or automation pipelines.

    .EXAMPLE
    Invoke-WindowsAttackSurfaceAnalyzer -Export -ExportJson -ExportCsv

    Generates all three report formats in one scan.

    .LINK
    https://github.com/NubleX/Windows-Attack-Surface-Analyzer

    .NOTES
    Run as Administrator for complete results. Without elevation, checks for
    BitLocker, TPM, and some user account details will be limited.
    #>
    [CmdletBinding()]
    [Alias('Invoke-WASA')]
    param(
        [switch]$Detailed,
        [switch]$Export,
        [string]$OutputPath  = '.\SecurityReport.html',
        [switch]$ExportJson,
        [string]$JsonPath    = '.\SecurityReport.json',
        [switch]$ExportCsv,
        [string]$CsvPath     = '.\SecurityReport.csv'
    )

    $scriptPath = Get-ModuleScriptPath

    if (-not (Test-Path $scriptPath)) {
        throw "Cannot find WindowsAttackSurfaceAnalyzer.ps1 in the module directory: $script:ModuleRoot"
    }

    # Build argument list dynamically
    $args = @{}
    if ($Detailed)    { $args['Detailed']    = $true }
    if ($Export)      { $args['Export']      = $true; $args['OutputPath'] = $OutputPath }
    if ($ExportJson)  { $args['ExportJson']  = $true; $args['JsonPath']   = $JsonPath }
    if ($ExportCsv)   { $args['ExportCsv']   = $true; $args['CsvPath']    = $CsvPath }

    & $scriptPath @args
}

#endregion

Export-ModuleMember -Function 'Invoke-WindowsAttackSurfaceAnalyzer' -Alias 'Invoke-WASA'
