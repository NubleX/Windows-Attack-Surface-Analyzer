@echo off
setlocal enabledelayedexpansion
title Windows Attack Surface Analyzer
color 0A

echo.
echo  ============================================
echo        Windows Attack Surface Analyzer
echo        Security Assessment Tool v0.2.0
echo  ============================================
echo.

:: ── Step 1: Ensure Administrator privileges ──────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Administrator privileges are required for a complete scan.
    echo  [!] Requesting elevated permissions now...
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs -Wait"
    exit /b
)

echo  [OK] Running as Administrator
echo.

:: ── Step 2: Locate the PowerShell script ─────────────────────────────────────
set "SCRIPT=%~dp0WindowsAttackSurfaceAnalyzer.ps1"

if not exist "%SCRIPT%" (
    echo  [ERROR] Cannot find WindowsAttackSurfaceAnalyzer.ps1
    echo          Make sure this .bat file is in the same folder as the script.
    echo.
    pause
    exit /b 1
)

:: ── Step 3: Set default report output path ───────────────────────────────────
set "REPORT=%~dp0SecurityReport.html"

:: ── Step 4: Pick the best available PowerShell version ───────────────────────
where pwsh >nul 2>&1
if %errorlevel% == 0 (
    echo  [*] PowerShell 7 detected - using pwsh
    echo.
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Export -OutputPath "%REPORT%"
) else (
    echo  [*] Using Windows PowerShell 5.1
    echo.
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Export -OutputPath "%REPORT%"
)

:: ── Step 5: Open the HTML report if it was created ───────────────────────────
echo.
if exist "%REPORT%" (
    echo  [OK] Report saved to: %REPORT%
    echo  [*]  Opening report in your browser...
    start "" "%REPORT%"
) else (
    echo  [!] Report file was not created. Check for errors above.
)

echo.
echo  ============================================
echo   Scan complete! Review your report above.
echo   Press any key to close this window.
echo  ============================================
echo.
pause >nul
