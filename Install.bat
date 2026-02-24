@echo off
setlocal EnableDelayedExpansion

:: =============================================
::   SimpleAntiCheat Driver Install Script
::   Run As Admin
:: =============================================

set "INF_PATH=%~1"
set "DEVGEN_PATH=%~2"

if "%INF_PATH%"=="" (
    echo.
    echo   ERROR: No .inf file provided.
    echo.
    echo   Usage:
    echo     Run from command line:
    echo        %~nx0 "C:\Path\To\SimpleAntiCheat.inf" "C:\Path\To\devgen.exe"
    echo.
    pause
    exit /b 1
)

if not exist "%INF_PATH%" (
    echo.
    echo   ERROR: File not found
    echo   "%INF_PATH%"
    echo.
    pause
    exit /b 1
)

if "%DEVGEN_PATH%"=="" (
    echo.
    echo   ERROR: No path to devgen.exe provided.
    echo.
    echo   Usage:
    echo    Run from command line:
    echo        %~nx0 "C:\Path\To\SimpleAntiCheat.inf" "C:\Path\To\devgen.exe"
    echo.
    pause
    exit /b 1
)

if not exist "%DEVGEN_PATH%" (
    echo.
    echo   ERROR: File not found
    echo   "%DEVGEN_PATH%"
    echo.
    pause
    exit /b 1
)

:: Extract directory and filename for nicer messages
for %%F in ("%INF_PATH%") do (
    set "INF_DIR=%%~dpF"
    set "INF_NAME=%%~nxF"
)

echo.
echo   Installing driver from:
echo     %INF_PATH%
echo.

:: =============================================
::   Step 1: Check if test signing is already enabled
:: =============================================
bcdedit /enum | find "testsigning             Yes" >nul
if %errorlevel% equ 0 (
    echo Test signing is already enabled. Skipping bcdedit step...
    goto :install_driver
)

:: =============================================
::   Step 2: Enable test signing
:: =============================================
echo Enabling test signing...
bcdedit /set testsigning on >nul 2>&1

if %errorlevel% neq 0 (
    echo.
    echo   ERROR: Failed to enable test signing.
    echo.
    echo   Most common cause: Secure Boot is still enabled
    echo   Other causes: Memory Integrity (HVCI), Credential Guard, or admin rights issue.
    echo.
    echo   Try these steps:
    echo     1. Boot into BIOS/UEFI and confirm Secure Boot is DISABLED
    echo     2. Disable Memory Integrity in Windows Security → Device Security → Core isolation
    echo     3. Run this script again after reboot
    echo.
    echo   If it still fails, boot into Safe Mode and try the command there.
    pause
    exit /b 1
)

echo.
echo Test signing enabled successfully!
echo   → You MUST reboot for this change to take effect.
echo   → After reboot, you'll see "Test Mode" in the bottom-right corner of the desktop.
echo.

:install_driver
echo Adding and installing driver...
:: =============================================
::   Create device
:: =============================================

"%DEVGEN_PATH%" /add /bus ROOT /hardwareid Root\SimpleAntiCheat

if errorlevel 1 (
    echo.
    echo ERROR: devgen failed. Check output above.
    pause
    exit /b 1
)

:: =============================================
::   Install via pnputil
:: =============================================

pnputil /add-driver "%INF_PATH%" /install

if errorlevel 1 (
    echo.
    echo ERROR: pnputil failed. Check output above.
    pause
    exit /b 1
)

echo.
echo Installation finished.
echo.
echo Quick checks:
echo   sc query SimpleAntiCheat
echo   Get-Service SimpleAntiCheat    (in PowerShell)
echo.
pause