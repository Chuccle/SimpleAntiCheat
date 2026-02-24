# SimpleAntiCheat - Quick Start Guide

## Prerequisites

### Required Software
- **Visual Studio 2019 or later** with "Desktop development with C++" workload
- **Windows 10/11 (x64 or ARM64)**
- **Administrator privileges**

### Automatic Setup (Recommended)
The solution automatically installs required dependencies via NuGet:
- ✅ **WDK (x64)** - Contains `devgen.exe` for x64 systems
- ✅ **WDK (ARM64)** - Contains `devgen.exe` for ARM64 systems

No manual WDK installation required!

## Build Instructions

### 1. Open Solution

### 2. Select Configuration
- **Configuration**: `Release` (or `Debug` for development)
- **Platform**: `x64` (or `ARM64` for Windows on ARM)

### 3. Build
- Press `Ctrl+Shift+B` or `Build → Build Solution`
- Build output will be in `x64\Release\` or `ARM64\Release\`

**Expected Output**:
```
Build succeeded.
    SimpleAntiCheat.sys - Driver binary
    SimpleAntiCheat.inf - Installation manifest
    SimpleAntiCheat.pdb - Debug symbols (Debug build only)
```

## Installation

### Prerequisites Check

#### Disable Secure Boot (Required)
```
⚠️ Test-signed drivers cannot load with Secure Boot enabled
```

**How to disable**:
1. Restart → Enter BIOS/UEFI (usually `Del`, `F2`, or `F12` during boot)
2. Navigate to **Security** or **Boot** settings
3. Set **Secure Boot** to **Disabled**
4. Save and exit

### Automated Installation

#### Method 1: Using Install.bat (Recommended)

The solution includes `Install.bat` which handles:
- Test signing enablement
- Device creation via `devgen.exe`
- Driver installation via `pnputil`

**Usage**:
```batch
# Navigate to build output directory
cd x64\Release

# Run install script (as Administrator)
Install.bat "C:\Path\To\SimpleAntiCheat.inf" "C:\Path\To\packages\Microsoft.Windows.WDK.x64.10.0.xxxxx\tools\x64\devgen.exe"
```

**Example** (adjust paths to your build output):
```batch
cd C:\Projects\SimpleAntiCheat\x64\Release
Install.bat "%cd%\SimpleAntiCheat.inf" "..\..\packages\Microsoft.Windows.WDK.x64.10.0.26100.1742\tools\x64\devgen.exe"
```

**What it does**:
1. ✅ Checks if test signing is enabled
2. ✅ Enables test signing if needed (`bcdedit /set testsigning on`)
3. ✅ Creates root-enumerated device (`devgen /add /bus ROOT /hardwareid Root\SimpleAntiCheat`)
4. ✅ Installs driver (`pnputil /add-driver /install`)

**First-time installation**:
```
Test signing enabled successfully!
  → You MUST reboot for this change to take effect.
  → After reboot, you'll see "Test Mode" in the bottom-right corner of the desktop.
```
**Reboot, then run `Install.bat` again** to complete installation.

#### Method 2: Manual Installation

If you prefer manual control:
```batch
# 1. Enable test signing (as Administrator)
bcdedit /set testsigning on
# Reboot required!

# 2. After reboot, create device (as Administrator)
cd packages\Microsoft.Windows.WDK.x64.10.0.xxxxx\tools\x64
devgen.exe /add /bus ROOT /hardwareid Root\SimpleAntiCheat

# 3. Install driver
cd C:\Path\To\x64\Release
pnputil /add-driver SimpleAntiCheat.inf /install
```

### Verification

#### Check Service Status
```batch
# Command Prompt
sc query SimpleAntiCheat

# PowerShell
Get-Service SimpleAntiCheat
```

**Expected Output**:
```
SERVICE_NAME: SimpleAntiCheat
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
```

#### Check Driver Loaded
```batch
# List loaded drivers
sc query type= driver state= all | findstr SimpleAntiCheat

# Or use DriverView from Sysinternals
```

#### View Debug Output

**Using DebugView** (https://learn.microsoft.com/en-us/sysinternals/downloads/debugview):

1. Run DebugView **as Administrator**
2. Enable `Capture → Capture Kernel` (Ctrl+K)
3. Enable `Capture → Enable Verbose Kernel Output`

**Expected Messages**:
```
[SimpleAntiCheat] Driver loading...
[SimpleAntiCheat] Process notification routine registered
[SimpleAntiCheat] ObRegisterCallbacks succeeded at altitude 375133
[SimpleAntiCheat] Scan thread started
[SimpleAntiCheat] Driver loaded successfully
[SimpleAntiCheat] Protecting process: notepad.exe
```

## Testing the Driver

### Basic Functionality Test

#### 1. Start Protected Process
```batch
notepad.exe
```

**DebugView Output**:
```
[SimpleAntiCheat] Protected process started: \Device\HarddiskVolume3\Windows\System32\notepad.exe (PID: 0000000000001A4C)
```

#### 2. Attempt to Access Memory
- Open **Task Manager** (Ctrl+Shift+Esc)
- Find `notepad.exe` in Details tab
- Right-click → **Create dump file** or use **Process Explorer**

**Expected**: Operation should fail or be limited

**DebugView Output**:
```
[SimpleAntiCheat] Handle creation attempt from PID: 0000000000002B8C
```

#### 3. Observe Periodic Scanning
Every 5 seconds, you'll see:

**Handle Scan**:
```
[SimpleAntiCheat] Handle detected - Process: \Device\...\taskmgr.exe, Access: 0x1FFFFF
```

**Memory Scan**:
```
[SimpleAntiCheat] === Scanning executable memory regions ===
[SimpleAntiCheat] Executable Region - Base: 0x00007FF7A2B40000, Protection: PAGE_EXECUTE_READ, Type: MEM_IMAGE, Size: 0x1E000
[SimpleAntiCheat] Executable Region - Base: 0x00007FFB2C450000, Protection: PAGE_EXECUTE_READ, Type: MEM_IMAGE, Size: 0x1A3000
```

### Advanced Testing
See SimpleAntiCheatTest project

## Configuration

### Change Protected Process

Edit `DriverMain.cpp`:
```cpp
// Line ~31
constexpr WCHAR PROTECTED_PROCESS_NAME[] = L"notepad.exe"; // Change to your target
```

Rebuild and reinstall.

### Whitelist Additional Processes

Edit `DriverMain.cpp`:
```cpp
// Line ~33
static constexpr const WCHAR* const WHITELISTED_PROCESSES[] = // Add more process names as needed
{
    L"smss.exe",        // Session Manager
    L"csrss.exe",       // Critical subsystem
    L"wininit.exe",     // Session 0 init
    L"services.exe",    // SCM
    L"lsass.exe",       // Security / auth
    L"winlogon.exe",    // Logon process
    L"LogonUI.exe",      // Credential provider / lock screen
    L"svchost.exe",     // Generic service host
    L"MsMpEng.exe",     // Defender engine
    L"fontdrvhost.exe", // Font driver
    L"dwm.exe",         // Desktop compositor
    L"explorer.exe",    // Shell
    L"sihost.exe",      // Shell infrastructure host
    L"ctfmon.exe"
};
```

Rebuild and reinstall.

### Change Scan Interval

Edit `DriverMain.cpp`:
```cpp
// Line ~51
constexpr DWORD SCAN_INTERVAL_MS = 10000; // Milliseconds
```

## Uninstallation

### Method 1: Automated (Recommended)
```batch
# As Administrator
pnputil /delete-driver SimpleAntiCheat.inf /uninstall /force

# Or if you know the OEM name
pnputil /enum-drivers | findstr SimpleAntiCheat
pnputil /delete-driver oem##.inf /uninstall
```

### Method 2: Device Manager

1. Open Device Manager
2. View → Show hidden devices
3. Expand **System devices** or **Software devices**
4. Right-click **SimpleAntiCheat** → Uninstall device
5. Check "Delete the driver software for this device"

### Method 3: Manual Cleanup
```batch
# Stop service (if running)
sc stop SimpleAntiCheat

# Delete service
sc delete SimpleAntiCheat

# Remove driver file
del C:\Windows\System32\drivers\SimpleAntiCheat.sys

# Disable test signing (optional)
bcdedit /set testsigning off
# Reboot required
```

## Troubleshooting

### "Test signing mode is not enabled"
```
Solution: Run bcdedit /set testsigning on as Administrator, then reboot
```

### "devgen.exe not found"
```
Solution: Restore NuGet packages in Visual Studio
  - Right-click solution → Restore NuGet Packages
  - Rebuild solution
  
Check: packages\Microsoft.Windows.WDK.x64.*\tools\x64\devgen.exe exists
```

### "No debug output in DebugView"
```
Checklist:
  ✅ DebugView running as Administrator
  ✅ Capture → Capture Kernel enabled (Ctrl+K)
  ✅ Capture → Enable Verbose Kernel Output enabled
  ✅ Driver actually loaded (sc query SimpleAntiCheat)
```

### "Protected process not detected"
```
Checklist:
  ✅ Process name matches exactly (case-insensitive)
  ✅ Driver loaded BEFORE target process started
  ✅ Check DebugView for "Protected process started" message
  
Try: Kill notepad.exe and start it again after driver loads
```

### "Can't create process after driver loads"
```
  ✅ Driver actually loaded (sc query SimpleAntiCheat)
  
  Advanced: Compile as debug, look for "[SimpleAntiCheat] Non-whitelisted process..." messages in DebugView to identify which process is being blocked. Add it to the whitelist if needed.
 
```

## ARM64 Support

For Windows on ARM devices:
```batch
# Build for ARM64
# Select Platform: ARM64 in Visual Studio

# Use ARM64 devgen
cd packages\Microsoft.Windows.WDK.ARM64.10.0.xxxxx\tools\arm64
Install.bat "C:\Path\To\SimpleAntiCheat.inf" "%cd%\devgen.exe"
```

## Summary

**Typical first-time workflow**:
```batch
# 1. Disable Secure Boot in BIOS/UEFI
# 2. Boot Windows

# 3. Build (in Visual Studio)
Ctrl+Shift+B

# 4. Install
cd x64\Release
Install.bat "%cd%\SimpleAntiCheat.inf" "..\..\packages\Microsoft.Windows.WDK.x64.10.0.26100.1742\tools\x64\devgen.exe"

# 5. Reboot (if test signing was just enabled)

# 6. Install again (if you rebooted)
Install.bat "%cd%\SimpleAntiCheat.inf" "..\..\packages\Microsoft.Windows.WDK.x64.10.0.26100.1742\tools\x64\devgen.exe"

# 7. Test
notepad.exe
# Open DebugView and monitor
```

**Subsequent rebuilds**:
```batch
# 1. Uninstall old driver
pnputil /delete-driver SimpleAntiCheat.inf /uninstall /force

# 2. Rebuild in Visual Studio

# 3. Reinstall
Install.bat "..." "..."
```

## Support

- **Debug Output**: Use DebugView with kernel capture enabled
- **System Logs**: Event Viewer → Windows Logs → System

---