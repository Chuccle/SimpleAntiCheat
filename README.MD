# SimpleAntiCheat

## Overview
A Windows kernel driver that protects a target process from external manipulation through callback-based interception and periodic scanning.

## Architecture

### Two-Component Design

#### 1. Callbacks (Real-time Protection)

**Process Notification Callback**
- Monitors process creation and termination system-wide
- Detects when the protected process starts/stops based on image name matching
- Maintains global state with process object reference and PID

**Handle Operation Callback** 
- Intercepts handle creation and duplication attempts to the protected process
- Whitelists legitimate first-party processes (System, csrss.exe, services.exe, smss.exe, wininit.exe)
- Strips dangerous access rights (VM_READ, VM_WRITE, VM_OPERATION, CREATE_THREAD) from unauthorized handles
- Logs all blocked attempts for forensic analysis

#### 2. Scanning (Periodic Detection)

Runs at configurable intervals (default: 10000ms) to detect post-compromise indicators:

**Handle Enumeration Scan**
- Queries `SystemExtendedHandleInformation` for all system handles
- Identifies external processes holding handles to the protected process
- Logs process name and granted access mask for each detection
- Filters out handles owned by the protected process itself

**Executable Memory Scan**  
- Enumerates the protected process's virtual address space
- Identifies executable memory regions (PAGE_EXECUTE*)
- Logs base address, page protection flags, memory type (MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE), and region size

## Synchronisation Strategy

### Challenge
The protected process state is globally shared between:
- **Single Writer**: `ProcessNotifyRoutine` (runs in context of creating/exiting thread)
- **Multiple Readers**: Scanning threads accessing process information

### Solution: Push Lock with Reference Counting

**Primitive Choice**: `EX_PUSH_LOCK` (reader-writer lock)
- Safe for direct use in our context (kernel APCs implicitly disabled)
- Optimized for reader-heavy workloads (scanning is more frequent than process start/stop)
- Lower overhead than ERESOURCE, better scalability than Fast Mutex

**Lifetime Management**:
```cpp
// Writer (ProcessNotifyRoutine):
// - On process start: implicit ObReferenceObject() before storing globally
// - On process exit: ObDereferenceObject() after removing from global state

// Readers (Scan threads):
// - Acquire shared lock
// - Take additional ObReferenceObject() while holding lock
// - Release lock
// - Use process object safely (protected by reference count)
// - ObDereferenceObject() when done
```

**Why This Works**:
1. **Prevent use-after-free**: Even if process exits during scan, the extra reference keeps the object valid
2. **Minimize lock contention**: Lock held only during reference increment and read of process pointer, not during entire scan

### Race Condition Mitigation

**Scenario**: Process exits between lock release and scan completion
- ❌ **Without extra reference**: Object freed mid-scan → BSOD
- ✅ **With extra reference**: Object remains valid until scan completes

**Example Flow**:
```
Thread A (Scan):                    Thread B (Process Exit):
1. Acquire shared lock              
2. Check ProcessObject != NULL      
3. ObReferenceObject()              
4. Release shared lock              
                                    5. Acquire exclusive lock
                                    6. ObDereferenceObject()
                                    7. Object refcount = 1 (kept alive by A)
                                    8. Release exclusive lock
7. Scan address space (SAFE)        
8. ObDereferenceObject()            
9. Object refcount = 0 → freed      
```

## Design Decisions

### Hardcoded Process Name
The protected process name is embedded in the driver binary rather than configurable via IOCTL because:
- **Threat Model**: A SYSTEM-level attacker could craft a malicious user mode service to disable protection via IOCTL if we use even a strict SDDL string
- **Mitigation**: Hardcoding + Secure Boot enforcement raises the attack bar to BYOVD (Bring Your Own Vulnerable Driver)
- **Trade-off**: Less flexible but significantly more tamper-resistant

### Dynamic Altitude Selection
```cpp
constexpr ULONG BASE_ALTITUDE = 375133;
// Retries with incremented altitude on collision
```
- Handles deployment environments with existing filter drivers
- Ensures successful registration without manual altitude coordination

## Security Considerations

**Not Protected Against** (by design):
- Kernel-mode exploits and rootkits
- BYOVD (Bring Your Own Vulnerable Driver) attacks
- Physical memory access (DMA)
- Hypervisor-level attacks

**Recommended Additional Mitigations**:
- HVCI (Hypervisor-Protected Code Integrity)
- Secure Boot enforcement
- IOMMU

## Technical Details

**APIs Used**:
- `PsSetCreateProcessNotifyRoutine` - Process lifecycle monitoring
- `ObRegisterCallbacks` - Object Manager handle interception
- `ZwQuerySystemInformation(SystemExtendedHandleInformation)` - Handle enumeration
- `ZwQueryVirtualMemory` - Memory region inspection
- `KeStackAttachProcess` - Cross-process context switching
- `SeLocateProcessImageName` - Process name retrieval

**Supported Platforms**: Windows 10+ (x64)  
**Driver Type**: WDM (Windows Driver Model)  
**IRQL Requirements**: PASSIVE_LEVEL

## Special requirements
It was required to add the /INTEGRITYCHECK option for the linker, this is because of a restriction of ObRegisterCallbacks. It will return a 0xC0000022 (STATUS_ACCESS_DENIED) if not detected as a signed image