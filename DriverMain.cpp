#include "DriverPCH.hpp"

extern "C" NTSTATUS ZwQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);

struct SimpleACProcess
{
    EX_PUSH_LOCK SharedLock;
    KernelObjectRef<PEPROCESS> ProcessObject;
    HANDLE ProcessId;
};

struct Globals
{
    KEVENT ThreadStopEvent;
    SimpleACProcess ProtectedProcess;
    PVOID ObCallbackHandle;
    PVOID ScanThreadObject;
} global;

// The reason why it's actually advantageous to hardcode this, is that an alternative might be to have it supplied by a usermode accessible means like an IOCTL.
// Even with restrictive SDDLs like SDDL_DEVOBJ_SYS_ALL mitigating; A determined cheater could still craft a malicious SYSTEM service to create a handle to our driver
// and issue IOCTLs to change and effectively disable our protection. With us hardcoding and embedding our protected process in our driver image combined with enforcing
// secure boot is enabled to open our protected process, we can significantly raise the bar for attackers, they will be limited to BYOVD or dodgy signed drivers to even
// attempt to bypass our protection
constexpr WCHAR PROTECTED_PROCESS_NAME[] = L"notepad.exe";

static constexpr const WCHAR* const WHITELISTED_PROCESSES[] =
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

constexpr DWORD SCAN_INTERVAL_MS = 10000;

VOID ProcessNotifyRoutine(
    HANDLE ParentId,
    HANDLE ProcessId,
    BOOLEAN Create
)
{
    UNREFERENCED_PARAMETER(ParentId);

    KernelObjectRef<PEPROCESS> processObject;
    {
        PEPROCESS rawProc = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &rawProc);

        if (!NT_SUCCESS(status))
        {
            return;
        }

        processObject.Reset(rawProc);
    }

    KernelProcessImageName procImageName(processObject.Get());

    if (!procImageName)
    {
        return;
    }

    if (!procImageName.IsProcessName(PROTECTED_PROCESS_NAME))
    {
        return;
    }

    if (Create)
    {
        if (global.ProtectedProcess.ProcessObject.Get() == nullptr)
        {
            {
                PushLockExclusive lock(&global.ProtectedProcess.SharedLock);
                global.ProtectedProcess.ProcessId = ProcessId;
                global.ProtectedProcess.ProcessObject = kernel_std::move(processObject); // ensure we keep a reference globally
            }

            KdPrint(("[SimpleAntiCheat] Protected process started: %wZ (PID: %p)\n",
                procImageName.Get(), ProcessId));
        }
    }
    else
    {
        if (global.ProtectedProcess.ProcessId == ProcessId)
        {
            KdPrint(("[SimpleAntiCheat] Protected process stopped: %wZ (PID: %p)\n",
                procImageName.Get(), ProcessId));

            {
                PushLockExclusive lock(&global.ProtectedProcess.SharedLock);
                global.ProtectedProcess.ProcessId = nullptr;
                global.ProtectedProcess.ProcessObject.Reset();
            }
        }
    }
}

OB_PREOP_CALLBACK_STATUS ProcessHandleCallback(
    IN PVOID RegistrationContext,
    IN POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Check if this is a process handle operation
    if (OperationInformation->ObjectType != *PsProcessType)
    {
        return OB_PREOP_SUCCESS;
    }

    auto targetProcess = static_cast<PEPROCESS>(OperationInformation->Object);
    {
        PushLockShared lock(&global.ProtectedProcess.SharedLock);

        if (targetProcess != global.ProtectedProcess.ProcessObject.Get())
        {
            return OB_PREOP_SUCCESS;
        }
    }

    PEPROCESS currentProcess = PsGetCurrentProcess();
    HANDLE currentPid = PsGetProcessId(currentProcess);

    // Allow certain system processes (System, csrss.exe, etc.)
    // PID 4 is System process, PID 0 is Idle
    if (currentPid == reinterpret_cast<HANDLE>(4) ||
        currentPid == reinterpret_cast<HANDLE>(0))
    {
        return OB_PREOP_SUCCESS;
    }

    // Allow the process itself
    if (currentProcess == targetProcess)
    {
        return OB_PREOP_SUCCESS;
    }

    // Check if caller is a system process (csrss, services, etc.)
    // These are necessary for process creation/management
    KernelProcessImageName procImageName(currentProcess);

    if (!procImageName)
    {
        return OB_PREOP_SUCCESS;
    }

    // I dont think there's any benefit to a hash lookup here since the list is rather tiny
    for (const auto& whitelistedProcess : WHITELISTED_PROCESSES)
    {
        if (procImageName.IsProcessName(whitelistedProcess))
        {
            return OB_PREOP_SUCCESS;
        }
    }

    // Makes life easier for anyone wanting to expand the whitelist
    KdPrint(("[SimpleAntiCheat] Non-whitelisted process: (%wZ -- PID: %p) has requested a handle\n", procImageName.Get(), currentPid));

    switch (OperationInformation->Operation)
    {
        case OB_OPERATION_HANDLE_CREATE:
        {
            // WriteProcessMemory and ReadProcessMemory require these
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);

            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                ~PROCESS_CREATE_THREAD;
            KdPrint(("[SimpleAntiCheat] Handle creation attempt from PID: %p\n", currentPid));
            break;
        }
        case OB_OPERATION_HANDLE_DUPLICATE:
        {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD);

            KdPrint(("[SimpleAntiCheat] Blocked handle duplication attempt from PID: %p\n", currentPid));
            break;
        }
    }

    return OB_PREOP_SUCCESS;
}

static NTSTATUS ScanHandles()
{
    HANDLE targetPid = nullptr;
    KernelObjectRef<PEPROCESS> targetProc;
    {
        PushLockShared lock(&global.ProtectedProcess.SharedLock);

        if (!global.ProtectedProcess.ProcessObject)
        {
            return STATUS_SUCCESS;
        }

        // Take an extra reference to preserve the process object for the duration of this scan, so that it doesn't get freed while we're scanning handles
        targetProc.Reset(global.ProtectedProcess.ProcessObject.Get());
        targetProc.AddRef();
        targetPid = global.ProtectedProcess.ProcessId;
    }

    KdPrint(("[SimpleAntiCheat] === Scanning system handle table ===\n"));

    auto handleInfo = [&]() -> KernelSmartPointer<SYSTEM_HANDLE_INFORMATION_EX>
        {
            ULONG size = 0x40000;  // 256 KB start - usually enough

            for (int i = 0; i < 5; i++)
            {
                auto handleInfoBuffer = KernelSmartPointer<SYSTEM_HANDLE_INFORMATION_EX>(
                    static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(
                        ExAllocatePoolUninitialized(NonPagedPool, size, 'hSAC')));

                if (!handleInfoBuffer)
                {
                    return handleInfoBuffer;
                }

                ULONG needed = 0;
                NTSTATUS status = ZwQuerySystemInformation(SystemExtendedHandleInformation, handleInfoBuffer.Get(), size, &needed);

                if (NT_SUCCESS(status))
                {
                    return handleInfoBuffer;
                }

                if (status != STATUS_INFO_LENGTH_MISMATCH)
                {
                    return {};
                }

                size = needed ? needed + 0x2000 : size * 2;
            }

            return {};
        }();

    if (!handleInfo)
    {
        KdPrint(("[SimpleAntiCheat] === Failed to obtain handle entries\n"));
        return STATUS_UNSUCCESSFUL;
    }

    for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = &handleInfo->Handles[i];

        if (handleEntry->UniqueProcessId == targetPid)
        {
            continue; // Skip handles owned by the protected process itself
        }

        // Check if this handle points to our protected process
        if (handleEntry->Object == targetProc.Get()) // Was tempted to also check for handleEntry->ObjectTypeIndex == 7 (process index) but seems to be unreliable across versions of Windows apparently
        {
            KernelObjectRef<PEPROCESS> ownerProcess;
            {
                PEPROCESS rawProc = nullptr;

                if (!NT_SUCCESS(PsLookupProcessByProcessId(handleEntry->UniqueProcessId, &rawProc)))
                {
                    continue;
                }

                ownerProcess.Reset(rawProc);
            }

            KernelProcessImageName procImageName(ownerProcess.Get());

            if (!procImageName)
            {
                continue;
            }

            if (procImageName.IsProcessName(PROTECTED_PROCESS_NAME))
            {
                continue;
            }

            DbgPrint("[SimpleAntiCheat] Handle detected - Process: %wZ (PID: %p), Access: 0x%lX\n",
                procImageName.Get(), handleEntry->UniqueProcessId, handleEntry->GrantedAccess);
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS ScanExecutableMemory()
{
    KernelObjectRef<PEPROCESS> targetProcess;
    {
        PushLockShared lock(&global.ProtectedProcess.SharedLock);

        if (!global.ProtectedProcess.ProcessObject)
        {
            return STATUS_SUCCESS;
        }

        // Take an extra reference to preserve the process object for the duration of this scan, so that it doesn't get freed while we're scanning address space
        targetProcess.Reset(global.ProtectedProcess.ProcessObject.Get());
        targetProcess.AddRef();
    }

    // Attach to target process context
    KAPC_STATE apcState;
    KeStackAttachProcess(targetProcess.Get(), &apcState);

    KdPrint(("[SimpleAntiCheat] === Scanning executable memory regions ===\n"));

    PVOID baseAddress = nullptr;
    while (baseAddress < MmHighestUserAddress)
    {
        MEMORY_BASIC_INFORMATION memInfo;
        SIZE_T returnLength;

        NTSTATUS status = ZwQueryVirtualMemory(
            ZwCurrentProcess(),
            baseAddress,
            static_cast<MEMORY_INFORMATION_CLASS>(MemoryBasicInformation),
            &memInfo,
            sizeof(memInfo),
            &returnLength);

        if (!NT_SUCCESS(status))
        {
            break;
        }

        constexpr ULONG executeFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        if (memInfo.Protect & executeFlags)
        {
            PCSTR protectStr = "Unknown_Execute";
            switch (memInfo.Protect & executeFlags)
            {
                case PAGE_EXECUTE:
                {
                    protectStr = "PAGE_EXECUTE";
                    break;
                }
                case PAGE_EXECUTE_READ:
                {
                    protectStr = "PAGE_EXECUTE_READ";
                    break;
                }
                case PAGE_EXECUTE_READWRITE:
                {
                    protectStr = "PAGE_EXECUTE_READWRITE";
                    break;
                }
                case PAGE_EXECUTE_WRITECOPY:
                {
                    protectStr = "PAGE_EXECUTE_WRITECOPY";
                    break;
                }
            }

            PCSTR typeStr = "Unknown";
            switch (memInfo.Type)
            {
                case MEM_IMAGE:
                {
                    typeStr = "MEM_IMAGE";
                    break;
                }
                case MEM_MAPPED:
                {
                    typeStr = "MEM_MAPPED";
                    break;
                }
                case MEM_PRIVATE:
                {
                    typeStr = "MEM_PRIVATE";
                    break;
                }
            }

            DbgPrint("[SimpleAntiCheat] Executable Region - Base: 0x%p, Protection: %s, Type: %s, Size: 0x%llX\n",
                memInfo.BaseAddress, protectStr, typeStr, static_cast<ULONG64>(memInfo.RegionSize));
        }

        baseAddress = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(memInfo.BaseAddress) + memInfo.RegionSize);
    }

    KeUnstackDetachProcess(&apcState);

    return STATUS_SUCCESS;
}

[[noreturn]] VOID ScanThread(IN PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    LARGE_INTEGER interval;

    KdPrint(("[SimpleAntiCheat] Scan thread started\n"));

    interval.QuadPart = -static_cast<LONG64>((SCAN_INTERVAL_MS * 10000));

    while (true)
    {
        NTSTATUS status = KeWaitForSingleObject(
            &global.ThreadStopEvent,
            Executive,
            KernelMode,
            false,
            &interval);

        if (status != STATUS_TIMEOUT) [[unlikely]]
        {
            break;
        }

        ScanHandles();
        ScanExecutableMemory();
    }

    KdPrint(("[SimpleAntiCheat] Scan thread stopped\n"));
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS RegisterProcessHandleCallback()
{
    constexpr ULONG BASE_ALTITUDE = 375133;

    UNICODE_STRING altitudeString;
    WCHAR altitudeBuffer[32] = { 0 };

    RtlInitUnicodeString(&altitudeString, altitudeBuffer);

    OB_CALLBACK_REGISTRATION callbackReg = { 0 };
    OB_OPERATION_REGISTRATION opReg = { 0 };

    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = ProcessHandleCallback;
    opReg.PostOperation = nullptr;

    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationRegistrationCount = 1;
    callbackReg.RegistrationContext = nullptr;
    callbackReg.OperationRegistration = &opReg;
    callbackReg.Altitude = altitudeString;

    RtlInitEmptyUnicodeString(&altitudeString, altitudeBuffer, sizeof(altitudeBuffer));

    ULONG currentAltitude = BASE_ALTITUDE;
    constexpr ULONG maxRetries = 10;    // generous

    for (ULONG retry = 0; retry <= maxRetries; retry++)
    {
        NTSTATUS status = RtlIntegerToUnicodeString(currentAltitude, 10, &altitudeString);

        if (!NT_SUCCESS(status))
        {
            KdPrint(("[SimpleAntiCheat] Failed to convert altitude %lu to string: 0x%08X\n", currentAltitude, status));
            return status;
        }

        status = ObRegisterCallbacks(&callbackReg, &global.ObCallbackHandle);

        if (NT_SUCCESS(status))
        {
            KdPrint(("[SimpleAntiCheat] ObRegisterCallbacks succeeded at altitude %lu\n", currentAltitude));
            return STATUS_SUCCESS;
        }

        if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
        {
            KdPrint(("[SimpleAntiCheat] ObRegisterCallbacks failed at altitude %lu: 0x%08X\n", currentAltitude, status));
            return status;
        }

        KdPrint(("[SimpleAntiCheat] Altitude collision at %lu, retrying...\n", currentAltitude));
        currentAltitude += 1;
    }

    KdPrint(("[SimpleAntiCheat] Failed to register ObCallback after %u retries (altitude range %lu�%lu)\n",
        maxRetries + 1, BASE_ALTITUDE, currentAltitude - 1));

    return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DriverCppCleanup();

    // Looking at the disassembly, this seems synchronous. Flushes concurrent callbacks.
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, true);

    {
        PushLockExclusive lock(&global.ProtectedProcess.SharedLock);
        global.ProtectedProcess.ProcessId = nullptr;
        global.ProtectedProcess.ProcessObject.Reset();
    }

    KeSetEvent(&global.ThreadStopEvent, IO_NO_INCREMENT, false);

    if (global.ScanThreadObject)
    {
        KeWaitForSingleObject(global.ScanThreadObject, Executive, KernelMode, false, nullptr);
        ObDereferenceObject(global.ScanThreadObject );
        global.ScanThreadObject = nullptr;
    }

    if (global.ObCallbackHandle)
    {
        ObUnRegisterCallbacks(global.ObCallbackHandle);
        global.ObCallbackHandle = nullptr;
    }

}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // Support for by NonPagedPoolNx by default if available on the Windows version we're running on.
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    DriverCppInitialize();

    KdPrint(("[SimpleAntiCheat] Driver loading...\n"));

    ExInitializePushLock(&global.ProtectedProcess.SharedLock);

    KeInitializeEvent(&global.ThreadStopEvent, NotificationEvent, false);

    // 1) Register process notification
    NTSTATUS status = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, false);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("[SimpleAntiCheat] Failed to register process notify routine: 0x%X\n", status));
        return status;
    }

    KdPrint(("[SimpleAntiCheat] Process notification routine registered\n"));

    // 2) Register object callback for process handles
    status = RegisterProcessHandleCallback();

    if (!NT_SUCCESS(status))
    {
        PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, true);
        return status;
    }

    KdPrint(("[SimpleAntiCheat] Object callback registered\n"));

    // 3 & 4) Create scanning thread. Alternatively, we could use a timer which sets off a work item but we will follow the specification and create a dedicated thread for scanning.
    HANDLE threadHandle;
    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        ScanThread,
        nullptr);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("[SimpleAntiCheat] Failed to create scan thread: 0x%X\n", status));
        ObUnRegisterCallbacks(global.ObCallbackHandle);
        PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, true);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        KernelMode,
        &global.ScanThreadObject,
        nullptr);

    ZwClose(threadHandle);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("[SimpleAntiCheat] Failed to reference thread object: 0x%X\n", status));
		KeSetEvent(&global.ThreadStopEvent, IO_NO_INCREMENT, false);
        ObUnRegisterCallbacks(global.ObCallbackHandle);
        PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, true);
        return status;
    }

    KdPrint(("[SimpleAntiCheat] Driver loaded successfully\n"));
    KdPrint(("[SimpleAntiCheat] Protecting process: %ws\n", PROTECTED_PROCESS_NAME));

    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}