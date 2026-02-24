#include "DriverPCH.hpp"

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t Size, POOL_TYPE PoolType, ULONG Tag) noexcept
{
    return ExAllocatePoolUninitialized(PoolType, Size, Tag);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new[](size_t Size, POOL_TYPE PoolType, ULONG Tag) noexcept
{
    return ExAllocatePoolUninitialized(PoolType, Size, Tag);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t Size)
{
    return ExAllocatePoolUninitialized(NonPagedPool, Size, CppRuntimeTag);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new[](size_t Size)
{
    return ExAllocatePoolUninitialized(NonPagedPool, Size, CppRuntimeTag);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* Ptr) noexcept
{
    if (Ptr)
    {
        ExFreePool(Ptr);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](void* Ptr) noexcept
{
    if (Ptr)
    {
        ExFreePool(Ptr);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* Ptr, size_t) noexcept
{
    if (Ptr)
    {
        ExFreePool(Ptr);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](void* Ptr, size_t) noexcept
{
    if (Ptr)
    {
        ExFreePool(Ptr);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* Ptr, ULONG Tag) noexcept
{
    if (Ptr)
    {
        ExFreePoolWithTag(Ptr, Tag);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](void* Ptr, ULONG Tag) noexcept
{
    if (Ptr)
    {
        ExFreePoolWithTag(Ptr, Tag);
    }
}

using _PVFV = void(__cdecl*)();
using _PIFV = int(__cdecl*)();

#pragma section(".CRT$XCA", long, read)
#pragma section(".CRT$XCZ", long, read)
#pragma section(".CRT$XIA", long, read)
#pragma section(".CRT$XIZ", long, read)
#pragma section(".CRT$XTA", long, read)
#pragma section(".CRT$XTZ", long, read)

__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { nullptr };
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { nullptr };
__declspec(allocate(".CRT$XIA")) _PIFV __xi_a[] = { nullptr };
__declspec(allocate(".CRT$XIZ")) _PIFV __xi_z[] = { nullptr };
__declspec(allocate(".CRT$XTA")) _PVFV __xt_a[] = { nullptr };
__declspec(allocate(".CRT$XTZ")) _PVFV __xt_z[] = { nullptr };

#pragma comment(linker, "/merge:.CRT=.rdata")

extern "C" void __cdecl _initterm(_PVFV* pfbegin, _PVFV* pfend)
{
    while (pfbegin < pfend)
    {
        if (*pfbegin != nullptr)
        {
            (**pfbegin)();
        }

        ++pfbegin;
    }
}

extern "C" int __cdecl _initterm_e(_PIFV* pfbegin, _PIFV* pfend)
{
    while (pfbegin < pfend)
    {
        if (*pfbegin != nullptr)
        {
            int result = (**pfbegin)();

            if (result != 0)
            {
                return result;
            }
        }

        ++pfbegin;
    }
    return 0;
}

extern "C" NTSTATUS DriverCppInitialize()
{
    if (_initterm_e(__xi_a, __xi_z) != 0)
    {
        return STATUS_UNSUCCESSFUL;
    }
    _initterm(__xc_a, __xc_z);

    KdPrint(("[SimpleAntiCheat] C++ runtime initialized\n"));
    return STATUS_SUCCESS;
}

// Note: This may introduce complexities with standard DriverUnload cleanup if C++ destructors rely on other kernel resources that may have already been cleaned up by the time this is called.
// Use with caution and ensure proper ordering of cleanup in DriverUnload.
extern "C" void DriverCppCleanup()
{
    KdPrint(("[SimpleAntiCheat] C++ runtime cleanup\n"));
}

extern "C" int __cdecl atexit(void(__cdecl*)(void))
{
    return 0;
}