#pragma once

template<typename P>
class KernelObjectRef
{
public:
    explicit KernelObjectRef(P Obj = nullptr) noexcept
        : Obj_(Obj)
    {
    }

    ~KernelObjectRef() noexcept
    {
        if (Obj_)
        {
            ObDereferenceObject(Obj_);
        }
    }

    KernelObjectRef(const KernelObjectRef&) = delete;
    KernelObjectRef& operator=(const KernelObjectRef&) = delete;

    KernelObjectRef(KernelObjectRef&& Other) noexcept
    {
        Reset(Other.Release());
    }

    KernelObjectRef& operator=(KernelObjectRef&& Other) noexcept
    {
        if (this != &Other)
        {
            Reset(Other.Release());
        }

        return *this;
    }

    [[nodiscard]] P Get() const noexcept
    {
        return Obj_;
    }

    explicit operator bool() const noexcept
    {
        return Obj_ != nullptr;
    }

    void Reset(P NewObj = nullptr) noexcept
    {
        if (Obj_)
        {
            ObDereferenceObject(Obj_);
        }

        Obj_ = NewObj;
    }

    P Release() noexcept
    {
        P p = Obj_;
        Obj_ = nullptr;
        return p;
    }

    void AddRef()
    {
        if (Obj_)
        {
            ObReferenceObject(Obj_);
        }
    }

private:
    P Obj_ = nullptr;
};

class KernelProcessImageName
{
public:
    explicit KernelProcessImageName(PEPROCESS Proc) noexcept
        : Name_(nullptr), Status_(STATUS_UNSUCCESSFUL)
    {
        Status_ = SeLocateProcessImageName(Proc, &Name_);
    }

    ~KernelProcessImageName() noexcept
    {
        if (NT_SUCCESS(Status_))
        {
            ExFreePool(Name_);
        }
    }

    KernelProcessImageName(const KernelProcessImageName&) = delete;
    KernelProcessImageName& operator=(const KernelProcessImageName&) = delete;

    [[nodiscard]] PCUNICODE_STRING Get() const noexcept
    {
        return Name_;
    }
    explicit operator bool() const noexcept
    {
        return NT_SUCCESS(Status_);
    }

    bool IsProcessName(PCWSTR ProcessName) const noexcept
    {
        if (!Name_ || !ProcessName || ProcessName[0] == L'\0')
        {
            return false;
        }

        // Special case for things like System process which has an empty string as its image name
        if (Name_->Length == 0)
        {
            return false;
        }

        UNICODE_STRING fileName;

        // Filename is delimited by the last backslash in the full path
        PWCHAR lastBackslash = wcsrchr(Name_->Buffer, L'\\');

        if (lastBackslash)
        {
            RtlInitUnicodeString(&fileName, lastBackslash + 1);
        }
        else
        {
            fileName = *Name_;
        }

        UNICODE_STRING targetName;
        RtlInitUnicodeString(&targetName, ProcessName);

        return RtlEqualUnicodeString(&fileName, &targetName, true);
    }

    bool IsProcessFullName(PCWSTR ProcessFullName) const noexcept
    {
        if (!Name_ || !ProcessFullName || ProcessFullName[0] == L'\0')
        {
            return false;
        }

        // Special case for things like System process which has an empty string as its image name
        if (Name_->Length == 0)
        {
            return false;
        }

        UNICODE_STRING targetName;
        RtlInitUnicodeString(&targetName, ProcessFullName);

        return RtlEqualUnicodeString(Name_, &targetName, true);
    }

private:
    PUNICODE_STRING Name_;
    NTSTATUS Status_;
};

// On x86_64, MOV is strongly ordered with respect to other memory operations (TSO)
// On ARM, we use stlr and ldar which provide the necessary ordering guarantees for our use case without the overhead of a full memory barrier or interlocked operations.
class KernelAtomicFlag
{
public:
    inline void Set()
    {
        KeMemoryBarrierWithoutFence();
        WriteRelease(&Val_, 1);
    }

    inline void Clear()
    {
        KeMemoryBarrierWithoutFence();
        WriteRelease(&Val_, 0);
    }

    [[nodiscard]] inline bool Get() const
    {
        LONG val = ReadAcquire(&Val_);
        KeMemoryBarrierWithoutFence();
        return val != 0;
    }

private:
    LONG Val_ = 0;
};

struct DefaultKernelDeleter
{
    void operator()(void* p) const noexcept
    {
        if (p)
        {
            ExFreePool(p);
        }
    }
};

template <ULONG Tag>
struct TaggedDeleter
{
    void operator()(void* p) const noexcept
    {
        if (p)
        {
            ExFreePoolWithTag(p, Tag);
        }
    }
};

template <typename T, typename Deleter = DefaultKernelDeleter>
class KernelSmartPointer
{
public:
    using Pointer = T*;
    using DeleterType = Deleter;

    KernelSmartPointer() noexcept = default;

    explicit KernelSmartPointer(Pointer Ptr) noexcept
        : Ptr_(Ptr)
    {
    }

    KernelSmartPointer(Pointer Ptr, DeleterType Deleter) noexcept
        : Ptr_(Ptr), Deleter_(static_cast<DeleterType&&>(Deleter))
    {
    }

    ~KernelSmartPointer() noexcept
    {
        if (Ptr_)
        {
            Deleter_(Ptr_);
        }
    }

    KernelSmartPointer(const KernelSmartPointer&) = delete;
    KernelSmartPointer& operator=(const KernelSmartPointer&) = delete;

    KernelSmartPointer(KernelSmartPointer&& Other) noexcept
    {
        Reset(Other.Release());
    }

    KernelSmartPointer& operator=(KernelSmartPointer&& Other) noexcept
    {
        if (this != &Other)
        {
            Reset(Other.Release());
        }

        return *this;
    }

    [[nodiscard]] Pointer Get() const noexcept
    {
        return Ptr_;
    }

    Pointer operator->() const noexcept
    {
        return Ptr_;
    }
    T& operator*() const noexcept
    {
        return *Ptr_;
    }
    explicit operator bool() const noexcept
    {
        return Ptr_ != nullptr;
    }

    void Reset(Pointer NewPtr = nullptr) noexcept
    {
        if (Ptr_)
        {
            Deleter_(Ptr_);
        }

        Ptr_ = NewPtr;
    }

    [[nodiscard]] Pointer Release() noexcept
    {
        Pointer p = Ptr_;
        Ptr_ = nullptr;
        return p;
    }

private:
    Pointer Ptr_ = nullptr;
    [[no_unique_address]] DeleterType Deleter_ = {};
};

class PushLockExclusive
{
public:
    explicit PushLockExclusive(EX_PUSH_LOCK* Lock) noexcept
        : Lock_(Lock)
    {
        ExAcquirePushLockExclusive(Lock_);
    }
    ~PushLockExclusive() noexcept
    {
        ExReleasePushLockExclusive(Lock_);
    }

    PushLockExclusive(const PushLockExclusive&) = delete;
    PushLockExclusive& operator=(const PushLockExclusive&) = delete;

private:
    EX_PUSH_LOCK* Lock_;
};

class PushLockShared
{
public:
    explicit PushLockShared(EX_PUSH_LOCK* Lock) noexcept
        : Lock_(Lock)
    {
        ExAcquirePushLockShared(Lock_);
    }
    ~PushLockShared() noexcept
    {
        ExReleasePushLockShared(Lock_);
    }

    PushLockShared(const PushLockShared&) = delete;
    PushLockShared& operator=(const PushLockShared&) = delete;

private:
    EX_PUSH_LOCK* Lock_;
};

namespace kernel_std
{
    template<typename T> struct remove_reference
    {
        typedef T type;
    };
    template<typename T> struct remove_reference<T&>
    {
        typedef T type;
    };
    template<typename T> struct remove_reference<T&&>
    {
        typedef T type;
    };

    template<typename T>
    constexpr typename remove_reference<T>::type&& move(T&& arg) noexcept
    {
        return static_cast<typename remove_reference<T>::type&&>(arg);
    }
}