// ============================================================================
//  ntdll_hooks.c — sfmc_hooks native lib 实现
//
//  SingleFileMc Phase 3: 守卫 stub + _suppressHooks + Reverse P/Invoke 桥。
//  本库【不】集成 MinHook 安装 —— patch 由托管层(修改后 MinHook.NET)执行,
//  本库只提供 detour 目标(Stub_*)与绑定注册(SetCallbacks)。
//
//  守卫模式(每个 stub 一致):
//    NTSTATUS WINAPI Stub_X(...) {
//        if (IsSuppressHooks() > 0) return Orig_X(...);     // 内部调用 -> 直接 trampoline
//        if (Managed_X == NULL)     return Orig_X(...);     // 未注册 -> 透传
//        IncrSuppressHooks();                               // native 自动 ++
//        NTSTATUS st = Managed_X(...);                      // Reverse P/Invoke -> 托管回调
//        DecSuppressHooks();                                // native 自动 --
//        return st;
//    }
//  托管回调执行期间(含 JIT / File.Exists / ConcurrentDictionary 等内部 ntdll 调用),
//  同线程 _suppressHooks > 0 -> 再次进入任何 Stub_* 直接走 Orig trampoline -> 零递归。
// ============================================================================
#include "ntdll_hooks.h"
#include <string.h>
#include <wchar.h>

// ---------------------------------------------------------------------------
// thread-static 守卫计数器: 由被 hook 的 ntdll 线程独占, 无锁
// ---------------------------------------------------------------------------
static __declspec(thread) int _suppressHooks;

// 绑定表: 13 托管回调 + 13 Orig trampoline(SetCallbacks 一次性拷贝; 初始全 NULL)
static SFMC_BINDINGS s_bind;

// ---------------------------------------------------------------------------
// 前置分流辅助(MODIFIED: 2026-08-04, runNATIVE-5b* 崩溃修复)
//
// 背景: 托管回调是 [UnmanagedCallersOnly] 的 unmanaged entry。CLR 内部托管线程
// (Finalizer/GC/ThreadPool 等)在 _suppressHooks==0 时若经本 stub 反向 P/Invoke
// 进入 Managed_*, CLR 检测到"线程已在托管执行" -> ReversePInvokeBadTransition
// failfast(0x80131506 "attempted to call a UnmanagedCallersOnly method from
// managed code", cdb 证据: JIT_ReversePInvokeEnterRare <- ReversePInvokeBadTransition
// <- EEPolicy::HandleFatalError, 调用点 Managed_NtClose)。
//
// 结论: thread-static 守卫只能保护"从 stub 进入托管回调的线程"自身的重入, 保护
// 不了 CLR 内部线程。修复 = stub 前置分流: 只有【假目标】(假文件句柄 0x5100xxxx /
// 假 section 句柄 0x5200xxxx / Z:\ 虚拟路径 / 假映射基址)才走 Managed 回调, 真实
// 句柄与真实路径(CLR 内部线程的全部调用)直接走 Orig trampoline, 永不 failfast。
// ---------------------------------------------------------------------------

// 假文件句柄: 0x51000000-0x51FFFFFF(FakeHandles 分配域, 见托管侧 MakeFakeFileHandle)
static BOOLEAN IsFakeFileHandle(HANDLE h)
{
    return ((ULONG_PTR)h & 0xFFFF0000UL) == 0x51000000UL;
}

// 假 section 句柄: 0x52000000-0x52FFFFFF(FakeSections 分配域)
static BOOLEAN IsFakeSectionHandle(HANDLE h)
{
    return ((ULONG_PTR)h & 0xFFFF0000UL) == 0x52000000UL;
}

// Z: 虚拟路径前缀 \??\Z:\ (7 个宽字符, 大小写不敏感; NULL 安全)
static BOOLEAN IsZPath(POBJECT_ATTRIBUTES oa)
{
    PUNICODE_STRING un;
    if (oa == NULL || oa->ObjectName == NULL)
        return FALSE;
    un = oa->ObjectName;
    if (un->Buffer == NULL || un->Length < 7 * sizeof(WCHAR))
        return FALSE;
    return _wcsnicmp(un->Buffer, L"\\??\\Z:\\", 7) == 0;
}

// 假映射基址表: NtUnmapViewOfSection 无句柄参数, 只有 BaseAddress; native 侧镜像
// 托管 FakeMappedBases, 记录由 Managed 分支成功映射的基址(数据映射 + 假 SEC_IMAGE)。
// 数量小(活跃映射几十个), SRWLOCK 保护即可; 表满时停止记录(保守 -> 走 Orig)。
#define FAKE_MAP_SLOTS 512
static SRWLOCK s_mapLock = SRWLOCK_INIT;
static ULONG_PTR s_fakeBases[FAKE_MAP_SLOTS];
static int s_fakeBaseCount;

static BOOLEAN IsFakeMappedBase(ULONG_PTR base)
{
    BOOLEAN hit = FALSE;
    if (base == 0)
        return FALSE;
    AcquireSRWLockShared(&s_mapLock);
    for (int i = 0; i < s_fakeBaseCount; i++)
    {
        if (s_fakeBases[i] == base)
        {
            hit = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&s_mapLock);
    return hit;
}

static void RecordFakeMappedBase(ULONG_PTR base)
{
    if (base == 0)
        return;
    AcquireSRWLockExclusive(&s_mapLock);
    for (int i = 0; i < s_fakeBaseCount; i++)
    {
        if (s_fakeBases[i] == base)
        {
            ReleaseSRWLockExclusive(&s_mapLock);
            return;
        }
    }
    if (s_fakeBaseCount < FAKE_MAP_SLOTS)
    {
        s_fakeBases[s_fakeBaseCount++] = base;
    }
    ReleaseSRWLockExclusive(&s_mapLock);
}

// 假数据 section 表: 托管 Hook_NtCreateSection 对非 SEC_IMAGE 假文件创建【真实内核
// section】并在托管侧注册(FakeSections: 真实句柄 -> 假字节), 后续 NtMapViewOfSection
// 需进 Managed 把假字节 memcpy 进 view。native 镜像该注册, 供 map/query/close 分流。
#define FAKE_SECTION_SLOTS 256
static SRWLOCK s_sectionLock = SRWLOCK_INIT;
static ULONG_PTR s_fakeDataSections[FAKE_SECTION_SLOTS];
static int s_fakeDataSectionCount;

static BOOLEAN IsFakeDataSection(HANDLE h)
{
    BOOLEAN hit = FALSE;
    ULONG_PTR v = (ULONG_PTR)h;
    if (v == 0)
        return FALSE;
    AcquireSRWLockShared(&s_sectionLock);
    for (int i = 0; i < s_fakeDataSectionCount; i++)
    {
        if (s_fakeDataSections[i] == v)
        {
            hit = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&s_sectionLock);
    return hit;
}

static void RecordFakeDataSection(ULONG_PTR h)
{
    if (h == 0)
        return;
    AcquireSRWLockExclusive(&s_sectionLock);
    for (int i = 0; i < s_fakeDataSectionCount; i++)
    {
        if (s_fakeDataSections[i] == h)
        {
            ReleaseSRWLockExclusive(&s_sectionLock);
            return;
        }
    }
    if (s_fakeDataSectionCount < FAKE_SECTION_SLOTS)
    {
        s_fakeDataSections[s_fakeDataSectionCount++] = h;
    }
    ReleaseSRWLockExclusive(&s_sectionLock);
}

// ---------------------------------------------------------------------------
// 守卫函数导出
// ---------------------------------------------------------------------------
SFMC_API void IncrSuppressHooks(void)
{
    _suppressHooks++;
}

SFMC_API void DecSuppressHooks(void)
{
    if (_suppressHooks > 0)
        _suppressHooks--;
}

SFMC_API int IsSuppressHooks(void)
{
    return _suppressHooks > 0 ? 1 : 0;
}

// 注册绑定; 返回 0 = 成功, -1 = 参数非法
SFMC_API int SetCallbacks(const SFMC_BINDINGS *bindings)
{
    if (bindings == NULL)
        return -1;
    memcpy(&s_bind, bindings, sizeof(SFMC_BINDINGS));
    return 0;
}

// ---------------------------------------------------------------------------
// PHASE11-AOT: 按名返回 Stub_* 地址。
// 背景: NativeAOT 单文件下 sfmc_hooks 以 static .lib 链入 exe, 符号不在 exe 导出表,
// 托管侧无法 NativeLibrary.GetExport —— 本函数是静态链接下按名取地址的唯一入口;
// shared 构建同样导出, 两种模式共用同一调用点。
// ---------------------------------------------------------------------------
SFMC_API void *SfmcGetExport(const char *name)
{
    if (name == NULL)
        return NULL;
    if (strcmp(name, "Stub_NtCreateFile") == 0)           return (void *)Stub_NtCreateFile;
    if (strcmp(name, "Stub_NtOpenFile") == 0)             return (void *)Stub_NtOpenFile;
    if (strcmp(name, "Stub_NtReadFile") == 0)             return (void *)Stub_NtReadFile;
    if (strcmp(name, "Stub_NtClose") == 0)                return (void *)Stub_NtClose;
    if (strcmp(name, "Stub_NtQueryInformationFile") == 0) return (void *)Stub_NtQueryInformationFile;
    if (strcmp(name, "Stub_NtQueryAttributesFile") == 0)  return (void *)Stub_NtQueryAttributesFile;
    if (strcmp(name, "Stub_NtQueryFullAttributesFile") == 0) return (void *)Stub_NtQueryFullAttributesFile;
    if (strcmp(name, "Stub_NtQueryVolumeInformationFile") == 0) return (void *)Stub_NtQueryVolumeInformationFile;
    if (strcmp(name, "Stub_NtSetInformationFile") == 0)   return (void *)Stub_NtSetInformationFile;
    if (strcmp(name, "Stub_NtCreateSection") == 0)        return (void *)Stub_NtCreateSection;
    if (strcmp(name, "Stub_NtMapViewOfSection") == 0)     return (void *)Stub_NtMapViewOfSection;
    if (strcmp(name, "Stub_NtUnmapViewOfSection") == 0)   return (void *)Stub_NtUnmapViewOfSection;
    if (strcmp(name, "Stub_NtQuerySection") == 0)         return (void *)Stub_NtQuerySection;
    if (strcmp(name, "Stub_NtQueryDirectoryFile") == 0)   return (void *)Stub_NtQueryDirectoryFile;
    if (strcmp(name, "Stub_NtQueryDirectoryFileEx") == 0) return (void *)Stub_NtQueryDirectoryFileEx;
    if (strcmp(name, "Stub_NtDuplicateObject") == 0)      return (void *)Stub_NtDuplicateObject;
    if (strcmp(name, "Stub_NtWriteFile") == 0)            return (void *)Stub_NtWriteFile;
    if (strcmp(name, "Stub_NtLockFile") == 0)             return (void *)Stub_NtLockFile;
    if (strcmp(name, "Stub_NtUnlockFile") == 0)           return (void *)Stub_NtUnlockFile;
    return NULL;
}

// ---------------------------------------------------------------------------
// 13 个守卫 stub (签名照 phnt)
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    if (IsSuppressHooks() > 0 || s_bind.NtCreateFile == NULL || !IsZPath(ObjectAttributes))
    {
        return s_bind.OrigNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    if (IsSuppressHooks() > 0 || s_bind.NtOpenFile == NULL || !IsZPath(ObjectAttributes))
    {
        return s_bind.OrigNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, ShareAccess, OpenOptions);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, ShareAccess, OpenOptions);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtReadFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    if (IsSuppressHooks() > 0 || s_bind.NtReadFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtClose(HANDLE Handle)
{
    if (IsSuppressHooks() > 0 || s_bind.NtClose == NULL
        || (!IsFakeFileHandle(Handle) && !IsFakeSectionHandle(Handle) && !IsFakeDataSection(Handle)))
    {
        return s_bind.OrigNtClose(Handle);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtClose(Handle);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtQueryInformationFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQueryInformationFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtQueryInformationFile(FileHandle, IoStatusBlock,
            FileInformation, Length, FileInformationClass);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQueryInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQueryAttributesFile == NULL || !IsZPath(ObjectAttributes))
    {
        return s_bind.OrigNtQueryAttributesFile(ObjectAttributes, FileInformation);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQueryAttributesFile(ObjectAttributes, FileInformation);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQueryFullAttributesFile == NULL || !IsZPath(ObjectAttributes))
    {
        return s_bind.OrigNtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtQueryVolumeInformationFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length,
    FS_INFORMATION_CLASS FsInformationClass)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQueryVolumeInformationFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtQueryVolumeInformationFile(FileHandle, IoStatusBlock,
            FsInformation, Length, FsInformationClass);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQueryVolumeInformationFile(FileHandle, IoStatusBlock,
        FsInformation, Length, FsInformationClass);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtSetInformationFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    if (IsSuppressHooks() > 0 || s_bind.NtSetInformationFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtSetInformationFile(FileHandle, IoStatusBlock,
            FileInformation, Length, FileInformationClass);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtSetInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
    NTSTATUS st = 0;
    if (IsSuppressHooks() > 0 || s_bind.NtCreateSection == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    }
    IncrSuppressHooks();
    st = s_bind.NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
        MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    DecSuppressHooks();
    // 托管可能返回真实内核 section(非 SEC_IMAGE data map)或假 section(0x52xxxxxx);
    // 前者需记录供后续 map/query/close 分流。
    if (st == 0 && SectionHandle != NULL && !IsFakeSectionHandle(*SectionHandle))
        RecordFakeDataSection((ULONG_PTR)*SectionHandle);
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
    NTSTATUS st = 0;
    if (IsSuppressHooks() > 0 || s_bind.NtMapViewOfSection == NULL
        || (!IsFakeSectionHandle(SectionHandle) && !IsFakeDataSection(SectionHandle)))
    {
        return s_bind.OrigNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
            ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition,
            AllocationType, Win32Protect);
    }
    IncrSuppressHooks();
    st = s_bind.NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
        ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition,
        AllocationType, Win32Protect);
    DecSuppressHooks();
    // 记录假映射基址(供 Stub_NtUnmapViewOfSection 分流; 托管回调成功时 *BaseAddress 已写)
    if (st == 0 && BaseAddress != NULL)
        RecordFakeMappedBase((ULONG_PTR)*BaseAddress);
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
    // Unmap 无句柄参数: 按 BaseAddress 是否假映射基址分流(native 镜像托管 FakeMappedBases)
    if (IsSuppressHooks() > 0 || s_bind.NtUnmapViewOfSection == NULL || !IsFakeMappedBase((ULONG_PTR)BaseAddress))
    {
        return s_bind.OrigNtUnmapViewOfSection(ProcessHandle, BaseAddress);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtQuerySection(HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation,
    SIZE_T SectionInformationLength, PSIZE_T ReturnLength)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQuerySection == NULL
        || (!IsFakeSectionHandle(SectionHandle) && !IsFakeDataSection(SectionHandle)))
    {
        return s_bind.OrigNtQuerySection(SectionHandle, SectionInformationClass,
            SectionInformation, SectionInformationLength, ReturnLength);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQuerySection(SectionHandle, SectionInformationClass,
        SectionInformation, SectionInformationLength, ReturnLength);
    DecSuppressHooks();
    return st;
}

// ---------------------------------------------------------------------------
// PHASE9: NtQueryDirectoryFile 守卫 stub (FindFirstFileW/FindNextFileW 核心)
// 只对假文件句柄(0x5100xxxx, 含目录假句柄)进入托管; 真实句柄/真实路径走 Orig。
// BOOLEAN (1 字节) 与 PUNICODE_STRING 直接透传, 不在 native 侧解释。
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQueryDirectoryFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, FileInformation, Length, FileInformationClass,
            ReturnSingleEntry, FileName, RestartScan);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan);
    DecSuppressHooks();
    return st;
}

// ---------------------------------------------------------------------------
// PHASE9 (续): NtQueryDirectoryFileEx 守卫 stub (Win11 25H2 kernelbase FindFirstFileExW
// 的实际调用目标)。QueryFlags: SL_RESTART_SCAN=1, SL_RETURN_SINGLE_ENTRY=2,
// SL_INDEX_SPECIFIED=4 —— 与 NtQueryDirectoryFile 的 RestartScan/ReturnSingleEntry 等价,
// 托管侧映射回同一业务体。
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags, PUNICODE_STRING FileName)
{
    if (IsSuppressHooks() > 0 || s_bind.NtQueryDirectoryFileEx == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, FileInformation, Length, FileInformationClass,
            QueryFlags, FileName);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length, FileInformationClass,
        QueryFlags, FileName);
    DecSuppressHooks();
    return st;
}

// ---------------------------------------------------------------------------
// PHASE16: NtDuplicateObject 守卫 stub —— kernelbase!DuplicateHandle 的 IAT 调用目标。
// JDK 25 FileChannelImpl.map -> duplicateForMapping -> DuplicateHandle(fake 文件句柄)
// 必须先可复制: 只对假文件句柄 (0x5100xxxx) 进托管 (托管侧新建假句柄共享同一 NativeBuffer,
// AddRef), 真实句柄/跨进程一律 Orig。
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Options)
{
    if (IsSuppressHooks() > 0 || s_bind.NtDuplicateObject == NULL || !IsFakeFileHandle(SourceHandle))
    {
        return s_bind.OrigNtDuplicateObject(SourceProcessHandle, SourceHandle,
            TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtDuplicateObject(SourceProcessHandle, SourceHandle,
        TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
    DecSuppressHooks();
    return st;
}

// ---------------------------------------------------------------------------
// PHASE18: NtWriteFile 守卫 stub (第 17 个钩子) —— natives 虚拟写 (Z:\cache\natives 可写区)。
// JVM 提取链 (JNA jna.tmpdir / LWJGL SharedLibraryExtractPath / Netty workdir) 经
// kernelbase WriteFile -> IAT 调本函数。只对假文件句柄 (0x5100xxxx) 进托管; 托管侧按
// AccessMode 分流 (只读句柄回 ACCESS_DENIED, 可写 natives 句柄写入可变缓冲); 真实句柄 Orig。
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtWriteFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
    if (IsSuppressHooks() > 0 || s_bind.NtWriteFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
    DecSuppressHooks();
    return st;
}

// ---------------------------------------------------------------------------
// PHASE18 (第 18/19 个钩子): NtLockFile/NtUnlockFile —— natives 虚拟锁 (tryLock 契约)。
// NativeLibrariesBootstrap.tryLock (FileChannelImpl.tryLock) 在 FileKey.init 成功后调用
// lock0 -> LockFile -> NtLockFile; 释放走 UnlockFile -> NtUnlockFile。只对假文件句柄进托管
// (托管侧授予/释放锁, 空操作即正确); 真实句柄走 Orig。
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtLockFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key,
    BOOLEAN FailImmediately, BOOLEAN ExclusiveLock)
{
    if (IsSuppressHooks() > 0 || s_bind.NtLockFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtLockFile(FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtLockFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock);
    DecSuppressHooks();
    return st;
}

SFMC_API NTSTATUS NTAPI Stub_NtUnlockFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length, ULONG Key)
{
    if (IsSuppressHooks() > 0 || s_bind.NtUnlockFile == NULL || !IsFakeFileHandle(FileHandle))
    {
        return s_bind.OrigNtUnlockFile(FileHandle, IoStatusBlock, ByteOffset, Length, Key);
    }
    IncrSuppressHooks();
    NTSTATUS st = s_bind.NtUnlockFile(FileHandle, IoStatusBlock, ByteOffset, Length, Key);
    DecSuppressHooks();
    return st;
}
