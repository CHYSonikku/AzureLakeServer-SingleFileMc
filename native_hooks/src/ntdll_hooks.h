// ============================================================================
//  ntdll_hooks.h — sfmc_hooks native lib 公共头
//
//  SingleFileMc Phase 3 (native 守卫 stub + 托管回调桥):
//    托管层(修改后 MinHook.NET)把 ntdll 函数 prologue patch 到本库的 Stub_*;
//    stub 只做 _suppressHooks 守卫 + Reverse P/Invoke 桥;业务逻辑在托管回调。
//
//  导出(shared):
//    IncrSuppressHooks / DecSuppressHooks / IsSuppressHooks  — thread-static 守卫
//    SetCallbacks(const SFMC_BINDINGS*)                     — 注册 13 回调 + 13 Orig
//    Stub_NtCreateFile ... Stub_NtQuerySection              — 13 个守卫 stub (hook 目标)
//
//  守卫机制:
//    static __declspec(thread) int _suppressHooks;
//    托管回调执行期间(含其内部任何 ntdll 调用), 同线程 _suppressHooks > 0 ->
//    再次进入任何 Stub_* 时直接走 Orig trampoline -> 零递归。
// ============================================================================
#ifndef SFMC_NTDLL_HOOKS_H
#define SFMC_NTDLL_HOOKS_H

#include <windows.h>
#include <winternl.h>

// ---------------------------------------------------------------------------
// winternl.h(用户态 SDK)未提供的结构, 按实际布局补齐(ntifs 才有)。
// stub 只透传指针, 不解释内容; 布局与托管侧一致即可。
// ---------------------------------------------------------------------------
typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
    ULONG Pad;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG Pad;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

// winternl.h 未提供的枚举(取 phnt 值); stub 只透传, 不解释数值
// (FILE_INFORMATION_CLASS 已由 winternl.h 定义, 此处不再定义)
typedef enum _FS_INFORMATION_CLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsSectorSizeInformation,
    FileFsDataCopyInformation,
    FileFsMetadataSizeInformation,
    FileFsFullSizeInformationEx,
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2,
} SECTION_INHERIT;

typedef enum _SECTION_INFORMATION_CLASS {
    SectionBasicInformation = 0,
    SectionImageInformation,
    SectionRelocationInformation,
    SectionOriginalBaseInformation,
    SectionInternalImageInformation,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

#ifdef __cplusplus
extern "C" {
#endif

// 导出宏: shared 构建 dllexport;static 构建供 linker 消费(符号直接可见)
#ifdef SFMC_BUILD_SHARED
#define SFMC_API __declspec(dllexport)
#else
#define SFMC_API
#endif

// ---------------------------------------------------------------------------
// 13 个托管回调函数指针类型(签名与 ntdll 导出完全一致, phnt; NTAPI = __stdcall)
// 托管侧对应 [UnmanagedCallersOnly(CallConvStdcall)] 静态方法。
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *PFN_CB_NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS (NTAPI *PFN_CB_NtOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions);

typedef NTSTATUS (NTAPI *PFN_CB_NtReadFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

// PHASE18: NtWriteFile (第 17 个钩子, natives 虚拟写)。签名与 NtReadFile 一致。
typedef NTSTATUS (NTAPI *PFN_CB_NtWriteFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

// PHASE18 (第 18 个钩子): NtLockFile —— NativeLibrariesBootstrap.tryLock 契约
// (FileChannelImpl.tryLock -> lock0 -> LockFile -> NtLockFile)。
typedef NTSTATUS (NTAPI *PFN_CB_NtLockFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key,
    BOOLEAN FailImmediately, BOOLEAN ExclusiveLock);

// PHASE18 (第 19 个钩子): NtUnlockFile —— FileLock.release / channel close 解锁。
typedef NTSTATUS (NTAPI *PFN_CB_NtUnlockFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length, ULONG Key);

typedef NTSTATUS (NTAPI *PFN_CB_NtClose)(HANDLE Handle);

typedef NTSTATUS (NTAPI *PFN_CB_NtQueryInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS (NTAPI *PFN_CB_NtQueryAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation);

typedef NTSTATUS (NTAPI *PFN_CB_NtQueryFullAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation);

typedef NTSTATUS (NTAPI *PFN_CB_NtQueryVolumeInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length,
    FS_INFORMATION_CLASS FsInformationClass);

typedef NTSTATUS (NTAPI *PFN_CB_NtSetInformationFile)(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS (NTAPI *PFN_CB_NtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

typedef NTSTATUS (NTAPI *PFN_CB_NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

typedef NTSTATUS (NTAPI *PFN_CB_NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS (NTAPI *PFN_CB_NtQuerySection)(HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation,
    SIZE_T SectionInformationLength, PSIZE_T ReturnLength);

// PHASE9 (registry 修复): NtQueryDirectoryFile —— FindFirstFileW/FindNextFileW 的核心。
// JDK 25 的 WindowsLinkSupport.getRealPath 逐路径组件调 FindFirstFile(不再用
// CreateFile+GetFinalPathNameByHandle), 目录枚举经本函数; 之前未 hook -> 真实内核收到
// 假句柄/不存在的 Z: -> 目录打开被托管侧拒绝 -> toRealPath NoSuchFileException ->
// vanilla pack 空 -> 注册表数据缺失崩溃。BOOLEAN 用 1 字节原生类型(byte)。
typedef NTSTATUS (NTAPI *PFN_CB_NtQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

// PHASE9 (续): NtQueryDirectoryFileEx —— Win11 25H2 kernelbase 的 FindFirstFileExW 走这个
// 新 API (NtQueryDirectoryFile 仅老调用方用)。签名 = NtQueryDirectoryFile 去掉
// ReturnSingleEntry/RestartScan, 换成 ULONG QueryFlags (SL_RESTART_SCAN=1,
// SL_RETURN_SINGLE_ENTRY=2, SL_INDEX_SPECIFIED=4)。托管侧映射回同一业务体。
typedef NTSTATUS (NTAPI *PFN_CB_NtQueryDirectoryFileEx)(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags, PUNICODE_STRING FileName);

// PHASE16: NtDuplicateObject —— kernelbase!DuplicateHandle 的唯一系统调用 (IAT)。
// JDK 25 FileChannelImpl.map -> duplicateForMapping -> DuplicateHandle(fake 句柄) 必须先可复制,
// 否则真内核以 STATUS_INVALID_HANDLE 拒绝 (jimage BasicImageReader "句柄无效" 根因)。
typedef NTSTATUS (NTAPI *PFN_CB_NtDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Options);

// ---------------------------------------------------------------------------
// 一次性绑定结构: 14 托管回调 + 14 Orig trampoline(MinHook.NET CreateHook 返回)
// 字段顺序 = 托管侧 SfmcBindings 的字段顺序(Sequential, 全部 8 字节指针)。
// ---------------------------------------------------------------------------
typedef struct _SFMC_BINDINGS {
    PFN_CB_NtCreateFile NtCreateFile;                 // 托管回调 (业务逻辑)
    PFN_CB_NtOpenFile NtOpenFile;
    PFN_CB_NtReadFile NtReadFile;
    PFN_CB_NtClose NtClose;
    PFN_CB_NtQueryInformationFile NtQueryInformationFile;
    PFN_CB_NtQueryAttributesFile NtQueryAttributesFile;
    PFN_CB_NtQueryFullAttributesFile NtQueryFullAttributesFile;
    PFN_CB_NtQueryVolumeInformationFile NtQueryVolumeInformationFile;
    PFN_CB_NtSetInformationFile NtSetInformationFile;
    PFN_CB_NtCreateSection NtCreateSection;
    PFN_CB_NtMapViewOfSection NtMapViewOfSection;
    PFN_CB_NtUnmapViewOfSection NtUnmapViewOfSection;
    PFN_CB_NtQuerySection NtQuerySection;
    PFN_CB_NtQueryDirectoryFile NtQueryDirectoryFile;
    PFN_CB_NtQueryDirectoryFileEx NtQueryDirectoryFileEx;
    // PHASE16: NtDuplicateObject (第 16 个钩子, JDK 25 FileChannelImpl.map 复制句柄)
    PFN_CB_NtDuplicateObject NtDuplicateObject;
    // PHASE18: NtWriteFile (第 17 个钩子, natives 虚拟写)
    PFN_CB_NtWriteFile NtWriteFile;
    // PHASE18 (第 18/19 个钩子): NtLockFile/NtUnlockFile (tryLock 契约)
    PFN_CB_NtLockFile NtLockFile;
    PFN_CB_NtUnlockFile NtUnlockFile;
    // Orig trampoline (MinHook.NET CreateHook 返回; 签名与回调一致)
    PFN_CB_NtCreateFile OrigNtCreateFile;
    PFN_CB_NtOpenFile OrigNtOpenFile;
    PFN_CB_NtReadFile OrigNtReadFile;
    PFN_CB_NtClose OrigNtClose;
    PFN_CB_NtQueryInformationFile OrigNtQueryInformationFile;
    PFN_CB_NtQueryAttributesFile OrigNtQueryAttributesFile;
    PFN_CB_NtQueryFullAttributesFile OrigNtQueryFullAttributesFile;
    PFN_CB_NtQueryVolumeInformationFile OrigNtQueryVolumeInformationFile;
    PFN_CB_NtSetInformationFile OrigNtSetInformationFile;
    PFN_CB_NtCreateSection OrigNtCreateSection;
    PFN_CB_NtMapViewOfSection OrigNtMapViewOfSection;
    PFN_CB_NtUnmapViewOfSection OrigNtUnmapViewOfSection;
    PFN_CB_NtQuerySection OrigNtQuerySection;
    PFN_CB_NtQueryDirectoryFile OrigNtQueryDirectoryFile;
    PFN_CB_NtQueryDirectoryFileEx OrigNtQueryDirectoryFileEx;
    PFN_CB_NtDuplicateObject OrigNtDuplicateObject;
    // PHASE18: NtWriteFile 的 Orig trampoline
    PFN_CB_NtWriteFile OrigNtWriteFile;
    // PHASE18 (第 18/19 个钩子): NtLockFile/NtUnlockFile 的 Orig trampoline
    PFN_CB_NtLockFile OrigNtLockFile;
    PFN_CB_NtUnlockFile OrigNtUnlockFile;
} SFMC_BINDINGS, *PSFMC_BINDINGS;

// ---------------------------------------------------------------------------
// 守卫函数(thread-static _suppressHooks)
// ---------------------------------------------------------------------------
SFMC_API void IncrSuppressHooks(void);
SFMC_API void DecSuppressHooks(void);
SFMC_API int  IsSuppressHooks(void);

// 注册绑定(托管侧在 EnableHooks 之前调用一次; bindings 被拷贝)
SFMC_API int  SetCallbacks(const SFMC_BINDINGS *bindings);

// PHASE11-AOT: 按名返回 Stub_* 地址 (static 链接下托管取 detour 目标的唯一入口;
// shared 构建同样导出, 两种模式共用)
SFMC_API void *SfmcGetExport(const char *name);

// ---------------------------------------------------------------------------
// 13 个守卫 stub —— MinHook 的 detour 目标
// ---------------------------------------------------------------------------
SFMC_API NTSTATUS NTAPI Stub_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

SFMC_API NTSTATUS NTAPI Stub_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions);

SFMC_API NTSTATUS NTAPI Stub_NtReadFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

SFMC_API NTSTATUS NTAPI Stub_NtClose(HANDLE Handle);

SFMC_API NTSTATUS NTAPI Stub_NtQueryInformationFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

SFMC_API NTSTATUS NTAPI Stub_NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation);

SFMC_API NTSTATUS NTAPI Stub_NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
    PFILE_NETWORK_OPEN_INFORMATION FileInformation);

SFMC_API NTSTATUS NTAPI Stub_NtQueryVolumeInformationFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length,
    FS_INFORMATION_CLASS FsInformationClass);

SFMC_API NTSTATUS NTAPI Stub_NtSetInformationFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

SFMC_API NTSTATUS NTAPI Stub_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

SFMC_API NTSTATUS NTAPI Stub_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

SFMC_API NTSTATUS NTAPI Stub_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

SFMC_API NTSTATUS NTAPI Stub_NtQuerySection(HANDLE SectionHandle,
    SECTION_INFORMATION_CLASS SectionInformationClass, PVOID SectionInformation,
    SIZE_T SectionInformationLength, PSIZE_T ReturnLength);

SFMC_API NTSTATUS NTAPI Stub_NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

SFMC_API NTSTATUS NTAPI Stub_NtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags, PUNICODE_STRING FileName);

// PHASE16: NtDuplicateObject 守卫 stub (第 16 个钩子)。只对假文件句柄进入托管;
// 真实句柄/非当前进程一律 Orig。
SFMC_API NTSTATUS NTAPI Stub_NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Options);

// PHASE18: NtWriteFile 守卫 stub (第 17 个钩子)。只对假文件句柄进入托管
// (托管侧按句柄 AccessMode 分流: 只读句柄回 ACCESS_DENIED); 其余走 Orig。
SFMC_API NTSTATUS NTAPI Stub_NtWriteFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

// PHASE18 (第 18 个钩子): NtLockFile 守卫 stub —— tryLock 契约。只对假文件句柄进入托管
// (托管侧授予锁); 真实句柄走 Orig。
SFMC_API NTSTATUS NTAPI Stub_NtLockFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG Key,
    BOOLEAN FailImmediately, BOOLEAN ExclusiveLock);

// PHASE18 (第 19 个钩子): NtUnlockFile 守卫 stub —— 解锁。只对假文件句柄进入托管。
SFMC_API NTSTATUS NTAPI Stub_NtUnlockFile(HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset,
    PLARGE_INTEGER Length, ULONG Key);

#ifdef __cplusplus
}
#endif

#endif // SFMC_NTDLL_HOOKS_H
