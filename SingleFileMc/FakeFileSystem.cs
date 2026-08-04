using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using MinHook;

namespace SingleFileMc;

/// <summary>
/// Spike: fake file I/O pipeline.
/// Hooks ntdll; any path starting with Z:\ (normalized \??\Z:\ / \\?\Z:\ / case-insensitive)
/// is redirected to a real file (容器激活时由 Container 服务; 否则回退 exe 旁磁盘别名, 见
/// JdkRoot/McDataRoot) and served from a fake-handle table backed by the real file's bytes.
/// Non-Z:\ paths fall through to the trampoline.
///
/// Hook set (12):
///   S2a (9): NtCreateFile NtOpenFile NtReadFile NtClose NtQueryInformationFile NtQueryAttributesFile
///            NtQueryFullAttributesFile NtQueryVolumeInformationFile NtSetInformationFile
///   S3a (3): NtCreateSection NtMapViewOfSection NtUnmapViewOfSection
///            - fake file handle -> REAL anonymous section of the file's byte length, stored as
///              FakeSection { byte[] Data }; NtMapViewOfSection maps it via the real kernel and
///              memcpy's the fake bytes in (data mapping only, SEC_COMMIT semantics; NO SEC_IMAGE /
///              PE layout — that is the blocked S2b); NtUnmapViewOfSection unmaps + deregisters.
///            PHASE12 勘误: 早期注释称 "kernelbase section 查询/关闭走 direct-syscall 绕过 ntdll
///            导出" 是错的 —— cdb 反汇编证明 kernelbase CreateFileW/CreateFileMappingW/MapViewOfFile
///            全链经 IAT 调 ntdll 导出 (零 direct syscall), 假句柄曾被真内核拒绝的真实原因是
///            当时未覆盖的 ntdll 导出 (NtUnmapViewOfSectionEx / EA 查询链等) 把假句柄传入真内核。
///            当前实现: 假 DATA section 走 REAL anonymous section (allocationAttributes 归一化
///            SEC_COMMIT 0x8000000, run12 最小复现契约), 完全绕开对假句柄的内核校验。
///
///   S3b (this spike): the fake byte cache lives in NATIVE memory (NativeMemory.Alloc) with
///            explicit refcounting (FakeFile owns 1 ref; each FakeSection sharing the buffer
///            AddRefs; freed when the last holder closes). A managed byte[] cache of a 15.9MB file
///            is an LOH allocation; combined with the CLR-side ReadAllBytes result it pushed
///            trigger_gc_for_alloc, and the GC's stomp_write_barrier -> ExecutableAllocator::MapRW
///            -> MapViewOfFile re-entered the NtMapViewOfSection detour -> managed hook ->
///            RareDisablePreemptiveGC -> WaitUntilGCComplete self-deadlock -> 0xC0000409 fail-fast
///            (crash4.dmp, WER subcode 0xC0000409). NativeMemory removes the hook-side LOH
///            sources; GC.TryStartNoGCRegion (Program.Main) removes the GC itself.
///
///   S3b (check 13, this spike): the JVM's ZipFile.Source reads the jar through
///            RandomAccessFile.seek -> SetFilePointerEx -> NtSetInformationFile(FilePositionInformation)
///            + readFully -> NtReadFile(NULL offset). Without a NtSetInformationFile hook the seek
///            hit the real kernel with our fabricated handle -> STATUS_INVALID_HANDLE -> ZipFile
///            ctor threw -> JarLoader invalidated the jar -> FindClass -> ClassNotFoundException.
///            Hook #12 (NtSetInformationFile, FilePositionInformation) + NtQueryInformationFile
///            FilePositionInformation make the fake handles seekable, completing the file-handle
///            contract for the JVM.
///
///   S2b (this spike): fake SEC_IMAGE section -> LoadLibraryExW of Z:\bin\*.dll straight from the
///            fake file bytes, WITHOUT any kernel section. KEY INSIGHT: the LoadLibrary path is
///            fully ntdll-export-driven (LdrLoadDll -> NtCreateFile/NtCreateSection/NtMapViewOfSection/
///            NtQuerySection/NtClose); unlike kernelbase's CreateFileMappingW path (S3a deviation),
///            nothing bypasses ntdll, so a FABRICATED section handle 0x52000000|n is never handed
///            to the real kernel. Hook #13 (NtQuerySection, SectionImageInformation/BasicInformation
///            for IsImage sections) + NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection/
///            NtClose branches:
///              - NtCreateSection(fake file, SEC_IMAGE): PURE fake section (PE headers parsed and
///                cached), no kernel call. Non-SEC_IMAGE keeps the verified REAL-anonymous-section
///                data path.
///              - NtMapViewOfSection(fake image section): manual PE layout - VirtualAlloc
///                (requested base or NULL, SizeOfImage, RESERVE|COMMIT, PAGE_EXECUTE_READWRITE;
///                requested-base failure -> STATUS_INVALID_IMAGE_BASE) + header copy + per-section
///                copy with zero-fill (VirtualSize > raw). No kernel call; the loader then does
///                relocation/imports/DllMain against OUR memory exactly as for a real SEC_IMAGE.
///              - NtUnmapViewOfSection(fake image base): VirtualFree(MEM_RELEASE).
///              - NtClose(fake image section): table remove only (no real kernel handle).
///            Loader three-map semantics (NULL -> != ImageBase -> unmap -> ImageBase retry ->
///            conflict -> NULL) is served by the VirtualAlloc base dance, per runtime trace.
///
/// JIT safety (S3a, mandatory): our hooks are managed code entered from native ntdll stubs.
/// Compiling a not-yet-JIT'd hook (or any managed call inside it) triggers the JIT, and the JIT
/// itself calls ntdll (VirtualAlloc, file reads, ...) -> re-enters our hooks -> recursion/stack
/// overflow. Mechanism (4 parts, all applied):
///   1. Thread-static suppression flag: every hook entry's first line is
///      `if (_suppressHooks > 0) return Trampoline(...)` — while suppressed, pass straight through.
///   2. Every hook body runs inside a `_suppressHooks++ / try / finally _suppressHooks--` scope
///      (whole-body scope = superset of per-call scopes; zero gap between entry check and scope).
///   3. All hook methods are compiled up front via RuntimeHelpers.PrepareMethod BEFORE any
///      detour is installed, so entering a hook never triggers JIT (JIT mode only).
///   4. TieredCompilation is disabled (runtimeconfig System.Runtime.TieredCompilation=false,
///      plus AppContext.SetSwitch in Main) so every method compiles once to its final form and no
///      background recompilation can JIT on a hooked stack.
///
/// DETOUR MECHANISM (Phase 3): 修改后 MinHook.NET(纯托管 MinHook 移植)把 ntdll 函数 prologue
/// patch 到 native 守卫 stub 库(sfmc_hooks_shared, 见 native_hooks/)。stub 只做三件事:
///   Stub_NtCreateFile(...) {
///       if (IsSuppressHooks() > 0) return Orig_NtCreateFile(...);  // 守卫 -> trampoline
///       IncrSuppressHooks();                                        // native 自动 ++
///       NTSTATUS r = Managed_NtCreateFile(...);                    // Reverse P/Invoke -> 托管回调
///       DecSuppressHooks();                                         // native 自动 --
///       return r;
///   }
/// - _suppressHooks 是 native thread-static 计数器: 托管回调(及其中间 JIT/File.Exists 等任何
///   ntdll 调用)执行期间同线程 > 0 -> 再入任何 stub 直接走 Orig trampoline -> 零递归, 与旧
///   托管 [ThreadStatic] 守卫等价但更快(原生层第一行判断)。
/// - Orig_* 由 MinHook.NET CreateHook(IntPtr target, IntPtr nativeDetour) 返回的 trampoline 地址
///   填充(新增原生重载, 见 third_party\Minhook.NET\MinHook.NET\HookEngine.cs MODIFIED 注释);
///   托管侧同时用该地址生成 pass-through 委托(_orig*), 供回调内非 Z: 路径透传。
/// - 托管业务仍是 [UnmanagedCallersOnly] 静态方法(经 native 桥进入, 无 delegate thunk;
///   AOT 安全: UnmanagedCallersOnly + LibraryImport + delegate* 函数指针, 无反射)。
/// - 与旧 delegate detour 对比: 托管 hook 方法不再被 GetFunctionPointerForDelegate 包装,
///   hook 安装 = CreateHook(ntdllExport, Stub_* 地址), 与 MonoMod compileMethod JitHook 的
///   fail-fast 结构上仍不可能(MinHook 无托管 JIT hook)。
/// </summary>
internal static partial class FakeFileSystem
{
    // ---- JIT safety: thread-local hook suppression flag ----
    // Read/written by every hook (plain ldsfld/stsfld, no managed call -> no JIT risk itself).
    [ThreadStatic]
    private static int _suppressHooks;

    // ---- x64 struct layouts (phnt) ----
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct UNICODE_STRING
    {
        public ushort Length;          // byte count, not char count
        public ushort MaximumLength;
        public char* Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct OBJECT_ATTRIBUTES
    {
        public uint Length;                        // 0x00
        public IntPtr RootDirectory;               // 0x08
        public UNICODE_STRING* ObjectName;         // 0x10
        public uint Attributes;                    // 0x18
        public IntPtr SecurityDescriptor;          // 0x20
        public IntPtr SecurityQualityOfService;    // 0x28  (total 0x30 = 48)
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    // ---- NTSTATUS constants ----
    private const int STATUS_OBJECT_NAME_NOT_FOUND = unchecked((int)0xC0000034);
    private const int STATUS_INVALID_INFO_CLASS = unchecked((int)0xC0000003);
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const int STATUS_NO_MEMORY = unchecked((int)0xC0000017);
    private const int STATUS_INVALID_IMAGE_FORMAT = unchecked((int)0xC000007B);
    private const int STATUS_INVALID_IMAGE_BASE = unchecked((int)0xC0000090);
    private const int STATUS_UNSUCCESSFUL = unchecked((int)0xC0000001);
    // PHASE9: 目录枚举状态 (NtQueryDirectoryFile; FindNextFileW 依赖 NO_MORE_FILES)
    private const int STATUS_NO_MORE_FILES = unchecked((int)0x80000006);
    private const int STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005);

    // ---- PHASE16: NtDuplicateObject (JDK 25 FileChannelImpl.map 复制句柄) ----
    private static readonly IntPtr NtCurrentProcess = new(-1);
    private const uint DUPLICATE_CLOSE_SOURCE = 0x1;

    // ---- S2b: SEC_IMAGE + VirtualAlloc flags ----
    private const uint SEC_IMAGE = 0x1000000u;
    // JVM jimage 映射 lib\modules 时带的"镜像无执行"标志 (JDK 25 W^X 加固)。
    // 匿名 REAL section 保留/剥离该标志均被内核镜像语义拒绝 (run12 证据: create 0xC00000F4
    // INVALID_IMAGE_NOT_MZ / map 0xC0000022·0xC000001F) —— 该标志走假 DATA section (见
    // Hook_NtCreateSection), 完全绕开内核 section 语义。
    private const uint SEC_IMAGE_NO_EXECUTE = 0x8000000u;
    // 25H2 内核契约 (run12 最小复现): 匿名 section 必须带 SEC_IMAGE_NO_EXECUTE, 否则内核按
    // 镜像语义拒绝 (0xC00000F4 INVALID_IMAGE_NOT_MZ); SEC_COMMIT 需剥离 (组合同样被拒)。
    private const uint MEM_RESERVE = 0x2000u;
    private const uint MEM_COMMIT = 0x1000u;
    private const uint MEM_RELEASE = 0x8000u;
    private const uint PAGE_READONLY = 0x02u;
    private const uint PAGE_READWRITE = 0x04u;
    private const uint PAGE_EXECUTE_READWRITE = 0x40u;
    // FakeMappedBases values: 1 = data map (real NtUnmapViewOfSection), 2 = image map (VirtualFree)
    private const int MapKindData = 1;
    private const int MapKindImage = 2;

    // ---- real disk alias roots (回退, 仅无容器调试) ----
    // 全部 exe 旁相对 (AppContext.BaseDirectory 运行时动态获取), 无任何硬编码绝对路径。
    // static readonly 字段: 类初始化发生在任何 detour 安装之前 (WarmupTeardown 首次触达),
    // 故 hook 栈上读取它们无 JIT 风险 (Path.Combine 2 参重载已由 McLaunch.Warmup 预热)。
    // 磁盘 JDK 树根: <exe>\jdk\  (Z:\bin\java.dll -> <exe>\jdk\bin\java.dll;
    //  Z:\openjdk\... 顶层段剥除 -> <exe>\jdk\...)
    private static readonly string JdkRoot = Path.Combine(AppContext.BaseDirectory, "jdk");
    // 磁盘 MC 数据树根: <exe>\Minecraft\  (Z:\minecraft\... -> <exe>\Minecraft\...,
    //  PHASE13 换层: minecraft 顶层 = .minecraft 内容, 无 .minecraft 中间段)
    private static readonly string McDataRoot = Path.Combine(AppContext.BaseDirectory, "Minecraft");

    // ---- lib\modules 已去物化 (PHASE16, 详见 PHASE16-ZERODISK-FINAL.md) ----
    // PHASE15 曾断言 "kernelbase 走 direct-syscall, lib\modules 必须物化", 依据是 S3a 时代
    // 注释 —— PHASE12 cdb 反汇编 + PHASE16 源码/反汇编/运行日志三重实测已推翻:
    //   1) 源码 (jdk-25+25 osSupport_windows.cpp): map_memory = CreateFileA -> CreateFileMappingA
    //      -> MapViewOfFileEx (全 kernelbase API, 按名重开文件); openReadOnly = CRT _open ->
    //      CreateFileW; read = ReadFile。
    //   2) 反汇编 (本地 jimage.dll, 容器实际二进制, 带符号): osSupport::map_memory 反汇编确认
    //      _imp_CreateFileA / _imp_CreateFileMappingA / _imp_MapViewOfFileEx / _imp_CloseHandle×2。
    //      PHASE12: kernelbase CreateFileInternal->_imp_NtCreateFile、CreateFileMappingW->
    //      _imp_NtCreateSection、MapViewOfFileEx->_imp_NtMapViewOfSection —— 全经 IAT, 零 direct syscall。
    //   3) 运行日志 (run12-container-d6.log): [CreateFileW] Z: -> real 'Z:\lib\modules' (kernelbase
    //      hook 命中) + [NtCreateFile] REAL modules '\??\Z:\lib\modules' (ntdll hook 命中)。
    // 结论: jimage 打开+映射链完全在 hook 面内, 假句柄 + 假 DATA section 即可服务
    // (与 MC 数据树 jar 同机制), 真实文件物化无必要。ModulesRealPath 恒 null, 相关特判失效。
    // 下方 MaterializeModulesFile 保留为历史工具 (不再被调用); conf 树物化另见
    // GetOrMaterializeConfFile (PHASE16 阶段1 一并移除)。
    /// <summary>临时物化/提取根: <exe>\game\cache (gameDir 内统一管理, 退出时清理)。</summary>
    public static readonly string CacheRoot = Path.Combine(AppContext.BaseDirectory, "game", "cache");

    public static string? ModulesRealPath;

    public static void MaterializeModulesFile()
    {
        if (!Container.Active) { return; }
        string key = Container.JdkPrefix + "/lib/modules";
        if (!Container.HasEntry(key)) { return; }
        string dir = Path.Combine(CacheRoot, "modules");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "modules");
        long len = Container.GetLength(key);
        if (!File.Exists(path) || new FileInfo(path).Length != len)
        {
            byte[] data = Container.ReadAllBytes(key);
            File.WriteAllBytes(path, data);
            Console.WriteLine($"[prejit] materialized modules file: {path} ({data.Length} B)");
        }
        else
        {
            Console.WriteLine($"[prejit] modules file exists: {path} ({len} B)");
        }
        ModulesRealPath = path;
    }

    // ---- JDK conf 树物化 (run12): JVM 的 java.io.FileInputStream (Security.loadMaster 读
    // conf\security\java.security 等) 走 kernelbase CreateFileW direct-syscall, 完全绕过 ntdll
    // hook —— 假句柄方案对这类打开无效。预热期把容器 jdkPrefix/conf/** 物化到
    // <gameDir>\cache\modules\conf\, 再以托管 detour hook kernelbase!CreateFileW 重写路径。
    private static readonly ConcurrentDictionary<string, string> ConfMaterialized = new(StringComparer.Ordinal);

    /// <summary>容器键 (jdkPrefix/conf/...) -> 真实物化路径 (win32 形式, CreateFileW 用)。</summary>
    public static string GetOrMaterializeConfFile(string key)
    {
        if (ConfMaterialized.TryGetValue(key, out string? cached)) { return cached; }
        string dir = Path.Combine(CacheRoot, "modules", "conf");
        string path = Path.Combine(dir, key[(Container.JdkPrefix.Length + 1)..].Replace('/', '\\'));
        long len = Container.GetLength(key);
        if (!File.Exists(path) || new FileInfo(path).Length != len)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            byte[] data = Container.ReadAllBytes(key);
            File.WriteAllBytes(path, data);
            Log($"[CreateFileW] materialized conf: {key} -> {path} ({data.Length} B)");
        }
        ConfMaterialized[key] = path;
        return path;
    }

    // ---- phnt signatures (NTSTATUS int, HANDLE IntPtr) ----
    private delegate int D_NtCreateFile(out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objAttr,
        out IO_STATUS_BLOCK ioStatus, IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

    private delegate int D_NtOpenFile(out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objAttr,
        out IO_STATUS_BLOCK ioStatus, uint shareAccess, uint openOptions);

    private delegate int D_NtReadFile(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        out IO_STATUS_BLOCK ioStatus, IntPtr buffer, uint length, IntPtr byteOffset, IntPtr key);

    private delegate int D_NtClose(IntPtr handle);

    private delegate int D_NtQueryInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass);

    private delegate int D_NtQueryAttributesFile(ref OBJECT_ATTRIBUTES objAttr, IntPtr fileInformation);

    private delegate int D_NtQueryFullAttributesFile(ref OBJECT_ATTRIBUTES objAttr, IntPtr fileInformation);

    private delegate int D_NtQueryVolumeInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fsInformation, uint length, int fsInformationClass);

    private delegate int D_NtSetInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass);

    private delegate int D_NtCreateSection(out IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes,
        IntPtr maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle);

    // S2b byref workaround: baseAddress/viewSize/sectionOffset arrive as PLAIN IntPtr POINTERS TO
    // THE CALLER'S SLOTS (native ABI: pointer-sized value, zero-copy through the reverse-P/Invoke
    // stub), NOT as CLR `ref` byrefs. A `ref long sectionOffset` byref receives NULL when the
    // loader passes NULL for the optional SectionOffset (LdrpMinimalMapModule), and the CLR
    // write-back through that NULL byref NREs on the hooked stack (runS2b-5..20, NRE at
    // MapImageIntoMemory write-back; base/view refs wrote fine, the NULL offset ref NRE'd).
    // Explicit IntPtr + null-guarded writes eliminate the CLR byref marshaling entirely.
    private delegate int D_NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, IntPtr baseAddressPtr,
        IntPtr zeroBits, UIntPtr commitSize, IntPtr sectionOffsetPtr, IntPtr viewSizePtr,
        int inheritDisposition, uint allocationType, uint win32Protect);

    private delegate int D_NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress);

    private delegate int D_NtQuerySection(IntPtr sectionHandle, int sectionInformationClass, IntPtr sectionInformation,
        UIntPtr sectionInformationLength, IntPtr returnLength);

    // PHASE9 (registry 修复): NtQueryDirectoryFile —— FindFirstFileW/FindNextFileW 核心
    // (JDK25 WindowsLinkSupport.getRealPath 逐组件目录枚举依赖)。BOOLEAN 用 byte
    // (1 字节原生类型; bool 是 4 字节, marshaling 会错位)。
    private delegate int D_NtQueryDirectoryFile(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        out IO_STATUS_BLOCK ioStatus, IntPtr fileInformation, uint length, int fileInformationClass,
        byte returnSingleEntry, IntPtr fileNamePtr, byte restartScan);

    // PHASE9 (续): NtQueryDirectoryFileEx —— Win11 25H2 kernelbase FindFirstFileExW 走这个
    // 新 API。无 ReturnSingleEntry/RestartScan, 用 ULONG QueryFlags
    // (SL_RESTART_SCAN=1, SL_RETURN_SINGLE_ENTRY=2, SL_INDEX_SPECIFIED=4)。
    private delegate int D_NtQueryDirectoryFileEx(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        out IO_STATUS_BLOCK ioStatus, IntPtr fileInformation, uint length, int fileInformationClass,
        uint queryFlags, IntPtr fileNamePtr);

    // PHASE16: NtDuplicateObject —— kernelbase!DuplicateHandle 的唯一系统调用 (IAT,
    // cdb 反汇编确认)。JDK 25 FileChannelImpl.map -> duplicateForMapping 复制句柄。
    private delegate int D_NtDuplicateObject(IntPtr sourceProcessHandle, IntPtr sourceHandle,
        IntPtr targetProcessHandle, out IntPtr targetHandle, uint desiredAccess, uint handleAttributes, uint options);

    // ---- original function pointers (trampolines) ----
    // Phase 3: 由修改后 MinHook.NET CreateHook(IntPtr, IntPtr) 返回的 trampoline 地址生成的
    // pass-through 委托(托管回调内非 Z: 路径透传; native stub 的 Orig 用同一地址)。
    private static D_NtCreateFile? _origNtCreateFile;
    private static D_NtOpenFile? _origNtOpenFile;
    private static D_NtReadFile? _origNtReadFile;
    private static D_NtClose? _origNtClose;
    private static D_NtQueryInformationFile? _origNtQueryInformationFile;
    private static D_NtQueryAttributesFile? _origNtQueryAttributesFile;
    private static D_NtQueryFullAttributesFile? _origNtQueryFullAttributesFile;
    private static D_NtQueryVolumeInformationFile? _origNtQueryVolumeInformationFile;
    private static D_NtSetInformationFile? _origNtSetInformationFile;
    private static D_NtCreateSection? _origNtCreateSection;
    private static D_NtMapViewOfSection? _origNtMapViewOfSection;
    private static D_NtUnmapViewOfSection? _origNtUnmapViewOfSection;
    private static D_NtQuerySection? _origNtQuerySection;
    private static D_NtQueryDirectoryFile? _origNtQueryDirectoryFile;
    private static D_NtQueryDirectoryFileEx? _origNtQueryDirectoryFileEx;
    private static D_NtDuplicateObject? _origNtDuplicateObject;

    // ---- fake handle table: handle -> file bytes + position + name ----
    // S3b: the byte cache is a NATIVE buffer (NativeBuffer) with explicit refcounting; see
    // ReleaseBuffer. A managed byte[] cache would be an LOH allocation that feeds the GC
    // self-deadlock described in the class doc.
    private sealed unsafe class NativeBuffer
    {
        public byte* Data;        // NativeMemory.Alloc'ed, valid while RefCount > 0
        public int Length;
        public int RefCount;      // 1 = FakeFile owner; every sharing FakeSection adds 1
    }

    private sealed unsafe class FakeFile
    {
        public NativeBuffer? Buf;
        public int Pos;
        public int ReadCount;
        public string Name = "";
        // PHASE9 (registry 修复): 目录假句柄支持 —— FindFirstFileW 打开 Z: 目录时返回
        // IsDir 假句柄; NtQueryDirectoryFile 从 Real 真实目录枚举条目 (DirEntries 缓存)。
        public bool IsDir;
        public string Real = "";
        public DirEntry[]? DirEntries;   // 已按 pattern 过滤的枚举缓存 (仅匹配项)
        public string DirPattern = "";   // 缓存对应的 pattern
        public int DirIndex;             // FindNextFileW 游标
    }

    /// <summary>PHASE9: 单个目录条目快照 (NtQueryDirectoryFile 写记录用; 时间为 FILETIME)。</summary>
    private readonly struct DirEntry
    {
        public readonly string Name;
        public readonly bool IsDir;
        public readonly long Length;
        public readonly long Creation;
        public readonly long LastAccess;
        public readonly long LastWrite;
        public readonly long Change;

        public DirEntry(string name, bool isDir, long length, long creation, long lastAccess, long lastWrite, long change)
        {
            Name = name;
            IsDir = isDir;
            Length = length;
            Creation = creation;
            LastAccess = lastAccess;
            LastWrite = lastWrite;
            Change = change;
        }
    }

    private static readonly ConcurrentDictionary<IntPtr, FakeFile> FakeHandles = new();
    private static int _handleCounter;

    // ---- S3a/S2b: fake sections (handle -> shared file buffer) and fake mapped view bases ----
    /// <summary>
    /// S2b: PE headers cached at NtCreateSection time (parsed once from the native file buffer).
    /// Field set = exactly what SECTION_IMAGE_INFORMATION / the manual layout need.
    /// </summary>
    private sealed class PeInfo
    {
        public int FileSize;
        public long ImageBase;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint AddressOfEntryPoint;
        public long SizeOfStackReserve;
        public long SizeOfStackCommit;
        public ushort Subsystem;
        // SII naming: SubSystem{Minor,Major}@0x24/0x26 <-> PE MajorSubsystemVersion@+48/Minor@+50
        public ushort SubSystemMinorVersion;
        public ushort SubSystemMajorVersion;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public ushort Characteristics;   // COFF Characteristics (@e_lfanew+0x16)
        public uint LoaderFlags;
        public ushort DllCharacteristics;
        // S2b: the ACTUAL base of the last map (0 = not mapped yet / preferred base was used);
        // SII TransferAddress must follow the real mapping for relocated images.
        public long ActualBase;
        public (int VirtualAddress, int VirtualSize, int SizeOfRawData, int PointerToRawData)[] Sections = [];
    }

    private sealed unsafe class FakeSection
    {
        public NativeBuffer? Buf; // shares the FakeFile's buffer (refcounted, see Hook_NtCreateSection)
        public string Name = "";
        // S2b: true = SEC_IMAGE fake section (fabricated handle 0x52000000|n, no kernel object);
        // false = S3a data section (REAL anonymous kernel section, real handle).
        public bool IsImage;
        public PeInfo? Pe; // parsed at section-create time (IsImage only)
    }

    private static readonly ConcurrentDictionary<IntPtr, FakeSection> FakeSections = new();
    // value: MapKindData (real unmap) or MapKindImage (VirtualFree)
    private static readonly ConcurrentDictionary<IntPtr, int> FakeMappedBases = new();
    private static int _sectionCounter;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFree(IntPtr lpAddress, nuint dwSize, uint dwFreeType);

    // ---- detour layer (Phase 3: 修改后 MinHook.NET + native 守卫 stub 桥) ----
    // HookEngine: CreateHook(target, nativeDetour) -> Orig trampoline 地址(新增原生重载);
    // EnableHook/DisableHook patch/restore 单个 hook 的 5 字节 prologue; Dispose() 全部禁用+释放。
    // NOTE: EnableHook/DisableHook 挂起其他进程线程(MinHook.NET 设计)。Init 时 JVM 不存在、
    // Shutdown 时 JVM 线程已停 -> 挂起窗口安全(与旧 delegate 版一致)。
    private static readonly HookEngine HookEngine = new();
    private static bool _engineActive;
    // Keep the ORIG pass-through delegates alive (native stub 的 Orig 由 trampoline 地址填充,
    // 托管回调内非 Z: 路径经此 delegate 调 trampoline; static 字段已持有, 列表是 belt-and-braces)。
    private static readonly List<Delegate> _hookDelegates = [];
    private static readonly object LogLock = new();

    // ---- Phase 3: native 守卫 stub 库 (sfmc_hooks_shared) 绑定 ----
    // 布局 = native_hooks/src/ntdll_hooks.h 的 SFMC_BINDINGS(26 个 8 字节指针, 顺序一致)。
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SfmcBindings
    {
        // 13 个托管回调 [UnmanagedCallersOnly] thunk 地址
        public IntPtr NtCreateFile;
        public IntPtr NtOpenFile;
        public IntPtr NtReadFile;
        public IntPtr NtClose;
        public IntPtr NtQueryInformationFile;
        public IntPtr NtQueryAttributesFile;
        public IntPtr NtQueryFullAttributesFile;
        public IntPtr NtQueryVolumeInformationFile;
        public IntPtr NtSetInformationFile;
        public IntPtr NtCreateSection;
        public IntPtr NtMapViewOfSection;
        public IntPtr NtUnmapViewOfSection;
        public IntPtr NtQuerySection;
        // PHASE9: 第 14/15 个钩子 (FindFirstFileW/FindNextFileW 核心, 目录枚举; Ex 版供
        // Win11 25H2 kernelbase 的 FindFirstFileExW)
        public IntPtr NtQueryDirectoryFile;
        public IntPtr NtQueryDirectoryFileEx;
        // PHASE16: NtDuplicateObject (第 16 个钩子, JDK 25 FileChannelImpl.map 复制句柄)
        public IntPtr NtDuplicateObject;
        // 15 个 Orig trampoline (MinHook.NET CreateHook 返回)
        public IntPtr OrigNtCreateFile;
        public IntPtr OrigNtOpenFile;
        public IntPtr OrigNtReadFile;
        public IntPtr OrigNtClose;
        public IntPtr OrigNtQueryInformationFile;
        public IntPtr OrigNtQueryAttributesFile;
        public IntPtr OrigNtQueryFullAttributesFile;
        public IntPtr OrigNtQueryVolumeInformationFile;
        public IntPtr OrigNtSetInformationFile;
        public IntPtr OrigNtCreateSection;
        public IntPtr OrigNtMapViewOfSection;
        public IntPtr OrigNtUnmapViewOfSection;
        public IntPtr OrigNtQuerySection;
        public IntPtr OrigNtQueryDirectoryFile;
        public IntPtr OrigNtQueryDirectoryFileEx;
        public IntPtr OrigNtDuplicateObject;
    }

    // ---- PHASE11-AOT: native 守卫绑定 (AOT/JIT 双模式) ----
    // JIT 模式: sfmc_hooks_shared.dll 动态加载, LibraryImport("sfmc_hooks_shared") 按名解析;
    // NativeAOT 模式: sfmc_hooks_static.lib 经 <NativeLibrary> 静态链入 exe,
    // LibraryImport("__Internal") 由 AOT 链接器直接解析符号 (零外部依赖)。
    // 运行时分派: RuntimeFeature.IsDynamicCodeSupported == false 即 NativeAOT。
    private static readonly bool NativeAot = !RuntimeFeature.IsDynamicCodeSupported;

    [LibraryImport("sfmc_hooks_shared", EntryPoint = "SetCallbacks")]
    private static unsafe partial int NativeSetCallbacksShared(SfmcBindings* bindings);

    [LibraryImport("__Internal", EntryPoint = "SetCallbacks")]
    private static unsafe partial int NativeSetCallbacksAot(SfmcBindings* bindings);

    [LibraryImport("sfmc_hooks_shared", EntryPoint = "IsSuppressHooks")]
    private static partial int NativeIsSuppressHooksShared();

    [LibraryImport("__Internal", EntryPoint = "IsSuppressHooks")]
    private static partial int NativeIsSuppressHooksAot();

    // SfmcGetExport: 按名取 Stub_* 地址 (AOT: 静态链接符号; JIT: shared dll 导出表)。
    // 静态链接下符号不在 exe 导出表, NativeLibrary.GetExport 不可用 —— 这是唯一入口。
    [LibraryImport("sfmc_hooks_shared", EntryPoint = "SfmcGetExport", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint NativeGetExportShared(string name);

    [LibraryImport("__Internal", EntryPoint = "SfmcGetExport", StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint NativeGetExportAot(string name);

    private static unsafe int NativeSetCallbacks(SfmcBindings* bindings)
        => NativeAot ? NativeSetCallbacksAot(bindings) : NativeSetCallbacksShared(bindings);

    private static int NativeIsSuppressHooks()
        => NativeAot ? NativeIsSuppressHooksAot() : NativeIsSuppressHooksShared();

    private static nint NativeGetExport(string name)
        => NativeAot ? NativeGetExportAot(name) : NativeGetExportShared(name);

    // ------------------------------------------------------------------ init

    public static unsafe void Init()
    {
        if (_origNtCreateFile != null) { return; } // already initialized

        DebugHelpers.AssertLayouts();

        // JIT safety part 3: compile every hook method to its final form BEFORE installing any
        // detour. With TieredCompilation disabled (runtimeconfig) this is a full-optimization
        // compilation, so the moment the first ntdll call enters a hook, no JIT can run on the
        // hooked stack (JIT -> ntdll -> hook -> JIT recursion is the crash we are preventing).
        // PHASE11-AOT: NativeAOT 无 JIT —— 方法已全量编译, 反射预热无意义, 跳过。
        if (!NativeAot) { PrepareHooks(); }

        var ntdll = NativeLibrary.Load("ntdll.dll");

        // NOTE (Phase 3 / native stub switch): the MinHook.NET delegate-detour path is GONE.
        // 托管 hook 不再经 Marshal.GetFunctionPointerForDelegate 包装; detour 目标是 native lib
        // 的守卫 stub(Stub_*), 由修改后 MinHook.NET 的 CreateHook(IntPtr, IntPtr) 原生重载安装,
        // 返回 Orig trampoline 地址。托管业务逻辑在 [UnmanagedCallersOnly] 回调中, 经 stub 桥调用。
        // 旧 WarmupThunks 问题的等价物已不存在: 回调首次被 NATIVE 入口触发时经合法
        // unmanaged->managed 过渡(JVM 线程处于 preemptive 模式), 且回调内 JIT 由 native
        // _suppressHooks 守卫兜底(见类文档)。

        // 全量 hook 集(9 S2a + 4 S3a/S2b): 文件句柄层(NtCreateFile..NtSetInformationFile) +
        // 内存映射层(NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection/NtQuerySection)。
        // Phase 3: native 守卫 stub 库加载。PHASE11-AOT: JIT 模式加载 shared dll (csproj 后置拷贝
        // 到输出目录, 显式绝对路径不依赖进程 CWD); NativeAOT 模式 sfmc_hooks_static.lib 已静态
        // 链入 exe, 无任何外部 dll —— 符号经 __Internal 直接解析。
        nint hHooks = IntPtr.Zero;
        if (!NativeAot)
        {
            string hookLibPath = Path.Combine(AppContext.BaseDirectory, "sfmc_hooks_shared.dll");
            try
            {
                hHooks = NativeLibrary.Load(hookLibPath);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"无法加载 native 守卫 stub 库 {hookLibPath} (Phase 3):\n{ex}");
            }
            Log($"[hooks] native lib sfmc_hooks_shared loaded @0x{hHooks.ToInt64():X}");
        }
        else
        {
            Log("[hooks] NativeAOT: sfmc_hooks_static.lib 静态链接, 符号经 __Internal 解析 (零外部依赖)");
        }

        // 组装一次性绑定: 13 托管回调 + 13 Orig trampoline(全量安装)。
        SfmcBindings b = default;

        // ---- S2a: file-handle layer (create/open/read/close/query/seek) ----
        b.NtCreateFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr*, uint, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, IntPtr, uint, uint, uint, uint, IntPtr, uint, int>)&Managed_NtCreateFile;
        b.OrigNtCreateFile = InstallNativeHook(ntdll, hHooks, "NtCreateFile", out _origNtCreateFile);
        b.NtOpenFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr*, uint, OBJECT_ATTRIBUTES*, IO_STATUS_BLOCK*, uint, uint, int>)&Managed_NtOpenFile;
        b.OrigNtOpenFile = InstallNativeHook(ntdll, hHooks, "NtOpenFile", out _origNtOpenFile);
        b.NtReadFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr, IO_STATUS_BLOCK*, IntPtr, uint, IntPtr, IntPtr, int>)&Managed_NtReadFile;
        b.OrigNtReadFile = InstallNativeHook(ntdll, hHooks, "NtReadFile", out _origNtReadFile);
        b.NtClose = (nint)(delegate* unmanaged[Stdcall]<IntPtr, int>)&Managed_NtClose;
        b.OrigNtClose = InstallNativeHook(ntdll, hHooks, "NtClose", out _origNtClose);
        b.NtQueryInformationFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IO_STATUS_BLOCK*, IntPtr, uint, int, int>)&Managed_NtQueryInformationFile;
        b.OrigNtQueryInformationFile = InstallNativeHook(ntdll, hHooks, "NtQueryInformationFile", out _origNtQueryInformationFile);
        b.NtQueryAttributesFile = (nint)(delegate* unmanaged[Stdcall]<OBJECT_ATTRIBUTES*, IntPtr, int>)&Managed_NtQueryAttributesFile;
        b.OrigNtQueryAttributesFile = InstallNativeHook(ntdll, hHooks, "NtQueryAttributesFile", out _origNtQueryAttributesFile);
        b.NtQueryFullAttributesFile = (nint)(delegate* unmanaged[Stdcall]<OBJECT_ATTRIBUTES*, IntPtr, int>)&Managed_NtQueryFullAttributesFile;
        b.OrigNtQueryFullAttributesFile = InstallNativeHook(ntdll, hHooks, "NtQueryFullAttributesFile", out _origNtQueryFullAttributesFile);
        b.NtQueryVolumeInformationFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IO_STATUS_BLOCK*, IntPtr, uint, int, int>)&Managed_NtQueryVolumeInformationFile;
        b.OrigNtQueryVolumeInformationFile = InstallNativeHook(ntdll, hHooks, "NtQueryVolumeInformationFile", out _origNtQueryVolumeInformationFile);
        b.NtSetInformationFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IO_STATUS_BLOCK*, IntPtr, uint, int, int>)&Managed_NtSetInformationFile;
        b.OrigNtSetInformationFile = InstallNativeHook(ntdll, hHooks, "NtSetInformationFile", out _origNtSetInformationFile);

        // ---- S3a/S2b: memory-mapping layer (CreateFileMapping -> NtCreateSection -> NtMapViewOfSection) ----
        b.NtCreateSection = (nint)(delegate* unmanaged[Stdcall]<IntPtr*, uint, IntPtr, IntPtr, uint, uint, IntPtr, int>)&Managed_NtCreateSection;
        b.OrigNtCreateSection = InstallNativeHook(ntdll, hHooks, "NtCreateSection", out _origNtCreateSection);
        b.NtMapViewOfSection = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr, UIntPtr, IntPtr, IntPtr, int, uint, uint, int>)&Managed_NtMapViewOfSection;
        b.OrigNtMapViewOfSection = InstallNativeHook(ntdll, hHooks, "NtMapViewOfSection", out _origNtMapViewOfSection);
        b.NtUnmapViewOfSection = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)&Managed_NtUnmapViewOfSection;
        b.OrigNtUnmapViewOfSection = InstallNativeHook(ntdll, hHooks, "NtUnmapViewOfSection", out _origNtUnmapViewOfSection);
        b.NtQuerySection = (nint)(delegate* unmanaged[Stdcall]<IntPtr, int, IntPtr, UIntPtr, IntPtr, int>)&Managed_NtQuerySection;
        b.OrigNtQuerySection = InstallNativeHook(ntdll, hHooks, "NtQuerySection", out _origNtQuerySection);

        // ---- PHASE9 (registry 修复): directory enumeration (FindFirstFileW/FindNextFileW) ----
        b.NtQueryDirectoryFile = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr, IO_STATUS_BLOCK*, IntPtr, uint, int, byte, IntPtr, byte, int>)&Managed_NtQueryDirectoryFile;
        b.OrigNtQueryDirectoryFile = InstallNativeHook(ntdll, hHooks, "NtQueryDirectoryFile", out _origNtQueryDirectoryFile);
        b.NtQueryDirectoryFileEx = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr, IO_STATUS_BLOCK*, IntPtr, uint, int, uint, IntPtr, int>)&Managed_NtQueryDirectoryFileEx;
        b.OrigNtQueryDirectoryFileEx = InstallNativeHook(ntdll, hHooks, "NtQueryDirectoryFileEx", out _origNtQueryDirectoryFileEx);

        // ---- PHASE16 (第 16 个钩子): NtDuplicateObject —— JDK 25 FileChannelImpl.map ->
        // duplicateForMapping 复制句柄; kernelbase!DuplicateHandle 经 IAT 调本函数 (cdb 反汇编)。
        // 假文件句柄必须可复制, 否则 jimage BasicImageReader 抛 "句柄无效" (patch-module 实测)。
        b.NtDuplicateObject = (nint)(delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, IntPtr*, uint, uint, uint, int>)&Managed_NtDuplicateObject;
        b.OrigNtDuplicateObject = InstallNativeHook(ntdll, hHooks, "NtDuplicateObject", out _origNtDuplicateObject);

        // run12: kernelbase!CreateFileW 托管 detour —— JVM 的 java.io.FileInputStream 走
        // kernelbase direct-syscall 绕过 ntdll hook; 用 MinHook 原生重载直接挂 CreateFileW
        // 导出 ([UnmanagedCallersOnly] 回调自管理 _suppressHooks, 不经 native 守卫 stub)。
        // 仅对 Z: 的 JDK conf 路径重写为物化真实文件, 其余原样放行。
        {
            nint kernelbase = NativeLibrary.Load("kernelbase.dll");
            nint cwfTarget = NativeLibrary.GetExport(kernelbase, "CreateFileW");
            nint cwfStub = (nint)(delegate* unmanaged[Stdcall]<char*, uint, uint, void*, uint, uint, IntPtr, IntPtr>)&Managed_CreateFileW;
            nint cwfOrig = HookEngine.CreateHook(cwfTarget, cwfStub);
            _origCreateFileW = Marshal.GetDelegateForFunctionPointer<D_CreateFileW>(cwfOrig);
            _hookDelegates.Add(_origCreateFileW);
            Log($"[hooks] CreateFileW @ 0x{cwfTarget:X} -> hooked (managed detour, orig trampoline 0x{cwfOrig:X})");
        }

        // Phase 3: 一次注册全部绑定(回调 + Orig), 必须在 EnableHooks 之前
        if (NativeSetCallbacks(&b) != 0)
        {
            throw new InvalidOperationException("SetCallbacks 注册失败 (native sfmc_hooks_shared)");
        }
        Log($"[hooks] SetCallbacks ok: 16 callbacks + 16 origs registered");

        // 修改后 MinHook.NET: CreateHook 只建 trampoline(未 patch); EnableHooks 应用全部
        // prologue patch(delegate + 原生两个映射)。安全窗口同旧版(JVM 尚不存在)。
        HookEngine.EnableHooks();
        _engineActive = true;
        Log($"[hooks] 11 S2a + 4 S3a/S2b + 1 PHASE16 (NtDuplicateObject) native-stub detours enabled on ntdll (suppress={NativeIsSuppressHooks()})");
    }

    /// <summary>
    /// Phase 3: 安装单个 hook —— 修改后 MinHook.NET CreateHook(ntdllExport, Stub_* 地址)
    /// 原生 detour 重载: 生成 trampoline(Orig)并返回其地址; 同时生成托管 pass-through 委托。
    /// </summary>
    private static unsafe IntPtr InstallNativeHook<T>(nint ntdll, nint hHooks, string name, [NotNull] out T? orig) where T : Delegate
    {
        nint target = NativeLibrary.GetExport(ntdll, name);
        // PHASE11-AOT: AOT 模式符号从静态链接库按名解析 (SfmcGetExport -> __Internal);
        // JIT 模式从 shared dll 导出表解析。静态链接符号不在 exe 导出表, GetExport 不可用。
        nint stub = NativeAot ? NativeGetExport("Stub_" + name) : NativeLibrary.GetExport(hHooks, "Stub_" + name);
        if (stub == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Stub_{name} 解析失败 (AOT={NativeAot}, hHooks=0x{hHooks.ToInt64():X})");
        }
        Log($"[hooks] {name}: export 0x{target:X}, native stub 0x{stub:X}");
        nint origPtr = HookEngine.CreateHook((IntPtr)target, (IntPtr)stub); // MODIFIED MinHook.NET: 原生 detour 重载
        orig = Marshal.GetDelegateForFunctionPointer<T>(origPtr);
        _hookDelegates.Add(orig);
        Log($"[hooks] {name} @ 0x{target:X} -> hooked (orig trampoline 0x{origPtr:X})");
        return origPtr;
    }

    /// <summary>
    /// JIT safety part 3: eagerly compile all hook methods (and the trampoline-free helpers they
    /// call before their first suppression scope) so no ntdll->hook->JIT recursion can start.
    /// </summary>
    private static void PrepareHooks()
    {
        // PHASE11-AOT: NativeAOT 无 JIT —— 全部方法编译期已生成, 反射预热 (GetMethod + 
        // PrepareMethod) 无意义且触发 AOT 反射告警, 直接跳过。
        if (NativeAot) { return; }
        string[] hookNames =
        [
            nameof(Hook_NtCreateFile), nameof(Hook_NtOpenFile), nameof(Hook_NtReadFile), nameof(Hook_NtClose),
            nameof(Hook_NtQueryInformationFile), nameof(Hook_NtQueryAttributesFile), nameof(Hook_NtQueryFullAttributesFile),
            nameof(Hook_NtQueryVolumeInformationFile), nameof(Hook_NtSetInformationFile), nameof(Hook_NtCreateSection),
            nameof(Hook_NtMapViewOfSection), nameof(Hook_NtUnmapViewOfSection), nameof(Hook_NtQuerySection),
            nameof(Hook_NtQueryDirectoryFile),
            nameof(Hook_NtDuplicateObject),
            // Phase 3: [UnmanagedCallersOnly] 桥方法(首次 NATIVE 入口不得触发 JIT)
            nameof(Managed_NtCreateFile), nameof(Managed_NtOpenFile), nameof(Managed_NtReadFile), nameof(Managed_NtClose),
            nameof(Managed_NtQueryInformationFile), nameof(Managed_NtQueryAttributesFile), nameof(Managed_NtQueryFullAttributesFile),
            nameof(Managed_NtQueryVolumeInformationFile), nameof(Managed_NtSetInformationFile), nameof(Managed_NtCreateSection),
            nameof(Managed_NtMapViewOfSection), nameof(Managed_NtUnmapViewOfSection), nameof(Managed_NtQuerySection),
            nameof(Managed_NtQueryDirectoryFile), nameof(Managed_NtQueryDirectoryFileEx),
            nameof(Hook_NtQueryDirectoryFileEx),
            nameof(Managed_NtDuplicateObject),
            // PHASE9: 目录枚举辅助(钩子内首调不得触发 JIT)
            nameof(ServeDirectoryQuery), nameof(EnsureDirEntries), nameof(MatchesPattern),
            nameof(WildcardMatch), nameof(StatEntry), nameof(WriteDirRecord), nameof(ReadUnicodeString),
            // S2b helpers called from hooks (PE parse / image layout / SII fill) - compiled up front
            nameof(TryParsePe), nameof(MapImageIntoMemory), nameof(FillSectionImageInfo), nameof(MakeFakeSectionHandle),
            // run12: kernelbase CreateFileW 托管 detour (JVM FileInputStream 走 direct-syscall,
            // 绕过 ntdll hook —— conf 文件重写为物化真实路径)
            nameof(Managed_CreateFileW), nameof(Hook_CreateFileW), nameof(GetOrMaterializeConfFile), nameof(MaterializeConfTree),
        ];
        foreach (string n in hookNames)
        {
            MethodInfo m = typeof(FakeFileSystem).GetMethod(n, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                ?? throw new InvalidOperationException($"PrepareHooks: {n} not found");
            RuntimeHelpers.PrepareMethod(m.MethodHandle);
            Log($"[jit-safety] prepared {n}");
        }
    }

    // ------------------------------------------------------------------ run12: kernelbase CreateFileW
    // JVM 的 java.io.FileInputStream (Security.loadMaster 读 conf\security\java.security 等 JDK
    // conf 文件) 走 kernelbase CreateFileW —— 本 25H2 构建上 kernelbase 对文件打开用 direct-syscall,
    // 完全绕过 ntdll hook, 假句柄/假盘方案对这类打开无效。方案: 托管 detour 直接挂
    // kernelbase!CreateFileW (MinHook 原生重载, [UnmanagedCallersOnly] 回调), Z:\ 的 JDK conf
    // 路径重写为 %TEMP%\sfmc-modules\conf\ 下的物化真实文件 (容器仍是数据源)。

    private unsafe delegate IntPtr D_CreateFileW(char* lpFileName, uint dwDesiredAccess, uint dwShareMode,
        void* lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    private static D_CreateFileW? _origCreateFileW;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe IntPtr Managed_CreateFileW(char* lpFileName, uint dwDesiredAccess, uint dwShareMode,
        void* lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile)
    {
        return Hook_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe IntPtr Hook_CreateFileW(char* lpFileName, uint dwDesiredAccess, uint dwShareMode,
        void* lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile)
    {
        if (_suppressHooks > 0)
        {
            return _origCreateFileW!(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }
        _suppressHooks++;
        try
        {
            string? s = lpFileName is null ? null : new string(lpFileName);
            if (s != null && s.Contains("java.security", StringComparison.OrdinalIgnoreCase))
            {
                Log($"[CreateFileW] PROBE java.security '{s}' suppress={_suppressHooks}");
            }
            string? rest = StripZPrefix(s);
            if (rest is not null)
            {
                // PHASE16: Z: 文件走 CreateFileW (kernelbase -> 内层 NtCreateFile 已被本 hook
                // 抑制, 不能再依赖 ntdll 特判)。lib\modules 与 JDK conf 树均已去物化
                // (ModulesRealPath=null, 无 conf 重写): 全部与 MC 数据树 jar 同机制 ——
                // 放行给 kernelbase, 由内层 NtCreateFile 经 ntdll hook 以假句柄服务
                // (jimage 打开链实测可 hook, 见 Hook_NtCreateFile 注释; PHASE12 反汇编证明
                // kernelbase CreateFileW 零 direct syscall)。
                string key = "";
                bool isDir = false;
                bool mapHit = Container.Active && Container.TryMapKey(rest, out key, out isDir) && !isDir;
                if (mapHit)
                {
                    // MC 数据树 jar 等: 放行给 kernelbase, 由内层 NtCreateFile 经 ntdll hook 服务
                    // (run12 回归修复: 本回调内 [ThreadStatic] _suppressHooks>0 会遮蔽内层
                    //  ntdll hook 导致真内核收 Z: 路径 -> jar 全失败 -> ClassNotFound;
                    //  临时放开守卫后与 run10 (无 CreateFileW hook) 语义一致)。
                    _suppressHooks--;
                    try
                    {
                        return _origCreateFileW!(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
                    }
                    finally { _suppressHooks++; }
                }
                Log($"[CreateFileW] Z: direct open (bypass) '{s}' rest='{rest}' mapHit={mapHit}"
                    + (mapHit ? $" key='{key}' isDir={isDir} modules={(ModulesRealPath is null ? "NULL" : "set")}" : "")
                    + $" access=0x{dwDesiredAccess:X} flags=0x{dwFlagsAndAttributes:X} disp={dwCreationDisposition}");
            }
            return _origCreateFileW!(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }
        finally { _suppressHooks--; }
    }

    /// <summary>预热期物化整个 JDK conf 树 (detour 前: JIT 安全 + 首开零延迟)。</summary>
    public static void MaterializeConfTree()
    {
        if (!Container.Active) { return; }
        string prefix = Container.JdkPrefix + "/conf";
        var stack = new Stack<string>();
        stack.Push(prefix);
        while (stack.Count > 0)
        {
            string d = stack.Pop();
            foreach ((string cname, bool cdir, long _) in Container.EnumerateChildren(d))
            {
                string k = d + "/" + cname;
                if (cdir) { stack.Push(k); }
                else { _ = GetOrMaterializeConfFile(k); }
            }
        }
        Console.WriteLine($"[prejit] materialized JDK conf tree ({ConfMaterialized.Count} files)");
    }

    /// <summary>
    /// PHASE15: 删除整个 <gameDir>\cache (物化 modules + natives 提取), 幂等。
    /// 预热期调用 (Program.PreJitWarmup 最前: 清上次崩溃残留, pre-detour 无 hook 干扰);
    /// 退出路径调用 (McLaunch.CleanupTempArtifacts, 已 JIT 预热, post-detour 真实路径透传)。
    /// 游戏进程仍存活时被占用文件删除失败 -> 捕获记录, 残留位于 gameDir 内 (非 %TEMP%),
    /// 下次启动清理。
    /// </summary>
    public static void CleanupCache()
    {
        try
        {
            if (Directory.Exists(CacheRoot))
            {
                Directory.Delete(CacheRoot, true);
                Console.WriteLine($"[cache] cleaned {CacheRoot}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[cache] cleanup FAILED (残留位于 gameDir 内, 下次启动清理):\n{ex}");
        }
    }

    /// <summary>
    /// JIT-safety warmup: compile every interpolation shape used by the hook Log calls BEFORE the
    /// first detour exists. With MinHook.NET a post-detour JIT is no longer a fail-fast (no JIT
    /// hook exists), but compiling early still keeps the hooked stack free of JIT re-entry.
    /// Program.Main calls this before FakeFileSystem.Init.
    /// </summary>
    internal static void WarmupLogPatterns()
    {
        // the exact interpolation shapes used by the hook Log calls; first use JIT-compiles the
        // DefaultInterpolatedStringHandler overloads (AppendFormatted(bool/int/long/uint/IntPtr/string))
        IntPtr h = IntPtr.Zero; long off = 0; uint len = 0; int n = 0; string s = "warm";
        Log($"[NtReadFile] FAKE 0x{h:X} off={off} len={len} -> {n} B ({s})");
        Log($"[NtCreateFile] FAKE handle=0x{h:X} '{s}' -> '{s}' ({n} B)");
        Log($"[NtQueryInformationFile] FAKE 0x{h:X} FileStandardInformation -> {off} B ({s})");
        Log($"[NtClose] FAKE 0x{h:X} removed ({s})");
        Log($"[NtMapViewOfSection] FAKE section=0x{h:X} -> base=0x{h:X} view={off} B");
        Log($"[NtCreateSection] FAKE-IMAGE file 0x{h:X} -> fake section=0x{h:X} (base=0x{h:X} size=0x{off:X} aep=0x{off:X}, '{s}')");
        Log($"[NtMapViewOfSection] FAKE-IMAGE section=0x{h:X} -> st=0x{h:X} base=0x{h:X} view=0x{off:X} (pe-base=0x{h:X}, '{s}')");
        Log($"[NtQuerySection] FAKE-IMAGE 0x{h:X} class={n} -> SII 0x{off:X} B (pe-base=0x{h:X})");
        Log($"[NtQuerySection] FAKE-IMAGE 0x{h:X} class={n} -> SBI (size=0x{off:X})");
        Log($"[NtUnmapViewOfSection] FAKE-IMAGE base=0x{h:X} VirtualFree(MEM_RELEASE)");
        Log($"[NtClose] FAKE-IMAGE section 0x{h:X} removed ({s})");
        Log($"[jit-safety] warmed image pipeline: st=0x{h:X} base=0x{h:X} size=0x{off:X}");
        Log($"[NtMapViewOfSection] FAKE-IMAGE EXCEPTION in layout: {s}: {s}");
        // PHASE9: directory enumeration log shapes (NtQueryDirectoryFile / dir fake handles)
        Log($"[NtQueryDirectoryFile] FAKE 0x{h:X} class={n} -> {n} B ({s})");
        Log($"[NtQueryDirectoryFile] FAKE 0x{h:X} class={n} -> NO_MORE_FILES ({s})");
        Log($"[NtQueryDirectoryFile] FAKE 0x{h:X} class={n} -> INVALID_INFO_CLASS ({s})");
        Log($"[NtQueryDirectoryFile] FAKE 0x{h:X} -> BUFFER_OVERFLOW ({s})");
        Exception wex = new IOException("warmup enumeration probe");
        Log($"[NtQueryDirectoryFile] FAKE enumerate threw: {wex}");
        Log($"[NtQueryDirectoryFileEx] FAKE 0x{h:X} class={n} flags=0x{off:X} -> {n} B ({s})");
        Log($"[NtOpenFile] FAKE DIR handle=0x{h:X} '{s}' -> '{s}'");
        Log($"[NtCreateFile] FAKE DIR handle=0x{h:X} '{s}' -> '{s}'");
        bool b = false;
        Log($"[prejit] warmup shapes: {b} {h:X} {off} {len} {n} {s}");
        // Phase 2: Directory.Exists + File.Exists now run inside the attribute/create hooks
        // (directory stat support for Z:\minecraft\... data paths) -- compile their internals now.
        bool wdir = Directory.Exists(@"C:\Windows");
        bool wfile = File.Exists(@"C:\Windows\explorer.exe");
        Log($"[prejit] warmup dir/file stat: dir={wdir} file={wfile}");
        // PHASE9: warm the directory-enumeration + per-entry stat paths (run inside the new
        // NtQueryDirectoryFile hook): EnumerateFileSystemEntries / Path.GetFileName /
        // DirectoryInfo + FileInfo stat / FILETIME conversion / wildcard matcher.
        foreach (string we in Directory.EnumerateFileSystemEntries(@"C:\Windows"))
        {
            _ = Path.GetFileName(we);
            break;
        }
        var wdi = new DirectoryInfo(@"C:\Windows");
        _ = wdi.CreationTimeUtc.ToFileTimeUtc();
        var wfi = new FileInfo(@"C:\Windows\explorer.exe");
        _ = wfi.Length;
        _ = MatchesPattern("explorer.exe", "*.exe");
        _ = MatchesPattern("explorer.exe", "explorer.exe");
        _ = WildcardMatch("a.b.c", "a*.*");
        Log("[prejit] warmup dir enumeration + stat + wildcard match");
    }

    /// <summary>
    /// JIT-warm the teardown path (HookEngine.Dispose + Shutdown body) while NO detour exists.
    /// Under MonoMod this was mandatory (any teardown JIT re-entered the compileMethod JitHook);
    /// with MinHook.NET it is a harmless belt-and-braces warmup of Shutdown()'s own body. Program
    /// calls this before StartNoGcRegion. NOTE: no throwaway hook here anymore — MinHook.NET has no
    /// RemoveHook API, and a leftover throwaway in the shared HookEngine would be re-enabled by
    /// Init's EnableHooks (stray NtYieldExecution patch); the MonoMod-era throwaway existed only to
    /// warm Undo, which MinHook does not need.
    /// </summary>
    public static void WarmupTeardown()
    {
        // JIT the full Shutdown() body (loop bodies, List/ConcurrentDictionary ops, ReleaseBuffer
        // call sites) on the empty state; no detours exist yet so nothing can go wrong.
        Shutdown();
        Log("[jit-safety] warmed teardown path (Shutdown + hook disable)");
    }

    /// <summary>Undo all detours (restore ntdll stubs) before process exit to avoid shutdown-order crashes.</summary>
    public static unsafe void Shutdown()
    {
        Log("[shutdown] disable MinHook.NET hooks ...");
        // HookEngine.Dispose() = DisableHooks (restore every prologue; each DisableHook briefly
        // suspends the other threads — the JVM threads are parked at this point, see Init doc) +
        // free the trampoline memory blocks. Idempotent: no-op when Init never ran (WarmupTeardown
        // calls Shutdown pre-Init -> _engineActive is false).
        if (_engineActive)
        {
            HookEngine.Dispose();
            _engineActive = false;
            Log("[shutdown] hooks disabled, trampolines freed");
        }
        else
        {
            Log("[shutdown] no active hooks (warmup pass)");
        }
        // free any native byte caches still alive (leak hygiene). Detours are already undone, so no
        // late hook can touch these pointers. Refcounted: a buffer shared by a FakeFile + FakeSection
        // is decremented twice and freed exactly once.
        Log($"[shutdown] release buffers (handles={FakeHandles.Count} sections={FakeSections.Count} maps={FakeMappedBases.Count})");
        foreach (var kv in FakeHandles) { ReleaseBuffer(kv.Value.Buf); }
        foreach (var kv in FakeSections) { ReleaseBuffer(kv.Value.Buf); }
        // S2b: any fake IMAGE maps still alive are our own VirtualAlloc regions -> free them
        foreach (var kv in FakeMappedBases)
        {
            if (kv.Value == MapKindImage && kv.Key != IntPtr.Zero) { VirtualFree(kv.Key, UIntPtr.Zero, MEM_RELEASE); }
        }
        FakeHandles.Clear();
        FakeSections.Clear();
        FakeMappedBases.Clear();
        Log("[shutdown] done");
    }

    // ------------------------------------------------------------------ path mapping

    /// <summary>Public mirror of the hook-internal mapping, used by the verifier to compute the real path.</summary>
    public static string? ToRealPath(string zPath)
    {
        string? rest = StripZPrefix(zPath);
        return rest is null ? null : TryMap(rest);
    }

    /// <summary>仅磁盘别名的解析 (跳过容器分支)。容器加载失败回退真实 JDK 用。</summary>
    public static string? ToRealDiskPath(string zPath)
    {
        string? rest = StripZPrefix(zPath);
        return rest is null ? null : TryMapDiskOnly(rest);
    }

    /// <summary>TryMap 的磁盘别名部分 (容器激活时仍可用; 根 = exe 旁, 无硬编码绝对路径)。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static string? TryMapDiskOnly(string rest)
    {
        // Z:\minecraft 根 -> <exe>\Minecraft (PHASE13: minecraft 顶层 = MC 数据树根)
        if (rest.Equals("minecraft", StringComparison.OrdinalIgnoreCase))
        {
            if (Directory.Exists(McDataRoot)) { return McDataRoot; }
        }
        else if (rest.StartsWith(@"minecraft\", StringComparison.OrdinalIgnoreCase))
        {
            string cm = Path.Combine(McDataRoot, rest[10..]);
            if (File.Exists(cm) || Directory.Exists(cm)) { return cm; }
        }
        string c1 = Path.Combine(JdkRoot, rest);
        if (File.Exists(c1) || Directory.Exists(c1)) { return c1; }
        // Z:\openjdk\... 顶层段剥除 -> <exe>\jdk\... (PHASE13 换层; 旧 jdk-25.0.4.7-hotspot
        // 冗余段容错被 openjdk 抽象名替代 —— openjdk 即 JDK 树根, 不再保留版本段)
        if (rest.StartsWith(@"openjdk\", StringComparison.OrdinalIgnoreCase))
        {
            string c2 = Path.Combine(JdkRoot, rest[8..]);
            if (File.Exists(c2) || Directory.Exists(c2)) { return c2; }
        }
        return null;
    }

    /// <summary>Normalize \??\Z:\... / \\?\Z:\... / Z:\... (case-insensitive) to the tail after "Z:\".</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static string? StripZPrefix(string? name)
    {
        if (string.IsNullOrEmpty(name)) { return null; }
        string n = name;
        if (n.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)) { n = n[4..]; }
        else if (n.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)) { n = n[4..]; }
        if (n.Length < 3 || (n[0] != 'Z' && n[0] != 'z') || n[1] != ':') { return null; }
        // PHASE12: TrimEnd('\\') —— 目录路径 '\??\Z:\a\b\' 的尾反斜杠会使 TryMapKey 的
        // 键转换 (Replace '\\'->'/') 带尾斜杠而匹配不到 entries (键无尾斜杠), 目录打开
        // 被误判 missing (JVM Path.toRealPath 逐组件打开目录的运行时证据)。
        return n[2..].TrimStart('\\').TrimEnd('\\');
    }

    /// <summary>Z:\&lt;rest&gt; -> real path on disk (only if the real file OR directory exists).</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static string? TryMap(string rest)
    {
        // 容器优先 (阶段 2): 尾部 zip 激活时, Z: 路径先查容器; 容器命中返回 Z: 伪路径
        // (IsContainerReal 识别), 不存在则回退磁盘别名。Z: 根 (rest=="") 返回合成根。
        if (Container.Active)
        {
            if (rest.Length == 0) { return @"Z:\"; }
            if (Container.TryMapKey(rest, out _, out _)) { return @"Z:\" + rest; }
        }
        // 磁盘回退 (仅无容器调试): Z:\minecraft\... -> <exe>\Minecraft\...
        if (rest.Equals("minecraft", StringComparison.OrdinalIgnoreCase))
        {
            if (Directory.Exists(McDataRoot)) { return McDataRoot; }
        }
        else if (rest.StartsWith(@"minecraft\", StringComparison.OrdinalIgnoreCase))
        {
            string cm = Path.Combine(McDataRoot, rest[10..]);
            if (File.Exists(cm) || Directory.Exists(cm)) { return cm; }
        }
        string c1 = Path.Combine(JdkRoot, rest);
        if (File.Exists(c1) || Directory.Exists(c1)) { return c1; }
        // Z:\openjdk\... 顶层段剥除 -> <exe>\jdk\... (PHASE13 换层; 旧 jdk-25.0.4.7-hotspot
        // 容错被 openjdk 抽象名替代 —— openjdk 即 JDK 树根, 不再保留版本段)
        if (rest.StartsWith(@"openjdk\", StringComparison.OrdinalIgnoreCase))
        {
            string c2 = Path.Combine(JdkRoot, rest[8..]);
            if (File.Exists(c2) || Directory.Exists(c2)) { return c2; }
        }
        return null;
    }

    /// <summary>是否为容器伪路径 (TryMap 在容器命中时返回 "Z:\&lt;rest&gt;")。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static bool IsContainerReal(string real)
    {
        return Container.Active && real.StartsWith(@"Z:\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>解析 real 路径的目录性: 容器伪路径 -> 容器目录表; 磁盘 -> Directory.Exists。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static bool ResolveIsDir(string real)
    {
        if (IsContainerReal(real))
        {
            string rest = real[3..];
            if (rest.Length == 0) { return true; } // Z: 根 = 容器合成目录
            return Container.TryMapKey(rest, out _, out bool isDir) && isDir;
        }
        return Directory.Exists(real);
    }

    /// <summary>real 路径的字节长度: 容器伪路径 -> 容器条目长度; 磁盘 -> FileInfo.Length。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static long ResolveLength(string real)
    {
        if (IsContainerReal(real))
        {
            string rest = real[3..];
            if (Container.TryMapKey(rest, out string key, out bool isDir) && !isDir)
            {
                return Container.GetLength(key);
            }
            return 0;
        }
        return new FileInfo(real).Length;
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe string? ReadObjectName(ref OBJECT_ATTRIBUTES objAttr)
    {
        UNICODE_STRING* us = objAttr.ObjectName;
        if (us == null || us->Buffer == null || us->Length == 0) { return null; }
        return new string(us->Buffer, 0, us->Length / 2);
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static IntPtr MakeFakeHandle()
    {
        uint n = (uint)Interlocked.Increment(ref _handleCounter) & 0x00FFFFFFu;
        return new IntPtr(0x51000000u | n);
    }

    // ------------------------------------------------------------------ native 桥: [UnmanagedCallersOnly] 托管回调
    //
    // Phase 3: 这些方法经 native stub(Stub_*)的 Reverse P/Invoke 进入, 签名与 native
    // typedef 完全一致(指针化); 内部复用原 Hook_* 业务体(out/ref 通过 *ptr 解引用透传)。
    // - 守卫已由 native _suppressHooks 完成: stub 只在计数器 == 0 时调用回调, 回调内任何
    //   ntdll 调用被 native 计数器兜住 -> 这里不需要再写托管入口守卫。
    // - Hook_* 体内的托管 [ThreadStatic] _suppressHooks 仍保留(与 native 守卫并存, 无冲突,
    //   纯托管路径的 belt-and-braces, 行为与旧版一致)。
    // - CallConvStdcall 匹配 native NTAPI; x64 上调用约定统一, 该标注为显式契约。

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtCreateFile(IntPtr* fileHandle, uint desiredAccess, OBJECT_ATTRIBUTES* objAttr,
        IO_STATUS_BLOCK* ioStatus, IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength)
    {
        return Hook_NtCreateFile(out *fileHandle, desiredAccess, ref *objAttr, out *ioStatus, allocationSize,
            fileAttributes, shareAccess, createDisposition, createOptions, eaBuffer, eaLength);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtOpenFile(IntPtr* fileHandle, uint desiredAccess, OBJECT_ATTRIBUTES* objAttr,
        IO_STATUS_BLOCK* ioStatus, uint shareAccess, uint openOptions)
    {
        return Hook_NtOpenFile(out *fileHandle, desiredAccess, ref *objAttr, out *ioStatus, shareAccess, openOptions);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtReadFile(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        IO_STATUS_BLOCK* ioStatus, IntPtr buffer, uint length, IntPtr byteOffset, IntPtr key)
    {
        return Hook_NtReadFile(fileHandle, evt, apcRoutine, apcContext, out *ioStatus, buffer, length, byteOffset, key);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Managed_NtClose(IntPtr handle)
    {
        return Hook_NtClose(handle);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQueryInformationFile(IntPtr fileHandle, IO_STATUS_BLOCK* ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass)
    {
        return Hook_NtQueryInformationFile(fileHandle, out *ioStatus, fileInformation, length, fileInformationClass);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQueryAttributesFile(OBJECT_ATTRIBUTES* objAttr, IntPtr fileInformation)
    {
        return Hook_NtQueryAttributesFile(ref *objAttr, fileInformation);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQueryFullAttributesFile(OBJECT_ATTRIBUTES* objAttr, IntPtr fileInformation)
    {
        return Hook_NtQueryFullAttributesFile(ref *objAttr, fileInformation);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQueryVolumeInformationFile(IntPtr fileHandle, IO_STATUS_BLOCK* ioStatus,
        IntPtr fsInformation, uint length, int fsInformationClass)
    {
        return Hook_NtQueryVolumeInformationFile(fileHandle, out *ioStatus, fsInformation, length, fsInformationClass);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtSetInformationFile(IntPtr fileHandle, IO_STATUS_BLOCK* ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass)
    {
        return Hook_NtSetInformationFile(fileHandle, out *ioStatus, fileInformation, length, fileInformationClass);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtCreateSection(IntPtr* sectionHandle, uint desiredAccess, IntPtr objectAttributes,
        IntPtr maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
    {
        return Hook_NtCreateSection(out *sectionHandle, desiredAccess, objectAttributes, maximumSize,
            sectionPageProtection, allocationAttributes, fileHandle);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, IntPtr baseAddressPtr,
        IntPtr zeroBits, UIntPtr commitSize, IntPtr sectionOffsetPtr, IntPtr viewSizePtr,
        int inheritDisposition, uint allocationType, uint win32Protect)
    {
        return Hook_NtMapViewOfSection(sectionHandle, processHandle, baseAddressPtr, zeroBits, commitSize,
            sectionOffsetPtr, viewSizePtr, inheritDisposition, allocationType, win32Protect);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int Managed_NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress)
    {
        return Hook_NtUnmapViewOfSection(processHandle, baseAddress);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQuerySection(IntPtr sectionHandle, int infoClass, IntPtr infoBuffer,
        UIntPtr infoLength, IntPtr returnLengthPtr)
    {
        return Hook_NtQuerySection(sectionHandle, infoClass, infoBuffer, infoLength, returnLengthPtr);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQueryDirectoryFile(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        IO_STATUS_BLOCK* ioStatus, IntPtr fileInformation, uint length, int fileInformationClass,
        byte returnSingleEntry, IntPtr fileNamePtr, byte restartScan)
    {
        return Hook_NtQueryDirectoryFile(fileHandle, evt, apcRoutine, apcContext, out *ioStatus, fileInformation,
            length, fileInformationClass, returnSingleEntry, fileNamePtr, restartScan);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtQueryDirectoryFileEx(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        IO_STATUS_BLOCK* ioStatus, IntPtr fileInformation, uint length, int fileInformationClass,
        uint queryFlags, IntPtr fileNamePtr)
    {
        return Hook_NtQueryDirectoryFileEx(fileHandle, evt, apcRoutine, apcContext, out *ioStatus, fileInformation,
            length, fileInformationClass, queryFlags, fileNamePtr);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int Managed_NtDuplicateObject(IntPtr sourceProcessHandle, IntPtr sourceHandle,
        IntPtr targetProcessHandle, IntPtr* targetHandlePtr, uint desiredAccess, uint handleAttributes, uint options)
    {
        return Hook_NtDuplicateObject(sourceProcessHandle, sourceHandle, targetProcessHandle, out *targetHandlePtr,
            desiredAccess, handleAttributes, options);
    }

    // ------------------------------------------------------------------ hooks
    //
    // JIT safety parts 1+2 applied uniformly: the FIRST line of every hook is the suppression
    // passthrough (`if (_suppressHooks > 0) return Trampoline(...)` — a plain flag test + calli,
    // never triggers JIT), and the whole body runs inside a suppression scope so any managed
    // call that JIT-compiles on first use (File.ReadAllBytes, ConcurrentDictionary, Marshal.*,
    // string ops, Console/logging, P/Invoke resolution) re-enters ntdll with the flag set and
    // every hook passes straight through to its trampoline.

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe int Hook_NtCreateFile(out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objAttr,
        out IO_STATUS_BLOCK ioStatus, IntPtr allocationSize, uint fileAttributes, uint shareAccess,
        uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength)
    {
        if (_suppressHooks > 0)
        {
            return _origNtCreateFile!(out fileHandle, desiredAccess, ref objAttr, out ioStatus, allocationSize,
                fileAttributes, shareAccess, createDisposition, createOptions, eaBuffer, eaLength);
        }
        _suppressHooks++;
        try
        {
            fileHandle = IntPtr.Zero;
            ioStatus = default;
            string? name = ReadObjectName(ref objAttr);
            string? rest = StripZPrefix(name);
            if (rest is not null)
            {
                // ---- PHASE16: lib\modules 不再特判真实文件。jimage 打开+映射链
                // (osSupport::openReadOnly -> CRT _open -> CreateFileW; osSupport::map_memory ->
                // CreateFileA -> CreateFileMappingA -> MapViewOfFileEx) 全走 kernelbase API, 其内部
                // 经 IAT 调 ntdll 导出 (PHASE12 cdb 反汇编: CreateFileInternal->_imp_NtCreateFile、
                // CreateFileMappingW->_imp_NtCreateSection、MapViewOfFileEx->_imp_NtMapViewOfSection,
                // 零 direct syscall; 本地 jimage.dll 反汇编确认 _imp_CreateFileA/_imp_CreateFileMappingA/
                // _imp_MapViewOfFileEx; run12 日志实测两个 hook 均命中 lib\modules)。假句柄 +
                // 假 section 即可服务, 与 MC 数据树 jar 同机制。----
                string? real = TryMap(rest);
                // PHASE9: 目录也返回假句柄(IsDir) —— JDK25 toRealPath / FindFirstFileW 的
                // FindFirstFileExW 会打开【父目录】句柄再 NtQueryDirectoryFile 枚举; 之前目录
                // 被拒 -> Z: 路径 toRealPath 全崩 -> vanilla pack 空 -> registry 崩溃。
                if (real is not null)
                {
                    bool isDir = ResolveIsDir(real);
                    if (isDir || File.Exists(real) || IsContainerReal(real))
                    {
                        NativeBuffer? buf = isDir ? null : ReadFileToNative(real);
                        IntPtr h = MakeFakeHandle();
                        FakeHandles[h] = new FakeFile { Buf = buf, Pos = 0, IsDir = isDir, Real = real, Name = name ?? "" };
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(1);
                        fileHandle = h;
                        if (isDir)
                        {
                            Log($"[NtCreateFile] FAKE DIR handle=0x{h:X} '{name}' -> '{real}'");
                        }
                        else
                        {
                            Log($"[NtCreateFile] FAKE handle=0x{h:X} '{name}' -> '{real}' ({buf!.Length} B)");
                        }
                        return 0;
                    }
                    Log($"[NtCreateFile] Z: missing '{name}' -> STATUS_OBJECT_NAME_NOT_FOUND");
                    ioStatus.Status = new IntPtr(STATUS_OBJECT_NAME_NOT_FOUND);
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }
                Log($"[NtCreateFile] Z: missing '{name}' -> STATUS_OBJECT_NAME_NOT_FOUND");
                ioStatus.Status = new IntPtr(STATUS_OBJECT_NAME_NOT_FOUND);
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            return _origNtCreateFile!(out fileHandle, desiredAccess, ref objAttr, out ioStatus, allocationSize,
                fileAttributes, shareAccess, createDisposition, createOptions, eaBuffer, eaLength);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtOpenFile(out IntPtr fileHandle, uint desiredAccess, ref OBJECT_ATTRIBUTES objAttr,
        out IO_STATUS_BLOCK ioStatus, uint shareAccess, uint openOptions)
    {
        if (_suppressHooks > 0)
        {
            return _origNtOpenFile!(out fileHandle, desiredAccess, ref objAttr, out ioStatus, shareAccess, openOptions);
        }
        _suppressHooks++;
        try
        {
            fileHandle = IntPtr.Zero;
            ioStatus = default;
            string? name = ReadObjectName(ref objAttr);
            string? rest = StripZPrefix(name);
            if (rest is not null)
            {
                string? real = TryMap(rest);
                // PHASE9: 目录假句柄 (见 Hook_NtCreateFile 注释)
                if (real is not null)
                {
                    bool isDir = ResolveIsDir(real);
                    if (isDir || File.Exists(real) || IsContainerReal(real))
                    {
                        NativeBuffer? buf = isDir ? null : ReadFileToNative(real);
                        IntPtr h = MakeFakeHandle();
                        FakeHandles[h] = new FakeFile { Buf = buf, Pos = 0, IsDir = isDir, Real = real, Name = name ?? "" };
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(1);
                        fileHandle = h;
                        if (isDir)
                        {
                            Log($"[NtOpenFile] FAKE DIR handle=0x{h:X} '{name}' -> '{real}'");
                        }
                        else
                        {
                            Log($"[NtOpenFile] FAKE handle=0x{h:X} '{name}' -> '{real}' ({buf!.Length} B)");
                        }
                        return 0;
                    }
                }
                Log($"[NtOpenFile] Z: {(real is not null ? "directory" : "missing")} '{name}' -> STATUS_OBJECT_NAME_NOT_FOUND");
                ioStatus.Status = new IntPtr(STATUS_OBJECT_NAME_NOT_FOUND);
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            return _origNtOpenFile!(out fileHandle, desiredAccess, ref objAttr, out ioStatus, shareAccess, openOptions);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe int Hook_NtReadFile(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        out IO_STATUS_BLOCK ioStatus, IntPtr buffer, uint length, IntPtr byteOffset, IntPtr key)
    {
        if (_suppressHooks > 0)
        {
            return _origNtReadFile!(fileHandle, evt, apcRoutine, apcContext, out ioStatus, buffer, length, byteOffset, key);
        }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryGetValue(fileHandle, out FakeFile? f) && f.Buf is { } buf)
            {
                long offset;
                if (byteOffset == IntPtr.Zero)
                {
                    offset = f.Pos; // kernel file-pointer semantics
                }
                else
                {
                    // kernelbase reads fake handles through an OVERLAPPED and passes a pointer to its
                    // Offset field (u32@0, u32 OffsetHigh@4). Observed: the OVERLAPPED is rebuilt/zeroed
                    // per call, so its offset cannot drive continuity -> fall back to the fake file
                    // pointer whenever the caller asks for offset 0.
                    long callerOff = (long)(uint)Marshal.ReadInt32(byteOffset, 0)
                                   | ((long)(uint)Marshal.ReadInt32(byteOffset, 4) << 32);
                    offset = callerOff == 0 ? f.Pos : callerOff;
                }

                if (offset < 0 || offset >= buf.Length)
                {
                    ioStatus.Status = IntPtr.Zero;      // EOF: success, 0 bytes -> caller sees EOF
                    ioStatus.Information = IntPtr.Zero;
                    Log($"[NtReadFile] FAKE 0x{fileHandle:X} EOF at {offset} ({f.Name})");
                    return 0;
                }

                int n = (int)Math.Min(length, (long)buf.Length - offset);
                // S3b: native -> caller buffer via Span (no managed byte[] in the hook pipeline)
                new Span<byte>(buf.Data + offset, n).CopyTo(new Span<byte>((void*)buffer, n));
                long next = offset + n;
                f.Pos = (int)next;
                if (byteOffset != IntPtr.Zero)
                {
                    // keep the caller's OVERLAPPED.Offset in sync, like the IO manager does
                    Marshal.WriteInt32(byteOffset, 0, (int)next);
                    Marshal.WriteInt32(byteOffset, 4, (int)(next >> 32));
                }
                ioStatus.Status = IntPtr.Zero;
                ioStatus.Information = new IntPtr(n);
                f.ReadCount++;
                if (f.ReadCount <= 2 || f.ReadCount % 10000 == 0)
                {
                    Log($"[NtReadFile] FAKE 0x{fileHandle:X} off={offset} len={length} -> {n} B ({f.Name})");
                }
                return 0;
            }
            return _origNtReadFile!(fileHandle, evt, apcRoutine, apcContext, out ioStatus, buffer, length, byteOffset, key);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtDuplicateObject(IntPtr sourceProcessHandle, IntPtr sourceHandle,
        IntPtr targetProcessHandle, out IntPtr targetHandle, uint desiredAccess, uint handleAttributes, uint options)
    {
        if (_suppressHooks > 0)
        {
            return _origNtDuplicateObject!(sourceProcessHandle, sourceHandle, targetProcessHandle,
                out targetHandle, desiredAccess, handleAttributes, options);
        }
        _suppressHooks++;
        try
        {
            targetHandle = IntPtr.Zero;
            // PHASE16: JDK 25 FileChannelImpl.map -> duplicateForMapping -> DuplicateHandle(fake
            // 句柄) -> NtDuplicateObject (kernelbase IAT, cdb 反汇编确认)。假文件句柄必须可复制:
            // 新建假句柄共享同一 NativeBuffer (AddRef), 供 map0 的 CreateFileMappingW
            // (NtCreateSection hook) 与后续 nd.close 使用。jimage BasicImageReader 的
            // "句柄无效" IOException 即此调用被真内核拒绝所致 (patch-module 探针实测堆栈)。
            if (sourceProcessHandle == NtCurrentProcess && targetProcessHandle == NtCurrentProcess
                && FakeHandles.TryGetValue(sourceHandle, out FakeFile? f))
            {
                if (f.Buf is not null) { Interlocked.Increment(ref f.Buf.RefCount); }
                IntPtr h = MakeFakeHandle();
                FakeHandles[h] = new FakeFile
                {
                    Buf = f.Buf,
                    Pos = f.Pos,
                    IsDir = f.IsDir,
                    Real = f.Real,
                    Name = f.Name,
                };
                if ((options & DUPLICATE_CLOSE_SOURCE) != 0)
                {
                    // DuplicateHandle 语义: CLOSE_SOURCE 关闭源句柄 —— 移除源条目并 DropRef
                    // (副本已 AddRef 持有, 底层字节存活)。
                    FakeHandles.TryRemove(sourceHandle, out _);
                    ReleaseBuffer(f.Buf);
                }
                targetHandle = h;
                Log($"[NtDuplicateObject] FAKE 0x{sourceHandle:X} -> 0x{h:X} ({f.Name}) opts=0x{options:X}");
                return 0;
            }
            return _origNtDuplicateObject!(sourceProcessHandle, sourceHandle, targetProcessHandle,
                out targetHandle, desiredAccess, handleAttributes, options);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtClose(IntPtr handle)
    {
        if (_suppressHooks > 0) { return _origNtClose!(handle); }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryRemove(handle, out FakeFile? f))
            {
                ReleaseBuffer(f.Buf);
                Log($"[NtClose] FAKE 0x{handle:X} removed ({f.Name})");
                return 0;
            }
            if (FakeSections.TryRemove(handle, out FakeSection? s))
            {
                // S2b: image sections have FABRICATED handles (no kernel object) -> skip real close;
                // S3a data sections have REAL kernel handles -> close them.
                int st = s.IsImage ? 0 : _origNtClose!(handle);
                string kind = s.IsImage ? "FAKE-IMAGE section" : "FAKE section";
                ReleaseBuffer(s.Buf);
                Log($"[NtClose] {kind} 0x{handle:X} removed + real close st=0x{st:X} ({s.Name})");
                return 0;
            }
            return _origNtClose!(handle);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtQueryInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQueryInformationFile!(fileHandle, out ioStatus, fileInformation, length, fileInformationClass);
        }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryGetValue(fileHandle, out FakeFile? f))
            {
                const int FileBasicInformation = 4;        // FILE_BASIC_INFORMATION (40 B)
                const int FileStandardInformation = 5;     // FILE_STANDARD_INFORMATION (24 B)
                const int FileInternalInformation = 6;     // 8 B (index number)
                const int FilePositionInformation = 14;    // FILE_POSITION_INFORMATION (8 B)
                const int FileAllInformation = 21;         // variable (Basic+Standard+Internal+Ea+Access+Position+Mode+Alignment+Name)
                const int FileAttributeTagInformation = 35; // 8 B
                long sz = f.Buf?.Length ?? 0;
                // PHASE9: 目录假句柄的属性位 (FindFirstFileW 枚举结果 / GetFileInformationByHandleEx)
                int attrs = f.IsDir ? 0x10 : 0x20; // FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE
                switch (fileInformationClass)
                {
                    case FileBasicInformation:
                        // FILE_BASIC_INFORMATION (40 B): CreationTime@0, LastAccessTime@8,
                        // LastWriteTime@16, ChangeTime@24 (FILETIME, 0 = no times), FileAttributes@32.
                        // Zero times -> JVM's WindowsFileAttributes.toFileTime(0) = 1970-01-01 (no
                        // overflow; the runAOT-3 failure was a FAILED class-4 query leaving garbage,
                        // not a real timestamp). Required by GetFileInformationByHandleEx(FileBasicInfo)
                        // which the JVM classpath loader uses to validate classpath jars.
                        for (int i = 0; i < 40; i++) { Marshal.WriteByte(fileInformation, i, 0); }
                        Marshal.WriteInt32(fileInformation, 32, attrs);
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(40);
                        Log($"[NtQueryInformationFile] FAKE 0x{fileHandle:X} FileBasicInformation ({f.Name})");
                        return 0;
                    case FileStandardInformation:
                        // FILE_STANDARD_INFORMATION (24 B): AllocationSize@0, EndOfFile@8, NumberOfLinks@16(u32),
                        // DeletePending@20, Directory@21, pad@22-23
                        Marshal.WriteInt64(fileInformation, 0, sz);
                        Marshal.WriteInt64(fileInformation, 8, sz);
                        Marshal.WriteInt64(fileInformation, 16, 0);
                        Marshal.WriteByte(fileInformation, 21, f.IsDir ? (byte)1 : (byte)0);
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(24);
                        Log($"[NtQueryInformationFile] FAKE 0x{fileHandle:X} FileStandardInformation -> {sz} B ({f.Name})");
                        return 0;
                    case FileInternalInformation:
                        // FILE_INTERNAL_INFORMATION (8 B): index number (0 is fine)
                        for (int i = 0; i < 8; i++) { Marshal.WriteByte(fileInformation, i, 0); }
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(8);
                        return 0;
                    case FilePositionInformation:
                        // FILE_POSITION_INFORMATION (8 B): CurrentByteOffset@0 (i64) -- RandomAccessFile
                        // getFilePointer()/GetFileInformationByHandleEx(FilePositionInfo) query this.
                        Marshal.WriteInt64(fileInformation, 0, f.Pos);
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(8);
                        Log($"[NtQueryInformationFile] FAKE 0x{fileHandle:X} FilePositionInformation -> pos={f.Pos} ({f.Name})");
                        return 0;
                    case FileAllInformation:
                        // FILE_ALL_INFORMATION: Basic@0(40) + Standard@40(24) + Internal@64(8) +
                        // Ea@72(4) + Access@76(4) + Position@80(8) + Mode@88(4) + Alignment@92(4) +
                        // Name@96(2 + chars). Fill what the JVM's WindowsFileAttributes may read.
                        for (int i = 0; i < 96; i++) { Marshal.WriteByte(fileInformation, i, 0); }
                        Marshal.WriteInt32(fileInformation, 32, attrs);             // Basic.FileAttributes
                        Marshal.WriteInt64(fileInformation, 40, sz);           // Standard.AllocationSize
                        Marshal.WriteInt64(fileInformation, 48, sz);           // Standard.EndOfFile
                        Marshal.WriteByte(fileInformation, 61, f.IsDir ? (byte)1 : (byte)0); // Standard.Directory
                        Marshal.WriteInt64(fileInformation, 80, f.Pos);        // Position.CurrentByteOffset
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(96);
                        Log($"[NtQueryInformationFile] FAKE 0x{fileHandle:X} FileAllInformation -> {sz} B ({f.Name})");
                        return 0;
                    case FileAttributeTagInformation:
                        // FILE_ATTRIBUTE_TAG_INFORMATION (8 B): FileAttributes@0, ReparseTag@4
                        for (int i = 0; i < 8; i++) { Marshal.WriteByte(fileInformation, i, 0); }
                        Marshal.WriteInt32(fileInformation, 0, attrs);
                        ioStatus.Status = IntPtr.Zero;
                        ioStatus.Information = new IntPtr(8);
                        return 0;
                }
                Log($"[NtQueryInformationFile] FAKE 0x{fileHandle:X} class={fileInformationClass} -> STATUS_INVALID_INFO_CLASS");
                ioStatus.Status = new IntPtr(STATUS_INVALID_INFO_CLASS);
                ioStatus.Information = IntPtr.Zero;
                return STATUS_INVALID_INFO_CLASS;
            }
            return _origNtQueryInformationFile!(fileHandle, out ioStatus, fileInformation, length, fileInformationClass);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtQueryAttributesFile(ref OBJECT_ATTRIBUTES objAttr, IntPtr fileInformation)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQueryAttributesFile!(ref objAttr, fileInformation);
        }
        _suppressHooks++;
        try
        {
            string? name = ReadObjectName(ref objAttr);
            string? rest = StripZPrefix(name);
            if (rest is not null)
            {
                string? real = TryMap(rest);
                if (real is not null)
                {
                    // FILE_BASIC_INFORMATION (40 B) zero-filled; FileAttributes@36 = 0 (file) or
                    // FILE_ATTRIBUTE_DIRECTORY (Phase 2: --assetsDir etc. must stat as directories
                    // so Files.isDirectory on Z:\minecraft\... paths returns true).
                    bool isDir = ResolveIsDir(real);
                    for (int i = 0; i < 40; i++) Marshal.WriteByte(fileInformation, i, 0);
                    if (isDir) { Marshal.WriteInt32(fileInformation, 36, 0x10); }
                    Log($"[NtQueryAttributesFile] FAKE {(isDir ? "dir" : "exists")} '{name}' -> '{real}'");
                    return 0;
                }
                Log($"[NtQueryAttributesFile] Z: missing '{name}' -> STATUS_OBJECT_NAME_NOT_FOUND");
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            return _origNtQueryAttributesFile!(ref objAttr, fileInformation);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtQueryFullAttributesFile(ref OBJECT_ATTRIBUTES objAttr, IntPtr fileInformation)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQueryFullAttributesFile!(ref objAttr, fileInformation);
        }
        _suppressHooks++;
        try
        {
            string? name = ReadObjectName(ref objAttr);
            string? rest = StripZPrefix(name);
            if (rest is not null)
            {
                string? real = TryMap(rest);
                if (real is not null)
                {
                    // FILE_NETWORK_OPEN_INFORMATION (56 B): CreationTime@0 .. ChangeTime@24, AllocationSize@32,
                    // EndOfFile@40, FileAttributes@48, FileNameLength@52. .NET's FileStatus (FileInfo.Length)
                    // reads EndOfFile from this struct, so it must carry the real byte count.
                    bool isDir = ResolveIsDir(real);
                    long sz = isDir ? 0 : ResolveLength(real);
                    for (int i = 0; i < 56; i++) Marshal.WriteByte(fileInformation, i, 0);
                    Marshal.WriteInt64(fileInformation, 32, sz); // AllocationSize
                    Marshal.WriteInt64(fileInformation, 40, sz); // EndOfFile
                    if (isDir) { Marshal.WriteInt32(fileInformation, 48, 0x10); } // FILE_ATTRIBUTE_DIRECTORY
                    Log($"[NtQueryFullAttributesFile] FAKE {(isDir ? "dir" : "exists")} '{name}' -> '{real}' ({sz} B)");
                    return 0;
                }
                Log($"[NtQueryFullAttributesFile] Z: missing '{name}' -> STATUS_OBJECT_NAME_NOT_FOUND");
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            return _origNtQueryFullAttributesFile!(ref objAttr, fileInformation);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtQueryVolumeInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fsInformation, uint length, int fsInformationClass)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQueryVolumeInformationFile!(fileHandle, out ioStatus, fsInformation, length, fsInformationClass);
        }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryGetValue(fileHandle, out FakeFile? f))
            {
                const int FileFsVolumeInformation = 1;   // GetFileType probe
                const int FileFsDeviceInformation = 4;   // device-type probe
                int size = fsInformationClass switch
                {
                    FileFsVolumeInformation => 56,
                    FileFsDeviceInformation => 8,
                    _ => -1,
                };
                if (size < 0)
                {
                    ioStatus.Status = new IntPtr(STATUS_INVALID_INFO_CLASS);
                    ioStatus.Information = IntPtr.Zero;
                    Log($"[NtQueryVolumeInformationFile] FAKE 0x{fileHandle:X} class={fsInformationClass} -> STATUS_INVALID_INFO_CLASS");
                    return STATUS_INVALID_INFO_CLASS;
                }
                int fill = (int)Math.Min(length, (uint)size);
                for (int i = 0; i < fill; i++) Marshal.WriteByte(fsInformation, i, 0);
                if (fsInformationClass == FileFsDeviceInformation && length >= 8)
                {
                    // FILE_FS_DEVICE_INFORMATION: DeviceType@0 (u32), Characteristics@4 (u32).
                    // GetFileType() maps DeviceType -> FILE_TYPE_DISK; 0 would map to FILE_TYPE_UNKNOWN
                    // and kernelbase would reject GetFileSizeEx on the fake handle.
                    Marshal.WriteInt32(fsInformation, 0, 7); // FILE_DEVICE_DISK
                }
                ioStatus.Status = IntPtr.Zero;
                ioStatus.Information = new IntPtr(size);
                Log($"[NtQueryVolumeInformationFile] FAKE 0x{fileHandle:X} class={fsInformationClass} -> ok ({f.Name})");
                return 0;
            }
            return _origNtQueryVolumeInformationFile!(fileHandle, out ioStatus, fsInformation, length, fsInformationClass);
        }
        finally { _suppressHooks--; }
    }

    // S3b (check 13): RandomAccessFile.seek -> SetFilePointerEx -> NtSetInformationFile
    // (FilePositionInformation). Without this hook the seek reached the real kernel with the
    // fabricated handle -> STATUS_INVALID_HANDLE -> ZipFile ctor threw -> jar unusable.
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtSetInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass)
    {
        if (_suppressHooks > 0)
        {
            return _origNtSetInformationFile!(fileHandle, out ioStatus, fileInformation, length, fileInformationClass);
        }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryGetValue(fileHandle, out FakeFile? f))
            {
                const int FilePositionInformation = 14; // FILE_INFORMATION_CLASS (see NtQueryInformationFile)
                if (fileInformationClass == FilePositionInformation && length >= 8)
                {
                    // FILE_POSITION_INFORMATION (8 B): CurrentByteOffset@0 (i64) -- the new file
                    // pointer; subsequent NtReadFile(NULL offset) reads from here (f.Pos).
                    long pos = Marshal.ReadInt64(fileInformation, 0);
                    f.Pos = (int)Math.Min(Math.Max(pos, 0), int.MaxValue);
                    ioStatus.Status = IntPtr.Zero;
                    ioStatus.Information = new IntPtr(8);
                    Log($"[NtSetInformationFile] FAKE 0x{fileHandle:X} FilePositionInformation -> pos={f.Pos} ({f.Name})");
                    return 0;
                }
                Log($"[NtSetInformationFile] FAKE 0x{fileHandle:X} class={fileInformationClass} -> STATUS_INVALID_INFO_CLASS");
                ioStatus.Status = new IntPtr(STATUS_INVALID_INFO_CLASS);
                ioStatus.Information = IntPtr.Zero;
                return STATUS_INVALID_INFO_CLASS;
            }
            return _origNtSetInformationFile!(fileHandle, out ioStatus, fileInformation, length, fileInformationClass);
        }
        finally { _suppressHooks--; }
    }

    // ------------------------------------------------------------------ PHASE9: directory enumeration
    //
    // 根因 (2026-08-04, PHASE9-REGISTRY): JDK 25 的 WindowsLinkSupport.getRealPath 逐路径组件调
    // FindFirstFileW(旧 JDK 用 CreateFile+GetFinalPathNameByHandle), 而 kernelbase 的
    // FindFirstFileExW 打开【父目录】句柄 + NtQueryDirectoryFile 按 pattern 枚举。目录打开此前被
    // 拒(STATUS_OBJECT_NAME_NOT_FOUND, 日志 119x "[NtOpenFile] Z: directory '\??\Z:\'"), 且
    // NtQueryDirectoryFile 未 hook -> 真实内核收到假句柄 -> Z: 路径 toRealPath 全部
    // NoSuchFileException -> VanillaPackResourcesBuilder 用 jar: URL 打不开
    // minecraft-client-patched jar -> vanilla pack 空 -> data/minecraft 资源全缺
    // (TagLoader missing / RegistryDataLoader Unbound values) -> registry 加载崩溃。
    // 修复 = 目录假句柄 (Hook_NtOpenFile/NtCreateFile) + 本钩子 (真实目录枚举 -> 写
    // FILE_DIRECTORY_INFORMATION 族记录, FindFirstFileW/FindNextFileW 契约)。

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtQueryDirectoryFile(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        out IO_STATUS_BLOCK ioStatus, IntPtr fileInformation, uint length, int fileInformationClass,
        byte returnSingleEntry, IntPtr fileNamePtr, byte restartScan)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQueryDirectoryFile!(fileHandle, evt, apcRoutine, apcContext, out ioStatus, fileInformation,
                length, fileInformationClass, returnSingleEntry, fileNamePtr, restartScan);
        }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryGetValue(fileHandle, out FakeFile? f))
            {
                return ServeDirectoryQuery(f, fileHandle, out ioStatus, fileInformation, length,
                    fileInformationClass, returnSingleEntry != 0, fileNamePtr, restartScan != 0);
            }
            return _origNtQueryDirectoryFile!(fileHandle, evt, apcRoutine, apcContext, out ioStatus, fileInformation,
                length, fileInformationClass, returnSingleEntry, fileNamePtr, restartScan);
        }
        finally { _suppressHooks--; }
    }

    /// <summary>
    /// PHASE9 (续): NtQueryDirectoryFileEx —— Win11 25H2 kernelbase 的 FindFirstFileExW 实际调用
    /// 目标 (NtQueryDirectoryFile 仅老调用方用)。QueryFlags 的 SL_RESTART_SCAN(1)/
    /// SL_RETURN_SINGLE_ENTRY(2) 映射回与 NtQueryDirectoryFile 相同的业务体。
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtQueryDirectoryFileEx(IntPtr fileHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        out IO_STATUS_BLOCK ioStatus, IntPtr fileInformation, uint length, int fileInformationClass,
        uint queryFlags, IntPtr fileNamePtr)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQueryDirectoryFileEx!(fileHandle, evt, apcRoutine, apcContext, out ioStatus, fileInformation,
                length, fileInformationClass, queryFlags, fileNamePtr);
        }
        _suppressHooks++;
        try
        {
            if (FakeHandles.TryGetValue(fileHandle, out FakeFile? f))
            {
                const uint SL_RESTART_SCAN = 0x00000001;
                const uint SL_RETURN_SINGLE_ENTRY = 0x00000002;
                bool restartScan = (queryFlags & SL_RESTART_SCAN) != 0;
                bool singleEntry = (queryFlags & SL_RETURN_SINGLE_ENTRY) != 0;
                return ServeDirectoryQuery(f, fileHandle, out ioStatus, fileInformation, length,
                    fileInformationClass, singleEntry, fileNamePtr, restartScan);
            }
            return _origNtQueryDirectoryFileEx!(fileHandle, evt, apcRoutine, apcContext, out ioStatus, fileInformation,
                length, fileInformationClass, queryFlags, fileNamePtr);
        }
        finally { _suppressHooks--; }
    }

    /// <summary>NtQueryDirectoryFile 业务体: 枚举真实目录 -> 按 pattern 过滤 -> 写目录信息记录。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int ServeDirectoryQuery(FakeFile f, IntPtr fileHandle, out IO_STATUS_BLOCK ioStatus,
        IntPtr fileInformation, uint length, int fileInformationClass, bool returnSingleEntry, IntPtr fileNamePtr, bool restartScan)
    {
        // 各 info class 的固定头大小 (FileName 起始偏移); 1/2/3/37/38 覆盖 FindFirstFileW 全部
        // InfoLevel 与 JDK DirectoryStream 的 FileIdBothDirectoryInformation。
        // FILE_INFORMATION_CLASS (phnt): 1=FileDirectoryInformation, 2=FileFullDirectoryInformation,
        // 3=FileBothDirectoryInformation (kernelbase FindFirstFileExW 默认), 37=FileIdBothDirectoryInformation,
        // 38=FileIdFullDirectoryInformation。
        int hdr = fileInformationClass switch
        {
            1 => 64,   // FileDirectoryInformation
            2 => 68,   // FileFullDirectoryInformation
            3 => 94,   // FileBothDirectoryInformation
            37 => 102, // FileIdBothDirectoryInformation
            38 => 76,  // FileIdFullDirectoryInformation
            _ => 0,
        };
        if (hdr == 0)
        {
            Log($"[NtQueryDirectoryFile] FAKE 0x{fileHandle:X} class={fileInformationClass} -> INVALID_INFO_CLASS ({f.Name})");
            ioStatus.Status = new IntPtr(STATUS_INVALID_INFO_CLASS);
            ioStatus.Information = IntPtr.Zero;
            return STATUS_INVALID_INFO_CLASS;
        }
        string? pattern = ReadUnicodeString(fileNamePtr);
        EnsureDirEntries(f, pattern, restartScan);
        if (f.DirIndex >= f.DirEntries!.Length)
        {
            Log($"[NtQueryDirectoryFile] FAKE 0x{fileHandle:X} class={fileInformationClass} -> NO_MORE_FILES ({f.Name})");
            ioStatus.Status = new IntPtr(STATUS_NO_MORE_FILES);
            ioStatus.Information = IntPtr.Zero;
            return STATUS_NO_MORE_FILES;
        }
        int used = 0;
        while (f.DirIndex < f.DirEntries.Length)
        {
            DirEntry e = f.DirEntries[f.DirIndex];
            int entryLen = hdr + e.Name.Length * 2;
            int recordSize = (entryLen + 7) & ~7; // 8 字节对齐 (NextEntryOffset 对齐契约)
            bool more = !returnSingleEntry && f.DirIndex + 1 < f.DirEntries.Length;
            if (used + recordSize > length)
            {
                if (used == 0)
                {
                    Log($"[NtQueryDirectoryFile] FAKE 0x{fileHandle:X} -> BUFFER_OVERFLOW ({f.Name})");
                    ioStatus.Status = new IntPtr(STATUS_BUFFER_OVERFLOW);
                    ioStatus.Information = IntPtr.Zero;
                    return STATUS_BUFFER_OVERFLOW;
                }
                break;
            }
            WriteDirRecord(fileInformation + used, in e, hdr, fileInformationClass, more ? recordSize : 0);
            used += recordSize;
            f.DirIndex++;
            if (returnSingleEntry) { break; }
        }
        ioStatus.Status = IntPtr.Zero;
        ioStatus.Information = new IntPtr(used);
        Log($"[NtQueryDirectoryFile] FAKE 0x{fileHandle:X} class={fileInformationClass} -> {used} B ({f.Name})");
        return 0;
    }

    /// <summary>
    /// 构建/复用目录条目缓存。restartScan=TRUE (FindFirstFileW) 或 pattern 变化时重建;
    /// FindNextFileW (restartScan=FALSE) 继续用游标。真实目录枚举 + DOS pattern 过滤。
    /// Z: 根 (\??\Z:\ -> JDK 根) 注入虚拟 "openjdk"/"minecraft" 顶层目录条目
    /// (PHASE13 换层: 磁盘回退时 Z: 根枚举 = JDK 根内容 + 两个虚拟顶层)。
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static void EnsureDirEntries(FakeFile f, string? pattern, bool restartScan)
    {
        string pat = pattern ?? "";
        if (!restartScan && f.DirEntries != null && f.DirPattern == pat)
        {
            return; // 继续上次的游标 (FindNextFileW)
        }
        try
        {
            var list = new List<DirEntry>();
            bool injectTops = f.IsDir && string.Equals(f.Real, JdkRoot, StringComparison.OrdinalIgnoreCase);
            if (f.IsDir)
            {
                // 容器分支 (阶段 2): f.Real 是 Z: 伪路径 -> 从容器目录表枚举
                if (IsContainerReal(f.Real))
                {
                    string rest = f.Real[3..];
                    string? key = rest.Length == 0 ? "" : (Container.TryMapKey(rest, out string k, out bool isDir) && isDir ? k : null);
                    if (key is not null)
                    {
                        foreach ((string cname, bool cdir, long clen) in Container.EnumerateChildren(key))
                        {
                            if (!MatchesPattern(cname, pat)) { continue; }
                            list.Add(new DirEntry(cname, cdir, clen, 0, 0, 0, 0));
                        }
                    }
                }
                else
                {
                    foreach (string e in Directory.EnumerateFileSystemEntries(f.Real))
                    {
                        string n = Path.GetFileName(e);
                        if (!MatchesPattern(n, pat)) { continue; }
                        DirEntry de;
                        try { de = StatEntry(e, n); }
                        catch { de = new DirEntry(n, Directory.Exists(e), 0, 0, 0, 0, 0); }
                        list.Add(de);
                    }
                    if (injectTops)
                    {
                        if (MatchesPattern("openjdk", pat)) { list.Add(new DirEntry("openjdk", true, 0, 0, 0, 0, 0)); }
                        if (MatchesPattern("minecraft", pat)) { list.Add(new DirEntry("minecraft", true, 0, 0, 0, 0, 0)); }
                    }
                }
            }
            else
            {
                // 文件句柄上的枚举 (FindFirstFileExW 的 file-retry 路径): 单条目 = 文件自身
                string baseName = Path.GetFileName(f.Real);
                if (MatchesPattern(baseName, pat))
                {
                    try { list.Add(StatEntry(f.Real, baseName)); }
                    catch { list.Add(new DirEntry(baseName, false, 0, 0, 0, 0, 0)); }
                }
            }
            f.DirEntries = [.. list];
            f.DirPattern = pat;
            f.DirIndex = 0;
        }
        catch (Exception ex)
        {
            Log($"[NtQueryDirectoryFile] FAKE enumerate threw: {ex}");
            f.DirEntries = [];
            f.DirPattern = pat;
            f.DirIndex = 0;
        }
    }

    /// <summary>真实路径 stat -> DirEntry (FILETIME 为 UTC; 失败由调用方兜底)。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static DirEntry StatEntry(string realPath, string name)
    {
        if (Directory.Exists(realPath))
        {
            var di = new DirectoryInfo(realPath);
            return new DirEntry(name, true, 0,
                di.CreationTimeUtc.ToFileTimeUtc(), di.LastAccessTimeUtc.ToFileTimeUtc(),
                di.LastWriteTimeUtc.ToFileTimeUtc(), di.LastWriteTimeUtc.ToFileTimeUtc());
        }
        var fi = new FileInfo(realPath);
        return new DirEntry(name, false, fi.Length,
            fi.CreationTimeUtc.ToFileTimeUtc(), fi.LastAccessTimeUtc.ToFileTimeUtc(),
            fi.LastWriteTimeUtc.ToFileTimeUtc(), fi.LastWriteTimeUtc.ToFileTimeUtc());
    }

    /// <summary>DOS pattern 匹配: 无通配符走精确比较; 有通配符走迭代匹配。大小写不敏感。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static bool MatchesPattern(string name, string pattern)
    {
        if (pattern.Length == 0) { return true; }
        if (pattern.IndexOf('*') < 0 && pattern.IndexOf('?') < 0)
        {
            return string.Equals(name, pattern, StringComparison.OrdinalIgnoreCase);
        }
        return WildcardMatch(name, pattern);
    }

    /// <summary>迭代式 DOS 通配符匹配 ('*' 任意序列, '?' 单字符; NTFS 大小写不敏感)。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static bool WildcardMatch(string name, string pattern)
    {
        int ni = 0, pi = 0, star = -1, starNi = -1;
        while (ni < name.Length)
        {
            if (pi < pattern.Length && (pattern[pi] == '?' || char.ToUpperInvariant(pattern[pi]) == char.ToUpperInvariant(name[ni])))
            {
                pi++;
                ni++;
            }
            else if (pi < pattern.Length && pattern[pi] == '*')
            {
                star = pi++;
                starNi = ni;
            }
            else if (star >= 0)
            {
                pi = star + 1;
                ni = ++starNi;
            }
            else
            {
                return false;
            }
        }
        while (pi < pattern.Length && pattern[pi] == '*') { pi++; }
        return pi == pattern.Length;
    }

    /// <summary>写一条目录信息记录 (FILE_DIRECTORY_INFORMATION 族; 头 64/68/94/76/102 B 后跟 UTF-16 名)。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static void WriteDirRecord(IntPtr p, in DirEntry e, int hdr, int infoClass, int nextOffset)
    {
        for (int i = 0; i < hdr; i++) { Marshal.WriteByte(p, i, 0); }
        Marshal.WriteInt32(p, 0, nextOffset);                 // NextEntryOffset (0 = 最后一条)
        Marshal.WriteInt32(p, 4, 0);                          // FileIndex
        Marshal.WriteInt64(p, 8, e.Creation);                 // CreationTime (FILETIME)
        Marshal.WriteInt64(p, 16, e.LastAccess);              // LastAccessTime
        Marshal.WriteInt64(p, 24, e.LastWrite);               // LastWriteTime
        Marshal.WriteInt64(p, 32, e.Change);                  // ChangeTime
        Marshal.WriteInt64(p, 40, e.Length);                  // EndOfFile
        Marshal.WriteInt64(p, 48, e.Length);                  // AllocationSize
        Marshal.WriteInt32(p, 56, e.IsDir ? 0x10 : 0x20);     // FileAttributes
        Marshal.WriteInt32(p, 60, e.Name.Length * 2);         // FileNameLength (字节数)
        if (infoClass == 2 || infoClass == 3 || infoClass == 37 || infoClass == 38)
        {
            Marshal.WriteInt32(p, 64, 0);                     // EaSize
        }
        if (infoClass == 3 || infoClass == 37)
        {
            Marshal.WriteByte(p, 68, 0);                      // ShortNameLength (ShortName[24]@70 = 0)
        }
        if (infoClass == 38)
        {
            Marshal.WriteInt64(p, 68, 0);                     // FileId
        }
        if (infoClass == 37)
        {
            Marshal.WriteInt64(p, 94, 0);                     // FileId
        }
        int nameOff = hdr;
        for (int i = 0; i < e.Name.Length; i++)
        {
            Marshal.WriteInt16(p, nameOff + i * 2, (short)e.Name[i]);
        }
    }

    /// <summary>UNICODE_STRING* (Length@0, MaximumLength@2, Buffer@8) -> string? (find 的 pattern)。</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe string? ReadUnicodeString(IntPtr usPtr)
    {
        if (usPtr == IntPtr.Zero) { return null; }
        ushort len = (ushort)Marshal.ReadInt16(usPtr, 0);
        IntPtr buf = Marshal.ReadIntPtr(usPtr, 8);
        if (buf == IntPtr.Zero || len == 0) { return null; }
        return new string((char*)buf, 0, len / 2);
    }

    // ------------------------------------------------------------------ S3a: memory-mapped section hooks (data mapping only)

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe int Hook_NtCreateSection(out IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes,
        IntPtr maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
    {
        if (_suppressHooks > 0)
        {
            return _origNtCreateSection!(out sectionHandle, desiredAccess, objectAttributes, maximumSize,
                sectionPageProtection, allocationAttributes, fileHandle);
        }
        _suppressHooks++;
        try
        {
            sectionHandle = IntPtr.Zero;
            if (fileHandle != IntPtr.Zero && FakeHandles.TryGetValue(fileHandle, out FakeFile? f) && f.Buf is { } buf)
            {
                // ---- S2b: SEC_IMAGE on a fake file -> PURE fake section (no kernel call) ----
                // The LoadLibrary pipeline is fully ntdll-export-driven (LdrLoadDll -> LdrpMapDll ->
                // these exact calls), so the fabricated 0x52000000|n handle is never validated by the
                // real kernel (unlike kernelbase's CreateFileMappingW direct-syscall path, S3a).
                if ((allocationAttributes & SEC_IMAGE) != 0)
                {
                    if (!TryParsePe(buf, out PeInfo? pe) || pe is null)
                    {
                        Log($"[NtCreateSection] FAKE-IMAGE parse FAILED (not a PE32+ x64 image) ({f.Name})");
                        return STATUS_INVALID_IMAGE_FORMAT;
                    }
                    IntPtr h = MakeFakeSectionHandle();
                    Interlocked.Increment(ref buf.RefCount);
                    FakeSections[h] = new FakeSection { Buf = buf, Name = f.Name, IsImage = true, Pe = pe };
                    sectionHandle = h;
                    Log($"[NtCreateSection] FAKE-IMAGE file 0x{fileHandle:X} -> fake section=0x{h:X} "
                        + $"(base=0x{pe.ImageBase:X} size=0x{pe.SizeOfImage:X} aep=0x{pe.AddressOfEntryPoint:X}, '{f.Name}')");
                    return 0;
                }
                // ---- REAL anonymous section (S3a deviation, see class doc) ----
                // 25H2 内核契约 (run12 最小复现证据): 匿名 section 的 allocationAttributes 必须
                // 含 SEC_IMAGE_NO_EXECUTE (0x8000000) —— kernelbase CreateFileMappingW 对无 SEC_*
                // 标志的调用强制补该位 (反汇编证据: cmove esi, 8000000h); 缺它 (0 / SEC_COMMIT 0x800000)
                // 内核按镜像语义拒绝 (0xC00000F4 INVALID_IMAGE_NOT_MZ)。SEC_COMMIT 需剥离
                // (0x800000|0x8000000 组合同样被拒)。映射契约: allocationType=0 + 调用方保护
                // (PAGE_READONLY 可; PAGE_READWRITE 一律 0xC0000022/0xC000000D) —— 假字节写入
                // 走 VirtualProtect 临时 RW + 恢复 (Hook_NtMapViewOfSection)。
                long maxSize = buf.Length;
                uint effAttrs = (allocationAttributes & ~0x800000u /* SEC_COMMIT */) | SEC_IMAGE_NO_EXECUTE;
                int st = _origNtCreateSection!(out sectionHandle, desiredAccess, objectAttributes,
                    new IntPtr(&maxSize), PAGE_READWRITE, effAttrs, IntPtr.Zero);
                if (st != 0)
                {
                    Log($"[NtCreateSection] REAL anonymous section failed st=0x{st:X} ({f.Name}) "
                        + $"access=0x{(long)desiredAccess:X} alloc=0x{(long)allocationAttributes:X}");
                    return st;
                }
                // S3b: the section shares the file's NATIVE buffer; AddRef so closing the file
                // handle (or the section) alone cannot free it out from under the other holder.
                Interlocked.Increment(ref buf.RefCount);
                FakeSections[sectionHandle] = new FakeSection { Buf = buf, Name = f.Name };
                Log($"[NtCreateSection] FAKE file 0x{fileHandle:X} -> REAL section=0x{sectionHandle:X} "
                    + $"({buf.Length} B, '{f.Name}') access=0x{(long)desiredAccess:X} alloc=0x{(long)allocationAttributes:X}");
                return 0;
            }
            return _origNtCreateSection!(out sectionHandle, desiredAccess, objectAttributes, maximumSize,
                sectionPageProtection, allocationAttributes, fileHandle);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe int Hook_NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, IntPtr baseAddressPtr,
        IntPtr zeroBits, UIntPtr commitSize, IntPtr sectionOffsetPtr, IntPtr viewSizePtr,
        int inheritDisposition, uint allocationType, uint win32Protect)
    {
        if (_suppressHooks > 0)
        {
            return _origNtMapViewOfSection!(sectionHandle, processHandle, baseAddressPtr, zeroBits, commitSize,
                sectionOffsetPtr, viewSizePtr, inheritDisposition, allocationType, win32Protect);
        }
        _suppressHooks++;
        try
        {
            if (FakeSections.TryGetValue(sectionHandle, out FakeSection? s) && s.Buf is { } buf)
            {
                // ---- S2b: fake image section -> manual PE layout (no kernel call) ----
                // baseAddressPtr/viewSizePtr/sectionOffsetPtr are POINTERS TO THE LOADER'S SLOTS
                // (see D_NtMapViewOfSection doc: plain IntPtr = zero-copy through the IL stub).
                // Read the requested (wanted) base from the loader's slot; the loader passes NULL
                // to request any address.
                IntPtr want = baseAddressPtr == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(baseAddressPtr, 0);
                if (s.IsImage && s.Pe is { } pe)
                {
                    int st = MapImageIntoMemory(s, baseAddressPtr, viewSizePtr, sectionOffsetPtr);
                    IntPtr got = baseAddressPtr == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(baseAddressPtr, 0);
                    Log($"[NtMapViewOfSection] FAKE-IMAGE section=0x{sectionHandle:X} -> st=0x{st:X} "
                        + $"want=0x{want:X} base=0x{got:X} (pe-base=0x{pe.ImageBase:X}, '{s.Name}')");
                    return st;
                }
                // Map the view PAGE_WRITECOPY (0x08) instead of the caller's protection: the
                // section is created with SEC_IMAGE_NO_EXECUTE (25H2 W^X 加固), 其视图拒绝
                // PAGE_READWRITE 映射 (0xC0000022/0xC000000D) 且拒绝 VirtualProtect(RW)
                // (win32=87, run12 证据); 但 PAGE_WRITECOPY 映射可写 (私有写拷贝页, 最小复现
                // 探测: 138MB 直映射 + 写回读 OK)。调用方 (jimage) 只读, 无感知。
                // JVM 的 os::map_memory/jimage 以 0xFFFFFFFF 表示"映射整节" (run12 证据:
                // reqVS=4294967295), 内核会按 INVALID_VIEW_SIZE (0xC000001F) 拒绝 ——
                // 映射前规范化为节大小 (与整节映射语义一致, 内核成功后会写回实际大小)。
                if (viewSizePtr != IntPtr.Zero)
                {
                    long rawVS = Marshal.ReadInt64(viewSizePtr, 0);
                    if (rawVS <= 0 || rawVS > (long)buf.Length) { Marshal.WriteInt64(viewSizePtr, 0, buf.Length); }
                }
                int st2 = _origNtMapViewOfSection!(sectionHandle, processHandle, baseAddressPtr, zeroBits, commitSize,
                    sectionOffsetPtr, viewSizePtr, inheritDisposition, allocationType, 0x08 /* PAGE_WRITECOPY */);
                if (st2 != 0)
                {
                    long reqVS = viewSizePtr == IntPtr.Zero ? 0 : Marshal.ReadInt64(viewSizePtr, 0);
                    long reqOff = sectionOffsetPtr == IntPtr.Zero ? 0 : Marshal.ReadInt64(sectionOffsetPtr, 0);
                    Log($"[NtMapViewOfSection] real map failed st=0x{st2:X} section=0x{sectionHandle:X} ({s.Name}) "
                        + $"type=0x{(long)allocationType:X} commit={(long)commitSize} inherit={inheritDisposition} want=0x{(long)want:X} prot=0x{(long)win32Protect:X} reqVS={reqVS} reqOff={reqOff}");
                    return st2;
                }
                // serve the fake file's bytes from the real mapping (S3b: Span copy, no managed byte[])
                // runAOT-3 fix: copy ONLY the requested view range (section offset + view size), NOT
                // the whole file -- the JVM's FileChannel.map(full or PARTIAL range) must get exactly
                // the mapped bytes. The previous whole-file memcpy overflowed partial views and
                // corrupted the JVM heap (AV inside NewStringUTF after the game's first partial map).
                // WC 视图可写 -> 直接 memcpy, 无需 VirtualProtect。
                IntPtr dataBase = baseAddressPtr == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(baseAddressPtr, 0);
                long viewSize = viewSizePtr == IntPtr.Zero ? buf.Length : Marshal.ReadInt64(viewSizePtr, 0);
                long secOff = sectionOffsetPtr == IntPtr.Zero ? 0 : Marshal.ReadInt64(sectionOffsetPtr, 0);
                if (viewSize <= 0 || viewSize > (long)int.MaxValue) { viewSize = buf.Length; }
                if (secOff < 0) { secOff = 0; }
                long copyLen = Math.Min(viewSize, (long)buf.Length - secOff);
                if (copyLen < 0) { copyLen = 0; }
                if (copyLen > 0 && dataBase != IntPtr.Zero)
                {
                    new Span<byte>(buf.Data + secOff, (int)copyLen).CopyTo(new Span<byte>((void*)dataBase, (int)copyLen));
                }
                if (viewSizePtr != IntPtr.Zero) { Marshal.WriteIntPtr(viewSizePtr, 0, new IntPtr(copyLen)); }
                if (sectionOffsetPtr != IntPtr.Zero) { Marshal.WriteInt64(sectionOffsetPtr, 0, secOff); }
                FakeMappedBases[dataBase] = MapKindData;
                Log($"[NtMapViewOfSection] FAKE section=0x{sectionHandle:X} -> base=0x{dataBase:X} view={copyLen} B (off={secOff})");
                return 0;
            }
            return _origNtMapViewOfSection!(sectionHandle, processHandle, baseAddressPtr, zeroBits, commitSize,
                sectionOffsetPtr, viewSizePtr, inheritDisposition, allocationType, win32Protect);
        }
        finally { _suppressHooks--; }
    }

    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static int Hook_NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress)
    {
        if (_suppressHooks > 0)
        {
            return _origNtUnmapViewOfSection!(processHandle, baseAddress);
        }
        _suppressHooks++;
        try
        {
            if (FakeMappedBases.TryRemove(baseAddress, out int kind))
            {
                if (kind == MapKindImage)
                {
                    // S2b: fake image map -> our own VirtualAlloc region, free it directly
                    VirtualFree(baseAddress, UIntPtr.Zero, MEM_RELEASE);
                    Log($"[NtUnmapViewOfSection] FAKE-IMAGE base=0x{baseAddress:X} VirtualFree(MEM_RELEASE)");
                    return 0;
                }
                int st = _origNtUnmapViewOfSection!(processHandle, baseAddress);
                Log($"[NtUnmapViewOfSection] FAKE base=0x{baseAddress:X} real unmap st=0x{st:X}");
                return 0;
            }
            return _origNtUnmapViewOfSection!(processHandle, baseAddress);
        }
        finally { _suppressHooks--; }
    }

    // ------------------------------------------------------------------ S2b: fake image section query

    /// <summary>
    /// S2b hook #13: NtQuerySection on a fake IMAGE section. The loader (LdrpMapDll) queries
    /// SectionImageInformation to derive the image base (TransferAddress - AddressOfEntryPoint) and
    /// to check IMAGE_FILE_DLL before/around mapping, so this MUST be served purely from the PE
    /// headers cached at section-create time (may run before NtMapViewOfSection -> PE ImageBase,
    /// not the actual base).
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe int Hook_NtQuerySection(IntPtr sectionHandle, int infoClass, IntPtr infoBuffer,
        UIntPtr infoLength, IntPtr returnLengthPtr)
    {
        if (_suppressHooks > 0)
        {
            return _origNtQuerySection!(sectionHandle, infoClass, infoBuffer, infoLength, returnLengthPtr);
        }
        _suppressHooks++;
        try
        {
            if (FakeSections.TryGetValue(sectionHandle, out FakeSection? s) && s.IsImage && s.Pe is { } pe)
            {
                // SECTION_INFORMATION_CLASS: 0 = SectionBasicInformation, 1 = SectionImageInformation,
                // 2 = SectionRelocationInformation (legacy image-info alias per task spec)
                if (infoClass == 1 || infoClass == 2)
                {
                    const int SII_SIZE = 0x60;
                    if (returnLengthPtr != IntPtr.Zero) { Marshal.WriteIntPtr(returnLengthPtr, new IntPtr(SII_SIZE)); }
                    if (infoBuffer == IntPtr.Zero || infoLength.ToUInt64() < SII_SIZE)
                    {
                        return STATUS_INFO_LENGTH_MISMATCH;
                    }
                    FillSectionImageInfo(pe, infoBuffer);
                    Log($"[NtQuerySection] FAKE-IMAGE 0x{sectionHandle:X} class={infoClass} -> SII 0x{SII_SIZE:X} B (pe-base=0x{pe.ImageBase:X})");
                    return 0;
                }
                if (infoClass == 0)
                {
                    // SECTION_BASIC_INFORMATION (24 B): BaseAddress@0=0, AllocationAttributes@8=SEC_IMAGE,
                    // MaximumSize@16=SizeOfImage
                    const int SBI_SIZE = 24;
                    if (returnLengthPtr != IntPtr.Zero) { Marshal.WriteIntPtr(returnLengthPtr, new IntPtr(SBI_SIZE)); }
                    if (infoBuffer == IntPtr.Zero || infoLength.ToUInt64() < SBI_SIZE)
                    {
                        return STATUS_INFO_LENGTH_MISMATCH;
                    }
                    for (int i = 0; i < SBI_SIZE; i++) { Marshal.WriteByte(infoBuffer, i, 0); }
                    Marshal.WriteInt32(infoBuffer, 8, (int)SEC_IMAGE);
                    Marshal.WriteInt64(infoBuffer, 16, pe.SizeOfImage);
                    Log($"[NtQuerySection] FAKE-IMAGE 0x{sectionHandle:X} class=0 -> SBI (size=0x{pe.SizeOfImage:X})");
                    return 0;
                }
                Log($"[NtQuerySection] FAKE-IMAGE 0x{sectionHandle:X} class={infoClass} -> trampoline");
            }
            return _origNtQuerySection!(sectionHandle, infoClass, infoBuffer, infoLength, returnLengthPtr);
        }
        finally { _suppressHooks--; }
    }

    // ------------------------------------------------------------------ S2b: PE parse + manual image layout

    /// <summary>Fabricated section handle for fake SEC_IMAGE sections: 0x52000000|n.</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static IntPtr MakeFakeSectionHandle()
    {
        uint n = (uint)Interlocked.Increment(ref _sectionCounter) & 0x00FFFFFFu;
        return new IntPtr(0x52000000u | n);
    }

    /// <summary>
    /// Parse PE32+ (x64) headers from the native file buffer. Offsets per spike spec: e_lfanew@0x3C,
    /// PE sig @e_lfanew, Machine@+4 (0x8664), NumberOfSections@+6, SizeOfOptionalHeader@+0x14,
    /// Characteristics@+0x16, optional header @e_lfanew+0x18 (AEP@+16, ImageBase@+24, SectionAlignment@+32,
    /// FileAlignment@+36, Subsystem versions @+48/+50, SizeOfImage@+56, SizeOfHeaders@+60, Subsystem@+68,
    /// DllCharacteristics@+70, SizeOfStackReserve@+72, SizeOfStackCommit@+80, LoaderFlags@+104);
    /// section table @opt+SizeOfOptionalHeader, 40 B each (VirtualSize@+8, VirtualAddress@+12,
    /// SizeOfRawData@+16, PointerToRawData@+20).
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe bool TryParsePe(NativeBuffer buf, out PeInfo? pe)
    {
        pe = null;
        byte* d = buf.Data;
        int len = buf.Length;
        if (d == null || len < 0x40 || d[0] != (byte)'M' || d[1] != (byte)'Z') { return false; }
        int e = *(int*)(d + 0x3C); // e_lfanew
        if (e < 0 || e + 0x18 + 108 > len || *(int*)(d + e) != 0x00004550) { return false; } // "PE\0\0"
        if (*(ushort*)(d + e + 4) != 0x8664) { return false; } // Machine: x64 only (spike scope)
        ushort nSections = *(ushort*)(d + e + 6);
        ushort optSize = *(ushort*)(d + e + 0x14);
        if (nSections == 0 || optSize < 108) { return false; }
        int opt = e + 0x18;
        if (opt + optSize + (int)nSections * 40 > len) { return false; }
        if (*(ushort*)(d + opt) != 0x20B) { return false; } // PE32+ magic
        ushort majSub = *(ushort*)(d + opt + 48);
        ushort minSub = *(ushort*)(d + opt + 50);
        var p = new PeInfo
        {
            FileSize = len,
            AddressOfEntryPoint = *(uint*)(d + opt + 16),
            ImageBase = *(long*)(d + opt + 24),
            SizeOfImage = *(uint*)(d + opt + 56),
            SizeOfHeaders = *(uint*)(d + opt + 60),
            Subsystem = *(ushort*)(d + opt + 68),
            DllCharacteristics = *(ushort*)(d + opt + 70),
            SizeOfStackReserve = *(long*)(d + opt + 72),
            SizeOfStackCommit = *(long*)(d + opt + 80),
            LoaderFlags = *(uint*)(d + opt + 104),
            Characteristics = *(ushort*)(d + e + 0x16),
            MajorOperatingSystemVersion = *(ushort*)(d + opt + 40),
            MinorOperatingSystemVersion = *(ushort*)(d + opt + 42),
            MajorImageVersion = *(ushort*)(d + opt + 44),
            MinorImageVersion = *(ushort*)(d + opt + 46),
            MajorSubsystemVersion = majSub,
            MinorSubsystemVersion = minSub,
            SubSystemMajorVersion = majSub,
            SubSystemMinorVersion = minSub,
        };
        var sections = new (int VirtualAddress, int VirtualSize, int SizeOfRawData, int PointerToRawData)[nSections];
        int secTab = opt + optSize;
        for (int i = 0; i < nSections; i++)
        {
            byte* s = d + secTab + i * 40;
            sections[i] = ((int)*(uint*)(s + 12), (int)*(uint*)(s + 8), (int)*(uint*)(s + 16), (int)*(uint*)(s + 20));
        }
        p.Sections = sections;
        pe = p;
        return true;
    }

    /// <summary>
    /// S2b manual PE layout: VirtualAlloc(requested base or NULL, SizeOfImage, RESERVE|COMMIT,
    /// PAGE_EXECUTE_READWRITE) -> copy SizeOfHeaders -> copy each section (raw bytes, zero-fill the
    /// VirtualSize tail) -> register in FakeMappedBases (kind = image). NO kernel section call; the
    /// loader's relocation/import/DllMain processing then runs against this real memory exactly as
    /// it would against a real SEC_IMAGE mapping.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe int MapImageIntoMemory(FakeSection s, IntPtr baseAddressPtr, IntPtr viewSizePtr, IntPtr sectionOffsetPtr)
    {
        try
        {
            return MapImageLayout(s, baseAddressPtr, viewSizePtr, sectionOffsetPtr);
        }
        catch (Exception ex)
        {
            // DIAGNOSTIC (S2b): an exception on this hooked stack propagates through ntdll loader
            // frames and fail-fasts (ReversePInvokeBadTransition). Log the FULL exception
            // (rule: never ex.Message alone) and fail the map gracefully instead.
            Log($"[NtMapViewOfSection] FAKE-IMAGE EXCEPTION in layout:\n{ex}");
            return STATUS_UNSUCCESSFUL;
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static unsafe int MapImageLayout(FakeSection s, IntPtr baseAddressPtr, IntPtr viewSizePtr, IntPtr sectionOffsetPtr)
    {
        PeInfo pe = s.Pe ?? throw new InvalidOperationException("MapImageIntoMemory: image section without PeInfo");
        NativeBuffer buf = s.Buf ?? throw new InvalidOperationException("MapImageIntoMemory: image section without buffer");
        byte* data = buf.Data;
        int len = buf.Length;
        if (data == null || len < 0x40) { return STATUS_INVALID_IMAGE_FORMAT; }
        // baseAddressPtr points at the loader's slot: read the REQUESTED base (NULL = any address)
        IntPtr want = baseAddressPtr == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(baseAddressPtr, 0);
        IntPtr allocBase;
        long relocDelta = 0; // nonzero = image relocated away from its declared ImageBase
        if (want == IntPtr.Zero)
        {
            // REAL SEC_IMAGE kernel contract: a NULL requested base maps at the image's PREFERRED
            // base (the section object knows ImageBase). The 25H2 loader ASSUMES this: it computes
            // image-relative addresses (e.g. TLS AddressOfIndex write) from the header's ImageBase
            // field -- runS2b-22 VEH evidence: ntdll!LdrpAllocateTlsEntry+0xaf AV'd writing the TLS
            // index to 0x180000000+0xE75E7C after we returned a random base with st=0.
            allocBase = VirtualAlloc((IntPtr)pe.ImageBase, (nuint)pe.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (allocBase == IntPtr.Zero)
            {
                // preferred base busy (two DLLs claiming 0x180000000, e.g. java.dll after jvm.dll):
                // map at a random base, then patch the MAPPED header ImageBase to the actual base
                // and pre-apply the .reloc fixups, so the loader's preferred-base computations
                // agree with the mapping and it skips its own relocation (base == ImageBase).
                allocBase = VirtualAlloc(IntPtr.Zero, (nuint)pe.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (allocBase == IntPtr.Zero)
                {
                    return STATUS_NO_MEMORY;
                }
                relocDelta = allocBase.ToInt64() - pe.ImageBase;
            }
        }
        else
        {
            // explicit base request (loader retry after a NULL-base result != ImageBase)
            allocBase = VirtualAlloc(want, (nuint)pe.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (allocBase == IntPtr.Zero)
            {
                return STATUS_INVALID_IMAGE_BASE;
            }
        }
        Log($"[layout] {pe.SizeOfImage:X} {pe.SizeOfHeaders:X} want=0x{want:X} base=0x{allocBase:X} len={len}");
        // headers
        int hdr = (int)Math.Min(pe.SizeOfHeaders, (uint)len);
        if (hdr > 0) { Buffer.MemoryCopy(data, (void*)allocBase, pe.SizeOfImage, hdr); }
        if (hdr < (int)pe.SizeOfHeaders)
        {
            new Span<byte>((void*)((byte*)allocBase + hdr), (int)pe.SizeOfHeaders - hdr).Clear();
        }
        // sections
        int n = 0;
        foreach ((int va, int vsz, int rawsz, int rawptr) in pe.Sections)
        {
            Log($"[layout] sec {n} va=0x{va:X} vsz=0x{vsz:X} rawsz=0x{rawsz:X} rawptr=0x{rawptr:X}");
            n++;
            if (va < 0 || va >= (int)pe.SizeOfImage) { continue; }
            byte* dst = (byte*)allocBase + va;
            int copy = 0;
            if (rawptr >= 0 && rawptr < len) { copy = Math.Min(rawsz, len - rawptr); }
            long dstRoom = (long)pe.SizeOfImage - va;
            if (copy > dstRoom) { copy = (int)dstRoom; }
            if (copy > 0) { Buffer.MemoryCopy(data + rawptr, dst, dstRoom, copy); }
            int total = Math.Max(vsz, rawsz);
            if (total > copy && va + total <= (int)pe.SizeOfImage)
            {
                new Span<byte>(dst + copy, total - copy).Clear();
            }
        }
        if (relocDelta != 0)
        {
            // Relocated image (preferred base was busy): patch the MAPPED copy's header ImageBase
            // to the ACTUAL base (the loader computes TLS/image-relative addresses from it) and
            // apply the .reloc fixups ourselves (the loader then skips its own relocation because
            // it sees base == ImageBase). Data directory index 5 = IMAGE_DIRECTORY_ENTRY_BASERELOC.
            byte* mapped = (byte*)allocBase;
            int me = *(int*)(mapped + 0x3C); // e_lfanew of the mapped copy (headers were copied)
            int mopt = me + 0x18;
            *(long*)(mapped + mopt + 24) = allocBase.ToInt64(); // ImageBase -> actual base
            uint nDirs = *(uint*)(mapped + mopt + 108);         // NumberOfRvaAndSizes
            if (nDirs > 5)
            {
                byte* dd = mapped + mopt + 0x70; // data directory
                uint relocRva = *(uint*)(dd + 5 * 8);
                uint relocSize = *(uint*)(dd + 5 * 8 + 4);
                if (relocRva != 0 && relocSize >= 8 && relocRva < pe.SizeOfImage)
                {
                    uint pos = relocRva;
                    uint end = Math.Min(relocRva + relocSize, pe.SizeOfImage);
                    while (pos + 8 <= end)
                    {
                        byte* block = mapped + pos;
                        uint blockVa = *(uint*)block;         // VirtualAddress of this block
                        uint blockSize = *(uint*)(block + 4); // SizeOfBlock (incl. 8B header)
                        if (blockSize < 8 || pos + blockSize > end) { break; }
                        int nFixups = (int)((blockSize - 8) / 2);
                        for (int i = 0; i < nFixups; i++)
                        {
                            ushort entry = *(ushort*)(block + 8 + i * 2);
                            int type = entry >> 12;
                            int off = entry & 0xFFF;
                            if (type == 0x0A) // IMAGE_REL_BASED_DIR64
                            {
                                *(long*)(mapped + blockVa + off) += relocDelta;
                            }
                        }
                        pos += blockSize;
                    }
                }
            }
            Log($"[layout] RELOC delta=0x{relocDelta:X} base=0x{allocBase:X} (patched ImageBase + .reloc applied)");
        }
        // Write the map results back to the loader's slots. ALL THREE are explicit null-guarded
        // writes (S2b byref workaround, see D_NtMapViewOfSection doc): sectionOffset is OPTIONAL
        // in the native API and the loader passes NULL (LdrpMinimalMapModule) -- a CLR `ref` for
        // it would NRE on the write-back through NULL on the hooked stack (runS2b-5..20 evidence:
        // base/view ref writes landed, the NULL `ref long` offset write NRE'd).
        if (baseAddressPtr != IntPtr.Zero) { Marshal.WriteIntPtr(baseAddressPtr, 0, allocBase); }
        if (viewSizePtr != IntPtr.Zero) { Marshal.WriteIntPtr(viewSizePtr, 0, new IntPtr((long)pe.SizeOfImage)); }
        if (sectionOffsetPtr != IntPtr.Zero) { Marshal.WriteInt64(sectionOffsetPtr, 0, 0); }
        pe.ActualBase = allocBase.ToInt64(); // SII TransferAddress follows the real mapping
        // indexer (not TryAdd): a STALE data-map entry may exist at this address (S3a check 6/7
        // MMF unmaps go through kernelbase direct syscalls that bypass the ntdll hook, leaving a
        // dead MapKindData entry); the latest map kind must win so NtUnmapViewOfSection chooses
        // VirtualFree (image) over the real unmap (which returns STATUS_INVALID_ADDRESS).
        FakeMappedBases[allocBase] = MapKindImage;
        Log($"[layout] done base=0x{allocBase:X}");
        return 0;
    }

    /// <summary>Fill a 0x60-byte SECTION_IMAGE_INFORMATION from the cached PE headers (task layout).</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe void FillSectionImageInfo(PeInfo pe, IntPtr infoBuffer)
    {
        byte* p = (byte*)infoBuffer;
        for (int i = 0; i < 0x60; i++) { p[i] = 0; }
        long baseAddr = pe.ActualBase != 0 ? pe.ActualBase : pe.ImageBase;
        *(long*)(p + 0x00) = baseAddr + pe.AddressOfEntryPoint; // TransferAddress
        // ZeroBits @0x08 = 0
        *(long*)(p + 0x10) = pe.SizeOfStackReserve;  // MaximumStackSize
        *(long*)(p + 0x18) = pe.SizeOfStackCommit;   // CommittedStackSize
        *(uint*)(p + 0x20) = pe.Subsystem;           // SubSystemType
        *(ushort*)(p + 0x24) = pe.SubSystemMinorVersion;
        *(ushort*)(p + 0x26) = pe.SubSystemMajorVersion;
        *(ushort*)(p + 0x28) = pe.MajorOperatingSystemVersion;
        *(ushort*)(p + 0x2A) = pe.MinorOperatingSystemVersion;
        *(ushort*)(p + 0x2C) = pe.MajorImageVersion;
        *(ushort*)(p + 0x2E) = pe.MinorImageVersion;
        *(ushort*)(p + 0x30) = pe.MajorSubsystemVersion;
        *(ushort*)(p + 0x32) = pe.MinorSubsystemVersion;
        *(ushort*)(p + 0x34) = pe.MajorSubsystemVersion;
        *(ushort*)(p + 0x36) = pe.MinorSubsystemVersion;
        *(uint*)(p + 0x38) = pe.Characteristics;     // ImageCharacteristics
        *(uint*)(p + 0x3C) = (uint)pe.FileSize;      // ImageFileSize
        *(uint*)(p + 0x40) = pe.LoaderFlags;
        *(uint*)(p + 0x44) = pe.DllCharacteristics;
        *(uint*)(p + 0x48) = (pe.Characteristics & 0x2) != 0 ? 1u : 0u; // ImageContainsCode
        // 0x4C..0x5F stay zero (ImageContainsCodeFrozen/Hollow/InRange, FileRange...)
    }

    /// <summary>
    /// JIT-warm the S2b pipeline (PE parse + image layout + SII fill + VirtualFree) against a REAL
    /// PE file BEFORE any detour exists (S3a JIT-safety discipline; all of this runs inside hooks).
    /// </summary>
    public static unsafe void WarmupImagePipeline(string realPath)
    {
        NativeBuffer b = ReadFileToNative(realPath);
        try
        {
            if (!TryParsePe(b, out PeInfo? pe) || pe is null)
            {
                Log($"[jit-safety] warmup image parse FAILED for {realPath}");
                return;
            }
            var fake = new FakeSection { Buf = b, Name = "warmup", IsImage = true, Pe = pe };
            // S2b byref workaround: exercise the EXPLICIT slot-write path with the same shape as
            // the real loader call (the hook receives IntPtr POINTERS to the caller's slots and
            // writes through them directly -- no CLR `ref` marshaling anywhere in the path).
            IntPtr baseAddr = IntPtr.Zero;
            UIntPtr viewSize = UIntPtr.Zero;
            long off = 0;
            int st = MapImageIntoMemory(fake, (IntPtr)(&baseAddr), (IntPtr)(&viewSize), (IntPtr)(&off));
            Log($"[jit-safety] warmed image pipeline: st=0x{st:X} base=0x{baseAddr:X} size=0x{viewSize.ToUInt64():X} ({realPath})");
        // pre-JIT the StackTrace(true) diagnostic used by the layout exception catcher
        _ = new System.Diagnostics.StackTrace(true);
            if (st == 0 && baseAddr != IntPtr.Zero)
            {
                FakeMappedBases.TryRemove(baseAddr, out _);
                VirtualFree(baseAddr, UIntPtr.Zero, MEM_RELEASE);
            }
            IntPtr probe = Marshal.AllocHGlobal(0x60);
            FillSectionImageInfo(pe, probe);
            Marshal.FreeHGlobal(probe);
        }
        finally { ReleaseBuffer(b); }
        Log("[jit-safety] warmed PE parse + image layout + SII fill path");
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// Read a whole file into NATIVE memory (no managed byte[] -> no LOH object in the hook
    /// pipeline). Called from the create/open hooks with the suppression flag active, so the
    /// FileStream work passes straight through the detours. Length is int-capped (same bound as the
    /// previous byte[] design; spike files are &lt; 16MB).
    /// </summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    // P/Invoke file read for ReadFileToNative: MUST NOT use CLR FileStream/File APIs here. Those
    // go through coreclr internal paths that call ntdll via [SuppressGCTransition] P/Invoke
    // (thread stays Cooperative), and when the target is one of OUR patched ntdll exports the
    // detour thunk detects Cooperative + reverse P/Invoke -> ReversePInvokeBadTransition
    // (0x80131506, runMH-26 evidence: Z:-mode fake reads crashed, REALCP-mode real reads did not).
    // Explicit [DllImport] P/Invoke stubs switch the thread Preemptive, so re-entry into the
    // nested hook (suppressed by _suppressHooks) is always legal.
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern unsafe bool ReadFile(IntPtr hFile, byte* lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x1, FILE_SHARE_WRITE = 0x2;
    private const uint OPEN_EXISTING = 3;

    private static unsafe NativeBuffer ReadFileToNative(string realPath)
    {
        // 容器分支 (阶段 2): Z: 伪路径 -> 从 mmap 映射内存零拷贝读入原生缓冲
        // (NativeBuffer 语义与磁盘读一致: NativeMemory.Alloc + 引用计数, 免 LOH)。
        if (IsContainerReal(realPath))
        {
            string rest = realPath[3..];
            if (Container.TryMapKey(rest, out string key, out bool isDir) && !isDir)
            {
                long len = Container.GetLength(key);
                if (len <= 0)
                {
                    return new NativeBuffer { Data = null, Length = 0, RefCount = 1 };
                }
                byte* data = (byte*)NativeMemory.Alloc((nuint)len);
                try
                {
                    Container.ReadAt(key, new Span<byte>(data, (int)len), 0);
                    return new NativeBuffer { Data = data, Length = (int)len, RefCount = 1 };
                }
                catch
                {
                    NativeMemory.Free(data);
                    throw;
                }
            }
        }
        Microsoft.Win32.SafeHandles.SafeFileHandle h = CreateFileW(realPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0x80 /* FILE_ATTRIBUTE_NORMAL */, IntPtr.Zero);
        if (h.IsInvalid)
        {
            throw new IOException($"CreateFileW failed ({Marshal.GetLastWin32Error()}) for {realPath}");
        }
        try
        {
            if (!GetFileSizeEx(h.DangerousGetHandle(), out long len) || len <= 0)
            {
                h.SetHandleAsInvalid();
                CloseHandle(h.DangerousGetHandle());
                return new NativeBuffer { Data = null, Length = 0, RefCount = 1 };
            }
            byte* data = (byte*)NativeMemory.Alloc((nuint)len);
            try
            {
                uint total = 0;
                while (total < len)
                {
                    uint chunk = (uint)Math.Min(len - total, 1 << 20);
                    if (!ReadFile(h.DangerousGetHandle(), data + total, chunk, out uint got, IntPtr.Zero))
                    {
                        throw new IOException($"ReadFile failed ({Marshal.GetLastWin32Error()}) for {realPath}");
                    }
                    total += got;
                    if (got == 0) { throw new EndOfStreamException($"unexpected EOF for {realPath}"); }
                }
                return new NativeBuffer { Data = data, Length = (int)len, RefCount = 1 };
            }
            catch
            {
                NativeMemory.Free(data);
                throw;
            }
        }
        finally
        {
            CloseHandle(h.DangerousGetHandle());
            h.SetHandleAsInvalid();
        }
    }

    /// <summary>Drop one reference on a native byte buffer; free it when the last holder lets go.</summary>
    [MethodImpl(MethodImplOptions.NoOptimization)]
    private static unsafe void ReleaseBuffer(NativeBuffer? buf)
    {
        if (buf is null) { return; }
        if (Interlocked.Decrement(ref buf.RefCount) == 0)
        {
            if (buf.Data != null)
            {
                NativeMemory.Free(buf.Data);
                buf.Data = null;
            }
            Log($"[native] freed {buf.Length} B buffer");
            buf.Length = 0;
        }
    }

    /// <summary>
    /// JIT-warm the native read + Span-copy path used by the hooks BEFORE any detour exists
    /// (S3a JIT safety; the hook bodies call ReadFileToNative / Span.CopyTo, whose first call
    /// would otherwise JIT on the hooked stack).
    /// </summary>
    public static unsafe void WarmupNativeRead(string realPath)
    {
        NativeBuffer b = ReadFileToNative(realPath);
        if (b.Length > 0)
        {
            void* dst = NativeMemory.Alloc((nuint)b.Length);
            new Span<byte>(b.Data, b.Length).CopyTo(new Span<byte>(dst, b.Length));
            NativeMemory.Free(dst);
        }
        ReleaseBuffer(b);
        Log("[jit-safety] warmed native file read + span copy path");
    }

    private static void Log(string msg)
    {
        lock (LogLock) Console.WriteLine($"[t{Environment.CurrentManagedThreadId}] {msg}");
    }

    private static class DebugHelpers
    {
        public static unsafe void AssertLayouts()
        {
            // x64 struct sizes (checked at runtime on first init)
            if (sizeof(UNICODE_STRING) != 16) { throw new InvalidOperationException("UNICODE_STRING layout mismatch"); }
            if (sizeof(OBJECT_ATTRIBUTES) != 48) { throw new InvalidOperationException("OBJECT_ATTRIBUTES layout mismatch"); }
            if (sizeof(IO_STATUS_BLOCK) != 16) { throw new InvalidOperationException("IO_STATUS_BLOCK layout mismatch"); }
        }
    }
}
