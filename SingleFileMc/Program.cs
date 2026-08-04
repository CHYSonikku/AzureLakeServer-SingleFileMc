using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace SingleFileMc;

/// <summary>
/// SingleFileMc host: JVM over the fake file I/O pipeline (Z:\ virtual paths -> real disk alias
/// through the ntdll hooks) + JNI process-hosted JVM + Minecraft launch chain (McLaunch).
///
/// Production flow (PHASE7-CLEAN.md):
///   1. JIT-safety warmup (compile everything before the first detour: teardown path, launch
///      pipeline against real paths, PE/image-layout path, JNI delegates).
///   2. FakeFileSystem.Init() installs the ntdll hooks (fake handles / Z: path mapping / fake
///      SEC_IMAGE / native guard stub bridge).
///   3. jvm.dll loads from the REAL path; JNI_CreateJavaVM starts the JVM with the virtual Z:
///      classpath (the MC libraries tree maps through the hooks).
///   4. McLaunch runs the full Minecraft launch chain (version json -> classpath/args -> natives ->
///      gameDir -> Client.main(String[]) with the 180 s watchdog).
///   5. TerminateProcess exits without CLR teardown (a hooked-stack graceful shutdown is not safe).
///
/// JIT-safety discipline (kept): compile-everything-before-the-first-detour + TerminateProcess
/// exit are what keep the process alive on a hooked stack. GC runs with the default config
/// (workstation + background); the native guard stubs' 前置分流 (real handles/paths -> Orig
/// trampoline, only fake handles/Z: paths -> managed) keeps GC-internal ntdll calls out of the
/// managed hooks.
/// </summary>
internal static class Program
{
    /// <summary>jvm.dll 是否从容器加载 (假 SEC_IMAGE, Z: 路径)。false = 磁盘真实 JDK。
    /// McLaunch 据此决定是否显式 -Djava.home。</summary>
    public static bool JvmFromContainer;

    /// <summary>PHASE11-AOT: NativeAOT 进程标志。AOT 下无 JIT —— 所有 JIT 预热
    /// (PrepareMethod 反射预热 / GetMethod) 无意义且触发 AOT 反射告警, 统一跳过。</summary>
    public static bool IsAot => !RuntimeFeature.IsDynamicCodeSupported;

    private static int Main()
    {
        // JIT safety (S3a): disable tiered compilation as early as possible. The authoritative
        // knob is the runtimeconfig option (System.Runtime.TieredCompilation=false, see csproj);
        // this process-level switch is belt-and-braces.
        AppContext.SetSwitch("System.Runtime.TieredCompilation", false);

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("=== SingleFileMc: JVM over VFS (fake file I/O Z: -> container zip | real disk alias + JNI + fake SEC_IMAGE) ===");

        // 阶段 2: 容器数据源 —— 宿主最早期 mmap 自身 exe 并解析尾部 Store zip。
        // 无尾部 zip -> Active=false, 数据源回退真实磁盘别名 (既有 TryMap 磁盘分支)。
        Container.Init();

        // Phase 2 diag: record every managed exception first-chance. A managed exception thrown
        // inside a hook (native->managed thunk frame) propagates back through the thunk's
        // exception boundary; with the detours live the propagation can itself re-enter the
        // runtime illegally (ReversePInvokeBadTransition 0x80131506). Logging the exception
        // pinpoints the throwing hook.
        AppDomain.CurrentDomain.FirstChanceException += (s, e) =>
        {
            // PHASE16 probe: full stack on first-chance exceptions to locate the throwing call
            Console.WriteLine($"[fce] {e.Exception.GetType().Name}: {e.Exception.Message}\n{e.Exception}");
        };

        // JIT safety (S3a): compile the teardown path (Shutdown) while no detour exists so no
        // post-Init teardown JIT can run on the hooked stack.
        WarmupTeardownPaths();

        // Data source: 容器激活时 Z: 路径直接由容器服务 (TryMap 返回 Z: 伪路径);
        // 否则回退 exe 旁磁盘别名 (仅无容器调试: <exe>\jdk\ 与 <exe>\Minecraft\)。
        string zJava = @"Z:\bin\java.dll";
        string realJava = FakeFileSystem.ToRealPath(zJava)
            ?? throw new InvalidOperationException("cannot resolve real path for Z:\\bin\\java.dll");
        string zJvm = @"Z:\bin\server\jvm.dll";
        string realJvm = FakeFileSystem.ToRealPath(zJvm)
            ?? throw new InvalidOperationException("cannot resolve real path for Z:\\bin\\server\\jvm.dll");

        // JIT safety: compile the whole launch pipeline (incl. the hook-side File/PE/native-read
        // paths and the MC launch chain) BEFORE the first detour exists, then install the hooks.
        PreJitWarmup(realJava, realJvm);
        FakeFileSystem.Init();

        // ---- JNI: JVM over VFS (spike-jvm core) ----
        // jvm.dll 引导加载 (计划 §17 既定设计): 优先真实磁盘 JDK (S2b 假 SEC_IMAGE 的
        // 运行期验证链已取消, jvm.dll 从系统/缓存 JDK 真实加载是已证方案); 磁盘缺失时才
        // 回退 Z: 路径 (经假 SEC_IMAGE 从容器加载, 此时需要显式 -Djava.home)。
        // 容器负责 Minecraft 数据树全量 (Z: 类路径 jar / 版本 json / natives / assets 走 mmap zip)。
        Console.WriteLine("---- JVM over VFS: JNI_CreateJavaVM with virtual Z: classpath ----");

        string jvmLoadPath = realJvm;
        if (Container.Active)
        {
            string? diskJvm = FakeFileSystem.ToRealDiskPath(zJvm);
            if (diskJvm is not null)
            {
                jvmLoadPath = diskJvm;
                JvmFromContainer = false;
                Console.WriteLine($"[jni] container active; jvm.dll from disk JDK: {diskJvm}");
            }
            else
            {
                JvmFromContainer = true;
                Console.WriteLine($"[jni] container active, no disk JDK -> jvm.dll from container via fake SEC_IMAGE: {realJvm}");
            }
        }

        IntPtr hJvm = JniPlumbing.LoadLibraryExW(jvmLoadPath, IntPtr.Zero, JniPlumbing.LOAD_WITH_ALTERED_SEARCH_PATH);
        if (hJvm == IntPtr.Zero)
        {
            Console.WriteLine($"[jni] LoadLibraryExW({jvmLoadPath}) FAILED win32={Marshal.GetLastWin32Error()}");
            // 回退链: 磁盘失败 -> 容器 Z: (假 SEC_IMAGE); 容器失败 -> 磁盘; 全失败 -> 退出
            if (Container.Active && !JvmFromContainer)
            {
                Console.WriteLine($"[jni] disk load failed -> try container Z: path: {realJvm}");
                hJvm = JniPlumbing.LoadLibraryExW(realJvm, IntPtr.Zero, JniPlumbing.LOAD_WITH_ALTERED_SEARCH_PATH);
                if (hJvm != IntPtr.Zero) { JvmFromContainer = true; }
            }
            else if (Container.Active && JvmFromContainer)
            {
                string? diskJvm = FakeFileSystem.ToRealDiskPath(zJvm);
                Console.WriteLine($"[jni] container load failed -> fallback disk JDK: {diskJvm ?? "(none)"}");
                if (diskJvm is not null)
                {
                    hJvm = JniPlumbing.LoadLibraryExW(diskJvm, IntPtr.Zero, JniPlumbing.LOAD_WITH_ALTERED_SEARCH_PATH);
                    if (hJvm != IntPtr.Zero) { JvmFromContainer = false; }
                }
            }
            if (hJvm == IntPtr.Zero)
            {
                Console.WriteLine($"[jni] LoadLibraryExW(jvm.dll) FAILED win32={Marshal.GetLastWin32Error()}");
                FakeFileSystem.Shutdown(); // restore ntdll stubs before exit
                FakeFileSystem.CleanupCache(); // PHASE15: 物化缓存已写入, 失败退出也清理
                TerminateProcess(GetCurrentProcess(), 1);
                return 1; // unreachable
            }
        }
        Console.WriteLine($"[jni] jvm.dll loaded @0x{hJvm.ToInt64():X}");

        // Minecraft launch chain (stage D): version json -> classpath/args -> natives -> gameDir ->
        // Client.main(String[]) with the watchdog. Returns the evidence exit code.
        int mcCode = McLaunch.Run(hJvm);
        Console.WriteLine($"[mc] Run -> code {mcCode}");

        // The game is running or just exited: undoing hooks under a live game (or DestroyJavaVM
        // which blocks on live threads) would be risky -- TerminateProcess straight to the
        // evidence code (0 window / 3 game-exited / 42 timeout). TerminateProcess also skips the
        // CLR graceful teardown (finalizer/teardown GCs + nondeterministic JITs on a hooked stack).
        // PHASE15: 兜底清理 (watchdog 成功/超时路径已在 WatchdogLoop 清理; 此处覆盖
        // FindClass 失败等提前返回路径 —— 幂等)。
        FakeFileSystem.CleanupCache();
        Console.WriteLine($"[exit] TerminateProcess({mcCode}) without hook teardown");
        TerminateProcess(GetCurrentProcess(), (uint)mcCode);
        return mcCode; // unreachable
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern void TerminateProcess(IntPtr hProcess, uint uExitCode);

    /// <summary>
    /// JIT-safety warmup: JIT the teardown methods before Init so the process exit path compiles
    /// nothing new (kept from the MonoMod era; harmless belt-and-braces with MinHook.NET). The
    /// throwaway-hook + Shutdown() calls inside FakeFileSystem.WarmupTeardown warm the MinHook
    /// enable/disable machinery. Called at the very top of Main, before PreJitWarmup.
    /// </summary>
    private static void WarmupTeardownPaths()
    {
        FakeFileSystem.WarmupTeardown();
        Console.WriteLine("[prejit] warmed teardown paths (Shutdown / Undo)");
    }

    /// <summary>
    /// JIT-safety warmup: compile the launch pipeline against REAL paths BEFORE the ntdll detours
    /// exist, so no managed method (including .NET internals the hooks touch) is JIT-compiled
    /// after Init. See FakeFileSystem.WarmupLogPatterns for the hook-side half; this also warms
    /// the interpolation shapes used by the JNI logs and pre-compiles the JNI delegate stubs.
    /// </summary>
    private static void PreJitWarmup(string realJava, string realJvm)
    {
        Console.WriteLine("[prejit] warming pipeline against real paths (no detours installed yet) ...");
        // PHASE15: 清上次运行残留的 <gameDir>\cache (物化 modules + natives) —— pre-detour 执行,
        // 无 hook 干扰; 同时保证本次物化不落入陈旧目录。
        FakeFileSystem.CleanupCache();
        // PHASE16 (G1 去物化): lib\modules 不再物化。jimage 链实测可 hook 拦截 ——
        // osSupport_windows.cpp map_memory = CreateFileA->CreateFileMappingA->MapViewOfFileEx
        // (jdk-25+25 源码 + 本地 jimage.dll 反汇编 _imp_ 三重确认), kernelbase 全链经 IAT 调
        // ntdll 导出 (PHASE12 cdb 反汇编, 零 direct syscall), run12 日志实测 CreateFileW /
        // NtCreateFile hook 均命中 lib\modules。假句柄 + 假 section 服务 (与 jars 同机制),
        // ModulesRealPath 恒为 null, 相关特判自然失效。
        // PHASE16 (G1 续): JDK conf 树同样去物化 —— run12 物化理由是 "kernelbase CreateFileW
        // direct-syscall 绕过 ntdll", 与 PHASE12 反汇编矛盾 (CreateFileW 经 IAT 调 NtCreateFile,
        // 且我们已托管 detour kernelbase!CreateFileW, 在 kernelbase 层即可拦截); conf 走
        // 与 jars 相同的假句柄路径 (CreateFileW 放行 -> 内层 NtCreateFile 假句柄 -> NtReadFile)。
        // MaterializeConfTree 保留为历史工具, 不再被调用。
        // File.Exists / FileInfo.Length internals: called by the hooks' TryMap / attribute paths
        // (Hook_NtQueryFullAttributesFile reads FileInfo.Length; every Z: stat goes through
        // File.Exists/Directory.Exists) -- compile them before the first detour.
        _ = File.Exists(realJava);
        if (!Container.Active)
        {
            _ = new FileInfo(realJava).Length;
        }
        else
        {
            // 容器模式: realJava/realJvm 是 Z: 伪路径, 磁盘 FileInfo.Length 会抛 —— 改走容器
            // 读取路径预热 (键推导 + 全量读 + 目录枚举 + PE 解析)。
            Container.Warmup(@"bin\java.dll", Container.JdkPrefix + "/bin/server/jvm.dll");
        }
        // JIT safety (Phase 2/MinHook gap, observed in runAOT-2): the FIRST exception-message
        // lookup compiles System.SR -> ResourceManager -> RuntimeResourceSet ->
        // Dictionary<__Canon,ResourceLocator> + the IEqualityComparer<__Canon> interface-dispatch
        // stub. If that first lookup happens AFTER the detours exist, the JIT's own ntdll calls
        // (NtMapViewOfSection for executable memory, NtCreateSection, ...) re-enter our hooks from
        // COOP mode -> coreclr ReversePInvokeBadTransition fail-fast (0x80131506, verified via
        // crash dump: StubDispatchFrame on IEqualityComparer<__Canon>.GetHashCode inside
        // Win32Marshal.GetExceptionForWin32Error). Warm the whole path now with a real
        // missing-file probe (parent dir exists -> guaranteed FileNotFoundException).
        try
        {
            using var _ = File.OpenHandle(@"C:\Windows\__sfmc_warm_missing_0x1234__.dll", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Console.WriteLine("[prejit] WARNING: missing-file probe unexpectedly succeeded");
        }
        catch (FileNotFoundException) { }
        catch (Exception ex) { Console.WriteLine($"[prejit] missing-file probe threw (unexpected type): {ex}"); }
        // Z:-path mapping warmups (runAOT-3 gap): TryMap branches that only post-Init Z: traffic
        // reaches must be compiled BEFORE the detours exist — a first-time JIT after Init that
        // allocates executable memory via the hooked NtMapViewOfSection fail-fasts (COOP-mode
        // reverse P/Invoke, see above). Warm the minecraft/jdk-prefix branches that the JVM's
        // Z:\minecraft\... opens will hit in the launch chain (PHASE13 换层: 新 Z: 路径)。
        _ = FakeFileSystem.ToRealPath(@"Z:\minecraft\assets\indexes\32.json"); // minecraft tree branch
        _ = FakeFileSystem.ToRealPath(@"Z:\openjdk\bin\java.dll");             // jdk-prefix branch
        Console.WriteLine("[prejit] warmed Z: TryMap branches (minecraft / jdk-prefix)");
        // settle LOH/finalizer activity pre-init: no GC (or SafeHandle finalization -> NtClose
        // hook entry) may run on the hooked stack later for these sizes.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        // interpolation shapes used by the JNI logs (bool/int/long/uint/IntPtr/string + hex)
        bool wb = true; int wi = 0; long wl = 0; uint wu = 4096;
        IntPtr wp = IntPtr.Zero; string ws = realJava;
        Console.WriteLine($"[prejit] shapes (ret={wb} {wi} {wl} {wu} 0x{wp:X} {ws})");
        FakeFileSystem.WarmupLogPatterns();   // hook Log interpolation overloads
        FakeFileSystem.WarmupNativeRead(realJvm); // native read + Span copy path used by the hooks
        FakeFileSystem.WarmupImagePipeline(realJava); // PE parse + image layout path (fake SEC_IMAGE)
        FakeFileSystem.WarmupImagePipeline(realJvm);
        JniPlumbing.Warmup();          // JNI delegate Invoke stubs
        McLaunch.Warmup();             // version json -> classpath/args -> natives -> gameDir
        Console.WriteLine("[prejit] done");
    }
}

// ---- JNI plumbing (env usage per spike-coexist SPIKECO_FIND=fixed): ----
// JNIEnv* = penv itself (&_jni_environment); the function table (*penv) is ONLY read to fetch
// function addresses. JavaVMInitArgs = 24 B (int version + int nOptions + IntPtr options +
// byte ignoreUnrecognized), JavaVMOption = 16 B (IntPtr optionString + IntPtr extraInfo).
internal static class JniPlumbing
{
    public const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;
    private const int JNI_VERSION_1_8 = 0x00010008;
    private const int JNI_OK = 0;

    /// <summary>JavaVM* from JNI_CreateJavaVM; destroyed by <see cref="DestroyVm"/> (called by Main
    /// AFTER FakeFileSystem.Shutdown, so JVM teardown runs on real ntdll and cannot fail-fast in a hook).</summary>
    public static IntPtr CreatedVm;

    /// <summary>JNIEnv* from the last successful JNI_CreateJavaVM (used by McLaunch stage D).</summary>
    public static IntPtr CreatedEnv;

    /// <summary>jclass of the last TARGET FindClass in the shared core (used by McLaunch stage D).</summary>
    public static IntPtr CreatedTargetClass;

    [StructLayout(LayoutKind.Sequential)]
    private struct JavaVMOption
    {
        public IntPtr optionString;   // 0x00
        public IntPtr extraInfo;      // 0x08  (total 16)
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JavaVMInitArgs
    {
        public int version;                 // 0x00
        public int nOptions;                // 0x04
        public IntPtr options;              // 0x08
        public byte ignoreUnrecognized;     // 0x10  jboolean must be byte (total 24 with pad)
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int JNI_CreateJavaVM_t(out IntPtr pvm, out IntPtr penv, IntPtr args);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int DestroyJavaVM_t(IntPtr vm);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr FindClass_t(IntPtr env, [MarshalAs(UnmanagedType.LPStr)] string name);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int GetVersion_t(IntPtr env);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr ExceptionOccurred_t(IntPtr env);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ExceptionDescribe_t(IntPtr env);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ExceptionClear_t(IntPtr env);

    // ---- Phase 2 (MC launch): JNIEnv function-table slots (jni.h JNINativeInterface_ indices).
    // VERIFIED against the RUNTIME function table of the installed MS JDK 25 jvm.dll (crash-dump
    // dump of the live table, runMH-6): JDK25's jni.h inserted GetStringUTFLength + GetArrayLength
    // and moved GetStringArrayRegion/GetStringUTFRegion, so NewStringUTF=167 (not 164),
    // NewObjectArray=172 (not 184), SetObjectArrayElement=174 (not 186). The pre-JDK25 indices
    // hit GetStringLength / GetByteArrayElements / GetShortArrayElements -> JNIHandles::resolve
    // on a garbage jarray -> AV 0xC0000005 (fault=0x18, rbp=0x1A=len) at Client.main arg build.
    // Correct & verified: GetStaticMethodID=113, CallStaticVoidMethodA=143, FindClass=6,
    // ExceptionOccurred=15/Describe=16/Clear=17; JavaVM table: AttachCurrentThread=2. ----
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr GetStaticMethodID_t(IntPtr env, IntPtr clazz, string name, string sig);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr NewStringUTF_t(IntPtr env, string utf);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr NewObjectArray_t(IntPtr env, int len, IntPtr clazz, IntPtr init);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void SetObjectArrayElement_t(IntPtr env, IntPtr array, int index, IntPtr value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void CallStaticVoidMethodA_t(IntPtr env, IntPtr clazz, IntPtr methodID, IntPtr args);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int AttachCurrentThread_t(IntPtr vm, out IntPtr penv, IntPtr args);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryExW(string fileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr GetModuleHandleW(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hLibModule);

    private static T Get<T>(IntPtr hModule, string name) where T : Delegate
    {
        IntPtr p = GetProcAddress(hModule, name);
        if (p == IntPtr.Zero)
        {
            throw new EntryPointNotFoundException($"{name} (win32={Marshal.GetLastWin32Error()})");
        }
        return Marshal.GetDelegateForFunctionPointer<T>(p);
    }

    /// <summary>
    /// S3b: pre-compile the JNI delegate Invoke stubs (and the marshal stubs the delegates use)
    /// while no ntdll detour exists, so the JNI calls do not JIT on the hooked stack.
    /// PHASE11-AOT: 无 JIT, 委托 Invoke 已编译 —— 反射预热直接跳过。
    /// </summary>
    public static void Warmup()
    {
        if (Program.IsAot) { return; }
        RuntimeHelpers.PrepareMethod(typeof(JNI_CreateJavaVM_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(FindClass_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(GetVersion_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(ExceptionOccurred_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(ExceptionDescribe_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(ExceptionClear_t).GetMethod("Invoke")!.MethodHandle);
        // Phase 2: main-call plumbing (GetStaticMethodID / NewStringUTF / NewObjectArray /
        // SetObjectArrayElement / CallStaticVoidMethodA / AttachCurrentThread) + the helper
        // methods that run post-Init (JIT safety: nothing new may compile after the detours exist).
        RuntimeHelpers.PrepareMethod(typeof(GetStaticMethodID_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(NewStringUTF_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(NewObjectArray_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(SetObjectArrayElement_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(CallStaticVoidMethodA_t).GetMethod("Invoke")!.MethodHandle);
        RuntimeHelpers.PrepareMethod(typeof(AttachCurrentThread_t).GetMethod("Invoke")!.MethodHandle);
    }

    /// <summary>
    /// Stop the JVM. MUST be called AFTER FakeFileSystem.Shutdown: JVM teardown threads (G1
    /// concurrent, VM thread, ...) call ntdll (NtClose/NtUnmapViewOfSection/...) while they are
    /// dying, and a dying thread entering one of our managed hooks through the reverse-P/Invoke
    /// thunk occasionally hits ReversePInvokeBadTransition -> 0x80131506 fail-fast (racy, observed
    /// right after FindClass). With the detours undone, teardown runs on the real ntdll.
    /// </summary>
    public static void DestroyVm()
    {
        if (CreatedVm == IntPtr.Zero) { return; }
        try
        {
            // JNIInvokeInterface: reserved0/1/2 at slots 0-2, DestroyJavaVM at slot 3
            IntPtr vmTable = Marshal.ReadIntPtr(CreatedVm);
            var dvm = Marshal.GetDelegateForFunctionPointer<DestroyJavaVM_t>(Marshal.ReadIntPtr(vmTable, 3 * IntPtr.Size));
            int dret = dvm(CreatedVm);
            Console.WriteLine($"[jni] DestroyJavaVM -> {dret}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[jni] DestroyJavaVM threw {ex}");
        }
    }

    /// <summary>
    /// Create the JVM with an arbitrary option list and load the launch target class (the
    /// Minecraft main class). Returns 0 = VM created + target class loaded; 1 = JNI_CreateJavaVM
    /// failed; 2 = VM created but FindClass returned NULL (exception detail printed).
    ///
    /// runAOT-3 evidence: with MinHook + the 115-jar virtual classpath, the FIRST app-classpath
    /// FindClass performed through a fresh GetDelegateForFunctionPointer stub deterministically
    /// fails with a stack-less NoClassDefFoundError from systemDictionary.cpp:326, while this
    /// exact sequence (GetVersion, control FindClass(java/lang/String), then a warmup FindClass
    /// through the SAME delegate, then the target) always succeeds. All MC-launch class lookups
    /// therefore go through here.
    /// </summary>
    public static int CreateJvmAndFindClass(IntPtr hJvm, string classpath, string targetClass, string[] extraOpts)
    {
        if (Marshal.SizeOf<JavaVMOption>() != 16) { throw new InvalidOperationException("JavaVMOption layout != 16"); }
        if (Marshal.SizeOf<JavaVMInitArgs>() != 24) { throw new InvalidOperationException("JavaVMInitArgs layout != 24"); }

        var createVm = Get<JNI_CreateJavaVM_t>(hJvm, "JNI_CreateJavaVM");

        // no -Djava.home: the real jvm.dll derives its home from its own location, so all
        // JVM-internal loads (bin\java.dll, lib\modules, ...) stay on real paths; only the
        // classpath jars are virtual. -Xshare:off keeps CDS out of the picture.
        string[] baseOpts = { "-Djava.class.path=" + classpath, "-Xshare:off" };
        // extraOpts (MC launch: CreateStageOpts result = version-json jvm args + natives props)
        // merge AFTER the base opts; duplicate -Djava.class.path= / -Xshare:off from the stage
        // opts are dropped (baseOpts is authoritative -- runNOGC-2 fix).
        string[] opts = [.. baseOpts,
            .. extraOpts.Where(o => !o.StartsWith("-Djava.class.path=", StringComparison.Ordinal)
                && !o.StartsWith("-Xshare", StringComparison.Ordinal))];
        int n = opts.Length;
        IntPtr optMem = Marshal.AllocHGlobal(n * Marshal.SizeOf<JavaVMOption>());
        IntPtr[] optStrings = new IntPtr[n];
        try
        {
            for (int i = 0; i < n; i++)
            {
                optStrings[i] = Marshal.StringToHGlobalAnsi(opts[i]);
                IntPtr slot = IntPtr.Add(optMem, i * Marshal.SizeOf<JavaVMOption>());
                Marshal.WriteIntPtr(slot, 0, optStrings[i]);
                Marshal.WriteIntPtr(slot, IntPtr.Size, IntPtr.Zero); // extraInfo
            }
            Console.WriteLine($"[jni] options: [{string.Join(" | ", opts)}]");

            IntPtr args = Marshal.AllocHGlobal(Marshal.SizeOf<JavaVMInitArgs>());
            try
            {
                Marshal.WriteInt32(args, 0, JNI_VERSION_1_8); // version
                Marshal.WriteInt32(args, 4, n);              // nOptions
                Marshal.WriteIntPtr(args, 8, optMem);        // options
                Marshal.WriteByte(args, 16, 0);              // ignoreUnrecognized = JNI_FALSE
                // 17..23 zeroed by AllocHGlobal

                IntPtr pvm = IntPtr.Zero, penv = IntPtr.Zero;
                Console.WriteLine("[jni] calling JNI_CreateJavaVM ...");
                int ret = createVm(out pvm, out penv, args);
                Console.WriteLine($"[jni] JNI_CreateJavaVM ret={ret} pvm=0x{pvm.ToInt64():X} penv=0x{penv.ToInt64():X}");
                CreatedVm = pvm;
                CreatedEnv = penv;
                if (ret != JNI_OK)
                {
                    return 1;
                }

                // fixed env usage: env argument = penv itself (&_jni_environment); the function
                // table (ReadIntPtr(penv)) is ONLY used to fetch function addresses.
                IntPtr table = Marshal.ReadIntPtr(penv);
                Console.WriteLine($"[jni] penv=0x{penv.ToInt64():X} (=&_jni_environment) table=0x{table.ToInt64():X}");

                var fgv = Marshal.GetDelegateForFunctionPointer<GetVersion_t>(Marshal.ReadIntPtr(table, 4 * IntPtr.Size));
                Console.WriteLine($"[jni] GetVersion(penv) -> 0x{fgv(penv):X8}");

                var ffc = Marshal.GetDelegateForFunctionPointer<FindClass_t>(Marshal.ReadIntPtr(table, 6 * IntPtr.Size));
                IntPtr ctl = ffc(penv, "java/lang/String");
                Console.WriteLine($"[jni] control FindClass(penv, \"java/lang/String\") -> 0x{ctl.ToInt64():X}");

                // warmup + target through the SAME delegate (runAOT-3): the first app-classpath
                // FindClass on a fresh delegate deterministically fails, so the target class is
                // loaded once to warm the delegate, then looked up again for the real jclass.
                IntPtr warm = ffc(penv, targetClass);
                Console.WriteLine($"[jni] warmup FindClass(\"{targetClass}\") -> 0x{warm.ToInt64():X}");
                IntPtr tgt = ffc(penv, targetClass);
                Console.WriteLine($"[jni] TARGET FindClass(\"{targetClass}\") -> 0x{tgt.ToInt64():X} "
                    + (tgt == IntPtr.Zero ? "(NULL)" : "(loaded)"));
                CreatedTargetClass = tgt;
                if (tgt == IntPtr.Zero)
                {
                    DiagnosePending(penv);
                    return 2;
                }
                return 0;
            }
            finally
            {
                Marshal.FreeHGlobal(args);
            }
        }
        finally
        {
            for (int i = 0; i < n; i++) { Marshal.FreeHGlobal(optStrings[i]); }
            Marshal.FreeHGlobal(optMem);
        }
    }

    // ------------------------------------------------------------------ Phase 2 (MC launch) JNI APIs
    // CreateJvmAndFindClass above stays untouched (regression baseline); the MC launch path uses
    // these: arbitrary VM option lists + FindClass(Client) + Client.main(String[]) invocation.

    /// <summary>
    /// JNI_CreateJavaVM with an arbitrary option list. Returns (ret, pvm, penv); CreatedVm is set
    /// on success. Ret 0 = OK, 1 = create failed (log printed).
    /// </summary>
    public static (int ret, IntPtr pvm, IntPtr penv) CreateVmWithOptions(IntPtr hJvm, string[] opts)
    {
        if (Marshal.SizeOf<JavaVMOption>() != 16) { throw new InvalidOperationException("JavaVMOption layout != 16"); }
        if (Marshal.SizeOf<JavaVMInitArgs>() != 24) { throw new InvalidOperationException("JavaVMInitArgs layout != 24"); }
        var createVm = Get<JNI_CreateJavaVM_t>(hJvm, "JNI_CreateJavaVM");
        int n = opts.Length;
        IntPtr optMem = Marshal.AllocHGlobal(n * Marshal.SizeOf<JavaVMOption>());
        IntPtr[] optStrings = new IntPtr[n];
        try
        {
            for (int i = 0; i < n; i++)
            {
                optStrings[i] = Marshal.StringToHGlobalAnsi(opts[i]);
                IntPtr slot = IntPtr.Add(optMem, i * Marshal.SizeOf<JavaVMOption>());
                Marshal.WriteIntPtr(slot, 0, optStrings[i]);
                Marshal.WriteIntPtr(slot, IntPtr.Size, IntPtr.Zero); // extraInfo
            }
            Console.WriteLine($"[jni] options ({n}):");
            foreach (string o in opts) { Console.WriteLine($"  {o}"); }

            IntPtr args = Marshal.AllocHGlobal(Marshal.SizeOf<JavaVMInitArgs>());
            try
            {
                Marshal.WriteInt32(args, 0, JNI_VERSION_1_8);
                Marshal.WriteInt32(args, 4, n);
                Marshal.WriteIntPtr(args, 8, optMem);
                Marshal.WriteByte(args, 16, 0); // ignoreUnrecognized = JNI_FALSE
                IntPtr pvm = IntPtr.Zero, penv = IntPtr.Zero;
                Console.WriteLine("[jni] calling JNI_CreateJavaVM ...");
                int ret = createVm(out pvm, out penv, args);
                Console.WriteLine($"[jni] JNI_CreateJavaVM ret={ret} pvm=0x{pvm.ToInt64():X} penv=0x{penv.ToInt64():X}");
                if (ret == JNI_OK) { CreatedVm = pvm; }
                return (ret, pvm, penv);
            }
            finally { Marshal.FreeHGlobal(args); }
        }
        finally
        {
            for (int i = 0; i < n; i++) { Marshal.FreeHGlobal(optStrings[i]); }
            Marshal.FreeHGlobal(optMem);
        }
    }

    /// <summary>FindClass with the standard pending-exception diagnosis (ExceptionDescribe) on NULL.</summary>
    public static IntPtr FindClassChecked(IntPtr penv, string name)
    {
        IntPtr table = Marshal.ReadIntPtr(penv);
        var ffc = Marshal.GetDelegateForFunctionPointer<FindClass_t>(Marshal.ReadIntPtr(table, 6 * IntPtr.Size));
        IntPtr cls = ffc(penv, name);
        Console.WriteLine($"[jni] FindClass(\"{name}\") -> 0x{cls.ToInt64():X} ({(cls == IntPtr.Zero ? "NULL" : "loaded")})");
        if (cls == IntPtr.Zero)
        {
            DiagnosePending(penv);
        }
        return cls;
    }

    /// <summary>AttachCurrentThread(vm) -> JNIEnv* for a non-creator managed thread (JNI requires
    /// explicit attach before any JNIEnv call from a thread that did not create the VM). JavaVM
    /// table slot 2 = AttachCurrentThread (5 = AttachCurrentThreadAsDaemon, fixed in runMH-4).</summary>
    public static IntPtr AttachCurrentThread(IntPtr vm)
    {
        IntPtr vmTable = Marshal.ReadIntPtr(vm);
        var attach = Marshal.GetDelegateForFunctionPointer<AttachCurrentThread_t>(Marshal.ReadIntPtr(vmTable, 2 * IntPtr.Size));
        IntPtr penv;
        int ret = attach(vm, out penv, IntPtr.Zero);
        Console.WriteLine($"[jni] AttachCurrentThread -> ret={ret} penv=0x{penv.ToInt64():X}");
        if (ret != 0) { throw new InvalidOperationException($"AttachCurrentThread failed ret={ret}"); }
        return penv;
    }

    /// <summary>
    /// Invoke Client.main(String[]) via JNI: GetStaticMethodID -> NewObjectArray/String[]
    /// (NewStringUTF + SetObjectArrayElement) -> CallStaticVoidMethodA with a jvalue array of one
    /// object slot. Pending exception after the call is diagnosed (the JVM main() normally exits
    /// via System.exit, so returning usually means shutdown).
    /// </summary>
    public static int CallStaticVoidMain(IntPtr penv, IntPtr cls, string[] args)
    {
        IntPtr table = Marshal.ReadIntPtr(penv);

        var fgsm = Marshal.GetDelegateForFunctionPointer<GetStaticMethodID_t>(Marshal.ReadIntPtr(table, 113 * IntPtr.Size));
        IntPtr mid = fgsm(penv, cls, "main", "([Ljava/lang/String;)V");
        Console.WriteLine($"[jni] GetStaticMethodID(Client, \"main\", \"([Ljava/lang/String;)V\") -> 0x{mid.ToInt64():X}");
        if (mid == IntPtr.Zero)
        {
            Console.WriteLine("[jni] GetStaticMethodID returned NULL -> diagnose pending exception");
            DiagnosePending(penv);
            return 1;
        }

        var fnsu = Marshal.GetDelegateForFunctionPointer<NewStringUTF_t>(Marshal.ReadIntPtr(table, 167 * IntPtr.Size)); // NewStringUTF (JDK25 jni.h: 167, was 164 pre-JDK25)
        var fnoa = Marshal.GetDelegateForFunctionPointer<NewObjectArray_t>(Marshal.ReadIntPtr(table, 172 * IntPtr.Size)); // NewObjectArray (JDK25: 172, was 184 pre-JDK25)
        var fsae = Marshal.GetDelegateForFunctionPointer<SetObjectArrayElement_t>(Marshal.ReadIntPtr(table, 174 * IntPtr.Size)); // SetObjectArrayElement (JDK25: 174, was 186 pre-JDK25)

        // java/lang/String class (control FindClass in the same env)
        var ffc = Marshal.GetDelegateForFunctionPointer<FindClass_t>(Marshal.ReadIntPtr(table, 6 * IntPtr.Size));
        IntPtr strCls = ffc(penv, "java/lang/String");
        if (strCls == IntPtr.Zero)
        {
            Console.WriteLine("[jni] FindClass(java/lang/String) returned NULL");
            DiagnosePending(penv);
            return 2;
        }

        IntPtr array = fnoa(penv, args.Length, strCls, IntPtr.Zero);
        Console.WriteLine($"[jni] NewObjectArray({args.Length}, String) -> 0x{array.ToInt64():X}");
        if (array == IntPtr.Zero)
        {
            Console.WriteLine("[jni] NewObjectArray returned NULL -> diagnose pending exception");
            DiagnosePending(penv);
            return 3;
        }
        for (int i = 0; i < args.Length; i++)
        {
            IntPtr js = fnsu(penv, args[i]);
            if (js == IntPtr.Zero)
            {
                Console.WriteLine($"[jni] NewStringUTF(arg[{i}]=\"{args[i]}\") returned NULL -> diagnose");
                DiagnosePending(penv);
                return 4;
            }
            fsae(penv, array, i, js);
        }
        Console.WriteLine($"[jni] String[] built ({args.Length} args)");
        Console.WriteLine($"[jni] game args: [{string.Join(" | ", args)}]");

        // jvalue array (x64: 8 B per slot; one object slot holding the String[] jobject)
        IntPtr jvalues = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            Marshal.WriteIntPtr(jvalues, 0, array);
            var fcsvm = Marshal.GetDelegateForFunctionPointer<CallStaticVoidMethodA_t>(Marshal.ReadIntPtr(table, 143 * IntPtr.Size));
            Console.WriteLine("[jni] calling Client.main(String[]) via CallStaticVoidMethodA ...");
            fcsvm(penv, cls, mid, jvalues);
            Console.WriteLine("[jni] CallStaticVoidMethodA returned");
            DiagnosePending(penv);
            return 0;
        }
        finally { Marshal.FreeHGlobal(jvalues); }
    }

    private static void DiagnosePending(IntPtr penv)
    {
        IntPtr table = Marshal.ReadIntPtr(penv);
        var exOcc = Marshal.GetDelegateForFunctionPointer<ExceptionOccurred_t>(Marshal.ReadIntPtr(table, 15 * IntPtr.Size));
        var exDesc = Marshal.GetDelegateForFunctionPointer<ExceptionDescribe_t>(Marshal.ReadIntPtr(table, 16 * IntPtr.Size));
        var exClear = Marshal.GetDelegateForFunctionPointer<ExceptionClear_t>(Marshal.ReadIntPtr(table, 17 * IntPtr.Size));
        if (exOcc(penv) != IntPtr.Zero)
        {
            Console.WriteLine("[jni] pending exception (ExceptionDescribe):");
            exDesc(penv);
            exClear(penv);
            Console.WriteLine("[jni] (cleared)");
        }
        else
        {
            Console.WriteLine("[jni] no pending exception");
        }
    }
}
