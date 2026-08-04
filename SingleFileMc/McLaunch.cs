using System.IO.Compression;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace SingleFileMc;

/// <summary>
/// Phase 2 (MC launch): start Minecraft 26.2-NeoForge from the JVM-over-VFS host.
///
/// Launch chain (S3b-proven simplification): the JVM's -Djava.class.path may hold the Z:\ virtual
/// jar list -- the system class loader reads it through the fake file hooks, no custom ClassLoader
/// needed. So: build classpath + JNI_CreateJavaVM + FindClass(mainClass) + CallStaticVoidMethod.
///
/// Production flow (single stage, the former stage D):
///   parse version json -> windows-filtered library classpath (Z:\... jar list) + version jar ->
///   build game/jvm args (template substitution) -> natives: temporary extraction to
///   <gameDir>\cache\natives\{java,jna,lwjgl,netty} (PHASE15: gameDir 内统一缓存, 退出清理,
///   %TEMP% 零残留; full memory layout arrives with the natives-virtualization task) -> gameDir
///   creation -> Client.main(String[]) via JNI (NewObjectArray +
///   NewStringUTF + GetStaticMethodID + CallStaticVoidMethodA), watchdog 180 s, window/log evidence.
///
/// JIT safety: everything runs through Warmup() BEFORE any ntdll detour exists (Program's
/// PreJitWarmup) -- json parse, classpath/args build, natives extraction, gameDir creation, and
/// PrepareMethod for every post-Init entry point -- so nothing new compiles on the hooked stack.
/// </summary>
internal static class McLaunch
{
    // ---- task constants ----
    private const string VersionId = "26.2-NeoForge_26.2.0.45-beta";
    // JNI native format ('/' separators, per JNI spec): runAOT-3 evidence -- FindClass with the
    // dotted form deterministically returns NULL with a stack-less NoClassDefFoundError
    // (systemDictionary.cpp:326) on this JVM, while the slashed form always loads.
    private const string MainClass = "net/neoforged/fml/startup/Client";
    private const string AssetIndex = "32";
    // PHASE13 (VFS 换层): Z: 虚拟路径 = zip 顶层 minecraft/ 一一对应, 不再有 .minecraft 段。
    private const string AssetsDir = @"Z:\minecraft\assets";
    private const string LibrariesDir = @"Z:\minecraft\libraries";
    private const string VersionJarZ = @"Z:\minecraft\versions\" + VersionId + @"\" + VersionId + ".jar";
    // 数据源键: 相对容器根的正斜杠路径, 与 zip 条目一致 (容器激活时唯一数据源)。
    private const string RelContainerRoot = "minecraft/";   // zip 顶层 (新分层)
    private const string RelVersionJson = "minecraft/versions/" + VersionId + "/" + VersionId + ".json";
    private const string RelVersionJar = "minecraft/versions/" + VersionId + "/" + VersionId + ".jar";
    private const string RelLibrariesKey = "minecraft/libraries";
    // 磁盘回退根 (仅无容器调试): <exe>\Minecraft (AppContext.BaseDirectory 运行时动态, 无硬编码绝对路径)。
    private static readonly string DiskMcRoot = Path.Combine(AppContext.BaseDirectory, "Minecraft");
    // 容器键 -> 磁盘路径: 剥 "minecraft/" 顶层段 (磁盘树 <exe>\Minecraft 即 .minecraft 内容)。
    private static string DiskPath(string containerKey) => Path.Combine(DiskMcRoot, containerKey[RelContainerRoot.Length..]);
    private const long WatchdogMs = 180_000;

    // ---- phase state (built in Warmup pre-detour; consumed post-Init) ----
    public static string[] Classpath = [];   // Z:\ jar paths in classpath order
    public static string[] JvmArgs = [];     // substituted version-json jvm args (-cp pair removed)
    public static string[] GameArgs = [];    // substituted game args
    public static string[] MissingJars = []; // windows-allowed artifacts absent from disk
    public static string[] NativesSources = [];
    public static string GameDir = "";       // <exe>\game (real, writable)
    public static string NativesDir = "";    // <gameDir>\cache\natives (PHASE15: 退出时清理, %TEMP% 零残留)
    public static int AllowedLibraries;      // windows-filtered library count (classpath excludes the version jar)
    public static int TotalLibraries;
    public static int NativesExtracted;

    private static readonly Dictionary<string, string> Vars = new(StringComparer.Ordinal);

    // ---- stage D: main() invocation state (explicit method + static fields: no lambda/JIT risk) ----
    private static IntPtr _vmForMain;
    private static IntPtr _clsForMain;

    // ---- window detection (user32) ----
    private delegate bool EnumProc(IntPtr hwnd, IntPtr lParam);
    private static readonly EnumProc EnumProcImpl = EnumWindowsProc;
    private static readonly List<(IntPtr Hwnd, string Title)> _mcWindows = [];

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumProc cb, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    private static bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam)
    {
        if (!IsWindowVisible(hwnd)) { return true; }
        var sb = new StringBuilder(256);
        GetWindowTextW(hwnd, sb, sb.Capacity);
        string t = sb.ToString();
        if (t.Contains("Minecraft", StringComparison.OrdinalIgnoreCase))
        {
            _mcWindows.Add((hwnd, t));
        }
        return true;
    }

    /// <summary>所有标题含 "Minecraft" 的可见窗口(不只第一个:加载窗口 "Minecraft: NeoForge
    /// Loading..." 与 GLFW 游戏窗口 "Minecraft &lt;version&gt;" 会先后出现,必须区分)。</summary>
    private static List<(IntPtr Hwnd, string Title)>? FindMinecraftWindows()
    {
        _mcWindows.Clear();
        EnumWindows(EnumProcImpl, IntPtr.Zero);
        return _mcWindows.Count == 0 ? null : [.. _mcWindows];
    }

    // ------------------------------------------------------------------ warmup (pre-detour)

    /// <summary>
    /// Run the ENTIRE phase-2 pipeline against real paths while no detour exists: json parse ->
    /// classpath -> game/jvm args -> natives extraction -> gameDir creation -> watchdog plumbing.
    /// Post-Init, Run() only consumes the cached results and calls the prepared JNI entry points.
    /// </summary>
    public static void Warmup()
    {
        Console.WriteLine("[prejit] Phase 2 (MC launch) warmup ...");
        GameDir = Path.Combine(AppContext.BaseDirectory, "game");
        NativesDir = Path.Combine(AppContext.BaseDirectory, "game", "cache", "natives");
        PrepareVars();
        BuildFromVersionJson();
        NativesExtracted = ExtractNatives();
        EnsureGameDir();
        // PHASE15: JIT 预热退出清理路径 (post-detour 在 watchdog 线程执行: Directory.Delete
        // 递归 + File API 必须在 detour 前编译; 真实执行一次 dummy 创建+删除, 覆盖全部内部链)。
        CleanupWarmup();
        // watchdog plumbing: window scan + log tail + thread machinery (compiled pre-detour)
        _ = FindMinecraftWindows();
        _ = ReadTail(Path.Combine(GameDir, "logs", "latest.log"), 2000);
        // DumpEvidence's hs_err_pid scan (Directory.EnumerateFiles + ReadTail) compiles here too
        foreach (string f in Directory.EnumerateFiles(GameDir, "hs_err_pid*.log")) { _ = ReadTail(f, 4000); }
        var dummy = new Thread(() => { }) { IsBackground = true };
        dummy.Start();
        dummy.Join();
        // PrepareMethod for every post-Init entry point (their callees were just warmed by the
        // pipeline above; delegates/Invoke stubs warmed by JniPlumbing.Warmup).
        // PHASE11-AOT: 无 JIT, 反射预热跳过 (GetMethod 字符串反射在 AOT 下有裁剪告警)。
        if (!Program.IsAot)
        {
            string[] mcMethods =
            [
                "Run", "CreateStageOpts", "CallMainWithWatchdog", "WatchdogLoop", "DumpEvidence",
                "FindMinecraftWindows", "ReadTail", "Substitute", "CleanupTempArtifacts", "CleanupWarmup",
            ];
            foreach (string m in mcMethods)
            {
                MethodInfo mi = typeof(McLaunch).GetMethod(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                    ?? throw new InvalidOperationException($"McLaunch.Warmup: {m} not found");
                RuntimeHelpers.PrepareMethod(mi.MethodHandle);
            }
            string[] jniMethods = ["CreateVmWithOptions", "FindClassChecked", "AttachCurrentThread", "CallStaticVoidMain", "DiagnosePending"];
            foreach (string m in jniMethods)
            {
                MethodInfo mi = typeof(JniPlumbing).GetMethod(m, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                    ?? throw new InvalidOperationException($"McLaunch.Warmup: JniPlumbing.{m} not found");
                RuntimeHelpers.PrepareMethod(mi.MethodHandle);
            }
            RuntimeHelpers.PrepareMethod(typeof(Thread).GetMethod("Sleep", [typeof(int)])!.MethodHandle);
        }
        Console.WriteLine("[prejit] Phase 2 (MC launch) warmup done");
    }

    private static void PrepareVars()
    {
        Vars["${auth_player_name}"] = "Steve";
        Vars["${version_name}"] = VersionId;
        Vars["${game_directory}"] = GameDir;
        Vars["${assets_root}"] = AssetsDir;
        Vars["${assets_index_name}"] = AssetIndex;
        Vars["${auth_uuid}"] = "12345678-1234-1234-1234-1234567890ab";
        Vars["${auth_access_token}"] = "00000FFF00000FFF00000FFF00000FFF";
        Vars["${clientid}"] = "SingleFileMc";
        Vars["${auth_xuid}"] = "";
        Vars["${version_type}"] = "release";
        Vars["${natives_directory}"] = NativesDir;
        Vars["${library_directory}"] = LibrariesDir;
        Vars["${launcher_name}"] = "SingleFileMc";
        Vars["${launcher_version}"] = "1.0";
    }

    private static string Substitute(string s)
    {
        if (s.IndexOf("${", StringComparison.Ordinal) < 0) { return s; }
        foreach (KeyValuePair<string, string> kv in Vars)
        {
            s = s.Replace(kv.Key, kv.Value);
        }
        return s;
    }
    /// <summary>Launcher rule evaluation (last matching rule wins; os=windows, arch=amd64; feature-gated args never match).</summary>
    private static bool RulesAllow(JsonElement element)
    {
        if (!element.TryGetProperty("rules", out JsonElement rules)) { return true; }
        if (rules.ValueKind != JsonValueKind.Array || rules.GetArrayLength() == 0) { return true; }
        bool allowed = false;
        foreach (JsonElement r in rules.EnumerateArray())
        {
            bool match = true;
            if (r.TryGetProperty("os", out JsonElement os))
            {
                if (os.TryGetProperty("name", out JsonElement nm) && !string.Equals(nm.GetString(), "windows", StringComparison.OrdinalIgnoreCase)) { match = false; }
                if (os.TryGetProperty("arch", out JsonElement ar) && !string.Equals(ar.GetString(), "amd64", StringComparison.OrdinalIgnoreCase)) { match = false; }
            }
            if (r.TryGetProperty("features", out _)) { match = false; }
            if (match && r.TryGetProperty("action", out JsonElement act)) { allowed = act.GetString() == "allow"; }
        }
        return allowed;
    }

    /// <summary>An arguments-rule "value" field is either a plain string or a string array.</summary>
    private static IEnumerable<string> ArgValues(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.String)
        {
            yield return value.GetString() ?? "";
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement v in value.EnumerateArray())
            {
                yield return v.GetString() ?? "";
            }
        }
    }

    /// <summary>
    /// Parse the version json (real path, pre-detour; 容器激活时从容器读): windows-filtered
    /// library classpath (Z:\ paths) + version jar, substituted jvm/game args, natives-jar
    /// sources, missing-artifact list.
    /// </summary>
    private static void BuildFromVersionJson()
    {
        Console.WriteLine($"[mc] parsing version json {RelVersionJson}");
        byte[] jsonBytes;
        if (Container.Active)
        {
            if (!Container.HasEntry(RelVersionJson))
            {
                throw new InvalidOperationException($"容器缺版本 json: {RelVersionJson}");
            }
            jsonBytes = Container.ReadAllBytes(RelVersionJson);
            Console.WriteLine($"[mc] version json from container: {RelVersionJson} ({jsonBytes.Length} B)");
        }
        else
        {
            jsonBytes = File.ReadAllBytes(DiskPath(RelVersionJson));
        }
        using JsonDocument doc = JsonDocument.Parse(jsonBytes);
        JsonElement root = doc.RootElement;
        string mainClass = root.GetProperty("mainClass").GetString() ?? "";
        Console.WriteLine($"[mc] mainClass = {mainClass}");
        Console.WriteLine($"[mc] assetIndex = {root.GetProperty("assetIndex").GetProperty("id").GetString()}");

        var cp = new List<string>();
        var natives = new List<string>();
        var missing = new List<string>();
        int total = 0, allowed = 0;
        foreach (JsonElement lib in root.GetProperty("libraries").EnumerateArray())
        {
            total++;
            if (!RulesAllow(lib)) { continue; }
            allowed++;
            if (!lib.TryGetProperty("downloads", out JsonElement dl)) { continue; }
            if (!dl.TryGetProperty("artifact", out JsonElement art) || !art.TryGetProperty("path", out JsonElement pt)) { continue; }
            string rel = pt.GetString() ?? "";
            if (rel.Length == 0) { continue; }
            cp.Add(LibrariesDir + @"\" + rel.Replace('/', '\\'));
            string relKey = RelLibrariesKey + "/" + rel;   // 容器键 (与 zip 条目一致)
            // 容器激活时缺失检查走容器 (磁盘可能不存在, 容器是最终数据源)
            bool exists = Container.Active
                ? Container.HasEntry(relKey)
                : File.Exists(DiskPath(relKey));
            if (!exists) { missing.Add(rel); }
            if (rel.Contains("-natives-windows")) { natives.Add(relKey); }
        }
        cp.Add(VersionJarZ);
        bool versionJarExists = Container.Active
            ? Container.HasEntry(RelVersionJar)
            : File.Exists(DiskPath(RelVersionJar));
        if (!versionJarExists) { missing.Add("versions/" + VersionId + "/" + VersionId + ".jar"); }
        TotalLibraries = total;
        AllowedLibraries = allowed;
        Classpath = [.. cp];
        MissingJars = [.. missing];
        NativesSources = [.. natives];

        var jvm = new List<string>();
        foreach (JsonElement a in root.GetProperty("arguments").GetProperty("jvm").EnumerateArray())
        {
            if (a.ValueKind == JsonValueKind.String)
            {
                string s = a.GetString() ?? "";
                if (s == "-cp" || s == "${classpath}") { continue; } // replaced by -Djava.class.path
                jvm.Add(Substitute(s));
            }
            else if (RulesAllow(a))
            {
                // "value" may be a plain string (e.g. -XX:HeapDumpPath=...) or a string array
                foreach (string s in ArgValues(a.GetProperty("value")))
                {
                    if (s == "-cp" || s == "${classpath}") { continue; }
                    jvm.Add(Substitute(s));
                }
            }
        }
        // The version json lists --add-opens / --add-exports as a BARE token followed by the module
        // spec as the NEXT entry. The JVM launcher rejects the bare form ("Unrecognized option:
        // --add-opens"); the official MC launcher merges each pair into one option
        // (--add-opens=<module>/<package>=<target>). Do the same here (runAOT-3 evidence).
        var merged = new List<string>();
        for (int i = 0; i < jvm.Count; i++)
        {
            string s = jvm[i];
            if ((s == "--add-opens" || s == "--add-exports") && i + 1 < jvm.Count)
            {
                merged.Add(s + "=" + jvm[i + 1]);
                i++;
                continue;
            }
            merged.Add(s);
        }
        JvmArgs = [.. merged];

        var ga = new List<string>();
        foreach (JsonElement a in root.GetProperty("arguments").GetProperty("game").EnumerateArray())
        {
            if (a.ValueKind == JsonValueKind.String)
            {
                ga.Add(Substitute(a.GetString() ?? ""));
            }
            else if (RulesAllow(a))
            {
                foreach (string s in ArgValues(a.GetProperty("value")))
                {
                    ga.Add(Substitute(s));
                }
            }
        }
        GameArgs = [.. ga];

        string cpJoined = string.Join(";", Classpath);
        Console.WriteLine($"[mc] libraries: {total} total, {allowed} windows-allowed (classpath jars incl. natives: {Classpath.Length}, version jar included)");
        Console.WriteLine($"[mc] classpath length: {cpJoined.Length} chars, {cpJoined.Split(';').Length} entries");
        Console.WriteLine($"[mc] missing artifacts on disk: {missing.Count}");
        foreach (string m in missing) { Console.WriteLine($"  MISSING: {m}"); }
    }

    /// <summary>
    /// TEMPORARY natives scheme (PHASE15: 提取到 <gameDir>\cache\natives, 退出清理, %TEMP% 零残留;
    /// 完全内存化随 natives 虚拟化任务): extract
    /// every natives-windows jar into {NativesDir}\java (serves -Djava.library.path);
    /// create the lwjgl/jna/netty siblings (SharedLibraryExtractPath / jna.tmpdir / netty.workdir).
    /// 容器激活时 natives jar 从容器读 (字节 -> 内存 ZipArchive), 磁盘模式保持 ZipFile.OpenRead。
    /// </summary>
    private static int ExtractNatives()
    {
        string target = Path.Combine(NativesDir, "java");
        Directory.CreateDirectory(target);
        Directory.CreateDirectory(Path.Combine(NativesDir, "lwjgl"));
        Directory.CreateDirectory(Path.Combine(NativesDir, "jna"));
        Directory.CreateDirectory(Path.Combine(NativesDir, "netty"));
        int files = 0;
        foreach (string jarKey in NativesSources)
        {
            try
            {
                if (Container.Active)
                {
                    if (!Container.HasEntry(jarKey))
                    {
                        Console.WriteLine($"[mc] natives jar 不在容器: {jarKey}");
                        continue;
                    }
                    using var ms = new MemoryStream(Container.ReadAllBytes(jarKey));
                    using var za = new ZipArchive(ms, ZipArchiveMode.Read);
                    foreach (ZipArchiveEntry entry in za.Entries)
                    {
                        if (entry.FullName.EndsWith('/')) { continue; }
                        string dest = Path.Combine(target, Path.GetFileName(entry.FullName));
                        entry.ExtractToFile(dest, true);
                        files++;
                    }
                }
                else
                {
                    using ZipArchive za = ZipFile.OpenRead(DiskPath(jarKey));
                    foreach (ZipArchiveEntry entry in za.Entries)
                    {
                        if (entry.FullName.EndsWith('/')) { continue; }
                        string dest = Path.Combine(target, Path.GetFileName(entry.FullName));
                        entry.ExtractToFile(dest, true);
                        files++;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[mc] natives extract FAILED {jarKey}:\n{ex}");
            }
        }
        Console.WriteLine($"[mc] natives extracted {files} files from {NativesSources.Length} jars -> {target}");
        return files;
    }

    /// <summary>Create &lt;exe&gt;\game\{saves,mods,logs,config,resourcepacks} and probe writability.</summary>
    private static void EnsureGameDir()
    {
        foreach (string sub in new[] { "saves", "mods", "logs", "config", "resourcepacks" })
        {
            Directory.CreateDirectory(Path.Combine(GameDir, sub));
        }
        string probe = Path.Combine(GameDir, ".sfmc-write-probe");
        bool writable = false;
        try
        {
            File.WriteAllText(probe, "ok");
            writable = File.Exists(probe);
            File.Delete(probe);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[mc] gameDir writability probe threw:\n{ex}");
        }
        Console.WriteLine($"[mc] gameDir {GameDir} created, writable={writable}");
    }

    /// <summary>
    /// PHASE15: 退出清理 —— 删除整个 <gameDir>\cache (物化 modules + natives 提取), 使 %TEMP%
    /// 零残留。幂等, 可重复调用。post-detour 执行 (watchdog 线程/主线程, 已在 Warmup 经
    /// CleanupWarmup 全链 JIT 预热); 真实路径删除经 hooks 前置分流透传, 无假句柄风险。
    /// 游戏进程仍存活时 (watchdog 成功路径) 被占用文件删除会抛 IOException —— 捕获记录,
    /// 残留位于 gameDir 内 (非 %TEMP%), 由下次启动的 CleanupCache 清除。
    /// </summary>
    public static void CleanupTempArtifacts()
    {
        FakeFileSystem.CleanupCache();
    }

    /// <summary>预热期真实执行一次 dummy 创建+删除, 编译 Directory.Delete 递归 + File API 全链
    /// (post-detour 的退出清理在 hook 存活栈上执行时不得再触发 JIT)。</summary>
    private static void CleanupWarmup()
    {
        string dummy = Path.Combine(FakeFileSystem.CacheRoot, ".warmup-clean");
        try
        {
            Directory.CreateDirectory(dummy);
            File.WriteAllText(Path.Combine(dummy, "probe.bin"), "warmup");
            Directory.Delete(dummy, true);
            Console.WriteLine("[prejit] warmed cache cleanup path (dummy create+delete)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[prejit] CleanupWarmup threw:\n{ex}");
        }
    }

    // ------------------------------------------------------------------ post-Init run (per stage)

    /// <summary>
    /// Run the full Minecraft launch chain. Returns the process exit code; never returns normally
    /// (the watchdog TerminateProcess with the evidence code: 0 window / 3 game-exited / 42 timeout).
    /// </summary>
    public static int Run(IntPtr hJvm)
    {
        Console.WriteLine("========== Phase 2: MC launch ==========");
        Console.WriteLine($"[mc] mainClass={MainClass}");
        Console.WriteLine($"[mc] classpath: {Classpath.Length} jars, {string.Join(";", Classpath).Length} chars");
        Console.WriteLine($"[mc] gameDir={GameDir}");
        Console.WriteLine($"[mc] nativesDir={NativesDir} ({NativesExtracted} files extracted)");
        Console.WriteLine($"[mc] missing jars on disk: {MissingJars.Length}");
        Console.WriteLine($"[mc] game args ({GameArgs.Length}):");
        Console.WriteLine(string.Join(" ", GameArgs));
        Console.WriteLine($"[mc] jvm args ({JvmArgs.Length}):");
        foreach (string j in JvmArgs) { Console.WriteLine($"  {j}"); }

        // runAOT-3 evidence: the CreateVmWithOptions + FindClassChecked combination deterministically
        // fails the FIRST app-classpath FindClass on the 115-jar virtual classpath (stack-less
        // NoClassDefFoundError, systemDictionary.cpp:326) while the shared core (GetVersion ->
        // control FindClass -> warmup FindClass -> target, all through one delegate) always
        // succeeds. Route every MC launch through that core.
        // runNOGC-2 fix: the VM must receive the FULL option list (version-json jvm args incl.
        // -DlibraryDirectory + natives props + -XX:ErrorFile); before this, only -Djava.class.path
        // and -Xshare:off reached JNI_CreateJavaVM, so GameLocator saw libraryDirectory == null
        // and declared the NeoForge installation corrupted.
        string cpForJvm = string.Join(";", Classpath);
        int jr = JniPlumbing.CreateJvmAndFindClass(hJvm, cpForJvm, MainClass, CreateStageOpts());
        if (jr != 0)
        {
            Console.WriteLine($"[mc] FindClass({MainClass}) FAILED (missing jars on disk: {MissingJars.Length})");
            return jr;
        }
        Console.WriteLine($"[mc] {MainClass} loaded from virtual-FS classpath ({Classpath.Length} jars)");
        return CallMainWithWatchdog(JniPlumbing.CreatedVm, JniPlumbing.CreatedEnv, JniPlumbing.CreatedTargetClass);
    }

    private static string[] CreateStageOpts()
    {
        var opts = new List<string> { "-Djava.class.path=" + string.Join(";", Classpath), "-Xshare:off" };
        if (Container.Active && Program.JvmFromContainer)
        {
            // jvm.dll 从容器经假 SEC_IMAGE 加载 (Z: 路径): GetModuleFileName 返回
            // Z:\bin\server\jvm.dll 而非真实 JDK 路径 -> java.home 推导会错 -> 必须显式指定。
            // JVM 内部读取 (lib/modules、bin\java.dll) 走 Z:\openjdk\ 前缀 (PHASE13 换层) -> 容器服务。
            opts.Add("-Djava.home=Z:\\" + Container.JdkPrefix);
        }
        opts.Add("-Djava.library.path=" + Path.Combine(NativesDir, "java"));
        opts.Add("-Djna.tmpdir=" + Path.Combine(NativesDir, "jna"));
        opts.Add("-Dorg.lwjgl.system.SharedLibraryExtractPath=" + Path.Combine(NativesDir, "lwjgl"));
        opts.Add("-Dio.netty.native.workdir=" + Path.Combine(NativesDir, "netty"));
        // PHASE15 (G3): 抑制 hsperfdata 共享内存 (perfMemory_init_globals 直接跳过) ->
        // 不再生成 %TEMP%\hsperfdata_<user> (MC 不用 jvmstat, 零副作用)。
        opts.Add("-XX:+PerfDisableSharedMem");
        foreach (string j in JvmArgs)
        {
            if (j.StartsWith("-Djava.library.path=", StringComparison.Ordinal)
                || j.StartsWith("-Djna.tmpdir=", StringComparison.Ordinal)
                || j.StartsWith("-Dorg.lwjgl.system.SharedLibraryExtractPath=", StringComparison.Ordinal)
                || j.StartsWith("-Dio.netty.native.workdir=", StringComparison.Ordinal))
            {
                continue; // natives props already added above (identical values)
            }
            opts.Add(j);
        }
        opts.Add("-XX:ErrorFile=" + Path.Combine(GameDir, "hs_err_pid_%p.log"));
        return [.. opts];
    }

    // ------------------------------------------------------------------ stage D: main call + watchdog

    /// <summary>
    /// Run Client.main(String[]) on THIS thread with the creator JNIEnv (from JNI_CreateJavaVM;
    /// a JVM env is valid on its creating thread -- runAOT-3 evidence: AttachCurrentThread from a
    /// separate CLR thread returned ret=0 with penv=0x0, and calling into the JVM with a NULL env
    /// AV'd into the armed VEH -> ReversePInvokeBadTransition fail-fast). The WATCHDOG runs on a
    /// background thread: polls for the Minecraft window / FML log growth / 180s deadline and
    /// TerminateProcess with the evidence code: 0 = window found, 42 = timeout. If Client.main
    /// returns, the game exited on its own -> code 3.
    /// </summary>
    private static int CallMainWithWatchdog(IntPtr vm, IntPtr penv, IntPtr cls)
    {
        _vmForMain = vm;
        _clsForMain = cls;
        string latest = Path.Combine(GameDir, "logs", "latest.log");
        // PHASE9: 恢复 watchdog(此前被注释): 检测游戏窗口(非 FML loading 标题)即成功,
        // 退出码 0。游戏窗口 "Minecraft NeoForge* 26.2" 出现 = 主菜单在渲染。
        var t = new Thread(() => WatchdogLoop(latest)) { IsBackground = true, Name = "mc-watchdog" };
        Console.WriteLine("[mc] starting watchdog thread, Client.main on this thread ...");
        t.Start();

        int r;
        try
        {
            r = JniPlumbing.CallStaticVoidMain(penv, cls, GameArgs);
            Console.WriteLine($"[mc] Client.main returned (jni result {r})");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[mc] main thread exception:\n{ex}");
        }
        Console.WriteLine("[mc] main thread exited -> the game ended itself");
        DumpEvidence(latest);
        CleanupTempArtifacts();
        Console.WriteLine("[mc] exit code 3 (game exited)");
        return 3;
    }

    /// <summary>Background poller: window / log growth / deadline; TerminateProcess on success or timeout.</summary>
    private static void WatchdogLoop(string latest)
    {
        long deadline = Environment.TickCount64 + WatchdogMs;
        int lastLen = -1;
        long lastAliveLog = Environment.TickCount64;
        while (true)
        {
            Thread.Sleep(500);
            Console.WriteLine("[wd] after Sleep");
            var wins = FindMinecraftWindows();
            Console.WriteLine($"[wd] after EnumWindows: {(wins is null ? "(none)" : string.Join(" | ", wins.Select(w => w.Title)))}");
            // Success = a Minecraft window that is NOT the FML loading splash ("Minecraft:
            // NeoForge Loading..."): the GLFW game window ("Minecraft <version>") only appears
            // once the game layer is up, i.e. the main menu is rendering (runNEO-1 evidence:
            // the old first-match check fired on the loading window and killed the game mid-load).
            string? game = wins?.Where(w => !w.Title.Contains("NeoForge Loading", StringComparison.OrdinalIgnoreCase))
                .Select(w => w.Title)
                .FirstOrDefault();
            if (game is not null)
            {
                Console.WriteLine($"[mc] SUCCESS: Minecraft game window detected: '{game}'");
                DumpEvidence(latest);
                // PHASE15: 清理物化/提取缓存 (删除被占用文件失败时残留于 gameDir 内, 下次启动清)
                CleanupTempArtifacts();
                Console.WriteLine("[mc] exit code 0 (game window found)");
                TerminateProcess(GetCurrentProcess(), 0);
                return;
            }
            long len = 0;
            if (File.Exists(latest)) { len = new FileInfo(latest).Length; }
            Console.WriteLine($"[wd] after File.Exists: len={len}");
            if (len != lastLen)
            {
                lastLen = (int)len;
                Console.WriteLine($"[mc] latest.log size {len}");
                if (len > 0) { Console.WriteLine(ReadTail(latest, 2000)); }
                Console.WriteLine("[wd] after ReadTail");
            }
            if (Environment.TickCount64 > deadline)
            {
                Console.WriteLine($"[mc] TIMEOUT after {WatchdogMs / 1000} s");
                DumpEvidence(latest);
                CleanupTempArtifacts();
                Console.WriteLine("[mc] exit code 42 (timeout)");
                TerminateProcess(GetCurrentProcess(), 42);
                return;
            }
            if (Environment.TickCount64 - lastAliveLog > 10_000)
            {
                lastAliveLog = Environment.TickCount64;
                Console.WriteLine($"[mc] watchdog alive, waiting for window ...");
            }
        }
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern void TerminateProcess(IntPtr hProcess, uint uExitCode);

    private static void DumpEvidence(string latest)
    {
        try
        {
            string tail = ReadTail(latest, 8000);
            Console.WriteLine("---- gameDir logs/latest.log tail ----");
            Console.WriteLine(tail.Length == 0 ? "(no latest.log)" : tail);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[mc] latest.log read threw:\n{ex}");
        }
        foreach (string dir in new[] { GameDir, AppContext.BaseDirectory })
        {
            try
            {
                foreach (string f in Directory.EnumerateFiles(dir, "hs_err_pid*.log"))
                {
                    Console.WriteLine($"[mc] crash dump: {f}");
                    Console.WriteLine(ReadTail(f, 4000));
                }
            }
            catch { /* dir unreadable */ }
        }
    }

    /// <summary>Tail of a (possibly still-growing) file, real path; FileShare.ReadWrite for log4j's live writer.</summary>
    private static string ReadTail(string path, int maxLen)
    {
        if (!File.Exists(path)) { return ""; }
        long len = new FileInfo(path).Length;
        if (len <= 0) { return ""; }
        long start = Math.Max(0, len - maxLen);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        fs.Seek(start, SeekOrigin.Begin);
        int n = (int)(len - start);
        byte[] buf = new byte[n];
        fs.ReadExactly(buf);
        return Encoding.UTF8.GetString(buf);
    }
}
