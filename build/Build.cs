using System.Diagnostics;
using System.IO.Compression;
using Nuke.Common;
using Nuke.Common.IO;

/// <summary>构建配置 (NUKE 10 无内置 Configuration 枚举, 自定义)。</summary>
public enum Configuration
{
    Debug,
    Release,
}

// ============================================================================
// SingleFileMc NUKE 构建 —— 纯打包管线 (用户明确: 无任何 Verify/Test/Smoke target)。
//
// Targets (全部打包动作, 验证由 worker 在 NUKE 之外手动执行):
//   Build     dotnet build 主工程 (SingleFileMc/SingleFileMc.csproj) —— JIT 调试链路, 保留
//   Native    cmake --build native_hooks (sfmc_hooks_shared.dll)
//   Pack      Minecraft/ 数据树 -> container.zip (ZipArchive + NoCompression, 全 Store)
//   Append    AOT exe 尾部追加 container.zip -> artifacts/SingleFileMc.exe (最终交付物)
//   Publish   NativeAOT 发布: dotnet publish -c Release -r win-x64 (纯原生单 exe, 零外部 dll)
//
// 依赖: Append = Publish + Pack; Build (JIT) 独立保留作调试链路, 不再参与交付管线。
// 执行工具全部走标准 System.Diagnostics.Process (NUKE 10 工具 API 拆分频繁, 不用)。
// ============================================================================
class BuildScript : NukeBuild
{
    /// <summary>入口 target (默认运行 Build)。</summary>
    public static int Main() => Execute<BuildScript>(x => x.Build);

    [Parameter("Configuration to build - Default is: Debug")]
    private readonly Configuration Configuration = Configuration.Debug;

    // ---- 路径 ----
    private AbsolutePath MainProject => RootDirectory / "SingleFileMc" / "SingleFileMc.csproj";
    private AbsolutePath NativeBuildDir => RootDirectory / "native_hooks" / "build";
    private AbsolutePath MinecraftRoot => RootDirectory / "SingleFileMc" / "Minecraft";
    private AbsolutePath ArtifactsDir => RootDirectory / "artifacts";
    private AbsolutePath ContainerZip => ArtifactsDir / "container.zip";
    private AbsolutePath FinalExe => ArtifactsDir / "SingleFileMc.exe";
    private AbsolutePath BuiltExe => RootDirectory / "SingleFileMc" / "bin" / Configuration.ToString() / "net10.0" / "SingleFileMc.exe";
    // PHASE17-AOT: AOT 发布产物 (dotnet publish -c Release -r win-x64)。AOT 固定 Release,
    // 不受 NUKE Configuration 参数影响 (PublishAot 发布只走 Release 优化, 与 PHASE11 基线一致)。
    private AbsolutePath AotExe => RootDirectory / "SingleFileMc" / "bin" / "Release" / "net10.0" / "win-x64" / "publish" / "SingleFileMc.exe";

    /// <summary>Build: dotnet build 主工程 (JIT 模式, 容器验证链路)。
    /// PHASE11-AOT: csproj 默认 PublishAot=true (NativeAOT 发布用); JIT 测试/容器模式必须
    /// 显式 -p:PublishAot=false 覆盖 —— 否则 runtimeconfig 带 IsDynamicCodeSupported=false,
    /// 运行时误判 NativeAot 走 __Internal 静态符号 (JIT 构建不存在) -> DllNotFoundException。</summary>
    private Target Build => _ => _
        .Executes(() =>
        {
            Console.WriteLine("==> Build: dotnet build SingleFileMc (JIT mode, PublishAot=false)");
            RunTool("dotnet", $"build \"{MainProject}\" -c {Configuration} -p:PublishAot=false");
            if (!File.Exists(BuiltExe))
            {
                throw new InvalidOperationException($"Build 未产出 exe: {BuiltExe}");
            }
            Console.WriteLine($"==> Build 完成: {BuiltExe} ({new FileInfo(BuiltExe).Length} B)");
        });

    /// <summary>Native: cmake --build native_hooks/build (sfmc_hooks_shared.dll)。</summary>
    private Target Native => _ => _
        .Executes(() =>
        {
            Console.WriteLine("==> Native: cmake --build native_hooks/build");
            if (!Directory.Exists(NativeBuildDir))
            {
                throw new DirectoryNotFoundException($"native_hooks/build 不存在, 请先 cmake 配置: {NativeBuildDir}");
            }
            RunTool(FindCmake(), $"--build \"{NativeBuildDir}\"");
            string dll = Path.Combine(NativeBuildDir, "sfmc_hooks_shared.dll");
            if (!File.Exists(dll))
            {
                throw new InvalidOperationException($"Native 未产出 {dll}");
            }
            Console.WriteLine($"==> Native 完成: {dll} ({new FileInfo(dll).Length} B)");
        });

    /// <summary>
    /// Pack: Minecraft/ 数据树 -> container.zip。
    /// ZipArchive + NoCompression => 全部条目 method=0 (Store), 运行时 mmap 直接按偏移读。
    /// 排除 (计划 §3.5): PCL/、Plain Craft Launcher 2.exe、.gitignore、**/Log*.txt。
    /// PHASE13 (VFS 换层): zip 顶层 = openjdk/ + minecraft/ —— 源顶层映射:
    ///   Minecraft/.minecraft/**                -> minecraft/**
    ///   Minecraft/&lt;jdk顶层&gt;/** (含 bin/server/jvm.dll) -> openjdk/**
    /// (jdk 顶层名动态发现, 不硬编码版本号; 其余顶层必须已被 Excluded 过滤, 否则报错防静默丢数据)
    /// </summary>
    private Target Pack => _ => _
        .Executes(() =>
        {
            Console.WriteLine($"==> Pack: {MinecraftRoot} -> {ContainerZip}");
            if (!Directory.Exists(MinecraftRoot))
            {
                throw new DirectoryNotFoundException($"Minecraft 数据树不存在: {MinecraftRoot}");
            }
            Dictionary<string, string> topMap = BuildTopMap(MinecraftRoot);
            Directory.CreateDirectory(ArtifactsDir);
            long total = 0;
            int files = 0, dirs = 0;
            using (FileStream fs = File.Create(ContainerZip))
            using (var zip = new ZipArchive(fs, ZipArchiveMode.Create, leaveOpen: false))
            {
                // 目录条目 (显式, 结尾 '/') + 文件条目, 条目名 = 映射后的正斜杠路径
                foreach (string dir in EnumerateDirs(MinecraftRoot))
                {
                    zip.CreateEntry(MapEntry(dir, topMap) + "/", CompressionLevel.NoCompression);
                    dirs++;
                }
                foreach (string file in EnumerateFiles(MinecraftRoot))
                {
                    string entry = MapEntry(file, topMap);
                    ZipArchiveEntry ze = zip.CreateEntry(entry, CompressionLevel.NoCompression);
                    using (Stream dst = ze.Open())
                    using (FileStream src = File.OpenRead(file))
                    {
                        src.CopyTo(dst);
                    }
                    total += new FileInfo(file).Length;
                    files++;
                }
            }
            Console.WriteLine($"==> Pack 完成: {files} files + {dirs} dirs, {total / (1024.0 * 1024.0):F1} MB -> {ContainerZip}");
        });

    /// <summary>Append: AOT exe 尾部追加 container.zip -> artifacts/SingleFileMc.exe (记录前后大小)。
    /// PHASE17-AOT: 来源从 JIT BuiltExe 切换为 Publish 产出的 AOT 单 exe —— 最终交付物 = 纯原生 exe + 尾部 zip。</summary>
    private Target Append => _ => _
        .DependsOn(Publish, Pack)
        .Executes(() =>
        {
            long exeLen = new FileInfo(AotExe).Length;
            long zipLen = new FileInfo(ContainerZip).Length;
            Console.WriteLine($"==> Append: {AotExe} ({exeLen} B) + {ContainerZip} ({zipLen} B)");
            Directory.CreateDirectory(ArtifactsDir);
            using (FileStream dst = File.Create(FinalExe))
            {
                using (FileStream src = File.OpenRead(AotExe)) { src.CopyTo(dst); }
                using (FileStream src = File.OpenRead(ContainerZip)) { src.CopyTo(dst); }
            }
            long outLen = new FileInfo(FinalExe).Length;
            Console.WriteLine($"==> Append 完成: {exeLen} B exe + {zipLen} B zip = {outLen} B -> {FinalExe}");
        });

    /// <summary>
    /// Publish: NativeAOT 发布 (PHASE17-AOT 落地) —— dotnet publish -c Release -r win-x64。
    /// csproj 默认 PublishAot=true, 产出纯原生单 exe (sfmc_hooks_static.lib 静态链接, 零外部 dll)。
    /// 断言: publish 目录 exe 存在且 &gt; 1 MiB (AOT 镜像 ~3.3 MiB; 若误出 JIT apphost 仅 ~162 KiB, 直接报错)。
    /// </summary>
    private Target Publish => _ => _
        .Executes(() =>
        {
            Console.WriteLine("==> Publish: dotnet publish -c Release -r win-x64 (NativeAOT)");
            RunTool("dotnet", $"publish \"{MainProject}\" -c Release -r win-x64");
            if (!File.Exists(AotExe))
            {
                throw new FileNotFoundException($"Publish 未产出 AOT exe: {AotExe}");
            }
            long len = new FileInfo(AotExe).Length;
            if (len < 1024 * 1024)
            {
                throw new InvalidOperationException($"AOT exe 异常偏小 ({len} B, 疑似 JIT apphost 而非 AOT 镜像): {AotExe}");
            }
            Console.WriteLine($"==> Publish 完成: {AotExe} ({len} B)");
        });

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// 源顶层目录 -> zip 顶层目录名 (PHASE13 VFS 分层)。
    /// jdk 顶层动态发现: 含 bin/server/jvm.dll 的顶层 -> "openjdk"; .minecraft -> "minecraft"。
    /// 其余顶层 (PCL/ 等) 必须已由 Excluded 过滤, 否则抛错防静默丢数据。
    /// </summary>
    private Dictionary<string, string> BuildTopMap(AbsolutePath mcRoot)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal) { [".minecraft"] = "minecraft" };
        foreach (string dir in Directory.GetDirectories(mcRoot))
        {
            string name = Path.GetFileName(dir);
            if (File.Exists(Path.Combine(dir, "bin", "server", "jvm.dll")))
            {
                map[name] = "openjdk";
                Console.WriteLine($"==> Pack 顶层映射: {name}/ -> openjdk/");
            }
        }
        if (!map.ContainsValue("openjdk"))
        {
            throw new DirectoryNotFoundException($"Minecraft 树缺 JDK 顶层 (未找到 bin/server/jvm.dll): {mcRoot}");
        }
        foreach (string dir in Directory.GetDirectories(mcRoot))
        {
            string name = Path.GetFileName(dir);
            if (!map.ContainsKey(name) && !Excluded(dir))
            {
                throw new InvalidOperationException($"Minecraft 树未知顶层目录: {name} (需加入映射或 Excluded)");
            }
        }
        return map;
    }

    /// <summary>绝对路径 -> zip 条目名: 顶层段按 topMap 映射, 其余段照抄 (正斜杠)。</summary>
    private string MapEntry(string abs, Dictionary<string, string> topMap)
    {
        string rel = Path.GetRelativePath(MinecraftRoot, abs);
        int idx = rel.IndexOf(Path.DirectorySeparatorChar);
        string top = idx < 0 ? rel : rel[..idx];
        string rest = idx < 0 ? "" : rel[(idx + 1)..];
        if (!topMap.TryGetValue(top, out string? mapped))
        {
            throw new InvalidOperationException($"Minecraft 树未映射条目: {abs}");
        }
        return rest.Length == 0 ? mapped : mapped + "/" + rest.Replace('\\', '/');
    }

    private static bool Excluded(string abs)
    {
        string name = Path.GetFileName(abs);
        if (name.Equals("Plain Craft Launcher 2.exe", StringComparison.OrdinalIgnoreCase)) { return true; }
        if (name.Equals(".gitignore", StringComparison.OrdinalIgnoreCase)) { return true; }
        if (name.StartsWith("Log", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)) { return true; }
        // PCL/ 目录整树排除
        foreach (string seg in abs.Split(Path.DirectorySeparatorChar))
        {
            if (seg.Equals("PCL", StringComparison.OrdinalIgnoreCase)) { return true; }
        }
        return false;
    }

    private static IEnumerable<string> EnumerateDirs(string root)
    {
        var q = new Queue<string>();
        q.Enqueue(root);
        while (q.Count > 0)
        {
            string d = q.Dequeue();
            foreach (string sub in Directory.GetDirectories(d).OrderBy(x => x, StringComparer.Ordinal))
            {
                if (Excluded(sub)) { continue; }
                q.Enqueue(sub);
            }
            if (d != root) { yield return d; }
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root)
    {
        foreach (string f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                     .OrderBy(x => x, StringComparer.Ordinal))
        {
            if (Excluded(f)) { continue; }
            yield return f;
        }
    }

    /// <summary>执行外部工具并断言零退出码 (输出实时透传)。</summary>
    private static void RunTool(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"无法启动 {exe}");
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) { Console.WriteLine(e.Data); } };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null) { Console.Error.WriteLine(e.Data); } };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"{exe} 退出码 {p.ExitCode}: {args}");
        }
    }

    /// <summary>定位 cmake: PATH 优先, 回退 VS 内置 CMake。</summary>
    private static string FindCmake()
    {
        string? fromPath = Environment.GetEnvironmentVariable("PATH")?
            .Split(Path.PathSeparator)
            .Select(d => Path.Combine(d, "cmake.exe"))
            .FirstOrDefault(File.Exists);
        if (fromPath is not null) { return fromPath; }
        string vsCmake = @"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe";
        if (File.Exists(vsCmake)) { return vsCmake; }
        throw new FileNotFoundException("未找到 cmake (PATH 或 VS 内置)");
    }
}
