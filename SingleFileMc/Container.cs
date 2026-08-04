using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SingleFileMc;

/// <summary>
/// 容器数据源: exe 尾部附加的 Store(不压缩)zip。
///
/// 机制 (阶段 2, PHASE10-CONTAINER):
///   1. Init() 在宿主最早期执行: mmap 自身 exe (CreateFileMappingW + MapViewOfFile,
///      PAGE_READONLY), 全程 Int64 偏移 (容器 zip 可到 ~1.3GB, 避免 32 位偏移问题)。
///   2. 尾部扫描 EOCD (0x06054b50, commentLen 校验) -> 中央目录偏移/条目数 ->
///      逐条目解析 (46 B 中央目录头: sig@0, method@10, compSize@20, uncompSize@24,
///      fnameLen@28, extraLen@30, commentLen@32, localOff@42;
///      dataOffset = localOff + 30 + fnameLen + extraLen)。
///   3. Store 校验: 任何条目 method != 0 (或 compSize != uncompSize) -> 打印错误并
///      Environment.Exit(ExitNotStore) —— 容器必须是零压缩, 运行时不做解压。
///   4. 目录表 FrozenDictionary (键 = '/' 分隔条目名, 目录键无尾斜杠), 只读。
///   5. API: OpenRead / GetLength / ReadAt (直接读映射内存, 零拷贝, 不依赖 ZipArchive)。
///
/// 映射规则 (rest = Z: 路径去前缀, '\' 分隔; 键 = 容器条目名, '/' 分隔):
///   - rest 精确匹配条目            -> 该条目 (Z:\openjdk\bin\java.dll -> openjdk/bin/java.dll;
///                                     Z:\minecraft\versions\... -> minecraft/versions\... 等)
///   - 其余                         -> "&lt;jdk顶层名&gt;/" + rest     (Z:\bin\java.dll -> openjdk/bin/java.dll)
///
/// PHASE13 (VFS 换层): zip 顶层由 jdk-25.0.4.7-hotspot/ + .minecraft/ 改为 openjdk/ + minecraft/,
/// 虚拟映射 Z:\openjdk\... 与 Z:\minecraft\... 同容器条目一一对应 —— 旧版
/// "minecraft\ 前缀 -> .minecraft/..." 的换层逻辑已删除 (Z:\minecraft\... 直接精确命中)。
///
/// 无尾部 zip 时 Active=false, 调用方回退真实磁盘别名 (既有 TryMap 磁盘分支)。
/// 映射只读: 假 SEC_IMAGE 布局 (MapImageLayout) 仍用现有 VirtualAlloc RWX 副本,
/// 容器映射本身永远 PAGE_READONLY, 不被写入。
/// </summary>
internal static unsafe class Container
{
    // ---- 退出码 (PHASE10-CONTAINER 记录) ----
    public const int ExitNotStore = 100;   // 容器 zip 含非 Store 条目
    public const int ExitInvalid = 101;    // zip 结构损坏 / 解析失败

    // ---- zip 常量 ----
    private const uint SigEocd = 0x06054b50;
    private const uint SigCentral = 0x02014b50;
    private const int EocdSize = 22;
    private const int CentralSize = 46;
    private const int LocalHeaderSize = 30;

    // ---- 状态 ----
    private static byte* _base;                    // 映射基址 (exe+zip 全量)
    private static long _mapLen;                   // 映射长度
    private static long _zipStart;                 // zip 数据在文件中的起始偏移 (= exe 大小)
    private static string _jdkPrefix = "";         // 容器 jdk 顶层目录名 (新分层 = openjdk)
    private static FrozenDictionary<string, Entry> _entries = FrozenDictionary<string, Entry>.Empty;
    private static FrozenDictionary<string, byte> _dirs = FrozenDictionary<string, byte>.Empty;
    // 父目录键 (无尾斜杠) -> 子条目名 -> (IsDir, Length); "" = 顶层
    private static FrozenDictionary<string, FrozenDictionary<string, ChildInfo>> _children =
        FrozenDictionary<string, FrozenDictionary<string, ChildInfo>>.Empty;

    /// <summary>尾部 zip 是否存在且解析成功。false = 回退真实磁盘别名。</summary>
    public static bool Active { get; private set; }

    /// <summary>容器 jdk 顶层目录名 (Z: 前缀映射用)。</summary>
    public static string JdkPrefix => _jdkPrefix;

    /// <summary>zip 数据在 exe 文件中的起始偏移 (记录用)。</summary>
    public static long ZipStart => _zipStart;

    /// <summary>容器条目 (目录表值, 只读)。</summary>
    private readonly struct Entry
    {
        public readonly long DataOffset;   // 数据区起始 (local header 30 + name + extra 之后)
        public readonly long Length;       // uncompressed size (== compressed size, Store)
        public readonly bool IsDir;
        public readonly ushort Method;

        public Entry(long dataOffset, long length, bool isDir, ushort method)
        {
            DataOffset = dataOffset;
            Length = length;
            IsDir = isDir;
            Method = method;
        }
    }

    /// <summary>子条目 (目录枚举用)。</summary>
    private readonly struct ChildInfo
    {
        public readonly bool IsDir;
        public readonly long Length;

        public ChildInfo(bool isDir, long length)
        {
            IsDir = isDir;
            Length = length;
        }
    }

    // ------------------------------------------------------------------ Init

    /// <summary>
    /// 初始化容器: mmap 自身 exe -> 尾部找 EOCD -> 解析中央目录 -> Store 校验 -> 建目录表。
    /// 必须在任何 ntdll detour 安装之前调用 (本方法用 File API + 可能 Environment.Exit)。
    /// </summary>
    public static void Init()
    {
        try
        {
            InitCore();
        }
        catch (Exception ex)
        {
            // 解析失败: 打印完整异常并退出 (容器损坏不可静默回退 —— Store 校验是安全语义)
            Console.Error.WriteLine($"[container] FATAL: 容器解析失败:\n{ex}");
            Environment.Exit(ExitInvalid);
        }
    }

    private static void InitCore()
    {
        string exePath = GetModuleFileNameW();
        using SafeFileHandle h = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h.IsInvalid)
        {
            Console.WriteLine($"[container] CreateFileW({exePath}) failed win32={Marshal.GetLastWin32Error()} -> 回退磁盘别名");
            return;
        }
        if (!GetFileSizeEx(h.DangerousGetHandle(), out long fileLen) || fileLen < EocdSize)
        {
            Console.WriteLine("[container] 无尾部 zip (文件过小) -> 回退磁盘别名");
            return;
        }

        // ---- 尾部扫描 EOCD (最多回看 64KB + 22; commentLen 与文件尾距离一致才接受) ----
        long eocdPos = FindEocd(h, fileLen);
        if (eocdPos < 0)
        {
            Console.WriteLine("[container] 无尾部 zip (未找到 EOCD 0x06054b50) -> 回退磁盘别名");
            return;
        }

        // ---- mmap 整个 exe (只读, 全程 Int64; 映射句柄由进程生命周期持有) ----
        IntPtr map = CreateFileMappingW(h.DangerousGetHandle(), IntPtr.Zero, PAGE_READONLY, 0, 0, null);
        if (map == IntPtr.Zero)
        {
            throw new InvalidOperationException($"CreateFileMappingW failed win32={Marshal.GetLastWin32Error()}");
        }
        byte* baseAddr = (byte*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, UIntPtr.Zero);
        if (baseAddr == null)
        {
            throw new InvalidOperationException($"MapViewOfFile failed win32={Marshal.GetLastWin32Error()}");
        }
        _base = baseAddr;
        _mapLen = fileLen;

        // ---- EOCD 头 (22 B) ----
        ushort count = ReadU16(eocdPos + 8);
        uint cdSize = ReadU32(eocdPos + 12);
        uint cdOffset = ReadU32(eocdPos + 16);
        ushort commentLen = ReadU16(eocdPos + 20);
        // zip 被追加到 exe 尾部: zip 内部偏移 (localOff/cdOffset) 以 zip 文件自身为 0 基,
        // 映射内存中实际位置 = zipBase + 内部偏移。zipBase 由文件总长反推:
        // zip 长度 = cdOffset + cdSize + 22 + commentLen (中央目录 + EOCD 在 zip 尾部)。
        long zipBase = fileLen - ((long)cdOffset + cdSize + EocdSize + commentLen);
        if (zipBase < 0 || zipBase + cdOffset + cdSize > eocdPos)
        {
            throw new InvalidDataException($"zip 基址越界: zipBase={zipBase} cdOffset={cdOffset} cdSize={cdSize} eocdPos={eocdPos}");
        }
        _zipStart = zipBase;
        Console.WriteLine($"[container] EOCD@{eocdPos} entries={count} cdOffset={cdOffset} cdSize={cdSize} zipBase={zipBase} fileLen={fileLen}");

        // ---- 逐条目解析中央目录 (映射内存直读) ----
        var entries = new Dictionary<string, Entry>(count * 2, StringComparer.Ordinal);
        var dirs = new HashSet<string>(StringComparer.Ordinal);
        var children = new Dictionary<string, SortedDictionary<string, ChildInfo>>(StringComparer.Ordinal);
        long pos = zipBase + cdOffset;
        for (int i = 0; i < count; i++)
        {
            if (pos + CentralSize > eocdPos)
            {
                throw new InvalidDataException($"中央目录第 {i} 条越界 @{pos}");
            }
            uint sig = ReadU32(pos);
            if (sig != SigCentral)
            {
                throw new InvalidDataException($"中央目录第 {i} 条签名错误: 0x{sig:X8} @{pos}");
            }
            ushort method = ReadU16(pos + 10);
            uint csize = ReadU32(pos + 20);
            uint usize = ReadU32(pos + 24);
            int fnameLen = ReadU16(pos + 28);
            int extraLen = ReadU16(pos + 30);
            int entryCommentLen = ReadU16(pos + 32);
            uint localOff = ReadU32(pos + 42);

            // ---- Store 校验 (安全语义): method != 0 或 压缩/原始大小不一致 -> 报错退出 ----
            if (method != 0)
            {
                string name = ReadName(pos + CentralSize, fnameLen);
                Console.Error.WriteLine($"[container] FATAL: 条目 '{name}' method={method} (非 Store) —— 容器必须是零压缩 zip");
                Console.Error.WriteLine($"[container] 拒绝启动 (退出码 {ExitNotStore})");
                Environment.Exit(ExitNotStore);
            }
            if (csize != usize)
            {
                string name = ReadName(pos + CentralSize, fnameLen);
                Console.Error.WriteLine($"[container] FATAL: 条目 '{name}' compSize({csize}) != uncompSize({usize}) —— Store 语义被破坏");
                Console.Error.WriteLine($"[container] 拒绝启动 (退出码 {ExitNotStore})");
                Environment.Exit(ExitNotStore);
            }

            long dataOffset = zipBase + (long)localOff + LocalHeaderSize + fnameLen + extraLen;
            if (dataOffset + usize > eocdPos)
            {
                throw new InvalidDataException($"条目@{i} 数据越界: dataOffset={dataOffset} size={usize} eocdPos={eocdPos}");
            }
            bool isDir = fnameLen > 0 && _base[pos + CentralSize + fnameLen - 1] == (byte)'/';
            string key = ReadName(pos + CentralSize, fnameLen).TrimEnd('/');
            entries[key] = new Entry(dataOffset, usize, isDir, method);
            if (isDir) { dirs.Add(key); }

            // ---- 子条目分组 (目录枚举用): 父键 + 子名 ----
            string? parent = GetParent(key);
            string childName = parent is null ? key : key[(parent.Length + 1)..];
            if (!children.TryGetValue(parent ?? "", out SortedDictionary<string, ChildInfo>? grp))
            {
                grp = new SortedDictionary<string, ChildInfo>(StringComparer.Ordinal);
                children[parent ?? ""] = grp;
            }
            grp[childName] = new ChildInfo(isDir, usize);

            pos += CentralSize + fnameLen + extraLen + entryCommentLen;
        }
        if (pos != eocdPos)
        {
            throw new InvalidDataException($"中央目录尾部残留 {eocdPos - pos} B");
        }

        // ---- 隐式父目录补全 (文件条目 "a/b/c" 的父 "a/b"、"a" 必须可当目录枚举) ----
        var allDirs = new HashSet<string>(dirs, StringComparer.Ordinal);
        foreach (string k in entries.Keys)
        {
            int idx = k.IndexOf('/');
            while (idx > 0)
            {
                allDirs.Add(k[..idx]);
                idx = k.IndexOf('/', idx + 1);
            }
        }
        _dirs = allDirs.ToFrozenDictionary(k => k, _ => (byte)1, StringComparer.Ordinal);
        _entries = entries.ToFrozenDictionary(StringComparer.Ordinal);

        // ---- 子条目分组冻结 (含隐式父目录的空组, 枚举时不缺键) ----
        var childMap = new Dictionary<string, Dictionary<string, ChildInfo>>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, SortedDictionary<string, ChildInfo>> kv in children)
        {
            childMap[kv.Key] = kv.Value.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        }
        foreach (string d in _dirs.Keys)
        {
            if (!childMap.ContainsKey(d)) { childMap[d] = new Dictionary<string, ChildInfo>(StringComparer.Ordinal); }
        }
        childMap[""] = new Dictionary<string, ChildInfo>(StringComparer.Ordinal);
        var frozenChildren = new Dictionary<string, FrozenDictionary<string, ChildInfo>>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, Dictionary<string, ChildInfo>> kv in childMap)
        {
            frozenChildren[kv.Key] = kv.Value.ToFrozenDictionary(StringComparer.Ordinal);
        }
        _children = frozenChildren.ToFrozenDictionary(StringComparer.Ordinal);

        // ---- jdk 顶层名推导: 存在 "{prefix}/bin/server/jvm.dll" 的条目 ----
        foreach (string k in _entries.Keys)
        {
            int slash = k.IndexOf('/');
            if (slash > 0 && k.AsSpan(slash + 1).SequenceEqual("bin/server/jvm.dll"))
            {
                _jdkPrefix = k[..slash];
                break;
            }
        }
        if (_jdkPrefix.Length == 0)
        {
            // 无 jvm.dll 的容器也允许 (仅 MC 数据树), 取第一个顶层键作为 jdk 前缀候选 (仅用于 Z: 前缀映射)
            foreach (string k in _entries.Keys)
            {
                int slash = k.IndexOf('/');
                if (slash > 0)
                {
                    _jdkPrefix = k[..slash];
                    break;
                }
            }
        }

        Active = true;
        Console.WriteLine($"[container] OK: {_entries.Count} entries, {_dirs.Count} dirs, jdkPrefix='{_jdkPrefix}', mapLen={_mapLen}");
    }

    // ------------------------------------------------------------------ 映射规则

    /// <summary>
    /// Z: 路径 rest (反斜杠, 无 "Z:\" 前缀) -> 容器键 (正斜杠, 无尾斜杠)。
    /// 规则: ①精确 ②其余 -> jdkPrefix/...。
    /// PHASE13: zip 顶层 = openjdk/ + minecraft/, Z:\minecraft\... 与容器条目 minecraft/...
    /// 一一对应 (旧版 "minecraft\ 前缀 -> .minecraft/..." 的换层规则已删除)。
    /// </summary>
    public static bool TryMapKey(string rest, out string key, out bool isDir)
    {
        key = "";
        isDir = false;
        if (!Active || string.IsNullOrEmpty(rest)) { return false; }
        string k = rest.Replace('\\', '/');

        // ① 精确匹配 (Z:\openjdk\bin\java.dll -> openjdk/bin/java.dll;
        //    Z:\minecraft\versions\x.json -> minecraft/versions/x.json)
        if (_entries.ContainsKey(k)) { return Get(k, out key, out isDir); }

        // ② 无顶层名的 Z: 路径 (Z:\bin\java.dll) -> openjdk/bin/java.dll
        if (_jdkPrefix.Length > 0 && !k.StartsWith(_jdkPrefix + "/", StringComparison.OrdinalIgnoreCase))
        {
            string k2 = _jdkPrefix + "/" + k;
            if (_entries.ContainsKey(k2)) { return Get(k2, out key, out isDir); }
        }
        return false;
    }

    private static bool Get(string key, out string outKey, out bool isDir)
    {
        Entry e = _entries[key];
        outKey = key;
        isDir = e.IsDir;
        return true;
    }

    /// <summary>容器条目是否存在 (键 = 相对 Minecraft 树根的正斜杠路径, 与 zip 条目一致;
    /// 容器激活时是唯一数据源)。</summary>
    public static bool HasEntry(string key)
    {
        return Active && _entries.ContainsKey(key);
    }

    // ------------------------------------------------------------------ 数据 API

    /// <summary>打开容器文件 (顺序读)。不存在返回 null。</summary>
    public static ContainerFile? OpenRead(string key)
    {
        if (!Active || !_entries.TryGetValue(key, out Entry e) || e.IsDir) { return null; }
        return new ContainerFile(key, e.Length);
    }

    /// <summary>条目长度 (字节)。</summary>
    public static long GetLength(string key)
    {
        if (!Active || !_entries.TryGetValue(key, out Entry e)) { throw new KeyNotFoundException($"容器缺条目: {key}"); }
        return e.Length;
    }

    /// <summary>是否存在 (文件)。</summary>
    public static bool HasFile(string key) => Active && _entries.ContainsKey(key) && !_dirs.ContainsKey(key);

    /// <summary>是否存在 (目录)。</summary>
    public static bool HasDir(string key) => Active && _dirs.ContainsKey(key);

    /// <summary>直接读映射内存: dest[0..dest.Length) <- 条目数据 [offset, offset+len)。越界抛异常。</summary>
    public static void ReadAt(string key, Span<byte> dest, long offset)
    {
        if (!Active) { throw new InvalidOperationException("容器未激活"); }
        Entry e = _entries[key];
        if (offset < 0 || offset + dest.Length > e.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), $"容器读越界: key={key} offset={offset} len={dest.Length} size={e.Length}");
        }
        long src = e.DataOffset + offset;
        fixed (byte* pd = dest)
        {
            Buffer.MemoryCopy(_base + src, pd, dest.Length, dest.Length);
        }
    }

    /// <summary>整文件读入 byte[] (小文件用, 如版本 json)。</summary>
    public static byte[] ReadAllBytes(string key)
    {
        long len = GetLength(key);
        var buf = new byte[len];
        ReadAt(key, buf, 0);
        return buf;
    }

    /// <summary>目录枚举: key 目录 (无尾斜杠; "" = Z: 根合成) 下的直接子条目。</summary>
    public static List<(string Name, bool IsDir, long Length)> EnumerateChildren(string key)
    {
        var list = new List<(string, bool, long)>();
        if (!Active) { return list; }
        if (key.Length == 0)
        {
            // Z: 根合成: 全部顶层目录 (容器条目第一段, 新分层含 openjdk 与 minecraft) + "minecraft" 别名。
            // PHASE12 修复: 此前误枚举 jdkPrefix 的【内部】子项 (bin/conf/lib/...), JVM
            // Path.toRealPath 逐组件在 Z:\ 根找不到 "openjdk" -> IOException
            // -> "Error loading java.security file" (Security.loadMaster 前置失败)。
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (string d in _dirs.Keys)
            {
                int slash = d.IndexOf('/');
                string top = slash < 0 ? d : d[..slash];
                if (top.Length > 0 && seen.Add(top))
                {
                    list.Add((top, true, 0));
                }
            }
            if (seen.Add("minecraft"))
            {
                list.Add(("minecraft", true, 0));
            }
            return list;
        }
        if (_children.TryGetValue(key, out var grp))
        {
            foreach (KeyValuePair<string, ChildInfo> kv in grp)
            {
                list.Add((kv.Key, kv.Value.IsDir, kv.Value.Length));
            }
        }
        return list;
    }

    /// <summary>目录键是否存在于容器 (隐式父目录也算)。</summary>
    public static bool IsDirKey(string key) => Active && _dirs.ContainsKey(key);

    /// <summary>目录键的条目数 (记录用)。</summary>
    public static int EntryCount => Active ? _entries.Count : 0;

    // ------------------------------------------------------------------ 顺序读文件句柄

    /// <summary>容器文件顺序读句柄 (OpenRead 返回; Read 推进游标)。</summary>
    public sealed class ContainerFile
    {
        private readonly string _key;
        private readonly long _length;
        private long _pos;

        internal ContainerFile(string key, long length)
        {
            _key = key;
            _length = length;
        }

        public long Length => _length;
        public long Position { get => _pos; set => _pos = value; }

        public int Read(Span<byte> dest)
        {
            long want = Math.Min(dest.Length, _length - _pos);
            if (want <= 0) { return 0; }
            ReadAt(_key, dest[..(int)want], _pos);
            _pos += want;
            return (int)want;
        }
    }

    // ------------------------------------------------------------------ JIT 安全预热

    /// <summary>
    /// 预热容器读取路径 (detour 安装前调用): 键推导各分支 + 全量读 + 目录枚举。
    /// 主工程 ReadFileToNative / TryMap 在 hook 栈上走这些路径, 必须提前编译。
    /// </summary>
    public static void Warmup(string restProbe, string keyProbe)
    {
        if (!Active) { return; }
        // 键推导分支 (PHASE13: minecraft 直映射 + jdk 前缀补全)
        _ = TryMapKey(restProbe, out _, out _);
        _ = TryMapKey(@"minecraft\assets\indexes\32.json", out _, out _);
        _ = TryMapKey(@"bin\server\jvm.dll", out _, out _);
        // 全量读 + 目录枚举
        if (_entries.TryGetValue(keyProbe, out Entry e) && !e.IsDir && e.Length > 0)
        {
            int chunk = (int)Math.Min(e.Length, 64 * 1024);
            var buf = new byte[chunk];
            ReadAt(keyProbe, buf, 0);
        }
        _ = EnumerateChildren("");
        foreach (string d in _dirs.Keys.Take(4)) { _ = EnumerateChildren(d); }
        _ = HasEntry("minecraft/versions/x.json");
        Console.WriteLine("[prejit] warmed container read/map paths");
    }

    // ------------------------------------------------------------------ 底层读映射

    private static byte* P(long off) => _base + off;

    private static uint ReadU32(long off)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(P(off), 4));
    }

    private static ushort ReadU16(long off)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(P(off), 2));
    }

    private static string ReadName(long off, int len)
    {
        return Encoding.UTF8.GetString(new ReadOnlySpan<byte>(P(off), len));
    }

    private static string? GetParent(string key)
    {
        int idx = key.LastIndexOf('/');
        return idx < 0 ? null : key[..idx];
    }

    // ------------------------------------------------------------------ P/Invoke

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x1;
    private const uint FILE_SHARE_WRITE = 0x2;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint PAGE_READONLY = 0x02;
    private const uint FILE_MAP_READ = 0x0004;
    private const int EocdBackScan = 64 * 1024;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetModuleFileNameW(IntPtr hModule, StringBuilder lpFilename, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateFileMappingW(IntPtr hFile, IntPtr lpAttributes, uint flProtect,
        uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern byte* MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess,
        uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

    private static string GetModuleFileNameW()
    {
        var sb = new StringBuilder(1024);
        int n = GetModuleFileNameW(IntPtr.Zero, sb, sb.Capacity);
        if (n == 0)
        {
            throw new InvalidOperationException($"GetModuleFileNameW failed win32={Marshal.GetLastWin32Error()}");
        }
        return sb.ToString();
    }

    /// <summary>尾部扫描 EOCD: 从文件尾回看最多 64KB+22 B, 匹配 0x06054b50 且
    /// commentLen == fileLen - eocdPos - 22 (即 EOCD 紧贴文件尾或带注释)。找不到返回 -1。</summary>
    private static long FindEocd(SafeFileHandle h, long fileLen)
    {
        long tailStart = Math.Max(0, fileLen - (EocdBackScan + EocdSize));
        long tailLen = fileLen - tailStart;
        // 必须先定位文件指针到 tailStart (ReadFile 从当前文件指针读, 默认 0 = 文件开头!)
        if (!SetFilePointerEx(h.DangerousGetHandle(), tailStart, IntPtr.Zero, FILE_BEGIN))
        {
            return -1;
        }
        byte[] tail = new byte[tailLen];
        bool ok = false;
        fixed (byte* p = tail)
        {
            uint total = 0;
            while (total < tailLen)
            {
                if (!ReadFile(h.DangerousGetHandle(), p + total, (uint)Math.Min(tailLen - total, 1 << 20), out uint r, IntPtr.Zero))
                {
                    break;
                }
                total += r;
                if (r == 0) { break; }
            }
            ok = total == tailLen;
        }
        if (!ok) { return -1; }
        for (long i = tailLen - EocdSize; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan((int)i, 4)) != SigEocd) { continue; }
            ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan((int)i + 20, 2));
            if (commentLen == fileLen - (tailStart + i) - EocdSize)
            {
                return tailStart + i;
            }
        }
        return -1;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern unsafe bool ReadFile(IntPtr hFile, byte* lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(IntPtr hFile, long liDistanceToMove, IntPtr lpNewFilePointer, uint dwMoveMethod);

    private const uint FILE_BEGIN = 0;
}
