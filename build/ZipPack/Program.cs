// ZipPack —— SingleFileMc 阶段 1 打包工具 (构建期工具, 不进主工程)。
//
// 职责:
//   pack    <srcRoot> <zipOut> <top1> [top2...]  —— 只打包 srcRoot 下指定的顶层目录,
//                                                   产出 **Store(不压缩)模式 zip**:
//                                                    - 条目路径 = 相对路径, 正斜杠 '/'
//                                                    - 所有 local header + central directory 的
//                                                      method 字段 == 0 (STORE)
//                                                    - 显式目录条目(结尾 '/', 便于运行时目录 stat)
//                                                    - 手工构造 zip 结构(不依赖 ZipArchive 的
//                                                      method 写入行为), 打包后立即自校验
//   append   <exeIn> <zipIn> <out>              —— exe 尾部追加 zip 字节, 产出单文件产物
//   verify   <zipIn>                            —— 原始字节校验: EOCD -> 中央目录 -> 每条目
//                                                   method==0 + local header method==0 + 偏移一致
//   deflate  <srcRoot> <zipOut> <top1>          —— 用 Deflate(压缩)打一个 zip(阶段 5 的
//                                                   "压缩 zip -> 报错" 分支测试用)
//
// 约定: 所有 zip 文件名按 UTF-8 写入(通用位 bit 11), 目录条目与文件条目都以 '/' 分隔。

using System.Buffers.Binary;
using System.Text;

namespace ZipPack;

internal static class Program
{
    // ---- zip 常量 ----
    private const uint SigLocal = 0x04034b50;
    private const uint SigCentral = 0x02014b50;
    private const uint SigEocd = 0x06054b50;
    private const ushort MethodStore = 0;
    private const ushort MethodDeflate = 8;
    private const ushort GpFlagUtf8 = 0x0800;

    private static int Main(string[] args)
    {
        try
        {
            if (args.Length < 1)
            {
                Usage();
                return 2;
            }
            string cmd = args[0];
            switch (cmd)
            {
                case "pack":
                {
                    Require(args, 3, "pack <srcRoot> <zipOut> <top1> [top2...]");
                    string src = Path.GetFullPath(args[1]);
                    string zipOut = Path.GetFullPath(args[2]);
                    string[] tops = args.Skip(3).ToArray();
                    if (tops.Length == 0) { throw new ArgumentException("pack: 至少一个顶层目录"); }
                    int n = PackStore(src, zipOut, tops, MethodStore);
                    Verify(zipOut, expectedCount: n);
                    Console.WriteLine($"[ZipPack] pack OK: {n} entries, all method=0 (Store), -> {zipOut}");
                    return 0;
                }
                case "deflate":
                {
                    Require(args, 3, "deflate <srcRoot> <zipOut> <top1>");
                    string src = Path.GetFullPath(args[1]);
                    string zipOut = Path.GetFullPath(args[2]);
                    int n = PackStore(src, zipOut, [args[3]], MethodDeflate);
                    Console.WriteLine($"[ZipPack] deflate OK: {n} entries compressed (method=8) -> {zipOut}");
                    return 0;
                }
                case "append":
                {
                    Require(args, 3, "append <exeIn> <zipIn> <out>");
                    string exe = Path.GetFullPath(args[1]);
                    string zip = Path.GetFullPath(args[2]);
                    string outp = Path.GetFullPath(args[3]);
                    long zLen = new FileInfo(zip).Length;
                    using (FileStream fs = new(outp, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        using (FileStream srcFs = new(exe, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            srcFs.CopyTo(fs);
                        }
                        using (FileStream zFs = new(zip, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            zFs.CopyTo(fs);
                        }
                    }
                    long exeLen = new FileInfo(exe).Length;
                    Console.WriteLine($"[ZipPack] append OK: {exeLen} B exe + {zLen} B zip = {new FileInfo(outp).Length} B -> {outp}");
                    return 0;
                }
                case "verify":
                {
                    Require(args, 1, "verify <zipIn>");
                    Verify(Path.GetFullPath(args[1]), expectedCount: null);
                    Console.WriteLine($"[ZipPack] verify OK: {Path.GetFullPath(args[1])}");
                    return 0;
                }
                default:
                    Console.Error.WriteLine($"ZipPack: unknown command '{cmd}'");
                    Usage();
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ZipPack] FAILED:\n{ex}");
            return 1;
        }
    }

    private static void Require(string[] args, int min, string usage)
    {
        if (args.Length <= min) { throw new ArgumentException($"用法: {usage}"); }
    }

    private static void Usage()
    {
        Console.WriteLine("用法:");
        Console.WriteLine("  ZipPack pack    <srcRoot> <zipOut> <top1> [top2...]  # Store zip");
        Console.WriteLine("  ZipPack deflate <srcRoot> <zipOut> <top1>             # Deflate zip(报错分支测试)");
        Console.WriteLine("  ZipPack append  <exeIn> <zipIn> <out>                 # zip 追加到 exe 尾部");
        Console.WriteLine("  ZipPack verify  <zipIn>                               # 校验全部条目 method==0");
    }

    /// <summary>
    /// 手工构造 zip: 目录条目(显式) + 文件条目, method 由参数指定 (Store=0 / Deflate=8)。
    /// 返回条目总数。文件名一律 UTF-8 + bit11。时间戳写 0(DOS epoch), 调用方不关心。
    /// </summary>
    private static int PackStore(string srcRoot, string zipOut, string[] tops, ushort method)
    {
        // 收集 (entryPath '/'-分隔, diskPath, isDir)
        var entries = new List<(string Entry, string Disk, bool IsDir)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string top in tops)
        {
            string topDisk = Path.Combine(srcRoot, top);
            if (!Directory.Exists(topDisk)) { throw new DirectoryNotFoundException($"顶层目录不存在: {topDisk}"); }
            AddTree(topDisk, top, entries, seen);
        }
        entries.Sort((a, b) => StringComparer.Ordinal.Compare(a.Entry, b.Entry));

        using FileStream fs = new(zipOut, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20);
        using BufferedStream w = new(fs, 1 << 20);

        var central = new List<(string Entry, bool IsDir, uint Crc, long LocalOffset, long Size)>();
        var crc = new Crc32();
        byte[] nameBuf = new byte[4096];
        byte[] hdr = new byte[30 + 46 + 4]; // local header 30 + central header 46

        foreach ((string entry, string disk, bool isDir) in entries)
        {
            long localStart = w.Position;
            uint crcVal = 0;
            long size = 0;
            if (!isDir)
            {
                using FileStream inFs = new(disk, FileMode.Open, FileAccess.Read, FileShare.Read);
                size = inFs.Length;
                crc.Reset();
                byte[] buf = new byte[1 << 20];
                int r;
                while ((r = inFs.Read(buf, 0, buf.Length)) > 0) { crc.Append(buf.AsSpan(0, r)); }
                crcVal = crc.Value;
            }

            int nameLen = WriteUtf8(entry, nameBuf);
            // ---- local file header (30 B) ----
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(0, 4), SigLocal);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(4, 2), 20);        // version needed
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(6, 2), GpFlagUtf8); // bit11: UTF-8 名
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(8, 2), method);     // method
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(10, 2), 0);         // mod time
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(12, 2), 0x21);      // mod date (1980-01-01)
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(14, 4), crcVal);
            long storeSize = size;
            byte[]? compressed = null;
            if (method == MethodDeflate && !isDir)
            {
                // Deflate 模式(仅报错分支测试用): 先压进内存拿到真实压缩大小再写头
                using var ms = new MemoryStream();
                using (var def = new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
                {
                    using FileStream inFs = new(disk, FileMode.Open, FileAccess.Read, FileShare.Read);
                    inFs.CopyTo(def);
                }
                compressed = ms.ToArray();
                storeSize = compressed.Length;
            }
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(18, 4), (uint)storeSize); // compressed size
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(22, 4), (uint)size); // uncompressed size
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(26, 2), (ushort)nameLen);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(28, 2), 0); // extra len
            w.Write(hdr.AsSpan(0, 30));
            w.Write(nameBuf.AsSpan(0, nameLen));

            if (!isDir)
            {
                if (method == MethodStore)
                {
                    using FileStream inFs = new(disk, FileMode.Open, FileAccess.Read, FileShare.Read);
                    byte[] buf = new byte[1 << 20];
                    int r;
                    while ((r = inFs.Read(buf, 0, buf.Length)) > 0) { w.Write(buf, 0, r); }
                }
                else
                {
                    w.Write(compressed!);
                }
            }
            central.Add((entry, isDir, crcVal, localStart, size));
        }

        long cdStart = w.Position;
        int count = 0;
        foreach ((string entry, bool isDir, uint crcVal, long localOffset, long size) in central)
        {
            int nameLen = WriteUtf8(entry, nameBuf);
            // ---- central directory header (46 B) ----
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(0, 4), SigCentral);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(4, 2), 20);        // version made by
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(6, 2), 20);        // version needed
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(8, 2), GpFlagUtf8);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(10, 2), method);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(12, 2), 0);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(14, 2), 0x21);
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(16, 4), crcVal);
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(20, 4), (uint)size);
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(24, 4), (uint)size);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(28, 2), (ushort)nameLen);
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(30, 2), 0); // extra
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(32, 2), 0); // comment
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(34, 2), 0); // disk
            BinaryPrimitives.WriteUInt16LittleEndian(hdr.AsSpan(36, 2), 0); // internal attrs
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(38, 4), isDir ? 0x10u : 0x20u); // external attrs
            BinaryPrimitives.WriteUInt32LittleEndian(hdr.AsSpan(42, 4), (uint)localOffset);
            w.Write(hdr.AsSpan(0, 46));
            w.Write(nameBuf.AsSpan(0, nameLen));
            count++;
        }
        long cdEnd = w.Position;

        // ---- EOCD (22 B), 无 comment ----
        byte[] eocd = new byte[22];
        BinaryPrimitives.WriteUInt32LittleEndian(eocd.AsSpan(0, 4), SigEocd);
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(4, 2), 0); // disk
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(6, 2), 0); // cd disk
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(8, 2), (ushort)count);
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(10, 2), (ushort)count);
        BinaryPrimitives.WriteUInt32LittleEndian(eocd.AsSpan(12, 4), (uint)(cdEnd - cdStart));
        BinaryPrimitives.WriteUInt32LittleEndian(eocd.AsSpan(16, 4), (uint)cdStart);
        BinaryPrimitives.WriteUInt16LittleEndian(eocd.AsSpan(20, 2), 0); // comment len
        w.Write(eocd);
        w.Flush();
        return count;
    }

    private static void AddTree(string diskDir, string entryPrefix, List<(string, string, bool)> entries, HashSet<string> seen)
    {
        // 显式目录条目(含顶层), 结尾 '/' 以区别于文件
        if (seen.Add(entryPrefix + "/"))
        {
            entries.Add((entryPrefix + "/", diskDir, true));
        }
        foreach (string dir in Directory.GetDirectories(diskDir).OrderBy(d => d, StringComparer.Ordinal))
        {
            AddTree(dir, entryPrefix + "/" + Path.GetFileName(dir), entries, seen);
        }
        foreach (string file in Directory.GetFiles(diskDir).OrderBy(f => f, StringComparer.Ordinal))
        {
            entries.Add((entryPrefix + "/" + Path.GetFileName(file), file, false));
        }
    }

    private static int WriteUtf8(string s, byte[] buf)
    {
        int n = Encoding.UTF8.GetBytes(s, buf);
        return n;
    }

    // ------------------------------------------------------------------ verify: 原始字节校验

    /// <summary>
    /// 从尾部定位 EOCD(校验 comment 长度), 解析中央目录, 逐条检查:
    /// 中央目录 method==0 + local header method==0 + 名称一致 + 偏移/大小范围合法。
    /// </summary>
    private static void Verify(string zipPath, int? expectedCount)
    {
        using FileStream fs = new(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        long len = fs.Length;
        if (len < 22) { throw new InvalidDataException($"文件过小({len} B), 不可能是 zip"); }

        // ---- 从文件尾向前找 EOCD (最多回看 64KB + 22) ----
        long eocdPos = FindEocd(fs, len);
        byte[] eocd = new byte[22];
        fs.Position = eocdPos;
        ReadExact(fs, eocd);
        int count = BinaryPrimitives.ReadUInt16LittleEndian(eocd.AsSpan(8, 2));
        long cdOffset = BinaryPrimitives.ReadUInt32LittleEndian(eocd.AsSpan(16, 4));
        long cdSize = BinaryPrimitives.ReadUInt32LittleEndian(eocd.AsSpan(12, 4));

        // ---- 中央目录 ----
        if (cdOffset + cdSize > len) { throw new InvalidDataException($"中央目录越界: off={cdOffset} size={cdSize} fileLen={len}"); }
        byte[] cd = new byte[cdSize];
        fs.Position = cdOffset;
        ReadExact(fs, cd);

        int n = 0;
        long pos = 0;
        var bad = new List<string>();
        while (pos + 46 <= cdSize)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(cd.AsSpan((int)pos, 4));
            if (sig != SigCentral) { throw new InvalidDataException($"中央目录第 {n} 条签名错误: 0x{sig:X8} @cd+{pos}"); }
            ushort method = BinaryPrimitives.ReadUInt16LittleEndian(cd.AsSpan((int)pos + 10, 2));
            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(cd.AsSpan((int)pos + 8, 2));
            uint csize = BinaryPrimitives.ReadUInt32LittleEndian(cd.AsSpan((int)pos + 20, 4));
            uint usize = BinaryPrimitives.ReadUInt32LittleEndian(cd.AsSpan((int)pos + 24, 4));
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(cd.AsSpan((int)pos + 28, 2));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(cd.AsSpan((int)pos + 30, 2));
            int commentLen = BinaryPrimitives.ReadUInt16LittleEndian(cd.AsSpan((int)pos + 32, 2));
            long localOff = BinaryPrimitives.ReadUInt32LittleEndian(cd.AsSpan((int)pos + 42, 4));
            if (method != MethodStore) { bad.Add($"条目@{n} method={method} (非 Store)"); }
            if (csize != usize && method == MethodStore) { bad.Add($"条目@{n} csize({csize})!=usize({usize})"); }
            string name = Encoding.UTF8.GetString(cd, (int)pos + 46, nameLen);

            // ---- 核对 local header ----
            if (localOff + 30 > len) { bad.Add($"条目'{name}' local 偏移越界 {localOff}"); }
            else
            {
                byte[] lh = new byte[30];
                fs.Position = localOff;
                ReadExact(fs, lh);
                uint lsig = BinaryPrimitives.ReadUInt32LittleEndian(lh.AsSpan(0, 4));
                ushort lmethod = BinaryPrimitives.ReadUInt16LittleEndian(lh.AsSpan(8, 2));
                int lnameLen = BinaryPrimitives.ReadUInt16LittleEndian(lh.AsSpan(26, 2));
                int lextraLen = BinaryPrimitives.ReadUInt16LittleEndian(lh.AsSpan(28, 2));
                if (lsig != SigLocal) { bad.Add($"条目'{name}' local 签名错误"); }
                if (lmethod != MethodStore) { bad.Add($"条目'{name}' local method={lmethod} (非 Store)"); }
                if (lnameLen != nameLen) { bad.Add($"条目'{name}' local/central 名称长度不一致"); }
                long dataLen = (flags & 0x8) != 0 ? usize : csize; // data descriptor 时以 central 为准
                _ = dataLen;
                if (localOff + 30 + lnameLen + lextraLen + usize > len) { bad.Add($"条目'{name}' 数据越界"); }
            }
            pos += 46 + nameLen + extraLen + commentLen;
            n++;
        }
        if (pos != cdSize) { throw new InvalidDataException($"中央目录尾部残留 {cdSize - pos} B"); }
        if (expectedCount is int ec && n != ec) { throw new InvalidDataException($"条目数不符: 期望 {ec}, 实际 {n}"); }
        Console.WriteLine($"[ZipPack] verify: EOCD@{eocdPos}, {n} entries, cdOffset={cdOffset} cdSize={cdSize}");
        if (bad.Count > 0)
        {
            Console.Error.WriteLine($"[ZipPack] verify FAILED ({bad.Count}):");
            foreach (string b in bad.Take(20)) { Console.Error.WriteLine("  - " + b); }
            throw new InvalidDataException($"zip 校验失败: {bad.Count} 个问题");
        }
    }

    private static long FindEocd(FileStream fs, long len)
    {
        long tailStart = Math.Max(0, len - (64L * 1024 + 22));
        long tailLen = len - tailStart;
        byte[] tail = new byte[tailLen];
        fs.Position = tailStart;
        ReadExact(fs, tail);
        for (long i = tailLen - 22; i >= 0; i--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(tail.AsSpan((int)i, 4)) != SigEocd) { continue; }
            ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(tail.AsSpan((int)i + 20, 2));
            if (commentLen == len - (tailStart + i) - 22) { return tailStart + i; }
        }
        throw new InvalidDataException("未找到 EOCD (0x06054b50)");
    }

    private static void ReadExact(FileStream fs, byte[] buf)
    {
        int off = 0;
        while (off < buf.Length)
        {
            int r = fs.Read(buf, off, buf.Length - off);
            if (r <= 0) { throw new EndOfStreamException(); }
            off += r;
        }
    }

    /// <summary>标准 CRC-32 (多项式 0xEDB88320), 用于 zip 头部 CRC 字段。</summary>
    private sealed class Crc32
    {
        private static readonly uint[] Table = BuildTable();
        private uint _crc = 0xFFFFFFFF;

        private static uint[] BuildTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                {
                    c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                }
                t[i] = c;
            }
            return t;
        }

        public void Reset() { _crc = 0xFFFFFFFF; }

        public void Append(ReadOnlySpan<byte> data)
        {
            foreach (byte b in data) { _crc = Table[(_crc ^ b) & 0xFF] ^ (_crc >> 8); }
        }

        public uint Value => _crc ^ 0xFFFFFFFF;
    }
}
