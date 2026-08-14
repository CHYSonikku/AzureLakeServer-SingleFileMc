# Azure Lake Server - SingleFileMc 适配版

> 本仓库是 [FrostyTwilight/SingleFileMc](https://github.com/FrostyTwilight/SingleFileMc) 的 **GPL v3 协议 Fork**，专为 **Azure Lake Server** 的 Minecraft 1.21.11 Fabric 整合包定制。

## 🎯 与原项目的主要区别

- **Java 版本**：从 Java 25 改为 **Java 21**（兼容 1.21.11 及其模组）
- **JVM 参数**：移除 `-XX:+UseCompactObjectHeaders`、`-XX:+UseZGC` 等 Java 21 不支持的选项，改用 `-XX:+UseG1GC`
- **主类**：从原版客户端改为 Fabric 加载器入口 `net.fabricmc.loader.impl.launch.knot.KnotClient`
- **游戏内容**：替换为完整的 Azure Lake Server 整合包（包含 51 个模组及预配置）
- **路径处理**：使用相对路径，支持将 exe 放在任意盘符运行，存档 / 配置 / mods 全部保存在 exe 同级目录，**不写 C 盘**

## 📜 许可证

本 Fork 遵循 **GNU General Public License v3.0** 协议，与原项目一致。  
- 原项目：[FrostyTwilight/SingleFileMc](https://github.com/FrostyTwilight/SingleFileMc)  
- 原项目协议：GPL v3

---

以下为原项目 README 内容（未做实质性改动，仅保留以供参考）：

# SingleFileMc：单文件 Minecraft 启动器

> 一个约 1.07 GB 的单 exe 启动器：双击即玩，不解压、零驱动、零管理员、零外部依赖，
> 直接运行 **Minecraft 26.2-NeoForge_26.2.0.45-beta**（离线单机）。

`artifacts\SingleFileMc.exe` = **~3.4 MiB NativeAOT 宿主** + **~1.06 GB 尾部 Store zip 容器**。
核心是纯用户态 `ntdll` hook 虚拟文件系统（`Z:\` 虚拟根、假句柄表、假 `SEC_IMAGE` 内存加载
`jvm.dll`）+ JNI 进程内 JVM + 容器 mmap 手动解析 zip。

---

## 目录

- [项目简介](#项目简介)
- [快速开始](#快速开始)
- [技术架构](#技术架构)
- [构建](#构建)
- [目录结构](#目录结构)
- [已知限制与设计取舍](#已知限制与设计取舍)
- [许可证](#许可证)

---

## 项目简介

SingleFileMc 把整套 Minecraft + NeoForge + JDK 数据树（约 1.06 GB）打进启动器 exe 的尾部
zip 容器里。运行时不做任何解压：宿主通过 mmap 直接把 exe 尾部的 zip 当作数据源，再用
`ntdll` hook 把 JVM 与游戏对文件系统的所有访问引导到一个虚拟的 `Z:\` 根上，由容器按偏移
直接提供文件内容。没有驱动、没有提权、没有临时解压目录、没有真实盘符。

关键特性：

- **单文件交付**：只分发 `SingleFileMc.exe` 一个文件。
- **零解压**：容器内条目全部 Store（不压缩），运行时 mmap 按偏移直读，不落地。
- **零驱动 / 零管理员**：全部是纯用户态 ntdll hook，无内核组件、无需 UAC。
- **零外部依赖**：NativeAOT 发布 + `sfmc_hooks_static.lib` 静态链接，exe 之外没有任何 dll。
- **离线单机**：无微软账号登录；用户名取自 exe 文件名（默认 `SingleFileMc.exe` 显示
  "SingleFileMc"，重命名 exe 即可改名）。
- **存档持久**：gameDir 是真实可写目录，存档 / 配置 / mods 持久保存。

环境基线：Windows 11 26100，.NET 10，x64。

---

## 快速开始

1. 双击 `artifacts\SingleFileMc.exe`（或在 `artifacts\` 目录内执行）。
2. 进程会先启动 JVM，然后拉起 Minecraft，等待主菜单窗口出现。
3. 关闭游戏窗口后进程退出（详见[已知限制与设计取舍](#已知限制与设计取舍)）。

启动后生成：

- `artifacts\game\`：gameDir（真实、可写、持久）。`saves\` 存档、`mods\`、
  `config\`、`resourcepacks\` 都在这。**mods 放 `artifacts\game\mods\` 即可加载。**
- `artifacts\logs\`：游戏日志。
- natives 虚拟化：JVM natives 全部位于虚拟 `Z:\cache\natives\`（内存，不落盘），
  真实 `artifacts\game\cache` 零 natives。

### 调试环境变量

| 变量 | 取值 | 作用 |
|---|---|---|
| `SFMC_VERBOSE_HOOKS` | `1` / `true` | 开启 ntdll hook 全量日志（默认关闭，避免刷屏） |

---

## 技术架构

### 总体数据流

```
双击 SingleFileMc.exe
   │
   ├─ 1. Container.Init()        最早期 mmap 自身 exe，尾部扫描 EOCD，解析中央目录，
   │                             Store 校验，建虚拟目录表（不落盘）
   ├─ 2. JIT-safety 预热          在第一个 detour 安装前编译全部热路径
   │                             （回退/启动链/PE 镜像布局/JNI delegate）
   ├─ 3. FakeFileSystem.Init()   安装 19 个 ntdll hook（MinHook.NET 原生 detour）
   ├─ 4. JNI_CreateJavaVM        进程内创建 JVM；jvm.dll 优先真实磁盘加载，
   │                             缺失时经假 SEC_IMAGE 从容器内存加载
   └─ 5. McLaunch.Run()          解析版本 json → 构建 Z:\ 类路径 → natives 虚拟化到
                                 Z:\cache\natives → gameDir 就绪 → Client.main(String[])
                                 → 等待主菜单
```

### 尾部 zip 容器（`Container.cs`）

- 宿主最早期 `CreateFileMappingW + MapViewOfFile` 把整个 exe 映射进内存（只读）。
- 从文件尾回看最多 64 KB + 22 B 扫描 EOCD（`0x06054b50`），校验 commentLen 与文件尾
  距离一致才接受。
- 手动解析中央目录，建立条目表。zip 顶层只有两棵：`openjdk/` 与 `minecraft/`
  （打包时由 `Minecraft/` 数据树映射，见[构建](#构建)）。
- **Store 校验**：任何条目 `method != 0` 或 `compSize != uncompSize` 都视为容器损坏，
  打印错误并以退出码 **100** 拒绝启动。运行时不做任何解压，全部按偏移直读。
- 损坏到无法解析时以退出码 **101** 退出。

### ntdll hook 虚拟文件系统（`FakeFileSystem.cs` + `native_hooks/`）

19 个 hook，分五组：

| 组 | Hook |
|---|---|
| 文件 | `NtCreateFile` `NtOpenFile` `NtReadFile` `NtClose` `NtQueryInformationFile` `NtQueryAttributesFile` `NtQueryFullAttributesFile` `NtQueryVolumeInformationFile` `NtSetInformationFile` |
| 映射 | `NtCreateSection` `NtMapViewOfSection` `NtUnmapViewOfSection` `NtQuerySection` |
| 目录枚举 | `NtQueryDirectoryFile` `NtQueryDirectoryFileEx` |
| 句柄 | `NtDuplicateObject` |
| 写入与锁 | `NtWriteFile` `NtLockFile` `NtUnlockFile` |

（`NtDuplicateObject` 保留在句柄组；写入与锁组为 PHASE18 新增，服务虚拟 natives 区。）

关键机制：

- **`Z:\` 虚拟根**：JVM 与游戏的路径访问被改写到 `Z:\openjdk\...`、`Z:\minecraft\...`，
  由容器条目表直接服务；无容器时回退 exe 旁的磁盘别名（仅调试用）。
- **假句柄表**：`NtCreateFile`/`NtOpenFile` 对容器内文件与虚拟 natives 文件返回伪造句柄
  （文件 `0x5100xxxx`、section `0x52000000|n`），真实句柄一律放行到原 trampoline。
- **虚拟可写区（PHASE18）**：仅 `Z:\cache\natives\` 子树可写，natives 提取与运行期
  JNA/LWJGL/Netty 写入全走内存虚拟文件表（经 `NtWriteFile` hook），其余 `Z:\` 保持只读；
  可写句柄拒读、只读句柄拒写（句柄级 + 文件级互斥）。
- **假 `SEC_IMAGE`**：`NtCreateSection` / `NtMapViewOfSection` 对容器内 PE 文件
  （如 `jvm.dll`）做纯托管 PE32+ 解析 + 手工镜像布局，内存里按节加载，不落盘。
- **JNI 进程内 JVM**：加载 `jvm.dll` → `JNI_CreateJavaVM` → 在宿主进程内直接跑
  Minecraft。类路径全部是 `Z:\...` 虚拟路径，经 hook 由容器提供字节。
- **native 守卫 stub**（`native_hooks/`，C）：每个 hook 有一个 `Stub_*` 前置分流，
  只在命中假句柄 / `Z:\` 路径时才进托管，GC 内部的 ntdll 调用不经过托管 hook；
  `Suppress` 计数防重入。

### NativeAOT 与 native 守卫库

- 宿主以 `dotnet publish -c Release -r win-x64`（`<PublishAot>true</PublishAot>`）发布为
  纯原生单 exe，运行时零 JIT。
- native 守卫库以 `sfmc_hooks_static.lib` 通过 `<DirectPInvoke Include="__Internal">`
  + `<NativeLibrary>` **静态链接**进 exe，`LibraryImport("__Internal")` 符号由链接器直接
  解析，运行时不再 LoadLibrary。这是"零外部依赖"的根基。
- JIT 调试模式（`Build` target）则使用 `sfmc_hooks_shared.dll` 动态加载。
- MinHook 用嵌入的**修改后 MinHook.NET**（新增 `CreateHook(IntPtr, IntPtr)` 原生 detour
  重载），见 `third_party/Minhook.NET/`（BSD-3）。

### 退出码

| 码 | 含义 |
|---|---|
| `0` | 检测到游戏窗口（主菜单在渲染；watchdog 激活路径） |
| `3` | 游戏自行退出（当前实际路径，见限制） |
| `42` | watchdog 超时（180 s 未检测到窗口） |
| `100` | 容器含非 Store 条目，拒绝启动 |
| `101` | 容器 zip 结构损坏 / 解析失败 |

---

## 构建

### 前置条件

- **.NET 10 SDK**（csproj 目标 `net10.0`，NativeAOT publish）
- **cmake**（PATH 中，或 VS 内置 CMake）
- **Visual Studio 构建工具**（MSVC，编译 native_hooks 与 AOT link）

### NUKE 管线（`build.ps1` → `build/Build.cs`）

| Target | 作用 |
|---|---|
| `Build` | `dotnet build -p:PublishAot=false` 主工程，**JIT 调试链路**，不参与交付 |
| `Native` | `cmake --build native_hooks/build` 产 `sfmc_hooks_shared.dll` |
| `Pack` | `Minecraft/` 数据树 → `artifacts\container.zip`（全 Store 不压缩） |
| `Publish` | `dotnet publish -c Release -r win-x64` 产 NativeAOT 单 exe |
| `Append` | **最终交付**：`Publish` + `Pack` 后，把 zip 追加到 AOT exe 尾部 |

主命令：

```powershell
# 完整交付：Publish AOT + Pack 容器 + Append 尾部拼接 -> artifacts\SingleFileMc.exe
.\build.ps1 Append

# 仅 JIT 调试构建（容器验证链路）
.\build.ps1 Build

# 仅编译 native 守卫库
.\build.ps1 Native

# 帮助
.\build.ps1 --help
```

首次构建顺序（native 静态库是 AOT 链接的硬依赖）：

```powershell
cmake -S native_hooks -B native_hooks/build     # 先配置一次（生成 sfmc_hooks_static.lib 目标）
.\build.ps1 Native
.\build.ps1 Append
```

### 打包映射规则（`Pack`）

源数据树 `SingleFileMc\Minecraft\`：

```
.minecraft\…            ->  zip 顶层 minecraft\…
<jdk顶层>\…             ->  zip 顶层 openjdk\…   （jdk 顶层动态发现：含 bin/server/jvm.dll）
PCL\ 与 Plain Craft Launcher 2.exe 等         ->  排除
```

容器 zip 顶层只有 `openjdk/` 与 `minecraft/`，未知顶层目录直接报错，防止静默丢数据。

---

## 目录结构

```
SingleFileMc/
├─ build.ps1                     # NUKE 构建引导脚本
├─ LICENSE                       # GNU GPL v3（主工程 + native 守卫库）
├─ SingleFileMc.slnx             # 解决方案
├─ SingleFileMc/                 # 宿主主工程（net10.0 / NativeAOT）
│  ├─ Program.cs                 # 入口：容器 Init -> 预热 -> hook 安装 -> JNI -> MC 启动
│  ├─ Container.cs               # 尾部 zip 容器：mmap + EOCD + 手动解析 + Store 校验
│  ├─ FakeFileSystem.cs          # ntdll hook VFS：Z:\ + 假句柄 + 假 SEC_IMAGE + 19 hooks
│  ├─ McLaunch.cs                # 启动链：版本 json -> 类路径 -> natives 虚拟化 -> Client.main
│  ├─ Minecraft/                 # 游戏数据树（打包进容器；.minecraft/ 与 jdk-25.0.4.7-hotspot/）
│  └─ TestFS/                    # VFS 相关测试
├─ native_hooks/                 # C 守卫 stub 库（CMake）
│  └─ src/ntdll_hooks.c          # Stub_* 前置分流 + Suppress + SetCallbacks 绑定
├─ build/                        # NUKE 构建管线（Build.cs）
├─ third_party/Minhook.NET/      # 嵌入的修改后 MinHook.NET（BSD-3，含 LICENSE）
├─ artifacts/                    # 交付物 + gameDir
│  ├─ SingleFileMc.exe           # 最终交付物（AOT 宿主 + 尾部 zip）
│  ├─ container.zip              # 打包中间产物
│  └─ game/                      # gameDir（存档 / mods / config 持久）
├─ .omo/docs/PHASE*.md           # 阶段演进文档（见下）
├─ tools/                        # spike 验证工程（spike-jvm / spike-secimage 等）
├─ docs/spike-results.md         # spike 结论汇总
└─ logs/                         # 运行日志
```

---

## 已知限制与设计取舍

- **gameDir 是真实目录**：存档/配置持久保存是特性；但**容器内打包的 mods 不会自动进入
  gameDir**，要装 mod 请直接放进 `artifacts\game\mods\`。
- **natives 已完全虚拟化**（PHASE18）：natives 提取与运行期 JNA/LWJGL/Netty 写入全走虚拟
  `Z:\cache\natives\` 内存区（提取直写 + 运行期经 `NtWriteFile` hook；LoadLibrary 从虚拟区
  经假 SEC_IMAGE 加载），真实 `game\cache` 零 natives、`%TEMP%` 零残留。仅该子树可写，
  其余 `Z:\` 只读；可写句柄拒读、只读句柄拒写（句柄级 + 文件级互斥）。
- **JNA `File.createTempFile` 在虚拟区不可用**（PHASE18 已知限制）：MS JDK 25 的临时文件
  创建链绕过部分 detour，仅造成 SystemReport/OSHI 路径的 log4j WARN（装饰性，非致命），
  游戏照常启动到主菜单。
- **离线单机**：Realms 登录、微软账号、多人联机登录均不可用；离线身份由 exe 文件名决定。
- **watchdog 当前被注释**（`McLaunch.cs` 中 `t.Start()` 被注释）：处于手动测试模式，
  进程持续到玩家关闭游戏窗口，之后以退出码 **3** 结束；窗口检测 / 超时路径（0 / 42）
  逻辑保留，恢复后即可自动退出。
- **固定 x64 / Windows**：无跨平台、无 32 位支持。
- **体积即成本**：全 Store 不压缩是"零解压"的前提，代价是容器大小 ≈ 原始数据树。

---

## 许可证

- **主工程**（`SingleFileMc/` 宿主）+ **native 守卫库**（`native_hooks/`）：**GNU GPL v3**，
  全文见根目录 `LICENSE`。
- **嵌入的第三方库**保持各自许可：**MinHook.NET**（`third_party/Minhook.NET/`）为 BSD-3，
  许可证保留于 `third_party/Minhook.NET/LICENSE`（BSD-3 与 GPL-3.0 兼容，GPL 项目可包含
  BSD 组件）。

分发 / 修改本项目请遵守 GPL-3.0 条款，参见 [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.txt)。
