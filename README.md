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

...（后面保持原 README 内容不变，直到结尾）
