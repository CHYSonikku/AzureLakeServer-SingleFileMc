# ============================================================================
#  sfmc_hooks — SingleFileMc native 守卫 stub 库
#
#  产物:
#    sfmc_hooks_shared.dll/.lib  (SHARED) — 非 AOT 测试模式, 托管层 NativeLibrary.Load
#    sfmc_hooks_static.lib        (STATIC) — NativeAOT linker 消费(随 exe 静态链入)
#
#  说明: 本库不集成 MinHook 安装; patch 由托管层(修改后 MinHook.NET)执行,
#  本库仅提供 detour 目标(Stub_*) + Suppress 守卫 + SetCallbacks 绑定。
# ============================================================================
cmake_minimum_required(VERSION 3.20)
project(sfmc_hooks C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SFMC_SOURCES src/ntdll_hooks.c)

# ---- shared: 测试模式(托管层按名加载) ----
add_library(sfmc_hooks_shared SHARED ${SFMC_SOURCES})
target_include_directories(sfmc_hooks_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(sfmc_hooks_shared PRIVATE SFMC_BUILD_SHARED)
# 源码含 UTF-8 中文注释: MSVC 强制按 UTF-8 读取(消除 C4819)
target_compile_options(sfmc_hooks_shared PRIVATE $<$<C_COMPILER_ID:MSVC>:/utf-8>)
set_target_properties(sfmc_hooks_shared PROPERTIES
    OUTPUT_NAME sfmc_hooks_shared
    PREFIX "")

# ---- static: NativeAOT linker 消费 ----
add_library(sfmc_hooks_static STATIC ${SFMC_SOURCES})
target_include_directories(sfmc_hooks_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(sfmc_hooks_static PRIVATE $<$<C_COMPILER_ID:MSVC>:/utf-8>)
set_target_properties(sfmc_hooks_static PROPERTIES
    OUTPUT_NAME sfmc_hooks_static)
