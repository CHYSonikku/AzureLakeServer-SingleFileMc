# SingleFileMc NUKE 引导脚本 (Windows)。
# 用法:
#   .\build.ps1 --help        # 列出全部 Targets
#   .\build.ps1 Build         # 构建主工程
#   .\build.ps1 Native        # cmake 构建 native_hooks
#   .\build.ps1 Pack          # Minecraft/ -> container.zip (Store)
#   .\build.ps1 Append        # exe 尾部追加 zip (依赖 Build + Pack)
#   .\build.ps1 Publish       # NativeAOT 占位
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Join-Path $root "build\_build.csproj"

if (-not (Test-Path $proj)) {
    Write-Error "找不到 NUKE 构建工程: $proj"
    exit 1
}

& dotnet run --project $proj -- $args
exit $LASTEXITCODE
