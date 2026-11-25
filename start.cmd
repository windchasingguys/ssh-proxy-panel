@echo off
rem ===================================================================
rem  SSH 隧道面板 —— Windows 快速启动
rem  双击本文件：最小化窗口启动面板，并自动打开浏览器。
rem  想要"开机就挂着、永不弹窗"，请用 scripts\install-autostart.ps1
rem  注册登录自启计划任务（隐藏运行）。
rem ===================================================================
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo 找不到 node，请先安装 Node.js 18 或更高版本： https://nodejs.org/
  pause
  exit /b 1
)

if not exist "tunnels.json" (
  echo 还没有 tunnels.json，先生成一份示例配置...
  node "src\cli.mjs" init
  echo.
  echo 请编辑 tunnels.json 里的 via / target 后再启动。
  notepad "tunnels.json"
  exit /b 0
)

start "ssh-proxy-panel" /min node "src\cli.mjs" serve --config "tunnels.json" --open %*
exit /b 0
