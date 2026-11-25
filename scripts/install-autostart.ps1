# 注册「登录后自动启动 SSH 隧道面板」计划任务（Windows，当前用户，无需管理员）
#
# 用法（在项目根目录）：
#   powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1
# 卸载：
#   powershell -ExecutionPolicy Bypass -File scripts\uninstall-autostart.ps1

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$cli = Join-Path $root 'src\cli.mjs'
$config = Join-Path $root 'tunnels.json'
$taskName = 'SshProxyPanel'

if (-not (Test-Path $cli)) { throw "找不到 $cli，请在项目目录内运行本脚本" }

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { throw '找不到 node，请先安装 Node.js 18+' }

if (-not (Test-Path $config)) {
  Write-Warning "还没创建 $config"
  Write-Warning "先执行: node src\cli.mjs init  然后按需修改 via / target"
}

$action = New-ScheduledTaskAction -Execute $node `
  -Argument "`"$cli`" serve --config `"$config`" --quiet" `
  -WorkingDirectory $root

$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -ExecutionTimeLimit ([TimeSpan]::Zero) `
  -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
  -Description 'SSH -N -L 隧道面板：登录后常驻，托盘无窗口，浏览器打开 http://127.0.0.1:7788' -Force | Out-Null

Start-ScheduledTask -TaskName $taskName

Write-Host "已注册计划任务: $taskName"
Write-Host "  命令: $node `"$cli`" serve --config `"$config`" --quiet"
Write-Host "  工作目录: $root"
Write-Host "  面板地址: http://127.0.0.1:7788/"
Write-Host ""
Write-Host "提示：把 http://127.0.0.1:7788/ 存成浏览器书签，以后点开就能开关隧道。"
Write-Host "立即停止: Stop-ScheduledTask -TaskName $taskName"
