# 卸载「登录后自动启动 SSH 隧道面板」计划任务
$ErrorActionPreference = 'Stop'
$taskName = 'SshProxyPanel'

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  Write-Host "已删除计划任务: $taskName"
} else {
  Write-Host "没有找到计划任务: $taskName"
}
