# 安全策略

这个工具会经手 SSH 凭据，所以安全相关的问题请**私下**报，不要开公开 issue。

## 怎么报

- 用 GitHub 的 [Private vulnerability reporting](https://docs.github.com/zh/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  （仓库 → Security → Report a vulnerability），或
- 给维护者发邮件（见仓库 commit 署名）。

请说明：影响版本、复现步骤、你判断的后果。**不要**附真实的主机地址、私钥或密码——用 `edge.example.com` 这类占位符代替。

## 设计上已经做了什么

| 面 | 处理方式 |
|---|---|
| 面板监听 | 默认只绑 `127.0.0.1`，不对外 |
| 面板登录 | 令牌 / scrypt 密码哈希 / Ed25519 公钥签名（挑战 2 分钟、一次性） |
| 会话 | HttpOnly + SameSite=Strict Cookie，绝对到期 + 闲置超时，可退出，输错 5 次锁 30 秒 |
| CSRF | 状态变更请求校验 `Origin` 与 `Host` 一致 |
| 隧道密码 | 静态加密（AES-256-GCM，密钥在 `.ssh-proxy/secret.key`），或只放内存（"连接时输入"） |
| 凭据传递 | 走 `SSH_ASKPASS`，不进命令行参数、不进日志 |
| 仓库 | `tunnels.json`、`.ssh-proxy/`（含加密密钥）在 `.gitignore` 里，从不入库 |

## 已知的边界（不算漏洞）

- **能读你用户目录的人本来就赢**：`.ssh-proxy/secret.key` 能解密存下来的隧道密码；本机同用户进程也能读环境变量里的临时凭据。
  需要更强隔离时，用"连接时输入"或改用密钥登录。
- **面板自身不是堡垒**：它是本机工具。要暴露到别的机器，请套 SSH 隧道 / Tailscale / WireGuard，并配上强凭据。
- **SSH 私钥口令**在内存与子进程环境里短暂出现（`ssh` 需要它）；这条路径无法用纯 Node 完全避免。

## 支持范围

只维护最新版本。Windows 打包产物由 GitHub Actions 在 tag 上构建。
