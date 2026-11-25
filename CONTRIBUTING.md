# 参与贡献

欢迎 issue 和 PR。这个项目刻意保持"零运行时依赖"：`src/` 只用 Node 内置模块，`public/` 是纯静态文件，
不要为了一个小功能引入框架。

## 本地开发

```bash
node --version            # 需要 ≥ 18
node src/cli.mjs init     # 生成 tunnels.json
node src/cli.mjs serve --open
```

只有**打包 exe** 才需要装依赖（esbuild / postject）：

```bash
npm install
node scripts/build-exe.mjs --no-zip
```

## 跑测试

不需要真实 SSH 服务器——`test/fake-ssh.mjs` 会扮演 ssh，还会校验 `SSH_ASKPASS` 递过来的密码。

```bash
node test/smoke.mjs        # 97 项端到端：起停/自愈/退避/端口占用/孤儿回收/配置增删改/登录/密钥/隧道密码
```

UI 检查需要本机有 Chrome 或 Edge：

```bash
node test/demo-config.mjs
node src/cli.mjs serve --config .tmp-demo/tunnels.json --port 7799
node test/ui-check.mjs --url http://127.0.0.1:7799/ --allow-write
```

**改完请至少让 `smoke` 全绿**；动了 `public/` 或登录流程再跑一遍 `ui-check`。

## 代码约定

- 注释和用户可见文案用中文；变量/函数名用英文。
- 每个模块职责单一，别让 `server.mjs` 直接操作配置文件——写配置走 `config-writer.mjs`。
- 涉及凭据的地方：**任何情况下都不要把密码写进日志、命令行参数或 `runtime.json`**。
- 提交信息用 Conventional Commits 前缀：

```
feat:     新功能        fix:     修 bug
refactor: 不改行为的整理  docs:    文档
test:     测试          build:   打包/依赖
chore:    杂务
```

## 别提交这些

`tunnels.json`、`.ssh-proxy/`、`dist/`、`node_modules/` 已在 `.gitignore` 里。
提交前可以用 `git status` 确认一下；真实主机地址请一律换成 `edge.example.com` / `10.0.0.x`。

## 安全相关

发现了安全问题请走私密渠道，见 [SECURITY.md](SECURITY.md)。
