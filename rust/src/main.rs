//! 入口（对应 `src/cli.mjs`）。
//!
//! 里程碑 M4b：`serve` + 15 个子命令（status/up/down/restart/logs/cmd/secret/reload/init/auth/passwd/addkey/rmkey/version/help）。
//! 还剩 M5：把 Rust core 换进 C# 托盘壳、`--prepare` 自检、CI 改造。

mod auth;
mod cli;
mod config;
mod config_writer;
mod http;
mod secrets;
mod session;
mod ssh;
mod supervisor;
mod util;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use supervisor::Supervisor;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_CONFIG_FILE: &str = config::DEFAULT_CONFIG_FILE;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // ssh 要密码时会执行 `ssh-proxy --askpass`（askpass 小帮手），这里最先处理，别做别的事
    if argv.iter().any(|a| a == "--askpass") {
        let secret = std::env::var("SSHPROXY_SSH_SECRET").unwrap_or_default();
        if secret.is_empty() {
            eprintln!("ssh-proxy: 没有可用的凭据（SSHPROXY_SSH_SECRET 为空）");
            return ExitCode::FAILURE;
        }
        println!("{}", secret);
        return ExitCode::SUCCESS;
    }

    match run(&argv) {
        Ok(code) => {
            if code == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("错误: {}", err);
            ExitCode::FAILURE
        }
    }
}

struct Flags {
    config_file: String,
    /// 命令行是否显式给了 --config（JS 的 `flags.config || positional[1]` 优先级靠它）
    config_given: bool,
    host: Option<String>,
    port: Option<u16>,
    token: Option<String>,
    open: bool,
    quiet: bool,
    self_check: bool,
    name: Option<String>,
    file: Option<String>,
    key: Option<String>,
    clear: bool,
    target: Option<String>,
    help: bool,
    positional: Vec<String>,
}

fn parse_args(argv: &[String]) -> Result<Flags, String> {
    let mut flags = Flags {
        config_file: DEFAULT_CONFIG_FILE.to_string(),
        config_given: false,
        host: None,
        port: None,
        token: None,
        open: false,
        quiet: false,
        self_check: false,
        name: None,
        file: None,
        key: None,
        clear: false,
        target: None,
        help: false,
        positional: Vec::new(),
    };

    let mut i = 0;
    while i < argv.len() {
        let item = &argv[i];
        if let Some(rest) = item.strip_prefix("--") {
            let (key, inline) = match rest.split_once('=') {
                Some((k, v)) => (k, Some(v.to_string())),
                None => (rest, None),
            };
            // 与 JS 的 parseArgs 一致：`--k v` 只在下一个参数不以 '-' 开头时取值
            let take = |i: &mut usize| -> Option<String> {
                if let Some(v) = &inline {
                    return Some(v.clone());
                }
                if let Some(next) = argv.get(*i + 1) {
                    if !next.starts_with('-') {
                        *i += 1;
                        return Some(next.clone());
                    }
                }
                None
            };
            match key {
                "config" => {
                    if let Some(v) = take(&mut i) {
                        flags.config_file = v;
                        flags.config_given = true;
                    }
                }
                "host" => flags.host = take(&mut i),
                "port" => {
                    if let Some(v) = take(&mut i) {
                        flags.port = Some(v.parse().map_err(|_| {
                            format!("--port 必须是 1-65535 的整数，当前为: {}", v)
                        })?);
                    }
                }
                "token" => flags.token = take(&mut i),
                "name" => flags.name = take(&mut i),
                "file" => flags.file = take(&mut i),
                "key" => flags.key = take(&mut i),
                "target" => flags.target = take(&mut i),
                "open" => flags.open = true,
                "quiet" => flags.quiet = true,
                "self-check" => flags.self_check = true,
                "clear" => flags.clear = true,
                "help" => flags.help = true,
                _ => {}
            }
        } else {
            flags.positional.push(item.clone());
        }
        i += 1;
    }
    Ok(flags)
}

fn run(argv: &[String]) -> Result<i32, String> {
    let flags = parse_args(argv)?;
    let command = flags
        .positional
        .first()
        .cloned()
        .unwrap_or_else(|| "serve".to_string());

    if command == "version" {
        println!("ssh-proxy-panel {}", VERSION);
        return Ok(0);
    }
    if command == "help" || flags.help {
        print_help();
        return Ok(0);
    }
    if command == "init" {
        let target = flags
            .target
            .clone()
            .or_else(|| flags.positional.get(1).cloned())
            .unwrap_or_else(|| flags.config_file.clone());
        return cli::init(&target);
    }

    // 与 JS 的 `flags.config || positional[1] || DEFAULT` 一致：
    // 显式 --config 优先；否则子命令的第二个位置参数会被当成配置文件名（既有约定，照搬）
    let config_file = if flags.config_given {
        flags.config_file.clone()
    } else {
        flags
            .positional
            .get(1)
            .cloned()
            .unwrap_or_else(|| DEFAULT_CONFIG_FILE.to_string())
    };
    let mut config = config::load_config(&config_file)?;
    if let Some(port) = flags.port {
        config.panel.port = port;
    }
    if let Some(host) = &flags.host {
        config.panel.host = host.clone();
    }
    if let Some(token) = &flags.token {
        config.panel.token = token.trim().to_string();
        config.panel.token_source = "cli".to_string();
        if !config.panel.auth_methods.iter().any(|m| m == "token") {
            config.panel.auth_methods.push("token".to_string());
        }
    }

    // ---- 登录凭据管理（直接改文件，重启面板后生效）
    if command == "auth" {
        cli::auth(&config);
        return Ok(0);
    }
    if command == "passwd" {
        let file = std::path::absolute(&config_file)
            .unwrap_or_else(|_| PathBuf::from(&config_file));
        return cli::passwd(&file, flags.clear, std::env::var("SSH_PROXY_PASSWORD").ok());
    }
    if command == "addkey" {
        let file = std::path::absolute(&config_file)
            .unwrap_or_else(|_| PathBuf::from(&config_file));
        return cli::add_key(
            &file,
            flags.name.clone(),
            flags.key.clone(),
            flags.file.clone(),
            flags.positional.get(1).cloned(),
        );
    }
    if command == "rmkey" {
        let file = std::path::absolute(&config_file)
            .unwrap_or_else(|_| PathBuf::from(&config_file));
        return cli::remove_key(&file, flags.positional.get(1).cloned());
    }

    if command != "serve" {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("初始化 tokio 运行时失败: {}", e))?;
        let secret_env = std::env::var("SSH_PROXY_TUNNEL_SECRET").ok();
        return runtime.block_on(cli::http_command(
            &command,
            &config,
            &flags.positional,
            secret_env,
        ));
    }

    serve(config, flags)
}

fn print_help() {
    println!(
        "ssh-proxy — 本地 SSH -N -L 隧道面板（Rust 实现）

用法:
  ssh-proxy serve [--config tunnels.json] [--port 7788] [--host 127.0.0.1]
                  [--token <令牌>] [--open] [--quiet]
  ssh-proxy status                      查看所有隧道状态
  ssh-proxy up <id|all>                  开启某条（或全部）隧道
  ssh-proxy down <id|all>                关闭某条（或全部）隧道
  ssh-proxy restart <id>                 重连
  ssh-proxy logs <id> [行数]             查看隧道日志
  ssh-proxy cmd <id>                     打印等价的 ssh 命令
  ssh-proxy secret <id>                  给\"连接时输入\"的隧道送一次密码（面板在跑）
  ssh-proxy reload                       重载 tunnels.json
  ssh-proxy init [文件名]                生成示例配置

登录凭据（面板要登录时才需要）:
  ssh-proxy passwd                       交互式设置登录密码（只存 scrypt 哈希）
  ssh-proxy passwd --clear               清除密码
  ssh-proxy addkey [--name 名字] [--file 公钥] [--key \"ssh-ed25519 ...\"]
                                         注册一把 Ed25519 公钥
  ssh-proxy rmkey <id|指纹>              删除一把公钥
  ssh-proxy auth                         查看当前启用的登录方式
  ssh-proxy help

环境变量:
  SSH_PROXY_TOKEN     面板访问令牌（等价于 panel.token）
  SSH_PROXY_PORT      面板端口（等价于 panel.port）
  SSH_PROXY_PASSWORD  非交互设置密码时用（passwd 会优先读它）
  SSH_PROXY_TUNNEL_SECRET  非交互给 secret 子命令传密码

注意（与 Node 版的已知差异）：
  - `passwd` 在交互式终端下**会回显输入**（Rust 版没有关终端回显）；
    非交互场景请用 SSH_PROXY_PASSWORD。
"
    );
}

fn serve(config: config::Config, flags: Flags) -> Result<i32, String> {
    let host = config.panel.host.clone();
    let port = config.panel.port;
    let config_file_display = config.config_file.display().to_string();
    let tunnel_count = config.tunnels.len();
    let methods = config.panel.auth_methods.clone();
    let ttl = config.panel.session_ttl_minutes;
    let idle = config.panel.session_idle_minutes;
    let token_source = config.panel.token_source.clone();
    let open_on_start = config.panel.open_on_start;
    let quiet = flags.quiet;
    let config_exists = config.config_exists;

    let supervisor = Supervisor::new(config, quiet)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("初始化 tokio 运行时失败: {}", e))?;

    // 先做孤儿回收与看门狗（对应 JS 的 init()：回收 → 建运行时 → 起 watch）
    runtime.block_on(async { supervisor.init().await });

    let state = Arc::new(http::State::new(supervisor.clone()));

    // 定期清理过期会话（对应 JS 的 300s sweeper）
    {
        let sweeper_state = state.clone();
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                sweeper_state.sessions.sweep();
            }
        });
    }

    let server_state = state.clone();
    let server_host = host.clone();
    // 监听失败（端口被占 / 没权限）必须立刻退出并说清楚：Node 版是 let server.once('error') 直接 reject，
    // 不退出会表现成"托盘在跑、面板打不开、日志里什么都没有"。
    let server = runtime.spawn(async move {
        if let Err(err) = http::serve(server_state, &server_host, port).await {
            eprintln!("✖ {}", err);
            std::process::exit(1);
        }
    });

    // 等监听就绪（最多 5 s），顺便自检一次
    let health = runtime.block_on(async {
        for _ in 0..50 {
            if let Ok(text) = http::self_check(&host, port).await {
                if text.contains("200 OK") {
                    return Some(text);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    });

    if !quiet {
        if !config_exists {
            eprintln!("未找到配置文件 {}", config_file_display);
            eprintln!("可以先执行: ssh-proxy init  生成一份示例再用。");
        }
        println!();
        println!("  SSH 隧道面板已启动（Rust 版）");
        println!("  面板地址   http://{}:{}/", host, port);
        println!("  配置文件   {}", config_file_display);
        println!("  隧道数量   {}", tunnel_count);
        if methods.is_empty() {
            println!("  登录方式   不需要登录（本机直接打开即可）");
        } else {
            let label = |m: &String| match m.as_str() {
                "token" => "令牌".to_string(),
                "password" => "密码".to_string(),
                "key" => "密钥".to_string(),
                other => other.to_string(),
            };
            println!(
                "  登录方式   {}{}",
                methods.iter().map(label).collect::<Vec<_>>().join(" / "),
                if methods.iter().any(|m| m == "token") {
                    format!(
                        "（令牌来源：{}）",
                        match token_source.as_str() {
                            "env" => "环境变量 SSH_PROXY_TOKEN",
                            "cli" => "命令行参数 --token",
                            "file" => "配置文件里的 panel.token",
                            _ => "未设置",
                        }
                    )
                } else {
                    String::new()
                }
            );
            println!(
                "  会话       {} 分钟到期，{} 分钟无操作失效（面板右上角可退出）",
                ttl, idle
            );
        }
        if token_source == "cli" {
            println!("  提示       --token 只在本次运行生效，不会写进配置文件；想固定下来就改 panel.token 或设 SSH_PROXY_TOKEN");
        }
        match &health {
            Some(_) => println!("  自检       /healthz 200 OK"),
            None => println!("  自检       未拿到 /healthz 响应（服务仍在运行）"),
        }
        println!("  Ctrl+C 关闭面板并停止所有隧道");
        println!();
    }

    if flags.self_check {
        runtime.block_on(async { supervisor.shutdown().await });
        server.abort();
        runtime.shutdown_background();
        return match health {
            Some(text) => {
                println!("{}", text);
                Ok(0)
            }
            None => Err("自检失败：/healthz 无响应".into()),
        };
    }

    // 按上次的用户意图拉起隧道（对应 JS 的 autostart）
    runtime.block_on(async { supervisor.autostart().await });

    if flags.open || open_on_start {
        open_external(&format!("http://{}:{}/", host, port));
    }

    runtime.block_on(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    if !quiet {
        println!("收到 Ctrl+C，正在停止所有隧道…");
    }
    runtime.block_on(async { supervisor.shutdown().await });
    server.abort();
    runtime.shutdown_background();
    Ok(0)
}

fn open_external(url: &str) {
    if cfg!(windows) {
        let script = format!("Start-Process '{}'", url.replace('\'', "''"));
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script.as_str()])
            .spawn();
    } else if cfg!(target_os = "macos") {
        let _ = std::process::Command::new("open").arg(url).spawn();
    } else {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

/// 前端资源目录（`public/`）。SEA 版在后面的里程碑换成内嵌资源。
///
/// 解析顺序：`SSH_PROXY_WEB_ROOT` → exe 所在目录逐级往上 6 层 → 当前目录。
pub fn web_root() -> PathBuf {
    if let Ok(dir) = std::env::var("SSH_PROXY_WEB_ROOT") {
        return PathBuf::from(dir);
    }
    let has_assets =
        |dir: &std::path::Path| dir.join("app.js").exists() && dir.join("style.css").exists();

    if let Ok(exe) = std::env::current_exe() {
        let mut cursor = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..6 {
            let Some(dir) = cursor else { break };
            let candidate = dir.join("public");
            if has_assets(&candidate) {
                return candidate;
            }
            cursor = dir.parent().map(|p| p.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("public");
        if has_assets(&candidate) {
            return candidate;
        }
    }
    PathBuf::from("public")
}
