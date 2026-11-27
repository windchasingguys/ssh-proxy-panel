//! CLI 子命令 —— 对应 `src/cli.mjs` 的非 `serve` 部分。
//!
//! 分工：`serve` 在 `main.rs`；这里放"查状态 / 开关隧道 / 日志 / 凭据管理"这些命令。
//! 除了 `init` / `auth` / `passwd` / `addkey` / `rmkey` 直接改文件，其余都通过 HTTP 打面板
//! （与 Node 版一致：CLI 只是面板的客户端，自己不起隧道）。
//!
//! HTTP 客户端手写（几十行），不引 reqwest/hyper 客户端，保持二进制小。

use std::path::Path;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::hash_password;
use crate::config::{example_config, Config};
use crate::config_writer::{
    add_public_key, read_raw_config, remove_public_key, set_password_hash, write_raw_config,
};
use crate::util::now_ms;

const STATUS_TEXT: [(&str, &str); 5] = [
    ("stopped", "已停止"),
    ("starting", "连接中"),
    ("up", "已连通"),
    ("retrying", "重连中"),
    ("failed", "已暂停"),
];

fn status_text(status: &str) -> &str {
    STATUS_TEXT
        .iter()
        .find(|(key, _)| *key == status)
        .map(|(_, text)| *text)
        .unwrap_or(status)
}

/// 与 `util.mjs` 的 `formatDuration` 一致
pub fn format_duration(ms: i64) -> String {
    let total = (ms as f64 / 1000.0).floor().max(0.0) as i64;
    if total < 60 {
        return format!("{} 秒", total);
    }
    let m = total / 60;
    let s = total % 60;
    if m < 60 {
        return if s != 0 {
            format!("{} 分 {} 秒", m, s)
        } else {
            format!("{} 分", m)
        };
    }
    let h = m / 60;
    let mm = m % 60;
    if h < 24 {
        return if mm != 0 {
            format!("{} 小时 {} 分", h, mm)
        } else {
            format!("{} 小时", h)
        };
    }
    format!("{} 天 {} 小时", h / 24, h % 24)
}

fn token_source_text(source: &str) -> &'static str {
    match source {
        "env" => "环境变量 SSH_PROXY_TOKEN",
        "cli" => "命令行参数 --token",
        "file" => "配置文件里的 panel.token",
        _ => "未设置",
    }
}

/// 面板为什么找我要凭据？这句话要能直接回答这个问题
fn describe_auth(panel: &crate::config::Panel) -> String {
    let methods = &panel.auth_methods;
    if methods.is_empty() {
        return "不需要登录（本机直接打开即可）".into();
    }
    let label = |m: &String| match m.as_str() {
        "token" => "令牌".to_string(),
        "password" => "密码".to_string(),
        "key" => "密钥".to_string(),
        other => other.to_string(),
    };
    let extra = if methods.iter().any(|m| m == "token") {
        format!(
            "（令牌来源：{}）",
            token_source_text(&panel.token_source)
        )
    } else {
        String::new()
    };
    format!(
        "{}{}",
        methods.iter().map(label).collect::<Vec<_>>().join(" / "),
        extra
    )
}

fn base_host(host: &str) -> &str {
    match host {
        "0.0.0.0" | "::" => "127.0.0.1",
        other => other,
    }
}

/// 手写的最小 HTTP 客户端（只发一个请求、读完整响应）
async fn http_request(
    config: &Config,
    route: &str,
    method: &str,
    body: Option<&Value>,
) -> Result<(u16, Value), String> {
    let host = base_host(&config.panel.host).to_string();
    let port = config.panel.port;
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| {
        format!(
            "连不上面板 http://{}:{}：连接超时（先运行 ssh-proxy serve）",
            host, port
        )
    })?
    .map_err(|e| {
        format!(
            "连不上面板 http://{}:{}：{}（先运行 ssh-proxy serve）",
            host, port, e
        )
    })?;

    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
        method, route, host, port
    );
    if !config.panel.token.is_empty() {
        request.push_str(&format!("x-panel-token: {}\r\n", config.panel.token));
    }
    if body.is_some() {
        request.push_str("content-type: application/json\r\n");
        request.push_str(&format!("content-length: {}\r\n", payload.len()));
    }
    request.push_str("\r\n");
    request.push_str(&payload);

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("请求面板失败: {}", e))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("读取面板响应失败: {}", e))?;

    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body_text) = match text.split_once("\r\n\r\n") {
        Some((head, body)) => (head, body.to_string()),
        None => (text.as_str(), String::new()),
    };
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);

    // 支持 chunked（服务端目前用 content-length，这里兜一下）
    let body_text = if head.to_lowercase().contains("transfer-encoding: chunked") {
        decode_chunked(&body_text)
    } else {
        body_text
    };

    let data: Value = serde_json::from_str(&body_text).unwrap_or_else(|_| json!({}));

    if status == 401 {
        return Err("面板需要登录：CLI 只支持用 panel.token 免登录操作；如果只配了密码/密钥，请在浏览器里登录后用面板操作".into());
    }
    if !(200..300).contains(&status) {
        let message = data
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or(&format!("HTTP {}", status))
            .to_string();
        return Err(message);
    }
    Ok((status, data))
}

fn decode_chunked(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    loop {
        let Some((size_line, tail)) = rest.split_once("\r\n") else {
            break;
        };
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        if tail.len() < size {
            out.push_str(tail);
            break;
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].trim_start_matches("\r\n");
    }
    out
}

fn print_tunnels(tunnels: &[Value]) {
    if tunnels.is_empty() {
        println!("（没有配置隧道，编辑 tunnels.json 后执行 reload）");
        return;
    }
    let now = now_ms();
    for tunnel in tunnels {
        let text = |key: &str| tunnel.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let num = |key: &str| tunnel.get(key).and_then(|v| v.as_i64());
        let status = text("status");
        let dot = match status.as_str() {
            "up" => "●",
            "stopped" => "○",
            _ => "◐",
        };
        let via = tunnel.get("via").cloned().unwrap_or(json!({}));
        let user = via.get("user").and_then(|v| v.as_str()).unwrap_or("");
        let host = via.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let port = via.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
        let jump = via.get("proxyJump").and_then(|v| v.as_str()).unwrap_or("");
        let via_text = format!(
            "{}{}:{}{}",
            if user.is_empty() {
                String::new()
            } else {
                format!("{}@", user)
            },
            host,
            port,
            if jump.is_empty() {
                String::new()
            } else {
                format!(" via {}", jump)
            }
        );
        let target = tunnel.get("target").cloned().unwrap_or(json!({}));
        let target_host = target.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let target_port = target.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
        let tail = match (num("upAt"), num("nextRetryAt")) {
            (Some(up_at), _) => format!("已连通 {}", format_duration(now as i64 - up_at)),
            (None, Some(next)) => {
                let seconds = ((next - now as i64) as f64 / 1000.0).round().max(0.0) as i64;
                format!("重连倒计时 {}s", seconds)
            }
            _ => text("lastError"),
        };
        println!(
            "{} {:<12} {:<6} {:<18} → {:<34} → {}:{}  {}",
            dot,
            text("id"),
            status_text(&status),
            format!("{}:{}", text("bindAddress"), num("localPort").unwrap_or(0)),
            via_text,
            target_host,
            target_port,
            tail
        );
    }
}

// ---------------------------------------------------------------- 直接改文件的命令

pub fn init(target: &str) -> Result<i32, String> {
    let path = std::path::absolute(target).unwrap_or_else(|_| Path::new(target).to_path_buf());
    if path.exists() {
        eprintln!(
            "已存在 {}，为避免覆盖已退出。换个文件名或用 --target 指定。",
            path.display()
        );
        return Ok(1);
    }
    let mut text = serde_json::to_string_pretty(&example_config())
        .map_err(|e| format!("序列化示例配置失败: {}", e))?;
    text.push('\n');
    std::fs::write(&path, text).map_err(|e| format!("写入 {} 失败: {}", path.display(), e))?;
    println!("已生成示例配置: {}", path.display());
    println!("按需修改 via（边缘机/跳板机）、target（内网服务）后运行: ssh-proxy serve --open");
    Ok(0)
}

pub fn auth(config: &Config) {
    println!("登录方式   {}", describe_auth(&config.panel));
    if config.panel.token.is_empty() {
        println!("  令牌     未设置");
    } else {
        println!(
            "  令牌     已设置（来源：{}）",
            token_source_text(&config.panel.token_source)
        );
    }
    println!(
        "  密码     {}",
        if config.panel.password_hash.is_empty() {
            "未设置".to_string()
        } else {
            "已设置（scrypt 哈希，不可逆）".to_string()
        }
    );
    if config.panel.public_keys.is_empty() {
        println!("  密钥     未注册");
    } else {
        for key in &config.panel.public_keys {
            println!("  密钥     {}  {}  {}", key.id, key.name, key.fingerprint);
        }
    }
    println!(
        "  会话     {} 分钟到期 / {} 分钟闲置失效",
        config.panel.session_ttl_minutes, config.panel.session_idle_minutes
    );
}

/// 关掉终端回显的守卫：`Drop` 时一定恢复，避免把用户终端搞坏。
///
/// Windows：`SetConsoleMode` 清 `ENABLE_ECHO_INPUT`（手写 kernel32 FFI，不引 crate）；
/// POSIX：`tcgetattr`/`tcsetattr` 清 `ECHO`。
struct EchoGuard {
    #[cfg(windows)]
    handle: *mut std::ffi::c_void,
    #[cfg(windows)]
    mode: u32,
    #[cfg(unix)]
    saved: libc::termios,
}

#[cfg(windows)]
mod win_console {
    use std::ffi::c_void;

    pub const STD_INPUT_HANDLE: u32 = 0u32.wrapping_sub(10); // -10
    pub const ENABLE_ECHO_INPUT: u32 = 0x0004;

    extern "system" {
        pub fn GetStdHandle(which: u32) -> *mut c_void;
        pub fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }
}

impl EchoGuard {
    fn new() -> Option<Self> {
        #[cfg(windows)]
        {
            unsafe {
                let handle = win_console::GetStdHandle(win_console::STD_INPUT_HANDLE);
                if handle.is_null() || handle as isize == -1 {
                    return None;
                }
                let mut mode = 0u32;
                if win_console::GetConsoleMode(handle, &mut mode) == 0 {
                    return None; // 不是控制台（管道 / 重定向）
                }
                if win_console::SetConsoleMode(
                    handle,
                    mode & !win_console::ENABLE_ECHO_INPUT,
                ) == 0
                {
                    return None;
                }
                Some(Self { handle, mode })
            }
        }
        #[cfg(unix)]
        {
            unsafe {
                let fd = libc::STDIN_FILENO;
                if libc::isatty(fd) != 1 {
                    return None;
                }
                let mut original: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut original) != 0 {
                    return None;
                }
                let mut quiet: libc::termios = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(&original, &mut quiet, 1);
                quiet.c_lflag &= !libc::ECHO;
                if libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) != 0 {
                    return None;
                }
                Some(Self { saved: original })
            }
        }
        #[cfg(not(any(windows, unix)))]
        {
            None
        }
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            win_console::SetConsoleMode(self.handle, self.mode);
        }
        #[cfg(unix)]
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &self.saved);
        }
    }
}

fn prompt_hidden(question: &str) -> Result<String, String> {
    use std::io::{BufRead, Write};
    print!("{}", question);
    std::io::stdout().flush().ok();
    let mut line = String::new();
    // 守卫活到读完这一行为止；离开作用域即恢复回显
    let guard = EchoGuard::new();
    let muted = guard.is_some();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("读取输入失败: {}", e));
    drop(guard);
    // 回显被关掉时用户看不到自己敲的回车，补一个换行
    if muted {
        println!();
    }
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub fn passwd(config_file: &Path, clear: bool, password_env: Option<String>) -> Result<i32, String> {
    if clear {
        let result = set_password_hash(config_file, "")?;
        write_raw_config(config_file, &result.raw)?;
        println!("已清除登录密码: {}", config_file.display());
        println!("重启面板后生效。");
        return Ok(0);
    }
    let password = match password_env {
        Some(value) if !value.is_empty() => {
            println!("使用环境变量 SSH_PROXY_PASSWORD");
            value
        }
        _ => {
            let first = prompt_hidden("新密码: ")?;
            let again = prompt_hidden("再输一遍: ")?;
            if first != again {
                return Err("两次输入不一致".into());
            }
            first
        }
    };
    if password.is_empty() {
        return Err("密码不能为空".into());
    }
    if password.chars().count() < 8 {
        eprintln!("提示：密码偏短，建议 12 位以上，或者干脆用密钥登录");
    }
    let hash = hash_password(&password)?;
    let result = set_password_hash(config_file, &hash)?;
    write_raw_config(config_file, &result.raw)?;
    println!("已写入密码哈希（scrypt）: {}", config_file.display());
    println!("重启面板后生效；登录框里会多出\"密码\"方式。");
    Ok(0)
}

pub fn add_key(
    config_file: &Path,
    name: Option<String>,
    key_flag: Option<String>,
    file_flag: Option<String>,
    positional_key: Option<String>,
) -> Result<i32, String> {
    let mut key_text = key_flag.unwrap_or_default();
    if key_text.is_empty() {
        if let Some(file) = file_flag {
            key_text = std::fs::read_to_string(&file)
                .map_err(|e| format!("读取公钥文件 {} 失败: {}", file, e))?;
        }
    }
    if key_text.is_empty() {
        if let Some(value) = positional_key {
            key_text = value;
        }
    }
    if key_text.trim().is_empty() {
        return Err(
            "没读到公钥：用 --key \"ssh-ed25519 ...\"、--file ~/.ssh/id_ed25519.pub，或从 stdin 传入"
                .into(),
        );
    }
    let display_name = name.clone().unwrap_or_else(|| "未命名密钥".into());
    let result = add_public_key(config_file, name.as_deref().unwrap_or(""), &key_text)?;
    write_raw_config(config_file, &result.raw)?;
    println!("已注册公钥: {}（{}）", result.id, display_name);
    println!("指纹: {}", result.fingerprint);
    println!("重启面板后生效；也可以在面板登录后用\"注册本机密钥\"自动完成。");
    Ok(0)
}

pub fn remove_key(config_file: &Path, target: Option<String>) -> Result<i32, String> {
    let Some(target) = target else {
        return Err("用法: ssh-proxy rmkey <id|指纹>".into());
    };
    let result = remove_public_key(config_file, &target)?;
    write_raw_config(config_file, &result.raw)?;
    println!("已删除: {}", target);
    println!("重启面板后生效。");
    Ok(0)
}

// ---------------------------------------------------------------- 走 HTTP 的命令

pub async fn http_command(
    command: &str,
    config: &Config,
    positional: &[String],
    tunnel_secret_env: Option<String>,
) -> Result<i32, String> {
    let arg = |index: usize| positional.get(index).cloned();
    match command {
        "status" => {
            let (_, data) = http_request(config, "/api/state", "GET", None).await?;
            let tunnels = data
                .get("tunnels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            print_tunnels(&tunnels);
        }
        "reload" => {
            let (_, data) = http_request(config, "/api/reload", "POST", None).await?;
            let count = data.get("tunnels").and_then(|v| v.as_i64()).unwrap_or(0);
            let added = data
                .get("added")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let changed = data
                .get("changed")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            println!(
                "配置已重载: {} 个隧道（新增 {}，改动 {}）",
                count, added, changed
            );
        }
        "up" | "down" => {
            let Some(id) = arg(1) else {
                return Err(format!("用法: ssh-proxy {} <id|all>", command));
            };
            let action = if command == "up" { "start" } else { "stop" };
            let route = if id == "all" {
                format!("/api/all/{}", action)
            } else {
                format!("/api/tunnels/{}/{}", encode_segment(&id), action)
            };
            http_request(config, &route, "POST", None).await?;
            let (_, data) = http_request(config, "/api/state", "GET", None).await?;
            let tunnels = data
                .get("tunnels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            print_tunnels(&tunnels);
        }
        "restart" => {
            let Some(id) = arg(1) else {
                return Err("用法: ssh-proxy restart <id>".into());
            };
            let route = format!("/api/tunnels/{}/restart", encode_segment(&id));
            http_request(config, &route, "POST", None).await?;
            println!("已重连 {}", id);
        }
        "secret" => {
            let Some(id) = arg(1) else {
                return Err("用法: ssh-proxy secret <id>".into());
            };
            let mut value = tunnel_secret_env.unwrap_or_default();
            if value.is_empty() {
                value = prompt_hidden("SSH 密码/口令: ")?;
            }
            if value.is_empty() {
                return Err("密码不能为空".into());
            }
            let route = format!("/api/tunnels/{}/secret", encode_segment(&id));
            let (_, data) = http_request(config, &route, "POST", Some(&json!({ "value": value }))).await?;
            let status = data
                .get("tunnel")
                .and_then(|t| t.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("未知");
            println!("已把凭据交给隧道 {}（只在内存里），当前状态: {}", id, status);
        }
        "logs" => {
            let Some(id) = arg(1) else {
                return Err("用法: ssh-proxy logs <id> [行数]".into());
            };
            let limit = arg(2)
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(80);
            let route = format!("/api/tunnels/{}/logs?lines={}", encode_segment(&id), limit);
            let (_, data) = http_request(config, &route, "GET", None).await?;
            for line in data
                .get("lines")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let t = line.get("t").and_then(|v| v.as_i64()).unwrap_or(0);
                let stream = line.get("stream").and_then(|v| v.as_str()).unwrap_or("");
                let text = line.get("text").and_then(|v| v.as_str()).unwrap_or("");
                println!("{} [{}] {}", local_hhmmss(t), stream, text);
            }
        }
        "cmd" => {
            let (_, data) = http_request(config, "/api/state", "GET", None).await?;
            let tunnels = data
                .get("tunnels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let target = match arg(1) {
                Some(id) => tunnels
                    .iter()
                    .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(id.as_str()))
                    .cloned()
                    .ok_or_else(|| format!("找不到隧道 {}", id))?,
                None => tunnels.first().cloned().ok_or_else(|| "没有隧道".to_string())?,
            };
            println!(
                "{}",
                target.get("command").and_then(|v| v.as_str()).unwrap_or("")
            );
        }
        other => return Err(format!("未知命令: {}（运行 ssh-proxy help 查看用法）", other)),
    }
    Ok(0)
}

fn encode_segment(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// 本地时间的 `HH:mm:ss`（对应 `toLocaleTimeString('zh-CN', { hour12: false })`）
fn local_hhmmss(ms: i64) -> String {
    let offset = local_offset_seconds();
    let total = ms / 1000 + offset;
    let secs = total.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(windows)]
fn local_offset_seconds() -> i64 {
    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    extern "system" {
        fn GetLocalTime(out: *mut SystemTime);
        fn GetSystemTime(out: *mut SystemTime);
    }
    extern "system" {
        fn SystemTimeToFileTime(time: *const SystemTime, out: *mut FileTime) -> i32;
    }
    unsafe {
        let mut local = SystemTime::default();
        let mut utc = SystemTime::default();
        GetLocalTime(&mut local);
        GetSystemTime(&mut utc);
        let mut lf = FileTime::default();
        let mut uf = FileTime::default();
        if SystemTimeToFileTime(&local, &mut lf) == 0
            || SystemTimeToFileTime(&utc, &mut uf) == 0
        {
            return 0;
        }
        let lv = ((lf.high as u64) << 32 | lf.low as u64) as i64;
        let uv = ((uf.high as u64) << 32 | uf.low as u64) as i64;
        // FILETIME 是 100ns 单位，换算成秒
        (lv - uv) / 10_000_000
    }
}

#[cfg(not(windows))]
fn local_offset_seconds() -> i64 {
    0
}

/// `init` 之外还要给 serve 用：把 raw 读出来（保留键序）以便 CLI 改文件后原样写回
#[allow(dead_code)]
pub fn read_raw(config_file: &Path) -> Result<Value, String> {
    read_raw_config(config_file)
}
