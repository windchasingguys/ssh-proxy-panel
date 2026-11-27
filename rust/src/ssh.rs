//! ssh 命令层（对应 `src/ssh.mjs` 的纯函数部分）。
//!
//! 只有参数拼装与命令展示在这里；spawn / askpass / killTree 属于 supervisor 里程碑（M2）。

use serde_json::Value;

use crate::config::{expand_home, AuthMode, Config, Tunnel};

/// ssh 可执行文件：字符串或数组（数组便于测试 / 自定义包装脚本）
pub fn command_prefix(tunnel: &Tunnel, config: &Config) -> Vec<String> {
    let bin = tunnel
        .ssh_bin
        .clone()
        .unwrap_or_else(|| config.ssh.bin.clone());
    match bin {
        Value::Array(items) => items.iter().map(text).collect(),
        other => vec![text(&other)],
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn quote_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".into();
    }
    let safe = arg.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '\\' | '~' | '^' | '-')
    });
    if safe {
        arg.to_string()
    } else {
        format!("\"{}\"", arg.replace('"', "\\\""))
    }
}

/// 给 UI / CLI 看的“等价命令”
pub fn format_command(prefix: &[String], args: &[String]) -> String {
    prefix
        .iter()
        .chain(args.iter())
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn num(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{}", value)
    }
}

/// 构建 `ssh -N -L …` 参数（逐条对应 `buildSshArgs`）
pub fn build_ssh_args(tunnel: &Tunnel, config: &Config, secret: Option<&str>) -> Vec<String> {
    let cfg = &config.ssh;
    let auth = &tunnel.auth;
    let has_secret = secret.map(|s| !s.is_empty()).unwrap_or(false);

    let mut args: Vec<String> = vec!["-N".into(), "-T".into()];
    let opt = |args: &mut Vec<String>, v: String| {
        args.push("-o".into());
        args.push(v);
    };

    opt(&mut args, "ExitOnForwardFailure=yes".into());
    opt(&mut args, format!("ConnectTimeout={}", num(cfg.connect_timeout)));
    opt(
        &mut args,
        format!("ServerAliveInterval={}", num(cfg.server_alive_interval)),
    );
    opt(
        &mut args,
        format!("ServerAliveCountMax={}", num(cfg.server_alive_count_max)),
    );
    opt(
        &mut args,
        format!("StrictHostKeyChecking={}", cfg.strict_host_key_checking),
    );
    opt(&mut args, "TCPKeepAlive=yes".into());

    if auth.mode == AuthMode::Password {
        // 密码登录：只走密码 / keyboard-interactive，不做公钥探测
        opt(&mut args, "PubkeyAuthentication=no".into());
        opt(
            &mut args,
            "PreferredAuthentications=password,keyboard-interactive".into(),
        );
        opt(&mut args, "NumberOfPasswordPrompts=1".into());
    }

    let needs_prompt = auth.mode == AuthMode::Password || has_secret;
    opt(
        &mut args,
        if cfg.batch_mode && !needs_prompt {
            "BatchMode=yes".into()
        } else {
            "BatchMode=no".into()
        },
    );

    if tunnel.via.port != 0 {
        args.push("-p".into());
        args.push(tunnel.via.port.to_string());
    }
    if let Some(jump) = &tunnel.via.proxy_jump {
        args.push("-J".into());
        args.push(jump.clone());
    }
    if let Some(cmd) = &tunnel.via.proxy_command {
        opt(&mut args, format!("ProxyCommand={}", cmd));
    }

    let identity = if !auth.identity_file.is_empty() {
        Some(auth.identity_file.clone())
    } else {
        tunnel.via.identity_file.clone()
    };
    if let Some(path) = identity.filter(|_| auth.mode != AuthMode::Password) {
        args.push("-i".into());
        args.push(expand_home(&path));
    }
    if let Some(known) = &tunnel.via.known_hosts_file {
        opt(&mut args, format!("UserKnownHostsFile={}", expand_home(known)));
    }

    args.extend(cfg.extra_args.iter().cloned());
    args.extend(tunnel.extra_args.iter().cloned());
    args.push("-L".into());
    args.push(tunnel.forward_spec.clone());
    args.push(match &tunnel.via.user {
        Some(user) if !user.is_empty() => format!("{}@{}", user, tunnel.via.host),
        _ => tunnel.via.host.clone(),
    });
    args
}

/// `openOnUp` 打开的地址：路径拼到 `scheme://host:localPort`，完整 URL 原样用
pub fn open_url(tunnel: &Tunnel) -> String {
    let host = match tunnel.bind_address.as_str() {
        "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    let scheme = if tunnel.scheme == "https" { "https" } else { "http" };
    let host_part = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host
    };
    let base = format!("{}://{}:{}", scheme, host_part, tunnel.local_port);
    let raw = tunnel.url.trim();
    if raw.is_empty() {
        return format!("{}/", base);
    }
    if raw.contains("://") && raw.split("://").next().is_some_and(|s| {
        let mut chars = s.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    }) {
        return raw.to_string();
    }
    if raw.starts_with('/') {
        format!("{}{}", base, raw)
    } else {
        format!("{}/{}", base, raw)
    }
}

// ---------------------------------------------------------------- 进程与 askpass

/// 生成/更新 askpass 小帮手（对应 `ensureAskpassHelper`）。
///
/// Windows 上 `SSH_ASKPASS` 必须是可直接 `CreateProcess` 的目标，实测 `.cmd` 可行；
/// POSIX 给 shebang 脚本加可执行位。
pub fn ensure_askpass_helper(data_dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("取当前可执行文件路径失败: {}", e))?;
    let is_win = cfg!(windows);
    let helper = data_dir.join(if is_win { "askpass.cmd" } else { "askpass.sh" });
    let quoted = format!("\"{}\"", exe.display().to_string().replace('"', "\\\""));
    let content = if is_win {
        format!("@echo off\r\n{} --askpass %*\r\n", quoted)
    } else {
        format!("#!/bin/sh\nexec {} --askpass \"$@\"\n", quoted)
    };

    std::fs::create_dir_all(data_dir).map_err(|e| format!("创建数据目录失败: {}", e))?;
    let current = std::fs::read_to_string(&helper).unwrap_or_default();
    if current != content {
        std::fs::write(&helper, content).map_err(|e| format!("写入 askpass 失败: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(helper)
}

/// ssh 子进程的额外环境：凭据只走环境变量，不落盘（对应 `askpassEnv`）
pub fn askpass_env(helper: &std::path::Path, secret: &str) -> Vec<(String, String)> {
    if secret.is_empty() {
        return Vec::new();
    }
    vec![
        ("SSH_ASKPASS".to_string(), helper.display().to_string()),
        ("SSH_ASKPASS_REQUIRE".to_string(), "force".to_string()),
        ("SSHPROXY_SSH_SECRET".to_string(), secret.to_string()),
        // 个别平台在没有 DISPLAY 时会跳过 askpass
        (
            "DISPLAY".to_string(),
            std::env::var("DISPLAY").unwrap_or_else(|_| ":0".to_string()),
        ),
    ]
}

/// 杀掉 ssh 进程树：Windows 用 `taskkill /T /F` 连子进程一起杀，POSIX 打进程组
pub fn kill_tree(pid: u32) {
    if pid == 0 {
        return;
    }
    if cfg!(windows) {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    } else {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &format!("-{}", pid)])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let group = format!("-{}", pid);
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &group])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

pub fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if cfg!(windows) {
        let Ok(output) = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
            .output()
        else {
            return false;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        text.contains(&format!("\"{}\"", pid))
    } else {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
}

/// 读进程命令行（孤儿回收要按 `-N` 与本隧道的 `-L` 规格匹配，避免误杀别人的 ssh）
pub fn read_cmdline(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }
    if cfg!(windows) {
        let script = format!(
            "$p = Get-CimInstance Win32_Process -Filter \"ProcessId={}\"; if ($p) {{ $p.CommandLine }}",
            pid
        );
        let Ok(output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
        else {
            return String::new();
        };
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "args=", "-p", &pid.to_string()])
            .output()
        else {
            return String::new();
        };
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }
}