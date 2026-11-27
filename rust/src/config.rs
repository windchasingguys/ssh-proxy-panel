//! 配置解析 / 校验 / 默认值 —— 对应 `src/config.mjs`。
//!
//! 这里的每个默认值、每条别名、每个报错文案都要与 JS 实现保持一致：
//! 面板、CLI、测试与文档都以这套行为为准（见 `20_核心架构.md` 第四节）。
//!
//! 尚未实现（后续里程碑）：`publicKeys` 的 PEM 解析、`auth.mjs` 的 scrypt / Ed25519 验签。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Map, Value};

pub const DEFAULT_CONFIG_FILE: &str = "tunnels.json";

// ---------------------------------------------------------------- 结构

#[derive(Debug, Clone, Serialize)]
pub struct Config {
    pub panel: Panel,
    pub ssh: Ssh,
    pub supervision: Supervision,
    pub tunnels: Vec<Tunnel>,
    #[serde(skip)]
    pub config_file: PathBuf,
    #[serde(skip)]
    pub config_exists: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Panel {
    pub host: String,
    pub port: u16,
    pub token: String,
    /// `env` | `cli` | `file` | `none` —— 让用户看得见令牌是从哪来的
    pub token_source: String,
    pub password_hash: String,
    pub public_keys: Vec<PublicKeyEntry>,
    pub auth_methods: Vec<String>,
    pub open_on_start: bool,
    pub session_ttl_minutes: f64,
    pub session_idle_minutes: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    pub id: String,
    pub name: String,
    pub key: String,
    pub fingerprint: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ssh {
    /// 字符串或字符串数组（数组用于测试 / 包装脚本）
    pub bin: Value,
    pub connect_timeout: f64,
    pub server_alive_interval: f64,
    pub server_alive_count_max: f64,
    pub strict_host_key_checking: String,
    pub batch_mode: bool,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Supervision {
    pub start_timeout_ms: u64,
    pub watch_interval_ms: u64,
    pub max_failures: u64,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    pub stable_reset_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub bind_address: String,
    pub local_port: u16,
    pub target: Target,
    pub via: Via,
    pub auth: Auth,
    /// `bindAddress:localPort:target.host:target.port`，即 `-L` 参数
    pub forward_spec: String,
    pub scheme: String,
    pub url: String,
    pub auto_start: bool,
    pub open_on_up: bool,
    pub health_url: String,
    pub ssh_bin: Option<Value>,
    pub extra_args: Vec<String>,
    pub env: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Via {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
    pub identity_file: Option<String>,
    /// 归一化后键名保留大写的 `ProxyJump`（与 `config.mjs` 的输出形状一致）
    #[serde(rename = "ProxyJump")]
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
    pub known_hosts_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Key,
    Password,
    Ask,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Key => "key",
            AuthMode::Password => "password",
            AuthMode::Ask => "ask",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Auth {
    pub mode: AuthMode,
    pub identity_file: String,
    pub password: String,
    pub passphrase: String,
}

// ---------------------------------------------------------------- 默认值

fn defaults_panel() -> Value {
    json!({
        "host": "127.0.0.1",
        "port": 7788,
        "token": "",
        "passwordHash": "",
        "publicKeys": [],
        "authMethods": [],
        "openOnStart": false,
        "sessionTtlMinutes": 720,
        "sessionIdleMinutes": 120,
    })
}

fn defaults_ssh() -> Value {
    json!({
        "bin": "ssh",
        "connectTimeout": 10,
        "serverAliveInterval": 15,
        "serverAliveCountMax": 3,
        "strictHostKeyChecking": "accept-new",
        "batchMode": true,
        "extraArgs": [],
    })
}

fn defaults_supervision() -> Value {
    json!({
        "startTimeoutMs": 9000,
        "watchIntervalMs": 5000,
        "maxFailures": 12,
        "backoffBaseMs": 1000,
        "backoffMaxMs": 30000,
        "stableResetMs": 60000,
    })
}

/// 与 `mergeSection` 等价：逐键覆盖，子对象递归合并。
fn merge_section(defaults: &Value, given: Option<&Value>) -> Value {
    let Some(given) = given.filter(|v| v.is_object()) else {
        return defaults.clone();
    };
    let mut out = defaults.as_object().cloned().unwrap_or_default();
    if let Some(map) = given.as_object() {
        for (key, value) in map {
            // JS 的 mergeSection 只跳过 undefined；JSON 里没有 undefined，所以 null 照覆盖
            let merged = match (out.get(key), value.is_object()) {
                (Some(base), true) if base.is_object() => merge_section(base, Some(value)),
                _ => value.clone(),
            };
            out.insert(key.clone(), merged);
        }
    }
    Value::Object(out)
}

// ---------------------------------------------------------------- 小工具

fn is_plain_object(v: &Value) -> bool {
    v.is_object()
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}


/// `~` / `~/x` / `~\x` 展开成 home（ssh 的 `-i` 不一定会自己展开）
pub fn expand_home(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let home = home_dir();
    if input == "~" {
        return home;
    }
    if input.starts_with("~/") || input.starts_with("~\\") {
        return format!("{}{}", home, &input[1..]);
    }
    input.to_string()
}

fn home_dir() -> String {
    // Node 的 os.homedir() 在 Windows 上取 USERPROFILE，这里保持同样优先级
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default()
        .trim_end_matches(['/', '\\'])
        .to_string()
}

fn slug(name: &str) -> Option<String> {
    let trimmed = name.trim().to_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut last_dash = false;
    for ch in trimmed.chars() {
        let keep = ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-');
        if keep {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn assert_port(value: &Value, label: &str) -> Result<u16, String> {
    let n = match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match n {
        Some(n) if n.fract() == 0.0 && (1.0..=65535.0).contains(&n) => Ok(n as u16),
        _ => Err(format!(
            "{} 必须是 1-65535 之间的整数，当前为: {}",
            label, value
        )),
    }
}

/// `deploy@edge.example.com:2222` / `[::1]:22` 简写
fn parse_via_string(input: &str) -> Via {
    let text = input.trim().to_string();
    let (user, host_part) = match text.rfind('@') {
        Some(at) if at > 0 => (
            Some(text[..at].to_string()),
            text[at + 1..].to_string(),
        ),
        _ => (None, text.clone()),
    };
    let (host, port) = split_host_port(&host_part, 22);
    Via {
        user,
        host,
        port,
        identity_file: None,
        proxy_jump: None,
        proxy_command: None,
        known_hosts_file: None,
    }
}

/// `host:port` / `[v6]:port`，取不到端口就用 fallback
fn split_host_port(text: &str, fallback_port: u16) -> (String, u16) {
    let raw = text.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(fallback_port);
            return (host.to_string(), port);
        }
    }
    if let Some(idx) = raw.rfind(':') {
        let (host, port_part) = (&raw[..idx], &raw[idx + 1..]);
        if !host.is_empty() && !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = port_part.parse::<u16>() {
                return (host.to_string(), port);
            }
        }
    }
    (raw.to_string(), fallback_port)
}

fn parse_host_port(text: &str, fallback_port: u16) -> (String, u16) {
    split_host_port(text, fallback_port)
}

// 配置层复用 auth 模块的实现（指纹算的是 SPKI DER，别在这里重写一遍）
pub use crate::auth::{is_password_hash, normalize_public_key, public_key_fingerprint};
pub use crate::secrets::is_encrypted;
// ---------------------------------------------------------------- 主流程

/// 生成示例配置（`init` 命令与"配置文件不存在"时用），与 `exampleConfig()` 对齐
pub fn example_config() -> Value {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "deploy".to_string());
    json!({
        "panel": {
            "host": "127.0.0.1",
            "port": 7788,
            "token": "",
            "passwordHash": "",
            "publicKeys": [],
            "authMethods": [],
            "openOnStart": false,
            "sessionTtlMinutes": 720,
            "sessionIdleMinutes": 120,
        },
        "ssh": {
            "bin": "ssh",
            "connectTimeout": 10,
            "serverAliveInterval": 15,
            "serverAliveCountMax": 3,
            "strictHostKeyChecking": "accept-new",
            "batchMode": true,
        },
        "supervision": {
            "startTimeoutMs": 9000,
            "watchIntervalMs": 5000,
            "maxFailures": 12,
            "backoffBaseMs": 1000,
            "backoffMaxMs": 30000,
            "stableResetMs": 60000,
        },
        "tunnels": [
            {
                "id": "app",
                "name": "项目 Web",
                "description": "通过边缘机跳到内网项目，本机 8080 访问",
                "bindAddress": "127.0.0.1",
                "localPort": 8080,
                "target": { "host": "10.0.0.12", "port": 8080 },
                "via": {
                    "user": user,
                    "host": "edge.example.com",
                    "port": 22,
                    "identityFile": "~/.ssh/id_ed25519",
                },
                "scheme": "http",
                "autoStart": false,
                "openOnUp": false,
            },
            {
                "id": "app-db",
                "name": "项目数据库",
                "description": "把内网 MySQL 映射到本机 13306，方便用客户端连",
                "localPort": 13306,
                "target": { "host": "10.0.0.13", "port": 3306 },
                "via": "deploy@edge.example.com:22",
                "autoStart": false,
            },
        ],
    })
}
pub fn load_config(file: &str) -> Result<Config, String> {
    let abs = std::path::absolute(file).unwrap_or_else(|_| PathBuf::from(file));
    let exists = abs.exists();
    let raw = if exists {
        let text = std::fs::read_to_string(&abs)
            .map_err(|e| format!("配置文件读取失败 ({}): {}", abs.display(), e))?;
        let text = text.trim_start_matches('\u{feff}');
        serde_json::from_str::<Value>(text)
            .map_err(|e| format!("配置文件解析失败 ({}): {}", abs.display(), e))?
    } else {
        json!({ "tunnels": [] })
    };
    let mut config = normalize_config(&raw, &abs)?;
    config.config_exists = exists;
    Ok(config)
}

pub fn normalize_config(raw: &Value, config_file: &Path) -> Result<Config, String> {
    if !is_plain_object(raw) {
        return Err("配置文件根节点必须是一个 JSON 对象".into());
    }

    let panel_value = merge_section(&defaults_panel(), raw.get("panel"));
    let ssh_value = merge_section(&defaults_ssh(), raw.get("ssh"));
    let supervision_value = merge_section(&defaults_supervision(), raw.get("supervision"));

    // ---- panel
    let env_token = std::env::var("SSH_PROXY_TOKEN").ok();
    let token = env_token
        .clone()
        .unwrap_or_else(|| as_text(panel_value.get("token").unwrap_or(&Value::Null)))
        .trim()
        .to_string();
    let token_source = if env_token.is_some() {
        "env"
    } else if !token.is_empty() {
        "file"
    } else {
        "none"
    };

    let password_hash = as_text(panel_value.get("passwordHash").unwrap_or(&Value::Null))
        .trim()
        .to_string();
    if !password_hash.is_empty() && !is_password_hash(&password_hash) {
        return Err("panel.passwordHash 必须是 scrypt 哈希；用 \"node src/cli.mjs passwd\" 生成，不要手写明文密码".into());
    }

    let raw_keys = panel_value
        .get("publicKeys")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut public_keys = Vec::new();
    for (index, item) in raw_keys.iter().enumerate() {
        let Some(obj) = item.as_object() else { continue };
        let key_text = as_text(obj.get("key").unwrap_or(&Value::Null));
        if key_text.trim().is_empty() {
            continue;
        }
        let key = normalize_public_key(&key_text)?;
        public_keys.push(PublicKeyEntry {
            id: obj
                .get("id")
                .map(as_text)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("key-{}", index + 1)),
            name: obj
                .get("name")
                .map(as_text)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("密钥 {}", index + 1)),
            fingerprint: public_key_fingerprint(&key),
            created_at: obj
                .get("createdAt")
                .filter(|v| !v.is_null())
                .map(as_text),
            key,
        });
    }

    // 可用方式由配置推导；authMethods 只做“减法”
    let mut configured: Vec<String> = Vec::new();
    if !token.is_empty() {
        configured.push("token".into());
    }
    if !password_hash.is_empty() {
        configured.push("password".into());
    }
    if !public_keys.is_empty() {
        configured.push("key".into());
    }
    let wanted: Vec<String> = panel_value
        .get("authMethods")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(as_text).collect())
        .unwrap_or_default();
    let allowed: Vec<String> = if wanted.is_empty() {
        configured.clone()
    } else {
        configured
            .iter()
            .filter(|m| wanted.contains(m))
            .cloned()
            .collect()
    };
    let auth_methods = if allowed.is_empty() {
        configured.clone()
    } else {
        allowed
    };

    let session_ttl_minutes = positive_number(&panel_value, "sessionTtlMinutes")?;
    let session_idle_minutes = positive_number(&panel_value, "sessionIdleMinutes")?;

    // 与 JS 一致：`panel.port` 不做范围校验（`listen(0)` 就是"随机端口"，smoke 测试就靠这个）；
    // 只有环境变量 SSH_PROXY_PORT 会被严格校验。
    let mut port = match panel_value.get("port") {
        Some(Value::Number(n)) => n.as_u64().filter(|v| *v <= 65535).unwrap_or(0) as u16,
        Some(Value::String(s)) => s.trim().parse::<u16>().unwrap_or(0),
        Some(Value::Null) | None => 7788,
        _ => 0,
    };
    if let Ok(env_port) = std::env::var("SSH_PROXY_PORT") {
        port = assert_port(&Value::String(env_port), "panel.port")?;
    }

    let panel = Panel {
        host: as_text(panel_value.get("host").unwrap_or(&Value::Null)),
        port,
        token,
        token_source: token_source.to_string(),
        password_hash,
        public_keys,
        auth_methods,
        open_on_start: truthy(panel_value.get("openOnStart")),
        session_ttl_minutes,
        session_idle_minutes,
    };

    // ---- ssh / supervision（未列出的键暂时丢弃，后续里程碑保留透传）
    let ssh = Ssh {
        bin: ssh_value.get("bin").cloned().unwrap_or(json!("ssh")),
        connect_timeout: num(&ssh_value, "connectTimeout"),
        server_alive_interval: num(&ssh_value, "serverAliveInterval"),
        server_alive_count_max: num(&ssh_value, "serverAliveCountMax"),
        strict_host_key_checking: as_text(
            ssh_value.get("strictHostKeyChecking").unwrap_or(&Value::Null),
        ),
        batch_mode: truthy(ssh_value.get("batchMode")),
        extra_args: string_list(ssh_value.get("extraArgs")),
    };

    let supervision = Supervision {
        start_timeout_ms: uint(&supervision_value, "startTimeoutMs"),
        watch_interval_ms: uint(&supervision_value, "watchIntervalMs"),
        max_failures: uint(&supervision_value, "maxFailures"),
        backoff_base_ms: uint(&supervision_value, "backoffBaseMs"),
        backoff_max_ms: uint(&supervision_value, "backoffMaxMs"),
        stable_reset_ms: uint(&supervision_value, "stableResetMs"),
    };

    // ---- tunnels
    let tunnels_raw = raw
        .get("tunnels")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut tunnels = Vec::with_capacity(tunnels_raw.len());
    for (index, item) in tunnels_raw.iter().enumerate() {
        tunnels.push(normalize_tunnel(item, index)?);
    }
    let mut seen: HashSet<String> = HashSet::new();
    for tunnel in &tunnels {
        if !seen.insert(tunnel.id.clone()) {
            return Err(format!("隧道 id 重复: {}", tunnel.id));
        }
    }

    Ok(Config {
        panel,
        ssh,
        supervision,
        tunnels,
        config_file: config_file.to_path_buf(),
        config_exists: false,
    })
}

fn num(section: &Value, key: &str) -> f64 {
    match section.get(key) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn uint(section: &Value, key: &str) -> u64 {
    let v = num(section, key);
    if v <= 0.0 {
        0
    } else {
        v as u64
    }
}

fn positive_number(section: &Value, key: &str) -> Result<f64, String> {
    let value = num(section, key);
    if !value.is_finite() || value <= 0.0 {
        return Err(format!("panel.{} 必须是大于 0 的数字（单位：分钟）", key));
    }
    Ok(value)
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        _ => false,
    }
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(as_text).collect())
        .unwrap_or_default()
}

pub fn normalize_tunnel(raw: &Value, index: usize) -> Result<Tunnel, String> {
    if !is_plain_object(raw) {
        return Err(format!("第 {} 个隧道配置必须是对象", index + 1));
    }
    let obj = raw.as_object().cloned().unwrap_or_default();
    let label = obj
        .get("name")
        .map(as_text)
        .filter(|s| !s.is_empty())
        .or_else(|| obj.get("id").map(as_text).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| format!("第 {} 个隧道", index + 1));

    let local_port_raw = obj
        .get("localPort")
        .or_else(|| obj.get("listenPort"))
        .or_else(|| obj.get("port"))
        .cloned()
        .unwrap_or(Value::Null);
    let local_port = assert_port(&local_port_raw, &format!("{} 的 localPort", label))?;
    let bind_address = obj
        .get("bindAddress")
        .or_else(|| obj.get("listenAddress"))
        .map(as_text)
        .unwrap_or_else(|| "127.0.0.1".into());

    let (target_host, target_port) = match obj.get("target") {
        Some(Value::String(s)) => parse_host_port(s, local_port),
        Some(t) if t.is_object() => (
            as_text(t.get("host").unwrap_or(&json!("127.0.0.1"))),
            assert_port(
                t.get("port").unwrap_or(&json!(local_port)),
                &format!("{} 的 target.port", label),
            )?,
        ),
        _ => (
            as_text(
                obj.get("remoteHost")
                    .or_else(|| obj.get("host"))
                    .unwrap_or(&json!("127.0.0.1")),
            ),
            assert_port(
                obj.get("remotePort")
                    .or_else(|| obj.get("targetPort"))
                    .unwrap_or(&json!(local_port)),
                &format!("{} 的 target.port", label),
            )?,
        ),
    };

    let mut via = match obj.get("via") {
        Some(Value::String(s)) => parse_via_string(s),
        Some(v) if v.is_object() => {
            let port_value = v.get("port");
            let port = match port_value {
                None | Some(Value::Null) => 22,
                Some(p) => assert_port(p, &format!("{} 的 via.port", label))?,
            };
            Via {
                user: v.get("user").map(as_text).filter(|s| !s.is_empty()),
                host: as_text(v.get("host").unwrap_or(&Value::Null)),
                port,
                identity_file: v
                    .get("identityFile")
                    .map(as_text)
                    .filter(|s| !s.is_empty())
                    .map(|s| expand_home(&s)),
                proxy_jump: v
                    .get("proxyJump")
                    .or_else(|| v.get("jump"))
                    .map(as_text)
                    .filter(|s| !s.is_empty()),
                proxy_command: v
                    .get("proxyCommand")
                    .map(as_text)
                    .filter(|s| !s.is_empty()),
                known_hosts_file: v
                    .get("knownHostsFile")
                    .map(as_text)
                    .filter(|s| !s.is_empty())
                    .map(|s| expand_home(&s)),
            }
        }
        _ => {
            return Err(format!(
                "{} 缺少 via（边缘/跳板机地址），例如 \"via\": \"deploy@edge.example.com:22\"",
                label
            ))
        }
    };
    if via.host.is_empty() {
        return Err(format!("{} 缺少 via.host（边缘/跳板机地址）", label));
    }
    if via.proxy_jump.is_some() && via.port == 0 {
        via.port = 22;
    }

    let id = match obj.get("id").map(as_text).filter(|s| !s.is_empty()) {
        Some(id) => id,
        None => obj
            .get("name")
            .map(as_text)
            .and_then(|name| slug(&name))
            .unwrap_or_else(|| format!("tunnel-{}", index + 1)),
    };
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "{} 的 id 只能包含字母、数字、点、下划线、短横线，当前为: {}",
            label, id
        ));
    }

    // 隧道到边缘机的认证方式：私钥 / 存储密码（加密）/ 连接时输入
    let auth_obj = obj
        .get("auth")
        .and_then(|a| a.as_object())
        .cloned()
        .unwrap_or_default();
    let mode_text = auth_obj
        .get("mode")
        .map(as_text)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "key".into())
        .to_lowercase();
    let mode = match mode_text.as_str() {
        "key" => AuthMode::Key,
        "password" => AuthMode::Password,
        "ask" => AuthMode::Ask,
        _ => {
            return Err(format!(
                "{} 的 auth.mode 只能是 key（私钥）/ password（存储密码）/ ask（连接时输入）",
                label
            ))
        }
    };
    let auth_password = auth_obj
        .get("password")
        .map(as_text)
        .unwrap_or_default();
    let auth_passphrase = auth_obj
        .get("passphrase")
        .map(as_text)
        .unwrap_or_default();
    if !auth_password.is_empty() && !is_encrypted(&auth_password) {
        return Err(format!(
            "{} 的 auth.password 必须是加密后的值；请用面板编辑或 CLI 设置，不要手填明文",
            label
        ));
    }
    if !auth_passphrase.is_empty() && !is_encrypted(&auth_passphrase) {
        return Err(format!(
            "{} 的 auth.passphrase 必须是加密后的值；请用面板编辑或 CLI 设置",
            label
        ));
    }
    if mode == AuthMode::Password && auth_password.is_empty() {
        return Err(format!(
            "{} 选了密码登录，但还没有设置密码（在面板里编辑这条隧道即可）",
            label
        ));
    }

    let forward_spec = format!("{}:{}:{}:{}", bind_address, local_port, target_host, target_port);
    let identity_file = auth_obj
        .get("identityFile")
        .map(as_text)
        .filter(|s| !s.is_empty())
        .map(|s| expand_home(&s))
        .or_else(|| via.identity_file.clone())
        .unwrap_or_default();

    Ok(Tunnel {
        id: id.clone(),
        name: obj
            .get("name")
            .map(as_text)
            .filter(|s| !s.is_empty())
            .unwrap_or(id),
        description: obj.get("description").map(as_text).unwrap_or_default(),
        bind_address,
        local_port,
        target: Target {
            host: target_host,
            port: target_port,
        },
        via,
        auth: Auth {
            mode,
            identity_file,
            password: auth_password,
            passphrase: auth_passphrase,
        },
        forward_spec,
        scheme: obj
            .get("scheme")
            .map(as_text)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "http".into()),
        url: obj.get("url").map(as_text).unwrap_or_default().trim().to_string(),
        auto_start: truthy(obj.get("autoStart")),
        open_on_up: truthy(obj.get("openOnUp")),
        health_url: obj.get("healthUrl").map(as_text).unwrap_or_default(),
        ssh_bin: obj.get("sshBin").filter(|v| !v.is_null()).cloned(),
        extra_args: string_list(obj.get("extraArgs")),
        env: obj
            .get("env")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default(),
    })
}

/// `/api/config` 用的表单视图（逐字段对应 `server.mjs` 的 `tunnelForForm`）
pub fn form_view(config: &Config) -> Value {
    let keys: Vec<Value> = config
        .panel
        .public_keys
        .iter()
        .map(|k| {
            let mut item = Map::new();
            item.insert("id".into(), json!(k.id));
            item.insert("name".into(), json!(k.name));
            item.insert("fingerprint".into(), json!(k.fingerprint));
            if let Some(created_at) = &k.created_at {
                item.insert("createdAt".into(), json!(created_at));
            }
            Value::Object(item)
        })
        .collect();

    let tunnels: Vec<Value> = config.tunnels.iter().map(tunnel_for_form).collect();

    json!({
        "configFile": config.config_file.display().to_string(),
        "panel": {
            "host": config.panel.host,
            "port": config.panel.port,
            "tokenRequired": !config.panel.auth_methods.is_empty(),
            "tokenSource": config.panel.token_source,
            "methods": config.panel.auth_methods,
            "hasPassword": !config.panel.password_hash.is_empty(),
            "hasToken": !config.panel.token.is_empty(),
            "keys": keys,
            "sessionTtlMinutes": config.panel.session_ttl_minutes,
            "sessionIdleMinutes": config.panel.session_idle_minutes,
            "openOnStart": config.panel.open_on_start,
        },
        "ssh": config.ssh,
        "supervision": config.supervision,
        "tunnels": tunnels,
    })
}

/// 单条隧道的表单视图：不含 `forwardSpec` / `sshBin` / `env`，密码只暴露布尔位
fn tunnel_for_form(tunnel: &Tunnel) -> Value {
    json!({
        "id": tunnel.id,
        "name": tunnel.name,
        "description": tunnel.description,
        "localPort": tunnel.local_port,
        "bindAddress": tunnel.bind_address,
        "target": tunnel.target,
        "via": {
            "user": tunnel.via.user.clone().unwrap_or_default(),
            "host": tunnel.via.host,
            "port": tunnel.via.port,
            "identityFile": tunnel.via.identity_file.clone().unwrap_or_default(),
            "proxyJump": tunnel.via.proxy_jump.clone().unwrap_or_default(),
        },
        "auth": {
            "mode": tunnel.auth.mode.as_str(),
            "identityFile": tunnel.auth.identity_file,
            "hasPassword": !tunnel.auth.password.is_empty(),
            "hasPassphrase": !tunnel.auth.passphrase.is_empty(),
        },
        "scheme": tunnel.scheme,
        "url": tunnel.url,
        "healthUrl": tunnel.health_url,
        "extraArgs": tunnel.extra_args,
        "autoStart": tunnel.auto_start,
        "openOnUp": tunnel.open_on_up,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn one_tunnel(value: Value) -> Result<Tunnel, String> {
        normalize_tunnel(&value, 0)
    }

    fn config_of(value: Value) -> Result<Config, String> {
        normalize_config(&value, Path::new("unit-tunnels.json"))
    }

    #[test]
    fn local_port_aliases_are_accepted() {
        for raw in [
            json!({ "id": "a", "localPort": 8080, "target": "10.0.0.1:80", "via": "d@e.test:22" }),
            json!({ "id": "a", "listenPort": 8080, "target": "10.0.0.1:80", "via": "d@e.test:22" }),
            json!({ "id": "a", "port": 8080, "target": "10.0.0.1:80", "via": "d@e.test:22" }),
        ] {
            assert_eq!(one_tunnel(raw).unwrap().local_port, 8080);
        }
    }

    #[test]
    fn via_string_is_parsed() {
        let tunnel = one_tunnel(json!({
            "id": "a", "localPort": 8080, "via": "deploy@edge.test:2222"
        }))
        .unwrap();
        assert_eq!(tunnel.via.user.as_deref(), Some("deploy"));
        assert_eq!(tunnel.via.host, "edge.test");
        assert_eq!(tunnel.via.port, 2222);
    }

    #[test]
    fn forward_spec_matches_ssh_dash_l() {
        let tunnel = one_tunnel(json!({
            "id": "a", "localPort": 8080, "bindAddress": "127.0.0.1",
            "target": { "host": "10.0.0.12", "port": 80 }, "via": "d@e.test:22"
        }))
        .unwrap();
        assert_eq!(tunnel.forward_spec, "127.0.0.1:8080:10.0.0.12:80");
    }

    #[test]
    fn id_falls_back_to_slug_of_name() {
        let tunnel = one_tunnel(json!({
            "name": "Project Web!", "localPort": 8080, "via": "d@e.test:22"
        }))
        .unwrap();
        assert_eq!(tunnel.id, "project-web");
    }

    #[test]
    fn id_with_illegal_chars_is_rejected() {
        let err = one_tunnel(json!({
            "id": "带 中文", "localPort": 8080, "via": "d@e.test:22"
        }))
        .unwrap_err();
        assert!(err.contains("id 只能包含"));
    }

    #[test]
    fn plaintext_password_is_rejected() {
        let err = one_tunnel(json!({
            "id": "a", "localPort": 8080, "via": "d@e.test:22",
            "auth": { "mode": "password", "password": "明文" }
        }))
        .unwrap_err();
        assert!(err.contains("必须是加密后的值"));
    }

    #[test]
    fn ask_mode_needs_no_password() {
        let tunnel = one_tunnel(json!({
            "id": "a", "localPort": 8080, "via": "d@e.test:22",
            "auth": { "mode": "ask" }
        }))
        .unwrap();
        assert_eq!(tunnel.auth.mode, AuthMode::Ask);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let err = config_of(json!({
            "tunnels": [
                { "id": "same", "localPort": 8080, "via": "d@e.test:22" },
                { "id": "same", "localPort": 8081, "via": "d@e.test:22" }
            ]
        }))
        .unwrap_err();
        assert!(err.contains("隧道 id 重复"));
    }

    #[test]
    fn panel_port_zero_is_allowed() {
        // JS 不校验 panel.port；0 表示让系统选随机端口（smoke 就靠这个）
        let config = config_of(json!({ "panel": { "port": 0 }, "tunnels": [] })).unwrap();
        assert_eq!(config.panel.port, 0);
    }

    #[test]
    fn auth_methods_are_derived_from_credentials() {
        let config = config_of(json!({
            "panel": {
                "token": "t",
                "passwordHash": "scrypt$16384$8$1$AAAA$BBBB",
            },
            "tunnels": []
        }))
        .unwrap();
        assert_eq!(config.panel.auth_methods, vec!["token", "password"]);
    }

    #[test]
    fn auth_methods_can_only_subtract() {
        // 配置里写 authMethods 只能做减法，不能凭空加出没配凭据的方式
        let config = config_of(json!({
            "panel": { "token": "t", "authMethods": ["token", "key"] },
            "tunnels": []
        }))
        .unwrap();
        assert_eq!(config.panel.auth_methods, vec!["token"]);
    }

    #[test]
    fn unknown_fields_survive_parsing() {
        let config = config_of(json!({
            "ssh": { "bin": ["/usr/bin/ssh", "-v"], "extraArgs": ["-o", "LogLevel=ERROR"] },
            "tunnels": []
        }))
        .unwrap();
        assert!(config.ssh.bin.is_array());
        assert_eq!(config.ssh.extra_args, vec!["-o", "LogLevel=ERROR"]);
    }
}