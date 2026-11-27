//! 面板改配置的落盘层 —— 对应 `src/config-writer.mjs`。
//!
//! 三条硬约束（都来自 JS 版注释，改之前先读）：
//!  1. **只改动 tunnels 数组里对应的那一项**：其它顶层字段（panel / ssh / supervision 以及未来新增的字段）原样保留；
//!  2. **单条隧道里面板不认识的字段（env / sshBin）也要保留**，避免手写的内容被吃掉；
//!  3. **写之前先用 normalize_config 全量校验**，校验不过就直接报错、文件一个字都不动。
//!
//! 另外两个容易忽略的细节：
//!  - `serde_json` 开了 `preserve_order`，解析出来的键序就是文件里的键序，写回时才不会把用户文件重排；
//!  - 落盘格式必须与 `JSON.stringify(raw, null, 2) + "\n"` 一致（两空格缩进 + 结尾换行），
//!    否则"面板改一次"就会把整份文件 diff 掉。

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::auth::{normalize_public_key, public_key_fingerprint};
use crate::config::{example_config, normalize_config, Config};
use crate::util::now_ms;

/// 这些字段面板不编辑，但必须原样保留
const PRESERVE_KEYS: [&str; 2] = ["env", "sshBin"];

fn as_string(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.trim().to_string(),
        Some(other) => other.to_string().trim().to_string(),
    }
}

fn as_positive_number(value: &Value, label: &str) -> Result<f64, String> {
    let n = match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    };
    match n {
        Some(n) if n.is_finite() && n > 0.0 => Ok(n),
        _ => Err(format!("{} 必须是一个大于 0 的数字", label)),
    }
}

/// 整数值按整数写（否则 8080 会变成 8080.0，与 JS 的 JSON.stringify 不一致）
fn number_value(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < i64::MAX as f64 {
        json!(n as i64)
    } else {
        json!(n)
    }
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

fn empty_config() -> Value {
    let mut base = example_config();
    if let Some(map) = base.as_object_mut() {
        map.insert("tunnels".into(), json!([]));
    }
    base
}

pub fn read_raw_config(file: &Path) -> Result<Value, String> {
    if !file.exists() {
        return Ok(empty_config());
    }
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("读取 {} 失败: {}", file.display(), e))?;
    let text = text.trim_start_matches('\u{feff}');
    if text.trim().is_empty() {
        return Ok(empty_config());
    }
    serde_json::from_str(text).map_err(|e| format!("配置文件解析失败 ({}): {}", file.display(), e))
}

/// 原子写回，格式与 `JSON.stringify(raw, null, 2) + "\n"` 一致
pub fn write_raw_config(file: &Path, raw: &Value) -> Result<(), String> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败: {}", e))?;
    }
    let tmp = file.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut text = serde_json::to_string_pretty(raw).map_err(|e| format!("序列化失败: {}", e))?;
    text.push('\n');
    std::fs::write(&tmp, text).map_err(|e| format!("写入临时文件失败: {}", e))?;
    std::fs::rename(&tmp, file).map_err(|e| format!("替换 {} 失败: {}", file.display(), e))
}

/// 把面板表单提交的数据转成配置文件里的一条隧道（字段顺序也要与 JS 一致）
pub fn tunnel_from_payload(payload: &Value, previous: Option<&Value>) -> Result<Value, String> {
    let Some(payload_obj) = payload.as_object() else {
        return Err("请求体格式不对".into());
    };
    let get = |key: &str| payload_obj.get(key);

    let id = as_string(get("id"));
    if id.is_empty() {
        return Err("id 不能为空（字母、数字、点、下划线、短横线）".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("id 只能包含字母、数字、点、下划线、短横线".into());
    }

    let local_port = as_positive_number(
        get("localPort").unwrap_or(&Value::Null),
        "本机端口",
    )?;
    let target = get("target").cloned().unwrap_or_else(|| json!({}));
    let target = if target.is_object() { target } else { json!({}) };
    let via = get("via").cloned().unwrap_or_else(|| json!({}));
    let via = if via.is_object() { via } else { json!({}) };
    let target_obj = target.as_object().cloned().unwrap_or_default();
    let via_obj = via.as_object().cloned().unwrap_or_default();

    let via_host = as_string(via_obj.get("host"));
    if via_host.is_empty() {
        return Err("边缘机地址（via.host）不能为空".into());
    }
    let via_port_raw = as_string(via_obj.get("port"));
    let via_port = if via_port_raw.is_empty() {
        22.0
    } else {
        as_positive_number(&json!(via_port_raw), "边缘机端口")?
    };

    let bind_address = {
        let value = as_string(get("bindAddress"));
        if value.is_empty() {
            "127.0.0.1".to_string()
        } else {
            value
        }
    };
    let target_host = {
        let value = as_string(target_obj.get("host"));
        if value.is_empty() {
            "127.0.0.1".to_string()
        } else {
            value
        }
    };
    let target_port_raw = as_string(target_obj.get("port"));
    let target_port = if target_port_raw.is_empty() {
        local_port
    } else {
        as_positive_number(&json!(target_port_raw), "目标端口")?
    };

    // 先按"好看"的顺序编排已知字段，再把保留字段补到后面
    let mut out = Map::new();
    out.insert("id".into(), json!(id));
    let name = as_string(get("name"));
    if !name.is_empty() {
        out.insert("name".into(), json!(name));
    }
    let description = as_string(get("description"));
    if !description.is_empty() {
        out.insert("description".into(), json!(description));
    }
    out.insert("localPort".into(), number_value(local_port));
    if bind_address != "127.0.0.1" {
        out.insert("bindAddress".into(), json!(bind_address));
    }
    out.insert(
        "target".into(),
        json!({ "host": target_host, "port": number_value(target_port) }),
    );

    let mut via_out = Map::new();
    let via_user = as_string(via_obj.get("user"));
    if !via_user.is_empty() {
        via_out.insert("user".into(), json!(via_user));
    }
    via_out.insert("host".into(), json!(via_host));
    via_out.insert("port".into(), number_value(via_port));
    let identity_file = as_string(via_obj.get("identityFile"));
    if !identity_file.is_empty() {
        via_out.insert("identityFile".into(), json!(identity_file));
    }
    let proxy_jump = as_string(via_obj.get("proxyJump"));
    if !proxy_jump.is_empty() {
        via_out.insert("proxyJump".into(), json!(proxy_jump));
    }
    out.insert("via".into(), Value::Object(via_out));

    // 隧道到边缘机的认证方式：私钥 / 存储密码（已加密）/ 连接时输入
    let previous_auth = previous
        .and_then(|p| p.get("auth"))
        .and_then(|a| a.as_object())
        .cloned()
        .unwrap_or_default();
    match get("auth").and_then(|a| a.as_object()) {
        Some(auth_in) => {
            let mode = {
                let value = as_string(auth_in.get("mode"));
                if value.is_empty() {
                    let previous_mode = as_string(previous_auth.get("mode"));
                    if previous_mode.is_empty() {
                        "key".to_string()
                    } else {
                        previous_mode
                    }
                } else {
                    value
                }
            };
            let mut auth_out = Map::new();
            auth_out.insert("mode".into(), json!(mode));
            let auth_identity = {
                let value = as_string(auth_in.get("identityFile"));
                if value.is_empty() {
                    as_string(previous_auth.get("identityFile"))
                } else {
                    value
                }
            };
            if !auth_identity.is_empty() {
                auth_out.insert("identityFile".into(), json!(auth_identity));
            }
            let password = if truthy(auth_in.get("clearPassword")) {
                String::new()
            } else {
                let value = as_string(auth_in.get("password"));
                if value.is_empty() {
                    as_string(previous_auth.get("password"))
                } else {
                    value
                }
            };
            if !password.is_empty() {
                auth_out.insert("password".into(), json!(password));
            }
            let passphrase = if truthy(auth_in.get("clearPassphrase")) {
                String::new()
            } else {
                let value = as_string(auth_in.get("passphrase"));
                if value.is_empty() {
                    as_string(previous_auth.get("passphrase"))
                } else {
                    value
                }
            };
            if !passphrase.is_empty() {
                auth_out.insert("passphrase".into(), json!(passphrase));
            }
            out.insert("auth".into(), Value::Object(auth_out));
        }
        None => {
            if let Some(previous) = previous.and_then(|p| p.get("auth")).filter(|a| a.is_object()) {
                out.insert("auth".into(), previous.clone());
            }
        }
    }

    let scheme = as_string(get("scheme"));
    if !scheme.is_empty() && scheme != "http" {
        out.insert("scheme".into(), json!(scheme));
    }
    let open_path = as_string(get("url"));
    if !open_path.is_empty() {
        out.insert("url".into(), json!(open_path));
    }
    let health_url = as_string(get("healthUrl"));
    if !health_url.is_empty() {
        out.insert("healthUrl".into(), json!(health_url));
    }
    if let Some(Value::Array(args)) = get("extraArgs") {
        let list: Vec<Value> = args
            .iter()
            .map(|a| as_string(Some(a)))
            .filter(|a| !a.is_empty())
            .map(|a| json!(a))
            .collect();
        if !list.is_empty() {
            out.insert("extraArgs".into(), Value::Array(list));
        }
    }
    if truthy(get("autoStart")) {
        out.insert("autoStart".into(), json!(true));
    }
    if truthy(get("openOnUp")) {
        out.insert("openOnUp".into(), json!(true));
    }
    if let Some(env) = get("env").and_then(|e| e.as_object()) {
        out.insert("env".into(), Value::Object(env.clone()));
    }

    if let Some(previous) = previous.and_then(|p| p.as_object()) {
        for key in previous.keys() {
            if !out.contains_key(key) && PRESERVE_KEYS.contains(&key.as_str()) {
                out.insert(key.clone(), previous[key].clone());
            }
        }
    }
    Ok(Value::Object(out))
}

/// 找到 `raw.tunnels` 里对应某个规范化 id 的下标（兼容手写时省略 id 的情况）
fn index_of_tunnel(raw_tunnels: &[Value], normalized_ids: &[String], id: &str) -> Option<usize> {
    if let Some(idx) = normalized_ids.iter().position(|t| t == id) {
        return Some(idx);
    }
    raw_tunnels
        .iter()
        .position(|item| as_string(item.get("id")) == id)
}

#[derive(Debug)]
pub struct MutateResult {
    pub raw: Value,
    pub config: Config,
}

fn with_tunnels(raw: &Value, tunnels: Vec<Value>) -> Value {
    let mut next = raw.as_object().cloned().unwrap_or_default();
    next.insert("tunnels".into(), Value::Array(tunnels));
    Value::Object(next)
}

/// 增 / 改 / 删一条隧道。校验失败直接返回 Err，调用方据此回 400，文件保持不动。
pub fn mutate_tunnels(
    file: &Path,
    action: &str,
    id: &str,
    payload: &Value,
) -> Result<MutateResult, String> {
    let raw = read_raw_config(file)?;
    let mut raw_tunnels: Vec<Value> = raw
        .get("tunnels")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();

    let before_raw = with_tunnels(&raw, raw_tunnels.clone());
    let before = normalize_config(&before_raw, file)?;
    let before_ids: Vec<String> = before.tunnels.iter().map(|t| t.id.clone()).collect();

    match action {
        "create" => {
            let new_id = as_string(payload.get("id"));
            if before_ids.iter().any(|t| t == &new_id) {
                return Err(format!(
                    "已存在 id 为 {} 的隧道，换个 id 或直接编辑它",
                    new_id
                ));
            }
            raw_tunnels.push(tunnel_from_payload(payload, None)?);
        }
        "update" | "delete" => {
            let idx = index_of_tunnel(&raw_tunnels, &before_ids, id)
                .ok_or_else(|| format!("找不到隧道: {}", id))?;
            if action == "update" {
                let previous = raw_tunnels[idx].clone();
                let next_tunnel = tunnel_from_payload(payload, Some(&previous))?;
                let next_id = as_string(next_tunnel.get("id"));
                if next_id != id && before_ids.iter().any(|t| t == &next_id) {
                    return Err(format!("已存在 id 为 {} 的隧道", next_id));
                }
                raw_tunnels[idx] = next_tunnel;
            } else {
                raw_tunnels.remove(idx);
            }
        }
        other => return Err(format!("未知操作: {}", other)),
    }

    let next_raw = with_tunnels(&raw, raw_tunnels);
    let config = normalize_config(&next_raw, file)?;
    Ok(MutateResult {
        raw: next_raw,
        config,
    })
}

/// 更新 ssh / supervision 这类全局默认参数（以及 panel 的"门户参数"）
pub fn mutate_settings(file: &Path, payload: &Value) -> Result<MutateResult, String> {
    let mut raw = read_raw_config(file)?;
    let empty = Map::new();
    let payload_obj = payload.as_object().cloned().unwrap_or_else(|| empty.clone());

    if let Some(ssh_in) = payload_obj.get("ssh").and_then(|v| v.as_object()) {
        let mut ssh = raw
            .get("ssh")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(bin) = ssh_in.get("bin") {
            if let Some(list) = bin.as_array() {
                let items: Vec<Value> = list
                    .iter()
                    .map(|x| as_string(Some(x)))
                    .filter(|x| !x.is_empty())
                    .map(|x| json!(x))
                    .collect();
                if items.is_empty() {
                    return Err("ssh.bin 不能为空".into());
                }
                ssh.insert("bin".into(), Value::Array(items));
            } else {
                let value = as_string(Some(bin));
                if value.is_empty() {
                    return Err("ssh.bin 不能为空".into());
                }
                ssh.insert("bin".into(), json!(value));
            }
        }
        for (key, label) in [
            ("connectTimeout", "ssh.connectTimeout"),
            ("serverAliveInterval", "ssh.serverAliveInterval"),
            ("serverAliveCountMax", "ssh.serverAliveCountMax"),
        ] {
            if let Some(value) = ssh_in.get(key) {
                let n = as_positive_number(value, label)?;
                ssh.insert(key.into(), number_value(n));
            }
        }
        if let Some(value) = ssh_in.get("strictHostKeyChecking") {
            let text = as_string(Some(value));
            if !["yes", "no", "accept-new", "ask"].contains(&text.as_str()) {
                return Err("StrictHostKeyChecking 只能是 yes / no / accept-new".into());
            }
            ssh.insert("strictHostKeyChecking".into(), json!(text));
        }
        if let Some(value) = ssh_in.get("batchMode") {
            ssh.insert("batchMode".into(), json!(truthy(Some(value))));
        }
        raw["ssh"] = Value::Object(ssh);
    }

    if let Some(sup_in) = payload_obj.get("supervision").and_then(|v| v.as_object()) {
        let mut sup = raw
            .get("supervision")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        for key in [
            "startTimeoutMs",
            "watchIntervalMs",
            "maxFailures",
            "backoffBaseMs",
            "backoffMaxMs",
            "stableResetMs",
        ] {
            if let Some(value) = sup_in.get(key) {
                let n = as_positive_number(value, &format!("supervision.{}", key))?;
                sup.insert(key.into(), number_value(n));
            }
        }
        raw["supervision"] = Value::Object(sup);
    }

    // panel.* 属于"门户参数"：可以在这里改，但需要重启面板才生效（服务端只落盘不热应用）
    if let Some(panel_in) = payload_obj.get("panel").and_then(|v| v.as_object()) {
        let mut panel = raw
            .get("panel")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(value) = panel_in.get("token") {
            panel.insert("token".into(), json!(as_string(Some(value))));
        }
        for key in ["sessionTtlMinutes", "sessionIdleMinutes"] {
            if let Some(value) = panel_in.get(key) {
                let n = as_positive_number(value, &format!("panel.{}", key))?;
                panel.insert(key.into(), number_value(n));
            }
        }
        raw["panel"] = Value::Object(panel);
    }

    let config = normalize_config(&raw, file)?;
    Ok(MutateResult { raw, config })
}

/// 只写入 scrypt 哈希，明文永远不进文件
#[allow(dead_code)] // M4b 的 `passwd` 子命令会用
pub fn set_password_hash(file: &Path, hash: &str) -> Result<MutateResult, String> {
    let mut raw = read_raw_config(file)?;
    let mut panel = raw
        .get("panel")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    panel.insert("passwordHash".into(), json!(hash));
    raw["panel"] = Value::Object(panel);
    let config = normalize_config(&raw, file)?;
    Ok(MutateResult { raw, config })
}

#[derive(Debug)]
pub struct AddKeyResult {
    pub raw: Value,
    pub config: Config,
    pub id: String,
    pub fingerprint: String,
}

/// 注册一把 Ed25519 公钥（重复公钥会被拒绝）
pub fn add_public_key(file: &Path, name: &str, key: &str) -> Result<AddKeyResult, String> {
    let normalized = normalize_public_key(key)?;
    let fingerprint = public_key_fingerprint(&normalized);
    let mut raw = read_raw_config(file)?;
    let mut panel = raw
        .get("panel")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut keys: Vec<Value> = panel
        .get("publicKeys")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let duplicated = keys.iter().any(|item| {
        let text = as_string(item.get("key"));
        normalize_public_key(&text)
            .map(|k| public_key_fingerprint(&k) == fingerprint)
            .unwrap_or(false)
    });
    if duplicated {
        return Err("这把公钥已经注册过了".into());
    }

    let id = format!(
        "key-{}{}",
        base36(now_ms()),
        crate::auth::random_hex(2) // 4 个十六进制字符，够区分同一毫秒内的两次注册
    );
    let entry_name = if name.trim().is_empty() {
        "未命名密钥".to_string()
    } else {
        name.trim().to_string()
    };
    let mut entry = Map::new();
    entry.insert("id".into(), json!(id));
    entry.insert("name".into(), json!(entry_name));
    entry.insert("key".into(), json!(normalized));
    entry.insert("createdAt".into(), json!(crate::util::iso8601_now()));
    keys.push(Value::Object(entry));
    panel.insert("publicKeys".into(), Value::Array(keys));
    raw["panel"] = Value::Object(panel);

    let config = normalize_config(&raw, file)?;
    Ok(AddKeyResult {
        raw,
        config,
        id,
        fingerprint,
    })
}

fn base36(mut value: u64) -> String {
    if value == 0 {
        return "0".into();
    }
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while value > 0 {
        out.push(DIGITS[(value % 36) as usize]);
        value /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// 删掉一把公钥（按 id 或指纹）
pub fn remove_public_key(file: &Path, id_or_fingerprint: &str) -> Result<MutateResult, String> {
    let mut raw = read_raw_config(file)?;
    let mut panel = raw
        .get("panel")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let keys: Vec<Value> = panel
        .get("publicKeys")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let target = id_or_fingerprint.trim().to_string();

    let next: Vec<Value> = keys
        .iter()
        .filter(|item| {
            if as_string(item.get("id")) == target {
                return false;
            }
            let text = as_string(item.get("key"));
            match normalize_public_key(&text) {
                Ok(key) => public_key_fingerprint(&key) != target,
                Err(_) => true,
            }
        })
        .cloned()
        .collect();
    if next.len() == keys.len() {
        return Err(format!("找不到要删除的密钥: {}", target));
    }
    panel.insert("publicKeys".into(), Value::Array(next));
    raw["panel"] = Value::Object(panel);
    let config = normalize_config(&raw, file)?;
    Ok(MutateResult { raw, config })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tunnel_from_payload_keeps_field_order() {
        let payload = json!({
            "id": "app",
            "name": "项目 Web",
            "description": "说明",
            "localPort": 8080,
            "target": { "host": "10.0.0.12", "port": 80 },
            "via": { "user": "deploy", "host": "edge.test", "port": 22 },
            "auth": { "mode": "key" },
            "url": "/login",
            "autoStart": true
        });
        let tunnel = tunnel_from_payload(&payload, None).unwrap();
        let keys: Vec<&str> = tunnel.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["id", "name", "description", "localPort", "target", "via", "auth", "url", "autoStart"]
        );
    }

    #[test]
    fn tunnel_from_payload_keeps_handwritten_fields() {
        let previous = json!({
            "id": "app",
            "localPort": 8080,
            "via": "d@e.test:22",
            "env": { "FAKE_SSH_MODE": "ok" },
            "sshBin": ["/usr/bin/node", "fake-ssh.mjs"],
            "handwritten": "别动我"
        });
        let payload = json!({
            "id": "app",
            "localPort": 8080,
            "via": { "host": "e.test", "port": 22 }
        });
        let tunnel = tunnel_from_payload(&payload, Some(&previous)).unwrap();
        // env / sshBin 是显式保留键；其它未知键（handwritten）JS 版也不会保留，这里跟着不保留
        assert!(tunnel.get("env").is_some());
        assert!(tunnel.get("sshBin").is_some());
        assert!(tunnel.get("handwritten").is_none());
    }

    #[test]
    fn clear_password_flag_drops_the_secret() {
        let previous = json!({
            "id": "app", "localPort": 8080, "via": "d@e.test:22",
            "auth": { "mode": "password", "password": "enc:v1:AAAA:BBBB:CCCC" }
        });
        let payload = json!({
            "id": "app", "localPort": 8080, "via": { "host": "e.test", "port": 22 },
            "auth": { "mode": "key", "clearPassword": true }
        });
        let tunnel = tunnel_from_payload(&payload, Some(&previous)).unwrap();
        assert!(tunnel["auth"].get("password").is_none());
        assert_eq!(tunnel["auth"]["mode"], json!("key"));
    }

    #[test]
    fn invalid_id_and_missing_via_are_rejected() {
        let err = tunnel_from_payload(&json!({ "id": "带 中文", "localPort": 8080, "via": "d@e:22" }), None)
            .unwrap_err();
        assert!(err.contains("id 只能包含"));
        let err = tunnel_from_payload(&json!({ "id": "a", "localPort": 8080 }), None).unwrap_err();
        assert!(err.contains("via.host"));
    }

    #[test]
    fn numeric_strings_are_normalised_to_numbers() {
        let tunnel = tunnel_from_payload(
            &json!({
                "id": "a",
                "localPort": "8080",
                "target": { "host": "10.0.0.1", "port": "80" },
                "via": { "host": "e.test", "port": "2222" }
            }),
            None,
        )
        .unwrap();
        // 落盘必须是整数，不能写成 8080.0（否则整份文件都会被 diff）
        assert_eq!(tunnel["localPort"], json!(8080));
        assert_eq!(tunnel["target"]["port"], json!(80));
        assert_eq!(tunnel["via"]["port"], json!(2222));
    }

    #[test]
    fn settings_reject_invalid_strict_host_key_checking() {
        let file = std::env::temp_dir().join(format!("ssh-proxy-unit-{}.json", std::process::id()));
        std::fs::write(&file, "{\"tunnels\":[]}").unwrap();
        let err = mutate_settings(&file, &json!({ "ssh": { "strictHostKeyChecking": "maybe" } })).unwrap_err();
        assert!(err.contains("StrictHostKeyChecking"));
        let _ = std::fs::remove_file(&file);
    }
}