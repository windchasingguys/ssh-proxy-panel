//! 通用工具 —— 对应 `src/util.mjs` 里 Rust 需要的部分：探活、时间、原子写 JSON、抖动随机数。

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// TCP 探活：能建立连接即认为端口可用（对应 `probeTcp`）
pub async fn probe_tcp(port: u16, host: &str, timeout_ms: u64) -> bool {
    let addr = match parse_socket_addr(host, port) {
        Some(addr) => addr,
        None => return false,
    };
    matches!(
        tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

fn parse_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    // 主机名：交给 tokio 的 to_socket_addrs 太重，这里只处理回环与字面量
    if host == "localhost" {
        return Some(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port));
    }
    None
}

/// HTTP 探活：`status < 500` 算通（对应 `probeHttp`）。
/// 目前只发 HTTP/1.1（https 会退化成 TCP 探测，见 `70_Rust迁移评估.md` 的遗留项）。
pub async fn probe_http(url: &str, timeout_ms: u64) -> bool {
    let Some((scheme, host, port, path)) = split_http_url(url) else {
        return false;
    };
    if scheme == "https" {
        return probe_tcp(port, &host, timeout_ms).await;
    }

    let fut = async {
        let mut stream = TcpStream::connect(parse_socket_addr(&host, port)?).await.ok()?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nUser-Agent: ssh-proxy-probe\r\n\r\n",
            path, host, port
        );
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await.ok()?;
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        let status = head.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        Some(status < 500)
    };
    tokio::time::timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

fn split_http_url(url: &str) -> Option<(String, String, u16, String)> {
    let (scheme_raw, rest) = url.split_once("://")?;
    let scheme = scheme_raw.to_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    let default_port = if scheme == "https" { 443 } else { 80 };

    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Some((scheme, host.to_string(), port, path));
    }
    match authority.rsplit_once(':') {
        Some((host, port_text)) if port_text.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = port_text.parse().ok()?;
            Some((scheme, host.to_string(), port, path))
        }
        _ => Some((scheme, authority.to_string(), default_port, path)),
    }
}

/// 0.0.0.0 / :: 归一成 127.0.0.1 再探（对应 `#probeHost`）
pub fn probe_host(bind_address: &str) -> String {
    match bind_address {
        "" | "0.0.0.0" | "::" => "127.0.0.1".to_string(),
        other => other.to_string(),
    }
}

fn rng_state() -> &'static AtomicU64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    &STATE
}

/// 0.0~1.0 的伪随机数（xorshift64*），只用于重连抖动，不用于安全用途
pub fn random_unit() -> f64 {
    let state = rng_state();
    let mut x = state.load(Ordering::Relaxed);
    if x == 0 {
        x = now_ms().wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407) | 1;
    }
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state.store(x, Ordering::Relaxed);
    let value = x.wrapping_mul(0x2545F4914F6CDD1D) >> 11;
    (value as f64) / ((1u64 << 53) as f64)
}

pub fn read_json_safe(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim_start_matches('\u{feff}');
    serde_json::from_str(text).ok()
}

/// 原子写 JSON（`<file>.<pid>.tmp` → rename），失败只记日志不抛
pub fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("创建目录失败: {}", e))?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let text = serde_json::to_string_pretty(value).map_err(|e| format!("序列化失败: {}", e))?;
    std::fs::write(&tmp, text).map_err(|e| format!("写入临时文件失败: {}", e))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("替换目标文件失败: {}", e))
}

/// `new Date().toISOString()` 的等价实现（UTC，毫秒 3 位，结尾 Z）
pub fn iso8601_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        millis
    )
}

/// Howard Hinnant 的 civil_from_days
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}