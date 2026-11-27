//! 面板登录态：会话、Cookie、登录频率限制 —— 对应 `server.mjs` 的会话层。
//!
//! 会话只存在内存里（`serve` 重启即全部失效，这是设计而非缺陷）；
//! Cookie 用 `HttpOnly; SameSite=Strict`，非 GET 请求另外校验 `Origin.host === Host` 防 CSRF。

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

use crate::auth::random_token;
use crate::util::now_ms;

pub const SESSION_COOKIE: &str = "sshproxy_session";
pub const MAX_SESSIONS: usize = 32;
const LOGIN_MAX_FAILURES: u32 = 5;
const LOGIN_LOCK_MS: u64 = 30_000;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub created_at: u64,
    pub last_seen: u64,
    pub expires_at: u64,
    pub idle_until: u64,
    #[serde(skip)]
    pub idle_ms: u64,
    pub method: String,
}

#[derive(Default)]
struct Guard {
    failures: u32,
    until: u64,
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    guard: Mutex<Guard>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            guard: Mutex::new(Guard::default()),
        }
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_guard(&self) -> std::sync::MutexGuard<'_, Guard> {
        self.guard.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn create(&self, method: &str, ttl_ms: u64, idle_ms: u64) -> String {
        let id = random_token(24);
        let now = now_ms();
        let session = Session {
            created_at: now,
            last_seen: now,
            expires_at: now + ttl_ms,
            idle_until: now + idle_ms,
            idle_ms,
            method: method.to_string(),
        };
        let mut sessions = self.lock_sessions();
        sessions.insert(id.clone(), session);
        if sessions.len() > MAX_SESSIONS {
            // 淘汰最久未使用的那条
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest);
            }
        }
        id
    }

    /// 校验并续期（滑动过期）。返回 `Err(reason)`：`unknown` / `expired` / `idle`
    pub fn touch(&self, id: &str) -> Result<Session, &'static str> {
        let mut sessions = self.lock_sessions();
        let Some(session) = sessions.get_mut(id) else {
            return Err("unknown");
        };
        let now = now_ms();
        if now > session.expires_at {
            sessions.remove(id);
            return Err("expired");
        }
        if now > session.idle_until {
            sessions.remove(id);
            return Err("idle");
        }
        session.last_seen = now;
        session.idle_until = now + session.idle_ms;
        Ok(session.clone())
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        self.lock_sessions().get(id).cloned()
    }

    pub fn remove(&self, id: &str) {
        self.lock_sessions().remove(id);
    }

    pub fn sweep(&self) {
        let now = now_ms();
        let mut sessions = self.lock_sessions();
        sessions.retain(|_, s| now <= s.expires_at && now <= s.idle_until);
    }

    /// 登录锁还剩多少秒（0 表示没锁）
    pub fn guard_seconds_left(&self) -> u64 {
        let guard = self.lock_guard();
        let now = now_ms();
        if guard.until > now {
            (guard.until - now).div_ceil(1000)
        } else {
            0
        }
    }

    pub fn record_failure(&self) {
        let mut guard = self.lock_guard();
        guard.failures += 1;
        if guard.failures >= LOGIN_MAX_FAILURES {
            guard.failures = 0;
            guard.until = now_ms() + LOGIN_LOCK_MS;
        }
    }

    pub fn clear_guard(&self) {
        let mut guard = self.lock_guard();
        guard.failures = 0;
        guard.until = 0;
    }
}

/// 从 `Cookie` 头里取某个值（对应 `readCookie`）
pub fn read_cookie(header: Option<&str>, name: &str) -> String {
    let Some(raw) = header else {
        return String::new();
    };
    if raw.is_empty() {
        return String::new();
    }
    for part in raw.split(';') {
        let Some(idx) = part.find('=') else {
            continue;
        };
        if part[..idx].trim() != name {
            continue;
        }
        let value = part[idx + 1..].trim();
        return percent_decode(value);
    }
    String::new()
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn session_cookie(id: &str, max_age_seconds: u64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_COOKIE, id, max_age_seconds
    )
}

pub fn clear_cookie() -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        SESSION_COOKIE
    )
}

/// Cookie 会话必须防跨站表单提交：带 Origin 且和 Host 不一致就拒绝
pub fn same_origin(origin: Option<&str>, host: Option<&str>) -> bool {
    let Some(origin) = origin.filter(|v| !v.is_empty()) else {
        return true;
    };
    let host = host.unwrap_or("");
    let Some((_, rest)) = origin.split_once("://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    authority.eq_ignore_ascii_case(host)
}
