//! HTTP 面 —— 对应 `src/server.mjs`（里程碑 M3：只读面 + 启停 + SSE + 三方式登录/会话 + 静态资源）。
//!
//! 未实现（M4）：配置编辑 API（`POST/PUT/DELETE /api/tunnels*`、`/api/settings`、`/api/auth/keys`）。

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::auth::{new_challenge, random_hex, safe_equal, verify_password, verify_signature};
use crate::config::{form_view, load_config, Config};
use crate::config_writer;
use crate::session::{
    clear_cookie, read_cookie, same_origin, session_cookie, SessionStore, SESSION_COOKIE,
};
use crate::supervisor::{Event, Supervisor};
use crate::util::now_ms;

pub type Resp = Response<BoxBody<Bytes, Infallible>>;

pub struct ChallengeEntry {
    pub challenge: String,
    pub key_id: String,
    pub expires_at: u64,
}

pub struct State {
    pub supervisor: Arc<Supervisor>,
    pub sessions: SessionStore,
    pub challenges: Mutex<HashMap<String, ChallengeEntry>>,
}

impl State {
    pub fn new(supervisor: Arc<Supervisor>) -> Self {
        Self {
            supervisor,
            sessions: SessionStore::new(),
            challenges: Mutex::new(HashMap::new()),
        }
    }

    /// 前端资源版本号：`app.js` + `style.css` 的最大 mtime（毫秒，取整）与体积之和，
    /// 与 `server.mjs` 的 `assetVersion()` 格式一致（`<mtimeMs>-<sizeSum>`，出错 `0`）。
    pub fn asset_version(&self) -> String {
        let dir = crate::web_root();
        let mut mtime_ms: u128 = 0;
        let mut total_size: u64 = 0;
        for name in ["app.js", "style.css"] {
            let Ok(meta) = std::fs::metadata(dir.join(name)) else {
                return "0".to_string();
            };
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis())
                .unwrap_or(0);
            mtime_ms = mtime_ms.max(modified);
            total_size += meta.len();
        }
        format!("{}-{}", mtime_ms, total_size)
    }
}

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

fn full(bytes: impl Into<Bytes>) -> BoxBody<Bytes, Infallible> {
    Full::new(bytes.into()).boxed()
}

fn json_response(status: StatusCode, value: &Value) -> Resp {
    let mut res = Response::new(full(value.to_string()));
    *res.status_mut() = status;
    res.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    with_common_headers(res)
}

fn text_response(status: StatusCode, content_type: &'static str, body: impl Into<String>) -> Resp {
    let mut res = Response::new(full(body.into()));
    *res.status_mut() = status;
    res.headers_mut()
        .insert("content-type", HeaderValue::from_static(content_type));
    with_common_headers(res)
}

fn with_common_headers(mut res: Resp) -> Resp {
    let headers = res.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    res
}

async fn read_json_body(req: Request<Incoming>) -> Result<Value, ApiError> {
    let body = req
        .into_body()
        .collect()
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("读取请求体失败: {}", e)))?
        .to_bytes();
    if body.len() > 256 * 1024 {
        return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "请求体过大"));
    }
    if body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&body)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, format!("请求体不是合法 JSON: {}", e)))
}

/// 请求里跟鉴权相关的头，先摘出来（后面 body 会被消费掉）
struct Headers {
    cookie: Option<String>,
    origin: Option<String>,
    host: Option<String>,
    token: Option<String>,
}

impl Headers {
    fn from_request(req: &Request<Incoming>) -> Self {
        let text = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_string())
        };
        Self {
            cookie: text("cookie"),
            origin: text("origin"),
            host: text("host"),
            token: text("x-panel-token"),
        }
    }
}

enum Denied {
    Expired,
    Idle,
    /// Cookie 里的会话已经不在表里（重启 / 被淘汰 / 已退出）
    Unknown,
    Missing,
}

fn ttl_ms(config: &Config) -> u64 {
    ((config.panel.session_ttl_minutes * 60_000.0) as u64).max(1000)
}

fn idle_ms(config: &Config) -> u64 {
    ((config.panel.session_idle_minutes * 60_000.0) as u64).max(1000)
}

/// 鉴权：会话 Cookie（浏览器），或请求头 / 查询串里的令牌（脚本 / CLI）。
/// 没配置任何登录方式时直接放行。
fn authenticate(
    state: &State,
    config: &Config,
    headers: &Headers,
    query: &str,
) -> Result<&'static str, Denied> {
    if config.panel.auth_methods.is_empty() {
        return Ok("none");
    }
    if let Some(cookie) = headers.cookie.as_deref() {
        let id = read_cookie(Some(cookie), SESSION_COOKIE);
        if !id.is_empty() {
            return match state.sessions.touch(&id) {
                Ok(_) => Ok("session"),
                Err("expired") => Err(Denied::Expired),
                Err("idle") => Err(Denied::Idle),
                Err(_) => Err(Denied::Unknown),
            };
        }
    }
    if config.panel.auth_methods.iter().any(|m| m == "token") {
        if let Some(header) = headers.token.as_deref().filter(|v| !v.is_empty()) {
            if safe_equal(header, &config.panel.token) {
                return Ok("token");
            }
        }
        if let Some(token) = query_param(query, "token").filter(|v| !v.is_empty()) {
            if safe_equal(&token, &config.panel.token) {
                return Ok("token");
            }
        }
    }
    Err(Denied::Missing)
}

/// Node 的登录响应是 `{ ok: true, ...sessionInfo }`，`ok` 在最前面；键序也要一致
fn with_ok_first(info: Value) -> Value {
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    if let Some(map) = info.as_object() {
        for (key, value) in map {
            out.insert(key.clone(), value.clone());
        }
    }
    Value::Object(out)
}

fn session_info(state: &State, config: &Config, id: Option<&str>) -> Value {
    let session = id.and_then(|id| state.sessions.get(id));
    let now = now_ms();
    let valid = session
        .as_ref()
        .map(|s| now <= s.expires_at && now <= s.idle_until)
        .unwrap_or(false);
    let methods = config.panel.auth_methods.clone();
    let keys: Vec<Value> = config
        .panel
        .public_keys
        .iter()
        .map(|k| json!({ "id": k.id, "name": k.name, "fingerprint": k.fingerprint }))
        .collect();

    json!({
        "authRequired": !methods.is_empty(),
        "authenticated": methods.is_empty() || valid,
        "method": if valid { session.as_ref().map(|s| s.method.clone()) } else { None },
        "expiresAt": if valid { session.as_ref().map(|s| s.expires_at) } else { None },
        "idleUntil": if valid { session.as_ref().map(|s| s.idle_until) } else { None },
        "ttlMinutes": config.panel.session_ttl_minutes,
        "idleMinutes": config.panel.session_idle_minutes,
        "tokenSource": config.panel.token_source,
        "methods": methods,
        "keyCount": keys.len(),
        "keys": if valid { keys } else { Vec::new() },
    })
}

async fn route(state: Arc<State>, req: Request<Incoming>) -> Result<Resp, Infallible> {
    match handle(state, req).await {
        Ok(res) => Ok(res),
        Err(err) => Ok(json_response(err.status, &json!({ "error": err.message }))),
    }
}

async fn handle(state: Arc<State>, req: Request<Incoming>) -> Result<Resp, ApiError> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers = Headers::from_request(&req);
    let config = state.supervisor.config_clone().await;

    // 不需要鉴权：只暴露"要不要登录 / 有哪些登录方式 / 前端资源版本"
    if path == "/healthz" && method == Method::GET {
        let snapshot = state.supervisor.snapshot().await;
        return Ok(json_response(
            StatusCode::OK,
            &json!({
                "ok": true,
                "up": snapshot["stats"]["up"],
                "authRequired": !config.panel.auth_methods.is_empty(),
                "methods": config.panel.auth_methods,
                "tokenSource": config.panel.token_source,
                "version": state.asset_version(),
            }),
        ));
    }

    // 登录态
    if path == "/api/session" {
        return handle_session(&state, &config, &headers, req).await;
    }

    // 公钥登录的挑战（公开：没登录才需要它）
    if path == "/api/auth/challenge" && method == Method::GET {
        let key_id = query_param(&query, "keyId").unwrap_or_default();
        return match issue_challenge(&state, &config, &key_id) {
            Some(value) => Ok(json_response(StatusCode::OK, &value)),
            None => Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "找不到这把密钥，可能已被删除；请用令牌或密码登录后重新注册",
            )),
        };
    }

    if path.starts_with("/api/") {
        if let Err(reason) = authenticate(&state, &config, &headers, &query) {
            let (message, expired) = match reason {
                Denied::Expired => ("登录已过期，请重新输入令牌", true),
                Denied::Idle => ("太久没有操作，登录已失效", true),
                Denied::Unknown => ("需要访问令牌", true),
                Denied::Missing => ("需要访问令牌", false),
            };
            // 与 Node 一致：401 一定带 sessionExpired 布尔（前端据此决定弹不弹"请重新登录"）
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({ "error": message, "authRequired": true, "sessionExpired": expired }),
            ));
        }
        if method != Method::GET && method != Method::HEAD {
            if !same_origin(headers.origin.as_deref(), headers.host.as_deref()) {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "跨站请求被拒绝"));
            }
        }
        return handle_api(&state, &config, method, path, query, req).await;
    }

    // 静态资源
    if method != Method::GET && method != Method::HEAD {
        return Ok(json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            &json!({ "error": "不支持的方法" }),
        ));
    }
    Ok(serve_static(&path, &state.asset_version()))
}

// ---------------------------------------------------------------- 会话

async fn handle_session(
    state: &Arc<State>,
    config: &Config,
    headers: &Headers,
    req: Request<Incoming>,
) -> Result<Resp, ApiError> {
    let method = req.method().clone();

    if method == Method::GET {
        let id = headers
            .cookie
            .as_deref()
            .map(|c| read_cookie(Some(c), SESSION_COOKIE))
            .filter(|v| !v.is_empty());
        return Ok(json_response(
            StatusCode::OK,
            &session_info(state, config, id.as_deref()),
        ));
    }

    if !same_origin(headers.origin.as_deref(), headers.host.as_deref()) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "跨站请求被拒绝"));
    }

    if method == Method::POST {
        let wait = state.sessions.guard_seconds_left();
        if wait > 0 {
            return Ok(json_response(
                StatusCode::TOO_MANY_REQUESTS,
                &json!({
                    "error": format!("尝试太频繁，请 {} 秒后再试", wait),
                    "retryAfter": wait,
                }),
            ));
        }
        let body = read_json_body(req).await?;
        let methods = config.panel.auth_methods.clone();
        if methods.is_empty() {
            let info = with_ok_first(session_info(state, config, None));
            return Ok(json_response(StatusCode::OK, &info));
        }
        let mode = body
            .get("mode")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .unwrap_or("token")
            .to_string();
        if !methods.contains(&mode) {
            return Ok(json_response(
                StatusCode::BAD_REQUEST,
                &json!({ "error": format!("未启用这种登录方式: {}", mode), "methods": methods }),
            ));
        }

        let passed = match mode.as_str() {
            "token" => {
                let given = body
                    .get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                !given.is_empty() && safe_equal(&given, &config.panel.token)
            }
            "password" => verify_password(
                body.get("password").and_then(|v| v.as_str()).unwrap_or(""),
                &config.panel.password_hash,
            ),
            "key" => verify_key_login(state, config, &body),
            _ => false,
        };

        if !passed {
            state.sessions.record_failure();
            let message = match mode.as_str() {
                "password" => "密码不正确",
                "key" => "密钥签名校验失败",
                _ => "令牌不正确",
            };
            return Ok(json_response(
                StatusCode::UNAUTHORIZED,
                &json!({ "error": message, "mode": mode }),
            ));
        }

        state.sessions.clear_guard();
        let id = state
            .sessions
            .create(&mode, ttl_ms(config), idle_ms(config));
        let info = with_ok_first(session_info(state, config, Some(&id)));
        let mut res = json_response(StatusCode::OK, &info);
        let max_age = ttl_ms(config) / 1000;
        res.headers_mut().insert(
            "set-cookie",
            HeaderValue::from_str(&session_cookie(&id, max_age))
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        return Ok(res);
    }

    if method == Method::DELETE {
        if let Some(cookie) = headers.cookie.as_deref() {
            let sid = read_cookie(Some(cookie), SESSION_COOKIE);
            if !sid.is_empty() {
                state.sessions.remove(&sid);
            }
        }
        let mut res = json_response(
            StatusCode::OK,
            &json!({
                "ok": true,
                "authRequired": !config.panel.auth_methods.is_empty(),
                "authenticated": config.panel.auth_methods.is_empty(),
            }),
        );
        res.headers_mut()
            .insert("set-cookie", HeaderValue::from_str(&clear_cookie()).unwrap());
        return Ok(res);
    }

    Ok(json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        &json!({ "error": format!("不支持的方法: {}", method.as_str()) }),
    ))
}

fn issue_challenge(state: &State, config: &Config, key_id: &str) -> Option<Value> {
    let key = config.panel.public_keys.iter().find(|k| k.id == key_id)?;
    let id = random_hex(12);
    let challenge = new_challenge();
    let now = now_ms();
    {
        let mut challenges = state.challenges.lock().unwrap_or_else(|e| e.into_inner());
        challenges.insert(
            id.clone(),
            ChallengeEntry {
                challenge: challenge.clone(),
                key_id: key.id.clone(),
                expires_at: now + 120_000,
            },
        );
        challenges.retain(|_, entry| now <= entry.expires_at);
    }
    Some(json!({
        "challengeId": id,
        "challenge": challenge,
        "keyId": key.id,
        "expiresIn": 120,
    }))
}

fn verify_key_login(state: &State, config: &Config, body: &Value) -> bool {
    let challenge_id = body
        .get("challengeId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let signature = body
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if challenge_id.is_empty() || signature.is_empty() {
        return false;
    }
    let entry = {
        // 一次性：先删再验，防重放
        let mut challenges = state.challenges.lock().unwrap_or_else(|e| e.into_inner());
        challenges.remove(challenge_id)
    };
    let Some(entry) = entry else {
        return false;
    };
    if now_ms() > entry.expires_at {
        return false;
    }
    let Some(key) = config
        .panel
        .public_keys
        .iter()
        .find(|k| k.id == entry.key_id)
    else {
        return false;
    };
    verify_signature(&key.key, &entry.challenge, signature)
}

// ---------------------------------------------------------------- 业务路由

async fn handle_api(
    state: &Arc<State>,
    config: &Config,
    method: Method,
    path: String,
    query: String,
    req: Request<Incoming>,
) -> Result<Resp, ApiError> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    match (path.as_str(), method.as_str()) {
        ("/api/state", "GET") => {
            return Ok(json_response(StatusCode::OK, &state.supervisor.snapshot().await));
        }
        ("/api/config", "GET") => {
            return Ok(json_response(StatusCode::OK, &form_view(config)));
        }
        ("/api/events", "GET") => {
            return Ok(sse_response(state.clone()));
        }
        ("/api/all/start", "POST") => {
            state.supervisor.start_all().await;
            return Ok(json_response(
                StatusCode::OK,
                &json!({ "ok": true, "state": state.supervisor.snapshot().await }),
            ));
        }
        ("/api/all/stop", "POST") => {
            state.supervisor.stop_all().await;
            return Ok(json_response(
                StatusCode::OK,
                &json!({ "ok": true, "state": state.supervisor.snapshot().await }),
            ));
        }
        ("/api/reload", "POST") => {
            let config_file = config.config_file.clone();
            let next = load_config(&config_file.to_string_lossy())
                .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
            let mut result = state.supervisor.reload(next).await;
            if let Some(map) = result.as_object_mut() {
                map.insert("ok".into(), json!(true));
            }
            return Ok(json_response(StatusCode::OK, &result));
        }
        ("/api/shutdown", "POST") => {
            let supervisor = state.supervisor.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(250)).await;
                supervisor.shutdown().await;
                std::process::exit(0);
            });
            return Ok(json_response(
                StatusCode::OK,
                &json!({ "ok": true, "stopping": true }),
            ));
        }
        _ => {}
    }

    // ---- 配置编辑：新建隧道
    if path == "/api/tunnels" && method == "POST" {
        let body = read_json_body(req).await?;
        let payload = with_encrypted_auth(config, &body)?;
        let config_file = config.config_file.clone();
        let result = config_writer::mutate_tunnels(&config_file, "create", "", &payload)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        config_writer::write_raw_config(&config_file, &result.raw)
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        apply_config(&state, result.config).await;
        let new_id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let tunnel = state.supervisor.snapshot_tunnel(new_id).await.unwrap_or(Value::Null);
        return Ok(json_response(
            StatusCode::OK,
            &json!({ "ok": true, "tunnel": tunnel, "state": state.supervisor.snapshot().await }),
        ));
    }

    // ---- 配置编辑：改 / 删单条隧道
    if segments.len() == 3 && segments[1] == "tunnels" && matches!(method.as_str(), "PUT" | "PATCH" | "DELETE") {
        let id = decode_segment(segments[2]);
        let was_running = state.supervisor.is_desired(&id);
        let config_file = config.config_file.clone();
        let payload = if method == "DELETE" {
            Value::Null
        } else {
            with_encrypted_auth(config, &read_json_body(req).await?)?
        };
        let action = if method == "DELETE" { "delete" } else { "update" };
        let result = config_writer::mutate_tunnels(&config_file, action, &id, &payload)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        config_writer::write_raw_config(&config_file, &result.raw)
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        apply_config(&state, result.config).await;
        let new_id = if method == "DELETE" {
            None
        } else {
            let candidate = payload
                .get("id")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| id.clone());
            Some(candidate)
        };
        if let Some(new_id) = &new_id {
            if new_id != &id && was_running {
                let _ = state.supervisor.start(new_id, true).await;
            }
        }
        let tunnel = match &new_id {
            Some(new_id) => state.supervisor.snapshot_tunnel(new_id).await.unwrap_or(Value::Null),
            None => Value::Null,
        };
        return Ok(json_response(
            StatusCode::OK,
            &json!({
                "ok": true,
                "id": new_id,
                "tunnel": tunnel,
                "state": state.supervisor.snapshot().await,
            }),
        ));
    }

    // ---- 配置编辑：全局设置（ssh / supervision / 门户参数）
    if path == "/api/settings" && matches!(method.as_str(), "PUT" | "PATCH") {
        let body = read_json_body(req).await?;
        let config_file = config.config_file.clone();
        let result = config_writer::mutate_settings(&config_file, &body)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        config_writer::write_raw_config(&config_file, &result.raw)
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        // panel.token / 会话时效只落盘，不热应用；前端据此提示要重启
        let panel_changed = result.config.panel.token != config.panel.token
            || result.config.panel.session_ttl_minutes != config.panel.session_ttl_minutes
            || result.config.panel.session_idle_minutes != config.panel.session_idle_minutes;
        let next = result.config;
        let ssh = serde_json::to_value(&next.ssh).unwrap_or(Value::Null);
        let supervision = serde_json::to_value(&next.supervision).unwrap_or(Value::Null);
        let token_required = !next.panel.token.is_empty();
        let ttl = next.panel.session_ttl_minutes;
        let idle = next.panel.session_idle_minutes;
        apply_config(&state, next).await;
        return Ok(json_response(
            StatusCode::OK,
            &json!({
                "ok": true,
                "restartRequired": panel_changed,
                "ssh": ssh,
                "supervision": supervision,
                "panel": {
                    "tokenRequired": token_required,
                    "sessionTtlMinutes": ttl,
                    "sessionIdleMinutes": idle,
                },
                "state": state.supervisor.snapshot().await,
            }),
        ));
    }

    // ---- 注册公钥（纯增量，热应用即可）
    if path == "/api/auth/keys" && method == "POST" {
        let body = read_json_body(req).await?;
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let key = body.get("publicKey").and_then(|v| v.as_str()).unwrap_or("");
        let config_file = config.config_file.clone();
        let result = config_writer::add_public_key(&config_file, name, key)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        config_writer::write_raw_config(&config_file, &result.raw)
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let id = result.id.clone();
        let fingerprint = result.fingerprint.clone();
        apply_config(&state, result.config).await;
        let fresh = state.supervisor.config_clone().await;
        let methods = fresh.panel.auth_methods.clone();
        let keys: Vec<Value> = fresh
            .panel
            .public_keys
            .iter()
            .map(|k| json!({ "id": k.id, "name": k.name, "fingerprint": k.fingerprint }))
            .collect();
        return Ok(json_response(
            StatusCode::OK,
            &json!({ "ok": true, "id": id, "fingerprint": fingerprint, "methods": methods, "keys": keys }),
        ));
    }

    // ---- 删除公钥（不能删掉最后一种登录方式）
    if segments.len() == 4 && segments[1] == "auth" && segments[2] == "keys" && method == "DELETE" {
        let target = decode_segment(segments[3]);
        let config_file = config.config_file.clone();
        let result = config_writer::remove_public_key(&config_file, &target)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
        if result.config.panel.auth_methods.is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "删掉这把密钥后就没有任何登录方式了（面板会变成开放的），先设置令牌或密码再删",
            ));
        }
        config_writer::write_raw_config(&config_file, &result.raw)
            .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e))?;
        apply_config(&state, result.config).await;
        let fresh = state.supervisor.config_clone().await;
        let methods = fresh.panel.auth_methods.clone();
        let keys: Vec<Value> = fresh
            .panel
            .public_keys
            .iter()
            .map(|k| json!({ "id": k.id, "name": k.name, "fingerprint": k.fingerprint }))
            .collect();
        return Ok(json_response(
            StatusCode::OK,
            &json!({ "ok": true, "methods": methods, "keys": keys }),
        ));
    }

    if segments.len() == 4 && segments[1] == "tunnels" {
        let id = decode_segment(segments[2]);
        if !state.supervisor.has_tunnel(&id) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("未知隧道: {}", id),
            ));
        }
        match (segments[3], method.as_str()) {
            ("logs", "GET") => {
                let lines: usize = query_param(&query, "lines")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(200);
                let entries = state
                    .supervisor
                    .logs(&id, lines)
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "id": id, "lines": entries }),
                ));
            }
            ("start", "POST") => {
                let tunnel = state
                    .supervisor
                    .start(&id, true)
                    .await
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "ok": true, "tunnel": tunnel, "state": state.supervisor.snapshot().await }),
                ));
            }
            ("stop", "POST") => {
                let tunnel = state
                    .supervisor
                    .stop(&id)
                    .await
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "ok": true, "tunnel": tunnel, "state": state.supervisor.snapshot().await }),
                ));
            }
            ("restart", "POST") => {
                let tunnel = state
                    .supervisor
                    .restart(&id)
                    .await
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "ok": true, "tunnel": tunnel, "state": state.supervisor.snapshot().await }),
                ));
            }
            ("secret", "POST") => {
                let body = read_json_body(req).await?;
                let value = body.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let tunnel = state
                    .supervisor
                    .set_secret(&id, value)
                    .await
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "ok": true, "tunnel": tunnel, "state": state.supervisor.snapshot().await }),
                ));
            }
            ("secret", "DELETE") => {
                let tunnel = state
                    .supervisor
                    .forget_secret(&id)
                    .await
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "ok": true, "tunnel": tunnel }),
                ));
            }
            _ => {}
        }
    }

    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        format!("未知接口: {} {}", method.as_str(), path),
    ))
}

// ---------------------------------------------------------------- 配置编辑辅助

/// 表单里的明文密码 / 口令 → 加密后再落盘（对应 `withEncryptedAuth`）
fn with_encrypted_auth(config: &Config, payload: &Value) -> Result<Value, ApiError> {
    let Some(auth) = payload.get("auth").and_then(|a| a.as_object()) else {
        return Ok(payload.clone());
    };
    let data_dir = config
        .config_file
        .parent()
        .map(|p| p.join(".ssh-proxy"))
        .unwrap_or_else(|| PathBuf::from(".ssh-proxy"));

    let mut next_auth = auth.clone();
    for key in ["password", "passphrase"] {
        if let Some(Value::String(text)) = auth.get(key) {
            if !text.is_empty() {
                let encrypted = crate::secrets::encrypt_secret(&data_dir, text)
                    .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e))?;
                next_auth.insert(key.into(), json!(encrypted));
            }
        }
    }
    let mut out = payload.clone();
    if let Some(map) = out.as_object_mut() {
        map.insert("auth".into(), Value::Object(next_auth));
    }
    Ok(out)
}

/// 配置变更后的统一入口（对应 `applyConfig`）：
/// 门户参数只落盘不热应用；密码/公钥这类凭据可以热加，但要按实际生效的凭据重算可用方式。
async fn apply_config(state: &Arc<State>, mut next: Config) {
    let current = state.supervisor.config_clone().await;
    next.panel.host = current.panel.host.clone();
    next.panel.port = current.panel.port;
    next.panel.token = current.panel.token.clone();
    next.panel.token_source = current.panel.token_source.clone();
    next.panel.session_ttl_minutes = current.panel.session_ttl_minutes;
    next.panel.session_idle_minutes = current.panel.session_idle_minutes;

    let mut methods: Vec<String> = Vec::new();
    if !next.panel.token.is_empty() {
        methods.push("token".into());
    }
    if !next.panel.password_hash.is_empty() {
        methods.push("password".into());
    }
    if !next.panel.public_keys.is_empty() {
        methods.push("key".into());
    }
    let wanted = next.panel.auth_methods.clone();
    let allowed: Vec<String> = if wanted.is_empty() {
        methods.clone()
    } else {
        methods
            .iter()
            .filter(|m| wanted.contains(m))
            .cloned()
            .collect()
    };
    next.panel.auth_methods = if allowed.is_empty() { methods } else { allowed };

    let _ = state.supervisor.reload(next).await;
}

// ---------------------------------------------------------------- 静态资源

const MIME: &[(&str, &str)] = &[
    (".html", "text/html; charset=utf-8"),
    (".js", "text/javascript; charset=utf-8"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".css", "text/css; charset=utf-8"),
    (".json", "application/json; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".png", "image/png"),
    (".ico", "image/x-icon"),
    (".woff2", "font/woff2"),
];

fn mime_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    MIME.iter()
        .find(|(suffix, _)| *suffix == ext)
        .map(|(_, value)| *value)
        .unwrap_or("application/octet-stream")
}

/// 与 `serveStatic` 等价：解码 → 归一化 → 拒绝路径穿越 → 读文件（HTML 注入 `?v=`）
fn serve_static(pathname: &str, asset_version: &str) -> Resp {
    let decoded = decode_segment(pathname);
    let rel = if decoded == "/" || decoded.is_empty() {
        "/index.html".to_string()
    } else {
        decoded
    };
    let root = crate::web_root();
    let root = std::fs::canonicalize(&root).unwrap_or(root);

    // 与 `path.normalize` 一致：越过根的 `..` 直接丢弃（所以 /..%2f..%2fx 会变成 /x，找不到就 404，
    // 而不是 403；只有解析出盘符/根这类绝对路径才拒绝）
    let mut rel_path = PathBuf::new();
    for part in PathBuf::from(rel.trim_start_matches(['/', '\\'])).components() {
        match part {
            Component::Normal(name) => rel_path.push(name),
            Component::ParentDir => {
                rel_path.pop();
            }
            Component::CurDir => {}
            _ => {
                return text_response(StatusCode::FORBIDDEN, "text/plain; charset=utf-8", "forbidden")
            }
        }
    }
    let target = root.join(rel_path);
    if !target.starts_with(&root) {
        return text_response(StatusCode::FORBIDDEN, "text/plain; charset=utf-8", "forbidden");
    }

    let Ok(data) = std::fs::read(&target) else {
        return text_response(StatusCode::NOT_FOUND, "text/plain; charset=utf-8", "not found");
    };

    let is_html = target
        .extension()
        .map(|e| e.eq_ignore_ascii_case("html"))
        .unwrap_or(false);
    let body = if is_html {
        let text = String::from_utf8_lossy(&data)
            .replace(
                "href=\"/style.css\"",
                &format!("href=\"/style.css?v={}\"", asset_version),
            )
            .replace(
                "src=\"/app.js\"",
                &format!("src=\"/app.js?v={}\"", asset_version),
            );
        Bytes::from(text)
    } else {
        Bytes::from(data)
    };

    let len = body.len();
    let mut res = Response::new(full(body));
    *res.status_mut() = StatusCode::OK;
    let headers = res.headers_mut();
    headers.insert("content-type", HeaderValue::from_static(mime_for(&target)));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "content-length",
        HeaderValue::from_str(&len.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    with_common_headers(res)
}

// ---------------------------------------------------------------- SSE

/// SSE：先推一次全量快照，随后 `change` 事件 100ms 去抖、`log` 事件逐条转发、25s 心跳
fn sse_response(state: Arc<State>) -> Resp {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(64);
    let supervisor = state.supervisor.clone();

    tokio::spawn(async move {
        let mut events = supervisor.subscribe();
        let mut first = true;
        let mut debounce: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

        loop {
            if first {
                first = false;
                let snapshot = supervisor.snapshot().await;
                if tx.send(Ok(sse_frame("state", &snapshot))).await.is_err() {
                    return;
                }
            }

            let tick = tokio::time::sleep(Duration::from_millis(25_000));
            tokio::pin!(tick);

            tokio::select! {
                event = events.recv() => {
                    match event {
                        Ok(Event::Change) => {
                            debounce = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
                        }
                        Ok(Event::Log { id, line }) => {
                            let payload = json!({ "id": id, "line": line });
                            if tx.send(Ok(sse_frame("log", &payload))).await.is_err() {
                                return;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            debounce = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
                        }
                        Err(_) => return,
                    }
                }
                _ = async { match debounce.as_mut() { Some(sleep) => sleep.as_mut().await, None => std::future::pending().await } } => {
                    debounce = None;
                    let snapshot = supervisor.snapshot().await;
                    if tx.send(Ok(sse_frame("state", &snapshot))).await.is_err() {
                        return;
                    }
                }
                _ = &mut tick => {
                    if tx.send(Ok(Frame::data(Bytes::from_static(b": ping\n\n")))).await.is_err() {
                        return;
                    }
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = StreamBody::new(stream).boxed();
    let mut res = Response::new(body);
    *res.status_mut() = StatusCode::OK;
    let headers = res.headers_mut();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    headers.insert("connection", HeaderValue::from_static("keep-alive"));
    res
}

fn sse_frame(name: &str, data: &Value) -> Frame<Bytes> {
    Frame::data(Bytes::from(format!("event: {}\ndata: {}\n\n", name, data)))
}

// ---------------------------------------------------------------- 小工具

fn query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if key == name {
            return Some(decode_segment(value));
        }
    }
    None
}

fn decode_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(value) = u8::from_str_radix(&segment[i + 1..i + 3], 16) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn serve(state: Arc<State>, host: &str, port: u16) -> Result<(), String> {
    let listener = TcpListener::bind((host, port))
        .await
        .map_err(|e| format!("面板监听 {}:{} 失败: {}", host, port, e))?;

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("接受连接失败: {}", err);
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { route(state, req).await }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });
    }
}

/// 起完服务后自己打一次 `/healthz`（`--self-check` 与启动横幅用）
pub async fn self_check(host: &str, port: u16) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| "连接超时".to_string())?
    .map_err(|e| format!("连接失败: {}", e))?;

    let request = format!(
        "GET /healthz HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        host, port
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("写入失败: {}", e))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("读取失败: {}", e))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
