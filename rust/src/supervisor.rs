//! 隧道状态机 —— 对应 `src/supervisor.mjs`。
//!
//! 语义逐条对齐 JS 版：六态、`desired` 与运行态分离、退避抖动与失败预算、稳定期清零、
//! 看门狗三态回收、孤儿回收、`state.json`/`runtime.json` 原子写、日志环形缓冲 400 行。
//!
//! 并发模型（踩过的坑，改之前先读）：
//!  - `inner` 是 **std** 互斥锁，绝不跨 `await` 持有；所有探测/等待都在锁外做。
//!  - 回到锁内时用代次号判断回调是否过期（`gen` = 连接代次，`retry_gen` = 重连代次），
//!    等价于 JS 的 `rt.child !== child` / `clearTimeout`。
//!  - 日志先在锁内塞进环形缓冲并收集，解锁后再统一打印 + 广播，避免锁内做 IO。

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::broadcast;

use crate::config::{AuthMode, Config, Supervision, Tunnel};
use crate::secrets::decrypt_secret;
use crate::ssh::{
    askpass_env, build_ssh_args, command_prefix, ensure_askpass_helper, format_command, kill_tree,
    open_url, process_alive, read_cmdline,
};
use crate::util::{
    now_ms, probe_host, probe_http, probe_tcp, random_unit, read_json_safe, write_json_atomic,
};

pub const LOG_LIMIT: usize = 400;

// ---------------------------------------------------------------- 类型

#[derive(Clone, Debug, Serialize)]
pub struct LogLine {
    pub t: u64,
    pub stream: String,
    pub text: String,
}

#[derive(Clone, Debug)]
pub enum Event {
    Change,
    Log { id: String, line: LogLine },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Stopped,
    Starting,
    Up,
    Retrying,
    Failed,
    NeedsSecret,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Stopped => "stopped",
            Status::Starting => "starting",
            Status::Up => "up",
            Status::Retrying => "retrying",
            Status::Failed => "failed",
            Status::NeedsSecret => "needs-secret",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LastExit {
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub at: u64,
}

struct Runtime {
    id: String,
    tunnel: Tunnel,
    desired: bool,
    status: Status,
    pid: Option<u32>,
    running: bool,
    started_at: Option<u64>,
    up_at: Option<u64>,
    restarts: u64,
    failures: u64,
    last_error: Option<String>,
    last_exit: Option<LastExit>,
    stopping: bool,
    paused: bool,
    fatal_spawn: Option<String>,
    last_args: String,
    secret: Option<String>,
    next_retry_at: Option<u64>,
    port_failures: u32,
    logs: VecDeque<LogLine>,
    gen: u64,
    retry_gen: u64,
}

impl Runtime {
    fn new(tunnel: Tunnel, desired: bool, last_args: String) -> Self {
        Self {
            id: tunnel.id.clone(),
            tunnel,
            desired,
            status: Status::Stopped,
            pid: None,
            running: false,
            started_at: None,
            up_at: None,
            restarts: 0,
            failures: 0,
            last_error: None,
            last_exit: None,
            stopping: false,
            paused: false,
            fatal_spawn: None,
            last_args,
            secret: None,
            next_retry_at: None,
            port_failures: 0,
            logs: VecDeque::new(),
            gen: 0,
            retry_gen: 0,
        }
    }

    fn push_log(&mut self, stream: &str, text: String) -> LogLine {
        let line = LogLine {
            t: now_ms(),
            stream: stream.to_string(),
            text,
        };
        self.logs.push_back(line.clone());
        while self.logs.len() > LOG_LIMIT {
            self.logs.pop_front();
        }
        line
    }
}

// ---------------------------------------------------------------- Supervisor

pub struct Supervisor {
    config: tokio::sync::RwLock<Config>,
    inner: Mutex<Vec<Runtime>>,
    events: broadcast::Sender<Event>,
    data_dir: PathBuf,
    state_file: PathBuf,
    runtime_file: PathBuf,
    askpass_helper: PathBuf,
    shutting_down: AtomicBool,
    quiet: bool,
}

impl Supervisor {
    pub fn new(config: Config, quiet: bool) -> Result<Arc<Self>, String> {
        let data_dir = config
            .config_file
            .parent()
            .map(|p| p.join(".ssh-proxy"))
            .unwrap_or_else(|| PathBuf::from(".ssh-proxy"));
        std::fs::create_dir_all(&data_dir).map_err(|e| format!("创建数据目录失败: {}", e))?;
        let askpass_helper = ensure_askpass_helper(&data_dir)?;
        let state_file = data_dir.join("state.json");
        let runtime_file = data_dir.join("runtime.json");

        let persisted = read_json_safe(&state_file).unwrap_or(Value::Null);
        let mut runtimes = Vec::with_capacity(config.tunnels.len());
        for tunnel in &config.tunnels {
            let desired = persisted
                .get(&tunnel.id)
                .and_then(|item| item.get("desired"))
                .and_then(|v| v.as_bool())
                .unwrap_or(tunnel.auto_start);
            let signature = args_signature(tunnel, &config);
            runtimes.push(Runtime::new(tunnel.clone(), desired, signature));
        }

        let (events, _) = broadcast::channel(256);
        Ok(Arc::new(Self {
            config: tokio::sync::RwLock::new(config),
            inner: Mutex::new(runtimes),
            events,
            data_dir,
            state_file,
            runtime_file,
            askpass_helper,
            shutting_down: AtomicBool::new(false),
            quiet,
        }))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub async fn config_clone(&self) -> Config {
        self.config.read().await.clone()
    }

    fn lock_inner(&self) -> MutexGuard<'_, Vec<Runtime>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn change(&self) {
        self.emit(Event::Change);
    }

    fn index_of(inner: &[Runtime], id: &str) -> Option<usize> {
        inner.iter().position(|rt| rt.id == id)
    }

    fn dispatch_log(&self, id: &str, line: LogLine) {
        if !self.quiet {
            let marker = if line.stream == "err" { "!" } else { "-" };
            println!("{} [{}] {}", marker, id, line.text);
        }
        self.emit(Event::Log {
            id: id.to_string(),
            line,
        });
    }

    fn dispatch_logs(&self, id: &str, lines: Vec<LogLine>) {
        for line in lines {
            self.dispatch_log(id, line);
        }
    }

    /// 记一条日志（自带加锁 + 广播），给"锁外"的调用点用
    fn log(&self, id: &str, stream: &str, text: impl Into<String>) {
        let line = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            inner[idx].push_log(stream, text.into())
        };
        self.dispatch_log(id, line);
    }

    fn persist_locked(&self, inner: &[Runtime]) {
        let mut data = Map::new();
        for rt in inner {
            data.insert(rt.id.clone(), json!({ "desired": rt.desired }));
        }
        if let Err(err) = write_json_atomic(&self.state_file, &Value::Object(data)) {
            eprintln!("写入 {} 失败: {}", self.state_file.display(), err);
        }
    }

    fn record_runtime_locked(&self, inner: &[Runtime]) {
        let list: Vec<Value> = inner
            .iter()
            .filter_map(|rt| {
                let pid = rt.pid?;
                Some(json!({
                    "id": rt.id,
                    "pid": pid,
                    "spec": rt.tunnel.forward_spec,
                    "at": now_ms(),
                }))
            })
            .collect();
        if let Err(err) = write_json_atomic(&self.runtime_file, &Value::Array(list)) {
            eprintln!("写入 {} 失败: {}", self.runtime_file.display(), err);
        }
    }

    async fn supervision(&self) -> Supervision {
        self.config.read().await.supervision.clone()
    }

    // ------------------------------------------------------------ 快照

    pub async fn snapshot(&self) -> Value {
        let config = self.config.read().await;
        let inner = self.lock_inner();
        let tunnels: Vec<Value> = inner.iter().map(|rt| tunnel_snapshot(&config, rt)).collect();
        let up = tunnels.iter().filter(|t| t["status"] == json!("up")).count();
        let desired = tunnels.iter().filter(|t| t["desired"] == json!(true)).count();
        let failed = tunnels.iter().filter(|t| t["status"] == json!("failed")).count();
        json!({
            "ts": now_ms(),
            "tunnels": tunnels,
            "stats": { "total": tunnels.len(), "up": up, "desired": desired, "failed": failed },
            "panel": { "configFile": config.config_file.display().to_string() },
        })
    }

    pub async fn snapshot_tunnel(&self, id: &str) -> Result<Value, String> {
        let config = self.config.read().await;
        let inner = self.lock_inner();
        let idx = Self::index_of(&inner, id).ok_or_else(|| format!("未知隧道: {}", id))?;
        Ok(tunnel_snapshot(&config, &inner[idx]))
    }

    pub fn logs(&self, id: &str, limit: usize) -> Result<Vec<LogLine>, String> {
        let inner = self.lock_inner();
        let idx = Self::index_of(&inner, id).ok_or_else(|| format!("未知隧道: {}", id))?;
        let n = limit.clamp(1, LOG_LIMIT);
        let logs = &inner[idx].logs;
        let start = logs.len().saturating_sub(n);
        Ok(logs.iter().skip(start).cloned().collect())
    }

    /// 这条隧道"用户想不想开着"（改名逻辑用它判断重启后要不要重新拉起）
    pub fn is_desired(&self, id: &str) -> bool {
        let inner = self.lock_inner();
        Self::index_of(&inner, id)
            .map(|idx| inner[idx].desired)
            .unwrap_or(false)
    }

    pub fn has_tunnel(&self, id: &str) -> bool {
        Self::index_of(&self.lock_inner(), id).is_some()
    }

    fn is_running(&self, id: &str) -> bool {
        let inner = self.lock_inner();
        Self::index_of(&inner, id)
            .map(|idx| inner[idx].running)
            .unwrap_or(false)
    }

    // ------------------------------------------------------------ 启停

    pub async fn start(self: &Arc<Self>, id: &str, manual: bool) -> Result<Value, String> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err("面板正在关闭，无法启动隧道".into());
        }
        let (already_running, lines) = {
            let mut inner = self.lock_inner();
            let idx = Self::index_of(&inner, id).ok_or_else(|| format!("未知隧道: {}", id))?;
            let mut lines = Vec::new();
            {
                let rt = &mut inner[idx];
                rt.desired = true;
                if manual {
                    rt.failures = 0;
                    rt.paused = false;
                }
                if !rt.running {
                    rt.next_retry_at = None;
                    rt.retry_gen += 1;
                } else {
                    lines.push(rt.push_log("info", "隧道已在运行".into()));
                }
            }
            self.persist_locked(&inner);
            let running = inner[idx].running;
            (running, lines)
        };
        self.dispatch_logs(id, lines);
        if already_running {
            self.change();
            return self.snapshot_tunnel(id).await;
        }
        self.spawn_attempt(id).await;
        self.snapshot_tunnel(id).await
    }

    pub async fn stop(self: &Arc<Self>, id: &str) -> Result<Value, String> {
        let (pid, lines) = {
            let mut inner = self.lock_inner();
            let idx = Self::index_of(&inner, id).ok_or_else(|| format!("未知隧道: {}", id))?;
            let mut lines = Vec::new();
            let pid;
            {
                let rt = &mut inner[idx];
                rt.desired = false;
                rt.paused = false;
                rt.secret = None; // 手动停止就把"连接时输入"的凭据忘掉
                rt.retry_gen += 1;
                rt.next_retry_at = None;
                match rt.pid {
                    Some(current) => {
                        rt.stopping = true;
                        pid = Some(current);
                    }
                    None => {
                        rt.status = Status::Stopped;
                        rt.up_at = None;
                        rt.port_failures = 0;
                        pid = None;
                    }
                }
            }
            self.persist_locked(&inner);
            if pid.is_some() {
                lines.push(inner[idx].push_log("info", "正在停止隧道…".into()));
            }
            (pid, lines)
        };
        self.dispatch_logs(id, lines);

        let Some(pid) = pid else {
            self.change();
            return self.snapshot_tunnel(id).await;
        };

        kill_tree(pid);
        let mut waited = 0u64;
        while self.is_running(id) && waited < 6000 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            waited += 100;
        }
        if self.is_running(id) {
            self.log(id, "warn", "ssh 进程未响应，继续等待强制结束");
            kill_tree(pid);
            let mut waited = 0u64;
            while self.is_running(id) && waited < 3000 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                waited += 100;
            }
        }
        {
            let mut inner = self.lock_inner();
            if let Some(idx) = Self::index_of(&inner, id) {
                if !inner[idx].running {
                    inner[idx].status = Status::Stopped;
                    inner[idx].up_at = None;
                }
            }
        }
        self.change();
        self.snapshot_tunnel(id).await
    }

    pub async fn restart(self: &Arc<Self>, id: &str) -> Result<Value, String> {
        self.stop(id).await?;
        self.start(id, true).await
    }

    pub async fn set_secret(self: &Arc<Self>, id: &str, value: &str) -> Result<Value, String> {
        if value.is_empty() {
            return Err("密码不能为空".into());
        }
        let (running, pid) = {
            let mut inner = self.lock_inner();
            let idx = Self::index_of(&inner, id).ok_or_else(|| format!("未知隧道: {}", id))?;
            let rt = &mut inner[idx];
            rt.secret = Some(value.to_string());
            rt.failures = 0;
            rt.paused = false;
            rt.last_error = None;
            (rt.running, rt.pid)
        };
        self.log(
            id,
            "info",
            "已收到凭据（只保存在内存里，不会写进配置文件）",
        );
        if running {
            // 已经在跑：换新凭据需要重建（关闭回调会按 desired 触发重连）
            if let Some(pid) = pid {
                kill_tree(pid);
            }
            return self.snapshot_tunnel(id).await;
        }
        self.spawn_attempt(id).await;
        self.snapshot_tunnel(id).await
    }

    pub async fn forget_secret(&self, id: &str) -> Result<Value, String> {
        let needs_change = {
            let mut inner = self.lock_inner();
            let idx = Self::index_of(&inner, id).ok_or_else(|| format!("未知隧道: {}", id))?;
            let rt = &mut inner[idx];
            rt.secret = None;
            rt.status == Status::NeedsSecret
        };
        if needs_change {
            self.change();
        }
        self.snapshot_tunnel(id).await
    }

    /// 按上次的用户意图拉起隧道（对应 JS 的 `autostart()`）
    pub async fn autostart(self: &Arc<Self>) {
        let ids: Vec<String> = {
            let inner = self.lock_inner();
            inner
                .iter()
                .filter(|rt| rt.desired)
                .map(|rt| rt.id.clone())
                .collect()
        };
        for id in ids {
            let _ = self.start(&id, false).await;
        }
    }
    pub async fn start_all(self: &Arc<Self>) {
        let ids: Vec<String> = self.lock_inner().iter().map(|rt| rt.id.clone()).collect();
        for id in ids {
            let _ = self.start(&id, true).await;
        }
    }

    pub async fn stop_all(self: &Arc<Self>) {
        let ids: Vec<String> = self.lock_inner().iter().map(|rt| rt.id.clone()).collect();
        for id in ids {
            let _ = self.stop(&id).await;
        }
    }

    // ------------------------------------------------------------ 派生动作

    async fn fail_start(self: &Arc<Self>, id: &str, message: String) {
        let max_failures = self.supervision().await.max_failures;
        let (lines, schedule, retry_gen) = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            let rt = &mut inner[idx];
            let mut lines = Vec::new();
            rt.last_error = Some(message.clone());
            rt.failures += 1;
            lines.push(rt.push_log("err", format!("✖ {}", message)));
            let mut schedule = false;
            let mut retry_gen = 0;
            if !rt.desired {
                rt.status = Status::Stopped;
            } else if rt.failures > max_failures {
                rt.status = Status::Failed;
                rt.paused = true;
                let text = format!(
                    "连续失败 {} 次，已暂停自动重连（点“重连”或开关重新开始）",
                    max_failures
                );
                rt.last_error = Some(text.clone());
                lines.push(rt.push_log("err", text));
            } else {
                rt.status = Status::Retrying;
                rt.retry_gen += 1;
                retry_gen = rt.retry_gen;
                schedule = true;
            }
            (lines, schedule, retry_gen)
        };
        self.dispatch_logs(id, lines);
        self.change();
        if schedule {
            self.schedule_retry(id, retry_gen);
        }
    }

    async fn spawn_attempt(self: &Arc<Self>, id: &str) {
        if self.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        let config = self.config.read().await.clone();

        // 1) 取隧道、占代次
        let (tunnel, gen) = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            let rt = &mut inner[idx];
            if !rt.desired || rt.running || rt.paused {
                return;
            }
            rt.gen += 1;
            (rt.tunnel.clone(), rt.gen)
        };

        // 2) 准备凭据
        let mut secret = String::new();
        let auth = &tunnel.auth;
        if auth.mode == AuthMode::Password {
            match decrypt_secret(&self.data_dir, &auth.password) {
                Ok(value) => secret = value,
                Err(err) => {
                    self.fail_start(id, format!("读取保存的凭据失败（密钥文件变了？）: {}", err))
                        .await;
                    return;
                }
            }
        } else if !auth.passphrase.is_empty() {
            match decrypt_secret(&self.data_dir, &auth.passphrase) {
                Ok(value) => secret = value,
                Err(err) => {
                    self.fail_start(id, format!("读取保存的凭据失败（密钥文件变了？）: {}", err))
                        .await;
                    return;
                }
            }
        } else if auth.mode == AuthMode::Ask {
            let inner = self.lock_inner();
            secret = Self::index_of(&inner, id)
                .and_then(|idx| inner[idx].secret.clone())
                .unwrap_or_default();
        }

        if auth.mode == AuthMode::Ask && secret.is_empty() {
            let line = {
                let mut inner = self.lock_inner();
                let Some(idx) = Self::index_of(&inner, id) else {
                    return;
                };
                let rt = &mut inner[idx];
                if rt.gen != gen {
                    return;
                }
                rt.status = Status::NeedsSecret;
                rt.up_at = None;
                rt.last_error = None;
                rt.push_log("warn", "这条隧道设置了「连接时输入」，等待你输入密码/口令".into())
            };
            self.dispatch_log(id, line);
            self.change();
            return;
        }

        // 3) 本地端口占用预检
        if probe_tcp(tunnel.local_port, &probe_host(&tunnel.bind_address), 400).await {
            self.fail_start(
                id,
                format!(
                    "本地端口 {}:{} 已被其他程序占用",
                    tunnel.bind_address, tunnel.local_port
                ),
            )
            .await;
            return;
        }

        // 4) 起进程
        let prefix = command_prefix(&tunnel, &config);
        let args = build_ssh_args(&tunnel, &config, Some(secret.as_str()));
        let command_line = format_command(&prefix, &args);
        let line = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            let rt = &mut inner[idx];
            if rt.gen != gen || rt.running || !rt.desired {
                return;
            }
            rt.status = Status::Starting;
            rt.started_at = Some(now_ms());
            rt.up_at = None;
            rt.port_failures = 0;
            rt.last_error = None;
            rt.fatal_spawn = None;
            rt.stopping = false;
            let text = if secret.is_empty() {
                format!("▶ {}", command_line)
            } else {
                format!("▶ {}（凭据通过 askpass 传入，不进命令行）", command_line)
            };
            rt.push_log("info", text)
        };
        self.dispatch_log(id, line);
        self.change();

        let mut command = tokio::process::Command::new(&prefix[0]);
        command.args(&prefix[1..]).args(&args);
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
        command.stdin(std::process::Stdio::null());
        command.kill_on_drop(false);
        for (key, value) in tunnel.env.iter() {
            command.env(key, value.as_str().unwrap_or_default());
        }
        for (key, value) in askpass_env(&self.askpass_helper, &secret) {
            command.env(key, value);
        }
        #[cfg(unix)]
        {
            command.process_group(0);
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                let hint = if err.kind() == std::io::ErrorKind::NotFound {
                    format!(
                        "找不到 ssh 可执行文件（{}），检查「全局设置」里的 ssh 路径",
                        prefix[0]
                    )
                } else {
                    format!("无法启动 ssh ({}): {}", prefix[0], err)
                };
                self.fail_start(id, hint).await;
                return;
            }
        };

        let pid = child.id();
        {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            {
                let rt = &mut inner[idx];
                if rt.gen != gen {
                    // 期间被停掉了：直接把刚起的进程杀掉
                    if let Some(pid) = pid {
                        kill_tree(pid);
                    }
                    return;
                }
                rt.running = true;
                rt.pid = pid;
            }
            self.record_runtime_locked(&inner);
        }

        // 5) 输出泵 + 退出等待
        if let Some(stdout) = child.stdout.take() {
            let supervisor = self.clone();
            let id_owned = id.to_string();
            tokio::spawn(async move { pump(stdout, supervisor, id_owned, "out", gen).await });
        }
        if let Some(stderr) = child.stderr.take() {
            let supervisor = self.clone();
            let id_owned = id.to_string();
            tokio::spawn(async move { pump(stderr, supervisor, id_owned, "err", gen).await });
        }

        let supervisor = self.clone();
        let id_owned = id.to_string();
        tokio::spawn(async move {
            let status = child.wait().await.ok();
            let (code, signal) = match status {
                Some(status) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::process::ExitStatusExt;
                        (status.code(), status.signal().map(|s| s.to_string()))
                    }
                    #[cfg(not(unix))]
                    {
                        (status.code(), None)
                    }
                }
                None => (None, None),
            };
            supervisor.on_close(&id_owned, gen, code, signal).await;
        });

        // 6) 就绪探测（后台，不阻塞调用方）
        let supervisor = self.clone();
        let id_owned = id.to_string();
        tokio::spawn(async move { supervisor.wait_ready(&id_owned, gen).await });
    }

    async fn wait_ready(self: Arc<Self>, id: &str, gen: u64) {
        let (tunnel, start_timeout) = {
            let config = self.config.read().await;
            let inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            (inner[idx].tunnel.clone(), config.supervision.start_timeout_ms)
        };
        let deadline = now_ms() + start_timeout;
        let host = probe_host(&tunnel.bind_address);

        loop {
            {
                let inner = self.lock_inner();
                let current = Self::index_of(&inner, id)
                    .map(|idx| inner[idx].gen == gen && inner[idx].running)
                    .unwrap_or(false);
                if !current {
                    return;
                }
            }
            let ready = if tunnel.health_url.is_empty() {
                probe_tcp(tunnel.local_port, &host, 500).await
            } else {
                probe_http(&tunnel.health_url, 1500).await
            };
            if ready {
                break;
            }
            if now_ms() >= deadline {
                self.log(
                    id,
                    "warn",
                    format!("本地端口在 {}ms 内未就绪，继续观察", start_timeout),
                );
                self.change();
                return;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        let stable_ms = self.supervision().await.stable_reset_ms;
        let (line, open_on_up) = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            let rt = &mut inner[idx];
            if rt.gen != gen || !rt.running {
                return;
            }
            rt.status = Status::Up;
            rt.up_at = Some(now_ms());
            rt.port_failures = 0;
            let text = format!(
                "✔ 隧道就绪: {}:{} → {}:{}",
                rt.tunnel.bind_address,
                rt.tunnel.local_port,
                rt.tunnel.target.host,
                rt.tunnel.target.port
            );
            (rt.push_log("info", text), rt.tunnel.open_on_up)
        };
        self.dispatch_log(id, line);
        self.change();

        // 稳定期后清零失败计数
        let supervisor = self.clone();
        let id_owned = id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(stable_ms)).await;
            let mut inner = supervisor.lock_inner();
            if let Some(idx) = Self::index_of(&inner, &id_owned) {
                let rt = &mut inner[idx];
                if rt.gen == gen && rt.status == Status::Up {
                    rt.failures = 0;
                }
            }
        });

        if open_on_up {
            let url = {
                let inner = self.lock_inner();
                Self::index_of(&inner, id).map(|idx| open_url(&inner[idx].tunnel))
            };
            if let Some(url) = url {
                open_external(&url);
            }
        }
    }

    async fn on_close(
        self: Arc<Self>,
        id: &str,
        gen: u64,
        code: Option<i32>,
        signal: Option<String>,
    ) {
        let max_failures = self.supervision().await.max_failures;
        let shutting_down = self.shutting_down.load(Ordering::Relaxed);
        let (lines, schedule, retry_gen) = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            let mut lines = Vec::new();
            {
                let rt = &mut inner[idx];
                if rt.gen != gen {
                    return; // 陈旧回调（已经换了一代连接）
                }
                rt.running = false;
                rt.pid = None;
                rt.port_failures = 0;
                rt.next_retry_at = None;
            }
            self.record_runtime_locked(&inner);

            let rt = &mut inner[idx];
            let mut schedule = false;
            let mut retry_gen = 0;
            if rt.stopping || shutting_down || !rt.desired {
                rt.stopping = false;
                rt.status = Status::Stopped;
                rt.up_at = None;
                rt.fatal_spawn = None;
                lines.push(rt.push_log("info", "■ 隧道已停止".into()));
            } else if let Some(fatal) = rt.fatal_spawn.clone() {
                rt.status = Status::Failed;
                rt.paused = true;
                rt.last_error = Some(fatal.clone());
                rt.fatal_spawn = None;
                lines.push(rt.push_log("err", fatal));
            } else {
                rt.up_at = None;
                rt.last_exit = Some(LastExit {
                    code,
                    signal: signal.clone(),
                    at: now_ms(),
                });
                rt.failures += 1;
                let text = format!(
                    "ssh 退出 (code={} signal={})，准备重连",
                    code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
                    signal.clone().unwrap_or_else(|| "-".into())
                );
                lines.push(rt.push_log("err", text));
                if rt.failures > max_failures {
                    rt.status = Status::Failed;
                    rt.paused = true;
                    let text = format!(
                        "连续失败 {} 次，已暂停自动重连（点“重连”或开关重新开始）",
                        max_failures
                    );
                    rt.last_error = Some(text.clone());
                    lines.push(rt.push_log("err", text));
                } else {
                    rt.restarts += 1;
                    rt.status = Status::Retrying;
                    rt.retry_gen += 1;
                    retry_gen = rt.retry_gen;
                    schedule = true;
                }
            }
            (lines, schedule, retry_gen)
        };
        self.dispatch_logs(id, lines);
        self.change();
        if schedule {
            self.schedule_retry(id, retry_gen);
        }
    }

    fn schedule_retry(self: &Arc<Self>, id: &str, retry_gen: u64) {
        let (backoff_base, backoff_max) = (
            self.config.try_read().map(|c| c.supervision.backoff_base_ms).unwrap_or(1000),
            self.config.try_read().map(|c| c.supervision.backoff_max_ms).unwrap_or(30000),
        );
        let failures = {
            let inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            if inner[idx].retry_gen != retry_gen {
                return;
            }
            inner[idx].failures
        };

        let exp = (backoff_max as f64).min(backoff_base as f64 * 2f64.powi(failures.saturating_sub(1) as i32));
        let jitter = (exp * (random_unit() * 0.3 - 0.15)).round();
        let delay = (exp + jitter).max(500.0) as u64;

        let line = {
            let mut inner = self.lock_inner();
            let Some(idx) = Self::index_of(&inner, id) else {
                return;
            };
            let rt = &mut inner[idx];
            if rt.retry_gen != retry_gen {
                return;
            }
            rt.next_retry_at = Some(now_ms() + delay);
            rt.push_log(
                "info",
                format!(
                    "{:.1} 秒后重连（第 {} 次失败）",
                    delay as f64 / 1000.0,
                    rt.failures
                ),
            )
        };
        self.dispatch_log(id, line);
        self.change();

        let supervisor = self.clone();
        let id_owned = id.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            {
                let mut inner = supervisor.lock_inner();
                let Some(idx) = Self::index_of(&inner, &id_owned) else {
                    return;
                };
                let rt = &mut inner[idx];
                if rt.retry_gen != retry_gen {
                    return;
                }
                rt.next_retry_at = None;
            }
            supervisor.spawn_attempt(&id_owned).await;
        });
    }

    // ------------------------------------------------------------ 看门狗

    pub async fn init(self: &Arc<Self>) {
        if let Err(err) = self.reap_orphans().await {
            eprintln!("[reap] {}", err);
        }
        let supervisor = self.clone();
        tokio::spawn(async move {
            loop {
                if supervisor.shutting_down.load(Ordering::Relaxed) {
                    return;
                }
                let interval = supervisor.config.read().await.supervision.watch_interval_ms;
                tokio::time::sleep(Duration::from_millis(interval.max(200))).await;
                supervisor.watch().await;
            }
        });
    }

    async fn watch(self: &Arc<Self>) {
        if self.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        let start_timeout = self.supervision().await.start_timeout_ms;
        let candidates: Vec<(String, Status, bool, bool, u16, String, Option<u32>, Option<u64>)> = {
            let inner = self.lock_inner();
            inner
                .iter()
                .map(|rt| {
                    (
                        rt.id.clone(),
                        rt.status,
                        rt.desired,
                        rt.paused,
                        rt.tunnel.local_port,
                        rt.tunnel.bind_address.clone(),
                        rt.pid,
                        rt.started_at,
                    )
                })
                .collect()
        };

        for (id, status, desired, paused, port, bind, pid, started_at) in candidates {
            if !desired || paused || status == Status::NeedsSecret {
                continue;
            }
            match status {
                Status::Up => {
                    let ok = probe_tcp(port, &probe_host(&bind), 800).await;
                    if !self.is_running(&id) {
                        continue;
                    }
                    if ok {
                        let mut inner = self.lock_inner();
                        if let Some(idx) = Self::index_of(&inner, &id) {
                            inner[idx].port_failures = 0;
                        }
                    } else {
                        let (line, should_kill) = {
                            let mut inner = self.lock_inner();
                            let Some(idx) = Self::index_of(&inner, &id) else {
                                continue;
                            };
                            let rt = &mut inner[idx];
                            rt.port_failures += 1;
                            let failures = rt.port_failures;
                            let mut line = rt.push_log(
                                "warn",
                                format!("本地端口探测失败 ({}/3)", failures),
                            );
                            if failures >= 3 {
                                rt.port_failures = 0;
                                line = rt.push_log("err", "隧道已不可用，重建连接".into());
                                (line, true)
                            } else {
                                (line, false)
                            }
                        };
                        self.dispatch_log(&id, line);
                        if should_kill {
                            if let Some(pid) = pid {
                                kill_tree(pid);
                            }
                        }
                    }
                }
                Status::Starting => {
                    if let (Some(pid), Some(started_at)) = (pid, started_at) {
                        if now_ms() > started_at + start_timeout + 15000 {
                            self.log(&id, "err", "连接超时，重建连接");
                            kill_tree(pid);
                        }
                    }
                }
                Status::Retrying => {
                    let retry_gen = {
                        let mut inner = self.lock_inner();
                        let Some(idx) = Self::index_of(&inner, &id) else {
                            continue;
                        };
                        let rt = &mut inner[idx];
                        if rt.next_retry_at.is_none() && rt.pid.is_none() {
                            rt.retry_gen += 1;
                            Some(rt.retry_gen)
                        } else {
                            None
                        }
                    };
                    if let Some(retry_gen) = retry_gen {
                        self.schedule_retry(&id, retry_gen);
                    }
                }
                _ => {}
            }
        }
    }

    // ------------------------------------------------------------ 孤儿回收

    async fn reap_orphans(&self) -> Result<(), String> {
        let Some(previous) = read_json_safe(&self.runtime_file) else {
            return Ok(());
        };
        let Some(entries) = previous.as_array() else {
            return Ok(());
        };
        for entry in entries {
            let Some(pid) = entry.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) else {
                continue;
            };
            if pid == 0 {
                continue;
            }
            if !tokio::task::spawn_blocking(move || process_alive(pid))
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let spec = entry
                .get("spec")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let id = entry
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let cmdline = tokio::task::spawn_blocking(move || read_cmdline(pid))
                .await
                .unwrap_or_default();
            let ours = cmdline.contains("-N") && (spec.is_empty() || cmdline.contains(&spec));
            if !ours {
                continue;
            }
            if !self.quiet {
                println!("[reap] 结束上次遗留的 ssh 进程 pid={} ({})", pid, id);
            }
            kill_tree(pid);
        }
        if let Err(err) = write_json_atomic(&self.runtime_file, &json!([])) {
            eprintln!("清空 {} 失败: {}", self.runtime_file.display(), err);
        }
        Ok(())
    }

    // ------------------------------------------------------------ 重载配置

    pub async fn reload(self: &Arc<Self>, next: Config) -> Value {
        let (prev_ssh, prev_watch) = {
            let config = self.config.read().await;
            (
                serde_json::to_string(&config.ssh).unwrap_or_default(),
                config.supervision.watch_interval_ms,
            )
        };
        let ssh_changed = prev_ssh != serde_json::to_string(&next.ssh).unwrap_or_default();
        let _watch_changed = prev_watch != next.supervision.watch_interval_ms;
        *self.config.write().await = next.clone();

        let mut added: Vec<String> = Vec::new();
        let mut removed: Vec<String> = Vec::new();
        let mut changed: Vec<String> = Vec::new();

        {
            let mut inner = self.lock_inner();
            for tunnel in &next.tunnels {
                if Self::index_of(&inner, &tunnel.id).is_none() {
                    let signature = args_signature(tunnel, &next);
                    inner.push(Runtime::new(tunnel.clone(), tunnel.auto_start, signature));
                    added.push(tunnel.id.clone());
                }
            }
        }

        let missing: Vec<String> = {
            let inner = self.lock_inner();
            inner
                .iter()
                .map(|rt| rt.id.clone())
                .filter(|id| !next.tunnels.iter().any(|t| &t.id == id))
                .collect()
        };
        for id in missing {
            let _ = self.stop(&id).await;
            {
                let mut inner = self.lock_inner();
                if let Some(idx) = Self::index_of(&inner, &id) {
                    inner.remove(idx);
                }
            }
            removed.push(id);
        }

        let mut lines: Vec<(String, LogLine)> = Vec::new();
        {
            let mut inner = self.lock_inner();
            for tunnel in &next.tunnels {
                let Some(idx) = Self::index_of(&inner, &tunnel.id) else {
                    continue;
                };
                let rt = &mut inner[idx];
                rt.tunnel = tunnel.clone();
                if ssh_changed && rt.running && !changed.contains(&tunnel.id) {
                    changed.push(tunnel.id.clone());
                }
                let signature = args_signature(tunnel, &next);
                if !rt.last_args.is_empty() && rt.last_args != signature && !changed.contains(&tunnel.id) {
                    changed.push(tunnel.id.clone());
                }
                rt.last_args = signature;
            }
            for id in &changed {
                if let Some(idx) = Self::index_of(&inner, id) {
                    let rt = &mut inner[idx];
                    rt.failures = 0;
                    rt.paused = false;
                    let line = rt.push_log("warn", "配置已变更，隧道将重建".into());
                    lines.push((id.clone(), line));
                }
            }
        }
        let pids: Vec<u32> = {
            let inner = self.lock_inner();
            changed
                .iter()
                .filter_map(|id| Self::index_of(&inner, id).and_then(|idx| inner[idx].pid))
                .collect()
        };
        for (id, line) in lines {
            self.dispatch_log(&id, line);
        }
        for pid in pids {
            kill_tree(pid);
        }

        for id in &added {
            let desired = {
                let inner = self.lock_inner();
                Self::index_of(&inner, id)
                    .map(|idx| inner[idx].desired)
                    .unwrap_or(false)
            };
            if desired {
                let _ = self.start(id, false).await;
            }
        }

        {
            let inner = self.lock_inner();
            self.persist_locked(&inner);
        }
        // 与 JS 的 reload() 一致：配置变了要让面板收到一次 state 事件重绘
        self.change();

        json!({
            "added": added,
            "changed": changed,
            "removed": removed,
            "tunnels": next.tunnels.len(),
        })
    }

    pub async fn shutdown(self: &Arc<Self>) {
        if self.shutting_down.swap(true, Ordering::Relaxed) {
            return;
        }
        let pids: Vec<u32> = {
            let inner = self.lock_inner();
            inner.iter().filter_map(|rt| rt.pid).collect()
        };
        for pid in pids {
            kill_tree(pid);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = write_json_atomic(&self.runtime_file, &json!([]));
    }
}

// ---------------------------------------------------------------- 辅助

async fn pump<R>(mut reader: R, supervisor: Arc<Supervisor>, id: String, stream: &'static str, gen: u64)
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
                    let mut line: Vec<u8> = pending.drain(..=pos).collect();
                    if line.last() == Some(&b'\n') {
                        line.pop();
                    }
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    let text = String::from_utf8_lossy(&line).into_owned();
                    supervisor.log_if_current(&id, gen, stream, text);
                }
                if pending.len() > 4000 {
                    let text = String::from_utf8_lossy(&pending).into_owned();
                    pending.clear();
                    supervisor.log_if_current(&id, gen, stream, text);
                }
            }
            Err(_) => break,
        }
    }
    if !pending.is_empty() {
        let text = String::from_utf8_lossy(&pending).into_owned();
        supervisor.log_if_current(&id, gen, stream, text);
    }
}

impl Supervisor {
    fn log_if_current(&self, id: &str, gen: u64, stream: &str, text: String) {
        let current = {
            let inner = self.lock_inner();
            Self::index_of(&inner, id)
                .map(|idx| inner[idx].gen == gen)
                .unwrap_or(false)
        };
        if current {
            self.log(id, stream, text);
        }
    }
}

/// 连接参数签名：ssh 参数 + 加密后的密码/口令（改了密码也应该重建连接）
fn args_signature(tunnel: &Tunnel, config: &Config) -> String {
    let args = build_ssh_args(tunnel, config, None);
    serde_json::to_string(&json!({
        "args": args,
        "mode": tunnel.auth.mode.as_str(),
        "password": tunnel.auth.password,
        "passphrase": tunnel.auth.passphrase,
        "identityFile": tunnel.auth.identity_file,
    }))
    .unwrap_or_default()
}

fn tunnel_snapshot(config: &Config, rt: &Runtime) -> Value {
    let tunnel = &rt.tunnel;
    let prefix = command_prefix(tunnel, config);
    let args = build_ssh_args(tunnel, config, None);

    let mut via = Map::new();
    via.insert("host".into(), json!(tunnel.via.host));
    via.insert("port".into(), json!(tunnel.via.port));
    if let Some(user) = &tunnel.via.user {
        via.insert("user".into(), json!(user));
    }
    if let Some(jump) = &tunnel.via.proxy_jump {
        via.insert("proxyJump".into(), json!(jump));
    }
    via.insert(
        "identityFile".into(),
        json!(tunnel.via.identity_file.clone().unwrap_or_default()),
    );

    json!({
        "id": rt.id,
        "name": tunnel.name,
        "description": tunnel.description,
        "status": rt.status.as_str(),
        "desired": rt.desired,
        "paused": rt.paused,
        "bindAddress": tunnel.bind_address,
        "localPort": tunnel.local_port,
        "target": tunnel.target,
        "via": Value::Object(via),
        "auth": {
            "mode": tunnel.auth.mode.as_str(),
            "identityFile": tunnel.auth.identity_file,
            "hasPassword": !tunnel.auth.password.is_empty(),
            "hasPassphrase": !tunnel.auth.passphrase.is_empty(),
            "hasSecret": rt.secret.is_some(),
            "needsSecret": rt.status == Status::NeedsSecret,
        },
        "scheme": tunnel.scheme,
        "healthUrl": tunnel.health_url,
        "extraArgs": tunnel.extra_args,
        "url": open_url(tunnel),
        "openPath": tunnel.url,
        "command": format_command(&prefix, &args),
        "pid": rt.pid,
        "startedAt": rt.started_at,
        "upAt": rt.up_at,
        "uptimeMs": rt.up_at.map(|up| now_ms().saturating_sub(up)).unwrap_or(0),
        "restarts": rt.restarts,
        "failures": rt.failures,
        "lastError": rt.last_error,
        "lastExit": rt.last_exit,
        "nextRetryAt": rt.next_retry_at,
        "autoStart": tunnel.auto_start,
        "openOnUp": tunnel.open_on_up,
    })
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
