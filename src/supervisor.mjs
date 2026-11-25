import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { sleep, probeTcp, probeHttp, makeLineReader, readJsonSafe } from './util.mjs';
import { decryptSecret } from './secrets.mjs';
import {
  buildSshArgs,
  commandPrefix,
  formatCommand,
  killTree,
  readCmdline,
  processAlive,
  openExternal,
  ensureAskpassHelper,
  askpassEnv,
} from './ssh.mjs';

const LOG_LIMIT = 400;

class Runtime {
  constructor(tunnel, desired) {
    this.tunnel = tunnel;
    this.id = tunnel.id;
    this.desired = desired;
    this.status = 'stopped'; // stopped | starting | up | retrying | failed
    this.child = null;
    this.pid = null;
    this.startedAt = null;
    this.upAt = null;
    this.restarts = 0;
    this.failures = 0;
    this.lastError = null;
    this.lastExit = null;
    this.stopping = false;
    this.paused = false;
    this.fatalSpawn = null;
    this.lastArgs = null;
    this.secret = null; // "连接时输入"的凭据：只存在内存里
    this.retryTimer = null;
    this.stableTimer = null;
    this.nextRetryAt = null;
    this.portFailures = 0;
    this.logs = [];
  }

  pushLog(stream, text) {
    const line = { t: Date.now(), stream, text };
    this.logs.push(line);
    if (this.logs.length > LOG_LIMIT) this.logs.splice(0, this.logs.length - LOG_LIMIT);
    return line;
  }

  clearTimers() {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (this.stableTimer) clearTimeout(this.stableTimer);
    this.retryTimer = null;
    this.stableTimer = null;
    this.nextRetryAt = null;
  }
}

/**
 * 判断"这条隧道的连接参数变没变"用的签名。
 * 除了 ssh 参数，还把加密后的密码/口令算进去——改了密码也应该重建连接。
 */
function argsSignature(tunnel, config) {
  const auth = tunnel.auth || {};
  return JSON.stringify({
    args: buildSshArgs(tunnel, config),
    mode: auth.mode || 'key',
    password: auth.password || '',
    passphrase: auth.passphrase || '',
    identityFile: auth.identityFile || '',
  });
}

export class Supervisor extends EventEmitter {
  constructor(config, { logger = console } = {}) {
    super();
    this.config = config;
    this.logger = logger;
    this.runtimes = new Map();
    this.dataDir = path.join(path.dirname(config.configFile), '.ssh-proxy');
    this.stateFile = path.join(this.dataDir, 'state.json');
    this.runtimeFile = path.join(this.dataDir, 'runtime.json');
    this.shuttingDown = false;
    this.watchTimer = null;
  }

  async init({ reapOrphans = true } = {}) {
    fs.mkdirSync(this.dataDir, { recursive: true });
    this.askpassHelper = ensureAskpassHelper(this.dataDir);
    if (reapOrphans) await this.#reapOrphans();
    this.#build();
    this.watchTimer = setInterval(() => {
      this.#watch().catch((err) => this.logger.error?.('[watch]', err));
    }, this.config.supervision.watchIntervalMs);
    this.watchTimer.unref?.();
    return this;
  }

  /** 按配置 + 上次的用户意图建立运行时对象 */
  #build() {
    const persisted = readJsonSafe(this.stateFile, {}) || {};
    for (const tunnel of this.config.tunnels) {
      const saved = persisted[tunnel.id];
      const desired = typeof saved?.desired === 'boolean' ? saved.desired : Boolean(tunnel.autoStart);
      const rt = new Runtime(tunnel, desired);
      rt.lastArgs = argsSignature(tunnel, this.config);
      this.runtimes.set(tunnel.id, rt);
    }
  }

  async autostart() {
    for (const rt of this.runtimes.values()) {
      if (rt.desired) await this.start(rt.id, { manual: false });
    }
  }

  #get(id) {
    const rt = this.runtimes.get(id);
    if (!rt) throw new Error(`未知隧道: ${id}`);
    return rt;
  }

  #probeHost(tunnel) {
    const addr = tunnel.bindAddress;
    if (!addr || addr === '0.0.0.0' || addr === '::') return '127.0.0.1';
    return addr;
  }

  #log(rt, stream, text) {
    const line = rt.pushLog(stream, text);
    this.emit('log', { id: rt.id, line });
    if (stream === 'err') this.logger.warn?.(`[${rt.id}] ${text}`);
    else this.logger.log?.(`[${rt.id}] ${text}`);
  }

  #change() {
    this.emit('change', this.snapshot());
  }

  #persist() {
    const data = {};
    for (const rt of this.runtimes.values()) data[rt.id] = { desired: rt.desired };
    this.#writeJson(this.stateFile, data);
  }

  #recordRuntime() {
    const list = [];
    for (const rt of this.runtimes.values()) {
      if (rt.child?.pid) list.push({ id: rt.id, pid: rt.child.pid, spec: rt.tunnel.forwardSpec, at: Date.now() });
    }
    this.#writeJson(this.runtimeFile, list);
  }

  #writeJson(file, data) {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
      fs.renameSync(tmp, file);
    } catch (err) {
      this.logger.warn?.(`写入 ${file} 失败: ${err.message}`);
    }
  }

  /**
   * 面板/控制器重启后，回收上一次遗留的 ssh 进程。
   * 只杀“命令行里含有本隧道 -L 转发规格”的进程，避免误杀别人的 ssh。
   */
  async #reapOrphans() {
    const previous = readJsonSafe(this.runtimeFile, null);
    if (!Array.isArray(previous) || previous.length === 0) return;
    for (const entry of previous) {
      if (!entry?.pid || !processAlive(entry.pid)) continue;
      const cmdline = await readCmdline(entry.pid);
      const looksLikeOurs = cmdline.includes('-N') && (entry.spec ? cmdline.includes(entry.spec) : true);
      if (!looksLikeOurs) continue;
      this.logger.warn?.(`[reap] 结束上次遗留的 ssh 进程 pid=${entry.pid} (${entry.id})`);
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/PID', String(entry.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
        } else {
          process.kill(Number(entry.pid), 'SIGTERM');
        }
      } catch {
        /* 进程可能刚好自己退出了 */
      }
    }
    this.#writeJson(this.runtimeFile, []);
  }

  /**
   * "在浏览器打开"的目标地址：
   *  - url 空            → http://<本机>:<端口>/
   *  - url 以 / 开头      → http://<本机>:<端口>/<路径>
   *  - url 是完整 URL     → 原样使用（https 外链也行）
   */
  #openUrl(rt) {
    const t = rt.tunnel;
    const host = t.bindAddress === '0.0.0.0' || t.bindAddress === '::' ? '127.0.0.1' : t.bindAddress;
    const base = `${t.scheme === 'https' ? 'https' : 'http'}://${host.includes(':') ? `[${host}]` : host}:${t.localPort}`;
    const raw = String(t.url || '').trim();
    if (!raw) return `${base}/`;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw;
    return `${base}${raw.startsWith('/') ? '' : '/'}${raw}`;
  }

  async start(id, { manual = true } = {}) {
    const rt = this.#get(id);
    if (this.shuttingDown) throw new Error('面板正在关闭，无法启动隧道');
    rt.desired = true;
    if (manual) {
      rt.failures = 0;
      rt.paused = false;
    }
    this.#persist();
    if (rt.child) {
      this.#log(rt, 'info', '隧道已在运行');
      this.#change();
      return this.snapshotTunnel(rt);
    }
    if (rt.retryTimer) {
      clearTimeout(rt.retryTimer);
      rt.retryTimer = null;
      rt.nextRetryAt = null;
    }
    await this.#spawn(rt);
    return this.snapshotTunnel(rt);
  }

  async stop(id) {
    const rt = this.#get(id);
    rt.desired = false;
    rt.paused = false;
    rt.secret = null; // 手动停止就把"连接时输入"的凭据忘掉
    this.#persist();
    rt.clearTimers();
    const child = rt.child;
    if (!child) {
      rt.status = 'stopped';
      rt.upAt = null;
      rt.portFailures = 0;
      this.#change();
      return this.snapshotTunnel(rt);
    }
    rt.stopping = true;
    this.#log(rt, 'info', '正在停止隧道…');
    killTree(child, { force: true });
    let elapsed = 0;
    while (rt.child && elapsed < 6000) {
      await sleep(100);
      elapsed += 100;
    }
    if (rt.child) {
      this.#log(rt, 'warn', 'ssh 进程未响应，继续等待强制结束');
      killTree(child, { force: true });
      elapsed = 0;
      while (rt.child && elapsed < 3000) {
        await sleep(100);
        elapsed += 100;
      }
    }
    if (!rt.child) {
      rt.status = 'stopped';
      rt.upAt = null;
    }
    this.#change();
    return this.snapshotTunnel(rt);
  }

  async restart(id) {
    await this.stop(id);
    return this.start(id, { manual: true });
  }

  /** 「连接时输入」：把凭据放进内存（不落盘），然后立刻连 */
  async setSecret(id, value) {
    const rt = this.#get(id);
    const secret = String(value ?? '');
    if (!secret) throw new Error('密码不能为空');
    rt.secret = secret;
    rt.failures = 0;
    rt.paused = false;
    rt.lastError = null;
    this.#log(rt, 'info', '已收到凭据（只保存在内存里，不会写进配置文件）');
    if (rt.child) {
      // 已经在跑：换新凭据需要重建
      killTree(rt.child, { force: true });
      return this.snapshotTunnel(rt);
    }
    await this.#spawn(rt);
    return this.snapshotTunnel(rt);
  }

  /** 忘掉内存里的凭据（下次连接要重新输入） */
  forgetSecret(id) {
    const rt = this.#get(id);
    rt.secret = null;
    if (rt.status === 'needs-secret') this.#change();
    return this.snapshotTunnel(rt);
  }

  async startAll() {
    const out = [];
    for (const rt of this.runtimes.values()) out.push(await this.start(rt.id, { manual: true }));
    return out;
  }

  async stopAll() {
    const out = [];
    for (const rt of this.runtimes.values()) out.push(await this.stop(rt.id));
    return out;
  }

  async #spawn(rt) {
    if (this.shuttingDown || !rt.desired || rt.child || rt.paused) return;
    const tunnel = rt.tunnel;
    const auth = tunnel.auth || { mode: 'key' };

    // 先把凭据准备好：密码/口令可能是加密存在配置里，也可能是"连接时输入"存在内存里
    let secret = '';
    try {
      if (auth.mode === 'password') secret = decryptSecret(this.dataDir, auth.password);
      else if (auth.passphrase) secret = decryptSecret(this.dataDir, auth.passphrase);
      else if (auth.mode === 'ask') secret = rt.secret || '';
    } catch (err) {
      this.#failStart(rt, `读取保存的凭据失败（密钥文件变了？）: ${err.message}`);
      return;
    }
    if (auth.mode === 'ask' && !secret) {
      rt.status = 'needs-secret';
      rt.upAt = null;
      rt.lastError = null;
      this.#log(rt, 'warn', '这条隧道设置了「连接时输入」，等待你输入密码/口令');
      this.#change();
      return;
    }

    const busy = await probeTcp(tunnel.localPort, this.#probeHost(tunnel), 400);
    if (busy) {
      this.#failStart(rt, `本地端口 ${tunnel.bindAddress}:${tunnel.localPort} 已被其他程序占用`);
      return;
    }

    const prefix = commandPrefix(tunnel, this.config);
    const args = buildSshArgs(tunnel, this.config, { secret });
    rt.status = 'starting';
    rt.startedAt = Date.now();
    rt.upAt = null;
    rt.portFailures = 0;
    rt.lastError = null;
    rt.fatalSpawn = null;
    rt.stopping = false;
    this.#log(rt, 'info', `▶ ${formatCommand(prefix, args)}${secret ? '（凭据通过 askpass 传入，不进命令行）' : ''}`);
    this.#change();

    let child;
    try {
      child = spawn(prefix[0], [...prefix.slice(1), ...args], {
        windowsHide: true,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...process.env,
          ...(tunnel.env || {}),
          ...askpassEnv(this.askpassHelper, secret),
        },
      });
    } catch (err) {
      this.#failStart(rt, `无法启动 ssh (${prefix[0]}): ${err.message}`);
      return;
    }

    rt.child = child;
    rt.pid = child.pid ?? null;
    this.#recordRuntime();

    const onOut = makeLineReader((line) => this.#log(rt, 'out', line));
    const onErr = makeLineReader((line) => this.#log(rt, 'err', line));
    child.stdout?.on('data', onOut);
    child.stderr?.on('data', onErr);

    let closed = false;
    child.once('error', (err) => {
      rt.lastError = err.message;
      this.#log(rt, 'err', `ssh 启动失败: ${err.message}`);
      // 可执行文件都不存在的话，重试没有意义，直接停下并说清楚
      if (err.code === 'ENOENT') {
        rt.fatalSpawn = `找不到 ssh 可执行文件（${prefix[0]}），检查「全局设置」里的 ssh 路径`;
      }
    });
    child.once('close', (code, signal) => {
      if (closed) return;
      closed = true;
      this.#onClose(rt, code, signal);
    });

    // 就绪判定放到后台，避免 HTTP/CLI 调用被 9 秒的探测阻塞
    this.#waitReady(rt, child)
      .then((ready) => {
        if (rt.child !== child) return;
        if (!ready) {
          this.#log(rt, 'warn', `本地端口在 ${this.config.supervision.startTimeoutMs}ms 内未就绪，继续观察`);
          this.#change();
          return;
        }
        rt.status = 'up';
        rt.upAt = Date.now();
        rt.portFailures = 0;
        this.#log(rt, 'info', `✔ 隧道就绪: ${tunnel.bindAddress}:${tunnel.localPort} → ${tunnel.target.host}:${tunnel.target.port}`);
        if (rt.stableTimer) clearTimeout(rt.stableTimer);
        rt.stableTimer = setTimeout(() => {
          rt.failures = 0;
          rt.stableTimer = null;
        }, this.config.supervision.stableResetMs);
        rt.stableTimer.unref?.();
        if (tunnel.openOnUp) openExternal(this.#openUrl(rt));
        this.#change();
      })
      .catch((err) => this.#log(rt, 'err', `就绪探测异常: ${err.message}`));
  }

  async #waitReady(rt, child) {
    const tunnel = rt.tunnel;
    const deadline = Date.now() + this.config.supervision.startTimeoutMs;
    const host = this.#probeHost(tunnel);
    while (Date.now() < deadline) {
      if (rt.child !== child) return false;
      const ok = tunnel.healthUrl
        ? await probeHttp(tunnel.healthUrl, 1500)
        : await probeTcp(tunnel.localPort, host, 500);
      if (ok) return true;
      await sleep(300);
    }
    return false;
  }

  #onClose(rt, code, signal) {
    rt.child = null;
    rt.pid = null;
    rt.portFailures = 0;
    rt.clearTimers();
    this.#recordRuntime();

    if (rt.stopping || this.shuttingDown || !rt.desired) {
      rt.stopping = false;
      rt.status = 'stopped';
      rt.upAt = null;
      rt.fatalSpawn = null;
      this.#log(rt, 'info', '■ 隧道已停止');
      this.#change();
      return;
    }

    if (rt.fatalSpawn) {
      rt.status = 'failed';
      rt.paused = true;
      rt.lastError = rt.fatalSpawn;
      rt.fatalSpawn = null;
      this.#log(rt, 'err', rt.lastError);
      this.#change();
      return;
    }

    rt.upAt = null;
    rt.lastExit = { code, signal, at: Date.now() };
    rt.failures += 1;
    this.#log(rt, 'err', `ssh 退出 (code=${code ?? '-'} signal=${signal ?? '-'})，准备重连`);

    const max = this.config.supervision.maxFailures;
    if (rt.failures > max) {
      rt.status = 'failed';
      rt.paused = true;
      rt.lastError = `连续失败 ${max} 次，已暂停自动重连（点“重连”或开关重新开始）`;
      this.#log(rt, 'err', rt.lastError);
      this.#change();
      return;
    }

    rt.restarts += 1;
    rt.status = 'retrying';
    this.#scheduleRetry(rt);
    this.#change();
  }

  #failStart(rt, message) {
    rt.lastError = message;
    rt.failures += 1;
    this.#log(rt, 'err', `✖ ${message}`);
    if (!rt.desired) {
      rt.status = 'stopped';
      this.#change();
      return;
    }
    const max = this.config.supervision.maxFailures;
    if (rt.failures > max) {
      rt.status = 'failed';
      rt.paused = true;
      rt.lastError = `连续失败 ${max} 次，已暂停自动重连（点“重连”或开关重新开始）`;
      this.#log(rt, 'err', rt.lastError);
    } else {
      rt.status = 'retrying';
      this.#scheduleRetry(rt);
    }
    this.#change();
  }

  #scheduleRetry(rt) {
    const { backoffBaseMs, backoffMaxMs } = this.config.supervision;
    const exp = Math.min(backoffMaxMs, backoffBaseMs * 2 ** Math.max(0, rt.failures - 1));
    const jitter = Math.round(exp * (Math.random() * 0.3 - 0.15));
    const delay = Math.max(500, exp + jitter);
    if (rt.retryTimer) clearTimeout(rt.retryTimer);
    rt.nextRetryAt = Date.now() + delay;
    rt.retryTimer = setTimeout(() => {
      rt.retryTimer = null;
      rt.nextRetryAt = null;
      this.#spawn(rt).catch((err) => this.#log(rt, 'err', `重试失败: ${err.message}`));
    }, delay);
    rt.retryTimer.unref?.();
    this.#log(rt, 'info', `${(delay / 1000).toFixed(1)} 秒后重连（第 ${rt.failures} 次失败）`);
    this.#change();
  }

  /** 守护循环：隧道应开但端口不通 / starting 卡住 / retrying 丢失定时器，都拉回来 */
  async #watch() {
    if (this.shuttingDown) return;
    const { startTimeoutMs } = this.config.supervision;
    for (const rt of this.runtimes.values()) {
      if (!rt.desired || rt.paused || rt.status === 'needs-secret') continue;
      if (rt.status === 'up' && rt.child) {
        const ok = await probeTcp(rt.tunnel.localPort, this.#probeHost(rt.tunnel), 800);
        if (!rt.child) continue;
        if (ok) {
          rt.portFailures = 0;
        } else {
          rt.portFailures += 1;
          this.#log(rt, 'warn', `本地端口探测失败 (${rt.portFailures}/3)`);
          if (rt.portFailures >= 3) {
            this.#log(rt, 'err', '隧道已不可用，重建连接');
            rt.portFailures = 0;
            killTree(rt.child, { force: true });
          }
        }
      } else if (rt.status === 'starting' && rt.child && Date.now() - (rt.startedAt || 0) > startTimeoutMs + 15000) {
        this.#log(rt, 'err', '连接超时，重建连接');
        killTree(rt.child, { force: true });
      } else if (rt.status === 'retrying' && !rt.retryTimer && !rt.child) {
        this.#scheduleRetry(rt);
      }
    }
  }

  logs(id, limit = 200) {
    const rt = this.#get(id);
    const n = Math.max(1, Math.min(LOG_LIMIT, Number(limit) || 200));
    return rt.logs.slice(-n);
  }

  /** 重新读配置文件：新增/删除/改动的隧道都做相应处理 */
  async reload(config) {
    const prevSsh = JSON.stringify(this.config.ssh || {});
    const prevWatch = this.config.supervision?.watchIntervalMs;
    this.config = config;

    const sshChanged = prevSsh !== JSON.stringify(config.ssh || {});
    const watchChanged = prevWatch !== config.supervision.watchIntervalMs;
    if (watchChanged && this.watchTimer) {
      clearInterval(this.watchTimer);
      this.watchTimer = setInterval(() => {
        this.#watch().catch((err) => this.logger.error?.('[watch]', err));
      }, config.supervision.watchIntervalMs);
      this.watchTimer.unref?.();
    }

    const seen = new Set();
    const added = [];
    const changed = new Set();
    const removed = [];
    for (const tunnel of config.tunnels) {
      seen.add(tunnel.id);
      const rt = this.runtimes.get(tunnel.id);
      if (!rt) {
        const next = new Runtime(tunnel, Boolean(tunnel.autoStart));
        next.lastArgs = argsSignature(tunnel, config);
        this.runtimes.set(tunnel.id, next);
        added.push(tunnel.id);
        continue;
      }
      rt.tunnel = tunnel;
      // 全局 ssh 参数变了 → 所有在跑的隧道都要按新参数重建
      if (sshChanged && rt.child) changed.add(tunnel.id);
    }

    for (const [id, rt] of [...this.runtimes.entries()]) {
      if (!seen.has(id)) {
        await this.stop(id);
        this.runtimes.delete(id);
        removed.push(id);
      }
    }

    // 隧道自身参数变了（端口/跳板/目标/链路）→ 重建
    for (const tunnel of config.tunnels) {
      const rt = this.runtimes.get(tunnel.id);
      if (!rt || added.includes(tunnel.id)) continue;
      const args = argsSignature(tunnel, this.config);
      if (rt.lastArgs && rt.lastArgs !== args) changed.add(tunnel.id);
      rt.lastArgs = args;
    }

    for (const id of changed) {
      const rt = this.runtimes.get(id);
      if (!rt) continue;
      this.#log(rt, 'warn', '配置已变更，隧道将重建');
      rt.failures = 0;
      rt.paused = false;
      if (rt.child) killTree(rt.child, { force: true });
    }

    // 新增的隧道如果标了 autoStart，直接拉起来
    for (const id of added) {
      const rt = this.runtimes.get(id);
      if (rt?.desired) await this.start(id, { manual: false });
    }

    this.#persist();
    this.#change();
    return { added, changed: [...changed], removed, tunnels: config.tunnels.length };
  }

  snapshotTunnel(rt) {
    const t = rt.tunnel;
    return {
      id: rt.id,
      name: t.name,
      description: t.description,
      status: rt.status,
      desired: rt.desired,
      paused: rt.paused,
      bindAddress: t.bindAddress,
      localPort: t.localPort,
      target: t.target,
      via: {
        host: t.via.host,
        port: t.via.port,
        user: t.via.user,
        proxyJump: t.via.ProxyJump,
        identityFile: t.via.identityFile || '',
      },
      auth: {
        mode: t.auth?.mode || 'key',
        identityFile: t.auth?.identityFile || '',
        hasPassword: Boolean(t.auth?.password),
        hasPassphrase: Boolean(t.auth?.passphrase),
        hasSecret: Boolean(rt.secret),
        needsSecret: rt.status === 'needs-secret',
      },
      scheme: t.scheme,
      healthUrl: t.healthUrl || '',
      extraArgs: t.extraArgs || [],
      url: this.#openUrl(rt),
      openPath: t.url || '',
      command: formatCommand(commandPrefix(t, this.config), buildSshArgs(t, this.config)),
      pid: rt.pid,
      startedAt: rt.startedAt,
      upAt: rt.upAt,
      uptimeMs: rt.upAt ? Date.now() - rt.upAt : 0,
      restarts: rt.restarts,
      failures: rt.failures,
      lastError: rt.lastError,
      lastExit: rt.lastExit,
      nextRetryAt: rt.nextRetryAt,
      autoStart: Boolean(t.autoStart),
      openOnUp: Boolean(t.openOnUp),
    };
  }

  snapshot() {
    const tunnels = [...this.runtimes.values()].map((rt) => this.snapshotTunnel(rt));
    return {
      ts: Date.now(),
      tunnels,
      stats: {
        total: tunnels.length,
        up: tunnels.filter((t) => t.status === 'up').length,
        desired: tunnels.filter((t) => t.desired).length,
        failed: tunnels.filter((t) => t.status === 'failed').length,
      },
      panel: { configFile: this.config.configFile },
    };
  }

  async shutdown() {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    if (this.watchTimer) clearInterval(this.watchTimer);
    this.watchTimer = null;
    const active = [...this.runtimes.values()].filter((rt) => rt.child);
    for (const rt of this.runtimes.values()) rt.clearTimers();
    for (const rt of active) {
      rt.stopping = true;
      killTree(rt.child, { force: true });
    }
    for (const rt of active) {
      let elapsed = 0;
      while (rt.child && elapsed < 4000) {
        await sleep(100);
        elapsed += 100;
      }
    }
    this.#writeJson(this.runtimeFile, []);
  }
}
