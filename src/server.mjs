import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { loadConfig } from './config.mjs';
import { mutateTunnels, mutateSettings, writeRawConfig, addPublicKey, removePublicKey } from './config-writer.mjs';
import { verifyPassword, verifySignature, newChallenge } from './auth.mjs';
import { encryptSecret } from './secrets.mjs';
import { publicDir as defaultPublicDir } from './app-root.mjs';

const DEFAULT_PUBLIC_DIR = defaultPublicDir();
const BODY_LIMIT = 256 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        reject(new ApiError(413, '请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('error', reject);
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (!text.trim()) return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch (err) {
        reject(new ApiError(400, `请求体不是合法 JSON: ${err.message}`));
      }
    });
  });
}

/** 面板表单需要的完整隧道字段 */
function tunnelForForm(t) {
  return {
    id: t.id,
    name: t.name,
    description: t.description,
    localPort: t.localPort,
    bindAddress: t.bindAddress,
    target: t.target,
    via: {
      user: t.via.user || '',
      host: t.via.host,
      port: t.via.port,
      identityFile: t.via.identityFile || '',
      proxyJump: t.via.ProxyJump || '',
    },
    auth: {
      mode: t.auth?.mode || 'key',
      identityFile: t.auth?.identityFile || '',
      hasPassword: Boolean(t.auth?.password),
      hasPassphrase: Boolean(t.auth?.passphrase),
    },
    scheme: t.scheme,
    url: t.url || '',
    healthUrl: t.healthUrl || '',
    extraArgs: t.extraArgs || [],
    autoStart: Boolean(t.autoStart),
    openOnUp: Boolean(t.openOnUp),
  };
}

export function createPanelServer({ supervisor, config, publicDir = DEFAULT_PUBLIC_DIR }) {
  const clients = new Set();
  let stateTimer = null;
  let current = config;

  const writeEvent = (res, event, data) => {
    try {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    } catch {
      clients.delete(res);
    }
  };

  const broadcastState = () => {
    const snapshot = supervisor.snapshot();
    for (const res of clients) writeEvent(res, 'state', snapshot);
  };

  const scheduleState = () => {
    if (stateTimer) return;
    stateTimer = setTimeout(() => {
      stateTimer = null;
      broadcastState();
    }, 100);
    stateTimer.unref?.();
  };

  const onLog = ({ id, line }) => {
    for (const res of clients) writeEvent(res, 'log', { id, line });
  };

  const onConfigChange = () => {
    for (const res of clients) writeEvent(res, 'config', { configFile: current.configFile });
  };

  supervisor.on('change', scheduleState);
  supervisor.on('log', onLog);

  const heartbeat = setInterval(() => {
    for (const res of clients) {
      try {
        res.write(': ping\n\n');
      } catch {
        clients.delete(res);
      }
    }
  }, 25000);
  heartbeat.unref?.();

  /** 配置变更后的统一入口：先热更新托管器，再切换本服务的配置引用 */
  async function applyConfig(next) {
    // panel 的"门户参数"只落盘不热应用：它们要么需要重新 listen（host/port），
    // 要么会当场把当前会话踢下线（token / 会话时效）。
    next.panel = {
      ...next.panel,
      host: current.panel.host,
      port: current.panel.port,
      token: current.panel.token,
      tokenSource: current.panel.tokenSource,
      sessionTtlMinutes: current.panel.sessionTtlMinutes,
      sessionIdleMinutes: current.panel.sessionIdleMinutes,
    };
    // 密码、公钥是"可以热加"的凭据，但可用方式要按实际生效的凭据重算
    const methods = [];
    if (next.panel.token) methods.push('token');
    if (next.panel.passwordHash) methods.push('password');
    if ((next.panel.publicKeys || []).length) methods.push('key');
    const wanted = Array.isArray(next.panel.authMethods) ? next.panel.authMethods : [];
    next.panel.authMethods = wanted.length ? methods.filter((m) => wanted.includes(m)) : methods;
    if (!next.panel.authMethods.length) next.panel.authMethods = methods;

    await supervisor.reload(next);
    current = next;
    onConfigChange();
  }

  /* ---------------- 登录态（会话） ---------------- */

  const SESSION_COOKIE = 'sshproxy_session';
  const sessions = new Map(); // id -> { createdAt, lastSeen, expiresAt, idleUntil, idleMs, method }
  const challenges = new Map(); // challengeId -> { challenge, keyId, expiresAt }
  const MAX_SESSIONS = 32;
  let loginGuard = { failures: 0, until: 0 };

  /** 当前启用的登录方式（token / password / key），由配置推导 */
  const authMethods = () => current.panel?.authMethods || [];

  const ttlMs = () => Math.max(1000, Number(current.panel.sessionTtlMinutes ?? 720) * 60_000);
  const idleMs = () => Math.max(1000, Number(current.panel.sessionIdleMinutes ?? 120) * 60_000);

  function createSession(method = 'token') {
    const id = crypto.randomBytes(24).toString('base64url');
    const now = Date.now();
    const idle = idleMs();
    sessions.set(id, { createdAt: now, lastSeen: now, expiresAt: now + ttlMs(), idleUntil: now + idle, idleMs: idle, method });
    if (sessions.size > MAX_SESSIONS) {
      const oldest = [...sessions.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen)[0];
      if (oldest) sessions.delete(oldest[0]);
    }
    return id;
  }

  /** 返回 { ok, reason }；ok 时顺带把闲置时间续上（滑动过期） */
  function touchSession(id) {
    const session = sessions.get(id);
    if (!session) return { ok: false, reason: 'unknown' };
    const now = Date.now();
    if (now > session.expiresAt) {
      sessions.delete(id);
      return { ok: false, reason: 'expired' };
    }
    if (now > session.idleUntil) {
      sessions.delete(id);
      return { ok: false, reason: 'idle' };
    }
    session.lastSeen = now;
    session.idleUntil = now + session.idleMs;
    return { ok: true, session };
  }

  function readCookie(req, name) {
    const raw = req.headers.cookie;
    if (typeof raw !== 'string' || !raw) return '';
    for (const part of raw.split(';')) {
      const idx = part.indexOf('=');
      if (idx < 0) continue;
      if (part.slice(0, idx).trim() !== name) continue;
      try {
        return decodeURIComponent(part.slice(idx + 1).trim());
      } catch {
        return part.slice(idx + 1).trim();
      }
    }
    return '';
  }

  function sessionCookie(id) {
    const maxAge = Math.floor(ttlMs() / 1000);
    return `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
  }

  const CLEAR_COOKIE = `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;

  /**
   * 鉴权：会话 Cookie（浏览器），或请求头/查询串里的令牌（脚本/CLI）。
   * 没配置任何登录方式时直接放行。
   */
  function authenticate(req, url) {
    const methods = authMethods();
    if (methods.length === 0) return { ok: true, method: 'none' };

    const session = readCookie(req, SESSION_COOKIE);
    if (session) {
      const result = touchSession(session);
      if (result.ok) return { ok: true, method: 'session', session: result.session };
      return { ok: false, reason: result.reason };
    }

    if (methods.includes('token')) {
      const token = current.panel.token;
      const header = req.headers['x-panel-token'];
      if (typeof header === 'string' && header && safeEqual(header, token)) return { ok: true, method: 'token' };
      const query = url.searchParams.get('token');
      if (typeof query === 'string' && query && safeEqual(query, token)) return { ok: true, method: 'token' };
    }
    return { ok: false, reason: 'missing' };
  }

  /** Cookie 会话必须防跨站表单提交；带 Origin 且和 Host 不一致就拒绝 */
  function sameOrigin(req) {
    const origin = req.headers.origin;
    if (typeof origin !== 'string' || !origin) return true;
    try {
      return new URL(origin).host === (req.headers.host || '');
    } catch {
      return false;
    }
  }

  function sessionInfo(id) {
    const session = id ? sessions.get(id) : null;
    const now = Date.now();
    const valid = Boolean(session && now <= session.expiresAt && now <= session.idleUntil);
    const methods = authMethods();
    const keys = (current.panel.publicKeys || []).map((k) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint }));
    return {
      authRequired: methods.length > 0,
      authenticated: methods.length === 0 || valid,
      method: valid ? session.method : null,
      expiresAt: valid ? session.expiresAt : null,
      idleUntil: valid ? session.idleUntil : null,
      ttlMinutes: Number(current.panel?.sessionTtlMinutes ?? 720),
      idleMinutes: Number(current.panel?.sessionIdleMinutes ?? 120),
      tokenSource: current.panel?.tokenSource || 'none',
      methods,
      keyCount: keys.length,
      keys: valid ? keys : [],
    };
  }

  function sessionPayload(req) {
    return sessionInfo(readCookie(req, SESSION_COOKIE));
  }

  /** 一次性挑战：签名登录用 */
  function issueChallenge(keyId) {
    const key = (current.panel.publicKeys || []).find((k) => k.id === keyId);
    if (!key) return null;
    const id = crypto.randomBytes(12).toString('hex');
    const challenge = newChallenge();
    challenges.set(id, { challenge, keyId, expiresAt: Date.now() + 120_000 });
    for (const [cid, item] of challenges) {
      if (Date.now() > item.expiresAt) challenges.delete(cid);
    }
    return { challengeId: id, challenge, keyId, expiresIn: 120 };
  }

  function verifyKeyLogin(body) {
    const challengeId = String(body?.challengeId || '');
    const signature = String(body?.signature || '');
    if (!challengeId || !signature) return false;
    const entry = challenges.get(challengeId);
    if (!entry) return false;
    challenges.delete(challengeId); // 一次性，防止重放
    if (Date.now() > entry.expiresAt) return false;
    const key = (current.panel.publicKeys || []).find((k) => k.id === entry.keyId);
    if (!key) return false;
    return verifySignature(key.key, entry.challenge, signature);
  }

  /**
   * 前端资源版本号（app.js + style.css 的 mtime/size）。
   * 页面会带上 ?v=，服务端也能通过 /healthz 告诉页面对不上——
   * 这样"改了代码但浏览器还挂着旧页面"就不会再变成玄学。
   */
  let versionCache = { at: 0, value: '0' };
  function assetVersion() {
    const now = Date.now();
    if (now - versionCache.at < 2000 && versionCache.value !== '0') return versionCache.value;
    try {
      const files = ['app.js', 'style.css'].map((name) => fs.statSync(path.join(publicDir, name)));
      const mtime = Math.max(...files.map((f) => f.mtimeMs));
      const size = files.reduce((sum, f) => sum + f.size, 0);
      versionCache = { at: now, value: `${Math.round(mtime)}-${size}` };
    } catch {
      versionCache = { at: now, value: '0' };
    }
    return versionCache.value;
  }

  function serveStatic(res, pathname) {
    const root = path.resolve(publicDir);
    let rel = decodeURIComponent(pathname);
    if (rel === '/' || rel === '') rel = '/index.html';
    const target = path.resolve(root, path.normalize(rel).replace(/^([/\\])+/, ''));
    if (target !== root && !target.startsWith(root + path.sep)) {
      res.writeHead(403).end('forbidden');
      return;
    }
    fs.readFile(target, (err, data) => {
      if (err) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('not found');
        return;
      }
      let body = data;
      if (path.extname(target).toLowerCase() === '.html') {
        // 给静态资源加版本号，顺手让页面知道自己的版本
        const v = assetVersion();
        const text = data
          .toString('utf8')
          .replace('href="/style.css"', `href="/style.css?v=${v}"`)
          .replace('src="/app.js"', `src="/app.js?v=${v}"`);
        body = Buffer.from(text, 'utf8');
      }
      res.writeHead(200, {
        'content-type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream',
        'cache-control': 'no-store',
        'content-length': body.length,
      });
      res.end(body);
    });
  }

  /** 配置校验类错误一律按 400 返回（写文件失败才是 500） */
  function validated(fn) {
    try {
      return fn();
    } catch (err) {
      throw new ApiError(400, err.message);
    }
  }

  /** 表单里的明文密码/口令 → 加密后再落盘 */
  function withEncryptedAuth(payload) {
    if (!payload || typeof payload !== 'object') return payload;
    if (!payload.auth || typeof payload.auth !== 'object') return payload;
    const dataDir = path.join(path.dirname(current.configFile), '.ssh-proxy');
    const auth = { ...payload.auth };
    if (typeof auth.password === 'string' && auth.password) auth.password = encryptSecret(dataDir, auth.password);
    if (typeof auth.passphrase === 'string' && auth.passphrase) auth.passphrase = encryptSecret(dataDir, auth.passphrase);
    return { ...payload, auth };
  }

  async function handleApi(req, res, url) {
    const { pathname, searchParams } = url;
    const method = req.method || 'GET';

    if (pathname === '/api/state' && method === 'GET') {
      return json(res, 200, supervisor.snapshot());
    }

    if (pathname === '/api/config' && method === 'GET') {
      return json(res, 200, {
        configFile: current.configFile,
        panel: {
          host: current.panel.host,
          port: current.panel.port,
          tokenRequired: authMethods().length > 0,
          tokenSource: current.panel.tokenSource || 'none',
          methods: authMethods(),
          hasPassword: Boolean(current.panel.passwordHash),
          hasToken: Boolean(current.panel.token),
          keys: (current.panel.publicKeys || []).map((k) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint, createdAt: k.createdAt })),
          sessionTtlMinutes: current.panel.sessionTtlMinutes,
          sessionIdleMinutes: current.panel.sessionIdleMinutes,
          openOnStart: Boolean(current.panel.openOnStart),
        },
        ssh: current.ssh,
        supervision: current.supervision,
        tunnels: current.tunnels.map(tunnelForForm),
      });
    }

    if (pathname === '/api/events' && method === 'GET') {
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-store',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      res.write('retry: 2000\n\n');
      clients.add(res);
      writeEvent(res, 'state', supervisor.snapshot());
      req.on('close', () => clients.delete(res));
      return undefined;
    }

    const logsMatch = pathname.match(/^\/api\/tunnels\/([^/]+)\/logs$/);
    if (logsMatch && method === 'GET') {
      const id = decodeURIComponent(logsMatch[1]);
      return json(res, 200, { id, lines: supervisor.logs(id, Number(searchParams.get('lines')) || 200) });
    }

    const actionMatch = pathname.match(/^\/api\/tunnels\/([^/]+)\/(start|stop|restart)$/);
    if (actionMatch && method === 'POST') {
      const id = decodeURIComponent(actionMatch[1]);
      const action = actionMatch[2];
      const tunnel =
        action === 'stop'
          ? await supervisor.stop(id)
          : action === 'restart'
            ? await supervisor.restart(id)
            : await supervisor.start(id, { manual: true });
      return json(res, 200, { ok: true, tunnel, state: supervisor.snapshot() });
    }

    // 「连接时输入」：把密码/口令交给运行中的隧道（只进内存）
    const secretMatch = pathname.match(/^\/api\/tunnels\/([^/]+)\/secret$/);
    if (secretMatch && method === 'POST') {
      const id = decodeURIComponent(secretMatch[1]);
      const body = await readBody(req);
      const value = typeof body?.value === 'string' ? body.value : '';
      if (!value) throw new ApiError(400, '密码不能为空');
      const tunnel = await supervisor.setSecret(id, value);
      return json(res, 200, { ok: true, tunnel, state: supervisor.snapshot() });
    }
    if (secretMatch && method === 'DELETE') {
      const id = decodeURIComponent(secretMatch[1]);
      const tunnel = supervisor.forgetSecret(id);
      return json(res, 200, { ok: true, tunnel });
    }

    /* ---------- 配置编辑 ---------- */

    if (pathname === '/api/tunnels' && method === 'POST') {
      const payload = await readBody(req);
      const { raw, config: next } = validated(() =>
        mutateTunnels(current.configFile, { action: 'create', payload: withEncryptedAuth(payload) }),
      );
      writeRawConfig(current.configFile, raw);
      await applyConfig(next);
      const tunnel = supervisor.snapshot().tunnels.find((t) => t.id === payload?.id) || null;
      return json(res, 200, { ok: true, tunnel, state: supervisor.snapshot() });
    }

    const tunnelMatch = pathname.match(/^\/api\/tunnels\/([^/]+)$/);
    if (tunnelMatch && (method === 'PUT' || method === 'PATCH' || method === 'DELETE')) {
      const id = decodeURIComponent(tunnelMatch[1]);
      const wasRunning = Boolean(supervisor.runtimes.get(id)?.desired);
      const payload = method === 'DELETE' ? null : await readBody(req);
      const { raw, config: next } = validated(() =>
        mutateTunnels(current.configFile, {
          action: method === 'DELETE' ? 'delete' : 'update',
          id,
          payload: payload ? withEncryptedAuth(payload) : payload,
        }),
      );
      writeRawConfig(current.configFile, raw);
      await applyConfig(next);
      const newId = method === 'DELETE' ? null : String(payload?.id ?? id).trim() || id;
      if (method !== 'DELETE' && newId !== id && wasRunning) {
        await supervisor.start(newId, { manual: true });
      }
      const tunnel = newId ? supervisor.snapshot().tunnels.find((t) => t.id === newId) || null : null;
      return json(res, 200, { ok: true, id: newId, tunnel, state: supervisor.snapshot() });
    }

    if (pathname === '/api/settings' && (method === 'PUT' || method === 'PATCH')) {
      const payload = await readBody(req);
      const { raw, config: next } = validated(() => mutateSettings(current.configFile, payload));
      writeRawConfig(current.configFile, raw);
      // panel.token / 会话时效只落盘，不热应用（applyConfig 里统一处理），这里只负责告诉前端要重启
      const panelChanged =
        next.panel.token !== current.panel.token ||
        next.panel.sessionTtlMinutes !== current.panel.sessionTtlMinutes ||
        next.panel.sessionIdleMinutes !== current.panel.sessionIdleMinutes;
      await applyConfig(next);
      return json(res, 200, {
        ok: true,
        restartRequired: panelChanged,
        ssh: next.ssh,
        supervision: next.supervision,
        panel: { tokenRequired: Boolean(next.panel.token), sessionTtlMinutes: next.panel.sessionTtlMinutes, sessionIdleMinutes: next.panel.sessionIdleMinutes },
        state: supervisor.snapshot(),
      });
    }

    if (pathname === '/api/auth/keys' && method === 'POST') {
      const body = await readBody(req);
      const result = validated(() => addPublicKey(current.configFile, { name: body?.name, key: body?.publicKey }));
      writeRawConfig(current.configFile, result.raw);
      // 加密钥是纯增量，热应用即可（不像改 token 会把自己踢下线）
      current.panel = result.config.panel;
      onConfigChange();
      return json(res, 200, {
        ok: true,
        id: result.id,
        fingerprint: result.fingerprint,
        methods: authMethods(),
        keys: (current.panel.publicKeys || []).map((k) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint })),
      });
    }

    const keyMatch = pathname.match(/^\/api\/auth\/keys\/([^/]+)$/);
    if (keyMatch && method === 'DELETE') {
      const target = decodeURIComponent(keyMatch[1]);
      const result = validated(() => removePublicKey(current.configFile, target));
      if (result.config.panel.authMethods.length === 0) {
        throw new ApiError(400, '删掉这把密钥后就没有任何登录方式了（面板会变成开放的），先设置令牌或密码再删');
      }
      writeRawConfig(current.configFile, result.raw);
      current.panel = result.config.panel;
      onConfigChange();
      return json(res, 200, { ok: true, methods: authMethods(), keys: (current.panel.publicKeys || []).map((k) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint })) });
    }

    const allMatch = pathname.match(/^\/api\/all\/(start|stop)$/);
    if (allMatch && method === 'POST') {
      if (allMatch[1] === 'start') await supervisor.startAll();
      else await supervisor.stopAll();
      return json(res, 200, { ok: true, state: supervisor.snapshot() });
    }

    if (pathname === '/api/reload' && method === 'POST') {
      const next = loadConfig(current.configFile);
      const result = await supervisor.reload(next);
      current = next;
      onConfigChange();
      return json(res, 200, { ok: true, ...result });
    }

    // 给托盘/脚本用的"优雅退出"：先停所有隧道再退
    if (pathname === '/api/shutdown' && method === 'POST') {
      json(res, 200, { ok: true, stopping: true });
      setTimeout(() => {
        supervisor
          .shutdown()
          .catch(() => {})
          .finally(() => process.exit(0));
      }, 250);
      return undefined;
    }

    return json(res, 404, { error: `未知接口: ${method} ${pathname}` });
  }

  async function handleSession(req, res, url) {
    const method = req.method || 'GET';

    if (method === 'GET') return json(res, 200, sessionPayload(req));

    if (!sameOrigin(req)) return json(res, 403, { error: '跨站请求被拒绝' });

    if (method === 'POST') {
      const now = Date.now();
      if (loginGuard.until > now) {
        const wait = Math.ceil((loginGuard.until - now) / 1000);
        return json(res, 429, { error: `尝试太频繁，请 ${wait} 秒后再试`, retryAfter: wait });
      }
      const body = await readBody(req);
      const methods = authMethods();
      if (methods.length === 0) return json(res, 200, { ok: true, ...sessionInfo('') });

      const mode = String(body?.mode || 'token');
      if (!methods.includes(mode)) {
        return json(res, 400, { error: `未启用这种登录方式: ${mode}`, methods });
      }

      let passed = false;
      if (mode === 'token') {
        const given = typeof body?.token === 'string' ? body.token.trim() : '';
        passed = Boolean(given) && safeEqual(given, current.panel.token);
      } else if (mode === 'password') {
        passed = verifyPassword(body?.password, current.panel.passwordHash);
      } else if (mode === 'key') {
        passed = verifyKeyLogin(body);
      }

      if (!passed) {
        loginGuard.failures += 1;
        if (loginGuard.failures >= 5) loginGuard = { failures: 0, until: now + 30_000 };
        const message = mode === 'password' ? '密码不正确' : mode === 'key' ? '密钥签名校验失败' : '令牌不正确';
        return json(res, 401, { error: message, mode });
      }

      loginGuard = { failures: 0, until: 0 };
      const id = createSession(mode);
      res.setHeader('set-cookie', sessionCookie(id));
      return json(res, 200, { ok: true, ...sessionInfo(id) });
    }

    if (method === 'DELETE') {
      const sid = readCookie(req, SESSION_COOKIE);
      if (sid) sessions.delete(sid);
      res.setHeader('set-cookie', CLEAR_COOKIE);
      return json(res, 200, { ok: true, authRequired: authMethods().length > 0, authenticated: authMethods().length === 0 });
    }

    return json(res, 405, { error: `不支持的方法: ${method}` });
  }

  // 定期清理过期会话，避免长期不访问的会话一直留在内存里
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (now > session.expiresAt || now > session.idleUntil) sessions.delete(id);
    }
  }, 300_000);
  sweeper.unref?.();

  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('referrer-policy', 'no-referrer');

    // 不需要鉴权：只暴露"要不要登录 / 有哪些登录方式 / 前端资源版本"，前端据此决定弹不弹窗
    if (url.pathname === '/healthz') {
      const methods = authMethods();
      return json(res, 200, {
        ok: true,
        up: supervisor.snapshot().stats.up,
        authRequired: methods.length > 0,
        methods,
        tokenSource: current.panel.tokenSource || 'none',
        version: assetVersion(),
      });
    }

    // 登录态：GET 查状态（公开），POST 用令牌/密码/密钥换会话，DELETE 退出
    if (url.pathname === '/api/session') {
      return handleSession(req, res, url).catch((err) => {
        if (!res.headersSent) json(res, err.status || 500, { error: err.message });
        else res.end();
      });
    }

    // 签名登录的挑战（公开：没登录才需要它）
    if (url.pathname === '/api/auth/challenge' && req.method === 'GET') {
      const info = issueChallenge(String(url.searchParams.get('keyId') || ''));
      if (!info) return json(res, 404, { error: '找不到这把密钥，可能已被删除；请用令牌或密码登录后重新注册' });
      return json(res, 200, info);
    }

    if (url.pathname.startsWith('/api/')) {
      const auth = authenticate(req, url);
      if (!auth.ok) {
        const message =
          auth.reason === 'expired'
            ? '登录已过期，请重新输入令牌'
            : auth.reason === 'idle'
              ? '太久没有操作，登录已失效'
              : '需要访问令牌';
        return json(res, 401, { error: message, authRequired: true, sessionExpired: auth.reason !== 'missing' });
      }
      if (req.method !== 'GET' && req.method !== 'HEAD' && !sameOrigin(req)) {
        return json(res, 403, { error: '跨站请求被拒绝' });
      }
      return handleApi(req, res, url).catch((err) => {
        const status = err instanceof ApiError ? err.status : err.status || 500;
        if (!res.headersSent) json(res, status, { error: err.message });
        else res.end();
      });
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return json(res, 405, { error: '不支持的方法' });
    }
    return serveStatic(res, url.pathname);
  });

  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  async function close() {
    clearInterval(heartbeat);
    clearInterval(sweeper);
    if (stateTimer) clearTimeout(stateTimer);
    supervisor.off('change', scheduleState);
    supervisor.off('log', onLog);
    for (const res of clients) {
      try {
        res.end();
      } catch {
        /* ignore */
      }
    }
    clients.clear();
    await new Promise((resolve) => server.close(resolve));
  }

  return { server, close };
}
