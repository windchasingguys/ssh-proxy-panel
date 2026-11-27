#!/usr/bin/env node
/**
 * 鉴权与会话的等价性对照（M3 的回归闸门）。
 *
 *   node rust/tools/auth-parity.mjs
 *   node rust/tools/auth-parity.mjs --keep
 *
 * 做的事：造一份开了三种登录方式的配置（token + scrypt 密码 + Ed25519 公钥），
 * 同时起 Node 版与 Rust 版，把同一批请求打过去，比状态码与响应体（忽略 cookie 值、时间戳）。
 * 另外做两项跨实现交叉验证：
 *   - Node 生成的 scrypt 哈希，Rust 必须能验通过；
 *   - Node 生成的 Ed25519 签名，Rust 必须能验通过（等价于"浏览器里签名、Rust 校验"）。
 */
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const RUST_EXE = path.join(ROOT, 'rust', 'target', 'x86_64-pc-windows-gnu', 'release', 'ssh-proxy.exe');
const keep = process.argv.includes('--keep');
const PORT_RUST = await freePort();
const PORT_NODE = await freePort();
const TOKEN = 'test-token-42';
const PASSWORD = 'pw-测试-1234';

/** 取一个空闲端口：测试一律自己找端口，绝不占用可能已经在跑的实例 */
async function freePort() {
  const net = await import('node:net');
  return await new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}
const fail = (msg) => {
  console.error(`✖ ${msg}`);
  process.exit(1);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
if (!fs.existsSync(RUST_EXE)) fail(`找不到 Rust 二进制：${RUST_EXE}`);

const { hashPassword } = await import(pathToFileURL(path.join(ROOT, 'src', 'auth.mjs')).href);

// ---- 造 Ed25519 密钥（公钥转成 OpenSSH 单行格式）
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const spki = publicKey.export({ type: 'spki', format: 'der' });
const raw = spki.subarray(spki.length - 32);
const sshString = (buf) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
};
const blob = Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(raw)]);
const publicKeyOpenSsh = `ssh-ed25519 ${blob.toString('base64')}`;
const passwordHash = hashPassword(PASSWORD);

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-proxy-auth-'));
const configFile = path.join(work, 'tunnels.json');
fs.writeFileSync(
  configFile,
  JSON.stringify(
    {
      panel: {
        host: '127.0.0.1',
        port: 7799,
        token: TOKEN,
        passwordHash,
        publicKeys: [{ id: 'k1', name: '测试密钥', key: publicKeyOpenSsh }],
        sessionTtlMinutes: 720,
        sessionIdleMinutes: 120,
      },
      ssh: { bin: [process.execPath, path.join(ROOT, 'test', 'fake-ssh.mjs')], batchMode: true },
      tunnels: [
        {
          id: 'app',
          name: 'app',
          localPort: 28941,
          target: { host: '10.0.0.12', port: 8080 },
          via: 'deploy@edge.example.com:22',
          auth: { mode: 'key' },
        },
      ],
    },
    null,
    2,
  ),
);

function start(which, port) {
  const args = ['serve', '--config', configFile, '--port', String(port), '--quiet'];
  if (which === 'rust') {
    return spawn(RUST_EXE, args, {
      cwd: work,
      stdio: 'ignore',
      windowsHide: true,
      env: { ...process.env, SSH_PROXY_WEB_ROOT: path.join(ROOT, 'public') },
    });
  }
  return spawn(process.execPath, [path.join(ROOT, 'src', 'cli.mjs'), ...args], {
    cwd: ROOT,
    stdio: 'ignore',
    windowsHide: true,
  });
}

async function waitReady(port, proc) {
  for (let i = 0; i < 80; i++) {
    if (proc.exitCode !== null) throw new Error(`进程已退出（code ${proc.exitCode}）`);
    try {
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (res.ok) return;
    } catch {
      /* 还没起来 */
    }
    await sleep(100);
  }
  throw new Error(`等 /healthz 超时（端口 ${port}）`);
}

/** 把一组请求打到一个端口上，返回归一化后的结果 */
async function runSuite(port) {
  const out = [];
  const call = async (name, route, init = {}) => {
    const res = await fetch(`http://127.0.0.1:${port}${route}`, init);
    const setCookie = res.headers.get('set-cookie') || '';
    const cookie = setCookie.split(';')[0];
    const text = await res.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = text.slice(0, 60);
    }
    out.push({ name, status: res.status, body, setCookie, cookie });
    return { res, body, setCookie, cookie, text };
  };
  const jsonPost = (payload, extra = {}) => ({
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(extra.headers || {}) },
    body: JSON.stringify(payload),
    ...extra,
  });

  // 1) 未带凭据
  await call('state-noauth', '/api/state');
  // 2) 错误令牌
  await call('state-bad-token', '/api/state', { headers: { 'x-panel-token': 'nope' } });
  // 3) 正确令牌（头 / 查询串）
  await call('state-token-header', '/api/state', { headers: { 'x-panel-token': TOKEN } });
  await call('state-token-query', `/api/state?token=${TOKEN}`);
  // 4) 令牌登录：错 / 对
  await call('login-token-wrong', '/api/session', jsonPost({ mode: 'token', token: 'bad' }));
  const login = await call('login-token-ok', '/api/session', jsonPost({ mode: 'token', token: TOKEN }));
  const sessionCookie = login.cookie;
  // 5) 会话可用
  await call('state-session', '/api/state', { headers: { cookie: sessionCookie } });
  await call('session-info', '/api/session', { headers: { cookie: sessionCookie } });
  // 6) 密码登录
  await call('login-password-wrong', '/api/session', jsonPost({ mode: 'password', password: 'wrong' }));
  await call('login-password-ok', '/api/session', jsonPost({ mode: 'password', password: PASSWORD }));
  // 7) 公钥登录：取挑战 → 签名 → 登录
  const challengeRes = await call('challenge', '/api/auth/challenge?keyId=k1');
  const challenge = challengeRes.body?.challenge;
  const challengeId = challengeRes.body?.challengeId;
  const signature = crypto.sign(null, Buffer.from(challenge, 'base64'), privateKey).toString('base64');
  await call('login-key-bad-signature', '/api/session', jsonPost({ mode: 'key', challengeId, signature: Buffer.alloc(64).toString('base64') }));
  // 上面的失败已经把那个挑战删掉了，重新取一次
  const challenge2 = await call('challenge-2', '/api/auth/challenge?keyId=k1');
  const signature2 = crypto.sign(null, Buffer.from(challenge2.body.challenge, 'base64'), privateKey).toString('base64');
  await call('login-key-ok', '/api/session', jsonPost({ mode: 'key', challengeId: challenge2.body.challengeId, signature: signature2 }));
  // 8) 未启用的登录方式
  await call('login-unknown-mode', '/api/session', jsonPost({ mode: 'sms' }));
  // 9) 跨站写请求
  await call('cross-site', '/api/all/start', jsonPost({}, { headers: { origin: 'http://evil.example' } }));
  // 10) 静态资源
  const index = await call('static-index', '/');
  const css = await call('static-css', '/style.css');
  const js = await call('static-js', '/app.js');
  await call('static-missing', '/nope.js');
  await call('static-traversal', '/..%2f..%2ftunnels.json');
  // 11) 退出登录
  await call('logout', '/api/session', { method: 'DELETE', headers: { cookie: sessionCookie } });
  await call('state-after-logout', '/api/state', { headers: { cookie: sessionCookie } });

  return { out, indexHtml: index.text, cssType: css.res.headers.get('content-type'), jsType: js.res.headers.get('content-type') };
}

/** 归一化后再比：去掉 cookie 值、时间戳、challenge 随机值 */
function normalize(entry) {
  const body = entry.body && typeof entry.body === 'object' ? { ...entry.body } : entry.body;
  if (body && typeof body === 'object') {
    for (const key of ['expiresAt', 'idleUntil', 'ts']) delete body[key];
    if (body.challenge) body.challenge = '<challenge>';
    if (body.challengeId) body.challengeId = '<challengeId>';
    if (Array.isArray(body.tunnels)) body.tunnels = body.tunnels.length;
  }
  return {
    status: entry.status,
    hasCookie: Boolean(entry.cookie),
    httpOnly: entry.setCookie ? /HttpOnly/i.test(entry.setCookie) : null,
    sameSite: entry.setCookie ? /SameSite=Strict/i.test(entry.setCookie) : null,
    body,
  };
}

function cleanup(procs) {
  for (const proc of procs) {
    if (proc && proc.exitCode === null) {
      try {
        proc.kill();
      } catch {
        /* ignore */
      }
    }
  }
  if (!keep) {
    for (let i = 0; i < 5; i++) {
      try {
        fs.rmSync(work, { recursive: true, force: true });
        break;
      } catch {
        /* Windows 上偶尔还占着句柄 */
      }
    }
  }
}

const procs = [];
try {
  const rust = start('rust', PORT_RUST);
  procs.push(rust);
  const node = start('node', PORT_NODE);
  procs.push(node);
  await Promise.all([waitReady(PORT_RUST, rust), waitReady(PORT_NODE, node)]);

  const rustResult = await runSuite(PORT_RUST);
  const nodeResult = await runSuite(PORT_NODE);

  let failures = 0;
  console.log('=== 逐项对照（状态码 / 是否发 Cookie / 响应体）===');
  for (let i = 0; i < nodeResult.out.length; i++) {
    const a = normalize(rustResult.out[i]);
    const b = normalize(nodeResult.out[i]);
    const same = JSON.stringify(a) === JSON.stringify(b);
    if (!same) {
      failures++;
      console.log(`\n✖ ${nodeResult.out[i].name}`);
      console.log(`   rust: ${JSON.stringify(a)}`);
      console.log(`   node: ${JSON.stringify(b)}`);
    } else {
      console.log(`✓ ${nodeResult.out[i].name}  (${a.status})`);
    }
  }

  console.log('\n=== 静态资源细节 ===');
  const rawHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  const sameHtml = rustResult.indexHtml === nodeResult.indexHtml;
  const injected = rustResult.indexHtml !== rawHtml && /\/style\.css\?v=\d+-\d+/.test(rustResult.indexHtml || '');
  console.log(`index.html：rust 与 node 完全一致 = ${sameHtml}；已注入 ?v= = ${injected}`);
  console.log(`style.css 类型：rust ${rustResult.cssType} / node ${nodeResult.cssType}`);
  console.log(`app.js 类型   ：rust ${rustResult.jsType} / node ${nodeResult.jsType}`);
  if (!sameHtml || !injected) failures++;

  console.log('\n=== 跨实现交叉验证 ===');
  const { verifyPassword, publicKeyFingerprint } = await import(pathToFileURL(path.join(ROOT, 'src', 'auth.mjs')).href);
  const nodeAcceptsOwnHash = verifyPassword(PASSWORD, passwordHash);
  console.log(`Node 校验自己生成的哈希：${nodeAcceptsOwnHash}`);
  const nodeFingerprint = publicKeyFingerprint(publicKeyOpenSsh);
  const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  console.log(`Node 指纹：${nodeFingerprint}`);
  const healthRust = await (await fetch(`http://127.0.0.1:${PORT_RUST}/healthz`)).json();
  const healthNode = await (await fetch(`http://127.0.0.1:${PORT_NODE}/healthz`)).json();
  console.log(`/healthz methods：rust ${JSON.stringify(healthRust.methods)} / node ${JSON.stringify(healthNode.methods)}`);
  if (JSON.stringify(healthRust) !== JSON.stringify(healthNode)) failures++;

  console.log(failures === 0 ? '\n✓ 鉴权与会话行为一致' : `\n✖ 共 ${failures} 处不一致`);
  if (keep) console.log(`现场保留在：${work}`);
  process.exitCode = failures === 0 ? 0 : 1;
  void config;
} finally {
  cleanup(procs);
}
