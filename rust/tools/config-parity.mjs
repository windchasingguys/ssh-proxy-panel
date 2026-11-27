#!/usr/bin/env node
/**
 * 配置写回的字节级对照（M4 的回归闸门）。
 *
 *   node rust/tools/config-parity.mjs
 *   node rust/tools/config-parity.mjs --keep
 *
 * 做法：把同一份**手写风格**的配置（带面板不认识的顶层字段、隧道级 env / sshBin）复制两份，
 * 分别让 Node 版与 Rust 版跑完全相同的编辑序列，每一步之后把两份文件按字节比较。
 * 目标是"面板改一次不会把用户文件 diff 掉"，所以这里比的是原文，不是 JSON 语义。
 *
 * 另外单独验两件不能按字节比的事：
 *   - 明文密码提交后必须变成 `enc:v1:` 密文，且原文件里不出现明文；
 *   - 注册的公钥能真的用来登录（签名 → 会话）。
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

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-proxy-cfg-'));
const files = { rust: path.join(work, 'rust.json'), node: path.join(work, 'node.json') };

/** 手写风格的配置：故意带上面板不认识的顶层字段与隧道字段 */
const initialConfig = {
  panel: { host: '127.0.0.1', port: 7799, token: 'cfg-token' },
  ssh: { bin: [process.execPath, path.join(ROOT, 'test', 'fake-ssh.mjs')], batchMode: true },
  supervision: { watchIntervalMs: 5000, maxFailures: 12 },
  // 面板不认识的顶层字段，必须原样保留
  customNote: '手写注释字段，面板不该动它',
  tunnels: [
    {
      id: 'app',
      name: '项目 Web',
      localPort: 28951,
      target: { host: '10.0.0.12', port: 8080 },
      via: { user: 'deploy', host: 'edge.example.com', port: 22 },
      auth: { mode: 'key' },
      // 面板不编辑但要保留的字段
      env: { FAKE_SSH_MODE: 'ok' },
      sshBin: [process.execPath, path.join(ROOT, 'test', 'fake-ssh.mjs')],
      handwritten: 'ssh -L 手写备注',
    },
  ],
};

for (const file of Object.values(files)) {
  fs.writeFileSync(file, `${JSON.stringify(initialConfig, null, 2)}\n`);
}

function start(which, port) {
  const args = ['serve', '--config', files[which], '--port', String(port), '--quiet'];
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

const TOKEN = 'cfg-token';
const headers = { 'content-type': 'application/json', 'x-panel-token': TOKEN };

async function call(port, method, route, body) {
  const res = await fetch(`http://127.0.0.1:${port}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

/** 按顺序执行同一批编辑动作；每一步之后比两份文件的字节 */
async function runSequence(port, label) {
  const steps = [];
  const record = (name) => {
    const rust = fs.readFileSync(files.rust, 'utf8');
    const node = fs.readFileSync(files.node, 'utf8');
    steps.push({ name, rust, node });
  };

  // 1) 新建
  const createBody = {
    id: 'staging',
    name: '预发布',
    description: '面板新建的隧道',
    localPort: 28952,
    bindAddress: '127.0.0.1',
    target: { host: '10.0.0.14', port: 8443 },
    via: { user: 'deploy', host: 'edge2.example.com', port: 2222 },
    auth: { mode: 'key', identityFile: '~/.ssh/id_ed25519' },
    scheme: 'https',
    url: '/login',
    healthUrl: 'http://127.0.0.1:28952/healthz',
    extraArgs: ['-o', 'LogLevel=ERROR'],
    autoStart: true,
    openOnUp: false,
    env: { FAKE_SSH_MODE: 'ok' },
  };
  const created = await call(port, 'POST', '/api/tunnels', createBody);
  if (created.status !== 200) throw new Error(`${label}: 新建失败 ${created.status} ${created.text.slice(0, 200)}`);
  record('create');

  // 2) 改（改名 + 改端口 + 改 url + 关掉 autoStart）
  const updateBody = { ...createBody, id: 'staging2', name: '预发布（改名）', localPort: 28953, url: '', autoStart: false };
  const updated = await call(port, 'PUT', '/api/tunnels/staging', updateBody);
  if (updated.status !== 200) throw new Error(`${label}: 改名失败 ${updated.status} ${updated.text.slice(0, 200)}`);
  record('update+rename');

  // 3) 全局设置
  const settings = await call(port, 'PUT', '/api/settings', {
    ssh: { connectTimeout: 12, serverAliveInterval: 20, strictHostKeyChecking: 'yes', batchMode: false },
    supervision: { maxFailures: 7, backoffBaseMs: 1500 },
    panel: { sessionTtlMinutes: 600 },
  });
  if (settings.status !== 200) throw new Error(`${label}: 设置失败 ${settings.status} ${settings.text.slice(0, 200)}`);
  record('settings');
  const restartRequired = settings.json?.restartRequired;

  // 4) 删除
  const deleted = await call(port, 'DELETE', '/api/tunnels/staging2');
  if (deleted.status !== 200) throw new Error(`${label}: 删除失败 ${deleted.status} ${deleted.text.slice(0, 200)}`);
  record('delete');

  return { steps, restartRequired };
}

/** 密码与公钥：不能按字节比，改验行为 */
async function runAuthFlow(port, label) {
  const passwordBody = {
    id: 'pwtest',
    name: '密码隧道',
    localPort: 28954,
    target: { host: '10.0.0.15', port: 80 },
    via: { host: 'edge.example.com', port: 22 },
    auth: { mode: 'password', password: '明文密码-abc' },
  };
  const created = await call(port, 'POST', '/api/tunnels', passwordBody);
  if (created.status !== 200) throw new Error(`${label}: 密码隧道创建失败 ${created.status} ${created.text.slice(0, 200)}`);

  const raw = fs.readFileSync(files[port === PORT_RUST ? 'rust' : 'node'], 'utf8');
  const hasCipher = raw.includes('enc:v1:');
  const hasPlain = raw.includes('明文密码-abc');

  // 注册公钥并登录
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawKey = spki.subarray(spki.length - 32);
  const sshString = (buf) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length);
    return Buffer.concat([len, buf]);
  };
  const blob = Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(rawKey)]);
  const publicKeyOpenSsh = `ssh-ed25519 ${blob.toString('base64')}`;

  const added = await call(port, 'POST', '/api/auth/keys', { name: '配置测试', publicKey: publicKeyOpenSsh });
  if (added.status !== 200) throw new Error(`${label}: 注册公钥失败 ${added.status} ${added.text.slice(0, 200)}`);
  const keyId = added.json?.id;
  const fingerprint = added.json?.fingerprint;

  const challengeRes = await call(port, 'GET', `/api/auth/challenge?keyId=${keyId}`);
  const challenge = challengeRes.json?.challenge;
  const challengeId = challengeRes.json?.challengeId;
  const signature = crypto.sign(null, Buffer.from(challenge, 'base64'), privateKey).toString('base64');
  const login = await call(port, 'POST', '/api/session', { mode: 'key', challengeId, signature });

  // 删公钥前先确认"不能删掉最后一种登录方式"：此时还有 token，所以能删
  const removed = await call(port, 'DELETE', `/api/auth/keys/${keyId}`);

  return {
    hasCipher,
    hasPlain,
    addedStatus: added.status,
    loginStatus: login.status,
    removedStatus: removed.status,
    fingerprintLooksValid: typeof fingerprint === 'string' && fingerprint.startsWith('SHA256:'),
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

  const rustRun = await runSequence(PORT_RUST, 'rust');
  const nodeRun = await runSequence(PORT_NODE, 'node');

  let failures = 0;
  console.log('=== 写回字节级对照 ===');
  for (let i = 0; i < nodeRun.steps.length; i++) {
    const a = rustRun.steps[i];
    const b = nodeRun.steps[i];
    const same = a.rust === b.node;
    if (!same) {
      failures++;
      const aLines = a.rust.split('\n');
      const bLines = b.node.split('\n');
      const firstDiff = aLines.findIndex((line, idx) => line !== bLines[idx]);
      console.log(`\n✖ ${a.name}: 文件不一致（首个差异在第 ${firstDiff + 1} 行）`);
      console.log(`   rust: ${aLines[firstDiff]}`);
      console.log(`   node: ${bLines[firstDiff]}`);
    } else {
      console.log(`✓ ${a.name} — 文件逐字节相同（${a.rust.length} 字节）`);
    }
  }

  console.log('\n=== 手写字段是否保留 ===');
  const finalRust = JSON.parse(rustRun.steps.at(-1).rust);
  const finalNode = JSON.parse(nodeRun.steps.at(-1).node);
  const kept = (obj) => obj.customNote === initialConfig.customNote && Array.isArray(obj.tunnels);
  const appKept = (obj) => {
    const app = obj.tunnels.find((t) => t.id === 'app');
    return app && app.handwritten === 'ssh -L 手写备注' && app.env && app.sshBin;
  };
  console.log(`顶层 customNote：rust ${kept(finalRust)} / node ${kept(finalNode)}`);
  console.log(`app 的 env / sshBin / handwritten：rust ${appKept(finalRust)} / node ${appKept(finalNode)}`);
  if (!kept(finalRust) || !appKept(finalRust)) failures++;
  if (rustRun.restartRequired !== nodeRun.restartRequired) {
    failures++;
    console.log(`✖ restartRequired 不一致：rust ${rustRun.restartRequired} / node ${nodeRun.restartRequired}`);
  } else {
    console.log(`✓ restartRequired 一致（${rustRun.restartRequired}）`);
  }

  console.log('\n=== 密码 / 公钥行为（不能按字节比）===');
  const rustAuth = await runAuthFlow(PORT_RUST, 'rust');
  const nodeAuth = await runAuthFlow(PORT_NODE, 'node');
  for (const [label, result] of [
    ['rust', rustAuth],
    ['node', nodeAuth],
  ]) {
    console.log(
      `${label}: 密文=${result.hasCipher} 明文残留=${result.hasPlain} 注册=${result.addedStatus} 公钥登录=${result.loginStatus} 删钥=${result.removedStatus} 指纹=${result.fingerprintLooksValid}`,
    );
  }
  const sameAuth =
    JSON.stringify({ ...rustAuth }) === JSON.stringify({ ...nodeAuth });
  console.log(`行为一致：${sameAuth}`);
  if (!sameAuth || rustAuth.hasPlain || !rustAuth.hasCipher) failures++;

  console.log(failures === 0 ? '\n✓ 配置写回行为一致' : `\n✖ 共 ${failures} 处不一致`);
  if (keep) console.log(`现场保留在：${work}`);
  process.exitCode = failures === 0 ? 0 : 1;
} finally {
  cleanup(procs);
}
