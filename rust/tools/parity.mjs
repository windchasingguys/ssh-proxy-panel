#!/usr/bin/env node
/**
 * Node 版 ↔ Rust 版等价性对照（Rust 迁移的回归闸门）。
 *
 *   node rust/tools/parity.mjs                     # 只读面 + 生命周期，全套
 *   node rust/tools/parity.mjs --config my.json
 *   node rust/tools/parity.mjs --skip-lifecycle     # 只比只读接口
 *   node rust/tools/parity.mjs --keep               # 保留临时目录
 *
 * 两段检查：
 *   1) 只读面：同时起两个实现，比 /healthz、/api/state、/api/config；
 *   2) 生命周期：**顺序**执行（同一份配置里的 localPort 只能被一个进程占用）——
 *      起隧道 → 等 up → 抓快照 → 停隧道 → 等 stopped → 抓快照，两边各跑一遍再比。
 *
 * 允许忽略的字段：ts / uptimeMs / pid / startedAt / upAt / nextRetryAt / panel.port
 * （时间与进程号天然不同；port 是因为两个实例必须用不同端口）。
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const RUST_EXE = path.join(ROOT, 'rust', 'target', 'x86_64-pc-windows-gnu', 'release', 'ssh-proxy.exe');

const argOf = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const has = (name) => process.argv.includes(`--${name}`);

const configSrc = argOf('config', path.join(ROOT, '.tmp-demo', 'tunnels.json'));
const portRust = Number(argOf('port-rust', '0')) || (await freePort());
const portNode = Number(argOf('port-node', '0')) || (await freePort());
const keep = has('keep');
const skipLifecycle = has('skip-lifecycle');
const tunnelId = argOf('tunnel', 'app');

const IGNORE_KEYS = new Set(['ts', 'uptimeMs', 'pid', 'startedAt', 'upAt', 'nextRetryAt']);
const IGNORE_PATHS = new Set(['config.panel.port']);

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

if (!fs.existsSync(RUST_EXE)) fail(`找不到 Rust 二进制：${RUST_EXE}（先 cargo build --release）`);
if (!fs.existsSync(configSrc)) {
  fail(`找不到配置文件：${configSrc}\n  先跑 node test/demo-config.mjs（生成 fake-ssh 演示配置）`);
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-proxy-parity-'));
const configFile = path.join(work, 'tunnels.json');
fs.copyFileSync(configSrc, configFile);

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

async function getJson(port, route, init) {
  const res = await fetch(`http://127.0.0.1:${port}${route}`, init);
  if (!res.ok) throw new Error(`${route} 返回 ${res.status}`);
  return res.json();
}

function diff(a, b, where, out, ignore = IGNORE_KEYS) {
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) out.push(`${where}: 数组长度 ${a.length} vs ${b.length}`);
    for (let i = 0; i < Math.min(a.length, b.length); i++) diff(a[i], b[i], `${where}[${i}]`, out, ignore);
    return;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    for (const key of Object.keys(a)) if (!(key in b)) out.push(`${where}.${key}: 仅 rust 有（${JSON.stringify(a[key])}）`);
    for (const key of Object.keys(b)) if (!(key in a)) out.push(`${where}.${key}: 仅 node 有（${JSON.stringify(b[key])}）`);
    for (const key of Object.keys(a)) {
      if (!(key in b) || ignore.has(key) || IGNORE_PATHS.has(`${where}.${key}`)) continue;
      diff(a[key], b[key], `${where}.${key}`, out, ignore);
    }
    return;
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) out.push(`${where}: ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
}

async function readOnlyPhase(procs) {
  const rust = start('rust', portRust);
  procs.push(rust);
  const node = start('node', portNode);
  procs.push(node);
  await Promise.all([waitReady(portRust, rust), waitReady(portNode, node)]);

  let failures = 0;
  const healthDiff = [];
  diff(
    await getJson(portRust, '/healthz'),
    await getJson(portNode, '/healthz'),
    'healthz',
    healthDiff,
    new Set(['ts', 'uptimeMs']),
  );
  console.log(`\n=== 只读面 /healthz: ${healthDiff.length} 处差异 ===`);
  healthDiff.forEach((line) => console.log(`  ${line}`));
  failures += healthDiff.length;

  for (const route of ['/api/state', '/api/config']) {
    const out = [];
    diff(await getJson(portRust, route), await getJson(portNode, route), route.replace('/api/', ''), out);
    console.log(`\n=== 只读面 ${route}: ${out.length} 处差异 ===`);
    out.slice(0, 40).forEach((line) => console.log(`  ${line}`));
    if (out.length > 40) console.log(`  ...（还有 ${out.length - 40} 处）`);
    failures += out.length;
  }
  return failures;
}

/** 单侧跑一遍生命周期，返回 [up 快照, stopped 快照] */
async function lifecyclePhase(which, port, procs) {
  const proc = start(which, port);
  procs.push(proc);
  await waitReady(port, proc);
  const post = (route) => getJson(port, route, { method: 'POST' });

  await post(`/api/tunnels/${tunnelId}/start`);
  let upSnapshot = null;
  for (let i = 0; i < 100; i++) {
    const state = await getJson(port, '/api/state');
    const tunnel = state.tunnels.find((t) => t.id === tunnelId);
    if (tunnel && tunnel.status === 'up') {
      upSnapshot = state;
      break;
    }
    if (tunnel && tunnel.status === 'failed') break;
    await sleep(150);
  }
  if (!upSnapshot) {
    const state = await getJson(port, '/api/state');
    const tunnel = state.tunnels.find((t) => t.id === tunnelId);
    throw new Error(`${which}: 隧道没有进入 up 状态（当前 ${tunnel?.status}，lastError=${tunnel?.lastError}）`);
  }

  const logs = await getJson(port, `/api/tunnels/${tunnelId}/logs?lines=200`);
  await post(`/api/tunnels/${tunnelId}/stop`);
  let stoppedSnapshot = null;
  for (let i = 0; i < 100; i++) {
    const state = await getJson(port, '/api/state');
    const tunnel = state.tunnels.find((t) => t.id === tunnelId);
    if (tunnel && tunnel.status === 'stopped') {
      stoppedSnapshot = state;
      break;
    }
    await sleep(150);
  }
  if (!stoppedSnapshot) throw new Error(`${which}: 隧道没有回到 stopped 状态`);

  if (proc.exitCode === null) {
    try {
      proc.kill();
    } catch {
      /* ignore */
    }
  }
  // 等端口释放，避免下一轮（另一实现）绑不上
  await sleep(400);
  return { up: upSnapshot, stopped: stoppedSnapshot, logCount: logs.lines.length };
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
    try {
      fs.rmSync(work, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
}

async function main() {
  const procs = [];
  try {
    let failures = await readOnlyPhase(procs);
    for (const proc of procs) if (proc.exitCode === null) proc.kill();
    await sleep(500);

    if (!skipLifecycle) {
      console.log(`\n=== 生命周期（顺序执行，隧道 ${tunnelId}）===`);
      const rust = await lifecyclePhase('rust', portRust, procs);
      await sleep(600);
      const node = await lifecyclePhase('node', portNode, procs);

      for (const phase of ['up', 'stopped']) {
        const out = [];
        diff(rust[phase], node[phase], `lifecycle.${phase}`, out);
        console.log(`\n--- ${phase} 快照：${out.length} 处差异 ---`);
        out.slice(0, 40).forEach((line) => console.log(`  ${line}`));
        if (out.length > 40) console.log(`  ...（还有 ${out.length - 40} 处）`);
        failures += out.length;
      }
      const logDelta = Math.abs(rust.logCount - node.logCount);
      console.log(`\n--- 日志条数：rust ${rust.logCount} / node ${node.logCount}（差 ${logDelta}，只作参考不判失败）---`);
    }

    console.log(failures === 0 ? '\n✓ Node 版与 Rust 版行为一致' : `\n✖ 共 ${failures} 处差异`);
    if (keep) console.log(`现场保留在：${work}`);
    process.exitCode = failures === 0 ? 0 : 1;
  } finally {
    cleanup(procs);
  }
}

main().catch((err) => {
  cleanup([]);
  console.error(`✖ ${err.message}`);
  process.exitCode = 1;
});
