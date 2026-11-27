#!/usr/bin/env node
/**
 * CLI 子命令的等价性对照（M4b 的回归闸门）。
 *
 *   node rust/tools/cli-parity.mjs
 *   node rust/tools/cli-parity.mjs --keep
 *
 * 顺序执行（同一份配置的 localPort 只能被一个进程占用）：
 *   对每个实现：起面板 → 跑一串 CLI 子命令 → 收输出 → 停面板；
 * 然后把两侧的 stdout / 退出码逐条比。时间相关的数字（"已连通 3 秒"、端口）会归一化。
 */
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const RUST_EXE = path.join(ROOT, 'rust', 'target', 'x86_64-pc-windows-gnu', 'release', 'ssh-proxy.exe');
const keep = process.argv.includes('--keep');
const PORT = await freePort();

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

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-proxy-cli-'));
const configFile = path.join(work, 'tunnels.json');

/** 归一化：把时间/端口/绝对路径这类天然不同的东西抹平 */
function normalize(text) {
  return String(text)
    .replace(/\r\n/g, '\n')
    .replace(/已连通 \d+ (秒|分|小时|天)[^\n]*/g, '已连通 <时长>')
    .replace(/重连倒计时 \d+s/g, '重连倒计时 <n>s')
    .replace(/\d{2}:\d{2}:\d{2}/g, '<时间>')
    .replace(new RegExp(work.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&'), 'g'), '<work>')
    .replace(/[A-Za-z]:\\\\?[^\s"']*node_modules[^\s"']*/g, '<path>')
    // 程序名不同是刻意的（standalone 二进制），归一化后再比
    .replace(/node src\/cli\.mjs/g, 'ssh-proxy')
    .replace(/node src\\cli\.mjs/g, 'ssh-proxy')
    .trim();
}

function writeConfig() {
  const cfg = {
    panel: { host: '127.0.0.1', port: PORT, token: 'cli-token' },
    ssh: { bin: [process.execPath, path.join(ROOT, 'test', 'fake-ssh.mjs')], batchMode: true },
    supervision: { watchIntervalMs: 1000, maxFailures: 12, startTimeoutMs: 4000 },
    tunnels: [
      {
        id: 'app',
        name: '项目 Web',
        localPort: 28961,
        target: { host: '10.0.0.12', port: 8080 },
        via: { user: 'deploy', host: 'edge.example.com', port: 22 },
        auth: { mode: 'key' },
        env: { FAKE_SSH_MODE: 'ok' },
      },
    ],
  };
  fs.writeFileSync(configFile, `${JSON.stringify(cfg, null, 2)}\n`);
}

function commandFor(which, args) {
  if (which === 'rust') return { file: RUST_EXE, args };
  return { file: process.execPath, args: [path.join(ROOT, 'src', 'cli.mjs'), ...args] };
}

function runCli(which, args, extraEnv = {}) {
  const { file, args: argv } = commandFor(which, args);
  const result = spawnSync(file, argv, {
    cwd: work,
    encoding: 'utf8',
    env: { ...process.env, SSH_PROXY_TUNNEL_SECRET: '', ...extraEnv },
    timeout: 30_000,
  });
  return {
    status: result.status,
    stdout: normalize(result.stdout || ''),
    stderr: normalize(result.stderr || ''),
  };
}

function startServer(which) {
  const args = ['serve', '--config', configFile, '--port', String(PORT), '--quiet'];
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

async function waitReady(proc) {
  for (let i = 0; i < 80; i++) {
    if (proc.exitCode !== null) throw new Error(`面板进程已退出（code ${proc.exitCode}）`);
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/healthz`);
      if (res.ok) return;
    } catch {
      /* 还没起来 */
    }
    await sleep(100);
  }
  throw new Error('等面板就绪超时');
}

async function waitTunnelUp(id) {
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/api/state`, {
        headers: { 'x-panel-token': 'cli-token' },
      });
      const data = await res.json();
      const tunnel = (data.tunnels || []).find((t) => t.id === id);
      if (tunnel?.status === 'up') return true;
      if (tunnel?.status === 'failed') return false;
    } catch {
      /* 还没起来 */
    }
    await sleep(150);
  }
  return false;
}
async function runSuite(which) {
  writeConfig();
  const out = [];
  const record = (name, result) => out.push({ name, ...result });

  // 不需要面板的命令
  record('version', runCli(which, ['version']));

  const server = startServer(which);
  try {
    await waitReady(server);

    const cfg = ['--config', configFile];
    record('status-empty', runCli(which, [...cfg, 'status']));
    record('cmd', runCli(which, [...cfg, 'cmd', 'app']));
    record('up', runCli(which, [...cfg, 'up', 'app']));
    await waitTunnelUp('app');
    record('status-up', runCli(which, [...cfg, 'status']));
    record('logs', runCli(which, [...cfg, 'logs', 'app', '5']));
    record('restart', runCli(which, [...cfg, 'restart', 'app']));
    await sleep(400);
    record('down', runCli(which, [...cfg, 'down', 'app']));
    await sleep(300);
    record('up-unknown', runCli(which, [...cfg, 'up', 'nope']));
    record('up-missing-arg', runCli(which, [...cfg, 'up']));
    record('reload', runCli(which, [...cfg, 'reload']));
    record('unknown-command', runCli(which, ['bogus']));

    // 凭据管理（直接改文件）
    record('auth-before', runCli(which, [...cfg, 'auth']));
    record('passwd', runCli(which, [...cfg, 'passwd'], { SSH_PROXY_PASSWORD: 'test-password-123' }));
    record('auth-after-passwd', runCli(which, [...cfg, 'auth']));
    record('passwd-clear', runCli(which, [...cfg, 'passwd', '--clear']));
    record('addkey-bad', runCli(which, [...cfg, 'addkey', '--key', 'not-a-key']));
    record('rmkey-missing', runCli(which, [...cfg, 'rmkey', 'nope']));
  } finally {
    if (server.exitCode === null) server.kill();
    await sleep(400);
  }

  return out;
}

function cleanup() {
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

try {
  const rust = await runSuite('rust');
  await sleep(500);
  const node = await runSuite('node');

  let failures = 0;
  console.log('=== CLI 输出对照 ===');
  for (let i = 0; i < node.length; i++) {
    const a = rust[i];
    const b = node[i];
    const same = a.status === b.status && a.stdout === b.stdout && a.stderr === b.stderr;
    if (same) {
      console.log(`✓ ${a.name}  (exit ${a.status})`);
    } else {
      failures++;
      console.log(`\n✖ ${a.name}`);
      if (a.status !== b.status) console.log(`   exit: rust ${a.status} / node ${b.status}`);
      if (a.stdout !== b.stdout) {
        console.log(`   rust stdout: ${JSON.stringify(a.stdout).slice(0, 400)}`);
        console.log(`   node stdout: ${JSON.stringify(b.stdout).slice(0, 400)}`);
      }
      if (a.stderr !== b.stderr) {
        console.log(`   rust stderr: ${JSON.stringify(a.stderr).slice(0, 300)}`);
        console.log(`   node stderr: ${JSON.stringify(b.stderr).slice(0, 300)}`);
      }
    }
  }

  console.log('\n=== 哈希可交叉验证 ===');
  const { verifyPassword } = await import(pathToFileURL(path.join(ROOT, 'src', 'auth.mjs')).href);
  writeConfig();
  runCli('rust', ['passwd'], { SSH_PROXY_PASSWORD: 'cross-check-42' });
  const afterRust = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  const rustHashOk = verifyPassword('cross-check-42', afterRust.panel.passwordHash);
  writeConfig();
  runCli('node', ['passwd'], { SSH_PROXY_PASSWORD: 'cross-check-42' });
  const afterNode = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  const nodeHashOk = verifyPassword('cross-check-42', afterNode.panel.passwordHash);
  console.log(`Rust 写的哈希能被 Node 验证：${rustHashOk}`);
  console.log(`Node 写的哈希能被 Node 验证：${nodeHashOk}`);
  if (!rustHashOk || !nodeHashOk) failures++;

  console.log(failures === 0 ? '\n✓ CLI 行为一致' : `\n✖ 共 ${failures} 处不一致`);
  if (keep) console.log(`现场保留在：${work}`);
  process.exitCode = failures === 0 ? 0 : 1;
} finally {
  cleanup();
}
