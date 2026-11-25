import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { expandHome } from './util.mjs';
import { askpassLaunch } from './app-root.mjs';

/** ssh 可执行文件：支持字符串或数组（数组便于测试/自定义包装脚本） */
export function commandPrefix(tunnel, config) {
  const bin = tunnel?.sshBin ?? config?.ssh?.bin ?? 'ssh';
  if (Array.isArray(bin)) return bin.map(String);
  return [String(bin)];
}

function quoteArg(arg) {
  const s = String(arg);
  if (s === '') return '""';
  if (/^[A-Za-z0-9_@%+=:,./\\~^-]+$/.test(s)) return s;
  return `"${s.replace(/"/g, '\\"')}"`;
}

export function formatCommand(prefix, args) {
  return [...prefix, ...args].map(quoteArg).join(' ');
}

/**
 * 构建 `ssh -N -L ...` 参数。
 * 关键项：
 *  -N            不执行远端命令（纯转发，不占终端）
 *  -T            不分配 TTY
 *  ExitOnForwardFailure=yes  转发失败直接退出，而不是“连着但不通”
 *  BatchMode=yes 禁止交互式提示（纯密钥/agent 时用，避免卡在提示符上）
 *  ServerAlive*  半开连接检测，网络断了能自己退出并触发重连
 *
 * options.secret：密码/口令。有它就关掉 BatchMode，并让 ssh 通过 SSH_ASKPASS 取（见 askpassEnv）
 */
export function buildSshArgs(tunnel, config, options = {}) {
  const cfg = config.ssh;
  const auth = tunnel.auth || { mode: 'key' };
  const secret = options.secret || '';
  const args = ['-N', '-T'];
  args.push('-o', 'ExitOnForwardFailure=yes');
  args.push('-o', `ConnectTimeout=${cfg.connectTimeout}`);
  args.push('-o', `ServerAliveInterval=${cfg.serverAliveInterval}`);
  args.push('-o', `ServerAliveCountMax=${cfg.serverAliveCountMax}`);
  args.push('-o', `StrictHostKeyChecking=${cfg.strictHostKeyChecking}`);
  args.push('-o', 'TCPKeepAlive=yes');

  if (auth.mode === 'password') {
    // 密码登录：只走密码 / keyboard-interactive，不做公钥探测
    args.push('-o', 'PubkeyAuthentication=no');
    args.push('-o', 'PreferredAuthentications=password,keyboard-interactive');
    args.push('-o', 'NumberOfPasswordPrompts=1');
  }
  const needsPrompt = auth.mode === 'password' || Boolean(secret);
  if (cfg.batchMode && !needsPrompt) args.push('-o', 'BatchMode=yes');
  else args.push('-o', 'BatchMode=no');

  const via = tunnel.via || {};
  if (via.port) args.push('-p', String(via.port));
  if (via.ProxyJump) args.push('-J', String(via.ProxyJump));
  if (via.proxyCommand) args.push('-o', `ProxyCommand=${via.proxyCommand}`);
  const identityFile = auth.identityFile || via.identityFile;
  if (identityFile && auth.mode !== 'password') args.push('-i', expandHome(identityFile));
  if (via.knownHostsFile) args.push('-o', `UserKnownHostsFile=${expandHome(via.knownHostsFile)}`);

  args.push(...(cfg.extraArgs || []));
  args.push(...(tunnel.extraArgs || []));
  args.push('-L', tunnel.forwardSpec);
  args.push(via.user ? `${via.user}@${via.host}` : String(via.host));
  return args;
}

/**
 * 生成 askpass 帮手（每个数据目录一份）。
 * Windows 上 SSH_ASKPASS 必须是可直接 CreateProcess 的目标，实测 .cmd 可行；
 * POSIX 上给 shebang 脚本加可执行位。
 */
export function ensureAskpassHelper(dataDir) {
  const launch = askpassLaunch();
  const isWin = process.platform === 'win32';
  const helper = path.join(dataDir, isWin ? 'askpass.cmd' : 'askpass.sh');
  const quote = (value) => `"${String(value).replace(/"/g, '\\"')}"`;
  const command = [launch.file, ...launch.args].map(quote).join(' ');
  const content = isWin ? `@echo off\r\n${command} %*\r\n` : `#!/bin/sh\nexec ${command} "$@"\n`;
  fs.mkdirSync(dataDir, { recursive: true });
  const current = fs.existsSync(helper) ? fs.readFileSync(helper, 'utf8') : '';
  if (current !== content) {
    fs.writeFileSync(helper, content, { mode: 0o700 });
    try {
      fs.chmodSync(helper, 0o700);
    } catch {
      /* Windows 忽略 */
    }
  }
  return helper;
}

/** ssh 子进程的环境：凭据只走环境变量，不落盘 */
export function askpassEnv(helper, secret) {
  if (!secret) return {};
  return {
    SSH_ASKPASS: helper,
    SSH_ASKPASS_REQUIRE: 'force',
    SSHPROXY_SSH_SECRET: secret,
    // 个别平台在没有 DISPLAY 时会跳过 askpass
    DISPLAY: process.env.DISPLAY || ':0',
  };
}

/** 杀掉 ssh 进程（Windows 用 taskkill 连子进程一起杀，POSIX 用进程组） */
export function killTree(child, { force = true } = {}) {
  if (!child || child.exitCode !== null || child.signalCode) return;
  const pid = child.pid;
  if (!pid) return;
  if (process.platform === 'win32') {
    const args = ['/PID', String(pid), '/T'];
    if (force) args.push('/F');
    const killer = spawn('taskkill', args, { windowsHide: true, stdio: 'ignore' });
    killer.on('error', () => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
    });
    return;
  }
  try {
    process.kill(-pid, 'SIGTERM');
  } catch {
    try {
      child.kill('SIGTERM');
    } catch {
      /* ignore */
    }
  }
  const timer = setTimeout(() => {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      /* ignore */
    }
  }, 3000);
  timer.unref?.();
}

/** 读取进程命令行，用于启动时辨认“上次没关干净的 ssh” */
export function readCmdline(pid) {
  return new Promise((resolve) => {
    if (!pid) return resolve('');
    const win = process.platform === 'win32';
    const cmd = win ? 'powershell' : 'ps';
    const args = win
      ? [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          `$p = Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}"; if ($p) { $p.CommandLine }`,
        ]
      : ['-o', 'args=', '-p', String(pid)];
    let out = '';
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(out.trim());
    };
    let child;
    try {
      child = spawn(cmd, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      return finish();
    }
    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
      finish();
    }, 5000);
    timer.unref?.();
    child.stdout?.on('data', (d) => {
      out += d.toString('utf8');
    });
    child.once('error', finish);
    child.once('close', () => {
      clearTimeout(timer);
      finish();
    });
  });
}

export function processAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(Number(pid), 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

/** 用系统默认浏览器打开 URL（仅在本机使用） */
export function openExternal(url) {
  try {
    if (process.platform === 'win32') {
      spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', `Start-Process '${String(url).replace(/'/g, "''")}'`], {
        windowsHide: true,
        stdio: 'ignore',
        detached: true,
      }).unref();
    } else if (process.platform === 'darwin') {
      spawn('open', [url], { stdio: 'ignore', detached: true }).unref();
    } else {
      spawn('xdg-open', [url], { stdio: 'ignore', detached: true }).unref();
    }
  } catch {
    /* 打不开就算了，面板里还有链接 */
  }
}
