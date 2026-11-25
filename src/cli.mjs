#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import readline from 'node:readline';
import { loadConfig, exampleConfig, DEFAULT_CONFIG_FILE } from './config.mjs';
import { setPasswordHash, addPublicKey, removePublicKey, writeRawConfig } from './config-writer.mjs';
import { hashPassword } from './auth.mjs';
import { Supervisor } from './supervisor.mjs';
import { createPanelServer } from './server.mjs';
import { openExternal } from './ssh.mjs';
import { formatDuration } from './util.mjs';

// ssh 要密码时会执行 `ssh-proxy --askpass`（askpass 小帮手），这里最先处理，别做别的事
if (process.argv.includes('--askpass')) {
  const secret = process.env.SSHPROXY_SSH_SECRET;
  if (!secret) {
    process.stderr.write('ssh-proxy: 没有可用的凭据（SSHPROXY_SSH_SECRET 为空）\n');
    process.exit(1);
  }
  process.stdout.write(`${secret}\n`);
  process.exit(0);
}

const STATUS_TEXT = {
  stopped: '已停止',
  starting: '连接中',
  up: '已连通',
  retrying: '重连中',
  failed: '已暂停',
};

function parseArgs(list) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < list.length; i += 1) {
    const item = list[i];
    if (item.startsWith('--')) {
      const eq = item.indexOf('=');
      if (eq > 0) {
        flags[item.slice(2, eq)] = item.slice(eq + 1);
      } else {
        const key = item.slice(2);
        const next = list[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          flags[key] = next;
          i += 1;
        } else {
          flags[key] = true;
        }
      }
    } else {
      positional.push(item);
    }
  }
  return { flags, positional };
}

function help() {
  console.log(`ssh-proxy — 本地 SSH -N -L 隧道面板

用法:
  node src/cli.mjs serve [--config tunnels.json] [--port 7788] [--host 127.0.0.1]
                         [--token <令牌>] [--open] [--quiet]
  node src/cli.mjs status                      查看所有隧道状态
  node src/cli.mjs up <id|all>                  开启某条（或全部）隧道
  node src/cli.mjs down <id|all>                关闭某条（或全部）隧道
  node src/cli.mjs restart <id>                 重连
  node src/cli.mjs logs <id> [行数]             查看隧道日志
  node src/cli.mjs cmd <id>                     打印等价的 ssh 命令
  node src/cli.mjs secret <id>                  给"连接时输入"的隧道送一次密码（面板在跑）
  node src/cli.mjs reload                       重载 tunnels.json
  node src/cli.mjs init [文件名]                生成示例配置

登录凭据（面板要登录时才需要）:
  node src/cli.mjs passwd                       交互式设置登录密码（只存 scrypt 哈希）
  node src/cli.mjs passwd --clear               清除密码
  node src/cli.mjs addkey [--name 名字] [--file 公钥] [--key "ssh-ed25519 ..."]
                                                注册一把 Ed25519 公钥（也可直接读 stdin）
  node src/cli.mjs rmkey <id|指纹>              删除一把公钥
  node src/cli.mjs auth                         查看当前启用的登录方式
  node src/cli.mjs help

环境变量:
  SSH_PROXY_TOKEN     面板访问令牌（等价于 panel.token）
  SSH_PROXY_PORT      面板端口（等价于 panel.port）
  SSH_PROXY_PASSWORD  非交互设置密码时用（passwd 会优先读它）
`);
}

function baseUrl(config) {
  const host = config.panel.host === '0.0.0.0' || config.panel.host === '::' ? '127.0.0.1' : config.panel.host;
  return `http://${host}:${config.panel.port}`;
}

const TOKEN_SOURCE_TEXT = {
  env: '环境变量 SSH_PROXY_TOKEN',
  cli: '命令行参数 --token',
  file: '配置文件里的 panel.token',
  none: '未设置',
};

/** 面板为什么找我要凭据？这句话要能直接回答这个问题 */
function describeAuth(panel) {
  const methods = panel.authMethods || [];
  if (!methods.length) return '不需要登录（本机直接打开即可）';
  const label = { token: '令牌', password: '密码', key: '密钥' };
  const extra = methods.includes('token') ? `（令牌来源：${TOKEN_SOURCE_TEXT[panel.tokenSource] || '未知'}）` : '';
  return `${methods.map((m) => label[m] || m).join(' / ')}${extra}`;
}

async function api(config, route, method = 'GET', body) {
  const headers = {};
  if (config.panel.token) headers['x-panel-token'] = config.panel.token;
  let payload;
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(`${baseUrl(config)}${route}`, { method, headers, body: payload });
  } catch (err) {
    throw new Error(`连不上面板 ${baseUrl(config)}：${err.message}（先运行 node src/cli.mjs serve）`);
  }
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    throw new Error(
      '面板需要登录：CLI 只支持用 panel.token 免登录操作；如果只配了密码/密钥，请在浏览器里登录后用面板操作',
    );
  }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function printTunnels(tunnels) {
  if (!tunnels.length) {
    console.log('（没有配置隧道，编辑 tunnels.json 后执行 reload）');
    return;
  }
  for (const t of tunnels) {
    const dot = t.status === 'up' ? '●' : t.status === 'stopped' ? '○' : '◐';
    const via = `${t.via.user ? `${t.via.user}@` : ''}${t.via.host}:${t.via.port}${t.via.proxyJump ? ` via ${t.via.proxyJump}` : ''}`;
    const tail = t.upAt
      ? `已连通 ${formatDuration(Date.now() - t.upAt)}`
      : t.nextRetryAt
        ? `重连倒计时 ${Math.max(0, Math.round((t.nextRetryAt - Date.now()) / 1000))}s`
        : t.lastError || '';
    console.log(
      `${dot} ${t.id.padEnd(12)} ${(STATUS_TEXT[t.status] || t.status).padEnd(6)} ` +
        `${`${t.bindAddress}:${t.localPort}`.padEnd(18)} → ${via.padEnd(34)} → ${t.target.host}:${t.target.port}  ${tail}`,
    );
  }
}

/** 不回显的输入（密码）；非 TTY 时退回普通读一行 */
async function promptHidden(question) {
  if (!process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    const answer = await new Promise((resolve) => rl.question(question, resolve));
    rl.close();
    return answer;
  }
  process.stdout.write(question);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const mute = () => {};
  const original = rl._writeToOutput;
  rl._writeToOutput = mute;
  const answer = await new Promise((resolve) => rl.question('', resolve));
  rl._writeToOutput = original;
  rl.close();
  process.stdout.write('\n');
  return answer;
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const { flags, positional } = parseArgs(rawArgs);
  const command = positional[0] || 'serve';
  const configFile = String(flags.config || positional[1] || DEFAULT_CONFIG_FILE);

  if (command === 'version') {
    console.log('ssh-proxy-panel 1.0.0');
    return;
  }

  if (command === 'help' || flags.help) {
    help();
    return;
  }

  if (command === 'init') {
    const target = path.resolve(String(flags.target || configFile));
    if (fs.existsSync(target)) {
      console.error(`已存在 ${target}，为避免覆盖已退出。换个文件名或用 --target 指定。`);
      process.exitCode = 1;
      return;
    }
    fs.writeFileSync(target, `${JSON.stringify(exampleConfig(), null, 2)}\n`);
    console.log(`已生成示例配置: ${target}`);
    console.log('按需修改 via（边缘机/跳板机）、target（内网服务）后运行: node src/cli.mjs serve --open');
    return;
  }

  const config = loadConfig(configFile);
  if (flags.port) config.panel.port = Number(flags.port);
  if (flags.host) config.panel.host = String(flags.host);
  if (flags.token) {
    config.panel.token = String(flags.token).trim();
    config.panel.tokenSource = 'cli';
    if (!config.panel.authMethods.includes('token')) config.panel.authMethods.push('token');
  }

  /* ---- 登录凭据管理（直接改文件，重启面板后生效） ---- */

  if (command === 'auth') {
    console.log(`登录方式   ${describeAuth(config.panel)}`);
    console.log(`  令牌     ${config.panel.token ? '已设置' : '未设置'}${config.panel.token ? `（来源：${TOKEN_SOURCE_TEXT[config.panel.tokenSource] || '未知'}）` : ''}`);
    console.log(`  密码     ${config.panel.passwordHash ? '已设置（scrypt 哈希，不可逆）' : '未设置'}`);
    if (config.panel.publicKeys.length) {
      for (const key of config.panel.publicKeys) console.log(`  密钥     ${key.id}  ${key.name}  ${key.fingerprint}`);
    } else {
      console.log('  密钥     未注册');
    }
    console.log(`  会话     ${config.panel.sessionTtlMinutes} 分钟到期 / ${config.panel.sessionIdleMinutes} 分钟闲置失效`);
    return;
  }

  if (command === 'passwd') {
    const file = path.resolve(configFile);
    if (flags.clear) {
      const { raw } = setPasswordHash(file, '');
      writeRawConfig(file, raw);
      console.log(`已清除登录密码: ${file}`);
      console.log('重启面板后生效。');
      return;
    }
    let password = process.env.SSH_PROXY_PASSWORD;
    if (password) {
      console.log('使用环境变量 SSH_PROXY_PASSWORD');
    } else {
      password = await promptHidden('新密码: ');
      const again = await promptHidden('再输一遍: ');
      if (password !== again) throw new Error('两次输入不一致');
    }
    if (!password) throw new Error('密码不能为空');
    if (password.length < 8) console.warn('提示：密码偏短，建议 12 位以上，或者干脆用密钥登录');
    const { raw } = setPasswordHash(file, hashPassword(password));
    writeRawConfig(file, raw);
    console.log(`已写入密码哈希（scrypt）: ${file}`);
    console.log('重启面板后生效；登录框里会多出"密码"方式。');
    return;
  }

  if (command === 'addkey') {
    const file = path.resolve(configFile);
    let keyText = String(flags.key || '');
    if (!keyText && flags.file) keyText = fs.readFileSync(String(flags.file), 'utf8');
    if (!keyText && positional[1]) keyText = positional[1];
    if (!keyText && !process.stdin.isTTY) keyText = fs.readFileSync(0, 'utf8');
    if (!keyText.trim()) {
      throw new Error('没读到公钥：用 --key "ssh-ed25519 ..."、--file ~/.ssh/id_ed25519.pub，或从 stdin 传入');
    }
    const { raw, id, fingerprint } = addPublicKey(file, { name: flags.name, key: keyText });
    writeRawConfig(file, raw);
    console.log(`已注册公钥: ${id}（${flags.name || '未命名密钥'}）`);
    console.log(`指纹: ${fingerprint}`);
    console.log('重启面板后生效；也可以在面板登录后用"注册本机密钥"自动完成。');
    return;
  }

  if (command === 'rmkey') {
    const file = path.resolve(configFile);
    const target = positional[1];
    if (!target) throw new Error('用法: node src/cli.mjs rmkey <id|指纹>');
    const { raw } = removePublicKey(file, target);
    writeRawConfig(file, raw);
    console.log(`已删除: ${target}`);
    console.log('重启面板后生效。');
    return;
  }

  if (command !== 'serve') {
    if (command === 'status') return printTunnels((await api(config, '/api/state')).tunnels);
    if (command === 'reload') {
      const res = await api(config, '/api/reload', 'POST');
      console.log(`配置已重载: ${res.tunnels} 个隧道（新增 ${res.added.length}，改动 ${res.changed.length}）`);
      return;
    }
    if (command === 'up' || command === 'down') {
      const id = positional[1];
      if (!id) throw new Error(`用法: node src/cli.mjs ${command} <id|all>`);
      if (id === 'all') {
        await api(config, `/api/all/${command === 'up' ? 'start' : 'stop'}`, 'POST');
      } else {
        await api(config, `/api/tunnels/${encodeURIComponent(id)}/${command === 'up' ? 'start' : 'stop'}`, 'POST');
      }
      const state = await api(config, '/api/state');
      printTunnels(state.tunnels);
      return;
    }
    if (command === 'restart') {
      const id = positional[1];
      if (!id) throw new Error('用法: node src/cli.mjs restart <id>');
      await api(config, `/api/tunnels/${encodeURIComponent(id)}/restart`, 'POST');
      console.log(`已重连 ${id}`);
      return;
    }
    if (command === 'secret') {
      const id = positional[1];
      if (!id) throw new Error('用法: node src/cli.mjs secret <id>');
      let value = process.env.SSH_PROXY_TUNNEL_SECRET;
      if (!value) value = await promptHidden('SSH 密码/口令: ');
      if (!value) throw new Error('密码不能为空');
      const body = await api(config, `/api/tunnels/${encodeURIComponent(id)}/secret`, 'POST', { value });
      console.log(`已把凭据交给隧道 ${id}（只在内存里），当前状态: ${body.tunnel?.status || '未知'}`);
      return;
    }
    if (command === 'logs') {
      const id = positional[1];
      if (!id) throw new Error('用法: node src/cli.mjs logs <id> [行数]');
      const limit = Number(positional[2]) || 80;
      const data = await api(config, `/api/tunnels/${encodeURIComponent(id)}/logs?lines=${limit}`);
      for (const line of data.lines) {
        const time = new Date(line.t).toLocaleTimeString('zh-CN', { hour12: false });
        console.log(`${time} [${line.stream}] ${line.text}`);
      }
      return;
    }
    if (command === 'cmd') {
      const id = positional[1];
      const state = await api(config, '/api/state');
      const target = id ? state.tunnels.find((t) => t.id === id) : state.tunnels[0];
      if (!target) throw new Error(id ? `找不到隧道 ${id}` : '没有隧道');
      console.log(target.command);
      return;
    }
    throw new Error(`未知命令: ${command}（运行 node src/cli.mjs help 查看用法）`);
  }

  /* ---- serve ---- */
  const quiet = Boolean(flags.quiet);
  const logger = quiet
    ? { log: () => {}, warn: () => {}, error: (...a) => console.error(...a) }
    : {
        log: (...a) => console.log(...a),
        warn: (...a) => console.warn(...a),
        error: (...a) => console.error(...a),
      };

  if (!config.configExists) {
    console.warn(`未找到配置文件 ${config.configFile}`);
    console.warn('可以先执行: node src/cli.mjs init  生成一份示例再用。');
  }

  const supervisor = new Supervisor(config, { logger });
  await supervisor.init();
  const { server, close } = await createPanelServer({ supervisor, config });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.panel.port, config.panel.host, resolve);
  });

  const port = server.address().port;
  const panelUrl = `http://${config.panel.host === '0.0.0.0' || config.panel.host === '::' ? '127.0.0.1' : config.panel.host}:${port}/`;

  console.log('');
  console.log('  SSH 隧道面板已启动');
  console.log(`  面板地址   ${panelUrl}`);
  console.log(`  配置文件   ${config.configFile}`);
  console.log(`  隧道数量   ${config.tunnels.length}`);
  console.log(`  登录方式   ${describeAuth(config.panel)}`);
  if (config.panel.authMethods.length) {
    console.log(`  会话       ${config.panel.sessionTtlMinutes} 分钟到期，${config.panel.sessionIdleMinutes} 分钟无操作失效（面板右上角可退出）`);
  }
  if (config.panel.tokenSource === 'cli') {
    console.log('  提示       --token 只在本次运行生效，不会写进配置文件；想固定下来就改 panel.token 或设 SSH_PROXY_TOKEN');
  }
  console.log('  Ctrl+C 关闭面板并停止所有隧道');
  console.log('');

  await supervisor.autostart();

  if (flags.open || config.panel.openOnStart) openExternal(panelUrl);

  let closing = false;
  const shutdown = async (signal) => {
    if (closing) return;
    closing = true;
    console.log(`\n收到 ${signal}，正在停止所有隧道…`);
    try {
      await supervisor.shutdown();
      await close();
    } catch (err) {
      console.error(err.message);
    }
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));
}

main().catch((err) => {
  console.error(`错误: ${err.message}`);
  process.exitCode = 1;
});
