#!/usr/bin/env node
/**
 * 假 ssh：只做本地端口监听，用来验证控制器/面板逻辑（不需要真实服务器）。
 *
 * 环境变量 FAKE_SSH_MODE:
 *   ok     正常“转发”（监听本地端口后常驻）
 *   fail   立刻以 255 退出（模拟认证失败/端口占用）
 *   flaky  先监听 1.5 秒再以 255 退出（模拟连接被掐断）
 *   slow   永不监听（模拟转发建立不起来）
 */
import net from 'node:net';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2);
let spec = null;
for (let i = 0; i < argv.length; i += 1) {
  if (argv[i] === '-L') spec = argv[i + 1];
}
if (!spec) {
  console.error('fake-ssh: 缺少 -L 参数');
  process.exit(2);
}

// 模拟真实 ssh 在需要密码时调用 SSH_ASKPASS 的行为
if (process.env.SSH_ASKPASS) {
  const res = spawnSync(process.env.SSH_ASKPASS, [], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
    env: process.env,
  });
  const got = (res.stdout || '').trim();
  const expect = process.env.FAKE_SSH_EXPECT || '';
  if (res.status !== 0 || !expect || got !== expect) {
    console.error('deploy@edge.test: Permission denied (password).');
    process.exit(255);
  }
  console.error('fake-ssh: 密码校验通过（来自 askpass）');
}
const parts = spec.split(':');
const localPort = Number(parts[1]);
const host = parts[parts.length - 2];
const port = parts[parts.length - 1];
const mode = process.env.FAKE_SSH_MODE || 'ok';

console.error(`Warning: Permanently added '${host}' (ED25519) to the list of known hosts.`);

if (mode === 'fail') {
  console.error(`deploy@${host}: Permission denied (publickey).`);
  process.exit(255);
}
if (mode === 'slow') {
  console.error('fake-ssh: 模拟握手卡住（不监听本地端口）');
  setInterval(() => {}, 1 << 30);
  process.on('SIGTERM', () => process.exit(0));
  process.on('SIGINT', () => process.exit(0));
} else {
  const server = net.createServer((socket) => {
    socket.on('error', () => {});
    socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
  });
  server.on('error', (err) => {
    console.error(`fake-ssh: 监听 127.0.0.1:${localPort} 失败: ${err.message}`);
    process.exit(255);
  });
  server.listen(localPort, '127.0.0.1', () => {
    console.error(`fake-ssh: forwarding 127.0.0.1:${localPort} -> ${host}:${port} (mode=${mode})`);
  });

  if (mode === 'flaky') {
    setTimeout(() => {
      console.error('fake-ssh: Connection reset by peer');
      process.exit(255);
    }, 1500);
  }

  const bye = () => {
    server.close();
    process.exit(0);
  };
  process.on('SIGTERM', bye);
  process.on('SIGINT', bye);
}
