#!/usr/bin/env node
/**
 * 生成一份"演示 / UI 测试"用的配置：ssh 用 test/fake-ssh.mjs 扮演，
 * 所以不需要真实服务器也能看到面板完整效果（截图、无头浏览器检查都用它）。
 *
 * 用法: node test/demo-config.mjs [输出路径]   # 默认 .tmp-demo/tunnels.json
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] || path.join(HERE, '..', '.tmp-demo', 'tunnels.json'));

const config = {
  panel: { host: '127.0.0.1', port: 7799, token: '' },
  ssh: {
    // 用假 ssh 代替真 ssh，方便离线演示
    bin: [process.execPath, path.join(HERE, 'fake-ssh.mjs')],
    connectTimeout: 10,
    serverAliveInterval: 15,
    serverAliveCountMax: 3,
    strictHostKeyChecking: 'accept-new',
    batchMode: true,
  },
  supervision: {
    startTimeoutMs: 9000,
    watchIntervalMs: 1500,
    maxFailures: 4,
    backoffBaseMs: 800,
    backoffMaxMs: 4000,
    stableResetMs: 60000,
  },
  tunnels: [
    {
      id: 'app',
      name: '项目 Web',
      description: '边缘机 → 内网项目，本机 http://127.0.0.1:28880',
      localPort: 28880,
      target: { host: '10.0.0.12', port: 8080 },
      via: { user: 'deploy', host: 'edge.example.com', port: 22 },
      scheme: 'http',
    },
    {
      id: 'app-db',
      name: '项目数据库',
      description: '内网 MySQL 映射到本机 28901，用客户端连',
      localPort: 28901,
      target: { host: '10.0.0.13', port: 3306 },
      via: 'deploy@edge.example.com:22',
    },
    {
      id: 'edge-admin',
      name: '生产后台（两跳）',
      description: '本机 → 跳板机 → 边缘机 → 后台服务',
      localPort: 28902,
      target: '127.0.0.1:9000',
      via: { user: 'deploy', host: 'edge.internal', port: 22, proxyJump: 'jump@bastion.example.com:22' },
    },
    {
      id: 'staging',
      name: '预发环境',
      description: '需要时再打开，避免长期占用本机端口',
      localPort: 28903,
      target: { host: '10.0.0.20', port: 8080 },
      via: 'deploy@edge.example.com:22',
    },
  ],
};

fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
console.log(`已生成演示配置: ${out}`);
