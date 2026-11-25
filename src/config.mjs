import fs from 'node:fs';
import path from 'node:path';
import { expandHome } from './util.mjs';
import { isPasswordHash, normalizePublicKey, publicKeyFingerprint } from './auth.mjs';
import { isEncrypted } from './secrets.mjs';

export const DEFAULT_CONFIG_FILE = 'tunnels.json';

const DEFAULTS = {
  panel: {
    host: '127.0.0.1',
    port: 7788,
    token: '',
    passwordHash: '',
    publicKeys: [],
    authMethods: [],
    openOnStart: false,
    sessionTtlMinutes: 720,
    sessionIdleMinutes: 120,
  },
  ssh: {
    bin: 'ssh',
    connectTimeout: 10,
    serverAliveInterval: 15,
    serverAliveCountMax: 3,
    strictHostKeyChecking: 'accept-new',
    batchMode: true,
    extraArgs: [],
  },
  supervision: {
    startTimeoutMs: 9000,
    watchIntervalMs: 5000,
    maxFailures: 12,
    backoffBaseMs: 1000,
    backoffMaxMs: 30000,
    stableResetMs: 60000,
  },
};

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function mergeSection(defaults, given) {
  if (!isPlainObject(given)) return { ...defaults };
  const out = { ...defaults };
  for (const [key, value] of Object.entries(given)) {
    if (value === undefined) continue;
    out[key] = isPlainObject(value) && isPlainObject(defaults[key]) ? mergeSection(defaults[key], value) : value;
  }
  return out;
}

/** 支持 via: "[email protected]:2222" 这种简写 */
function parseViaString(input) {
  const text = String(input).trim();
  const at = text.lastIndexOf('@');
  let user;
  let hostPart = text;
  if (at > 0) {
    user = text.slice(0, at);
    hostPart = text.slice(at + 1);
  }
  let host = hostPart;
  let port = 22;
  const ipv6 = hostPart.match(/^\[(.+)\](?::(\d+))?$/);
  if (ipv6) {
    host = ipv6[1];
    if (ipv6[2]) port = Number(ipv6[2]);
  } else {
    const idx = hostPart.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(hostPart.slice(idx + 1))) {
      host = hostPart.slice(0, idx);
      port = Number(hostPart.slice(idx + 1));
    }
  }
  return { user, host, port };
}

function parseHostPort(text, fallbackPort) {
  const raw = String(text).trim();
  const ipv6 = raw.match(/^\[(.+)\](?::(\d+))?$/);
  if (ipv6) return { host: ipv6[1], port: ipv6[2] ? Number(ipv6[2]) : fallbackPort };
  const idx = raw.lastIndexOf(':');
  if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
    return { host: raw.slice(0, idx), port: Number(raw.slice(idx + 1)) };
  }
  return { host: raw, port: fallbackPort };
}

function assertPort(value, label) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`${label} 必须是 1-65535 之间的整数，当前为: ${JSON.stringify(value)}`);
  }
  return port;
}

function normalizeTunnel(raw, index) {
  if (!isPlainObject(raw)) throw new Error(`第 ${index + 1} 个隧道配置必须是对象`);
  const label = raw.name || raw.id || `第 ${index + 1} 个隧道`;

  const localPort = assertPort(raw.localPort ?? raw.listenPort ?? raw.port, `${label} 的 localPort`);
  const bindAddress = String(raw.bindAddress ?? raw.listenAddress ?? '127.0.0.1');

  let target;
  if (typeof raw.target === 'string') {
    target = parseHostPort(raw.target, localPort);
  } else if (isPlainObject(raw.target)) {
    target = {
      host: String(raw.target.host ?? '127.0.0.1'),
      port: assertPort(raw.target.port ?? localPort, `${label} 的 target.port`),
    };
  } else {
    target = {
      host: String(raw.remoteHost ?? raw.host ?? '127.0.0.1'),
      port: assertPort(raw.remotePort ?? raw.targetPort ?? localPort, `${label} 的 target.port`),
    };
  }

  let via;
  if (typeof raw.via === 'string') {
    via = parseViaString(raw.via);
  } else if (isPlainObject(raw.via)) {
    via = {
      user: raw.via.user,
      host: raw.via.host,
      port: raw.via.port === undefined ? 22 : assertPort(raw.via.port, `${label} 的 via.port`),
      identityFile: raw.via.identityFile,
      ProxyJump: raw.via.proxyJump ?? raw.via.jump,
      proxyCommand: raw.via.proxyCommand,
      knownHostsFile: raw.via.knownHostsFile,
    };
    if (!via.host) throw new Error(`${label} 缺少 via.host（边缘/跳板机地址）`);
    if (via.ProxyJump && !via.port) via.port = 22;
  } else {
    throw new Error(`${label} 缺少 via（边缘/跳板机地址），例如 "via": "deploy@edge.example.com:22"`);
  }
  if (!via.host) throw new Error(`${label} 缺少 via.host（边缘/跳板机地址）`);

  const id = String(raw.id ?? slug(raw.name) ?? `tunnel-${index + 1}`);
  if (!/^[A-Za-z0-9._-]+$/.test(id)) {
    throw new Error(`${label} 的 id 只能包含字母、数字、点、下划线、短横线，当前为: ${id}`);
  }

  // 隧道到边缘机的认证方式：私钥 / 存储密码（加密）/ 连接时输入
  const authRaw = isPlainObject(raw.auth) ? raw.auth : {};
  const authMode = String(authRaw.mode || 'key').toLowerCase();
  if (!['key', 'password', 'ask'].includes(authMode)) {
    throw new Error(`${label} 的 auth.mode 只能是 key（私钥）/ password（存储密码）/ ask（连接时输入）`);
  }
  const authPassword = String(authRaw.password || '');
  const authPassphrase = String(authRaw.passphrase || '');
  if (authPassword && !isEncrypted(authPassword)) {
    throw new Error(`${label} 的 auth.password 必须是加密后的值；请用面板编辑或 CLI 设置，不要手填明文`);
  }
  if (authPassphrase && !isEncrypted(authPassphrase)) {
    throw new Error(`${label} 的 auth.passphrase 必须是加密后的值；请用面板编辑或 CLI 设置`);
  }
  if (authMode === 'password' && !authPassword) {
    throw new Error(`${label} 选了密码登录，但还没有设置密码（在面板里编辑这条隧道即可）`);
  }

  const forwardSpec = `${bindAddress}:${localPort}:${target.host}:${target.port}`;
  const scheme = String(raw.scheme ?? 'http');

  return {
    id,
    name: String(raw.name ?? id),
    description: raw.description ? String(raw.description) : '',
    bindAddress,
    localPort,
    target,
    via: {
      ...via,
      identityFile: via.identityFile ? expandHome(String(via.identityFile)) : undefined,
      knownHostsFile: via.knownHostsFile ? expandHome(String(via.knownHostsFile)) : undefined,
    },
    auth: {
      mode: authMode,
      identityFile: authRaw.identityFile ? expandHome(String(authRaw.identityFile)) : via.identityFile ? expandHome(String(via.identityFile)) : '',
      password: authPassword,
      passphrase: authPassphrase,
    },
    forwardSpec,
    scheme,
    // 可以只写路径（/admin/login），也可以写完整 URL（https://foo/bar）；空表示打开根路径
    url: raw.url ? String(raw.url).trim() : '',
    autoStart: Boolean(raw.autoStart ?? false),
    openOnUp: Boolean(raw.openOnUp ?? false),
    healthUrl: raw.healthUrl ? String(raw.healthUrl) : '',
    sshBin: raw.sshBin,
    extraArgs: Array.isArray(raw.extraArgs) ? raw.extraArgs.map(String) : [],
    env: isPlainObject(raw.env) ? raw.env : {},
  };
}

function slug(name) {
  if (!name) return undefined;
  const s = String(name)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return s || undefined;
}

export function normalizeConfig(raw, configFile) {
  if (!isPlainObject(raw)) throw new Error('配置文件根节点必须是一个 JSON 对象');
  const config = {
    panel: mergeSection(DEFAULTS.panel, raw.panel),
    ssh: mergeSection(DEFAULTS.ssh, raw.ssh),
    supervision: mergeSection(DEFAULTS.supervision, raw.supervision),
    configFile: path.resolve(configFile),
  };
  const envToken = process.env.SSH_PROXY_TOKEN;
  config.panel.token = String(envToken ?? config.panel.token ?? '').trim();
  // 令牌来源要能看见：环境变量 > 命令行 --token > 配置文件，三个地方不一致时最容易把人挡在门外
  config.panel.tokenSource = envToken !== undefined ? 'env' : config.panel.token ? 'file' : 'none';

  // 密码只存 scrypt 哈希（不可逆）；手写明文会被拒绝并给出提示
  const passwordHash = String(config.panel.passwordHash ?? '').trim();
  if (passwordHash && !isPasswordHash(passwordHash)) {
    throw new Error('panel.passwordHash 必须是 scrypt 哈希；用 "node src/cli.mjs passwd" 生成，不要手写明文密码');
  }
  config.panel.passwordHash = passwordHash;

  // 密钥登录：Ed25519 公钥（OpenSSH 或 PEM）
  const rawKeys = Array.isArray(config.panel.publicKeys) ? config.panel.publicKeys : [];
  config.panel.publicKeys = rawKeys
    .filter((item) => item && typeof item.key === 'string' && item.key.trim())
    .map((item, index) => {
      const key = normalizePublicKey(item.key);
      return {
        id: String(item.id || `key-${index + 1}`),
        name: String(item.name || `密钥 ${index + 1}`),
        key,
        fingerprint: publicKeyFingerprint(key),
        createdAt: item.createdAt || null,
      };
    });

  // 可用方式由配置推导；authMethods 只用来做"减法"（比如只想留密钥登录）
  const configured = [];
  if (config.panel.token) configured.push('token');
  if (config.panel.passwordHash) configured.push('password');
  if (config.panel.publicKeys.length) configured.push('key');
  const wanted = Array.isArray(config.panel.authMethods) ? config.panel.authMethods.map((x) => String(x)) : [];
  const allowed = wanted.length ? configured.filter((m) => wanted.includes(m)) : configured;
  config.panel.authMethods = allowed.length ? allowed : configured;

  for (const key of ['sessionTtlMinutes', 'sessionIdleMinutes']) {
    const value = Number(config.panel[key]);
    if (!Number.isFinite(value) || value <= 0) throw new Error(`panel.${key} 必须是大于 0 的数字（单位：分钟）`);
    config.panel[key] = value;
  }
  if (process.env.SSH_PROXY_PORT) config.panel.port = assertPort(process.env.SSH_PROXY_PORT, 'panel.port');

  const tunnelsRaw = Array.isArray(raw.tunnels) ? raw.tunnels : [];
  const tunnels = tunnelsRaw.map(normalizeTunnel);
  const seen = new Set();
  for (const tunnel of tunnels) {
    if (seen.has(tunnel.id)) throw new Error(`隧道 id 重复: ${tunnel.id}`);
    seen.add(tunnel.id);
  }
  config.tunnels = tunnels;
  return config;
}

export function loadConfig(file = DEFAULT_CONFIG_FILE) {
  const abs = path.resolve(file);
  const exists = fs.existsSync(abs);
  let raw = { tunnels: [] };
  if (exists) {
    const text = fs.readFileSync(abs, 'utf8').replace(/^\uFEFF/, '');
    try {
      raw = JSON.parse(text);
    } catch (err) {
      throw new Error(`配置文件解析失败 (${abs}): ${err.message}`);
    }
  }
  const config = normalizeConfig(raw, abs);
  config.configExists = exists;
  return config;
}

/** 生成示例配置（init 命令 / 首次运行提示用） */
export function exampleConfig() {
  return {
    panel: {
      host: '127.0.0.1',
      port: 7788,
      token: '',
      passwordHash: '',
      publicKeys: [],
      authMethods: [],
      openOnStart: false,
      sessionTtlMinutes: 720,
      sessionIdleMinutes: 120,
    },
    ssh: {
      bin: 'ssh',
      connectTimeout: 10,
      serverAliveInterval: 15,
      serverAliveCountMax: 3,
      strictHostKeyChecking: 'accept-new',
      batchMode: true,
    },
    supervision: {
      startTimeoutMs: 9000,
      watchIntervalMs: 5000,
      maxFailures: 12,
      backoffBaseMs: 1000,
      backoffMaxMs: 30000,
      stableResetMs: 60000,
    },
    tunnels: [
      {
        id: 'app',
        name: '项目 Web',
        description: '通过边缘机跳到内网项目，本机 8080 访问',
        bindAddress: '127.0.0.1',
        localPort: 8080,
        target: { host: '10.0.0.12', port: 8080 },
        via: {
          user: process.env.USERNAME || 'deploy',
          host: 'edge.example.com',
          port: 22,
          identityFile: '~/.ssh/id_ed25519',
        },
        scheme: 'http',
        autoStart: false,
        openOnUp: false,
      },
      {
        id: 'app-db',
        name: '项目数据库',
        description: '把内网 MySQL 映射到本机 13306，方便用客户端连',
        localPort: 13306,
        target: { host: '10.0.0.13', port: 3306 },
        via: 'deploy@edge.example.com:22',
        autoStart: false,
      },
    ],
  };
}
