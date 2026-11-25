import fs from 'node:fs';
import path from 'node:path';
import { normalizeConfig, exampleConfig } from './config.mjs';
import { normalizePublicKey, publicKeyFingerprint } from './auth.mjs';

/**
 * 面板改配置的落盘逻辑：
 *  - 只改动 tunnels 数组里对应的一项，其它顶层字段（panel/ssh/supervision 以及未来新增的字段）原样保留
 *  - 单条隧道里面板不认识的字段（env、sshBin 等）也会保留，避免手写的内容被吃掉
 *  - 写之前先用 normalizeConfig 全量校验，校验不过就不动文件
 */

const FORM_KEYS = [
  'id',
  'name',
  'description',
  'localPort',
  'listenPort',
  'port',
  'bindAddress',
  'listenAddress',
  'target',
  'targetPort',
  'remoteHost',
  'remotePort',
  'host',
  'via',
  'scheme',
  'url',
  'autoStart',
  'openOnUp',
  'healthUrl',
  'extraArgs',
  'auth',
];
// 这些字段面板不编辑，但必须原样保留
const PRESERVE_KEYS = new Set(['env', 'sshBin']);

function asString(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function asPositiveNumber(value, label) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${label} 必须是一个大于 0 的数字`);
  return n;
}

function emptyConfig() {
  const base = exampleConfig();
  base.tunnels = [];
  return base;
}

function readRawConfig(file) {
  if (!fs.existsSync(file)) return emptyConfig();
  const text = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
  if (!text.trim()) return emptyConfig();
  return JSON.parse(text);
}

export function writeRawConfig(file, raw) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(raw, null, 2)}\n`, 'utf8');
  fs.renameSync(tmp, file);
}

/** 把面板表单提交的数据转成配置文件里的一条隧道 */
function tunnelFromPayload(payload, previousRaw = null) {
  if (!payload || typeof payload !== 'object') throw new Error('请求体格式不对');

  const id = asString(payload.id);
  if (!id) throw new Error('id 不能为空（字母、数字、点、下划线、短横线）');
  if (!/^[A-Za-z0-9._-]+$/.test(id)) throw new Error('id 只能包含字母、数字、点、下划线、短横线');

  const localPort = asPositiveNumber(payload.localPort, '本机端口');
  const target = payload.target && typeof payload.target === 'object' ? payload.target : {};
  const via = payload.via && typeof payload.via === 'object' ? payload.via : {};

  const viaHost = asString(via.host);
  if (!viaHost) throw new Error('边缘机地址（via.host）不能为空');

  const viaPortRaw = asString(via.port);
  const viaPort = viaPortRaw ? asPositiveNumber(viaPortRaw, '边缘机端口') : 22;

  const bindAddress = asString(payload.bindAddress) || '127.0.0.1';
  const targetHost = asString(target.host) || '127.0.0.1';
  const targetPortRaw = asString(target.port);
  const targetPort = targetPortRaw ? asPositiveNumber(targetPortRaw, '目标端口') : localPort;

  // 先按“好看”的顺序编排已知字段，再把保留字段补到后面
  const out = { id };
  const name = asString(payload.name);
  if (name) out.name = name;
  const description = asString(payload.description);
  if (description) out.description = description;
  out.localPort = localPort;
  if (bindAddress !== '127.0.0.1') out.bindAddress = bindAddress;
  out.target = { host: targetHost, port: targetPort };

  const viaOut = {};
  const viaUser = asString(via.user);
  if (viaUser) viaOut.user = viaUser;
  viaOut.host = viaHost;
  viaOut.port = viaPort;
  const identityFile = asString(via.identityFile);
  if (identityFile) viaOut.identityFile = identityFile;
  const proxyJump = asString(via.proxyJump);
  if (proxyJump) viaOut.proxyJump = proxyJump;
  out.via = viaOut;

  // 隧道到边缘机的认证方式：私钥 / 存储密码（已加密）/ 连接时输入
  const authIn = payload.auth && typeof payload.auth === 'object' ? payload.auth : null;
  if (authIn) {
    const prevAuth = previousRaw && typeof previousRaw.auth === 'object' ? previousRaw.auth : {};
    const outAuth = { mode: String(authIn.mode || prevAuth.mode || 'key') };
    const authIdentity = asString(authIn.identityFile) || asString(prevAuth.identityFile);
    if (authIdentity) outAuth.identityFile = authIdentity;
    const password = authIn.clearPassword ? '' : asString(authIn.password) || asString(prevAuth.password);
    if (password) outAuth.password = password;
    const passphrase = authIn.clearPassphrase ? '' : asString(authIn.passphrase) || asString(prevAuth.passphrase);
    if (passphrase) outAuth.passphrase = passphrase;
    out.auth = outAuth;
  } else if (previousRaw && previousRaw.auth && typeof previousRaw.auth === 'object') {
    out.auth = previousRaw.auth;
  }

  const scheme = asString(payload.scheme);
  if (scheme && scheme !== 'http') out.scheme = scheme;
  // 打开路径：留空 = 根路径；也可以写完整 URL
  const openPath = asString(payload.url);
  if (openPath) out.url = openPath;
  const healthUrl = asString(payload.healthUrl);
  if (healthUrl) out.healthUrl = healthUrl;
  if (Array.isArray(payload.extraArgs) && payload.extraArgs.length) {
    out.extraArgs = payload.extraArgs.map((a) => String(a)).filter(Boolean);
  }
  if (payload.autoStart) out.autoStart = true;
  if (payload.openOnUp) out.openOnUp = true;
  if (payload.env && typeof payload.env === 'object' && !Array.isArray(payload.env)) {
    out.env = { ...(payload.env || {}) };
  }

  if (previousRaw && typeof previousRaw === 'object') {
    for (const key of Object.keys(previousRaw)) {
      if (!(key in out) && PRESERVE_KEYS.has(key)) out[key] = previousRaw[key];
    }
  }
  return out;
}

/** 找到 raw.tunnels 中对应某个规范化 id 的下标（兼容手写时省略 id 的情况） */
function indexOfTunnel(rawTunnels, normalizedTunnels, id) {
  const idx = normalizedTunnels.findIndex((t) => t.id === id);
  if (idx >= 0) return idx;
  return rawTunnels.findIndex((t) => asString(t?.id) === id);
}

/**
 * 增/改/删一条隧道，返回 { raw, config, action }。
 * 校验失败直接抛错，调用方据此返回 400，文件保持不动。
 */
export function mutateTunnels(file, { action, id, payload }) {
  const raw = readRawConfig(file);
  const rawTunnels = Array.isArray(raw.tunnels) ? [...raw.tunnels] : [];
  const before = normalizeConfig({ ...raw, tunnels: rawTunnels }, file);

  if (action === 'create') {
    if (before.tunnels.some((t) => t.id === asString(payload?.id))) {
      throw new Error(`已存在 id 为 ${asString(payload?.id)} 的隧道，换个 id 或直接编辑它`);
    }
    rawTunnels.push(tunnelFromPayload(payload));
  } else {
    const idx = indexOfTunnel(rawTunnels, before.tunnels, id);
    if (idx < 0) throw new Error(`找不到隧道: ${id}`);
    if (action === 'update') {
      const previous = rawTunnels[idx];
      const nextTunnel = tunnelFromPayload(payload, previous);
      if (nextTunnel.id !== id && before.tunnels.some((t) => t.id === nextTunnel.id)) {
        throw new Error(`已存在 id 为 ${nextTunnel.id} 的隧道`);
      }
      rawTunnels[idx] = nextTunnel;
    } else if (action === 'delete') {
      rawTunnels.splice(idx, 1);
    } else {
      throw new Error(`未知操作: ${action}`);
    }
  }

  const nextRaw = { ...raw, tunnels: rawTunnels };
  const config = normalizeConfig(nextRaw, file); // 校验：端口、id 唯一性、via 完整性
  return { raw: nextRaw, config };
}

/** 更新 ssh / supervision 这类全局默认参数 */
export function mutateSettings(file, payload) {
  const raw = readRawConfig(file);
  const sshIn = payload?.ssh;
  const supIn = payload?.supervision;

  if (sshIn && typeof sshIn === 'object') {
    const ssh = { ...(raw.ssh || {}) };
    if (sshIn.bin !== undefined) {
      // 允许 "ssh" / "C:\\path\\ssh.exe" 这样的字符串，也允许 ["node","fake-ssh.mjs"] 这类数组
      if (Array.isArray(sshIn.bin)) {
        const list = sshIn.bin.map((x) => String(x)).filter(Boolean);
        if (!list.length) throw new Error('ssh.bin 不能为空');
        ssh.bin = list;
      } else {
        const bin = asString(sshIn.bin);
        if (!bin) throw new Error('ssh.bin 不能为空');
        ssh.bin = bin;
      }
    }
    if (sshIn.connectTimeout !== undefined) ssh.connectTimeout = asPositiveNumber(sshIn.connectTimeout, 'ssh.connectTimeout');
    if (sshIn.serverAliveInterval !== undefined) {
      ssh.serverAliveInterval = asPositiveNumber(sshIn.serverAliveInterval, 'ssh.serverAliveInterval');
    }
    if (sshIn.serverAliveCountMax !== undefined) {
      ssh.serverAliveCountMax = asPositiveNumber(sshIn.serverAliveCountMax, 'ssh.serverAliveCountMax');
    }
    if (sshIn.strictHostKeyChecking !== undefined) {
      const value = asString(sshIn.strictHostKeyChecking);
      if (!['yes', 'no', 'accept-new', 'ask'].includes(value)) throw new Error('StrictHostKeyChecking 只能是 yes / no / accept-new');
      ssh.strictHostKeyChecking = value;
    }
    if (sshIn.batchMode !== undefined) ssh.batchMode = Boolean(sshIn.batchMode);
    raw.ssh = ssh;
  }

  if (supIn && typeof supIn === 'object') {
    const sup = { ...(raw.supervision || {}) };
    for (const key of ['startTimeoutMs', 'watchIntervalMs', 'maxFailures', 'backoffBaseMs', 'backoffMaxMs', 'stableResetMs']) {
      if (supIn[key] !== undefined) sup[key] = asPositiveNumber(supIn[key], `supervision.${key}`);
    }
    raw.supervision = sup;
  }

  // panel.* 属于"门户参数"：可以在这里改，但需要重启面板才生效（服务端只落盘不热应用）
  const panelIn = payload?.panel;
  if (panelIn && typeof panelIn === 'object') {
    const panel = { ...(raw.panel || {}) };
    if (panelIn.token !== undefined) panel.token = asString(panelIn.token);
    for (const key of ['sessionTtlMinutes', 'sessionIdleMinutes']) {
      if (panelIn[key] !== undefined) panel[key] = asPositiveNumber(panelIn[key], `panel.${key}`);
    }
    raw.panel = panel;
  }

  const config = normalizeConfig(raw, file);
  return { raw, config };
}

/* ---------------- 登录凭据（密码 / 公钥） ---------------- */

/** 只写入 scrypt 哈希，明文永远不进文件 */
export function setPasswordHash(file, hash) {
  const raw = readRawConfig(file);
  raw.panel = { ...(raw.panel || {}), passwordHash: String(hash || '') };
  const config = normalizeConfig(raw, file);
  return { raw, config };
}

/** 注册一把 Ed25519 公钥（重复公钥会被拒绝） */
export function addPublicKey(file, { name, key }) {
  const normalized = normalizePublicKey(key);
  const fingerprint = publicKeyFingerprint(normalized);
  const raw = readRawConfig(file);
  const panel = { ...(raw.panel || {}) };
  const keys = Array.isArray(panel.publicKeys) ? [...panel.publicKeys] : [];
  const duplicated = keys.some((item) => {
    try {
      return publicKeyFingerprint(normalizePublicKey(item?.key || '')) === fingerprint;
    } catch {
      return false;
    }
  });
  if (duplicated) throw new Error('这把公钥已经注册过了');

  const id = `key-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
  keys.push({ id, name: String(name || '未命名密钥'), key: normalized, createdAt: new Date().toISOString() });
  panel.publicKeys = keys;
  raw.panel = panel;
  const config = normalizeConfig(raw, file);
  return { raw, config, id, fingerprint };
}

/** 删掉一把公钥（按 id 或指纹） */
export function removePublicKey(file, idOrFingerprint) {
  const raw = readRawConfig(file);
  const panel = { ...(raw.panel || {}) };
  const keys = Array.isArray(panel.publicKeys) ? [...panel.publicKeys] : [];
  const target = String(idOrFingerprint || '');
  const next = keys.filter((item) => {
    if (String(item?.id) === target) return false;
    try {
      return publicKeyFingerprint(normalizePublicKey(item?.key || '')) !== target;
    } catch {
      return true;
    }
  });
  if (next.length === keys.length) throw new Error(`找不到要删除的密钥: ${target}`);
  panel.publicKeys = next;
  raw.panel = panel;
  const config = normalizeConfig(raw, file);
  return { raw, config };
}
