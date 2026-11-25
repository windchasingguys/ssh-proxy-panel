import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

/**
 * 隧道凭据的"静态加密"：
 *  - 配置文件里只放密文（AES-256-GCM）
 *  - 密钥是 .ssh-proxy/secret.key 里的 32 字节随机数（首次使用时生成，尽量收紧权限）
 *
 * 说明：这是"防止配置文件被单独拷走/贴给别人"级别的保护，不是硬件保险箱。
 * 能读这台机器上你的用户目录的人，同样能读到 secret.key——真要更强就用密钥登录（私钥在浏览器里）。
 */

const KEY_FILE = 'secret.key';
const PREFIX = 'enc:v1:';

export function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(PREFIX);
}

function keyPath(dataDir) {
  return path.join(dataDir, KEY_FILE);
}

/** 读取（必要时生成）本机主密钥 */
function loadOrCreateKey(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = keyPath(dataDir);
  if (fs.existsSync(file)) {
    const buf = fs.readFileSync(file);
    if (buf.length === 32) return buf;
    // 长度不对就重建（旧密文会解不开，属于预期内的失败）
    fs.rmSync(file, { force: true });
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(file, key, { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    /* Windows 上 chmod 基本是空操作 */
  }
  if (process.platform === 'win32') {
    // 尽力收紧 ACL：只保留当前用户
    try {
      execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${process.env.USERNAME}:F`], { stdio: 'ignore' });
    } catch {
      /* 失败不影响功能，只是权限没这么紧 */
    }
  }
  return key;
}

export function encryptSecret(dataDir, plain) {
  const text = String(plain ?? '');
  if (!text) throw new Error('凭据不能为空');
  const key = loadOrCreateKey(dataDir);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${data.toString('base64')}`;
}

export function decryptSecret(dataDir, payload) {
  const value = String(payload ?? '');
  if (!isEncrypted(value)) throw new Error('凭据不是加密格式（不要手写明文，用面板或 CLI 设置）');
  const [, , ivB64, tagB64, dataB64] = value.split(':');
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('密文格式损坏');
  const key = loadOrCreateKey(dataDir);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const plain = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]);
  return plain.toString('utf8');
}
