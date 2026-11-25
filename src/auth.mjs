import crypto from 'node:crypto';

/**
 * 面板登录的三种凭据：
 *  - token   ：共享密钥（兼容旧配置），明文放配置里，适合本机
 *  - password：只存 scrypt 哈希（不可逆），配置泄露也拿不到明文
 *  - key     ：Ed25519 公钥（私钥留在浏览器 IndexedDB 里，不可导出），登录时签名挑战
 */

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 };
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/* ---------------- 密码（只存哈希） ---------------- */

export function hashPassword(password) {
  const text = String(password ?? '');
  if (text.length < 1) throw new Error('密码不能为空');
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(text, salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: SCRYPT.maxmem,
  });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function isPasswordHash(value) {
  return typeof value === 'string' && /^scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/.test(value);
}

export function verifyPassword(password, stored) {
  if (!isPasswordHash(stored)) return false;
  try {
    const [, N, r, p, saltB64, hashB64] = stored.split('$');
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(String(password ?? ''), salt, expected.length, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
      maxmem: SCRYPT.maxmem,
    });
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/* ---------------- 公钥（Ed25519） ---------------- */

/** 接受 "ssh-ed25519 AAAA..." / 完整 authorized_keys 行 / PEM */
export function normalizePublicKey(input) {
  const text = String(input ?? '').trim();
  if (!text) throw new Error('公钥不能为空');
  if (text.includes('BEGIN PUBLIC KEY') || text.includes('BEGIN RSA PUBLIC KEY')) {
    return text.replace(/\r/g, '').replace(/\n+$/, '');
  }
  const parts = text.split(/\s+/);
  if (parts.length >= 2 && /^ssh-(ed25519|rsa)$|^ecdsa-sha2-/.test(parts[0])) {
    return `${parts[0]} ${parts[1]}`;
  }
  throw new Error('公钥格式无法识别：支持 "ssh-ed25519 AAAA..."、authorized_keys 整行，或 PEM');
}

function readSshString(blob, offsetRef) {
  const len = blob.readUInt32BE(offsetRef.offset);
  offsetRef.offset += 4;
  const value = blob.subarray(offsetRef.offset, offsetRef.offset + len);
  offsetRef.offset += len;
  return value;
}

function publicKeyToKeyObject(stored) {
  const text = normalizePublicKey(stored);
  if (text.includes('BEGIN')) return crypto.createPublicKey(text);
  const [type, blobB64] = text.split(' ');
  if (type !== 'ssh-ed25519') {
    throw new Error(`目前只支持 ssh-ed25519 公钥（收到 ${type}）。可以用 "ssh-keygen -t ed25519" 或直接在面板里生成`);
  }
  const blob = Buffer.from(blobB64, 'base64');
  const offsetRef = { offset: 0 };
  const declaredType = readSshString(blob, offsetRef).toString('utf8');
  if (declaredType !== 'ssh-ed25519') throw new Error(`公钥内容与类型不匹配: ${declaredType}`);
  const raw = readSshString(blob, offsetRef);
  if (raw.length !== 32) throw new Error('Ed25519 公钥长度异常');
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/** 浏览器导出的 raw 32 字节 → ssh-ed25519 字符串 */
export function opensshFromRawEd25519(rawB64) {
  const raw = Buffer.from(String(rawB64), 'base64');
  if (raw.length !== 32) throw new Error('Ed25519 公钥必须是 32 字节');
  const type = Buffer.from('ssh-ed25519');
  const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    return b;
  };
  const blob = Buffer.concat([u32(type.length), type, u32(raw.length), raw]);
  return `ssh-ed25519 ${blob.toString('base64')}`;
}

export function publicKeyFingerprint(stored) {
  try {
    const key = publicKeyToKeyObject(stored);
    const der = key.export({ format: 'der', type: 'spki' });
    return `SHA256:${crypto.createHash('sha256').update(der).digest('base64').replace(/=+$/, '')}`;
  } catch {
    return '';
  }
}

/** 校验 Ed25519 签名：dataB64 是挑战的 base64，signatureB64 是签名的 base64 */
export function verifySignature(storedPublicKey, dataB64, signatureB64) {
  try {
    const key = publicKeyToKeyObject(storedPublicKey);
    const data = Buffer.from(String(dataB64), 'base64');
    const signature = Buffer.from(String(signatureB64), 'base64');
    if (!data.length || !signature.length) return false;
    return crypto.verify(null, data, key, signature);
  } catch {
    return false;
  }
}

/** 服务端生成挑战（32 字节随机数的 base64） */
export function newChallenge() {
  return crypto.randomBytes(32).toString('base64');
}
