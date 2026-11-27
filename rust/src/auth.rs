//! 面板登录的三种凭据 —— 对应 `src/auth.mjs`。
//!
//! - `token`   ：共享密钥（明文放配置），适合本机
//! - `password`：只存 scrypt 哈希（`scrypt$N$r$p$saltB64$hashB64`）
//! - `key`     ：Ed25519 公钥，登录时对挑战签名（私钥在浏览器 IndexedDB 里）
//!
//! 注意：指纹算的是 **SPKI DER** 的 SHA256（不是 OpenSSH 线上的 blob），
//! 与 Node 的 `publicKeyFingerprint()` 一致。

use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[allow(dead_code)] // M4 的 `passwd` 子命令会用
pub const SCRYPT_N: u32 = 16384;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;
pub const SCRYPT_KEYLEN: usize = 32;

/// Ed25519 的 SPKI DER 前缀（`30 2a 30 05 06 03 2b 65 70 03 21 00`）
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

// ---------------------------------------------------------------- 密码

#[allow(dead_code)] // M4 的 `passwd` 子命令会用
pub fn hash_password(password: &str) -> Result<String, String> {
    if password.is_empty() {
        return Err("密码不能为空".into());
    }
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| format!("生成盐失败: {}", e))?;

    let params = scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, SCRYPT_KEYLEN)
        .map_err(|e| format!("scrypt 参数非法: {}", e))?;
    let mut hash = [0u8; SCRYPT_KEYLEN];
    scrypt::scrypt(password.as_bytes(), &salt, &params, &mut hash)
        .map_err(|e| format!("scrypt 计算失败: {}", e))?;

    Ok(format!(
        "scrypt${}${}${}${}${}",
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        b64().encode(salt),
        b64().encode(hash)
    ))
}

/// `scrypt$N$r$p$saltB64$hashB64` 的格式校验（与 `auth.mjs` 的正则等价）
pub fn is_password_hash(value: &str) -> bool {
    let parts: Vec<&str> = value.split('$').collect();
    if parts.len() != 6 || parts[0] != "scrypt" {
        return false;
    }
    let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if !numeric(parts[1]) || !numeric(parts[2]) || !numeric(parts[3]) {
        return false;
    }
    let b64ish = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    };
    b64ish(parts[4]) && b64ish(parts[5])
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    if !is_password_hash(stored) {
        return false;
    }
    let parts: Vec<&str> = stored.split('$').collect();
    let Ok(n) = parts[1].parse::<u32>() else {
        return false;
    };
    let Ok(r) = parts[2].parse::<u32>() else {
        return false;
    };
    let Ok(p) = parts[3].parse::<u32>() else {
        return false;
    };
    // N 必须是 2 的幂，才能换成 scrypt 的 log_n
    if n < 2 || !n.is_power_of_two() {
        return false;
    }
    let log_n = n.trailing_zeros() as u8;
    let Ok(salt) = b64().decode(parts[4]) else {
        return false;
    };
    let Ok(expected) = b64().decode(parts[5]) else {
        return false;
    };
    if expected.is_empty() || !(10..=64).contains(&expected.len()) {
        return false;
    }

    let Ok(params) = scrypt::Params::new(log_n, r, p, expected.len()) else {
        return false;
    };
    let mut actual = vec![0u8; expected.len()];
    if scrypt::scrypt(password.as_bytes(), &salt, &params, &mut actual).is_err() {
        return false;
    }
    safe_equal_bytes(&actual, &expected)
}

/// 常数时间比较（对应 `crypto.timingSafeEqual`）
pub fn safe_equal_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn safe_equal(a: &str, b: &str) -> bool {
    safe_equal_bytes(a.as_bytes(), b.as_bytes())
}

// ---------------------------------------------------------------- 公钥

/// 接受 `ssh-ed25519 AAAA...` / 完整 authorized_keys 行 / PEM
pub fn normalize_public_key(input: &str) -> Result<String, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("公钥不能为空".into());
    }
    if text.contains("BEGIN PUBLIC KEY") || text.contains("BEGIN RSA PUBLIC KEY") {
        return Ok(text.replace('\r', "").trim_end_matches('\n').to_string());
    }
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() >= 2
        && (parts[0] == "ssh-ed25519"
            || parts[0] == "ssh-rsa"
            || parts[0].starts_with("ecdsa-sha2-"))
    {
        return Ok(format!("{} {}", parts[0], parts[1]));
    }
    Err("公钥格式无法识别：支持 \"ssh-ed25519 AAAA...\"、authorized_keys 整行，或 PEM".into())
}

/// 读一个 SSH 线格式字符串（4 字节大端长度 + 内容）
fn read_ssh_string(blob: &[u8], offset: &mut usize) -> Option<Vec<u8>> {
    if *offset + 4 > blob.len() {
        return None;
    }
    let len = u32::from_be_bytes(blob[*offset..*offset + 4].try_into().ok()?) as usize;
    *offset += 4;
    if *offset + len > blob.len() {
        return None;
    }
    let value = blob[*offset..*offset + len].to_vec();
    *offset += len;
    Some(value)
}

fn verifying_key(stored: &str) -> Option<VerifyingKey> {
    let text = normalize_public_key(stored).ok()?;
    if text.contains("BEGIN") {
        return VerifyingKey::from_public_key_pem(&text).ok();
    }
    let mut parts = text.split_whitespace();
    let kind = parts.next()?;
    let blob_b64 = parts.next()?;
    if kind != "ssh-ed25519" {
        return None;
    }
    let blob = b64().decode(blob_b64).ok()?;
    let mut offset = 0usize;
    let declared = read_ssh_string(&blob, &mut offset)?;
    if declared != b"ssh-ed25519" {
        return None;
    }
    let raw = read_ssh_string(&blob, &mut offset)?;
    if raw.len() != 32 {
        return None;
    }
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(&raw);
    VerifyingKey::from_public_key_der(&der).ok()
}

pub fn public_key_fingerprint(stored: &str) -> String {
    let Some(key) = verifying_key(stored) else {
        return String::new();
    };
    let Ok(der) = key.to_public_key_der() else {
        return String::new();
    };
    let digest = Sha256::digest(der.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{}", encoded)
}

/// `data_b64` 是挑战的 base64，`signature_b64` 是签名的 base64
pub fn verify_signature(stored: &str, data_b64: &str, signature_b64: &str) -> bool {
    let Some(key) = verifying_key(stored) else {
        return false;
    };
    let Ok(data) = b64().decode(data_b64) else {
        return false;
    };
    let Ok(sig_bytes) = b64().decode(signature_b64) else {
        return false;
    };
    if data.is_empty() || sig_bytes.is_empty() {
        return false;
    }
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return false;
    };
    key.verify_strict(&data, &signature).is_ok()
}

/// 服务端生成挑战（32 字节随机数的 base64）
pub fn new_challenge() -> String {
    let mut buf = [0u8; 32];
    if getrandom::getrandom(&mut buf).is_err() {
        return String::new();
    }
    b64().encode(buf)
}

/// 会话 id / 挑战 id 用的随机串（base64url，无填充）
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        return String::new();
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    if getrandom::getrandom(&mut buf).is_err() {
        return String::new();
    }
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}
