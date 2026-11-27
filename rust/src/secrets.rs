//! 隧道凭据的静态加密 —— 对应 `src/secrets.mjs`。
//!
//! 配置文件里只放密文（AES-256-GCM，格式 `enc:v1:<ivB64>:<tagB64>:<ctB64>`），
//! 密钥是 `.ssh-proxy/secret.key` 里 32 字节随机数。这是"防止配置文件被单独拷走"级别的保护，
//! 不是硬件保险箱 —— 能读用户目录的人同样能读 secret.key（与 `SECURITY.md` 的口径一致）。

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;

pub const KEY_FILE: &str = "secret.key";
pub const PREFIX: &str = "enc:v1:";

pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX)
}

fn key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KEY_FILE)
}

/// 读取（必要时生成）本机主密钥；长度不对就重建（旧密文解不开，属预期失败）
fn load_or_create_key(data_dir: &Path) -> Result<Vec<u8>, String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("创建数据目录失败: {}", e))?;
    let file = key_path(data_dir);
    if let Ok(buf) = std::fs::read(&file) {
        if buf.len() == 32 {
            return Ok(buf);
        }
        let _ = std::fs::remove_file(&file);
    }

    let mut key = vec![0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| format!("生成随机密钥失败: {}", e))?;
    std::fs::write(&file, &key).map_err(|e| format!("写入 {} 失败: {}", file.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        // 尽力收紧 ACL：只保留当前用户（失败不影响功能，只是权限没这么紧）
        if let Ok(user) = std::env::var("USERNAME") {
            let _ = std::process::Command::new("icacls")
                .args([
                    file.to_string_lossy().as_ref(),
                    "/inheritance:r",
                    "/grant:r",
                    &format!("{}:F", user),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    Ok(key)
}

#[allow(dead_code)] // M4 的配置写回（面板保存明文密码时就地加密）会用
pub fn encrypt_secret(data_dir: &Path, plain: &str) -> Result<String, String> {
    if plain.is_empty() {
        return Err("凭据不能为空".into());
    }
    let key = load_or_create_key(data_dir)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("初始化加密器失败: {}", e))?;

    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|e| format!("生成随机 IV 失败: {}", e))?;

    let encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), plain.as_bytes())
        .map_err(|_| "加密失败".to_string())?;

    // aes-gcm 把 tag 追加在密文尾部（16 字节），这里拆开以对齐 JS 的 <iv>:<tag>:<ct> 格式
    if encrypted.len() < 16 {
        return Err("加密结果异常".into());
    }
    let (ct, tag) = encrypted.split_at(encrypted.len() - 16);
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(format!(
        "{}{}:{}:{}",
        PREFIX,
        b64.encode(iv),
        b64.encode(tag),
        b64.encode(ct)
    ))
}

pub fn decrypt_secret(data_dir: &Path, payload: &str) -> Result<String, String> {
    if !is_encrypted(payload) {
        return Err("凭据不是加密格式（不要手写明文，用面板或 CLI 设置）".into());
    }
    let parts: Vec<&str> = payload.split(':').collect();
    if parts.len() < 5 {
        return Err("密文格式损坏".into());
    }
    let (iv_b64, tag_b64, data_b64) = (parts[2], parts[3], parts[4]);
    if iv_b64.is_empty() || tag_b64.is_empty() || data_b64.is_empty() {
        return Err("密文格式损坏".into());
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let iv = b64.decode(iv_b64).map_err(|_| "密文格式损坏".to_string())?;
    let tag = b64.decode(tag_b64).map_err(|_| "密文格式损坏".to_string())?;
    let ct = b64.decode(data_b64).map_err(|_| "密文格式损坏".to_string())?;
    if iv.len() != 12 || tag.len() != 16 {
        return Err("密文格式损坏".into());
    }

    let key = load_or_create_key(data_dir)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("初始化解密器失败: {}", e))?;

    let mut payload = ct;
    payload.extend_from_slice(&tag);
    let plain = cipher
        .decrypt(Nonce::from_slice(&iv), payload.as_slice())
        .map_err(|_| "凭据解密失败（secret.key 可能已更换）".to_string())?;
    String::from_utf8(plain).map_err(|_| "凭据不是合法 UTF-8".to_string())
}
