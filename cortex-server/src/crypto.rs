use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Plaintext stub stored alongside the KEK — decrypting it on startup proves
/// the operator-supplied password produced the same KEK as the prior boot.
pub const KEK_SENTINEL_PLAINTEXT: &str = "CORTEX_AUTH_KEK_SENTINEL_v1";

/// 32-byte KEK held in memory after the operator unseals the server.
/// Cleared from memory on drop.
pub struct Kek(Box<[u8; 32]>);

impl Kek {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Kek {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Kek {
    fn clone(&self) -> Self {
        Kek::from_bytes(*self.0)
    }
}

/// Best-effort `mlock` on the KEK page so it isn't swapped to disk. No-op on
/// platforms that don't expose mlock; logs a warning if the syscall fails.
#[cfg(unix)]
pub fn protect_memory(kek: &Kek) {
    let ptr = kek.as_bytes().as_ptr() as *const libc::c_void;
    let len = kek.as_bytes().len();
    let rc = unsafe { libc::mlock(ptr, len) };
    if rc != 0 {
        tracing::warn!(
            "mlock of KEK failed (errno {}); KEK may be swappable",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(unix))]
pub fn protect_memory(_kek: &Kek) {}

/// Derive a 32-byte KEK from the operator password using Argon2id with the
/// stored salt. Salt is per-installation and stored in `kek_metadata`.
pub fn derive_kek(password: &str, salt: &[u8]) -> Result<Kek> {
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("KEK derivation failed: {}", e))?;
    Ok(Kek::from_bytes(out))
}

pub fn random_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// AES-256-GCM "seal": returns base64(nonce || ciphertext).
fn seal_with(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(&combined))
}

fn open_with(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>> {
    let data = BASE64.decode(encoded).context("Invalid base64")?;
    if data.len() < 12 {
        anyhow::bail!("Ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    Ok(plaintext)
}

/// Encrypted payload from the envelope flow: a fresh per-row DEK, a body
/// ciphertext encrypted under that DEK, and the DEK wrapped with the KEK.
pub struct Envelope {
    pub body_ciphertext: String,
    pub wrapped_dek: String,
}

/// Generate a fresh DEK, encrypt `plaintext` under it, then wrap the DEK with
/// the KEK. The DEK is zeroized before returning.
pub fn seal_envelope(plaintext: &str, kek: &Kek) -> Result<Envelope> {
    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);

    let body = seal_with(&dek, plaintext.as_bytes())?;
    let wrapped = seal_with(kek.as_bytes(), &dek)?;

    dek.zeroize();
    Ok(Envelope {
        body_ciphertext: body,
        wrapped_dek: wrapped,
    })
}

/// Reverse of `seal_envelope`. The recovered DEK is zeroized before returning;
/// the plaintext String is the caller's responsibility.
pub fn open_envelope(body_ciphertext: &str, wrapped_dek: &str, kek: &Kek) -> Result<String> {
    let mut dek_bytes = open_with(kek.as_bytes(), wrapped_dek)
        .context("Failed to unwrap DEK with KEK (wrong password or tampered row)")?;
    if dek_bytes.len() != 32 {
        dek_bytes.zeroize();
        anyhow::bail!("Wrapped DEK has unexpected length {}", dek_bytes.len());
    }
    let mut dek_arr = [0u8; 32];
    dek_arr.copy_from_slice(&dek_bytes);
    dek_bytes.zeroize();

    let plaintext_bytes = open_with(&dek_arr, body_ciphertext)
        .context("Failed to decrypt body with DEK");
    dek_arr.zeroize();
    let plaintext_bytes = plaintext_bytes?;
    String::from_utf8(plaintext_bytes).context("Decrypted value is not valid UTF-8")
}

/// Encrypt the sentinel marker directly under the KEK (no DEK indirection —
/// the sentinel is itself the verifier).
pub fn seal_sentinel(kek: &Kek) -> Result<String> {
    seal_with(kek.as_bytes(), KEK_SENTINEL_PLAINTEXT.as_bytes())
}

/// Decrypt the sentinel and verify it matches the expected marker. Returns Err
/// when the password produced the wrong KEK.
pub fn verify_sentinel(kek: &Kek, sentinel_ciphertext: &str) -> Result<()> {
    let bytes = open_with(kek.as_bytes(), sentinel_ciphertext)
        .context("Sentinel decryption failed — wrong KEK password")?;
    if bytes != KEK_SENTINEL_PLAINTEXT.as_bytes() {
        anyhow::bail!("Sentinel mismatch — wrong KEK password");
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Hash failed: {}", e))?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!("Invalid hash: {}", e))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn verify_token(token: &str, hash: &str) -> bool {
    let computed = hash_token(token);
    computed.as_bytes().ct_eq(hash.as_bytes()).into()
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Kek {
        let salt = b"test-salt-fixed-";
        derive_kek("test-operator-password", salt).unwrap()
    }

    #[test]
    fn test_envelope_roundtrip() {
        let kek = test_kek();
        let plaintext = "sk-abc123";
        let env = seal_envelope(plaintext, &kek).unwrap();
        let recovered = open_envelope(&env.body_ciphertext, &env.wrapped_dek, &kek).unwrap();
        assert_eq!(plaintext, recovered);
    }

    #[test]
    fn test_envelope_distinct_dek_per_seal() {
        let kek = test_kek();
        let a = seal_envelope("same", &kek).unwrap();
        let b = seal_envelope("same", &kek).unwrap();
        // Fresh DEK + nonce per row → wrapped_dek must differ.
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
        assert_ne!(a.body_ciphertext, b.body_ciphertext);
    }

    #[test]
    fn test_sentinel_roundtrip() {
        let kek = test_kek();
        let s = seal_sentinel(&kek).unwrap();
        verify_sentinel(&kek, &s).unwrap();
    }

    #[test]
    fn test_sentinel_wrong_kek_rejected() {
        let kek = test_kek();
        let s = seal_sentinel(&kek).unwrap();
        let other = derive_kek("different-password", b"test-salt-fixed-").unwrap();
        assert!(verify_sentinel(&other, &s).is_err());
    }

    #[test]
    fn test_hash_token_verify() {
        let token = generate_token();
        let hash = hash_token(&token);
        assert!(verify_token(&token, &hash));
        assert!(!verify_token("wrong-token", &hash));
    }

    #[test]
    fn test_password_hash_verify() {
        let password = "agent-jwt-secret";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }
}
