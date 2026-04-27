//! Server-side Ed25519 keypair lifecycle.
//!
//! Used by:
//!   * #14 — signed project tokens (`server_sign_jwt` mints EdDSA JWTs that
//!           clients verify against the JWKS endpoint).
//!   * #13 (server side) — verifying agent auth proofs that have an
//!           `agent_pub` registered.
//!
//! The server's own private key is generated on first boot and persisted
//! envelope-encrypted under the KEK in the `server_keys` table. Public keys
//! are exposed at `GET /.well-known/jwks.json` keyed by `kid` so old tokens
//! stay verifiable across rotations.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{crypto, db::DbPool};

/// Keypair held in memory after server boot.
pub struct ServerKeypair {
    pub kid: String,
    pub signing: SigningKey,
}

impl ServerKeypair {
    pub fn verifying(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
}

/// Load the active server signing key, generating one on first boot.
pub async fn load_or_init(pool: &DbPool, kek: &crypto::Kek) -> Result<ServerKeypair> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT kid, signing_key_ciphertext, signing_key_wrapped_dek FROM server_keys \
         WHERE active = 1 ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("Reading server_keys")?;

    if let Some((kid, ct, wrapped)) = row {
        let bytes_b64 = crypto::open_envelope(&ct, &wrapped, kek)
            .context("Failed to decrypt server signing key")?;
        let bytes = BASE64URL
            .decode(bytes_b64.as_bytes())
            .context("Stored signing key is not base64url")?;
        anyhow::ensure!(bytes.len() == 32, "signing key must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signing = SigningKey::from_bytes(&arr);
        return Ok(ServerKeypair { kid, signing });
    }

    // Generate a new keypair on first boot.
    let signing = SigningKey::generate(&mut OsRng);
    let kid = uuid::Uuid::new_v4().to_string();
    let priv_bytes = signing.to_bytes();
    let priv_b64 = BASE64URL.encode(priv_bytes);
    let envelope = crypto::seal_envelope(&priv_b64, kek)?;

    sqlx::query(
        "INSERT INTO server_keys (kid, signing_key_ciphertext, signing_key_wrapped_dek, kek_version, active) \
         VALUES (?, ?, ?, 1, 1)",
    )
    .bind(&kid)
    .bind(&envelope.body_ciphertext)
    .bind(&envelope.wrapped_dek)
    .execute(pool)
    .await
    .context("Persisting server signing key")?;

    tracing::info!("Generated new server Ed25519 keypair (kid={})", kid);
    Ok(ServerKeypair { kid, signing })
}

/// JWKS view of the server's *active and historical* public keys. Clients
/// fetching `/.well-known/jwks.json` resolve a token's `kid` against this set.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    pub alg: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

pub async fn list_jwks(pool: &DbPool, kek: &crypto::Kek) -> Result<JwkSet> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT kid, signing_key_ciphertext, signing_key_wrapped_dek FROM server_keys \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    let mut keys = Vec::with_capacity(rows.len());
    for (kid, ct, wrapped) in rows {
        let priv_b64 = match crypto::open_envelope(&ct, &wrapped, kek) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let priv_bytes = match BASE64URL.decode(priv_b64.as_bytes()) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&priv_bytes);
        let signing = SigningKey::from_bytes(&arr);
        let pub_bytes = signing.verifying_key().to_bytes();
        keys.push(Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            kid,
            x: BASE64URL.encode(pub_bytes),
            alg: "EdDSA".into(),
        });
    }
    Ok(JwkSet { keys })
}

/// Mint an EdDSA-signed JWT (compact serialization) over the given claims.
pub fn sign_jwt<C: Serialize>(keypair: &ServerKeypair, claims: &C) -> Result<String> {
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": keypair.kid,
    });
    let header_b64 = BASE64URL.encode(serde_json::to_vec(&header)?);
    let payload_b64 = BASE64URL.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let sig: Signature = keypair.signing.sign(signing_input.as_bytes());
    let sig_b64 = BASE64URL.encode(sig.to_bytes());
    Ok(format!("{}.{}", signing_input, sig_b64))
}

/// Verify an EdDSA-signed JWT minted by *this server*. Returns the parsed
/// claims on success.
pub fn verify_jwt<C: for<'de> Deserialize<'de>>(
    keypair: &ServerKeypair,
    token: &str,
) -> Result<C> {
    let parts: Vec<&str> = token.split('.').collect();
    anyhow::ensure!(parts.len() == 3, "JWT must have 3 parts");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = BASE64URL
        .decode(parts[2].as_bytes())
        .context("signature is not base64url")?;
    let sig =
        Signature::from_slice(&sig_bytes).context("signature has wrong length")?;
    keypair
        .verifying()
        .verify(signing_input.as_bytes(), &sig)
        .context("JWT signature did not verify")?;
    let payload = BASE64URL
        .decode(parts[1].as_bytes())
        .context("payload is not base64url")?;
    let claims: C =
        serde_json::from_slice(&payload).context("payload is not valid JSON")?;
    Ok(claims)
}

/// Verify an Ed25519 signature using a public key registered for an agent
/// (#13). Used to authenticate `/agent/discover` when the agent uploaded
/// `agent_pub` instead of (or in addition to) the legacy HMAC `jwt_secret`.
pub fn verify_agent_signature(
    agent_pub_b64: &str,
    message: &[u8],
    sig_b64: &str,
) -> Result<()> {
    let pub_bytes = BASE64URL
        .decode(agent_pub_b64.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(agent_pub_b64.as_bytes()))
        .context("agent_pub is not base64")?;
    anyhow::ensure!(pub_bytes.len() == 32, "agent_pub must be 32 bytes");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);
    let verifying = VerifyingKey::from_bytes(&arr).context("agent_pub is not a valid Ed25519 key")?;

    let sig_bytes = BASE64URL
        .decode(sig_b64.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()))
        .context("signature is not base64")?;
    let sig = Signature::from_slice(&sig_bytes).context("signature has wrong length")?;
    verifying
        .verify(message, &sig)
        .context("agent signature did not verify")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_signature_roundtrip() {
        let signing = SigningKey::generate(&mut OsRng);
        let pub_b64 = BASE64URL.encode(signing.verifying_key().to_bytes());
        let msg = b"ts=1|nonce=abc|agent_id=foo|path=/agent/discover";
        let sig: Signature = signing.sign(msg);
        let sig_b64 = BASE64URL.encode(sig.to_bytes());
        verify_agent_signature(&pub_b64, msg, &sig_b64).unwrap();
    }
}
