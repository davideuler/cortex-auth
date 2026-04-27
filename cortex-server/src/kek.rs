//! KEK lifecycle: derive from operator password, verify against the on-disk
//! sentinel, or initialize the sentinel on first boot.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

use crate::{
    crypto::{self, Kek},
    db::DbPool,
};

/// Result of unsealing the server. Holds the in-memory KEK and the salt that
/// produced it (kept around for diagnostic logs only).
pub struct Unsealed {
    pub kek: Kek,
    pub kek_version: i64,
}

/// On first boot the kek_metadata row is empty. We generate a salt, derive a
/// KEK from the supplied password, encrypt the sentinel, and store both. On
/// subsequent boots we read the salt, re-derive, and verify the sentinel — a
/// wrong password cannot decrypt it and is rejected.
pub async fn unseal(pool: &DbPool, password: &str) -> Result<Unsealed> {
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT salt, sentinel_ciphertext, kek_version FROM kek_metadata WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .context("Reading kek_metadata")?;

    if let Some((salt_b64, sentinel_ct, kek_version)) = row {
        let salt = BASE64.decode(&salt_b64).context("Stored salt is not base64")?;
        let kek = crypto::derive_kek(password, &salt)?;
        crypto::protect_memory(&kek);
        crypto::verify_sentinel(&kek, &sentinel_ct)?;
        tracing::info!(
            "KEK unsealed with stored salt (kek_version={})",
            kek_version
        );
        Ok(Unsealed { kek, kek_version })
    } else {
        let salt = crypto::random_salt();
        let kek = crypto::derive_kek(password, &salt)?;
        crypto::protect_memory(&kek);
        let sentinel = crypto::seal_sentinel(&kek)?;

        sqlx::query(
            "INSERT INTO kek_metadata (id, salt, sentinel_ciphertext, kek_version) VALUES (1, ?, ?, 1)",
        )
        .bind(BASE64.encode(&salt))
        .bind(&sentinel)
        .execute(pool)
        .await
        .context("Persisting kek_metadata sentinel")?;

        tracing::info!("Initialized KEK sentinel on first boot (kek_version=1)");
        Ok(Unsealed { kek, kek_version: 1 })
    }
}
