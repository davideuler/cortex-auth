//! Bootstrap admin token lifecycle.
//!
//! On first boot we generate a random 256-bit token, store its SHA-256 hash in
//! the `admin_token` table, and hand the plaintext back to `main` for a
//! one-time console display. On subsequent boots only the hash is loaded — the
//! plaintext is unrecoverable from the server, matching the user expectation
//! that the cortex-server keeps a one-way encrypted copy.

use anyhow::{Context, Result};

use crate::{crypto, db::DbPool};

pub struct AdminTokenInit {
    /// SHA-256 hex digest stored on the server and used to verify the
    /// `X-Admin-Token` request header.
    pub hash: String,
    /// `Some(plaintext)` only on the boot that generated the token. The caller
    /// is expected to print this to the operator console exactly once.
    pub plaintext_to_show: Option<String>,
}

pub async fn ensure_admin_token(pool: &DbPool) -> Result<AdminTokenInit> {
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT token_hash FROM admin_token WHERE id = 1")
            .fetch_optional(pool)
            .await
            .context("Reading admin_token row")?;

    if let Some((hash,)) = existing {
        return Ok(AdminTokenInit {
            hash,
            plaintext_to_show: None,
        });
    }

    let plaintext = crypto::generate_token();
    let hash = crypto::hash_token(&plaintext);

    sqlx::query("INSERT INTO admin_token (id, token_hash) VALUES (1, ?)")
        .bind(&hash)
        .execute(pool)
        .await
        .context("Persisting initial admin token hash")?;

    Ok(AdminTokenInit {
        hash,
        plaintext_to_show: Some(plaintext),
    })
}

/// Test-only helper: install a known plaintext token (and return its hash) so
/// tests can drive the admin API without scraping stdout. Replaces any
/// existing row.
pub async fn set_admin_token_for_tests(pool: &DbPool, plaintext: &str) -> Result<String> {
    let hash = crypto::hash_token(plaintext);
    sqlx::query("INSERT OR REPLACE INTO admin_token (id, token_hash) VALUES (1, ?)")
        .bind(&hash)
        .execute(pool)
        .await
        .context("Seeding admin_token row for tests")?;
    Ok(hash)
}
