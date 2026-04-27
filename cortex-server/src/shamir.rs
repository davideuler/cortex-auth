//! Shamir m-of-n secret sharing wrapper around the `sharks` crate.
//!
//! Used to:
//!   * split the in-memory KEK into N shares with threshold M (admin-triggered),
//!   * reconstruct the KEK at boot from M shares supplied on stdin (recovery
//!     mode — see `kek::unseal_via_recovery`).
//!
//! Shares are returned/accepted as base64 strings so they survive being
//! pasted into chat / a password manager.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sharks::{Share, Sharks};

/// Split `secret` into `n` shares any `m` of which can reconstruct it.
/// Returns base64-encoded shares.
pub fn split(secret: &[u8], threshold: u8, n: u8) -> Result<Vec<String>> {
    anyhow::ensure!(threshold >= 2, "threshold must be >= 2");
    anyhow::ensure!(n >= threshold, "shares must be >= threshold");

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Share> = dealer.take(n as usize).collect();
    Ok(shares
        .into_iter()
        .map(|s| BASE64.encode(Vec::from(&s)))
        .collect())
}

/// Recover the secret from base64-encoded shares. Caller is responsible for
/// supplying at least `threshold` shares — sharks errors otherwise.
pub fn recover(threshold: u8, shares_b64: &[String]) -> Result<Vec<u8>> {
    anyhow::ensure!(threshold >= 2, "threshold must be >= 2");
    anyhow::ensure!(
        shares_b64.len() as u8 >= threshold,
        "supplied {} shares but threshold is {}",
        shares_b64.len(),
        threshold
    );

    let mut shares = Vec::with_capacity(shares_b64.len());
    for (i, b64) in shares_b64.iter().enumerate() {
        let bytes = BASE64
            .decode(b64.trim())
            .with_context(|| format!("share {} is not valid base64", i + 1))?;
        let share = Share::try_from(bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("share {}: {}", i + 1, e))?;
        shares.push(share);
    }

    let sharks = Sharks(threshold);
    let secret = sharks
        .recover(shares.iter())
        .map_err(|e| anyhow::anyhow!("Shamir recovery failed: {}", e))?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_recover_roundtrip() {
        let secret = [42u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = recover(3, &shares[..3]).unwrap();
        assert_eq!(recovered, secret.to_vec());

        let recovered = recover(3, &[shares[0].clone(), shares[2].clone(), shares[4].clone()]).unwrap();
        assert_eq!(recovered, secret.to_vec());
    }

    #[test]
    fn too_few_shares_is_rejected() {
        let secret = [1u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        let err = recover(3, &shares[..2]).unwrap_err();
        assert!(err.to_string().contains("threshold"));
    }
}
