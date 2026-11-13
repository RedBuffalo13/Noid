//! META-03: Argon2id-blinded username record keys.
//!
//! The legacy key is `SHA256("noid:username:" || name)` — a crawler can
//! precompute every dictionary name offline and harvest the whole user
//! directory. The blinded key runs the name through Argon2id with a fixed
//! domain salt: each probe costs ~20–40 ms of memory-hard work, so bulk
//! enumeration becomes impractical while a single legit lookup stays
//! instant. The record value keeps its signed JSON form — knowing the
//! name is still required to resolve it, same as today.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use libp2p::kad;

const M_COST: u32 = 8192; // KiB — light on purpose: lookup path, not PIN
const T_COST: u32 = 1;
const P_COST: u32 = 1;
const SALT: &[u8] = b"noid:userblind:v1";

/// Blinded Kademlia key for `username` (lowercased for case-stable
/// resolution, matching the legacy key's normalization).
pub fn username_blind_key(username: &str) -> Result<kad::RecordKey> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(32))
        .map_err(|e| anyhow!("argon2 params: {}", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(username.to_lowercase().as_bytes(), SALT, &mut out)
        .map_err(|e| anyhow!("argon2 blind key: {}", e))?;
    Ok(kad::RecordKey::new(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_case_insensitive() {
        assert_eq!(
            username_blind_key("Alice").unwrap(),
            username_blind_key("alice").unwrap()
        );
        assert_ne!(
            username_blind_key("alice").unwrap(),
            username_blind_key("bob").unwrap()
        );
    }
}
