//! Offline onion identity: one stable hsid keypair per Noid identity, created
//! after PIN login without opening a single Tor socket or publishing a
//! descriptor. The key material lives only inside `EncryptedKeystore`
//! (AES-256-GCM + NOIDKEY2 envelope); Arti's native keystore is never used.

use anyhow::{Context, Result};
use safelog::DisplayRedacted;
use std::path::Path;
use std::sync::Arc;
use tor_hsservice::{config::OnionServiceConfigBuilder, OnionService, OnionServiceConfig};
use tor_keymgr::{KeyMgr, KeyMgrBuilder};
use tor_persist::state_dir::StateDirectory;

use super::encrypted_keystore::EncryptedKeystore;

/// Onion identity bound to this Noid identity. Constructing it performs no
/// network I/O: `generate_identity_key` is a pure keystore operation.
pub struct OnionIdentity {
    /// Full `xxxxxxxx…onion` host (no port). Only expose in invites/UI where
    /// the user expects it — never in routine logs (use `redacted()`).
    pub onion_address: String,
    /// Durable encrypted keystore backing the identity.
    pub keystore: EncryptedKeystore,
    /// KeyMgr built over our keystore — injected into `OnionService` so Arti's
    /// native (unencrypted) keystore is never touched.
    keymgr: Arc<KeyMgr>,
    service_config: OnionServiceConfig,
    state_dir: StateDirectory,
}

impl OnionIdentity {
    /// Rebuild the `OnionService` object for a service launch. Launching is
    /// the supervisor's job and only happens after explicit consent.
    pub(crate) fn build_service(&self) -> Result<OnionService> {
        OnionService::builder()
            .config(self.service_config.clone())
            .keymgr(self.keymgr.clone())
            .state_dir(self.state_dir.clone())
            .build()
            .map_err(|e| anyhow::anyhow!("onion service build failed: {}", e))
    }

    /// Redacted form for logs (Arti redacts the middle of the address).
    pub fn redacted(&self) -> String {
        let a = &self.onion_address;
        if a.len() > 16 { format!("{}…{}", &a[..8], &a[a.len() - 8..]) } else { a.clone() }
    }
}

/// Load or create the onion identity under `tor_dir` using the login master
/// key. Idempotent: an existing encrypted store is reopened, otherwise the
/// hsid keypair is generated once and durably persisted.
pub fn ensure_onion_identity(master: &[u8; 32], tor_dir: &Path) -> Result<OnionIdentity> {
    let key_dir = tor_dir.join("keys");
    std::fs::create_dir_all(&key_dir).context("create tor key dir")?;
    let keystore = EncryptedKeystore::open(&key_dir.join("keystore.noidkey"), *master)
        .map_err(|e| anyhow::anyhow!("tor keystore open failed: {}", e))?;
    let keymgr = Arc::new(
        KeyMgrBuilder::default()
            .primary_store(Box::new(keystore.clone()))
            .build()
            .context("keymgr build failed")?,
    );
    let service_config = OnionServiceConfigBuilder::default()
        .nickname("noid".parse().context("nickname parse")?)
        .build()
        .context("onion service config build")?;
    let state_dir = StateDirectory::new(tor_dir.join("hs"), &fs_mistrust::Mistrust::default())
        .map_err(|e| anyhow::anyhow!("state dir open failed: {}", e))?;
    let service = OnionService::builder()
        .config(service_config.clone())
        .keymgr(keymgr.clone())
        .state_dir(state_dir.clone())
        .build()
        .map_err(|e| anyhow::anyhow!("onion service build failed: {}", e))?;
    // Keystore write only: generates the hsid keypair once, then always
    // returns the stored one. No TorClient, no sockets, no descriptor.
    let hsid = service
        .generate_identity_key(Default::default())
        .map_err(|e| anyhow::anyhow!("onion identity generation failed: {}", e))?;
    let onion_address = hsid.display_unredacted().to_string();
    Ok(OnionIdentity {
        onion_address,
        keystore,
        keymgr,
        service_config,
        state_dir,
    })
}
