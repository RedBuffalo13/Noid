//! TPM 2.0 sealing for the relay master key (Q09/A8, later#1).
//!
//! Threat: `relay.pass` on a VPS disk is a single-point key compromise —
//! a stolen disk image or snapshot yields the passphrase, hence every
//! key envelope. With TPM sealing the passphrase lives only inside the
//! TPM's sealed object space: `relay.tpm` on disk is just a marker, and
//! the sealed object is bound to the chip's seed — it cannot be unsealed
//! on another machine or after the TPM is cleared.
//!
//! Design:
//! - The passphrase is sealed into a KeyedHash object under the owner
//!   hierarchy and evicted to a PERSISTENT handle — no serialized blob
//!   ever leaves the TPM, so there is nothing to smuggle out.
//! - `relay.tpm` (data dir) records that sealing was enabled — presence
//!   means "operator intended TPM", absence means "legacy pass file".
//! - Fallback is mandatory (megaplan): a missing/unreadable TPM never
//!   wedges the relay — `read_passphrase` falls through to `relay.pass`
//!   / env / prompt with a loud warning. Only `--init` with
//!   `NOID_RELAY_TPM=1` hard-fails on seal errors (explicit request).
//!
//! Build: requires `--features tpm` (pulls `tss-esapi`) and the
//! `tpm2-tss` system libraries (`libtss2-dev`) — Linux only. Every other
//! configuration compiles the stubs below and behaves exactly like the
//! legacy flow. TCTI defaults to the resource manager device;
//! `NOID_TPM_TCTI` overrides (e.g. `device:/dev/tpm0`, `swtpm:` for a
//! virtual TPM on a VPS without vTPM hardware).

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Marker file recording that this relay was initialized with TPM
/// sealing — presence, not content, is the signal.
pub const TPM_MARKER: &str = "relay.tpm";

/// Persistent TPM handle holding the sealed passphrase object. Chosen
/// inside the platform-reserved user range 0x81000000-0x817FFFFF.
pub const PERSISTENT_HANDLE: u32 = 0x8100_4E49; // 'NI' suffix

pub fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TPM_MARKER)
}

/// Whether this relay was initialized for TPM sealing.
pub fn sealing_enabled(data_dir: &Path) -> bool {
    marker_path(data_dir).exists()
}

/// Whether the operator explicitly asked for TPM at init.
pub fn sealing_requested() -> bool {
    std::env::var("NOID_RELAY_TPM")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
mod imp {
    use super::*;
    use anyhow::anyhow;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            dynamic_handles::PersistentTpmHandle,
            resource_handles::{Hierarchy, Provision},
            session_handles::AuthSession,
        },
        structures::{
            Digest, KeyedHashParameters, PublicBuilder, SensitiveData,
            SymmetricCipherParameters, SymmetricDefinitionObject,
        },
        tcti_ldr::{DeviceConfig, TctiNameConf},
        TpmHandle,
    };
    use tss_esapi::interface_types::keyedhash::KeyedHashScheme;

    fn ctx() -> Result<tss_esapi::Context> {
        let tcti = match std::env::var("NOID_TPM_TCTI") {
            Ok(v) => TctiNameConf::try_from(v.as_str())
                .map_err(|e| anyhow!("NOID_TPM_TCTI invalid: {}", e))?,
            Err(_) => TctiNameConf::Device(DeviceConfig::default()),
        };
        tss_esapi::Context::new(tcti).map_err(|e| anyhow!("TPM context failed: {}", e))
    }

    /// Restricted decryption AES-256-CFB storage key (the SRK profile).
    fn storage_public() -> Result<tss_esapi::structures::Public> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(|e| anyhow!("TPM attrs: {}", e))?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_256_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .build()
            .map_err(|e| anyhow!("TPM primary public: {}", e))
    }

    /// Public area of the sealed passphrase object.
    fn sealed_public() -> Result<tss_esapi::structures::Public> {
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| anyhow!("TPM sealed attrs: {}", e))?;
        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_keyed_hash_parameters(KeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|e| anyhow!("TPM sealed public: {}", e))
    }

    fn persistent_handle() -> Result<PersistentTpmHandle> {
        PersistentTpmHandle::new(PERSISTENT_HANDLE)
            .map_err(|e| anyhow!("TPM persistent handle: {}", e))
    }

    /// Seal `pass` into the TPM at the persistent handle (replacing any
    /// existing object there), then drop the `relay.tpm` marker.
    pub fn seal_passphrase(data_dir: &Path, pass: &str) -> Result<()> {
        let mut context = ctx()?;
        let sensitive = SensitiveData::try_from(pass.as_bytes().to_vec())
            .map_err(|e| anyhow!("TPM sensitive data: {}", e))?;
        let persistent = persistent_handle()?;

        // Evict anything already squatting on the handle (re-init path).
        if let Ok(handle) = context.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
            context.execute_with_nullauth_session(|ctx| {
                ctx.evict_control(Provision::Owner, handle.into(), persistent)
                    .map(|_| ())
            });
        }

        context.execute_with_nullauth_session(move |ctx| -> Result<()> {
            let primary = ctx
                .create_primary_key(Hierarchy::Owner, storage_public()?, None, None, None, None)
                .map_err(|e| anyhow!("TPM create_primary: {}", e))?;
            let sealed = ctx
                .create(
                    primary.key_handle,
                    sealed_public()?,
                    None,
                    Some(sensitive),
                    None,
                    None,
                )
                .map_err(|e| anyhow!("TPM seal create: {}", e))?;
            let loaded = ctx
                .load(primary.key_handle, sealed.out_private, sealed.out_public)
                .map_err(|e| anyhow!("TPM load sealed: {}", e))?;
            ctx.evict_control(Provision::Owner, loaded.into(), persistent)
                .map_err(|e| anyhow!("TPM evict_control: {}", e))?;
            // The transient primary is flushed implicitly when the
            // session/context drops — no persistent slot is consumed.
            Ok(())
        })?;

        std::fs::write(
            marker_path(data_dir),
            format!("sealed=1\nhandle=0x{:08x}\n", PERSISTENT_HANDLE),
        )?;
        Ok(())
    }

    /// `Ok(Some)` — passphrase recovered from the sealed object;
    /// `Ok(None)` — no marker, the caller falls through to relay.pass.
    pub fn unseal_passphrase(data_dir: &Path) -> Result<Option<String>> {
        if !sealing_enabled(data_dir) {
            return Ok(None);
        }
        let mut context = ctx()?;
        let persistent = persistent_handle()?;
        let handle = context
            .tr_from_tpm_public(TpmHandle::Persistent(persistent))
            .map_err(|e| anyhow!("TPM: no sealed object at handle: {}", e))?;
        let data = context
            .execute_with_session(AuthSession::Password, |ctx| ctx.unseal(handle.into()))
            .map_err(|e| anyhow!("TPM unseal failed: {}", e))?;
        let pass = String::from_utf8(data.value().to_vec())
            .map_err(|e| anyhow!("TPM unseal: payload is not UTF-8: {}", e))?;
        Ok(Some(pass))
    }
}

#[cfg(not(all(target_os = "linux", feature = "tpm")))]
mod imp {
    use super::*;
    use anyhow::anyhow;

    /// TPM sealing was not compiled in — explicit init requests fail
    /// loudly rather than silently downgrading to the pass file.
    pub fn seal_passphrase(_data_dir: &Path, _pass: &str) -> Result<()> {
        Err(anyhow!(
            "NOID_RELAY_TPM requested but this build has no TPM support — \
             rebuild with `--features tpm` on Linux with libtss2-dev"
        ))
    }

    /// No TPM support compiled: marker present → loud warning (the log
    /// line in the caller makes the downgrade visible), then the
    /// standard relay.pass fallback applies.
    pub fn unseal_passphrase(data_dir: &Path) -> Result<Option<String>> {
        if sealing_enabled(data_dir) {
            log::warn!(
                "relay.tpm present but this build lacks TPM support — \
                 falling back to relay.pass / env / prompt"
            );
        }
        Ok(None)
    }
}

pub use imp::{seal_passphrase, unseal_passphrase};
