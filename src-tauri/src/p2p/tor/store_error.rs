//! Keystore error type: every reject is the same opaque failure so Arti sees
//! a corrupted-store condition rather than partial plaintext fallbacks.
#[derive(Clone, Debug, thiserror::Error)]
#[error("Noid tor store rejected invalid, unsupported or busy access")]
pub struct TorStoreError;

impl tor_error::HasKind for TorStoreError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::KeystoreCorrupted
    }
}

impl tor_keymgr::KeystoreError for TorStoreError {}

impl From<TorStoreError> for tor_keymgr::Error {
    fn from(error: TorStoreError) -> Self {
        Self::Keystore(std::sync::Arc::new(error))
    }
}
