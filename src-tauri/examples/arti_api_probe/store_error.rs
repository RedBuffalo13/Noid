#[derive(Clone, Debug, thiserror::Error)]
#[error("P0 encrypted store rejected invalid, unsupported or busy access")]
pub struct StoreError;

impl tor_error::HasKind for StoreError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::KeystoreCorrupted
    }
}

impl tor_keymgr::KeystoreError for StoreError {}

impl From<StoreError> for tor_keymgr::Error {
    fn from(error: StoreError) -> Self {
        Self::Keystore(std::sync::Arc::new(error))
    }
}
