//! Encrypted-at-rest Arti keystore.
//!
//! Every record is AES-256-GCM sealed under the `tor-keystore` domain subkey
//! of the login master key; the record map is wrapped in a NOIDKEY2 envelope
//! on disk (`key_store::save` — tmp file + atomic rename). No plaintext key
//! material ever reaches the filesystem: neither Arti's native keystore nor
//! temporary files are used.
//!
//! Mutations (`insert`/`remove`, called by `tor_keymgr` on Arti's tasks)
//! persist immediately so a crash cannot lose freshly generated keys.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use tor_key_forge::{EncodableItem, ErasedKey, KeystoreItem, KeystoreItemType, SshKeyData};
use tor_keymgr::{ArtiPath, KeySpecifier, Keystore, KeystoreEntry, KeystoreId, RawEntryId};
use zeroize::Zeroizing;

use super::store_error::TorStoreError;

type Records = BTreeMap<(String, String), Vec<u8>>;
type StoreResult<T> = Result<T, TorStoreError>;

const MAX_SNAPSHOT: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 128;
const MAX_PATH_LEN: usize = 256;
const MAX_KIND_LEN: usize = 64;
const MAX_CIPHERTEXT: usize = 16384;
const MAX_PLAINTEXT: usize = 16356;
const MIN_CIPHERTEXT: usize = 28; // 12-byte nonce + 16-byte tag minimum

/// Durable encrypted keystore; `Clone` shares the same record map so the
/// supervisor can hold a handle while `KeyMgr` owns a boxed copy.
#[derive(Clone)]
pub struct EncryptedKeystore {
    id: KeystoreId,
    key: Arc<Zeroizing<[u8; 32]>>,
    records: Arc<Mutex<Records>>,
    path: PathBuf,
    master: Arc<Zeroizing<[u8; 32]>>,
}

impl EncryptedKeystore {
    /// Open the store at `path`, decrypting and validating the NOIDKEY2
    /// snapshot if the file exists. Wrong master key, truncation, tampering
    /// or bound violations reject the whole store — never partial restore.
    pub fn open(path: &Path, master: [u8; 32]) -> StoreResult<Self> {
        let key = Zeroizing::new(crate::security::derive_domain_key(&master, "tor-keystore"));
        let mut records = Records::new();
        if path.exists() {
            let snapshot = crate::security::key_store::load(path, &master).map_err(|_| TorStoreError)?;
            if snapshot.len() > MAX_SNAPSHOT {
                return Err(TorStoreError);
            }
            let entries: Vec<((String, String), Vec<u8>)> =
                serde_json::from_slice(&snapshot).map_err(|_| TorStoreError)?;
            if entries.len() > MAX_ENTRIES {
                return Err(TorStoreError);
            }
            for (name, ciphertext) in entries {
                if name.0.len() > MAX_PATH_LEN
                    || name.1.len() > MAX_KIND_LEN
                    || name.0.parse::<ArtiPath>().is_err()
                    || ciphertext.len() < MIN_CIPHERTEXT
                    || ciphertext.len() > MAX_CIPHERTEXT
                    || records.insert(name, ciphertext).is_some()
                {
                    return Err(TorStoreError);
                }
            }
        }
        let store = Self {
            id: "noid-tor-encrypted".parse().map_err(|_| TorStoreError)?,
            key: Arc::new(key),
            records: Arc::new(Mutex::new(records)),
            path: path.to_path_buf(),
            master: Arc::new(Zeroizing::new(master)),
        };
        // Authenticate every entry before accepting a restored store.
        {
            let records = store.records()?;
            for (name, ciphertext) in records.iter() {
                store.decrypt(name, ciphertext)?;
            }
        }
        Ok(store)
    }

    /// Atomic write of the whole record map: NOIDKEY2 envelope + tmp+rename.
    fn persist(&self) -> StoreResult<()> {
        let records = self.records()?;
        let snapshot =
            serde_json::to_vec(&records.iter().collect::<Vec<_>>()).map_err(|_| TorStoreError)?;
        crate::security::key_store::save(&self.path, &snapshot, &self.master)
            .map_err(|_| TorStoreError)
    }

    fn records(&self) -> StoreResult<MutexGuard<'_, Records>> {
        self.records.lock().map_err(|_| TorStoreError)
    }

    fn name(spec: &dyn KeySpecifier, kind: &KeystoreItemType) -> StoreResult<(String, String)> {
        let path = spec.arti_path().map_err(|_| TorStoreError)?.to_string();
        let kind = kind.arti_extension();
        if path.len() > MAX_PATH_LEN || kind.len() > MAX_KIND_LEN {
            return Err(TorStoreError);
        }
        Ok((path, kind))
    }

    fn aad(name: &(String, String)) -> StoreResult<Vec<u8>> {
        serde_json::to_vec(&("noid-tor", 1, &name.0, &name.1)).map_err(|_| TorStoreError)
    }

    fn decrypt(&self, name: &(String, String), data: &[u8]) -> StoreResult<Zeroizing<Vec<u8>>> {
        if data.len() < MIN_CIPHERTEXT || data.len() > MAX_CIPHERTEXT {
            return Err(TorStoreError);
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref().as_ref()).map_err(|_| TorStoreError)?;
        let aad = Self::aad(name)?;
        let nonce = Nonce::from(<[u8; 12]>::try_from(&data[..12]).map_err(|_| TorStoreError)?);
        cipher
            .decrypt(&nonce, Payload { msg: &data[12..], aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| TorStoreError)
    }
}

impl Keystore for EncryptedKeystore {
    fn id(&self) -> &KeystoreId {
        &self.id
    }

    fn contains(&self, spec: &dyn KeySpecifier, kind: &KeystoreItemType) -> tor_keymgr::Result<bool> {
        Ok(self.get(spec, kind)?.is_some())
    }

    fn get(&self, spec: &dyn KeySpecifier, kind: &KeystoreItemType) -> tor_keymgr::Result<Option<ErasedKey>> {
        let name = Self::name(spec, kind)?;
        let ciphertext = {
            let records = self.records()?;
            match records.get(&name) {
                Some(c) => c.clone(),
                None => return Ok(None),
            }
        };
        let plaintext = self.decrypt(&name, &ciphertext)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| TorStoreError)?;
        let key = if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
            let key = tor_keymgr::ssh_key::PrivateKey::from_openssh(text).map_err(|_| TorStoreError)?;
            SshKeyData::try_from_keypair_data(key.key_data().clone())?
        } else {
            let key = tor_keymgr::ssh_key::PublicKey::from_openssh(text).map_err(|_| TorStoreError)?;
            SshKeyData::try_from_key_data(key.key_data().clone())?
        };
        if KeystoreItemType::from(key.key_type()?) != *kind {
            return Err(TorStoreError.into());
        }
        Ok(Some(key.into_erased()?))
    }

    fn insert(&self, key: &dyn EncodableItem, spec: &dyn KeySpecifier) -> tor_keymgr::Result<()> {
        let KeystoreItem::Key(key) = key.as_keystore_item()? else {
            return Err(TorStoreError.into());
        };
        let name = Self::name(spec, &key.key_type()?.into())?;
        let plaintext = Zeroizing::new(key.to_openssh_string("")?);
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(TorStoreError.into());
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref().as_ref()).map_err(|_| TorStoreError)?;
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let aad = Self::aad(&name)?;
        let encrypted = cipher
            .encrypt(&Nonce::from(nonce), Payload { msg: plaintext.as_bytes(), aad: &aad })
            .map_err(|_| TorStoreError)?;
        {
            let mut records = self.records()?;
            if records.len() >= MAX_ENTRIES && !records.contains_key(&name) {
                return Err(TorStoreError.into());
            }
            records.insert(name, [nonce.as_slice(), encrypted.as_slice()].concat());
        }
        self.persist()?;
        Ok(())
    }

    fn remove(&self, spec: &dyn KeySpecifier, kind: &KeystoreItemType) -> tor_keymgr::Result<Option<()>> {
        let name = Self::name(spec, kind)?;
        let removed = {
            let mut records = self.records()?;
            records.remove(&name).map(|_| ())
        };
        if removed.is_some() {
            self.persist()?;
        }
        Ok(removed)
    }

    fn list(&self) -> tor_keymgr::Result<Vec<tor_keymgr::KeystoreEntryResult<KeystoreEntry<'_>>>> {
        let records = self.records()?;
        records
            .keys()
            .map(|(path, kind)| {
                let path: ArtiPath = path.parse().map_err(|_| TorStoreError)?;
                let kind = KeystoreItemType::from(kind.as_str());
                Ok(Ok(KeystoreEntry::new(
                    path.clone().into(),
                    kind.clone(),
                    &self.id,
                    RawEntryId::Ephemeral((path, kind)),
                )))
            })
            .collect()
    }

    fn raw_entry_id(&self, _raw_id: &str) -> tor_keymgr::Result<RawEntryId> {
        Err(TorStoreError.into())
    }

    fn remove_unchecked(&self, _entry_id: &RawEntryId) -> tor_keymgr::Result<()> {
        Err(TorStoreError.into())
    }
}
