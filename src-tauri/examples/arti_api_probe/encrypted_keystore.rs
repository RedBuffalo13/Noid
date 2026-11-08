use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use rand::Rng;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;
use tor_key_forge::{EncodableItem, ErasedKey, KeystoreItem, KeystoreItemType, SshKeyData};
use tor_keymgr::{ArtiPath, KeySpecifier, Keystore, KeystoreEntry, KeystoreId, RawEntryId};
use zeroize::Zeroizing;

use crate::store_error::StoreError;

type Records = BTreeMap<(String, String), Vec<u8>>;

#[derive(Clone)]
/// P0 snapshot-only store; not a production filesystem, certificate or shutdown implementation.
pub struct EncryptedKeystore {
    id: KeystoreId,
    key: Arc<Zeroizing<[u8; 32]>>,
    records: Arc<Mutex<Records>>,
}

impl EncryptedKeystore {
    /// Authenticate every bounded snapshot entry before accepting a restored store.
    pub fn new(master: [u8; 32], snapshot: Option<&[u8]>) -> Result<Self, StoreError> {
        let master = Zeroizing::new(master);
        let key = Zeroizing::new(crate::domains::derive_domain_key(&master, "tor-keystore"));
        let mut records = Records::new();
        if let Some(snapshot) = snapshot {
            if snapshot.len() > 1024 * 1024 {
                return Err(StoreError);
            }
            let entries: Vec<((String, String), Vec<u8>)> =
                serde_json::from_slice(snapshot).map_err(|_| StoreError)?;
            if entries.len() > 128 {
                return Err(StoreError);
            }
            for (name, ciphertext) in entries {
                if name.0.len() > 256 || name.1.len() > 64
                    || name.0.parse::<ArtiPath>().is_err()
                    || ciphertext.len() < 28 || ciphertext.len() > 16384
                    || records.insert(name, ciphertext).is_some()
                {
                    return Err(StoreError);
                }
            }
        }
        let store = Self {
            id: "noid-p0-encrypted".parse().map_err(|_| StoreError)?,
            key: Arc::new(key),
            records: Arc::new(Mutex::new(records)),
        };
        {
            let records = store.records.try_lock().map_err(|_| StoreError)?;
            for (name, ciphertext) in records.iter() {
                store.decrypt(name, ciphertext)?;
            }
        }
        Ok(store)
    }

    /// Export public key identifiers and encrypted key bodies, never plaintext key material.
    pub fn snapshot(&self) -> Result<Vec<u8>, StoreError> {
        let records = self.records.try_lock().map_err(|_| StoreError)?;
        serde_json::to_vec(&records.iter().collect::<Vec<_>>()).map_err(|_| StoreError)
    }

    fn name(spec: &dyn KeySpecifier, kind: &KeystoreItemType) -> Result<(String, String), StoreError> {
        let path = spec.arti_path().map_err(|_| StoreError)?.to_string();
        let kind = kind.arti_extension();
        if path.len() > 256 || kind.len() > 64 {
            return Err(StoreError);
        }
        Ok((path, kind))
    }

    fn aad(name: &(String, String)) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(&("noid-tor-probe", 1, &name.0, &name.1)).map_err(|_| StoreError)
    }

    fn decrypt(&self, name: &(String, String), data: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if data.len() < 28 || data.len() > 16384 {
            return Err(StoreError);
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref().as_ref()).map_err(|_| StoreError)?;
        let aad = Self::aad(name)?;
        let nonce = Nonce::from(<[u8; 12]>::try_from(&data[..12]).map_err(|_| StoreError)?);
        cipher.decrypt(&nonce, Payload { msg: &data[12..], aad: &aad })
            .map(Zeroizing::new).map_err(|_| StoreError)
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
        let records = self.records.try_lock().map_err(|_| StoreError)?;
        let Some(ciphertext) = records.get(&name) else {
            return Ok(None);
        };
        let plaintext = self.decrypt(&name, ciphertext)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| StoreError)?;
        let key = if text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
            let key = tor_keymgr::ssh_key::PrivateKey::from_openssh(text).map_err(|_| StoreError)?;
            SshKeyData::try_from_keypair_data(key.key_data().clone())?
        } else {
            let key = tor_keymgr::ssh_key::PublicKey::from_openssh(text).map_err(|_| StoreError)?;
            SshKeyData::try_from_key_data(key.key_data().clone())?
        };
        if KeystoreItemType::from(key.key_type()?) != *kind {
            return Err(StoreError.into());
        }
        Ok(Some(key.into_erased()?))
    }

    fn insert(&self, key: &dyn EncodableItem, spec: &dyn KeySpecifier) -> tor_keymgr::Result<()> {
        let KeystoreItem::Key(key) = key.as_keystore_item()? else {
            return Err(StoreError.into());
        };
        let name = Self::name(spec, &key.key_type()?.into())?;
        let plaintext = Zeroizing::new(key.to_openssh_string("")?);
        if plaintext.len() > 16356 {
            return Err(StoreError.into());
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref().as_ref()).map_err(|_| StoreError)?;
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let aad = Self::aad(&name)?;
        let encrypted = cipher.encrypt(&Nonce::from(nonce), Payload {
            msg: plaintext.as_bytes(), aad: &aad,
        }).map_err(|_| StoreError)?;
        let mut records = self.records.try_lock().map_err(|_| StoreError)?;
        if records.len() >= 128 && !records.contains_key(&name) {
            return Err(StoreError.into());
        }
        records.insert(name, [nonce.as_slice(), encrypted.as_slice()].concat());
        Ok(())
    }

    fn remove(&self, spec: &dyn KeySpecifier, kind: &KeystoreItemType) -> tor_keymgr::Result<Option<()>> {
        let name = Self::name(spec, kind)?;
        let mut records = self.records.try_lock().map_err(|_| StoreError)?;
        Ok(records.remove(&name).map(|_| ()))
    }

    fn list(&self) -> tor_keymgr::Result<Vec<tor_keymgr::KeystoreEntryResult<KeystoreEntry<'_>>>> {
        let records = self.records.try_lock().map_err(|_| StoreError)?;
        records.keys().map(|(path, kind)| {
            let path: ArtiPath = path.parse().map_err(|_| StoreError)?;
            let kind = KeystoreItemType::from(kind.as_str());
            Ok(Ok(KeystoreEntry::new(
                path.clone().into(), kind.clone(), &self.id, RawEntryId::Ephemeral((path, kind)),
            )))
        }).collect()
    }

    fn raw_entry_id(&self, _raw_id: &str) -> tor_keymgr::Result<RawEntryId> {
        Err(StoreError.into())
    }

    fn remove_unchecked(&self, _entry_id: &RawEntryId) -> tor_keymgr::Result<()> {
        Err(StoreError.into())
    }
}
