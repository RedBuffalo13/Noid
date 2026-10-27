//! ECDH шифрование для DHT сообщений
//!
//! Использует X25519 для производной ключа и HKDF для генерации 32-байтного ключа
//! Затем AES-256-GCM для шифрования сообщений

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{x25519, PublicKey, StaticSecret};

/// Структура зашифрованного сообщения для DHT
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DHTEncryptedMessage {
    /// Случайная nonce (12 байт)
    pub nonce: [u8; 12],
    /// Зашифрованный ciphertext
    pub ciphertext: Vec<u8>,
    /// Публичный ключ отправителя (32 байта)
    pub sender_public_key: Vec<u8>,
}

/// Менеджер ECDH шифрования
pub struct DHTCipher {
    /// Приватный ключ для ECDH
    private_key: StaticSecret,
    /// Публичный ключ для экспорта
    public_key: PublicKey,
}

impl DHTCipher {
    /// Генерация новой пары ключей
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let private_key = StaticSecret::random_from_rng(&mut rng);
        let public_key = PublicKey::from(&private_key);
        
        Self {
            private_key,
            public_key,
        }
    }
    
    /// Создание из существующих ключей
    pub fn from_keys(private_key: StaticSecret, public_key: PublicKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    /// Phase 2.2: Получить приватный ключ как байты для персистентного хранения
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    /// Phase 2.2: Восстановление из сохранённых байтов приватного ключа
    pub fn from_private_bytes(key_bytes: &[u8]) -> Result<Self, DHTCipherError> {
        if key_bytes.len() != 32 {
            return Err(DHTCipherError::InvalidPublicKey);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(key_bytes);
        // Check for all-zero key (invalid)
        if bytes == [0u8; 32] {
            return Err(DHTCipherError::InvalidPublicKey);
        }
        let private_key = StaticSecret::from(bytes);
        let public_key = PublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }
    
    /// Получить публичный ключ для экспорта
    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }
    
    /// Получить публичный ключ как байты
    pub fn get_public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }
    
    /// Производная общего секрета используя ECDH
    /// 
    /// # Аргументы
    /// * `other_public_key` - публичный ключ другой стороны
    /// 
    /// # Возвращает
    /// 32-байтный общий секрет через HKDF
    pub fn derive_shared_secret(&self, other_public_key: &PublicKey) -> Result<[u8; 32], DHTCipherError> {
        // ECDH: private_key * other_public_key
        let shared_secret = x25519(
            self.private_key.to_bytes(),
            other_public_key.to_bytes(),
        );

        // Contributory check: a low-order public key forces the shared
        // secret to all-zero — reject instead of deriving a known key.
        if shared_secret == [0u8; 32] {
            return Err(DHTCipherError::NonContributory);
        }

        // HKDF для получения 32-байтного ключа
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(b"noid-dht-message", &mut key)
            .map_err(|_| DHTCipherError::InvalidKeyLength)?;

        Ok(key)
    }
    
    /// Шифрование сообщения для получателя
    /// 
    /// # Аргументы
    /// * `plaintext` - исходное сообщение
    /// * `recipient_public_key` - публичный ключ получателя
    /// 
    /// # Возвращает
    /// Зашифрованное сообщение с nonce и публичным ключом отправителя
    pub fn encrypt_for_recipient(
        &self,
        plaintext: &[u8],
        recipient_public_key: &PublicKey,
    ) -> Result<DHTEncryptedMessage, DHTCipherError> {
        // Производная общего секрета
        let shared_secret = self.derive_shared_secret(recipient_public_key)?;
        
        // Генерация случайной nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        
        // Шифрование AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&shared_secret)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)?;
        
        Ok(DHTEncryptedMessage {
            nonce: nonce_bytes,
            ciphertext,
            sender_public_key: self.get_public_key_bytes().to_vec(),
        })
    }
    
    /// Дешифрование сообщения
    /// 
    /// # Аргументы
    /// * `encrypted` - зашифрованное сообщение
    /// 
    /// # Возвращает
    /// Исходное сообщение
    pub fn decrypt_message(
        &self,
        encrypted: &DHTEncryptedMessage,
    ) -> Result<Vec<u8>, DHTCipherError> {
        // Извлечение публичного ключа отправителя
        let sender_public_key: PublicKey = {
            let bytes: [u8; 32] = encrypted.sender_public_key
                .as_slice()
                .try_into()
                .map_err(|_| DHTCipherError::InvalidPublicKey)?;
            PublicKey::from(bytes)
        };

        // Производная общего секрета (private_key * sender_public_key)
        let shared_secret = self.derive_shared_secret(&sender_public_key)?;

        // Дешифрование AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&shared_secret)?;
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher.decrypt(nonce, encrypted.ciphertext.as_slice())?;

        Ok(plaintext)
    }
}

/// Reject low-order X25519 public keys received over the wire: every such
/// point forces the shared secret to all-zero regardless of our key, making
/// any "E2EE" built on it publicly computable (audit S2/S22).
/// Implementation: DH with a throwaway secret — a non-contributory result
/// means the peer's point is low-order.
pub fn is_low_order_x25519(key_bytes: &[u8; 32]) -> bool {
    let peer = PublicKey::from(*key_bytes);
    let probe = StaticSecret::random_from_rng(rand::thread_rng());
    !probe.diffie_hellman(&peer).was_contributory()
}

impl Default for DHTCipher {
    fn default() -> Self {
        Self::new()
    }
}

/// Ошибки шифрования
#[derive(Debug, thiserror::Error)]
pub enum DHTCipherError {
    #[error("Invalid public key format")]
    InvalidPublicKey,

    #[error("Non-contributory X25519 output — low-order public key rejected")]
    NonContributory,
    
    #[error("Invalid key length")]
    InvalidKeyLength,
    
    #[error("Encryption error")]
    Encryption,
    
    #[error("Decryption error")]
    Decryption,
}

impl From<sha2::digest::InvalidLength> for DHTCipherError {
    fn from(_: sha2::digest::InvalidLength) -> Self {
        DHTCipherError::InvalidKeyLength
    }
}

impl From<aes_gcm::Error> for DHTCipherError {
    fn from(_: aes_gcm::Error) -> Self {
        DHTCipherError::Encryption
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_decryption() {
        // Алиса создаёт пару ключей
        let alice = DHTCipher::new();
        
        // Боб создаёт пару ключей
        let bob = DHTCipher::new();
        
        // Исходное сообщение
        let plaintext = b"Hello, Bob! This is a secret message.";
        
        // Алиса шифрует для Боба (использует публичный ключ Боба)
        let encrypted = alice.encrypt_for_recipient(plaintext, bob.get_public_key())
            .expect("Шифрование должно работать");
        
        // Боб дешифрует (использует свой приватный ключ)
        let decrypted = bob.decrypt_message(&encrypted)
            .expect("Дешифрование должно работать");
        
        // Проверка
        assert_eq!(plaintext.to_vec(), decrypted);
    }
    
    #[test]
    fn test_shared_secret() {
        // Алиса и Боб создают пары ключей
        let alice = DHTCipher::new();
        let bob = DHTCipher::new();
        
        // Обе стороны должны получить одинаковый общий секрет
        let alice_secret = alice.derive_shared_secret(bob.get_public_key()).unwrap();
        let bob_secret = bob.derive_shared_secret(alice.get_public_key()).unwrap();

        assert_eq!(alice_secret, bob_secret);
    }
}
