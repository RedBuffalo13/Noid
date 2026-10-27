//! Модуль безопасности
//!
//! Содержит компоненты для:
//! - KDF (Argon2id)
//! - Шифрование (AES-256-GCM)
//! - ECDH для DHT
//! - Kill PIN
//! - Forward Secrecy (X3DH + Double Ratchet)

pub mod cipher;
pub mod domains;
pub mod field_cipher;
pub mod identity_sig;
pub mod room_crypto;
pub mod key_store;
pub mod manager;
pub mod x3dh;
pub mod ratchet;
pub mod ratchet_session;
pub mod secure_delete;
pub mod audit_log;
#[cfg(test)]
mod manager_test;
#[cfg(test)]
mod security_test;
#[cfg(test)]
mod audit_log_test;
#[cfg(test)]
mod secure_delete_test;
#[cfg(test)]
mod ratchet_session_test;

pub use cipher::is_low_order_x25519;
pub use cipher::DHTCipher;
pub use domains::derive_domain_key;
pub use cipher::DHTEncryptedMessage;
pub use manager::SecurityManager;
pub use x3dh::{X3DH, PrekeyBundle, InitialMessage};
pub use ratchet::{DoubleRatchet, RatchetMessage, RatchetHeader};
pub use ratchet_session::RatchetSessionManager;
pub use secure_delete::{secure_delete, secure_delete_dir};
pub use audit_log::AuditLog;
