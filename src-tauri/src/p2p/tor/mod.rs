//! Embedded Tor/onion connectivity. Optional `embedded-tor` feature; all
//! types compile without it so strict-mode policy can be built generically.
pub mod mode;
pub mod status;
pub mod config;
pub mod handle;
pub mod onion_addr;
#[cfg(feature = "embedded-tor")]
pub mod store_error;
#[cfg(feature = "embedded-tor")]
pub mod identity;
#[cfg(feature = "embedded-tor")]
pub mod encrypted_keystore;
#[cfg(feature = "embedded-tor")]
pub mod supervisor;
#[cfg(feature = "embedded-tor")]
pub mod transport;
#[cfg(feature = "embedded-tor")]
pub mod accept_loop;
#[cfg(all(test, feature = "embedded-tor"))]
mod tor_keystore_test;
