//! Embedded Tor/onion connectivity. Always compiled — Tor is a product
//! feature; the only off-switch is the `NOID_DISABLE_TOR` runtime env.
pub mod mode;
pub mod status;
pub mod config;
pub mod handle;
pub mod onion_addr;
pub mod store_error;
pub mod identity;
pub mod encrypted_keystore;
pub mod supervisor;
pub mod transport;
pub mod accept_loop;
pub mod self_probe;
#[cfg(test)]
mod tor_keystore_test;
