//! Centralized input validation for Tauri command boundaries.
//! Every string arriving from the frontend is untrusted — validate length
//! and shape here before it reaches the DB, the DHT, or a dial.

pub mod bounded;
pub mod peer_id;

pub use bounded::bounded_str;
pub use peer_id::parse_peer_id;

#[cfg(test)]
mod validation_test;
