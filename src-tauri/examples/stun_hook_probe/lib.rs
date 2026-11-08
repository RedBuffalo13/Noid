#[cfg(test)]
mod binding_response;
#[cfg(test)]
mod different_public_ips;
#[cfg(test)]
mod fresh_probe_transactions;
#[cfg(test)]
mod listener_registry_lifetime;
#[cfg(test)]
mod rejects_nonreflector_response;
#[cfg(test)]
mod rejects_truncated_response;
#[cfg(test)]
mod rejects_unaligned_response;
#[path = "../../../vendor/libp2p-quic/src/stun_hook.rs"]
pub mod stun_hook;
#[cfg(test)]
mod valid_response;
