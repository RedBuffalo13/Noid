use super::{SocketAddr, StunNatKind};

/// Classify already validated samples from distinct reflectors.
pub(crate) fn classify_stun_samples(
    samples: &[(SocketAddr, SocketAddr)],
) -> Option<(SocketAddr, StunNatKind)> {
    let first = samples.first()?.1;
    let nat_kind = if samples.len() >= 2 {
        let second = samples[1].1;
        if first == second {
            StunNatKind::Cone
        } else if first.ip() != second.ip() {
            StunNatKind::AddressDependent
        } else {
            let delta = (second.port() as i32) - (first.port() as i32);
            StunNatKind::Symmetric { delta }
        }
    } else {
        StunNatKind::SingleSample
    };
    Some((first, nat_kind))
}
