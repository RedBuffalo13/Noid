//! META-01: bucket padding for ratchet frames. Wire observers see only
//! bucket sizes (256 B / 1 KB / 4 KB / 16 KB / 64 KB), never the exact
//! plaintext length — a 1-char "ok" and a 240-char paragraph produce the
//! same 256 B frame. Payloads > 64 KB (file chunks) round up to whole
//! 64 KB multiples.
//!
//! Frame format inside AEAD: `PAD1 || u32be len || payload || zeros`.
//! Legacy peers decrypt to raw plaintext — `unpad_frame` is a no-op
//! unless the magic matches, so mixed-version stays compatible.

const MAGIC: &[u8; 4] = b"PAD1";
const BUCKETS: [usize; 5] = [256, 1024, 4096, 16384, 65536];
const OVERHEAD: usize = MAGIC.len() + 4;

/// Pad `payload` into the smallest bucket that fits `overhead + len`.
pub fn pad_frame(payload: &[u8]) -> Vec<u8> {
    let need = OVERHEAD + payload.len();
    let target = BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= need)
        .unwrap_or_else(|| need.div_ceil(65536) * 65536);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(target, 0);
    out
}

/// Strip the padding envelope; `None` when the magic is absent.
pub fn unpad_frame(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < OVERHEAD || &buf[..4] != MAGIC {
        return None;
    }
    let len = u32::from_be_bytes(buf[4..8].try_into().ok()?) as usize;
    if OVERHEAD + len > buf.len() {
        return None;
    }
    Some(buf[OVERHEAD..OVERHEAD + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_roundtrip() {
        for payload_len in [0usize, 1, 200, 700, 3000, 15000, 60000, 70000] {
            let payload = vec![0xABu8; payload_len];
            let padded = pad_frame(&payload);
            let bucket = BUCKETS
                .iter()
                .find(|b| **b >= padded.len())
                .copied()
                .unwrap_or(padded.len());
            assert_eq!(padded.len() % 256, 0);
            assert!(padded.len() <= bucket.max(65536));
            assert_eq!(unpad_frame(&padded).unwrap(), payload);
        }
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        assert!(unpad_frame(b"hello").is_none());
    }
}
