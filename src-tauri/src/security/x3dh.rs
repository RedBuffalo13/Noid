use anyhow::{anyhow, Result};
use x25519_dalek::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct X3DH {
    identity_secret: StaticSecret,
    identity_public: PublicKey,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrekeyBundle {
    pub identity_public: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub one_time_prekey_public: Option<Vec<u8>>,
    /// S1: OTPK pool — advertising a single key let one stale X3DHInit
    /// burn the only OTPK and fail-close every later handshake until the
    /// next re-login. Initiators pick randomly from the pool; the legacy
    /// single field stays for old peers (mirrors pool[0]).
    #[serde(default)]
    pub one_time_prekeys: Vec<Vec<u8>>,
    /// Owner's libp2p peer id — binds the bundle to a network identity so a
    /// malicious DHT peer cannot swap in their own keys (MITM).
    #[serde(default)]
    pub owner_peer_id: Option<String>,
    /// Ed25519 signature over `prekey_signing_payload` by the owner's
    /// libp2p identity key. Unsigned/invalid bundles are rejected.
    #[serde(default)]
    pub identity_signature: Option<Vec<u8>>,
    /// D17: signed generation timestamp (RFC3339). A signed-but-stale
    /// bundle can be replayed over the current record in the LWW store;
    /// the timestamp lets initiators bound how old a bundle they will
    /// initiate against.
    #[serde(default)]
    pub generated_at: Option<String>,
}

/// Canonical bytes covered by `identity_signature`.
pub fn prekey_signing_payload(bundle: &PrekeyBundle) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(b"noid-prekey-v1");
    if let Some(owner) = &bundle.owner_peer_id {
        v.extend_from_slice(owner.as_bytes());
    }
    v.extend_from_slice(&bundle.identity_public);
    v.extend_from_slice(&bundle.signed_prekey_public);
    if let Some(otpk) = &bundle.one_time_prekey_public {
        v.extend_from_slice(otpk);
    }
    for otpk in &bundle.one_time_prekeys {
        v.extend_from_slice(otpk);
    }
    if let Some(ts) = &bundle.generated_at {
        v.extend_from_slice(ts.as_bytes());
    }
    v
}

/// Verify the bundle's owner signature. Unsigned or invalid bundles are
/// hostile — always reject, never fall back to trusting them.
pub fn verify_prekey_bundle(bundle: &PrekeyBundle) -> bool {
    match (&bundle.owner_peer_id, &bundle.identity_signature) {
        (Some(owner), Some(sig)) => {
            crate::security::identity_sig::verify_payload(
                owner,
                &prekey_signing_payload(bundle),
                sig,
            )
        }
        _ => false,
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InitialMessage {
    pub identity_public: Vec<u8>,
    pub ephemeral_public: Vec<u8>,
    pub one_time_prekey_id: Option<Vec<u8>>,
}

impl Default for X3DH {
    fn default() -> Self {
        Self::new()
    }
}

impl X3DH {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let identity_secret = StaticSecret::random_from_rng(&mut rng);
        let identity_public = PublicKey::from(&identity_secret);
        Self {
            identity_secret,
            identity_public,
        }
    }

    pub fn from_secret(secret: StaticSecret) -> Self {
        let identity_public = PublicKey::from(&secret);
        Self {
            identity_secret: secret,
            identity_public,
        }
    }

    /// Phase A.2: Get identity secret bytes for persistent storage.
    pub fn identity_secret_bytes(&self) -> Vec<u8> {
        self.identity_secret.to_bytes().to_vec()
    }

    pub fn identity_public(&self) -> PublicKey {
        self.identity_public
    }

    pub fn identity_public_bytes(&self) -> Vec<u8> {
        self.identity_public.to_bytes().to_vec()
    }

    pub fn generate_prekey_bundle(&self) -> (PrekeyBundle, StaticSecret, Option<StaticSecret>) {
        let mut rng = rand::thread_rng();
        let signed_prekey_secret = StaticSecret::random_from_rng(&mut rng);
        let signed_prekey_public = PublicKey::from(&signed_prekey_secret);

        let one_time_prekey_secret = StaticSecret::random_from_rng(&mut rng);
        let one_time_prekey_public = PublicKey::from(&one_time_prekey_secret);

        let bundle = PrekeyBundle {
            identity_public: self.identity_public.to_bytes().to_vec(),
            signed_prekey_public: signed_prekey_public.to_bytes().to_vec(),
            one_time_prekey_public: Some(one_time_prekey_public.to_bytes().to_vec()),
            one_time_prekeys: vec![one_time_prekey_public.to_bytes().to_vec()],
            owner_peer_id: None,
            identity_signature: None,
            generated_at: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        };

        (bundle, signed_prekey_secret, Some(one_time_prekey_secret))
    }

    pub fn initiate(
        &self,
        bundle: &PrekeyBundle,
    ) -> Result<(InitialMessage, [u8; 32])> {
        let mut rng = rand::thread_rng();

        let their_identity = parse_public_key(&bundle.identity_public)?;
        let their_signed_prekey = parse_public_key(&bundle.signed_prekey_public)?;

        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let dh1 = dh_checked(&ephemeral_secret, &their_identity)?;
        let dh2 = dh_checked(&self.identity_secret, &their_signed_prekey)?;
        let dh3 = dh_checked(&ephemeral_secret, &their_signed_prekey)?;

        let mut combined = Vec::new();
        combined.extend_from_slice(&dh1);
        combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3);

        // S1: pick a random OTPK from the pool (spreads consumption across
        // keys instead of all initiators racing on the same one), falling
        // back to the legacy single-key field.
        let chosen_otpk = if !bundle.one_time_prekeys.is_empty() {
            use rand::seq::SliceRandom;
            bundle.one_time_prekeys.choose(&mut rng).cloned()
        } else {
            bundle.one_time_prekey_public.clone()
        };
        let one_time_prekey_id = if let Some(otpk) = &chosen_otpk {
            let their_one_time = parse_public_key(otpk)?;
            let dh4 = dh_checked(&ephemeral_secret, &their_one_time)?;
            combined.extend_from_slice(&dh4);
            Some(otpk.clone())
        } else {
            None
        };

        let shared_secret = derive_key(&combined, b"noid-x3dh-v1")?;

        let initial_msg = InitialMessage {
            identity_public: self.identity_public.to_bytes().to_vec(),
            ephemeral_public: ephemeral_public.to_bytes().to_vec(),
            one_time_prekey_id: one_time_prekey_id.clone(),
        };

        Ok((initial_msg, shared_secret))
    }

    pub fn receive(
        &self,
        initial_msg: &InitialMessage,
        signed_prekey_secret: &StaticSecret,
        one_time_prekey_secret: Option<&StaticSecret>,
    ) -> Result<[u8; 32]> {
        let their_identity = parse_public_key(&initial_msg.identity_public)?;
        let their_ephemeral = parse_public_key(&initial_msg.ephemeral_public)?;

        let dh1 = dh_checked(&self.identity_secret, &their_ephemeral)?;
        let dh2 = dh_checked(signed_prekey_secret, &their_identity)?;
        let dh3 = dh_checked(signed_prekey_secret, &their_ephemeral)?;

        let mut combined = Vec::new();
        combined.extend_from_slice(&dh1);
        combined.extend_from_slice(&dh2);
        combined.extend_from_slice(&dh3);

        if let Some(otpk_secret) = one_time_prekey_secret {
            let dh4 = dh_checked(otpk_secret, &their_ephemeral)?;
            combined.extend_from_slice(&dh4);
        }

        let shared_secret = derive_key(&combined, b"noid-x3dh-v1")?;

        Ok(shared_secret)
    }
}

fn parse_public_key(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 32 {
        return Err(anyhow!("Invalid public key length: {}", bytes.len()));
    }
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("Key conversion failed"))?;
    Ok(PublicKey::from(arr))
}

/// Contributory-checked X25519: a low-order public key forces the shared
/// secret to all-zero and would hand every observer a known key — reject
/// instead of deriving it (audit: missing contributory validation).
fn dh_checked(secret: &StaticSecret, public: &PublicKey) -> Result<[u8; 32]> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(anyhow!(
            "Non-contributory X25519 output — low-order public key rejected"
        ));
    }
    Ok(*shared.as_bytes())
}

fn derive_key(input: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, input);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .map_err(|e| anyhow!("HKDF error: {}", e))?;
    Ok(okm)
}

impl Drop for X3DH {
    fn drop(&mut self) {
        // StaticSecret implements Zeroize on drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x3dh_key_agreement() {
        let alice = X3DH::new();
        let bob = X3DH::new();

        let (bundle, bob_signed_prekey, bob_one_time_prekey) = bob.generate_prekey_bundle();

        let (initial_msg, alice_shared) = alice.initiate(&bundle).unwrap();
        let bob_shared = bob
            .receive(&initial_msg, &bob_signed_prekey, bob_one_time_prekey.as_ref())
            .unwrap();

        assert_eq!(alice_shared, bob_shared);
    }
}
