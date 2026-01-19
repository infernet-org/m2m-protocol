//! X25519 key exchange for cross-owner M2M communication.
//!
//! Allows two agents from different organizations to establish a shared
//! secret without prior key distribution.

#![allow(missing_docs)]

use super::keyring::KeyMaterial;
use thiserror::Error;

/// Errors from key exchange operations
#[derive(Debug, Error)]
pub enum KeyExchangeError {
    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    GenerationFailed(String),
}

/// X25519 public key (32 bytes)
#[derive(Clone)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, KeyExchangeError> {
        if slice.len() != 32 {
            return Err(KeyExchangeError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey([{}...])", hex_encode(&self.0[..4]))
    }
}

/// X25519 key pair (private + public)
pub struct KeyPair {
    /// Secret key
    #[cfg(feature = "crypto")]
    secret: x25519_dalek::StaticSecret,
    #[cfg(not(feature = "crypto"))]
    secret: [u8; 32],

    /// Public key
    public: PublicKey,
}

impl KeyPair {
    /// Generate a new random key pair
    #[cfg(feature = "crypto")]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);

        Self {
            secret,
            public: PublicKey::from_bytes(public.to_bytes()),
        }
    }

    /// Generate a new key pair (fallback without crypto)
    #[cfg(not(feature = "crypto"))]
    pub fn generate() -> Self {
        // Deterministic "random" for testing - NOT SECURE
        let secret = [0x42u8; 32];
        let mut public = [0u8; 32];
        for (i, byte) in public.iter_mut().enumerate() {
            *byte = secret[i] ^ 0xFF;
        }

        Self {
            secret,
            public: PublicKey::from_bytes(public),
        }
    }

    /// Create from a secret key (32 bytes)
    #[cfg(feature = "crypto")]
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

        let secret = StaticSecret::from(secret_bytes);
        let public = X25519Public::from(&secret);

        Self {
            secret,
            public: PublicKey::from_bytes(public.to_bytes()),
        }
    }

    /// Create from a secret key (fallback without crypto)
    #[cfg(not(feature = "crypto"))]
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        let mut public = [0u8; 32];
        for (i, byte) in public.iter_mut().enumerate() {
            *byte = secret_bytes[i] ^ 0xFF;
        }

        Self {
            secret: secret_bytes,
            public: PublicKey::from_bytes(public),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Perform Diffie-Hellman key exchange
    #[cfg(feature = "crypto")]
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> KeyMaterial {
        use x25519_dalek::PublicKey as X25519Public;

        let peer = X25519Public::from(*peer_public.as_bytes());
        let shared = self.secret.diffie_hellman(&peer);

        KeyMaterial::new(shared.as_bytes().to_vec())
    }

    /// Perform Diffie-Hellman (fallback without crypto)
    #[cfg(not(feature = "crypto"))]
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> KeyMaterial {
        // XOR "DH" for testing - NOT SECURE
        let mut shared = [0u8; 32];
        for (i, byte) in shared.iter_mut().enumerate() {
            *byte = self.secret[i] ^ peer_public.as_bytes()[i];
        }
        KeyMaterial::new(shared.to_vec())
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Key exchange helper for M2M sessions
#[derive(Debug)]
pub struct KeyExchange {
    /// Our key pair
    key_pair: KeyPair,
    /// Peer's public key (once received)
    peer_public: Option<PublicKey>,
    /// Derived shared secret (once computed)
    shared_secret: Option<KeyMaterial>,
}

impl KeyExchange {
    /// Create a new key exchange instance
    pub fn new() -> Self {
        Self {
            key_pair: KeyPair::generate(),
            peer_public: None,
            shared_secret: None,
        }
    }

    /// Create from an existing key pair
    pub fn with_key_pair(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            peer_public: None,
            shared_secret: None,
        }
    }

    /// Get our public key to send to peer
    pub fn public_key(&self) -> &PublicKey {
        self.key_pair.public_key()
    }

    /// Set the peer's public key and compute shared secret
    pub fn set_peer_public(&mut self, peer_public: PublicKey) {
        let shared = self.key_pair.diffie_hellman(&peer_public);
        self.peer_public = Some(peer_public);
        self.shared_secret = Some(shared);
    }

    /// Get the shared secret (None if peer public key not yet set)
    pub fn shared_secret(&self) -> Option<&KeyMaterial> {
        self.shared_secret.as_ref()
    }

    /// Derive a session key from the shared secret
    #[cfg(feature = "crypto")]
    pub fn derive_session_key(&self, context: &str) -> Option<KeyMaterial> {
        self.shared_secret
            .as_ref()
            .and_then(|secret| secret.derive(context.as_bytes(), 32).ok())
    }

    /// Derive a session key (fallback without crypto)
    #[cfg(not(feature = "crypto"))]
    pub fn derive_session_key(&self, _context: &str) -> Option<KeyMaterial> {
        self.shared_secret.clone()
    }

    /// Check if key exchange is complete
    pub fn is_complete(&self) -> bool {
        self.shared_secret.is_some()
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple hex encoder
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{:02x}", b);
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_diffie_hellman_symmetric() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        // Alice computes shared secret with Bob's public key
        let alice_shared = alice.diffie_hellman(bob.public_key());

        // Bob computes shared secret with Alice's public key
        let bob_shared = bob.diffie_hellman(alice.public_key());

        // Both should derive the same shared secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_key_exchange_flow() {
        // Alice initiates
        let mut alice = KeyExchange::new();
        let alice_public = alice.public_key().clone();

        // Bob responds
        let mut bob = KeyExchange::new();
        let bob_public = bob.public_key().clone();

        // Exchange public keys
        alice.set_peer_public(bob_public);
        bob.set_peer_public(alice_public);

        // Both should have the same shared secret
        assert!(alice.is_complete());
        assert!(bob.is_complete());

        let alice_secret = alice.shared_secret().unwrap();
        let bob_secret = bob.shared_secret().unwrap();
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_session_key_derivation() {
        let mut alice = KeyExchange::new();
        let mut bob = KeyExchange::new();

        alice.set_peer_public(bob.public_key().clone());
        bob.set_peer_public(alice.public_key().clone());

        // Derive session keys with same context
        let alice_session = alice.derive_session_key("m2m-session-v1").unwrap();
        let bob_session = bob.derive_session_key("m2m-session-v1").unwrap();

        assert_eq!(alice_session.as_bytes(), bob_session.as_bytes());

        // Different context = different key
        let alice_other = alice.derive_session_key("other-context").unwrap();
        assert_ne!(alice_session.as_bytes(), alice_other.as_bytes());
    }

    #[test]
    fn test_public_key_from_slice() {
        let bytes = [0x42u8; 32];
        let pk = PublicKey::from_slice(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);

        // Wrong size should fail
        let result = PublicKey::from_slice(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_pair_from_secret() {
        let secret = [0x42u8; 32];
        let kp1 = KeyPair::from_secret(secret);
        let kp2 = KeyPair::from_secret(secret);

        // Same secret should produce same public key
        assert_eq!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    }
}
