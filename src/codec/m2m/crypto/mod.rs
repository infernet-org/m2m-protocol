//! Cryptographic security for M2M wire format.
//!
//! This module provides optional cryptographic security for M2M frames:
//!
//! - **HMAC-SHA256**: Message authentication (integrity only)
//! - **ChaCha20-Poly1305 AEAD**: Authenticated encryption (confidentiality + integrity)
//! - **HKDF key derivation**: Derive session keys from master secrets
//! - **X25519 key exchange**: Establish shared secrets between agents
//!
//! # Security Modes
//!
//! The M2M wire format supports three security modes:
//!
//! 1. `SecurityMode::None` - No cryptographic protection (default)
//! 2. `SecurityMode::Hmac` - HMAC-SHA256 authentication tag appended
//! 3. `SecurityMode::Aead` - Full AEAD encryption with ChaCha20-Poly1305
//!
//! # Key Management
//!
//! Two key derivation approaches are supported:
//!
//! ## Same-Owner M2M (HKDF)
//!
//! When both agents share a master secret (e.g., same organization):
//!
//! ```text
//! master_secret -> HKDF-Expand -> session_key
//! ```
//!
//! ## Cross-Owner M2M (X25519 + HKDF)
//!
//! When agents need to establish a shared secret:
//!
//! ```text
//! Agent A: (sk_a, pk_a) = X25519::generate()
//! Agent B: (sk_b, pk_b) = X25519::generate()
//!
//! shared_secret = X25519(sk_a, pk_b) = X25519(sk_b, pk_a)
//! session_key = HKDF(shared_secret, "m2m-session-v1")
//! ```
//!
//! # Wire Format
//!
//! When security is enabled, the frame structure changes:
//!
//! ```text
//! HMAC mode:
//!   #M2M|1|<headers><payload><hmac_tag:32>
//!
//! AEAD mode:
//!   #M2M|1|<headers><nonce:12><ciphertext><auth_tag:16>
//! ```
//!
//! # Feature Flag
//!
//! This module requires the `crypto` feature:
//!
//! ```toml
//! m2m-core = { version = "0.4", features = ["crypto"] }
//! ```

mod aead;
mod hmac_auth;
mod keyring;

#[cfg(feature = "crypto")]
mod exchange;

pub use aead::{AeadCipher, AeadError};
pub use hmac_auth::{HmacAuth, HmacError};
pub use keyring::{KeyId, KeyMaterial, Keyring, KeyringError};

#[cfg(feature = "crypto")]
pub use exchange::{KeyExchange, KeyPair};

/// Nonce size for ChaCha20-Poly1305 (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size for ChaCha20-Poly1305 (128 bits)
pub const AEAD_TAG_SIZE: usize = 16;

/// HMAC-SHA256 tag size (256 bits)
pub const HMAC_TAG_SIZE: usize = 32;

/// Minimum key size (256 bits)
pub const MIN_KEY_SIZE: usize = 32;

/// Security context for frame operations
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Key material for this context
    key: KeyMaterial,
    /// Counter for nonce generation (AEAD mode)
    nonce_counter: u64,
}

impl SecurityContext {
    /// Create a new security context with the given key
    pub fn new(key: KeyMaterial) -> Self {
        Self {
            key,
            nonce_counter: 0,
        }
    }

    /// Get the key material
    pub fn key(&self) -> &KeyMaterial {
        &self.key
    }

    /// Generate a unique nonce for AEAD
    ///
    /// Nonce format: [counter:8][random:4]
    /// This ensures uniqueness even with clock skew
    #[cfg(feature = "crypto")]
    pub fn next_nonce(&mut self) -> [u8; NONCE_SIZE] {
        use rand::RngCore;

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&self.nonce_counter.to_le_bytes());

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce[8..12]);

        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }

    /// Generate a nonce without random component (for testing/deterministic use)
    pub fn next_nonce_deterministic(&mut self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_context_nonce_uniqueness() {
        let key = KeyMaterial::new(vec![0u8; 32]);
        let mut ctx = SecurityContext::new(key);

        let nonce1 = ctx.next_nonce_deterministic();
        let nonce2 = ctx.next_nonce_deterministic();
        let nonce3 = ctx.next_nonce_deterministic();

        // Nonces should be unique
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);

        // Counter should increment
        assert_eq!(nonce1[0], 0);
        assert_eq!(nonce2[0], 1);
        assert_eq!(nonce3[0], 2);
    }
}
