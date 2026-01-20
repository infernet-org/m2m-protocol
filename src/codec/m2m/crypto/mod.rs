//! Cryptographic security for M2M wire format.
//!
//! This module provides optional cryptographic security for M2M frames:
//!
//! - **HMAC-SHA256**: Message authentication (integrity only)
//! - **ChaCha20-Poly1305 AEAD**: Authenticated encryption (confidentiality + integrity)
//! - **HKDF key derivation**: Derive session keys from master secrets
//! - **X25519 key exchange**: Establish shared secrets between agents
//! - **Hierarchical Key Derivation**: Multi-agent key management from shared master
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
//! Three key management approaches are supported:
//!
//! ## Same-Owner M2M (HKDF Hierarchy)
//!
//! When agents belong to the same organization, use hierarchical key derivation:
//!
//! ```text
//! Organization Master Secret
//!     │
//!     ├─[HKDF]─► "m2m/v1/{org}/agent-001" ─► Agent 001 Key
//!     ├─[HKDF]─► "m2m/v1/{org}/agent-002" ─► Agent 002 Key
//!     └─[HKDF]─► "m2m/v1/{org}/session/agent-001:agent-002/sess-id" ─► Session Key
//! ```
//!
//! All agents can derive session keys without explicit key exchange:
//!
//! ```ignore
//! use m2m::codec::m2m::crypto::{KeyHierarchy, AgentId};
//!
//! let hierarchy = KeyHierarchy::new(master_secret, "org-acme");
//! let session = hierarchy.derive_session_key(&agent_a, &agent_b, "session-123")?;
//! ```
//!
//! ## Same-Owner M2M (Simple HKDF)
//!
//! For simpler cases without hierarchy:
//!
//! ```text
//! master_secret -> HKDF-Expand -> session_key
//! ```
//!
//! ## Cross-Owner M2M (X25519 + HKDF)
//!
//! When agents need to establish a shared secret across organizations:
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
//!
//! # Test Vectors
//!
//! This implementation is validated against:
//! - RFC 5869 HKDF test vectors (Appendix A)
//! - M2M-specific test vectors for external compatibility
//!
//! See `keyring::rfc5869_tests` and `hierarchy::tests` for details.

mod aead;
mod hmac_auth;
mod keyring;

#[cfg(feature = "crypto")]
mod exchange;

#[cfg(feature = "crypto")]
mod hierarchy;

pub use aead::{AeadCipher, AeadError};
pub use hmac_auth::{HmacAuth, HmacError};
pub use keyring::{KeyId, KeyMaterial, Keyring, KeyringError};

#[cfg(feature = "crypto")]
pub use exchange::{KeyExchange, KeyPair};

#[cfg(feature = "crypto")]
pub use hierarchy::{AgentId, AgentKeyContext, KeyHierarchy, KeyPurpose};

/// Nonce size for ChaCha20-Poly1305 (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size for ChaCha20-Poly1305 (128 bits)
pub const AEAD_TAG_SIZE: usize = 16;

/// HMAC-SHA256 tag size (256 bits)
pub const HMAC_TAG_SIZE: usize = 32;

/// Minimum key size (256 bits)
pub const MIN_KEY_SIZE: usize = 32;

/// Security context for frame operations.
///
/// # Nonce Generation Strategy
///
/// This implementation uses **fully random 96-bit nonces** for AEAD encryption.
/// This approach is chosen over counter-based nonces because:
///
/// 1. **Stateless**: No need to persist counter state across restarts
/// 2. **Safe by default**: Counter-based nonces reset on restart → nonce reuse vulnerability
/// 3. **Sufficient entropy**: 96-bit random nonces have birthday bound at 2^48 messages
///
/// For typical M2M sessions (thousands to millions of messages), the collision
/// probability is negligible (~2^-49 for 2^24 messages).
///
/// # Security Considerations
///
/// - Nonces are generated using the system CSPRNG (`rand::thread_rng()`)
/// - Each encryption operation gets a fresh random nonce
/// - Nonce is prepended to ciphertext, so decryption doesn't need external state
/// - If you need deterministic nonces for testing, use `next_nonce_deterministic()`
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Key material for this context
    key: KeyMaterial,
    /// Counter for deterministic nonce generation (testing only)
    #[cfg(test)]
    test_nonce_counter: u64,
}

impl SecurityContext {
    /// Create a new security context with the given key
    pub fn new(key: KeyMaterial) -> Self {
        Self {
            key,
            #[cfg(test)]
            test_nonce_counter: 0,
        }
    }

    /// Get the key material
    pub fn key(&self) -> &KeyMaterial {
        &self.key
    }

    /// Generate a cryptographically secure random nonce for AEAD.
    ///
    /// Uses the system CSPRNG to generate a fresh 96-bit (12-byte) nonce
    /// for each encryption operation. This is the recommended approach
    /// for ChaCha20-Poly1305 as it avoids nonce-reuse vulnerabilities
    /// that can occur with counter-based schemes after process restarts.
    ///
    /// # Panics
    ///
    /// Panics if the system CSPRNG fails (should never happen on supported platforms).
    #[cfg(feature = "crypto")]
    pub fn next_nonce(&mut self) -> [u8; NONCE_SIZE] {
        use rand::RngCore;

        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Generate a deterministic nonce for testing purposes only.
    ///
    /// **WARNING**: Do not use in production! Counter-based nonces without
    /// persistence will cause nonce reuse after process restarts, which
    /// completely breaks ChaCha20-Poly1305 security.
    ///
    /// This method is only available in test builds.
    #[cfg(test)]
    pub fn next_nonce_deterministic(&mut self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&self.test_nonce_counter.to_le_bytes());
        self.test_nonce_counter = self.test_nonce_counter.wrapping_add(1);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_context_deterministic_nonce() {
        let key = KeyMaterial::new(vec![0u8; 32]);
        let mut ctx = SecurityContext::new(key);

        let nonce1 = ctx.next_nonce_deterministic();
        let nonce2 = ctx.next_nonce_deterministic();
        let nonce3 = ctx.next_nonce_deterministic();

        // Deterministic nonces should be unique and sequential
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);

        // Counter should increment (first 8 bytes)
        assert_eq!(nonce1[0], 0);
        assert_eq!(nonce2[0], 1);
        assert_eq!(nonce3[0], 2);
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_security_context_random_nonce_uniqueness() {
        let key = KeyMaterial::new(vec![0u8; 32]);
        let mut ctx = SecurityContext::new(key);

        // Generate many nonces and verify they're all unique
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..1000 {
            let nonce = ctx.next_nonce();
            assert!(
                nonces.insert(nonce),
                "Random nonce collision detected (extremely unlikely)"
            );
        }
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_security_context_random_nonce_entropy() {
        let key = KeyMaterial::new(vec![0u8; 32]);
        let mut ctx = SecurityContext::new(key);

        // Verify nonces aren't all zeros or trivial patterns
        let nonce = ctx.next_nonce();
        let zeros: [u8; NONCE_SIZE] = [0u8; NONCE_SIZE];
        assert_ne!(nonce, zeros, "Random nonce should not be all zeros");

        // Check that multiple bytes have non-zero values (basic entropy check)
        let non_zero_count = nonce.iter().filter(|&&b| b != 0).count();
        assert!(
            non_zero_count >= 3,
            "Random nonce should have reasonable entropy, got {} non-zero bytes",
            non_zero_count
        );
    }
}
