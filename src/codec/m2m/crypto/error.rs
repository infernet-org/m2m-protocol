//! Unified cryptographic error type for M2M.
//!
//! This module provides a single error type that aggregates all crypto-related
//! errors, enabling proper error chain preservation through the `#[source]`
//! attribute.
//!
//! # Epistemic Classification
//!
//! Crypto errors fall into two categories:
//!
//! ## B_i Falsified (Belief Proven Wrong)
//!
//! Most crypto errors indicate a caller's belief was incorrect:
//!
//! | Error | Falsified Belief |
//! |-------|------------------|
//! | `Key` | Key material was valid |
//! | `Keyring` | Key operation would succeed |
//! | `Aead` | Data was properly encrypted/formatted |
//! | `Hmac` | Authentication tag was valid |
//! | `Exchange` | Key exchange parameters were correct |
//! | `Id` | Identifier was well-formed |
//!
//! **Handling**: Validate inputs, don't retry without fixing the issue.
//!
//! ## I^B (Bounded Ignorance)
//!
//! One error type represents inherent runtime uncertainty:
//!
//! | Error | Unknown State |
//! |-------|---------------|
//! | `Nonce` | System RNG availability |
//!
//! **Handling**: May retry, but RNG failure is usually catastrophic.

use thiserror::Error;

use super::aead::AeadError;
use super::hmac_auth::HmacError;
use super::keyring::{KeyError, KeyringError};
use super::NonceError;

#[cfg(feature = "crypto")]
use super::exchange::KeyExchangeError;

#[cfg(feature = "crypto")]
use super::hierarchy::IdError;

/// Unified error type for all cryptographic operations.
///
/// This type preserves the full error chain via `#[source]`, enabling
/// debugging tools to display the complete error context.
///
/// See module documentation for epistemic classification of each variant.
///
/// # Example
///
/// ```ignore
/// use m2m::codec::m2m::crypto::{CryptoError, AeadError};
///
/// fn encrypt_data(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
///     // AeadError automatically converts to CryptoError
///     let cipher = AeadCipher::new(key)?;
///     cipher.encrypt(nonce, aad, data).map_err(CryptoError::from)
/// }
/// ```
#[derive(Debug, Error)]
pub enum CryptoError {
    // ═══════════════════════════════════════════════════════════════════════
    // B_i FALSIFIED — Caller's belief about crypto validity proven wrong
    // ═══════════════════════════════════════════════════════════════════════
    /// AEAD encryption/decryption error.
    ///
    /// **Epistemic**: B_i falsified — data was not properly encrypted/formatted.
    #[error("AEAD: {0}")]
    Aead(#[source] AeadError),

    /// HMAC authentication error.
    ///
    /// **Epistemic**: B_i falsified — authentication tag did not verify.
    #[error("HMAC: {0}")]
    Hmac(#[source] HmacError),

    /// Key material error (empty, too short, invalid).
    ///
    /// **Epistemic**: B_i falsified — key material was not valid.
    #[error("Key: {0}")]
    Key(#[source] KeyError),

    /// Keyring operation error.
    ///
    /// **Epistemic**: B_i falsified — keyring operation preconditions not met.
    #[error("Keyring: {0}")]
    Keyring(#[source] KeyringError),

    /// Key exchange error (X25519).
    ///
    /// **Epistemic**: B_i falsified — key exchange parameters were invalid.
    #[cfg(feature = "crypto")]
    #[error("Key exchange: {0}")]
    Exchange(#[source] KeyExchangeError),

    /// ID validation error (AgentId, OrgId).
    ///
    /// **Epistemic**: B_i falsified — identifier format was invalid.
    #[cfg(feature = "crypto")]
    #[error("ID validation: {0}")]
    Id(#[source] IdError),

    // ═══════════════════════════════════════════════════════════════════════
    // I^B — Bounded Ignorance (RNG state unknown until runtime)
    // ═══════════════════════════════════════════════════════════════════════
    /// Nonce generation error (RNG failure).
    ///
    /// **Epistemic**: I^B materialized — system RNG availability was unknown
    /// until generation was attempted.
    ///
    /// **Note**: RNG failure is rare but catastrophic. If this occurs,
    /// the system entropy pool may be exhausted or unavailable.
    #[error("Nonce: {0}")]
    Nonce(#[source] NonceError),
}

// ============================================================================
// From implementations for automatic conversion
// ============================================================================

impl From<AeadError> for CryptoError {
    fn from(err: AeadError) -> Self {
        CryptoError::Aead(err)
    }
}

impl From<HmacError> for CryptoError {
    fn from(err: HmacError) -> Self {
        CryptoError::Hmac(err)
    }
}

impl From<KeyError> for CryptoError {
    fn from(err: KeyError) -> Self {
        CryptoError::Key(err)
    }
}

impl From<KeyringError> for CryptoError {
    fn from(err: KeyringError) -> Self {
        CryptoError::Keyring(err)
    }
}

impl From<NonceError> for CryptoError {
    fn from(err: NonceError) -> Self {
        CryptoError::Nonce(err)
    }
}

#[cfg(feature = "crypto")]
impl From<KeyExchangeError> for CryptoError {
    fn from(err: KeyExchangeError) -> Self {
        CryptoError::Exchange(err)
    }
}

#[cfg(feature = "crypto")]
impl From<IdError> for CryptoError {
    fn from(err: IdError) -> Self {
        CryptoError::Id(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_error_conversion() {
        let aead_err = AeadError::DataTooShort;
        let crypto_err: CryptoError = aead_err.into();
        assert!(matches!(crypto_err, CryptoError::Aead(_)));
        assert!(crypto_err.to_string().contains("AEAD"));
    }

    #[test]
    fn test_hmac_error_conversion() {
        let hmac_err = HmacError::VerificationFailed;
        let crypto_err: CryptoError = hmac_err.into();
        assert!(matches!(crypto_err, CryptoError::Hmac(_)));
        assert!(crypto_err.to_string().contains("HMAC"));
    }

    #[test]
    fn test_key_error_conversion() {
        let key_err = KeyError::Empty;
        let crypto_err: CryptoError = key_err.into();
        assert!(matches!(crypto_err, CryptoError::Key(_)));
    }

    #[test]
    fn test_nonce_error_conversion() {
        let nonce_err = NonceError::RngFailure("test".to_string());
        let crypto_err: CryptoError = nonce_err.into();
        assert!(matches!(crypto_err, CryptoError::Nonce(_)));
    }

    #[test]
    fn test_error_source_chain() {
        use std::error::Error;

        let aead_err = AeadError::DecryptionFailed("bad tag".to_string());
        let crypto_err: CryptoError = aead_err.into();

        // Verify source chain is preserved
        let source = crypto_err.source();
        assert!(source.is_some());
        assert!(source.unwrap().to_string().contains("bad tag"));
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_id_error_conversion() {
        let id_err = IdError::Empty { kind: "Agent" };
        let crypto_err: CryptoError = id_err.into();
        assert!(matches!(crypto_err, CryptoError::Id(_)));
    }
}
