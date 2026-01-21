//! M2M Protocol error types with epistemic classification.
//!
//! # Epistemic Error Taxonomy
//!
//! This module organizes errors by their epistemic nature - what they tell us
//! about the state of knowledge at the time of failure. This classification
//! helps developers understand:
//!
//! 1. **Whether the error was predictable** (and thus should be handled gracefully)
//! 2. **What remediation is appropriate** (retry, fail-fast, degrade gracefully)
//! 3. **Where defensive code is needed** (validation boundaries, I/O edges)
//!
//! ## Categories
//!
//! ### B_i Falsified (Belief Proven Wrong)
//!
//! The caller held a belief about validity that was proven false at runtime.
//! These are "expected" errors in the sense that the system was designed to
//! detect and report them. Examples:
//!
//! - Invalid input format (caller believed input was valid)
//! - Session not established (caller believed session was ready)
//! - Capability mismatch (caller believed peers were compatible)
//!
//! **Handling**: Validate early, return descriptive errors, don't retry.
//!
//! ### I^B (Bounded Ignorance Materialized)
//!
//! The system could not know the outcome at compile time - it depends on
//! external state (network, filesystem, RNG, upstream services). These errors
//! represent the inherent uncertainty of distributed systems.
//!
//! - Network errors (connectivity is I^B until we try)
//! - Upstream service errors (availability is I^B)
//! - RNG failures (entropy availability is I^B)
//!
//! **Handling**: Timeouts, retries with backoff, circuit breakers, fallbacks.
//!
//! ### K_i Violated (Invariant Broken)
//!
//! A known invariant that "should never happen" was violated. These indicate
//! bugs in the code or corruption. They are NOT expected in normal operation.
//!
//! - Internal state corruption
//! - Logic errors (unreachable code reached)
//!
//! **Handling**: Log extensively, fail fast, alert operators.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use m2m::error::{M2MError, Result};
//!
//! fn process_message(session: &Session, data: &[u8]) -> Result<Response> {
//!     // B_i: Caller believes session is established
//!     if !session.is_established() {
//!         return Err(M2MError::SessionNotEstablished);
//!     }
//!     
//!     // B_i: Caller believes data is valid JSON
//!     let parsed = serde_json::from_slice(data)?;
//!     
//!     // I^B: Network availability unknown until we try
//!     let response = send_upstream(parsed).await?;
//!     
//!     Ok(response)
//! }
//! ```

use thiserror::Error;

use crate::codec::m2m::crypto::CryptoError;

/// M2M Protocol errors, organized by epistemic category.
///
/// See module documentation for the full epistemic taxonomy.
#[derive(Error, Debug)]
pub enum M2MError {
    // ═══════════════════════════════════════════════════════════════════════
    // B_i FALSIFIED — Caller's belief about validity proven wrong
    // ═══════════════════════════════════════════════════════════════════════
    //
    // These errors indicate the caller made an assumption that was incorrect.
    // They are "expected" errors - the system is designed to detect them.
    // Handling: Validate inputs, return clear errors, don't retry.
    // ═══════════════════════════════════════════════════════════════════════
    /// Compression failed due to invalid input or unsupported content.
    ///
    /// **Epistemic**: B_i falsified — caller believed content was compressible.
    #[error("Compression error: {0}")]
    Compression(String),

    /// Decompression failed due to corrupted or invalid wire format.
    ///
    /// **Epistemic**: B_i falsified — caller believed data was valid M2M format.
    #[error("Decompression error: {0}")]
    Decompression(String),

    /// Codec identifier not recognized or not supported.
    ///
    /// **Epistemic**: B_i falsified — caller believed codec was available.
    #[error("Invalid codec: {0}")]
    InvalidCodec(String),

    /// Protocol state machine violation.
    ///
    /// **Epistemic**: B_i falsified — caller believed operation was valid
    /// in current state.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Session handshake failed to agree on capabilities.
    ///
    /// **Epistemic**: B_i falsified — caller believed negotiation would succeed.
    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),

    /// Operation requires an established session, but session is not ready.
    ///
    /// **Epistemic**: B_i falsified — caller believed session was established.
    #[error("Session not established")]
    SessionNotEstablished,

    /// Session has exceeded its timeout duration.
    ///
    /// **Epistemic**: B_i falsified — caller believed session was still valid.
    #[error("Session expired")]
    SessionExpired,

    /// Message does not conform to expected format.
    ///
    /// **Epistemic**: B_i falsified — caller believed message was well-formed.
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Peers have incompatible capabilities for the requested operation.
    ///
    /// **Epistemic**: B_i falsified — caller believed capabilities were compatible.
    #[error("Capability mismatch: {0}")]
    CapabilityMismatch(String),

    /// ML model was expected to be loaded but isn't.
    ///
    /// **Epistemic**: B_i falsified — caller believed model was available.
    #[error("Model not loaded: {0}")]
    ModelNotLoaded(String),

    /// Requested model not found in the registry.
    ///
    /// **Epistemic**: B_i falsified — caller believed model existed.
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    /// Tokenizer operation failed (invalid encoding, unknown token).
    ///
    /// **Epistemic**: B_i falsified — caller believed input was tokenizable.
    #[error("Tokenizer error: {0}")]
    Tokenizer(String),

    /// Configuration is invalid or missing required values.
    ///
    /// **Epistemic**: B_i falsified — caller believed config was valid.
    #[error("Config error: {0}")]
    Config(String),

    /// JSON serialization/deserialization failed.
    ///
    /// **Epistemic**: B_i falsified — caller believed data was valid JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // ═══════════════════════════════════════════════════════════════════════
    // I^B — Bounded Ignorance (External State Unknown Until Runtime)
    // ═══════════════════════════════════════════════════════════════════════
    //
    // These errors stem from inherent uncertainty about external systems.
    // We cannot know network state, service availability, or RNG entropy
    // at compile time - it's bounded ignorance that materializes at runtime.
    // Handling: Timeouts, retries, circuit breakers, graceful degradation.
    // ═══════════════════════════════════════════════════════════════════════
    /// Network operation failed (connection, timeout, DNS).
    ///
    /// **Epistemic**: I^B materialized — network availability was unknown
    /// until we attempted the operation.
    ///
    /// **Handling**: Retry with exponential backoff, circuit breaker.
    #[error("Network error: {0}")]
    Network(String),

    /// Upstream service returned an error or is unavailable.
    ///
    /// **Epistemic**: I^B materialized — upstream health was unknown
    /// until we made the request.
    ///
    /// **Handling**: Retry, failover to alternate upstream, degrade gracefully.
    #[error("Upstream error: {0}")]
    Upstream(String),

    /// Server-side processing error.
    ///
    /// **Epistemic**: I^B materialized — server state was unknown to client.
    #[error("Server error: {0}")]
    Server(String),

    /// ML inference failed during execution.
    ///
    /// **Epistemic**: I^B materialized — model execution success depends on
    /// input characteristics and runtime state.
    #[error("Inference error: {0}")]
    Inference(String),

    /// Failed to load ML model from filesystem or network.
    ///
    /// **Epistemic**: I^B materialized — model file availability unknown
    /// until load attempted.
    #[error("Model load error: {0}")]
    ModelLoad(String),

    /// I/O operation failed.
    ///
    /// **Epistemic**: I^B materialized — filesystem/resource state unknown
    /// until operation attempted.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation failed (key derivation, encryption, auth).
    ///
    /// **Epistemic**: Mixed — may be B_i (invalid key) or I^B (RNG failure).
    /// The inner `CryptoError` provides specific classification.
    ///
    /// This variant preserves the full error chain via `#[source]`,
    /// enabling tools like `anyhow` to display complete context.
    #[error("Crypto error: {0}")]
    Crypto(#[source] CryptoError),

    // ═══════════════════════════════════════════════════════════════════════
    // SECURITY — Policy Violations (Special Category)
    // ═══════════════════════════════════════════════════════════════════════
    //
    // Security errors are epistemically B_i (content was believed safe),
    // but they warrant special handling due to their nature. They should
    // NOT be retried and may require alerting.
    // ═══════════════════════════════════════════════════════════════════════
    /// Security scanner detected a threat in content.
    ///
    /// **Epistemic**: B_i falsified — content was believed to be safe.
    ///
    /// **Handling**: Do NOT retry, log for security audit, consider blocking source.
    #[error("Security threat detected: {threat_type}")]
    SecurityThreat {
        /// Type of threat detected (e.g., "prompt_injection", "jailbreak").
        threat_type: String,
        /// Detection confidence score (0.0-1.0).
        confidence: f32,
    },

    /// Content blocked by security policy.
    ///
    /// **Epistemic**: B_i falsified — content was believed to comply with policy.
    ///
    /// **Handling**: Do NOT retry, inform user of policy violation.
    #[error("Content blocked: {0}")]
    ContentBlocked(String),
}

/// Result type alias for M2M operations.
pub type Result<T> = std::result::Result<T, M2MError>;

// ═══════════════════════════════════════════════════════════════════════════
// From Implementations
// ═══════════════════════════════════════════════════════════════════════════

impl From<CryptoError> for M2MError {
    fn from(err: CryptoError) -> Self {
        M2MError::Crypto(err)
    }
}

impl From<reqwest::Error> for M2MError {
    fn from(err: reqwest::Error) -> Self {
        M2MError::Network(err.to_string())
    }
}

impl From<toml::de::Error> for M2MError {
    fn from(err: toml::de::Error) -> Self {
        M2MError::Config(err.to_string())
    }
}

impl From<base64::DecodeError> for M2MError {
    fn from(err: base64::DecodeError) -> Self {
        M2MError::Decompression(format!("Base64 decode error: {err}"))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Helper Methods
// ═══════════════════════════════════════════════════════════════════════════

impl M2MError {
    /// Returns `true` if this error is retryable.
    ///
    /// I^B errors (network, upstream, inference) are generally retryable.
    /// B_i errors (validation failures) are NOT retryable without changes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// match operation() {
    ///     Err(e) if e.is_retryable() => retry_with_backoff(operation),
    ///     Err(e) => return Err(e),
    ///     Ok(v) => v,
    /// }
    /// ```
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            M2MError::Network(_)
                | M2MError::Upstream(_)
                | M2MError::Server(_)
                | M2MError::Inference(_)
                | M2MError::Io(_)
        )
    }

    /// Returns `true` if this error is security-related.
    ///
    /// Security errors should NOT be retried and may warrant special logging.
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            M2MError::SecurityThreat { .. } | M2MError::ContentBlocked(_)
        )
    }

    /// Returns `true` if this error indicates bounded ignorance (I^B).
    ///
    /// These errors stem from external system state that was unknown
    /// at compile time.
    pub fn is_bounded_ignorance(&self) -> bool {
        matches!(
            self,
            M2MError::Network(_)
                | M2MError::Upstream(_)
                | M2MError::Server(_)
                | M2MError::Inference(_)
                | M2MError::ModelLoad(_)
                | M2MError::Io(_)
                | M2MError::Crypto(_)
        )
    }

    /// Returns `true` if this error indicates a falsified belief (B_i).
    ///
    /// These errors indicate the caller made an incorrect assumption
    /// about input validity or system state.
    pub fn is_belief_falsified(&self) -> bool {
        !self.is_bounded_ignorance()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retryable_classification() {
        // I^B errors are retryable
        assert!(M2MError::Network("timeout".to_string()).is_retryable());
        assert!(M2MError::Upstream("503".to_string()).is_retryable());
        assert!(M2MError::Server("overloaded".to_string()).is_retryable());

        // B_i errors are NOT retryable
        assert!(!M2MError::SessionNotEstablished.is_retryable());
        assert!(!M2MError::InvalidMessage("bad format".to_string()).is_retryable());
        assert!(!M2MError::Decompression("corrupt".to_string()).is_retryable());
    }

    #[test]
    fn test_security_classification() {
        assert!(M2MError::SecurityThreat {
            threat_type: "injection".to_string(),
            confidence: 0.95
        }
        .is_security_error());

        assert!(M2MError::ContentBlocked("policy".to_string()).is_security_error());

        // Non-security errors
        assert!(!M2MError::Network("timeout".to_string()).is_security_error());
    }

    #[test]
    fn test_bounded_ignorance_classification() {
        // I^B errors
        assert!(M2MError::Network("timeout".to_string()).is_bounded_ignorance());
        assert!(M2MError::Upstream("503".to_string()).is_bounded_ignorance());
        assert!(M2MError::ModelLoad("not found".to_string()).is_bounded_ignorance());

        // B_i errors (NOT bounded ignorance)
        assert!(!M2MError::SessionNotEstablished.is_bounded_ignorance());
        assert!(!M2MError::InvalidCodec("unknown".to_string()).is_bounded_ignorance());
    }

    #[test]
    fn test_belief_falsified_is_inverse() {
        let network_err = M2MError::Network("timeout".to_string());
        let session_err = M2MError::SessionNotEstablished;

        // These should be inverses
        assert_eq!(
            network_err.is_bounded_ignorance(),
            !network_err.is_belief_falsified()
        );
        assert_eq!(
            session_err.is_bounded_ignorance(),
            !session_err.is_belief_falsified()
        );
    }
}
