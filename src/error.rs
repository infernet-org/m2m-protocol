//! M2M Protocol error types.
//!
//! # Epistemic Error Classification
//!
//! M2M errors follow epistemic principles:
//!
//! - **B_i falsified**: Most errors indicate a runtime belief was proven wrong
//!   (invalid input, network failure, etc.)
//! - **I^B handling**: Errors from bounded ignorance (RNG availability, network state)
//!   are wrapped as `Result` rather than panicking
//!
//! The `Crypto` variant preserves the full error chain via `#[source]`,
//! enabling debugging tools to display complete error context.

use thiserror::Error;

use crate::codec::m2m::crypto::CryptoError;

/// M2M Protocol errors.
#[derive(Error, Debug)]
pub enum M2MError {
    /// Compression operation failed.
    #[error("Compression error: {0}")]
    Compression(String),

    /// Decompression operation failed.
    #[error("Decompression error: {0}")]
    Decompression(String),

    /// Invalid or unsupported codec.
    #[error("Invalid codec: {0}")]
    InvalidCodec(String),

    /// Protocol-level error.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Capability negotiation failed.
    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),

    /// Operation requires an established session.
    #[error("Session not established")]
    SessionNotEstablished,

    /// Session has timed out.
    #[error("Session expired")]
    SessionExpired,

    /// Invalid message format.
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Capability mismatch between peers.
    #[error("Capability mismatch: {0}")]
    CapabilityMismatch(String),

    /// ML model not loaded.
    #[error("Model not loaded: {0}")]
    ModelNotLoaded(String),

    /// ML inference error.
    #[error("Inference error: {0}")]
    Inference(String),

    /// Failed to load ML model.
    #[error("Model load error: {0}")]
    ModelLoad(String),

    /// Security threat detected in content.
    #[error("Security threat detected: {threat_type}")]
    SecurityThreat {
        /// Type of threat detected.
        threat_type: String,
        /// Confidence score (0.0-1.0).
        confidence: f32,
    },

    /// Content blocked by security policy.
    #[error("Content blocked: {0}")]
    ContentBlocked(String),

    /// Network communication error.
    #[error("Network error: {0}")]
    Network(String),

    /// Upstream service error.
    #[error("Upstream error: {0}")]
    Upstream(String),

    /// Server-side error.
    #[error("Server error: {0}")]
    Server(String),

    /// Configuration error.
    #[error("Config error: {0}")]
    Config(String),

    /// Model not found in registry.
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    /// Tokenizer error.
    #[error("Tokenizer error: {0}")]
    Tokenizer(String),

    /// Cryptographic operation failed.
    ///
    /// This variant preserves the full error chain via `#[source]`,
    /// enabling tools like `anyhow` to display the complete context.
    ///
    /// # Epistemic Classification
    ///
    /// Crypto errors represent B_i falsified (invalid keys, auth failures)
    /// or I^B handling (RNG failures).
    #[error("Crypto error: {0}")]
    Crypto(#[source] CryptoError),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for M2M operations
pub type Result<T> = std::result::Result<T, M2MError>;

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
