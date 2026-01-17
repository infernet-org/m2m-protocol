//! M2M Protocol error types.

use thiserror::Error;

/// M2M Protocol errors
#[derive(Error, Debug)]
pub enum M2MError {
    // === Codec Errors ===
    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Invalid codec: {0}")]
    InvalidCodec(String),

    // === Protocol Errors ===
    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Negotiation failed: {0}")]
    NegotiationFailed(String),

    #[error("Session not established")]
    SessionNotEstablished,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Capability mismatch: {0}")]
    CapabilityMismatch(String),

    // === Inference Errors ===
    #[error("Model not loaded: {0}")]
    ModelNotLoaded(String),

    #[error("Inference error: {0}")]
    Inference(String),

    #[error("Model load error: {0}")]
    ModelLoad(String),

    // === Security Errors ===
    #[error("Security threat detected: {threat_type}")]
    SecurityThreat {
        threat_type: String,
        confidence: f32,
    },

    #[error("Content blocked: {0}")]
    ContentBlocked(String),

    // === Network Errors ===
    #[error("Network error: {0}")]
    Network(String),

    #[error("Upstream error: {0}")]
    Upstream(String),

    // === Server Errors ===
    #[error("Server error: {0}")]
    Server(String),

    // === Configuration Errors ===
    #[error("Config error: {0}")]
    Config(String),

    #[error("Model not found: {0}")]
    ModelNotFound(String),

    // === Tokenizer Errors ===
    #[error("Tokenizer error: {0}")]
    Tokenizer(String),

    // === Standard Errors ===
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for M2M operations
pub type Result<T> = std::result::Result<T, M2MError>;

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
