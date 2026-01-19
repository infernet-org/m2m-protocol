//! M2M Wire Format v1 - Binary protocol with 100% JSON fidelity.
//!
//! The M2M wire format provides efficient binary encoding while preserving
//! the complete original JSON payload. Headers are extracted for routing
//! without decompression.
//!
//! # Wire Format Structure
//!
//! ```text
//! #M2M|1|<fixed_header:20><routing_header><payload>
//!
//! Fixed Header (20 bytes):
//!   [header_len: 2]    Total header length
//!   [schema: 1]        Message type (request/response/stream)
//!   [security: 1]      Security mode (none/hmac/aead)
//!   [flags: 4]         Feature flags
//!   [reserved: 12]     Future use
//!
//! Routing Header (variable):
//!   [model_len: 1][model: utf8]
//!   [msg_count: varint]
//!   [roles: packed bits]
//!   [content_hint: varint]
//!   ...additional fields based on flags
//!
//! Payload:
//!   [payload_len: 4]
//!   [crc32: 4]
//!   [compressed_json: N]  (Brotli or raw based on flag)
//! ```
//!
//! # Security Modes
//!
//! The wire format supports optional cryptographic security:
//!
//! - `SecurityMode::None` - No authentication or encryption (default)
//! - `SecurityMode::Hmac` - HMAC-SHA256 authentication (integrity only)
//! - `SecurityMode::Aead` - ChaCha20-Poly1305 encryption (confidentiality + integrity)
//!
//! Enable the `crypto` feature for cryptographic operations:
//!
//! ```toml
//! m2m-core = { version = "0.4", features = ["crypto"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use m2m::codec::m2m::{M2MCodec, SecurityMode};
//!
//! let codec = M2MCodec::new();
//! let json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
//!
//! // Encode to wire format
//! let frame = codec.encode(json, SecurityMode::None)?;
//!
//! // Decode back to JSON (100% fidelity)
//! let decoded = codec.decode(&frame)?;
//! assert_eq!(json, decoded);
//! ```

mod cost;
pub mod crypto;
mod flags;
mod frame;
mod header;
mod varint;

pub use cost::{estimate_cost, ModelPricing};
pub use flags::{CommonFlags, RequestFlags, ResponseFlags};
pub use frame::{M2MCodec, M2MFrame};
pub use header::{FinishReason, FixedHeader, ResponseHeader, RoutingHeader, Schema, SecurityMode};
pub use varint::{read_varint, write_varint};

/// M2M wire format prefix
pub const M2M_PREFIX: &str = "#M2M|1|";

/// M2M wire format version
pub const M2M_VERSION: u8 = 1;

/// Minimum payload size to apply compression (bytes)
/// Below this threshold, raw JSON is more efficient
pub const COMPRESSION_THRESHOLD: usize = 100;

/// Check if content is M2M v1 format
pub fn is_m2m_format(content: &str) -> bool {
    content.starts_with(M2M_PREFIX)
}

/// Check if content starts with any M2M prefix
pub fn is_any_m2m_format(content: &str) -> bool {
    content.starts_with("#M2M|")
}
