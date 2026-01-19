//! Multi-codec compression engine for M2M Protocol.
//!
//! This module provides the core compression functionality with multiple
//! algorithms optimized for different content types and sizes.
//!
//! # Algorithms
//!
//! | Algorithm    | Wire Prefix          | Best For                        |
//! |--------------|----------------------|---------------------------------|
//! | [`M2M`]      | `#M2M\|1\|`          | All content (100% JSON fidelity)|
//! | [`TokenNative`] | `#TK\|`           | Legacy token-based compression  |
//! | [`Brotli`]   | `#M2M[v3.0]\|DATA:`  | Large repetitive content (>1KB) |
//! | [`None`]     | (passthrough)        | Small content (<100 bytes)      |
//!
//! # M2M Wire Format v1
//!
//! The new M2M wire format provides:
//! - **100% JSON fidelity**: Original JSON is perfectly reconstructed
//! - **Header extraction**: Routing info available without decompression
//! - **Cost estimation**: Token counts and cost in headers
//! - **Optional encryption**: HMAC or AEAD security modes
//!
//! # Wire Format Examples
//!
//! ```text
//! // M2M v1 format (default)
//! #M2M|1|<fixed_header><routing_header><compressed_payload>
//!
//! // Legacy formats (still supported for decoding)
//! #TK|C|<varint_tokens>
//! #M2M[v3.0]|DATA:<base64_brotli>
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use m2m::codec::{CodecEngine, Algorithm};
//! use m2m::codec::m2m::M2MCodec;
//!
//! // New M2M codec (recommended)
//! let m2m_codec = M2MCodec::new();
//! let encoded = m2m_codec.encode(json)?;
//! let decoded = m2m_codec.decode(&encoded)?; // 100% fidelity
//!
//! // Or use CodecEngine for auto-selection
//! let engine = CodecEngine::new();
//! let result = engine.compress(content, Algorithm::M2M)?;
//! let original = engine.decompress(&result.data)?;
//! ```
//!
//! [`M2M`]: Algorithm::M2M
//! [`TokenNative`]: Algorithm::TokenNative
//! [`Brotli`]: Algorithm::Brotli
//! [`None`]: Algorithm::None

mod algorithm;
mod brotli;
mod dictionary;
mod engine;
pub mod m2m;
mod m3;
mod streaming;
mod tables;
mod token;
mod token_native;

pub use algorithm::{Algorithm, CompressionResult};
pub use brotli::BrotliCodec;
pub use dictionary::DictionaryCodec;
pub use engine::{CodecEngine, ContentAnalysis};
pub use m2m::{M2MCodec, M2MFrame};
pub use m3::{M3ChatRequest, M3Codec, M3Message, M3_PREFIX};
pub use streaming::{
    SseEvent, StreamingCodec, StreamingDecompressor, StreamingMode, StreamingStats,
};
pub use tables::{
    is_default_value, KEY_ABBREV, KEY_EXPAND, MODEL_ABBREV, MODEL_EXPAND, PATTERN_ABBREV,
    PATTERN_EXPAND, ROLE_ABBREV, ROLE_EXPAND,
};
pub use token::TokenCodec;
pub use token_native::TokenNativeCodec;

/// Check if content is in M2M compressed format
pub fn is_m2m_format(content: &str) -> bool {
    content.starts_with("#M2M|1|")  // M2M v1 format (default)
        || content.starts_with("#TK|")  // TokenNative
        || content.starts_with("#M2M[v3.0]|") // Brotli
}

/// Detect the compression algorithm used in a message
pub fn detect_algorithm(content: &str) -> Option<Algorithm> {
    Algorithm::from_prefix(content)
}
