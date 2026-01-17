//! Multi-codec compression engine for M2M Protocol.
//!
//! This module provides the core compression functionality with multiple
//! algorithms optimized for different content types and sizes.
//!
//! # Algorithms
//!
//! | Algorithm    | Wire Prefix          | Best For                        |
//! |--------------|----------------------|---------------------------------|
//! | [`Token`]    | `#T1\|`              | LLM API JSON (messages, roles)  |
//! | [`Brotli`]   | `#M2M[v3.0]\|DATA:`  | Large repetitive content (>1KB) |
//! | [`Dictionary`]| `#M2M\|`            | JSON with common patterns       |
//! | [`None`]     | (passthrough)        | Small content (<100 bytes)      |
//!
//! # Token Compression
//!
//! The Token algorithm uses domain-specific abbreviation tables to reduce
//! common LLM API keys and values. This is optimized for token efficiency
//! rather than pure byte reduction.
//!
//! **Abbreviations include:**
//! - Keys: `messages` → `m`, `content` → `c`, `role` → `r`, `model` → `M`
//! - Roles: `user` → `u`, `assistant` → `a`, `system` → `s`
//! - Models: `gpt-4o` → `4o`, `claude-3-opus` → `c3o`
//!
//! # Wire Format Examples
//!
//! ```text
//! // Token compressed
//! #T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
//!
//! // Brotli compressed (base64 encoded)
//! #M2M[v3.0]|DATA:G5gAAI...
//!
//! // Dictionary compressed
//! #M2M|<pattern_encoded_content>
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use m2m_core::codec::{CodecEngine, Algorithm};
//!
//! let engine = CodecEngine::new();
//!
//! // Auto-select best algorithm
//! let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
//! let (result, algo) = engine.compress_auto(content).unwrap();
//! println!("Algorithm: {:?}, Ratio: {:.1}%", algo, result.byte_ratio() * 100.0);
//!
//! // Use specific algorithm
//! let result = engine.compress(content, Algorithm::Token).unwrap();
//!
//! // Decompress (auto-detects from wire prefix)
//! let original = engine.decompress(&result.data).unwrap();
//! ```
//!
//! # Algorithm Selection Heuristics
//!
//! The [`CodecEngine::compress_auto`] method selects algorithms based on:
//!
//! 1. **Content analysis**: Detects LLM API patterns (messages, roles)
//! 2. **Size thresholds**: Small content bypasses compression
//! 3. **Repetition ratio**: High repetition favors Brotli
//! 4. **ML routing**: Optional Hydra model for intelligent selection
//!
//! [`Token`]: Algorithm::Token
//! [`Brotli`]: Algorithm::Brotli
//! [`Dictionary`]: Algorithm::Dictionary
//! [`None`]: Algorithm::None

mod algorithm;
mod brotli;
mod dictionary;
mod engine;
mod streaming;
mod tables;
mod token;

pub use algorithm::{Algorithm, CompressionResult};
pub use brotli::BrotliCodec;
pub use dictionary::DictionaryCodec;
pub use engine::{CodecEngine, ContentAnalysis};
pub use streaming::{SseEvent, StreamingCodec, StreamingDecompressor, StreamingStats};
pub use tables::{KEY_ABBREV, KEY_EXPAND, MODEL_ABBREV, MODEL_EXPAND, ROLE_ABBREV, ROLE_EXPAND};
pub use token::TokenCodec;

/// Check if content is in M2M compressed format
pub fn is_m2m_format(content: &str) -> bool {
    content.starts_with("#M2M") || content.starts_with("#T1|")
}

/// Detect the compression algorithm used in a message
pub fn detect_algorithm(content: &str) -> Option<Algorithm> {
    if content.starts_with("#T1|") {
        Some(Algorithm::Token)
    } else if content.starts_with("#M2M[v3.0]|") {
        Some(Algorithm::Brotli)
    } else if content.starts_with("#M2M[v1.0]|") || content.starts_with("#M2M|") {
        Some(Algorithm::Dictionary)
    } else {
        None
    }
}
