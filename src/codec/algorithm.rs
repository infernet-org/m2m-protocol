//! Compression algorithm types and results.

use serde::{Deserialize, Serialize};

/// Available compression algorithms
///
/// M2M Protocol v0.4.0 supports three compression algorithms:
/// - **M2M**: Default, 100% JSON fidelity with extracted routing headers
/// - **TokenNative**: Token ID transmission for maximum compression  
/// - **Brotli**: High-ratio compression for large content (>1KB)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// No compression (passthrough)
    None,
    /// M2M Wire Format v1 (default, 100% JSON fidelity)
    ///
    /// Binary protocol with header extraction for routing and Brotli-compressed
    /// JSON payload. Provides 100% fidelity reconstruction of original JSON.
    ///
    /// Wire format: `#M2M|1|<fixed_header><routing_header><payload>`
    #[default]
    M2M,
    /// Token-native compression (transmit token IDs directly)
    ///
    /// This algorithm tokenizes content using the negotiated tokenizer and
    /// transmits token IDs with VarInt encoding. Achieves 50-60% compression
    /// by leveraging the tokenizer as the compression dictionary.
    ///
    /// Wire format: `#TK|<tokenizer_id>|<varint_encoded_tokens>`
    TokenNative,
    /// Brotli compression (high ratio, base64 encoded)
    ///
    /// Best for large content (>1KB) with repetitive patterns.
    /// Achieves 60-80% compression.
    ///
    /// Wire format: `#M2M[v3.0]|DATA:<base64_brotli>`
    Brotli,
}

impl Algorithm {
    /// Get the wire format prefix for this algorithm
    pub fn prefix(&self) -> &'static str {
        match self {
            Algorithm::None => "",
            Algorithm::M2M => "#M2M|1|",
            Algorithm::TokenNative => "#TK|",
            Algorithm::Brotli => "#M2M[v3.0]|DATA:",
        }
    }

    /// Parse algorithm from wire format
    pub fn from_prefix(content: &str) -> Option<Self> {
        if content.starts_with("#M2M|1|") {
            Some(Algorithm::M2M)
        } else if content.starts_with("#TK|") {
            Some(Algorithm::TokenNative)
        } else if content.starts_with("#M2M[v3.0]|") {
            Some(Algorithm::Brotli)
        } else {
            None
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::None => "NONE",
            Algorithm::M2M => "M2M",
            Algorithm::TokenNative => "TOKEN_NATIVE",
            Algorithm::Brotli => "BROTLI",
        }
    }

    /// Get all available algorithms in preference order
    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::M2M,
            Algorithm::TokenNative,
            Algorithm::Brotli,
            Algorithm::None,
        ]
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Result of compression operation
#[derive(Debug, Clone)]
pub struct CompressionResult {
    /// Compressed data (wire format)
    pub data: String,
    /// Algorithm used
    pub algorithm: Algorithm,
    /// Original size in bytes
    pub original_bytes: usize,
    /// Compressed size in bytes
    pub compressed_bytes: usize,
    /// Original token count (if available)
    pub original_tokens: Option<usize>,
    /// Compressed token count (if available)
    pub compressed_tokens: Option<usize>,
}

impl CompressionResult {
    /// Create new compression result
    pub fn new(
        data: String,
        algorithm: Algorithm,
        original_bytes: usize,
        compressed_bytes: usize,
    ) -> Self {
        Self {
            data,
            algorithm,
            original_bytes,
            compressed_bytes,
            original_tokens: None,
            compressed_tokens: None,
        }
    }

    /// Set token counts
    pub fn with_tokens(mut self, original: usize, compressed: usize) -> Self {
        self.original_tokens = Some(original);
        self.compressed_tokens = Some(compressed);
        self
    }

    /// Calculate byte compression ratio
    pub fn byte_ratio(&self) -> f64 {
        if self.compressed_bytes == 0 {
            0.0
        } else {
            self.original_bytes as f64 / self.compressed_bytes as f64
        }
    }

    /// Calculate token savings percentage
    pub fn token_savings_percent(&self) -> Option<f64> {
        match (self.original_tokens, self.compressed_tokens) {
            (Some(orig), Some(comp)) if orig > 0 => {
                Some((orig as f64 - comp as f64) / orig as f64 * 100.0)
            },
            _ => None,
        }
    }

    /// Check if compression was beneficial
    pub fn is_beneficial(&self) -> bool {
        match (self.original_tokens, self.compressed_tokens) {
            (Some(orig), Some(comp)) => comp < orig,
            _ => self.compressed_bytes < self.original_bytes,
        }
    }
}
