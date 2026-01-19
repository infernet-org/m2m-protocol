//! Compression algorithm types and results.

use serde::{Deserialize, Serialize};

/// Available compression algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Algorithm {
    /// No compression (passthrough)
    None,
    /// Token-optimized compression (key/value abbreviation)
    Token,
    /// Token-native compression (transmit token IDs directly)
    ///
    /// This algorithm tokenizes content using the negotiated tokenizer and
    /// transmits token IDs with VarInt encoding. Achieves 50-60% compression
    /// by leveraging the tokenizer as the compression dictionary.
    ///
    /// Wire format: `#TK|<tokenizer_id>|<varint_encoded_tokens>`
    TokenNative,
    /// M3: Schema-aware binary compression (M2M v3.0)
    ///
    /// Eliminates JSON structural overhead by using positional encoding
    /// with a known schema. Achieves ~60% byte savings.
    ///
    /// Wire format: `#M3|<schema><binary_payload>`
    #[default]
    M3,
    /// Brotli compression (high ratio, base64 encoded)
    Brotli,
    /// Zlib/deflate compression (DEPRECATED in v3.0)
    ///
    /// This algorithm is kept for backwards compatibility with v2.0 wire format.
    /// New implementations MUST NOT use Zlib for compression.
    /// Decompression attempts will fall back to Brotli.
    #[deprecated(
        since = "3.0.0",
        note = "Use M3 or Brotli instead. Kept for v2.0 wire format compatibility."
    )]
    Zlib,
    /// Dictionary-based encoding (DEPRECATED - negative compression)
    #[deprecated(
        since = "3.0.0",
        note = "Use M3 instead. Dictionary has negative compression."
    )]
    Dictionary,
}

impl Algorithm {
    /// Get the wire format prefix for this algorithm
    #[allow(deprecated)]
    pub fn prefix(&self) -> &'static str {
        match self {
            Algorithm::None => "",
            Algorithm::Token => "#T1|",
            Algorithm::TokenNative => "#TK|",
            Algorithm::M3 => "#M3|",
            Algorithm::Brotli => "#M2M[v3.0]|DATA:",
            Algorithm::Zlib => "#M2M[v2.0]|DATA:",
            Algorithm::Dictionary => "#M2M|",
        }
    }

    /// Parse algorithm from wire format
    ///
    /// Note: v2.0 format (Zlib) is detected for backwards compatibility
    /// but decompression will fall back to Brotli.
    #[allow(deprecated)]
    pub fn from_prefix(content: &str) -> Option<Self> {
        if content.starts_with("#M3|") {
            Some(Algorithm::M3)
        } else if content.starts_with("#TK|") {
            Some(Algorithm::TokenNative)
        } else if content.starts_with("#T1|") {
            Some(Algorithm::Token)
        } else if content.starts_with("#M2M[v3.0]|") {
            Some(Algorithm::Brotli)
        } else if content.starts_with("#M2M[v2.0]|") {
            Some(Algorithm::Zlib)
        } else if content.starts_with("#M2M|") {
            Some(Algorithm::Dictionary)
        } else {
            None
        }
    }

    /// Get human-readable name
    #[allow(deprecated)]
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::None => "NONE",
            Algorithm::Token => "TOKEN (LEGACY)",
            Algorithm::TokenNative => "TOKEN_NATIVE (LEGACY)",
            Algorithm::M3 => "M3",
            Algorithm::Brotli => "BROTLI",
            Algorithm::Zlib => "ZLIB (DEPRECATED)",
            Algorithm::Dictionary => "DICTIONARY (DEPRECATED)",
        }
    }

    /// Get all available algorithms in preference order
    ///
    /// Note: Deprecated algorithms are excluded.
    /// Use [`Algorithm::all_including_deprecated`] if you need to include them.
    pub fn all() -> &'static [Algorithm] {
        &[
            Algorithm::M3,
            Algorithm::TokenNative,
            Algorithm::Token,
            Algorithm::Brotli,
            Algorithm::None,
        ]
    }

    /// Get all algorithms including deprecated ones
    #[allow(deprecated)]
    pub fn all_including_deprecated() -> &'static [Algorithm] {
        &[
            Algorithm::M3,
            Algorithm::TokenNative,
            Algorithm::Token,
            Algorithm::Brotli,
            Algorithm::Zlib,
            Algorithm::Dictionary,
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
