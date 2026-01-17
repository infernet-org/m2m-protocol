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
    #[default]
    Token,
    /// Brotli compression (high ratio, base64 encoded)
    Brotli,
    /// Zlib/deflate compression
    Zlib,
    /// Dictionary-based encoding
    Dictionary,
}

impl Algorithm {
    /// Get the wire format prefix for this algorithm
    pub fn prefix(&self) -> &'static str {
        match self {
            Algorithm::None => "",
            Algorithm::Token => "#T1|",
            Algorithm::Brotli => "#M2M[v3.0]|DATA:",
            Algorithm::Zlib => "#M2M[v2.0]|DATA:",
            Algorithm::Dictionary => "#M2M|",
        }
    }

    /// Parse algorithm from wire format
    pub fn from_prefix(content: &str) -> Option<Self> {
        if content.starts_with("#T1|") {
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
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::None => "NONE",
            Algorithm::Token => "TOKEN",
            Algorithm::Brotli => "BROTLI",
            Algorithm::Zlib => "ZLIB",
            Algorithm::Dictionary => "DICTIONARY",
        }
    }

    /// Get all available algorithms in preference order
    pub fn all() -> &'static [Algorithm] {
        &[
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
