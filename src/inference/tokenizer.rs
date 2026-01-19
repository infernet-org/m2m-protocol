//! Tokenizer infrastructure for Hydra model.
//!
//! Provides a unified trait for tokenization with multiple backend implementations:
//!
//! - [`Llama3Tokenizer`]: HuggingFace Tokenizers format (Llama 3, Mistral, etc.)
//! - [`TiktokenTokenizer`]: OpenAI tiktoken format (cl100k, o200k)
//! - [`FallbackTokenizer`]: Simple byte-level fallback
//!
//! # Example
//!
//! ```rust,ignore
//! use m2m::inference::{HydraTokenizer, Llama3Tokenizer, TokenizerType};
//!
//! // Load Llama 3 tokenizer from file
//! let tokenizer = Llama3Tokenizer::from_file("./models/hydra/tokenizer.json")?;
//!
//! // Encode text to token IDs
//! let tokens = tokenizer.encode("Hello, world!")?;
//!
//! // Get vocab size (128K for Llama 3)
//! assert_eq!(tokenizer.vocab_size(), 128000);
//! ```

use std::path::Path;
use std::sync::Arc;

use crate::error::{M2MError, Result};

// Re-export tiktoken for OpenAI tokenizers
use tiktoken_rs::{cl100k_base, o200k_base, CoreBPE};

// HuggingFace tokenizers
use tokenizers::Tokenizer;

/// Maximum sequence length for Hydra input
pub const MAX_SEQUENCE_LENGTH: usize = 512;

/// Tokenizer type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizerType {
    /// Llama 3 tokenizer (128K vocab, HuggingFace format)
    Llama3,
    /// OpenAI o200k_base (200K vocab, tiktoken)
    O200kBase,
    /// OpenAI cl100k_base (100K vocab, tiktoken)
    Cl100kBase,
    /// Fallback byte-level tokenizer
    Fallback,
}

impl TokenizerType {
    /// Get the expected vocabulary size for this tokenizer type
    #[must_use]
    pub fn vocab_size(&self) -> usize {
        match self {
            Self::Llama3 => 128_000,
            Self::O200kBase => 200_019,
            Self::Cl100kBase => 100_256,
            Self::Fallback => 256, // Byte-level
        }
    }

    /// Get display name
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Llama3 => "llama3",
            Self::O200kBase => "o200k_base",
            Self::Cl100kBase => "cl100k_base",
            Self::Fallback => "fallback",
        }
    }
}

impl std::fmt::Display for TokenizerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// HydraTokenizer Trait
// ============================================================================

/// Trait for tokenizers used by Hydra model.
///
/// This trait abstracts over different tokenizer implementations,
/// allowing Hydra to work with Llama 3, OpenAI, or other tokenizers.
pub trait HydraTokenizer: Send + Sync {
    /// Encode text to token IDs.
    ///
    /// Returns a vector of token IDs representing the input text.
    /// The encoding should NOT include special tokens (BOS/EOS) unless
    /// the specific tokenizer requires them for correct operation.
    fn encode(&self, text: &str) -> Result<Vec<u32>>;

    /// Decode token IDs back to text.
    ///
    /// Returns the original text (or approximation) from token IDs.
    fn decode(&self, tokens: &[u32]) -> Result<String>;

    /// Get the vocabulary size.
    fn vocab_size(&self) -> usize;

    /// Get the tokenizer type.
    fn tokenizer_type(&self) -> TokenizerType;

    /// Truncate tokens to maximum length for Hydra.
    ///
    /// Default implementation truncates to `MAX_SEQUENCE_LENGTH`.
    fn truncate(&self, tokens: Vec<u32>) -> Vec<u32> {
        if tokens.len() > MAX_SEQUENCE_LENGTH {
            tokens[..MAX_SEQUENCE_LENGTH].to_vec()
        } else {
            tokens
        }
    }

    /// Encode and truncate for Hydra input.
    fn encode_for_hydra(&self, text: &str) -> Result<Vec<u32>> {
        let tokens = self.encode(text)?;
        Ok(self.truncate(tokens))
    }
}

// ============================================================================
// Llama3Tokenizer - HuggingFace Tokenizers format
// ============================================================================

/// Llama 3 tokenizer using HuggingFace Tokenizers library.
///
/// This is the primary tokenizer for Hydra, supporting the 128K vocabulary
/// used by Llama 3 and compatible models.
///
/// # Example
///
/// ```rust,ignore
/// let tokenizer = Llama3Tokenizer::from_file("./tokenizer.json")?;
/// let tokens = tokenizer.encode("Hello, world!")?;
/// ```
pub struct Llama3Tokenizer {
    inner: Tokenizer,
    vocab_size: usize,
}

impl Llama3Tokenizer {
    /// Load tokenizer from a `tokenizer.json` file.
    ///
    /// # Errors
    ///
    /// Returns error if the file cannot be read or parsed.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let inner = Tokenizer::from_file(path.as_ref())
            .map_err(|e| M2MError::Tokenizer(format!("Failed to load tokenizer: {e}")))?;

        let vocab_size = inner.get_vocab_size(true);

        Ok(Self { inner, vocab_size })
    }

    /// Load tokenizer from JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if the JSON is invalid.
    pub fn from_json(json: &str) -> Result<Self> {
        Self::from_bytes(json.as_bytes())
    }

    /// Load tokenizer from bytes.
    ///
    /// # Errors
    ///
    /// Returns error if the bytes are not valid JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = Tokenizer::from_bytes(bytes)
            .map_err(|e| M2MError::Tokenizer(format!("Failed to parse tokenizer: {e}")))?;

        let vocab_size = inner.get_vocab_size(true);

        Ok(Self { inner, vocab_size })
    }
}

impl HydraTokenizer for Llama3Tokenizer {
    fn encode(&self, text: &str) -> Result<Vec<u32>> {
        let encoding = self
            .inner
            .encode(text, false)
            .map_err(|e| M2MError::Tokenizer(format!("Encoding failed: {e}")))?;

        Ok(encoding.get_ids().to_vec())
    }

    fn decode(&self, tokens: &[u32]) -> Result<String> {
        self.inner
            .decode(tokens, true)
            .map_err(|e| M2MError::Tokenizer(format!("Decoding failed: {e}")))
    }

    fn vocab_size(&self) -> usize {
        self.vocab_size
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::Llama3
    }
}

// ============================================================================
// TiktokenTokenizer - OpenAI tiktoken format
// ============================================================================

/// OpenAI tiktoken-based tokenizer.
///
/// Supports cl100k_base (GPT-4) and o200k_base (GPT-4o) encodings.
pub struct TiktokenTokenizer {
    inner: CoreBPE,
    tokenizer_type: TokenizerType,
}

impl TiktokenTokenizer {
    /// Create cl100k_base tokenizer (GPT-3.5, GPT-4).
    ///
    /// # Errors
    ///
    /// Returns error if tokenizer initialization fails.
    pub fn cl100k() -> Result<Self> {
        let inner = cl100k_base()
            .map_err(|e| M2MError::Tokenizer(format!("Failed to load cl100k: {e}")))?;

        Ok(Self {
            inner,
            tokenizer_type: TokenizerType::Cl100kBase,
        })
    }

    /// Create o200k_base tokenizer (GPT-4o, o1, o3).
    ///
    /// # Errors
    ///
    /// Returns error if tokenizer initialization fails.
    pub fn o200k() -> Result<Self> {
        let inner =
            o200k_base().map_err(|e| M2MError::Tokenizer(format!("Failed to load o200k: {e}")))?;

        Ok(Self {
            inner,
            tokenizer_type: TokenizerType::O200kBase,
        })
    }

    /// Create tokenizer from type.
    ///
    /// # Errors
    ///
    /// Returns error if tokenizer initialization fails or type is not tiktoken-based.
    pub fn from_type(tokenizer_type: TokenizerType) -> Result<Self> {
        match tokenizer_type {
            TokenizerType::Cl100kBase => Self::cl100k(),
            TokenizerType::O200kBase => Self::o200k(),
            _ => Err(M2MError::Tokenizer(format!(
                "Tokenizer type {tokenizer_type} is not tiktoken-based"
            ))),
        }
    }
}

impl HydraTokenizer for TiktokenTokenizer {
    fn encode(&self, text: &str) -> Result<Vec<u32>> {
        // tiktoken Rank is u32, so direct collect works
        Ok(self.inner.encode_with_special_tokens(text))
    }

    fn decode(&self, tokens: &[u32]) -> Result<String> {
        // tiktoken Rank is u32, so just convert slice to Vec
        self.inner
            .decode(tokens.to_vec())
            .map_err(|e| M2MError::Tokenizer(format!("Decoding failed: {e}")))
    }

    fn vocab_size(&self) -> usize {
        self.tokenizer_type.vocab_size()
    }

    fn tokenizer_type(&self) -> TokenizerType {
        self.tokenizer_type
    }
}

// ============================================================================
// HydraByteTokenizer - Byte-level tokenizer matching training
// ============================================================================

/// Byte-level tokenizer that matches Hydra's training tokenizer.
///
/// Uses the same encoding as the Python `SimpleTokenizer`:
/// - PAD = 0, EOS = 1, BOS = 2
/// - Byte values 0-255 map to token IDs 3-258
/// - Sequences are wrapped with BOS and EOS tokens
#[derive(Debug, Clone)]
pub struct HydraByteTokenizer {
    /// Maximum sequence length (default 512)
    max_length: usize,
}

impl HydraByteTokenizer {
    /// PAD token ID
    pub const PAD_TOKEN_ID: u32 = 0;
    /// EOS token ID
    pub const EOS_TOKEN_ID: u32 = 1;
    /// BOS token ID
    pub const BOS_TOKEN_ID: u32 = 2;
    /// Offset for byte values (first 3 IDs reserved for special tokens)
    pub const BYTE_OFFSET: u32 = 3;

    /// Create new Hydra byte tokenizer with default max length (512).
    #[must_use]
    pub fn new() -> Self {
        Self { max_length: 512 }
    }

    /// Create tokenizer with custom max length.
    #[must_use]
    pub fn with_max_length(max_length: usize) -> Self {
        Self { max_length }
    }
}

impl Default for HydraByteTokenizer {
    fn default() -> Self {
        Self::new()
    }
}

impl HydraTokenizer for HydraByteTokenizer {
    fn encode(&self, text: &str) -> Result<Vec<u32>> {
        let mut tokens = Vec::with_capacity(self.max_length.min(text.len() + 2));

        // BOS token
        tokens.push(Self::BOS_TOKEN_ID);

        // Encode bytes with offset (leave room for EOS)
        let max_content = self.max_length.saturating_sub(2);
        for byte in text.bytes().take(max_content) {
            tokens.push((byte as u32) + Self::BYTE_OFFSET);
        }

        // EOS token
        tokens.push(Self::EOS_TOKEN_ID);

        Ok(tokens)
    }

    fn decode(&self, tokens: &[u32]) -> Result<String> {
        let bytes: Vec<u8> = tokens
            .iter()
            .filter_map(|&t| {
                // Skip special tokens, decode byte tokens
                if t >= Self::BYTE_OFFSET && t < Self::BYTE_OFFSET + 256 {
                    Some((t - Self::BYTE_OFFSET) as u8)
                } else {
                    None
                }
            })
            .collect();

        String::from_utf8(bytes)
            .map_err(|e| M2MError::Tokenizer(format!("Invalid UTF-8 in tokens: {e}")))
    }

    fn vocab_size(&self) -> usize {
        // 3 special tokens + 256 byte values = 259, but model uses 32000
        32000
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::Fallback // Use same type for compatibility
    }
}

// ============================================================================
// FallbackTokenizer - Simple byte-level tokenizer (legacy)
// ============================================================================

/// Fallback byte-level tokenizer.
///
/// Used when no proper tokenizer is available. Maps bytes directly to token IDs.
/// This is NOT recommended for production use but ensures Hydra can always run.
///
/// **Note**: For Hydra inference, prefer [`HydraByteTokenizer`] which matches
/// the training tokenizer exactly.
#[derive(Debug, Clone, Default)]
pub struct FallbackTokenizer {
    vocab_size: usize,
}

impl FallbackTokenizer {
    /// Create new fallback tokenizer.
    #[must_use]
    pub fn new() -> Self {
        Self { vocab_size: 256 }
    }

    /// Create fallback tokenizer that maps to a specific vocab size.
    ///
    /// Token IDs will be `byte % vocab_size` to ensure they fit within bounds.
    #[must_use]
    pub fn with_vocab_size(vocab_size: usize) -> Self {
        Self { vocab_size }
    }
}

impl HydraTokenizer for FallbackTokenizer {
    fn encode(&self, text: &str) -> Result<Vec<u32>> {
        Ok(text
            .bytes()
            .map(|b| (b as u32) % (self.vocab_size as u32))
            .collect())
    }

    fn decode(&self, tokens: &[u32]) -> Result<String> {
        // Best effort: treat tokens as bytes
        let bytes: Vec<u8> = tokens
            .iter()
            .filter_map(|&t| if t < 256 { Some(t as u8) } else { None })
            .collect();

        String::from_utf8(bytes)
            .map_err(|e| M2MError::Tokenizer(format!("Invalid UTF-8 in tokens: {e}")))
    }

    fn vocab_size(&self) -> usize {
        self.vocab_size
    }

    fn tokenizer_type(&self) -> TokenizerType {
        TokenizerType::Fallback
    }
}

// ============================================================================
// BoxedTokenizer - Type-erased tokenizer for dynamic dispatch
// ============================================================================

/// Type-erased tokenizer for storing different tokenizer implementations.
pub type BoxedTokenizer = Arc<dyn HydraTokenizer>;

/// Create a boxed tokenizer from a specific implementation.
pub fn boxed<T: HydraTokenizer + 'static>(tokenizer: T) -> BoxedTokenizer {
    Arc::new(tokenizer)
}

// ============================================================================
// Tokenizer Loading Utilities
// ============================================================================

/// Load the best available tokenizer for Hydra.
///
/// Attempts to load in order:
/// 1. Llama 3 tokenizer from the specified path
/// 2. Fallback tokenizer with specified vocab size
///
/// # Arguments
///
/// * `tokenizer_path` - Optional path to `tokenizer.json`
/// * `vocab_size` - Fallback vocab size if no tokenizer found
///
/// # Example
///
/// ```rust,ignore
/// let tokenizer = load_tokenizer(Some("./models/hydra/tokenizer.json"), 128000)?;
/// ```
pub fn load_tokenizer(tokenizer_path: Option<&Path>, vocab_size: usize) -> Result<BoxedTokenizer> {
    // Try to load Llama 3 tokenizer if path provided
    if let Some(path) = tokenizer_path {
        if path.exists() {
            match Llama3Tokenizer::from_file(path) {
                Ok(tokenizer) => {
                    tracing::info!(
                        "Loaded Llama 3 tokenizer from {} (vocab: {})",
                        path.display(),
                        tokenizer.vocab_size()
                    );
                    return Ok(boxed(tokenizer));
                },
                Err(e) => {
                    tracing::warn!("Failed to load tokenizer from {}: {e}", path.display());
                },
            }
        }
    }

    // Fallback
    tracing::warn!(
        "Using fallback byte-level tokenizer (vocab_size: {vocab_size}). \
         For best results, provide a tokenizer.json file."
    );
    Ok(boxed(FallbackTokenizer::with_vocab_size(vocab_size)))
}

/// Load tokenizer by type.
///
/// # Errors
///
/// Returns error if the specified tokenizer type cannot be loaded.
pub fn load_tokenizer_by_type(
    tokenizer_type: TokenizerType,
    tokenizer_path: Option<&Path>,
) -> Result<BoxedTokenizer> {
    match tokenizer_type {
        TokenizerType::Llama3 => {
            let path = tokenizer_path
                .ok_or_else(|| M2MError::Tokenizer("Llama3 tokenizer requires a path".into()))?;
            Ok(boxed(Llama3Tokenizer::from_file(path)?))
        },
        TokenizerType::O200kBase => Ok(boxed(TiktokenTokenizer::o200k()?)),
        TokenizerType::Cl100kBase => Ok(boxed(TiktokenTokenizer::cl100k()?)),
        TokenizerType::Fallback => Ok(boxed(FallbackTokenizer::new())),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_tokenizer_encode_decode() {
        let tokenizer = FallbackTokenizer::new();
        let text = "Hello";

        let tokens = tokenizer.encode(text).unwrap();
        assert_eq!(tokens.len(), 5); // 5 bytes

        // Verify byte values
        assert_eq!(tokens[0], b'H' as u32);
        assert_eq!(tokens[1], b'e' as u32);
    }

    #[test]
    fn test_fallback_tokenizer_vocab_mapping() {
        let tokenizer = FallbackTokenizer::with_vocab_size(128000);
        let text = "Test";

        let tokens = tokenizer.encode(text).unwrap();

        // All tokens should be < vocab_size
        for &t in &tokens {
            assert!(t < 128000);
        }
    }

    #[test]
    fn test_tiktoken_cl100k() {
        let tokenizer = TiktokenTokenizer::cl100k().unwrap();

        assert_eq!(tokenizer.tokenizer_type(), TokenizerType::Cl100kBase);
        assert_eq!(tokenizer.vocab_size(), 100_256);

        let tokens = tokenizer.encode("Hello, world!").unwrap();
        assert!(!tokens.is_empty());

        let decoded = tokenizer.decode(&tokens).unwrap();
        assert_eq!(decoded, "Hello, world!");
    }

    #[test]
    fn test_tiktoken_o200k() {
        let tokenizer = TiktokenTokenizer::o200k().unwrap();

        assert_eq!(tokenizer.tokenizer_type(), TokenizerType::O200kBase);
        assert_eq!(tokenizer.vocab_size(), 200_019);

        let tokens = tokenizer.encode("Hello, world!").unwrap();
        assert!(!tokens.is_empty());

        let decoded = tokenizer.decode(&tokens).unwrap();
        assert_eq!(decoded, "Hello, world!");
    }

    #[test]
    fn test_truncate() {
        let tokenizer = FallbackTokenizer::new();

        // Create tokens longer than MAX_SEQUENCE_LENGTH
        let long_text = "x".repeat(MAX_SEQUENCE_LENGTH + 100);
        let tokens = tokenizer.encode(&long_text).unwrap();
        let truncated = tokenizer.truncate(tokens);

        assert_eq!(truncated.len(), MAX_SEQUENCE_LENGTH);
    }

    #[test]
    fn test_tokenizer_type_vocab_size() {
        assert_eq!(TokenizerType::Llama3.vocab_size(), 128_000);
        assert_eq!(TokenizerType::O200kBase.vocab_size(), 200_019);
        assert_eq!(TokenizerType::Cl100kBase.vocab_size(), 100_256);
        assert_eq!(TokenizerType::Fallback.vocab_size(), 256);
    }
}
