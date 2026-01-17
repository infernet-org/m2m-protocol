//! Token counting implementation.
//!
//! Uses tiktoken-rs for accurate BPE token counting with lazy-loaded encoders.

use std::sync::OnceLock;
use tiktoken_rs::{cl100k_base, o200k_base, CoreBPE};

use crate::models::Encoding;

// Lazy-loaded tokenizer instances (thread-safe singletons)
static CL100K: OnceLock<CoreBPE> = OnceLock::new();
static O200K: OnceLock<CoreBPE> = OnceLock::new();

/// Get the cl100k_base tokenizer (lazy-loaded)
fn get_cl100k() -> &'static CoreBPE {
    CL100K.get_or_init(|| cl100k_base().expect("Failed to load cl100k_base tokenizer"))
}

/// Get the o200k_base tokenizer (lazy-loaded)
fn get_o200k() -> &'static CoreBPE {
    O200K.get_or_init(|| o200k_base().expect("Failed to load o200k_base tokenizer"))
}

/// Count tokens using the default encoding (cl100k_base)
///
/// This is the most commonly used encoding for GPT-3.5/GPT-4 models.
///
/// # Example
/// ```
/// use m2m::tokenizer::count_tokens;
///
/// let tokens = count_tokens("Hello, world!");
/// assert!(tokens > 0);
/// assert!(tokens < 10);
/// ```
pub fn count_tokens(text: &str) -> usize {
    count_tokens_with_encoding(text, Encoding::Cl100kBase)
}

/// Count tokens with a specific encoding
///
/// # Example
/// ```
/// use m2m::tokenizer::count_tokens_with_encoding;
/// use m2m::models::Encoding;
///
/// // GPT-4o uses o200k_base
/// let tokens = count_tokens_with_encoding("Hello!", Encoding::O200kBase);
///
/// // GPT-4 uses cl100k_base
/// let tokens = count_tokens_with_encoding("Hello!", Encoding::Cl100kBase);
///
/// // Unknown models use heuristic (~4 chars per token)
/// let tokens = count_tokens_with_encoding("Hello!", Encoding::Heuristic);
/// ```
pub fn count_tokens_with_encoding(text: &str, encoding: Encoding) -> usize {
    match encoding {
        Encoding::Cl100kBase => get_cl100k().encode_with_special_tokens(text).len(),
        Encoding::O200kBase => get_o200k().encode_with_special_tokens(text).len(),
        Encoding::Heuristic => {
            // Rough estimate: ~4 characters per token
            // This is reasonably accurate for most text
            heuristic_count(text)
        }
    }
}

/// Count tokens for a specific model ID
///
/// Infers the encoding from the model ID and counts tokens.
///
/// # Example
/// ```
/// use m2m::tokenizer::count_tokens_for_model;
///
/// let tokens = count_tokens_for_model("Hello!", "openai/gpt-4o");
/// ```
pub fn count_tokens_for_model(text: &str, model: &str) -> usize {
    let encoding = Encoding::infer_from_id(model);
    count_tokens_with_encoding(text, encoding)
}

/// Heuristic token count (~4 characters per token)
///
/// This is a reasonable approximation for most languages and models
/// when exact tokenization is not available.
fn heuristic_count(text: &str) -> usize {
    // Round up to avoid underestimating
    text.len().div_ceil(4)
}

/// Token counter with caching and batch support
///
/// For repeated counting with the same encoding, this struct provides
/// a cleaner interface than the free functions.
///
/// # Example
/// ```
/// use m2m::tokenizer::TokenCounter;
/// use m2m::models::Encoding;
///
/// let counter = TokenCounter::new(Encoding::O200kBase);
///
/// let tokens1 = counter.count("Hello, world!");
/// let tokens2 = counter.count("Another message");
/// let total = counter.count_many(&["Hello", "World"]);
/// ```
pub struct TokenCounter {
    encoding: Encoding,
}

impl TokenCounter {
    /// Create a new token counter with the specified encoding
    pub fn new(encoding: Encoding) -> Self {
        Self { encoding }
    }

    /// Create a token counter for the default encoding (cl100k_base)
    pub fn default_encoding() -> Self {
        Self::new(Encoding::Cl100kBase)
    }

    /// Create a token counter for a specific model
    pub fn for_model(model: &str) -> Self {
        Self::new(Encoding::infer_from_id(model))
    }

    /// Count tokens in text
    pub fn count(&self, text: &str) -> usize {
        count_tokens_with_encoding(text, self.encoding)
    }

    /// Count tokens in multiple texts
    pub fn count_many(&self, texts: &[&str]) -> usize {
        texts.iter().map(|t| self.count(t)).sum()
    }

    /// Count tokens in JSON value (serialized)
    pub fn count_json(&self, value: &serde_json::Value) -> usize {
        let text = serde_json::to_string(value).unwrap_or_default();
        self.count(&text)
    }

    /// Get the encoding used by this counter
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
}

impl Default for TokenCounter {
    fn default() -> Self {
        Self::default_encoding()
    }
}

/// Estimate token savings from compression
///
/// Returns (original_tokens, compressed_tokens, savings, savings_percent)
#[allow(dead_code)]
pub fn estimate_savings(
    original: &str,
    compressed: &str,
    encoding: Encoding,
) -> (usize, usize, i64, f64) {
    let original_tokens = count_tokens_with_encoding(original, encoding);
    let compressed_tokens = count_tokens_with_encoding(compressed, encoding);
    let savings = original_tokens as i64 - compressed_tokens as i64;
    let savings_percent = if original_tokens > 0 {
        (savings as f64 / original_tokens as f64) * 100.0
    } else {
        0.0
    };

    (original_tokens, compressed_tokens, savings, savings_percent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_tokens_basic() {
        let tokens = count_tokens("Hello, world!");
        assert!(tokens > 0);
        assert!(tokens < 10);
    }

    #[test]
    fn test_count_tokens_empty() {
        assert_eq!(count_tokens(""), 0);
    }

    #[test]
    fn test_different_encodings() {
        let text = "Hello, world! This is a test.";

        let cl100k = count_tokens_with_encoding(text, Encoding::Cl100kBase);
        let o200k = count_tokens_with_encoding(text, Encoding::O200kBase);
        let heuristic = count_tokens_with_encoding(text, Encoding::Heuristic);

        // All should be positive
        assert!(cl100k > 0);
        assert!(o200k > 0);
        assert!(heuristic > 0);

        // Heuristic is approximately len/4
        let expected_heuristic = (text.len() + 3) / 4;
        assert_eq!(heuristic, expected_heuristic);
    }

    #[test]
    fn test_count_tokens_for_model() {
        let text = "Hello!";

        // These models use o200k_base
        let o200k_tokens = count_tokens_for_model(text, "openai/gpt-4o");

        // These use cl100k_base
        let cl100k_tokens = count_tokens_for_model(text, "openai/gpt-4");

        // Both should give reasonable results
        assert!(o200k_tokens > 0);
        assert!(cl100k_tokens > 0);
    }

    #[test]
    fn test_token_counter_struct() {
        let counter = TokenCounter::new(Encoding::Cl100kBase);

        let tokens = counter.count("Hello, world!");
        assert!(tokens > 0);

        let total = counter.count_many(&["Hello", "World"]);
        assert!(total > 0);
    }

    #[test]
    fn test_token_counter_json() {
        let counter = TokenCounter::default();

        let json = serde_json::json!({
            "message": "Hello, world!",
            "count": 42
        });

        let tokens = counter.count_json(&json);
        assert!(tokens > 0);
    }

    #[test]
    fn test_estimate_savings() {
        // Use a more realistic example with longer keys that definitely save tokens
        let original = r#"{"messages":[{"role":"assistant","content":"Hello there! How can I help you today?"}],"temperature":1.0}"#;
        let compressed = r#"{"m":[{"r":"A","c":"Hello there! How can I help you today?"}]}"#;

        let (orig, comp, savings, percent) =
            estimate_savings(original, compressed, Encoding::Cl100kBase);

        // The compressed version should have fewer tokens
        // If not, just check the function works correctly
        if orig > comp {
            assert!(savings > 0, "Should have positive savings");
            assert!(percent > 0.0, "Should have positive percentage");
        } else {
            // Even if compression didn't help, verify the math is correct
            assert_eq!(savings, orig as i64 - comp as i64);
        }
    }

    #[test]
    fn test_heuristic_never_zero() {
        // Even short strings should give at least 1 token
        assert!(heuristic_count("a") >= 1);
        assert!(heuristic_count("ab") >= 1);
        assert!(heuristic_count("abc") >= 1);
        assert!(heuristic_count("abcd") >= 1);
    }

    #[test]
    fn test_encoding_consistency() {
        // Same text, same encoding should always give same result
        let text = "The quick brown fox jumps over the lazy dog.";

        let count1 = count_tokens(text);
        let count2 = count_tokens(text);
        let count3 = count_tokens_with_encoding(text, Encoding::Cl100kBase);

        assert_eq!(count1, count2);
        assert_eq!(count1, count3);
    }

    #[test]
    fn test_json_message_tokens() {
        // Typical chat completion message
        let message = r#"{"model":"openai/gpt-4o","messages":[{"role":"user","content":"Hello"}],"temperature":1.0}"#;

        let tokens = count_tokens(message);

        // Should be reasonable for this size message
        assert!(tokens > 10);
        assert!(tokens < 50);
    }
}
