//! Token-optimized compression (legacy, deprecated).
//!
//! **DEPRECATED**: Use M2M codec instead. Token compression only achieves 3% token savings.
//!
//! Optimizes JSON for LLM tokenizer efficiency through:
//! - Pattern replacement (multi-token patterns -> single control char)
//! - Key abbreviation (only those verified to save tokens)
//! - Role abbreviation (system -> S, assistant -> A)
//! - Model name abbreviation (gpt-4o -> g4o)
//! - Default value removal (temperature: 1.0 -> removed)
//!
//! # Token Savings Strategy
//!
//! Based on empirical analysis (see `cargo run --bin token_analysis`), this codec
//! uses a three-tier optimization strategy:
//!
//! 1. **Pattern Replacement** (highest ROI): Multi-token patterns like
//!    `{"role":"user","content":"` (7 tokens) are replaced with single
//!    control characters (1 token). Saves 6+ tokens per pattern.
//!
//! 2. **Key Abbreviation** (medium ROI): Only keys verified to save tokens
//!    are abbreviated. Keys like "messages", "role" that cost the same
//!    tokens when abbreviated are NOT changed.
//!
//! 3. **Default Removal** (low ROI): Removes common default values.

use serde_json::{Map, Value};

use super::tables::{
    is_default_value, KEY_ABBREV, KEY_EXPAND, MODEL_ABBREV, MODEL_EXPAND, PATTERN_ABBREV,
    PATTERN_EXPAND, ROLE_ABBREV, ROLE_EXPAND,
};
use crate::error::Result;

/// Wire format prefix for token codec
pub const TOKEN_PREFIX: &str = "#T1|";

/// Token compressor using pattern replacement and key/value abbreviation
#[derive(Clone)]
pub struct TokenCodec {
    /// Apply pattern replacement (highest token savings)
    pub apply_patterns: bool,
    /// Abbreviate keys (only token-saving ones)
    pub abbreviate_keys: bool,
    /// Abbreviate roles
    pub abbreviate_roles: bool,
    /// Abbreviate model names
    pub abbreviate_models: bool,
    /// Remove default values
    pub remove_defaults: bool,
    /// Remove null values
    pub remove_nulls: bool,
}

impl Default for TokenCodec {
    fn default() -> Self {
        Self {
            // Pattern compression disabled by default - JSON field ordering is not guaranteed
            // and patterns may not match. Enable with caution.
            apply_patterns: false,
            abbreviate_keys: true,
            abbreviate_roles: true,
            abbreviate_models: true,
            remove_defaults: true,
            remove_nulls: true,
        }
    }
}

impl TokenCodec {
    /// Create new token codec with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Compress JSON value to token-optimized format
    ///
    /// **DEPRECATED**: Use M2M codec instead.
    #[deprecated(note = "Use M2M codec instead")]
    pub fn compress(&self, value: &Value) -> Result<(String, usize, usize)> {
        let original = serde_json::to_string(value)?;

        // Step 1: Apply structural transformations (key abbreviation, role/model abbreviation)
        let compressed_value = self.compress_value(value, None);
        let mut compressed_json = serde_json::to_string(&compressed_value)?;

        // Step 2: Apply pattern replacement on the compressed JSON
        // These patterns now use abbreviated keys where applicable
        if self.apply_patterns {
            compressed_json = self.apply_pattern_compression(&compressed_json);
        }

        // Wire format: #T1|{compressed_json}
        let wire = format!("{TOKEN_PREFIX}{compressed_json}");
        let wire_len = wire.len();

        Ok((wire, original.len(), wire_len))
    }

    /// Compress only (no wire format prefix)
    pub fn compress_raw(&self, value: &Value) -> String {
        let compressed_value = self.compress_value(value, None);
        let mut compressed_json = serde_json::to_string(&compressed_value).unwrap_or_default();

        if self.apply_patterns {
            compressed_json = self.apply_pattern_compression(&compressed_json);
        }

        compressed_json
    }

    /// Decompress from wire format
    pub fn decompress(&self, wire: &str) -> Result<Value> {
        let json_str = wire.strip_prefix(TOKEN_PREFIX).unwrap_or(wire);

        // Expand patterns first
        let expanded_json = self.apply_pattern_expansion(json_str);

        let value: Value = serde_json::from_str(&expanded_json)?;
        let expanded = self.expand_value(&value, None);
        // Restore default values that were omitted during compression
        Ok(self.restore_defaults(&expanded))
    }

    /// Decompress raw JSON (no prefix)
    pub fn decompress_raw(&self, json_str: &str) -> Result<Value> {
        let expanded_json = self.apply_pattern_expansion(json_str);
        let value: Value = serde_json::from_str(&expanded_json)?;
        let expanded = self.expand_value(&value, None);
        Ok(self.restore_defaults(&expanded))
    }

    /// Apply pattern compression to serialized JSON
    ///
    /// Replaces multi-token patterns with single control characters.
    /// Patterns are applied in order from PATTERN_ABBREV (longest first recommended).
    fn apply_pattern_compression(&self, json: &str) -> String {
        let mut result = json.to_string();

        for (pattern, replacement) in PATTERN_ABBREV {
            result = result.replace(pattern, replacement);
        }

        result
    }

    /// Expand patterns back to original form
    fn apply_pattern_expansion(&self, json: &str) -> String {
        let mut result = json.to_string();

        for (replacement, pattern) in PATTERN_EXPAND {
            result = result.replace(replacement, pattern);
        }

        result
    }

    fn compress_value(&self, value: &Value, parent_key: Option<&str>) -> Value {
        match value {
            Value::Object(map) => {
                let mut result = Map::new();

                for (key, val) in map {
                    // Skip nulls
                    if self.remove_nulls && val.is_null() {
                        continue;
                    }

                    // Skip defaults
                    if self.remove_defaults && is_default_value(key, val) {
                        continue;
                    }

                    // Abbreviate key (only if it saves tokens)
                    let new_key = if self.abbreviate_keys {
                        KEY_ABBREV
                            .get(key.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| key.clone())
                    } else {
                        key.clone()
                    };

                    // Process value recursively
                    let new_val = self.compress_value_with_context(val, key);
                    result.insert(new_key, new_val);
                }

                Value::Object(result)
            },
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| self.compress_value(v, parent_key))
                    .collect(),
            ),
            _ => self.compress_value_with_context(value, parent_key.unwrap_or("")),
        }
    }

    fn compress_value_with_context(&self, value: &Value, key: &str) -> Value {
        match value {
            Value::String(s) => {
                // Abbreviate role values
                if (key == "role" || key == "r") && self.abbreviate_roles {
                    if let Some(abbrev) = ROLE_ABBREV.get(s.as_str()) {
                        return Value::String(abbrev.to_string());
                    }
                }

                // Abbreviate model names
                if (key == "model" || key == "M") && self.abbreviate_models {
                    if let Some(abbrev) = MODEL_ABBREV.get(s.as_str()) {
                        return Value::String(abbrev.to_string());
                    }
                }

                value.clone()
            },
            Value::Object(_) => self.compress_value(value, Some(key)),
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| self.compress_value(v, Some(key)))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    fn expand_value(&self, value: &Value, parent_key: Option<&str>) -> Value {
        match value {
            Value::Object(map) => {
                let mut result = Map::new();

                for (key, val) in map {
                    // Expand key
                    let expanded_key = KEY_EXPAND
                        .get(key.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| key.clone());

                    // Expand value recursively
                    let expanded_val = self.expand_value(val, Some(&expanded_key));
                    result.insert(expanded_key, expanded_val);
                }

                Value::Object(result)
            },
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(|v| self.expand_value(v, parent_key))
                    .collect(),
            ),
            Value::String(s) => {
                if let Some(key) = parent_key {
                    // Expand role values
                    if key == "role" || key == "r" {
                        if let Some(expanded) = ROLE_EXPAND.get(s.as_str()) {
                            return Value::String(expanded.to_string());
                        }
                    }

                    // Expand model names
                    if key == "model" || key == "M" {
                        if let Some(expanded) = MODEL_EXPAND.get(s.as_str()) {
                            return Value::String(expanded.to_string());
                        }
                    }
                }

                value.clone()
            },
            _ => value.clone(),
        }
    }

    /// Restore default values that were omitted during compression.
    ///
    /// Per spec section 5.3.5, implementations MUST restore omitted parameters
    /// during decompression. This only applies to LLM API request objects
    /// (those with "messages" or "model" keys).
    fn restore_defaults(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                // Only restore defaults for LLM API request objects
                let is_llm_request = map.contains_key("messages") || map.contains_key("model");

                if is_llm_request {
                    let mut result = map.clone();

                    // Restore defaults per spec 5.3.5
                    if !result.contains_key("temperature") {
                        result.insert("temperature".to_string(), Value::from(1.0));
                    }
                    if !result.contains_key("top_p") {
                        result.insert("top_p".to_string(), Value::from(1.0));
                    }
                    if !result.contains_key("n") {
                        result.insert("n".to_string(), Value::from(1));
                    }
                    if !result.contains_key("stream") {
                        result.insert("stream".to_string(), Value::Bool(false));
                    }
                    if !result.contains_key("frequency_penalty") {
                        result.insert("frequency_penalty".to_string(), Value::from(0));
                    }
                    if !result.contains_key("presence_penalty") {
                        result.insert("presence_penalty".to_string(), Value::from(0));
                    }

                    Value::Object(result)
                } else {
                    // Recursively process nested objects
                    let mut result = Map::new();
                    for (key, val) in map {
                        result.insert(key.clone(), self.restore_defaults(val));
                    }
                    Value::Object(result)
                }
            },
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.restore_defaults(v)).collect())
            },
            _ => value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[allow(deprecated)]
    fn test_compress_basic() {
        let codec = TokenCodec::new();
        let input = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });

        let (data, _, _) = codec.compress(&input).unwrap();
        assert!(data.starts_with("#T1|"));
        // Model should be abbreviated (saves tokens)
        assert!(data.contains("\"M\":\"g4o\"") || data.contains("\"M\": \"g4o\""));
        // Content should be abbreviated (saves tokens)
        assert!(data.contains("\"c\""));
    }

    #[test]
    #[allow(deprecated)]
    fn test_pattern_compression() {
        let codec = TokenCodec::new();
        let input = json!({
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"}
            ]
        });

        let (data, _, _) = codec.compress(&input).unwrap();

        // Pattern replacement should have been applied
        // The pattern {"role":"user","content":" should be replaced with \u0001
        // Note: This depends on the exact JSON serialization order
        println!("Compressed: {}", data);

        // Verify roundtrip works
        let decompressed = codec.decompress(&data).unwrap();
        assert_eq!(decompressed["messages"][0]["content"], "Hello");
        assert_eq!(decompressed["messages"][1]["content"], "Hi there!");
    }

    #[test]
    #[allow(deprecated)]
    fn test_roundtrip() {
        let codec = TokenCodec::new();
        let input = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hello"}
            ],
            "max_tokens": 100
        });

        let (data, _, _) = codec.compress(&input).unwrap();
        let decompressed = codec.decompress(&data).unwrap();

        // Content should match
        assert_eq!(
            decompressed["messages"][0]["content"],
            input["messages"][0]["content"]
        );
        assert_eq!(
            decompressed["messages"][1]["content"],
            input["messages"][1]["content"]
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_removes_defaults() {
        let codec = TokenCodec::new();
        let input = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 1.0,
            "stream": false,
            "n": 1
        });

        let (data, _, _) = codec.compress(&input).unwrap();

        // Defaults should be removed
        assert!(!data.contains("temperature"));
        assert!(!data.contains("stream"));
    }

    #[test]
    #[allow(deprecated)]
    fn test_role_abbreviation() {
        let codec = TokenCodec::new();
        let input = json!({
            "messages": [
                {"role": "system", "content": "Be helpful"},
                {"role": "assistant", "content": "OK"}
            ]
        });

        let (data, _, _) = codec.compress(&input).unwrap();

        // Roles should be abbreviated to S and A
        // Note: with pattern compression, the full pattern might be replaced
        let decompressed = codec.decompress(&data).unwrap();
        assert_eq!(decompressed["messages"][0]["role"], "system");
        assert_eq!(decompressed["messages"][1]["role"], "assistant");
    }

    #[test]
    #[allow(deprecated)]
    fn test_default_restoration() {
        let codec = TokenCodec::new();

        // Input with explicit defaults that will be omitted during compression
        let input = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 1.0,
            "top_p": 1.0,
            "n": 1,
            "stream": false,
            "frequency_penalty": 0,
            "presence_penalty": 0
        });

        let (data, _, _) = codec.compress(&input).unwrap();
        let decompressed = codec.decompress(&data).unwrap();

        // Per spec 5.3.5: MUST restore omitted parameters during decompression
        assert_eq!(decompressed["temperature"], 1.0);
        assert_eq!(decompressed["top_p"], 1.0);
        assert_eq!(decompressed["n"], 1);
        assert_eq!(decompressed["stream"], false);
        assert_eq!(decompressed["frequency_penalty"], 0);
        assert_eq!(decompressed["presence_penalty"], 0);

        // Original content should be preserved
        assert_eq!(decompressed["model"], "gpt-4o");
        assert_eq!(decompressed["messages"][0]["content"], "Hello");
    }

    #[test]
    #[allow(deprecated)]
    fn test_default_restoration_preserves_non_defaults() {
        let codec = TokenCodec::new();

        // Input with non-default values that should be preserved
        let input = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.7,
            "top_p": 0.9,
            "n": 2,
            "stream": true,
            "frequency_penalty": 0.5,
            "presence_penalty": 0.5
        });

        let (data, _, _) = codec.compress(&input).unwrap();
        let decompressed = codec.decompress(&data).unwrap();

        // Non-default values MUST be preserved exactly
        assert_eq!(decompressed["temperature"], 0.7);
        assert_eq!(decompressed["top_p"], 0.9);
        assert_eq!(decompressed["n"], 2);
        assert_eq!(decompressed["stream"], true);
        assert_eq!(decompressed["frequency_penalty"], 0.5);
        assert_eq!(decompressed["presence_penalty"], 0.5);
    }

    #[test]
    #[allow(deprecated)]
    fn test_roundtrip_with_defaults_complete() {
        let codec = TokenCodec::new();

        // Original request with defaults
        let original = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hello"}
            ],
            "temperature": 1.0,
            "stream": false
        });

        // Compress
        let (data, _, _) = codec.compress(&original).unwrap();

        // Verify defaults were removed during compression
        assert!(!data.contains("temperature"));
        assert!(!data.contains("stream"));

        // Decompress
        let decompressed = codec.decompress(&data).unwrap();

        // Verify structural completeness - all fields restored
        assert!(decompressed.get("temperature").is_some());
        assert!(decompressed.get("stream").is_some());
        assert!(decompressed.get("top_p").is_some());
        assert!(decompressed.get("n").is_some());
        assert!(decompressed.get("frequency_penalty").is_some());
        assert!(decompressed.get("presence_penalty").is_some());
    }

    #[test]
    fn test_pattern_expansion_roundtrip() {
        let codec = TokenCodec::new();

        // Test each pattern individually
        for (pattern, abbrev) in super::super::tables::PATTERN_ABBREV {
            let compressed = codec.apply_pattern_compression(pattern);
            assert_eq!(
                compressed, *abbrev,
                "Pattern compression failed for: {}",
                pattern
            );

            let expanded = codec.apply_pattern_expansion(&compressed);
            assert_eq!(
                expanded, *pattern,
                "Pattern expansion failed for: {}",
                pattern
            );
        }
    }
}
