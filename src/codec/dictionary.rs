//! Dictionary-based compression (Algorithm::Dictionary).
//!
//! Uses lookup tables for common JSON patterns in LLM API requests/responses.
//! Optimized for structured, repetitive content.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::Value;
use std::collections::HashMap;

use super::{Algorithm, CompressionResult};
use crate::error::Result;

/// Common patterns encoded as single bytes (0x80-0xFF range)
const PATTERN_START: u8 = 0x80;

lazy_static::lazy_static! {
    /// Common JSON patterns → single byte
    static ref PATTERN_ENCODE: HashMap<&'static str, u8> = {
        let mut m = HashMap::new();
        // Common structural patterns
        m.insert(r#"{"role":"user","content":"#, 0x80);
        m.insert(r#"{"role":"assistant","content":"#, 0x81);
        m.insert(r#"{"role":"system","content":"#, 0x82);
        m.insert(r#""}"#, 0x83);
        m.insert(r#"},"#, 0x84);
        m.insert(r#""}]"#, 0x85);
        m.insert(r#"{"messages":["#, 0x86);
        m.insert(r#"{"model":"#, 0x87);
        m.insert(r#","messages":["#, 0x88);
        m.insert(r#","max_tokens":"#, 0x89);
        m.insert(r#","temperature":"#, 0x8A);
        m.insert(r#","stream":true"#, 0x8B);
        m.insert(r#","stream":false"#, 0x8C);
        // Common model prefixes
        m.insert(r#""gpt-4"#, 0x90);
        m.insert(r#""gpt-4o"#, 0x91);
        m.insert(r#""gpt-4o-mini"#, 0x92);
        m.insert(r#""gpt-3.5-turbo"#, 0x93);
        m.insert(r#""claude-3"#, 0x94);
        m.insert(r#""llama"#, 0x95);
        // Response patterns
        m.insert(r#"{"choices":[{"#, 0xA0);
        m.insert(r#""finish_reason":"stop""#, 0xA1);
        m.insert(r#""finish_reason":"length""#, 0xA2);
        m.insert(r#","usage":{"#, 0xA3);
        m.insert(r#""prompt_tokens":"#, 0xA4);
        m.insert(r#","completion_tokens":"#, 0xA5);
        m.insert(r#","total_tokens":"#, 0xA6);
        m.insert(r#""index":0,"#, 0xA7);
        m.insert(r#""message":{"#, 0xA8);
        m.insert(r#""delta":{"#, 0xA9);
        // Tool patterns
        m.insert(r#""tool_calls":[{"#, 0xB0);
        m.insert(r#""type":"function","#, 0xB1);
        m.insert(r#""function":{"#, 0xB2);
        m.insert(r#""name":"#, 0xB3);
        m.insert(r#","arguments":"#, 0xB4);
        m
    };

    /// Single byte → common pattern
    static ref PATTERN_DECODE: HashMap<u8, &'static str> = {
        PATTERN_ENCODE.iter().map(|(k, v)| (*v, *k)).collect()
    };

    /// Patterns sorted by length (longest first) for deterministic matching
    static ref PATTERNS_SORTED: Vec<(&'static str, u8)> = {
        let mut patterns: Vec<_> = PATTERN_ENCODE.iter().map(|(k, v)| (*k, *v)).collect();
        // Sort by length descending to match longest patterns first
        patterns.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        patterns
    };
}

/// Dictionary codec using pattern matching
#[derive(Clone)]
pub struct DictionaryCodec {
    /// Enable pattern matching
    pub use_patterns: bool,
    /// Minimum content length to apply compression
    pub min_length: usize,
}

impl Default for DictionaryCodec {
    fn default() -> Self {
        Self {
            use_patterns: true,
            min_length: 50,
        }
    }
}

impl DictionaryCodec {
    /// Create new dictionary codec
    pub fn new() -> Self {
        Self::default()
    }

    /// Compress JSON string using dictionary patterns
    pub fn compress(&self, content: &str) -> Result<CompressionResult> {
        if content.len() < self.min_length {
            // Too short, return as-is with prefix
            let wire = format!("#M2M|{content}");
            let wire_len = wire.len();
            return Ok(CompressionResult::new(
                wire,
                Algorithm::Dictionary,
                content.len(),
                wire_len,
            ));
        }

        let compressed = if self.use_patterns {
            self.compress_with_patterns(content)
        } else {
            content.as_bytes().to_vec()
        };

        // Encode as base64 for wire format
        let encoded = BASE64.encode(&compressed);
        let wire = format!("#M2M|{encoded}");
        let wire_len = wire.len();

        Ok(CompressionResult::new(
            wire,
            Algorithm::Dictionary,
            content.len(),
            wire_len,
        ))
    }

    /// Decompress from wire format
    pub fn decompress(&self, wire: &str) -> Result<String> {
        let data = wire.strip_prefix("#M2M|").unwrap_or(wire);

        // Try to decode as base64
        match BASE64.decode(data) {
            Ok(decoded) => {
                if self.use_patterns {
                    self.decompress_with_patterns(&decoded)
                } else {
                    String::from_utf8(decoded)
                        .map_err(|e| crate::error::M2MError::Decompression(e.to_string()))
                }
            },
            Err(_) => {
                // Not base64, return as-is (was too short to compress)
                Ok(data.to_string())
            },
        }
    }

    /// Compress using pattern replacement
    fn compress_with_patterns(&self, content: &str) -> Vec<u8> {
        let mut result = Vec::with_capacity(content.len());
        let bytes = content.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            let remaining = &content[i..];
            let mut matched = false;

            // Try to match patterns (sorted by length, longest first for determinism)
            for (pattern, code) in PATTERNS_SORTED.iter() {
                if remaining.starts_with(pattern) {
                    result.push(*code);
                    i += pattern.len();
                    matched = true;
                    break;
                }
            }

            if !matched {
                result.push(bytes[i]);
                i += 1;
            }
        }

        result
    }

    /// Decompress using pattern expansion
    fn decompress_with_patterns(&self, data: &[u8]) -> Result<String> {
        let mut result = String::with_capacity(data.len() * 2);

        for &byte in data {
            if byte >= PATTERN_START {
                if let Some(&pattern) = PATTERN_DECODE.get(&byte) {
                    result.push_str(pattern);
                } else {
                    // Unknown pattern byte, treat as literal
                    result.push(byte as char);
                }
            } else {
                result.push(byte as char);
            }
        }

        Ok(result)
    }

    /// Compress JSON value directly
    pub fn compress_value(&self, value: &Value) -> Result<CompressionResult> {
        let json = serde_json::to_string(value)?;
        self.compress(&json)
    }

    /// Decompress to JSON value
    pub fn decompress_value(&self, wire: &str) -> Result<Value> {
        let json = self.decompress(wire)?;
        serde_json::from_str(&json)
            .map_err(|e| crate::error::M2MError::Decompression(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_short() {
        let codec = DictionaryCodec::new();
        let content = r#"{"model":"gpt-4o"}"#;

        let result = codec.compress(content).unwrap();
        assert!(result.data.starts_with("#M2M|"));

        let decompressed = codec.decompress(&result.data).unwrap();
        assert_eq!(decompressed, content);
    }

    #[test]
    fn test_compress_with_patterns() {
        let content = r#"{"messages":[{"role":"user","content":"Hello"}]}"#;

        // Force compression even for short content
        let mut codec = DictionaryCodec::new();
        codec.min_length = 0;

        let result = codec.compress(content).unwrap();
        assert!(result.data.starts_with("#M2M|"));

        let decompressed = codec.decompress(&result.data).unwrap();
        assert_eq!(decompressed, content);
    }

    #[test]
    fn test_compress_request() {
        let codec = DictionaryCodec {
            min_length: 0,
            ..Default::default()
        };

        let content = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"Be helpful"},{"role":"user","content":"Hello"}]}"#;

        let result = codec.compress(content).unwrap();

        // Verify roundtrip
        let decompressed = codec.decompress(&result.data).unwrap();
        assert_eq!(decompressed, content);

        // Should achieve some compression due to patterns
        println!(
            "Original: {} bytes, Wire: {} bytes",
            content.len(),
            result.data.len()
        );
    }

    #[test]
    fn test_pattern_encode_decode() {
        // Verify all patterns have corresponding decode entries
        for (pattern, code) in PATTERN_ENCODE.iter() {
            assert!(
                PATTERN_DECODE.contains_key(code),
                "Pattern '{pattern}' (0x{code:02X}) missing decode entry"
            );
        }
    }
}
