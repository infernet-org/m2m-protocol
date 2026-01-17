//! Token-optimized compression (Algorithm::Token).
//!
//! Optimizes JSON for LLM tokenizer efficiency through:
//! - Key abbreviation (messages → m, content → c)
//! - Role abbreviation (system → S, assistant → A)
//! - Model name abbreviation (gpt-4o → g4o)
//! - Default value removal (temperature: 1.0 → removed)

use serde_json::{Map, Value};

use super::tables::{
    is_default_value, KEY_ABBREV, KEY_EXPAND, MODEL_ABBREV, MODEL_EXPAND, ROLE_ABBREV, ROLE_EXPAND,
};
use super::{Algorithm, CompressionResult};
use crate::error::Result;

/// Token compressor using key/value abbreviation
#[derive(Clone)]
pub struct TokenCodec {
    /// Abbreviate keys
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
    pub fn compress(&self, value: &Value) -> Result<CompressionResult> {
        let original = serde_json::to_string(value)?;
        let compressed_value = self.compress_value(value, None);
        let compressed_json = serde_json::to_string(&compressed_value)?;

        // Wire format: #T1|{compressed_json}
        let wire = format!("#T1|{compressed_json}");
        let wire_len = wire.len();

        Ok(CompressionResult::new(
            wire,
            Algorithm::Token,
            original.len(),
            wire_len,
        ))
    }

    /// Compress only (no wire format prefix)
    pub fn compress_raw(&self, value: &Value) -> Value {
        self.compress_value(value, None)
    }

    /// Decompress from wire format
    pub fn decompress(&self, wire: &str) -> Result<Value> {
        let json_str = wire.strip_prefix("#T1|").unwrap_or(wire);
        let value: Value = serde_json::from_str(json_str)?;
        Ok(self.expand_value(&value, None))
    }

    /// Decompress raw JSON (no prefix)
    pub fn decompress_raw(&self, value: &Value) -> Value {
        self.expand_value(value, None)
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

                    // Abbreviate key
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

    #[allow(clippy::only_used_in_recursion)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compress_basic() {
        let codec = TokenCodec::new();
        let input = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        });

        let result = codec.compress(&input).unwrap();
        assert!(result.data.starts_with("#T1|"));
        assert!(result.data.contains("\"M\""));
        assert!(result.data.contains("\"m\""));
        assert!(result.data.contains("\"c\""));
    }

    #[test]
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

        let result = codec.compress(&input).unwrap();
        let decompressed = codec.decompress(&result.data).unwrap();

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
    fn test_removes_defaults() {
        let codec = TokenCodec::new();
        let input = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 1.0,
            "stream": false,
            "n": 1
        });

        let result = codec.compress(&input).unwrap();

        // Defaults should be removed
        assert!(!result.data.contains("temperature"));
        assert!(!result.data.contains("stream"));
    }

    #[test]
    fn test_role_abbreviation() {
        let codec = TokenCodec::new();
        let input = json!({
            "messages": [
                {"role": "system", "content": "Be helpful"},
                {"role": "assistant", "content": "OK"}
            ]
        });

        let result = codec.compress(&input).unwrap();

        // Roles should be abbreviated
        assert!(result.data.contains("\"r\":\"S\""));
        assert!(result.data.contains("\"r\":\"A\""));
    }
}
