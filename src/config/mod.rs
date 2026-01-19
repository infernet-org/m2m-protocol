//! Configuration management.
//!
//! Supports configuration from:
//! - TOML config files
//! - Environment variables

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{M2MError, Result};

/// Main configuration struct
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Compression configuration
    #[serde(default)]
    pub compression: CompressionConfig,

    /// Model registry configuration
    #[serde(default)]
    pub models: ModelConfig,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let content = std::fs::read_to_string(&path)
            .map_err(|e| M2MError::Config(format!("Failed to read config file: {e}")))?;

        toml::from_str(&content)
            .map_err(|e| M2MError::Config(format!("Failed to parse config: {e}")))
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Compression settings
        if let Ok(val) = std::env::var("M2M_COMPRESS_MIN_TOKENS") {
            if let Ok(val) = val.parse() {
                config.compression.min_tokens = val;
            }
        }

        config
    }

    /// Merge with another config (other takes precedence)
    pub fn merge(self, other: Self) -> Self {
        Self {
            compression: other.compression,
            models: other.models,
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Enable compression (false = passthrough mode)
    pub enabled: bool,

    /// Minimum tokens to consider compression
    pub min_tokens: usize,

    /// Threshold for full compression
    pub full_compression_threshold: usize,

    /// Enable key abbreviation
    pub abbreviate_keys: bool,

    /// Enable role abbreviation
    pub abbreviate_roles: bool,

    /// Enable model abbreviation
    pub abbreviate_models: bool,

    /// Remove default values
    pub remove_defaults: bool,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_tokens: 25,
            full_compression_threshold: 50,
            abbreviate_keys: true,
            abbreviate_roles: true,
            abbreviate_models: true,
            remove_defaults: true,
        }
    }
}

/// Model registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Enable fetching models from OpenRouter
    pub fetch_openrouter: bool,

    /// Cache directory for dynamic models
    pub cache_dir: Option<PathBuf>,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            fetch_openrouter: false,
            cache_dir: dirs::cache_dir().map(|p| p.join("m2m")),
            cache_ttl_secs: 3600, // 1 hour
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.compression.abbreviate_keys);
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
            [compression]
            enabled = true
            min_tokens = 50
            full_compression_threshold = 50
            abbreviate_keys = true
            abbreviate_roles = true
            abbreviate_models = true
            remove_defaults = true
        "#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.compression.min_tokens, 50);
        assert!(config.compression.enabled);
    }
}
