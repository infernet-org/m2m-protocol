//! Configuration management.
//!
//! Supports configuration from:
//! - TOML config files
//! - Environment variables
//! - CLI arguments (for proxy)

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{M2MError, Result};

/// Main configuration struct
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Proxy configuration
    #[serde(default)]
    pub proxy: ProxyConfig,

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

        // Proxy settings
        if let Ok(upstream) = std::env::var("M2M_PROXY_UPSTREAM") {
            config.proxy.upstream = upstream;
        }
        if let Ok(port) = std::env::var("M2M_PROXY_PORT") {
            if let Ok(port) = port.parse() {
                config.proxy.port = port;
            }
        }
        if let Ok(host) = std::env::var("M2M_PROXY_HOST") {
            config.proxy.host = host;
        }

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
        // For now, just use other's values if they differ from defaults
        Self {
            proxy: ProxyConfig {
                upstream: if other.proxy.upstream != ProxyConfig::default().upstream {
                    other.proxy.upstream
                } else {
                    self.proxy.upstream
                },
                port: if other.proxy.port != ProxyConfig::default().port {
                    other.proxy.port
                } else {
                    self.proxy.port
                },
                host: if other.proxy.host != ProxyConfig::default().host {
                    other.proxy.host
                } else {
                    self.proxy.host
                },
                ..other.proxy
            },
            compression: other.compression,
            models: other.models,
        }
    }
}

/// Proxy server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Upstream API URL (e.g., https://api.openai.com)
    pub upstream: String,

    /// Port to listen on
    pub port: u16,

    /// Host to bind to
    pub host: String,

    /// Request timeout in seconds
    pub timeout_secs: u64,

    /// Enable verbose logging
    pub verbose: bool,

    /// Maximum request body size in bytes
    pub max_body_size: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream: "https://api.openai.com".to_string(),
            port: 8080,
            host: "127.0.0.1".to_string(),
            timeout_secs: 60,
            verbose: false,
            max_body_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

impl ProxyConfig {
    /// Get the full listen address
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
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
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.proxy.upstream, "https://api.openai.com");
        assert!(config.compression.abbreviate_keys);
    }

    #[test]
    fn test_proxy_listen_addr() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
            [proxy]
            upstream = "https://api.anthropic.com"
            port = 9090
            host = "0.0.0.0"
            timeout_secs = 60
            verbose = false
            max_body_size = 10485760

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
        assert_eq!(config.proxy.upstream, "https://api.anthropic.com");
        assert_eq!(config.proxy.port, 9090);
        assert_eq!(config.compression.min_tokens, 50);
        assert!(config.compression.enabled);
    }
}
