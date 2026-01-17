//! Agent capabilities for protocol negotiation.
//!
//! Capabilities are advertised during the HELLO/ACCEPT handshake
//! to establish what compression algorithms and features both
//! agents support.

use serde::{Deserialize, Serialize};

use crate::codec::Algorithm;

/// Compression-related capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionCaps {
    /// Supported algorithms in preference order
    pub algorithms: Vec<Algorithm>,
    /// Maximum payload size in bytes (0 = unlimited)
    pub max_payload: usize,
    /// Supports streaming compression
    pub streaming: bool,
    /// Has ML routing capability
    pub ml_routing: bool,
}

impl Default for CompressionCaps {
    fn default() -> Self {
        Self {
            algorithms: vec![
                Algorithm::Token,
                Algorithm::Brotli,
                Algorithm::Dictionary,
                Algorithm::None,
            ],
            max_payload: 0, // unlimited
            streaming: true,
            ml_routing: false,
        }
    }
}

impl CompressionCaps {
    /// Create with ML routing enabled
    pub fn with_ml_routing(mut self) -> Self {
        self.ml_routing = true;
        self
    }

    /// Create with specific algorithms
    pub fn with_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Check if algorithm is supported
    pub fn supports(&self, algorithm: Algorithm) -> bool {
        self.algorithms.contains(&algorithm)
    }

    /// Get best mutually supported algorithm
    pub fn negotiate(&self, other: &CompressionCaps) -> Option<Algorithm> {
        // Find first algorithm supported by both (preference order is ours)
        for algo in &self.algorithms {
            if other.supports(*algo) {
                return Some(*algo);
            }
        }
        None
    }
}

/// Security-related capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCaps {
    /// Has security threat detection
    pub threat_detection: bool,
    /// Security model version
    pub model_version: Option<String>,
    /// Blocks detected threats (vs just flagging)
    pub blocking_mode: bool,
    /// Minimum confidence threshold for blocking (0.0 - 1.0)
    pub block_threshold: f32,
}

impl Default for SecurityCaps {
    fn default() -> Self {
        Self {
            threat_detection: false,
            model_version: None,
            blocking_mode: false,
            block_threshold: 0.8,
        }
    }
}

impl SecurityCaps {
    /// Enable threat detection
    pub fn with_threat_detection(mut self, model_version: &str) -> Self {
        self.threat_detection = true;
        self.model_version = Some(model_version.to_string());
        self
    }

    /// Enable blocking mode
    pub fn with_blocking(mut self, threshold: f32) -> Self {
        self.blocking_mode = true;
        self.block_threshold = threshold.clamp(0.0, 1.0);
        self
    }
}

/// Full agent capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// Protocol version
    pub version: String,
    /// Agent identifier
    pub agent_id: String,
    /// Agent type/name
    pub agent_type: String,
    /// Compression capabilities
    pub compression: CompressionCaps,
    /// Security capabilities
    pub security: SecurityCaps,
    /// Custom extensions (key-value pairs)
    #[serde(default)]
    pub extensions: std::collections::HashMap<String, String>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            version: super::PROTOCOL_VERSION.to_string(),
            agent_id: uuid::Uuid::new_v4().to_string(),
            agent_type: "m2m-rust".to_string(),
            compression: CompressionCaps::default(),
            security: SecurityCaps::default(),
            extensions: std::collections::HashMap::new(),
        }
    }
}

impl Capabilities {
    /// Create new capabilities with custom agent type
    pub fn new(agent_type: &str) -> Self {
        Self {
            agent_type: agent_type.to_string(),
            ..Default::default()
        }
    }

    /// Add compression capabilities
    pub fn with_compression(mut self, caps: CompressionCaps) -> Self {
        self.compression = caps;
        self
    }

    /// Add security capabilities
    pub fn with_security(mut self, caps: SecurityCaps) -> Self {
        self.security = caps;
        self
    }

    /// Add extension
    pub fn with_extension(mut self, key: &str, value: &str) -> Self {
        self.extensions.insert(key.to_string(), value.to_string());
        self
    }

    /// Check version compatibility
    pub fn is_compatible(&self, other: &Capabilities) -> bool {
        // Major version must match
        let self_major = self.version.split('.').next().unwrap_or("0");
        let other_major = other.version.split('.').next().unwrap_or("0");
        self_major == other_major
    }

    /// Negotiate capabilities with peer
    pub fn negotiate(&self, peer: &Capabilities) -> Option<NegotiatedCaps> {
        if !self.is_compatible(peer) {
            return None;
        }

        let algorithm = self.compression.negotiate(&peer.compression)?;

        Some(NegotiatedCaps {
            algorithm,
            streaming: self.compression.streaming && peer.compression.streaming,
            ml_routing: self.compression.ml_routing && peer.compression.ml_routing,
            threat_detection: self.security.threat_detection || peer.security.threat_detection,
            blocking_mode: self.security.blocking_mode || peer.security.blocking_mode,
        })
    }
}

/// Result of capability negotiation
#[derive(Debug, Clone)]
pub struct NegotiatedCaps {
    /// Agreed compression algorithm
    pub algorithm: Algorithm,
    /// Both support streaming
    pub streaming: bool,
    /// Both have ML routing
    pub ml_routing: bool,
    /// Either has threat detection
    pub threat_detection: bool,
    /// Either has blocking mode
    pub blocking_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_negotiation() {
        let caps1 = CompressionCaps::default();
        let caps2 = CompressionCaps {
            algorithms: vec![Algorithm::Brotli, Algorithm::None],
            ..Default::default()
        };

        // Should negotiate to Brotli (first common in caps1's preference order)
        assert_eq!(caps1.negotiate(&caps2), Some(Algorithm::Brotli));
    }

    #[test]
    fn test_no_common_algorithm() {
        let caps1 = CompressionCaps {
            algorithms: vec![Algorithm::Token],
            ..Default::default()
        };
        let caps2 = CompressionCaps {
            algorithms: vec![Algorithm::Brotli],
            ..Default::default()
        };

        assert_eq!(caps1.negotiate(&caps2), None);
    }

    #[test]
    fn test_version_compatibility() {
        let caps1 = Capabilities::default();
        let mut caps2 = Capabilities::default();

        assert!(caps1.is_compatible(&caps2));

        caps2.version = "3.1".to_string();
        assert!(caps1.is_compatible(&caps2)); // Minor version diff OK

        caps2.version = "4.0".to_string();
        assert!(!caps1.is_compatible(&caps2)); // Major version diff NOT OK
    }

    #[test]
    fn test_full_negotiation() {
        let caps1 = Capabilities::default()
            .with_security(SecurityCaps::default().with_threat_detection("1.0"));

        let caps2 = Capabilities::default();

        let negotiated = caps1.negotiate(&caps2).unwrap();
        assert_eq!(negotiated.algorithm, Algorithm::Token);
        assert!(negotiated.threat_detection); // One has it
    }
}
