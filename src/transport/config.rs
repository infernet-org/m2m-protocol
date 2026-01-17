//! Transport configuration for TLS and QUIC.
//!
//! Handles certificate management, QUIC-specific settings, and
//! development vs production TLS configuration.

use rcgen::{Certificate, CertificateParams};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{M2MError, Result};

/// Certificate configuration source.
#[derive(Debug, Clone)]
pub enum CertConfig {
    /// Generate self-signed certificates (development only).
    SelfSigned {
        /// Common name for the certificate.
        common_name: String,
    },
    /// Load certificates from files.
    Files {
        /// Path to PEM certificate file.
        cert_path: PathBuf,
        /// Path to PEM private key file.
        key_path: PathBuf,
    },
    /// Use raw certificate data.
    Raw {
        /// DER-encoded certificate chain.
        cert_der: Vec<Vec<u8>>,
        /// DER-encoded private key (PKCS8).
        key_der: Vec<u8>,
    },
}

impl Default for CertConfig {
    fn default() -> Self {
        Self::SelfSigned {
            common_name: "localhost".to_string(),
        }
    }
}

impl CertConfig {
    /// Create development configuration with self-signed cert.
    pub fn development() -> Self {
        Self::SelfSigned {
            common_name: "localhost".to_string(),
        }
    }

    /// Create production configuration from files.
    pub fn from_files(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self::Files {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
        }
    }

    /// Load and return the certificate chain and private key for rustls 0.21.
    pub fn load(&self) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey)> {
        match self {
            Self::SelfSigned { common_name } => {
                tracing::warn!(
                    "Using self-signed certificate for '{}' - NOT FOR PRODUCTION",
                    common_name
                );

                let mut params = CertificateParams::new(vec![
                    common_name.clone(),
                    "127.0.0.1".to_string(),
                    "::1".to_string(),
                ]);

                params.distinguished_name = rcgen::DistinguishedName::new();
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, common_name.clone());

                // Certificate::from_params creates self-signed cert with auto-generated key
                let cert = Certificate::from_params(params).map_err(|e| {
                    M2MError::Config(format!("Failed to generate self-signed cert: {}", e))
                })?;

                let cert_der = rustls::Certificate(
                    cert.serialize_der()
                        .map_err(|e| M2MError::Config(format!("Failed to serialize cert: {}", e)))?,
                );
                let key_der = rustls::PrivateKey(cert.serialize_private_key_der());

                Ok((vec![cert_der], key_der))
            }
            Self::Files { cert_path, key_path } => {
                let cert_pem = fs::read(cert_path).map_err(|e| {
                    M2MError::Config(format!("Failed to read cert file {:?}: {}", cert_path, e))
                })?;

                let key_pem = fs::read(key_path).map_err(|e| {
                    M2MError::Config(format!("Failed to read key file {:?}: {}", key_path, e))
                })?;

                let certs: Vec<rustls::Certificate> =
                    rustls_pemfile::certs(&mut cert_pem.as_slice())
                        .map_err(|e| M2MError::Config(format!("Failed to parse cert PEM: {}", e)))?
                        .into_iter()
                        .map(rustls::Certificate)
                        .collect();

                if certs.is_empty() {
                    return Err(M2MError::Config(
                        "No certificates found in PEM file".to_string(),
                    ));
                }

                // Try to read PKCS8 first, then RSA
                let key = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())
                    .map_err(|e| M2MError::Config(format!("Failed to parse key PEM: {}", e)))?
                    .into_iter()
                    .next()
                    .map(rustls::PrivateKey)
                    .or_else(|| {
                        rustls_pemfile::rsa_private_keys(&mut key_pem.as_slice())
                            .ok()?
                            .into_iter()
                            .next()
                            .map(rustls::PrivateKey)
                    })
                    .ok_or_else(|| {
                        M2MError::Config("No private key found in PEM file".to_string())
                    })?;

                Ok((certs, key))
            }
            Self::Raw { cert_der, key_der } => {
                let certs = cert_der
                    .iter()
                    .map(|c| rustls::Certificate(c.clone()))
                    .collect();
                let key = rustls::PrivateKey(key_der.clone());
                Ok((certs, key))
            }
        }
    }
}

/// TLS configuration for secure transports.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate source.
    pub cert: CertConfig,
    /// ALPN protocols to advertise (e.g., ["h3", "h2"]).
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert: CertConfig::default(),
            alpn_protocols: vec![b"h3".to_vec()],
        }
    }
}

impl TlsConfig {
    /// Create development TLS config with self-signed cert.
    pub fn development() -> Self {
        Self {
            cert: CertConfig::development(),
            alpn_protocols: vec![b"h3".to_vec()],
        }
    }

    /// Create production TLS config from certificate files.
    pub fn production(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            cert: CertConfig::from_files(cert_path, key_path),
            alpn_protocols: vec![b"h3".to_vec()],
        }
    }
}

/// QUIC transport configuration.
#[derive(Debug, Clone)]
pub struct QuicTransportConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// TLS configuration.
    pub tls: TlsConfig,
    /// Enable 0-RTT for returning connections.
    pub enable_0rtt: bool,
    /// Maximum idle timeout before closing connection.
    pub max_idle_timeout: Duration,
    /// Maximum concurrent bidirectional streams per connection.
    pub max_concurrent_bidi_streams: u32,
    /// Maximum concurrent unidirectional streams per connection.
    pub max_concurrent_uni_streams: u32,
    /// Use BBR congestion control (vs Cubic).
    pub use_bbr: bool,
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8443".parse().unwrap(),
            tls: TlsConfig::default(),
            enable_0rtt: true,
            max_idle_timeout: Duration::from_secs(30),
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            use_bbr: true,
        }
    }
}

impl QuicTransportConfig {
    /// Create development configuration with self-signed cert.
    pub fn development() -> Self {
        Self {
            tls: TlsConfig::development(),
            ..Default::default()
        }
    }

    /// Create production configuration with certificate files.
    pub fn production(
        listen_addr: SocketAddr,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            listen_addr,
            tls: TlsConfig::production(cert_path, key_path),
            ..Default::default()
        }
    }

    /// Set listen address.
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Set maximum idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.max_idle_timeout = timeout;
        self
    }

    /// Build quinn ServerConfig from this configuration.
    pub fn build_quinn_config(&self) -> Result<quinn::ServerConfig> {
        let (certs, key) = self.tls.cert.load()?;

        let mut rustls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| M2MError::Config(format!("Failed to build TLS config: {}", e)))?;

        rustls_config.alpn_protocols = self.tls.alpn_protocols.clone();
        rustls_config.max_early_data_size = u32::MAX; // Enable 0-RTT

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            self.max_idle_timeout
                .try_into()
                .unwrap_or(quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap()),
        ));
        transport_config.max_concurrent_bidi_streams(self.max_concurrent_bidi_streams.into());
        transport_config.max_concurrent_uni_streams(self.max_concurrent_uni_streams.into());

        // Enable BBR congestion control for better throughput
        if self.use_bbr {
            transport_config.congestion_controller_factory(Arc::new(
                quinn::congestion::BbrConfig::default(),
            ));
        }

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(rustls_config));
        server_config.transport_config(Arc::new(transport_config));

        Ok(server_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_config_self_signed() {
        let config = CertConfig::development();
        let result = config.load();
        assert!(result.is_ok());

        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_quic_config_default() {
        let config = QuicTransportConfig::default();
        assert_eq!(config.listen_addr.port(), 8443);
        assert!(config.enable_0rtt);
        assert!(config.use_bbr);
    }
}
