//! Transport layer abstraction for M2M Protocol.
//!
//! Provides pluggable transport backends including:
//! - **TCP/HTTP**: Traditional TCP with HTTP/1.1 or HTTP/2
//! - **QUIC/HTTP/3**: Modern UDP-based transport with 0-RTT
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │              M2M Server                  │
//! │         (Transport-Agnostic)            │
//! └──────────────────┬──────────────────────┘
//!                    │
//!          ┌────────┴────────┐
//!          ▼                 ▼
//! ┌─────────────────┐ ┌─────────────────┐
//! │  TcpTransport   │ │  QuicTransport  │
//! │   (HTTP/1.1)    │ │   (HTTP/3)      │
//! └─────────────────┘ └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use m2m::transport::{TransportKind, QuicTransportConfig};
//!
//! // Select transport for M2M protocol server
//! let transport = TransportKind::Tcp;  // or Quic, Both
//! ```

mod config;
mod quic;
mod tcp;

pub use config::{CertConfig, QuicTransportConfig, TlsConfig};
pub use quic::QuicTransport;
pub use tcp::TcpTransport;

use crate::error::Result;
use axum::Router;
use std::future::Future;
use std::pin::Pin;

/// Transport kind selection for the M2M server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransportKind {
    /// Traditional TCP with HTTP/1.1 (default)
    #[default]
    Tcp,
    /// QUIC with HTTP/3 - 0-RTT, no HOL blocking
    Quic,
    /// Both TCP and QUIC for gradual migration
    Both,
}

impl TransportKind {
    /// Get descriptive name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP/HTTP",
            Self::Quic => "QUIC/HTTP3",
            Self::Both => "TCP+QUIC",
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for TransportKind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" | "http" => Ok(Self::Tcp),
            "quic" | "http3" | "h3" => Ok(Self::Quic),
            "both" | "dual" => Ok(Self::Both),
            _ => Err(format!("Unknown transport kind: {}", s)),
        }
    }
}

/// Transport trait for pluggable network backends.
///
/// Implementations handle the low-level network protocol while
/// the server remains transport-agnostic.
pub trait Transport: Send + Sync {
    /// Serve the given Axum router on this transport.
    ///
    /// This method should run until shutdown is signaled.
    fn serve(&self, router: Router) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Get the transport name for logging.
    fn name(&self) -> &'static str;

    /// Get the listen address as a string.
    fn listen_addr(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_transport_kind_from_str() {
        assert_eq!(TransportKind::from_str("tcp").unwrap(), TransportKind::Tcp);
        assert_eq!(
            TransportKind::from_str("quic").unwrap(),
            TransportKind::Quic
        );
        assert_eq!(
            TransportKind::from_str("HTTP3").unwrap(),
            TransportKind::Quic
        );
        assert_eq!(
            TransportKind::from_str("both").unwrap(),
            TransportKind::Both
        );
        assert!(TransportKind::from_str("invalid").is_err());
    }

    #[test]
    fn test_transport_kind_default() {
        assert_eq!(TransportKind::default(), TransportKind::Tcp);
    }
}
