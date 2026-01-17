//! QUIC/HTTP3 transport implementation for M2M Protocol.
//!
//! High-performance UDP-based transport with:
//! - **0-RTT resumption**: Reduced latency for returning connections
//! - **No head-of-line blocking**: Multiplexed streams
//! - **Connection migration**: Survives network changes
//! - **Built-in TLS 1.3**: Secure by default
//!
//! # Architecture
//!
//! ```text
//! quinn::Endpoint (UDP socket)
//!        │
//!        ▼
//! quinn::Connection (QUIC connection)
//!        │
//!        ▼
//! h3_quinn::Connection (HTTP/3 layer)
//!        │
//!        ▼
//! h3::server::Connection (HTTP/3 server)
//!        │
//!        ▼
//! Axum Router (HTTP request handling)
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use bytes::{Buf, Bytes};
use h3::quic::BidiStream;
use h3::server::RequestStream;
use http::{Method, Request, Response};
use tower::ServiceExt;

use super::config::QuicTransportConfig;
use super::Transport;
use crate::error::{M2MError, Result};

/// QUIC/HTTP3 transport using quinn and h3.
pub struct QuicTransport {
    config: QuicTransportConfig,
}

impl QuicTransport {
    /// Create a new QUIC transport with the given configuration.
    pub fn new(config: QuicTransportConfig) -> Self {
        Self { config }
    }

    /// Create development transport with self-signed certificates.
    pub fn development(port: u16) -> Self {
        let mut config = QuicTransportConfig::development();
        config.listen_addr = SocketAddr::from(([127, 0, 0, 1], port));
        Self::new(config)
    }

    /// Handle a single HTTP/3 connection.
    async fn handle_connection(
        router: Router,
        connection: quinn::Connection,
    ) -> Result<()> {
        let remote_addr = connection.remote_address();
        tracing::debug!("New QUIC connection from {}", remote_addr);

        // Wrap quinn connection for h3
        let h3_conn = h3_quinn::Connection::new(connection);

        // Create HTTP/3 server connection
        let mut h3_server = h3::server::Connection::new(h3_conn)
            .await
            .map_err(|e| M2MError::Server(format!("H3 connection error: {}", e)))?;

        // Handle requests on this connection
        loop {
            match h3_server.accept().await {
                Ok(Some((request, stream))) => {
                    let router = router.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_request(router, request, stream).await {
                            tracing::error!("Request error: {}", e);
                        }
                    });
                }
                Ok(None) => {
                    tracing::debug!("Connection closed gracefully");
                    break;
                }
                Err(e) => {
                    tracing::warn!("Connection error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single HTTP/3 request.
    async fn handle_request<S>(
        router: Router,
        request: Request<()>,
        mut stream: RequestStream<S, Bytes>,
    ) -> Result<()>
    where
        S: BidiStream<Bytes> + Send + 'static,
    {
        let method = request.method().clone();
        let uri = request.uri().clone();
        tracing::debug!("{} {}", method, uri);

        // Read request body if present
        let body = if method != Method::GET && method != Method::HEAD {
            let mut body_bytes = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.map_err(|e| {
                M2MError::Server(format!("Failed to read request body: {}", e))
            })? {
                // Copy bytes from Buf implementation
                while chunk.has_remaining() {
                    let bytes = chunk.chunk();
                    body_bytes.extend_from_slice(bytes);
                    let len = bytes.len();
                    chunk.advance(len);
                }
            }
            axum::body::Body::from(body_bytes)
        } else {
            axum::body::Body::empty()
        };

        // Build Axum request
        let mut axum_request = Request::builder()
            .method(request.method())
            .uri(request.uri());

        for (name, value) in request.headers() {
            axum_request = axum_request.header(name, value);
        }

        let axum_request = axum_request
            .body(body)
            .map_err(|e| M2MError::Server(format!("Failed to build request: {}", e)))?;

        // Route through Axum
        let response = router
            .oneshot(axum_request)
            .await
            .map_err(|e| M2MError::Server(format!("Router error: {}", e)))?;

        // Extract response parts
        let (parts, body) = response.into_parts();

        // Convert body to bytes
        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|e| M2MError::Server(format!("Failed to read response body: {}", e)))?;

        // Build HTTP/3 response
        let h3_response = Response::builder()
            .status(parts.status)
            .body(())
            .map_err(|e| M2MError::Server(format!("Failed to build H3 response: {}", e)))?;

        // Send response headers
        stream
            .send_response(h3_response)
            .await
            .map_err(|e| M2MError::Server(format!("Failed to send H3 response: {}", e)))?;

        // Send response body
        if !body_bytes.is_empty() {
            stream
                .send_data(body_bytes)
                .await
                .map_err(|e| M2MError::Server(format!("Failed to send H3 body: {}", e)))?;
        }

        // Finish the stream
        stream
            .finish()
            .await
            .map_err(|e| M2MError::Server(format!("Failed to finish H3 stream: {}", e)))?;

        Ok(())
    }
}

impl Transport for QuicTransport {
    fn serve(
        &self,
        router: Router,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let addr = self.config.listen_addr;

            // Build QUIC server configuration
            let server_config = self.config.build_quinn_config()?;

            tracing::info!("QUIC transport listening on {}", addr);
            tracing::info!("  0-RTT: {}", if self.config.enable_0rtt { "enabled" } else { "disabled" });
            tracing::info!("  Congestion control: {}", if self.config.use_bbr { "BBR" } else { "Cubic" });

            // Create QUIC endpoint
            let endpoint = quinn::Endpoint::server(server_config, addr)
                .map_err(|e| M2MError::Server(format!("Failed to create QUIC endpoint: {}", e)))?;

            tracing::info!("QUIC/HTTP3 server ready at https://{}", addr);

            // Accept connections
            while let Some(incoming) = endpoint.accept().await {
                let router = router.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(connection) => {
                            if let Err(e) = Self::handle_connection(router, connection).await {
                                tracing::error!("Connection handler error: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to accept connection: {}", e);
                        }
                    }
                });
            }

            Ok(())
        })
    }

    fn name(&self) -> &'static str {
        "QUIC/HTTP3"
    }

    fn listen_addr(&self) -> String {
        format!("https://{}", self.config.listen_addr)
    }
}

/// Statistics for QUIC transport.
#[derive(Debug, Clone, Default)]
pub struct QuicStats {
    /// Total connections accepted.
    pub connections_accepted: u64,
    /// Currently active connections.
    pub active_connections: u64,
    /// Connections using 0-RTT.
    pub zero_rtt_connections: u64,
    /// Connection migrations detected.
    pub migrations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_transport_development() {
        let transport = QuicTransport::development(8443);
        assert_eq!(transport.name(), "QUIC/HTTP3");
        assert!(transport.listen_addr().contains("8443"));
    }
}
