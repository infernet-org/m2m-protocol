//! TCP transport implementation for M2M Protocol.
//!
//! Traditional HTTP/1.1 over TCP transport using Axum's built-in
//! TCP listener. This is the default transport for backwards compatibility.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::Router;
use tokio::net::TcpListener;

use super::Transport;
use crate::error::{M2MError, Result};

/// TCP/HTTP transport using Axum's built-in server.
#[derive(Debug, Clone)]
pub struct TcpTransport {
    /// Address to listen on.
    listen_addr: SocketAddr,
}

impl TcpTransport {
    /// Create a new TCP transport.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    /// Create with default localhost address.
    pub fn localhost(port: u16) -> Self {
        Self::new(SocketAddr::from(([127, 0, 0, 1], port)))
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::localhost(8080)
    }
}

impl Transport for TcpTransport {
    fn serve(
        &self,
        router: Router,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let addr = self.listen_addr;

        Box::pin(async move {
            tracing::info!("TCP transport listening on {}", addr);

            let listener = TcpListener::bind(addr).await.map_err(|e| {
                M2MError::Server(format!("Failed to bind TCP to {}: {}", addr, e))
            })?;

            axum::serve(listener, router)
                .await
                .map_err(|e| M2MError::Server(format!("TCP server error: {}", e)))?;

            Ok(())
        })
    }

    fn name(&self) -> &'static str {
        "TCP/HTTP"
    }

    fn listen_addr(&self) -> String {
        format!("http://{}", self.listen_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_default() {
        let transport = TcpTransport::default();
        assert_eq!(transport.listen_addr.port(), 8080);
        assert_eq!(transport.name(), "TCP/HTTP");
    }

    #[test]
    fn test_tcp_transport_localhost() {
        let transport = TcpTransport::localhost(3000);
        assert_eq!(transport.listen_addr.port(), 3000);
        assert_eq!(transport.listen_addr(), "http://127.0.0.1:3000");
    }
}
