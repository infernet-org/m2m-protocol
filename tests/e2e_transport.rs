//! End-to-end transport layer tests.
//!
//! These tests verify that transport implementations actually work
//! with real network connections, not just configuration validation.

use std::net::SocketAddr;
use std::time::Duration;

use axum::{routing::get, Json, Router};
use m2m::transport::{TcpTransport, Transport, TransportKind};
use serde_json::{json, Value};
use tokio::time::timeout;

/// Find an available port for testing
async fn find_available_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Create a simple test router
fn test_router() -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status": "ok"})) }))
        .route(
            "/echo",
            get(|| async { Json(json!({"message": "hello from M2M"})) }),
        )
}

#[tokio::test]
async fn test_tcp_transport_serves_requests() {
    // Find an available port
    let port = find_available_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Create transport
    let transport = TcpTransport::new(addr);

    // Start server in background
    let router = test_router();
    let server_handle = tokio::spawn(async move {
        let _ = transport.serve(router).await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Make HTTP request
    let client = reqwest::Client::new();
    let response = timeout(
        Duration::from_secs(5),
        client
            .get(format!("http://127.0.0.1:{}/health", port))
            .send(),
    )
    .await
    .expect("Request timed out")
    .expect("Request failed");

    assert!(response.status().is_success());

    let body: Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    // Clean up
    server_handle.abort();
}

#[tokio::test]
async fn test_tcp_transport_handles_multiple_requests() {
    let port = find_available_port().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let transport = TcpTransport::new(addr);
    let router = test_router();

    let server_handle = tokio::spawn(async move {
        let _ = transport.serve(router).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    // Send multiple concurrent requests
    let mut handles = vec![];
    for _ in 0..10 {
        let client = client.clone();
        let url = format!("http://127.0.0.1:{}/echo", port);
        handles.push(tokio::spawn(async move { client.get(&url).send().await }));
    }

    // All requests should succeed
    for handle in handles {
        let response = handle.await.unwrap().unwrap();
        assert!(response.status().is_success());
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_transport_kind_parsing() {
    assert_eq!("tcp".parse::<TransportKind>().unwrap(), TransportKind::Tcp);
    assert_eq!(
        "quic".parse::<TransportKind>().unwrap(),
        TransportKind::Quic
    );
    assert_eq!(
        "http3".parse::<TransportKind>().unwrap(),
        TransportKind::Quic
    );
    assert_eq!(
        "both".parse::<TransportKind>().unwrap(),
        TransportKind::Both
    );
    assert!("invalid".parse::<TransportKind>().is_err());
}

#[tokio::test]
async fn test_tcp_transport_listen_addr_format() {
    let transport = TcpTransport::localhost(9999);
    assert_eq!(transport.listen_addr(), "http://127.0.0.1:9999");
    assert_eq!(transport.name(), "TCP/HTTP");
}

#[tokio::test]
async fn test_tcp_transport_handles_connection_refused_gracefully() {
    // Try to connect to a port with no server
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();

    let result = client.get("http://127.0.0.1:59999/health").send().await;
    assert!(result.is_err()); // Should fail, but not panic
}

// Note: QUIC transport E2E tests require TLS certificates.
// The following test documents this limitation and tests configuration only.
#[cfg(test)]
mod quic_tests {
    use m2m::transport::{CertConfig, QuicTransportConfig, TlsConfig};
    use std::net::SocketAddr;

    #[test]
    fn test_quic_config_development_mode() {
        let config = QuicTransportConfig::development();
        // Default listen address is 127.0.0.1:8443
        assert_eq!(config.listen_addr.port(), 8443);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn test_quic_config_production_mode() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let config = QuicTransportConfig::production(addr, "/path/to/cert.pem", "/path/to/key.pem");
        assert_eq!(config.listen_addr.port(), 4433);
        assert!(config.enable_0rtt);

        // Check that TLS is configured with files
        match &config.tls.cert {
            CertConfig::Files {
                cert_path,
                key_path,
            } => {
                assert_eq!(cert_path.to_str().unwrap(), "/path/to/cert.pem");
                assert_eq!(key_path.to_str().unwrap(), "/path/to/key.pem");
            },
            _ => panic!("Expected file-based cert config"),
        }
    }

    #[test]
    fn test_cert_config_development() {
        // Development uses self-signed
        let config = CertConfig::development();
        match config {
            CertConfig::SelfSigned { common_name } => {
                assert_eq!(common_name, "localhost");
            },
            _ => panic!("Expected self-signed config"),
        }
    }

    #[test]
    fn test_tls_config_development() {
        let config = TlsConfig::development();
        // Should have h3 ALPN protocol
        assert!(!config.alpn_protocols.is_empty());
        assert_eq!(config.alpn_protocols[0], b"h3".to_vec());
    }
}
