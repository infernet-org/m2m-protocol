//! OpenAI-compatible proxy server with transparent M2M compression.
//!
//! This proxy acts as a drop-in replacement for OpenAI/OpenRouter endpoints,
//! automatically compressing requests and decompressing responses.
//!
//! # Architecture
//!
//! ```text
//! Client App          M2M Proxy              LLM Provider
//!     |                   |                       |
//!     |-- POST /v1/chat --|                       |
//!     |   (normal JSON)   |                       |
//!     |                   |-- M2M compressed ---->|
//!     |                   |<-- M2M compressed ----|
//!     |<-- normal JSON ---|   (or SSE stream)     |
//!     |   (or SSE)        |                       |
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use m2m::proxy::{ProxyServer, ProxyConfig};
//!
//! let config = ProxyConfig {
//!     listen_addr: "127.0.0.1:8080".parse().unwrap(),
//!     upstream_url: "https://openrouter.ai/api/v1".to_string(),
//!     api_key: Some("sk-...".to_string()),
//!     compress_requests: true,
//!     compress_responses: true,
//! };
//!
//! let server = ProxyServer::new(config);
//! server.run().await?;
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::stream::StreamExt;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::codec::{Algorithm, CodecEngine};
use crate::error::Result;
use crate::security::SecurityScanner;

use super::stats::{ProxyStats, StatsSummary};

/// Proxy server configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on
    pub listen_addr: SocketAddr,
    /// Upstream LLM API URL (e.g., "https://openrouter.ai/api/v1")
    pub upstream_url: String,
    /// API key for upstream (optional, can use client's key)
    pub api_key: Option<String>,
    /// Whether to compress outgoing requests
    pub compress_requests: bool,
    /// Whether to compress incoming responses
    pub compress_responses: bool,
    /// Enable security scanning
    pub security_scanning: bool,
    /// Security blocking threshold (0.0-1.0)
    pub security_threshold: f32,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            upstream_url: "https://openrouter.ai/api/v1".to_string(),
            api_key: None,
            compress_requests: true,
            compress_responses: true,
            security_scanning: true,
            security_threshold: 0.8,
            timeout_secs: 120,
        }
    }
}

/// Shared proxy state
pub struct ProxyState {
    config: ProxyConfig,
    client: Client,
    codec: CodecEngine,
    scanner: SecurityScanner,
    stats: ProxyStats,
    shutdown_tx: broadcast::Sender<()>,
}

impl ProxyState {
    fn new(config: ProxyConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        let scanner = SecurityScanner::new().with_blocking(config.security_threshold);

        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            client,
            codec: CodecEngine::new(),
            scanner,
            stats: ProxyStats::new(),
            shutdown_tx,
        }
    }
}

/// M2M Proxy Server
pub struct ProxyServer {
    state: Arc<ProxyState>,
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            state: Arc::new(ProxyState::new(config)),
        }
    }

    /// Get the router for the proxy
    pub fn router(&self) -> Router {
        Router::new()
            // Health and status
            .route("/health", get(health_handler))
            .route("/stats", get(stats_handler))
            .route("/stats/reset", post(reset_stats_handler))
            // OpenAI-compatible endpoints
            .route("/v1/chat/completions", post(chat_completions_handler))
            .route("/chat/completions", post(chat_completions_handler))
            // Direct compression endpoints
            .route("/v1/compress", post(compress_handler))
            .route("/v1/decompress", post(decompress_handler))
            .with_state(self.state.clone())
    }

    /// Run the proxy server
    pub async fn run(&self) -> Result<()> {
        let addr = self.state.config.listen_addr;
        let router = self.router();

        tracing::info!("M2M Proxy listening on {}", addr);
        tracing::info!("Upstream: {}", self.state.config.upstream_url);
        tracing::info!(
            "Compression: requests={}, responses={}",
            self.state.config.compress_requests,
            self.state.config.compress_responses
        );

        let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
            crate::error::M2MError::Server(format!("Failed to bind to {}: {}", addr, e))
        })?;

        axum::serve(listener, router)
            .await
            .map_err(|e| crate::error::M2MError::Server(format!("Server error: {}", e)))?;

        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> StatsSummary {
        self.state.stats.summary()
    }

    /// Send shutdown signal
    pub fn shutdown(&self) {
        let _ = self.state.shutdown_tx.send(());
    }
}

// === Handlers ===

async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "m2m-proxy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn stats_handler(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    Json(state.stats.summary())
}

async fn reset_stats_handler(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    state.stats.reset();
    Json(json!({"status": "reset"}))
}

/// Main chat completions handler - supports both streaming and non-streaming
async fn chat_completions_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let start = Instant::now();

    // Security scan if enabled
    if state.config.security_scanning {
        let content = serde_json::to_string(&payload).unwrap_or_default();
        match state.scanner.scan(&content) {
            Ok(result) if !result.safe => {
                state.stats.record_error();
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": {
                            "message": "Content blocked by security scan",
                            "type": "security_error",
                            "threats": result.threats.iter().map(|t| &t.name).collect::<Vec<_>>()
                        }
                    })),
                )
                    .into_response();
            },
            Err(e) => {
                tracing::warn!("Security scan failed: {}", e);
            },
            _ => {},
        }
    }

    // Check if streaming requested
    let is_streaming = payload
        .get("stream")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if is_streaming {
        handle_streaming_request(state, headers, payload, start).await
    } else {
        handle_regular_request(state, headers, payload, start).await
    }
}

/// Handle non-streaming chat completion
async fn handle_regular_request(
    state: Arc<ProxyState>,
    headers: HeaderMap,
    payload: Value,
    start: Instant,
) -> Response {
    let request_json = serde_json::to_string(&payload).unwrap_or_default();
    let original_size = request_json.len();

    // Optionally compress request
    let (body, content_type) = if state.config.compress_requests {
        match state.codec.compress(&request_json, Algorithm::Token) {
            Ok(result) => (result.data, "application/x-m2m"),
            Err(_) => (request_json, "application/json"),
        }
    } else {
        (request_json, "application/json")
    };

    // Build upstream request
    let upstream_url = format!("{}/chat/completions", state.config.upstream_url);

    let mut request = state
        .client
        .post(&upstream_url)
        .header("Content-Type", content_type)
        .body(body.clone());

    // Forward authorization
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, auth);
    } else if let Some(ref api_key) = state.config.api_key {
        request = request.header(header::AUTHORIZATION, format!("Bearer {}", api_key));
    }

    // Forward other relevant headers
    if let Some(referer) = headers.get(header::REFERER) {
        request = request.header(header::REFERER, referer);
    }
    if let Some(title) = headers.get("X-Title") {
        request = request.header("X-Title", title);
    }

    // Send request
    match request.send().await {
        Ok(response) => {
            let status = response.status();

            match response.bytes().await {
                Ok(bytes) => {
                    let _response_size = bytes.len();

                    // Decompress if M2M format
                    let response_body = if let Ok(text) = std::str::from_utf8(&bytes) {
                        if crate::codec::is_m2m_format(text) {
                            match state.codec.decompress(text) {
                                Ok(decompressed) => decompressed,
                                Err(_) => text.to_string(),
                            }
                        } else {
                            text.to_string()
                        }
                    } else {
                        String::from_utf8_lossy(&bytes).to_string()
                    };

                    let latency = start.elapsed();
                    state
                        .stats
                        .record_request(original_size, body.len(), latency);

                    (
                        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
                        [(header::CONTENT_TYPE, "application/json")],
                        response_body,
                    )
                        .into_response()
                },
                Err(e) => {
                    state.stats.record_error();
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({
                            "error": {
                                "message": format!("Failed to read upstream response: {}", e),
                                "type": "proxy_error"
                            }
                        })),
                    )
                        .into_response()
                },
            }
        },
        Err(e) => {
            state.stats.record_error();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {
                        "message": format!("Failed to connect to upstream: {}", e),
                        "type": "proxy_error"
                    }
                })),
            )
                .into_response()
        },
    }
}

/// Handle streaming chat completion
async fn handle_streaming_request(
    state: Arc<ProxyState>,
    headers: HeaderMap,
    payload: Value,
    _start: Instant,
) -> Response {
    state.stats.record_streaming_request();

    let request_json = serde_json::to_string(&payload).unwrap_or_default();

    // Optionally compress request
    let (body, content_type) = if state.config.compress_requests {
        match state.codec.compress(&request_json, Algorithm::Token) {
            Ok(result) => (result.data, "application/x-m2m"),
            Err(_) => (request_json, "application/json"),
        }
    } else {
        (request_json, "application/json")
    };

    let _bytes_in = body.len();

    // Build upstream request
    let upstream_url = format!("{}/chat/completions", state.config.upstream_url);

    let mut request = state
        .client
        .post(&upstream_url)
        .header("Content-Type", content_type)
        .body(body);

    // Forward authorization
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, auth);
    } else if let Some(ref api_key) = state.config.api_key {
        request = request.header(header::AUTHORIZATION, format!("Bearer {}", api_key));
    }

    // Send request and stream response
    match request.send().await {
        Ok(response) => {
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                state.stats.record_error();
                return (
                    StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                    body,
                )
                    .into_response();
            }

            // Create streaming response
            let _stats = Arc::new(state.stats.summary());
            let _compress = state.config.compress_responses;

            let stream = response.bytes_stream().map(move |chunk| {
                match chunk {
                    Ok(bytes) => {
                        // For now, pass through SSE chunks
                        // In production, we'd compress each chunk
                        Ok::<_, std::io::Error>(bytes)
                    },
                    Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                }
            });

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header(header::CACHE_CONTROL, "no-cache")
                .header(header::CONNECTION, "keep-alive")
                .body(Body::from_stream(stream))
                .unwrap()
        },
        Err(e) => {
            state.stats.record_error();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": {
                        "message": format!("Failed to connect to upstream: {}", e),
                        "type": "proxy_error"
                    }
                })),
            )
                .into_response()
        },
    }
}

/// Direct compression endpoint
async fn compress_handler(State(state): State<Arc<ProxyState>>, body: String) -> impl IntoResponse {
    match state.codec.compress(&body, Algorithm::Token) {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({
                "compressed": result.data,
                "original_bytes": result.original_bytes,
                "compressed_bytes": result.compressed_bytes,
                "ratio": result.byte_ratio()
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Compression failed: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Direct decompression endpoint
async fn decompress_handler(
    State(state): State<Arc<ProxyState>>,
    body: String,
) -> impl IntoResponse {
    match state.codec.decompress(&body) {
        Ok(decompressed) => (StatusCode::OK, decompressed).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Decompression failed: {}", e)
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(config.compress_requests);
        assert!(config.compress_responses);
    }

    #[test]
    fn test_proxy_state_creation() {
        let config = ProxyConfig::default();
        let state = ProxyState::new(config);
        assert_eq!(state.stats.total_requests(), 0);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config);
        let _app = server.router();

        let _response = axum::http::Request::builder()
            .method("GET")
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        // Note: Would need tower::ServiceExt for full testing
        // This just verifies the router builds correctly
    }
}
