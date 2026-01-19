//! HTTP request handlers.

use std::sync::Arc;

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use super::state::AppState;
use crate::codec::Algorithm;
use crate::protocol::{Capabilities, Message, MessageType};

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health and status
        .route("/health", get(health_check))
        .route("/status", get(status))
        // Protocol operations
        .route("/session", post(create_session))
        .route("/session/{id}", get(get_session))
        .route("/session/{id}", axum::routing::delete(delete_session))
        // Compression operations
        .route("/compress", post(compress))
        .route("/decompress", post(decompress))
        .route("/compress/auto", post(compress_auto))
        // Security operations
        .route("/scan", post(scan_content))
        // Protocol messages
        .route("/message", post(process_message))
        .with_state(state)
}

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Status response
#[derive(Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_secs: u64,
    pub active_sessions: usize,
    pub capabilities: Capabilities,
}

/// Status endpoint
async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let session_count = state.sessions.count().await;

    Json(StatusResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.uptime().as_secs(),
        active_sessions: session_count,
        capabilities: state.capabilities(),
    })
}

/// Session create request
#[derive(Deserialize)]
pub struct CreateSessionRequest {
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
}

/// Session response
#[derive(Serialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub capabilities: Capabilities,
}

/// Create new session
async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let client_caps = req.capabilities.unwrap_or_default();
    let mut session = state.sessions.create(client_caps).await;

    // Create HELLO and process it
    let hello = session.create_hello();
    let _ = session.process_message(&hello);

    let response = SessionResponse {
        session_id: session.id().to_string(),
        capabilities: state.capabilities(),
    };

    state.sessions.update(&session).await;
    (StatusCode::CREATED, Json(response))
}

/// Get session info
async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.sessions.get(&id).await {
        Some(session) => {
            let stats = session.stats();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "session_id": stats.session_id,
                    "state": format!("{:?}", stats.state),
                    "messages_sent": stats.messages_sent,
                    "messages_received": stats.messages_received,
                    "bytes_compressed": stats.bytes_compressed,
                    "bytes_saved": stats.bytes_saved,
                    "compression_ratio": stats.compression_ratio(),
                })),
            )
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session not found"})),
        ),
    }
}

/// Delete session
async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.sessions.remove(&id).await;
    StatusCode::NO_CONTENT
}

/// Compress request
#[derive(Deserialize)]
pub struct CompressRequest {
    pub content: String,
    #[serde(default)]
    pub algorithm: Option<Algorithm>,
}

/// Compress response
#[derive(Serialize)]
#[allow(dead_code)]
pub struct CompressResponse {
    pub data: String,
    pub algorithm: Algorithm,
    pub original_bytes: usize,
    pub compressed_bytes: usize,
    pub ratio: f64,
}

/// Compress content
async fn compress(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CompressRequest>,
) -> impl IntoResponse {
    // Security check
    if state.config.security_enabled {
        let scan_result = state.scanner.scan(&req.content);
        if let Ok(result) = scan_result {
            if result.should_block {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "Content blocked by security scan",
                        "threats": result.threats.iter().map(|t| &t.name).collect::<Vec<_>>(),
                    })),
                );
            }
        }
    }

    let algorithm = req.algorithm.unwrap_or(Algorithm::M2M);

    match state.codec.compress(&req.content, algorithm) {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "data": result.data,
                "algorithm": result.algorithm,
                "original_bytes": result.original_bytes,
                "compressed_bytes": result.compressed_bytes,
                "ratio": result.byte_ratio(),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Auto-compress with best algorithm
async fn compress_auto(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CompressRequest>,
) -> impl IntoResponse {
    // Security check
    if state.config.security_enabled {
        if let Ok(result) = state.scanner.scan(&req.content) {
            if result.should_block {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "Content blocked by security scan",
                    })),
                );
            }
        }
    }

    match state.codec.compress_auto(&req.content) {
        Ok((result, _)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "data": result.data,
                "algorithm": result.algorithm,
                "original_bytes": result.original_bytes,
                "compressed_bytes": result.compressed_bytes,
                "ratio": result.byte_ratio(),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Decompress request
#[derive(Deserialize)]
pub struct DecompressRequest {
    pub data: String,
}

/// Decompress content
async fn decompress(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DecompressRequest>,
) -> impl IntoResponse {
    match state.codec.decompress(&req.data) {
        Ok(content) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "content": content,
                "bytes": content.len(),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Scan request
#[derive(Deserialize)]
pub struct ScanRequest {
    pub content: String,
}

/// Scan content for threats
async fn scan_content(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {
    match state.scanner.scan(&req.content) {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "safe": result.safe,
                "confidence": result.confidence,
                "threats": result.threats.iter().map(|t| serde_json::json!({
                    "name": t.name,
                    "category": t.category,
                    "severity": t.severity,
                    "description": t.description,
                })).collect::<Vec<_>>(),
                "should_block": result.should_block,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// Process protocol message
async fn process_message(
    State(state): State<Arc<AppState>>,
    Json(message): Json<Message>,
) -> impl IntoResponse {
    match message.msg_type {
        MessageType::Hello => {
            // Create new session and respond with ACCEPT
            let caps = message.get_capabilities().cloned().unwrap_or_default();
            let mut session = state.sessions.create(caps).await;

            match session.process_message(&message) {
                Ok(Some(response)) => {
                    state.sessions.update(&session).await;
                    (StatusCode::OK, Json(response))
                },
                Ok(None) => (
                    StatusCode::OK,
                    Json(Message::accept(session.id(), state.capabilities())),
                ),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(Message::reject(
                        crate::protocol::RejectionCode::Unknown,
                        &e.to_string(),
                    )),
                ),
            }
        },
        MessageType::Data => {
            // Process data message
            let Some(session_id) = message.session_id.as_ref() else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(Message::reject(
                        crate::protocol::RejectionCode::Unknown,
                        "Missing session ID",
                    )),
                );
            };

            match state.sessions.get(session_id).await {
                Some(mut session) => match session.decompress(&message) {
                    Ok(content) => {
                        state.sessions.update(&session).await;
                        (
                                StatusCode::OK,
                                Json(serde_json::from_str::<Message>(&format!(
                                    r#"{{"type":"DATA","session_id":"{session_id}","payload":{{"content":"{content}"}}}}"#
                                )).unwrap_or(message)),
                            )
                    },
                    Err(e) => (
                        StatusCode::BAD_REQUEST,
                        Json(Message::reject(
                            crate::protocol::RejectionCode::Unknown,
                            &e.to_string(),
                        )),
                    ),
                },
                None => (
                    StatusCode::NOT_FOUND,
                    Json(Message::reject(
                        crate::protocol::RejectionCode::Unknown,
                        "Session not found",
                    )),
                ),
            }
        },
        MessageType::Ping => {
            let session_id = message.session_id.as_deref().unwrap_or("unknown");
            (StatusCode::OK, Json(Message::pong(session_id)))
        },
        MessageType::Close => {
            if let Some(id) = &message.session_id {
                state.sessions.remove(id).await;
            }
            (StatusCode::OK, Json(message))
        },
        _ => (
            StatusCode::BAD_REQUEST,
            Json(Message::reject(
                crate::protocol::RejectionCode::Unknown,
                "Unsupported message type",
            )),
        ),
    }
}
