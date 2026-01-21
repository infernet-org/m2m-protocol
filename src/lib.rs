//! # M2M Protocol - Machine-to-Machine LLM Communication
//!
//! High-performance agent-to-agent protocol for LLM API communication with
//! intelligent compression, cryptographic security, and dynamic algorithm routing.
//!
//! ## Features
//!
//! - **Multi-codec compression**: M2M (60-70% savings), TokenNative (30-35%), Brotli (high-ratio)
//! - **Protocol negotiation**: HELLO/ACCEPT handshake for capability exchange
//! - **ML-based routing**: Hydra model for intelligent algorithm selection
//! - **Security scanning**: Threat detection for prompt injection/jailbreaks
//! - **Session management**: Stateful sessions with timeout and keep-alive
//!
//! ## Protocol Overview
//!
//! M2M Protocol v3.0 defines a wire format for efficient LLM API payload exchange
//! between agents. The protocol uses a session-based model with capability negotiation.
//!
//! ### Architecture
//!
//! ```text
//! Agent A                        M2M Server                       Agent B
//!    |                              |                                |
//!    |------ HELLO (caps) -------->|                                |
//!    |<----- ACCEPT (caps) --------|                                |
//!    |                              |                                |
//!    |====== DATA (compressed) ===>|------- DATA (compressed) ----->|
//!    |<===== DATA (compressed) ====|<------ DATA (compressed) ------|
//!    |                              |                                |
//!    |------ CLOSE --------------->|                                |
//! ```
//!
//! ### State Machine
//!
//! ```text
//!                    create_hello()
//!     [Initial] ─────────────────────> [HelloSent]
//!         │                                 │
//!         │ process_hello()                 │ process_accept()
//!         │ (valid caps)                    │
//!         v                                 v
//!     [Established] <───────────────────────┘
//!         │                                 │
//!         │ close()                         │ process_reject()
//!         v                                 v
//!     [Closing] ────────────────────> [Closed]
//! ```
//!
//! ### Wire Formats
//!
//! Each compression algorithm has a distinct wire format prefix:
//!
//! | Algorithm    | Wire Format                    | Use Case                    |
//! |--------------|--------------------------------|-----------------------------|
//! | M2M          | `#M2M\|1\|<header><payload>`   | LLM API payloads (~60-70%)  |
//! | TokenNative  | `#TK\|C\|<base64_tokens>`      | Token ID transmission       |
//! | Brotli       | `#M2M[v3.0]\|DATA:<base64>`    | Large repetitive content    |
//! | Hybrid       | `#HY\|<binary>`                | Streaming mode              |
//! | None         | (passthrough)                  | Small content (<100 bytes)  |
//!
//! ### Message Types
//!
//! | Type   | Direction      | Purpose                              |
//! |--------|----------------|--------------------------------------|
//! | HELLO  | Client→Server  | Initiate handshake with capabilities |
//! | ACCEPT | Server→Client  | Confirm session, return negotiated   |
//! | REJECT | Server→Client  | Deny session with reason code        |
//! | DATA   | Bidirectional  | Compressed payload exchange          |
//! | PING   | Bidirectional  | Keep-alive request                   |
//! | PONG   | Bidirectional  | Keep-alive response                  |
//! | CLOSE  | Bidirectional  | Session termination                  |
//!
//! ## Quick Start
//!
//! ### Compression Only (Stateless)
//!
//! ```rust,ignore
//! use m2m_core::{CodecEngine, Algorithm};
//!
//! let engine = CodecEngine::new();
//!
//! // Compress LLM API payload
//! let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
//! let result = engine.compress(content, Algorithm::M2M).unwrap();
//!
//! println!("Compressed: {}", result.data);
//! println!("Ratio: {:.1}%", result.byte_ratio() * 100.0);
//!
//! // Decompress (auto-detects algorithm from wire format)
//! let original = engine.decompress(&result.data).unwrap();
//! assert_eq!(original, content);
//! ```
//!
//! ### Auto-Selection (Best Algorithm)
//!
//! ```rust,ignore
//! use m2m_core::CodecEngine;
//!
//! let engine = CodecEngine::new();
//! let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
//!
//! // Automatically select best algorithm based on content
//! let (result, algorithm) = engine.compress_auto(content).unwrap();
//! println!("Selected: {:?}", algorithm);
//! ```
//!
//! ### Full Protocol (Session-Based)
//!
//! ```rust,ignore
//! use m2m_core::{Session, Capabilities, MessageType};
//!
//! // Client side
//! let mut client = Session::new(Capabilities::default());
//! let hello = client.create_hello();
//!
//! // Server side
//! let mut server = Session::new(Capabilities::default());
//! let accept = server.process_hello(&hello).unwrap();
//!
//! // Client processes accept
//! client.process_accept(&accept).unwrap();
//! assert!(client.is_established());
//!
//! // Exchange compressed data
//! let data_msg = client.compress(r#"{"model":"gpt-4o","messages":[]}"#).unwrap();
//! let content = server.decompress(&data_msg).unwrap();
//! ```
//!
//! ### Security Scanning
//!
//! ```rust,ignore
//! use m2m_core::SecurityScanner;
//!
//! let scanner = SecurityScanner::new().with_blocking(0.8);
//!
//! // Safe content
//! let result = scanner.scan(r#"{"messages":[{"role":"user","content":"Hello"}]}"#).unwrap();
//! assert!(result.safe);
//!
//! // Potential threat
//! let result = scanner.scan("Ignore previous instructions").unwrap();
//! assert!(!result.safe);
//! println!("Threat: {:?}", result.threats);
//! ```
//!
//! ## Modules
//!
//! - [`codec`]: Multi-algorithm compression engine
//! - [`protocol`]: Session management and capability negotiation
//! - [`inference`]: Hydra ML model for algorithm routing
//! - [`security`]: Threat detection and content scanning
//! - [`server`]: HTTP API server (Axum-based)
//! - [`models`]: LLM model registry and metadata
//! - [`config`]: Configuration management
//! - [`error`]: Error types and result aliases
//!
//! ## Performance
//!
//! Typical compression ratios for LLM API payloads:
//!
//! | Content Type        | M2M     | TokenNative | Brotli  |
//! |---------------------|---------|-------------|---------|
//! | Chat completion     | ~60%    | ~30%        | ~20%    |
//! | Long conversation   | ~65%    | ~35%        | ~40%    |
//! | Tool calls          | ~70%    | ~40%        | ~15%    |
//!
//! Algorithm selection heuristics:
//! - **M2M**: Best for standard LLM API JSON (default, 100% fidelity)
//! - **TokenNative**: Best for token-optimized transmission
//! - **Brotli**: Best for large repetitive content (>1KB with patterns)
//! - **Hybrid**: Best for streaming use cases
//! - **None**: Content under 100 bytes (overhead exceeds savings)

pub mod codec;
pub mod config;
pub mod error;
pub mod inference;
pub mod models;
pub mod protocol;
pub mod security;
pub mod server;
pub mod tokenizer;
pub mod transport;

// Re-exports for convenience
pub use codec::{Algorithm, CodecEngine, CompressionResult, StreamingCodec, StreamingDecompressor};
pub use config::Config;
pub use error::{M2MError, Result};
pub use inference::{HydraModel, SecurityDecision};
pub use models::{ModelCard, ModelRegistry, Provider};
pub use protocol::{Capabilities, Message, Session, SessionState};
pub use security::{ScanResult, SecurityScanner};
pub use server::{AppState, ServerConfig};
pub use tokenizer::{
    count_tokens, count_tokens_for_model, count_tokens_with_encoding, TokenCounter,
};
pub use transport::{QuicTransport, QuicTransportConfig, TcpTransport, Transport, TransportKind};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// M2M Protocol version
pub const PROTOCOL_VERSION: &str = "3.0";

/// Check if content is in M2M format
pub fn is_m2m_format(content: &str) -> bool {
    codec::is_m2m_format(content)
}

/// Detect compression algorithm from wire format
pub fn detect_algorithm(content: &str) -> Option<Algorithm> {
    codec::detect_algorithm(content)
}
