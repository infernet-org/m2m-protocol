//! OpenAI-compatible proxy with transparent M2M compression.
//!
//! This module provides a drop-in proxy server that sits between your application
//! and LLM providers (OpenAI, OpenRouter, etc.), automatically compressing
//! requests and responses using M2M protocol.
//!
//! # Features
//!
//! - **Drop-in replacement**: Use same endpoints as OpenAI API
//! - **Transparent compression**: Requests/responses compressed automatically
//! - **Streaming support**: SSE streams compressed in real-time
//! - **Security scanning**: Block prompt injection attempts
//! - **Statistics**: Track compression savings and latencies
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      M2M Proxy                               │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  Client App ──────> Security ──────> Compress ──────>       │
//! │                      Scanner         Request                 │
//! │                                         │                    │
//! │                                         v                    │
//! │                                   ┌──────────┐               │
//! │                                   │ Upstream │               │
//! │                                   │   LLM    │               │
//! │                                   └──────────┘               │
//! │                                         │                    │
//! │  Client App <────── Decompress <────────┘                   │
//! │               (or stream chunks)                             │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use m2m::proxy::{ProxyServer, ProxyConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = ProxyConfig {
//!         listen_addr: "0.0.0.0:8080".parse().unwrap(),
//!         upstream_url: "https://openrouter.ai/api/v1".to_string(),
//!         api_key: std::env::var("OPENROUTER_API_KEY").ok(),
//!         ..Default::default()
//!     };
//!
//!     let server = ProxyServer::new(config);
//!     server.run().await.unwrap();
//! }
//! ```
//!
//! # Endpoints
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/health` | GET | Health check |
//! | `/stats` | GET | Compression statistics |
//! | `/v1/chat/completions` | POST | OpenAI-compatible chat endpoint |
//! | `/v1/compress` | POST | Direct compression |
//! | `/v1/decompress` | POST | Direct decompression |
//!
//! # Client Configuration
//!
//! Point your OpenAI client at the proxy:
//!
//! ```python
//! # Python
//! from openai import OpenAI
//!
//! client = OpenAI(
//!     base_url="http://localhost:8080/v1",
//!     api_key="your-api-key"
//! )
//! ```
//!
//! ```javascript
//! // JavaScript
//! const openai = new OpenAI({
//!     baseURL: "http://localhost:8080/v1",
//!     apiKey: "your-api-key"
//! });
//! ```

mod server;
mod stats;

pub use server::{ProxyConfig, ProxyServer};
pub use stats::{ProxyStats, StatsSummary};
