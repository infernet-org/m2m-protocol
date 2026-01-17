//! M2M Protocol HTTP server.
//!
//! Provides an HTTP API for M2M protocol operations:
//! - Session management (handshake)
//! - Compression/decompression
//! - Security scanning
//!
//! # Example
//!
//! ```rust,ignore
//! use m2m::server::{Server, ServerConfig};
//!
//! let config = ServerConfig::default().with_port(8080);
//! let server = Server::new(config);
//! server.run().await?;
//! ```

mod config;
mod handlers;
mod state;

pub use config::ServerConfig;
pub use handlers::{create_router, health_check};
pub use state::{AppState, SessionManager};
