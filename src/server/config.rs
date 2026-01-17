//! Server configuration.

use std::net::SocketAddr;
use std::time::Duration;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address
    pub addr: SocketAddr,
    /// Enable security scanning
    pub security_enabled: bool,
    /// Security blocking mode
    pub security_blocking: bool,
    /// Security block threshold
    pub block_threshold: f32,
    /// Session timeout
    pub session_timeout: Duration,
    /// Maximum request body size (bytes)
    pub max_body_size: usize,
    /// Enable request logging
    pub logging: bool,
    /// CORS enabled
    pub cors_enabled: bool,
    /// Model path (optional)
    pub model_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:3000".parse().unwrap(),
            security_enabled: true,
            security_blocking: false,
            block_threshold: 0.8,
            session_timeout: Duration::from_secs(300),
            max_body_size: 10 * 1024 * 1024, // 10MB
            logging: true,
            cors_enabled: true,
            model_path: None,
        }
    }
}

impl ServerConfig {
    /// Create with custom port
    pub fn with_port(mut self, port: u16) -> Self {
        self.addr = format!("127.0.0.1:{port}").parse().unwrap();
        self
    }

    /// Bind to all interfaces
    pub fn bind_all(mut self) -> Self {
        let port = self.addr.port();
        self.addr = format!("0.0.0.0:{port}").parse().unwrap();
        self
    }

    /// Set address directly
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.addr = addr;
        self
    }

    /// Enable security blocking
    pub fn with_security_blocking(mut self, threshold: f32) -> Self {
        self.security_blocking = true;
        self.block_threshold = threshold;
        self
    }

    /// Disable security
    pub fn without_security(mut self) -> Self {
        self.security_enabled = false;
        self
    }

    /// Set model path
    pub fn with_model(mut self, path: &str) -> Self {
        self.model_path = Some(path.to_string());
        self
    }

    /// Set session timeout
    pub fn with_session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Set max body size
    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Disable logging
    pub fn without_logging(mut self) -> Self {
        self.logging = false;
        self
    }

    /// Disable CORS
    pub fn without_cors(mut self) -> Self {
        self.cors_enabled = false;
        self
    }
}
