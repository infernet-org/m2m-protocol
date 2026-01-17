//! Server state and session management.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::config::ServerConfig;
use crate::codec::CodecEngine;
use crate::inference::HydraModel;
use crate::protocol::{Capabilities, Session};
use crate::security::SecurityScanner;

/// Application state shared across handlers
pub struct AppState {
    /// Server configuration
    pub config: ServerConfig,
    /// Session manager
    pub sessions: SessionManager,
    /// Codec engine
    pub codec: CodecEngine,
    /// Security scanner
    pub scanner: SecurityScanner,
    /// Hydra model (optional)
    pub model: Option<HydraModel>,
    /// Server start time
    pub start_time: Instant,
}

impl AppState {
    /// Create new application state
    pub fn new(config: ServerConfig) -> Self {
        let scanner = if config.security_enabled {
            if config.security_blocking {
                SecurityScanner::new().with_blocking(config.block_threshold)
            } else {
                SecurityScanner::new()
            }
        } else {
            SecurityScanner::new()
        };

        let model = config
            .model_path
            .as_ref()
            .and_then(|path| HydraModel::load(path).ok());

        Self {
            config,
            sessions: SessionManager::new(),
            codec: CodecEngine::new(),
            scanner,
            model,
            start_time: Instant::now(),
        }
    }

    /// Get server uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get server capabilities
    pub fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::new("m2m-server");

        if self.config.security_enabled {
            caps = caps.with_security(
                crate::protocol::SecurityCaps::default()
                    .with_threat_detection(crate::security::SECURITY_VERSION),
            );
        }

        if self.model.is_some() {
            caps.compression = caps.compression.with_ml_routing();
        }

        caps
    }
}

/// Manages active sessions
pub struct SessionManager {
    /// Active sessions by ID
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
    /// Session timeout
    timeout: Duration,
}

/// Session entry with metadata
struct SessionEntry {
    /// The session
    session: Session,
    /// Last access time
    last_access: Instant,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    /// Create new session manager
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout: Duration::from_secs(300),
        }
    }

    /// Set session timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Create a new session
    pub async fn create(&self, capabilities: Capabilities) -> Session {
        let session = Session::new(capabilities);
        let id = session.id().to_string();

        let entry = SessionEntry {
            session: session.clone(),
            last_access: Instant::now(),
        };

        self.sessions.write().await.insert(id, entry);
        session
    }

    /// Get session by ID
    pub async fn get(&self, id: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().await;

        if let Some(entry) = sessions.get_mut(id) {
            // Check expiry
            if entry.last_access.elapsed() > self.timeout {
                sessions.remove(id);
                return None;
            }

            entry.last_access = Instant::now();
            Some(entry.session.clone())
        } else {
            None
        }
    }

    /// Update session
    pub async fn update(&self, session: &Session) {
        let mut sessions = self.sessions.write().await;

        if let Some(entry) = sessions.get_mut(session.id()) {
            entry.session = session.clone();
            entry.last_access = Instant::now();
        }
    }

    /// Remove session
    pub async fn remove(&self, id: &str) {
        self.sessions.write().await.remove(id);
    }

    /// Get session count
    pub async fn count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Clean up expired sessions
    pub async fn cleanup(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();

        sessions.retain(|_, entry| entry.last_access.elapsed() < self.timeout);

        before - sessions.len()
    }

    /// Get all session IDs
    pub async fn list_ids(&self) -> Vec<String> {
        self.sessions.read().await.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_create_and_get() {
        let manager = SessionManager::new();
        let caps = Capabilities::default();

        let session = manager.create(caps).await;
        let id = session.id().to_string();

        let retrieved = manager.get(&id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id(), id);
    }

    #[tokio::test]
    async fn test_session_remove() {
        let manager = SessionManager::new();
        let caps = Capabilities::default();

        let session = manager.create(caps).await;
        let id = session.id().to_string();

        manager.remove(&id).await;

        let retrieved = manager.get(&id).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_session_count() {
        let manager = SessionManager::new();
        let caps = Capabilities::default();

        assert_eq!(manager.count().await, 0);

        manager.create(caps.clone()).await;
        manager.create(caps.clone()).await;
        manager.create(caps).await;

        assert_eq!(manager.count().await, 3);
    }

    #[tokio::test]
    async fn test_session_expiry() {
        let manager = SessionManager::new().with_timeout(Duration::from_millis(10));
        let caps = Capabilities::default();

        let session = manager.create(caps).await;
        let id = session.id().to_string();

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        let retrieved = manager.get(&id).await;
        assert!(retrieved.is_none());
    }
}
