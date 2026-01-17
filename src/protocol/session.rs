//! Session management for M2M protocol.
//!
//! Handles the lifecycle of agent-to-agent sessions including
//! handshake, data exchange, and termination.

use std::time::{Duration, Instant};

use super::capabilities::{Capabilities, NegotiatedCaps};
use super::message::{Message, MessageType, RejectionCode};
use super::SESSION_TIMEOUT_SECS;
use crate::codec::{Algorithm, CodecEngine};
use crate::error::{M2MError, Result};

/// Session state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, no handshake yet
    Initial,
    /// HELLO sent, waiting for ACCEPT/REJECT
    HelloSent,
    /// Session established, ready for data
    Established,
    /// Session closing
    Closing,
    /// Session closed
    Closed,
}

/// M2M protocol session
pub struct Session {
    /// Session ID
    id: String,
    /// Current state
    state: SessionState,
    /// Local capabilities
    local_caps: Capabilities,
    /// Remote capabilities (after handshake)
    remote_caps: Option<Capabilities>,
    /// Negotiated capabilities
    negotiated: Option<NegotiatedCaps>,
    /// Codec engine
    codec: CodecEngine,
    /// Last activity timestamp
    last_activity: Instant,
    /// Session timeout duration
    timeout: Duration,
    /// Messages sent
    messages_sent: u64,
    /// Messages received
    messages_received: u64,
    /// Bytes compressed
    bytes_compressed: u64,
    /// Bytes saved
    bytes_saved: u64,
}

impl Session {
    /// Create new session with capabilities
    pub fn new(capabilities: Capabilities) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            state: SessionState::Initial,
            local_caps: capabilities,
            remote_caps: None,
            negotiated: None,
            codec: CodecEngine::new(),
            last_activity: Instant::now(),
            timeout: Duration::from_secs(SESSION_TIMEOUT_SECS),
            messages_sent: 0,
            messages_received: 0,
            bytes_compressed: 0,
            bytes_saved: 0,
        }
    }

    /// Create session with existing ID (for server-side)
    pub fn with_id(id: &str, capabilities: Capabilities) -> Self {
        let mut session = Self::new(capabilities);
        session.id = id.to_string();
        session
    }

    /// Get session ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get current state
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if session is established
    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > self.timeout
    }

    /// Get negotiated algorithm
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.negotiated.as_ref().map(|n| n.algorithm)
    }

    /// Create HELLO message to initiate handshake
    pub fn create_hello(&mut self) -> Message {
        self.state = SessionState::HelloSent;
        self.messages_sent += 1;
        self.touch();
        Message::hello(self.local_caps.clone())
    }

    /// Process incoming HELLO and create ACCEPT/REJECT response
    pub fn process_hello(&mut self, hello: &Message) -> Result<Message> {
        if self.state != SessionState::Initial {
            return Err(M2MError::Protocol(format!(
                "Cannot process HELLO in state {:?}",
                self.state
            )));
        }

        let remote_caps = hello
            .get_capabilities()
            .ok_or_else(|| M2MError::InvalidMessage("HELLO missing capabilities".to_string()))?;

        self.messages_received += 1;
        self.touch();

        // Check version compatibility
        if !self.local_caps.is_compatible(remote_caps) {
            return Ok(Message::reject(
                RejectionCode::VersionMismatch,
                &format!(
                    "Version {} not compatible with {}",
                    remote_caps.version, self.local_caps.version
                ),
            ));
        }

        // Negotiate capabilities
        match self.local_caps.negotiate(remote_caps) {
            Some(negotiated) => {
                self.remote_caps = Some(remote_caps.clone());
                self.negotiated = Some(negotiated);
                self.state = SessionState::Established;

                // Configure codec based on negotiated caps
                if let Some(ref neg) = self.negotiated {
                    self.codec = self.codec.clone().with_ml_routing(neg.ml_routing);
                }

                self.messages_sent += 1;
                Ok(Message::accept(&self.id, self.local_caps.clone()))
            },
            None => Ok(Message::reject(
                RejectionCode::NoCommonAlgorithm,
                "No common compression algorithm",
            )),
        }
    }

    /// Process incoming ACCEPT message
    pub fn process_accept(&mut self, accept: &Message) -> Result<()> {
        if self.state != SessionState::HelloSent {
            return Err(M2MError::Protocol(format!(
                "Cannot process ACCEPT in state {:?}",
                self.state
            )));
        }

        let remote_caps = accept
            .get_capabilities()
            .ok_or_else(|| M2MError::InvalidMessage("ACCEPT missing capabilities".to_string()))?;

        let session_id = accept
            .session_id
            .as_ref()
            .ok_or_else(|| M2MError::InvalidMessage("ACCEPT missing session ID".to_string()))?;

        self.messages_received += 1;
        self.touch();

        // Update session ID from server
        self.id = session_id.clone();

        // Negotiate and store
        match self.local_caps.negotiate(remote_caps) {
            Some(negotiated) => {
                self.remote_caps = Some(remote_caps.clone());
                self.negotiated = Some(negotiated);
                self.state = SessionState::Established;

                // Configure codec
                if let Some(ref neg) = self.negotiated {
                    self.codec = self.codec.clone().with_ml_routing(neg.ml_routing);
                }

                Ok(())
            },
            None => Err(M2MError::NegotiationFailed(
                "Failed to negotiate capabilities".to_string(),
            )),
        }
    }

    /// Process incoming REJECT message
    pub fn process_reject(&mut self, reject: &Message) -> Result<()> {
        self.messages_received += 1;
        self.state = SessionState::Closed;

        let rejection = reject.get_rejection();
        let reason = rejection
            .map(|r| format!("{:?}: {}", r.code, r.message))
            .unwrap_or_else(|| "Unknown rejection".to_string());

        Err(M2MError::NegotiationFailed(reason))
    }

    /// Compress and create DATA message
    pub fn compress(&mut self, content: &str) -> Result<Message> {
        if !self.is_established() {
            return Err(M2MError::SessionNotEstablished);
        }

        if self.is_expired() {
            return Err(M2MError::SessionExpired);
        }

        let algorithm = self.algorithm().unwrap_or(Algorithm::Token);
        let result = self.codec.compress(content, algorithm)?;

        // Update stats
        self.bytes_compressed += result.compressed_bytes as u64;
        if result.original_bytes > result.compressed_bytes {
            self.bytes_saved += (result.original_bytes - result.compressed_bytes) as u64;
        }
        self.messages_sent += 1;
        self.touch();

        Ok(Message::data(&self.id, algorithm, result.data))
    }

    /// Decompress DATA message content
    pub fn decompress(&mut self, message: &Message) -> Result<String> {
        if !self.is_established() {
            return Err(M2MError::SessionNotEstablished);
        }

        if self.is_expired() {
            return Err(M2MError::SessionExpired);
        }

        let data = message
            .get_data()
            .ok_or_else(|| M2MError::InvalidMessage("Not a DATA message".to_string()))?;

        self.messages_received += 1;
        self.touch();

        self.codec.decompress(&data.content)
    }

    /// Process any incoming message
    pub fn process_message(&mut self, message: &Message) -> Result<Option<Message>> {
        self.touch();

        match message.msg_type {
            MessageType::Hello => {
                let response = self.process_hello(message)?;
                Ok(Some(response))
            },
            MessageType::Accept => {
                self.process_accept(message)?;
                Ok(None)
            },
            MessageType::Reject => {
                self.process_reject(message)?;
                Ok(None)
            },
            MessageType::Ping => {
                self.messages_received += 1;
                self.messages_sent += 1;
                Ok(Some(Message::pong(&self.id)))
            },
            MessageType::Pong => {
                self.messages_received += 1;
                Ok(None)
            },
            MessageType::Close => {
                self.messages_received += 1;
                self.state = SessionState::Closed;
                Ok(None)
            },
            MessageType::Data => {
                // Data messages are processed via decompress()
                Ok(None)
            },
        }
    }

    /// Close the session
    pub fn close(&mut self) -> Message {
        self.state = SessionState::Closing;
        self.messages_sent += 1;
        Message::close(&self.id)
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            session_id: self.id.clone(),
            state: self.state,
            messages_sent: self.messages_sent,
            messages_received: self.messages_received,
            bytes_compressed: self.bytes_compressed,
            bytes_saved: self.bytes_saved,
            uptime_secs: self.last_activity.elapsed().as_secs(),
        }
    }

    /// Update last activity timestamp
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            state: self.state,
            local_caps: self.local_caps.clone(),
            remote_caps: self.remote_caps.clone(),
            negotiated: self.negotiated.clone(),
            codec: CodecEngine::new(), // Fresh codec
            last_activity: Instant::now(),
            timeout: self.timeout,
            messages_sent: 0,
            messages_received: 0,
            bytes_compressed: 0,
            bytes_saved: 0,
        }
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Session ID
    pub session_id: String,
    /// Current state
    pub state: SessionState,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Total bytes compressed
    pub bytes_compressed: u64,
    /// Bytes saved by compression
    pub bytes_saved: u64,
    /// Session uptime in seconds
    pub uptime_secs: u64,
}

impl SessionStats {
    /// Calculate compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.bytes_compressed == 0 {
            1.0
        } else {
            (self.bytes_compressed + self.bytes_saved) as f64 / self.bytes_compressed as f64
        }
    }

    /// Calculate savings percentage
    pub fn savings_percent(&self) -> f64 {
        let total = self.bytes_compressed + self.bytes_saved;
        if total == 0 {
            0.0
        } else {
            self.bytes_saved as f64 / total as f64 * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_handshake() {
        // Client side
        let mut client = Session::new(Capabilities::default());
        let hello = client.create_hello();
        assert_eq!(client.state(), SessionState::HelloSent);

        // Server side
        let mut server = Session::new(Capabilities::default());
        let accept = server.process_hello(&hello).unwrap();
        assert_eq!(server.state(), SessionState::Established);
        assert_eq!(accept.msg_type, MessageType::Accept);

        // Client processes accept
        client.process_accept(&accept).unwrap();
        assert_eq!(client.state(), SessionState::Established);
        assert_eq!(client.id(), server.id()); // IDs should match
    }

    #[test]
    fn test_session_reject() {
        let mut client = Session::new(Capabilities::new("client"));
        let hello = client.create_hello();

        // Server with incompatible version
        let server_caps = Capabilities {
            version: "4.0".to_string(),
            ..Default::default()
        };
        let mut server = Session::new(server_caps);

        let response = server.process_hello(&hello).unwrap();
        assert_eq!(response.msg_type, MessageType::Reject);

        // Client processes reject
        let result = client.process_reject(&response);
        assert!(result.is_err());
        assert_eq!(client.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_data_exchange() {
        // Establish session
        let mut client = Session::new(Capabilities::default());
        let mut server = Session::new(Capabilities::default());

        let hello = client.create_hello();
        let accept = server.process_hello(&hello).unwrap();
        client.process_accept(&accept).unwrap();

        // Send data from client
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
        let data_msg = client.compress(content).unwrap();

        // Server receives and decompresses
        let decompressed = server.decompress(&data_msg).unwrap();
        let original: serde_json::Value = serde_json::from_str(content).unwrap();
        let recovered: serde_json::Value = serde_json::from_str(&decompressed).unwrap();

        assert_eq!(
            original["messages"][0]["content"],
            recovered["messages"][0]["content"]
        );
    }

    #[test]
    fn test_session_stats() {
        let mut client = Session::new(Capabilities::default());
        let mut server = Session::new(Capabilities::default());

        let hello = client.create_hello();
        let accept = server.process_hello(&hello).unwrap();
        client.process_accept(&accept).unwrap();

        // Send some data
        for _ in 0..5 {
            let _ = client.compress(r#"{"test":"data"}"#);
        }

        let stats = client.stats();
        assert_eq!(stats.messages_sent, 6); // 1 hello + 5 data
        assert!(stats.bytes_compressed > 0);
    }
}
