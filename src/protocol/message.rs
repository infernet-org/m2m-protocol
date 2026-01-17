//! Protocol messages for M2M communication.
//!
//! Defines the wire format for HELLO, ACCEPT, REJECT, and DATA messages.

use serde::{Deserialize, Serialize};

use super::Capabilities;
use crate::codec::Algorithm;

/// Message types in the M2M protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum MessageType {
    /// Initial handshake message
    Hello,
    /// Positive handshake response
    Accept,
    /// Negative handshake response
    Reject,
    /// Data payload
    Data,
    /// Keep-alive ping
    Ping,
    /// Ping response
    Pong,
    /// Session termination
    Close,
}

/// Protocol message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message type
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    /// Session ID (empty for HELLO)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Message payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<MessagePayload>,
    /// Timestamp (Unix millis)
    pub timestamp: u64,
}

/// Message payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessagePayload {
    /// Capabilities for HELLO/ACCEPT
    Capabilities(Capabilities),
    /// Rejection reason
    Rejection(RejectionInfo),
    /// Compressed data
    Data(DataPayload),
    /// Empty (for PING/PONG/CLOSE)
    Empty {},
}

/// Rejection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionInfo {
    /// Rejection reason code
    pub code: RejectionCode,
    /// Human-readable message
    pub message: String,
}

/// Rejection reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionCode {
    /// Version mismatch
    VersionMismatch,
    /// No common compression algorithm
    NoCommonAlgorithm,
    /// Security policy violation
    SecurityPolicy,
    /// Rate limited
    RateLimited,
    /// Unknown/other error
    Unknown,
}

/// Data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPayload {
    /// Compression algorithm used
    pub algorithm: Algorithm,
    /// Compressed content
    pub content: String,
    /// Original size (for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_size: Option<usize>,
    /// Security scan result (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_status: Option<SecurityStatus>,
}

/// Security scan status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    /// Was content scanned
    pub scanned: bool,
    /// Is content safe
    pub safe: bool,
    /// Threat type if detected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    /// Confidence score (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
}

impl Message {
    /// Create a HELLO message
    pub fn hello(capabilities: Capabilities) -> Self {
        Self {
            msg_type: MessageType::Hello,
            session_id: None,
            payload: Some(MessagePayload::Capabilities(capabilities)),
            timestamp: current_timestamp(),
        }
    }

    /// Create an ACCEPT message
    pub fn accept(session_id: &str, capabilities: Capabilities) -> Self {
        Self {
            msg_type: MessageType::Accept,
            session_id: Some(session_id.to_string()),
            payload: Some(MessagePayload::Capabilities(capabilities)),
            timestamp: current_timestamp(),
        }
    }

    /// Create a REJECT message
    pub fn reject(code: RejectionCode, message: &str) -> Self {
        Self {
            msg_type: MessageType::Reject,
            session_id: None,
            payload: Some(MessagePayload::Rejection(RejectionInfo {
                code,
                message: message.to_string(),
            })),
            timestamp: current_timestamp(),
        }
    }

    /// Create a DATA message
    pub fn data(session_id: &str, algorithm: Algorithm, content: String) -> Self {
        Self {
            msg_type: MessageType::Data,
            session_id: Some(session_id.to_string()),
            payload: Some(MessagePayload::Data(DataPayload {
                algorithm,
                content,
                original_size: None,
                security_status: None,
            })),
            timestamp: current_timestamp(),
        }
    }

    /// Create a DATA message with security status
    pub fn data_with_security(
        session_id: &str,
        algorithm: Algorithm,
        content: String,
        security: SecurityStatus,
    ) -> Self {
        Self {
            msg_type: MessageType::Data,
            session_id: Some(session_id.to_string()),
            payload: Some(MessagePayload::Data(DataPayload {
                algorithm,
                content,
                original_size: None,
                security_status: Some(security),
            })),
            timestamp: current_timestamp(),
        }
    }

    /// Create a PING message
    pub fn ping(session_id: &str) -> Self {
        Self {
            msg_type: MessageType::Ping,
            session_id: Some(session_id.to_string()),
            payload: Some(MessagePayload::Empty {}),
            timestamp: current_timestamp(),
        }
    }

    /// Create a PONG message
    pub fn pong(session_id: &str) -> Self {
        Self {
            msg_type: MessageType::Pong,
            session_id: Some(session_id.to_string()),
            payload: Some(MessagePayload::Empty {}),
            timestamp: current_timestamp(),
        }
    }

    /// Create a CLOSE message
    pub fn close(session_id: &str) -> Self {
        Self {
            msg_type: MessageType::Close,
            session_id: Some(session_id.to_string()),
            payload: Some(MessagePayload::Empty {}),
            timestamp: current_timestamp(),
        }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to JSON (compact)
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get capabilities from HELLO/ACCEPT payload
    pub fn get_capabilities(&self) -> Option<&Capabilities> {
        match &self.payload {
            Some(MessagePayload::Capabilities(caps)) => Some(caps),
            _ => None,
        }
    }

    /// Get data payload
    pub fn get_data(&self) -> Option<&DataPayload> {
        match &self.payload {
            Some(MessagePayload::Data(data)) => Some(data),
            _ => None,
        }
    }

    /// Get rejection info
    pub fn get_rejection(&self) -> Option<&RejectionInfo> {
        match &self.payload {
            Some(MessagePayload::Rejection(info)) => Some(info),
            _ => None,
        }
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_message() {
        let caps = Capabilities::default();
        let msg = Message::hello(caps);

        assert_eq!(msg.msg_type, MessageType::Hello);
        assert!(msg.session_id.is_none());
        assert!(msg.get_capabilities().is_some());

        let json = msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();
        assert_eq!(parsed.msg_type, MessageType::Hello);
    }

    #[test]
    fn test_accept_message() {
        let caps = Capabilities::default();
        let msg = Message::accept("session-123", caps);

        assert_eq!(msg.msg_type, MessageType::Accept);
        assert_eq!(msg.session_id, Some("session-123".to_string()));
    }

    #[test]
    fn test_reject_message() {
        let msg = Message::reject(RejectionCode::VersionMismatch, "Version 4.0 not supported");

        assert_eq!(msg.msg_type, MessageType::Reject);
        let rejection = msg.get_rejection().unwrap();
        assert_eq!(rejection.code, RejectionCode::VersionMismatch);
    }

    #[test]
    fn test_data_message() {
        let msg = Message::data(
            "session-123",
            Algorithm::Token,
            "#T1|{\"m\":[]}".to_string(),
        );

        assert_eq!(msg.msg_type, MessageType::Data);
        let data = msg.get_data().unwrap();
        assert_eq!(data.algorithm, Algorithm::Token);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let caps = Capabilities::new("test-agent").with_extension("custom", "value");
        let msg = Message::hello(caps);

        let json = msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();

        let caps = parsed.get_capabilities().unwrap();
        assert_eq!(caps.agent_type, "test-agent");
        assert_eq!(caps.extensions.get("custom"), Some(&"value".to_string()));
    }
}
