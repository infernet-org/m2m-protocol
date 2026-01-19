//! End-to-end session management tests.
//!
//! These tests verify session lifecycle, timeout enforcement,
//! and message exchange beyond the unit test level.

use m2m::codec::Algorithm;
use m2m::protocol::{Capabilities, CompressionCaps, Message, MessageType, Session, SessionState};
use serde_json::json;

/// Test complete session handshake flow
#[test]
fn test_full_session_handshake() {
    // Create client and server with default capabilities
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    // Verify initial states
    assert_eq!(client.state(), SessionState::Initial);
    assert_eq!(server.state(), SessionState::Initial);

    // Client initiates handshake
    let hello = client.create_hello();
    assert_eq!(hello.msg_type, MessageType::Hello);
    assert_eq!(client.state(), SessionState::HelloSent);

    // Server processes hello and responds
    let accept = server.process_hello(&hello).unwrap();
    assert_eq!(accept.msg_type, MessageType::Accept);
    assert_eq!(server.state(), SessionState::Established);

    // Client processes accept
    client.process_accept(&accept).unwrap();
    assert_eq!(client.state(), SessionState::Established);

    // Both sessions should have matching IDs
    assert_eq!(client.id(), server.id());
    assert!(!client.id().is_empty());
}

/// Test session handles version mismatch gracefully
#[test]
fn test_session_version_mismatch_rejection() {
    let client_caps = Capabilities::default();
    let mut client = Session::new(client_caps);

    // Server with incompatible version
    let server_caps = Capabilities {
        version: "99.0".to_string(),
        ..Default::default()
    };
    let mut server = Session::new(server_caps);

    let hello = client.create_hello();
    let response = server.process_hello(&hello).unwrap();

    // Should be rejected
    assert_eq!(response.msg_type, MessageType::Reject);

    // Client processes rejection
    let result = client.process_reject(&response);
    assert!(result.is_err());
    assert_eq!(client.state(), SessionState::Closed);
}

/// Test data exchange after handshake
#[test]
fn test_session_data_roundtrip() {
    // Establish session
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // Test various JSON payloads
    let payloads = vec![
        json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Hello"}]
        }),
        json!({
            "model": "anthropic/claude-3-opus",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "What is 2+2?"},
                {"role": "assistant", "content": "4"}
            ],
            "temperature": 0.7
        }),
        json!({
            "model": "meta-llama/llama-3.1-70b-instruct",
            "messages": [{"role": "user", "content": "Test with tools"}],
            "tools": [{"type": "function", "function": {"name": "get_weather"}}]
        }),
    ];

    for original in payloads {
        let content = serde_json::to_string(&original).unwrap();

        // Client compresses
        let data_msg = client.compress(&content).unwrap();
        assert_eq!(data_msg.msg_type, MessageType::Data);

        // Server decompresses
        let decompressed = server.decompress(&data_msg).unwrap();
        let recovered: serde_json::Value = serde_json::from_str(&decompressed).unwrap();

        // Core content should match
        assert_eq!(original["messages"], recovered["messages"]);
        assert_eq!(original["model"], recovered["model"]);
    }
}

/// Test PING/PONG message handling
#[test]
fn test_session_ping_pong() {
    // Establish session
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // Client sends PING
    let ping = Message::ping(client.id());
    assert_eq!(ping.msg_type, MessageType::Ping);

    // Server processes PING, should respond with PONG
    let response = server.process_message(&ping).unwrap();
    assert!(response.is_some());

    let pong = response.unwrap();
    assert_eq!(pong.msg_type, MessageType::Pong);
}

/// Test session close handling
#[test]
fn test_session_close() {
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // Client initiates close
    let close_msg = client.close();
    assert_eq!(close_msg.msg_type, MessageType::Close);
    assert_eq!(client.state(), SessionState::Closing);

    // Server processes close
    let response = server.process_message(&close_msg).unwrap();
    assert!(response.is_none()); // No response to CLOSE
    assert_eq!(server.state(), SessionState::Closed);
}

/// Test session expiry detection
#[test]
fn test_session_expiry_detection() {
    let caps = Capabilities::default();
    let session = Session::new(caps);

    // Freshly created session should not be expired
    assert!(!session.is_expired());
}

/// Test that session operations fail when not established
#[test]
fn test_session_operations_require_established() {
    let mut session = Session::new(Capabilities::default());

    // Try to compress before handshake
    let content = r#"{"test": "data"}"#;
    let result = session.compress(content);
    assert!(result.is_err());

    // Verify the error type
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not established"));
}

/// Test negotiated algorithm selection
#[test]
fn test_session_algorithm_negotiation() {
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // After negotiation, both should have an algorithm
    let client_algo = client.algorithm();
    let server_algo = server.algorithm();

    assert!(client_algo.is_some());
    assert!(server_algo.is_some());
    assert_eq!(client_algo, server_algo);
}

/// Test session statistics tracking
#[test]
fn test_session_stats_tracking() {
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // Send multiple messages
    for i in 0..5 {
        let content = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"Message {}"}}]}}"#,
            i
        );
        let data_msg = client.compress(&content).unwrap();
        let _ = server.decompress(&data_msg).unwrap();
    }

    let client_stats = client.stats();
    let server_stats = server.stats();

    // Client: 1 hello + 5 data = 6 sent
    assert_eq!(client_stats.messages_sent, 6);
    // Client: 1 accept = 1 received
    assert_eq!(client_stats.messages_received, 1);

    // Server: 1 accept = 1 sent
    assert_eq!(server_stats.messages_sent, 1);
    // Server: 1 hello + 5 data = 6 received
    assert_eq!(server_stats.messages_received, 6);

    // Both should have tracked compression
    assert!(client_stats.bytes_compressed > 0);
}

/// Test capabilities negotiation with different algorithm preferences
#[test]
fn test_capabilities_algorithm_negotiation() {
    // Client prefers TokenNative, Brotli
    let client_compression =
        CompressionCaps::default().with_algorithms(vec![Algorithm::TokenNative, Algorithm::Brotli]);
    let client_caps = Capabilities::default().with_compression(client_compression);

    // Server prefers Brotli, TokenNative
    let server_compression =
        CompressionCaps::default().with_algorithms(vec![Algorithm::Brotli, Algorithm::TokenNative]);
    let server_caps = Capabilities::default().with_compression(server_compression);

    let mut client = Session::new(client_caps);
    let mut server = Session::new(server_caps);

    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // Should negotiate to a common algorithm
    let algo = client.algorithm().unwrap();
    assert!(algo == Algorithm::TokenNative || algo == Algorithm::Brotli);
}

/// Test that process_message dispatches correctly
#[test]
fn test_session_process_message_dispatch() {
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());

    // Process HELLO
    let hello = client.create_hello();
    let response = server.process_message(&hello).unwrap();
    assert!(response.is_some());
    assert_eq!(response.unwrap().msg_type, MessageType::Accept);

    // Process ACCEPT (client side)
    let accept = Message::accept(server.id(), Capabilities::default());
    // Note: This creates a new accept, not from server.process_hello
    // Just testing dispatch
    let _ = client.process_message(&accept);

    // Re-establish for more tests
    let mut client = Session::new(Capabilities::default());
    let mut server = Session::new(Capabilities::default());
    let hello = client.create_hello();
    let accept = server.process_hello(&hello).unwrap();
    client.process_accept(&accept).unwrap();

    // Process PING
    let ping = Message::ping(server.id());
    let response = server.process_message(&ping).unwrap();
    assert!(response.is_some());
    assert_eq!(response.unwrap().msg_type, MessageType::Pong);

    // Process PONG (no response expected)
    let pong = Message::pong(client.id());
    let response = client.process_message(&pong).unwrap();
    assert!(response.is_none());

    // Process CLOSE
    let close = Message::close(server.id());
    let response = server.process_message(&close).unwrap();
    assert!(response.is_none());
    assert_eq!(server.state(), SessionState::Closed);
}

/// Test concurrent session creation (simulating parallel clients)
#[test]
fn test_concurrent_session_creation() {
    use std::sync::Arc;
    use std::thread;

    let sessions: Vec<_> = (0..10)
        .map(|_| {
            let caps = Capabilities::default();
            Arc::new(std::sync::Mutex::new(Session::new(caps)))
        })
        .collect();

    // Each thread does a handshake with a shared "server"
    let handles: Vec<_> = sessions
        .iter()
        .map(|session| {
            let session = Arc::clone(session);
            thread::spawn(move || {
                let mut s = session.lock().unwrap();
                let hello = s.create_hello();
                assert_eq!(s.state(), SessionState::HelloSent);
                drop(s);
                hello
            })
        })
        .collect();

    // Collect all hello messages
    let hellos: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All should have created valid hello messages
    assert_eq!(hellos.len(), 10);
    for hello in &hellos {
        assert_eq!(hello.msg_type, MessageType::Hello);
    }
}
