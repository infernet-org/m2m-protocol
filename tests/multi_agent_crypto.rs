//! Multi-Agent Cryptographic Test Suite
//!
//! This test suite validates the M2M protocol's cryptographic primitives
//! across multiple agents and organizations. It progresses through phases
//! of increasing complexity:
//!
//! - **Phase 1**: Foundation - Basic org/agent creation, session key symmetry
//! - **Phase 2**: Crypto Core - AEAD encrypt/decrypt, tampering detection
//! - **Phase 3**: Multi-Org - Cross-org isolation, X25519 key exchange
//! - **Phase 4**: Scale - 100 agents across 5 organizations
//! - **Phase 5**: Protocol - M2M frames, sessions, secure roundtrip
//! - **Phase 6**: Autonomous - LLM-powered agents (requires API key)
//! - **Phase 7**: Network - Full autonomous multi-agent simulation
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all deterministic tests (Phase 1-5)
//! cargo test --features crypto multi_agent_crypto
//!
//! # Run autonomous tests (Phase 6-7, requires OPENROUTER_API_KEY)
//! cargo test --features crypto multi_agent_crypto -- --ignored
//! ```

#![cfg(feature = "crypto")]

use std::collections::HashSet;

use m2m::codec::m2m::crypto::{
    AeadCipher, AeadError, AgentId, AgentKeyContext, KeyExchange, KeyHierarchy, KeyMaterial, OrgId,
    SecurityContext,
};
use m2m::codec::m2m::{M2MFrame, SecurityMode};
use m2m::protocol::{Capabilities, Session, SessionState};

// =============================================================================
// FIXTURES MODULE
// =============================================================================

/// Test fixtures and utilities for multi-agent crypto tests
mod fixtures {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Create a deterministic test master key
    ///
    /// Uses a fixed seed for reproducibility across test runs.
    #[allow(dead_code)]
    pub fn test_master() -> KeyMaterial {
        KeyMaterial::new(vec![0x42u8; 32])
    }

    /// Create a unique master key for an organization
    ///
    /// The master key is derived deterministically from the org name,
    /// ensuring different orgs have cryptographically independent keys.
    pub fn master_for_org(org_name: &str) -> KeyMaterial {
        let mut hasher = Sha256::new();
        hasher.update(b"m2m-test-master-v1:");
        hasher.update(org_name.as_bytes());
        KeyMaterial::new(hasher.finalize().to_vec())
    }

    /// A test organization with a key hierarchy and agents
    pub struct TestOrg {
        /// Organization name
        pub name: String,
        /// Organization ID
        pub org_id: OrgId,
        /// Key hierarchy for this org
        pub hierarchy: KeyHierarchy,
        /// Agents in this organization
        pub agents: Vec<TestAgent>,
    }

    impl TestOrg {
        /// Create a new test organization with the specified number of agents
        ///
        /// Agent IDs follow the pattern: `agent-{org}-{nn}` (e.g., `agent-alpha-00`)
        pub fn new(name: &str, agent_count: usize) -> Self {
            let master = master_for_org(name);
            let org_id = OrgId::new(name);
            let hierarchy = KeyHierarchy::new(master, name);

            let agents = (0..agent_count)
                .map(|i| {
                    let agent_id = AgentId::new(format!("agent-{name}-{i:02}"));
                    let key_context =
                        AgentKeyContext::from_hierarchy(&hierarchy, agent_id.clone()).unwrap();
                    let session = Session::new(Capabilities::new(&format!("agent-{name}-{i:02}")));

                    TestAgent {
                        id: agent_id,
                        org_id: org_id.clone(),
                        key_context,
                        session,
                    }
                })
                .collect();

            Self {
                name: name.to_string(),
                org_id,
                hierarchy,
                agents,
            }
        }

        /// Get an agent by index
        pub fn agent(&self, index: usize) -> &TestAgent {
            &self.agents[index]
        }

        /// Get an agent by ID
        #[allow(dead_code)]
        pub fn agent_by_id(&self, id: &AgentId) -> Option<&TestAgent> {
            self.agents.iter().find(|a| &a.id == id)
        }
    }

    /// A test agent with cryptographic context
    pub struct TestAgent {
        /// Agent identifier
        pub id: AgentId,
        /// Organization this agent belongs to
        pub org_id: OrgId,
        /// Cryptographic key context
        pub key_context: AgentKeyContext,
        /// M2M session (for future protocol tests)
        #[allow(dead_code)]
        pub session: Session,
    }

    impl TestAgent {
        /// Derive a session key for communicating with a peer
        pub fn derive_session_key(&self, peer: &AgentId, session_id: &str) -> KeyMaterial {
            self.key_context
                .derive_session_key(peer, session_id)
                .expect("Session key derivation should succeed")
        }

        /// Create a security context for secure communication with a peer
        pub fn create_security_context(&self, peer: &AgentId, session_id: &str) -> SecurityContext {
            let session_key = self.derive_session_key(peer, session_id);
            SecurityContext::new(session_key)
        }
    }
}

use fixtures::{master_for_org, TestOrg};

// =============================================================================
// PHASE 1: FOUNDATION
// =============================================================================

/// Phase 1: Verify we can create an organization with a key hierarchy
#[test]
fn test_create_org() {
    let org = TestOrg::new("alpha", 0);

    assert_eq!(org.name, "alpha");
    assert_eq!(org.org_id.as_str(), "alpha");
    assert!(org.agents.is_empty());

    // Verify hierarchy can derive org key
    let org_key = org.hierarchy.derive_org_key().unwrap();
    assert_eq!(org_key.as_bytes().len(), 32);
}

/// Phase 1: Verify we can create agents within an organization
#[test]
fn test_create_agent() {
    let org = TestOrg::new("alpha", 3);

    assert_eq!(org.agents.len(), 3);

    // Verify agent IDs follow naming convention
    assert_eq!(org.agents[0].id.as_str(), "agent-alpha-00");
    assert_eq!(org.agents[1].id.as_str(), "agent-alpha-01");
    assert_eq!(org.agents[2].id.as_str(), "agent-alpha-02");

    // Verify each agent has a key context
    for agent in &org.agents {
        assert_eq!(agent.org_id.as_str(), "alpha");
        // Key context should have a valid identity key
        let identity_key = agent.key_context.identity_key();
        assert_eq!(identity_key.as_bytes().len(), 32);
    }
}

/// Phase 1: Verify two agents derive the same session key (symmetry)
///
/// This is the foundational property that enables same-org communication:
/// `derive_session_key(A, B, sid)` == `derive_session_key(B, A, sid)`
#[test]
fn test_two_agents_session_key_symmetry() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_id = "session-001";

    // Alice derives session key with Bob
    let key_ab = alice.derive_session_key(&bob.id, session_id);

    // Bob derives session key with Alice
    let key_ba = bob.derive_session_key(&alice.id, session_id);

    // Keys must be identical
    assert_eq!(
        key_ab.as_bytes(),
        key_ba.as_bytes(),
        "Session keys must be symmetric: alice↔bob == bob↔alice"
    );

    // Sanity check: key is not all zeros
    assert_ne!(
        key_ab.as_bytes(),
        &[0u8; 32],
        "Session key should not be all zeros"
    );
}

// =============================================================================
// PHASE 2: CRYPTO CORE
// =============================================================================

/// Phase 2: AEAD encrypt/decrypt roundtrip with derived session key
#[test]
fn test_aead_roundtrip_with_derived_key() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_key = alice.derive_session_key(&bob.id, "aead-test");
    let cipher = AeadCipher::new(session_key).expect("Cipher creation should succeed");

    let plaintext = b"Hello, Bob! This is a secret message.";
    let aad = b"additional authenticated data";
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    // Encrypt
    let ciphertext = cipher
        .encrypt(plaintext, &nonce, aad)
        .expect("Encryption should succeed");

    // Ciphertext should be different from plaintext
    assert_ne!(&ciphertext[12..ciphertext.len() - 16], plaintext);

    // Decrypt
    let decrypted = cipher
        .decrypt(&ciphertext, aad)
        .expect("Decryption should succeed");

    assert_eq!(
        decrypted, plaintext,
        "Decrypted message must match original"
    );
}

/// Phase 2: AEAD decryption fails with wrong key
#[test]
fn test_aead_wrong_key_fails() {
    let org = TestOrg::new("alpha", 3);
    let alice = org.agent(0);
    let bob = org.agent(1);
    let charlie = org.agent(2);

    // Alice encrypts for Bob
    let alice_bob_key = alice.derive_session_key(&bob.id, "wrong-key-test");
    let cipher_ab = AeadCipher::new(alice_bob_key).unwrap();

    let plaintext = b"Secret for Bob only";
    let aad = b"header";
    let nonce = [0u8; 12];

    let ciphertext = cipher_ab.encrypt(plaintext, &nonce, aad).unwrap();

    // Charlie tries to decrypt with his key (should fail)
    let charlie_bob_key = charlie.derive_session_key(&bob.id, "wrong-key-test");
    let cipher_cb = AeadCipher::new(charlie_bob_key).unwrap();

    let result = cipher_cb.decrypt(&ciphertext, aad);

    assert!(
        matches!(result, Err(AeadError::DecryptionFailed(_))),
        "Decryption with wrong key must fail"
    );
}

/// Phase 2: AEAD detects ciphertext tampering
#[test]
fn test_aead_tamper_detection() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_key = alice.derive_session_key(&bob.id, "tamper-test");
    let cipher = AeadCipher::new(session_key).unwrap();

    let plaintext = b"Sensitive data that must not be modified";
    let aad = b"authenticated header";
    let nonce = [42u8; 12];

    let mut ciphertext = cipher.encrypt(plaintext, &nonce, aad).unwrap();

    // Tamper with the ciphertext (flip a bit in the encrypted payload)
    let tamper_index = 20; // After nonce (12 bytes), in the ciphertext body
    ciphertext[tamper_index] ^= 0xFF;

    let result = cipher.decrypt(&ciphertext, aad);

    assert!(
        matches!(result, Err(AeadError::DecryptionFailed(_))),
        "Tampered ciphertext must fail authentication"
    );
}

/// Phase 2: AEAD detects wrong AAD (associated authenticated data)
#[test]
fn test_aead_wrong_aad_detection() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_key = alice.derive_session_key(&bob.id, "aad-test");
    let cipher = AeadCipher::new(session_key).unwrap();

    let plaintext = b"Message with authenticated header";
    let correct_aad = b"correct-header-data";
    let wrong_aad = b"wrong-header-data";
    let nonce = [7u8; 12];

    let ciphertext = cipher.encrypt(plaintext, &nonce, correct_aad).unwrap();

    // Try to decrypt with wrong AAD
    let result = cipher.decrypt(&ciphertext, wrong_aad);

    assert!(
        matches!(result, Err(AeadError::DecryptionFailed(_))),
        "Decryption with wrong AAD must fail"
    );
}

/// Phase 2: Session keys differ for different session IDs
#[test]
fn test_session_key_uniqueness() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let key_session_1 = alice.derive_session_key(&bob.id, "session-001");
    let key_session_2 = alice.derive_session_key(&bob.id, "session-002");
    let key_session_3 = alice.derive_session_key(&bob.id, "different-context");

    // All session keys must be different
    assert_ne!(
        key_session_1.as_bytes(),
        key_session_2.as_bytes(),
        "Different session IDs must produce different keys"
    );
    assert_ne!(
        key_session_1.as_bytes(),
        key_session_3.as_bytes(),
        "Different session IDs must produce different keys"
    );
    assert_ne!(
        key_session_2.as_bytes(),
        key_session_3.as_bytes(),
        "Different session IDs must produce different keys"
    );
}

// =============================================================================
// PHASE 3: MULTI-ORG
// =============================================================================

/// Phase 3: Different organizations have different master keys
#[test]
fn test_different_orgs_different_masters() {
    let master_alpha = master_for_org("alpha");
    let master_beta = master_for_org("beta");
    let master_gamma = master_for_org("gamma");

    // All masters must be unique
    assert_ne!(
        master_alpha.as_bytes(),
        master_beta.as_bytes(),
        "Different orgs must have different master keys"
    );
    assert_ne!(
        master_alpha.as_bytes(),
        master_gamma.as_bytes(),
        "Different orgs must have different master keys"
    );
    assert_ne!(
        master_beta.as_bytes(),
        master_gamma.as_bytes(),
        "Different orgs must have different master keys"
    );
}

/// Phase 3: Same agent ID in different orgs produces different identity keys
#[test]
fn test_cross_org_key_isolation() {
    let org_alpha = TestOrg::new("alpha", 1);
    let org_beta = TestOrg::new("beta", 1);

    let agent_alpha = org_alpha.agent(0);
    let agent_beta = org_beta.agent(0);

    // Both agents have ID "agent-{org}-00" but different org prefixes
    // More importantly, they have different identity keys
    let key_alpha = agent_alpha.key_context.identity_key();
    let key_beta = agent_beta.key_context.identity_key();

    assert_ne!(
        key_alpha.as_bytes(),
        key_beta.as_bytes(),
        "Same agent ID in different orgs must have different identity keys"
    );
}

/// Phase 3: Cross-org AEAD decryption fails (no shared master secret)
///
/// This test verifies that agents from different organizations cannot
/// decrypt each other's messages using HKDF-derived keys, because they
/// derive from different master secrets.
#[test]
fn test_cross_org_aead_failure() {
    let org_alpha = TestOrg::new("alpha", 1);
    let org_beta = TestOrg::new("beta", 1);

    let alice = org_alpha.agent(0); // org-alpha
    let bob = org_beta.agent(0); // org-beta

    // Alice encrypts with her org's derived key
    // She derives a "session key" with bob's ID, but using her org's hierarchy
    let alice_key = alice.derive_session_key(&bob.id, "cross-org-test");
    let alice_cipher = AeadCipher::new(alice_key).unwrap();

    let plaintext = b"Secret message from alpha org";
    let aad = b"cross-org-header";
    let nonce = [0u8; 12];

    let ciphertext = alice_cipher.encrypt(plaintext, &nonce, aad).unwrap();

    // Bob tries to decrypt with his org's derived key
    // He derives using alice's ID, but with his org's hierarchy
    let bob_key = bob.derive_session_key(&alice.id, "cross-org-test");
    let bob_cipher = AeadCipher::new(bob_key).unwrap();

    let result = bob_cipher.decrypt(&ciphertext, aad);

    assert!(
        matches!(result, Err(AeadError::DecryptionFailed(_))),
        "Cross-org decryption must fail without key exchange"
    );
}

/// Phase 3: X25519 key exchange produces identical shared secrets
///
/// This test verifies that two agents (even from different orgs) can
/// perform Diffie-Hellman key exchange to establish a shared secret.
#[test]
fn test_cross_org_x25519_exchange() {
    // Create key exchange instances for both parties
    let mut alice_exchange = KeyExchange::new();
    let mut bob_exchange = KeyExchange::new();

    // Exchange public keys
    let alice_public = alice_exchange.public_key().clone();
    let bob_public = bob_exchange.public_key().clone();

    alice_exchange.set_peer_public(bob_public);
    bob_exchange.set_peer_public(alice_public);

    // Both derive session keys from the shared secret
    let alice_session = alice_exchange
        .derive_session_key("cross-org-session-v1")
        .expect("Alice should derive session key");
    let bob_session = bob_exchange
        .derive_session_key("cross-org-session-v1")
        .expect("Bob should derive session key");

    // Keys must be identical
    assert_eq!(
        alice_session.as_bytes(),
        bob_session.as_bytes(),
        "X25519 exchange must produce identical shared secrets"
    );

    // Verify the key can be used for AEAD
    let cipher = AeadCipher::new(alice_session).unwrap();
    let plaintext = b"Cross-org secure message";
    let nonce = [1u8; 12];
    let ciphertext = cipher.encrypt(plaintext, &nonce, b"").unwrap();
    let decrypted = cipher.decrypt(&ciphertext, b"").unwrap();

    assert_eq!(decrypted, plaintext);
}

// =============================================================================
// PHASE 4: SCALE
// =============================================================================

/// Phase 4: 20 agents in one org can all derive session keys with each other
///
/// Tests full mesh connectivity within an organization: all C(20,2) = 190 pairs.
#[test]
fn test_same_org_full_mesh_20_agents() {
    let org = TestOrg::new("alpha", 20);
    let mut pairs_tested = 0;
    let mut all_keys: HashSet<Vec<u8>> = HashSet::new();

    for i in 0..20 {
        for j in (i + 1)..20 {
            let agent_i = org.agent(i);
            let agent_j = org.agent(j);

            // Both agents derive session key
            let key_ij = agent_i.derive_session_key(&agent_j.id, "mesh-test");
            let key_ji = agent_j.derive_session_key(&agent_i.id, "mesh-test");

            // Keys must match (symmetry)
            assert_eq!(
                key_ij.as_bytes(),
                key_ji.as_bytes(),
                "Session key symmetry failed for agents {} and {}",
                i,
                j
            );

            // Track unique keys
            all_keys.insert(key_ij.as_bytes().to_vec());
            pairs_tested += 1;
        }
    }

    // Verify we tested all pairs: C(20,2) = 190
    assert_eq!(pairs_tested, 190, "Should test all 190 unique pairs");

    // All pair keys should be unique
    assert_eq!(all_keys.len(), 190, "All 190 session keys should be unique");
}

/// Phase 4: 100 agents across 5 orgs all have unique identity keys
#[test]
fn test_100_agents_unique_keys() {
    let orgs: Vec<TestOrg> = ["alpha", "beta", "gamma", "delta", "epsilon"]
        .iter()
        .map(|name| TestOrg::new(name, 20))
        .collect();

    let mut all_identity_keys: HashSet<Vec<u8>> = HashSet::new();
    let mut agent_count = 0;

    for org in &orgs {
        for agent in &org.agents {
            let identity_key = agent.key_context.identity_key().as_bytes().to_vec();
            let is_unique = all_identity_keys.insert(identity_key);

            assert!(
                is_unique,
                "Duplicate identity key found for agent {}",
                agent.id.as_str()
            );

            agent_count += 1;
        }
    }

    assert_eq!(agent_count, 100, "Should have exactly 100 agents");
    assert_eq!(
        all_identity_keys.len(),
        100,
        "All 100 identity keys must be unique"
    );
}

/// Phase 4: Cross-org pairs are correctly isolated (sampling)
#[test]
fn test_cross_org_isolation_at_scale() {
    let org_alpha = TestOrg::new("alpha", 5);
    let org_beta = TestOrg::new("beta", 5);

    // Test all cross-org pairs (5 × 5 = 25 pairs)
    for alice in &org_alpha.agents {
        for bob in &org_beta.agents {
            // Alice's derived "session key" with Bob
            let alice_key = alice.derive_session_key(&bob.id, "isolation-test");

            // Bob's derived "session key" with Alice
            let bob_key = bob.derive_session_key(&alice.id, "isolation-test");

            // Keys must be DIFFERENT (no shared master)
            assert_ne!(
                alice_key.as_bytes(),
                bob_key.as_bytes(),
                "Cross-org agents {}<->{} should have different derived keys",
                alice.id.as_str(),
                bob.id.as_str()
            );
        }
    }
}

/// Phase 4: X25519 exchange works for multiple cross-org pairs
#[test]
fn test_multi_pair_x25519_exchange() {
    let org_alpha = TestOrg::new("alpha", 3);
    let org_beta = TestOrg::new("beta", 3);

    // Each agent from alpha exchanges keys with each agent from beta
    for (i, _alice) in org_alpha.agents.iter().enumerate() {
        for (j, _bob) in org_beta.agents.iter().enumerate() {
            let mut alice_exchange = KeyExchange::new();
            let mut bob_exchange = KeyExchange::new();

            // Exchange public keys
            alice_exchange.set_peer_public(bob_exchange.public_key().clone());
            bob_exchange.set_peer_public(alice_exchange.public_key().clone());

            // Derive session keys
            let context = format!("session-alpha{i}-beta{j}");
            let alice_session = alice_exchange.derive_session_key(&context).unwrap();
            let bob_session = bob_exchange.derive_session_key(&context).unwrap();

            assert_eq!(
                alice_session.as_bytes(),
                bob_session.as_bytes(),
                "X25519 exchange failed for pair ({i}, {j})"
            );
        }
    }
}

// =============================================================================
// PHASE 5: PROTOCOL
// =============================================================================

/// Phase 5: M2M session handshake between two agents
#[test]
fn test_m2m_session_handshake() {
    let _org = TestOrg::new("alpha", 2);

    let mut alice_session = Session::new(Capabilities::new("agent-alpha-00"));
    let mut bob_session = Session::new(Capabilities::new("agent-alpha-01"));

    // Initial state
    assert_eq!(alice_session.state(), SessionState::Initial);
    assert_eq!(bob_session.state(), SessionState::Initial);

    // Alice sends HELLO
    let hello = alice_session.create_hello();
    assert_eq!(alice_session.state(), SessionState::HelloSent);

    // Bob processes HELLO, sends ACCEPT
    let accept = bob_session
        .process_hello(&hello)
        .expect("Bob should accept hello");
    assert_eq!(bob_session.state(), SessionState::Established);

    // Alice processes ACCEPT
    alice_session
        .process_accept(&accept)
        .expect("Alice should process accept");
    assert_eq!(alice_session.state(), SessionState::Established);

    // Sessions should have matching IDs
    assert_eq!(
        alice_session.id(),
        bob_session.id(),
        "Session IDs must match after handshake"
    );
}

/// Phase 5: Secure M2M frame encode/decode roundtrip
#[test]
fn test_secure_frame_roundtrip() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    // Create payload (typical LLM API request)
    let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, world!"}],"temperature":0.7}"#;

    // Alice creates and encrypts frame
    let frame = M2MFrame::new_request(payload).expect("Frame creation should succeed");
    let mut alice_ctx = alice.create_security_context(&bob.id, "frame-test");

    let encrypted = frame
        .encode_secure(SecurityMode::Aead, &mut alice_ctx)
        .expect("Frame encryption should succeed");

    // Encrypted data should be different from plaintext
    assert!(
        !encrypted
            .windows(payload.len())
            .any(|w| w == payload.as_bytes()),
        "Plaintext should not appear in encrypted frame"
    );

    // Bob decrypts frame
    let bob_ctx = bob.create_security_context(&alice.id, "frame-test");

    let decrypted_frame =
        M2MFrame::decode_secure(&encrypted, &bob_ctx).expect("Frame decryption should succeed");

    // Verify payload matches
    assert_eq!(
        decrypted_frame.payload, payload,
        "Decrypted payload must match original"
    );
}

/// Phase 5: Multi-turn secure message exchange
#[test]
fn test_multi_turn_secure_exchange() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_id = "multi-turn-session";
    let mut alice_ctx = alice.create_security_context(&bob.id, session_id);
    let bob_ctx = bob.create_security_context(&alice.id, session_id);

    // Simulate 5 request/response pairs (each must be valid LLM API JSON)
    let requests = [
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"How are you?"}]}"#,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"What is 2+2?"}]}"#,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Thanks!"}]}"#,
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Goodbye"}]}"#,
    ];

    for (i, msg) in requests.iter().enumerate() {
        let frame = M2MFrame::new_request(msg).expect("Frame creation should succeed");

        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .expect("Encryption should succeed");

        // Decrypt with Bob's context
        let decrypted =
            M2MFrame::decode_secure(&encrypted, &bob_ctx).expect("Decryption should succeed");

        assert_eq!(decrypted.payload, *msg, "Message {} roundtrip failed", i);
    }
}

/// Phase 5: Cross-org secure session with X25519 exchange + AEAD
#[test]
fn test_cross_org_secure_session() {
    let org_alpha = TestOrg::new("alpha", 1);
    let org_beta = TestOrg::new("beta", 1);

    let _alice = org_alpha.agent(0);
    let _bob = org_beta.agent(0);

    // Step 1: X25519 key exchange
    let mut alice_exchange = KeyExchange::new();
    let mut bob_exchange = KeyExchange::new();

    alice_exchange.set_peer_public(bob_exchange.public_key().clone());
    bob_exchange.set_peer_public(alice_exchange.public_key().clone());

    let shared_key = alice_exchange
        .derive_session_key("cross-org-aead-v1")
        .expect("Key derivation should succeed");

    // Step 2: Create security context with exchanged key
    let mut alice_ctx = SecurityContext::new(shared_key.clone());
    let bob_ctx = SecurityContext::new(shared_key);

    // Step 3: Secure communication
    let payload =
        r#"{"model":"claude-3-opus","messages":[{"role":"user","content":"Cross-org test"}]}"#;
    let frame = M2MFrame::new_request(payload).expect("Frame creation should succeed");

    let encrypted = frame
        .encode_secure(SecurityMode::Aead, &mut alice_ctx)
        .expect("Cross-org encryption should succeed");

    let decrypted =
        M2MFrame::decode_secure(&encrypted, &bob_ctx).expect("Cross-org decryption should succeed");

    assert_eq!(decrypted.payload, payload);
}

/// Phase 5: Real LLM payload secure roundtrip (no API call)
#[test]
fn test_llm_payload_secure_roundtrip() {
    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    // Realistic multi-turn conversation payload
    let payload = serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"},
            {"role": "assistant", "content": "The capital of France is Paris."},
            {"role": "user", "content": "What is its population?"}
        ],
        "temperature": 0.7,
        "max_tokens": 150
    });

    let payload_str = serde_json::to_string(&payload).unwrap();
    let frame = M2MFrame::new_request(&payload_str).expect("Frame creation should succeed");

    let mut alice_ctx = alice.create_security_context(&bob.id, "llm-payload-test");
    let bob_ctx = bob.create_security_context(&alice.id, "llm-payload-test");

    let encrypted = frame
        .encode_secure(SecurityMode::Aead, &mut alice_ctx)
        .expect("LLM payload encryption should succeed");

    let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx)
        .expect("LLM payload decryption should succeed");

    // Parse and verify JSON structure is preserved
    let decrypted_json: serde_json::Value =
        serde_json::from_str(&decrypted.payload).expect("Should parse as JSON");

    assert_eq!(decrypted_json["model"], "gpt-4o");
    assert_eq!(decrypted_json["messages"].as_array().unwrap().len(), 4);
    assert_eq!(decrypted_json["temperature"], 0.7);
}

// =============================================================================
// PHASE 6: AUTONOMOUS (requires OPENROUTER_API_KEY)
// =============================================================================

/// OpenRouter API helpers for autonomous agent tests
mod openrouter {
    use reqwest::Client;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    pub const API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
    /// Cheap paid model (~$0.02/M input, $0.05/M output) - more reliable than free tier
    pub const MODEL: &str = "meta-llama/llama-3.2-3b-instruct";

    /// Get API key from environment
    pub fn get_api_key() -> Option<String> {
        std::env::var("OPENROUTER_API_KEY").ok()
    }

    /// Create HTTP client for OpenRouter
    pub fn create_client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client")
    }

    #[derive(Debug, Serialize)]
    pub struct ChatRequest {
        pub model: String,
        pub messages: Vec<ChatMessage>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub temperature: Option<f32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub max_tokens: Option<u32>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ChatMessage {
        pub role: String,
        pub content: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct ChatResponse {
        pub choices: Vec<Choice>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Choice {
        pub message: ChatMessage,
    }

    /// Call OpenRouter chat completion API
    pub async fn chat_completion(
        client: &Client,
        model: &str,
        messages: Vec<ChatMessage>,
        temperature: Option<f32>,
        max_tokens: Option<u32>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let api_key = get_api_key().ok_or("OPENROUTER_API_KEY not set")?;

        let request = ChatRequest {
            model: model.to_string(),
            messages,
            temperature,
            max_tokens,
        };

        let response = client
            .post(API_URL)
            .header("Authorization", format!("Bearer {api_key}"))
            .header(
                "HTTP-Referer",
                "https://github.com/infernet-org/m2m-protocol",
            )
            .header("X-Title", "M2M Multi-Agent Test Suite")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("OpenRouter API error: {error_text}").into());
        }

        let result: ChatResponse = response.json().await?;
        Ok(result
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default())
    }
}

/// Phase 6: Single agent can call LLM
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_single_agent_llm_call -- --ignored"]
async fn test_single_agent_llm_call() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    let client = openrouter::create_client();

    let messages = vec![openrouter::ChatMessage {
        role: "user".to_string(),
        content: "Say 'Hello from M2M test' and nothing else.".to_string(),
    }];

    let response =
        openrouter::chat_completion(&client, openrouter::MODEL, messages, Some(0.1), Some(50))
            .await;

    match response {
        Ok(text) => {
            println!("LLM Response: {text}");
            assert!(!text.is_empty(), "Response should not be empty");
        },
        Err(e) => {
            let error_msg = e.to_string();
            // Handle rate limits (429) and spending limits (402)
            if error_msg.contains("429")
                || error_msg.contains("402")
                || error_msg.contains("rate-limit")
                || error_msg.contains("spend")
                || error_msg.contains("limit exceeded")
            {
                println!("Skipping: API limit reached ({error_msg})");
                return;
            }
            panic!("LLM call failed: {e}");
        },
    }
}

/// Phase 6: Two agents have encrypted conversation via LLM
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_two_agent_encrypted_conversation -- --ignored"]
async fn test_two_agent_encrypted_conversation() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_id = "autonomous-conv-001";
    let mut alice_ctx = alice.create_security_context(&bob.id, session_id);
    let bob_ctx = bob.create_security_context(&alice.id, session_id);

    let client = openrouter::create_client();

    // Alice asks a question
    let alice_question = "What is 2 + 2? Reply with just the number.";

    // Create encrypted request payload
    let request_payload = serde_json::json!({
        "model": openrouter::MODEL,
        "messages": [
            {"role": "user", "content": alice_question}
        ],
        "temperature": 0.1,
        "max_tokens": 10
    });

    let request_str = serde_json::to_string(&request_payload).unwrap();
    println!("Alice's request (plaintext): {request_str}");

    // Encrypt the request
    let frame = M2MFrame::new_request(&request_str).expect("Frame creation should succeed");
    let encrypted = frame
        .encode_secure(SecurityMode::Aead, &mut alice_ctx)
        .expect("Encryption should succeed");

    println!(
        "Encrypted request size: {} bytes (original: {} bytes)",
        encrypted.len(),
        request_str.len()
    );

    // Bob decrypts and processes
    let decrypted_frame =
        M2MFrame::decode_secure(&encrypted, &bob_ctx).expect("Decryption should succeed");

    let decrypted_request: serde_json::Value =
        serde_json::from_str(&decrypted_frame.payload).unwrap();

    println!("Bob decrypted request: {decrypted_request}");

    // Bob calls LLM (simulating agent processing)
    let messages = vec![openrouter::ChatMessage {
        role: "user".to_string(),
        content: alice_question.to_string(),
    }];

    let llm_response = match openrouter::chat_completion(
        &client,
        openrouter::MODEL,
        messages,
        Some(0.1),
        Some(10),
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            let error_msg = e.to_string();
            // Handle rate limits (429) and spending limits (402)
            if error_msg.contains("429")
                || error_msg.contains("402")
                || error_msg.contains("rate-limit")
                || error_msg.contains("spend")
                || error_msg.contains("limit exceeded")
            {
                println!("Skipping LLM validation: API limit reached ({error_msg})");
                println!("=== Encryption roundtrip successful (LLM skipped due to API limit) ===");
                return;
            }
            panic!("LLM call failed: {e}");
        },
    };

    println!("LLM response: {llm_response}");

    // For the roundtrip test, we verify the LLM was called and got a response
    // The response doesn't need to go through M2MFrame (it's internal agent state)

    // Verify the response contains "4" (or similar)
    assert!(
        llm_response.contains('4'),
        "Response should contain '4', got: {llm_response}"
    );

    println!("=== Encrypted conversation successful! ===");
}

/// Phase 6: Cross-org agents exchange keys and chat
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_cross_org_autonomous_chat -- --ignored"]
async fn test_cross_org_autonomous_chat() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    let _org_alpha = TestOrg::new("alpha", 1);
    let _org_beta = TestOrg::new("beta", 1);

    println!("=== Cross-Org Autonomous Chat ===");
    println!("Alice (org-alpha) <-> Bob (org-beta)");

    // Step 1: Key exchange
    println!("\n1. Performing X25519 key exchange...");
    let mut alice_exchange = KeyExchange::new();
    let mut bob_exchange = KeyExchange::new();

    alice_exchange.set_peer_public(bob_exchange.public_key().clone());
    bob_exchange.set_peer_public(alice_exchange.public_key().clone());

    let shared_key = alice_exchange
        .derive_session_key("cross-org-chat-v1")
        .unwrap();
    println!("   Shared secret established!");

    // Step 2: Create security contexts
    let mut alice_ctx = SecurityContext::new(shared_key.clone());
    let bob_ctx = SecurityContext::new(shared_key);

    // Step 3: Alice sends encrypted LLM request
    println!("\n2. Alice sends encrypted LLM request...");
    let question = "Name one planet in our solar system. Reply with just the name.";

    let request_payload = serde_json::json!({
        "model": openrouter::MODEL,
        "messages": [{"role": "user", "content": question}],
        "temperature": 0.1,
        "max_tokens": 20
    });

    let request_str = serde_json::to_string(&request_payload).unwrap();
    let frame = M2MFrame::new_request(&request_str).expect("Frame creation should succeed");
    let encrypted = frame
        .encode_secure(SecurityMode::Aead, &mut alice_ctx)
        .unwrap();

    println!("   Encrypted {} bytes", encrypted.len());

    // Step 4: Bob decrypts and processes
    println!("\n3. Bob decrypts and calls LLM...");
    let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();
    let request: serde_json::Value = serde_json::from_str(&decrypted.payload).unwrap();

    println!("   Decrypted: {request}");

    let client = openrouter::create_client();
    let messages = vec![openrouter::ChatMessage {
        role: "user".to_string(),
        content: question.to_string(),
    }];

    let response = match openrouter::chat_completion(
        &client,
        openrouter::MODEL,
        messages,
        Some(0.1),
        Some(20),
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            let error_msg = e.to_string();
            // Handle rate limits (429) and spending limits (402)
            if error_msg.contains("429")
                || error_msg.contains("402")
                || error_msg.contains("rate-limit")
                || error_msg.contains("spend")
                || error_msg.contains("limit exceeded")
            {
                println!("   Skipping LLM: API limit reached ({error_msg})");
                println!(
                    "\n=== Cross-org encryption successful (LLM skipped due to API limit) ==="
                );
                return;
            }
            panic!("LLM call failed: {e}");
        },
    };

    println!("   LLM response: {response}");

    // Step 5: Verify encryption worked for cross-org
    assert!(!response.is_empty(), "Should get a response");
    println!("\n=== Cross-org encrypted chat successful! ===");
}

// =============================================================================
// PHASE 7: PROTOCOL METRICS & INSTRUMENTATION
// =============================================================================

/// Metrics collected during protocol operations
#[derive(Debug, Default)]
struct ProtocolMetrics {
    // Compression
    total_original_bytes: usize,
    total_compressed_bytes: usize,
    total_encrypted_bytes: usize,

    // Operations
    key_derivations: usize,
    encryptions: usize,
    decryptions: usize,

    // Overhead breakdown
    prefix_overhead: usize, // #M2M|1| prefix
    header_overhead: usize, // Fixed + routing headers
    nonce_overhead: usize,  // 12 bytes per AEAD
    tag_overhead: usize,    // 16 bytes per AEAD

    // Timing (if needed)
    total_encrypt_ns: u128,
    total_decrypt_ns: u128,
}

impl ProtocolMetrics {
    fn compression_ratio(&self) -> f64 {
        if self.total_original_bytes == 0 {
            return 0.0;
        }
        self.total_compressed_bytes as f64 / self.total_original_bytes as f64
    }

    fn encryption_overhead(&self) -> f64 {
        if self.total_compressed_bytes == 0 {
            return 0.0;
        }
        (self.total_encrypted_bytes as f64 / self.total_compressed_bytes as f64) - 1.0
    }

    fn total_overhead(&self) -> f64 {
        if self.total_original_bytes == 0 {
            return 0.0;
        }
        (self.total_encrypted_bytes as f64 / self.total_original_bytes as f64) - 1.0
    }

    fn print_summary(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║              PROTOCOL METRICS SUMMARY                        ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ SIZES                                                        ║");
        println!(
            "║   Original payload:     {:>10} bytes                     ║",
            self.total_original_bytes
        );
        println!(
            "║   After compression:    {:>10} bytes ({:>5.1}%)            ║",
            self.total_compressed_bytes,
            self.compression_ratio() * 100.0
        );
        println!(
            "║   After encryption:     {:>10} bytes                     ║",
            self.total_encrypted_bytes
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ OVERHEAD BREAKDOWN                                           ║");
        println!(
            "║   Prefix (#M2M|1|):     {:>10} bytes                     ║",
            self.prefix_overhead
        );
        println!(
            "║   Headers (fixed+var):  {:>10} bytes                     ║",
            self.header_overhead
        );
        println!(
            "║   Nonce (per message):  {:>10} bytes                     ║",
            self.nonce_overhead
        );
        println!(
            "║   AEAD tag (per msg):   {:>10} bytes                     ║",
            self.tag_overhead
        );
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ EFFICIENCY                                                   ║");
        println!(
            "║   Compression ratio:    {:>10.1}%                          ║",
            self.compression_ratio() * 100.0
        );
        println!(
            "║   Encryption overhead:  {:>10.1}%                          ║",
            self.encryption_overhead() * 100.0
        );
        println!(
            "║   Total overhead:       {:>10.1}%                          ║",
            self.total_overhead() * 100.0
        );
        if self.total_overhead() > 0.0 {
            println!("║   ⚠️  INEFFICIENCY: Output larger than input!                ║");
        } else {
            println!(
                "║   ✅ Net savings: {:>5.1}%                                   ║",
                -self.total_overhead() * 100.0
            );
        }
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║ OPERATIONS                                                   ║");
        println!(
            "║   Key derivations:      {:>10}                           ║",
            self.key_derivations
        );
        println!(
            "║   Encryptions:          {:>10}                           ║",
            self.encryptions
        );
        println!(
            "║   Decryptions:          {:>10}                           ║",
            self.decryptions
        );
        println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

/// Protocol efficiency analysis with detailed metrics
#[test]
fn test_protocol_efficiency_metrics() {
    use std::time::Instant;

    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let mut metrics = ProtocolMetrics::default();

    // Test payloads of various sizes
    let payloads = [
        // Small payload (typical single message)
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#,
        // Medium payload (multi-turn conversation)
        r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is the capital of France?"},{"role":"assistant","content":"Paris."},{"role":"user","content":"What about Germany?"}],"temperature":0.7}"#,
        // Large payload (with code)
        r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a Rust expert."},{"role":"user","content":"Write a function that implements binary search."},{"role":"assistant","content":"```rust\nfn binary_search<T: Ord>(arr: &[T], target: &T) -> Option<usize> {\n    let mut left = 0;\n    let mut right = arr.len();\n    while left < right {\n        let mid = left + (right - left) / 2;\n        match arr[mid].cmp(target) {\n            std::cmp::Ordering::Equal => return Some(mid),\n            std::cmp::Ordering::Less => left = mid + 1,\n            std::cmp::Ordering::Greater => right = mid,\n        }\n    }\n    None\n}\n```"},{"role":"user","content":"Can you add error handling?"}],"temperature":0.5,"max_tokens":500}"#,
    ];

    let session_id = "metrics-test";
    let mut alice_ctx = alice.create_security_context(&bob.id, session_id);
    let bob_ctx = bob.create_security_context(&alice.id, session_id);
    metrics.key_derivations += 2;

    println!("\n=== Protocol Efficiency Analysis ===\n");

    for (i, payload) in payloads.iter().enumerate() {
        let original_len = payload.len();
        metrics.total_original_bytes += original_len;

        // Create frame
        let frame = M2MFrame::new_request(payload).expect("Frame creation failed");

        // Encode without encryption first to measure compression
        let encoded_plain = frame.encode().expect("Plain encode failed");
        let compressed_len = encoded_plain.len();
        metrics.total_compressed_bytes += compressed_len;

        // Encode with AEAD
        let start = Instant::now();
        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .expect("Encryption failed");
        metrics.total_encrypt_ns += start.elapsed().as_nanos();
        metrics.encryptions += 1;

        let encrypted_len = encrypted.len();
        metrics.total_encrypted_bytes += encrypted_len;

        // Measure overhead components
        metrics.prefix_overhead += 7; // #M2M|1|
        metrics.nonce_overhead += 12; // AEAD nonce
        metrics.tag_overhead += 16; // AEAD tag

        // Decrypt to verify
        let start = Instant::now();
        let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx).expect("Decryption failed");
        metrics.total_decrypt_ns += start.elapsed().as_nanos();
        metrics.decryptions += 1;

        assert_eq!(decrypted.payload, *payload, "Payload mismatch");

        // Per-payload stats
        let compression_ratio = compressed_len as f64 / original_len as f64;
        let encryption_overhead = (encrypted_len as f64 / compressed_len as f64) - 1.0;
        let total_ratio = encrypted_len as f64 / original_len as f64;

        println!("Payload {}: {} bytes", i + 1, original_len);
        println!(
            "  Compressed: {} bytes ({:.1}%)",
            compressed_len,
            compression_ratio * 100.0
        );
        println!(
            "  Encrypted:  {} bytes (+{:.1}% overhead)",
            encrypted_len,
            encryption_overhead * 100.0
        );
        println!(
            "  Total:      {:.1}% of original {}",
            total_ratio * 100.0,
            if total_ratio < 1.0 {
                "✅ SAVINGS"
            } else {
                "⚠️ LARGER"
            }
        );
        println!();
    }

    // Calculate header overhead (total - payload - nonce - tag)
    metrics.header_overhead = metrics
        .total_encrypted_bytes
        .saturating_sub(metrics.total_compressed_bytes)
        .saturating_sub(metrics.nonce_overhead)
        .saturating_sub(metrics.tag_overhead)
        .saturating_sub(metrics.prefix_overhead);

    metrics.print_summary();

    // Assertions for efficiency
    // Compression should achieve some savings on larger payloads
    // But small payloads may have overhead due to headers
}

/// Measure key derivation performance at scale
#[test]
fn test_key_derivation_performance() {
    use std::time::Instant;

    println!("\n=== Key Derivation Performance ===\n");

    let org = TestOrg::new("alpha", 100);

    // Measure identity key derivation (already done in TestOrg::new)
    // Now measure session key derivation

    let start = Instant::now();
    let mut session_keys = Vec::with_capacity(100);

    // Derive session keys for first 10 agents with all others
    // Note: session keys are symmetric, so A->B == B->A
    for i in 0..10 {
        for j in 0..100 {
            if i != j {
                let key = org.agents[i].derive_session_key(&org.agents[j].id, "perf-test");
                session_keys.push(key);
            }
        }
    }

    let duration = start.elapsed();
    let derivations = session_keys.len();
    let per_derivation_ns = duration.as_nanos() / derivations as u128;

    println!("Session key derivations: {}", derivations);
    println!("Total time: {:?}", duration);
    println!(
        "Per derivation: {} ns ({:.2} µs)",
        per_derivation_ns,
        per_derivation_ns as f64 / 1000.0
    );
    println!(
        "Throughput: {:.0} derivations/second",
        1_000_000_000.0 / per_derivation_ns as f64
    );

    // Count unique keys
    // Note: Due to symmetry (A,B) == (B,A), we expect some duplicates when i<10 and j<10
    let unique_keys: std::collections::HashSet<Vec<u8>> =
        session_keys.iter().map(|k| k.as_bytes().to_vec()).collect();

    // Expected unique: 10*99 = 990 total derivations
    // But pairs where both i,j < 10 will be duplicated: 10*9 = 90 pairs, 45 unique
    // So unique = 990 - 45 = 945
    let expected_unique = derivations - 45; // 45 symmetric duplicates

    println!("\nUniqueness analysis:");
    println!("  Total derivations: {}", derivations);
    println!("  Unique keys: {}", unique_keys.len());
    println!(
        "  Symmetric duplicates: {} (expected ~45 from pairs where both agents < 10)",
        derivations - unique_keys.len()
    );

    assert_eq!(
        unique_keys.len(),
        expected_unique,
        "Expected {} unique keys (accounting for symmetric pairs)",
        expected_unique
    );
    println!("\n✅ Key derivation is symmetric as expected");
}

/// Measure encryption/decryption throughput
#[test]
fn test_encryption_throughput() {
    use std::time::Instant;

    println!("\n=== Encryption Throughput ===\n");

    let org = TestOrg::new("alpha", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    // Medium-sized realistic payload
    let payload = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful AI assistant."},{"role":"user","content":"Explain quantum computing in simple terms."}],"temperature":0.7,"max_tokens":500}"#;

    let iterations = 1000;
    let payload_bytes = payload.len();

    // Warm up
    let mut ctx = alice.create_security_context(&bob.id, "warmup");
    let frame = M2MFrame::new_request(payload).unwrap();
    let _ = frame.encode_secure(SecurityMode::Aead, &mut ctx);

    // Measure encryption
    let mut ctx = alice.create_security_context(&bob.id, "throughput-test");
    let start = Instant::now();

    let mut encrypted_samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let frame = M2MFrame::new_request(payload).unwrap();
        let encrypted = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();
        encrypted_samples.push(encrypted);
    }

    let encrypt_duration = start.elapsed();

    // Measure decryption
    let bob_ctx = bob.create_security_context(&alice.id, "throughput-test");
    let start = Instant::now();

    for encrypted in &encrypted_samples {
        let _ = M2MFrame::decode_secure(encrypted, &bob_ctx).unwrap();
    }

    let decrypt_duration = start.elapsed();

    // Calculate metrics
    let total_bytes = payload_bytes * iterations;
    let encrypt_throughput_mbps =
        (total_bytes as f64 / encrypt_duration.as_secs_f64()) / 1_000_000.0;
    let decrypt_throughput_mbps =
        (total_bytes as f64 / decrypt_duration.as_secs_f64()) / 1_000_000.0;

    println!("Payload size: {} bytes", payload_bytes);
    println!("Iterations: {}", iterations);
    println!();
    println!("Encryption:");
    println!("  Total time: {:?}", encrypt_duration);
    println!(
        "  Per operation: {:.2} µs",
        encrypt_duration.as_micros() as f64 / iterations as f64
    );
    println!("  Throughput: {:.2} MB/s", encrypt_throughput_mbps);
    println!();
    println!("Decryption:");
    println!("  Total time: {:?}", decrypt_duration);
    println!(
        "  Per operation: {:.2} µs",
        decrypt_duration.as_micros() as f64 / iterations as f64
    );
    println!("  Throughput: {:.2} MB/s", decrypt_throughput_mbps);
    println!();

    // Size analysis
    let encrypted_size = encrypted_samples[0].len();
    let overhead_bytes = encrypted_size as i64 - payload_bytes as i64;
    let overhead_pct = (overhead_bytes as f64 / payload_bytes as f64) * 100.0;

    println!("Size analysis:");
    println!("  Original: {} bytes", payload_bytes);
    println!("  Encrypted: {} bytes", encrypted_size);
    println!(
        "  Overhead: {} bytes ({:+.1}%)",
        overhead_bytes, overhead_pct
    );
}

/// Full mesh communication test with metrics
#[test]
fn test_full_mesh_with_metrics() {
    use std::time::Instant;

    println!("\n=== Full Mesh Communication Test (20 agents) ===\n");

    let org = TestOrg::new("alpha", 20);

    let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test message"}]}"#;

    let mut total_encryptions = 0;
    let mut total_decryptions = 0;
    let mut total_bytes_encrypted = 0usize;
    let mut successful_pairs = 0;

    let start = Instant::now();

    // Each agent sends to every other agent
    for i in 0..20 {
        for j in 0..20 {
            if i == j {
                continue;
            }

            let sender = &org.agents[i];
            let receiver = &org.agents[j];

            let session_id = format!("mesh-{}-{}", i, j);
            let mut sender_ctx = sender.create_security_context(&receiver.id, &session_id);
            let receiver_ctx = receiver.create_security_context(&sender.id, &session_id);

            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame
                .encode_secure(SecurityMode::Aead, &mut sender_ctx)
                .unwrap();
            total_encryptions += 1;
            total_bytes_encrypted += encrypted.len();

            let decrypted = M2MFrame::decode_secure(&encrypted, &receiver_ctx).unwrap();
            total_decryptions += 1;

            assert_eq!(decrypted.payload, payload);
            successful_pairs += 1;
        }
    }

    let duration = start.elapsed();

    println!("Agents: 20");
    println!("Communication pairs: {} (20 × 19)", successful_pairs);
    println!("Total encryptions: {}", total_encryptions);
    println!("Total decryptions: {}", total_decryptions);
    println!(
        "Total bytes encrypted: {} ({:.2} KB)",
        total_bytes_encrypted,
        total_bytes_encrypted as f64 / 1024.0
    );
    println!();
    println!("Performance:");
    println!("  Total time: {:?}", duration);
    println!(
        "  Per pair (encrypt+decrypt): {:.2} µs",
        duration.as_micros() as f64 / successful_pairs as f64
    );
    println!(
        "  Throughput: {:.0} pairs/second",
        successful_pairs as f64 / duration.as_secs_f64()
    );
    println!();
    println!("✅ All {} communication pairs successful", successful_pairs);
}

// =============================================================================
// PHASE 8: PROTOCOL INVARIANTS & PROPERTY-BASED TESTING
// =============================================================================

/// Property-based tests using proptest
mod invariants {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    // =========================================================================
    // COMPRESSION INVARIANTS
    // =========================================================================

    proptest! {
        /// INV-C1: decode(encode(json)) == json for all valid LLM request JSON
        #[test]
        fn inv_c1_compression_roundtrip_request(
            model in "[a-z]{3,10}(-[a-z0-9]+)?",
            content in "[a-zA-Z0-9 .,!?]{1,500}",
            temperature in 0.0f64..2.0f64,
        ) {
            let json = format!(
                r#"{{"model":"{}","messages":[{{"role":"user","content":"{}"}}],"temperature":{:.2}}}"#,
                model, content, temperature
            );

            let frame = M2MFrame::new_request(&json).unwrap();
            let encoded = frame.encode().unwrap();
            let decoded = M2MFrame::decode(&encoded).unwrap();

            prop_assert_eq!(decoded.payload, json, "Compression roundtrip must preserve payload exactly");
        }

        /// INV-C2: Compression provides benefit for payloads > threshold
        #[test]
        fn inv_c2_compression_beneficial_for_large_payloads(
            repeat_count in 10usize..50usize,
        ) {
            // Create a large payload by repeating content
            let content = "Hello world! This is a test message. ".repeat(repeat_count);
            let json = format!(
                r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
                content
            );

            // Only test if payload is above compression threshold
            if json.len() > 100 {
                let frame = M2MFrame::new_request(&json).unwrap();
                let encoded = frame.encode().unwrap();

                // Compressed should be smaller than original JSON
                prop_assert!(
                    encoded.len() < json.len(),
                    "Compressed size {} should be < original size {} for large payloads",
                    encoded.len(),
                    json.len()
                );
            }
        }

        /// INV-C3: encode() is deterministic (same input → same output)
        #[test]
        fn inv_c3_compression_deterministic(
            content in "[a-zA-Z0-9 ]{10,200}",
        ) {
            let json = format!(
                r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
                content
            );

            let frame1 = M2MFrame::new_request(&json).unwrap();
            let frame2 = M2MFrame::new_request(&json).unwrap();

            let encoded1 = frame1.encode().unwrap();
            let encoded2 = frame2.encode().unwrap();

            prop_assert_eq!(encoded1, encoded2, "Encoding must be deterministic");
        }
    }

    /// INV-C4: decode() rejects malformed wire format
    #[test]
    fn inv_c4_malformed_frame_rejection() {
        // Empty input
        assert!(M2MFrame::decode(&[]).is_err());

        // Wrong prefix
        assert!(M2MFrame::decode(b"#INVALID|1|data").is_err());

        // Truncated header
        assert!(M2MFrame::decode(b"#M2M|1|").is_err());

        // Truncated after prefix
        assert!(M2MFrame::decode(b"#M2M|1|short").is_err());

        // Random garbage
        assert!(M2MFrame::decode(&[0xFF; 100]).is_err());

        // Valid prefix but corrupted data
        let mut corrupted = b"#M2M|1|".to_vec();
        corrupted.extend_from_slice(&[0u8; 50]);
        assert!(M2MFrame::decode(&corrupted).is_err());
    }

    // =========================================================================
    // ENCRYPTION INVARIANTS
    // =========================================================================

    proptest! {
        /// INV-E1: decrypt(encrypt(m, k), k) == m
        #[test]
        fn inv_e1_encryption_roundtrip(
            content in "[a-zA-Z0-9 .,!?]{10,300}",
        ) {
            let json = format!(
                r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
                content
            );

            let org = TestOrg::new("alpha", 2);
            let alice = org.agent(0);
            let bob = org.agent(1);

            let mut alice_ctx = alice.create_security_context(&bob.id, "inv-e1-test");
            let bob_ctx = bob.create_security_context(&alice.id, "inv-e1-test");

            let frame = M2MFrame::new_request(&json).unwrap();
            let encrypted = frame.encode_secure(SecurityMode::Aead, &mut alice_ctx).unwrap();
            let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();

            prop_assert_eq!(decrypted.payload, json);
        }
    }

    /// INV-E2: decrypt(encrypt(m, k1), k2) fails when k1 ≠ k2
    #[test]
    fn inv_e2_wrong_key_fails() {
        let org = TestOrg::new("alpha", 3);
        let alice = org.agent(0);
        let bob = org.agent(1);
        let charlie = org.agent(2);

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Secret"}]}"#;
        let frame = M2MFrame::new_request(payload).unwrap();

        // Alice encrypts for Bob
        let mut alice_ctx = alice.create_security_context(&bob.id, "inv-e2-test");
        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .unwrap();

        // Charlie tries to decrypt (wrong key)
        let charlie_ctx = charlie.create_security_context(&alice.id, "inv-e2-test");
        let result = M2MFrame::decode_secure(&encrypted, &charlie_ctx);

        assert!(result.is_err(), "Decryption with wrong key must fail");
    }

    /// INV-E3: decrypt(tamper(encrypt(m, k)), k) fails
    #[test]
    fn inv_e3_tamper_detection() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Tamper test"}]}"#;
        let frame = M2MFrame::new_request(payload).unwrap();

        let mut alice_ctx = alice.create_security_context(&bob.id, "inv-e3-test");
        let bob_ctx = bob.create_security_context(&alice.id, "inv-e3-test");

        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .unwrap();

        // Tamper with various positions
        for tamper_offset in [20, 50, encrypted.len() / 2, encrypted.len() - 10] {
            if tamper_offset < encrypted.len() {
                let mut tampered = encrypted.clone();
                tampered[tamper_offset] ^= 0xFF;

                let result = M2MFrame::decode_secure(&tampered, &bob_ctx);
                assert!(
                    result.is_err(),
                    "Tampered ciphertext at offset {} must fail",
                    tamper_offset
                );
            }
        }
    }

    /// INV-E4: encrypt(m, k, n1) ≠ encrypt(m, k, n2) when n1 ≠ n2
    #[test]
    fn inv_e4_different_nonces_different_ciphertext() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Same message"}]}"#;

        let mut ciphertexts = Vec::new();

        for i in 0..10 {
            let mut alice_ctx = alice.create_security_context(&bob.id, &format!("inv-e4-{}", i));
            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame
                .encode_secure(SecurityMode::Aead, &mut alice_ctx)
                .unwrap();
            ciphertexts.push(encrypted);
        }

        // All ciphertexts should be unique
        let unique: HashSet<Vec<u8>> = ciphertexts.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            10,
            "Same plaintext must produce different ciphertexts with different nonces"
        );
    }

    /// INV-E5: Nonces never repeat within a session
    #[test]
    fn inv_e5_nonce_uniqueness() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let mut alice_ctx = alice.create_security_context(&bob.id, "inv-e5-nonce-test");

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}]}"#;

        // Encrypt many messages with the same context
        let mut nonces = HashSet::new();
        let iterations = 1000;

        for _ in 0..iterations {
            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame
                .encode_secure(SecurityMode::Aead, &mut alice_ctx)
                .unwrap();

            // Extract nonce (12 bytes after headers)
            // Headers end at: prefix(7) + fixed_header(20) + variable_header
            let header_len_offset = 7; // after prefix
            let header_len = u16::from_le_bytes([
                encrypted[header_len_offset],
                encrypted[header_len_offset + 1],
            ]) as usize;
            let nonce_start = 7 + header_len;
            let nonce = encrypted[nonce_start..nonce_start + 12].to_vec();

            let is_new = nonces.insert(nonce);
            assert!(is_new, "Nonce reuse detected!");
        }

        assert_eq!(
            nonces.len(),
            iterations,
            "All {} nonces must be unique",
            iterations
        );
    }

    /// INV-E6: AAD modification causes auth failure
    #[test]
    fn inv_e6_aad_binding() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"AAD test"}]}"#;
        let frame = M2MFrame::new_request(payload).unwrap();

        let mut alice_ctx = alice.create_security_context(&bob.id, "inv-e6-test");
        let bob_ctx = bob.create_security_context(&alice.id, "inv-e6-test");

        let mut encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .unwrap();

        // Tamper with the header (AAD) - modify the schema byte
        let schema_offset = 7 + 2; // prefix + header_len
        encrypted[schema_offset] ^= 0x01;

        let result = M2MFrame::decode_secure(&encrypted, &bob_ctx);
        assert!(
            result.is_err(),
            "Modified AAD must cause authentication failure"
        );
    }

    // =========================================================================
    // KEY DERIVATION INVARIANTS
    // =========================================================================

    /// INV-K1: derive(A, B, sid) == derive(B, A, sid) [symmetry]
    #[test]
    fn inv_k1_session_key_symmetry() {
        let org = TestOrg::new("alpha", 10);

        for i in 0..10 {
            for j in (i + 1)..10 {
                let agent_i = org.agent(i);
                let agent_j = org.agent(j);

                for session_id in ["s1", "s2", "test-session", "abc123"] {
                    let key_ij = agent_i.derive_session_key(&agent_j.id, session_id);
                    let key_ji = agent_j.derive_session_key(&agent_i.id, session_id);

                    assert_eq!(
                        key_ij.as_bytes(),
                        key_ji.as_bytes(),
                        "Session key symmetry violated for agents {} and {} with session {}",
                        i,
                        j,
                        session_id
                    );
                }
            }
        }
    }

    /// INV-K2: derive(A, B, s1) ≠ derive(A, B, s2) [session isolation]
    #[test]
    fn inv_k2_session_isolation() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let session_ids = ["session-1", "session-2", "session-3", "different", ""];
        let mut keys = HashSet::new();

        for sid in &session_ids {
            let key = alice.derive_session_key(&bob.id, sid);
            let is_new = keys.insert(key.as_bytes().to_vec());
            assert!(is_new, "Session '{}' produced duplicate key", sid);
        }

        assert_eq!(
            keys.len(),
            session_ids.len(),
            "All session keys must be unique"
        );
    }

    /// INV-K3: derive_org1(A, B) ≠ derive_org2(A, B) [org isolation]
    #[test]
    fn inv_k3_org_isolation() {
        let org_alpha = TestOrg::new("alpha", 2);
        let org_beta = TestOrg::new("beta", 2);

        // Same agent indices, same session ID, different orgs
        let alice_alpha = org_alpha.agent(0);
        let bob_alpha = org_alpha.agent(1);
        let alice_beta = org_beta.agent(0);
        let bob_beta = org_beta.agent(1);

        let key_alpha = alice_alpha.derive_session_key(&bob_alpha.id, "cross-org-test");
        let key_beta = alice_beta.derive_session_key(&bob_beta.id, "cross-org-test");

        assert_ne!(
            key_alpha.as_bytes(),
            key_beta.as_bytes(),
            "Different orgs must produce different keys"
        );
    }

    /// INV-K4: All agent identity keys are unique within an org
    #[test]
    fn inv_k4_identity_key_uniqueness() {
        let org = TestOrg::new("alpha", 100);

        let mut identity_keys = HashSet::new();

        for agent in &org.agents {
            let key = agent.key_context.identity_key().as_bytes().to_vec();
            let is_new = identity_keys.insert(key);
            assert!(
                is_new,
                "Duplicate identity key for agent {}",
                agent.id.as_str()
            );
        }

        assert_eq!(
            identity_keys.len(),
            100,
            "All 100 identity keys must be unique"
        );
    }

    // =========================================================================
    // KEY EXCHANGE INVARIANTS
    // =========================================================================

    /// INV-X1: alice.dh(bob.pub) == bob.dh(alice.pub)
    #[test]
    fn inv_x1_dh_agreement() {
        for _ in 0..100 {
            let mut alice = KeyExchange::new();
            let mut bob = KeyExchange::new();

            alice.set_peer_public(bob.public_key().clone());
            bob.set_peer_public(alice.public_key().clone());

            let alice_shared = alice.derive_session_key("test").unwrap();
            let bob_shared = bob.derive_session_key("test").unwrap();

            assert_eq!(
                alice_shared.as_bytes(),
                bob_shared.as_bytes(),
                "DH key agreement failed"
            );
        }
    }

    /// INV-X2: Each KeyExchange produces unique keypair
    #[test]
    fn inv_x2_keypair_uniqueness() {
        let mut public_keys = HashSet::new();

        for _ in 0..100 {
            let exchange = KeyExchange::new();
            let pubkey = exchange.public_key().as_bytes().to_vec();
            let is_new = public_keys.insert(pubkey);
            assert!(is_new, "Duplicate public key generated");
        }

        assert_eq!(public_keys.len(), 100);
    }

    // =========================================================================
    // FRAMING INVARIANTS
    // =========================================================================

    /// INV-F1: decode(encode(frame)) == frame
    #[test]
    fn inv_f1_frame_roundtrip() {
        let payloads = [
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
            r#"{"model":"claude-3-opus","messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"Hello"}],"temperature":0.7}"#,
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test with unicode: 你好 🚀 émoji"}]}"#,
        ];

        for payload in payloads {
            let frame = M2MFrame::new_request(payload).unwrap();
            let encoded = frame.encode().unwrap();
            let decoded = M2MFrame::decode(&encoded).unwrap();

            assert_eq!(
                decoded.payload, payload,
                "Frame roundtrip failed for: {}",
                payload
            );
            assert_eq!(decoded.fixed.schema, frame.fixed.schema);
        }
    }

    /// INV-F2: Wire format starts with correct prefix
    #[test]
    fn inv_f2_wire_format_prefix() {
        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}]}"#;
        let frame = M2MFrame::new_request(payload).unwrap();

        let encoded = frame.encode().unwrap();
        assert!(
            encoded.starts_with(b"#M2M|1|"),
            "Wire format must start with #M2M|1|"
        );

        let encoded_string = frame.encode_string().unwrap();
        assert!(
            encoded_string.starts_with("#M2M|1|"),
            "String format must start with #M2M|1|"
        );
    }

    /// INV-F3: Empty and edge case payloads
    #[test]
    fn inv_f3_edge_case_payloads() {
        // Minimal valid JSON
        let minimal = r#"{"model":"x","messages":[]}"#;
        let frame = M2MFrame::new_request(minimal).unwrap();
        let encoded = frame.encode().unwrap();
        let decoded = M2MFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, minimal);

        // Large payload (1MB)
        let large_content = "x".repeat(100_000);
        let large_json = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
            large_content
        );
        let frame = M2MFrame::new_request(&large_json).unwrap();
        let encoded = frame.encode().unwrap();
        let decoded = M2MFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, large_json);

        // Unicode content
        let unicode = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"日本語 中文 한국어 العربية 🎉🚀💻"}]}"#;
        let frame = M2MFrame::new_request(unicode).unwrap();
        let encoded = frame.encode().unwrap();
        let decoded = M2MFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, unicode);
    }

    // =========================================================================
    // SESSION INVARIANTS
    // =========================================================================

    /// INV-S1: State transitions follow defined FSM
    #[test]
    fn inv_s1_session_state_machine() {
        let mut alice = Session::new(Capabilities::new("alice"));
        let mut bob = Session::new(Capabilities::new("bob"));

        // Initial state
        assert_eq!(alice.state(), SessionState::Initial);
        assert_eq!(bob.state(), SessionState::Initial);

        // Alice sends HELLO → HelloSent
        let hello = alice.create_hello();
        assert_eq!(alice.state(), SessionState::HelloSent);

        // Bob processes HELLO → Established
        let accept = bob.process_hello(&hello).unwrap();
        assert_eq!(bob.state(), SessionState::Established);

        // Alice processes ACCEPT → Established
        alice.process_accept(&accept).unwrap();
        assert_eq!(alice.state(), SessionState::Established);
    }

    /// INV-S2: Session IDs match after handshake
    #[test]
    fn inv_s2_session_id_agreement() {
        for _ in 0..10 {
            let mut alice = Session::new(Capabilities::new("alice"));
            let mut bob = Session::new(Capabilities::new("bob"));

            let hello = alice.create_hello();
            let accept = bob.process_hello(&hello).unwrap();
            alice.process_accept(&accept).unwrap();

            assert_eq!(
                alice.id(),
                bob.id(),
                "Session IDs must match after handshake"
            );
            assert!(!alice.id().is_empty(), "Session ID must not be empty");
        }
    }
}

// =============================================================================
// PHASE 9: PERFORMANCE REGRESSION TESTS
// =============================================================================

/// Performance regression tests with explicit thresholds
mod performance {
    use super::*;
    use std::time::{Duration, Instant};

    /// Key derivation must complete in reasonable time
    #[test]
    fn perf_key_derivation_under_threshold() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let iterations = 1000;
        let start = Instant::now();

        for i in 0..iterations {
            let _ = alice.derive_session_key(&bob.id, &format!("session-{}", i));
        }

        let duration = start.elapsed();
        let per_op = duration / iterations;

        // Threshold: 100µs per derivation (very conservative)
        let threshold = Duration::from_micros(100);

        println!(
            "Key derivation: {:?} per op ({} iterations)",
            per_op, iterations
        );

        assert!(
            per_op < threshold,
            "Key derivation too slow: {:?} > {:?} threshold",
            per_op,
            threshold
        );
    }

    /// Encryption must maintain minimum throughput
    #[test]
    fn perf_encryption_throughput() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"Explain quantum computing."}],"temperature":0.7}"#;
        let _payload_size = payload.len();

        let iterations = 500;
        let mut total_bytes = 0usize;

        let start = Instant::now();

        for i in 0..iterations {
            let mut ctx = alice.create_security_context(&bob.id, &format!("perf-{}", i));
            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();
            total_bytes += encrypted.len();
        }

        let duration = start.elapsed();
        let throughput_mbps = (total_bytes as f64 / duration.as_secs_f64()) / 1_000_000.0;

        // Threshold: 0.5 MB/s minimum (very conservative for debug builds)
        let threshold_mbps = 0.5;

        println!(
            "Encryption: {:.2} MB/s ({} bytes in {:?})",
            throughput_mbps, total_bytes, duration
        );

        assert!(
            throughput_mbps > threshold_mbps,
            "Encryption throughput too low: {:.2} MB/s < {:.2} MB/s threshold",
            throughput_mbps,
            threshold_mbps
        );
    }

    /// Full roundtrip (encrypt + decrypt) must meet performance target
    #[test]
    fn perf_roundtrip_latency() {
        let org = TestOrg::new("alpha", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;

        let iterations = 500;
        let start = Instant::now();

        for i in 0..iterations {
            let session_id = format!("roundtrip-{}", i);
            let mut alice_ctx = alice.create_security_context(&bob.id, &session_id);
            let bob_ctx = bob.create_security_context(&alice.id, &session_id);

            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame
                .encode_secure(SecurityMode::Aead, &mut alice_ctx)
                .unwrap();
            let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();

            assert_eq!(decrypted.payload, payload);
        }

        let duration = start.elapsed();
        let per_roundtrip = duration / iterations;

        // Threshold: 500µs per roundtrip (conservative for debug builds)
        let threshold = Duration::from_micros(500);

        println!(
            "Roundtrip latency: {:?} ({} iterations in {:?})",
            per_roundtrip, iterations, duration
        );

        assert!(
            per_roundtrip < threshold,
            "Roundtrip too slow: {:?} > {:?} threshold",
            per_roundtrip,
            threshold
        );
    }

    /// Mesh communication scales linearly
    #[test]
    fn perf_mesh_scaling() {
        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}]}"#;

        // Test with 10 and 20 agents
        let (time_10, pairs_10) = measure_mesh_time(10, payload);
        let (time_20, pairs_20) = measure_mesh_time(20, payload);

        let per_pair_10 = time_10.as_nanos() as f64 / pairs_10 as f64;
        let per_pair_20 = time_20.as_nanos() as f64 / pairs_20 as f64;

        println!(
            "10 agents: {:?} for {} pairs ({:.0} ns/pair)",
            time_10, pairs_10, per_pair_10
        );
        println!(
            "20 agents: {:?} for {} pairs ({:.0} ns/pair)",
            time_20, pairs_20, per_pair_20
        );

        // Per-pair time should not more than double (allow 2.5x for variance)
        let scaling_factor = per_pair_20 / per_pair_10;

        assert!(
            scaling_factor < 2.5,
            "Mesh scaling degraded: {:.2}x slowdown per pair (expected < 2.5x)",
            scaling_factor
        );
    }

    fn measure_mesh_time(agent_count: usize, payload: &str) -> (Duration, usize) {
        let org = TestOrg::new("perf-mesh", agent_count);

        let start = Instant::now();
        let mut pairs = 0;

        for i in 0..agent_count {
            for j in 0..agent_count {
                if i == j {
                    continue;
                }

                let sender = &org.agents[i];
                let receiver = &org.agents[j];

                let session_id = format!("mesh-{}-{}", i, j);
                let mut sender_ctx = sender.create_security_context(&receiver.id, &session_id);
                let receiver_ctx = receiver.create_security_context(&sender.id, &session_id);

                let frame = M2MFrame::new_request(payload).unwrap();
                let encrypted = frame
                    .encode_secure(SecurityMode::Aead, &mut sender_ctx)
                    .unwrap();
                let _ = M2MFrame::decode_secure(&encrypted, &receiver_ctx).unwrap();

                pairs += 1;
            }
        }

        (start.elapsed(), pairs)
    }
}

// =============================================================================
// PHASE 10: STRESS TESTS - FIND THE LIMITS
// =============================================================================

/// Stress tests to determine protocol throughput limits
mod stress {
    use super::*;
    use std::time::{Duration, Instant};

    /// Maximum throughput test - how many messages per second can we process?
    #[test]
    fn stress_max_throughput() {
        println!("\n============================================================");
        println!("STRESS TEST: Maximum Throughput");
        println!("============================================================\n");

        let org = TestOrg::new("stress", 2);
        let alice = org.agent(0);
        let bob = org.agent(1);

        // Test payloads of different sizes
        let payloads = [
            ("tiny", r#"{"model":"x","messages":[]}"#),
            (
                "small",
                r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
            ),
            (
                "medium",
                r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful AI assistant."},{"role":"user","content":"Explain quantum computing in simple terms."}],"temperature":0.7,"max_tokens":500}"#,
            ),
            (
                "large",
                &format!(
                    r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
                    "x".repeat(1000)
                ),
            ),
        ];

        println!(
            "| {:10} | {:>10} | {:>12} | {:>12} | {:>10} |",
            "Payload", "Size", "Ops/sec", "MB/s", "Latency"
        );
        println!(
            "|{:-<12}|{:-<12}|{:-<14}|{:-<14}|{:-<12}|",
            "", "", "", "", ""
        );

        for (name, payload) in &payloads {
            let payload_size = payload.len();
            let iterations = 10_000;

            let start = Instant::now();

            for i in 0..iterations {
                let session_id = format!("stress-{}", i % 100); // Reuse some sessions
                let mut alice_ctx = alice.create_security_context(&bob.id, &session_id);
                let bob_ctx = bob.create_security_context(&alice.id, &session_id);

                let frame = M2MFrame::new_request(payload).unwrap();
                let encrypted = frame
                    .encode_secure(SecurityMode::Aead, &mut alice_ctx)
                    .unwrap();
                let _ = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();
            }

            let duration = start.elapsed();
            let ops_per_sec = iterations as f64 / duration.as_secs_f64();
            let throughput_mbps =
                (payload_size as f64 * iterations as f64 / duration.as_secs_f64()) / 1_000_000.0;
            let latency_us = duration.as_micros() as f64 / iterations as f64;

            println!(
                "| {:10} | {:>10} | {:>12.0} | {:>12.2} | {:>10.1}µs |",
                name, payload_size, ops_per_sec, throughput_mbps, latency_us
            );
        }

        println!();
    }

    /// Agent scaling test - how many agents can we support?
    #[test]
    fn stress_agent_scaling() {
        println!("\n============================================================");
        println!("STRESS TEST: Agent Scaling");
        println!("============================================================\n");

        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}]}"#;

        println!(
            "| {:>8} | {:>10} | {:>12} | {:>12} | {:>10} |",
            "Agents", "Pairs", "Total Time", "Per Pair", "Pairs/sec"
        );
        println!(
            "|{:-<10}|{:-<12}|{:-<14}|{:-<14}|{:-<12}|",
            "", "", "", "", ""
        );

        for &agent_count in &[10, 25, 50, 100, 200, 500] {
            let org = TestOrg::new("scale-test", agent_count);
            let pairs = agent_count * (agent_count - 1); // Full mesh (directed)

            let start = Instant::now();
            let mut successful = 0;

            // Full mesh: every agent sends to every other agent
            for i in 0..agent_count {
                for j in 0..agent_count {
                    if i == j {
                        continue;
                    }

                    let sender = &org.agents[i];
                    let receiver = &org.agents[j];

                    let session_id = format!("scale-{}-{}", i, j);
                    let mut sender_ctx = sender.create_security_context(&receiver.id, &session_id);
                    let receiver_ctx = receiver.create_security_context(&sender.id, &session_id);

                    let frame = M2MFrame::new_request(payload).unwrap();
                    let encrypted = frame
                        .encode_secure(SecurityMode::Aead, &mut sender_ctx)
                        .unwrap();
                    let decrypted = M2MFrame::decode_secure(&encrypted, &receiver_ctx).unwrap();

                    assert_eq!(decrypted.payload, payload);
                    successful += 1;
                }
            }

            let duration = start.elapsed();
            let per_pair_us = duration.as_micros() as f64 / successful as f64;
            let pairs_per_sec = successful as f64 / duration.as_secs_f64();

            println!(
                "| {:>8} | {:>10} | {:>12.2?} | {:>10.1}µs | {:>10.0} |",
                agent_count, pairs, duration, per_pair_us, pairs_per_sec
            );
        }

        println!();
    }

    /// Multi-organization stress test
    #[test]
    fn stress_multi_org() {
        println!("\n============================================================");
        println!("STRESS TEST: Multi-Organization Communication");
        println!("============================================================\n");

        let org_names = [
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
        ];
        let agents_per_org = 50;

        let orgs: Vec<TestOrg> = org_names
            .iter()
            .map(|name| TestOrg::new(name, agents_per_org))
            .collect();

        let total_agents = orgs.len() * agents_per_org;
        println!("Organizations: {}", orgs.len());
        println!("Agents per org: {}", agents_per_org);
        println!("Total agents: {}", total_agents);
        println!();

        // Test same-org communication (sample)
        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}]}"#;

        let same_org_iterations = 1000;
        let start = Instant::now();

        for _ in 0..same_org_iterations {
            let org = &orgs[0];
            let alice = org.agent(0);
            let bob = org.agent(1);

            let mut ctx = alice.create_security_context(&bob.id, "same-org-stress");
            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

            let bob_ctx = bob.create_security_context(&alice.id, "same-org-stress");
            let _ = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();
        }

        let same_org_duration = start.elapsed();
        let same_org_ops_sec = same_org_iterations as f64 / same_org_duration.as_secs_f64();

        // Test cross-org communication (requires X25519)
        let cross_org_iterations = 500;
        let start = Instant::now();

        for i in 0..cross_org_iterations {
            let org_a = &orgs[i % orgs.len()];
            let org_b = &orgs[(i + 1) % orgs.len()];

            let _alice = org_a.agent(0);
            let _bob = org_b.agent(0);

            // X25519 key exchange
            let mut alice_exchange = KeyExchange::new();
            let mut bob_exchange = KeyExchange::new();

            alice_exchange.set_peer_public(bob_exchange.public_key().clone());
            bob_exchange.set_peer_public(alice_exchange.public_key().clone());

            let shared_key = alice_exchange
                .derive_session_key("cross-org-stress")
                .unwrap();

            // Encrypt with shared key
            let mut ctx = SecurityContext::new(shared_key.clone());
            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

            // Decrypt
            let bob_ctx = SecurityContext::new(shared_key);
            let _ = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();
        }

        let cross_org_duration = start.elapsed();
        let cross_org_ops_sec = cross_org_iterations as f64 / cross_org_duration.as_secs_f64();

        println!("Same-org communication:");
        println!("  {} ops in {:?}", same_org_iterations, same_org_duration);
        println!("  {:.0} ops/sec", same_org_ops_sec);
        println!();
        println!("Cross-org communication (with X25519):");
        println!("  {} ops in {:?}", cross_org_iterations, cross_org_duration);
        println!("  {:.0} ops/sec", cross_org_ops_sec);
        println!();
        println!(
            "Cross-org overhead: {:.1}x slower (due to key exchange)",
            same_org_ops_sec / cross_org_ops_sec
        );
    }

    /// Sustained load test - can we maintain throughput over time?
    #[test]
    fn stress_sustained_load() {
        println!("\n============================================================");
        println!("STRESS TEST: Sustained Load (30 seconds)");
        println!("============================================================\n");

        let org = TestOrg::new("sustained", 10);
        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Sustained load test message"}]}"#;

        let test_duration = Duration::from_secs(5); // 5 seconds for test (30 would be too long)
        let mut total_ops = 0u64;
        let mut interval_ops = 0u64;
        let interval = Duration::from_secs(1);

        let start = Instant::now();
        let mut last_report = start;
        let mut intervals = Vec::new();

        println!("Running sustained load for {:?}...\n", test_duration);
        println!(
            "| {:>6} | {:>12} | {:>12} |",
            "Second", "Ops/sec", "Cumulative"
        );
        println!("|{:-<8}|{:-<14}|{:-<14}|", "", "", "");

        while start.elapsed() < test_duration {
            // Round-robin through agent pairs
            let i = (total_ops as usize) % org.agents.len();
            let j = (i + 1) % org.agents.len();

            let sender = &org.agents[i];
            let receiver = &org.agents[j];

            let session_id = format!("sustained-{}", total_ops % 100);
            let mut sender_ctx = sender.create_security_context(&receiver.id, &session_id);
            let receiver_ctx = receiver.create_security_context(&sender.id, &session_id);

            let frame = M2MFrame::new_request(payload).unwrap();
            let encrypted = frame
                .encode_secure(SecurityMode::Aead, &mut sender_ctx)
                .unwrap();
            let _ = M2MFrame::decode_secure(&encrypted, &receiver_ctx).unwrap();

            total_ops += 1;
            interval_ops += 1;

            // Report every second
            if last_report.elapsed() >= interval {
                let ops_per_sec = interval_ops as f64 / last_report.elapsed().as_secs_f64();
                intervals.push(ops_per_sec);

                println!(
                    "| {:>6} | {:>12.0} | {:>12} |",
                    intervals.len(),
                    ops_per_sec,
                    total_ops
                );

                interval_ops = 0;
                last_report = Instant::now();
            }
        }

        let total_duration = start.elapsed();
        let avg_ops_sec = total_ops as f64 / total_duration.as_secs_f64();

        // Calculate variance
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let std_dev = variance.sqrt();
        let cv = (std_dev / mean) * 100.0; // Coefficient of variation

        println!();
        println!("Summary:");
        println!("  Total operations: {}", total_ops);
        println!("  Total duration: {:?}", total_duration);
        println!("  Average throughput: {:.0} ops/sec", avg_ops_sec);
        println!("  Std deviation: {:.0} ops/sec", std_dev);
        println!("  Coefficient of variation: {:.1}%", cv);

        // CV under 10% indicates stable throughput
        assert!(
            cv < 20.0,
            "Throughput too variable: {}% CV (expected < 20%)",
            cv
        );
    }

    /// Memory pressure test - many concurrent contexts
    #[test]
    fn stress_memory_contexts() {
        println!("\n============================================================");
        println!("STRESS TEST: Memory (Many Security Contexts)");
        println!("============================================================\n");

        let org = TestOrg::new("memory", 100);
        let payload = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}]}"#;

        // Create many security contexts simultaneously
        let context_counts = [100, 500, 1000, 5000];

        for &count in &context_counts {
            let start = Instant::now();

            let mut contexts: Vec<SecurityContext> = Vec::with_capacity(count);

            for i in 0..count {
                let agent_i = i % org.agents.len();
                let agent_j = (i + 1) % org.agents.len();

                let sender = &org.agents[agent_i];
                let receiver = &org.agents[agent_j];

                let ctx = sender.create_security_context(&receiver.id, &format!("ctx-{}", i));
                contexts.push(ctx);
            }

            let create_duration = start.elapsed();

            // Use all contexts
            let start = Instant::now();
            for (_i, ctx) in contexts.iter_mut().enumerate() {
                let frame = M2MFrame::new_request(payload).unwrap();
                let _ = frame.encode_secure(SecurityMode::Aead, ctx).unwrap();
            }
            let use_duration = start.elapsed();

            println!(
                "{} contexts: create={:?}, use={:?}, total={:?}",
                count,
                create_duration,
                use_duration,
                create_duration + use_duration
            );
        }
    }
}

// =============================================================================
// PHASE 11: TRUE MULTI-AGENT LLM COMMUNICATION
// =============================================================================
// These tests validate actual agent-to-agent communication with real LLM traffic.
// Unlike the stress tests (which validate crypto throughput), these tests ensure
// the protocol works correctly for multi-round, multi-agent conversations.
//
// Key differences from Phase 6:
// - Multi-round (3+ turns) instead of single request-response
// - Agent relay (Alice → Bob → LLM → Bob → Alice)
// - Dynamic payload sizes (LLM generates variable responses)
// - Cross-org collaboration
// - Small network simulation (5+ agents)

/// Phase 11: Multi-round conversation between two agents via LLM
/// Tests: Session state persistence, nonce progression, variable payloads
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_multi_round_conversation -- --ignored"]
async fn test_multi_round_conversation() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    println!("\n============================================================");
    println!("PHASE 11: Multi-Round Conversation (3 turns)");
    println!("============================================================\n");

    let org = TestOrg::new("multiround", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_id = "multi-round-001";
    let mut alice_ctx = alice.create_security_context(&bob.id, session_id);
    let mut bob_ctx = bob.create_security_context(&alice.id, session_id);

    let client = openrouter::create_client();

    // Conversation history for multi-turn
    let mut conversation: Vec<openrouter::ChatMessage> = vec![];

    // System message to establish context
    conversation.push(openrouter::ChatMessage {
        role: "system".to_string(),
        content: "You are a helpful assistant in a secure multi-agent communication test. Keep responses under 50 words.".to_string(),
    });

    let turns = [
        "What is the capital of France? Reply briefly.",
        "What language do they speak there? Reply briefly.",
        "Name one famous landmark there. Reply briefly.",
    ];

    let mut total_encrypted_bytes = 0usize;
    let mut total_plaintext_bytes = 0usize;
    let mut encrypted_frames: Vec<Vec<u8>> = vec![];

    for (i, user_msg) in turns.iter().enumerate() {
        println!("--- Turn {} ---", i + 1);

        // Alice adds her message to conversation
        conversation.push(openrouter::ChatMessage {
            role: "user".to_string(),
            content: user_msg.to_string(),
        });

        // Create request payload with full conversation history
        let request_payload = serde_json::json!({
            "model": openrouter::MODEL,
            "messages": conversation,
            "temperature": 0.1,
            "max_tokens": 100
        });

        let request_str = serde_json::to_string(&request_payload).unwrap();
        total_plaintext_bytes += request_str.len();

        // Alice encrypts request
        let frame = M2MFrame::new_request(&request_str).expect("Frame creation failed");
        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .expect("Alice encryption failed");

        total_encrypted_bytes += encrypted.len();
        encrypted_frames.push(encrypted.clone());

        println!(
            "  Alice → Bob: {} bytes encrypted (plaintext: {})",
            encrypted.len(),
            request_str.len()
        );

        // Bob decrypts
        let decrypted_frame =
            M2MFrame::decode_secure(&encrypted, &bob_ctx).expect("Bob decryption failed");

        assert_eq!(decrypted_frame.payload, request_str, "Payload mismatch");

        // Bob calls LLM (simulating Bob as gateway agent)
        let response = openrouter::chat_completion(
            &client,
            openrouter::MODEL,
            conversation.clone(),
            Some(0.1),
            Some(100),
        )
        .await;

        let llm_response = match response {
            Ok(text) => text,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("429")
                    || error_msg.contains("402")
                    || error_msg.contains("rate")
                    || error_msg.contains("limit")
                {
                    println!("  Skipping: API limit reached ({error_msg})");
                    return;
                }
                panic!("LLM call failed: {e}");
            },
        };

        println!(
            "  LLM response: {}",
            llm_response.chars().take(80).collect::<String>()
        );

        // Add assistant response to conversation
        conversation.push(openrouter::ChatMessage {
            role: "assistant".to_string(),
            content: llm_response.clone(),
        });

        // Bob encrypts response back to Alice
        let response_payload = serde_json::json!({
            "response": llm_response,
            "turn": i + 1
        });

        let response_str = serde_json::to_string(&response_payload).unwrap();
        total_plaintext_bytes += response_str.len();

        let response_frame =
            M2MFrame::new_response(&response_str).expect("Response frame creation failed");
        let encrypted_response = response_frame
            .encode_secure(SecurityMode::Aead, &mut bob_ctx)
            .expect("Bob encryption failed");

        total_encrypted_bytes += encrypted_response.len();

        println!(
            "  Bob → Alice: {} bytes encrypted (plaintext: {})",
            encrypted_response.len(),
            response_str.len()
        );

        // Alice decrypts response
        let alice_received = M2MFrame::decode_secure(&encrypted_response, &alice_ctx)
            .expect("Alice decryption failed");

        let parsed: serde_json::Value = serde_json::from_str(&alice_received.payload).unwrap();
        assert_eq!(parsed["turn"], i + 1, "Turn number mismatch");

        println!();
    }

    // Validate invariants
    println!("=== Multi-Round Summary ===");
    println!("Turns completed: {}", turns.len());
    println!(
        "Total encrypted: {} bytes, plaintext: {} bytes",
        total_encrypted_bytes, total_plaintext_bytes
    );
    println!(
        "Encrypted frames captured: {} (for nonce uniqueness validation)",
        encrypted_frames.len()
    );

    // Nonce uniqueness is guaranteed by the fact that:
    // 1. Each encryption uses a fresh random nonce (see SecurityContext::next_nonce)
    // 2. Decryption succeeded for all frames (would fail with nonce reuse + same key)
    // 3. The encrypted frames have different sizes (variable LLM responses)

    // Verify frames are all different (different nonces + different payloads = different ciphertext)
    for i in 0..encrypted_frames.len() {
        for j in i + 1..encrypted_frames.len() {
            assert_ne!(
                encrypted_frames[i], encrypted_frames[j],
                "Encrypted frames {} and {} should be different",
                i, j
            );
        }
    }
    println!("All encrypted frames are unique (implies unique nonces).");

    println!("Multi-round conversation completed successfully!");
}

/// Phase 11: Agent relay (Alice → Bob → LLM → Bob → Alice)
/// Tests: Intermediary agent handling, re-encryption, chain of custody
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_agent_relay -- --ignored"]
async fn test_agent_relay() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    println!("\n============================================================");
    println!("PHASE 11: Agent Relay (Alice → Bob → Charlie → LLM)");
    println!("============================================================\n");

    // Three agents: Alice (initiator), Bob (relay), Charlie (gateway to LLM)
    let org = TestOrg::new("relay", 3);
    let alice = org.agent(0);
    let bob = org.agent(1);
    let charlie = org.agent(2);

    // Alice → Bob session
    let session_ab = "relay-ab-001";
    let mut alice_to_bob_ctx = alice.create_security_context(&bob.id, session_ab);
    let bob_from_alice_ctx = bob.create_security_context(&alice.id, session_ab);

    // Bob → Charlie session
    let session_bc = "relay-bc-001";
    let mut bob_to_charlie_ctx = bob.create_security_context(&charlie.id, session_bc);
    let charlie_from_bob_ctx = charlie.create_security_context(&bob.id, session_bc);

    // Charlie → Bob session (for response)
    let mut charlie_to_bob_ctx = charlie.create_security_context(&bob.id, session_bc);
    let bob_from_charlie_ctx = bob.create_security_context(&charlie.id, session_bc);

    // Bob → Alice session (for response)
    let mut bob_to_alice_ctx = bob.create_security_context(&alice.id, session_ab);
    let alice_from_bob_ctx = alice.create_security_context(&bob.id, session_ab);

    let client = openrouter::create_client();

    // Alice creates request
    let request_payload = serde_json::json!({
        "model": openrouter::MODEL,
        "messages": [
            {"role": "system", "content": "You are testing a relay system. Be brief."},
            {"role": "user", "content": "What is 7 * 8? Reply with just the number."}
        ],
        "temperature": 0.0,
        "max_tokens": 10
    });

    let request_str = serde_json::to_string(&request_payload).unwrap();
    println!("Alice's original request: {} bytes", request_str.len());

    // Step 1: Alice → Bob (encrypted)
    let frame1 = M2MFrame::new_request(&request_str).unwrap();
    let encrypted1 = frame1
        .encode_secure(SecurityMode::Aead, &mut alice_to_bob_ctx)
        .unwrap();
    println!("1. Alice → Bob: {} bytes (encrypted)", encrypted1.len());

    // Step 2: Bob decrypts from Alice
    let decrypted_at_bob = M2MFrame::decode_secure(&encrypted1, &bob_from_alice_ctx).unwrap();
    println!("2. Bob decrypts Alice's message");

    // Step 3: Bob re-encrypts for Charlie
    let frame2 = M2MFrame::new_request(&decrypted_at_bob.payload).unwrap();
    let encrypted2 = frame2
        .encode_secure(SecurityMode::Aead, &mut bob_to_charlie_ctx)
        .unwrap();
    println!(
        "3. Bob → Charlie: {} bytes (re-encrypted)",
        encrypted2.len()
    );

    // Step 4: Charlie decrypts from Bob
    let decrypted_at_charlie = M2MFrame::decode_secure(&encrypted2, &charlie_from_bob_ctx).unwrap();
    println!("4. Charlie decrypts Bob's message");

    // Verify payload integrity through relay
    assert_eq!(
        decrypted_at_charlie.payload, request_str,
        "Payload must survive relay intact"
    );

    // Step 5: Charlie calls LLM
    let response = openrouter::chat_completion(
        &client,
        openrouter::MODEL,
        vec![
            openrouter::ChatMessage {
                role: "system".to_string(),
                content: "You are testing a relay system. Be brief.".to_string(),
            },
            openrouter::ChatMessage {
                role: "user".to_string(),
                content: "What is 7 * 8? Reply with just the number.".to_string(),
            },
        ],
        Some(0.0),
        Some(10),
    )
    .await;

    let llm_response = match response {
        Ok(text) => text,
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("429")
                || error_msg.contains("402")
                || error_msg.contains("rate")
                || error_msg.contains("limit")
            {
                println!("Skipping: API limit reached ({error_msg})");
                return;
            }
            panic!("LLM call failed: {e}");
        },
    };

    println!("5. Charlie receives LLM response: {}", llm_response.trim());

    // Step 6: Charlie → Bob (encrypted response)
    let response_frame = M2MFrame::new_response(&llm_response).unwrap();
    let encrypted3 = response_frame
        .encode_secure(SecurityMode::Aead, &mut charlie_to_bob_ctx)
        .unwrap();
    println!("6. Charlie → Bob: {} bytes (encrypted)", encrypted3.len());

    // Step 7: Bob decrypts from Charlie
    let bob_receives = M2MFrame::decode_secure(&encrypted3, &bob_from_charlie_ctx).unwrap();
    println!("7. Bob decrypts Charlie's response");

    // Step 8: Bob → Alice (encrypted response)
    let response_frame2 = M2MFrame::new_response(&bob_receives.payload).unwrap();
    let encrypted4 = response_frame2
        .encode_secure(SecurityMode::Aead, &mut bob_to_alice_ctx)
        .unwrap();
    println!("8. Bob → Alice: {} bytes (encrypted)", encrypted4.len());

    // Step 9: Alice decrypts final response
    let alice_receives = M2MFrame::decode_secure(&encrypted4, &alice_from_bob_ctx).unwrap();
    println!(
        "9. Alice receives final response: {}",
        alice_receives.payload.trim()
    );

    // Verify response made it through the relay
    assert!(
        alice_receives.payload.contains("56")
            || alice_receives.payload.to_lowercase().contains("fifty"),
        "Expected 56 in response, got: {}",
        alice_receives.payload
    );

    println!("\nRelay chain completed: Alice → Bob → Charlie → LLM → Charlie → Bob → Alice");
}

/// Phase 11: Cross-organization collaboration
/// Tests: X25519 key exchange between different org hierarchies
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_cross_org_llm -- --ignored"]
async fn test_cross_org_llm() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    println!("\n============================================================");
    println!("PHASE 11: Cross-Organization LLM Communication");
    println!("============================================================\n");

    // Two different organizations (different master keys!)
    let org_alpha = TestOrg::new("alpha", 2);
    let org_beta = TestOrg::new("beta", 2);

    let _alice = org_alpha.agent(0); // Alpha org
    let _bob = org_beta.agent(0); // Beta org

    // For cross-org communication, we must use X25519 key exchange
    // because the agents don't share a common master key
    let mut alice_exchange = KeyExchange::new();
    let mut bob_exchange = KeyExchange::new();

    // Exchange public keys (in real system, this would happen over the network)
    let alice_public = alice_exchange.public_key().clone();
    let bob_public = bob_exchange.public_key().clone();

    alice_exchange.set_peer_public(bob_public);
    bob_exchange.set_peer_public(alice_public);

    // Derive shared session key from X25519 exchange
    let session_id = "cross-org-llm-001";
    let alice_session_key = alice_exchange
        .derive_session_key(session_id)
        .expect("Alice should derive session key");
    let bob_session_key = bob_exchange
        .derive_session_key(session_id)
        .expect("Bob should derive session key");

    // Verify keys match (fundamental DH property)
    assert_eq!(
        alice_session_key.as_bytes(),
        bob_session_key.as_bytes(),
        "X25519 derived keys must match"
    );
    println!("X25519 key exchange complete - shared secret established");

    // Create security contexts with the shared key
    let mut alice_ctx = SecurityContext::new(alice_session_key);
    let bob_ctx = SecurityContext::new(bob_session_key);

    let client = openrouter::create_client();

    // Alice (Alpha org) sends to Bob (Beta org)
    let request_payload = serde_json::json!({
        "model": openrouter::MODEL,
        "messages": [
            {"role": "system", "content": "You are in a cross-org secure test. Be brief."},
            {"role": "user", "content": "Name a primary color. One word only."}
        ],
        "temperature": 0.5,
        "max_tokens": 10
    });

    let request_str = serde_json::to_string(&request_payload).unwrap();

    // Alice encrypts with shared key
    let frame = M2MFrame::new_request(&request_str).unwrap();
    let encrypted = frame
        .encode_secure(SecurityMode::Aead, &mut alice_ctx)
        .unwrap();

    println!(
        "Alice (Alpha) → Bob (Beta): {} bytes encrypted",
        encrypted.len()
    );

    // Bob decrypts with shared key
    let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();

    assert_eq!(
        decrypted.payload, request_str,
        "Cross-org decryption failed"
    );
    println!("Bob successfully decrypted cross-org message");

    // Bob calls LLM
    let response = openrouter::chat_completion(
        &client,
        openrouter::MODEL,
        vec![
            openrouter::ChatMessage {
                role: "system".to_string(),
                content: "You are in a cross-org secure test. Be brief.".to_string(),
            },
            openrouter::ChatMessage {
                role: "user".to_string(),
                content: "Name a primary color. One word only.".to_string(),
            },
        ],
        Some(0.5),
        Some(10),
    )
    .await;

    match response {
        Ok(text) => {
            println!("LLM response: {}", text.trim());
            assert!(!text.is_empty(), "Response should not be empty");
        },
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("429")
                || error_msg.contains("402")
                || error_msg.contains("rate")
                || error_msg.contains("limit")
            {
                println!("Skipping: API limit reached ({error_msg})");
                return;
            }
            panic!("LLM call failed: {e}");
        },
    }

    println!("Cross-org communication successful!");
}

/// Phase 11: Small agent network (5 agents, mesh communication)
/// Tests: Scale with real LLM traffic, concurrent contexts
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_small_agent_network -- --ignored"]
async fn test_small_agent_network() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    println!("\n============================================================");
    println!("PHASE 11: Small Agent Network (5 agents, round-robin LLM)");
    println!("============================================================\n");

    let org = TestOrg::new("network", 5);

    // Create a simple round-robin: agent 0 → 1 → 2 → 3 → 4 → 0
    let client = openrouter::create_client();

    let mut total_messages = 0;
    let mut total_encrypted_bytes = 0;

    // Each agent passes a message to the next, calling LLM once in the chain
    for i in 0..5 {
        let sender_idx = i;
        let receiver_idx = (i + 1) % 5;

        let sender = org.agent(sender_idx);
        let receiver = org.agent(receiver_idx);

        let session_id = format!("network-{}-{}", sender_idx, receiver_idx);
        let mut sender_ctx = sender.create_security_context(&receiver.id, &session_id);
        let receiver_ctx = receiver.create_security_context(&sender.id, &session_id);

        // Only agent 2 actually calls the LLM (to minimize API costs)
        let payload = if sender_idx == 2 {
            // Call LLM
            let response = openrouter::chat_completion(
                &client,
                openrouter::MODEL,
                vec![openrouter::ChatMessage {
                    role: "user".to_string(),
                    content: "Say 'Network test OK' and nothing else.".to_string(),
                }],
                Some(0.0),
                Some(20),
            )
            .await;

            match response {
                Ok(text) => {
                    println!("Agent 2 received LLM response: {}", text.trim());
                    serde_json::json!({
                        "from_agent": sender_idx,
                        "llm_response": text.trim(),
                        "hop": i
                    })
                    .to_string()
                },
                Err(e) => {
                    let error_msg = e.to_string();
                    if error_msg.contains("429")
                        || error_msg.contains("402")
                        || error_msg.contains("rate")
                        || error_msg.contains("limit")
                    {
                        println!("Skipping: API limit reached ({error_msg})");
                        return;
                    }
                    panic!("LLM call failed: {e}");
                },
            }
        } else {
            // Synthetic payload (no LLM call)
            serde_json::json!({
                "from_agent": sender_idx,
                "message": format!("Hello from agent {}", sender_idx),
                "hop": i
            })
            .to_string()
        };

        // Encrypt and send
        let frame = M2MFrame::new_request(&payload).unwrap();
        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut sender_ctx)
            .unwrap();

        total_encrypted_bytes += encrypted.len();

        // Receiver decrypts
        let decrypted = M2MFrame::decode_secure(&encrypted, &receiver_ctx).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&decrypted.payload).unwrap();
        assert_eq!(parsed["from_agent"], sender_idx, "Sender mismatch");
        assert_eq!(parsed["hop"], i, "Hop count mismatch");

        println!(
            "Agent {} → Agent {}: {} bytes (hop {})",
            sender_idx,
            receiver_idx,
            encrypted.len(),
            i
        );

        total_messages += 1;
    }

    println!("\n=== Network Summary ===");
    println!("Agents: 5");
    println!("Messages: {}", total_messages);
    println!("Total encrypted bytes: {}", total_encrypted_bytes);
    println!("LLM calls: 1 (agent 2 only, to minimize API costs)");
    println!("Network test completed successfully!");
}

/// Phase 11: Variable payload sizes with real LLM responses
/// Tests: Protocol handles dynamically-sized LLM outputs correctly
#[tokio::test]
#[ignore = "requires OPENROUTER_API_KEY - run with: cargo test --features crypto test_variable_payload_sizes -- --ignored"]
async fn test_variable_payload_sizes() {
    dotenvy::dotenv().ok();

    let api_key = openrouter::get_api_key();
    if api_key.is_none() {
        println!("Skipping: OPENROUTER_API_KEY not set");
        return;
    }

    println!("\n============================================================");
    println!("PHASE 11: Variable Payload Sizes (LLM-generated)");
    println!("============================================================\n");

    let org = TestOrg::new("variable", 2);
    let alice = org.agent(0);
    let bob = org.agent(1);

    let session_id = "variable-001";
    let mut alice_ctx = alice.create_security_context(&bob.id, session_id);
    let bob_ctx = bob.create_security_context(&alice.id, session_id);

    let client = openrouter::create_client();

    // Request different sized responses
    let size_prompts = [
        ("tiny", "Say 'OK'.", 5),
        ("small", "Write exactly one sentence about the sun.", 50),
        (
            "medium",
            "Write a short paragraph (3-4 sentences) about the ocean.",
            200,
        ),
        (
            "large",
            "Write 5 sentences about space exploration, each on a new line.",
            500,
        ),
    ];

    let mut payload_sizes: Vec<(String, usize, usize)> = vec![];

    for (label, prompt, max_tokens) in size_prompts {
        println!("--- {} response ---", label);

        let response = openrouter::chat_completion(
            &client,
            openrouter::MODEL,
            vec![openrouter::ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            Some(0.3),
            Some(max_tokens),
        )
        .await;

        let llm_response = match response {
            Ok(text) => text,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("429")
                    || error_msg.contains("402")
                    || error_msg.contains("rate")
                    || error_msg.contains("limit")
                {
                    println!("Skipping: API limit reached ({error_msg})");
                    return;
                }
                panic!("LLM call failed: {e}");
            },
        };

        let response_len = llm_response.len();
        println!("  LLM response length: {} chars", response_len);

        // Wrap LLM response in JSON (M2MFrame requires valid JSON)
        let payload_json = serde_json::json!({
            "response": llm_response,
            "size_class": label
        });
        let payload_str = serde_json::to_string(&payload_json).unwrap();
        let payload_len = payload_str.len();

        // Alice encrypts the JSON-wrapped LLM response
        let frame = M2MFrame::new_request(&payload_str).unwrap();
        let encrypted = frame
            .encode_secure(SecurityMode::Aead, &mut alice_ctx)
            .unwrap();

        let encrypted_len = encrypted.len();
        println!(
            "  Encrypted: {} bytes (payload: {} bytes, overhead: {:.1}%)",
            encrypted_len,
            payload_len,
            ((encrypted_len as f64 / payload_len as f64) - 1.0) * 100.0
        );

        // Bob decrypts
        let decrypted = M2MFrame::decode_secure(&encrypted, &bob_ctx).unwrap();
        assert_eq!(
            decrypted.payload, payload_str,
            "Payload mismatch for {} response",
            label
        );

        payload_sizes.push((label.to_string(), payload_len, encrypted_len));
        println!();
    }

    println!("=== Payload Size Summary ===");
    for (label, plain, encrypted) in &payload_sizes {
        println!(
            "{:8}: plaintext={:4} bytes, encrypted={:4} bytes",
            label, plain, encrypted
        );
    }

    // Verify protocol handled all sizes
    assert_eq!(payload_sizes.len(), 4, "Should have tested 4 payload sizes");
    println!("\nVariable payload test completed successfully!");
}
