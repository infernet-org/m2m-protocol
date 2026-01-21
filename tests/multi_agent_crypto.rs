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
    pub const FREE_MODEL: &str = "meta-llama/llama-3.2-3b-instruct:free";

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

    let response = openrouter::chat_completion(
        &client,
        openrouter::FREE_MODEL,
        messages,
        Some(0.1),
        Some(50),
    )
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
        "model": openrouter::FREE_MODEL,
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
        openrouter::FREE_MODEL,
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
        "model": openrouter::FREE_MODEL,
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
        openrouter::FREE_MODEL,
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
// PHASE 7: NETWORK (Full simulation - future expansion)
// =============================================================================

// Phase 7 tests will be added in subsequent iterations:
// - test_20_agent_mesh
// - test_40_agent_cross_org
// - test_100_agent_full_network
// - test_distributed_research_task
