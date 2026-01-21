---
title: Security
description: Threat model and security mitigations
---

# 7. Security Considerations

## 7.1 Overview

This section addresses security implications of M2M Protocol deployment. Implementations MUST consider these factors when designing systems using M2M Protocol.

## 7.2 Threat Model

### 7.2.1 Assumptions

- Transport layer (TLS 1.2+) provides confidentiality and integrity
- Endpoints are authenticated at the transport layer
- Attackers may observe message sizes and timing

### 7.2.2 In-Scope Threats

| Threat | Description |
|--------|-------------|
| Compression oracle | Information leakage through size variations |
| Denial of service | Resource exhaustion via malformed messages |
| Prompt injection | Malicious content in LLM payloads |
| Message tampering | Modification of compressed content |

### 7.2.3 Out-of-Scope Threats

| Threat | Reason |
|--------|--------|
| Eavesdropping | TLS provides confidentiality |
| Man-in-the-middle | TLS provides authentication |
| Endpoint compromise | Application-level concern |

## 7.3 Transport Security

### 7.3.1 Requirements

Implementations:
- MUST use TLS 1.2 or later for production deployments
- MUST verify server certificates
- SHOULD use TLS 1.3 when available
- SHOULD implement certificate pinning for high-security deployments

### 7.3.2 Cipher Suites

Recommended cipher suites (TLS 1.3):
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_AES_128_GCM_SHA256

### 7.3.3 Certificate Validation

- Verify certificate chain to trusted root
- Check certificate expiration
- Validate hostname matches certificate

## 7.4 Compression Security

### 7.4.1 Compression Oracle Attacks

Compression can leak information about plaintext through ciphertext size variations (CRIME, BREACH attacks).

**Risk:** If user-controlled content is compressed alongside secrets, attackers may infer secret values by observing compressed size changes.

**Mitigations:**

1. **Separate compression contexts**
   - Do NOT compress user content with API keys
   - Compress request body separately from headers

2. **Add random padding**
   ```
   Implementations MAY add random padding to obscure size:
   - Add 0-64 random bytes to payload
   - Padding MUST be removed during decompression
   ```

3. **Disable compression for sensitive fields**
   ```
   Fields that SHOULD NOT be compressed:
   - Authorization headers
   - API keys
   - Session tokens
   ```

### 7.4.2 Decompression Bombs

Maliciously crafted compressed content may expand to enormous size.

**Mitigations:**

- MUST limit maximum decompressed size (default: 16 MiB)
- MUST implement streaming decompression with size checks
- MUST abort decompression if limit exceeded
- SHOULD reject before fully reading oversized input

### 7.4.3 Algorithmic Complexity

Some compression operations have worst-case quadratic complexity.

**Mitigations:**

- MUST implement timeouts for compression operations
- SHOULD limit input size before compression
- MAY use constant-time implementations for sensitive contexts

## 7.5 Content Security

### 7.5.1 Prompt Injection Detection

M2M Protocol includes optional security scanning for LLM-specific threats.

**Detected Patterns:**

| Category | Examples |
|----------|----------|
| Role confusion | "Ignore previous instructions", "You are now DAN" |
| Jailbreaks | "Developer mode", "Bypass safety", "Disable restrictions" |
| Encoding attacks | Base64-encoded malicious content, Unicode exploits |
| Data exfiltration | "Print environment variables", "Read /etc/passwd" |

### 7.5.2 Security Scanner Configuration

```toml
[security]
enabled = true           # Enable scanning
blocking = true          # Reject unsafe content
threshold = 0.8          # Confidence threshold (0.0-1.0)
```

### 7.5.3 Scanning Results

```json
{
  "scanned": true,
  "safe": false,
  "threat_type": "PROMPT_INJECTION",
  "confidence": 0.95,
  "details": "Pattern: 'ignore previous instructions'"
}
```

### 7.5.4 False Positives

Security scanning may produce false positives for legitimate content.

**Mitigations:**

- Adjust threshold based on use case
- Implement allowlists for known-good patterns
- Log blocked content for review
- Provide override mechanism for trusted sources

## 7.6 Denial of Service

### 7.6.1 Resource Limits

| Resource | Limit | Rationale |
|----------|-------|-----------|
| Max message size | 16 MiB | Memory exhaustion |
| Max JSON depth | 32 | Stack overflow |
| Max string length | 10 MiB | Single allocation limit |
| Max array elements | 10,000 | Processing time |
| Session timeout | 5 minutes | Connection exhaustion |
| Max sessions per IP | 100 | Connection flooding |

### 7.6.2 Rate Limiting

Implementations SHOULD implement rate limiting:

```
Rate limits (recommendations):
- 1000 requests/minute per session
- 100 new sessions/minute per IP
- 10 MB/second per session
```

### 7.6.3 Slowloris Prevention

- MUST implement connection timeouts
- MUST limit incomplete request duration
- SHOULD use async I/O with per-connection limits

## 7.7 Message Integrity

### 7.7.1 Transport Integrity

TLS provides message integrity via authenticated encryption.

### 7.7.2 Application Integrity

M2M Protocol provides optional application-layer integrity via the `crypto` feature:

- **HMAC-SHA256**: Authentication tag appended to frame (32 bytes)
- **ChaCha20-Poly1305 AEAD**: Authenticated encryption with 16-byte tag

### 7.7.3 Replay Protection

M2M Protocol does NOT provide replay protection.

**Mitigations:**

- TLS provides replay protection at transport layer
- Implementations MAY add timestamps with rejection of stale messages
- Implementations MAY add nonces for replay detection

## 7.8 Cryptographic Key Management

### 7.8.1 Key Hierarchy (HKDF)

M2M supports hierarchical key derivation using HKDF-SHA256 (RFC 5869).

**Same-Organization Key Derivation:**

```
Organization Master Secret
    │
    ├─[HKDF]─► "m2m/v1/{org}/agent-001" ─► Agent 001 Key
    ├─[HKDF]─► "m2m/v1/{org}/agent-002" ─► Agent 002 Key
    └─[HKDF]─► "m2m/v1/{org}/session/{a}:{b}/{session_id}" ─► Session Key
```

**Derivation Paths:**

| Path | Purpose |
|------|---------|
| `m2m/v1/{org}` | Organization-level key |
| `m2m/v1/{org}/{agent}` | Agent identity key |
| `m2m/v1/{org}/{agent}/{purpose}` | Purpose-specific key (encryption/auth) |
| `m2m/v1/{org}/session/{a}:{b}/{sid}` | Session key between agents |
| `m2m/v1/{org}/shared` | Shared organization broadcast key |

**Security Properties:**

- All derivations are deterministic (same inputs → same output)
- Session keys are symmetric (agent order doesn't matter)
- Maximum output length: 8160 bytes (255 × 32)
- Validated against RFC 5869 test vectors

### 7.8.2 Cross-Organization Key Exchange

For agents in different organizations, use X25519 Diffie-Hellman:

```
Agent A: (sk_a, pk_a) = X25519::generate()
Agent B: (sk_b, pk_b) = X25519::generate()

shared_secret = X25519(sk_a, pk_b) = X25519(sk_b, pk_a)
session_key = HKDF(shared_secret, "m2m-session-v1", 32)
```

### 7.8.3 Key Zeroization

Key material SHOULD be zeroized on drop:

```rust
impl Drop for KeyMaterial {
    fn drop(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}
```

**Note:** For production use, consider using the `zeroize` crate for
compiler-guaranteed zeroization.

### 7.8.4 Nonce Generation

ChaCha20-Poly1305 requires unique nonces for each encryption operation with the same key.
**Nonce reuse completely breaks the security of AEAD encryption.**

**M2M uses fully random 96-bit nonces:**

```
Nonce: [random: 12 bytes]
       └─ Generated from CSPRNG (rand::thread_rng)
```

**Why random nonces instead of counters?**

| Approach | Pros | Cons |
|----------|------|------|
| Counter-based | Guaranteed unique | Resets on restart → nonce reuse |
| Persisted counter | Guaranteed unique | Complex, needs storage |
| **Random (chosen)** | Stateless, simple | Birthday bound at 2^48 |

For ChaCha20-Poly1305 with 96-bit random nonces:
- Birthday bound: ~2^48 messages before 50% collision probability
- At 2^24 messages (~16 million): collision probability ~2^-49
- For typical M2M sessions: negligible risk

**Security Requirements:**

- MUST use cryptographically secure random number generator (CSPRNG)
- MUST NOT use predictable or sequential nonces in production
- MUST NOT reuse nonces with the same key
- Nonce is prepended to ciphertext (no external state needed for decryption)

**Deterministic nonces (testing only):**

For reproducible tests, `next_nonce_deterministic()` is available but:
- Only available in test builds (`#[cfg(test)]`)
- MUST NOT be used in production code

### 7.8.5 Test Vectors

For implementation compatibility, use this test vector:

```
Master Key:  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Org ID:      test-org
Agent ID:    agent-001
Path:        m2m/v1/test-org/agent-001
Output:      c87f687fae1cf5991cd0cc64e113ec09750b0d1c41338a41cd8ad90bdd60dba1
```

## 7.9 Privacy Considerations

### 7.9.1 Metadata Exposure

Compression dictionaries are public. However:

- Message size after compression MAY reveal content structure
- Timing MAY reveal content complexity
- Session patterns MAY reveal usage patterns

### 7.9.2 Logging Recommendations

Implementations:
- SHOULD NOT log message payloads by default
- SHOULD NOT log user content in production
- MUST NOT log credentials or API keys
- MAY log metadata (size, algorithm, timing) for debugging

### 7.9.3 Data Retention

- Session state SHOULD be cleared after closure
- Compression statistics MAY be retained for analytics
- Security scan results MAY be retained for audit

## 7.10 Implementation Security

### 7.10.1 Memory Safety

- Use memory-safe languages (Rust) when possible
- Validate all input before processing
- Clear sensitive data after use

### 7.10.2 Dependency Security

- Audit dependencies regularly
- Use dependency scanning (cargo-audit)
- Pin dependency versions

### 7.10.3 Side Channels

- Constant-time comparison for security-sensitive operations
- Avoid branching on secret data
- Consider timing attacks in high-security contexts

## 7.11 Security Checklist

### 7.11.1 Deployment Checklist

- [ ] TLS 1.2+ enabled
- [ ] Certificate validation enabled
- [ ] Rate limiting configured
- [ ] Message size limits set
- [ ] Session timeouts configured
- [ ] Security scanning enabled (if processing user content)
- [ ] Logging configured (no sensitive data)
- [ ] Dependency audit completed

### 7.11.2 Development Checklist

- [ ] Input validation on all message fields
- [ ] Error messages do not leak sensitive information
- [ ] Decompression size limits enforced
- [ ] Timeout handling for all operations
- [ ] Memory cleared after processing sensitive data
