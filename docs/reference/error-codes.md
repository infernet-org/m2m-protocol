---
title: Error Codes
description: Complete error code reference
---

# Error Codes Reference

## Overview

M2M Protocol defines error types for all operations. This document covers session errors, compression errors, security errors, and cryptographic errors.

## M2MError Variants

The main error type for M2M Protocol operations.

### Compression Errors

| Variant | Description | Common Causes |
|---------|-------------|---------------|
| `Compression(String)` | Compression operation failed | Invalid input, Brotli error |
| `Decompression(String)` | Decompression operation failed | Corrupted data, wrong algorithm |
| `InvalidCodec(String)` | Unknown or unsupported codec | Invalid prefix, version mismatch |

### Session Errors

| Variant | Description | Recovery |
|---------|-------------|----------|
| `SessionNotEstablished` | Operation requires established session | Call `connect()` first |
| `SessionExpired` | Session has timed out | Establish new session |
| `NegotiationFailed(String)` | Capability negotiation failed | Check capabilities |
| `CapabilityMismatch(String)` | Peers have incompatible capabilities | Adjust capabilities |
| `Protocol(String)` | Protocol-level error | Check message format |
| `InvalidMessage(String)` | Invalid message format | Validate input |

### Security Errors

| Variant | Fields | Description |
|---------|--------|-------------|
| `SecurityThreat` | `threat_type: String`, `confidence: f32` | Threat detected in content |
| `ContentBlocked(String)` | - | Content blocked by security policy |

### Cryptographic Errors

| Variant | Description | Source |
|---------|-------------|--------|
| `Crypto(CryptoError)` | Cryptographic operation failed | See [CryptoError](#cryptoerror-variants) |

> **Note:** The `Crypto` variant preserves the full error chain via `#[source]`, enabling debugging tools to display complete error context.

### Infrastructure Errors

| Variant | Description | Common Causes |
|---------|-------------|---------------|
| `Network(String)` | Network communication error | Connection failed, timeout |
| `Upstream(String)` | Upstream service error | LLM API error |
| `Server(String)` | Server-side error | Internal server error |
| `Config(String)` | Configuration error | Invalid config file |
| `Io(std::io::Error)` | I/O error | File not found, permission denied |
| `Json(serde_json::Error)` | JSON parsing error | Invalid JSON |

### ML/Inference Errors

| Variant | Description | Resolution |
|---------|-------------|------------|
| `ModelNotLoaded(String)` | ML model not loaded | Load model first |
| `ModelLoad(String)` | Failed to load ML model | Check model path |
| `ModelNotFound(String)` | Model not in registry | Register model |
| `Inference(String)` | ML inference error | Check input format |
| `Tokenizer(String)` | Tokenizer error | Check tokenizer config |

## CryptoError Variants

Unified error type for cryptographic operations. All variants preserve error source chain.

### AEAD Errors

| Variant | Description | Cause |
|---------|-------------|-------|
| `Aead(AeadError::InvalidKey)` | Invalid AEAD key | Key too short (<32 bytes) |
| `Aead(AeadError::EncryptionFailed)` | Encryption failed | Internal crypto error |
| `Aead(AeadError::DecryptionFailed)` | Decryption failed | Wrong key, corrupted data, tampered |
| `Aead(AeadError::DataTooShort)` | Ciphertext too short | Missing nonce or tag |

### HMAC Errors

| Variant | Description | Cause |
|---------|-------------|-------|
| `Hmac(HmacError::InvalidKey)` | Invalid HMAC key | Key too short |
| `Hmac(HmacError::VerificationFailed)` | HMAC verification failed | Wrong key, tampered data |
| `Hmac(HmacError::DataTooShort)` | Data too short for HMAC | Missing tag |

### Key Management Errors

| Variant | Description | Cause |
|---------|-------------|-------|
| `Key(KeyError::Empty)` | Empty key material | Zero-length key provided |
| `Key(KeyError::TooShort)` | Key too short | Below minimum length |
| `Keyring(KeyringError::KeyNotFound)` | Key not found in keyring | Key ID doesn't exist |
| `Keyring(KeyringError::DerivationFailed)` | Key derivation failed | HKDF error |

### Nonce Errors

| Variant | Description | Cause |
|---------|-------------|-------|
| `Nonce(NonceError::RngFailure)` | CSPRNG failed | System RNG unavailable |

### Key Exchange Errors

| Variant | Description | Cause |
|---------|-------------|-------|
| `Exchange(KeyExchangeError::InvalidPublicKey)` | Invalid public key | Wrong size, invalid point |
| `Exchange(KeyExchangeError::GenerationFailed)` | Key generation failed | RNG error |

### ID Validation Errors

| Variant | Description | Cause |
|---------|-------------|-------|
| `Id(IdError::Empty)` | Empty ID | AgentId or OrgId is empty |
| `Id(IdError::TooLong)` | ID too long | Exceeds 128 characters |
| `Id(IdError::InvalidChars)` | Invalid characters | Must be alphanumeric, hyphen, underscore |

## Session Rejection Codes

Returned in REJECT messages during session establishment.

| Code | Description | Recovery |
|------|-------------|----------|
| `VERSION_MISMATCH` | Protocol version not supported | Use supported version |
| `NO_COMMON_ALGORITHM` | No mutually supported algorithms | Add required algorithms |
| `SECURITY_POLICY` | Security policy violation | Review security settings |
| `RATE_LIMITED` | Rate limit exceeded | Retry with backoff |
| `SERVER_BUSY` | Server at capacity | Retry later |
| `UNKNOWN` | Unspecified error | Contact support |

## Closure Reason Codes

Returned in CLOSE messages during session termination.

| Code | Description |
|------|-------------|
| `NORMAL` | Clean shutdown |
| `TIMEOUT` | Session timeout exceeded |
| `ERROR` | Protocol error occurred |
| `CLIENT_SHUTDOWN` | Client application closing |
| `SERVER_SHUTDOWN` | Server shutting down |

## Security Scan Results

Threat types detected by security scanner.

| Threat Type | Severity | Description |
|-------------|----------|-------------|
| `PROMPT_INJECTION` | High | Attempt to override system instructions |
| `JAILBREAK` | Critical | Attempt to bypass safety measures |
| `DATA_EXFILTRATION` | High | Attempt to extract sensitive data |
| `MALFORMED_INPUT` | Medium | Null bytes, unicode exploits |
| `EXCESSIVE_NESTING` | Medium | JSON depth exceeds limit |

## HTTP Status Codes (Proxy)

| Status | Endpoint | Meaning |
|--------|----------|---------|
| 200 | All | Success |
| 400 | `/v1/*` | Invalid request format |
| 401 | `/v1/*` | Missing or invalid API key |
| 413 | `/v1/*` | Payload too large |
| 422 | `/v1/*` | Security scan failed (blocking mode) |
| 429 | `/v1/*` | Rate limit exceeded |
| 500 | All | Internal server error |
| 502 | `/v1/*` | Upstream server error |
| 504 | `/v1/*` | Upstream timeout |

## Error Response Format

### Proxy Error Response

```json
{
  "error": {
    "code": "SECURITY_VIOLATION",
    "message": "Content blocked by security scanner",
    "details": {
      "threat_type": "PROMPT_INJECTION",
      "confidence": 0.95
    }
  }
}
```

### Crypto Error Response

```json
{
  "error": {
    "code": "CRYPTO_ERROR",
    "message": "Crypto error: AEAD: Decryption failed: authentication tag mismatch",
    "source": "AeadError::DecryptionFailed"
  }
}
```

## Rust Error Types

### M2MError

```rust
pub enum M2MError {
    // Compression
    Compression(String),
    Decompression(String),
    InvalidCodec(String),
    
    // Session
    Protocol(String),
    NegotiationFailed(String),
    SessionNotEstablished,
    SessionExpired,
    InvalidMessage(String),
    CapabilityMismatch(String),
    
    // Security
    SecurityThreat { threat_type: String, confidence: f32 },
    ContentBlocked(String),
    
    // Cryptography (preserves error chain via #[source])
    Crypto(#[source] CryptoError),
    
    // Infrastructure
    Network(String),
    Upstream(String),
    Server(String),
    Config(String),
    
    // ML/Inference
    ModelNotLoaded(String),
    Inference(String),
    ModelLoad(String),
    ModelNotFound(String),
    Tokenizer(String),
    
    // Standard errors
    Json(#[from] serde_json::Error),
    Io(#[from] std::io::Error),
}
```

### CryptoError

```rust
pub enum CryptoError {
    Aead(#[source] AeadError),
    Hmac(#[source] HmacError),
    Key(#[source] KeyError),
    Keyring(#[source] KeyringError),
    Nonce(#[source] NonceError),
    Exchange(#[source] KeyExchangeError),  // crypto feature
    Id(#[source] IdError),                 // crypto feature
}
```

## Error Chain Example

The `CryptoError` type preserves the full error chain:

```rust
use std::error::Error;

fn handle_error(err: M2MError) {
    println!("Error: {}", err);
    
    // Walk the error chain
    let mut source = err.source();
    while let Some(cause) = source {
        println!("  Caused by: {}", cause);
        source = cause.source();
    }
}

// Output:
// Error: Crypto error: AEAD: Decryption failed: authentication tag mismatch
//   Caused by: Decryption failed: authentication tag mismatch
```
