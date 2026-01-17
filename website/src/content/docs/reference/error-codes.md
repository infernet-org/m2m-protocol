---
title: Error Codes
description: Complete error code reference
---

# Error Codes Reference

## Overview

M2M Protocol defines error codes for session management and data processing.

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

## Compression Errors

Errors during compression/decompression operations.

| Error | Description | Resolution |
|-------|-------------|------------|
| `InvalidPrefix` | Unknown wire format prefix | Check message format |
| `DecompressionFailed` | Content could not be decompressed | Verify algorithm match |
| `InvalidJson` | Decompressed content is not valid JSON | Check source content |
| `ContentTooLarge` | Content exceeds size limit | Reduce payload size |
| `UnsupportedAlgorithm` | Algorithm not supported | Use negotiated algorithm |

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

### Library Error Types (Rust)

```rust
pub enum M2MError {
    /// Compression operation failed
    Compression(String),

    /// Decompression operation failed
    Decompression(String),

    /// Security scan detected threat
    SecurityThreat { threat_type: String, confidence: f32 },

    /// Session error
    Session(String),

    /// Configuration error
    Config(String),

    /// Network/IO error
    Io(std::io::Error),

    /// JSON parsing error
    Json(serde_json::Error),

    /// Server error
    Server(String),
}
```
