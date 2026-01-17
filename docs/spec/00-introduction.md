# 1. Introduction

## 1.1 Abstract

This document defines the M2M (Machine-to-Machine) Protocol, a token-optimized compression scheme for Large Language Model (LLM) API traffic. Unlike traditional compression algorithms that reduce bytes but increase token count due to Base64 encoding, M2M Protocol achieves 25-40% token reduction through semantic key abbreviation, value substitution, and default parameter elimination.

This specification defines the wire format, compression mappings, session negotiation, and security considerations for M2M Protocol version 1.0.

## 1.2 Background

### 1.2.1 The Problem

LLM APIs charge based on token count, not bytes. Traditional compression algorithms (gzip, brotli, zstd) reduce byte size but produce binary output requiring Base64 encoding, which typically **increases** token count by 33%.

Example with gzip:
```
Original:     68 bytes  → 42 tokens
Gzip+Base64:  52 bytes  → 58 tokens (+38% tokens)
```

### 1.2.2 The Solution

M2M Protocol applies semantic compression that preserves JSON structure while reducing both bytes and tokens:

```
Original:     68 bytes  → 42 tokens
M2M Token:    45 bytes  → 29 tokens (-31% tokens)
```

Key techniques:
1. **Key abbreviation**: `"messages"` → `"m"`
2. **Value substitution**: `"assistant"` → `"a"`
3. **Model abbreviation**: `"gpt-4o"` → `"4o"`
4. **Default elimination**: Remove `"temperature": 1.0` (default)

## 1.3 Protocol Overview

M2M Protocol operates in two modes:

### 1.3.1 Stateless Mode

Direct compression/decompression without session establishment:

```
Client                          Server
   |                               |
   |--- Compressed Request ------->|
   |<-- Compressed Response -------|
```

### 1.3.2 Session Mode

Full protocol with capability negotiation:

```
Client                          Server
   |                               |
   |-------- HELLO --------------->|
   |<------- ACCEPT ---------------|
   |                               |
   |======= DATA (compressed) ====>|
   |<====== DATA (compressed) =====|
   |                               |
   |-------- CLOSE --------------->|
```

## 1.4 Design Goals

1. **Token Reduction**: Optimize for LLM tokenizer output, not just bytes
2. **JSON Compatibility**: Compressed output is valid JSON
3. **Low Latency**: Sub-millisecond compression overhead
4. **Backward Compatibility**: Graceful fallback to uncompressed
5. **Extensibility**: Support for new compression algorithms
6. **Security**: Optional threat detection for prompt injection

## 1.5 Non-Goals

1. **General-purpose compression**: Optimized specifically for LLM API payloads
2. **Encryption**: Transport security (TLS) is assumed
3. **Authentication**: Delegated to transport layer
4. **Binary protocols**: JSON-based wire format only

## 1.6 Relationship to Other Protocols

| Protocol | Relationship |
|----------|--------------|
| HTTP/1.1, HTTP/2, HTTP/3 | M2M operates over HTTP as transport |
| QUIC (RFC 9000) | Preferred transport for agent-to-agent communication |
| TLS 1.2+ / TLS 1.3 | Required for transport security (built-in with QUIC) |
| JSON (RFC 8259) | Wire format is JSON-compatible |
| OpenAI API | Primary target for compression |
| SSE | Streaming responses supported |

## 1.7 Document Structure

| Section | Contents |
|---------|----------|
| [01-terminology](01-terminology.md) | Definitions and RFC 2119 keywords |
| [02-wire-format](02-wire-format.md) | Message structure and encoding |
| [03-message-types](03-message-types.md) | HELLO, ACCEPT, DATA, etc. |
| [04-compression](04-compression.md) | Algorithms and mappings |
| [05-session-management](05-session-management.md) | State machine and lifecycle |
| [06-security](06-security.md) | Threat model and mitigations |
