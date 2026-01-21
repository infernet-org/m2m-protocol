---
title: Compression
description: Compression algorithms and selection heuristics
---

# 5. Compression Algorithms

## 5.1 Overview

M2M Protocol supports multiple compression algorithms optimized for LLM API traffic.

| Algorithm | Prefix | Best For | Typical Savings |
|-----------|--------|----------|-----------------|
| **M2M v1** (default) | `#M2M\|1\|` | All LLM API payloads | 40-70% |
| TokenNative | `#TK\|` | Small payloads, token-sensitive | 30-50% |
| Brotli | `#M2M[v3.0]\|DATA:` | Large content (>1KB) | 60-80% |
| None | (passthrough) | Very small content (<100B) | 0% |

## 5.2 M2M v1 Compression (Default)

### 5.2.1 Overview

M2M v1 is the primary compression algorithm, designed for LLM API payloads. It combines:

1. **Binary headers**: Routing metadata in compact binary format
2. **Brotli payload**: JSON payload compressed with Brotli
3. **100% fidelity**: Original JSON fully recoverable

### 5.2.2 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        M2M v1 ENCODING                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Input JSON                                                      │
│      │                                                           │
│      ├─► Extract routing metadata ─► Binary routing header       │
│      │   (model, msg_count, roles)                               │
│      │                                                           │
│      └─► Brotli compress ─────────► Compressed payload           │
│                                                                  │
│  Output: #M2M|1|<fixed_header><routing_header><payload>         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2.3 Routing Metadata Extraction

The following fields are extracted to the routing header (readable without decompression):

| Field | Source | Purpose |
|-------|--------|---------|
| `model` | `$.model` | Load balancing, cost attribution |
| `msg_count` | `$.messages.length` | Analytics, rate limiting |
| `roles` | `$.messages[*].role` | Conversation analysis |
| `content_hint` | Sum of content lengths | Size estimation |
| `max_tokens` | `$.max_tokens` | Resource planning |
| `cost_estimate` | Calculated | Billing preview |

### 5.2.4 Compression Ratios

| Content Type | Original | Compressed | Savings |
|--------------|----------|------------|---------|
| Simple request | 147 B | 60 B | 59% |
| Multi-turn conversation | 2.4 KB | 1.0 KB | 58% |
| Tool calls + schema | 8.2 KB | 3.5 KB | 57% |
| Large context (32K tokens) | 128 KB | 48 KB | 62% |

### 5.2.5 When to Use

M2M v1 is the **default algorithm** for all LLM API payloads. Use it unless:
- Content is too small (<100 bytes) → passthrough
- Binary-safe channel available and need maximum compression → TokenNative binary mode

## 5.3 TokenNative Compression

### 5.3.1 Overview

TokenNative transmits BPE token IDs directly, using the tokenizer vocabulary as a compression dictionary. This achieves 30-50% compression on the wire.

### 5.3.2 How It Works

```
Input:  "Hello, world!"
         │
         ▼
Tokenize: [15496, 11, 995, 0]  (4 tokens)
         │
         ▼
VarInt:   [0xE8, 0x78, 0x0B, 0xE3, 0x07, 0x00]  (6 bytes)
         │
         ▼
Base64:   "6HgL4wcA"  (8 characters)
         │
         ▼
Output:   "#TK|C|6HgL4wcA"
```

### 5.3.3 Supported Tokenizers

| ID | Tokenizer | Vocabulary | Use With |
|----|-----------|------------|----------|
| `C` | cl100k_base | 100,256 | GPT-3.5, GPT-4 (canonical fallback) |
| `O` | o200k_base | 200,019 | GPT-4o, o1, o3 |
| `L` | Llama BPE | 128,256 | Llama 3, Mistral |

Implementations MUST support `C` (cl100k_base) as the canonical fallback.

### 5.3.4 VarInt Encoding

Token IDs are encoded as variable-length integers to minimize size:

| Value Range | Bytes | Format |
|-------------|-------|--------|
| 0-127 | 1 | `0xxxxxxx` |
| 128-16383 | 2 | `1xxxxxxx 0xxxxxxx` |
| 16384-2097151 | 3 | `1xxxxxxx 1xxxxxxx 0xxxxxxx` |

Average: ~1.5 bytes per token for typical vocabularies.

### 5.3.5 Binary Mode

For binary-safe channels (WebSocket binary frames, QUIC streams), skip Base64:

```
Binary: <tokenizer_byte><varint_tokens>
```

This achieves ~50% compression (vs ~35% with Base64 overhead).

### 5.3.6 When to Use

- Small-to-medium payloads (<1KB)
- Both endpoints support same tokenizer
- Maximum token efficiency required
- Binary channel available (for best compression)

## 5.4 Brotli Compression

### 5.4.1 Overview

Brotli compression with Base64 encoding, for large content where byte reduction outweighs Base64 overhead.

### 5.4.2 Encoding

```
Input JSON ─► Brotli compress (quality 4-6) ─► Base64 encode ─► #M2M[v3.0]|DATA:<base64>
```

### 5.4.3 When to Use

- Content size > 1KB
- High repetition (>30% duplicate substrings)
- Non-LLM API content
- Legacy compatibility

### 5.4.4 Compression Ratios

| Content Type | Original | Compressed | Savings |
|--------------|----------|------------|---------|
| Large JSON | 10 KB | 4 KB | 60% |
| Highly repetitive | 10 KB | 2 KB | 80% |
| Mixed content | 10 KB | 5 KB | 50% |

## 5.5 Algorithm Selection

### 5.5.1 Automatic Selection (Recommended)

```rust
let result = engine.compress_auto(json)?;
```

The engine selects the optimal algorithm based on content analysis.

### 5.5.2 Selection Heuristics

```
if content_size < 100:
    return None (passthrough)

if is_llm_api_payload(content):
    return M2M_V1  # Default for all LLM API traffic

if content_size > 1024 and high_repetition:
    return Brotli

return M2M_V1
```

### 5.5.3 Explicit Selection

```rust
// Force specific algorithm
let result = engine.compress(json, Algorithm::M2M)?;
let result = engine.compress(json, Algorithm::TokenNative)?;
let result = engine.compress(json, Algorithm::Brotli)?;
```

### 5.5.4 ML-Assisted Selection (Hydra)

```rust
// Use Hydra model for intelligent selection
let result = engine.compress_with_hydra(json)?;
```

The Hydra MoE model analyzes content to select the optimal algorithm.

## 5.6 Algorithm Negotiation

During session establishment, endpoints negotiate supported algorithms:

```
Client HELLO:
  algorithms: [M2M, TOKEN_NATIVE, BROTLI]
  encodings: [CL100K_BASE, O200K_BASE]

Server ACCEPT:
  algorithms: [M2M, BROTLI]  # Intersection
  encoding: CL100K_BASE      # Agreed tokenizer
```

For stateless mode, the prefix indicates the algorithm used.

## 5.7 Decompression

### 5.7.1 Algorithm Detection

Implementations MUST detect algorithm from prefix:

```rust
match content {
    s if s.starts_with("#M2M|1|") => decompress_m2m_v1(s),
    s if s.starts_with("#TK|") => decompress_token_native(s),
    s if s.starts_with("#M2M[v3.0]|DATA:") => decompress_brotli(s),
    _ => Ok(content.to_string()),  // Passthrough
}
```

### 5.7.2 Error Handling

- Invalid prefix → `InvalidCodec` error
- Decompression failure → `Decompression` error  
- Invalid JSON after decompression → `Decompression` error

Implementations MUST NOT return partially decompressed content.

## 5.8 Deprecated Algorithms

### 5.8.1 Token v1 (`#T1|`) - REMOVED

The Token v1 algorithm used semantic key abbreviation:

```
Original: {"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}
Token v1: #T1|{"M":"4o","m":[{"r":"u","c":"Hi"}]}
```

**Status:** Removed in v0.4.0. Use M2M v1 instead.

### 5.8.2 Dictionary (`#DI|`) - DEPRECATED

Pattern-based dictionary encoding is deprecated in favor of M2M v1.

### 5.8.3 Zlib (`#M2M[v2.0]|DATA:`) - DEPRECATED

Replaced by Brotli (`#M2M[v3.0]|DATA:`).

## 5.9 Compression Comparison

| Algorithm | Wire Size | Decode Speed | Headers Readable | Binary Safe |
|-----------|-----------|--------------|------------------|-------------|
| **M2M v1** | 40-70% | Fast | Yes | Yes |
| TokenNative | 50-70% | Fast | No | Yes (binary mode) |
| Brotli | 40-60% | Medium | No | No (Base64) |
| None | 100% | Instant | Yes | Yes |

## 5.10 Best Practices

1. **Use M2M v1 by default** for all LLM API payloads
2. **Use automatic selection** unless you have specific requirements
3. **Negotiate capabilities** in session mode for optimal compression
4. **Fall back gracefully** to passthrough for unknown content
5. **Validate decompressed JSON** before processing
