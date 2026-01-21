---
title: Wire Format
description: Message structure and encoding specification
---

# 3. Wire Format

## 3.1 Overview

M2M Protocol defines wire formats for efficient LLM API payload transmission. The primary format is M2M v1, which uses a binary header with Brotli-compressed payload, achieving 40-70% compression while keeping routing metadata readable without decompression.

## 3.2 Algorithm Tags

| Prefix | Algorithm | Description | Use Case |
|--------|-----------|-------------|----------|
| `#M2M\|1\|` | **M2M v1** | Binary header + Brotli payload | Default for all LLM API traffic |
| `#TK\|` | TokenNative | BPE token ID transmission | Token-efficient small payloads |
| `#M2M[v3.0]\|DATA:` | Brotli | Brotli + Base64 | Large content (>1KB) |

## 3.3 M2M v1 Format (`#M2M|1|`) - DEFAULT

The M2M v1 format is the primary wire format, optimized for LLM API payloads with inspectable routing headers.

### 3.3.1 Wire Structure

```
#M2M|1|<fixed_header:20><routing_header:var><payload_len:4><crc32:4><payload:var>
```

**Visual Representation:**

```
┌─────────┬──────────────────────────────┬────────────────────┬─────────┬───────┬─────────────┐
│ Prefix  │       Fixed Header (20B)     │   Routing Header   │ Payload │ CRC32 │   Payload   │
│ #M2M|1| │                              │     (variable)     │ Len 4B  │  4B   │ (compress)  │
├─────────┼───────┬────┬────┬──────┬─────┼────────────────────┼─────────┴───────┴─────────────┤
│         │HdrLen │Sch │Sec │Flags │Rsrv │ Model (len+str)    │                               │
│         │  2B   │ 1B │ 1B │  4B  │ 12B │ MsgCount (varint)  │  Brotli-compressed JSON       │
│         │       │    │    │      │     │ Roles (2b packed)  │  (100% fidelity)              │
│         │       │    │    │      │     │ ContentHint (var)  │                               │
│         │       │    │    │      │     │ MaxTokens (var)    │                               │
│         │       │    │    │      │     │ CostEst (f32)      │                               │
├─────────┴───────┴────┴────┴──────┴─────┴────────────────────┼───────────────────────────────┤
│               ▲ Readable without decompression              │ ▲ Requires decode             │
└─────────────────────────────────────────────────────────────┴───────────────────────────────┘
```

### 3.3.2 Fixed Header (20 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | `header_len` | Total header length (fixed + routing) |
| 2 | 1 | `schema` | Message type (Request, Response, etc.) |
| 3 | 1 | `security` | Security mode (None, HMAC, AEAD) |
| 4 | 4 | `flags` | Feature flags (streaming, tools, etc.) |
| 8 | 12 | `reserved` | Reserved for future use |

**Schema Values:**

| Value | Schema | Description |
|-------|--------|-------------|
| `0x01` | Request | Chat completion request |
| `0x02` | Response | Chat completion response |
| `0x03` | Stream | Streaming chunk |
| `0x10` | Error | Error response |
| `0x11` | EmbeddingRequest | Embedding request |
| `0x12` | EmbeddingResponse | Embedding response |

**Security Values:**

| Value | Mode | Description |
|-------|------|-------------|
| `0x00` | None | No cryptographic protection |
| `0x01` | HMAC | HMAC-SHA256 authentication tag appended |
| `0x02` | AEAD | ChaCha20-Poly1305 authenticated encryption |

### 3.3.3 Routing Header (variable)

The routing header contains metadata readable without decompressing the payload:

| Field | Encoding | Description |
|-------|----------|-------------|
| `model` | length-prefixed string | Model identifier (e.g., "gpt-4o") |
| `msg_count` | varint | Number of messages |
| `roles` | 2-bit packed | Role sequence (system=0, user=1, assistant=2) |
| `content_hint` | varint | Approximate content size |
| `max_tokens` | varint (optional) | Max completion tokens |
| `cost_estimate` | f32 (optional) | Estimated cost in USD |

### 3.3.4 Security Modes

**None (default):**
```
#M2M|1|<headers><payload_len><crc32><payload>
```

**HMAC-SHA256:**
```
#M2M|1|<headers><payload_len><crc32><payload><hmac_tag:32>
```

**ChaCha20-Poly1305 AEAD:**
```
#M2M|1|<headers><nonce:12><ciphertext><auth_tag:16>
```

Note: In AEAD mode, headers remain readable (authenticated but not encrypted).

### 3.3.5 Example

**Original JSON (147 bytes):**
```json
{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, how are you?"}],"temperature":0.7}
```

**M2M v1 Wire Format (~60 bytes):**
```
#M2M|1|<binary_headers><brotli_compressed_payload>
```

**Compression:** 59% savings

## 3.4 TokenNative Format (`#TK|`)

TokenNative transmits BPE token IDs directly, using the tokenizer vocabulary as a compression dictionary.

### 3.4.1 Wire Structure

```
#TK|<tokenizer_id>|<base64_varint_tokens>
```

**Components:**
- `#TK|` - Algorithm prefix (4 bytes)
- `<tokenizer_id>` - Single character: `C` (cl100k), `O` (o200k), `L` (llama)
- `|` - Separator
- `<base64_varint_tokens>` - Base64-encoded VarInt token IDs

### 3.4.2 Tokenizer IDs

| ID | Tokenizer | Vocabulary | Models |
|----|-----------|------------|--------|
| `C` | cl100k_base | 100,256 | GPT-3.5, GPT-4 (canonical fallback) |
| `O` | o200k_base | 200,019 | GPT-4o, o1, o3 |
| `L` | Llama BPE | 128,256 | Llama 3, Mistral |

### 3.4.3 VarInt Encoding

| Value Range | Bytes | Encoding |
|-------------|-------|----------|
| 0-127 | 1 | `0xxxxxxx` |
| 128-16383 | 2 | `1xxxxxxx 0xxxxxxx` |
| 16384+ | 3+ | Continuation bits |

### 3.4.4 Example

**Original (68 bytes):**
```json
{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
```

**TokenNative Wire (~40 bytes):**
```
#TK|C|W3sib29kZWwiOiJncHQ...
```

**Compression:** 41% savings

## 3.5 Brotli Format (`#M2M[v3.0]|DATA:`)

For large content where byte reduction outweighs Base64 overhead.

### 3.5.1 Wire Structure

```
#M2M[v3.0]|DATA:<base64_brotli_compressed>
```

### 3.5.2 When to Use

- Content size > 1KB
- High repetition (>30% duplicate substrings)
- Non-LLM API content

### 3.5.3 Example

**Original (10KB JSON):**
```json
{"messages":[{"role":"user","content":"...large content..."}]}
```

**Brotli Wire (~4KB):**
```
#M2M[v3.0]|DATA:G6kEABwHcNP2Yk9N...
```

**Compression:** 60% savings

## 3.6 Deprecated Formats

### 3.6.1 Token v1 (`#T1|`) - REMOVED in 0.4.0

The Token v1 format used semantic key abbreviation:
```
#T1|{"M":"4o","m":[{"r":"u","c":"Hi"}]}
```

**Migration:** Use M2M v1 format (`#M2M|1|`) instead.

### 3.6.2 Zlib (`#M2M[v2.0]|DATA:`) - DEPRECATED

Implementations:
- MUST NOT generate new messages with v2.0 format
- MAY accept v2.0 messages for backward compatibility

## 3.7 Encoding Rules

### 3.7.1 Character Encoding

All M2M messages MUST be valid UTF-8.

Implementations:
- MUST reject messages containing invalid UTF-8 sequences
- MUST preserve Unicode characters in content fields

### 3.7.2 Payload Encoding

For M2M v1 and TokenNative formats, the payload is binary.
For Brotli format, the payload is Base64-encoded.

## 3.8 Size Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Maximum message size | 16 MiB | Prevent memory exhaustion |
| Maximum decompressed size | 16 MiB | Prevent decompression bombs |
| Maximum JSON depth | 32 levels | Prevent stack overflow |
| Maximum string length | 10 MiB | Single field limit |
| Maximum array elements | 10,000 | Prevent DoS |

Implementations:
- MUST reject messages exceeding size limits
- MUST implement streaming decompression with size checks
- SHOULD reject before fully reading oversized messages

## 3.9 ABNF Grammar

```abnf
; M2M Protocol Wire Format Grammar (RFC 5234)

m2m-message      = m2m-v1-message / token-native-message / brotli-message

; M2M v1 (primary format)
m2m-v1-message   = "#M2M" PIPE "1" PIPE binary-frame
binary-frame     = fixed-header routing-header payload-section

; TokenNative
token-native-message = "#TK" PIPE tokenizer-id PIPE base64-data

; Brotli
brotli-message   = "#M2M[v3.0]" PIPE "DATA:" base64-data

PIPE             = %x7C                    ; |
tokenizer-id     = "C" / "O" / "L"         ; cl100k / o200k / llama
base64-data      = *( ALPHA / DIGIT / "+" / "/" / "=" )

; Binary frame components (for reference)
fixed-header     = 20OCTET
routing-header   = *OCTET                  ; variable length
payload-section  = payload-len crc32 compressed-payload
payload-len      = 4OCTET                  ; little-endian u32
crc32            = 4OCTET                  ; CRC32 of original JSON
compressed-payload = *OCTET               ; Brotli-compressed
```

## 3.10 Algorithm Detection

Implementations MUST detect algorithm from prefix:

```
if starts_with("#M2M|1|"):
    return decode_m2m_v1(content)
elif starts_with("#TK|"):
    return decode_token_native(content)
elif starts_with("#M2M[v3.0]|DATA:"):
    return decode_brotli(content)
else:
    return content  # Passthrough (no compression)
```

## 3.11 Examples

### 3.11.1 M2M v1 Chat Request

```
Original:
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are helpful."},
    {"role": "user", "content": "Hello!"}
  ],
  "temperature": 0.7,
  "max_tokens": 100
}

Wire: #M2M|1|<20-byte fixed header><routing header><payload>

Routing header readable without decompression:
  - model: "gpt-4o"
  - msg_count: 2
  - roles: [system, user]
  - max_tokens: 100
```

### 3.11.2 M2M v1 with AEAD Security

```
Wire: #M2M|1|<headers><nonce:12><encrypted_payload><tag:16>

Headers remain readable for routing.
Payload is encrypted with ChaCha20-Poly1305.
```
