---
title: Wire Format
description: Message structure and encoding specification
---

# 3. Wire Format

## 3.1 Overview

M2M Protocol uses a text-based wire format optimized for JSON payloads. All messages are UTF-8 encoded and consist of a prefix indicating the compression algorithm followed by the payload.

## 3.2 Message Structure

```
M2M-Message = Prefix "|" Payload
Prefix      = "#" Algorithm-Tag
Payload     = Compressed-JSON / Raw-Content
```

### 3.2.1 Visual Representation

```
+-------+-----+----------------------------------+
| "#"   | Tag | "|" | Payload                    |
+-------+-----+----------------------------------+
| 1 byte| var | 1 b | variable length            |
+-------+-----+----------------------------------+
```

## 3.3 Algorithm Tags

| Prefix | Algorithm | Description |
|--------|-----------|-------------|
| `#T1\|` | Token v1 | Semantic key/value abbreviation |
| `#TK\|` | TokenNative | Direct BPE token ID transmission |
| `#M2M[v3.0]\|DATA:` | Brotli | Brotli compression + Base64 |
| `#M2M\|` | Dictionary | Pattern-based encoding |

### 3.3.1 Token Algorithm (`#T1|`)

```
#T1|<abbreviated-json>
```

The payload is valid JSON with abbreviated keys and values. See [04-compression.md](04-compression.md) for mapping tables.

**Example:**
```
Original:  {"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}
Wire:      #T1|{"M":"4o","m":[{"r":"u","c":"Hi"}]}
```

### 3.3.2 TokenNative Algorithm (`#TK|`)

```
#TK|<tokenizer_id>|<base64_varint_tokens>
```

TokenNative compression transmits BPE token IDs directly instead of text, achieving ~50-60% compression. The tokenizer vocabulary serves as the compression dictionary.

**Wire Format:**
- `#TK|` - Algorithm prefix
- `<tokenizer_id>` - Single character identifying the tokenizer
- `|` - Separator
- `<base64_varint_tokens>` - Base64-encoded VarInt token IDs

**Tokenizer IDs:**

| ID | Tokenizer | Models |
|----|-----------|--------|
| `C` | cl100k_base | GPT-3.5, GPT-4, GPT-4o (canonical fallback) |
| `O` | o200k_base | GPT-4o, o1, o3 |
| `L` | Llama BPE | Llama 3, Mistral |

**Binary Format (for binary-safe channels):**

For WebSocket binary frames or QUIC streams, a more compact binary format is available:

```
<tokenizer_byte><varint_tokens>
```

- Byte 0: Tokenizer ID (0=cl100k, 1=o200k, 2=llama)
- Bytes 1+: VarInt-encoded token IDs (no Base64 overhead)

**VarInt Encoding:**
- Values 0-127: 1 byte (high bit clear)
- Values 128-16383: 2 bytes (high bit set on first byte)
- Values 16384+: 3+ bytes (continuation)

**Example:**
```
Original:  {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
Wire:      #TK|C|W3sib... (base64-encoded token IDs)
```

**Compression Ratios:**

| Content Type | Text Size | Wire Size | Compression |
|--------------|-----------|-----------|-------------|
| Small JSON   | 200 bytes | 80 bytes  | 60%         |
| Medium JSON  | 1KB       | 450 bytes | 55%         |
| Large JSON   | 10KB      | 4.5KB     | 55%         |

TokenNative is optimal for small-to-medium LLM API payloads (<1KB) where token efficiency matters more than maximum byte compression.

### 3.3.3 Brotli Algorithm (`#M2M[v3.0]|DATA:`)

```
#M2M[v3.0]|DATA:<base64-encoded-brotli>
```

The payload is Brotli-compressed content encoded as Base64. The version tag (`v3.0`) indicates protocol version.

**Example:**
```
Original:  {"model":"gpt-4o","messages":[...large content...]}
Wire:      #M2M[v3.0]|DATA:G6kEABwHcNP2Yk9N...
```

### 3.3.4 Dictionary Algorithm (`#M2M|`)

```
#M2M|<pattern-encoded>
```

Reserved for pattern-based dictionary encoding. See [04-compression.md](04-compression.md).

### 3.3.5 Deprecated Formats

#### Zlib Algorithm (`#M2M[v2.0]|DATA:`) - DEPRECATED

```
#M2M[v2.0]|DATA:<base64-encoded-zlib>
```

The Zlib algorithm was used in M2M Protocol v2.0 but is **deprecated** in v3.0.

Implementations:
- MUST NOT generate new messages with the v2.0 format
- SHOULD detect v2.0 format for backwards compatibility
- MAY attempt to decompress v2.0 messages using Brotli as a fallback
- SHOULD log a warning when v2.0 format is encountered

**Migration**: All new implementations should use Brotli (`#M2M[v3.0]|DATA:`) for large content compression.

## 3.4 Encoding Rules

### 3.4.1 Character Encoding

All M2M messages MUST be valid UTF-8.

Implementations:
- MUST reject messages containing invalid UTF-8 sequences
- MUST preserve Unicode characters in content fields
- SHOULD use NFC normalization for consistency

### 3.4.2 JSON Encoding

The payload (after prefix) MUST be valid JSON per [RFC8259].

Implementations:
- MUST NOT produce JSON with trailing commas
- MUST escape special characters in strings
- SHOULD minimize whitespace (compact JSON)

### 3.4.3 Delimiter

The pipe character `|` (U+007C) separates prefix from payload.

- MUST appear exactly once after the algorithm tag
- MUST NOT appear unescaped in the prefix
- MAY appear in payload (as part of JSON strings)

## 3.5 Size Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Maximum message size | 16 MiB | Prevent memory exhaustion |
| Maximum JSON depth | 32 levels | Prevent stack overflow |
| Maximum string length | 10 MiB | Single field limit |
| Maximum array elements | 10,000 | Prevent DoS |

Implementations:
- MUST reject messages exceeding size limits
- SHOULD reject before fully reading oversized messages
- MAY impose stricter limits

## 3.6 ABNF Grammar

```abnf
; M2M Protocol Wire Format Grammar (RFC 5234)

m2m-message    = token-message / token-native-message / brotli-message / dict-message
token-message  = "#T1" PIPE payload
token-native-message = "#TK" PIPE tokenizer-id PIPE base64-data
brotli-message = "#M2M[v3.0]" PIPE "DATA:" base64-data
dict-message   = "#M2M" PIPE payload

PIPE           = %x7C                    ; |
tokenizer-id   = "C" / "O" / "L"         ; cl100k / o200k / llama
base64-data    = *( ALPHA / DIGIT / "+" / "/" / "=" )

payload        = json-value
json-value     = json-object / json-array / json-string /
                 json-number / "true" / "false" / "null"
json-object    = "{" [ member *( "," member ) ] "}"
json-array     = "[" [ json-value *( "," json-value ) ] "]"
member         = json-string ":" json-value
json-string    = DQUOTE *char DQUOTE
json-number    = [ "-" ] int [ frac ] [ exp ]

DQUOTE         = %x22                    ; "
int            = "0" / ( %x31-39 *DIGIT )
frac           = "." 1*DIGIT
exp            = ( "e" / "E" ) [ "+" / "-" ] 1*DIGIT
DIGIT          = %x30-39                 ; 0-9
char           = unescaped / escaped
unescaped      = %x20-21 / %x23-5B / %x5D-10FFFF
escaped        = "\" ( %x22 / %x5C / %x2F / %x62 / %x66 /
                       %x6E / %x72 / %x74 / %x75 4HEXDIG )
HEXDIG         = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
```

## 3.7 Byte Order

M2M Protocol uses UTF-8 encoding exclusively. There is no byte order consideration for the text format.

For numeric values within JSON:
- Numbers are decimal ASCII representation
- No binary integer encoding
- IEEE 754 semantics for floating point

## 3.8 Versioning in Wire Format

Protocol version is NOT embedded in every message. Version negotiation occurs during session establishment (see [05-session-management.md](05-session-management.md)).

For stateless mode, the algorithm tag implies version:
- `T1` = Token compression v1.0
- `TK` = TokenNative compression v1.0
- Future versions may use `T2`, `TK2`, etc.

## 3.9 Examples

### 3.9.1 Minimal Message

```
#T1|{"M":"4o","m":[]}
```

### 3.9.2 Chat Completion Request

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

Compressed:
#T1|{"M":"4o","m":[{"r":"s","c":"You are helpful."},{"r":"u","c":"Hello!"}],"T":0.7,"x":100}
```

### 3.9.3 Chat Completion Response

```
Original:
{
  "id": "chatcmpl-123",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "Hello!"},
    "finish_reason": "stop"
  }],
  "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
}

Compressed:
#T1|{"id":"chatcmpl-123","C":[{"i":0,"m":{"r":"a","c":"Hello!"},"fr":"stop"}],"U":{"pt":10,"ct":5,"tt":15}}
```
