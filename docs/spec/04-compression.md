# 5. Compression Algorithms

## 5.1 Overview

M2M Protocol supports multiple compression algorithms optimized for different content types.

| Algorithm | Tag | Best For | Typical Savings |
|-----------|-----|----------|-----------------|
| Token | `T1` | LLM API payloads | 25-40% |
| Brotli | `BR` | Large content (>4KB) | 60-80% |
| Dictionary | `DI` | Repetitive patterns | 20-30% |
| None | - | Small content (<100B) | 0% |

## 5.2 Algorithm Selection

### 5.2.1 Automatic Selection

Implementations SHOULD select algorithms based on:

1. **Content size**: Small content (<100 bytes) → None
2. **Content type**: JSON with LLM keys → Token
3. **Repetition**: Highly repetitive → Brotli
4. **Token sensitivity**: API-bound → Token preferred

### 5.2.2 Selection Heuristics

```
if content_size < 100:
    return None
elif is_llm_api_payload(content):
    if content_size > 4096 and repetition_ratio > 0.3:
        return Brotli
    else:
        return Token
else:
    return Brotli
```

## 5.3 Token Compression (Algorithm T1)

### 5.3.1 Overview

Token compression applies semantic abbreviation to JSON keys, values, and model names. The goal is to reduce token count, not just byte count.

### 5.3.2 Key Abbreviation

Keys are abbreviated to single characters or short sequences.

**Request Keys:**

| Original | Abbreviated | Tokens Saved |
|----------|-------------|--------------|
| `messages` | `m` | 1 |
| `content` | `c` | 1 |
| `role` | `r` | 1 |
| `model` | `M` | 1 |
| `temperature` | `T` | 2 |
| `max_tokens` | `x` | 2 |
| `top_p` | `p` | 2 |
| `stream` | `s` | 1 |
| `stop` | `S` | 1 |
| `frequency_penalty` | `f` | 3 |
| `presence_penalty` | `P` | 3 |
| `logit_bias` | `lb` | 2 |
| `user` | `u` | 1 |
| `n` | `n` | 0 |
| `seed` | `se` | 1 |
| `tools` | `ts` | 1 |
| `tool_choice` | `tc` | 2 |
| `function_call` | `fc` | 3 |
| `functions` | `fs` | 2 |
| `response_format` | `rf` | 3 |

**Response Keys:**

| Original | Abbreviated | Tokens Saved |
|----------|-------------|--------------|
| `choices` | `C` | 1 |
| `index` | `i` | 1 |
| `message` | `m` | 1 |
| `finish_reason` | `fr` | 3 |
| `usage` | `U` | 1 |
| `prompt_tokens` | `pt` | 2 |
| `completion_tokens` | `ct` | 3 |
| `total_tokens` | `tt` | 2 |
| `delta` | `d` | 1 |
| `logprobs` | `lp` | 2 |

**Tool Keys:**

| Original | Abbreviated |
|----------|-------------|
| `tool_calls` | `tc` |
| `function` | `fn` |
| `name` | `n` |
| `arguments` | `a` |
| `type` | `t` |

### 5.3.3 Value Abbreviation

Common string values are abbreviated.

**Role Values:**

| Original | Abbreviated |
|----------|-------------|
| `system` | `s` |
| `user` | `u` |
| `assistant` | `a` |
| `function` | `f` |
| `tool` | `t` |

**Finish Reason Values:**

| Original | Abbreviated |
|----------|-------------|
| `stop` | `s` |
| `length` | `l` |
| `tool_calls` | `tc` |
| `content_filter` | `cf` |
| `function_call` | `fc` |

### 5.3.4 Model Abbreviation

Model identifiers are abbreviated by provider.

**OpenAI Models:**

| Original | Abbreviated |
|----------|-------------|
| `gpt-4o` | `4o` |
| `gpt-4o-mini` | `4om` |
| `gpt-4-turbo` | `4t` |
| `gpt-4` | `4` |
| `gpt-3.5-turbo` | `35t` |
| `o1` | `o1` |
| `o1-mini` | `o1m` |
| `o1-preview` | `o1p` |
| `o3` | `o3` |
| `o3-mini` | `o3m` |

**Meta Llama Models:**

| Original | Abbreviated |
|----------|-------------|
| `meta-llama/llama-3.3-70b` | `ml3370` |
| `meta-llama/llama-3.1-405b` | `ml31405` |
| `meta-llama/llama-3.1-70b` | `ml3170` |
| `meta-llama/llama-3.1-8b` | `ml318` |

**Mistral Models:**

| Original | Abbreviated |
|----------|-------------|
| `mistralai/mistral-large` | `mim-l` |
| `mistralai/mistral-small` | `mim-s` |
| `mistralai/mixtral-8x7b` | `mimx87` |

### 5.3.5 Default Value Omission

Parameters matching default values MAY be omitted.

| Parameter | Default | Omit When |
|-----------|---------|-----------|
| `temperature` | `1.0` | Equal to 1.0 |
| `top_p` | `1.0` | Equal to 1.0 |
| `n` | `1` | Equal to 1 |
| `stream` | `false` | Equal to false |
| `frequency_penalty` | `0` | Equal to 0 |
| `presence_penalty` | `0` | Equal to 0 |
| `logit_bias` | `{}` | Empty object |
| `stop` | `null` | Null |

Implementations:
- MUST restore omitted parameters during decompression
- MUST preserve non-default values exactly
- SHOULD NOT omit if value differs from default

### 5.3.6 Compression Algorithm

```
function compress_token(json):
    obj = parse_json(json)
    obj = abbreviate_keys(obj, KEY_MAP)
    obj = abbreviate_values(obj, VALUE_MAP)
    obj = abbreviate_model(obj)
    obj = omit_defaults(obj)
    return "#T1|" + serialize_json(obj)

function decompress_token(wire):
    payload = strip_prefix(wire, "#T1|")
    obj = parse_json(payload)
    obj = expand_keys(obj, KEY_MAP)
    obj = expand_values(obj, VALUE_MAP)
    obj = expand_model(obj)
    obj = restore_defaults(obj)
    return serialize_json(obj)
```

### 5.3.7 Example

**Original (68 bytes, ~42 tokens):**
```json
{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"temperature":1.0,"stream":false}
```

**Compressed (45 bytes, ~29 tokens):**
```
#T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
```

**Savings:** 34% bytes, 31% tokens

## 5.4 Brotli Compression (Algorithm BR)

### 5.4.1 Overview

Brotli compression is used for large content where byte reduction outweighs Base64 token overhead.

### 5.4.2 Encoding

1. Compress content using Brotli (quality level 4-6)
2. Encode compressed bytes as Base64
3. Prepend `#BR|` prefix

### 5.4.3 When to Use

- Content size > 4096 bytes
- High repetition (>30% duplicate substrings)
- Non-LLM API content

### 5.4.4 Example

**Original (large JSON):**
```json
{"messages":[{"role":"user","content":"...10KB of text..."}]}
```

**Compressed:**
```
#BR|G6kEABwHcNP2Yk9N...base64...
```

## 5.5 Dictionary Compression (Algorithm DI)

### 5.5.1 Overview

Dictionary compression encodes common JSON patterns as single bytes.

### 5.5.2 Pattern Table

| Pattern | Code |
|---------|------|
| `{"role":"user","content":"` | `0x80` |
| `{"role":"assistant","content":"` | `0x81` |
| `{"role":"system","content":"` | `0x82` |
| `"}` | `0x83` |
| `"},` | `0x84` |
| `"}]` | `0x85` |
| `{"messages":[` | `0x86` |
| `{"model":"` | `0x87` |

### 5.5.3 Encoding

Patterns in the 0x80-0xFF byte range are reserved for dictionary codes.

## 5.6 No Compression

### 5.6.1 When to Use

- Content size < 100 bytes
- Already compressed content
- Binary content that cannot be JSON-encoded

### 5.6.2 Wire Format

Content is passed through without prefix modification.

## 5.7 Algorithm Negotiation

During session establishment, endpoints negotiate supported algorithms:

1. Client sends list of supported algorithms in HELLO
2. Server responds with intersection in ACCEPT
3. Subsequent DATA messages use any negotiated algorithm

For stateless mode, the prefix indicates the algorithm used.

## 5.8 Decompression

### 5.8.1 Algorithm Detection

Implementations MUST detect algorithm from prefix:

```
if starts_with("#T1|"):
    return decompress_token(content)
elif starts_with("#BR|"):
    return decompress_brotli(content)
elif starts_with("#DI|"):
    return decompress_dictionary(content)
else:
    return content  # No compression
```

### 5.8.2 Error Handling

- Invalid prefix → return error
- Decompression failure → return error
- Invalid JSON after decompression → return error

Implementations MUST NOT return partially decompressed content.
