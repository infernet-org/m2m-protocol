# M2M Protocol v2.0 - Product Requirements Document

## Executive Summary

M2M Protocol v2.0 is a high-performance Rust implementation of a token-optimized compression protocol for LLM API traffic. It provides an OpenAI SDK-compatible proxy with automatic protocol negotiation, enabling transparent compression for M2M-aware clients while maintaining full compatibility with standard clients.

**Primary Goal**: Reduce LLM API token costs by 30-50% through intelligent compression, with sub-millisecond latency overhead.

---

## Problem Statement

### Current State
1. LLM APIs charge per token, not per byte
2. Traditional compression (gzip, brotli) increases token count due to base64 encoding
3. JSON payloads contain significant redundancy (repeated keys, default values)
4. No standard protocol exists for LLM-to-LLM communication optimization

### Impact
- Enterprises spend millions on redundant tokens
- High latency from verbose payloads
- No interoperability between compression schemes

---

## Solution Overview

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     M2M Protocol v2.0 Proxy                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────┐     ┌──────────────┐     ┌───────────────────────┐  │
│  │  Client   │────▶│  Negotiator  │────▶│  Compression Engine   │  │
│  │  Request  │     │              │     │                       │  │
│  └───────────┘     │  Detects:    │     │  - Structural         │  │
│                    │  - M2M Client│     │  - Default Removal    │  │
│                    │  - Standard  │     │  - Model Abbreviation │  │
│                    └──────────────┘     └───────────────────────┘  │
│                           │                       │                 │
│                           ▼                       ▼                 │
│                    ┌──────────────┐     ┌───────────────────────┐  │
│                    │   Router     │     │   Token Counter       │  │
│                    │              │     │   (tiktoken-rs)       │  │
│                    │  - Skip      │     └───────────────────────┘  │
│                    │  - Optimize  │                                 │
│                    │  - Full      │                                 │
│                    └──────────────┘                                 │
│                           │                                         │
│                           ▼                                         │
│                    ┌──────────────┐                                 │
│                    │   Upstream   │                                 │
│                    │   Forwarder  │                                 │
│                    └──────────────┘                                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol Negotiation

```
Standard Client Flow:
  Client → [Standard JSON] → M2M Proxy → [Optimized JSON] → Upstream
  
M2M-Aware Client Flow:
  Client → [M2M Header] → M2M Proxy → [Decompress] → Upstream
  
Detection via Header:
  X-M2M-Protocol: 1.0
  
Or via Content Structure:
  {"M":"og4o",...}  ← Abbreviated keys indicate M2M format
```

---

## Functional Requirements

### FR1: OpenAI SDK Compatibility

| ID | Requirement | Priority |
|----|-------------|----------|
| FR1.1 | Support `POST /v1/chat/completions` endpoint | P0 |
| FR1.2 | Support `GET /v1/models` endpoint | P1 |
| FR1.3 | Pass through all standard request fields | P0 |
| FR1.4 | Return responses in exact OpenAI format | P0 |
| FR1.5 | Support SSE streaming (`stream: true`) | P0 |
| FR1.6 | Pass through Authorization headers | P0 |

### FR2: Compression Engine

| ID | Requirement | Priority |
|----|-------------|----------|
| FR2.1 | Abbreviate JSON keys (messages→m, content→c) | P0 |
| FR2.2 | Abbreviate model names (gpt-4o→og4o) | P0 |
| FR2.3 | Abbreviate role values (assistant→A, system→S) | P1 |
| FR2.4 | Remove default parameter values | P0 |
| FR2.5 | Support lossless round-trip compression | P0 |
| FR2.6 | Header-less format for M2M clients | P1 |

### FR3: Protocol Negotiation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR3.1 | Detect M2M clients via `X-M2M-Protocol` header | P0 |
| FR3.2 | Detect M2M format via content structure | P1 |
| FR3.3 | Auto-decompress M2M requests before upstream | P0 |
| FR3.4 | Compress responses for M2M clients | P1 |
| FR3.5 | Fallback to standard mode for unknown clients | P0 |

### FR4: Model Registry

| ID | Requirement | Priority |
|----|-------------|----------|
| FR4.1 | Embedded registry of top 50 models | P0 |
| FR4.2 | Runtime fetch from OpenRouter API | P1 |
| FR4.3 | Cache fetched models with 24h TTL | P1 |
| FR4.4 | Map model IDs to abbreviations | P0 |
| FR4.5 | Map model IDs to tokenizer encodings | P0 |

### FR5: Token Counting

| ID | Requirement | Priority |
|----|-------------|----------|
| FR5.1 | Count tokens using tiktoken (cl100k_base) | P0 |
| FR5.2 | Support o200k_base for GPT-4o models | P0 |
| FR5.3 | Heuristic fallback for unknown encodings | P1 |
| FR5.4 | Report token savings in stats | P0 |

### FR6: Smart Routing

| ID | Requirement | Priority |
|----|-------------|----------|
| FR6.1 | Skip compression for messages < 25 tokens | P0 |
| FR6.2 | Detect high-value compression opportunities | P1 |
| FR6.3 | Rule-based routing (no ML in MVP) | P0 |

### FR7: CLI Tool

| ID | Requirement | Priority |
|----|-------------|----------|
| FR7.1 | `m2m compress` - Compress JSON input | P0 |
| FR7.2 | `m2m decompress` - Decompress M2M format | P0 |
| FR7.3 | `m2m tokens` - Count tokens in text | P0 |
| FR7.4 | `m2m proxy` - Start HTTP proxy server | P0 |
| FR7.5 | `m2m models` - List/query model registry | P1 |

### FR8: Configuration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR8.1 | TOML config file support | P1 |
| FR8.2 | CLI flags override config file | P0 |
| FR8.3 | Environment variable support | P1 |
| FR8.4 | Sensible defaults (zero-config startup) | P0 |

---

## Non-Functional Requirements

### NFR1: Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR1.1 | Compression latency | < 1ms |
| NFR1.2 | Token counting latency | < 0.5ms |
| NFR1.3 | Proxy overhead (e2e) | < 2ms |
| NFR1.4 | Memory footprint | < 50MB |
| NFR1.5 | Binary size | < 10MB |

### NFR2: Reliability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR2.1 | Graceful degradation on errors | 100% |
| NFR2.2 | No request blocking on failures | 100% |
| NFR2.3 | Upstream timeout handling | Configurable |

### NFR3: Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR3.1 | OpenAI SDK (Python) | Full |
| NFR3.2 | OpenAI SDK (Node.js) | Full |
| NFR3.3 | Anthropic SDK | Full |
| NFR3.4 | LiteLLM | Full |
| NFR3.5 | OpenRouter | Full |

---

## Data Structures

### Compressed Message Format

```
Standard Format:
{
  "model": "openai/gpt-4o",
  "messages": [
    {"role": "system", "content": "You are helpful"},
    {"role": "user", "content": "Hello"}
  ],
  "temperature": 1.0,
  "stream": false
}

M2M Compressed Format:
{
  "M": "og4o",
  "m": [
    {"r": "S", "c": "You are helpful"},
    {"r": "user", "c": "Hello"}
  ]
}

Notes:
- "user" not abbreviated (costs more tokens)
- temperature=1.0, stream=false removed (defaults)
- No header (structure-based detection)
```

### Model Card Structure

```rust
struct ModelCard {
    id: String,           // "openai/gpt-4o"
    abbrev: String,       // "og4o"
    provider: Provider,   // Provider::OpenAI
    encoding: Encoding,   // Encoding::O200kBase
    context_length: u32,  // 128000
    defaults: HashMap<String, Value>,
    pricing: Option<Pricing>,
}
```

### Compression Result

```rust
struct CompressionResult {
    compressed: Value,
    original_tokens: usize,
    compressed_tokens: usize,
    tokens_saved: i32,
    strategy: Strategy,
    cost_saved: Option<f64>,
}
```

---

## API Specification

### Proxy Endpoints

#### POST /v1/chat/completions

**Request:**
```http
POST /v1/chat/completions HTTP/1.1
Host: localhost:8080
Authorization: Bearer sk-xxx
Content-Type: application/json
X-M2M-Protocol: 1.0  # Optional, indicates M2M client

{...request body...}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-M2M-Tokens-Original: 150
X-M2M-Tokens-Compressed: 95
X-M2M-Tokens-Saved: 55

{...response body...}
```

#### GET /v1/models

**Response:**
```json
{
  "object": "list",
  "data": [
    {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
    {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"}
  ]
}
```

#### GET /_m2m/health

**Response:**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "uptime_seconds": 3600
}
```

#### GET /_m2m/stats

**Response:**
```json
{
  "requests_total": 10000,
  "tokens_original": 1500000,
  "tokens_compressed": 975000,
  "tokens_saved": 525000,
  "savings_percent": 35.0,
  "avg_latency_ms": 1.2
}
```

---

## CLI Specification

```bash
m2m 2.0.0
High-performance LLM API token compression

USAGE:
    m2m <COMMAND>

COMMANDS:
    compress    Compress a JSON message
    decompress  Decompress an M2M message
    tokens      Count tokens in text
    proxy       Start the HTTP proxy server
    models      Manage model registry
    help        Print help information

OPTIONS:
    -h, --help       Print help
    -V, --version    Print version
```

### compress

```bash
m2m compress [OPTIONS] [INPUT]

Arguments:
  [INPUT]  JSON input (or - for stdin)

Options:
  -o, --output <FILE>   Output file (default: stdout)
  -m, --model <MODEL>   Target model for token counting
  -s, --stats           Show compression statistics
  --native              Output M2M native format (with abbreviations)
```

### proxy

```bash
m2m proxy [OPTIONS]

Options:
  -t, --target <URL>    Upstream URL [default: https://api.openai.com]
  -p, --port <PORT>     Listen port [default: 8080]
  -c, --config <FILE>   Config file path
  --no-compress         Disable compression (passthrough mode)
  --stats-interval <S>  Stats logging interval [default: 60]
```

---

## Configuration

### Config File (~/.m2m/config.toml)

```toml
[proxy]
port = 8080
upstream = "https://api.openai.com"
timeout_ms = 30000
max_body_size_mb = 10

[compression]
enabled = true
min_tokens = 25
remove_defaults = true
abbreviate_keys = true
abbreviate_models = true

[registry]
auto_fetch = true
cache_ttl_hours = 24
embedded_only = false

[logging]
level = "info"
format = "json"
```

### Environment Variables

```bash
M2M_PROXY_PORT=8080
M2M_PROXY_UPSTREAM=https://api.openai.com
M2M_LOG_LEVEL=debug
```

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Token savings (M2M mode) | 30-50% | Avg across request types |
| Token savings (Proxy mode) | 5-10% | Default removal only |
| Compression latency | < 1ms | p99 |
| Proxy latency overhead | < 2ms | p99 |
| SDK compatibility | 100% | Test suite pass rate |
| Memory usage | < 50MB | Steady state |

---

## Out of Scope (MVP)

1. Security/Hydra ML model integration
2. Response compression
3. WebSocket support
4. Multi-upstream routing
5. Rate limiting
6. Authentication (passthrough only)
7. WASM target
8. Python bindings

---

## Milestones

| Phase | Components | Duration |
|-------|------------|----------|
| 1 | Core: Models, Tokenizer, Compression | 1 week |
| 2 | CLI: compress, decompress, tokens | 3 days |
| 3 | Proxy: Basic HTTP, negotiation | 1 week |
| 4 | Proxy: Streaming (SSE) | 3 days |
| 5 | Testing, benchmarks, docs | 3 days |

**Total: ~3.5 weeks**

---

## Appendix A: Abbreviation Tables

### Key Abbreviations

| Original | Abbreviated | Tokens Saved |
|----------|-------------|--------------|
| messages | m | 0 |
| content | c | 1 |
| role | r | 0 |
| model | M | 1 |
| temperature | T | 1 |
| max_tokens | x | 2 |
| stream | s | 0 |
| function_call | fc | 3 |
| tool_calls | tc | 2 |

### Model Abbreviations

| Original | Abbreviated | Tokens Saved |
|----------|-------------|--------------|
| openai/gpt-4o | og4o | 4 |
| openai/gpt-4o-mini | og4om | 5 |
| anthropic/claude-3.5-sonnet | ac35s | 8 |
| meta-llama/llama-3.1-405b | ml31405 | 11 |

### Role Abbreviations

| Original | Abbreviated | Tokens Saved |
|----------|-------------|--------------|
| system | S | 1 |
| assistant | A | 1 |
| function | F | 1 |
| tool | T | 1 |
| user | (no abbrev) | -1 (skip) |

---

## Appendix B: Default Values

Parameters removed when matching these values:

```json
{
  "temperature": 1.0,
  "top_p": 1.0,
  "n": 1,
  "stream": false,
  "frequency_penalty": 0,
  "presence_penalty": 0,
  "logit_bias": {},
  "stop": null
}
```
