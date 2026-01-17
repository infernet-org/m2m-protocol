# M2M Protocol

[![INFERNET](https://img.shields.io/badge/INFERNET-m2m--protocol-green.svg)](https://infernet.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)

**The only compression protocol that actually reduces LLM costs.**

## The Problem

LLM APIs charge by **tokens**, not bytes. Traditional compression backfires:

```
Original JSON:     68 bytes  →  42 tokens  →  $0.42 per 1M
Gzip + Base64:     52 bytes  →  58 tokens  →  $0.58 per 1M  ❌ +38% MORE expensive
```

Why? Gzip produces binary output requiring Base64 encoding, which **increases** token count by ~33%.

## The Solution

M2M applies **token-aware semantic compression** that reduces both bytes AND tokens:

```
Original JSON:     68 bytes  →  42 tokens  →  $0.42 per 1M
M2M Compressed:    45 bytes  →  29 tokens  →  $0.29 per 1M  ✓ 31% CHEAPER
```

The compressed output remains **valid JSON** — fully debuggable and tooling-compatible.

## How It Works

M2M uses semantic abbreviation optimized for LLM API structure:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Original                                                                    │
│ {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}          │
│                                                                             │
│ Wire Format                                                                 │
│ ┌────┬───┬──────────────────────────────────────────────────────────────┐  │
│ │ #  │T1 │ | {"M":"4o","m":[{"r":"u","c":"Hello"}]}                     │  │
│ └────┴───┴──────────────────────────────────────────────────────────────┘  │
│   ↑    ↑   ↑                                                                │
│   │    │   └─ Delimiter                                                     │
│   │    └───── Algorithm tag (T1 = Token v1)                                 │
│   └────────── M2M marker                                                    │
│                                                                             │
│ Savings: 34% bytes, 31% tokens                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Abbreviation Mappings

| Original | Compressed | Tokens Saved |
|----------|------------|--------------|
| `"messages"` | `"m"` | 2 → 1 |
| `"content"` | `"c"` | 2 → 1 |
| `"assistant"` | `"a"` | 2 → 1 |
| `"model"` | `"M"` | 2 → 1 |
| `"gpt-4o"` | `"4o"` | 3 → 1 |

Full mapping table: [docs/reference/abbreviations.md](docs/reference/abbreviations.md)

## Wire Format

Four algorithms with self-describing prefixes:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ TOKEN NATIVE (Recommended for M2M)                                           │
│ Best for: Small-medium LLM API JSON (<1KB) — ~50% compression                │
│                                                                              │
│  #  TK  |  C  |  W3sib29kZWw...                                              │
│  ▲  ▲   ▲  ▲  ▲  ▲                                                           │
│  │  │   │  │  │  └─ Base64-encoded VarInt token IDs                          │
│  │  │   │  │  └──── Separator                                                │
│  │  │   │  └─────── Tokenizer ID (C=cl100k, O=o200k, L=llama)                │
│  │  │   └────────── Delimiter                                                │
│  │  └────────────── Algorithm: TokenNative                                   │
│  └───────────────── M2M marker                                               │
│                                                                              │
│  Transmits BPE token IDs directly — tokenizer IS the dictionary              │
├──────────────────────────────────────────────────────────────────────────────┤
│ TOKEN                                                                        │
│ Best for: LLM API JSON — preserves structure, ~30% token savings             │
│                                                                              │
│  #  T1  |  { "M":"4o", "m":[{"r":"u","c":"Hello"}] }                         │
│  ▲  ▲   ▲  ▲                                                                 │
│  │  │   │  └─ Abbreviated JSON (still valid JSON!)                           │
│  │  │   └──── Delimiter                                                      │
│  │  └──────── Algorithm: Token v1                                            │
│  └─────────── M2M marker                                                     │
│                                                                              │
│  Prefix: 4 bytes                                                             │
├──────────────────────────────────────────────────────────────────────────────┤
│ BROTLI                                                                       │
│ Best for: Large repetitive content (>1KB)                                    │
│                                                                              │
│  #M2M[v3.0]|DATA:  G6kEABwHcNP2Yk9N...                                       │
│  ▲                 ▲                                                         │
│  │                 └─ Base64-encoded Brotli compressed data                  │
│  └─────────────────── Version-tagged prefix                                  │
│                                                                              │
│  Prefix: 16 bytes                                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│ NONE                                                                         │
│ Passthrough for: Small content (<100 bytes)                                  │
│                                                                              │
│  {"model":"gpt-4o","messages":[]}                                            │
│                                                                              │
│  No prefix — compression overhead would exceed savings                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

Auto-detection from prefix means decompression always knows which algorithm was used.

## Quick Start

### Installation

```bash
cargo install --path .
```

### As a Library

```rust
use m2m::{CodecEngine, Algorithm};

let engine = CodecEngine::new();

// Compress with Token (abbreviated JSON)
let json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
let result = engine.compress(json, Algorithm::Token)?;

println!("{}", result.data);  // #T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
println!("Saved: {:.0}%", (1.0 - result.byte_ratio()) * 100.0);

// Compress with TokenNative (direct token IDs — best for M2M)
use m2m::codec::TokenNativeCodec;
use m2m::models::Encoding;

let codec = TokenNativeCodec::new(Encoding::Cl100kBase);
let result = codec.compress(json)?;

println!("{}", result.data);  // #TK|C|W3sib29kZWw... (~50% smaller)

// Decompress (auto-detects algorithm from prefix)
let original = engine.decompress(&result.data)?;
```

### As a Proxy

Drop-in replacement for any OpenAI-compatible endpoint:

```bash
# Start proxy
m2m proxy --port 8080 --upstream http://localhost:11434/v1

# Use normally — compression is transparent
curl http://localhost:8080/v1/chat/completions \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"Hello"}]}'
```

Works with vLLM, Ollama, OpenAI, OpenRouter, Azure, or any OpenAI-compatible API.

## Protocol Modes

### Stateless (Simple)

Direct compression/decompression — no handshake required:

```
Client                              Server
   │                                   │
   │══════ Compressed Request ════════>│
   │<═════ Compressed Response ════════│
```

### Session-Based (Full Protocol)

Capability negotiation with HELLO/ACCEPT handshake:

```
Client                              Server
   │                                   │
   │────────── HELLO (caps) ──────────>│  Advertise: algorithms, security, streaming
   │<───────── ACCEPT (caps) ──────────│  Negotiate: common capabilities
   │                                   │
   │══════════ DATA ══════════════════>│  Exchange compressed payloads
   │<═════════ DATA ═══════════════════│
   │                                   │
   │────────── PING ──────────────────>│  Keep-alive (every 60s)
   │<───────── PONG ───────────────────│
   │                                   │
   │────────── CLOSE ─────────────────>│  Graceful termination
```

```rust
use m2m::{Session, Capabilities};

// Establish session
let mut client = Session::new(Capabilities::default());
let hello = client.create_hello();

let mut server = Session::new(Capabilities::default());
let accept = server.process_hello(&hello)?;
client.process_accept(&accept)?;

// Exchange data
let request = client.compress(r#"{"model":"gpt-4o","messages":[]}"#)?;
let response_content = server.decompress(&incoming)?;
```

## Features

### Security Scanning

Detect prompt injection and jailbreak attempts:

```rust
use m2m::SecurityScanner;

let scanner = SecurityScanner::new().with_blocking(0.8);
let result = scanner.scan("Ignore previous instructions")?;

if !result.safe {
    println!("Blocked: {:?}", result.threats);  // [Injection, confidence: 0.95]
}
```

| Threat | Description | Severity |
|--------|-------------|----------|
| Injection | "Ignore previous instructions" | High |
| Jailbreak | DAN mode, developer mode | Critical |
| DataExfil | Environment variable access | High |
| Malformed | Null bytes, excessive nesting | High |

### QUIC/HTTP3 Transport (Experimental)

Modern transport with 0-RTT, no head-of-line blocking:

```bash
m2m proxy --port 8080 --upstream http://localhost:11434/v1 \
          --transport both --quic-port 8443
```

> **Note**: QUIC support requires TLS certificates. Development mode uses self-signed certs.
> Production deployments should use proper certificates. QUIC transport is functional but
> has limited E2E test coverage compared to TCP transport.

### Intelligent Algorithm Selection

M2M includes intelligent algorithm selection that chooses the optimal compression based on content characteristics:

- **Small content (<100 bytes)**: No compression (overhead exceeds savings)
- **LLM API payloads**: Token compression (preserves JSON structure)
- **Large/repetitive content (>500 bytes)**: Brotli (best compression ratio)

The selection uses heuristics by default. For enhanced accuracy, optional ML-based routing
via [Hydra SLM](https://huggingface.co/infernet/hydra) is available:

```bash
# Download model (optional, heuristics work well for most cases)
huggingface-cli download infernet/hydra --local-dir ./models/hydra

# Build with ONNX support
cargo build --release --features onnx
```

> **Note**: The `onnx` feature enables model loading, but inference currently falls back
> to heuristics. ONNX tensor integration is in progress. Heuristic-based selection achieves
> similar results for most workloads.

## CLI Reference

```bash
m2m compress '{"model":"gpt-4o","messages":[...]}'     # Compress with Token
m2m compress -a brotli '{"large":"content"...}'        # Compress with Brotli
m2m decompress '#T1|{"M":"4o","m":[]}'                 # Decompress (auto-detect)
m2m scan "Ignore previous instructions"                # Security scan
m2m analyze '{"messages":[...]}'                       # Show recommended algorithm
m2m proxy --port 8080 --upstream http://...            # Start proxy
```

## Performance

| Metric | Value |
|--------|-------|
| Compression latency | < 1ms |
| Proxy overhead | < 2ms |
| Security scan | < 2ms |
| Memory footprint | < 50MB |

| Content Type | Token (T1) Savings | TokenNative (TK) Savings |
|--------------|-------------------|--------------------------|
| Chat completion | ~30% tokens | ~50% bytes |
| Long conversation | ~35% tokens | ~55% bytes |
| Tool calls | ~40% tokens | ~50% bytes |

**TokenNative** provides maximum byte compression for M2M communication.
**Token** preserves human-readable JSON for debugging.

## Supported Models

Accurate compression for models with open tokenizers:

| Provider | Models |
|----------|--------|
| OpenAI | GPT-4o, GPT-4, o1, o3 |
| Meta | Llama 3, 3.1, 3.3 |
| Mistral | Mistral, Mixtral |
| DeepSeek | DeepSeek v3, r1 |
| Qwen | Qwen 2.5 |

Models with closed tokenizers (Claude, Gemini) work via heuristic estimates.

## Configuration

```bash
# Environment
M2M_SERVER_PORT=8080
M2M_UPSTREAM_URL=http://localhost:11434/v1
M2M_SECURITY_ENABLED=true
```

```toml
# ~/.m2m/config.toml
[proxy]
listen = "127.0.0.1:8080"
upstream = "http://localhost:11434/v1"

[compression]
prefer_token_for_api = true
brotli_threshold = 1024
```

## Documentation

- [Protocol Specification](docs/spec/00-introduction.md)
- [Proxy Guide](docs/guides/proxy.md)
- [Configuration Reference](docs/reference/configuration.md)

## License

Apache-2.0 — [INFERNET](https://infernet.org)

## Links

- [INFERNET](https://infernet.org)
- [Hydra Model](https://huggingface.co/infernet/hydra)
- [API Docs](https://docs.rs/m2m)
- [GitHub](https://github.com/infernet-org/m2m-protocol)
