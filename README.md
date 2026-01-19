# M2M Protocol

[![Crates.io](https://img.shields.io/crates/v/m2m-core.svg)](https://crates.io/crates/m2m-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-220%20passing-brightgreen.svg)]()

**The compression protocol for machine-to-machine LLM communication.**

```
┌────────────────────────────────────────────────────────────────┐
│  BEFORE                           AFTER                        │
│  ────────────────────────────     ────────────────────────     │
│  {"model":"gpt-4o",               #M2M|1|<binary>              │
│   "messages":[                                                 │
│     {"role":"system",...},        147 bytes → 52 bytes         │
│     {"role":"user",...}           65% compression              │
│   ],                              < 1ms latency                │
│   "temperature":0.7}              100% fidelity                │
└────────────────────────────────────────────────────────────────┘
```

## What is M2M Protocol?

M2M is a wire protocol designed specifically for AI agent communication:

- **Compression**: 40-70% smaller payloads, optimized for LLM API JSON
- **Security**: Protocol-embedded threat detection (prompt injection, jailbreaks)
- **Routing**: Extract model/provider/tokens without decompression
- **Crypto**: Optional HMAC authentication and AEAD encryption

## The Problem

LLM APIs charge by **tokens**, not bytes. Traditional compression backfires:

| Approach | Bytes | Tokens | Cost Impact |
|----------|-------|--------|-------------|
| Original JSON | 147 | 42 | baseline |
| Gzip + Base64 | 180 | 58 | **+38% more expensive** |
| **M2M Protocol** | 52 | N/A | **-65% wire size** |

Why? Gzip produces binary requiring Base64, which *increases* token count. M2M compresses at the wire level while preserving routability.

## Quick Start

### Installation

```bash
# From crates.io
cargo install m2m-core

# From source
cargo install --path .

# With cryptographic features (HMAC, AEAD)
cargo install m2m-core --features crypto
```

### 30-Second Example

```rust
use m2m::{CodecEngine, Algorithm};

let engine = CodecEngine::new();

// Compress
let json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
let compressed = engine.compress(json, Algorithm::M2M)?;

println!("{} → {} bytes", compressed.original_bytes, compressed.compressed_bytes);

// Decompress (auto-detects algorithm)
let original = engine.decompress(&compressed.data)?;
assert_eq!(original, json);
```

### CLI

```bash
# Compress
m2m compress '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'

# Decompress (auto-detects format)
m2m decompress '#M2M|1|...'

# Security scan
m2m scan "Ignore all previous instructions"
```

## Features

### Compression Algorithms

| Algorithm | Wire Format | Compression | Best For |
|-----------|-------------|-------------|----------|
| **M2M** (default) | `#M2M\|1\|<binary>` | 40-70% | LLM API JSON with routing headers |
| **TokenNative** | `#TK\|C\|<tokens>` | 30-50% | Direct token ID transmission |
| **Brotli** | `#M2M[v3.0]\|DATA:<b64>` | 60-80% | Large payloads (>1KB) |
| **None** | passthrough | 0% | Small content (<100 bytes) |

> **Note**: M2M compression includes ~50 byte header overhead for routing metadata. Best results on payloads >200 bytes.

### Security Scanning

```rust
use m2m::SecurityScanner;

let scanner = SecurityScanner::new().with_blocking(0.8);
let result = scanner.scan("Ignore previous instructions")?;

if !result.safe {
    println!("Threats: {:?}", result.threats);
}
```

| Threat Type | Detection | Status |
|-------------|-----------|--------|
| Prompt Injection | Pattern matching | Available |
| Jailbreak Attempts | DAN/developer mode | Available |
| Data Exfiltration | Env/path patterns | Available |
| Malformed Payloads | Encoding attacks | Available |

### Cryptographic Security (Optional)

Enable with `--features crypto`:

```rust
use m2m::codec::m2m::{M2MFrame, SecurityMode};

// HMAC authentication
let frame = M2MFrame::from_json(json)?
    .with_security(SecurityMode::Hmac, &key)?;

// AEAD encryption (ChaCha20-Poly1305)  
let frame = M2MFrame::from_json(json)?
    .with_security(SecurityMode::Aead, &key)?;
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           M2M PROTOCOL STACK                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Agent A   │───▶│   ENCODE    │───▶│   DECODE    │───▶│   Agent B   │  │
│  └─────────────┘    └──────┬──────┘    └──────┬──────┘    └─────────────┘  │
│                            │                  │                             │
│                            ▼                  ▼                             │
│                    ┌──────────────────────────────────┐                     │
│                    │       COGNITIVE SECURITY         │                     │
│                    │  • Prompt injection detection    │                     │
│                    │  • Jailbreak pattern matching    │                     │
│                    │  • Algorithm routing (Hydra)     │                     │
│                    └──────────────────────────────────┘                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### M2M Wire Format v1

The default format extracts routing headers for inspection without decompression:

```
#M2M|1|<fixed_header><routing_header><payload>
       │             │               │
       │             │               └─ Brotli-compressed JSON
       │             └───────────────── Model, provider, token count  
       └─────────────────────────────── Version, flags, compression level
```

**Key advantage**: Load balancers and routers can read model/provider without decompressing the payload.

<details>
<summary><b>All Wire Formats</b></summary>

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ M2M v1 (Default)                                                             │
│ #M2M|1|<fixed_header><routing_header><brotli_payload>                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ TokenNative                                                                  │
│ #TK|<tokenizer>|<base64_varint_tokens>                                       │
│ Tokenizer: C=cl100k, O=o200k, L=llama                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│ Brotli                                                                       │
│ #M2M[v3.0]|DATA:<base64_brotli>                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ None (Passthrough)                                                           │
│ Original content unchanged                                                   │
└──────────────────────────────────────────────────────────────────────────────┘
```

</details>

## Protocol Modes

### Stateless (Simple)

Direct compression/decompression — no handshake:

```
Agent A                             Agent B
   │                                   │
   │══════ #M2M|1|<compressed> ═══════>│
   │<═════ #M2M|1|<compressed> ════════│
```

### Session-Based (Full Protocol)

Capability negotiation with HELLO/ACCEPT handshake:

```
Agent A                             Agent B
   │                                   │
   │────────── HELLO (caps) ──────────>│
   │<───────── ACCEPT (caps) ──────────│
   │                                   │
   │══════════ DATA ══════════════════>│
   │<═════════ DATA ═══════════════════│
   │                                   │
   │────────── PING ──────────────────>│
   │<───────── PONG ───────────────────│
```

```rust
use m2m::{Session, Capabilities};

let mut client = Session::new(Capabilities::default());
let hello = client.create_hello();

let mut server = Session::new(Capabilities::default());
let accept = server.process_hello(&hello)?;
client.process_accept(&accept)?;

// Exchange compressed data
let compressed = client.compress(content)?;
```

## Performance

| Metric | Value |
|--------|-------|
| Compression latency | ~0.24ms |
| Security scan | ~0.20ms |
| M2M compression | 40-70% (payloads >200B) |
| TokenNative compression | 30-50% |
| Brotli compression | 60-80% (payloads >1KB) |

## Hydra: ML-Based Routing

[Hydra](https://huggingface.co/infernet/hydra) is an optional MoE classifier for intelligent algorithm selection:

- **Architecture**: 4-layer MoE, top-2 routing
- **Size**: ~37MB safetensors
- **Inference**: Native Rust — no ONNX/Python required

```bash
# Download model
make model-download
# Or: huggingface-cli download infernet/hydra --local-dir ./models/hydra
```

> **Status**: Compression routing works well (95%+ accuracy). Security classification is experimental.

## Configuration

### Environment Variables

```bash
M2M_SERVER_PORT=3000
M2M_SECURITY_ENABLED=true
M2M_SECURITY_BLOCK_THRESHOLD=0.8
```

### Config File

```toml
# ~/.m2m/config.toml
[compression]
default_algorithm = "m2m"    # m2m, token-native, brotli
brotli_threshold = 1024

[security]
enabled = true
block_threshold = 0.8
```

## CLI Reference

```bash
# Compression
m2m compress '{"model":"gpt-4o",...}'           # Auto-select algorithm
m2m compress -a m2m '...'                       # Force M2M
m2m compress -a token-native '...'              # Force TokenNative
m2m decompress '#M2M|1|...'                     # Auto-detect format

# Security
m2m scan "content to scan"                      # Check for threats
m2m scan --block-threshold 0.8 "..."            # With blocking

# Analysis
m2m analyze '{"messages":[...]}'                # Recommend algorithm

# Server
m2m server --port 3000                          # Start M2M server
m2m server --port 3000 --blocking               # With security blocking
```

## Project Status

**Version 0.4.0** — Active development, 220+ tests passing.

| Feature | Status |
|---------|--------|
| M2M Wire Format v1 | Stable |
| TokenNative compression | Stable |
| Brotli compression | Stable |
| Security scanning (heuristic) | Stable |
| HMAC/AEAD crypto | Stable |
| Session management | Stable |
| Hydra compression routing | Stable |
| Hydra security classification | Experimental |
| QUIC/HTTP3 transport | Experimental |

## Documentation

- [Protocol Specification](docs/spec/00-introduction.md)
- [Wire Format](docs/spec/02-wire-format.md)
- [Compression Algorithms](docs/spec/04-compression.md)
- [Security](docs/spec/06-security.md)
- [Changelog](CHANGELOG.md)

## Contributing

Contributions welcome! See [issues](https://github.com/infernet-org/m2m-protocol/issues) or [VISION.md](VISION.md) for the roadmap.

```bash
# Development
make setup          # Build + download Hydra model
make test           # Run tests
make lint           # Run clippy
make bench-algorithms  # Run benchmarks
```

## License

Apache-2.0 — [INFERNET](https://infernet.org)

## Links

- [INFERNET](https://infernet.org)
- [Hydra Model](https://huggingface.co/infernet/hydra)
- [GitHub](https://github.com/infernet-org/m2m-protocol)
