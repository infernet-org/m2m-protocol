# M2M Protocol

[![Crates.io](https://img.shields.io/crates/v/m2m-protocol.svg)](https://crates.io/crates/m2m-protocol)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88+-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-268%20passing-brightgreen.svg)]()

**Wire protocol for AI agent communication with inspectable headers and semantic security.**

```
M2M Frame (Application Layer - transported over HTTP/QUIC)
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

Security Modes (headers always readable):
  None: [headers][payload_len][crc32][payload]
  HMAC: [headers][payload_len][crc32][payload][hmac_tag:32B]
  AEAD: [headers][nonce:12B][encrypt(payload_len+crc32+payload)+tag:16B]
                  ▲ headers remain readable ▲

Sch: 0x01=Request  0x02=Response  0x03=Stream  0x10=Error
Sec: 0x00=None     0x01=HMAC-SHA256           0x02=ChaCha20-Poly1305
```

Cognitive security (threat detection) operates pre-transmission — see [SecurityScanner](#cognitive-security).

## The Problem

When AI agents communicate at scale, three problems emerge that traditional tools can't solve:

### 1. The Compression Paradox

Traditional compression (gzip, brotli, zstd) reduces **bytes** but produces binary output requiring Base64 encoding. This *increases* token count:

```
Original JSON:     68 bytes  →  42 tokens
Gzip + Base64:     52 bytes  →  58 tokens  (+38% tokens)
```

Binary data tokenizes poorly (~1 byte/token) compared to text (~4 chars/token). For agent-to-agent traffic where latency matters, you're transmitting **more data** after "compression."

### 2. The Observability Gap

Compressed traffic is opaque. Load balancers, API gateways, and observability tools must decompress every payload to make routing decisions. At scale, this adds latency and complexity.

### 3. The Semantic Security Gap

Network security (TLS, firewalls, WAFs) operates at the packet level. It can't understand what agents are *saying* to each other. Prompt injection, jailbreaks, and data exfiltration attempts pass through undetected.

**M2M solves all three.**

## Quick Start

```bash
cargo add m2m-core
```

```rust
use m2m::{CodecEngine, Algorithm};

let engine = CodecEngine::new();

// Compress
let json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
let compressed = engine.compress(json, Algorithm::M2M)?;

// Decompress (auto-detects algorithm)
let original = engine.decompress(&compressed.data)?;
```

```bash
# CLI
cargo install m2m-core

m2m compress '{"model":"gpt-4o","messages":[...]}'
m2m decompress '#M2M|1|...'
m2m scan "Ignore all previous instructions"
```

## Core Concepts

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         M2M Protocol Stack                          │
├─────────────────────────────────────────────────────────────────────┤
│  Application    │  Your Agent Code                                  │
├─────────────────┼───────────────────────────────────────────────────┤
│  Security       │  SecurityScanner → Cognitive threat detection     │
├─────────────────┼───────────────────────────────────────────────────┤
│  Codec          │  CodecEngine → M2M / TokenNative / Brotli         │
├─────────────────┼───────────────────────────────────────────────────┤
│  Protocol       │  Session → HELLO/ACCEPT/DATA/CLOSE                │
├─────────────────┼───────────────────────────────────────────────────┤
│  Transport      │  TCP (HTTP/1.1) │ QUIC (HTTP/3, 0-RTT)            │
└─────────────────┴───────────────────────────────────────────────────┘
```

### Protocol Primitives

| Primitive | Purpose | Usage |
|-----------|---------|-------|
| `CodecEngine` | Compress/decompress payloads | `engine.compress(json, Algorithm::M2M)` |
| `Session` | Stateful connection with capability negotiation | `Session::new(capabilities)` |
| `SecurityScanner` | Semantic threat detection | `scanner.scan(content)` |
| `Algorithm` | Compression algorithm selection | `M2M`, `TokenNative`, `Brotli` |
| `M2MFrame` | Wire format with routing headers | 20-byte fixed header + payload |
| `Capabilities` | Protocol negotiation | Algorithms, security, streaming |

### Protocol Modes

**Stateless**: Direct compress/decompress. No handshake, no state.

```rust
let engine = CodecEngine::new();
let compressed = engine.compress(json, Algorithm::M2M)?;
```

**Session-based**: HELLO/ACCEPT capability negotiation, PING/PONG keep-alive, graceful CLOSE.

```rust
let mut session = Session::new(Capabilities::default());
session.connect(&mut transport)?;  // HELLO/ACCEPT
session.send(json)?;               // DATA
session.close()?;                  // CLOSE
```

## Agentic Observability

M2M's wire format exposes routing metadata **without decompressing the payload**:

```
#M2M|1|<header><payload>
       │
       └─ Model, provider, token count readable here
          Payload stays compressed
```

| Capability | Without M2M | With M2M |
|------------|-------------|----------|
| Route by model/provider | Decompress → Parse → Route | Read header → Route |
| Cost attribution | Parse every payload | Read token count from header |
| Traffic analytics | Full decompression pipeline | Header inspection only |
| Audit logging | Store raw or lose visibility | Compressed + inspectable |

**Infrastructure-layer intelligence**: Load balancers, API gateways, and observability tools can make routing decisions without parsing JSON or decompressing payloads.

## Cognitive Security

Traditional security operates at the network layer. Cognitive Security operates at the **semantic layer**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                              │
├─────────────────────────────────────────────────────────────────┤
│  Network Security    │  TLS, firewalls, IP rules               │
│  (can't see content) │  "Is this connection allowed?"          │
├──────────────────────┼──────────────────────────────────────────┤
│  Cognitive Security  │  Semantic analysis, intent detection    │
│  (understands meaning)│  "Is this agent trying to jailbreak?"   │
└──────────────────────┴──────────────────────────────────────────┘
```

### Threat Detection

```rust
use m2m::SecurityScanner;

let scanner = SecurityScanner::new().with_blocking(0.8);
let result = scanner.scan("Ignore all previous instructions")?;

if !result.safe {
    // Blocked at protocol level — never reaches downstream agent
    println!("Threats: {:?}", result.threats);
}
```

| Threat | Detection Method |
|--------|------------------|
| Prompt injection | Semantic pattern analysis |
| Jailbreak attempts | DAN/developer mode detection |
| Data exfiltration | Environment/path pattern matching |
| Malformed payloads | Encoding attack detection |

### Cryptographic Security

Optional (`--features crypto`):

| Feature | Algorithm | Purpose |
|---------|-----------|---------|
| HMAC | SHA-256 | Message authentication |
| AEAD | ChaCha20-Poly1305 | Authenticated encryption |
| Key Exchange | X25519 | Ephemeral key agreement |
| Key Derivation | HKDF-SHA256 | Hierarchical key derivation |

**Security as a protocol guarantee**: Every M2M-speaking agent gets the same threat detection and crypto primitives. No per-agent implementation. No gaps.

## Wire Format

| Algorithm | Wire Format | Compression | Best For |
|-----------|-------------|-------------|----------|
| **M2M** (default) | `#M2M\|1\|<header><payload>` | 40-70% | LLM API JSON, routing-aware |
| **TokenNative** | `#TK\|<enc>\|<tokens>` | 30-50% | Token ID transmission |
| **Brotli** | `#M2M[v3.0]\|DATA:<b64>` | 60-80% | Large payloads (>1KB) |

### Algorithm Selection

```rust
// Automatic (recommended)
let result = engine.compress_auto(json)?;

// Explicit
let result = engine.compress(json, Algorithm::M2M)?;

// ML-assisted (requires Hydra model)
let result = engine.compress_with_hydra(json)?;
```

## M2M vs Alternatives

### Latency Comparison

| Approach | Wire Size | Tokens | Encode | Decode | Headers Readable |
|----------|-----------|--------|--------|--------|------------------|
| Raw JSON | 100% | 100% | 0 | 0 | Yes |
| Gzip + Base64 | ~52% | **+38%** | ~0.5ms | ~0.3ms | No |
| Brotli + Base64 | ~40% | **+25%** | ~2ms | ~0.5ms | No |
| Protobuf | ~50% | N/A | ~0.2ms | ~0.2ms | No |
| **M2M** | ~45% | **-40%** | **0.24ms** | **0.15ms** | **Yes** |

M2M optimizes for the metrics that matter in agent-to-agent communication:
- **Sub-millisecond latency**: Encode + decode < 0.5ms total
- **Token reduction**: Fewer tokens = faster LLM processing
- **Routing without decompression**: Headers always readable

### When to Use M2M

- Agent-to-agent communication over HTTP/QUIC
- LLM API traffic where token count affects latency
- Systems requiring payload inspection at infrastructure layer
- Multi-agent architectures needing standardized security

### When NOT to Use M2M

- Non-LLM traffic (use gzip/brotli directly)
- Already using efficient binary protocols end-to-end (gRPC, Cap'n Proto)
- Single-agent systems with no inter-agent communication
- Environments where payload inspection isn't needed

## Performance

| Metric | Value |
|--------|-------|
| Compression | ~0.24ms |
| Decompression | ~0.15ms |
| Security scan | ~0.20ms |
| Throughput | 4,000+ req/sec |

## Hydra (Optional)

[Hydra](https://huggingface.co/infernet/hydra) is an ML classifier for intelligent algorithm selection. Native Rust inference — no ONNX/Python runtime required.

```bash
make model-download
```

## Project Status

**Version 0.4.0** — 268 tests passing.

| Feature | Status |
|---------|--------|
| M2M Wire Format v1 | Stable |
| Agentic Observability | Stable |
| Cognitive Security | Stable |
| HMAC/AEAD crypto | Stable |
| Hydra ML routing | Stable |
| QUIC/HTTP3 | Experimental |

## Documentation

- [Protocol Specification](docs/spec/00-introduction.md)
- [Wire Format](docs/spec/02-wire-format.md)
- [Security](docs/spec/06-security.md)
- [Changelog](CHANGELOG.md)

## License

Apache-2.0 — [INFERNET](https://infernet.org)

[GitHub](https://github.com/infernet-org/m2m-protocol) · [Crates.io](https://crates.io/crates/m2m-core) · [Hydra Model](https://huggingface.co/infernet/hydra)
