# M2M Protocol

[![Crates.io](https://img.shields.io/crates/v/m2m-core.svg)](https://crates.io/crates/m2m-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.79+-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-220%20passing-brightgreen.svg)]()

**The wire protocol for machine-to-machine AI agent communication.**

```
┌────────────────────────────────────────────────────────────────┐
│  BEFORE                           AFTER                        │
│  ────────────────────────────     ────────────────────────     │
│  {"model":"gpt-4o",               #M2M|1|<binary>              │
│   "messages":[                                                 │
│     {"role":"system",...},        2.4 KB → 1.0 KB              │
│     {"role":"user",...}           58% smaller on the wire      │
│   ],                              < 1ms latency                │
│   "temperature":0.7}              100% fidelity                │
└────────────────────────────────────────────────────────────────┘
```

## What is M2M Protocol?

M2M is a wire protocol for **agent-to-agent communication** with two innovations:

1. **Agentic Observability** — Routing metadata readable without decompression
2. **Cognitive Security** — Semantic-level threat detection at the protocol layer

When AI agents communicate at scale, traditional tools fail: you can't inspect compressed payloads, and network-layer security can't understand what agents are saying to each other. M2M solves both.

## Agentic Observability

Traditional observability breaks down with compressed traffic — you can't inspect what you can't read. M2M's wire format exposes routing metadata **without decompressing the payload**:

```
#M2M|1|<header><payload>
       │
       └─ Model, provider, token count readable here
          Payload stays compressed
```

This enables:

| Capability | Without M2M | With M2M |
|------------|-------------|----------|
| Route by model/provider | Decompress → Parse JSON → Route | Read header → Route |
| Cost attribution | Parse every payload | Read token count from header |
| Traffic analytics | Full decompression pipeline | Header inspection only |
| Audit logging | Store raw or lose visibility | Compressed + inspectable |

**Infrastructure-layer intelligence**: Load balancers, API gateways, and observability tools can make routing decisions without parsing JSON or decompressing payloads.

## Cognitive Security

Traditional security operates at the network layer — TLS, firewalls, WAFs. But network security can't understand **what agents are saying to each other**.

Cognitive Security operates at the **semantic layer**:

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

M2M embeds threat detection **at the protocol layer** — before transmission:

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

**Security as a protocol guarantee**: Every M2M-speaking agent gets the same threat detection. No per-agent implementation. No gaps.

## Quick Start

```bash
cargo install m2m-core
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
m2m compress '{"model":"gpt-4o","messages":[...]}'
m2m decompress '#M2M|1|...'
m2m scan "Ignore all previous instructions"
```

## Why M2M?

| Problem | Solution |
|---------|----------|
| **Latency** | 58% smaller payloads, sub-ms encode/decode |
| **Payload limits** | Fit 2-3x more context within Lambda/API Gateway limits |
| **Storage costs** | 40-70% smaller logs and audit trails |
| **Blind routing** | Headers readable without decompression |
| **Semantic attacks** | Cognitive security at protocol layer |

## Wire Format

| Algorithm | Wire Format | Compression | Best For |
|-----------|-------------|-------------|----------|
| **M2M** (default) | `#M2M\|1\|...` | 40-70% | LLM API JSON |
| **TokenNative** | `#TK\|C\|...` | 30-50% | Token ID transmission |
| **Brotli** | `#M2M[v3.0]\|DATA:...` | 60-80% | Large payloads (>1KB) |

## Cryptographic Security

Optional (`--features crypto`):

- **HMAC** — Message authentication
- **AEAD** — ChaCha20-Poly1305 encryption
- **X25519** — Key exchange

## Protocol Modes

**Stateless**: Direct compress/decompress, no handshake.

**Session-based**: HELLO/ACCEPT capability negotiation, PING/PONG keep-alive.

## Performance

| Metric | Value |
|--------|-------|
| Compression | ~0.24ms |
| Decompression | ~0.15ms |
| Security scan | ~0.20ms |
| Throughput | 4,000+ req/sec |

## Hydra (Optional)

[Hydra](https://huggingface.co/infernet/hydra) is an ML classifier for intelligent algorithm selection. Native Rust inference — no ONNX/Python.

```bash
make model-download
```

## Project Status

**Version 0.4.0** — 220+ tests passing.

| Feature | Status |
|---------|--------|
| M2M Wire Format v1 | Stable |
| Agentic Observability | Stable |
| Cognitive Security | Stable |
| HMAC/AEAD crypto | Stable |
| Hydra routing | Stable |
| QUIC/HTTP3 | Experimental |

## Documentation

- [Protocol Specification](docs/spec/00-introduction.md)
- [Wire Format](docs/spec/02-wire-format.md)
- [Security](docs/spec/06-security.md)
- [Changelog](CHANGELOG.md)

## License

Apache-2.0 — [INFERNET](https://infernet.org)

[GitHub](https://github.com/infernet-org/m2m-protocol) · [Hydra Model](https://huggingface.co/infernet/hydra)
