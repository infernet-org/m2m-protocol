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

M2M is a wire protocol for **agent-to-agent communication** — not agent-to-LLM-API.

When AI agents communicate at scale, they exchange massive amounts of JSON: conversation histories, tool outputs, context windows, and orchestration data. M2M compresses this traffic by 40-70% while keeping it routable and secure.

## Why M2M?

| Problem | Solution |
|---------|----------|
| **Latency** | 58% smaller payloads, sub-ms encode/decode |
| **Payload limits** | Fit 2-3x more context within Lambda/API Gateway limits |
| **Storage costs** | 40-70% smaller logs and audit trails |
| **Routing overhead** | Extract model/provider without decompression |
| **Security gaps** | Protocol-embedded threat detection |

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

## Wire Format

M2M's wire format exposes routing headers **without decompressing the payload**:

```
#M2M|1|<fixed_header><routing_header><payload>
       │             │               │
       │             │               └─ Brotli-compressed JSON
       │             └───────────────── Model, provider, token count  
       └─────────────────────────────── Version, flags, compression level
```

Load balancers can route by model/provider without parsing JSON.

| Algorithm | Wire Format | Compression | Best For |
|-----------|-------------|-------------|----------|
| **M2M** (default) | `#M2M\|1\|...` | 40-70% | LLM API JSON |
| **TokenNative** | `#TK\|C\|...` | 30-50% | Token ID transmission |
| **Brotli** | `#M2M[v3.0]\|DATA:...` | 60-80% | Large payloads (>1KB) |

## Security

Threat detection at the protocol layer — **before** transmission:

```rust
use m2m::SecurityScanner;

let scanner = SecurityScanner::new().with_blocking(0.8);
let result = scanner.scan("Ignore previous instructions")?;

if !result.safe {
    println!("Blocked: {:?}", result.threats);
}
```

**Detects**: Prompt injection, jailbreaks, data exfiltration, malformed payloads.

**Optional crypto** (`--features crypto`): HMAC authentication, AEAD encryption (ChaCha20-Poly1305).

## Protocol Modes

**Stateless**: Direct compress/decompress, no handshake.

**Session-based**: HELLO/ACCEPT capability negotiation, PING/PONG keep-alive.

```rust
use m2m::{Session, Capabilities};

let mut client = Session::new(Capabilities::default());
let hello = client.create_hello();

let mut server = Session::new(Capabilities::default());
let accept = server.process_hello(&hello)?;
client.process_accept(&accept)?;
```

## Performance

| Metric | Value |
|--------|-------|
| Compression | ~0.24ms |
| Decompression | ~0.15ms |
| Security scan | ~0.20ms |
| Throughput | 4,000+ req/sec |

## Hydra (Optional)

[Hydra](https://huggingface.co/infernet/hydra) is an ML classifier for intelligent algorithm selection:

```bash
make model-download
```

Native Rust inference from safetensors — no ONNX/Python required.

## Project Status

**Version 0.4.0** — 220+ tests passing.

| Feature | Status |
|---------|--------|
| M2M Wire Format v1 | Stable |
| TokenNative / Brotli | Stable |
| Security scanning | Stable |
| HMAC/AEAD crypto | Stable |
| Session management | Stable |
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
