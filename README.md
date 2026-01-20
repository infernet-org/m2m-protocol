# M2M Protocol

[![Crates.io](https://img.shields.io/crates/v/m2m-core.svg)](https://crates.io/crates/m2m-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
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

When AI agents communicate at scale, they exchange massive amounts of JSON: conversation histories, tool outputs, context windows, and orchestration data. M2M compresses this traffic:

- **Bandwidth**: 40-70% smaller payloads = reduced egress costs
- **Latency**: Faster transmission between agents/services
- **Routing**: Extract model/provider without decompression (load balancer friendly)
- **Security**: Protocol-embedded threat detection (prompt injection, jailbreaks)
- **Crypto**: Optional HMAC authentication and AEAD encryption

## The Problem

As multi-agent systems scale, raw JSON becomes a bottleneck. Cloud egress fees—charged when data leaves a provider's network—add up quickly.

| Scale | Messages/Day | Payload | Monthly Traffic | With M2M (58%) | Saved |
|-------|--------------|---------|-----------------|----------------|-------|
| Startup | 100K | 2 KB | 180 GB | 76 GB | 104 GB |
| Growth | 1M | 2 KB | 1.8 TB | 756 GB | 1 TB |
| Scale | 10M | 2 KB | 18 TB | 7.6 TB | 10 TB |
| Enterprise | 100M | 2 KB | 180 TB | 76 TB | 104 TB |

**Cloud Egress Cost Impact** (2025 rates, internet egress):

| Provider | Free Tier | Rate | 18 TB Raw | 7.6 TB (M2M) | Savings |
|----------|-----------|------|-----------|--------------|---------|
| AWS | 100 GB/mo | $0.05-0.09/GB | ~$1,500 | ~$630 | ~$870 |
| Azure | 100 GB/mo | $0.087/GB | ~$1,560 | ~$650 | ~$910 |
| GCP | varies | $0.08-0.12/GB | ~$1,800 | ~$760 | ~$1,040 |
| Oracle | 10 TB/mo | $0.0085/GB | ~$68 | ~$0* | ~$68 |

*Oracle's 10TB free tier covers most M2M-compressed traffic at this scale.

> **Note**: Egress is billed on volume transferred. Compression directly reduces the bill—every byte saved is money saved. This compounds with other strategies like CDNs, regional locality, and private links.

Every agent-to-agent message carries redundant JSON structure: `{"role":`, `"content":`, `"model":`, etc. M2M eliminates this overhead while keeping payloads routable.

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

// Compress for agent-to-agent transmission
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

## Use Cases

| Use Case | Why M2M? |
|----------|----------|
| **Agent orchestration** | Reduce bandwidth between coordinator and worker agents |
| **Conversation relay** | Compress context windows passed between agents |
| **Tool output forwarding** | Large tool responses (search results, DB queries) compress well |
| **Audit logging** | Store compressed conversation logs, decompress on demand |
| **Edge deployment** | Minimize data transfer for bandwidth-constrained agents |

## Compression Algorithms

| Algorithm | Wire Format | Compression | Best For |
|-----------|-------------|-------------|----------|
| **M2M** (default) | `#M2M\|1\|<binary>` | 40-70% | LLM API JSON with routing headers |
| **TokenNative** | `#TK\|C\|<tokens>` | 30-50% | Direct token ID transmission |
| **Brotli** | `#M2M[v3.0]\|DATA:<b64>` | 60-80% | Large payloads (>1KB) |
| **None** | passthrough | 0% | Small content (<100 bytes) |

> **Note**: M2M includes ~50 byte header overhead for routing metadata. Best results on payloads >200 bytes.

### Compression Benchmarks

| Content | Original | M2M | Savings |
|---------|----------|-----|---------|
| Simple request | 147 B | 60 B | 59% |
| Multi-turn conversation | 2.4 KB | 1.0 KB | 58% |
| Tool calls + schema | 8.2 KB | 3.5 KB | 57% |
| Large context (32K tokens) | 128 KB | 48 KB | 62% |

## Security

### Threat Detection

M2M embeds security scanning at the protocol layer — threats are detected **before** transmission to downstream agents.

```rust
use m2m::SecurityScanner;

let scanner = SecurityScanner::new().with_blocking(0.8);
let result = scanner.scan("Ignore previous instructions")?;

if !result.safe {
    println!("Blocked threats: {:?}", result.threats);
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

// HMAC authentication — verify message integrity
let frame = M2MFrame::from_json(json)?
    .with_security(SecurityMode::Hmac, &key)?;

// AEAD encryption — ChaCha20-Poly1305
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
│                    │       SECURITY SCANNING          │                     │
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

**Key advantage**: Load balancers can route requests by model/provider without decompressing the payload.

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
| Decompression latency | ~0.15ms |
| Security scan | ~0.20ms |
| Throughput | 4,000+ req/sec (single thread) |

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
