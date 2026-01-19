---
title: M2M Protocol
description: The wire protocol for machine-to-machine AI agent communication
template: splash
hero:
  tagline: The wire protocol for machine-to-machine AI agent communication
  actions:
    - text: Get Started
      link: /guides/quickstart/
      icon: right-arrow
      variant: primary
    - text: View on GitHub
      link: https://github.com/infernet-org/m2m-protocol
      icon: external
---

## The Problem: Agent Traffic at Scale

As autonomous agents multiply, they generate massive amounts of inter-agent traffic:

| Challenge | Impact | M2M Solution |
|-----------|--------|--------------|
| **Bandwidth** | Terabytes of redundant JSON structure | 40-70% compression |
| **Latency** | Large payloads slow agent coordination | Sub-millisecond encode/decode |
| **Routing** | Can't inspect compressed payloads | Headers readable without decompression |
| **Security** | Agents pass malicious prompts to each other | Protocol-embedded threat detection |

**M2M Protocol is designed for agent-to-agent communication — not agent-to-LLM-API.**

## The Architecture

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
│                    │  ┌────────────────────────────┐  │                     │
│                    │  │      Hydra MoE Model       │  │                     │
│                    │  │  • Prompt injection detect │  │                     │
│                    │  │  • Jailbreak detection     │  │                     │
│                    │  │  • Compression routing     │  │                     │
│                    │  └────────────────────────────┘  │                     │
│                    └──────────────────────────────────┘                     │
│                                                                             │
│  Wire Formats:  #M2M|1|<header><payload>   #TK|C|<tokens>   #M2M[v3.0]|DATA:<brotli>  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Why Compress Agent Traffic?

Multi-agent systems generate enormous amounts of redundant data:

| Deployment | Daily Messages | Raw JSON | With M2M | Monthly Savings |
|------------|----------------|----------|----------|-----------------|
| Small | 100K | 240 GB | 100 GB | **140 GB** |
| Medium | 10M | 24 TB | 10 TB | **14 TB** |
| Large | 1B | 2.4 PB | 1 PB | **1.4 PB** |

Every message carries the same JSON boilerplate: `{"role":`, `"content":`, `"model":`, etc. M2M eliminates this overhead.

## Security: Protocol-Embedded

**Security at the protocol layer, not bolted on top.**

Traditional security operates at network or application layers. M2M embeds security *within the protocol itself*, detecting threats before they're forwarded to downstream agents.

### Hydra: Mixture-of-Experts Classifier

A specialized classifier designed for protocol-embedded inference:

- **Architecture**: 4-layer MoE, top-2 routing (vocab: 32K, hidden: 192)
- **Size**: ~37MB safetensors — native Rust inference, no Python/ONNX required
- **Tasks**: Compression routing (4-class) + Security screening (2-class)
- **Status**: Compression routing functional; security screening experimental

`[Pattern matching: Available]` `[Neural inference: Experimental]`

### What It Detects

| Threat | Method | Status |
|--------|--------|--------|
| Prompt Injection | Semantic pattern analysis | ✓ Available |
| Jailbreak Attempts | DAN/developer mode detection | ✓ Available |
| Data Exfiltration | Environment/path pattern detection | ✓ Available |
| Malformed Payloads | Encoding attack detection | ✓ Available |

### Protocol-Level vs Application-Level Security

| Traditional Approach | M2M Approach |
|---------------------|--------------|
| Security at application layer | Security at protocol layer |
| Each agent implements own checks | Standardized threat detection |
| Malicious content transmitted, then detected | Blocked before transmission |
| No inter-agent security contract | Protocol-level security guarantee |

```rust
use m2m::{CodecEngine, SecurityScanner};

// Security is embedded in the protocol flow
let scanner = SecurityScanner::new().with_blocking(0.8);

let content = r#"{"messages":[{"content":"Ignore previous instructions"}]}"#;
let scan = scanner.scan(content)?;

if !scan.safe {
    // Blocked at protocol level — never reaches downstream agent
    return Err(M2MError::SecurityThreat(scan.threats));
}
```

## Compression

M2M eliminates JSON structural overhead using schema-aware binary encoding:

| Content | Original | M2M | Savings |
|---------|----------|-----|---------|
| Simple request | 147 B | 60 B | 59% |
| Multi-turn conversation | 2.4 KB | 1.0 KB | 58% |
| Tool calls + schema | 8.2 KB | 3.5 KB | 57% |
| Large context (32K tokens) | 128 KB | 48 KB | 62% |

### Wire Formats

```
#M2M|1|<header><payload>         M2M v1: Schema-aware binary (40-70% savings)
#TK|C|<token_ids>                TokenNative: BPE token IDs (30-50%)
#M2M[v3.0]|DATA:<brotli>         Brotli: Large content compression (60-80%)
```

### M2M Wire Format v1

M2M eliminates JSON structural overhead by using positional encoding with a known schema. Both endpoints understand the LLM API schema, so structure doesn't need to be transmitted.

```
Wire format: #M2M|1|<fixed_header><routing_header><payload>

Routing header (readable without decompression):
  [model:string][provider:string][token_count:varint]

Payload:
  [brotli_compressed_json]
```

**Key advantage**: Load balancers can route by model/provider without decompressing.

`[M2M: Default]` `[TokenNative: Available]` `[Brotli: Large content]`

## Transport: Built for Agents

**QUIC/HTTP3 transport optimized for high-frequency agent communication.**

- **0-RTT**: No handshake latency for repeat connections
- **No head-of-line blocking**: Parallel streams don't wait for each other
- **Connection migration**: Agents can move between networks without reconnecting

`[QUIC Transport: Available]` `[HTTP/1.1 Fallback: Available]`

## The Vision

We are entering **ERA 3** of computing:

```
ERA 1 (1970-2000): Human → Computer
ERA 2 (2000-2020): Human → Computer → Human  
ERA 3 (2020-2030): Human → Agent → Agent → ... → Agent → Human
ERA 4 (2030+):     Agent ⇄ Agent (Human optional)
```

M2M Protocol is infrastructure for ERA 3 and beyond — where autonomous agents communicate at scale, and the protocol itself must be intelligent enough to ensure security, efficiency, and trust.

[Read the full vision →](https://github.com/infernet-org/m2m-protocol/blob/main/VISION.md)

## Quick Start

```bash
# Install
cargo install m2m-core

# Or with crypto features
cargo install m2m-core --features crypto
```

```rust
use m2m::{CodecEngine, Algorithm, SecurityScanner};

// Security scanning before compression
let scanner = SecurityScanner::new().with_blocking(0.8);
let scan = scanner.scan(content)?;

if scan.safe {
    // Compress for agent-to-agent transmission
    let engine = CodecEngine::new();
    let result = engine.compress(content, Algorithm::M2M)?;
    // Send to downstream agent...
}
```

## License

Apache-2.0 — Use it, fork it, build on it.
