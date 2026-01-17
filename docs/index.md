---
title: M2M Protocol
description: Token-native compression for LLM APIs. Because gzip costs more, not less.
template: splash
hero:
  tagline: Token-native compression for LLM APIs. Because gzip costs more, not less.
  actions:
    - text: Get Started
      link: /guides/quickstart/
      icon: right-arrow
      variant: primary
    - text: View on GitHub
      link: https://github.com/infernet-org/m2m-protocol
      icon: external
---

## The Problem: Compression Backfires

LLM APIs charge by **tokens**, not bytes. Traditional compression makes things worse:

| Approach | Bytes | Tokens | Cost per 1M |
|----------|-------|--------|-------------|
| Original JSON | 68 | 42 | $0.42 |
| Gzip + Base64 | 52 | 58 | $0.58 |
| **M2M TokenNative** | 45 | — | **$0.38** |

**Why?** Gzip outputs binary, requiring Base64 encoding, which *increases* token count by ~33%. You pay more, not less.

## The Solution: Token-Native Compression

M2M compresses in token-space, not byte-space. The result: **30-35% smaller payloads** that actually reduce your LLM bill.

```
Original:    {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
M2M Token:   #T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
M2M Native:  #TK|C|<base64_token_ids>
```

## Features

- **Token-Native Compression** — Unlike gzip, M2M compresses in token-space. 30-35% wire savings that actually reduce your bill. ~50% in binary mode.

- **OpenAI-Compatible Proxy** — Drop-in reverse proxy for any OpenAI-compatible API. Point your code at M2M, it handles compression transparently.

- **QUIC/HTTP3 Transport** — 0-RTT connection establishment, no head-of-line blocking. Built for high-frequency agent-to-agent communication.

- **Security Scanning** — Inspects content during compression. Detects prompt injection, jailbreaks, and data exfiltration before they reach the LLM.

## Quick Start

```bash
# Install
cargo install --git https://github.com/infernet-org/m2m-protocol

# Start proxy (forwards to local Ollama)
m2m proxy --port 8080 --upstream http://localhost:11434/v1

# Use normally - compression is transparent
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3.2", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Benchmarks

Measured on real LLM API payloads:

| Content Type | Original | Compressed | Savings |
|--------------|----------|------------|---------|
| Chat request | 2.4 KB | 1.6 KB | 33% |
| Multi-turn conversation | 48 KB | 32 KB | 33% |
| Tool calls + function schema | 8.2 KB | 5.4 KB | 34% |
| Streaming chunks | 156 B | 102 B | 35% |

*TokenNative algorithm, wire format (Base64). Binary transport achieves ~50% savings.*

## When to Use What

| Content | Size | Algorithm | Why |
|---------|------|-----------|-----|
| LLM API JSON | < 4KB | **TokenNative** | Best compression for structured LLM traffic |
| Large prompts | > 4KB | **Brotli** | Better ratio on large text |
| Low-latency streaming | Any | **Token (T1)** | Human-readable, fast encode/decode |

## License

Apache-2.0 — Use it, fork it, build on it.
