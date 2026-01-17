---
title: M2M Protocol
description: High-performance Machine-to-Machine protocol for LLM API communication
template: splash
hero:
  tagline: Token-optimized compression for LLM APIs. 25-40% savings on every request.
  actions:
    - text: Get Started
      link: /guides/quickstart/
      icon: right-arrow
      variant: primary
    - text: View on GitHub
      link: https://github.com/infernet-org/m2m-protocol
      icon: external
---

## Features

- **Multi-codec Compression** - Token (~30% savings), Brotli (high-ratio), and Dictionary compression algorithms optimized for LLM payloads.
- **OpenAI-Compatible Proxy** - Drop-in reverse proxy for any OpenAI-compatible API. Works with vLLM, Ollama, OpenRouter, and more.
- **QUIC/HTTP3 Transport** - 0-RTT connection establishment, no head-of-line blocking, and connection migration for resilient agent communication.
- **Security Scanning** - Built-in threat detection for prompt injection, jailbreaks, and data exfiltration attempts.

## Quick Example

```bash
# Start proxy forwarding to local Ollama
m2m proxy --port 8080 --upstream http://localhost:11434/v1

# Use normally - compression is transparent
curl http://localhost:8080/v1/chat/completions \
  -d '{"model": "llama3.2", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Compression Results

| Content Type | Original | Compressed | Savings |
|--------------|----------|------------|---------|
| Chat request | 2.4 KB | 1.7 KB | ~30% |
| Long conversation | 48 KB | 31 KB | ~35% |
| Tool calls | 8.2 KB | 4.9 KB | ~40% |
