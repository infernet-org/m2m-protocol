---
title: Documentation
description: M2M Protocol documentation index
---

# M2M Protocol Documentation

Version 1.0 | [GitHub](https://github.com/infernet-org/m2m-protocol) | [Hydra Model](https://huggingface.co/infernet/hydra)

## Overview

M2M (Machine-to-Machine) Protocol is a token-optimized compression scheme for LLM API traffic. Unlike byte-oriented compression (gzip, brotli) that increases token count due to Base64 encoding, M2M achieves 25-40% token reduction through semantic compression.

## Documentation Structure

### Specification (`spec/`)

Formal protocol specification following IETF RFC conventions:

| Document | Description |
|----------|-------------|
| [00-introduction.md](spec/00-introduction.md) | Protocol overview, goals, and scope |
| [01-terminology.md](spec/01-terminology.md) | Definitions and RFC 2119 requirement keywords |
| [02-wire-format.md](spec/02-wire-format.md) | Binary/text encoding specification |
| [03-message-types.md](spec/03-message-types.md) | Complete message catalog |
| [04-compression.md](spec/04-compression.md) | Compression algorithms and mappings |
| [05-session-management.md](spec/05-session-management.md) | Session lifecycle and state machine |
| [06-security.md](spec/06-security.md) | Security model and threat mitigations |

### Guides (`guides/`)

Human-readable documentation for implementers:

| Document | Description |
|----------|-------------|
| [quickstart.md](guides/quickstart.md) | 5-minute getting started guide |
| [proxy.md](guides/proxy.md) | OpenAI-compatible proxy server |

### Reference (`reference/`)

API and configuration reference:

| Document | Description |
|----------|-------------|
| [error-codes.md](reference/error-codes.md) | Complete error code reference |
| [configuration.md](reference/configuration.md) | Configuration options |
| [abbreviations.md](reference/abbreviations.md) | Key/value abbreviation tables |

### Examples (`examples/`)

Working examples and test vectors:

| Directory | Description |
|-----------|-------------|
| [wire-format/](examples/wire-format/) | Annotated wire format examples |

## Quick Reference

### Wire Format Prefixes

| Algorithm | Prefix | Use Case |
|-----------|--------|----------|
| Token | `#T1\|` | LLM API payloads (~30% savings) |
| Brotli | `#BR\|` | Large content (>4KB) |
| None | (passthrough) | Small content (<100 bytes) |

### Compression Example

```
Original (68 bytes):
{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}

Compressed (45 bytes, 34% reduction):
#T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
```

## Version History

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

Apache-2.0
