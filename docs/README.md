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
| [Introduction](/spec/00-introduction/) | Protocol overview, goals, and scope |
| [Terminology](/spec/01-terminology/) | Definitions and RFC 2119 requirement keywords |
| [Wire Format](/spec/02-wire-format/) | Binary/text encoding specification |
| [Message Types](/spec/03-message-types/) | Complete message catalog |
| [Compression](/spec/04-compression/) | Compression algorithms and mappings |
| [Session Management](/spec/05-session-management/) | Session lifecycle and state machine |
| [Security](/spec/06-security/) | Security model and threat mitigations |

### Guides (`guides/`)

Human-readable documentation for implementers:

| Document | Description |
|----------|-------------|
| [Quickstart](/guides/quickstart/) | 5-minute getting started guide |

### Reference (`reference/`)

API and configuration reference:

| Document | Description |
|----------|-------------|
| [Error Codes](/reference/error-codes/) | Complete error code reference |
| [Configuration](/reference/configuration/) | Configuration options |
| [Abbreviations](/reference/abbreviations/) | Key/value abbreviation tables |

### Examples (`examples/`)

Working examples and test vectors:

| Directory | Description |
|-----------|-------------|
| [wire-format/](examples/wire-format/) | Annotated wire format examples |

## Quick Reference

### Wire Format Prefixes

| Algorithm | Prefix | Use Case |
|-----------|--------|----------|
| TokenNative | `#TK\|` | M2M traffic (~30-35% wire, ~50% binary) |
| Token | `#T1\|` | Human-readable (~10-20% savings) |
| Brotli | `#BR\|` | Large content (>1KB) |
| None | (passthrough) | Small content (<100 bytes) |

*Note: Session mode uses full prefix `#M2M[v3.0]|DATA:` for framing.*

### Compression Example

```
Original (68 bytes):
{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}

TokenNative (~40 bytes, transmits BPE token IDs):
#TK|C|W3sib29kZWw...

Token (45 bytes, human-readable):
#T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
```

## Version History

See [CHANGELOG](/changelog/) for version history.

## License

Apache-2.0
