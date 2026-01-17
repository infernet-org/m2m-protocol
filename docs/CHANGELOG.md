# Changelog

All notable changes to M2M Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-17

### Added

- **Wire Format Specification**
  - Token compression (`#T1|`) with semantic abbreviation
  - Brotli compression (`#BR|`) for large content
  - Dictionary compression (`#DI|`) for pattern-based encoding

- **Message Types**
  - HELLO/ACCEPT handshake for session establishment
  - REJECT for session denial with reason codes
  - DATA for compressed payload exchange
  - PING/PONG for keep-alive
  - CLOSE for graceful termination

- **Token Compression**
  - 50+ key abbreviations for OpenAI API schema
  - Role value abbreviations (system, user, assistant, etc.)
  - Model abbreviations for OpenAI, Meta, Mistral, DeepSeek, Qwen
  - Default value omission for reduced payload size

- **Security Scanning**
  - Prompt injection detection
  - Jailbreak pattern recognition
  - Configurable blocking/monitoring modes
  - Confidence threshold tuning

- **OpenAI-Compatible Proxy**
  - Drop-in proxy for any OpenAI-compatible endpoint
  - Transparent request/response compression
  - SSE streaming support
  - Statistics endpoint

- **Session Management**
  - Capability negotiation
  - Session timeout and keep-alive
  - State machine implementation

### Supported Providers

- OpenAI (tiktoken tokenizer)
- Meta Llama (Llama BPE tokenizer)
- Mistral/Mixtral (Llama BPE tokenizer)
- DeepSeek (heuristic tokenizer)
- Qwen (heuristic tokenizer)
- Nvidia Nemotron (Llama BPE tokenizer)

### Documentation

- RFC-style protocol specification
- Quick start guide
- Proxy configuration guide
- Complete abbreviation reference
- Wire format examples

## [0.2.0] - 2025-01-16

### Added

- Initial Rust implementation
- Basic compression codecs
- CLI tool

### Changed

- Migrated from Python prototype

## [0.1.0] - 2025-01-01

### Added

- Python prototype
- Proof of concept compression
