# Changelog

All notable changes to M2M Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-19

### Added

- **M3 Protocol**: New schema-aware binary compression that eliminates JSON structural overhead
  - Wire format: `#M3|<schema:1byte><binary_payload>`
  - Achieves ~60% byte savings for typical LLM API payloads
  - Supports ChatCompletionRequest schema with messages, model, and parameters
  - Uses varint encoding for efficient number representation
  - M3 is now the default negotiated algorithm

### Changed

- Default compression algorithm changed from TokenNative to M3
- Hydra routing heuristics updated to prefer M3 for LLM API content
- Algorithm preference order: M3 > TokenNative > Brotli > None

### Deprecated

- **Algorithm::Token**: Only achieves 3% token savings. Use M3 instead.
- **Algorithm::Zlib**: Kept for v2.0 wire format compatibility only.
- **Algorithm::Dictionary**: Has negative compression (increases size).

### Removed

- Proxy module removed - M2M is designed for direct agent-to-agent communication

### Fixed

- Documentation now reflects empirically verified compression numbers
- Security detection claims corrected (heuristic works, neural ~50% accuracy)

## [0.2.0] - 2026-01-18

### Added

- TokenNative compression: transmit token IDs directly with VarInt encoding
- Hydra BitNet model for ML-based routing and security scanning
- QUIC/HTTP3 transport support
- Session-based protocol with capability negotiation
- Security scanning with threat detection (prompt injection, jailbreak)

### Changed

- Restructured codec system with pluggable algorithms
- Improved tokenizer support (cl100k, o200k, Llama 3)

## [0.1.0] - 2026-01-15

### Added

- Initial release
- Basic compression codecs (Brotli, Zlib, Dictionary)
- Token-optimized compression with key abbreviation
- CLI tool for compression testing
- HTTP server for API access
