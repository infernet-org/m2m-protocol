# Changelog

All notable changes to M2M Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-01-19

### Added

- **M2M Wire Format v1** as the new default compression algorithm
  - Routing headers (model, provider, token count) readable without decompression
  - ~60-70% byte savings with 100% JSON fidelity
  - Wire format: `#M2M|1|<fixed_header><routing_header><brotli_payload>`
- **Cryptographic security** (feature: `crypto`)
  - HMAC message authentication
  - AEAD encryption with ChaCha20-Poly1305
  - X25519 key exchange for session keys
- **Stress test binary** (`m2m_stress_test`) for performance validation
- **Streaming M2M** compression/decompression finalized

### Changed

- Default algorithm changed from Token to M2M
- Hydra inference updated to route between M2M, Brotli, and Hybrid
- Protocol capabilities now advertise: M2M, Brotli, Hybrid, TokenNative
- Benchmark binaries rewritten to test current algorithms
- Documentation updated to reflect M2M v1 as primary format

### Removed

- **BREAKING**: `Algorithm::Token` variant removed
- **BREAKING**: `Algorithm::Dictionary` variant removed  
- **BREAKING**: `Algorithm::Zlib` variant removed
- **BREAKING**: `Algorithm::M3` variant removed
- `compress_m2m()` method removed from engine (use `compress()` with `Algorithm::M2M`)
- `#[deprecated]` attributes removed (deprecated items are now gone)

### Migration Guide

If you were using any of the removed algorithms, update your code:

```rust
// Before (0.3.x)
let result = engine.compress(content, Algorithm::Token)?;
let result = engine.compress(content, Algorithm::Dictionary)?;
let result = engine.compress(content, Algorithm::M3)?;

// After (0.4.0)
let result = engine.compress(content, Algorithm::M2M)?;      // Recommended default
let result = engine.compress(content, Algorithm::Brotli)?;   // High compression
let result = engine.compress(content, Algorithm::TokenNative)?; // Token ID transmission
```

### Backwards Compatibility

- **Reading old data**: Wire formats `#TK|`, `#DC|`, `#ZL|`, `#M3|` can still be decompressed
- **Writing new data**: Only M2M, Brotli, Hybrid, and TokenNative formats are produced

### Performance

Stress test results (1000 requests):
- Throughput: ~4000+ requests/second
- Compression latency: <1ms average
- M2M compression ratio: ~60-70%

## [0.3.0] - 2025-12-XX

### Added

- Initial M3 schema-aware compression
- TokenNative codec for BPE token ID transmission
- Hydra MoE model for algorithm routing
- Security scanner with heuristic threat detection
- QUIC/HTTP3 transport (experimental)

### Deprecated

- `Algorithm::Token` (use M2M or TokenNative)
- `Algorithm::Dictionary` (use M2M)
- `Algorithm::Zlib` (use Brotli)

## [0.2.0] - 2025-XX-XX

### Added

- Token compression algorithm
- Dictionary compression algorithm
- Brotli compression for large content
- Protocol negotiation (HELLO/ACCEPT)
- Session management

## [0.1.0] - 2025-XX-XX

### Added

- Initial release
- Basic compression/decompression
- Wire format detection
