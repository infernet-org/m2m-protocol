# Changelog

All notable changes to M2M Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Unified `CryptoError` type** for error chain preservation
  - Aggregates all crypto errors (`AeadError`, `HmacError`, `KeyringError`, etc.)
  - Preserves error source chain via `#[source]` attribute
  - Enables debugging tools to display complete error context
- **`M2MError::Crypto` variant** for proper crypto error propagation
  - Crypto errors no longer wrapped as generic `Compression`/`Decompression` strings
  - Full error chain preserved through `std::error::Error::source()`
- **`KeyPair::generate_with_rng()`** for deterministic key generation in tests
  - Accepts any `CryptoRng + RngCore` implementation
  - Enables reproducible test cases with seeded RNGs

### Changed

- Crypto errors in `frame.rs` now use `M2MError::Crypto(e.into())` pattern
  - HMAC init/verify errors preserve `HmacError` source
  - AEAD init/encrypt/decrypt errors preserve `AeadError` source
  - Nonce generation errors preserve `NonceError` source

### Epistemic Notes

Error handling now follows epistemic principles:
- **B_i falsified**: Most errors indicate a runtime belief was proven wrong
- **I^B handling**: Bounded ignorance errors (RNG, network) return `Result`
- **Error chains**: `#[source]` enables tracing errors to root cause

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
- **Hierarchical Key Derivation** (feature: `crypto`)
  - HKDF-based multi-agent key management
  - Derive unique keys for 100+ agents from single master secret
  - Symmetric session key derivation between agents
  - RFC 5869 compliant with official test vectors
  - Documented test vectors for external implementation compatibility
- **Stress test binary** (`m2m_stress_test`) for performance validation
- **Streaming M2M** compression/decompression finalized

### Changed

- Default algorithm changed from Token to M2M
- Hydra inference updated to route between M2M, Brotli, and Hybrid
- Protocol capabilities now advertise: M2M, Brotli, Hybrid, TokenNative
- Benchmark binaries rewritten to test current algorithms
- Documentation updated to reflect M2M v1 as primary format

### Security

- **Fixed nonce reuse vulnerability in AEAD encryption**
  - Previous: Counter-based nonces reset to 0 on process restart
  - Now: Fully random 96-bit nonces from CSPRNG
  - This prevents catastrophic key recovery attacks from nonce reuse
  - Deterministic nonces now restricted to test builds only (`#[cfg(test)]`)
- Added nonce generation security documentation (Section 7.8.4)
- **Guaranteed key zeroization** using `zeroize` crate
  - Key material is securely cleared from memory on drop
  - Volatile writes prevent compiler optimization of zeroization
  - Non-crypto builds use best-effort volatile writes
- **Key material validation** (`KeyMaterial::try_new()`)
  - Validates non-empty keys at construction time
  - `try_new_with_min_length()` for explicit length requirements
- **Agent and Organization ID validation** (`AgentId::try_new()`, `OrgId::try_new()`)
  - Validates IDs are non-empty, use valid characters, and respect length limits
  - Prevents path injection in key derivation paths
- **Fallible nonce generation** (`SecurityContext::next_nonce() -> Result`)
  - RNG failures are now properly propagated instead of panicking
  - Epistemic: I^B (bounded ignorance) properly handled as `Result`

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

### Documentation

- **Wire Format Spec** (`docs/spec/02-wire-format.md`): Complete rewrite to document actual M2M binary format (`#M2M|1|`), header structure, and legacy format detection
- **Compression Spec** (`docs/spec/04-compression.md`): Updated to reflect M2M as primary algorithm, Token removal, and migration guidance
- **Error Reference** (`docs/reference/error-codes.md`): Complete rewrite with all `M2MError` variants, new `CryptoError` unified type, and epistemic classification
- **Security Spec** (`docs/spec/06-security.md`): Updated zeroization example to use `zeroize` crate, added Section 7.9 Error Handling
- Fixed spec/implementation drift identified via epistemic systems analysis

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
