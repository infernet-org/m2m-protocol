# M2M Protocol v2.0 - Implementation Roadmap

## Phase 1: Core Foundation (Days 1-2)

### 1.1 Project Scaffold
- [x] Create `rust/m2m-core/` directory structure
- [x] Write `Cargo.toml` with dependencies
- [x] Create PRD.md and TECHNICAL_DESIGN.md
- [x] Create README.md
- [ ] Create `src/lib.rs` with module declarations
- [ ] Create `src/error.rs` with error types

### 1.2 Models Module
- [ ] `src/models/mod.rs` - Module exports
- [ ] `src/models/card.rs` - ModelCard struct, Provider enum, Encoding enum
- [ ] `src/models/embedded.rs` - Compile-time embedded model data
- [ ] `src/models/registry.rs` - ModelRegistry with lookup functions
- [ ] Tests for model lookups and abbreviation generation

**Deliverable**: `ModelRegistry::new()` returns registry with 35+ embedded models

### 1.3 Tokenizer Module
- [ ] `src/tokenizer/mod.rs` - Module exports
- [ ] `src/tokenizer/counter.rs` - Token counting with tiktoken-rs
- [ ] Support for cl100k_base and o200k_base encodings
- [ ] Heuristic fallback for unknown models
- [ ] Tests for token counting accuracy

**Deliverable**: `count_tokens("text")` returns accurate count

---

## Phase 2: Compression Engine (Days 3-4)

### 2.1 Abbreviation Tables
- [ ] `src/compress/mod.rs` - Module exports
- [ ] `src/compress/tables.rs` - phf compile-time hash maps
  - Key abbreviations (25+ keys)
  - Key expansions (reverse mapping)
  - Role abbreviations
  - Default value detection

### 2.2 Structural Compressor
- [ ] `src/compress/structural.rs` - StructuralCompressor
  - `compress()` - Full M2M compression
  - `optimize()` - Default removal only
  - `decompress()` - Expand abbreviated format
  - Recursive JSON traversal
- [ ] Tests for compression/decompression round-trip

### 2.3 Smart Router
- [ ] `src/compress/router.rs` - Router
  - `route()` - Returns Strategy (Skip/Optimize/Full)
  - Token threshold checks
  - Default detection heuristics
- [ ] Tests for routing decisions

**Deliverable**: `compressor.compress(json)` returns compressed JSON

---

## Phase 3: CLI Tool (Days 5-6)

### 3.1 CLI Framework
- [ ] `src/bin/m2m.rs` - CLI entry point with clap
- [ ] `src/cli/mod.rs` - CLI module

### 3.2 Commands
- [ ] `src/cli/compress.rs` - `m2m compress` command
  - JSON input from argument, file, or stdin
  - Output to stdout or file
  - Stats display option
- [ ] `src/cli/decompress.rs` - `m2m decompress` command
- [ ] `src/cli/tokens.rs` - `m2m tokens` command
  - Model selection
  - File input support
- [ ] `src/cli/models.rs` - `m2m models` command
  - `list` subcommand
  - `info <model>` subcommand

**Deliverable**: Working CLI with `compress`, `decompress`, `tokens`, `models`

---

## Phase 4: HTTP Proxy (Days 7-9)

### 4.1 Configuration
- [ ] `src/config/mod.rs` - Config module
- [ ] `src/config/file.rs` - TOML config loading
- [ ] Environment variable support
- [ ] CLI argument parsing for proxy

### 4.2 Proxy Server
- [ ] `src/proxy/mod.rs` - Proxy module
- [ ] `src/proxy/state.rs` - Shared ProxyState
- [ ] `src/proxy/server.rs` - Axum router setup
- [ ] `src/proxy/handlers.rs` - Request handlers
  - `/v1/chat/completions` - Main handler
  - `/v1/models` - Models list
  - `/_m2m/health` - Health check
  - `/_m2m/stats` - Statistics
  - `/_m2m/compress` - Direct compression API

### 4.3 Protocol Negotiation
- [ ] Detect `X-M2M-Protocol` header
- [ ] Detect M2M format from content structure
- [ ] Auto-decompress M2M requests
- [ ] Optimize standard requests

### 4.4 Streaming Support
- [ ] SSE passthrough for `stream: true`
- [ ] Proper header handling
- [ ] Chunked transfer

### 4.5 Stats Tracking
- [ ] `src/proxy/stats.rs` - Statistics struct
- [ ] Request counting
- [ ] Token tracking
- [ ] Latency measurement

**Deliverable**: `m2m proxy --target https://api.openai.com` works with OpenAI SDK

---

## Phase 5: Testing & Polish (Days 10-11)

### 5.1 Unit Tests
- [ ] Compression round-trip tests
- [ ] Token counting accuracy tests
- [ ] Model registry tests
- [ ] Router decision tests

### 5.2 Integration Tests
- [ ] Proxy with mock upstream
- [ ] Streaming tests
- [ ] Protocol negotiation tests
- [ ] Error handling tests

### 5.3 Benchmarks
- [ ] `benches/compression.rs` - Compression benchmarks
- [ ] Token counting benchmarks
- [ ] End-to-end latency benchmarks

### 5.4 Documentation
- [ ] Inline documentation (rustdoc)
- [ ] Example code
- [ ] API reference

**Deliverable**: `cargo test` passes, benchmarks show <1ms compression

---

## Phase 6: Release (Day 12)

### 6.1 Build & Package
- [ ] Release build optimization
- [ ] Binary size verification (<10MB)
- [ ] Cross-compilation (Linux, macOS, Windows)

### 6.2 CI/CD
- [ ] GitHub Actions workflow
- [ ] Automated tests
- [ ] Release artifact upload

### 6.3 Distribution
- [ ] GitHub release
- [ ] crates.io publish
- [ ] Docker image

**Deliverable**: Released v0.1.0

---

## File Checklist

```
rust/m2m-core/
├── Cargo.toml                    [x]
├── README.md                     [x]
├── docs/
│   ├── PRD.md                    [x]
│   ├── TECHNICAL_DESIGN.md       [x]
│   └── IMPLEMENTATION_ROADMAP.md [x]
├── src/
│   ├── lib.rs                    [ ]
│   ├── error.rs                  [ ]
│   ├── models/
│   │   ├── mod.rs                [ ]
│   │   ├── card.rs               [ ]
│   │   ├── embedded.rs           [ ]
│   │   └── registry.rs           [ ]
│   ├── tokenizer/
│   │   ├── mod.rs                [ ]
│   │   └── counter.rs            [ ]
│   ├── compress/
│   │   ├── mod.rs                [ ]
│   │   ├── tables.rs             [ ]
│   │   ├── structural.rs         [ ]
│   │   └── router.rs             [ ]
│   ├── config/
│   │   ├── mod.rs                [ ]
│   │   └── file.rs               [ ]
│   ├── cli/
│   │   ├── mod.rs                [ ]
│   │   ├── compress.rs           [ ]
│   │   ├── decompress.rs         [ ]
│   │   ├── tokens.rs             [ ]
│   │   └── models.rs             [ ]
│   ├── proxy/
│   │   ├── mod.rs                [ ]
│   │   ├── state.rs              [ ]
│   │   ├── server.rs             [ ]
│   │   ├── handlers.rs           [ ]
│   │   └── stats.rs              [ ]
│   └── bin/
│       └── m2m.rs                [ ]
├── tests/
│   ├── compression_test.rs       [ ]
│   ├── tokenizer_test.rs         [ ]
│   └── integration_test.rs       [ ]
└── benches/
    └── compression.rs            [ ]
```

---

## Success Criteria

### Performance
- [ ] Compression: < 1ms (p99)
- [ ] Token counting: < 0.5ms (p99)
- [ ] Proxy overhead: < 2ms (p99)
- [ ] Memory: < 50MB steady state
- [ ] Binary: < 10MB

### Functionality
- [ ] All CLI commands working
- [ ] Proxy works with OpenAI Python SDK
- [ ] Proxy works with streaming responses
- [ ] M2M client detection and decompression
- [ ] Stats endpoint returning accurate data

### Quality
- [ ] All tests passing
- [ ] No clippy warnings
- [ ] Documentation complete
- [ ] Benchmarks published

---

## Timeline Summary

| Phase | Duration | Cumulative |
|-------|----------|------------|
| 1. Core Foundation | 2 days | Day 2 |
| 2. Compression Engine | 2 days | Day 4 |
| 3. CLI Tool | 2 days | Day 6 |
| 4. HTTP Proxy | 3 days | Day 9 |
| 5. Testing & Polish | 2 days | Day 11 |
| 6. Release | 1 day | Day 12 |

**Total: ~12 working days (~2.5 weeks)**

---

## Dependencies Risk Assessment

| Dependency | Risk | Mitigation |
|------------|------|------------|
| tiktoken-rs | Low | Well-maintained, used by many |
| axum | Low | Major web framework |
| reqwest | Low | Standard HTTP client |
| phf | Low | Stable, used in production |

## Open Questions

1. **Caching**: Should we add request caching for identical prompts?
   - Decision: Defer to v2.1 (MVP focuses on compression)

2. **Multi-upstream**: Support routing to different providers?
   - Decision: Defer to v2.1 (single upstream for MVP)

3. **Response compression**: Compress responses for M2M clients?
   - Decision: Defer to v2.1 (focus on request side first)

4. **Metrics export**: Prometheus format?
   - Decision: Defer to v2.1 (JSON stats endpoint for MVP)
