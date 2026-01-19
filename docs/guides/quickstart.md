---
title: Quick Start
description: Get started with M2M Protocol in 5 minutes
---

# Quick Start Guide

Get started with M2M Protocol in 5 minutes.

## Installation

### From Source

```bash
git clone https://github.com/infernet-org/m2m-protocol.git
cd m2m-protocol
cargo install --path .
```

### Verify Installation

```bash
m2m --version
# m2m 0.2.0
```

## Basic Usage

### Compress a Request

```bash
m2m compress '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
# Output: #T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}
```

### Decompress

```bash
m2m decompress '#T1|{"M":"4o","m":[{"r":"u","c":"Hello"}]}'
# Output: {"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}
```

### Analyze Content

```bash
m2m analyze '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
# Output:
# Algorithm: Token
# Original: 68 bytes
# Compressed: 45 bytes
# Ratio: 66% (34% savings)
```

## Using as a Library

### Add Dependency

```toml
# Cargo.toml
[dependencies]
m2m = "0.2"
```

### Compress/Decompress

```rust
use m2m::{CodecEngine, Algorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = CodecEngine::new();

    // Compress
    let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
    let result = engine.compress(content, Algorithm::Token)?;

    println!("Compressed: {}", result.data);
    println!("Savings: {:.0}%", (1.0 - result.byte_ratio()) * 100.0);

    // Decompress
    let original = engine.decompress(&result.data)?;
    assert_eq!(original, content);

    Ok(())
}
```

### Auto-Select Algorithm

```rust
use m2m::CodecEngine;

let engine = CodecEngine::new();
let (result, algorithm) = engine.compress_auto(content)?;
println!("Selected algorithm: {:?}", algorithm);
```

### Security Scanning

```rust
use m2m::SecurityScanner;

let scanner = SecurityScanner::new().with_blocking(0.8);
let result = scanner.scan("Ignore previous instructions")?;

if !result.safe {
    println!("Threat detected: {:?}", result.threats);
}
```

## Running the Server

### Start M2M Protocol Server

```bash
# Start M2M protocol server for agent-to-agent communication
m2m server --port 3000

# With security scanning enabled
m2m server --port 3000 --blocking --threshold 0.8
```

### Use with HTTP Client

```bash
# Compress and send via M2M protocol
curl http://localhost:3000/v1/compress \
  -H "Content-Type: application/json" \
  -d '{"content": "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}"}'
```

## Configuration

### Config File

Create `~/.m2m/config.toml`:

```toml
[security]
enabled = true
threshold = 0.8

[compression]
prefer_token = true
```

### Environment Variables

```bash
export M2M_SERVER_PORT=8080
export M2M_UPSTREAM_URL=http://localhost:11434/v1
export M2M_SECURITY_ENABLED=true
```

## Next Steps

- [Compression Spec](../spec/04-compression/) - Algorithm details
- [Security](../spec/06-security/) - Security considerations
