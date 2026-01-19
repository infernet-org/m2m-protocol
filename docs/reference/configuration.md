---
title: Configuration
description: Configuration options and environment variables
---

# Configuration Reference

## Overview

M2M Protocol can be configured via:
1. Configuration file (`~/.m2m/config.toml`)
2. Environment variables
3. Command-line arguments

Priority: CLI > Environment > Config File > Defaults

## Configuration File

Default location: `~/.m2m/config.toml`

### Complete Example

```toml
# M2M Protocol Configuration

[server]
# Address to listen on
listen = "127.0.0.1:3000"

# Request timeout in seconds
timeout = 30

[security]
# Enable security scanning
enabled = true

# Block unsafe content (vs just logging)
blocking = true

# Confidence threshold (0.0 - 1.0)
threshold = 0.8

[compression]
# Use ML model for algorithm routing
ml_routing = false

# Minimum size for Brotli (bytes)
brotli_threshold = 4096

# Prefer token compression for API payloads
prefer_token_for_api = true

[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# JSON format for structured logging
json = false
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `M2M_SERVER_PORT` | Server listen port | `3000` |
| `M2M_SERVER_HOST` | Server listen address | `127.0.0.1` |
| `M2M_SECURITY_ENABLED` | Enable security scanning | `true` |
| `M2M_SECURITY_BLOCKING` | Block unsafe content | `true` |
| `M2M_BLOCK_THRESHOLD` | Security confidence threshold | `0.8` |
| `M2M_LOG_LEVEL` | Logging level | `info` |
| `M2M_LOG_JSON` | JSON log format | `false` |
| `M2M_TIMEOUT` | Request timeout (seconds) | `30` |

## CLI Arguments

### Server Command

```bash
m2m server [OPTIONS]

Options:
  -p, --port <PORT>          Listen port [default: 3000]
  -h, --host <HOST>          Listen address [default: 127.0.0.1]
  --blocking                  Enable security blocking
  --threshold <FLOAT>        Security threshold [default: 0.8]
  --timeout <SECONDS>        Request timeout [default: 30]
  --log-level <LEVEL>        Log level [default: info]
  --log-json                 JSON log format
```

### Compress Command

```bash
m2m compress [OPTIONS] <CONTENT>

Arguments:
  <CONTENT>                  Content to compress (or - for stdin)

Options:
  -a, --algorithm <ALG>      Algorithm (token, brotli, auto) [default: auto]
  -o, --output <FILE>        Output file (default: stdout)
```

### Decompress Command

```bash
m2m decompress [OPTIONS] <CONTENT>

Arguments:
  <CONTENT>                  Content to decompress (or - for stdin)

Options:
  -o, --output <FILE>        Output file (default: stdout)
```

### Scan Command

```bash
m2m scan [OPTIONS] <CONTENT>

Arguments:
  <CONTENT>                  Content to scan

Options:
  -t, --threshold <FLOAT>    Confidence threshold [default: 0.8]
  --json                     JSON output format
```

## Server Configuration Details

### Listen Address

```toml
[server]
listen = "127.0.0.1:3000"  # Local only
listen = "0.0.0.0:3000"    # All interfaces (caution!)
```

## Security Configuration

### Scanning Modes

| Mode | `enabled` | `blocking` | Behavior |
|------|-----------|------------|----------|
| Disabled | false | - | No scanning |
| Monitor | true | false | Scan and log, allow all |
| Blocking | true | true | Scan and reject threats |

### Threshold Tuning

| Threshold | False Positives | False Negatives |
|-----------|-----------------|-----------------|
| 0.5 | High | Low |
| 0.8 | Medium | Medium |
| 0.95 | Low | High |

## Compression Configuration

### Algorithm Selection

| Setting | Description |
|---------|-------------|
| `auto` | Automatically select best algorithm |
| `token` | Always use token compression |
| `brotli` | Always use Brotli compression |
| `none` | Disable compression |

### Size Thresholds

```toml
[compression]
# Minimum content size for compression (bytes)
min_size = 100

# Use Brotli above this size (bytes)
brotli_threshold = 4096

# Maximum content size (bytes)
max_size = 16777216
```

## Logging Configuration

### Log Levels

| Level | Description |
|-------|-------------|
| `trace` | Very detailed debugging |
| `debug` | Debugging information |
| `info` | Normal operation |
| `warn` | Warning conditions |
| `error` | Error conditions |

### JSON Logging

```toml
[logging]
json = true
```

Output:
```json
{"timestamp":"2026-01-17T12:00:00Z","level":"INFO","message":"Request compressed","algorithm":"token","ratio":0.66}
```
