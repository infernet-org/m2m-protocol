# M2M Proxy Server

The M2M Proxy is an OpenAI API-compatible reverse proxy that transparently applies M2M protocol compression to reduce bandwidth and costs for LLM API communication.

## Design Philosophy

The proxy is designed to work with **any OpenAI-compatible API endpoint**, not just OpenAI. This includes:

| Provider Type | Examples | Token Counting |
|---------------|----------|----------------|
| **OpenAI** | api.openai.com | Exact (tiktoken) |
| **Self-hosted OSS** | vLLM, Ollama, LocalAI, TGI | Exact (Llama BPE) |
| **Cloud Providers** | OpenRouter, Together.ai, Anyscale | Exact or Heuristic |
| **Enterprise** | Azure OpenAI, AWS Bedrock | Exact (tiktoken) |

### Why OpenAI-Compatible?

The OpenAI chat completion API has become the de facto standard for LLM inference. Most inference servers (vLLM, Ollama, LocalAI, Text Generation Inference) expose an OpenAI-compatible endpoint because:

1. **Ecosystem compatibility** - Tools, SDKs, and applications expect this interface
2. **Zero migration cost** - Switch between providers by changing the base URL
3. **Standardized schema** - Predictable request/response structure enables optimization

## Architecture

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Application   │         │   M2M Proxy     │         │  LLM Provider   │
│                 │         │                 │         │                 │
│  POST /v1/chat  │────────>│  Compress req   │────────>│  vLLM/Ollama/   │
│  /completions   │         │  Security scan  │         │  OpenAI/etc.    │
│                 │<────────│  Decompress res │<────────│                 │
└─────────────────┘         └─────────────────┘         └─────────────────┘
```

### Request Flow

1. **Receive** - Application sends standard OpenAI-format request to proxy
2. **Security Scan** - Check for prompt injection, jailbreaks (optional)
3. **Compress** - Apply M2M compression to reduce payload size
4. **Forward** - Send compressed request to upstream LLM provider
5. **Stream/Buffer** - Handle streaming SSE responses
6. **Decompress** - Expand response back to standard format
7. **Return** - Send unmodified OpenAI response to application

### Compression Benefits

| Scenario | Without M2M | With M2M | Savings |
|----------|-------------|----------|---------|
| Chat request | 2.4 KB | 1.7 KB | ~30% |
| Long conversation | 48 KB | 31 KB | ~35% |
| Tool calls | 8.2 KB | 4.9 KB | ~40% |

## Usage

### Starting the Proxy

```bash
# Basic usage - forwards to local Ollama
m2m proxy --port 8080 --upstream http://localhost:11434/v1

# Forward to vLLM
m2m proxy --port 8080 --upstream http://vllm-server:8000/v1

# Forward to OpenAI with API key
m2m proxy --port 8080 --upstream https://api.openai.com/v1 --api-key $OPENAI_API_KEY

# With security scanning enabled
m2m proxy --port 8080 --upstream http://localhost:11434/v1 --security --threshold 0.8
```

### Transport Options

The proxy supports multiple transport protocols:

```bash
# TCP only (default)
m2m proxy --port 8080 --upstream http://localhost:11434/v1 --transport tcp

# QUIC/HTTP3 only (requires TLS)
m2m proxy --port 8443 --upstream http://localhost:11434/v1 --transport quic

# Both TCP and QUIC simultaneously
m2m proxy --port 8080 --upstream http://localhost:11434/v1 --transport both --quic-port 8443

# QUIC with custom certificates (production)
m2m proxy --port 8443 --upstream http://localhost:11434/v1 --transport quic \
  --cert /path/to/cert.pem --key /path/to/key.pem
```

#### QUIC Benefits

| Feature | Benefit |
|---------|---------|
| **0-RTT Connection** | Reduced latency for returning connections |
| **No Head-of-Line Blocking** | Multiplexed streams don't block each other |
| **Connection Migration** | Survives network changes (WiFi → cellular) |
| **Built-in TLS 1.3** | Secure by default, no separate TLS handshake |
| **BBR Congestion Control** | Better throughput on lossy networks |

### Configuration

```toml
# ~/.m2m/config.toml

[proxy]
listen = "127.0.0.1:8080"
upstream = "http://localhost:11434/v1"
api_key = ""  # Optional: forwarded to upstream

[proxy.compression]
requests = true
responses = true

[proxy.security]
enabled = true
blocking = true
threshold = 0.8
```

### Using with Applications

Point your application to the proxy instead of the upstream:

```python
# Before: Direct to Ollama
client = OpenAI(base_url="http://localhost:11434/v1")

# After: Through M2M proxy
client = OpenAI(base_url="http://localhost:8080/v1")
```

```bash
# curl example
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3.2", "messages": [{"role": "user", "content": "Hello"}]}'
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/stats` | GET | Compression statistics |
| `/v1/chat/completions` | POST | OpenAI-compatible chat endpoint |
| `/v1/compress` | POST | Manual compression (debugging) |
| `/v1/decompress` | POST | Manual decompression (debugging) |

### Stats Response

```json
{
  "requests_total": 1542,
  "bytes_in": 3847291,
  "bytes_out": 2693104,
  "compression_ratio": 0.70,
  "avg_latency_ms": 0.8,
  "p99_latency_ms": 2.1
}
```

## Streaming Support

The proxy fully supports Server-Sent Events (SSE) streaming:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3.2", "messages": [...], "stream": true}'
```

SSE chunks are compressed individually using the streaming codec, which:
- Abbreviates JSON keys in each chunk
- Accumulates content for final statistics
- Maintains SSE format compatibility

## Token Counting Accuracy

| Provider | Tokenizer | Accuracy |
|----------|-----------|----------|
| OpenAI GPT-4o/o1/o3 | tiktoken (o200k_base) | Exact |
| OpenAI GPT-4/3.5 | tiktoken (cl100k_base) | Exact |
| Llama 3.x | Llama BPE | Exact |
| Mistral/Mixtral | Llama BPE | Exact |
| DeepSeek | Heuristic | ~95% |
| Qwen | Heuristic | ~95% |
| Claude* | Heuristic | ~90% |
| Gemini* | Heuristic | ~90% |

*Closed tokenizers - compression still works, token stats are estimates.

## Self-Hosted Model Example

### With Ollama

```bash
# Start Ollama with Llama 3.2
ollama run llama3.2

# Start M2M proxy
m2m proxy --port 8080 --upstream http://localhost:11434/v1

# Use normally
curl http://localhost:8080/v1/chat/completions \
  -d '{"model": "llama3.2", "messages": [{"role": "user", "content": "Hello"}]}'
```

### With vLLM

```bash
# Start vLLM
python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-3.1-8B-Instruct \
  --port 8000

# Start M2M proxy
m2m proxy --port 8080 --upstream http://localhost:8000/v1

# Use normally
curl http://localhost:8080/v1/chat/completions \
  -d '{"model": "meta-llama/Llama-3.1-8B-Instruct", "messages": [...]}'
```

## Security Scanning

When enabled, the proxy scans all incoming requests for:

- **Prompt injection** - "ignore previous instructions", role confusion
- **Jailbreaks** - DAN mode, developer mode, bypass attempts
- **Malformed input** - Null bytes, unicode exploits, excessive nesting
- **Data exfiltration** - Environment variable access, file path probing

```bash
# Enable blocking mode (rejects threats)
m2m proxy --port 8080 --upstream ... --security --threshold 0.8

# Enable monitoring mode (logs but doesn't block)
m2m proxy --port 8080 --upstream ... --security --threshold 0.0
```

## Performance

| Metric | Value |
|--------|-------|
| Added latency | < 2ms |
| Memory overhead | < 20MB |
| Max throughput | 10k+ req/s |
| Compression ratio | 25-40% savings |

The proxy adds minimal overhead while providing significant bandwidth savings, especially valuable for:
- High-volume inference workloads
- Edge deployments with limited bandwidth
- Cost optimization on metered connections
