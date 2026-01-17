---
title: Session Management
description: Session lifecycle and state machine
---

# 6. Session Management

## 6.1 Overview

M2M Protocol supports two operational modes:

| Mode | Session | Use Case |
|------|---------|----------|
| **Stateless** | No session | Single request/response |
| **Session** | HELLO/ACCEPT handshake | Multiple exchanges, capability negotiation |

## 6.2 Session State Machine

### 6.2.1 State Diagram

```
                         create_hello()
    ┌──────────┐ ─────────────────────────> ┌──────────────┐
    │ INITIAL  │                            │  HELLO_SENT  │
    └──────────┘                            └──────┬───────┘
         │                                         │
         │ process_hello()                         │ process_accept()
         │ (server side)                           │
         ▼                                         ▼
    ┌──────────────┐ <───────────────────── ┌──────────────┐
    │ ESTABLISHED  │                        │ ESTABLISHED  │
    └──────┬───────┘                        └──────────────┘
           │
           │ close() or timeout or error
           ▼
    ┌──────────┐     process_reject()      ┌──────────┐
    │ CLOSING  │ ────────────────────────> │  CLOSED  │
    └──────────┘                           └──────────┘
```

### 6.2.2 State Definitions

| State | Description | Valid Operations |
|-------|-------------|------------------|
| `INITIAL` | No session established | `create_hello()` (client), `process_hello()` (server) |
| `HELLO_SENT` | Client awaiting ACCEPT/REJECT | `process_accept()`, `process_reject()` |
| `ESTABLISHED` | Session active | `compress()`, `decompress()`, `ping()`, `close()` |
| `CLOSING` | Close initiated | None |
| `CLOSED` | Session terminated | None |

### 6.2.3 State Transitions

| From | Event | To | Action |
|------|-------|-----|--------|
| INITIAL | create_hello() | HELLO_SENT | Send HELLO message |
| INITIAL | process_hello() | ESTABLISHED | Generate session_id, send ACCEPT |
| HELLO_SENT | process_accept() | ESTABLISHED | Store capabilities |
| HELLO_SENT | process_reject() | CLOSED | Log rejection reason |
| HELLO_SENT | timeout (30s) | CLOSED | Connection timeout |
| ESTABLISHED | close() | CLOSING | Send CLOSE message |
| ESTABLISHED | receive CLOSE | CLOSED | Acknowledge closure |
| ESTABLISHED | timeout | CLOSED | Session expired |
| CLOSING | timeout (5s) | CLOSED | Force close |

## 6.3 Session Establishment

### 6.3.1 Client Procedure

```
1. Create Capabilities with supported features
2. Call create_hello() to generate HELLO message
3. Send HELLO to server
4. Wait for ACCEPT or REJECT (timeout: 30 seconds)
5. If ACCEPT: call process_accept(), transition to ESTABLISHED
6. If REJECT: call process_reject(), transition to CLOSED
```

### 6.3.2 Server Procedure

```
1. Receive HELLO message
2. Validate protocol version
3. Compute capability intersection
4. If compatible:
   a. Generate unique session_id
   b. Send ACCEPT with negotiated capabilities
   c. Transition to ESTABLISHED
5. If incompatible:
   a. Send REJECT with reason code
   b. Close connection
```

### 6.3.3 Capability Negotiation

Capabilities are negotiated as the intersection of client and server support:

```
Client capabilities:
  algorithms: [TOKEN, BROTLI, DICTIONARY]
  security_scanning: true
  max_payload_size: 16777216

Server capabilities:
  algorithms: [TOKEN, BROTLI]
  security_scanning: true
  max_payload_size: 10485760

Negotiated (intersection):
  algorithms: [TOKEN, BROTLI]
  security_scanning: true
  max_payload_size: 10485760  (minimum)
```

## 6.4 Session Parameters

### 6.4.1 Session ID

- Format: `sess_` prefix + 20 random alphanumeric characters
- Example: `sess_a1b2c3d4e5f6g7h8i9j0`
- MUST be unique per server
- MUST NOT be reused after session closure

### 6.4.2 Session Timeout

| Parameter | Default | Range |
|-----------|---------|-------|
| `session_timeout_ms` | 300000 (5 min) | 60000 - 3600000 |
| `ping_interval_ms` | 60000 (1 min) | 10000 - 300000 |
| `ping_timeout_ms` | 10000 (10 sec) | 5000 - 60000 |

### 6.4.3 Keep-Alive

Implementations SHOULD send PING messages during idle periods:

```
if time_since_last_message > ping_interval_ms:
    send(PING)
    await PONG with timeout ping_timeout_ms
```

Three consecutive missed PONGs SHOULD trigger session closure.

## 6.5 Data Exchange

### 6.5.1 Compression

In ESTABLISHED state, call `compress()` to create DATA message:

```rust
let data_msg = session.compress(content)?;
// data_msg contains:
// - Selected algorithm (from negotiated set)
// - Compressed content
// - Optional security status
```

### 6.5.2 Decompression

Receive DATA message and call `decompress()`:

```rust
let content = session.decompress(&data_msg)?;
// Returns original content
```

### 6.5.3 Algorithm Selection

Within a session, each DATA message MAY use any negotiated algorithm:

```
Session algorithms: [TOKEN, BROTLI]

DATA #1: algorithm=TOKEN  ✓
DATA #2: algorithm=BROTLI ✓
DATA #3: algorithm=TOKEN  ✓
```

## 6.6 Session Termination

### 6.6.1 Graceful Closure

```
1. Send CLOSE message with reason
2. Stop sending DATA messages
3. Wait for peer acknowledgment (timeout: 5 seconds)
4. Close connection
```

### 6.6.2 Forced Closure

- Timeout exceeded
- Protocol error
- Connection lost

### 6.6.3 Closure Reasons

| Reason | Description |
|--------|-------------|
| `NORMAL` | Clean shutdown |
| `TIMEOUT` | Session timeout |
| `ERROR` | Protocol error |
| `CLIENT_SHUTDOWN` | Client terminating |
| `SERVER_SHUTDOWN` | Server terminating |

## 6.7 Stateless Mode

### 6.7.1 Overview

Stateless mode bypasses session establishment for simple use cases.

### 6.7.2 Usage

```
# Direct compression without session
compressed = codec.compress(content, Algorithm::Token)
# Result: #T1|{...}

# Direct decompression
original = codec.decompress(compressed)
```

### 6.7.3 Limitations

- No capability negotiation
- No security scanning coordination
- No keep-alive
- No session-level statistics

## 6.8 Error Handling

### 6.8.1 Connection Errors

| Error | Recovery |
|-------|----------|
| Connection timeout | Retry with backoff |
| Connection refused | Check server status |
| TLS handshake failure | Verify certificates |

### 6.8.2 Protocol Errors

| Error | Recovery |
|-------|----------|
| Invalid message format | Close session, report error |
| Unknown message type | Ignore (log warning) |
| Invalid session_id | Close session |
| Decompression failure | Request retransmission |

### 6.8.3 Session Recovery

M2M Protocol does NOT support session resumption. On error:

1. Close current session
2. Establish new session with HELLO/ACCEPT
3. Retry failed operation

## 6.9 Concurrency

### 6.9.1 Single Session

Each connection SHOULD have exactly one session.

### 6.9.2 Message Ordering

Messages within a session MUST be processed in order.

### 6.9.3 Thread Safety

Session state modifications MUST be serialized.
