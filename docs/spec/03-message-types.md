# 4. Message Types

## 4.1 Overview

M2M Protocol defines seven message types for session management and data exchange.

| Type | Direction | Purpose |
|------|-----------|---------|
| HELLO | Client → Server | Initiate session with capabilities |
| ACCEPT | Server → Client | Confirm session establishment |
| REJECT | Server → Client | Deny session with reason |
| DATA | Bidirectional | Exchange compressed payloads |
| PING | Bidirectional | Keep-alive request |
| PONG | Bidirectional | Keep-alive response |
| CLOSE | Bidirectional | Terminate session |

## 4.2 Message Envelope

All session messages share a common envelope structure:

```json
{
  "type": "<MESSAGE_TYPE>",
  "session_id": "<string|null>",
  "timestamp": <unix_millis>,
  "payload": <type-specific>
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | REQUIRED | Message type identifier |
| `session_id` | string | CONDITIONAL | Session ID (null for HELLO) |
| `timestamp` | integer | REQUIRED | Unix timestamp in milliseconds |
| `payload` | object | REQUIRED | Type-specific payload |

## 4.3 Control Messages

### 4.3.1 HELLO

Initiates a session with capability advertisement.

**Direction:** Client → Server

**Payload:**
```json
{
  "version": "1.0",
  "algorithms": ["TOKEN", "BROTLI"],
  "security_scanning": true,
  "max_payload_size": 10485760,
  "supports_streaming": true,
  "extensions": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | REQUIRED | Protocol version (e.g., "1.0") |
| `algorithms` | array | REQUIRED | Supported compression algorithms |
| `security_scanning` | boolean | OPTIONAL | Security scanning capability |
| `max_payload_size` | integer | OPTIONAL | Maximum payload size in bytes |
| `supports_streaming` | boolean | OPTIONAL | SSE streaming support |
| `extensions` | object | OPTIONAL | Extension capabilities |

**Example:**
```json
{
  "type": "HELLO",
  "session_id": null,
  "timestamp": 1705520400000,
  "payload": {
    "version": "1.0",
    "algorithms": ["TOKEN", "BROTLI"],
    "security_scanning": true
  }
}
```

**Processing Rules:**
- Server MUST respond with ACCEPT or REJECT within 30 seconds
- Client MUST NOT send other messages before receiving response
- Client SHOULD include all supported algorithms

### 4.3.2 ACCEPT

Confirms session establishment with negotiated capabilities.

**Direction:** Server → Client

**Payload:**
```json
{
  "version": "1.0",
  "algorithms": ["TOKEN"],
  "security_scanning": true,
  "session_timeout_ms": 300000,
  "extensions": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | REQUIRED | Negotiated protocol version |
| `algorithms` | array | REQUIRED | Supported algorithms (intersection) |
| `security_scanning` | boolean | REQUIRED | Security scanning enabled |
| `session_timeout_ms` | integer | REQUIRED | Session timeout in milliseconds |
| `extensions` | object | OPTIONAL | Negotiated extensions |

**Example:**
```json
{
  "type": "ACCEPT",
  "session_id": "sess_abc123",
  "timestamp": 1705520400100,
  "payload": {
    "version": "1.0",
    "algorithms": ["TOKEN"],
    "security_scanning": true,
    "session_timeout_ms": 300000
  }
}
```

**Processing Rules:**
- Server MUST assign unique session_id
- Server MUST include only mutually supported algorithms
- Client MUST store session_id for subsequent messages

### 4.3.3 REJECT

Denies session establishment with reason.

**Direction:** Server → Client

**Payload:**
```json
{
  "code": "VERSION_MISMATCH",
  "message": "Protocol version 2.0 not supported"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `code` | string | REQUIRED | Rejection reason code |
| `message` | string | OPTIONAL | Human-readable explanation |

**Rejection Codes:**

| Code | Description |
|------|-------------|
| `VERSION_MISMATCH` | Unsupported protocol version |
| `NO_COMMON_ALGORITHM` | No mutually supported algorithms |
| `SECURITY_POLICY` | Security policy violation |
| `RATE_LIMITED` | Rate limit exceeded |
| `SERVER_BUSY` | Server at capacity |
| `UNKNOWN` | Unspecified reason |

**Example:**
```json
{
  "type": "REJECT",
  "session_id": null,
  "timestamp": 1705520400100,
  "payload": {
    "code": "NO_COMMON_ALGORITHM",
    "message": "Server requires TOKEN algorithm"
  }
}
```

## 4.4 Data Messages

### 4.4.1 DATA

Exchanges compressed payloads.

**Direction:** Bidirectional

**Payload:**
```json
{
  "algorithm": "TOKEN",
  "content": "#T1|{...}",
  "original_size": 1024,
  "security_status": {
    "scanned": true,
    "safe": true
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algorithm` | string | REQUIRED | Compression algorithm used |
| `content` | string | REQUIRED | Compressed data (wire format) |
| `original_size` | integer | OPTIONAL | Original size for verification |
| `security_status` | object | OPTIONAL | Security scan results |

**Security Status:**

| Field | Type | Description |
|-------|------|-------------|
| `scanned` | boolean | Whether content was scanned |
| `safe` | boolean | Whether content passed scanning |
| `threat_type` | string | Type of threat detected (if any) |
| `confidence` | number | Confidence score 0.0-1.0 |

**Example:**
```json
{
  "type": "DATA",
  "session_id": "sess_abc123",
  "timestamp": 1705520401000,
  "payload": {
    "algorithm": "TOKEN",
    "content": "#T1|{\"M\":\"4o\",\"m\":[{\"r\":\"u\",\"c\":\"Hello\"}]}",
    "original_size": 68,
    "security_status": {
      "scanned": true,
      "safe": true
    }
  }
}
```

## 4.5 Keep-Alive Messages

### 4.5.1 PING

Requests keep-alive acknowledgment.

**Direction:** Bidirectional

**Payload:** Empty object `{}`

**Example:**
```json
{
  "type": "PING",
  "session_id": "sess_abc123",
  "timestamp": 1705520500000,
  "payload": {}
}
```

**Processing Rules:**
- Receiver MUST respond with PONG within 10 seconds
- Sender SHOULD send PING every 60 seconds during idle periods
- Three consecutive missed PONGs SHOULD trigger session closure

### 4.5.2 PONG

Acknowledges keep-alive request.

**Direction:** Bidirectional

**Payload:** Empty object `{}`

**Example:**
```json
{
  "type": "PONG",
  "session_id": "sess_abc123",
  "timestamp": 1705520500050,
  "payload": {}
}
```

## 4.6 Termination Messages

### 4.6.1 CLOSE

Initiates graceful session termination.

**Direction:** Bidirectional

**Payload:**
```json
{
  "reason": "CLIENT_SHUTDOWN",
  "message": "Application closing"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | OPTIONAL | Closure reason code |
| `message` | string | OPTIONAL | Human-readable explanation |

**Closure Reasons:**

| Code | Description |
|------|-------------|
| `CLIENT_SHUTDOWN` | Client application closing |
| `SERVER_SHUTDOWN` | Server shutting down |
| `TIMEOUT` | Session timeout exceeded |
| `ERROR` | Unrecoverable error |
| `NORMAL` | Normal closure |

**Example:**
```json
{
  "type": "CLOSE",
  "session_id": "sess_abc123",
  "timestamp": 1705520600000,
  "payload": {
    "reason": "NORMAL"
  }
}
```

**Processing Rules:**
- Receiver MUST acknowledge by closing connection
- Receiver SHOULD NOT send further DATA messages
- Either endpoint MAY initiate CLOSE

## 4.7 Message Sequence

### 4.7.1 Successful Session

```
Client                              Server
   |                                   |
   |---------- HELLO ----------------->|
   |<--------- ACCEPT -----------------|
   |                                   |
   |========== DATA ==================>|
   |<========= DATA ===================|
   |                                   |
   |---------- PING ------------------>|
   |<--------- PONG -------------------|
   |                                   |
   |---------- CLOSE ----------------->|
   |                                   |
```

### 4.7.2 Rejected Session

```
Client                              Server
   |                                   |
   |---------- HELLO ----------------->|
   |<--------- REJECT -----------------|
   |                                   |
```

### 4.7.3 Stateless Mode

```
Client                              Server
   |                                   |
   |========== DATA (no session) =====>|
   |<========= DATA (no session) ======|
   |                                   |
```

In stateless mode, `session_id` is null and no HELLO/ACCEPT exchange occurs.
