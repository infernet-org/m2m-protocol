---
title: Terminology
description: Definitions and RFC 2119 requirement keywords
---

# 2. Terminology

## 2.1 Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

### 2.1.1 Keyword Definitions

| Keyword | Meaning |
|---------|---------|
| **MUST** | Absolute requirement. Non-compliance breaks interoperability. |
| **MUST NOT** | Absolute prohibition. |
| **REQUIRED** | Equivalent to MUST. |
| **SHALL** | Equivalent to MUST. |
| **SHALL NOT** | Equivalent to MUST NOT. |
| **SHOULD** | Recommended. Valid reasons may exist to deviate. |
| **SHOULD NOT** | Not recommended. Acceptable in specific circumstances. |
| **RECOMMENDED** | Equivalent to SHOULD. |
| **MAY** | Truly optional. Implementations may include or omit. |
| **OPTIONAL** | Equivalent to MAY. |

## 2.2 Protocol Definitions

### 2.2.1 Endpoints

**Client**
: The endpoint initiating M2M protocol communication. In session mode, sends HELLO message.

**Server**
: The endpoint receiving M2M protocol communication. In session mode, responds with ACCEPT or REJECT.

**Endpoint**
: Either a client or server participating in M2M protocol.

**Proxy**
: An intermediary that transparently applies M2M compression between client and upstream server.

### 2.2.2 Messages

**Message**
: A single M2M protocol data unit, consisting of a prefix and payload.

**Prefix**
: The message identifier indicating compression algorithm (e.g., `#T1|`).

**Payload**
: The compressed or uncompressed content following the prefix.

**Wire Format**
: The byte sequence transmitted between endpoints.

### 2.2.3 Sessions

**Session**
: A stateful connection between client and server with negotiated parameters.

**Session ID**
: A unique identifier assigned by the server upon ACCEPT.

**Capabilities**
: The set of features and algorithms supported by an endpoint.

**Handshake**
: The HELLO/ACCEPT exchange that establishes a session.

### 2.2.4 Compression

**Algorithm**
: A specific compression method (Token, Brotli, Dictionary, None).

**Abbreviation**
: A shortened form of a key, value, or model name.

**Dictionary**
: The mapping table defining abbreviations.

**Compression Ratio**
: `compressed_size / original_size` (lower is better).

**Token**
: A discrete unit in LLM tokenization as defined by the target model's tokenizer.

### 2.2.5 Security

**Threat**
: A potential security concern detected in content.

**Scan**
: Analysis of content for security threats.

**Safe**
: Content that passes security scanning without detected threats.

**Blocking Mode**
: Security configuration that rejects unsafe content.

## 2.3 Abbreviations

| Abbreviation | Expansion |
|--------------|-----------|
| API | Application Programming Interface |
| BPE | Byte Pair Encoding |
| JSON | JavaScript Object Notation |
| LLM | Large Language Model |
| M2M | Machine-to-Machine |
| RFC | Request for Comments |
| SSE | Server-Sent Events |
| TLS | Transport Layer Security |
| UTF-8 | Unicode Transformation Format - 8-bit |

## 2.4 References

### 2.4.1 Normative References

**[RFC2119]**
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.

**[RFC8174]**
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.

**[RFC8259]**
: Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, DOI 10.17487/RFC8259, December 2017.

### 2.4.2 Informative References

**[TIKTOKEN]**
: OpenAI, "tiktoken: Fast BPE tokenizer", 2023, <https://github.com/openai/tiktoken>.

**[OPENAI-API]**
: OpenAI, "Chat Completions API", 2024, <https://platform.openai.com/docs/api-reference/chat>.
