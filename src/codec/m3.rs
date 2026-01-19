//! M3 Protocol: Schema-aware token compression for M2M communication.
//!
//! **DEPRECATED**: Use M2M codec instead. M3 does NOT provide 100% JSON fidelity.
//!
//! M3 eliminates JSON structural overhead by using positional encoding
//! with a known schema. Both M2M endpoints understand the schema, so
//! structure doesn't need to be transmitted.
//!
//! # Wire Format
//!
//! ```text
//! #M3|<schema:1><payload>
//!
//! Schema byte:
//!   0x01 = ChatCompletionRequest
//!   0x02 = ChatCompletionResponse  
//!   0x03 = ChatMessage (single)
//!
//! ChatCompletionRequest payload:
//!   [model_len:varint][model:utf8]      # Model identifier
//!   [flags:1]                            # Bitfield for optional params
//!   [num_messages:varint]                # Message count
//!   [messages...]                        # Sequential messages
//!   [params...]                          # Based on flags
//!
//! Message:
//!   [role:1]                             # 0=system, 1=user, 2=assistant, 3=tool
//!   [content_len:varint][content:utf8]   # Content (lossless)
//! ```
//!
//! # Token Savings
//!
//! JSON structural overhead is ~72% of tokens for typical LLM payloads.
//! M3 eliminates this overhead, achieving 50-70% token reduction.
//!
//! | Component | JSON Tokens | M3 Tokens | Savings |
//! |-----------|-------------|-----------|---------|
//! | `{"model":"gpt-4o",` | 6 | ~2 | 67% |
//! | `"messages":[` | 3 | 0 | 100% |
//! | `{"role":"user","content":"` | 7 | 1 | 86% |
//! | Content | N | N | 0% |
//! | `"}],"temperature":0.7}` | 8 | ~2 | 75% |

use std::io::{Cursor, Read};

use crate::error::{M2MError, Result};

/// M3 wire format prefix
pub const M3_PREFIX: &str = "#M3|";

/// Schema identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(clippy::enum_variant_names)] // Chat prefix is intentional for clarity
pub enum Schema {
    /// Chat completion request (messages, model, params)
    ChatCompletionRequest = 0x01,
    /// Chat completion response (choices, usage)
    ChatCompletionResponse = 0x02,
    /// Single chat message
    ChatMessage = 0x03,
}

impl Schema {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Schema::ChatCompletionRequest),
            0x02 => Some(Schema::ChatCompletionResponse),
            0x03 => Some(Schema::ChatMessage),
            _ => None,
        }
    }
}

/// Role identifiers (1 byte instead of 6-9 tokens)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    System = 0,
    User = 1,
    Assistant = 2,
    Tool = 3,
}

impl Role {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Role::System),
            1 => Some(Role::User),
            2 => Some(Role::Assistant),
            3 => Some(Role::Tool),
            _ => None,
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "system" => Some(Role::System),
            "user" => Some(Role::User),
            "assistant" => Some(Role::Assistant),
            "tool" => Some(Role::Tool),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

/// Flags for optional parameters (bitfield)
#[derive(Debug, Clone, Copy, Default)]
pub struct ParamFlags(u8);

impl ParamFlags {
    pub const HAS_TEMPERATURE: u8 = 0x01;
    pub const HAS_MAX_TOKENS: u8 = 0x02;
    pub const HAS_TOP_P: u8 = 0x04;
    pub const STREAM: u8 = 0x08;
    pub const HAS_STOP: u8 = 0x10;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    pub fn has(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    pub fn as_byte(&self) -> u8 {
        self.0
    }

    pub fn from_byte(b: u8) -> Self {
        Self(b)
    }
}

/// A single chat message in M3 format
#[derive(Debug, Clone)]
pub struct M3Message {
    /// Message role (system, user, assistant, tool)
    pub role: Role,
    /// Message content (lossless)
    pub content: String,
    /// Optional name (for tool messages)
    pub name: Option<String>,
}

/// Chat completion request in M3 format
#[derive(Debug, Clone, Default)]
pub struct M3ChatRequest {
    /// Model identifier
    pub model: String,
    /// Chat messages
    pub messages: Vec<M3Message>,
    /// Temperature (0.0-2.0, quantized to 0.01 precision)
    pub temperature: Option<f32>,
    /// Maximum tokens to generate
    pub max_tokens: Option<u32>,
    /// Top-p sampling
    pub top_p: Option<f32>,
    /// Enable streaming
    pub stream: bool,
    /// Stop sequences
    pub stop: Option<Vec<String>>,
}

/// M3 Codec for schema-aware compression
#[derive(Debug, Clone, Default)]
pub struct M3Codec;

impl M3Codec {
    /// Create a new M3 codec
    pub fn new() -> Self {
        Self
    }

    /// Encode a chat completion request to M3 wire format
    pub fn encode_request(&self, req: &M3ChatRequest) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);

        // Write prefix
        buf.extend_from_slice(M3_PREFIX.as_bytes());

        // Schema byte
        buf.push(Schema::ChatCompletionRequest as u8);

        // Model (length-prefixed)
        write_varint(&mut buf, req.model.len() as u64);
        buf.extend_from_slice(req.model.as_bytes());

        // Flags
        let mut flags = ParamFlags::new();
        if req.temperature.is_some() {
            flags.set(ParamFlags::HAS_TEMPERATURE);
        }
        if req.max_tokens.is_some() {
            flags.set(ParamFlags::HAS_MAX_TOKENS);
        }
        if req.top_p.is_some() {
            flags.set(ParamFlags::HAS_TOP_P);
        }
        if req.stream {
            flags.set(ParamFlags::STREAM);
        }
        if req.stop.is_some() {
            flags.set(ParamFlags::HAS_STOP);
        }
        buf.push(flags.as_byte());

        // Number of messages
        write_varint(&mut buf, req.messages.len() as u64);

        // Messages
        for msg in &req.messages {
            buf.push(msg.role as u8);
            write_varint(&mut buf, msg.content.len() as u64);
            buf.extend_from_slice(msg.content.as_bytes());
        }

        // Optional parameters
        if let Some(temp) = req.temperature {
            // Quantize to 0-100 range (0.01 precision)
            let quantized = (temp * 100.0).round() as u8;
            buf.push(quantized);
        }
        if let Some(max_tok) = req.max_tokens {
            write_varint(&mut buf, max_tok as u64);
        }
        if let Some(top_p) = req.top_p {
            let quantized = (top_p * 100.0).round() as u8;
            buf.push(quantized);
        }
        // Stop sequences (if any)
        if let Some(ref stops) = req.stop {
            write_varint(&mut buf, stops.len() as u64);
            for stop in stops {
                write_varint(&mut buf, stop.len() as u64);
                buf.extend_from_slice(stop.as_bytes());
            }
        }

        Ok(buf)
    }

    /// Decode M3 wire format to chat completion request
    pub fn decode_request(&self, data: &[u8]) -> Result<M3ChatRequest> {
        // Check prefix
        if !data.starts_with(M3_PREFIX.as_bytes()) {
            return Err(M2MError::Decompression("Invalid M3 prefix".to_string()));
        }

        let mut cursor = Cursor::new(&data[M3_PREFIX.len()..]);

        // Schema byte
        let mut schema_byte = [0u8; 1];
        cursor
            .read_exact(&mut schema_byte)
            .map_err(|e| M2MError::Decompression(e.to_string()))?;

        if Schema::from_byte(schema_byte[0]) != Some(Schema::ChatCompletionRequest) {
            return Err(M2MError::Decompression(format!(
                "Expected ChatCompletionRequest schema, got {:02x}",
                schema_byte[0]
            )));
        }

        // Model
        let model_len = read_varint(&mut cursor)? as usize;
        let mut model_bytes = vec![0u8; model_len];
        cursor
            .read_exact(&mut model_bytes)
            .map_err(|e| M2MError::Decompression(e.to_string()))?;
        let model =
            String::from_utf8(model_bytes).map_err(|e| M2MError::Decompression(e.to_string()))?;

        // Flags
        let mut flags_byte = [0u8; 1];
        cursor
            .read_exact(&mut flags_byte)
            .map_err(|e| M2MError::Decompression(e.to_string()))?;
        let flags = ParamFlags::from_byte(flags_byte[0]);

        // Number of messages
        let num_messages = read_varint(&mut cursor)? as usize;

        // Messages
        let mut messages = Vec::with_capacity(num_messages);
        for _ in 0..num_messages {
            let mut role_byte = [0u8; 1];
            cursor
                .read_exact(&mut role_byte)
                .map_err(|e| M2MError::Decompression(e.to_string()))?;
            let role = Role::from_byte(role_byte[0])
                .ok_or_else(|| M2MError::Decompression("Invalid role byte".to_string()))?;

            let content_len = read_varint(&mut cursor)? as usize;
            let mut content_bytes = vec![0u8; content_len];
            cursor
                .read_exact(&mut content_bytes)
                .map_err(|e| M2MError::Decompression(e.to_string()))?;
            let content = String::from_utf8(content_bytes)
                .map_err(|e| M2MError::Decompression(e.to_string()))?;

            messages.push(M3Message {
                role,
                content,
                name: None,
            });
        }

        // Optional parameters
        let temperature = if flags.has(ParamFlags::HAS_TEMPERATURE) {
            let mut temp_byte = [0u8; 1];
            cursor
                .read_exact(&mut temp_byte)
                .map_err(|e| M2MError::Decompression(e.to_string()))?;
            Some(temp_byte[0] as f32 / 100.0)
        } else {
            None
        };

        let max_tokens = if flags.has(ParamFlags::HAS_MAX_TOKENS) {
            Some(read_varint(&mut cursor)? as u32)
        } else {
            None
        };

        let top_p = if flags.has(ParamFlags::HAS_TOP_P) {
            let mut top_p_byte = [0u8; 1];
            cursor
                .read_exact(&mut top_p_byte)
                .map_err(|e| M2MError::Decompression(e.to_string()))?;
            Some(top_p_byte[0] as f32 / 100.0)
        } else {
            None
        };

        let stop = if flags.has(ParamFlags::HAS_STOP) {
            let num_stops = read_varint(&mut cursor)? as usize;
            let mut stops = Vec::with_capacity(num_stops);
            for _ in 0..num_stops {
                let stop_len = read_varint(&mut cursor)? as usize;
                let mut stop_bytes = vec![0u8; stop_len];
                cursor
                    .read_exact(&mut stop_bytes)
                    .map_err(|e| M2MError::Decompression(e.to_string()))?;
                let stop_str = String::from_utf8(stop_bytes)
                    .map_err(|e| M2MError::Decompression(e.to_string()))?;
                stops.push(stop_str);
            }
            Some(stops)
        } else {
            None
        };

        Ok(M3ChatRequest {
            model,
            messages,
            temperature,
            max_tokens,
            top_p,
            stream: flags.has(ParamFlags::STREAM),
            stop,
        })
    }

    /// Parse JSON to M3ChatRequest
    pub fn from_json(&self, json: &str) -> Result<M3ChatRequest> {
        let value: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| M2MError::Decompression(format!("Invalid JSON: {}", e)))?;

        let model = value
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let messages = value
            .get("messages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        let role_str = m.get("role").and_then(|r| r.as_str())?;
                        let role = Role::from_str(role_str)?;
                        let content = m
                            .get("content")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = m
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string());
                        Some(M3Message {
                            role,
                            content,
                            name,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let temperature = value
            .get("temperature")
            .and_then(|v| v.as_f64())
            .map(|f| f as f32);
        let max_tokens = value
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        let top_p = value
            .get("top_p")
            .and_then(|v| v.as_f64())
            .map(|f| f as f32);
        let stream = value
            .get("stream")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let stop = value.get("stop").and_then(|v| {
            if let Some(arr) = v.as_array() {
                Some(
                    arr.iter()
                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                        .collect(),
                )
            } else if let Some(s) = v.as_str() {
                Some(vec![s.to_string()])
            } else {
                None
            }
        });

        Ok(M3ChatRequest {
            model,
            messages,
            temperature,
            max_tokens,
            top_p,
            stream,
            stop,
        })
    }

    /// Convert M3ChatRequest back to JSON
    pub fn to_json(&self, req: &M3ChatRequest) -> String {
        let mut obj = serde_json::Map::new();

        obj.insert("model".to_string(), serde_json::json!(req.model));

        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|m| {
                let mut msg = serde_json::Map::new();
                msg.insert("role".to_string(), serde_json::json!(m.role.as_str()));
                msg.insert("content".to_string(), serde_json::json!(m.content));
                if let Some(ref name) = m.name {
                    msg.insert("name".to_string(), serde_json::json!(name));
                }
                serde_json::Value::Object(msg)
            })
            .collect();
        obj.insert("messages".to_string(), serde_json::Value::Array(messages));

        if let Some(temp) = req.temperature {
            obj.insert("temperature".to_string(), serde_json::json!(temp));
        }
        if let Some(max_tok) = req.max_tokens {
            obj.insert("max_tokens".to_string(), serde_json::json!(max_tok));
        }
        if let Some(top_p) = req.top_p {
            obj.insert("top_p".to_string(), serde_json::json!(top_p));
        }
        if req.stream {
            obj.insert("stream".to_string(), serde_json::json!(true));
        }
        if let Some(ref stop) = req.stop {
            obj.insert("stop".to_string(), serde_json::json!(stop));
        }

        serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
    }

    /// Compress JSON to M3 wire format
    ///
    /// **DEPRECATED**: Use M2M codec instead.
    #[deprecated(note = "Use M2M codec instead")]
    pub fn compress(&self, json: &str) -> Result<(String, usize, usize)> {
        let req = self.from_json(json)?;
        let encoded = self.encode_request(&req)?;

        // For wire format, we use base64 for the binary payload after prefix
        let wire = format!("{}", String::from_utf8_lossy(&encoded));

        Ok((wire, json.len(), encoded.len()))
    }

    /// Decompress M3 wire format to JSON
    pub fn decompress(&self, wire: &str) -> Result<String> {
        let req = self.decode_request(wire.as_bytes())?;
        Ok(self.to_json(&req))
    }

    /// Check if content is M3 format
    pub fn is_m3_format(content: &str) -> bool {
        content.starts_with(M3_PREFIX)
    }
}

// VarInt encoding (LEB128)
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;

    loop {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|e| M2MError::Decompression(format!("VarInt read error: {}", e)))?;

        result |= ((byte[0] & 0x7F) as u64) << shift;

        if byte[0] & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(M2MError::Decompression("VarInt overflow".to_string()));
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let codec = M3Codec::new();

        let req = M3ChatRequest {
            model: "gpt-4o".to_string(),
            messages: vec![
                M3Message {
                    role: Role::System,
                    content: "You are a helpful assistant.".to_string(),
                    name: None,
                },
                M3Message {
                    role: Role::User,
                    content: "Hello!".to_string(),
                    name: None,
                },
            ],
            temperature: Some(0.7),
            max_tokens: Some(1000),
            top_p: None,
            stream: false,
            stop: None,
        };

        let encoded = codec.encode_request(&req).unwrap();
        let decoded = codec.decode_request(&encoded).unwrap();

        assert_eq!(req.model, decoded.model);
        assert_eq!(req.messages.len(), decoded.messages.len());
        assert_eq!(req.messages[0].content, decoded.messages[0].content);
        assert_eq!(req.messages[1].content, decoded.messages[1].content);
        // Temperature is quantized, so check approximate equality
        assert!((req.temperature.unwrap() - decoded.temperature.unwrap()).abs() < 0.02);
        assert_eq!(req.max_tokens, decoded.max_tokens);
    }

    #[test]
    fn test_json_roundtrip() {
        let codec = M3Codec::new();

        let json = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"Hi!"}],"temperature":0.7,"max_tokens":100}"#;

        let req = codec.from_json(json).unwrap();
        let back_to_json = codec.to_json(&req);

        // Parse both and compare semantically
        let original: serde_json::Value = serde_json::from_str(json).unwrap();
        let recovered: serde_json::Value = serde_json::from_str(&back_to_json).unwrap();

        assert_eq!(original["model"], recovered["model"]);
        assert_eq!(
            original["messages"][0]["content"],
            recovered["messages"][0]["content"]
        );
        assert_eq!(
            original["messages"][1]["content"],
            recovered["messages"][1]["content"]
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_compression_savings() {
        let codec = M3Codec::new();

        let json = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is 2+2?"}],"temperature":0.7}"#;

        let (_, original_bytes, compressed_bytes) = codec.compress(json).unwrap();

        println!("Original JSON: {} bytes", json.len());
        println!("M3 encoded: {} bytes", compressed_bytes);
        println!(
            "Savings: {:.1}%",
            (1.0 - compressed_bytes as f64 / original_bytes as f64) * 100.0
        );

        // M3 should be significantly smaller than JSON
        assert!(
            compressed_bytes < original_bytes,
            "M3 should compress the data"
        );
    }

    #[test]
    fn test_varint_encoding() {
        let mut buf = Vec::new();

        // Small values
        write_varint(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        write_varint(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        buf.clear();
        write_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);

        // Roundtrip
        buf.clear();
        write_varint(&mut buf, 12345);
        let mut cursor = Cursor::new(&buf);
        let value = read_varint(&mut cursor).unwrap();
        assert_eq!(value, 12345);
    }
}
