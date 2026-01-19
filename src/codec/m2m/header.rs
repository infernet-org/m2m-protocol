//! Header structures for M2M wire format.
//!
//! Headers are extracted from JSON for routing without decompression.

#![allow(missing_docs)]

use super::flags::{Flags, RequestFlags, ResponseFlags};
use super::varint::{read_varint_slice, varint_size, write_varint_vec};
use crate::error::{M2MError, Result};

/// Fixed header size in bytes
pub const FIXED_HEADER_SIZE: usize = 20;

/// Reserved bytes in fixed header
pub const RESERVED_SIZE: usize = 12;

/// Schema type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Schema {
    /// Chat completion request
    Request = 0x01,
    /// Chat completion response
    Response = 0x02,
    /// Streaming chunk
    Stream = 0x03,
    /// Embedding request
    EmbeddingRequest = 0x04,
    /// Embedding response
    EmbeddingResponse = 0x05,
    /// Error response
    Error = 0x10,
    /// Custom/extension
    Custom = 0xFE,
    /// Unknown/passthrough
    Unknown = 0xFF,
}

impl Schema {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Schema::Request,
            0x02 => Schema::Response,
            0x03 => Schema::Stream,
            0x04 => Schema::EmbeddingRequest,
            0x05 => Schema::EmbeddingResponse,
            0x10 => Schema::Error,
            0xFE => Schema::Custom,
            _ => Schema::Unknown,
        }
    }

    pub fn as_byte(&self) -> u8 {
        *self as u8
    }

    pub fn is_request(&self) -> bool {
        matches!(self, Schema::Request | Schema::EmbeddingRequest)
    }

    pub fn is_response(&self) -> bool {
        matches!(
            self,
            Schema::Response | Schema::EmbeddingResponse | Schema::Error
        )
    }
}

/// Security mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SecurityMode {
    /// No security (default)
    #[default]
    None = 0x00,
    /// HMAC authentication (integrity only)
    Hmac = 0x01,
    /// AEAD encryption (confidentiality + integrity)
    Aead = 0x02,
}

impl SecurityMode {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => SecurityMode::Hmac,
            0x02 => SecurityMode::Aead,
            _ => SecurityMode::None,
        }
    }

    pub fn as_byte(&self) -> u8 {
        *self as u8
    }
}

/// Finish reason for responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FinishReason {
    /// Natural stop or hit stop sequence
    Stop = 0x00,
    /// Hit max_tokens limit
    Length = 0x01,
    /// Model wants to call tools
    ToolCalls = 0x02,
    /// Content was filtered
    ContentFilter = 0x03,
    /// Unknown reason
    Unknown = 0xFF,
}

impl FinishReason {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => FinishReason::Stop,
            0x01 => FinishReason::Length,
            0x02 => FinishReason::ToolCalls,
            0x03 => FinishReason::ContentFilter,
            _ => FinishReason::Unknown,
        }
    }

    /// Parse finish reason from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "stop" => FinishReason::Stop,
            "length" => FinishReason::Length,
            "tool_calls" => FinishReason::ToolCalls,
            "content_filter" => FinishReason::ContentFilter,
            _ => FinishReason::Unknown,
        }
    }

    pub fn as_byte(&self) -> u8 {
        *self as u8
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FinishReason::Stop => "stop",
            FinishReason::Length => "length",
            FinishReason::ToolCalls => "tool_calls",
            FinishReason::ContentFilter => "content_filter",
            FinishReason::Unknown => "unknown",
        }
    }
}

/// Role in a message (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    System = 0,
    User = 1,
    Assistant = 2,
    Tool = 3,
}

impl Role {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Role::System,
            1 => Role::User,
            2 => Role::Assistant,
            _ => Role::Tool,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "system" | "developer" => Some(Role::System),
            "user" => Some(Role::User),
            "assistant" => Some(Role::Assistant),
            "tool" => Some(Role::Tool),
            _ => None,
        }
    }

    pub fn as_bits(&self) -> u8 {
        *self as u8
    }
}

/// Fixed header (20 bytes)
#[derive(Debug, Clone)]
pub struct FixedHeader {
    /// Total header length (fixed + variable)
    pub header_len: u16,
    /// Schema type
    pub schema: Schema,
    /// Security mode
    pub security: SecurityMode,
    /// Flags (32 bits)
    pub flags: Flags,
    /// Reserved for future use (12 bytes, zeroed)
    pub reserved: [u8; RESERVED_SIZE],
}

impl FixedHeader {
    pub fn new(schema: Schema, security: SecurityMode, flags: Flags) -> Self {
        Self {
            header_len: FIXED_HEADER_SIZE as u16, // Will be updated when variable header is added
            schema,
            security,
            flags,
            reserved: [0u8; RESERVED_SIZE],
        }
    }

    /// Encode to bytes
    pub fn to_bytes(&self) -> [u8; FIXED_HEADER_SIZE] {
        let mut bytes = [0u8; FIXED_HEADER_SIZE];
        bytes[0..2].copy_from_slice(&self.header_len.to_le_bytes());
        bytes[2] = self.schema.as_byte();
        bytes[3] = self.security.as_byte();
        bytes[4..8].copy_from_slice(&self.flags.to_bytes());
        // bytes[8..20] remain zero (reserved)
        bytes
    }

    /// Decode from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_HEADER_SIZE {
            return Err(M2MError::Decompression(format!(
                "Fixed header too short: {} < {}",
                bytes.len(),
                FIXED_HEADER_SIZE
            )));
        }

        let header_len = u16::from_le_bytes([bytes[0], bytes[1]]);
        let schema = Schema::from_byte(bytes[2]);
        let security = SecurityMode::from_byte(bytes[3]);
        let flags = Flags::from_bytes(&[bytes[4], bytes[5], bytes[6], bytes[7]]);

        let mut reserved = [0u8; RESERVED_SIZE];
        reserved.copy_from_slice(&bytes[8..20]);

        Ok(Self {
            header_len,
            schema,
            security,
            flags,
            reserved,
        })
    }
}

/// Routing header (variable length, extracted from request JSON)
#[derive(Debug, Clone)]
pub struct RoutingHeader {
    /// Model identifier
    pub model: String,
    /// Number of messages
    pub msg_count: u32,
    /// Role sequence (2 bits per role, packed)
    pub roles: Vec<Role>,
    /// Total content bytes (hint for cost estimation)
    pub content_hint: u32,
    /// Max tokens (if specified)
    pub max_tokens: Option<u32>,
    /// Estimated cost in USD (IEEE 754 float)
    pub est_cost_usd: Option<f32>,
}

impl RoutingHeader {
    pub fn new(model: String) -> Self {
        Self {
            model,
            msg_count: 0,
            roles: Vec::new(),
            content_hint: 0,
            max_tokens: None,
            est_cost_usd: None,
        }
    }

    /// Extract routing header from JSON
    pub fn from_json(json: &serde_json::Value, request_flags: &RequestFlags) -> Result<Self> {
        let model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut msg_count = 0u32;
        let mut roles = Vec::new();
        let mut content_hint = 0u32;

        if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
            msg_count = messages.len() as u32;

            for msg in messages {
                // Extract role
                if let Some(role_str) = msg.get("role").and_then(|v| v.as_str()) {
                    if let Some(role) = Role::from_str(role_str) {
                        roles.push(role);
                    }
                }

                // Accumulate content size
                if let Some(content) = msg.get("content") {
                    if let Some(s) = content.as_str() {
                        content_hint += s.len() as u32;
                    } else if let Some(arr) = content.as_array() {
                        // Multimodal content
                        for part in arr {
                            if let Some(text) = part.get("text").and_then(|v| v.as_str()) {
                                content_hint += text.len() as u32;
                            }
                        }
                    }
                }
            }
        }

        let max_tokens = if request_flags.has(RequestFlags::HAS_MAX_TOKENS) {
            json.get("max_tokens")
                .or_else(|| json.get("max_completion_tokens"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
        } else {
            None
        };

        Ok(Self {
            model,
            msg_count,
            roles,
            content_hint,
            max_tokens,
            est_cost_usd: None, // Calculated separately
        })
    }

    /// Encode to bytes
    pub fn to_bytes(&self, request_flags: &RequestFlags) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // Model (length-prefixed)
        let model_bytes = self.model.as_bytes();
        buf.push(model_bytes.len() as u8);
        buf.extend_from_slice(model_bytes);

        // Message count
        write_varint_vec(&mut buf, self.msg_count as u64);

        // Roles (packed bits, 2 bits per role)
        let roles_bytes = pack_roles(&self.roles);
        buf.extend_from_slice(&roles_bytes);

        // Content hint
        write_varint_vec(&mut buf, self.content_hint as u64);

        // Max tokens (if flag set)
        if request_flags.has(RequestFlags::HAS_MAX_TOKENS) {
            if let Some(max_tokens) = self.max_tokens {
                write_varint_vec(&mut buf, max_tokens as u64);
            }
        }

        // Estimated cost (if present)
        if let Some(cost) = self.est_cost_usd {
            buf.extend_from_slice(&cost.to_le_bytes());
        }

        buf
    }

    /// Decode from bytes
    pub fn from_bytes(data: &[u8], request_flags: &RequestFlags) -> Result<(Self, usize)> {
        let mut pos = 0;

        // Model
        if pos >= data.len() {
            return Err(M2MError::Decompression("Missing model length".to_string()));
        }
        let model_len = data[pos] as usize;
        pos += 1;

        if pos + model_len > data.len() {
            return Err(M2MError::Decompression("Model truncated".to_string()));
        }
        let model = String::from_utf8(data[pos..pos + model_len].to_vec())
            .map_err(|e| M2MError::Decompression(format!("Invalid model UTF-8: {}", e)))?;
        pos += model_len;

        // Message count
        let (msg_count, consumed) = read_varint_slice(&data[pos..])?;
        pos += consumed;
        let msg_count = msg_count as u32;

        // Roles
        let roles_byte_count = (msg_count as usize * 2 + 7) / 8;
        if pos + roles_byte_count > data.len() {
            return Err(M2MError::Decompression("Roles truncated".to_string()));
        }
        let roles = unpack_roles(&data[pos..pos + roles_byte_count], msg_count as usize);
        pos += roles_byte_count;

        // Content hint
        let (content_hint, consumed) = read_varint_slice(&data[pos..])?;
        pos += consumed;
        let content_hint = content_hint as u32;

        // Max tokens (if flag set)
        let max_tokens = if request_flags.has(RequestFlags::HAS_MAX_TOKENS) {
            let (max, consumed) = read_varint_slice(&data[pos..])?;
            pos += consumed;
            Some(max as u32)
        } else {
            None
        };

        // Estimated cost (if present, 4 bytes)
        let est_cost_usd = if pos + 4 <= data.len() {
            let cost_bytes: [u8; 4] = data[pos..pos + 4].try_into().unwrap();
            pos += 4;
            Some(f32::from_le_bytes(cost_bytes))
        } else {
            None
        };

        Ok((
            Self {
                model,
                msg_count,
                roles,
                content_hint,
                max_tokens,
                est_cost_usd,
            },
            pos,
        ))
    }

    /// Calculate the encoded size
    pub fn encoded_size(&self, request_flags: &RequestFlags) -> usize {
        let mut size = 0;
        size += 1 + self.model.len(); // model length + model
        size += varint_size(self.msg_count as u64); // msg_count
        size += (self.roles.len() * 2 + 7) / 8; // packed roles
        size += varint_size(self.content_hint as u64); // content_hint

        if request_flags.has(RequestFlags::HAS_MAX_TOKENS) {
            if let Some(max_tokens) = self.max_tokens {
                size += varint_size(max_tokens as u64);
            }
        }

        if self.est_cost_usd.is_some() {
            size += 4;
        }

        size
    }
}

/// Response header (variable length)
#[derive(Debug, Clone)]
pub struct ResponseHeader {
    /// Response ID (e.g., "chatcmpl-xxx")
    pub id: String,
    /// Model used
    pub model: String,
    /// Finish reason
    pub finish_reason: FinishReason,
    /// Prompt tokens
    pub prompt_tokens: u32,
    /// Completion tokens
    pub completion_tokens: u32,
    /// Cached tokens (if applicable)
    pub cached_tokens: Option<u32>,
    /// Reasoning tokens (o-series)
    pub reasoning_tokens: Option<u32>,
    /// Estimated cost in USD
    pub est_cost_usd: Option<f32>,
}

impl ResponseHeader {
    /// Extract response header from JSON
    pub fn from_json(json: &serde_json::Value, response_flags: &ResponseFlags) -> Result<Self> {
        let id = json
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let model = json
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let finish_reason = json
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("finish_reason"))
            .and_then(|v| v.as_str())
            .map(FinishReason::from_str)
            .unwrap_or(FinishReason::Unknown);

        let usage = json.get("usage");

        let prompt_tokens = usage
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let completion_tokens = usage
            .and_then(|u| u.get("completion_tokens"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let cached_tokens = if response_flags.has(ResponseFlags::HAS_CACHED_TOKENS) {
            usage
                .and_then(|u| u.get("prompt_tokens_details"))
                .and_then(|d| d.get("cached_tokens"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
        } else {
            None
        };

        let reasoning_tokens = if response_flags.has(ResponseFlags::HAS_REASONING_TOKENS) {
            usage
                .and_then(|u| u.get("completion_tokens_details"))
                .and_then(|d| d.get("reasoning_tokens"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
        } else {
            None
        };

        Ok(Self {
            id,
            model,
            finish_reason,
            prompt_tokens,
            completion_tokens,
            cached_tokens,
            reasoning_tokens,
            est_cost_usd: None, // Calculated separately
        })
    }

    /// Encode to bytes
    pub fn to_bytes(&self, response_flags: &ResponseFlags) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);

        // ID (length-prefixed)
        let id_bytes = self.id.as_bytes();
        buf.push(id_bytes.len() as u8);
        buf.extend_from_slice(id_bytes);

        // Model (length-prefixed)
        let model_bytes = self.model.as_bytes();
        buf.push(model_bytes.len() as u8);
        buf.extend_from_slice(model_bytes);

        // Finish reason
        buf.push(self.finish_reason.as_byte());

        // Token counts
        write_varint_vec(&mut buf, self.prompt_tokens as u64);
        write_varint_vec(&mut buf, self.completion_tokens as u64);

        // Cached tokens (if flag set)
        if response_flags.has(ResponseFlags::HAS_CACHED_TOKENS) {
            write_varint_vec(&mut buf, self.cached_tokens.unwrap_or(0) as u64);
        }

        // Reasoning tokens (if flag set)
        if response_flags.has(ResponseFlags::HAS_REASONING_TOKENS) {
            write_varint_vec(&mut buf, self.reasoning_tokens.unwrap_or(0) as u64);
        }

        // Estimated cost (if flag set)
        if response_flags.has(ResponseFlags::HAS_COST_ESTIMATE) {
            if let Some(cost) = self.est_cost_usd {
                buf.extend_from_slice(&cost.to_le_bytes());
            }
        }

        buf
    }

    /// Decode from bytes
    pub fn from_bytes(data: &[u8], response_flags: &ResponseFlags) -> Result<(Self, usize)> {
        let mut pos = 0;

        // ID
        if pos >= data.len() {
            return Err(M2MError::Decompression("Missing ID length".to_string()));
        }
        let id_len = data[pos] as usize;
        pos += 1;
        if pos + id_len > data.len() {
            return Err(M2MError::Decompression("ID truncated".to_string()));
        }
        let id = String::from_utf8(data[pos..pos + id_len].to_vec())
            .map_err(|e| M2MError::Decompression(format!("Invalid ID UTF-8: {}", e)))?;
        pos += id_len;

        // Model
        if pos >= data.len() {
            return Err(M2MError::Decompression("Missing model length".to_string()));
        }
        let model_len = data[pos] as usize;
        pos += 1;
        if pos + model_len > data.len() {
            return Err(M2MError::Decompression("Model truncated".to_string()));
        }
        let model = String::from_utf8(data[pos..pos + model_len].to_vec())
            .map_err(|e| M2MError::Decompression(format!("Invalid model UTF-8: {}", e)))?;
        pos += model_len;

        // Finish reason
        if pos >= data.len() {
            return Err(M2MError::Decompression("Missing finish reason".to_string()));
        }
        let finish_reason = FinishReason::from_byte(data[pos]);
        pos += 1;

        // Token counts
        let (prompt_tokens, consumed) = read_varint_slice(&data[pos..])?;
        pos += consumed;
        let prompt_tokens = prompt_tokens as u32;

        let (completion_tokens, consumed) = read_varint_slice(&data[pos..])?;
        pos += consumed;
        let completion_tokens = completion_tokens as u32;

        // Cached tokens
        let cached_tokens = if response_flags.has(ResponseFlags::HAS_CACHED_TOKENS) {
            let (val, consumed) = read_varint_slice(&data[pos..])?;
            pos += consumed;
            Some(val as u32)
        } else {
            None
        };

        // Reasoning tokens
        let reasoning_tokens = if response_flags.has(ResponseFlags::HAS_REASONING_TOKENS) {
            let (val, consumed) = read_varint_slice(&data[pos..])?;
            pos += consumed;
            Some(val as u32)
        } else {
            None
        };

        // Estimated cost
        let est_cost_usd =
            if response_flags.has(ResponseFlags::HAS_COST_ESTIMATE) && pos + 4 <= data.len() {
                let cost_bytes: [u8; 4] = data[pos..pos + 4].try_into().unwrap();
                pos += 4;
                Some(f32::from_le_bytes(cost_bytes))
            } else {
                None
            };

        Ok((
            Self {
                id,
                model,
                finish_reason,
                prompt_tokens,
                completion_tokens,
                cached_tokens,
                reasoning_tokens,
                est_cost_usd,
            },
            pos,
        ))
    }
}

/// Pack roles into bytes (2 bits per role)
fn pack_roles(roles: &[Role]) -> Vec<u8> {
    let byte_count = (roles.len() * 2 + 7) / 8;
    let mut bytes = vec![0u8; byte_count];

    for (i, role) in roles.iter().enumerate() {
        let byte_idx = (i * 2) / 8;
        let bit_offset = (i * 2) % 8;
        bytes[byte_idx] |= role.as_bits() << bit_offset;
    }

    bytes
}

/// Unpack roles from bytes
fn unpack_roles(bytes: &[u8], count: usize) -> Vec<Role> {
    let mut roles = Vec::with_capacity(count);

    for i in 0..count {
        let byte_idx = (i * 2) / 8;
        let bit_offset = (i * 2) % 8;
        if byte_idx < bytes.len() {
            let bits = (bytes[byte_idx] >> bit_offset) & 0x03;
            roles.push(Role::from_bits(bits));
        }
    }

    roles
}

/// Detect request flags from JSON
pub fn detect_request_flags(json: &serde_json::Value) -> RequestFlags {
    let mut flags = RequestFlags::new();

    // Check messages for system prompt
    if let Some(messages) = json.get("messages").and_then(|v| v.as_array()) {
        for msg in messages {
            if let Some(role) = msg.get("role").and_then(|v| v.as_str()) {
                if role == "system" || role == "developer" {
                    flags.set(RequestFlags::HAS_SYSTEM_PROMPT);
                }
            }
            // Check for images in content
            if let Some(content) = msg.get("content").and_then(|v| v.as_array()) {
                for part in content {
                    if part.get("type").and_then(|v| v.as_str()) == Some("image_url") {
                        flags.set(RequestFlags::HAS_IMAGES);
                    }
                }
            }
        }
    }

    // Direct field checks
    if json.get("tools").is_some() || json.get("functions").is_some() {
        flags.set(RequestFlags::HAS_TOOLS);
    }
    if json.get("tool_choice").is_some() || json.get("function_call").is_some() {
        flags.set(RequestFlags::HAS_TOOL_CHOICE);
    }
    if json.get("stream").and_then(|v| v.as_bool()) == Some(true) {
        flags.set(RequestFlags::STREAM_REQUESTED);
    }
    if json.get("response_format").is_some() {
        flags.set(RequestFlags::HAS_RESPONSE_FORMAT);
    }
    if json.get("max_tokens").is_some() || json.get("max_completion_tokens").is_some() {
        flags.set(RequestFlags::HAS_MAX_TOKENS);
    }
    if json.get("reasoning_effort").is_some() {
        flags.set(RequestFlags::HAS_REASONING_EFFORT);
    }
    if json.get("service_tier").is_some() {
        flags.set(RequestFlags::HAS_SERVICE_TIER);
    }
    if json.get("seed").is_some() {
        flags.set(RequestFlags::HAS_SEED);
    }
    if json.get("logprobs").is_some() {
        flags.set(RequestFlags::HAS_LOGPROBS);
    }
    if json.get("user").is_some() {
        flags.set(RequestFlags::HAS_USER_ID);
    }
    if json.get("temperature").is_some() {
        flags.set(RequestFlags::HAS_TEMPERATURE);
    }
    if json.get("top_p").is_some() {
        flags.set(RequestFlags::HAS_TOP_P);
    }
    if json.get("stop").is_some() {
        flags.set(RequestFlags::HAS_STOP);
    }

    flags
}

/// Detect response flags from JSON
pub fn detect_response_flags(json: &serde_json::Value) -> ResponseFlags {
    let mut flags = ResponseFlags::new();

    // Check choices
    if let Some(choices) = json.get("choices").and_then(|v| v.as_array()) {
        if let Some(first) = choices.first() {
            // Tool calls
            if first
                .get("message")
                .and_then(|m| m.get("tool_calls"))
                .is_some()
            {
                flags.set(ResponseFlags::HAS_TOOL_CALLS);
            }
            // Refusal
            if first
                .get("message")
                .and_then(|m| m.get("refusal"))
                .and_then(|v| v.as_str())
                .is_some()
            {
                flags.set(ResponseFlags::HAS_REFUSAL);
            }
            // Content filter
            if first.get("finish_reason").and_then(|v| v.as_str()) == Some("content_filter") {
                flags.set(ResponseFlags::CONTENT_FILTERED);
            }
            // Truncated
            if first.get("finish_reason").and_then(|v| v.as_str()) == Some("length") {
                flags.set(ResponseFlags::TRUNCATED);
            }
        }
    }

    // Usage
    if let Some(usage) = json.get("usage") {
        flags.set(ResponseFlags::HAS_USAGE);

        // Cached tokens
        if usage
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(|v| v.as_u64())
            .map(|v| v > 0)
            .unwrap_or(false)
        {
            flags.set(ResponseFlags::HAS_CACHED_TOKENS);
        }

        // Reasoning tokens
        if usage
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(|v| v.as_u64())
            .map(|v| v > 0)
            .unwrap_or(false)
        {
            flags.set(ResponseFlags::HAS_REASONING_TOKENS);
        }
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::super::flags::CommonFlags;
    use super::*;

    #[test]
    fn test_fixed_header_roundtrip() {
        let mut request_flags = RequestFlags::new();
        request_flags.set(RequestFlags::HAS_SYSTEM_PROMPT);
        request_flags.set(RequestFlags::STREAM_REQUESTED);

        let mut common = CommonFlags::new();
        common.set(CommonFlags::COMPRESSED);

        let flags = Flags::for_request(request_flags, common);
        let header = FixedHeader::new(Schema::Request, SecurityMode::None, flags);

        let bytes = header.to_bytes();
        let decoded = FixedHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.schema, decoded.schema);
        assert_eq!(header.security, decoded.security);
        assert!(decoded
            .flags
            .request_flags()
            .has(RequestFlags::HAS_SYSTEM_PROMPT));
        assert!(decoded.flags.is_compressed());
    }

    #[test]
    fn test_roles_packing() {
        let roles = vec![
            Role::System,
            Role::User,
            Role::Assistant,
            Role::User,
            Role::Assistant,
        ];
        let packed = pack_roles(&roles);
        let unpacked = unpack_roles(&packed, roles.len());

        assert_eq!(roles.len(), unpacked.len());
        for (a, b) in roles.iter().zip(unpacked.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_routing_header_roundtrip() {
        let mut request_flags = RequestFlags::new();
        request_flags.set(RequestFlags::HAS_MAX_TOKENS);

        let mut header = RoutingHeader::new("gpt-4o".to_string());
        header.msg_count = 3;
        header.roles = vec![Role::System, Role::User, Role::Assistant];
        header.content_hint = 1500;
        header.max_tokens = Some(1000);

        let bytes = header.to_bytes(&request_flags);
        let (decoded, _) = RoutingHeader::from_bytes(&bytes, &request_flags).unwrap();

        assert_eq!(header.model, decoded.model);
        assert_eq!(header.msg_count, decoded.msg_count);
        assert_eq!(header.roles.len(), decoded.roles.len());
        assert_eq!(header.content_hint, decoded.content_hint);
        assert_eq!(header.max_tokens, decoded.max_tokens);
    }

    #[test]
    fn test_detect_request_flags() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Hello"}
            ],
            "stream": true,
            "max_tokens": 1000,
            "tools": []
        }"#,
        )
        .unwrap();

        let flags = detect_request_flags(&json);

        assert!(flags.has(RequestFlags::HAS_SYSTEM_PROMPT));
        assert!(flags.has(RequestFlags::STREAM_REQUESTED));
        assert!(flags.has(RequestFlags::HAS_MAX_TOKENS));
        assert!(flags.has(RequestFlags::HAS_TOOLS));
        assert!(!flags.has(RequestFlags::HAS_IMAGES));
    }
}
