//! M2M Frame encoding and decoding.
//!
//! The M2MFrame structure encapsulates the complete wire format including
//! headers and compressed payload.
//!
//! # Security Modes
//!
//! Frames can be encoded with different security levels:
//!
//! - `SecurityMode::None` - No authentication (default)
//! - `SecurityMode::Hmac` - HMAC-SHA256 authentication tag appended
//! - `SecurityMode::Aead` - ChaCha20-Poly1305 encryption
//!
//! # Wire Format with Security
//!
//! ```text
//! None: #M2M|1|<headers><payload_len><crc32><payload>
//! HMAC: #M2M|1|<headers><payload_len><crc32><payload><hmac_tag:32>
//! AEAD: #M2M|1|<headers><nonce:12><encrypted_payload_with_tag>
//! ```

#![allow(missing_docs)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use brotli::{CompressorWriter, Decompressor};
use std::io::{Read, Write};

use super::{
    cost::{estimate_cost, estimate_tokens_from_content},
    crypto::{SecurityContext, AEAD_TAG_SIZE, HMAC_TAG_SIZE, NONCE_SIZE},
    flags::{CommonFlags, Flags, ResponseFlags},
    header::{
        detect_request_flags, detect_response_flags, FixedHeader, ResponseHeader, RoutingHeader,
        Schema, SecurityMode, FIXED_HEADER_SIZE,
    },
    COMPRESSION_THRESHOLD, M2M_PREFIX,
};
use crate::error::{M2MError, Result};

/// Complete M2M frame
#[derive(Debug, Clone)]
pub struct M2MFrame {
    /// Fixed header (20 bytes)
    pub fixed: FixedHeader,
    /// Routing header (for requests)
    pub routing: Option<RoutingHeader>,
    /// Response header (for responses)
    pub response: Option<ResponseHeader>,
    /// Original JSON payload (100% fidelity)
    pub payload: String,
    /// CRC32 checksum of original JSON
    pub checksum: u32,
}

impl M2MFrame {
    /// Create a new request frame
    pub fn new_request(json: &str) -> Result<Self> {
        let parsed: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| M2MError::Compression(format!("Invalid JSON: {}", e)))?;

        // Detect flags from JSON content
        let request_flags = detect_request_flags(&parsed);

        // Determine if compression is beneficial
        let should_compress = json.len() >= COMPRESSION_THRESHOLD;
        let mut common_flags = CommonFlags::new();
        if should_compress {
            common_flags.set(CommonFlags::COMPRESSED);
        }

        let flags = Flags::for_request(request_flags, common_flags);

        // Extract routing header
        let mut routing = RoutingHeader::from_json(&parsed, &request_flags)?;

        // Estimate cost if we have enough info
        let estimated_tokens = estimate_tokens_from_content(routing.content_hint as usize);
        let estimated_completion = routing.max_tokens.unwrap_or(500);
        routing.est_cost_usd = Some(estimate_cost(
            &routing.model,
            estimated_tokens,
            estimated_completion,
        ));

        // Calculate header length
        let routing_size = routing.encoded_size(&request_flags);
        let header_len = (FIXED_HEADER_SIZE + routing_size) as u16;

        let fixed = FixedHeader {
            header_len,
            schema: Schema::Request,
            security: SecurityMode::None,
            flags,
            reserved: [0u8; 12],
        };

        // Calculate checksum
        let checksum = crc32fast::hash(json.as_bytes());

        Ok(Self {
            fixed,
            routing: Some(routing),
            response: None,
            payload: json.to_string(),
            checksum,
        })
    }

    /// Create a new response frame
    pub fn new_response(json: &str) -> Result<Self> {
        let parsed: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| M2MError::Compression(format!("Invalid JSON: {}", e)))?;

        // Detect flags from JSON content
        let mut response_flags = detect_response_flags(&parsed);

        // Determine if compression is beneficial
        let should_compress = json.len() >= COMPRESSION_THRESHOLD;
        let mut common_flags = CommonFlags::new();
        if should_compress {
            common_flags.set(CommonFlags::COMPRESSED);
        }

        // Extract response header
        let mut response_header = ResponseHeader::from_json(&parsed, &response_flags)?;

        // Calculate cost if we have usage
        if response_flags.has(ResponseFlags::HAS_USAGE) {
            response_header.est_cost_usd = Some(estimate_cost(
                &response_header.model,
                response_header.prompt_tokens,
                response_header.completion_tokens,
            ));
            response_flags.set(ResponseFlags::HAS_COST_ESTIMATE);
        }

        let flags = Flags::for_response(response_flags, common_flags);

        // Calculate header length
        let response_size = response_header.to_bytes(&response_flags).len();
        let header_len = (FIXED_HEADER_SIZE + response_size) as u16;

        let fixed = FixedHeader {
            header_len,
            schema: Schema::Response,
            security: SecurityMode::None,
            flags,
            reserved: [0u8; 12],
        };

        // Calculate checksum
        let checksum = crc32fast::hash(json.as_bytes());

        Ok(Self {
            fixed,
            routing: None,
            response: Some(response_header),
            payload: json.to_string(),
            checksum,
        })
    }

    /// Encode frame to wire format bytes
    ///
    /// Returns raw binary format suitable for binary-safe transport channels
    /// (TCP, QUIC, WebSocket binary frames, etc.).
    ///
    /// For text-based transport (HTTP headers, JSON fields), use `encode_string()`
    /// which wraps the binary in base64.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256 + self.payload.len());

        // Write prefix
        buf.extend_from_slice(M2M_PREFIX.as_bytes());

        // Write fixed header
        buf.extend_from_slice(&self.fixed.to_bytes());

        // Write variable header (routing or response)
        match self.fixed.schema {
            Schema::Request | Schema::EmbeddingRequest => {
                if let Some(ref routing) = self.routing {
                    let request_flags = self.fixed.flags.request_flags();
                    buf.extend_from_slice(&routing.to_bytes(&request_flags));
                }
            },
            Schema::Response | Schema::EmbeddingResponse | Schema::Error => {
                if let Some(ref response) = self.response {
                    let response_flags = self.fixed.flags.response_flags();
                    buf.extend_from_slice(&response.to_bytes(&response_flags));
                }
            },
            _ => {},
        }

        // Compress or raw payload
        let payload_bytes = if self.fixed.flags.is_compressed() {
            compress_brotli(self.payload.as_bytes())?
        } else {
            self.payload.as_bytes().to_vec()
        };

        // Write payload length
        buf.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());

        // Write checksum
        buf.extend_from_slice(&self.checksum.to_le_bytes());

        // Write payload
        buf.extend_from_slice(&payload_bytes);

        Ok(buf)
    }

    /// Encode frame to wire format string (for text transport)
    ///
    /// Uses base64 encoding for the binary portion after the ASCII prefix.
    /// Format: `#M2M|1|<base64_encoded_binary>`
    ///
    /// Use this for text-based channels (HTTP, JSON). For binary-safe channels,
    /// prefer `encode()` which avoids the ~33% base64 overhead.
    pub fn encode_string(&self) -> Result<String> {
        let bytes = self.encode()?;

        // The prefix is ASCII, the rest is binary - use base64 for text transport
        let prefix_len = M2M_PREFIX.len();
        let binary_part = &bytes[prefix_len..];
        let encoded = BASE64.encode(binary_part);

        Ok(format!("{}{}", M2M_PREFIX, encoded))
    }

    /// Encode frame with security (HMAC or AEAD)
    ///
    /// # Arguments
    /// * `security_mode` - The security mode to use
    /// * `security_ctx` - Security context with key material
    ///
    /// # Wire Format
    /// - HMAC: `<frame><hmac_tag:32>`
    /// - AEAD: `<headers><nonce:12><encrypted_payload_with_tag>`
    pub fn encode_secure(
        &self,
        security_mode: SecurityMode,
        security_ctx: &mut SecurityContext,
    ) -> Result<Vec<u8>> {
        match security_mode {
            SecurityMode::None => self.encode(),
            SecurityMode::Hmac => self.encode_with_hmac(security_ctx),
            SecurityMode::Aead => self.encode_with_aead(security_ctx),
        }
    }

    /// Encode frame with HMAC-SHA256 authentication
    fn encode_with_hmac(&self, security_ctx: &SecurityContext) -> Result<Vec<u8>> {
        use super::crypto::HmacAuth;

        // First encode the frame normally
        let mut frame_bytes = self.encode()?;

        // Update the security mode in the fixed header
        // The security byte is at offset: prefix_len + 3
        let security_offset = M2M_PREFIX.len() + 3;
        if security_offset < frame_bytes.len() {
            frame_bytes[security_offset] = SecurityMode::Hmac.as_byte();
        }

        // Compute HMAC over the entire frame (excluding prefix for efficiency)
        let hmac_auth =
            HmacAuth::new(security_ctx.key().clone()).map_err(|e| M2MError::Crypto(e.into()))?;

        let data_to_sign = &frame_bytes[M2M_PREFIX.len()..];
        let tag = hmac_auth.compute_tag(data_to_sign);

        // Append HMAC tag
        frame_bytes.extend_from_slice(&tag);

        Ok(frame_bytes)
    }

    /// Encode frame with ChaCha20-Poly1305 AEAD encryption
    fn encode_with_aead(&self, security_ctx: &mut SecurityContext) -> Result<Vec<u8>> {
        use super::crypto::AeadCipher;

        let mut buf = Vec::with_capacity(256 + self.payload.len());

        // Write prefix
        buf.extend_from_slice(M2M_PREFIX.as_bytes());

        // Create fixed header with AEAD security mode
        let mut fixed = self.fixed.clone();
        fixed.security = SecurityMode::Aead;
        buf.extend_from_slice(&fixed.to_bytes());

        // Write variable header (routing or response) - this is authenticated but not encrypted
        match self.fixed.schema {
            Schema::Request | Schema::EmbeddingRequest => {
                if let Some(ref routing) = self.routing {
                    let request_flags = self.fixed.flags.request_flags();
                    buf.extend_from_slice(&routing.to_bytes(&request_flags));
                }
            },
            Schema::Response | Schema::EmbeddingResponse | Schema::Error => {
                if let Some(ref response) = self.response {
                    let response_flags = self.fixed.flags.response_flags();
                    buf.extend_from_slice(&response.to_bytes(&response_flags));
                }
            },
            _ => {},
        }

        // header_end marks the end of all headers (fixed + variable)
        let header_end = buf.len();

        // Prepare plaintext: payload_len || crc32 || payload
        let payload_bytes = if self.fixed.flags.is_compressed() {
            compress_brotli(self.payload.as_bytes())?
        } else {
            self.payload.as_bytes().to_vec()
        };

        let mut plaintext = Vec::with_capacity(8 + payload_bytes.len());
        plaintext.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(&self.checksum.to_le_bytes());
        plaintext.extend_from_slice(&payload_bytes);

        // Generate cryptographically secure random nonce
        #[cfg(feature = "crypto")]
        let nonce = security_ctx
            .next_nonce()
            .map_err(|e| M2MError::Crypto(e.into()))?;
        #[cfg(not(feature = "crypto"))]
        let nonce = {
            // Fallback for non-crypto builds (NOT SECURE - testing only)
            let mut n = [0u8; 12];
            n[0..8].copy_from_slice(
                &(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64)
                    .to_le_bytes(),
            );
            n
        };
        let cipher =
            AeadCipher::new(security_ctx.key().clone()).map_err(|e| M2MError::Crypto(e.into()))?;

        // Associated data = headers (authenticated but not encrypted)
        let aad = &buf[M2M_PREFIX.len()..header_end];

        let ciphertext = cipher
            .encrypt(&plaintext, &nonce, aad)
            .map_err(|e| M2MError::Crypto(e.into()))?;

        // Append ciphertext (includes nonce at start and tag at end)
        buf.extend_from_slice(&ciphertext);

        Ok(buf)
    }

    /// Encode frame with security to string (base64)
    pub fn encode_secure_string(
        &self,
        security_mode: SecurityMode,
        security_ctx: &mut SecurityContext,
    ) -> Result<String> {
        let bytes = self.encode_secure(security_mode, security_ctx)?;
        let prefix_len = M2M_PREFIX.len();
        let binary_part = &bytes[prefix_len..];
        let encoded = BASE64.encode(binary_part);
        Ok(format!("{}{}", M2M_PREFIX, encoded))
    }

    /// Decode frame from wire format bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        // Check prefix
        if !data.starts_with(M2M_PREFIX.as_bytes()) {
            return Err(M2MError::Decompression("Invalid M2M prefix".to_string()));
        }

        let mut pos = M2M_PREFIX.len();

        // Read fixed header
        if pos + FIXED_HEADER_SIZE > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for fixed header".to_string(),
            ));
        }
        let fixed = FixedHeader::from_bytes(&data[pos..pos + FIXED_HEADER_SIZE])?;
        pos += FIXED_HEADER_SIZE;

        // Calculate variable header size (with underflow protection)
        let header_len = fixed.header_len as usize;
        if header_len < FIXED_HEADER_SIZE {
            return Err(M2MError::Decompression(format!(
                "Invalid header_len: {} < minimum {}",
                header_len, FIXED_HEADER_SIZE
            )));
        }
        let variable_header_size = header_len - FIXED_HEADER_SIZE;

        if pos + variable_header_size > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for variable header".to_string(),
            ));
        }

        // Read variable header
        let (routing, response) = match fixed.schema {
            Schema::Request | Schema::EmbeddingRequest => {
                let request_flags = fixed.flags.request_flags();
                let (routing, _) = RoutingHeader::from_bytes(&data[pos..], &request_flags)?;
                pos += variable_header_size;
                (Some(routing), None)
            },
            Schema::Response | Schema::EmbeddingResponse | Schema::Error => {
                let response_flags = fixed.flags.response_flags();
                let (response, _) = ResponseHeader::from_bytes(&data[pos..], &response_flags)?;
                pos += variable_header_size;
                (None, Some(response))
            },
            _ => {
                pos += variable_header_size;
                (None, None)
            },
        };

        // Read payload length
        if pos + 4 > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for payload length".to_string(),
            ));
        }
        let payload_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        // Read checksum
        if pos + 4 > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for checksum".to_string(),
            ));
        }
        let checksum = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        // Read payload
        if pos + payload_len > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for payload".to_string(),
            ));
        }
        let payload_bytes = &data[pos..pos + payload_len];

        // Decompress if needed
        let payload = if fixed.flags.is_compressed() {
            let decompressed = decompress_brotli(payload_bytes)?;
            String::from_utf8(decompressed)
                .map_err(|e| M2MError::Decompression(format!("Invalid UTF-8: {}", e)))?
        } else {
            String::from_utf8(payload_bytes.to_vec())
                .map_err(|e| M2MError::Decompression(format!("Invalid UTF-8: {}", e)))?
        };

        // Verify checksum
        let computed_checksum = crc32fast::hash(payload.as_bytes());
        if computed_checksum != checksum {
            return Err(M2MError::Decompression(format!(
                "Checksum mismatch: expected {:08x}, got {:08x}",
                checksum, computed_checksum
            )));
        }

        Ok(Self {
            fixed,
            routing,
            response,
            payload,
            checksum,
        })
    }

    /// Decode frame from wire format string
    ///
    /// Handles base64-encoded format: `#M2M|1|<base64_encoded_binary>`
    pub fn decode_string(data: &str) -> Result<Self> {
        // Check for M2M prefix
        if !data.starts_with(M2M_PREFIX) {
            return Err(M2MError::Decompression("Invalid M2M prefix".to_string()));
        }

        // Decode base64 portion after prefix
        let base64_part = &data[M2M_PREFIX.len()..];
        let binary = BASE64
            .decode(base64_part)
            .map_err(|e| M2MError::Decompression(format!("Base64 decode failed: {}", e)))?;

        // Reconstruct full frame with prefix
        let mut full_frame = M2M_PREFIX.as_bytes().to_vec();
        full_frame.extend_from_slice(&binary);

        Self::decode(&full_frame)
    }

    /// Decode frame with security verification
    ///
    /// Automatically detects security mode from the fixed header and
    /// verifies/decrypts accordingly.
    pub fn decode_secure(data: &[u8], security_ctx: &SecurityContext) -> Result<Self> {
        // Check prefix
        if !data.starts_with(M2M_PREFIX.as_bytes()) {
            return Err(M2MError::Decompression("Invalid M2M prefix".to_string()));
        }

        // Read security mode from fixed header (offset: prefix_len + 3)
        let security_offset = M2M_PREFIX.len() + 3;
        if security_offset >= data.len() {
            return Err(M2MError::Decompression("Frame too short".to_string()));
        }

        let security_mode = SecurityMode::from_byte(data[security_offset]);

        match security_mode {
            SecurityMode::None => Self::decode(data),
            SecurityMode::Hmac => Self::decode_with_hmac(data, security_ctx),
            SecurityMode::Aead => Self::decode_with_aead(data, security_ctx),
        }
    }

    /// Decode frame with HMAC verification
    fn decode_with_hmac(data: &[u8], security_ctx: &SecurityContext) -> Result<Self> {
        use super::crypto::HmacAuth;

        // Frame must have at least prefix + header + HMAC tag
        if data.len() < M2M_PREFIX.len() + FIXED_HEADER_SIZE + HMAC_TAG_SIZE {
            return Err(M2MError::Decompression(
                "Frame too short for HMAC".to_string(),
            ));
        }

        // Split frame and HMAC tag
        let frame_end = data.len() - HMAC_TAG_SIZE;
        let frame_data = &data[..frame_end];
        let provided_tag = &data[frame_end..];

        // Verify HMAC over frame (excluding prefix for consistency with encode)
        let hmac_auth =
            HmacAuth::new(security_ctx.key().clone()).map_err(|e| M2MError::Crypto(e.into()))?;

        let data_to_verify = &frame_data[M2M_PREFIX.len()..];
        hmac_auth
            .verify_tag(data_to_verify, provided_tag)
            .map_err(|e| M2MError::Crypto(e.into()))?;

        // Decode the verified frame
        Self::decode(frame_data)
    }

    /// Decode frame with AEAD decryption
    fn decode_with_aead(data: &[u8], security_ctx: &SecurityContext) -> Result<Self> {
        use super::crypto::AeadCipher;

        // Check prefix
        if !data.starts_with(M2M_PREFIX.as_bytes()) {
            return Err(M2MError::Decompression("Invalid M2M prefix".to_string()));
        }

        let mut pos = M2M_PREFIX.len();

        // Read fixed header
        if pos + FIXED_HEADER_SIZE > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for fixed header".to_string(),
            ));
        }
        let fixed = FixedHeader::from_bytes(&data[pos..pos + FIXED_HEADER_SIZE])?;
        pos += FIXED_HEADER_SIZE;

        // Calculate variable header size (with underflow protection)
        let header_len = fixed.header_len as usize;
        if header_len < FIXED_HEADER_SIZE {
            return Err(M2MError::Decompression(format!(
                "Invalid header_len: {} < minimum {}",
                header_len, FIXED_HEADER_SIZE
            )));
        }
        let variable_header_size = header_len - FIXED_HEADER_SIZE;

        if pos + variable_header_size > data.len() {
            return Err(M2MError::Decompression(
                "Frame too short for variable header".to_string(),
            ));
        }

        // Read variable header
        let (routing, response) = match fixed.schema {
            Schema::Request | Schema::EmbeddingRequest => {
                let request_flags = fixed.flags.request_flags();
                let (routing, _) = RoutingHeader::from_bytes(&data[pos..], &request_flags)?;
                pos += variable_header_size;
                (Some(routing), None)
            },
            Schema::Response | Schema::EmbeddingResponse | Schema::Error => {
                let response_flags = fixed.flags.response_flags();
                let (response, _) = ResponseHeader::from_bytes(&data[pos..], &response_flags)?;
                pos += variable_header_size;
                (None, Some(response))
            },
            _ => {
                pos += variable_header_size;
                (None, None)
            },
        };

        // Remaining data is the encrypted payload (nonce + ciphertext + tag)
        let encrypted_data = &data[pos..];
        if encrypted_data.len() < NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(M2MError::Decompression(
                "Frame too short for AEAD payload".to_string(),
            ));
        }

        // Decrypt
        let cipher =
            AeadCipher::new(security_ctx.key().clone()).map_err(|e| M2MError::Crypto(e.into()))?;

        // Associated data = fixed header + variable header
        let header_end = M2M_PREFIX.len() + fixed.header_len as usize;
        let aad = &data[M2M_PREFIX.len()..header_end];

        let plaintext = cipher
            .decrypt(encrypted_data, aad)
            .map_err(|e| M2MError::Crypto(e.into()))?;

        // Parse decrypted payload: payload_len || crc32 || payload
        if plaintext.len() < 8 {
            return Err(M2MError::Decompression(
                "Decrypted payload too short".to_string(),
            ));
        }

        let payload_len =
            u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
        let checksum = u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        let payload_bytes = &plaintext[8..];

        if payload_bytes.len() != payload_len {
            return Err(M2MError::Decompression(format!(
                "Payload length mismatch: expected {}, got {}",
                payload_len,
                payload_bytes.len()
            )));
        }

        // Decompress if needed
        let payload = if fixed.flags.is_compressed() {
            let decompressed = decompress_brotli(payload_bytes)?;
            String::from_utf8(decompressed)
                .map_err(|e| M2MError::Decompression(format!("Invalid UTF-8: {}", e)))?
        } else {
            String::from_utf8(payload_bytes.to_vec())
                .map_err(|e| M2MError::Decompression(format!("Invalid UTF-8: {}", e)))?
        };

        // Verify checksum
        let computed_checksum = crc32fast::hash(payload.as_bytes());
        if computed_checksum != checksum {
            return Err(M2MError::Decompression(format!(
                "Checksum mismatch: expected {:08x}, got {:08x}",
                checksum, computed_checksum
            )));
        }

        Ok(Self {
            fixed,
            routing,
            response,
            payload,
            checksum,
        })
    }

    /// Decode secure frame from string (base64)
    pub fn decode_secure_string(data: &str, security_ctx: &SecurityContext) -> Result<Self> {
        if !data.starts_with(M2M_PREFIX) {
            return Err(M2MError::Decompression("Invalid M2M prefix".to_string()));
        }

        let base64_part = &data[M2M_PREFIX.len()..];
        let binary = BASE64
            .decode(base64_part)
            .map_err(|e| M2MError::Decompression(format!("Base64 decode failed: {}", e)))?;

        let mut full_frame = M2M_PREFIX.as_bytes().to_vec();
        full_frame.extend_from_slice(&binary);

        Self::decode_secure(&full_frame, security_ctx)
    }

    /// Get the original JSON payload (100% fidelity)
    pub fn json(&self) -> &str {
        &self.payload
    }

    /// Check if this is a request
    pub fn is_request(&self) -> bool {
        self.fixed.schema.is_request()
    }

    /// Check if this is a response
    pub fn is_response(&self) -> bool {
        self.fixed.schema.is_response()
    }

    /// Get compression ratio (compressed_size / original_size)
    pub fn compression_ratio(&self) -> f64 {
        let original = self.payload.len();
        if original == 0 {
            return 1.0;
        }

        // Estimate encoded size (this is approximate)
        let encoded_len = M2M_PREFIX.len() + self.fixed.header_len as usize + 8; // payload_len + checksum

        if self.fixed.flags.is_compressed() {
            // Actual compression ratio requires encoding
            // For now, estimate based on typical Brotli performance
            (encoded_len as f64 + original as f64 * 0.3) / original as f64
        } else {
            (encoded_len as f64 + original as f64) / original as f64
        }
    }
}

/// M2M Codec for encoding and decoding frames
#[derive(Debug, Clone, Default)]
pub struct M2MCodec;

impl M2MCodec {
    pub fn new() -> Self {
        Self
    }

    /// Encode JSON to M2M wire format
    pub fn encode(&self, json: &str) -> Result<Vec<u8>> {
        // Auto-detect if request or response
        let parsed: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| M2MError::Compression(format!("Invalid JSON: {}", e)))?;

        let frame = if parsed.get("messages").is_some() && parsed.get("model").is_some() {
            // Request (has messages and model)
            M2MFrame::new_request(json)?
        } else if parsed.get("choices").is_some()
            || parsed
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("chatcmpl-"))
                .unwrap_or(false)
        {
            // Response (has choices or chatcmpl ID)
            M2MFrame::new_response(json)?
        } else {
            // Default to request
            M2MFrame::new_request(json)?
        };

        frame.encode()
    }

    /// Decode M2M wire format to JSON (100% fidelity)
    pub fn decode(&self, data: &[u8]) -> Result<String> {
        let frame = M2MFrame::decode(data)?;
        Ok(frame.payload)
    }

    /// Encode JSON to M2M wire format string (base64 encoded)
    pub fn encode_string(&self, json: &str) -> Result<String> {
        // Auto-detect if request or response
        let parsed: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| M2MError::Compression(format!("Invalid JSON: {}", e)))?;

        let frame = if parsed.get("messages").is_some() && parsed.get("model").is_some() {
            M2MFrame::new_request(json)?
        } else if parsed.get("choices").is_some()
            || parsed
                .get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("chatcmpl-"))
                .unwrap_or(false)
        {
            M2MFrame::new_response(json)?
        } else {
            M2MFrame::new_request(json)?
        };

        frame.encode_string()
    }

    /// Decode M2M wire format string to JSON
    pub fn decode_string(&self, data: &str) -> Result<String> {
        let frame = M2MFrame::decode_string(data)?;
        Ok(frame.payload)
    }

    /// Check if content is M2M format
    pub fn is_m2m_format(content: &str) -> bool {
        content.starts_with(M2M_PREFIX)
    }
}

/// Compress data using Brotli
fn compress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    let mut compressed = Vec::new();
    {
        // Quality 5 is a good balance of speed and compression
        let mut compressor = CompressorWriter::new(&mut compressed, 4096, 5, 22);
        compressor
            .write_all(data)
            .map_err(|e| M2MError::Compression(format!("Brotli compression failed: {}", e)))?;
    }
    Ok(compressed)
}

/// Decompress data using Brotli
fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>> {
    let mut decompressed = Vec::new();
    let mut decompressor = Decompressor::new(data, 4096);
    decompressor
        .read_to_end(&mut decompressed)
        .map_err(|e| M2MError::Decompression(format!("Brotli decompression failed: {}", e)))?;
    Ok(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REQUEST: &str = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is 2+2?"}],"temperature":0.7,"max_tokens":1000}"#;

    const TEST_RESPONSE: &str = r#"{"id":"chatcmpl-abc123","object":"chat.completion","created":1705520400,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"The answer is 4."},"finish_reason":"stop"}],"usage":{"prompt_tokens":50,"completion_tokens":10,"total_tokens":60}}"#;

    #[test]
    fn test_request_roundtrip() {
        let codec = M2MCodec::new();

        let encoded = codec.encode(TEST_REQUEST).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        // 100% fidelity - exact match
        assert_eq!(TEST_REQUEST, decoded);
    }

    #[test]
    fn test_response_roundtrip() {
        let codec = M2MCodec::new();

        let encoded = codec.encode(TEST_RESPONSE).unwrap();
        let decoded = codec.decode(&encoded).unwrap();

        // 100% fidelity - exact match
        assert_eq!(TEST_RESPONSE, decoded);
    }

    #[test]
    fn test_frame_has_correct_schema() {
        let request_frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        assert_eq!(request_frame.fixed.schema, Schema::Request);
        assert!(request_frame.routing.is_some());

        let response_frame = M2MFrame::new_response(TEST_RESPONSE).unwrap();
        assert_eq!(response_frame.fixed.schema, Schema::Response);
        assert!(response_frame.response.is_some());
    }

    #[test]
    fn test_routing_header_extraction() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let routing = frame.routing.unwrap();

        assert_eq!(routing.model, "gpt-4o");
        assert_eq!(routing.msg_count, 2);
        assert_eq!(routing.roles.len(), 2);
        assert_eq!(routing.max_tokens, Some(1000));
    }

    #[test]
    fn test_response_header_extraction() {
        let frame = M2MFrame::new_response(TEST_RESPONSE).unwrap();
        let response = frame.response.unwrap();

        assert_eq!(response.id, "chatcmpl-abc123");
        assert_eq!(response.model, "gpt-4o");
        assert_eq!(response.prompt_tokens, 50);
        assert_eq!(response.completion_tokens, 10);
    }

    #[test]
    fn test_small_payload_not_compressed() {
        let small_json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#;
        let frame = M2MFrame::new_request(small_json).unwrap();

        // Small payloads should not be compressed
        assert!(!frame.fixed.flags.is_compressed());
    }

    #[test]
    fn test_large_payload_compressed() {
        let large_content = "Hello world! ".repeat(50);
        let large_json = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
            large_content
        );
        let frame = M2MFrame::new_request(&large_json).unwrap();

        // Large payloads should be compressed
        assert!(frame.fixed.flags.is_compressed());
    }

    #[test]
    fn test_checksum_verification() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let encoded = frame.encode().unwrap();

        // Corrupt a byte in the payload
        let mut corrupted = encoded.clone();
        if let Some(last) = corrupted.last_mut() {
            *last ^= 0xFF;
        }

        // Decoding should fail with checksum mismatch
        let result = M2MFrame::decode(&corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_wire_format_prefix() {
        let codec = M2MCodec::new();
        let encoded = codec.encode(TEST_REQUEST).unwrap();

        // Should start with M2M prefix
        assert!(encoded.starts_with(M2M_PREFIX.as_bytes()));
    }

    #[test]
    fn test_cost_estimation() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let routing = frame.routing.unwrap();

        // Should have cost estimate
        assert!(routing.est_cost_usd.is_some());
        assert!(routing.est_cost_usd.unwrap() > 0.0);
    }

    #[test]
    fn test_response_cost_estimation() {
        let frame = M2MFrame::new_response(TEST_RESPONSE).unwrap();
        let response = frame.response.unwrap();

        // Should have cost estimate
        assert!(response.est_cost_usd.is_some());

        // Cost for 50 prompt + 10 completion on gpt-4o:
        // 50 * 0.25/100 + 10 * 1.00/100 = 0.000125 + 0.0001 = 0.000225 USD
        let cost = response.est_cost_usd.unwrap();
        assert!(cost > 0.0001 && cost < 0.001);
    }

    #[test]
    fn test_string_roundtrip() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();

        let encoded = frame.encode_string().unwrap();
        assert!(encoded.starts_with(M2M_PREFIX));

        let decoded = M2MFrame::decode_string(&encoded).unwrap();
        assert_eq!(decoded.payload, TEST_REQUEST);
    }

    #[test]
    fn test_binary_vs_base64_size() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();

        let binary = frame.encode().unwrap();
        let base64_str = frame.encode_string().unwrap();

        // Base64 adds ~33% overhead to the binary portion
        // binary = prefix + headers + payload
        // base64 = prefix + base64(headers + payload)
        let prefix_len = M2M_PREFIX.len();
        let binary_data_len = binary.len() - prefix_len;
        let base64_data_len = base64_str.len() - prefix_len;

        // Base64 overhead should be approximately 4/3 (33%)
        let expected_base64_len = (binary_data_len * 4 + 2) / 3; // ceil division
        assert!(
            base64_data_len <= expected_base64_len + 2, // Allow for padding
            "Base64 length {} should be close to expected {}",
            base64_data_len,
            expected_base64_len
        );

        // Binary should always be smaller
        assert!(
            binary.len() < base64_str.len(),
            "Binary {} should be smaller than base64 {}",
            binary.len(),
            base64_str.len()
        );

        // Both should decode to same content
        let decoded_binary = M2MFrame::decode(&binary).unwrap();
        let decoded_base64 = M2MFrame::decode_string(&base64_str).unwrap();
        assert_eq!(decoded_binary.payload, decoded_base64.payload);
        assert_eq!(decoded_binary.payload, TEST_REQUEST);
    }
}

/// Tests for secure encode/decode functionality
#[cfg(test)]
mod secure_tests {
    use super::super::crypto::{KeyMaterial, SecurityContext};
    use super::*;

    const TEST_REQUEST: &str = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is 2+2?"}],"temperature":0.7,"max_tokens":1000}"#;

    const TEST_RESPONSE: &str = r#"{"id":"chatcmpl-abc123","object":"chat.completion","created":1705520400,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"The answer is 4."},"finish_reason":"stop"}],"usage":{"prompt_tokens":50,"completion_tokens":10,"total_tokens":60}}"#;

    fn test_key() -> KeyMaterial {
        KeyMaterial::new(vec![0x42u8; 32])
    }

    #[test]
    fn test_hmac_request_roundtrip() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        // Encode with HMAC
        let encoded = frame.encode_secure(SecurityMode::Hmac, &mut ctx).unwrap();

        // Should have HMAC tag appended (32 bytes)
        let plain_encoded = frame.encode().unwrap();
        assert_eq!(encoded.len(), plain_encoded.len() + HMAC_TAG_SIZE);

        // Decode with verification
        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure(&encoded, &decode_ctx).unwrap();

        // 100% fidelity
        assert_eq!(decoded.payload, TEST_REQUEST);
    }

    #[test]
    fn test_hmac_response_roundtrip() {
        let frame = M2MFrame::new_response(TEST_RESPONSE).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let encoded = frame.encode_secure(SecurityMode::Hmac, &mut ctx).unwrap();

        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure(&encoded, &decode_ctx).unwrap();

        assert_eq!(decoded.payload, TEST_RESPONSE);
    }

    #[test]
    fn test_hmac_tamper_detection() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let mut encoded = frame.encode_secure(SecurityMode::Hmac, &mut ctx).unwrap();

        // Tamper with payload (not the HMAC tag)
        let tamper_idx = encoded.len() / 2;
        encoded[tamper_idx] ^= 0xFF;

        // Decode should fail
        let decode_ctx = SecurityContext::new(key);
        let result = M2MFrame::decode_secure(&encoded, &decode_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_wrong_key_rejection() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key);

        let encoded = frame.encode_secure(SecurityMode::Hmac, &mut ctx).unwrap();

        // Try to decode with different key
        let wrong_key = KeyMaterial::new(vec![0x99u8; 32]);
        let decode_ctx = SecurityContext::new(wrong_key);
        let result = M2MFrame::decode_secure(&encoded, &decode_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_request_roundtrip() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        // Encode with AEAD
        let encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

        // Decode with decryption
        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure(&encoded, &decode_ctx).unwrap();

        // 100% fidelity
        assert_eq!(decoded.payload, TEST_REQUEST);
    }

    #[test]
    fn test_aead_response_roundtrip() {
        let frame = M2MFrame::new_response(TEST_RESPONSE).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure(&encoded, &decode_ctx).unwrap();

        assert_eq!(decoded.payload, TEST_RESPONSE);
    }

    #[test]
    fn test_aead_tamper_detection() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let mut encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

        // Tamper with ciphertext
        let tamper_idx = encoded.len() - 20; // somewhere in the ciphertext
        encoded[tamper_idx] ^= 0xFF;

        // Decode should fail (AEAD auth tag won't verify)
        let decode_ctx = SecurityContext::new(key);
        let result = M2MFrame::decode_secure(&encoded, &decode_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_key_rejection() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key);

        let encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

        // Try to decode with different key
        let wrong_key = KeyMaterial::new(vec![0x99u8; 32]);
        let decode_ctx = SecurityContext::new(wrong_key);
        let result = M2MFrame::decode_secure(&encoded, &decode_ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_string_hmac_roundtrip() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let encoded = frame
            .encode_secure_string(SecurityMode::Hmac, &mut ctx)
            .unwrap();
        assert!(encoded.starts_with(M2M_PREFIX));

        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure_string(&encoded, &decode_ctx).unwrap();
        assert_eq!(decoded.payload, TEST_REQUEST);
    }

    #[test]
    fn test_secure_string_aead_roundtrip() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let encoded = frame
            .encode_secure_string(SecurityMode::Aead, &mut ctx)
            .unwrap();
        assert!(encoded.starts_with(M2M_PREFIX));

        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure_string(&encoded, &decode_ctx).unwrap();
        assert_eq!(decoded.payload, TEST_REQUEST);
    }

    #[test]
    fn test_security_mode_none_passthrough() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        // SecurityMode::None should produce same result as plain encode
        let secure_encoded = frame.encode_secure(SecurityMode::None, &mut ctx).unwrap();
        let plain_encoded = frame.encode().unwrap();

        assert_eq!(secure_encoded, plain_encoded);

        // Should decode with or without security context
        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure(&secure_encoded, &decode_ctx).unwrap();
        assert_eq!(decoded.payload, TEST_REQUEST);
    }

    #[test]
    fn test_large_payload_aead() {
        // Test with a payload large enough to trigger compression
        let large_content = "This is a test message that should trigger compression. ".repeat(20);
        let large_json = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}"}}]}}"#,
            large_content
        );

        let frame = M2MFrame::new_request(&large_json).unwrap();
        assert!(frame.fixed.flags.is_compressed());

        let key = test_key();
        let mut ctx = SecurityContext::new(key.clone());

        let encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

        let decode_ctx = SecurityContext::new(key);
        let decoded = M2MFrame::decode_secure(&encoded, &decode_ctx).unwrap();

        assert_eq!(decoded.payload, large_json);
    }

    #[test]
    fn test_security_mode_in_header() {
        let frame = M2MFrame::new_request(TEST_REQUEST).unwrap();
        let key = test_key();
        let mut ctx = SecurityContext::new(key);

        // HMAC mode
        let hmac_encoded = frame.encode_secure(SecurityMode::Hmac, &mut ctx).unwrap();
        let security_offset = M2M_PREFIX.len() + 3;
        assert_eq!(
            SecurityMode::from_byte(hmac_encoded[security_offset]),
            SecurityMode::Hmac
        );

        // AEAD mode
        let aead_encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();
        assert_eq!(
            SecurityMode::from_byte(aead_encoded[security_offset]),
            SecurityMode::Aead
        );
    }
}
