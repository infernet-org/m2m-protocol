//! Flag definitions for M2M wire format.
//!
//! Flags are stored as a 32-bit bitfield in the fixed header.
//! - Bits 0-15: Request/Response specific flags
//! - Bits 16-23: Reserved
//! - Bits 24-31: Common flags

/// Request-specific flags (bits 0-15)
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestFlags(u16);

#[allow(missing_docs)]
impl RequestFlags {
    /// Request has a system prompt
    pub const HAS_SYSTEM_PROMPT: u16 = 1 << 0;
    /// Request has tools defined
    pub const HAS_TOOLS: u16 = 1 << 1;
    /// Request specifies tool choice
    pub const HAS_TOOL_CHOICE: u16 = 1 << 2;
    /// Request includes images
    pub const HAS_IMAGES: u16 = 1 << 3;
    /// Streaming response requested
    pub const STREAM_REQUESTED: u16 = 1 << 4;
    /// Response format specified
    pub const HAS_RESPONSE_FORMAT: u16 = 1 << 5;
    /// Max tokens specified
    pub const HAS_MAX_TOKENS: u16 = 1 << 6;
    /// Reasoning effort specified (o-series)
    pub const HAS_REASONING_EFFORT: u16 = 1 << 7;
    /// Service tier specified
    pub const HAS_SERVICE_TIER: u16 = 1 << 8;
    /// Seed specified
    pub const HAS_SEED: u16 = 1 << 9;
    /// Logprobs requested
    pub const HAS_LOGPROBS: u16 = 1 << 10;
    /// User ID specified
    pub const HAS_USER_ID: u16 = 1 << 11;
    /// Temperature specified
    pub const HAS_TEMPERATURE: u16 = 1 << 12;
    /// Top P specified
    pub const HAS_TOP_P: u16 = 1 << 13;
    /// Stop sequences specified
    pub const HAS_STOP: u16 = 1 << 14;
    // Bit 15 reserved

    /// Create new empty flags
    pub fn new() -> Self {
        Self(0)
    }

    /// Create from raw bits
    pub fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub fn bits(&self) -> u16 {
        self.0
    }

    /// Set a flag
    pub fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: u16) {
        self.0 &= !flag;
    }

    /// Check if flag is set
    pub fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

/// Response-specific flags (bits 0-15)
#[derive(Debug, Clone, Copy, Default)]
pub struct ResponseFlags(u16);

#[allow(missing_docs)]
impl ResponseFlags {
    /// Response has tool calls
    pub const HAS_TOOL_CALLS: u16 = 1 << 0;
    /// Response has refusal
    pub const HAS_REFUSAL: u16 = 1 << 1;
    /// Content was filtered
    pub const CONTENT_FILTERED: u16 = 1 << 2;
    /// Response includes usage data
    pub const HAS_USAGE: u16 = 1 << 3;
    /// Response was truncated
    pub const TRUNCATED: u16 = 1 << 4;
    /// Response includes cached token count
    pub const HAS_CACHED_TOKENS: u16 = 1 << 5;
    /// Response includes reasoning token count
    pub const HAS_REASONING_TOKENS: u16 = 1 << 6;
    /// Response includes cost estimate
    pub const HAS_COST_ESTIMATE: u16 = 1 << 7;
    // Bits 8-15 reserved

    /// Create new empty flags
    pub fn new() -> Self {
        Self(0)
    }

    /// Create from raw bits
    pub fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub fn bits(&self) -> u16 {
        self.0
    }

    /// Set a flag
    pub fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: u16) {
        self.0 &= !flag;
    }

    /// Check if flag is set
    pub fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

/// Common flags (bits 24-31 of the 32-bit flags field)
#[derive(Debug, Clone, Copy, Default)]
pub struct CommonFlags(u8);

#[allow(missing_docs)]
impl CommonFlags {
    /// Payload is compressed
    pub const COMPRESSED: u8 = 1 << 0; // Bit 24 in full flags
    /// Frame has extensions
    pub const HAS_EXTENSIONS: u8 = 1 << 1; // Bit 25 in full flags
                                           // Bits 26-31 reserved

    /// Create new empty flags
    pub fn new() -> Self {
        Self(0)
    }

    /// Create from raw bits
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Set a flag
    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    /// Check if flag is set
    pub fn has(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Check if compressed flag is set
    pub fn is_compressed(&self) -> bool {
        self.has(Self::COMPRESSED)
    }

    /// Check if has extensions flag is set
    pub fn has_extensions(&self) -> bool {
        self.has(Self::HAS_EXTENSIONS)
    }
}

/// Combined 32-bit flags field
#[derive(Debug, Clone, Copy, Default)]
pub struct Flags {
    /// Request or Response specific flags (bits 0-15)
    pub specific: u16,
    /// Reserved (bits 16-23)
    pub reserved: u8,
    /// Common flags (bits 24-31)
    pub common: CommonFlags,
}

#[allow(missing_docs)]
impl Flags {
    /// Create new empty flags
    pub fn new() -> Self {
        Self::default()
    }

    /// Create flags for a request
    pub fn for_request(request: RequestFlags, common: CommonFlags) -> Self {
        Self {
            specific: request.bits(),
            reserved: 0,
            common,
        }
    }

    /// Create flags for a response
    pub fn for_response(response: ResponseFlags, common: CommonFlags) -> Self {
        Self {
            specific: response.bits(),
            reserved: 0,
            common,
        }
    }

    /// Encode to 4 bytes (little-endian)
    pub fn as_bytes(self) -> [u8; 4] {
        let mut bytes = [0u8; 4];
        bytes[0..2].copy_from_slice(&self.specific.to_le_bytes());
        bytes[2] = self.reserved;
        bytes[3] = self.common.bits();
        bytes
    }

    /// Encode to 4 bytes (little-endian) - for compatibility
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 4] {
        self.as_bytes()
    }

    /// Decode from 4 bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        Self {
            specific: u16::from_le_bytes([bytes[0], bytes[1]]),
            reserved: bytes[2],
            common: CommonFlags::from_bits(bytes[3]),
        }
    }

    /// Get request flags (only valid if schema is Request)
    pub fn request_flags(&self) -> RequestFlags {
        RequestFlags::from_bits(self.specific)
    }

    /// Get response flags (only valid if schema is Response)
    pub fn response_flags(&self) -> ResponseFlags {
        ResponseFlags::from_bits(self.specific)
    }

    pub fn is_compressed(&self) -> bool {
        self.common.is_compressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_flags() {
        let mut flags = RequestFlags::new();
        assert!(!flags.has(RequestFlags::HAS_SYSTEM_PROMPT));

        flags.set(RequestFlags::HAS_SYSTEM_PROMPT);
        flags.set(RequestFlags::HAS_TOOLS);

        assert!(flags.has(RequestFlags::HAS_SYSTEM_PROMPT));
        assert!(flags.has(RequestFlags::HAS_TOOLS));
        assert!(!flags.has(RequestFlags::HAS_IMAGES));
    }

    #[test]
    fn test_flags_roundtrip() {
        let mut request = RequestFlags::new();
        request.set(RequestFlags::HAS_SYSTEM_PROMPT);
        request.set(RequestFlags::STREAM_REQUESTED);
        request.set(RequestFlags::HAS_MAX_TOKENS);

        let mut common = CommonFlags::new();
        common.set(CommonFlags::COMPRESSED);

        let flags = Flags::for_request(request, common);
        let bytes = flags.to_bytes();
        let decoded = Flags::from_bytes(&bytes);

        assert_eq!(flags.specific, decoded.specific);
        assert_eq!(flags.common.bits(), decoded.common.bits());
        assert!(decoded.request_flags().has(RequestFlags::HAS_SYSTEM_PROMPT));
        assert!(decoded.is_compressed());
    }

    #[test]
    fn test_response_flags() {
        let mut flags = ResponseFlags::new();
        flags.set(ResponseFlags::HAS_USAGE);
        flags.set(ResponseFlags::HAS_COST_ESTIMATE);

        assert!(flags.has(ResponseFlags::HAS_USAGE));
        assert!(flags.has(ResponseFlags::HAS_COST_ESTIMATE));
        assert!(!flags.has(ResponseFlags::HAS_TOOL_CALLS));
    }
}
