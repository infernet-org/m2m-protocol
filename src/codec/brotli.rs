//! Brotli compression codec (Algorithm::Brotli).
//!
//! Uses Brotli compression for high compression ratios on larger payloads.
//! Output is base64-encoded for wire transmission.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use brotli::{CompressorWriter, Decompressor};
use std::io::{Read, Write};

use super::{Algorithm, CompressionResult};
use crate::error::{M2MError, Result};

/// Brotli compression quality (0-11, higher = better compression, slower)
const DEFAULT_QUALITY: u32 = 11;

/// Window size for Brotli (larger = better compression for large files)
const DEFAULT_WINDOW_SIZE: u32 = 22;

/// Brotli codec
#[derive(Clone)]
pub struct BrotliCodec {
    /// Compression quality (0-11)
    pub quality: u32,
    /// Window size (10-24)
    pub window_size: u32,
}

impl Default for BrotliCodec {
    fn default() -> Self {
        Self {
            quality: DEFAULT_QUALITY,
            window_size: DEFAULT_WINDOW_SIZE,
        }
    }
}

impl BrotliCodec {
    /// Create new Brotli codec with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create codec with custom quality
    pub fn with_quality(quality: u32) -> Self {
        Self {
            quality: quality.min(11),
            ..Default::default()
        }
    }

    /// Compress bytes to Brotli format
    pub fn compress_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut compressed = Vec::new();
        {
            let mut writer =
                CompressorWriter::new(&mut compressed, 4096, self.quality, self.window_size);
            writer
                .write_all(data)
                .map_err(|e| M2MError::Compression(e.to_string()))?;
        }
        Ok(compressed)
    }

    /// Decompress Brotli bytes
    pub fn decompress_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decompressor = Decompressor::new(data, 4096);
        let mut decompressed = Vec::new();
        decompressor
            .read_to_end(&mut decompressed)
            .map_err(|e| M2MError::Decompression(e.to_string()))?;
        Ok(decompressed)
    }

    /// Compress string to wire format: `#M2M[v3.0]|DATA:<base64>`
    pub fn compress(&self, content: &str) -> Result<CompressionResult> {
        let compressed = self.compress_bytes(content.as_bytes())?;
        let encoded = BASE64.encode(&compressed);
        let wire = format!("#M2M[v3.0]|DATA:{encoded}");
        let wire_len = wire.len();

        Ok(CompressionResult::new(
            wire,
            Algorithm::Brotli,
            content.len(),
            wire_len,
        ))
    }

    /// Decompress from wire format
    pub fn decompress(&self, wire: &str) -> Result<String> {
        let data = wire
            .strip_prefix("#M2M[v3.0]|DATA:")
            .ok_or_else(|| M2MError::InvalidMessage("Invalid Brotli wire format".to_string()))?;

        let compressed = BASE64.decode(data)?;
        let decompressed = self.decompress_bytes(&compressed)?;

        String::from_utf8(decompressed)
            .map_err(|e| M2MError::Decompression(format!("Invalid UTF-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let codec = BrotliCodec::new();
        let original =
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, world!"}]}"#;

        let result = codec.compress(original).unwrap();
        assert!(result.data.starts_with("#M2M[v3.0]|DATA:"));

        let decompressed = codec.decompress(&result.data).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compression_ratio() {
        let codec = BrotliCodec::new();

        // Repetitive content compresses well
        let original = r#"{"messages":[{"role":"user","content":"Hello"},{"role":"assistant","content":"Hi there!"},{"role":"user","content":"How are you?"},{"role":"assistant","content":"I'm doing great, thank you for asking!"}]}"#;

        let result = codec.compress(original).unwrap();

        // Brotli should achieve some compression
        println!(
            "Original: {} bytes, Compressed: {} bytes, Ratio: {:.2}",
            result.original_bytes,
            result.compressed_bytes,
            result.byte_ratio()
        );
    }

    #[test]
    fn test_bytes_roundtrip() {
        let codec = BrotliCodec::new();
        let original = b"Hello, Brotli! This is a test of byte compression.";

        let compressed = codec.compress_bytes(original).unwrap();
        let decompressed = codec.decompress_bytes(&compressed).unwrap();

        assert_eq!(decompressed, original);
    }
}
