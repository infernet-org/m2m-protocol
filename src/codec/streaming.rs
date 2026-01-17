//! Streaming compression for Server-Sent Events (SSE).
//!
//! This module handles real-time compression of streaming LLM responses,
//! processing SSE chunks as they arrive to minimize time-to-first-token.
//!
//! # SSE Format
//!
//! OpenAI-style SSE streams look like:
//! ```text
//! data: {"id":"chatcmpl-123","choices":[{"delta":{"content":"Hello"}}]}
//!
//! data: {"id":"chatcmpl-123","choices":[{"delta":{"content":" world"}}]}
//!
//! data: [DONE]
//! ```
//!
//! # Compression Strategy
//!
//! For streaming, we use lightweight token abbreviation (no Brotli) to minimize
//! latency per chunk. Full compression can be applied to the accumulated response.

use crate::codec::tables::{KEY_ABBREV, KEY_EXPAND, ROLE_ABBREV, ROLE_EXPAND};
use crate::error::{M2MError, Result};
use bytes::Bytes;
use serde_json::Value;

/// SSE event types
#[derive(Debug, Clone, PartialEq)]
pub enum SseEvent {
    /// Data event with JSON payload
    Data(Value),
    /// Stream complete marker
    Done,
    /// Comment or keep-alive
    Comment(String),
    /// Error event
    Error(String),
}

/// Streaming codec for SSE compression
///
/// Maintains state across chunks for optimal compression and
/// accumulates content for final aggregation.
#[derive(Debug)]
pub struct StreamingCodec {
    /// Accumulated content tokens
    accumulated_content: String,
    /// Total chunks processed
    chunks_processed: usize,
    /// Total bytes before compression
    bytes_in: usize,
    /// Total bytes after compression
    bytes_out: usize,
    /// Whether compression is enabled
    compress: bool,
}

impl Default for StreamingCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingCodec {
    /// Create a new streaming codec
    pub fn new() -> Self {
        Self {
            accumulated_content: String::new(),
            chunks_processed: 0,
            bytes_in: 0,
            bytes_out: 0,
            compress: true,
        }
    }

    /// Create codec with compression disabled (passthrough)
    pub fn passthrough() -> Self {
        Self {
            compress: false,
            ..Self::new()
        }
    }

    /// Parse an SSE line into an event
    pub fn parse_sse_line(&self, line: &str) -> Option<SseEvent> {
        let line = line.trim();

        if line.is_empty() {
            return None;
        }

        if line.starts_with(':') {
            return Some(SseEvent::Comment(line[1..].trim().to_string()));
        }

        if let Some(data) = line.strip_prefix("data: ") {
            if data == "[DONE]" {
                return Some(SseEvent::Done);
            }

            match serde_json::from_str(data) {
                Ok(json) => Some(SseEvent::Data(json)),
                Err(_) => Some(SseEvent::Error(format!("Invalid JSON: {}", data))),
            }
        } else if let Some(error) = line.strip_prefix("error: ") {
            Some(SseEvent::Error(error.to_string()))
        } else {
            None
        }
    }

    /// Process a raw SSE chunk (may contain multiple events)
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>> {
        let text = std::str::from_utf8(chunk)
            .map_err(|e| M2MError::Compression(format!("Invalid UTF-8: {}", e)))?;

        self.bytes_in += chunk.len();

        let mut outputs = Vec::new();

        for line in text.lines() {
            if let Some(event) = self.parse_sse_line(line) {
                let output = self.process_event(event)?;
                if let Some(bytes) = output {
                    self.bytes_out += bytes.len();
                    outputs.push(bytes);
                }
            }
        }

        self.chunks_processed += 1;
        Ok(outputs)
    }

    /// Process a single SSE event
    fn process_event(&mut self, event: SseEvent) -> Result<Option<Bytes>> {
        match event {
            SseEvent::Data(json) => {
                // Extract and accumulate content
                if let Some(content) = self.extract_delta_content(&json) {
                    self.accumulated_content.push_str(&content);
                }

                if self.compress {
                    // Compress the JSON
                    let compressed = self.compress_sse_json(&json)?;
                    Ok(Some(Bytes::from(format!("data: {}\n\n", compressed))))
                } else {
                    // Passthrough
                    Ok(Some(Bytes::from(format!(
                        "data: {}\n\n",
                        serde_json::to_string(&json).unwrap_or_default()
                    ))))
                }
            },
            SseEvent::Done => Ok(Some(Bytes::from_static(b"data: [DONE]\n\n"))),
            SseEvent::Comment(c) => Ok(Some(Bytes::from(format!(": {}\n", c)))),
            SseEvent::Error(e) => Ok(Some(Bytes::from(format!("error: {}\n\n", e)))),
        }
    }

    /// Extract delta content from a streaming response
    fn extract_delta_content(&self, json: &Value) -> Option<String> {
        json.get("choices")?
            .get(0)?
            .get("delta")?
            .get("content")?
            .as_str()
            .map(String::from)
    }

    /// Compress SSE JSON using lightweight token abbreviation
    fn compress_sse_json(&self, json: &Value) -> Result<String> {
        let compressed = self.abbreviate_keys(json);
        serde_json::to_string(&compressed)
            .map_err(|e| M2MError::Compression(format!("JSON serialization failed: {}", e)))
    }

    /// Recursively abbreviate JSON keys
    fn abbreviate_keys(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let key_str = key.as_str();
                    let new_key = KEY_ABBREV.get(key_str).copied().unwrap_or(key_str);
                    let new_val = self.abbreviate_keys(val);

                    // Special handling for role values
                    let new_val = if key == "role" {
                        if let Value::String(role) = &new_val {
                            if let Some(abbrev) = ROLE_ABBREV.get(role.as_str()) {
                                Value::String((*abbrev).to_string())
                            } else {
                                new_val
                            }
                        } else {
                            new_val
                        }
                    } else {
                        new_val
                    };

                    new_map.insert(new_key.to_string(), new_val);
                }
                Value::Object(new_map)
            },
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.abbreviate_keys(v)).collect())
            },
            _ => value.clone(),
        }
    }

    /// Get accumulated content from all chunks
    pub fn accumulated_content(&self) -> &str {
        &self.accumulated_content
    }

    /// Get compression statistics
    pub fn stats(&self) -> StreamingStats {
        StreamingStats {
            chunks_processed: self.chunks_processed,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            compression_ratio: if self.bytes_in > 0 {
                self.bytes_out as f64 / self.bytes_in as f64
            } else {
                1.0
            },
            accumulated_length: self.accumulated_content.len(),
        }
    }

    /// Reset the codec state
    pub fn reset(&mut self) {
        self.accumulated_content.clear();
        self.chunks_processed = 0;
        self.bytes_in = 0;
        self.bytes_out = 0;
    }
}

/// Statistics from streaming compression
#[derive(Debug, Clone)]
pub struct StreamingStats {
    /// Number of SSE chunks processed
    pub chunks_processed: usize,
    /// Total input bytes
    pub bytes_in: usize,
    /// Total output bytes
    pub bytes_out: usize,
    /// Compression ratio (output/input)
    pub compression_ratio: f64,
    /// Length of accumulated content
    pub accumulated_length: usize,
}

/// Streaming decompressor for expanding abbreviated SSE
#[derive(Debug, Default)]
pub struct StreamingDecompressor {
    /// Accumulated content
    accumulated_content: String,
}

impl StreamingDecompressor {
    /// Create a new decompressor
    pub fn new() -> Self {
        Self::default()
    }

    /// Decompress an SSE chunk
    pub fn decompress_chunk(&mut self, chunk: &[u8]) -> Result<Bytes> {
        let text = std::str::from_utf8(chunk)
            .map_err(|e| M2MError::Decompression(format!("Invalid UTF-8: {}", e)))?;

        let mut output = String::new();

        for line in text.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if data == "[DONE]" {
                    output.push_str("data: [DONE]\n\n");
                } else if let Ok(json) = serde_json::from_str::<Value>(data) {
                    let expanded = self.expand_keys(&json);

                    // Extract content for accumulation
                    if let Some(content) = self.extract_delta_content(&expanded) {
                        self.accumulated_content.push_str(&content);
                    }

                    output.push_str(&format!(
                        "data: {}\n\n",
                        serde_json::to_string(&expanded).unwrap_or_default()
                    ));
                } else {
                    // Pass through invalid JSON as-is
                    output.push_str(line);
                    output.push_str("\n\n");
                }
            } else if !line.is_empty() {
                output.push_str(line);
                output.push('\n');
            }
        }

        Ok(Bytes::from(output))
    }

    /// Expand abbreviated keys back to full form
    fn expand_keys(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    let key_str = key.as_str();
                    let new_key = KEY_EXPAND.get(key_str).copied().unwrap_or(key_str);
                    let new_val = self.expand_keys(val);

                    // Special handling for role values
                    let new_val = if new_key == "role" {
                        if let Value::String(role) = &new_val {
                            if let Some(expanded) = ROLE_EXPAND.get(role.as_str()) {
                                Value::String((*expanded).to_string())
                            } else {
                                new_val
                            }
                        } else {
                            new_val
                        }
                    } else {
                        new_val
                    };

                    new_map.insert(new_key.to_string(), new_val);
                }
                Value::Object(new_map)
            },
            Value::Array(arr) => Value::Array(arr.iter().map(|v| self.expand_keys(v)).collect()),
            _ => value.clone(),
        }
    }

    /// Extract delta content
    fn extract_delta_content(&self, json: &Value) -> Option<String> {
        json.get("choices")?
            .get(0)?
            .get("delta")?
            .get("content")?
            .as_str()
            .map(String::from)
    }

    /// Get accumulated content
    pub fn accumulated_content(&self) -> &str {
        &self.accumulated_content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sse_data() {
        let codec = StreamingCodec::new();

        let line = r#"data: {"id":"123","choices":[{"delta":{"content":"Hi"}}]}"#;
        let event = codec.parse_sse_line(line);

        assert!(matches!(event, Some(SseEvent::Data(_))));
    }

    #[test]
    fn test_parse_sse_done() {
        let codec = StreamingCodec::new();

        let event = codec.parse_sse_line("data: [DONE]");
        assert_eq!(event, Some(SseEvent::Done));
    }

    #[test]
    fn test_parse_sse_comment() {
        let codec = StreamingCodec::new();

        let event = codec.parse_sse_line(": keep-alive");
        assert_eq!(event, Some(SseEvent::Comment("keep-alive".to_string())));
    }

    #[test]
    fn test_compress_sse_chunk() {
        let mut codec = StreamingCodec::new();

        let chunk = br#"data: {"id":"chatcmpl-123","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"}}]}

"#;

        let outputs = codec.process_chunk(chunk).unwrap();
        assert_eq!(outputs.len(), 1);

        let output = std::str::from_utf8(&outputs[0]).unwrap();
        assert!(output.starts_with("data: "));
        // Should have abbreviated keys
        assert!(output.contains("\"I\":")); // id -> I
        assert!(output.contains("\"C\":")); // choices -> C
        assert!(output.contains("\"D\":")); // delta -> D
    }

    #[test]
    fn test_accumulate_content() {
        let mut codec = StreamingCodec::new();

        let chunks = vec![
            br#"data: {"choices":[{"delta":{"content":"Hello"}}]}"#.as_slice(),
            br#"data: {"choices":[{"delta":{"content":" world"}}]}"#.as_slice(),
            br#"data: {"choices":[{"delta":{"content":"!"}}]}"#.as_slice(),
        ];

        for chunk in chunks {
            codec.process_chunk(chunk).unwrap();
        }

        assert_eq!(codec.accumulated_content(), "Hello world!");
    }

    #[test]
    fn test_streaming_stats() {
        let mut codec = StreamingCodec::new();

        let chunk = br#"data: {"id":"123","choices":[{"delta":{"content":"Test"}}]}"#;
        codec.process_chunk(chunk).unwrap();

        let stats = codec.stats();
        assert_eq!(stats.chunks_processed, 1);
        assert!(stats.bytes_in > 0);
        assert!(stats.bytes_out > 0);
        assert!(stats.compression_ratio < 1.0); // Should compress
    }

    #[test]
    fn test_decompress_chunk() {
        let mut decompressor = StreamingDecompressor::new();

        // Abbreviated SSE
        let chunk = br#"data: {"I":"123","C":[{"D":{"c":"Hello"}}]}"#;
        let output = decompressor.decompress_chunk(chunk).unwrap();

        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.contains("\"id\":")); // I -> id
        assert!(text.contains("\"choices\":")); // C -> choices
        assert!(text.contains("\"delta\":")); // D -> delta
    }

    #[test]
    fn test_roundtrip() {
        let mut codec = StreamingCodec::new();
        let mut decompressor = StreamingDecompressor::new();

        let original = br#"data: {"id":"chatcmpl-123","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello world"}}]}

"#;

        // Compress
        let compressed = codec.process_chunk(original).unwrap();
        assert!(!compressed.is_empty());

        // Decompress
        let decompressed = decompressor.decompress_chunk(&compressed[0]).unwrap();

        // Parse both and compare structure
        let orig_text = std::str::from_utf8(original).unwrap();
        let decomp_text = std::str::from_utf8(&decompressed).unwrap();

        // Extract JSON from both
        let orig_json: Value =
            serde_json::from_str(orig_text.strip_prefix("data: ").unwrap().trim()).unwrap();
        let decomp_json: Value =
            serde_json::from_str(decomp_text.strip_prefix("data: ").unwrap().trim()).unwrap();

        // Content should match
        assert_eq!(
            orig_json["choices"][0]["delta"]["content"],
            decomp_json["choices"][0]["delta"]["content"]
        );
    }

    #[test]
    fn test_passthrough_mode() {
        let mut codec = StreamingCodec::passthrough();

        let chunk = br#"data: {"id":"123","choices":[{"delta":{"content":"Test"}}]}"#;
        let outputs = codec.process_chunk(chunk).unwrap();

        let output = std::str::from_utf8(&outputs[0]).unwrap();
        // Should NOT have abbreviated keys
        assert!(output.contains("\"id\":")); // Not abbreviated
        assert!(output.contains("\"choices\":")); // Not abbreviated
    }
}
