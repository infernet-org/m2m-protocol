//! Codec engine for automatic algorithm selection and compression.
//!
//! The engine analyzes content characteristics and selects the optimal
//! compression algorithm. Can also be guided by ML inference for
//! intelligent routing decisions.

use serde_json::Value;

use super::brotli::BrotliCodec;
use super::dictionary::DictionaryCodec;
use super::token::TokenCodec;
use super::{Algorithm, CompressionResult};
use crate::error::{M2MError, Result};

/// Content characteristics for algorithm selection
#[derive(Debug, Clone)]
pub struct ContentAnalysis {
    /// Content length in bytes
    pub length: usize,
    /// Is valid JSON
    pub is_json: bool,
    /// Has LLM API structure (messages, model, etc.)
    pub is_llm_api: bool,
    /// Repetition ratio (0.0 = unique, 1.0 = highly repetitive)
    pub repetition_ratio: f32,
    /// Has tool/function calls
    pub has_tools: bool,
    /// Estimated token count
    pub estimated_tokens: usize,
}

impl ContentAnalysis {
    /// Analyze content for compression characteristics
    pub fn analyze(content: &str) -> Self {
        let length = content.len();
        let parsed: Option<Value> = serde_json::from_str(content).ok();
        let is_json = parsed.is_some();

        let (is_llm_api, has_tools) = if let Some(ref value) = parsed {
            let is_api = value.get("messages").is_some()
                || value.get("model").is_some()
                || value.get("choices").is_some();
            let tools = value.get("tools").is_some()
                || value.get("tool_calls").is_some()
                || value.get("functions").is_some();
            (is_api, tools)
        } else {
            (false, false)
        };

        // Simple repetition detection
        let repetition_ratio = Self::calculate_repetition(content);

        // Rough token estimate (chars / 4 for English)
        let estimated_tokens = length / 4;

        Self {
            length,
            is_json,
            is_llm_api,
            repetition_ratio,
            has_tools,
            estimated_tokens,
        }
    }

    fn calculate_repetition(content: &str) -> f32 {
        if content.len() < 100 {
            return 0.0;
        }

        // Count unique 4-grams
        let mut seen = std::collections::HashSet::new();
        let chars: Vec<char> = content.chars().collect();
        let total = chars.len().saturating_sub(3);

        if total == 0 {
            return 0.0;
        }

        for window in chars.windows(4) {
            let gram: String = window.iter().collect();
            seen.insert(gram);
        }

        1.0 - (seen.len() as f32 / total as f32)
    }
}

/// Codec engine with automatic algorithm selection
#[derive(Clone)]
pub struct CodecEngine {
    /// Token codec instance
    token: TokenCodec,
    /// Brotli codec instance
    brotli: BrotliCodec,
    /// Dictionary codec instance
    dictionary: DictionaryCodec,
    /// ML routing enabled (requires inference module)
    pub ml_routing: bool,
    /// Minimum size for Brotli (bytes)
    pub brotli_threshold: usize,
    /// Prefer token compression for LLM API payloads
    pub prefer_token_for_api: bool,
}

impl Default for CodecEngine {
    fn default() -> Self {
        Self {
            token: TokenCodec::new(),
            brotli: BrotliCodec::new(),
            dictionary: DictionaryCodec::new(),
            ml_routing: false,
            brotli_threshold: 1024, // 1KB
            prefer_token_for_api: true,
        }
    }
}

impl CodecEngine {
    /// Create new codec engine
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable ML-based routing (requires loaded model)
    pub fn with_ml_routing(mut self, enabled: bool) -> Self {
        self.ml_routing = enabled;
        self
    }

    /// Set Brotli threshold
    pub fn with_brotli_threshold(mut self, threshold: usize) -> Self {
        self.brotli_threshold = threshold;
        self
    }

    /// Compress with specified algorithm
    pub fn compress(&self, content: &str, algorithm: Algorithm) -> Result<CompressionResult> {
        match algorithm {
            Algorithm::None => Ok(CompressionResult::new(
                content.to_string(),
                Algorithm::None,
                content.len(),
                content.len(),
            )),
            Algorithm::Token => {
                let value: Value = serde_json::from_str(content)?;
                self.token.compress(&value)
            },
            Algorithm::Brotli => self.brotli.compress(content),
            Algorithm::Dictionary => self.dictionary.compress(content),
            Algorithm::Zlib => {
                // Zlib not yet implemented, fall back to Brotli
                self.brotli.compress(content)
            },
        }
    }

    /// Compress with automatic algorithm selection
    pub fn compress_auto(&self, content: &str) -> Result<(CompressionResult, Algorithm)> {
        let analysis = ContentAnalysis::analyze(content);
        let algorithm = self.select_algorithm(&analysis);

        let result = self.compress(content, algorithm)?;
        Ok((result, algorithm))
    }

    /// Compress JSON value with automatic selection
    pub fn compress_value(&self, value: &Value) -> Result<(CompressionResult, Algorithm)> {
        let content = serde_json::to_string(value)?;
        self.compress_auto(&content)
    }

    /// Select optimal algorithm based on content analysis
    pub fn select_algorithm(&self, analysis: &ContentAnalysis) -> Algorithm {
        // If ML routing is enabled, defer to inference module
        // (This will be implemented when inference module is ready)
        if self.ml_routing {
            return self.ml_select_algorithm(analysis);
        }

        // Heuristic-based selection
        self.heuristic_select_algorithm(analysis)
    }

    /// ML-based algorithm selection (placeholder for inference integration)
    fn ml_select_algorithm(&self, analysis: &ContentAnalysis) -> Algorithm {
        // TODO: Integrate with inference module
        // For now, fall back to heuristics
        self.heuristic_select_algorithm(analysis)
    }

    /// Heuristic-based algorithm selection
    fn heuristic_select_algorithm(&self, analysis: &ContentAnalysis) -> Algorithm {
        // LLM API JSON: token compression (even for small content)
        if analysis.is_llm_api && self.prefer_token_for_api {
            return Algorithm::Token;
        }

        // Small content: no compression
        if analysis.length < 100 {
            return Algorithm::None;
        }

        // Large content with high repetition: Brotli
        if analysis.length > self.brotli_threshold && analysis.repetition_ratio > 0.3 {
            return Algorithm::Brotli;
        }

        // Structured JSON with patterns: Dictionary
        if analysis.is_json && analysis.has_tools {
            return Algorithm::Dictionary;
        }

        // Default: Token for JSON, Brotli for large content
        if analysis.is_json {
            Algorithm::Token
        } else if analysis.length > self.brotli_threshold {
            Algorithm::Brotli
        } else {
            Algorithm::None
        }
    }

    /// Decompress content (auto-detects algorithm from wire format)
    pub fn decompress(&self, wire: &str) -> Result<String> {
        let algorithm = super::detect_algorithm(wire).unwrap_or(Algorithm::None);

        match algorithm {
            Algorithm::None => Ok(wire.to_string()),
            Algorithm::Token => {
                let value = self.token.decompress(wire)?;
                serde_json::to_string(&value).map_err(|e| M2MError::Decompression(e.to_string()))
            },
            Algorithm::Brotli => self.brotli.decompress(wire),
            Algorithm::Dictionary => self.dictionary.decompress(wire),
            Algorithm::Zlib => {
                // Zlib shares format with Brotli for now
                self.brotli.decompress(wire)
            },
        }
    }

    /// Decompress to JSON value
    pub fn decompress_value(&self, wire: &str) -> Result<Value> {
        let json = self.decompress(wire)?;
        serde_json::from_str(&json).map_err(|e| M2MError::Decompression(e.to_string()))
    }

    /// Try all algorithms and return best result
    pub fn compress_best(&self, content: &str) -> Result<CompressionResult> {
        let mut best: Option<CompressionResult> = None;

        // Try each algorithm
        for algo in [Algorithm::Token, Algorithm::Brotli, Algorithm::Dictionary] {
            if let Ok(result) = self.compress(content, algo) {
                let is_better = match &best {
                    None => true,
                    Some(current) => result.compressed_bytes < current.compressed_bytes,
                };

                if is_better {
                    best = Some(result);
                }
            }
        }

        best.ok_or_else(|| M2MError::Compression("All algorithms failed".to_string()))
    }

    /// Get analysis for content
    pub fn analyze(&self, content: &str) -> ContentAnalysis {
        ContentAnalysis::analyze(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_select_small() {
        let engine = CodecEngine::new();
        let analysis = ContentAnalysis::analyze("small");
        assert_eq!(engine.select_algorithm(&analysis), Algorithm::None);
    }

    #[test]
    fn test_auto_select_llm_api() {
        let engine = CodecEngine::new();
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
        let analysis = ContentAnalysis::analyze(content);

        assert!(analysis.is_json);
        assert!(analysis.is_llm_api);
        assert_eq!(engine.select_algorithm(&analysis), Algorithm::Token);
    }

    #[test]
    fn test_compress_decompress_auto() {
        let engine = CodecEngine::new();
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, how are you doing today?"}],"temperature":0.7}"#;

        let (result, algo) = engine.compress_auto(content).unwrap();
        println!("Selected algorithm: {algo:?}");
        println!(
            "Original: {} bytes, Compressed: {} bytes",
            result.original_bytes, result.compressed_bytes
        );

        let decompressed = engine.decompress(&result.data).unwrap();
        let original: Value = serde_json::from_str(content).unwrap();
        let recovered: Value = serde_json::from_str(&decompressed).unwrap();

        // Core content should match
        assert_eq!(
            original["messages"][0]["content"],
            recovered["messages"][0]["content"]
        );
    }

    #[test]
    fn test_compress_best() {
        let engine = CodecEngine::new();
        let content = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is the capital of France?"},{"role":"assistant","content":"The capital of France is Paris."}]}"#;

        let result = engine.compress_best(content).unwrap();
        println!(
            "Best algorithm: {:?}, ratio: {:.2}",
            result.algorithm,
            result.byte_ratio()
        );
    }

    #[test]
    fn test_content_analysis() {
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"test"}],"tools":[{"type":"function"}]}"#;
        let analysis = ContentAnalysis::analyze(content);

        assert!(analysis.is_json);
        assert!(analysis.is_llm_api);
        assert!(analysis.has_tools);
    }

    #[test]
    fn test_large_content_selects_brotli() {
        let engine = CodecEngine::new();

        // Create large repetitive content
        let repeated = "hello world ".repeat(200);
        let analysis = ContentAnalysis::analyze(&repeated);

        assert!(analysis.length > engine.brotli_threshold);
        assert!(analysis.repetition_ratio > 0.3);
        assert_eq!(engine.select_algorithm(&analysis), Algorithm::Brotli);
    }
}
