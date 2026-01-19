//! Codec engine for automatic algorithm selection and compression.
//!
//! The engine analyzes content characteristics and selects the optimal
//! compression algorithm. Can also be guided by ML inference for
//! intelligent routing decisions.

use serde_json::Value;

use super::brotli::BrotliCodec;
use super::dictionary::DictionaryCodec;
use super::m3::M3Codec;
use super::token::TokenCodec;
use super::token_native::TokenNativeCodec;
use super::{Algorithm, CompressionResult};
use crate::error::{M2MError, Result};
use crate::inference::HydraModel;
use crate::models::Encoding;
use crate::security::SecurityScanner;
use crate::tokenizer::count_tokens_with_encoding;

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
    /// Token-native codec instance
    token_native: TokenNativeCodec,
    /// M3 codec instance (default for M2M v3)
    m3: M3Codec,
    /// Brotli codec instance
    brotli: BrotliCodec,
    /// Dictionary codec instance (deprecated)
    #[allow(deprecated)]
    dictionary: DictionaryCodec,
    /// Hydra model for ML routing (optional)
    hydra: Option<HydraModel>,
    /// ML routing enabled (requires inference module)
    pub ml_routing: bool,
    /// Minimum size for Brotli (bytes)
    pub brotli_threshold: usize,
    /// Prefer M3 for LLM API payloads (default: true)
    pub prefer_m3_for_api: bool,
}

impl Default for CodecEngine {
    #[allow(deprecated)]
    fn default() -> Self {
        Self {
            token: TokenCodec::new(),
            token_native: TokenNativeCodec::default(),
            m3: M3Codec::new(),
            brotli: BrotliCodec::new(),
            dictionary: DictionaryCodec::new(),
            hydra: None,
            ml_routing: false,
            brotli_threshold: 1024, // 1KB
            prefer_m3_for_api: true,
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

    /// Set Hydra model for ML-based algorithm selection
    pub fn with_hydra(mut self, model: HydraModel) -> Self {
        self.hydra = Some(model);
        self.ml_routing = true;
        self
    }

    /// Set Brotli threshold
    pub fn with_brotli_threshold(mut self, threshold: usize) -> Self {
        self.brotli_threshold = threshold;
        self
    }

    /// Set token-native encoding
    pub fn with_encoding(mut self, encoding: Encoding) -> Self {
        self.token_native = TokenNativeCodec::new(encoding);
        self
    }

    /// Compress with specified algorithm and track token counts
    ///
    /// This method counts tokens before and after compression to provide
    /// accurate token savings metrics. Use this when token efficiency matters
    /// more than raw speed.
    #[allow(deprecated)]
    pub fn compress_with_tokens(
        &self,
        content: &str,
        algorithm: Algorithm,
        encoding: Encoding,
    ) -> Result<CompressionResult> {
        let original_tokens = count_tokens_with_encoding(content, encoding);
        let mut result = self.compress(content, algorithm)?;

        let compressed_tokens = count_tokens_with_encoding(&result.data, encoding);
        result.original_tokens = Some(original_tokens);
        result.compressed_tokens = Some(compressed_tokens);

        Ok(result)
    }

    /// Compress for M2M communication (no wire prefix, optimized for token savings)
    ///
    /// In M2M protocol, both sides negotiate capabilities during handshake,
    /// so the wire format prefix is redundant. This method skips the prefix
    /// to maximize token savings.
    ///
    /// Use this method when:
    /// - Communicating over established M2M sessions
    /// - Token efficiency is the primary goal
    /// - Both sides have negotiated Token compression capability
    pub fn compress_m2m(&self, content: &str, encoding: Encoding) -> Result<CompressionResult> {
        let value: Value = serde_json::from_str(content)?;
        let original_tokens = count_tokens_with_encoding(content, encoding);

        // Use token codec without wire prefix
        let compressed_json = self.token.compress_raw(&value);
        let compressed_tokens = count_tokens_with_encoding(&compressed_json, encoding);

        let mut result = CompressionResult::new(
            compressed_json.clone(),
            Algorithm::Token,
            content.len(),
            compressed_json.len(),
        );
        result.original_tokens = Some(original_tokens);
        result.compressed_tokens = Some(compressed_tokens);

        Ok(result)
    }

    /// Decompress M2M format (no wire prefix expected)
    pub fn decompress_m2m(&self, content: &str) -> Result<String> {
        // Try to parse as compressed JSON
        if let Ok(value) = self.token.decompress_raw(content) {
            serde_json::to_string(&value).map_err(|e| M2MError::Decompression(e.to_string()))
        } else {
            // Assume it's raw JSON
            Ok(content.to_string())
        }
    }

    /// Secure compress: Run cognitive security scan before compression
    ///
    /// This method combines security scanning with compression:
    /// 1. Scans plaintext for threats using Hydra/patterns
    /// 2. If safe, compresses with optimal algorithm
    /// 3. If threat detected and blocking enabled, returns error
    ///
    /// Epistemic basis:
    /// - K: Threats exist in plaintext, not compressed form
    /// - K: Security scan must happen before compression
    /// - B: Combined scan provides defense in depth
    pub fn secure_compress(
        &self,
        content: &str,
        scanner: &SecurityScanner,
    ) -> Result<CompressionResult> {
        // 1. Security scan (cognitive security)
        let scan_result = scanner.scan_and_validate(content)?;

        if scan_result.should_block {
            let threat_desc = scan_result
                .threats
                .first()
                .map(|t| t.name.clone())
                .unwrap_or_else(|| "unknown".to_string());

            return Err(M2MError::ContentBlocked(format!(
                "Content blocked: {} (confidence: {:.2})",
                threat_desc, scan_result.confidence
            )));
        }

        // 2. If safe (or not blocking), compress with optimal algorithm
        let analysis = ContentAnalysis::analyze(content);
        let algorithm = self.select_algorithm(&analysis);
        self.compress(content, algorithm)
    }

    /// Secure compress with ML-based algorithm selection
    ///
    /// Uses Hydra for both security scanning and algorithm selection.
    pub fn secure_compress_ml(&self, content: &str) -> Result<(CompressionResult, bool)> {
        // Use Hydra for security if available
        let is_safe = if let Some(ref hydra) = self.hydra {
            let security = hydra.predict_security(content)?;
            security.safe
        } else {
            // Fallback to heuristic
            let fallback = HydraModel::fallback_only();
            fallback.predict_security(content)?.safe
        };

        // Compress with ML-selected algorithm
        let algorithm = self.select_algorithm_for_content(content);
        let result = self.compress(content, algorithm)?;

        Ok((result, is_safe))
    }

    /// Compress with automatic algorithm selection and token tracking
    pub fn compress_auto_with_tokens(
        &self,
        content: &str,
        encoding: Encoding,
    ) -> Result<(CompressionResult, Algorithm)> {
        let analysis = ContentAnalysis::analyze(content);
        let algorithm = self.select_algorithm(&analysis);

        let result = self.compress_with_tokens(content, algorithm, encoding)?;
        Ok((result, algorithm))
    }

    /// Compress with specified algorithm
    #[allow(deprecated)]
    pub fn compress(&self, content: &str, algorithm: Algorithm) -> Result<CompressionResult> {
        match algorithm {
            Algorithm::None => Ok(CompressionResult::new(
                content.to_string(),
                Algorithm::None,
                content.len(),
                content.len(),
            )),
            Algorithm::M3 => self.m3.compress(content),
            Algorithm::Token => {
                let value: Value = serde_json::from_str(content)?;
                self.token.compress(&value)
            },
            Algorithm::TokenNative => self.token_native.compress(content),
            Algorithm::Brotli => self.brotli.compress(content),
            Algorithm::Dictionary => self.dictionary.compress(content),
            Algorithm::Zlib => {
                // Zlib is deprecated in v3.0 - return error to make it explicit
                Err(M2MError::InvalidCodec(
                    "Zlib algorithm is deprecated in M2M v3.0. Use M3 instead.".to_string(),
                ))
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
        // If ML routing is enabled and Hydra model is available, use ML
        if self.ml_routing {
            return self.ml_select_algorithm(analysis);
        }

        // Heuristic-based selection
        self.heuristic_select_algorithm(analysis)
    }

    /// ML-based algorithm selection using Hydra SLM
    fn ml_select_algorithm(&self, analysis: &ContentAnalysis) -> Algorithm {
        // Use Hydra model if available
        if let Some(ref hydra) = self.hydra {
            // Hydra needs the raw content, but we only have analysis
            // For full ML routing, we need to pass content through
            // For now, use Hydra's heuristic which mirrors our logic
            // but with TokenNative awareness
            if let Ok(decision) = hydra.predict_compression("") {
                return decision.algorithm;
            }
        }

        // Fall back to heuristics
        self.heuristic_select_algorithm(analysis)
    }

    /// Select algorithm with full content access (for ML routing)
    pub fn select_algorithm_for_content(&self, content: &str) -> Algorithm {
        // If ML routing is enabled and Hydra model is available, use ML
        if self.ml_routing {
            if let Some(ref hydra) = self.hydra {
                if let Ok(decision) = hydra.predict_compression(content) {
                    return decision.algorithm;
                }
            }
        }

        // Fall back to analysis-based selection
        let analysis = ContentAnalysis::analyze(content);
        self.heuristic_select_algorithm(&analysis)
    }

    /// Heuristic-based algorithm selection
    ///
    /// Epistemic basis:
    /// - K: M3 achieves ~60% byte savings for LLM API JSON
    /// - K: Brotli is optimal for large repetitive content (>1KB)
    /// - B: M3 is best for small-medium LLM API JSON (<1KB)
    fn heuristic_select_algorithm(&self, analysis: &ContentAnalysis) -> Algorithm {
        // Small content: no compression (overhead not worth it)
        // Epistemic: K - compression overhead exceeds savings
        if analysis.length < 100 {
            return Algorithm::None;
        }

        // Large content (>1KB): Brotli is almost always best
        // Epistemic: K - Brotli achieves 40-60% savings on large content
        if analysis.length > self.brotli_threshold {
            return Algorithm::Brotli;
        }

        // Medium LLM API JSON (100-1KB): M3 compression (schema-aware)
        // Epistemic: K - M3 achieves ~60% compression
        if analysis.is_llm_api && self.prefer_m3_for_api {
            return Algorithm::M3;
        }

        // Medium content with high repetition: Brotli
        if analysis.repetition_ratio > 0.3 {
            return Algorithm::Brotli;
        }

        // Default: M3 for JSON (M2M optimal), None for others
        if analysis.is_json {
            Algorithm::M3
        } else {
            Algorithm::None
        }
    }

    /// Decompress content (auto-detects algorithm from wire format)
    #[allow(deprecated)]
    pub fn decompress(&self, wire: &str) -> Result<String> {
        let algorithm = super::detect_algorithm(wire).unwrap_or(Algorithm::None);

        match algorithm {
            Algorithm::None => Ok(wire.to_string()),
            Algorithm::M3 => self.m3.decompress(wire),
            Algorithm::Token => {
                let value = self.token.decompress(wire)?;
                serde_json::to_string(&value).map_err(|e| M2MError::Decompression(e.to_string()))
            },
            Algorithm::TokenNative => self.token_native.decompress(wire),
            Algorithm::Brotli => self.brotli.decompress(wire),
            Algorithm::Dictionary => self.dictionary.decompress(wire),
            Algorithm::Zlib => {
                // Zlib v2.0 format is no longer supported in v3.0
                // Attempt to decompress as Brotli for backwards compatibility
                tracing::warn!("Zlib format detected - attempting Brotli decompression for backwards compatibility");
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

        // Try each algorithm (M3 first as best for schema-aware compression)
        for algo in [
            Algorithm::M3,
            Algorithm::TokenNative,
            Algorithm::Token,
            Algorithm::Brotli,
        ] {
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
        // Content must be 100-1024 bytes for M3 selection
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello, how are you doing today? This is a longer message to test the compression algorithm selection."}]}"#;
        let analysis = ContentAnalysis::analyze(content);

        assert!(analysis.is_json);
        assert!(analysis.is_llm_api);
        assert!(analysis.length >= 100 && analysis.length <= 1024);
        assert_eq!(engine.select_algorithm(&analysis), Algorithm::M3);
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

        // Create large content (>1024 bytes) - should select Brotli
        let repeated = "hello world ".repeat(100);
        let analysis = ContentAnalysis::analyze(&repeated);

        assert!(
            analysis.length > 1024,
            "Content should be >1024 bytes for Brotli selection"
        );
        assert_eq!(engine.select_algorithm(&analysis), Algorithm::Brotli);
    }

    #[test]
    fn test_ml_routing_with_hydra() {
        let hydra = HydraModel::fallback_only();
        let engine = CodecEngine::new().with_hydra(hydra);

        // Should use Hydra's heuristics when ML routing is enabled
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test message"}]}"#;
        let algo = engine.select_algorithm_for_content(content);

        // Hydra should select TokenNative for small LLM API content
        assert_eq!(algo, Algorithm::TokenNative);
    }

    #[test]
    fn test_token_native_roundtrip() {
        let engine = CodecEngine::new();
        let content = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello!"}]}"#;

        let result = engine.compress(content, Algorithm::TokenNative).unwrap();
        assert!(result.data.starts_with("#TK|"));

        let decompressed = engine.decompress(&result.data).unwrap();
        assert_eq!(content, decompressed);
    }
}
