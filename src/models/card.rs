//! Model card data structures.
//!
//! This module defines the core types for model metadata:
//! - `ModelCard`: Complete model metadata including abbreviation, encoding, etc.
//! - `Provider`: LLM provider enum for models with accessible tokenizers
//! - `Encoding`: Tokenizer encoding type (cl100k_base, o200k_base, llama_bpe, etc.)
//! - `Pricing`: Token pricing information
//!
//! Note: Only models with publicly accessible tokenizers are supported.
//! This includes OpenAI (via tiktoken) and open source models (Llama, Mistral, etc.).
//! Closed tokenizer models (Anthropic, Google, X.AI, Cohere) are excluded.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// LLM provider categorization
///
/// Only providers with publicly available tokenizers are supported.
/// This ensures accurate token counting for M2M compression optimization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// OpenAI models (GPT-5.x, GPT-4.x, o1-o4) - tokenizer available via tiktoken
    OpenAI,
    /// Meta Llama models (Llama 4, 3.x)
    Meta,
    /// Mistral AI models (Large, Ministral, Devstral, Codestral)
    Mistral,
    /// DeepSeek models (v3.2, R1)
    DeepSeek,
    /// Qwen models (3, 2.5, coder)
    Qwen,
    /// Nvidia models (Nemotron 3 - Llama-based)
    Nvidia,
    /// Google Gemma models (open source, NOT Gemini)
    Google,
    /// Allen AI OLMo models (fully open source)
    AllenAI,
    /// Other/unknown provider
    #[default]
    Other,
}

impl Provider {
    /// Get the abbreviation prefix for this provider
    ///
    /// These prefixes are used in model abbreviations:
    /// - `o` = OpenAI (e.g., `og4o` for gpt-4o)
    /// - `m` = Meta (e.g., `ml3170i` for llama-3.1-70b-instruct)
    /// - `mi` = Mistral (e.g., `mim-l` for mistral-large)
    /// - `d` = DeepSeek (e.g., `dv3` for deepseek-v3)
    /// - `q` = Qwen (e.g., `qq2572` for qwen-2.5-72b)
    /// - `n` = Nvidia (e.g., `nn70` for nemotron-70b)
    /// - `g` = Google Gemma (e.g., `gg327` for gemma-3-27b)
    /// - `a` = Allen AI (e.g., `aolmo` for olmo)
    pub fn prefix(&self) -> &'static str {
        match self {
            Provider::OpenAI => "o",
            Provider::Meta => "m",
            Provider::Mistral => "mi",
            Provider::DeepSeek => "d",
            Provider::Qwen => "q",
            Provider::Nvidia => "n",
            Provider::Google => "g",
            Provider::AllenAI => "a",
            Provider::Other => "_",
        }
    }

    /// Parse provider from model ID prefix
    ///
    /// # Examples
    /// ```
    /// use m2m::models::Provider;
    ///
    /// assert_eq!(Provider::from_model_id("openai/gpt-4o"), Provider::OpenAI);
    /// assert_eq!(Provider::from_model_id("meta-llama/llama-3.1-70b"), Provider::Meta);
    /// assert_eq!(Provider::from_model_id("mistralai/mistral-large"), Provider::Mistral);
    /// ```
    pub fn from_model_id(id: &str) -> Self {
        let prefix = id.split('/').next().unwrap_or(id);
        let model_name = id.split('/').nth(1).unwrap_or("");
        match prefix {
            "openai" => Provider::OpenAI,
            "meta-llama" => Provider::Meta,
            "mistralai" => Provider::Mistral,
            "deepseek" => Provider::DeepSeek,
            "qwen" => Provider::Qwen,
            "nvidia" => Provider::Nvidia,
            // Google Gemma is open source, Gemini is not
            "google" if model_name.starts_with("gemma") => Provider::Google,
            "allenai" => Provider::AllenAI,
            _ => Provider::Other,
        }
    }

    /// Get provider display name
    pub fn name(&self) -> &'static str {
        match self {
            Provider::OpenAI => "OpenAI",
            Provider::Meta => "Meta",
            Provider::Mistral => "Mistral",
            Provider::DeepSeek => "DeepSeek",
            Provider::Qwen => "Qwen",
            Provider::Nvidia => "Nvidia",
            Provider::Google => "Google",
            Provider::AllenAI => "Allen AI",
            Provider::Other => "Other",
        }
    }
}

/// Tokenizer encoding type
///
/// Different models use different tokenizers. The encoding type determines
/// which tokenizer to use for accurate token counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Encoding {
    /// OpenAI cl100k_base encoding (GPT-3.5, GPT-4) - via tiktoken
    #[default]
    Cl100kBase,
    /// OpenAI o200k_base encoding (GPT-4o, o1, o3) - via tiktoken
    O200kBase,
    /// Llama-style BPE tokenizer (Llama, Mistral, and derivatives)
    LlamaBpe,
    /// Heuristic fallback (~4 characters per token)
    Heuristic,
}

impl Encoding {
    /// Infer encoding from model ID
    ///
    /// # Examples
    /// ```
    /// use m2m::models::Encoding;
    ///
    /// assert_eq!(Encoding::infer_from_id("openai/gpt-4o"), Encoding::O200kBase);
    /// assert_eq!(Encoding::infer_from_id("openai/gpt-4"), Encoding::Cl100kBase);
    /// assert_eq!(Encoding::infer_from_id("meta-llama/llama-3.1-70b"), Encoding::LlamaBpe);
    /// ```
    pub fn infer_from_id(id: &str) -> Self {
        let id_lower = id.to_lowercase();

        // O200k models: GPT-4o family, o1, o3
        if id_lower.contains("gpt-4o")
            || id_lower.contains("o1-")
            || id_lower.contains("o3-")
            || id_lower.contains("/o1")
            || id_lower.contains("/o3")
        {
            return Encoding::O200kBase;
        }

        // Cl100k models: GPT-3.5, GPT-4 (non-o)
        if id_lower.contains("gpt-3") || id_lower.contains("gpt-4") {
            return Encoding::Cl100kBase;
        }

        // Llama-based models
        if id_lower.contains("llama")
            || id_lower.contains("mistral")
            || id_lower.contains("mixtral")
            || id_lower.contains("nemotron")
        {
            return Encoding::LlamaBpe;
        }

        // Everything else uses heuristic
        Encoding::Heuristic
    }

    /// Get encoding name as string
    pub fn name(&self) -> &'static str {
        match self {
            Encoding::Cl100kBase => "cl100k_base",
            Encoding::O200kBase => "o200k_base",
            Encoding::LlamaBpe => "llama_bpe",
            Encoding::Heuristic => "heuristic",
        }
    }
}

/// Token pricing information (USD per token)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pricing {
    /// Cost per prompt/input token (USD)
    pub prompt: f64,
    /// Cost per completion/output token (USD)
    pub completion: f64,
}

impl Pricing {
    /// Create new pricing
    pub fn new(prompt: f64, completion: f64) -> Self {
        Self { prompt, completion }
    }

    /// Create pricing from per-million token rates (common format)
    pub fn from_per_million(prompt_per_m: f64, completion_per_m: f64) -> Self {
        Self {
            prompt: prompt_per_m / 1_000_000.0,
            completion: completion_per_m / 1_000_000.0,
        }
    }

    /// Calculate cost for given token counts
    pub fn calculate(&self, prompt_tokens: u64, completion_tokens: u64) -> f64 {
        self.prompt * prompt_tokens as f64 + self.completion * completion_tokens as f64
    }
}

/// Model metadata card
///
/// Contains all metadata needed for compression, token counting, and optimization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCard {
    /// Full model ID (e.g., "openai/gpt-4o")
    pub id: String,

    /// Short abbreviation for compression (e.g., "og4o")
    pub abbrev: String,

    /// Provider
    pub provider: Provider,

    /// Tokenizer encoding
    pub encoding: Encoding,

    /// Context window size (max input + output tokens)
    pub context_length: u32,

    /// Default parameter values (for removal during compression)
    #[serde(default)]
    pub defaults: HashMap<String, serde_json::Value>,

    /// Supported parameters
    #[serde(default)]
    pub supported_params: HashSet<String>,

    /// Pricing information (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing: Option<Pricing>,

    /// Whether this model supports streaming
    #[serde(default = "default_true")]
    pub supports_streaming: bool,

    /// Whether this model supports function/tool calling
    #[serde(default)]
    pub supports_tools: bool,

    /// Whether this model supports vision/images
    #[serde(default)]
    pub supports_vision: bool,
}

fn default_true() -> bool {
    true
}

impl ModelCard {
    /// Create a new model card with auto-generated abbreviation
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        let provider = Provider::from_model_id(&id);
        let encoding = Encoding::infer_from_id(&id);
        let abbrev = Self::generate_abbrev(&id, provider);

        Self {
            id,
            abbrev,
            provider,
            encoding,
            context_length: 128000, // Safe default
            defaults: default_params(),
            supported_params: common_params(),
            pricing: None,
            supports_streaming: true,
            supports_tools: false,
            supports_vision: false,
        }
    }

    /// Create model card with explicit abbreviation
    pub fn with_abbrev(id: impl Into<String>, abbrev: impl Into<String>) -> Self {
        let id = id.into();
        let provider = Provider::from_model_id(&id);
        let encoding = Encoding::infer_from_id(&id);

        Self {
            id,
            abbrev: abbrev.into(),
            provider,
            encoding,
            context_length: 128000,
            defaults: default_params(),
            supported_params: common_params(),
            pricing: None,
            supports_streaming: true,
            supports_tools: false,
            supports_vision: false,
        }
    }

    /// Builder: set encoding
    pub fn encoding(mut self, encoding: Encoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Builder: set context length
    pub fn context_length(mut self, context_length: u32) -> Self {
        self.context_length = context_length;
        self
    }

    /// Builder: set pricing
    pub fn pricing(mut self, pricing: Pricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    /// Builder: enable tools support
    pub fn with_tools(mut self) -> Self {
        self.supports_tools = true;
        self
    }

    /// Builder: enable vision support
    pub fn with_vision(mut self) -> Self {
        self.supports_vision = true;
        self
    }

    /// Generate abbreviation from model ID
    ///
    /// The abbreviation scheme:
    /// 1. Provider prefix (1-2 chars): o=OpenAI, m=Meta, mi=Mistral, etc.
    /// 2. Compressed model name: remove common prefixes, compress version numbers
    ///
    /// Examples:
    /// - `openai/gpt-4o` -> `og4o`
    /// - `meta-llama/llama-3.1-405b` -> `ml31405b`
    /// - `deepseek/deepseek-v3` -> `dv3`
    pub fn generate_abbrev(id: &str, provider: Provider) -> String {
        let prefix = provider.prefix();

        // Extract model name part (after provider/)
        let name = id.split('/').next_back().unwrap_or(id);

        // Generate short form through a series of replacements
        let short = name
            // Remove common model prefixes
            .replace("gpt-", "g")
            .replace("llama-", "l")
            .replace("mistral-", "m")
            .replace("mixtral-", "mx")
            .replace("deepseek-", "")
            .replace("qwen-", "q")
            .replace("nemotron-", "n")
            .replace("codestral-", "cod")
            // Compress version qualifiers
            .replace("-turbo", "t")
            .replace("-preview", "p")
            .replace("-mini", "m")
            .replace("-latest", "l")
            .replace("-instruct", "i")
            .replace("-chat", "")
            .replace("-coder", "c")
            .replace("-lite", "l")
            // Remove punctuation
            .replace(['.', '-'], "");

        format!("{prefix}{short}")
    }
}

/// Get common default parameter values
///
/// These are the OpenAI API defaults that can be safely removed during compression.
pub fn default_params() -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    map.insert("temperature".into(), serde_json::json!(1.0));
    map.insert("top_p".into(), serde_json::json!(1.0));
    map.insert("n".into(), serde_json::json!(1));
    map.insert("stream".into(), serde_json::json!(false));
    map.insert("frequency_penalty".into(), serde_json::json!(0));
    map.insert("presence_penalty".into(), serde_json::json!(0));
    map
}

/// Get common supported parameters
pub fn common_params() -> HashSet<String> {
    [
        "model",
        "messages",
        "temperature",
        "top_p",
        "n",
        "stream",
        "stop",
        "max_tokens",
        "frequency_penalty",
        "presence_penalty",
        "logit_bias",
        "tools",
        "tool_choice",
        "response_format",
        "seed",
        "user",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_from_model_id() {
        assert_eq!(Provider::from_model_id("openai/gpt-4o"), Provider::OpenAI);
        assert_eq!(
            Provider::from_model_id("meta-llama/llama-3.1-70b"),
            Provider::Meta
        );
        assert_eq!(
            Provider::from_model_id("mistralai/mistral-large"),
            Provider::Mistral
        );
        assert_eq!(
            Provider::from_model_id("deepseek/deepseek-v3"),
            Provider::DeepSeek
        );
        // Closed tokenizer providers map to Other
        assert_eq!(
            Provider::from_model_id("anthropic/claude-3.5-sonnet"),
            Provider::Other
        );
        assert_eq!(
            Provider::from_model_id("google/gemini-2.0-flash"),
            Provider::Other
        );
        assert_eq!(Provider::from_model_id("unknown/model"), Provider::Other);
        assert_eq!(Provider::from_model_id("gpt-4"), Provider::Other);
    }

    #[test]
    fn test_provider_prefix() {
        assert_eq!(Provider::OpenAI.prefix(), "o");
        assert_eq!(Provider::Meta.prefix(), "m");
        assert_eq!(Provider::Mistral.prefix(), "mi");
        assert_eq!(Provider::DeepSeek.prefix(), "d");
        assert_eq!(Provider::Qwen.prefix(), "q");
    }

    #[test]
    fn test_encoding_inference() {
        // OpenAI models
        assert_eq!(
            Encoding::infer_from_id("openai/gpt-4o"),
            Encoding::O200kBase
        );
        assert_eq!(
            Encoding::infer_from_id("openai/gpt-4o-mini"),
            Encoding::O200kBase
        );
        assert_eq!(Encoding::infer_from_id("openai/o1"), Encoding::O200kBase);
        assert_eq!(
            Encoding::infer_from_id("openai/gpt-4-turbo"),
            Encoding::Cl100kBase
        );
        assert_eq!(
            Encoding::infer_from_id("openai/gpt-3.5-turbo"),
            Encoding::Cl100kBase
        );
        // Llama-based models
        assert_eq!(
            Encoding::infer_from_id("meta-llama/llama-3.1-70b"),
            Encoding::LlamaBpe
        );
        assert_eq!(
            Encoding::infer_from_id("mistralai/mistral-large"),
            Encoding::LlamaBpe
        );
        // Other models use heuristic
        assert_eq!(
            Encoding::infer_from_id("qwen/qwen-2.5-72b"),
            Encoding::Heuristic
        );
    }

    #[test]
    fn test_abbreviation_generation() {
        // OpenAI models
        assert_eq!(
            ModelCard::generate_abbrev("openai/gpt-4o", Provider::OpenAI),
            "og4o"
        );
        assert_eq!(
            ModelCard::generate_abbrev("openai/gpt-4o-mini", Provider::OpenAI),
            "og4om"
        );
        assert_eq!(
            ModelCard::generate_abbrev("openai/gpt-4-turbo", Provider::OpenAI),
            "og4t"
        );
        assert_eq!(
            ModelCard::generate_abbrev("openai/o1", Provider::OpenAI),
            "oo1"
        );

        // Meta models
        assert_eq!(
            ModelCard::generate_abbrev("meta-llama/llama-3.1-405b", Provider::Meta),
            "ml31405b"
        );

        // DeepSeek models
        assert_eq!(
            ModelCard::generate_abbrev("deepseek/deepseek-v3", Provider::DeepSeek),
            "dv3"
        );
    }

    #[test]
    fn test_model_card_creation() {
        let card = ModelCard::new("openai/gpt-4o");
        assert_eq!(card.id, "openai/gpt-4o");
        assert_eq!(card.abbrev, "og4o");
        assert_eq!(card.provider, Provider::OpenAI);
        assert_eq!(card.encoding, Encoding::O200kBase);
    }

    #[test]
    fn test_pricing_calculation() {
        // GPT-4o pricing: $2.50/M input, $10/M output
        let pricing = Pricing::from_per_million(2.50, 10.0);
        let cost = pricing.calculate(1000, 500);
        assert!((cost - 0.0075).abs() < 0.0001); // 0.0025 + 0.005 = 0.0075
    }
}
