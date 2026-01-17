# M2M Protocol v2.0 - Technical Design Document

## 1. System Architecture

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              M2M Protocol v2.0                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           Library Layer                              │   │
│  │                                                                      │   │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│  │   │   Compress   │  │   Tokenizer  │  │    Models    │             │   │
│  │   │   Engine     │  │   Counter    │  │   Registry   │             │   │
│  │   └──────────────┘  └──────────────┘  └──────────────┘             │   │
│  │          │                  │                  │                    │   │
│  │          └──────────────────┼──────────────────┘                    │   │
│  │                             │                                       │   │
│  │                    ┌────────▼────────┐                              │   │
│  │                    │  Smart Router   │                              │   │
│  │                    └─────────────────┘                              │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌─────────────────────────────────┼───────────────────────────────────┐   │
│  │                         Application Layer                            │   │
│  │                                 │                                    │   │
│  │   ┌──────────────┐    ┌────────▼────────┐    ┌──────────────┐      │   │
│  │   │     CLI      │    │   HTTP Proxy    │    │   Config     │      │   │
│  │   │              │    │                 │    │   Manager    │      │   │
│  │   │ - compress   │    │ - /v1/chat/*    │    │              │      │   │
│  │   │ - decompress │    │ - /_m2m/*       │    │ - TOML       │      │   │
│  │   │ - tokens     │    │ - Negotiation   │    │ - ENV        │      │   │
│  │   │ - proxy      │    │ - Streaming     │    │ - CLI args   │      │   │
│  │   │ - models     │    │                 │    │              │      │   │
│  │   └──────────────┘    └─────────────────┘    └──────────────┘      │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Module Dependency Graph

```
                    ┌─────────┐
                    │  error  │
                    └────┬────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐    ┌──────────┐    ┌─────────┐
    │ models  │    │ tokenizer│    │ config  │
    └────┬────┘    └────┬─────┘    └────┬────┘
         │              │               │
         └──────────────┼───────────────┘
                        │
                   ┌────▼────┐
                   │compress │
                   └────┬────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
              ▼         ▼         ▼
         ┌────────┐ ┌───────┐ ┌───────┐
         │  cli   │ │ proxy │ │  lib  │
         └────────┘ └───────┘ └───────┘
```

---

## 2. Component Design

### 2.1 Models Module (`src/models/`)

#### 2.1.1 Data Structures

```rust
// src/models/card.rs

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// Provider enum for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    OpenAI,
    Anthropic,
    Google,
    Meta,
    Mistral,
    DeepSeek,
    Qwen,
    XAI,
    Cohere,
    Nvidia,
    Other,
}

impl Provider {
    /// Get the abbreviation prefix for this provider
    pub fn prefix(&self) -> &'static str {
        match self {
            Provider::OpenAI => "o",
            Provider::Anthropic => "a",
            Provider::Google => "g",
            Provider::Meta => "m",
            Provider::Mistral => "mi",
            Provider::DeepSeek => "d",
            Provider::Qwen => "q",
            Provider::XAI => "x",
            Provider::Cohere => "co",
            Provider::Nvidia => "n",
            Provider::Other => "_",
        }
    }
    
    /// Parse provider from model ID
    pub fn from_model_id(id: &str) -> Self {
        let prefix = id.split('/').next().unwrap_or(id);
        match prefix {
            "openai" => Provider::OpenAI,
            "anthropic" => Provider::Anthropic,
            "google" => Provider::Google,
            "meta-llama" => Provider::Meta,
            "mistralai" => Provider::Mistral,
            "deepseek" => Provider::DeepSeek,
            "qwen" => Provider::Qwen,
            "x-ai" => Provider::XAI,
            "cohere" => Provider::Cohere,
            "nvidia" => Provider::Nvidia,
            _ => Provider::Other,
        }
    }
}

/// Tokenizer encoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Encoding {
    /// OpenAI cl100k_base (GPT-3.5, GPT-4)
    Cl100kBase,
    /// OpenAI o200k_base (GPT-4o, o1, o3)
    O200kBase,
    /// Heuristic fallback (~4 chars per token)
    Heuristic,
}

impl Default for Encoding {
    fn default() -> Self {
        Encoding::Cl100kBase
    }
}

/// Pricing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pricing {
    /// Cost per prompt token (USD)
    pub prompt: f64,
    /// Cost per completion token (USD)
    pub completion: f64,
}

/// Model metadata card
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCard {
    /// Full model ID (e.g., "openai/gpt-4o")
    pub id: String,
    
    /// Short abbreviation (e.g., "og4o")
    pub abbrev: String,
    
    /// Provider
    pub provider: Provider,
    
    /// Tokenizer encoding
    pub encoding: Encoding,
    
    /// Context window size
    pub context_length: u32,
    
    /// Default parameter values (for removal)
    #[serde(default)]
    pub defaults: HashMap<String, serde_json::Value>,
    
    /// Supported parameters
    #[serde(default)]
    pub supported_params: HashSet<String>,
    
    /// Pricing (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pricing: Option<Pricing>,
}

impl ModelCard {
    /// Create a new model card with auto-generated abbreviation
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        let provider = Provider::from_model_id(&id);
        let encoding = Self::infer_encoding(&id);
        let abbrev = Self::generate_abbrev(&id, provider);
        
        Self {
            id,
            abbrev,
            provider,
            encoding,
            context_length: 128000, // Safe default
            defaults: HashMap::new(),
            supported_params: HashSet::new(),
            pricing: None,
        }
    }
    
    /// Infer encoding from model ID
    fn infer_encoding(id: &str) -> Encoding {
        if id.contains("gpt-4o") || id.contains("o1") || id.contains("o3") {
            Encoding::O200kBase
        } else if id.contains("gpt-") || id.contains("claude") {
            Encoding::Cl100kBase
        } else {
            Encoding::Heuristic
        }
    }
    
    /// Generate abbreviation from model ID
    fn generate_abbrev(id: &str, provider: Provider) -> String {
        let prefix = provider.prefix();
        
        // Extract model name part
        let name = id.split('/').last().unwrap_or(id);
        
        // Generate short form
        let short = name
            .replace("gpt-", "g")
            .replace("claude-", "c")
            .replace("llama-", "l")
            .replace("mistral-", "m")
            .replace("gemini-", "ge")
            .replace("-turbo", "t")
            .replace("-preview", "p")
            .replace("-mini", "m")
            .replace("-sonnet", "s")
            .replace("-opus", "o")
            .replace("-haiku", "h")
            .replace("-flash", "f")
            .replace("-pro", "p")
            .replace(".", "")
            .replace("-", "");
        
        format!("{}{}", prefix, short)
    }
}
```

#### 2.1.2 Registry Implementation

```rust
// src/models/registry.rs

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::models::{ModelCard, Encoding, Provider};
use crate::error::M2MError;

/// Model registry with embedded + dynamic models
pub struct ModelRegistry {
    /// Embedded models (always available)
    embedded: HashMap<String, ModelCard>,
    
    /// Abbreviation to ID mapping
    abbrev_to_id: HashMap<String, String>,
    
    /// Dynamic models (fetched at runtime)
    dynamic: RwLock<HashMap<String, ModelCard>>,
    
    /// Cache file path
    cache_path: Option<PathBuf>,
}

impl ModelRegistry {
    /// Create new registry with embedded models
    pub fn new() -> Self {
        let mut registry = Self {
            embedded: HashMap::new(),
            abbrev_to_id: HashMap::new(),
            dynamic: RwLock::new(HashMap::new()),
            cache_path: dirs::cache_dir().map(|p| p.join("m2m").join("models.json")),
        };
        
        // Load embedded models
        registry.load_embedded();
        
        // Try to load cached dynamic models
        registry.load_cache();
        
        registry
    }
    
    /// Load embedded model definitions
    fn load_embedded(&mut self) {
        // Embedded models are defined at compile time
        for (id, abbrev, encoding, ctx_len) in EMBEDDED_MODELS.iter() {
            let card = ModelCard {
                id: id.to_string(),
                abbrev: abbrev.to_string(),
                provider: Provider::from_model_id(id),
                encoding: *encoding,
                context_length: *ctx_len,
                defaults: default_params(),
                supported_params: common_params(),
                pricing: None,
            };
            
            self.abbrev_to_id.insert(abbrev.to_string(), id.to_string());
            self.embedded.insert(id.to_string(), card);
        }
    }
    
    /// Get model by ID or abbreviation
    pub fn get(&self, id_or_abbrev: &str) -> Option<&ModelCard> {
        // Try direct lookup
        if let Some(card) = self.embedded.get(id_or_abbrev) {
            return Some(card);
        }
        
        // Try abbreviation lookup
        if let Some(full_id) = self.abbrev_to_id.get(id_or_abbrev) {
            return self.embedded.get(full_id);
        }
        
        // Try dynamic models
        if let Ok(dynamic) = self.dynamic.read() {
            if let Some(card) = dynamic.get(id_or_abbrev) {
                // Return reference is tricky with RwLock, 
                // consider cloning or Arc<ModelCard>
            }
        }
        
        None
    }
    
    /// Get encoding for a model
    pub fn get_encoding(&self, model: &str) -> Encoding {
        self.get(model)
            .map(|c| c.encoding)
            .unwrap_or_else(|| Encoding::infer_from_id(model))
    }
    
    /// Get abbreviation for a model ID
    pub fn abbreviate(&self, model_id: &str) -> String {
        self.get(model_id)
            .map(|c| c.abbrev.clone())
            .unwrap_or_else(|| ModelCard::new(model_id).abbrev)
    }
    
    /// Expand abbreviation to full ID
    pub fn expand(&self, abbrev: &str) -> Option<String> {
        self.abbrev_to_id.get(abbrev).cloned()
    }
    
    /// List all known model IDs
    pub fn list_ids(&self) -> Vec<&str> {
        self.embedded.keys().map(|s| s.as_str()).collect()
    }
    
    /// Fetch models from OpenRouter (async)
    pub async fn fetch_from_openrouter(&self) -> Result<usize, M2MError> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://openrouter.ai/api/v1/models")
            .send()
            .await
            .map_err(|e| M2MError::FetchError(e.to_string()))?;
        
        let data: OpenRouterModelsResponse = response
            .json()
            .await
            .map_err(|e| M2MError::ParseError(e.to_string()))?;
        
        let mut dynamic = self.dynamic.write()
            .map_err(|_| M2MError::LockError)?;
        
        let count = data.data.len();
        
        for model in data.data {
            let card = ModelCard::from_openrouter(model);
            dynamic.insert(card.id.clone(), card);
        }
        
        // Save to cache
        self.save_cache(&dynamic)?;
        
        Ok(count)
    }
}

// Embedded models constant
static EMBEDDED_MODELS: &[(&str, &str, Encoding, u32)] = &[
    // OpenAI
    ("openai/gpt-4o", "og4o", Encoding::O200kBase, 128000),
    ("openai/gpt-4o-mini", "og4om", Encoding::O200kBase, 128000),
    ("openai/gpt-4-turbo", "og4t", Encoding::Cl100kBase, 128000),
    ("openai/gpt-4", "og4", Encoding::Cl100kBase, 8192),
    ("openai/gpt-3.5-turbo", "og35t", Encoding::Cl100kBase, 16385),
    ("openai/o1", "oo1", Encoding::O200kBase, 200000),
    ("openai/o1-mini", "oo1m", Encoding::O200kBase, 128000),
    ("openai/o3", "oo3", Encoding::O200kBase, 200000),
    ("openai/o3-mini", "oo3m", Encoding::O200kBase, 200000),
    
    // Anthropic
    ("anthropic/claude-3.5-sonnet", "ac35s", Encoding::Cl100kBase, 200000),
    ("anthropic/claude-3.5-haiku", "ac35h", Encoding::Cl100kBase, 200000),
    ("anthropic/claude-3-opus", "ac3o", Encoding::Cl100kBase, 200000),
    ("anthropic/claude-3-sonnet", "ac3s", Encoding::Cl100kBase, 200000),
    ("anthropic/claude-3-haiku", "ac3h", Encoding::Cl100kBase, 200000),
    
    // Google
    ("google/gemini-2.0-flash", "gge2f", Encoding::Heuristic, 1048576),
    ("google/gemini-2.0-pro", "gge2p", Encoding::Heuristic, 1048576),
    ("google/gemini-1.5-pro", "gge15p", Encoding::Heuristic, 2097152),
    ("google/gemini-1.5-flash", "gge15f", Encoding::Heuristic, 1048576),
    
    // Meta
    ("meta-llama/llama-3.1-405b", "ml31405", Encoding::Heuristic, 128000),
    ("meta-llama/llama-3.1-70b", "ml3170", Encoding::Heuristic, 128000),
    ("meta-llama/llama-3.1-8b", "ml318", Encoding::Heuristic, 128000),
    ("meta-llama/llama-3.3-70b", "ml3370", Encoding::Heuristic, 128000),
    
    // Mistral
    ("mistralai/mistral-large", "mim-l", Encoding::Heuristic, 128000),
    ("mistralai/mistral-small", "mim-s", Encoding::Heuristic, 32000),
    ("mistralai/mixtral-8x7b", "mimx87", Encoding::Heuristic, 32000),
    ("mistralai/mixtral-8x22b", "mimx822", Encoding::Heuristic, 65000),
    
    // DeepSeek
    ("deepseek/deepseek-v3", "ddv3", Encoding::Heuristic, 64000),
    ("deepseek/deepseek-r1", "ddr1", Encoding::Heuristic, 64000),
    ("deepseek/deepseek-coder", "ddc", Encoding::Heuristic, 128000),
    
    // Qwen
    ("qwen/qwen-2.5-72b", "qq2572", Encoding::Heuristic, 131072),
    ("qwen/qwen-2.5-32b", "qq2532", Encoding::Heuristic, 131072),
    ("qwen/qwen-2.5-coder-32b", "qqc32", Encoding::Heuristic, 131072),
    
    // X.AI
    ("x-ai/grok-2", "xg2", Encoding::Heuristic, 131072),
    ("x-ai/grok-beta", "xgb", Encoding::Heuristic, 131072),
];

fn default_params() -> HashMap<String, serde_json::Value> {
    let mut map = HashMap::new();
    map.insert("temperature".into(), serde_json::json!(1.0));
    map.insert("top_p".into(), serde_json::json!(1.0));
    map.insert("n".into(), serde_json::json!(1));
    map.insert("stream".into(), serde_json::json!(false));
    map.insert("frequency_penalty".into(), serde_json::json!(0));
    map.insert("presence_penalty".into(), serde_json::json!(0));
    map
}

fn common_params() -> HashSet<String> {
    [
        "temperature", "top_p", "n", "stream", "stop", "max_tokens",
        "frequency_penalty", "presence_penalty", "logit_bias",
        "tools", "tool_choice", "response_format", "seed",
    ].into_iter().map(String::from).collect()
}
```

### 2.2 Tokenizer Module (`src/tokenizer/`)

```rust
// src/tokenizer/counter.rs

use std::sync::OnceLock;
use tiktoken_rs::{cl100k_base, o200k_base, CoreBPE};

use crate::models::Encoding;

static CL100K: OnceLock<CoreBPE> = OnceLock::new();
static O200K: OnceLock<CoreBPE> = OnceLock::new();

/// Count tokens using default encoding (cl100k)
pub fn count_tokens(text: &str) -> usize {
    count_tokens_with_encoding(text, Encoding::Cl100kBase)
}

/// Count tokens with specific encoding
pub fn count_tokens_with_encoding(text: &str, encoding: Encoding) -> usize {
    match encoding {
        Encoding::Cl100kBase => {
            let bpe = CL100K.get_or_init(|| cl100k_base().unwrap());
            bpe.encode_with_special_tokens(text).len()
        }
        Encoding::O200kBase => {
            let bpe = O200K.get_or_init(|| o200k_base().unwrap());
            bpe.encode_with_special_tokens(text).len()
        }
        Encoding::Heuristic => {
            // Rough estimate: ~4 characters per token
            (text.len() + 3) / 4
        }
    }
}

/// Count tokens for a specific model
pub fn count_tokens_for_model(text: &str, model: &str) -> usize {
    let encoding = Encoding::infer_from_id(model);
    count_tokens_with_encoding(text, encoding)
}

impl Encoding {
    /// Infer encoding from model ID
    pub fn infer_from_id(id: &str) -> Self {
        if id.contains("gpt-4o") || id.contains("o1") || id.contains("o3") {
            Encoding::O200kBase
        } else if id.contains("gpt-") || id.contains("claude") {
            Encoding::Cl100kBase
        } else {
            Encoding::Heuristic
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_count_tokens() {
        let text = "Hello, world!";
        let tokens = count_tokens(text);
        assert!(tokens > 0);
        assert!(tokens < 10);
    }
    
    #[test]
    fn test_encoding_inference() {
        assert_eq!(Encoding::infer_from_id("openai/gpt-4o"), Encoding::O200kBase);
        assert_eq!(Encoding::infer_from_id("openai/gpt-4"), Encoding::Cl100kBase);
        assert_eq!(Encoding::infer_from_id("meta-llama/llama-3"), Encoding::Heuristic);
    }
}
```

### 2.3 Compression Module (`src/compress/`)

#### 2.3.1 Abbreviation Tables

```rust
// src/compress/tables.rs

use phf::phf_map;

/// Key abbreviations (JSON keys)
pub static KEY_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    "messages" => "m",
    "message" => "mg",
    "content" => "c",
    "role" => "r",
    "model" => "M",
    "temperature" => "T",
    "max_tokens" => "x",
    "stream" => "s",
    "stop" => "S",
    "top_p" => "p",
    "frequency_penalty" => "f",
    "presence_penalty" => "P",
    "n" => "n",
    "user" => "u",
    "functions" => "Fs",
    "function_call" => "fc",
    "name" => "N",
    "arguments" => "a",
    "tool_calls" => "tc",
    "tools" => "ts",
    "tool_choice" => "tx",
    "response_format" => "rf",
    "seed" => "se",
    "logit_bias" => "lb",
    "logprobs" => "lp",
    "top_logprobs" => "tlp",
    // Response keys
    "choices" => "C",
    "index" => "i",
    "finish_reason" => "fr",
    "usage" => "U",
    "prompt_tokens" => "pt",
    "completion_tokens" => "ct",
    "total_tokens" => "tt",
    "id" => "I",
    "object" => "O",
    "created" => "cr",
    "delta" => "D",
};

/// Reverse key mapping (for decompression)
pub static KEY_EXPAND: phf::Map<&'static str, &'static str> = phf_map! {
    "m" => "messages",
    "mg" => "message",
    "c" => "content",
    "r" => "role",
    "M" => "model",
    "T" => "temperature",
    "x" => "max_tokens",
    "s" => "stream",
    "S" => "stop",
    "p" => "top_p",
    "f" => "frequency_penalty",
    "P" => "presence_penalty",
    "n" => "n",
    "u" => "user",
    "Fs" => "functions",
    "fc" => "function_call",
    "N" => "name",
    "a" => "arguments",
    "tc" => "tool_calls",
    "ts" => "tools",
    "tx" => "tool_choice",
    "rf" => "response_format",
    "se" => "seed",
    "lb" => "logit_bias",
    "lp" => "logprobs",
    "tlp" => "top_logprobs",
    "C" => "choices",
    "i" => "index",
    "fr" => "finish_reason",
    "U" => "usage",
    "pt" => "prompt_tokens",
    "ct" => "completion_tokens",
    "tt" => "total_tokens",
    "I" => "id",
    "O" => "object",
    "cr" => "created",
    "D" => "delta",
};

/// Role abbreviations
/// NOTE: "user" is intentionally NOT abbreviated (costs more tokens)
pub static ROLE_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    "system" => "S",
    "assistant" => "A",
    "function" => "F",
    "tool" => "T",
};

pub static ROLE_EXPAND: phf::Map<&'static str, &'static str> = phf_map! {
    "S" => "system",
    "A" => "assistant",
    "F" => "function",
    "T" => "tool",
};

/// Default values that can be removed
pub fn is_default_value(key: &str, value: &serde_json::Value) -> bool {
    use serde_json::Value;
    
    match (key, value) {
        ("temperature" | "T", Value::Number(n)) => {
            n.as_f64().map(|f| (f - 1.0).abs() < 0.001).unwrap_or(false)
        }
        ("top_p" | "p", Value::Number(n)) => {
            n.as_f64().map(|f| (f - 1.0).abs() < 0.001).unwrap_or(false)
        }
        ("n", Value::Number(n)) => {
            n.as_i64() == Some(1)
        }
        ("stream" | "s", Value::Bool(b)) => !b,
        ("frequency_penalty" | "f", Value::Number(n)) => {
            n.as_i64() == Some(0) || n.as_f64() == Some(0.0)
        }
        ("presence_penalty" | "P", Value::Number(n)) => {
            n.as_i64() == Some(0) || n.as_f64() == Some(0.0)
        }
        ("logit_bias" | "lb", Value::Object(m)) => m.is_empty(),
        ("stop" | "S", Value::Null) => true,
        _ => false,
    }
}
```

#### 2.3.2 Structural Compressor

```rust
// src/compress/structural.rs

use serde_json::{Value, Map};

use crate::compress::tables::{
    KEY_ABBREV, KEY_EXPAND, ROLE_ABBREV, ROLE_EXPAND, is_default_value
};
use crate::models::ModelRegistry;
use crate::tokenizer::count_tokens_with_encoding;

/// Compression options
#[derive(Debug, Clone)]
pub struct CompressOptions {
    pub abbreviate_keys: bool,
    pub abbreviate_roles: bool,
    pub abbreviate_models: bool,
    pub remove_defaults: bool,
    pub remove_nulls: bool,
}

impl Default for CompressOptions {
    fn default() -> Self {
        Self {
            abbreviate_keys: true,
            abbreviate_roles: true,
            abbreviate_models: true,
            remove_defaults: true,
            remove_nulls: true,
        }
    }
}

/// Structural compressor
pub struct StructuralCompressor {
    options: CompressOptions,
    registry: ModelRegistry,
}

impl StructuralCompressor {
    pub fn new(options: CompressOptions, registry: ModelRegistry) -> Self {
        Self { options, registry }
    }
    
    pub fn with_defaults() -> Self {
        Self::new(CompressOptions::default(), ModelRegistry::new())
    }
    
    /// Compress a JSON value (full M2M compression with abbreviations)
    pub fn compress(&self, value: &Value) -> Value {
        self.compress_value(value, None)
    }
    
    /// Optimize a JSON value (remove defaults only, no abbreviations)
    /// Used for standard client → upstream flow
    pub fn optimize(&self, value: &Value) -> Value {
        let opts = CompressOptions {
            abbreviate_keys: false,
            abbreviate_roles: false,
            abbreviate_models: false,
            remove_defaults: true,
            remove_nulls: true,
        };
        self.compress_with_options(value, &opts)
    }
    
    /// Decompress an M2M-compressed value
    pub fn decompress(&self, value: &Value) -> Value {
        self.expand_value(value, None)
    }
    
    fn compress_with_options(&self, value: &Value, opts: &CompressOptions) -> Value {
        match value {
            Value::Object(map) => {
                let mut result = Map::new();
                
                for (key, val) in map {
                    // Skip nulls
                    if opts.remove_nulls && val.is_null() {
                        continue;
                    }
                    
                    // Skip defaults
                    if opts.remove_defaults && is_default_value(key, val) {
                        continue;
                    }
                    
                    // Abbreviate key
                    let new_key = if opts.abbreviate_keys {
                        KEY_ABBREV.get(key.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| key.clone())
                    } else {
                        key.clone()
                    };
                    
                    // Process value
                    let new_val = self.compress_value_with_key(val, key, opts);
                    result.insert(new_key, new_val);
                }
                
                Value::Object(result)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.compress_with_options(v, opts)).collect())
            }
            _ => value.clone(),
        }
    }
    
    fn compress_value(&self, value: &Value, parent_key: Option<&str>) -> Value {
        self.compress_value_with_key(value, parent_key.unwrap_or(""), &self.options)
    }
    
    fn compress_value_with_key(&self, value: &Value, key: &str, opts: &CompressOptions) -> Value {
        match value {
            Value::String(s) => {
                // Abbreviate role values
                if (key == "role" || key == "r") && opts.abbreviate_roles {
                    if let Some(abbrev) = ROLE_ABBREV.get(s.as_str()) {
                        return Value::String(abbrev.to_string());
                    }
                }
                
                // Abbreviate model names
                if (key == "model" || key == "M") && opts.abbreviate_models {
                    return Value::String(self.registry.abbreviate(s));
                }
                
                value.clone()
            }
            Value::Object(map) => self.compress_with_options(value, opts),
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.compress_with_options(v, opts)).collect())
            }
            _ => value.clone(),
        }
    }
    
    fn expand_value(&self, value: &Value, parent_key: Option<&str>) -> Value {
        match value {
            Value::Object(map) => {
                let mut result = Map::new();
                
                for (key, val) in map {
                    // Expand key
                    let expanded_key = KEY_EXPAND.get(key.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| key.clone());
                    
                    // Expand value
                    let expanded_val = self.expand_value(val, Some(&expanded_key));
                    result.insert(expanded_key, expanded_val);
                }
                
                Value::Object(result)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.expand_value(v, parent_key)).collect())
            }
            Value::String(s) => {
                // Expand role values
                if let Some(key) = parent_key {
                    if key == "role" || key == "r" {
                        if let Some(expanded) = ROLE_EXPAND.get(s.as_str()) {
                            return Value::String(expanded.to_string());
                        }
                    }
                    
                    // Expand model names
                    if key == "model" || key == "M" {
                        if let Some(expanded) = self.registry.expand(s) {
                            return Value::String(expanded);
                        }
                    }
                }
                
                value.clone()
            }
            _ => value.clone(),
        }
    }
}

/// Detect if a message is in M2M compressed format
pub fn is_m2m_format(value: &Value) -> bool {
    if let Value::Object(map) = value {
        // Check for abbreviated keys
        map.contains_key("M") || map.contains_key("m") || map.contains_key("c")
    } else {
        false
    }
}
```

#### 2.3.3 Smart Router

```rust
// src/compress/router.rs

use serde_json::Value;

use crate::tokenizer::count_tokens_with_encoding;
use crate::models::{ModelRegistry, Encoding};

/// Compression strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Skip compression (message too small)
    Skip,
    /// Optimize only (remove defaults, no abbreviations)
    Optimize,
    /// Full M2M compression (abbreviations + default removal)
    Full,
}

/// Router configuration
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Minimum tokens to consider compression
    pub min_tokens: usize,
    /// Threshold for full compression
    pub full_compression_threshold: usize,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            min_tokens: 25,
            full_compression_threshold: 50,
        }
    }
}

/// Smart compression router
pub struct Router {
    config: RouterConfig,
    registry: ModelRegistry,
}

impl Router {
    pub fn new(config: RouterConfig, registry: ModelRegistry) -> Self {
        Self { config, registry }
    }
    
    pub fn with_defaults() -> Self {
        Self::new(RouterConfig::default(), ModelRegistry::new())
    }
    
    /// Determine compression strategy for a message
    pub fn route(&self, message: &Value) -> Strategy {
        // Extract model and count tokens
        let model = message.get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gpt-4");
        
        let encoding = self.registry.get_encoding(model);
        let json_str = serde_json::to_string(message).unwrap_or_default();
        let tokens = count_tokens_with_encoding(&json_str, encoding);
        
        // Small messages: skip
        if tokens < self.config.min_tokens {
            return Strategy::Skip;
        }
        
        // Check for high-value optimization opportunities
        let has_defaults = self.has_removable_defaults(message);
        let has_long_model = self.has_long_model_name(message);
        
        // Determine strategy
        if tokens >= self.config.full_compression_threshold || has_long_model {
            Strategy::Full
        } else if has_defaults {
            Strategy::Optimize
        } else if tokens >= self.config.min_tokens {
            Strategy::Optimize
        } else {
            Strategy::Skip
        }
    }
    
    fn has_removable_defaults(&self, message: &Value) -> bool {
        if let Value::Object(map) = message {
            map.get("temperature").and_then(|v| v.as_f64()) == Some(1.0) ||
            map.get("stream").and_then(|v| v.as_bool()) == Some(false) ||
            map.get("top_p").and_then(|v| v.as_f64()) == Some(1.0) ||
            map.get("n").and_then(|v| v.as_i64()) == Some(1)
        } else {
            false
        }
    }
    
    fn has_long_model_name(&self, message: &Value) -> bool {
        message.get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.len() > 15)
            .unwrap_or(false)
    }
}
```

### 2.4 Proxy Module (`src/proxy/`)

#### 2.4.1 Server

```rust
// src/proxy/server.rs

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    routing::{get, post},
    extract::{State, Json},
    http::{StatusCode, HeaderMap, header},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::compress::{StructuralCompressor, Router as CompressRouter, Strategy, is_m2m_format};
use crate::models::ModelRegistry;
use crate::proxy::stats::Stats;
use crate::config::ProxyConfig;

/// Shared proxy state
pub struct ProxyState {
    pub config: ProxyConfig,
    pub client: Client,
    pub compressor: StructuralCompressor,
    pub router: CompressRouter,
    pub registry: ModelRegistry,
    pub stats: RwLock<Stats>,
}

impl ProxyState {
    pub fn new(config: ProxyConfig) -> Self {
        let registry = ModelRegistry::new();
        
        Self {
            config,
            client: Client::new(),
            compressor: StructuralCompressor::with_defaults(),
            router: CompressRouter::with_defaults(),
            registry,
            stats: RwLock::new(Stats::new()),
        }
    }
}

/// Create the proxy router
pub fn create_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        // OpenAI-compatible endpoints
        .route("/v1/chat/completions", post(chat_completions_handler))
        .route("/v1/models", get(models_handler))
        
        // M2M endpoints
        .route("/_m2m/health", get(health_handler))
        .route("/_m2m/stats", get(stats_handler))
        .route("/_m2m/compress", post(compress_handler))
        
        // Fallback for other /v1/* routes
        .route("/v1/*path", post(passthrough_handler).get(passthrough_handler))
        
        .with_state(state)
}

/// Main chat completions handler with protocol negotiation
async fn chat_completions_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let start = Instant::now();
    
    // Detect M2M client
    let is_m2m_client = headers
        .get("x-m2m-protocol")
        .map(|v| v.to_str().unwrap_or("").starts_with("1"))
        .unwrap_or(false) || is_m2m_format(&payload);
    
    // Process request
    let (processed, original_tokens, processed_tokens) = if is_m2m_client {
        // M2M client: decompress for upstream
        let decompressed = state.compressor.decompress(&payload);
        let orig_str = serde_json::to_string(&payload).unwrap_or_default();
        let proc_str = serde_json::to_string(&decompressed).unwrap_or_default();
        let orig_tokens = crate::tokenizer::count_tokens(&orig_str);
        let proc_tokens = crate::tokenizer::count_tokens(&proc_str);
        (decompressed, orig_tokens, proc_tokens)
    } else {
        // Standard client: optimize (remove defaults)
        let strategy = state.router.route(&payload);
        
        match strategy {
            Strategy::Skip => {
                let json_str = serde_json::to_string(&payload).unwrap_or_default();
                let tokens = crate::tokenizer::count_tokens(&json_str);
                (payload.clone(), tokens, tokens)
            }
            Strategy::Optimize | Strategy::Full => {
                let optimized = state.compressor.optimize(&payload);
                let orig_str = serde_json::to_string(&payload).unwrap_or_default();
                let opt_str = serde_json::to_string(&optimized).unwrap_or_default();
                let orig_tokens = crate::tokenizer::count_tokens(&orig_str);
                let opt_tokens = crate::tokenizer::count_tokens(&opt_str);
                (optimized, orig_tokens, opt_tokens)
            }
        }
    };
    
    // Forward to upstream
    let upstream_url = format!("{}/v1/chat/completions", state.config.upstream);
    
    // Copy authorization header
    let mut req = state.client.post(&upstream_url).json(&processed);
    
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        req = req.header(header::AUTHORIZATION, auth);
    }
    
    match req.send().await {
        Ok(response) => {
            let status = response.status();
            
            // Check if streaming
            let is_streaming = response.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.contains("text/event-stream"))
                .unwrap_or(false);
            
            if is_streaming {
                // Stream response directly
                return stream_response(response, original_tokens, processed_tokens).await;
            }
            
            // Non-streaming: read body
            match response.json::<Value>().await {
                Ok(body) => {
                    // Update stats
                    {
                        let mut stats = state.stats.write().await;
                        stats.record_request(original_tokens, processed_tokens, start.elapsed());
                    }
                    
                    // Add M2M headers
                    let mut response = Json(body).into_response();
                    let headers = response.headers_mut();
                    headers.insert("x-m2m-tokens-original", original_tokens.to_string().parse().unwrap());
                    headers.insert("x-m2m-tokens-sent", processed_tokens.to_string().parse().unwrap());
                    headers.insert("x-m2m-tokens-saved", (original_tokens as i64 - processed_tokens as i64).to_string().parse().unwrap());
                    
                    response
                }
                Err(e) => {
                    (StatusCode::BAD_GATEWAY, format!("Failed to parse upstream response: {}", e)).into_response()
                }
            }
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY, format!("Upstream request failed: {}", e)).into_response()
        }
    }
}

/// Stream SSE response
async fn stream_response(
    response: reqwest::Response,
    original_tokens: usize,
    processed_tokens: usize,
) -> Response {
    use axum::body::Body;
    use futures::StreamExt;
    
    let status = response.status();
    let headers = response.headers().clone();
    
    // Convert reqwest stream to axum body
    let stream = response.bytes_stream().map(|result| {
        result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    });
    
    let body = Body::from_stream(stream);
    
    let mut response = Response::builder()
        .status(status.as_u16())
        .body(body)
        .unwrap();
    
    // Copy headers
    for (key, value) in headers.iter() {
        response.headers_mut().insert(key.clone(), value.clone());
    }
    
    // Add M2M headers
    response.headers_mut().insert("x-m2m-tokens-original", original_tokens.to_string().parse().unwrap());
    response.headers_mut().insert("x-m2m-tokens-sent", processed_tokens.to_string().parse().unwrap());
    
    response
}

/// Health check
async fn health_handler(State(state): State<Arc<ProxyState>>) -> Json<Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "upstream": state.config.upstream,
    }))
}

/// Stats endpoint
async fn stats_handler(State(state): State<Arc<ProxyState>>) -> Json<Value> {
    let stats = state.stats.read().await;
    Json(stats.to_json())
}

/// Direct compression API
async fn compress_handler(
    State(state): State<Arc<ProxyState>>,
    Json(payload): Json<Value>,
) -> Json<Value> {
    let compressed = state.compressor.compress(&payload);
    
    let orig_str = serde_json::to_string(&payload).unwrap_or_default();
    let comp_str = serde_json::to_string(&compressed).unwrap_or_default();
    let orig_tokens = crate::tokenizer::count_tokens(&orig_str);
    let comp_tokens = crate::tokenizer::count_tokens(&comp_str);
    
    Json(serde_json::json!({
        "compressed": compressed,
        "original_tokens": orig_tokens,
        "compressed_tokens": comp_tokens,
        "tokens_saved": orig_tokens as i64 - comp_tokens as i64,
    }))
}

/// Models list endpoint
async fn models_handler(State(state): State<Arc<ProxyState>>) -> Json<Value> {
    let models: Vec<Value> = state.registry.list_ids()
        .into_iter()
        .map(|id| serde_json::json!({
            "id": id,
            "object": "model",
            "owned_by": "m2m-registry",
        }))
        .collect();
    
    Json(serde_json::json!({
        "object": "list",
        "data": models,
    }))
}

/// Passthrough handler for other endpoints
async fn passthrough_handler(
    State(state): State<Arc<ProxyState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Just forward as-is
    let path = headers.get("x-original-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/v1/unknown");
    
    let url = format!("{}{}", state.config.upstream, path);
    
    let mut req = state.client.post(&url).body(body.to_vec());
    
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        req = req.header(header::AUTHORIZATION, auth);
    }
    
    match req.send().await {
        Ok(response) => {
            let status = response.status();
            match response.bytes().await {
                Ok(bytes) => {
                    Response::builder()
                        .status(status.as_u16())
                        .body(axum::body::Body::from(bytes))
                        .unwrap()
                }
                Err(e) => {
                    (StatusCode::BAD_GATEWAY, e.to_string()).into_response()
                }
            }
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY, e.to_string()).into_response()
        }
    }
}
```

#### 2.4.2 Stats Tracking

```rust
// src/proxy/stats.rs

use std::time::Duration;
use serde_json::Value;

/// Proxy statistics
#[derive(Debug, Default)]
pub struct Stats {
    pub requests_total: u64,
    pub tokens_original: u64,
    pub tokens_sent: u64,
    pub total_latency_ms: u64,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn record_request(&mut self, original: usize, sent: usize, latency: Duration) {
        self.requests_total += 1;
        self.tokens_original += original as u64;
        self.tokens_sent += sent as u64;
        self.total_latency_ms += latency.as_millis() as u64;
    }
    
    pub fn tokens_saved(&self) -> i64 {
        self.tokens_original as i64 - self.tokens_sent as i64
    }
    
    pub fn savings_percent(&self) -> f64 {
        if self.tokens_original == 0 {
            0.0
        } else {
            (self.tokens_saved() as f64 / self.tokens_original as f64) * 100.0
        }
    }
    
    pub fn avg_latency_ms(&self) -> f64 {
        if self.requests_total == 0 {
            0.0
        } else {
            self.total_latency_ms as f64 / self.requests_total as f64
        }
    }
    
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "requests_total": self.requests_total,
            "tokens_original": self.tokens_original,
            "tokens_sent": self.tokens_sent,
            "tokens_saved": self.tokens_saved(),
            "savings_percent": format!("{:.2}", self.savings_percent()),
            "avg_latency_ms": format!("{:.2}", self.avg_latency_ms()),
        })
    }
}
```

---

## 3. Error Handling

```rust
// src/error.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum M2MError {
    #[error("JSON parsing error: {0}")]
    ParseError(String),
    
    #[error("Compression error: {0}")]
    CompressionError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Fetch error: {0}")]
    FetchError(String),
    
    #[error("Lock error")]
    LockError,
    
    #[error("Config error: {0}")]
    ConfigError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, M2MError>;
```

---

## 4. Testing Strategy

### 4.1 Unit Tests

- Compression/decompression round-trip
- Token counting accuracy
- Model registry lookups
- Abbreviation tables

### 4.2 Integration Tests

- Proxy with mock upstream
- SSE streaming
- Protocol negotiation

### 4.3 Benchmarks

```rust
// benches/compression_bench.rs

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_compression(c: &mut Criterion) {
    let compressor = m2m::compress::StructuralCompressor::with_defaults();
    
    let message = serde_json::json!({
        "model": "openai/gpt-4o",
        "messages": [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "Hello, how are you?"}
        ],
        "temperature": 1.0,
        "stream": false
    });
    
    c.bench_function("compress", |b| {
        b.iter(|| compressor.compress(&message))
    });
    
    let compressed = compressor.compress(&message);
    
    c.bench_function("decompress", |b| {
        b.iter(|| compressor.decompress(&compressed))
    });
}

fn bench_token_counting(c: &mut Criterion) {
    let text = "Hello, world! This is a test message for token counting.";
    
    c.bench_function("count_tokens_cl100k", |b| {
        b.iter(|| m2m::tokenizer::count_tokens(text))
    });
}

criterion_group!(benches, bench_compression, bench_token_counting);
criterion_main!(benches);
```

---

## 5. Security Considerations

1. **Auth passthrough**: Authorization headers are forwarded unchanged
2. **No secrets stored**: Proxy is stateless regarding credentials
3. **Input validation**: JSON parsing with size limits
4. **HTTPS upstream**: Recommend HTTPS for upstream connections
5. **No logging of content**: Only metadata/stats logged

---

## 6. Deployment

### 6.1 Binary Build

```bash
cargo build --release
# Output: target/release/m2m (~5-10MB)
```

### 6.2 Docker

```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/m2m /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["m2m", "proxy"]
```

### 6.3 Configuration

```bash
# Environment
export M2M_PROXY_UPSTREAM=https://api.openai.com
export M2M_PROXY_PORT=8080

# Or config file
m2m proxy --config /etc/m2m/config.toml
```
