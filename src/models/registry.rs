//! Model registry for model lookups and management.
//!
//! The registry provides:
//! - Fast model lookup by ID or abbreviation
//! - Encoding inference for token counting
//! - Abbreviation expansion for decompression
//! - Optional dynamic model fetching from OpenRouter

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::{M2MError, Result};
use crate::models::card::{Encoding, ModelCard, Provider};
use crate::models::embedded::get_embedded_models;

/// Model registry with embedded + dynamic models
///
/// The registry maintains two sets of models:
/// 1. Embedded models: Compiled into the binary, always available
/// 2. Dynamic models: Fetched at runtime (optional), stored in RwLock
///
/// # Example
/// ```
/// use m2m::models::ModelRegistry;
///
/// let registry = ModelRegistry::new();
///
/// // Lookup by ID
/// let card = registry.get("openai/gpt-4o").unwrap();
/// assert_eq!(card.abbrev, "og4o");
///
/// // Lookup by abbreviation
/// let card = registry.get("ml3170i").unwrap();
/// assert_eq!(card.id, "meta-llama/llama-3.1-70b-instruct");
///
/// // Abbreviate a model name
/// let abbrev = registry.abbreviate("openai/gpt-4o");
/// assert_eq!(abbrev, "og4o");
///
/// // Expand an abbreviation
/// let id = registry.expand("og4o").unwrap();
/// assert_eq!(id, "openai/gpt-4o");
/// ```
pub struct ModelRegistry {
    /// ID -> ModelCard
    by_id: HashMap<String, ModelCard>,

    /// Abbreviation -> ID
    abbrev_to_id: HashMap<String, String>,

    /// Dynamic models (fetched at runtime)
    dynamic: RwLock<HashMap<String, ModelCard>>,

    /// Dynamic abbreviations
    dynamic_abbrevs: RwLock<HashMap<String, String>>,
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRegistry {
    /// Create a new registry with embedded models loaded
    pub fn new() -> Self {
        let mut registry = Self {
            by_id: HashMap::new(),
            abbrev_to_id: HashMap::new(),
            dynamic: RwLock::new(HashMap::new()),
            dynamic_abbrevs: RwLock::new(HashMap::new()),
        };

        registry.load_embedded();
        registry
    }

    /// Load embedded models into the registry
    fn load_embedded(&mut self) {
        for card in get_embedded_models() {
            self.abbrev_to_id
                .insert(card.abbrev.clone(), card.id.clone());
            self.by_id.insert(card.id.clone(), card);
        }
    }

    /// Get a model by ID or abbreviation
    ///
    /// Tries lookups in order:
    /// 1. Direct ID match in embedded models
    /// 2. Abbreviation match
    /// 3. Dynamic models (if any)
    pub fn get(&self, id_or_abbrev: &str) -> Option<ModelCard> {
        // Try direct ID lookup in embedded
        if let Some(card) = self.by_id.get(id_or_abbrev) {
            return Some(card.clone());
        }

        // Try abbreviation lookup
        if let Some(full_id) = self.abbrev_to_id.get(id_or_abbrev) {
            if let Some(card) = self.by_id.get(full_id) {
                return Some(card.clone());
            }
        }

        // Try dynamic models
        if let Ok(dynamic) = self.dynamic.read() {
            if let Some(card) = dynamic.get(id_or_abbrev) {
                return Some(card.clone());
            }
        }

        // Try dynamic abbreviations
        if let Ok(abbrevs) = self.dynamic_abbrevs.read() {
            if let Some(full_id) = abbrevs.get(id_or_abbrev) {
                if let Ok(dynamic) = self.dynamic.read() {
                    if let Some(card) = dynamic.get(full_id) {
                        return Some(card.clone());
                    }
                }
            }
        }

        None
    }

    /// Check if a model exists in the registry
    pub fn contains(&self, id_or_abbrev: &str) -> bool {
        self.get(id_or_abbrev).is_some()
    }

    /// Get the encoding for a model (with fallback inference)
    ///
    /// If the model is not in the registry, infers encoding from the model ID.
    pub fn get_encoding(&self, model: &str) -> Encoding {
        self.get(model)
            .map(|c| c.encoding)
            .unwrap_or_else(|| Encoding::infer_from_id(model))
    }

    /// Get the context length for a model (with safe default)
    pub fn get_context_length(&self, model: &str) -> u32 {
        self.get(model).map(|c| c.context_length).unwrap_or(128000) // Safe default
    }

    /// Abbreviate a model ID
    ///
    /// Returns the abbreviation from the registry if available,
    /// otherwise generates one using the standard algorithm.
    pub fn abbreviate(&self, model_id: &str) -> String {
        // Check embedded models
        if let Some(card) = self.by_id.get(model_id) {
            return card.abbrev.clone();
        }

        // Check dynamic models
        if let Ok(dynamic) = self.dynamic.read() {
            if let Some(card) = dynamic.get(model_id) {
                return card.abbrev.clone();
            }
        }

        // Generate abbreviation
        let provider = Provider::from_model_id(model_id);
        ModelCard::generate_abbrev(model_id, provider)
    }

    /// Expand an abbreviation to full model ID
    ///
    /// Returns None if the abbreviation is not recognized.
    pub fn expand(&self, abbrev: &str) -> Option<String> {
        // Check embedded abbreviations
        if let Some(id) = self.abbrev_to_id.get(abbrev) {
            return Some(id.clone());
        }

        // Check dynamic abbreviations
        if let Ok(abbrevs) = self.dynamic_abbrevs.read() {
            if let Some(id) = abbrevs.get(abbrev) {
                return Some(id.clone());
            }
        }

        None
    }

    /// List all known model IDs (embedded only, not dynamic)
    pub fn list_ids(&self) -> Vec<&str> {
        self.by_id.keys().map(|s| s.as_str()).collect()
    }

    /// List all known abbreviations
    pub fn list_abbrevs(&self) -> Vec<&str> {
        self.abbrev_to_id.keys().map(|s| s.as_str()).collect()
    }

    /// Get total count of models (embedded + dynamic)
    pub fn len(&self) -> usize {
        let dynamic_count = self.dynamic.read().map(|d| d.len()).unwrap_or(0);
        self.by_id.len() + dynamic_count
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get count of embedded models
    pub fn embedded_count(&self) -> usize {
        self.by_id.len()
    }

    /// Get count of dynamic models
    pub fn dynamic_count(&self) -> usize {
        self.dynamic.read().map(|d| d.len()).unwrap_or(0)
    }

    /// Add a model to the dynamic registry
    pub fn add_dynamic(&self, card: ModelCard) -> Result<()> {
        let mut dynamic = self
            .dynamic
            .write()
            .map_err(|_| M2MError::Compression("Lock poisoned".into()))?;

        let mut abbrevs = self
            .dynamic_abbrevs
            .write()
            .map_err(|_| M2MError::Compression("Lock poisoned".into()))?;

        abbrevs.insert(card.abbrev.clone(), card.id.clone());
        dynamic.insert(card.id.clone(), card);

        Ok(())
    }

    /// Clear dynamic models
    pub fn clear_dynamic(&self) -> Result<()> {
        let mut dynamic = self
            .dynamic
            .write()
            .map_err(|_| M2MError::Compression("Lock poisoned".into()))?;

        let mut abbrevs = self
            .dynamic_abbrevs
            .write()
            .map_err(|_| M2MError::Compression("Lock poisoned".into()))?;

        dynamic.clear();
        abbrevs.clear();

        Ok(())
    }

    /// Get models filtered by provider
    pub fn get_by_provider(&self, provider: Provider) -> Vec<ModelCard> {
        self.by_id
            .values()
            .filter(|card| card.provider == provider)
            .cloned()
            .collect()
    }

    /// Search models by ID substring
    pub fn search(&self, query: &str) -> Vec<ModelCard> {
        let query_lower = query.to_lowercase();

        self.by_id
            .values()
            .filter(|card| {
                card.id.to_lowercase().contains(&query_lower)
                    || card.abbrev.to_lowercase().contains(&query_lower)
            })
            .cloned()
            .collect()
    }

    /// Iterate over all embedded models
    pub fn iter(&self) -> impl Iterator<Item = &ModelCard> {
        self.by_id.values()
    }
}

/// OpenRouter API model response (for future dynamic fetching)
#[derive(Debug, serde::Deserialize)]
pub struct OpenRouterModel {
    pub id: String,
    pub name: Option<String>,
    pub context_length: Option<u32>,
    pub pricing: Option<OpenRouterPricing>,
}

#[derive(Debug, serde::Deserialize)]
pub struct OpenRouterPricing {
    pub prompt: Option<String>,
    pub completion: Option<String>,
}

/// Response from OpenRouter /models API
///
/// Used for dynamic model registry updates. This struct is prepared for
/// future `fetch_openrouter_models` implementation (requires `reqwest` feature).
/// The struct and methods are intentionally public for API consumers who
/// want to implement their own fetching logic.
#[derive(Debug, serde::Deserialize)]
pub struct OpenRouterModelsResponse {
    /// List of available models
    pub data: Vec<OpenRouterModel>,
}

// Note: These methods are intentionally public for API consumers implementing
// their own OpenRouter model fetching. Clippy flags them as dead code because
// the built-in fetch function isn't implemented yet.
#[allow(dead_code)]
impl OpenRouterModelsResponse {
    /// Get the list of models
    pub fn models(&self) -> &[OpenRouterModel] {
        &self.data
    }

    /// Get the number of models
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl ModelCard {
    /// Create ModelCard from OpenRouter API model
    pub fn from_openrouter(model: OpenRouterModel) -> Self {
        let provider = Provider::from_model_id(&model.id);
        let encoding = Encoding::infer_from_id(&model.id);
        let abbrev = Self::generate_abbrev(&model.id, provider);

        Self {
            id: model.id,
            abbrev,
            provider,
            encoding,
            context_length: model.context_length.unwrap_or(128000),
            defaults: crate::models::card::default_params(),
            supported_params: crate::models::card::common_params(),
            pricing: model.pricing.and_then(|p| {
                let prompt: f64 = p.prompt?.parse().ok()?;
                let completion: f64 = p.completion?.parse().ok()?;
                Some(crate::models::card::Pricing::new(prompt, completion))
            }),
            supports_streaming: true,
            supports_tools: false,
            supports_vision: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = ModelRegistry::new();
        assert!(registry.embedded_count() >= 35);
    }

    #[test]
    fn test_get_by_id() {
        let registry = ModelRegistry::new();
        let card = registry.get("openai/gpt-4o").expect("Should find gpt-4o");
        assert_eq!(card.abbrev, "og4o");
        assert_eq!(card.encoding, Encoding::O200kBase);
    }

    #[test]
    fn test_get_by_abbrev() {
        let registry = ModelRegistry::new();
        let card = registry.get("ml3170i").expect("Should find by abbrev");
        assert_eq!(card.id, "meta-llama/llama-3.1-70b-instruct");
    }

    #[test]
    fn test_abbreviate() {
        let registry = ModelRegistry::new();

        // Known model
        assert_eq!(registry.abbreviate("openai/gpt-4o"), "og4o");

        // Unknown model (generates abbreviation)
        let abbrev = registry.abbreviate("openai/gpt-5-super");
        assert!(abbrev.starts_with("o")); // OpenAI prefix
    }

    #[test]
    fn test_expand() {
        let registry = ModelRegistry::new();

        assert_eq!(registry.expand("og4o"), Some("openai/gpt-4o".to_string()));
        assert_eq!(
            registry.expand("ml3170i"),
            Some("meta-llama/llama-3.1-70b-instruct".to_string())
        );
        assert_eq!(registry.expand("unknown"), None);
    }

    #[test]
    fn test_get_encoding() {
        let registry = ModelRegistry::new();

        // Known model
        assert_eq!(registry.get_encoding("openai/gpt-4o"), Encoding::O200kBase);

        // Unknown model (infers encoding)
        assert_eq!(
            registry.get_encoding("openai/gpt-4o-future"),
            Encoding::O200kBase
        );
        assert_eq!(
            registry.get_encoding("some-random-model"),
            Encoding::Heuristic
        );
    }

    #[test]
    fn test_contains() {
        let registry = ModelRegistry::new();

        assert!(registry.contains("openai/gpt-4o"));
        assert!(registry.contains("og4o"));
        assert!(!registry.contains("nonexistent-model"));
    }

    #[test]
    fn test_get_by_provider() {
        let registry = ModelRegistry::new();

        let openai_models = registry.get_by_provider(Provider::OpenAI);
        assert!(!openai_models.is_empty());
        assert!(openai_models.iter().all(|m| m.provider == Provider::OpenAI));

        let meta_models = registry.get_by_provider(Provider::Meta);
        assert!(!meta_models.is_empty());
        assert!(meta_models.iter().all(|m| m.provider == Provider::Meta));
    }

    #[test]
    fn test_search() {
        let registry = ModelRegistry::new();

        let results = registry.search("gpt-4");
        assert!(!results.is_empty());
        assert!(results.iter().all(|m| m.id.contains("gpt-4")));

        let results = registry.search("llama");
        assert!(!results.is_empty());
        assert!(results.iter().all(|m| m.id.contains("llama")));
    }

    #[test]
    fn test_dynamic_models() {
        let registry = ModelRegistry::new();
        let initial_count = registry.len();

        // Add a dynamic model
        let card = ModelCard::new("test/custom-model");
        registry.add_dynamic(card).unwrap();

        assert_eq!(registry.len(), initial_count + 1);
        assert_eq!(registry.dynamic_count(), 1);

        // Should be findable
        let found = registry.get("test/custom-model");
        assert!(found.is_some());

        // Clear dynamic
        registry.clear_dynamic().unwrap();
        assert_eq!(registry.dynamic_count(), 0);
    }

    #[test]
    fn test_openrouter_response_parsing() {
        // Test that OpenRouterModelsResponse can deserialize API responses
        let json = r#"{
            "data": [
                {
                    "id": "openai/gpt-4o",
                    "name": "GPT-4o",
                    "context_length": 128000,
                    "pricing": {
                        "prompt": "0.000005",
                        "completion": "0.000015"
                    }
                },
                {
                    "id": "anthropic/claude-3-opus",
                    "name": "Claude 3 Opus",
                    "context_length": 200000
                }
            ]
        }"#;

        let response: OpenRouterModelsResponse = serde_json::from_str(json).unwrap();
        // Test the accessor methods
        assert_eq!(response.len(), 2);
        assert!(!response.is_empty());

        let models = response.models();
        assert_eq!(models[0].id, "openai/gpt-4o");
        assert_eq!(models[0].context_length, Some(128000));
        assert!(models[0].pricing.is_some());
        assert_eq!(models[1].id, "anthropic/claude-3-opus");
        assert!(models[1].pricing.is_none());
    }

    #[test]
    fn test_model_card_from_openrouter() {
        let model = OpenRouterModel {
            id: "openai/gpt-4o-test".to_string(),
            name: Some("GPT-4o Test".to_string()),
            context_length: Some(128000),
            pricing: Some(OpenRouterPricing {
                prompt: Some("0.000005".to_string()),
                completion: Some("0.000015".to_string()),
            }),
        };

        let card = ModelCard::from_openrouter(model);
        assert_eq!(card.id, "openai/gpt-4o-test");
        assert_eq!(card.provider, Provider::OpenAI);
        assert_eq!(card.context_length, 128000);
        assert!(card.pricing.is_some());
    }
}
