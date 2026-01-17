//! Embedded model definitions.
//!
//! This module contains compile-time model definitions for LLMs with
//! publicly accessible tokenizers. Only models where we can accurately
//! count tokens are included.
//!
//! Supported providers:
//! - OpenAI (via tiktoken - cl100k_base, o200k_base)
//! - Meta Llama (open source BPE tokenizer)
//! - Mistral (open source tokenizer)
//! - DeepSeek (open source tokenizer)
//! - Qwen (open source tokenizer)
//! - Nvidia (Llama-based, open source)
//!
//! Excluded (closed tokenizers):
//! - Anthropic Claude
//! - Google Gemini
//! - X.AI Grok
//! - Cohere Command

use crate::models::{Encoding, ModelCard, Pricing};

/// Embedded model definition tuple: (id, abbrev, encoding, context_length)
pub type EmbeddedModel = (&'static str, &'static str, Encoding, u32);

/// All embedded model definitions
///
/// Only models with publicly accessible tokenizers are included.
/// Models are organized by provider.
pub static EMBEDDED_MODELS: &[EmbeddedModel] = &[
    // ============================================================
    // OpenAI Models (tokenizer available via tiktoken)
    // ============================================================

    // GPT-4o family (o200k_base encoding)
    ("openai/gpt-4o", "og4o", Encoding::O200kBase, 128000),
    ("openai/gpt-4o-mini", "og4om", Encoding::O200kBase, 128000),
    (
        "openai/gpt-4o-2024-11-20",
        "og4o1120",
        Encoding::O200kBase,
        128000,
    ),
    (
        "openai/gpt-4o-2024-08-06",
        "og4o0806",
        Encoding::O200kBase,
        128000,
    ),
    (
        "openai/gpt-4o-2024-05-13",
        "og4o0513",
        Encoding::O200kBase,
        128000,
    ),
    // GPT-4 family (cl100k_base encoding)
    ("openai/gpt-4-turbo", "og4t", Encoding::Cl100kBase, 128000),
    (
        "openai/gpt-4-turbo-preview",
        "og4tp",
        Encoding::Cl100kBase,
        128000,
    ),
    ("openai/gpt-4", "og4", Encoding::Cl100kBase, 8192),
    ("openai/gpt-4-32k", "og432k", Encoding::Cl100kBase, 32768),
    // GPT-3.5 family
    ("openai/gpt-3.5-turbo", "og35t", Encoding::Cl100kBase, 16385),
    (
        "openai/gpt-3.5-turbo-16k",
        "og35t16k",
        Encoding::Cl100kBase,
        16385,
    ),
    // o1/o3 reasoning models (o200k_base encoding)
    ("openai/o1", "oo1", Encoding::O200kBase, 200000),
    ("openai/o1-mini", "oo1m", Encoding::O200kBase, 128000),
    ("openai/o1-preview", "oo1p", Encoding::O200kBase, 128000),
    ("openai/o3", "oo3", Encoding::O200kBase, 200000),
    ("openai/o3-mini", "oo3m", Encoding::O200kBase, 200000),
    // ============================================================
    // Meta Llama Models (open source tokenizer)
    // ============================================================

    // Llama 3.3 family
    (
        "meta-llama/llama-3.3-70b",
        "ml3370",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "meta-llama/llama-3.3-70b-instruct",
        "ml3370i",
        Encoding::LlamaBpe,
        128000,
    ),
    // Llama 3.1 family
    (
        "meta-llama/llama-3.1-405b",
        "ml31405",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "meta-llama/llama-3.1-405b-instruct",
        "ml31405i",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "meta-llama/llama-3.1-70b",
        "ml3170",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "meta-llama/llama-3.1-70b-instruct",
        "ml3170i",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "meta-llama/llama-3.1-8b",
        "ml318",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "meta-llama/llama-3.1-8b-instruct",
        "ml318i",
        Encoding::LlamaBpe,
        128000,
    ),
    // Llama 3 family
    ("meta-llama/llama-3-70b", "ml370", Encoding::LlamaBpe, 8192),
    (
        "meta-llama/llama-3-70b-instruct",
        "ml370i",
        Encoding::LlamaBpe,
        8192,
    ),
    ("meta-llama/llama-3-8b", "ml38", Encoding::LlamaBpe, 8192),
    (
        "meta-llama/llama-3-8b-instruct",
        "ml38i",
        Encoding::LlamaBpe,
        8192,
    ),
    // ============================================================
    // Mistral Models (open source tokenizer)
    // ============================================================

    // Mistral Large
    (
        "mistralai/mistral-large",
        "mim-l",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "mistralai/mistral-large-latest",
        "mim-ll",
        Encoding::LlamaBpe,
        128000,
    ),
    (
        "mistralai/mistral-large-2411",
        "mim-l2411",
        Encoding::LlamaBpe,
        128000,
    ),
    // Mistral Medium/Small
    (
        "mistralai/mistral-medium",
        "mim-m",
        Encoding::LlamaBpe,
        32000,
    ),
    (
        "mistralai/mistral-small",
        "mim-s",
        Encoding::LlamaBpe,
        32000,
    ),
    (
        "mistralai/mistral-small-latest",
        "mim-sl",
        Encoding::LlamaBpe,
        32000,
    ),
    // Mixtral
    (
        "mistralai/mixtral-8x7b",
        "mimx87",
        Encoding::LlamaBpe,
        32000,
    ),
    (
        "mistralai/mixtral-8x7b-instruct",
        "mimx87i",
        Encoding::LlamaBpe,
        32000,
    ),
    (
        "mistralai/mixtral-8x22b",
        "mimx822",
        Encoding::LlamaBpe,
        65000,
    ),
    (
        "mistralai/mixtral-8x22b-instruct",
        "mimx822i",
        Encoding::LlamaBpe,
        65000,
    ),
    // Mistral 7B
    ("mistralai/mistral-7b", "mim7", Encoding::LlamaBpe, 32000),
    (
        "mistralai/mistral-7b-instruct",
        "mim7i",
        Encoding::LlamaBpe,
        32000,
    ),
    // Codestral
    (
        "mistralai/codestral-latest",
        "micodl",
        Encoding::LlamaBpe,
        32000,
    ),
    (
        "mistralai/codestral-mamba",
        "micodm",
        Encoding::LlamaBpe,
        256000,
    ),
    // ============================================================
    // DeepSeek Models (open source tokenizer)
    // ============================================================
    ("deepseek/deepseek-v3", "ddv3", Encoding::Heuristic, 64000),
    (
        "deepseek/deepseek-v2.5",
        "ddv25",
        Encoding::Heuristic,
        64000,
    ),
    ("deepseek/deepseek-r1", "ddr1", Encoding::Heuristic, 64000),
    (
        "deepseek/deepseek-r1-lite",
        "ddr1l",
        Encoding::Heuristic,
        64000,
    ),
    (
        "deepseek/deepseek-coder",
        "ddc",
        Encoding::Heuristic,
        128000,
    ),
    (
        "deepseek/deepseek-coder-v2",
        "ddcv2",
        Encoding::Heuristic,
        128000,
    ),
    (
        "deepseek/deepseek-chat",
        "ddchat",
        Encoding::Heuristic,
        64000,
    ),
    // ============================================================
    // Qwen Models (open source tokenizer)
    // ============================================================

    // Qwen 2.5
    ("qwen/qwen-2.5-72b", "qq2572", Encoding::Heuristic, 131072),
    (
        "qwen/qwen-2.5-72b-instruct",
        "qq2572i",
        Encoding::Heuristic,
        131072,
    ),
    ("qwen/qwen-2.5-32b", "qq2532", Encoding::Heuristic, 131072),
    (
        "qwen/qwen-2.5-32b-instruct",
        "qq2532i",
        Encoding::Heuristic,
        131072,
    ),
    ("qwen/qwen-2.5-14b", "qq2514", Encoding::Heuristic, 131072),
    ("qwen/qwen-2.5-7b", "qq257", Encoding::Heuristic, 131072),
    // Qwen 2.5 Coder
    (
        "qwen/qwen-2.5-coder-32b",
        "qqc32",
        Encoding::Heuristic,
        131072,
    ),
    (
        "qwen/qwen-2.5-coder-32b-instruct",
        "qqc32i",
        Encoding::Heuristic,
        131072,
    ),
    (
        "qwen/qwen-2.5-coder-14b",
        "qqc14",
        Encoding::Heuristic,
        131072,
    ),
    (
        "qwen/qwen-2.5-coder-7b",
        "qqc7",
        Encoding::Heuristic,
        131072,
    ),
    // ============================================================
    // Nvidia Models (Llama-based, open source tokenizer)
    // ============================================================
    ("nvidia/nemotron-70b", "nn70", Encoding::LlamaBpe, 32768),
    (
        "nvidia/llama-3.1-nemotron-70b-instruct",
        "nnl3170i",
        Encoding::LlamaBpe,
        32768,
    ),
];

/// Get all embedded models as ModelCard instances
pub fn get_embedded_models() -> Vec<ModelCard> {
    EMBEDDED_MODELS
        .iter()
        .map(|(id, abbrev, encoding, ctx_len)| {
            ModelCard::with_abbrev(*id, *abbrev)
                .encoding(*encoding)
                .context_length(*ctx_len)
        })
        .collect()
}

/// Get embedded model by ID
pub fn get_embedded_by_id(id: &str) -> Option<ModelCard> {
    EMBEDDED_MODELS
        .iter()
        .find(|(model_id, _, _, _)| *model_id == id)
        .map(|(id, abbrev, encoding, ctx_len)| {
            ModelCard::with_abbrev(*id, *abbrev)
                .encoding(*encoding)
                .context_length(*ctx_len)
        })
}

/// Get embedded model by abbreviation
pub fn get_embedded_by_abbrev(abbrev: &str) -> Option<ModelCard> {
    EMBEDDED_MODELS
        .iter()
        .find(|(_, model_abbrev, _, _)| *model_abbrev == abbrev)
        .map(|(id, abbrev, encoding, ctx_len)| {
            ModelCard::with_abbrev(*id, *abbrev)
                .encoding(*encoding)
                .context_length(*ctx_len)
        })
}

/// Get pricing for popular models (per million tokens, USD)
pub fn get_pricing(model_id: &str) -> Option<Pricing> {
    // Prices as of January 2026 (approximate)
    match model_id {
        // OpenAI
        "openai/gpt-4o" => Some(Pricing::from_per_million(2.50, 10.00)),
        "openai/gpt-4o-mini" => Some(Pricing::from_per_million(0.15, 0.60)),
        "openai/gpt-4-turbo" => Some(Pricing::from_per_million(10.00, 30.00)),
        "openai/gpt-4" => Some(Pricing::from_per_million(30.00, 60.00)),
        "openai/gpt-3.5-turbo" => Some(Pricing::from_per_million(0.50, 1.50)),
        "openai/o1" => Some(Pricing::from_per_million(15.00, 60.00)),
        "openai/o1-mini" => Some(Pricing::from_per_million(3.00, 12.00)),

        // DeepSeek (very competitive pricing)
        "deepseek/deepseek-v3" | "deepseek/deepseek-chat" => {
            Some(Pricing::from_per_million(0.27, 1.10))
        },
        "deepseek/deepseek-r1" => Some(Pricing::from_per_million(0.55, 2.19)),

        // Mistral
        "mistralai/mistral-large" | "mistralai/mistral-large-latest" => {
            Some(Pricing::from_per_million(2.00, 6.00))
        },
        "mistralai/mistral-small" | "mistralai/mistral-small-latest" => {
            Some(Pricing::from_per_million(0.20, 0.60))
        },

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_models_count() {
        // Should have at least 50 models (removed ~20 closed tokenizer models)
        assert!(
            EMBEDDED_MODELS.len() >= 50,
            "Expected at least 50 embedded models, got {}",
            EMBEDDED_MODELS.len()
        );
    }

    #[test]
    fn test_unique_abbreviations() {
        let mut seen = std::collections::HashSet::new();
        for (id, abbrev, _, _) in EMBEDDED_MODELS {
            assert!(
                seen.insert(*abbrev),
                "Duplicate abbreviation '{abbrev}' for model '{id}'"
            );
        }
    }

    #[test]
    fn test_unique_ids() {
        let mut seen = std::collections::HashSet::new();
        for (id, _, _, _) in EMBEDDED_MODELS {
            assert!(seen.insert(*id), "Duplicate model ID '{id}'");
        }
    }

    #[test]
    fn test_get_embedded_by_id() {
        let card = get_embedded_by_id("openai/gpt-4o").expect("Should find gpt-4o");
        assert_eq!(card.abbrev, "og4o");
        assert_eq!(card.encoding, Encoding::O200kBase);
    }

    #[test]
    fn test_get_embedded_by_abbrev() {
        let card = get_embedded_by_abbrev("ml3170i").expect("Should find llama-3.1-70b-instruct");
        assert_eq!(card.id, "meta-llama/llama-3.1-70b-instruct");
        assert_eq!(card.context_length, 128000);
    }

    #[test]
    fn test_pricing() {
        let pricing = get_pricing("openai/gpt-4o").expect("Should have pricing for gpt-4o");
        // GPT-4o is $2.50/M input, so 1M tokens = $2.50
        let cost = pricing.prompt * 1_000_000.0;
        assert!((cost - 2.50).abs() < 0.01);
    }

    #[test]
    fn test_all_providers_represented() {
        use crate::models::Provider;

        let models = get_embedded_models();
        let providers: std::collections::HashSet<_> = models.iter().map(|m| m.provider).collect();

        // Only providers with public tokenizers
        assert!(providers.contains(&Provider::OpenAI), "Missing OpenAI");
        assert!(providers.contains(&Provider::Meta), "Missing Meta");
        assert!(providers.contains(&Provider::Mistral), "Missing Mistral");
        assert!(providers.contains(&Provider::DeepSeek), "Missing DeepSeek");
        assert!(providers.contains(&Provider::Qwen), "Missing Qwen");
        assert!(providers.contains(&Provider::Nvidia), "Missing Nvidia");

        // Should NOT contain closed tokenizer providers
        assert!(
            !providers.contains(&Provider::Other),
            "Should not have Other provider for known models"
        );
    }
}
