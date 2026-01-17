//! Embedded model definitions.
//!
//! This module contains compile-time model definitions for LLMs with
//! publicly accessible tokenizers. Only models where we can accurately
//! count tokens are included.
//!
//! Supported providers (2026):
//! - OpenAI (via tiktoken - cl100k_base, o200k_base) - GPT-5.x, GPT-4.x, o1-o4
//! - Meta Llama (open source BPE tokenizer) - Llama 4, 3.x
//! - Mistral (open source tokenizer) - Large, Ministral, Devstral
//! - DeepSeek (open source tokenizer) - v3.2, R1
//! - Qwen (open source tokenizer) - Qwen 3, 2.5
//! - Nvidia (Llama-based) - Nemotron 3
//! - Google Gemma (open source) - Gemma 3
//! - Allen AI OLMo (fully open) - OLMo 3.1
//!
//! Excluded (closed tokenizers):
//! - Anthropic Claude (4.x, 3.x)
//! - Google Gemini (3.x, 2.x)
//! - X.AI Grok (4.x)
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

    // GPT-5.x family (2026 - o200k_base encoding)
    ("openai/gpt-5.2", "og52", Encoding::O200kBase, 400000),
    ("openai/gpt-5.2-pro", "og52p", Encoding::O200kBase, 400000),
    ("openai/gpt-5.2-codex", "og52c", Encoding::O200kBase, 400000),
    ("openai/gpt-5.2-chat", "og52ch", Encoding::O200kBase, 128000),
    ("openai/gpt-5.1", "og51", Encoding::O200kBase, 400000),
    ("openai/gpt-5.1-codex", "og51c", Encoding::O200kBase, 400000),
    (
        "openai/gpt-5.1-codex-mini",
        "og51cm",
        Encoding::O200kBase,
        400000,
    ),
    ("openai/gpt-5", "og5", Encoding::O200kBase, 400000),
    ("openai/gpt-5-pro", "og5p", Encoding::O200kBase, 400000),
    ("openai/gpt-5-mini", "og5m", Encoding::O200kBase, 128000),
    ("openai/gpt-5-nano", "og5n", Encoding::O200kBase, 64000),
    // GPT-4.1 family (2025-2026)
    ("openai/gpt-4.1", "og41", Encoding::O200kBase, 128000),
    ("openai/gpt-4.1-mini", "og41m", Encoding::O200kBase, 128000),
    ("openai/gpt-4.1-nano", "og41n", Encoding::O200kBase, 64000),
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
    // o-series reasoning models (o200k_base encoding)
    ("openai/o4-mini", "oo4m", Encoding::O200kBase, 200000),
    ("openai/o4-mini-high", "oo4mh", Encoding::O200kBase, 200000),
    ("openai/o3", "oo3", Encoding::O200kBase, 200000),
    ("openai/o3-pro", "oo3p", Encoding::O200kBase, 200000),
    ("openai/o3-mini", "oo3m", Encoding::O200kBase, 200000),
    ("openai/o3-mini-high", "oo3mh", Encoding::O200kBase, 200000),
    ("openai/o1", "oo1", Encoding::O200kBase, 200000),
    ("openai/o1-pro", "oo1p", Encoding::O200kBase, 200000),
    // ============================================================
    // Meta Llama Models (open source tokenizer)
    // ============================================================

    // Llama 4 family (2026)
    (
        "meta-llama/llama-4-maverick",
        "ml4mav",
        Encoding::LlamaBpe,
        256000,
    ),
    (
        "meta-llama/llama-4-scout",
        "ml4sc",
        Encoding::LlamaBpe,
        256000,
    ),
    // Llama Guard 4
    (
        "meta-llama/llama-guard-4-12b",
        "mlg412",
        Encoding::LlamaBpe,
        131072,
    ),
    (
        "meta-llama/llama-guard-3-8b",
        "mlg38",
        Encoding::LlamaBpe,
        131072,
    ),
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

    // Mistral Large 2512 (2026)
    (
        "mistralai/mistral-large-2512",
        "mim-l2512",
        Encoding::LlamaBpe,
        262144,
    ),
    // Ministral (2026)
    (
        "mistralai/ministral-14b-2512",
        "mimin14",
        Encoding::LlamaBpe,
        262144,
    ),
    (
        "mistralai/ministral-8b-2512",
        "mimin8",
        Encoding::LlamaBpe,
        262144,
    ),
    (
        "mistralai/ministral-3b-2512",
        "mimin3",
        Encoding::LlamaBpe,
        131072,
    ),
    // Devstral (2026)
    (
        "mistralai/devstral-2512",
        "midev2512",
        Encoding::LlamaBpe,
        262144,
    ),
    (
        "mistralai/devstral-medium",
        "midevmed",
        Encoding::LlamaBpe,
        262144,
    ),
    (
        "mistralai/devstral-small",
        "midevsm",
        Encoding::LlamaBpe,
        131072,
    ),
    // Codestral (2026)
    (
        "mistralai/codestral-2508",
        "micod2508",
        Encoding::LlamaBpe,
        262144,
    ),
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

    // DeepSeek v3.2 (2026)
    (
        "deepseek/deepseek-v3.2",
        "ddv32",
        Encoding::Heuristic,
        163840,
    ),
    (
        "deepseek/deepseek-v3.2-speciale",
        "ddv32s",
        Encoding::Heuristic,
        163840,
    ),
    // DeepSeek v3.1
    (
        "deepseek/deepseek-chat-v3.1",
        "ddv31",
        Encoding::Heuristic,
        163840,
    ),
    // DeepSeek R1 (2026)
    ("deepseek/deepseek-r1", "ddr1", Encoding::Heuristic, 163840),
    (
        "deepseek/deepseek-r1-0528",
        "ddr10528",
        Encoding::Heuristic,
        163840,
    ),
    (
        "deepseek/deepseek-r1-distill-llama-70b",
        "ddr1dl70",
        Encoding::LlamaBpe,
        131072,
    ),
    (
        "deepseek/deepseek-r1-distill-qwen-32b",
        "ddr1dq32",
        Encoding::Heuristic,
        131072,
    ),
    // DeepSeek v3
    ("deepseek/deepseek-v3", "ddv3", Encoding::Heuristic, 64000),
    (
        "deepseek/deepseek-chat",
        "ddchat",
        Encoding::Heuristic,
        64000,
    ),
    (
        "deepseek/deepseek-chat-v3-0324",
        "ddv30324",
        Encoding::Heuristic,
        64000,
    ),
    // ============================================================
    // Qwen Models (open source tokenizer)
    // ============================================================

    // Qwen 3 (2026)
    (
        "qwen/qwen3-235b-a22b",
        "qq3235",
        Encoding::Heuristic,
        131072,
    ),
    (
        "qwen/qwen3-235b-a22b-2507",
        "qq32352507",
        Encoding::Heuristic,
        131072,
    ),
    ("qwen/qwen3-32b", "qq332", Encoding::Heuristic, 131072),
    ("qwen/qwen3-14b", "qq314", Encoding::Heuristic, 131072),
    ("qwen/qwen3-8b", "qq38", Encoding::Heuristic, 131072),
    // Qwen 3 MoE
    ("qwen/qwen3-30b-a3b", "qq330a3", Encoding::Heuristic, 131072),
    (
        "qwen/qwen3-30b-a3b-instruct-2507",
        "qq330i",
        Encoding::Heuristic,
        131072,
    ),
    // Qwen 3 Coder
    ("qwen/qwen3-coder", "qq3cod", Encoding::Heuristic, 262144),
    (
        "qwen/qwen3-coder-plus",
        "qq3codp",
        Encoding::Heuristic,
        262144,
    ),
    (
        "qwen/qwen3-coder-flash",
        "qq3codf",
        Encoding::Heuristic,
        131072,
    ),
    // Qwen 3 VL (Vision-Language)
    (
        "qwen/qwen3-vl-235b-a22b-instruct",
        "qq3vl235",
        Encoding::Heuristic,
        131072,
    ),
    (
        "qwen/qwen3-vl-32b-instruct",
        "qq3vl32",
        Encoding::Heuristic,
        131072,
    ),
    // Qwen 2.5
    ("qwen/qwen-2.5-72b", "qq2572", Encoding::Heuristic, 131072),
    (
        "qwen/qwen-2.5-72b-instruct",
        "qq2572i",
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
        "qwen/qwen-2.5-7b-instruct",
        "qq257i",
        Encoding::Heuristic,
        131072,
    ),
    // QwQ (reasoning)
    ("qwen/qwq-32b", "qqwq32", Encoding::Heuristic, 131072),
    // ============================================================
    // Nvidia Models (Llama-based, open source tokenizer)
    // ============================================================

    // Nemotron 3 (2026)
    (
        "nvidia/nemotron-3-nano-30b-a3b",
        "nn3nano30",
        Encoding::LlamaBpe,
        262144,
    ),
    (
        "nvidia/nemotron-nano-12b-v2-vl",
        "nnnano12vl",
        Encoding::LlamaBpe,
        131072,
    ),
    // Nemotron (legacy)
    ("nvidia/nemotron-70b", "nn70", Encoding::LlamaBpe, 32768),
    (
        "nvidia/llama-3.1-nemotron-70b-instruct",
        "nnl3170i",
        Encoding::LlamaBpe,
        32768,
    ),
    // ============================================================
    // Google Gemma Models (open source tokenizer)
    // ============================================================

    // Gemma 3 (2026)
    (
        "google/gemma-3-27b-it",
        "gg327",
        Encoding::Heuristic,
        131072,
    ),
    (
        "google/gemma-3-12b-it",
        "gg312",
        Encoding::Heuristic,
        131072,
    ),
    ("google/gemma-3-4b-it", "gg34", Encoding::Heuristic, 131072),
    // Gemma 3n (nano)
    (
        "google/gemma-3n-e4b-it",
        "gg3n4",
        Encoding::Heuristic,
        131072,
    ),
    // Gemma 2 (legacy)
    ("google/gemma-2-27b-it", "gg227", Encoding::Heuristic, 8192),
    ("google/gemma-2-9b-it", "gg29", Encoding::Heuristic, 8192),
    // ============================================================
    // Allen AI OLMo Models (fully open source)
    // ============================================================

    // OLMo 3.1 (2026)
    (
        "allenai/olmo-3.1-32b-instruct",
        "aolmo3132i",
        Encoding::Heuristic,
        65536,
    ),
    (
        "allenai/olmo-3.1-32b-think",
        "aolmo3132t",
        Encoding::Heuristic,
        65536,
    ),
    // OLMo 3 (2026)
    (
        "allenai/olmo-3-32b-think",
        "aolmo332t",
        Encoding::Heuristic,
        65536,
    ),
    (
        "allenai/olmo-3-7b-instruct",
        "aolmo37i",
        Encoding::Heuristic,
        65536,
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
    // Prices as of January 2026 from OpenRouter
    match model_id {
        // OpenAI GPT-5.x (2026)
        "openai/gpt-5.2" | "openai/gpt-5.2-codex" => Some(Pricing::from_per_million(1.75, 7.00)),
        "openai/gpt-5.2-pro" => Some(Pricing::from_per_million(21.00, 84.00)),
        "openai/gpt-5.1" | "openai/gpt-5.1-codex" => Some(Pricing::from_per_million(1.25, 5.00)),
        "openai/gpt-5" => Some(Pricing::from_per_million(1.75, 7.00)),
        "openai/gpt-5-pro" => Some(Pricing::from_per_million(15.00, 60.00)),
        "openai/gpt-5-mini" => Some(Pricing::from_per_million(0.30, 1.20)),
        "openai/gpt-5-nano" => Some(Pricing::from_per_million(0.10, 0.40)),

        // OpenAI GPT-4.x
        "openai/gpt-4.1" => Some(Pricing::from_per_million(2.00, 8.00)),
        "openai/gpt-4.1-mini" => Some(Pricing::from_per_million(0.40, 1.60)),
        "openai/gpt-4o" => Some(Pricing::from_per_million(2.50, 10.00)),
        "openai/gpt-4o-mini" => Some(Pricing::from_per_million(0.15, 0.60)),
        "openai/gpt-4-turbo" => Some(Pricing::from_per_million(10.00, 30.00)),
        "openai/gpt-4" => Some(Pricing::from_per_million(30.00, 60.00)),
        "openai/gpt-3.5-turbo" => Some(Pricing::from_per_million(0.50, 1.50)),

        // OpenAI o-series reasoning
        "openai/o4-mini" => Some(Pricing::from_per_million(1.10, 4.40)),
        "openai/o3" => Some(Pricing::from_per_million(10.00, 40.00)),
        "openai/o3-pro" => Some(Pricing::from_per_million(20.00, 80.00)),
        "openai/o3-mini" => Some(Pricing::from_per_million(1.10, 4.40)),
        "openai/o1" => Some(Pricing::from_per_million(15.00, 60.00)),
        "openai/o1-pro" => Some(Pricing::from_per_million(150.00, 600.00)),

        // DeepSeek (very competitive pricing)
        "deepseek/deepseek-v3.2" | "deepseek/deepseek-chat" => {
            Some(Pricing::from_per_million(0.25, 1.00))
        },
        "deepseek/deepseek-r1" => Some(Pricing::from_per_million(0.55, 2.19)),

        // Mistral (2026)
        "mistralai/mistral-large-2512" => Some(Pricing::from_per_million(0.50, 1.50)),
        "mistralai/ministral-8b-2512" => Some(Pricing::from_per_million(0.15, 0.15)),
        "mistralai/devstral-2512" => Some(Pricing::from_per_million(0.05, 0.05)),

        // Qwen 3 (2026)
        "qwen/qwen3-235b-a22b" => Some(Pricing::from_per_million(0.20, 0.60)),
        "qwen/qwen3-coder" => Some(Pricing::from_per_million(0.14, 0.14)),

        // Meta Llama 4
        "meta-llama/llama-4-maverick" => Some(Pricing::from_per_million(0.20, 0.60)),
        "meta-llama/llama-4-scout" => Some(Pricing::from_per_million(0.08, 0.30)),

        // Google Gemma 3 (free tiers available)
        "google/gemma-3-27b-it" => Some(Pricing::from_per_million(0.10, 0.10)),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_models_count() {
        // Should have at least 80 models after 2026 updates
        assert!(
            EMBEDDED_MODELS.len() >= 80,
            "Expected at least 80 embedded models, got {}",
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
        assert!(
            providers.contains(&Provider::Google),
            "Missing Google (Gemma)"
        );
    }
}
