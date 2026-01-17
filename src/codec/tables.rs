//! Abbreviation tables for token compression.
//!
//! These tables map common JSON keys, roles, and values to shorter forms
//! **optimized for LLM tokenizer efficiency** (not just byte reduction).
//!
//! # Token-Optimized Design
//!
//! All abbreviations in this module have been empirically validated to reduce
//! token count using tiktoken cl100k_base encoding. Abbreviations that only
//! save bytes but not tokens have been removed.
//!
//! Run `cargo run --bin token_analysis` to verify token savings.

use phf::phf_map;

/// Key abbreviations (JSON keys -> short form)
///
/// **ONLY includes abbreviations that save tokens** (validated via token_analysis)
///
/// Removed (cost same or more tokens):
/// - user, description, type, text (WORSE - cost MORE tokens)
/// - messages, message, role, usage, name, code, functions, parameters,
///   object, function, properties, index, required, id, n, seed, tools, created (NO SAVE)
pub static KEY_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    // Token-saving request keys (verified +1 to +2 tokens saved)
    "content" => "c",           // 3->2 tokens (+1)
    "model" => "M",             // 3->2 tokens (+1)
    "temperature" => "T",       // 3->2 tokens (+1)
    "max_tokens" => "x",        // 4->2 tokens (+2)
    "stream" => "s",            // 3->2 tokens (+1)
    "stop" => "S",              // 3->2 tokens (+1)
    "top_p" => "p",             // 4->3 tokens (+1)
    "frequency_penalty" => "f", // 4->2 tokens (+2)
    "presence_penalty" => "P",  // 4->2 tokens (+2)
    "function_call" => "fc",    // 4->3 tokens (+1)
    "arguments" => "a",         // 3->2 tokens (+1)
    "tool_calls" => "tc",       // 4->3 tokens (+1)
    "tool_choice" => "tx",      // 4->3 tokens (+1)
    "response_format" => "rf",  // 4->3 tokens (+1)
    "logit_bias" => "lb",       // 4->3 tokens (+1)
    "logprobs" => "lp",         // 4->3 tokens (+1)
    "top_logprobs" => "tlp",    // 6->4 tokens (+2)
    // Token-saving response keys
    "choices" => "C",           // 3->2 tokens (+1)
    "finish_reason" => "fr",    // 4->3 tokens (+1)
    "prompt_tokens" => "pt",    // 4->3 tokens (+1)
    "completion_tokens" => "ct",// 4->3 tokens (+1)
    "total_tokens" => "tt",     // 4->3 tokens (+1)
    "delta" => "D",             // 3->2 tokens (+1)
    "system_fingerprint" => "sf", // 5->3 tokens (+2)
    "error" => "E",             // 3->2 tokens (+1)
};

/// Reverse key mapping (short form -> full key)
pub static KEY_EXPAND: phf::Map<&'static str, &'static str> = phf_map! {
    "c" => "content",
    "M" => "model",
    "T" => "temperature",
    "x" => "max_tokens",
    "s" => "stream",
    "S" => "stop",
    "p" => "top_p",
    "f" => "frequency_penalty",
    "P" => "presence_penalty",
    "fc" => "function_call",
    "a" => "arguments",
    "tc" => "tool_calls",
    "tx" => "tool_choice",
    "rf" => "response_format",
    "lb" => "logit_bias",
    "lp" => "logprobs",
    "tlp" => "top_logprobs",
    "C" => "choices",
    "fr" => "finish_reason",
    "pt" => "prompt_tokens",
    "ct" => "completion_tokens",
    "tt" => "total_tokens",
    "D" => "delta",
    "sf" => "system_fingerprint",
    "E" => "error",
};

/// Role abbreviations
///
/// All role abbreviations save tokens (verified +1 each).
/// Note: "user" is NOT abbreviated (analysis shows it costs MORE tokens as "u")
pub static ROLE_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    "system" => "S",     // 3->2 tokens (+1)
    "assistant" => "A",  // 3->2 tokens (+1)
    "function" => "F",   // 3->2 tokens (+1)
    "tool" => "T",       // 3->2 tokens (+1)
};

/// Reverse role mapping
pub static ROLE_EXPAND: phf::Map<&'static str, &'static str> = phf_map! {
    "S" => "system",
    "A" => "assistant",
    "F" => "function",
    "T" => "tool",
};

/// Model name abbreviations
///
/// Only models with publicly accessible tokenizers are included.
/// All abbreviations save 2-9 tokens (verified via token_analysis).
///
/// Removed (no token savings): o1, o3, o1-mini, o3-mini
pub static MODEL_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    // OpenAI (tokenizer available via tiktoken)
    "gpt-4o" => "g4o",           // 6->4 tokens (+2)
    "gpt-4o-mini" => "g4om",     // 7->4 tokens (+3)
    "gpt-4-turbo" => "g4t",      // 8->4 tokens (+4)
    "gpt-4" => "g4",             // 5->3 tokens (+2)
    "gpt-3.5-turbo" => "g35t",   // 10->4 tokens (+6)
    // Meta Llama (open source tokenizer)
    "llama-3.1-405b" => "l31405", // 11->5 tokens (+6)
    "llama-3.1-70b" => "l3170",   // 11->5 tokens (+6)
    "llama-3.1-8b" => "l318",     // 11->4 tokens (+7)
    "llama-3.3-70b" => "l3370",   // 11->5 tokens (+6)
    // Mistral (open source tokenizer)
    "mistral-large-latest" => "mll",  // 7->4 tokens (+3)
    "mistral-small-latest" => "msl",  // 7->4 tokens (+3)
    "mixtral-8x7b" => "mx87",         // 10->4 tokens (+6)
    "mixtral-8x22b" => "mx822",       // 10->4 tokens (+6)
    // DeepSeek (open source tokenizer)
    "deepseek-v3" => "dv3",      // 6->4 tokens (+2)
    "deepseek-r1" => "dr1",      // 6->4 tokens (+2)
    "deepseek-coder" => "dc",    // 6->3 tokens (+3)
    // Qwen (open source tokenizer)
    "qwen-2.5-72b" => "q2572",   // 11->5 tokens (+6)
    "qwen-2.5-32b" => "q2532",   // 11->5 tokens (+6)
    "qwen-2.5-coder-32b" => "qc32", // 13->4 tokens (+9)
};

/// Reverse model mapping
pub static MODEL_EXPAND: phf::Map<&'static str, &'static str> = phf_map! {
    // OpenAI
    "g4o" => "gpt-4o",
    "g4om" => "gpt-4o-mini",
    "g4t" => "gpt-4-turbo",
    "g4" => "gpt-4",
    "g35t" => "gpt-3.5-turbo",
    // Meta Llama
    "l31405" => "llama-3.1-405b",
    "l3170" => "llama-3.1-70b",
    "l318" => "llama-3.1-8b",
    "l3370" => "llama-3.3-70b",
    // Mistral
    "mll" => "mistral-large-latest",
    "msl" => "mistral-small-latest",
    "mx87" => "mixtral-8x7b",
    "mx822" => "mixtral-8x22b",
    // DeepSeek
    "dv3" => "deepseek-v3",
    "dr1" => "deepseek-r1",
    "dc" => "deepseek-coder",
    // Qwen
    "q2572" => "qwen-2.5-72b",
    "q2532" => "qwen-2.5-32b",
    "qc32" => "qwen-2.5-coder-32b",
};

/// High-frequency patterns for token-efficient compression
///
/// These patterns are 5-8 tokens each and can be replaced with single-token
/// escape sequences for significant savings. Use \u00XX format for JSON safety.
///
/// Pattern encoding: \u0001 to \u001F (control chars, valid in JSON strings)
pub static PATTERN_ABBREV: &[(&str, &str)] = &[
    // Role patterns (7 tokens each -> 1 token)
    (r#"{"role":"user","content":""#, "\u{0001}"),
    (r#"{"role":"assistant","content":""#, "\u{0002}"),
    (r#"{"role":"system","content":""#, "\u{0003}"),
    (r#"{"role":"tool","content":""#, "\u{0004}"),
    // Streaming patterns (8 tokens each -> 1 token)
    (r#"{"index":0,"delta":{"#, "\u{0005}"),
    (r#"{"index":0,"message":{"#, "\u{0006}"),
    // Finish reason patterns (6-7 tokens each -> 1 token)
    (r#""finish_reason":"stop""#, "\u{0007}"),
    (r#""finish_reason":"length""#, "\u{0008}"),
    (r#""finish_reason":"tool_calls""#, "\u{0009}"),
    // Tool patterns (8 tokens -> 1 token)
    (r#"{"type":"function","function":{"#, "\u{000A}"),
    // Common structural patterns (3-4 tokens each -> 1 token)
    (r#""choices":[{"#, "\u{000B}"),
    (r#"{"messages":["#, "\u{000C}"),
    (r#"],"model":""#, "\u{000D}"),
];

/// Reverse pattern mapping for decompression
pub static PATTERN_EXPAND: &[(&str, &str)] = &[
    ("\u{0001}", r#"{"role":"user","content":""#),
    ("\u{0002}", r#"{"role":"assistant","content":""#),
    ("\u{0003}", r#"{"role":"system","content":""#),
    ("\u{0004}", r#"{"role":"tool","content":""#),
    ("\u{0005}", r#"{"index":0,"delta":{"#),
    ("\u{0006}", r#"{"index":0,"message":{"#),
    ("\u{0007}", r#""finish_reason":"stop""#),
    ("\u{0008}", r#""finish_reason":"length""#),
    ("\u{0009}", r#""finish_reason":"tool_calls""#),
    ("\u{000A}", r#"{"type":"function","function":{"#),
    ("\u{000B}", r#""choices":[{"#),
    ("\u{000C}", r#"{"messages":["#),
    ("\u{000D}", r#"],"model":""#),
];

/// Check if a value is a default that can be removed
pub fn is_default_value(key: &str, value: &serde_json::Value) -> bool {
    use serde_json::Value;

    match (key, value) {
        ("temperature" | "T", Value::Number(n)) => {
            n.as_f64().map(|f| (f - 1.0).abs() < 0.001).unwrap_or(false)
        },
        ("top_p" | "p", Value::Number(n)) => {
            n.as_f64().map(|f| (f - 1.0).abs() < 0.001).unwrap_or(false)
        },
        ("n", Value::Number(n)) => n.as_i64() == Some(1),
        ("stream" | "s", Value::Bool(b)) => !b,
        ("frequency_penalty" | "f", Value::Number(n)) => {
            n.as_i64() == Some(0) || n.as_f64() == Some(0.0)
        },
        ("presence_penalty" | "P", Value::Number(n)) => {
            n.as_i64() == Some(0) || n.as_f64() == Some(0.0)
        },
        ("logit_bias" | "lb", Value::Object(m)) => m.is_empty(),
        ("stop" | "S", Value::Null) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_roundtrip() {
        for (full, abbrev) in KEY_ABBREV.entries() {
            assert_eq!(
                KEY_EXPAND.get(*abbrev),
                Some(full),
                "Key '{full}' -> '{abbrev}' doesn't round-trip"
            );
        }
    }

    #[test]
    fn test_role_roundtrip() {
        for (full, abbrev) in ROLE_ABBREV.entries() {
            assert_eq!(
                ROLE_EXPAND.get(*abbrev),
                Some(full),
                "Role '{full}' -> '{abbrev}' doesn't round-trip"
            );
        }
    }

    #[test]
    fn test_model_roundtrip() {
        for (full, abbrev) in MODEL_ABBREV.entries() {
            assert_eq!(
                MODEL_EXPAND.get(*abbrev),
                Some(full),
                "Model '{full}' -> '{abbrev}' doesn't round-trip"
            );
        }
    }

    #[test]
    fn test_pattern_roundtrip() {
        for (pattern, abbrev) in PATTERN_ABBREV {
            let expanded = PATTERN_EXPAND
                .iter()
                .find(|(a, _)| a == abbrev)
                .map(|(_, p)| *p);
            assert_eq!(
                expanded,
                Some(*pattern),
                "Pattern '{pattern}' -> '{abbrev:?}' doesn't round-trip"
            );
        }
    }

    #[test]
    fn test_default_detection() {
        use serde_json::json;

        assert!(is_default_value("temperature", &json!(1.0)));
        assert!(!is_default_value("temperature", &json!(0.7)));
        assert!(is_default_value("stream", &json!(false)));
        assert!(!is_default_value("stream", &json!(true)));
        assert!(is_default_value("n", &json!(1)));
        assert!(!is_default_value("n", &json!(2)));
    }
}
