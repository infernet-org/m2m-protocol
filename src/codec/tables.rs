//! Abbreviation tables for token compression.
//!
//! These tables map common JSON keys, roles, and values to shorter forms
//! optimized for LLM tokenizer efficiency.

use phf::phf_map;

/// Key abbreviations (JSON keys → short form)
pub static KEY_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    // Request keys
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
    "system_fingerprint" => "sf",
    // Tool keys
    "type" => "t",
    "function" => "fn",
    "parameters" => "pm",
    "description" => "ds",
    "required" => "rq",
    "properties" => "pr",
    // Additional common keys
    "text" => "txt",
    "error" => "E",
    "code" => "cd",
};

/// Reverse key mapping (short form → full key)
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
    "sf" => "system_fingerprint",
    "t" => "type",
    "fn" => "function",
    "pm" => "parameters",
    "ds" => "description",
    "rq" => "required",
    "pr" => "properties",
    "txt" => "text",
    "E" => "error",
    "cd" => "code",
};

/// Role abbreviations
/// NOTE: "user" is NOT abbreviated (costs more tokens in some tokenizers)
pub static ROLE_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    "system" => "S",
    "assistant" => "A",
    "function" => "F",
    "tool" => "T",
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
/// This ensures accurate token counting for compression optimization.
pub static MODEL_ABBREV: phf::Map<&'static str, &'static str> = phf_map! {
    // OpenAI (tokenizer available via tiktoken)
    "gpt-4o" => "g4o",
    "gpt-4o-mini" => "g4om",
    "gpt-4-turbo" => "g4t",
    "gpt-4" => "g4",
    "gpt-3.5-turbo" => "g35t",
    "o1" => "o1",
    "o1-mini" => "o1m",
    "o3" => "o3",
    "o3-mini" => "o3m",
    // Meta Llama (open source tokenizer)
    "llama-3.1-405b" => "l31405",
    "llama-3.1-70b" => "l3170",
    "llama-3.1-8b" => "l318",
    "llama-3.3-70b" => "l3370",
    // Mistral (open source tokenizer)
    "mistral-large-latest" => "mll",
    "mistral-small-latest" => "msl",
    "mixtral-8x7b" => "mx87",
    "mixtral-8x22b" => "mx822",
    // DeepSeek (open source tokenizer)
    "deepseek-v3" => "dv3",
    "deepseek-r1" => "dr1",
    "deepseek-coder" => "dc",
    // Qwen (open source tokenizer)
    "qwen-2.5-72b" => "q2572",
    "qwen-2.5-32b" => "q2532",
    "qwen-2.5-coder-32b" => "qc32",
};

/// Reverse model mapping
pub static MODEL_EXPAND: phf::Map<&'static str, &'static str> = phf_map! {
    // OpenAI
    "g4o" => "gpt-4o",
    "g4om" => "gpt-4o-mini",
    "g4t" => "gpt-4-turbo",
    "g4" => "gpt-4",
    "g35t" => "gpt-3.5-turbo",
    "o1" => "o1",
    "o1m" => "o1-mini",
    "o3" => "o3",
    "o3m" => "o3-mini",
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
