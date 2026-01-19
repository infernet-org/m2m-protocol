//! Token Savings Benchmark
//!
//! Validates M2M compression achieves good token savings.
//!
//! Run with: cargo run --bin token_benchmark

use m2m::codec::{Algorithm, CodecEngine};
use m2m::models::Encoding;
use serde_json::json;

fn separator(c: char, len: usize) -> String {
    std::iter::repeat(c).take(len).collect()
}

fn main() {
    println!("\n{}", separator('=', 80));
    println!(" TOKEN SAVINGS BENCHMARK");
    println!(" Validating >= 20% token savings target");
    println!("{}\n", separator('=', 80));

    let engine = CodecEngine::new();
    let encoding = Encoding::Cl100kBase;

    // Test payloads of increasing complexity
    let payloads = vec![
        (
            "minimal",
            json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Hi"}]
            }),
        ),
        (
            "simple_chat",
            json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "What is the capital of France?"}
                ]
            }),
        ),
        (
            "multi_turn",
            json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hello! How can I help you today?"},
                    {"role": "user", "content": "What is 2+2?"},
                    {"role": "assistant", "content": "2+2 equals 4."},
                    {"role": "user", "content": "Thanks! Now what is 3+3?"}
                ],
                "temperature": 0.7
            }),
        ),
        (
            "with_tools",
            json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "What's the weather in Paris?"}],
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "description": "Get current weather for a location",
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "location": {"type": "string", "description": "City name"},
                                    "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
                                },
                                "required": ["location"]
                            }
                        }
                    }
                ],
                "tool_choice": "auto"
            }),
        ),
        (
            "response",
            json!({
                "id": "chatcmpl-123456",
                "object": "chat.completion",
                "created": 1234567890,
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Hello! I'm here to help you with any questions or tasks you may have. How can I assist you today?"
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 25,
                    "completion_tokens": 30,
                    "total_tokens": 55
                }
            }),
        ),
        (
            "long_context",
            json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": format!(
                        "Please summarize the following text:\n\n{}",
                        "The quick brown fox jumps over the lazy dog. ".repeat(20)
                    )}
                ],
                "max_tokens": 500
            }),
        ),
    ];

    // Track totals
    let mut total_original_tokens = 0usize;
    let mut total_compressed_tokens = 0usize;
    let mut total_original_bytes = 0usize;
    let mut total_compressed_bytes = 0usize;

    println!(
        "{:<15} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Payload", "Orig Tok", "Comp Tok", "Savings", "Bytes", "Byte Sav"
    );
    println!("{}", separator('-', 80));

    for (name, payload) in &payloads {
        let content = serde_json::to_string(payload).unwrap();

        // Use M2M compression with token tracking
        let result = engine
            .compress_with_tokens(&content, Algorithm::M2M, encoding)
            .unwrap();

        let original_tokens = result.original_tokens.unwrap();
        let compressed_tokens = result.compressed_tokens.unwrap();
        let token_savings =
            (original_tokens as f64 - compressed_tokens as f64) / original_tokens as f64 * 100.0;
        let byte_savings = (result.original_bytes as f64 - result.compressed_bytes as f64)
            / result.original_bytes as f64
            * 100.0;

        total_original_tokens += original_tokens;
        total_compressed_tokens += compressed_tokens;
        total_original_bytes += result.original_bytes;
        total_compressed_bytes += result.compressed_bytes;

        println!(
            "{:<15} {:>10} {:>10} {:>9.1}% {:>10} {:>9.1}%",
            name,
            original_tokens,
            compressed_tokens,
            token_savings,
            result.original_bytes,
            byte_savings
        );
    }

    println!("{}", separator('-', 80));

    let overall_token_savings = (total_original_tokens as f64 - total_compressed_tokens as f64)
        / total_original_tokens as f64
        * 100.0;
    let overall_byte_savings = (total_original_bytes as f64 - total_compressed_bytes as f64)
        / total_original_bytes as f64
        * 100.0;

    println!(
        "{:<15} {:>10} {:>10} {:>9.1}% {:>10} {:>9.1}%",
        "TOTAL",
        total_original_tokens,
        total_compressed_tokens,
        overall_token_savings,
        total_original_bytes,
        overall_byte_savings
    );

    // Scale tests
    println!("\n{}", separator('=', 80));
    println!(" SCALE TESTS (1K, 10K, 100K tokens)");
    println!("{}\n", separator('=', 80));

    // Generate payloads of increasing size
    let scale_tests = vec![
        ("1K tokens", 250),     // ~1000 tokens
        ("10K tokens", 2500),   // ~10000 tokens
        ("100K tokens", 25000), // ~100000 tokens
    ];

    for (label, message_count) in scale_tests {
        let mut messages =
            vec![json!({"role": "system", "content": "You are a helpful assistant."})];

        for i in 0..message_count {
            if i % 2 == 0 {
                messages.push(json!({
                    "role": "user",
                    "content": format!("Message #{}: What is the answer to question {}?", i, i)
                }));
            } else {
                messages.push(json!({
                    "role": "assistant",
                    "content": format!("Response #{}: The answer to question {} is approximately {}.", i, i-1, i * 42)
                }));
            }
        }

        let payload = json!({
            "model": "gpt-4o",
            "messages": messages,
            "temperature": 0.7
        });

        let content = serde_json::to_string(&payload).unwrap();
        let result = engine
            .compress_with_tokens(&content, Algorithm::M2M, encoding)
            .unwrap();

        let original_tokens = result.original_tokens.unwrap();
        let compressed_tokens = result.compressed_tokens.unwrap();
        let token_savings =
            (original_tokens as f64 - compressed_tokens as f64) / original_tokens as f64 * 100.0;
        let byte_savings = (result.original_bytes as f64 - result.compressed_bytes as f64)
            / result.original_bytes as f64
            * 100.0;

        println!("{:<15} {:>8} tokens -> {:>8} tokens ({:>5.1}% savings) | {:>8} -> {:>8} bytes ({:>5.1}%)",
                 label,
                 original_tokens,
                 compressed_tokens,
                 token_savings,
                 result.original_bytes,
                 result.compressed_bytes,
                 byte_savings);
    }

    // Summary
    println!("\n{}", separator('=', 80));
    println!(" VALIDATION RESULTS");
    println!("{}\n", separator('=', 80));

    let target = 20.0;
    let passed = overall_token_savings >= target;

    println!("Overall Token Savings: {:.1}%", overall_token_savings);
    println!("Target: >= {:.0}%", target);
    println!(
        "Status: {}",
        if passed {
            "PASSED"
        } else {
            "FAILED - needs optimization"
        }
    );

    if passed {
        println!("\nToken-optimized compression is achieving the target!");
    } else {
        println!(
            "\nGap: {:.1}% more savings needed",
            target - overall_token_savings
        );
    }

    println!();
}
