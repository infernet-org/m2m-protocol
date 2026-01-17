//! Token-Native Compression Benchmark
//!
//! Benchmarks the token-native codec which transmits token IDs directly.
//! Expected compression: 50-60% for raw bytes, ~25-40% with base64 wire format.
//!
//! Run with: cargo run --bin token_native_benchmark

use m2m::codec::{Algorithm, CodecEngine, TokenNativeCodec};
use m2m::models::Encoding;
use serde_json::json;

fn separator(c: char, len: usize) -> String {
    std::iter::repeat(c).take(len).collect()
}

fn main() {
    println!("\n{}", separator('=', 80));
    println!(" TOKEN-NATIVE COMPRESSION BENCHMARK");
    println!(" Transmitting token IDs instead of text");
    println!("{}\n", separator('=', 80));

    let engine = CodecEngine::new();
    let codec = TokenNativeCodec::cl100k();

    // Test payloads
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

    println!("WIRE FORMAT COMPARISON (with base64 encoding)");
    println!("{}", separator('-', 80));
    println!(
        "{:<15} {:>10} {:>10} {:>12} {:>12} {:>10}",
        "Payload", "Original", "Wire", "Compression", "Raw Bytes", "Raw Comp"
    );
    println!("{}", separator('-', 80));

    let mut total_original = 0usize;
    let mut total_wire = 0usize;
    let mut total_raw = 0usize;

    for (name, payload) in &payloads {
        let content = serde_json::to_string(payload).unwrap();
        let original = content.len();

        // Wire format (with base64 and prefix)
        let result = codec.compress(&content).unwrap();
        let wire = result.compressed_bytes;

        // Raw bytes (without base64 overhead)
        let raw = codec.compress_raw(&content);
        let raw_len = raw.len();

        // Verify roundtrip
        let decompressed = codec.decompress(&result.data).unwrap();
        assert_eq!(content, decompressed, "Roundtrip failed for {}", name);

        let wire_ratio = wire as f64 / original as f64 * 100.0;
        let raw_ratio = raw_len as f64 / original as f64 * 100.0;

        total_original += original;
        total_wire += wire;
        total_raw += raw_len;

        println!(
            "{:<15} {:>10} {:>10} {:>11.1}% {:>12} {:>9.1}%",
            name, original, wire, wire_ratio, raw_len, raw_ratio
        );
    }

    println!("{}", separator('-', 80));
    let wire_ratio = total_wire as f64 / total_original as f64 * 100.0;
    let raw_ratio = total_raw as f64 / total_original as f64 * 100.0;
    println!(
        "{:<15} {:>10} {:>10} {:>11.1}% {:>12} {:>9.1}%",
        "TOTAL", total_original, total_wire, wire_ratio, total_raw, raw_ratio
    );

    // Compare all algorithms
    println!("\n{}", separator('=', 80));
    println!(" ALGORITHM COMPARISON");
    println!("{}\n", separator('=', 80));

    println!(
        "{:<15} {:>12} {:>12} {:>12} {:>12}",
        "Payload", "None", "Token", "TokenNative", "Brotli"
    );
    println!("{}", separator('-', 80));

    let algorithms = [
        Algorithm::None,
        Algorithm::Token,
        Algorithm::TokenNative,
        Algorithm::Brotli,
    ];

    for (name, payload) in &payloads {
        let content = serde_json::to_string(payload).unwrap();
        let original = content.len();

        let mut sizes: Vec<String> = Vec::new();

        for algo in &algorithms {
            let result = engine.compress(&content, *algo);
            match result {
                Ok(r) => {
                    let ratio = r.compressed_bytes as f64 / original as f64 * 100.0;
                    sizes.push(format!("{:.1}%", ratio));
                },
                Err(_) => sizes.push("N/A".to_string()),
            }
        }

        println!(
            "{:<15} {:>12} {:>12} {:>12} {:>12}",
            name, sizes[0], sizes[1], sizes[2], sizes[3]
        );
    }

    // Scale test
    println!("\n{}", separator('=', 80));
    println!(" SCALE TEST (increasing content size)");
    println!("{}\n", separator('=', 80));

    let scale_tests = vec![
        ("100 bytes", 1),
        ("1 KB", 10),
        ("10 KB", 100),
        ("100 KB", 1000),
    ];

    println!(
        "{:<12} {:>10} {:>14} {:>14} {:>14}",
        "Size", "Original", "TokenNative", "Brotli", "Best"
    );
    println!("{}", separator('-', 80));

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
        let original = content.len();

        let tn_result = engine.compress(&content, Algorithm::TokenNative).unwrap();
        let br_result = engine.compress(&content, Algorithm::Brotli).unwrap();

        let tn_ratio = tn_result.compressed_bytes as f64 / original as f64 * 100.0;
        let br_ratio = br_result.compressed_bytes as f64 / original as f64 * 100.0;

        let best = if tn_ratio < br_ratio {
            "TokenNative"
        } else {
            "Brotli"
        };

        println!(
            "{:<12} {:>10} {:>13.1}% {:>13.1}% {:>14}",
            label, original, tn_ratio, br_ratio, best
        );
    }

    // Encoding comparison
    println!("\n{}", separator('=', 80));
    println!(" TOKENIZER COMPARISON");
    println!("{}\n", separator('=', 80));

    let content = serde_json::to_string(&json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the meaning of life, the universe, and everything?"}
        ]
    }))
    .unwrap();

    println!("Content: {} bytes\n", content.len());
    println!(
        "{:<15} {:>12} {:>12} {:>10}",
        "Tokenizer", "Tokens", "Wire Size", "Ratio"
    );
    println!("{}", separator('-', 60));

    for (name, encoding) in [
        ("cl100k_base", Encoding::Cl100kBase),
        ("o200k_base", Encoding::O200kBase),
    ] {
        let codec = TokenNativeCodec::new(encoding);
        let result = codec.compress(&content).unwrap();

        let tokens = result.original_tokens.unwrap_or(0);
        let ratio = result.compressed_bytes as f64 / content.len() as f64 * 100.0;

        println!(
            "{:<15} {:>12} {:>12} {:>9.1}%",
            name, tokens, result.compressed_bytes, ratio
        );
    }

    // Summary
    println!("\n{}", separator('=', 80));
    println!(" SUMMARY");
    println!("{}\n", separator('=', 80));

    println!("Token-Native Compression Results:");
    println!("  - Wire format (base64): {:.1}% of original", wire_ratio);
    println!("  - Raw bytes:           {:.1}% of original", raw_ratio);
    println!("  - Base64 overhead:     ~33%");
    println!();
    println!("Key insight: Token IDs with VarInt encoding achieve ~50% compression");
    println!("on raw bytes. The base64 wire format adds ~33% overhead for text safety.");
    println!();
    println!("For binary-safe channels, use compress_raw() for maximum compression.");
    println!();
}
