//! M2M Protocol Stress Test
//!
//! Comprehensive stress testing for the M2M wire format protocol.
//! Tests throughput, compression efficiency, security overhead, and protocol coverage.
//!
//! # Usage
//!
//! ```bash
//! # Run all tests with default configuration
//! cargo run --bin m2m_stress_test --features crypto
//!
//! # Run specific test phase
//! cargo run --bin m2m_stress_test --features crypto -- --phase throughput
//!
//! # Quick smoke test
//! cargo run --bin m2m_stress_test --features crypto -- --quick
//!
//! # JSON output for CI
//! cargo run --bin m2m_stress_test --features crypto -- --json
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[cfg(feature = "crypto")]
use m2m::codec::m2m::SecurityMode;
use m2m::codec::m2m::{M2MCodec, M2MFrame};
use m2m::codec::{Algorithm, CodecEngine, StreamingCodec, StreamingMode};
use m2m::models::Encoding;
use m2m::protocol::{Capabilities, Session};

#[cfg(feature = "crypto")]
use m2m::codec::m2m::crypto::{KeyMaterial, SecurityContext};

// ============================================================================
// CLI Interface
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "m2m_stress_test")]
#[command(about = "M2M Protocol Stress Test - Comprehensive protocol testing")]
struct Args {
    /// Test phase to run (default: all)
    #[arg(long, value_enum)]
    phase: Option<TestPhase>,

    /// Number of iterations per test
    #[arg(long, default_value = "1000")]
    iterations: usize,

    /// Number of concurrent workers for parallel tests
    #[arg(long, default_value = "10")]
    concurrency: usize,

    /// Payload sizes to test (in approximate tokens)
    #[arg(long, value_delimiter = ',', default_value = "500,2000,10000,50000")]
    payload_sizes: Vec<usize>,

    /// Quick smoke test (reduced iterations)
    #[arg(long)]
    quick: bool,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Duration for long-running stability test (seconds)
    #[arg(long, default_value = "60")]
    duration: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum TestPhase {
    /// Throughput tests (encode/decode speed)
    Throughput,
    /// Compression efficiency tests
    Compression,
    /// Bidirectional request/response simulation
    Bidirectional,
    /// Streaming SSE tests
    Streaming,
    /// Security mode overhead tests
    Security,
    /// Concurrency and parallel tests
    Concurrency,
    /// Edge cases and error handling
    EdgeCases,
    /// All tests
    All,
}

// ============================================================================
// Payload Generation
// ============================================================================

/// Generate realistic OpenAI API request payload
fn generate_request_payload(token_count: usize) -> String {
    let content_tokens = token_count.saturating_sub(50); // Reserve for structure
    let content = generate_content(content_tokens);

    let messages = if token_count > 2000 {
        // Multi-turn conversation for larger payloads
        generate_conversation(content_tokens)
    } else {
        json!([
            {
                "role": "system",
                "content": "You are a helpful AI assistant specializing in software engineering, data science, and technical problem-solving. Provide clear, accurate, and well-structured responses."
            },
            {
                "role": "user",
                "content": content
            }
        ])
    };

    let payload = json!({
        "model": "gpt-4o",
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 4096,
        "top_p": 1.0,
        "frequency_penalty": 0.0,
        "presence_penalty": 0.0
    });

    serde_json::to_string(&payload).unwrap()
}

/// Generate realistic OpenAI API response payload
fn generate_response_payload(token_count: usize) -> String {
    let content_tokens = token_count.saturating_sub(100); // Reserve for structure
    let content = generate_content(content_tokens);

    let prompt_tokens = (token_count as f64 * 0.3) as u32;
    let completion_tokens = (token_count as f64 * 0.7) as u32;

    let payload = json!({
        "id": format!("chatcmpl-{}", generate_id()),
        "object": "chat.completion",
        "created": 1705520400,
        "model": "gpt-4o-2024-08-06",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "logprobs": null,
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "completion_tokens_details": {
                "reasoning_tokens": 0,
                "accepted_prediction_tokens": 0,
                "rejected_prediction_tokens": 0
            }
        },
        "system_fingerprint": "fp_a1b2c3d4e5"
    });

    serde_json::to_string(&payload).unwrap()
}

/// Generate content of approximately N tokens (~4 chars per token)
fn generate_content(tokens: usize) -> String {
    let chars = tokens * 4;

    // Mix of realistic content patterns
    let patterns = [
        "The implementation follows a modular architecture pattern that separates concerns effectively. ",
        "Consider using async/await for I/O-bound operations to improve throughput. ",
        "Error handling should be comprehensive with proper error types and recovery strategies. ",
        "Performance optimization requires careful profiling to identify actual bottlenecks. ",
        "Security best practices include input validation, output encoding, and principle of least privilege. ",
        "Documentation should explain the why, not just the what, for better maintainability. ",
        "Testing strategies should cover unit, integration, and end-to-end scenarios. ",
        "Code review is essential for maintaining quality and sharing knowledge across the team. ",
        "Refactoring should be done incrementally with good test coverage as a safety net. ",
        "Monitoring and observability are crucial for understanding system behavior in production. ",
    ];

    let mut content = String::with_capacity(chars);
    let mut pattern_idx = 0;

    while content.len() < chars {
        content.push_str(patterns[pattern_idx % patterns.len()]);
        pattern_idx += 1;
    }

    content.truncate(chars);
    content
}

/// Generate multi-turn conversation
fn generate_conversation(total_tokens: usize) -> serde_json::Value {
    let turns = 6;
    let tokens_per_turn = total_tokens / turns;

    let mut messages = vec![json!({
        "role": "system",
        "content": "You are a helpful AI assistant specializing in software engineering."
    })];

    for i in 0..turns {
        if i % 2 == 0 {
            messages.push(json!({
                "role": "user",
                "content": generate_content(tokens_per_turn)
            }));
        } else {
            messages.push(json!({
                "role": "assistant",
                "content": generate_content(tokens_per_turn)
            }));
        }
    }

    json!(messages)
}

/// Generate unique ID
fn generate_id() -> String {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("{:016x}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Generate SSE streaming chunks
fn generate_sse_chunks(total_tokens: usize, chunk_count: usize) -> Vec<String> {
    let tokens_per_chunk = total_tokens / chunk_count;
    let mut chunks = Vec::with_capacity(chunk_count + 2);

    // Initial chunk with role
    chunks.push(format!(
        r#"data: {{"id":"chatcmpl-{}","object":"chat.completion.chunk","created":1705520400,"model":"gpt-4o","choices":[{{"index":0,"delta":{{"role":"assistant","content":""}},"finish_reason":null}}]}}"#,
        generate_id()
    ));

    // Content chunks
    for _ in 0..chunk_count {
        let content = generate_content(tokens_per_chunk);
        chunks.push(format!(
            r#"data: {{"id":"chatcmpl-{}","choices":[{{"index":0,"delta":{{"content":"{}"}},"finish_reason":null}}]}}"#,
            generate_id(),
            content.replace('"', "\\\"").replace('\n', "\\n")
        ));
    }

    // Final chunk
    chunks.push(r#"data: [DONE]"#.to_string());

    chunks
}

// ============================================================================
// Metrics Collection
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestMetrics {
    name: String,
    iterations: usize,
    total_bytes_in: usize,
    total_bytes_out: usize,
    total_time_us: u64,
    latencies_us: Vec<u64>,
    errors: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<HashMap<String, f64>>,
}

impl TestMetrics {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            iterations: 0,
            total_bytes_in: 0,
            total_bytes_out: 0,
            total_time_us: 0,
            latencies_us: Vec::new(),
            errors: 0,
            extra: None,
        }
    }

    fn record(&mut self, bytes_in: usize, bytes_out: usize, duration: Duration) {
        self.iterations += 1;
        self.total_bytes_in += bytes_in;
        self.total_bytes_out += bytes_out;
        let us = duration.as_micros() as u64;
        self.total_time_us += us;
        self.latencies_us.push(us);
    }

    fn record_error(&mut self) {
        self.errors += 1;
    }

    fn set_extra(&mut self, key: &str, value: f64) {
        self.extra
            .get_or_insert_with(HashMap::new)
            .insert(key.to_string(), value);
    }

    fn throughput_ops_per_sec(&self) -> f64 {
        if self.total_time_us == 0 {
            return 0.0;
        }
        (self.iterations as f64) / (self.total_time_us as f64 / 1_000_000.0)
    }

    fn throughput_mb_per_sec(&self) -> f64 {
        if self.total_time_us == 0 {
            return 0.0;
        }
        let mb = self.total_bytes_in as f64 / (1024.0 * 1024.0);
        mb / (self.total_time_us as f64 / 1_000_000.0)
    }

    fn compression_ratio(&self) -> f64 {
        if self.total_bytes_out == 0 {
            return 1.0;
        }
        self.total_bytes_in as f64 / self.total_bytes_out as f64
    }

    fn percentile(&self, p: f64) -> u64 {
        if self.latencies_us.is_empty() {
            return 0;
        }
        let mut sorted = self.latencies_us.clone();
        sorted.sort_unstable();
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64) as usize;
        sorted[idx]
    }

    fn avg_latency_us(&self) -> f64 {
        if self.latencies_us.is_empty() {
            return 0.0;
        }
        self.total_time_us as f64 / self.iterations as f64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestResults {
    test_name: String,
    timestamp: String,
    configuration: TestConfiguration,
    metrics: Vec<TestMetrics>,
    summary: TestSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestConfiguration {
    iterations: usize,
    concurrency: usize,
    payload_sizes: Vec<usize>,
    crypto_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestSummary {
    total_operations: usize,
    total_bytes_processed: usize,
    total_time_secs: f64,
    peak_throughput_ops: f64,
    peak_throughput_mb: f64,
    errors: usize,
}

// ============================================================================
// Test Implementations
// ============================================================================

/// Phase 1: Throughput Tests
fn run_throughput_tests(args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 1: THROUGHPUT TESTS");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let codec = M2MCodec::new();
    let iterations = if args.quick { 100 } else { args.iterations };

    // Test M2M encode/decode for each payload size
    for &token_count in &args.payload_sizes {
        let test_name = format!("m2m_encode_decode_{}tok", token_count);
        let mut metrics = TestMetrics::new(&test_name);

        // Pre-generate payloads
        let request = generate_request_payload(token_count);
        let response = generate_response_payload(token_count);

        println!(
            "Testing: {} ({} bytes request, {} bytes response)",
            test_name,
            request.len(),
            response.len()
        );

        for i in 0..iterations {
            // Alternate between request and response
            let payload = if i % 2 == 0 { &request } else { &response };
            let bytes_in = payload.len();

            let start = Instant::now();

            // Encode
            let encoded = match codec.encode(payload) {
                Ok(e) => e,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };

            // Decode
            let decoded = match codec.decode(&encoded) {
                Ok(d) => d,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };

            let duration = start.elapsed();

            // Verify fidelity
            if decoded != *payload {
                metrics.record_error();
                continue;
            }

            metrics.record(bytes_in, encoded.len(), duration);
        }

        print_metrics_row(&metrics);
        all_metrics.push(metrics);
    }

    // Test binary vs base64 transport
    println!("\n--- Binary vs Base64 Transport ---\n");

    let token_count = 10000;
    let request = generate_request_payload(token_count);
    let frame = M2MFrame::new_request(&request).unwrap();

    // Binary transport
    let mut binary_metrics = TestMetrics::new("transport_binary_10k");
    for _ in 0..iterations {
        let start = Instant::now();
        let encoded = frame.encode().unwrap();
        let decoded = M2MFrame::decode(&encoded).unwrap();
        let duration = start.elapsed();

        if decoded.json() == request {
            binary_metrics.record(request.len(), encoded.len(), duration);
        } else {
            binary_metrics.record_error();
        }
    }
    print_metrics_row(&binary_metrics);
    all_metrics.push(binary_metrics);

    // Base64 transport
    let mut base64_metrics = TestMetrics::new("transport_base64_10k");
    for _ in 0..iterations {
        let start = Instant::now();
        let encoded = frame.encode_string().unwrap();
        let decoded = M2MFrame::decode_string(&encoded).unwrap();
        let duration = start.elapsed();

        if decoded.json() == request {
            base64_metrics.record(request.len(), encoded.len(), duration);
        } else {
            base64_metrics.record_error();
        }
    }
    print_metrics_row(&base64_metrics);
    all_metrics.push(base64_metrics);

    all_metrics
}

/// Phase 1: Compression Efficiency Tests  
fn run_compression_tests(args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 1: COMPRESSION EFFICIENCY TESTS");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let engine = CodecEngine::new();
    let m2m_codec = M2MCodec::new();
    let iterations = if args.quick { 50 } else { args.iterations / 10 };

    println!(
        "{:<25} {:>10} {:>10} {:>10} {:>8} {:>10}",
        "Test", "Raw(B)", "M2M(B)", "Ratio", "Enc(us)", "Dec(us)"
    );
    println!("{}", "-".repeat(75));

    for &token_count in &args.payload_sizes {
        // Request payloads
        let request = generate_request_payload(token_count);
        let mut metrics = TestMetrics::new(&format!("compress_request_{}tok", token_count));

        for _ in 0..iterations {
            let start = Instant::now();
            let encoded = m2m_codec.encode(&request).unwrap();
            let encode_time = start.elapsed();

            let start = Instant::now();
            let decoded = m2m_codec.decode(&encoded).unwrap();
            let decode_time = start.elapsed();

            if decoded == request {
                metrics.record(request.len(), encoded.len(), encode_time + decode_time);
                metrics.set_extra("encode_us", encode_time.as_micros() as f64);
                metrics.set_extra("decode_us", decode_time.as_micros() as f64);
            }
        }

        println!(
            "{:<25} {:>10} {:>10} {:>9.2}x {:>7.0} {:>10.0}",
            format!("request_{}tok", token_count),
            request.len(),
            metrics.total_bytes_out / iterations.max(1),
            metrics.compression_ratio(),
            metrics
                .extra
                .as_ref()
                .map(|e| e.get("encode_us").copied().unwrap_or(0.0))
                .unwrap_or(0.0),
            metrics
                .extra
                .as_ref()
                .map(|e| e.get("decode_us").copied().unwrap_or(0.0))
                .unwrap_or(0.0)
        );
        all_metrics.push(metrics);

        // Response payloads
        let response = generate_response_payload(token_count);
        let mut metrics = TestMetrics::new(&format!("compress_response_{}tok", token_count));

        for _ in 0..iterations {
            let start = Instant::now();
            let encoded = m2m_codec.encode(&response).unwrap();
            let encode_time = start.elapsed();

            let start = Instant::now();
            let decoded = m2m_codec.decode(&encoded).unwrap();
            let decode_time = start.elapsed();

            if decoded == response {
                metrics.record(response.len(), encoded.len(), encode_time + decode_time);
            }
        }

        println!(
            "{:<25} {:>10} {:>10} {:>9.2}x {:>7.0} {:>10.0}",
            format!("response_{}tok", token_count),
            response.len(),
            metrics.total_bytes_out / iterations.max(1),
            metrics.compression_ratio(),
            metrics.avg_latency_us() * 0.5,
            metrics.avg_latency_us() * 0.5
        );
        all_metrics.push(metrics);
    }

    // Compare algorithms for 10K token payload
    println!("\n--- Algorithm Comparison (10K tokens) ---\n");

    let payload = generate_request_payload(10000);
    let algorithms = [
        ("None", Algorithm::None),
        ("TokenNative", Algorithm::TokenNative),
        ("Brotli", Algorithm::Brotli),
        ("M2M", Algorithm::M2M),
    ];

    println!(
        "{:<15} {:>10} {:>10} {:>10} {:>10}",
        "Algorithm", "Raw(B)", "Comp(B)", "Ratio", "Time(us)"
    );
    println!("{}", "-".repeat(55));

    for (name, algo) in &algorithms {
        let mut total_time = Duration::ZERO;
        let mut comp_size = 0;

        for _ in 0..iterations {
            let start = Instant::now();
            if let Ok(result) = engine.compress(&payload, *algo) {
                comp_size = result.compressed_bytes;
                let _ = engine.decompress(&result.data);
            }
            total_time += start.elapsed();
        }

        let avg_time = total_time.as_micros() as f64 / iterations as f64;
        let ratio = if comp_size > 0 {
            payload.len() as f64 / comp_size as f64
        } else {
            1.0
        };

        println!(
            "{:<15} {:>10} {:>10} {:>9.2}x {:>10.0}",
            name,
            payload.len(),
            comp_size,
            ratio,
            avg_time
        );
    }

    all_metrics
}

/// Phase 2: Bidirectional Simulation
fn run_bidirectional_tests(args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: BIDIRECTIONAL SIMULATION");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let iterations = if args.quick { 100 } else { args.iterations };

    // Simple request-response roundtrip
    for &token_count in &args.payload_sizes {
        let test_name = format!("bidirectional_{}tok", token_count);
        let mut metrics = TestMetrics::new(&test_name);

        let request_json = generate_request_payload(token_count);
        let response_json = generate_response_payload(token_count);

        println!(
            "Testing: {} (req: {} B, resp: {} B)",
            test_name,
            request_json.len(),
            response_json.len()
        );

        for _ in 0..iterations {
            let start = Instant::now();

            // Client: encode request
            let request_frame = match M2MFrame::new_request(&request_json) {
                Ok(f) => f,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };
            let request_bytes = match request_frame.encode() {
                Ok(b) => b,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };

            // Server: decode request
            let decoded_request = match M2MFrame::decode(&request_bytes) {
                Ok(f) => f,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };

            // Verify request fidelity
            if decoded_request.json() != request_json {
                metrics.record_error();
                continue;
            }

            // Server: encode response
            let response_frame = match M2MFrame::new_response(&response_json) {
                Ok(f) => f,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };
            let response_bytes = match response_frame.encode() {
                Ok(b) => b,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };

            // Client: decode response
            let decoded_response = match M2MFrame::decode(&response_bytes) {
                Ok(f) => f,
                Err(_) => {
                    metrics.record_error();
                    continue;
                },
            };

            // Verify response fidelity
            if decoded_response.json() != response_json {
                metrics.record_error();
                continue;
            }

            let duration = start.elapsed();
            let total_bytes = request_json.len() + response_json.len();
            let total_encoded = request_bytes.len() + response_bytes.len();
            metrics.record(total_bytes, total_encoded, duration);
        }

        print_metrics_row(&metrics);
        all_metrics.push(metrics);
    }

    all_metrics
}

/// Phase 2: Streaming Tests
fn run_streaming_tests(args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: STREAMING TESTS");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let iterations = if args.quick { 50 } else { args.iterations / 10 };

    let streaming_modes = [
        ("abbreviation", StreamingMode::Abbreviation),
        ("token_native", StreamingMode::TokenNative),
        ("hybrid", StreamingMode::Hybrid),
        ("passthrough", StreamingMode::Passthrough),
    ];

    let chunk_count = 50;
    let total_tokens = 10000;

    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>12}",
        "Mode", "Chunks", "In(B)", "Out(B)", "Time(us)"
    );
    println!("{}", "-".repeat(65));

    for (name, mode) in &streaming_modes {
        let chunks = generate_sse_chunks(total_tokens, chunk_count);
        let mut metrics = TestMetrics::new(&format!("streaming_{}", name));

        for _ in 0..iterations {
            let mut codec = match mode {
                StreamingMode::Abbreviation => StreamingCodec::new(),
                StreamingMode::TokenNative => StreamingCodec::token_native(Encoding::Cl100kBase),
                StreamingMode::Hybrid => StreamingCodec::hybrid(Encoding::Cl100kBase),
                StreamingMode::Passthrough => StreamingCodec::passthrough(),
            };

            let start = Instant::now();
            let mut total_in = 0;
            let mut total_out = 0;

            for chunk in &chunks {
                total_in += chunk.len();
                if let Ok(outputs) = codec.process_chunk(chunk.as_bytes()) {
                    for output in outputs {
                        total_out += output.len();
                    }
                }
            }

            let duration = start.elapsed();
            metrics.record(total_in, total_out, duration);
        }

        let stats = metrics.clone();
        println!(
            "{:<20} {:>10} {:>10} {:>10} {:>12.0}",
            name,
            chunk_count,
            stats.total_bytes_in / iterations.max(1),
            stats.total_bytes_out / iterations.max(1),
            stats.avg_latency_us()
        );
        all_metrics.push(metrics);
    }

    // Test M2M finalization
    println!("\n--- M2M Stream Finalization ---\n");

    let chunks = generate_sse_chunks(total_tokens, chunk_count);
    let mut codec = StreamingCodec::new();

    for chunk in &chunks {
        let _ = codec.process_chunk(chunk.as_bytes());
    }

    let response_json = generate_response_payload(total_tokens);

    let start = Instant::now();
    let m2m_result = codec.finalize_m2m(&response_json);
    let m2m_time = start.elapsed();

    if let Ok(m2m_encoded) = m2m_result {
        println!(
            "M2M Finalization: {} -> {} bytes ({:.2}x) in {} us",
            response_json.len(),
            m2m_encoded.len(),
            response_json.len() as f64 / m2m_encoded.len() as f64,
            m2m_time.as_micros()
        );
    }

    all_metrics
}

/// Phase 2: Security Overhead Tests
#[cfg(feature = "crypto")]
fn run_security_tests(args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: SECURITY OVERHEAD TESTS");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let iterations = if args.quick { 100 } else { args.iterations };

    let key = KeyMaterial::new(vec![0x42u8; 32]);
    let token_count = 10000;
    let request = generate_request_payload(token_count);
    let frame = M2MFrame::new_request(&request).unwrap();

    let security_modes = [
        ("none", SecurityMode::None),
        ("hmac", SecurityMode::Hmac),
        ("aead", SecurityMode::Aead),
    ];

    println!(
        "{:<10} {:>10} {:>10} {:>10} {:>12} {:>12}",
        "Mode", "Raw(B)", "Enc(B)", "Overhead", "Enc(us)", "Dec(us)"
    );
    println!("{}", "-".repeat(70));

    let baseline_size = frame.encode().unwrap().len();

    for (name, mode) in &security_modes {
        let mut metrics = TestMetrics::new(&format!("security_{}", name));
        let mut encode_times = Vec::new();
        let mut decode_times = Vec::new();

        for _ in 0..iterations {
            let mut ctx = SecurityContext::new(key.clone());

            let start = Instant::now();
            let encoded = frame.encode_secure(*mode, &mut ctx).unwrap();
            let encode_time = start.elapsed();
            encode_times.push(encode_time.as_micros() as u64);

            let decode_ctx = SecurityContext::new(key.clone());
            let start = Instant::now();
            let decoded = M2MFrame::decode_secure(&encoded, &decode_ctx).unwrap();
            let decode_time = start.elapsed();
            decode_times.push(decode_time.as_micros() as u64);

            if decoded.json() == request {
                metrics.record(request.len(), encoded.len(), encode_time + decode_time);
            } else {
                metrics.record_error();
            }
        }

        let avg_enc: u64 = encode_times.iter().sum::<u64>() / iterations as u64;
        let avg_dec: u64 = decode_times.iter().sum::<u64>() / iterations as u64;
        let enc_size = metrics.total_bytes_out / iterations.max(1);
        let overhead = ((enc_size as f64 / baseline_size as f64) - 1.0) * 100.0;

        println!(
            "{:<10} {:>10} {:>10} {:>9.1}% {:>12} {:>12}",
            name, baseline_size, enc_size, overhead, avg_enc, avg_dec
        );

        metrics.set_extra("encode_us", avg_enc as f64);
        metrics.set_extra("decode_us", avg_dec as f64);
        metrics.set_extra("overhead_pct", overhead);
        all_metrics.push(metrics);
    }

    // Tamper detection test
    println!("\n--- Tamper Detection ---\n");

    let mut ctx = SecurityContext::new(key.clone());
    let encoded = frame.encode_secure(SecurityMode::Hmac, &mut ctx).unwrap();

    let mut tampered = encoded.clone();
    tampered[encoded.len() / 2] ^= 0xFF;

    let decode_ctx = SecurityContext::new(key.clone());
    let result = M2MFrame::decode_secure(&tampered, &decode_ctx);
    println!(
        "HMAC tamper detection: {}",
        if result.is_err() { "PASS" } else { "FAIL" }
    );

    let mut ctx = SecurityContext::new(key.clone());
    let encoded = frame.encode_secure(SecurityMode::Aead, &mut ctx).unwrap();

    let mut tampered = encoded.clone();
    tampered[encoded.len() - 20] ^= 0xFF;

    let decode_ctx = SecurityContext::new(key.clone());
    let result = M2MFrame::decode_secure(&tampered, &decode_ctx);
    println!(
        "AEAD tamper detection: {}",
        if result.is_err() { "PASS" } else { "FAIL" }
    );

    all_metrics
}

#[cfg(not(feature = "crypto"))]
fn run_security_tests(_args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: SECURITY OVERHEAD TESTS");
    println!("{}\n", "=".repeat(70));
    println!("Security tests require --features crypto");
    println!("Run with: cargo run --bin m2m_stress_test --features crypto");
    Vec::new()
}

/// Phase 2: Concurrency Tests
fn run_concurrency_tests(args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: CONCURRENCY TESTS");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let iterations = if args.quick { 100 } else { args.iterations };
    let token_count = 10000;

    let concurrency_levels = if args.quick {
        vec![1, 4]
    } else {
        vec![1, 4, 16, 64]
    };

    println!(
        "{:<12} {:>12} {:>12} {:>12} {:>12}",
        "Workers", "Total Ops", "Ops/sec", "MB/sec", "Errors"
    );
    println!("{}", "-".repeat(65));

    for workers in concurrency_levels {
        let test_name = format!("concurrent_{}w", workers);

        let request = generate_request_payload(token_count);
        let response = generate_response_payload(token_count);

        let total_ops = Arc::new(AtomicUsize::new(0));
        let total_bytes = Arc::new(AtomicUsize::new(0));
        let total_errors = Arc::new(AtomicUsize::new(0));

        let ops_per_worker = iterations / workers;

        let start = Instant::now();

        std::thread::scope(|s| {
            for _ in 0..workers {
                let request = request.clone();
                let response = response.clone();
                let ops = Arc::clone(&total_ops);
                let bytes = Arc::clone(&total_bytes);
                let errors = Arc::clone(&total_errors);

                s.spawn(move || {
                    let codec = M2MCodec::new();

                    for i in 0..ops_per_worker {
                        let payload = if i % 2 == 0 { &request } else { &response };

                        match codec.encode(payload) {
                            Ok(encoded) => match codec.decode(&encoded) {
                                Ok(decoded) if decoded == *payload => {
                                    ops.fetch_add(1, Ordering::Relaxed);
                                    bytes.fetch_add(payload.len(), Ordering::Relaxed);
                                },
                                _ => {
                                    errors.fetch_add(1, Ordering::Relaxed);
                                },
                            },
                            Err(_) => {
                                errors.fetch_add(1, Ordering::Relaxed);
                            },
                        }
                    }
                });
            }
        });

        let duration = start.elapsed();
        let ops = total_ops.load(Ordering::Relaxed);
        let bytes = total_bytes.load(Ordering::Relaxed);
        let errs = total_errors.load(Ordering::Relaxed);

        let ops_per_sec = ops as f64 / duration.as_secs_f64();
        let mb_per_sec = (bytes as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64();

        println!(
            "{:<12} {:>12} {:>12.0} {:>12.1} {:>12}",
            workers, ops, ops_per_sec, mb_per_sec, errs
        );

        let mut metrics = TestMetrics::new(&test_name);
        metrics.iterations = ops;
        metrics.total_bytes_in = bytes;
        metrics.total_time_us = duration.as_micros() as u64;
        metrics.errors = errs;
        metrics.set_extra("workers", workers as f64);
        metrics.set_extra("ops_per_sec", ops_per_sec);
        metrics.set_extra("mb_per_sec", mb_per_sec);
        all_metrics.push(metrics);
    }

    all_metrics
}

/// Phase 2: Edge Cases
fn run_edge_case_tests(_args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: EDGE CASES & ERROR HANDLING");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();
    let codec = M2MCodec::new();

    let edge_cases = [
        ("empty_messages", r#"{"model":"gpt-4o","messages":[]}"#),
        (
            "single_char",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"a"}]}"#,
        ),
        (
            "unicode",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello 世界 🌍 Привет مرحبا"}]}"#,
        ),
        (
            "newlines",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"line1\nline2\nline3"}]}"#,
        ),
        (
            "special_chars",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"<script>alert('xss')</script>"}]}"#,
        ),
        (
            "long_model",
            &format!(
                r#"{{"model":"{}","messages":[{{"role":"user","content":"test"}}]}}"#,
                "a".repeat(100)
            ),
        ),
    ];

    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>10}",
        "Case", "Input(B)", "Output(B)", "Ratio", "Status"
    );
    println!("{}", "-".repeat(65));

    for (name, payload) in edge_cases {
        let mut metrics = TestMetrics::new(name);

        let result = codec.encode(payload);
        let (output_size, status) = match result {
            Ok(encoded) => match codec.decode(&encoded) {
                Ok(decoded) if decoded == payload => {
                    metrics.record(payload.len(), encoded.len(), Duration::from_micros(1));
                    (encoded.len(), "PASS")
                },
                Ok(_) => {
                    metrics.record_error();
                    (0, "FIDELITY_FAIL")
                },
                Err(_) => {
                    metrics.record_error();
                    (0, "DECODE_FAIL")
                },
            },
            Err(_) => {
                metrics.record_error();
                (0, "ENCODE_FAIL")
            },
        };

        let ratio = if output_size > 0 {
            payload.len() as f64 / output_size as f64
        } else {
            0.0
        };

        println!(
            "{:<20} {:>10} {:>10} {:>9.2}x {:>10}",
            name,
            payload.len(),
            output_size,
            ratio,
            status
        );
        all_metrics.push(metrics);
    }

    // Error handling tests
    println!("\n--- Error Handling ---\n");

    let error_cases = [
        ("invalid_prefix", b"INVALID|data".to_vec()),
        ("truncated_header", b"#M2M|1|".to_vec()),
        ("corrupted_checksum", {
            let valid = codec
                .encode(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"test"}]}"#)
                .unwrap();
            let mut corrupted = valid;
            if let Some(last) = corrupted.last_mut() {
                *last ^= 0xFF;
            }
            corrupted
        }),
    ];

    for (name, data) in error_cases {
        let result = codec.decode(&data);
        let status = if result.is_err() {
            "CORRECTLY_REJECTED"
        } else {
            "UNEXPECTED_SUCCESS"
        };
        println!("{:<25}: {}", name, status);
    }

    all_metrics
}

/// Session Protocol Tests
fn run_session_tests(_args: &Args) -> Vec<TestMetrics> {
    println!("\n{}", "=".repeat(70));
    println!(" PHASE 2: SESSION PROTOCOL TESTS");
    println!("{}\n", "=".repeat(70));

    let mut all_metrics = Vec::new();

    // Full handshake test
    println!("--- Handshake Flow ---\n");

    let start = Instant::now();

    let client_caps = Capabilities::new("stress-test-client");
    let server_caps = Capabilities::new("stress-test-server");

    let mut client = Session::new(client_caps);
    let mut server = Session::new(server_caps);

    // HELLO
    let hello = client.create_hello();
    println!("1. Client -> HELLO (state: {:?})", client.state());

    // ACCEPT
    let accept = server.process_hello(&hello).expect("Server should accept");
    println!("2. Server -> ACCEPT (state: {:?})", server.state());

    // Process ACCEPT
    client
        .process_accept(&accept)
        .expect("Client should process accept");
    println!("3. Client processed ACCEPT (state: {:?})", client.state());

    let handshake_time = start.elapsed();
    println!("\nHandshake completed in {:?}", handshake_time);
    println!("Session ID: {}", client.id());
    println!("Negotiated algorithm: {:?}", client.algorithm());

    let mut metrics = TestMetrics::new("session_handshake");
    metrics.record(0, 0, handshake_time);
    all_metrics.push(metrics);

    all_metrics
}

// ============================================================================
// Output Helpers
// ============================================================================

fn print_metrics_row(metrics: &TestMetrics) {
    println!(
        "  {:>8} ops | {:>8.0} ops/s | {:>8.1} MB/s | p50: {:>6}us | p99: {:>6}us | ratio: {:>5.2}x | errors: {}",
        metrics.iterations,
        metrics.throughput_ops_per_sec(),
        metrics.throughput_mb_per_sec(),
        metrics.percentile(50.0),
        metrics.percentile(99.0),
        metrics.compression_ratio(),
        metrics.errors
    );
}

fn print_summary(all_metrics: &[TestMetrics]) {
    println!("\n{}", "=".repeat(70));
    println!(" SUMMARY");
    println!("{}\n", "=".repeat(70));

    let total_ops: usize = all_metrics.iter().map(|m| m.iterations).sum();
    let total_bytes: usize = all_metrics.iter().map(|m| m.total_bytes_in).sum();
    let total_errors: usize = all_metrics.iter().map(|m| m.errors).sum();
    let total_time_us: u64 = all_metrics.iter().map(|m| m.total_time_us).sum();

    let peak_ops = all_metrics
        .iter()
        .map(|m| m.throughput_ops_per_sec())
        .fold(0.0f64, |a, b| a.max(b));

    let peak_mb = all_metrics
        .iter()
        .map(|m| m.throughput_mb_per_sec())
        .fold(0.0f64, |a, b| a.max(b));

    println!("Total Operations:    {:>12}", total_ops);
    println!(
        "Total Data:          {:>12} bytes ({:.2} MB)",
        total_bytes,
        total_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "Total Time:          {:>12.2} seconds",
        total_time_us as f64 / 1_000_000.0
    );
    println!("Peak Throughput:     {:>12.0} ops/sec", peak_ops);
    println!("Peak Bandwidth:      {:>12.1} MB/sec", peak_mb);
    println!("Total Errors:        {:>12}", total_errors);
    println!(
        "Error Rate:          {:>12.4}%",
        if total_ops > 0 {
            (total_errors as f64 / total_ops as f64) * 100.0
        } else {
            0.0
        }
    );
}

fn print_json_results(results: &TestResults) {
    println!("{}", serde_json::to_string_pretty(results).unwrap());
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args = Args::parse();

    if !args.json {
        println!("\n{}", "=".repeat(70));
        println!(" M2M PROTOCOL STRESS TEST");
        println!("{}", "=".repeat(70));
        println!("\nConfiguration:");
        if args.quick {
            println!("  Iterations:    QUICK MODE");
        } else {
            println!("  Iterations:    {}", args.iterations);
        }
        println!("  Concurrency:   {}", args.concurrency);
        println!("  Payload sizes: {:?} tokens", args.payload_sizes);
        println!("  Crypto:        {}", cfg!(feature = "crypto"));
    }

    let mut all_metrics = Vec::new();
    let phase = args.phase.unwrap_or(TestPhase::All);

    match phase {
        TestPhase::Throughput => {
            all_metrics.extend(run_throughput_tests(&args));
        },
        TestPhase::Compression => {
            all_metrics.extend(run_compression_tests(&args));
        },
        TestPhase::Bidirectional => {
            all_metrics.extend(run_bidirectional_tests(&args));
        },
        TestPhase::Streaming => {
            all_metrics.extend(run_streaming_tests(&args));
        },
        TestPhase::Security => {
            all_metrics.extend(run_security_tests(&args));
        },
        TestPhase::Concurrency => {
            all_metrics.extend(run_concurrency_tests(&args));
        },
        TestPhase::EdgeCases => {
            all_metrics.extend(run_edge_case_tests(&args));
            all_metrics.extend(run_session_tests(&args));
        },
        TestPhase::All => {
            all_metrics.extend(run_throughput_tests(&args));
            all_metrics.extend(run_compression_tests(&args));
            all_metrics.extend(run_bidirectional_tests(&args));
            all_metrics.extend(run_streaming_tests(&args));
            all_metrics.extend(run_security_tests(&args));
            all_metrics.extend(run_concurrency_tests(&args));
            all_metrics.extend(run_edge_case_tests(&args));
            all_metrics.extend(run_session_tests(&args));
        },
    }

    if args.json {
        let results = TestResults {
            test_name: "m2m_stress_test".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            configuration: TestConfiguration {
                iterations: args.iterations,
                concurrency: args.concurrency,
                payload_sizes: args.payload_sizes.clone(),
                crypto_enabled: cfg!(feature = "crypto"),
            },
            metrics: all_metrics.clone(),
            summary: TestSummary {
                total_operations: all_metrics.iter().map(|m| m.iterations).sum(),
                total_bytes_processed: all_metrics.iter().map(|m| m.total_bytes_in).sum(),
                total_time_secs: all_metrics.iter().map(|m| m.total_time_us).sum::<u64>() as f64
                    / 1_000_000.0,
                peak_throughput_ops: all_metrics
                    .iter()
                    .map(|m| m.throughput_ops_per_sec())
                    .fold(0.0f64, |a, b| a.max(b)),
                peak_throughput_mb: all_metrics
                    .iter()
                    .map(|m| m.throughput_mb_per_sec())
                    .fold(0.0f64, |a, b| a.max(b)),
                errors: all_metrics.iter().map(|m| m.errors).sum(),
            },
        };
        print_json_results(&results);
    } else {
        print_summary(&all_metrics);

        println!("\n{}", "=".repeat(70));
        println!(" STRESS TEST COMPLETE");
        println!("{}\n", "=".repeat(70));
    }
}
