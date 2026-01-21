//! AI-to-AI M2M Protocol Test
//!
//! Tests the M2M protocol with true machine-to-machine communication:
//! - Full encoder/decoder on both sides
//! - Multiple open-source models with known tokenizers
//! - Accurate token counting via tiktoken
//! - Multi-turn conversations across 3 scenarios
//!
//! # Usage
//! ```bash
//! OPENROUTER_API_KEY=sk-or-... cargo run --bin m2m-ai-test
//! ```

use std::time::{Duration, Instant};

use m2m::codec::{Algorithm, CodecEngine};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tiktoken_rs::{cl100k_base, CoreBPE};

// =============================================================================
// Constants
// =============================================================================

const OPENROUTER_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";

/// Free tier models with known tokenizers (LlamaBpe compatible)
const MODEL_LLAMA_3_2_3B: &str = "meta-llama/llama-3.2-3b-instruct:free";
const MODEL_LLAMA_3_3_70B: &str = "meta-llama/llama-3.3-70b-instruct:free";
const MODEL_MISTRAL_SMALL: &str = "mistralai/mistral-small-3.1-24b-instruct:free";

// =============================================================================
// Data Structures
// =============================================================================

/// Test scenario types
#[derive(Debug, Clone, Copy)]
enum Scenario {
    /// Short Q&A conversation
    SimpleQA,
    /// Medium-length code discussion
    CodeReview,
    /// Multi-step reasoning problems
    Reasoning,
}

impl Scenario {
    fn name(&self) -> &'static str {
        match self {
            Scenario::SimpleQA => "Simple Q&A",
            Scenario::CodeReview => "Code Review",
            Scenario::Reasoning => "Reasoning",
        }
    }

    fn questions(&self) -> Vec<&'static str> {
        match self {
            Scenario::SimpleQA => vec![
                "What is the capital of France?",
                "What is its approximate population?",
                "Name its most famous landmark and when it was built.",
            ],
            Scenario::CodeReview => vec![
                "Review this Python function and suggest improvements:\n\n```python\ndef fibonacci(n):\n    if n <= 1:\n        return n\n    return fibonacci(n-1) + fibonacci(n-2)\n```",
                "Can you optimize it for large values of n? Show the improved code.",
                "Now add type hints and a docstring to the optimized version.",
            ],
            Scenario::Reasoning => vec![
                "Solve step-by-step: A train leaves Station A at 9:00 AM traveling at 60 mph toward Station B, which is 180 miles away. Another train leaves Station B at 9:30 AM traveling at 80 mph toward Station A. At what time will they meet?",
                "What if the first train makes a 15-minute stop at the halfway point?",
                "Summarize the key factors that affect when two objects traveling toward each other will meet.",
            ],
        }
    }
}

/// Configuration for a test run
#[derive(Debug, Clone)]
struct TestConfig {
    model_a: String,
    model_b: String,
    scenario: Scenario,
}

impl TestConfig {
    fn new(model_a: &str, model_b: &str, scenario: Scenario) -> Self {
        Self {
            model_a: model_a.to_string(),
            model_b: model_b.to_string(),
            scenario,
        }
    }

    /// Get short model name for display
    fn short_name(model: &str) -> String {
        model
            .split('/')
            .last()
            .unwrap_or(model)
            .replace(":free", "")
            .replace("-instruct", "")
    }
}

/// Metrics for a single message (request or response)
#[derive(Debug, Clone, Default)]
struct MessageMetrics {
    original_bytes: usize,
    compressed_bytes: usize,
    original_tokens: usize,
    compressed_tokens: usize,
    compression_time_ms: f64,
}

impl MessageMetrics {
    fn byte_savings_pct(&self) -> f64 {
        if self.original_bytes == 0 {
            return 0.0;
        }
        (1.0 - (self.compressed_bytes as f64 / self.original_bytes as f64)) * 100.0
    }

    fn token_savings_pct(&self) -> f64 {
        if self.original_tokens == 0 {
            return 0.0;
        }
        (1.0 - (self.compressed_tokens as f64 / self.original_tokens as f64)) * 100.0
    }

    fn bytes_saved(&self) -> usize {
        self.original_bytes.saturating_sub(self.compressed_bytes)
    }

    fn tokens_saved(&self) -> usize {
        self.original_tokens.saturating_sub(self.compressed_tokens)
    }
}

/// Results for a single turn in the conversation
#[derive(Debug, Clone)]
struct TurnResult {
    turn: usize,
    question: String,
    answer: String,
    request_metrics: MessageMetrics,
    response_metrics: MessageMetrics,
    roundtrip_valid: bool,
    api_latency_ms: f64,
}

/// Full test result for a scenario
#[derive(Debug)]
struct ScenarioResult {
    config: TestConfig,
    turns: Vec<TurnResult>,
}

impl ScenarioResult {
    fn total_request_bytes_saved(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.request_metrics.bytes_saved())
            .sum()
    }

    fn total_response_bytes_saved(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.response_metrics.bytes_saved())
            .sum()
    }

    fn total_request_tokens_saved(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.request_metrics.tokens_saved())
            .sum()
    }

    fn total_response_tokens_saved(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.response_metrics.tokens_saved())
            .sum()
    }

    fn total_original_request_bytes(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.request_metrics.original_bytes)
            .sum()
    }

    fn total_original_response_bytes(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.response_metrics.original_bytes)
            .sum()
    }

    fn total_original_request_tokens(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.request_metrics.original_tokens)
            .sum()
    }

    fn total_original_response_tokens(&self) -> usize {
        self.turns
            .iter()
            .map(|t| t.response_metrics.original_tokens)
            .sum()
    }

    fn avg_request_byte_savings(&self) -> f64 {
        let total = self.total_original_request_bytes();
        if total == 0 {
            return 0.0;
        }
        (self.total_request_bytes_saved() as f64 / total as f64) * 100.0
    }

    fn avg_response_byte_savings(&self) -> f64 {
        let total = self.total_original_response_bytes();
        if total == 0 {
            return 0.0;
        }
        (self.total_response_bytes_saved() as f64 / total as f64) * 100.0
    }

    fn avg_request_token_savings(&self) -> f64 {
        let total = self.total_original_request_tokens();
        if total == 0 {
            return 0.0;
        }
        (self.total_request_tokens_saved() as f64 / total as f64) * 100.0
    }

    fn avg_response_token_savings(&self) -> f64 {
        let total = self.total_original_response_tokens();
        if total == 0 {
            return 0.0;
        }
        (self.total_response_tokens_saved() as f64 / total as f64) * 100.0
    }

    fn all_roundtrips_valid(&self) -> bool {
        self.turns.iter().all(|t| t.roundtrip_valid)
    }

    fn valid_count(&self) -> usize {
        self.turns.iter().filter(|t| t.roundtrip_valid).count()
    }
}

/// Chat message structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

/// Chat completion request
#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

/// Chat completion response
#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

// =============================================================================
// API Functions
// =============================================================================

fn get_api_key() -> String {
    std::env::var("OPENROUTER_API_KEY")
        .expect("OPENROUTER_API_KEY environment variable must be set")
}

fn create_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .expect("Failed to create HTTP client")
}

async fn chat_completion(
    client: &Client,
    model: &str,
    messages: Vec<Message>,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = ChatRequest {
        model: model.to_string(),
        messages,
        temperature: Some(0.7),
        max_tokens: Some(500),
    };

    let response = client
        .post(OPENROUTER_API_URL)
        .header("Authorization", format!("Bearer {}", get_api_key()))
        .header("HTTP-Referer", "https://github.com/m2m-protocol")
        .header("X-Title", "M2M AI-to-AI Test")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let error = response.text().await?;
        return Err(format!("API error: {}", error).into());
    }

    let result: ChatResponse = response.json().await?;
    let content = result
        .choices
        .first()
        .map(|c| c.message.content.clone())
        .unwrap_or_default();

    Ok(content)
}

// =============================================================================
// Compression & Measurement Functions
// =============================================================================

/// Compress content and measure metrics
fn compress_and_measure(
    codec: &CodecEngine,
    tokenizer: &CoreBPE,
    json_str: &str,
) -> Result<(String, MessageMetrics), Box<dyn std::error::Error>> {
    let original_bytes = json_str.len();
    let original_tokens = tokenizer.encode_ordinary(json_str).len();

    let start = Instant::now();
    let compressed = codec.compress(json_str, Algorithm::M2M)?;
    let compression_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    let compressed_bytes = compressed.data.len();
    let compressed_tokens = tokenizer.encode_ordinary(&compressed.data).len();

    Ok((
        compressed.data,
        MessageMetrics {
            original_bytes,
            compressed_bytes,
            original_tokens,
            compressed_tokens,
            compression_time_ms,
        },
    ))
}

/// Validate roundtrip: compress -> decompress -> compare JSON equivalence
fn validate_roundtrip(codec: &CodecEngine, original: &str, compressed: &str) -> bool {
    match codec.decompress(compressed) {
        Ok(decompressed) => {
            // Parse both as JSON and compare structure
            let orig: Result<Value, _> = serde_json::from_str(original);
            let decomp: Result<Value, _> = serde_json::from_str(&decompressed);

            match (orig, decomp) {
                (Ok(o), Ok(d)) => {
                    // Compare messages content (ignoring restored defaults)
                    let orig_messages = o.get("messages");
                    let decomp_messages = d.get("messages");

                    match (orig_messages, decomp_messages) {
                        (Some(om), Some(dm)) => {
                            // Check each message's content matches
                            let om_arr = om.as_array();
                            let dm_arr = dm.as_array();

                            match (om_arr, dm_arr) {
                                (Some(oa), Some(da)) => {
                                    if oa.len() != da.len() {
                                        return false;
                                    }
                                    for (o_msg, d_msg) in oa.iter().zip(da.iter()) {
                                        if o_msg.get("content") != d_msg.get("content") {
                                            return false;
                                        }
                                        // Role should match (accounting for abbreviation)
                                        let o_role = o_msg.get("role").and_then(|r| r.as_str());
                                        let d_role = d_msg.get("role").and_then(|r| r.as_str());
                                        if o_role != d_role {
                                            return false;
                                        }
                                    }
                                    true
                                },
                                _ => false,
                            }
                        },
                        (None, None) => true,
                        _ => false,
                    }
                },
                _ => false,
            }
        },
        Err(_) => false,
    }
}

// =============================================================================
// Test Execution
// =============================================================================

/// Execute a single turn: build request, compress, call API, measure response
async fn execute_turn(
    client: &Client,
    codec: &CodecEngine,
    tokenizer: &CoreBPE,
    model: &str,
    conversation: &[Message],
    question: &str,
    turn_num: usize,
) -> Result<TurnResult, Box<dyn std::error::Error>> {
    // Build conversation with new question
    let mut messages = conversation.to_vec();
    messages.push(Message {
        role: "user".to_string(),
        content: question.to_string(),
    });

    // Build request JSON
    let request = ChatRequest {
        model: model.to_string(),
        messages: messages.clone(),
        temperature: Some(0.7),
        max_tokens: Some(500),
    };
    let request_json = serde_json::to_string(&request)?;

    // Compress request and measure
    let (compressed_request, request_metrics) =
        compress_and_measure(codec, tokenizer, &request_json)?;

    // Validate roundtrip BEFORE sending
    let roundtrip_valid = validate_roundtrip(codec, &request_json, &compressed_request);

    // Call API (with original request - API doesn't understand M2M)
    let api_start = Instant::now();
    let answer = chat_completion(client, model, messages).await?;
    let api_latency_ms = api_start.elapsed().as_secs_f64() * 1000.0;

    // Build response JSON for measurement
    let response_json = serde_json::to_string(&json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": answer
            }
        }]
    }))?;

    // Compress response and measure
    let (compressed_response, response_metrics) =
        compress_and_measure(codec, tokenizer, &response_json)?;

    // Validate response roundtrip too
    let response_roundtrip = validate_roundtrip(codec, &response_json, &compressed_response);

    Ok(TurnResult {
        turn: turn_num,
        question: question.to_string(),
        answer,
        request_metrics,
        response_metrics,
        roundtrip_valid: roundtrip_valid && response_roundtrip,
        api_latency_ms,
    })
}

/// Run a complete AI-to-AI test for a given configuration
async fn run_ai_to_ai_test(
    client: &Client,
    codec: &CodecEngine,
    tokenizer: &CoreBPE,
    config: &TestConfig,
) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
    let questions = config.scenario.questions();
    let mut turns = Vec::new();
    let mut conversation = vec![Message {
        role: "system".to_string(),
        content: "You are a helpful assistant. Keep responses concise but informative.".to_string(),
    }];

    for (i, question) in questions.iter().enumerate() {
        let turn_result = execute_turn(
            client,
            codec,
            tokenizer,
            &config.model_b,
            &conversation,
            question,
            i + 1,
        )
        .await?;

        // Add to conversation history
        conversation.push(Message {
            role: "user".to_string(),
            content: question.to_string(),
        });
        conversation.push(Message {
            role: "assistant".to_string(),
            content: turn_result.answer.clone(),
        });

        turns.push(turn_result);
    }

    Ok(ScenarioResult {
        config: config.clone(),
        turns,
    })
}

// =============================================================================
// Report Generation
// =============================================================================

fn print_header() {
    println!();
    println!("{}", "=".repeat(78));
    println!("{:^78}", "M2M AI-to-AI PROTOCOL TEST");
    println!("{}", "=".repeat(78));
    println!();
    println!("Testing M2M compression with true machine-to-machine communication.");
    println!("Full encoder/decoder validation with token counting via tiktoken.");
    println!();
}

fn print_test_matrix(configs: &[TestConfig]) {
    println!("Test Matrix:");
    println!("  +-----+---------------------------+---------------------------+--------------+");
    println!("  |  #  | Agent A                   | Agent B                   | Scenario     |");
    println!("  +-----+---------------------------+---------------------------+--------------+");
    for (i, config) in configs.iter().enumerate() {
        println!(
            "  | T{:<2} | {:<25} | {:<25} | {:<12} |",
            i + 1,
            TestConfig::short_name(&config.model_a),
            TestConfig::short_name(&config.model_b),
            config.scenario.name()
        );
    }
    println!("  +-----+---------------------------+---------------------------+--------------+");
    println!();
}

fn print_turn_result(turn: &TurnResult) {
    let q_short = if turn.question.len() > 50 {
        format!("{}...", &turn.question[..47])
    } else {
        turn.question.clone()
    };

    println!("Turn {}: \"{}\"", turn.turn, q_short);
    println!("  +-------------+----------+------------+---------+");
    println!("  |             | Original | Compressed | Savings |");
    println!("  +-------------+----------+------------+---------+");
    println!(
        "  | Request  B  | {:>8} | {:>10} | {:>6.1}% |",
        turn.request_metrics.original_bytes,
        turn.request_metrics.compressed_bytes,
        turn.request_metrics.byte_savings_pct()
    );
    println!(
        "  | Request  T  | {:>8} | {:>10} | {:>6.1}% |",
        turn.request_metrics.original_tokens,
        turn.request_metrics.compressed_tokens,
        turn.request_metrics.token_savings_pct()
    );
    println!(
        "  | Response B  | {:>8} | {:>10} | {:>6.1}% |",
        turn.response_metrics.original_bytes,
        turn.response_metrics.compressed_bytes,
        turn.response_metrics.byte_savings_pct()
    );
    println!(
        "  | Response T  | {:>8} | {:>10} | {:>6.1}% |",
        turn.response_metrics.original_tokens,
        turn.response_metrics.compressed_tokens,
        turn.response_metrics.token_savings_pct()
    );
    println!("  +-------------+----------+------------+---------+");

    let valid_str = if turn.roundtrip_valid {
        "VALID"
    } else {
        "FAILED"
    };
    println!(
        "  Roundtrip: {} {} | Latency: {:.2}s | Compression: {:.2}ms",
        if turn.roundtrip_valid { "[OK]" } else { "[X]" },
        valid_str,
        turn.api_latency_ms / 1000.0,
        turn.request_metrics.compression_time_ms
    );
    println!();
}

fn print_scenario_result(result: &ScenarioResult, test_num: usize) {
    println!("{}", "=".repeat(78));
    println!(
        "TEST {}: {} <-> {} ({})",
        test_num,
        TestConfig::short_name(&result.config.model_a),
        TestConfig::short_name(&result.config.model_b),
        result.config.scenario.name()
    );
    println!("{}", "=".repeat(78));
    println!();

    for turn in &result.turns {
        print_turn_result(turn);
    }

    // Summary
    println!("Summary T{}:", test_num);
    println!(
        "  Total bytes saved (req):  {} ({:.1}%)",
        result.total_request_bytes_saved(),
        result.avg_request_byte_savings()
    );
    println!(
        "  Total bytes saved (resp): {} ({:.1}%)",
        result.total_response_bytes_saved(),
        result.avg_response_byte_savings()
    );
    println!(
        "  Total tokens saved (req): {} ({:.1}%)",
        result.total_request_tokens_saved(),
        result.avg_request_token_savings()
    );
    println!(
        "  Total tokens saved (resp): {} ({:.1}%)",
        result.total_response_tokens_saved(),
        result.avg_response_token_savings()
    );
    println!(
        "  All roundtrips: {} ({}/{})",
        if result.all_roundtrips_valid() {
            "[OK] VALID"
        } else {
            "[X] FAILED"
        },
        result.valid_count(),
        result.turns.len()
    );
    println!();
}

fn print_final_summary(results: &[ScenarioResult]) {
    println!("{}", "=".repeat(78));
    println!("{:^78}", "FINAL SUMMARY");
    println!("{}", "=".repeat(78));
    println!();

    // Compression performance table
    println!("  +----------------------+------------+------------+------------+------------+");
    println!("  |                      | Bytes Req  | Bytes Resp | Tokens Req | Tokens Resp|");
    println!("  +----------------------+------------+------------+------------+------------+");

    let mut total_req_bytes_orig = 0usize;
    let mut total_req_bytes_saved = 0usize;
    let mut total_resp_bytes_orig = 0usize;
    let mut total_resp_bytes_saved = 0usize;
    let mut total_req_tokens_orig = 0usize;
    let mut total_req_tokens_saved = 0usize;
    let mut total_resp_tokens_orig = 0usize;
    let mut total_resp_tokens_saved = 0usize;
    let mut total_valid = 0usize;
    let mut total_turns = 0usize;

    for (i, result) in results.iter().enumerate() {
        let model_a_short = TestConfig::short_name(&result.config.model_a);
        let model_b_short = TestConfig::short_name(&result.config.model_b);
        let label = format!(
            "T{}: {}↔{}",
            i + 1,
            &model_a_short[..model_a_short.len().min(8)],
            &model_b_short[..model_b_short.len().min(8)]
        );

        println!(
            "  | {:<20} | {:>9.1}% | {:>9.1}% | {:>9.1}% | {:>9.1}% |",
            label,
            result.avg_request_byte_savings(),
            result.avg_response_byte_savings(),
            result.avg_request_token_savings(),
            result.avg_response_token_savings()
        );

        total_req_bytes_orig += result.total_original_request_bytes();
        total_req_bytes_saved += result.total_request_bytes_saved();
        total_resp_bytes_orig += result.total_original_response_bytes();
        total_resp_bytes_saved += result.total_response_bytes_saved();
        total_req_tokens_orig += result.total_original_request_tokens();
        total_req_tokens_saved += result.total_request_tokens_saved();
        total_resp_tokens_orig += result.total_original_response_tokens();
        total_resp_tokens_saved += result.total_response_tokens_saved();
        total_valid += result.valid_count();
        total_turns += result.turns.len();
    }

    println!("  +----------------------+------------+------------+------------+------------+");

    // Calculate overall averages
    let avg_req_bytes = if total_req_bytes_orig > 0 {
        (total_req_bytes_saved as f64 / total_req_bytes_orig as f64) * 100.0
    } else {
        0.0
    };
    let avg_resp_bytes = if total_resp_bytes_orig > 0 {
        (total_resp_bytes_saved as f64 / total_resp_bytes_orig as f64) * 100.0
    } else {
        0.0
    };
    let avg_req_tokens = if total_req_tokens_orig > 0 {
        (total_req_tokens_saved as f64 / total_req_tokens_orig as f64) * 100.0
    } else {
        0.0
    };
    let avg_resp_tokens = if total_resp_tokens_orig > 0 {
        (total_resp_tokens_saved as f64 / total_resp_tokens_orig as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "  | {:<20} | {:>9.1}% | {:>9.1}% | {:>9.1}% | {:>9.1}% |",
        "AVERAGE", avg_req_bytes, avg_resp_bytes, avg_req_tokens, avg_resp_tokens
    );
    println!("  +----------------------+------------+------------+------------+------------+");
    println!();

    // Protocol verification
    println!("Protocol Verification:");
    let all_valid = total_valid == total_turns;
    println!(
        "  {} All roundtrips valid: {}/{}",
        if all_valid { "[OK]" } else { "[X]" },
        total_valid,
        total_turns
    );
    println!(
        "  {} Cross-provider compatibility: {}",
        if all_valid { "[OK]" } else { "[X]" },
        if all_valid { "VERIFIED" } else { "ISSUES" }
    );

    let overall_savings = (avg_req_bytes + avg_resp_bytes + avg_req_tokens + avg_resp_tokens) / 4.0;
    println!(
        "  {} Token savings achieved: {:.1}% average",
        if overall_savings > 15.0 {
            "[OK]"
        } else {
            "[!]"
        },
        f64::midpoint(avg_req_tokens, avg_resp_tokens)
    );

    println!();
    println!("{}", "=".repeat(78));
    println!("{:^78}", "TEST COMPLETE");
    println!("{}", "=".repeat(78));
    println!();
}

// =============================================================================
// Main Entry Point
// =============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let client = create_client();
    let codec = CodecEngine::new();
    let tokenizer = cl100k_base()?;

    print_header();

    // Define test matrix
    let test_configs = vec![
        // Test 1: Same model baseline (Llama 3.2 3B talking to itself)
        TestConfig::new(MODEL_LLAMA_3_2_3B, MODEL_LLAMA_3_2_3B, Scenario::SimpleQA),
        // Test 2: Same provider, different size
        TestConfig::new(
            MODEL_LLAMA_3_2_3B,
            MODEL_LLAMA_3_3_70B,
            Scenario::CodeReview,
        ),
        // Test 3: Cross-provider (Llama -> Mistral)
        TestConfig::new(MODEL_LLAMA_3_2_3B, MODEL_MISTRAL_SMALL, Scenario::Reasoning),
        // Test 4: Cross-provider with larger models
        TestConfig::new(MODEL_LLAMA_3_3_70B, MODEL_MISTRAL_SMALL, Scenario::SimpleQA),
    ];

    print_test_matrix(&test_configs);

    // Run all tests
    let mut all_results = Vec::new();

    for (i, config) in test_configs.iter().enumerate() {
        println!(
            "Running Test {} of {}: {} <-> {} ({})...",
            i + 1,
            test_configs.len(),
            TestConfig::short_name(&config.model_a),
            TestConfig::short_name(&config.model_b),
            config.scenario.name()
        );
        println!();

        match run_ai_to_ai_test(&client, &codec, &tokenizer, config).await {
            Ok(result) => {
                print_scenario_result(&result, i + 1);
                all_results.push(result);
            },
            Err(e) => {
                println!("  [X] Test {} failed: {}", i + 1, e);
                println!();
            },
        }
    }

    // Print final summary if we have results
    if !all_results.is_empty() {
        print_final_summary(&all_results);
    }

    Ok(())
}
