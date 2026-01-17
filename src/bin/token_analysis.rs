//! Token Cost Analysis for M2M Abbreviations
//!
//! This tool measures actual token costs of abbreviations vs originals,
//! resolving the epistemic uncertainty about which abbreviations actually
//! save tokens (not just bytes).
//!
//! Run with: cargo run --bin token_analysis

use m2m::codec::{KEY_ABBREV, MODEL_ABBREV, ROLE_ABBREV};
use m2m::tokenizer::count_tokens;

fn separator(c: char, len: usize) -> String {
    std::iter::repeat(c).take(len).collect()
}

fn main() {
    println!("\n");
    println!("{}", separator('=', 80));
    println!(" M2M TOKEN COST ANALYSIS");
    println!(" Resolving: Which abbreviations save TOKENS (not just bytes)?");
    println!("{}", separator('=', 80));

    // ========================================================================
    // SECTION 1: KEY ABBREVIATIONS
    // ========================================================================
    println!("\n--- KEY ABBREVIATIONS ---\n");
    println!(
        "{:<25} {:>8} {:>8} {:>8} {:>8} {:>10}",
        "Key", "Orig", "Abbrev", "Delta", "Bytes", "Verdict"
    );
    println!("{}", separator('-', 80));

    let mut key_saves_tokens = 0;
    let mut key_no_savings = 0;
    let mut key_total_token_savings = 0i32;

    for (full, abbrev) in KEY_ABBREV.entries() {
        // Measure as JSON key with quotes: "key"
        let orig_str = format!("\"{}\"", full);
        let abbrev_str = format!("\"{}\"", abbrev);

        let orig_tokens = count_tokens(&orig_str);
        let abbrev_tokens = count_tokens(&abbrev_str);
        let delta = orig_tokens as i32 - abbrev_tokens as i32;
        let byte_delta = orig_str.len() as i32 - abbrev_str.len() as i32;

        let verdict = if delta > 0 {
            key_saves_tokens += 1;
            key_total_token_savings += delta;
            "SAVES"
        } else if delta < 0 {
            "WORSE!"
        } else {
            key_no_savings += 1;
            "NO SAVE"
        };

        println!(
            "{:<25} {:>8} {:>8} {:>+8} {:>+8} {:>10}",
            full, orig_tokens, abbrev_tokens, delta, byte_delta, verdict
        );
    }

    println!("{}", separator('-', 80));
    println!(
        "KEY SUMMARY: {} save tokens, {} no savings, {} total tokens saved",
        key_saves_tokens, key_no_savings, key_total_token_savings
    );

    // ========================================================================
    // SECTION 2: ROLE ABBREVIATIONS
    // ========================================================================
    println!("\n--- ROLE ABBREVIATIONS ---\n");
    println!(
        "{:<25} {:>8} {:>8} {:>8} {:>8} {:>10}",
        "Role", "Orig", "Abbrev", "Delta", "Bytes", "Verdict"
    );
    println!("{}", separator('-', 80));

    let mut role_saves_tokens = 0;
    let mut role_no_savings = 0;

    for (full, abbrev) in ROLE_ABBREV.entries() {
        let orig_str = format!("\"{}\"", full);
        let abbrev_str = format!("\"{}\"", abbrev);

        let orig_tokens = count_tokens(&orig_str);
        let abbrev_tokens = count_tokens(&abbrev_str);
        let delta = orig_tokens as i32 - abbrev_tokens as i32;
        let byte_delta = orig_str.len() as i32 - abbrev_str.len() as i32;

        let verdict = if delta > 0 {
            role_saves_tokens += 1;
            "SAVES"
        } else if delta < 0 {
            "WORSE!"
        } else {
            role_no_savings += 1;
            "NO SAVE"
        };

        println!(
            "{:<25} {:>8} {:>8} {:>+8} {:>+8} {:>10}",
            full, orig_tokens, abbrev_tokens, delta, byte_delta, verdict
        );
    }

    println!("{}", separator('-', 80));
    println!(
        "ROLE SUMMARY: {} save tokens, {} no savings",
        role_saves_tokens, role_no_savings
    );

    // ========================================================================
    // SECTION 3: MODEL ABBREVIATIONS
    // ========================================================================
    println!("\n--- MODEL ABBREVIATIONS ---\n");
    println!(
        "{:<30} {:>6} {:>6} {:>6} {:>6} {:>10}",
        "Model", "Orig", "Abbr", "Delta", "Bytes", "Verdict"
    );
    println!("{}", separator('-', 80));

    let mut model_saves_tokens = 0;
    let mut model_no_savings = 0;
    let mut model_total_token_savings = 0i32;

    for (full, abbrev) in MODEL_ABBREV.entries() {
        let orig_str = format!("\"{}\"", full);
        let abbrev_str = format!("\"{}\"", abbrev);

        let orig_tokens = count_tokens(&orig_str);
        let abbrev_tokens = count_tokens(&abbrev_str);
        let delta = orig_tokens as i32 - abbrev_tokens as i32;
        let byte_delta = orig_str.len() as i32 - abbrev_str.len() as i32;

        let verdict = if delta > 0 {
            model_saves_tokens += 1;
            model_total_token_savings += delta;
            "SAVES"
        } else if delta < 0 {
            "WORSE!"
        } else {
            model_no_savings += 1;
            "NO SAVE"
        };

        println!(
            "{:<30} {:>6} {:>6} {:>+6} {:>+6} {:>10}",
            full, orig_tokens, abbrev_tokens, delta, byte_delta, verdict
        );
    }

    println!("{}", separator('-', 80));
    println!(
        "MODEL SUMMARY: {} save tokens, {} no savings, {} total tokens saved",
        model_saves_tokens, model_no_savings, model_total_token_savings
    );

    // ========================================================================
    // SECTION 4: COMMON PATTERNS (Multi-token sequences)
    // ========================================================================
    println!("\n--- COMMON MULTI-TOKEN PATTERNS ---\n");
    println!("{:<50} {:>8} {:>10}", "Pattern", "Tokens", "Potential");
    println!("{}", separator('-', 80));

    let patterns = [
        r#"{"role":"user","content":""#,
        r#"{"role":"assistant","content":""#,
        r#"{"role":"system","content":""#,
        r#"{"role":"tool","content":""#,
        r#""finish_reason":"stop""#,
        r#""finish_reason":"length""#,
        r#""finish_reason":"tool_calls""#,
        r#"{"type":"function","function":{"#,
        r#""prompt_tokens":"#,
        r#""completion_tokens":"#,
        r#""total_tokens":"#,
        r#"{"messages":["#,
        r#"],"model":""#,
        r#"","temperature":"#,
        r#"","max_tokens":"#,
        r#"{"index":0,"delta":{"#,
        r#"{"index":0,"message":{"#,
        r#""choices":[{"#,
    ];

    let mut total_pattern_tokens = 0;
    for pattern in &patterns {
        let tokens = count_tokens(pattern);
        total_pattern_tokens += tokens;
        let potential = if tokens >= 5 {
            "HIGH"
        } else if tokens >= 3 {
            "MEDIUM"
        } else {
            "LOW"
        };
        println!("{:<50} {:>8} {:>10}", pattern, tokens, potential);
    }

    println!("{}", separator('-', 80));
    println!(
        "PATTERN SUMMARY: {} patterns, {} total tokens (avg {:.1} per pattern)",
        patterns.len(),
        total_pattern_tokens,
        total_pattern_tokens as f64 / patterns.len() as f64
    );

    // ========================================================================
    // SECTION 5: REALISTIC PAYLOAD ANALYSIS
    // ========================================================================
    println!("\n--- REALISTIC PAYLOAD ANALYSIS ---\n");

    let payloads = [
        (
            "minimal",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
        ),
        (
            "with_system",
            r#"{"model":"gpt-4o","messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":"Hello"}]}"#,
        ),
        (
            "multi_turn",
            r#"{"model":"gpt-4o","messages":[{"role":"system","content":"Be brief."},{"role":"user","content":"Hi"},{"role":"assistant","content":"Hello!"},{"role":"user","content":"Bye"}]}"#,
        ),
        (
            "with_params",
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Test"}],"temperature":0.7,"max_tokens":100,"top_p":0.9}"#,
        ),
        (
            "response",
            r#"{"id":"chatcmpl-123","object":"chat.completion","created":1234567890,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
        ),
    ];

    println!(
        "{:<15} {:>10} {:>10} {:>15}",
        "Payload", "Bytes", "Tokens", "Bytes/Token"
    );
    println!("{}", separator('-', 60));

    for (name, payload) in &payloads {
        let bytes = payload.len();
        let tokens = count_tokens(payload);
        let ratio = bytes as f64 / tokens as f64;
        println!("{:<15} {:>10} {:>10} {:>15.2}", name, bytes, tokens, ratio);
    }

    // ========================================================================
    // SUMMARY & RECOMMENDATIONS
    // ========================================================================
    println!("\n");
    println!("{}", separator('=', 80));
    println!(" EPISTEMIC CONCLUSIONS");
    println!("{}", separator('=', 80));

    println!("\n[KNOWLEDGE GAINED]");
    println!(
        "  K1: {}/{} key abbreviations save tokens",
        key_saves_tokens,
        key_saves_tokens + key_no_savings
    );
    println!(
        "  K2: {}/{} role abbreviations save tokens",
        role_saves_tokens,
        role_saves_tokens + role_no_savings
    );
    println!(
        "  K3: {}/{} model abbreviations save tokens",
        model_saves_tokens,
        model_saves_tokens + model_no_savings
    );
    println!(
        "  K4: Average pattern length = {:.1} tokens (HIGH compression potential)",
        total_pattern_tokens as f64 / patterns.len() as f64
    );

    println!("\n[RECOMMENDATIONS]");
    if key_no_savings > key_saves_tokens {
        println!("  R1: REMOVE non-saving key abbreviations (waste bytes, save 0 tokens)");
    }
    if role_no_savings > 0 {
        println!("  R2: REMOVE non-saving role abbreviations");
    }
    println!("  R3: IMPLEMENT pattern replacement (highest ROI)");
    println!("  R4: Target patterns with >= 5 tokens for single-token replacement");

    println!("\n[NEXT ACTION]");
    println!("  -> Run Phase 2: Evidence-based table redesign");

    // Debug compression output
    debug_compression();

    println!();
}

// Debug output for compression
fn debug_compression() {
    use m2m::codec::{Algorithm, CodecEngine};

    let engine = CodecEngine::new();

    let original = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
    let result = engine.compress(original, Algorithm::Token).unwrap();

    println!("\n--- DEBUG COMPRESSION ---");
    println!("Original:   {}", original);
    println!("Compressed: {}", result.data);
    println!("Original tokens:   {}", count_tokens(original));
    println!("Compressed tokens: {}", count_tokens(&result.data));

    println!("\n--- PREFIX TOKEN COSTS ---");
    let prefixes = ["#T1|", "#1|", "#T|", "~", "~1", "#", "\u{0001}"];
    for p in &prefixes {
        println!("  {:10} = {} tokens", format!("{:?}", p), count_tokens(p));
    }
}
