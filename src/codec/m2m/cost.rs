//! Cost estimation for LLM API calls.
//!
//! Provides estimated costs based on model and token counts.

/// Model pricing (per 1K tokens in cents)
#[derive(Debug, Clone, Copy)]
pub struct ModelPricing {
    /// Input cost per 1K tokens (cents)
    pub input_cents: f32,
    /// Output cost per 1K tokens (cents)
    pub output_cents: f32,
}

impl ModelPricing {
    /// Create a new pricing structure
    pub const fn new(input_cents: f32, output_cents: f32) -> Self {
        Self {
            input_cents,
            output_cents,
        }
    }
}

/// Get pricing for a model
pub fn get_model_pricing(model: &str) -> ModelPricing {
    // Normalize model name for matching
    let model_lower = model.to_lowercase();

    // OpenAI models
    if model_lower.starts_with("gpt-4o-mini") {
        ModelPricing::new(0.015, 0.06)
    } else if model_lower.starts_with("gpt-4o") {
        ModelPricing::new(0.25, 1.00)
    } else if model_lower.starts_with("gpt-4-turbo") {
        ModelPricing::new(1.00, 3.00)
    } else if model_lower.starts_with("gpt-4") {
        ModelPricing::new(3.00, 6.00)
    } else if model_lower.starts_with("gpt-3.5-turbo") {
        ModelPricing::new(0.05, 0.15)
    } else if model_lower.starts_with("o1-preview") {
        ModelPricing::new(1.50, 6.00)
    } else if model_lower.starts_with("o1-mini") {
        ModelPricing::new(0.30, 1.20)
    } else if model_lower.starts_with("o3-mini") {
        ModelPricing::new(0.11, 0.44)
    } else if model_lower.starts_with("o3") {
        // Placeholder - actual pricing TBD
        ModelPricing::new(2.00, 8.00)
    }
    // Anthropic models
    else if model_lower.starts_with("claude-3-opus") {
        ModelPricing::new(1.50, 7.50)
    } else if model_lower.starts_with("claude-3.5-sonnet")
        || model_lower.starts_with("claude-3-5-sonnet")
        || model_lower.starts_with("claude-3-sonnet")
    {
        // Claude 3 Sonnet and 3.5 Sonnet have the same pricing
        ModelPricing::new(0.30, 1.50)
    } else if model_lower.starts_with("claude-3.5-haiku")
        || model_lower.starts_with("claude-3-5-haiku")
    {
        ModelPricing::new(0.08, 0.40)
    } else if model_lower.starts_with("claude-3-haiku") {
        ModelPricing::new(0.025, 0.125)
    }
    // Google models
    else if model_lower.starts_with("gemini-1.5-pro") {
        ModelPricing::new(0.125, 0.50)
    } else if model_lower.starts_with("gemini-1.5-flash") {
        ModelPricing::new(0.0075, 0.03)
    } else if model_lower.starts_with("gemini-2.0-flash") {
        ModelPricing::new(0.01, 0.04)
    }
    // Default fallback (conservative estimate)
    else {
        ModelPricing::new(0.10, 0.30)
    }
}

/// Estimate the cost of a request/response in USD
pub fn estimate_cost(model: &str, prompt_tokens: u32, completion_tokens: u32) -> f32 {
    let pricing = get_model_pricing(model);

    let input_cost = (prompt_tokens as f32 / 1000.0) * pricing.input_cents;
    let output_cost = (completion_tokens as f32 / 1000.0) * pricing.output_cents;

    // Convert cents to dollars
    (input_cost + output_cost) / 100.0
}

/// Estimate the cost of a request (before completion)
#[allow(dead_code)]
pub fn estimate_request_cost(model: &str, prompt_tokens: u32, estimated_completion: u32) -> f32 {
    estimate_cost(model, prompt_tokens, estimated_completion)
}

/// Estimate tokens from content length (rough approximation)
/// Uses ~4 characters per token for English text
pub fn estimate_tokens_from_content(content_bytes: usize) -> u32 {
    (content_bytes / 4) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpt4o_pricing() {
        let cost = estimate_cost("gpt-4o", 1000, 500);
        // 1000 input * 0.25/100 + 500 output * 1.00/100 = 0.0025 + 0.005 = 0.0075
        assert!((cost - 0.0075).abs() < 0.0001);
    }

    #[test]
    fn test_gpt4o_mini_pricing() {
        let cost = estimate_cost("gpt-4o-mini", 10000, 1000);
        // 10000 * 0.015/100 + 1000 * 0.06/100 = 0.0015 + 0.0006 = 0.0021
        assert!((cost - 0.0021).abs() < 0.0001);
    }

    #[test]
    fn test_claude_pricing() {
        let cost = estimate_cost("claude-3.5-sonnet", 5000, 2000);
        // 5000 * 0.30/100 + 2000 * 1.50/100 = 0.015 + 0.03 = 0.045
        assert!((cost - 0.045).abs() < 0.001);
    }

    #[test]
    fn test_unknown_model_fallback() {
        let pricing = get_model_pricing("unknown-model");
        assert!((pricing.input_cents - 0.10).abs() < f32::EPSILON);
        assert!((pricing.output_cents - 0.30).abs() < f32::EPSILON);
    }

    #[test]
    fn test_token_estimation() {
        // "Hello world" = 11 chars ≈ 2-3 tokens
        let tokens = estimate_tokens_from_content(11);
        assert_eq!(tokens, 2); // 11 / 4 = 2
    }
}
