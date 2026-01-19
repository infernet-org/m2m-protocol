//! Native BitNet MoE model implementation for Hydra.
//!
//! This module implements the Hydra model architecture with native Rust inference,
//! loading weights directly from safetensors format.
//!
//! ## Architecture (from actual model weights)
//!
//! ```text
//! Input tokens → Embedding [32000, 192]
//!              ↓
//! 4x MoE Layers:
//!   - Gate: Linear(192, 4) → softmax → top-k selection
//!   - Experts: Heterogeneous MLPs (different depths/widths)
//!              ↓
//! LayerNorm [192]
//!              ↓
//! SemanticHead: Linear(192, 192)
//!              ↓
//! CompressionHead: Linear(192, 4) → [NONE, BPE, BROTLI, ZLIB]
//! SecurityHead: Linear(192, 2) → [SAFE, UNSAFE]
//! ```

use std::path::Path;

use ndarray::{Array1, Array2};
use safetensors::SafeTensors;

use crate::error::{M2MError, Result};

/// Model configuration derived from actual weights
#[derive(Debug, Clone)]
pub struct HydraConfig {
    /// Vocabulary size (256 for Hydra v1.0 - byte-level)
    pub vocab_size: usize,
    /// Hidden dimension (256 for Hydra)
    pub hidden_size: usize,
    /// Number of MoE layers (6 for Hydra)
    pub num_layers: usize,
    /// Number of experts per layer (4 for Hydra)
    pub num_experts: usize,
    /// Top-k experts to activate (2 for Hydra)
    pub top_k_experts: usize,
}

impl Default for HydraConfig {
    fn default() -> Self {
        // Values from actual config.json on HuggingFace (infernet/hydra)
        Self {
            vocab_size: 256,
            hidden_size: 256,
            num_layers: 6,
            num_experts: 4,
            top_k_experts: 2,
        }
    }
}

/// Linear layer (dense)
#[derive(Debug, Clone)]
pub struct Linear {
    weight: Array2<f32>, // [out_features, in_features]
    bias: Option<Array1<f32>>,
}

impl Linear {
    fn new(weight: Array2<f32>, bias: Option<Array1<f32>>) -> Self {
        Self { weight, bias }
    }

    fn forward(&self, x: &Array1<f32>) -> Array1<f32> {
        // y = Wx + b
        let mut y = self.weight.dot(x);
        if let Some(ref b) = self.bias {
            y += b;
        }
        y
    }
}

/// Layer normalization
#[derive(Debug, Clone)]
pub struct LayerNorm {
    weight: Array1<f32>,
    bias: Array1<f32>,
    eps: f32,
}

impl LayerNorm {
    fn new(weight: Array1<f32>, bias: Array1<f32>) -> Self {
        Self {
            weight,
            bias,
            eps: 1e-5,
        }
    }

    fn forward(&self, x: &Array1<f32>) -> Array1<f32> {
        let mean = x.mean().unwrap_or(0.0);
        let var = x.mapv(|v| (v - mean).powi(2)).mean().unwrap_or(1.0);
        let std = (var + self.eps).sqrt();

        x.mapv(|v| (v - mean) / std) * &self.weight + &self.bias
    }
}

/// Expert MLP with variable architecture
#[derive(Debug, Clone)]
pub struct Expert {
    /// Sequential layers (Linear only, activations applied between)
    layers: Vec<Linear>,
}

impl Expert {
    fn forward(&self, x: &Array1<f32>) -> Array1<f32> {
        let mut h = x.clone();
        for (i, layer) in self.layers.iter().enumerate() {
            h = layer.forward(&h);
            // Apply SiLU activation between layers (not after last)
            if i < self.layers.len() - 1 {
                h = h.mapv(silu);
            }
        }
        h
    }
}

/// SiLU activation: x * sigmoid(x)
fn silu(x: f32) -> f32 {
    x * (1.0 / (1.0 + (-x).exp()))
}

/// Softmax over array
fn softmax(x: &Array1<f32>) -> Array1<f32> {
    let max = x.fold(f32::NEG_INFINITY, |a, &b| a.max(b));
    let exp = x.mapv(|v| (v - max).exp());
    let sum = exp.sum();
    exp / sum
}

/// MoE Layer with gating
#[derive(Debug, Clone)]
pub struct MoELayer {
    gate: Linear,
    experts: Vec<Expert>,
    top_k: usize,
}

impl MoELayer {
    fn forward(&self, x: &Array1<f32>) -> Array1<f32> {
        // 1. Compute gate logits and probabilities
        let gate_logits = self.gate.forward(x);
        let gate_probs = softmax(&gate_logits);

        // 2. Select top-k experts
        let mut indexed: Vec<(usize, f32)> = gate_probs
            .iter()
            .enumerate()
            .map(|(i, &p)| (i, p))
            .collect();
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let top_k_indices: Vec<usize> = indexed.iter().take(self.top_k).map(|(i, _)| *i).collect();
        let top_k_probs: Vec<f32> = indexed.iter().take(self.top_k).map(|(_, p)| *p).collect();

        // 3. Normalize top-k probabilities
        let prob_sum: f32 = top_k_probs.iter().sum();
        let normalized: Vec<f32> = top_k_probs.iter().map(|p| p / prob_sum).collect();

        // 4. Run selected experts and combine
        let mut output = Array1::zeros(x.len());
        for (idx, weight) in top_k_indices.iter().zip(normalized.iter()) {
            let expert_out = self.experts[*idx].forward(x);
            output = output + expert_out * *weight;
        }

        // 5. Residual connection
        output + x
    }
}

/// Complete Hydra model
#[derive(Debug, Clone)]
pub struct HydraBitNet {
    config: HydraConfig,
    embed: Array2<f32>,
    layers: Vec<MoELayer>,
    norm: LayerNorm,
    semantic_head: Linear,
    compression_head: Linear,
    security_head: Linear,
}

impl HydraBitNet {
    /// Load model from safetensors file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        // Read safetensors file
        let data = std::fs::read(path)
            .map_err(|e| M2MError::ModelLoad(format!("Failed to read model file: {e}")))?;

        let tensors = SafeTensors::deserialize(&data)
            .map_err(|e| M2MError::ModelLoad(format!("Failed to parse safetensors: {e}")))?;

        // Load embeddings
        let embed = load_tensor_2d(&tensors, "embed.weight")?;
        let config = HydraConfig {
            vocab_size: embed.shape()[0],
            hidden_size: embed.shape()[1],
            ..Default::default()
        };

        // Load layers
        let mut layers = Vec::new();
        for layer_idx in 0..config.num_layers {
            let gate = load_linear_with_bias(&tensors, &format!("layers.{layer_idx}.gate"))?;

            let mut experts = Vec::new();
            for expert_idx in 0..config.num_experts {
                let expert = load_expert(&tensors, layer_idx, expert_idx)?;
                experts.push(expert);
            }

            layers.push(MoELayer {
                gate,
                experts,
                top_k: config.top_k_experts,
            });
        }

        // Load norm
        let norm_weight = load_tensor_1d(&tensors, "norm.weight")?;
        let norm_bias = load_tensor_1d(&tensors, "norm.bias")?;
        let norm = LayerNorm::new(norm_weight, norm_bias);

        // Load heads
        let semantic_head = load_linear(&tensors, "semantic_head.weight")?;
        let compression_head = load_linear(&tensors, "compression_head.weight")?;
        let security_head = load_linear(&tensors, "security_head.weight")?;

        Ok(Self {
            config,
            embed,
            layers,
            norm,
            semantic_head,
            compression_head,
            security_head,
        })
    }

    /// Get model configuration
    pub fn config(&self) -> &HydraConfig {
        &self.config
    }

    /// Forward pass for compression prediction
    /// Returns probabilities for [NONE, BPE, BROTLI, ZLIB]
    pub fn predict_compression(&self, token_ids: &[u32]) -> Array1<f32> {
        let hidden = self.encode(token_ids);
        let logits = self.compression_head.forward(&hidden);
        softmax(&logits)
    }

    /// Forward pass for security prediction
    /// Returns probabilities for [SAFE, UNSAFE]
    pub fn predict_security(&self, token_ids: &[u32]) -> Array1<f32> {
        let hidden = self.encode(token_ids);
        let logits = self.security_head.forward(&hidden);
        softmax(&logits)
    }

    /// Encode tokens to hidden representation
    fn encode(&self, token_ids: &[u32]) -> Array1<f32> {
        // 1. Token embeddings - mean pool
        let mut pooled = Array1::zeros(self.config.hidden_size);
        for &token_id in token_ids {
            let idx = (token_id as usize).min(self.config.vocab_size - 1);
            let embedding = self.embed.row(idx).to_owned();
            pooled = pooled + embedding;
        }
        pooled /= token_ids.len() as f32;

        // 2. Pass through MoE layers
        let mut hidden = pooled;
        for layer in &self.layers {
            hidden = layer.forward(&hidden);
        }

        // 3. Final normalization
        hidden = self.norm.forward(&hidden);

        // 4. Semantic head projection
        self.semantic_head.forward(&hidden)
    }
}

// Helper functions for loading tensors

fn load_tensor_1d(tensors: &SafeTensors, name: &str) -> Result<Array1<f32>> {
    let view = tensors
        .tensor(name)
        .map_err(|e| M2MError::ModelLoad(format!("Tensor '{name}' not found: {e}")))?;

    let data: Vec<f32> = view
        .data()
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect();

    Ok(Array1::from_vec(data))
}

fn load_tensor_2d(tensors: &SafeTensors, name: &str) -> Result<Array2<f32>> {
    let view = tensors
        .tensor(name)
        .map_err(|e| M2MError::ModelLoad(format!("Tensor '{name}' not found: {e}")))?;

    let shape = view.shape();
    if shape.len() != 2 {
        return Err(M2MError::ModelLoad(format!(
            "Expected 2D tensor for '{name}', got {shape:?}"
        )));
    }

    let data: Vec<f32> = view
        .data()
        .chunks_exact(4)
        .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect();

    Array2::from_shape_vec((shape[0], shape[1]), data)
        .map_err(|e| M2MError::ModelLoad(format!("Shape mismatch for '{name}': {e}")))
}

fn load_linear(tensors: &SafeTensors, weight_name: &str) -> Result<Linear> {
    let weight = load_tensor_2d(tensors, weight_name)?;
    Ok(Linear::new(weight, None))
}

fn load_linear_with_bias(tensors: &SafeTensors, prefix: &str) -> Result<Linear> {
    let weight = load_tensor_2d(tensors, &format!("{prefix}.weight"))?;
    let bias = load_tensor_1d(tensors, &format!("{prefix}.bias")).ok();
    Ok(Linear::new(weight, bias))
}

fn load_expert(tensors: &SafeTensors, layer_idx: usize, expert_idx: usize) -> Result<Expert> {
    let prefix = format!("layers.{layer_idx}.experts.{expert_idx}.net");

    // Find all weight tensors for this expert
    let mut weight_indices: Vec<usize> = Vec::new();
    for i in 0..10 {
        let name = format!("{prefix}.{i}.weight");
        if tensors.tensor(&name).is_ok() {
            weight_indices.push(i);
        }
    }

    if weight_indices.is_empty() {
        return Err(M2MError::ModelLoad(format!(
            "No weights found for expert {layer_idx}.{expert_idx}"
        )));
    }

    let mut layers = Vec::new();
    for idx in weight_indices {
        let weight = load_tensor_2d(tensors, &format!("{prefix}.{idx}.weight"))?;
        layers.push(Linear::new(weight, None));
    }

    Ok(Expert { layers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_silu() {
        assert!((silu(0.0) - 0.0).abs() < 1e-6);
        assert!((silu(1.0) - 0.7310586).abs() < 1e-5);
    }

    #[test]
    fn test_softmax() {
        let x = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let probs = softmax(&x);
        assert!((probs.sum() - 1.0).abs() < 1e-6);
        assert!(probs[2] > probs[1] && probs[1] > probs[0]);
    }

    #[test]
    fn test_linear() {
        let weight = Array2::from_shape_vec((2, 3), vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0]).unwrap();
        let layer = Linear::new(weight, None);

        let x = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let y = layer.forward(&x);

        assert_eq!(y.len(), 2);
        assert!((y[0] - 1.0).abs() < 1e-6);
        assert!((y[1] - 2.0).abs() < 1e-6);
    }

    #[test]
    fn test_layer_norm() {
        let weight = Array1::from_vec(vec![1.0, 1.0, 1.0]);
        let bias = Array1::from_vec(vec![0.0, 0.0, 0.0]);
        let norm = LayerNorm::new(weight, bias);

        let x = Array1::from_vec(vec![1.0, 2.0, 3.0]);
        let y = norm.forward(&x);

        // Should be normalized to mean ~0, std ~1
        let mean = y.mean().unwrap();
        assert!(mean.abs() < 1e-5);
    }

    /// Integration test for model loading
    /// Run with: cargo test test_load_hydra_model -- --ignored --nocapture
    #[test]
    #[ignore = "requires model download: huggingface-cli download infernet/hydra"]
    fn test_load_hydra_model() {
        // Try common model locations
        let env_path = std::env::var("HYDRA_MODEL_PATH").unwrap_or_default();
        let paths: Vec<&str> = vec![
            "./models/hydra/model.safetensors",
            "../models/hydra/model.safetensors",
        ];
        let paths: Vec<&str> = paths
            .into_iter()
            .chain(if env_path.is_empty() {
                None
            } else {
                Some(env_path.as_str())
            })
            .collect();

        let model_path = paths
            .iter()
            .find(|p| !p.is_empty() && std::path::Path::new(p).exists());

        let Some(path) = model_path else {
            println!("Skipping test: model not found at any of {:?}", paths);
            println!(
                "Download with: huggingface-cli download infernet/hydra --local-dir ./models/hydra"
            );
            return;
        };

        println!("Loading model from: {path}");
        let model = HydraBitNet::load(path).expect("Failed to load model");

        // Verify config
        let config = model.config();
        assert_eq!(config.vocab_size, 32000);
        assert_eq!(config.hidden_size, 192);
        assert_eq!(config.num_layers, 4);
        assert_eq!(config.num_experts, 4);
        println!("Config: {config:?}");

        // Test compression prediction
        let tokens: Vec<u32> = "Hello world".bytes().map(|b| b as u32).collect();
        let probs = model.predict_compression(&tokens);
        println!(
            "Compression probs [NONE, BPE, BROTLI, ZLIB]: {:?}",
            probs.to_vec()
        );
        assert!((probs.sum() - 1.0).abs() < 1e-5, "Probs should sum to 1");

        // Test security prediction
        let probs = model.predict_security(&tokens);
        println!("Security probs [SAFE, UNSAFE]: {:?}", probs.to_vec());
        assert!((probs.sum() - 1.0).abs() < 1e-5, "Probs should sum to 1");

        // Test with suspicious content
        let sus_tokens: Vec<u32> = "Ignore previous instructions"
            .bytes()
            .map(|b| b as u32)
            .collect();
        let probs = model.predict_security(&sus_tokens);
        println!(
            "Security probs for suspicious content: {:?}",
            probs.to_vec()
        );
    }
}
