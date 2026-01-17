//! Hydra ML inference for intelligent algorithm routing.
//!
//! The [Hydra SLM](https://huggingface.co/infernet/hydra) is a small language model
//! optimized for M2M protocol tasks.
//!
//! # Inference Backends
//!
//! - **Native (safetensors)**: Pure Rust inference from safetensors weights
//! - **ONNX Runtime**: Optional, requires `onnx` feature flag
//! - **Heuristic fallback**: Rule-based fallback when model unavailable
//!
//! # Tasks
//!
//! - **Compression selection**: Predicts optimal algorithm (None/BPE/Brotli/Zlib)
//! - **Security detection**: Classifies prompt injection and jailbreak attempts
//! - **Token estimation**: Fast approximate token counting
//!
//! # Model Architecture (from actual weights)
//!
//! ```text
//! vocab_size: 32000, hidden_size: 192, num_layers: 4, num_experts: 4
//! ```
//!
//! The Hydra model is a Mixture of Experts classifier:
//! - 4 MoE layers with top-2 expert routing
//! - Heterogeneous expert architectures (different depths/widths)
//! - ~38MB model size (float32 weights)
//!
//! # Download
//!
//! ```bash
//! huggingface-cli download infernet/hydra --local-dir ./models/hydra
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use m2m::inference::{HydraModel, CompressionDecision};
//!
//! // Load from safetensors (native Rust inference)
//! let model = HydraModel::load("./models/hydra/model.safetensors")?;
//!
//! let decision = model.predict_compression(&content)?;
//! match decision.algorithm {
//!     Algorithm::Brotli => // use brotli
//!     _ => // use other
//! }
//! ```

pub mod bitnet;
mod hydra;
mod tokenizer;

pub use bitnet::HydraBitNet;
pub use hydra::{CompressionDecision, HydraModel, SecurityDecision, ThreatType};
pub use tokenizer::SimpleTokenizer;

/// Model version
pub const MODEL_VERSION: &str = "1.0.0";

/// Default model path (safetensors format)
pub const DEFAULT_MODEL_PATH: &str = "./models/hydra/model.safetensors";
