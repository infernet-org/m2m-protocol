//! Hydra ML inference for intelligent algorithm routing.
//!
//! The [Hydra SLM](https://huggingface.co/infernet/hydra) is a small language model
//! optimized for M2M protocol tasks. Uses ONNX Runtime for inference.
//!
//! # Tasks
//!
//! - **Compression selection**: Predicts optimal algorithm (None/Token/Brotli/Dictionary)
//! - **Security detection**: Classifies prompt injection and jailbreak attempts
//! - **Token estimation**: Fast approximate token counting
//!
//! # Model Architecture
//!
//! The Hydra model is a 1.58-bit quantized BitNet Mixture of Experts:
//! - 4 experts: Compression, Security, Semantic, General
//! - Ternary weights: {-1, 0, 1}
//! - ~3.8MB model size
//! - <10ms inference latency
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
//! let model = HydraModel::load("./models/hydra")?;
//!
//! let decision = model.predict_compression(&content)?;
//! match decision.algorithm {
//!     Algorithm::Brotli => // use brotli
//!     _ => // use other
//! }
//! ```

mod hydra;
mod tokenizer;

pub use hydra::{CompressionDecision, HydraModel, SecurityDecision, ThreatType};
pub use tokenizer::SimpleTokenizer;

/// Model version
pub const MODEL_VERSION: &str = "1.0.0";

/// Default model path
pub const DEFAULT_MODEL_PATH: &str = "./models/hydra.onnx";
