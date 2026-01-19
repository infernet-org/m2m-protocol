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
//! # Tokenizers
//!
//! Hydra supports multiple tokenizer backends:
//!
//! - **Llama 3** (128K vocab): Primary tokenizer for open source ecosystem
//! - **o200k_base** (200K vocab): OpenAI GPT-4o, o1, o3
//! - **cl100k_base** (100K vocab): OpenAI GPT-3.5, GPT-4
//! - **Fallback**: Byte-level tokenizer when nothing else available
//!
//! # Tasks
//!
//! - **Compression selection**: Predicts optimal algorithm (None/BPE/Brotli/Zlib)
//! - **Security detection**: Classifies prompt injection and jailbreak attempts
//! - **Token estimation**: Fast approximate token counting
//!
//! # Model Architecture
//!
//! ```text
//! vocab_size: 128000 (Llama 3), hidden_size: 192, num_layers: 4, num_experts: 4
//! ```
//!
//! The Hydra model is a Mixture of Experts classifier:
//! - 4 MoE layers with top-2 expert routing
//! - Heterogeneous expert architectures (different depths/widths)
//! - ~100MB model size (float32 weights with 128K vocab)
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
//! use m2m::inference::{HydraModel, CompressionDecision, Llama3Tokenizer};
//!
//! // Load model and tokenizer
//! let model = HydraModel::load("./models/hydra")?;
//!
//! let decision = model.predict_compression(&content)?;
//! match decision.algorithm {
//!     Algorithm::Brotli => // use brotli
//!     _ => // use other
//! }
//! ```

pub mod bitnet;
mod hydra;
pub mod tokenizer;

pub use bitnet::HydraBitNet;
pub use hydra::{CompressionDecision, HydraModel, SecurityDecision, ThreatType};

// Tokenizer exports
pub use tokenizer::{
    boxed, load_tokenizer, load_tokenizer_by_type, BoxedTokenizer, FallbackTokenizer,
    HydraByteTokenizer, HydraTokenizer, Llama3Tokenizer, TiktokenTokenizer, TokenizerType,
    MAX_SEQUENCE_LENGTH,
};

/// Model version
pub const MODEL_VERSION: &str = "2.0.0";

/// Default model path (safetensors format)
pub const DEFAULT_MODEL_PATH: &str = "./models/hydra/model.safetensors";

/// Default tokenizer path
pub const DEFAULT_TOKENIZER_PATH: &str = "./models/hydra/tokenizer.json";
