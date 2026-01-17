//! Model registry and metadata.
//!
//! This module provides model cards with metadata including:
//! - Abbreviations for compression
//! - Tokenizer encoding types
//! - Default parameter values
//! - Context window sizes
//!
//! # Example
//!
//! ```
//! use m2m::models::{ModelRegistry, Encoding, Provider};
//!
//! // Create a registry
//! let registry = ModelRegistry::new();
//!
//! // Lookup a model
//! let card = registry.get("openai/gpt-4o").unwrap();
//! assert_eq!(card.abbrev, "og4o");
//! assert_eq!(card.provider, Provider::OpenAI);
//! assert_eq!(card.encoding, Encoding::O200kBase);
//!
//! // Abbreviate and expand
//! assert_eq!(registry.abbreviate("openai/gpt-4o"), "og4o");
//! assert_eq!(registry.expand("og4o"), Some("openai/gpt-4o".to_string()));
//! ```

mod card;
mod embedded;
mod registry;

pub use card::{Encoding, ModelCard, Pricing, Provider};
pub use embedded::{
    get_embedded_by_abbrev, get_embedded_by_id, get_embedded_models, get_pricing, EMBEDDED_MODELS,
};
pub use registry::ModelRegistry;
