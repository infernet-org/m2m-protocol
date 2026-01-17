//! Token counting utilities.
//!
//! This module provides accurate token counting using tiktoken encodings
//! for OpenAI-compatible models, with heuristic fallback for others.
//!
//! # Supported Encodings
//!
//! - **cl100k_base**: GPT-3.5, GPT-4, Claude (approximate)
//! - **o200k_base**: GPT-4o, o1, o3 models
//! - **heuristic**: ~4 characters per token fallback
//!
//! # Example
//!
//! ```
//! use m2m::tokenizer::{count_tokens, count_tokens_with_encoding};
//! use m2m::models::Encoding;
//!
//! // Count with default encoding (cl100k)
//! let tokens = count_tokens("Hello, world!");
//! println!("Token count: {}", tokens);
//!
//! // Count with specific encoding
//! let tokens = count_tokens_with_encoding("Hello, world!", Encoding::O200kBase);
//! println!("Token count (o200k): {}", tokens);
//! ```

mod counter;

pub use counter::{count_tokens, count_tokens_for_model, count_tokens_with_encoding, TokenCounter};
