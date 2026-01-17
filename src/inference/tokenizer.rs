//! Simple tokenizer for model input preparation.
//!
//! Provides basic BPE-like tokenization for the Hydra model.
//! This is a simplified tokenizer - for production use with
//! specific LLM tokenizers, use tiktoken or similar.

use std::collections::HashMap;

use crate::error::Result;

/// Simple character-level tokenizer with basic BPE merges
pub struct SimpleTokenizer {
    /// Vocabulary mapping (token -> id)
    vocab: HashMap<String, u32>,
    /// Reverse vocabulary (id -> token)
    reverse_vocab: HashMap<u32, String>,
    /// Special tokens
    special_tokens: SpecialTokens,
    /// Maximum sequence length
    max_length: usize,
}

/// Special token IDs
#[derive(Debug, Clone)]
pub struct SpecialTokens {
    pub pad: u32,
    pub unk: u32,
    pub bos: u32,
    pub eos: u32,
}

impl Default for SpecialTokens {
    fn default() -> Self {
        Self {
            pad: 0,
            unk: 1,
            bos: 2,
            eos: 3,
        }
    }
}

impl Default for SimpleTokenizer {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleTokenizer {
    /// Create new tokenizer with default vocabulary
    pub fn new() -> Self {
        let mut vocab = HashMap::new();
        let mut reverse_vocab = HashMap::new();

        // Special tokens
        vocab.insert("<pad>".to_string(), 0);
        vocab.insert("<unk>".to_string(), 1);
        vocab.insert("<bos>".to_string(), 2);
        vocab.insert("<eos>".to_string(), 3);

        // ASCII characters (4-127)
        for i in 0u8..128 {
            let ch = i as char;
            let id = i as u32 + 4;
            vocab.insert(ch.to_string(), id);
            reverse_vocab.insert(id, ch.to_string());
        }

        // Common JSON patterns (128+)
        let patterns = [
            ("messages", 128),
            ("content", 129),
            ("role", 130),
            ("model", 131),
            ("user", 132),
            ("assistant", 133),
            ("system", 134),
            ("gpt-4", 135),
            ("claude", 136),
            ("temperature", 137),
            ("max_tokens", 138),
            ("stream", 139),
            ("true", 140),
            ("false", 141),
            ("null", 142),
        ];

        for (token, id) in patterns {
            vocab.insert(token.to_string(), id);
            reverse_vocab.insert(id, token.to_string());
        }

        // Build reverse vocab for basic chars
        for (token, &id) in &vocab {
            reverse_vocab.insert(id, token.clone());
        }

        Self {
            vocab,
            reverse_vocab,
            special_tokens: SpecialTokens::default(),
            max_length: 512,
        }
    }

    /// Load tokenizer from vocabulary file
    pub fn from_vocab_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut tokenizer = Self::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 2 {
                if let Ok(id) = parts[1].parse::<u32>() {
                    tokenizer.vocab.insert(parts[0].to_string(), id);
                    tokenizer.reverse_vocab.insert(id, parts[0].to_string());
                }
            }
        }

        Ok(tokenizer)
    }

    /// Tokenize text to token IDs
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut tokens = vec![self.special_tokens.bos];

        // Simple word-level tokenization with JSON pattern matching
        let mut chars = text.chars().peekable();

        while let Some(ch) = chars.next() {
            // Try to match known patterns
            let remaining: String = std::iter::once(ch).chain(chars.clone()).collect();

            let mut matched = false;
            for (pattern, &id) in &self.vocab {
                if pattern.len() > 1 && remaining.starts_with(pattern) {
                    tokens.push(id);
                    // Skip the matched characters
                    for _ in 0..pattern.len() - 1 {
                        chars.next();
                    }
                    matched = true;
                    break;
                }
            }

            if !matched {
                // Single character
                let token_id = self
                    .vocab
                    .get(&ch.to_string())
                    .copied()
                    .unwrap_or(self.special_tokens.unk);
                tokens.push(token_id);
            }
        }

        tokens.push(self.special_tokens.eos);

        // Truncate to max length
        if tokens.len() > self.max_length {
            tokens.truncate(self.max_length - 1);
            tokens.push(self.special_tokens.eos);
        }

        tokens
    }

    /// Decode token IDs back to text
    pub fn decode(&self, tokens: &[u32]) -> String {
        tokens
            .iter()
            .filter_map(|&id| {
                if id == self.special_tokens.pad
                    || id == self.special_tokens.bos
                    || id == self.special_tokens.eos
                {
                    None
                } else {
                    self.reverse_vocab.get(&id).cloned()
                }
            })
            .collect()
    }

    /// Pad or truncate tokens to specific length
    pub fn pad_to_length(&self, tokens: &[u32], length: usize) -> Vec<u32> {
        let mut result = tokens.to_vec();

        if result.len() > length {
            result.truncate(length - 1);
            result.push(self.special_tokens.eos);
        } else {
            while result.len() < length {
                result.push(self.special_tokens.pad);
            }
        }

        result
    }

    /// Get vocabulary size
    pub fn vocab_size(&self) -> usize {
        self.vocab.len()
    }

    /// Set maximum sequence length
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Estimate token count (rough approximation)
    pub fn estimate_tokens(&self, text: &str) -> usize {
        // Rough estimate: ~4 chars per token for English
        text.len() / 4 + 2 // +2 for BOS/EOS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let tokenizer = SimpleTokenizer::new();
        let text = "Hello, world!";

        let tokens = tokenizer.encode(text);
        assert!(!tokens.is_empty());
        assert_eq!(tokens[0], tokenizer.special_tokens.bos);
        assert_eq!(*tokens.last().unwrap(), tokenizer.special_tokens.eos);

        let decoded = tokenizer.decode(&tokens);
        assert_eq!(decoded, text);
    }

    #[test]
    fn test_json_pattern_matching() {
        let tokenizer = SimpleTokenizer::new();
        let text = r#"{"messages":[{"role":"user","content":"Hello"}]}"#;

        let tokens = tokenizer.encode(text);

        // Should contain the pattern tokens
        let has_messages = tokens.contains(&128); // "messages"
        let has_role = tokens.contains(&130); // "role"
        let has_content = tokens.contains(&129); // "content"

        assert!(has_messages || has_role || has_content);
    }

    #[test]
    fn test_padding() {
        let tokenizer = SimpleTokenizer::new();
        let tokens = vec![2, 72, 101, 108, 108, 111, 3]; // <bos>Hello<eos>

        let padded = tokenizer.pad_to_length(&tokens, 10);
        assert_eq!(padded.len(), 10);
        assert_eq!(padded[7], 0); // PAD token
    }

    #[test]
    fn test_truncation() {
        let tokenizer = SimpleTokenizer::new().with_max_length(10);
        let long_text = "This is a very long text that should be truncated";

        let tokens = tokenizer.encode(long_text);
        assert!(tokens.len() <= 10);
        assert_eq!(*tokens.last().unwrap(), tokenizer.special_tokens.eos);
    }
}
