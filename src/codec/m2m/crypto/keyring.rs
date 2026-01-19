//! Key derivation and management for M2M security.
//!
//! Uses HKDF (HMAC-based Key Derivation Function) to derive session keys
//! from master secrets.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Errors from keyring operations
#[derive(Debug, Error)]
pub enum KeyringError {
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Invalid key material
    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
}

/// Key identifier (typically a UUID or deterministic ID)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new key ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for KeyId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Key material (secret bytes)
#[derive(Clone)]
pub struct KeyMaterial {
    /// The raw key bytes
    bytes: Vec<u8>,
}

impl KeyMaterial {
    /// Create new key material from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create key material from a hex string
    pub fn from_hex(hex: &str) -> Result<Self, KeyringError> {
        let bytes = hex_decode(hex).map_err(|e| KeyringError::InvalidKey(e.to_string()))?;
        Ok(Self::new(bytes))
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key length
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Derive a new key using HKDF
    #[cfg(feature = "crypto")]
    pub fn derive(&self, info: &[u8], output_len: usize) -> Result<KeyMaterial, KeyringError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut okm = vec![0u8; output_len];

        hk.expand(info, &mut okm)
            .map_err(|e| KeyringError::DerivationFailed(format!("HKDF expand failed: {}", e)))?;

        Ok(KeyMaterial::new(okm))
    }

    /// Derive a new key (no-op without crypto feature)
    #[cfg(not(feature = "crypto"))]
    pub fn derive(&self, _info: &[u8], output_len: usize) -> Result<KeyMaterial, KeyringError> {
        // Without crypto feature, just truncate/extend the key
        let mut result = vec![0u8; output_len];
        let copy_len = self.bytes.len().min(output_len);
        result[..copy_len].copy_from_slice(&self.bytes[..copy_len]);
        Ok(KeyMaterial::new(result))
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't leak key material in debug output
        write!(f, "KeyMaterial([REDACTED, {} bytes])", self.bytes.len())
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        // Zeroize key material on drop
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

/// Keyring for managing multiple keys
#[derive(Debug, Default)]
pub struct Keyring {
    /// Keys indexed by ID
    keys: HashMap<KeyId, KeyMaterial>,
    /// Default key ID
    default_key: Option<KeyId>,
}

impl Keyring {
    /// Create a new empty keyring
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default_key: None,
        }
    }

    /// Add a key to the keyring
    pub fn add_key(&mut self, id: KeyId, material: KeyMaterial) {
        if self.keys.is_empty() {
            self.default_key = Some(id.clone());
        }
        self.keys.insert(id, material);
    }

    /// Get a key by ID
    pub fn get_key(&self, id: &KeyId) -> Option<&KeyMaterial> {
        self.keys.get(id)
    }

    /// Get the default key
    pub fn default_key(&self) -> Option<&KeyMaterial> {
        self.default_key.as_ref().and_then(|id| self.keys.get(id))
    }

    /// Set the default key
    pub fn set_default(&mut self, id: KeyId) -> Result<(), KeyringError> {
        if !self.keys.contains_key(&id) {
            return Err(KeyringError::KeyNotFound(id.to_string()));
        }
        self.default_key = Some(id);
        Ok(())
    }

    /// Remove a key
    pub fn remove_key(&mut self, id: &KeyId) -> Option<KeyMaterial> {
        if self.default_key.as_ref() == Some(id) {
            self.default_key = None;
        }
        self.keys.remove(id)
    }

    /// Check if the keyring is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get the number of keys
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Derive a session key from the default key
    #[cfg(feature = "crypto")]
    pub fn derive_session_key(
        &self,
        context: &str,
        session_id: &str,
    ) -> Result<KeyMaterial, KeyringError> {
        let master = self
            .default_key()
            .ok_or_else(|| KeyringError::KeyNotFound("no default key".to_string()))?;

        // Info = "m2m-v1" || context || session_id
        let info = format!("m2m-v1|{}|{}", context, session_id);
        master.derive(info.as_bytes(), 32)
    }

    /// Derive a session key (no-op without crypto feature)
    #[cfg(not(feature = "crypto"))]
    pub fn derive_session_key(
        &self,
        _context: &str,
        _session_id: &str,
    ) -> Result<KeyMaterial, KeyringError> {
        self.default_key()
            .cloned()
            .ok_or_else(|| KeyringError::KeyNotFound("no default key".to_string()))
    }
}

/// Simple hex decoder (no external dependency)
fn hex_decode(hex: &str) -> Result<Vec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("Invalid hex string length");
    }

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let high = hex_char_to_nibble(chunk[0])?;
            let low = hex_char_to_nibble(chunk[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_char_to_nibble(c: u8) -> Result<u8, &'static str> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("Invalid hex character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_material_from_hex() {
        let key = KeyMaterial::from_hex("0123456789abcdef").unwrap();
        assert_eq!(key.len(), 8);
        assert_eq!(
            key.as_bytes(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn test_keyring_basic() {
        let mut keyring = Keyring::new();
        assert!(keyring.is_empty());

        let key = KeyMaterial::new(vec![1, 2, 3, 4]);
        keyring.add_key(KeyId::new("test"), key);

        assert!(!keyring.is_empty());
        assert_eq!(keyring.len(), 1);

        let retrieved = keyring.get_key(&KeyId::new("test")).unwrap();
        assert_eq!(retrieved.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_keyring_default() {
        let mut keyring = Keyring::new();

        // First key becomes default
        let key1 = KeyMaterial::new(vec![1, 2, 3, 4]);
        keyring.add_key(KeyId::new("key1"), key1);

        let key2 = KeyMaterial::new(vec![5, 6, 7, 8]);
        keyring.add_key(KeyId::new("key2"), key2);

        // Default should be key1
        let default = keyring.default_key().unwrap();
        assert_eq!(default.as_bytes(), &[1, 2, 3, 4]);

        // Change default
        keyring.set_default(KeyId::new("key2")).unwrap();
        let default = keyring.default_key().unwrap();
        assert_eq!(default.as_bytes(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_key_material_debug_redacted() {
        let key = KeyMaterial::new(vec![0x41, 0x42, 0x43]); // "ABC"
        let debug = format!("{:?}", key);
        assert!(!debug.contains("ABC"));
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("3 bytes"));
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_hkdf_derivation() {
        let master = KeyMaterial::new(vec![0u8; 32]);
        let derived = master.derive(b"test-context", 32).unwrap();

        // Derived key should be different from master
        assert_ne!(derived.as_bytes(), master.as_bytes());
        assert_eq!(derived.len(), 32);

        // Deterministic: same inputs = same output
        let derived2 = master.derive(b"test-context", 32).unwrap();
        assert_eq!(derived.as_bytes(), derived2.as_bytes());

        // Different context = different key
        let derived3 = master.derive(b"other-context", 32).unwrap();
        assert_ne!(derived.as_bytes(), derived3.as_bytes());
    }
}
