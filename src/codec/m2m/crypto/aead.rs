//! ChaCha20-Poly1305 AEAD encryption for M2M frames.
//!
//! Provides authenticated encryption with associated data (AEAD).
//! The nonce and auth tag are prepended/appended to the ciphertext.

#![allow(missing_docs)]

use super::keyring::KeyMaterial;
use super::{AEAD_TAG_SIZE, MIN_KEY_SIZE, NONCE_SIZE};
use thiserror::Error;

/// Errors from AEAD operations
#[derive(Debug, Error)]
pub enum AeadError {
    /// Invalid key
    #[error("Invalid AEAD key: {0}")]
    InvalidKey(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed (auth tag mismatch or corrupted data)
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Data too short
    #[error("Ciphertext too short")]
    DataTooShort,
}

/// ChaCha20-Poly1305 cipher for authenticated encryption
#[derive(Debug)]
pub struct AeadCipher {
    /// Key material (must be 32 bytes)
    key: KeyMaterial,
}

impl AeadCipher {
    /// Create a new AEAD cipher with the given key
    pub fn new(key: KeyMaterial) -> Result<Self, AeadError> {
        if key.len() < MIN_KEY_SIZE {
            return Err(AeadError::InvalidKey(format!(
                "Key too short: {} bytes (need {})",
                key.len(),
                MIN_KEY_SIZE
            )));
        }
        Ok(Self { key })
    }

    /// Encrypt plaintext with the given nonce and associated data
    ///
    /// Returns: nonce || ciphertext || tag
    #[cfg(feature = "crypto")]
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8; NONCE_SIZE],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };

        let key_bytes: [u8; 32] = self.key.as_bytes()[..32]
            .try_into()
            .map_err(|_| AeadError::InvalidKey("Key conversion failed".to_string()))?;

        let cipher = ChaCha20Poly1305::new(&key_bytes.into());
        let nonce_obj = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        let ciphertext = cipher
            .encrypt(nonce_obj, payload)
            .map_err(|e| AeadError::EncryptionFailed(e.to_string()))?;

        // Output format: nonce || ciphertext (includes auth tag)
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Encrypt (fallback without crypto feature - NOT SECURE)
    #[cfg(not(feature = "crypto"))]
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8; NONCE_SIZE],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        // XOR "encryption" for testing only - NOT CRYPTOGRAPHICALLY SECURE
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= self.key.as_bytes()[i % self.key.len()];
            *byte ^= nonce[i % NONCE_SIZE];
        }

        // Add fake auth tag
        let mut tag = [0u8; AEAD_TAG_SIZE];
        for (i, byte) in plaintext.iter().enumerate() {
            tag[i % AEAD_TAG_SIZE] ^= byte;
        }

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len() + AEAD_TAG_SIZE);
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);

        Ok(result)
    }

    /// Decrypt ciphertext
    ///
    /// Input format: nonce || ciphertext || tag
    #[cfg(feature = "crypto")]
    pub fn decrypt(
        &self,
        ciphertext_with_nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305, Nonce,
        };

        if ciphertext_with_nonce.len() < NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(AeadError::DataTooShort);
        }

        let nonce = &ciphertext_with_nonce[..NONCE_SIZE];
        let ciphertext = &ciphertext_with_nonce[NONCE_SIZE..];

        let key_bytes: [u8; 32] = self.key.as_bytes()[..32]
            .try_into()
            .map_err(|_| AeadError::InvalidKey("Key conversion failed".to_string()))?;

        let cipher = ChaCha20Poly1305::new(&key_bytes.into());
        let nonce_obj = Nonce::from_slice(nonce);

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        cipher
            .decrypt(nonce_obj, payload)
            .map_err(|e| AeadError::DecryptionFailed(e.to_string()))
    }

    /// Decrypt (fallback without crypto feature - NOT SECURE)
    #[cfg(not(feature = "crypto"))]
    pub fn decrypt(
        &self,
        ciphertext_with_nonce: &[u8],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if ciphertext_with_nonce.len() < NONCE_SIZE + AEAD_TAG_SIZE {
            return Err(AeadError::DataTooShort);
        }

        let nonce = &ciphertext_with_nonce[..NONCE_SIZE];
        let ciphertext =
            &ciphertext_with_nonce[NONCE_SIZE..ciphertext_with_nonce.len() - AEAD_TAG_SIZE];
        let _tag = &ciphertext_with_nonce[ciphertext_with_nonce.len() - AEAD_TAG_SIZE..];

        // XOR "decryption" for testing only
        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= self.key.as_bytes()[i % self.key.len()];
            *byte ^= nonce[i % NONCE_SIZE];
        }

        Ok(plaintext)
    }

    /// Encrypt with auto-generated nonce (requires crypto feature for secure RNG)
    #[cfg(feature = "crypto")]
    pub fn encrypt_auto_nonce(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        use rand::RngCore;

        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);

        self.encrypt(plaintext, &nonce, associated_data)
    }
}

/// Convenience function to encrypt data with a key
#[cfg(feature = "crypto")]
#[allow(dead_code)]
pub fn encrypt(
    key: &KeyMaterial,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = AeadCipher::new(key.clone())?;
    cipher.encrypt_auto_nonce(plaintext, associated_data)
}

/// Convenience function to decrypt data with a key
#[allow(dead_code)]
pub fn decrypt(
    key: &KeyMaterial,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = AeadCipher::new(key.clone())?;
    cipher.decrypt(ciphertext, associated_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> KeyMaterial {
        KeyMaterial::new(vec![0x42u8; 32])
    }

    fn test_nonce() -> [u8; NONCE_SIZE] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    }

    #[test]
    fn test_aead_encrypt_decrypt() {
        let cipher = AeadCipher::new(test_key()).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"associated data";

        let ciphertext = cipher.encrypt(plaintext, &test_nonce(), aad).unwrap();

        // Ciphertext should be longer (nonce + tag)
        assert!(ciphertext.len() > plaintext.len());

        let decrypted = cipher.decrypt(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_aead_tamper_detection() {
        let cipher = AeadCipher::new(test_key()).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"associated data";

        let mut ciphertext = cipher.encrypt(plaintext, &test_nonce(), aad).unwrap();

        // Tamper with the ciphertext
        let tamper_idx = NONCE_SIZE + 1;
        if tamper_idx < ciphertext.len() {
            ciphertext[tamper_idx] ^= 0xFF;
        }

        // Decryption should fail
        let result = cipher.decrypt(&ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_aad() {
        let cipher = AeadCipher::new(test_key()).unwrap();
        let plaintext = b"Hello, World!";

        // Wrong AAD should fail (with crypto feature)
        #[cfg(feature = "crypto")]
        {
            let ciphertext = cipher
                .encrypt(plaintext, &test_nonce(), b"correct aad")
                .unwrap();
            let result = cipher.decrypt(&ciphertext, b"wrong aad");
            assert!(result.is_err());
        }

        // Without crypto, just verify encryption works
        #[cfg(not(feature = "crypto"))]
        {
            let _ = cipher
                .encrypt(plaintext, &test_nonce(), b"correct aad")
                .unwrap();
        }
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_aead_wrong_key() {
        let cipher1 = AeadCipher::new(KeyMaterial::new(vec![1u8; 32])).unwrap();
        let cipher2 = AeadCipher::new(KeyMaterial::new(vec![2u8; 32])).unwrap();

        let plaintext = b"Hello, World!";
        let aad = b"";

        let ciphertext = cipher1.encrypt(plaintext, &test_nonce(), aad).unwrap();

        // Different key should fail
        let result = cipher2.decrypt(&ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_key_too_short() {
        let short_key = KeyMaterial::new(vec![0u8; 16]);
        let result = AeadCipher::new(short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_data_too_short() {
        let cipher = AeadCipher::new(test_key()).unwrap();

        // Too short for nonce + tag
        let result = cipher.decrypt(&[0u8; 10], b"");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn test_aead_auto_nonce() {
        let cipher = AeadCipher::new(test_key()).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"";

        let ciphertext1 = cipher.encrypt_auto_nonce(plaintext, aad).unwrap();
        let ciphertext2 = cipher.encrypt_auto_nonce(plaintext, aad).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly
        let decrypted1 = cipher.decrypt(&ciphertext1, aad).unwrap();
        let decrypted2 = cipher.decrypt(&ciphertext2, aad).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
