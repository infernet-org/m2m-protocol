//! HMAC-SHA256 message authentication for M2M frames.
//!
//! Provides integrity protection without encryption. The HMAC tag is
//! appended to the frame payload.

#![allow(missing_docs)]

use super::keyring::KeyMaterial;
use super::HMAC_TAG_SIZE;
use thiserror::Error;

/// Errors from HMAC operations
#[derive(Debug, Error)]
pub enum HmacError {
    /// Invalid key
    #[error("Invalid HMAC key: {0}")]
    InvalidKey(String),

    /// Tag verification failed
    #[error("HMAC verification failed")]
    VerificationFailed,

    /// Data too short
    #[error("Data too short for HMAC tag")]
    DataTooShort,
}

/// HMAC-SHA256 authenticator
#[derive(Debug)]
pub struct HmacAuth {
    /// Key material
    key: KeyMaterial,
}

impl HmacAuth {
    /// Create a new HMAC authenticator with the given key
    pub fn new(key: KeyMaterial) -> Result<Self, HmacError> {
        if key.len() < 16 {
            return Err(HmacError::InvalidKey(format!(
                "Key too short: {} bytes (minimum 16)",
                key.len()
            )));
        }
        Ok(Self { key })
    }

    /// Compute HMAC-SHA256 tag for data
    #[cfg(feature = "crypto")]
    pub fn compute_tag(&self, data: &[u8]) -> [u8; HMAC_TAG_SIZE] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(self.key.as_bytes()).expect("HMAC accepts any key size");
        mac.update(data);

        let result = mac.finalize();
        let mut tag = [0u8; HMAC_TAG_SIZE];
        tag.copy_from_slice(&result.into_bytes());
        tag
    }

    /// Compute HMAC tag (fallback without crypto feature)
    #[cfg(not(feature = "crypto"))]
    pub fn compute_tag(&self, data: &[u8]) -> [u8; HMAC_TAG_SIZE] {
        // Simple XOR-based "MAC" for testing only
        // NOT CRYPTOGRAPHICALLY SECURE
        let mut tag = [0u8; HMAC_TAG_SIZE];
        for (i, byte) in data.iter().enumerate() {
            tag[i % HMAC_TAG_SIZE] ^= byte;
        }
        for (i, byte) in self.key.as_bytes().iter().enumerate() {
            tag[i % HMAC_TAG_SIZE] ^= byte;
        }
        tag
    }

    /// Verify HMAC tag
    #[cfg(feature = "crypto")]
    pub fn verify_tag(&self, data: &[u8], tag: &[u8]) -> Result<(), HmacError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac =
            HmacSha256::new_from_slice(self.key.as_bytes()).expect("HMAC accepts any key size");
        mac.update(data);

        mac.verify_slice(tag)
            .map_err(|_| HmacError::VerificationFailed)
    }

    /// Verify HMAC tag (fallback without crypto feature)
    #[cfg(not(feature = "crypto"))]
    pub fn verify_tag(&self, data: &[u8], tag: &[u8]) -> Result<(), HmacError> {
        let expected = self.compute_tag(data);
        if constant_time_eq(&expected, tag) {
            Ok(())
        } else {
            Err(HmacError::VerificationFailed)
        }
    }

    /// Sign data by appending HMAC tag
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let tag = self.compute_tag(data);
        let mut result = Vec::with_capacity(data.len() + HMAC_TAG_SIZE);
        result.extend_from_slice(data);
        result.extend_from_slice(&tag);
        result
    }

    /// Verify and return data without tag
    pub fn verify(&self, signed_data: &[u8]) -> Result<Vec<u8>, HmacError> {
        if signed_data.len() < HMAC_TAG_SIZE {
            return Err(HmacError::DataTooShort);
        }

        let data_len = signed_data.len() - HMAC_TAG_SIZE;
        let data = &signed_data[..data_len];
        let tag = &signed_data[data_len..];

        self.verify_tag(data, tag)?;
        Ok(data.to_vec())
    }
}

/// Constant-time comparison to prevent timing attacks
#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> KeyMaterial {
        KeyMaterial::new(vec![0u8; 32])
    }

    #[test]
    fn test_hmac_sign_verify() {
        let auth = HmacAuth::new(test_key()).unwrap();
        let data = b"Hello, World!";

        let signed = auth.sign(data);
        assert_eq!(signed.len(), data.len() + HMAC_TAG_SIZE);

        let verified = auth.verify(&signed).unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn test_hmac_tamper_detection() {
        let auth = HmacAuth::new(test_key()).unwrap();
        let data = b"Hello, World!";

        let mut signed = auth.sign(data);

        // Tamper with the data
        signed[0] ^= 0xFF;

        let result = auth.verify(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_wrong_key() {
        let auth1 = HmacAuth::new(KeyMaterial::new(vec![1u8; 32])).unwrap();
        let auth2 = HmacAuth::new(KeyMaterial::new(vec![2u8; 32])).unwrap();

        let data = b"Hello, World!";
        let signed = auth1.sign(data);

        // Different key should fail verification
        let result = auth2.verify(&signed);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_deterministic() {
        let auth = HmacAuth::new(test_key()).unwrap();
        let data = b"Hello, World!";

        let tag1 = auth.compute_tag(data);
        let tag2 = auth.compute_tag(data);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_key_too_short() {
        let short_key = KeyMaterial::new(vec![0u8; 8]);
        let result = HmacAuth::new(short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
