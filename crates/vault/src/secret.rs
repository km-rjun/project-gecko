//! Secret containers. None implement `Clone`, `Display` or `Serialize`; `Debug` is redacted.

use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Heap bytes wiped on drop.
#[derive(Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED; {}])", self.0.len())
    }
}

/// UTF-8 string wiped on drop. Deserializable so request bodies land directly in it.
#[derive(Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

/// 256-bit symmetric key wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Key32([u8; 32]);

impl Key32 {
    pub(crate) fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub(crate) fn random() -> Result<Self, crate::VaultError> {
        crate::random_array::<32>().map(Self)
    }
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Master Vault Key: encrypts every node record of one user. Lives only in the session keyring.
pub struct Mvk(pub(crate) Key32);

impl fmt::Debug for Mvk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mvk([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let s = SecretString::new("hunter2-very-secret".into());
        let b = SecretBytes::new(b"raw-secret-bytes".to_vec());
        let m = Mvk(Key32::from_array([7u8; 32]));
        let out = format!("{s:?} {b:?} {m:?}");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("raw-secret"));
        assert!(!out.contains("7, 7"));
        assert!(out.contains("REDACTED"));
    }

    #[test]
    fn secret_string_deserializes() {
        let s: SecretString = serde_json::from_str("\"pw\"").expect("json");
        assert_eq!(s.expose(), "pw");
    }
}
