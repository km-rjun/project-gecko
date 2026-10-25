//! Small shared helpers: time, identifiers, random tokens, hashing.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Current Unix time in milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// New UUIDv7 identifier.
pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// 256-bit random token, base64url without padding. Returned in a zeroizing container.
pub fn random_token() -> Result<Zeroizing<String>, vault::VaultError> {
    let raw = Zeroizing::new(vault::random_array::<32>()?);
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(raw.as_ref())))
}

/// SHA-256 of a token; the only form in which tokens are stored.
pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
