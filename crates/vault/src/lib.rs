//! Zero-plaintext vault: Argon2id, HKDF-SHA256, XChaCha20-Poly1305 and zeroizing secret types.
//!
//! Specification: docs/02-security-and-vault-spec.md (§3 key hierarchy, §5 memory hygiene).
//! This crate performs no I/O, no logging and no database access.
#![forbid(unsafe_code)]

pub mod aad;
pub mod error;
pub mod kdf;
pub mod pad;
pub mod recovery;
pub mod seal;
pub mod secret;
pub mod user;

pub use error::VaultError;
pub use kdf::KdfParams;
pub use seal::Sealed;
pub use secret::{Mvk, SecretBytes, SecretString};
pub use user::UserKeyRecord;

/// Version of the on-disk cryptographic format (`users.crypto_version`).
pub const CRYPTO_VERSION: u16 = 1;

/// AEAD identifier stored next to every ciphertext.
pub const AEAD_ID: &str = "xchacha20poly1305-v1";

/// Fills `buf` from the operating system CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf).map_err(|_| VaultError::Random)
}

/// Returns `N` random bytes from the operating system CSPRNG.
pub fn random_array<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut out = [0u8; N];
    random_bytes(&mut out)?;
    Ok(out)
}
