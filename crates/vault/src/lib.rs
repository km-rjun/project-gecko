//! Zero-plaintext vault: Argon2id, HKDF-SHA256, XChaCha20-Poly1305 and zeroizing secret types.
//!
//! Specification: docs/02-security-and-vault-spec.md. Implemented in Checkpoint 2.
//! This crate performs no I/O, no logging and no database access.
#![forbid(unsafe_code)]

/// Version of the on-disk cryptographic format (`users.crypto_version`).
pub const CRYPTO_VERSION: u16 = 1;
