use std::fmt;

/// Errors returned by vault operations. Messages never contain secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Password (or recovery key) did not verify.
    InvalidCredentials,
    /// Ciphertext, nonce, tag or bound context failed authentication.
    Integrity,
    /// Recovery key is malformed or its checksum does not match.
    InvalidRecoveryKey,
    /// Password rejected by policy.
    PasswordPolicy(&'static str),
    /// Stored record has an unexpected shape (wrong lengths, unknown parameters).
    Malformed(&'static str),
    /// Operating system CSPRNG failure.
    Random,
    /// Argon2 rejected the parameters.
    Kdf,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => f.write_str("invalid credentials"),
            Self::Integrity => f.write_str("stored data failed integrity check"),
            Self::InvalidRecoveryKey => f.write_str("invalid recovery key"),
            Self::PasswordPolicy(why) => write!(f, "password rejected: {why}"),
            Self::Malformed(what) => write!(f, "malformed vault record: {what}"),
            Self::Random => f.write_str("random number generator failure"),
            Self::Kdf => f.write_str("key derivation failure"),
        }
    }
}

impl std::error::Error for VaultError {}
