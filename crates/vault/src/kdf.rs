//! Password → Argon2id → HKDF-SHA256 → (AuthKey, KEK) (docs/02 §3.1).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{SecretString, VaultError, secret::Key32};

pub const INFO_AUTH: &[u8] = b"vault.v1.auth";
pub const INFO_KEK: &[u8] = b"vault.v1.kek";
pub const KDF_ALG: &str = "argon2id-v19";

pub const PASSWORD_MIN_CHARS: usize = 12;
pub const PASSWORD_MAX_BYTES: usize = 1024;

/// Argon2id cost parameters, stored per user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Production parameters: m = 64 MiB, t = 3, p = 4.
    pub const DEFAULT: Self = Self {
        m_kib: 65536,
        t: 3,
        p: 4,
    };
    /// Minimal parameters for unit/integration tests only.
    #[doc(hidden)]
    pub const INSECURE_TEST: Self = Self {
        m_kib: 64,
        t: 1,
        p: 1,
    };
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Output of a password derivation.
pub struct DerivedKeys {
    /// SHA-256(AuthKey); stored as `users.auth_verifier`.
    pub auth_verifier: [u8; 32],
    pub(crate) kek: Key32,
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKeys([REDACTED])")
    }
}

/// Validates and NFC-normalises a password.
pub fn normalize_password(password: &SecretString) -> Result<SecretString, VaultError> {
    let normalized = SecretString::new(password.expose().nfc().collect());
    if normalized.expose().chars().count() < PASSWORD_MIN_CHARS {
        return Err(VaultError::PasswordPolicy("must be at least 12 characters"));
    }
    if normalized.len() > PASSWORD_MAX_BYTES {
        return Err(VaultError::PasswordPolicy("must be at most 1024 bytes"));
    }
    Ok(normalized)
}

/// Derives AuthKey (→ verifier) and KEK. CPU/memory heavy: call from a blocking thread.
pub fn derive(
    password: &SecretString,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<DerivedKeys, VaultError> {
    let pw = normalize_password(password)?;
    let argon_params =
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| VaultError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut ikm = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pw.expose().as_bytes(), salt, ikm.as_mut())
        .map_err(|_| VaultError::Kdf)?;

    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut auth_key = Zeroizing::new([0u8; 32]);
    let mut kek = [0u8; 32];
    hk.expand(INFO_AUTH, auth_key.as_mut())
        .map_err(|_| VaultError::Kdf)?;
    hk.expand(INFO_KEK, &mut kek).map_err(|_| VaultError::Kdf)?;
    let auth_verifier: [u8; 32] = Sha256::digest(auth_key.as_ref()).into();
    Ok(DerivedKeys {
        auth_verifier,
        kek: Key32::from_array(kek),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::new(s.into())
    }

    #[test]
    fn deterministic_and_salted() {
        let salt = [1u8; 16];
        let a = derive(
            &pw("correct horse battery"),
            &salt,
            KdfParams::INSECURE_TEST,
        )
        .expect("derive");
        let b = derive(
            &pw("correct horse battery"),
            &salt,
            KdfParams::INSECURE_TEST,
        )
        .expect("derive");
        let c = derive(
            &pw("correct horse battery"),
            &[2u8; 16],
            KdfParams::INSECURE_TEST,
        )
        .expect("derive");
        assert_eq!(a.auth_verifier, b.auth_verifier);
        assert_eq!(a.kek.as_bytes(), b.kek.as_bytes());
        assert_ne!(a.auth_verifier, c.auth_verifier);
        // verifier is independent of the KEK
        assert_ne!(&a.auth_verifier, a.kek.as_bytes());
    }

    #[test]
    fn nfc_normalisation_makes_equivalent_passwords_equal() {
        let salt = [3u8; 16];
        let composed =
            derive(&pw("caf\u{e9}-password-1"), &salt, KdfParams::INSECURE_TEST).expect("derive");
        let decomposed = derive(
            &pw("cafe\u{301}-password-1"),
            &salt,
            KdfParams::INSECURE_TEST,
        )
        .expect("derive");
        assert_eq!(composed.auth_verifier, decomposed.auth_verifier);
    }

    #[test]
    fn policy() {
        assert!(normalize_password(&pw("short")).is_err());
        assert!(normalize_password(&pw(&"x".repeat(1025))).is_err());
        assert!(normalize_password(&pw("twelve chars")).is_ok());
    }

    #[test]
    fn production_parameters_match_spec() {
        assert_eq!(
            KdfParams::DEFAULT,
            KdfParams {
                m_kib: 65536,
                t: 3,
                p: 4
            }
        );
    }
}
