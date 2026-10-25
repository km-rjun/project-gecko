//! XChaCha20-Poly1305 with random 192-bit nonces.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

use crate::{Mvk, SecretBytes, VaultError, aad, pad, secret::Key32};

/// Nonce + ciphertext (tag appended) as stored in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub(crate) fn seal_with(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, VaultError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| VaultError::Kdf)?;
    let nonce = crate::random_array::<24>()?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Integrity)?;
    Ok(Sealed { nonce, ciphertext })
}

pub(crate) fn open_with(
    key: &Key32,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, VaultError> {
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| VaultError::Malformed("nonce length"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| VaultError::Kdf)?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(SecretBytes::new)
        .map_err(|_| VaultError::Integrity)
}

/// Kinds of MVK-encrypted records stored in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// `nodes.meta_ciphertext`
    NodeMeta,
    /// `encrypted_secrets.ciphertext`
    Secrets,
    /// `node_host_identities.ciphertext`
    HostIdentity,
    /// `audit_logs.sealed_details`
    Audit,
}

impl RecordKind {
    fn label(self) -> &'static str {
        match self {
            Self::NodeMeta => aad::LABEL_NODE_META,
            Self::Secrets => aad::LABEL_SECRET,
            Self::HostIdentity => aad::LABEL_HOST_IDENTITY,
            Self::Audit => aad::LABEL_AUDIT,
        }
    }
    fn bucket(self) -> usize {
        match self {
            Self::Secrets => pad::BUCKET_SECRETS,
            _ => pad::BUCKET_META,
        }
    }
}

impl Mvk {
    /// Pads and encrypts `plaintext`, binding it to (`kind`, `user_id`, `record_id`).
    pub fn seal(
        &self,
        kind: RecordKind,
        user_id: &str,
        record_id: &str,
        plaintext: &[u8],
    ) -> Result<Sealed, VaultError> {
        let padded = pad::pad(plaintext, kind.bucket())?;
        seal_with(
            &self.0,
            &aad::record(kind.label(), user_id, record_id),
            &padded,
        )
    }

    /// Decrypts and unpads a record sealed with [`Mvk::seal`] for the same context.
    pub fn open(
        &self,
        kind: RecordKind,
        user_id: &str,
        record_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretBytes, VaultError> {
        let padded = open_with(
            &self.0,
            &aad::record(kind.label(), user_id, record_id),
            nonce,
            ciphertext,
        )?;
        pad::unpad(&padded)
    }

    /// Test/support constructor from raw bytes (not used by the gateway).
    #[doc(hidden)]
    pub fn from_bytes_for_tests(bytes: [u8; 32]) -> Self {
        Mvk(Key32::from_array(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mvk() -> Mvk {
        Mvk(Key32::random().expect("rng"))
    }

    #[test]
    fn round_trip_and_padding() {
        let k = mvk();
        let s = k
            .seal(RecordKind::NodeMeta, "u1", "n1", b"{\"host\":\"10.0.0.5\"}")
            .expect("seal");
        assert_eq!(s.ciphertext.len(), 256 + 16);
        let p = k
            .open(RecordKind::NodeMeta, "u1", "n1", &s.nonce, &s.ciphertext)
            .expect("open");
        assert_eq!(p.expose(), b"{\"host\":\"10.0.0.5\"}");
        let sec = k.seal(RecordKind::Secrets, "u1", "n1", b"x").expect("seal");
        assert_eq!(sec.ciphertext.len(), 512 + 16);
    }

    #[test]
    fn nonces_are_unique() {
        let k = mvk();
        let a = k
            .seal(RecordKind::Secrets, "u", "n", b"same")
            .expect("seal");
        let b = k
            .seal(RecordKind::Secrets, "u", "n", b"same")
            .expect("seal");
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn any_tampering_fails_with_integrity() {
        let k = mvk();
        let s = k
            .seal(RecordKind::Secrets, "u1", "n1", b"password")
            .expect("seal");
        let open = |nonce: &[u8], ct: &[u8], kind, user: &str, node: &str| {
            k.open(kind, user, node, nonce, ct)
        };

        let mut nonce = s.nonce;
        nonce[0] ^= 1;
        assert_eq!(
            open(&nonce, &s.ciphertext, RecordKind::Secrets, "u1", "n1").unwrap_err(),
            VaultError::Integrity
        );

        for i in [0, s.ciphertext.len() / 2, s.ciphertext.len() - 1] {
            let mut ct = s.ciphertext.clone();
            ct[i] ^= 0x80;
            assert_eq!(
                open(&s.nonce, &ct, RecordKind::Secrets, "u1", "n1").unwrap_err(),
                VaultError::Integrity
            );
        }
        // swapped node, user, or record type (AAD mismatch)
        assert_eq!(
            open(&s.nonce, &s.ciphertext, RecordKind::Secrets, "u1", "n2").unwrap_err(),
            VaultError::Integrity
        );
        assert_eq!(
            open(&s.nonce, &s.ciphertext, RecordKind::Secrets, "u2", "n1").unwrap_err(),
            VaultError::Integrity
        );
        assert_eq!(
            open(&s.nonce, &s.ciphertext, RecordKind::NodeMeta, "u1", "n1").unwrap_err(),
            VaultError::Integrity
        );
        // truncated
        assert_eq!(
            open(
                &s.nonce,
                &s.ciphertext[..10],
                RecordKind::Secrets,
                "u1",
                "n1"
            )
            .unwrap_err(),
            VaultError::Integrity
        );
        // wrong key
        assert_eq!(
            mvk()
                .open(RecordKind::Secrets, "u1", "n1", &s.nonce, &s.ciphertext)
                .unwrap_err(),
            VaultError::Integrity
        );
    }
}
