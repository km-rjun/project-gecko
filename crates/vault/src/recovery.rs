//! Recovery Key: 256-bit random, displayed as `RK1-` + Crockford Base32 of `RK ‖ SHA-256(RK)[0..2]`
//! in groups of 4 (docs/02 §3.1).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{SecretString, VaultError, secret::Key32};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "RK1-";

pub const INFO_RECOVERY_KEK: &[u8] = b"vault.v1.recovery-kek";
const PAYLOAD_LEN: usize = 34; // 32 key bytes + 2 checksum bytes
const ENCODED_LEN: usize = (PAYLOAD_LEN * 8).div_ceil(5); // 55 chars

/// Raw recovery key bytes, wiped on drop.
pub(crate) struct RecoveryKey(Key32);

impl RecoveryKey {
    pub(crate) fn generate() -> Result<Self, VaultError> {
        Key32::random().map(Self)
    }

    /// Display form shown to the user exactly once.
    pub(crate) fn display(&self) -> SecretString {
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        payload[..32].copy_from_slice(self.0.as_bytes());
        let sum = Sha256::digest(self.0.as_bytes());
        payload[32..].copy_from_slice(&sum[..2]);
        let chars = encode(payload.as_ref());
        let mut out = String::with_capacity(PREFIX.len() + chars.len() + chars.len() / 4);
        out.push_str(PREFIX);
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(*c));
        }
        SecretString::new(out)
    }

    /// Parses a user-entered key: case-insensitive, `-`/whitespace ignored, Crockford aliases accepted.
    pub(crate) fn parse(input: &SecretString) -> Result<Self, VaultError> {
        // Normalise: drop separators/whitespace, uppercase; strip the "RK1" prefix when present.
        let compact: Zeroizing<String> = Zeroizing::new(
            input
                .expose()
                .chars()
                .filter(|c| *c != '-' && !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let body = match compact.strip_prefix("RK1") {
            Some(rest) if rest.len() == ENCODED_LEN => rest,
            _ => compact.as_str(),
        };
        let mut symbols = Zeroizing::new(Vec::with_capacity(ENCODED_LEN));
        for c in body.chars() {
            symbols.push(symbol_value(c).ok_or(VaultError::InvalidRecoveryKey)?);
        }
        if symbols.len() != ENCODED_LEN {
            return Err(VaultError::InvalidRecoveryKey);
        }
        let payload = decode(&symbols)?;
        let key: [u8; 32] = payload[..32]
            .try_into()
            .map_err(|_| VaultError::InvalidRecoveryKey)?;
        let sum = Sha256::digest(key);
        if sum[..2] != payload[32..] {
            return Err(VaultError::InvalidRecoveryKey);
        }
        Ok(Self(Key32::from_array(key)))
    }

    /// RKEK = HKDF-SHA256(salt = rk_salt, IKM = RK, info = "vault.v1.recovery-kek").
    pub(crate) fn kek(&self, salt: &[u8; 16]) -> Result<Key32, VaultError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), self.0.as_bytes());
        let mut out = [0u8; 32];
        hk.expand(INFO_RECOVERY_KEK, &mut out)
            .map_err(|_| VaultError::Kdf)?;
        Ok(Key32::from_array(out))
    }
}

fn symbol_value(c: char) -> Option<u8> {
    let c = c.to_ascii_uppercase();
    let c = match c {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| char::from(a) == c)
        .and_then(|p| u8::try_from(p).ok())
}

fn encode(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(ENCODED_LEN));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1F) as usize]);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize]);
    }
    out
}

fn decode(symbols: &[u8]) -> Result<Zeroizing<[u8; PAYLOAD_LEN]>, VaultError> {
    let mut out = Zeroizing::new([0u8; PAYLOAD_LEN]);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut idx = 0usize;
    for &s in symbols {
        buffer = (buffer << 5) | u32::from(s);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = out.get_mut(idx).ok_or(VaultError::InvalidRecoveryKey)?;
            *byte = ((buffer >> bits) & 0xFF) as u8;
            idx += 1;
            buffer &= (1 << bits) - 1;
        }
    }
    // Trailing bits must be zero padding, and every byte must be present.
    if idx != PAYLOAD_LEN || buffer != 0 {
        return Err(VaultError::InvalidRecoveryKey);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        let rk = RecoveryKey::generate().expect("rng");
        let shown = rk.display();
        let s = shown.expose();
        assert!(s.starts_with("RK1-"));
        let groups: Vec<&str> = s[4..].split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups[..13].iter().all(|g| g.len() == 4));
        assert_eq!(groups[13].len(), 3);
    }

    #[test]
    fn parse_round_trip_and_leniency() {
        let rk = RecoveryKey::generate().expect("rng");
        let shown = rk.display();
        let parsed = RecoveryKey::parse(&shown).expect("parse");
        assert_eq!(parsed.0.as_bytes(), rk.0.as_bytes());
        let sloppy = SecretString::new(format!(
            "  {}  ",
            shown.expose().to_lowercase().replace('-', " ")
        ));
        let parsed2 = RecoveryKey::parse(&sloppy).expect("parse sloppy");
        assert_eq!(parsed2.0.as_bytes(), rk.0.as_bytes());
    }

    #[test]
    fn checksum_catches_typos() {
        let rk = RecoveryKey::generate().expect("rng");
        let shown = rk.display();
        let mut chars: Vec<char> = shown.expose().chars().collect();
        let i = 10;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let typo = SecretString::new(chars.into_iter().collect());
        assert!(RecoveryKey::parse(&typo).is_err());
        assert!(RecoveryKey::parse(&SecretString::new("RK1-ABCD".into())).is_err());
        assert!(RecoveryKey::parse(&SecretString::new("RK1-!!!!".into())).is_err());
    }
}
