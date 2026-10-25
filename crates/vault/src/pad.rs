//! Length-hiding padding: `u32 BE length ‖ payload ‖ zeros` up to a bucket multiple (docs/02 §3.1).

use zeroize::Zeroizing;

use crate::{SecretBytes, VaultError};

/// Bucket for node metadata, host identities and sealed audit details.
pub const BUCKET_META: usize = 256;
/// Bucket for credential bundles.
pub const BUCKET_SECRETS: usize = 512;

/// Pads `payload` to the next multiple of `bucket` (at least one bucket).
pub fn pad(payload: &[u8], bucket: usize) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let len =
        u32::try_from(payload.len()).map_err(|_| VaultError::Malformed("payload too large"))?;
    let needed = payload.len() + 4;
    let total = needed.div_ceil(bucket).max(1) * bucket;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(total, 0);
    Ok(out)
}

/// Removes padding, validating the declared length.
pub fn unpad(padded: &SecretBytes) -> Result<SecretBytes, VaultError> {
    let bytes = padded.expose();
    let (head, rest) = bytes
        .split_at_checked(4)
        .ok_or(VaultError::Malformed("padding header"))?;
    let len = u32::from_be_bytes(
        head.try_into()
            .map_err(|_| VaultError::Malformed("padding header"))?,
    ) as usize;
    let payload = rest
        .get(..len)
        .ok_or(VaultError::Malformed("padding length"))?;
    Ok(SecretBytes::new(payload.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_bucket_and_round_trips() {
        for len in [0usize, 1, 251, 252, 253, 600] {
            let payload = vec![0xAB; len];
            let padded = pad(&payload, BUCKET_META).expect("pad");
            assert_eq!(padded.len() % BUCKET_META, 0);
            let back = unpad(&SecretBytes::new(padded.to_vec())).expect("unpad");
            assert_eq!(back.expose(), payload.as_slice());
        }
        assert_eq!(pad(&[0; 252], BUCKET_META).expect("pad").len(), 256);
        assert_eq!(pad(&[0; 253], BUCKET_META).expect("pad").len(), 512);
    }

    #[test]
    fn rejects_bad_length() {
        let mut bad = vec![0u8; 256];
        bad[..4].copy_from_slice(&1000u32.to_be_bytes());
        assert!(unpad(&SecretBytes::new(bad)).is_err());
        assert!(unpad(&SecretBytes::new(vec![1, 2])).is_err());
    }
}
