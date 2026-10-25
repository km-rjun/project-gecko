//! Additional authenticated data: unambiguous length-prefixed concatenation (docs/02 §3.2).

/// AAD labels. Each record type has its own label, so a ciphertext never opens as another type.
pub const LABEL_MVK_WRAP: &str = "vault.v1.mvk-wrap";
pub const LABEL_SECRET: &str = "vault.v1.secret";
pub const LABEL_NODE_META: &str = "vault.v1.node-meta";
pub const LABEL_HOST_IDENTITY: &str = "vault.v1.host-identity";
pub const LABEL_AUDIT: &str = "vault.v1.audit";

/// Encodes each field as `u16 big-endian length ‖ bytes`.
///
/// # Panics
/// If a field exceeds `u16::MAX` bytes (only fixed, short identifiers are ever passed).
pub fn encode(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 2).sum());
    for field in fields {
        let len = u16::try_from(field.len()).expect("AAD field longer than 65535 bytes");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// AAD for a record owned by `user_id` and identified by `record_id`.
pub fn record(label: &str, user_id: &str, record_id: &str) -> Vec<u8> {
    encode(&[label.as_bytes(), user_id.as_bytes(), record_id.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_prevents_ambiguity() {
        assert_ne!(encode(&[b"ab", b"c"]), encode(&[b"a", b"bc"]));
        assert_eq!(encode(&[b"ab"]), vec![0, 2, b'a', b'b']);
    }
}
