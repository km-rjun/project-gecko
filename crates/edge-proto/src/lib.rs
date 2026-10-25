//! Shared message types for the edge-runner tunnel (enrollment, control stream, dial requests).
//!
//! Specification: docs/05-edge-runner-pool-spec.md. Implemented in Checkpoint 9.
#![forbid(unsafe_code)]

/// ALPN identifier for the mTLS runner tunnel.
pub const ALPN_TUNNEL: &[u8] = b"edge-runner/1";
/// ALPN identifier for runner enrollment.
pub const ALPN_ENROLL: &[u8] = b"edge-runner-enroll/1";
