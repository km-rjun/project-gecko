//! Browser wire framing and protocol engines (SSH, VNC, RDP).
//!
//! Specification: docs/03-wire-protocol-spec.md. No knowledge of HTTP, users or the database.
#![forbid(unsafe_code)]

pub mod dial;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod wire;

/// WebSocket subprotocol negotiated by the workspace socket.
pub const WORKSPACE_SUBPROTOCOL: &str = "workspace.v1";
