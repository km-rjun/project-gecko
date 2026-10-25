//! Browser wire framing and protocol engines (SSH, VNC, RDP).
//!
//! Specification: docs/03-wire-protocol-spec.md. Wire codec and SSH land in Checkpoint 3,
//! VNC in Checkpoint 5, RDP in Checkpoint 6. No knowledge of HTTP, users or the database.
#![forbid(unsafe_code)]

/// WebSocket subprotocol negotiated by the workspace socket.
pub const WORKSPACE_SUBPROTOCOL: &str = "workspace.v1";
