//! Log hygiene shared by the binary and the tests.

use tracing::{Level, Metadata};

/// Crates whose TRACE output contains raw payloads (WebSocket messages carry keystrokes and
/// ephemeral credentials; SSH packets carry terminal data).
const PAYLOAD_TARGETS: &[&str] = &["tungstenite", "tokio_tungstenite", "russh"];

/// `true` if an event may be logged. TRACE from payload-carrying crates is always dropped,
/// whatever `GATEWAY_LOG` says.
pub fn allowed(meta: &Metadata<'_>) -> bool {
    !(*meta.level() == Level::TRACE
        && PAYLOAD_TARGETS.iter().any(|t| {
            meta.target() == *t
                || meta
                    .target()
                    .strip_prefix(t)
                    .is_some_and(|r| r.starts_with("::"))
        }))
}

/// Per-layer filter applying [`allowed`].
pub fn payload_guard() -> tracing_subscriber::filter::FilterFn<fn(&Metadata<'_>) -> bool> {
    tracing_subscriber::filter::FilterFn::new(allowed as fn(&Metadata<'_>) -> bool)
}
