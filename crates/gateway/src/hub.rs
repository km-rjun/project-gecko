//! Registry of live workspace sockets per login session, so logout, revocation and
//! "Lock & disconnect all" can close them.

use std::{
    collections::HashMap,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio_util::sync::CancellationToken;

/// Maximum workspace sockets per login session (docs/02 §7).
pub const MAX_SOCKETS_PER_SESSION: usize = 8;

type Map = HashMap<String, Vec<(u64, CancellationToken)>>;

#[derive(Debug, Default)]
pub struct Hub {
    sockets: Mutex<Map>,
    next: AtomicU64,
}

impl Hub {
    fn lock(&self) -> MutexGuard<'_, Map> {
        self.sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers a socket; `None` when the session already has the maximum number of sockets.
    pub fn register(&self, session_id: &str) -> Option<(u64, CancellationToken)> {
        let mut map = self.lock();
        let list = map.entry(session_id.to_owned()).or_default();
        if list.len() >= MAX_SOCKETS_PER_SESSION {
            return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        list.push((id, cancel.clone()));
        Some((id, cancel))
    }

    pub fn unregister(&self, session_id: &str, id: u64) {
        let mut map = self.lock();
        if let Some(list) = map.get_mut(session_id) {
            list.retain(|(i, _)| *i != id);
            if list.is_empty() {
                map.remove(session_id);
            }
        }
    }

    /// Closes every socket of a session.
    pub fn close_session(&self, session_id: &str) {
        if let Some(list) = self.lock().remove(session_id) {
            for (_, c) in list {
                c.cancel();
            }
        }
    }

    pub fn count(&self, session_id: &str) -> usize {
        self.lock().get(session_id).map_or(0, Vec::len)
    }
}
