//! In-memory keyring: session token hash → unwrapped MVK. Never persisted; a restart locks every vault.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use vault::Mvk;

struct Entry {
    user_id: String,
    mvk: Arc<Mvk>,
    last_activity: Instant,
}

/// Vault state of one session.
#[derive(Debug)]
pub enum VaultState {
    Unlocked(Arc<Mvk>),
    Locked,
    /// Was unlocked but exceeded the idle limit; the entry has just been removed.
    IdleLocked,
}

pub struct Keyring {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
    idle_limit: Duration,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keyring([REDACTED])")
    }
}

impl Keyring {
    pub fn new(idle_limit: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            idle_limit,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn insert(&self, session: [u8; 32], user_id: &str, mvk: Mvk) {
        self.lock().insert(
            session,
            Entry {
                user_id: user_id.to_owned(),
                mvk: Arc::new(mvk),
                last_activity: Instant::now(),
            },
        );
    }

    /// Moves an entry to a rotated session token.
    pub fn rekey(&self, old: &[u8; 32], new: [u8; 32]) {
        let mut map = self.lock();
        if let Some(entry) = map.remove(old) {
            map.insert(new, entry);
        }
    }

    /// Current vault state; enforces the idle limit.
    pub fn state(&self, session: &[u8; 32]) -> VaultState {
        let mut map = self.lock();
        match map.get(session) {
            None => VaultState::Locked,
            Some(e) if e.last_activity.elapsed() > self.idle_limit => {
                map.remove(session);
                VaultState::IdleLocked
            }
            Some(e) => VaultState::Unlocked(Arc::clone(&e.mvk)),
        }
    }

    /// Records user activity (mutating request or session input).
    pub fn touch(&self, session: &[u8; 32]) {
        if let Some(e) = self.lock().get_mut(session) {
            e.last_activity = Instant::now();
        }
    }

    /// Seconds until idle lock, if unlocked.
    pub fn idle_lock_in(&self, session: &[u8; 32]) -> Option<u64> {
        self.lock().get(session).map(|e| {
            self.idle_limit
                .saturating_sub(e.last_activity.elapsed())
                .as_secs()
        })
    }

    /// Drops one session's MVK. Returns whether it was unlocked.
    pub fn remove(&self, session: &[u8; 32]) -> bool {
        self.lock().remove(session).is_some()
    }

    /// Drops every MVK of `user_id`, optionally keeping one session.
    pub fn remove_user(&self, user_id: &str, keep: Option<&[u8; 32]>) {
        self.lock()
            .retain(|k, e| e.user_id != user_id || Some(k) == keep);
    }

    /// Removes idle entries; returns their user ids (for audit).
    pub fn sweep(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.lock().retain(|_, e| {
            let keep = e.last_activity.elapsed() <= self.idle_limit;
            if !keep {
                out.push(e.user_id.clone());
            }
            keep
        });
        out
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
