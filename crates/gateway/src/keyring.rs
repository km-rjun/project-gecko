//! In-memory keyring: session id → unwrapped MVK. Never persisted; a restart locks every vault.

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
    entries: Mutex<HashMap<String, Entry>>,
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

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn insert(&self, session: &str, user_id: &str, mvk: Mvk) {
        self.lock().insert(
            session.to_owned(),
            Entry {
                user_id: user_id.to_owned(),
                mvk: Arc::new(mvk),
                last_activity: Instant::now(),
            },
        );
    }

    /// Current vault state; enforces the idle limit.
    pub fn state(&self, session: &str) -> VaultState {
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
    pub fn touch(&self, session: &str) {
        if let Some(e) = self.lock().get_mut(session) {
            e.last_activity = Instant::now();
        }
    }

    /// Seconds until idle lock, if unlocked.
    pub fn idle_lock_in(&self, session: &str) -> Option<u64> {
        self.lock().get(session).map(|e| {
            self.idle_limit
                .saturating_sub(e.last_activity.elapsed())
                .as_secs()
        })
    }

    /// Drops one session's MVK. Returns whether it was unlocked.
    pub fn remove(&self, session: &str) -> bool {
        self.lock().remove(session).is_some()
    }

    /// Drops every MVK of `user_id`, optionally keeping one session.
    pub fn remove_user(&self, user_id: &str, keep: Option<&str>) {
        self.lock()
            .retain(|k, e| e.user_id != user_id || Some(k.as_str()) == keep);
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
