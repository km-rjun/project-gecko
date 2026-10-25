//! Shared application state.

use std::{path::PathBuf, sync::Arc, time::Duration};

use sqlx::SqlitePool;
use tokio::sync::{Mutex, Semaphore};
use vault::KdfParams;

use crate::{
    config::{Config, TlsMode},
    hub::Hub,
    keyring::Keyring,
    ratelimit::Limiters,
};

/// Settings derived from [`Config`] that request handlers need.
#[derive(Debug, Clone)]
pub struct Settings {
    pub public_origin: String,
    pub secure_cookies: bool,
    pub session_absolute: Duration,
    pub session_idle: Duration,
    pub vault_idle_lock: Duration,
    pub data_dir: PathBuf,
    pub kdf: KdfParams,
}

impl Settings {
    pub fn from_config(c: &Config) -> Self {
        Self {
            public_origin: c.effective_public_origin(),
            secure_cookies: c.tls_mode != TlsMode::PlaintextDev,
            session_absolute: c.session_absolute,
            session_idle: c.session_idle,
            vault_idle_lock: c.vault_idle_lock,
            data_dir: c.data_dir.clone(),
            kdf: KdfParams::DEFAULT,
        }
    }
}

#[derive(Debug)]
pub struct Inner {
    pub db: SqlitePool,
    pub settings: Settings,
    pub keyring: Keyring,
    pub hub: Hub,
    pub limits: Limiters,
    pub argon: Semaphore,
    /// Serialises audit appends so the hash chain stays linear.
    pub audit_lock: Mutex<()>,
    /// SHA-256 of the first-run bootstrap token while no user exists.
    pub bootstrap: std::sync::Mutex<Option<[u8; 32]>>,
}

#[derive(Debug, Clone)]
pub struct AppState(pub Arc<Inner>);

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(db: SqlitePool, settings: Settings, argon_concurrency: usize) -> Self {
        Self(Arc::new(Inner {
            keyring: Keyring::new(settings.vault_idle_lock),
            hub: Hub::default(),
            db,
            settings,
            limits: Limiters::default(),
            argon: Semaphore::new(argon_concurrency),
            audit_lock: Mutex::new(()),
            bootstrap: std::sync::Mutex::new(None),
        }))
    }

    /// Runs a CPU/memory-heavy vault operation (Argon2id) on the blocking pool, bounded by the semaphore.
    pub async fn run_kdf<T, F>(&self, f: F) -> Result<T, crate::error::ApiError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let _permit = self
            .argon
            .acquire()
            .await
            .map_err(crate::error::ApiError::internal)?;
        tokio::task::spawn_blocking(f)
            .await
            .map_err(crate::error::ApiError::internal)
    }
}
