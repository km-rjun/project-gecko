//! SQLite pool and migrations.

use std::{path::Path, str::FromStr, time::Duration};

use anyhow::Context;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

pub const DB_FILE: &str = "gateway.db";

/// Opens (creating if needed) `<data_dir>/gateway.db` and applies migrations.
pub async fn open(data_dir: &Path) -> anyhow::Result<SqlitePool> {
    ensure_private_dir(data_dir)?;
    let path = data_dir.join(DB_FILE);
    let options = SqliteConnectOptions::from_str("sqlite://")?
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        // Freed pages are overwritten with zeros so replaced ciphertext does not linger.
        .pragma("secure_delete", "ON");
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("migrations")?;
    restrict_file(&path)?;
    Ok(pool)
}

/// Creates `dir` with mode 0700 (Unix).
pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Sets mode 0600 on a file (Unix).
pub fn restrict_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
