//! First-run bootstrap token (decision D-024).

use std::path::Path;

use subtle::ConstantTimeEq;

use crate::{state::AppState, util::token_hash};

pub const TOKEN_FILE: &str = "bootstrap-token";

/// When no user exists: load or create the bootstrap token, write it to `<data_dir>/bootstrap-token`
/// (0600) and print it to stdout. Returns whether setup is pending.
pub async fn init(state: &AppState) -> anyhow::Result<bool> {
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    let path = state.settings.data_dir.join(TOKEN_FILE);
    if users > 0 {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        return Ok(false);
    }
    let token = match std::fs::read_to_string(&path) {
        Ok(existing) if existing.trim().len() >= 32 => {
            zeroize::Zeroizing::new(existing.trim().to_owned())
        }
        _ => {
            let t = crate::util::random_token()?;
            write_private(&path, t.as_bytes())?;
            t
        }
    };
    *state
        .bootstrap
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token_hash(&token));
    println!(
        "\n  First-run setup required. Bootstrap token (also in {}):\n\n    {}\n",
        path.display(),
        token.as_str()
    );
    Ok(true)
}

fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

/// Constant-time check of a submitted bootstrap token.
pub fn check(state: &AppState, submitted: &str) -> bool {
    let guard = state
        .bootstrap
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .as_ref()
        .is_some_and(|expected| bool::from(token_hash(submitted).ct_eq(expected)))
}

/// Consumes the bootstrap token after the first admin exists.
pub fn consume(state: &AppState) {
    *state
        .bootstrap
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let path = state.settings.data_dir.join(TOKEN_FILE);
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(error = %e, "could not delete bootstrap token file");
    }
}
