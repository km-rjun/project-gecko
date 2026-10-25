use std::net::SocketAddr;

use anyhow::Context;
use clap::{Parser, Subcommand};
use gateway::{
    BRAND_DISPLAY_NAME, audit, bootstrap,
    config::{Config, LogFormat},
    db, http,
    state::{AppState, Settings},
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "gateway",
    version,
    about = "Remote access gateway",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    config: Config,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit log maintenance.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
}

#[derive(Debug, Subcommand)]
enum AuditAction {
    /// Recompute the audit hash chain; exits non-zero on the first mismatch.
    Verify {
        #[arg(long, env = "GATEWAY_DATA_DIR", default_value = "./data")]
        data_dir: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Audit {
            action: AuditAction::Verify { data_dir },
        }) => verify(&data_dir).await,
        None => serve(cli.config).await,
    }
}

async fn verify(data_dir: &std::path::Path) -> anyhow::Result<()> {
    let pool = db::open(data_dir).await?;
    let report = audit::verify(&pool).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.ok {
        Ok(())
    } else {
        std::process::exit(2)
    }
}

async fn serve(config: Config) -> anyhow::Result<()> {
    init_tracing(&config)?;
    config.validate()?;
    harden_process();

    let pool = db::open(&config.data_dir).await?;
    let state = AppState::new(
        pool,
        Settings::from_config(&config),
        config.argon2_max_concurrent,
    );
    bootstrap::init(&state).await.context("bootstrap")?;
    let housekeeping = http::spawn_housekeeping(state.clone());

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    tracing::info!(
        product = BRAND_DISPLAY_NAME,
        listen = %config.listen,
        public_origin = %state.settings.public_origin,
        tls_mode = ?config.tls_mode,
        "gateway listening"
    );

    axum::serve(
        listener,
        http::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;
    housekeeping.abort();
    tracing::info!("gateway stopped");
    Ok(())
}

/// Disables core dumps so key material cannot end up on disk after a crash (docs/02 §5 rule 7).
fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // Files created by the gateway (db, -wal, -shm, keys) are private to the service user.
        rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
        use rustix::process::{Resource, Rlimit, setrlimit};
        if let Err(e) = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        ) {
            tracing::warn!(error = %e, "could not disable core dumps (RLIMIT_CORE)");
        }
        if let Err(e) =
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        {
            tracing::warn!(error = %e, "could not set PR_SET_DUMPABLE=0");
        }
    }
}

fn init_tracing(config: &Config) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.log).context("invalid GATEWAY_LOG filter")?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match config.log_format {
        LogFormat::Text => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %e, "cannot listen for Ctrl+C");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "cannot listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
    tracing::info!("shutdown signal received");
}
