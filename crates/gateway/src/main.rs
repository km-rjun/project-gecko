use anyhow::Context;
use clap::Parser;
use gateway::{
    BRAND_DISPLAY_NAME,
    config::{Config, LogFormat},
    http,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    init_tracing(&config)?;
    config.validate()?;

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    tracing::info!(
        product = BRAND_DISPLAY_NAME,
        listen = %config.listen,
        tls_mode = ?config.tls_mode,
        "gateway listening"
    );

    axum::serve(listener, http::router())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    tracing::info!("gateway stopped");
    Ok(())
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
