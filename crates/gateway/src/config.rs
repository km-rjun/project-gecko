//! Runtime configuration. Precedence: CLI flags > environment variables > defaults.
//! (`gateway.toml` file support arrives with production packaging in Checkpoint 7.)

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};

/// TLS termination mode (docs/01 §3.4, decision D-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TlsMode {
    /// Certificate and key files (`GATEWAY_TLS_CERT`, `GATEWAY_TLS_KEY`). Checkpoint 7.
    Files,
    /// Generated self-signed certificate persisted in the data dir. Checkpoint 7.
    SelfSigned,
    /// Plain HTTP. Only permitted on a loopback listen address.
    PlaintextDev,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Parser)]
#[command(name = "gateway", version, about = "Remote access gateway")]
pub struct Config {
    /// Socket address to listen on.
    #[arg(long, env = "GATEWAY_LISTEN", default_value = "127.0.0.1:8443")]
    pub listen: SocketAddr,

    /// TLS mode.
    #[arg(long, env = "GATEWAY_TLS_MODE", value_enum, default_value_t = TlsMode::SelfSigned)]
    pub tls_mode: TlsMode,

    /// Directory for gateway.db, the runner CA and generated certificates.
    #[arg(long, env = "GATEWAY_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// `tracing` env-filter directive.
    #[arg(long, env = "GATEWAY_LOG", default_value = "info")]
    pub log: String,

    /// Log output format.
    #[arg(long, env = "GATEWAY_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

/// Configuration rejected at startup.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("plaintext-dev mode is only allowed on a loopback address, got {0}")]
    PlaintextNotLoopback(SocketAddr),
    #[error(
        "TLS mode {0:?} is not implemented yet (Checkpoint 7); use --tls-mode plaintext-dev on 127.0.0.1 for development"
    )]
    TlsModeNotImplemented(TlsMode),
}

impl Config {
    /// Enforces startup invariants. Called before any listener is bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.tls_mode {
            TlsMode::PlaintextDev if !self.listen.ip().is_loopback() => {
                Err(ConfigError::PlaintextNotLoopback(self.listen))
            }
            TlsMode::PlaintextDev => Ok(()),
            mode @ (TlsMode::Files | TlsMode::SelfSigned) => {
                Err(ConfigError::TlsModeNotImplemented(mode))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> Config {
        let mut argv = vec!["gateway"];
        argv.extend_from_slice(args);
        Config::try_parse_from(argv).expect("parse")
    }

    #[test]
    fn plaintext_on_loopback_is_allowed() {
        let c = cfg(&["--tls-mode", "plaintext-dev", "--listen", "127.0.0.1:8443"]);
        assert_eq!(c.validate(), Ok(()));
        let c6 = cfg(&["--tls-mode", "plaintext-dev", "--listen", "[::1]:8443"]);
        assert_eq!(c6.validate(), Ok(()));
    }

    #[test]
    fn plaintext_on_public_address_is_rejected() {
        let c = cfg(&["--tls-mode", "plaintext-dev", "--listen", "0.0.0.0:8443"]);
        assert!(matches!(
            c.validate(),
            Err(ConfigError::PlaintextNotLoopback(_))
        ));
    }

    #[test]
    fn tls_modes_not_yet_available() {
        let c = cfg(&[]);
        assert_eq!(c.tls_mode, TlsMode::SelfSigned);
        assert_eq!(
            c.validate(),
            Err(ConfigError::TlsModeNotImplemented(TlsMode::SelfSigned))
        );
    }
}
