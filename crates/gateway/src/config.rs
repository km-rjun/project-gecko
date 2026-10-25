//! Runtime configuration. Precedence: CLI flags > environment variables > defaults.
//! (`gateway.toml` file support arrives with production packaging, decision D-033.)

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Parser, ValueEnum};

/// TLS termination mode (docs/01 §3.4, decision D-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TlsMode {
    /// Certificate and key files (`GATEWAY_TLS_CERT`, `GATEWAY_TLS_KEY`). Not implemented yet.
    Files,
    /// Generated self-signed certificate persisted in the data dir. Not implemented yet.
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

    /// Exact origin browsers use to reach the gateway (e.g. https://remote.example.com).
    /// Defaults to http://<listen> in plaintext-dev mode.
    #[arg(long, env = "GATEWAY_PUBLIC_ORIGIN")]
    pub public_origin: Option<String>,

    /// Directory for gateway.db, the runner CA and generated certificates.
    #[arg(long, env = "GATEWAY_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Vault idle auto-lock (e.g. 15m).
    #[arg(long, env = "GATEWAY_VAULT_IDLE_LOCK", default_value = "15m", value_parser = parse_duration)]
    pub vault_idle_lock: Duration,

    /// Absolute session lifetime.
    #[arg(long, env = "GATEWAY_SESSION_ABSOLUTE", default_value = "8h", value_parser = parse_duration)]
    pub session_absolute: Duration,

    /// Session idle timeout.
    #[arg(long, env = "GATEWAY_SESSION_IDLE", default_value = "30m", value_parser = parse_duration)]
    pub session_idle: Duration,

    /// Maximum concurrent Argon2id derivations (each uses 64 MiB).
    #[arg(long, env = "GATEWAY_ARGON2_MAX_CONCURRENT", default_value_t = 4)]
    pub argon2_max_concurrent: usize,

    /// `tracing` env-filter directive.
    #[arg(long, env = "GATEWAY_LOG", default_value = "info")]
    pub log: String,

    /// Log output format.
    #[arg(long, env = "GATEWAY_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

/// Parses `90s`, `15m`, `8h` or a plain number of seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration: {s}"))?;
    if n == 0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_secs(n * mult))
}

/// Configuration rejected at startup.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("plaintext-dev mode is only allowed on a loopback address, got {0}")]
    PlaintextNotLoopback(SocketAddr),
    #[error(
        "TLS mode {0:?} is not implemented yet; use --tls-mode plaintext-dev on 127.0.0.1 for development"
    )]
    TlsModeNotImplemented(TlsMode),
    #[error("public origin must look like scheme://host[:port] without a path, got {0:?}")]
    InvalidOrigin(String),
    #[error("argon2 concurrency must be between 1 and 64")]
    InvalidArgonConcurrency,
}

impl Config {
    /// Enforces startup invariants. Called before any listener is bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.tls_mode {
            TlsMode::PlaintextDev if !self.listen.ip().is_loopback() => {
                return Err(ConfigError::PlaintextNotLoopback(self.listen));
            }
            TlsMode::PlaintextDev => {}
            mode @ (TlsMode::Files | TlsMode::SelfSigned) => {
                return Err(ConfigError::TlsModeNotImplemented(mode));
            }
        }
        let origin = self.effective_public_origin();
        let valid = (origin.starts_with("http://") || origin.starts_with("https://"))
            && !origin
                .trim_end_matches('/')
                .split("://")
                .nth(1)
                .unwrap_or("")
                .contains('/')
            && !origin.ends_with('/');
        if !valid {
            return Err(ConfigError::InvalidOrigin(origin));
        }
        if !(1..=64).contains(&self.argon2_max_concurrent) {
            return Err(ConfigError::InvalidArgonConcurrency);
        }
        Ok(())
    }

    /// Origin required on mutating requests and WebSocket upgrades.
    pub fn effective_public_origin(&self) -> String {
        self.public_origin.clone().unwrap_or_else(|| {
            let scheme = if self.tls_mode == TlsMode::PlaintextDev {
                "http"
            } else {
                "https"
            };
            format!("{scheme}://{}", self.listen)
        })
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
        assert_eq!(c.effective_public_origin(), "http://127.0.0.1:8443");
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

    #[test]
    fn origin_validation() {
        let ok = cfg(&[
            "--tls-mode",
            "plaintext-dev",
            "--public-origin",
            "http://127.0.0.1:5173",
        ]);
        assert_eq!(ok.validate(), Ok(()));
        for bad in ["127.0.0.1:5173", "http://host/path", "http://host/"] {
            let c = cfg(&["--tls-mode", "plaintext-dev", "--public-origin", bad]);
            assert!(
                matches!(c.validate(), Err(ConfigError::InvalidOrigin(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("8h"), Ok(Duration::from_secs(28800)));
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
