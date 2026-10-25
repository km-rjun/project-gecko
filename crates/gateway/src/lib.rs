//! Gateway library: configuration, persistence, auth, vault keyring, audit and HTTP API.
//!
//! Architecture: docs/01-architecture-and-prior-art.md · Security: docs/02-security-and-vault-spec.md.
#![deny(unsafe_code)]

pub mod api;
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod db;
pub mod error;
pub mod extract;
pub mod http;
pub mod keyring;
pub mod ratelimit;
pub mod security;
pub mod session;
pub mod state;
pub mod util;

/// Product display name from `branding.toml`, injected at build time.
pub const BRAND_DISPLAY_NAME: &str = env!("BRAND_DISPLAY_NAME");
