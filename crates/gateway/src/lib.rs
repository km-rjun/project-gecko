//! Gateway library: configuration, HTTP router and server lifecycle.
//!
//! Architecture: docs/01-architecture-and-prior-art.md.
#![deny(unsafe_code)]

pub mod config;
pub mod http;

/// Product display name from `branding.toml`, injected at build time.
pub const BRAND_DISPLAY_NAME: &str = env!("BRAND_DISPLAY_NAME");
