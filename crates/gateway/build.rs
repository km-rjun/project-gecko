//! Reads the product display name from `branding.toml` (the single rename point).

use std::{env, fs, path::PathBuf};

#[derive(serde::Deserialize)]
struct Branding {
    display_name: String,
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("../../branding.toml");
    println!("cargo:rerun-if-changed={}", path.display());
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let branding: Branding =
        toml::from_str(&raw).unwrap_or_else(|e| panic!("invalid {}: {e}", path.display()));
    let name = branding.display_name.trim();
    assert!(
        !name.is_empty(),
        "branding.toml: display_name must not be empty"
    );
    println!("cargo:rustc-env=BRAND_DISPLAY_NAME={name}");
}
