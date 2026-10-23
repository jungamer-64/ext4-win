//! Generates the filesystem's authenticated Unicode table for the target build.

use core::error::Error;
use std::{env, path::PathBuf};

/// Fails the build before compiling runtime code if acquisition or generation fails.
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=build.rs");
    for name in ext4_unicode_gen::ENVIRONMENT_INPUTS {
        println!("cargo::rerun-if-env-changed={name}");
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo did not supply OUT_DIR")?);
    let cache = ext4_unicode_gen::cache_directory()?;
    for input in ext4_unicode_gen::generate(&output, &cache)? {
        let input = input
            .to_str()
            .ok_or("UCD cache paths must be valid UTF-8 for Cargo tracking")?;
        println!("cargo::rerun-if-changed={input}");
    }
    Ok(())
}
