//! Build script for the native ext4 Windows file system driver.

use core::error::Error;
use std::{ffi::OsString, fs, io, path::PathBuf};

/// Environment variable carrying the one-build production artifact identity.
const ARTIFACT_ID_ENVIRONMENT: &str = "EXT4WIN_ARTIFACT_ID";

/// Sentinel used by ordinary developer builds that cannot pass the production artifact gate.
const UNVERIFIED_ARTIFACT_ID: &str = "00000000000000000000000000000000";

/// Linker-visible symbol that keeps the artifact marker in the final PE image.
const ARTIFACT_ID_SYMBOL: &str = "EXT4WIN_PRODUCTION_ARTIFACT_ID";

fn main() -> Result<(), Box<dyn Error>> {
    const SECURITY_CAPTURE_SOURCE: &str = "native/security_capture.c";
    const DATA_TRANSFER_SOURCE: &str = "native/data_transfer.c";
    const CANCEL_SOURCE: &str = "native/cancel.c";

    println!("cargo:rerun-if-changed={SECURITY_CAPTURE_SOURCE}");
    println!("cargo:rerun-if-changed={DATA_TRANSFER_SOURCE}");
    println!("cargo:rerun-if-changed={CANCEL_SOURCE}");
    println!("cargo:rerun-if-env-changed={ARTIFACT_ID_ENVIRONMENT}");

    let artifact_id = production_artifact_id()?;
    println!("cargo:rustc-env={ARTIFACT_ID_ENVIRONMENT}={artifact_id}");

    let config = wdk_build::Config::from_env_auto()?;
    config.configure_binary_build()?;

    let is_msvc = std::env::var_os("CARGO_CFG_TARGET_ENV").is_some_and(|target| target == "msvc");
    let mut native = cc::Build::new();
    for (name, value) in config.preprocessor_definitions() {
        // MSVC's /kernel switch defines this reserved implementation macro itself.
        if !(is_msvc && name == "_KERNEL_MODE") {
            native.define(&name, value.as_deref());
        }
    }
    native
        .includes(config.include_paths()?)
        .file(SECURITY_CAPTURE_SOURCE)
        .file(DATA_TRANSFER_SOURCE)
        .file(CANCEL_SOURCE);

    if is_msvc {
        native.flag("/kernel").flag("/W4").flag("/WX");
        let map_path = package_link_map_path()?;
        let map_parent = map_path
            .parent()
            .ok_or_else(|| io::Error::other("the ext4win link-map path has no parent directory"))?;
        fs::create_dir_all(map_parent)?;
        println!("cargo:rustc-link-arg=/MAP:{}", map_path.display());
        println!("cargo:rustc-link-arg=/INCLUDE:{ARTIFACT_ID_SYMBOL}");
    }

    native.compile("ext4win_security_capture");
    Ok(())
}

/// Validates the externally supplied artifact identity or selects the fail-closed sentinel.
///
/// # Errors
///
/// Returns an input error when a supplied identity is not exactly 32 nonzero hexadecimal digits.
fn production_artifact_id() -> Result<String, io::Error> {
    let Some(value) = std::env::var_os(ARTIFACT_ID_ENVIRONMENT) else {
        return Ok(UNVERIFIED_ARTIFACT_ID.to_owned());
    };
    let value = value.into_string().map_err(|_: OsString| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ARTIFACT_ID_ENVIRONMENT} is not valid Unicode"),
        )
    })?;
    if value.len() != UNVERIFIED_ARTIFACT_ID.len()
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value == UNVERIFIED_ARTIFACT_ID
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{ARTIFACT_ID_ENVIRONMENT} must be 32 hexadecimal digits and cannot be all zero"
            ),
        ));
    }
    Ok(value)
}

/// Resolves the fixed link-map path consumed by `cargo-wdk` packaging.
///
/// # Errors
///
/// Returns an environment or layout error when Cargo's profile directory cannot be identified.
fn package_link_map_path() -> Result<PathBuf, io::Error> {
    let out_directory =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide OUT_DIR")
        })?);
    let build_directory = out_directory
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .ok_or_else(|| io::Error::other("OUT_DIR is not below Cargo's build directory"))?;
    let profile_directory = build_directory
        .parent()
        .ok_or_else(|| io::Error::other("Cargo's build directory has no profile parent"))?;
    Ok(profile_directory.join("deps").join("ext4win.map"))
}
