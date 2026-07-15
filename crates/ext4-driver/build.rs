//! Build script for the native ext4 Windows file system driver.

fn main() -> Result<(), wdk_build::ConfigError> {
    const SECURITY_CAPTURE_SOURCE: &str = "native/security_capture.c";

    println!("cargo:rerun-if-changed={SECURITY_CAPTURE_SOURCE}");
    println!("cargo:rustc-link-lib=Cng");

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
        .file(SECURITY_CAPTURE_SOURCE);

    if is_msvc {
        native.flag("/kernel").flag("/W4").flag("/WX");
    }

    native.compile("ext4win_security_capture");
    Ok(())
}
