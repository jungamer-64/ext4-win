//! Build script for the native ext4 Windows file system driver.

fn main() -> Result<(), wdk_build::ConfigError> {
    println!("cargo:rustc-link-lib=Cng");
    wdk_build::configure_wdk_binary_build()
}
