//! A real Linux executable owns Linux-local mutations even when the orchestrator runs on Windows.
use crate::{
    TaskResult,
    process::{cargo_command, require_file, run_checked},
};
use std::path::{Path, PathBuf};

/// Builds a current-source fixture executable for the selected execution host.
/// # Errors
/// Returns toolchain, target, build or missing-executable errors. Windows requires the pinned
/// toolchain's x86_64-unknown-linux-musl target; the linked helper has no Linux runtime dependency.
pub(crate) fn executable(root: &Path) -> TaskResult<PathBuf> {
    let command = cargo_command(root, &["build", "--locked", "-p", "ext4-fixture"]);
    #[cfg(windows)]
    let command = {
        let mut command = command;
        command.args(["--target", "x86_64-unknown-linux-musl"]);
        command
    };
    run_checked(command, "native Linux fixture build")?;
    #[cfg(windows)]
    let path = root.join("target/x86_64-unknown-linux-musl/debug/ext4-fixture");
    #[cfg(not(windows))]
    let path = root.join("target/debug/ext4-fixture");
    require_file(&path, "native Linux fixture executable")?;
    Ok(path)
}
