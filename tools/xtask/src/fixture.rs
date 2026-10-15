//! A real Linux executable owns Linux-local mutations even when the orchestrator runs on Windows.
use crate::{
    TaskResult,
    process::{cargo_command, require_file, run_checked_output},
};
use std::{
    io,
    path::{Path, PathBuf},
};

/// Builds a current-source fixture executable for the selected execution host.
/// # Errors
/// Returns toolchain, target, build or missing-executable errors. Windows requires the pinned
/// toolchain's x86_64-unknown-linux-musl target; the linked helper has no Linux runtime dependency.
pub(crate) fn executable(root: &Path) -> TaskResult<PathBuf> {
    let command = cargo_command(
        root,
        &[
            "build",
            "--locked",
            "-p",
            "ext4-fixture",
            "--message-format=json",
        ],
    );
    #[cfg(windows)]
    let command = {
        let mut command = command;
        command.args(["--target", "x86_64-unknown-linux-musl"]);
        command
    };
    let output = run_checked_output(command, "native Linux fixture build")?;
    let path = built_executable(&output.stdout)?;
    require_file(&path, "native Linux fixture executable")?;
    Ok(path)
}

/// Resolves the sole executable reported by this Cargo invocation.
/// # Errors
/// Rejects malformed output or an absent/ambiguous artifact receipt.
fn built_executable(stdout: &[u8]) -> TaskResult<PathBuf> {
    let mut executable = None;
    for line in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: serde_json::Value = serde_json::from_slice(line)?;
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
            || message
                .pointer("/target/name")
                .and_then(serde_json::Value::as_str)
                != Some("ext4-fixture")
        {
            continue;
        }
        let Some(path) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if executable.replace(PathBuf::from(path)).is_some() {
            return Err(
                io::Error::other("Cargo emitted multiple Linux fixture executables").into(),
            );
        }
    }
    executable.ok_or_else(|| io::Error::other("Cargo omitted its Linux fixture executable").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Errors
    /// Returns a rejected valid artifact receipt.
    /// # Panics
    /// Fails if stale inferred paths or ambiguous Cargo output can select a fixture executable.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions compare independently supplied Cargo output with the selected artifact path"
    )]
    fn cargo_fixture_receipt_requires_one_executable() -> TaskResult<()> {
        let output = br#"{"reason":"compiler-artifact","target":{"name":"ext4-fixture"},"executable":"/actual/fixture"}"#;
        assert_eq!(built_executable(output)?, PathBuf::from("/actual/fixture"));
        assert!(built_executable(b"{bad}").is_err());
        assert!(built_executable(br#"{"reason":"build-finished","success":true}"#).is_err());
        let duplicate = [output.as_slice(), b"\n", output.as_slice()].concat();
        assert!(built_executable(&duplicate).is_err());
        Ok(())
    }
}
