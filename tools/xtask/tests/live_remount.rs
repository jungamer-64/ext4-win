//! Exercises the live remount requester's process contract on a local file.

#![cfg(windows)]

use std::{fs, io, path::Path, process::Command};

/// # Errors
/// Returns fixture read, requester launch, or diagnostic decoding errors.
/// # Panics
/// Fails if the requester changes the file bytes or reports progress past a failed open.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify the actual requester executable after fallible process execution"
)]
fn remount_requester_separates_payload_and_progress() -> io::Result<()> {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("read-remount-payload")
        .arg(&file)
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, fs::read(&file)?);
    let stderr = String::from_utf8(output.stderr).map_err(io::Error::other)?;
    assert!(stderr.lines().eq([
        "live remount requester: opening file",
        "live remount requester: fresh open completed",
        "live remount requester: payload read completed",
        "live remount requester: closing fresh handle",
        "live remount requester: fresh handle closed",
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("read-remount-payload")
        .arg(file.join("unreachable-child"))
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).map_err(io::Error::other)?;
    assert!(stderr.starts_with("live remount requester: opening file"));
    assert!(stderr.contains("xtask failed:"));
    assert!(!stderr.contains("fresh open completed"));
    Ok(())
}
