//! Exercises the actual read-only SetupAPI worker process without installing a driver.

#[cfg(windows)]
use std::{io, process::Command};

/// Worker failures carry native diagnostics rather than a successful path observation.
/// # Errors
/// Returns worker launch or native diagnostic decoding failures.
/// # Panics
/// Fails if malformed or absent OEM identities produce successful JSON observations.
#[cfg(windows)]
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify the actual worker executable's protocol after fallible process execution"
)]
fn driver_store_worker_rejects_unresolved_identity() -> io::Result<()> {
    for (oem, diagnostic) in [
        ("oem-not-a-number.inf", "invalid OEM INF name"),
        ("oem4294967295.inf", "xtask failed:"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["resolve-driver-store-image", oem])
            .output()?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).map_err(io::Error::other)?;
        assert!(stderr.contains(diagnostic), "{stderr}");
        assert!(!stderr.contains("usage:"), "{stderr}");
    }
    Ok(())
}
