use crate::{
    TaskResult,
    driver_load::{DriverLoadSessionId, check_hosted_driver_host},
    process::{require_file, run_checked},
    production::{VerifiedProductionBundle, build_verified_production_bundle},
};
use std::{ffi::OsStr, io, path::Path, process::Command};

/// Performs read-only validation of the dedicated live-driver host contract.
///
/// # Errors
///
/// Returns an error on non-Windows hosts or when the common driver-load preflight, Hyper-V
/// PowerShell, WSL, e2fsprogs, or Driver Verifier configuration is absent.
pub(crate) fn check_live_driver_host(repository_root: &Path) -> TaskResult<()> {
    require_windows_live_host()?;
    check_hosted_driver_host(repository_root)?;
    run_live_vhdx_script(repository_root, "Preflight", None, None)
}

/// Builds one verified production bundle and exercises it only on a new fixed-size VHDX.
///
/// # Errors
///
/// Returns an error for host-contract, release-gate, session-recording, VHDX, WSL, DriverStore,
/// driver operation, dismount, unload, or cleanup failure.
pub(crate) fn verify_live_vhdx(repository_root: &Path) -> TaskResult<()> {
    check_live_driver_host(repository_root)?;
    let bundle = build_verified_production_bundle(repository_root)?;
    let session_id = DriverLoadSessionId::create(repository_root)?;
    run_live_vhdx_script(
        repository_root,
        "Run",
        Some(bundle.as_path()),
        Some(&session_id),
    )?;
    println!("live VHDX driver assurance: PASS");
    println!("session: {}", session_id.as_str());
    Ok(())
}

/// Reconciles an interrupted session after validating its generated identity boundary.
///
/// # Errors
///
/// Returns an error for a malformed identifier, missing or mismatched session evidence, or any
/// unload, package removal, VHDX detach, or cleanup failure.
pub(crate) fn cleanup_live_vhdx_session(
    repository_root: &Path,
    session_id: &OsStr,
) -> TaskResult<()> {
    require_windows_live_host()?;
    let session_id = DriverLoadSessionId::parse(session_id)?;
    run_live_vhdx_script(repository_root, "Cleanup", None, Some(&session_id))
}

/// Rejects live workflows outside the Windows host boundary.
///
/// # Errors
///
/// Returns `Unsupported` on non-Windows hosts.
fn require_windows_live_host() -> TaskResult<()> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "live VHDX validation requires a dedicated elevated Windows host",
        )
        .into())
    }
}

/// Invokes the repository-owned live VHDX script with only generated bundle/session identities.
///
/// # Errors
///
/// Returns an error when the script is absent, PowerShell cannot start, or the requested workflow
/// fails closed.
fn run_live_vhdx_script(
    repository_root: &Path,
    mode: &str,
    bundle: Option<&VerifiedProductionBundle>,
    session_id: Option<&DriverLoadSessionId>,
) -> TaskResult<()> {
    let script = repository_root
        .join("tools")
        .join("xtask")
        .join("live-vhdx.ps1");
    require_file(&script, "live VHDX workflow script")?;
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]);
    command
        .arg(script)
        .arg("-Mode")
        .arg(mode)
        .arg("-RepositoryRoot")
        .arg(repository_root);
    if let Some(bundle) = bundle {
        command.arg("-Bundle").arg(bundle);
    }
    if let Some(session_id) = session_id {
        command.arg("-SessionId").arg(session_id.as_str());
    }
    run_checked(command, &format!("live VHDX {mode} workflow"))
}
