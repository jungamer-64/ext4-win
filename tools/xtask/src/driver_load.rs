use crate::{
    TaskResult,
    process::{require_file, run_checked},
    production::{VerifiedProductionBundle, build_verified_production_bundle},
};
use core::fmt::Write as _;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    io,
    path::Path,
    process::{self as host_process, Command},
    time::{SystemTime, UNIX_EPOCH},
};

/// Generated identity of one recoverable DriverStore/service lifecycle session.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DriverLoadSessionId(String);

impl DriverLoadSessionId {
    /// Creates a process- and instant-bound identifier in the driver-load identity domain.
    ///
    /// # Errors
    ///
    /// Returns an error when the system clock predates the Unix epoch or hexadecimal formatting
    /// fails.
    pub(crate) fn create(repository_root: &Path) -> TaskResult<Self> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let mut hasher = Sha256::new();
        hasher.update(b"ext4win-driver-load-session-v1");
        hasher.update(elapsed.as_nanos().to_le_bytes());
        hasher.update(host_process::id().to_le_bytes());
        hasher.update(repository_root.as_os_str().to_string_lossy().as_bytes());

        let mut value = String::with_capacity(32);
        for byte in hasher.finalize().iter().take(16) {
            write!(&mut value, "{byte:02x}")?;
        }
        Ok(Self(value))
    }

    /// Parses the exact external form accepted by recovery commands.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is exactly 32 lowercase hexadecimal digits.
    pub(crate) fn parse(value: &OsStr) -> TaskResult<Self> {
        let value = value
            .to_str()
            .filter(|candidate| {
                candidate.len() == 32
                    && candidate
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| {
                io::Error::other("session id must be exactly 32 lowercase hexadecimal digits")
            })?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the exact value persisted by the PowerShell session owner.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Performs the read-only hosted driver-load host contract check.
///
/// # Errors
///
/// Returns an error outside Windows or when administrator rights, `TESTSIGNING`, PnPUtil/SCM,
/// or the required clean ext4win package/service state is absent.
pub(crate) fn check_hosted_driver_host(repository_root: &Path) -> TaskResult<()> {
    require_windows_driver_host()?;
    run_driver_load_script(repository_root, "Preflight", None, None)
}

/// Builds one verified production bundle, loads that exact driver, and mandates full cleanup.
///
/// # Errors
///
/// Returns an error for any hosted preflight, production build, certificate identity,
/// DriverStore, service initialization, or mandatory cleanup failure.
pub(crate) fn verify_hosted_driver_load(repository_root: &Path) -> TaskResult<()> {
    check_hosted_driver_host(repository_root)?;
    let bundle = build_verified_production_bundle(repository_root)?;
    shutdown_production_wsl_oracle()?;
    let session_id = DriverLoadSessionId::create(repository_root)?;
    println!("driver-load session: {}", session_id.as_str());
    run_driver_load_script(repository_root, "Run", Some(&bundle), Some(&session_id))?;
    println!("hosted kernel-load smoke assurance: PASS");
    Ok(())
}

/// Shuts down the production gate's WSL oracle before registering a filesystem driver.
///
/// The production gate may leave its ext4-backed WSL virtual disk attached. The hosted smoke
/// session must not let that oracle volume become an incidental mount target.
///
/// # Errors
///
/// Returns an error when WSL cannot detach its distributions and virtual machine.
fn shutdown_production_wsl_oracle() -> TaskResult<()> {
    let mut command = Command::new("wsl.exe");
    command.arg("--shutdown");
    run_checked(command, "production WSL oracle shutdown")?;
    println!("production WSL oracle shutdown: PASS");
    Ok(())
}

/// Reconciles one interrupted DriverStore/service lifecycle session by its persisted identity.
///
/// # Errors
///
/// Returns an error outside Windows, for a malformed or mismatched session identity, or when
/// service/package cleanup cannot establish absence.
pub(crate) fn cleanup_driver_load_session(
    repository_root: &Path,
    session_id: &OsStr,
) -> TaskResult<()> {
    require_windows_driver_host()?;
    let session_id = DriverLoadSessionId::parse(session_id)?;
    run_driver_load_script(repository_root, "Cleanup", None, Some(&session_id))
}

/// Rejects driver-load workflows outside the Windows host boundary.
///
/// # Errors
///
/// Returns `Unsupported` on non-Windows hosts.
fn require_windows_driver_host() -> TaskResult<()> {
    if cfg!(target_os = "windows") {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "driver-load validation requires an elevated Windows host",
        )
        .into())
    }
}

/// Invokes the single repository owner of DriverStore and driver-service lifecycle state.
///
/// # Errors
///
/// Returns an error when the script is absent, PowerShell cannot start, or the requested session
/// workflow fails closed.
fn run_driver_load_script(
    repository_root: &Path,
    mode: &str,
    bundle: Option<&VerifiedProductionBundle>,
    session_id: Option<&DriverLoadSessionId>,
) -> TaskResult<()> {
    let script = repository_root
        .join("tools")
        .join("xtask")
        .join("driver-load.ps1");
    require_file(&script, "driver-load workflow script")?;
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
        command.arg("-Bundle").arg(bundle.as_path());
    }
    if let Some(session_id) = session_id {
        command.arg("-SessionId").arg(session_id.as_str());
    }
    run_checked(command, &format!("driver-load {mode} workflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// Recovery identity parsing accepts only the exact generated boundary shape.
    ///
    /// # Panics
    ///
    /// Panics if malformed, uppercase, or non-UTF-8-compatible command-line values are admitted.
    #[test]
    fn recovery_identity_parser_is_exact() {
        assert!(DriverLoadSessionId::parse(OsStr::new("0123456789abcdef0123456789abcdef")).is_ok());
        assert!(
            DriverLoadSessionId::parse(OsStr::new("0123456789ABCDEF0123456789ABCDEF")).is_err()
        );
        assert!(DriverLoadSessionId::parse(OsStr::new("0123456789abcdef")).is_err());
        assert!(
            DriverLoadSessionId::parse(&OsString::from("g123456789abcdef0123456789abcdef"))
                .is_err()
        );
    }
}
