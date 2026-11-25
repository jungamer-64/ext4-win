//! DriverStore and SCM lifecycle ownership; a failed requester never establishes rollback.
#[cfg(any(windows, test))]
mod inventory;
#[cfg(windows)]
mod owner;
#[cfg(windows)]
pub(crate) use owner::{
    check_hosted_driver_host, cleanup_driver_load_session, install_session, quiesce_session,
    resolve_driver_store_image, start_session, unload_requester, verify_hosted_driver_load,
};

#[cfg(not(windows))]
use crate::TaskResult;
#[cfg(not(windows))]
use std::{ffi::OsStr, io, path::Path};

/// Lifecycle request issued by a supervised requester against the session's bound driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnloadRequest {
    /// Close intake and wait for pending mounts to settle before dismount.
    QuiesceMounts,
    /// Retire the control device after mounted volumes drain.
    PrepareUnload,
}

impl UnloadRequest {
    /// Command line name of this requester.
    pub(crate) const fn command(self) -> &'static str {
        match self {
            Self::QuiesceMounts => "quiesce-driver-mounts",
            Self::PrepareUnload => "prepare-driver-unload",
        }
    }
}

/// Rejects a Windows kernel-load workflow on a portable host.
/// # Errors
/// Always returns Unsupported on non-Windows hosts.
#[cfg(not(windows))]
pub(crate) fn check_hosted_driver_host(_root: &Path) -> TaskResult<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "driver-load validation requires an elevated Windows host",
    )
    .into())
}
/// Rejects driver installation on a portable host.
/// # Errors
/// Always returns Unsupported on non-Windows hosts.
#[cfg(not(windows))]
pub(crate) fn verify_hosted_driver_load(root: &Path) -> TaskResult<()> {
    check_hosted_driver_host(root)
}
/// Rejects Windows session reconciliation on a portable host.
/// # Errors
/// Always returns Unsupported on non-Windows hosts.
#[cfg(not(windows))]
pub(crate) fn cleanup_driver_load_session(root: &Path, _id: &OsStr) -> TaskResult<()> {
    check_hosted_driver_host(root)
}
/// Rejects secured Windows device control on a portable host.
/// # Errors
/// Always returns Unsupported on non-Windows hosts.
#[cfg(not(windows))]
pub(crate) fn unload_requester(
    root: &Path,
    _id: &OsStr,
    _request: UnloadRequest,
) -> TaskResult<()> {
    check_hosted_driver_host(root)
}

/// Rejects native package mapping on a portable host.
/// # Errors
/// Always returns Unsupported on non-Windows hosts.
#[cfg(not(windows))]
pub(crate) fn resolve_driver_store_image(_oem: &OsStr) -> TaskResult<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "DriverStore mapping requires Windows",
    )
    .into())
}
