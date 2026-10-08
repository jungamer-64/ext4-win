//! DriverStore and SCM lifecycle ownership; a failed requester never establishes rollback.
#[cfg(windows)]
mod owner;
#[cfg(windows)]
pub(crate) use owner::{
    check_hosted_driver_host, cleanup_driver_load_session, prepare_driver_unload, restart_session,
    start_session, verify_hosted_driver_load,
};

#[cfg(not(windows))]
use crate::TaskResult;
#[cfg(not(windows))]
use std::{ffi::OsStr, io, path::Path};

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
pub(crate) fn prepare_driver_unload(root: &Path, _id: &OsStr) -> TaskResult<()> {
    check_hosted_driver_host(root)
}
