//! Disposable VHDX validation with storage cleanup preceding driver retirement.
#[cfg(windows)]
mod owner;
#[cfg(not(windows))]
use crate::TaskResult;
#[cfg(windows)]
pub(crate) use owner::{check_live_driver_host, cleanup_live_vhdx_session, verify_live_vhdx};
#[cfg(not(windows))]
use std::{ffi::OsStr, io, path::Path};
/// Rejects Windows live validation on portable hosts.
/// # Errors
/// Always returns Unsupported outside Windows.
#[cfg(not(windows))]
pub(crate) fn check_live_driver_host(_root: &Path) -> TaskResult<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "live VHDX validation requires a dedicated elevated Windows host",
    )
    .into())
}
/// Rejects Windows storage mutation on portable hosts.
/// # Errors
/// Always returns Unsupported outside Windows.
#[cfg(not(windows))]
pub(crate) fn verify_live_vhdx(root: &Path) -> TaskResult<()> {
    check_live_driver_host(root)
}
/// Rejects Windows storage reconciliation on portable hosts.
/// # Errors
/// Always returns Unsupported outside Windows.
#[cfg(not(windows))]
pub(crate) fn cleanup_live_vhdx_session(root: &Path, _id: &OsStr) -> TaskResult<()> {
    check_live_driver_host(root)
}
