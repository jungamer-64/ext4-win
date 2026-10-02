//! Host-side development and production verification workflows for ext4-win.

#![feature(allocator_api)]

extern crate alloc;

/// Parses and dispatches repository workflow commands.
mod cli;
/// Owns portable, driver, and deterministic fuzz development gates.
mod development;
/// Owns hosted DriverStore and demand-start service lifecycle verification.
mod driver_load;
/// Builds the native Linux fixture capability used by interoperability and live tests.
mod fixture;
/// Owns external ext4 interoperability and production-core host execution.
mod interop;
/// Owns VHDX, WSL, filesystem I/O, and Driver Verifier live assurance.
mod live;
/// Owns repository paths, child processes, temporary directories, hashes, and cleanup.
mod process;
/// Owns signed production artifact construction, sealing, and publication.
mod production;
/// Durable phase records shared by the DriverStore and disposable storage owners.
#[cfg(windows)]
mod session;
/// Windows disk and GPT observations, independent of driver and live-session owners.
#[cfg(windows)]
mod storage;
/// Native Windows management-command boundary, excluding lifecycle policy.
#[cfg(windows)]
mod windows;

use core::error::Error;
use std::process::ExitCode;

/// Dynamically dispatched error returned by one host workflow.
type TaskResult<T> = Result<T, Box<dyn Error>>;

fn main() -> ExitCode {
    cli::run()
}
