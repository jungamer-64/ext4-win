//! Host-side development and production verification workflows for ext4-win.

#![feature(allocator_api)]

extern crate alloc;

/// Parses and dispatches repository workflow commands.
mod cli;
/// Owns portable, driver, and deterministic fuzz development gates.
mod development;
/// Owns external ext4 interoperability and production-core host execution.
mod interop;
/// Owns the elevated live-driver/VHDX process boundary.
mod live;
/// Owns repository paths, child processes, temporary directories, hashes, and cleanup.
mod process;
/// Owns signed production artifact construction, sealing, and publication.
mod production;

use core::error::Error;
use std::process::ExitCode;

/// Dynamically dispatched error returned by one host workflow.
type TaskResult<T> = Result<T, Box<dyn Error>>;

fn main() -> ExitCode {
    cli::run()
}
