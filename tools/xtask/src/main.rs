//! Host-side development and production verification workflows for ext4-win.

#![feature(allocator_api)]

mod cli;
mod development;
mod interop;
mod live;
mod process;
mod production;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
