//! Native Windows host boundaries shared by diagnostics and the live driver harness.
//!
//! Handles own their native release operation. Fallible protocol completion is explicit;
//! dropping an owner is a fallback and never establishes a successful live validation.

#![deny(unsafe_code)]
#![cfg_attr(windows, feature(allocator_api))]

extern crate alloc;

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "this module exclusively owns validated Windows ABI calls and native handle lifetimes"
)]
mod native;
#[cfg(windows)]
pub use native::*;
