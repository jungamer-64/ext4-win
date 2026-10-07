//! Allocation-free, non-cancellable MDL return ownership.
//!
//! A stream prepares its worker before exposing cache pages. Each queued worker cycle retains
//! a FILE_OBJECT until its last stream access; CLOSE cannot destroy the inbox before that point.

/// Intrusive original-request ownership, independent of native execution resources.
mod fifo;

/// Native execution resources stay outside the host-independent ownership FIFO.
#[cfg(not(test))]
mod native;

#[cfg(not(test))]
pub(crate) use native::MdlCompletionQueue;
