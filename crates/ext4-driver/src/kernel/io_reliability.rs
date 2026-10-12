//! Read/write permission projected from the reactor's authoritative reliability state.
//! Native observers cannot change policy or recover the publication owner.

use crate::kernel::status::DriverResult;
use crate::memory::{DriverShared, DriverSharedLease};
use core::sync::atomic::{AtomicU8, Ordering};

/// Native I/O classes permitted by the last authoritative volume failure transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum NativeIoPolicy {
    /// Reads and writes remain trustworthy.
    ReadWrite = 0,
    /// Committed data remains readable; no write may be accepted.
    ReadOnly = 1,
    /// Native I/O must fall back to the actor's exact terminal failure.
    Unavailable = 2,
}

impl NativeIoPolicy {
    /// One scalar snapshot decides a callback's read and write permissions together.
    pub(crate) const fn permits(self, write: bool) -> bool {
        match self {
            Self::ReadWrite => true,
            Self::ReadOnly => !write,
            Self::Unavailable => false,
        }
    }

    /// Fixed scalar representation shared with native callbacks.
    #[expect(clippy::as_conversions, reason = "repr(u8) fixes this internal native policy ABI")]
    pub(crate) const fn raw(self) -> u8 {
        self as u8
    }
}

/// Sole publisher retained by the reactor's volume runtime.
#[derive(Debug)]
pub(crate) struct IoReliabilityOwner {
    /// Release/acquire projection; it never independently determines volume failure.
    policy: DriverShared<AtomicU8>,
}

impl IoReliabilityOwner {
    /// Allocates before mount publication, with all I/O initially permitted.
    /// # Errors
    /// Returns nonpaged allocation failure before native callbacks exist.
    pub(crate) fn try_new() -> DriverResult<Self> {
        Ok(Self { policy: DriverShared::try_new(AtomicU8::new(0))? })
    }

    /// Attenuates publication ownership to a retained read-only observation.
    /// # Errors
    /// Returns finite reference-budget exhaustion before installing a native stream.
    pub(crate) fn observe(&self) -> DriverResult<IoReliabilityObservation> {
        self.policy.try_acquire().map(|policy| IoReliabilityObservation { policy })
    }

    /// Publishes immediately with the actor's failure transition, without allocation.
    pub(crate) fn publish(&mut self, policy: NativeIoPolicy) {
        self.policy.get().store(policy.raw(), Ordering::Release);
    }
}

/// Native read-only observation retained until the enclosing volume stream is destroyed.
#[derive(Debug)]
pub(crate) struct IoReliabilityObservation {
    /// This lease exposes neither the publication owner nor mutable atomic access.
    policy: DriverSharedLease<AtomicU8>,
}

impl IoReliabilityObservation {
    /// Acquires the complete read/write projection from one failure publication.
    pub(crate) fn policy(&self) -> NativeIoPolicy {
        match self.policy.get().load(Ordering::Acquire) {
            0 => NativeIoPolicy::ReadWrite,
            1 => NativeIoPolicy::ReadOnly,
            _ => NativeIoPolicy::Unavailable,
        }
    }
}
