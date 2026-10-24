//! Read/write permission projected from the reactor's authoritative reliability state.
//! Native observers cannot change policy or recover the publication owner.

use crate::kernel::status::DriverResult;
use crate::memory::{DriverShared, DriverSharedLease};
use core::sync::atomic::{AtomicU64, Ordering};

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
    #[expect(
        clippy::as_conversions,
        reason = "repr(u8) fixes this internal native policy ABI"
    )]
    pub(crate) const fn raw(self) -> u8 {
        self as u8
    }
}

/// One scalar publishes permission and its acknowledged expiration as a consistent snapshot.
/// Zero upper bits mean no MMP deadline. Low bits retain the native three-policy encoding.
#[derive(Clone, Copy, Debug)]
struct NativeIoSnapshot(u64);

impl NativeIoSnapshot {
    /// Encodes host monotonic milliseconds; an unrepresentable observation rejects every callback.
    fn new(policy: NativeIoPolicy, deadline: Option<ext4_core::MmpDeadline>) -> Self {
        let expiry = match deadline {
            None => 0,
            Some(deadline) => match deadline.monotonic_millis().checked_mul(4) {
                Some(value) if value != 0 => value,
                _ => return Self(u64::from(NativeIoPolicy::Unavailable.raw())),
            },
        };
        Self(expiry | u64::from(policy.raw()))
    }

    /// Consults the native clock only for an admitted policy with a physical ownership deadline.
    fn policy(self, monotonic_millis: impl FnOnce() -> u64) -> NativeIoPolicy {
        let policy = match self.0 & 3 {
            0 => NativeIoPolicy::ReadWrite,
            1 => NativeIoPolicy::ReadOnly,
            _ => return NativeIoPolicy::Unavailable,
        };
        let deadline = self.0 >> 2;
        if deadline != 0 && monotonic_millis() >= deadline {
            return NativeIoPolicy::Unavailable;
        }
        policy
    }
}

/// Sole publisher retained by the reactor's volume runtime.
#[derive(Debug)]
pub(crate) struct IoReliabilityOwner {
    /// Release/acquire projection; it never independently determines volume failure.
    policy: DriverShared<AtomicU64>,
}

impl IoReliabilityOwner {
    /// Allocates before mount publication, with all I/O initially permitted.
    /// # Errors
    /// Returns nonpaged allocation failure before native callbacks exist.
    pub(crate) fn try_new() -> DriverResult<Self> {
        Ok(Self {
            policy: DriverShared::try_new(AtomicU64::new(0))?,
        })
    }

    /// Attenuates publication ownership to a retained read-only observation.
    /// # Errors
    /// Returns finite reference-budget exhaustion before installing a native stream.
    pub(crate) fn observe(&self) -> DriverResult<IoReliabilityObservation> {
        self.policy
            .try_acquire()
            .map(|policy| IoReliabilityObservation { policy })
    }

    /// Publishes immediately with the actor's failure transition, without allocation.
    pub(crate) fn publish(&mut self, policy: NativeIoPolicy, deadline: Option<ext4_core::MmpDeadline>) {
        self.policy.get().store(NativeIoSnapshot::new(policy, deadline).0, Ordering::Release);
    }
}

/// Native read-only observation retained until the enclosing volume stream is destroyed.
#[derive(Debug)]
pub(crate) struct IoReliabilityObservation {
    /// This lease exposes neither the publication owner nor mutable atomic access.
    policy: DriverSharedLease<AtomicU64>,
}

impl IoReliabilityObservation {
    /// Acquires the complete read/write projection from one failure publication.
    pub(crate) fn policy(&self) -> NativeIoPolicy {
        NativeIoSnapshot(self.policy.get().load(Ordering::Acquire))
            .policy(crate::kernel::time::monotonic_millis)
    }
}
