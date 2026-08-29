//! Driver-lifetime operational ETW ownership and payload-free event capability.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

use wdk_sys::{NTSTATUS, STATUS_PENDING, STATUS_SUCCESS};

use crate::kernel::fatal::KernelWideInconsistency;

/// Generated scalar projection of the checked-in operational trace schema.
mod contract {
    include!(concat!(env!("OUT_DIR"), "/operational-trace-v1.rs"));
}

/// Driver-owned path identity recorded without file names, offsets, lengths, or payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationalPath {
    /// Paging read admitted independently from handle cleanup.
    PagingRead,
    /// Paging write or lazy writeback.
    PagingWrite,
    /// Raw lower-volume read.
    RawRead,
    /// Raw lower-volume write.
    RawWrite,
    /// Raw write-through lower-device flush.
    RawFlush,
}

impl OperationalPath {
    /// Returns the stable event identifier generated from the repository-owned trace contract.
    const fn event_id(self) -> u16 {
        match self {
            Self::PagingRead => contract::TRACE_EVENT_PAGING_READ,
            Self::PagingWrite => contract::TRACE_EVENT_PAGING_WRITE,
            Self::RawRead => contract::TRACE_EVENT_RAW_READ,
            Self::RawWrite => contract::TRACE_EVENT_RAW_WRITE,
            Self::RawFlush => contract::TRACE_EVENT_RAW_FLUSH,
        }
    }
}

/// Path-selection outcome kept independent from the operation's machine-readable `NTSTATUS`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationalOutcome {
    /// The path was selected before its effect or asynchronous continuation.
    Selected,
    /// The selected path reached its normal completion boundary.
    Completed,
    /// The selected path completed with a non-success operation status.
    Failed,
    /// The selected path transferred completion authority to an asynchronous continuation.
    Pending,
}

impl OperationalOutcome {
    /// Returns the stable payload value generated from the trace contract.
    const fn value(self) -> u32 {
        match self {
            Self::Selected => contract::TRACE_OUTCOME_SELECTED,
            Self::Completed => contract::TRACE_OUTCOME_COMPLETED,
            Self::Failed => contract::TRACE_OUTCOME_FAILED,
            Self::Pending => contract::TRACE_OUTCOME_PENDING,
        }
    }
}

/// Copyable, write-only capability attenuated from the unique provider registration owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct OperationalTrace {
    /// Nonzero ETW registration identity owned by the driver-lifetime registration.
    handle: NonZeroU64,
}

impl OperationalTrace {
    /// Returns the scalar registration identity for native stream construction.
    #[cfg(not(test))]
    pub(super) const fn handle(self) -> u64 {
        self.handle.get()
    }

    /// Records one data-free path observation without affecting filesystem completion semantics.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the ETW capability passes only driver-owned scalar payloads to native code"
        )
    )]
    pub(crate) fn record(
        self,
        path: OperationalPath,
        status: NTSTATUS,
        outcome: OperationalOutcome,
    ) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Registration outlives every copied capability; event id, status, and outcome
            // are scalar values whose schema cannot carry user data or kernel pointers.
            ext4win_trace_write(self.handle.get(), path.event_id(), status, outcome.value());
        }
        #[cfg(test)]
        let _event = (self, path.event_id(), status, outcome.value());
    }

    /// Records the operation result while preserving its machine-readable driver status.
    pub(crate) fn record_result<T>(
        self,
        path: OperationalPath,
        result: &Result<T, crate::kernel::status::DriverError>,
    ) {
        match result {
            Ok(_) => self.record(path, STATUS_SUCCESS, OperationalOutcome::Completed),
            Err(error) => self.record(path, error.ntstatus(), OperationalOutcome::Failed),
        }
    }

    /// Records an explicit terminal status when the IRP result also carries committed progress.
    pub(crate) fn record_status(self, path: OperationalPath, status: NTSTATUS) {
        self.record(
            path,
            status,
            if status == STATUS_PENDING {
                OperationalOutcome::Pending
            } else if status >= STATUS_SUCCESS {
                OperationalOutcome::Completed
            } else {
                OperationalOutcome::Failed
            },
        );
    }

    /// Creates the inert host-test capability without exposing a production construction path.
    #[cfg(test)]
    pub(crate) const fn host_test() -> Self {
        Self {
            handle: NonZeroU64::MIN,
        }
    }
}

/// Unique DriverEntry-owned provider registration before it is published for DriverUnload.
pub(crate) struct OperationalTraceRegistration {
    /// Unique unregister authority until publication transfers it to DriverUnload.
    handle: Option<NonZeroU64>,
}

impl OperationalTraceRegistration {
    /// Registers the provider before any device or trace-capable stream is published.
    /// # Errors
    ///
    /// Returns the exact native registration status, or an invariant status for a zero handle.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "DriverEntry owns the native ETW provider registration output"
        )
    )]
    pub(crate) fn register() -> Result<Self, NTSTATUS> {
        #[cfg(not(test))]
        {
            let mut handle = 0_u64;
            let status = unsafe {
                // SAFETY: This writable scalar out parameter remains live for the synchronous call.
                ext4win_trace_register(core::ptr::addr_of_mut!(handle))
            };
            if status < STATUS_SUCCESS {
                return Err(status);
            }
            let handle = NonZeroU64::new(handle).ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?;
            Ok(Self {
                handle: Some(handle),
            })
        }
        #[cfg(test)]
        {
            Ok(Self {
                handle: Some(NonZeroU64::MIN),
            })
        }
    }

    /// Attenuates the registration into a copyable event-write capability.
    pub(crate) fn trace(&self) -> OperationalTrace {
        OperationalTrace {
            handle: self.handle.unwrap_or_else(|| {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck()
            }),
        }
    }

    /// Publishes sole unregister authority only after device creation has succeeded.
    pub(crate) fn publish(mut self) {
        let handle = self.handle.take().unwrap_or_else(|| {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck()
        });
        if PUBLISHED_OPERATIONAL_TRACE
            .compare_exchange(0, handle.get(), Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
    }
}

impl Drop for OperationalTraceRegistration {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        unregister(handle);
    }
}

/// Sole driver-lifetime unregister authority; copied trace capabilities cannot reach this state.
static PUBLISHED_OPERATIONAL_TRACE: AtomicU64 = AtomicU64::new(0);

/// Consumes the registered provider only after every device and stream capability has retired.
pub(crate) fn unregister_published() {
    let handle = PUBLISHED_OPERATIONAL_TRACE.swap(0, Ordering::AcqRel);
    let handle = NonZeroU64::new(handle)
        .unwrap_or_else(|| KernelWideInconsistency::driver_device_teardown_corruption().bugcheck());
    unregister(handle);
}

/// Observes fallible finalization at the terminal driver lifecycle boundary.
#[cfg_attr(
    not(test),
    expect(
        unsafe_code,
        reason = "the unique provider owner consumes its native registration handle"
    )
)]
fn unregister(handle: NonZeroU64) {
    #[cfg(not(test))]
    {
        let status = unsafe {
            // SAFETY: The caller uniquely consumed the still-registered nonzero handle.
            ext4win_trace_unregister(handle.get())
        };
        if status < STATUS_SUCCESS {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
    }
    #[cfg(test)]
    let _handle = handle;
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "these declarations expose the native ETW registration and scalar event boundary"
)]
unsafe extern "system" {
    fn ext4win_trace_register(registration_handle_out: *mut u64) -> NTSTATUS;
    fn ext4win_trace_unregister(registration_handle: u64) -> NTSTATUS;
    fn ext4win_trace_write(registration_handle: u64, event_id: u16, status: NTSTATUS, outcome: u32);
}

#[cfg(test)]
mod tests {
    use super::{OperationalOutcome, OperationalPath, OperationalTrace};

    /// # Panics
    ///
    /// Panics if the checked-in contract aliases path identifiers or outcome values.
    #[test]
    fn event_schema_has_unique_nonzero_domains() {
        let events = [
            OperationalPath::PagingRead,
            OperationalPath::PagingWrite,
            OperationalPath::RawRead,
            OperationalPath::RawWrite,
            OperationalPath::RawFlush,
        ];
        for (index, event) in events.iter().enumerate() {
            assert_ne!(event.event_id(), 0);
            assert!(
                !events
                    .iter()
                    .take(index)
                    .any(|prior| prior.event_id() == event.event_id())
            );
        }
        let outcomes = [
            OperationalOutcome::Selected,
            OperationalOutcome::Completed,
            OperationalOutcome::Failed,
            OperationalOutcome::Pending,
        ];
        for (index, outcome) in outcomes.iter().enumerate() {
            assert_ne!(outcome.value(), 0);
            assert!(
                !outcomes
                    .iter()
                    .take(index)
                    .any(|prior| prior.value() == outcome.value())
            );
        }
        OperationalTrace::host_test().record(
            OperationalPath::PagingRead,
            STATUS_SUCCESS,
            OperationalOutcome::Completed,
        );
    }

    use wdk_sys::STATUS_SUCCESS;
}
