//! Preallocated continuations for the single non-cancellable handle-finalization lane.

use super::{OwnedIrp, reactor::CompletionOperation};
use alloc::boxed::Box;
use core::fmt;

/// Ownership transferred from the reactor reserve to exactly one terminal handle request.
pub(crate) trait FinalizationOperation: fmt::Debug + Send + 'static {
    /// Starts one request without allocation. Completion must return the cleared continuation.
    fn activate(self: Box<Self>, owned: OwnedIrp) -> Box<dyn CompletionOperation>;
    /// Selects the reserve to which this cleared continuation belongs.
    fn kind(&self) -> FinalizationRequest;
}

/// Distinct Windows handle-finalization boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalizationRequest {
    /// Releases handle resources while shared stream storage remains live until Close.
    Cleanup,
    /// Reclaims FILE_OBJECT contexts after all prior handle work has drained.
    Close,
}

/// One continuation per terminal boundary, prepared before the reactor is published.
#[derive(Debug)]
pub(crate) struct FinalizationPool {
    /// Present only while no Cleanup owns this reusable continuation.
    cleanup: Option<Box<dyn FinalizationOperation>>,
    /// Present only while no Close owns this reusable continuation.
    close: Option<Box<dyn FinalizationOperation>>,
}

impl FinalizationPool {
    /// Takes ownership of prepared continuations without publishing native effects.
    pub(crate) fn new(
        cleanup: Box<dyn FinalizationOperation>,
        close: Box<dyn FinalizationOperation>,
    ) -> Self {
        Self {
            cleanup: Some(cleanup),
            close: Some(close),
        }
    }
    /// Transfers the single reserved continuation; the finalization execution slot prevents reuse.
    pub(crate) fn activate(
        &mut self,
        kind: FinalizationRequest,
        owned: OwnedIrp,
    ) -> Box<dyn CompletionOperation> {
        let slot = match kind {
            FinalizationRequest::Cleanup => &mut self.cleanup,
            FinalizationRequest::Close => &mut self.close,
        };
        slot.take()
            .unwrap_or_else(|| {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            })
            .activate(owned)
    }
    /// Restores a cleared continuation before the request releases its execution slot.
    pub(crate) fn restore(&mut self, operation: Box<dyn FinalizationOperation>) {
        let slot = match operation.kind() {
            FinalizationRequest::Cleanup => &mut self.cleanup,
            FinalizationRequest::Close => &mut self.close,
        };
        if slot.replace(operation).is_some() {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::irp::reactor::{CompletionEvent, OperationTransition, ReactorTarget};
    use crate::kernel::status::DriverResult;
    use crate::kernel::storage::StorageFailureClass;

    /// Independent completion consumer exercising the mandatory reserve-return protocol.
    #[derive(Debug)]
    struct ReleasedHandle {
        kind: FinalizationRequest,
        request: Option<OwnedIrp>,
    }
    impl FinalizationOperation for ReleasedHandle {
        fn activate(mut self: Box<Self>, owned: OwnedIrp) -> Box<dyn CompletionOperation> {
            self.request = Some(owned);
            self
        }
        fn kind(&self) -> FinalizationRequest {
            self.kind
        }
    }
    impl CompletionOperation for ReleasedHandle {
        fn advance(
            mut self: Box<Self>,
            _event: CompletionEvent,
            _target: &mut ReactorTarget,
        ) -> OperationTransition {
            let owned = self.request.take().unwrap_or_else(|| crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck());
            OperationTransition::CompleteFinalization {
                completion: owned.prepare_result(Ok(crate::irp::IrpCompletion::EMPTY)),
                reusable: self,
            }
        }
        fn record_storage_failure(
            &mut self,
            _failure: StorageFailureClass,
            _target: &mut ReactorTarget,
        ) {
        }
    }

    /// # Errors
    /// Returns allocation failure while constructing the initial two reserves.
    /// # Panics
    /// Panics if returning one completion reserve prevents subsequent Cleanup or Close requests.
    #[test]
    #[expect(
        unsafe_code,
        reason = "owned completion fixtures retain their device and IRP until explicit notification"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "setup propagates allocation errors while assertions enforce repeated terminal progress"
    )]
    fn completed_release_returns_capacity_for_subsequent_handles() -> DriverResult<()> {
        let cleanup = crate::memory::boxed_try_with(|| {
            Ok(ReleasedHandle {
                kind: FinalizationRequest::Cleanup,
                request: None,
            })
        })?;
        let close = crate::memory::boxed_try_with(|| {
            Ok(ReleasedHandle {
                kind: FinalizationRequest::Close,
                request: None,
            })
        })?;
        let mut pool = FinalizationPool::new(cleanup, close);
        let mut raw_device = wdk_sys::DEVICE_OBJECT::default();
        let device = unsafe {
            // SAFETY: The fixture retains its device until every completion owner has returned.
            crate::state::KernelDevice::from_raw(core::ptr::from_mut(&mut raw_device))
        }
        .ok_or(crate::kernel::status::DriverError::InvalidParameter)?;
        for _ in 0..128 {
            for kind in [FinalizationRequest::Cleanup, FinalizationRequest::Close] {
                let mut irp = wdk_sys::IRP::default();
                let owned = unsafe {
                    // SAFETY: The fixture retains this exclusive IRP through the matching notification.
                    OwnedIrp::from_test_raw(device, core::ptr::from_mut(&mut irp))
                }
                .ok_or(crate::kernel::status::DriverError::InvalidParameter)?;
                let operation = pool.activate(kind, owned);
                let result = operation.advance(
                    CompletionEvent::Core(ext4_core::OperationEvent::Admitted),
                    &mut ReactorTarget::ControlDevice(crate::identity::IdentityCatalog::empty()),
                );
                let OperationTransition::CompleteFinalization {
                    completion,
                    reusable,
                } = result
                else {
                    return Err(crate::kernel::status::DriverError::InternalInvariantViolation);
                };
                pool.restore(reusable);
                assert_eq!(completion.notify(), wdk_sys::STATUS_SUCCESS);
            }
        }
        Ok(())
    }
}
