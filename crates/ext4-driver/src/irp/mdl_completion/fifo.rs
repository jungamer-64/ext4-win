//! Unique original-IRP ownership for the non-cancellable MDL return FIFO.

use super::super::{KernelIrp, MdlCompletion};
use core::ffi::c_void;

/// Intrusive storage uses only the original IRP's driver-owned slots, without allocation.
pub(super) struct CompletionFifo {
    /// First uniquely owned request.
    head: Option<KernelIrp>,
    /// Last request; absent exactly when `head` is absent.
    tail: Option<KernelIrp>,
}

impl CompletionFifo {
    /// Empty ownership before any consuming notification arrives.
    pub(super) const fn new() -> Self {
        Self {
            head: None,
            tail: None,
        }
    }

    /// Whether destruction has no outstanding request authority to abandon.
    pub(super) const fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Transfers exclusive original-request ownership into the FIFO.
    /// # Safety
    /// `irp` must be live, unqueued and uniquely owned, with unused driver-context slots.
    /// The owner must retain it until dequeue and serialize all FIFO access.
    #[expect(
        unsafe_code,
        reason = "unique publication owns both new slots and queued tail linkage"
    )]
    pub(super) unsafe fn push(&mut self, mut irp: KernelIrp, action: MdlCompletion) {
        let slots = unsafe {
            // SAFETY: Publication uniquely owns this unqueued request.
            driver_slots(&mut irp)
        };
        slots[0] = core::ptr::null_mut();
        slots[1] = match action {
            MdlCompletion::Read => core::ptr::null_mut(),
            MdlCompletion::Write => core::ptr::without_provenance_mut(1),
        };
        if let Some(mut tail) = self.tail {
            let slots = unsafe {
                // SAFETY: Serialized FIFO ownership retains the queued tail.
                driver_slots(&mut tail)
            };
            slots[0] = irp.as_ptr().cast();
        } else {
            self.head = Some(irp);
        }
        self.tail = Some(irp);
    }

    /// Transfers one original request and its consuming action out, clearing queue-owned slots.
    #[expect(
        unsafe_code,
        reason = "the FIFO retains every request through exclusive dequeue"
    )]
    pub(super) fn pop(&mut self) -> Option<(KernelIrp, MdlCompletion)> {
        let mut irp = self.head?;
        let slots = unsafe {
            // SAFETY: The serialized FIFO uniquely owns the retained head request.
            driver_slots(&mut irp)
        };
        self.head = unsafe {
            // SAFETY: Only publication writes linkage to another live uniquely queued request.
            KernelIrp::from_raw(slots[0].cast())
        };
        if self.head.is_none() {
            self.tail = None;
        }
        let action = if slots[1].is_null() {
            MdlCompletion::Read
        } else {
            MdlCompletion::Write
        };
        slots[0] = core::ptr::null_mut();
        slots[1] = core::ptr::null_mut();
        Some((irp, action))
    }
}

/// Borrows only the driver-context arm; independent stack/list union arms are untouched.
/// # Safety
/// The caller must uniquely own the request or serialize its queued ownership.
#[expect(
    unsafe_code,
    reason = "the narrow slot boundary decodes each WDK union arm independently"
)]
unsafe fn driver_slots(irp: &mut KernelIrp) -> &mut [*mut c_void; 4] {
    let slots = irp.driver_context_slots();
    unsafe {
        // SAFETY: The caller retains and uniquely owns these initialized driver slots. This
        // reference does not include Cancel or the independent stack/list overlay fields.
        &mut *slots.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::status::{DriverError, DriverResult};

    /// # Errors
    /// Returns an invariant failure if a live test request cannot be represented or dequeued.
    /// # Panics
    /// Fails if consuming actions reorder, repeat, disappear or retain queue-owned slots.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture construction accompanies assertions of completion ownership"
    )]
    #[expect(
        unsafe_code,
        reason = "local initialized WDK records remain pinned throughout FIFO ownership"
    )]
    fn original_requests_return_once_in_order_and_release_slots() -> DriverResult<()> {
        let mut first: wdk_sys::IRP = unsafe {
            // SAFETY: A zeroed host IRP record has valid scalar/pointer representations.
            core::mem::zeroed()
        };
        let mut second: wdk_sys::IRP = unsafe {
            // SAFETY: This independent host IRP starts with unowned null context slots.
            core::mem::zeroed()
        };
        let first = unsafe {
            // SAFETY: Local storage remains live and unmoved until all queue operations finish.
            KernelIrp::from_raw(core::ptr::from_mut(&mut first))
        }
        .ok_or(DriverError::InternalInvariantViolation)?;
        let second = unsafe {
            // SAFETY: The distinct local request remains live through its unique dequeue.
            KernelIrp::from_raw(core::ptr::from_mut(&mut second))
        }
        .ok_or(DriverError::InternalInvariantViolation)?;
        let mut fifo = CompletionFifo::new();
        unsafe {
            // SAFETY: This test transfers its unique unqueued first request.
            fifo.push(first, MdlCompletion::Read);
        }
        unsafe {
            // SAFETY: This distinct unqueued request has no other completion owner.
            fifo.push(second, MdlCompletion::Write);
        }
        let (returned, action) = fifo.pop().ok_or(DriverError::InternalInvariantViolation)?;
        assert_eq!(returned.as_ptr(), first.as_ptr());
        assert_eq!(action, MdlCompletion::Read);
        let mut returned = returned;
        let slots = unsafe {
            // SAFETY: Dequeue returned exclusive ownership to this test.
            driver_slots(&mut returned)
        };
        assert!(slots[..2].iter().all(|slot| slot.is_null()));
        assert!(!fifo.is_empty());
        let (returned, action) = fifo.pop().ok_or(DriverError::InternalInvariantViolation)?;
        assert_eq!(returned.as_ptr(), second.as_ptr());
        assert_eq!(action, MdlCompletion::Write);
        assert!(fifo.is_empty());
        assert!(fifo.pop().is_none());
        unsafe {
            // SAFETY: The dequeued first request can transfer ownership again with a fresh action.
            fifo.push(first, MdlCompletion::Write);
        }
        let (returned, action) = fifo.pop().ok_or(DriverError::InternalInvariantViolation)?;
        assert_eq!(returned.as_ptr(), first.as_ptr());
        assert_eq!(action, MdlCompletion::Write);
        assert!(fifo.is_empty());
        Ok(())
    }
}
