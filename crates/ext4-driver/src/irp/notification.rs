//! Preallocated PASSIVE_LEVEL terminal notifications, independent of the volume actor.

use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    lifecycle::KernelIrp,
    lower::{CompletionRundown, CompletionRundownLease},
};
use crate::{
    kernel::{
        fatal::KernelWideInconsistency,
        ffi,
        status::{DriverError, DriverResult},
    },
    memory::KernelVec,
    state::KernelDevice,
};

/// Fixed notification capacity, reserved before request admission and never grown afterward.
pub(super) struct NotificationPool {
    /// Final-address slots; acquisition cannot move or extend this allocation.
    slots: KernelVec<NotificationSlot>,
}

impl NotificationPool {
    /// Allocates all native work items before the device accepts requests.
    /// # Errors
    /// Returns allocation failure without publishing any slot.
    pub(super) fn try_new(device: KernelDevice, capacity: usize) -> DriverResult<Self> {
        let mut slots = KernelVec::try_with_capacity(capacity)?;
        for _ in 0..capacity {
            slots
                .push_reserved_owned(NotificationSlot::try_new(device)?)
                .map_err(|failure| failure.into_parts().0)?;
        }
        Ok(Self { slots })
    }

    /// Reserves one notification through its terminal callback, independently of actor slots.
    /// # Errors
    /// Returns resource exhaustion when all notification slots remain owned, or shutdown when
    /// rundown admission has closed. No request effect has occurred at this boundary.
    #[expect(
        unsafe_code,
        reason = "atomic reservation grants unique payload access and the rundown lease pins the pool"
    )]
    pub(super) fn reserve(&self, rundown: &CompletionRundown) -> DriverResult<NotificationPermit> {
        let lease = rundown
            .acquire()?
            .ok_or(DriverError::InvalidDeviceRequest)?;
        for slot in self.slots.iter() {
            if slot
                .occupied
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                unsafe {
                    // SAFETY: The successful reservation exclusively owns this slot until release.
                    *slot.rundown.get() = Some(lease);
                }
                return Ok(NotificationPermit {
                    slot: NonNull::from(slot),
                });
            }
        }
        Err(DriverError::DeviceBusy)
    }
}

/// One work item reused only after the previous callback has finished all slot access.
struct NotificationSlot {
    /// WDK-owned, preallocated work item for the retaining device.
    work_item: NonNull<wdk_sys::_IO_WORKITEM>,
    /// Exclusive reservation spanning dispatch, the actor, and native notification.
    occupied: AtomicBool,
    /// Destination lifetime retained even while the reactor has no active operation for this IRP.
    rundown: UnsafeCell<Option<CompletionRundownLease>>,
    /// Terminal notification installed once immediately before queue publication.
    job: UnsafeCell<Option<(KernelIrp, wdk_sys::NTSTATUS)>>,
}

impl NotificationSlot {
    /// Allocates the native work item while device initialization owns rollback.
    /// # Errors
    /// Returns insufficient resources if the I/O Manager cannot allocate a work item.
    #[expect(
        unsafe_code,
        reason = "the initializing device remains alive through pool construction and destruction"
    )]
    fn try_new(device: KernelDevice) -> DriverResult<Self> {
        let work_item = unsafe {
            // SAFETY: Initialization retains this live device; no callback has been published.
            ffi::IoAllocateWorkItem(device.as_ptr())
        };
        Ok(Self {
            work_item: NonNull::new(work_item).ok_or(DriverError::InsufficientResources)?,
            occupied: AtomicBool::new(false),
            rundown: UnsafeCell::new(None),
            job: UnsafeCell::new(None),
        })
    }
}

impl Drop for NotificationSlot {
    #[expect(
        unsafe_code,
        reason = "reactor teardown joins dispatch and drains notification rundown before destroying work items"
    )]
    fn drop(&mut self) {
        if self.occupied.load(Ordering::Acquire) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        unsafe {
            // SAFETY: Construction rollback or completed rundown proves this item is not queued.
            ffi::IoFreeWorkItem(self.work_item.as_ptr());
        }
    }
}

/// Unique reservation transferred through DriverContext[2], then the owned IRP, then a callback.
#[derive(Debug)]
pub(super) struct NotificationPermit {
    /// Slot retained by its stored rundown lease until this permit releases it.
    slot: NonNull<NotificationSlot>,
}

#[expect(
    unsafe_code,
    reason = "the permit exclusively owns the slot and its lease pins the pool across thread transfer"
)]
// SAFETY: Only the unique permit may access slot payloads. Moving it transfers that authority.
unsafe impl Send for NotificationPermit {}

impl NotificationPermit {
    /// Transfers the pre-admitted reservation into the pending IRP's unused context slot.
    #[expect(
        unsafe_code,
        reason = "the pending IRP is uniquely owned before CSQ insertion"
    )]
    pub(super) fn publish(self, irp: KernelIrp) {
        unsafe {
            // SAFETY: Context[2] belongs to this notification protocol, separately from capture
            // and cancellation. Pending publication owns the IRP and transfers the permit once.
            *notification_context(irp) = self.slot.as_ptr().cast();
        }
        core::mem::forget(self);
    }

    /// Recovers the reservation after exclusive CSQ removal.
    /// # Safety
    /// The IRP must have been published with a permit and removed exactly once from the CSQ.
    #[expect(
        unsafe_code,
        reason = "the caller proves exclusive pending IRP ownership and matching context publication"
    )]
    pub(super) unsafe fn take(irp: KernelIrp) -> Self {
        let context = unsafe {
            // SAFETY: The caller uniquely owns the removed IRP and its notification context.
            notification_context(irp)
        };
        let raw = core::mem::replace(context, core::ptr::null_mut());
        Self {
            slot: NonNull::new(raw.cast()).unwrap_or_else(|| {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            }),
        }
    }

    /// Queues terminal notification after actor borrows, cancellation and handle lanes are gone.
    #[expect(
        unsafe_code,
        reason = "the unique permit transfers initialized job ownership to the native work queue"
    )]
    pub(super) fn queue(self, irp: KernelIrp, status: wdk_sys::NTSTATUS) {
        let slot = unsafe {
            // SAFETY: This permit retains and exclusively owns the reserved slot.
            self.slot.as_ref()
        };
        unsafe {
            // SAFETY: The slot is not queued, and this is its sole terminal job publication.
            *slot.job.get() = Some((irp, status));
        }
        let work_item = slot.work_item;
        let context = self.slot.as_ptr().cast();
        core::mem::forget(self);
        unsafe {
            // SAFETY: The callback receives sole permit ownership; its rundown lease retains the
            // slot until the callback's last access. IoQueueWorkItem retains the driver device.
            ffi::IoQueueWorkItem(
                work_item.as_ptr(),
                Some(notify_irp),
                wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                context,
            );
        }
    }
}

/// Borrows the notification-owned context field during exclusive IRP ownership.
/// # Safety
/// The caller must exclusively own this live IRP for the returned borrow's lifetime.
#[expect(
    unsafe_code,
    reason = "this boundary isolates WDK tail-overlay union projection"
)]
unsafe fn notification_context<'a>(irp: KernelIrp) -> &'a mut wdk_sys::PVOID {
    let irp = unsafe {
        // SAFETY: The caller supplies unique, live IRP ownership for this borrow.
        &mut *irp.as_ptr()
    };
    let overlay = unsafe {
        // SAFETY: Driver context occupies the IRP's active tail-overlay arm.
        &mut irp.Tail.Overlay
    };
    let storage = unsafe {
        // SAFETY: This union arm holds DriverContext, independently of the CSQ list entry.
        &mut overlay.__bindgen_anon_1.__bindgen_anon_1
    };
    &mut storage.DriverContext[2]
}

impl Drop for NotificationPermit {
    #[expect(
        unsafe_code,
        reason = "exclusive permit destruction releases its slot before the final pool lifetime lease"
    )]
    fn drop(&mut self) {
        let slot = unsafe {
            // SAFETY: This unique permit retains the pool through the stored rundown lease.
            self.slot.as_ref()
        };
        let lease = unsafe {
            // SAFETY: No actor or callback can concurrently access this reserved payload.
            (&mut *slot.rundown.get()).take()
        };
        if lease.is_none() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        slot.occupied.store(false, Ordering::Release);
        // No slot access is permitted beyond this point: another dispatch may reuse it, and
        // releasing rundown may permit pool destruction. WDK dequeues before callback entry.
        drop(lease);
    }
}

/// Executes terminal notification at PASSIVE_LEVEL while the volume actor remains available.
/// # Safety
/// `context` must be the unique slot queued by NotificationPermit::queue.
#[expect(
    unsafe_code,
    reason = "the I/O Manager transfers the queued permit to this PASSIVE_LEVEL callback"
)]
unsafe extern "C" fn notify_irp(_device: wdk_sys::PDEVICE_OBJECT, context: wdk_sys::PVOID) {
    let permit = NotificationPermit {
        slot: NonNull::new(context.cast()).unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        }),
    };
    let slot = unsafe {
        // SAFETY: The work queue transferred sole permit ownership to this invocation.
        permit.slot.as_ref()
    };
    let (irp, status) = unsafe {
        // SAFETY: Queue publication initialized the job, and the permit excludes all other access.
        (&mut *slot.job.get()).take()
    }
    .unwrap_or_else(|| KernelWideInconsistency::completion_reactor_state_corruption().bugcheck());
    let _status = irp.finish_completion(status);
    drop(permit);
}
