//! Preallocated outer completions. Paging DPCs cannot be starved by Cache Manager workers.

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
    pub(super) fn try_new(
        device: KernelDevice,
        reactor: NonNull<super::reactor::CompletionReactor>,
    ) -> DriverResult<Self> {
        let mut slots = KernelVec::try_with_capacity(super::scheduler::MAX_OPERATIONS)?;
        for class in [
            super::scheduler::ExecutionClass::Ordinary,
            super::scheduler::ExecutionClass::Paging,
            super::scheduler::ExecutionClass::Finalization,
        ] {
            for _ in class.slots() {
                slots
                    .push_reserved_owned(NotificationSlot::try_new(device, reactor, class)?)
                    .map_err(|failure| failure.into_parts().0)?;
            }
        }
        let pool = Self { slots };
        for slot in pool.slots.iter() {
            slot.initialize_callback();
        }
        Ok(pool)
    }

    /// Reserves one notification through its terminal callback, independently of actor slots.
    /// # Errors
    /// Returns resource exhaustion when all notification slots remain owned, or shutdown when
    /// rundown admission has closed. No request effect has occurred at this boundary.
    #[expect(
        unsafe_code,
        reason = "atomic reservation grants unique payload access and the rundown lease pins the pool"
    )]
    pub(super) fn reserve(
        &self,
        rundown: &CompletionRundown,
        class: super::scheduler::ExecutionClass,
    ) -> DriverResult<NotificationPermit> {
        let lease = rundown
            .acquire()?
            .ok_or(DriverError::InvalidDeviceRequest)?;
        for (index, slot) in self.slots.iter().enumerate() {
            if !class.slots().contains(&index) {
                continue;
            }
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
    /// Actor wake destination retained by stored or callback-owned rundown.
    reactor: NonNull<super::reactor::CompletionReactor>,
    /// Native callback storage whose queue matches the request's progress responsibility.
    callback: NotificationCallback,
    /// Exclusive reservation spanning actor admission through native notification publication.
    occupied: AtomicBool,
    /// Destination lifetime retained even while the reactor has no active operation for this IRP.
    rundown: UnsafeCell<Option<CompletionRundownLease>>,
    /// Terminal notification installed once immediately before queue publication.
    job: UnsafeCell<Option<NotificationJob>>,
}

/// Paging completion is DISPATCH_LEVEL-safe and independent of blocking native cache workers.
enum NotificationCallback {
    /// Ordinary and terminal handle notifications may call PASSIVE_LEVEL native routines.
    Worker(NonNull<wdk_sys::_IO_WORKITEM>),
    /// Resident final-address DPC storage for paging read/write completion.
    Paging(UnsafeCell<wdk_sys::KDPC>),
}

/// Mutually exclusive terminal ownership selected before the actor releases its slot.
enum NotificationJob {
    /// Notify upper drivers of a prepared status.
    Complete(KernelIrp, wdk_sys::NTSTATUS),
    /// Submit the original query-remove IRP; lower drivers then own completion.
    QueryRemove(super::lifecycle::PnpSubmission),
}

impl NotificationSlot {
    /// Allocates the native work item while device initialization owns rollback.
    /// # Errors
    /// Returns insufficient resources if the I/O Manager cannot allocate a work item.
    #[expect(
        unsafe_code,
        reason = "the initializing device remains alive through pool construction and destruction"
    )]
    fn try_new(
        device: KernelDevice,
        reactor: NonNull<super::reactor::CompletionReactor>,
        class: super::scheduler::ExecutionClass,
    ) -> DriverResult<Self> {
        let callback = if class == super::scheduler::ExecutionClass::Paging {
            NotificationCallback::Paging(UnsafeCell::new(wdk_sys::KDPC::default()))
        } else {
            let work_item = unsafe {
                // SAFETY: Initialization retains this live device; no callback is published.
                ffi::IoAllocateWorkItem(device.as_ptr())
            };
            NotificationCallback::Worker(
                NonNull::new(work_item).ok_or(DriverError::InsufficientResources)?,
            )
        };
        Ok(Self {
            reactor,
            callback,
            occupied: AtomicBool::new(false),
            rundown: UnsafeCell::new(None),
            job: UnsafeCell::new(None),
        })
    }
    /// Initializes resident DPC identity only after all slots occupy their final allocation.
    #[expect(
        unsafe_code,
        reason = "pool construction retains exclusive final-address DPC initialization authority"
    )]
    fn initialize_callback(&self) {
        if let NotificationCallback::Paging(dpc) = &self.callback {
            unsafe {
                // SAFETY: This resident slot will never move and no request can yet acquire it.
                ffi::KeInitializeDpc(
                    dpc.get(),
                    Some(notify_paging),
                    core::ptr::from_ref(self).cast_mut().cast(),
                );
            }
        }
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
        if let NotificationCallback::Worker(work_item) = &self.callback {
            unsafe {
                // SAFETY: Rollback or completed rundown proves the work item is not queued.
                ffi::IoFreeWorkItem(work_item.as_ptr());
            }
        }
        // Paging DPC storage is resident; joined notification rundown and DPC drain precede drop.
    }
}

/// Unique callback reservation transferred from an admitted IRP to terminal notification.
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
    /// Queues terminal notification after actor borrows, cancellation and handle lanes are gone.
    pub(super) fn queue(self, irp: KernelIrp, status: wdk_sys::NTSTATUS) {
        self.queue_job(NotificationJob::Complete(irp, status));
    }

    /// Uses the reserved worker to transfer an original PnP request outside the actor.
    pub(super) fn queue_query_remove(self, forwarding: super::lifecycle::PnpSubmission) {
        self.queue_job(NotificationJob::QueryRemove(forwarding));
    }

    /// Publishes the sole consuming action; its preallocated work item cannot fail admission.
    #[expect(
        unsafe_code,
        reason = "the unique notification permit publishes one retained job to the native queue"
    )]
    fn queue_job(self, job: NotificationJob) {
        let slot = unsafe {
            // SAFETY: This permit retains and exclusively owns the reserved slot.
            self.slot.as_ref()
        };
        unsafe {
            // SAFETY: The slot is not queued, and this is its sole terminal job publication.
            *slot.job.get() = Some(job);
        }
        let context = self.slot.as_ptr().cast();
        // Copy only native queue identity before publication permits callback-driven slot reuse.
        let (work_item, dpc) = match &slot.callback {
            NotificationCallback::Worker(work_item) => (Some(*work_item), core::ptr::null_mut()),
            NotificationCallback::Paging(dpc) => (None, dpc.get()),
        };
        core::mem::forget(self);
        if let Some(work_item) = work_item {
            unsafe {
                // SAFETY: The unique permit owns an unqueued work item and its retained job.
                ffi::IoQueueWorkItem(
                    work_item.as_ptr(),
                    Some(notify_irp),
                    wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                    context,
                );
            }
        } else {
            let queued = unsafe {
                // SAFETY: The unique permit owns this resident unqueued DPC and its retained job.
                ffi::KeInsertQueueDpc(dpc, core::ptr::null_mut(), core::ptr::null_mut())
            };
            if queued == 0 {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
    }
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

/// Copies terminal ownership out and releases callback storage before upper-driver reentry.
/// # Safety
/// Context must be the unique slot published once through NotificationPermit::queue_job.
#[expect(
    unsafe_code,
    reason = "native callback entry owns all reserved payloads until atomic slot release"
)]
unsafe fn take_notification(context: wdk_sys::PVOID) -> (NotificationJob, CompletionRundownLease) {
    let permit = NotificationPermit {
        slot: NonNull::new(context.cast()).unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        }),
    };
    let slot = unsafe {
        // SAFETY: The work queue transferred sole permit ownership to this invocation.
        permit.slot.as_ref()
    };
    let job = unsafe {
        // SAFETY: Queue publication initialized the job, and the permit excludes all other access.
        (&mut *slot.job.get()).take()
    }
    .unwrap_or_else(|| KernelWideInconsistency::completion_reactor_state_corruption().bugcheck());
    let lease = unsafe {
        // SAFETY: This callback uniquely owns payloads before the slot is released.
        (&mut *slot.rundown.get()).take()
    }
    .unwrap_or_else(|| KernelWideInconsistency::completion_reactor_state_corruption().bugcheck());
    let reactor = slot.reactor;
    slot.occupied.store(false, Ordering::Release);
    core::mem::forget(permit);
    unsafe {
        // SAFETY: Callback-owned rundown pins the actor after slot reuse is enabled.
        reactor.as_ref().notification_released();
    }
    (job, lease)
}

/// Executes terminal notification at PASSIVE_LEVEL while the volume actor remains available.
/// # Safety
/// `context` must be the unique slot queued by NotificationPermit::queue.
#[expect(
    unsafe_code,
    reason = "the I/O Manager transfers the queued permit to this PASSIVE_LEVEL callback"
)]
unsafe extern "C" fn notify_irp(_device: wdk_sys::PDEVICE_OBJECT, context: wdk_sys::PVOID) {
    let (job, lease) = unsafe {
        // SAFETY: Work queue entry receives the unique published notification slot.
        take_notification(context)
    };
    // No slot access follows release; reentrant completion may reuse the same work item.
    match job {
        NotificationJob::Complete(irp, status) => {
            let _status = irp.finish_completion(status);
        }
        NotificationJob::QueryRemove(forwarding) => forwarding.submit(),
    }
    drop(lease);
}

/// Routing distinguishes actor ownership from a never-started queue rejection.
#[derive(Debug)]
pub(super) enum IrpNotification {
    /// Upper completion must run outside the actor's state transition.
    Worker(NotificationPermit),
    /// Queue removal owns completion outside the actor and needs no worker.
    Dispatch,
    /// Actor-originated cancellation retains an IRP backlog until a worker can consume it.
    Deferred(NonNull<super::reactor::CompletionReactor>),
}
impl IrpNotification {
    /// Dispatch routes complete immediately; actor routes consume their prepared worker.
    #[expect(
        unsafe_code,
        reason = "the actor is the sole producer of deferred queue completions and retains its own lifetime"
    )]
    pub(super) fn queue(self, irp: KernelIrp, status: wdk_sys::NTSTATUS) {
        match self {
            Self::Worker(permit) => permit.queue(irp, status),
            Self::Dispatch => {
                let _status = irp.finish_completion(status);
            }
            Self::Deferred(reactor) => unsafe {
                // SAFETY: Deferred routing is created only during this retaining actor's transition.
                reactor.as_ref().defer_notification(irp);
            },
        }
    }
    /// Query removal uses its admitted worker to cross the actor boundary.
    pub(super) fn queue_query_remove(self, forwarding: super::lifecycle::PnpSubmission) {
        match self {
            Self::Worker(permit) => permit.queue_query_remove(forwarding),
            Self::Dispatch | Self::Deferred(_) => {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            }
        }
    }
}

/// Paging completion never waits for the system workers that may be blocked on this same IRP.
/// # Safety
/// The native DPC must return the final-address slot initialized by NotificationSlot.
#[expect(
    unsafe_code,
    reason = "the DPC owns a status-prepared paging IRP and resident notification slot"
)]
unsafe extern "C" fn notify_paging(
    _dpc: *mut wdk_sys::KDPC,
    context: wdk_sys::PVOID,
    _first: wdk_sys::PVOID,
    _second: wdk_sys::PVOID,
) {
    let (job, lease) = unsafe {
        // SAFETY: DPC publication uniquely transferred this paging slot and its lifetime lease.
        take_notification(context)
    };
    let NotificationJob::Complete(irp, status) = job else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let _status = irp.finish_completion(status);
    drop(lease);
}
