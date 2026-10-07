//! Pinned execution storage and reference-owned native MDL worker cycles.

use super::super::{IrpCompletion, KernelIrp, MdlCompletion};
use super::fifo::CompletionFifo;
use crate::{
    kernel::{
        fatal::KernelWideInconsistency,
        ffi,
        status::{DriverError, DriverResult},
    },
    memory,
};
use alloc::boxed::Box;
use core::{cell::UnsafeCell, ffi::c_void, marker::PhantomPinned, pin::Pin, ptr::NonNull};
use wdk_sys::{NTSTATUS, PFILE_OBJECT, PIRP};

/// One worker cycle either has no authority or retains its FILE_OBJECT owner.
enum WorkerCycle {
    /// No callback can touch the inbox.
    Idle,
    /// One scheduled/running callback owns the retained file reference.
    Running(PFILE_OBJECT),
}

/// Spin-lock-protected FIFO and its preallocated native execution resource.
struct Inbox {
    /// Reserved before the first MDL acquisition.
    work_item: Option<NonNull<wdk_sys::_IO_WORKITEM>>,
    /// Owns original consuming notifications until exclusive dequeue.
    requests: CompletionFifo,
    /// Worker cycle authority retained independently of queue emptiness.
    cycle: WorkerCycle,
}

/// Address-stable stream-owned completion inbox; C receives only preparation access.
pub(crate) struct MdlCompletionQueue {
    /// Serializes both IRP linkage and the idle-to-running ownership transfer.
    lock: UnsafeCell<wdk_sys::KSPIN_LOCK>,
    /// Mutated only under `lock`.
    inbox: UnsafeCell<Inbox>,
    /// Native callbacks retain this address through the stream lifetime.
    _pin: PhantomPinned,
}

impl MdlCompletionQueue {
    /// Creates dormant storage before the stream header can be published.
    /// # Errors
    /// Returns nonpaged allocation failure without acquiring any native execution resource.
    pub(crate) fn try_new() -> DriverResult<Pin<Box<Self>>> {
        memory::boxed_try_with(|| {
            Ok(Self {
                lock: UnsafeCell::new(0),
                inbox: UnsafeCell::new(Inbox {
                    work_item: None,
                    requests: CompletionFifo::new(),
                    cycle: WorkerCycle::Idle,
                }),
                _pin: PhantomPinned,
            })
        })
        .map(Box::into_pin)
    }

    /// Borrows the stable allocation for native stream construction.
    pub(crate) fn as_ptr(self: Pin<&Self>) -> *mut c_void {
        core::ptr::from_ref(self.get_ref()).cast_mut().cast()
    }

    /// Borrows mutable inbox state under one spin-lock/APC-independent scope.
    #[expect(
        unsafe_code,
        reason = "the callback borrow cannot escape the native spin lock"
    )]
    fn with_inbox<R>(&self, operation: impl FnOnce(&mut Inbox) -> R) -> R {
        let irql = unsafe {
            // SAFETY: The pinned nonpaged lock starts at the WDK zero state.
            ffi::KeAcquireSpinLockRaiseToDpc(self.lock.get())
        };
        let inbox = unsafe {
            // SAFETY: This lock scope uniquely owns all inbox and IRP linkage mutation.
            &mut *self.inbox.get()
        };
        let result = operation(inbox);
        unsafe {
            // SAFETY: This thread acquired the lock and restores the incoming IRQL.
            ffi::KeReleaseSpinLock(self.lock.get(), irql);
        }
        result
    }

    /// Ensures a worker exists before Cc can expose an MDL chain.
    /// # Safety
    /// `file` must remain live for this PASSIVE_LEVEL call and belong to the retaining stream.
    /// # Errors
    /// Returns worker allocation failure before page acquisition.
    #[expect(
        unsafe_code,
        reason = "stream retention covers related-device lookup and worker preparation"
    )]
    unsafe fn prepare(&self, file: PFILE_OBJECT) -> DriverResult<()> {
        if self.with_inbox(|inbox| inbox.work_item.is_some()) {
            return Ok(());
        }
        let device = unsafe {
            // SAFETY: The acquisition IRP retains this FILE_OBJECT and its device.
            ffi::IoGetRelatedDeviceObject(file)
        };
        let candidate = NonNull::new(unsafe {
            // SAFETY: The retained file pins the related device through allocation.
            ffi::IoAllocateWorkItem(device)
        })
        .ok_or(DriverError::InsufficientResources)?;
        let unused = self.with_inbox(|inbox| {
            if inbox.work_item.is_some() {
                Some(candidate)
            } else {
                inbox.work_item = Some(candidate);
                None
            }
        });
        if let Some(unused) = unused {
            unsafe {
                // SAFETY: This losing preparation owns an item that was never published.
                ffi::IoFreeWorkItem(unused.as_ptr());
            }
        }
        Ok(())
    }

    /// Publishes unique completion authority; after success cancellation cannot skip chain return.
    /// # Safety
    /// The caller owns this live unqueued IRP and retains `file` and this queue.
    /// The call is at most DISPATCH_LEVEL. Success consumes IRP completion authority; failure does not.
    /// # Errors
    /// Returns invalid-parameter before publication if the notification has no MDL chain.
    #[expect(
        unsafe_code,
        reason = "FIFO publication transfers the original IRP and a referenced worker-cycle owner"
    )]
    pub(in crate::irp) unsafe fn enqueue(
        &self,
        irp: KernelIrp,
        file: PFILE_OBJECT,
        action: MdlCompletion,
    ) -> DriverResult<()> {
        let has_chain = unsafe {
            // SAFETY: Dispatch still exclusively owns this unqueued original IRP.
            !(*irp.as_ptr()).MdlAddress.is_null()
        };
        if !has_chain {
            return Err(DriverError::InvalidParameter);
        }
        let scheduled = self.with_inbox(|inbox| {
            // A live driver-owned chain proves preparation succeeded. Losing its reserved worker
            // cannot return an ordinary error: chain release at elevated IRQL would then be abandoned.
            let work_item = inbox.work_item.unwrap_or_else(|| {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            });
            irp.mark_pending();
            unsafe {
                // SAFETY: This lock scope transfers the uniquely owned original request.
                inbox.requests.push(irp, action);
            }
            if matches!(inbox.cycle, WorkerCycle::Idle) {
                unsafe {
                    // SAFETY: Dispatch retains file; this reference pins the stream until final callback access.
                    ffi::ObfReferenceObject(file.cast());
                }
                inbox.cycle = WorkerCycle::Running(file);
                Some(work_item)
            } else {
                None
            }
        });
        if let Some(work_item) = scheduled {
            unsafe {
                // SAFETY: The cycle reference retains this pinned inbox until the callback releases it.
                ffi::IoQueueWorkItem(
                    work_item.as_ptr(),
                    Some(worker),
                    wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                    core::ptr::from_ref(self).cast_mut().cast(),
                );
            }
        }
        Ok(())
    }
}

/// Prepares only execution storage; this boundary cannot publish IRPs or grant completion authority.
/// # Safety
/// C must pass the live stream's pinned inbox and retained FILE_OBJECT at PASSIVE_LEVEL.
#[expect(
    unsafe_code,
    reason = "native page acquisition borrows the stream-owned Rust completion inbox"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_prepare_mdl_completion(
    queue: *const MdlCompletionQueue,
    file: PFILE_OBJECT,
) -> NTSTATUS {
    let queue = unsafe {
        // SAFETY: The stream owns this queue until all FILE_OBJECTs retire.
        &*queue
    };
    match unsafe {
        // SAFETY: The native acquisition boundary retains file at PASSIVE_LEVEL.
        queue.prepare(file)
    } {
        Ok(()) => wdk_sys::STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// The joined cycle drains every consuming notification before releasing its FILE_OBJECT.
/// # Safety
/// IoQueueWorkItem transfers a referenced cycle and this pinned queue to the callback.
#[expect(
    unsafe_code,
    reason = "the worker cycle pins the inbox and every queued request until chain consumption"
)]
unsafe extern "C" fn worker(_device: wdk_sys::PDEVICE_OBJECT, context: *mut c_void) {
    let queue = unsafe {
        // SAFETY: The scheduled worker-cycle reference retains this exact pinned queue.
        &*context.cast::<MdlCompletionQueue>()
    };
    loop {
        let next = queue.with_inbox(|inbox| {
            if let Some(next) = inbox.requests.pop() {
                return Ok(next);
            }
            let WorkerCycle::Running(owner) =
                core::mem::replace(&mut inbox.cycle, WorkerCycle::Idle)
            else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            Err(owner)
        });
        let (irp, action) = match next {
            Ok(next) => next,
            Err(owner) => {
                unsafe {
                    // SAFETY: No queue access follows; CLOSE may now destroy the stream and this inbox.
                    ffi::ObfDereferenceObject(owner.cast());
                }
                return;
            }
        };
        let status = unsafe {
            // SAFETY: The worker exclusively owns the chain; native SEH consumes or aborts it.
            ext4win_complete_cache_mdl(irp.as_ptr(), action.action())
        };
        let completion = if status >= wdk_sys::STATUS_SUCCESS {
            IrpCompletion::EMPTY
        } else {
            IrpCompletion::from_native_failure(status)
        };
        let _status = irp.complete(completion);
    }
}

#[expect(
    unsafe_code,
    reason = "the stream owner drops the inbox only after all cycle references have retired"
)]
impl Drop for MdlCompletionQueue {
    fn drop(&mut self) {
        let inbox = self.inbox.get_mut();
        if !inbox.requests.is_empty() || !matches!(inbox.cycle, WorkerCycle::Idle) {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
        if let Some(work_item) = inbox.work_item.take() {
            unsafe {
                // SAFETY: All callbacks retired; this owner releases its preallocated native item once.
                ffi::IoFreeWorkItem(work_item.as_ptr());
            }
        }
    }
}

#[expect(
    unsafe_code,
    reason = "the pinned nonpaged queue is serialized by its native spin lock"
)]
// SAFETY: Mutation and linkage are locked; worker references retain storage across processors.
unsafe impl Send for MdlCompletionQueue {}
#[expect(
    unsafe_code,
    reason = "shared queue access is serialized and cycle references prevent destruction"
)]
// SAFETY: Every shared mutation uses the same spin lock; final destruction requires all cycles to retire.
unsafe impl Sync for MdlCompletionQueue {}

#[expect(
    unsafe_code,
    reason = "native code only consumes Cc chains under the required SEH boundary"
)]
unsafe extern "system" {
    fn ext4win_complete_cache_mdl(irp: PIRP, action: super::super::MdlAction) -> NTSTATUS;
}
