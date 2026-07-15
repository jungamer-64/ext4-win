//! PASSIVE_LEVEL future executor and cancel-safe IRP mailbox.

use alloc::boxed::Box;
#[cfg(not(test))]
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use core::{cell::UnsafeCell, ffi::c_void, future::Future, pin::Pin, ptr::NonNull};

use wdk_sys::{LIST_ENTRY, NTSTATUS, PIO_WORKITEM, PIRP, PLIST_ENTRY, PVOID};
#[cfg(not(test))]
use wdk_sys::{PIO_CSQ, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::ffi;
#[cfg(not(test))]
use crate::{kernel::fatal::KernelWideInconsistency, memory};
use crate::{
    kernel::status::{DriverError, DriverResult},
    state::{KernelDevice, KernelFileObject},
};

use super::{KernelIrp, OwnedIrp, PendingIrp, ReceivedIrp};

/// One pinned request continuation owned by a device execution lane.
type DeviceTask = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// PASSIVE_LEVEL worker scheduling state protected by the executor spin lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerState {
    /// No work item is queued and no task is being polled.
    Dormant,
    /// Exactly one work item is queued but has not entered its callback.
    Queued,
    /// Exactly one worker is polling the active task.
    Polling,
    /// A wake occurred while the active worker was polling.
    PollingWoken,
}

impl WorkerState {
    /// Records a wake and returns whether a system work item must be queued.
    fn request_poll(&mut self) -> bool {
        match self {
            Self::Dormant => {
                *self = Self::Queued;
                true
            }
            Self::Queued | Self::PollingWoken => false,
            Self::Polling => {
                *self = Self::PollingWoken;
                false
            }
        }
    }

    /// Transfers the single queued-work-item right into the polling worker.
    fn enter_worker(&mut self) -> bool {
        if *self != Self::Queued {
            return false;
        }
        *self = Self::Polling;
        true
    }

    /// Resolves one pending poll without losing a concurrent wake.
    fn settle_pending(&mut self) -> WorkerContinuation {
        match self {
            Self::Polling => {
                *self = Self::Dormant;
                WorkerContinuation::Sleep
            }
            Self::PollingWoken => {
                *self = Self::Polling;
                WorkerContinuation::Repoll
            }
            Self::Dormant | Self::Queued => WorkerContinuation::Invalid,
        }
    }
}

/// Decision made after an active task returns `Poll::Pending`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerContinuation {
    /// No wake raced with the poll; the worker relinquished execution ownership.
    Sleep,
    /// A wake raced with the poll; the same worker must poll again.
    Repoll,
    /// The protected state machine was already corrupted.
    Invalid,
}

/// Device-owned executor that serializes filesystem request futures.
///
/// The embedded CSQ is the first field because the WDK callback API supplies only its address.
/// Every field mutated outside initialization is either protected by `lock` or confined to the one
/// worker represented by [`WorkerState::Polling`].
#[repr(C)]
pub(crate) struct DeviceExecutor {
    /// Cancel-safe queue callback table. This must remain the first field.
    csq: wdk_sys::IO_CSQ,
    /// Spin lock shared by CSQ callbacks and worker scheduling transitions.
    lock: wdk_sys::KSPIN_LOCK,
    /// FIFO of pending IRPs using `IRP.Tail.Overlay.ListEntry`.
    list_head: UnsafeCell<LIST_ENTRY>,
    /// System work item whose callback always runs at `PASSIVE_LEVEL`.
    work_item: PIO_WORKITEM,
    /// Wake/poll state protected by `lock`.
    worker_state: UnsafeCell<WorkerState>,
    /// Pinned request future accessed only by the unique polling worker.
    active: UnsafeCell<Option<DeviceTask>>,
    /// Device object that owns this stable executor storage.
    device: KernelDevice,
}

impl DeviceExecutor {
    /// Builds unlinked executor storage for placement in a unit-test device extension.
    #[cfg(test)]
    pub(super) fn test_storage(device: KernelDevice) -> Self {
        Self {
            csq: wdk_sys::IO_CSQ::default(),
            lock: 0,
            list_head: UnsafeCell::new(LIST_ENTRY::default()),
            work_item: core::ptr::null_mut(),
            worker_state: UnsafeCell::new(WorkerState::Dormant),
            active: UnsafeCell::new(None),
            device,
        }
    }

    /// Initializes self-referential list links after test storage reaches its stable address.
    #[cfg(test)]
    pub(super) fn initialize_test_links(&self) {
        initialize_list_head(self.list_head.get());
    }

    /// Removes one FIFO IRP without invoking unavailable kernel CSQ services in tests.
    #[cfg(test)]
    pub(super) fn test_remove_next_irp(&self, context: PVOID) -> PIRP {
        self.remove_next_irp(context)
    }

    /// Returns whether a unit-test wake has reserved exactly one worker callback.
    #[cfg(test)]
    pub(super) fn test_worker_is_queued(&self) -> bool {
        self.with_worker_state(|state| *state == WorkerState::Queued)
    }

    /// Returns whether a unit-test executor has no reserved worker callback.
    #[cfg(test)]
    pub(super) fn test_worker_is_dormant(&self) -> bool {
        self.with_worker_state(|state| *state == WorkerState::Dormant)
    }

    /// Initializes an executor directly inside stable device-extension storage.
    /// # Safety
    ///
    /// `executor` must point to writable device-extension memory that will not move before
    /// [`Self::release_at`]. The owning device must remain alive throughout that interval.
    /// # Errors
    ///
    /// Returns an error when the CSQ or its PASSIVE_LEVEL work item cannot be initialized.
    pub(crate) unsafe fn initialize_at(
        executor: *mut Self,
        device: KernelDevice,
    ) -> DriverResult<()> {
        unsafe {
            // SAFETY: The caller supplies exclusive writable device-extension storage.
            core::ptr::write(
                executor,
                Self {
                    csq: wdk_sys::IO_CSQ::default(),
                    lock: 0,
                    list_head: UnsafeCell::new(LIST_ENTRY::default()),
                    work_item: core::ptr::null_mut(),
                    worker_state: UnsafeCell::new(WorkerState::Dormant),
                    active: UnsafeCell::new(None),
                    device,
                },
            );
        }
        let executor = unsafe {
            // SAFETY: The complete executor value was written immediately above.
            executor.as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        initialize_list_head(executor.list_head.get());

        #[cfg(not(test))]
        {
            unsafe {
                // SAFETY: The spin lock is stable executor-owned storage.
                ffi::KeInitializeSpinLock(core::ptr::addr_of!(executor.lock).cast_mut());
            }
            let status = unsafe {
                // SAFETY: `csq` is the first stable field and every callback recovers this exact
                // executor before accessing state protected by its spin lock.
                ffi::IoCsqInitialize(
                    executor.csq_ptr(),
                    Some(csq_insert_irp),
                    Some(csq_remove_irp),
                    Some(csq_peek_next_irp),
                    Some(csq_acquire_lock),
                    Some(csq_release_lock),
                    Some(csq_complete_canceled_irp),
                )
            };
            if status < STATUS_SUCCESS {
                return Err(DriverError::InsufficientResources);
            }
            let work_item = unsafe {
                // SAFETY: The live device owns this executor and therefore the work item.
                ffi::IoAllocateWorkItem(device.as_ptr())
            };
            let Some(work_item) = NonNull::new(work_item) else {
                return Err(DriverError::InsufficientResources);
            };
            unsafe {
                // SAFETY: Initialization retains exclusive access before the device is published.
                core::ptr::addr_of!(executor.work_item)
                    .cast_mut()
                    .write(work_item.as_ptr());
            }
        }

        Ok(())
    }

    /// Releases executor-owned resources in device-extension storage.
    /// # Safety
    ///
    /// No dispatch, completion callback, queued IRP, work item, active task, or lower request may
    /// still reference this executor.
    pub(crate) unsafe fn release_at(executor: *mut Self) {
        let Some(executor) = (unsafe {
            // SAFETY: The caller guarantees exclusive teardown access.
            executor.as_mut()
        }) else {
            return;
        };
        #[cfg(not(test))]
        if let Some(work_item) = NonNull::new(executor.work_item) {
            unsafe {
                // SAFETY: This work item was allocated once during successful initialization and
                // the teardown precondition excludes any queued callback.
                ffi::IoFreeWorkItem(work_item.as_ptr());
            }
            executor.work_item = core::ptr::null_mut();
        }
        unsafe {
            // SAFETY: Teardown is exclusive and releases any Rust-owned task allocation exactly
            // once before the I/O Manager frees the extension bytes.
            core::ptr::drop_in_place(executor);
        }
    }

    /// Marks an async-capable IRP pending, inserts it into this device mailbox, and schedules its
    /// execution lane.
    pub(crate) fn receive(received: ReceivedIrp) -> NTSTATUS {
        let executor = match Self::from_device(received.device()) {
            Ok(executor) => executor,
            Err(error) => return received.complete_result(Err(error)),
        };
        let pending = match PendingIrp::from_received(received) {
            Ok(pending) => pending,
            Err(error) => return error.complete(),
        };
        let status = pending.dispatch_status();
        let executor = unsafe {
            // SAFETY: The device extension remains stable for the pending IRP lifetime.
            executor.as_ref()
        };
        executor.enqueue(pending);
        status
    }

    /// Cancels every not-yet-active IRP for one cleaned-up FILE_OBJECT.
    /// # Errors
    ///
    /// Returns an error when the device does not contain a driver executor.
    pub(crate) fn cancel_file_object(
        device: KernelDevice,
        file_object: KernelFileObject,
    ) -> DriverResult<()> {
        let executor = Self::from_device(device)?;
        let executor = unsafe {
            // SAFETY: Cleanup retains the live device extension throughout queue cancellation.
            executor.as_ref()
        };
        let context = file_object.as_ptr().cast::<c_void>();
        loop {
            let irp = executor.remove_next_irp(context);
            if irp.is_null() {
                return Ok(());
            }
            if let Some(owned) = OwnedIrp::from_raw(executor.device, irp) {
                let _status = owned.complete_cancelled();
            }
        }
    }

    /// Returns the executor embedded at offset zero in a driver device extension.
    /// # Errors
    ///
    /// Returns an error when the device object or its driver-owned extension is absent.
    fn from_device(device: KernelDevice) -> DriverResult<NonNull<Self>> {
        let object = unsafe {
            // SAFETY: The typed device pointer remains live during dispatch and is read only for
            // its stable driver-owned extension pointer.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        NonNull::new(object.DeviceExtension.cast::<Self>()).ok_or(DriverError::InvalidParameter)
    }

    /// Returns the embedded CSQ address.
    #[cfg(not(test))]
    fn csq_ptr(&self) -> PIO_CSQ {
        core::ptr::addr_of!(self.csq).cast_mut()
    }

    /// Inserts a pending IRP through the cancel-safe queue and records a worker wake.
    fn enqueue(&self, pending: PendingIrp) {
        let irp = pending.as_raw_irp();
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The typestate proves this IRP is pending, and the CSQ now owns its
            // cancellation-safe mailbox membership.
            ffi::IoCsqInsertIrp(
                self.csq_ptr(),
                irp,
                core::ptr::null_mut::<wdk_sys::IO_CSQ_IRP_CONTEXT>(),
            );
        }
        #[cfg(test)]
        self.insert_irp(irp);
        self.request_poll();
    }

    /// Records that the active task must be polled from a PASSIVE_LEVEL worker.
    fn request_poll(&self) {
        let should_queue = self.with_worker_state(WorkerState::request_poll);
        #[cfg(not(test))]
        if should_queue {
            unsafe {
                // SAFETY: The transition to `Queued` grants exactly one work-item callback the
                // right to enter polling, and this executor address is stable device storage.
                ffi::IoQueueWorkItem(
                    self.work_item,
                    Some(device_executor_worker),
                    wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                    core::ptr::from_ref(self).cast_mut().cast::<c_void>(),
                );
            }
        }
        #[cfg(test)]
        let _: bool = should_queue;
    }

    /// Runs one closure while holding the executor spin lock.
    fn with_worker_state<T>(&self, operation: impl FnOnce(&mut WorkerState) -> T) -> T {
        #[cfg(not(test))]
        {
            let old_irql = unsafe {
                // SAFETY: The spin lock belongs to this stable executor.
                ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
            };
            let result = operation(unsafe {
                // SAFETY: The spin lock serializes every access to `worker_state`.
                &mut *self.worker_state.get()
            });
            unsafe {
                // SAFETY: Releases the exact acquisition above at its saved IRQL.
                ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
            }
            result
        }
        #[cfg(test)]
        {
            operation(unsafe {
                // SAFETY: Executor unit tests access this state from one thread only.
                &mut *self.worker_state.get()
            })
        }
    }

    /// Polls request futures until one awaits an unwoken lower operation or the mailbox is empty.
    #[cfg(not(test))]
    fn run(&self) {
        if !self.with_worker_state(WorkerState::enter_worker) {
            KernelWideInconsistency::async_executor_state_corruption().bugcheck();
        }
        loop {
            if unsafe {
                // SAFETY: `Polling` grants this worker exclusive access to the active slot.
                (*self.active.get()).is_none()
            } && !self.install_next_task()
            {
                match self.with_worker_state(WorkerState::settle_pending) {
                    WorkerContinuation::Repoll => continue,
                    WorkerContinuation::Sleep => return,
                    WorkerContinuation::Invalid => {
                        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
                    }
                }
            }

            let poll = {
                let waker = self.waker();
                let mut context = Context::from_waker(&waker);
                let active = unsafe {
                    // SAFETY: Only the unique `Polling` worker accesses the pinned active task.
                    &mut *self.active.get()
                };
                let Some(task) = active.as_mut() else {
                    continue;
                };
                task.as_mut().poll(&mut context)
            };
            match poll {
                Poll::Ready(()) => unsafe {
                    // SAFETY: This is the unique polling worker, and a ready task retains no
                    // terminal IRP authority after its async body returns.
                    *self.active.get() = None;
                },
                Poll::Pending => match self.with_worker_state(WorkerState::settle_pending) {
                    WorkerContinuation::Repoll => {}
                    WorkerContinuation::Sleep => return,
                    WorkerContinuation::Invalid => {
                        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
                    }
                },
            }
        }
    }

    /// Removes the next pending IRP and installs its ownership-bearing future.
    #[cfg(not(test))]
    fn install_next_task(&self) -> bool {
        loop {
            let irp = self.remove_next_irp(core::ptr::null_mut());
            if irp.is_null() {
                return false;
            }
            let Some(owned) = OwnedIrp::from_raw(self.device, irp) else {
                continue;
            };
            let task = memory::boxed_try_map(owned, |owned| async move {
                crate::request::dispatch::execute_owned(owned).await;
            });
            match task {
                Ok(task) => {
                    let task: DeviceTask = Box::into_pin(task);
                    unsafe {
                        // SAFETY: This worker owns the empty active slot under `Polling`.
                        *self.active.get() = Some(task);
                    }
                    return true;
                }
                Err(error) => {
                    let (error, owned) = error.into_parts();
                    let _status = owned.complete_result(Err(error));
                }
            }
        }
    }

    /// Builds the non-owning waker used only while this stable executor remains live.
    #[cfg(not(test))]
    fn waker(&self) -> Waker {
        unsafe {
            // SAFETY: Device teardown excludes active tasks and lower completions, so every cloned
            // raw waker is dropped before this stable executor storage is released.
            Waker::from_raw(RawWaker::new(
                core::ptr::from_ref(self).cast::<()>(),
                &EXECUTOR_WAKER_VTABLE,
            ))
        }
    }

    /// Removes the next queued IRP matching an optional FILE_OBJECT context.
    fn remove_next_irp(&self, context: PVOID) -> PIRP {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The CSQ serializes removal with cancellation and insertion.
            ffi::IoCsqRemoveNextIrp(self.csq_ptr(), context)
        }
        #[cfg(test)]
        {
            let irp = self.peek_next_irp(core::ptr::null_mut(), context);
            if !irp.is_null() {
                self.remove_irp(irp);
            }
            irp
        }
    }

    /// Inserts one IRP at the FIFO tail while the CSQ lock is held.
    fn insert_irp(&self, irp: PIRP) {
        let Some(entry) = irp_list_entry(irp) else {
            return;
        };
        insert_tail_list(self.list_head.get(), entry);
    }

    /// Removes one IRP from the FIFO while the CSQ lock is held.
    fn remove_irp(&self, irp: PIRP) {
        let Some(entry) = irp_list_entry(irp) else {
            return;
        };
        remove_entry_list(entry);
    }

    /// Finds the next FIFO IRP matching an optional FILE_OBJECT context.
    fn peek_next_irp(&self, irp: PIRP, context: PVOID) -> PIRP {
        let head = self.list_head.get();
        let mut entry = if irp.is_null() {
            unsafe {
                // SAFETY: The executor list head is initialized and the CSQ lock is held.
                (*head).Flink
            }
        } else {
            let Some(entry) = irp_list_entry(irp) else {
                return core::ptr::null_mut();
            };
            unsafe {
                // SAFETY: The supplied IRP is currently linked under the CSQ lock.
                (*entry).Flink
            }
        };
        while entry != head {
            let candidate = irp_from_list_entry(entry);
            if irp_matches_context(candidate, context) {
                return candidate;
            }
            entry = unsafe {
                // SAFETY: `entry` is a live node in the initialized intrusive list.
                (*entry).Flink
            };
        }
        core::ptr::null_mut()
    }
}

// SAFETY: The device extension is stable and all shared mutation follows the spin-lock or unique
// polling-worker disciplines documented on each `UnsafeCell` field.
unsafe impl Sync for DeviceExecutor {}

/// Raw-waker clone retains the same non-owning stable executor address.
/// # Safety
///
/// `data` must identify a live, device-stable `DeviceExecutor` whose teardown is excluded until
/// every raw-waker callback has finished.
#[cfg(not(test))]
unsafe fn executor_waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &EXECUTOR_WAKER_VTABLE)
}

/// Raw-waker wake records a PASSIVE_LEVEL poll request.
/// # Safety
///
/// `data` must identify a live, device-stable `DeviceExecutor` whose work item remains allocated.
#[cfg(not(test))]
unsafe fn executor_waker_wake(data: *const ()) {
    let Some(executor) = NonNull::new(data.cast_mut().cast::<DeviceExecutor>()) else {
        return;
    };
    unsafe {
        // SAFETY: The raw-waker contract keeps the stable executor alive until every clone drops.
        executor.as_ref()
    }
    .request_poll();
}

/// Raw-waker by-reference wake has identical scheduling semantics.
/// # Safety
///
/// `data` must satisfy the live-executor contract of `executor_waker_wake` and remains owned by
/// the caller after this function returns.
#[cfg(not(test))]
unsafe fn executor_waker_wake_by_ref(data: *const ()) {
    unsafe {
        // SAFETY: This forwards the same live non-owning raw-waker context without consuming it.
        executor_waker_wake(data);
    }
}

/// Raw-waker drop is a no-op because device storage, not the waker, owns the executor.
/// # Safety
///
/// `data` must be the non-owning executor address installed by `DeviceExecutor::waker`; no
/// executor ownership is transferred through the raw waker.
#[cfg(not(test))]
unsafe fn executor_waker_drop(_data: *const ()) {}

/// Vtable for executor-address wakers stored in lower completion state.
#[cfg(not(test))]
static EXECUTOR_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    executor_waker_clone,
    executor_waker_wake,
    executor_waker_wake_by_ref,
    executor_waker_drop,
);

#[cfg(not(test))]
/// PASSIVE_LEVEL system work-item callback.
/// # Safety
///
/// `context` must be the stable `DeviceExecutor` address passed to `IoQueueWorkItem`, and device
/// teardown must remain excluded for the duration of the callback.
unsafe extern "C" fn device_executor_worker(_device: wdk_sys::PDEVICE_OBJECT, context: PVOID) {
    let Some(executor) = NonNull::new(context.cast::<DeviceExecutor>()) else {
        return;
    };
    unsafe {
        // SAFETY: `IoQueueWorkItem` received this stable executor address as its context.
        executor.as_ref()
    }
    .run();
}

#[cfg(not(test))]
/// CSQ insertion callback.
/// # Safety
///
/// `csq` must be the first-field CSQ of a live executor and `irp` must be an unlinked pending IRP
/// handed to this callback by the I/O Manager while the CSQ lock is held.
unsafe extern "C" fn csq_insert_irp(csq: PIO_CSQ, irp: PIRP) {
    if let Some(executor) = unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    } {
        executor.insert_irp(irp);
    }
}

#[cfg(not(test))]
/// CSQ removal callback.
/// # Safety
///
/// `csq` must belong to a live executor and `irp` must currently be linked in that executor's
/// queue while the CSQ lock is held.
unsafe extern "C" fn csq_remove_irp(csq: PIO_CSQ, irp: PIRP) {
    if let Some(executor) = unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    } {
        executor.remove_irp(irp);
    }
}

#[cfg(not(test))]
/// CSQ FIFO peek callback.
/// # Safety
///
/// `csq` must belong to a live executor; a non-null `irp` must be linked in that queue, and a
/// non-null `context` must be a FILE_OBJECT identity supplied by the I/O Manager.
unsafe extern "C" fn csq_peek_next_irp(csq: PIO_CSQ, irp: PIRP, context: PVOID) -> PIRP {
    unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }
    .map_or(core::ptr::null_mut(), |executor| {
        executor.peek_next_irp(irp, context)
    })
}

#[cfg(not(test))]
/// CSQ spin-lock acquisition callback.
/// # Safety
///
/// `csq` must belong to a live executor and `irql` must point to writable saved-IRQL storage
/// supplied by the I/O Manager.
unsafe extern "C" fn csq_acquire_lock(csq: PIO_CSQ, irql: wdk_sys::PKIRQL) {
    let Some(executor) = (unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }) else {
        return;
    };
    let Some(irql) = (unsafe {
        // SAFETY: The CSQ framework supplies writable saved-IRQL storage.
        irql.as_mut()
    }) else {
        return;
    };
    *irql = unsafe {
        // SAFETY: This lock belongs to the recovered executor.
        ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(executor.lock).cast_mut())
    };
}

#[cfg(not(test))]
/// CSQ spin-lock release callback.
/// # Safety
///
/// `csq` must identify the executor whose lock was acquired by `csq_acquire_lock`, and `irql`
/// must be the value saved by that acquisition.
unsafe extern "C" fn csq_release_lock(csq: PIO_CSQ, irql: wdk_sys::KIRQL) {
    let Some(executor) = (unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }) else {
        return;
    };
    unsafe {
        // SAFETY: This releases the acquisition performed by `csq_acquire_lock`.
        ffi::KeReleaseSpinLock(core::ptr::addr_of!(executor.lock).cast_mut(), irql);
    }
}

#[cfg(not(test))]
/// CSQ cancellation callback that consumes the removed IRP's terminal authority.
/// # Safety
///
/// `csq` must belong to a live executor and `irp` must be the canceled IRP atomically removed by
/// the CSQ framework, with terminal completion authority transferred to this callback.
unsafe extern "C" fn csq_complete_canceled_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(executor) = (unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }) else {
        return;
    };
    if let Some(owned) = OwnedIrp::from_raw(executor.device, irp) {
        let _status = owned.complete_cancelled();
    }
}

#[cfg(not(test))]
/// Recovers the containing executor from its first-field CSQ pointer.
/// # Safety
///
/// `csq` must point to the first field of a live `DeviceExecutor` for the returned borrow's full
/// lifetime.
unsafe fn executor_from_csq<'a>(csq: PIO_CSQ) -> Option<&'a DeviceExecutor> {
    let executor = NonNull::new(csq.cast::<DeviceExecutor>())?;
    Some(unsafe {
        // SAFETY: Layout guarantees that the first-field CSQ and its containing executor share an
        // address, and the WDK callback contract keeps that executor live.
        executor.as_ref()
    })
}

/// Initializes one intrusive-list head.
fn initialize_list_head(head: PLIST_ENTRY) {
    let head = unsafe {
        // SAFETY: The caller supplies writable list-head storage.
        &mut *head
    };
    head.Flink = core::ptr::from_mut(head);
    head.Blink = core::ptr::from_mut(head);
}

/// Inserts one entry immediately before the list head.
fn insert_tail_list(head: PLIST_ENTRY, entry: PLIST_ENTRY) {
    let head_ref = unsafe {
        // SAFETY: `head` is an initialized list head protected by the CSQ lock.
        &mut *head
    };
    let previous = head_ref.Blink;
    let entry_ref = unsafe {
        // SAFETY: `entry` is currently unlinked and protected by the CSQ lock.
        &mut *entry
    };
    entry_ref.Flink = head;
    entry_ref.Blink = previous;
    unsafe {
        // SAFETY: `previous` is the initialized list's current tail.
        (*previous).Flink = entry;
    }
    head_ref.Blink = entry;
}

/// Removes one entry from its initialized intrusive list.
fn remove_entry_list(entry: PLIST_ENTRY) {
    let entry_ref = unsafe {
        // SAFETY: `entry` is linked in an initialized list under the CSQ lock.
        &mut *entry
    };
    let previous = entry_ref.Blink;
    let next = entry_ref.Flink;
    unsafe {
        // SAFETY: `previous` belongs to the same initialized list and remains live under the lock.
        (*previous).Flink = next;
    }
    unsafe {
        // SAFETY: `next` belongs to the same initialized list and remains live under the lock.
        (*next).Blink = previous;
    }
    initialize_list_head(entry);
}

/// Returns the intrusive list entry embedded in one pending IRP.
fn irp_list_entry(irp: PIRP) -> Option<PLIST_ENTRY> {
    let mut irp = NonNull::new(irp)?;
    Some(unsafe {
        // SAFETY: The I/O Manager keeps the pending IRP live while this driver queues it.
        core::ptr::addr_of_mut!(irp.as_mut().Tail.Overlay.__bindgen_anon_2.ListEntry)
    })
}

/// Offset of `IRP.Tail.Overlay.ListEntry` from its containing IRP.
const IRP_LIST_ENTRY_OFFSET: usize = core::mem::offset_of!(wdk_sys::IRP, Tail)
    + core::mem::offset_of!(wdk_sys::_IRP__bindgen_ty_4__bindgen_ty_1, __bindgen_anon_2)
    + core::mem::offset_of!(
        wdk_sys::_IRP__bindgen_ty_4__bindgen_ty_1__bindgen_ty_2,
        ListEntry
    );

/// Recovers an IRP pointer from its embedded list entry.
fn irp_from_list_entry(entry: PLIST_ENTRY) -> PIRP {
    entry
        .cast::<u8>()
        .wrapping_sub(IRP_LIST_ENTRY_OFFSET)
        .cast::<wdk_sys::IRP>()
}

/// Returns whether one queued IRP matches an optional FILE_OBJECT context.
fn irp_matches_context(irp: PIRP, context: PVOID) -> bool {
    if context.is_null() {
        return true;
    }
    let Some(irp) = KernelIrp::from_raw(irp) else {
        return false;
    };
    let Ok(stack) = irp.current_stack() else {
        return false;
    };
    let stack = unsafe {
        // SAFETY: The pending IRP retains its current stack location while queued.
        stack.stack.as_ref()
    };
    stack.FileObject.cast::<c_void>() == context
}

#[cfg(test)]
mod tests {
    use super::{WorkerContinuation, WorkerState};

    /// # Panics
    ///
    /// Panics when repeated wakes can enqueue more than one PASSIVE_LEVEL worker.
    #[test]
    fn dormant_executor_queues_exactly_one_worker() {
        let mut state = WorkerState::Dormant;
        assert!(state.request_poll());
        assert_eq!(state, WorkerState::Queued);
        assert!(!state.request_poll());
        assert_eq!(state, WorkerState::Queued);
    }

    /// # Panics
    ///
    /// Panics when a wake racing with `Poll::Pending` can be lost.
    #[test]
    fn polling_wake_forces_repoll_before_sleep() {
        let mut state = WorkerState::Queued;
        assert!(state.enter_worker());
        assert!(!state.request_poll());
        assert_eq!(state, WorkerState::PollingWoken);
        assert_eq!(state.settle_pending(), WorkerContinuation::Repoll);
        assert_eq!(state, WorkerState::Polling);
        assert_eq!(state.settle_pending(), WorkerContinuation::Sleep);
        assert_eq!(state, WorkerState::Dormant);
    }

    /// # Panics
    ///
    /// Panics when an unowned worker can enter the polling section.
    #[test]
    fn only_queued_worker_can_enter_polling() {
        for state in [
            WorkerState::Dormant,
            WorkerState::Polling,
            WorkerState::PollingWoken,
        ] {
            let mut state = state;
            assert!(!state.enter_worker());
        }
    }
}
