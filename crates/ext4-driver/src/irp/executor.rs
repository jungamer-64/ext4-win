//! PASSIVE_LEVEL future executor and cancel-safe IRP mailbox.

use alloc::boxed::Box;
#[cfg(not(test))]
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    future::Future,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
};

use wdk_sys::{LIST_ENTRY, NTSTATUS, PIRP, PLIST_ENTRY, PVOID};
#[cfg(not(test))]
use wdk_sys::{PIO_CSQ, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::ffi;
#[cfg(not(test))]
use crate::memory;
use crate::{
    kernel::{
        fatal::KernelWideInconsistency,
        status::{DriverError, DriverResult},
    },
    state::{KernelDevice, KernelFileObject},
};

use super::{DispatchMajor, KernelIrp, OwnedIrp, PendingIrp, QueueContext, ReceivedIrp};

/// One pinned request continuation owned by a device execution lane.
type DeviceTask = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// Maximum captured requests waiting in one serialized device execution lane.
const MAX_QUEUED_REQUESTS: usize = 64;

/// Dedicated device actor lifecycle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActorState {
    /// The actor accepts new IRPs and serially executes them.
    Running = 0,
    /// Admission is closed; queued IRPs are canceled and the active task is draining.
    Draining = 1,
    /// The actor thread has released every task and terminated.
    Stopped = 2,
}

impl ActorState {
    /// Encodes this declared state for atomic publication.
    const fn as_raw(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Draining => 1,
            Self::Stopped => 2,
        }
    }

    /// Decodes a lifecycle state published through the atomic boundary.
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Running),
            1 => Some(Self::Draining),
            2 => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// One queue slot reserved before requestor-owned memory is captured.
///
/// Dropping this value rolls back an unpublished reservation. Publishing consumes it without
/// decrementing; the cancel-safe queue then releases the count at atomic removal.
#[derive(Debug)]
struct QueueSlotReservation {
    /// Stable per-device counter owned by the executor extension.
    queued_requests: NonNull<AtomicUsize>,
}

impl QueueSlotReservation {
    /// Reserves one slot without allowing the counter to exceed the per-device bound.
    /// # Errors
    ///
    /// Returns insufficient resources when this device already owns the maximum queue depth.
    fn acquire(queued_requests: &AtomicUsize) -> DriverResult<Self> {
        queued_requests
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= MAX_QUEUED_REQUESTS)
            })
            .map_err(|_| DriverError::InsufficientResources)?;
        Ok(Self {
            queued_requests: NonNull::from(queued_requests),
        })
    }

    /// Transfers this reservation to the cancel-safe queue.
    fn publish(self) {
        core::mem::forget(self);
    }
}

impl Drop for QueueSlotReservation {
    fn drop(&mut self) {
        let queued_requests = unsafe {
            // SAFETY: The executor storage remains live throughout receive, including every
            // rollback path before queue publication.
            self.queued_requests.as_ref()
        };
        release_queue_slot(queued_requests);
    }
}

/// Releases one previously reserved or published queue slot.
fn release_queue_slot(queued_requests: &AtomicUsize) {
    if queued_requests.fetch_sub(1, Ordering::AcqRel) == 0 {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    }
}

/// Device-owned executor that serializes filesystem request futures.
///
/// The embedded CSQ is the first field because the WDK callback API supplies only its address.
/// Every field mutated outside initialization is either protected by `lock` or confined to the one
/// dedicated actor thread.
#[repr(C)]
pub(crate) struct DeviceExecutor {
    /// Cancel-safe queue callback table. This must remain the first field.
    csq: wdk_sys::IO_CSQ,
    /// Spin lock shared by CSQ callbacks and mailbox transitions.
    lock: wdk_sys::KSPIN_LOCK,
    /// FIFO of pending IRPs using `IRP.Tail.Overlay.ListEntry`.
    list_head: UnsafeCell<LIST_ENTRY>,
    /// Captured requests admitted but not yet atomically removed from the CSQ.
    queued_requests: AtomicUsize,
    /// Auto-reset event that wakes the dedicated PASSIVE_LEVEL actor thread.
    wake_event: wdk_sys::KEVENT,
    /// Running/draining/stopped lifecycle shared with admission and teardown.
    lifecycle: AtomicU8,
    /// Kernel handle used by teardown to join the dedicated actor thread.
    thread_handle: wdk_sys::HANDLE,
    /// Pinned request future accessed only by the dedicated actor thread.
    active: UnsafeCell<Option<DeviceTask>>,
    /// Unit-test observation of whether a mailbox wake was published.
    #[cfg(test)]
    wake_requested: core::sync::atomic::AtomicBool,
    /// Device object that owns this stable executor storage.
    device: KernelDevice,
}

impl DeviceExecutor {
    /// Returns the current actor lifecycle or terminates on an impossible discriminant.
    fn actor_state(&self) -> ActorState {
        ActorState::from_raw(self.lifecycle.load(Ordering::Acquire)).unwrap_or_else(|| {
            KernelWideInconsistency::async_executor_state_corruption().bugcheck()
        })
    }

    /// Closes request admission and starts terminal draining exactly once.
    fn begin_drain(&self) {
        match self.lifecycle.compare_exchange(
            ActorState::Running.as_raw(),
            ActorState::Draining.as_raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(raw) if ActorState::from_raw(raw) == Some(ActorState::Stopped) => {}
            Err(_) => KernelWideInconsistency::async_executor_state_corruption().bugcheck(),
        }
    }

    /// Builds unlinked executor storage for placement in a unit-test device extension.
    #[cfg(test)]
    pub(super) fn test_storage(device: KernelDevice) -> Self {
        Self {
            csq: wdk_sys::IO_CSQ::default(),
            lock: 0,
            list_head: UnsafeCell::new(LIST_ENTRY::default()),
            queued_requests: AtomicUsize::new(0),
            wake_event: wdk_sys::KEVENT::default(),
            lifecycle: AtomicU8::new(ActorState::Running.as_raw()),
            thread_handle: core::ptr::null_mut(),
            active: UnsafeCell::new(None),
            wake_requested: core::sync::atomic::AtomicBool::new(false),
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
        let irp = self.remove_next_irp(context);
        if let Some(irp) = KernelIrp::from_raw(irp) {
            drop(irp.take_queue_context());
        }
        irp
    }

    /// Returns whether a unit-test wake was requested for the actor.
    #[cfg(test)]
    pub(super) fn test_wake_is_requested(&self) -> bool {
        self.wake_requested.load(Ordering::Acquire)
    }

    /// Returns whether a unit-test executor has no pending actor wake.
    #[cfg(test)]
    pub(super) fn test_has_no_pending_wake(&self) -> bool {
        !self.wake_requested.load(Ordering::Acquire)
    }

    /// Initializes an executor directly inside stable device-extension storage.
    /// # Safety
    ///
    /// `executor` must point to writable device-extension memory that will not move before
    /// [`Self::release_at`]. The owning device must remain alive throughout that interval.
    /// # Errors
    ///
    /// Returns an error when the CSQ or its dedicated PASSIVE_LEVEL actor thread cannot be
    /// initialized.
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
                    queued_requests: AtomicUsize::new(0),
                    wake_event: wdk_sys::KEVENT::default(),
                    lifecycle: AtomicU8::new(ActorState::Running.as_raw()),
                    thread_handle: core::ptr::null_mut(),
                    active: UnsafeCell::new(None),
                    #[cfg(test)]
                    wake_requested: core::sync::atomic::AtomicBool::new(false),
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
            unsafe {
                // SAFETY: The event is stable executor-owned storage initialized before the actor
                // thread can observe it.
                ffi::KeInitializeEvent(
                    core::ptr::addr_of!(executor.wake_event).cast_mut(),
                    wdk_sys::_EVENT_TYPE::SynchronizationEvent,
                    0,
                );
            }
            let mut attributes = wdk_sys::OBJECT_ATTRIBUTES {
                Length: u32::try_from(core::mem::size_of::<wdk_sys::OBJECT_ATTRIBUTES>())
                    .map_err(|_| DriverError::InvalidParameter)?,
                Attributes: wdk_sys::OBJ_KERNEL_HANDLE,
                ..wdk_sys::OBJECT_ATTRIBUTES::default()
            };
            let mut thread_handle = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: The stable executor address remains valid until release joins this
                // kernel-handle-owned system thread.
                ffi::PsCreateSystemThread(
                    core::ptr::addr_of_mut!(thread_handle),
                    wdk_sys::SYNCHRONIZE,
                    core::ptr::addr_of_mut!(attributes),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    Some(device_executor_thread),
                    core::ptr::from_ref(executor).cast_mut().cast::<c_void>(),
                )
            };
            if status < STATUS_SUCCESS || thread_handle.is_null() {
                return Err(DriverError::InsufficientResources);
            }
            unsafe {
                // SAFETY: Initialization retains exclusive access before the device is published.
                core::ptr::addr_of!(executor.thread_handle)
                    .cast_mut()
                    .write(thread_handle);
            }
        }

        Ok(())
    }

    /// Releases executor-owned resources in device-extension storage.
    /// # Safety
    ///
    /// No new dispatch callback may enter this executor. This transition closes admission,
    /// cancels queued IRPs, drains the active request and lower completions, joins the actor, and
    /// only then destroys the executor storage.
    pub(crate) unsafe fn release_at(executor: *mut Self) {
        let Some(mut executor_address) = NonNull::new(executor) else {
            return;
        };
        let executor = unsafe {
            // SAFETY: Teardown keeps the stable device extension alive until the actor is joined.
            executor_address.as_ref()
        };
        executor.begin_drain();
        loop {
            let irp = executor.remove_next_irp(core::ptr::null_mut());
            if irp.is_null() {
                break;
            }
            let owned = OwnedIrp::from_queued_raw(executor.device, irp);
            let _status = owned.complete_cancelled();
        }
        executor.request_poll();

        #[cfg(not(test))]
        {
            let thread_handle = executor.thread_handle;
            if thread_handle.is_null() {
                KernelWideInconsistency::async_executor_state_corruption().bugcheck();
            }
            let wait_status = unsafe {
                // SAFETY: Initialization stored a kernel handle for the sole actor thread.
                ffi::ZwWaitForSingleObject(thread_handle, 0, core::ptr::null_mut())
            };
            if wait_status < STATUS_SUCCESS {
                KernelWideInconsistency::async_executor_state_corruption().bugcheck();
            }
            let close_status = unsafe {
                // SAFETY: The actor has terminated and teardown owns its sole kernel handle.
                ffi::ZwClose(thread_handle)
            };
            if close_status < STATUS_SUCCESS {
                KernelWideInconsistency::async_executor_state_corruption().bugcheck();
            }
        }
        #[cfg(test)]
        executor
            .lifecycle
            .store(ActorState::Stopped.as_raw(), Ordering::Release);

        if executor.actor_state() != ActorState::Stopped
            || executor.queued_requests.load(Ordering::Acquire) != 0
            || unsafe {
                // SAFETY: The actor is joined, so teardown exclusively observes the task slot.
                (*executor.active.get()).is_some()
            }
        {
            KernelWideInconsistency::async_executor_state_corruption().bugcheck();
        }
        let executor = unsafe {
            // SAFETY: Joining the actor and closing admission grants exclusive teardown access.
            executor_address.as_mut()
        };
        executor.thread_handle = core::ptr::null_mut();
        unsafe {
            // SAFETY: Teardown is exclusive and releases any Rust-owned task allocation exactly
            // once before the I/O Manager frees the extension bytes.
            core::ptr::drop_in_place(executor);
        }
    }

    /// Captures an async request, inserts it into this device mailbox, and schedules its lane.
    pub(crate) fn receive(mut received: ReceivedIrp, major: DispatchMajor) -> NTSTATUS {
        let executor = match Self::from_device(received.device()) {
            Ok(executor) => executor,
            Err(error) => return received.complete_result(Err(error)),
        };
        let executor = unsafe {
            // SAFETY: The device extension remains stable throughout request capture and queueing.
            executor.as_ref()
        };
        if executor.actor_state() != ActorState::Running {
            return received.complete_result(Err(DriverError::InvalidDeviceRequest));
        }
        let reservation = match QueueSlotReservation::acquire(&executor.queued_requests) {
            Ok(reservation) => reservation,
            Err(error) => return received.complete_result(Err(error)),
        };
        let context = match received.with_active(|active| QueueContext::capture(active, major)) {
            Ok(context) => context,
            Err(completion) => return received.complete(completion),
        };
        let pending = PendingIrp::from_received(received, context);
        let status = pending.dispatch_status();
        executor.enqueue(pending, reservation);
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
            let owned = OwnedIrp::from_queued_raw(executor.device, irp);
            let _status = owned.complete_cancelled();
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

    /// Inserts a pending IRP through the cancel-safe queue and wakes the actor.
    fn enqueue(&self, pending: PendingIrp, reservation: QueueSlotReservation) {
        #[cfg(test)]
        mark_pending_for_csq_test(pending.target.irp);
        let irp = pending.publish();
        reservation.publish();
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Context publication transferred the Box before this call. IoCsqInsertIrp
            // marks the IRP pending and may consume it through inline cancellation, so this path
            // never dereferences the IRP after the call.
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

    /// Signals the dedicated PASSIVE_LEVEL actor that mailbox or continuation work is ready.
    fn request_poll(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The event is initialized before thread publication and remains live until
            // every waker has been drained and the actor thread is joined.
            let _previous = ffi::KeSetEvent(core::ptr::addr_of!(self.wake_event).cast_mut(), 0, 0);
        }
        #[cfg(test)]
        self.wake_requested.store(true, Ordering::Release);
    }

    /// Owns and polls every device future on one system thread until terminal draining completes.
    #[cfg(not(test))]
    fn run(&self) {
        loop {
            if unsafe {
                // SAFETY: The dedicated actor thread is the sole accessor of the active slot.
                (*self.active.get()).is_none()
            } && !self.install_next_task()
            {
                if self.actor_state() == ActorState::Draining {
                    self.lifecycle
                        .store(ActorState::Stopped.as_raw(), Ordering::Release);
                    return;
                }
                self.wait_for_wake();
                continue;
            }

            let poll = {
                let waker = self.waker();
                let mut context = Context::from_waker(&waker);
                let active = unsafe {
                    // SAFETY: Only the dedicated actor thread accesses the pinned active task.
                    &mut *self.active.get()
                };
                let Some(task) = active.as_mut() else {
                    continue;
                };
                task.as_mut().poll(&mut context)
            };
            match poll {
                Poll::Ready(()) => unsafe {
                    // SAFETY: This is the dedicated actor thread, and a ready task retains no
                    // terminal IRP authority after its async body returns.
                    *self.active.get() = None;
                },
                Poll::Pending => self.wait_for_wake(),
            }
        }
    }

    /// Blocks the actor until queue admission, lower-I/O completion, or teardown signals its event.
    #[cfg(not(test))]
    fn wait_for_wake(&self) {
        let status = unsafe {
            // SAFETY: The actor is the only waiter on this initialized auto-reset event.
            ffi::KeWaitForSingleObject(
                core::ptr::addr_of!(self.wake_event)
                    .cast_mut()
                    .cast::<c_void>(),
                wdk_sys::_KWAIT_REASON::Executive,
                i8::try_from(wdk_sys::_MODE::KernelMode).unwrap_or(0),
                0,
                core::ptr::null_mut(),
            )
        };
        if status < STATUS_SUCCESS {
            KernelWideInconsistency::async_executor_state_corruption().bugcheck();
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
            let owned = OwnedIrp::from_queued_raw(self.device, irp);
            let task = memory::boxed_try_map(owned, |owned| async move {
                crate::request::dispatch::execute_owned(owned).await;
            });
            match task {
                Ok(task) => {
                    let task: DeviceTask = Box::into_pin(task);
                    unsafe {
                        // SAFETY: The dedicated actor owns the empty active slot.
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
            KernelWideInconsistency::async_executor_state_corruption().bugcheck();
        };
        insert_tail_list(self.list_head.get(), entry);
    }

    /// Removes one IRP from the FIFO while the CSQ lock is held.
    fn remove_irp(&self, irp: PIRP) {
        let Some(entry) = irp_list_entry(irp) else {
            KernelWideInconsistency::async_executor_state_corruption().bugcheck();
        };
        remove_entry_list(entry);
        release_queue_slot(&self.queued_requests);
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
                KernelWideInconsistency::async_executor_state_corruption().bugcheck();
            };
            unsafe {
                // SAFETY: The supplied IRP is currently linked under the CSQ lock.
                (*entry).Flink
            }
        };
        while entry != head {
            let candidate = irp_from_list_entry(entry);
            if queued_irp_matches_context(candidate, context) {
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
// actor-thread disciplines documented on each `UnsafeCell` field.
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
/// `data` must identify a live, device-stable `DeviceExecutor` whose wake event remains initialized.
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
/// Dedicated PASSIVE_LEVEL device actor thread.
/// # Safety
///
/// `context` must be the stable `DeviceExecutor` address passed to `PsCreateSystemThread`.
unsafe extern "C" fn device_executor_thread(context: PVOID) {
    let Some(executor) = NonNull::new(context.cast::<DeviceExecutor>()) else {
        let _status = unsafe {
            // SAFETY: This callback is running as a system thread and cannot return normally.
            ffi::PsTerminateSystemThread(DriverError::InternalInvariantViolation.ntstatus())
        };
        return;
    };
    unsafe {
        // SAFETY: `PsCreateSystemThread` received this stable executor address as its context.
        executor.as_ref()
    }
    .run();
    let _status = unsafe {
        // SAFETY: The actor published `Stopped` and released its task before terminating itself.
        ffi::PsTerminateSystemThread(STATUS_SUCCESS)
    };
}

#[cfg(not(test))]
/// CSQ insertion callback.
/// # Safety
///
/// `csq` must be the first-field CSQ of a live executor and `irp` must be an unlinked pending IRP
/// handed to this callback by the I/O Manager while the CSQ lock is held.
unsafe extern "C" fn csq_insert_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(executor) = (unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }) else {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    executor.insert_irp(irp);
}

#[cfg(not(test))]
/// CSQ removal callback.
/// # Safety
///
/// `csq` must belong to a live executor and `irp` must currently be linked in that executor's
/// queue while the CSQ lock is held.
unsafe extern "C" fn csq_remove_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(executor) = (unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }) else {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    executor.remove_irp(irp);
}

#[cfg(not(test))]
/// CSQ FIFO peek callback.
/// # Safety
///
/// `csq` must belong to a live executor; a non-null `irp` must be linked in that queue, and a
/// non-null `context` must be a FILE_OBJECT identity supplied by the I/O Manager.
unsafe extern "C" fn csq_peek_next_irp(csq: PIO_CSQ, irp: PIRP, context: PVOID) -> PIRP {
    let Some(executor) = (unsafe {
        // SAFETY: The CSQ is the first field of one live executor.
        executor_from_csq(csq)
    }) else {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    executor.peek_next_irp(irp, context)
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
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    let Some(irql) = (unsafe {
        // SAFETY: The CSQ framework supplies writable saved-IRQL storage.
        irql.as_mut()
    }) else {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
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
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
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
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    let owned = OwnedIrp::from_queued_raw(executor.device, irp);
    let _status = owned.complete_cancelled();
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

/// Models the pending transition performed internally by `IoCsqInsertIrp` in unit tests.
#[cfg(test)]
fn mark_pending_for_csq_test(irp: KernelIrp) {
    let pending_bit = match u8::try_from(wdk_sys::SL_PENDING_RETURNED) {
        Ok(bit) => bit,
        Err(_) => KernelWideInconsistency::async_executor_state_corruption().bugcheck(),
    };
    let mut raw_irp = irp.irp;
    let raw_irp = unsafe {
        // SAFETY: The test executor owns this not-yet-inserted IRP.
        raw_irp.as_mut()
    };
    let overlay = unsafe {
        // SAFETY: The test fixture initialized the current-stack tail overlay.
        raw_irp.Tail.Overlay
    };
    let current_stack = unsafe {
        // SAFETY: The list overlay contains the current stack fixture pointer.
        overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    let Some(stack) = (unsafe {
        // SAFETY: Successful queue capture already validated this fixture stack pointer.
        current_stack.as_mut()
    }) else {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    stack.Control |= pending_bit;
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
fn queued_irp_matches_context(irp: PIRP, context: PVOID) -> bool {
    let Some(irp) = KernelIrp::from_raw(irp) else {
        KernelWideInconsistency::async_executor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: The CSQ lock retains queue membership, so context publication cannot be taken
        // until this callback returns its candidate decision.
        irp.published_queue_context_matches(context)
    }
}

#[cfg(test)]
mod tests {
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{ActorState, DeviceExecutor, MAX_QUEUED_REQUESTS, QueueSlotReservation};
    use crate::state::KernelDevice;

    /// Builds actor storage around a non-dereferenced device identity.
    fn actor_storage() -> Option<DeviceExecutor> {
        let device = KernelDevice::from_raw(NonNull::<wdk_sys::DEVICE_OBJECT>::dangling().as_ptr());
        device.map(DeviceExecutor::test_storage)
    }

    /// # Panics
    ///
    /// Panics when one device can reserve beyond its bounded queue depth or rollback leaks slots.
    #[test]
    fn queue_slot_reservations_enforce_the_device_bound() {
        let queued_requests = AtomicUsize::new(0);
        let reservations: [_; MAX_QUEUED_REQUESTS] =
            core::array::from_fn(|_| QueueSlotReservation::acquire(&queued_requests));

        assert!(reservations.iter().all(Result::is_ok));
        assert!(QueueSlotReservation::acquire(&queued_requests).is_err());
        drop(reservations);
        assert_eq!(queued_requests.load(Ordering::Acquire), 0);
    }

    /// # Panics
    ///
    /// Panics when the actor lifecycle accepts an unknown atomic discriminant.
    #[test]
    fn actor_state_decodes_only_declared_lifecycle_states() {
        assert_eq!(ActorState::from_raw(0), Some(ActorState::Running));
        assert_eq!(ActorState::from_raw(1), Some(ActorState::Draining));
        assert_eq!(ActorState::from_raw(2), Some(ActorState::Stopped));
        assert_eq!(ActorState::from_raw(3), None);
        assert_eq!(ActorState::from_raw(u8::MAX), None);
    }

    /// # Panics
    ///
    /// Panics when terminal draining does not close admission and wake the actor.
    #[test]
    fn actor_drain_closes_admission_before_publishing_wake() {
        let executor = actor_storage();
        assert!(executor.is_some());
        let Some(executor) = executor else {
            return;
        };
        assert_eq!(executor.actor_state(), ActorState::Running);
        assert!(executor.test_has_no_pending_wake());

        executor.begin_drain();
        assert_eq!(executor.actor_state(), ActorState::Draining);
        assert!(executor.test_has_no_pending_wake());

        executor.request_poll();
        assert!(executor.test_wake_is_requested());
    }
}
