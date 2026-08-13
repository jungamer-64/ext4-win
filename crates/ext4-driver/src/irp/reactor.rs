//! Bounded completion-driven filesystem operation reactor.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use ext4_core::{MutationResource, OperationEvent, StorageRequest};
use wdk_sys::{LIST_ENTRY, NTSTATUS, PIRP, PLIST_ENTRY, PVOID};
#[cfg(not(test))]
use wdk_sys::{PIO_CSQ, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::ffi;
use crate::kernel::{
    fatal::KernelWideInconsistency,
    status::{DriverError, DriverResult},
};
use crate::state::{KernelDevice, KernelFileObject};

#[cfg(not(test))]
use super::ActiveCancelDestination;
#[cfg(not(test))]
use super::lower::{LowerCompletionEnvelope, LowerCompletionRoute, PublishedLowerRequest};
use super::{
    ActiveCancelEnvelope, DispatchMajor, KernelIrp, OwnedIrp, PendingIrp, QueueContext,
    ReceivedIrp, lower::CompletionRundown,
};
#[cfg(not(test))]
use crate::kernel::storage::{
    DeviceLengthProbe, PreparedStorageCommand, RetryingStorageCommand, StorageCommand,
    StorageCommandStep, StorageRetryDecision, StorageRetryDelay, failed_unsubmitted_request,
};
use crate::kernel::storage::{MountedStorageDevices, StorageFailureClass};
use crate::memory::DriverVec;

/// Operation representation moved through storage-command envelopes.
type SuspendedOperation = Box<dyn CompletionOperation>;
/// One concrete storage command captured by a private lower IRP.
#[cfg(not(test))]
type ReactorStorageCommand = StorageCommand<SuspendedOperation>;
/// Stable completion envelope type linked into this reactor's storage inbox.
#[cfg(not(test))]
type ReactorStorageEnvelope =
    LowerCompletionEnvelope<ReactorStorageCommand, StorageCompletionRoute>;
/// Driver-specific length query retaining one suspended mount operation.
#[cfg(not(test))]
type ReactorLengthProbe = DeviceLengthProbe<SuspendedOperation>;
/// Stable completion envelope linked into the separate length-query inbox.
#[cfg(not(test))]
type ReactorLengthEnvelope = LowerCompletionEnvelope<ReactorLengthProbe, LengthCompletionRoute>;

/// Stable, statically dispatched destination for storage-command completions.
#[cfg(not(test))]
struct StorageCompletionRoute {
    /// Reactor retained live by the envelope's rundown lease.
    reactor: NonNull<CompletionReactor>,
}

/// Stable, statically dispatched destination for device-length completions.
#[cfg(not(test))]
struct LengthCompletionRoute {
    /// Reactor retained live by the envelope's rundown lease.
    reactor: NonNull<CompletionReactor>,
}

// SAFETY: The completion rundown lease keeps the immutable reactor address live across threads.
#[cfg(not(test))]
unsafe impl Send for StorageCompletionRoute {}
// SAFETY: Callback publication serializes reactor inbox mutation with its spin lock.
#[cfg(not(test))]
unsafe impl Sync for StorageCompletionRoute {}
// SAFETY: The completion rundown lease keeps the immutable reactor address live across threads.
#[cfg(not(test))]
unsafe impl Send for LengthCompletionRoute {}
// SAFETY: Callback publication serializes reactor inbox mutation with its spin lock.
#[cfg(not(test))]
unsafe impl Sync for LengthCompletionRoute {}

// SAFETY: This route performs only typed intrusive publication and wakeup under the reactor lock.
#[cfg(not(test))]
unsafe impl LowerCompletionRoute<ReactorStorageCommand> for StorageCompletionRoute {
    unsafe fn publish(&self, envelope: NonNull<ReactorStorageEnvelope>) {
        let reactor = unsafe {
            // SAFETY: The envelope's rundown lease retains the stable reactor through publication.
            self.reactor.as_ref()
        };
        unsafe {
            // SAFETY: Completion transfers its unique unlinked node to the storage inbox.
            reactor.enqueue_storage(envelope);
        }
    }
}

// SAFETY: This route performs only typed intrusive publication and wakeup under the reactor lock.
#[cfg(not(test))]
unsafe impl LowerCompletionRoute<ReactorLengthProbe> for LengthCompletionRoute {
    unsafe fn publish(&self, envelope: NonNull<ReactorLengthEnvelope>) {
        let reactor = unsafe {
            // SAFETY: The envelope's rundown lease retains the stable reactor through publication.
            self.reactor.as_ref()
        };
        unsafe {
            // SAFETY: Completion transfers its unique unlinked node to the length inbox.
            reactor.enqueue_length(envelope);
        }
    }
}

/// Published lower cancellation identity without erasing the concrete envelope payload type.
#[cfg(not(test))]
enum PublishedReactorLower {
    /// Core read/write/flush request.
    Storage(PublishedLowerRequest<ReactorStorageCommand, StorageCompletionRoute>),
    /// Mount-time device length query.
    Length(PublishedLowerRequest<ReactorLengthProbe, LengthCompletionRoute>),
}

#[cfg(not(test))]
impl fmt::Debug for PublishedReactorLower {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(_) => formatter.write_str("Storage"),
            Self::Length(_) => formatter.write_str("Length"),
        }
    }
}

#[cfg(not(test))]
impl PublishedReactorLower {
    /// Propagates cancellation to the published lower IRP without taking release authority.
    /// # Safety
    ///
    /// The active slot must still retain this exact published lower identity.
    #[cfg(not(test))]
    unsafe fn cancel(&self) {
        match self {
            Self::Storage(lower) => unsafe {
                // SAFETY: The active slot retains the storage envelope identity through this call.
                lower.cancel();
            },
            Self::Length(lower) => unsafe {
                // SAFETY: The active slot retains the length envelope identity through this call.
                lower.cancel();
            },
        }
    }
}

/// Hard bound shared by pending and active filesystem operations on one device.
pub(crate) const MAX_OPERATIONS: usize = 64;

/// Scheduler-local identity for the per-handle CLEANUP terminal barrier.
pub(crate) const CLEANUP_HANDLE_BARRIER: u64 = 2;
/// Scheduler-local identity for the terminal CLOSE drain.
pub(crate) const CLOSE_HANDLE_BARRIER: u64 = 3;

/// Synchronous selector borrowed only for one `IoCsqRemoveNextIrp` traversal.
#[repr(C)]
struct PendingIrpSelection {
    /// FILE_OBJECT whose not-yet-started requests are considered.
    file_object: KernelFileObject,
    /// Whether paging/internal requests and terminal markers must remain queued.
    ordinary_cleanup_only: bool,
}

impl PendingIrpSelection {
    /// Selects only ordinary requests that CLEANUP is authorized to cancel.
    const fn cleanup(file_object: KernelFileObject) -> Self {
        Self {
            file_object,
            ordinary_cleanup_only: true,
        }
    }
}

/// Requests whose FILE_OBJECT lifetime legally continues after CLEANUP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostCleanupRequest {
    /// Paging read captured from `IRP_PAGING_IO`.
    PagingRead,
    /// Paging write captured from `IRP_PAGING_IO`.
    PagingWrite,
    /// Explicit device flush that accesses no user-visible handle authority.
    FlushBuffers,
    /// Terminal context release after every earlier post-cleanup request drains.
    Close,
}

/// Exact per-handle scheduler lane selected at operation admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleOperationLane {
    /// Normal request admitted only while the handle is open.
    Ordinary,
    /// Terminal cleanup barrier that closes ordinary admission.
    Cleanup,
    /// Explicitly legal post-cleanup request.
    PostCleanup(PostCleanupRequest),
}

/// Scheduler identity retained independently from operation payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationAdmission {
    /// Device-wide request with no FILE_OBJECT serialization requirement.
    Device,
    /// Request serialized in one stable FILE_OBJECT lane.
    Handle {
        /// Stable FILE_OBJECT identity retained until CLOSE consumes the lane.
        file_object: KernelFileObject,
        /// Typed lifecycle lane.
        lane: HandleOperationLane,
    },
}

impl OperationAdmission {
    /// Returns the per-handle identity, if this is not a device-wide request.
    const fn file_object(self) -> Option<KernelFileObject> {
        match self {
            Self::Device => None,
            Self::Handle { file_object, .. } => Some(file_object),
        }
    }

    /// Returns whether CLEANUP may cancel this active ordinary request.
    const fn is_ordinary_handle(self) -> bool {
        matches!(
            self,
            Self::Handle {
                lane: HandleOperationLane::Ordinary,
                ..
            }
        )
    }

    /// Returns whether cancellation must not preempt this terminal lifecycle operation.
    const fn is_terminal_handle_barrier(self) -> bool {
        matches!(
            self,
            Self::Handle {
                lane: HandleOperationLane::Cleanup
                    | HandleOperationLane::PostCleanup(PostCleanupRequest::Close),
                ..
            }
        )
    }
}

/// Fallibly allocated operation paired with its allocation-free scheduler admission identity.
#[derive(Debug)]
pub(crate) struct AdmittedOperation {
    /// Consuming operation state machine.
    operation: Box<dyn CompletionOperation>,
    /// Independent handle/device lane identity.
    admission: OperationAdmission,
}

impl AdmittedOperation {
    /// Binds a successfully allocated operation to its scheduler lane.
    pub(crate) const fn new(
        operation: Box<dyn CompletionOperation>,
        admission: OperationAdmission,
    ) -> Self {
        Self {
            operation,
            admission,
        }
    }

    /// Separates operation ownership from its independent lane identity.
    fn into_parts(self) -> (Box<dyn CompletionOperation>, OperationAdmission) {
        (self.operation, self.admission)
    }
}

/// One concrete operation advanced only by a matching scheduler event.
///
/// Multiple request, mount, and checkpoint state machines implement this boundary. The boxed
/// receiver is an owned continuation, not a `Future`; the reactor never probes it for readiness.
pub(crate) trait CompletionOperation: fmt::Debug + Send + 'static {
    /// Consumes this operation and its one concrete event into exactly one scheduler action.
    fn advance(self: Box<Self>, event: OperationEvent) -> OperationTransition;

    /// Records a terminal lower-storage classification before the matching completion event.
    fn record_storage_failure(&mut self, failure: StorageFailureClass);
}

/// Authority consumed by one allocation-free reactor publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationAuthority {
    /// Durable visibility releases resource intents and the serialized commit grant.
    Durable {
        /// Stable mounted VCB receiving publication.
        volume: NonNull<crate::state::VolumeControlBlock>,
        /// FIFO mutation ticket whose grants are consumed.
        ticket: u64,
    },
    /// Checkpoint publication releases journal space but owns no resource intent.
    Checkpoint {
        /// Stable mounted VCB receiving overlay removal.
        volume: NonNull<crate::state::VolumeControlBlock>,
        /// Overlay epoch being retired.
        epoch: ext4_core::EpochSequence,
    },
}

/// Prebuilt publication that reuses its existing operation allocation.
pub(crate) trait InfalliblePublication: fmt::Debug + Send + 'static {
    /// Scheduler authority consumed by this publication.
    fn authority(&self) -> PublicationAuthority;

    /// Publishes prepared values and returns the same box in its next operation phase.
    fn publish(self: Box<Self>) -> Box<dyn CompletionOperation>;
}

/// Resource-intent request prepared before a mutation can reserve allocation.
#[derive(Debug)]
pub(crate) struct IntentRequest {
    /// Stable mounted VCB whose resources are named by this request.
    volume: NonNull<crate::state::VolumeControlBlock>,
    /// Stable FIFO mutation ticket.
    ticket: u64,
    /// Complete resource set acquired atomically or not at all.
    resources: DriverVec<MutationResource>,
}

impl IntentRequest {
    /// Builds a fallibly allocated intent request before any lower write exists.
    pub(crate) const fn new(
        volume: NonNull<crate::state::VolumeControlBlock>,
        ticket: u64,
        resources: DriverVec<MutationResource>,
    ) -> Self {
        Self {
            volume,
            ticket,
            resources,
        }
    }

    /// Mounted volume whose resource namespace this request uses.
    pub(crate) const fn volume(&self) -> NonNull<crate::state::VolumeControlBlock> {
        self.volume
    }

    /// Stable FIFO ticket.
    pub(crate) const fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Complete opaque resource set.
    pub(crate) fn resources(&self) -> &[MutationResource] {
        self.resources.as_slice()
    }
}

/// Reason an operation is suspended without a lower transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitCondition {
    /// Durable values are waiting for the short epoch visibility gate.
    Visibility {
        /// Mounted runtime whose epoch gate is requested.
        volume: NonNull<crate::state::VolumeControlBlock>,
        /// Durable mutation ticket.
        ticket: u64,
    },
    /// Published overlay work is waiting for the independent checkpoint slot.
    Checkpoint {
        /// Mounted runtime whose checkpoint gate is requested.
        volume: NonNull<crate::state::VolumeControlBlock>,
        /// Visible overlay epoch.
        epoch: ext4_core::EpochSequence,
    },
    /// Ordinary flush waits for every already granted or queued commit to become durable.
    VolumeDurability {
        /// Mounted volume whose commit lane must drain.
        volume: NonNull<crate::state::VolumeControlBlock>,
    },
    /// Shutdown/clean-dismount waits until checkpoint has released journal space.
    JournalClean {
        /// Mounted volume whose journal must return to the clean ready state.
        volume: NonNull<crate::state::VolumeControlBlock>,
    },
    /// A per-handle terminal or durability barrier has not drained earlier work.
    Barrier {
        /// Stable barrier identity resumed by one matching release event.
        identity: u64,
    },
}

/// One consuming action emitted by an event-driven operation.
#[derive(Debug)]
pub(crate) enum OperationTransition {
    /// Build and submit one mount-time lower device-length query.
    QueryDeviceLength {
        /// Driver-owned device whose image pins the completion callback.
        completion_owner: KernelDevice,
        /// Lower storage device being mounted.
        target: KernelDevice,
        /// Mount operation moved by value into the stable completion envelope.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Build and submit one owned lower command.
    SubmitLower {
        /// Mounted devices selected by the operation's stable volume capability.
        devices: MountedStorageDevices,
        /// Owned core transfer token.
        request: StorageRequest,
        /// Operation moved by value into the lower completion envelope.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Atomically acquire a resolved mutation's full resource set.
    RequestIntent {
        /// Stable FIFO/resource request.
        request: IntentRequest,
        /// Operation resumed only by the resulting intent grant.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Wait for the serialized journal commit slot.
    RequestCommit {
        /// Mounted runtime whose journal gate is requested.
        volume: NonNull<crate::state::VolumeControlBlock>,
        /// FIFO mutation ticket.
        ticket: u64,
        /// Operation resumed only by its commit grant.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Arm one fixed storage retry timer.
    #[cfg(not(test))]
    ArmRetry {
        /// Failed command retaining the original suspended operation.
        retry: RetryingStorageCommand<Box<dyn CompletionOperation>>,
    },
    /// Wait for a visibility, checkpoint, or terminal-barrier grant.
    Wait {
        /// Exact condition whose release produces an event.
        condition: WaitCondition,
        /// Operation retained without being re-executed.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Apply a prebuilt allocation-free publication and continue one operation.
    Publish {
        /// Publication values and continuation prepared before durable I/O.
        publication: Box<dyn InfalliblePublication>,
    },
    /// Operation has consumed every terminal authority it owned.
    Complete,
}

/// Device reactor lifecycle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReactorState {
    /// Admission is open and concrete events are processed.
    Running = 0,
    /// Admission is closed while queued and active work drains.
    Draining = 1,
    /// The system thread and every completion envelope have terminated.
    Stopped = 2,
}

impl ReactorState {
    /// Stable atomic representation.
    const fn as_raw(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Draining => 1,
            Self::Stopped => 2,
        }
    }

    /// Checked atomic decoding.
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Running),
            1 => Some(Self::Draining),
            2 => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// Admission rundown closes capture and CSQ insertion atomically with teardown.
struct AdmissionRundown {
    /// Native executive rundown state.
    #[cfg(not(test))]
    native: UnsafeCell<wdk_sys::EX_RUNDOWN_REF>,
    /// Closed bit plus active admission count in deterministic tests.
    #[cfg(test)]
    state: AtomicUsize,
}

/// High bit marking closed test admission.
#[cfg(test)]
const TEST_ADMISSION_CLOSED: usize = 1_usize << (usize::BITS - 1);

impl AdmissionRundown {
    /// Creates an uninitialized native gate or open test gate.
    fn new() -> Self {
        Self {
            #[cfg(not(test))]
            native: UnsafeCell::new(wdk_sys::EX_RUNDOWN_REF::default()),
            #[cfg(test)]
            state: AtomicUsize::new(0),
        }
    }

    /// Initializes native rundown after final placement.
    fn initialize(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The containing device extension is already address-stable.
            ffi::ExInitializeRundownProtection(self.native.get());
        }
    }

    /// Acquires one admission lease unless teardown closed the gate.
    fn acquire(&self) -> Option<AdmissionLease<'_>> {
        #[cfg(not(test))]
        {
            let acquired = unsafe {
                // SAFETY: Native rundown was initialized before device publication.
                ffi::ExAcquireRundownProtection(self.native.get())
            };
            if acquired == 0 {
                return None;
            }
        }
        #[cfg(test)]
        {
            self.state
                .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    if state & TEST_ADMISSION_CLOSED != 0 {
                        None
                    } else {
                        state
                            .checked_add(1)
                            .filter(|next| next & TEST_ADMISSION_CLOSED == 0)
                    }
                })
                .ok()?;
        }
        Some(AdmissionLease { owner: self })
    }

    /// Closes admission and waits for every capture/insertion lease.
    fn close_and_wait(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Teardown runs at PASSIVE_LEVEL after publishing Draining.
            ffi::ExWaitForRundownProtectionRelease(self.native.get());
        }
        #[cfg(test)]
        {
            let previous = self.state.fetch_or(TEST_ADMISSION_CLOSED, Ordering::AcqRel);
            if previous & TEST_ADMISSION_CLOSED != 0 {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            while self.state.load(Ordering::Acquire) != TEST_ADMISSION_CLOSED {
                core::hint::spin_loop();
            }
        }
    }

    /// Releases one admission lease.
    fn release(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Each lease corresponds to one successful acquisition.
            ffi::ExReleaseRundownProtection(self.native.get());
        }
        #[cfg(test)]
        {
            let previous = self.state.fetch_sub(1, Ordering::AcqRel);
            if previous == 0 || previous == TEST_ADMISSION_CLOSED {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
    }
}

// SAFETY: Native rundown or the test atomic serializes every interior access.
unsafe impl Sync for AdmissionRundown {}

/// One capture-to-insertion admission lease.
struct AdmissionLease<'owner> {
    /// Stable gate owning the acquisition.
    owner: &'owner AdmissionRundown,
}

impl Drop for AdmissionLease<'_> {
    fn drop(&mut self) {
        self.owner.release();
    }
}

/// One operation-capacity reservation retained until top-level terminal completion.
#[derive(Debug)]
struct OperationReservation {
    /// Stable per-device count.
    admitted: NonNull<AtomicUsize>,
}

impl OperationReservation {
    /// Reserves one of the device's fixed operation slots.
    /// # Errors
    ///
    /// Returns [`DriverError::InsufficientResources`] when all bounded operation slots are in use.
    fn acquire(admitted: &AtomicUsize) -> DriverResult<Self> {
        admitted
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(1)
                    .filter(|next| *next <= MAX_OPERATIONS)
            })
            .map_err(|_| DriverError::InsufficientResources)?;
        Ok(Self {
            admitted: NonNull::from(admitted),
        })
    }

    /// Moves this reservation into queue-owned context bookkeeping.
    fn publish(self) {
        core::mem::forget(self);
    }
}

impl Drop for OperationReservation {
    fn drop(&mut self) {
        release_operation_reservation(unsafe {
            // SAFETY: Device teardown waits for the admitted count to reach zero.
            self.admitted.as_ref()
        });
    }
}

/// Releases one operation capacity unit.
fn release_operation_reservation(admitted: &AtomicUsize) {
    if admitted.fetch_sub(1, Ordering::AcqRel) == 0 {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
}

/// Stable active-slot phase. The operation itself is held here only when no lower envelope owns it.
enum ActivePhase {
    /// Slot is available.
    Vacant,
    /// One concrete event is ready for delivery by the reactor thread.
    Ready {
        /// Owned state machine.
        operation: Box<dyn CompletionOperation>,
        /// Concrete event that made this slot ready.
        event: OperationEvent,
    },
    /// Operation is retained until its exact earlier FILE_OBJECT predecessor terminates.
    HandleTurn {
        /// Owned state machine that has not yet received its admission event.
        operation: Box<dyn CompletionOperation>,
    },
    /// Resource intents are queued under FIFO arbitration.
    Intent {
        /// Complete request retained for atomic acquisition.
        request: IntentRequest,
        /// Suspended state machine.
        operation: Box<dyn CompletionOperation>,
    },
    /// Journal commit grant is queued.
    Commit {
        /// Mounted runtime whose commit gate is queued.
        volume: NonNull<crate::state::VolumeControlBlock>,
        /// FIFO mutation ticket.
        ticket: u64,
        /// Suspended state machine.
        operation: Box<dyn CompletionOperation>,
    },
    /// Non-I/O gate wait.
    Waiting {
        /// Exact gate condition.
        condition: WaitCondition,
        /// Suspended state machine.
        operation: Box<dyn CompletionOperation>,
    },
    /// One retry timer is armed; the original operation remains inside the command.
    #[cfg(not(test))]
    Retry(RetryingStorageCommand<Box<dyn CompletionOperation>>),
    /// Lower IRP registration/call is executing on the reactor thread.
    #[cfg(not(test))]
    Registering,
    /// Completion envelope owns the operation and lower lifetime.
    #[cfg(not(test))]
    Lower(PublishedReactorLower),
}

impl fmt::Debug for ActivePhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vacant => formatter.write_str("Vacant"),
            Self::Ready { .. } => formatter.write_str("Ready"),
            Self::HandleTurn { .. } => formatter.write_str("HandleTurn"),
            Self::Intent { .. } => formatter.write_str("Intent"),
            Self::Commit { .. } => formatter.write_str("Commit"),
            Self::Waiting { .. } => formatter.write_str("Waiting"),
            #[cfg(not(test))]
            Self::Retry(_) => formatter.write_str("Retry"),
            #[cfg(not(test))]
            Self::Registering => formatter.write_str("Registering"),
            #[cfg(not(test))]
            Self::Lower(_) => formatter.write_str("Lower"),
        }
    }
}

/// One bounded operation slot.
#[derive(Debug)]
struct ActiveSlot {
    /// Monotonic generation encoded into external timer/grant identities.
    generation: u64,
    /// Resource set held from intent grant through durable visibility publication.
    intent: Option<HeldIntent>,
    /// Commit grant retained until durable publication or harmless pre-write abandonment.
    commit: Option<HeldCommit>,
    /// A top-level cancel has been published but not yet consumed by the operation.
    cancel_pending: bool,
    /// Lower cancellation remains legal until the first effect-bearing write/flush submission.
    cancel_enabled: bool,
    /// Device or exact FILE_OBJECT lane retained independently from the operation allocation.
    admission: Option<OperationAdmission>,
    /// Exact earlier same-handle slot that must terminate before admission is delivered.
    predecessor: Option<ActiveSlotIdentity>,
    /// Current ownership phase.
    phase: ActivePhase,
}

/// Generation-checked active-slot identity used only by bounded per-handle predecessor chains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveSlotIdentity {
    /// Fixed registry index.
    index: usize,
    /// Monotonic reuse generation at that index.
    generation: u64,
}

/// Address-stable timer/DPC envelope for one bounded retry slot.
#[repr(C)]
struct RetryTimerEnvelope {
    /// Native one-shot timer.
    timer: UnsafeCell<wdk_sys::KTIMER>,
    /// Native DPC publishing only a slot-generation event.
    dpc: UnsafeCell<wdk_sys::KDPC>,
    /// Stable owning reactor, null only before final-address initialization.
    reactor: AtomicPtr<CompletionReactor>,
    /// Fixed bounded slot index.
    index: usize,
    /// Active slot generation captured when the timer was armed.
    generation: AtomicU64,
}

impl RetryTimerEnvelope {
    /// Creates inert storage completed by final-address initialization.
    fn inert(index: usize) -> Self {
        Self {
            timer: UnsafeCell::new(wdk_sys::KTIMER::default()),
            dpc: UnsafeCell::new(wdk_sys::KDPC::default()),
            reactor: AtomicPtr::new(core::ptr::null_mut()),
            index,
            generation: AtomicU64::new(0),
        }
    }

    /// Initializes native timer state and binds this envelope to its stable reactor.
    /// # Safety
    ///
    /// The envelope and `reactor` must both be at their final nonpaged addresses and remain live
    /// until every armed timer and DPC has drained.
    #[cfg(not(test))]
    unsafe fn initialize(&self, reactor: NonNull<CompletionReactor>) {
        unsafe {
            // SAFETY: The timer field is in final-address nonpaged device-extension storage.
            ffi::KeInitializeTimer(self.timer.get());
        }
        unsafe {
            // SAFETY: The DPC context points to this final-address envelope until teardown drains.
            ffi::KeInitializeDpc(
                self.dpc.get(),
                Some(storage_retry_timer_dpc),
                core::ptr::from_ref(self).cast_mut().cast::<c_void>(),
            );
        }
        self.reactor.store(reactor.as_ptr(), Ordering::Release);
    }

    /// Arms one concrete fixed-delay retry for the current slot generation.
    #[cfg(not(test))]
    fn arm(&self, generation: u64, delay: StorageRetryDelay) {
        self.generation.store(generation, Ordering::Release);
        let hundred_nanoseconds = match delay {
            StorageRetryDelay::TenMilliseconds => -100_000_i64,
            StorageRetryDelay::HundredMilliseconds => -1_000_000_i64,
        };
        let already_armed = unsafe {
            // SAFETY: This one-shot timer is armed only while its slot is in `Retry`.
            ffi::KeSetTimer(
                self.timer.get(),
                wdk_sys::LARGE_INTEGER {
                    QuadPart: hundred_nanoseconds,
                },
                self.dpc.get(),
            )
        };
        if already_armed != 0 {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }
}

// SAFETY: Native timer/DPC state is initialized once at a stable address; callbacks publish only
// atomics and the reactor thread exclusively owns operation payloads.
unsafe impl Sync for RetryTimerEnvelope {}

/// Resource ownership retained outside the suspended operation payload.
#[derive(Debug)]
struct HeldIntent {
    /// Mounted resource namespace.
    volume: NonNull<crate::state::VolumeControlBlock>,
    /// Stable FIFO ticket.
    ticket: u64,
    /// Complete atomically acquired resource set.
    resources: DriverVec<MutationResource>,
}

/// Serialized commit ownership retained by one active slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeldCommit {
    /// Mounted runtime whose gate was granted.
    volume: NonNull<crate::state::VolumeControlBlock>,
    /// Stable FIFO ticket.
    ticket: u64,
}

impl ActiveSlot {
    /// Creates one vacant slot.
    const fn vacant() -> Self {
        Self {
            generation: 0,
            intent: None,
            commit: None,
            cancel_pending: false,
            cancel_enabled: false,
            admission: None,
            predecessor: None,
            phase: ActivePhase::Vacant,
        }
    }
}

/// Device-owned completion reactor.
///
/// The CSQ remains the first field because native callbacks receive only its address. All shared
/// callback state is atomic or protected by `lock`; operation state advances only on the dedicated
/// PASSIVE_LEVEL system thread.
#[repr(C)]
pub(crate) struct CompletionReactor {
    /// Cancel-safe pending top-level IRP queue; must remain first.
    csq: wdk_sys::IO_CSQ,
    /// Spin lock shared by CSQ, completion-inbox, and active-cancel publication.
    lock: wdk_sys::KSPIN_LOCK,
    /// FIFO pending IRPs using `IRP.Tail.Overlay.ListEntry`.
    pending_head: UnsafeCell<LIST_ENTRY>,
    /// Completed lower envelopes using their first-field intrusive node.
    completion_head: UnsafeCell<LIST_ENTRY>,
    /// Completed mount length-query envelopes kept type-separated from storage commands.
    length_completion_head: UnsafeCell<LIST_ENTRY>,
    /// Pending plus active operation count, bounded by `MAX_OPERATIONS`.
    admitted: AtomicUsize,
    /// Auto-reset event signaled only when a concrete event is published.
    wake_event: wdk_sys::KEVENT,
    /// Bitset of retry timer events published by DPC callbacks.
    retry_ready: AtomicU64,
    /// Bitset of active top-level cancel events published by cancel routines.
    cancel_ready: AtomicU64,
    /// Running/draining/stopped lifecycle.
    lifecycle: AtomicU8,
    /// Capture-to-CSQ insertion teardown gate.
    admission: AdmissionRundown,
    /// Lifetime gate retained by every lower completion envelope.
    completion_rundown: CompletionRundown,
    /// System-thread handle joined during teardown.
    thread_handle: wdk_sys::HANDLE,
    /// Fixed operation registry; callbacks never dereference operation payloads.
    active: UnsafeCell<[ActiveSlot; MAX_OPERATIONS]>,
    /// One address-stable native timer envelope per bounded active slot.
    retry_timers: [RetryTimerEnvelope; MAX_OPERATIONS],
    /// One address-stable top-level cancel envelope per bounded active slot.
    cancel_envelopes: [ActiveCancelEnvelope; MAX_OPERATIONS],
    /// Device object owning this stable extension.
    device: KernelDevice,
}

impl CompletionReactor {
    /// Returns the checked reactor lifecycle.
    fn state(&self) -> ReactorState {
        ReactorState::from_raw(self.lifecycle.load(Ordering::Acquire)).unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        })
    }

    /// Begins terminal draining once.
    fn begin_drain(&self) {
        match self.lifecycle.compare_exchange(
            ReactorState::Running.as_raw(),
            ReactorState::Draining.as_raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(raw) if ReactorState::from_raw(raw) == Some(ReactorState::Stopped) => {}
            Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
        }
    }

    /// Returns the embedded CSQ address.
    #[cfg(not(test))]
    fn csq_ptr(&self) -> PIO_CSQ {
        core::ptr::addr_of!(self.csq).cast_mut()
    }

    /// Initializes one reactor directly in stable device-extension storage.
    /// # Safety
    ///
    /// `reactor` must remain at this address through [`Self::release_at`].
    /// # Errors
    ///
    /// Returns an error when native queue, event, timer, cancel, or worker-thread initialization
    /// cannot be completed.
    pub(crate) unsafe fn initialize_at(
        reactor: *mut Self,
        device: KernelDevice,
    ) -> DriverResult<()> {
        unsafe {
            // SAFETY: The caller owns writable, final-address device-extension bytes.
            core::ptr::write(
                reactor,
                Self {
                    csq: wdk_sys::IO_CSQ::default(),
                    lock: 0,
                    pending_head: UnsafeCell::new(LIST_ENTRY::default()),
                    completion_head: UnsafeCell::new(LIST_ENTRY::default()),
                    length_completion_head: UnsafeCell::new(LIST_ENTRY::default()),
                    admitted: AtomicUsize::new(0),
                    wake_event: wdk_sys::KEVENT::default(),
                    retry_ready: AtomicU64::new(0),
                    cancel_ready: AtomicU64::new(0),
                    lifecycle: AtomicU8::new(ReactorState::Running.as_raw()),
                    admission: AdmissionRundown::new(),
                    completion_rundown: CompletionRundown::new(),
                    thread_handle: core::ptr::null_mut(),
                    active: UnsafeCell::new(core::array::from_fn(|_| ActiveSlot::vacant())),
                    retry_timers: core::array::from_fn(RetryTimerEnvelope::inert),
                    cancel_envelopes: core::array::from_fn(ActiveCancelEnvelope::inert),
                    device,
                },
            );
        }
        let reactor = unsafe {
            // SAFETY: A complete value was written immediately above.
            reactor.as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        initialize_list_head(reactor.pending_head.get());
        initialize_list_head(reactor.completion_head.get());
        initialize_list_head(reactor.length_completion_head.get());
        reactor.admission.initialize();
        unsafe {
            // SAFETY: The embedded gate is now at its final device-extension address.
            reactor.completion_rundown.initialize();
        }
        #[cfg(not(test))]
        for timer in &reactor.retry_timers {
            unsafe {
                // SAFETY: Every timer and the reactor itself are now at their final addresses.
                timer.initialize(NonNull::from(reactor));
            }
        }
        #[cfg(not(test))]
        for envelope in &reactor.cancel_envelopes {
            let destination = unsafe {
                // SAFETY: Reactor storage is now final-address and remains live through drain.
                ActiveCancelDestination::new(
                    NonNull::from(reactor).cast::<c_void>(),
                    publish_active_cancel,
                )
            };
            unsafe {
                // SAFETY: Each fixed envelope is initialized exactly once before device exposure.
                envelope.initialize(destination);
            }
        }

        #[cfg(not(test))]
        {
            unsafe {
                // SAFETY: Stable reactor-owned spin-lock storage.
                ffi::KeInitializeSpinLock(core::ptr::addr_of!(reactor.lock).cast_mut());
            }
            let status = unsafe {
                // SAFETY: First-field CSQ and callbacks share this stable reactor lifetime.
                ffi::IoCsqInitialize(
                    reactor.csq_ptr(),
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
                // SAFETY: Stable event storage initialized before thread publication.
                ffi::KeInitializeEvent(
                    core::ptr::addr_of!(reactor.wake_event).cast_mut(),
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
                // SAFETY: Teardown joins this thread before releasing reactor storage.
                ffi::PsCreateSystemThread(
                    core::ptr::addr_of_mut!(thread_handle),
                    wdk_sys::SYNCHRONIZE,
                    core::ptr::addr_of_mut!(attributes),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    Some(completion_reactor_thread),
                    core::ptr::from_ref(reactor).cast_mut().cast::<c_void>(),
                )
            };
            if status < STATUS_SUCCESS || thread_handle.is_null() {
                return Err(DriverError::InsufficientResources);
            }
            unsafe {
                // SAFETY: Initialization is exclusive before device publication.
                core::ptr::addr_of!(reactor.thread_handle)
                    .cast_mut()
                    .write(thread_handle);
            }
        }
        Ok(())
    }

    /// Captures a queued request and emits only its admission event.
    pub(crate) fn receive(mut received: ReceivedIrp, major: DispatchMajor) -> NTSTATUS {
        let reactor = match Self::from_device(received.device()) {
            Ok(reactor) => reactor,
            Err(error) => return received.complete_result(Err(error)),
        };
        let reactor = unsafe {
            // SAFETY: Dispatch keeps the device extension stable through queue insertion.
            reactor.as_ref()
        };
        let Some(_admission) = reactor.admission.acquire() else {
            return received.complete_result(Err(DriverError::InvalidDeviceRequest));
        };
        if reactor.state() != ReactorState::Running {
            return received.complete_result(Err(DriverError::InvalidDeviceRequest));
        }
        let reservation = match OperationReservation::acquire(&reactor.admitted) {
            Ok(reservation) => reservation,
            Err(error) => return received.complete_result(Err(error)),
        };
        let context = match received.with_active(|active| QueueContext::capture(active, major)) {
            Ok(context) => context,
            Err(completion) => return received.complete(completion),
        };
        let pending = PendingIrp::from_received(received, context);
        let status = pending.dispatch_status();
        reactor.enqueue(pending, reservation);
        status
    }

    /// Removes and completes every queued ordinary request for one FILE_OBJECT.
    fn cancel_pending_ordinary(&self, file_object: KernelFileObject) {
        let selection = PendingIrpSelection::cleanup(file_object);
        loop {
            let irp = self.remove_next_irp(Some(&selection));
            if irp.is_null() {
                return;
            }
            let owned = OwnedIrp::from_queued_raw(self.device, irp);
            release_operation_reservation(&self.admitted);
            let _status = owned.complete_cancelled();
        }
    }

    /// Returns the reactor prefix of a driver-owned device extension.
    /// # Errors
    ///
    /// Returns [`DriverError::InvalidParameter`] when either the device object or its extension is
    /// null.
    fn from_device(device: KernelDevice) -> DriverResult<NonNull<Self>> {
        let object = unsafe {
            // SAFETY: Dispatch owns a live typed device pointer.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        NonNull::new(object.DeviceExtension.cast::<Self>()).ok_or(DriverError::InvalidParameter)
    }

    /// Publishes a pending IRP to the CSQ, then wakes the reactor for its admission event.
    fn enqueue(&self, pending: PendingIrp, reservation: OperationReservation) {
        #[cfg(test)]
        mark_pending_for_csq_test(pending.target.irp);
        let irp = pending.publish();
        reservation.publish();
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Context and reservation ownership transfer before CSQ insertion; inline
            // cancellation may consume the IRP, so it is not touched afterward.
            ffi::IoCsqInsertIrp(
                self.csq_ptr(),
                irp,
                core::ptr::null_mut::<wdk_sys::IO_CSQ_IRP_CONTEXT>(),
            );
        }
        #[cfg(test)]
        self.insert_irp(irp);
        self.wake();
    }

    /// Signals that at least one concrete admission/completion/cancel/grant event exists.
    fn wake(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Event lifetime covers admission through reactor-thread join.
            let _previous = ffi::KeSetEvent(core::ptr::addr_of!(self.wake_event).cast_mut(), 0, 0);
        }
    }

    /// Removes the next queued IRP matching an optional synchronous selection.
    fn remove_next_irp(&self, selection: Option<&PendingIrpSelection>) -> PIRP {
        let context = selection.map_or(core::ptr::null_mut(), |selection| {
            core::ptr::from_ref(selection).cast_mut().cast::<c_void>()
        });
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The CSQ serializes removal with insertion and cancellation.
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

    /// Inserts one IRP at the pending FIFO tail while the CSQ lock is held.
    fn insert_irp(&self, irp: PIRP) {
        let Some(entry) = irp_list_entry(irp) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        insert_tail_list(self.pending_head.get(), entry);
    }

    /// Removes one pending IRP while the CSQ lock is held.
    fn remove_irp(&self, irp: PIRP) {
        let Some(entry) = irp_list_entry(irp) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        remove_entry_list(entry);
    }

    /// Finds the next pending IRP matching an optional FILE_OBJECT identity.
    fn peek_next_irp(&self, irp: PIRP, context: PVOID) -> PIRP {
        let head = self.pending_head.get();
        let mut entry = if irp.is_null() {
            unsafe {
                // SAFETY: Initialized list is held under the CSQ lock.
                (*head).Flink
            }
        } else {
            let Some(entry) = irp_list_entry(irp) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            unsafe {
                // SAFETY: The supplied IRP remains linked under the CSQ lock.
                (*entry).Flink
            }
        };
        while entry != head {
            let candidate = irp_from_list_entry(entry);
            if queued_irp_matches_context(candidate, context) {
                return candidate;
            }
            entry = unsafe {
                // SAFETY: Current entry remains linked under the CSQ lock.
                (*entry).Flink
            };
        }
        core::ptr::null_mut()
    }

    /// Reserves one vacant slot before its stable active-cancel envelope becomes visible.
    /// # Errors
    ///
    /// Returns an invariant error when no slot is vacant or the selected generation overflows.
    fn reserve_active_slot(&self) -> DriverResult<usize> {
        let slots = unsafe {
            // SAFETY: Only the dedicated reactor thread installs or advances operation payloads.
            &mut *self.active.get()
        };
        let Some((index, slot)) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| matches!(slot.phase, ActivePhase::Vacant))
        else {
            return Err(DriverError::InternalInvariantViolation);
        };
        slot.generation = slot
            .generation
            .checked_add(1)
            .ok_or(DriverError::InternalInvariantViolation)?;
        slot.cancel_pending = false;
        slot.cancel_enabled = true;
        slot.admission = None;
        slot.predecessor = None;
        Ok(index)
    }

    /// Installs an operation after cancellation was bound to its reserved fixed slot.
    #[cfg(not(test))]
    fn install_admitted_at(&self, index: usize, admitted: AdmittedOperation) {
        let (operation, admission) = admitted.into_parts();
        let cancelled = self.take_cancel_bit(index);
        let slots = unsafe {
            // SAFETY: Only the reactor thread installs the operation payload.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !matches!(slot.phase, ActivePhase::Vacant)
            || slot.intent.is_some()
            || slot.commit.is_some()
            || slot.admission.is_some()
            || slot.predecessor.is_some()
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let terminal_barrier = admission.is_terminal_handle_barrier();
        let predecessor = admission
            .file_object()
            .and_then(|file_object| latest_handle_predecessor(slots, index, file_object));
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        slot.cancel_enabled = !terminal_barrier;
        slot.cancel_pending = cancelled && !terminal_barrier;
        slot.admission = Some(admission);
        slot.predecessor = predecessor;
        slot.phase = if slot.cancel_pending {
            ActivePhase::Ready {
                operation,
                event: OperationEvent::CancelRequested,
            }
        } else if predecessor.is_some() {
            ActivePhase::HandleTurn { operation }
        } else {
            ActivePhase::Ready {
                operation,
                event: OperationEvent::Admitted,
            }
        };

        if let OperationAdmission::Handle {
            file_object,
            lane: HandleOperationLane::Cleanup,
        } = admission
        {
            self.cancel_active_ordinary_for_cleanup(index, file_object);
            self.cancel_pending_ordinary(file_object);
        }
    }

    /// Publishes cancellation to every active ordinary operation preceding one CLEANUP barrier.
    #[cfg(not(test))]
    fn cancel_active_ordinary_for_cleanup(
        &self,
        cleanup_index: usize,
        file_object: KernelFileObject,
    ) {
        let mut targets = 0_u64;
        {
            let slots = unsafe {
                // SAFETY: Only the reactor thread observes independent admission metadata.
                &*self.active.get()
            };
            for (index, slot) in slots.iter().enumerate() {
                if index != cleanup_index
                    && slot.admission.is_some_and(|admission| {
                        admission.file_object() == Some(file_object)
                            && admission.is_ordinary_handle()
                    })
                {
                    targets |= slot_bit(index);
                }
            }
        }
        while targets != 0 {
            let index = match usize::try_from(targets.trailing_zeros()) {
                Ok(index) => index,
                Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            targets &= !slot_bit(index);
            self.request_active_cancel(index);
        }
    }

    /// Clears cancellation bookkeeping after terminal IRP authority has been consumed.
    fn retire_cancel_slot(&self, index: usize) {
        let _was_pending = self.take_cancel_bit(index);
        let slots = unsafe {
            // SAFETY: Only the reactor thread retires slot-local cancellation state.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        slot.cancel_pending = false;
        slot.cancel_enabled = false;
    }

    /// Replaces the operation's next action with its already-published cancel event when legal.
    fn resume_cancel_if_requested(
        &self,
        index: usize,
        suspended: SuspendedOperation,
    ) -> Option<SuspendedOperation> {
        if !self.cancellation_is_pending(index) {
            return Some(suspended);
        }
        let slots = unsafe {
            // SAFETY: Only the reactor thread observes slot-local cancellation state.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !matches!(slot.phase, ActivePhase::Vacant) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        slot.phase = ActivePhase::Ready {
            operation: suspended,
            event: OperationEvent::CancelRequested,
        };
        None
    }

    /// Atomically linearizes cancellation before the first effect-bearing write or flush.
    ///
    /// A callback publication observed by the atomic exchange wins the boundary. A publication
    /// after that exchange is ordered after effect authority was consumed and is retired later.
    fn consume_cancellation_before_effect(&self, index: usize) -> bool {
        let published = self.take_cancel_bit(index);
        let slots = unsafe {
            // SAFETY: Only the reactor thread consumes slot-local cancel authority.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !slot.cancel_enabled {
            slot.cancel_pending = false;
            return false;
        }
        slot.cancel_pending |= published;
        if slot.cancel_pending {
            return true;
        }
        slot.cancel_enabled = false;
        false
    }

    /// Folds callback publication into the reactor-owned slot and reports one legal cancel event.
    fn cancellation_is_pending(&self, index: usize) -> bool {
        let published = self.take_cancel_bit(index);
        let slots = unsafe {
            // SAFETY: Only the reactor thread folds callback publication into slot-local state.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !slot.cancel_enabled {
            slot.cancel_pending = false;
            return false;
        }
        slot.cancel_pending |= published;
        slot.cancel_pending
    }

    /// Installs one resumed event, giving an already-published legal cancel precedence.
    #[cfg(not(test))]
    fn set_ready_operation_event(
        &self,
        index: usize,
        operation: SuspendedOperation,
        event: OperationEvent,
    ) {
        let event = if self.cancellation_is_pending(index) {
            OperationEvent::CancelRequested
        } else {
            event
        };
        self.set_phase(index, ActivePhase::Ready { operation, event });
    }

    /// Atomically consumes this fixed slot's callback-published cancel bit.
    fn take_cancel_bit(&self, index: usize) -> bool {
        let mask = slot_bit(index);
        self.cancel_ready.fetch_and(!mask, Ordering::AcqRel) & mask != 0
    }

    /// Consumes callback-published active cancels without touching unrelated operations.
    #[cfg(not(test))]
    fn drain_active_cancels(&self) -> bool {
        let mut ready = self.cancel_ready.swap(0, Ordering::AcqRel);
        if ready == 0 {
            return false;
        }
        while ready != 0 {
            let index = match usize::try_from(ready.trailing_zeros()) {
                Ok(index) => index,
                Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            let mask = slot_bit(index);
            ready &= !mask;
            self.request_active_cancel(index);
        }
        true
    }

    /// Publishes cancellation into one active slot or its exact published lower request.
    #[cfg(not(test))]
    fn request_active_cancel(&self, index: usize) {
        let slots = unsafe {
            // SAFETY: Only the reactor thread mutates active phases and cancellation state.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !slot.cancel_enabled {
            slot.cancel_pending = false;
            return;
        }
        slot.cancel_pending = true;
        let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
        slot.phase = match phase {
            ActivePhase::Ready { operation, .. } => ActivePhase::Ready {
                operation,
                event: OperationEvent::CancelRequested,
            },
            ActivePhase::HandleTurn { operation } => ActivePhase::Ready {
                operation,
                event: OperationEvent::CancelRequested,
            },
            ActivePhase::Intent { operation, .. }
            | ActivePhase::Commit { operation, .. }
            | ActivePhase::Waiting { operation, .. } => ActivePhase::Ready {
                operation,
                event: OperationEvent::CancelRequested,
            },
            ActivePhase::Lower(lower) => {
                unsafe {
                    // SAFETY: This active phase retains the exact published lower identity.
                    lower.cancel();
                }
                ActivePhase::Lower(lower)
            }
            ActivePhase::Retry(retry) => ActivePhase::Retry(retry),
            ActivePhase::Registering => ActivePhase::Registering,
            ActivePhase::Vacant => {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            }
        };
    }

    /// Returns whether any active slot still owns work.
    fn has_active(&self) -> bool {
        let slots = unsafe {
            // SAFETY: Only the reactor thread calls this lifecycle observation.
            &*self.active.get()
        };
        slots
            .iter()
            .any(|slot| !matches!(slot.phase, ActivePhase::Vacant))
    }

    /// Releases reactor-owned resources after dispatch admission has been closed.
    /// # Safety
    ///
    /// No new dispatch callback may enter this device extension. The mounted state and completion
    /// destination must remain live until this method joins the reactor and drains rundown.
    pub(crate) unsafe fn release_at(reactor: *mut Self) {
        let Some(mut reactor_address) = NonNull::new(reactor) else {
            return;
        };
        let reactor = unsafe {
            // SAFETY: Device teardown retains the stable extension through this method.
            reactor_address.as_ref()
        };
        reactor.begin_drain();
        reactor.admission.close_and_wait();
        loop {
            let irp = reactor.remove_next_irp(None);
            if irp.is_null() {
                break;
            }
            let owned = OwnedIrp::from_queued_raw(reactor.device, irp);
            release_operation_reservation(&reactor.admitted);
            let _status = owned.complete_cancelled();
        }
        reactor.wake();

        #[cfg(not(test))]
        {
            let thread_handle = reactor.thread_handle;
            if thread_handle.is_null() {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            let wait_status = unsafe {
                // SAFETY: Initialization stored the sole system-thread kernel handle.
                ffi::ZwWaitForSingleObject(thread_handle, 0, core::ptr::null_mut())
            };
            if wait_status < STATUS_SUCCESS {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            let close_status = unsafe {
                // SAFETY: The joined thread can no longer use this handle.
                ffi::ZwClose(thread_handle)
            };
            if close_status < STATUS_SUCCESS {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
        #[cfg(test)]
        reactor
            .lifecycle
            .store(ReactorState::Stopped.as_raw(), Ordering::Release);

        unsafe {
            // SAFETY: The thread is joined and every completion can still reach this empty inbox.
            reactor.completion_rundown.close_and_wait();
        }
        if reactor.state() != ReactorState::Stopped
            || reactor.admitted.load(Ordering::Acquire) != 0
            || reactor.has_active()
            || !list_is_empty(reactor.completion_head.get())
            || !list_is_empty(reactor.length_completion_head.get())
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let reactor = unsafe {
            // SAFETY: Join, empty slots, and rundown closure grant exclusive teardown access.
            reactor_address.as_mut()
        };
        reactor.thread_handle = core::ptr::null_mut();
        unsafe {
            // SAFETY: Rust-owned fields are released exactly once before extension bytes vanish.
            core::ptr::drop_in_place(reactor);
        }
    }

    /// Runs concrete-event delivery on the sole PASSIVE_LEVEL reactor thread.
    #[cfg(not(test))]
    fn run(&self) {
        loop {
            let mut progressed = self.drain_storage_completions();
            progressed |= self.drain_length_completions();
            progressed |= self.drain_active_cancels();
            progressed |= self.drain_retry_events();
            progressed |= self.admit_pending_requests();
            progressed |= self.drive_ready_operations();
            if self.state() == ReactorState::Draining
                && self.admitted.load(Ordering::Acquire) == 0
                && !self.has_active()
                && list_is_empty(self.completion_head.get())
                && list_is_empty(self.length_completion_head.get())
            {
                self.lifecycle
                    .store(ReactorState::Stopped.as_raw(), Ordering::Release);
                return;
            }
            if !progressed {
                self.wait_for_event();
            }
        }
    }

    /// Waits for a newly published admission, lower completion, cancel, timer, or grant event.
    #[cfg(not(test))]
    fn wait_for_event(&self) {
        let status = unsafe {
            // SAFETY: This thread is the sole waiter on the initialized auto-reset event.
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
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Converts pending CSQ ownership into explicit operation admission events.
    #[cfg(not(test))]
    fn admit_pending_requests(&self) -> bool {
        let mut admitted_any = false;
        loop {
            let irp = self.remove_next_irp(None);
            if irp.is_null() {
                return admitted_any;
            }
            admitted_any = true;
            let mut owned = OwnedIrp::from_queued_raw(self.device, irp);
            let index = match self.reserve_active_slot() {
                Ok(index) => index,
                Err(_) => {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
            };
            let Some(envelope) = self.cancel_envelopes.get(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            owned.install_active_cancellation(NonNull::from(envelope));
            match crate::request::dispatch::admit_owned(owned) {
                Ok(operation) => {
                    self.install_admitted_at(index, operation);
                }
                Err(error) => {
                    let (error, owned) = error.into_parts();
                    release_operation_reservation(&self.admitted);
                    let _status = owned.complete_result(Err(error));
                    self.retire_cancel_slot(index);
                }
            }
        }
    }

    /// Advances every slot that already owns one concrete event, never probing waiting slots.
    #[cfg(not(test))]
    fn drive_ready_operations(&self) -> bool {
        let mut progressed = false;
        loop {
            let ready = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread moves operation payloads.
                    &mut *self.active.get()
                };
                slots.iter_mut().enumerate().find_map(|(index, slot)| {
                    let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
                    match phase {
                        ActivePhase::Ready { operation, event } => Some((index, operation, event)),
                        phase => {
                            slot.phase = phase;
                            None
                        }
                    }
                })
            };
            let Some((index, operation, event)) = ready else {
                return progressed;
            };
            progressed = true;
            let transition = operation.advance(event);
            self.apply_transition(index, transition);
        }
    }

    /// Applies one operation transition without executing any unrelated operation.
    #[cfg(not(test))]
    fn apply_transition(&self, index: usize, transition: OperationTransition) {
        match transition {
            OperationTransition::QueryDeviceLength {
                completion_owner,
                target,
                suspended,
            } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    return;
                };
                self.submit_device_length(index, completion_owner, target, suspended);
            }
            OperationTransition::SubmitLower {
                devices,
                request,
                suspended,
            } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    drop(request);
                    return;
                };
                self.submit_storage(index, devices, request, suspended);
            }
            OperationTransition::RequestIntent { request, suspended } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    drop(request);
                    return;
                };
                let retained = {
                    let slots = unsafe {
                        // SAFETY: Only this reactor thread observes scheduler-owned intent state.
                        &*self.active.get()
                    };
                    let Some(slot) = slots.get(index) else {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    };
                    slot.intent
                        .as_ref()
                        .is_some_and(|held| held_intent_matches_request(held, &request))
                };
                if retained {
                    let ticket = request.ticket();
                    drop(request);
                    self.set_ready_operation_event(
                        index,
                        suspended,
                        OperationEvent::IntentGranted(ext4_core::MutationLease::granted(ticket)),
                    );
                    return;
                }
                self.release_intent(index);
                self.set_phase(
                    index,
                    ActivePhase::Intent {
                        request,
                        operation: suspended,
                    },
                );
                self.grant_available_intents();
            }
            OperationTransition::RequestCommit {
                volume,
                ticket,
                suspended,
            } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    return;
                };
                self.set_phase(
                    index,
                    ActivePhase::Commit {
                        volume,
                        ticket,
                        operation: suspended,
                    },
                );
                self.grant_available_commit();
            }
            OperationTransition::ArmRetry { retry } => {
                self.arm_retry(index, retry);
            }
            OperationTransition::Wait {
                condition,
                suspended,
            } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    return;
                };
                self.set_phase(
                    index,
                    ActivePhase::Waiting {
                        condition,
                        operation: suspended,
                    },
                );
                self.grant_available_wait(index);
            }
            OperationTransition::Publish { publication } => {
                let authority = publication.authority();
                self.consume_publication_authority(index, authority);
                let operation = publication.publish();
                if matches!(authority, PublicationAuthority::Durable { .. }) {
                    self.retire_cancel_slot(index);
                    self.release_handle_lane(index);
                }
                self.set_ready_operation_event(index, operation, OperationEvent::Admitted);
                self.grant_available_intents();
                self.grant_available_commit();
                self.grant_all_available_waits();
                self.grant_all_handle_turns();
            }
            OperationTransition::Complete => {
                self.release_intent(index);
                self.abandon_commit(index);
                self.set_phase(index, ActivePhase::Vacant);
                self.release_handle_lane(index);
                self.retire_cancel_slot(index);
                release_operation_reservation(&self.admitted);
                self.grant_available_intents();
                self.grant_available_commit();
                self.grant_all_available_waits();
                self.grant_all_handle_turns();
            }
        }
    }

    /// Replaces one reactor-thread-owned active phase after validating its slot.
    #[cfg(not(test))]
    fn set_phase(&self, index: usize, phase: ActivePhase) {
        let slots = unsafe {
            // SAFETY: Only the reactor thread moves phase payloads.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !matches!(slot.phase, ActivePhase::Vacant) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        slot.phase = phase;
    }

    /// Detaches one top-level FILE_OBJECT lane while a post-publication checkpoint may continue.
    #[cfg(not(test))]
    fn release_handle_lane(&self, index: usize) {
        let slots = unsafe {
            // SAFETY: Only the reactor thread mutates scheduler admission metadata.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        slot.admission = None;
        slot.predecessor = None;
    }

    /// Delivers admission only to handle operations whose exact predecessor has terminated.
    #[cfg(not(test))]
    fn grant_all_handle_turns(&self) {
        for index in 0..MAX_OPERATIONS {
            let ready = {
                let slots = unsafe {
                    // SAFETY: Only the reactor thread observes the fixed predecessor registry.
                    &*self.active.get()
                };
                let Some(slot) = slots.get(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                matches!(slot.phase, ActivePhase::HandleTurn { .. })
                    && slot
                        .predecessor
                        .is_none_or(|predecessor| !active_predecessor_is_live(slots, predecessor))
            };
            if !ready {
                continue;
            }
            let operation = {
                let slots = unsafe {
                    // SAFETY: Only the reactor thread moves the now-unblocked operation payload.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
                let ActivePhase::HandleTurn { operation } = phase else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                slot.predecessor = None;
                operation
            };
            self.set_ready_operation_event(index, operation, OperationEvent::Admitted);
        }
    }

    /// Releases any resource set retained by one slot.
    #[cfg(not(test))]
    fn release_intent(&self, index: usize) {
        let slots = unsafe {
            // SAFETY: Resource ownership is mutated only by the reactor thread.
            &mut *self.active.get()
        };
        let Some(slot) = slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        drop(slot.intent.take());
    }

    /// Returns a pre-write commit grant to its mounted runtime.
    #[cfg(not(test))]
    fn abandon_commit(&self, index: usize) {
        let commit = {
            let slots = unsafe {
                // SAFETY: Commit ownership is mutated only by the reactor thread.
                &mut *self.active.get()
            };
            let Some(slot) = slots.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            slot.commit.take()
        };
        if let Some(commit) = commit {
            let mut access = unsafe {
                // SAFETY: The mounted VCB is stable and this reactor transition is non-suspending.
                crate::state::VolumeControlBlock::operation_access(commit.volume)
            };
            access.runtime_mut().abandon_commit(commit.ticket);
        }
    }

    /// Consumes exactly the grants required by one infallible publication.
    #[cfg(not(test))]
    fn consume_publication_authority(&self, index: usize, authority: PublicationAuthority) {
        match authority {
            PublicationAuthority::Durable { volume, ticket } => {
                let slots = unsafe {
                    // SAFETY: Publication runs only on the sole reactor thread.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let intent = slot.intent.take();
                let commit = slot.commit.take();
                if !matches!(
                    intent,
                    Some(HeldIntent {
                        volume: held_volume,
                        ticket: held_ticket,
                        ..
                    }) if held_volume == volume && held_ticket == ticket
                ) || commit != Some(HeldCommit { volume, ticket })
                {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
            }
            PublicationAuthority::Checkpoint { .. } => {
                let slots = unsafe {
                    // SAFETY: Publication runs only on the sole reactor thread.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if slot.intent.is_some() || slot.commit.is_some() {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
            }
        }
    }

    /// Builds, registers, and submits one lower storage command with ownership-preserving errors.
    #[cfg(not(test))]
    fn submit_storage(
        &self,
        index: usize,
        devices: MountedStorageDevices,
        request: StorageRequest,
        suspended: SuspendedOperation,
    ) {
        let prepared = match PreparedStorageCommand::try_new(devices, request, suspended) {
            Ok(prepared) => prepared,
            Err(error) => {
                let (error, suspended, request) = error.into_parts();
                self.set_ready_storage_failure(index, suspended, request, error);
                return;
            }
        };
        self.submit_prepared_storage(index, prepared);
    }

    /// Builds, registers, and submits the private mount-time length query.
    #[cfg(not(test))]
    fn submit_device_length(
        &self,
        index: usize,
        completion_owner: KernelDevice,
        target: KernelDevice,
        suspended: SuspendedOperation,
    ) {
        let Some(rundown) = self.completion_rundown.acquire() else {
            self.set_ready_length_failure(index, suspended, DriverError::InvalidDeviceRequest);
            return;
        };
        let destination = LengthCompletionRoute {
            reactor: NonNull::from(self),
        };
        let mut lower = match DeviceLengthProbe::prepare(
            completion_owner,
            target,
            suspended,
            destination,
            rundown,
        ) {
            Ok(lower) => lower,
            Err(error) => {
                let (error, probe) = error.into_parts();
                self.set_ready_length_failure(index, probe.into_suspended(), error);
                return;
            }
        };
        let cancellation = lower.cancellation_identity();
        self.set_phase(index, ActivePhase::Registering);
        match lower.register_and_submit() {
            Ok(()) => {
                let slots = unsafe {
                    // SAFETY: Submission and this publication run on the sole reactor thread.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !matches!(slot.phase, ActivePhase::Registering) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                slot.phase = ActivePhase::Lower(PublishedReactorLower::Length(cancellation));
            }
            Err(error) => {
                let (error, probe) = error.into_parts();
                let slots = unsafe {
                    // SAFETY: Registration failure cannot have published a completion callback.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !matches!(slot.phase, ActivePhase::Registering) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                slot.phase = ActivePhase::Vacant;
                self.set_ready_length_failure(index, probe.into_suspended(), error);
            }
        }
    }

    /// Sends one completely prepared command through a fresh private IRP.
    #[cfg(not(test))]
    fn submit_prepared_storage(
        &self,
        index: usize,
        prepared: PreparedStorageCommand<SuspendedOperation>,
    ) {
        if prepared.is_effect_bearing() && self.consume_cancellation_before_effect(index) {
            let (suspended, _request) = prepared.into_command().into_parts();
            self.set_ready_operation_event(index, suspended, OperationEvent::CancelRequested);
            return;
        }
        let Some(rundown) = self.completion_rundown.acquire() else {
            let command = prepared.into_command();
            let (suspended, request) = command.into_parts();
            self.set_ready_storage_failure(
                index,
                suspended,
                request,
                DriverError::InvalidDeviceRequest,
            );
            return;
        };
        let destination = StorageCompletionRoute {
            reactor: NonNull::from(self),
        };
        let mut lower = match prepared.build_lower(destination, rundown) {
            Ok(lower) => lower,
            Err(error) => {
                let (error, command) = error.into_parts();
                let (suspended, request) = command.into_parts();
                self.set_ready_storage_failure(index, suspended, request, error);
                return;
            }
        };
        let cancellation = lower.cancellation_identity();
        self.set_phase(index, ActivePhase::Registering);
        match lower.register_and_submit() {
            Ok(()) => {
                let slots = unsafe {
                    // SAFETY: Submission and this publication run on the sole reactor thread.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !matches!(slot.phase, ActivePhase::Registering) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                slot.phase = ActivePhase::Lower(PublishedReactorLower::Storage(cancellation));
            }
            Err(error) => {
                let (error, command) = error.into_parts();
                let (suspended, request) = command.into_parts();
                let slots = unsafe {
                    // SAFETY: Registration failure cannot have published a completion callback.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !matches!(slot.phase, ActivePhase::Registering) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                slot.phase = ActivePhase::Vacant;
                self.set_ready_storage_failure(index, suspended, request, error);
            }
        }
    }

    /// Converts a never-submitted driver error into one concrete core completion event.
    #[cfg(not(test))]
    fn set_ready_storage_failure(
        &self,
        index: usize,
        suspended: SuspendedOperation,
        request: StorageRequest,
        error: DriverError,
    ) {
        let error = driver_error_to_core(error);
        self.set_ready_operation_event(
            index,
            suspended,
            OperationEvent::StorageCompleted(failed_unsubmitted_request(request, error)),
        );
    }

    /// Converts an unsubmitted length-query failure into its concrete mount event.
    #[cfg(not(test))]
    fn set_ready_length_failure(
        &self,
        index: usize,
        suspended: SuspendedOperation,
        error: DriverError,
    ) {
        self.set_ready_operation_event(
            index,
            suspended,
            OperationEvent::DeviceLengthCompleted(Err(driver_error_to_core(error))),
        );
    }

    /// Links one completed envelope into the allocation-free storage inbox.
    /// # Safety
    ///
    /// `envelope` must be uniquely completion-owned, unlinked, nonpaged, and protected by this
    /// reactor's completion rundown lease.
    #[cfg(not(test))]
    unsafe fn enqueue_storage(&self, envelope: NonNull<ReactorStorageEnvelope>) {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion callbacks and inbox removal.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        insert_tail_list(self.completion_head.get(), unsafe {
            // SAFETY: Completion owns this unlinked first-field node until publication.
            envelope.as_ref().node_ptr()
        });
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        self.wake();
    }

    /// Removes one completed storage envelope, if present.
    #[cfg(not(test))]
    fn pop_storage_completion(&self) -> Option<NonNull<ReactorStorageEnvelope>> {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion list access.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = remove_head_list(self.completion_head.get());
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        node.map(|node| unsafe {
            // SAFETY: The envelope's node is its first field.
            LowerCompletionEnvelope::from_node(node)
        })
    }

    /// Reclaims and routes all lower completions currently published to this reactor.
    #[cfg(not(test))]
    fn drain_storage_completions(&self) -> bool {
        let mut progressed = false;
        while let Some(envelope) = self.pop_storage_completion() {
            progressed = true;
            let index = self.take_completed_lower_slot(envelope);
            let envelope = unsafe {
                // SAFETY: Inbox removal and slot detachment grant unique envelope ownership.
                Box::from_raw(envelope.as_ptr())
            };
            let completed = unsafe {
                // SAFETY: Completion publication proves lower buffer use and cancel races ended.
                LowerCompletionEnvelope::reclaim(envelope)
            };
            match completed.advance() {
                Ok(StorageCommandStep::SubmitNext(prepared)) => {
                    self.submit_prepared_storage(index, prepared);
                }
                Ok(StorageCommandStep::Complete {
                    suspended,
                    completion,
                }) => {
                    self.set_ready_operation_event(
                        index,
                        suspended,
                        OperationEvent::StorageCompleted(completion),
                    );
                }
                Ok(StorageCommandStep::Failed(failed)) => match failed.into_retry() {
                    StorageRetryDecision::Retry(retry) => {
                        self.apply_transition(index, OperationTransition::ArmRetry { retry })
                    }
                    StorageRetryDecision::Terminal(failed) => {
                        let (mut suspended, request, class) = failed.into_failure();
                        suspended.record_storage_failure(class);
                        self.set_ready_operation_event(
                            index,
                            suspended,
                            OperationEvent::StorageCompleted(failed_unsubmitted_request(
                                request,
                                ext4_core::Error::DeviceIo,
                            )),
                        );
                    }
                },
                Err(_error) => {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
            }
        }
        progressed
    }

    /// Links one completed length-query envelope into its type-separated inbox.
    /// # Safety
    ///
    /// `envelope` must be uniquely completion-owned, unlinked, nonpaged, and protected by this
    /// reactor's completion rundown lease.
    #[cfg(not(test))]
    unsafe fn enqueue_length(&self, envelope: NonNull<ReactorLengthEnvelope>) {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion callbacks and inbox removal.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        insert_tail_list(self.length_completion_head.get(), unsafe {
            // SAFETY: Completion owns this unlinked first-field node until publication.
            envelope.as_ref().node_ptr()
        });
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        self.wake();
    }

    /// Removes one completed length-query envelope, if present.
    #[cfg(not(test))]
    fn pop_length_completion(&self) -> Option<NonNull<ReactorLengthEnvelope>> {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion list access.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = remove_head_list(self.length_completion_head.get());
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        node.map(|node| unsafe {
            // SAFETY: The envelope's node is its first field.
            LowerCompletionEnvelope::from_node(node)
        })
    }

    /// Reclaims and routes every completed mount-time device-length query.
    #[cfg(not(test))]
    fn drain_length_completions(&self) -> bool {
        let mut progressed = false;
        while let Some(envelope) = self.pop_length_completion() {
            progressed = true;
            let index = self.take_completed_length_slot(envelope);
            let envelope = unsafe {
                // SAFETY: Inbox removal and slot detachment grant unique envelope ownership.
                Box::from_raw(envelope.as_ptr())
            };
            let completed = unsafe {
                // SAFETY: Completion publication proves lower buffer use and cancel races ended.
                LowerCompletionEnvelope::reclaim(envelope)
            };
            match completed.finish() {
                Ok((suspended, length)) => self.set_ready_operation_event(
                    index,
                    suspended,
                    OperationEvent::DeviceLengthCompleted(Ok(length)),
                ),
                Err((suspended, error)) => {
                    self.set_ready_length_failure(index, suspended, error);
                }
            }
        }
        progressed
    }

    /// Detaches the active lower cancellation identity before reclaim can free the envelope.
    #[cfg(not(test))]
    fn take_completed_lower_slot(&self, envelope: NonNull<ReactorStorageEnvelope>) -> usize {
        let slots = unsafe {
            // SAFETY: Only the reactor thread mutates slot payloads; completion only linked a node.
            &mut *self.active.get()
        };
        for (index, slot) in slots.iter_mut().enumerate() {
            let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
            match phase {
                ActivePhase::Lower(PublishedReactorLower::Storage(lower))
                    if lower.identifies(envelope) =>
                {
                    return index;
                }
                phase => slot.phase = phase,
            }
        }
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    }

    /// Detaches one completed length-query identity before reclaim frees its envelope.
    #[cfg(not(test))]
    fn take_completed_length_slot(&self, envelope: NonNull<ReactorLengthEnvelope>) -> usize {
        let slots = unsafe {
            // SAFETY: Only the reactor thread mutates slot payloads; completion only linked a node.
            &mut *self.active.get()
        };
        for (index, slot) in slots.iter_mut().enumerate() {
            let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
            match phase {
                ActivePhase::Lower(PublishedReactorLower::Length(lower))
                    if lower.identifies(envelope) =>
                {
                    return index;
                }
                phase => slot.phase = phase,
            }
        }
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    }

    /// Retains one retry command until its concrete fixed-delay timer event arrives.
    #[cfg(not(test))]
    fn arm_retry(&self, index: usize, retry: RetryingStorageCommand<SuspendedOperation>) {
        if self.cancellation_is_pending(index) {
            let (suspended, _request) = retry.into_parts();
            self.set_ready_operation_event(index, suspended, OperationEvent::CancelRequested);
            return;
        }
        let delay = retry.delay();
        self.set_phase(index, ActivePhase::Retry(retry));
        let generation = {
            let slots = unsafe {
                // SAFETY: Only this reactor thread observes active slot generations.
                &*self.active.get()
            };
            let Some(slot) = slots.get(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            slot.generation
        };
        let Some(timer) = self.retry_timers.get(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        timer.arm(generation, delay);
    }

    /// Consumes timer events published by DPC callbacks and builds a fresh private IRP attempt.
    #[cfg(not(test))]
    fn drain_retry_events(&self) -> bool {
        let mut ready = self.retry_ready.swap(0, Ordering::AcqRel);
        if ready == 0 {
            return false;
        }
        while ready != 0 {
            let index = match usize::try_from(ready.trailing_zeros()) {
                Ok(index) => index,
                Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            let shift = match u32::try_from(index) {
                Ok(shift) => shift,
                Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            let Some(mask) = 1_u64.checked_shl(shift) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            ready &= !mask;
            let generation = match self.retry_timers.get(index) {
                Some(timer) => timer.generation.load(Ordering::Acquire),
                None => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            let retry = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread moves retry command payloads.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if slot.generation != generation {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
                let ActivePhase::Retry(retry) = phase else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                retry
            };
            if self.cancellation_is_pending(index) {
                let (suspended, _request) = retry.into_parts();
                self.set_ready_operation_event(index, suspended, OperationEvent::CancelRequested);
                continue;
            }
            let prepared = match retry.permitted() {
                Ok(prepared) => prepared,
                Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            self.submit_prepared_storage(index, prepared);
        }
        true
    }

    /// Grants newly unblocked resource sets in stable FIFO order.
    #[cfg(not(test))]
    fn grant_available_intents(&self) {
        self.grant_intents_in_fifo_order();
    }

    /// Grants the sole commit slot when checkpoint/journal-space state permits it.
    #[cfg(not(test))]
    fn grant_available_commit(&self) {
        self.grant_next_commit();
    }

    /// Grants an already-satisfied visibility/checkpoint/barrier wait without probing its operation.
    #[cfg(not(test))]
    fn grant_available_wait(&self, index: usize) {
        self.grant_wait_if_ready(index);
    }

    /// Rechecks every concrete gate after commit/checkpoint ownership changes.
    #[cfg(not(test))]
    fn grant_all_available_waits(&self) {
        for index in 0..MAX_OPERATIONS {
            self.grant_wait_if_ready(index);
        }
    }

    /// Grants every resource request that is conflict-free without bypassing an earlier
    /// conflicting FIFO ticket.
    #[cfg(not(test))]
    fn grant_intents_in_fifo_order(&self) {
        loop {
            let candidate = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread observes scheduler-owned intent state.
                    &*self.active.get()
                };
                slots
                    .iter()
                    .enumerate()
                    .filter_map(|(index, slot)| {
                        let ActivePhase::Intent { request, .. } = &slot.phase else {
                            return None;
                        };
                        if intent_conflicts_with_held(slots, request)
                            || earlier_queued_intent_conflicts(slots, request)
                        {
                            return None;
                        }
                        Some((request.ticket(), index))
                    })
                    .min_by_key(|candidate| *candidate)
                    .map(|(_, index)| index)
            };
            let Some(index) = candidate else {
                return;
            };
            let (operation, event) = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread moves scheduler-owned intent state.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
                let ActivePhase::Intent { request, operation } = phase else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let ticket = request.ticket();
                slot.intent = Some(HeldIntent {
                    volume: request.volume(),
                    ticket,
                    resources: request.resources,
                });
                (
                    operation,
                    OperationEvent::IntentGranted(ext4_core::MutationLease::granted(ticket)),
                )
            };
            self.set_ready_operation_event(index, operation, event);
        }
    }

    /// Attempts every queued per-volume commit in FIFO order without blocking other volumes.
    #[cfg(not(test))]
    fn grant_next_commit(&self) {
        let mut attempted = [false; MAX_OPERATIONS];
        loop {
            let candidate = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread observes commit queues.
                    &*self.active.get()
                };
                slots
                    .iter()
                    .enumerate()
                    .filter_map(|(index, slot)| {
                        let Some(was_attempted) = attempted.get(index) else {
                            KernelWideInconsistency::completion_reactor_state_corruption()
                                .bugcheck();
                        };
                        if *was_attempted {
                            return None;
                        }
                        let ActivePhase::Commit { ticket, .. } = slot.phase else {
                            return None;
                        };
                        Some((ticket, index))
                    })
                    .min_by_key(|candidate| *candidate)
                    .map(|(_, index)| index)
            };
            let Some(index) = candidate else {
                return;
            };
            let Some(was_attempted) = attempted.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            *was_attempted = true;
            let (volume, ticket) = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread observes commit queues.
                    &*self.active.get()
                };
                let Some(slot) = slots.get(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let ActivePhase::Commit { volume, ticket, .. } = slot.phase else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                (volume, ticket)
            };
            let grant = {
                let mut access = unsafe {
                    // SAFETY: Commit arbitration is one non-suspending reactor transition.
                    crate::state::VolumeControlBlock::operation_access(volume)
                };
                access.runtime_mut().try_grant_commit(ticket)
            };
            let Some(grant) = grant else {
                continue;
            };
            let operation = {
                let slots = unsafe {
                    // SAFETY: Only this reactor thread moves commit queues.
                    &mut *self.active.get()
                };
                let Some(slot) = slots.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
                let ActivePhase::Commit {
                    volume: queued_volume,
                    ticket: queued_ticket,
                    operation,
                } = phase
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if queued_volume != volume || queued_ticket != ticket || slot.commit.is_some() {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                slot.commit = Some(HeldCommit { volume, ticket });
                operation
            };
            self.set_ready_operation_event(index, operation, OperationEvent::CommitGranted(grant));
        }
    }

    /// Grants one already-satisfied non-I/O gate without probing its operation.
    #[cfg(not(test))]
    fn grant_wait_if_ready(&self, index: usize) {
        let condition = {
            let slots = unsafe {
                // SAFETY: Only this reactor thread observes wait phases.
                &*self.active.get()
            };
            let Some(slot) = slots.get(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            let ActivePhase::Waiting { condition, .. } = slot.phase else {
                return;
            };
            condition
        };
        let event = match condition {
            WaitCondition::Visibility { volume, ticket } => {
                let mut access = unsafe {
                    // SAFETY: Visibility arbitration is a non-suspending reactor transition.
                    crate::state::VolumeControlBlock::operation_access(volume)
                };
                access
                    .runtime_mut()
                    .try_grant_visibility(ticket)
                    .map(OperationEvent::VisibilityGranted)
            }
            WaitCondition::Checkpoint { volume, epoch } => {
                let mut access = unsafe {
                    // SAFETY: Checkpoint arbitration is a non-suspending reactor transition.
                    crate::state::VolumeControlBlock::operation_access(volume)
                };
                access
                    .runtime_mut()
                    .try_grant_checkpoint(epoch)
                    .map(OperationEvent::CheckpointGranted)
            }
            WaitCondition::VolumeDurability { volume } => {
                let slots = unsafe {
                    // SAFETY: Only the reactor thread observes scheduler commit ownership.
                    &*self.active.get()
                };
                (!volume_has_commit_work(slots, volume))
                    .then(|| OperationEvent::BarrierReleased(ext4_core::BarrierPermit::released(0)))
            }
            WaitCondition::JournalClean { volume } => {
                let slots = unsafe {
                    // SAFETY: Only the reactor thread observes scheduler commit ownership.
                    &*self.active.get()
                };
                if volume_has_commit_work(slots, volume) {
                    None
                } else {
                    let access = unsafe {
                        // SAFETY: Journal cleanliness is observed only for this reactor transition.
                        crate::state::VolumeControlBlock::operation_access(volume)
                    };
                    access.runtime().journal_is_clean().then(|| {
                        OperationEvent::BarrierReleased(ext4_core::BarrierPermit::released(1))
                    })
                }
            }
            WaitCondition::Barrier { identity } => {
                let slots = unsafe {
                    // SAFETY: Only the reactor thread observes terminal lane metadata.
                    &*self.active.get()
                };
                let Some(slot) = slots.get(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !terminal_barrier_is_releasable(slot, identity) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                Some(OperationEvent::BarrierReleased(
                    ext4_core::BarrierPermit::released(identity),
                ))
            }
        };
        let Some(event) = event else {
            return;
        };
        let operation = {
            let slots = unsafe {
                // SAFETY: Only this reactor thread moves wait phases.
                &mut *self.active.get()
            };
            let Some(slot) = slots.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            let phase = core::mem::replace(&mut slot.phase, ActivePhase::Vacant);
            let ActivePhase::Waiting { operation, .. } = phase else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            operation
        };
        self.set_ready_operation_event(index, operation, event);
    }
}

/// Returns whether one volume still has a queued or granted commit that is not yet visible.
fn volume_has_commit_work(
    slots: &[ActiveSlot; MAX_OPERATIONS],
    volume: NonNull<crate::state::VolumeControlBlock>,
) -> bool {
    slots.iter().any(|slot| {
        matches!(slot.commit, Some(HeldCommit { volume: held, .. }) if held == volume)
            || matches!(slot.phase, ActivePhase::Commit { volume: queued, .. } if queued == volume)
    })
}

/// Returns whether a generation-checked predecessor still retains any active phase.
fn active_predecessor_is_live(
    slots: &[ActiveSlot; MAX_OPERATIONS],
    predecessor: ActiveSlotIdentity,
) -> bool {
    let Some(slot) = slots.get(predecessor.index) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    slot.generation == predecessor.generation && !matches!(slot.phase, ActivePhase::Vacant)
}

/// Finds the unique tail of one bounded FILE_OBJECT predecessor chain.
fn latest_handle_predecessor(
    slots: &[ActiveSlot; MAX_OPERATIONS],
    reserved_index: usize,
    file_object: KernelFileObject,
) -> Option<ActiveSlotIdentity> {
    let mut tail = None;
    for (index, slot) in slots.iter().enumerate() {
        if index == reserved_index
            || matches!(slot.phase, ActivePhase::Vacant)
            || slot.admission.and_then(OperationAdmission::file_object) != Some(file_object)
        {
            continue;
        }
        let identity = ActiveSlotIdentity {
            index,
            generation: slot.generation,
        };
        let has_successor = slots
            .iter()
            .enumerate()
            .any(|(successor_index, successor)| {
                successor_index != reserved_index
                    && !matches!(successor.phase, ActivePhase::Vacant)
                    && successor
                        .admission
                        .and_then(OperationAdmission::file_object)
                        == Some(file_object)
                    && successor.predecessor == Some(identity)
            });
        if has_successor {
            continue;
        }
        if tail.replace(identity).is_some() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }
    tail
}

/// Whether two complete resource sets overlap.
fn resource_sets_overlap(left: &[MutationResource], right: &[MutationResource]) -> bool {
    left.iter().any(|resource| right.contains(resource))
}

/// Tests a queued request against every currently held set on the same volume.
fn intent_conflicts_with_held(
    slots: &[ActiveSlot; MAX_OPERATIONS],
    request: &IntentRequest,
) -> bool {
    slots.iter().any(|slot| {
        let Some(held) = &slot.intent else {
            return false;
        };
        held.volume == request.volume()
            && resource_sets_overlap(held.resources.as_slice(), request.resources())
    })
}

/// Returns whether a re-resolved mutation requests the exact resource set it already owns.
fn held_intent_matches_request(held: &HeldIntent, request: &IntentRequest) -> bool {
    held.volume == request.volume()
        && held.ticket == request.ticket()
        && mutation_resource_sets_equal(held.resources.as_slice(), request.resources())
}

/// Compares mutation resource sets without relying on discovery order or allocating.
fn mutation_resource_sets_equal(left: &[MutationResource], right: &[MutationResource]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|resource| right.iter().any(|candidate| candidate == resource))
        && right
            .iter()
            .all(|resource| left.iter().any(|candidate| candidate == resource))
}

/// Prevents a later ticket from bypassing an earlier queued request for an overlapping resource.
fn earlier_queued_intent_conflicts(
    slots: &[ActiveSlot; MAX_OPERATIONS],
    request: &IntentRequest,
) -> bool {
    slots.iter().any(|slot| {
        let ActivePhase::Intent {
            request: earlier, ..
        } = &slot.phase
        else {
            return false;
        };
        earlier.volume() == request.volume()
            && earlier.ticket() < request.ticket()
            && resource_sets_overlap(earlier.resources(), request.resources())
    })
}

// SAFETY: Stable device placement and documented spin-lock/reactor-thread disciplines serialize
// every interior field.
unsafe impl Sync for CompletionReactor {}

/// Returns the single bit assigned to one validated bounded slot index.
fn slot_bit(index: usize) -> u64 {
    let shift = match u32::try_from(index) {
        Ok(shift) => shift,
        Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
    };
    match 1_u64.checked_shl(shift) {
        Some(mask) => mask,
        None => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
    }
}

/// Cancel-routine destination that publishes one fixed-slot event and wakes the reactor.
/// # Safety
///
/// `context` must identify the live final-address reactor owning `index`'s cancel envelope.
#[cfg(not(test))]
unsafe fn publish_active_cancel(context: NonNull<c_void>, index: usize) {
    let reactor = unsafe {
        // SAFETY: Active top-level IRP ownership retains the reactor through token removal.
        context.cast::<CompletionReactor>().as_ref()
    };
    let mask = slot_bit(index);
    reactor.cancel_ready.fetch_or(mask, Ordering::AcqRel);
    reactor.wake();
}

/// Maps pre-domain driver failures into the core operation failure domain.
fn driver_error_to_core(error: DriverError) -> ext4_core::Error {
    match error {
        DriverError::InsufficientResources | DriverError::InvalidBufferSize => {
            ext4_core::Error::OutOfMemory
        }
        DriverError::Core(error) => error,
        _ => ext4_core::Error::DeviceIo,
    }
}

/// DPC callback publishing one concrete retry-timer event without touching operation state.
/// # Safety
///
/// `context` must point to the address-stable [`RetryTimerEnvelope`] installed in the reactor.
#[cfg(not(test))]
unsafe extern "C" fn storage_retry_timer_dpc(
    _dpc: *mut wdk_sys::KDPC,
    context: PVOID,
    _argument_one: PVOID,
    _argument_two: PVOID,
) {
    let Some(timer) = NonNull::new(context.cast::<RetryTimerEnvelope>()) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let timer = unsafe {
        // SAFETY: Native DPC context was bound to this stable envelope during initialization.
        timer.as_ref()
    };
    let Some(reactor) = NonNull::new(timer.reactor.load(Ordering::Acquire)) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let shift = match u32::try_from(timer.index) {
        Ok(shift) => shift,
        Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
    };
    let Some(mask) = 1_u64.checked_shl(shift) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let reactor = unsafe {
        // SAFETY: Device teardown joins the reactor after every active timer has fired.
        reactor.as_ref()
    };
    if reactor.retry_ready.fetch_or(mask, Ordering::AcqRel) & mask != 0 {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
    reactor.wake();
}

/// Dedicated PASSIVE_LEVEL reactor thread entry.
/// # Safety
///
/// `context` must be the stable reactor address passed to `PsCreateSystemThread`.
#[cfg(not(test))]
unsafe extern "C" fn completion_reactor_thread(context: PVOID) {
    let Some(reactor) = NonNull::new(context.cast::<CompletionReactor>()) else {
        let _status = unsafe {
            // SAFETY: This callback is a system thread and cannot return to a caller.
            ffi::PsTerminateSystemThread(DriverError::InternalInvariantViolation.ntstatus())
        };
        return;
    };
    unsafe {
        // SAFETY: Thread creation passed the stable reactor address and teardown joins this thread.
        reactor.as_ref()
    }
    .run();
    let _status = unsafe {
        // SAFETY: Reactor published Stopped before terminating its system thread.
        ffi::PsTerminateSystemThread(STATUS_SUCCESS)
    };
}

/// CSQ insertion callback.
/// # Safety
///
/// `csq` must be the first field of a live reactor and `irp` an unlinked pending IRP.
#[cfg(not(test))]
unsafe extern "C" fn csq_insert_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    reactor.insert_irp(irp);
}

/// CSQ removal callback.
/// # Safety
///
/// `irp` must currently be linked in this reactor's pending list under the CSQ lock.
#[cfg(not(test))]
unsafe extern "C" fn csq_remove_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    reactor.remove_irp(irp);
}

/// CSQ FIFO peek callback.
/// # Safety
///
/// A non-null `irp` must be linked in this queue and `context` is an optional FILE_OBJECT key.
#[cfg(not(test))]
unsafe extern "C" fn csq_peek_next_irp(csq: PIO_CSQ, irp: PIRP, context: PVOID) -> PIRP {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    reactor.peek_next_irp(irp, context)
}

/// CSQ spin-lock acquisition callback.
/// # Safety
///
/// `irql` must point to writable saved-IRQL storage supplied by the I/O Manager.
#[cfg(not(test))]
unsafe extern "C" fn csq_acquire_lock(csq: PIO_CSQ, irql: wdk_sys::PKIRQL) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let Some(irql) = (unsafe {
        // SAFETY: The CSQ framework supplies writable storage for this callback.
        irql.as_mut()
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    *irql = unsafe {
        // SAFETY: Stable reactor-owned lock.
        ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(reactor.lock).cast_mut())
    };
}

/// CSQ spin-lock release callback.
/// # Safety
///
/// `irql` must be the value returned by the matching acquisition callback.
#[cfg(not(test))]
unsafe extern "C" fn csq_release_lock(csq: PIO_CSQ, irql: wdk_sys::KIRQL) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: Releases the matching CSQ acquisition.
        ffi::KeReleaseSpinLock(core::ptr::addr_of!(reactor.lock).cast_mut(), irql);
    }
}

/// CSQ cancellation callback owning terminal completion of one never-started IRP.
/// # Safety
///
/// The CSQ framework must have atomically removed `irp` before invoking this callback.
#[cfg(not(test))]
unsafe extern "C" fn csq_complete_canceled_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let owned = OwnedIrp::from_queued_raw(reactor.device, irp);
    release_operation_reservation(&reactor.admitted);
    let _status = owned.complete_cancelled();
}

/// Recovers a reactor from its first-field CSQ pointer.
/// # Safety
///
/// `csq` must identify a live reactor initialized by `CompletionReactor::initialize_at`.
#[cfg(not(test))]
unsafe fn reactor_from_csq<'reactor>(csq: PIO_CSQ) -> Option<&'reactor CompletionReactor> {
    let reactor = NonNull::new(csq.cast::<CompletionReactor>())?;
    Some(unsafe {
        // SAFETY: `repr(C)` first-field layout makes both addresses identical.
        reactor.as_ref()
    })
}

/// Initializes one intrusive list head.
fn initialize_list_head(head: PLIST_ENTRY) {
    let head = unsafe {
        // SAFETY: Caller supplies writable stable list-head storage.
        &mut *head
    };
    head.Flink = core::ptr::from_mut(head);
    head.Blink = core::ptr::from_mut(head);
}

/// Returns whether one initialized intrusive list is empty.
fn list_is_empty(head: PLIST_ENTRY) -> bool {
    unsafe {
        // SAFETY: Caller retains the initialized head for this single pointer observation.
        (*head).Flink == head
    }
}

/// Removes and returns the head entry of a nonempty intrusive list.
fn remove_head_list(head: PLIST_ENTRY) -> Option<NonNull<LIST_ENTRY>> {
    let entry = unsafe {
        // SAFETY: Caller holds the list's owning lock.
        (*head).Flink
    };
    if entry == head {
        return None;
    }
    remove_entry_list(entry);
    NonNull::new(entry)
}

/// Inserts an unlinked entry at one intrusive list tail.
fn insert_tail_list(head: PLIST_ENTRY, entry: PLIST_ENTRY) {
    let head_ref = unsafe {
        // SAFETY: Initialized list is held under its owning lock.
        &mut *head
    };
    let previous = head_ref.Blink;
    let entry_ref = unsafe {
        // SAFETY: Entry is unlinked and exclusively supplied by its owner.
        &mut *entry
    };
    entry_ref.Flink = head;
    entry_ref.Blink = previous;
    unsafe {
        // SAFETY: Previous is the live tail of the same initialized list.
        (*previous).Flink = entry;
    }
    head_ref.Blink = entry;
}

/// Removes one entry from its initialized intrusive list.
fn remove_entry_list(entry: PLIST_ENTRY) {
    let entry_ref = unsafe {
        // SAFETY: Entry remains linked under its owning lock.
        &mut *entry
    };
    let previous = entry_ref.Blink;
    let next = entry_ref.Flink;
    unsafe {
        // SAFETY: Previous remains live in the same locked list.
        (*previous).Flink = next;
    }
    unsafe {
        // SAFETY: Next remains live in the same locked list.
        (*next).Blink = previous;
    }
    initialize_list_head(entry);
}

/// Embedded pending-list entry for one top-level IRP.
fn irp_list_entry(irp: PIRP) -> Option<PLIST_ENTRY> {
    let mut irp = NonNull::new(irp)?;
    Some(unsafe {
        // SAFETY: CSQ queue ownership keeps the IRP live and exclusively linked.
        core::ptr::addr_of_mut!(irp.as_mut().Tail.Overlay.__bindgen_anon_2.ListEntry)
    })
}

/// Byte offset of `IRP.Tail.Overlay.ListEntry`.
const IRP_LIST_ENTRY_OFFSET: usize = core::mem::offset_of!(wdk_sys::IRP, Tail)
    + core::mem::offset_of!(wdk_sys::_IRP__bindgen_ty_4__bindgen_ty_1, __bindgen_anon_2)
    + core::mem::offset_of!(
        wdk_sys::_IRP__bindgen_ty_4__bindgen_ty_1__bindgen_ty_2,
        ListEntry
    );

/// Recovers an IRP from its embedded pending-list entry.
fn irp_from_list_entry(entry: PLIST_ENTRY) -> PIRP {
    entry
        .cast::<u8>()
        .wrapping_sub(IRP_LIST_ENTRY_OFFSET)
        .cast::<wdk_sys::IRP>()
}

/// Tests one queued IRP against the synchronous selector under the CSQ lock.
fn queued_irp_matches_context(irp: PIRP, context: PVOID) -> bool {
    let Some(irp) = KernelIrp::from_raw(irp) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    if context.is_null() {
        return unsafe {
            // SAFETY: Queue membership retains the published context throughout this comparison.
            irp.published_queue_context_matches(core::ptr::null_mut(), false)
        };
    }
    let selection = unsafe {
        // SAFETY: `remove_next_irp` lends this exact selector for the synchronous CSQ traversal.
        &*context.cast::<PendingIrpSelection>()
    };
    unsafe {
        // SAFETY: Queue membership retains the published context throughout this comparison.
        irp.published_queue_context_matches(
            selection.file_object.as_ptr().cast::<c_void>(),
            selection.ordinary_cleanup_only,
        )
    }
}

/// Models the CSQ pending transition in unit tests.
#[cfg(test)]
fn mark_pending_for_csq_test(irp: KernelIrp) {
    let pending_bit = match u8::try_from(wdk_sys::SL_PENDING_RETURNED) {
        Ok(bit) => bit,
        Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
    };
    let mut raw_irp = irp.irp;
    let raw_irp = unsafe {
        // SAFETY: Test reactor owns this not-yet-inserted IRP.
        raw_irp.as_mut()
    };
    let overlay = unsafe {
        // SAFETY: Fixture initialized the current-stack tail overlay.
        raw_irp.Tail.Overlay
    };
    let current_stack = unsafe {
        // SAFETY: Fixture selected the current-stack union representation.
        overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    let Some(stack) = (unsafe {
        // SAFETY: Queue capture validated the fixture stack pointer.
        current_stack.as_mut()
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    stack.Control |= pending_bit;
}

/// Validates that only an admitted terminal lane with no predecessor can receive its barrier.
fn terminal_barrier_is_releasable(slot: &ActiveSlot, identity: u64) -> bool {
    if slot.predecessor.is_some() {
        return false;
    }
    matches!(
        (slot.admission, identity),
        (
            Some(OperationAdmission::Handle {
                lane: HandleOperationLane::Cleanup,
                ..
            }),
            CLEANUP_HANDLE_BARRIER
        ) | (
            Some(OperationAdmission::Handle {
                lane: HandleOperationLane::PostCleanup(PostCleanupRequest::Close),
                ..
            }),
            CLOSE_HANDLE_BARRIER
        )
    )
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;
    use core::sync::atomic::Ordering;

    use ext4_core::{MutationResource, OperationEvent};

    use crate::kernel::status::DriverError;
    use crate::kernel::storage::StorageFailureClass;
    use crate::memory::{self, DriverVec};
    use crate::state::{KernelDevice, KernelFileObject, VolumeControlBlock};

    use super::{
        ActivePhase, ActiveSlot, ActiveSlotIdentity, AdmittedOperation, CLEANUP_HANDLE_BARRIER,
        CLOSE_HANDLE_BARRIER, CompletionOperation, CompletionReactor, HandleOperationLane,
        HeldCommit, HeldIntent, InfalliblePublication, IntentRequest, MAX_OPERATIONS,
        OperationAdmission, OperationTransition, PendingIrpSelection, PostCleanupRequest,
        PublicationAuthority, SuspendedOperation, WaitCondition, active_predecessor_is_live,
        driver_error_to_core, earlier_queued_intent_conflicts, held_intent_matches_request,
        initialize_list_head, insert_tail_list, intent_conflicts_with_held,
        latest_handle_predecessor, list_is_empty, mutation_resource_sets_equal, remove_head_list,
        resource_sets_overlap, slot_bit, terminal_barrier_is_releasable, volume_has_commit_work,
    };

    #[derive(Debug)]
    struct TestOperation;

    impl CompletionOperation for TestOperation {
        fn advance(self: Box<Self>, _event: OperationEvent) -> OperationTransition {
            OperationTransition::Complete
        }

        fn record_storage_failure(&mut self, _failure: StorageFailureClass) {}
    }

    macro_rules! test_operation {
        () => {
            match memory::boxed_try_with(|| Ok(TestOperation)) {
                Ok(operation) => {
                    let operation: SuspendedOperation = operation;
                    operation
                }
                Err(_) => return,
            }
        };
    }

    fn advance_concrete_event(
        mut operation: SuspendedOperation,
        failure: StorageFailureClass,
        event: OperationEvent,
    ) -> OperationTransition {
        operation.record_storage_failure(failure);
        operation.advance(event)
    }

    fn publish_prebuilt_value(
        publication: alloc::boxed::Box<dyn InfalliblePublication>,
    ) -> (PublicationAuthority, SuspendedOperation) {
        let authority = publication.authority();
        (authority, publication.publish())
    }

    fn consume_transition(transition: OperationTransition) {
        match transition {
            OperationTransition::QueryDeviceLength {
                completion_owner: _completion_owner,
                target: _target,
                suspended,
            } => {
                drop(suspended);
            }
            OperationTransition::SubmitLower {
                devices: _devices,
                request,
                suspended,
            } => {
                drop(request);
                drop(suspended);
            }
            OperationTransition::RequestIntent { request, suspended } => {
                let _volume = request.volume();
                let _ticket = request.ticket();
                let _resources = request.resources();
                drop(request);
                drop(suspended);
            }
            OperationTransition::RequestCommit {
                volume: _volume,
                ticket: _ticket,
                suspended,
            } => {
                drop(suspended);
            }
            OperationTransition::Wait {
                condition: _condition,
                suspended,
            } => {
                drop(suspended);
            }
            OperationTransition::Publish { publication } => drop(publication),
            OperationTransition::Complete => {}
        }
    }

    fn consume_active_phase(phase: ActivePhase) {
        match phase {
            ActivePhase::Vacant => {}
            ActivePhase::Ready {
                operation,
                event: _,
            } => {
                drop(operation);
            }
            ActivePhase::HandleTurn { operation } => drop(operation),
            ActivePhase::Intent { request, operation } => {
                drop(request);
                drop(operation);
            }
            ActivePhase::Commit {
                volume: _volume,
                ticket: _ticket,
                operation,
            } => {
                drop(operation);
            }
            ActivePhase::Waiting {
                condition: _condition,
                operation,
            } => {
                drop(operation);
            }
        }
    }

    /// Keeps both consuming trait-object transitions in the unit-test production graph.
    ///
    /// # Panics
    ///
    /// This test has no runtime failure path. Compilation fails if operations stop consuming one
    /// concrete event or durable publication gains a second construction path.
    #[test]
    fn consuming_operation_boundaries_remain_linked() {
        let _advance: fn(
            SuspendedOperation,
            StorageFailureClass,
            OperationEvent,
        ) -> OperationTransition = advance_concrete_event;
        let _publish: fn(
            alloc::boxed::Box<dyn InfalliblePublication>,
        ) -> (PublicationAuthority, SuspendedOperation) = publish_prebuilt_value;
        let _consume: fn(OperationTransition) = consume_transition;
        let _consume_phase: fn(ActivePhase) = consume_active_phase;
    }

    /// # Panics
    ///
    /// Panics if typed handle lanes lose their admission, cancellation, or terminal-barrier
    /// distinctions.
    #[test]
    fn handle_admission_and_terminal_barriers_are_typed() {
        let mut raw_file = wdk_sys::FILE_OBJECT::default();
        let Some(file_object) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(raw_file))
        else {
            return;
        };
        let ordinary = OperationAdmission::Handle {
            file_object,
            lane: HandleOperationLane::Ordinary,
        };
        assert_eq!(ordinary.file_object(), Some(file_object));
        assert!(ordinary.is_ordinary_handle());
        assert!(!ordinary.is_terminal_handle_barrier());

        let cleanup = OperationAdmission::Handle {
            file_object,
            lane: HandleOperationLane::Cleanup,
        };
        assert!(cleanup.is_terminal_handle_barrier());
        let close = OperationAdmission::Handle {
            file_object,
            lane: HandleOperationLane::PostCleanup(PostCleanupRequest::Close),
        };
        assert!(close.is_terminal_handle_barrier());

        let selection = PendingIrpSelection::cleanup(file_object);
        assert_eq!(selection.file_object, file_object);
        assert!(selection.ordinary_cleanup_only);

        let admitted = AdmittedOperation::new(test_operation!(), cleanup);
        let (operation, admission) = admitted.into_parts();
        assert_eq!(admission, cleanup);
        assert!(matches!(
            operation.advance(OperationEvent::Admitted),
            OperationTransition::Complete
        ));

        let mut slot = ActiveSlot::vacant();
        slot.admission = Some(cleanup);
        assert!(terminal_barrier_is_releasable(
            &slot,
            CLEANUP_HANDLE_BARRIER
        ));
        assert!(!terminal_barrier_is_releasable(&slot, CLOSE_HANDLE_BARRIER));
        slot.predecessor = Some(ActiveSlotIdentity {
            index: 1,
            generation: 1,
        });
        assert!(!terminal_barrier_is_releasable(
            &slot,
            CLEANUP_HANDLE_BARRIER
        ));
        slot.predecessor = None;
        slot.admission = Some(close);
        assert!(terminal_barrier_is_releasable(&slot, CLOSE_HANDLE_BARRIER));
        consume_active_phase(ActivePhase::Waiting {
            condition: WaitCondition::Barrier {
                identity: CLOSE_HANDLE_BARRIER,
            },
            operation: test_operation!(),
        });
    }

    /// # Panics
    ///
    /// Panics if same-handle requests stop chaining to the exact tail or if another handle is
    /// serialized accidentally.
    #[test]
    fn handle_predecessors_chain_only_within_one_file_object() {
        let mut raw_a = wdk_sys::FILE_OBJECT::default();
        let mut raw_b = wdk_sys::FILE_OBJECT::default();
        let Some(file_a) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(raw_a)) else {
            return;
        };
        let Some(file_b) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(raw_b)) else {
            return;
        };
        let mut slots = core::array::from_fn(|_| ActiveSlot::vacant());
        slots[0].generation = 1;
        slots[0].admission = Some(OperationAdmission::Handle {
            file_object: file_a,
            lane: HandleOperationLane::Ordinary,
        });
        slots[0].phase = ActivePhase::Ready {
            operation: test_operation!(),
            event: OperationEvent::Admitted,
        };
        let first = ActiveSlotIdentity {
            index: 0,
            generation: 1,
        };
        assert_eq!(latest_handle_predecessor(&slots, 1, file_a), Some(first));
        assert_eq!(latest_handle_predecessor(&slots, 1, file_b), None);
        assert!(active_predecessor_is_live(&slots, first));

        slots[1].generation = 4;
        slots[1].admission = Some(OperationAdmission::Handle {
            file_object: file_a,
            lane: HandleOperationLane::PostCleanup(PostCleanupRequest::PagingRead),
        });
        slots[1].predecessor = Some(first);
        slots[1].phase = ActivePhase::HandleTurn {
            operation: test_operation!(),
        };
        let tail = ActiveSlotIdentity {
            index: 1,
            generation: 4,
        };
        assert_eq!(latest_handle_predecessor(&slots, 2, file_a), Some(tail));

        slots[0].phase = ActivePhase::Vacant;
        assert!(!active_predecessor_is_live(&slots, first));
        slots[1].phase = ActivePhase::Vacant;
    }

    /// # Panics
    ///
    /// Panics if disjoint resource intents conflict or an overlapping later FIFO ticket bypasses
    /// an earlier request.
    #[test]
    fn intent_arbitration_is_overlap_scoped_and_fifo() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let metadata = [MutationResource::VOLUME_METADATA];
        let keys = [MutationResource::KEY_SET];
        assert!(resource_sets_overlap(&metadata, &metadata));
        assert!(!resource_sets_overlap(&metadata, &keys));

        let Ok(held_resources) = DriverVec::try_copied_from_slice(&metadata) else {
            return;
        };
        let mut slots = core::array::from_fn(|_| ActiveSlot::vacant());
        slots[0].intent = Some(HeldIntent {
            volume,
            ticket: 1,
            resources: held_resources,
        });
        let Ok(candidate_resources) = DriverVec::try_copied_from_slice(&metadata) else {
            return;
        };
        let candidate = IntentRequest::new(volume, 3, candidate_resources);
        assert_eq!(candidate.volume(), volume);
        assert_eq!(candidate.ticket(), 3);
        assert_eq!(candidate.resources(), metadata);
        assert!(intent_conflicts_with_held(&slots, &candidate));
        assert_eq!(
            slots[0].intent.as_ref().map(|intent| intent.ticket),
            Some(1)
        );

        let Ok(disjoint_resources) = DriverVec::try_copied_from_slice(&keys) else {
            return;
        };
        let disjoint = IntentRequest::new(volume, 4, disjoint_resources);
        assert!(!intent_conflicts_with_held(&slots, &disjoint));

        let Ok(earlier_resources) = DriverVec::try_copied_from_slice(&metadata) else {
            return;
        };
        slots[1].phase = ActivePhase::Intent {
            request: IntentRequest::new(volume, 2, earlier_resources),
            operation: test_operation!(),
        };
        assert!(earlier_queued_intent_conflicts(&slots, &candidate));
        assert!(!earlier_queued_intent_conflicts(&slots, &disjoint));
        slots[1].phase = ActivePhase::Vacant;
    }

    /// # Panics
    ///
    /// Panics if stale-plan re-resolution releases an unchanged intent set or retains a changed
    /// volume, ticket, or resource set.
    #[test]
    fn stale_resolution_retains_only_the_exact_held_intent() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut other_storage = MaybeUninit::<VolumeControlBlock>::uninit();
        let other = NonNull::from(&mut other_storage).cast::<VolumeControlBlock>();
        let original = [MutationResource::VOLUME_METADATA, MutationResource::KEY_SET];
        let reordered = [MutationResource::KEY_SET, MutationResource::VOLUME_METADATA];
        let duplicated = [
            MutationResource::VOLUME_METADATA,
            MutationResource::VOLUME_METADATA,
        ];
        assert!(mutation_resource_sets_equal(&original, &reordered));
        assert!(!mutation_resource_sets_equal(&duplicated, &original));

        let Ok(held_resources) = DriverVec::try_copied_from_slice(&original) else {
            return;
        };
        let held = HeldIntent {
            volume,
            ticket: 17,
            resources: held_resources,
        };
        let Ok(reordered_resources) = DriverVec::try_copied_from_slice(&reordered) else {
            return;
        };
        let matching = IntentRequest::new(volume, 17, reordered_resources);
        assert!(held_intent_matches_request(&held, &matching));

        let changed_set = [MutationResource::VOLUME_METADATA];
        let Ok(changed_resources) = DriverVec::try_copied_from_slice(&changed_set) else {
            return;
        };
        let changed = IntentRequest::new(volume, 17, changed_resources);
        assert!(!held_intent_matches_request(&held, &changed));

        let Ok(ticket_resources) = DriverVec::try_copied_from_slice(&original) else {
            return;
        };
        let changed_ticket = IntentRequest::new(volume, 18, ticket_resources);
        assert!(!held_intent_matches_request(&held, &changed_ticket));

        let Ok(volume_resources) = DriverVec::try_copied_from_slice(&original) else {
            return;
        };
        let changed_volume = IntentRequest::new(other, 17, volume_resources);
        assert!(!held_intent_matches_request(&held, &changed_volume));
    }

    /// # Panics
    ///
    /// Panics if commit visibility accounting ignores either a granted or queued commit.
    #[test]
    fn commit_work_tracks_granted_and_queued_slots() {
        let mut volume_storage = MaybeUninit::<VolumeControlBlock>::uninit();
        let mut other_storage = MaybeUninit::<VolumeControlBlock>::uninit();
        let volume = NonNull::from(&mut volume_storage).cast::<VolumeControlBlock>();
        let other = NonNull::from(&mut other_storage).cast::<VolumeControlBlock>();
        let mut slots = core::array::from_fn(|_| ActiveSlot::vacant());
        slots[0].commit = Some(HeldCommit { volume, ticket: 9 });
        assert!(volume_has_commit_work(&slots, volume));
        assert!(!volume_has_commit_work(&slots, other));
        slots[0].commit = None;
        slots[1].phase = ActivePhase::Commit {
            volume,
            ticket: 10,
            operation: test_operation!(),
        };
        assert!(volume_has_commit_work(&slots, volume));
        slots[1].phase = ActivePhase::Vacant;
    }

    /// # Panics
    ///
    /// Panics if callback publication is lost before, or remains legal after, the exact
    /// effect-bearing write boundary.
    #[test]
    fn active_cancel_is_consumed_by_one_exact_slot() {
        let mut raw_device = wdk_sys::DEVICE_OBJECT::default();
        let Some(device) = KernelDevice::from_raw(core::ptr::addr_of_mut!(raw_device)) else {
            return;
        };
        let mut storage = MaybeUninit::<CompletionReactor>::uninit();
        let initialized = unsafe {
            // SAFETY: Stack storage stays fixed until `release_at` destroys the reactor in place.
            CompletionReactor::initialize_at(storage.as_mut_ptr(), device)
        };
        assert!(initialized.is_ok());
        if initialized.is_err() {
            return;
        }
        let reactor = unsafe {
            // SAFETY: Initialization wrote a complete reactor value.
            &*storage.as_ptr()
        };
        let index = reactor.reserve_active_slot();
        assert_eq!(index, Ok(0));
        let Ok(index) = index else {
            return;
        };
        {
            let slots = unsafe {
                // SAFETY: This isolated test is the sole owner of reactor-thread state.
                &mut *reactor.active.get()
            };
            let Some(slot) = slots.get_mut(index) else {
                return;
            };
            slot.cancel_enabled = true;
            slot.cancel_pending = false;
        }
        reactor
            .cancel_ready
            .store(slot_bit(index), Ordering::Release);
        assert!(reactor.cancellation_is_pending(index));
        assert_eq!(reactor.cancel_ready.load(Ordering::Acquire), 0);
        let resumed = reactor.resume_cancel_if_requested(index, test_operation!());
        assert!(resumed.is_none());
        let phase = {
            let slots = unsafe {
                // SAFETY: This isolated test is the sole owner of reactor-thread state.
                &mut *reactor.active.get()
            };
            let Some(slot) = slots.get_mut(index) else {
                return;
            };
            core::mem::replace(&mut slot.phase, ActivePhase::Vacant)
        };
        let ActivePhase::Ready { operation, event } = phase else {
            return;
        };
        assert!(matches!(event, OperationEvent::CancelRequested));
        drop(operation);

        {
            let slots = unsafe {
                // SAFETY: This isolated test is the sole owner of reactor-thread state.
                &mut *reactor.active.get()
            };
            let Some(slot) = slots.get_mut(index) else {
                return;
            };
            slot.cancel_enabled = true;
            slot.cancel_pending = false;
        }
        reactor
            .cancel_ready
            .store(slot_bit(index), Ordering::Release);
        assert!(reactor.consume_cancellation_before_effect(index));
        assert!(reactor.cancellation_is_pending(index));
        reactor.retire_cancel_slot(index);

        {
            let slots = unsafe {
                // SAFETY: This isolated test is the sole owner of reactor-thread state.
                &mut *reactor.active.get()
            };
            let Some(slot) = slots.get_mut(index) else {
                return;
            };
            slot.cancel_enabled = true;
            slot.cancel_pending = false;
        }
        assert!(!reactor.consume_cancellation_before_effect(index));
        reactor
            .cancel_ready
            .store(slot_bit(index), Ordering::Release);
        assert!(!reactor.cancellation_is_pending(index));
        reactor.retire_cancel_slot(index);

        let mut raw_file = wdk_sys::FILE_OBJECT::default();
        let Some(file_object) = KernelFileObject::from_raw(core::ptr::addr_of_mut!(raw_file))
        else {
            return;
        };
        reactor.cancel_pending_ordinary(file_object);
        unsafe {
            // SAFETY: No pending, active, or completion-owned work remains.
            CompletionReactor::release_at(storage.as_mut_ptr());
        }
    }

    /// # Panics
    ///
    /// Panics if intrusive completion inbox removal or error-domain mapping changes silently.
    #[test]
    fn intrusive_inbox_and_error_mapping_are_exact() {
        let mut head = wdk_sys::LIST_ENTRY::default();
        let mut first = wdk_sys::LIST_ENTRY::default();
        let mut second = wdk_sys::LIST_ENTRY::default();
        initialize_list_head(core::ptr::addr_of_mut!(head));
        insert_tail_list(
            core::ptr::addr_of_mut!(head),
            core::ptr::addr_of_mut!(first),
        );
        insert_tail_list(
            core::ptr::addr_of_mut!(head),
            core::ptr::addr_of_mut!(second),
        );
        let removed = remove_head_list(core::ptr::addr_of_mut!(head));
        assert_eq!(removed, NonNull::new(core::ptr::addr_of_mut!(first)));
        let removed = remove_head_list(core::ptr::addr_of_mut!(head));
        assert_eq!(removed, NonNull::new(core::ptr::addr_of_mut!(second)));
        assert!(list_is_empty(core::ptr::addr_of_mut!(head)));

        assert_eq!(
            driver_error_to_core(DriverError::InsufficientResources),
            ext4_core::Error::OutOfMemory
        );
        assert_eq!(
            driver_error_to_core(DriverError::InvalidParameter),
            ext4_core::Error::DeviceIo
        );
        assert_eq!(slot_bit(MAX_OPERATIONS - 1), 1_u64 << 63);
    }
}
