//! Bounded completion-driven filesystem operation reactor.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use ext4_core::{OperationEvent, StorageRequest};
use wdk_sys::{LIST_ENTRY, NTSTATUS, PIRP, PLIST_ENTRY, PVOID};
#[cfg(not(test))]
use wdk_sys::{PIO_CSQ, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::ffi;
use crate::kernel::{
    fatal::KernelWideInconsistency,
    status::{DriverError, DriverResult},
};
use crate::memory::InPlaceInitialization;
use crate::state::{KernelDevice, KernelFileObject, MountedVolumeAccess, MountedVolumeBinding};
#[cfg(not(test))]
use crate::state::{MountedVolumeDevice, VolumeRetirement};

#[cfg(not(test))]
use super::ActiveCancelDestination;
#[cfg(not(test))]
use super::cache::CacheWorkEnvelope;
#[cfg(not(test))]
use super::lower::{LowerCompletionEnvelope, LowerCompletionRoute, PublishedLowerRequest};
#[cfg(not(test))]
use super::scheduler::{
    Admission as SchedulerAdmission, AdmissionStart, CancelDisposition, HandleId, IntentDisposition,
};
pub(crate) use super::scheduler::{
    CLEANUP_HANDLE_BARRIER, CLOSE_HANDLE_BARRIER, HandleOperationLane, IntentRequest,
    MAX_OPERATIONS, PostCleanupRequest, WaitCondition,
};
use super::scheduler::{Phase, Scheduler, SlotId};
use super::{
    ActiveCancelEnvelope, DispatchMajor, KernelIrp, OwnedIrp, PendingIrp, QueueContext,
    ReceivedIrp, lower::CompletionRundown,
};
#[cfg(not(test))]
use crate::kernel::storage::{
    DeviceLengthProbe, PreparedStorageCommand, RetryingStorageCommand, StorageCommand,
    StorageCommandStep, StorageRetryDecision, StorageRetryDelay, failed_unsubmitted_request,
};
use crate::kernel::storage::{MountedStorageRoute, StorageFailureClass};

/// Operation representation moved through storage-command envelopes.
type SuspendedOperation = Box<dyn CompletionOperation>;
/// Scheduler metadata retained with an operation through lower phases and retries.
#[cfg(not(test))]
#[derive(Debug)]
pub(crate) struct ScheduledStorageOperation {
    /// Suspended filesystem operation that consumes the lower completion.
    operation: SuspendedOperation,
    /// Cancellation policy fixed when the durability-changing effect was scheduled.
    cancellation: EffectCancellation,
}

#[cfg(not(test))]
impl ScheduledStorageOperation {
    /// Recovers the suspended filesystem operation after lower-command ownership ends.
    fn into_operation(self) -> SuspendedOperation {
        self.operation
    }
}
/// One concrete storage command captured by a private lower IRP.
#[cfg(not(test))]
type ReactorStorageCommand = StorageCommand<ScheduledStorageOperation>;
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

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The completion rundown lease keeps the immutable reactor address live across threads.
unsafe impl Send for StorageCompletionRoute {}
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Callback publication serializes reactor inbox mutation with its spin lock.
unsafe impl Sync for StorageCompletionRoute {}
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The completion rundown lease keeps the immutable reactor address live across threads.
unsafe impl Send for LengthCompletionRoute {}
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Callback publication serializes reactor inbox mutation with its spin lock.
unsafe impl Sync for LengthCompletionRoute {}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: This route performs only typed intrusive publication and wakeup under the reactor lock.
unsafe impl LowerCompletionRoute<ReactorStorageCommand> for StorageCompletionRoute {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: This route performs only typed intrusive publication and wakeup under the reactor lock.
unsafe impl LowerCompletionRoute<ReactorLengthProbe> for LengthCompletionRoute {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
    Storage {
        /// Published private lower IRP identity.
        lower: PublishedLowerRequest<ReactorStorageCommand, StorageCompletionRoute>,
        /// Whether top-level cancellation may propagate to this private lower IRP.
        cancellation: EffectCancellation,
    },
    /// Mount-time device length query.
    Length(PublishedLowerRequest<ReactorLengthProbe, LengthCompletionRoute>),
}

/// Cancellation semantics at an effect-bearing lower-storage boundary.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectCancellation {
    /// Cancellation wins until the first write or flush is submitted.
    AbortBeforeEffect,
    /// One-way closing already began, so durability must continue to a known outcome.
    ContinueClosing,
}

#[cfg(not(test))]
impl fmt::Debug for PublishedReactorLower {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage { .. } => formatter.write_str("Storage"),
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn cancel(&self) {
        match self {
            Self::Storage {
                lower,
                cancellation: EffectCancellation::AbortBeforeEffect,
            } => unsafe {
                // SAFETY: The active slot retains the storage envelope identity through this call.
                lower.cancel();
            },
            Self::Storage {
                lower: _,
                cancellation: EffectCancellation::ContinueClosing,
            } => {}
            Self::Length(lower) => unsafe {
                // SAFETY: The active slot retains the length envelope identity through this call.
                lower.cancel();
            },
        }
    }
}

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
    /// Converts the WDK boundary identity into the pointer-free scheduler admission.
    #[cfg(not(test))]
    fn scheduler_admission(self) -> SchedulerAdmission {
        match self {
            Self::Device => SchedulerAdmission::Device,
            Self::Handle { file_object, lane } => SchedulerAdmission::Handle {
                handle: HandleId::from_address(file_object.as_ptr().addr()),
                lane,
            },
        }
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
    fn advance(
        self: Box<Self>,
        event: CompletionEvent,
        target: &mut ReactorTarget,
    ) -> OperationTransition;

    /// Records a terminal lower-storage classification before the matching completion event.
    fn record_storage_failure(&mut self, failure: StorageFailureClass, target: &mut ReactorTarget);
}

/// Events owned by the Windows executor, including failures with native status semantics.
///
/// A volume failure only rejects an ungranted commit or a durability wait. It never revokes
/// an issued commit/visibility/checkpoint lease or drops an in-flight lower operation.
#[derive(Debug)]
pub(crate) enum CompletionEvent {
    /// A filesystem event with its original consuming grant or lower completion.
    Core(OperationEvent),
    /// One PASSIVE_LEVEL Cache Manager work item returned to the unique reactor owner.
    CacheCompleted(crate::irp::CacheWorkCompletion),
    /// The volume can no longer satisfy a pre-effect commit or durability wait.
    VolumeFailed(DriverError),
}

impl CompletionEvent {
    /// Extracts an event for an operation that never waits on volume durability.
    /// A native wait failure routed to such an operation is reactor state corruption.
    pub(crate) fn into_core(self) -> OperationEvent {
        match self {
            Self::Core(event) => event,
            Self::CacheCompleted(_) | Self::VolumeFailed(_) => {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            }
        }
    }

    /// Turns one authoritative readiness observation into a grant, rejection, or continued wait.
    /// Failure is checked even while earlier commit/checkpoint work still occupies its lane.
    fn durability_wait(identity: u64, readiness: DriverResult<bool>) -> Option<Self> {
        match readiness {
            Ok(false) => None,
            Ok(true) => Some(Self::Core(OperationEvent::BarrierReleased(
                ext4_core::BarrierPermit::released(identity),
            ))),
            Err(error) => Some(Self::VolumeFailed(error)),
        }
    }
}

/// Operation payload valid only for the file-system control device.
pub(crate) trait ControlDeviceOperation: fmt::Debug + Send + 'static {
    /// Consumes one control-device event without any mounted-volume authority.
    fn advance_control(self: Box<Self>, event: OperationEvent) -> OperationTransition;

    /// Records a lower-storage failure owned by the control-device operation.
    fn record_control_storage_failure(&mut self, failure: StorageFailureClass);
}

/// Operation payload valid only for a mounted-volume device.
pub(crate) trait MountedVolumeOperation: fmt::Debug + Send + 'static {
    /// Consumes one event inside the sole lifetime-bound mounted access scope.
    fn advance_mounted(
        self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition;

    /// Records a lower-storage failure inside the mounted access scope.
    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    );
}

/// Authority consumed by one allocation-free reactor publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationAuthority {
    /// Durable visibility releases resource intents and the serialized commit grant.
    Durable {
        /// FIFO mutation ticket whose grants are consumed.
        ticket: u64,
    },
    /// Checkpoint publication releases journal space but owns no resource intent.
    Checkpoint {
        /// Overlay epoch being retired.
        epoch: ext4_core::EpochSequence,
    },
}

/// Prebuilt publication that reuses its existing operation allocation.
pub(crate) trait InfalliblePublication: fmt::Debug + Send + 'static {
    /// Scheduler authority consumed by this publication.
    fn authority(&self) -> PublicationAuthority;

    /// Publishes prepared values and returns the same box in its next operation phase.
    fn publish(
        self: Box<Self>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> Box<dyn CompletionOperation>;
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
        devices: MountedStorageRoute,
        /// Owned core transfer token.
        request: StorageRequest,
        /// Operation moved by value into the lower completion envelope.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Submit one close-durability command after the one-way `Closing` boundary.
    SubmitClosingLower {
        /// Mounted devices selected by the stable VCB lifetime owner.
        devices: MountedStorageRoute,
        /// Owned core clean-close transfer.
        request: StorageRequest,
        /// Close operation that must continue even when top-level cancellation is pending.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Execute one prepared Cache Manager call outside the actor and requester threads.
    SubmitCacheWork {
        /// Fully captured Cc/MM operation whose stream lease owns every referenced identity.
        work: crate::irp::CacheWork,
        /// Operation moved by value into the work-item completion envelope.
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
        /// FIFO mutation ticket.
        ticket: u64,
        /// Operation resumed only by its commit grant.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Arm one fixed storage retry timer.
    #[cfg(not(test))]
    ArmRetry {
        /// Failed command retaining the original suspended operation.
        retry: RetryingStorageCommand<ScheduledStorageOperation>,
    },
    /// Wait for a visibility, checkpoint, or terminal-barrier grant.
    Wait {
        /// Exact condition whose release produces an event.
        condition: WaitCondition,
        /// Operation retained without being re-executed.
        suspended: Box<dyn CompletionOperation>,
    },
    /// Wait for pre-closing mutations/checkpoints without allowing cancellation to undo closing.
    WaitForClosingDrain {
        /// Clean-journal and admitted-mutation drain condition.
        condition: WaitCondition,
        /// Close operation resumed only when the condition becomes true.
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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

/// WDK-shell payload ownership paired with the pointer-free scheduler slot at the same index.
enum SlotPayload {
    /// Scheduler or the sole actor owns no shell payload in this slot.
    Empty,
    /// Suspended operation, with an event only while scheduler phase is `Ready`.
    Operation {
        /// Owned operation state machine.
        operation: Box<dyn CompletionOperation>,
        /// Concrete event selected by the scheduler shell.
        event: Option<CompletionEvent>,
    },
    /// One retry command retaining its original operation.
    #[cfg(not(test))]
    Retry(RetryingStorageCommand<ScheduledStorageOperation>),
    /// Completion envelope owning lower lifetime and cancellation identity.
    #[cfg(not(test))]
    Lower(PublishedReactorLower),
}

impl fmt::Debug for SlotPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Empty"),
            Self::Operation { event: Some(_), .. } => formatter.write_str("ReadyOperation"),
            Self::Operation { event: None, .. } => formatter.write_str("SuspendedOperation"),
            #[cfg(not(test))]
            Self::Retry(_) => formatter.write_str("Retry"),
            #[cfg(not(test))]
            Self::Lower(_) => formatter.write_str("Lower"),
        }
    }
}

/// One shell-owned payload slot; scheduler metadata lives only in [`Scheduler`].
#[derive(Debug)]
struct ShellSlot {
    /// Pointer-bearing or callback-bearing payload owned by the WDK shell.
    payload: SlotPayload,
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Native timer/DPC state is initialized once at a stable address; callbacks publish only
// atomics and the reactor thread exclusively owns operation payloads.
unsafe impl Sync for RetryTimerEnvelope {}

/// Actor-owned arming state for the one shared delayed-close timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DelayedCloseTimerState {
    /// No timer or DPC event remains outstanding.
    Idle,
    /// The native timer has been set and its DPC event has not yet been consumed.
    Armed,
}

impl DelayedCloseTimerState {
    /// Consumes the idle state when the actor sets the native one-shot timer.
    fn arm(self) -> Self {
        match self {
            Self::Idle => Self::Armed,
            Self::Armed => {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            }
        }
    }

    /// Consumes one cancelled or DPC-published native timer obligation.
    fn disarm(self) -> Self {
        match self {
            Self::Armed => Self::Idle,
            Self::Idle => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
        }
    }
}

/// Address-stable timer/DPC envelope shared by every handle-free native stream resident.
#[repr(C)]
struct DelayedCloseTimerEnvelope {
    /// Native one-shot timer.
    timer: UnsafeCell<wdk_sys::KTIMER>,
    /// Native DPC that publishes only the timer-expired event.
    dpc: UnsafeCell<wdk_sys::KDPC>,
    /// Stable owning reactor, null only before final-address initialization.
    reactor: AtomicPtr<CompletionReactor>,
}

impl DelayedCloseTimerEnvelope {
    /// Creates inert storage completed after the containing reactor reaches its final address.
    fn inert() -> Self {
        Self {
            timer: UnsafeCell::new(wdk_sys::KTIMER::default()),
            dpc: UnsafeCell::new(wdk_sys::KDPC::default()),
            reactor: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Initializes native timer state and binds this envelope to its stable reactor.
    /// # Safety
    ///
    /// Both addresses must remain live until reactor teardown has cancelled the timer and flushed
    /// every queued DPC.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "stable nonpaged reactor storage owns the native timer and DPC"
    )]
    unsafe fn initialize(&self, reactor: NonNull<CompletionReactor>) {
        unsafe {
            // SAFETY: This timer is in final-address nonpaged device-extension storage.
            ffi::KeInitializeTimer(self.timer.get());
        }
        unsafe {
            // SAFETY: The DPC context remains bound to this stable envelope through DPC flush.
            ffi::KeInitializeDpc(
                self.dpc.get(),
                Some(delayed_close_timer_dpc),
                core::ptr::from_ref(self).cast_mut().cast::<c_void>(),
            );
        }
        self.reactor.store(reactor.as_ptr(), Ordering::Release);
    }

    /// Arms the one shared one-shot poll after the actor observed a nonempty delayed-close set.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the actor exclusively owns the timer's idle-to-armed transition"
    )]
    fn arm(&self) {
        let already_armed = unsafe {
            // SAFETY: Actor state proves this timer is idle before the one-shot set operation.
            ffi::KeSetTimer(
                self.timer.get(),
                wdk_sys::LARGE_INTEGER {
                    QuadPart: -1_000_000_i64,
                },
                self.dpc.get(),
            )
        };
        if already_armed != 0 {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Cancels an armed timer during reactor drain when its DPC has not already been queued.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "terminal actor drain owns cancellation of the shared delayed-close timer"
    )]
    fn cancel(&self) -> bool {
        unsafe {
            // SAFETY: The actor calls this only for its own initialized armed timer.
            ffi::KeCancelTimer(self.timer.get()) != 0
        }
    }
}

#[expect(
    unsafe_code,
    reason = "native timer state is stable and callbacks publish only atomics plus the wake event"
)]
// SAFETY: Initialization fixes the envelope address before publication. Only the reactor actor
// arms/cancels it, and the DPC touches atomic callback state until terminal DPC flush.
unsafe impl Sync for DelayedCloseTimerEnvelope {}

/// Device-specific authority retained by the WDK reactor shell, outside scheduler state.
#[derive(Debug)]
pub(crate) enum ReactorTarget {
    /// File-system control device; no mounted state exists.
    ControlDevice,
    /// Mounted device whose VCB can be entered only on the sole actor thread.
    MountedVolume(MountedVolumeBinding),
}

impl ReactorTarget {
    /// Confirms that an operation belongs to the control-device shell.
    pub(crate) fn require_control_device(&self) {
        if !matches!(self, Self::ControlDevice) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Enters the non-cloneable mounted binding for one non-suspending operation callback.
    pub(crate) fn with_mounted_access<R>(
        &mut self,
        transition: impl FnOnce(&mut MountedVolumeAccess<'_>) -> R,
    ) -> R {
        let Self::MountedVolume(binding) = self else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        binding.with_access(transition)
    }

    /// Returns whether the mounted target owns any handle-free native stream resident.
    #[cfg(not(test))]
    fn delayed_close_pending(&mut self) -> bool {
        match self {
            Self::ControlDevice => false,
            Self::MountedVolume(binding) => {
                binding.with_access(|access| access.delayed_close_pending())
            }
        }
    }

    /// Consumes the mounted target's shared delayed-close timer event.
    #[cfg(not(test))]
    fn expire_delayed_close_timer(&mut self) -> VolumeRetirement {
        let Self::MountedVolume(binding) = self else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        binding.with_access(|access| access.expire_delayed_close_timer())
    }
}

impl ShellSlot {
    /// Creates one empty shell payload slot.
    const fn vacant() -> Self {
        Self {
            payload: SlotPayload::Empty,
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
    /// Completed Cache Manager work envelopes kept type-separated from lower I/O.
    cache_completion_head: UnsafeCell<LIST_ENTRY>,
    /// Pending plus active operation count, bounded by `MAX_OPERATIONS`.
    admitted: AtomicUsize,
    /// Auto-reset event signaled only when a concrete event is published.
    wake_event: wdk_sys::KEVENT,
    /// Bitset of retry timer events published by DPC callbacks.
    retry_ready: AtomicU64,
    /// Shared delayed-close timer event published by its DPC callback.
    delayed_close_ready: AtomicU8,
    /// Bitset of active top-level cancel events published by cancel routines.
    cancel_ready: AtomicU64,
    /// Running/draining/stopped lifecycle.
    lifecycle: AtomicU8,
    /// Lifetime gate retained by every lower completion envelope.
    completion_rundown: CompletionRundown,
    /// System-thread handle joined during teardown.
    thread_handle: AtomicPtr<c_void>,
    /// Pure pointer-free scheduling authority owned by the sole actor.
    scheduler: UnsafeCell<Scheduler>,
    /// Fixed WDK-shell payload registry; callbacks never dereference these values.
    payloads: UnsafeCell<[ShellSlot; MAX_OPERATIONS]>,
    /// One address-stable native timer envelope per bounded active slot.
    retry_timers: [RetryTimerEnvelope; MAX_OPERATIONS],
    /// One native timer shared by the complete mounted-volume delayed-close set.
    delayed_close_timer: DelayedCloseTimerEnvelope,
    /// Arming state mutated only by the sole reactor actor.
    delayed_close_timer_state: UnsafeCell<DelayedCloseTimerState>,
    /// One address-stable top-level cancel envelope per bounded active slot.
    cancel_envelopes: [ActiveCancelEnvelope; MAX_OPERATIONS],
    /// Device object owning this stable extension.
    device: KernelDevice,
    /// Device-specific authority entered only by the sole reactor actor.
    target: UnsafeCell<ReactorTarget>,
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

    /// Returns the exclusively owned embedded CSQ address during initialization.
    #[cfg(not(test))]
    fn csq_mut_ptr(&mut self) -> PIO_CSQ {
        core::ptr::addr_of_mut!(self.csq)
    }

    /// Initializes one reactor directly in stable device-extension storage.
    /// # Safety
    ///
    /// `reactor` must remain at this address through [`Self::release_at`]. Its owner must close
    /// and drain every dispatch borrow before beginning release.
    /// # Errors
    ///
    /// Returns an error when native queue, event, timer, cancel, or worker-thread initialization
    /// cannot be completed.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn initialize_at(
        reactor: *mut Self,
        device: KernelDevice,
        target: ReactorTarget,
    ) -> DriverResult<()> {
        let completion_rundown = CompletionRundown::try_new()?;
        let mut initialization = unsafe {
            // SAFETY: The caller owns writable, uninitialized final-address extension storage.
            InPlaceInitialization::write(
                reactor,
                Self {
                    csq: wdk_sys::IO_CSQ::default(),
                    lock: 0,
                    pending_head: UnsafeCell::new(LIST_ENTRY::default()),
                    completion_head: UnsafeCell::new(LIST_ENTRY::default()),
                    length_completion_head: UnsafeCell::new(LIST_ENTRY::default()),
                    cache_completion_head: UnsafeCell::new(LIST_ENTRY::default()),
                    admitted: AtomicUsize::new(0),
                    wake_event: wdk_sys::KEVENT::default(),
                    retry_ready: AtomicU64::new(0),
                    delayed_close_ready: AtomicU8::new(0),
                    cancel_ready: AtomicU64::new(0),
                    lifecycle: AtomicU8::new(ReactorState::Running.as_raw()),
                    completion_rundown,
                    thread_handle: AtomicPtr::new(core::ptr::null_mut()),
                    scheduler: UnsafeCell::new(Scheduler::new()),
                    payloads: UnsafeCell::new(core::array::from_fn(|_| ShellSlot::vacant())),
                    retry_timers: core::array::from_fn(RetryTimerEnvelope::inert),
                    delayed_close_timer: DelayedCloseTimerEnvelope::inert(),
                    delayed_close_timer_state: UnsafeCell::new(DelayedCloseTimerState::Idle),
                    cancel_envelopes: core::array::from_fn(ActiveCancelEnvelope::inert),
                    device,
                    target: UnsafeCell::new(target),
                },
            )?
        };
        let reactor = initialization.get_mut();
        #[cfg(not(test))]
        let reactor_address = NonNull::from(&mut *reactor);
        unsafe {
            // SAFETY: This is an exclusive, final-address list head before reactor publication.
            initialize_list_head(reactor.pending_head.get());
        }
        unsafe {
            // SAFETY: This is an exclusive, final-address list head before reactor publication.
            initialize_list_head(reactor.completion_head.get());
        }
        unsafe {
            // SAFETY: This is an exclusive, final-address list head before reactor publication.
            initialize_list_head(reactor.length_completion_head.get());
        }
        unsafe {
            // SAFETY: This is an exclusive, final-address list head before reactor publication.
            initialize_list_head(reactor.cache_completion_head.get());
        }
        #[cfg(not(test))]
        for timer in &reactor.retry_timers {
            unsafe {
                // SAFETY: Every timer and the reactor itself are now at their final addresses.
                timer.initialize(reactor_address);
            }
        }
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The shared timer and reactor have both reached their final addresses.
            reactor.delayed_close_timer.initialize(reactor_address);
        }
        #[cfg(not(test))]
        for envelope in &reactor.cancel_envelopes {
            let destination = unsafe {
                // SAFETY: Reactor storage is now final-address and remains live through drain.
                ActiveCancelDestination::new(
                    reactor_address.cast::<c_void>(),
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
                ffi::KeInitializeSpinLock(core::ptr::addr_of_mut!(reactor.lock));
            }
            let status = unsafe {
                // SAFETY: First-field CSQ and callbacks share this stable reactor lifetime.
                ffi::IoCsqInitialize(
                    reactor.csq_mut_ptr(),
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
                    core::ptr::addr_of_mut!(reactor.wake_event),
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
                    reactor_address.as_ptr().cast::<c_void>(),
                )
            };
            if status < STATUS_SUCCESS {
                if !thread_handle.is_null() {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                return Err(DriverError::InsufficientResources);
            }
            if thread_handle.is_null() {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            let published_reactor = unsafe {
                // SAFETY: Successful creation may start the thread, so only shared atomic access is
                // used from this point until rollback ownership is discharged.
                reactor_address.as_ref()
            };
            published_reactor
                .thread_handle
                .store(thread_handle.cast::<c_void>(), Ordering::Release);
        }
        initialization.publish();
        Ok(())
    }

    /// Captures a request under the device owner's dispatch lease and emits its admission event.
    pub(crate) fn receive(&self, mut received: ReceivedIrp, major: DispatchMajor) -> NTSTATUS {
        if self.state() != ReactorState::Running {
            return received.complete_result(Err(DriverError::InvalidDeviceRequest));
        }
        let reservation = match OperationReservation::acquire(&self.admitted) {
            Ok(reservation) => reservation,
            Err(error) => return received.complete_result(Err(error)),
        };
        let context = match received.with_active(|active| QueueContext::capture(active, major)) {
            Ok(context) => context,
            Err(completion) => return received.complete(completion),
        };
        let pending = PendingIrp::from_received(received, context);
        let status = pending.dispatch_status();
        self.enqueue(pending, reservation);
        status
    }

    /// Removes and completes every queued ordinary request for one FILE_OBJECT.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn cancel_pending_ordinary(&self, file_object: KernelFileObject) {
        let selection = PendingIrpSelection::cleanup(file_object);
        loop {
            let irp = self.remove_next_irp(Some(&selection));
            if irp.is_null() {
                return;
            }
            let owned = unsafe {
                // SAFETY: CSQ removal returned this live IRP with exclusive queue ownership.
                OwnedIrp::from_queued_raw(self.device, irp)
            };
            release_operation_reservation(&self.admitted);
            let _status = owned.complete_cancelled();
        }
    }

    /// Publishes a pending IRP to the CSQ, then wakes the reactor for its admission event.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
        unsafe {
            // SAFETY: The isolated test queue owns this live unlinked fixture IRP.
            self.insert_irp(irp);
        }
        self.wake();
    }

    /// Signals that at least one concrete admission/completion/cancel/grant event exists.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn wake(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Event lifetime covers admission through reactor-thread join.
            let _previous = ffi::KeSetEvent(core::ptr::addr_of!(self.wake_event).cast_mut(), 0, 0);
        }
    }

    /// Removes the next queued IRP matching an optional synchronous selection.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
            let irp = unsafe {
                // SAFETY: The isolated test reactor serializes its pending-list access.
                self.peek_next_irp(core::ptr::null_mut(), context)
            };
            if !irp.is_null() {
                unsafe {
                    // SAFETY: The preceding peek returned this still-linked fixture IRP.
                    self.remove_irp(irp);
                }
            }
            irp
        }
    }

    /// Inserts one IRP at the pending FIFO tail while the CSQ lock is held.
    /// # Safety
    ///
    /// The caller must hold the queue lock and `irp` must be live and currently unlinked.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn insert_irp(&self, irp: PIRP) {
        let Some(entry) = (unsafe {
            // SAFETY: The caller retains exclusive queue ownership of this live IRP.
            irp_list_entry(irp)
        }) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        unsafe {
            // SAFETY: The queue lock protects the initialized head and unlinked entry.
            insert_tail_list(self.pending_head.get(), entry);
        }
    }

    /// Removes one pending IRP while the CSQ lock is held.
    /// # Safety
    ///
    /// The caller must hold the queue lock and `irp` must be live and linked in this queue.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn remove_irp(&self, irp: PIRP) {
        let Some(entry) = (unsafe {
            // SAFETY: The caller retains exclusive queue ownership of this linked IRP.
            irp_list_entry(irp)
        }) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        unsafe {
            // SAFETY: The queue lock protects the linked entry and its neighbors.
            remove_entry_list(entry);
        }
    }

    /// Finds the next pending IRP matching an optional FILE_OBJECT identity.
    /// # Safety
    ///
    /// The caller must hold the queue lock; a non-null `irp` must be live and linked in this queue.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn peek_next_irp(&self, irp: PIRP, context: PVOID) -> PIRP {
        let head = self.pending_head.get();
        let mut entry = if irp.is_null() {
            unsafe {
                // SAFETY: Initialized list is held under the CSQ lock.
                (*head).Flink
            }
        } else {
            let Some(entry) = (unsafe {
                // SAFETY: The caller proves this non-null IRP is live and linked.
                irp_list_entry(irp)
            }) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            unsafe {
                // SAFETY: The supplied IRP remains linked under the CSQ lock.
                (*entry).Flink
            }
        };
        while entry != head {
            let candidate = unsafe {
                // SAFETY: `entry` is a live IRP list node protected by the queue lock.
                irp_from_list_entry(entry)
            };
            if unsafe {
                // SAFETY: The same queue ownership retains the candidate and its context.
                queued_irp_matches_context(candidate, context)
            } {
                return candidate;
            }
            entry = unsafe {
                // SAFETY: Current entry remains linked under the CSQ lock.
                (*entry).Flink
            };
        }
        core::ptr::null_mut()
    }

    /// Executes one non-suspending transition against the pointer-free scheduler model.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn with_scheduler<R>(&self, transition: impl FnOnce(&mut Scheduler) -> R) -> R {
        let scheduler = unsafe {
            // SAFETY: Scheduler state is accessed only by the sole reactor actor or isolated tests.
            &mut *self.scheduler.get()
        };
        transition(scheduler)
    }

    /// Executes one non-suspending transition against WDK-shell payload storage.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn with_payloads<R>(
        &self,
        transition: impl FnOnce(&mut [ShellSlot; MAX_OPERATIONS]) -> R,
    ) -> R {
        let payloads = unsafe {
            // SAFETY: Callbacks publish only atomics and never dereference shell payloads.
            &mut *self.payloads.get()
        };
        transition(payloads)
    }

    /// Installs one shell payload only while its slot has no other carrier.
    fn install_payload(&self, index: usize, payload: SlotPayload) {
        self.with_payloads(|payloads| {
            let Some(slot) = payloads.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            if !matches!(slot.payload, SlotPayload::Empty) {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            slot.payload = payload;
        });
    }

    /// Detaches one shell operation payload for sole-actor transition logic.
    #[cfg(not(test))]
    fn take_operation_payload(&self, index: usize) -> SuspendedOperation {
        self.with_payloads(|payloads| {
            let Some(slot) = payloads.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            let payload = core::mem::replace(&mut slot.payload, SlotPayload::Empty);
            let SlotPayload::Operation { operation, .. } = payload else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            operation
        })
    }

    /// Reserves one vacant slot before its stable active-cancel envelope becomes visible.
    /// # Errors
    ///
    /// Returns an invariant error when no slot is vacant or the selected generation overflows.
    fn reserve_active_slot(&self) -> DriverResult<usize> {
        if self.state() != ReactorState::Running {
            self.with_scheduler(Scheduler::begin_drain);
            return Err(DriverError::InternalInvariantViolation);
        }
        self.with_scheduler(Scheduler::reserve)
            .map(SlotId::index)
            .ok_or(DriverError::InternalInvariantViolation)
    }

    /// Installs an operation after cancellation was bound to its reserved fixed slot.
    #[cfg(not(test))]
    fn install_admitted_at(&self, index: usize, admitted: AdmittedOperation) {
        let (operation, admission) = admitted.into_parts();
        let cancelled = self.take_cancel_bit(index);
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let Some(start) = self.with_scheduler(|scheduler| {
            scheduler.install(identity, admission.scheduler_admission(), cancelled)
        }) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        self.with_payloads(|payloads| {
            let Some(slot) = payloads.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            if !matches!(slot.payload, SlotPayload::Empty) {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            slot.payload = SlotPayload::Operation {
                operation,
                event: match start {
                    AdmissionStart::Cancelled => {
                        Some(CompletionEvent::Core(OperationEvent::CancelRequested))
                    }
                    AdmissionStart::HandleTurn => None,
                    AdmissionStart::Admitted => {
                        Some(CompletionEvent::Core(OperationEvent::Admitted))
                    }
                },
            };
        });

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
        let handle = HandleId::from_address(file_object.as_ptr().addr());
        let mut targets =
            self.with_scheduler(|scheduler| scheduler.ordinary_handle_mask(cleanup_index, handle));
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
        if !self.with_scheduler(|scheduler| scheduler.retire_cancel(index)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
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
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.set_phase(identity, Phase::Ready)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        self.install_payload(
            index,
            SlotPayload::Operation {
                operation: suspended,
                event: Some(CompletionEvent::Core(OperationEvent::CancelRequested)),
            },
        );
        None
    }

    /// Atomically linearizes cancellation before the first effect-bearing write or flush.
    ///
    /// A callback publication observed by the atomic exchange wins the boundary. A publication
    /// after that exchange is ordered after effect authority was consumed and is retired later.
    #[cfg(not(test))]
    fn consume_cancellation_before_effect(&self, index: usize) -> bool {
        let published = self.take_cancel_bit(index);
        self.with_scheduler(|scheduler| scheduler.consume_cancel_before_effect(index, published))
    }

    /// Folds callback publication into the reactor-owned slot and reports one legal cancel event.
    fn cancellation_is_pending(&self, index: usize) -> bool {
        let published = self.take_cancel_bit(index);
        self.with_scheduler(|scheduler| scheduler.cancellation_is_pending(index, published))
    }

    /// Installs one resumed event, giving an already-published legal cancel precedence.
    #[cfg(not(test))]
    fn set_ready_operation_event(
        &self,
        index: usize,
        operation: SuspendedOperation,
        event: CompletionEvent,
    ) {
        let event = if self.cancellation_is_pending(index) {
            CompletionEvent::Core(OperationEvent::CancelRequested)
        } else {
            event
        };
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.set_phase(identity, Phase::Ready)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        self.install_payload(
            index,
            SlotPayload::Operation {
                operation,
                event: Some(event),
            },
        );
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

    /// Requests cancellation once for every interruptible operation retained during drain.
    #[cfg(not(test))]
    fn cancel_active_for_drain(&self) -> bool {
        let mut targets = self.with_scheduler(|scheduler| scheduler.drain_cancel_mask());
        if targets == 0 {
            return false;
        }
        while targets != 0 {
            let index = match usize::try_from(targets.trailing_zeros()) {
                Ok(index) => index,
                Err(_) => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
            };
            targets &= !slot_bit(index);
            self.request_active_cancel(index);
        }
        true
    }

    /// Publishes cancellation into one active slot or its exact published lower request.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn request_active_cancel(&self, index: usize) {
        match self.with_scheduler(|scheduler| scheduler.request_cancel(index)) {
            CancelDisposition::Ignored
            | CancelDisposition::AwaitRetry
            | CancelDisposition::AwaitRegistration => {}
            CancelDisposition::ResumeOperation => {
                self.with_payloads(|payloads| {
                    let Some(slot) = payloads.get_mut(index) else {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    };
                    let SlotPayload::Operation { event, .. } = &mut slot.payload else {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    };
                    *event = Some(CompletionEvent::Core(OperationEvent::CancelRequested));
                });
            }
            CancelDisposition::CancelLower => {
                self.with_payloads(|payloads| {
                    let Some(slot) = payloads.get(index) else {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    };
                    let SlotPayload::Lower(lower) = &slot.payload else {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    };
                    unsafe {
                        // SAFETY: This active phase retains the exact published lower identity.
                        lower.cancel();
                    }
                });
            }
        }
    }

    /// Returns whether any active slot still owns work.
    fn has_active(&self) -> bool {
        self.with_scheduler(|scheduler| scheduler.has_active())
    }

    /// Closes admission, drains every operation, and joins the reactor without destroying it.
    /// # Safety
    ///
    /// This transition may be called exactly once. The device extension and target must remain live
    /// until [`Self::release_quiesced_at`] consumes the stopped reactor.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn quiesce_at(reactor: *mut Self) {
        let reactor_address = NonNull::new(reactor).unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let reactor = unsafe {
            // SAFETY: Device teardown retains the stable extension through this method.
            reactor_address.as_ref()
        };
        reactor.begin_drain();
        loop {
            let irp = reactor.remove_next_irp(None);
            if irp.is_null() {
                break;
            }
            let owned = unsafe {
                // SAFETY: Drain removed this live IRP exclusively from the CSQ.
                OwnedIrp::from_queued_raw(reactor.device, irp)
            };
            release_operation_reservation(&reactor.admitted);
            let _status = owned.complete_cancelled();
        }
        reactor.wake();

        #[cfg(not(test))]
        {
            let thread_handle = reactor.thread_handle.load(Ordering::Acquire);
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

        #[cfg(not(test))]
        unsafe {
            // SAFETY: Every reactor timer is expired or cancelled and the actor is joined. A DPC
            // may have published its final event immediately before the join, so global DPC drain
            // is required before the device-extension timer envelopes can be destroyed.
            ffi::KeFlushQueuedDpcs();
        }

        unsafe {
            // SAFETY: The thread is joined and every completion can still reach this empty inbox.
            reactor.completion_rundown.close_and_wait();
        }
        let completion_list_empty = unsafe {
            // SAFETY: The worker is joined and teardown exclusively owns this initialized list.
            list_is_empty(reactor.completion_head.get())
        };
        let length_completion_list_empty = unsafe {
            // SAFETY: The worker is joined and teardown exclusively owns this initialized list.
            list_is_empty(reactor.length_completion_head.get())
        };
        let cache_completion_list_empty = unsafe {
            // SAFETY: The worker is joined and teardown exclusively owns this initialized list.
            list_is_empty(reactor.cache_completion_head.get())
        };
        if reactor.state() != ReactorState::Stopped
            || reactor.admitted.load(Ordering::Acquire) != 0
            || reactor.has_active()
            || reactor.delayed_close_timer_state() != DelayedCloseTimerState::Idle
            || reactor.delayed_close_ready.load(Ordering::Acquire) != 0
            || !completion_list_empty
            || !length_completion_list_empty
            || !cache_completion_list_empty
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        reactor
            .thread_handle
            .store(core::ptr::null_mut(), Ordering::Release);
    }

    /// Destroys a reactor after its quiesce transition and returns its target authority.
    /// # Safety
    ///
    /// [`Self::quiesce_at`] must have completed exactly once for this reactor. No dispatch callback
    /// may still access the containing device extension.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn release_quiesced_at(reactor: *mut Self) -> ReactorTarget {
        let mut reactor_address = NonNull::new(reactor).unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let reactor = unsafe {
            // SAFETY: The completed quiesce transition grants exclusive teardown access.
            reactor_address.as_mut()
        };
        if reactor.state() != ReactorState::Stopped
            || !reactor.thread_handle.load(Ordering::Acquire).is_null()
            || reactor.admitted.load(Ordering::Acquire) != 0
            || reactor.has_active()
            || reactor.delayed_close_timer_state() != DelayedCloseTimerState::Idle
            || reactor.delayed_close_ready.load(Ordering::Acquire) != 0
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let target = core::mem::replace(
            unsafe {
                // SAFETY: Join and rundown closure grant terminal exclusive shell access.
                &mut *reactor.target.get()
            },
            ReactorTarget::ControlDevice,
        );
        unsafe {
            // SAFETY: Rust-owned fields are released exactly once before extension bytes vanish.
            core::ptr::drop_in_place(reactor);
        }
        target
    }

    /// Quiesces and destroys one reactor when no external lifecycle boundary separates the phases.
    /// # Safety
    ///
    /// No new dispatch callback may enter this device extension. The mounted state and completion
    /// destination must remain live until this method joins the reactor and drains rundown.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn release_at(reactor: *mut Self) -> ReactorTarget {
        unsafe {
            // SAFETY: The caller grants the complete single-phase teardown contract.
            Self::quiesce_at(reactor);
        }
        unsafe {
            // SAFETY: The preceding transition completed quiescence for the same stable address.
            Self::release_quiesced_at(reactor)
        }
    }

    /// Enters the mounted binding for one non-suspending sole-actor transition.
    #[cfg(not(test))]
    fn with_mounted_access<R>(
        &self,
        transition: impl FnOnce(&mut MountedVolumeAccess<'_>) -> R,
    ) -> R {
        self.with_target(|target| target.with_mounted_access(transition))
    }

    /// Executes one non-suspending transition against device-specific shell authority.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn with_target<R>(&self, transition: impl FnOnce(&mut ReactorTarget) -> R) -> R {
        let target = unsafe {
            // SAFETY: This method is called only from the dedicated reactor thread; callbacks never
            // read or mutate device-specific authority.
            &mut *self.target.get()
        };
        transition(target)
    }

    /// Runs concrete-event delivery on the sole PASSIVE_LEVEL reactor thread.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn run(&self) {
        loop {
            let mut progressed = false;
            if self.state() == ReactorState::Draining {
                self.with_scheduler(Scheduler::begin_drain);
                progressed |= self.cancel_active_for_drain();
                progressed |= self.cancel_delayed_close_timer();
            }
            progressed |= self.drain_storage_completions();
            progressed |= self.drain_length_completions();
            progressed |= self.drain_cache_completions();
            progressed |= self.drain_active_cancels();
            progressed |= self.drain_retry_events();
            progressed |= self.admit_pending_requests();
            progressed |= self.drive_ready_operations();
            progressed |= self.maintain_delayed_close();
            let completion_list_empty = unsafe {
                // SAFETY: The sole reactor actor observes this initialized inbox list.
                list_is_empty(self.completion_head.get())
            };
            let length_completion_list_empty = unsafe {
                // SAFETY: The sole reactor actor observes this initialized inbox list.
                list_is_empty(self.length_completion_head.get())
            };
            let cache_completion_list_empty = unsafe {
                // SAFETY: The sole reactor actor observes this initialized inbox list.
                list_is_empty(self.cache_completion_head.get())
            };
            if self.state() == ReactorState::Draining
                && self.admitted.load(Ordering::Acquire) == 0
                && !self.has_active()
                && self.delayed_close_timer_state() == DelayedCloseTimerState::Idle
                && self.delayed_close_ready.load(Ordering::Acquire) == 0
                && completion_list_empty
                && length_completion_list_empty
                && cache_completion_list_empty
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

    /// Returns the shared delayed-close timer state owned by this actor thread.
    #[expect(
        unsafe_code,
        reason = "the sole reactor actor owns this interior mutable timer state"
    )]
    fn delayed_close_timer_state(&self) -> DelayedCloseTimerState {
        unsafe {
            // SAFETY: Production callers are the sole reactor actor. Host tests remain
            // single-threaded while inspecting initialized reactor storage.
            *self.delayed_close_timer_state.get()
        }
    }

    /// Publishes one shared delayed-close timer transition from the sole actor thread.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the sole reactor actor owns this interior mutable timer state"
    )]
    fn set_delayed_close_timer_state(&self, state: DelayedCloseTimerState) {
        unsafe {
            // SAFETY: Only the dedicated reactor actor mutates this field after publication.
            *self.delayed_close_timer_state.get() = state;
        }
    }

    /// Cancels the shared timer as reactor drain begins, or waits for its already-queued DPC.
    #[cfg(not(test))]
    fn cancel_delayed_close_timer(&self) -> bool {
        if self.delayed_close_timer_state() == DelayedCloseTimerState::Idle {
            return false;
        }
        if self.delayed_close_timer.cancel() {
            self.set_delayed_close_timer_state(self.delayed_close_timer_state().disarm());
            true
        } else {
            false
        }
    }

    /// Consumes a timer event, rechecks due native residents once, and maintains one shared timer.
    #[cfg(not(test))]
    fn maintain_delayed_close(&self) -> bool {
        let mut progressed = false;
        if self.delayed_close_ready.swap(0, Ordering::AcqRel) != 0 {
            if self.delayed_close_timer_state() != DelayedCloseTimerState::Armed {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            self.set_delayed_close_timer_state(self.delayed_close_timer_state().disarm());
            let retirement = self.with_target(ReactorTarget::expire_delayed_close_timer);
            if retirement == VolumeRetirement::Start {
                MountedVolumeDevice::schedule_retirement(self.device);
            }
            progressed = true;
        }

        let pending = self.with_target(ReactorTarget::delayed_close_pending);
        if !pending && self.delayed_close_timer_state() == DelayedCloseTimerState::Armed {
            progressed |= self.cancel_delayed_close_timer();
        }
        if self.state() == ReactorState::Draining {
            if pending {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            return progressed;
        }
        if pending && self.delayed_close_timer_state() == DelayedCloseTimerState::Idle {
            self.delayed_close_timer.arm();
            self.set_delayed_close_timer_state(self.delayed_close_timer_state().arm());
            progressed = true;
        }
        progressed
    }

    /// Waits for a newly published admission, lower completion, cancel, timer, or grant event.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn admit_pending_requests(&self) -> bool {
        let mut admitted_any = false;
        loop {
            let irp = self.remove_next_irp(None);
            if irp.is_null() {
                return admitted_any;
            }
            admitted_any = true;
            let mut owned = unsafe {
                // SAFETY: CSQ removal returned this live IRP with exclusive completion ownership.
                OwnedIrp::from_queued_raw(self.device, irp)
            };
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
            match self.with_target(|target| crate::request::dispatch::admit_owned(owned, target)) {
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
            let Some(identity) = self.with_scheduler(Scheduler::take_ready) else {
                return progressed;
            };
            let index = identity.index();
            let payload = self.with_payloads(|payloads| {
                let Some(slot) = payloads.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                core::mem::replace(&mut slot.payload, SlotPayload::Empty)
            });
            let SlotPayload::Operation {
                operation,
                event: Some(event),
            } = payload
            else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            progressed = true;
            let transition = self.with_target(|target| operation.advance(event, target));
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
                self.submit_storage(
                    index,
                    devices,
                    request,
                    suspended,
                    EffectCancellation::AbortBeforeEffect,
                );
            }
            OperationTransition::SubmitClosingLower {
                devices,
                request,
                suspended,
            } => {
                self.submit_storage(
                    index,
                    devices,
                    request,
                    suspended,
                    EffectCancellation::ContinueClosing,
                );
            }
            OperationTransition::SubmitCacheWork { work, suspended } => {
                self.submit_cache_work(index, work, suspended);
            }
            OperationTransition::RequestIntent { request, suspended } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    drop(request);
                    return;
                };
                let ticket = request.ticket();
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let Some(disposition) =
                    self.with_scheduler(|scheduler| scheduler.request_intent(identity, request))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                match disposition {
                    IntentDisposition::Retained => self.install_payload(
                        index,
                        SlotPayload::Operation {
                            operation: suspended,
                            event: Some(CompletionEvent::Core(OperationEvent::IntentGranted(
                                ext4_core::MutationLease::granted(ticket),
                            ))),
                        },
                    ),
                    IntentDisposition::Queued => self.install_payload(
                        index,
                        SlotPayload::Operation {
                            operation: suspended,
                            event: None,
                        },
                    ),
                }
                self.grant_available_intents();
            }
            OperationTransition::RequestCommit { ticket, suspended } => {
                let Some(suspended) = self.resume_cancel_if_requested(index, suspended) else {
                    return;
                };
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !self.with_scheduler(|scheduler| scheduler.request_commit(identity, ticket)) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                self.install_payload(
                    index,
                    SlotPayload::Operation {
                        operation: suspended,
                        event: None,
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
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !self.with_scheduler(|scheduler| scheduler.request_wait(identity, condition)) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                self.install_payload(
                    index,
                    SlotPayload::Operation {
                        operation: suspended,
                        event: None,
                    },
                );
                self.grant_available_wait(index);
            }
            OperationTransition::WaitForClosingDrain {
                condition,
                suspended,
            } => {
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !self
                    .with_scheduler(|scheduler| scheduler.request_closing_wait(identity, condition))
                {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                self.install_payload(
                    index,
                    SlotPayload::Operation {
                        operation: suspended,
                        event: None,
                    },
                );
                self.grant_available_wait(index);
            }
            OperationTransition::Publish { publication } => {
                let authority = publication.authority();
                self.consume_publication_authority(index, authority);
                let operation = self.with_mounted_access(|access| publication.publish(access));
                if matches!(authority, PublicationAuthority::Durable { .. }) {
                    self.retire_cancel_slot(index);
                    self.release_handle_lane(index);
                }
                self.set_ready_operation_event(
                    index,
                    operation,
                    CompletionEvent::Core(OperationEvent::Admitted),
                );
                self.grant_available_intents();
                self.grant_available_commit();
                self.grant_all_available_waits();
                self.grant_all_handle_turns();
            }
            OperationTransition::Complete => {
                self.release_intent(index);
                self.abandon_commit(index);
                self.release_handle_lane(index);
                self.retire_cancel_slot(index);
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !self.with_scheduler(|scheduler| scheduler.complete(identity)) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                release_operation_reservation(&self.admitted);
                self.grant_available_intents();
                self.grant_available_commit();
                self.grant_all_available_waits();
                self.grant_all_handle_turns();
            }
        }
    }

    /// Enters the non-interruptible lower-registration phase with no shell payload retained.
    #[cfg(not(test))]
    fn begin_registering(&self, index: usize) {
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.set_phase(identity, Phase::Registering)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Publishes a registered lower identity into the WDK shell.
    #[cfg(not(test))]
    fn finish_registering_lower(&self, index: usize, lower: PublishedReactorLower) {
        let Some(identity) = self.with_scheduler(|scheduler| {
            scheduler.enter_phase(index, |phase| matches!(phase, Phase::Registering))
        }) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.set_phase(identity, Phase::Lower)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        self.install_payload(index, SlotPayload::Lower(lower));
        if self.cancellation_is_pending(index) {
            self.request_active_cancel(index);
        }
    }

    /// Returns a failed lower registration to actor ownership.
    #[cfg(not(test))]
    fn recover_registering(&self, index: usize) {
        if self
            .with_scheduler(|scheduler| {
                scheduler.enter_phase(index, |phase| matches!(phase, Phase::Registering))
            })
            .is_none()
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Detaches one top-level FILE_OBJECT lane while a post-publication checkpoint may continue.
    #[cfg(not(test))]
    fn release_handle_lane(&self, index: usize) {
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.release_handle_lane(identity)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Delivers admission only to handle operations whose exact predecessor has terminated.
    #[cfg(not(test))]
    fn grant_all_handle_turns(&self) {
        let mut ready = self.with_scheduler(|scheduler| scheduler.ready_handle_turns());
        while ready != 0 {
            let index = usize::try_from(ready.trailing_zeros()).unwrap_or_else(|_| {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
            });
            ready &= !slot_bit(index);
            if self
                .with_scheduler(|scheduler| scheduler.grant_handle_turn(index))
                .is_none()
            {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            let operation = self.take_operation_payload(index);
            self.set_ready_operation_event(
                index,
                operation,
                CompletionEvent::Core(OperationEvent::Admitted),
            );
        }
    }

    /// Releases any resource set retained by one slot.
    #[cfg(not(test))]
    fn release_intent(&self, index: usize) {
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.release_intent(identity)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }

    /// Returns a pre-write commit grant to its mounted runtime.
    #[cfg(not(test))]
    fn abandon_commit(&self, index: usize) {
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if let Some(ticket) = self.with_scheduler(|scheduler| scheduler.abandon_commit(identity)) {
            self.with_mounted_access(|access| {
                access.abandon_commit(ticket);
            });
        }
    }

    /// Consumes exactly the grants required by one infallible publication.
    #[cfg(not(test))]
    fn consume_publication_authority(&self, index: usize, authority: PublicationAuthority) {
        match authority {
            PublicationAuthority::Durable { ticket } => {
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !self.with_scheduler(|scheduler| {
                    scheduler.consume_durable_authority(identity, ticket)
                }) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
            }
            PublicationAuthority::Checkpoint { .. } => {
                let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index))
                else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                if !self
                    .with_scheduler(|scheduler| scheduler.checkpoint_authority_is_clear(identity))
                {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
            }
        }
    }

    /// Allocates and queues one PASSIVE_LEVEL Cache Manager call outside actor ownership.
    #[cfg(not(test))]
    fn submit_cache_work(
        &self,
        index: usize,
        work: crate::irp::CacheWork,
        suspended: SuspendedOperation,
    ) {
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let rundown = match self.completion_rundown.acquire() {
            Ok(Some(rundown)) => rundown,
            Ok(None) => {
                self.set_ready_operation_event(
                    index,
                    suspended,
                    CompletionEvent::CacheCompleted(work.failed(DriverError::InvalidDeviceRequest)),
                );
                return;
            }
            Err(error) => {
                self.set_ready_operation_event(
                    index,
                    suspended,
                    CompletionEvent::CacheCompleted(work.failed(error)),
                );
                return;
            }
        };
        let prepared = match CacheWorkEnvelope::try_new(
            self.device,
            NonNull::from(self),
            identity,
            work,
            suspended,
            rundown,
        ) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let (error, work, suspended) = failure.into_parts();
                self.set_ready_operation_event(
                    index,
                    suspended,
                    CompletionEvent::CacheCompleted(work.failed(error)),
                );
                return;
            }
        };
        if self.consume_cancellation_before_effect(index) {
            let (_work, suspended) = CacheWorkEnvelope::cancel_before_queue(prepared);
            self.set_ready_operation_event(
                index,
                suspended,
                CompletionEvent::Core(OperationEvent::CancelRequested),
            );
            return;
        }
        if !self.with_scheduler(|scheduler| scheduler.set_phase(identity, Phase::Cache)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        CacheWorkEnvelope::queue(prepared);
    }

    /// Builds, registers, and submits one lower storage command with ownership-preserving errors.
    #[cfg(not(test))]
    fn submit_storage(
        &self,
        index: usize,
        devices: MountedStorageRoute,
        request: StorageRequest,
        suspended: SuspendedOperation,
        cancellation: EffectCancellation,
    ) {
        let scheduled = ScheduledStorageOperation {
            operation: suspended,
            cancellation,
        };
        let prepared = match PreparedStorageCommand::try_new(devices, request, scheduled) {
            Ok(prepared) => prepared,
            Err(error) => {
                let (error, scheduled, request) = error.into_parts();
                self.set_ready_storage_failure(index, scheduled.into_operation(), request, error);
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
        let rundown = match self.completion_rundown.acquire() {
            Ok(Some(rundown)) => rundown,
            Ok(None) => {
                self.set_ready_length_failure(index, suspended, DriverError::InvalidDeviceRequest);
                return;
            }
            Err(error) => {
                self.set_ready_length_failure(index, suspended, error);
                return;
            }
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
        self.begin_registering(index);
        match lower.register_and_submit() {
            Ok(()) => {
                self.finish_registering_lower(index, PublishedReactorLower::Length(cancellation));
            }
            Err(error) => {
                let (error, probe) = error.into_parts();
                self.recover_registering(index);
                self.set_ready_length_failure(index, probe.into_suspended(), error);
            }
        }
    }

    /// Sends one completely prepared command through a fresh private IRP.
    #[cfg(not(test))]
    fn submit_prepared_storage(
        &self,
        index: usize,
        prepared: PreparedStorageCommand<ScheduledStorageOperation>,
    ) {
        let cancellation = prepared.suspended().cancellation;
        if cancellation == EffectCancellation::AbortBeforeEffect
            && prepared.is_effect_bearing()
            && self.consume_cancellation_before_effect(index)
        {
            let (scheduled, _request) = prepared.into_command().into_parts();
            self.set_ready_operation_event(
                index,
                scheduled.into_operation(),
                CompletionEvent::Core(OperationEvent::CancelRequested),
            );
            return;
        }
        let rundown = match self.completion_rundown.acquire() {
            Ok(Some(rundown)) => rundown,
            Ok(None) => {
                let command = prepared.into_command();
                let (scheduled, request) = command.into_parts();
                self.set_ready_storage_failure(
                    index,
                    scheduled.into_operation(),
                    request,
                    DriverError::InvalidDeviceRequest,
                );
                return;
            }
            Err(error) => {
                let command = prepared.into_command();
                let (scheduled, request) = command.into_parts();
                self.set_ready_storage_failure(index, scheduled.into_operation(), request, error);
                return;
            }
        };
        let destination = StorageCompletionRoute {
            reactor: NonNull::from(self),
        };
        let mut lower = match prepared.build_lower(destination, rundown) {
            Ok(lower) => lower,
            Err(error) => {
                let (error, command) = error.into_parts();
                let (scheduled, request) = command.into_parts();
                self.set_ready_storage_failure(index, scheduled.into_operation(), request, error);
                return;
            }
        };
        let cancellation_identity = lower.cancellation_identity();
        self.begin_registering(index);
        match lower.register_and_submit() {
            Ok(()) => {
                self.finish_registering_lower(
                    index,
                    PublishedReactorLower::Storage {
                        lower: cancellation_identity,
                        cancellation,
                    },
                );
            }
            Err(error) => {
                let (error, command) = error.into_parts();
                let (scheduled, request) = command.into_parts();
                self.recover_registering(index);
                self.set_ready_storage_failure(index, scheduled.into_operation(), request, error);
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
            CompletionEvent::Core(OperationEvent::StorageCompleted(
                failed_unsubmitted_request(request, error),
            )),
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
            CompletionEvent::Core(OperationEvent::DeviceLengthCompleted(Err(
                driver_error_to_core(error),
            ))),
        );
    }

    /// Links one completed envelope into the allocation-free storage inbox.
    /// # Safety
    ///
    /// `envelope` must be uniquely completion-owned, unlinked, nonpaged, and protected by this
    /// reactor's completion rundown lease.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn enqueue_storage(&self, envelope: NonNull<ReactorStorageEnvelope>) {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion callbacks and inbox removal.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = unsafe {
            // SAFETY: Completion owns this live envelope until its node is linked below.
            envelope.as_ref().node_ptr()
        };
        unsafe {
            // SAFETY: The reactor lock is held and `node` is live and unlinked.
            insert_tail_list(self.completion_head.get(), node);
        }
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        self.wake();
    }

    /// Removes one completed storage envelope, if present.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn pop_storage_completion(&self) -> Option<NonNull<ReactorStorageEnvelope>> {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion list access.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = unsafe {
            // SAFETY: The reactor lock is held for this initialized completion list.
            remove_head_list(self.completion_head.get())
        };
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
                    suspended: scheduled,
                    completion,
                }) => {
                    self.set_ready_operation_event(
                        index,
                        scheduled.into_operation(),
                        CompletionEvent::Core(OperationEvent::StorageCompleted(completion)),
                    );
                }
                Ok(StorageCommandStep::Failed(failed)) => match failed.into_retry() {
                    StorageRetryDecision::Retry(retry) => {
                        self.apply_transition(index, OperationTransition::ArmRetry { retry })
                    }
                    StorageRetryDecision::Terminal(failed) => {
                        let (scheduled, request, class) = failed.into_failure();
                        let mut suspended = scheduled.into_operation();
                        self.with_target(|target| suspended.record_storage_failure(class, target));
                        self.set_ready_operation_event(
                            index,
                            suspended,
                            CompletionEvent::Core(OperationEvent::StorageCompleted(
                                failed_unsubmitted_request(request, ext4_core::Error::DeviceIo),
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn enqueue_length(&self, envelope: NonNull<ReactorLengthEnvelope>) {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion callbacks and inbox removal.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = unsafe {
            // SAFETY: Completion owns this live envelope until its node is linked below.
            envelope.as_ref().node_ptr()
        };
        unsafe {
            // SAFETY: The reactor lock is held and `node` is live and unlinked.
            insert_tail_list(self.length_completion_head.get(), node);
        }
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        self.wake();
    }

    /// Removes one completed length-query envelope, if present.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn pop_length_completion(&self) -> Option<NonNull<ReactorLengthEnvelope>> {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes completion list access.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = unsafe {
            // SAFETY: The reactor lock is held for this initialized completion list.
            remove_head_list(self.length_completion_head.get())
        };
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
                    CompletionEvent::Core(OperationEvent::DeviceLengthCompleted(Ok(length))),
                ),
                Err((suspended, error)) => {
                    self.set_ready_length_failure(index, suspended, error);
                }
            }
        }
        progressed
    }

    /// Links one completed Cache Manager work envelope into its type-separated inbox.
    /// # Safety
    ///
    /// `envelope` must be uniquely worker-owned, unlinked, nonpaged, and protected by this
    /// reactor's completion rundown lease.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the work callback transfers one completed intrusive envelope under the reactor lock"
    )]
    pub(super) unsafe fn enqueue_cache_completion(&self, envelope: NonNull<CacheWorkEnvelope>) {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes work callbacks and inbox removal.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = unsafe {
            // SAFETY: Completion owns this live envelope until its node is linked below.
            envelope.as_ref().node_ptr()
        };
        unsafe {
            // SAFETY: The reactor lock is held and `node` is live and unlinked.
            insert_tail_list(self.cache_completion_head.get(), node);
        }
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        self.wake();
    }

    /// Removes one completed cache work envelope, if present.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the reactor lock protects the typed cache-completion intrusive list"
    )]
    fn pop_cache_completion(&self) -> Option<NonNull<CacheWorkEnvelope>> {
        let old_irql = unsafe {
            // SAFETY: Stable reactor lock serializes cache-completion list access.
            ffi::KeAcquireSpinLockRaiseToDpc(core::ptr::addr_of!(self.lock).cast_mut())
        };
        let node = unsafe {
            // SAFETY: The reactor lock is held for this initialized completion list.
            remove_head_list(self.cache_completion_head.get())
        };
        unsafe {
            // SAFETY: Releases the exact acquisition above.
            ffi::KeReleaseSpinLock(core::ptr::addr_of!(self.lock).cast_mut(), old_irql);
        }
        node.map(|node| unsafe {
            // SAFETY: The cache envelope's node is its first field.
            CacheWorkEnvelope::from_node(node)
        })
    }

    /// Reclaims and routes every completed Cache Manager work item.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "inbox removal grants unique ownership of the completed cache envelope"
    )]
    fn drain_cache_completions(&self) -> bool {
        let mut progressed = false;
        while let Some(envelope) = self.pop_cache_completion() {
            progressed = true;
            let identity = unsafe {
                // SAFETY: Inbox ownership retains the complete envelope through this observation.
                envelope.as_ref().identity()
            };
            let index = identity.index();
            let entered = self.with_scheduler(|scheduler| {
                scheduler.enter_phase(index, |phase| matches!(phase, Phase::Cache))
            });
            if entered != Some(identity)
                || !self.with_payloads(|payloads| {
                    payloads
                        .get(index)
                        .is_some_and(|slot| matches!(slot.payload, SlotPayload::Empty))
                })
            {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            let envelope = unsafe {
                // SAFETY: Inbox removal and exact slot-generation validation grant unique ownership.
                Box::from_raw(envelope.as_ptr())
            };
            let (suspended, completion) = CacheWorkEnvelope::reclaim(envelope);
            self.set_ready_operation_event(
                index,
                suspended,
                CompletionEvent::CacheCompleted(completion),
            );
        }
        progressed
    }

    /// Detaches the active lower cancellation identity before reclaim can free the envelope.
    #[cfg(not(test))]
    fn take_completed_lower_slot(&self, envelope: NonNull<ReactorStorageEnvelope>) -> usize {
        let index = self.with_payloads(|payloads| {
            payloads.iter_mut().enumerate().find_map(|(index, slot)| {
                let identifies = matches!(
                    &slot.payload,
                    SlotPayload::Lower(PublishedReactorLower::Storage { lower, .. })
                        if lower.identifies(envelope)
                );
                identifies.then(|| {
                    slot.payload = SlotPayload::Empty;
                    index
                })
            })
        });
        let Some(index) = index else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if self
            .with_scheduler(|scheduler| {
                scheduler.enter_phase(index, |phase| matches!(phase, Phase::Lower))
            })
            .is_none()
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        index
    }

    /// Detaches one completed length-query identity before reclaim frees its envelope.
    #[cfg(not(test))]
    fn take_completed_length_slot(&self, envelope: NonNull<ReactorLengthEnvelope>) -> usize {
        let index = self.with_payloads(|payloads| {
            payloads.iter_mut().enumerate().find_map(|(index, slot)| {
                let identifies = matches!(
                    &slot.payload,
                    SlotPayload::Lower(PublishedReactorLower::Length(lower))
                        if lower.identifies(envelope)
                );
                identifies.then(|| {
                    slot.payload = SlotPayload::Empty;
                    index
                })
            })
        });
        let Some(index) = index else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if self
            .with_scheduler(|scheduler| {
                scheduler.enter_phase(index, |phase| matches!(phase, Phase::Lower))
            })
            .is_none()
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        index
    }

    /// Retains one retry command until its concrete fixed-delay timer event arrives.
    #[cfg(not(test))]
    fn arm_retry(&self, index: usize, retry: RetryingStorageCommand<ScheduledStorageOperation>) {
        if retry.suspended().cancellation == EffectCancellation::AbortBeforeEffect
            && self.cancellation_is_pending(index)
        {
            let (scheduled, _request) = retry.into_parts();
            self.set_ready_operation_event(
                index,
                scheduled.into_operation(),
                CompletionEvent::Core(OperationEvent::CancelRequested),
            );
            return;
        }
        let delay = retry.delay();
        let Some(identity) = self.with_scheduler(|scheduler| scheduler.identity(index)) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !self.with_scheduler(|scheduler| scheduler.set_phase(identity, Phase::Retry)) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        self.install_payload(index, SlotPayload::Retry(retry));
        let Some(timer) = self.retry_timers.get(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        timer.arm(identity.generation(), delay);
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
            let identity = SlotId::from_parts(index, generation);
            if !self.with_scheduler(|scheduler| scheduler.enter_retry(identity)) {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            let retry = self.with_payloads(|payloads| {
                let Some(slot) = payloads.get_mut(index) else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                let payload = core::mem::replace(&mut slot.payload, SlotPayload::Empty);
                let SlotPayload::Retry(retry) = payload else {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                };
                retry
            });
            if retry.suspended().cancellation == EffectCancellation::AbortBeforeEffect
                && self.cancellation_is_pending(index)
            {
                let (scheduled, _request) = retry.into_parts();
                self.set_ready_operation_event(
                    index,
                    scheduled.into_operation(),
                    CompletionEvent::Core(OperationEvent::CancelRequested),
                );
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
            let Some((identity, ticket)) = self.with_scheduler(Scheduler::grant_next_intent) else {
                return;
            };
            let operation = self.take_operation_payload(identity.index());
            self.set_ready_operation_event(
                identity.index(),
                operation,
                CompletionEvent::Core(OperationEvent::IntentGranted(
                    ext4_core::MutationLease::granted(ticket),
                )),
            );
        }
    }

    /// Attempts every queued per-volume commit in FIFO order without blocking other volumes.
    #[cfg(not(test))]
    fn grant_next_commit(&self) {
        let mut attempted = [false; MAX_OPERATIONS];
        loop {
            let Some((identity, ticket)) =
                self.with_scheduler(|scheduler| scheduler.next_commit_candidate(&attempted))
            else {
                return;
            };
            let index = identity.index();
            let Some(was_attempted) = attempted.get_mut(index) else {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            };
            *was_attempted = true;
            let grant = self.with_mounted_access(|access| access.acquire_commit(ticket));
            let event = match grant {
                Ok(Some(grant)) => {
                    if !self.with_scheduler(|scheduler| scheduler.grant_commit(identity, ticket)) {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    }
                    CompletionEvent::Core(OperationEvent::CommitGranted(grant))
                }
                Ok(None) => continue,
                Err(error) => {
                    if !self.with_scheduler(|scheduler| scheduler.reject_commit(identity, ticket)) {
                        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    }
                    CompletionEvent::VolumeFailed(error)
                }
            };
            let operation = self.take_operation_payload(index);
            self.set_ready_operation_event(index, operation, event);
        }
    }

    /// Grants one already-satisfied non-I/O gate without probing its operation.
    #[cfg(not(test))]
    fn grant_wait_if_ready(&self, index: usize) {
        let Some(condition) = self.with_scheduler(|scheduler| scheduler.wait_condition(index))
        else {
            return;
        };
        let event = match condition {
            WaitCondition::Visibility { ticket } => self.with_mounted_access(|access| {
                access
                    .try_grant_visibility(ticket)
                    .map(|grant| CompletionEvent::Core(OperationEvent::VisibilityGranted(grant)))
            }),
            WaitCondition::Checkpoint { epoch } => self.with_mounted_access(|access| {
                access
                    .try_grant_checkpoint(epoch)
                    .map(|grant| CompletionEvent::Core(OperationEvent::CheckpointGranted(grant)))
            }),
            WaitCondition::VolumeDurability => {
                let has_commit_work = self.with_scheduler(|scheduler| scheduler.has_commit_work());
                let readiness = self.with_mounted_access(|access| {
                    access.authorize_durability()?;
                    Ok(!has_commit_work)
                });
                CompletionEvent::durability_wait(0, readiness)
            }
            WaitCondition::JournalClean => {
                let has_commit_work = self.with_scheduler(|scheduler| scheduler.has_commit_work());
                let readiness = self.with_mounted_access(|access| {
                    access.authorize_durability()?;
                    Ok(!has_commit_work && access.journal_is_clean())
                });
                CompletionEvent::durability_wait(1, readiness)
            }
            WaitCondition::Barrier { identity } => {
                if !self.with_scheduler(|scheduler| {
                    scheduler.terminal_barrier_is_releasable(index, identity)
                }) {
                    KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                Some(CompletionEvent::Core(OperationEvent::BarrierReleased(
                    ext4_core::BarrierPermit::released(identity),
                )))
            }
        };
        let Some(event) = event else {
            return;
        };
        if self
            .with_scheduler(|scheduler| scheduler.grant_wait(index))
            .is_none()
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let operation = self.take_operation_payload(index);
        self.set_ready_operation_event(index, operation, event);
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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

/// DPC callback publishing the one shared delayed-close timer event.
/// # Safety
///
/// `context` must point to the address-stable [`DelayedCloseTimerEnvelope`] installed in the
/// reactor whose teardown flushes queued DPCs before releasing the containing extension.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the native DPC context identifies one stable reactor-owned timer envelope"
)]
unsafe extern "C" fn delayed_close_timer_dpc(
    _dpc: *mut wdk_sys::KDPC,
    context: PVOID,
    _argument_one: PVOID,
    _argument_two: PVOID,
) {
    let Some(timer) = NonNull::new(context.cast::<DelayedCloseTimerEnvelope>()) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let timer = unsafe {
        // SAFETY: Initialization bound this stable nonpaged envelope as the DPC context.
        timer.as_ref()
    };
    let Some(reactor) = NonNull::new(timer.reactor.load(Ordering::Acquire)) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let reactor = unsafe {
        // SAFETY: Reactor teardown cancels the timer and flushes DPCs before storage is released.
        reactor.as_ref()
    };
    if reactor
        .delayed_close_ready
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
    reactor.wake();
}

/// DPC callback publishing one concrete retry-timer event without touching operation state.
/// # Safety
///
/// `context` must point to the address-stable [`RetryTimerEnvelope`] installed in the reactor.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn csq_insert_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: The CSQ calls insertion with its lock held and an unlinked live IRP.
        reactor.insert_irp(irp);
    }
}

/// CSQ removal callback.
/// # Safety
///
/// `irp` must currently be linked in this reactor's pending list under the CSQ lock.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn csq_remove_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: The CSQ calls removal with its lock held and this IRP still linked.
        reactor.remove_irp(irp);
    }
}

/// CSQ FIFO peek callback.
/// # Safety
///
/// A non-null `irp` must be linked in this queue and `context` is an optional FILE_OBJECT key.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn csq_peek_next_irp(csq: PIO_CSQ, irp: PIRP, context: PVOID) -> PIRP {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: The CSQ holds the queue lock and validates the optional starting IRP.
        reactor.peek_next_irp(irp, context)
    }
}

/// CSQ spin-lock acquisition callback.
/// # Safety
///
/// `irql` must point to writable saved-IRQL storage supplied by the I/O Manager.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn csq_complete_canceled_irp(csq: PIO_CSQ, irp: PIRP) {
    let Some(reactor) = (unsafe {
        // SAFETY: Native initialization binds this callback to the first-field CSQ.
        reactor_from_csq(csq)
    }) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let owned = unsafe {
        // SAFETY: The CSQ removed this live IRP exclusively before invoking cancellation.
        OwnedIrp::from_queued_raw(reactor.device, irp)
    };
    release_operation_reservation(&reactor.admitted);
    let _status = owned.complete_cancelled();
}

/// Recovers a reactor from its first-field CSQ pointer.
/// # Safety
///
/// `csq` must identify a live reactor initialized by `CompletionReactor::initialize_at`.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn reactor_from_csq<'reactor>(csq: PIO_CSQ) -> Option<&'reactor CompletionReactor> {
    let reactor = NonNull::new(csq.cast::<CompletionReactor>())?;
    Some(unsafe {
        // SAFETY: `repr(C)` first-field layout makes both addresses identical.
        reactor.as_ref()
    })
}

/// Initializes one intrusive list head.
/// # Safety
///
/// `head` must point to exclusive writable storage that remains live for the list lifetime.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn initialize_list_head(head: PLIST_ENTRY) {
    let head = unsafe {
        // SAFETY: Caller supplies writable stable list-head storage.
        &mut *head
    };
    head.Flink = core::ptr::from_mut(head);
    head.Blink = core::ptr::from_mut(head);
}

/// Returns whether one initialized intrusive list is empty.
/// # Safety
///
/// `head` must identify a live initialized list protected against concurrent mutation.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn list_is_empty(head: PLIST_ENTRY) -> bool {
    unsafe {
        // SAFETY: Caller retains the initialized head for this single pointer observation.
        (*head).Flink == head
    }
}

/// Removes and returns the head entry of a nonempty intrusive list.
/// # Safety
///
/// `head` must identify a live initialized list whose owning lock is held by the caller.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn remove_head_list(head: PLIST_ENTRY) -> Option<NonNull<LIST_ENTRY>> {
    let entry = unsafe {
        // SAFETY: Caller holds the list's owning lock.
        (*head).Flink
    };
    if entry == head {
        return None;
    }
    unsafe {
        // SAFETY: `entry` is the first linked node under the caller-held list lock.
        remove_entry_list(entry);
    }
    NonNull::new(entry)
}

/// Inserts an unlinked entry at one intrusive list tail.
/// # Safety
///
/// The caller must hold the list lock; both pointers must be live and `entry` must be unlinked.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn insert_tail_list(head: PLIST_ENTRY, entry: PLIST_ENTRY) {
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
/// # Safety
///
/// The caller must hold the list lock and `entry` must be a live linked member.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn remove_entry_list(entry: PLIST_ENTRY) {
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
    unsafe {
        // SAFETY: Removal now uniquely owns the detached entry for self-link initialization.
        initialize_list_head(entry);
    }
}

/// Embedded pending-list entry for one top-level IRP.
/// # Safety
///
/// A non-null `irp` must be live and exclusively retained by the CSQ operation.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn irp_list_entry(irp: PIRP) -> Option<PLIST_ENTRY> {
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
/// # Safety
///
/// `entry` must be the embedded list node of a live WDK IRP.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn irp_from_list_entry(entry: PLIST_ENTRY) -> PIRP {
    entry
        .cast::<u8>()
        .wrapping_sub(IRP_LIST_ENTRY_OFFSET)
        .cast::<wdk_sys::IRP>()
}

/// Tests one queued IRP against the synchronous selector under the CSQ lock.
/// # Safety
///
/// `irp` must be a live queued IRP whose context cannot change while the queue lock is held.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn queued_irp_matches_context(irp: PIRP, context: PVOID) -> bool {
    let Some(irp) = (unsafe {
        // SAFETY: The caller retains the live queued IRP for this context observation.
        KernelIrp::from_raw(irp)
    }) else {
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;
    use core::sync::atomic::Ordering;

    use ext4_core::OperationEvent;

    use crate::kernel::status::DriverError;
    use crate::kernel::storage::StorageFailureClass;
    use crate::memory;
    use crate::state::{KernelDevice, KernelFileObject};

    use super::{
        AdmittedOperation, CompletionEvent, CompletionOperation, CompletionReactor,
        DelayedCloseTimerState, HandleOperationLane, InfalliblePublication, MAX_OPERATIONS,
        OperationAdmission, OperationTransition, PendingIrpSelection, PublicationAuthority,
        SlotPayload, SuspendedOperation, driver_error_to_core, initialize_list_head,
        insert_tail_list, list_is_empty, remove_head_list, slot_bit,
    };

    #[derive(Debug)]
    struct TestOperation;

    /// # Panics
    ///
    /// Panics if the shared delayed-close timer loses its one-obligation state transition.
    #[test]
    fn delayed_close_timer_has_one_explicit_arming_obligation() {
        let armed = DelayedCloseTimerState::Idle.arm();
        assert_eq!(armed, DelayedCloseTimerState::Armed);
        assert_eq!(armed.disarm(), DelayedCloseTimerState::Idle);
    }

    /// # Panics
    ///
    /// Panics when a failed volume wait produces a success permit or loses the native status.
    #[test]
    fn durability_wait_distinguishes_pending_grant_and_volume_failure() {
        assert!(CompletionEvent::durability_wait(1, Ok(false)).is_none());
        let released = CompletionEvent::durability_wait(1, Ok(true));
        assert!(matches!(
            &released,
            Some(CompletionEvent::Core(OperationEvent::BarrierReleased(_)))
        ));
        let Some(CompletionEvent::Core(OperationEvent::BarrierReleased(permit))) = released else {
            return;
        };
        assert_eq!(permit.into_identity(), 1);
        let error = DriverError::CacheManagerFailure(wdk_sys::STATUS_IO_DEVICE_ERROR);
        assert!(matches!(
            CompletionEvent::durability_wait(1, Err(error)),
            Some(CompletionEvent::VolumeFailed(failure)) if failure == error
        ));
    }

    impl CompletionOperation for TestOperation {
        fn advance(
            self: Box<Self>,
            _event: CompletionEvent,
            _target: &mut super::ReactorTarget,
        ) -> OperationTransition {
            OperationTransition::Complete
        }

        fn record_storage_failure(
            &mut self,
            _failure: StorageFailureClass,
            _target: &mut super::ReactorTarget,
        ) {
        }
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
        event: CompletionEvent,
    ) -> OperationTransition {
        let mut target = super::ReactorTarget::ControlDevice;
        operation.record_storage_failure(failure, &mut target);
        operation.advance(event, &mut target)
    }

    fn publish_prebuilt_value(
        publication: alloc::boxed::Box<dyn InfalliblePublication>,
        access: &mut crate::state::MountedVolumeAccess<'_>,
    ) -> (PublicationAuthority, SuspendedOperation) {
        let authority = publication.authority();
        (authority, publication.publish(access))
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
            OperationTransition::SubmitCacheWork { work, suspended } => {
                let _failed_boundary: fn(
                    crate::irp::CacheWork,
                    DriverError,
                ) -> crate::irp::CacheWorkCompletion = crate::irp::CacheWork::failed;
                let completion = work.execute();
                let event = CompletionEvent::CacheCompleted(completion);
                let CompletionEvent::CacheCompleted(completion) = event else {
                    return;
                };
                match completion {
                    crate::irp::CacheWorkCompletion::Read(result) => {
                        let _result = result;
                    }
                    crate::irp::CacheWorkCompletion::Write(result)
                    | crate::irp::CacheWorkCompletion::Flush(result)
                    | crate::irp::CacheWorkCompletion::Purge(result)
                    | crate::irp::CacheWorkCompletion::Uninitialize(result) => {
                        let _result = result;
                    }
                    crate::irp::CacheWorkCompletion::DrainForVolumeLock(result) => {
                        let _result = result;
                    }
                }
                drop(suspended);
            }
            OperationTransition::SubmitClosingLower {
                devices: _devices,
                request,
                suspended,
            } => {
                drop(request);
                drop(suspended);
            }
            OperationTransition::RequestIntent { request, suspended } => {
                let _ticket = request.ticket();
                let _resources = request.resources();
                drop(request);
                drop(suspended);
            }
            OperationTransition::RequestCommit {
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
            OperationTransition::WaitForClosingDrain {
                condition: _condition,
                suspended,
            } => {
                drop(suspended);
            }
            OperationTransition::Publish { publication } => drop(publication),
            OperationTransition::Complete => {}
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
            CompletionEvent,
        ) -> OperationTransition = advance_concrete_event;
        let _publish: fn(
            alloc::boxed::Box<dyn InfalliblePublication>,
            &mut crate::state::MountedVolumeAccess<'_>,
        ) -> (PublicationAuthority, SuspendedOperation) = publish_prebuilt_value;
        let _consume: fn(OperationTransition) = consume_transition;
    }

    /// # Panics
    ///
    /// Panics if typed handle lanes lose their admission, cancellation, or terminal-barrier
    /// distinctions.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn handle_admission_and_terminal_barriers_are_typed() {
        let mut raw_file = wdk_sys::FILE_OBJECT::default();
        let Some(file_object) = (unsafe {
            // SAFETY: The stack-local FILE_OBJECT remains live throughout this test.
            KernelFileObject::from_raw(core::ptr::addr_of_mut!(raw_file))
        }) else {
            return;
        };
        let ordinary = OperationAdmission::Handle {
            file_object,
            lane: HandleOperationLane::Ordinary,
        };
        let cleanup = OperationAdmission::Handle {
            file_object,
            lane: HandleOperationLane::Cleanup,
        };
        assert_ne!(ordinary, cleanup);

        let selection = PendingIrpSelection::cleanup(file_object);
        assert_eq!(selection.file_object, file_object);
        assert!(selection.ordinary_cleanup_only);

        let admitted = AdmittedOperation::new(test_operation!(), cleanup);
        let (operation, admission) = admitted.into_parts();
        assert_eq!(admission, cleanup);
        let mut target = super::ReactorTarget::ControlDevice;
        assert!(matches!(
            operation.advance(CompletionEvent::Core(OperationEvent::Admitted), &mut target),
            OperationTransition::Complete
        ));
    }

    /// # Panics
    ///
    /// Panics if callback publication is lost before, or remains legal after, the exact
    /// effect-bearing write boundary.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn active_cancel_is_consumed_by_one_exact_slot() {
        let mut raw_device = wdk_sys::DEVICE_OBJECT::default();
        let Some(device) = (unsafe {
            // SAFETY: The stack-local device remains live until reactor release.
            KernelDevice::from_raw(core::ptr::addr_of_mut!(raw_device))
        }) else {
            return;
        };
        let mut storage = MaybeUninit::<CompletionReactor>::uninit();
        let initialized = unsafe {
            // SAFETY: Stack storage stays fixed until `release_at` destroys the reactor in place.
            CompletionReactor::initialize_at(
                storage.as_mut_ptr(),
                device,
                super::ReactorTarget::ControlDevice,
            )
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
        reactor
            .cancel_ready
            .store(slot_bit(index), Ordering::Release);
        assert!(reactor.cancellation_is_pending(index));
        assert_eq!(reactor.cancel_ready.load(Ordering::Acquire), 0);
        let resumed = reactor.resume_cancel_if_requested(index, test_operation!());
        assert!(resumed.is_none());
        let Some(identity) = reactor.with_scheduler(super::Scheduler::take_ready) else {
            return;
        };
        let payload = reactor.with_payloads(|payloads| {
            let Some(slot) = payloads.get_mut(index) else {
                return SlotPayload::Empty;
            };
            core::mem::replace(&mut slot.payload, SlotPayload::Empty)
        });
        let SlotPayload::Operation {
            operation,
            event: Some(event),
        } = payload
        else {
            return;
        };
        assert!(matches!(
            event,
            CompletionEvent::Core(OperationEvent::CancelRequested)
        ));
        drop(operation);
        reactor.retire_cancel_slot(index);
        assert!(reactor.with_scheduler(|scheduler| scheduler.release_intent(identity)));
        assert!(
            reactor
                .with_scheduler(|scheduler| scheduler.abandon_commit(identity))
                .is_none()
        );
        assert!(reactor.with_scheduler(|scheduler| scheduler.release_handle_lane(identity)));
        assert!(reactor.with_scheduler(|scheduler| scheduler.complete(identity)));

        let mut raw_file = wdk_sys::FILE_OBJECT::default();
        let Some(file_object) = (unsafe {
            // SAFETY: The stack-local FILE_OBJECT remains live through reactor release.
            KernelFileObject::from_raw(core::ptr::addr_of_mut!(raw_file))
        }) else {
            return;
        };
        reactor.cancel_pending_ordinary(file_object);
        unsafe {
            // SAFETY: No pending, active, or completion-owned work remains, and the stable test
            // storage remains live after this quiesce boundary.
            CompletionReactor::quiesce_at(storage.as_mut_ptr());
        }
        let target = unsafe {
            // SAFETY: The preceding transition quiesced the reactor at this stable address.
            CompletionReactor::release_quiesced_at(storage.as_mut_ptr())
        };
        assert!(matches!(target, super::ReactorTarget::ControlDevice));
    }

    /// # Panics
    ///
    /// Panics if intrusive completion inbox removal or error-domain mapping changes silently.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn intrusive_inbox_and_error_mapping_are_exact() {
        let mut head = wdk_sys::LIST_ENTRY::default();
        let mut first = wdk_sys::LIST_ENTRY::default();
        let mut second = wdk_sys::LIST_ENTRY::default();
        unsafe {
            // SAFETY: This test exclusively owns the live head before any insertion.
            initialize_list_head(core::ptr::addr_of_mut!(head));
        }
        unsafe {
            // SAFETY: This test exclusively owns the initialized head and unlinked first node.
            insert_tail_list(
                core::ptr::addr_of_mut!(head),
                core::ptr::addr_of_mut!(first),
            );
        }
        unsafe {
            // SAFETY: This test exclusively owns the initialized head and unlinked second node.
            insert_tail_list(
                core::ptr::addr_of_mut!(head),
                core::ptr::addr_of_mut!(second),
            );
        }
        let removed = unsafe {
            // SAFETY: The test exclusively owns the initialized nonempty list.
            remove_head_list(core::ptr::addr_of_mut!(head))
        };
        assert_eq!(removed, NonNull::new(core::ptr::addr_of_mut!(first)));
        let removed = unsafe {
            // SAFETY: The test still exclusively owns the initialized nonempty list.
            remove_head_list(core::ptr::addr_of_mut!(head))
        };
        assert_eq!(removed, NonNull::new(core::ptr::addr_of_mut!(second)));
        assert!(unsafe {
            // SAFETY: The test exclusively owns the initialized list head.
            list_is_empty(core::ptr::addr_of_mut!(head))
        });

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
