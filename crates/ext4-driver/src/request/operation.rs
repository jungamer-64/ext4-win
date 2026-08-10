//! Concrete top-level request operations advanced only by scheduler events.

use alloc::boxed::Box;
use core::ptr::NonNull;

use ext4_core::{
    CleanJournalDurability, CommitDurability, CommitReadyMutation, DurableMutation,
    EpochReadOperation, Error, HomeBlockDurability, JournalPayloadDurability,
    MutationResolveOperation, MutationResolveTransition, OperationEvent, OrderedDataDurability,
    ReadTransition, ReservedMutation, ResolvedMutation, StorageRequest, StorageRequestIdentity,
    StorageRequestSequence, StorageRequestSequenceStep,
};

use crate::irp::reactor::{
    CompletionOperation, InfalliblePublication, IntentRequest, OperationTransition,
    PublicationAuthority, WaitCondition,
};
use crate::irp::{CreateCompletion, IrpCompletion, OwnedIrp};
use crate::kernel::cng::CngFscryptNonceGenerator;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::{MountedStorageDevices, StorageFailureClass};
use crate::memory;
use crate::state::{
    EpochLease, EpochPublicationSlot, EpochPublicationSlots, MountedVolumeDevice,
    PendingCheckpoint, VolumeControlBlock,
};

/// Admission failure that preserves the unique top-level completion authority.
#[derive(Debug)]
pub(crate) struct AdmitOperationError {
    /// Normal driver error completed to the requestor.
    error: DriverError,
    /// IRP that never entered an active scheduler slot.
    owned: OwnedIrp,
}

impl AdmitOperationError {
    /// Builds an ownership-preserving admission failure.
    pub(crate) const fn new(error: DriverError, owned: OwnedIrp) -> Self {
        Self { error, owned }
    }

    /// Separates the error from terminal IRP ownership.
    pub(crate) fn into_parts(self) -> (DriverError, OwnedIrp) {
        (self.error, self.owned)
    }
}

/// Read-only request executed against one immutable epoch lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadRequestKind {
    /// Regular file data read.
    Read,
    /// File information query.
    QueryInformation,
    /// Directory enumeration query.
    QueryDirectory,
    /// Extended-attribute query.
    QueryEa,
    /// Security descriptor query.
    QuerySecurity,
}

/// Explicit ownership phase of one top-level read operation.
#[derive(Debug)]
enum ReadOperationState {
    /// IRP and transcript are available for one concrete event.
    Running {
        /// Unique top-level completion authority.
        owned: OwnedIrp,
        /// Operation-owned storage transcript.
        read: EpochReadOperation,
    },
    /// Terminal completion consumed the IRP; only the box remains to be dropped.
    Terminal,
}

/// One restartable read operation over a fixed committed epoch.
#[derive(Debug)]
struct ReadRequestOperation {
    /// Mounted VCB retained by the admitted device/FILE_OBJECT lifetime.
    volume: NonNull<VolumeControlBlock>,
    /// Immutable epoch pinned independently from later checkpoint publication.
    epoch: EpochLease,
    /// Concrete mounted lower devices.
    devices: MountedStorageDevices,
    /// Request semantics selected from captured queue metadata.
    kind: ReadRequestKind,
    /// Explicit operation phase.
    state: ReadOperationState,
}

impl ReadRequestOperation {
    /// Allocates and initializes one read operation while preserving IRP ownership on failure.
    fn try_new(
        owned: OwnedIrp,
        kind: ReadRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let volume = match MountedVolumeDevice::vcb(owned.device()) {
            Some(volume) => volume,
            None => {
                return Err(AdmitOperationError::new(
                    DriverError::InvalidDeviceRequest,
                    owned,
                ));
            }
        };
        let (epoch, devices, read) = {
            let mut access = unsafe {
                // SAFETY: Admission executes on the sole reactor thread and the mounted VCB is
                // stable until its reactor has drained every admitted operation.
                VolumeControlBlock::operation_access(volume)
            };
            let read = EpochReadOperation::new(access.runtime().profile());
            let devices = access.runtime().storage();
            let epoch = match access.runtime_mut().acquire_epoch() {
                Ok(epoch) => epoch,
                Err(error) => return Err(AdmitOperationError::new(error, owned)),
            };
            (epoch, devices, read)
        };
        match memory::boxed_try_map((owned, epoch), |(owned, epoch)| Self {
            volume,
            epoch,
            devices,
            kind,
            state: ReadOperationState::Running { owned, read },
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _epoch)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Executes the driver read surface for one ephemeral committed pass.
    fn execute_pass(
        kind: ReadRequestKind,
        owned: &mut OwnedIrp,
        read: &mut ext4_core::EpochReadPass<'_, '_, '_>,
    ) -> DriverResult<IrpCompletion> {
        match kind {
            ReadRequestKind::Read => crate::request::file_info::read(owned.request(), read),
            ReadRequestKind::QueryInformation => {
                crate::request::file_info::query(owned.request(), read)
            }
            ReadRequestKind::QueryDirectory => {
                crate::request::file_info::query_directory(owned.request(), read)
            }
            ReadRequestKind::QueryEa => crate::request::ea::query(owned.request(), read),
            ReadRequestKind::QuerySecurity => {
                crate::request::security::query(owned.request(), read)
            }
        }
    }

    /// Completes and consumes one terminal top-level IRP.
    fn complete(owned: OwnedIrp, result: DriverResult<IrpCompletion>) -> OperationTransition {
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }
}

impl CompletionOperation for ReadRequestOperation {
    fn advance(mut self: Box<Self>, event: OperationEvent) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, ReadOperationState::Terminal);
        let ReadOperationState::Running { mut owned, read } = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        let kind = self.kind;
        let transition = read.run(event, self.epoch.epoch(), |pass| {
            match Self::execute_pass(kind, &mut owned, pass) {
                Err(DriverError::Core(Error::OperationSuspended)) => Err(Error::OperationSuspended),
                result => Ok(result),
            }
        });
        match transition {
            ReadTransition::SubmitLower { request, suspended } => {
                self.state = ReadOperationState::Running {
                    owned,
                    read: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            ReadTransition::Complete(Ok(result)) => Self::complete(owned, result),
            ReadTransition::Complete(Err(error)) => {
                Self::complete(owned, Err(DriverError::from(error)))
            }
        }
    }

    fn record_storage_failure(&mut self, failure: StorageFailureClass) {
        if failure == StorageFailureClass::DurabilityUnknown {
            let mut access = unsafe {
                // SAFETY: Failure classification executes on the sole reactor thread while this
                // operation retains the mounted VCB lifetime.
                VolumeControlBlock::operation_access(self.volume)
            };
            access.runtime_mut().record_durability_unknown();
        }
    }
}

// SAFETY: The VCB and epoch remain stable until reactor drain, and the unique IRP moves only
// between this box and completion envelopes.
unsafe impl Send for ReadRequestOperation {}

/// Synchronous request kinds that require no lower-storage state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImmediateRequestKind {
    /// Volume information query from already committed runtime state.
    QueryVolumeInformation,
    /// Terminal FILE_OBJECT close.
    Close,
}

/// Explicit state of one immediate top-level operation.
#[derive(Debug)]
enum ImmediateOperationState {
    /// IRP is available for its sole admitted event.
    Ready(OwnedIrp),
    /// IRP completion was consumed.
    Terminal,
}

/// One request that completes in a single reactor transition.
#[derive(Debug)]
struct ImmediateRequestOperation {
    /// Concrete request semantics.
    kind: ImmediateRequestKind,
    /// Explicit ownership phase.
    state: ImmediateOperationState,
}

impl ImmediateRequestOperation {
    /// Allocates an immediate operation without losing IRP completion authority on OOM.
    fn try_new(
        owned: OwnedIrp,
        kind: ImmediateRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        match memory::boxed_try_map(owned, |owned| Self {
            kind,
            state: ImmediateOperationState::Ready(owned),
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, owned) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }
}

impl CompletionOperation for ImmediateRequestOperation {
    fn advance(mut self: Box<Self>, event: OperationEvent) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, ImmediateOperationState::Terminal);
        let ImmediateOperationState::Ready(mut owned) = state else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        let result = match event {
            OperationEvent::Admitted => match self.kind {
                ImmediateRequestKind::QueryVolumeInformation => {
                    crate::request::volume_info::query(owned.request())
                }
                ImmediateRequestKind::Close => owned
                    .request()
                    .with_active(crate::request::file_info::close),
            },
            OperationEvent::CancelRequested => Err(DriverError::from(Error::OperationCancelled)),
            OperationEvent::StorageCompleted(_)
            | OperationEvent::RetryElapsed(_)
            | OperationEvent::IntentGranted(_)
            | OperationEvent::CommitGranted(_)
            | OperationEvent::VisibilityGranted(_)
            | OperationEvent::CheckpointGranted(_)
            | OperationEvent::BarrierReleased(_) => Err(DriverError::InternalInvariantViolation),
        };
        let _status = owned.complete_result(result);
        OperationTransition::Complete
    }

    fn record_storage_failure(&mut self, _failure: StorageFailureClass) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

// SAFETY: Unique IRP authority is moved only by the reactor thread.
unsafe impl Send for ImmediateRequestOperation {}

/// Mutation request semantics selected entirely from captured queue metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MutationRequestKind {
    /// Create/open, including missing-child creation.
    Create,
    /// Regular-file data write.
    Write,
    /// File-information mutation.
    SetInformation,
    /// Extended-attribute mutation.
    SetEa,
    /// Security-descriptor mutation.
    SetSecurity,
    /// Volume-label mutation.
    SetVolumeInformation,
    /// Cleanup-time namespace deletion after the terminal handle barrier.
    Cleanup,
}

/// Terminal payload appropriate for the top-level IRP's major function.
#[derive(Debug)]
enum TopLevelCompletion {
    /// Ordinary status/information completion.
    Normal(IrpCompletion),
    /// Create completion with create action or reparse ownership.
    Create(CreateCompletion),
}

/// Driver-visible values produced by one successful mutation resolve pass.
#[derive(Debug)]
enum PendingDriverPublication {
    /// Create must acquire its FCB/share claim before the first write.
    Create(crate::request::create::PendingCreatePublication),
    /// Write position was fully validated and prepared by resolve.
    Write(crate::request::file_info::PreparedWritePublication),
    /// Set-information driver state was fully allocated by resolve.
    SetFile(crate::request::file_info::SetFilePublication),
    /// Cleanup deletion notification and target were fully prepared by resolve.
    Cleanup(crate::request::file_info::PreparedCleanupPublication),
    /// Prevalidated VPB label publication.
    VolumeLabel(crate::request::volume_info::PreparedVolumeLabelPublication),
    /// Mutation has no additional driver state to publish.
    Normal(IrpCompletion),
}

/// Post-commit driver publication whose durable path cannot allocate or fail.
#[derive(Debug)]
enum PreparedDriverPublication {
    /// Fully claimed create handle state.
    Create(crate::request::create::PreparedCreatePublication),
    /// Checked write cursor and completion.
    Write(crate::request::file_info::PreparedWritePublication),
    /// Set-information publication.
    SetFile(crate::request::file_info::SetFilePublication),
    /// Cleanup deletion publication.
    Cleanup(crate::request::file_info::PreparedCleanupPublication),
    /// Volume-label publication.
    VolumeLabel(crate::request::volume_info::PreparedVolumeLabelPublication),
    /// No driver-side mutation publication.
    Normal(IrpCompletion),
}

impl PendingDriverPublication {
    /// Completes every fallible driver-side acquisition before commit I/O can start.
    fn prepare(self) -> DriverResult<PreparedDriverPublication> {
        Ok(match self {
            Self::Create(publication) => PreparedDriverPublication::Create(publication.prepare()?),
            Self::Write(publication) => PreparedDriverPublication::Write(publication),
            Self::SetFile(publication) => PreparedDriverPublication::SetFile(publication),
            Self::Cleanup(publication) => PreparedDriverPublication::Cleanup(publication),
            Self::VolumeLabel(publication) => PreparedDriverPublication::VolumeLabel(publication),
            Self::Normal(completion) => PreparedDriverPublication::Normal(completion),
        })
    }
}

impl PreparedDriverPublication {
    /// Applies only moves and prevalidated pointer/state updates after commit durability.
    fn publish(self, operations: &mut crate::state::VolumeAccess) -> TopLevelCompletion {
        match self {
            Self::Create(publication) => {
                TopLevelCompletion::Create(publication.publish(operations))
            }
            Self::Write(publication) => TopLevelCompletion::Normal(publication.publish()),
            Self::SetFile(publication) => {
                publication.publish(operations);
                TopLevelCompletion::Normal(IrpCompletion::EMPTY)
            }
            Self::Cleanup(publication) => {
                TopLevelCompletion::Normal(publication.publish(operations))
            }
            Self::VolumeLabel(publication) => {
                publication.publish();
                TopLevelCompletion::Normal(IrpCompletion::EMPTY)
            }
            Self::Normal(completion) => TopLevelCompletion::Normal(completion),
        }
    }
}

/// State retained throughout one durable commit while the top-level IRP remains owned.
#[derive(Debug)]
struct CommitContext {
    /// Unique top-level completion authority.
    owned: OwnedIrp,
    /// Infallible driver-visible publication.
    publication: PreparedDriverPublication,
    /// Pre-reserved durable epoch slot.
    durable_slot: EpochPublicationSlot,
    /// Pre-reserved checkpoint epoch slot.
    checkpoint_slot: EpochPublicationSlot,
}

/// Exact write/flush phase awaiting one matching lower completion.
#[derive(Debug)]
enum CommitIoPhase {
    /// One ordered data write is in flight; `remaining` owns the rest.
    OrderedWrite {
        expected: StorageRequestIdentity,
        remaining: StorageRequestSequence<OrderedDataDurability>,
    },
    /// Filesystem flush after every ordered data write.
    OrderedFlush {
        expected: StorageRequestIdentity,
        next: OrderedDataDurability,
    },
    /// One journal descriptor/payload write is in flight.
    JournalWrite {
        expected: StorageRequestIdentity,
        remaining: StorageRequestSequence<JournalPayloadDurability>,
    },
    /// Journal payload durability flush preceding the commit record.
    JournalFlush {
        expected: StorageRequestIdentity,
        next: JournalPayloadDurability,
    },
    /// Single commit record write.
    CommitWrite {
        expected: StorageRequestIdentity,
        next: CommitDurability,
    },
    /// Flush that establishes commit durability.
    CommitFlush {
        expected: StorageRequestIdentity,
        next: CommitDurability,
    },
}

/// Exact checkpoint write/flush phase after the top-level mutation is already visible.
#[derive(Debug)]
enum CheckpointIoPhase {
    /// One home-block write is in flight.
    HomeWrite {
        expected: StorageRequestIdentity,
        remaining: StorageRequestSequence<HomeBlockDurability>,
    },
    /// Filesystem durability flush after home-block writes.
    HomeFlush {
        expected: StorageRequestIdentity,
        next: HomeBlockDurability,
    },
    /// Clean journal-superblock write.
    CleanWrite {
        expected: StorageRequestIdentity,
        next: CleanJournalDurability,
    },
    /// Flush that makes the clean journal state durable.
    CleanFlush {
        expected: StorageRequestIdentity,
        next: CleanJournalDurability,
    },
}

/// Explicit ownership phase of one journaled mutation operation.
#[derive(Debug)]
enum MutationOperationState {
    /// Read-only resolution against one immutable epoch.
    Resolving {
        owned: OwnedIrp,
        epoch: EpochLease,
        resolve: MutationResolveOperation<CngFscryptNonceGenerator>,
    },
    /// Resolved resources await atomic intent acquisition.
    AwaitingIntent {
        owned: OwnedIrp,
        resolved: ResolvedMutation,
        publication: PendingDriverPublication,
    },
    /// Revalidated reservation and all publication allocations await commit serialization.
    AwaitingCommit {
        owned: OwnedIrp,
        reserved: ReservedMutation,
        publication: PreparedDriverPublication,
        slots: EpochPublicationSlots,
    },
    /// Commit writes and durability flushes are in progress.
    CommitIo {
        context: CommitContext,
        phase: CommitIoPhase,
    },
    /// Durable mutation waits only for the short visibility gate.
    AwaitingVisibility {
        context: CommitContext,
        durable: DurableMutation,
    },
    /// Durable values plus the consumed visibility grant await infallible publication.
    PublishingDurable {
        context: CommitContext,
        durable: DurableMutation,
        visibility: ext4_core::VisibilityLease,
    },
    /// Detached checkpoint waits independently of reader visibility.
    AwaitingCheckpoint(PendingCheckpoint),
    /// Checkpoint lower I/O is in progress.
    CheckpointIo {
        phase: CheckpointIoPhase,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    },
    /// Clean journal and overlay-free epoch await infallible publication.
    PublishingCheckpoint {
        durability: CleanJournalDurability,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    },
    /// Every authority has been consumed.
    Terminal,
}

/// One journaled request whose operation allocation is reused through checkpoint completion.
#[derive(Debug)]
struct MutationRequestOperation {
    /// Stable mounted volume receiving all coordinator and publication transitions.
    volume: NonNull<VolumeControlBlock>,
    /// Validated mounted lower devices.
    devices: MountedStorageDevices,
    /// Stable FIFO ticket retained across stale-plan re-resolution.
    ticket: u64,
    /// Timestamp fixed for the logical mutation across every replay pass.
    now: ext4_core::Ext4Timestamp,
    /// Captured request semantics.
    kind: MutationRequestKind,
    /// Cleanup deletion plan retained across resolve suspension.
    cleanup_deletion: Option<crate::request::file_info::PendingCleanupDeletion>,
    /// Whether a successful pre-commit write has made abort/replay relevant.
    write_effect_observed: bool,
    /// Current consuming state.
    state: MutationOperationState,
}

/// Result of one driver request surface invoked inside an ephemeral core resolve pass.
enum DriverResolveDisposition {
    /// Request completed without staging a filesystem mutation.
    Complete(TopLevelCompletion),
    /// Core mutation and corresponding post-commit driver values were staged.
    Mutation(PendingDriverPublication),
}

impl MutationRequestOperation {
    /// Allocates one mutation operation after acquiring its stable ticket and epoch lease.
    fn try_new(
        owned: OwnedIrp,
        kind: MutationRequestKind,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let volume = match MountedVolumeDevice::vcb(owned.device()) {
            Some(volume) => volume,
            None => {
                return Err(AdmitOperationError::new(
                    DriverError::InvalidDeviceRequest,
                    owned,
                ));
            }
        };
        let now = match crate::kernel::time::current_ext4_timestamp() {
            Ok(now) => now,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        let (ticket, devices, epoch, resolve) = {
            let mut access = unsafe {
                // SAFETY: Admission executes on the sole reactor thread and every returned token
                // is owned by the operation before that access projection ends.
                VolumeControlBlock::operation_access(volume)
            };
            let ticket = match access.runtime_mut().admit_mutation() {
                Ok(ticket) => ticket,
                Err(error) => return Err(AdmitOperationError::new(error, owned)),
            };
            let epoch = match access.runtime_mut().acquire_epoch() {
                Ok(epoch) => epoch,
                Err(error) => return Err(AdmitOperationError::new(error, owned)),
            };
            let devices = access.runtime().storage();
            let resolve =
                MutationResolveOperation::new(access.runtime().profile(), CngFscryptNonceGenerator);
            (ticket, devices, epoch, resolve)
        };
        match memory::boxed_try_map((owned, epoch), |(owned, epoch)| Self {
            volume,
            devices,
            ticket,
            now,
            kind,
            cleanup_deletion: None,
            write_effect_observed: false,
            state: MutationOperationState::Resolving {
                owned,
                epoch,
                resolve,
            },
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _epoch)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Completes one top-level success with its major-function-specific ownership protocol.
    fn complete_success(owned: OwnedIrp, completion: TopLevelCompletion) -> OperationTransition {
        match completion {
            TopLevelCompletion::Normal(completion) => {
                let _status = owned.complete(completion);
            }
            TopLevelCompletion::Create(completion) => {
                let _status = owned.complete_create_result(Ok(completion));
            }
        }
        OperationTransition::Complete
    }

    /// Completes one top-level failure while respecting create auxiliary-buffer ownership.
    fn complete_error(&self, owned: OwnedIrp, error: DriverError) -> OperationTransition {
        if self.kind == MutationRequestKind::Create {
            let _status = owned.complete_create_result(Err(error));
        } else {
            let _status = owned.complete_result(Err(error));
        }
        OperationTransition::Complete
    }

    /// Runs the concrete driver mutation surface inside one restart-local core pass.
    fn execute_resolve(
        &mut self,
        owned: &mut OwnedIrp,
        operations: &mut crate::state::VolumeAccess,
        mutation: &mut crate::request::DriverMutationPass<'_, '_, '_>,
    ) -> DriverResult<DriverResolveDisposition> {
        match self.kind {
            MutationRequestKind::Create => {
                match crate::request::create::execute(owned.request(), operations, mutation)? {
                    crate::request::create::CreateResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Create(completion)),
                    ),
                    crate::request::create::CreateResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::Create(publication),
                        ))
                    }
                }
            }
            MutationRequestKind::Write => {
                match crate::request::file_info::write(owned.request(), mutation)? {
                    crate::request::file_info::WriteResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Normal(completion)),
                    ),
                    crate::request::file_info::WriteResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::Write(publication),
                        ))
                    }
                }
            }
            MutationRequestKind::SetInformation => {
                match crate::request::file_info::set(owned.request(), operations, mutation)? {
                    crate::request::file_info::SetFileResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Normal(completion)),
                    ),
                    crate::request::file_info::SetFileResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::SetFile(publication),
                        ))
                    }
                }
            }
            MutationRequestKind::SetEa => {
                let completion = crate::request::ea::set(owned.request(), mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            MutationRequestKind::SetSecurity => {
                let completion = crate::request::security::set(owned.request(), mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Normal(completion),
                ))
            }
            MutationRequestKind::SetVolumeInformation => {
                match crate::request::volume_info::set(owned.request(), mutation)? {
                    crate::request::volume_info::SetVolumeResolution::Complete(completion) => Ok(
                        DriverResolveDisposition::Complete(TopLevelCompletion::Normal(completion)),
                    ),
                    crate::request::volume_info::SetVolumeResolution::Mutation(publication) => {
                        Ok(DriverResolveDisposition::Mutation(
                            PendingDriverPublication::VolumeLabel(publication),
                        ))
                    }
                }
            }
            MutationRequestKind::Cleanup => {
                if self.cleanup_deletion.is_none() {
                    match crate::request::file_info::cleanup(owned.request())? {
                        crate::request::file_info::CleanupResolution::Complete(completion) => {
                            return Ok(DriverResolveDisposition::Complete(
                                TopLevelCompletion::Normal(completion),
                            ));
                        }
                        crate::request::file_info::CleanupResolution::Delete(deletion) => {
                            self.cleanup_deletion = Some(deletion);
                        }
                    }
                }
                let Some(deletion) = self.cleanup_deletion.as_ref() else {
                    return Err(DriverError::InternalInvariantViolation);
                };
                let publication =
                    crate::request::file_info::stage_cleanup_deletion(deletion, mutation)?;
                Ok(DriverResolveDisposition::Mutation(
                    PendingDriverPublication::Cleanup(publication),
                ))
            }
        }
    }

    /// Reacquires the latest immutable epoch while retaining the original FIFO ticket.
    fn restart_resolution(self: Box<Self>, owned: OwnedIrp) -> OperationTransition {
        let (epoch, resolve) = {
            let mut access = unsafe {
                // SAFETY: Stale-plan restart runs on the sole reactor thread and projects the
                // stable mounted runtime only for token acquisition.
                VolumeControlBlock::operation_access(self.volume)
            };
            let epoch = match access.runtime_mut().acquire_epoch() {
                Ok(epoch) => epoch,
                Err(error) => return self.complete_error(owned, error),
            };
            let resolve =
                MutationResolveOperation::new(access.runtime().profile(), CngFscryptNonceGenerator);
            (epoch, resolve)
        };
        self.advance_resolution(owned, epoch, resolve, OperationEvent::Admitted)
    }

    /// Integrates one resolution event and emits only its matching next action.
    fn advance_resolution(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        epoch: EpochLease,
        resolve: MutationResolveOperation<CngFscryptNonceGenerator>,
        event: OperationEvent,
    ) -> OperationTransition {
        let mut ready = match resolve.accept(event) {
            Ok(ready) => ready,
            Err(error) => return self.complete_error(owned, DriverError::from(error)),
        };
        let mut publication = None;
        let resolved = {
            let mut operations = unsafe {
                // SAFETY: One reactor transition owns this VCB projection; no reference crosses
                // the transition or enters a completion envelope.
                VolumeControlBlock::operation_access(self.volume)
            };
            let mut pass = ready.begin_pass(epoch.epoch(), self.now);
            match self.execute_resolve(&mut owned, &mut operations, &mut pass) {
                Ok(DriverResolveDisposition::Complete(completion)) => {
                    return Self::complete_success(owned, completion);
                }
                Ok(DriverResolveDisposition::Mutation(prepared)) => {
                    publication = Some(prepared);
                    pass.resolve(self.ticket, operations.runtime().coordinator())
                }
                Err(DriverError::Core(Error::OperationSuspended)) => Err(Error::OperationSuspended),
                Err(error) => return self.complete_error(owned, error),
            }
        };
        match ready.finish(resolved) {
            MutationResolveTransition::SubmitLower { request, suspended } => {
                self.state = MutationOperationState::Resolving {
                    owned,
                    epoch,
                    resolve: suspended,
                };
                OperationTransition::SubmitLower {
                    devices: self.devices,
                    request,
                    suspended: self,
                }
            }
            MutationResolveTransition::Complete(Ok(resolved)) => {
                let Some(publication) = publication else {
                    return self.complete_error(owned, DriverError::InternalInvariantViolation);
                };
                let resources = resolved.observed_resources().resources();
                let mut requested = match memory::DriverVec::try_with_capacity(resources.len()) {
                    Ok(requested) => requested,
                    Err(error) => return self.complete_error(owned, error),
                };
                for resource in resources {
                    if let Err(error) = requested.try_push(resource) {
                        return self.complete_error(owned, error);
                    }
                }
                self.state = MutationOperationState::AwaitingIntent {
                    owned,
                    resolved,
                    publication,
                };
                OperationTransition::RequestIntent {
                    request: IntentRequest::new(self.volume, self.ticket, requested),
                    suspended: self,
                }
            }
            MutationResolveTransition::Complete(Err(error)) => {
                self.complete_error(owned, DriverError::from(error))
            }
        }
    }

    /// Submits one commit-phase request after storing its exact expected completion identity.
    fn submit_commit_request(
        mut self: Box<Self>,
        context: CommitContext,
        phase: CommitIoPhase,
        request: StorageRequest,
    ) -> OperationTransition {
        self.state = MutationOperationState::CommitIo { context, phase };
        OperationTransition::SubmitLower {
            devices: self.devices,
            request,
            suspended: self,
        }
    }

    /// Emits the next ordered-data request or its required filesystem flush.
    fn drive_ordered(
        self: Box<Self>,
        context: CommitContext,
        sequence: StorageRequestSequence<OrderedDataDurability>,
    ) -> OperationTransition {
        match sequence.advance() {
            StorageRequestSequenceStep::Submit { request, suspended } => {
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::OrderedWrite {
                        expected,
                        remaining: suspended,
                    },
                    request,
                )
            }
            StorageRequestSequenceStep::Finished(next) => {
                let request = next.flush_request();
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::OrderedFlush { expected, next },
                    request,
                )
            }
        }
    }

    /// Emits the next journal payload write or its pre-commit durability flush.
    fn drive_journal(
        self: Box<Self>,
        context: CommitContext,
        sequence: StorageRequestSequence<JournalPayloadDurability>,
    ) -> OperationTransition {
        match sequence.advance() {
            StorageRequestSequenceStep::Submit { request, suspended } => {
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::JournalWrite {
                        expected,
                        remaining: suspended,
                    },
                    request,
                )
            }
            StorageRequestSequenceStep::Finished(next) => {
                let request = next.flush_request();
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_commit_request(
                    context,
                    CommitIoPhase::JournalFlush { expected, next },
                    request,
                )
            }
        }
    }

    /// Submits the single commit record after journal payload durability.
    fn submit_commit_record(
        self: Box<Self>,
        context: CommitContext,
        payload: JournalPayloadDurability,
    ) -> OperationTransition {
        let (request, next) = payload.completed().submit();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_commit_request(
            context,
            CommitIoPhase::CommitWrite { expected, next },
            request,
        )
    }

    /// Submits the flush that makes the commit record durable.
    fn submit_commit_flush(
        self: Box<Self>,
        context: CommitContext,
        next: CommitDurability,
    ) -> OperationTransition {
        let request = next.flush_request();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_commit_request(
            context,
            CommitIoPhase::CommitFlush { expected, next },
            request,
        )
    }

    /// Converts a commit-path lower failure into a recovery-required terminal result.
    fn fail_commit_path(&self, context: CommitContext, error: Error) -> OperationTransition {
        let mut access = unsafe {
            // SAFETY: Failure publication runs on the sole reactor thread against a stable VCB.
            VolumeControlBlock::operation_access(self.volume)
        };
        if self.write_effect_observed {
            access.runtime_mut().record_durability_unknown();
        }
        self.complete_error(context.owned, DriverError::from(error))
    }

    /// Records one successfully completed pre-visibility write.
    fn observed_write(mut self: Box<Self>) -> Box<Self> {
        self.write_effect_observed = true;
        self
    }

    /// Integrates one matching commit-phase completion and advances only that phase.
    fn advance_commit_io(
        self: Box<Self>,
        context: CommitContext,
        phase: CommitIoPhase,
        event: OperationEvent,
    ) -> OperationTransition {
        let OperationEvent::StorageCompleted(completion) = event else {
            return self.fail_commit_path(context, Error::DeviceIo);
        };
        match phase {
            CommitIoPhase::OrderedWrite {
                expected,
                remaining,
            } => match expected.complete(completion) {
                Ok(()) => self.observed_write().drive_ordered(context, remaining),
                Err(error) => self.fail_commit_path(context, error),
            },
            CommitIoPhase::OrderedFlush { expected, next } => match expected.complete(completion) {
                Ok(()) => self.drive_journal(context, next.completed()),
                Err(error) => self.fail_commit_path(context, error),
            },
            CommitIoPhase::JournalWrite {
                expected,
                remaining,
            } => match expected.complete(completion) {
                Ok(()) => self.observed_write().drive_journal(context, remaining),
                Err(error) => self.fail_commit_path(context, error),
            },
            CommitIoPhase::JournalFlush { expected, next } => match expected.complete(completion) {
                Ok(()) => self.submit_commit_record(context, next),
                Err(error) => self.fail_commit_path(context, error),
            },
            CommitIoPhase::CommitWrite { expected, next } => match expected.complete(completion) {
                Ok(()) => self.observed_write().submit_commit_flush(context, next),
                Err(error) => self.fail_commit_path(context, error),
            },
            CommitIoPhase::CommitFlush { expected, next } => match expected.complete(completion) {
                Ok(()) => {
                    let durable = next.completed();
                    let volume = self.volume;
                    let ticket = self.ticket;
                    let mut this = self;
                    this.state = MutationOperationState::AwaitingVisibility { context, durable };
                    OperationTransition::Wait {
                        condition: WaitCondition::Visibility { volume, ticket },
                        suspended: this,
                    }
                }
                Err(error) => self.fail_commit_path(context, error),
            },
        }
    }

    /// Submits one checkpoint request after storing its expected identity.
    fn submit_checkpoint_request(
        mut self: Box<Self>,
        phase: CheckpointIoPhase,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
        request: StorageRequest,
    ) -> OperationTransition {
        self.state = MutationOperationState::CheckpointIo {
            phase,
            publication,
            epoch,
        };
        OperationTransition::SubmitLower {
            devices: self.devices,
            request,
            suspended: self,
        }
    }

    /// Emits the next home-block write or its filesystem durability flush.
    fn drive_checkpoint_home(
        self: Box<Self>,
        sequence: StorageRequestSequence<HomeBlockDurability>,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) -> OperationTransition {
        match sequence.advance() {
            StorageRequestSequenceStep::Submit { request, suspended } => {
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_checkpoint_request(
                    CheckpointIoPhase::HomeWrite {
                        expected,
                        remaining: suspended,
                    },
                    publication,
                    epoch,
                    request,
                )
            }
            StorageRequestSequenceStep::Finished(next) => {
                let request = next.flush_request();
                let expected = StorageRequestIdentity::from_request(&request);
                self.submit_checkpoint_request(
                    CheckpointIoPhase::HomeFlush { expected, next },
                    publication,
                    epoch,
                    request,
                )
            }
        }
    }

    /// Submits the clean journal-superblock write after home-block durability.
    fn submit_clean_record(
        self: Box<Self>,
        next: HomeBlockDurability,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) -> OperationTransition {
        let (request, next) = next.completed().submit();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_checkpoint_request(
            CheckpointIoPhase::CleanWrite { expected, next },
            publication,
            epoch,
            request,
        )
    }

    /// Submits the flush that establishes a clean journal state.
    fn submit_clean_flush(
        self: Box<Self>,
        next: CleanJournalDurability,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
    ) -> OperationTransition {
        let request = next.flush_request();
        let expected = StorageRequestIdentity::from_request(&request);
        self.submit_checkpoint_request(
            CheckpointIoPhase::CleanFlush { expected, next },
            publication,
            epoch,
            request,
        )
    }

    /// Ends a failed detached checkpoint while retaining the already published overlay.
    fn fail_checkpoint(
        &self,
        publication: EpochPublicationSlot,
        failure: StorageFailureClass,
    ) -> OperationTransition {
        drop(publication);
        let mut access = unsafe {
            // SAFETY: Detached checkpoint failure is published on the sole reactor thread.
            VolumeControlBlock::operation_access(self.volume)
        };
        match failure {
            StorageFailureClass::Terminal => access.runtime_mut().record_durable_abort(),
            StorageFailureClass::DurabilityUnknown => {
                access.runtime_mut().record_durability_unknown();
            }
        }
        OperationTransition::Complete
    }

    /// Integrates one matching detached-checkpoint completion.
    fn advance_checkpoint_io(
        self: Box<Self>,
        phase: CheckpointIoPhase,
        publication: EpochPublicationSlot,
        epoch: ext4_core::EpochSequence,
        event: OperationEvent,
    ) -> OperationTransition {
        let OperationEvent::StorageCompleted(completion) = event else {
            return self.fail_checkpoint(publication, StorageFailureClass::DurabilityUnknown);
        };
        match phase {
            CheckpointIoPhase::HomeWrite {
                expected,
                remaining,
            } => match expected.complete(completion) {
                Ok(()) => self.drive_checkpoint_home(remaining, publication, epoch),
                Err(_) => self.fail_checkpoint(publication, StorageFailureClass::Terminal),
            },
            CheckpointIoPhase::HomeFlush { expected, next } => {
                match expected.complete(completion) {
                    Ok(()) => self.submit_clean_record(next, publication, epoch),
                    Err(_) => self.fail_checkpoint(publication, StorageFailureClass::Terminal),
                }
            }
            CheckpointIoPhase::CleanWrite { expected, next } => {
                match expected.complete(completion) {
                    Ok(()) => self.submit_clean_flush(next, publication, epoch),
                    Err(_) => {
                        self.fail_checkpoint(publication, StorageFailureClass::DurabilityUnknown)
                    }
                }
            }
            CheckpointIoPhase::CleanFlush { expected, next } => {
                match expected.complete(completion) {
                    Ok(()) => {
                        let mut this = self;
                        this.state = MutationOperationState::PublishingCheckpoint {
                            durability: next,
                            publication,
                            epoch,
                        };
                        OperationTransition::Publish { publication: this }
                    }
                    Err(_) => {
                        self.fail_checkpoint(publication, StorageFailureClass::DurabilityUnknown)
                    }
                }
            }
        }
    }
}

impl CompletionOperation for MutationRequestOperation {
    fn advance(mut self: Box<Self>, event: OperationEvent) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
        match state {
            MutationOperationState::Resolving {
                owned,
                epoch,
                resolve,
            } => self.advance_resolution(owned, epoch, resolve, event),
            MutationOperationState::AwaitingIntent {
                owned,
                resolved,
                publication,
            } => {
                let OperationEvent::IntentGranted(intent) = event else {
                    return self.complete_error(owned, DriverError::InvalidDeviceRequest);
                };
                let reserved = {
                    let access = unsafe {
                        // SAFETY: Version revalidation is a non-suspending projection on the sole
                        // reactor thread.
                        VolumeControlBlock::operation_access(self.volume)
                    };
                    resolved.reserve(access.runtime().coordinator(), intent)
                };
                let reserved = match reserved {
                    Ok(reserved) => reserved,
                    Err(Error::ClusterReferenceConflict) => {
                        drop(publication);
                        return self.restart_resolution(owned);
                    }
                    Err(error) => {
                        drop(publication);
                        return self.complete_error(owned, DriverError::from(error));
                    }
                };
                let publication = match publication.prepare() {
                    Ok(publication) => publication,
                    Err(error) => return self.complete_error(owned, error),
                };
                let slots = {
                    let mut access = unsafe {
                        // SAFETY: The VCB is heap-stable and publication reservations remain
                        // operation-owned until publish or pre-write rollback.
                        VolumeControlBlock::operation_access(self.volume)
                    };
                    match unsafe { access.runtime_mut().reserve_epoch_publication() } {
                        Ok(slots) => slots,
                        Err(error) => return self.complete_error(owned, error),
                    }
                };
                self.state = MutationOperationState::AwaitingCommit {
                    owned,
                    reserved,
                    publication,
                    slots,
                };
                OperationTransition::RequestCommit {
                    volume: self.volume,
                    ticket: self.ticket,
                    suspended: self,
                }
            }
            MutationOperationState::AwaitingCommit {
                owned,
                reserved,
                publication,
                slots,
            } => {
                let OperationEvent::CommitGranted(commit) = event else {
                    return self.complete_error(owned, DriverError::InvalidDeviceRequest);
                };
                let ready: Result<CommitReadyMutation, Error> = {
                    let access = unsafe {
                        // SAFETY: Commit preparation borrows stable runtime state only for this
                        // transition and all returned values are owned.
                        VolumeControlBlock::operation_access(self.volume)
                    };
                    let runtime = access.runtime();
                    reserved.prepare_commit(runtime.coordinator(), runtime.current_epoch(), commit)
                };
                let ready = match ready {
                    Ok(ready) => ready,
                    Err(error) => return self.complete_error(owned, DriverError::from(error)),
                };
                let (durable_slot, checkpoint_slot) = slots.into_parts();
                let context = CommitContext {
                    owned,
                    publication,
                    durable_slot,
                    checkpoint_slot,
                };
                self.drive_ordered(context, ready.start())
            }
            MutationOperationState::CommitIo { context, phase } => {
                self.advance_commit_io(context, phase, event)
            }
            MutationOperationState::AwaitingVisibility { context, durable } => {
                let OperationEvent::VisibilityGranted(visibility) = event else {
                    return self.fail_commit_path(context, Error::DeviceIo);
                };
                self.state = MutationOperationState::PublishingDurable {
                    context,
                    durable,
                    visibility,
                };
                OperationTransition::Publish { publication: self }
            }
            MutationOperationState::PublishingDurable { context, .. } => {
                self.fail_commit_path(context, Error::DeviceIo)
            }
            MutationOperationState::AwaitingCheckpoint(pending) => match event {
                OperationEvent::Admitted => OperationTransition::Wait {
                    condition: WaitCondition::Checkpoint {
                        volume: self.volume,
                        epoch: pending.epoch(),
                    },
                    suspended: {
                        self.state = MutationOperationState::AwaitingCheckpoint(pending);
                        self
                    },
                },
                OperationEvent::CheckpointGranted(checkpoint) => {
                    let (operation, publication, epoch) = pending.into_parts();
                    self.drive_checkpoint_home(operation.start(checkpoint), publication, epoch)
                }
                OperationEvent::StorageCompleted(_)
                | OperationEvent::CancelRequested
                | OperationEvent::RetryElapsed(_)
                | OperationEvent::IntentGranted(_)
                | OperationEvent::CommitGranted(_)
                | OperationEvent::VisibilityGranted(_)
                | OperationEvent::BarrierReleased(_) => {
                    let (_, publication, _) = pending.into_parts();
                    self.fail_checkpoint(publication, StorageFailureClass::DurabilityUnknown)
                }
            },
            MutationOperationState::CheckpointIo {
                phase,
                publication,
                epoch,
            } => self.advance_checkpoint_io(phase, publication, epoch, event),
            MutationOperationState::PublishingCheckpoint { publication, .. } => {
                self.fail_checkpoint(publication, StorageFailureClass::DurabilityUnknown)
            }
            MutationOperationState::Terminal => OperationTransition::Complete,
        }
    }

    fn record_storage_failure(&mut self, failure: StorageFailureClass) {
        let mut access = unsafe {
            // SAFETY: Lower completion returns this operation to the sole reactor thread before
            // failure classification mutates the stable volume runtime.
            VolumeControlBlock::operation_access(self.volume)
        };
        match (&self.state, failure) {
            (MutationOperationState::CommitIo { .. }, StorageFailureClass::DurabilityUnknown) => {
                access.runtime_mut().record_durability_unknown();
            }
            (MutationOperationState::CheckpointIo { .. }, StorageFailureClass::Terminal) => {
                access.runtime_mut().record_durable_abort();
            }
            (
                MutationOperationState::CheckpointIo { .. },
                StorageFailureClass::DurabilityUnknown,
            ) => {
                access.runtime_mut().record_durability_unknown();
            }
            (
                MutationOperationState::Resolving { .. },
                StorageFailureClass::Terminal | StorageFailureClass::DurabilityUnknown,
            )
            | (
                MutationOperationState::AwaitingIntent { .. }
                | MutationOperationState::AwaitingCommit { .. }
                | MutationOperationState::AwaitingVisibility { .. }
                | MutationOperationState::PublishingDurable { .. }
                | MutationOperationState::AwaitingCheckpoint(_)
                | MutationOperationState::PublishingCheckpoint { .. }
                | MutationOperationState::Terminal,
                _,
            )
            | (MutationOperationState::CommitIo { .. }, StorageFailureClass::Terminal) => {}
        }
    }
}

impl InfalliblePublication for MutationRequestOperation {
    fn authority(&self) -> PublicationAuthority {
        match &self.state {
            MutationOperationState::PublishingDurable { .. } => PublicationAuthority::Durable {
                volume: self.volume,
                ticket: self.ticket,
            },
            MutationOperationState::PublishingCheckpoint { epoch, .. } => {
                PublicationAuthority::Checkpoint {
                    volume: self.volume,
                    epoch: *epoch,
                }
            }
            MutationOperationState::Resolving { .. }
            | MutationOperationState::AwaitingIntent { .. }
            | MutationOperationState::AwaitingCommit { .. }
            | MutationOperationState::CommitIo { .. }
            | MutationOperationState::AwaitingVisibility { .. }
            | MutationOperationState::AwaitingCheckpoint(_)
            | MutationOperationState::CheckpointIo { .. }
            | MutationOperationState::Terminal => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn publish(mut self: Box<Self>) -> Box<dyn CompletionOperation> {
        let state = core::mem::replace(&mut self.state, MutationOperationState::Terminal);
        match state {
            MutationOperationState::PublishingDurable {
                context,
                durable,
                visibility,
            } => {
                let CommitContext {
                    owned,
                    publication,
                    durable_slot,
                    checkpoint_slot,
                } = context;
                let (completion, pending) = {
                    let mut access = unsafe {
                        // SAFETY: Publication is the sole reactor-owned transition and all inputs
                        // were preallocated before the first write.
                        VolumeControlBlock::operation_access(self.volume)
                    };
                    let pending = access.runtime_mut().publish_durable(
                        durable,
                        visibility,
                        durable_slot,
                        checkpoint_slot,
                    );
                    let completion = publication.publish(&mut access);
                    (completion, pending)
                };
                let _complete = Self::complete_success(owned, completion);
                self.state = MutationOperationState::AwaitingCheckpoint(pending);
            }
            MutationOperationState::PublishingCheckpoint {
                durability,
                publication,
                epoch,
            } => {
                let mut access = unsafe {
                    // SAFETY: Checkpoint publication exclusively consumes the matching gate and
                    // pre-reserved epoch slot on the reactor thread.
                    VolumeControlBlock::operation_access(self.volume)
                };
                access
                    .runtime_mut()
                    .publish_checkpoint(durability, publication, epoch);
                self.state = MutationOperationState::Terminal;
            }
            MutationOperationState::Resolving { .. }
            | MutationOperationState::AwaitingIntent { .. }
            | MutationOperationState::AwaitingCommit { .. }
            | MutationOperationState::CommitIo { .. }
            | MutationOperationState::AwaitingVisibility { .. }
            | MutationOperationState::AwaitingCheckpoint(_)
            | MutationOperationState::CheckpointIo { .. }
            | MutationOperationState::Terminal => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
        self
    }
}

// SAFETY: Every raw identity names VCB/FCB/FILE_OBJECT storage retained through reactor drain;
// mutable access is confined to the sole reactor thread and completion envelopes move only owned
// state.
unsafe impl Send for MutationRequestOperation {}

/// Allocates one concrete read operation.
pub(crate) fn read(
    owned: OwnedIrp,
    kind: ReadRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ReadRequestOperation::try_new(owned, kind)
}

/// Allocates one concrete single-transition operation.
pub(crate) fn immediate(
    owned: OwnedIrp,
    kind: ImmediateRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    ImmediateRequestOperation::try_new(owned, kind)
}

/// Allocates one concrete journaled mutation operation.
pub(crate) fn mutation(
    owned: OwnedIrp,
    kind: MutationRequestKind,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    MutationRequestOperation::try_new(owned, kind)
}
