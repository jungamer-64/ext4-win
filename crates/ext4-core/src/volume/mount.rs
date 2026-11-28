//! Mount admission, recovery, and first publication.

use alloc::boxed::Box;
use core::mem::MaybeUninit;

use super::block_group::AllocationIndexBuild;
use super::orphan::{ORPHAN_METADATA_BUDGET, OrphanRecoveryQueue, ValidatedOrphanInventory};
use super::scope::*;
use super::session_marker::{prepare_primary_images, prepare_session_checkpoint};
use super::transaction::{
    OrphanBatchCompletion, StorageRequestSequence, StorageRequestSequenceStep, prepare_orphan_batch,
};
use crate::disk::storage::{OperationDevice, StorageReadOverlay, StorageTarget, StorageTranscript};
use crate::disk_format::journal::{
    CleanJournal, ExternalJournalLoad, FilesystemHomeSpace, Journal, JournalRecoveryCompletion,
    JournalRecoveryOperation, LoadedJournal,
};
use crate::disk_format::superblock::{
    ChecksumInvalidSuperblock, FilesystemUuid, JournalMode, JournalUuid, PrimarySuperblockRead,
    WriteSessionState,
};

/// First publication of a recovered filesystem with its independently owned media lease.
#[derive(Debug)]
pub struct CompletedMount {
    /// Immutable mount profile.
    profile: MountedProfile,
    /// Initial immutable committed epoch.
    epoch: CommittedEpoch,
    /// Mutable journal and mutation coordinator.
    coordinator: MutationCoordinatorState,
    /// Sole media ownership lease, requiring independent host heartbeat and final release.
    mmp: Option<super::MmpLease>,
}

impl CompletedMount {
    /// Transfers core state and the independent physical lease to the host.
    /// The host owns heartbeat, mutation fencing and clean release after filesystem finalization.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        MountedProfile,
        CommittedEpoch,
        MutationCoordinatorState,
        Option<super::MmpLease>,
    ) {
        (self.profile, self.epoch, self.coordinator, self.mmp)
    }
}

/// Immutable requirement emitted when the primary filesystem names an external journal UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalJournalRequirement {
    /// External journal UUID from the primary filesystem superblock.
    journal_uuid: JournalUuid,
    /// Primary filesystem UUID required as the sole JBD2 user.
    filesystem_uuid: FilesystemUuid,
    /// Complete immutable geometry and ownership exclusions shared by discovery and replay.
    home_space: FilesystemHomeSpace,
}

impl ExternalJournalRequirement {
    /// UUID used to select candidate volume devices.
    #[must_use]
    pub const fn journal_uuid(self) -> JournalUuid {
        self.journal_uuid
    }

    /// Filesystem UUID that must be the external journal's sole user.
    #[must_use]
    pub const fn filesystem_uuid(self) -> FilesystemUuid {
        self.filesystem_uuid
    }

    /// Required external journal block size.
    #[must_use]
    pub const fn block_size(self) -> BlockSize {
        self.home_space.block_size()
    }
}

/// Non-forgeable proof that one concrete device was fully validated by the core probe path.
#[derive(Debug)]
pub struct ValidatedExternalJournal {
    /// Requirement satisfied by this exact validation.
    requirement: ExternalJournalRequirement,
    /// Validated candidate device length.
    device_length: DeviceLength,
}

impl ValidatedExternalJournal {
    /// Validated external device length retained for driver storage ownership.
    #[must_use]
    pub const fn device_length(&self) -> DeviceLength {
        self.device_length
    }
}

/// Terminal classification of one external-journal candidate.
#[derive(Debug)]
pub enum ExternalJournalProbeOutcome {
    /// Candidate UUID differs and discovery may continue.
    Mismatch,
    /// Candidate exactly matches and is safe to attach under its current device ownership.
    Match(Box<ValidatedExternalJournal>),
}

/// One consuming transition of an external-journal probe.
#[derive(Debug)]
pub enum ExternalJournalProbeTransition {
    /// Submit one candidate-device read.
    SubmitLower {
        /// Owned external-journal request.
        request: crate::StorageRequest,
        /// Probe resumed only by the matching completion.
        suspended: Box<ExternalJournalProbeOperation>,
    },
    /// Probe completed with a mismatch, validated token, or structural error.
    Complete(Result<ExternalJournalProbeOutcome>),
}

/// Concrete completion-driven validator for one external-journal candidate device.
#[derive(Debug)]
pub struct ExternalJournalProbeOperation {
    /// Filesystem-derived requirement.
    requirement: ExternalJournalRequirement,
    /// Candidate device transcript used only before a token is minted.
    candidate: StorageTranscript,
}

impl ExternalJournalProbeOperation {
    /// Starts validation for one candidate device length.
    #[must_use]
    pub const fn new(requirement: ExternalJournalRequirement, device_length: DeviceLength) -> Self {
        Self {
            requirement,
            candidate: StorageTranscript::new(StorageTarget::ExternalJournal, device_length),
        }
    }

    /// Consumes one candidate event; only identity/geometry evidence survives discovery.
    #[must_use]
    pub fn advance(
        self: Box<Self>,
        event: super::OperationEvent,
    ) -> ExternalJournalProbeTransition {
        let requirement = self.requirement;
        let device_length = self.candidate.len();
        match self.advance_loaded(event) {
            ExternalJournalLoadTransition::SubmitLower { request, suspended } => {
                ExternalJournalProbeTransition::SubmitLower { request, suspended }
            }
            ExternalJournalLoadTransition::Complete(result) => {
                ExternalJournalProbeTransition::Complete(result.and_then(|loaded| {
                    match loaded {
                        ExternalJournalLoad::Mismatch => Ok(ExternalJournalProbeOutcome::Mismatch),
                        ExternalJournalLoad::Match(_journal) => {
                            memory::try_box(ValidatedExternalJournal {
                                requirement,
                                device_length,
                            })
                            .map(ExternalJournalProbeOutcome::Match)
                        }
                    }
                }))
            }
        }
    }

    /// The mount reloads the cursor under its current ownership before replay admission.
    fn advance_loaded(
        mut self: Box<Self>,
        event: super::OperationEvent,
    ) -> ExternalJournalLoadTransition {
        let accepted = match event {
            super::OperationEvent::Admitted => Ok(()),
            super::OperationEvent::StorageCompleted(completion) => {
                self.candidate.complete(completion)
            }
            super::OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return ExternalJournalLoadTransition::Complete(Err(error));
        }
        let loaded = {
            let mut device = OperationDevice::new(&mut self.candidate);
            Journal::<LoadedJournal>::from_external_device(
                &mut device,
                self.requirement.journal_uuid,
                self.requirement.filesystem_uuid,
                self.requirement.home_space,
            )
        };
        match loaded {
            Err(Error::OperationSuspended) => match self.candidate.take_pending_request() {
                Ok(request) => ExternalJournalLoadTransition::SubmitLower {
                    request,
                    suspended: self,
                },
                Err(error) => ExternalJournalLoadTransition::Complete(Err(error)),
            },
            result => ExternalJournalLoadTransition::Complete(result),
        }
    }
}

/// A loaded cursor remains private to the active mount, never in a discovery token.
#[derive(Debug)]
enum ExternalJournalLoadTransition {
    /// This loader owns the exact candidate transcript across its next read.
    SubmitLower {
        /// Exact exclusive-candidate read.
        request: crate::StorageRequest,
        /// Unique parser and transcript continuation.
        suspended: Box<ExternalJournalProbeOperation>,
    },
    /// Current candidate cursor or independent mismatch/failure.
    Complete(Result<ExternalJournalLoad>),
}

/// Read-only primary-device probe. It grants no recovery or media-write authority.
#[derive(Debug)]
pub struct MountProbeOperation {
    /// The primary bytes retained for the selected mount, avoiding an identity reread race.
    filesystem: StorageTranscript,
}
/// Probe suspension or a consumed preparation that can accept exactly one mount policy.
#[derive(Debug)]
pub enum MountProbeTransition {
    /// Only reads can be produced before policy selection.
    SubmitLower {
        /// Owned primary-device read.
        request: crate::StorageRequest,
        /// Sole continuation for its completion.
        suspended: Box<MountProbeOperation>,
    },
    /// Primary magic and UUID were observed; policy selection precedes complete validation.
    Complete(Result<ProbedMount>),
}
/// Captured primary identity retained across UUID-scoped policy selection.
///
/// Its UUID identifies policy, not a healthy filesystem: a damaged primary may require journal
/// repair, and ordinary mount validation must finish before any mounted state is published.
#[derive(Debug)]
pub struct ProbedMount {
    /// Captured primary reads become the mount's sole bootstrap transcript.
    filesystem: StorageTranscript,
    /// UUID pinned before policy selection; journal recovery may not replace this identity.
    uuid: FilesystemUuid,
}
impl MountProbeOperation {
    /// Starts a primary probe without any permission to mutate storage.
    pub const fn new(length: DeviceLength) -> Self {
        Self {
            filesystem: StorageTranscript::new(StorageTarget::Filesystem, length),
        }
    }
    /// Consumes a probe event until another read or the policy-selection boundary.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: super::OperationEvent) -> MountProbeTransition {
        let accepted = match event {
            super::OperationEvent::Admitted => Ok(()),
            super::OperationEvent::StorageCompleted(completion) => {
                self.filesystem.complete(completion)
            }
            super::OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return MountProbeTransition::Complete(Err(error));
        }
        let result = {
            let mut device = OperationDevice::new(&mut self.filesystem);
            Superblock::probe_uuid(&mut device)
        };
        match result {
            Ok(uuid) => MountProbeTransition::Complete(Ok(ProbedMount {
                filesystem: self.filesystem,
                uuid,
            })),
            Err(Error::OperationSuspended) => match self.filesystem.take_pending_request() {
                Ok(request) => MountProbeTransition::SubmitLower {
                    request,
                    suspended: self,
                },
                Err(error) => MountProbeTransition::Complete(Err(error)),
            },
            Err(error) => MountProbeTransition::Complete(Err(error)),
        }
    }
}
impl ProbedMount {
    /// UUID used to pin the next-mount policy before recovery can accept any effect.
    pub const fn uuid(&self) -> FilesystemUuid {
        self.uuid
    }
    /// Consumes primary admission and fixes media authority for the entire mounted session.
    /// # Errors
    /// Rejects ownership placement or allocation before recovery can write storage.
    pub fn start(
        mut self,
        fscrypt_keys: FscryptKeySet,
        access: super::MountAccess,
        device_access: super::DeviceWriteAccess,
        owner: super::MmpOwner,
        now: super::MmpTime,
    ) -> Result<MountOperation> {
        let mount = owner.mount();
        if access == super::MountAccess::ReadWrite
            && device_access == super::DeviceWriteAccess::ReadOnly
        {
            return Err(Error::ReadOnlyFilesystem);
        }
        let primary = {
            let mut device = OperationDevice::new(&mut self.filesystem);
            match Superblock::read_for_mount(&mut device, access)? {
                PrimarySuperblockRead::Valid(primary) => primary,
                PrimarySuperblockRead::ChecksumInvalid(primary) => primary.recovery_bootstrap(),
            }
        };
        let mmp = primary.mmp();
        let ownership = match (mmp, access) {
            (
                _,
                super::MountAccess::ReadOnly {
                    recovery: super::ReadOnlyRecovery::Replay | super::ReadOnlyRecovery::NoLoad,
                },
            ) => MountOwnership::Unprotected,
            (Some(parameters), _) => MountOwnership::Observing(memory::try_box(
                super::MmpOperation::acquire(parameters, owner, super::MediaAccess::ReadOnly)?,
            )?),
            (None, _) => MountOwnership::Unprotected,
        };
        Ok(MountOperation {
            mount,
            ownership,
            mmp_parameters: mmp,
            primary_uuid: self.uuid,
            now,
            access,
            device_access,
            media_outcome: MountMediaOutcome::Unchanged,
            external_access: super::DeviceWriteAccess::ReadOnly,
            recovery: match access {
                super::MountAccess::ReadOnly {
                    recovery: super::ReadOnlyRecovery::Memory { limit },
                } => Some(super::recovery::RecoveryOverlay::new(limit)),
                _ => None,
            },
            filesystem: self.filesystem,
            external: None,
            fscrypt_keys,
            state: MountState::Resolving,
        })
    }
}

/// Physical recovery outcome, independent of a mount failure reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountMediaOutcome {
    /// No physical write or durability request was submitted.
    Unchanged,
    /// Acknowledged effects preceded failure; no filesystem was published.
    RecoveryIncomplete,
    /// An effect was submitted without an authenticated complete acknowledgement.
    OutcomeUnknown,
}

/// Terminal mount failure preserves effects independently of diagnostic classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountFailure {
    /// Reason used for diagnostics and recovery policy.
    pub reason: Error,
    /// Failure does not imply unchanged storage or permission to retry.
    pub media: MountMediaOutcome,
}

impl core::fmt::Display for MountFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "{} (mount media outcome: {:?})",
            self.reason, self.media
        )
    }
}

impl core::error::Error for MountFailure {}

/// One consuming transition of the mount operation.
#[derive(Debug)]
pub enum MountTransition {
    /// Direct ownership protocol transfer; no failed write may be blindly retried.
    SubmitOwnership {
        /// Complete uncached filesystem-device transfer.
        request: crate::StorageRequest,
        /// Sole mount continuation, including all provisional recovery state.
        suspended: Box<MountOperation>,
    },
    /// Independent media ownership observation requires a complete monotonic delay.
    WaitForTimer {
        /// Delay required before another ownership read can establish admission.
        seconds: u32,
        /// Sole timer continuation, retaining all mount and storage ownership.
        suspended: Box<MountOperation>,
    },
    /// Submit one owned lower request while the whole mount operation is suspended by value.
    SubmitLower {
        /// Request moved into the lower completion envelope.
        request: crate::StorageRequest,
        /// Mount state resumed only by the matching completion.
        suspended: Box<MountOperation>,
    },
    /// Driver must discover, exclusively reopen, and revalidate the named external journal.
    DiscoverExternalJournal {
        /// Exact filesystem-derived discovery requirement.
        requirement: ExternalJournalRequirement,
        /// Mount operation awaiting a matching validation token.
        suspended: Box<MountOperation>,
    },
    /// Mount terminated with either fully separated mounted state or a normal error.
    Complete(core::result::Result<Box<CompletedMount>, MountFailure>),
}

/// Internal progress returns to the executor before another phase runs. In particular,
/// journal admission and ownership completion must not nest metadata execution on the stack.
#[derive(Debug)]
enum MountStep {
    /// Sole operation owner returned to the iterative executor.
    Continue(Box<MountOperation>),
    /// Replay preparation runs after the mount state dispatcher releases its scratch frame.
    PrepareDeltas {
        /// Sole mount owner while replay advances.
        mount: Box<MountOperation>,
        /// Private replay state for the next pass.
        operation: Box<super::fast_commit::DeltaReplayOperation>,
        /// Device receiving the eventual journal checkpoint.
        journal_target: StorageTarget,
    },
    /// Session checkpoint preparation runs after the dispatcher releases its scratch frame.
    PrepareMarker {
        /// Sole mount owner while the marker is prepared.
        mount: Box<MountOperation>,
        /// Indexed metadata and journal authority for the next pass.
        indexed: Box<IndexedMount>,
    },
    /// Constructs the live session after the dispatcher releases its scratch frame.
    Publish {
        /// Owner of the mount lease and virtual recovery, if present.
        mount: Box<MountOperation>,
        /// Durable mount image and its reserved publication storage.
        recovered: UnpublishedMount,
    },
    /// External effect or terminal result; ownership effects bypass private replay.
    Yield(MountTransition),
}

/// Completion-driven journaled mount operation.
#[derive(Debug)]
pub struct MountOperation {
    /// Physical effect history, independent of virtual recovery.
    media_outcome: MountMediaOutcome,
    /// Physical external-journal availability, admitted only with its matching validation token.
    external_access: super::DeviceWriteAccess,
    /// Physical primary-device availability selected independently of mounted media authority.
    device_access: super::DeviceWriteAccess,
    /// One origin for physical ownership, committed epochs and all later grants.
    mount: MountIdentity,
    /// Independent ownership is established before journal replay and retained through publication.
    ownership: MountOwnership,
    /// Immutable placement selected before recovery; replay cannot substitute another ownership domain.
    mmp_parameters: Option<crate::disk_format::mmp::MmpParameters>,
    /// UUID that selected the mount policy before recovery; replay cannot substitute another policy domain.
    primary_uuid: FilesystemUuid,
    /// Host clock sampled at the current consuming event boundary.
    now: super::MmpTime,
    /// Media authority fixed before the first mount operation.
    access: super::MountAccess,
    /// Private replay destination. Writable bootstrap discards it before claiming ownership;
    /// read-only publication seals it into the epoch.
    recovery: Option<super::recovery::RecoveryOverlay>,
    /// Filesystem-device transcript used only for restartable metadata resolution.
    filesystem: StorageTranscript,
    /// Exclusive-device identity evidence; loaded journal cursors are always read afresh.
    external: Option<Box<ValidatedExternalJournal>>,
    /// Private key snapshot transferred into the first committed epoch at publication.
    fscrypt_keys: FscryptKeySet,
    /// Explicit mount and durability phase.
    state: MountState,
}

/// Media ownership cannot be reconstructed from the journal or a mount UUID.
#[derive(Debug)]
enum MountOwnership {
    /// The selected protocol requires no writable MMP claim.
    Unprotected,
    /// Initial write-free owner observation precedes metadata and device discovery.
    Observing(Box<super::MmpOperation>),
    /// Discovery may read metadata, but recovery effects still require a fresh writable acquisition.
    ReadyToClaim(super::MmpOwner),
    /// A lower request or monotonic timer owns the pending acquisition or renewal.
    Pending {
        /// Sole completion or timer continuation for the direct record protocol.
        operation: Box<super::MmpOperation>,
        /// Acquisition and renewal retain distinct I/O admission authority.
        authority: PendingMountOwnership,
    },
    /// Acknowledged media ownership; every later mutation requires freshness.
    Held(super::MmpLease),
}

/// The physical update continuation cannot independently extend a retained I/O window.
#[derive(Debug)]
enum PendingMountOwnership {
    /// Initial observation grants no filesystem-write authority.
    Observation,
    /// Acquisition has no pre-existing writable lease.
    Acquisition,
    /// Acknowledged prior validity remains bounded until its exact durable successor arrives.
    Renewal(super::MmpRenewingLease),
}

/// Internal mount phase with no independently inspectable flags.
#[derive(Debug)]
enum MountState {
    /// Journal and orphan recovery are complete; RO completion markers still need persistence.
    FinishingReadOnly(UnpublishedMount),
    /// Prepared home update has no journal-loading or ordinary mutation authority.
    ReadOnlyWrites {
        /// Fully private mounted state, published only after durability.
        recovered: UnpublishedMount,
        /// Complete preallocated home-write sequence.
        sequence: StorageRequestSequence<()>,
    },
    /// Only the exact lower completion can reveal the remaining RO completion writes.
    ReadOnlyPending {
        /// Retained private state.
        recovered: UnpublishedMount,
        /// Unique transfer continuation.
        pending: crate::PendingStorageTransfer<StorageRequestSequence<()>>,
    },
    /// Resolve the primary superblock and internal journal placement.
    Resolving,
    /// Await a core-minted token for the exact external-journal requirement.
    AwaitingExternal {
        /// Exact requirement that the exclusive candidate must satisfy.
        requirement: ExternalJournalRequirement,
    },
    /// Read the external journal afresh within the current mount-ownership phase.
    LoadingExternal {
        /// Validated bootstrap geometry; it cannot authorize effects before claim.
        primary: ResolvedPrimary,
        /// The exclusive candidate's private read continuation.
        operation: Box<ExternalJournalProbeOperation>,
    },
    /// Drive bounded journal recovery without a storage transcript.
    Recovering {
        /// Primary admission state whose checksum status selects ordinary or repair replay.
        primary: ResolvedPrimary,
        /// Device selected by the validated journal location.
        journal_target: StorageTarget,
        /// Consuming three-pass recovery operation.
        operation: Box<JournalRecoveryOperation>,
    },
    /// Journal replay repaired the primary block; strict revalidation must precede publication.
    VerifyingReplayedPrimary {
        /// Pending semantic replay remains owned until the fresh filesystem admits its operands.
        completion: JournalRecoveryCompletion,
        /// Device containing the journal.
        journal_target: StorageTarget,
    },
    /// Resolve and validate prospective images without granting write authority to its read phases.
    PreparingDeltas {
        /// Owns the program, original allocation evidence and candidate validation continuation.
        operation: Box<super::fast_commit::DeltaReplayOperation>,
        /// Physical journal device selected during admission.
        journal_target: StorageTarget,
    },
    /// Fully allocated full-commit conversion and home checkpoint requests.
    DeltaWrites {
        /// Only matching lower completions can advance this sequence.
        sequence: StorageRequestSequence<Journal<CleanJournal>>,
        /// Physical journal target retained for mount publication.
        journal_target: StorageTarget,
    },
    /// A submitted delta-conversion transfer remains owned even after cancellation.
    DeltaWritePending {
        /// Consuming continuation revealed by the exact transfer completion.
        pending: crate::PendingStorageTransfer<StorageRequestSequence<Journal<CleanJournal>>>,
        /// Physical journal target retained for mount publication.
        journal_target: StorageTarget,
    },
    /// Validate both persistent orphan trackers before granting write authority.
    ScanningOrphans(MountPublicationSeed),
    /// Build allocation ownership with validated admission for zero-link orphans.
    Indexing(ValidatedMountSeed),
    /// Prepare the marker image and all publication allocations before its first write.
    PreparingMarker(Box<IndexedMount>),
    /// The complete session image is journaled and checkpointed before publication.
    SessionWrites {
        /// Fully allocated mounted state, still private.
        recovered: UnpublishedMount,
        /// Log, commit, checkpoint and clean-journal durability.
        sequence: StorageRequestSequence<Journal<CleanJournal>>,
    },
    /// Only the matching lower completion can advance session publication.
    SessionPending {
        /// Fully allocated mounted state, still private.
        recovered: UnpublishedMount,
        /// Sole consuming continuation for this transfer.
        pending: crate::PendingStorageTransfer<StorageRequestSequence<Journal<CleanJournal>>>,
    },
    /// Resolve one bounded batch, with no published namespace or scheduler authority.
    RecoveringOrphans(UnpublishedMount),
    /// Immutable requests and their post-checkpoint state, all allocated before submission.
    OrphanWrites {
        /// Private mount and prospective queue state.
        mount: UnpublishedMount,
        /// Journal commit and home-checkpoint sequence.
        sequence: StorageRequestSequence<OrphanBatchCompletion>,
    },
    /// An effect-bearing batch cannot be canceled while one transfer is pending.
    OrphanWritePending {
        /// Mount state retained until the exact recovery write completes.
        mount: UnpublishedMount,
        /// Only a matching completion reveals the remaining recovery sequence.
        pending: crate::PendingStorageTransfer<StorageRequestSequence<OrphanBatchCompletion>>,
    },
    /// Selected recovery and required durability completed; the mount may be published.
    ReadyToPublish(UnpublishedMount),
}

/// Validated mount view awaiting any admitted recovery work and publication.
#[derive(Debug)]
struct MountPublicationSeed {
    /// Validated primary superblock state.
    superblock: Superblock,
    /// Admitted clean journal, absent when journal loading was suppressed or unnecessary.
    journal: Option<Journal<CleanJournal>>,
    /// Device containing the journal.
    journal_target: Option<StorageTarget>,
}

/// Validated orphan membership and resumable allocation ownership awaiting indexing.
#[derive(Debug)]
struct ValidatedMountSeed {
    /// Primary view and optional journal admitted for recovery.
    publication: MountPublicationSeed,
    /// Immutable membership, consumed only after allocation indexing completes.
    orphans: ValidatedOrphanInventory,
    /// Resumable mount-private ownership validation, retained across lower completions.
    index: Box<AllocationIndexBuild>,
}

/// Allocation-indexed metadata owned by mount recovery.
#[derive(Debug)]
struct IndexedMount {
    /// Working primary image, advanced by recovery and the session marker.
    superblock: Superblock,
    /// Prospective queue state remains behind each pending orphan checkpoint.
    orphans: OrphanRecoveryQueue,
    /// Admitted journal for checkpointing and mutation.
    journal: Option<Journal<CleanJournal>>,
    /// Device containing the admitted journal.
    journal_target: Option<StorageTarget>,
    /// Fully validated committed allocation ownership.
    clusters: Option<ClusterReferenceIndex>,
}

/// Mount-private state with preallocated storage for its eventual publication.
#[derive(Debug)]
struct UnpublishedMount {
    /// Same heap allocation used during marker preparation.
    image: Box<IndexedMount>,
    /// Reserved before submitting the session marker; initialized only on success.
    destination: Box<MaybeUninit<CompletedMount>>,
}

/// Journal resolution result before recovery begins.
#[derive(Debug)]
enum JournalResolution {
    /// Validated raw home view; no journal was opened or interpreted.
    Unloaded(Superblock),
    /// A concrete internal journal is ready for ownership/recovery admission.
    Loaded {
        /// Valid primary metadata or authenticated repair image.
        primary: ResolvedPrimary,
        /// Current journal cursor.
        journal: Journal<LoadedJournal>,
        /// Device containing this cursor.
        journal_target: StorageTarget,
    },
    /// External placement needs either host discovery or a fresh exclusive-device read.
    External {
        /// Validated bootstrap metadata, with repair authority still withheld.
        primary: ResolvedPrimary,
        /// Exact candidate identity and filesystem home space.
        requirement: ExternalJournalRequirement,
    },
}

/// Primary-superblock authority retained through journal discovery and recovery.
#[derive(Clone, Copy, Debug)]
enum ResolvedPrimary {
    /// The primary checksum and every structural field are valid.
    Valid(Superblock),
    /// Only recovery-bootstrap fields are admitted; journal replay must replace the primary block.
    JournalRepairRequired(ChecksumInvalidSuperblock),
}

impl ResolvedPrimary {
    /// Returns geometry and journal placement for the recovery bootstrap boundary only.
    const fn recovery_bootstrap(self) -> Superblock {
        match self {
            Self::Valid(superblock) => superblock,
            Self::JournalRepairRequired(provisional) => provisional.recovery_bootstrap(),
        }
    }

    /// Constructs recovery with authority appropriate to the primary checksum state.
    /// # Errors
    ///
    /// Returns an error when recovery buffers cannot be allocated or provisional primary metadata
    /// has no dirty journal from which to establish repair authority.
    fn begin_recovery(
        self,
        journal: Journal<LoadedJournal>,
        access: super::MountAccess,
    ) -> Result<Box<JournalRecoveryOperation>> {
        let operation = match self {
            Self::Valid(superblock) => {
                if matches!(
                    access,
                    super::MountAccess::ReadOnly {
                        recovery: super::ReadOnlyRecovery::Replay
                    }
                ) {
                    JournalRecoveryOperation::read_only_mount(journal, superblock.recovery_state())
                } else {
                    JournalRecoveryOperation::new(journal, superblock.recovery_state())
                }
            }
            Self::JournalRepairRequired(_) => JournalRecoveryOperation::repairing_primary(journal),
        }?;
        memory::try_box(operation)
    }
}

impl MountOperation {
    /// Terminates without discarding accepted recovery effects.
    fn fail(self: Box<Self>, reason: Error) -> MountTransition {
        MountTransition::Complete(Err(MountFailure {
            reason,
            media: self.media_outcome,
        }))
    }

    /// Native external handle authority; virtual replay needs only read access.
    pub const fn external_write_access(&self) -> super::DeviceWriteAccess {
        match self.access {
            super::MountAccess::ReadOnly {
                recovery: super::ReadOnlyRecovery::Memory { .. } | super::ReadOnlyRecovery::NoLoad,
            } => super::DeviceWriteAccess::ReadOnly,
            _ => self.device_access,
        }
    }
    /// Physical MMP write width, needed by the host only for writable sessions.
    pub const fn ownership_block_size(&self) -> Option<BlockSize> {
        match (self.access, self.mmp_parameters) {
            (super::MountAccess::ReadWrite, Some(parameters)) => Some(parameters.bytes),
            _ => None,
        }
    }
    /// Observes the bound retained by the suspended mount for host-side lower admission.
    /// This observation grants no recovery, ownership-update or publication authority.
    pub fn submission_deadline(&self) -> Option<super::MmpDeadline> {
        match &self.ownership {
            MountOwnership::Held(lease) => Some(lease.deadline()),
            MountOwnership::Observing(operation) | MountOwnership::Pending { operation, .. } => {
                operation.submission_deadline()
            }
            MountOwnership::Unprotected | MountOwnership::ReadyToClaim(_) => None,
        }
    }

    /// Attaches a token minted by exclusive core validation and resumes external recovery.
    #[must_use]
    pub fn attach_external_journal(
        mut self: Box<Self>,
        validated: Box<ValidatedExternalJournal>,
        device_access: super::DeviceWriteAccess,
        now: super::MmpTime,
    ) -> MountTransition {
        self.now = now;
        let MountState::AwaitingExternal { requirement } = self.state else {
            return self.fail(Error::DeviceIo);
        };
        if requirement != validated.requirement {
            return self.fail(Error::UnsupportedJournal);
        }
        self.external = Some(validated);
        self.external_access = device_access;
        self.filesystem = StorageTranscript::new(StorageTarget::Filesystem, self.filesystem.len());
        self.state = MountState::Resolving;
        Self::drive(MountStep::Continue(self))
    }

    /// Consumes one concrete event and runs until the next lower request or terminal result.
    /// The executor must drain lower ownership before cancellation. If it withholds a completed
    /// effect's acknowledgement, cancellation retains an uncertain media outcome and cannot retry.
    #[must_use]
    pub fn advance(
        mut self: Box<Self>,
        event: super::OperationEvent,
        now: super::MmpTime,
    ) -> MountTransition {
        self.now = now;
        let ownership = core::mem::replace(&mut self.ownership, MountOwnership::Unprotected);
        match ownership {
            MountOwnership::Observing(operation) => {
                let event = match event {
                    super::OperationEvent::Admitted => super::MmpEvent::Start,
                    super::OperationEvent::CancelRequested => super::MmpEvent::Cancel,
                    _ => return self.fail(Error::DeviceIo),
                };
                return Self::drive(self.accept_ownership(
                    PendingMountOwnership::Observation,
                    operation.advance(event, now),
                ));
            }
            MountOwnership::Pending {
                operation,
                authority,
            } => {
                let event = match event {
                    super::OperationEvent::StorageCompleted(completion) => {
                        super::MmpEvent::StorageCompleted(completion)
                    }
                    super::OperationEvent::TimerElapsed => super::MmpEvent::Elapsed,
                    super::OperationEvent::CancelRequested => super::MmpEvent::Cancel,
                    _ => return self.fail(Error::DeviceIo),
                };
                return Self::drive(
                    self.accept_ownership(authority, operation.advance(event, now)),
                );
            }
            ownership => self.ownership = ownership,
        }
        let accepted = match event {
            super::OperationEvent::Admitted => match &self.state {
                MountState::Resolving => Ok(()),
                _ => Err(Error::DeviceIo),
            },
            super::OperationEvent::StorageCompleted(completion) => {
                self.accept_completion(completion)
            }
            super::OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return self.fail(error);
        }
        Self::drive(MountStep::Continue(self))
    }

    /// Ownership effects bypass the recovery overlay and every metadata transcript.
    fn accept_ownership(
        mut self: Box<Self>,
        authority: PendingMountOwnership,
        transition: super::MmpTransition,
    ) -> MountStep {
        match transition {
            super::MmpTransition::SubmitLower { request, suspended } => {
                if !matches!(request, crate::StorageRequest::Read { .. }) {
                    self.media_outcome = MountMediaOutcome::OutcomeUnknown;
                }
                self.ownership = MountOwnership::Pending {
                    operation: suspended,
                    authority,
                };
                MountStep::Yield(MountTransition::SubmitOwnership {
                    request,
                    suspended: self,
                })
            }
            super::MmpTransition::Wait { seconds, suspended } => {
                self.ownership = MountOwnership::Pending {
                    operation: suspended,
                    authority,
                };
                MountStep::Yield(MountTransition::WaitForTimer {
                    seconds,
                    suspended: self,
                })
            }
            super::MmpTransition::Complete(Ok(completion)) => {
                if self.media_outcome == MountMediaOutcome::OutcomeUnknown {
                    self.media_outcome = MountMediaOutcome::RecoveryIncomplete;
                }
                self.ownership = match (authority, completion) {
                    (PendingMountOwnership::Acquisition, super::MmpCompletion::Acquired(lease)) => {
                        MountOwnership::Held(lease)
                    }
                    (PendingMountOwnership::Observation, super::MmpCompletion::Observed(owner)) => {
                        if self.access.media_access() == super::MediaAccess::ReadWrite {
                            MountOwnership::ReadyToClaim(owner)
                        } else {
                            MountOwnership::Unprotected
                        }
                    }
                    (
                        PendingMountOwnership::Renewal(pending),
                        super::MmpCompletion::Renewed(renewal),
                    ) => match pending.complete(renewal, self.now) {
                        Ok(lease) => MountOwnership::Held(lease),
                        Err((error, _renewal)) => return MountStep::Yield(self.fail(error)),
                    },
                    _ => return MountStep::Yield(self.fail(Error::DeviceIo)),
                };
                MountStep::Continue(self)
            }
            super::MmpTransition::Complete(Err(failure)) => {
                MountStep::Yield(self.fail(failure.reason))
            }
        }
    }

    /// Routes one completion exclusively to the phase that submitted it.
    /// # Errors
    ///
    /// Returns an error for a failed, mismatched, short, or phase-inconsistent completion.
    fn accept_completion(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        let completion = if let Some(recovery) = &self.recovery {
            completion.apply_overlay(recovery)?
        } else {
            completion
        };
        match core::mem::replace(&mut self.state, MountState::Resolving) {
            MountState::FinishingReadOnly(recovered) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::FinishingReadOnly(recovered);
            }
            MountState::ReadOnlyPending { recovered, pending } => {
                self.state = MountState::ReadOnlyWrites {
                    recovered,
                    sequence: pending.complete(completion)?,
                };
            }
            MountState::Resolving => {
                self.filesystem.complete(completion)?;
                self.state = MountState::Resolving;
            }
            MountState::LoadingExternal {
                primary,
                mut operation,
            } => {
                operation.candidate.complete(completion)?;
                self.state = MountState::LoadingExternal { primary, operation };
            }
            MountState::ScanningOrphans(publication) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::ScanningOrphans(publication);
            }
            MountState::RecoveringOrphans(mount) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::RecoveringOrphans(mount);
            }
            MountState::OrphanWritePending { mount, pending } => {
                let sequence = pending.complete(completion)?;
                self.state = MountState::OrphanWrites { mount, sequence };
            }
            MountState::Indexing(publication) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::Indexing(publication);
            }
            MountState::PreparingMarker(indexed) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::PreparingMarker(indexed);
            }
            MountState::VerifyingReplayedPrimary {
                completion: recovered,
                journal_target,
            } => {
                self.filesystem.complete(completion)?;
                self.state = MountState::VerifyingReplayedPrimary {
                    completion: recovered,
                    journal_target,
                };
            }
            MountState::PreparingDeltas {
                mut operation,
                journal_target,
            } => {
                operation.complete(completion)?;
                self.state = MountState::PreparingDeltas {
                    operation,
                    journal_target,
                };
            }
            MountState::DeltaWritePending {
                pending,
                journal_target,
            } => {
                self.state = MountState::DeltaWrites {
                    sequence: pending.complete(completion)?,
                    journal_target,
                };
            }
            MountState::Recovering {
                primary,
                journal_target,
                mut operation,
            } => {
                operation.complete(completion)?;
                self.state = MountState::Recovering {
                    primary,
                    journal_target,
                    operation,
                };
            }
            MountState::SessionPending { recovered, pending } => {
                self.state = MountState::SessionWrites {
                    recovered,
                    sequence: pending.complete(completion)?,
                };
            }
            state @ (MountState::AwaitingExternal { .. }
            | MountState::ReadOnlyWrites { .. }
            | MountState::SessionWrites { .. }
            | MountState::OrphanWrites { .. }
            | MountState::DeltaWrites { .. }
            | MountState::ReadyToPublish(_)) => {
                self.state = state;
                return Err(Error::DeviceIo);
            }
        }
        if self.media_outcome == MountMediaOutcome::OutcomeUnknown {
            self.media_outcome = MountMediaOutcome::RecoveryIncomplete;
        }
        Ok(())
    }

    /// Routes private replay through its bounded overlay and transfers admitted physical requests.
    fn drive(mut step: MountStep) -> MountTransition {
        loop {
            let transition = match step {
                MountStep::Continue(operation) => {
                    step = operation.drive_step();
                    continue;
                }
                MountStep::PrepareDeltas {
                    mount,
                    operation,
                    journal_target,
                } => {
                    step = mount.prepare_deltas(operation, journal_target);
                    continue;
                }
                MountStep::PrepareMarker { mount, indexed } => {
                    step = mount.prepare_marker(indexed);
                    continue;
                }
                MountStep::Publish { mount, recovered } => return mount.publish_mount(recovered),
                MountStep::Yield(transition) => transition,
            };
            let MountTransition::SubmitLower {
                mut request,
                mut suspended,
            } = transition
            else {
                return transition;
            };
            let Some(recovery) = &mut suspended.recovery else {
                if !matches!(request, crate::StorageRequest::Read { .. }) {
                    suspended.media_outcome = MountMediaOutcome::OutcomeUnknown;
                }
                return MountTransition::SubmitLower { request, suspended };
            };
            let result = match &mut request {
                crate::StorageRequest::Read {
                    target,
                    offset,
                    buffer,
                } => match recovery.read(*target, *offset, buffer) {
                    Ok(true) => Ok(()),
                    Ok(false) => return MountTransition::SubmitLower { request, suspended },
                    Err(error) => Err(error),
                },
                crate::StorageRequest::Write {
                    target,
                    offset,
                    buffer,
                } => recovery.write(*target, *offset, buffer),
                crate::StorageRequest::Flush { .. } => Ok(()),
            };
            if let Err(error) = result {
                return suspended.fail(error);
            }
            let information = request.byte_count();
            let completion = crate::StorageCompletion::success(
                crate::CompletedStorageTransfer::from_request(request),
                information,
            );
            if let Err(error) = suspended.accept_completion(completion) {
                return suspended.fail(error);
            }
            step = MountStep::Continue(suspended);
        }
    }

    /// Dispatches phases without merging their metadata scratch into one resident kernel frame.
    /// Each phase returns before the iterative executor advances another one.
    #[inline(never)]
    fn drive_step(mut self: Box<Self>) -> MountStep {
        let ownership = core::mem::replace(&mut self.ownership, MountOwnership::Unprotected);
        match ownership {
            MountOwnership::Held(lease) => {
                if let Err(error) = lease.authorize(self.now) {
                    return MountStep::Yield(self.fail(error));
                }
                if lease.renewal_due(self.now) {
                    let now = self.now;
                    let (pending, operation) = match lease.renew(now) {
                        Ok(update) => update,
                        Err(error) => return MountStep::Yield(self.fail(error)),
                    };
                    let operation = match memory::try_box(operation) {
                        Ok(operation) => operation,
                        Err(error) => return MountStep::Yield(self.fail(error)),
                    };
                    return self.accept_ownership(
                        PendingMountOwnership::Renewal(pending),
                        operation.advance(super::MmpEvent::Start, now),
                    );
                }
                self.ownership = MountOwnership::Held(lease);
            }
            ownership @ (MountOwnership::Unprotected | MountOwnership::ReadyToClaim(_)) => {
                self.ownership = ownership;
            }
            _ => return MountStep::Yield(self.fail(Error::DeviceIo)),
        }

        loop {
            match core::mem::replace(&mut self.state, MountState::Resolving) {
                MountState::FinishingReadOnly(recovered) => {
                    return self.finish_read_only(recovered);
                }
                MountState::ReadOnlyWrites {
                    recovered,
                    sequence,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.state = MountState::ReadOnlyPending {
                            recovered,
                            pending: suspended,
                        };
                        return MountStep::Yield(MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        });
                    }
                    StorageRequestSequenceStep::Finished(()) => {
                        self.state = MountState::ReadyToPublish(recovered);
                    }
                },
                MountState::ReadOnlyPending { .. } => {
                    return MountStep::Yield(self.fail(Error::DeviceIo));
                }
                MountState::Resolving => match self.resolve_journal() {
                    Ok(JournalResolution::Unloaded(superblock)) => {
                        self.state = MountState::ScanningOrphans(MountPublicationSeed {
                            superblock,
                            journal: None,
                            journal_target: None,
                        });
                    }
                    Ok(JournalResolution::Loaded {
                        primary,
                        journal,
                        journal_target,
                    }) => {
                        return self.admit_journal(primary, journal, journal_target);
                    }
                    Ok(JournalResolution::External {
                        primary,
                        requirement,
                    }) => {
                        if let Some(external) = &self.external {
                            if external.requirement != requirement {
                                return MountStep::Yield(self.fail(Error::UnsupportedJournal));
                            }
                            let operation =
                                match memory::try_box(ExternalJournalProbeOperation::new(
                                    requirement,
                                    external.device_length,
                                )) {
                                    Ok(operation) => operation,
                                    Err(error) => return MountStep::Yield(self.fail(error)),
                                };
                            self.state = MountState::LoadingExternal { primary, operation };
                        } else {
                            self.state = MountState::AwaitingExternal { requirement };
                            return MountStep::Yield(MountTransition::DiscoverExternalJournal {
                                requirement,
                                suspended: self,
                            });
                        }
                    }
                    Err(Error::OperationSuspended) => {
                        self.state = MountState::Resolving;
                        return self.submit_pending_read();
                    }
                    Err(error) => return MountStep::Yield(self.fail(error)),
                },
                MountState::AwaitingExternal { requirement } => {
                    self.state = MountState::AwaitingExternal { requirement };
                    return MountStep::Yield(MountTransition::DiscoverExternalJournal {
                        requirement,
                        suspended: self,
                    });
                }
                MountState::LoadingExternal { primary, operation } => {
                    match operation.advance_loaded(super::OperationEvent::Admitted) {
                        ExternalJournalLoadTransition::SubmitLower { request, suspended } => {
                            self.state = MountState::LoadingExternal {
                                primary,
                                operation: suspended,
                            };
                            return MountStep::Yield(MountTransition::SubmitLower {
                                request,
                                suspended: self,
                            });
                        }
                        ExternalJournalLoadTransition::Complete(Ok(
                            ExternalJournalLoad::Match(journal),
                        )) => {
                            return self.admit_journal(
                                primary,
                                journal,
                                StorageTarget::ExternalJournal,
                            );
                        }
                        ExternalJournalLoadTransition::Complete(Ok(
                            ExternalJournalLoad::Mismatch,
                        )) => {
                            return MountStep::Yield(self.fail(Error::UnsupportedJournal));
                        }
                        ExternalJournalLoadTransition::Complete(Err(error)) => {
                            return MountStep::Yield(self.fail(error));
                        }
                    }
                }
                MountState::Recovering {
                    primary,
                    journal_target,
                    mut operation,
                } => match operation.next_request() {
                    Ok(Some(request)) => {
                        self.state = MountState::Recovering {
                            primary,
                            journal_target,
                            operation,
                        };
                        return MountStep::Yield(MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        });
                    }
                    Ok(None) => match (*operation).into_recovered() {
                        Ok(completion) => {
                            let filesystem_length = self.filesystem.len();
                            self.filesystem = StorageTranscript::new(
                                StorageTarget::Filesystem,
                                filesystem_length,
                            );
                            self.state = MountState::VerifyingReplayedPrimary {
                                completion,
                                journal_target,
                            };
                        }
                        Err(error) => return MountStep::Yield(self.fail(error)),
                    },
                    Err(error) => return MountStep::Yield(self.fail(error)),
                },
                MountState::VerifyingReplayedPrimary {
                    completion,
                    journal_target,
                } => {
                    return self.verify_replayed_primary(completion, journal_target);
                }
                MountState::PreparingDeltas {
                    operation,
                    journal_target,
                } => {
                    return MountStep::PrepareDeltas {
                        mount: self,
                        operation,
                        journal_target,
                    };
                }
                MountState::DeltaWrites {
                    sequence,
                    journal_target,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.state = MountState::DeltaWritePending {
                            pending: suspended,
                            journal_target,
                        };
                        return MountStep::Yield(MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        });
                    }
                    StorageRequestSequenceStep::Finished(journal) => {
                        self.filesystem = StorageTranscript::new(
                            StorageTarget::Filesystem,
                            self.filesystem.len(),
                        );
                        self.state = MountState::VerifyingReplayedPrimary {
                            completion: JournalRecoveryCompletion::Clean(journal),
                            journal_target,
                        };
                    }
                },
                MountState::DeltaWritePending { .. } => {
                    return MountStep::Yield(self.fail(Error::DeviceIo));
                }
                MountState::ScanningOrphans(publication) => {
                    return self.scan_orphans(publication);
                }
                MountState::Indexing(validated) => {
                    return self.index_allocations(validated);
                }
                MountState::PreparingMarker(indexed) => {
                    return MountStep::PrepareMarker {
                        mount: self,
                        indexed,
                    };
                }
                MountState::SessionWrites {
                    mut recovered,
                    sequence,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.state = MountState::SessionPending {
                            recovered,
                            pending: suspended,
                        };
                        return MountStep::Yield(MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        });
                    }
                    StorageRequestSequenceStep::Finished(journal) => {
                        recovered.image.journal = Some(journal);
                        self.filesystem = StorageTranscript::new(
                            StorageTarget::Filesystem,
                            self.filesystem.len(),
                        );
                        self.state = MountState::RecoveringOrphans(recovered);
                    }
                },
                MountState::SessionPending { .. } => {
                    return MountStep::Yield(self.fail(Error::DeviceIo));
                }
                MountState::RecoveringOrphans(mount) => {
                    return self.recover_orphans(mount);
                }
                MountState::OrphanWrites {
                    mut mount,
                    sequence,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.state = MountState::OrphanWritePending {
                            mount,
                            pending: suspended,
                        };
                        return MountStep::Yield(MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        });
                    }
                    StorageRequestSequenceStep::Finished(completion) => {
                        mount.image.superblock = completion.superblock;
                        mount.image.clusters = Some(completion.clusters);
                        mount.image.journal = completion.journal;
                        self.filesystem = StorageTranscript::new(
                            StorageTarget::Filesystem,
                            self.filesystem.len(),
                        );
                        self.state = MountState::RecoveringOrphans(mount);
                    }
                },
                MountState::OrphanWritePending { .. } => {
                    return MountStep::Yield(self.fail(Error::DeviceIo));
                }
                MountState::ReadyToPublish(recovered) => {
                    return MountStep::Publish {
                        mount: self,
                        recovered,
                    };
                }
            }
        }
    }

    /// Seals the recovery view and initializes the sole live session after all required effects.
    #[inline(never)]
    fn publish_mount(mut self: Box<Self>, recovered: UnpublishedMount) -> MountTransition {
        let mmp = match core::mem::replace(&mut self.ownership, MountOwnership::Unprotected) {
            MountOwnership::Held(lease) => Some(lease),
            MountOwnership::Unprotected => None,
            _ => return self.fail(Error::DeviceIo),
        };
        let recovery = match self
            .recovery
            .take()
            .map(super::recovery::RecoveryOverlay::seal)
            .transpose()
        {
            Ok(recovery) => recovery,
            Err(error) => return self.fail(error),
        };
        let IndexedMount {
            superblock,
            journal,
            journal_target,
            clusters,
            orphans: _,
        } = *recovered.image;
        let access = self.access.media_access();
        let (journal, clusters) = match access {
            super::MediaAccess::ReadOnly => (None, None),
            super::MediaAccess::ReadWrite => (journal, clusters),
        };
        let profile = MountedProfile::new(
            &self.mount,
            superblock,
            self.filesystem.len(),
            journal_target,
            access,
        );
        let epoch = CommittedEpoch::initial(
            superblock,
            self.fscrypt_keys,
            clusters,
            self.access,
            self.mount,
            recovery,
        );
        let coordinator = MutationCoordinatorState::new(journal, &epoch);
        MountTransition::Complete(Ok(Box::write(
            recovered.destination,
            CompletedMount {
                profile,
                epoch,
                coordinator,
                mmp,
            },
        )))
    }

    /// Prepares the read-only completion images without retaining their scratch in other phases.
    #[inline(never)]
    fn finish_read_only(mut self: Box<Self>, mut recovered: UnpublishedMount) -> MountStep {
        let result = (|| {
            let mut device = OperationDevice::new(&mut self.filesystem);
            let mut raw = [0_u8; 1024];
            device.read_exact_at(ByteOffset::new(1024), &mut raw)?;
            let superblock = Superblock::parse_read_only(&raw)?;
            let mut view = EpochReadView::recovery(device, superblock, &self.fscrypt_keys, None);
            if !ValidatedOrphanInventory::observe_file(&mut view)? {
                return Err(Error::InvalidOrphanTracking);
            }
            let mut device = OperationDevice::new(&mut self.filesystem);
            let Some(raw) =
                Superblock::prepare_read_only_completion(&mut device, self.now.unix_seconds())?
            else {
                return Ok(None);
            };
            let superblock = Superblock::parse_read_only(&raw)?;
            let images = prepare_primary_images(&mut device, &raw, superblock.block_size())?;
            let sequence =
                StorageRequestSequence::home_updates(images, superblock.block_size(), ())?;
            Ok(Some((superblock, sequence)))
        })();
        match result {
            Ok(Some((superblock, sequence))) => {
                recovered.image.superblock = superblock;
                self.state = MountState::ReadOnlyWrites {
                    recovered,
                    sequence,
                };
            }
            Ok(None) => self.state = MountState::ReadyToPublish(recovered),
            Err(Error::OperationSuspended) => {
                self.state = MountState::FinishingReadOnly(recovered);
                return self.submit_pending_read();
            }
            Err(error) => return MountStep::Yield(self.fail(error)),
        }
        MountStep::Continue(self)
    }

    /// Validates the recovered primary before selecting orphan or delta recovery.
    #[inline(never)]
    fn verify_replayed_primary(
        mut self: Box<Self>,
        completion: JournalRecoveryCompletion,
        journal_target: StorageTarget,
    ) -> MountStep {
        let primary = {
            let mut filesystem = OperationDevice::new(&mut self.filesystem);
            Superblock::read_for_mount(&mut filesystem, self.access)
        };
        match primary {
            Ok(PrimarySuperblockRead::Valid(superblock)) => {
                if superblock.mmp() != self.mmp_parameters || superblock.uuid() != self.primary_uuid
                {
                    return MountStep::Yield(self.fail(Error::MmpCorrupt));
                }
                if matches!(self.ownership, MountOwnership::ReadyToClaim(_)) {
                    return self.claim_ownership();
                }
                self.state = match completion {
                    JournalRecoveryCompletion::Clean(journal) => {
                        MountState::ScanningOrphans(MountPublicationSeed {
                            superblock,
                            journal: Some(journal),
                            journal_target: Some(journal_target),
                        })
                    }
                    JournalRecoveryCompletion::Deltas(seed) => {
                        let operation = match super::fast_commit::DeltaReplayOperation::new(
                            self.filesystem.len(),
                            superblock,
                            seed,
                        )
                        .and_then(memory::try_box)
                        {
                            Ok(operation) => operation,
                            Err(error) => {
                                return MountStep::Yield(self.fail(error));
                            }
                        };
                        MountState::PreparingDeltas {
                            operation,
                            journal_target,
                        }
                    }
                };
            }
            Ok(PrimarySuperblockRead::ChecksumInvalid(_)) => {
                return MountStep::Yield(self.fail(Error::ChecksumMismatch));
            }
            Err(Error::OperationSuspended) => {
                self.state = MountState::VerifyingReplayedPrimary {
                    completion,
                    journal_target,
                };
                return self.submit_pending_read();
            }
            Err(error) => return MountStep::Yield(self.fail(error)),
        }
        MountStep::Continue(self)
    }

    /// Resolves delta recovery with a frame independent of ordinary mount phases.
    #[inline(never)]
    fn prepare_deltas(
        mut self: Box<Self>,
        mut operation: Box<super::fast_commit::DeltaReplayOperation>,
        journal_target: StorageTarget,
    ) -> MountStep {
        match operation.next_request(&self.fscrypt_keys) {
            Ok(Some(request)) => {
                self.state = MountState::PreparingDeltas {
                    operation,
                    journal_target,
                };
                return MountStep::Yield(MountTransition::SubmitLower {
                    request,
                    suspended: self,
                });
            }
            Ok(None) => match (*operation).into_sequence() {
                Ok(sequence) => {
                    self.state = MountState::DeltaWrites {
                        sequence,
                        journal_target,
                    }
                }
                Err(error) => return MountStep::Yield(self.fail(error)),
            },
            Err(error) => return MountStep::Yield(self.fail(error)),
        }
        MountStep::Continue(self)
    }

    /// Validates persistent orphan membership before allocation indexing.
    #[inline(never)]
    fn scan_orphans(mut self: Box<Self>, publication: MountPublicationSeed) -> MountStep {
        let result = {
            let device = OperationDevice::new(&mut self.filesystem);
            let mut volume =
                EpochReadView::recovery(device, publication.superblock, &self.fscrypt_keys, None);
            if self.access == super::MountAccess::ReadWrite
                || self.recovery.is_some()
                || (self.device_access == super::DeviceWriteAccess::Writable
                    && publication.superblock.permits_orphan_cleanup())
            {
                ValidatedOrphanInventory::load(&mut volume)
            } else {
                ValidatedOrphanInventory::observe_file(&mut volume)
                    .map(|_empty| ValidatedOrphanInventory::empty())
            }
        };
        match result {
            Ok(orphans) => {
                if !orphans.is_empty()
                    && let Some(journal) = &publication.journal
                    && let Err(error) = journal.require_metadata_capacity(
                        ORPHAN_METADATA_BUDGET,
                        publication.superblock.block_size(),
                    )
                {
                    return MountStep::Yield(self.fail(error));
                }
                if self.access.media_access() == super::MediaAccess::ReadOnly && orphans.is_empty()
                {
                    return self.begin_marker_preparation(publication, orphans, None);
                }
                let index = match memory::try_box(AllocationIndexBuild::new()) {
                    Ok(index) => index,
                    Err(error) => return MountStep::Yield(self.fail(error)),
                };
                self.state = MountState::Indexing(ValidatedMountSeed {
                    publication,
                    orphans,
                    index,
                });
            }
            Err(Error::OperationSuspended) => {
                self.state = MountState::ScanningOrphans(publication);
                return self.submit_pending_read();
            }
            Err(error) => return MountStep::Yield(self.fail(error)),
        }
        MountStep::Continue(self)
    }

    /// Builds allocation ownership from the validated orphan inventory.
    #[inline(never)]
    fn index_allocations(mut self: Box<Self>, mut validated: ValidatedMountSeed) -> MountStep {
        let clusters = validated.index.advance(
            &mut self.filesystem,
            &validated.publication.superblock,
            &validated.orphans,
        );
        match clusters {
            Ok(clusters) => self.begin_marker_preparation(
                validated.publication,
                validated.orphans,
                Some(clusters),
            ),
            Err(Error::OperationSuspended) => {
                self.state = MountState::Indexing(validated);
                self.submit_pending_read()
            }
            Err(error) => MountStep::Yield(self.fail(error)),
        }
    }

    /// Retains only the inputs needed after indexing. The preparation and any read suspension
    /// transfer this same allocation so the executor's continuation stays small.
    fn begin_marker_preparation(
        mut self: Box<Self>,
        publication: MountPublicationSeed,
        orphans: ValidatedOrphanInventory,
        clusters: Option<ClusterReferenceIndex>,
    ) -> MountStep {
        let indexed = match memory::try_box(IndexedMount {
            superblock: publication.superblock,
            orphans: orphans.into_queue(),
            journal: publication.journal,
            journal_target: publication.journal_target,
            clusters,
        }) {
            Ok(indexed) => indexed,
            Err(error) => return MountStep::Yield(self.fail(error)),
        };
        self.state = MountState::PreparingMarker(indexed);
        MountStep::Continue(self)
    }

    /// Constructs the session marker and unpublished mount within this phase's stack frame.
    #[inline(never)]
    fn prepare_marker(mut self: Box<Self>, mut indexed: Box<IndexedMount>) -> MountStep {
        let raw = {
            let mut filesystem = OperationDevice::new(&mut self.filesystem);
            match self.access {
                super::MountAccess::ReadWrite => Superblock::prepare_write_session(
                    &mut filesystem,
                    WriteSessionState::Active,
                    self.now.unix_seconds(),
                ),
                super::MountAccess::ReadOnly { .. } => {
                    let mut raw = [0_u8; 1024];
                    filesystem
                        .read_exact_at(ByteOffset::new(1024), &mut raw)
                        .map(|()| raw)
                }
            }
        };
        match raw {
            Ok(raw) => {
                let marked = match if self.access == super::MountAccess::ReadWrite {
                    Superblock::parse_read_write(&raw)
                } else {
                    Superblock::parse_read_only(&raw)
                } {
                    Ok(marked)
                        if marked.mmp() == self.mmp_parameters
                            && marked.uuid() == self.primary_uuid =>
                    {
                        marked
                    }
                    Ok(_) => return MountStep::Yield(self.fail(Error::MmpCorrupt)),
                    Err(error) => return MountStep::Yield(self.fail(error)),
                };
                let sequence = if matches!(self.access, super::MountAccess::ReadWrite) {
                    let Some(journal) = &indexed.journal else {
                        return MountStep::Yield(self.fail(Error::JournalCorrupt));
                    };
                    let mut device = OperationDevice::new(&mut self.filesystem);
                    match prepare_session_checkpoint(
                        &mut device,
                        &raw,
                        marked.block_size(),
                        journal,
                        &[],
                    ) {
                        Ok(sequence) => Some(sequence),
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::PreparingMarker(indexed);
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountStep::Yield(self.fail(error)),
                    }
                } else {
                    None
                };
                let destination = match Box::try_new_uninit() {
                    Ok(destination) => destination,
                    Err(_) => return MountStep::Yield(self.fail(Error::OutOfMemory)),
                };
                indexed.superblock = marked;
                if sequence.is_some() {
                    // The submitted sequence owns the next usable journal cursor.
                    indexed.journal = None;
                }
                let recovered = UnpublishedMount {
                    image: indexed,
                    destination,
                };
                self.state = match sequence {
                    Some(sequence) => MountState::SessionWrites {
                        recovered,
                        sequence,
                    },
                    None => MountState::RecoveringOrphans(recovered),
                };
            }
            Err(Error::OperationSuspended) => {
                self.state = MountState::PreparingMarker(indexed);
                return self.submit_pending_read();
            }
            Err(error) => return MountStep::Yield(self.fail(error)),
        }
        MountStep::Continue(self)
    }

    /// Prepares one orphan batch before returning its continuation to the executor.
    #[inline(never)]
    fn recover_orphans(mut self: Box<Self>, mut mount: UnpublishedMount) -> MountStep {
        let Some(target) = mount.image.orphans.current() else {
            self.state = if matches!(
                self.access,
                super::MountAccess::ReadOnly {
                    recovery: super::ReadOnlyRecovery::Replay
                }
            ) && self.device_access == super::DeviceWriteAccess::Writable
                && mount.image.journal_target.is_some()
            {
                MountState::FinishingReadOnly(mount)
            } else {
                MountState::ReadyToPublish(mount)
            };
            return MountStep::Continue(self);
        };
        let inode = target.tracking.inode;
        let result = {
            let device = OperationDevice::new(&mut self.filesystem);
            let view = EpochReadView::recovery(
                device,
                mount.image.superblock,
                &self.fscrypt_keys,
                mount.image.clusters.as_ref(),
            );
            prepare_orphan_batch(view, target, mount.image.journal.as_ref())
        };
        match result {
            Ok((sequence, progress)) => {
                if let Err(error) = mount.image.orphans.prepare_advance(inode, progress) {
                    return MountStep::Yield(self.fail(error));
                }
                self.state = MountState::OrphanWrites { mount, sequence };
            }
            Err(Error::OperationSuspended) => {
                self.state = MountState::RecoveringOrphans(mount);
                return self.submit_pending_read();
            }
            Err(error) => return MountStep::Yield(self.fail(error)),
        }
        MountStep::Continue(self)
    }

    /// Drops all preflight cursors before acquiring writable ownership, then reloads under that lease.
    fn admit_journal(
        mut self: Box<Self>,
        primary: ResolvedPrimary,
        journal: Journal<LoadedJournal>,
        journal_target: StorageTarget,
    ) -> MountStep {
        if matches!(
            self.access,
            super::MountAccess::ReadOnly {
                recovery: super::ReadOnlyRecovery::Replay
            }
        ) && (self.device_access == super::DeviceWriteAccess::ReadOnly
            || (journal_target == StorageTarget::ExternalJournal
                && self.external_access == super::DeviceWriteAccess::ReadOnly))
        {
            let superblock = primary.recovery_bootstrap();
            if superblock.recovery_state()
                == crate::disk_format::superblock::RecoveryState::NeedsRecovery
            {
                return MountStep::Yield(self.fail(Error::ReadOnlyFilesystem));
            }
            self.state = MountState::ScanningOrphans(MountPublicationSeed {
                superblock,
                journal: None,
                journal_target: None,
            });
            return MountStep::Continue(self);
        }
        if matches!(self.ownership, MountOwnership::ReadyToClaim(_)) {
            if matches!(primary, ResolvedPrimary::Valid(_)) {
                return self.claim_ownership();
            }
            // A checksum-invalid primary supplies placement only. Authenticate its committed
            // journal replacement in private memory before it can authorize any MMP write.
            self.recovery = Some(super::recovery::RecoveryOverlay::new(
                super::RecoveryMemoryLimit::DEFAULT,
            ));
        }
        self.state = match primary.begin_recovery(journal, self.access) {
            Ok(operation) => MountState::Recovering {
                primary,
                journal_target,
                operation,
            },
            Err(error) => return MountStep::Yield(self.fail(error)),
        };
        MountStep::Continue(self)
    }

    /// Acquires physical ownership only from a checksum-authenticated primary identity.
    /// Private replay observations are discarded; physical recovery is read afresh under the lease.
    fn claim_ownership(mut self: Box<Self>) -> MountStep {
        self.recovery = None;
        let MountOwnership::ReadyToClaim(owner) =
            core::mem::replace(&mut self.ownership, MountOwnership::Unprotected)
        else {
            return MountStep::Yield(self.fail(Error::DeviceIo));
        };
        let Some(parameters) = self.mmp_parameters else {
            return MountStep::Yield(self.fail(Error::MmpCorrupt));
        };
        let operation =
            match super::MmpOperation::acquire(parameters, owner, super::MediaAccess::ReadWrite)
                .and_then(memory::try_box)
            {
                Ok(operation) => operation,
                Err(error) => return MountStep::Yield(self.fail(error)),
            };
        self.filesystem = StorageTranscript::new(StorageTarget::Filesystem, self.filesystem.len());
        self.state = MountState::Resolving;
        let now = self.now;
        self.accept_ownership(
            PendingMountOwnership::Acquisition,
            operation.advance(super::MmpEvent::Start, now),
        )
    }

    /// Resolves primary metadata and either loads an internal journal or emits discovery facts.
    /// # Errors
    ///
    /// Returns an error for invalid primary metadata, journal placement, profile, or suspended I/O.
    #[inline(never)]
    fn resolve_journal(&mut self) -> Result<JournalResolution> {
        let primary_read = {
            let mut filesystem = OperationDevice::new(&mut self.filesystem);
            Superblock::read_for_mount(&mut filesystem, self.access)?
        };
        let primary = match primary_read {
            PrimarySuperblockRead::Valid(superblock) => ResolvedPrimary::Valid(superblock),
            PrimarySuperblockRead::ChecksumInvalid(provisional) => {
                ResolvedPrimary::JournalRepairRequired(provisional)
            }
        };
        let superblock = primary.recovery_bootstrap();
        if superblock.mmp() != self.mmp_parameters || superblock.uuid() != self.primary_uuid {
            return Err(Error::MmpCorrupt);
        }
        if matches!(
            self.access,
            super::MountAccess::ReadOnly {
                recovery: super::ReadOnlyRecovery::NoLoad
            }
        ) {
            return Ok(JournalResolution::Unloaded(superblock));
        }
        match superblock.journal_mode() {
            JournalMode::Internal(journal_inode_id) => {
                let journal_inode = {
                    let filesystem = OperationDevice::new(&mut self.filesystem);
                    let mut volume =
                        EpochReadView::recovery(filesystem, superblock, &self.fscrypt_keys, None);
                    volume.read_inode_record(journal_inode_id)?
                };
                let journal = {
                    let mut filesystem = OperationDevice::new(&mut self.filesystem);
                    Journal::<LoadedJournal>::from_inode(
                        &journal_inode,
                        FilesystemHomeSpace::from_superblock(&superblock),
                        &mut filesystem,
                    )?
                };
                Ok(JournalResolution::Loaded {
                    primary,
                    journal,
                    journal_target: StorageTarget::Filesystem,
                })
            }
            JournalMode::External(journal_uuid) => Ok(JournalResolution::External {
                primary,
                requirement: ExternalJournalRequirement {
                    journal_uuid,
                    filesystem_uuid: superblock.uuid(),
                    home_space: FilesystemHomeSpace::from_superblock(&superblock),
                },
            }),
            JournalMode::None if self.access.media_access() == super::MediaAccess::ReadOnly => {
                Ok(JournalResolution::Unloaded(superblock))
            }
            JournalMode::None => Err(Error::UnsupportedJournal),
        }
    }

    /// Moves the current restartable metadata read into lower ownership.
    fn submit_pending_read(mut self: Box<Self>) -> MountStep {
        match self.filesystem.take_pending_request() {
            Ok(request) => MountStep::Yield(MountTransition::SubmitLower {
                request,
                suspended: self,
            }),
            Err(error) => MountStep::Yield(self.fail(error)),
        }
    }
}
