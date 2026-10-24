//! Mounted profile, bounded epoch leases, mutation coordination, and volume failure state.

mod mmp;
use mmp::MediaOwnership;

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

use ext4_core::{
    CheckpointOperation, CheckpointPublication, CommittedEpoch, CompletedMount, DurableMutation,
    EpochSequence, FscryptKeyIdentifier, FscryptKeyPresence, MountedProfile,
    MutationCoordinatorState, PublishedMutation, VisibilityLease,
};
use wdk_sys::NTSTATUS;

use crate::kernel::cng::CngProvider;
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::io_reliability::{IoReliabilityObservation, IoReliabilityOwner, NativeIoPolicy};
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::{MountedStorage, MountedStorageRoute};
use crate::memory::{DriverShared, DriverSharedLease, DriverSharedSlot};

/// Volume reliability state after lower-device or checkpoint failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeFailureState {
    /// Reads and journaled mutations remain admitted.
    Operational,
    /// Existing committed data remains readable, but no new mutation may start.
    DegradedReadOnly,
    /// Journal replay or durability is unknown and this runtime must be torn down.
    RecoveryRequired,
    /// Ext4 commit is durable but its Windows stream projection could not be published.
    CommittedButUnpublished {
        /// Exact Cc/MM status returned to the committing IRP and later operations.
        status: NTSTATUS,
        /// Number of live native stream headers that reached the durable epoch.
        published_streams: usize,
        /// Number of prepared update records not examined after a pre-header-commit failure.
        unexamined_updates: usize,
    },
    /// Cache Manager could not establish dirty-page writeback durability.
    CacheWritebackFailed {
        /// Exact Cc status returned to this and every later mutation or flush.
        status: NTSTATUS,
    },
    /// Lower reads are no longer trustworthy.
    Failed,
}

impl VolumeFailureState {
    /// One-way native projection; exact failures remain owned by the actor.
    fn native_policy(self) -> NativeIoPolicy {
        if self.authorize_mutation().is_ok() {
            NativeIoPolicy::ReadWrite
        } else if self.authorize_read().is_ok() {
            NativeIoPolicy::ReadOnly
        } else {
            NativeIoPolicy::Unavailable
        }
    }
    /// Rejects a new mutation unless the runtime is fully operational.
    /// # Errors
    ///
    /// Returns revoked media ownership, an exact native failure, or volume dismount after degradation.
    pub(crate) fn authorize_mutation(self) -> DriverResult<()> {
        match self {
            Self::Operational => Ok(()),
            Self::DegradedReadOnly | Self::RecoveryRequired | Self::Failed => {
                Err(DriverError::VolumeDismounted)
            }
            Self::CommittedButUnpublished { status, .. }
            | Self::CacheWritebackFailed { status } => {
                Err(DriverError::CacheManagerFailure(status))
            }
        }
    }

    /// Rejects reads only after read reliability itself has been lost.
    /// # Errors
    ///
    /// Returns revoked ownership, an exact native failure, or dismount when reads require recovery.
    pub(crate) fn authorize_read(self) -> DriverResult<()> {
        match self {
            Self::Operational | Self::DegradedReadOnly | Self::CacheWritebackFailed { .. } => {
                Ok(())
            }
            Self::RecoveryRequired | Self::Failed => Err(DriverError::VolumeDismounted),
            Self::CommittedButUnpublished { status, .. } => {
                Err(DriverError::CacheManagerFailure(status))
            }
        }
    }

    /// Moves to a durable-abort read-only state without weakening a stronger prior failure.
    const fn durable_abort(self) -> Self {
        match self {
            Self::Operational => Self::DegradedReadOnly,
            Self::DegradedReadOnly
            | Self::RecoveryRequired
            | Self::CommittedButUnpublished { .. }
            | Self::CacheWritebackFailed { .. }
            | Self::Failed => self,
        }
    }

    /// Moves to recovery-required when commit/abort/data durability is unknown.
    const fn durability_unknown(self) -> Self {
        match self {
            Self::Operational | Self::DegradedReadOnly => Self::RecoveryRequired,
            Self::RecoveryRequired
            | Self::CommittedButUnpublished { .. }
            | Self::CacheWritebackFailed { .. }
            | Self::Failed => self,
        }
    }

    /// Moves to terminal failure once reads cannot be trusted.
    const fn read_unreliable(self) -> Self {
        Self::Failed
    }

    /// Records the exact post-commit publication failure as a non-retryable terminal state.
    const fn publication_failed(
        self,
        status: NTSTATUS,
        published_streams: usize,
        unexamined_updates: usize,
    ) -> Self {
        match self {
            Self::Failed => Self::Failed,
            Self::CommittedButUnpublished { .. } => self,
            Self::Operational
            | Self::DegradedReadOnly
            | Self::RecoveryRequired
            | Self::CacheWritebackFailed { .. } => Self::CommittedButUnpublished {
                status,
                published_streams,
                unexamined_updates,
            },
        }
    }

    /// Preserves the first exact Cache Manager writeback failure as terminal mutation authority.
    const fn cache_writeback_failed(self, status: NTSTATUS) -> Self {
        match self {
            Self::Operational | Self::DegradedReadOnly => Self::CacheWritebackFailed { status },
            Self::RecoveryRequired
            | Self::CommittedButUnpublished { .. }
            | Self::CacheWritebackFailed { .. }
            | Self::Failed => self,
        }
    }
}

/// Current immutable epoch; each operation retains the exact version it observed.
#[derive(Debug)]
pub(crate) struct EpochRegistry {
    /// Epoch selected for new operations.
    current: DriverShared<CommittedEpoch>,
}

impl EpochRegistry {
    /// Fallibly installs the initial mount epoch in shared immutable storage.
    /// # Errors
    ///
    /// Returns an error when storage for the initial immutable epoch cannot be allocated.
    pub(crate) fn try_new(initial: CommittedEpoch) -> DriverResult<Self> {
        let current = DriverShared::try_new(initial)?;
        Ok(Self { current })
    }

    /// Acquires one operation lease on the current immutable epoch.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite shared-reference budget is exhausted.
    pub(crate) fn acquire_current(&self) -> DriverResult<EpochLease> {
        Ok(EpochLease {
            epoch: self.current.try_acquire()?,
        })
    }

    /// Borrows the current epoch for one non-suspending reactor transition.
    pub(crate) fn current(&self) -> &CommittedEpoch {
        self.current.get()
    }

    /// Reserves both durable and checkpoint epoch allocations before any lower write is issued.
    /// # Errors
    ///
    /// Returns insufficient resources when either stable allocation fails.
    pub(crate) fn reserve_publication(&self) -> DriverResult<EpochPublicationSlots> {
        Ok(EpochPublicationSlots {
            durable: self.reserve_slot()?,
            checkpoint: self.reserve_slot()?,
        })
    }

    /// Reserves one immutable publication without implying a later checkpoint.
    /// # Errors
    /// Returns insufficient resources before publication can start.
    fn reserve_slot(&self) -> DriverResult<EpochPublicationSlot> {
        Ok(EpochPublicationSlot {
            storage: DriverSharedSlot::try_new()?,
        })
    }

    /// Publishes one preallocated immutable epoch without a fallible post-commit step.
    fn publish(&mut self, publication: EpochPublicationSlot, epoch: CommittedEpoch) {
        self.current = publication.initialize(epoch);
    }
}

/// Immutable operation view that keeps the exact observed epoch alive.
#[derive(Debug)]
pub(crate) struct EpochLease {
    /// Shared immutable epoch owner.
    epoch: DriverSharedLease<CommittedEpoch>,
}

impl EpochLease {
    /// Borrows the immutable epoch retained by this operation.
    pub(crate) fn epoch(&self) -> &CommittedEpoch {
        self.epoch.get()
    }
}

/// Preallocated storage for one infallible post-commit epoch publication.
pub(crate) struct EpochPublicationSlot {
    /// Uninitialized shared allocation that becomes the published epoch owner.
    storage: DriverSharedSlot<CommittedEpoch>,
}

impl EpochPublicationSlot {
    /// Initializes this uniquely owned reservation and converts it to immutable epoch ownership.
    fn initialize(self, epoch: CommittedEpoch) -> DriverShared<CommittedEpoch> {
        self.storage.initialize(epoch)
    }
}

impl fmt::Debug for EpochPublicationSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochPublicationSlot(..)")
    }
}

/// Pair of epoch slots reserved before a commit can issue its first lower write.
#[derive(Debug)]
pub(crate) struct EpochPublicationSlots {
    /// Durable overlay epoch slot.
    durable: EpochPublicationSlot,
    /// Overlay-free checkpoint epoch slot.
    checkpoint: EpochPublicationSlot,
}

impl EpochPublicationSlots {
    /// Separates the slots so durable and checkpoint publication remain independent.
    pub(crate) fn into_parts(self) -> (EpochPublicationSlot, EpochPublicationSlot) {
        (self.durable, self.checkpoint)
    }
}

/// Driver-local mounted runtime split into immutable profile, immutable epochs, and mutable
/// mutation coordination.
#[derive(Debug)]
pub(crate) struct VolumeRuntime {
    /// UUID-specific identity publication independent of inode epochs.
    pub(super) identity: crate::identity::IdentityBinding,
    /// Raw metadata reuse owned by this volume and borrowed only by the sole reactor actor.
    pub(super) metadata_cache: ext4_core::MetadataCache,
    /// Immutable feature, geometry, and device identity.
    profile: MountedProfile,
    /// Current immutable epoch owner.
    epochs: EpochRegistry,
    /// Journal cursor, allocation state, and resource versions.
    coordinator: MutationCoordinatorState,
    /// Physical media ownership retained independently of journal state.
    ownership: MediaOwnership,
    /// Validated lower-device geometry and completion owner.
    storage: MountedStorage,
    /// Mount admission owner for independently retained CNG algorithm providers.
    crypto: CngProvider,
    /// Current read/write reliability state.
    failure: VolumeFailureState,
    /// Sole publisher of the native observation of `failure`.
    native_reliability: IoReliabilityOwner,
    /// Mutations admitted before closing and not yet fully checkpointed or abandoned.
    active_mutations: DriverShared<AtomicU32>,
    /// Sole owner of periodic discard admission, completion and terminal failure.
    automatic_trim: automatic_trim::AutomaticTrimState,
}

impl VolumeRuntime {
    /// Separates one completed mount into the runtime's independent state domains.
    /// # Errors
    ///
    /// Returns an error when the initial epoch registry or mount-scoped CNG providers cannot be
    /// allocated and initialized.
    pub(crate) fn try_new(
        mount: CompletedMount,
        storage: MountedStorage,
        automatic_trim: ext4_control::AutomaticTrim,
        catalog: &mut crate::identity::IdentityDirectory,
    ) -> DriverResult<Self> {
        let (profile, epoch, coordinator, mmp) = mount.into_parts();
        let identity = catalog.binding(epoch.identity().uuid())?;
        let mut native_reliability = IoReliabilityOwner::try_new()?;
        native_reliability.publish(
            match profile.access() {
                ext4_core::MediaAccess::ReadWrite => NativeIoPolicy::ReadWrite,
                ext4_core::MediaAccess::ReadOnly => NativeIoPolicy::ReadOnly,
            },
            mmp.as_ref().map(ext4_core::MmpLease::deadline),
        );
        let crypto = CngProvider::try_open()?;
        let metadata_cache = ext4_core::MetadataCache::try_new(&epoch).unwrap_or_default();
        Ok(Self {
            automatic_trim: automatic_trim::AutomaticTrimState::new(
                automatic_trim,
                profile.access(),
                crate::kernel::time::monotonic_millis(),
            ),
            identity,
            metadata_cache,
            profile,
            epochs: EpochRegistry::try_new(epoch)?,
            coordinator,
            ownership: MediaOwnership::from_mount(mmp),
            storage,
            crypto,
            failure: VolumeFailureState::Operational,
            native_reliability,
            active_mutations: DriverShared::try_new(AtomicU32::new(0))?,
        })
    }

    /// Immutable mount profile.
    pub(crate) const fn profile(&self) -> &MountedProfile {
        &self.profile
    }

    /// Validated mounted lower devices.
    pub(crate) const fn storage(&self) -> MountedStorageRoute {
        self.storage.route()
    }

    /// Admission owner used to acquire provider leases and prebuild operation-owned CNG objects.
    pub(crate) const fn crypto(&self) -> &CngProvider {
        &self.crypto
    }

    /// Retains a read-only reliability projection before native mount publication.
    /// # Errors
    /// Returns reference-budget exhaustion before installing callbacks.
    pub(crate) fn observe_reliability(&self) -> DriverResult<IoReliabilityObservation> {
        self.native_reliability.observe()
    }

    /// Recomputes the sole native projection from independent reliability and ownership authority.
    fn publish_reliability(&mut self) {
        let policy = if !self.ownership.permits_io() {
            NativeIoPolicy::Unavailable
        } else {
            match (self.failure.native_policy(), self.profile.access()) {
                (NativeIoPolicy::ReadWrite, ext4_core::MediaAccess::ReadOnly) => {
                    NativeIoPolicy::ReadOnly
                }
                (policy, _) => policy,
            }
        };
        self.native_reliability
            .publish(policy, self.ownership.deadline());
    }
    /// Publishes with the authoritative transition in one non-suspending actor step.
    fn set_failure(&mut self, failure: VolumeFailureState) {
        self.failure = failure;
        self.publish_reliability();
    }

    /// Whether journal space has no granted commit or published overlay awaiting checkpoint.
    #[cfg(not(test))]
    pub(crate) fn journal_is_clean(&self) -> bool {
        self.active_mutations.get().load(Ordering::Acquire) == 0
            && self.coordinator.journal_is_clean()
            && !self.coordinator.has_pending_trim()
    }

    /// Observes discard admission without waiting for unrelated provisional mutation work.
    /// # Errors
    /// Returns revoked ownership or unreliable writes instead of leaving an impossible wait pending.
    pub(crate) fn trim_ready(&self) -> DriverResult<bool> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        if self.profile.access() == ext4_core::MediaAccess::ReadOnly {
            return Err(ext4_core::Error::ReadOnlyFilesystem.into());
        }
        Ok(self.coordinator.journal_is_clean() && !self.coordinator.has_pending_trim())
    }
    /// Acquires only the ranges selected by the exact current checkpointed epoch.
    /// # Errors
    /// Returns media revocation, stale selection, read-only policy or pre-effect allocation failure.
    pub(crate) fn reserve_trim(
        &mut self,
        selection: ext4_core::TrimSelection,
    ) -> DriverResult<ext4_core::TrimAdmission> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        Ok(selection.reserve(&mut self.coordinator, self.epochs.current())?)
    }
    /// Retires completed physical ownership independently of the session's current I/O permissions.
    /// # Errors
    /// A foreign native completion retains both owners and cannot release another reservation.
    pub(crate) fn complete_trim(
        &mut self,
        pending: ext4_core::PendingTrim,
        completion: ext4_core::TrimCompletion,
    ) -> Result<ext4_core::TrimBatchResult, ext4_core::TrimCompletionMismatch> {
        pending.complete(&mut self.coordinator, completion)
    }

    /// Acquires one current immutable epoch for a read or resolve operation.
    /// # Errors
    ///
    /// Returns an error when reads are no longer authorized.
    pub(crate) fn acquire_epoch(&mut self) -> DriverResult<EpochLease> {
        self.authorize_ownership()?;
        self.failure.authorize_read()?;
        self.epochs.acquire_current()
    }

    /// Current epoch for one non-suspending projection.
    pub(crate) fn current_epoch(&self) -> &CommittedEpoch {
        self.epochs.current()
    }

    /// Combines read reliability admission with current metadata and dependency versions.
    /// # Errors
    /// Returns the authoritative volume failure or a mismatched coordinator publication.
    pub(crate) fn committed_read<'state>(
        &'state self,
        cache: &'state mut ext4_core::MetadataCache,
    ) -> DriverResult<ext4_core::CommittedReadContext<'state>> {
        self.authorize_ownership()?;
        self.failure.authorize_read()?;
        Ok(self
            .coordinator
            .read_context(cache.access(self.epochs.current()))?)
    }

    /// Captures provisional staging admission independently of native per-handle state.
    /// # Errors
    /// Returns media revocation, unreliable writes or a stale/foreign epoch before staging starts.
    pub(crate) fn mutation_context<'cache>(
        &self,
        cache: ext4_core::MetadataCacheAccess<'cache>,
    ) -> DriverResult<ext4_core::MutationResolveContext<'cache>> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        Ok(self.coordinator.mutation_context(cache)?)
    }

    /// Mutation coordinator under reactor-issued intent/commit capability.
    pub(crate) const fn coordinator(&self) -> &MutationCoordinatorState {
        &self.coordinator
    }

    /// Reserves coordinator index capacity under the granted commit lane.
    /// # Errors
    /// Returns core version, serialization, or allocation failures before lower writes.
    pub(crate) fn prepare_mutation_commit(
        &mut self,
        reserved: ext4_core::ReservedMutation,
        commit: ext4_core::CommitLease,
    ) -> Result<ext4_core::CommitReadyMutation, ext4_core::Error> {
        reserved.prepare_commit(
            commit,
            &mut self.coordinator,
            self.epochs.current(),
            &mut self.metadata_cache,
        )
    }

    /// Allocates one stable FIFO mutation ticket before resolve begins.
    /// # Errors
    ///
    /// Returns an error when mutations are no longer authorized or ticket allocation overflows.
    pub(crate) fn admit_mutation(&mut self) -> DriverResult<(u64, MutationActivityLease)> {
        self.require_media_write()?;
        self.admit_key_change()
    }

    /// Requires the session's fixed media authority independently of runtime health.
    /// # Errors
    /// Returns write protection for a read-only mount.
    pub(crate) fn require_media_write(&self) -> DriverResult<()> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        self.authorize_ownership()?;
        match self.profile.access() {
            ext4_core::MediaAccess::ReadWrite => Ok(()),
            ext4_core::MediaAccess::ReadOnly => {
                Err(DriverError::from(ext4_core::Error::ReadOnlyFilesystem))
            }
        }
    }

    /// Admits mount-local key publication without granting any media write authority.
    /// # Errors
    /// Returns unhealthy volume state or finite operation-accounting exhaustion.
    pub(crate) fn admit_key_change(&mut self) -> DriverResult<(u64, MutationActivityLease)> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        let activity = MutationActivityLease::acquire(&self.active_mutations)?;
        let ticket = self
            .coordinator
            .admit_mutation()
            .map_err(DriverError::from)?;
        Ok((ticket, activity))
    }

    /// Mutable coordinator used only by consuming visibility/checkpoint publication.
    fn coordinator_mut(&mut self) -> &mut MutationCoordinatorState {
        &mut self.coordinator
    }

    /// Reserves both post-commit epoch slots while allocation failure remains harmless.
    /// # Errors
    ///
    /// Returns an error when mutations are not authorized or stable epoch storage cannot be
    /// allocated.
    pub(crate) fn reserve_epoch_publication(&mut self) -> DriverResult<EpochPublicationSlots> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        self.epochs.reserve_publication()
    }

    /// Resolves a mount-local insertion against the current key authority.
    /// # Errors
    /// Returns mutation admission, duplicate-key, or snapshot allocation failures.
    pub(crate) fn resolve_key_addition(
        &self,
        ticket: u64,
        key: ext4_core::FscryptMasterKey,
    ) -> DriverResult<ext4_core::ResolvedKeyChange> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        Ok(ext4_core::ResolvedKeyChange::add(
            self.epochs.current(),
            &self.coordinator,
            ticket,
            key,
        )?)
    }

    /// Resolves mount-local removal without touching filesystem storage.
    /// # Errors
    /// Returns mutation admission or snapshot allocation failures.
    pub(crate) fn resolve_key_removal(
        &self,
        ticket: u64,
        identifier: FscryptKeyIdentifier,
    ) -> DriverResult<ext4_core::ResolvedKeyChange> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        Ok(ext4_core::ResolvedKeyChange::remove(
            self.epochs.current(),
            &self.coordinator,
            ticket,
            identifier,
        )?)
    }

    /// Prepares the key epoch while both scheduler grants remain exclusively held.
    /// # Errors
    /// Returns stale grants, changed key versions, or allocation failures before publication.
    pub(crate) fn prepare_key_change(
        &mut self,
        change: ext4_core::ReservedKeyChange,
        commit: ext4_core::CommitLease,
    ) -> DriverResult<ext4_core::PreparedKeyChange> {
        Ok(change.prepare(commit, &mut self.coordinator, self.epochs.current())?)
    }

    /// Retires unpublished secret storage; a fenced coordinator already retired its grants.
    pub(crate) fn abort_key_change(&mut self, change: ext4_core::PreparedKeyChange) {
        if let Err((error, _change)) = change.abort(&mut self.coordinator) {
            self.reject_publication(error);
        }
    }

    /// Reserves the single immutable epoch needed by a mount-local key publication.
    /// # Errors
    /// Returns mutation admission or stable allocation failure.
    pub(crate) fn reserve_key_publication(&self) -> DriverResult<EpochPublicationSlot> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        self.epochs.reserve_slot()
    }

    /// Publishes mount keys only while this session still owns its media observation.
    /// # Errors
    /// Returns revoked ownership before changing the visible key snapshot.
    pub(crate) fn publish_keys(
        &mut self,
        change: ext4_core::PreparedKeyChange,
        visibility: VisibilityLease,
        slot: EpochPublicationSlot,
    ) -> DriverResult<()> {
        self.require_media_ownership()?;
        let epoch = match change.publish(visibility, &mut self.coordinator) {
            Ok(epoch) => epoch,
            Err((error, _change)) => return Err(self.reject_publication(error).into()),
        };
        self.metadata_cache.publish(&epoch);
        self.epochs.publish(slot, epoch);
        Ok(())
    }

    /// Converts successful scheduler intent arbitration into this mount's capability.
    #[cfg(not(test))]
    pub(crate) fn grant_intent(&mut self, ticket: u64) -> ext4_core::MutationLease {
        self.coordinator.grant_intent(ticket)
    }

    /// Attempts a commit grant while retaining volume failure separately from contention.
    /// # Errors
    ///
    /// Returns the volume's mutation failure without acquiring or replacing a grant.
    #[cfg(not(test))]
    pub(crate) fn acquire_commit(
        &mut self,
        ticket: u64,
    ) -> DriverResult<Option<ext4_core::CommitLease>> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()?;
        Ok(self.coordinator.acquire_commit(ticket)?)
    }

    /// Revokes a grant that has not been consumed by core preparation.
    #[cfg(not(test))]
    pub(crate) fn abandon_commit(&mut self, ticket: u64) {
        self.coordinator.revoke_unprepared_commit(ticket);
    }

    /// Grants the short visibility swap independently of checkpoint I/O.
    /// # Errors
    /// Rejects revoked ownership separately from ordinary visibility contention.
    #[cfg(not(test))]
    pub(crate) fn try_grant_visibility(
        &mut self,
        ticket: u64,
    ) -> DriverResult<Option<VisibilityLease>> {
        self.authorize_ownership()?;
        Ok(self.coordinator.acquire_visibility(ticket))
    }

    /// Grants the detached checkpoint operation after durable visibility publication.
    /// # Errors
    /// Rejects revoked ownership separately from an occupied checkpoint lane.
    #[cfg(not(test))]
    pub(crate) fn try_grant_checkpoint(
        &mut self,
        epoch: EpochSequence,
    ) -> DriverResult<Option<ext4_core::CheckpointLease>> {
        self.authorize_ownership()?;
        Ok(self.coordinator.acquire_checkpoint(epoch))
    }

    /// Allocation-free durable epoch publication after a matching visibility grant.
    /// # Errors
    /// Returns revoked ownership while retaining the last visible epoch for teardown.
    pub(crate) fn publish_durable(
        &mut self,
        mutation: DurableMutation,
        visibility: VisibilityLease,
        durable_slot: EpochPublicationSlot,
        checkpoint_slot: EpochPublicationSlot,
    ) -> DriverResult<PendingCheckpoint> {
        self.require_media_ownership()?;
        let published: PublishedMutation =
            match mutation.publish(visibility, self.coordinator_mut()) {
                Ok(published) => published,
                Err((error, _mutation)) => return Err(self.reject_publication(error).into()),
            };
        let (epoch, checkpoint) = published.into_parts();
        let sequence = epoch.sequence();
        self.metadata_cache.publish(&epoch);
        self.epochs.publish(durable_slot, epoch);
        Ok(PendingCheckpoint {
            epoch: sequence,
            operation: checkpoint,
            publication: checkpoint_slot,
        })
    }

    /// Installs a completed overlay-free checkpoint and releases journal space.
    /// # Errors
    /// Returns ownership loss without restoring the fenced journal cursor.
    pub(crate) fn publish_checkpoint(
        &mut self,
        durability: CheckpointPublication,
        publication: EpochPublicationSlot,
    ) -> DriverResult<()> {
        self.require_media_ownership()?;
        let checkpointed = match durability.publish(self.coordinator_mut()) {
            Ok(epoch) => epoch,
            Err((error, _durability)) => return Err(self.reject_publication(error).into()),
        };
        self.metadata_cache.publish(&checkpointed);
        self.epochs.publish(publication, checkpointed);
        Ok(())
    }

    /// Samples the monotonic clock only for a physically protected session.
    /// # Errors
    /// Returns revoked, expired or finally consumed ownership independently of reliability.
    fn authorize_ownership(&self) -> DriverResult<()> {
        let millis = self
            .ownership
            .deadline()
            .map_or(0, |_deadline| crate::kernel::time::monotonic_millis());
        self.ownership.authorize(ext4_core::MmpTime::new(millis, 0))
    }
    /// Retires every core grant before native observers can admit another callback.
    /// Dropping physical authority cannot issue a clean marker against a replacement owner.
    fn revoke_media_ownership(&mut self) {
        self.fail_mmp(ext4_core::Error::MmpOwnershipLost);
    }
    /// Observes expiration at each mounted actor callback, including cache-only work.
    pub(crate) fn observe_media_ownership(&mut self) {
        if self.authorize_ownership() == Err(ext4_core::Error::MmpOwnershipLost.into()) {
            self.revoke_media_ownership();
        }
    }
    /// Revalidates issued grants at publication and immediately before lower submission.
    /// # Errors
    /// An expired lease revokes this session; later completions cannot restore it.
    pub(crate) fn require_media_ownership(&mut self) -> DriverResult<()> {
        self.observe_media_ownership();
        self.authorize_ownership()
    }
    /// Observes the next heartbeat or outstanding record-operation deadline for the actor timer.
    #[cfg(not(test))]
    pub(crate) fn mmp_wakeup(&self) -> Option<ext4_core::MmpDeadline> {
        self.ownership.wakeup()
    }
    /// Starts only a due renewal or a filesystem-close-authorized release.
    /// # Errors
    /// Records terminal ownership failure before returning a failed handoff.
    #[cfg(not(test))]
    pub(crate) fn start_mmp_action(&mut self) -> DriverResult<Option<ext4_core::MmpOperation>> {
        if self.ownership.wakeup().is_none() {
            return Ok(None);
        }
        let now = ext4_core::MmpTime::new(crate::kernel::time::monotonic_millis(), 0);
        match self.ownership.next_action(now) {
            Ok(operation) => {
                self.publish_reliability();
                Ok(operation)
            }
            Err(error) => {
                self.fail_mmp(error);
                Err(error.into())
            }
        }
    }
    /// Accepts the completed child before publishing its next deadline to native callbacks.
    /// # Errors
    /// A late or revoked child cannot restore the retired coordinator or native permissions.
    pub(crate) fn complete_mmp_action(
        &mut self,
        completion: ext4_core::MmpCompletion,
    ) -> DriverResult<()> {
        let now = ext4_core::MmpTime::new(crate::kernel::time::monotonic_millis(), 0);
        if let Err(error) = self.ownership.complete(completion, now) {
            self.fail_mmp(error);
            return Err(error.into());
        }
        if self.ownership.close_ready() == Ok(true) {
            self.coordinator.revoke_media_ownership();
        }
        self.publish_reliability();
        Ok(())
    }
    /// Transfers the filesystem's completed close protocol into the final record-release handoff.
    /// # Errors
    /// Returns a terminal or duplicate close error without requesting another physical release.
    pub(crate) fn request_mmp_close(
        &mut self,
        durability: ext4_core::CleanCloseDurability,
    ) -> DriverResult<()> {
        self.ownership
            .request_close(durability)
            .map_err(|(error, _durability)| error)?;
        self.coordinator.revoke_media_ownership();
        self.publish_reliability();
        Ok(())
    }
    /// Readiness for the native close, retaining terminal failure separately from a pending release.
    /// # Errors
    /// Returns the first ownership failure while a close acknowledgment is pending.
    #[cfg(not(test))]
    pub(crate) fn mmp_close_ready(&self) -> DriverResult<bool> {
        self.ownership.close_ready()
    }
    /// Consumes the combined close acknowledgment only after final physical ownership release.
    /// # Errors
    /// Rejects premature, duplicate or failed close completion.
    pub(crate) fn finish_mmp_close(&mut self) -> DriverResult<ext4_core::CleanCloseDurability> {
        let durability = self.ownership.finish_close()?;
        self.publish_reliability();
        Ok(durability)
    }
    /// Observes a failed, uncertain or expired physical ownership operation without retrying it.
    pub(crate) fn fail_mmp(&mut self, reason: ext4_core::Error) {
        self.coordinator.revoke_media_ownership();
        self.ownership.revoke(reason);
        self.publish_reliability();
    }

    /// Revocation is an expected external transition; mismatched internal grants remain fatal.
    fn reject_publication(&mut self, error: ext4_core::Error) -> ext4_core::Error {
        if error != ext4_core::Error::MmpOwnershipLost {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        self.revoke_media_ownership();
        error
    }

    /// Requires a healthy runtime before a flush can claim journal durability.
    /// # Errors
    ///
    /// Returns the same terminal status observed by mutation admission.
    pub(crate) fn authorize_durability(&self) -> DriverResult<()> {
        self.authorize_ownership()?;
        self.failure.authorize_mutation()
    }

    /// Moves a confirmed durable abort into read-only state.
    pub(crate) fn record_durable_abort(&mut self) {
        self.set_failure(self.failure.durable_abort());
    }

    /// Marks commit/abort/data effects as unknown and requires a fresh replay mount.
    pub(crate) fn record_durability_unknown(&mut self) {
        self.set_failure(self.failure.durability_unknown());
    }

    /// Marks lower reads untrustworthy.
    pub(crate) fn record_read_unreliable(&mut self) {
        self.set_failure(self.failure.read_unreliable());
    }

    /// Records an exact post-commit Cc/MM publication failure and stream progress.
    pub(crate) fn record_publication_failure(
        &mut self,
        status: NTSTATUS,
        published_streams: usize,
        unexamined_updates: usize,
    ) {
        self.set_failure(self.failure.publication_failed(
            status,
            published_streams,
            unexamined_updates,
        ));
    }

    /// Records the exact dirty-page writeback failure returned by Cache Manager.
    pub(crate) fn record_cache_writeback_failure(&mut self, status: NTSTATUS) {
        self.set_failure(self.failure.cache_writeback_failed(status));
    }

    /// Current volume identity from the selected immutable epoch.
    pub(crate) fn identity(&self) -> ext4_core::VolumeIdentity {
        self.current_epoch().identity()
    }

    /// Current fscrypt key presence from the immutable epoch.
    pub(crate) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.current_epoch().fscrypt_key_presence(identifier)
    }
}

/// One admitted mutation that keeps its activity counter alive through every terminal path.
#[derive(Debug)]
pub(crate) struct MutationActivityLease {
    /// Shared mutation-count owner retained independently from the runtime field.
    active: DriverSharedLease<AtomicU32>,
}

impl MutationActivityLease {
    /// Increments the logical activity budget and returns its release authority.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite mutation count is exhausted.
    fn acquire(active: &DriverShared<AtomicU32>) -> DriverResult<Self> {
        let lease = active.try_acquire()?;
        lease
            .get()
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| DriverError::InsufficientResources)?;
        Ok(Self { active: lease })
    }
}

impl Drop for MutationActivityLease {
    fn drop(&mut self) {
        let previous = self.active.get().fetch_sub(1, Ordering::AcqRel);
        if previous == 0 {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }
}

/// Checkpoint work detached from visibility together with its pre-reserved publication slot.
#[derive(Debug)]
pub(crate) struct PendingCheckpoint {
    /// Visible overlay epoch being checkpointed.
    epoch: EpochSequence,
    /// Prebuilt home/journal-clean operation.
    operation: CheckpointOperation,
    /// Overlay-free epoch slot reserved before the original commit.
    publication: EpochPublicationSlot,
}

impl PendingCheckpoint {
    /// Visible overlay epoch identity.
    pub(crate) const fn epoch(&self) -> EpochSequence {
        self.epoch
    }

    /// Separates checkpoint I/O from its infallible publication target.
    pub(crate) fn into_parts(self) -> (CheckpointOperation, EpochPublicationSlot, EpochSequence) {
        (self.operation, self.publication, self.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::VolumeFailureState;

    /// # Panics
    ///
    /// Panics when failure-state transitions weaken an already stronger failure.
    #[test]
    fn volume_failure_transitions_are_monotonic() {
        for failure in [
            VolumeFailureState::Operational,
            VolumeFailureState::DegradedReadOnly,
            VolumeFailureState::RecoveryRequired,
            VolumeFailureState::Failed,
            VolumeFailureState::CommittedButUnpublished {
                status: wdk_sys::STATUS_IO_DEVICE_ERROR,
                published_streams: 1,
                unexamined_updates: 2,
            },
            VolumeFailureState::CacheWritebackFailed {
                status: wdk_sys::STATUS_IO_DEVICE_ERROR,
            },
        ] {
            assert_eq!(
                failure.native_policy().permits(false),
                failure.authorize_read().is_ok()
            );
            assert_eq!(
                failure.native_policy().permits(true),
                failure.authorize_mutation().is_ok()
            );
        }
        let publication_status = wdk_sys::STATUS_IO_DEVICE_ERROR;
        assert_eq!(
            VolumeFailureState::Operational.durable_abort(),
            VolumeFailureState::DegradedReadOnly
        );
        assert_eq!(
            VolumeFailureState::DegradedReadOnly.durability_unknown(),
            VolumeFailureState::RecoveryRequired
        );
        assert_eq!(
            VolumeFailureState::RecoveryRequired.durable_abort(),
            VolumeFailureState::RecoveryRequired
        );
        assert_eq!(
            VolumeFailureState::Operational.read_unreliable(),
            VolumeFailureState::Failed
        );
        let publication =
            VolumeFailureState::Operational.publication_failed(publication_status, 2, 1);
        assert_eq!(
            publication.authorize_mutation(),
            Err(crate::kernel::status::DriverError::CacheManagerFailure(
                publication_status
            ))
        );
        assert_eq!(publication.durable_abort(), publication);
        assert_eq!(publication.durability_unknown(), publication);
        assert_eq!(
            publication.publication_failed(wdk_sys::STATUS_INSUFFICIENT_RESOURCES, 0, 3),
            publication
        );
        let writeback = VolumeFailureState::Operational.cache_writeback_failed(publication_status);
        assert_eq!(writeback.authorize_read(), Ok(()));
        assert_eq!(
            writeback.authorize_mutation(),
            Err(crate::kernel::status::DriverError::CacheManagerFailure(
                publication_status
            ))
        );
        assert_eq!(
            writeback.cache_writeback_failed(wdk_sys::STATUS_INSUFFICIENT_RESOURCES),
            writeback
        );
        assert_eq!(writeback.durability_unknown(), writeback);
        assert_eq!(
            writeback.publication_failed(wdk_sys::STATUS_INSUFFICIENT_RESOURCES, 4, 2),
            VolumeFailureState::CommittedButUnpublished {
                status: wdk_sys::STATUS_INSUFFICIENT_RESOURCES,
                published_streams: 4,
                unexamined_updates: 2,
            }
        );
    }
}

mod automatic_trim;
pub(crate) use automatic_trim::{AutomaticTrimDeadline, AutomaticTrimRun};
