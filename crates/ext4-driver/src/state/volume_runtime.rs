//! Mounted profile, bounded epoch leases, mutation coordination, and volume failure state.

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

use ext4_core::{
    CheckpointOperation, CleanJournalDurability, CommittedEpoch, CompletedMount, DurableMutation,
    EpochSequence, FscryptKeyIdentifier, FscryptKeyPresence, MountedProfile,
    MutationCoordinatorState, PublishedMutation, VisibilityLease,
};
use wdk_sys::NTSTATUS;

use crate::kernel::cng::CngProvider;
use crate::kernel::fatal::KernelWideInconsistency;
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
    },
    /// Lower reads are no longer trustworthy.
    Failed,
}

impl VolumeFailureState {
    /// Rejects a new mutation unless the runtime is fully operational.
    /// # Errors
    ///
    /// Returns [`DriverError::VolumeDismounted`] after any read-only or terminal volume failure.
    pub(crate) fn authorize_mutation(self) -> DriverResult<()> {
        match self {
            Self::Operational => Ok(()),
            Self::DegradedReadOnly | Self::RecoveryRequired | Self::Failed => {
                Err(DriverError::VolumeDismounted)
            }
            Self::CommittedButUnpublished { status } => {
                Err(DriverError::CacheManagerFailure(status))
            }
        }
    }

    /// Rejects reads only after read reliability itself has been lost.
    /// # Errors
    ///
    /// Returns [`DriverError::VolumeDismounted`] when recovery is required or reads are failed.
    pub(crate) fn authorize_read(self) -> DriverResult<()> {
        match self {
            Self::Operational | Self::DegradedReadOnly => Ok(()),
            Self::RecoveryRequired | Self::Failed => Err(DriverError::VolumeDismounted),
            Self::CommittedButUnpublished { status } => {
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
            | Self::Failed => self,
        }
    }

    /// Moves to recovery-required when commit/abort/data durability is unknown.
    const fn durability_unknown(self) -> Self {
        match self {
            Self::Operational | Self::DegradedReadOnly => Self::RecoveryRequired,
            Self::RecoveryRequired | Self::CommittedButUnpublished { .. } | Self::Failed => self,
        }
    }

    /// Moves to terminal failure once reads cannot be trusted.
    const fn read_unreliable(self) -> Self {
        Self::Failed
    }

    /// Records the exact post-commit publication failure as a non-retryable terminal state.
    const fn publication_failed(self, status: NTSTATUS) -> Self {
        match self {
            Self::Failed => Self::Failed,
            Self::CommittedButUnpublished { status } => Self::CommittedButUnpublished { status },
            Self::Operational | Self::DegradedReadOnly | Self::RecoveryRequired => {
                Self::CommittedButUnpublished { status }
            }
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
        let durable = DriverSharedSlot::try_new()?;
        let checkpoint = DriverSharedSlot::try_new()?;
        Ok(EpochPublicationSlots {
            durable: EpochPublicationSlot { storage: durable },
            checkpoint: EpochPublicationSlot {
                storage: checkpoint,
            },
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

/// Commit/checkpoint gate state for the currently supported one-transaction journal profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitGateState {
    /// Journal space is clean and one commit may be granted.
    Ready,
    /// One mutation owns commit authority through durable visibility publication.
    CommitGranted {
        /// Mutation ticket owning commit authority.
        ticket: u64,
    },
    /// A visible overlay is awaiting independent checkpoint and journal-space release.
    CheckpointPending {
        /// Visible overlay epoch awaiting checkpoint admission.
        epoch: EpochSequence,
    },
    /// The detached checkpoint operation owns journal-space release authority.
    CheckpointGranted {
        /// Visible overlay epoch whose detached checkpoint owns the journal lane.
        epoch: EpochSequence,
    },
}

/// Short allocation-free visibility gate, separate from checkpoint ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisibilityGateState {
    /// No durable epoch is being installed.
    Ready,
    /// One durable mutation owns the sole epoch-swap transition.
    Granted {
        /// Durable mutation ticket owning the short publication gate.
        ticket: u64,
    },
}

/// Driver-local mounted runtime split into immutable profile, immutable epochs, and mutable
/// mutation coordination.
#[derive(Debug)]
pub(crate) struct VolumeRuntime {
    /// Immutable feature, geometry, and device identity.
    profile: MountedProfile,
    /// Current immutable epoch owner.
    epochs: EpochRegistry,
    /// Journal cursor, allocation state, and resource versions.
    coordinator: MutationCoordinatorState,
    /// Validated lower-device geometry and completion owner.
    storage: MountedStorage,
    /// Immutable mount-scoped CNG algorithm providers.
    crypto: CngProvider,
    /// Current read/write reliability state.
    failure: VolumeFailureState,
    /// Serialized commit/checkpoint ownership.
    commit_gate: CommitGateState,
    /// Short epoch-swap gate independent from checkpoint I/O.
    visibility_gate: VisibilityGateState,
    /// Mutations admitted before closing and not yet fully checkpointed or abandoned.
    active_mutations: DriverShared<AtomicU32>,
}

impl VolumeRuntime {
    /// Separates one completed mount into the runtime's independent state domains.
    /// # Errors
    ///
    /// Returns an error when the initial epoch registry or mount-scoped CNG providers cannot be
    /// allocated and initialized.
    pub(crate) fn try_new(mount: CompletedMount, storage: MountedStorage) -> DriverResult<Self> {
        let (profile, epoch, coordinator) = mount.into_parts();
        let crypto = CngProvider::try_open()?;
        Ok(Self {
            profile,
            epochs: EpochRegistry::try_new(epoch)?,
            coordinator,
            storage,
            crypto,
            failure: VolumeFailureState::Operational,
            commit_gate: CommitGateState::Ready,
            visibility_gate: VisibilityGateState::Ready,
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

    /// Mount-scoped algorithm providers used to prebuild operation-owned CNG objects.
    pub(crate) const fn crypto(&self) -> &CngProvider {
        &self.crypto
    }

    /// Whether journal space has no granted commit or published overlay awaiting checkpoint.
    pub(crate) fn journal_is_clean(&self) -> bool {
        self.active_mutations.get().load(Ordering::Acquire) == 0
            && matches!(self.commit_gate, CommitGateState::Ready)
    }

    /// Acquires one current immutable epoch for a read or resolve operation.
    /// # Errors
    ///
    /// Returns an error when reads are no longer authorized.
    pub(crate) fn acquire_epoch(&mut self) -> DriverResult<EpochLease> {
        self.failure.authorize_read()?;
        self.epochs.acquire_current()
    }

    /// Current epoch for one non-suspending projection.
    pub(crate) fn current_epoch(&self) -> &CommittedEpoch {
        self.epochs.current()
    }

    /// Mutation coordinator under reactor-issued intent/commit capability.
    pub(crate) const fn coordinator(&self) -> &MutationCoordinatorState {
        &self.coordinator
    }

    /// Allocates one stable FIFO mutation ticket before resolve begins.
    /// # Errors
    ///
    /// Returns an error when mutations are no longer authorized or ticket allocation overflows.
    pub(crate) fn admit_mutation(&mut self) -> DriverResult<(u64, MutationActivityLease)> {
        self.failure.authorize_mutation()?;
        let activity = MutationActivityLease::acquire(&self.active_mutations)?;
        let ticket = self
            .coordinator
            .admit_mutation()
            .map_err(DriverError::from)?;
        Ok((ticket, activity))
    }

    /// Mutable coordinator used only by infallible visibility/checkpoint publication.
    fn coordinator_mut(&mut self) -> &mut MutationCoordinatorState {
        &mut self.coordinator
    }

    /// Reserves both post-commit epoch slots while allocation failure remains harmless.
    /// # Errors
    ///
    /// Returns an error when mutations are not authorized or stable epoch storage cannot be
    /// allocated.
    pub(crate) fn reserve_epoch_publication(&mut self) -> DriverResult<EpochPublicationSlots> {
        self.failure.authorize_mutation()?;
        self.epochs.reserve_publication()
    }

    /// Grants the commit slot if this ticket is currently eligible.
    pub(crate) fn try_grant_commit(&mut self, ticket: u64) -> Option<ext4_core::CommitLease> {
        if self.failure.authorize_mutation().is_err() {
            return None;
        }
        match self.commit_gate {
            CommitGateState::Ready => {
                self.commit_gate = CommitGateState::CommitGranted { ticket };
                Some(ext4_core::CommitLease::granted(ticket))
            }
            CommitGateState::CommitGranted { .. }
            | CommitGateState::CheckpointPending { .. }
            | CommitGateState::CheckpointGranted { .. } => None,
        }
    }

    /// Releases a commit grant before the first lower write was issued.
    pub(crate) fn abandon_commit(&mut self, ticket: u64) {
        if self.commit_gate == (CommitGateState::CommitGranted { ticket }) {
            self.commit_gate = CommitGateState::Ready;
        }
    }

    /// Grants the short visibility swap independently of checkpoint I/O.
    pub(crate) fn try_grant_visibility(&mut self, ticket: u64) -> Option<VisibilityLease> {
        if self.commit_gate != (CommitGateState::CommitGranted { ticket })
            || self.visibility_gate != VisibilityGateState::Ready
        {
            return None;
        }
        self.visibility_gate = VisibilityGateState::Granted { ticket };
        Some(VisibilityLease::granted(ticket))
    }

    /// Grants the detached checkpoint operation after durable visibility publication.
    pub(crate) fn try_grant_checkpoint(
        &mut self,
        epoch: EpochSequence,
    ) -> Option<ext4_core::CheckpointLease> {
        if self.commit_gate != (CommitGateState::CheckpointPending { epoch }) {
            return None;
        }
        self.commit_gate = CommitGateState::CheckpointGranted { epoch };
        Some(ext4_core::CheckpointLease::granted(epoch))
    }

    /// Allocation-free durable epoch publication after a matching visibility grant.
    pub(crate) fn publish_durable(
        &mut self,
        mutation: DurableMutation,
        visibility: VisibilityLease,
        durable_slot: EpochPublicationSlot,
        checkpoint_slot: EpochPublicationSlot,
    ) -> PendingCheckpoint {
        let ticket = visibility.ticket();
        if self.commit_gate != (CommitGateState::CommitGranted { ticket }) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        if self.visibility_gate != (VisibilityGateState::Granted { ticket }) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let published: PublishedMutation = mutation.publish(self.coordinator_mut(), visibility);
        let (epoch, checkpoint) = published.into_parts();
        let sequence = epoch.sequence();
        self.epochs.publish(durable_slot, epoch);
        self.commit_gate = CommitGateState::CheckpointPending { epoch: sequence };
        self.visibility_gate = VisibilityGateState::Ready;
        PendingCheckpoint {
            epoch: sequence,
            operation: checkpoint,
            publication: checkpoint_slot,
        }
    }

    /// Installs a completed overlay-free checkpoint and releases journal space.
    pub(crate) fn publish_checkpoint(
        &mut self,
        durability: CleanJournalDurability,
        publication: EpochPublicationSlot,
        epoch: EpochSequence,
    ) {
        if self.commit_gate != (CommitGateState::CheckpointGranted { epoch }) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let checkpointed = durability.completed(self.coordinator_mut());
        self.epochs.publish(publication, checkpointed);
        self.commit_gate = CommitGateState::Ready;
    }

    /// Moves a confirmed durable abort into read-only state.
    pub(crate) fn record_durable_abort(&mut self) {
        self.failure = self.failure.durable_abort();
    }

    /// Marks commit/abort/data effects as unknown and requires a fresh replay mount.
    pub(crate) fn record_durability_unknown(&mut self) {
        self.failure = self.failure.durability_unknown();
    }

    /// Marks lower reads untrustworthy.
    pub(crate) fn record_read_unreliable(&mut self) {
        self.failure = self.failure.read_unreliable();
    }

    /// Records an exact post-commit Cc/MM publication failure.
    pub(crate) fn record_publication_failure(&mut self, status: NTSTATUS) {
        self.failure = self.failure.publication_failed(status);
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
    use super::{VolumeFailureState, VolumeRuntime};

    /// # Panics
    ///
    /// Panics when failure-state transitions weaken an already stronger failure.
    #[test]
    fn volume_failure_transitions_are_monotonic() {
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
        let publication = VolumeFailureState::Operational.publication_failed(publication_status);
        assert_eq!(
            publication.authorize_mutation(),
            Err(crate::kernel::status::DriverError::CacheManagerFailure(
                publication_status
            ))
        );
        assert_eq!(publication.durable_abort(), publication);
    }

    /// Keeps serialized commit, visibility, and checkpoint grants in the unit-test production
    /// graph even though constructing a mounted runtime belongs to mount integration tests.
    ///
    /// # Panics
    ///
    /// This test has no runtime failure path. Compilation fails if these gates cease to be one
    /// explicit state-machine boundary.
    #[test]
    fn durability_gate_boundaries_remain_linked() {
        let _clean: fn(&VolumeRuntime) -> bool = VolumeRuntime::journal_is_clean;
        let _commit: fn(&mut VolumeRuntime, u64) -> Option<ext4_core::CommitLease> =
            VolumeRuntime::try_grant_commit;
        let _abandon: fn(&mut VolumeRuntime, u64) = VolumeRuntime::abandon_commit;
        let _visibility: fn(&mut VolumeRuntime, u64) -> Option<ext4_core::VisibilityLease> =
            VolumeRuntime::try_grant_visibility;
        let _checkpoint: fn(
            &mut VolumeRuntime,
            ext4_core::EpochSequence,
        ) -> Option<ext4_core::CheckpointLease> = VolumeRuntime::try_grant_checkpoint;
    }
}
