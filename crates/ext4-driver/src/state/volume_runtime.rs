//! Mounted profile, bounded epoch leases, mutation coordination, and volume failure state.

use core::fmt;
use core::ptr::NonNull;

use ext4_core::{
    CheckpointOperation, CleanJournalDurability, CommittedEpoch, CompletedMount, DurableMutation,
    EpochSequence, FscryptKeyIdentifier, FscryptKeyPresence, MountedProfile,
    MutationCoordinatorState, PublishedMutation, VisibilityLease,
};

use crate::irp::reactor::MAX_OPERATIONS;
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::MountedStorageDevices;

/// Current epoch plus one distinct retained epoch per operation and two pre-commit publication
/// reservations.
const MAX_EPOCH_SLOTS: usize = MAX_OPERATIONS + 2;

/// Volume reliability state after lower-device or checkpoint failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeFailureState {
    /// Reads and journaled mutations remain admitted.
    Operational,
    /// Existing committed data remains readable, but no new mutation may start.
    DegradedReadOnly,
    /// Journal replay or durability is unknown and this runtime must be torn down.
    RecoveryRequired,
    /// Lower reads are no longer trustworthy.
    Failed,
}

impl VolumeFailureState {
    /// Rejects a new mutation unless the runtime is fully operational.
    pub(crate) fn authorize_mutation(self) -> DriverResult<()> {
        match self {
            Self::Operational => Ok(()),
            Self::DegradedReadOnly | Self::RecoveryRequired | Self::Failed => {
                Err(DriverError::VolumeDismounted)
            }
        }
    }

    /// Rejects reads only after read reliability itself has been lost.
    pub(crate) fn authorize_read(self) -> DriverResult<()> {
        match self {
            Self::Operational | Self::DegradedReadOnly => Ok(()),
            Self::RecoveryRequired | Self::Failed => Err(DriverError::VolumeDismounted),
        }
    }

    /// Moves to a durable-abort read-only state without weakening a stronger prior failure.
    const fn durable_abort(self) -> Self {
        match self {
            Self::Operational => Self::DegradedReadOnly,
            Self::DegradedReadOnly | Self::RecoveryRequired | Self::Failed => self,
        }
    }

    /// Moves to recovery-required when commit/abort/data durability is unknown.
    const fn durability_unknown(self) -> Self {
        match self {
            Self::Operational | Self::DegradedReadOnly => Self::RecoveryRequired,
            Self::RecoveryRequired | Self::Failed => self,
        }
    }

    /// Moves to terminal failure once reads cannot be trusted.
    const fn read_unreliable(self) -> Self {
        Self::Failed
    }
}

/// One fixed registry slot with lifecycle encoded by its variant.
enum EpochSlot {
    /// Available for a pre-write publication reservation.
    Vacant {
        /// Last generation used by this slot.
        generation: u64,
    },
    /// Reserved before the first lower write; publication into this slot cannot fail.
    Reserved {
        /// Generation uniquely identifying this reservation.
        generation: u64,
    },
    /// Immutable epoch retained by the current pointer or outstanding leases.
    Occupied {
        /// Generation checked by every lease.
        generation: u64,
        /// Immutable committed state.
        epoch: CommittedEpoch,
        /// Number of outstanding operation leases.
        leases: u8,
        /// Whether new reads acquire this slot.
        current: bool,
    },
}

impl fmt::Debug for EpochSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vacant { generation } => formatter
                .debug_struct("Vacant")
                .field("generation", generation)
                .finish(),
            Self::Reserved { generation } => formatter
                .debug_struct("Reserved")
                .field("generation", generation)
                .finish(),
            Self::Occupied {
                generation,
                epoch,
                leases,
                current,
            } => formatter
                .debug_struct("Occupied")
                .field("generation", generation)
                .field("epoch", &epoch.sequence())
                .field("leases", leases)
                .field("current", current)
                .finish(),
        }
    }
}

/// Fixed, allocation-free registry retaining committed epochs without `Arc`.
#[derive(Debug)]
pub(crate) struct EpochRegistry {
    /// Current and retained epoch slots.
    slots: [EpochSlot; MAX_EPOCH_SLOTS],
    /// Slot selected for new read leases.
    current: usize,
}

impl EpochRegistry {
    /// Installs the initial mount epoch without allocation.
    pub(crate) fn new(initial: CommittedEpoch) -> Self {
        let mut slots = core::array::from_fn(|_| EpochSlot::Vacant { generation: 0 });
        slots[0] = EpochSlot::Occupied {
            generation: 1,
            epoch: initial,
            leases: 0,
            current: true,
        };
        Self { slots, current: 0 }
    }

    /// Acquires one non-cloneable lease on the current immutable epoch.
    /// # Errors
    ///
    /// Returns an invariant error if the bounded active-operation count cannot fit the lease field.
    pub(crate) fn acquire_current(&mut self) -> DriverResult<EpochLease> {
        let index = self.current;
        let generation = {
            let Some(slot) = self.slots.get_mut(index) else {
                return Err(DriverError::InternalInvariantViolation);
            };
            let EpochSlot::Occupied {
                generation,
                leases,
                current: true,
                ..
            } = slot
            else {
                return Err(DriverError::InternalInvariantViolation);
            };
            *leases = leases
                .checked_add(1)
                .ok_or(DriverError::InternalInvariantViolation)?;
            *generation
        };
        Ok(EpochLease {
            registry: NonNull::from(&mut *self),
            index,
            generation,
        })
    }

    /// Borrows the current epoch for one non-suspending reactor transition.
    pub(crate) fn current(&self) -> &CommittedEpoch {
        match self.slots.get(self.current) {
            Some(EpochSlot::Occupied {
                epoch,
                current: true,
                ..
            }) => epoch,
            _ => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
        }
    }

    /// Reserves both durable and checkpoint epoch slots before any lower write is issued.
    /// # Errors
    ///
    /// Returns insufficient resources if long-lived readers exhaust the bounded registry or a
    /// slot generation cannot advance.
    /// # Safety
    ///
    /// The registry must already reside in its final mounted VCB address and remain live until both
    /// returned reservations are published or dropped on the reactor thread.
    pub(crate) unsafe fn reserve_publication(&mut self) -> DriverResult<EpochPublicationSlots> {
        let mut indices =
            self.slots.iter().enumerate().filter_map(|(index, slot)| {
                matches!(slot, EpochSlot::Vacant { .. }).then_some(index)
            });
        let durable_index = indices.next().ok_or(DriverError::InsufficientResources)?;
        let checkpoint_index = indices.next().ok_or(DriverError::InsufficientResources)?;
        let durable_generation = next_slot_generation(
            self.slots
                .get(durable_index)
                .ok_or(DriverError::InternalInvariantViolation)?,
        )?;
        let checkpoint_generation = next_slot_generation(
            self.slots
                .get(checkpoint_index)
                .ok_or(DriverError::InternalInvariantViolation)?,
        )?;
        self.slots[durable_index] = EpochSlot::Reserved {
            generation: durable_generation,
        };
        self.slots[checkpoint_index] = EpochSlot::Reserved {
            generation: checkpoint_generation,
        };
        let registry = NonNull::from(self);
        Ok(EpochPublicationSlots {
            durable: EpochPublicationSlot {
                registry,
                index: durable_index,
                generation: durable_generation,
                consumed: false,
            },
            checkpoint: EpochPublicationSlot {
                registry,
                index: checkpoint_index,
                generation: checkpoint_generation,
                consumed: false,
            },
        })
    }

    /// Releases one lease and recycles a non-current epoch as soon as its count reaches zero.
    fn release(&mut self, index: usize, generation: u64) {
        let Some(slot) = self.slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let EpochSlot::Occupied {
            generation: current_generation,
            leases,
            current,
            ..
        } = slot
        else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if *current_generation != generation || *leases == 0 {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *leases -= 1;
        if *leases == 0 && !*current {
            *slot = EpochSlot::Vacant { generation };
        }
    }

    /// Publishes one pre-reserved immutable epoch by moves and fixed-slot replacement only.
    fn publish(&mut self, index: usize, generation: u64, epoch: CommittedEpoch) {
        let Some(target) = self.slots.get(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !matches!(target, EpochSlot::Reserved { generation: current } if *current == generation)
        {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let previous = self.current;
        let Some(previous_slot) = self.slots.get_mut(previous) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        match previous_slot {
            EpochSlot::Occupied {
                generation,
                leases,
                current,
                ..
            } if *current => {
                *current = false;
                if *leases == 0 {
                    let generation = *generation;
                    *previous_slot = EpochSlot::Vacant { generation };
                }
            }
            EpochSlot::Vacant { .. } | EpochSlot::Reserved { .. } | EpochSlot::Occupied { .. } => {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
        self.slots[index] = EpochSlot::Occupied {
            generation,
            epoch,
            leases: 0,
            current: true,
        };
        self.current = index;
    }

    /// Rolls back one unused pre-write reservation.
    fn release_reservation(&mut self, index: usize, generation: u64) {
        let Some(slot) = self.slots.get_mut(index) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        if !matches!(slot, EpochSlot::Reserved { generation: current } if *current == generation) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *slot = EpochSlot::Vacant { generation };
    }
}

/// Returns the next reservation generation for one vacant slot.
fn next_slot_generation(slot: &EpochSlot) -> DriverResult<u64> {
    let EpochSlot::Vacant { generation } = slot else {
        return Err(DriverError::InternalInvariantViolation);
    };
    generation
        .checked_add(1)
        .ok_or(DriverError::InsufficientResources)
}

/// Non-cloneable immutable epoch capability owned by one operation.
pub(crate) struct EpochLease {
    /// Stable mounted registry.
    registry: NonNull<EpochRegistry>,
    /// Fixed slot index.
    index: usize,
    /// Slot generation preventing stale reuse.
    generation: u64,
}

impl EpochLease {
    /// Borrows the immutable epoch selected when this lease was acquired.
    pub(crate) fn epoch(&self) -> &CommittedEpoch {
        let registry = unsafe {
            // SAFETY: The VCB outlives every operation lease and teardown drains operations first.
            self.registry.as_ref()
        };
        match registry.slots.get(self.index) {
            Some(EpochSlot::Occupied {
                generation, epoch, ..
            }) if *generation == self.generation => epoch,
            _ => KernelWideInconsistency::completion_reactor_state_corruption().bugcheck(),
        }
    }
}

impl fmt::Debug for EpochLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochLease")
            .field("index", &self.index)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Drop for EpochLease {
    fn drop(&mut self) {
        let registry = unsafe {
            // SAFETY: Reactor teardown drains every lease before releasing the stable VCB.
            self.registry.as_mut()
        };
        registry.release(self.index, self.generation);
    }
}

// SAFETY: The lease is moved only among reactor state and completion envelopes; release occurs on
// the sole reactor thread after lower-buffer ownership ends.
unsafe impl Send for EpochLease {}

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

/// One pre-reserved infallible epoch publication target.
pub(crate) struct EpochPublicationSlot {
    /// Stable registry address.
    registry: NonNull<EpochRegistry>,
    /// Fixed target index.
    index: usize,
    /// Reservation generation.
    generation: u64,
    /// Whether publication already consumed this reservation.
    consumed: bool,
}

impl EpochPublicationSlot {
    /// Publishes an already-built epoch without allocation or an ordinary failure path.
    pub(crate) fn publish(mut self, epoch: CommittedEpoch) {
        let registry = unsafe {
            // SAFETY: The reservation contract keeps the mounted registry stable and uniquely
            // reactor-owned for publication.
            self.registry.as_mut()
        };
        registry.publish(self.index, self.generation, epoch);
        self.consumed = true;
    }
}

impl fmt::Debug for EpochPublicationSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochPublicationSlot")
            .field("index", &self.index)
            .field("generation", &self.generation)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl Drop for EpochPublicationSlot {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }
        let registry = unsafe {
            // SAFETY: An unpublished reservation remains uniquely owned by this token.
            self.registry.as_mut()
        };
        registry.release_reservation(self.index, self.generation);
    }
}

// SAFETY: Publication tokens move only among reactor-owned operation state.
unsafe impl Send for EpochPublicationSlot {}

/// Commit/checkpoint gate state for the currently supported one-transaction journal profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitGateState {
    /// Journal space is clean and one commit may be granted.
    Ready,
    /// One mutation owns commit authority through durable visibility publication.
    CommitGranted { ticket: u64 },
    /// A visible overlay is awaiting independent checkpoint and journal-space release.
    CheckpointPending { epoch: EpochSequence },
    /// The detached checkpoint operation owns journal-space release authority.
    CheckpointGranted { epoch: EpochSequence },
}

/// Short allocation-free visibility gate, separate from checkpoint ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisibilityGateState {
    /// No durable epoch is being installed.
    Ready,
    /// One durable mutation owns the sole epoch-swap transition.
    Granted { ticket: u64 },
}

/// Driver-local mounted runtime split into immutable profile, immutable epochs, and mutable
/// mutation coordination.
#[derive(Debug)]
pub(crate) struct VolumeRuntime {
    /// Immutable feature, geometry, and device identity.
    profile: MountedProfile,
    /// Bounded immutable epoch registry.
    epochs: EpochRegistry,
    /// Journal cursor, allocation state, and resource versions.
    coordinator: MutationCoordinatorState,
    /// Validated lower-device geometry and completion owner.
    storage: MountedStorageDevices,
    /// Current read/write reliability state.
    failure: VolumeFailureState,
    /// Serialized commit/checkpoint ownership.
    commit_gate: CommitGateState,
    /// Short epoch-swap gate independent from checkpoint I/O.
    visibility_gate: VisibilityGateState,
}

impl VolumeRuntime {
    /// Separates one completed mount into the runtime's independent state domains.
    pub(crate) fn new(mount: CompletedMount, storage: MountedStorageDevices) -> Self {
        let (profile, epoch, coordinator) = mount.into_parts();
        Self {
            profile,
            epochs: EpochRegistry::new(epoch),
            coordinator,
            storage,
            failure: VolumeFailureState::Operational,
            commit_gate: CommitGateState::Ready,
            visibility_gate: VisibilityGateState::Ready,
        }
    }

    /// Immutable mount profile.
    pub(crate) const fn profile(&self) -> &MountedProfile {
        &self.profile
    }

    /// Validated mounted lower devices.
    pub(crate) const fn storage(&self) -> MountedStorageDevices {
        self.storage
    }

    /// Whether journal space has no granted commit or published overlay awaiting checkpoint.
    pub(crate) const fn journal_is_clean(&self) -> bool {
        matches!(self.commit_gate, CommitGateState::Ready)
    }

    /// Acquires one current immutable epoch for a read or resolve operation.
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
    pub(crate) fn admit_mutation(&mut self) -> DriverResult<u64> {
        self.failure.authorize_mutation()?;
        self.coordinator.admit_mutation().map_err(DriverError::from)
    }

    /// Mutable coordinator used only by infallible visibility/checkpoint publication.
    fn coordinator_mut(&mut self) -> &mut MutationCoordinatorState {
        &mut self.coordinator
    }

    /// Reserves both post-commit epoch slots while allocation failure remains harmless.
    /// # Safety
    ///
    /// This runtime must already reside inside its final heap-stable VCB.
    pub(crate) unsafe fn reserve_epoch_publication(
        &mut self,
    ) -> DriverResult<EpochPublicationSlots> {
        self.failure.authorize_mutation()?;
        unsafe {
            // SAFETY: The caller extends this runtime's stable-address guarantee to the registry.
            self.epochs.reserve_publication()
        }
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
        durable_slot.publish(epoch);
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
        publication.publish(checkpointed);
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
    }
}
