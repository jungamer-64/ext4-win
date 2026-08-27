//! Immutable mount profile, committed epochs, and mutation coordinator state.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::orphan::{OrphanRecoveryQueue, ValidatedOrphanInventory};
use super::scope::*;
use super::transaction::{
    ORPHAN_METADATA_BUDGET, OrphanBatchCompletion, StorageRequestSequence,
    StorageRequestSequenceStep, prepare_orphan_batch,
};
use crate::disk::storage::{
    OperationDevice, StorageReadOverlay, StorageRequestIdentity, StorageTarget, StorageTranscript,
};
use crate::disk_format::journal::{
    CleanJournal, ExternalJournalLoad, Journal, JournalRecoveryOperation, LoadedJournal,
    MetadataBlock,
};
use crate::disk_format::superblock::{
    ChecksumInvalidSuperblock, FilesystemUuid, JournalMode, JournalUuid, PrimarySuperblockRead,
    WriteSessionState,
};

/// Maximum distinct resources whose committed versions are tracked by one mounted volume.
const MAX_TRACKED_RESOURCES: usize = 4096;

/// Opaque resource identity used by scheduler intent arbitration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationResource {
    /// Resource domain kept private from the scheduler.
    domain: MutationResourceDomain,
    /// Domain-local stable identity.
    identity: u64,
}

/// Internal domain of a mutation resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationResourceDomain {
    /// One inode record and its node-visible metadata.
    Inode,
    /// One block group whose descriptor or allocation bitmap is staged.
    BlockGroup,
    /// Primary superblock counters or label.
    VolumeMetadata,
    /// Mount-scoped fscrypt key snapshot.
    KeySet,
}

impl MutationResource {
    /// Builds an inode resource identity.
    pub(crate) fn inode(inode: InodeId) -> Self {
        Self {
            domain: MutationResourceDomain::Inode,
            identity: u64::from(inode.as_u32()),
        }
    }

    /// Builds a block-group resource identity.
    pub(crate) fn block_group(group: BlockGroupId) -> Self {
        Self {
            domain: MutationResourceDomain::BlockGroup,
            identity: u64::from(group.as_u32()),
        }
    }

    /// Resource identity for primary volume metadata.
    pub const VOLUME_METADATA: Self = Self {
        domain: MutationResourceDomain::VolumeMetadata,
        identity: 0,
    };

    /// Resource identity for the mount-scoped key snapshot.
    pub const KEY_SET: Self = Self {
        domain: MutationResourceDomain::KeySet,
        identity: 0,
    };
}

/// Monotonic version of one mutation resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceVersion(u64);

impl ResourceVersion {
    /// Initial version for a resource not yet changed after mount.
    const INITIAL: Self = Self(0);

    /// Computes the next committed version before the first lower write.
    /// # Errors
    ///
    /// Returns [`Error::ArithmeticOverflow`] when the version space is exhausted.
    fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(Error::ArithmeticOverflow)
    }
}

/// One resource/version pair observed by mutation resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedResourceVersion {
    /// Resource selected by the resolved plan.
    resource: MutationResource,
    /// Version observed while resolving.
    version: ResourceVersion,
}

/// Resource set and versions recorded by one resolved mutation.
#[derive(Debug)]
pub struct ObservedResourceVersionSet {
    /// FIFO ticket retained across version-mismatch re-resolution.
    ticket: u64,
    /// Unique resources in discovery order.
    entries: Vec<ObservedResourceVersion>,
}

impl ObservedResourceVersionSet {
    /// Starts an empty observed set for one stable FIFO ticket.
    pub(crate) const fn new(ticket: u64) -> Self {
        Self {
            ticket,
            entries: Vec::new(),
        }
    }

    /// Adds one unique resource and its current version without infallible growth.
    /// # Errors
    ///
    /// Returns an allocation or capacity error when the observed set cannot retain the resource.
    pub(crate) fn include(
        &mut self,
        resource: MutationResource,
        version: ResourceVersion,
    ) -> Result<()> {
        if self.entries.iter().any(|entry| entry.resource == resource) {
            return Ok(());
        }
        self.entries
            .try_push(ObservedResourceVersion { resource, version })
    }

    /// FIFO ticket preserved when a stale plan returns to resolution.
    #[must_use]
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }

    /// Returns true when both sets describe the same resources, independent of discovery order.
    pub fn has_same_resources(&self, other: &Self) -> bool {
        self.entries.len() == other.entries.len()
            && self.entries.iter().all(|left| {
                other
                    .entries
                    .iter()
                    .any(|right| right.resource == left.resource)
            })
    }

    /// Iterates opaque resources for scheduler intent acquisition.
    pub fn resources(&self) -> impl ExactSizeIterator<Item = MutationResource> + '_ {
        self.entries.iter().map(|entry| entry.resource)
    }
}

/// One populated entry in the fixed resource-version table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceVersionEntry {
    /// Tracked resource.
    resource: MutationResource,
    /// Current committed version.
    version: ResourceVersion,
}

/// Bounded table cloned before commit so post-durability publication cannot fail.
#[derive(Debug)]
struct ResourceVersionTable {
    /// Populated entries, bounded independently of allocator capacity.
    entries: Vec<ResourceVersionEntry>,
}

impl ResourceVersionTable {
    /// Builds an empty version table without allocation or a large stack object.
    const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Fallibly copies the current table before the first lower write.
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the independent publication table cannot be allocated.
    fn try_clone(&self) -> Result<Self> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in self.entries.iter().copied() {
            entries.try_push(entry)?;
        }
        Ok(Self { entries })
    }

    /// Looks up one resource, treating absent entries as the initial version.
    fn version(&self, resource: MutationResource) -> ResourceVersion {
        self.entries
            .iter()
            .find(|entry| entry.resource == resource)
            .map_or(ResourceVersion::INITIAL, |entry| entry.version)
    }

    /// Advances one resource in this private pre-publication table.
    /// # Errors
    ///
    /// Returns an error when the version overflows, the table bound is exhausted, or storage for
    /// a new entry cannot be allocated.
    fn advance(&mut self, resource: MutationResource) -> Result<()> {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.resource == resource)
        {
            entry.version = entry.version.next()?;
            return Ok(());
        }
        if self.entries.len() >= MAX_TRACKED_RESOURCES {
            return Err(Error::OutOfMemory);
        }
        self.entries.try_push(ResourceVersionEntry {
            resource,
            version: ResourceVersion::INITIAL.next()?,
        })?;
        Ok(())
    }
}

/// Complete next version table allocated and validated before the first lower write.
#[derive(Debug)]
pub(crate) struct ResourceVersionPublication {
    /// Table moved into the coordinator at infallible publish.
    next: ResourceVersionTable,
}

/// Stable filesystem identity exposed outside the raw superblock domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeIdentity {
    /// Filesystem UUID.
    uuid: crate::disk_format::superblock::FilesystemUuid,
    /// Filesystem volume label from the selected committed epoch.
    label: Ext4VolumeLabel,
}

impl VolumeIdentity {
    /// Filesystem UUID.
    #[must_use]
    pub const fn uuid(self) -> crate::disk_format::superblock::FilesystemUuid {
        self.uuid
    }

    /// Filesystem volume label.
    #[must_use]
    pub const fn label(self) -> Ext4VolumeLabel {
        self.label
    }
}

/// Allocation geometry projected from one committed epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeGeometry {
    /// Filesystem block size.
    block_size: BlockSize,
    /// Allocation cluster size.
    cluster_size: crate::disk_format::superblock::ClusterSize,
    /// Total allocation cluster count.
    cluster_count: crate::disk_format::superblock::ClusterCount,
    /// Free allocation clusters in the selected committed epoch.
    free_cluster_count: FreeClusterCount,
}

impl VolumeGeometry {
    /// Filesystem block size.
    #[must_use]
    pub const fn block_size(self) -> BlockSize {
        self.block_size
    }

    /// Allocation cluster size.
    #[must_use]
    pub const fn cluster_size(self) -> crate::disk_format::superblock::ClusterSize {
        self.cluster_size
    }

    /// Total allocation cluster count.
    #[must_use]
    pub const fn cluster_count(self) -> crate::disk_format::superblock::ClusterCount {
        self.cluster_count
    }

    /// Free allocation clusters in the selected committed epoch.
    #[must_use]
    pub const fn free_cluster_count(self) -> FreeClusterCount {
        self.free_cluster_count
    }
}

/// Monotonic identity of one immutable committed filesystem epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpochSequence(u64);

impl EpochSequence {
    /// Initial epoch published by a successful fresh mount.
    pub(crate) const INITIAL: Self = Self(0);

    /// Returns the next sequence, or an invariant error on exhaustion.
    /// # Errors
    ///
    /// Returns [`Error::ArithmeticOverflow`] when the epoch sequence is exhausted.
    pub(crate) fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Raw sequence value for bounded registry bookkeeping.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Immutable feature, geometry, device, and journal identity established at mount.
#[derive(Debug)]
pub struct MountedProfile {
    /// Validated feature and fixed geometry fields.
    superblock: Superblock,
    /// Filesystem device length validated at the storage boundary.
    filesystem_length: DeviceLength,
    /// Device that stores the JBD2 log.
    journal_target: StorageTarget,
}

impl MountedProfile {
    /// Builds the immutable profile after replay has established a supported filesystem.
    pub(crate) const fn new(
        superblock: Superblock,
        filesystem_length: DeviceLength,
        journal_target: StorageTarget,
    ) -> Self {
        Self {
            superblock,
            filesystem_length,
            journal_target,
        }
    }

    /// Validated filesystem device length.
    #[must_use]
    pub const fn filesystem_length(&self) -> DeviceLength {
        self.filesystem_length
    }

    /// Filesystem block size fixed for the lifetime of the mount.
    #[must_use]
    pub const fn block_size(&self) -> BlockSize {
        self.superblock.block_size()
    }

    /// Device that stores journal records for this mount.
    #[must_use]
    pub const fn journal_target(&self) -> StorageTarget {
        self.journal_target
    }
}

/// Immutable state visible to readers after one commit publication.
#[derive(Debug)]
pub struct CommittedEpoch {
    /// Monotonic registry identity.
    sequence: EpochSequence,
    /// Current counters, label, and checksum policy source.
    pub(super) superblock: Superblock,
    /// Mount-scoped fscrypt key snapshot.
    pub(super) fscrypt_keys: FscryptKeySet,
    /// Committed allocation-cluster ownership.
    pub(super) clusters: ClusterReferenceIndex,
    /// Durable journal metadata not yet copied to home blocks.
    pub(super) overlay: Vec<MetadataBlock>,
}

impl CommittedEpoch {
    /// Builds the initial committed epoch after successful replay and mount validation.
    pub(super) const fn initial(
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: ClusterReferenceIndex,
    ) -> Self {
        Self {
            sequence: EpochSequence::INITIAL,
            superblock,
            fscrypt_keys,
            clusters,
            overlay: Vec::new(),
        }
    }

    /// Builds a post-commit epoch from values allocated before the first lower write.
    pub(super) const fn prepared(
        sequence: EpochSequence,
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: ClusterReferenceIndex,
        overlay: Vec<MetadataBlock>,
    ) -> Self {
        Self {
            sequence,
            superblock,
            fscrypt_keys,
            clusters,
            overlay,
        }
    }

    /// This epoch's monotonic identity.
    #[must_use]
    pub const fn sequence(&self) -> EpochSequence {
        self.sequence
    }

    /// Stable identity with the label from this epoch.
    #[must_use]
    pub const fn identity(&self) -> VolumeIdentity {
        VolumeIdentity {
            uuid: self.superblock.uuid(),
            label: self.superblock.volume_label(),
        }
    }

    /// Allocation geometry and current free count from this epoch.
    #[must_use]
    pub const fn geometry(&self) -> VolumeGeometry {
        VolumeGeometry {
            block_size: self.superblock.block_size(),
            cluster_size: self.superblock.cluster_size(),
            cluster_count: self.superblock.cluster_count(),
            free_cluster_count: self.superblock.free_cluster_count(),
        }
    }

    /// Returns this epoch's fscrypt key presence for one identifier.
    #[must_use]
    pub fn fscrypt_key_presence(&self, identifier: FscryptKeyIdentifier) -> FscryptKeyPresence {
        if self.fscrypt_keys.contains(identifier) {
            FscryptKeyPresence::Present
        } else {
            FscryptKeyPresence::Absent
        }
    }
}

impl StorageReadOverlay for CommittedEpoch {
    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if target != StorageTarget::Filesystem || out.is_empty() {
            return Ok(());
        }
        let request_start = offset.get();
        let request_end = request_start
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        for image in &self.overlay {
            let image_start = self.superblock.block_size().offset_of(image.block())?.get();
            let image_end = image_start
                .checked_add(
                    u64::try_from(image.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let overlap_start = core::cmp::max(request_start, image_start);
            let overlap_end = core::cmp::min(request_end, image_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let target_start = usize::try_from(
                overlap_start
                    .checked_sub(request_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let target_end = usize::try_from(
                overlap_end
                    .checked_sub(request_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let source_start = usize::try_from(
                overlap_start
                    .checked_sub(image_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let source_end = usize::try_from(
                overlap_end
                    .checked_sub(image_start)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            memory::copy_exact(
                out.get_mut(target_start..target_end)
                    .ok_or(Error::DeviceRange)?,
                image
                    .bytes()
                    .get(source_start..source_end)
                    .ok_or(Error::DeviceRange)?,
            )?;
        }
        Ok(())
    }
}

/// Journal coordinator phase. A new commit is granted only in `Ready`.
#[derive(Debug)]
pub(crate) enum JournalCoordinatorState {
    /// Clean journal with space available for one commit.
    Ready(Journal<CleanJournal>),
    /// Commit is visible, while an independent checkpoint still owns the dirty journal state.
    CheckpointPending,
}

/// Mutable journal cursor, resource versions, and allocation reservations.
#[derive(Debug)]
pub struct MutationCoordinatorState {
    /// Current journal phase.
    pub(crate) journal: JournalCoordinatorState,
    /// Monotonic FIFO ticket assigned to the next mutation admission.
    next_ticket: u64,
    /// Fixed-capacity committed resource versions.
    resource_versions: ResourceVersionTable,
}

impl MutationCoordinatorState {
    /// Builds coordinator state after mount replay has produced a clean journal.
    pub(crate) const fn new(journal: Journal<CleanJournal>) -> Self {
        Self {
            journal: JournalCoordinatorState::Ready(journal),
            next_ticket: 0,
            resource_versions: ResourceVersionTable::empty(),
        }
    }

    /// Allocates one stable FIFO ticket without wrapping.
    /// # Errors
    ///
    /// Returns [`Error::ArithmeticOverflow`] when the FIFO ticket space is exhausted.
    pub fn admit_mutation(&mut self) -> Result<u64> {
        let ticket = self.next_ticket;
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(ticket)
    }

    /// Current committed version of one resource.
    pub(crate) fn resource_version(&self, resource: MutationResource) -> ResourceVersion {
        self.resource_versions.version(resource)
    }

    /// Revalidates every resource observed by a resolved mutation.
    pub(crate) fn revalidate(&self, observed: &ObservedResourceVersionSet) -> bool {
        observed
            .entries
            .iter()
            .all(|entry| self.resource_versions.version(entry.resource) == entry.version)
    }

    /// Prepares the complete next version table while failure is still harmless.
    /// # Errors
    ///
    /// Returns an error when observed versions are stale, the fixed table is exhausted, or a
    /// resource version cannot advance.
    pub(crate) fn prepare_version_publication(
        &self,
        observed: &ObservedResourceVersionSet,
    ) -> Result<ResourceVersionPublication> {
        if !self.revalidate(observed) {
            return Err(Error::ClusterReferenceConflict);
        }
        let mut next = self.resource_versions.try_clone()?;
        for entry in &observed.entries {
            next.advance(entry.resource)?;
        }
        Ok(ResourceVersionPublication { next })
    }

    /// Publishes a prevalidated resource table without allocation or failure.
    pub(crate) fn publish_versions(&mut self, publication: ResourceVersionPublication) {
        self.resource_versions = publication.next;
    }
}

/// Ephemeral read facade reconstructed for each completion-driven resolve pass.
///
/// It borrows immutable epoch state and an operation-owned storage transcript; it is never stored
/// in a lower completion context.
#[derive(Debug)]
pub(super) struct EpochReadView<'storage, 'epoch> {
    /// Concrete operation storage view.
    pub(super) device: OperationDevice<'storage>,
    /// Current validated superblock snapshot.
    pub(super) superblock: Superblock,
    /// Immutable key snapshot selected by the epoch lease.
    pub(super) fscrypt_keys: &'epoch FscryptKeySet,
    /// Allocation ownership snapshot used only by mutation resolution.
    pub(super) clusters: Option<&'epoch ClusterReferenceIndex>,
}

impl<'storage, 'epoch> EpochReadView<'storage, 'epoch> {
    /// Builds a view of an already committed epoch.
    pub(super) const fn committed(
        device: OperationDevice<'storage>,
        epoch: &'epoch CommittedEpoch,
    ) -> Self {
        Self {
            device,
            superblock: epoch.superblock,
            fscrypt_keys: &epoch.fscrypt_keys,
            clusters: Some(&epoch.clusters),
        }
    }

    /// Builds a mount-time view before the allocation ownership index exists.
    pub(super) const fn mounting(
        device: OperationDevice<'storage>,
        superblock: Superblock,
        fscrypt_keys: &'epoch FscryptKeySet,
    ) -> Self {
        Self {
            device,
            superblock,
            fscrypt_keys,
            clusters: None,
        }
    }

    /// Returns the committed allocation ownership required by mutation resolution.
    /// # Errors
    ///
    /// Returns [`Error::ClusterReferenceConflict`] when called from a mount-time view that has no
    /// committed allocation index.
    pub(super) fn committed_clusters(&self) -> Result<&ClusterReferenceIndex> {
        self.clusters.ok_or(Error::ClusterReferenceConflict)
    }
}

/// Completed mount values installed independently in the driver VCB.
#[derive(Debug)]
pub struct CompletedMount {
    /// Immutable mount profile.
    profile: MountedProfile,
    /// Initial immutable committed epoch.
    epoch: CommittedEpoch,
    /// Mutable journal and mutation coordinator.
    coordinator: MutationCoordinatorState,
}

impl CompletedMount {
    /// Separates the three mount-owned state domains for VCB publication.
    #[must_use]
    pub fn into_parts(self) -> (MountedProfile, CommittedEpoch, MutationCoordinatorState) {
        (self.profile, self.epoch, self.coordinator)
    }
}

/// Immutable requirement emitted when the primary filesystem names an external journal UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalJournalRequirement {
    /// External journal UUID from the primary filesystem superblock.
    journal_uuid: JournalUuid,
    /// Primary filesystem UUID required as the sole JBD2 user.
    filesystem_uuid: FilesystemUuid,
    /// Filesystem and journal block size.
    block_size: BlockSize,
    /// Filesystem home-block upper bound used by replay validation.
    filesystem_blocks: u64,
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
        self.block_size
    }
}

/// Non-forgeable proof that one concrete device was fully validated by the core probe path.
#[derive(Debug)]
pub struct ValidatedExternalJournal {
    /// Requirement satisfied by this exact validation.
    requirement: ExternalJournalRequirement,
    /// Validated candidate device length.
    device_length: DeviceLength,
    /// Loaded journal whose profile and external layout are already validated.
    journal: Journal<LoadedJournal>,
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

/// Proof that both primary write-session markers were durably cleared after every mounted device drained.
#[derive(Debug)]
pub struct CleanCloseDurability {
    /// Prevents construction outside this module.
    _private: (),
}

/// One consuming transition of the clean-close durability protocol.
#[derive(Debug)]
pub enum CleanCloseTransition {
    /// Submit one preallocated read, flush, or marker write.
    SubmitLower {
        /// Owned lower-storage request.
        request: crate::StorageRequest,
        /// Operation resumed only by the matching completion.
        suspended: Box<CleanCloseOperation>,
    },
    /// The marker is durably clean, or the volume must remain recovery-required.
    Complete(Result<CleanCloseDurability>),
}

/// Allocation-before-effects clean shutdown/dismount operation.
#[derive(Debug)]
pub struct CleanCloseOperation {
    /// Primary filesystem transcript used only to obtain the latest superblock bytes.
    filesystem: StorageTranscript,
    /// Journal flush target selected by validated mount placement.
    journal_target: StorageTarget,
    /// Current preparation, I/O, or terminal phase.
    phase: CleanClosePhase,
    /// Preallocated clean primary-superblock write image.
    marker: Option<Vec<u8>>,
    /// Cancellation observed after closing began; it never interrupts durability.
    cancellation_requested: bool,
}

/// Exact clean-close phase, separating ready requests from outstanding completions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanClosePhase {
    /// Read and pre-encode the latest primary marker before effects.
    PrepareMarker,
    /// Primary-superblock read is owned by the lower stack.
    MarkerReadPending,
    /// Filesystem data and metadata flush is ready.
    FilesystemFlushReady,
    /// Filesystem flush is owned by the lower stack.
    FilesystemFlushPending(StorageRequestIdentity),
    /// External-journal flush is ready.
    JournalFlushReady,
    /// External-journal flush is owned by the lower stack.
    JournalFlushPending(StorageRequestIdentity),
    /// Preallocated clean marker write is ready.
    MarkerWriteReady,
    /// Clean marker write is owned by the lower stack.
    MarkerWritePending(StorageRequestIdentity),
    /// Final primary-filesystem flush is ready.
    MarkerFlushReady,
    /// Final primary-filesystem flush is owned by the lower stack.
    MarkerFlushPending(StorageRequestIdentity),
    /// Every required durability boundary completed successfully.
    Complete,
}

impl CleanCloseOperation {
    /// Starts close preparation before the first effect-bearing request.
    #[must_use]
    pub const fn new(
        filesystem_length: crate::DeviceLength,
        journal_target: StorageTarget,
    ) -> Self {
        Self {
            filesystem: StorageTranscript::new(StorageTarget::Filesystem, filesystem_length),
            journal_target,
            phase: CleanClosePhase::PrepareMarker,
            marker: None,
            cancellation_requested: false,
        }
    }

    /// Consumes one event and runs until the next lower request or terminal durability result.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: super::OperationEvent) -> CleanCloseTransition {
        let accepted = match event {
            super::OperationEvent::Admitted if self.phase == CleanClosePhase::PrepareMarker => {
                Ok(())
            }
            super::OperationEvent::StorageCompleted(completion) => self.complete_lower(completion),
            super::OperationEvent::CancelRequested => {
                self.cancellation_requested = true;
                Ok(())
            }
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return CleanCloseTransition::Complete(Err(error));
        }
        self.drive()
    }

    /// Validates one exact lower completion and advances to the next ready phase.
    /// # Errors
    ///
    /// Returns an error for a failed, mismatched, short, or phase-inconsistent completion.
    fn complete_lower(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        match self.phase {
            CleanClosePhase::MarkerReadPending => {
                self.filesystem.complete(completion)?;
                self.phase = CleanClosePhase::PrepareMarker;
                Ok(())
            }
            CleanClosePhase::FilesystemFlushPending(expected) => {
                expected.complete(completion)?;
                self.phase = if self.journal_target == StorageTarget::ExternalJournal {
                    CleanClosePhase::JournalFlushReady
                } else {
                    CleanClosePhase::MarkerWriteReady
                };
                Ok(())
            }
            CleanClosePhase::JournalFlushPending(expected) => {
                expected.complete(completion)?;
                self.phase = CleanClosePhase::MarkerWriteReady;
                Ok(())
            }
            CleanClosePhase::MarkerWritePending(expected) => {
                expected.complete(completion)?;
                self.phase = CleanClosePhase::MarkerFlushReady;
                Ok(())
            }
            CleanClosePhase::MarkerFlushPending(expected) => {
                expected.complete(completion)?;
                self.phase = CleanClosePhase::Complete;
                Ok(())
            }
            CleanClosePhase::PrepareMarker
            | CleanClosePhase::FilesystemFlushReady
            | CleanClosePhase::JournalFlushReady
            | CleanClosePhase::MarkerWriteReady
            | CleanClosePhase::MarkerFlushReady
            | CleanClosePhase::Complete => Err(Error::DeviceIo),
        }
    }

    /// Drives allocation-free request publication after the marker image has been prepared.
    fn drive(mut self: Box<Self>) -> CleanCloseTransition {
        loop {
            match self.phase {
                CleanClosePhase::PrepareMarker => {
                    let raw = {
                        let mut filesystem = OperationDevice::new(&mut self.filesystem);
                        Superblock::prepare_write_session(
                            &mut filesystem,
                            WriteSessionState::Closed,
                        )
                    };
                    match raw {
                        Ok(raw) => {
                            self.marker = match memory::copied_slice(&raw) {
                                Ok(marker) => Some(marker),
                                Err(error) => return CleanCloseTransition::Complete(Err(error)),
                            };
                            self.phase = CleanClosePhase::FilesystemFlushReady;
                        }
                        Err(Error::OperationSuspended) => {
                            let request = match self.filesystem.take_pending_request() {
                                Ok(request) => request,
                                Err(error) => {
                                    return CleanCloseTransition::Complete(Err(error));
                                }
                            };
                            self.phase = CleanClosePhase::MarkerReadPending;
                            return CleanCloseTransition::SubmitLower {
                                request,
                                suspended: self,
                            };
                        }
                        Err(error) => return CleanCloseTransition::Complete(Err(error)),
                    }
                }
                CleanClosePhase::FilesystemFlushReady => {
                    return self.submit_flush(StorageTarget::Filesystem);
                }
                CleanClosePhase::JournalFlushReady => {
                    return self.submit_flush(StorageTarget::ExternalJournal);
                }
                CleanClosePhase::MarkerWriteReady => {
                    let Some(marker) = self.marker.take() else {
                        return CleanCloseTransition::Complete(Err(Error::DeviceIo));
                    };
                    let request = crate::StorageRequest::Write {
                        target: StorageTarget::Filesystem,
                        offset: crate::ByteOffset::new(1024),
                        buffer: marker,
                    };
                    let expected = StorageRequestIdentity::from_request(&request);
                    self.phase = CleanClosePhase::MarkerWritePending(expected);
                    return CleanCloseTransition::SubmitLower {
                        request,
                        suspended: self,
                    };
                }
                CleanClosePhase::MarkerFlushReady => {
                    return self.submit_flush(StorageTarget::Filesystem);
                }
                CleanClosePhase::Complete => {
                    let _cancellation_was_recorded = self.cancellation_requested;
                    return CleanCloseTransition::Complete(Ok(CleanCloseDurability {
                        _private: (),
                    }));
                }
                CleanClosePhase::MarkerReadPending
                | CleanClosePhase::FilesystemFlushPending(_)
                | CleanClosePhase::JournalFlushPending(_)
                | CleanClosePhase::MarkerWritePending(_)
                | CleanClosePhase::MarkerFlushPending(_) => {
                    return CleanCloseTransition::Complete(Err(Error::DeviceIo));
                }
            }
        }
    }

    /// Emits one allocation-free flush and records its exact next pending state.
    fn submit_flush(mut self: Box<Self>, target: StorageTarget) -> CleanCloseTransition {
        let request = crate::StorageRequest::Flush { target };
        let expected = StorageRequestIdentity::from_request(&request);
        self.phase = match self.phase {
            CleanClosePhase::FilesystemFlushReady => {
                CleanClosePhase::FilesystemFlushPending(expected)
            }
            CleanClosePhase::JournalFlushReady => CleanClosePhase::JournalFlushPending(expected),
            CleanClosePhase::MarkerFlushReady => CleanClosePhase::MarkerFlushPending(expected),
            _ => return CleanCloseTransition::Complete(Err(Error::DeviceIo)),
        };
        CleanCloseTransition::SubmitLower {
            request,
            suspended: self,
        }
    }
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

    /// Consumes one probe event and runs to the next lower read or terminal classification.
    #[must_use]
    pub fn advance(
        mut self: Box<Self>,
        event: super::OperationEvent,
    ) -> ExternalJournalProbeTransition {
        let accepted = match event {
            super::OperationEvent::Admitted => Ok(()),
            super::OperationEvent::StorageCompleted(completion) => {
                self.candidate.complete(completion)
            }
            super::OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return ExternalJournalProbeTransition::Complete(Err(error));
        }
        let loaded = {
            let mut device = OperationDevice::new(&mut self.candidate);
            Journal::<LoadedJournal>::from_external_device(
                &mut device,
                self.requirement.journal_uuid,
                self.requirement.filesystem_uuid,
                self.requirement.block_size,
                self.requirement.filesystem_blocks,
            )
        };
        match loaded {
            Ok(ExternalJournalLoad::Mismatch) => {
                ExternalJournalProbeTransition::Complete(Ok(ExternalJournalProbeOutcome::Mismatch))
            }
            Ok(ExternalJournalLoad::Match(journal)) => {
                match memory::try_box(ValidatedExternalJournal {
                    requirement: self.requirement,
                    device_length: self.candidate.len(),
                    journal,
                }) {
                    Ok(validated) => ExternalJournalProbeTransition::Complete(Ok(
                        ExternalJournalProbeOutcome::Match(validated),
                    )),
                    Err(error) => ExternalJournalProbeTransition::Complete(Err(error)),
                }
            }
            Err(Error::OperationSuspended) => match self.candidate.take_pending_request() {
                Ok(request) => ExternalJournalProbeTransition::SubmitLower {
                    request,
                    suspended: self,
                },
                Err(error) => ExternalJournalProbeTransition::Complete(Err(error)),
            },
            Err(error) => ExternalJournalProbeTransition::Complete(Err(error)),
        }
    }
}

/// One consuming transition of the mount operation.
#[derive(Debug)]
pub enum MountTransition {
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
    Complete(Result<Box<CompletedMount>>),
}

/// Completion-driven journaled mount operation.
#[derive(Debug)]
pub struct MountOperation {
    /// Filesystem-device transcript used only for restartable metadata resolution.
    filesystem: StorageTranscript,
    /// Mount key snapshot moved once into the initial epoch before marker publication.
    fscrypt_keys: Option<FscryptKeySet>,
    /// Explicit mount and durability phase.
    state: MountState,
    /// Cancellation recorded after a durability-changing recovery phase has begun.
    cancel_requested: bool,
}

/// Internal mount phase with no independently inspectable flags.
#[derive(Debug)]
enum MountState {
    /// Resolve the primary superblock and internal journal placement.
    Resolving,
    /// A validated previous write-session image is ready to replace a torn primary superblock.
    RepairWriteReady {
        /// Complete repaired primary-superblock image.
        marker: Vec<u8>,
    },
    /// The repair write is owned by the lower stack.
    RepairWritePending {
        /// Expected repair-write completion.
        expected: StorageRequestIdentity,
    },
    /// The repair write completed and must be made durable before metadata is interpreted.
    RepairFlushReady,
    /// The repair flush is owned by the lower stack.
    RepairFlushPending {
        /// Expected filesystem flush completion.
        expected: StorageRequestIdentity,
    },
    /// The repaired primary superblock is durable and must be read through a fresh transcript.
    Repaired,
    /// Await a core-minted token for the exact external-journal requirement.
    AwaitingExternal {
        /// Primary admission state retained across driver discovery.
        primary: ResolvedPrimary,
        /// Requirement that the attached token must satisfy exactly.
        requirement: ExternalJournalRequirement,
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
        /// Clean journal retained while the repaired primary is re-read.
        journal: Journal<CleanJournal>,
        /// Device containing the journal.
        journal_target: StorageTarget,
    },
    /// Validate both persistent orphan trackers before granting write authority.
    ScanningOrphans(MountPublicationSeed),
    /// Build allocation ownership with validated admission for zero-link orphans.
    Indexing(ValidatedMountSeed),
    /// Prepare the marker image and all publication allocations before its first write.
    PreparingMarker(IndexedMountSeed),
    /// Marker write is ready for lower submission.
    MarkerWriteReady {
        /// Fully allocated mount result, publishable only after marker flush.
        completed: UnpublishedMount,
        /// Owned primary-superblock marker image.
        marker: Vec<u8>,
    },
    /// Marker write is owned by the lower stack.
    MarkerWritePending {
        /// Fully allocated mount result.
        completed: UnpublishedMount,
        /// Expected marker write completion.
        expected: StorageRequestIdentity,
    },
    /// Marker write completed and its filesystem flush is ready.
    MarkerFlushReady(UnpublishedMount),
    /// Marker flush is owned by the lower stack.
    MarkerFlushPending {
        /// Fully allocated mount result.
        completed: UnpublishedMount,
        /// Expected filesystem flush completion.
        expected: StorageRequestIdentity,
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
        /// Private mount and prospective queue state.
        mount: UnpublishedMount,
        /// Remaining requests, resumed only after this exact completion succeeds.
        sequence: StorageRequestSequence<OrphanBatchCompletion>,
        /// Identity of the one outstanding transfer.
        expected: StorageRequestIdentity,
    },
    /// Write-session markers are durable and the completed mount may be published.
    Published(Box<CompletedMount>),
}

/// Mount values retained while the recovered allocation index is constructed.
#[derive(Debug)]
struct MountPublicationSeed {
    /// Validated primary superblock state.
    superblock: Superblock,
    /// Clean journal coordinator state.
    journal: Journal<CleanJournal>,
    /// Device containing the journal.
    journal_target: StorageTarget,
}

/// Allocation-indexed mount values awaiting durable write-session marking.
#[derive(Debug)]
struct ValidatedMountSeed {
    /// Replayed primary and clean journal.
    publication: MountPublicationSeed,
    /// Immutable membership, consumed only after allocation indexing completes.
    orphans: ValidatedOrphanInventory,
}

/// Allocation-indexed mount values awaiting durable write-session marking.
#[derive(Debug)]
struct IndexedMountSeed {
    /// Tracker ownership retained through marker durability.
    orphans: ValidatedOrphanInventory,
    /// Recovery and journal placement facts.
    publication: MountPublicationSeed,
    /// Fully validated committed allocation ownership.
    clusters: ClusterReferenceIndex,
}

/// A fully allocated mount that remains private until every orphan has checkpointed.
#[derive(Debug)]
struct UnpublishedMount {
    /// VCB components allocated before write-session marking.
    completed: Box<CompletedMount>,
    /// Prospective queue state may advance only while held behind a pending durable batch.
    orphans: OrphanRecoveryQueue,
}

/// Journal resolution result before recovery begins.
#[derive(Debug)]
enum JournalResolution {
    /// A torn write-session transition was recognized and must be restored before journal resolution.
    RepairWriteSession {
        /// Fully allocated previous valid primary-superblock image.
        marker: Vec<u8>,
    },
    /// A concrete loaded journal is ready for bounded recovery.
    Loaded {
        /// Valid primary metadata or provisional recovery-only geometry.
        primary: ResolvedPrimary,
        /// Loaded journal.
        journal: Journal<LoadedJournal>,
        /// Device that owns journal records.
        journal_target: StorageTarget,
    },
    /// Driver discovery is required before external recovery can begin.
    Discover {
        /// Valid primary metadata or provisional recovery-only geometry.
        primary: ResolvedPrimary,
        /// Exact candidate validation requirement.
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
    ) -> Result<Box<JournalRecoveryOperation>> {
        let operation = match self {
            Self::Valid(superblock) => {
                JournalRecoveryOperation::new(journal, superblock.recovery_state())
            }
            Self::JournalRepairRequired(_) => JournalRecoveryOperation::repairing_primary(journal),
        }?;
        memory::try_box(operation)
    }
}

impl MountOperation {
    /// Creates a mount operation for a primary filesystem device only.
    #[must_use]
    pub const fn new(filesystem_length: DeviceLength, fscrypt_keys: FscryptKeySet) -> Self {
        Self {
            filesystem: StorageTranscript::new(StorageTarget::Filesystem, filesystem_length),
            fscrypt_keys: Some(fscrypt_keys),
            state: MountState::Resolving,
            cancel_requested: false,
        }
    }

    /// Attaches a token minted by exclusive core validation and resumes external recovery.
    #[must_use]
    pub fn attach_external_journal(
        mut self: Box<Self>,
        validated: Box<ValidatedExternalJournal>,
    ) -> MountTransition {
        let validated = *validated;
        let state = core::mem::replace(&mut self.state, MountState::Resolving);
        let MountState::AwaitingExternal {
            primary,
            requirement,
        } = state
        else {
            return MountTransition::Complete(Err(Error::DeviceIo));
        };
        if requirement != validated.requirement {
            return MountTransition::Complete(Err(Error::UnsupportedJournal));
        }
        match primary.begin_recovery(validated.journal) {
            Ok(operation) => {
                self.state = MountState::Recovering {
                    primary,
                    journal_target: StorageTarget::ExternalJournal,
                    operation,
                };
                self.drive()
            }
            Err(error) => MountTransition::Complete(Err(error)),
        }
    }

    /// Consumes one concrete event and runs until the next lower request or terminal result.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: super::OperationEvent) -> MountTransition {
        let accepted = match event {
            super::OperationEvent::Admitted => match &self.state {
                MountState::Resolving => Ok(()),
                _ => Err(Error::DeviceIo),
            },
            super::OperationEvent::StorageCompleted(completion) => {
                self.accept_completion(completion)
            }
            super::OperationEvent::CancelRequested => {
                if matches!(
                    self.state,
                    MountState::RepairWriteReady { .. }
                        | MountState::RepairWritePending { .. }
                        | MountState::RepairFlushReady
                        | MountState::RepairFlushPending { .. }
                        | MountState::Repaired
                        | MountState::Recovering { .. }
                        | MountState::VerifyingReplayedPrimary { .. }
                        | MountState::MarkerWriteReady { .. }
                        | MountState::MarkerWritePending { .. }
                        | MountState::MarkerFlushReady(_)
                        | MountState::MarkerFlushPending { .. }
                        | MountState::OrphanWrites { .. }
                        | MountState::OrphanWritePending { .. }
                ) {
                    self.cancel_requested = true;
                    Ok(())
                } else {
                    Err(Error::OperationCancelled)
                }
            }
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return MountTransition::Complete(Err(error));
        }
        self.drive()
    }

    /// Routes one completion exclusively to the phase that submitted it.
    /// # Errors
    ///
    /// Returns an error for a failed, mismatched, short, or phase-inconsistent completion.
    fn accept_completion(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        match core::mem::replace(&mut self.state, MountState::Resolving) {
            MountState::Resolving => {
                self.filesystem.complete(completion)?;
                self.state = MountState::Resolving;
            }
            MountState::RepairWritePending { expected } => {
                expected.complete(completion)?;
                self.state = MountState::RepairFlushReady;
            }
            MountState::RepairFlushPending { expected } => {
                expected.complete(completion)?;
                self.state = MountState::Repaired;
            }
            MountState::ScanningOrphans(publication) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::ScanningOrphans(publication);
            }
            MountState::RecoveringOrphans(mount) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::RecoveringOrphans(mount);
            }
            MountState::OrphanWritePending {
                mount,
                sequence,
                expected,
            } => {
                expected.complete(completion)?;
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
                journal,
                journal_target,
            } => {
                self.filesystem.complete(completion)?;
                self.state = MountState::VerifyingReplayedPrimary {
                    journal,
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
            MountState::MarkerWritePending {
                completed,
                expected,
            } => {
                expected.complete(completion)?;
                self.state = MountState::MarkerFlushReady(completed);
            }
            MountState::MarkerFlushPending {
                completed,
                expected,
            } => {
                expected.complete(completion)?;
                self.filesystem =
                    StorageTranscript::new(StorageTarget::Filesystem, self.filesystem.len());
                self.state = MountState::RecoveringOrphans(completed);
            }
            state @ (MountState::AwaitingExternal { .. }
            | MountState::RepairWriteReady { .. }
            | MountState::RepairFlushReady
            | MountState::Repaired
            | MountState::MarkerWriteReady { .. }
            | MountState::MarkerFlushReady(_)
            | MountState::OrphanWrites { .. }
            | MountState::Published(_)) => {
                self.state = state;
                return Err(Error::DeviceIo);
            }
        }
        Ok(())
    }

    /// Advances internal phases without polling unrelated operations.
    fn drive(mut self: Box<Self>) -> MountTransition {
        loop {
            match core::mem::replace(&mut self.state, MountState::Resolving) {
                MountState::Resolving => match self.resolve_journal() {
                    Ok(JournalResolution::RepairWriteSession { marker }) => {
                        self.state = MountState::RepairWriteReady { marker };
                    }
                    Ok(JournalResolution::Loaded {
                        primary,
                        journal,
                        journal_target,
                    }) => match primary.begin_recovery(journal) {
                        Ok(operation) => {
                            self.state = MountState::Recovering {
                                primary,
                                journal_target,
                                operation,
                            };
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    },
                    Ok(JournalResolution::Discover {
                        primary,
                        requirement,
                    }) => {
                        self.state = MountState::AwaitingExternal {
                            primary,
                            requirement,
                        };
                        return MountTransition::DiscoverExternalJournal {
                            requirement,
                            suspended: self,
                        };
                    }
                    Err(Error::OperationSuspended) => {
                        self.state = MountState::Resolving;
                        return self.submit_pending_read();
                    }
                    Err(error) => return MountTransition::Complete(Err(error)),
                },
                MountState::RepairWriteReady { marker } => {
                    let request = crate::StorageRequest::Write {
                        target: StorageTarget::Filesystem,
                        offset: ByteOffset::new(1024),
                        buffer: marker,
                    };
                    let expected = StorageRequestIdentity::from_request(&request);
                    self.state = MountState::RepairWritePending { expected };
                    return MountTransition::SubmitLower {
                        request,
                        suspended: self,
                    };
                }
                MountState::RepairWritePending { expected } => {
                    self.state = MountState::RepairWritePending { expected };
                    return MountTransition::Complete(Err(Error::DeviceIo));
                }
                MountState::RepairFlushReady => {
                    let request = crate::StorageRequest::Flush {
                        target: StorageTarget::Filesystem,
                    };
                    let expected = StorageRequestIdentity::from_request(&request);
                    self.state = MountState::RepairFlushPending { expected };
                    return MountTransition::SubmitLower {
                        request,
                        suspended: self,
                    };
                }
                MountState::RepairFlushPending { expected } => {
                    self.state = MountState::RepairFlushPending { expected };
                    return MountTransition::Complete(Err(Error::DeviceIo));
                }
                MountState::Repaired => {
                    if self.cancel_requested {
                        return MountTransition::Complete(Err(Error::OperationCancelled));
                    }
                    let filesystem_length = self.filesystem.len();
                    self.filesystem =
                        StorageTranscript::new(StorageTarget::Filesystem, filesystem_length);
                    self.state = MountState::Resolving;
                }
                MountState::AwaitingExternal {
                    primary,
                    requirement,
                } => {
                    self.state = MountState::AwaitingExternal {
                        primary,
                        requirement,
                    };
                    return MountTransition::DiscoverExternalJournal {
                        requirement,
                        suspended: self,
                    };
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
                        return MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
                    }
                    Ok(None) => match (*operation).into_clean() {
                        Ok(journal) => {
                            if self.cancel_requested {
                                return MountTransition::Complete(Err(Error::OperationCancelled));
                            }
                            let filesystem_length = self.filesystem.len();
                            self.filesystem = StorageTranscript::new(
                                StorageTarget::Filesystem,
                                filesystem_length,
                            );
                            self.state = MountState::VerifyingReplayedPrimary {
                                journal,
                                journal_target,
                            };
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    },
                    Err(error) => return MountTransition::Complete(Err(error)),
                },
                MountState::VerifyingReplayedPrimary {
                    journal,
                    journal_target,
                } => {
                    let primary = {
                        let mut filesystem = OperationDevice::new(&mut self.filesystem);
                        Superblock::read_write_from(&mut filesystem)
                    };
                    match primary {
                        Ok(PrimarySuperblockRead::Valid(superblock)) => {
                            self.state = MountState::ScanningOrphans(MountPublicationSeed {
                                superblock,
                                journal,
                                journal_target,
                            });
                        }
                        Ok(
                            PrimarySuperblockRead::TornWriteSession { .. }
                            | PrimarySuperblockRead::ChecksumInvalid(_),
                        ) => return MountTransition::Complete(Err(Error::ChecksumMismatch)),
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::VerifyingReplayedPrimary {
                                journal,
                                journal_target,
                            };
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
                MountState::ScanningOrphans(publication) => {
                    let result = {
                        let device = OperationDevice::new(&mut self.filesystem);
                        let Some(keys) = self.fscrypt_keys.as_ref() else {
                            return MountTransition::Complete(Err(Error::DeviceIo));
                        };
                        let mut volume =
                            EpochReadView::mounting(device, publication.superblock, keys);
                        ValidatedOrphanInventory::load(&mut volume)
                    };
                    match result {
                        Ok(orphans) => {
                            if !orphans.is_empty()
                                && let Err(error) = publication.journal.require_metadata_capacity(
                                    ORPHAN_METADATA_BUDGET,
                                    publication.superblock.block_size(),
                                )
                            {
                                return MountTransition::Complete(Err(error));
                            }
                            self.state = MountState::Indexing(ValidatedMountSeed {
                                publication,
                                orphans,
                            });
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::ScanningOrphans(publication);
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
                MountState::Indexing(validated) => {
                    let clusters = {
                        let device = OperationDevice::new(&mut self.filesystem);
                        let Some(keys) = self.fscrypt_keys.as_ref() else {
                            return MountTransition::Complete(Err(Error::DeviceIo));
                        };
                        let mut volume =
                            EpochReadView::mounting(device, validated.publication.superblock, keys);
                        ClusterReferenceIndex::load(&mut volume, &validated.orphans)
                    };
                    match clusters {
                        Ok(clusters) => {
                            self.state = MountState::PreparingMarker(IndexedMountSeed {
                                publication: validated.publication,
                                orphans: validated.orphans,
                                clusters,
                            })
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::Indexing(validated);
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
                MountState::PreparingMarker(indexed) => {
                    let raw = {
                        let mut filesystem = OperationDevice::new(&mut self.filesystem);
                        Superblock::prepare_write_session(
                            &mut filesystem,
                            WriteSessionState::Active,
                        )
                    };
                    match raw {
                        Ok(raw) => {
                            let marked = match Superblock::parse_read_write(&raw) {
                                Ok(marked) => marked,
                                Err(error) => return MountTransition::Complete(Err(error)),
                            };
                            let keys = match self.fscrypt_keys.take() {
                                Some(keys) => keys,
                                None => return MountTransition::Complete(Err(Error::DeviceIo)),
                            };
                            let completed = CompletedMount {
                                profile: MountedProfile::new(
                                    marked,
                                    self.filesystem.len(),
                                    indexed.publication.journal_target,
                                ),
                                epoch: CommittedEpoch::initial(marked, keys, indexed.clusters),
                                coordinator: MutationCoordinatorState::new(
                                    indexed.publication.journal,
                                ),
                            };
                            let completed = match memory::try_box(completed) {
                                Ok(completed) => completed,
                                Err(error) => return MountTransition::Complete(Err(error)),
                            };
                            let marker = match memory::copied_slice(&raw) {
                                Ok(marker) => marker,
                                Err(error) => return MountTransition::Complete(Err(error)),
                            };
                            let completed = UnpublishedMount {
                                completed,
                                orphans: indexed.orphans.into_queue(),
                            };
                            self.state = MountState::MarkerWriteReady { completed, marker };
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::PreparingMarker(indexed);
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
                MountState::MarkerWriteReady { completed, marker } => {
                    let request = crate::StorageRequest::Write {
                        target: StorageTarget::Filesystem,
                        offset: ByteOffset::new(1024),
                        buffer: marker,
                    };
                    let expected = StorageRequestIdentity::from_request(&request);
                    self.state = MountState::MarkerWritePending {
                        completed,
                        expected,
                    };
                    return MountTransition::SubmitLower {
                        request,
                        suspended: self,
                    };
                }
                MountState::MarkerWritePending {
                    completed,
                    expected,
                } => {
                    self.state = MountState::MarkerWritePending {
                        completed,
                        expected,
                    };
                    return MountTransition::Complete(Err(Error::DeviceIo));
                }
                MountState::MarkerFlushReady(completed) => {
                    let request = crate::StorageRequest::Flush {
                        target: StorageTarget::Filesystem,
                    };
                    let expected = StorageRequestIdentity::from_request(&request);
                    self.state = MountState::MarkerFlushPending {
                        completed,
                        expected,
                    };
                    return MountTransition::SubmitLower {
                        request,
                        suspended: self,
                    };
                }
                MountState::MarkerFlushPending {
                    completed,
                    expected,
                } => {
                    self.state = MountState::MarkerFlushPending {
                        completed,
                        expected,
                    };
                    return MountTransition::Complete(Err(Error::DeviceIo));
                }
                MountState::RecoveringOrphans(mut mount) => {
                    if self.cancel_requested {
                        return MountTransition::Complete(Err(Error::OperationCancelled));
                    }
                    let Some(target) = mount.orphans.current() else {
                        self.state = MountState::Published(mount.completed);
                        continue;
                    };
                    let inode = target.tracking.inode;
                    let result = {
                        let device = OperationDevice::new(&mut self.filesystem);
                        let view = EpochReadView::committed(device, &mount.completed.epoch);
                        let JournalCoordinatorState::Ready(journal) =
                            &mount.completed.coordinator.journal
                        else {
                            return MountTransition::Complete(Err(Error::JournalCorrupt));
                        };
                        prepare_orphan_batch(view, target, journal)
                    };
                    match result {
                        Ok((sequence, progress)) => {
                            if let Err(error) = mount.orphans.prepare_advance(inode, progress) {
                                return MountTransition::Complete(Err(error));
                            }
                            self.state = MountState::OrphanWrites { mount, sequence };
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::RecoveringOrphans(mount);
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
                MountState::OrphanWrites {
                    mut mount,
                    sequence,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        let expected = StorageRequestIdentity::from_request(&request);
                        self.state = MountState::OrphanWritePending {
                            mount,
                            sequence: suspended,
                            expected,
                        };
                        return MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
                    }
                    StorageRequestSequenceStep::Finished(completion) => {
                        mount.completed.epoch.superblock = completion.superblock;
                        mount.completed.epoch.clusters = completion.clusters;
                        mount.completed.profile.superblock = completion.superblock;
                        mount.completed.coordinator.journal =
                            JournalCoordinatorState::Ready(completion.journal);
                        self.filesystem = StorageTranscript::new(
                            StorageTarget::Filesystem,
                            self.filesystem.len(),
                        );
                        self.state = MountState::RecoveringOrphans(mount);
                    }
                },
                MountState::OrphanWritePending { .. } => {
                    return MountTransition::Complete(Err(Error::DeviceIo));
                }
                MountState::Published(completed) => {
                    return if self.cancel_requested {
                        MountTransition::Complete(Err(Error::OperationCancelled))
                    } else {
                        MountTransition::Complete(Ok(completed))
                    };
                }
            }
        }
    }

    /// Resolves primary metadata and either loads an internal journal or emits discovery facts.
    /// # Errors
    ///
    /// Returns an error for invalid primary metadata, journal placement, profile, or suspended I/O.
    fn resolve_journal(&mut self) -> Result<JournalResolution> {
        let primary_read = {
            let mut filesystem = OperationDevice::new(&mut self.filesystem);
            Superblock::read_write_from(&mut filesystem)?
        };
        let primary = match primary_read {
            PrimarySuperblockRead::Valid(superblock) => ResolvedPrimary::Valid(superblock),
            PrimarySuperblockRead::TornWriteSession { repair } => {
                return Ok(JournalResolution::RepairWriteSession { marker: repair });
            }
            PrimarySuperblockRead::ChecksumInvalid(provisional) => {
                ResolvedPrimary::JournalRepairRequired(provisional)
            }
        };
        let superblock = primary.recovery_bootstrap();
        match superblock.journal_mode() {
            JournalMode::Internal(journal_inode_id) => {
                let journal_inode = {
                    let filesystem = OperationDevice::new(&mut self.filesystem);
                    let keys = self.fscrypt_keys.as_ref().ok_or(Error::DeviceIo)?;
                    let mut volume = EpochReadView::mounting(filesystem, superblock, keys);
                    volume.read_inode_record(journal_inode_id)?
                };
                let journal = {
                    let mut filesystem = OperationDevice::new(&mut self.filesystem);
                    Journal::<LoadedJournal>::from_inode(
                        &journal_inode,
                        superblock.block_size(),
                        superblock.block_count().as_u64(),
                        &mut filesystem,
                    )?
                };
                Ok(JournalResolution::Loaded {
                    primary,
                    journal,
                    journal_target: StorageTarget::Filesystem,
                })
            }
            JournalMode::External(journal_uuid) => Ok(JournalResolution::Discover {
                primary,
                requirement: ExternalJournalRequirement {
                    journal_uuid,
                    filesystem_uuid: superblock.uuid(),
                    block_size: superblock.block_size(),
                    filesystem_blocks: superblock.block_count().as_u64(),
                },
            }),
            JournalMode::None => Err(Error::UnsupportedJournal),
        }
    }

    /// Moves the current restartable metadata read into lower ownership.
    fn submit_pending_read(mut self: Box<Self>) -> MountTransition {
        match self.filesystem.take_pending_request() {
            Ok(request) => MountTransition::SubmitLower {
                request,
                suspended: self,
            },
            Err(error) => MountTransition::Complete(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::disk::endian::{DiskOffset, le_u32, put_le_u16, put_le_u32};
    use crate::memory::FallibleVec;
    use crate::{
        ByteOffset, CompletedStorageTransfer, DeviceLength, Error, Result, StorageCompletion,
        StorageRequest, StorageTarget,
    };

    use super::{CleanCloseOperation, CleanCloseTransition};
    use crate::volume::OperationEvent;

    /// Request shape observed by the clean-close host adapter.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ObservedCloseRequest {
        ReadFilesystem,
        FlushFilesystem,
        FlushExternalJournal,
        WriteCleanMarker,
    }

    /// Terminal result retained by the fault-injection adapter.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ObservedCloseOutcome {
        Durable,
        Failed(Error),
    }

    /// Drives the production clean-close state machine, optionally failing one effect completion.
    /// # Errors
    ///
    /// Returns an error for allocation, wire mutation, or an unexpected request shape.
    fn run_clean_close(
        journal_target: StorageTarget,
        fail_effect: Option<usize>,
        cancellation_at_closing: bool,
    ) -> Result<(Vec<ObservedCloseRequest>, ObservedCloseOutcome)> {
        let initial_event = if cancellation_at_closing {
            OperationEvent::CancelRequested
        } else {
            OperationEvent::Admitted
        };
        let mut transition = crate::memory::try_box(CleanCloseOperation::new(
            DeviceLength::from_bytes(16_384),
            journal_target,
        ))?
        .advance(initial_event);
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(5)
            .map_err(|_| Error::OutOfMemory)?;
        let mut effect_index = 0_usize;
        loop {
            match transition {
                CleanCloseTransition::SubmitLower {
                    mut request,
                    suspended,
                } => {
                    let shape = match &mut request {
                        StorageRequest::Read {
                            target,
                            offset,
                            buffer,
                        } => {
                            if *target != StorageTarget::Filesystem
                                || *offset != ByteOffset::new(1024)
                                || buffer.len() != 1024
                            {
                                return Err(Error::DeviceIo);
                            }
                            let mut primary = [0_u8; 1024];
                            for (offset, value) in [
                                (0, 128),
                                (4, 4096),
                                (20, 1),
                                (32, 8192),
                                (36, 8192),
                                (40, 128),
                                (84, 11),
                                (92, 0x1004),
                                (96, 0x46),
                                (100, 0x10000),
                                (224, 8),
                                (0x280, 12),
                            ] {
                                put_le_u32(&mut primary, DiskOffset::new(offset), value)?;
                            }
                            put_le_u16(&mut primary, DiskOffset::new(56), 0xef53)?;
                            put_le_u16(&mut primary, DiskOffset::new(58), 1)?;
                            put_le_u16(&mut primary, DiskOffset::new(88), 256)?;
                            crate::memory::copy_exact(buffer, &primary)?;
                            ObservedCloseRequest::ReadFilesystem
                        }
                        StorageRequest::Flush { target } => {
                            effect_index = effect_index
                                .checked_add(1)
                                .ok_or(Error::ArithmeticOverflow)?;
                            match target {
                                StorageTarget::Filesystem => ObservedCloseRequest::FlushFilesystem,
                                StorageTarget::ExternalJournal => {
                                    ObservedCloseRequest::FlushExternalJournal
                                }
                            }
                        }
                        StorageRequest::Write {
                            target,
                            offset,
                            buffer,
                        } => {
                            effect_index = effect_index
                                .checked_add(1)
                                .ok_or(Error::ArithmeticOverflow)?;
                            if *target != StorageTarget::Filesystem
                                || *offset != ByteOffset::new(1024)
                                || le_u32(buffer, DiskOffset::new(96))? != 0x42
                                || le_u32(buffer, DiskOffset::new(100))? != 0
                            {
                                return Err(Error::DeviceIo);
                            }
                            ObservedCloseRequest::WriteCleanMarker
                        }
                    };
                    observed.try_push(shape)?;
                    let information = request.byte_count();
                    let transfer = CompletedStorageTransfer::from_request(request);
                    let completion = if fail_effect == Some(effect_index) && effect_index != 0 {
                        StorageCompletion::failure(transfer, Error::DeviceIo)
                    } else {
                        StorageCompletion::success(transfer, information)
                    };
                    transition = suspended.advance(OperationEvent::StorageCompleted(completion));
                }
                CleanCloseTransition::Complete(result) => {
                    let outcome = match result {
                        Ok(_durability) => ObservedCloseOutcome::Durable,
                        Err(error) => ObservedCloseOutcome::Failed(error),
                    };
                    return Ok((observed, outcome));
                }
            }
        }
    }

    /// # Panics
    ///
    /// Panics when internal-journal close clears the marker outside the required flush ordering.
    #[test]
    fn internal_journal_clean_close_obeys_durability_order() {
        let result = (|| -> Result<()> {
            let (observed, outcome) = run_clean_close(StorageTarget::Filesystem, None, false)?;
            assert_eq!(
                observed,
                vec![
                    ObservedCloseRequest::ReadFilesystem,
                    ObservedCloseRequest::FlushFilesystem,
                    ObservedCloseRequest::WriteCleanMarker,
                    ObservedCloseRequest::FlushFilesystem,
                ]
            );
            assert_eq!(outcome, ObservedCloseOutcome::Durable);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when external-journal close omits its flush before the primary marker write.
    #[test]
    fn external_journal_clean_close_flushes_both_devices_in_order() {
        let result = (|| -> Result<()> {
            let (observed, outcome) = run_clean_close(StorageTarget::ExternalJournal, None, false)?;
            assert_eq!(
                observed,
                vec![
                    ObservedCloseRequest::ReadFilesystem,
                    ObservedCloseRequest::FlushFilesystem,
                    ObservedCloseRequest::FlushExternalJournal,
                    ObservedCloseRequest::WriteCleanMarker,
                    ObservedCloseRequest::FlushFilesystem,
                ]
            );
            assert_eq!(outcome, ObservedCloseOutcome::Durable);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when any failed durability boundary publishes a clean terminal outcome.
    #[test]
    fn clean_close_fault_matrix_never_publishes_uncertain_durability() {
        let result = (|| -> Result<()> {
            for effect in 1..=3 {
                let (_observed, outcome) =
                    run_clean_close(StorageTarget::Filesystem, Some(effect), false)?;
                assert_eq!(outcome, ObservedCloseOutcome::Failed(Error::DeviceIo));
            }
            for effect in 1..=4 {
                let (_observed, outcome) =
                    run_clean_close(StorageTarget::ExternalJournal, Some(effect), false)?;
                assert_eq!(outcome, ObservedCloseOutcome::Failed(Error::DeviceIo));
            }
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when cancellation recorded after entering Closing interrupts the durability sequence.
    #[test]
    fn cancellation_after_closing_is_recorded_without_interrupting_close() {
        let result = (|| -> Result<()> {
            let (observed, outcome) = run_clean_close(StorageTarget::ExternalJournal, None, true)?;
            assert_eq!(observed.len(), 5);
            assert_eq!(outcome, ObservedCloseOutcome::Durable);
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
