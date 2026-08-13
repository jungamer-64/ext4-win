//! Immutable mount profile, committed epochs, and mutation coordinator state.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::scope::*;
use crate::disk::storage::{
    OperationDevice, StorageReadOverlay, StorageRequestIdentity, StorageTarget, StorageTranscript,
};
use crate::disk_format::journal::{CleanJournal, Journal, MetadataBlock};

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
    /// Mount terminated with either fully separated mounted state or a normal error.
    Complete(Result<Box<CompletedMount>>),
}

/// Completion-driven journaled mount operation.
///
/// All device reads are retained in operation-owned transcripts. No borrowed buffer or pointer
/// into this state is placed in a lower request.
#[derive(Debug)]
pub struct MountOperation {
    /// Filesystem-device read transcript.
    filesystem: StorageTranscript,
    /// External-journal transcript, present only when the caller supplied that device.
    external_journal: Option<StorageTranscript>,
    /// Fallibly constructed mount key snapshot moved into the first committed epoch.
    fscrypt_keys: FscryptKeySet,
    /// Explicit mount phase.
    state: MountState,
}

/// Internal mount phase with no independently inspectable flags.
#[derive(Debug)]
enum MountState {
    /// Parse, validate, and drive recovery work.
    Resolving,
    /// Build the allocation ownership index from the recovered filesystem image.
    Indexing(MountPublicationSeed),
}

/// Mount values retained while the recovered allocation index is constructed.
#[derive(Debug)]
struct MountPublicationSeed {
    /// Cleaned and validated superblock state.
    superblock: Superblock,
    /// Clean journal coordinator state.
    journal: Journal<CleanJournal>,
    /// Device containing the journal.
    journal_target: StorageTarget,
}

impl MountOperation {
    /// Creates an internal- or external-journal mount operation.
    ///
    /// `external_journal_length` describes an actually supplied journal device. The parsed ext4
    /// journal mode must agree with its presence before any recovery write is issued.
    #[must_use]
    pub const fn new(
        filesystem_length: DeviceLength,
        external_journal_length: Option<DeviceLength>,
        fscrypt_keys: FscryptKeySet,
    ) -> Self {
        Self {
            filesystem: StorageTranscript::new(StorageTarget::Filesystem, filesystem_length),
            external_journal: match external_journal_length {
                Some(length) => Some(StorageTranscript::new(
                    StorageTarget::ExternalJournal,
                    length,
                )),
                None => None,
            },
            fscrypt_keys,
            state: MountState::Resolving,
        }
    }

    /// Consumes one concrete event and runs until the next lower request or terminal result.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: super::OperationEvent) -> MountTransition {
        let accepted = match event {
            super::OperationEvent::Admitted => match &self.state {
                MountState::Resolving => Ok(()),
                MountState::Indexing(_) => Err(Error::DeviceIo),
            },
            super::OperationEvent::StorageCompleted(completion) => {
                self.accept_completion(completion)
            }
            super::OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            super::OperationEvent::RetryElapsed(_)
            | super::OperationEvent::DeviceLengthCompleted(_)
            | super::OperationEvent::IntentGranted(_)
            | super::OperationEvent::CommitGranted(_)
            | super::OperationEvent::VisibilityGranted(_)
            | super::OperationEvent::CheckpointGranted(_)
            | super::OperationEvent::BarrierReleased(_) => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return MountTransition::Complete(Err(error));
        }
        self.drive()
    }

    /// Routes one completion exclusively to the phase that submitted it.
    /// # Errors
    ///
    /// Returns an error when the completion does not match the suspended phase or transfer.
    fn accept_completion(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        match core::mem::replace(&mut self.state, MountState::Resolving) {
            MountState::Resolving => {
                self.complete_read(completion)?;
                self.state = MountState::Resolving;
                Ok(())
            }
            MountState::Indexing(publication) => {
                self.complete_read(completion)?;
                self.state = MountState::Indexing(publication);
                Ok(())
            }
        }
    }

    /// Advances internal phases without polling unrelated operations.
    fn drive(mut self: Box<Self>) -> MountTransition {
        loop {
            match core::mem::replace(&mut self.state, MountState::Resolving) {
                MountState::Resolving => match self.drive_recovery() {
                    Ok(publication) => self.state = MountState::Indexing(publication),
                    Err(Error::OperationSuspended) => {
                        self.state = MountState::Resolving;
                        return self.submit_pending_read();
                    }
                    Err(error) => return MountTransition::Complete(Err(error)),
                },
                MountState::Indexing(publication) => {
                    let clusters = {
                        let device = OperationDevice::new(&mut self.filesystem);
                        let mut volume = EpochReadView::mounting(
                            device,
                            publication.superblock,
                            &self.fscrypt_keys,
                        );
                        ClusterReferenceIndex::load(&mut volume)
                    };
                    match clusters {
                        Ok(clusters) => {
                            let Self {
                                filesystem,
                                external_journal: _,
                                fscrypt_keys,
                                state: _,
                            } = *self;
                            let profile = MountedProfile::new(
                                publication.superblock,
                                filesystem.len(),
                                publication.journal_target,
                            );
                            let epoch = CommittedEpoch::initial(
                                publication.superblock,
                                fscrypt_keys,
                                clusters,
                            );
                            let coordinator = MutationCoordinatorState::new(publication.journal);
                            let completed = CompletedMount {
                                profile,
                                epoch,
                                coordinator,
                            };
                            return MountTransition::Complete(memory::try_box(completed));
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::Indexing(publication);
                            return self.submit_pending_read();
                        }
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
            }
        }
    }

    /// Moves the current resolve pass's sole pending read into lower ownership.
    fn submit_pending_read(mut self: Box<Self>) -> MountTransition {
        let request = if self.filesystem.has_pending_request() {
            self.filesystem.take_pending_request()
        } else if let Some(journal) = self.external_journal.as_mut() {
            if journal.has_pending_request() {
                journal.take_pending_request()
            } else {
                Err(Error::DeviceIo)
            }
        } else {
            Err(Error::DeviceIo)
        };
        match request {
            Ok(request) => MountTransition::SubmitLower {
                request,
                suspended: self,
            },
            Err(error) => MountTransition::Complete(Err(error)),
        }
    }

    /// Integrates one read completion into its operation-owned transcript.
    /// # Errors
    ///
    /// Returns an error when the completion does not match either mount transcript or reports an
    /// invalid transfer.
    fn complete_read(&mut self, completion: crate::StorageCompletion) -> Result<()> {
        match completion.target() {
            StorageTarget::Filesystem => self.filesystem.complete(completion),
            StorageTarget::ExternalJournal => self
                .external_journal
                .as_mut()
                .ok_or(Error::UnsupportedJournal)?
                .complete(completion),
        }
    }
}
