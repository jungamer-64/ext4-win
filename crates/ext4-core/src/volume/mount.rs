//! Immutable mount profile, committed epochs, and mutation coordinator state.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::block_group::AllocationIndexBuild;
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
    CleanJournal, ExternalJournalLoad, Journal, JournalBlock, JournalRecoveryOperation,
    LoadedJournal,
};
use crate::disk_format::superblock::{
    ChecksumInvalidSuperblock, FilesystemUuid, JournalMode, JournalUuid, PrimarySuperblockRead,
    WriteSessionState,
};

/// Process-local origin of one mount attempt, independent of UUIDs and allocation lifetimes.
/// Copying this identity grants no access to mounted state and performs no allocation or counting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MountIdentity(usize);

/// Sole issuer for all mount attempts in this loaded core image. Issued values are never recycled.
static MOUNT_IDENTITIES: MountIdentitySequence = MountIdentitySequence(AtomicUsize::new(0));

/// Monotonic identity issuance; `usize::MAX` permanently seals the exhausted sequence.
#[derive(Debug)]
struct MountIdentitySequence(AtomicUsize);

impl MountIdentitySequence {
    /// Reserves one distinct origin without publishing or retaining any mounted resource.
    /// # Errors
    /// Returns [`Error::MountIdentityExhausted`] once this image's identity space is exhausted.
    fn issue(&self) -> Result<MountIdentity> {
        // Only uniqueness is shared here; no mounted data is published through this counter.
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map(MountIdentity)
            .map_err(|_| Error::MountIdentityExhausted)
    }
}

impl MountIdentity {
    /// Reserves a fresh origin before any mount publication write.
    /// # Errors
    /// Returns [`Error::MountIdentityExhausted`] without publishing a mount.
    fn new() -> Result<Self> {
        MOUNT_IDENTITIES.issue()
    }
}

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
    /// One complete filesystem block image written through the journal.
    JournalBlock,
}

impl MutationResource {
    /// Names the physical unit preserved by a journal block image.
    pub(crate) const fn journal_block(block: BlockAddress) -> Self {
        Self {
            domain: MutationResourceDomain::JournalBlock,
            identity: block.get(),
        }
    }
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
    /// Origin retained independently of on-disk UUID and local sequence numbers.
    pub(super) mount: MountIdentity,
    /// FIFO ticket retained across version-mismatch re-resolution.
    ticket: u64,
    /// Unique resources in discovery order.
    entries: Vec<ObservedResourceVersion>,
}

impl ObservedResourceVersionSet {
    /// Starts an empty observed set for one stable FIFO ticket.
    pub(super) fn new(ticket: u64, mount: &MountIdentity) -> Self {
        Self {
            mount: *mount,
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
        self.mount == other.mount
            && self.entries.len() == other.entries.len()
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

/// Fallibly expanding index of committed resource versions.
#[derive(Debug)]
pub(super) struct ResourceVersionTable {
    /// Open-addressed slots, with growth admitted before lower I/O.
    slots: Vec<Option<ResourceVersionEntry>>,
    /// Number of populated resource identities.
    occupied: usize,
}

impl ResourceVersionTable {
    /// Starts without allocation; capacity is admitted by commit preparation.
    const fn empty() -> Self {
        Self {
            slots: Vec::new(),
            occupied: 0,
        }
    }

    /// Finds an existing resource or its first empty slot in a power-of-two table.
    fn slot(&self, resource: MutationResource) -> Option<usize> {
        let domain = match resource.domain {
            MutationResourceDomain::Inode => 1_u64,
            MutationResourceDomain::BlockGroup => 2,
            MutationResourceDomain::VolumeMetadata => 3,
            MutationResourceDomain::KeySet => 4,
            MutationResourceDomain::JournalBlock => 5,
        };
        let mut hash = resource.identity ^ domain.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        hash ^= hash >> 31;
        let mask = self.slots.len().checked_sub(1)?;
        let mut position = usize::try_from(hash & u64::try_from(mask).ok()?).ok()?;
        for _ in 0..self.slots.len() {
            match self.slots.get(position)? {
                None => return Some(position),
                Some(entry) if entry.resource == resource => return Some(position),
                Some(_) => position = position.wrapping_add(1) & mask,
            }
        }
        None
    }

    /// Treats a resource that has never changed as the initial version.
    fn version(&self, resource: MutationResource) -> ResourceVersion {
        self.slot(resource)
            .and_then(|slot| self.slots.get(slot))
            .and_then(Option::as_ref)
            .map_or(ResourceVersion::INITIAL, |entry| entry.version)
    }

    /// Reserves index space without changing any committed version.
    /// # Errors
    /// Returns capacity arithmetic or allocation failure before lower I/O.
    fn reserve(&mut self, additional: usize) -> Result<()> {
        let required = self
            .occupied
            .checked_add(additional)
            .and_then(|count| count.checked_mul(2))
            .ok_or(Error::ArithmeticOverflow)?
            .max(16)
            .checked_next_power_of_two()
            .ok_or(Error::ArithmeticOverflow)?;
        if required <= self.slots.len() {
            return Ok(());
        }
        let mut next = Self {
            slots: memory::repeated_vec(None, required)?,
            occupied: self.occupied,
        };
        for entry in self.slots.iter().flatten().copied() {
            let slot = next.slot(entry.resource).ok_or(Error::ArithmeticOverflow)?;
            *next.slots.get_mut(slot).ok_or(Error::ArithmeticOverflow)? = Some(entry);
        }
        *self = next;
        Ok(())
    }

    /// Installs identity at version zero and computes its durable increment.
    /// # Errors
    /// Returns version overflow or a violated pre-reservation boundary.
    fn prepare_increment(
        &mut self,
        resource: MutationResource,
    ) -> Result<(usize, ResourceVersion)> {
        let slot = self.slot(resource).ok_or(Error::ArithmeticOverflow)?;
        let cell = self.slots.get_mut(slot).ok_or(Error::ArithmeticOverflow)?;
        let version = cell
            .as_ref()
            .map_or(ResourceVersion::INITIAL, |entry| entry.version)
            .next()?;
        if cell.is_none() {
            self.occupied = self
                .occupied
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
            *cell = Some(ResourceVersionEntry {
                resource,
                version: ResourceVersion::INITIAL,
            });
        }
        Ok((slot, version))
    }

    /// Consumes slot increments prepared under the serialized commit grant.
    fn publish(&mut self, publication: ResourceVersionPublication) {
        for (slot, version) in publication.delta {
            if let Some(Some(entry)) = self.slots.get_mut(slot) {
                entry.version = version;
            }
        }
    }
}

/// Version increments computed while commit authority is held, before lower I/O.
#[derive(Debug)]
pub(crate) struct ResourceVersionPublication {
    /// Changed slots in the reserved index; publication cannot grow the index.
    delta: Vec<(usize, ResourceVersion)>,
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
    /// Media operations fixed when this session was constructed.
    access: super::MediaAccess,
    /// Origin retained independently of on-disk UUID and local sequence numbers.
    pub(super) mount: MountIdentity,
    /// Validated feature and fixed geometry fields.
    superblock: Superblock,
    /// Filesystem device length validated at the storage boundary.
    filesystem_length: DeviceLength,
    /// Device that stores the JBD2 log.
    journal_target: StorageTarget,
}

impl MountedProfile {
    /// Media authority fixed before recovery; failure state cannot widen it.
    #[must_use]
    pub const fn access(&self) -> super::MediaAccess {
        self.access
    }

    /// Builds the immutable profile after replay has established a supported filesystem.
    pub(super) fn new(
        mount: &MountIdentity,
        superblock: Superblock,
        filesystem_length: DeviceLength,
        journal_target: StorageTarget,
        access: super::MediaAccess,
    ) -> Self {
        Self {
            access,
            mount: *mount,
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
    /// Immutable media authority inherited by each successor.
    access: super::MediaAccess,
    /// Origin retained independently of on-disk UUID and local sequence numbers.
    pub(super) mount: MountIdentity,
    /// Monotonic registry identity.
    sequence: EpochSequence,
    /// Current counters, label, and checksum policy source.
    pub(super) superblock: Superblock,
    /// Mount-scoped fscrypt key snapshot.
    pub(super) fscrypt_keys: FscryptKeySet,
    /// Committed allocation-cluster ownership.
    pub(super) clusters: ClusterReferenceIndex,
    /// Durable journal payloads not yet copied to home blocks.
    pub(super) overlay: Vec<JournalBlock>,
    /// Immutable virtual recovery bytes; absent for writable mounts.
    recovery: Option<alloc::sync::Arc<super::recovery::RecoveryOverlay>>,
}

impl CommittedEpoch {
    /// Rejects media mutation independently of mount-local key publication.
    /// # Errors
    /// Returns write protection for sessions admitted without media authority.
    pub(super) fn require_writable(&self) -> Result<()> {
        match self.access {
            super::MediaAccess::ReadWrite => Ok(()),
            super::MediaAccess::ReadOnly => Err(Error::ReadOnlyFilesystem),
        }
    }

    /// Builds the initial committed epoch after successful replay and mount validation.
    /// # Errors
    /// Returns mount identity exhaustion before any mount publication write.
    pub(super) fn initial(
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: ClusterReferenceIndex,
        access: super::MountAccess,
    ) -> Result<Self> {
        Ok(Self {
            mount: MountIdentity::new()?,
            access: access.media_access(),
            sequence: EpochSequence::INITIAL,
            superblock,
            fscrypt_keys,
            clusters,
            overlay: Vec::new(),
            recovery: None,
        })
    }

    /// Builds a post-commit epoch from values allocated before the first lower write.
    pub(super) fn prepared(
        current: &Self,
        sequence: EpochSequence,
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: ClusterReferenceIndex,
        overlay: Vec<JournalBlock>,
    ) -> Self {
        Self {
            mount: current.mount,
            access: current.access,
            sequence,
            superblock,
            fscrypt_keys,
            clusters,
            overlay,
            recovery: current.recovery.as_ref().map(alloc::sync::Arc::clone),
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
    fn read(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<bool> {
        if target != StorageTarget::Filesystem {
            return Ok(false);
        }
        let end = offset
            .get()
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        if let Some(recovery) = &self.recovery
            && recovery.read(target, offset, out)?
        {
            return Ok(true);
        }
        for image in &self.overlay {
            let start = self.superblock.block_size().offset_of(image.block())?.get();
            let image_end = start
                .checked_add(
                    u64::try_from(image.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            if offset.get() >= start && end <= image_end {
                let from = usize::try_from(
                    offset
                        .get()
                        .checked_sub(start)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?;
                let to = from
                    .checked_add(out.len())
                    .ok_or(Error::ArithmeticOverflow)?;
                memory::copy_exact(out, image.bytes().get(from..to).ok_or(Error::DeviceRange)?)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if target != StorageTarget::Filesystem || out.is_empty() {
            return Ok(());
        }
        if let Some(recovery) = &self.recovery {
            recovery.apply(target, offset, out)?;
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

/// Operation authority over a clean journal, independent of its durable on-disk state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommitAdmission {
    /// No journal or mount-key operation owns the commit lane.
    Available,
    /// One unprepared lease can be consumed or explicitly revoked.
    Granted(super::event::CommitClaim),
    /// The preparation owns all subsequent commit/publication authority.
    Prepared(super::event::CommitClaim),
    /// One visibility lease has been issued for that preparation.
    Publishing(super::event::CommitClaim),
}

/// Checkpoint admission cannot be reconstructed after its lease is issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CheckpointAdmission {
    /// The durable mutation has handed off its dirty journal to checkpoint work.
    Available,
    /// The checkpoint operation owns its only grant through clean publication.
    Granted,
}

/// Journal coordinator phase. A new commit is granted only in `Ready`.
#[derive(Debug)]
pub(super) enum JournalCoordinatorState {
    /// Clean journal with space available for one commit.
    Ready {
        /// Clean log whose space can admit the next commit.
        journal: Journal<CleanJournal>,
        /// Sole acquisition and consumption state for this clean journal.
        admission: CommitAdmission,
        /// Published identity paired with the version table while no checkpoint is pending.
        epoch: (FilesystemUuid, EpochSequence),
    },
    /// Commit is visible, while an independent checkpoint still owns the dirty journal state.
    CheckpointPending {
        /// Sole checkpoint acquisition state.
        admission: CheckpointAdmission,
        /// Durable overlay identity paired with versions until home-block durability completes.
        epoch: (FilesystemUuid, EpochSequence),
    },
}

impl JournalCoordinatorState {
    /// Identity published by the transition that owns this journal phase.
    const fn epoch(&self) -> (FilesystemUuid, EpochSequence) {
        match self {
            Self::Ready { epoch, .. } | Self::CheckpointPending { epoch, .. } => *epoch,
        }
    }
}

/// Current committed metadata and its resource-version observation authority.
///
/// Constructed by the coordinator at each synchronous pass. An epoch retains journal payloads and
/// keys, without snapshotting unrelated backing sectors; suspended reads must revalidate their
/// inode dependencies before interpreting a returned buffer. Unrelated publications do not
/// invalidate a read.
#[derive(Debug)]
pub struct CommittedReadContext<'state> {
    /// Current metadata and cache borrow.
    pub(super) cache: crate::MetadataCacheAccess<'state>,
    /// Sole committed resource-version authority.
    pub(super) versions: &'state ResourceVersionTable,
}

/// Dependencies retained by one completion-driven read.
#[derive(Debug, Default)]
pub(super) struct ReadObservations {
    /// Ordinary file reads and directory/entry projections need no dependency allocation.
    inline: [Option<ObservedResourceVersion>; 2],
    /// Traversals that interpret additional independent inodes admit their storage fallibly.
    additional: Vec<ObservedResourceVersion>,
}

impl ReadObservations {
    /// Starts a read without any interpreted storage dependency.
    pub(super) const fn new() -> Self {
        Self {
            inline: [None; 2],
            additional: Vec::new(),
        }
    }
    /// All dependencies, independent of their storage representation.
    fn entries(&self) -> impl Iterator<Item = &ObservedResourceVersion> {
        self.inline.iter().flatten().chain(&self.additional)
    }
    /// Records each dependency once, before a lower read can suspend the pass.
    /// # Errors
    /// Returns allocation failure before consuming dependent storage bytes.
    fn include(&mut self, resource: MutationResource, version: ResourceVersion) -> Result<()> {
        if self.entries().any(|entry| entry.resource == resource) {
            return Ok(());
        }
        let entry = ObservedResourceVersion { resource, version };
        if let Some(slot) = self.inline.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(entry);
        } else {
            self.additional.try_push(entry)?;
        }
        Ok(())
    }

    /// Retains the namespace and inode identity of a directory record through its metadata read.
    /// # Errors
    /// Returns allocation failure before handing entry projection to another read operation.
    pub(super) fn entry(&self, directory: DirectoryNodeId, node: NodeId) -> Result<Self> {
        if !self
            .entries()
            .any(|entry| entry.resource == MutationResource::inode(node.inode()))
        {
            return Err(Error::InvalidInode);
        }
        let mut observed = Self::new();
        for entry in self.entries().filter(|entry| {
            entry.resource == MutationResource::inode(directory.inode())
                || entry.resource == MutationResource::inode(node.inode())
                || entry.resource == MutationResource::KEY_SET
        }) {
            observed.include(entry.resource, entry.version)?;
        }
        Ok(observed)
    }

    /// Keeps only directory and key dependencies after an entry's projection is consumed.
    pub(super) fn retain_directory(&mut self, directory: DirectoryNodeId) {
        let retained = |entry: &ObservedResourceVersion| {
            entry.resource == MutationResource::inode(directory.inode())
                || entry.resource == MutationResource::KEY_SET
        };
        for slot in &mut self.inline {
            if slot.is_some_and(|entry| !retained(&entry)) {
                *slot = None;
            }
        }
        self.additional.retain(retained);
    }
}

impl ResourceVersionTable {
    /// Whether all bytes decoded by a suspended reader still belong to its observed inodes.
    pub(super) fn revalidate_read(&self, read: &ReadObservations) -> bool {
        read.entries()
            .all(|entry| self.version(entry.resource) == entry.version)
    }
}

/// A pass-local read dependency recorder; no mutation or publication authority is exposed.
#[derive(Debug)]
struct ReadObservation<'pass, 'state> {
    /// Dependencies owned by the suspended read operation.
    observed: &'pass mut ReadObservations,
    /// Current committed versions for this pass.
    versions: &'state ResourceVersionTable,
}

/// Mutable journal cursor, resource versions, and allocation reservations.
///
/// The scheduler selects candidates; this coordinator acquires and consumes journal authority.
/// Each grant belongs to this mount session and is consumed even when a transition rejects it.
#[derive(Debug)]
pub struct MutationCoordinatorState {
    /// Fixed media authority; key-publication grants do not widen it.
    access: super::MediaAccess,
    /// Origin retained independently of on-disk UUID and local sequence numbers.
    pub(super) mount: MountIdentity,
    /// Current journal phase.
    pub(super) journal: JournalCoordinatorState,
    /// Monotonic FIFO ticket assigned to the next mutation admission.
    next_ticket: u64,
    /// Next non-reusable commit acquisition identity.
    next_claim: u64,
    /// Indexed committed resource versions, expanded before commit I/O.
    resource_versions: ResourceVersionTable,
}

impl MutationCoordinatorState {
    /// Fixed media authority of this coordinator session.
    pub(super) const fn mount_access(&self) -> super::MediaAccess {
        self.access
    }

    /// Published identity paired with the committed resource-version authority.
    pub(super) const fn published_epoch(&self) -> (FilesystemUuid, EpochSequence) {
        self.journal.epoch()
    }
    /// Builds coordinator state after mount replay has produced a clean journal.
    pub(crate) fn new(journal: Journal<CleanJournal>, current: &CommittedEpoch) -> Self {
        Self {
            mount: current.mount,
            access: current.access,
            journal: JournalCoordinatorState::Ready {
                admission: CommitAdmission::Available,
                journal,
                epoch: (current.identity().uuid(), current.sequence()),
            },
            next_ticket: 0,
            next_claim: 0,
            resource_versions: ResourceVersionTable::empty(),
        }
    }

    /// Admits a read pass against the coordinator's currently published epoch.
    /// # Errors
    /// Returns [`Error::StaleReadContext`] when the supplied metadata belongs to another epoch.
    pub fn read_context<'state>(
        &'state self,
        cache: crate::MetadataCacheAccess<'state>,
    ) -> Result<CommittedReadContext<'state>> {
        let epoch = cache.epoch();
        if self.mount != epoch.mount
            || self.journal.epoch() != (epoch.identity().uuid(), epoch.sequence())
        {
            return Err(Error::StaleReadContext);
        }
        Ok(CommittedReadContext {
            cache,
            versions: &self.resource_versions,
        })
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

    /// Issues a mount-scoped intent grant after the owning scheduler acquires its gate.
    /// The scheduler retains arbitration and release responsibility; observation alone grants no gate.
    #[must_use]
    pub fn grant_intent(&mut self, ticket: u64) -> super::MutationLease {
        super::MutationLease::new(self.mount, ticket)
    }

    /// Acquires the sole commit lane without bypassing a pending checkpoint.
    /// `Ok(None)` denotes contention and leaves the existing owner unchanged.
    /// # Errors
    /// Returns acquisition-identity exhaustion before issuing any authority.
    pub fn acquire_commit(&mut self, ticket: u64) -> Result<Option<super::CommitLease>> {
        let JournalCoordinatorState::Ready {
            admission: CommitAdmission::Available,
            ..
        } = self.journal
        else {
            return Ok(None);
        };
        let claim = super::event::CommitClaim {
            ticket,
            generation: self.next_claim,
        };
        let next = self
            .next_claim
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        if let JournalCoordinatorState::Ready { admission, .. } = &mut self.journal {
            *admission = CommitAdmission::Granted(claim);
        }
        self.next_claim = next;
        Ok(Some(super::CommitLease::new(self.mount, claim)))
    }

    /// Revokes an unprepared grant; a stale lease stays invalid after reacquisition.
    /// Prepared, durable, and checkpoint authority can only be retired by their owning values.
    pub fn revoke_unprepared_commit(&mut self, ticket: u64) {
        if let JournalCoordinatorState::Ready { admission, .. } = &mut self.journal
            && matches!(admission, CommitAdmission::Granted(claim) if claim.ticket == ticket)
        {
            *admission = CommitAdmission::Available;
        }
    }

    /// Issues visibility authority only once for the current completed preparation.
    /// A dropped or consumed lease is never reissued; an unstarted preparation can be explicitly
    /// aborted through its owning value, while a started commit requires mount recovery.
    #[must_use]
    pub fn acquire_visibility(&mut self, ticket: u64) -> Option<super::VisibilityLease> {
        let JournalCoordinatorState::Ready { admission, .. } = &mut self.journal else {
            return None;
        };
        let CommitAdmission::Prepared(claim) = *admission else {
            return None;
        };
        if claim.ticket != ticket {
            return None;
        }
        *admission = CommitAdmission::Publishing(claim);
        Some(super::VisibilityLease::new(self.mount, claim))
    }

    /// Acquires checkpoint authority exactly once for the currently visible dirty epoch.
    /// A dropped or consumed lease is never reissued; its owner must complete or recover the mount.
    #[must_use]
    pub fn acquire_checkpoint(
        &mut self,
        requested: EpochSequence,
    ) -> Option<super::CheckpointLease> {
        let JournalCoordinatorState::CheckpointPending { epoch, admission } = &mut self.journal
        else {
            return None;
        };
        if epoch.1 != requested || *admission != CheckpointAdmission::Available {
            return None;
        }
        *admission = CheckpointAdmission::Granted;
        Some(super::CheckpointLease::new(self.mount, requested))
    }

    /// Whether a clean journal has no granted or prepared operation.
    #[must_use]
    pub fn journal_is_clean(&self) -> bool {
        matches!(
            self.journal,
            JournalCoordinatorState::Ready {
                admission: CommitAdmission::Available,
                ..
            }
        )
    }

    /// Consumes only the acquisition currently reserved for this preparation.
    /// # Errors
    /// Returns a revoked, foreign or mismatched lease; no unrelated authority is released.
    pub(super) fn accept_commit(
        &self,
        lease: super::CommitLease,
        ticket: u64,
    ) -> Result<super::event::CommitClaim> {
        let claim = lease.consume(&self.mount)?;
        if claim.ticket != ticket
            || !matches!(self.journal, JournalCoordinatorState::Ready { admission: CommitAdmission::Granted(current), .. } if current == claim)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(claim)
    }

    /// Owns grant consumption, fallible preparation and pre-effect failure recovery together.
    /// # Errors
    /// Returns a rejected grant or preparation failure; accepted failures release the acquisition.
    pub(super) fn prepare_publication<T>(
        &mut self,
        lease: super::CommitLease,
        ticket: u64,
        prepare: impl FnOnce(&mut Self, super::event::CommitClaim) -> Result<T>,
    ) -> Result<T> {
        let claim = self.accept_commit(lease, ticket)?;
        let result = prepare(self, claim);
        if let JournalCoordinatorState::Ready { admission, .. } = &mut self.journal {
            *admission = match &result {
                Ok(_) => CommitAdmission::Prepared(claim),
                Err(_) => CommitAdmission::Available,
            };
        }
        result
    }

    /// Checks the one visibility lease against its preparation, acquisition and mount.
    pub(super) fn accepts_visibility(
        &self,
        lease: super::VisibilityLease,
        claim: super::event::CommitClaim,
    ) -> bool {
        lease.consume(&self.mount) == Ok(claim)
            && matches!(self.journal, JournalCoordinatorState::Ready { admission: CommitAdmission::Publishing(current), .. } if current == claim)
    }

    /// Retires an unpublished preparation only when its owning value is being consumed.
    /// # Errors
    /// Returns a foreign or superseded preparation without changing current authority.
    pub(super) fn abort_prepared(
        &mut self,
        mount: MountIdentity,
        claim: super::event::CommitClaim,
    ) -> Result<()> {
        if self.mount != mount {
            return Err(Error::ClusterReferenceConflict);
        }
        let JournalCoordinatorState::Ready { admission, .. } = &mut self.journal else {
            return Err(Error::ClusterReferenceConflict);
        };
        if !matches!(admission, CommitAdmission::Prepared(current) | CommitAdmission::Publishing(current) if *current == claim)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        *admission = CommitAdmission::Available;
        Ok(())
    }

    /// Current committed version of one resource.
    pub(crate) fn resource_version(&self, resource: MutationResource) -> ResourceVersion {
        self.resource_versions.version(resource)
    }

    /// Revalidates every resource observed by a resolved mutation.
    pub(crate) fn revalidate(&self, observed: &ObservedResourceVersionSet) -> bool {
        self.mount == observed.mount
            && observed
                .entries
                .iter()
                .all(|entry| self.resource_versions.version(entry.resource) == entry.version)
    }

    /// Reserves the index and computes only changed versions while failure is harmless.
    /// # Errors
    ///
    /// Returns an error when observed versions are stale, index allocation fails, or a
    /// resource version cannot advance.
    pub(crate) fn prepare_version_publication(
        &mut self,
        observed: &ObservedResourceVersionSet,
    ) -> Result<ResourceVersionPublication> {
        if !self.revalidate(observed) {
            return Err(Error::ClusterReferenceConflict);
        }
        self.resource_versions.reserve(observed.entries.len())?;
        let mut delta = Vec::new();
        delta
            .try_reserve_exact(observed.entries.len())
            .map_err(|_| Error::OutOfMemory)?;
        for entry in &observed.entries {
            delta.try_push(self.resource_versions.prepare_increment(entry.resource)?)?;
        }
        Ok(ResourceVersionPublication { delta })
    }

    /// Publishes reserved slot increments without allocation or failure.
    /// The serialized commit grant prevents index growth between preparation and publication.
    pub(crate) fn publish_versions(&mut self, publication: ResourceVersionPublication) {
        self.resource_versions.publish(publication);
    }
}

/// Whether a pass has consumed mount-key authority while building its result.
#[derive(Clone, Copy, Debug)]
enum KeySetDependency {
    /// No operation in this pass has depended on a master key.
    Independent,
    /// Mutation reservation and serialized commit preparation must revalidate the key version.
    Required,
}

/// Ephemeral read facade reconstructed for each completion-driven resolve pass.
///
/// It borrows immutable epoch state and an operation-owned storage transcript; it is never stored
/// in a lower completion context.
#[derive(Debug)]
pub(super) struct EpochReadView<'storage, 'epoch> {
    /// Retains key usage across the remainder of mutation resolution, including plaintext staging.
    key_dependency: KeySetDependency,
    /// Read dependencies; mount and mutation resolution have separate admission protocols.
    observation: Option<ReadObservation<'storage, 'epoch>>,
    /// Concrete operation storage view.
    pub(super) device: OperationDevice<'storage>,
    /// Current validated superblock snapshot.
    pub(super) superblock: Superblock,
    /// Immutable key snapshot selected by the epoch lease.
    pub(super) fscrypt_keys: &'epoch FscryptKeySet,
    /// Identity of the immutable snapshot; absent before mount has committed.
    pub(super) epoch: Option<(FilesystemUuid, EpochSequence)>,
    /// Session identity borrowed from the selected epoch.
    pub(super) mount: Option<&'epoch MountIdentity>,
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
            key_dependency: KeySetDependency::Independent,
            observation: None,
            device,
            superblock: epoch.superblock,
            fscrypt_keys: &epoch.fscrypt_keys,
            clusters: Some(&epoch.clusters),
            epoch: Some((epoch.identity().uuid(), epoch.sequence())),
            mount: Some(&epoch.mount),
        }
    }

    /// Builds a mount-time view before the allocation ownership index exists.
    pub(super) const fn mounting(
        device: OperationDevice<'storage>,
        superblock: Superblock,
        fscrypt_keys: &'epoch FscryptKeySet,
    ) -> Self {
        Self {
            key_dependency: KeySetDependency::Independent,
            observation: None,
            device,
            superblock,
            fscrypt_keys,
            clusters: None,
            epoch: None,
            mount: None,
        }
    }

    /// Constructs a read view whose lower bytes are checked against committed inode versions.
    pub(super) fn observing(
        device: OperationDevice<'storage>,
        epoch: &'epoch CommittedEpoch,
        versions: &'epoch ResourceVersionTable,
        observed: &'storage mut ReadObservations,
    ) -> Self {
        let mut view = Self::committed(device, epoch);
        view.observation = Some(ReadObservation { observed, versions });
        view
    }

    /// Records an inode dependency before mapping or reading its disk representation.
    /// # Errors
    /// Returns allocation failure before issuing an inode-dependent lower read.
    pub(super) fn observe_inode(&mut self, inode: InodeId) -> Result<()> {
        self.observe_resource(MutationResource::inode(inode))
    }

    /// Records a dependency on the current key set before deriving plaintext.
    /// # Errors
    /// Returns allocation failure before consuming key-dependent bytes.
    pub(super) fn observe_resource(&mut self, resource: MutationResource) -> Result<()> {
        if let Some(observation) = &mut self.observation {
            observation
                .observed
                .include(resource, observation.versions.version(resource))?;
        }
        if resource == MutationResource::KEY_SET {
            self.key_dependency = KeySetDependency::Required;
        }
        Ok(())
    }

    /// Key snapshot dependency checked before a mutation enters its serialized commit.
    pub(super) const fn key_dependency(&self) -> Option<MutationResource> {
        match self.key_dependency {
            KeySetDependency::Independent => None,
            KeySetDependency::Required => Some(MutationResource::KEY_SET),
        }
    }

    /// Current inode version for decoded directory progress, absent during mount or resolution.
    pub(super) fn inode_version(&self, inode: InodeId) -> Option<ResourceVersion> {
        self.observation
            .as_ref()
            .map(|observation| observation.versions.version(MutationResource::inode(inode)))
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

/// Proof that this session's media-change obligations completed after its operations drained.
/// Read-only sessions leave the medium's existing recovery markers unchanged.
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
    /// This session has no remaining media-change obligation, or closing failed.
    Complete(Result<CleanCloseDurability>),
}

/// Allocation-before-effects clean shutdown/dismount operation.
#[derive(Debug)]
pub struct CleanCloseOperation {
    /// Authority selected when this close request was constructed.
    access: super::MediaAccess,
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
    pub const fn new(profile: &MountedProfile) -> Self {
        Self {
            access: profile.access(),
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
            journal_target: profile.journal_target(),
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
        if matches!(self.access, super::MediaAccess::ReadOnly) {
            return CleanCloseTransition::Complete(Ok(CleanCloseDurability { _private: () }));
        }
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
    /// Primary geometry is admitted; recovery still has to establish mounted validity.
    Complete(Result<ProbedMount>),
}
/// Primary admission retained across UUID-scoped policy selection.
///
/// Its UUID identifies policy, not a healthy filesystem: a damaged primary may require journal
/// repair, and ordinary mount validation must finish before any mounted state is published.
#[derive(Debug)]
pub struct ProbedMount {
    /// Captured primary reads become the mount's sole bootstrap transcript.
    filesystem: StorageTranscript,
    /// Filesystem identity extracted from admitted recovery geometry.
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
        let result = (|| {
            let mut device = OperationDevice::new(&mut self.filesystem);
            let primary = match Superblock::read_write_from(&mut device)? {
                PrimarySuperblockRead::Valid(value) => value,
                PrimarySuperblockRead::ChecksumInvalid(value) => value.recovery_bootstrap(),
                PrimarySuperblockRead::TornWriteSession { repair } => {
                    Superblock::parse_read_write(&repair)?
                }
            };
            Ok(primary.uuid())
        })();
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
    pub fn start(self, fscrypt_keys: FscryptKeySet, access: super::MountAccess) -> MountOperation {
        MountOperation {
            access,
            recovery: match access {
                super::MountAccess::ReadWrite => None,
                super::MountAccess::ReadOnly { recovery_memory } => {
                    Some(super::recovery::RecoveryOverlay::new(recovery_memory))
                }
            },
            filesystem: self.filesystem,
            fscrypt_keys: Some(fscrypt_keys),
            state: MountState::Resolving,
            cancel_requested: false,
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
    /// Media authority fixed before the first mount operation.
    access: super::MountAccess,
    /// Private recovery destination; moved into immutable epoch ownership at publication.
    recovery: Option<super::recovery::RecoveryOverlay>,
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
        /// Mount state retained until the exact recovery write completes.
        mount: UnpublishedMount,
        /// Only a matching completion reveals the remaining recovery sequence.
        pending: crate::PendingStorageTransfer<StorageRequestSequence<OrphanBatchCompletion>>,
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

/// Validated orphan membership and resumable allocation ownership awaiting indexing.
#[derive(Debug)]
struct ValidatedMountSeed {
    /// Replayed primary and clean journal.
    publication: MountPublicationSeed,
    /// Immutable membership, consumed only after allocation indexing completes.
    orphans: ValidatedOrphanInventory,
    /// Resumable mount-private ownership validation, retained across lower completions.
    index: Box<AllocationIndexBuild>,
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
        let completion = if let Some(recovery) = &self.recovery {
            let (mut transfer, information, result) = completion.into_parts();
            if result.is_ok()
                && let crate::CompletedStorageTransfer::Read {
                    target,
                    offset,
                    buffer,
                } = &mut transfer
                && information == buffer.len()
            {
                recovery.apply(*target, *offset, buffer)?;
            }
            match result {
                Ok(()) => crate::StorageCompletion::success(transfer, information),
                Err(error) => crate::StorageCompletion::failure(transfer, error),
            }
        } else {
            completion
        };
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

    /// Executes private recovery effects without ever publishing them to backing storage.
    fn drive(mut self: Box<Self>) -> MountTransition {
        loop {
            let transition = self.drive_step();
            let MountTransition::SubmitLower {
                mut request,
                mut suspended,
            } = transition
            else {
                return transition;
            };
            let Some(recovery) = &mut suspended.recovery else {
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
                return MountTransition::Complete(Err(error));
            }
            let information = request.byte_count();
            let completion = crate::StorageCompletion::success(
                crate::CompletedStorageTransfer::from_request(request),
                information,
            );
            if let Err(error) = suspended.accept_completion(completion) {
                return MountTransition::Complete(Err(error));
            }
            self = suspended;
        }
    }

    /// Advances internal phases until an owned effect or terminal result is ready.
    fn drive_step(mut self: Box<Self>) -> MountTransition {
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
                            let index = match memory::try_box(AllocationIndexBuild::new()) {
                                Ok(index) => index,
                                Err(error) => return MountTransition::Complete(Err(error)),
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
                        Err(error) => return MountTransition::Complete(Err(error)),
                    }
                }
                MountState::Indexing(mut validated) => {
                    let clusters = validated.index.advance(
                        &mut self.filesystem,
                        &validated.publication.superblock,
                        &validated.orphans,
                    );
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
                        match self.access {
                            super::MountAccess::ReadWrite => Superblock::prepare_write_session(
                                &mut filesystem,
                                WriteSessionState::Active,
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
                            let marked = match Superblock::parse_read_write(&raw) {
                                Ok(marked) => marked,
                                Err(error) => return MountTransition::Complete(Err(error)),
                            };
                            let keys = match self.fscrypt_keys.take() {
                                Some(keys) => keys,
                                None => return MountTransition::Complete(Err(Error::DeviceIo)),
                            };
                            let epoch = match CommittedEpoch::initial(
                                marked,
                                keys,
                                indexed.clusters,
                                self.access,
                            ) {
                                Ok(epoch) => epoch,
                                Err(error) => return MountTransition::Complete(Err(error)),
                            };
                            let completed = CompletedMount {
                                profile: MountedProfile::new(
                                    &epoch.mount,
                                    marked,
                                    self.filesystem.len(),
                                    indexed.publication.journal_target,
                                    self.access.media_access(),
                                ),
                                coordinator: MutationCoordinatorState::new(
                                    indexed.publication.journal,
                                    &epoch,
                                ),
                                epoch,
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
                            self.state = match self.access {
                                super::MountAccess::ReadWrite => {
                                    MountState::MarkerWriteReady { completed, marker }
                                }
                                super::MountAccess::ReadOnly { .. } => {
                                    MountState::RecoveringOrphans(completed)
                                }
                            };
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
                        let JournalCoordinatorState::Ready { journal, .. } =
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
                        self.state = MountState::OrphanWritePending {
                            mount,
                            pending: suspended,
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
                        mount.completed.coordinator.journal = JournalCoordinatorState::Ready {
                            admission: CommitAdmission::Available,
                            journal: completion.journal,
                            epoch: (
                                mount.completed.epoch.identity().uuid(),
                                mount.completed.epoch.sequence(),
                            ),
                        };
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
                MountState::Published(mut completed) => {
                    if let Some(recovery) = self.recovery.take() {
                        completed.epoch.recovery = match recovery.seal() {
                            Ok(recovery) => Some(recovery),
                            Err(error) => return MountTransition::Complete(Err(error)),
                        };
                    }
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

    /// # Panics
    /// Panics if the final identity cannot be issued or exhaustion reopens admission.
    #[test]
    fn mount_identity_exhaustion_is_permanent() {
        let sequence = super::MountIdentitySequence(super::AtomicUsize::new(usize::MAX - 1));
        let last = sequence.issue();
        assert_eq!(last, Ok(super::MountIdentity(usize::MAX - 1)));
        for _ in 0..2 {
            assert_eq!(sequence.issue(), Err(Error::MountIdentityExhausted));
        }
    }

    /// # Panics
    /// Panics if simultaneous mount attempts receive the same origin or cannot be joined.
    #[test]
    fn concurrent_mounts_receive_distinct_origins() {
        std::thread::scope(|scope| {
            let background = scope.spawn(super::MountIdentity::new);
            let foreground = super::MountIdentity::new();
            assert!(matches!(
                (background.join(), foreground),
                (Ok(Ok(left)), Ok(right)) if left != right
            ));
        });
    }

    /// # Panics
    /// Panics if distinct resources are capped or a delta changes unrelated versions.
    #[test]
    fn resource_versions_publish_more_than_eight_thousand_distinct_inodes() {
        let result = (|| -> Result<()> {
            let mut table = super::ResourceVersionTable::empty();
            for inode in 1..=8192 {
                let resource = super::MutationResource::inode(super::InodeId::try_from(inode)?);
                table.reserve(1)?;
                let increment = table.prepare_increment(resource)?;
                assert_eq!(table.version(resource), super::ResourceVersion::INITIAL);
                table.publish(super::ResourceVersionPublication {
                    delta: crate::memory::copied_slice(&[increment])?,
                });
                assert_eq!(table.version(resource), super::ResourceVersion(1));
            }
            for inode in 1..=8192 {
                let resource = super::MutationResource::inode(super::InodeId::try_from(inode)?);
                assert_eq!(table.version(resource), super::ResourceVersion(1));
            }
            let resource = super::MutationResource::inode(super::InodeId::try_from(4000)?);
            table.reserve(1)?;
            let increment = table.prepare_increment(resource)?;
            let capacity = table.slots.capacity();
            table.publish(super::ResourceVersionPublication {
                delta: crate::memory::copied_slice(&[increment])?,
            });
            assert_eq!(table.slots.capacity(), capacity);
            assert_eq!(table.version(resource), super::ResourceVersion(2));
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }

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
        let mut transition = crate::memory::try_box(CleanCloseOperation {
            access: crate::MediaAccess::ReadWrite,
            filesystem: super::StorageTranscript::new(
                StorageTarget::Filesystem,
                DeviceLength::from_bytes(16_384),
            ),
            journal_target,
            phase: super::CleanClosePhase::PrepareMarker,
            marker: None,
            cancellation_requested: false,
        })?
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
                            put_le_u32(&mut primary, DiskOffset::new(76), 1)?;
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
