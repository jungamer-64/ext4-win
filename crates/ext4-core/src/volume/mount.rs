//! Immutable mount profile, committed epochs, and mutation coordinator state.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::block_group::AllocationIndexBuild;
use super::orphan::{ORPHAN_METADATA_BUDGET, OrphanRecoveryQueue, ValidatedOrphanInventory};
use super::scope::*;
use super::transaction::{
    OrphanBatchCompletion, StorageRequestSequence, StorageRequestSequenceStep, prepare_orphan_batch,
};
use crate::disk::storage::{OperationDevice, StorageReadOverlay, StorageTarget, StorageTranscript};
use crate::disk_format::journal::{
    CleanJournal, ExternalJournalLoad, FilesystemHomeSpace, Journal, JournalBlock,
    JournalRecoveryCompletion, JournalRecoveryOperation, LoadedJournal,
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
    pub(super) fn new() -> Result<Self> {
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
    /// Allocation-cluster coordinate zero in physical filesystem block space.
    first_data_block: BlockAddress,
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
    /// Physical byte origin for allocation-cluster coordinates.
    /// # Errors
    /// Returns coordinate overflow before exposing an invalid physical address.
    pub fn allocation_start(self) -> Result<crate::ByteOffset> {
        self.block_size.offset_of(self.first_data_block)
    }
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
    journal_target: Option<StorageTarget>,
}

impl MountedProfile {
    /// Starts a fresh physical primary observation using this mount's immutable interpretation.
    /// No mounted cache, epoch overlay, recovery state or media-write authority is borrowed.
    #[must_use]
    pub fn verify_media(&self) -> super::MediaVerificationOperation {
        super::MediaVerificationOperation::new(self.superblock, self.access, self.filesystem_length)
    }
    /// Media authority fixed before recovery; failure state cannot widen it.
    #[must_use]
    pub const fn access(&self) -> super::MediaAccess {
        self.access
    }

    /// Builds the immutable profile after the selected mount protocol admits its view.
    pub(super) fn new(
        mount: &MountIdentity,
        superblock: Superblock,
        filesystem_length: DeviceLength,
        journal_target: Option<StorageTarget>,
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
    pub const fn journal_target(&self) -> Option<StorageTarget> {
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
    /// Allocation ownership when metadata updates are admitted; read-only observations need none.
    pub(super) clusters: Option<ClusterReferenceIndex>,
    /// Durable journal payloads not yet copied to home blocks.
    pub(super) overlay: Vec<JournalBlock>,
    /// Immutable virtual recovery bytes; absent for writable mounts.
    recovery: Option<alloc::sync::Arc<super::recovery::RecoveryOverlay>>,
}

impl CommittedEpoch {
    /// Persistent filesystem health from this exact committed metadata view.
    #[must_use]
    pub const fn requires_check(&self) -> bool {
        self.superblock.requires_check()
    }
    /// Declared format of this committed view, including recovered metadata on read-only mounts.
    #[must_use]
    pub const fn features(&self) -> crate::FilesystemFeatures {
        self.superblock.features()
    }
    /// Rejects media mutation independently of mount-local key publication.
    /// # Errors
    /// Returns write protection for sessions admitted without media authority.
    pub(super) fn require_writable(&self) -> Result<()> {
        match self.access {
            super::MediaAccess::ReadWrite => Ok(()),
            super::MediaAccess::ReadOnly => Err(Error::ReadOnlyFilesystem),
        }
    }

    /// Builds the initial visible epoch after the selected recovery and mount validation.
    /// The admitted origin was reserved before the first ownership or recovery effect.
    pub(super) fn initial(
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: Option<ClusterReferenceIndex>,
        access: super::MountAccess,
        mount: MountIdentity,
    ) -> Self {
        Self {
            mount,
            access: access.media_access(),
            sequence: EpochSequence::INITIAL,
            superblock,
            fscrypt_keys,
            clusters,
            overlay: Vec::new(),
            recovery: None,
        }
    }

    /// Builds a post-commit epoch from values allocated before the first lower write.
    pub(super) fn prepared(
        current: &Self,
        sequence: EpochSequence,
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: Option<ClusterReferenceIndex>,
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
            first_data_block: self.superblock.first_data_block(),
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
        let overlay = crate::disk_format::journal::JournalOverlay::new(
            self.superblock.block_size(),
            &self.overlay,
        );
        if overlay.read(target, offset, out)? {
            return Ok(true);
        }
        if let Some(recovery) = &self.recovery
            && recovery.read(target, offset, out)?
        {
            overlay.apply(target, offset, out)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if let Some(recovery) = &self.recovery {
            recovery.apply(target, offset, out)?;
        }
        crate::disk_format::journal::JournalOverlay::new(
            self.superblock.block_size(),
            &self.overlay,
        )
        .apply(target, offset, out)
    }
}

/// Serialized publication authority, independent of journal presence and durability.
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

/// Publication serialization and optional media journal. Key publication needs no journal.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the bounded inline journal moves between coordinator and checkpoint without allocating at publication"
)]
pub(super) enum PublicationState {
    /// Media ownership has been revoked; neither issued grants nor cached reads can restore it.
    Fenced {
        /// Last published identity retained for recovery diagnostics and stale-grant checks.
        epoch: (FilesystemUuid, EpochSequence),
    },
    /// Serialized publication lane, including mount-local key changes without a journal.
    Ready {
        /// Clean log available for media mutation; absent for read-only published sessions.
        journal: Option<Journal<CleanJournal>>,
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

impl PublicationState {
    /// Identity published by the transition that owns this journal phase.
    const fn epoch(&self) -> (FilesystemUuid, EpochSequence) {
        match self {
            Self::Ready { epoch, .. }
            | Self::CheckpointPending { epoch, .. }
            | Self::Fenced { epoch } => *epoch,
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

/// Coordinator-admitted snapshot for one synchronous mutation pass.
/// Its constructor checks the session and selected epoch. Staging remains provisional; sealing
/// and commit preparation revalidate against the current coordinator before any effect.
#[derive(Debug)]
pub struct MutationResolveContext<'state> {
    /// Immutable exclusions captured without borrowing unrelated native preparation state.
    pub(super) exclusions: super::trim::AllocationExclusions,
    /// Current immutable metadata and cache borrow; no journal publication capability is exposed.
    pub(super) cache: crate::MetadataCacheAccess<'state>,
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
    /// Allocation admission reservations remain independent of committed ownership.
    pub(super) trims: super::trim::TrimReservations,
    /// Fixed media authority; key-publication grants do not widen it.
    access: super::MediaAccess,
    /// Origin retained independently of on-disk UUID and local sequence numbers.
    pub(super) mount: MountIdentity,
    /// Current journal phase.
    pub(super) journal: PublicationState,
    /// Monotonic FIFO ticket assigned to the next mutation admission.
    next_ticket: u64,
    /// Next non-reusable commit acquisition identity.
    next_claim: u64,
    /// Indexed committed resource versions, expanded before commit I/O.
    resource_versions: ResourceVersionTable,
}

impl MutationCoordinatorState {
    /// Irreversibly revokes this session after loss of media ownership. A fresh mount must observe
    /// ownership and recover storage; issued intent, commit, visibility and checkpoint grants do not
    /// reconstruct the retired journal cursor or authorize another publication.
    pub fn revoke_media_ownership(&mut self) {
        let epoch = self.journal.epoch();
        self.journal = PublicationState::Fenced { epoch };
    }

    /// Requires the mounted session's independently revocable media ownership.
    /// # Errors
    /// Returns ownership loss after the one-way fence transition.
    pub(super) const fn require_session_authority(&self) -> Result<()> {
        if matches!(self.journal, PublicationState::Fenced { .. }) {
            return Err(Error::MmpOwnershipLost);
        }
        Ok(())
    }

    /// Fixed media authority of this coordinator session.
    pub(super) const fn mount_access(&self) -> super::MediaAccess {
        self.access
    }

    /// Published identity paired with the committed resource-version authority.
    pub(super) const fn published_epoch(&self) -> (FilesystemUuid, EpochSequence) {
        self.journal.epoch()
    }
    /// Pairs publication authority with the admitted media journal, when one exists.
    pub(crate) fn new(journal: Option<Journal<CleanJournal>>, current: &CommittedEpoch) -> Self {
        Self {
            trims: super::trim::TrimReservations::new(),
            mount: current.mount,
            access: current.access,
            journal: PublicationState::Ready {
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
        self.require_session_authority()?;
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

    /// Admits staging against this session's current writable epoch.
    /// # Errors
    /// Returns write protection, revoked ownership or a foreign/superseded metadata snapshot.
    pub fn mutation_context<'state>(
        &self,
        cache: crate::MetadataCacheAccess<'state>,
    ) -> Result<MutationResolveContext<'state>> {
        self.require_session_authority()?;
        let epoch = cache.epoch();
        epoch.require_writable()?;
        if self.mount != epoch.mount
            || self.journal.epoch() != (epoch.identity().uuid(), epoch.sequence())
        {
            return Err(Error::StaleReadContext);
        }
        Ok(MutationResolveContext {
            cache,
            exclusions: self.trims.observe(),
        })
    }

    /// Allocates one stable FIFO ticket without wrapping.
    /// # Errors
    ///
    /// Returns [`Error::ArithmeticOverflow`] when the FIFO ticket space is exhausted.
    pub fn admit_mutation(&mut self) -> Result<u64> {
        self.require_session_authority()?;
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
        self.require_session_authority()?;
        let PublicationState::Ready {
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
        if let PublicationState::Ready { admission, .. } = &mut self.journal {
            *admission = CommitAdmission::Granted(claim);
        }
        self.next_claim = next;
        Ok(Some(super::CommitLease::new(self.mount, claim)))
    }

    /// Revokes an unprepared grant; a stale lease stays invalid after reacquisition.
    /// Prepared, durable, and checkpoint authority can only be retired by their owning values.
    pub fn revoke_unprepared_commit(&mut self, ticket: u64) {
        if let PublicationState::Ready { admission, .. } = &mut self.journal
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
        let PublicationState::Ready { admission, .. } = &mut self.journal else {
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
        let PublicationState::CheckpointPending { epoch, admission } = &mut self.journal else {
            return None;
        };
        if epoch.1 != requested || *admission != CheckpointAdmission::Available {
            return None;
        }
        *admission = CheckpointAdmission::Granted;
        Some(super::CheckpointLease::new(self.mount, requested))
    }

    /// Whether no publication or checkpoint owns this session's serialized lane.
    #[must_use]
    pub fn publication_is_idle(&self) -> bool {
        matches!(
            self.journal,
            PublicationState::Ready {
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
        self.require_session_authority()?;
        let claim = lease.consume(&self.mount)?;
        if claim.ticket != ticket
            || !matches!(self.journal, PublicationState::Ready { admission: CommitAdmission::Granted(current), .. } if current == claim)
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
        if let PublicationState::Ready { admission, .. } = &mut self.journal {
            *admission = match &result {
                Ok(_) => CommitAdmission::Prepared(claim),
                Err(_) => CommitAdmission::Available,
            };
        }
        result
    }

    /// Consumes one visibility lease against its session, preparation and acquisition.
    /// # Errors
    /// Distinguishes revoked media ownership from foreign or superseded grants.
    pub(super) fn validate_visibility(
        &self,
        lease: super::VisibilityLease,
        claim: super::event::CommitClaim,
    ) -> Result<()> {
        self.require_session_authority()?;
        if lease.consume(&self.mount)? != claim
            || !matches!(self.journal, PublicationState::Ready { admission: CommitAdmission::Publishing(current), .. } if current == claim)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(())
    }

    /// Retires an unpublished preparation only when its owning value is being consumed.
    /// # Errors
    /// Returns a foreign or superseded preparation without changing current authority.
    pub(super) fn abort_prepared(
        &mut self,
        mount: MountIdentity,
        claim: super::event::CommitClaim,
    ) -> Result<()> {
        self.require_session_authority()?;
        if self.mount != mount {
            return Err(Error::ClusterReferenceConflict);
        }
        let PublicationState::Ready { admission, .. } = &mut self.journal else {
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
        self.require_session_authority().is_ok()
            && self.mount == observed.mount
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
            clusters: epoch.clusters.as_ref(),
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

    /// Pairs mount-private allocation evidence with its unchanged recovered filesystem.
    pub(super) const fn recovering(
        device: OperationDevice<'storage>,
        superblock: Superblock,
        fscrypt_keys: &'epoch FscryptKeySet,
        clusters: &'epoch ClusterReferenceIndex,
    ) -> Self {
        Self {
            key_dependency: KeySetDependency::Independent,
            observation: None,
            device,
            superblock,
            fscrypt_keys,
            clusters: Some(clusters),
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

/// Proof that this session's media-change obligations completed after its operations drained.
/// Read-only sessions leave the medium's existing recovery markers unchanged.
#[derive(Debug)]
pub struct CleanCloseDurability {
    /// Completion belongs to one admitted session even when UUIDs and device lengths match.
    pub(super) mount: MountIdentity,
}

/// One consuming transition of the clean-close durability protocol.
#[derive(Debug)]
pub enum CleanCloseTransition {
    /// Submit one prepared source read or journal/checkpoint transfer.
    SubmitLower {
        /// Owned lower-storage request.
        request: crate::StorageRequest,
        /// Operation resumed only by the matching completion.
        suspended: Box<CleanCloseOperation>,
    },
    /// This session has no remaining media-change obligation, or closing failed.
    Complete(Result<CleanCloseDurability>),
}

/// Prepares a complete primary block while retaining bytes outside the superblock payload.
/// All log/checkpoint requests are allocated before the first effect; journal replay is the
/// sole repair authority for a torn home image, including its clocks and checksum.
/// # Errors
/// Returns source-read suspension, invalid coordinates, serialization or allocation failure.
fn prepare_session_checkpoint(
    device: &mut OperationDevice<'_>,
    raw: &[u8; 1024],
    block_size: BlockSize,
    journal: &Journal<CleanJournal>,
    flush_before: &[StorageTarget],
) -> Result<StorageRequestSequence<Journal<CleanJournal>>> {
    let blocks = prepare_primary_images(device, raw, block_size)?;
    let prepared = journal.prepare_commit(
        block_size,
        crate::disk_format::journal::JournalCommitImage::full(blocks),
    )?;
    StorageRequestSequence::checkpoint(prepared, flush_before, |journal| journal)
}

/// Retains bytes outside the primary payload in its complete home-block image.
/// # Errors
/// Returns source suspension, range or allocation failure before submission.
fn prepare_primary_images(
    device: &mut OperationDevice<'_>,
    raw: &[u8; 1024],
    block_size: BlockSize,
) -> Result<Vec<JournalBlock>> {
    let block = Superblock::primary_block(block_size);
    let mut bytes = memory::repeated_vec(
        0,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    device.read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
    let offset = usize::try_from(
        1024_u64
            .checked_sub(block_size.offset_of(block)?.get())
            .ok_or(Error::InvalidSuperblock)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    memory::copy_exact(
        bytes
            .get_mut(offset..offset.checked_add(1024).ok_or(Error::ArithmeticOverflow)?)
            .ok_or(Error::InvalidSuperblock)?,
        raw,
    )?;
    let mut blocks = Vec::new();
    blocks.try_push(JournalBlock::new(block, bytes))?;
    Ok(blocks)
}

/// Allocation-before-effects clean shutdown/dismount operation.
#[derive(Debug)]
pub struct CleanCloseOperation {
    /// Exact mount whose drained journal may authorize finalization.
    mount: MountIdentity,
    /// Read-only sessions have no media effects, including flushes.
    access: super::MediaAccess,
    /// Transcript retained until every source byte has been read before effects.
    filesystem: StorageTranscript,
    /// Validated primary block width.
    block_size: BlockSize,
    /// Independent journal device, when present, must be flushed before close publication.
    journal_target: Option<StorageTarget>,
    /// Owns exactly one preparation or lower-transfer continuation.
    phase: CleanClosePhase,
}

/// Frozen after native writeback and every journal user has drained.
#[derive(Debug)]
struct CleanClosePreparation {
    /// Exact drained cursor; no later mutation may advance it during close.
    journal: Journal<CleanJournal>,
    /// One close event clock, retained unchanged across suspended source reads.
    unix_seconds: u64,
}

/// Source preparation and effect submission cannot share a live continuation.
#[derive(Debug)]
enum CleanClosePhase {
    /// Admission and native writeback have not yet drained.
    Ready,
    /// Latest drained journal cursor and close clock, sampled before any close effect.
    Preparing(CleanClosePreparation),
    /// Source read must complete before preparation resumes.
    ReadPending(CleanClosePreparation),
    /// Fully prepared flush, log, checkpoint and clean-journal requests.
    Writing(StorageRequestSequence<Journal<CleanJournal>>),
    /// Matching completion alone can reveal the remaining sequence.
    Pending(crate::PendingStorageTransfer<StorageRequestSequence<Journal<CleanJournal>>>),
    /// Completion consumed this operation's close authority.
    Complete,
}

impl CleanCloseOperation {
    /// Allocates no journal snapshot until the host seals admission and drains native writeback,
    /// mutations, checkpoints and discard. That exclusion must last through finalization.
    #[must_use]
    pub const fn new(profile: &MountedProfile) -> Self {
        Self {
            mount: profile.mount,
            access: profile.access(),
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
            block_size: profile.block_size(),
            journal_target: profile.journal_target(),
            phase: CleanClosePhase::Ready,
        }
    }

    /// Starts finalization using the latest drained journal cursor and current wall clock.
    /// A failure after submission can leave a committed close for subsequent mount recovery;
    /// the host must retain exclusion and must not retry an uncertain close.
    #[must_use]
    pub fn start(
        mut self: Box<Self>,
        coordinator: &MutationCoordinatorState,
        now: Ext4Timestamp,
    ) -> CleanCloseTransition {
        if !matches!(self.phase, CleanClosePhase::Ready) || self.mount != coordinator.mount {
            return CleanCloseTransition::Complete(Err(Error::ClusterReferenceConflict));
        }
        if matches!(self.access, super::MediaAccess::ReadOnly) {
            return CleanCloseTransition::Complete(Ok(CleanCloseDurability { mount: self.mount }));
        }
        if let Err(error) = coordinator.require_session_authority() {
            return CleanCloseTransition::Complete(Err(error));
        }
        let PublicationState::Ready {
            journal: Some(journal),
            admission: CommitAdmission::Available,
            ..
        } = &coordinator.journal
        else {
            return CleanCloseTransition::Complete(Err(Error::ClusterReferenceConflict));
        };
        let journal = match journal.try_clone() {
            Ok(journal) => journal,
            Err(error) => return CleanCloseTransition::Complete(Err(error)),
        };
        // Unsigned superblock clocks clamp dates before the Unix epoch to zero.
        self.phase = CleanClosePhase::Preparing(CleanClosePreparation {
            journal,
            unix_seconds: u64::try_from(now.seconds()).unwrap_or(0),
        });
        self.drive()
    }

    /// Completes one exact transfer. The host retains cancellation until durability completes.
    #[must_use]
    pub fn advance(mut self: Box<Self>, event: super::OperationEvent) -> CleanCloseTransition {
        let super::OperationEvent::StorageCompleted(completion) = event else {
            return CleanCloseTransition::Complete(Err(Error::DeviceIo));
        };
        let result = match core::mem::replace(&mut self.phase, CleanClosePhase::Complete) {
            CleanClosePhase::ReadPending(preparation) => self
                .filesystem
                .complete(completion)
                .map(|()| CleanClosePhase::Preparing(preparation)),
            CleanClosePhase::Pending(pending) => {
                pending.complete(completion).map(CleanClosePhase::Writing)
            }
            _ => Err(Error::DeviceIo),
        };
        match result {
            Ok(phase) => {
                self.phase = phase;
                self.drive()
            }
            Err(error) => CleanCloseTransition::Complete(Err(error)),
        }
    }

    /// Reads every source and prepares every request before issuing the initial durability barrier.
    fn drive(mut self: Box<Self>) -> CleanCloseTransition {
        loop {
            match core::mem::replace(&mut self.phase, CleanClosePhase::Complete) {
                CleanClosePhase::Preparing(preparation) => {
                    let result = (|| {
                        let mut device = OperationDevice::new(&mut self.filesystem);
                        let raw = Superblock::prepare_write_session(
                            &mut device,
                            WriteSessionState::Closed,
                            preparation.unix_seconds,
                        )?;
                        let flushes = [StorageTarget::Filesystem, StorageTarget::ExternalJournal];
                        let flush_before =
                            if self.journal_target == Some(StorageTarget::ExternalJournal) {
                                &flushes[..]
                            } else {
                                &flushes[..1]
                            };
                        prepare_session_checkpoint(
                            &mut device,
                            &raw,
                            self.block_size,
                            &preparation.journal,
                            flush_before,
                        )
                    })();
                    match result {
                        Ok(sequence) => self.phase = CleanClosePhase::Writing(sequence),
                        Err(Error::OperationSuspended) => {
                            let request = match self.filesystem.take_pending_request() {
                                Ok(request) => request,
                                Err(error) => return CleanCloseTransition::Complete(Err(error)),
                            };
                            self.phase = CleanClosePhase::ReadPending(preparation);
                            return CleanCloseTransition::SubmitLower {
                                request,
                                suspended: self,
                            };
                        }
                        Err(error) => return CleanCloseTransition::Complete(Err(error)),
                    }
                }
                CleanClosePhase::Writing(sequence) => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.phase = CleanClosePhase::Pending(suspended);
                        return CleanCloseTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
                    }
                    StorageRequestSequenceStep::Finished(_journal) => {
                        return CleanCloseTransition::Complete(Ok(CleanCloseDurability {
                            mount: self.mount,
                        }));
                    }
                },
                _ => return CleanCloseTransition::Complete(Err(Error::DeviceIo)),
            }
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
            fscrypt_keys: Some(fscrypt_keys),
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
    /// Mount key snapshot moved once into the initial epoch before marker publication.
    fscrypt_keys: Option<FscryptKeySet>,
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
    FinishingReadOnly(Box<CompletedMount>),
    /// Prepared home update has no journal-loading or ordinary mutation authority.
    ReadOnlyWrites {
        /// Fully private mounted state, published only after durability.
        completed: Box<CompletedMount>,
        /// Complete preallocated home-write sequence.
        sequence: StorageRequestSequence<()>,
    },
    /// Only the exact lower completion can reveal the remaining RO completion writes.
    ReadOnlyPending {
        /// Retained private state.
        completed: Box<CompletedMount>,
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
    PreparingMarker(IndexedMountSeed),
    /// The complete session image is journaled and checkpointed before publication.
    SessionWrites {
        /// Fully allocated mounted state, still private.
        completed: UnpublishedMount,
        /// Log, commit, checkpoint and clean-journal durability.
        sequence: StorageRequestSequence<Journal<CleanJournal>>,
    },
    /// Only the matching lower completion can advance session publication.
    SessionPending {
        /// Fully allocated mounted state, still private.
        completed: UnpublishedMount,
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
    Published(Box<CompletedMount>),
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

/// Allocation-indexed mount values awaiting durable write-session marking.
#[derive(Debug)]
struct IndexedMountSeed {
    /// Tracker ownership retained through marker durability.
    orphans: ValidatedOrphanInventory,
    /// Recovery and journal placement facts.
    publication: MountPublicationSeed,
    /// Fully validated committed allocation ownership.
    clusters: Option<ClusterReferenceIndex>,
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
        self.drive()
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
                return self.accept_ownership(
                    PendingMountOwnership::Observation,
                    operation.advance(event, now),
                );
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
                return self.accept_ownership(authority, operation.advance(event, now));
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
        self.drive()
    }

    /// Ownership effects bypass the recovery overlay and every metadata transcript.
    fn accept_ownership(
        mut self: Box<Self>,
        authority: PendingMountOwnership,
        transition: super::MmpTransition,
    ) -> MountTransition {
        match transition {
            super::MmpTransition::SubmitLower { request, suspended } => {
                if !matches!(request, crate::StorageRequest::Read { .. }) {
                    self.media_outcome = MountMediaOutcome::OutcomeUnknown;
                }
                self.ownership = MountOwnership::Pending {
                    operation: suspended,
                    authority,
                };
                MountTransition::SubmitOwnership {
                    request,
                    suspended: self,
                }
            }
            super::MmpTransition::Wait { seconds, suspended } => {
                self.ownership = MountOwnership::Pending {
                    operation: suspended,
                    authority,
                };
                MountTransition::WaitForTimer {
                    seconds,
                    suspended: self,
                }
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
                        Err((error, _renewal)) => return self.fail(error),
                    },
                    _ => return self.fail(Error::DeviceIo),
                };
                self.drive()
            }
            super::MmpTransition::Complete(Err(failure)) => self.fail(failure.reason),
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
            MountState::FinishingReadOnly(completed) => {
                self.filesystem.complete(completion)?;
                self.state = MountState::FinishingReadOnly(completed);
            }
            MountState::ReadOnlyPending { completed, pending } => {
                self.state = MountState::ReadOnlyWrites {
                    completed,
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
            MountState::SessionPending { completed, pending } => {
                self.state = MountState::SessionWrites {
                    completed,
                    sequence: pending.complete(completion)?,
                };
            }
            state @ (MountState::AwaitingExternal { .. }
            | MountState::ReadOnlyWrites { .. }
            | MountState::SessionWrites { .. }
            | MountState::OrphanWrites { .. }
            | MountState::DeltaWrites { .. }
            | MountState::Published(_)) => {
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
    fn drive(mut self: Box<Self>) -> MountTransition {
        let ownership = core::mem::replace(&mut self.ownership, MountOwnership::Unprotected);
        match ownership {
            MountOwnership::Held(lease) => {
                if let Err(error) = lease.authorize(self.now) {
                    return self.fail(error);
                }
                if lease.renewal_due(self.now) {
                    let now = self.now;
                    let (pending, operation) = match lease.renew(now) {
                        Ok(update) => update,
                        Err(error) => return self.fail(error),
                    };
                    let operation = match memory::try_box(operation) {
                        Ok(operation) => operation,
                        Err(error) => return self.fail(error),
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
            _ => return self.fail(Error::DeviceIo),
        }
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
            self = suspended;
        }
    }

    /// Advances internal phases until an owned effect or terminal result is ready.
    fn drive_step(mut self: Box<Self>) -> MountTransition {
        loop {
            match core::mem::replace(&mut self.state, MountState::Resolving) {
                MountState::FinishingReadOnly(mut completed) => {
                    let result = (|| {
                        let mut device = OperationDevice::new(&mut self.filesystem);
                        let mut raw = [0_u8; 1024];
                        device.read_exact_at(ByteOffset::new(1024), &mut raw)?;
                        let superblock = Superblock::parse_read_only(&raw)?;
                        let mut view = EpochReadView::mounting(
                            device,
                            superblock,
                            &completed.epoch.fscrypt_keys,
                        );
                        if !ValidatedOrphanInventory::observe_file(&mut view)? {
                            return Err(Error::InvalidOrphanTracking);
                        }
                        let mut device = OperationDevice::new(&mut self.filesystem);
                        let Some(raw) = Superblock::prepare_read_only_completion(
                            &mut device,
                            self.now.unix_seconds(),
                        )?
                        else {
                            return Ok(None);
                        };
                        let superblock = Superblock::parse_read_only(&raw)?;
                        let images =
                            prepare_primary_images(&mut device, &raw, superblock.block_size())?;
                        let sequence = StorageRequestSequence::home_updates(
                            images,
                            superblock.block_size(),
                            (),
                        )?;
                        Ok(Some((superblock, sequence)))
                    })();
                    match result {
                        Ok(Some((superblock, sequence))) => {
                            completed.epoch.superblock = superblock;
                            completed.profile.superblock = superblock;
                            self.state = MountState::ReadOnlyWrites {
                                completed,
                                sequence,
                            };
                        }
                        Ok(None) => self.state = MountState::Published(completed),
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::FinishingReadOnly(completed);
                            return self.submit_pending_read();
                        }
                        Err(error) => return self.fail(error),
                    }
                }
                MountState::ReadOnlyWrites {
                    completed,
                    sequence,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.state = MountState::ReadOnlyPending {
                            completed,
                            pending: suspended,
                        };
                        return MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
                    }
                    StorageRequestSequenceStep::Finished(()) => {
                        self.state = MountState::Published(completed)
                    }
                },
                MountState::ReadOnlyPending { .. } => return self.fail(Error::DeviceIo),
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
                                return self.fail(Error::UnsupportedJournal);
                            }
                            let operation =
                                match memory::try_box(ExternalJournalProbeOperation::new(
                                    requirement,
                                    external.device_length,
                                )) {
                                    Ok(operation) => operation,
                                    Err(error) => return self.fail(error),
                                };
                            self.state = MountState::LoadingExternal { primary, operation };
                        } else {
                            self.state = MountState::AwaitingExternal { requirement };
                            return MountTransition::DiscoverExternalJournal {
                                requirement,
                                suspended: self,
                            };
                        }
                    }
                    Err(Error::OperationSuspended) => {
                        self.state = MountState::Resolving;
                        return self.submit_pending_read();
                    }
                    Err(error) => return self.fail(error),
                },
                MountState::AwaitingExternal { requirement } => {
                    self.state = MountState::AwaitingExternal { requirement };
                    return MountTransition::DiscoverExternalJournal {
                        requirement,
                        suspended: self,
                    };
                }
                MountState::LoadingExternal { primary, operation } => {
                    match operation.advance_loaded(super::OperationEvent::Admitted) {
                        ExternalJournalLoadTransition::SubmitLower { request, suspended } => {
                            self.state = MountState::LoadingExternal {
                                primary,
                                operation: suspended,
                            };
                            return MountTransition::SubmitLower {
                                request,
                                suspended: self,
                            };
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
                            return self.fail(Error::UnsupportedJournal);
                        }
                        ExternalJournalLoadTransition::Complete(Err(error)) => {
                            return self.fail(error);
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
                        return MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
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
                        Err(error) => return self.fail(error),
                    },
                    Err(error) => return self.fail(error),
                },
                MountState::VerifyingReplayedPrimary {
                    completion,
                    journal_target,
                } => {
                    let primary = {
                        let mut filesystem = OperationDevice::new(&mut self.filesystem);
                        Superblock::read_for_mount(&mut filesystem, self.access)
                    };
                    match primary {
                        Ok(PrimarySuperblockRead::Valid(superblock)) => {
                            if superblock.mmp() != self.mmp_parameters
                                || superblock.uuid() != self.primary_uuid
                            {
                                return self.fail(Error::MmpCorrupt);
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
                                    let operation =
                                        match super::fast_commit::DeltaReplayOperation::new(
                                            self.filesystem.len(),
                                            superblock,
                                            seed,
                                        )
                                        .and_then(memory::try_box)
                                        {
                                            Ok(operation) => operation,
                                            Err(error) => {
                                                return self.fail(error);
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
                            return self.fail(Error::ChecksumMismatch);
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::VerifyingReplayedPrimary {
                                completion,
                                journal_target,
                            };
                            return self.submit_pending_read();
                        }
                        Err(error) => return self.fail(error),
                    }
                }
                MountState::PreparingDeltas {
                    mut operation,
                    journal_target,
                } => {
                    let Some(keys) = self.fscrypt_keys.as_ref() else {
                        return self.fail(Error::DeviceIo);
                    };
                    match operation.next_request(keys) {
                        Ok(Some(request)) => {
                            self.state = MountState::PreparingDeltas {
                                operation,
                                journal_target,
                            };
                            return MountTransition::SubmitLower {
                                request,
                                suspended: self,
                            };
                        }
                        Ok(None) => match (*operation).into_sequence() {
                            Ok(sequence) => {
                                self.state = MountState::DeltaWrites {
                                    sequence,
                                    journal_target,
                                }
                            }
                            Err(error) => return self.fail(error),
                        },
                        Err(error) => return self.fail(error),
                    }
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
                        return MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
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
                    return self.fail(Error::DeviceIo);
                }
                MountState::ScanningOrphans(publication) => {
                    let result = {
                        let device = OperationDevice::new(&mut self.filesystem);
                        let Some(keys) = self.fscrypt_keys.as_ref() else {
                            return self.fail(Error::DeviceIo);
                        };
                        let mut volume =
                            EpochReadView::mounting(device, publication.superblock, keys);
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
                                return self.fail(error);
                            }
                            if self.access.media_access() == super::MediaAccess::ReadOnly
                                && orphans.is_empty()
                            {
                                self.state = MountState::PreparingMarker(IndexedMountSeed {
                                    publication,
                                    orphans,
                                    clusters: None,
                                });
                                continue;
                            }
                            let index = match memory::try_box(AllocationIndexBuild::new()) {
                                Ok(index) => index,
                                Err(error) => return self.fail(error),
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
                        Err(error) => return self.fail(error),
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
                                clusters: Some(clusters),
                            })
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::Indexing(validated);
                            return self.submit_pending_read();
                        }
                        Err(error) => return self.fail(error),
                    }
                }
                MountState::PreparingMarker(indexed) => {
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
                                Ok(_) => return self.fail(Error::MmpCorrupt),
                                Err(error) => return self.fail(error),
                            };
                            let sequence = if matches!(self.access, super::MountAccess::ReadWrite) {
                                let Some(journal) = &indexed.publication.journal else {
                                    return self.fail(Error::JournalCorrupt);
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
                                    Err(error) => return self.fail(error),
                                }
                            } else {
                                None
                            };
                            let keys = match self.fscrypt_keys.take() {
                                Some(keys) => keys,
                                None => return self.fail(Error::DeviceIo),
                            };
                            let epoch = CommittedEpoch::initial(
                                marked,
                                keys,
                                indexed.clusters,
                                self.access,
                                self.mount,
                            );
                            let completed = CompletedMount {
                                mmp: None,
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
                                Err(error) => return self.fail(error),
                            };
                            let completed = UnpublishedMount {
                                completed,
                                orphans: indexed.orphans.into_queue(),
                            };
                            self.state = match sequence {
                                Some(sequence) => MountState::SessionWrites {
                                    completed,
                                    sequence,
                                },
                                None => MountState::RecoveringOrphans(completed),
                            };
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::PreparingMarker(indexed);
                            return self.submit_pending_read();
                        }
                        Err(error) => return self.fail(error),
                    }
                }
                MountState::SessionWrites {
                    mut completed,
                    sequence,
                } => match sequence.advance() {
                    StorageRequestSequenceStep::Submit { request, suspended } => {
                        self.state = MountState::SessionPending {
                            completed,
                            pending: suspended,
                        };
                        return MountTransition::SubmitLower {
                            request,
                            suspended: self,
                        };
                    }
                    StorageRequestSequenceStep::Finished(journal) => {
                        completed.completed.coordinator.journal = PublicationState::Ready {
                            admission: CommitAdmission::Available,
                            journal: Some(journal),
                            epoch: (
                                completed.completed.epoch.identity().uuid(),
                                completed.completed.epoch.sequence(),
                            ),
                        };
                        self.filesystem = StorageTranscript::new(
                            StorageTarget::Filesystem,
                            self.filesystem.len(),
                        );
                        self.state = MountState::RecoveringOrphans(completed);
                    }
                },
                MountState::SessionPending { .. } => {
                    return self.fail(Error::DeviceIo);
                }
                MountState::RecoveringOrphans(mut mount) => {
                    let Some(target) = mount.orphans.current() else {
                        self.state = if matches!(
                            self.access,
                            super::MountAccess::ReadOnly {
                                recovery: super::ReadOnlyRecovery::Replay
                            }
                        ) && self.device_access
                            == super::DeviceWriteAccess::Writable
                            && mount.completed.profile.journal_target().is_some()
                        {
                            MountState::FinishingReadOnly(mount.completed)
                        } else {
                            MountState::Published(mount.completed)
                        };
                        continue;
                    };
                    let inode = target.tracking.inode;
                    let result = {
                        let device = OperationDevice::new(&mut self.filesystem);
                        let view = EpochReadView::committed(device, &mount.completed.epoch);
                        let PublicationState::Ready { journal, .. } =
                            &mount.completed.coordinator.journal
                        else {
                            return self.fail(Error::JournalCorrupt);
                        };
                        prepare_orphan_batch(view, target, journal.as_ref())
                    };
                    match result {
                        Ok((sequence, progress)) => {
                            if let Err(error) = mount.orphans.prepare_advance(inode, progress) {
                                return self.fail(error);
                            }
                            self.state = MountState::OrphanWrites { mount, sequence };
                        }
                        Err(Error::OperationSuspended) => {
                            self.state = MountState::RecoveringOrphans(mount);
                            return self.submit_pending_read();
                        }
                        Err(error) => return self.fail(error),
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
                        mount.completed.epoch.clusters = Some(completion.clusters);
                        mount.completed.profile.superblock = completion.superblock;
                        mount.completed.coordinator.journal = PublicationState::Ready {
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
                    return self.fail(Error::DeviceIo);
                }
                MountState::Published(mut completed) => {
                    if self.access.media_access() == super::MediaAccess::ReadOnly {
                        completed.epoch.clusters = None;
                        let PublicationState::Ready { journal, .. } =
                            &mut completed.coordinator.journal
                        else {
                            return self.fail(Error::JournalCorrupt);
                        };
                        *journal = None;
                    }
                    completed.mmp = match core::mem::replace(
                        &mut self.ownership,
                        MountOwnership::Unprotected,
                    ) {
                        MountOwnership::Held(lease) => Some(lease),
                        MountOwnership::Unprotected => None,
                        _ => return self.fail(Error::DeviceIo),
                    };
                    if let Some(recovery) = self.recovery.take() {
                        completed.epoch.recovery = match recovery.seal() {
                            Ok(recovery) => Some(recovery),
                            Err(error) => return self.fail(error),
                        };
                    }
                    return MountTransition::Complete(Ok(completed));
                }
            }
        }
    }

    /// Drops all preflight cursors before acquiring writable ownership, then reloads under that lease.
    fn admit_journal(
        mut self: Box<Self>,
        primary: ResolvedPrimary,
        journal: Journal<LoadedJournal>,
        journal_target: StorageTarget,
    ) -> MountTransition {
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
                return self.fail(Error::ReadOnlyFilesystem);
            }
            self.state = MountState::ScanningOrphans(MountPublicationSeed {
                superblock,
                journal: None,
                journal_target: None,
            });
            return self.drive();
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
            Err(error) => return self.fail(error),
        };
        self.drive()
    }

    /// Acquires physical ownership only from a checksum-authenticated primary identity.
    /// Private replay observations are discarded; physical recovery is read afresh under the lease.
    fn claim_ownership(mut self: Box<Self>) -> MountTransition {
        self.recovery = None;
        let MountOwnership::ReadyToClaim(owner) =
            core::mem::replace(&mut self.ownership, MountOwnership::Unprotected)
        else {
            return self.fail(Error::DeviceIo);
        };
        let Some(parameters) = self.mmp_parameters else {
            return self.fail(Error::MmpCorrupt);
        };
        let operation =
            match super::MmpOperation::acquire(parameters, owner, super::MediaAccess::ReadWrite)
                .and_then(memory::try_box)
            {
                Ok(operation) => operation,
                Err(error) => return self.fail(error),
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
                    let keys = self.fscrypt_keys.as_ref().ok_or(Error::DeviceIo)?;
                    let mut volume = EpochReadView::mounting(filesystem, superblock, keys);
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
    fn submit_pending_read(mut self: Box<Self>) -> MountTransition {
        match self.filesystem.take_pending_request() {
            Ok(request) => MountTransition::SubmitLower {
                request,
                suspended: self,
            },
            Err(error) => self.fail(error),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{Error, Result};

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
}
