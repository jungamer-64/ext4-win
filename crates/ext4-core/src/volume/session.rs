//! Mounted metadata epochs, resource versions, and serialized publication.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::block_group::ClusterReferenceIndex;
use super::node::{DirectoryNodeId, NodeId};
use crate::disk::block::{BlockAddress, BlockSize, ByteOffset, DeviceLength};
use crate::disk::storage::{StorageReadOverlay, StorageTarget};
use crate::disk_format::inode::InodeId;
use crate::disk_format::journal::{CleanJournal, Journal, JournalBlock};
use crate::disk_format::superblock::{
    BlockGroupId, Ext4VolumeLabel, FilesystemUuid, FreeClusterCount, Superblock,
};
use crate::memory::{self, FallibleVec};
use crate::protection::fscrypt::{FscryptKeyIdentifier, FscryptKeyPresence, FscryptKeySet};
use crate::{Error, Result};

mod grant;
pub(super) use grant::CommitClaim;
pub use grant::{CheckpointLease, CommitLease, MutationLease, VisibilityLease};

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
    /// Opaque mount serial for tagging deferred raw metadata reads.
    pub(super) const fn serial(self) -> usize {
        self.0
    }

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
    pub(super) fn version(&self, resource: MutationResource) -> ResourceVersion {
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
    /// Whole free clusters outside the filesystem's reserved-block pool.
    available_cluster_count: FreeClusterCount,
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

    /// Whole free clusters available to ordinary allocation, excluding reserved blocks.
    #[must_use]
    pub const fn available_cluster_count(self) -> FreeClusterCount {
        self.available_cluster_count
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

/// Origin, sequence, and filesystem of a published metadata view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PublishedEpochId {
    /// Origin of the filesystem view.
    pub(super) mount: MountIdentity,
    /// Current sequence within this mount.
    pub(super) sequence: EpochSequence,
    /// Validated filesystem UUID paired with the published view.
    filesystem: FilesystemUuid,
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
    recovery: Option<ext4_shared::Shared<super::recovery::RecoveryOverlay>>,
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
        recovery: Option<ext4_shared::Shared<super::recovery::RecoveryOverlay>>,
    ) -> Self {
        Self {
            mount,
            access: access.media_access(),
            sequence: EpochSequence::INITIAL,
            superblock,
            fscrypt_keys,
            clusters,
            overlay: Vec::new(),
            recovery,
        }
    }

    /// Builds a post-commit epoch from values allocated before the first lower write.
    /// # Errors
    /// Returns reference exhaustion before any effect or publication when retaining recovery data.
    pub(super) fn prepared(
        current: &Self,
        sequence: EpochSequence,
        superblock: Superblock,
        fscrypt_keys: FscryptKeySet,
        clusters: Option<ClusterReferenceIndex>,
        overlay: Vec<JournalBlock>,
    ) -> Result<Self> {
        Ok(Self {
            mount: current.mount,
            access: current.access,
            sequence,
            superblock,
            fscrypt_keys,
            clusters,
            overlay,
            recovery: current
                .recovery
                .as_ref()
                .map(|overlay| overlay.try_acquire().map_err(crate::memory::shared_failure))
                .transpose()?,
        })
    }

    /// Publication identity used to match a view with its coordinator.
    pub(super) const fn publication_id(&self) -> PublishedEpochId {
        PublishedEpochId {
            mount: self.mount,
            sequence: self.sequence,
            filesystem: self.superblock.uuid(),
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
            available_cluster_count: self.superblock.available_cluster_count(),
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
            && recovery.get().read(target, offset, out)?
        {
            overlay.apply(target, offset, out)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn apply(&self, target: StorageTarget, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if let Some(recovery) = &self.recovery {
            recovery.get().apply(target, offset, out)?;
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
enum CommitAdmission {
    /// No journal or mount-key operation owns the commit lane.
    Available,
    /// One unprepared lease can be consumed or explicitly revoked.
    Granted(CommitClaim),
    /// The preparation owns all subsequent commit/publication authority.
    Prepared(CommitClaim),
    /// One visibility lease has been issued for that preparation.
    Publishing(CommitClaim),
}

/// Checkpoint admission cannot be reconstructed after its lease is issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckpointAdmission {
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
enum PublicationState {
    /// Media ownership has been revoked; neither issued grants nor cached reads can restore it.
    Fenced {
        /// Last published identity retained for recovery diagnostics and stale-grant checks.
        epoch: PublishedEpochId,
    },
    /// Serialized publication lane, including mount-local key changes without a journal.
    Ready {
        /// Clean log available for media mutation; absent for read-only published sessions.
        journal: Option<Journal<CleanJournal>>,
        /// Sole acquisition and consumption state for this clean journal.
        admission: CommitAdmission,
        /// Published identity paired with the version table while no checkpoint is pending.
        epoch: PublishedEpochId,
    },
    /// Commit is visible, while an independent checkpoint still owns the dirty journal state.
    CheckpointPending {
        /// Sole checkpoint acquisition state.
        admission: CheckpointAdmission,
        /// Durable overlay identity paired with versions until home-block durability completes.
        epoch: PublishedEpochId,
    },
}

impl PublicationState {
    /// Identity published by the transition that owns this journal phase.
    const fn epoch(&self) -> PublishedEpochId {
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
    pub(super) fn include(
        &mut self,
        resource: MutationResource,
        version: ResourceVersion,
    ) -> Result<()> {
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
    /// Current journal phase.
    journal: PublicationState,
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
    pub(super) const fn published_epoch(&self) -> PublishedEpochId {
        self.journal.epoch()
    }

    /// Identity of this session, including after its authority has been fenced.
    pub(super) const fn mount(&self) -> MountIdentity {
        self.published_epoch().mount
    }

    /// Pairs publication authority with the admitted media journal, when one exists.
    pub(super) fn new(journal: Option<Journal<CleanJournal>>, current: &CommittedEpoch) -> Self {
        Self {
            trims: super::trim::TrimReservations::new(),
            access: current.access,
            journal: PublicationState::Ready {
                admission: CommitAdmission::Available,
                journal,
                epoch: current.publication_id(),
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
        if self.published_epoch() != epoch.publication_id() {
            return Err(Error::StaleReadContext);
        }
        Ok(CommittedReadContext {
            cache,
            versions: &self.resource_versions,
        })
    }

    /// Admits staging against this session's current writable epoch.
    /// # Errors
    /// Returns write protection, revoked ownership, a foreign/superseded metadata snapshot, or
    /// reference exhaustion while retaining active discard exclusions.
    pub fn mutation_context<'state>(
        &self,
        cache: crate::MetadataCacheAccess<'state>,
    ) -> Result<MutationResolveContext<'state>> {
        self.require_session_authority()?;
        let epoch = cache.epoch();
        epoch.require_writable()?;
        if self.published_epoch() != epoch.publication_id() {
            return Err(Error::StaleReadContext);
        }
        Ok(MutationResolveContext {
            cache,
            exclusions: self.trims.observe()?,
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
    pub fn grant_intent(&mut self, ticket: u64) -> MutationLease {
        MutationLease::new(self.mount(), ticket)
    }

    /// Consumes the grant for the complete resource intent acquired by the scheduler.
    /// # Errors
    /// Returns a conflict for a grant issued by another mount or for another mutation.
    pub(super) fn consume_intent(&self, intent: MutationLease, ticket: u64) -> Result<()> {
        if intent.consume(&self.mount())? != ticket {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(())
    }

    /// Acquires the sole commit lane without bypassing a pending checkpoint.
    /// `Ok(None)` denotes contention and leaves the existing owner unchanged.
    /// # Errors
    /// Returns acquisition-identity exhaustion before issuing any authority.
    pub fn acquire_commit(&mut self, ticket: u64) -> Result<Option<CommitLease>> {
        self.require_session_authority()?;
        let PublicationState::Ready {
            admission: CommitAdmission::Available,
            ..
        } = self.journal
        else {
            return Ok(None);
        };
        let claim = CommitClaim {
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
        Ok(Some(CommitLease::new(self.mount(), claim)))
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
    pub fn acquire_visibility(&mut self, ticket: u64) -> Option<VisibilityLease> {
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
        Some(VisibilityLease::new(self.mount(), claim))
    }

    /// Acquires checkpoint authority exactly once for the currently visible dirty epoch.
    /// A dropped or consumed lease is never reissued; its owner must complete or recover the mount.
    #[must_use]
    pub fn acquire_checkpoint(&mut self, requested: EpochSequence) -> Option<CheckpointLease> {
        let PublicationState::CheckpointPending { epoch, admission } = &mut self.journal else {
            return None;
        };
        if epoch.sequence != requested || *admission != CheckpointAdmission::Available {
            return None;
        }
        *admission = CheckpointAdmission::Granted;
        Some(CheckpointLease::new(epoch.mount, requested))
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
    fn accept_commit(&self, lease: CommitLease, ticket: u64) -> Result<CommitClaim> {
        self.require_session_authority()?;
        let claim = lease.consume(&self.mount())?;
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
        lease: CommitLease,
        ticket: u64,
        prepare: impl FnOnce(&mut Self, CommitClaim) -> Result<T>,
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
    fn validate_visibility(&self, lease: VisibilityLease, claim: CommitClaim) -> Result<()> {
        self.require_session_authority()?;
        if lease.consume(&self.mount())? != claim
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
        claim: CommitClaim,
    ) -> Result<()> {
        self.require_session_authority()?;
        if self.mount() != mount {
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
            && self.mount() == observed.mount
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
    pub(super) fn prepare_version_publication(
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

    /// Supplies the clean journal under a commit acquisition during effect-free preparation.
    /// # Errors
    /// Returns journal corruption or a foreign or superseded epoch.
    pub(super) fn journal_for_commit(
        &self,
        current: &CommittedEpoch,
    ) -> Result<&Journal<CleanJournal>> {
        let PublicationState::Ready {
            journal: Some(journal),
            epoch,
            ..
        } = &self.journal
        else {
            return Err(Error::JournalCorrupt);
        };
        if *epoch != current.publication_id() {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(journal)
    }

    /// Snapshots the idle journal for an operation whose host has drained the session.
    /// # Errors
    /// Returns revoked ownership, a busy or absent journal, or snapshot allocation failure.
    pub(super) fn drained_journal(&self) -> Result<Journal<CleanJournal>> {
        self.require_session_authority()?;
        let PublicationState::Ready {
            journal: Some(journal),
            admission: CommitAdmission::Available,
            ..
        } = &self.journal
        else {
            return Err(Error::ClusterReferenceConflict);
        };
        journal.try_clone()
    }

    /// Captures the current predecessor for a key change under commit acquisition.
    /// # Errors
    /// Returns a stale context when the epoch no longer owns the publication lane.
    pub(super) fn key_change_predecessor(
        &self,
        current: &CommittedEpoch,
    ) -> Result<PublishedEpochId> {
        let expected = current.publication_id();
        if !matches!(self.journal, PublicationState::Ready { epoch, .. } if epoch == expected) {
            return Err(Error::StaleReadContext);
        }
        Ok(expected)
    }

    /// Consumes visibility authority and atomically advances the keys and their dependency version.
    /// # Errors
    /// Returns the unpublished version delta so the caller retains the prepared successor.
    pub(super) fn publish_keys(
        &mut self,
        visibility: VisibilityLease,
        claim: CommitClaim,
        predecessor: PublishedEpochId,
        successor: &CommittedEpoch,
        versions: ResourceVersionPublication,
    ) -> core::result::Result<(), (Error, ResourceVersionPublication)> {
        if let Err(error) = self.validate_visibility(visibility, claim) {
            return Err((error, versions));
        }
        if self.mount() != successor.mount {
            return Err((Error::ClusterReferenceConflict, versions));
        }
        let PublicationState::Ready {
            epoch, admission, ..
        } = &mut self.journal
        else {
            return Err((Error::StaleReadContext, versions));
        };
        if *epoch != predecessor {
            return Err((Error::StaleReadContext, versions));
        }
        *epoch = successor.publication_id();
        *admission = CommitAdmission::Available;
        self.resource_versions.publish(versions);
        Ok(())
    }

    /// Consumes visibility authority and transfers the durable epoch to checkpoint ownership.
    /// # Errors
    /// Returns the unpublished version delta with the grant or predecessor conflict.
    pub(super) fn publish_durable(
        &mut self,
        visibility: VisibilityLease,
        claim: CommitClaim,
        successor: &CommittedEpoch,
        versions: ResourceVersionPublication,
    ) -> core::result::Result<(), (Error, ResourceVersionPublication)> {
        if let Err(error) = self.validate_visibility(visibility, claim) {
            return Err((error, versions));
        }
        if !self.is_next_epoch(successor) {
            return Err((Error::ClusterReferenceConflict, versions));
        }
        self.journal = PublicationState::CheckpointPending {
            admission: CheckpointAdmission::Available,
            epoch: successor.publication_id(),
        };
        self.resource_versions.publish(versions);
        Ok(())
    }

    /// Consumes the checkpoint lease before its first home-block write.
    /// # Errors
    /// Returns revoked ownership or a foreign, unacquired, or superseded checkpoint.
    pub(super) fn authorize_checkpoint(
        &self,
        lease: CheckpointLease,
        successor: &CommittedEpoch,
    ) -> Result<()> {
        self.require_session_authority()?;
        if !self.is_next_epoch(successor)
            || self.published_epoch().filesystem != successor.identity().uuid()
            || !self.checkpoint_is_granted()
            || lease
                .consume(&successor.mount)
                .and_then(EpochSequence::next)
                != Ok(successor.sequence())
        {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(())
    }

    /// Installs only the checkpoint successor whose home blocks and clean record are durable.
    /// # Errors
    /// When ownership was revoked or the checkpoint no longer matches, returns the clean journal
    /// so the caller retains its completion.
    #[expect(
        clippy::result_large_err,
        reason = "a rejected checkpoint returns its clean cursor without allocating"
    )]
    pub(super) fn publish_checkpoint(
        &mut self,
        successor: &CommittedEpoch,
        clean_journal: Journal<CleanJournal>,
    ) -> core::result::Result<(), (Error, Journal<CleanJournal>)> {
        if let Err(error) = self.require_session_authority() {
            return Err((error, clean_journal));
        }
        if !self.is_next_epoch(successor) || !self.checkpoint_is_granted() {
            return Err((Error::ClusterReferenceConflict, clean_journal));
        }
        self.journal = PublicationState::Ready {
            admission: CommitAdmission::Available,
            journal: Some(clean_journal),
            epoch: successor.publication_id(),
        };
        Ok(())
    }

    /// Whether the supplied epoch immediately succeeds this mount's published view.
    fn is_next_epoch(&self, successor: &CommittedEpoch) -> bool {
        let current = self.published_epoch();
        current.mount == successor.mount && current.sequence.next() == Ok(successor.sequence())
    }

    /// Whether the current dirty epoch has handed out its one checkpoint lease.
    fn checkpoint_is_granted(&self) -> bool {
        matches!(
            self.journal,
            PublicationState::CheckpointPending {
                admission: CheckpointAdmission::Granted,
                ..
            }
        )
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
