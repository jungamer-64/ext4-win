//! Journaled write transaction domain for mounted ext4 volumes.

use super::scope::*;

mod allocation;
mod commit;
mod file_data;
mod namespace;
mod staging;
mod xattr;

use commit::{
    descriptor_byte_count, directory_entry_kind, map_extents, reject_reserved_directory_name,
    verity_metadata_image,
};
use staging::{BlockImage, EncryptedBlockBase, GroupDelta, RangeWrite};

/// Extent-tree reader that overlays this transaction's staged metadata blocks on the device.
struct TransactionExtentSource<'source, 'device> {
    /// Mounted storage containing committed extent metadata.
    device: &'source mut OperationDevice<'device>,
    /// Newer extent metadata images staged by this transaction.
    staged: &'source [BlockImage],
    /// Mounted filesystem block size used to locate staged images.
    block_size: BlockSize,
}

impl crate::disk_format::extent::ExtentNodeReader for TransactionExtentSource<'_, '_> {
    fn read_extent_bytes(&mut self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.device.read_exact_at(offset, out)?;
        let request_start = offset.get();
        let request_end = request_start
            .checked_add(u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        for image in self.staged {
            let image_start = self.block_size.offset_of(image.block)?.get();
            let image_end = image_start
                .checked_add(
                    u64::try_from(image.bytes.len()).map_err(|_| Error::ArithmeticOverflow)?,
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
                    .bytes
                    .get(source_start..source_end)
                    .ok_or(Error::DeviceRange)?,
            )?;
        }
        Ok(())
    }
}

/// Contiguous allocation-cluster ownership contributed by one inode structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InodeAllocationClusterRange {
    /// First allocation cluster owned by the inode structure.
    start: ClusterAddress,
    /// Exclusive cluster boundary, which may equal the filesystem cluster count.
    end_exclusive: u64,
}

impl InodeAllocationClusterRange {
    /// Maps one contiguous physical extent to its inclusive allocation-cluster coverage.
    /// # Errors
    ///
    /// Returns an error when the extent's physical range overflows or lies outside the filesystem.
    fn from_extent(superblock: Superblock, extent: Extent) -> Result<Self> {
        let last_offset = extent
            .len()
            .as_u64()
            .checked_sub(1)
            .ok_or(Error::InvalidExtentTree)?;
        let last_block = BlockAddress::new(
            extent
                .physical_start()
                .get()
                .checked_add(last_offset)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        Self::from_inclusive_clusters(
            superblock.cluster_of_block(extent.physical_start())?,
            superblock.cluster_of_block(last_block)?,
        )
    }

    /// Maps one inode-owned metadata block to its allocation cluster.
    /// # Errors
    ///
    /// Returns an error when `block` lies outside the filesystem or its exclusive cluster boundary
    /// overflows.
    fn from_block(superblock: Superblock, block: BlockAddress) -> Result<Self> {
        let cluster = superblock.cluster_of_block(block)?;
        Self::from_inclusive_clusters(cluster, cluster)
    }

    /// Builds a nonempty range from validated inclusive cluster boundaries.
    /// # Errors
    ///
    /// Returns an error when the boundaries are reversed or the exclusive end overflows.
    fn from_inclusive_clusters(start: ClusterAddress, end: ClusterAddress) -> Result<Self> {
        if end < start {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(Self {
            start,
            end_exclusive: end.get().checked_add(1).ok_or(Error::ArithmeticOverflow)?,
        })
    }

    /// Extends this range across an overlapping or adjacent sorted range.
    ///
    /// Returns whether `next` was merged.
    fn merge_sorted(&mut self, next: Self) -> bool {
        if next.start.get() > self.end_exclusive {
            return false;
        }
        self.end_exclusive = core::cmp::max(self.end_exclusive, next.end_exclusive);
        true
    }

    /// Returns the physical filesystem-block charge for this cluster range.
    /// # Errors
    ///
    /// Returns an error when cluster arithmetic overflows or the filesystem's final cluster cannot
    /// be inspected.
    fn charged_blocks(self, superblock: Superblock) -> Result<u64> {
        let clusters = self
            .end_exclusive
            .checked_sub(self.start.get())
            .ok_or(Error::InvalidClusterGeometry)?;
        let blocks_per_cluster = u64::from(superblock.blocks_per_cluster().as_u32());
        let mut blocks = clusters
            .checked_mul(blocks_per_cluster)
            .ok_or(Error::ArithmeticOverflow)?;
        if self.end_exclusive == superblock.cluster_count().as_u64() {
            let final_cluster = ClusterAddress::new(
                self.end_exclusive
                    .checked_sub(1)
                    .ok_or(Error::InvalidClusterGeometry)?,
            );
            let final_blocks = u64::from(superblock.blocks_in_cluster(final_cluster)?);
            let missing_tail = blocks_per_cluster
                .checked_sub(final_blocks)
                .ok_or(Error::InvalidClusterGeometry)?;
            blocks = blocks
                .checked_sub(missing_tail)
                .ok_or(Error::InvalidClusterGeometry)?;
        }
        Ok(blocks)
    }
}

/// Regular file selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFile {
    /// Mutable regular-file inode selected for this transaction.
    id: FileNodeId,
}

impl TransactionFile {
    /// Typed inode identifier backing this transaction file.
    #[must_use]
    pub const fn id(self) -> FileNodeId {
        self.id
    }

    /// Raw inode backing this transaction file.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }
}

/// Directory selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionDirectory {
    /// Mutable directory inode selected for this transaction.
    id: DirectoryNodeId,
}

impl TransactionDirectory {
    /// Typed inode identifier backing this transaction directory.
    #[must_use]
    pub const fn id(self) -> DirectoryNodeId {
        self.id
    }

    /// Raw inode backing this transaction directory.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }
}

/// Symbolic link selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionSymlink {
    /// Mutable symbolic-link inode selected for this transaction.
    id: SymlinkNodeId,
}

/// Non-directory inode selected as the source of a hard-link mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionHardLinkSource {
    /// Typed source kind; a directory cannot inhabit this state.
    id: HardLinkNodeId,
}

impl TransactionHardLinkSource {
    /// Raw inode backing this hard-link source.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }

    /// Directory-entry kind stored for a new link to this source.
    const fn entry_kind(self) -> DirectoryEntryKind {
        self.id.entry_kind()
    }
}

/// Prevalidated namespace state at a requested hard-link destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardLinkDestination<'name> {
    /// No Windows-visible entry occupies the requested destination.
    Vacant,
    /// One exact ext4 entry selected for replacement occupies the destination.
    Replace {
        /// Existing on-disk name, which can differ from the requested name only by case.
        existing_name: &'name Ext4Name,
    },
}

/// How a rename handles an already existing target name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameTargetCollision {
    /// The target name must be absent.
    Reject,
    /// The target name may be replaced by the source entry.
    Replace,
}

impl TransactionSymlink {
    /// Typed inode identifier backing this transaction symlink.
    #[must_use]
    pub const fn id(self) -> SymlinkNodeId {
        self.id
    }
}

/// Inode selected for POSIX metadata mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionNode {
    /// Mutable inode selected for metadata updates.
    id: NodeId,
}

impl TransactionNode {
    /// Typed inode identifier backing this transaction node.
    #[must_use]
    pub const fn id(self) -> NodeId {
        self.id
    }

    /// Raw inode backing this transaction node.
    const fn inode(self) -> InodeId {
        self.id.inode()
    }
}

/// Restart-local mutation resolver that owns no committed or coordinator state.
#[derive(Debug)]
pub struct MutationResolvePass<'storage, 'epoch, 'nonce, N> {
    /// Ephemeral view of the selected committed epoch and operation transcript.
    volume: EpochReadView<'storage, 'epoch>,
    /// Operation-owned nonce source, retained outside committed epoch state.
    nonce_generator: &'nonce mut N,
    /// Timestamp applied consistently to staged inode updates.
    now: Ext4Timestamp,
    /// Inode records staged for rewrite at commit.
    inode_updates: Vec<StagedInodeRecord>,
    /// Block bitmap images staged for allocation changes.
    block_bitmap_updates: Vec<BlockImage>,
    /// Inode bitmap images staged for allocation changes.
    inode_bitmap_updates: Vec<BlockImage>,
    /// Directory block images staged after dirent mutation.
    directory_updates: Vec<BlockImage>,
    /// External extent tree blocks staged after extent mutation.
    extent_updates: Vec<BlockImage>,
    /// External xattr blocks staged after xattr mutation.
    xattr_updates: Vec<BlockImage>,
    /// Per-group allocation count deltas to fold into descriptors.
    group_deltas: Vec<GroupDelta>,
    /// Ordered file data writes that must reach disk before metadata commit.
    data_writes: Vec<RangeWrite>,
    /// Staged cluster-reference changes to apply after journal commit.
    cluster_deltas: Vec<ClusterReferenceDelta>,
    /// Superblock free-cluster delta accumulated by this transaction.
    free_clusters_delta: FreeClusterDelta,
    /// Superblock free-inode delta accumulated by this transaction.
    free_inodes_delta: i64,
    /// Superblock volume label replacement staged by this transaction.
    volume_label_update: Option<Ext4VolumeLabel>,
    /// Mount-scoped fscrypt key snapshot prepared during resolve.
    fscrypt_keys_update: Option<FscryptKeySet>,
}

/// Fully resolved mutation with resource versions and provisional allocation choices.
#[derive(Debug)]
pub struct ResolvedMutation {
    /// Resource set and versions observed by this resolve pass.
    observed: ObservedResourceVersionSet,
    /// Ordered data images that must be durable before journal metadata is written.
    data_writes: Vec<RangeWrite>,
    /// Complete metadata blocks supplied to JBD2 serialization.
    metadata_blocks: Vec<MetadataBlock>,
    /// Cluster-reference changes merged into the latest disjoint committed epoch at commit grant.
    cluster_deltas: Vec<ClusterReferenceDelta>,
    /// Free-cluster counter change merged at commit grant.
    free_clusters_delta: FreeClusterDelta,
    /// Free-inode counter change merged at commit grant.
    free_inodes_delta: i64,
    /// Optional label replacement merged at commit grant.
    volume_label_update: Option<Ext4VolumeLabel>,
    /// Optional replacement for the mount-scoped fscrypt key snapshot.
    fscrypt_keys_update: Option<FscryptKeySet>,
}

impl ResolvedMutation {
    /// Resource/version snapshot used for intent acquisition and pre-reservation revalidation.
    #[must_use]
    pub const fn observed_resources(&self) -> &ObservedResourceVersionSet {
        &self.observed
    }

    /// Consumes a version-revalidated mutation into the reservation typestate.
    ///
    /// Allocation choices remain provisional until this transition occurs while all listed
    /// resource intents are held.
    /// # Errors
    ///
    /// Returns an error when a resource version changed after resolution.
    pub fn reserve(
        self,
        coordinator: &MutationCoordinatorState,
        intent: super::MutationLease,
    ) -> Result<ReservedMutation> {
        if intent.into_ticket() != self.observed.ticket() || !coordinator.revalidate(&self.observed)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(ReservedMutation { resolved: self })
    }
}

/// Mutation whose provisional block and inode choices are protected by held intents.
#[derive(Debug)]
pub struct ReservedMutation {
    /// Version-revalidated resolved data.
    resolved: ResolvedMutation,
}

/// All lower-write, epoch-publication, version, and checkpoint allocations prepared up front.
#[derive(Debug)]
pub struct CommitReadyMutation {
    /// Ordered data writes before journal descriptor/data records.
    ordered_data_writes: Vec<crate::StorageRequest>,
    /// Dirty-superblock, descriptor, and journal payload writes.
    journal_writes: Vec<crate::StorageRequest>,
    /// Commit record written after the first journal durability flush.
    commit_write: crate::StorageRequest,
    /// Journal device whose flush establishes commit durability.
    journal_target: crate::StorageTarget,
    /// Dirty journal coordinator value moved at visibility publication.
    durable_journal: Journal<DirtyJournal>,
    /// Immutable overlay epoch moved at visibility publication.
    durable_epoch: CommittedEpoch,
    /// Preallocated checkpoint and overlay-free epoch detached from visibility.
    checkpoint: CheckpointOperation,
    /// Complete next resource-version table.
    version_publication: ResourceVersionPublication,
}

/// Commit whose record and required flush are durable but not yet visible to readers.
#[derive(Debug)]
pub struct DurableMutation {
    /// Dirty journal coordinator value.
    durable_journal: Journal<DirtyJournal>,
    /// Overlay epoch ready for an allocation-free swap.
    durable_epoch: CommittedEpoch,
    /// Independent checkpoint work and overlay-free epoch.
    checkpoint: CheckpointOperation,
    /// Resource versions moved into the coordinator during visibility publication.
    version_publication: ResourceVersionPublication,
}

/// Visibility publication result containing the new epoch and detached checkpoint operation.
#[derive(Debug)]
pub struct PublishedMutation {
    /// Committed overlay epoch swapped into the bounded epoch registry.
    epoch: CommittedEpoch,
    /// Checkpoint work that does not retain the visibility grant.
    checkpoint: CheckpointOperation,
}

impl PublishedMutation {
    /// Consumes publication into the new epoch and independent checkpoint operation.
    #[must_use]
    pub fn into_parts(self) -> (CommittedEpoch, CheckpointOperation) {
        (self.epoch, self.checkpoint)
    }
}

/// Home-block checkpoint and clean-journal publication prepared before the commit started.
#[derive(Debug)]
pub struct CheckpointOperation {
    /// Preallocated filesystem home writes.
    home_writes: Vec<crate::StorageRequest>,
    /// Preallocated clean journal-superblock write.
    clean_write: crate::StorageRequest,
    /// Clean journal state installed after the final flush.
    clean_journal: Journal<CleanJournal>,
    /// Overlay-free epoch installed after the final flush.
    checkpointed_epoch: CommittedEpoch,
}

/// Allocation-free iterator over one prebuilt storage-request sequence.
#[derive(Debug)]
pub struct StorageRequestSequence<Next> {
    /// Remaining requests moved one at a time into lower-I/O ownership.
    remaining: alloc::vec::IntoIter<crate::StorageRequest>,
    /// Continuation revealed only after the sequence is exhausted.
    next: Next,
}

/// Consuming transition from a prebuilt storage-request sequence.
#[derive(Debug)]
pub enum StorageRequestSequenceStep<Next> {
    /// Submit one owned request and retain the remaining sequence as suspended operation state.
    Submit {
        /// Owned request transferred into the lower completion envelope.
        request: crate::StorageRequest,
        /// Suspended sequence resumed only by that request's completion.
        suspended: StorageRequestSequence<Next>,
    },
    /// Every request completed and the next typestate is available.
    Finished(Next),
}

impl<Next> StorageRequestSequence<Next> {
    /// Builds a consuming sequence from fully preallocated requests.
    fn new(requests: Vec<crate::StorageRequest>, next: Next) -> Self {
        Self {
            remaining: requests.into_iter(),
            next,
        }
    }

    /// Advances to one concrete request or the next phase without allocation.
    #[must_use]
    pub fn advance(mut self) -> StorageRequestSequenceStep<Next> {
        if let Some(request) = self.remaining.next() {
            StorageRequestSequenceStep::Submit {
                request,
                suspended: self,
            }
        } else {
            StorageRequestSequenceStep::Finished(self.next)
        }
    }
}

/// Continuation that requires filesystem durability after ordered data writes.
#[derive(Debug)]
pub struct OrderedDataDurability {
    /// Journal payload requests submitted after the filesystem flush.
    journal_writes: Vec<crate::StorageRequest>,
    /// State following journal payload writes.
    next: JournalPayloadDurability,
}

impl OrderedDataDurability {
    /// Filesystem flush required before journal metadata can be submitted.
    #[must_use]
    pub const fn flush_request(&self) -> crate::StorageRequest {
        crate::StorageRequest::Flush {
            target: crate::StorageTarget::Filesystem,
        }
    }

    /// Consumes a successful filesystem flush into the journal-payload sequence.
    #[must_use]
    pub fn completed(self) -> StorageRequestSequence<JournalPayloadDurability> {
        StorageRequestSequence::new(self.journal_writes, self.next)
    }
}

/// Continuation that requires journal durability after descriptor and payload writes.
#[derive(Debug)]
pub struct JournalPayloadDurability {
    /// Journal device flushed before the commit record is issued.
    journal_target: crate::StorageTarget,
    /// Preallocated commit record.
    commit_write: crate::StorageRequest,
    /// Sealed state revealed after commit durability.
    durable: DurableMutation,
}

impl JournalPayloadDurability {
    /// Flush required before the commit record can be submitted.
    #[must_use]
    pub const fn flush_request(&self) -> crate::StorageRequest {
        crate::StorageRequest::Flush {
            target: self.journal_target,
        }
    }

    /// Consumes a successful payload flush into the single commit-record phase.
    #[must_use]
    pub fn completed(self) -> CommitRecordPhase {
        CommitRecordPhase {
            request: self.commit_write,
            journal_target: self.journal_target,
            durable: self.durable,
        }
    }
}

/// Single commit-record write preceding the commit durability flush.
#[derive(Debug)]
pub struct CommitRecordPhase {
    /// Owned commit-record request.
    request: crate::StorageRequest,
    /// Journal device flushed after the commit record.
    journal_target: crate::StorageTarget,
    /// Sealed durable mutation state.
    durable: DurableMutation,
}

impl CommitRecordPhase {
    /// Moves the commit record into lower-I/O ownership and returns its suspended continuation.
    #[must_use]
    pub fn submit(self) -> (crate::StorageRequest, CommitDurability) {
        (
            self.request,
            CommitDurability {
                journal_target: self.journal_target,
                durable: self.durable,
            },
        )
    }
}

/// Continuation awaiting the flush that makes a commit record durable.
#[derive(Debug)]
pub struct CommitDurability {
    /// Journal device selected for the final commit flush.
    journal_target: crate::StorageTarget,
    /// Mutation revealed only after the flush succeeds.
    durable: DurableMutation,
}

impl CommitDurability {
    /// Flush that establishes commit durability.
    #[must_use]
    pub const fn flush_request(&self) -> crate::StorageRequest {
        crate::StorageRequest::Flush {
            target: self.journal_target,
        }
    }

    /// Reveals the durable mutation after a successful commit flush.
    #[must_use]
    pub fn completed(self) -> DurableMutation {
        self.durable
    }
}

/// Continuation requiring a filesystem flush after all home blocks complete.
#[derive(Debug)]
pub struct HomeBlockDurability {
    /// Clean journal-superblock request issued after home-block durability.
    clean_write: crate::StorageRequest,
    /// Journal target flushed after the clean write.
    journal_target: crate::StorageTarget,
    /// Clean publication state.
    clean_journal: Journal<CleanJournal>,
    /// Overlay-free epoch publication state.
    checkpointed_epoch: CommittedEpoch,
}

impl HomeBlockDurability {
    /// Filesystem flush that makes every checkpointed home block durable.
    #[must_use]
    pub const fn flush_request(&self) -> crate::StorageRequest {
        crate::StorageRequest::Flush {
            target: crate::StorageTarget::Filesystem,
        }
    }

    /// Consumes the successful home-block flush into the clean-record phase.
    #[must_use]
    pub fn completed(self) -> CleanJournalRecordPhase {
        CleanJournalRecordPhase {
            request: self.clean_write,
            journal_target: self.journal_target,
            clean_journal: self.clean_journal,
            checkpointed_epoch: self.checkpointed_epoch,
        }
    }
}

/// Single clean-journal superblock write.
#[derive(Debug)]
pub struct CleanJournalRecordPhase {
    /// Owned clean-superblock request.
    request: crate::StorageRequest,
    /// Journal device flushed after this request.
    journal_target: crate::StorageTarget,
    /// Clean journal coordinator state.
    clean_journal: Journal<CleanJournal>,
    /// Overlay-free committed epoch.
    checkpointed_epoch: CommittedEpoch,
}

impl CleanJournalRecordPhase {
    /// Moves the clean record into lower-I/O ownership and returns its continuation.
    #[must_use]
    pub fn submit(self) -> (crate::StorageRequest, CleanJournalDurability) {
        (
            self.request,
            CleanJournalDurability {
                journal_target: self.journal_target,
                clean_journal: self.clean_journal,
                checkpointed_epoch: self.checkpointed_epoch,
            },
        )
    }
}

/// Continuation awaiting the flush that makes the clean journal state durable.
#[derive(Debug)]
pub struct CleanJournalDurability {
    /// Journal device selected for the clean-state flush.
    journal_target: crate::StorageTarget,
    /// Clean journal coordinator state.
    clean_journal: Journal<CleanJournal>,
    /// Overlay-free epoch publication state.
    checkpointed_epoch: CommittedEpoch,
}

impl CleanJournalDurability {
    /// Flush that makes the clean journal superblock durable.
    #[must_use]
    pub const fn flush_request(&self) -> crate::StorageRequest {
        crate::StorageRequest::Flush {
            target: self.journal_target,
        }
    }
}

impl<'storage, 'epoch, 'nonce, N> MutationResolvePass<'storage, 'epoch, 'nonce, N> {
    /// Starts an empty mutation resolve pass against one committed epoch.
    pub(super) fn begin(
        volume: EpochReadView<'storage, 'epoch>,
        now: Ext4Timestamp,
        nonce_generator: &'nonce mut N,
    ) -> Self {
        Self {
            volume,
            nonce_generator,
            now,
            inode_updates: Vec::new(),
            block_bitmap_updates: Vec::new(),
            inode_bitmap_updates: Vec::new(),
            directory_updates: Vec::new(),
            extent_updates: Vec::new(),
            xattr_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            cluster_deltas: Vec::new(),
            free_clusters_delta: FreeClusterDelta::ZERO,
            free_inodes_delta: 0,
            volume_label_update: None,
            fscrypt_keys_update: None,
        }
    }
}
impl<N: FscryptNonceGenerator> MutationResolvePass<'_, '_, '_, N> {
    /// Verifies that the mounted profile admits xattr storage mutation.
    /// # Errors
    ///
    /// Returns an error when mounted xattr feature flags do not permit xattr storage mutation.
    fn require_xattr_mutation(&self) -> Result<()> {
        self.volume.superblock.xattr_mutation().require_supported()
    }

    /// Selects any supported inode for POSIX metadata mutation.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or carries mutation
    /// semantics outside the write domain.
    pub fn node(&mut self, id: NodeId) -> Result<TransactionNode> {
        let inode = self.volume.read_inode_record(id.inode())?;
        let _metadata = inode.metadata_mutation()?;
        match (id, inode.kind()) {
            (NodeId::File(_), InodeKind::File)
            | (NodeId::Directory(_), InodeKind::Directory)
            | (NodeId::Symlink(_), InodeKind::Symlink) => Ok(TransactionNode { id }),
            _ => Err(Error::WrongInodeKind),
        }
    }

    /// Selects a regular file for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file or cannot be read.
    pub fn file(&mut self, id: FileNodeId) -> Result<TransactionFile> {
        let inode = self.volume.read_inode_record(id.inode())?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        Ok(TransactionFile { id })
    }

    /// Selects a directory for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a directory or cannot be read.
    pub fn directory(&mut self, id: DirectoryNodeId) -> Result<TransactionDirectory> {
        let inode = self.volume.read_inode_record(id.inode())?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        Ok(TransactionDirectory { id })
    }

    /// Selects a symbolic link for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a symbolic link or carries
    /// mutation semantics outside the write domain.
    pub fn symlink(&mut self, id: SymlinkNodeId) -> Result<TransactionSymlink> {
        let inode = self.volume.read_inode_record(id.inode())?;
        if inode.kind() != InodeKind::Symlink {
            return Err(Error::WrongInodeKind);
        }
        self.require_file_data_mutation(&inode)?;
        Ok(TransactionSymlink { id })
    }

    /// Selects a regular file or symbolic link as a hard-link source.
    ///
    /// # Errors
    /// Returns an error when the typed identity does not match the inode or names a directory.
    pub fn hard_link_source(&mut self, id: HardLinkNodeId) -> Result<TransactionHardLinkSource> {
        let inode = self.volume.read_inode_record(id.inode())?;
        let _metadata = inode.metadata_mutation()?;
        match (id, inode.kind()) {
            (HardLinkNodeId::File(_), InodeKind::File)
            | (HardLinkNodeId::Symlink(_), InodeKind::Symlink) => {}
            (HardLinkNodeId::File(_), InodeKind::Directory | InodeKind::Symlink)
            | (HardLinkNodeId::Symlink(_), InodeKind::File | InodeKind::Directory) => {
                return Err(Error::WrongInodeKind);
            }
        }
        Ok(TransactionHardLinkSource { id })
    }

    /// Updates POSIX owner and permission state representable by ext4 inode fields.
    ///
    /// # Errors
    /// Returns an error when the inode leaves the mutable write domain or the
    /// inode record cannot be rewritten.
    pub fn set_posix_security(
        &mut self,
        node: TransactionNode,
        security: Ext4Security,
    ) -> Result<()> {
        let inode_index = self.ensure_inode_update(node.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        let _metadata = inode.metadata_mutation()?;
        raw_inode.set_owner(security.owner())?;
        raw_inode.set_permissions(security.permissions())?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Updates ext4 inode timestamps from a complete timestamp domain value.
    ///
    /// # Errors
    /// Returns an error when the inode leaves the mutable write domain or the
    /// inode record cannot be rewritten.
    pub fn set_times(&mut self, node: TransactionNode, times: Ext4Times) -> Result<()> {
        let inode_index = self.ensure_inode_update(node.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        let _metadata = inode.metadata_mutation()?;
        raw_inode.set_ext4_times(times, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Replaces the ext4 volume label stored in the primary superblock.
    pub fn set_volume_label(&mut self, label: Ext4VolumeLabel) {
        self.volume_label_update = Some(label);
    }

    /// Adds one key to an operation-owned snapshot for allocation-free durable publication.
    /// # Errors
    ///
    /// Returns an error when cloning key material fails or the identifier already exists.
    pub fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Result<()> {
        let mut keys = match self.fscrypt_keys_update.take() {
            Some(keys) => keys,
            None => self.volume.fscrypt_keys.try_clone()?,
        };
        keys.insert(key)?;
        self.fscrypt_keys_update = Some(keys);
        Ok(())
    }

    /// Removes one key from an operation-owned snapshot for allocation-free publication.
    /// # Errors
    ///
    /// Returns an error when cloning or rebuilding the key set fails.
    pub fn remove_fscrypt_key(&mut self, identifier: FscryptKeyIdentifier) -> Result<bool> {
        let mut keys = match self.fscrypt_keys_update.take() {
            Some(keys) => keys,
            None => self.volume.fscrypt_keys.try_clone()?,
        };
        let removed = keys.remove(identifier)?.is_some();
        self.fscrypt_keys_update = Some(keys);
        Ok(removed)
    }

    /// Computes mounted cluster state after a successful commit.
    /// # Errors
    ///
    /// Returns an error when staged cluster deltas conflict or the superblock free-cluster delta
    /// cannot be applied.
    fn committed_cluster_state(&self) -> Result<(ClusterReferenceIndex, Superblock)> {
        let mut clusters = self.volume.committed_clusters()?.try_clone()?;
        clusters.apply_deltas(self.cluster_deltas.as_slice())?;
        let mut superblock = self.volume.superblock;
        superblock.apply_free_cluster_delta(self.free_clusters_delta)?;
        superblock.apply_free_inode_delta(self.free_inodes_delta)?;
        if let Some(label) = self.volume_label_update {
            superblock.apply_volume_label(label);
        }
        Ok((clusters, superblock))
    }

    /// Verifies directory-entry creation policy using the latest staged inode.
    /// # Errors
    ///
    /// Returns an error when the parent inode cannot be loaded from staged/device state or does not
    /// permit directory-entry creation.
    fn require_directory_entry_create_mutation(
        &mut self,
        inode_id: InodeId,
    ) -> Result<DirectoryEntryMutationCapability> {
        let raw_inode = self.raw_inode_for_policy(inode_id)?;
        let inode = raw_inode.parse()?;
        self.require_directory_entry_create_mutation_for_inode(&inode)
    }

    /// Verifies directory-entry creation policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when `inode` is not a directory, lacks a required fscrypt key, or its
    /// storage policy rejects entry creation.
    fn require_directory_entry_create_mutation_for_inode(
        &mut self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
        }
        inode.directory_entry_mutation()
    }

    /// Verifies directory-entry deletion policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when `inode` is not a directory or its storage policy rejects entry
    /// deletion.
    fn require_directory_entry_delete_mutation_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        inode.directory_entry_mutation()
    }

    /// Verifies directory-entry rename policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when the source directory cannot satisfy entry creation-style mutation
    /// requirements for rename staging.
    fn require_directory_entry_rename_mutation_for_inode(
        &mut self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        self.require_directory_entry_create_mutation_for_inode(inode)
    }

    /// Verifies directory-entry replacement policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when the target directory cannot satisfy entry creation-style mutation
    /// requirements for replacement staging.
    fn require_directory_entry_replace_mutation_for_inode(
        &mut self,
        inode: &Inode,
    ) -> Result<DirectoryEntryMutationCapability> {
        self.require_directory_entry_create_mutation_for_inode(inode)
    }

    /// Builds the fscrypt context inherited by a new child of this directory.
    /// # Errors
    ///
    /// Returns an error when the encrypted parent has no mounted master key or a new file nonce
    /// cannot be generated.
    fn inherited_fscrypt_context(&mut self, parent: &Inode) -> Result<Option<FscryptContextV2>> {
        if !parent.protection().is_encrypted() {
            return Ok(None);
        }
        let (parent_context, _master_key) = self.volume.fscrypt_master_key_for_inode(parent)?;
        let nonce = self.nonce_generator.next_file_nonce()?;
        Ok(Some(FscryptContextV2::new(parent_context.policy(), nonce)))
    }

    /// Stores an inherited fscrypt context on a newly-initialized live inode.
    /// # Errors
    ///
    /// Returns an error when xattr mutation is unsupported, the encryption flag cannot be written,
    /// or the context cannot be stored in inode xattr storage.
    fn apply_fscrypt_context(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        context: Option<FscryptContextV2>,
    ) -> Result<()> {
        let Some(context) = context else {
            return Ok(());
        };
        self.require_xattr_mutation()?;
        raw_inode.mark_encrypted()?;
        let mut set = self.xattr_set_for_raw_inode(raw_inode)?;
        set.set_encryption_context(XattrValue::new(&context.to_bytes())?);
        self.store_xattr_set(raw_inode, &set)
    }

    /// Returns the staged inode record when present, otherwise the device image.
    /// # Errors
    ///
    /// Returns an error when an existing staged record is deleted or the live inode cannot be read
    /// from the mounted device.
    fn raw_inode_for_policy(&mut self, inode_id: InodeId) -> Result<LiveInodeRecord> {
        if let Some(raw_inode) = self
            .inode_updates
            .iter()
            .find(|raw_inode| raw_inode.id() == inode_id)
        {
            return raw_inode.clone_live();
        }
        self.volume.read_live_inode_record(inode_id)
    }

    /// Loads a mutable extent tree for an inode selected by this transaction.
    /// # Errors
    ///
    /// Returns an error when the inode does not expose a supported extent root or its extent tree
    /// cannot be loaded.
    fn mutable_extent_tree(&mut self, inode: &Inode) -> Result<MutableExtentTree> {
        let context = self.volume.extent_tree_context(inode);
        let block_size = self.volume.superblock.block_size();
        let mut source = TransactionExtentSource {
            device: &mut self.volume.device,
            staged: &self.extent_updates,
            block_size,
        };
        MutableExtentTree::load_inode_tree(inode.extent_root()?, block_size, &mut source, context)
    }

    /// Stages an updated extent tree and adjusts its metadata block ownership.
    /// # Errors
    ///
    /// Returns an error when metadata block allocation or release fails, extent serialization fails,
    /// or the updated inode block charge cannot be represented.
    fn stage_extent_tree(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        mut tree: MutableExtentTree,
    ) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let required = tree.required_metadata_blocks(block_size)?;
        let mut metadata_blocks = memory::copied_slice(tree.metadata_blocks())?;
        while metadata_blocks.len() < required {
            metadata_blocks.try_push(self.allocate_cluster()?)?;
        }
        while metadata_blocks.len() > required {
            let block = metadata_blocks.pop().ok_or(Error::InvalidExtentTree)?;
            self.release_cluster_reference(block)?;
        }
        tree.set_metadata_blocks(metadata_blocks);

        let inode = raw_inode.parse()?;
        let serialized = tree.serialize(block_size, self.volume.extent_tree_context(&inode))?;
        self.stage_serialized_extent_tree(raw_inode, &serialized)?;
        self.set_inode_allocation_size(raw_inode, Some(&tree))
    }

    /// Recomputes and writes the allocation charge for one inode.
    /// # Errors
    ///
    /// Returns an error when inode-owned blocks cannot be mapped to allocation clusters or the
    /// resulting charge cannot be represented by the mounted inode encoding.
    fn set_inode_allocation_size(
        &self,
        raw_inode: &mut LiveInodeRecord,
        tree: Option<&MutableExtentTree>,
    ) -> Result<()> {
        let allocation_size = self.inode_allocation_size(raw_inode, tree)?;
        let encoded = self
            .volume
            .superblock
            .inode_data_encoding()
            .encode_allocation_size(allocation_size)?;
        raw_inode.set_encoded_allocation_size(encoded)
    }

    /// Counts all allocation clusters owned by one inode.
    /// # Errors
    ///
    /// Returns an error when extent block arithmetic overflows or an inode-owned block cannot be
    /// mapped to mounted cluster geometry.
    fn inode_allocation_size(
        &self,
        raw_inode: &LiveInodeRecord,
        tree: Option<&MutableExtentTree>,
    ) -> Result<FileAllocationSize> {
        let superblock = self.volume.superblock;
        let mut ranges = Vec::new();
        if let Some(tree) = tree {
            for extent in tree.extents().iter().copied() {
                ranges.try_push(InodeAllocationClusterRange::from_extent(
                    superblock, extent,
                )?)?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                ranges.try_push(InodeAllocationClusterRange::from_block(superblock, block)?)?;
            }
        }
        if let Some(block) = raw_inode.xattr_block()? {
            ranges.try_push(InodeAllocationClusterRange::from_block(superblock, block)?)?;
        }
        memory::heap_sort_by(&mut ranges, |left, right| left.start.cmp(&right.start))?;

        let mut merged_ranges: Vec<InodeAllocationClusterRange> = Vec::new();
        for range in ranges {
            if let Some(previous) = merged_ranges.last_mut()
                && previous.merge_sorted(range)
            {
                continue;
            }
            merged_ranges.try_push(range)?;
        }
        let mut blocks = 0_u64;
        for range in merged_ranges {
            blocks = blocks
                .checked_add(range.charged_blocks(superblock)?)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        let bytes = blocks
            .checked_mul(u64::from(superblock.block_size().bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(FileAllocationSize::from_bytes(bytes))
    }

    /// Copies a serialized extent tree into the inode and metadata block staging areas.
    /// # Errors
    ///
    /// Returns an error when the serialized inode-root extent payload cannot be written.
    fn stage_serialized_extent_tree(
        &mut self,
        raw_inode: &mut LiveInodeRecord,
        serialized: &SerializedExtentTree,
    ) -> Result<()> {
        raw_inode.set_extent_root_bytes(serialized.inode_root())?;
        for block in serialized.external_blocks() {
            self.extent_updates.try_push(BlockImage {
                block: block.block(),
                bytes: memory::copied_slice(block.bytes())?,
            })?;
        }
        Ok(())
    }

    /// Increments a directory inode link count and updates timestamps.
    /// # Errors
    ///
    /// Returns an error when the directory inode cannot be staged, its link count is saturated, or
    /// timestamps cannot be written.
    fn increment_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        raw_inode.increment_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Decrements a directory inode link count and updates timestamps.
    /// # Errors
    ///
    /// Returns an error when the directory inode cannot be staged or the decremented link count and
    /// timestamps cannot be written.
    fn decrement_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let _links = raw_inode.decrement_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Returns the staged inode record index, loading it once when needed.
    /// # Errors
    ///
    /// Returns an error when `inode_id` cannot be read as a live inode or the staged index cannot be
    /// represented.
    fn ensure_inode_update(&mut self, inode_id: InodeId) -> Result<StagedInodeIndex> {
        if let Some(index) = self
            .inode_updates
            .iter()
            .position(|inode| inode.id() == inode_id)
        {
            return Ok(StagedInodeIndex::new(index));
        }
        let raw_inode = self.volume.read_live_inode_record(inode_id)?;
        self.inode_updates.try_push(raw_inode.into())?;
        Ok(StagedInodeIndex::new(
            self.inode_updates
                .len()
                .checked_sub(1)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Returns a staged live inode record by index.
    /// # Errors
    ///
    /// Returns an error when `index` is outside the staging vector or refers to a deleted inode.
    fn staged_live_inode(&self, index: StagedInodeIndex) -> Result<LiveInodeRecord> {
        self.inode_updates
            .get(index.get())
            .ok_or(Error::InvalidInode)?
            .clone_live()
    }

    /// Replaces a staged inode with its updated live state.
    /// # Errors
    ///
    /// Returns an error when `index` is outside the staged inode vector.
    fn replace_live_inode(
        &mut self,
        index: StagedInodeIndex,
        record: LiveInodeRecord,
    ) -> Result<()> {
        *self
            .inode_updates
            .get_mut(index.get())
            .ok_or(Error::InvalidInode)? = record.into();
        Ok(())
    }

    /// Replaces a staged inode with its deleted state.
    /// # Errors
    ///
    /// Returns an error when `index` is outside the staged inode vector.
    fn replace_deleted_inode(
        &mut self,
        index: StagedInodeIndex,
        record: DeletedInodeRecord,
    ) -> Result<()> {
        *self
            .inode_updates
            .get_mut(index.get())
            .ok_or(Error::InvalidInode)? = record.into();
        Ok(())
    }
}

impl<N: FscryptNonceGenerator> super::CommittedReadPass for MutationResolvePass<'_, '_, '_, N> {
    fn load_file(&mut self, id: FileNodeId) -> Result<FileNode> {
        self.volume.load_file(id)
    }

    fn load_directory(&mut self, id: DirectoryNodeId) -> Result<DirectoryNode> {
        self.volume.load_directory(id)
    }

    fn load_symlink(&mut self, id: SymlinkNodeId) -> Result<SymlinkNode> {
        self.volume.load_symlink(id)
    }

    fn load_node_by_file_index(&mut self, file_index: u32) -> Result<NodeId> {
        self.volume.load_node_by_file_index(file_index)
    }

    fn read_xattrs(&mut self, node: NodeId) -> Result<XattrSet> {
        self.volume.read_inode_xattrs(node.inode())
    }

    fn read_xattr(&mut self, node: NodeId, name: &XattrName) -> Result<Option<XattrValue>> {
        self.volume.read_inode_xattr(node.inode(), name)
    }

    fn read_windows_overlay(&mut self, node: NodeId) -> Result<Option<WindowsOverlay>> {
        self.volume.read_inode_windows_overlay(node.inode())
    }

    fn read_windows_symlink_reparse_point(
        &mut self,
        node: NodeId,
    ) -> Result<Option<WindowsSymlinkReparsePoint>> {
        self.volume
            .read_inode_windows_symlink_reparse_point(node.inode())
    }

    fn read_file(
        &mut self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.volume.read_file(file, offset, out)
    }

    fn read_symlink(&mut self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.volume.read_symlink(symlink)
    }

    fn read_directory(&mut self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        self.volume.read_directory(directory)
    }

    fn read_hard_links(&mut self, target: HardLinkNodeId) -> Result<HardLinks> {
        self.volume.read_hard_links(target)
    }

    fn lookup_child(&mut self, parent: &DirectoryNode, name: &Ext4Name) -> Result<ChildLookup> {
        self.volume.lookup_child(parent, name)
    }

    fn lookup_windows_child(
        &mut self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<ChildLookup> {
        self.volume.lookup_windows_child(parent, requested)
    }
}
