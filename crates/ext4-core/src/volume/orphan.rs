//! Mount-private orphan inventory and checkpointed cleanup ownership.

use super::scope::*;
use crate::disk_format::inode::InodeData;
use crate::disk_format::orphan::OrphanBlockContext;
use crate::disk_format::superblock::JournalMode;

/// Supported orphan-file size, measured in filesystem blocks independently of allocator capacity.
const MAX_ORPHAN_BLOCKS: u64 = 512;

/// Persistent location that must remain until the corresponding inode has finished recovery.
#[derive(Clone, Copy, Debug)]
pub(super) enum OrphanSource {
    /// Slot in an authenticated special-inode block.
    File {
        /// Physical block containing the authenticated slot.
        block: BlockAddress,
        /// Zero-based inode-number slot within the block payload.
        slot: usize,
        /// Special-inode checksum identity retained for exact removal.
        context: OrphanBlockContext,
    },
    /// Current fallback-chain head and its already validated successor.
    Chain {
        /// Successor encoded in the current inode's legacy deletion-time field.
        next: Option<InodeId>,
    },
}

/// One validated tracker-to-inode relation; storage is always re-read after a committed batch.
#[derive(Clone, Copy, Debug)]
pub(super) struct TrackedOrphan {
    /// Inode whose allocation is retained until cleanup completes.
    pub(super) inode: InodeId,
    /// Sole persistent entry granting cleanup authority.
    pub(super) source: OrphanSource,
}

/// Sorted immutable membership used while building the allocation ownership index.
#[derive(Debug)]
pub(super) struct ValidatedOrphanInventory {
    /// Unique inode identities, sorted for membership validation.
    entries: Vec<OrphanRecoveryTarget>,
    /// Fallback head, whose entries must be consumed in chain order.
    head: Option<InodeId>,
}

impl ValidatedOrphanInventory {
    /// Whether mount requires any orphan-cleanup transactions.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Validates both tracker encodings before the first write-session marker.
    /// # Errors
    /// Returns corruption, unsupported storage, capacity, allocation, or suspended-I/O errors.
    pub(super) fn load(volume: &mut EpochReadView<'_, '_>) -> Result<Self> {
        let mut inventory = Self {
            entries: Vec::new(),
            head: volume.superblock.last_orphan(),
        };
        if let Some(file) = volume.superblock.orphan_file() {
            validate_recovery_identity(volume.superblock, file.inode, None)?;
            let raw = read_allocated_inode(volume, file.inode)?;
            let inode = raw.parse()?;
            let block_size = volume.superblock.block_size();
            let block_bytes = u64::from(block_size.bytes());
            let file_size = inode.size().bytes();
            if inode.kind() != InodeKind::File
                || inode.links_count() != Ext4LinkCount::ONE
                || file_size == 0
                || file_size
                    .checked_rem(block_bytes)
                    .ok_or(Error::ArithmeticOverflow)?
                    != 0
            {
                return Err(Error::InvalidOrphanTracking);
            }
            let blocks = inode
                .size()
                .bytes()
                .checked_div(block_bytes)
                .ok_or(Error::ArithmeticOverflow)?;
            if blocks > MAX_ORPHAN_BLOCKS {
                return Err(Error::OrphanRecoveryLimitExceeded);
            }
            let context =
                OrphanBlockContext::new(volume.superblock, file.inode, inode.generation());
            let tree_context = volume.extent_tree_context(&inode);
            let mut logical = 0_u64;
            let mut allocation_items = 0_u64;
            let mut physical_blocks = Vec::new();
            crate::disk_format::extent::visit_allocations(
                inode.extent_root()?,
                block_size,
                &mut volume.device,
                tree_context,
                |allocation| {
                    allocation_items = allocation_items
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                    if allocation_items
                        > MAX_ORPHAN_BLOCKS
                            .checked_mul(2)
                            .ok_or(Error::ArithmeticOverflow)?
                    {
                        return Err(Error::OrphanRecoveryLimitExceeded);
                    }
                    if let crate::disk_format::extent::ExtentAllocation::Data(extent) = allocation {
                        if u64::from(extent.logical_start().as_u32()) != logical
                            || extent.initialization()
                                != crate::disk_format::extent::ExtentInitialization::Initialized
                        {
                            return Err(Error::InvalidOrphanTracking);
                        }
                        logical = logical
                            .checked_add(extent.len().as_u64())
                            .ok_or(Error::ArithmeticOverflow)?;
                        if logical > blocks {
                            return Err(Error::InvalidOrphanTracking);
                        }
                        for offset in 0..extent.len().as_u64() {
                            physical_blocks.try_push(BlockAddress::new(
                                extent
                                    .physical_start()
                                    .get()
                                    .checked_add(offset)
                                    .ok_or(Error::ArithmeticOverflow)?,
                            ))?;
                        }
                    }
                    Ok(())
                },
            )?;
            if logical != blocks
                || u64::try_from(physical_blocks.len()).map_err(|_| Error::ArithmeticOverflow)?
                    != blocks
            {
                return Err(Error::InvalidOrphanTracking);
            }
            for block in physical_blocks {
                let mut bytes = memory::repeated_vec(
                    0,
                    usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
                )?;
                volume
                    .device
                    .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
                let (entries, remainder) = context.entries(&bytes, block)?.as_chunks::<4>();
                if !remainder.is_empty() {
                    return Err(Error::InvalidOrphanTracking);
                }
                for (slot, entry) in entries.iter().enumerate() {
                    let value = le_u32(entry, disk_offset(0))?;
                    if value == 0 {
                        continue;
                    }
                    if !file.present {
                        return Err(Error::InvalidOrphanTracking);
                    }
                    let inode =
                        InodeId::try_from(value).map_err(|_| Error::InvalidOrphanTracking)?;
                    inventory.insert(
                        volume,
                        TrackedOrphan {
                            inode,
                            source: OrphanSource::File {
                                block,
                                slot,
                                context,
                            },
                        },
                    )?;
                }
            }
        }
        let mut current = inventory.head;
        while let Some(inode) = current {
            validate_recovery_identity(
                volume.superblock,
                inode,
                volume.superblock.orphan_file().map(|file| file.inode),
            )?;
            let raw = read_allocated_inode(volume, inode)?;
            let next = match le_u32(raw.bytes(), disk_offset(INODE_DTIME_OFFSET))? {
                0 => None,
                value => Some(InodeId::try_from(value).map_err(|_| Error::InvalidOrphanTracking)?),
            };
            inventory.insert(
                volume,
                TrackedOrphan {
                    inode,
                    source: OrphanSource::Chain { next },
                },
            )?;
            current = next;
        }
        Ok(inventory)
    }

    /// Adds a unique, allocated, checksum-valid recovery target.
    /// # Errors
    /// Returns corruption for duplicate/cyclic identities or invalid targets, or an I/O/allocation error.
    fn insert(&mut self, volume: &mut EpochReadView<'_, '_>, entry: TrackedOrphan) -> Result<()> {
        let insertion = match self
            .entries
            .binary_search_by_key(&entry.inode, |entry| entry.tracking.inode)
        {
            Ok(_) => return Err(Error::InvalidOrphanTracking),
            Err(insertion) => insertion,
        };
        validate_recovery_identity(
            volume.superblock,
            entry.inode,
            volume.superblock.orphan_file().map(|file| file.inode),
        )?;
        let raw = read_allocated_inode(volume, entry.inode)?;
        let recovery = RecoverableOrphanInode::parse(raw)?;
        let allocation = InodeAllocation::load(volume, &recovery)?;
        self.entries.try_insert(
            insertion,
            OrphanRecoveryTarget {
                tracking: entry,
                allocation,
            },
        )
    }

    /// Membership confers allocation-index admission, not permission to mutate the inode.
    pub(super) fn contains(&self, inode: InodeId) -> bool {
        self.entries
            .binary_search_by_key(&inode, |entry| entry.tracking.inode)
            .is_ok()
    }

    /// Transfers the immutable validation inventory into its sole cleanup owner.
    pub(super) fn into_queue(self) -> OrphanRecoveryQueue {
        OrphanRecoveryQueue { inventory: self }
    }
}

/// Private recovery continuation, sealed inside a pending batch until checkpoint completion.
#[derive(Debug)]
pub(super) struct OrphanRecoveryQueue {
    /// No allocation-index observer survives this ownership transition.
    inventory: ValidatedOrphanInventory,
}

impl OrphanRecoveryQueue {
    /// Current chain head takes precedence; file entries can be processed in descending inode order.
    pub(super) fn current(&self) -> Option<&OrphanRecoveryTarget> {
        if let Some(head) = self.inventory.head {
            self.inventory
                .entries
                .binary_search_by_key(&head, |entry| entry.tracking.inode)
                .ok()
                .and_then(|index| self.inventory.entries.get(index))
        } else {
            self.inventory.entries.last()
        }
    }

    /// Prepares the continuation before writes; the mount state seals it until checkpoint durability.
    /// # Errors
    /// Returns an invariant error if the completed target is no longer current.
    pub(super) fn prepare_advance(
        &mut self,
        inode: InodeId,
        progress: OrphanProgress,
    ) -> Result<()> {
        let current = self.current().ok_or(Error::InvalidOrphanTracking)?.tracking;
        if current.inode != inode {
            return Err(Error::InvalidOrphanTracking);
        }
        let index = self
            .inventory
            .entries
            .binary_search_by_key(&inode, |entry| entry.tracking.inode)
            .map_err(|_| Error::InvalidOrphanTracking)?;
        if let OrphanProgress::Remaining(allocation) = progress {
            self.inventory
                .entries
                .get_mut(index)
                .ok_or(Error::InvalidOrphanTracking)?
                .allocation = allocation;
            return Ok(());
        }
        let _entry = self.inventory.entries.try_remove_at(index)?;
        if let OrphanSource::Chain { next } = current.source {
            self.inventory.head = next;
        }
        Ok(())
    }
}

/// Rejects protected metadata inodes before interpreting tracker contents as recovery authority.
/// # Errors
/// Returns an orphan-tracking error for reserved, special, or out-of-range identities.
fn validate_recovery_identity(
    superblock: Superblock,
    inode: InodeId,
    special: Option<InodeId>,
) -> Result<()> {
    if inode.as_u32() < superblock.first_inode().as_u32()
        || inode.as_u32() > superblock.inode_count().as_u32()
        || Some(inode) == special
        || superblock.journal_mode() == JournalMode::Internal(inode)
    {
        return Err(Error::InvalidOrphanTracking);
    }
    Ok(())
}

/// Reads an allocated checksum-valid inode rather than trusting an orphan slot alone.
/// # Errors
/// Returns corruption for a free inode or bad checksum, or an underlying read failure.
pub(super) fn read_allocated_inode(
    volume: &mut EpochReadView<'_, '_>,
    inode: InodeId,
) -> Result<RawInodeRecord> {
    let position = InodeBitmapPosition::from_inode(&volume.superblock, inode)?;
    let descriptor =
        BlockGroupDescriptor::read_from(&mut volume.device, &volume.superblock, position.group())?;
    let bytes = read_allocation_bitmap(
        &mut volume.device,
        &volume.superblock,
        descriptor.inode_bitmap(),
    )?;
    if inode_bitmap_bit_state(&bytes, position)? != BitmapBitState::Used {
        return Err(Error::InvalidOrphanTracking);
    }
    let raw = volume.read_raw_inode_record(inode)?;
    raw.verify_checksum(&volume.superblock)?;
    Ok(raw)
}

/// Extent checksum identity available without granting live namespace access.
pub(super) fn extent_context(superblock: Superblock, inode: &InodeData) -> ExtentTreeContext {
    if superblock.metadata_checksum() == MetadataChecksum::Crc32c {
        ExtentTreeContext::metadata_csum(
            superblock.checksum_seed().as_u32(),
            inode.id(),
            inode.generation().as_u32(),
        )
    } else {
        ExtentTreeContext::none()
    }
}

/// Allocation accounting travels with the current tracker, never as an independent authority.
#[derive(Debug)]
pub(super) struct OrphanRecoveryTarget {
    /// Validated persistent entry to retain until terminal cleanup.
    pub(super) tracking: TrackedOrphan,
    /// Derived per-inode charge; changes are sealed with the corresponding journal batch.
    pub(super) allocation: InodeAllocation,
}

/// Next private queue state prepared before lower writes, installed only in a pending batch.
pub(super) enum OrphanProgress {
    /// The tracker remains until more allocation is removed.
    Remaining(InodeAllocation),
    /// The batch atomically removes the inode's persistent tracker.
    Complete,
}

/// Per-inode cluster charge, including shared xattr allocation and partial BIGALLOC clusters.
#[derive(Debug)]
pub(super) struct InodeAllocation {
    /// Sorted cluster reference multiplicities derived from this inode alone.
    clusters: Vec<InodeClusterCharge>,
}

/// One charged cluster, independent of other inodes' references to shared metadata.
#[derive(Clone, Copy, Debug)]
struct InodeClusterCharge {
    /// Physical allocation-cluster identity.
    cluster: ClusterAddress,
    /// References from this inode's extents, extent metadata, and external xattr.
    references: u32,
}

impl InodeAllocation {
    /// Scans allocation once with a depth-bounded walker before the write-session marker.
    /// # Errors
    /// Returns malformed metadata, checksum, arithmetic, allocation, or read errors.
    fn load(volume: &mut EpochReadView<'_, '_>, inode: &RecoverableOrphanInode) -> Result<Self> {
        use crate::disk_format::extent::{ExtentAllocation, visit_allocations};
        let data = inode.data()?;
        let superblock = volume.superblock;
        let reference_budget = core::cmp::min(
            data.allocation_size()
                .bytes()
                .checked_div(u64::from(superblock.block_size().bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
            superblock.block_count().as_u64(),
        );
        let mut references = 0_u64;
        let mut allocation = Self {
            clusters: Vec::new(),
        };
        if let InodeStorage::Extents(root) = data.storage() {
            visit_allocations(
                root,
                superblock.block_size(),
                &mut volume.device,
                extent_context(superblock, &data),
                |item| {
                    match item {
                        ExtentAllocation::Data(extent) => {
                            references = references
                                .checked_add(extent.len().as_u64())
                                .ok_or(Error::ArithmeticOverflow)?;
                            if references > reference_budget {
                                return Err(Error::InvalidOrphanTracking);
                            }
                            for offset in 0..extent.len().as_u64() {
                                allocation.add(
                                    superblock,
                                    BlockAddress::new(
                                        extent
                                            .physical_start()
                                            .get()
                                            .checked_add(offset)
                                            .ok_or(Error::ArithmeticOverflow)?,
                                    ),
                                )?;
                            }
                        }
                        ExtentAllocation::Metadata(block) => {
                            references =
                                references.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                            if references > reference_budget {
                                return Err(Error::InvalidOrphanTracking);
                            }
                            allocation.add(superblock, block)?;
                        }
                    }
                    Ok(())
                },
            )?;
        }
        if let Some(block) = inode.raw().xattr_block()? {
            references = references.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            if references > reference_budget {
                return Err(Error::InvalidOrphanTracking);
            }
            let mut bytes = memory::repeated_vec(
                0,
                usize::try_from(superblock.block_size().bytes())
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            volume
                .device
                .read_exact_at(superblock.block_size().offset_of(block)?, &mut bytes)?;
            let _xattrs = xattr_storage::parse_external_xattr_block(&bytes, block, &superblock)?;
            allocation.add(superblock, block)?;
        }
        if allocation.size(superblock)? != data.allocation_size() {
            return Err(Error::InvalidOrphanTracking);
        }
        Ok(allocation)
    }

    /// Adds a block's inode-local ownership reference.
    /// # Errors
    /// Returns an allocation, range, or reference-count overflow error.
    fn add(&mut self, superblock: Superblock, block: BlockAddress) -> Result<()> {
        let cluster = superblock.cluster_of_block(block)?;
        match self
            .clusters
            .binary_search_by_key(&cluster, |entry| entry.cluster)
        {
            Ok(index) => {
                let entry = self
                    .clusters
                    .get_mut(index)
                    .ok_or(Error::InvalidOrphanTracking)?;
                entry.references = entry
                    .references
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?;
            }
            Err(index) => self.clusters.try_insert(
                index,
                InodeClusterCharge {
                    cluster,
                    references: 1,
                },
            )?,
        }
        Ok(())
    }

    /// Prepares an independent next charge before a cleanup batch can issue writes.
    /// # Errors
    /// Returns an allocation error or underflow if a release was not owned by this inode.
    pub(super) fn releasing(
        &self,
        superblock: Superblock,
        blocks: &[BlockAddress],
    ) -> Result<Self> {
        let mut next = Self {
            clusters: memory::copied_slice(&self.clusters)?,
        };
        for block in blocks {
            let cluster = superblock.cluster_of_block(*block)?;
            let index = next
                .clusters
                .binary_search_by_key(&cluster, |entry| entry.cluster)
                .map_err(|_| Error::InvalidOrphanTracking)?;
            let entry = next
                .clusters
                .get_mut(index)
                .ok_or(Error::InvalidOrphanTracking)?;
            entry.references = entry
                .references
                .checked_sub(1)
                .ok_or(Error::InvalidOrphanTracking)?;
            if entry.references == 0 {
                let _released = next.clusters.try_remove_at(index)?;
            }
        }
        Ok(next)
    }

    /// Complete i_blocks charge under the filesystem's cluster geometry.
    /// # Errors
    /// Returns a geometry or arithmetic error.
    pub(super) fn size(&self, superblock: Superblock) -> Result<FileAllocationSize> {
        let mut blocks = 0_u64;
        for entry in &self.clusters {
            blocks = blocks
                .checked_add(u64::from(superblock.blocks_in_cluster(entry.cluster)?))
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(FileAllocationSize::from_bytes(
            blocks
                .checked_mul(u64::from(superblock.block_size().bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }
}
