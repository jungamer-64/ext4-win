//! Mount-private resumable allocation validation.

use super::*;
use crate::disk::storage::{StorageTarget, StorageTranscript};
use crate::disk_format::extent::{ExtentAllocation, ExtentAllocationCursor};
use crate::disk_format::inode::InodeData;
use crate::volume::orphan::ValidatedOrphanInventory;

/// Allocation evidence stays private until every owner and bitmap has been checked.
/// Each successful step retains decoded state, so only an unfinished read can be retried.
#[derive(Debug)]
pub(in crate::volume) struct AllocationIndexBuild {
    /// Descriptor, bitmap, and inode ownership are transferred between these phases.
    phase: IndexPhase,
    /// Physical ranges gathered once; sorting and conflict checking precede publication.
    ranges: Vec<AllocationRange>,
}

/// Only the inode phase contains a complete allocation snapshot.
#[derive(Debug)]
enum IndexPhase {
    /// Descriptor order is the group identity; layouts are its immutable projection.
    Descriptors {
        /// Validated descriptors in contiguous group order.
        descriptors: Vec<(BlockGroupId, BlockGroupDescriptor)>,
        /// Read-only layout projection derived from the descriptors.
        layouts: Vec<GroupMetadataLayout>,
    },
    /// A completed bitmap pair belongs to the descriptor at the same position.
    Bitmaps {
        /// Validated descriptors in contiguous group order.
        descriptors: Vec<(BlockGroupId, BlockGroupDescriptor)>,
        /// Read-only layout projection derived from the descriptors.
        layouts: Vec<GroupMetadataLayout>,
        /// Fully decoded pairs; their length identifies the next descriptor.
        bitmaps: Vec<(Vec<u8>, Vec<u8>)>,
        /// Which bitmap of the current descriptor may request storage.
        read: BitmapRead,
    },
    /// The cursor advances past an inode only after its allocation walk is owned here.
    Inodes {
        /// Complete recovered bitmap authority for the entire scan.
        allocation: MountedAllocationSnapshot,
        /// Group vector position; advanced only after all its live inodes.
        group: usize,
        /// Next inode bitmap bit, independent of the active inode traversal.
        bit: u32,
        /// Active inode traversal, or permission to select the next bitmap bit.
        scan: InodeAllocationScan,
    },
    /// The validated index has been consumed; this builder cannot be resumed.
    Finished,
}

/// A block bitmap is retained while the matching inode bitmap is outstanding.
#[derive(Debug)]
enum BitmapRead {
    /// No block bitmap has been consumed for this group.
    Block,
    /// Owns the block bitmap while its paired inode bitmap is read.
    Inode(Vec<u8>),
}

/// Allocation traversal retained across inode and external-node reads.
#[derive(Debug)]
enum InodeAllocationScan {
    /// No inode allocation remains outstanding.
    Next,
    /// A validated root and depth-bounded path retain extent progress.
    Extents(ExtentAllocationCursor),
    /// The double-indirect block is counted but its pointers are not yet read.
    ResizeRoot(BlockAddress),
    /// Parsed indirect addresses; only the selected branch can suspend.
    ResizeBranches {
        /// Nonzero child addresses owned by the decoded double-indirect block.
        blocks: Vec<BlockAddress>,
        /// First child whose metadata and reserved blocks are not yet counted.
        next: usize,
    },
}

/// Shared xattr blocks are the sole permitted overlap between physical owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockOwnership {
    /// Any second physical owner is corruption.
    Exclusive,
    /// Multiple inode references to the same singleton xattr block are valid.
    SharedXattr,
}

/// Nonempty half-open physical block range; shared ranges contain exactly one block.
#[derive(Clone, Copy, Debug)]
struct AllocationRange {
    /// Inclusive physical start.
    start: BlockAddress,
    /// Exclusive physical end, checked when the range is constructed.
    end: BlockAddress,
    /// Determines whether an overlap is a legitimate shared xattr.
    ownership: BlockOwnership,
}

impl AllocationRange {
    /// Checks range arithmetic before it enters the ownership inventory.
    /// # Errors
    /// Returns an error for an empty/overflowing range or a multi-block shared owner.
    fn new(start: BlockAddress, blocks: u64, ownership: BlockOwnership) -> Result<Self> {
        if blocks == 0 || (ownership == BlockOwnership::SharedXattr && blocks != 1) {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(Self {
            start,
            end: BlockAddress::new(
                start
                    .get()
                    .checked_add(blocks)
                    .ok_or(Error::ArithmeticOverflow)?,
            ),
            ownership,
        })
    }

    /// Equal singleton xattr owners count separately but may share physical storage.
    fn can_follow(self, previous: Self) -> bool {
        self.start >= previous.end
            || (self.ownership == BlockOwnership::SharedXattr
                && previous.ownership == BlockOwnership::SharedXattr
                && self.start == previous.start)
    }
}

impl AllocationIndexBuild {
    /// Begins with no validated allocation authority and no outstanding I/O.
    pub(in crate::volume) const fn new() -> Self {
        Self {
            phase: IndexPhase::Descriptors {
                descriptors: Vec::new(),
                layouts: Vec::new(),
            },
            ranges: Vec::new(),
        }
    }

    /// Advances against the same immutable recovered filesystem until completion or I/O.
    /// Decoded state owns every successful read before its transcript is released. Suspension
    /// retains only the unfinished step. Other errors are terminal and discard the builder.
    /// # Errors
    /// Returns malformed metadata, conflicting ownership, allocation, or storage errors.
    pub(in crate::volume) fn advance(
        &mut self,
        transcript: &mut StorageTranscript,
        superblock: &Superblock,
        orphans: &ValidatedOrphanInventory,
    ) -> Result<ClusterReferenceIndex> {
        loop {
            let result = self.step(&mut OperationDevice::new(transcript), superblock, orphans)?;
            // A successful step never retains a pending request or borrows transcript bytes.
            *transcript = StorageTranscript::new(StorageTarget::Filesystem, transcript.len());
            if let Some(index) = result {
                return Ok(index);
            }
        }
    }

    /// Runs one decode/ownership step. Only suspension leaves a step eligible for retry.
    /// # Errors
    /// Returns validation, allocation, or suspended-I/O errors before any mount publication.
    fn step(
        &mut self,
        reader: &mut OperationDevice<'_>,
        superblock: &Superblock,
        orphans: &ValidatedOrphanInventory,
    ) -> Result<Option<ClusterReferenceIndex>> {
        match &mut self.phase {
            IndexPhase::Descriptors {
                descriptors,
                layouts,
            } => {
                let group =
                    u32::try_from(descriptors.len()).map_err(|_| Error::ArithmeticOverflow)?;
                if group == superblock.block_group_count()?.as_u32() {
                    self.phase = IndexPhase::Bitmaps {
                        descriptors: core::mem::take(descriptors),
                        layouts: core::mem::take(layouts),
                        bitmaps: Vec::new(),
                        read: BitmapRead::Block,
                    };
                } else {
                    let group = BlockGroupId::from_u32(group);
                    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
                    layouts.try_push(GroupMetadataLayout::from_descriptor(group, &descriptor))?;
                    descriptors.try_push((group, descriptor))?;
                }
            }
            IndexPhase::Bitmaps {
                descriptors,
                layouts,
                bitmaps,
                read,
            } => {
                if bitmaps.len() == descriptors.len() {
                    let mut groups = Vec::new();
                    for ((group, descriptor), (block_bitmap, inode_bitmap)) in
                        core::mem::take(descriptors)
                            .into_iter()
                            .zip(core::mem::take(bitmaps))
                    {
                        groups.try_push(GroupAllocationSnapshot {
                            group,
                            descriptor,
                            block_bitmap,
                            inode_bitmap,
                        })?;
                    }
                    let allocation = MountedAllocationSnapshot { groups };
                    append_static_ranges(&mut self.ranges, superblock, &allocation)?;
                    self.phase = IndexPhase::Inodes {
                        allocation,
                        group: 0,
                        bit: 0,
                        scan: InodeAllocationScan::Next,
                    };
                } else {
                    let (group, descriptor) = descriptors
                        .get(bitmaps.len())
                        .ok_or(Error::InvalidSuperblock)?;
                    match read {
                        BitmapRead::Block => {
                            let bytes = match descriptor.block_bitmap_initialization() {
                                AllocationBitmapInitialization::Initialized => {
                                    read_allocation_bitmap(
                                        reader,
                                        superblock,
                                        descriptor.block_bitmap(),
                                    )?
                                }
                                AllocationBitmapInitialization::Uninitialized => {
                                    materialize_uninitialized_block_bitmap(
                                        superblock, *group, layouts,
                                    )?
                                }
                            };
                            *read = BitmapRead::Inode(bytes);
                        }
                        BitmapRead::Inode(block_bitmap) => {
                            let inode_bitmap = match descriptor.inode_bitmap_initialization() {
                                AllocationBitmapInitialization::Initialized => {
                                    read_allocation_bitmap(
                                        reader,
                                        superblock,
                                        descriptor.inode_bitmap(),
                                    )?
                                }
                                AllocationBitmapInitialization::Uninitialized => {
                                    materialize_uninitialized_inode_bitmap(superblock, *group)?
                                }
                            };
                            bitmaps.try_push((core::mem::take(block_bitmap), inode_bitmap))?;
                            *read = BitmapRead::Block;
                        }
                    }
                }
            }
            IndexPhase::Inodes {
                allocation,
                group,
                bit,
                scan,
            } => {
                if matches!(scan, InodeAllocationScan::Next) {
                    let Some(snapshot) = allocation.groups.get(*group) else {
                        let index = finish_ranges(
                            core::mem::take(&mut self.ranges),
                            superblock,
                            allocation,
                        )?;
                        self.phase = IndexPhase::Finished;
                        return Ok(Some(index));
                    };
                    let count = inode_count_in_group(superblock, snapshot.group)?;
                    while *bit < count {
                        let position = InodeBitmapPosition::new(snapshot.group, *bit);
                        if inode_bitmap_bit_state(&snapshot.inode_bitmap, position)?
                            == BitmapBitState::Used
                        {
                            let raw =
                                read_group_inode_record(reader, superblock, snapshot, position)?;
                            *scan = begin_inode_scan(raw, superblock, orphans, &mut self.ranges)?;
                            *bit = bit.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                            return Ok(None);
                        }
                        *bit = bit.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    }
                    *group = group.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    *bit = 0;
                } else {
                    advance_inode_scan(scan, reader, superblock, &mut self.ranges)?;
                }
            }
            IndexPhase::Finished => return Err(Error::DeviceIo),
        }
        Ok(None)
    }
}

/// Captures the inode's next traversal before advancing the group cursor.
/// # Errors
/// Returns invalid/unsupported inode storage, extent root, or allocation errors.
fn begin_inode_scan(
    raw: RawInodeRecord,
    superblock: &Superblock,
    orphans: &ValidatedOrphanInventory,
    ranges: &mut Vec<AllocationRange>,
) -> Result<InodeAllocationScan> {
    if raw.mode()? == 0 {
        return Ok(InodeAllocationScan::Next);
    }
    if superblock.is_resize_inode(raw.id) {
        let root = raw.resize_inode_block_map()?.double_indirect();
        ranges.try_push(AllocationRange::new(root, 1, BlockOwnership::Exclusive)?)?;
        return Ok(InodeAllocationScan::ResizeRoot(root));
    }
    if let Some(block) = raw.xattr_block()? {
        ranges.try_push(AllocationRange::new(block, 1, BlockOwnership::SharedXattr)?)?;
    }
    if !orphans.contains(raw.id) && raw.parse().is_err() {
        if raw.has_extent_tree()? {
            return Err(Error::UnsupportedBlockMap);
        }
        return Ok(InodeAllocationScan::Next);
    }
    let data = InodeData::parse(raw.id, &raw.bytes, raw.encoding)?;
    match data.storage() {
        InodeStorage::InlineBytes(_) => Ok(InodeAllocationScan::Next),
        InodeStorage::UnsupportedBlockMap => Err(Error::UnsupportedBlockMap),
        InodeStorage::Extents(root) => {
            Ok(InodeAllocationScan::Extents(ExtentAllocationCursor::new(
                root,
                superblock.block_size(),
                crate::volume::orphan::extent_context(*superblock, &data),
            )?))
        }
    }
}

/// One external extent or resize pointer block is consumed at most once.
/// # Errors
/// Returns corrupt pointer/tree, allocation, or read errors; suspension preserves the cursor.
fn advance_inode_scan(
    scan: &mut InodeAllocationScan,
    reader: &mut OperationDevice<'_>,
    superblock: &Superblock,
    ranges: &mut Vec<AllocationRange>,
) -> Result<()> {
    match scan {
        InodeAllocationScan::Next => return Err(Error::DeviceIo),
        InodeAllocationScan::Extents(cursor) => match cursor.next(reader)? {
            Some(ExtentAllocation::Data(extent)) => ranges.try_push(AllocationRange::new(
                extent.physical_start(),
                extent.len().as_u64(),
                BlockOwnership::Exclusive,
            )?)?,
            Some(ExtentAllocation::Metadata(block)) => {
                ranges.try_push(AllocationRange::new(block, 1, BlockOwnership::Exclusive)?)?
            }
            None => *scan = InodeAllocationScan::Next,
        },
        InodeAllocationScan::ResizeRoot(root) => {
            let blocks = read_resize_pointer_block(reader, superblock, *root)?;
            *scan = InodeAllocationScan::ResizeBranches { blocks, next: 0 };
        }
        InodeAllocationScan::ResizeBranches { blocks, next } => {
            if let Some(block) = blocks.get(*next).copied() {
                let reserved = read_resize_pointer_block(reader, superblock, block)?;
                ranges.try_push(AllocationRange::new(block, 1, BlockOwnership::Exclusive)?)?;
                for block in reserved {
                    ranges.try_push(AllocationRange::new(block, 1, BlockOwnership::Exclusive)?)?;
                }
                *next = next.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            } else {
                *scan = InodeAllocationScan::Next;
            }
        }
    }
    Ok(())
}

/// Static metadata is recorded as ranges rather than one sorted-vector insertion per block.
/// # Errors
/// Returns geometry, range arithmetic, or allocation errors.
fn append_static_ranges(
    ranges: &mut Vec<AllocationRange>,
    superblock: &Superblock,
    allocation: &MountedAllocationSnapshot,
) -> Result<()> {
    let descriptor_blocks = descriptor_table_blocks(superblock)?;
    for group in &allocation.groups {
        if group_has_superblock(superblock, group.group) {
            ranges.try_push(AllocationRange::new(
                group_start_block(superblock, group.group)?,
                descriptor_blocks
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?,
                BlockOwnership::Exclusive,
            )?)?;
        }
        for block in [
            group.descriptor.block_bitmap(),
            group.descriptor.inode_bitmap(),
        ] {
            ranges.try_push(AllocationRange::new(block, 1, BlockOwnership::Exclusive)?)?;
        }
        ranges.try_push(AllocationRange::new(
            group.descriptor.inode_table(),
            inode_table_blocks(superblock, group.group)?,
            BlockOwnership::Exclusive,
        )?)?;
    }
    Ok(())
}

/// Checks physical ownership once, then emits monotonically ordered cluster counts.
/// Mount-only conflict evidence is discarded instead of being cloned with every epoch.
/// # Errors
/// Returns overlapping/free/out-of-range allocation, count overflow, or allocation errors.
fn finish_ranges(
    mut ranges: Vec<AllocationRange>,
    superblock: &Superblock,
    allocation: &MountedAllocationSnapshot,
) -> Result<ClusterReferenceIndex> {
    memory::heap_sort_by(&mut ranges, |left, right| left.start.cmp(&right.start))?;
    let mut previous = None;
    let mut refs: Vec<ClusterReference> = Vec::new();
    for range in ranges {
        if previous.is_some_and(|previous| !range.can_follow(previous)) {
            return Err(Error::ClusterReferenceConflict);
        }
        previous = Some(range);
        let last = range
            .end
            .get()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let _last_cluster = superblock.cluster_of_block(BlockAddress::new(last))?;
        let mut block = range.start;
        while block < range.end {
            let cluster = superblock.cluster_of_block(block)?;
            if allocation.cluster_state(superblock, cluster)? != BitmapBitState::Used {
                return Err(Error::ClusterReferenceConflict);
            }
            let cluster_end = superblock
                .first_block_of_cluster(cluster)?
                .get()
                .checked_add(u64::from(superblock.blocks_in_cluster(cluster)?))
                .ok_or(Error::ArithmeticOverflow)?;
            let end = core::cmp::min(cluster_end, range.end.get());
            let count = u32::try_from(
                end.checked_sub(block.get())
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            if let Some(last) = refs.last_mut().filter(|last| last.cluster == cluster) {
                last.count = last
                    .count
                    .checked_add(count)
                    .ok_or(Error::ArithmeticOverflow)?;
            } else {
                refs.try_push(ClusterReference { cluster, count })?;
            }
            block = BlockAddress::new(end);
        }
    }
    Ok(ClusterReferenceIndex { refs })
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Allocation bitmaps captured once after journal recovery for mount validation.
struct MountedAllocationSnapshot {
    /// Per-group descriptors and allocation bitmap images, ordered by group id.
    groups: Vec<GroupAllocationSnapshot>,
}

impl MountedAllocationSnapshot {
    /// Returns group allocation state by its geometry-derived vector position.
    /// # Errors
    ///
    /// Returns an error when `group` is outside the captured filesystem geometry.
    fn group(&self, group: BlockGroupId) -> Result<&GroupAllocationSnapshot> {
        let index = usize::try_from(group.as_u32()).map_err(|_| Error::ArithmeticOverflow)?;
        let snapshot = self.groups.get(index).ok_or(Error::InvalidSuperblock)?;
        if snapshot.group == group {
            Ok(snapshot)
        } else {
            Err(Error::InvalidSuperblock)
        }
    }

    /// Returns whether an allocation cluster was marked used in the recovered image.
    /// # Errors
    ///
    /// Returns an error when `cluster` cannot be mapped into the captured group bitmaps.
    fn cluster_state(
        &self,
        superblock: &Superblock,
        cluster: ClusterAddress,
    ) -> Result<BitmapBitState> {
        let position = ClusterBitmapPosition::from_cluster(superblock, cluster)?;
        cluster_bitmap_bit_state(&self.group(position.group())?.block_bitmap, position)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One block group's validated descriptor and allocation bitmap images.
struct GroupAllocationSnapshot {
    /// Group represented by this snapshot.
    group: BlockGroupId,
    /// Descriptor selecting the bitmap and inode-table locations.
    descriptor: BlockGroupDescriptor,
    /// Allocation-cluster bitmap block.
    block_bitmap: Vec<u8>,
    /// Inode allocation bitmap block.
    inode_bitmap: Vec<u8>,
}

/// Reads one allocated inode record using its already loaded group descriptor.
/// # Errors
///
/// Returns an error when the group-local inode position is inconsistent, offset arithmetic
/// overflows, allocation fails, or the record cannot be read.
fn read_group_inode_record(
    reader: &mut OperationDevice<'_>,
    superblock: &Superblock,
    group: &GroupAllocationSnapshot,
    position: InodeBitmapPosition,
) -> Result<RawInodeRecord> {
    if position.group() != group.group {
        return Err(Error::InvalidInode);
    }
    let inode_id = position.inode_id(superblock)?;
    let inode_size = u64::from(superblock.inode_size().as_u16());
    let offset = superblock
        .block_size()
        .offset_of(group.descriptor.inode_table())?
        .get()
        .checked_add(
            u64::from(position.bit())
                .checked_mul(inode_size)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    let offset = ByteOffset::new(offset);
    let mut bytes = memory::repeated_vec(0_u8, usize::from(superblock.inode_size().as_u16()))?;
    reader.read_exact_at(offset, &mut bytes)?;
    Ok(RawInodeRecord {
        id: inode_id,
        offset,
        bytes,
        encoding: superblock.inode_data_encoding(),
    })
}

/// Reads the nonzero block addresses stored in one resize-inode pointer block.
/// # Errors
///
/// Returns an error when the block cannot be read or its length is not a whole number of pointers.
fn read_resize_pointer_block(
    reader: &mut OperationDevice<'_>,
    superblock: &Superblock,
    block: BlockAddress,
) -> Result<Vec<BlockAddress>> {
    let block_size = superblock.block_size();
    let mut bytes = memory::repeated_vec(
        0_u8,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    reader.read_exact_at(block_size.offset_of(block)?, bytes.as_mut_slice())?;
    parse_resize_pointer_block(bytes.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::storage::{CompletedStorageTransfer, StorageCompletion, StorageRequest};

    /// Hand-encoded geometry and descriptor, independent of the range accumulator.
    /// # Errors
    /// Returns wire parsing, allocation, or transcript-completion errors.
    fn allocation_fixture(
        cluster_log: u32,
        blocks: u32,
    ) -> Result<(Superblock, MountedAllocationSnapshot)> {
        let mut primary = [0_u8; 1024];
        let inodes = blocks
            .checked_sub(1)
            .ok_or(Error::InvalidSuperblock)?
            .div_ceil(8192)
            .checked_mul(128)
            .ok_or(Error::ArithmeticOverflow)?;
        for (offset, value) in [
            (0, inodes),
            (4, blocks),
            (20, 1),
            (28, cluster_log),
            (32, 8192),
            (
                36,
                8192_u32
                    .checked_shr(cluster_log)
                    .ok_or(Error::ArithmeticOverflow)?,
            ),
            (40, 128),
            (84, 11),
            (92, 4),
            (96, 0x42),
            (100, if cluster_log == 0 { 0 } else { 0x200 }),
            (224, 8),
        ] {
            put_le_u32(&mut primary, disk_offset(offset), value)?;
        }
        for (offset, value) in [(56, 0xef53), (58, 1), (88, 256)] {
            put_le_u16(&mut primary, disk_offset(offset), value)?;
        }
        let superblock = Superblock::parse_read_write(&primary)?;
        let mut transcript = StorageTranscript::new(
            StorageTarget::Filesystem,
            DeviceLength::from_bytes(u64::from(blocks) * 1024),
        );
        let group = BlockGroupId::from_u32(0);
        if !matches!(
            BlockGroupDescriptor::read_from(
                &mut OperationDevice::new(&mut transcript),
                &superblock,
                group
            ),
            Err(Error::OperationSuspended)
        ) {
            return Err(Error::DeviceIo);
        }
        let mut request = transcript.take_pending_request()?;
        let StorageRequest::Read { buffer, .. } = &mut request else {
            return Err(Error::DeviceIo);
        };
        for (offset, value) in [(0, 3), (4, 4), (8, 5)] {
            put_le_u32(buffer, disk_offset(offset), value)?;
        }
        let size = request.byte_count();
        transcript.complete(StorageCompletion::success(
            CompletedStorageTransfer::from_request(request),
            size,
        ))?;
        let descriptor = BlockGroupDescriptor::read_from(
            &mut OperationDevice::new(&mut transcript),
            &superblock,
            group,
        )?;
        let mut groups = Vec::new();
        groups.try_push(GroupAllocationSnapshot {
            group,
            descriptor,
            block_bitmap: memory::repeated_vec(0xff, 1024)?,
            inode_bitmap: memory::repeated_vec(0, 1024)?,
        })?;
        Ok((superblock, MountedAllocationSnapshot { groups }))
    }

    /// # Errors
    /// Returns fixture or range-validation errors.
    /// # Panics
    /// Fails if distinct blocks in a shared BIGALLOC cluster lose their separate counts.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions report contract failures while fixture setup propagates errors"
    )]
    fn range_counts_preserve_cluster_boundaries_and_shared_xattr_owners() -> Result<()> {
        let (superblock, allocation) = allocation_fixture(2, 4096)?;
        let mut ranges = Vec::new();
        for (start, blocks, ownership) in [
            (9, 1, BlockOwnership::SharedXattr),
            (2, 5, BlockOwnership::Exclusive),
            (9, 1, BlockOwnership::SharedXattr),
            (8, 1, BlockOwnership::Exclusive),
        ] {
            ranges.try_push(AllocationRange::new(
                BlockAddress::new(start),
                blocks,
                ownership,
            )?)?;
        }
        let index = finish_ranges(ranges, &superblock, &allocation)?;
        assert_eq!(index.count(ClusterAddress::new(0)), 3);
        assert_eq!(index.count(ClusterAddress::new(1)), 3);
        assert_eq!(index.count(ClusterAddress::new(2)), 2);
        assert_eq!(index.count(ClusterAddress::new(3)), 0);
        Ok(())
    }

    /// # Errors
    /// Returns fixture preparation errors.
    /// # Panics
    /// Fails if physical overlaps, free storage, or out-of-volume ranges are accepted.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions report contract failures while fixture setup propagates errors"
    )]
    fn allocation_publication_rejects_conflicts_and_unallocated_blocks() -> Result<()> {
        let (superblock, mut allocation) = allocation_fixture(0, 4096)?;
        for ownership in [BlockOwnership::Exclusive, BlockOwnership::SharedXattr] {
            for reverse in [false, true] {
                let mut ranges = Vec::new();
                ranges.try_push(AllocationRange::new(
                    BlockAddress::new(50),
                    4,
                    BlockOwnership::Exclusive,
                )?)?;
                ranges.try_push(AllocationRange::new(BlockAddress::new(51), 1, ownership)?)?;
                if reverse {
                    memory::reverse_checked(&mut ranges)?;
                }
                assert!(matches!(
                    finish_ranges(ranges, &superblock, &allocation),
                    Err(Error::ClusterReferenceConflict)
                ));
            }
        }
        let bitmap = &mut allocation
            .groups
            .first_mut()
            .ok_or(Error::InvalidSuperblock)?
            .block_bitmap;
        set_bitmap_bit(bitmap, 49, BitmapBitState::Free)?;
        for (start, expected) in [
            (50, Error::ClusterReferenceConflict),
            (4096, Error::InvalidClusterGeometry),
        ] {
            let mut ranges = Vec::new();
            ranges.try_push(AllocationRange::new(
                BlockAddress::new(start),
                1,
                BlockOwnership::Exclusive,
            )?)?;
            assert_eq!(
                finish_ranges(ranges, &superblock, &allocation),
                Err(expected)
            );
        }
        assert!(
            AllocationRange::new(BlockAddress::new(u64::MAX), 1, BlockOwnership::Exclusive)
                .is_err()
        );
        assert!(AllocationRange::new(BlockAddress::new(1), 0, BlockOwnership::Exclusive).is_err());
        Ok(())
    }

    /// # Errors
    /// Returns fixture or bitmap construction errors.
    /// # Panics
    /// Fails if a block range crossing cluster boundaries marks the wrong bitmap bits.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions report contract failures while fixture setup propagates errors"
    )]
    fn metadata_ranges_mark_only_intersecting_allocation_clusters() -> Result<()> {
        let (superblock, _) = allocation_fixture(2, 4096)?;
        let mut bitmap = memory::repeated_vec(0, 1024)?;
        mark_metadata_range(
            &mut bitmap,
            &superblock,
            BlockGroupId::from_u32(0),
            BlockAddress::new(4),
            6,
        )?;
        assert_eq!(bitmap.first().copied(), Some(0b111));

        let (superblock, _) = allocation_fixture(2, 16385)?;
        for (group, byte, mask) in [(0, 255, 0x80), (1, 0, 1)] {
            bitmap.fill(0);
            mark_metadata_range(
                &mut bitmap,
                &superblock,
                BlockGroupId::from_u32(group),
                BlockAddress::new(8191),
                5,
            )?;
            assert_eq!(bitmap.get(byte).copied(), Some(mask));
            assert_eq!(bitmap.iter().map(|byte| byte.count_ones()).sum::<u32>(), 1);
        }
        bitmap.fill(0);
        mark_metadata_range(
            &mut bitmap,
            &superblock,
            BlockGroupId::from_u32(1),
            BlockAddress::new(1),
            3,
        )?;
        assert!(bitmap.iter().all(|byte| *byte == 0));
        Ok(())
    }

    /// # Errors
    /// Returns fixture construction, decoding, or completion errors.
    /// # Panics
    /// Fails if a completed descriptor, bitmap, or inode must be fetched again after suspension.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions report contract failures while fixture setup propagates errors"
    )]
    fn index_build_consumes_metadata_once_across_individual_read_completions() -> Result<()> {
        let (superblock, _) = allocation_fixture(0, 4096)?;
        let mut transcript = StorageTranscript::new(
            StorageTarget::Filesystem,
            DeviceLength::from_bytes(4096 * 1024),
        );
        let keys = crate::FscryptKeySet::empty();
        let orphans = ValidatedOrphanInventory::load(&mut EpochReadView::mounting(
            OperationDevice::new(&mut transcript),
            superblock,
            &keys,
        ))?;
        let mut build = AllocationIndexBuild::new();
        let mut observed = Vec::new();
        let index = loop {
            match build.advance(&mut transcript, &superblock, &orphans) {
                Ok(index) => break index,
                Err(Error::OperationSuspended) => {}
                Err(error) => return Err(error),
            }
            let mut request = transcript.take_pending_request()?;
            let StorageRequest::Read { offset, buffer, .. } = &mut request else {
                return Err(Error::DeviceIo);
            };
            assert!(!observed.contains(&offset.get()));
            observed.try_push(offset.get())?;
            match offset.get() {
                2048 => {
                    for (offset, value) in [(0, 3), (4, 4), (8, 5)] {
                        put_le_u32(buffer, disk_offset(offset), value)?;
                    }
                }
                3072 => buffer.fill(0xff),
                4096 => *buffer.first_mut().ok_or(Error::DeviceIo)? = 3,
                // Reserved, uninitialized inode records have no data allocation to traverse.
                5120 | 5376 => {}
                _ => return Err(Error::DeviceIo),
            }
            let count = request.byte_count();
            transcript.complete(StorageCompletion::success(
                CompletedStorageTransfer::from_request(request),
                count,
            ))?;
        };
        assert_eq!(observed, [2048, 3072, 4096, 5120, 5376]);
        // Superblock, descriptor, two bitmaps and 32 inode-table blocks occupy blocks 1..37.
        for cluster in 0..36 {
            assert_eq!(index.count(ClusterAddress::new(cluster)), 1);
        }
        assert_eq!(index.count(ClusterAddress::new(36)), 0);
        Ok(())
    }
}
