//! Block-group allocation bitmaps and mounted cluster-reference accounting.

use super::scope::*;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Allocation bitmaps captured once after journal recovery for mount validation.
struct MountedAllocationSnapshot {
    /// Per-group descriptors and allocation bitmap images, ordered by group id.
    groups: Vec<GroupAllocationSnapshot>,
}

impl MountedAllocationSnapshot {
    /// Reads every descriptor and materializes its semantic allocation bitmap state.
    /// # Errors
    ///
    /// Returns an error when group geometry is invalid or any descriptor or bitmap cannot be read.
    fn load(reader: &mut OperationDevice<'_>, superblock: &Superblock) -> Result<Self> {
        let group_count = superblock.block_group_count()?;
        let mut descriptors = Vec::new();
        let mut layouts = Vec::new();
        for group in 0..group_count.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
            layouts.try_push(GroupMetadataLayout::from_descriptor(group, &descriptor))?;
            descriptors.try_push((group, descriptor))?;
        }
        let mut groups = Vec::new();
        for (group, descriptor) in descriptors {
            let block_bitmap = match descriptor.block_bitmap_initialization() {
                AllocationBitmapInitialization::Initialized => {
                    read_allocation_bitmap(reader, superblock, descriptor.block_bitmap())?
                }
                AllocationBitmapInitialization::Uninitialized => {
                    materialize_uninitialized_block_bitmap(superblock, group, &layouts)?
                }
            };
            let inode_bitmap = match descriptor.inode_bitmap_initialization() {
                AllocationBitmapInitialization::Initialized => {
                    read_allocation_bitmap(reader, superblock, descriptor.inode_bitmap())?
                }
                AllocationBitmapInitialization::Uninitialized => {
                    materialize_uninitialized_inode_bitmap(superblock, group)?
                }
            };
            groups.try_push(GroupAllocationSnapshot {
                group,
                descriptor,
                block_bitmap,
                inode_bitmap,
            })?;
        }
        Ok(Self { groups })
    }

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Static metadata locations selected by one block-group descriptor.
pub(super) struct GroupMetadataLayout {
    /// Block group whose descriptor selected these locations.
    group: BlockGroupId,
    /// Block allocation bitmap block.
    block_bitmap: BlockAddress,
    /// Inode allocation bitmap block.
    inode_bitmap: BlockAddress,
    /// First inode-table block.
    inode_table: BlockAddress,
}

impl GroupMetadataLayout {
    /// Captures the static layout fields from a verified descriptor.
    fn from_descriptor(group: BlockGroupId, descriptor: &BlockGroupDescriptor) -> Self {
        Self {
            group,
            block_bitmap: descriptor.block_bitmap(),
            inode_bitmap: descriptor.inode_bitmap(),
            inode_table: descriptor.inode_table(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Mounted allocation-cluster ownership index used by write transactions.
pub(super) struct ClusterReferenceIndex {
    /// Reference count per allocation cluster with at least one known owner, sorted by cluster.
    refs: Vec<ClusterReference>,
    /// Physical blocks that must have exclusive ownership, sorted by block address.
    exclusive_blocks: Vec<BlockAddress>,
    /// External xattr blocks that may be shared by ext4 xattr refcount, sorted by block address.
    xattr_blocks: Vec<BlockAddress>,
}

impl ClusterReferenceIndex {
    /// Copies the mounted cluster-reference index without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying any reference-index vector cannot allocate.
    pub(super) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            refs: memory::copied_slice(&self.refs)?,
            exclusive_blocks: memory::copied_slice(&self.exclusive_blocks)?,
            xattr_blocks: memory::copied_slice(&self.xattr_blocks)?,
        })
    }

    /// Builds the mounted reference index from static metadata and live inodes.
    /// # Errors
    ///
    /// Returns an error when static metadata or live inode block references cannot be validated
    /// against allocation bitmaps.
    pub(super) fn load(volume: &mut EpochReadView<'_, '_>) -> Result<Self> {
        let allocation = MountedAllocationSnapshot::load(&mut volume.device, &volume.superblock)?;
        let mut index = Self {
            refs: Vec::new(),
            exclusive_blocks: Vec::new(),
            xattr_blocks: Vec::new(),
        };
        index.add_static_metadata(&volume.superblock, &allocation)?;
        index.add_live_inodes(volume, &allocation)?;
        Ok(index)
    }

    /// Returns the known mounted reference count for one cluster.
    pub(super) fn count(&self, cluster: ClusterAddress) -> u32 {
        self.refs
            .binary_search_by_key(&cluster, |reference| reference.cluster)
            .ok()
            .and_then(|index| self.refs.get(index))
            .map_or(0, |reference| reference.count)
    }

    /// Applies committed staged reference deltas.
    /// # Errors
    ///
    /// Returns an error when a staged delta would drive a mounted cluster reference count below
    /// zero or overflow its signed representation.
    pub(super) fn apply_deltas(&mut self, deltas: &[ClusterReferenceDelta]) -> Result<()> {
        for delta in deltas {
            let updated = self.apply_delta(delta.cluster, delta.delta)?;
            if updated < 0 {
                return Err(Error::ClusterReferenceConflict);
            }
        }
        Ok(())
    }

    /// Adds one exclusive mounted reference after validating bitmap allocation.
    /// # Errors
    ///
    /// Returns an error when `block` is already known through another owner or is not marked
    /// allocated in the mounted cluster bitmap.
    fn add_exclusive_reference(
        &mut self,
        superblock: &Superblock,
        allocation: &MountedAllocationSnapshot,
        block: BlockAddress,
    ) -> Result<()> {
        if self.exclusive_blocks.binary_search(&block).is_ok()
            || self.xattr_blocks.binary_search(&block).is_ok()
        {
            return Err(Error::ClusterReferenceConflict);
        }
        let insertion = self
            .exclusive_blocks
            .binary_search(&block)
            .unwrap_or_else(core::convert::identity);
        self.exclusive_blocks.try_insert(insertion, block)?;
        self.add_cluster_reference(superblock, allocation, block)
    }

    /// Adds one external-xattr mounted reference after validating bitmap allocation.
    /// # Errors
    ///
    /// Returns an error when `block` conflicts with an exclusive owner or is not allocated in the
    /// mounted cluster bitmap.
    fn add_xattr_reference(
        &mut self,
        superblock: &Superblock,
        allocation: &MountedAllocationSnapshot,
        block: BlockAddress,
    ) -> Result<()> {
        if self.exclusive_blocks.binary_search(&block).is_ok() {
            return Err(Error::ClusterReferenceConflict);
        }
        if let Err(insertion) = self.xattr_blocks.binary_search(&block) {
            self.xattr_blocks.try_insert(insertion, block)?;
        }
        self.add_cluster_reference(superblock, allocation, block)
    }

    /// Adds one mounted cluster reference after validating bitmap allocation.
    /// # Errors
    ///
    /// Returns an error when `block` cannot be translated to a mounted cluster, the bitmap cannot
    /// be read, or the cluster is marked free.
    fn add_cluster_reference(
        &mut self,
        superblock: &Superblock,
        allocation: &MountedAllocationSnapshot,
        block: BlockAddress,
    ) -> Result<()> {
        let cluster = superblock.cluster_of_block(block)?;
        if allocation.cluster_state(superblock, cluster)? != BitmapBitState::Used {
            return Err(Error::ClusterReferenceConflict);
        }
        self.apply_delta(cluster, 1)?;
        Ok(())
    }

    /// Adds all static metadata ranges that must keep their clusters allocated.
    /// # Errors
    ///
    /// Returns an error when descriptor-table, bitmap, or inode-table blocks cannot be enumerated
    /// or are not exclusively allocated.
    fn add_static_metadata(
        &mut self,
        superblock: &Superblock,
        allocation: &MountedAllocationSnapshot,
    ) -> Result<()> {
        let groups = superblock.block_group_count()?;
        let descriptor_blocks = descriptor_table_blocks(superblock)?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            if group_has_superblock(superblock, group) {
                let superblock_block = group_start_block(superblock, group)?;
                self.add_exclusive_reference(superblock, allocation, superblock_block)?;
                for offset in 0..descriptor_blocks {
                    self.add_exclusive_reference(
                        superblock,
                        allocation,
                        BlockAddress::new(
                            superblock_block
                                .get()
                                .checked_add(1)
                                .and_then(|value| value.checked_add(offset))
                                .ok_or(Error::ArithmeticOverflow)?,
                        ),
                    )?;
                }
            }

            let descriptor = &allocation.group(group)?.descriptor;
            self.add_exclusive_reference(superblock, allocation, descriptor.block_bitmap())?;
            self.add_exclusive_reference(superblock, allocation, descriptor.inode_bitmap())?;
            let inode_table_blocks = inode_table_blocks(superblock, group)?;
            for offset in 0..inode_table_blocks {
                self.add_exclusive_reference(
                    superblock,
                    allocation,
                    BlockAddress::new(
                        descriptor
                            .inode_table()
                            .get()
                            .checked_add(offset)
                            .ok_or(Error::ArithmeticOverflow)?,
                    ),
                )?;
            }
        }
        Ok(())
    }

    /// Adds data and dynamic metadata references from allocated inode records.
    /// # Errors
    ///
    /// Returns an error when inode bitmaps, raw inode records, external xattr blocks, or extent tree
    /// blocks cannot be read or validated as allocated.
    fn add_live_inodes(
        &mut self,
        volume: &mut EpochReadView<'_, '_>,
        allocation: &MountedAllocationSnapshot,
    ) -> Result<()> {
        for group in &allocation.groups {
            let inode_count = inode_count_in_group(&volume.superblock, group.group)?;
            for bit in 0..inode_count {
                let position = InodeBitmapPosition::new(group.group, bit);
                if inode_bitmap_bit_state(&group.inode_bitmap, position)? != BitmapBitState::Used {
                    continue;
                }
                let inode_id = position.inode_id(&volume.superblock)?;
                let raw_inode = read_group_inode_record(volume, group, position)?;
                if raw_inode.mode()? == 0 {
                    continue;
                }
                if volume.superblock.is_resize_inode(inode_id) {
                    self.add_resize_inode_references(
                        volume,
                        allocation,
                        raw_inode.resize_inode_block_map()?,
                    )?;
                    continue;
                }
                if let Some(block) = raw_inode.xattr_block()? {
                    self.add_xattr_reference(&volume.superblock, allocation, block)?;
                }
                let Ok(inode) = raw_inode.parse() else {
                    if raw_inode.has_extent_tree()? {
                        return Err(Error::UnsupportedBlockMap);
                    }
                    continue;
                };
                let root = match inode.storage() {
                    InodeStorage::Extents(root) => root,
                    InodeStorage::InlineBytes(_) => continue,
                    InodeStorage::UnsupportedBlockMap => return Err(Error::UnsupportedBlockMap),
                };
                let context = volume.extent_tree_context(&inode);
                let tree = ExtentTree::load_inode_tree(
                    root,
                    volume.superblock.block_size(),
                    &mut volume.device,
                    context,
                )?;
                for extent in tree.extents().iter().copied() {
                    self.add_extent_references(&volume.superblock, allocation, extent)?;
                }
                for block in tree.metadata_blocks().iter().copied() {
                    self.add_exclusive_reference(&volume.superblock, allocation, block)?;
                }
            }
        }
        Ok(())
    }

    /// Adds the fixed double-indirect metadata ownership of ext4's reserved resize inode.
    /// # Errors
    ///
    /// Returns an error when pointer blocks cannot be read, contain invalid block addresses, or
    /// reference blocks that are not allocated exclusively.
    fn add_resize_inode_references(
        &mut self,
        volume: &mut EpochReadView<'_, '_>,
        allocation: &MountedAllocationSnapshot,
        block_map: ResizeInodeBlockMap,
    ) -> Result<()> {
        let double_indirect = block_map.double_indirect();
        self.add_exclusive_reference(&volume.superblock, allocation, double_indirect)?;
        let indirect_blocks = read_resize_pointer_block(volume, double_indirect)?;
        for indirect in indirect_blocks {
            self.add_exclusive_reference(&volume.superblock, allocation, indirect)?;
            let reserved_blocks = read_resize_pointer_block(volume, indirect)?;
            for reserved in reserved_blocks {
                self.add_exclusive_reference(&volume.superblock, allocation, reserved)?;
            }
        }
        Ok(())
    }

    /// Adds references for every physical block represented by an extent.
    /// # Errors
    ///
    /// Returns an error when the extent block range overflows or any represented block is not an
    /// exclusively allocated cluster.
    fn add_extent_references(
        &mut self,
        superblock: &Superblock,
        allocation: &MountedAllocationSnapshot,
        extent: Extent,
    ) -> Result<()> {
        for offset in 0..extent.len().as_u64() {
            self.add_exclusive_reference(
                superblock,
                allocation,
                BlockAddress::new(
                    extent
                        .physical_start()
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ),
            )?;
        }
        Ok(())
    }

    /// Applies one signed delta and returns the resulting signed count.
    /// # Errors
    ///
    /// Returns an error when reference-count arithmetic overflows or an existing reference slot
    /// cannot be found after lookup.
    pub(super) fn apply_delta(&mut self, cluster: ClusterAddress, delta: i32) -> Result<i32> {
        if let Ok(index) = self
            .refs
            .binary_search_by_key(&cluster, |reference| reference.cluster)
        {
            let current = i32::try_from(
                self.refs
                    .get(index)
                    .ok_or(Error::ClusterReferenceConflict)?
                    .count,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let updated = current
                .checked_add(delta)
                .ok_or(Error::ArithmeticOverflow)?;
            if updated <= 0 {
                let _removed = self.refs.try_remove_at(index)?;
            } else {
                self.refs
                    .get_mut(index)
                    .ok_or(Error::ClusterReferenceConflict)?
                    .count = u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?;
            }
            Ok(updated)
        } else if delta > 0 {
            let insertion = self
                .refs
                .binary_search_by_key(&cluster, |reference| reference.cluster)
                .unwrap_or_else(core::convert::identity);
            self.refs.try_insert(
                insertion,
                ClusterReference {
                    cluster,
                    count: u32::try_from(delta).map_err(|_| Error::ArithmeticOverflow)?,
                },
            )?;
            Ok(delta)
        } else {
            Ok(delta)
        }
    }
}

/// Reads all static group layouts without treating bitmap contents as authoritative.
/// # Errors
///
/// Returns an error when block-group geometry, descriptor validation, or allocation fails.
pub(super) fn read_group_metadata_layouts(
    reader: &mut OperationDevice<'_>,
    superblock: &Superblock,
) -> Result<Vec<GroupMetadataLayout>> {
    let group_count = superblock.block_group_count()?;
    let mut layouts = Vec::new();
    for group in 0..group_count.as_u32() {
        let group = BlockGroupId::from_u32(group);
        let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
        layouts.try_push(GroupMetadataLayout::from_descriptor(group, &descriptor))?;
    }
    Ok(layouts)
}

/// Derives the semantic contents of a block bitmap whose descriptor carries `BLOCK_UNINIT`.
///
/// An uninitialized on-disk block is not an all-free bitmap. ext4 derives its used clusters from
/// the superblock copies, descriptor tables and every descriptor-selected bitmap and inode table.
/// # Errors
///
/// Returns an error when metadata geometry is outside the filesystem or bitmap construction fails.
pub(super) fn materialize_uninitialized_block_bitmap(
    superblock: &Superblock,
    group: BlockGroupId,
    layouts: &[GroupMetadataLayout],
) -> Result<Vec<u8>> {
    let mut bytes = empty_allocation_bitmap(superblock)?;
    let clusters_in_group = superblock.clusters_in_group(group)?;
    reserve_bitmap_padding(
        &mut bytes,
        clusters_in_group,
        superblock.clusters_per_group().as_u32(),
    )?;

    if group_has_superblock(superblock, group) {
        let superblock_block = group_start_block(superblock, group)?;
        let metadata_blocks = 1_u64
            .checked_add(descriptor_table_blocks(superblock)?)
            .and_then(|count| count.checked_add(superblock.reserved_gdt_blocks().as_u64()))
            .ok_or(Error::ArithmeticOverflow)?;
        for offset in 0..metadata_blocks {
            mark_metadata_block(
                &mut bytes,
                superblock,
                group,
                BlockAddress::new(
                    superblock_block
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ),
            )?;
        }
    }

    for layout in layouts {
        mark_metadata_block(&mut bytes, superblock, group, layout.block_bitmap)?;
        mark_metadata_block(&mut bytes, superblock, group, layout.inode_bitmap)?;
        for offset in 0..inode_table_blocks(superblock, layout.group)? {
            mark_metadata_block(
                &mut bytes,
                superblock,
                group,
                BlockAddress::new(
                    layout
                        .inode_table
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ),
            )?;
        }
    }
    Ok(bytes)
}

/// Derives the semantic contents of an inode bitmap whose descriptor carries `INODE_UNINIT`.
/// # Errors
///
/// Returns an error when inode geometry or bitmap construction is invalid.
pub(super) fn materialize_uninitialized_inode_bitmap(
    superblock: &Superblock,
    group: BlockGroupId,
) -> Result<Vec<u8>> {
    let mut bytes = empty_allocation_bitmap(superblock)?;
    let inodes_in_group = inode_count_in_group(superblock, group)?;
    reserve_bitmap_padding(
        &mut bytes,
        inodes_in_group,
        superblock.inodes_per_group().as_u32(),
    )?;
    if group.as_u32() == 0 {
        let reserved = superblock
            .first_inode()
            .as_u32()
            .checked_sub(1)
            .ok_or(Error::InvalidSuperblock)?;
        for bit in 0..core::cmp::min(reserved, inodes_in_group) {
            set_bitmap_bit(&mut bytes, bit, BitmapBitState::Used)?;
        }
    }
    Ok(bytes)
}

/// Marks one metadata block in the bitmap when its allocation cluster belongs to `bitmap_group`.
/// # Errors
///
/// Returns an error when the metadata block or its bitmap position is outside mounted geometry.
fn mark_metadata_block(
    bytes: &mut [u8],
    superblock: &Superblock,
    bitmap_group: BlockGroupId,
    block: BlockAddress,
) -> Result<()> {
    let cluster = superblock.cluster_of_block(block)?;
    if superblock.cluster_group_of(cluster)? != bitmap_group {
        return Ok(());
    }
    let position = ClusterBitmapPosition::from_cluster(superblock, cluster)?;
    set_cluster_bitmap_bit(bytes, position, BitmapBitState::Used)
}

/// Marks bitmap bits outside the populated tail of a partial group as unavailable.
/// # Errors
///
/// Returns an error when the bitmap domain exceeds its allocated byte image.
fn reserve_bitmap_padding(bytes: &mut [u8], populated: u32, capacity: u32) -> Result<()> {
    if populated > capacity {
        return Err(Error::InvalidSuperblock);
    }
    for bit in populated..capacity {
        set_bitmap_bit(bytes, bit, BitmapBitState::Used)?;
    }
    Ok(())
}

/// Allocates one zero-filled bitmap block.
/// # Errors
///
/// Returns an error when the block byte count cannot be represented or allocated.
fn empty_allocation_bitmap(superblock: &Superblock) -> Result<Vec<u8>> {
    memory::repeated_vec(
        0_u8,
        usize::try_from(superblock.block_size().bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )
}

/// Reads one initialized allocation bitmap block into a fallibly allocated image.
/// # Errors
///
/// Returns an error when the bitmap byte count cannot be represented or the block cannot be read.
pub(super) fn read_allocation_bitmap(
    reader: &mut OperationDevice<'_>,
    superblock: &Superblock,
    block: BlockAddress,
) -> Result<Vec<u8>> {
    let mut bytes = empty_allocation_bitmap(superblock)?;
    reader.read_exact_at(superblock.block_size().offset_of(block)?, &mut bytes)?;
    Ok(bytes)
}

/// Reads one allocated inode record using its already loaded group descriptor.
/// # Errors
///
/// Returns an error when the group-local inode position is inconsistent, offset arithmetic
/// overflows, allocation fails, or the record cannot be read.
fn read_group_inode_record(
    volume: &mut EpochReadView<'_, '_>,
    group: &GroupAllocationSnapshot,
    position: InodeBitmapPosition,
) -> Result<RawInodeRecord> {
    if position.group() != group.group {
        return Err(Error::InvalidInode);
    }
    let inode_id = position.inode_id(&volume.superblock)?;
    let inode_size = u64::from(volume.superblock.inode_size().as_u16());
    let offset = volume
        .superblock
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
    let mut bytes =
        memory::repeated_vec(0_u8, usize::from(volume.superblock.inode_size().as_u16()))?;
    volume.device.read_exact_at(offset, &mut bytes)?;
    Ok(RawInodeRecord {
        id: inode_id,
        offset,
        bytes,
        encoding: volume.superblock.inode_data_encoding(),
    })
}

/// Reads the nonzero block addresses stored in one resize-inode pointer block.
/// # Errors
///
/// Returns an error when the block cannot be read or its length is not a whole number of pointers.
fn read_resize_pointer_block(
    volume: &mut EpochReadView<'_, '_>,
    block: BlockAddress,
) -> Result<Vec<BlockAddress>> {
    let block_size = volume.superblock.block_size();
    let mut bytes = memory::repeated_vec(
        0_u8,
        usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    volume
        .device
        .read_exact_at(block_size.offset_of(block)?, bytes.as_mut_slice())?;
    parse_resize_pointer_block(bytes.as_slice())
}

/// Converts a resize-inode pointer block into its nonzero physical block addresses.
/// # Errors
///
/// Returns an error when the byte length is not divisible by the 32-bit pointer width.
fn parse_resize_pointer_block(bytes: &[u8]) -> Result<Vec<BlockAddress>> {
    let pointer_bytes = core::mem::size_of::<u32>();
    if bytes
        .len()
        .checked_rem(pointer_bytes)
        .ok_or(Error::ArithmeticOverflow)?
        != 0
    {
        return Err(Error::UnsupportedBlockMap);
    }
    let entries = bytes
        .len()
        .checked_div(pointer_bytes)
        .ok_or(Error::ArithmeticOverflow)?;
    let mut blocks = Vec::new();
    for index in 0..entries {
        let offset = index
            .checked_mul(pointer_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let block = le_u32(bytes, disk_offset(offset))?;
        if block != 0 {
            blocks.try_push(BlockAddress::new(u64::from(block)))?;
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::{ClusterReferenceIndex, parse_resize_pointer_block};
    use crate::disk::block::BlockAddress;
    use crate::disk::endian::{DiskOffset, put_le_u32};
    use crate::disk_format::superblock::ClusterAddress;
    use crate::error::Error;

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn resize_pointer_block_keeps_only_nonzero_addresses() {
        let mut bytes = [0_u8; 12];
        assert_eq!(put_le_u32(&mut bytes, DiskOffset::new(4), 17_432), Ok(()));
        assert_eq!(put_le_u32(&mut bytes, DiskOffset::new(8), 65_537), Ok(()));
        assert_eq!(
            parse_resize_pointer_block(&bytes),
            Ok(vec![BlockAddress::new(17_432), BlockAddress::new(65_537)])
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn resize_pointer_block_rejects_partial_pointer_tail() {
        assert_eq!(
            parse_resize_pointer_block(&[0_u8; 5]),
            Err(Error::UnsupportedBlockMap)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn cluster_reference_index_preserves_sorted_lookup_after_out_of_order_inserts() {
        let mut index = ClusterReferenceIndex {
            refs: Vec::new(),
            exclusive_blocks: Vec::new(),
            xattr_blocks: Vec::new(),
        };
        assert_eq!(index.apply_delta(ClusterAddress::new(9), 1), Ok(1));
        assert_eq!(index.apply_delta(ClusterAddress::new(2), 1), Ok(1));
        assert_eq!(index.apply_delta(ClusterAddress::new(5), 1), Ok(1));

        assert_eq!(index.count(ClusterAddress::new(2)), 1);
        assert_eq!(index.count(ClusterAddress::new(5)), 1);
        assert_eq!(index.count(ClusterAddress::new(9)), 1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Mounted reference count for one allocation cluster.
struct ClusterReference {
    /// Allocation cluster.
    cluster: ClusterAddress,
    /// Number of known owners in the mounted image.
    count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Staged reference-count delta for one allocation cluster.
pub(super) struct ClusterReferenceDelta {
    /// Allocation cluster receiving the delta.
    pub(super) cluster: ClusterAddress,
    /// Signed reference delta.
    pub(super) delta: i32,
}

/// Position of one allocation cluster bit inside a block-group bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ClusterBitmapPosition {
    /// Block group owning the bitmap.
    group: BlockGroupId,
    /// Group-local cluster bit.
    bit: u32,
}

impl ClusterBitmapPosition {
    /// Creates a bitmap position for a validated group-local cluster bit.
    pub(super) const fn new(group: BlockGroupId, bit: u32) -> Self {
        Self { group, bit }
    }

    /// Computes the cluster bitmap position for an absolute cluster address.
    /// # Errors
    ///
    /// Returns an error when `cluster` is outside the filesystem or its group-local bit cannot be
    /// derived.
    pub(super) fn from_cluster(superblock: &Superblock, cluster: ClusterAddress) -> Result<Self> {
        let group = superblock.cluster_group_of(cluster)?;
        Ok(Self {
            group,
            bit: superblock.cluster_bit_in_group(cluster, group)?,
        })
    }

    /// Block group owning the bitmap.
    pub(super) const fn group(self) -> BlockGroupId {
        self.group
    }

    /// Group-local cluster bit.
    pub(super) const fn bit(self) -> u32 {
        self.bit
    }
}

/// Position of one inode bit inside a block-group bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InodeBitmapPosition {
    /// Block group owning the bitmap.
    group: BlockGroupId,
    /// Group-local inode bit.
    bit: u32,
}

impl InodeBitmapPosition {
    /// Creates a bitmap position for a validated group-local inode bit.
    pub(super) const fn new(group: BlockGroupId, bit: u32) -> Self {
        Self { group, bit }
    }

    /// Computes the inode bitmap position for an absolute inode id.
    /// # Errors
    ///
    /// Returns an error when `inode_id` is outside the filesystem inode range or group arithmetic is
    /// invalid.
    pub(super) fn from_inode(superblock: &Superblock, inode_id: InodeId) -> Result<Self> {
        if inode_id.as_u32() > superblock.inode_count().as_u32() {
            return Err(Error::InvalidInode);
        }
        let zero_based = inode_id
            .as_u32()
            .checked_sub(1)
            .ok_or(Error::InvalidInode)?;
        let group = zero_based
            .checked_div(superblock.inodes_per_group().as_u32())
            .ok_or(Error::InvalidSuperblock)?;
        let bit = zero_based
            .checked_rem(superblock.inodes_per_group().as_u32())
            .ok_or(Error::InvalidSuperblock)?;
        Ok(Self {
            group: BlockGroupId::from_u32(group),
            bit,
        })
    }

    /// Converts this bitmap position into its absolute inode id.
    /// # Errors
    ///
    /// Returns an error when group-local inode arithmetic overflows or produces inode number zero.
    pub(super) fn inode_id(self, superblock: &Superblock) -> Result<InodeId> {
        let zero_based = self
            .group
            .as_u32()
            .checked_mul(superblock.inodes_per_group().as_u32())
            .ok_or(Error::ArithmeticOverflow)?
            .checked_add(self.bit)
            .ok_or(Error::ArithmeticOverflow)?;
        InodeId::try_from(zero_based.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }

    /// Block group owning the bitmap.
    pub(super) const fn group(self) -> BlockGroupId {
        self.group
    }

    /// Group-local inode bit.
    pub(super) const fn bit(self) -> u32 {
        self.bit
    }
}

/// Allocation bitmap bit state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BitmapBitState {
    /// The represented inode or cluster is allocated.
    Used,
    /// The represented inode or cluster is free.
    Free,
}

/// Reads one allocation bitmap bit.
/// # Errors
///
/// Returns an error when `bit` points beyond `bytes` or bit-index arithmetic fails.
pub(super) fn bitmap_bit_state(bytes: &[u8], bit: u32) -> Result<BitmapBitState> {
    let byte_index = usize::try_from(bit.checked_div(8).ok_or(Error::ArithmeticOverflow)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let bit_index = bit.checked_rem(8).ok_or(Error::ArithmeticOverflow)?;
    let byte = bytes.get(byte_index).ok_or(Error::InvalidSuperblock)?;
    if byte & (1_u8 << bit_index) != 0 {
        Ok(BitmapBitState::Used)
    } else {
        Ok(BitmapBitState::Free)
    }
}

/// Reads one typed allocation-cluster bitmap bit.
/// # Errors
///
/// Returns an error when the cluster bitmap position falls outside `bytes`.
pub(super) fn cluster_bitmap_bit_state(
    bytes: &[u8],
    position: ClusterBitmapPosition,
) -> Result<BitmapBitState> {
    bitmap_bit_state(bytes, position.bit())
}

/// Reads one typed inode bitmap bit.
/// # Errors
///
/// Returns an error when the inode bitmap position falls outside `bytes`.
pub(super) fn inode_bitmap_bit_state(
    bytes: &[u8],
    position: InodeBitmapPosition,
) -> Result<BitmapBitState> {
    bitmap_bit_state(bytes, position.bit())
}

/// Writes one allocation bitmap bit.
/// # Errors
///
/// Returns an error when `bit` points beyond `bytes` or bit-index arithmetic fails.
pub(super) fn set_bitmap_bit(bytes: &mut [u8], bit: u32, state: BitmapBitState) -> Result<()> {
    let byte_index = usize::try_from(bit.checked_div(8).ok_or(Error::ArithmeticOverflow)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let bit_index = bit.checked_rem(8).ok_or(Error::ArithmeticOverflow)?;
    let byte = bytes.get_mut(byte_index).ok_or(Error::InvalidSuperblock)?;
    match state {
        BitmapBitState::Used => *byte |= 1_u8 << bit_index,
        BitmapBitState::Free => *byte &= !(1_u8 << bit_index),
    }
    Ok(())
}

/// Writes one typed allocation-cluster bitmap bit.
/// # Errors
///
/// Returns an error when the cluster bitmap position falls outside `bytes`.
pub(super) fn set_cluster_bitmap_bit(
    bytes: &mut [u8],
    position: ClusterBitmapPosition,
    state: BitmapBitState,
) -> Result<()> {
    set_bitmap_bit(bytes, position.bit(), state)
}

/// Writes one typed inode bitmap bit.
/// # Errors
///
/// Returns an error when the inode bitmap position falls outside `bytes`.
pub(super) fn set_inode_bitmap_bit(
    bytes: &mut [u8],
    position: InodeBitmapPosition,
    state: BitmapBitState,
) -> Result<()> {
    set_bitmap_bit(bytes, position.bit(), state)
}

/// Returns the first physical block in a block group.
/// # Errors
///
/// Returns an error when multiplying `group` by blocks-per-group or adding the first data block
/// overflows.
pub(super) fn group_start_block(
    superblock: &Superblock,
    group: BlockGroupId,
) -> Result<BlockAddress> {
    Ok(BlockAddress::new(
        superblock
            .first_data_block()
            .get()
            .checked_add(
                u64::from(group.as_u32())
                    .checked_mul(u64::from(superblock.blocks_per_group().as_u32()))
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?,
    ))
}

/// Returns whether a group carries a superblock and descriptor-table copy.
pub(super) fn group_has_superblock(superblock: &Superblock, group: BlockGroupId) -> bool {
    let value = group.as_u32();
    match superblock.sparse_superblock_layout() {
        SparseSuperblockLayout::FullCopies => true,
        SparseSuperblockLayout::SparseCopies => {
            value == 0
                || value == 1
                || is_power_of(value, 3)
                || is_power_of(value, 5)
                || is_power_of(value, 7)
        }
    }
}

/// Returns true when `value` is an exact positive power of `base`.
pub(super) fn is_power_of(mut value: u32, base: u32) -> bool {
    if value < base {
        return false;
    }
    while value.checked_rem(base) == Some(0) {
        value = value.checked_div(base).unwrap_or(0);
    }
    value == 1
}

/// Returns the number of blocks occupied by one descriptor-table copy.
/// # Errors
///
/// Returns an error when descriptor byte count multiplication or rounded block division overflows.
pub(super) fn descriptor_table_blocks(superblock: &Superblock) -> Result<u64> {
    let descriptor_bytes = u64::from(superblock.block_group_count()?.as_u32())
        .checked_mul(u64::from(superblock.descriptor_size().as_u16()))
        .ok_or(Error::ArithmeticOverflow)?;
    round_up_div(descriptor_bytes, u64::from(superblock.block_size().bytes()))
}

/// Returns the inode count actually present in a possibly partial group.
/// # Errors
///
/// Returns an error when the group start is past the inode count or group inode arithmetic
/// overflows.
pub(super) fn inode_count_in_group(superblock: &Superblock, group: BlockGroupId) -> Result<u32> {
    let group_start = u64::from(group.as_u32())
        .checked_mul(u64::from(superblock.inodes_per_group().as_u32()))
        .ok_or(Error::ArithmeticOverflow)?;
    let remaining = u64::from(superblock.inode_count().as_u32())
        .checked_sub(group_start)
        .ok_or(Error::InvalidSuperblock)?;
    Ok(core::cmp::min(
        superblock.inodes_per_group().as_u32(),
        u32::try_from(remaining).unwrap_or(u32::MAX),
    ))
}

/// Returns the number of blocks occupied by a group's inode table.
/// # Errors
///
/// Returns an error when inode count, inode size, or rounded block division arithmetic fails.
pub(super) fn inode_table_blocks(superblock: &Superblock, group: BlockGroupId) -> Result<u64> {
    let inode_bytes = u64::from(inode_count_in_group(superblock, group)?)
        .checked_mul(u64::from(superblock.inode_size().as_u16()))
        .ok_or(Error::ArithmeticOverflow)?;
    round_up_div(inode_bytes, u64::from(superblock.block_size().bytes()))
}

/// Computes the absolute device offset of an inode record.
/// # Errors
///
/// Returns an error when `inode_id` cannot be mapped to a group, the descriptor cannot be read, or
/// inode-table offset arithmetic overflows.
pub(super) fn inode_offset_on_device(
    reader: &mut OperationDevice<'_>,
    superblock: &Superblock,
    inode_id: InodeId,
) -> Result<ByteOffset> {
    let position = InodeBitmapPosition::from_inode(superblock, inode_id)?;
    let group = position.group();
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
    let inode_size = u64::from(superblock.inode_size().as_u16());
    let offset = superblock
        .block_size()
        .offset_of(descriptor.inode_table())?
        .get()
        .checked_add(
            u64::from(position.bit())
                .checked_mul(inode_size)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(ByteOffset::new(offset))
}

/// Divides with upward rounding and overflow checking.
/// # Errors
///
/// Returns an error when `divisor` is zero or the rounded numerator overflows.
pub(super) fn round_up_div(value: u64, divisor: u64) -> Result<u64> {
    if divisor == 0 {
        return Err(Error::ArithmeticOverflow);
    }
    let adjusted = value
        .checked_add(divisor.checked_sub(1).ok_or(Error::ArithmeticOverflow)?)
        .ok_or(Error::ArithmeticOverflow)?;
    adjusted
        .checked_div(divisor)
        .ok_or(Error::ArithmeticOverflow)
}
