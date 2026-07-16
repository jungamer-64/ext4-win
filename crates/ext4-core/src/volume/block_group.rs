//! Block-group allocation bitmaps and mounted cluster-reference accounting.

use super::scope::*;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Mounted allocation-cluster ownership index used by write transactions.
pub(super) struct ClusterReferenceIndex {
    /// Reference count per allocation cluster with at least one known owner.
    refs: Vec<ClusterReference>,
    /// Physical blocks that must have exclusive ownership.
    exclusive_blocks: Vec<BlockAddress>,
    /// External xattr blocks that may be shared by ext4 xattr refcount.
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
    pub(super) async fn load<D: BlockSource, State, N>(
        volume: &mut MountedVolume<D, State, N>,
    ) -> Result<Self> {
        let mut index = Self {
            refs: Vec::new(),
            exclusive_blocks: Vec::new(),
            xattr_blocks: Vec::new(),
        };
        index.add_static_metadata(volume).await?;
        index.add_live_inodes(volume).await?;
        Ok(index)
    }

    /// Returns the known mounted reference count for one cluster.
    pub(super) fn count(&self, cluster: ClusterAddress) -> u32 {
        self.refs
            .iter()
            .find(|reference| reference.cluster == cluster)
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
    pub(super) async fn add_exclusive_reference<D: BlockSource, State, N>(
        &mut self,
        volume: &mut MountedVolume<D, State, N>,
        block: BlockAddress,
    ) -> Result<()> {
        if self.exclusive_blocks.contains(&block) || self.xattr_blocks.contains(&block) {
            return Err(Error::ClusterReferenceConflict);
        }
        self.exclusive_blocks.try_push(block)?;
        self.add_cluster_reference(volume, block).await
    }

    /// Adds one external-xattr mounted reference after validating bitmap allocation.
    /// # Errors
    ///
    /// Returns an error when `block` conflicts with an exclusive owner or is not allocated in the
    /// mounted cluster bitmap.
    pub(super) async fn add_xattr_reference<D: BlockSource, State, N>(
        &mut self,
        volume: &mut MountedVolume<D, State, N>,
        block: BlockAddress,
    ) -> Result<()> {
        if self.exclusive_blocks.contains(&block) {
            return Err(Error::ClusterReferenceConflict);
        }
        if !self.xattr_blocks.contains(&block) {
            self.xattr_blocks.try_push(block)?;
        }
        self.add_cluster_reference(volume, block).await
    }

    /// Adds one mounted cluster reference after validating bitmap allocation.
    /// # Errors
    ///
    /// Returns an error when `block` cannot be translated to a mounted cluster, the bitmap cannot
    /// be read, or the cluster is marked free.
    pub(super) async fn add_cluster_reference<D: BlockSource, State, N>(
        &mut self,
        volume: &mut MountedVolume<D, State, N>,
        block: BlockAddress,
    ) -> Result<()> {
        let cluster = volume.superblock.cluster_of_block(block)?;
        if cluster_bitmap_state(&mut volume.device, &volume.superblock, cluster).await?
            != BitmapBitState::Used
        {
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
    pub(super) async fn add_static_metadata<D: BlockSource, State, N>(
        &mut self,
        volume: &mut MountedVolume<D, State, N>,
    ) -> Result<()> {
        let groups = volume.superblock.block_group_count()?;
        let descriptor_blocks = descriptor_table_blocks(&volume.superblock)?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            if group_has_superblock(volume, group) {
                let superblock_block = group_start_block(&volume.superblock, group)?;
                self.add_exclusive_reference(volume, superblock_block)
                    .await?;
                for offset in 0..descriptor_blocks {
                    self.add_exclusive_reference(
                        volume,
                        BlockAddress::new(
                            superblock_block
                                .get()
                                .checked_add(1)
                                .and_then(|value| value.checked_add(offset))
                                .ok_or(Error::ArithmeticOverflow)?,
                        ),
                    )
                    .await?;
                }
            }

            let descriptor =
                BlockGroupDescriptor::read_from(&mut volume.device, &volume.superblock, group)
                    .await?;
            self.add_exclusive_reference(volume, descriptor.block_bitmap())
                .await?;
            self.add_exclusive_reference(volume, descriptor.inode_bitmap())
                .await?;
            let inode_table_blocks = inode_table_blocks(&volume.superblock, group)?;
            for offset in 0..inode_table_blocks {
                self.add_exclusive_reference(
                    volume,
                    BlockAddress::new(
                        descriptor
                            .inode_table()
                            .get()
                            .checked_add(offset)
                            .ok_or(Error::ArithmeticOverflow)?,
                    ),
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Adds data and dynamic metadata references from allocated inode records.
    /// # Errors
    ///
    /// Returns an error when inode bitmaps, raw inode records, external xattr blocks, or extent tree
    /// blocks cannot be read or validated as allocated.
    pub(super) async fn add_live_inodes<D: BlockSource, State, N>(
        &mut self,
        volume: &mut MountedVolume<D, State, N>,
    ) -> Result<()> {
        for inode_number in 1..=volume.superblock.inode_count().as_u32() {
            let inode_id = InodeId::try_from(inode_number)?;
            if inode_bitmap_state(&mut volume.device, &volume.superblock, inode_id).await?
                != BitmapBitState::Used
            {
                continue;
            }
            let raw_inode = volume.read_raw_inode_record(inode_id).await?;
            if raw_inode.mode()? == 0 {
                continue;
            }
            if let Some(block) = raw_inode.xattr_block()? {
                self.add_xattr_reference(volume, block).await?;
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
                &root,
                volume.superblock.block_size(),
                &mut volume.device,
                context,
            )
            .await?;
            for extent in tree.extents().iter().copied() {
                self.add_extent_references(volume, extent).await?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                self.add_exclusive_reference(volume, block).await?;
            }
        }
        Ok(())
    }

    /// Adds references for every physical block represented by an extent.
    /// # Errors
    ///
    /// Returns an error when the extent block range overflows or any represented block is not an
    /// exclusively allocated cluster.
    pub(super) async fn add_extent_references<D: BlockSource, State, N>(
        &mut self,
        volume: &mut MountedVolume<D, State, N>,
        extent: Extent,
    ) -> Result<()> {
        for offset in 0..extent.len().as_u64() {
            self.add_exclusive_reference(
                volume,
                BlockAddress::new(
                    extent
                        .physical_start()
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ),
            )
            .await?;
        }
        Ok(())
    }

    /// Applies one signed delta and returns the resulting signed count.
    /// # Errors
    ///
    /// Returns an error when reference-count arithmetic overflows or an existing reference slot
    /// cannot be found after lookup.
    pub(super) fn apply_delta(&mut self, cluster: ClusterAddress, delta: i32) -> Result<i32> {
        if let Some(index) = self
            .refs
            .iter()
            .position(|reference| reference.cluster == cluster)
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
                self.refs.remove(index);
            } else {
                self.refs
                    .get_mut(index)
                    .ok_or(Error::ClusterReferenceConflict)?
                    .count = u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?;
            }
            Ok(updated)
        } else if delta > 0 {
            self.refs.try_push(ClusterReference {
                cluster,
                count: u32::try_from(delta).map_err(|_| Error::ArithmeticOverflow)?,
            })?;
            Ok(delta)
        } else {
            Ok(delta)
        }
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

/// Reads the allocation bitmap bit for one cluster.
/// # Errors
///
/// Returns an error when `cluster` is outside the mounted geometry, its group descriptor cannot be
/// read, or the bitmap block cannot be loaded.
pub(super) async fn cluster_bitmap_state(
    reader: &mut impl BlockSource,
    superblock: &Superblock,
    cluster: ClusterAddress,
) -> Result<BitmapBitState> {
    let position = ClusterBitmapPosition::from_cluster(superblock, cluster)?;
    let group = position.group();
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group).await?;
    let mut bytes = memory::repeated_vec(
        0_u8,
        usize::try_from(superblock.block_size().bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    reader
        .read_exact_at(
            superblock
                .block_size()
                .offset_of(descriptor.block_bitmap())?,
            &mut bytes,
        )
        .await?;
    cluster_bitmap_bit_state(bytes.as_slice(), position)
}

/// Reads the inode bitmap bit for one inode.
/// # Errors
///
/// Returns an error when `inode_id` is outside the mounted inode range, its group descriptor cannot
/// be read, or the bitmap block cannot be loaded.
pub(super) async fn inode_bitmap_state(
    reader: &mut impl BlockSource,
    superblock: &Superblock,
    inode_id: InodeId,
) -> Result<BitmapBitState> {
    let position = InodeBitmapPosition::from_inode(superblock, inode_id)?;
    let group = position.group();
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group).await?;
    let mut bytes = memory::repeated_vec(
        0_u8,
        usize::try_from(superblock.block_size().bytes()).map_err(|_| Error::ArithmeticOverflow)?,
    )?;
    reader
        .read_exact_at(
            superblock
                .block_size()
                .offset_of(descriptor.inode_bitmap())?,
            &mut bytes,
        )
        .await?;
    inode_bitmap_bit_state(bytes.as_slice(), position)
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
pub(super) fn group_has_superblock<D, State, N>(
    volume: &MountedVolume<D, State, N>,
    group: BlockGroupId,
) -> bool {
    let value = group.as_u32();
    match volume.superblock.sparse_superblock_layout() {
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
pub(super) async fn inode_offset_on_device(
    reader: &mut impl BlockSource,
    superblock: &Superblock,
    inode_id: InodeId,
) -> Result<ByteOffset> {
    let position = InodeBitmapPosition::from_inode(superblock, inode_id)?;
    let group = position.group();
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group).await?;
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
