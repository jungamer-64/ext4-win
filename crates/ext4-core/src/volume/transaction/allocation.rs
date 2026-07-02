//! Cluster, inode, bitmap, and block-group allocation transitions.

use super::*;

impl<D: BlockWriter, N: FscryptNonceGenerator, J> JournalTransaction<'_, D, N, J> {
    /// Allocates the first free allocation cluster visible in group bitmaps.
    /// # Errors
    ///
    /// Returns an error when no full free cluster is available, bitmap state conflicts with staged
    /// references, or cluster/group accounting cannot be updated.
    pub(super) fn allocate_cluster(&mut self) -> Result<BlockAddress> {
        let groups = self.volume.superblock.block_group_count()?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
            let clusters_in_group = self.volume.superblock.clusters_in_group(group)?;
            for bit in 0..clusters_in_group {
                let position = ClusterBitmapPosition::new(group, bit);
                let cluster = ClusterAddress::new(
                    u64::from(group.as_u32())
                        .checked_mul(u64::from(
                            self.volume.superblock.clusters_per_group().as_u32(),
                        ))
                        .and_then(|start| start.checked_add(u64::from(bit)))
                        .ok_or(Error::ArithmeticOverflow)?,
                );
                let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
                if first_block.get() >= self.volume.superblock.block_count().as_u64() {
                    break;
                }
                if self.volume.superblock.blocks_in_cluster(cluster)?
                    != self.volume.superblock.blocks_per_cluster().as_u32()
                {
                    continue;
                }
                let occupied = {
                    let bitmap = self
                        .block_bitmap_updates
                        .get(bitmap_index)
                        .ok_or(Error::InvalidSuperblock)?;
                    cluster_bitmap_bit_state(bitmap.bytes.as_slice(), position)?
                };
                if occupied == BitmapBitState::Used {
                    continue;
                }
                if self.staged_cluster_reference_count(cluster)? != 0 {
                    return Err(Error::ClusterReferenceConflict);
                }
                let bitmap = self
                    .block_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                set_cluster_bitmap_bit(
                    bitmap.bytes.as_mut_slice(),
                    position,
                    BitmapBitState::Used,
                )?;
                self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(-1))?;
                self.free_clusters_delta = self.free_clusters_delta.checked_add(-1)?;
                self.record_cluster_reference_delta(cluster, 1)?;
                self.stage_cluster_zeroes(cluster)?;
                return Ok(first_block);
            }
        }
        Err(Error::NoSpace)
    }

    /// Stages zeroes for every block covered by a newly allocated cluster.
    /// # Errors
    ///
    /// Returns an error when the cluster range or zero-fill byte count cannot be represented.
    pub(super) fn stage_cluster_zeroes(&mut self, cluster: ClusterAddress) -> Result<()> {
        let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
        let blocks = self.volume.superblock.blocks_in_cluster(cluster)?;
        let bytes = usize::try_from(
            u64::from(blocks)
                .checked_mul(u64::from(self.volume.superblock.block_size().bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        self.data_writes.try_push(RangeWrite {
            offset: self.volume.superblock.block_size().offset_of(first_block)?,
            bytes: memory::repeated_vec(0_u8, bytes)?,
        })?;
        Ok(())
    }

    /// Records one staged cluster-reference delta after checking underflow.
    /// # Errors
    ///
    /// Returns an error when the delta overflows or would make the staged reference count negative.
    pub(super) fn record_cluster_reference_delta(
        &mut self,
        cluster: ClusterAddress,
        delta: i32,
    ) -> Result<()> {
        let updated = self
            .staged_cluster_reference_count(cluster)?
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        if updated < 0 {
            return Err(Error::ClusterReferenceConflict);
        }
        if let Some(entry) = self
            .cluster_deltas
            .iter_mut()
            .find(|entry| entry.cluster == cluster)
        {
            entry.delta = entry
                .delta
                .checked_add(delta)
                .ok_or(Error::ArithmeticOverflow)?;
        } else {
            self.cluster_deltas
                .try_push(ClusterReferenceDelta { cluster, delta })?;
        }
        Ok(())
    }

    /// Returns mounted plus staged references for one cluster.
    /// # Errors
    ///
    /// Returns an error when mounted or staged reference counts cannot be represented as signed
    /// arithmetic.
    pub(super) fn staged_cluster_reference_count(&self, cluster: ClusterAddress) -> Result<i32> {
        let mut count = i32::try_from(self.volume.state.clusters.count(cluster))
            .map_err(|_| Error::ArithmeticOverflow)?;
        for delta in self
            .cluster_deltas
            .iter()
            .filter(|delta| delta.cluster == cluster)
        {
            count = count
                .checked_add(delta.delta)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(count)
    }

    /// Releases a block-owned cluster reference and frees the cluster if no references remain.
    /// # Errors
    ///
    /// Returns an error when `block` cannot be mapped to a cluster or releasing it would underflow
    /// the staged reference count.
    pub(super) fn release_cluster_reference(&mut self, block: BlockAddress) -> Result<()> {
        let cluster = self.volume.superblock.cluster_of_block(block)?;
        self.record_cluster_reference_delta(cluster, -1)?;
        if self.staged_cluster_reference_count(cluster)? == 0 {
            self.free_cluster(cluster)?;
        }
        Ok(())
    }

    /// Clears one cluster bitmap bit and records the affected accounting deltas.
    /// # Errors
    ///
    /// Returns an error when the cluster is not currently allocated, its bitmap cannot be staged, or
    /// free-cluster counters overflow.
    pub(super) fn free_cluster(&mut self, cluster: ClusterAddress) -> Result<()> {
        let position = ClusterBitmapPosition::from_cluster(&self.volume.superblock, cluster)?;
        let group = position.group();
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
        let bitmap = self
            .block_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if cluster_bitmap_bit_state(bitmap.bytes.as_slice(), position)? == BitmapBitState::Used {
            set_cluster_bitmap_bit(bitmap.bytes.as_mut_slice(), position, BitmapBitState::Free)?;
            self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(1))?;
            self.free_clusters_delta = self.free_clusters_delta.checked_add(1)?;
            Ok(())
        } else {
            Err(Error::ClusterReferenceConflict)
        }
    }

    /// Frees the suffix of an extent after `keep_len` blocks.
    /// # Errors
    ///
    /// Returns an error when the suffix block range overflows or any released cluster reference is
    /// inconsistent.
    pub(super) fn free_extent(&mut self, extent: Extent, keep_len: u16) -> Result<()> {
        let start = u64::from(keep_len);
        let len = extent.len().as_u64();
        let physical_start = extent
            .physical_start()
            .get()
            .checked_add(start)
            .ok_or(Error::ArithmeticOverflow)?;
        for offset in start..len {
            let block = BlockAddress::new(
                extent
                    .physical_start()
                    .get()
                    .checked_add(offset)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            self.release_cluster_reference(block)?;
        }
        if physical_start > extent.physical_start().get() || keep_len == 0 {
            Ok(())
        } else {
            Err(Error::ArithmeticOverflow)
        }
    }

    /// Allocates the first non-reserved inode visible in inode bitmaps.
    /// # Errors
    ///
    /// Returns an error when no free non-reserved inode exists, inode bitmap staging fails, or free
    /// inode counters cannot be updated.
    pub(super) fn allocate_inode(&mut self) -> Result<AllocatedInodeRecord> {
        let groups = self.volume.superblock.block_group_count()?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            if descriptor.free_inodes_count() == 0 {
                continue;
            }
            let bitmap_index = self.ensure_inode_bitmap_update(descriptor.inode_bitmap())?;
            let inodes_in_group = self.inodes_in_group(group)?;
            for bit in 0..inodes_in_group {
                let position = InodeBitmapPosition::new(group, bit);
                let inode_id = position.inode_id(&self.volume.superblock)?;
                if inode_id.as_u32() < self.volume.superblock.first_inode().as_u32() {
                    continue;
                }
                let bitmap = self
                    .inode_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                if inode_bitmap_bit_state(bitmap.bytes.as_slice(), position)?
                    == BitmapBitState::Free
                {
                    set_inode_bitmap_bit(
                        bitmap.bytes.as_mut_slice(),
                        position,
                        BitmapBitState::Used,
                    )?;
                    self.record_group_free_inodes_delta(group, -1)?;
                    return self.empty_allocated_inode_record(inode_id);
                }
            }
        }
        Err(Error::NoFreeInode)
    }

    /// Marks an inode free and records its group allocation delta.
    /// # Errors
    ///
    /// Returns an error when `inode_id` is the root inode, cannot be mapped to a bitmap bit, or the
    /// free-inode delta overflows.
    pub(super) fn free_inode(&mut self, inode_id: InodeId) -> Result<()> {
        if inode_id == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let position = InodeBitmapPosition::from_inode(&self.volume.superblock, inode_id)?;
        let group = position.group();
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_inode_bitmap_update(descriptor.inode_bitmap())?;
        let bitmap = self
            .inode_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if inode_bitmap_bit_state(bitmap.bytes.as_slice(), position)? == BitmapBitState::Used {
            set_inode_bitmap_bit(bitmap.bytes.as_mut_slice(), position, BitmapBitState::Free)?;
            self.record_group_free_inodes_delta(group, 1)?;
        }
        Ok(())
    }

    /// Returns the staged block bitmap index, loading it once when needed.
    /// # Errors
    ///
    /// Returns an error when the bitmap block cannot be read or its staged vector index cannot be
    /// represented.
    pub(super) fn ensure_block_bitmap_update(
        &mut self,
        bitmap_block: BlockAddress,
    ) -> Result<usize> {
        if let Some(index) = self
            .block_bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(self.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.volume.device.read_exact_at(
            self.volume
                .superblock
                .block_size()
                .offset_of(bitmap_block)?,
            &mut bytes,
        )?;
        self.block_bitmap_updates.try_push(BlockImage {
            block: bitmap_block,
            bytes,
        })?;
        self.block_bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Returns the staged inode bitmap index, loading it once when needed.
    /// # Errors
    ///
    /// Returns an error when the inode bitmap block cannot be read or its staged vector index cannot
    /// be represented.
    pub(super) fn ensure_inode_bitmap_update(
        &mut self,
        bitmap_block: BlockAddress,
    ) -> Result<usize> {
        if let Some(index) = self
            .inode_bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let mut bytes = memory::repeated_vec(
            0_u8,
            usize::try_from(self.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        self.volume.device.read_exact_at(
            self.volume
                .superblock
                .block_size()
                .offset_of(bitmap_block)?,
            &mut bytes,
        )?;
        self.inode_bitmap_updates.try_push(BlockImage {
            block: bitmap_block,
            bytes,
        })?;
        self.inode_bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Returns the inode count actually present in a possibly partial group.
    /// # Errors
    ///
    /// Returns an error when group inode arithmetic overflows or the group starts past the inode
    /// count.
    pub(super) fn inodes_in_group(&self, group: BlockGroupId) -> Result<u32> {
        let group_start = u64::from(group.as_u32())
            .checked_mul(u64::from(
                self.volume.superblock.inodes_per_group().as_u32(),
            ))
            .ok_or(Error::ArithmeticOverflow)?;
        let remaining = u64::from(self.volume.superblock.inode_count().as_u32())
            .checked_sub(group_start)
            .ok_or(Error::InvalidSuperblock)?;
        Ok(core::cmp::min(
            self.volume.superblock.inodes_per_group().as_u32(),
            u32::try_from(remaining).unwrap_or(u32::MAX),
        ))
    }

    /// Creates a zeroed inode record at the allocated inode's device offset.
    /// # Errors
    ///
    /// Returns an error when `inode_id` cannot be mapped to an inode-table offset.
    pub(super) fn empty_allocated_inode_record(
        &self,
        inode_id: InodeId,
    ) -> Result<AllocatedInodeRecord> {
        Ok(RawInodeRecord {
            id: inode_id,
            offset: inode_offset_on_device(&self.volume.device, &self.volume.superblock, inode_id)?,
            bytes: memory::repeated_vec(
                0_u8,
                usize::from(self.volume.superblock.inode_size().as_u16()),
            )?,
        }
        .into_allocated())
    }

    /// Returns the mutable delta accumulator for a block group.
    /// # Errors
    ///
    /// Returns an error when the newly inserted group delta cannot be recovered from the staging
    /// vector.
    pub(super) fn group_delta_mut(&mut self, group: BlockGroupId) -> Result<&mut GroupDelta> {
        if let Some(index) = self
            .group_deltas
            .iter()
            .position(|entry| entry.group == group)
        {
            return self
                .group_deltas
                .get_mut(index)
                .ok_or(Error::InvalidSuperblock);
        }
        self.group_deltas.try_push(GroupDelta::new(group))?;
        self.group_deltas.last_mut().ok_or(Error::InvalidSuperblock)
    }

    /// Records a free-cluster count delta for one block group.
    /// # Errors
    ///
    /// Returns an error when the group free-cluster delta exceeds the checked counter range.
    pub(super) fn record_group_free_clusters_delta(
        &mut self,
        group: BlockGroupId,
        delta: FreeClusterDelta,
    ) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.free_clusters_delta = entry.free_clusters_delta.checked_add(delta.as_i64())?;
        Ok(())
    }

    /// Records a free-inode count delta for one block group and the superblock.
    /// # Errors
    ///
    /// Returns an error when the group or superblock free-inode delta exceeds the checked counter
    /// range.
    pub(super) fn record_group_free_inodes_delta(
        &mut self,
        group: BlockGroupId,
        delta: i64,
    ) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.free_inodes_delta = entry
            .free_inodes_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        self.free_inodes_delta = self
            .free_inodes_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    /// Records a used-directory count delta for one block group.
    /// # Errors
    ///
    /// Returns an error when the used-directory delta exceeds the checked group counter range.
    pub(super) fn record_group_used_dirs_delta(
        &mut self,
        group: BlockGroupId,
        delta: i64,
    ) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.used_dirs_delta = entry
            .used_dirs_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }
}
