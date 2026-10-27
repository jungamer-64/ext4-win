//! Cluster, inode, bitmap, and block-group allocation transitions.

use super::*;

/// An exclusion snapshot observes reserved space; it cannot create allocation ownership.
#[derive(Debug)]
pub(super) enum AllocationExclusionSource {
    /// A mounted discard retains its independently completed lower-device reservation.
    Discard(super::super::trim::AllocationExclusions),
    /// Every recorded physical ADD remains protected before any recovery metadata allocation.
    Recovery(Vec<ProtectedClusters>),
}
/// Sorted, disjoint allocation intervals derived from an immutable authenticated program.
#[derive(Clone, Copy, Debug)]
pub(super) struct ProtectedClusters {
    /// Inclusive cluster coordinate.
    first: ClusterAddress,
    /// Exclusive allocation boundary, never dereferenced as a physical cluster.
    end: ClusterAddress,
}
impl AllocationExclusionSource {
    /// All physical operands are admitted before selecting any new recovery metadata block.
    /// # Errors
    /// Rejects out-of-filesystem extents, coordinate overflow or pre-effect allocation failure.
    pub(super) fn recovery(
        superblock: Superblock,
        program: &crate::disk_format::journal::fast_commit::DeltaProgram,
    ) -> Result<Self> {
        use crate::disk_format::journal::fast_commit::ParsedDelta;
        let mut ranges: Vec<ProtectedClusters> = Vec::new();
        for record in program.records() {
            if let ParsedDelta::AddRange { extent, .. } = record {
                let end = extent
                    .physical_start()
                    .get()
                    .checked_add(extent.len().as_u64())
                    .ok_or(Error::InvalidExtentTree)?;
                if end > superblock.block_count().as_u64() {
                    return Err(Error::InvalidExtentTree);
                }
                let first = superblock.cluster_of_block(extent.physical_start())?;
                let last = superblock.cluster_of_block(BlockAddress::new(
                    end.checked_sub(1).ok_or(Error::InvalidExtentTree)?,
                ))?;
                ranges.try_push(ProtectedClusters {
                    first,
                    end: ClusterAddress::new(
                        last.get().checked_add(1).ok_or(Error::ArithmeticOverflow)?,
                    ),
                })?;
            }
        }
        memory::heap_sort_by(&mut ranges, |a, b| a.first.cmp(&b.first))?;
        let mut merged: Vec<ProtectedClusters> = Vec::new();
        for range in ranges {
            if let Some(previous) = merged.last_mut()
                && range.first <= previous.end
            {
                previous.end = previous.end.max(range.end);
            } else {
                merged.try_push(range)?;
            }
        }
        Ok(Self::Recovery(merged))
    }
    /// Membership does not mutate a bitmap, reference count or reservation owner.
    fn contains(&self, cluster: ClusterAddress) -> bool {
        match self {
            Self::Discard(snapshot) => snapshot.contains(cluster),
            Self::Recovery(ranges) => {
                let index = ranges.partition_point(|range| range.end <= cluster);
                ranges
                    .get(index)
                    .is_some_and(|range| range.first <= cluster)
            }
        }
    }
}

impl MetadataMutation<'_, '_> {
    /// Allocates an unmapped logical block in its extent stream's physical cluster.
    /// Existing mappings in the same logical cluster select both the physical cluster and the
    /// offset within it. The caller records the extent's initialized or unwritten state.
    /// # Errors
    /// Returns invalid geometry, reference-accounting, arithmetic, or cluster-allocation failures.
    pub(super) fn allocate_extent_block(
        &mut self,
        tree: &MutableExtentTree,
        logical_block: LogicalBlock,
    ) -> Result<BlockAddress> {
        let blocks_per_cluster = u64::from(self.volume.superblock.blocks_per_cluster().as_u32());
        let logical = logical_block.as_u64();
        let cluster_offset = logical
            .checked_rem(blocks_per_cluster)
            .ok_or(Error::InvalidClusterGeometry)?;
        let logical_cluster_start = logical
            .checked_sub(cluster_offset)
            .ok_or(Error::ArithmeticOverflow)?;
        for offset in 0..blocks_per_cluster {
            let probe = logical_cluster_start
                .checked_add(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if probe > u64::from(u32::MAX) {
                break;
            }
            let Some(physical) = tree.allocated_block(LogicalBlock::try_from(probe)?)? else {
                continue;
            };
            let cluster = self.volume.superblock.cluster_of_block(physical)?;
            let physical = self.physical_block_in_cluster(cluster, cluster_offset)?;
            self.record_cluster_reference_delta(cluster, 1)?;
            return Ok(physical);
        }
        let first_block = self.allocate_cluster()?;
        let cluster = self.volume.superblock.cluster_of_block(first_block)?;
        self.physical_block_in_cluster(cluster, cluster_offset)
    }

    /// Converts a cluster-relative block offset within the mounted geometry.
    /// # Errors
    /// Returns invalid geometry for an absent offset, or physical-address overflow.
    fn physical_block_in_cluster(
        &self,
        cluster: ClusterAddress,
        offset: u64,
    ) -> Result<BlockAddress> {
        if offset >= u64::from(self.volume.superblock.blocks_in_cluster(cluster)?) {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(BlockAddress::new(
            self.volume
                .superblock
                .first_block_of_cluster(cluster)?
                .get()
                .checked_add(offset)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Releases payload and extent metadata ownership without inventing blocks for inline storage.
    /// # Errors
    /// Rejects unsupported storage and inconsistent allocation references.
    pub(super) fn release_inode_data(&mut self, inode: &Inode) -> Result<()> {
        self.register_zero_on_deallocation(inode)?;
        match inode.storage() {
            InodeStorage::FastSymlink(_) | InodeStorage::InlineData(_) => Ok(()),
            InodeStorage::UnsupportedBlockMap => Err(Error::UnsupportedBlockMap),
            InodeStorage::Extents(_) => {
                let tree = self.mutable_extent_tree(inode)?;
                for extent in tree.extents().iter().copied() {
                    self.free_extent(extent, 0)?;
                }
                for block in tree.metadata_blocks().iter().copied() {
                    self.release_cluster_reference(block)?;
                }
                Ok(())
            }
        }
    }
    /// Releases terminal inode ownership after all data and extent-node references are staged away.
    /// # Errors
    /// Returns an error for invalid xattr ownership, allocation bitmaps, or directory accounting.
    pub(super) fn reclaim_inode(&mut self, raw: &RawInodeRecord<Vec<u8>>) -> Result<()> {
        self.release_inline_attribute_values(raw)?;
        if let Some(block) = raw.xattr_block()? {
            if raw.flags()?.zero_on_deallocation() {
                self.protect_zero_retirement(block)?;
            }
            self.release_xattr_block_ref(block)?;
        }
        self.free_inode(raw.id())?;
        if InodeMode::from_disk(raw.mode()?)?.kind() == InodeKind::Directory {
            let group = InodeBitmapPosition::from_inode(&self.volume.superblock, raw.id())?.group();
            self.record_group_used_dirs_delta(group, -1)?;
        }
        Ok(())
    }

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
                &mut self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            let bitmap_index = self.ensure_block_bitmap_update(group, &descriptor)?;
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
                if let Some(block) = self.claim_cluster(cluster, position, bitmap_index)? {
                    return Ok(block);
                }
            }
        }
        Err(Error::NoSpace)
    }

    /// Claims one requested cluster through the same bitmap and reference authority as ordinary
    /// allocation. A bitmap observation never reserves its destination for a later relocation.
    /// # Errors
    /// Returns range, allocation exclusion, occupied destination or accounting failures.
    pub(super) fn allocate_cluster_at(&mut self, cluster: ClusterAddress) -> Result<BlockAddress> {
        let position = ClusterBitmapPosition::from_cluster(&self.volume.superblock, cluster)?;
        let descriptor = BlockGroupDescriptor::read_from(
            &mut self.volume.device,
            &self.volume.superblock,
            position.group(),
        )?;
        let bitmap = self.ensure_block_bitmap_update(position.group(), &descriptor)?;
        self.claim_cluster(cluster, position, bitmap)?
            .ok_or(Error::NoSpace)
    }

    /// Selects a full free run without granting allocation ownership. Later exact claims recheck
    /// the same bitmap, committed references and independent allocation exclusions.
    /// # Errors
    /// Returns finite-space exhaustion, malformed geometry or metadata/reference failures.
    pub(super) fn find_free_cluster_run(
        &mut self,
        count: crate::ClusterCount,
    ) -> Result<ClusterAddress> {
        let mut run = 0_u64;
        let mut first = ClusterAddress::new(0);
        for group in 0..self.volume.superblock.block_group_count()?.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &mut self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            // Candidate exploration owns no bitmap update or allocation authority. Only the
            // subsequently claimed chunk contributes group writes to mutation admission.
            let bitmap = if let Some(staged) = self
                .block_bitmap_updates
                .iter()
                .find(|image| image.block == descriptor.block_bitmap())
            {
                memory::copied_slice(&staged.bytes)?
            } else {
                match descriptor.block_bitmap_initialization() {
                    AllocationBitmapInitialization::Initialized => descriptor.read_bitmap(
                        &mut self.volume.device,
                        &self.volume.superblock,
                        AllocationBitmapKind::Block,
                    )?,
                    AllocationBitmapInitialization::Uninitialized => {
                        let layouts = read_group_metadata_layouts(
                            &mut self.volume.device,
                            &self.volume.superblock,
                        )?;
                        materialize_uninitialized_block_bitmap(
                            &self.volume.superblock,
                            group,
                            &layouts,
                        )?
                    }
                }
            };
            for bit in 0..self.volume.superblock.clusters_in_group(group)? {
                let cluster = ClusterAddress::new(
                    u64::from(group.as_u32())
                        .checked_mul(u64::from(
                            self.volume.superblock.clusters_per_group().as_u32(),
                        ))
                        .and_then(|base| base.checked_add(u64::from(bit)))
                        .ok_or(Error::ArithmeticOverflow)?,
                );
                if self.cluster_available(
                    cluster,
                    ClusterBitmapPosition::new(group, bit),
                    &bitmap,
                )? {
                    if run == 0 {
                        first = cluster;
                    }
                    run = run.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                    if run == count.as_u64() {
                        return Ok(first);
                    }
                } else {
                    run = 0;
                }
            }
        }
        Err(Error::NoSpace)
    }

    /// Allocates a logical block at an exact physical coordinate, sharing only its own already
    /// mapped logical cluster. Exact placement never silently falls back to another free cluster.
    /// # Errors
    /// Returns occupied destination, inconsistent cluster origin or allocation failures.
    pub(super) fn allocate_extent_block_at(
        &mut self,
        tree: &MutableExtentTree,
        logical: LogicalBlock,
        physical: BlockAddress,
    ) -> Result<()> {
        let superblock = self.volume.superblock;
        let cluster = superblock.cluster_of_block(physical)?;
        let width = u64::from(superblock.blocks_per_cluster().as_u32());
        let within = logical
            .as_u64()
            .checked_rem(width)
            .ok_or(Error::InvalidClusterGeometry)?;
        if self.physical_block_in_cluster(cluster, within)? != physical {
            return Err(Error::InvalidClusterGeometry);
        }
        let start = logical
            .as_u64()
            .checked_sub(within)
            .ok_or(Error::ArithmeticOverflow)?;
        for offset in 0..width {
            let probe = start.checked_add(offset).ok_or(Error::ArithmeticOverflow)?;
            if probe > u64::from(u32::MAX) {
                break;
            }
            if let Some(mapped) = tree.allocated_block(LogicalBlock::try_from(probe)?)? {
                if superblock.cluster_of_block(mapped)? != cluster {
                    return Err(Error::ClusterReferenceConflict);
                }
                return self.record_cluster_reference_delta(cluster, 1);
            }
        }
        self.allocate_cluster_at(cluster).map(|_| ())
    }

    /// A free observation is provisional; only `claim_cluster` publishes staged ownership.
    /// # Errors
    /// Returns malformed geometry or inconsistent committed/staged reference accounting.
    fn cluster_available(
        &self,
        cluster: ClusterAddress,
        position: ClusterBitmapPosition,
        bitmap: &[u8],
    ) -> Result<bool> {
        if self.volume.superblock.blocks_in_cluster(cluster)?
            != self.volume.superblock.blocks_per_cluster().as_u32()
        {
            return Ok(false);
        }
        if cluster_bitmap_bit_state(bitmap, position)? == BitmapBitState::Used
            || self.allocation.contains(cluster)
            || self.volume.committed_clusters()?.count(cluster) != 0
        {
            return Ok(false);
        }
        if self.staged_cluster_reference_count(cluster)? != 0 {
            return Err(Error::ClusterReferenceConflict);
        }
        Ok(true)
    }

    /// Claims a full unowned cluster, or reports a destination unavailable without changing it.
    /// # Errors
    /// Returns malformed geometry, inconsistent staged ownership or accounting/allocation failure.
    fn claim_cluster(
        &mut self,
        cluster: ClusterAddress,
        position: ClusterBitmapPosition,
        bitmap_index: usize,
    ) -> Result<Option<BlockAddress>> {
        let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
        // Ordered home writes cannot reuse an owner retired by this uncommitted transaction.
        let bitmap = self
            .block_bitmap_updates
            .get(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if !self.cluster_available(cluster, position, &bitmap.bytes)? {
            return Ok(None);
        }
        let bitmap = self
            .block_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        set_cluster_bitmap_bit(bitmap.bytes.as_mut_slice(), position, BitmapBitState::Used)?;
        self.record_group_free_clusters_delta(position.group(), FreeClusterDelta::from_i64(-1))?;
        self.free_clusters_delta = self.free_clusters_delta.checked_add(-1)?;
        self.record_cluster_reference_delta(cluster, 1)?;
        self.stage_cluster_zeroes(cluster)?;
        Ok(Some(first_block))
    }

    /// Stages zeroes for every block covered by a newly allocated cluster.
    /// # Errors
    ///
    /// Returns an error when the cluster range or zero-fill byte count cannot be represented.
    pub(super) fn stage_cluster_zeroes(&mut self, cluster: ClusterAddress) -> Result<()> {
        let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
        let blocks = self.volume.superblock.blocks_in_cluster(cluster)?;
        let block_size = self.volume.superblock.block_size();
        let bytes = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        for index in 0..blocks {
            let block = BlockAddress::new(
                first_block
                    .get()
                    .checked_add(u64::from(index))
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            self.stage_file_write(
                FileDataPersistence::Ordered,
                RangeWrite {
                    offset: block_size.offset_of(block)?,
                    bytes: memory::repeated_vec(0_u8, bytes)?,
                },
            )?;
        }
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
        let mut count = i32::try_from(self.volume.committed_clusters()?.count(cluster))
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
        self.release_block_images(block);
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
        let descriptor = BlockGroupDescriptor::read_from(
            &mut self.volume.device,
            &self.volume.superblock,
            group,
        )?;
        let bitmap_index = self.ensure_block_bitmap_update(group, &descriptor)?;
        let bitmap = self
            .block_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if cluster_bitmap_bit_state(bitmap.bytes.as_slice(), position)? == BitmapBitState::Used {
            set_cluster_bitmap_bit(bitmap.bytes.as_mut_slice(), position, BitmapBitState::Free)?;
            self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(1))?;
            self.free_clusters_delta = self.free_clusters_delta.checked_add(1)?;
            self.zero_retired_cluster(cluster)?;
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

    /// Allocates the first free inode not already represented by this transaction.
    /// Deleted records retain their identities until the transaction is consumed, so an
    /// earlier typed selection cannot silently bind to a new inode within the same pass.
    /// # Errors
    ///
    /// Returns no-free-inode when no unreserved identity remains, or an error when bitmap staging
    /// or inode accounting fails. Retirement reservations do not survive publication or abandonment.
    pub(super) fn allocate_inode(&mut self) -> Result<AllocatedInodeRecord> {
        let groups = self.volume.superblock.block_group_count()?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &mut self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            if descriptor.free_inodes_count() == 0 {
                continue;
            }
            let bitmap_index = self.ensure_inode_bitmap_update(group, &descriptor)?;
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
                    && !self
                        .inode_updates
                        .iter()
                        .any(|record| record.id() == inode_id)
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
        let descriptor = BlockGroupDescriptor::read_from(
            &mut self.volume.device,
            &self.volume.superblock,
            group,
        )?;
        let bitmap_index = self.ensure_inode_bitmap_update(group, &descriptor)?;
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
        group: BlockGroupId,
        descriptor: &BlockGroupDescriptor,
    ) -> Result<usize> {
        let bitmap_block = descriptor.block_bitmap();
        if let Some(index) = self
            .block_bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let bytes = match descriptor.block_bitmap_initialization() {
            AllocationBitmapInitialization::Initialized => descriptor.read_bitmap(
                &mut self.volume.device,
                &self.volume.superblock,
                AllocationBitmapKind::Block,
            )?,
            AllocationBitmapInitialization::Uninitialized => {
                let layouts =
                    read_group_metadata_layouts(&mut self.volume.device, &self.volume.superblock)?;
                let bytes = materialize_uninitialized_block_bitmap(
                    &self.volume.superblock,
                    group,
                    &layouts,
                )?;
                self.record_group_block_bitmap_initialization(group)?;
                bytes
            }
        };
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
        group: BlockGroupId,
        descriptor: &BlockGroupDescriptor,
    ) -> Result<usize> {
        let bitmap_block = descriptor.inode_bitmap();
        if let Some(index) = self
            .inode_bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let bytes = match descriptor.inode_bitmap_initialization() {
            AllocationBitmapInitialization::Initialized => descriptor.read_bitmap(
                &mut self.volume.device,
                &self.volume.superblock,
                AllocationBitmapKind::Inode,
            )?,
            AllocationBitmapInitialization::Uninitialized => {
                let bytes = materialize_uninitialized_inode_bitmap(&self.volume.superblock, group)?;
                self.record_group_inode_bitmap_initialization(group)?;
                bytes
            }
        };
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
        &mut self,
        inode_id: InodeId,
    ) -> Result<AllocatedInodeRecord> {
        Ok(RawInodeRecord {
            id: inode_id,
            offset: inode_offset_on_device(
                &mut self.volume.device,
                &self.volume.superblock,
                inode_id,
            )?,
            bytes: memory::repeated_vec(
                0_u8,
                usize::from(self.volume.superblock.inode_size().as_u16()),
            )?,
            encoding: self.volume.superblock.inode_data_encoding(),
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

    /// Records that this transaction will persist a formerly derived block bitmap.
    /// # Errors
    ///
    /// Returns an error when the group delta cannot be staged.
    pub(super) fn record_group_block_bitmap_initialization(
        &mut self,
        group: BlockGroupId,
    ) -> Result<()> {
        self.group_delta_mut(group)?.block_bitmap_initialization =
            BitmapInitializationTransition::Initialize;
        Ok(())
    }

    /// Records that this transaction will persist a formerly derived inode bitmap.
    /// # Errors
    ///
    /// Returns an error when the group delta cannot be staged.
    pub(super) fn record_group_inode_bitmap_initialization(
        &mut self,
        group: BlockGroupId,
    ) -> Result<()> {
        self.group_delta_mut(group)?.inode_bitmap_initialization =
            BitmapInitializationTransition::Initialize;
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
