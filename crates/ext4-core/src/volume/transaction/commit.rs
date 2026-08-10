//! Transaction commit serialization and journal handoff.

use super::*;

impl<N: FscryptNonceGenerator> MutationResolvePass<'_, '_, '_, N> {
    /// Serializes all staged metadata mutations into byte-range writes.
    /// # Errors
    ///
    /// Returns an error when staged bitmap, directory, extent, xattr, group, superblock, or inode
    /// metadata cannot be serialized to device byte ranges.
    fn metadata_writes(&mut self) -> Result<Vec<RangeWrite>> {
        let mut writes = Vec::new();
        for bitmap in &self.block_bitmap_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: memory::copied_slice(&bitmap.bytes)?,
            })?;
        }
        for bitmap in &self.inode_bitmap_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: memory::copied_slice(&bitmap.bytes)?,
            })?;
        }
        for directory in &self.directory_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(directory.block)?,
                bytes: memory::copied_slice(&directory.bytes)?,
            })?;
        }
        for extent in &self.extent_updates {
            writes.try_push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(extent.block)?,
                bytes: memory::copied_slice(&extent.bytes)?,
            })?;
        }
        for xattr in &self.xattr_updates {
            writes.try_push(RangeWrite {
                offset: self.volume.superblock.block_size().offset_of(xattr.block)?,
                bytes: memory::copied_slice(&xattr.bytes)?,
            })?;
        }
        for delta in &self.group_deltas {
            let mut descriptor = BlockGroupDescriptor::read_from(
                &mut self.volume.device,
                &self.volume.superblock,
                delta.group,
            )?;
            if !delta.free_clusters_delta.is_zero() {
                descriptor.apply_free_clusters_delta(
                    delta.free_clusters_delta,
                    &self.volume.superblock,
                    delta.group,
                )?;
            }
            if delta.free_inodes_delta != 0 {
                descriptor.apply_free_inodes_delta(
                    delta.free_inodes_delta,
                    &self.volume.superblock,
                    delta.group,
                )?;
            }
            if delta.used_dirs_delta != 0 {
                descriptor.apply_used_dirs_delta(
                    delta.used_dirs_delta,
                    &self.volume.superblock,
                    delta.group,
                )?;
            }
            if let Some(bitmap) = self
                .block_bitmap_updates
                .iter()
                .find(|bitmap| bitmap.block == descriptor.block_bitmap())
            {
                descriptor.refresh_block_bitmap_checksum(
                    &self.volume.superblock,
                    delta.group,
                    bitmap.bytes.as_slice(),
                )?;
            }
            if let Some(bitmap) = self
                .inode_bitmap_updates
                .iter()
                .find(|bitmap| bitmap.block == descriptor.inode_bitmap())
            {
                descriptor.refresh_inode_bitmap_checksum(
                    &self.volume.superblock,
                    delta.group,
                    bitmap.bytes.as_slice(),
                )?;
            }
            writes.try_push(RangeWrite {
                offset: descriptor.offset(),
                bytes: memory::copied_slice(descriptor.bytes())?,
            })?;
        }
        if !self.free_clusters_delta.is_zero()
            || self.free_inodes_delta != 0
            || self.volume_label_update.is_some()
        {
            writes.try_push(RangeWrite {
                offset: ByteOffset::new(SUPERBLOCK_OFFSET),
                bytes: self.updated_superblock_bytes()?,
            })?;
        }
        for inode in &self.inode_updates {
            let mut inode = inode.try_clone()?;
            inode.refresh_checksum(&self.volume.superblock)?;
            writes.try_push(RangeWrite {
                offset: inode.offset(),
                bytes: memory::copied_slice(inode.bytes())?,
            })?;
        }
        Ok(writes)
    }

    /// Coalesces metadata byte ranges into full blocks for journaling.
    /// # Errors
    ///
    /// Returns an error when a metadata write does not fit within one block or an original metadata
    /// block cannot be read before patching.
    fn metadata_blocks(&mut self) -> Result<Vec<MetadataBlock>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_bytes_u64 = u64::from(block_size.bytes());
        let mut blocks = Vec::new();

        for write in self.metadata_writes()? {
            let block = BlockAddress::new(
                write
                    .offset
                    .get()
                    .checked_div(block_bytes_u64)
                    .ok_or(Error::InvalidSuperblock)?,
            );
            let in_block = usize::try_from(
                write
                    .offset
                    .get()
                    .checked_rem(block_bytes_u64)
                    .ok_or(Error::InvalidSuperblock)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let end = in_block
                .checked_add(write.bytes.len())
                .ok_or(Error::ArithmeticOverflow)?;
            if end > block_bytes {
                return Err(Error::InvalidWriteRange);
            }

            let index = if let Some(index) = blocks
                .iter()
                .position(|metadata: &MetadataBlock| metadata.block() == block)
            {
                index
            } else {
                let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
                self.volume
                    .device
                    .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
                blocks.try_push(MetadataBlock::new(block, bytes))?;
                blocks
                    .len()
                    .checked_sub(1)
                    .ok_or(Error::ArithmeticOverflow)?
            };
            memory::copy_exact(
                blocks
                    .get_mut(index)
                    .ok_or(Error::InvalidSuperblock)?
                    .bytes_mut()
                    .get_mut(in_block..end)
                    .ok_or(Error::DeviceRange)?,
                &write.bytes,
            )?;
        }

        Ok(blocks)
    }

    /// Applies accumulated free-count deltas to a superblock image.
    /// # Errors
    ///
    /// Returns an error when the primary superblock cannot be read, free counters underflow or
    /// overflow, the label cannot be written, or the checksum cannot be refreshed.
    fn updated_superblock_bytes(&mut self) -> Result<Vec<u8>> {
        let mut bytes = memory::repeated_vec(0_u8, 1024)?;
        self.volume
            .device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut bytes)?;
        self.volume
            .superblock
            .apply_free_cluster_delta_to_raw(&mut bytes, self.free_clusters_delta)?;
        if self.free_inodes_delta != 0 {
            let current = u64::from(le_u32(&bytes, disk_offset(SUPERBLOCK_FREE_INODES_OFFSET))?);
            let raw_delta = self.free_inodes_delta;
            let updated = if raw_delta.is_negative() {
                current
                    .checked_sub(raw_delta.unsigned_abs())
                    .ok_or(Error::InvalidSuperblock)?
            } else {
                current
                    .checked_add(u64::try_from(raw_delta).map_err(|_| Error::ArithmeticOverflow)?)
                    .ok_or(Error::ArithmeticOverflow)?
            };
            put_le_u32(
                &mut bytes,
                disk_offset(SUPERBLOCK_FREE_INODES_OFFSET),
                u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        if let Some(label) = self.volume_label_update {
            label.write_to(&mut bytes)?;
        }
        Superblock::refresh_checksum(&mut bytes)?;
        Ok(bytes)
    }
}

impl<N: FscryptNonceGenerator> MutationResolvePass<'_, '_, '_, N> {
    /// Completes a storage-resolved mutation without issuing any lower write.
    /// # Errors
    ///
    /// Returns an error when metadata coalescing, staged allocation validation, resource discovery,
    /// or any pre-write allocation fails.
    pub fn resolve(
        mut self,
        ticket: u64,
        coordinator: &MutationCoordinatorState,
    ) -> Result<ResolvedMutation> {
        let metadata_blocks = self.metadata_blocks()?;
        let _validated_next_state = self.committed_cluster_state()?;
        let mut observed = ObservedResourceVersionSet::new(ticket);
        for inode in &self.inode_updates {
            let resource = MutationResource::inode(inode.id());
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        for delta in &self.group_deltas {
            let resource = MutationResource::block_group(delta.group);
            observed.include(resource, coordinator.resource_version(resource))?;
        }
        if !self.free_clusters_delta.is_zero()
            || self.free_inodes_delta != 0
            || self.volume_label_update.is_some()
            || self.fscrypt_keys_update.is_some()
        {
            observed.include(
                MutationResource::VOLUME_METADATA,
                coordinator.resource_version(MutationResource::VOLUME_METADATA),
            )?;
        }
        Ok(ResolvedMutation {
            observed,
            data_writes: core::mem::take(&mut self.data_writes),
            metadata_blocks,
            cluster_deltas: core::mem::take(&mut self.cluster_deltas),
            free_clusters_delta: self.free_clusters_delta,
            free_inodes_delta: self.free_inodes_delta,
            volume_label_update: self.volume_label_update,
            fscrypt_keys_update: self.fscrypt_keys_update,
        })
    }
}

impl ReservedMutation {
    /// Allocates the complete write plan, both epoch publications, and checkpoint before I/O.
    ///
    /// This must run only while the mutation's resource intents and global commit grant are held.
    /// # Errors
    ///
    /// Returns an error when versions changed, the journal is not clean, serialization fails, or
    /// any pre-publication allocation fails.
    pub fn prepare_commit(
        self,
        coordinator: &MutationCoordinatorState,
        current_epoch: &CommittedEpoch,
        commit: super::super::CommitLease,
    ) -> Result<CommitReadyMutation> {
        if commit.into_ticket() != self.resolved.observed.ticket()
            || !coordinator.revalidate(&self.resolved.observed)
        {
            return Err(Error::ClusterReferenceConflict);
        }
        let JournalCoordinatorState::Ready(journal) = &coordinator.journal else {
            return Err(Error::JournalCorrupt);
        };
        let version_publication =
            coordinator.prepare_version_publication(&self.resolved.observed)?;

        let mut durable_clusters = current_epoch.clusters.try_clone()?;
        durable_clusters.apply_deltas(&self.resolved.cluster_deltas)?;
        let checkpoint_clusters = durable_clusters.try_clone()?;
        let durable_keys = match self.resolved.fscrypt_keys_update {
            Some(keys) => keys,
            None => current_epoch.fscrypt_keys.try_clone()?,
        };
        let checkpoint_keys = durable_keys.try_clone()?;
        let mut superblock = current_epoch.superblock;
        superblock.apply_free_cluster_delta(self.resolved.free_clusters_delta)?;
        superblock.apply_free_inode_delta(self.resolved.free_inodes_delta)?;
        if let Some(label) = self.resolved.volume_label_update {
            superblock.apply_volume_label(label);
        }

        let mut ordered_data_writes = Vec::new();
        ordered_data_writes
            .try_reserve_exact(self.resolved.data_writes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for write in self.resolved.data_writes {
            ordered_data_writes.try_push(crate::StorageRequest::Write {
                target: crate::StorageTarget::Filesystem,
                offset: write.offset,
                buffer: write.bytes,
            })?;
        }

        let prepared = journal.prepare_commit(
            current_epoch.superblock.block_size(),
            self.resolved.metadata_blocks,
        )?;
        let (
            planned_journal_writes,
            planned_commit_write,
            journal_target,
            durable_journal,
            overlay,
            checkpoint,
        ) = prepared.into_parts();
        let mut journal_writes = Vec::new();
        journal_writes
            .try_reserve_exact(planned_journal_writes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for write in planned_journal_writes {
            journal_writes.try_push(write.into_request())?;
        }
        let commit_write = planned_commit_write.into_request();
        let (planned_home_writes, planned_clean_write, clean_journal) = checkpoint.into_parts();
        let mut home_writes = Vec::new();
        home_writes
            .try_reserve_exact(planned_home_writes.len())
            .map_err(|_| Error::OutOfMemory)?;
        for write in planned_home_writes {
            home_writes.try_push(write.into_request())?;
        }
        let durable_sequence = current_epoch.sequence().next()?;
        let checkpoint_sequence = durable_sequence.next()?;
        let durable_epoch = CommittedEpoch::prepared(
            durable_sequence,
            superblock,
            durable_keys,
            durable_clusters,
            overlay,
        );
        let checkpointed_epoch = CommittedEpoch::prepared(
            checkpoint_sequence,
            superblock,
            checkpoint_keys,
            checkpoint_clusters,
            Vec::new(),
        );
        let checkpoint = CheckpointOperation {
            home_writes,
            clean_write: planned_clean_write.into_request(),
            clean_journal,
            checkpointed_epoch,
        };
        Ok(CommitReadyMutation {
            ordered_data_writes,
            journal_writes,
            commit_write,
            journal_target,
            durable_journal,
            durable_epoch,
            checkpoint,
            version_publication,
        })
    }
}

impl CommitReadyMutation {
    /// Starts ordered data I/O while sealing all later commit and publication states.
    #[must_use]
    pub fn start(self) -> StorageRequestSequence<OrderedDataDurability> {
        let durable = DurableMutation {
            durable_journal: self.durable_journal,
            durable_epoch: self.durable_epoch,
            checkpoint: self.checkpoint,
            version_publication: self.version_publication,
        };
        StorageRequestSequence::new(
            self.ordered_data_writes,
            OrderedDataDurability {
                journal_writes: self.journal_writes,
                next: JournalPayloadDurability {
                    journal_target: self.journal_target,
                    commit_write: self.commit_write,
                    durable,
                },
            },
        )
    }
}

impl DurableMutation {
    /// Publishes a durable commit using moves and fixed-table replacement only.
    ///
    /// This transition performs no allocation and cannot return an ordinary error.
    #[must_use]
    pub fn publish(
        self,
        coordinator: &mut MutationCoordinatorState,
        visibility: super::super::VisibilityLease,
    ) -> PublishedMutation {
        let _ticket = visibility.into_ticket();
        let _durable_journal = self.durable_journal;
        coordinator.journal = JournalCoordinatorState::CheckpointPending;
        coordinator.publish_versions(self.version_publication);
        PublishedMutation {
            epoch: self.durable_epoch,
            checkpoint: self.checkpoint,
        }
    }
}

impl CheckpointOperation {
    /// Starts checkpoint home-block I/O while sealing clean publication state.
    #[must_use]
    pub fn start(
        self,
        checkpoint: super::super::CheckpointLease,
    ) -> StorageRequestSequence<HomeBlockDurability> {
        let _epoch = checkpoint.into_epoch();
        let journal_target = self.clean_write.target();
        StorageRequestSequence::new(
            self.home_writes,
            HomeBlockDurability {
                clean_write: self.clean_write,
                journal_target,
                clean_journal: self.clean_journal,
                checkpointed_epoch: self.checkpointed_epoch,
            },
        )
    }
}

impl CleanJournalDurability {
    /// Publishes prebuilt clean journal and overlay-free epoch after the final flush.
    ///
    /// This transition performs no allocation and cannot return an ordinary error.
    #[must_use]
    pub fn completed(self, coordinator: &mut MutationCoordinatorState) -> CommittedEpoch {
        coordinator.journal = JournalCoordinatorState::Ready(self.clean_journal);
        self.checkpointed_epoch
    }
}

/// Maps a logical block through an ordered extent list.
pub(super) fn map_extents(extents: &[Extent], logical_block: LogicalBlock) -> BlockMapping {
    for extent in extents {
        match extent.map_logical(logical_block) {
            BlockMapping::Physical(block) => return BlockMapping::Physical(block),
            BlockMapping::Uninitialized => return BlockMapping::Uninitialized,
            BlockMapping::Hole => {}
        }
    }
    BlockMapping::Hole
}

/// Returns descriptor plus signature byte count.
/// # Errors
///
/// Returns an error when descriptor and signature lengths exceed the `u32` fs-verity field.
pub(super) fn descriptor_byte_count(signature: &[u8]) -> Result<u32> {
    u32::try_from(
        FSVERITY_DESCRIPTOR_BYTES
            .checked_add(signature.len())
            .ok_or(Error::ArithmeticOverflow)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)
}

/// Builds the ext4 post-EOF verity metadata byte image.
/// # Errors
///
/// Returns an error when the verity layout offsets are inconsistent or any metadata slice falls
/// outside the allocated image.
pub(super) fn verity_metadata_image(
    layout: Ext4VerityMetadataLayout,
    merkle_tree: &[u8],
    descriptor: &[u8; FSVERITY_DESCRIPTOR_BYTES],
    signature: &[u8],
) -> Result<Vec<u8>> {
    let metadata_bytes = usize::try_from(
        layout
            .metadata_end()
            .checked_sub(layout.merkle_tree_offset())
            .ok_or(Error::InvalidVerityMetadata)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    let mut image = memory::repeated_vec(0_u8, metadata_bytes)?;
    let tree_end = merkle_tree.len();
    image
        .get_mut(..tree_end)
        .ok_or(Error::InvalidVerityMetadata)?
        .copy_from_slice(merkle_tree);
    let descriptor_offset = usize::try_from(
        layout
            .descriptor_offset()
            .checked_sub(layout.merkle_tree_offset())
            .ok_or(Error::InvalidVerityMetadata)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    let descriptor_end = descriptor_offset
        .checked_add(FSVERITY_DESCRIPTOR_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    image
        .get_mut(descriptor_offset..descriptor_end)
        .ok_or(Error::InvalidVerityMetadata)?
        .copy_from_slice(descriptor);
    let signature_end = descriptor_end
        .checked_add(signature.len())
        .ok_or(Error::ArithmeticOverflow)?;
    image
        .get_mut(descriptor_end..signature_end)
        .ok_or(Error::InvalidVerityMetadata)?
        .copy_from_slice(signature);
    let tail_offset = usize::try_from(
        layout
            .descriptor_size_offset()
            .checked_sub(layout.merkle_tree_offset())
            .ok_or(Error::InvalidVerityMetadata)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)?;
    put_le_u32(
        &mut image,
        disk_offset(tail_offset),
        descriptor_byte_count(signature)?,
    )?;
    Ok(image)
}

/// Converts an inode kind into the directory entry file-type byte domain.
pub(super) const fn directory_entry_kind(kind: InodeKind) -> DirectoryEntryKind {
    match kind {
        InodeKind::File => DirectoryEntryKind::File,
        InodeKind::Directory => DirectoryEntryKind::Directory,
        InodeKind::Symlink => DirectoryEntryKind::Symlink,
    }
}

/// Rejects `.` and `..` as caller-supplied child names.
/// # Errors
///
/// Returns an error when `name` is `.` or `..`.
pub(super) fn reject_reserved_directory_name(name: &Ext4Name) -> Result<()> {
    if matches!(name.bytes(), b"." | b"..") {
        Err(Error::InvalidName)
    } else {
        Ok(())
    }
}
