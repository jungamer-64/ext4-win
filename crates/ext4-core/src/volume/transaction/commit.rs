//! Transaction commit serialization and journal handoff.

use super::*;

impl<D: BlockStorage, N: FscryptNonceGenerator, J> JournalTransaction<'_, D, N, J> {
    /// Serializes all staged metadata mutations into byte-range writes.
    /// # Errors
    ///
    /// Returns an error when staged bitmap, directory, extent, xattr, group, superblock, or inode
    /// metadata cannot be serialized to device byte ranges.
    async fn metadata_writes(&mut self) -> Result<Vec<RangeWrite>> {
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
            )
            .await?;
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
                bytes: self.updated_superblock_bytes().await?,
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
    async fn metadata_blocks(&mut self) -> Result<Vec<MetadataBlock>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_bytes_u64 = u64::from(block_size.bytes());
        let mut blocks = Vec::new();

        for write in self.metadata_writes().await? {
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
                    .read_exact_at(block_size.offset_of(block)?, &mut bytes)
                    .await?;
                blocks.try_push(MetadataBlock::new(block, bytes))?;
                blocks
                    .len()
                    .checked_sub(1)
                    .ok_or(Error::ArithmeticOverflow)?
            };
            blocks
                .get_mut(index)
                .ok_or(Error::InvalidSuperblock)?
                .bytes_mut()
                .get_mut(in_block..end)
                .ok_or(Error::DeviceRange)?
                .copy_from_slice(&write.bytes);
        }

        Ok(blocks)
    }

    /// Writes ordered file data before the metadata transaction is committed.
    /// # Errors
    ///
    /// Returns an error when any ordered data write or the following device flush fails.
    async fn write_ordered_data(&mut self) -> Result<()> {
        for write in &self.data_writes {
            self.volume
                .device
                .write_exact_at(write.offset, write.bytes.as_slice())
                .await?;
        }
        self.volume.device.flush().await
    }

    /// Applies accumulated free-count deltas to a superblock image.
    /// # Errors
    ///
    /// Returns an error when the primary superblock cannot be read, free counters underflow or
    /// overflow, the label cannot be written, or the checksum cannot be refreshed.
    async fn updated_superblock_bytes(&mut self) -> Result<Vec<u8>> {
        let mut bytes = memory::repeated_vec(0_u8, 1024)?;
        self.volume
            .device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut bytes)
            .await?;
        let current = u64::from(le_u32(
            &bytes,
            disk_offset(SUPERBLOCK_FREE_BLOCKS_LO_OFFSET),
        )?) | if self.volume.superblock.descriptor_layout().has_high_fields() {
            u64::from(le_u32(
                &bytes,
                disk_offset(SUPERBLOCK_FREE_BLOCKS_HI_OFFSET),
            )?) << 32
        } else {
            0
        };
        let raw_delta = self.free_clusters_delta.as_i64();
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
            disk_offset(SUPERBLOCK_FREE_BLOCKS_LO_OFFSET),
            u32::try_from(updated & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.volume.superblock.descriptor_layout().has_high_fields() {
            put_le_u32(
                &mut bytes,
                disk_offset(SUPERBLOCK_FREE_BLOCKS_HI_OFFSET),
                u32::try_from(updated >> 32).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
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

impl<D: BlockStorage, N: FscryptNonceGenerator> JournalTransaction<'_, D, N, InternalJournal> {
    /// Commits staged data and metadata through the internal journal.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub async fn commit(mut self) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let metadata_blocks = self.metadata_blocks().await?;
        let (clusters, superblock) = self.committed_cluster_state()?;
        self.volume
            .state
            .journal
            .journal
            .ensure_transaction_capacity(metadata_blocks.len())?;
        self.write_ordered_data().await?;

        let volume = self.volume;
        volume
            .state
            .journal
            .journal
            .commit_internal(&mut volume.device, block_size, &metadata_blocks)
            .await?;
        volume.state.clusters = clusters;
        volume.superblock = superblock;
        Ok(())
    }
}

impl<D: BlockStorage, N: FscryptNonceGenerator, J: BlockStorage>
    JournalTransaction<'_, D, N, ExternalJournal<J>>
{
    /// Commits staged data and metadata through the external journal device.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub async fn commit(mut self) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let metadata_blocks = self.metadata_blocks().await?;
        let (clusters, superblock) = self.committed_cluster_state()?;
        self.volume
            .state
            .journal
            .journal
            .ensure_transaction_capacity(metadata_blocks.len())?;
        self.write_ordered_data().await?;

        let volume = self.volume;
        let journal = &mut volume.state.journal;
        journal
            .journal
            .commit_external(
                &mut volume.device,
                &mut journal.device,
                block_size,
                &metadata_blocks,
            )
            .await?;
        volume.state.clusters = clusters;
        volume.superblock = superblock;
        Ok(())
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
