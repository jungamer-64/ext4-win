//! Regular-file payload, size, and fs-verity mutations.

use super::*;

impl<D: BlockWriter, N: FscryptNonceGenerator, J> JournalTransaction<'_, D, N, J> {
    /// Selects a physical block for a sparse logical block using logical-cluster placement.
    /// # Errors
    ///
    /// Returns an error when cluster geometry is invalid, a matching physical cluster cannot be
    /// referenced, or a new cluster cannot be allocated.
    fn physical_block_for_hole(
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
            let BlockMapping::Physical(physical) = tree.map_logical(LogicalBlock::try_from(probe)?)
            else {
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

    /// Merges plaintext bytes into one encrypted file block and stages ciphertext.
    /// # Errors
    ///
    /// Returns an error when the plaintext base block cannot be obtained, `bytes` do not fit at
    /// `in_block`, encryption fails, or the physical write offset overflows.
    fn stage_encrypted_file_block_update(
        &mut self,
        contents_key: &FscryptContentsKey,
        logical_block: LogicalBlock,
        physical: BlockAddress,
        in_block: u64,
        bytes: &[u8],
        block_base: EncryptedBlockBase,
    ) -> Result<()> {
        let mut block = match block_base {
            EncryptedBlockBase::ExistingPlaintext => {
                self.plaintext_file_block_for_update(contents_key, logical_block, physical)?
            }
            EncryptedBlockBase::ZeroedPlaintext => memory::repeated_vec(
                0_u8,
                usize::try_from(self.volume.superblock.block_size().bytes())
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?,
        };
        let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        block
            .get_mut(start..end)
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(bytes);
        contents_key.encrypt_block(logical_block.as_u64(), &mut block)?;
        self.data_writes.try_push(RangeWrite {
            offset: self.volume.superblock.block_size().offset_of(physical)?,
            bytes: block,
        })?;
        Ok(())
    }

    /// Returns the latest plaintext image of one file block for encrypted updates.
    /// # Errors
    ///
    /// Returns an error when the block cannot be read from staged/device data or fscrypt decryption
    /// fails.
    fn plaintext_file_block_for_update(
        &self,
        contents_key: &FscryptContentsKey,
        logical_block: LogicalBlock,
        physical: BlockAddress,
    ) -> Result<Vec<u8>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_offset = block_size.offset_of(physical)?;
        let mut block = if let Some(staged) = self
            .data_writes
            .iter()
            .rev()
            .find(|write| write.offset == block_offset && write.bytes.len() == block_bytes)
        {
            memory::copied_slice(&staged.bytes)?
        } else {
            let mut bytes = memory::repeated_vec(0_u8, block_bytes)?;
            self.volume.device.read_exact_at(block_offset, &mut bytes)?;
            bytes
        };
        contents_key.decrypt_block(logical_block.as_u64(), &mut block)?;
        Ok(block)
    }

    /// Returns a block at `cluster_offset` inside a fully present physical cluster.
    /// # Errors
    ///
    /// Returns an error when `cluster_offset` is outside the cluster or physical block arithmetic
    /// overflows.
    fn physical_block_in_cluster(
        &self,
        cluster: ClusterAddress,
        cluster_offset: u64,
    ) -> Result<BlockAddress> {
        if cluster_offset >= u64::from(self.volume.superblock.blocks_in_cluster(cluster)?) {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(BlockAddress::new(
            self.volume
                .superblock
                .first_block_of_cluster(cluster)?
                .get()
                .checked_add(cluster_offset)
                .ok_or(Error::ArithmeticOverflow)?,
        ))
    }

    /// Stages a write into an inode extent stream without applying EOF limits.
    /// # Errors
    ///
    /// Returns an error when logical range arithmetic fails, the stream contains uninitialized
    /// extents, allocation fails, or a staged write slice cannot be represented.
    fn stage_inode_stream_write(
        &mut self,
        tree: &mut MutableExtentTree,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let mut completed = 0_usize;
        while completed < bytes.len() {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let block_remaining = block_size_u64
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = u64::try_from(
                bytes
                    .len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(block_remaining, total_remaining))
                .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            let logical_block = LogicalBlock::try_from(logical_block)?;
            let physical = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    physical
                }
            };
            let write_offset = self
                .volume
                .superblock
                .block_size()
                .offset_of(physical)?
                .get()
                .checked_add(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            self.data_writes.try_push(RangeWrite {
                offset: ByteOffset::new(write_offset),
                bytes: memory::copied_slice(bytes.get(completed..end).ok_or(Error::DeviceRange)?)?,
            })?;
            completed = end;
        }
        Ok(())
    }

    /// Stages a plaintext write into an encrypted inode stream without EOF limits.
    /// # Errors
    ///
    /// Returns an error when the inode has no mounted contents key, range arithmetic fails, the
    /// stream contains uninitialized extents, allocation fails, or encryption fails.
    fn stage_encrypted_inode_stream_write(
        &mut self,
        inode: &Inode,
        tree: &mut MutableExtentTree,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let contents_key = self.volume.fscrypt_contents_key_for_inode(inode)?;
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let mut completed = 0_usize;
        while completed < bytes.len() {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?;
            let block_remaining = block_size_u64
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = u64::try_from(
                bytes
                    .len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(block_remaining, total_remaining))
                .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            let logical_block = LogicalBlock::try_from(logical_block)?;
            let (physical, block_base) = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => {
                    (physical, EncryptedBlockBase::ExistingPlaintext)
                }
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    (physical, EncryptedBlockBase::ZeroedPlaintext)
                }
            };
            self.stage_encrypted_file_block_update(
                &contents_key,
                logical_block,
                physical,
                in_block,
                bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                block_base,
            )?;
            completed = end;
        }
        Ok(())
    }

    /// Extends a regular file as a sparse range.
    ///
    /// # Errors
    /// Returns an error when `new_size` would shrink the file.
    pub fn extend_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        self.require_file_size_mutation(&inode)?;
        if new_size < inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        self.require_inode_size_supported(new_size)?;
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Truncates a regular file and releases whole blocks beyond the new EOF.
    ///
    /// # Errors
    /// Returns an error when `new_size` would extend the file or root extent
    /// updates cannot fit in the inode.
    pub fn truncate_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        self.require_file_size_mutation(&inode)?;
        if new_size > inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        self.require_inode_size_supported(new_size)?;
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let mut tree = self.mutable_extent_tree(&inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let extents = memory::copied_slice(tree.extents())?;
        let keep_blocks = round_up_div(new_size.bytes(), block_size_u64)?;
        let mut updated = Vec::new();
        for extent in extents {
            let start = extent.logical_start().as_u64();
            let end = u64::from(extent.end_logical()?);
            if start >= keep_blocks {
                self.free_extent(extent, 0)?;
            } else if end > keep_blocks {
                let keep_len = u16::try_from(
                    keep_blocks
                        .checked_sub(start)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?;
                self.free_extent(extent, keep_len)?;
                updated.try_push(Extent::initialized(
                    extent.logical_start(),
                    ExtentLength::new(keep_len)?,
                    extent.physical_start(),
                ))?;
            } else {
                updated.try_push(extent)?;
            }
        }
        if new_size
            .bytes()
            .checked_rem(block_size_u64)
            .ok_or(Error::InvalidSuperblock)?
            != 0
        {
            if inode.protection().is_encrypted() {
                self.zero_encrypted_truncated_tail(
                    &inode,
                    updated.as_slice(),
                    new_size,
                    block_size_u64,
                )?;
            } else {
                self.zero_truncated_tail(updated.as_slice(), new_size, block_size_u64)?;
            }
        }
        tree.replace_extents(updated)?;
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Enables fs-verity on a plain regular file by journal-staging ext4
    /// post-EOF metadata and setting `EXT4_VERITY_FL`.
    ///
    /// # Errors
    /// Returns an error when the inode is not a plain regular file, the file
    /// cannot be read into the verification domain, metadata allocation fails,
    /// or the extent tree cannot represent the post-EOF metadata.
    pub fn enable_verity(&mut self, file: TransactionFile, enable: &FsverityEnable) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode())?;
        let mut raw_inode = self.staged_live_inode(inode_index)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(&inode)?;
        }
        if inode.protection().is_verity() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let _payload = inode.file_payload_mutation()?;

        let mut plaintext = memory::repeated_vec(0_u8, inode.size().to_usize()?)?;
        let read =
            self.volume
                .read_inode_plaintext_data(&inode, FileOffset::ZERO, &mut plaintext)?;
        if read.as_usize() != plaintext.len() {
            return Err(Error::InvalidVerityMetadata);
        }
        let merkle_tree = FsverityMerkleTree::build(
            &plaintext,
            enable.algorithm(),
            enable.block_size(),
            enable.salt(),
        )?;
        let descriptor = FsverityDescriptor::new(
            enable.algorithm(),
            enable.block_size(),
            inode.size().bytes(),
            merkle_tree.root_hash(),
            enable.salt().try_clone()?,
        )?;
        let descriptor_fixed = descriptor.to_bytes()?;
        let descriptor_bytes = descriptor_byte_count(enable.signature().bytes())?;
        let layout = Ext4VerityMetadataLayout::new(
            inode.size(),
            self.volume.superblock.block_size(),
            u64::try_from(merkle_tree.blocks().len()).map_err(|_| Error::ArithmeticOverflow)?,
            descriptor_bytes,
        )?;
        let metadata = verity_metadata_image(
            layout,
            merkle_tree.blocks(),
            &descriptor_fixed,
            enable.signature().bytes(),
        )?;

        let mut tree = self.mutable_extent_tree(&inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        if inode.protection().is_encrypted() {
            self.stage_encrypted_inode_stream_write(
                &inode,
                &mut tree,
                layout.merkle_tree_offset(),
                &metadata,
            )?;
        } else {
            self.stage_inode_stream_write(&mut tree, layout.merkle_tree_offset(), &metadata)?;
        }
        raw_inode.mark_verity()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        self.replace_live_inode(inode_index, raw_inode)?;
        Ok(())
    }

    /// Verifies file-data mutation policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when an encrypted inode lacks a mounted key, encrypted mutation is not
    /// supported for the inode kind, or the inode storage policy rejects payload mutation.
    pub(super) fn require_file_data_mutation(
        &self,
        inode: &Inode,
    ) -> Result<FilePayloadMutationCapability> {
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
            if inode.kind() != InodeKind::File || inode.protection().is_verity() {
                return Err(Error::UnsupportedEncryption);
            }
        }
        inode.file_payload_mutation()
    }

    /// Verifies file-size mutation policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when an encrypted inode lacks a mounted key, encrypted size mutation is not
    /// supported for the inode kind, or the inode storage policy rejects size mutation.
    pub(super) fn require_file_size_mutation(
        &self,
        inode: &Inode,
    ) -> Result<FileSizeMutationCapability> {
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
            if inode.kind() != InodeKind::File || inode.protection().is_verity() {
                return Err(Error::UnsupportedEncryption);
            }
        }
        inode.file_size_mutation()
    }

    /// Stages zeroes for the remainder of a partially truncated data block.
    /// # Errors
    ///
    /// Returns an error when tail offset arithmetic fails or the zero-filled write length cannot be
    /// represented.
    fn zero_truncated_tail(
        &mut self,
        extents: &[Extent],
        new_size: FileSize,
        block_size: u64,
    ) -> Result<()> {
        let logical_block = new_size
            .bytes()
            .checked_div(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let in_block = new_size
            .bytes()
            .checked_rem(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let BlockMapping::Physical(physical) =
            map_extents(extents, LogicalBlock::try_from(logical_block)?)
        else {
            return Ok(());
        };
        let zero_len = block_size
            .checked_sub(in_block)
            .ok_or(Error::ArithmeticOverflow)?;
        let offset = self
            .volume
            .superblock
            .block_size()
            .offset_of(physical)?
            .get()
            .checked_add(in_block)
            .ok_or(Error::ArithmeticOverflow)?;
        self.data_writes.try_push(RangeWrite {
            offset: ByteOffset::new(offset),
            bytes: memory::repeated_vec(
                0_u8,
                usize::try_from(zero_len).map_err(|_| Error::ArithmeticOverflow)?,
            )?,
        })?;
        Ok(())
    }

    /// Stages encrypted zeroes for the plaintext suffix of a truncated block.
    /// # Errors
    ///
    /// Returns an error when the inode has no mounted contents key, tail length arithmetic fails, or
    /// the encrypted block update cannot be staged.
    fn zero_encrypted_truncated_tail(
        &mut self,
        inode: &Inode,
        extents: &[Extent],
        new_size: FileSize,
        block_size: u64,
    ) -> Result<()> {
        let logical_block = new_size
            .bytes()
            .checked_div(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let in_block = new_size
            .bytes()
            .checked_rem(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let BlockMapping::Physical(physical) =
            map_extents(extents, LogicalBlock::try_from(logical_block)?)
        else {
            return Ok(());
        };
        let contents_key = self.volume.fscrypt_contents_key_for_inode(inode)?;
        let zero_len = usize::try_from(
            block_size
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        let zeroes = memory::repeated_vec(0_u8, zero_len)?;
        self.stage_encrypted_file_block_update(
            &contents_key,
            LogicalBlock::try_from(logical_block)?,
            physical,
            in_block,
            &zeroes,
            EncryptedBlockBase::ExistingPlaintext,
        )
    }
}
