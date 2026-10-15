//! Regular-file payload, size, and fs-verity mutations.

use super::*;

/// Allocation authority is absent from an EOF-bounded initialized overwrite.
enum FileWritePlan {
    /// Every payload byte has a validated initialized physical destination.
    Overwrite(InitializedOverwrite),
    /// Owns the allocation and extent serialization required by holes or EOF changes.
    AllocationChange(MutableExtentTree),
}

/// Private witness constructed only after the complete requested range has been mapped.
struct InitializedOverwrite {
    /// Ordered source slices and physical destinations; no inode allocation state changes.
    blocks: Vec<OverwriteBlock>,
}

/// One block-sized or partial-block destination within a validated overwrite.
struct OverwriteBlock {
    /// Encryption data-unit coordinate.
    logical: LogicalBlock,
    /// Existing initialized storage block.
    physical: BlockAddress,
    /// Byte position inside the physical block.
    in_block: u64,
    /// Exact slice in the original write payload.
    source: core::ops::Range<usize>,
}

impl MutationResolvePass<'_, '_, '_> {
    /// Resolves the entire overwrite before staging any data or acquiring allocation authority.
    /// # Errors
    /// Returns selected-node validation, I/O, range, or allocation failures.
    fn prepare_file_write(
        &mut self,
        inode: &Inode,
        offset: FileOffset,
        len: usize,
    ) -> Result<FileWritePlan> {
        if offset.checked_add_len(len)?.bytes() > inode.size().bytes() {
            return Ok(FileWritePlan::AllocationChange(
                self.mutation.mutable_extent_tree(inode)?,
            ));
        }
        let block_size = self.mutation.volume.superblock.block_size();
        let width = u64::from(block_size.bytes());
        let mut cursor = ExtentMappingCursor::new(
            inode.extent_root()?,
            block_size,
            self.mutation.volume.extent_tree_context(inode),
        )?;
        let mut blocks = Vec::new();
        let mut completed = 0_usize;
        while completed < len {
            let position = offset
                .bytes()
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical = LogicalBlock::try_from(
                position
                    .checked_div(width)
                    .ok_or(Error::InvalidSuperblock)?,
            )?;
            let in_block = position
                .checked_rem(width)
                .ok_or(Error::InvalidSuperblock)?;
            let chunk = usize::try_from(
                width
                    .checked_sub(in_block)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?
            .min(
                len.checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            let physical = {
                let mut source = TransactionExtentSource {
                    device: &mut self.mutation.volume.device,
                    staged: &self.mutation.extent_updates,
                    block_size,
                };
                match cursor.map(logical, &mut source)? {
                    BlockMapping::Physical(physical) => physical,
                    BlockMapping::Uninitialized | BlockMapping::Hole => {
                        return Ok(FileWritePlan::AllocationChange(
                            self.mutation.mutable_extent_tree(inode)?,
                        ));
                    }
                }
            };
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;
            blocks.try_push(OverwriteBlock {
                logical,
                physical,
                in_block,
                source: completed..end,
            })?;
            completed = end;
        }
        Ok(FileWritePlan::Overwrite(InitializedOverwrite { blocks }))
    }

    /// Consumes mapped destinations without modifying or serializing the inode's extent root.
    /// # Errors
    /// Returns payload-copy, encryption, partial-block read, or staging allocation failures.
    fn stage_initialized_overwrite(
        &mut self,
        inode: &Inode,
        plan: InitializedOverwrite,
        bytes: &[u8],
    ) -> Result<()> {
        let persistence = inode.data_persistence();
        let key = if inode.protection().is_encrypted() {
            Some(
                self.mutation
                    .volume
                    .fscrypt_contents_key_for_inode(inode, self.crypto)?,
            )
        } else {
            None
        };
        let block_size = self.mutation.volume.superblock.block_size();
        for block in plan.blocks {
            let payload = bytes.get(block.source).ok_or(Error::DeviceRange)?;
            if let Some(key) = &key {
                let base = if block.in_block == 0
                    && payload.len()
                        == usize::try_from(block_size.bytes())
                            .map_err(|_| Error::ArithmeticOverflow)?
                {
                    EncryptedBlockBase::ZeroedPlaintext
                } else {
                    EncryptedBlockBase::ExistingPlaintext
                };
                self.stage_encrypted_file_block_update(
                    persistence,
                    key,
                    block.logical,
                    block.physical,
                    block.in_block,
                    payload,
                    base,
                )?;
            } else {
                let offset = block_size
                    .offset_of(block.physical)?
                    .get()
                    .checked_add(block.in_block)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.mutation.stage_file_write(
                    persistence,
                    RangeWrite {
                        offset: ByteOffset::new(offset),
                        bytes: memory::copied_slice(payload)?,
                    },
                )?;
            }
        }
        Ok(())
    }
    /// Writes bytes into a regular file and extends EOF when the range reaches beyond it.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file, mutation policy rejects payload or
    /// size changes, the target size is unsupported, allocation fails, or the updated root extent
    /// set cannot fit in the inode.
    pub fn write_file_range(
        &mut self,
        file: TransactionFile,
        offset: FileOffset,
        bytes: &[u8],
    ) -> Result<()> {
        self.edit(|pass| {
            if bytes.is_empty() {
                return Ok(());
            }
            let end_offset = offset.checked_add_len(bytes.len())?;
            let new_size = FileSize::from_bytes(end_offset.bytes());
            let encoded_size = pass
                .mutation
                .volume
                .superblock
                .inode_data_encoding()
                .encode_file_size(new_size)?;
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            if inode.kind() != InodeKind::File {
                return Err(Error::WrongInodeKind);
            }
            pass.require_file_data_mutation(&inode)?;
            let extends_file = new_size > inode.size();
            let encoded_new_size = if extends_file {
                pass.require_file_size_mutation(&inode)?;
                Some(encoded_size)
            } else {
                None
            };

            let plan = pass.prepare_file_write(&inode, offset, bytes.len())?;
            match plan {
                FileWritePlan::Overwrite(plan) => {
                    pass.stage_initialized_overwrite(&inode, plan, bytes)?
                }
                FileWritePlan::AllocationChange(mut tree) => {
                    if offset.bytes() > inode.size().bytes() {
                        pass.stage_visible_extension_gap(&inode, &tree, inode.size(), offset)?;
                    }
                    if inode.protection().is_encrypted() {
                        pass.stage_encrypted_inode_stream_write(
                            &inode,
                            &mut tree,
                            offset.bytes(),
                            bytes,
                        )?;
                    } else {
                        pass.stage_inode_stream_write(
                            inode.data_persistence(),
                            &mut tree,
                            offset.bytes(),
                            bytes,
                        )?;
                    }
                    pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
                }
            }
            if let Some(encoded_new_size) = encoded_new_size {
                raw_inode.set_encoded_size(encoded_new_size)?;
            }
            raw_inode.touch_contents(pass.now)?;
            pass.mutation.replace_live_inode(inode_index, raw_inode)?;
            Ok(())
        })
    }

    /// Reserves zero-readable unwritten extents through an allocation bound without changing EOF.
    /// Existing payload blocks retain their contents. A later write initializes only its blocks
    /// and commits their full zero-based contents before publishing initialized extent metadata.
    ///
    /// # Errors
    /// Returns protected mutation, unrepresentable range, allocation, or extent serialization failures.
    pub fn reserve_file_allocation(
        &mut self,
        file: TransactionFile,
        bound: FileAllocationSize,
    ) -> Result<()> {
        self.edit(|pass| {
            if bound.bytes() == 0 {
                return Ok(());
            }
            pass.mutation
                .volume
                .superblock
                .inode_data_encoding()
                .encode_file_size(FileSize::from_bytes(bound.bytes()))?;
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            pass.require_file_data_mutation(&inode)?;
            let mut tree = pass.mutation.mutable_extent_tree(&inode)?;
            let block_size = pass.mutation.volume.superblock.block_size();
            let width =
                usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
            let mut offset = FileOffset::ZERO;
            while offset.bytes() < bound.bytes() {
                let logical = offset.logical_block(block_size)?;
                if matches!(tree.map_logical(logical), BlockMapping::Hole) {
                    let physical = pass.physical_block_for_hole(&tree, logical)?;
                    tree.insert_uninitialized(logical, physical)?;
                }
                offset = offset.checked_add_len(width)?;
            }
            pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
            raw_inode.touch_metadata(pass.now)?;
            pass.mutation.replace_live_inode(inode_index, raw_inode)?;
            Ok(())
        })
    }

    /// Sets block-rounded allocated storage while preserving EOF and existing visible payload.
    /// The caller must first truncate EOF when requesting an allocation bound below it.
    ///
    /// # Errors
    /// Returns invalid range below EOF, protected mutation, allocation, or extent staging failures.
    pub fn set_file_allocation(
        &mut self,
        file: TransactionFile,
        bound: FileAllocationSize,
    ) -> Result<()> {
        self.edit(|pass| {
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            pass.require_file_data_mutation(&inode)?;
            if bound.bytes() < inode.size().bytes() {
                return Err(Error::InvalidWriteRange);
            }
            pass.mutation
                .volume
                .superblock
                .inode_data_encoding()
                .encode_file_size(FileSize::from_bytes(bound.bytes()))?;
            let mut tree = pass.mutation.mutable_extent_tree(&inode)?;
            pass.retain_file_allocation(&mut tree, bound)?;
            pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
            raw_inode.touch_metadata(pass.now)?;
            pass.mutation.replace_live_inode(inode_index, raw_inode)?;
            pass.reserve_file_allocation(file, bound)
        })
    }

    /// Releases extent tails beyond a block-rounded byte bound, preserving initialization state.
    /// # Errors
    /// Returns extent arithmetic, allocation-accounting, or fallible tree-copy failures.
    fn retain_file_allocation(
        &mut self,
        tree: &mut MutableExtentTree,
        bound: FileAllocationSize,
    ) -> Result<()> {
        let block_size = u64::from(self.mutation.volume.superblock.block_size().bytes());
        let keep_blocks = round_up_div(bound.bytes(), block_size)?;
        let extents = memory::copied_slice(tree.extents())?;
        let mut updated = Vec::new();
        for extent in extents {
            let start = extent.logical_start().as_u64();
            let end = extent.end_logical();
            if start >= keep_blocks {
                self.mutation.free_extent(extent, 0)?;
            } else if end > keep_blocks {
                let keep_len = u16::try_from(
                    keep_blocks
                        .checked_sub(start)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?;
                self.mutation.free_extent(extent, keep_len)?;
                let length = ExtentLength::new(keep_len)?;
                let kept = match extent.initialization() {
                    ExtentInitialization::Initialized => {
                        Extent::initialized(extent.logical_start(), length, extent.physical_start())
                    }
                    ExtentInitialization::Uninitialized => Extent::uninitialized(
                        extent.logical_start(),
                        length,
                        extent.physical_start(),
                    ),
                };
                updated.try_push(kept)?;
            } else {
                updated.try_push(extent)?;
            }
        }
        tree.replace_extents(updated)
    }

    /// Stages zeroes for existing allocated blocks that become visible inside a sparse extension.
    /// # Errors
    ///
    /// Returns an error when extent arithmetic overflows, encryption fails, or zero writes cannot
    /// be staged.
    fn stage_visible_extension_gap(
        &mut self,
        inode: &Inode,
        tree: &MutableExtentTree,
        old_size: FileSize,
        write_offset: FileOffset,
    ) -> Result<()> {
        let persistence = inode.data_persistence();
        let gap_start = old_size.bytes();
        let gap_end = write_offset.bytes();
        if gap_start >= gap_end {
            return Ok(());
        }
        let block_size = u64::from(self.mutation.volume.superblock.block_size().bytes());
        let encrypted_contents_key = if inode.protection().is_encrypted() {
            Some(
                self.mutation
                    .volume
                    .fscrypt_contents_key_for_inode(inode, self.crypto)?,
            )
        } else {
            None
        };

        for extent in tree.extents().iter().copied() {
            if extent.initialization() == ExtentInitialization::Uninitialized {
                continue;
            }
            let extent_start = extent
                .logical_start()
                .as_u64()
                .checked_mul(block_size)
                .ok_or(Error::ArithmeticOverflow)?;
            let extent_len = extent
                .len()
                .as_u64()
                .checked_mul(block_size)
                .ok_or(Error::ArithmeticOverflow)?;
            let extent_end = extent_start
                .checked_add(extent_len)
                .ok_or(Error::ArithmeticOverflow)?;
            let zero_start = core::cmp::max(gap_start, extent_start);
            let zero_end = core::cmp::min(gap_end, extent_end);
            if zero_start < zero_end {
                self.stage_zero_visible_extent_range(
                    persistence,
                    extent,
                    zero_start,
                    zero_end,
                    block_size,
                    encrypted_contents_key.as_ref(),
                )?;
            }
        }
        Ok(())
    }

    /// Stages zeroes for one initialized extent byte range.
    /// # Errors
    ///
    /// Returns an error when logical block arithmetic overflows, the extent does not map the
    /// selected logical block, encryption fails, or zero writes cannot be staged.
    fn stage_zero_visible_extent_range(
        &mut self,
        persistence: FileDataPersistence,
        extent: Extent,
        start: u64,
        end: u64,
        block_size: u64,
        encrypted_contents_key: Option<&FscryptContentsKey>,
    ) -> Result<()> {
        let mut position = start;
        while position < end {
            let logical = position
                .checked_div(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let block_end = logical
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?
                .checked_mul(block_size)
                .ok_or(Error::ArithmeticOverflow)?;
            let range_end = core::cmp::min(end, block_end);
            let len = usize::try_from(
                range_end
                    .checked_sub(position)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let logical_block = LogicalBlock::try_from(logical)?;
            let BlockMapping::Physical(physical) = extent.map_logical(logical_block) else {
                return Err(Error::InvalidExtentTree);
            };
            self.stage_zero_file_block_range(
                persistence,
                logical_block,
                physical,
                in_block,
                len,
                encrypted_contents_key,
            )?;
            position = range_end;
        }
        Ok(())
    }

    /// Stages zeroes inside one initialized physical file block.
    /// # Errors
    ///
    /// Returns an error when the physical offset overflows, allocation for zero bytes fails, or
    /// encrypted block staging fails.
    fn stage_zero_file_block_range(
        &mut self,
        persistence: FileDataPersistence,
        logical_block: LogicalBlock,
        physical: BlockAddress,
        in_block: u64,
        len: usize,
        encrypted_contents_key: Option<&FscryptContentsKey>,
    ) -> Result<()> {
        let zeroes = memory::repeated_vec(0_u8, len)?;
        if let Some(contents_key) = encrypted_contents_key {
            return self.stage_encrypted_file_block_update(
                persistence,
                contents_key,
                logical_block,
                physical,
                in_block,
                zeroes.as_slice(),
                EncryptedBlockBase::ExistingPlaintext,
            );
        }
        let write_offset = self
            .mutation
            .volume
            .superblock
            .block_size()
            .offset_of(physical)?
            .get()
            .checked_add(in_block)
            .ok_or(Error::ArithmeticOverflow)?;
        self.mutation.stage_file_write(
            persistence,
            RangeWrite {
                offset: ByteOffset::new(write_offset),
                bytes: zeroes,
            },
        )?;
        Ok(())
    }

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
        let blocks_per_cluster = u64::from(
            self.mutation
                .volume
                .superblock
                .blocks_per_cluster()
                .as_u32(),
        );
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
            let cluster = self.mutation.volume.superblock.cluster_of_block(physical)?;
            let physical = self.physical_block_in_cluster(cluster, cluster_offset)?;
            self.mutation.record_cluster_reference_delta(cluster, 1)?;
            return Ok(physical);
        }

        let first_block = self.mutation.allocate_cluster()?;
        let cluster = self
            .mutation
            .volume
            .superblock
            .cluster_of_block(first_block)?;
        self.physical_block_in_cluster(cluster, cluster_offset)
    }

    /// Merges plaintext bytes into one encrypted file block and stages ciphertext.
    /// # Errors
    ///
    /// Returns an error when the plaintext base block cannot be obtained, `bytes` do not fit at
    /// `in_block`, encryption fails, or the physical write offset overflows.
    #[expect(
        clippy::too_many_arguments,
        reason = "the encryption key and logical coordinate, physical byte range, base image and inode persistence are independent inputs to one encrypted-block update"
    )]
    fn stage_encrypted_file_block_update(
        &mut self,
        persistence: FileDataPersistence,
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
                usize::try_from(self.mutation.volume.superblock.block_size().bytes())
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?,
        };
        let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        memory::copy_exact(block.get_mut(start..end).ok_or(Error::DeviceRange)?, bytes)?;
        contents_key.encrypt_block(logical_block.as_u64(), &mut block, self.crypto)?;
        self.mutation.stage_file_write(
            persistence,
            RangeWrite {
                offset: self
                    .mutation
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(physical)?,
                bytes: block,
            },
        )?;
        Ok(())
    }

    /// Returns the latest plaintext image of one file block for encrypted updates.
    /// # Errors
    ///
    /// Returns an error when the block cannot be read from staged/device data or fscrypt decryption
    /// fails.
    fn plaintext_file_block_for_update(
        &mut self,
        contents_key: &FscryptContentsKey,
        logical_block: LogicalBlock,
        physical: BlockAddress,
    ) -> Result<Vec<u8>> {
        let mut block = self.mutation.file_block_bytes(physical)?;
        contents_key.decrypt_block(logical_block.as_u64(), &mut block, self.crypto)?;
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
        if cluster_offset >= u64::from(self.mutation.volume.superblock.blocks_in_cluster(cluster)?)
        {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(BlockAddress::new(
            self.mutation
                .volume
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
    /// Returns an error when logical range arithmetic fails, allocation fails, or a staged write slice cannot be represented.
    fn stage_inode_stream_write(
        &mut self,
        persistence: FileDataPersistence,
        tree: &mut MutableExtentTree,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let block_size_u64 = u64::from(self.mutation.volume.superblock.block_size().bytes());
        let block_size = usize::try_from(block_size_u64).map_err(|_| Error::ArithmeticOverflow)?;
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
            match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => {
                    let write_offset = self
                        .mutation
                        .volume
                        .superblock
                        .block_size()
                        .offset_of(physical)?
                        .get()
                        .checked_add(in_block)
                        .ok_or(Error::ArithmeticOverflow)?;
                    self.mutation.stage_file_write(
                        persistence,
                        RangeWrite {
                            offset: ByteOffset::new(write_offset),
                            bytes: memory::copied_slice(
                                bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                            )?,
                        },
                    )?;
                }
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    let physical = if tree.allocated_block(logical_block)?.is_some() {
                        tree.initialize_block(logical_block)?
                    } else {
                        let physical = self.physical_block_for_hole(tree, logical_block)?;
                        tree.insert_or_extend_initialized(logical_block, physical)?;
                        physical
                    };
                    let mut block = memory::repeated_vec(0_u8, block_size)?;
                    let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                    let block_end = start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                    memory::copy_exact(
                        block.get_mut(start..block_end).ok_or(Error::DeviceRange)?,
                        bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                    )?;
                    self.mutation.stage_file_write(
                        persistence,
                        RangeWrite {
                            offset: self
                                .mutation
                                .volume
                                .superblock
                                .block_size()
                                .offset_of(physical)?,
                            bytes: block,
                        },
                    )?;
                }
            };
            completed = end;
        }
        Ok(())
    }

    /// Stages a plaintext write into an encrypted inode stream without EOF limits.
    /// # Errors
    ///
    /// Returns an error when the inode has no mounted contents key, range arithmetic fails, the
    /// allocation fails, or encryption fails.
    fn stage_encrypted_inode_stream_write(
        &mut self,
        inode: &Inode,
        tree: &mut MutableExtentTree,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        let persistence = inode.data_persistence();
        if bytes.is_empty() {
            return Ok(());
        }
        let contents_key = self
            .mutation
            .volume
            .fscrypt_contents_key_for_inode(inode, self.crypto)?;
        let block_size_u64 = u64::from(self.mutation.volume.superblock.block_size().bytes());
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
                BlockMapping::Uninitialized => (
                    tree.initialize_block(logical_block)?,
                    EncryptedBlockBase::ZeroedPlaintext,
                ),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    (physical, EncryptedBlockBase::ZeroedPlaintext)
                }
            };
            self.stage_encrypted_file_block_update(
                persistence,
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
    /// Returns an error when `new_size` would shrink the file, existing initialized storage cannot
    /// be zeroed before becoming visible, or the inode metadata cannot be staged.
    pub fn extend_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        self.edit(|pass| {
            let encoded_size = pass
                .mutation
                .volume
                .superblock
                .inode_data_encoding()
                .encode_file_size(new_size)?;
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            pass.require_file_size_mutation(&inode)?;
            if new_size < inode.size() {
                return Err(Error::InvalidWriteRange);
            }
            if new_size > inode.size() {
                let tree = pass.mutation.mutable_extent_tree(&inode)?;
                pass.stage_visible_extension_gap(
                    &inode,
                    &tree,
                    inode.size(),
                    FileOffset::from_bytes(new_size.bytes()),
                )?;
            }
            raw_inode.set_encoded_size(encoded_size)?;
            raw_inode.touch_contents(pass.now)?;
            pass.mutation.replace_live_inode(inode_index, raw_inode)?;
            Ok(())
        })
    }

    /// Truncates a regular file and releases whole blocks beyond the new EOF.
    ///
    /// # Errors
    /// Returns an error when `new_size` would extend the file or root extent
    /// updates cannot fit in the inode.
    pub fn truncate_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        self.edit(|pass| {
            let encoded_size = pass
                .mutation
                .volume
                .superblock
                .inode_data_encoding()
                .encode_file_size(new_size)?;
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            pass.require_file_size_mutation(&inode)?;
            if new_size > inode.size() {
                return Err(Error::InvalidWriteRange);
            }
            let block_size_u64 = u64::from(pass.mutation.volume.superblock.block_size().bytes());
            let mut tree = pass.mutation.mutable_extent_tree(&inode)?;
            pass.retain_file_allocation(
                &mut tree,
                FileAllocationSize::from_bytes(new_size.bytes()),
            )?;
            if new_size
                .bytes()
                .checked_rem(block_size_u64)
                .ok_or(Error::InvalidSuperblock)?
                != 0
            {
                if inode.protection().is_encrypted() {
                    pass.zero_encrypted_truncated_tail(
                        &inode,
                        tree.extents(),
                        new_size,
                        block_size_u64,
                    )?;
                } else {
                    pass.zero_truncated_tail(
                        inode.data_persistence(),
                        tree.extents(),
                        new_size,
                        block_size_u64,
                    )?;
                }
            }
            raw_inode.set_encoded_size(encoded_size)?;
            raw_inode.touch_contents(pass.now)?;
            pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
            pass.mutation.replace_live_inode(inode_index, raw_inode)?;
            Ok(())
        })
    }

    /// Enables fs-verity on a regular file by journal-staging ext4
    /// post-EOF metadata and setting `EXT4_VERITY_FL`.
    ///
    /// # Errors
    /// Returns an error when the filesystem lacks the verity feature, the inode is protected from
    /// mutation, the staged plaintext cannot be read, or the post-EOF metadata cannot be allocated
    /// or represented. Merkle data covers the current transaction's file image, including writes
    /// and size changes preceding this call.
    pub fn enable_verity(&mut self, file: TransactionFile, enable: &FsverityEnable) -> Result<()> {
        self.edit(|pass| {
            pass.mutation.volume.superblock.require_verity()?;
            let inode_index = pass.mutation.ensure_inode_update(file.inode())?;
            let mut raw_inode = pass.mutation.staged_live_inode(inode_index)?;
            let inode = raw_inode.parse()?;
            if inode.kind() != InodeKind::File {
                return Err(Error::WrongInodeKind);
            }
            if inode.protection().is_encrypted() {
                pass.mutation.volume.require_encryption_key(&inode)?;
            }
            if inode.protection().is_verity() {
                return Err(Error::UnsupportedInodeMutation);
            }
            if enable.block_size().bytes() > pass.mutation.volume.superblock.block_size().bytes() {
                return Err(Error::InvalidVerityMetadata);
            }
            let _payload = inode.file_payload_mutation()?;

            let mut tree = pass.mutation.mutable_extent_tree(&inode)?;
            pass.retain_file_allocation(
                &mut tree,
                FileAllocationSize::from_bytes(inode.size().bytes()),
            )?;
            let plaintext = pass.staged_file_plaintext(&inode, &tree)?;
            let merkle_tree = FsverityMerkleTree::build(
                &plaintext,
                enable.algorithm(),
                enable.block_size(),
                enable.salt(),
                pass.crypto,
            )?;
            let descriptor = FsverityDescriptor::new(
                enable.algorithm(),
                enable.block_size(),
                inode.size().bytes(),
                merkle_tree.root_hash(),
                enable.salt().try_clone()?,
            )?;
            let descriptor_image = descriptor.to_bytes(enable.signature())?;
            let descriptor_bytes =
                u32::try_from(descriptor_image.len()).map_err(|_| Error::ArithmeticOverflow)?;
            let layout = Ext4VerityMetadataLayout::new(
                inode.size(),
                pass.mutation.volume.superblock.block_size(),
                u64::try_from(merkle_tree.blocks().len()).map_err(|_| Error::ArithmeticOverflow)?,
                descriptor_bytes,
            )?;
            let metadata = verity_metadata_image(layout, merkle_tree.blocks(), &descriptor_image)?;
            if inode.protection().is_encrypted() {
                pass.stage_encrypted_inode_stream_write(
                    &inode,
                    &mut tree,
                    layout.merkle_tree_offset(),
                    &metadata,
                )?;
            } else {
                pass.stage_inode_stream_write(
                    inode.data_persistence(),
                    &mut tree,
                    layout.merkle_tree_offset(),
                    &metadata,
                )?;
            }
            raw_inode.mark_verity()?;
            raw_inode.touch_metadata(pass.now)?;
            pass.mutation.stage_extent_tree(&mut raw_inode, tree)?;
            pass.mutation.replace_live_inode(inode_index, raw_inode)?;
            Ok(())
        })
    }

    /// Reads the staged file image, preserving sparse and unwritten zero semantics before
    /// decrypting initialized blocks. Bytes beyond the staged EOF never enter the Merkle input.
    /// # Errors
    /// Returns allocation, mapping, staged block read or decryption failures.
    fn staged_file_plaintext(
        &mut self,
        inode: &Inode,
        tree: &MutableExtentTree,
    ) -> Result<Vec<u8>> {
        let mut plaintext = memory::repeated_vec(0_u8, inode.size().to_usize()?)?;
        let block_size = usize::try_from(self.mutation.volume.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let key = if inode.protection().is_encrypted() {
            Some(
                self.mutation
                    .volume
                    .fscrypt_contents_key_for_inode(inode, self.crypto)?,
            )
        } else {
            None
        };
        let mut extents = tree.extents().iter().peekable();
        let mut remaining = plaintext.as_mut_slice();
        let mut index = 0_u64;
        while !remaining.is_empty() {
            let len = remaining.len().min(block_size);
            let (target, next) = remaining
                .split_at_mut_checked(len)
                .ok_or(Error::DeviceRange)?;
            let logical = LogicalBlock::try_from(index)?;
            while extents
                .peek()
                .is_some_and(|extent| extent.end_logical() <= logical.as_u64())
            {
                extents.next();
            }
            let mapping = extents
                .peek()
                .map_or(BlockMapping::Hole, |extent| extent.map_logical(logical));
            if let BlockMapping::Physical(physical) = mapping {
                let mut block = self.mutation.file_block_bytes(physical)?;
                if let Some(key) = &key {
                    key.decrypt_block(logical.as_u64(), &mut block, self.crypto)?;
                }
                let len = target.len();
                memory::copy_exact(target, block.get(..len).ok_or(Error::DeviceRange)?)?;
            }
            remaining = next;
            index = index.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(plaintext)
    }

    /// Verifies file-data mutation policy with mount-scoped fscrypt keys.
    /// # Errors
    ///
    /// Returns an error when an encrypted inode lacks a mounted key, encrypted mutation is not
    /// supported for the inode kind, or the inode storage policy rejects payload mutation.
    pub(super) fn require_file_data_mutation(
        &mut self,
        inode: &Inode,
    ) -> Result<FilePayloadMutationCapability> {
        if inode.protection().is_encrypted() {
            self.mutation.volume.require_encryption_key(inode)?;
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
        &mut self,
        inode: &Inode,
    ) -> Result<FileSizeMutationCapability> {
        if inode.protection().is_encrypted() {
            self.mutation.volume.require_encryption_key(inode)?;
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
        persistence: FileDataPersistence,
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
            .mutation
            .volume
            .superblock
            .block_size()
            .offset_of(physical)?
            .get()
            .checked_add(in_block)
            .ok_or(Error::ArithmeticOverflow)?;
        self.mutation.stage_file_write(
            persistence,
            RangeWrite {
                offset: ByteOffset::new(offset),
                bytes: memory::repeated_vec(
                    0_u8,
                    usize::try_from(zero_len).map_err(|_| Error::ArithmeticOverflow)?,
                )?,
            },
        )?;
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
        let persistence = inode.data_persistence();
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
        let contents_key = self
            .mutation
            .volume
            .fscrypt_contents_key_for_inode(inode, self.crypto)?;
        let zero_len = usize::try_from(
            block_size
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        let zeroes = memory::repeated_vec(0_u8, zero_len)?;
        self.stage_encrypted_file_block_update(
            persistence,
            &contents_key,
            LogicalBlock::try_from(logical_block)?,
            physical,
            in_block,
            &zeroes,
            EncryptedBlockBase::ExistingPlaintext,
        )
    }
}
