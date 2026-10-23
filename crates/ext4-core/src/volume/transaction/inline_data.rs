//! Inode-body payload mutation and atomic publication of extent conversions.
use super::*;
use crate::disk_format::inode::InodeInlineData;

impl MetadataMutation<'_, '_> {
    /// Selects compact storage only when the filesystem advertises it and the complete body fits.
    /// # Errors
    /// Propagates malformed xattrs and physical allocation failure.
    pub(super) fn initialize_inline_file(&mut self, raw: &mut LiveInodeRecord) -> Result<()> {
        if !self.volume.superblock.supports_inline_data()
            || raw.parse()?.protection().is_encrypted()
        {
            return Ok(());
        }
        let mut set = self.xattr_set_for_raw_inode(raw)?;
        set.set_inline_data(XattrValue::new(&[])?);
        let body = match xattr_storage::serialize_inline_xattrs(
            &set,
            raw.writable_inline_xattr_region()?.len(),
        ) {
            Ok(body) => body,
            Err(Error::NoSpace) => return Ok(()),
            Err(error) => return Err(error),
        };
        raw.initialize_inline_storage()?;
        memory::copy_exact(raw.writable_inline_xattr_region()?, &body)?;
        self.store_xattr_set(raw, set)
    }
    /// Edits the two inline directory regions without allowing a record to span them.
    /// None leaves the inode unchanged and requires conversion to ordinary directory blocks.
    /// # Errors
    /// Propagates malformed entries, failed edits or physical allocation failure.
    pub(super) fn edit_inline_directory<T>(
        &mut self,
        raw: &mut LiveInodeRecord,
        edit: impl FnOnce(&mut InodeId, &mut DirectoryBlock, &mut DirectoryBlock) -> Result<T>,
    ) -> Result<Option<T>> {
        let inode = raw.parse()?;
        let InodeStorage::InlineData(InodeInlineData::Directory {
            parent,
            first,
            second,
        }) = inode.storage()
        else {
            return Ok(None);
        };
        let mut set = self.xattr_set_for_raw_inode(raw)?;
        let capacity = match xattr_storage::inline_data_capacity(
            &set,
            raw.writable_inline_xattr_region()?.len(),
        ) {
            Ok(capacity) => capacity,
            Err(Error::NoSpace) => return Ok(None),
            Err(error) => return Err(error),
        };
        let capacity = if capacity < 8 { 0 } else { capacity };
        if capacity < second.len() {
            return Ok(None);
        }
        let mut parent = *parent;
        let mut first = DirectoryBlock::new(memory::copied_slice(first)?, DirectoryChecksum::None);
        let mut second = if capacity == 0 {
            DirectoryBlock::new(Vec::new(), DirectoryChecksum::None)
        } else {
            DirectoryBlock::from_entries(
                capacity,
                DirectoryChecksum::None,
                &RawDirectoryEntry::parse_all(second)?,
            )?
        };
        let result = match edit(&mut parent, &mut first, &mut second) {
            Ok(result) => result,
            Err(Error::NoSpace) => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut prefix = [0; 60];
        memory::copy_exact(
            prefix.get_mut(..4).ok_or(Error::DeviceRange)?,
            &parent.as_u32().to_le_bytes(),
        )?;
        memory::copy_exact(
            prefix.get_mut(4..).ok_or(Error::DeviceRange)?,
            first.bytes(),
        )?;
        set.set_inline_data(XattrValue::new(second.bytes())?);
        let body = xattr_storage::serialize_inline_xattrs(
            &set,
            raw.writable_inline_xattr_region()?.len(),
        )?;
        let length = 60_usize
            .checked_add(second.bytes().len())
            .ok_or(Error::ArithmeticOverflow)?;
        let size = self
            .volume
            .superblock
            .inode_data_encoding()
            .encode_directory_size(DirectorySize::from_bytes(
                u64::try_from(length).map_err(|_| Error::ArithmeticOverflow)?,
            ))?;
        raw.set_inline_payload(&prefix)?;
        memory::copy_exact(raw.writable_inline_xattr_region()?, &body)?;
        raw.set_encoded_size(size)?;
        self.store_xattr_set(raw, set)?;
        Ok(Some(result))
    }
    /// Converts complete inode-body storage into ordinary journaled extent metadata.
    /// All payload writes and allocation changes remain private until the enclosing commit.
    /// # Errors
    /// Propagates malformed storage, allocation, encoding or journal staging failure.
    pub(super) fn convert_inline_data(
        &mut self,
        raw: &mut LiveInodeRecord,
        set: &mut InodeXattrSet,
    ) -> Result<()> {
        let inode = raw.parse()?;
        let InodeStorage::InlineData(data) = inode.storage() else {
            return Ok(());
        };
        let block_size = self.volume.superblock.block_size();
        let width = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let context = self.volume.extent_tree_context(&inode);
        let mut tree = MutableExtentTree::from_extents(Vec::new())?;
        let new_size = match data {
            InodeInlineData::File(payload) => {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "width comes from validated BlockSize and is at least 1024 bytes"
                )]
                let chunks = payload.chunks(width);
                for (index, chunk) in chunks.enumerate() {
                    let logical = LogicalBlock::try_from(
                        u64::try_from(index).map_err(|_| Error::ArithmeticOverflow)?,
                    )?;
                    let physical = self.allocate_extent_block(&tree, logical)?;
                    tree.insert_or_extend_initialized(logical, physical)?;
                    let mut bytes = memory::repeated_vec(0, width)?;
                    memory::copy_exact(
                        bytes.get_mut(..chunk.len()).ok_or(Error::DeviceRange)?,
                        chunk,
                    )?;
                    self.stage_file_write(
                        FileDataPersistence::Ordered,
                        RangeWrite {
                            offset: block_size.offset_of(physical)?,
                            bytes,
                        },
                    )?;
                }
                self.volume
                    .superblock
                    .inode_data_encoding()
                    .encode_file_size(inode.size())?
            }
            InodeInlineData::Directory { .. } => {
                let entries = data.directory_entries(inode.id())?;
                let checksum = self.volume.directory_checksum(&inode);
                let mut next = 0_u64;
                let mut block = DirectoryBlock::empty(width, checksum)?;
                block.initialize_free_space()?;
                for entry in entries {
                    if !block.insert(entry.inode(), entry.name(), entry.kind())? {
                        self.append_inline_directory_block(&mut tree, next, block)?;
                        next = next.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                        block = DirectoryBlock::empty(width, checksum)?;
                        block.initialize_free_space()?;
                        if !block.insert(entry.inode(), entry.name(), entry.kind())? {
                            return Err(Error::InvalidDirectoryEntry);
                        }
                    }
                }
                self.append_inline_directory_block(&mut tree, next, block)?;
                let size = next
                    .checked_add(1)
                    .and_then(|count| count.checked_mul(u64::from(block_size.bytes())))
                    .ok_or(Error::ArithmeticOverflow)?;
                self.volume
                    .superblock
                    .inode_data_encoding()
                    .encode_directory_size(DirectorySize::from_bytes(size))?
            }
        };
        // Establish a complete extent representation before any subsequent parser observes it.
        let empty = MutableExtentTree::from_extents(Vec::new())?.serialize(block_size, context)?;
        raw.replace_inline_storage(empty.inode_root())?;
        set.remove_inline_data();
        let body =
            xattr_storage::serialize_inline_xattrs(set, raw.writable_inline_xattr_region()?.len());
        // Other attributes may require the external block, which store_xattr_set owns.
        match body {
            Ok(bytes) => memory::copy_exact(raw.writable_inline_xattr_region()?, &bytes)?,
            Err(Error::NoSpace) => raw.clear_inline_xattr_region()?,
            Err(error) => return Err(error),
        }
        raw.set_encoded_size(new_size)?;
        self.stage_extent_tree(raw, tree)
    }
    /// Stages one converted directory block with its distinct metadata persistence semantics.
    /// # Errors
    /// Propagates allocation, extent or staging failure.
    fn append_inline_directory_block(
        &mut self,
        tree: &mut MutableExtentTree,
        index: u64,
        block: DirectoryBlock,
    ) -> Result<()> {
        let logical = LogicalBlock::try_from(index)?;
        let physical = self.allocate_extent_block(tree, logical)?;
        tree.insert_or_extend_initialized(logical, physical)?;
        self.directory_updates.try_push(BlockImage {
            block: physical,
            bytes: block.into_bytes(),
        })
    }
    /// Attempts to retain complete file bytes in inode-body storage.
    /// False leaves the raw inode unchanged; the caller can convert and continue its mutation.
    /// # Errors
    /// Propagates physical allocation, malformed xattrs and invalid size failures.
    pub(super) fn store_inline_file(
        &mut self,
        raw: &mut LiveInodeRecord,
        payload: &[u8],
    ) -> Result<bool> {
        let mut set = self.xattr_set_for_raw_inode(raw)?;
        let capacity = raw.writable_inline_xattr_region()?.len();
        if payload.len()
            > 60_usize
                .checked_add(capacity)
                .ok_or(Error::ArithmeticOverflow)?
        {
            return Ok(false);
        }
        set.set_inline_data(XattrValue::new(payload.get(60..).unwrap_or_default())?);
        let body = match xattr_storage::serialize_inline_xattrs(&set, capacity) {
            Ok(bytes) => bytes,
            Err(Error::NoSpace) => return Ok(false),
            Err(error) => return Err(error),
        };
        let mut prefix = [0; 60];
        let count = core::cmp::min(prefix.len(), payload.len());
        memory::copy_exact(
            prefix.get_mut(..count).ok_or(Error::DeviceRange)?,
            payload.get(..count).ok_or(Error::DeviceRange)?,
        )?;
        let size = self
            .volume
            .superblock
            .inode_data_encoding()
            .encode_file_size(FileSize::from_bytes(
                u64::try_from(payload.len()).map_err(|_| Error::ArithmeticOverflow)?,
            ))?;
        raw.set_inline_payload(&prefix)?;
        memory::copy_exact(raw.writable_inline_xattr_region()?, &body)?;
        raw.set_encoded_size(size)?;
        self.store_xattr_set(raw, set)?;
        Ok(true)
    }
    /// Preserves all inline bytes before an operation requiring extent allocation.
    /// # Errors
    /// Propagates allocation, xattr and conversion failures.
    pub(super) fn require_extent_storage(&mut self, raw: &mut LiveInodeRecord) -> Result<()> {
        if !raw.parse()?.flags().has_inline_data() {
            return Ok(());
        }
        let mut set = self.xattr_set_for_raw_inode(raw)?;
        self.convert_inline_data(raw, &mut set)?;
        self.store_xattr_set(raw, set)
    }
}
