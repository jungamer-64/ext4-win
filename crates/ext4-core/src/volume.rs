//! Mounted ext4 volume state and journaled write transactions.

use alloc::{vec, vec::Vec};

use crate::block::{BlockAddress, BlockReader, BlockWriter, ByteOffset};
use crate::dir::DirectoryEntry;
use crate::endian::put_le_u32;
use crate::error::{Error, Result};
use crate::extent::{Extent, ExtentTree, serialize_inode_root};
use crate::group::BlockGroupDescriptor;
use crate::inode::{Ext4Timestamp, Inode, InodeId, InodeKind};
use crate::journal::Journal;
use crate::name::WindowsName;
use crate::superblock::Superblock;

const MAX_EAGER_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const INODE_SIZE_LO_OFFSET: usize = 4;
const INODE_CTIME_OFFSET: usize = 12;
const INODE_MTIME_OFFSET: usize = 16;
const INODE_BLOCKS_LO_OFFSET: usize = 28;
const INODE_BLOCK_OFFSET: usize = 40;
const INODE_SIZE_HIGH_OFFSET: usize = 108;
const INODE_BLOCKS_HIGH_OFFSET: usize = 116;
const SUPERBLOCK_FREE_BLOCKS_LO_OFFSET: usize = 12;
const SUPERBLOCK_FREE_BLOCKS_HI_OFFSET: usize = 344;
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Read-only mounted volume state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnly;

/// Journaled read-write mounted volume state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadWrite {
    journal: Journal,
}

/// Mounted ext4 volume with typestate-selected mutation capability.
#[derive(Debug)]
pub struct Volume<D, State> {
    device: D,
    superblock: Superblock,
    state: State,
}

impl<D: BlockReader> Volume<D, ReadOnly> {
    /// Validates an ext4 volume and constructs read-only mounted state.
    ///
    /// # Errors
    /// Returns an error when the device does not contain a supported ext4 superblock.
    pub fn mount_read_only(device: D) -> Result<Self> {
        let superblock = Superblock::read_from(&device)?;
        Ok(Self {
            device,
            superblock,
            state: ReadOnly,
        })
    }
}

impl<D: BlockWriter> Volume<D, ReadWrite> {
    /// Replays the internal journal boundary and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when the device is not a supported journaled ext4 volume.
    pub fn mount_read_write(device: D) -> Result<Self> {
        let superblock = Superblock::read_write_from(&device)?;
        if !superblock.features().has_journal() || superblock.journal_inode() == 0 {
            return Err(Error::UnsupportedJournal);
        }
        let read_only = Volume::<D, ReadOnly> {
            device,
            superblock,
            state: ReadOnly,
        };
        let journal_inode = read_only.read_inode(InodeId::new(superblock.journal_inode()))?;
        let journal =
            Journal::from_inode(&journal_inode, superblock.block_size(), &read_only.device)?;
        Ok(Self {
            device: read_only.device,
            superblock,
            state: ReadWrite { journal },
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(&mut self, now: Ext4Timestamp) -> WriteTransaction<'_, D> {
        WriteTransaction {
            volume: self,
            now,
            inode_updates: Vec::new(),
            bitmap_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            free_blocks_delta: 0,
        }
    }
}

impl<D: BlockReader, State> Volume<D, State> {
    /// Validated superblock.
    #[must_use]
    pub const fn superblock(&self) -> Superblock {
        self.superblock
    }

    /// Reads and parses one inode.
    ///
    /// # Errors
    /// Returns an error when the inode number is outside the volume or the inode
    /// table cannot be read and parsed.
    pub fn read_inode(&self, inode_id: InodeId) -> Result<Inode> {
        self.read_raw_inode(inode_id)?.parse()
    }

    /// Reads file bytes from a regular file or symlink inode.
    ///
    /// # Errors
    /// Returns an error when the inode is not file-like or its extent mapping
    /// cannot be traversed.
    pub fn read_file(&self, inode_id: InodeId, offset: u64, out: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(inode_id)?;
        if !matches!(inode.kind(), InodeKind::File | InodeKind::Symlink) {
            return Err(Error::WrongInodeKind);
        }
        self.read_inode_data(&inode, offset, out)
    }

    /// Reads a symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the inode is not a symlink or its target cannot be read.
    pub fn read_symlink(&self, inode_id: InodeId) -> Result<Vec<u8>> {
        let inode = self.read_inode(inode_id)?;
        if inode.kind() != InodeKind::Symlink {
            return Err(Error::WrongInodeKind);
        }
        let len = usize::try_from(inode.size()).map_err(|_| Error::ArithmeticOverflow)?;
        if len <= inode.block().len() && !inode.has_extents() {
            return Ok(inode
                .block()
                .get(..len)
                .ok_or(Error::TruncatedStructure)?
                .to_vec());
        }
        let mut target = vec![0_u8; len];
        let _bytes_read = self.read_inode_data(&inode, 0, &mut target)?;
        Ok(target)
    }

    /// Enumerates directory entries from a directory inode.
    ///
    /// # Errors
    /// Returns an error when the inode is not a directory, is too large for eager
    /// enumeration, or contains malformed entries.
    pub fn read_directory(&self, inode_id: InodeId) -> Result<Vec<DirectoryEntry>> {
        let inode = self.read_inode(inode_id)?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if inode.size() > MAX_EAGER_DIRECTORY_BYTES {
            return Err(Error::DirectoryTooLarge);
        }
        let len = usize::try_from(inode.size()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut bytes = vec![0_u8; len];
        let _bytes_read = self.read_inode_data(&inode, 0, &mut bytes)?;
        DirectoryEntry::parse_all(&bytes)
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated as a directory.
    pub fn lookup_child(&self, parent: InodeId, name: &[u8]) -> Result<Option<InodeId>> {
        for entry in self.read_directory(parent)? {
            if entry.name().bytes() == name {
                return Ok(Some(entry.inode()));
            }
        }
        Ok(None)
    }

    /// Looks up a Windows-visible child name, accepting case-insensitive matches only when unique.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the
    /// case-insensitive Windows projection is ambiguous.
    pub fn lookup_windows_child(
        &self,
        parent: InodeId,
        requested_utf16: &[u16],
    ) -> Result<Option<InodeId>> {
        let mut exact = None;
        let mut folded = None;

        for entry in self.read_directory(parent)? {
            let Ok(name) = WindowsName::from_ext4(entry.name()) else {
                continue;
            };
            if name.equals_utf16(requested_utf16) {
                exact = Some(entry.inode());
                break;
            }
            if name.equals_ascii_case_insensitive(requested_utf16) {
                if folded.is_some() {
                    return Err(Error::AmbiguousWindowsName);
                }
                folded = Some(entry.inode());
            }
        }

        Ok(exact.or(folded))
    }

    fn read_inode_data(&self, inode: &Inode, offset: u64, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() || offset >= inode.size() {
            return Ok(0);
        }
        if !inode.has_extents() {
            return Err(Error::UnsupportedBlockMap);
        }

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            inode
                .size()
                .checked_sub(offset)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        let block_size = u64::from(self.superblock.block_size().bytes());
        let extent_tree =
            ExtentTree::load_inode_tree(inode.block(), self.superblock.block_size(), &self.device)?;
        let mut completed = 0_usize;

        while u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)? < readable {
            let position = offset
                .checked_add(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let logical_block = position
                .checked_div(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let in_block = position
                .checked_rem(block_size)
                .ok_or(Error::InvalidSuperblock)?;
            let block_remaining = block_size
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let total_remaining = readable
                .checked_sub(u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
            let chunk_u64 = core::cmp::min(block_remaining, total_remaining);
            let chunk = usize::try_from(chunk_u64).map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            if let Some(physical_block) = extent_tree.map_logical(logical_block) {
                let device_offset = self
                    .superblock
                    .block_size()
                    .offset_of(physical_block)?
                    .get()
                    .checked_add(in_block)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.device.read_exact_at(
                    ByteOffset::new(device_offset),
                    out.get_mut(completed..end).ok_or(Error::DeviceRange)?,
                )?;
            } else {
                out.get_mut(completed..end)
                    .ok_or(Error::DeviceRange)?
                    .fill(0);
            }
            completed = end;
        }

        Ok(completed)
    }

    fn read_raw_inode(&self, inode_id: InodeId) -> Result<RawInode> {
        if inode_id.get() == 0 || inode_id.get() > self.superblock.inode_count() {
            return Err(Error::InvalidInode);
        }

        let zero_based = inode_id.get().checked_sub(1).ok_or(Error::InvalidInode)?;
        let group = zero_based
            .checked_div(self.superblock.inodes_per_group())
            .ok_or(Error::InvalidSuperblock)?;
        let index = zero_based
            .checked_rem(self.superblock.inodes_per_group())
            .ok_or(Error::InvalidSuperblock)?;
        let descriptor = BlockGroupDescriptor::read_from(&self.device, &self.superblock, group)?;
        let inode_size = u64::from(self.superblock.inode_size());
        let inode_offset = self
            .superblock
            .block_size()
            .offset_of(descriptor.inode_table())?
            .get()
            .checked_add(
                u64::from(index)
                    .checked_mul(inode_size)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;

        let mut bytes = vec![0_u8; usize::from(self.superblock.inode_size())];
        self.device
            .read_exact_at(ByteOffset::new(inode_offset), &mut bytes)?;
        Ok(RawInode {
            id: inode_id,
            offset: ByteOffset::new(inode_offset),
            bytes,
        })
    }
}

/// In-progress ext4 write transaction.
#[derive(Debug)]
pub struct WriteTransaction<'a, D: BlockWriter> {
    volume: &'a mut Volume<D, ReadWrite>,
    now: Ext4Timestamp,
    inode_updates: Vec<RawInode>,
    bitmap_updates: Vec<BlockImage>,
    group_deltas: Vec<GroupDelta>,
    data_writes: Vec<RangeWrite>,
    free_blocks_delta: i64,
}

impl<D: BlockWriter> WriteTransaction<'_, D> {
    /// Overwrites bytes inside an existing regular file range.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file, the range extends
    /// beyond EOF, allocation fails, or the updated root extent set cannot fit
    /// in the inode.
    pub fn overwrite_file_range(
        &mut self,
        inode_id: InodeId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        let end_offset = offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)?;
        if end_offset > inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        if !inode.has_extents() {
            return Err(Error::UnsupportedBlockMap);
        }

        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let block_size = usize::try_from(block_size_u64).map_err(|_| Error::ArithmeticOverflow)?;
        let mut extents = ExtentTree::parse_inode_root(inode.block())?
            .extents()
            .to_vec();
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
            let total_remaining = bytes
                .len()
                .checked_sub(completed)
                .ok_or(Error::ArithmeticOverflow)?;
            let block_remaining = block_size_u64
                .checked_sub(in_block)
                .ok_or(Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(
                block_remaining,
                u64::try_from(total_remaining).map_err(|_| Error::ArithmeticOverflow)?,
            ))
            .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            if let Some(physical) = map_extents(&extents, logical_block) {
                let write_offset = self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(physical)?
                    .get()
                    .checked_add(in_block)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.data_writes.push(RangeWrite {
                    offset: ByteOffset::new(write_offset),
                    bytes: bytes
                        .get(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .to_vec(),
                });
            } else {
                let physical = self.allocate_block()?;
                insert_or_extend_extent(
                    &mut extents,
                    u32::try_from(logical_block).map_err(|_| Error::ArithmeticOverflow)?,
                    physical,
                )?;
                let mut block = vec![0_u8; block_size];
                let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                let block_end = start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                block
                    .get_mut(start..block_end)
                    .ok_or(Error::DeviceRange)?
                    .copy_from_slice(bytes.get(completed..end).ok_or(Error::DeviceRange)?);
                self.data_writes.push(RangeWrite {
                    offset: self.volume.superblock.block_size().offset_of(physical)?,
                    bytes: block,
                });
            }

            completed = end;
        }

        raw_inode.set_timestamps(self.now)?;
        raw_inode.set_extent_root(&extents)?;
        raw_inode.set_allocated_blocks(extents_allocated_blocks(&extents), block_size_u64)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Extends a regular file as a sparse range.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file or `new_size`
    /// would shrink the file.
    pub fn extend_file(&mut self, inode_id: InodeId, new_size: u64) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        if new_size < inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Truncates a regular file and releases whole blocks beyond the new EOF.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file, `new_size`
    /// would extend the file, or root extent updates cannot fit in the inode.
    pub fn truncate_file(&mut self, inode_id: InodeId, new_size: u64) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        if new_size > inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        if !inode.has_extents() {
            return Err(Error::UnsupportedBlockMap);
        }
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let extents = ExtentTree::parse_inode_root(inode.block())?
            .extents()
            .to_vec();
        let keep_blocks = round_up_div(new_size, block_size_u64)?;
        let mut updated = Vec::new();
        for extent in extents {
            let start = u64::from(extent.logical_start());
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
                updated.push(Extent::new(
                    extent.logical_start(),
                    keep_len,
                    extent.physical_start(),
                ));
            } else {
                updated.push(extent);
            }
        }
        if new_size
            .checked_rem(block_size_u64)
            .ok_or(Error::InvalidSuperblock)?
            != 0
        {
            self.zero_truncated_tail(&updated, new_size, block_size_u64)?;
        }
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now)?;
        raw_inode.set_extent_root(&updated)?;
        raw_inode.set_allocated_blocks(extents_allocated_blocks(&updated), block_size_u64)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Aborts the transaction without writing staged data or metadata.
    pub fn abort(self) {}

    /// Commits staged data and metadata using the volume journal ordering boundary.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub fn commit(mut self) -> Result<()> {
        let mut metadata_writes = self.metadata_writes()?;
        self.volume
            .state
            .journal
            .ensure_transaction_capacity(metadata_writes.len())?;

        for write in self.data_writes {
            self.volume
                .device
                .write_exact_at(write.offset, write.bytes.as_slice())?;
        }
        self.volume.device.flush()?;

        self.volume.state.journal.write_descriptor_marker(
            &mut self.volume.device,
            self.volume.superblock.block_size(),
            1,
        )?;
        self.volume.device.flush()?;

        for write in metadata_writes.drain(..) {
            self.volume
                .device
                .write_exact_at(write.offset, write.bytes.as_slice())?;
        }
        self.volume.device.flush()?;

        self.volume.state.journal.write_commit_marker(
            &mut self.volume.device,
            self.volume.superblock.block_size(),
            1,
        )?;
        self.volume.device.flush()
    }

    fn ensure_inode_update(&mut self, inode_id: InodeId) -> Result<usize> {
        if let Some(index) = self
            .inode_updates
            .iter()
            .position(|inode| inode.id == inode_id)
        {
            return Ok(index);
        }
        let raw_inode = self.volume.read_raw_inode(inode_id)?;
        self.inode_updates.push(raw_inode);
        self.inode_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    fn allocate_block(&mut self) -> Result<BlockAddress> {
        let groups = self.volume.superblock.block_group_count()?;
        for group in 0..groups {
            let descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            if descriptor.free_blocks_count() == 0 {
                continue;
            }
            let bitmap_index = self.ensure_bitmap_update(descriptor.block_bitmap())?;
            let group_start = u64::from(self.volume.superblock.first_data_block())
                .checked_add(
                    u64::from(group)
                        .checked_mul(u64::from(self.volume.superblock.blocks_per_group()))
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let blocks_in_group = self.blocks_in_group(group)?;
            for bit in 0..blocks_in_group {
                let absolute_block = group_start
                    .checked_add(u64::from(bit))
                    .ok_or(Error::ArithmeticOverflow)?;
                if absolute_block >= self.volume.superblock.block_count() {
                    break;
                }
                let bitmap = self
                    .bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                if !bitmap_bit(bitmap.bytes.as_slice(), bit)? {
                    set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, true)?;
                    self.record_group_delta(group, -1)?;
                    self.free_blocks_delta = self
                        .free_blocks_delta
                        .checked_sub(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                    return Ok(BlockAddress::new(absolute_block));
                }
            }
        }
        Err(Error::NoSpace)
    }

    fn free_extent(&mut self, extent: Extent, keep_len: u16) -> Result<()> {
        let start = u64::from(keep_len);
        let len = u64::from(extent.len());
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
            self.free_block(block)?;
        }
        if physical_start > extent.physical_start().get() || keep_len == 0 {
            Ok(())
        } else {
            Err(Error::ArithmeticOverflow)
        }
    }

    fn free_block(&mut self, block: BlockAddress) -> Result<()> {
        let group = block_group_of(&self.volume.superblock, block)?;
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_bitmap_update(descriptor.block_bitmap())?;
        let bitmap = self
            .bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        let bit = block_bit_in_group(&self.volume.superblock, block, group)?;
        if bitmap_bit(bitmap.bytes.as_slice(), bit)? {
            set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, false)?;
            self.record_group_delta(group, 1)?;
            self.free_blocks_delta = self
                .free_blocks_delta
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(())
    }

    fn zero_truncated_tail(
        &mut self,
        extents: &[Extent],
        new_size: u64,
        block_size: u64,
    ) -> Result<()> {
        let logical_block = new_size
            .checked_div(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let in_block = new_size
            .checked_rem(block_size)
            .ok_or(Error::InvalidSuperblock)?;
        let Some(physical) = map_extents(extents, logical_block) else {
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
        self.data_writes.push(RangeWrite {
            offset: ByteOffset::new(offset),
            bytes: vec![0_u8; usize::try_from(zero_len).map_err(|_| Error::ArithmeticOverflow)?],
        });
        Ok(())
    }

    fn ensure_bitmap_update(&mut self, bitmap_block: BlockAddress) -> Result<usize> {
        if let Some(index) = self
            .bitmap_updates
            .iter()
            .position(|image| image.block == bitmap_block)
        {
            return Ok(index);
        }
        let mut bytes = vec![
            0_u8;
            usize::try_from(self.volume.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?
        ];
        self.volume.device.read_exact_at(
            self.volume
                .superblock
                .block_size()
                .offset_of(bitmap_block)?,
            &mut bytes,
        )?;
        self.bitmap_updates.push(BlockImage {
            block: bitmap_block,
            bytes,
        });
        self.bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    fn blocks_in_group(&self, group: u32) -> Result<u32> {
        let group_start = u64::from(self.volume.superblock.first_data_block())
            .checked_add(
                u64::from(group)
                    .checked_mul(u64::from(self.volume.superblock.blocks_per_group()))
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let remaining = self
            .volume
            .superblock
            .block_count()
            .checked_sub(group_start)
            .ok_or(Error::InvalidSuperblock)?;
        Ok(core::cmp::min(
            self.volume.superblock.blocks_per_group(),
            u32::try_from(remaining).unwrap_or(u32::MAX),
        ))
    }

    fn record_group_delta(&mut self, group: u32, delta: i32) -> Result<()> {
        if let Some(existing) = self
            .group_deltas
            .iter_mut()
            .find(|entry| entry.group == group)
        {
            existing.delta = existing
                .delta
                .checked_add(delta)
                .ok_or(Error::ArithmeticOverflow)?;
            return Ok(());
        }
        self.group_deltas.push(GroupDelta { group, delta });
        Ok(())
    }

    fn metadata_writes(&mut self) -> Result<Vec<RangeWrite>> {
        let mut writes = Vec::new();
        for bitmap in &self.bitmap_updates {
            writes.push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: bitmap.bytes.clone(),
            });
        }
        for delta in &self.group_deltas {
            let mut descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                delta.group,
            )?;
            descriptor.apply_free_blocks_delta(
                delta.delta,
                self.volume.superblock.features().has_64bit(),
            )?;
            writes.push(RangeWrite {
                offset: descriptor.offset(),
                bytes: descriptor.bytes().to_vec(),
            });
        }
        if self.free_blocks_delta != 0 {
            writes.push(RangeWrite {
                offset: ByteOffset::new(SUPERBLOCK_OFFSET),
                bytes: self.updated_superblock_bytes()?,
            });
        }
        for inode in &self.inode_updates {
            writes.push(RangeWrite {
                offset: inode.offset,
                bytes: inode.bytes.clone(),
            });
        }
        Ok(writes)
    }

    fn updated_superblock_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0_u8; 1024];
        self.volume
            .device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut bytes)?;
        let current = self.volume.superblock.free_blocks_count();
        let updated = if self.free_blocks_delta.is_negative() {
            current
                .checked_sub(self.free_blocks_delta.unsigned_abs())
                .ok_or(Error::InvalidSuperblock)?
        } else {
            current
                .checked_add(
                    u64::try_from(self.free_blocks_delta).map_err(|_| Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?
        };
        put_le_u32(
            &mut bytes,
            SUPERBLOCK_FREE_BLOCKS_LO_OFFSET,
            u32::try_from(updated & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.volume.superblock.features().has_64bit() {
            put_le_u32(
                &mut bytes,
                SUPERBLOCK_FREE_BLOCKS_HI_OFFSET,
                u32::try_from(updated >> 32).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawInode {
    id: InodeId,
    offset: ByteOffset,
    bytes: Vec<u8>,
}

impl RawInode {
    fn parse(&self) -> Result<Inode> {
        Inode::parse(self.id, &self.bytes)
    }

    fn set_size(&mut self, size: u64) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            INODE_SIZE_LO_OFFSET,
            u32::try_from(size & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_le_u32(
            &mut self.bytes,
            INODE_SIZE_HIGH_OFFSET,
            u32::try_from(size >> 32).map_err(|_| Error::ArithmeticOverflow)?,
        )
    }

    fn set_timestamps(&mut self, now: Ext4Timestamp) -> Result<()> {
        put_le_u32(&mut self.bytes, INODE_CTIME_OFFSET, now.seconds())?;
        put_le_u32(&mut self.bytes, INODE_MTIME_OFFSET, now.seconds())
    }

    fn set_extent_root(&mut self, extents: &[Extent]) -> Result<()> {
        let root = serialize_inode_root(extents)?;
        let end = INODE_BLOCK_OFFSET
            .checked_add(root.len())
            .ok_or(Error::ArithmeticOverflow)?;
        self.bytes
            .get_mut(INODE_BLOCK_OFFSET..end)
            .ok_or(Error::TruncatedStructure)?
            .copy_from_slice(&root);
        Ok(())
    }

    fn set_allocated_blocks(&mut self, blocks: u64, block_size: u64) -> Result<()> {
        let sectors = blocks
            .checked_mul(block_size)
            .ok_or(Error::ArithmeticOverflow)?
            .checked_div(512)
            .ok_or(Error::ArithmeticOverflow)?;
        put_le_u32(
            &mut self.bytes,
            INODE_BLOCKS_LO_OFFSET,
            u32::try_from(sectors & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.bytes.len() > INODE_BLOCKS_HIGH_OFFSET {
            put_le_u32(
                &mut self.bytes,
                INODE_BLOCKS_HIGH_OFFSET,
                u32::try_from(sectors >> 32).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlockImage {
    block: BlockAddress,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GroupDelta {
    group: u32,
    delta: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RangeWrite {
    offset: ByteOffset,
    bytes: Vec<u8>,
}

fn map_extents(extents: &[Extent], logical_block: u64) -> Option<BlockAddress> {
    for extent in extents {
        if let Some(block) = extent.map_logical(logical_block) {
            return Some(block);
        }
    }
    None
}

fn insert_or_extend_extent(
    extents: &mut Vec<Extent>,
    logical_block: u32,
    physical_block: BlockAddress,
) -> Result<()> {
    if let Some(last) = extents.last_mut()
        && last.end_logical()? == logical_block
        && last
            .physical_start()
            .get()
            .checked_add(u64::from(last.len()))
            .ok_or(Error::ArithmeticOverflow)?
            == physical_block.get()
    {
        let len = last.len().checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        *last = Extent::new(last.logical_start(), len, last.physical_start());
        return Ok(());
    }
    extents.push(Extent::new(logical_block, 1, physical_block));
    extents.sort_by_key(|extent| extent.logical_start());
    Ok(())
}

fn extents_allocated_blocks(extents: &[Extent]) -> u64 {
    extents.iter().map(|extent| u64::from(extent.len())).sum()
}

fn round_up_div(value: u64, divisor: u64) -> Result<u64> {
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

fn bitmap_bit(bytes: &[u8], bit: u32) -> Result<bool> {
    let byte_index = usize::try_from(bit.checked_div(8).ok_or(Error::ArithmeticOverflow)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let bit_index = bit.checked_rem(8).ok_or(Error::ArithmeticOverflow)?;
    let byte = bytes.get(byte_index).ok_or(Error::InvalidSuperblock)?;
    Ok(byte & (1_u8 << bit_index) != 0)
}

fn set_bitmap_bit(bytes: &mut [u8], bit: u32, value: bool) -> Result<()> {
    let byte_index = usize::try_from(bit.checked_div(8).ok_or(Error::ArithmeticOverflow)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let bit_index = bit.checked_rem(8).ok_or(Error::ArithmeticOverflow)?;
    let byte = bytes.get_mut(byte_index).ok_or(Error::InvalidSuperblock)?;
    if value {
        *byte |= 1_u8 << bit_index;
    } else {
        *byte &= !(1_u8 << bit_index);
    }
    Ok(())
}

fn block_group_of(superblock: &Superblock, block: BlockAddress) -> Result<u32> {
    let relative = block
        .get()
        .checked_sub(u64::from(superblock.first_data_block()))
        .ok_or(Error::InvalidSuperblock)?;
    u32::try_from(
        relative
            .checked_div(u64::from(superblock.blocks_per_group()))
            .ok_or(Error::InvalidSuperblock)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)
}

fn block_bit_in_group(superblock: &Superblock, block: BlockAddress, group: u32) -> Result<u32> {
    let group_start = u64::from(superblock.first_data_block())
        .checked_add(
            u64::from(group)
                .checked_mul(u64::from(superblock.blocks_per_group()))
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    u32::try_from(
        block
            .get()
            .checked_sub(group_start)
            .ok_or(Error::InvalidSuperblock)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)
}
