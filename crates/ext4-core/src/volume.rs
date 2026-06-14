//! Mounted read-only ext4 volume state.

use alloc::{vec, vec::Vec};

use crate::block::{BlockAddress, BlockReader, ByteOffset};
use crate::dir::DirectoryEntry;
use crate::endian::le_u32;
use crate::error::{Error, Result};
use crate::extent::ExtentTree;
use crate::inode::{Inode, InodeId, InodeKind};
use crate::name::WindowsName;
use crate::superblock::Superblock;

const BLOCK_GROUP_DESCRIPTOR_SIZE: u64 = 32;
const MAX_EAGER_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;

/// Mounted read-only ext4 volume.
#[derive(Debug)]
pub struct Volume<D, State> {
    device: D,
    superblock: Superblock,
    state: State,
}

impl<D: BlockReader> Volume<D, ReadOnly> {
    /// Validates a clean ext4 volume and constructs mounted read-only state.
    ///
    /// # Errors
    /// Returns an error when the device does not contain a clean v1-supported
    /// ext4 superblock.
    pub fn mount(device: D) -> Result<Self> {
        let superblock = Superblock::read_from(&device)?;
        Ok(Self {
            device,
            superblock,
            state: ReadOnly,
        })
    }

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
        if inode_id.get() == 0 || inode_id.get() > self.superblock.inode_count() {
            return Err(Error::InvalidInode);
        }

        let zero_based = inode_id.get().checked_sub(1).ok_or(Error::InvalidInode)?;
        let group = zero_based
            .checked_div(self.superblock.inodes_per_group())
            .ok_or(Error::InvalidSuperblock)?;
        if group >= self.superblock.block_group_count()? {
            return Err(Error::InvalidInode);
        }
        let index = zero_based
            .checked_rem(self.superblock.inodes_per_group())
            .ok_or(Error::InvalidSuperblock)?;
        let inode_table = self.read_inode_table_block(group)?;
        let inode_size = u64::from(self.superblock.inode_size());
        let inode_offset = self
            .superblock
            .block_size()
            .offset_of(inode_table)?
            .get()
            .checked_add(
                u64::from(index)
                    .checked_mul(inode_size)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;

        let mut raw = vec![0_u8; usize::from(self.superblock.inode_size())];
        self.device
            .read_exact_at(ByteOffset::new(inode_offset), &mut raw)?;
        Inode::parse(inode_id, &raw)
    }

    /// Reads file bytes from a regular file or symlink inode.
    ///
    /// # Errors
    /// Returns an error when the inode is not file-like or its extent mapping
    /// cannot be traversed by v1.
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
    /// Returns an error when the inode is not a symlink or its target cannot be
    /// read through the supported inline/extent paths.
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
    /// Returns an error when the inode is not a directory, is too large for v1
    /// eager enumeration, or contains malformed entries.
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
        let extent_root = ExtentTree::parse_inode_root(inode.block())?;
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

            if let Some(physical_block) = extent_root.map_logical(logical_block) {
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

    fn read_inode_table_block(&self, group: u32) -> Result<BlockAddress> {
        let bgdt_start_block = if self.superblock.block_size().bytes() == 1024 {
            2_u64
        } else {
            1_u64
        };
        let descriptor_offset = self
            .superblock
            .block_size()
            .offset_of(BlockAddress::new(bgdt_start_block))?
            .get()
            .checked_add(
                u64::from(group)
                    .checked_mul(BLOCK_GROUP_DESCRIPTOR_SIZE)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let mut raw = [0_u8; 32];
        self.device
            .read_exact_at(ByteOffset::new(descriptor_offset), &mut raw)?;
        Ok(BlockAddress::new(u64::from(le_u32(&raw, 8)?)))
    }
}
