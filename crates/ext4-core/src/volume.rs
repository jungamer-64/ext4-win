//! Mounted ext4 volume state and journaled write transactions.

use alloc::{vec, vec::Vec};

use crate::block::{BlockAddress, BlockReader, BlockWriter, ByteOffset};
use crate::checksum::crc32c;
use crate::dir::{DirectoryBlock, DirectoryEntry, DirectoryEntryKind};
use crate::endian::{le_u16, le_u32, put_le_u16, put_le_u32};
use crate::error::{Error, Result};
use crate::extent::{
    BlockMapping, Extent, ExtentLength, ExtentTree, LogicalBlock, serialize_inode_root,
};
use crate::group::BlockGroupDescriptor;
use crate::inode::{
    Ext4Owner, Ext4Permissions, Ext4Timestamp, FileOffset, FileSize, Inode, InodeId, InodeKind,
    NewDirectoryMetadata, NewFileMetadata, ReadBytes,
};
use crate::journal::{Journal, LoadedJournal};
use crate::name::Ext4Name;
use crate::name::WindowsName;
use crate::superblock::{
    BlockGroupId, FreeBlockDelta, JournalMode, MetadataChecksum, RecoveryState, Superblock,
};

const MAX_EAGER_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
const MODE_DIRECTORY: u16 = 0x4000;
const MODE_REGULAR: u16 = 0x8000;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const INODE_MODE_OFFSET: usize = 0;
const INODE_UID_LO_OFFSET: usize = 2;
const INODE_SIZE_LO_OFFSET: usize = 4;
const INODE_ATIME_OFFSET: usize = 8;
const INODE_CTIME_OFFSET: usize = 12;
const INODE_MTIME_OFFSET: usize = 16;
const INODE_DTIME_OFFSET: usize = 20;
const INODE_GID_LO_OFFSET: usize = 24;
const INODE_LINKS_COUNT_OFFSET: usize = 26;
const INODE_BLOCKS_LO_OFFSET: usize = 28;
const INODE_FLAGS_OFFSET: usize = 32;
const INODE_BLOCK_OFFSET: usize = 40;
const INODE_GENERATION_OFFSET: usize = 100;
const INODE_SIZE_HIGH_OFFSET: usize = 108;
const INODE_BLOCKS_HIGH_OFFSET: usize = 116;
const INODE_CHECKSUM_LO_OFFSET: usize = 124;
const INODE_EXTRA_ISIZE_OFFSET: usize = 128;
const INODE_CTIME_EXTRA_OFFSET: usize = 132;
const INODE_MTIME_EXTRA_OFFSET: usize = 136;
const INODE_ATIME_EXTRA_OFFSET: usize = 140;
const INODE_CRTIME_OFFSET: usize = 144;
const INODE_CRTIME_EXTRA_OFFSET: usize = 148;
const INODE_UID_HI_OFFSET: usize = 120;
const INODE_GID_HI_OFFSET: usize = 122;
const INODE_CHECKSUM_HI_OFFSET: usize = 130;
const EXT4_INODE_MIN_EXTRA_ISIZE: u16 = 32;
const SUPERBLOCK_FREE_BLOCKS_LO_OFFSET: usize = 12;
const SUPERBLOCK_FREE_INODES_OFFSET: usize = 16;
const SUPERBLOCK_FREE_BLOCKS_HI_OFFSET: usize = 344;
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Read-only mounted volume state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnly;

/// Internal journal stored as a hidden ext4 inode on the filesystem device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalJournal {
    journal: Journal,
}

/// External journal stored on a separate journal device.
#[derive(Debug)]
pub struct ExternalJournal<J> {
    device: J,
    journal: Journal,
}

/// Journaled read-write mounted volume state.
#[derive(Debug)]
pub struct ReadWrite<J = InternalJournal> {
    journal: J,
}

/// Mounted ext4 volume with typestate-selected mutation capability.
#[derive(Debug)]
pub struct Volume<D, State> {
    device: D,
    superblock: Superblock,
    state: State,
}

/// Typed node loaded from an inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// Regular file node.
    File(FileNode),
    /// Directory node.
    Directory(DirectoryNode),
    /// Symbolic link node.
    Symlink(SymlinkNode),
}

impl Node {
    fn from_inode(inode: Inode) -> Self {
        match inode.kind() {
            InodeKind::File => Self::File(FileNode { inode }),
            InodeKind::Directory => Self::Directory(DirectoryNode { inode }),
            InodeKind::Symlink => Self::Symlink(SymlinkNode { inode }),
        }
    }
}

/// Typed regular file node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileNode {
    inode: Inode,
}

impl FileNode {
    /// Inode identifier backing this file node.
    #[must_use]
    pub const fn id(&self) -> InodeId {
        self.inode.id()
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.inode.size()
    }

    fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Typed directory node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryNode {
    inode: Inode,
}

impl DirectoryNode {
    /// Inode identifier backing this directory node.
    #[must_use]
    pub const fn id(&self) -> InodeId {
        self.inode.id()
    }

    fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Typed symbolic link node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkNode {
    inode: Inode,
}

impl SymlinkNode {
    /// Inode identifier backing this symbolic link node.
    #[must_use]
    pub const fn id(&self) -> InodeId {
        self.inode.id()
    }

    /// Symlink payload size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.inode.size()
    }

    fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Result of a directory lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupResult {
    /// The child name was found.
    Found(InodeId),
    /// No child matched the requested name.
    NotFound,
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

impl<D: BlockWriter> Volume<D, ReadWrite<InternalJournal>> {
    /// Replays the internal journal boundary and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when the device is not a supported journaled ext4 volume.
    pub fn mount_read_write(mut device: D) -> Result<Self> {
        let mut superblock = Superblock::read_write_from(&device)?;
        let JournalMode::Internal(journal_inode_id) = superblock.journal_mode() else {
            return Err(Error::UnsupportedJournal);
        };
        let read_only = Volume::<&mut D, ReadOnly> {
            device: &mut device,
            superblock,
            state: ReadOnly,
        };
        let journal_inode = read_only.read_inode_record(journal_inode_id)?;
        let journal = Journal::<LoadedJournal>::from_inode(
            &journal_inode,
            superblock.block_size(),
            superblock.block_count().as_u64(),
            &read_only.device,
        )?;
        let recovery_state = superblock.recovery_state();
        let journal = journal.replay_and_checkpoint_internal(
            &mut device,
            superblock.block_size(),
            recovery_state,
        )?;
        let journal = InternalJournal { journal };
        if recovery_state == RecoveryState::NeedsRecovery {
            Superblock::clear_recover_on_device(&mut device)?;
            superblock = Superblock::read_write_from(&device)?;
        }
        Ok(Self {
            device,
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
            block_bitmap_updates: Vec::new(),
            inode_bitmap_updates: Vec::new(),
            directory_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            free_blocks_delta: FreeBlockDelta::ZERO,
            free_inodes_delta: 0,
        }
    }
}

impl<D: BlockWriter, J: BlockWriter> Volume<D, ReadWrite<ExternalJournal<J>>> {
    /// Replays an external journal and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when either device cannot support the external journal contract.
    pub fn mount_read_write_with_external_journal(
        mut device: D,
        journal_device: J,
    ) -> Result<Self> {
        let mut superblock = Superblock::read_write_from(&device)?;
        let JournalMode::External(journal_uuid) = superblock.journal_mode() else {
            return Err(Error::UnsupportedJournal);
        };
        let journal = Journal::<LoadedJournal>::from_external_device(
            &journal_device,
            superblock.block_size(),
            journal_uuid.bytes(),
            superblock.block_count().as_u64(),
        )?;
        let recovery_state = superblock.recovery_state();
        let mut journal_device = journal_device;
        let journal = journal.replay_and_checkpoint_external(
            &mut device,
            &mut journal_device,
            superblock.block_size(),
            recovery_state,
        )?;
        let journal = ExternalJournal {
            device: journal_device,
            journal,
        };
        if recovery_state == RecoveryState::NeedsRecovery {
            Superblock::clear_recover_on_device(&mut device)?;
            superblock = Superblock::read_write_from(&device)?;
        }
        Ok(Self {
            device,
            superblock,
            state: ReadWrite { journal },
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> WriteTransaction<'_, D, ExternalJournal<J>> {
        WriteTransaction {
            volume: self,
            now,
            inode_updates: Vec::new(),
            block_bitmap_updates: Vec::new(),
            inode_bitmap_updates: Vec::new(),
            directory_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            free_blocks_delta: FreeBlockDelta::ZERO,
            free_inodes_delta: 0,
        }
    }
}

impl<D: BlockReader, State> Volume<D, State> {
    /// Validated superblock.
    #[must_use]
    pub const fn superblock(&self) -> Superblock {
        self.superblock
    }

    /// Reads and classifies one inode as a typed node.
    ///
    /// # Errors
    /// Returns an error when the inode number is outside the volume or the inode
    /// table cannot be read and parsed.
    pub fn read_node(&self, inode_id: InodeId) -> Result<Node> {
        Ok(Node::from_inode(self.read_inode_record(inode_id)?))
    }

    /// Reads file bytes from a typed regular file node.
    ///
    /// # Errors
    /// Returns an error when the file extent mapping cannot be traversed.
    pub fn read_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        self.read_inode_data(file.inode(), offset, out)
    }

    /// Reads a typed symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the symlink target cannot be read.
    pub fn read_symlink(&self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        let len = symlink.size().to_usize()?;
        if let Ok(inline) = symlink.inode().inline_bytes() {
            return Ok(inline.prefix(symlink.size())?.to_vec());
        }
        let mut target = vec![0_u8; len];
        let _bytes_read = self.read_inode_data(symlink.inode(), FileOffset::ZERO, &mut target)?;
        Ok(target)
    }

    /// Enumerates directory entries from a typed directory node.
    ///
    /// # Errors
    /// Returns an error when the directory is too large for eager
    /// enumeration, or contains malformed entries.
    pub fn read_directory(&self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        if directory.inode().size().bytes() > MAX_EAGER_DIRECTORY_BYTES {
            return Err(Error::DirectoryTooLarge);
        }
        let len = directory.inode().size().to_usize()?;
        let mut bytes = vec![0_u8; len];
        let _bytes_read = self.read_inode_data(directory.inode(), FileOffset::ZERO, &mut bytes)?;
        DirectoryEntry::parse_all(&bytes)
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated.
    pub fn lookup_child(&self, parent: &DirectoryNode, name: &Ext4Name) -> Result<LookupResult> {
        for entry in self.read_directory(parent)? {
            if entry.name() == name {
                return Ok(LookupResult::Found(entry.inode()));
            }
        }
        Ok(LookupResult::NotFound)
    }

    /// Looks up a Windows-visible child name, accepting case-insensitive matches only when unique.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the
    /// case-insensitive Windows projection is ambiguous.
    pub fn lookup_windows_child(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<LookupResult> {
        let mut folded = LookupResult::NotFound;

        for entry in self.read_directory(parent)? {
            let Ok(name) = WindowsName::from_ext4(entry.name()) else {
                continue;
            };
            if name.equals(requested) {
                return Ok(LookupResult::Found(entry.inode()));
            }
            if name.equals_ascii_case_insensitive(requested) {
                if matches!(folded, LookupResult::Found(_)) {
                    return Err(Error::AmbiguousWindowsName);
                }
                folded = LookupResult::Found(entry.inode());
            }
        }

        Ok(folded)
    }

    fn read_inode_data(
        &self,
        inode: &Inode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        if out.is_empty() || offset.bytes() >= inode.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            inode.size().remaining_from(offset)?,
        );
        let block_size = u64::from(self.superblock.block_size().bytes());
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &self.device,
        )?;
        let mut completed = 0_usize;

        while u64::try_from(completed).map_err(|_| Error::ArithmeticOverflow)? < readable {
            let position = offset
                .bytes()
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

            match extent_tree.map_logical(LogicalBlock::try_from(logical_block)?) {
                BlockMapping::Physical(physical_block) => {
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
                }
                BlockMapping::Hole => {
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .fill(0);
                }
            }
            completed = end;
        }

        Ok(ReadBytes::from_usize(completed))
    }

    fn read_raw_inode(&self, inode_id: InodeId) -> Result<RawInode> {
        if inode_id.as_u32() > self.superblock.inode_count().as_u32() {
            return Err(Error::InvalidInode);
        }

        let inode_offset = inode_offset_on_device(&self.device, &self.superblock, inode_id)?;

        let mut bytes = vec![0_u8; usize::from(self.superblock.inode_size().as_u16())];
        self.device.read_exact_at(inode_offset, &mut bytes)?;
        Ok(RawInode {
            id: inode_id,
            offset: inode_offset,
            bytes,
        })
    }

    fn read_inode_record(&self, inode_id: InodeId) -> Result<Inode> {
        self.read_raw_inode(inode_id)?.parse()
    }
}

/// Regular file selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFile {
    inode_id: InodeId,
}

impl TransactionFile {
    /// Inode identifier backing this transaction file.
    #[must_use]
    pub const fn inode_id(self) -> InodeId {
        self.inode_id
    }
}

/// Directory selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionDirectory {
    inode_id: InodeId,
}

impl TransactionDirectory {
    /// Inode identifier backing this transaction directory.
    #[must_use]
    pub const fn inode_id(self) -> InodeId {
        self.inode_id
    }
}

/// In-progress ext4 write transaction.
#[derive(Debug)]
pub struct WriteTransaction<'a, D: BlockWriter, J = InternalJournal> {
    volume: &'a mut Volume<D, ReadWrite<J>>,
    now: Ext4Timestamp,
    inode_updates: Vec<RawInode>,
    block_bitmap_updates: Vec<BlockImage>,
    inode_bitmap_updates: Vec<BlockImage>,
    directory_updates: Vec<BlockImage>,
    group_deltas: Vec<GroupDelta>,
    data_writes: Vec<RangeWrite>,
    free_blocks_delta: FreeBlockDelta,
    free_inodes_delta: i64,
}

impl<D: BlockWriter, J> WriteTransaction<'_, D, J> {
    /// Selects a regular file for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file or cannot be read.
    pub fn file(&self, inode_id: InodeId) -> Result<TransactionFile> {
        let inode = self.volume.read_inode_record(inode_id)?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        Ok(TransactionFile { inode_id })
    }

    /// Selects a directory for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a directory or cannot be read.
    pub fn directory(&self, inode_id: InodeId) -> Result<TransactionDirectory> {
        let inode = self.volume.read_inode_record(inode_id)?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if !inode.supports_basic_mutation() {
            return Err(Error::UnsupportedInodeMutation);
        }
        Ok(TransactionDirectory { inode_id })
    }

    /// Creates an empty regular file under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no
    /// inode is free, or the parent directory cannot receive another entry.
    pub fn create_file(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        metadata: NewFileMetadata,
    ) -> Result<TransactionFile> {
        self.ensure_child_absent(parent.inode_id(), name)?;
        let mut raw_inode = self.allocate_inode()?;
        raw_inode.initialize_file(metadata, self.now)?;
        let inode_id = raw_inode.id;
        self.add_directory_entry(parent.inode_id(), name, inode_id, DirectoryEntryKind::File)?;
        self.inode_updates.push(raw_inode);
        Ok(TransactionFile { inode_id })
    }

    /// Removes a regular file directory entry and releases its inode when the
    /// final link is removed.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, the child is not a mutable
    /// regular file, or metadata cannot be updated.
    pub fn unlink_file(&mut self, parent: TransactionDirectory, name: &Ext4Name) -> Result<()> {
        let removed = self.remove_directory_entry(parent.inode_id(), name)?;
        let inode_index = self.ensure_inode_update(removed.inode())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        if !inode.supports_basic_mutation() {
            return Err(Error::UnsupportedInodeMutation);
        }
        if raw_inode.decrement_links_count()? == 0 {
            let extents = ExtentTree::parse_inode_root(inode.extent_root()?)?
                .extents()
                .to_vec();
            for extent in extents {
                self.free_extent(extent, 0)?;
            }
            self.free_inode(raw_inode.id)?;
            raw_inode.clear_deleted(self.now)?;
        }
        raw_inode.set_timestamps(self.now)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Creates an empty child directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no
    /// inode or block is free, or metadata cannot be updated.
    pub fn create_directory(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        metadata: NewDirectoryMetadata,
    ) -> Result<TransactionDirectory> {
        self.ensure_child_absent(parent.inode_id(), name)?;
        let block = self.allocate_block()?;
        let mut raw_inode = self.allocate_inode()?;
        let inode_id = raw_inode.id;
        let block_size = self.volume.superblock.block_size();
        raw_inode.initialize_directory(metadata, self.now, u64::from(block_size.bytes()), block)?;

        let mut directory = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        directory.initialize_dot_entries(inode_id, parent.inode_id())?;
        self.directory_updates.push(BlockImage {
            block,
            bytes: directory.into_bytes(),
        });

        self.add_directory_entry(
            parent.inode_id(),
            name,
            inode_id,
            DirectoryEntryKind::Directory,
        )?;
        self.increment_directory_links(parent.inode_id())?;
        let (group, _) = inode_group_bit(&self.volume.superblock, inode_id)?;
        self.record_group_used_dirs_delta(group, 1)?;
        self.inode_updates.push(raw_inode);
        Ok(TransactionDirectory { inode_id })
    }

    /// Removes an empty child directory.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, not a directory, not empty,
    /// is the root directory, or metadata cannot be updated.
    pub fn remove_empty_directory(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
    ) -> Result<()> {
        let removed = self.find_child_entry(parent.inode_id(), name)?;
        if removed.inode() == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let inode_index = self.ensure_inode_update(removed.inode())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if !inode.supports_basic_mutation() {
            return Err(Error::UnsupportedInodeMutation);
        }
        if !self.directory_is_empty(&inode)? {
            return Err(Error::DirectoryNotEmpty);
        }
        let _removed = self.remove_directory_entry(parent.inode_id(), name)?;
        let extents = ExtentTree::parse_inode_root(inode.extent_root()?)?
            .extents()
            .to_vec();
        for extent in extents {
            self.free_extent(extent, 0)?;
        }
        self.free_inode(raw_inode.id)?;
        raw_inode.clear_deleted(self.now)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        self.decrement_directory_links(parent.inode_id())?;
        let (group, _) = inode_group_bit(&self.volume.superblock, removed.inode())?;
        self.record_group_used_dirs_delta(group, -1)
    }

    /// Overwrites bytes inside an existing regular file range.
    ///
    /// # Errors
    /// Returns an error when the inode is not a regular file, the range extends
    /// beyond EOF, allocation fails, or the updated root extent set cannot fit
    /// in the inode.
    pub fn overwrite_file_range(
        &mut self,
        file: TransactionFile,
        offset: FileOffset,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let inode_index = self.ensure_inode_update(file.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::File {
            return Err(Error::WrongInodeKind);
        }
        let end_offset = offset.checked_add_len(bytes.len())?;
        if end_offset.bytes() > inode.size().bytes() {
            return Err(Error::InvalidWriteRange);
        }

        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let block_size = usize::try_from(block_size_u64).map_err(|_| Error::ArithmeticOverflow)?;
        let mut extents = ExtentTree::parse_inode_root(inode.extent_root()?)?
            .extents()
            .to_vec();
        let mut completed = 0_usize;

        while completed < bytes.len() {
            let position = offset
                .bytes()
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

            let logical_block = LogicalBlock::try_from(logical_block)?;
            if let BlockMapping::Physical(physical) = map_extents(&extents, logical_block) {
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
                insert_or_extend_extent(&mut extents, logical_block, physical)?;
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
    /// Returns an error when `new_size` would shrink the file.
    pub fn extend_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
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
    /// Returns an error when `new_size` would extend the file or root extent
    /// updates cannot fit in the inode.
    pub fn truncate_file(&mut self, file: TransactionFile, new_size: FileSize) -> Result<()> {
        let inode_index = self.ensure_inode_update(file.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if new_size > inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let extents = ExtentTree::parse_inode_root(inode.extent_root()?)?
            .extents()
            .to_vec();
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
                updated.push(Extent::new(
                    extent.logical_start(),
                    ExtentLength::new(keep_len)?,
                    extent.physical_start(),
                ));
            } else {
                updated.push(extent);
            }
        }
        if new_size
            .bytes()
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

    fn ensure_child_absent(&self, parent: InodeId, name: &Ext4Name) -> Result<()> {
        match self.find_child_entry(parent, name) {
            Ok(_) => Err(Error::NameAlreadyExists),
            Err(Error::DirectoryEntryNotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn find_child_entry(&self, parent: InodeId, name: &Ext4Name) -> Result<DirectoryEntry> {
        let inode = self.volume.read_inode_record(parent)?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        for (_logical, _physical, block) in self.directory_blocks(&inode)? {
            for entry in block.entries()? {
                if entry.name() == name {
                    return Ok(entry);
                }
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    fn add_directory_entry(
        &mut self,
        parent: InodeId,
        name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
    ) -> Result<()> {
        let inode_index = self.ensure_inode_update(parent)?;
        let mut raw_parent = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if !parent_inode.supports_basic_mutation() {
            return Err(Error::UnsupportedInodeMutation);
        }

        for (logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if parent_inode.is_indexed_directory() && logical.as_u32() == 0 {
                continue;
            }
            if block.insert(child, name, kind)? {
                self.directory_updates.push(BlockImage {
                    block: physical,
                    bytes: block.into_bytes(),
                });
                raw_parent.set_timestamps(self.now)?;
                *self
                    .inode_updates
                    .get_mut(inode_index)
                    .ok_or(Error::InvalidInode)? = raw_parent;
                return Ok(());
            }
        }
        if parent_inode.is_indexed_directory() {
            return Err(Error::NoSpace);
        }

        let block_size = self.volume.superblock.block_size();
        let block_size_u64 = u64::from(block_size.bytes());
        let new_physical = self.allocate_block()?;
        let mut extents = ExtentTree::parse_inode_root(parent_inode.extent_root()?)?
            .extents()
            .to_vec();
        let logical_block =
            LogicalBlock::try_from(round_up_div(parent_inode.size().bytes(), block_size_u64)?)?;
        insert_or_extend_extent(&mut extents, logical_block, new_physical)?;

        let mut block = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        block.initialize_free_space()?;
        let inserted = block.insert(child, name, kind)?;
        if !inserted {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.directory_updates.push(BlockImage {
            block: new_physical,
            bytes: block.into_bytes(),
        });
        raw_parent.set_size(FileSize::from_bytes(
            parent_inode
                .size()
                .bytes()
                .checked_add(block_size_u64)
                .ok_or(Error::ArithmeticOverflow)?,
        ))?;
        raw_parent.set_timestamps(self.now)?;
        raw_parent.set_extent_root(&extents)?;
        raw_parent.set_allocated_blocks(extents_allocated_blocks(&extents), block_size_u64)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_parent;
        Ok(())
    }

    fn remove_directory_entry(
        &mut self,
        parent: InodeId,
        name: &Ext4Name,
    ) -> Result<DirectoryEntry> {
        let inode_index = self.ensure_inode_update(parent)?;
        let mut raw_parent = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let parent_inode = raw_parent.parse()?;
        if parent_inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        if !parent_inode.supports_basic_mutation() {
            return Err(Error::UnsupportedInodeMutation);
        }
        for (logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if parent_inode.is_indexed_directory() && logical.as_u32() == 0 {
                continue;
            }
            if let Some(removed) = block.remove(name)? {
                self.directory_updates.push(BlockImage {
                    block: physical,
                    bytes: block.into_bytes(),
                });
                raw_parent.set_timestamps(self.now)?;
                *self
                    .inode_updates
                    .get_mut(inode_index)
                    .ok_or(Error::InvalidInode)? = raw_parent;
                return Ok(removed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    fn directory_is_empty(&self, inode: &Inode) -> Result<bool> {
        for (_logical, _physical, block) in self.directory_blocks(inode)? {
            if !block.is_empty_directory_payload()? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn directory_blocks(
        &self,
        inode: &Inode,
    ) -> Result<Vec<(LogicalBlock, BlockAddress, DirectoryBlock)>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_count = round_up_div(inode.size().bytes(), u64::from(block_size.bytes()))?;
        let tree =
            ExtentTree::load_inode_tree(inode.extent_root()?, block_size, &self.volume.device)?;
        let mut blocks = Vec::new();
        for logical in 0..block_count {
            let logical = LogicalBlock::try_from(logical)?;
            let BlockMapping::Physical(physical) = tree.map_logical(logical) else {
                return Err(Error::InvalidDirectoryEntry);
            };
            let mut bytes = vec![0_u8; block_bytes];
            self.volume
                .device
                .read_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
            blocks.push((logical, physical, DirectoryBlock::new(bytes)));
        }
        Ok(blocks)
    }

    fn increment_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        raw_inode.increment_links_count()?;
        raw_inode.set_timestamps(self.now)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    fn decrement_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let _links = raw_inode.decrement_links_count()?;
        raw_inode.set_timestamps(self.now)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Aborts the transaction without writing staged data or metadata.
    pub fn abort(self) {}

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
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            let descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                group,
            )?;
            if descriptor.free_blocks_count() == 0 {
                continue;
            }
            let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
            let group_start = self
                .volume
                .superblock
                .first_data_block()
                .get()
                .checked_add(
                    u64::from(group.as_u32())
                        .checked_mul(u64::from(
                            self.volume.superblock.blocks_per_group().as_u32(),
                        ))
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            let blocks_in_group = self.blocks_in_group(group)?;
            for bit in 0..blocks_in_group {
                let absolute_block = group_start
                    .checked_add(u64::from(bit))
                    .ok_or(Error::ArithmeticOverflow)?;
                if absolute_block >= self.volume.superblock.block_count().as_u64() {
                    break;
                }
                let bitmap = self
                    .block_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                if !bitmap_bit(bitmap.bytes.as_slice(), bit)? {
                    set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, true)?;
                    self.record_group_free_blocks_delta(group, FreeBlockDelta::from_i64(-1))?;
                    self.free_blocks_delta = self.free_blocks_delta.checked_add(-1)?;
                    return Ok(BlockAddress::new(absolute_block));
                }
            }
        }
        Err(Error::NoSpace)
    }

    fn free_extent(&mut self, extent: Extent, keep_len: u16) -> Result<()> {
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
        let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
        let bitmap = self
            .block_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        let bit = block_bit_in_group(&self.volume.superblock, block, group)?;
        if bitmap_bit(bitmap.bytes.as_slice(), bit)? {
            set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, false)?;
            self.record_group_free_blocks_delta(group, FreeBlockDelta::from_i64(1))?;
            self.free_blocks_delta = self.free_blocks_delta.checked_add(1)?;
        }
        Ok(())
    }

    fn allocate_inode(&mut self) -> Result<RawInode> {
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
                let inode_id = self.inode_id_in_group(group, bit)?;
                if inode_id.as_u32() < self.volume.superblock.first_inode().as_u32() {
                    continue;
                }
                let bitmap = self
                    .inode_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                if !bitmap_bit(bitmap.bytes.as_slice(), bit)? {
                    set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, true)?;
                    self.record_group_free_inodes_delta(group, -1)?;
                    return self.empty_raw_inode(inode_id);
                }
            }
        }
        Err(Error::NoFreeInode)
    }

    fn free_inode(&mut self, inode_id: InodeId) -> Result<()> {
        if inode_id == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let (group, bit) = inode_group_bit(&self.volume.superblock, inode_id)?;
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_inode_bitmap_update(descriptor.inode_bitmap())?;
        let bitmap = self
            .inode_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        if bitmap_bit(bitmap.bytes.as_slice(), bit)? {
            set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, false)?;
            self.record_group_free_inodes_delta(group, 1)?;
        }
        Ok(())
    }

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
        self.data_writes.push(RangeWrite {
            offset: ByteOffset::new(offset),
            bytes: vec![0_u8; usize::try_from(zero_len).map_err(|_| Error::ArithmeticOverflow)?],
        });
        Ok(())
    }

    fn ensure_block_bitmap_update(&mut self, bitmap_block: BlockAddress) -> Result<usize> {
        if let Some(index) = self
            .block_bitmap_updates
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
        self.block_bitmap_updates.push(BlockImage {
            block: bitmap_block,
            bytes,
        });
        self.block_bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    fn ensure_inode_bitmap_update(&mut self, bitmap_block: BlockAddress) -> Result<usize> {
        if let Some(index) = self
            .inode_bitmap_updates
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
        self.inode_bitmap_updates.push(BlockImage {
            block: bitmap_block,
            bytes,
        });
        self.inode_bitmap_updates
            .len()
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    fn blocks_in_group(&self, group: BlockGroupId) -> Result<u32> {
        let group_start = self
            .volume
            .superblock
            .first_data_block()
            .get()
            .checked_add(
                u64::from(group.as_u32())
                    .checked_mul(u64::from(
                        self.volume.superblock.blocks_per_group().as_u32(),
                    ))
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        let remaining = self
            .volume
            .superblock
            .block_count()
            .as_u64()
            .checked_sub(group_start)
            .ok_or(Error::InvalidSuperblock)?;
        Ok(core::cmp::min(
            self.volume.superblock.blocks_per_group().as_u32(),
            u32::try_from(remaining).unwrap_or(u32::MAX),
        ))
    }

    fn inodes_in_group(&self, group: BlockGroupId) -> Result<u32> {
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

    fn inode_id_in_group(&self, group: BlockGroupId, bit: u32) -> Result<InodeId> {
        let zero_based = group
            .as_u32()
            .checked_mul(self.volume.superblock.inodes_per_group().as_u32())
            .ok_or(Error::ArithmeticOverflow)?
            .checked_add(bit)
            .ok_or(Error::ArithmeticOverflow)?;
        InodeId::try_from(zero_based.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }

    fn empty_raw_inode(&self, inode_id: InodeId) -> Result<RawInode> {
        Ok(RawInode {
            id: inode_id,
            offset: inode_offset_on_device(&self.volume.device, &self.volume.superblock, inode_id)?,
            bytes: vec![0_u8; usize::from(self.volume.superblock.inode_size().as_u16())],
        })
    }

    fn group_delta_mut(&mut self, group: BlockGroupId) -> Result<&mut GroupDelta> {
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
        self.group_deltas.push(GroupDelta::new(group));
        self.group_deltas.last_mut().ok_or(Error::InvalidSuperblock)
    }

    fn record_group_free_blocks_delta(
        &mut self,
        group: BlockGroupId,
        delta: FreeBlockDelta,
    ) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.free_blocks_delta = entry.free_blocks_delta.checked_add(delta.as_i64())?;
        Ok(())
    }

    fn record_group_free_inodes_delta(&mut self, group: BlockGroupId, delta: i64) -> Result<()> {
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

    fn record_group_used_dirs_delta(&mut self, group: BlockGroupId, delta: i64) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.used_dirs_delta = entry
            .used_dirs_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    fn metadata_writes(&mut self) -> Result<Vec<RangeWrite>> {
        let mut writes = Vec::new();
        for bitmap in &self.block_bitmap_updates {
            writes.push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: bitmap.bytes.clone(),
            });
        }
        for bitmap in &self.inode_bitmap_updates {
            writes.push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(bitmap.block)?,
                bytes: bitmap.bytes.clone(),
            });
        }
        for directory in &self.directory_updates {
            writes.push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(directory.block)?,
                bytes: directory.bytes.clone(),
            });
        }
        for delta in &self.group_deltas {
            let mut descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
                &self.volume.superblock,
                delta.group,
            )?;
            if !delta.free_blocks_delta.is_zero() {
                descriptor.apply_free_blocks_delta(
                    delta.free_blocks_delta,
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
            writes.push(RangeWrite {
                offset: descriptor.offset(),
                bytes: descriptor.bytes().to_vec(),
            });
        }
        if !self.free_blocks_delta.is_zero() || self.free_inodes_delta != 0 {
            writes.push(RangeWrite {
                offset: ByteOffset::new(SUPERBLOCK_OFFSET),
                bytes: self.updated_superblock_bytes()?,
            });
        }
        for inode in &self.inode_updates {
            let mut inode = inode.clone();
            inode.refresh_checksum(&self.volume.superblock)?;
            writes.push(RangeWrite {
                offset: inode.offset,
                bytes: inode.bytes.clone(),
            });
        }
        Ok(writes)
    }

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
                .position(|metadata: &MetadataBlock| metadata.block == block)
            {
                index
            } else {
                let mut bytes = vec![0_u8; block_bytes];
                self.volume
                    .device
                    .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
                blocks.push(MetadataBlock { block, bytes });
                blocks
                    .len()
                    .checked_sub(1)
                    .ok_or(Error::ArithmeticOverflow)?
            };
            blocks
                .get_mut(index)
                .ok_or(Error::InvalidSuperblock)?
                .bytes
                .get_mut(in_block..end)
                .ok_or(Error::DeviceRange)?
                .copy_from_slice(&write.bytes);
        }

        Ok(blocks)
    }

    fn write_ordered_data(&mut self) -> Result<()> {
        for write in &self.data_writes {
            self.volume
                .device
                .write_exact_at(write.offset, write.bytes.as_slice())?;
        }
        self.volume.device.flush()
    }

    fn updated_superblock_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0_u8; 1024];
        self.volume
            .device
            .read_exact_at(ByteOffset::new(SUPERBLOCK_OFFSET), &mut bytes)?;
        let current = u64::from(le_u32(&bytes, SUPERBLOCK_FREE_BLOCKS_LO_OFFSET)?)
            | if self.volume.superblock.descriptor_layout().has_high_fields() {
                u64::from(le_u32(&bytes, SUPERBLOCK_FREE_BLOCKS_HI_OFFSET)?) << 32
            } else {
                0
            };
        let raw_delta = self.free_blocks_delta.as_i64();
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
            SUPERBLOCK_FREE_BLOCKS_LO_OFFSET,
            u32::try_from(updated & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.volume.superblock.descriptor_layout().has_high_fields() {
            put_le_u32(
                &mut bytes,
                SUPERBLOCK_FREE_BLOCKS_HI_OFFSET,
                u32::try_from(updated >> 32).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        if self.free_inodes_delta != 0 {
            let current = u64::from(le_u32(&bytes, SUPERBLOCK_FREE_INODES_OFFSET)?);
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
                SUPERBLOCK_FREE_INODES_OFFSET,
                u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Superblock::refresh_checksum(&mut bytes)?;
        Ok(bytes)
    }
}

impl<D: BlockWriter> WriteTransaction<'_, D, InternalJournal> {
    /// Commits staged data and metadata through the internal journal.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub fn commit(mut self) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let metadata_blocks = self.metadata_blocks()?;
        self.volume
            .state
            .journal
            .journal
            .ensure_transaction_capacity(metadata_blocks.len())?;
        self.write_ordered_data()?;

        let volume = self.volume;
        volume.state.journal.journal.commit_internal(
            &mut volume.device,
            block_size,
            &metadata_blocks,
        )
    }
}

impl<D: BlockWriter, J: BlockWriter> WriteTransaction<'_, D, ExternalJournal<J>> {
    /// Commits staged data and metadata through the external journal device.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub fn commit(mut self) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let metadata_blocks = self.metadata_blocks()?;
        self.volume
            .state
            .journal
            .journal
            .ensure_transaction_capacity(metadata_blocks.len())?;
        self.write_ordered_data()?;

        let volume = self.volume;
        let journal = &mut volume.state.journal;
        journal.journal.commit_external(
            &mut volume.device,
            &mut journal.device,
            block_size,
            &metadata_blocks,
        )
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

    fn initialize_file(&mut self, metadata: NewFileMetadata, now: Ext4Timestamp) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(MODE_REGULAR, metadata.permissions())?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(0))?;
        self.set_links_count(1)?;
        self.set_timestamps(now)?;
        self.set_creation_time(now)?;
        self.set_deletion_time(0)?;
        self.set_flags(EXT4_EXTENTS_FL)?;
        self.set_extent_root(&[])?;
        self.set_allocated_blocks(0, 1024)
    }

    fn initialize_directory(
        &mut self,
        metadata: NewDirectoryMetadata,
        now: Ext4Timestamp,
        block_size: u64,
        first_block: BlockAddress,
    ) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(MODE_DIRECTORY, metadata.permissions())?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(block_size))?;
        self.set_links_count(2)?;
        self.set_timestamps(now)?;
        self.set_creation_time(now)?;
        self.set_deletion_time(0)?;
        self.set_flags(EXT4_EXTENTS_FL)?;
        self.set_extent_root(&[Extent::new(
            LogicalBlock::from_u32(0),
            ExtentLength::new(1)?,
            first_block,
        )])?;
        self.set_allocated_blocks(1, block_size)
    }

    fn set_mode(&mut self, file_type: u16, permissions: Ext4Permissions) -> Result<()> {
        put_le_u16(
            &mut self.bytes,
            INODE_MODE_OFFSET,
            file_type | permissions.as_u16(),
        )
    }

    fn set_owner(&mut self, owner: Ext4Owner) -> Result<()> {
        let uid = owner.uid().as_u32();
        let gid = owner.gid().as_u32();
        put_le_u16(
            &mut self.bytes,
            INODE_UID_LO_OFFSET,
            u16::try_from(uid & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_le_u16(
            &mut self.bytes,
            INODE_GID_LO_OFFSET,
            u16::try_from(gid & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.bytes.len() > INODE_UID_HI_OFFSET {
            put_le_u16(
                &mut self.bytes,
                INODE_UID_HI_OFFSET,
                u16::try_from(uid >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_le_u16(
                &mut self.bytes,
                INODE_GID_HI_OFFSET,
                u16::try_from(gid >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    fn set_links_count(&mut self, links: u16) -> Result<()> {
        put_le_u16(&mut self.bytes, INODE_LINKS_COUNT_OFFSET, links)
    }

    fn increment_links_count(&mut self) -> Result<()> {
        let links = self.parse()?.links_count();
        self.set_links_count(links.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }

    fn decrement_links_count(&mut self) -> Result<u16> {
        let links = self.parse()?.links_count();
        let updated = links.checked_sub(1).ok_or(Error::InvalidInode)?;
        self.set_links_count(updated)?;
        Ok(updated)
    }

    fn set_flags(&mut self, flags: u32) -> Result<()> {
        put_le_u32(&mut self.bytes, INODE_FLAGS_OFFSET, flags)
    }

    fn set_size(&mut self, size: FileSize) -> Result<()> {
        let size = size.bytes();
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
        put_le_u32(&mut self.bytes, INODE_ATIME_OFFSET, now.seconds())?;
        put_le_u32(&mut self.bytes, INODE_CTIME_OFFSET, now.seconds())?;
        put_le_u32(&mut self.bytes, INODE_MTIME_OFFSET, now.seconds())?;
        if self.bytes.len() > INODE_ATIME_EXTRA_OFFSET {
            put_le_u32(&mut self.bytes, INODE_ATIME_EXTRA_OFFSET, 0)?;
            put_le_u32(&mut self.bytes, INODE_CTIME_EXTRA_OFFSET, 0)?;
            put_le_u32(&mut self.bytes, INODE_MTIME_EXTRA_OFFSET, 0)?;
        }
        Ok(())
    }

    fn set_creation_time(&mut self, now: Ext4Timestamp) -> Result<()> {
        if self.bytes.len() > INODE_CRTIME_EXTRA_OFFSET {
            self.ensure_extra_isize()?;
            put_le_u32(&mut self.bytes, INODE_CRTIME_OFFSET, now.seconds())?;
            put_le_u32(&mut self.bytes, INODE_CRTIME_EXTRA_OFFSET, 0)?;
        }
        Ok(())
    }

    fn set_deletion_time(&mut self, seconds: u32) -> Result<()> {
        put_le_u32(&mut self.bytes, INODE_DTIME_OFFSET, seconds)
    }

    fn clear_deleted(&mut self, now: Ext4Timestamp) -> Result<()> {
        self.set_deletion_time(now.seconds())?;
        self.set_links_count(0)?;
        self.set_size(FileSize::from_bytes(0))?;
        self.set_allocated_blocks(0, 1024)?;
        self.set_extent_root(&[])
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

    fn refresh_checksum(&mut self, superblock: &Superblock) -> Result<()> {
        if superblock.metadata_checksum() != MetadataChecksum::Crc32c {
            return Ok(());
        }
        if self.bytes.len() <= INODE_CHECKSUM_LO_OFFSET {
            return Ok(());
        }
        self.ensure_extra_isize()?;
        put_le_u16(&mut self.bytes, INODE_CHECKSUM_LO_OFFSET, 0)?;
        if self.bytes.len() > INODE_CHECKSUM_HI_OFFSET {
            put_le_u16(&mut self.bytes, INODE_CHECKSUM_HI_OFFSET, 0)?;
        }
        let seed = crc32c(
            superblock.checksum_seed().as_u32(),
            &self.id.as_u32().to_le_bytes(),
        );
        let seed = crc32c(
            seed,
            &le_u32(&self.bytes, INODE_GENERATION_OFFSET)?.to_le_bytes(),
        );
        let checksum = crc32c(seed, &self.bytes);
        put_le_u16(
            &mut self.bytes,
            INODE_CHECKSUM_LO_OFFSET,
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if self.bytes.len() > INODE_CHECKSUM_HI_OFFSET {
            put_le_u16(
                &mut self.bytes,
                INODE_CHECKSUM_HI_OFFSET,
                u16::try_from(checksum >> 16).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    fn ensure_extra_isize(&mut self) -> Result<()> {
        if self.bytes.len() > INODE_EXTRA_ISIZE_OFFSET
            && le_u16(&self.bytes, INODE_EXTRA_ISIZE_OFFSET)? == 0
        {
            put_le_u16(
                &mut self.bytes,
                INODE_EXTRA_ISIZE_OFFSET,
                EXT4_INODE_MIN_EXTRA_ISIZE,
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
    group: BlockGroupId,
    free_blocks_delta: FreeBlockDelta,
    free_inodes_delta: i64,
    used_dirs_delta: i64,
}

impl GroupDelta {
    fn new(group: BlockGroupId) -> Self {
        Self {
            group,
            free_blocks_delta: FreeBlockDelta::ZERO,
            free_inodes_delta: 0,
            used_dirs_delta: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RangeWrite {
    offset: ByteOffset,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MetadataBlock {
    block: BlockAddress,
    bytes: Vec<u8>,
}

impl MetadataBlock {
    pub(crate) const fn block(&self) -> BlockAddress {
        self.block
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn map_extents(extents: &[Extent], logical_block: LogicalBlock) -> BlockMapping {
    for extent in extents {
        if let BlockMapping::Physical(block) = extent.map_logical(logical_block) {
            return BlockMapping::Physical(block);
        }
    }
    BlockMapping::Hole
}

fn insert_or_extend_extent(
    extents: &mut Vec<Extent>,
    logical_block: LogicalBlock,
    physical_block: BlockAddress,
) -> Result<()> {
    if let Some(last) = extents.last_mut()
        && last.end_logical()? == logical_block.as_u32()
        && last
            .physical_start()
            .get()
            .checked_add(last.len().as_u64())
            .ok_or(Error::ArithmeticOverflow)?
            == physical_block.get()
    {
        let len = last.len().checked_add_one()?;
        *last = Extent::new(last.logical_start(), len, last.physical_start());
        return Ok(());
    }
    extents.push(Extent::new(
        logical_block,
        ExtentLength::new(1)?,
        physical_block,
    ));
    extents.sort_by_key(|extent| extent.logical_start());
    Ok(())
}

fn extents_allocated_blocks(extents: &[Extent]) -> u64 {
    extents.iter().map(|extent| extent.len().as_u64()).sum()
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

fn block_group_of(superblock: &Superblock, block: BlockAddress) -> Result<BlockGroupId> {
    let relative = block
        .get()
        .checked_sub(superblock.first_data_block().get())
        .ok_or(Error::InvalidSuperblock)?;
    let group = relative
        .checked_div(u64::from(superblock.blocks_per_group().as_u32()))
        .ok_or(Error::InvalidSuperblock)?;
    Ok(BlockGroupId::from_u32(
        u32::try_from(group).map_err(|_| Error::ArithmeticOverflow)?,
    ))
}

fn inode_group_bit(superblock: &Superblock, inode_id: InodeId) -> Result<(BlockGroupId, u32)> {
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
    Ok((BlockGroupId::from_u32(group), bit))
}

fn inode_offset_on_device(
    reader: &impl BlockReader,
    superblock: &Superblock,
    inode_id: InodeId,
) -> Result<ByteOffset> {
    let (group, index) = inode_group_bit(superblock, inode_id)?;
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
    let inode_size = u64::from(superblock.inode_size().as_u16());
    let offset = superblock
        .block_size()
        .offset_of(descriptor.inode_table())?
        .get()
        .checked_add(
            u64::from(index)
                .checked_mul(inode_size)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(ByteOffset::new(offset))
}

fn block_bit_in_group(
    superblock: &Superblock,
    block: BlockAddress,
    group: BlockGroupId,
) -> Result<u32> {
    let group_start = superblock
        .first_data_block()
        .get()
        .checked_add(
            u64::from(group.as_u32())
                .checked_mul(u64::from(superblock.blocks_per_group().as_u32()))
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
