//! Mounted ext4 volume state and journaled write transactions.

use alloc::{vec, vec::Vec};

use crate::acl::{PosixAcl, PosixAclKind};
use crate::block::{BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset};
use crate::checksum::crc32c;
use crate::dir::{
    DirectoryBlock, DirectoryBlockData, DirectoryChecksum, DirectoryEntry, DirectoryEntryKind,
    DirectoryLayout, build_htree_directory,
};
use crate::endian::{le_u16, le_u32, put_le_u16, put_le_u32};
use crate::error::{Error, Result};
use crate::extent::{
    BlockMapping, Extent, ExtentLength, ExtentTree, ExtentTreeContext, LogicalBlock,
    MutableExtentTree, SerializedExtentTree,
};
use crate::fscrypt::{
    FscryptContentsKey, FscryptContextV2, FscryptFileNonce, FscryptFilenamePadding,
    FscryptFilenamesKey, FscryptKeyIdentifier, FscryptKeySet, FscryptMasterKey, FscryptNoKeyName,
    FscryptNoNonceGenerator, FscryptNonceGenerator,
};
use crate::group::BlockGroupDescriptor;
use crate::inode::{
    Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp, FileOffset, FileSize,
    Inode, InodeId, InodeKind, InodeMutation, InodeProtection, InodeStorage, NewDirectoryMetadata,
    NewFileMetadata, NewSymlinkMetadata, ReadBytes, SymlinkTarget,
};
use crate::journal::{Journal, LoadedJournal};
use crate::name::Ext4Name;
use crate::name::WindowsName;
use crate::superblock::{
    BlockGroupId, ClusterAddress, DirectoryIndexing, Ext4VolumeLabel, FreeClusterDelta,
    InodeTimestampEncoding, JournalMode, MetadataChecksum, RecoveryState, SparseSuperblockLayout,
    Superblock, XattrMutationSupport,
};
use crate::verity::{
    Ext4VerityMetadata, Ext4VerityMetadataLayout, FSVERITY_DESCRIPTOR_BYTES, FsverityDescriptor,
    FsverityEnable, FsverityMerkleTree,
};
use crate::windows::WindowsOverlay;
use crate::xattr::{self as xattr_storage, InodeXattrSet, XattrName, XattrSet, XattrValue};

// Volume mutation offsets are kept together so inode/superblock rewrites use one
// source of truth for on-disk byte layout.
/// Maximum directory size read eagerly for lookup and enumeration.
const MAX_EAGER_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
/// `i_mode` type bits for ext4 directories.
const MODE_DIRECTORY: u16 = 0x4000;
/// `i_mode` type bits for regular files.
const MODE_REGULAR: u16 = 0x8000;
/// `i_mode` type bits for symbolic links.
const MODE_SYMLINK: u16 = 0xA000;
/// `i_mode` mask that preserves inode type bits.
const MODE_KIND_MASK: u16 = 0xF000;
/// `i_flags` bit indicating extent-based block mapping.
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// `i_flags` bit indicating an HTree-indexed directory.
const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// `i_flags` bit indicating fscrypt-protected file contents or dirent names.
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
/// `i_flags` bit indicating fs-verity protected file contents.
const EXT4_VERITY_FL: u32 = 0x0010_0000;
/// Offset of `i_mode` in an inode record.
const INODE_MODE_OFFSET: usize = 0;
/// Offset of `i_uid_lo` in an inode record.
const INODE_UID_LO_OFFSET: usize = 2;
/// Offset of `i_size_lo` in an inode record.
const INODE_SIZE_LO_OFFSET: usize = 4;
/// Offset of `i_atime` in an inode record.
const INODE_ATIME_OFFSET: usize = 8;
/// Offset of `i_ctime` in an inode record.
const INODE_CTIME_OFFSET: usize = 12;
/// Offset of `i_mtime` in an inode record.
const INODE_MTIME_OFFSET: usize = 16;
/// Offset of `i_dtime` in an inode record.
const INODE_DTIME_OFFSET: usize = 20;
/// Offset of `i_gid_lo` in an inode record.
const INODE_GID_LO_OFFSET: usize = 24;
/// Offset of `i_links_count` in an inode record.
const INODE_LINKS_COUNT_OFFSET: usize = 26;
/// Offset of `i_blocks_lo` in an inode record.
const INODE_BLOCKS_LO_OFFSET: usize = 28;
/// Offset of `i_flags` in an inode record.
const INODE_FLAGS_OFFSET: usize = 32;
/// Offset of `i_block` in an inode record.
const INODE_BLOCK_OFFSET: usize = 40;
/// Offset of `i_generation` in an inode record.
const INODE_GENERATION_OFFSET: usize = 100;
/// Offset of `i_file_acl_lo` in an inode record.
const INODE_FILE_ACL_LO_OFFSET: usize = 104;
/// Offset of `i_size_high` in an inode record.
const INODE_SIZE_HIGH_OFFSET: usize = 108;
/// Offset of `i_blocks_high` in an inode record.
const INODE_BLOCKS_HIGH_OFFSET: usize = 116;
/// Offset of `i_file_acl_high` in an inode record.
const INODE_FILE_ACL_HI_OFFSET: usize = 118;
/// Offset of `i_checksum_lo` in an inode record.
const INODE_CHECKSUM_LO_OFFSET: usize = 124;
/// Offset of `i_extra_isize` in an inode record.
const INODE_EXTRA_ISIZE_OFFSET: usize = 128;
/// Offset of `i_ctime_extra` in an inode record.
const INODE_CTIME_EXTRA_OFFSET: usize = 132;
/// Offset of `i_mtime_extra` in an inode record.
const INODE_MTIME_EXTRA_OFFSET: usize = 136;
/// Offset of `i_atime_extra` in an inode record.
const INODE_ATIME_EXTRA_OFFSET: usize = 140;
/// Offset of `i_crtime` in an inode record.
const INODE_CRTIME_OFFSET: usize = 144;
/// Offset of `i_crtime_extra` in an inode record.
const INODE_CRTIME_EXTRA_OFFSET: usize = 148;
/// Offset of `i_uid_high` in an inode record.
const INODE_UID_HI_OFFSET: usize = 120;
/// Offset of `i_gid_high` in an inode record.
const INODE_GID_HI_OFFSET: usize = 122;
/// Offset of `i_checksum_hi` in an inode record.
const INODE_CHECKSUM_HI_OFFSET: usize = 130;
/// Minimum ext4 extra inode size required for checksum and creation-time fields.
const EXT4_INODE_MIN_EXTRA_ISIZE: u16 = 32;
/// Largest regular-file size accepted when `large_file` is absent.
const LEGACY_FILE_SIZE_LIMIT: u64 = 0x7fff_ffff;
/// Largest 512-byte sector count accepted when `huge_file` is absent.
const LEGACY_I_BLOCKS_LIMIT: u64 = 0xffff_ffff;
/// Offset of `s_free_blocks_count_lo` in the superblock.
const SUPERBLOCK_FREE_BLOCKS_LO_OFFSET: usize = 12;
/// Offset of `s_free_inodes_count` in the superblock.
const SUPERBLOCK_FREE_INODES_OFFSET: usize = 16;
/// Offset of `s_free_blocks_count_hi` in the superblock.
const SUPERBLOCK_FREE_BLOCKS_HI_OFFSET: usize = 344;
/// Byte offset of the primary ext4 superblock.
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Read-only mounted volume state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnly;

/// Mount-time context that keeps external fscrypt material out of superblock parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountContext<N = FscryptNoNonceGenerator> {
    /// fscrypt master keys available for this mount.
    fscrypt_keys: FscryptKeySet,
    /// Source of fresh nonces for newly-created encrypted inodes.
    fscrypt_nonce_generator: N,
}

impl<N> MountContext<N> {
    /// Creates a mount context with explicit fscrypt keys and nonce source.
    #[must_use]
    pub const fn new(fscrypt_keys: FscryptKeySet, fscrypt_nonce_generator: N) -> Self {
        Self {
            fscrypt_keys,
            fscrypt_nonce_generator,
        }
    }

    /// fscrypt master keys available to this mount.
    #[must_use]
    pub const fn fscrypt_keys(&self) -> &FscryptKeySet {
        &self.fscrypt_keys
    }

    /// Returns the next fscrypt nonce for a new encrypted inode.
    fn next_fscrypt_file_nonce(&mut self) -> Result<FscryptFileNonce>
    where
        N: FscryptNonceGenerator,
    {
        self.fscrypt_nonce_generator.next_file_nonce()
    }

    /// Adds one fscrypt master key to this mount context.
    ///
    /// # Errors
    /// Returns an error when the key identifier is already present.
    pub fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Result<()> {
        self.fscrypt_keys.insert(key)
    }

    /// Removes one fscrypt master key from this mount context.
    #[must_use]
    pub fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.fscrypt_keys.remove(identifier)
    }

    /// Returns whether this mount context contains a key identifier.
    #[must_use]
    pub fn contains_fscrypt_key(&self, identifier: FscryptKeyIdentifier) -> bool {
        self.fscrypt_keys.contains(identifier)
    }
}

/// Journal stored as a hidden ext4 inode on the filesystem device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalJournal {
    /// Clean journal state ready to accept write transactions.
    journal: Journal,
}

/// External journal stored on a separate journal device.
#[derive(Debug)]
pub struct ExternalJournal<J> {
    /// External journal block device.
    device: J,
    /// Clean journal state loaded from the external device.
    journal: Journal,
}

/// Journaled read-write mounted volume state.
#[derive(Debug)]
pub struct ReadWrite<J = InternalJournal> {
    /// Journal backend selected at mount.
    journal: J,
    /// Mounted cluster reference counts constructed before any mutation.
    clusters: ClusterReferenceIndex,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Mounted allocation-cluster ownership index used by write transactions.
struct ClusterReferenceIndex {
    /// Reference count per allocation cluster with at least one known owner.
    refs: Vec<ClusterReference>,
    /// Physical blocks that must have exclusive ownership.
    exclusive_blocks: Vec<BlockAddress>,
    /// External xattr blocks that may be shared by ext4 xattr refcount.
    xattr_blocks: Vec<BlockAddress>,
}

impl ClusterReferenceIndex {
    /// Builds the mounted reference index from static metadata and live inodes.
    fn load<D: BlockReader, State, N>(volume: &Volume<D, State, N>) -> Result<Self> {
        let mut index = Self {
            refs: Vec::new(),
            exclusive_blocks: Vec::new(),
            xattr_blocks: Vec::new(),
        };
        index.add_static_metadata(volume)?;
        index.add_live_inodes(volume)?;
        Ok(index)
    }

    /// Returns the known mounted reference count for one cluster.
    fn count(&self, cluster: ClusterAddress) -> u32 {
        self.refs
            .iter()
            .find(|reference| reference.cluster == cluster)
            .map_or(0, |reference| reference.count)
    }

    /// Applies committed staged reference deltas.
    fn apply_deltas(&mut self, deltas: &[ClusterReferenceDelta]) -> Result<()> {
        for delta in deltas {
            let updated = self.apply_delta(delta.cluster, delta.delta)?;
            if updated < 0 {
                return Err(Error::ClusterReferenceConflict);
            }
        }
        Ok(())
    }

    /// Adds one exclusive mounted reference after validating bitmap allocation.
    fn add_exclusive_reference<D: BlockReader, State, N>(
        &mut self,
        volume: &Volume<D, State, N>,
        block: BlockAddress,
    ) -> Result<()> {
        if self.exclusive_blocks.contains(&block) || self.xattr_blocks.contains(&block) {
            return Err(Error::ClusterReferenceConflict);
        }
        self.exclusive_blocks.push(block);
        self.add_cluster_reference(volume, block)
    }

    /// Adds one external-xattr mounted reference after validating bitmap allocation.
    fn add_xattr_reference<D: BlockReader, State, N>(
        &mut self,
        volume: &Volume<D, State, N>,
        block: BlockAddress,
    ) -> Result<()> {
        if self.exclusive_blocks.contains(&block) {
            return Err(Error::ClusterReferenceConflict);
        }
        if !self.xattr_blocks.contains(&block) {
            self.xattr_blocks.push(block);
        }
        self.add_cluster_reference(volume, block)
    }

    /// Adds one mounted cluster reference after validating bitmap allocation.
    fn add_cluster_reference<D: BlockReader, State, N>(
        &mut self,
        volume: &Volume<D, State, N>,
        block: BlockAddress,
    ) -> Result<()> {
        let cluster = volume.superblock.cluster_of_block(block)?;
        if !cluster_bitmap_bit(&volume.device, &volume.superblock, cluster)? {
            return Err(Error::ClusterReferenceConflict);
        }
        self.apply_delta(cluster, 1)?;
        Ok(())
    }

    /// Adds all static metadata ranges that must keep their clusters allocated.
    fn add_static_metadata<D: BlockReader, State, N>(
        &mut self,
        volume: &Volume<D, State, N>,
    ) -> Result<()> {
        let groups = volume.superblock.block_group_count()?;
        let descriptor_blocks = descriptor_table_blocks(&volume.superblock)?;
        for group in 0..groups.as_u32() {
            let group = BlockGroupId::from_u32(group);
            if group_has_superblock(volume, group) {
                let superblock_block = group_start_block(&volume.superblock, group)?;
                self.add_exclusive_reference(volume, superblock_block)?;
                for offset in 0..descriptor_blocks {
                    self.add_exclusive_reference(
                        volume,
                        BlockAddress::new(
                            superblock_block
                                .get()
                                .checked_add(1)
                                .and_then(|value| value.checked_add(offset))
                                .ok_or(Error::ArithmeticOverflow)?,
                        ),
                    )?;
                }
            }

            let descriptor =
                BlockGroupDescriptor::read_from(&volume.device, &volume.superblock, group)?;
            self.add_exclusive_reference(volume, descriptor.block_bitmap())?;
            self.add_exclusive_reference(volume, descriptor.inode_bitmap())?;
            let inode_table_blocks = inode_table_blocks(&volume.superblock, group)?;
            for offset in 0..inode_table_blocks {
                self.add_exclusive_reference(
                    volume,
                    BlockAddress::new(
                        descriptor
                            .inode_table()
                            .get()
                            .checked_add(offset)
                            .ok_or(Error::ArithmeticOverflow)?,
                    ),
                )?;
            }
        }
        Ok(())
    }

    /// Adds data and dynamic metadata references from allocated inode records.
    fn add_live_inodes<D: BlockReader, State, N>(
        &mut self,
        volume: &Volume<D, State, N>,
    ) -> Result<()> {
        for inode_number in 1..=volume.superblock.inode_count().as_u32() {
            let inode_id = InodeId::try_from(inode_number)?;
            if !inode_bitmap_bit(&volume.device, &volume.superblock, inode_id)? {
                continue;
            }
            let raw_inode = volume.read_raw_inode(inode_id)?;
            if raw_inode.mode()? == 0 {
                continue;
            }
            if let Some(block) = raw_inode.xattr_block()? {
                self.add_xattr_reference(volume, block)?;
            }
            let Ok(inode) = raw_inode.parse() else {
                if raw_inode.has_extent_tree()? {
                    return Err(Error::UnsupportedBlockMap);
                }
                continue;
            };
            let root = match inode.storage() {
                InodeStorage::Extents(root) => root,
                InodeStorage::InlineBytes(_) => continue,
                InodeStorage::UnsupportedBlockMap => return Err(Error::UnsupportedBlockMap),
            };
            let tree = ExtentTree::load_inode_tree(
                root,
                volume.superblock.block_size(),
                &volume.device,
                volume.extent_tree_context(&inode),
            )?;
            for extent in tree.extents().iter().copied() {
                self.add_extent_references(volume, extent)?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                self.add_exclusive_reference(volume, block)?;
            }
        }
        Ok(())
    }

    /// Adds references for every physical block represented by an extent.
    fn add_extent_references<D: BlockReader, State, N>(
        &mut self,
        volume: &Volume<D, State, N>,
        extent: Extent,
    ) -> Result<()> {
        for offset in 0..extent.len().as_u64() {
            self.add_exclusive_reference(
                volume,
                BlockAddress::new(
                    extent
                        .physical_start()
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ),
            )?;
        }
        Ok(())
    }

    /// Applies one signed delta and returns the resulting signed count.
    fn apply_delta(&mut self, cluster: ClusterAddress, delta: i32) -> Result<i32> {
        if let Some(index) = self
            .refs
            .iter()
            .position(|reference| reference.cluster == cluster)
        {
            let current = i32::try_from(
                self.refs
                    .get(index)
                    .ok_or(Error::ClusterReferenceConflict)?
                    .count,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let updated = current
                .checked_add(delta)
                .ok_or(Error::ArithmeticOverflow)?;
            if updated <= 0 {
                self.refs.remove(index);
            } else {
                self.refs
                    .get_mut(index)
                    .ok_or(Error::ClusterReferenceConflict)?
                    .count = u32::try_from(updated).map_err(|_| Error::ArithmeticOverflow)?;
            }
            Ok(updated)
        } else if delta > 0 {
            self.refs.push(ClusterReference {
                cluster,
                count: u32::try_from(delta).map_err(|_| Error::ArithmeticOverflow)?,
            });
            Ok(delta)
        } else {
            Ok(delta)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Mounted reference count for one allocation cluster.
struct ClusterReference {
    /// Allocation cluster.
    cluster: ClusterAddress,
    /// Number of known owners in the mounted image.
    count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Staged reference-count delta for one allocation cluster.
struct ClusterReferenceDelta {
    /// Allocation cluster receiving the delta.
    cluster: ClusterAddress,
    /// Signed reference delta.
    delta: i32,
}

/// Mounted ext4 volume with typestate-selected mutation capability.
#[derive(Debug)]
pub struct Volume<D, State, N = FscryptNoNonceGenerator> {
    /// Backing filesystem block device.
    device: D,
    /// Validated superblock and mount policy.
    superblock: Superblock,
    /// External mount context such as fscrypt unlock keys.
    mount_context: MountContext<N>,
    /// Typestate carrying read-only or journaled read-write capability.
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
    /// Wraps a parsed inode in the node type selected by its inode kind.
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
    /// Parsed inode backing this typed file node.
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

    /// POSIX security state parsed from the file inode.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.inode.security()
    }

    /// ext4 timestamps parsed from the file inode.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.inode.times()
    }

    /// Link count parsed from the file inode.
    #[must_use]
    pub const fn links_count(&self) -> u16 {
        self.inode.links_count()
    }

    /// Contents protection selected by file inode flags.
    #[must_use]
    pub const fn protection(&self) -> InodeProtection {
        self.inode.protection()
    }

    /// Returns the backing inode for volume-internal operations.
    fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Typed directory node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryNode {
    /// Parsed inode backing this typed directory node.
    inode: Inode,
}

impl DirectoryNode {
    /// Inode identifier backing this directory node.
    #[must_use]
    pub const fn id(&self) -> InodeId {
        self.inode.id()
    }

    /// POSIX security state parsed from the directory inode.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.inode.security()
    }

    /// Directory payload size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.inode.size()
    }

    /// ext4 timestamps parsed from the directory inode.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.inode.times()
    }

    /// Link count parsed from the directory inode.
    #[must_use]
    pub const fn links_count(&self) -> u16 {
        self.inode.links_count()
    }

    /// Contents protection selected by directory inode flags.
    #[must_use]
    pub const fn protection(&self) -> InodeProtection {
        self.inode.protection()
    }

    /// Returns the backing inode for volume-internal operations.
    fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Typed symbolic link node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkNode {
    /// Parsed inode backing this typed symlink node.
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

    /// POSIX security state parsed from the symlink inode.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.inode.security()
    }

    /// ext4 timestamps parsed from the symlink inode.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.inode.times()
    }

    /// Link count parsed from the symlink inode.
    #[must_use]
    pub const fn links_count(&self) -> u16 {
        self.inode.links_count()
    }

    /// Contents protection selected by symlink inode flags.
    #[must_use]
    pub const fn protection(&self) -> InodeProtection {
        self.inode.protection()
    }

    /// Returns the backing inode for volume-internal operations.
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

impl<D: BlockReader, N> Volume<D, ReadOnly, N> {
    /// Validates an ext4 volume and constructs read-only mounted state.
    ///
    /// # Errors
    /// Returns an error when the device does not contain a supported ext4 superblock.
    pub fn mount_read_only(device: D, mount_context: MountContext<N>) -> Result<Self> {
        let superblock = Superblock::read_from(&device)?;
        Ok(Self {
            device,
            superblock,
            mount_context,
            state: ReadOnly,
        })
    }
}

impl<D: BlockWriter, N: FscryptNonceGenerator + Clone> Volume<D, ReadWrite<InternalJournal>, N> {
    /// Replays the internal journal boundary and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when the device is not a supported journaled ext4 volume.
    pub fn mount_read_write(mut device: D, mount_context: MountContext<N>) -> Result<Self> {
        let mut superblock = Superblock::read_write_from(&device)?;
        let JournalMode::Internal(journal_inode_id) = superblock.journal_mode() else {
            return Err(Error::UnsupportedJournal);
        };
        let read_only = Volume::<&mut D, ReadOnly, N> {
            device: &mut device,
            superblock,
            mount_context: mount_context.clone(),
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
        let clusters = {
            let recovered = Volume::<&mut D, ReadOnly, N> {
                device: &mut device,
                superblock,
                mount_context: mount_context.clone(),
                state: ReadOnly,
            };
            ClusterReferenceIndex::load(&recovered)?
        };
        Ok(Self {
            device,
            superblock,
            mount_context,
            state: ReadWrite { journal, clusters },
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> WriteTransaction<'_, D, InternalJournal, N> {
        WriteTransaction {
            volume: self,
            now,
            inode_updates: Vec::new(),
            block_bitmap_updates: Vec::new(),
            inode_bitmap_updates: Vec::new(),
            directory_updates: Vec::new(),
            extent_updates: Vec::new(),
            xattr_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            cluster_deltas: Vec::new(),
            free_clusters_delta: FreeClusterDelta::ZERO,
            free_inodes_delta: 0,
            volume_label_update: None,
        }
    }
}

impl<D: BlockWriter, J: BlockWriter, N: FscryptNonceGenerator + Clone>
    Volume<D, ReadWrite<ExternalJournal<J>>, N>
{
    /// Replays an external journal and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when either device cannot support the external journal contract.
    pub fn mount_read_write_with_external_journal(
        mut device: D,
        journal_device: J,
        mount_context: MountContext<N>,
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
        let clusters = {
            let recovered = Volume::<&mut D, ReadOnly, N> {
                device: &mut device,
                superblock,
                mount_context: mount_context.clone(),
                state: ReadOnly,
            };
            ClusterReferenceIndex::load(&recovered)?
        };
        Ok(Self {
            device,
            superblock,
            mount_context,
            state: ReadWrite { journal, clusters },
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> WriteTransaction<'_, D, ExternalJournal<J>, N> {
        WriteTransaction {
            volume: self,
            now,
            inode_updates: Vec::new(),
            block_bitmap_updates: Vec::new(),
            inode_bitmap_updates: Vec::new(),
            directory_updates: Vec::new(),
            extent_updates: Vec::new(),
            xattr_updates: Vec::new(),
            group_deltas: Vec::new(),
            data_writes: Vec::new(),
            cluster_deltas: Vec::new(),
            free_clusters_delta: FreeClusterDelta::ZERO,
            free_inodes_delta: 0,
            volume_label_update: None,
        }
    }
}

impl<D: BlockReader, State, N> Volume<D, State, N> {
    /// Validated superblock.
    #[must_use]
    pub const fn superblock(&self) -> Superblock {
        self.superblock
    }

    /// Mount context used by this volume.
    #[must_use]
    pub const fn mount_context(&self) -> &MountContext<N> {
        &self.mount_context
    }

    /// Adds one fscrypt master key to this mounted volume.
    ///
    /// # Errors
    /// Returns an error when the key identifier is already present.
    pub fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Result<()> {
        self.mount_context.add_fscrypt_key(key)
    }

    /// Removes one fscrypt master key from this mounted volume.
    #[must_use]
    pub fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.mount_context.remove_fscrypt_key(identifier)
    }

    /// Returns whether this mounted volume has an fscrypt key.
    #[must_use]
    pub fn contains_fscrypt_key(&self, identifier: FscryptKeyIdentifier) -> bool {
        self.mount_context.contains_fscrypt_key(identifier)
    }

    /// Filesystem volume label parsed from the mounted superblock.
    #[must_use]
    pub const fn volume_label(&self) -> Ext4VolumeLabel {
        self.superblock.volume_label()
    }

    /// Reads all extended attributes attached to an inode.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub fn read_xattrs(&self, inode_id: InodeId) -> Result<XattrSet> {
        Ok(self
            .read_inode_xattrs_from_raw(&self.read_raw_inode(inode_id)?)?
            .public()
            .clone())
    }

    /// Reads one extended attribute value by name.
    ///
    /// # Errors
    /// Returns an error when the inode or its external xattr block is malformed.
    pub fn read_xattr(&self, inode_id: InodeId, name: &XattrName) -> Result<Option<XattrValue>> {
        Ok(self.read_xattrs(inode_id)?.get(name).cloned())
    }

    /// Reads a POSIX ACL from its ext4 xattr slot.
    ///
    /// # Errors
    /// Returns an error when the backing xattr or ACL payload is malformed.
    pub fn read_posix_acl(
        &self,
        inode_id: InodeId,
        kind: PosixAclKind,
    ) -> Result<Option<PosixAcl>> {
        let Some(value) = self.read_xattr(inode_id, &PosixAcl::xattr_name(kind)?)? else {
            return Ok(None);
        };
        Ok(Some(PosixAcl::parse(&value)?))
    }

    /// Reads Windows overlay metadata isolated in `user.ext4win.*` xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay xattr payload is malformed.
    pub fn read_windows_overlay(&self, inode_id: InodeId) -> Result<Option<WindowsOverlay>> {
        let Some(value) = self.read_xattr(inode_id, &WindowsOverlay::attributes_xattr_name()?)?
        else {
            return Ok(None);
        };
        Ok(Some(WindowsOverlay::parse(&value)?))
    }

    /// Reads the fscrypt v2 context stored in ext4's private inode xattr slot.
    ///
    /// # Errors
    /// Returns an error when the inode's xattr storage is malformed or the
    /// stored fscrypt context is not in the supported v2 AES profile.
    pub fn read_fscrypt_context(&self, inode_id: InodeId) -> Result<Option<FscryptContextV2>> {
        let xattrs = self.read_inode_xattrs_from_raw(&self.read_raw_inode(inode_id)?)?;
        let Some(value) = xattrs.encryption_context() else {
            return Ok(None);
        };
        Ok(Some(FscryptContextV2::parse(value.bytes())?))
    }

    /// Verifies that an encrypted inode has an available fscrypt master key.
    fn require_encryption_key(&self, inode: &Inode) -> Result<()> {
        if !inode.protection().is_encrypted() {
            return Ok(());
        }
        let _key = self.fscrypt_master_key_for_inode(inode)?;
        Ok(())
    }

    /// Returns the mount key matching an encrypted inode's fscrypt context.
    fn fscrypt_master_key_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<(FscryptContextV2, &FscryptMasterKey)> {
        let Some(context) = self.read_fscrypt_context(inode.id())? else {
            return Err(Error::InvalidEncryptionContext);
        };
        let Some(key) = self
            .mount_context
            .fscrypt_keys()
            .get(context.policy().master_key_identifier())
        else {
            return Err(Error::MissingEncryptionKey);
        };
        Ok((context, key))
    }

    /// Derives the per-file AES-XTS contents key for an encrypted inode.
    fn fscrypt_contents_key_for_inode(&self, inode: &Inode) -> Result<FscryptContentsKey> {
        let (context, master_key) = self.fscrypt_master_key_for_inode(inode)?;
        master_key.derive_contents_key(context.nonce())
    }

    /// Derives the per-directory filename key and padding policy.
    fn fscrypt_filenames_key_for_inode(
        &self,
        inode: &Inode,
    ) -> Result<(FscryptFilenamesKey, FscryptFilenamePadding)> {
        let (context, master_key) = self.fscrypt_master_key_for_inode(inode)?;
        Ok((
            master_key.derive_filenames_key(context.nonce())?,
            context.policy().filename_padding(),
        ))
    }

    /// Converts a plaintext child name to the on-disk name for a directory.
    fn encrypt_directory_child_name(&self, parent: &Inode, name: &Ext4Name) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ok(name.clone());
        }
        let (key, padding) = self.fscrypt_filenames_key_for_inode(parent)?;
        Ext4Name::from_disk(&key.encrypt_filename(name.bytes(), padding)?)
    }

    /// Converts an on-disk child name to plaintext for a directory.
    fn decrypt_directory_child_name(&self, parent: &Inode, name: &Ext4Name) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ok(name.clone());
        }
        let (key, _padding) = self.fscrypt_filenames_key_for_inode(parent)?;
        Ext4Name::new(&key.decrypt_filename(name.bytes())?)
    }

    /// Rejects protected plaintext data access until crypto and verification paths exist.
    fn reject_unsupported_protected_payload_access(&self, inode: &Inode) -> Result<()> {
        if inode.protection().is_encrypted() {
            self.require_encryption_key(inode)?;
            return Err(Error::UnsupportedEncryption);
        }
        if inode.protection().is_verity() {
            return Err(Error::UnsupportedVerity);
        }
        Ok(())
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
        if file.protection().is_verity() {
            return self.read_verified_file(file, offset, out);
        }
        self.read_inode_plaintext_data(file.inode(), offset, out)
    }

    /// Reads a typed symlink target as bytes.
    ///
    /// # Errors
    /// Returns an error when the symlink target cannot be read.
    pub fn read_symlink(&self, symlink: &SymlinkNode) -> Result<Vec<u8>> {
        self.reject_unsupported_protected_payload_access(symlink.inode())?;
        let len = symlink.size().to_usize()?;
        if let Ok(inline) = symlink.inode().inline_bytes() {
            return Ok(inline.prefix(symlink.size())?.to_vec());
        }
        let mut target = vec![0_u8; len];
        let _bytes_read = self.read_inode_data(symlink.inode(), FileOffset::ZERO, &mut target)?;
        Ok(target)
    }

    /// Reads a verity-protected regular file after verifying its full plaintext.
    fn read_verified_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        if out.is_empty() || offset.bytes() >= file.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }
        let metadata = self.read_verity_metadata(file)?;
        let mut plaintext = vec![0_u8; file.size().to_usize()?];
        let read =
            self.read_inode_plaintext_data(file.inode(), FileOffset::ZERO, &mut plaintext)?;
        if read.as_usize() != plaintext.len() {
            return Err(Error::InvalidVerityMetadata);
        }
        metadata
            .merkle_tree()
            .verify_data(&plaintext, metadata.descriptor())?;

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            file.size().remaining_from(offset)?,
        );
        let start = usize::try_from(offset.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let count = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        let end = start.checked_add(count).ok_or(Error::ArithmeticOverflow)?;
        out.get_mut(..count)
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(plaintext.get(start..end).ok_or(Error::DeviceRange)?);
        Ok(ReadBytes::from_usize(count))
    }

    /// Reads ext4 post-EOF fs-verity metadata from a regular file's extent stream.
    fn read_verity_metadata(&self, file: &FileNode) -> Result<Ext4VerityMetadata> {
        let block_size = self.superblock.block_size();
        let extent_tree = ExtentTree::load_inode_tree(
            file.inode().extent_root()?,
            block_size,
            &self.device,
            self.extent_tree_context(file.inode()),
        )?;
        let metadata_end = extent_payload_end_bytes(&extent_tree, block_size)?;
        if metadata_end <= file.size().bytes() {
            return Err(Error::InvalidVerityMetadata);
        }
        let tail_offset = metadata_end
            .checked_sub(4)
            .ok_or(Error::InvalidVerityMetadata)?;
        let mut descriptor_size_tail = [0_u8; 4];
        self.read_inode_plaintext_stream_range(
            file.inode(),
            &extent_tree,
            tail_offset,
            &mut descriptor_size_tail,
        )?;
        let descriptor_bytes = u32::from_le_bytes(descriptor_size_tail);
        let descriptor_offset = Ext4VerityMetadataLayout::descriptor_offset_from_metadata_end(
            block_size,
            metadata_end,
            descriptor_bytes,
        )?;
        let descriptor_len =
            usize::try_from(descriptor_bytes).map_err(|_| Error::ArithmeticOverflow)?;
        let mut descriptor_image = vec![0_u8; descriptor_len];
        self.read_inode_plaintext_stream_range(
            file.inode(),
            &extent_tree,
            descriptor_offset,
            &mut descriptor_image,
        )?;
        let descriptor = FsverityDescriptor::parse(
            descriptor_image
                .get(..FSVERITY_DESCRIPTOR_BYTES)
                .ok_or(Error::TruncatedStructure)?,
        )?;
        let layout = Ext4VerityMetadataLayout::from_metadata_end(
            file.size(),
            block_size,
            metadata_end,
            descriptor_bytes,
            &descriptor,
        )?;
        let merkle_tree_len =
            usize::try_from(layout.merkle_tree_bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let mut merkle_tree = vec![0_u8; merkle_tree_len];
        self.read_inode_plaintext_stream_range(
            file.inode(),
            &extent_tree,
            layout.merkle_tree_offset(),
            &mut merkle_tree,
        )?;
        let signature = descriptor_image
            .get(FSVERITY_DESCRIPTOR_BYTES..)
            .ok_or(Error::TruncatedStructure)?
            .to_vec();
        Ext4VerityMetadata::new(layout, descriptor, signature, merkle_tree)
    }

    /// Enumerates directory entries from a typed directory node.
    ///
    /// # Errors
    /// Returns an error when the directory is too large for eager
    /// enumeration, or contains malformed entries.
    pub fn read_directory(&self, directory: &DirectoryNode) -> Result<Vec<DirectoryEntry>> {
        let entries = self.read_directory_layout(directory.inode())?.entries();
        if !directory.protection().is_encrypted() {
            return Ok(entries);
        }
        match self.decrypt_directory_entries(directory.inode(), &entries) {
            Err(Error::MissingEncryptionKey) => Self::project_locked_directory_entries(entries),
            result => result,
        }
    }

    /// Decrypts directory-entry names for an unlocked encrypted directory.
    fn decrypt_directory_entries(
        &self,
        directory: &Inode,
        entries: &[DirectoryEntry],
    ) -> Result<Vec<DirectoryEntry>> {
        let mut decrypted = Vec::with_capacity(entries.len());
        for entry in entries {
            let name = self.decrypt_directory_child_name(directory, entry.name())?;
            decrypted.push(DirectoryEntry::new(entry.inode(), &name, entry.kind()));
        }
        Ok(decrypted)
    }

    /// Projects encrypted on-disk dirent names into reversible no-key names.
    fn project_locked_directory_entries(
        entries: Vec<DirectoryEntry>,
    ) -> Result<Vec<DirectoryEntry>> {
        let mut projected = Vec::with_capacity(entries.len());
        for entry in entries {
            let name = Self::project_locked_directory_name(entry.name())?;
            projected.push(DirectoryEntry::new(entry.inode(), &name, entry.kind()));
        }
        Ok(projected)
    }

    /// Projects one encrypted on-disk dirent name into a no-key display name.
    fn project_locked_directory_name(name: &Ext4Name) -> Result<Ext4Name> {
        if matches!(name.bytes(), b"." | b"..") {
            return Ok(name.clone());
        }
        let display = FscryptNoKeyName::from_ciphertext(name.bytes())?.display_bytes()?;
        Ext4Name::new(&display)
    }

    /// Decodes a no-key display name back into its encrypted on-disk name.
    fn locked_directory_ciphertext_name(name: &Ext4Name) -> Result<Option<Ext4Name>> {
        let Some(no_key_name) = FscryptNoKeyName::from_display(name.bytes())? else {
            return Ok(None);
        };
        Ok(Some(Ext4Name::from_disk(no_key_name.ciphertext_bytes())?))
    }

    /// Looks up an exact ext4 child name under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated.
    pub fn lookup_child(&self, parent: &DirectoryNode, name: &Ext4Name) -> Result<LookupResult> {
        if let Some(entry) = self.read_directory_layout(parent.inode())?.find(name) {
            return Ok(LookupResult::Found(entry.inode()));
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
        match self.lookup_windows_child_entry(parent, requested)? {
            Some(entry) => Ok(LookupResult::Found(entry.inode())),
            None => Ok(LookupResult::NotFound),
        }
    }

    /// Looks up a Windows-visible child name and returns the matched directory entry.
    ///
    /// # Errors
    /// Returns an error when the parent cannot be enumerated or the
    /// case-insensitive Windows projection is ambiguous.
    pub fn lookup_windows_child_entry(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> Result<Option<DirectoryEntry>> {
        if parent.protection().is_encrypted() {
            let visible_name = requested.to_ext4()?;
            let ciphertext = match self.encrypt_directory_child_name(parent.inode(), &visible_name)
            {
                Ok(ciphertext) => ciphertext,
                Err(Error::MissingEncryptionKey) => {
                    let Some(ciphertext) = Self::locked_directory_ciphertext_name(&visible_name)?
                    else {
                        return Err(Error::MissingEncryptionKey);
                    };
                    ciphertext
                }
                Err(error) => return Err(error),
            };
            return Ok(self
                .read_directory_layout(parent.inode())?
                .find(&ciphertext)
                .map(|entry| DirectoryEntry::new(entry.inode(), &visible_name, entry.kind())));
        }
        if parent.protection().is_verity() {
            return Err(Error::UnsupportedVerity);
        }
        let mut folded = None;

        for entry in self.read_directory(parent)? {
            let Ok(name) = WindowsName::from_ext4(entry.name()) else {
                continue;
            };
            if name.equals(requested) {
                return Ok(Some(entry));
            }
            if name.equals_ascii_case_insensitive(requested) {
                if folded.is_some() {
                    return Err(Error::AmbiguousWindowsName);
                }
                folded = Some(entry);
            }
        }

        Ok(folded)
    }

    /// Loads and validates the directory layout selected by an inode.
    fn read_directory_layout(&self, inode: &Inode) -> Result<DirectoryLayout> {
        if inode.size().bytes() > MAX_EAGER_DIRECTORY_BYTES {
            return Err(Error::DirectoryTooLarge);
        }
        if inode.is_indexed_directory() {
            self.superblock.directory_indexing().require_supported()?;
        }
        DirectoryLayout::parse(
            inode.is_indexed_directory(),
            self.read_directory_block_data(inode)?,
            self.superblock.directory_hash_seed(),
            self.superblock.default_directory_hash_version(),
            self.directory_checksum(inode),
        )
    }

    /// Reads directory file blocks through the inode extent tree.
    fn read_directory_block_data(&self, inode: &Inode) -> Result<Vec<DirectoryBlockData>> {
        let block_size = self.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_count = round_up_div(inode.size().bytes(), u64::from(block_size.bytes()))?;
        let tree = MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            &self.device,
            self.extent_tree_context(inode),
        )?;
        let mut blocks = Vec::new();
        for logical in 0..block_count {
            let logical_block = LogicalBlock::try_from(logical)?;
            let physical = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    return Err(Error::InvalidDirectoryEntry);
                }
            };
            let mut bytes = vec![0_u8; block_bytes];
            self.device
                .read_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
            blocks.push(DirectoryBlockData::new(logical_block.as_u32(), bytes));
        }
        Ok(blocks)
    }

    /// Reads plaintext file data, decrypting fscrypt contents when needed.
    fn read_inode_plaintext_data(
        &self,
        inode: &Inode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> Result<ReadBytes> {
        if !inode.protection().is_encrypted() {
            return self.read_inode_data(inode, offset, out);
        }
        if out.is_empty() || offset.bytes() >= inode.size().bytes() {
            return Ok(ReadBytes::from_usize(0));
        }

        let readable = core::cmp::min(
            u64::try_from(out.len()).map_err(|_| Error::ArithmeticOverflow)?,
            inode.size().remaining_from(offset)?,
        );
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &self.device,
            self.extent_tree_context(inode),
        )?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_plaintext_stream_range(
            inode,
            &extent_tree,
            offset.bytes(),
            out.get_mut(..readable_len).ok_or(Error::DeviceRange)?,
        )?;
        Ok(ReadBytes::from_usize(readable_len))
    }

    /// Reads file data through the inode extent tree, zero-filling sparse ranges.
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
        let extent_tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.superblock.block_size(),
            &self.device,
            self.extent_tree_context(inode),
        )?;
        let readable_len = usize::try_from(readable).map_err(|_| Error::ArithmeticOverflow)?;
        self.read_inode_stream_range(
            &extent_tree,
            offset.bytes(),
            out.get_mut(..readable_len).ok_or(Error::DeviceRange)?,
        )?;
        Ok(ReadBytes::from_usize(readable_len))
    }

    /// Reads plaintext bytes from an inode extent stream without applying `i_size` limits.
    fn read_inode_plaintext_stream_range(
        &self,
        inode: &Inode,
        extent_tree: &ExtentTree,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        if inode.protection().is_encrypted() {
            let contents_key = self.fscrypt_contents_key_for_inode(inode)?;
            self.read_encrypted_inode_stream_range(&contents_key, extent_tree, offset, out)
        } else {
            self.read_inode_stream_range(extent_tree, offset, out)
        }
    }

    /// Reads and decrypts bytes from an fscrypt inode stream.
    fn read_encrypted_inode_stream_range(
        &self,
        contents_key: &FscryptContentsKey,
        extent_tree: &ExtentTree,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size().bytes());
        let block_bytes = usize::try_from(self.superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let mut completed = 0_usize;

        while completed < out.len() {
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
            let total_remaining = u64::try_from(
                out.len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
            let chunk = usize::try_from(core::cmp::min(block_remaining, total_remaining))
                .map_err(|_| Error::ArithmeticOverflow)?;
            let end = completed
                .checked_add(chunk)
                .ok_or(Error::ArithmeticOverflow)?;

            match extent_tree.map_logical(LogicalBlock::try_from(logical_block)?) {
                BlockMapping::Physical(physical_block) => {
                    let mut block = vec![0_u8; block_bytes];
                    self.device.read_exact_at(
                        self.superblock.block_size().offset_of(physical_block)?,
                        &mut block,
                    )?;
                    contents_key.decrypt_block(logical_block, &mut block)?;
                    let start = usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                    let block_end = start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .copy_from_slice(block.get(start..block_end).ok_or(Error::DeviceRange)?);
                }
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .fill(0);
                }
            }
            completed = end;
        }

        Ok(())
    }

    /// Reads bytes from an inode extent stream without applying `i_size` limits.
    fn read_inode_stream_range(
        &self,
        extent_tree: &ExtentTree,
        offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size().bytes());
        let mut completed = 0_usize;

        while completed < out.len() {
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
            let total_remaining = u64::try_from(
                out.len()
                    .checked_sub(completed)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .map_err(|_| Error::ArithmeticOverflow)?;
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
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    out.get_mut(completed..end)
                        .ok_or(Error::DeviceRange)?
                        .fill(0);
                }
            }
            completed = end;
        }

        Ok(())
    }

    /// Reads an inode record together with its on-device offset.
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

    /// Reads and parses a typed inode record.
    fn read_inode_record(&self, inode_id: InodeId) -> Result<Inode> {
        self.read_raw_inode(inode_id)?.parse()
    }

    /// Reads all xattr storage locations referenced by a raw inode.
    fn read_inode_xattrs_from_raw(&self, raw_inode: &RawInode) -> Result<InodeXattrSet> {
        match self.superblock.xattr_mutation() {
            XattrMutationSupport::Disabled => return Ok(InodeXattrSet::empty()),
            XattrMutationSupport::Enabled => {}
        }
        let inline = xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?;
        let Some(block) = raw_inode.xattr_block()? else {
            return Ok(inline);
        };
        let mut bytes = vec![
            0_u8;
            usize::try_from(self.superblock.block_size().bytes())
                .map_err(|_| Error::ArithmeticOverflow)?
        ];
        self.device
            .read_exact_at(self.superblock.block_size().offset_of(block)?, &mut bytes)?;
        let external = xattr_storage::parse_external_xattr_block(&bytes, block, &self.superblock)?;
        xattr_storage::merge_xattr_sets(inline, external)
    }

    /// Builds the checksum context required for this inode's extent tree.
    fn extent_tree_context(&self, inode: &Inode) -> ExtentTreeContext {
        if self.superblock.metadata_checksum() == MetadataChecksum::Crc32c {
            ExtentTreeContext::metadata_csum(
                self.superblock.checksum_seed().as_u32(),
                inode.id(),
                inode.generation(),
            )
        } else {
            ExtentTreeContext::none()
        }
    }

    /// Builds the checksum context required for directory metadata.
    fn directory_checksum(&self, inode: &Inode) -> DirectoryChecksum {
        if self.superblock.metadata_checksum() == MetadataChecksum::Crc32c {
            DirectoryChecksum::metadata_csum(
                self.superblock.checksum_seed(),
                inode.id(),
                inode.generation(),
            )
        } else {
            DirectoryChecksum::None
        }
    }
}

/// Regular file selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionFile {
    /// Mutable regular-file inode selected for this transaction.
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
    /// Mutable directory inode selected for this transaction.
    inode_id: InodeId,
}

impl TransactionDirectory {
    /// Inode identifier backing this transaction directory.
    #[must_use]
    pub const fn inode_id(self) -> InodeId {
        self.inode_id
    }
}

/// Symbolic link selected for mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionSymlink {
    /// Mutable symbolic-link inode selected for this transaction.
    inode_id: InodeId,
}

impl TransactionSymlink {
    /// Inode identifier backing this transaction symlink.
    #[must_use]
    pub const fn inode_id(self) -> InodeId {
        self.inode_id
    }
}

/// Inode selected for POSIX metadata mutation inside a write transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionNode {
    /// Mutable inode selected for metadata updates.
    inode_id: InodeId,
}

impl TransactionNode {
    /// Inode identifier backing this transaction node.
    #[must_use]
    pub const fn inode_id(self) -> InodeId {
        self.inode_id
    }
}

/// In-progress ext4 write transaction.
#[derive(Debug)]
pub struct WriteTransaction<'a, D: BlockWriter, J = InternalJournal, N = FscryptNoNonceGenerator> {
    /// Mounted read-write volume being mutated.
    volume: &'a mut Volume<D, ReadWrite<J>, N>,
    /// Timestamp applied consistently to staged inode updates.
    now: Ext4Timestamp,
    /// Inode records staged for rewrite at commit.
    inode_updates: Vec<RawInode>,
    /// Block bitmap images staged for allocation changes.
    block_bitmap_updates: Vec<BlockImage>,
    /// Inode bitmap images staged for allocation changes.
    inode_bitmap_updates: Vec<BlockImage>,
    /// Directory block images staged after dirent mutation.
    directory_updates: Vec<BlockImage>,
    /// External extent tree blocks staged after extent mutation.
    extent_updates: Vec<BlockImage>,
    /// External xattr blocks staged after xattr mutation.
    xattr_updates: Vec<BlockImage>,
    /// Per-group allocation count deltas to fold into descriptors.
    group_deltas: Vec<GroupDelta>,
    /// Ordered file data writes that must reach disk before metadata commit.
    data_writes: Vec<RangeWrite>,
    /// Staged cluster-reference changes to apply after journal commit.
    cluster_deltas: Vec<ClusterReferenceDelta>,
    /// Superblock free-cluster delta accumulated by this transaction.
    free_clusters_delta: FreeClusterDelta,
    /// Superblock free-inode delta accumulated by this transaction.
    free_inodes_delta: i64,
    /// Superblock volume label replacement staged by this transaction.
    volume_label_update: Option<Ext4VolumeLabel>,
}

impl<D: BlockWriter, J, N: FscryptNonceGenerator> WriteTransaction<'_, D, J, N> {
    /// Verifies that the mounted profile admits xattr storage mutation.
    fn require_xattr_mutation(&self) -> Result<()> {
        self.volume.superblock.xattr_mutation().require_supported()
    }

    /// Verifies that an inode size is representable by the mounted profile.
    fn require_inode_size_supported(&self, size: FileSize) -> Result<()> {
        self.volume
            .superblock
            .file_size_encoding()
            .require_supported(size.bytes(), LEGACY_FILE_SIZE_LIMIT)
    }

    /// Verifies that an inode block charge is representable by the mounted profile.
    fn require_allocated_blocks_supported(&self, blocks: u64) -> Result<()> {
        let sectors = blocks
            .checked_mul(u64::from(self.volume.superblock.block_size().bytes()))
            .ok_or(Error::ArithmeticOverflow)?
            .checked_div(512)
            .ok_or(Error::ArithmeticOverflow)?;
        self.volume
            .superblock
            .inode_block_count_encoding()
            .require_supported(sectors, LEGACY_I_BLOCKS_LIMIT)
    }

    /// Selects any supported inode for POSIX metadata mutation.
    ///
    /// # Errors
    /// Returns an error when the inode cannot be read or carries mutation
    /// semantics outside the write domain.
    pub fn node(&self, inode_id: InodeId) -> Result<TransactionNode> {
        let inode = self.volume.read_inode_record(inode_id)?;
        inode.require_mutation(InodeMutation::Metadata)?;
        Ok(TransactionNode { inode_id })
    }

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
        Ok(TransactionDirectory { inode_id })
    }

    /// Selects a symbolic link for mutation.
    ///
    /// # Errors
    /// Returns an error when the inode is not a symbolic link or carries
    /// mutation semantics outside the write domain.
    pub fn symlink(&self, inode_id: InodeId) -> Result<TransactionSymlink> {
        let inode = self.volume.read_inode_record(inode_id)?;
        if inode.kind() != InodeKind::Symlink {
            return Err(Error::WrongInodeKind);
        }
        self.require_file_data_mutation(&inode)?;
        Ok(TransactionSymlink { inode_id })
    }

    /// Updates POSIX owner and permission state representable by ext4 inode fields.
    ///
    /// # Errors
    /// Returns an error when the inode leaves the mutable write domain or the
    /// inode record cannot be rewritten.
    pub fn set_posix_security(
        &mut self,
        node: TransactionNode,
        security: Ext4Security,
    ) -> Result<()> {
        let inode_index = self.ensure_inode_update(node.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        inode.require_mutation(InodeMutation::Metadata)?;
        raw_inode.set_owner(security.owner())?;
        raw_inode.set_permissions(security.permissions())?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
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
        self.require_directory_entry_mutation(
            parent.inode_id(),
            InodeMutation::DirectoryEntryCreate,
        )?;
        let parent_inode = self.raw_inode_for_policy(parent.inode_id())?.parse()?;
        let inherited_context = self.inherited_fscrypt_context(&parent_inode)?;
        let mut raw_inode = self.allocate_inode()?;
        raw_inode.initialize_file(
            metadata,
            self.now,
            self.volume.superblock.block_size(),
            self.volume.superblock.inode_timestamp_encoding(),
        )?;
        self.apply_fscrypt_context(&mut raw_inode, inherited_context)?;
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
        inode.require_mutation(InodeMutation::Delete)?;
        if raw_inode.decrement_links_count()? == 0 {
            let tree = self.mutable_extent_tree(&inode)?;
            for extent in tree.extents().iter().copied() {
                self.free_extent(extent, 0)?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                self.release_cluster_reference(block)?;
            }
            self.free_inode(raw_inode.id)?;
            raw_inode.clear_deleted(self.now, self.volume.superblock.block_size())?;
        }
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
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
        self.require_directory_entry_mutation(
            parent.inode_id(),
            InodeMutation::DirectoryEntryCreate,
        )?;
        let parent_inode = self.raw_inode_for_policy(parent.inode_id())?.parse()?;
        let inherited_context = self.inherited_fscrypt_context(&parent_inode)?;
        let block = self.allocate_cluster()?;
        let mut raw_inode = self.allocate_inode()?;
        let inode_id = raw_inode.id;
        let block_size = self.volume.superblock.block_size();
        let allocated_blocks = u64::from(
            self.volume
                .superblock
                .blocks_in_cluster(self.volume.superblock.cluster_of_block(block)?)?,
        );
        self.require_allocated_blocks_supported(allocated_blocks)?;
        raw_inode.initialize_directory(
            metadata,
            self.now,
            block_size,
            block,
            allocated_blocks,
            self.volume.superblock.inode_timestamp_encoding(),
        )?;
        self.apply_fscrypt_context(&mut raw_inode, inherited_context)?;

        let mut directory = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        directory.initialize_dot_entries(inode_id, parent.inode_id())?;
        self.stage_directory_block(block, directory.into_bytes());

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

    /// Creates a symbolic link under a directory.
    ///
    /// # Errors
    /// Returns an error when the parent is not mutable, the name exists, no
    /// inode or data block is free, or the target cannot be represented.
    pub fn create_symlink(
        &mut self,
        parent: TransactionDirectory,
        name: &Ext4Name,
        target: &SymlinkTarget,
        metadata: NewSymlinkMetadata,
    ) -> Result<TransactionSymlink> {
        self.ensure_child_absent(parent.inode_id(), name)?;
        self.require_directory_entry_mutation(
            parent.inode_id(),
            InodeMutation::DirectoryEntryCreate,
        )?;
        let parent_inode = self.raw_inode_for_policy(parent.inode_id())?.parse()?;
        if parent_inode.protection().is_encrypted() {
            return Err(Error::UnsupportedEncryption);
        }
        let mut raw_inode = self.allocate_inode()?;
        let inode_id = raw_inode.id;
        if target.is_inline() {
            raw_inode.initialize_inline_symlink(
                metadata,
                self.now,
                target,
                self.volume.superblock.inode_timestamp_encoding(),
            )?;
        } else {
            let block_size = self.volume.superblock.block_size();
            raw_inode.initialize_extent_symlink(
                metadata,
                self.now,
                block_size,
                target,
                self.volume.superblock.inode_timestamp_encoding(),
            )?;
            let block_bytes =
                usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
            let mut tree = MutableExtentTree::from_extents(Vec::new())?;
            for (logical, chunk) in target.bytes().chunks(block_bytes).enumerate() {
                let block = self.allocate_cluster()?;
                let mut bytes = vec![0_u8; block_bytes];
                bytes
                    .get_mut(..chunk.len())
                    .ok_or(Error::DeviceRange)?
                    .copy_from_slice(chunk);
                self.data_writes.push(RangeWrite {
                    offset: block_size.offset_of(block)?,
                    bytes,
                });
                tree.insert_or_extend_initialized(
                    LogicalBlock::try_from(
                        u64::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?,
                    )?,
                    block,
                )?;
            }
            self.stage_extent_tree(&mut raw_inode, tree)?;
        }
        self.add_directory_entry(
            parent.inode_id(),
            name,
            inode_id,
            DirectoryEntryKind::Symlink,
        )?;
        self.inode_updates.push(raw_inode);
        Ok(TransactionSymlink { inode_id })
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
        inode.require_mutation(InodeMutation::Delete)?;
        if !self.directory_is_empty(&inode)? {
            return Err(Error::DirectoryNotEmpty);
        }
        let _removed = self.remove_directory_entry(parent.inode_id(), name)?;
        let tree = self.mutable_extent_tree(&inode)?;
        for extent in tree.extents().iter().copied() {
            self.free_extent(extent, 0)?;
        }
        for block in tree.metadata_blocks().iter().copied() {
            self.release_cluster_reference(block)?;
        }
        self.free_inode(raw_inode.id)?;
        raw_inode.clear_deleted(self.now, self.volume.superblock.block_size())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        self.decrement_directory_links(parent.inode_id())?;
        let (group, _) = inode_group_bit(&self.volume.superblock, removed.inode())?;
        self.record_group_used_dirs_delta(group, -1)
    }

    /// Renames or moves a child entry without replacing an existing target.
    ///
    /// # Errors
    /// Returns an error when the source entry is absent, the target name exists,
    /// either parent is outside the mutable directory domain, or a moved
    /// directory cannot have its parent link updated.
    pub fn rename_child(
        &mut self,
        source_parent: TransactionDirectory,
        source_name: &Ext4Name,
        target_parent: TransactionDirectory,
        target_name: &Ext4Name,
    ) -> Result<()> {
        reject_reserved_directory_name(source_name)?;
        reject_reserved_directory_name(target_name)?;

        let source_parent = source_parent.inode_id();
        let target_parent = target_parent.inode_id();
        let source = self.find_child_entry(source_parent, source_name)?;
        if source_parent == target_parent && source_name == target_name {
            return Ok(());
        }
        self.ensure_child_absent(target_parent, target_name)?;

        let child_index = self.ensure_inode_update(source.inode())?;
        let mut child_raw = self
            .inode_updates
            .get(child_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let child_inode = child_raw.parse()?;
        child_inode.require_mutation(InodeMutation::Metadata)?;
        if child_inode.kind() == InodeKind::Directory && source.inode() == InodeId::ROOT {
            return Err(Error::CannotRemoveRoot);
        }
        let kind = directory_entry_kind(child_inode.kind());

        if source_parent == target_parent {
            let renamed = self.rename_directory_entry(
                source_parent,
                source_name,
                target_name,
                source.inode(),
                kind,
            )?;
            if renamed.inode() != source.inode() {
                return Err(Error::InvalidDirectoryEntry);
            }
        } else {
            self.add_directory_entry(target_parent, target_name, source.inode(), kind)?;
            let removed = self.remove_directory_entry(source_parent, source_name)?;
            if removed.inode() != source.inode() {
                return Err(Error::InvalidDirectoryEntry);
            }
            if child_inode.kind() == InodeKind::Directory {
                let dotdot = Ext4Name::new(b"..")?;
                let replaced = self.replace_directory_entry(
                    source.inode(),
                    &dotdot,
                    target_parent,
                    DirectoryEntryKind::Directory,
                )?;
                if replaced.inode() != source_parent {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.decrement_directory_links(source_parent)?;
                self.increment_directory_links(target_parent)?;
            }
        }

        child_raw.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        *self
            .inode_updates
            .get_mut(child_index)
            .ok_or(Error::InvalidInode)? = child_raw;
        Ok(())
    }

    /// Updates ext4 inode timestamps from a complete timestamp domain value.
    ///
    /// # Errors
    /// Returns an error when the inode leaves the mutable write domain or the
    /// inode record cannot be rewritten.
    pub fn set_times(&mut self, node: TransactionNode, times: Ext4Times) -> Result<()> {
        let inode_index = self.ensure_inode_update(node.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        inode.require_mutation(InodeMutation::Metadata)?;
        raw_inode.set_ext4_times(times, self.volume.superblock.inode_timestamp_encoding())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Sets or replaces one ext4 extended attribute.
    ///
    /// # Errors
    /// Returns an error when the inode is not mutable or the xattr set cannot
    /// fit in supported in-inode or single-block external storage.
    pub fn set_xattr(
        &mut self,
        node: TransactionNode,
        name: XattrName,
        value: XattrValue,
    ) -> Result<()> {
        self.update_xattrs(node, |set| {
            set.insert(name, value);
            Ok(())
        })
    }

    /// Removes one ext4 extended attribute.
    ///
    /// # Errors
    /// Returns an error when the inode or current xattr storage is malformed.
    pub fn remove_xattr(
        &mut self,
        node: TransactionNode,
        name: &XattrName,
    ) -> Result<Option<XattrValue>> {
        let mut removed = None;
        self.update_xattrs(node, |set| {
            removed = set.remove(name);
            Ok(())
        })?;
        Ok(removed)
    }

    /// Sets a POSIX ACL in the requested ACL xattr slot.
    ///
    /// # Errors
    /// Returns an error when the ACL cannot be serialized or stored.
    pub fn set_posix_acl(
        &mut self,
        node: TransactionNode,
        kind: PosixAclKind,
        acl: PosixAcl,
    ) -> Result<()> {
        self.set_xattr(node, PosixAcl::xattr_name(kind)?, acl.to_xattr_value()?)
    }

    /// Sets Windows overlay metadata in `user.ext4win.*` xattrs.
    ///
    /// # Errors
    /// Returns an error when the overlay cannot be serialized or stored.
    pub fn set_windows_overlay(
        &mut self,
        node: TransactionNode,
        overlay: WindowsOverlay,
    ) -> Result<()> {
        self.set_xattr(
            node,
            WindowsOverlay::attributes_xattr_name()?,
            overlay.to_xattr_value()?,
        )
    }

    /// Replaces the ext4 volume label stored in the primary superblock.
    pub fn set_volume_label(&mut self, label: Ext4VolumeLabel) {
        self.volume_label_update = Some(label);
    }

    /// Computes mounted cluster state after a successful commit.
    fn committed_cluster_state(&self) -> Result<(ClusterReferenceIndex, Superblock)> {
        let mut clusters = self.volume.state.clusters.clone();
        clusters.apply_deltas(self.cluster_deltas.as_slice())?;
        let mut superblock = self.volume.superblock;
        superblock.apply_free_cluster_delta(self.free_clusters_delta)?;
        Ok((clusters, superblock))
    }

    /// Removes a symbolic link directory entry and releases its inode.
    ///
    /// # Errors
    /// Returns an error when the entry is absent, not a symbolic link, or
    /// metadata cannot be updated.
    pub fn remove_symlink(&mut self, parent: TransactionDirectory, name: &Ext4Name) -> Result<()> {
        let removed = self.remove_directory_entry(parent.inode_id(), name)?;
        let inode_index = self.ensure_inode_update(removed.inode())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::Symlink {
            return Err(Error::WrongInodeKind);
        }
        inode.require_mutation(InodeMutation::Delete)?;
        if let Ok(tree) = self.mutable_extent_tree(&inode) {
            for extent in tree.extents().iter().copied() {
                self.free_extent(extent, 0)?;
            }
            for block in tree.metadata_blocks().iter().copied() {
                self.release_cluster_reference(block)?;
            }
        }
        self.free_inode(raw_inode.id)?;
        raw_inode.clear_deleted(self.now, self.volume.superblock.block_size())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
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
        self.require_file_data_mutation(&inode)?;
        let end_offset = offset.checked_add_len(bytes.len())?;
        if end_offset.bytes() > inode.size().bytes() {
            return Err(Error::InvalidWriteRange);
        }

        let block_size_u64 = u64::from(self.volume.superblock.block_size().bytes());
        let block_size = usize::try_from(block_size_u64).map_err(|_| Error::ArithmeticOverflow)?;
        let mut tree = self.mutable_extent_tree(&inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let encrypted_contents_key = if inode.protection().is_encrypted() {
            Some(self.volume.fscrypt_contents_key_for_inode(&inode)?)
        } else {
            None
        };
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
            match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => {
                    if let Some(contents_key) = &encrypted_contents_key {
                        self.stage_encrypted_file_block_update(
                            contents_key,
                            logical_block,
                            physical,
                            in_block,
                            bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                            EncryptedBlockBase::ExistingPlaintext,
                        )?;
                    } else {
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
                    }
                }
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.physical_block_for_hole(&tree, logical_block)?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    if let Some(contents_key) = &encrypted_contents_key {
                        self.stage_encrypted_file_block_update(
                            contents_key,
                            logical_block,
                            physical,
                            in_block,
                            bytes.get(completed..end).ok_or(Error::DeviceRange)?,
                            EncryptedBlockBase::ZeroedPlaintext,
                        )?;
                    } else {
                        let mut block = vec![0_u8; block_size];
                        let start =
                            usize::try_from(in_block).map_err(|_| Error::ArithmeticOverflow)?;
                        let block_end =
                            start.checked_add(chunk).ok_or(Error::ArithmeticOverflow)?;
                        block
                            .get_mut(start..block_end)
                            .ok_or(Error::DeviceRange)?
                            .copy_from_slice(bytes.get(completed..end).ok_or(Error::DeviceRange)?);
                        self.data_writes.push(RangeWrite {
                            offset: self.volume.superblock.block_size().offset_of(physical)?,
                            bytes: block,
                        });
                    }
                }
            }

            completed = end;
        }

        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Selects a physical block for a sparse logical block using logical-cluster placement.
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
            EncryptedBlockBase::ZeroedPlaintext => {
                vec![
                    0_u8;
                    usize::try_from(self.volume.superblock.block_size().bytes())
                        .map_err(|_| Error::ArithmeticOverflow)?
                ]
            }
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
        self.data_writes.push(RangeWrite {
            offset: self.volume.superblock.block_size().offset_of(physical)?,
            bytes: block,
        });
        Ok(())
    }

    /// Returns the latest plaintext image of one file block for encrypted updates.
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
            staged.bytes.clone()
        } else {
            let mut bytes = vec![0_u8; block_bytes];
            self.volume.device.read_exact_at(block_offset, &mut bytes)?;
            bytes
        };
        contents_key.decrypt_block(logical_block.as_u64(), &mut block)?;
        Ok(block)
    }

    /// Returns a block at `cluster_offset` inside a fully present physical cluster.
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
            self.data_writes.push(RangeWrite {
                offset: ByteOffset::new(write_offset),
                bytes: bytes
                    .get(completed..end)
                    .ok_or(Error::DeviceRange)?
                    .to_vec(),
            });
            completed = end;
        }
        Ok(())
    }

    /// Stages a plaintext write into an encrypted inode stream without EOF limits.
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
        let inode_index = self.ensure_inode_update(file.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        self.require_file_size_mutation(&inode)?;
        if new_size < inode.size() {
            return Err(Error::InvalidWriteRange);
        }
        self.require_inode_size_supported(new_size)?;
        raw_inode.set_size(new_size)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
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
        let extents = tree.extents().to_vec();
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
                updated.push(Extent::initialized(
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
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
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
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(&inode)?;
        }
        if inode.protection().is_verity() {
            return Err(Error::UnsupportedInodeMutation);
        }
        inode.require_mutation(InodeMutation::FileData)?;

        let mut plaintext = vec![0_u8; inode.size().to_usize()?];
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
            enable.salt().clone(),
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
        raw_inode.set_verity()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_inode, tree)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Verifies file-data mutation policy with mount-scoped fscrypt keys.
    fn require_file_data_mutation(&self, inode: &Inode) -> Result<()> {
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
            if inode.kind() != InodeKind::File || inode.protection().is_verity() {
                return Err(Error::UnsupportedEncryption);
            }
        }
        inode.require_mutation(InodeMutation::FileData)
    }

    /// Verifies file-size mutation policy with mount-scoped fscrypt keys.
    fn require_file_size_mutation(&self, inode: &Inode) -> Result<()> {
        if inode.protection().is_encrypted() {
            self.volume.require_encryption_key(inode)?;
            if inode.kind() != InodeKind::File || inode.protection().is_verity() {
                return Err(Error::UnsupportedEncryption);
            }
        }
        inode.require_mutation(InodeMutation::FileSize)
    }

    /// Verifies directory-entry mutation policy using the latest staged inode.
    fn require_directory_entry_mutation(
        &self,
        inode_id: InodeId,
        mutation: InodeMutation,
    ) -> Result<()> {
        let raw_inode = self.raw_inode_for_policy(inode_id)?;
        let inode = raw_inode.parse()?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        self.require_directory_entry_mutation_for_inode(&inode, mutation)
    }

    /// Verifies directory-entry mutation policy with mount-scoped fscrypt keys.
    fn require_directory_entry_mutation_for_inode(
        &self,
        inode: &Inode,
        mutation: InodeMutation,
    ) -> Result<()> {
        if inode.protection().is_encrypted() {
            match mutation {
                InodeMutation::DirectoryEntryDelete => {}
                InodeMutation::DirectoryEntryCreate
                | InodeMutation::DirectoryEntryRename
                | InodeMutation::DirectoryEntryReplace => {
                    self.volume.require_encryption_key(inode)?;
                }
                InodeMutation::Metadata
                | InodeMutation::FileData
                | InodeMutation::FileSize
                | InodeMutation::Delete => {}
            }
        }
        inode.require_mutation(mutation)
    }

    /// Builds the fscrypt context inherited by a new child of this directory.
    fn inherited_fscrypt_context(&mut self, parent: &Inode) -> Result<Option<FscryptContextV2>> {
        if !parent.protection().is_encrypted() {
            return Ok(None);
        }
        let (parent_context, _master_key) = self.volume.fscrypt_master_key_for_inode(parent)?;
        let nonce = self.volume.mount_context.next_fscrypt_file_nonce()?;
        Ok(Some(FscryptContextV2::new(parent_context.policy(), nonce)))
    }

    /// Stores an inherited fscrypt context on a newly-initialized raw inode.
    fn apply_fscrypt_context(
        &mut self,
        raw_inode: &mut RawInode,
        context: Option<FscryptContextV2>,
    ) -> Result<()> {
        let Some(context) = context else {
            return Ok(());
        };
        self.require_xattr_mutation()?;
        raw_inode.set_encrypted()?;
        let mut set = self.xattr_set_for_raw_inode(raw_inode)?;
        set.set_encryption_context(XattrValue::new(&context.to_bytes())?);
        self.store_xattr_set(raw_inode, &set)
    }

    /// Returns the staged inode record when present, otherwise the device image.
    fn raw_inode_for_policy(&self, inode_id: InodeId) -> Result<RawInode> {
        if let Some(raw_inode) = self
            .inode_updates
            .iter()
            .find(|raw_inode| raw_inode.id == inode_id)
        {
            return Ok(raw_inode.clone());
        }
        self.volume.read_raw_inode(inode_id)
    }

    /// Verifies that a directory does not already contain `name`.
    fn ensure_child_absent(&self, parent: InodeId, name: &Ext4Name) -> Result<()> {
        match self.find_child_entry(parent, name) {
            Ok(_) => Err(Error::NameAlreadyExists),
            Err(Error::DirectoryEntryNotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Finds a live directory entry by exact ext4 name.
    fn find_child_entry(&self, parent: InodeId, name: &Ext4Name) -> Result<DirectoryEntry> {
        let inode = self.volume.read_inode_record(parent)?;
        if inode.kind() != InodeKind::Directory {
            return Err(Error::WrongInodeKind);
        }
        let lookup_name = self.directory_lookup_name(&inode, name)?;
        if let Some(entry) = self.directory_layout(&inode)?.find(&lookup_name) {
            return Ok(entry);
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Returns the on-disk name to use for a directory lookup inside this transaction.
    fn directory_lookup_name(&self, directory: &Inode, name: &Ext4Name) -> Result<Ext4Name> {
        match self.volume.encrypt_directory_child_name(directory, name) {
            Err(Error::MissingEncryptionKey) => Ok(
                Volume::<D, ReadWrite<J>, N>::locked_directory_ciphertext_name(name)?
                    .unwrap_or_else(|| name.clone()),
            ),
            result => result,
        }
    }

    /// Adds a child entry to a mutable directory, extending it when supported.
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
        self.require_directory_entry_mutation_for_inode(
            &parent_inode,
            InodeMutation::DirectoryEntryCreate,
        )?;
        let disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, name)?;
        if self
            .directory_layout(&parent_inode)?
            .find(&disk_name)
            .is_some()
        {
            return Err(Error::NameAlreadyExists);
        }
        if parent_inode.is_indexed_directory() {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            entries.push(DirectoryEntry::new(child, &disk_name, kind));
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(());
        }

        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if block.insert(child, &disk_name, kind)? {
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                *self
                    .inode_updates
                    .get_mut(inode_index)
                    .ok_or(Error::InvalidInode)? = raw_parent;
                return Ok(());
            }
        }

        match self.volume.superblock.directory_indexing() {
            DirectoryIndexing::Enabled => {
                let mut entries = self.directory_layout(&parent_inode)?.entries();
                entries.push(DirectoryEntry::new(child, &disk_name, kind));
                self.stage_rebuilt_htree_directory(
                    inode_index,
                    raw_parent,
                    &parent_inode,
                    &entries,
                )?;
                return Ok(());
            }
            DirectoryIndexing::Disabled => {}
        }

        let block_size = self.volume.superblock.block_size();
        let block_size_u64 = u64::from(block_size.bytes());
        let new_physical = self.allocate_cluster()?;
        let mut tree = self.mutable_extent_tree(&parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        let logical_block =
            LogicalBlock::try_from(round_up_div(parent_inode.size().bytes(), block_size_u64)?)?;
        tree.insert_or_extend_initialized(logical_block, new_physical)?;

        let mut block = DirectoryBlock::empty(
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        );
        block.initialize_free_space()?;
        let inserted = block.insert(child, &disk_name, kind)?;
        if !inserted {
            return Err(Error::InvalidDirectoryEntry);
        }
        self.stage_directory_block(new_physical, block.into_bytes());
        let new_parent_size = FileSize::from_bytes(
            parent_inode
                .size()
                .bytes()
                .checked_add(block_size_u64)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        self.require_inode_size_supported(new_parent_size)?;
        raw_parent.set_size(new_parent_size)?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_parent, tree)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_parent;
        Ok(())
    }

    /// Removes a child entry from a mutable directory.
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
        self.require_directory_entry_mutation_for_inode(
            &parent_inode,
            InodeMutation::DirectoryEntryDelete,
        )?;
        let disk_name = self.directory_lookup_name(&parent_inode, name)?;
        if parent_inode.is_indexed_directory() {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            let Some(position) = entries.iter().position(|entry| entry.name() == &disk_name) else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let removed = entries.remove(position);
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(removed);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(removed) = block.remove(&disk_name)? {
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                *self
                    .inode_updates
                    .get_mut(inode_index)
                    .ok_or(Error::InvalidInode)? = raw_parent;
                return Ok(removed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Renames a child entry while preserving the expected child inode and kind.
    fn rename_directory_entry(
        &mut self,
        parent: InodeId,
        old_name: &Ext4Name,
        new_name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
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
        self.require_directory_entry_mutation_for_inode(
            &parent_inode,
            InodeMutation::DirectoryEntryRename,
        )?;
        let old_disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, old_name)?;
        let new_disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, new_name)?;
        if parent_inode.is_indexed_directory() {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            if entries.iter().any(|entry| entry.name() == &new_disk_name) {
                return Err(Error::NameAlreadyExists);
            }
            let Some(position) = entries
                .iter()
                .position(|entry| entry.name() == &old_disk_name)
            else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let renamed = entries
                .get(position)
                .ok_or(Error::InvalidDirectoryEntry)?
                .clone();
            if renamed.inode() != child {
                return Err(Error::InvalidDirectoryEntry);
            }
            *entries
                .get_mut(position)
                .ok_or(Error::InvalidDirectoryEntry)? =
                DirectoryEntry::new(child, &new_disk_name, kind);
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(renamed);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(renamed) = block.rename(&old_disk_name, &new_disk_name)? {
                if renamed.inode() != child {
                    return Err(Error::InvalidDirectoryEntry);
                }
                let replacement = block.replace(&new_disk_name, child, kind)?;
                if replacement.is_none() {
                    return Err(Error::InvalidDirectoryEntry);
                }
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                *self
                    .inode_updates
                    .get_mut(inode_index)
                    .ok_or(Error::InvalidInode)? = raw_parent;
                return Ok(renamed);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Replaces the inode and kind stored for an existing directory name.
    fn replace_directory_entry(
        &mut self,
        parent: InodeId,
        name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
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
        self.require_directory_entry_mutation_for_inode(
            &parent_inode,
            InodeMutation::DirectoryEntryReplace,
        )?;
        let disk_name = self
            .volume
            .encrypt_directory_child_name(&parent_inode, name)?;
        if parent_inode.is_indexed_directory() {
            let mut entries = self.directory_layout(&parent_inode)?.entries();
            let Some(position) = entries.iter().position(|entry| entry.name() == &disk_name) else {
                return Err(Error::DirectoryEntryNotFound);
            };
            let replaced = entries
                .get(position)
                .ok_or(Error::InvalidDirectoryEntry)?
                .clone();
            *entries
                .get_mut(position)
                .ok_or(Error::InvalidDirectoryEntry)? =
                DirectoryEntry::new(child, &disk_name, kind);
            self.stage_rebuilt_htree_directory(inode_index, raw_parent, &parent_inode, &entries)?;
            return Ok(replaced);
        }
        for (_logical, physical, mut block) in self.directory_blocks(&parent_inode)? {
            if let Some(replaced) = block.replace(&disk_name, child, kind)? {
                self.stage_directory_block(physical, block.into_bytes());
                raw_parent
                    .set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
                *self
                    .inode_updates
                    .get_mut(inode_index)
                    .ok_or(Error::InvalidInode)? = raw_parent;
                return Ok(replaced);
            }
        }
        Err(Error::DirectoryEntryNotFound)
    }

    /// Rebuilds and stages one directory as a canonical HTree image.
    fn stage_rebuilt_htree_directory(
        &mut self,
        inode_index: usize,
        mut raw_parent: RawInode,
        parent_inode: &Inode,
        entries: &[DirectoryEntry],
    ) -> Result<()> {
        let dot = entries
            .iter()
            .find(|entry| entry.name().bytes() == b".")
            .ok_or(Error::InvalidDirectoryEntry)?;
        if dot.inode() != parent_inode.id() {
            return Err(Error::InvalidDirectoryEntry);
        }
        let dotdot = entries
            .iter()
            .find(|entry| entry.name().bytes() == b"..")
            .ok_or(Error::InvalidDirectoryEntry)?;
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let checksum = self.volume.directory_checksum(parent_inode);
        let image = build_htree_directory(
            parent_inode.id(),
            dotdot.inode(),
            entries,
            block_bytes,
            self.volume.superblock.directory_hash_seed(),
            self.volume.superblock.default_directory_hash_version(),
            checksum,
        )?;
        let existing_blocks =
            round_up_div(parent_inode.size().bytes(), u64::from(block_size.bytes()))?;
        let image_blocks =
            u64::try_from(image.block_count()).map_err(|_| Error::ArithmeticOverflow)?;
        let target_blocks = existing_blocks.max(image_blocks);
        let mut tree = self.mutable_extent_tree(parent_inode)?;
        if tree.contains_uninitialized() {
            return Err(Error::UnsupportedInodeMutation);
        }
        for logical in 0..image_blocks {
            let logical_block = LogicalBlock::try_from(logical)?;
            let physical = match tree.map_logical(logical_block) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized => return Err(Error::UnsupportedInodeMutation),
                BlockMapping::Hole => {
                    let physical = self.allocate_cluster()?;
                    tree.insert_or_extend_initialized(logical_block, physical)?;
                    physical
                }
            };
            let image_block = image
                .blocks()
                .get(usize::try_from(logical).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::InvalidDirectoryEntry)?
                .clone();
            self.stage_directory_block(physical, image_block);
        }
        raw_parent.set_indexed_directory()?;
        let rebuilt_size = FileSize::from_bytes(
            target_blocks
                .checked_mul(u64::from(block_size.bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        );
        self.require_inode_size_supported(rebuilt_size)?;
        raw_parent.set_size(rebuilt_size)?;
        raw_parent.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        self.stage_extent_tree(&mut raw_parent, tree)?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_parent;
        Ok(())
    }

    /// Stages the latest image for a mutated directory block.
    fn stage_directory_block(&mut self, block: BlockAddress, bytes: Vec<u8>) {
        if let Some(image) = self
            .directory_updates
            .iter_mut()
            .find(|image| image.block == block)
        {
            image.bytes = bytes;
        } else {
            self.directory_updates.push(BlockImage { block, bytes });
        }
    }

    /// Stages the latest image for a mutated external xattr block.
    fn stage_xattr_block(&mut self, block: BlockAddress, bytes: Vec<u8>) {
        if let Some(image) = self
            .xattr_updates
            .iter_mut()
            .find(|image| image.block == block)
        {
            image.bytes = bytes;
        } else {
            self.xattr_updates.push(BlockImage { block, bytes });
        }
    }

    /// Reads an external xattr block, preferring this transaction's staged image.
    fn xattr_block_bytes(&self, block: BlockAddress) -> Result<Vec<u8>> {
        if let Some(staged) = self
            .xattr_updates
            .iter()
            .rev()
            .find(|image| image.block == block)
        {
            return Ok(staged.bytes.clone());
        }
        let block_size = self.volume.superblock.block_size();
        let mut bytes =
            vec![0_u8; usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?];
        self.volume
            .device
            .read_exact_at(block_size.offset_of(block)?, &mut bytes)?;
        Ok(bytes)
    }

    /// Reads all xattrs referenced by a staged raw inode.
    fn xattr_set_for_raw_inode(&self, raw_inode: &RawInode) -> Result<InodeXattrSet> {
        match self.volume.superblock.xattr_mutation() {
            XattrMutationSupport::Disabled => return Ok(InodeXattrSet::empty()),
            XattrMutationSupport::Enabled => {}
        }
        let inline = xattr_storage::parse_inline_xattrs(raw_inode.inline_xattr_region()?)?;
        let Some(block) = raw_inode.xattr_block()? else {
            return Ok(inline);
        };
        let bytes = self.xattr_block_bytes(block)?;
        let external =
            xattr_storage::parse_external_xattr_block(&bytes, block, &self.volume.superblock)?;
        xattr_storage::merge_xattr_sets(inline, external)
    }

    /// Applies a mutation to an inode's complete xattr set.
    fn update_xattrs(
        &mut self,
        node: TransactionNode,
        update: impl FnOnce(&mut XattrSet) -> Result<()>,
    ) -> Result<()> {
        self.require_xattr_mutation()?;
        let inode_index = self.ensure_inode_update(node.inode_id())?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let inode = raw_inode.parse()?;
        inode.require_mutation(InodeMutation::Metadata)?;

        let mut set = self.xattr_set_for_raw_inode(&raw_inode)?;
        update(set.public_mut())?;
        self.store_xattr_set(&mut raw_inode, &set)?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Stores a complete xattr set using inline storage when possible and one
    /// external xattr block otherwise.
    fn store_xattr_set(&mut self, raw_inode: &mut RawInode, set: &InodeXattrSet) -> Result<()> {
        let old_block = raw_inode.xattr_block()?;
        if set.is_empty() {
            raw_inode.clear_inline_xattr_region()?;
            if let Some(block) = old_block {
                self.release_xattr_block_ref(block)?;
            }
            raw_inode.set_xattr_block(None)?;
            return Ok(());
        }

        let inline_capacity = raw_inode.writable_inline_xattr_region()?.len();
        match xattr_storage::serialize_inline_xattrs(set, inline_capacity) {
            Ok(bytes) => {
                raw_inode
                    .writable_inline_xattr_region()?
                    .copy_from_slice(&bytes);
                if let Some(block) = old_block {
                    self.release_xattr_block_ref(block)?;
                }
                raw_inode.set_xattr_block(None)
            }
            Err(Error::NoSpace) => self.store_external_xattr_set(raw_inode, set, old_block),
            Err(error) => Err(error),
        }
    }

    /// Stores a complete xattr set in a single external block.
    fn store_external_xattr_set(
        &mut self,
        raw_inode: &mut RawInode,
        set: &InodeXattrSet,
        old_block: Option<BlockAddress>,
    ) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        xattr_storage::ensure_external_xattrs_fit(set, block_bytes)?;

        let block = if let Some(block) = old_block {
            let bytes = self.xattr_block_bytes(block)?;
            let refcount = xattr_storage::external_xattr_refcount(&bytes)?;
            if refcount == 1 {
                block
            } else {
                let new_block = self.allocate_cluster()?;
                self.release_cluster_reference(block)?;
                self.decrement_xattr_block_ref(block, bytes, refcount)?;
                new_block
            }
        } else {
            self.allocate_cluster()?
        };
        let bytes = xattr_storage::serialize_external_xattr_block(
            set,
            block_bytes,
            block,
            &self.volume.superblock,
        )?;
        self.stage_xattr_block(block, bytes);
        raw_inode.clear_inline_xattr_region()?;
        raw_inode.set_xattr_block(Some(block))
    }

    /// Releases one inode reference to an external xattr block.
    fn release_xattr_block_ref(&mut self, block: BlockAddress) -> Result<()> {
        let bytes = self.xattr_block_bytes(block)?;
        let refcount = xattr_storage::external_xattr_refcount(&bytes)?;
        self.release_cluster_reference(block)?;
        if refcount > 1 {
            self.decrement_xattr_block_ref(block, bytes, refcount)
        } else {
            Ok(())
        }
    }

    /// Decrements a shared external xattr block refcount.
    fn decrement_xattr_block_ref(
        &mut self,
        block: BlockAddress,
        mut bytes: Vec<u8>,
        refcount: u32,
    ) -> Result<()> {
        let updated = refcount.checked_sub(1).ok_or(Error::InvalidXattr)?;
        xattr_storage::set_external_xattr_refcount(
            &mut bytes,
            block,
            &self.volume.superblock,
            updated,
        )?;
        self.stage_xattr_block(block, bytes);
        Ok(())
    }

    /// Returns whether a directory contains only `.` and `..`.
    fn directory_is_empty(&self, inode: &Inode) -> Result<bool> {
        for entry in self.directory_layout(inode)?.entries() {
            let name = entry.name().bytes();
            if name != b"." && name != b".." {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Loads the staged-aware directory layout for mutation-time lookups.
    fn directory_layout(&self, inode: &Inode) -> Result<DirectoryLayout> {
        if inode.is_indexed_directory() {
            self.volume
                .superblock
                .directory_indexing()
                .require_supported()?;
        }
        let mut blocks = Vec::new();
        for (logical, _physical, block) in self.directory_blocks(inode)? {
            blocks.push(DirectoryBlockData::new(
                logical.as_u32(),
                block.into_bytes(),
            ));
        }
        DirectoryLayout::parse(
            inode.is_indexed_directory(),
            blocks,
            self.volume.superblock.directory_hash_seed(),
            self.volume.superblock.default_directory_hash_version(),
            self.volume.directory_checksum(inode),
        )
    }

    /// Loads directory blocks, preferring staged images over device bytes.
    fn directory_blocks(
        &self,
        inode: &Inode,
    ) -> Result<Vec<(LogicalBlock, BlockAddress, DirectoryBlock)>> {
        let block_size = self.volume.superblock.block_size();
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        let block_count = round_up_div(inode.size().bytes(), u64::from(block_size.bytes()))?;
        let tree = MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            &self.volume.device,
            self.volume.extent_tree_context(inode),
        )?;
        let mut blocks = Vec::new();
        for logical in 0..block_count {
            let logical = LogicalBlock::try_from(logical)?;
            let physical = match tree.map_logical(logical) {
                BlockMapping::Physical(physical) => physical,
                BlockMapping::Uninitialized | BlockMapping::Hole => {
                    return Err(Error::InvalidDirectoryEntry);
                }
            };
            let bytes = if let Some(staged) = self
                .directory_updates
                .iter()
                .find(|image| image.block == physical)
            {
                if staged.bytes.len() != block_bytes {
                    return Err(Error::InvalidDirectoryEntry);
                }
                staged.bytes.clone()
            } else {
                let mut bytes = vec![0_u8; block_bytes];
                self.volume
                    .device
                    .read_exact_at(block_size.offset_of(physical)?, &mut bytes)?;
                bytes
            };
            blocks.push((logical, physical, DirectoryBlock::new(bytes)));
        }
        Ok(blocks)
    }

    /// Loads a mutable extent tree for an inode selected by this transaction.
    fn mutable_extent_tree(&self, inode: &Inode) -> Result<MutableExtentTree> {
        MutableExtentTree::load_inode_tree(
            inode.extent_root()?,
            self.volume.superblock.block_size(),
            &self.volume.device,
            self.volume.extent_tree_context(inode),
        )
    }

    /// Stages an updated extent tree and adjusts its metadata block ownership.
    fn stage_extent_tree(
        &mut self,
        raw_inode: &mut RawInode,
        mut tree: MutableExtentTree,
    ) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let required = tree.required_metadata_blocks(block_size)?;
        let mut metadata_blocks = tree.metadata_blocks().to_vec();
        while metadata_blocks.len() < required {
            metadata_blocks.push(self.allocate_cluster()?);
        }
        while metadata_blocks.len() > required {
            let block = metadata_blocks.pop().ok_or(Error::InvalidExtentTree)?;
            self.release_cluster_reference(block)?;
        }
        tree.set_metadata_blocks(metadata_blocks);

        let inode = raw_inode.parse()?;
        let serialized = tree.serialize(block_size, self.volume.extent_tree_context(&inode))?;
        self.stage_serialized_extent_tree(raw_inode, &serialized)?;
        let allocated_blocks = self.allocated_data_blocks(&tree)?;
        self.require_allocated_blocks_supported(allocated_blocks)?;
        raw_inode.set_allocated_blocks(allocated_blocks, u64::from(block_size.bytes()))
    }

    /// Counts physical blocks charged to an inode through allocation clusters.
    fn allocated_data_blocks(&self, tree: &MutableExtentTree) -> Result<u64> {
        let mut clusters = Vec::new();
        for extent in tree.extents().iter().copied() {
            for offset in 0..extent.len().as_u64() {
                let cluster = self.volume.superblock.cluster_of_block(BlockAddress::new(
                    extent
                        .physical_start()
                        .get()
                        .checked_add(offset)
                        .ok_or(Error::ArithmeticOverflow)?,
                ))?;
                if !clusters.contains(&cluster) {
                    clusters.push(cluster);
                }
            }
        }
        let mut blocks = 0_u64;
        for cluster in clusters {
            blocks = blocks
                .checked_add(u64::from(
                    self.volume.superblock.blocks_in_cluster(cluster)?,
                ))
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(blocks)
    }

    /// Copies a serialized extent tree into the inode and metadata block staging areas.
    fn stage_serialized_extent_tree(
        &mut self,
        raw_inode: &mut RawInode,
        serialized: &SerializedExtentTree,
    ) -> Result<()> {
        raw_inode.set_extent_root_bytes(serialized.inode_root())?;
        for block in serialized.external_blocks() {
            self.extent_updates.push(BlockImage {
                block: block.block(),
                bytes: block.bytes().to_vec(),
            });
        }
        Ok(())
    }

    /// Increments a directory inode link count and updates timestamps.
    fn increment_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        raw_inode.increment_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Decrements a directory inode link count and updates timestamps.
    fn decrement_directory_links(&mut self, inode_id: InodeId) -> Result<()> {
        let inode_index = self.ensure_inode_update(inode_id)?;
        let mut raw_inode = self
            .inode_updates
            .get(inode_index)
            .ok_or(Error::InvalidInode)?
            .clone();
        let _links = raw_inode.decrement_links_count()?;
        raw_inode.set_timestamps(self.now, self.volume.superblock.inode_timestamp_encoding())?;
        *self
            .inode_updates
            .get_mut(inode_index)
            .ok_or(Error::InvalidInode)? = raw_inode;
        Ok(())
    }

    /// Aborts the transaction without writing staged data or metadata.
    pub fn abort(self) {}

    /// Returns the staged inode record index, loading it once when needed.
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

    /// Allocates the first free allocation cluster visible in group bitmaps.
    fn allocate_cluster(&mut self) -> Result<BlockAddress> {
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
                    bitmap_bit(bitmap.bytes.as_slice(), bit)?
                };
                if occupied {
                    continue;
                }
                if self.staged_cluster_reference_count(cluster)? != 0 {
                    return Err(Error::ClusterReferenceConflict);
                }
                let bitmap = self
                    .block_bitmap_updates
                    .get_mut(bitmap_index)
                    .ok_or(Error::InvalidSuperblock)?;
                set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, true)?;
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
    fn stage_cluster_zeroes(&mut self, cluster: ClusterAddress) -> Result<()> {
        let first_block = self.volume.superblock.first_block_of_cluster(cluster)?;
        let blocks = self.volume.superblock.blocks_in_cluster(cluster)?;
        let bytes = usize::try_from(
            u64::from(blocks)
                .checked_mul(u64::from(self.volume.superblock.block_size().bytes()))
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        self.data_writes.push(RangeWrite {
            offset: self.volume.superblock.block_size().offset_of(first_block)?,
            bytes: vec![0_u8; bytes],
        });
        Ok(())
    }

    /// Records one staged cluster-reference delta after checking underflow.
    fn record_cluster_reference_delta(
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
                .push(ClusterReferenceDelta { cluster, delta });
        }
        Ok(())
    }

    /// Returns mounted plus staged references for one cluster.
    fn staged_cluster_reference_count(&self, cluster: ClusterAddress) -> Result<i32> {
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
    fn release_cluster_reference(&mut self, block: BlockAddress) -> Result<()> {
        let cluster = self.volume.superblock.cluster_of_block(block)?;
        self.record_cluster_reference_delta(cluster, -1)?;
        if self.staged_cluster_reference_count(cluster)? == 0 {
            self.free_cluster(cluster)?;
        }
        Ok(())
    }

    /// Clears one cluster bitmap bit and records the affected accounting deltas.
    fn free_cluster(&mut self, cluster: ClusterAddress) -> Result<()> {
        let group = self.volume.superblock.cluster_group_of(cluster)?;
        let descriptor =
            BlockGroupDescriptor::read_from(&self.volume.device, &self.volume.superblock, group)?;
        let bitmap_index = self.ensure_block_bitmap_update(descriptor.block_bitmap())?;
        let bitmap = self
            .block_bitmap_updates
            .get_mut(bitmap_index)
            .ok_or(Error::InvalidSuperblock)?;
        let bit = self
            .volume
            .superblock
            .cluster_bit_in_group(cluster, group)?;
        if bitmap_bit(bitmap.bytes.as_slice(), bit)? {
            set_bitmap_bit(bitmap.bytes.as_mut_slice(), bit, false)?;
            self.record_group_free_clusters_delta(group, FreeClusterDelta::from_i64(1))?;
            self.free_clusters_delta = self.free_clusters_delta.checked_add(1)?;
            Ok(())
        } else {
            Err(Error::ClusterReferenceConflict)
        }
    }

    /// Frees the suffix of an extent after `keep_len` blocks.
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
            self.release_cluster_reference(block)?;
        }
        if physical_start > extent.physical_start().get() || keep_len == 0 {
            Ok(())
        } else {
            Err(Error::ArithmeticOverflow)
        }
    }

    /// Allocates the first non-reserved inode visible in inode bitmaps.
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

    /// Marks an inode free and records its group allocation delta.
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

    /// Stages zeroes for the remainder of a partially truncated data block.
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

    /// Stages encrypted zeroes for the plaintext suffix of a truncated block.
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
        let zeroes = vec![0_u8; zero_len];
        self.stage_encrypted_file_block_update(
            &contents_key,
            LogicalBlock::try_from(logical_block)?,
            physical,
            in_block,
            &zeroes,
            EncryptedBlockBase::ExistingPlaintext,
        )
    }

    /// Returns the staged block bitmap index, loading it once when needed.
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

    /// Returns the staged inode bitmap index, loading it once when needed.
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

    /// Returns the inode count actually present in a possibly partial group.
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

    /// Converts a group-local inode bitmap bit into an inode number.
    fn inode_id_in_group(&self, group: BlockGroupId, bit: u32) -> Result<InodeId> {
        let zero_based = group
            .as_u32()
            .checked_mul(self.volume.superblock.inodes_per_group().as_u32())
            .ok_or(Error::ArithmeticOverflow)?
            .checked_add(bit)
            .ok_or(Error::ArithmeticOverflow)?;
        InodeId::try_from(zero_based.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }

    /// Creates a zeroed inode record at the allocated inode's device offset.
    fn empty_raw_inode(&self, inode_id: InodeId) -> Result<RawInode> {
        Ok(RawInode {
            id: inode_id,
            offset: inode_offset_on_device(&self.volume.device, &self.volume.superblock, inode_id)?,
            bytes: vec![0_u8; usize::from(self.volume.superblock.inode_size().as_u16())],
        })
    }

    /// Returns the mutable delta accumulator for a block group.
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

    /// Records a free-cluster count delta for one block group.
    fn record_group_free_clusters_delta(
        &mut self,
        group: BlockGroupId,
        delta: FreeClusterDelta,
    ) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.free_clusters_delta = entry.free_clusters_delta.checked_add(delta.as_i64())?;
        Ok(())
    }

    /// Records a free-inode count delta for one block group and the superblock.
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

    /// Records a used-directory count delta for one block group.
    fn record_group_used_dirs_delta(&mut self, group: BlockGroupId, delta: i64) -> Result<()> {
        let entry = self.group_delta_mut(group)?;
        entry.used_dirs_delta = entry
            .used_dirs_delta
            .checked_add(delta)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }

    /// Serializes all staged metadata mutations into byte-range writes.
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
        for extent in &self.extent_updates {
            writes.push(RangeWrite {
                offset: self
                    .volume
                    .superblock
                    .block_size()
                    .offset_of(extent.block)?,
                bytes: extent.bytes.clone(),
            });
        }
        for xattr in &self.xattr_updates {
            writes.push(RangeWrite {
                offset: self.volume.superblock.block_size().offset_of(xattr.block)?,
                bytes: xattr.bytes.clone(),
            });
        }
        for delta in &self.group_deltas {
            let mut descriptor = BlockGroupDescriptor::read_from(
                &self.volume.device,
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
            writes.push(RangeWrite {
                offset: descriptor.offset(),
                bytes: descriptor.bytes().to_vec(),
            });
        }
        if !self.free_clusters_delta.is_zero()
            || self.free_inodes_delta != 0
            || self.volume_label_update.is_some()
        {
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

    /// Coalesces metadata byte ranges into full blocks for journaling.
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

    /// Writes ordered file data before the metadata transaction is committed.
    fn write_ordered_data(&mut self) -> Result<()> {
        for write in &self.data_writes {
            self.volume
                .device
                .write_exact_at(write.offset, write.bytes.as_slice())?;
        }
        self.volume.device.flush()
    }

    /// Applies accumulated free-count deltas to a superblock image.
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
        if let Some(label) = self.volume_label_update {
            label.write_to(&mut bytes)?;
        }
        Superblock::refresh_checksum(&mut bytes)?;
        Ok(bytes)
    }
}

impl<D: BlockWriter, N: FscryptNonceGenerator> WriteTransaction<'_, D, InternalJournal, N> {
    /// Commits staged data and metadata through the internal journal.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub fn commit(mut self) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let metadata_blocks = self.metadata_blocks()?;
        let (clusters, superblock) = self.committed_cluster_state()?;
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
        )?;
        volume.state.clusters = clusters;
        volume.superblock = superblock;
        Ok(())
    }
}

impl<D: BlockWriter, J: BlockWriter, N: FscryptNonceGenerator>
    WriteTransaction<'_, D, ExternalJournal<J>, N>
{
    /// Commits staged data and metadata through the external journal device.
    ///
    /// # Errors
    /// Returns an error when the transaction exceeds journal capacity or any
    /// backing device write/flush fails.
    pub fn commit(mut self) -> Result<()> {
        let block_size = self.volume.superblock.block_size();
        let metadata_blocks = self.metadata_blocks()?;
        let (clusters, superblock) = self.committed_cluster_state()?;
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
        )?;
        volume.state.clusters = clusters;
        volume.superblock = superblock;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Writable raw inode record paired with its inode number and device offset.
struct RawInode {
    /// Inode number represented by this raw record.
    id: InodeId,
    /// Absolute device offset of the inode record.
    offset: ByteOffset,
    /// Writable inode record bytes.
    bytes: Vec<u8>,
}

impl RawInode {
    /// Returns the raw inode mode field without imposing a supported kind.
    fn mode(&self) -> Result<u16> {
        le_u16(&self.bytes, INODE_MODE_OFFSET)
    }

    /// Returns whether the raw inode advertises an extent tree.
    fn has_extent_tree(&self) -> Result<bool> {
        Ok(le_u32(&self.bytes, INODE_FLAGS_OFFSET)? & EXT4_EXTENTS_FL != 0)
    }

    /// Marks a directory inode as HTree indexed.
    fn set_indexed_directory(&mut self) -> Result<()> {
        let flags = le_u32(&self.bytes, INODE_FLAGS_OFFSET)?;
        self.set_flags(flags | EXT4_INDEX_FL)
    }

    /// Marks a regular file inode as fs-verity protected.
    fn set_verity(&mut self) -> Result<()> {
        let flags = le_u32(&self.bytes, INODE_FLAGS_OFFSET)?;
        self.set_flags(flags | EXT4_VERITY_FL)
    }

    /// Marks an inode as fscrypt protected.
    fn set_encrypted(&mut self) -> Result<()> {
        let flags = le_u32(&self.bytes, INODE_FLAGS_OFFSET)?;
        self.set_flags(flags | EXT4_ENCRYPT_FL)
    }

    /// Parses the raw bytes as a validated inode.
    fn parse(&self) -> Result<Inode> {
        Inode::parse(self.id, &self.bytes)
    }

    /// Initializes a zeroed inode record as an empty extent-backed file.
    fn initialize_file(
        &mut self,
        metadata: NewFileMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(MODE_REGULAR, metadata.permissions())?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(0))?;
        self.set_links_count(1)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(EXT4_EXTENTS_FL)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        self.set_allocated_blocks(0, 1024)
    }

    /// Initializes a zeroed inode record as a directory owning its first block.
    fn initialize_directory(
        &mut self,
        metadata: NewDirectoryMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        first_block: BlockAddress,
        allocated_blocks: u64,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        self.bytes.fill(0);
        self.set_mode(MODE_DIRECTORY, metadata.permissions())?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(u64::from(block_size.bytes())))?;
        self.set_links_count(2)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(EXT4_EXTENTS_FL)?;
        let tree = MutableExtentTree::from_extents(vec![Extent::initialized(
            LogicalBlock::from_u32(0),
            ExtentLength::new(1)?,
            first_block,
        )])?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        self.set_allocated_blocks(allocated_blocks, u64::from(block_size.bytes()))
    }

    /// Initializes a zeroed inode record as an inline symbolic link.
    fn initialize_inline_symlink(
        &mut self,
        metadata: NewSymlinkMetadata,
        now: Ext4Timestamp,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        if !target.is_inline() {
            return Err(Error::InvalidWriteRange);
        }
        self.bytes.fill(0);
        self.set_mode(MODE_SYMLINK, metadata.permissions())?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_links_count(1)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(0)?;
        self.set_inline_target(target.bytes())?;
        self.set_allocated_blocks(0, 1024)
    }

    /// Initializes a zeroed inode record as an extent-backed symbolic link.
    fn initialize_extent_symlink(
        &mut self,
        metadata: NewSymlinkMetadata,
        now: Ext4Timestamp,
        block_size: BlockSize,
        target: &SymlinkTarget,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        if target.is_inline() {
            return Err(Error::InvalidWriteRange);
        }
        self.bytes.fill(0);
        self.set_mode(MODE_SYMLINK, metadata.permissions())?;
        self.set_owner(metadata.owner())?;
        self.set_size(FileSize::from_bytes(
            u64::try_from(target.bytes().len()).map_err(|_| Error::ArithmeticOverflow)?,
        ))?;
        self.set_links_count(1)?;
        self.set_timestamps(now, timestamp_encoding)?;
        self.set_creation_time(now, timestamp_encoding)?;
        self.set_deletion_time(0)?;
        self.set_flags(EXT4_EXTENTS_FL)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())?;
        self.set_allocated_blocks(0, 1024)
    }

    /// Writes inode type and permission bits into `i_mode`.
    fn set_mode(&mut self, file_type: u16, permissions: Ext4Permissions) -> Result<()> {
        put_le_u16(
            &mut self.bytes,
            INODE_MODE_OFFSET,
            file_type | permissions.as_u16(),
        )
    }

    /// Updates inode permission bits without changing the inode type.
    fn set_permissions(&mut self, permissions: Ext4Permissions) -> Result<()> {
        let mode = le_u16(&self.bytes, INODE_MODE_OFFSET)?;
        put_le_u16(
            &mut self.bytes,
            INODE_MODE_OFFSET,
            (mode & MODE_KIND_MASK) | permissions.as_u16(),
        )
    }

    /// Writes low and high UID/GID fields when the inode record can hold them.
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

    /// Writes the inode link count.
    fn set_links_count(&mut self, links: u16) -> Result<()> {
        put_le_u16(&mut self.bytes, INODE_LINKS_COUNT_OFFSET, links)
    }

    /// Increments the inode link count with overflow checking.
    fn increment_links_count(&mut self) -> Result<()> {
        let links = self.parse()?.links_count();
        self.set_links_count(links.checked_add(1).ok_or(Error::ArithmeticOverflow)?)
    }

    /// Decrements the inode link count with underflow checking.
    fn decrement_links_count(&mut self) -> Result<u16> {
        let links = self.parse()?.links_count();
        let updated = links.checked_sub(1).ok_or(Error::InvalidInode)?;
        self.set_links_count(updated)?;
        Ok(updated)
    }

    /// Writes the inode flags field.
    fn set_flags(&mut self, flags: u32) -> Result<()> {
        put_le_u32(&mut self.bytes, INODE_FLAGS_OFFSET, flags)
    }

    /// Splits a file size across low and high inode size fields.
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

    /// Updates access, change, and modification timestamps.
    fn set_timestamps(
        &mut self,
        now: Ext4Timestamp,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        put_le_u32(&mut self.bytes, INODE_ATIME_OFFSET, now.seconds())?;
        put_le_u32(&mut self.bytes, INODE_CTIME_OFFSET, now.seconds())?;
        put_le_u32(&mut self.bytes, INODE_MTIME_OFFSET, now.seconds())?;
        match timestamp_encoding {
            InodeTimestampEncoding::LegacySeconds => {}
            InodeTimestampEncoding::ExtraFields => {
                if self.bytes.len() > INODE_ATIME_EXTRA_OFFSET {
                    self.ensure_extra_isize()?;
                    put_le_u32(&mut self.bytes, INODE_ATIME_EXTRA_OFFSET, 0)?;
                    put_le_u32(&mut self.bytes, INODE_CTIME_EXTRA_OFFSET, 0)?;
                    put_le_u32(&mut self.bytes, INODE_MTIME_EXTRA_OFFSET, 0)?;
                }
            }
        }
        Ok(())
    }

    /// Writes creation time when the inode record has extra timestamp fields.
    fn set_creation_time(
        &mut self,
        now: Ext4Timestamp,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        match timestamp_encoding {
            InodeTimestampEncoding::LegacySeconds => {}
            InodeTimestampEncoding::ExtraFields => {
                if self.bytes.len() > INODE_CRTIME_EXTRA_OFFSET {
                    self.ensure_extra_isize()?;
                    put_le_u32(&mut self.bytes, INODE_CRTIME_OFFSET, now.seconds())?;
                    put_le_u32(&mut self.bytes, INODE_CRTIME_EXTRA_OFFSET, 0)?;
                }
            }
        }
        Ok(())
    }

    /// Writes the inode deletion time field.
    fn set_deletion_time(&mut self, seconds: u32) -> Result<()> {
        put_le_u32(&mut self.bytes, INODE_DTIME_OFFSET, seconds)
    }

    /// Clears live inode state before releasing an unlinked inode.
    fn clear_deleted(&mut self, now: Ext4Timestamp, block_size: BlockSize) -> Result<()> {
        self.set_deletion_time(now.seconds())?;
        self.set_links_count(0)?;
        self.set_size(FileSize::from_bytes(0))?;
        self.set_allocated_blocks(0, 1024)?;
        let tree = MutableExtentTree::from_extents(Vec::new())?;
        let serialized = tree.serialize(block_size, ExtentTreeContext::none())?;
        self.set_extent_root_bytes(serialized.inode_root())
    }

    /// Writes the serialized extent root into `i_block`.
    fn set_extent_root_bytes(&mut self, root: &[u8; 60]) -> Result<()> {
        let end = INODE_BLOCK_OFFSET
            .checked_add(root.len())
            .ok_or(Error::ArithmeticOverflow)?;
        self.bytes
            .get_mut(INODE_BLOCK_OFFSET..end)
            .ok_or(Error::TruncatedStructure)?
            .copy_from_slice(root);
        Ok(())
    }

    /// Writes explicit ext4 inode timestamps.
    fn set_ext4_times(
        &mut self,
        times: Ext4Times,
        timestamp_encoding: InodeTimestampEncoding,
    ) -> Result<()> {
        put_le_u32(
            &mut self.bytes,
            INODE_ATIME_OFFSET,
            times.accessed().seconds(),
        )?;
        put_le_u32(
            &mut self.bytes,
            INODE_CTIME_OFFSET,
            times.changed().seconds(),
        )?;
        put_le_u32(
            &mut self.bytes,
            INODE_MTIME_OFFSET,
            times.modified().seconds(),
        )?;
        match timestamp_encoding {
            InodeTimestampEncoding::LegacySeconds => {}
            InodeTimestampEncoding::ExtraFields => {
                if self.bytes.len() > INODE_ATIME_EXTRA_OFFSET {
                    self.ensure_extra_isize()?;
                    put_le_u32(&mut self.bytes, INODE_ATIME_EXTRA_OFFSET, 0)?;
                    put_le_u32(&mut self.bytes, INODE_CTIME_EXTRA_OFFSET, 0)?;
                    put_le_u32(&mut self.bytes, INODE_MTIME_EXTRA_OFFSET, 0)?;
                }
            }
        }
        self.set_creation_time(times.created(), timestamp_encoding)
    }

    /// Returns the external xattr block referenced by `i_file_acl`.
    fn xattr_block(&self) -> Result<Option<BlockAddress>> {
        if self.bytes.len() <= INODE_FILE_ACL_LO_OFFSET {
            return Ok(None);
        }
        let low = u64::from(le_u32(&self.bytes, INODE_FILE_ACL_LO_OFFSET)?);
        let high = if self.bytes.len() > INODE_FILE_ACL_HI_OFFSET {
            u64::from(le_u16(&self.bytes, INODE_FILE_ACL_HI_OFFSET)?)
        } else {
            0
        };
        let block = low | (high << 32);
        if block == 0 {
            Ok(None)
        } else {
            Ok(Some(BlockAddress::new(block)))
        }
    }

    /// Writes the external xattr block reference into `i_file_acl`.
    fn set_xattr_block(&mut self, block: Option<BlockAddress>) -> Result<()> {
        let raw = block.map_or(0, BlockAddress::get);
        put_le_u32(
            &mut self.bytes,
            INODE_FILE_ACL_LO_OFFSET,
            u32::try_from(raw & u64::from(u32::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        let high = raw >> 32;
        if self.bytes.len() > INODE_FILE_ACL_HI_OFFSET {
            put_le_u16(
                &mut self.bytes,
                INODE_FILE_ACL_HI_OFFSET,
                u16::try_from(high).map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        } else if high != 0 {
            return Err(Error::InvalidWriteRange);
        }
        Ok(())
    }

    /// Returns the in-inode xattr body region.
    fn inline_xattr_region(&self) -> Result<&[u8]> {
        let offset = self.inline_xattr_offset()?;
        self.bytes.get(offset..).ok_or(Error::InvalidXattr)
    }

    /// Returns the mutable in-inode xattr body region, initializing extra inode
    /// size before new xattrs are written.
    fn writable_inline_xattr_region(&mut self) -> Result<&mut [u8]> {
        self.ensure_extra_isize()?;
        let offset = self.inline_xattr_offset()?;
        self.bytes.get_mut(offset..).ok_or(Error::InvalidXattr)
    }

    /// Clears the in-inode xattr body region.
    fn clear_inline_xattr_region(&mut self) -> Result<()> {
        self.writable_inline_xattr_region()?.fill(0);
        Ok(())
    }

    /// Computes the in-inode xattr body offset from `i_extra_isize`.
    fn inline_xattr_offset(&self) -> Result<usize> {
        if self.bytes.len() <= INODE_EXTRA_ISIZE_OFFSET {
            return Ok(self.bytes.len());
        }
        let offset = 128_usize
            .checked_add(usize::from(le_u16(&self.bytes, INODE_EXTRA_ISIZE_OFFSET)?))
            .ok_or(Error::ArithmeticOverflow)?;
        if offset > self.bytes.len() {
            return Err(Error::InvalidXattr);
        }
        Ok(offset)
    }

    /// Writes an inline symbolic link target into `i_block`.
    fn set_inline_target(&mut self, target: &[u8]) -> Result<()> {
        if target.len() > SymlinkTarget::INLINE_CAPACITY {
            return Err(Error::InvalidWriteRange);
        }
        let end = INODE_BLOCK_OFFSET
            .checked_add(SymlinkTarget::INLINE_CAPACITY)
            .ok_or(Error::ArithmeticOverflow)?;
        let block = self
            .bytes
            .get_mut(INODE_BLOCK_OFFSET..end)
            .ok_or(Error::TruncatedStructure)?;
        block.fill(0);
        block
            .get_mut(..target.len())
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(target);
        Ok(())
    }

    /// Writes allocated 512-byte sector counts from allocated data blocks.
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
            put_le_u16(
                &mut self.bytes,
                INODE_BLOCKS_HIGH_OFFSET,
                u16::try_from((sectors >> 32) & u64::from(u16::MAX))
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        Ok(())
    }

    /// Recomputes inode checksum fields when metadata checksums are enabled.
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

    /// Ensures the inode advertises enough extra space for extended fields.
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
/// Full block image staged for metadata rewrite.
struct BlockImage {
    /// Metadata block address.
    block: BlockAddress,
    /// Complete block bytes to journal and write.
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Accumulated block group accounting changes.
struct GroupDelta {
    /// Block group receiving the accounting changes.
    group: BlockGroupId,
    /// Free-cluster count delta for the descriptor.
    free_clusters_delta: FreeClusterDelta,
    /// Free-inode count delta for the descriptor.
    free_inodes_delta: i64,
    /// Used-directory count delta for the descriptor.
    used_dirs_delta: i64,
}

impl GroupDelta {
    /// Starts an empty accounting delta for one block group.
    fn new(group: BlockGroupId) -> Self {
        Self {
            group,
            free_clusters_delta: FreeClusterDelta::ZERO,
            free_inodes_delta: 0,
            used_dirs_delta: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Plaintext image used as the base for an encrypted partial-block update.
enum EncryptedBlockBase {
    /// Decrypt the existing physical block before merging the write.
    ExistingPlaintext,
    /// Start from a zero-filled plaintext block.
    ZeroedPlaintext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Byte range write staged for ordered data or metadata persistence.
struct RangeWrite {
    /// Absolute device byte offset.
    offset: ByteOffset,
    /// Bytes to write at the offset.
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Full metadata block supplied to the journal commit path.
pub(crate) struct MetadataBlock {
    /// Filesystem block address.
    block: BlockAddress,
    /// Complete metadata block bytes.
    bytes: Vec<u8>,
}

impl MetadataBlock {
    /// Returns the filesystem block address.
    pub(crate) const fn block(&self) -> BlockAddress {
        self.block
    }

    /// Returns the full metadata block bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Maps a logical block through an ordered extent list.
fn map_extents(extents: &[Extent], logical_block: LogicalBlock) -> BlockMapping {
    for extent in extents {
        match extent.map_logical(logical_block) {
            BlockMapping::Physical(block) => return BlockMapping::Physical(block),
            BlockMapping::Uninitialized => return BlockMapping::Uninitialized,
            BlockMapping::Hole => {}
        }
    }
    BlockMapping::Hole
}

/// Returns the exclusive byte end of the logical inode stream described by extents.
fn extent_payload_end_bytes(extent_tree: &ExtentTree, block_size: BlockSize) -> Result<u64> {
    let mut end_blocks = 0_u64;
    for extent in extent_tree.extents().iter().copied() {
        end_blocks = end_blocks.max(u64::from(extent.end_logical()?));
    }
    end_blocks
        .checked_mul(u64::from(block_size.bytes()))
        .ok_or(Error::ArithmeticOverflow)
}

/// Returns descriptor plus signature byte count.
fn descriptor_byte_count(signature: &[u8]) -> Result<u32> {
    u32::try_from(
        FSVERITY_DESCRIPTOR_BYTES
            .checked_add(signature.len())
            .ok_or(Error::ArithmeticOverflow)?,
    )
    .map_err(|_| Error::ArithmeticOverflow)
}

/// Builds the ext4 post-EOF verity metadata byte image.
fn verity_metadata_image(
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
    let mut image = vec![0_u8; metadata_bytes];
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
    put_le_u32(&mut image, tail_offset, descriptor_byte_count(signature)?)?;
    Ok(image)
}

/// Converts an inode kind into the directory entry file-type byte domain.
const fn directory_entry_kind(kind: InodeKind) -> DirectoryEntryKind {
    match kind {
        InodeKind::File => DirectoryEntryKind::File,
        InodeKind::Directory => DirectoryEntryKind::Directory,
        InodeKind::Symlink => DirectoryEntryKind::Symlink,
    }
}

/// Rejects `.` and `..` as caller-supplied child names.
fn reject_reserved_directory_name(name: &Ext4Name) -> Result<()> {
    if matches!(name.bytes(), b"." | b"..") {
        Err(Error::InvalidName)
    } else {
        Ok(())
    }
}

/// Divides with upward rounding and overflow checking.
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

/// Reads one allocation bitmap bit.
fn bitmap_bit(bytes: &[u8], bit: u32) -> Result<bool> {
    let byte_index = usize::try_from(bit.checked_div(8).ok_or(Error::ArithmeticOverflow)?)
        .map_err(|_| Error::ArithmeticOverflow)?;
    let bit_index = bit.checked_rem(8).ok_or(Error::ArithmeticOverflow)?;
    let byte = bytes.get(byte_index).ok_or(Error::InvalidSuperblock)?;
    Ok(byte & (1_u8 << bit_index) != 0)
}

/// Writes one allocation bitmap bit.
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

/// Reads the allocation bitmap bit for one cluster.
fn cluster_bitmap_bit(
    reader: &impl BlockReader,
    superblock: &Superblock,
    cluster: ClusterAddress,
) -> Result<bool> {
    let group = superblock.cluster_group_of(cluster)?;
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
    let mut bytes = vec![
        0_u8;
        usize::try_from(superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?
    ];
    reader.read_exact_at(
        superblock
            .block_size()
            .offset_of(descriptor.block_bitmap())?,
        &mut bytes,
    )?;
    bitmap_bit(
        bytes.as_slice(),
        superblock.cluster_bit_in_group(cluster, group)?,
    )
}

/// Reads the inode bitmap bit for one inode.
fn inode_bitmap_bit(
    reader: &impl BlockReader,
    superblock: &Superblock,
    inode_id: InodeId,
) -> Result<bool> {
    let (group, bit) = inode_group_bit(superblock, inode_id)?;
    let descriptor = BlockGroupDescriptor::read_from(reader, superblock, group)?;
    let mut bytes = vec![
        0_u8;
        usize::try_from(superblock.block_size().bytes())
            .map_err(|_| Error::ArithmeticOverflow)?
    ];
    reader.read_exact_at(
        superblock
            .block_size()
            .offset_of(descriptor.inode_bitmap())?,
        &mut bytes,
    )?;
    bitmap_bit(bytes.as_slice(), bit)
}

/// Returns the first physical block in a block group.
fn group_start_block(superblock: &Superblock, group: BlockGroupId) -> Result<BlockAddress> {
    Ok(BlockAddress::new(
        superblock
            .first_data_block()
            .get()
            .checked_add(
                u64::from(group.as_u32())
                    .checked_mul(u64::from(superblock.blocks_per_group().as_u32()))
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?,
    ))
}

/// Returns whether a group carries a superblock and descriptor-table copy.
fn group_has_superblock<D, State, N>(volume: &Volume<D, State, N>, group: BlockGroupId) -> bool {
    let value = group.as_u32();
    match volume.superblock.sparse_superblock_layout() {
        SparseSuperblockLayout::FullCopies => true,
        SparseSuperblockLayout::SparseCopies => {
            value == 0
                || value == 1
                || is_power_of(value, 3)
                || is_power_of(value, 5)
                || is_power_of(value, 7)
        }
    }
}

/// Returns true when `value` is an exact positive power of `base`.
fn is_power_of(mut value: u32, base: u32) -> bool {
    if value < base {
        return false;
    }
    while value.checked_rem(base) == Some(0) {
        value = value.checked_div(base).unwrap_or(0);
    }
    value == 1
}

/// Returns the number of blocks occupied by one descriptor-table copy.
fn descriptor_table_blocks(superblock: &Superblock) -> Result<u64> {
    let descriptor_bytes = u64::from(superblock.block_group_count()?.as_u32())
        .checked_mul(u64::from(superblock.descriptor_size().as_u16()))
        .ok_or(Error::ArithmeticOverflow)?;
    round_up_div(descriptor_bytes, u64::from(superblock.block_size().bytes()))
}

/// Returns the inode count actually present in a possibly partial group.
fn inode_count_in_group(superblock: &Superblock, group: BlockGroupId) -> Result<u32> {
    let group_start = u64::from(group.as_u32())
        .checked_mul(u64::from(superblock.inodes_per_group().as_u32()))
        .ok_or(Error::ArithmeticOverflow)?;
    let remaining = u64::from(superblock.inode_count().as_u32())
        .checked_sub(group_start)
        .ok_or(Error::InvalidSuperblock)?;
    Ok(core::cmp::min(
        superblock.inodes_per_group().as_u32(),
        u32::try_from(remaining).unwrap_or(u32::MAX),
    ))
}

/// Returns the number of blocks occupied by a group's inode table.
fn inode_table_blocks(superblock: &Superblock, group: BlockGroupId) -> Result<u64> {
    let inode_bytes = u64::from(inode_count_in_group(superblock, group)?)
        .checked_mul(u64::from(superblock.inode_size().as_u16()))
        .ok_or(Error::ArithmeticOverflow)?;
    round_up_div(inode_bytes, u64::from(superblock.block_size().bytes()))
}

/// Computes the inode bitmap group and bit for an inode number.
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

/// Computes the absolute device offset of an inode record.
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
