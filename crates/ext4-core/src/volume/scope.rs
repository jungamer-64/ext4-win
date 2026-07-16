//! Private volume module scope shared by implementation submodules.

#[cfg(test)]
pub(super) use alloc::vec;
pub(super) use alloc::vec::Vec;

pub(super) use crate::disk::block::{BlockAddress, BlockSize, ByteOffset};
pub(super) use crate::disk::checksum::crc32c;
pub(super) use crate::disk::endian::{DiskOffset, le_u16, le_u32, put_le_u16, put_le_u32};
pub(super) use crate::disk::io::{BlockSource, BlockStorage};
#[cfg(test)]
pub(super) use crate::disk_format::acl::{PosixAcl, PosixAclKind};
pub(super) use crate::disk_format::dir::{
    DirectoryBlock, DirectoryBlockData, DirectoryChecksum, DirectoryEntry as RawDirectoryEntry,
    DirectoryEntryKind, DirectoryLayout, build_htree_directory,
};
pub(super) use crate::disk_format::extent::{
    BlockMapping, Extent, ExtentLength, ExtentTree, ExtentTreeContext, LogicalBlock,
    MutableExtentTree, SerializedExtentTree,
};
pub(super) use crate::disk_format::group::BlockGroupDescriptor;
pub(super) use crate::disk_format::inode::{
    DirectoryEntryMutationCapability, DirectoryStorageKind, Ext4LinkCount, Ext4Owner,
    Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp, FileOffset,
    FilePayloadMutationCapability, FileSize, FileSizeMutationCapability, Inode, InodeFlags,
    InodeId, InodeKind, InodeMode, InodeStorage, LinkCountAfterDecrement, NewDirectoryMetadata,
    NewFileMetadata, NewSymlinkMetadata, ReadBytes, SymlinkTarget,
};
pub(super) use crate::disk_format::journal::{Journal, LoadedJournal, MetadataBlock};
pub(super) use crate::disk_format::superblock::{
    BlockGroupId, ClusterAddress, DirectoryIndexing, Ext4VolumeLabel, FreeClusterCount,
    FreeClusterDelta, InodeTimestampEncoding, JournalMode, MetadataChecksum, RecoveryState,
    SparseSuperblockLayout, Superblock, XattrMutationSupport,
};
pub(super) use crate::disk_format::xattr::{
    self as xattr_storage, InodeXattrSet, XattrName, XattrSet, XattrValue,
};
pub(super) use crate::error::{Error, Result};
pub(super) use crate::memory::{self, FallibleVec};
pub(super) use crate::platform::name::Ext4Name;
pub(super) use crate::platform::name::WindowsName;
pub(super) use crate::platform::windows::{WindowsOverlay, WindowsSymlinkReparsePoint};
pub(super) use crate::protection::fscrypt::{
    FscryptContentsKey, FscryptContextV2, FscryptFileNonce, FscryptFilenamePadding,
    FscryptFilenamesKey, FscryptKeyIdentifier, FscryptKeyPresence, FscryptKeySet, FscryptMasterKey,
    FscryptNoKeyName, FscryptNonceGenerator,
};
pub(super) use crate::protection::verity::{
    Ext4VerityMetadata, Ext4VerityMetadataLayout, FSVERITY_DESCRIPTOR_BYTES, FsverityDescriptor,
    FsverityEnable, FsverityMerkleTree,
};

pub(super) use super::block_group::{
    BitmapBitState, ClusterBitmapPosition, ClusterReferenceDelta, ClusterReferenceIndex,
    InodeBitmapPosition, cluster_bitmap_bit_state, inode_bitmap_bit_state, inode_offset_on_device,
    round_up_div, set_cluster_bitmap_bit, set_inode_bitmap_bit,
};
pub(super) use super::inode_record::{
    AllocatedInodeRecord, DeletedInodeRecord, LiveInodeRecord, RawInodeRecord, StagedInodeIndex,
    StagedInodeRecord,
};
#[cfg(test)]
pub(super) use super::mount::ReadOnlyVolume;
pub(super) use super::mount::{
    ExternalJournal, InternalJournal, JournaledMount, JournaledVolume, MountedVolume,
    VolumeGeometry, VolumeIdentity,
};
pub(super) use super::node::{
    ChildLookup, DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId, FileNode,
    FileNodeId, LoadedNode, NodeId, SymlinkNode, SymlinkNodeId,
};

/// Builds a volume-owned on-disk field offset.
pub(super) const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}

// Volume mutation offsets are kept together so inode/superblock rewrites use one
// source of truth for on-disk byte layout.
/// Maximum directory size read eagerly for lookup and enumeration.
pub(super) const MAX_EAGER_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
/// `i_mode` type bits for ext4 directories.
#[cfg(test)]
pub(super) const MODE_DIRECTORY: u16 = 0x4000;
/// `i_mode` type bits for regular files.
#[cfg(test)]
pub(super) const MODE_REGULAR: u16 = 0x8000;
/// `i_mode` type bits for symbolic links.
#[cfg(test)]
pub(super) const MODE_SYMLINK: u16 = 0xA000;
/// `i_mode` mask that preserves inode type bits.
#[cfg(test)]
pub(super) const MODE_KIND_MASK: u16 = 0xF000;
/// `i_flags` bit indicating extent-based block mapping.
#[cfg(test)]
pub(super) const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// `i_flags` bit indicating an HTree-indexed directory.
#[cfg(test)]
pub(super) const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// Offset of `i_mode` in an inode record.
pub(super) const INODE_MODE_OFFSET: usize = 0;
/// Offset of `i_uid_lo` in an inode record.
pub(super) const INODE_UID_LO_OFFSET: usize = 2;
/// Offset of `i_size_lo` in an inode record.
pub(super) const INODE_SIZE_LO_OFFSET: usize = 4;
/// Offset of `i_atime` in an inode record.
pub(super) const INODE_ATIME_OFFSET: usize = 8;
/// Offset of `i_ctime` in an inode record.
pub(super) const INODE_CTIME_OFFSET: usize = 12;
/// Offset of `i_mtime` in an inode record.
pub(super) const INODE_MTIME_OFFSET: usize = 16;
/// Offset of `i_dtime` in an inode record.
pub(super) const INODE_DTIME_OFFSET: usize = 20;
/// Offset of `i_gid_lo` in an inode record.
pub(super) const INODE_GID_LO_OFFSET: usize = 24;
/// Offset of `i_links_count` in an inode record.
pub(super) const INODE_LINKS_COUNT_OFFSET: usize = 26;
/// Offset of `i_blocks_lo` in an inode record.
pub(super) const INODE_BLOCKS_LO_OFFSET: usize = 28;
/// Offset of `i_flags` in an inode record.
pub(super) const INODE_FLAGS_OFFSET: usize = 32;
/// Offset of `i_block` in an inode record.
pub(super) const INODE_BLOCK_OFFSET: usize = 40;
/// Offset of `i_generation` in an inode record.
pub(super) const INODE_GENERATION_OFFSET: usize = 100;
/// Offset of `i_file_acl_lo` in an inode record.
pub(super) const INODE_FILE_ACL_LO_OFFSET: usize = 104;
/// Offset of `i_size_high` in an inode record.
pub(super) const INODE_SIZE_HIGH_OFFSET: usize = 108;
/// Offset of `i_blocks_high` in an inode record.
pub(super) const INODE_BLOCKS_HIGH_OFFSET: usize = 116;
/// Offset of `i_file_acl_high` in an inode record.
pub(super) const INODE_FILE_ACL_HI_OFFSET: usize = 118;
/// Offset of `i_checksum_lo` in an inode record.
pub(super) const INODE_CHECKSUM_LO_OFFSET: usize = 124;
/// Offset of `i_extra_isize` in an inode record.
pub(super) const INODE_EXTRA_ISIZE_OFFSET: usize = 128;
/// Offset of `i_ctime_extra` in an inode record.
pub(super) const INODE_CTIME_EXTRA_OFFSET: usize = 132;
/// Offset of `i_mtime_extra` in an inode record.
pub(super) const INODE_MTIME_EXTRA_OFFSET: usize = 136;
/// Offset of `i_atime_extra` in an inode record.
pub(super) const INODE_ATIME_EXTRA_OFFSET: usize = 140;
/// Offset of `i_crtime` in an inode record.
pub(super) const INODE_CRTIME_OFFSET: usize = 144;
/// Offset of `i_crtime_extra` in an inode record.
pub(super) const INODE_CRTIME_EXTRA_OFFSET: usize = 148;
/// Offset of `i_uid_high` in an inode record.
pub(super) const INODE_UID_HI_OFFSET: usize = 120;
/// Offset of `i_gid_high` in an inode record.
pub(super) const INODE_GID_HI_OFFSET: usize = 122;
/// Offset of `i_checksum_hi` in an inode record.
pub(super) const INODE_CHECKSUM_HI_OFFSET: usize = 130;
/// Minimum ext4 extra inode size required for checksum and creation-time fields.
pub(super) const EXT4_INODE_MIN_EXTRA_ISIZE: u16 = 32;
/// Largest regular-file size accepted when `large_file` is absent.
pub(super) const LEGACY_FILE_SIZE_LIMIT: u64 = 0x7fff_ffff;
/// Largest 512-byte sector count accepted when `huge_file` is absent.
pub(super) const LEGACY_I_BLOCKS_LIMIT: u64 = 0xffff_ffff;
/// Offset of `s_free_blocks_count_lo` in the superblock.
pub(super) const SUPERBLOCK_FREE_BLOCKS_LO_OFFSET: usize = 12;
/// Offset of `s_free_inodes_count` in the superblock.
pub(super) const SUPERBLOCK_FREE_INODES_OFFSET: usize = 16;
/// Offset of `s_free_blocks_count_hi` in the superblock.
pub(super) const SUPERBLOCK_FREE_BLOCKS_HI_OFFSET: usize = 344;
/// Byte offset of the primary ext4 superblock.
pub(super) const SUPERBLOCK_OFFSET: u64 = 1024;
