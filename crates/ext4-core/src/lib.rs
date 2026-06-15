//! `no_std` ext4 domain for the Windows kernel driver.
//!
//! This crate owns ext4 on-disk validation, traversal, and journaled mutation.
//! It does not expose Windows types, NTSTATUS values, IRPs, or driver lifetime
//! state.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod block;
pub mod dir;
pub mod error;
pub mod extent;
pub mod inode;
pub mod name;
pub mod superblock;
pub mod volume;

mod checksum;
mod endian;
mod group;
mod journal;

pub use block::{
    BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset, DeviceLength, SliceBlockDevice,
    SliceBlockDeviceMut,
};
pub use dir::{DirectoryEntry, DirectoryEntryKind};
pub use error::{Error, Result};
pub use extent::{
    BlockMapping, Extent, ExtentInitialization, ExtentLength, ExtentTree, ExtentTreeContext,
    LogicalBlock, MutableExtentTree, SerializedExtentBlock, SerializedExtentTree,
};
pub use inode::{
    Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Timestamp, Ext4Uid, FileOffset,
    FileSize, Inode, InodeExtentRoot, InodeId, InodeInlineBytes, InodeKind, InodeStorage,
    NewDirectoryMetadata, NewFileMetadata, ReadBytes,
};
pub use name::{Ext4Name, WindowsName};
pub use superblock::{
    BlockCount, BlockGroupCount, BlockGroupDescriptorSize, BlockGroupId, BlocksPerGroup,
    ChecksumSeed, FilesystemUuid, FreeBlockCount, FreeBlockDelta, FreeInodeCount, FreeInodeDelta,
    InodeCount, InodeRecordSize, InodesPerGroup, JournalMode, JournalUuid, MetadataChecksum,
    RecoveryState, Superblock,
};
pub use volume::{
    DirectoryNode, ExternalJournal, FileNode, InternalJournal, LookupResult, Node, ReadOnly,
    ReadWrite, SymlinkNode, TransactionDirectory, TransactionFile, TransactionNode, Volume,
    WriteTransaction,
};

#[cfg(test)]
mod tests;
