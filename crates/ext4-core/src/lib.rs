//! `no_std` ext4 read domain for the Windows kernel driver.
//!
//! This crate owns ext4 on-disk validation and read-only traversal. It does
//! not expose Windows types, NTSTATUS values, IRPs, or driver lifetime state.

#![no_std]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "private parser offsets and backing fields repeat documented ext4 domain concepts"
    )
)]

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
pub use extent::{BlockMapping, Extent, ExtentLength, ExtentTree, LogicalBlock};
pub use inode::{
    Ext4Timestamp, FileOffset, FileSize, Inode, InodeExtentRoot, InodeId, InodeInlineBytes,
    InodeKind, InodeStorage, ReadBytes,
};
pub use name::{Ext4Name, WindowsName};
pub use superblock::{
    BlockCount, BlockGroupCount, BlockGroupDescriptorSize, BlockGroupId, BlocksPerGroup,
    ChecksumSeed, FilesystemUuid, FreeBlockCount, FreeBlockDelta, InodeCount, InodeRecordSize,
    InodesPerGroup, JournalMode, JournalUuid, MetadataChecksum, RecoveryState, Superblock,
};
pub use volume::{
    DirectoryNode, ExternalJournal, FileNode, InternalJournal, LookupResult, Node, ReadOnly,
    ReadWrite, SymlinkNode, TransactionFile, Volume, WriteTransaction,
};

#[cfg(test)]
mod tests;
