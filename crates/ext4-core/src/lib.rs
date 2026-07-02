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

mod disk;
mod disk_format;
mod error;
mod memory;
mod platform;
mod protection;
mod volume;

pub use disk::block::{BlockReader, BlockSize, BlockWriter, ByteOffset, DeviceLength};
pub use disk_format::inode::{
    Ext4Gid, Ext4LinkCount, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4Uid, FileOffset, FileSize, NewDirectoryMetadata, NewFileMetadata, NewSymlinkMetadata,
    ReadBytes, SymlinkTarget,
};
pub use disk_format::superblock::{
    ClusterCount, ClusterSize, Ext4VolumeLabel, FilesystemUuid, FreeClusterCount,
};
pub use disk_format::xattr::{XattrName, XattrNamespace, XattrSet, XattrValue};
pub use error::{Error, Result};
pub use platform::name::{Ext4Name, WindowsName};
pub use platform::windows::{Ext4WindowsAttributes, WindowsOverlay};
pub use protection::fscrypt::{
    FscryptFileNonce, FscryptKeyIdentifier, FscryptKeyPresence, FscryptKeySet, FscryptMasterKey,
    FscryptNonceGenerator,
};
pub use protection::verity::{
    FsverityBlockSize, FsverityEnable, FsverityHashAlgorithm, FsveritySalt, FsveritySignature,
};
pub use volume::{
    ChildLookup, DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId, FileNode,
    FileNodeId, InternalJournal, JournalTransaction, JournaledVolume, MountContext, NodeId,
    SymlinkNode, SymlinkNodeId, TransactionDirectory, TransactionFile, TransactionNode,
    TransactionSymlink, VolumeGeometry, VolumeIdentity,
};

#[cfg(test)]
mod tests;
