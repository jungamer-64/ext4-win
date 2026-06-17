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
pub mod fscrypt;
pub mod inode;
pub mod name;
pub mod superblock;
pub mod volume;
pub mod windows;
pub mod xattr;

mod acl;
mod checksum;
mod endian;
mod group;
mod journal;

pub use acl::{PosixAcl, PosixAclEntry, PosixAclKind};
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
pub use fscrypt::{
    FSCRYPT_CONTEXT_V2_BYTES, FSCRYPT_POLICY_V2_BYTES, FscryptContentsKey, FscryptContentsMode,
    FscryptContextV2, FscryptDataUnitSize, FscryptFileNonce, FscryptFilenamePadding,
    FscryptFilenamesKey, FscryptFilenamesMode, FscryptKeyIdentifier, FscryptKeySet,
    FscryptMasterKey, FscryptPolicyV2,
};
pub use inode::{
    Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp, Ext4Uid,
    FileOffset, FileSize, Inode, InodeExtentRoot, InodeId, InodeInlineBytes, InodeKind,
    InodeMutation, InodeStorage, NewDirectoryMetadata, NewFileMetadata, NewSymlinkMetadata,
    ReadBytes, SymlinkTarget,
};
pub use name::{Ext4Name, WindowsName};
pub use superblock::{
    BlockCount, BlockGroupCount, BlockGroupDescriptorSize, BlockGroupId, BlocksPerCluster,
    BlocksPerGroup, ChecksumSeed, ClusterAddress, ClusterCount, ClusterSize, ClustersPerGroup,
    Ext4VolumeLabel, FilesystemUuid, FreeClusterCount, FreeInodeCount, FreeInodeDelta, InodeCount,
    InodeRecordSize, InodesPerGroup, JournalMode, JournalUuid, MetadataChecksum, RecoveryState,
    Superblock,
};
pub use volume::{
    DirectoryNode, ExternalJournal, FileNode, InternalJournal, LookupResult, MountContext, Node,
    ReadOnly, ReadWrite, SymlinkNode, TransactionDirectory, TransactionFile, TransactionNode,
    TransactionSymlink, Volume, WriteTransaction,
};
pub use windows::{Ext4WindowsAttributes, WindowsOverlay};
pub use xattr::{XattrName, XattrNamespace, XattrSet, XattrValue};

#[cfg(test)]
mod tests;
