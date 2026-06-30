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
mod platform;
mod protection;
mod volume;

pub use disk::block::{BlockReader, BlockSize, BlockWriter, ByteOffset, DeviceLength};
pub use disk_format::acl::{PosixAcl, PosixAclEntry, PosixAclKind};
pub use disk_format::dir::DirectoryEntryKind;
pub use disk_format::inode::{
    DeletionMutationCapability, DirectoryEntryMutationCapability, Ext4Gid, Ext4LinkCount,
    Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp, Ext4Uid, FileOffset,
    FilePayloadMutationCapability, FileSize, FileSizeMutationCapability, InodeFlags,
    InodeGeneration, InodeMode, MetadataMutationCapability, NewDirectoryMetadata, NewFileMetadata,
    NewSymlinkMetadata, ReadBytes, SymlinkTarget,
};
pub use disk_format::superblock::{
    ClusterCount, ClusterSize, Ext4VolumeLabel, FilesystemUuid, FreeClusterCount,
};
pub use disk_format::xattr::{XattrName, XattrNamespace, XattrSet, XattrValue};
pub use error::{Error, Result};
pub use platform::name::{Ext4Name, WindowsName};
pub use platform::windows::{Ext4WindowsAttributes, WindowsOverlay};
pub use protection::fscrypt::{
    FSCRYPT_CONTEXT_V2_BYTES, FSCRYPT_POLICY_V2_BYTES, FscryptContentsKey, FscryptContentsMode,
    FscryptContextV2, FscryptDataUnitSize, FscryptFileNonce, FscryptFilenamePadding,
    FscryptFilenamesKey, FscryptFilenamesMode, FscryptKeyIdentifier, FscryptKeyPresence,
    FscryptKeySet, FscryptMasterKey, FscryptNoNonceGenerator, FscryptNonceGenerator,
    FscryptPolicyV2,
};
pub use protection::verity::{
    EXT4_VERITY_METADATA_ALIGNMENT_BYTES, Ext4VerityMetadata, Ext4VerityMetadataLayout,
    FSVERITY_DESCRIPTOR_BYTES, FSVERITY_MAX_BLOCK_BYTES, FSVERITY_MAX_SIGNATURE_BYTES,
    FSVERITY_MIN_BLOCK_BYTES, FsverityBlockSize, FsverityDescriptor, FsverityDigest,
    FsverityEnable, FsverityHashAlgorithm, FsverityMerkleTree, FsverityRootHash, FsveritySalt,
    FsveritySignature,
};
pub use volume::{
    ChildLookup, DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId, ExternalJournal,
    FileNode, FileNodeId, InternalJournal, JournalTransaction, JournaledVolume, LoadedNode,
    MountContext, NodeId, ReadOnlyVolume, SymlinkNode, SymlinkNodeId, TransactionDirectory,
    TransactionFile, TransactionNode, TransactionSymlink, VolumeGeometry, VolumeIdentity,
};

#[cfg(test)]
mod tests;
