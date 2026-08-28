//! `no_std` ext4 domain for the Windows kernel driver.
//!
//! This crate owns ext4 on-disk validation, traversal, and journaled mutation.
//! It does not expose Windows types, NTSTATUS values, IRPs, or driver lifetime
//! state.

#![no_std]
#![forbid(unsafe_code)]
#![feature(allocator_api)]
#![feature(vec_push_within_capacity)]

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

pub use disk::block::{BlockSize, ByteOffset, DeviceLength};
pub use disk::storage::{
    CompletedStorageTransfer, StorageCompletion, StorageRequest, StorageRequestIdentity,
    StorageTarget,
};
pub use disk_format::inode::{
    Ext4Gid, Ext4LinkCount, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4Uid, FileAllocationSize, FileOffset, FileSize, NewDirectoryMetadata, NewFileMetadata,
    NewSymlinkMetadata, ReadBytes, SymlinkTarget,
};
pub use disk_format::superblock::{
    ClusterCount, ClusterSize, Ext4VolumeLabel, ExtVolumeSignature, FilesystemUuid,
    FreeClusterCount, JournalUuid,
};
pub use disk_format::xattr::{XattrName, XattrNamespace, XattrSet, XattrValue};
pub use error::{Error, Result};
pub use platform::name::{Ext4Name, WindowsName};
pub use platform::windows::{Ext4WindowsAttributes, WindowsOverlay, WindowsSymlinkReparsePoint};
pub use protection::crypto::CryptographicOperation;
pub use protection::fscrypt::{
    FscryptFileNonce, FscryptKeyIdentifier, FscryptKeyPresence, FscryptKeySet, FscryptMasterKey,
};
pub use protection::verity::{
    FsverityBlockSize, FsverityEnable, FsverityHashAlgorithm, FsveritySalt, FsveritySignature,
};
pub use volume::{
    BarrierPermit, CheckpointLease, CheckpointOperation, ChildLookup, CleanCloseDurability,
    CleanCloseOperation, CleanCloseTransition, CleanJournalDurability, CleanJournalRecordPhase,
    CommitDurability, CommitLease, CommitReadyMutation, CommitRecordPhase, CommittedEpoch,
    CommittedReadPass, CompletedMount, DirectoryChild, DirectoryEntry, DirectoryNode,
    DirectoryNodeId, DirectoryScanBatch, DirectoryScanCursor, DirectoryScanLimit, DurableMutation,
    EpochReadOperation, EpochReadPass, EpochSequence, ExternalJournalProbeOperation,
    ExternalJournalProbeOutcome, ExternalJournalProbeTransition, ExternalJournalRequirement,
    FileNode, FileNodeId, HardLinkDestination, HardLinkEntry, HardLinkNodeId, HardLinks,
    HomeBlockDurability, JournalPayloadDurability, MAX_DIRECTORY_SCAN_ENTRIES, MountOperation,
    MountTransition, MountedProfile, MutationCoordinatorState, MutationLease,
    MutationResolveOperation, MutationResolvePass, MutationResolveReady, MutationResolveTransition,
    MutationResource, NodeId, NodeStorageSnapshot, ObservedResourceVersionSet, OperationEvent,
    OperationId, OrderedDataDurability, PublishedMutation, ReadTransition, RenameTargetCollision,
    ReservedMutation, ResolvedMutation, ResourceVersion, RetryPermit, ScannedDirectoryEntry,
    StorageRequestSequence, StorageRequestSequenceStep, SymlinkNode, SymlinkNodeId,
    TransactionDirectory, TransactionFile, TransactionHardLinkSource, TransactionNode,
    TransactionSymlink, ValidatedExternalJournal, VisibilityLease, VolumeGeometry, VolumeIdentity,
    WindowsNameMatch,
};
