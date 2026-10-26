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
mod protection;
mod volume;

pub use disk::block::{BlockSize, ByteOffset, DeviceLength};
pub use disk::storage::{
    CompletedStorageTransfer, PendingStorageTransfer, StorageCompletion, StorageRequest,
    StorageRequestIdentity, StorageTarget,
};
pub use disk_format::acl::{AclGroup, AclPermissions, AclUser, Ext4Access, PosixAcl};
pub use disk_format::inode::{
    Ext4Gid, Ext4LinkCount, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4Uid, FileAllocationSize, FileOffset, FileSize, InodeId, NewDirectoryMetadata,
    NewFileMetadata, NewSymlinkMetadata, ReadBytes, SymlinkTarget, InodeGeneration,
};
pub use disk_format::name::{DirectoryCasefold, Ext4Name};
pub use disk_format::superblock::{
    ClusterAddress, ClusterCount, ClusterSize, CompatibleFeatures, Ext4VolumeLabel,
    ExtVolumeSignature, FilesystemFeature, FilesystemFeatures, FilesystemUuid, FreeClusterCount,
    IncompatibleFeatures, JournalUuid, ReadOnlyCompatibleFeatures,
};
pub use disk_format::xattr::{XattrName, XattrNamespace, XattrSet, XattrValue};
pub use error::{Error, Result};
pub use protection::crypto::CryptographicOperation;
pub use protection::fscrypt::{
    FscryptFileNonce, FscryptKeyIdentifier, FscryptKeyPresence, FscryptKeySet, FscryptMasterKey,
};
pub use protection::verity::{
    FsverityBlockSize, FsverityEnable, FsverityHashAlgorithm, FsveritySalt, FsveritySignature,
};
pub use volume::{
    CheckpointLease, CheckpointOperation, CheckpointPublication, ChildLookup, CleanCloseDurability,
    CleanCloseOperation, CleanCloseTransition, CleanJournalDurability, CleanJournalRecordPhase,
    CommitDurability, CommitLease, CommitReadyMutation, CommitRecordPhase, CommittedEpoch,
    CommittedReadContext, CommittedReadPass, CompletedMount, ContiguousFileStorage, DataAllocationRun, DeviceWriteAccess,
    DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId, DirectoryReadOperation,
    DirectoryReadTransition, DirectoryReader, DirectoryScanCursor, DurableMutation,
    EpochReadOperation, EpochReadPass, EpochSequence, ExternalJournalProbeOperation,
    ExternalJournalProbeOutcome, ExternalJournalProbeTransition, ExternalJournalRequirement,
    FileNode, FileNodeId, HardLinkEntry, HardLinkNodeId, HardLinks, HomeBlockDurability,
    JournalPayloadDurability, MediaAccess, MetadataCache, MetadataCacheAccess, MmpChange,
    MmpCompletion, MmpDeadline, MmpEffect, MmpEvent, MmpFailure, MmpLease, MmpOperation, MmpOwner,
    MmpRenewal, MmpRenewingLease, MmpTime, MmpTransition, MountAccess, MountFailure,
    MountMediaOutcome, MountOperation, MountProbeOperation, MountProbeTransition, MountTransition,
    MountedProfile, MutationCoordinatorState, MutationLease, MutationResolveContext,
    MutationCompletionDurability, MutationResolveOperation, MutationResolvePass, MutationResolveReady, MutationResolveTransition,
    MutationResource, NamespaceDestination, NodeDataPolicy, NodeId, NodeMetadataSnapshot,
    NodeMetadataUpdate, ObservedResourceVersionSet, OperationEvent, OrderedDataDurability,
    PendingTrim, PreparedKeyChange, PreparedTrim, ProbedMount, PublishedMutation, ReadOnlyRecovery,
    ReadTransition, RecoveryMemoryLimit, ReservedKeyChange, ReservedMutation, ResolvedKeyChange,
    ResolvedMutation, ResourceVersion, ScannedDirectoryEntry, StorageRequestSequence,
    StorageRequestSequenceStep, SymlinkNode, SymlinkNodeId, TRIM_BATCH_BYTES, TRIM_BATCH_RANGES,
    TransactionDirectory, TransactionFile, TransactionHardLinkSource, TransactionNode,
    TransactionSymlink, TrimAdmission, TrimAlignment, TrimBatchResult, TrimCompletion,
    TrimCompletionMismatch, TrimCursor, TrimFailure, TrimIoOutcome, TrimRange, TrimRequest,
    TrimScanOperation, TrimScanTransition, TrimSelection, ValidatedExternalJournal,
    VisibilityLease, VolumeGeometry, VolumeIdentity,
};
