//! Mounted ext4 volume state and journaled write transactions.

mod block_group;
mod inode_record;
mod mount;
mod node;
mod read;
mod scope;
mod transaction;

pub use mount::{InternalJournal, MountContext, VolumeGeometry, VolumeIdentity};
pub use node::{
    ChildLookup, DirectoryChild, DirectoryEntry, DirectoryNode, DirectoryNodeId, FileNode,
    FileNodeId, HardLinkEntry, HardLinkNodeId, HardLinks, NodeId, SymlinkNode, SymlinkNodeId,
};
pub use transaction::{
    HardLinkDestination, RenameTargetCollision, TransactionDirectory, TransactionFile,
    TransactionHardLinkSource, TransactionNode, TransactionSymlink,
};

#[cfg(test)]
pub(crate) use mount::{ExternalJournal, ReadOnlyVolume};
