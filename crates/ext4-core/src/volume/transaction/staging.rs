//! Staged transaction images.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Full block image staged for metadata rewrite.
pub(super) struct BlockImage {
    /// Metadata block address.
    pub(super) block: BlockAddress,
    /// Complete block bytes to journal and write.
    pub(super) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Accumulated block group accounting changes.
pub(super) struct GroupDelta {
    /// Block group receiving the accounting changes.
    pub(super) group: BlockGroupId,
    /// Free-cluster count delta for the descriptor.
    pub(super) free_clusters_delta: FreeClusterDelta,
    /// Free-inode count delta for the descriptor.
    pub(super) free_inodes_delta: i64,
    /// Used-directory count delta for the descriptor.
    pub(super) used_dirs_delta: i64,
}

impl GroupDelta {
    /// Starts an empty accounting delta for one block group.
    pub(super) fn new(group: BlockGroupId) -> Self {
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
pub(super) enum EncryptedBlockBase {
    /// Decrypt the existing physical block before merging the write.
    ExistingPlaintext,
    /// Start from a zero-filled plaintext block.
    ZeroedPlaintext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Byte range write staged for ordered data or metadata persistence.
pub(super) struct RangeWrite {
    /// Absolute device byte offset.
    pub(super) offset: ByteOffset,
    /// Bytes to write at the offset.
    pub(super) bytes: Vec<u8>,
}
