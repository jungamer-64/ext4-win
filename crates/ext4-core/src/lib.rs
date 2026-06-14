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

mod endian;

pub use block::{BlockAddress, BlockDevice, BlockSize, ByteOffset, SliceBlockDevice};
pub use dir::{DirectoryEntry, DirectoryEntryKind};
pub use error::{Error, Result};
pub use inode::{Inode, InodeId, InodeKind};
pub use name::{Ext4Name, WindowsName};
pub use superblock::{CleanSuperblock, FeatureSet};
pub use volume::MountedVolume;

#[cfg(test)]
mod tests;
