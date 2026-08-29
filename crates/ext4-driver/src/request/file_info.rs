//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use core::{num::NonZeroUsize, ptr::NonNull};

use ext4_core::{
    ChildLookup, CommittedReadPass, DirectoryNode, DirectoryNodeId, DirectoryScanLimit,
    Ext4LinkCount, Ext4Name, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4WindowsAttributes, FileAllocationSize, FileNodeId, FileOffset, FileSize,
    HardLinkDestination, HardLinkNodeId, HardLinks, NodeId, RenameTargetCollision, StorageRequest,
    StorageTarget, WindowsName, WindowsOverlay,
};
use wdk_sys::LARGE_INTEGER;

use crate::irp::{
    ActiveFileObject, ActiveIrp, CreateDeletion, DataIoKind, DirectoryChangeFilter,
    DirectoryCursorPosition, DirectoryEntryEmission, DirectoryInformationClass,
    DirectoryWatchScope, FileAttributesWriteAccess, IrpBufferLength, IrpCompletion, OwnedIrp,
    PendingIrpLease, PreparedDirectoryPattern, QueryFileInformationClass, ReadStartingPoint,
    RegularFileWriteAccess, SetFileInformationClass, SetFileStack, WriteStartingPoint,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{self, DriverVec};
use crate::state::{
    CleanupStart, CloseReleasePlan, DirectoryChange, DirectoryChangeAction, DirectoryCursor,
    DirectoryNotificationRegistration, FileCleanupDisposition, FileControlBlock, FileDeleteTarget,
    MountedVolumeAccess, MountedVolumeDevice, OpenedDirectory, OpenedFileObject, OpenedLocation,
    OpenedObject, OpenedRegularFile, PagingStreamLease, PendingFileDeletion,
    PreparedFilePositionPublication, PreparedHandleAdmission, PreparedOpenedLocationPublication,
    PreparedStreamDeletion, RawVolumeOperationKind, RawVolumeTarget, VolumeHandleCleanup,
    VolumeRetirement, release_cancelled_file_control_block, release_file_control_block,
};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};

use super::DriverMutationPass;
use directory::{
    align_to_eight, clear_record, field_offset, record_field_offset, signed_i64, utf16_byte_len,
    windows_time_quad, wire_offset, wire_range, write_utf16,
};
use query::{
    FileMetadata, FileMetadataKind, FileMetadataReparsePoint, file_attributes, metadata_from_node,
    query_file_information, reparse_tag, windows_time,
};
use set::{UTF16_BACKSLASH, regular_file_size, set_file_information};

mod data;
mod directory;
mod dispatch;
mod lifecycle;
mod query;
mod set;

pub(crate) use data::*;
pub(crate) use directory::*;
pub(crate) use dispatch::*;
pub(crate) use lifecycle::*;
pub(crate) use set::*;

#[cfg(test)]
mod test_support;
