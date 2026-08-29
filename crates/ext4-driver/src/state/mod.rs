//! Driver-local lifecycle and open-object state.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::pin::Pin;
use core::ptr::NonNull;
#[cfg(test)]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::{AtomicU8, Ordering};
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

use ext4_core::{
    ByteOffset, CleanJournalDurability, ClusterSize, CommitLease, CommitReadyMutation,
    CompletedMount, DeviceLength, DirectoryNodeId, DirectoryScanCursor, DurableMutation, Ext4Name,
    FileNodeId, FileOffset, FscryptKeyIdentifier, FscryptKeyPresence, MountedProfile,
    MutationLease, MutationResolvePass, NewDirectoryMetadata, NewFileMetadata, NodeId,
    NodeStorageSnapshot, ReservedMutation, ResolvedMutation, VisibilityLease, VolumeGeometry,
    VolumeIdentity, WindowsName, XattrName, XattrValue,
};
use wdk_sys::{
    DO_DEVICE_INITIALIZING, DO_DIRECT_IO, FILE_OBJECT, LARGE_INTEGER, PDEVICE_OBJECT,
    PDRIVER_OBJECT, SHARE_ACCESS, STATUS_SUCCESS, UNICODE_STRING, VPB_MOUNTED,
};
#[cfg(not(test))]
use wdk_sys::{LIST_ENTRY, PNOTIFY_SYNC, STATUS_PENDING};

use crate::irp::reactor::ReactorTarget;
use crate::irp::{
    ActiveFileObject, ByteRangeLockKey, CompletionReactor, CreateDeletion, DataIoKind,
    DeleteAccess, DispatchMajor, DispatchTarget, ExistingOperationAccess,
    FileAttributesWriteAccess, GrantedAccess, OplockCreatePolicy, ReceivedIrp,
    RegularFileWriteAccess, RequestorProcess, ShareAccess,
};
use crate::kernel::cng::CngOperation;
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::ffi;
use crate::kernel::operational_trace::OperationalTrace;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::{MountedStorage, MountedStorageRoute};
use crate::kernel::stream::{StreamContext, StreamOwnerKind, StreamSizes};
use crate::memory::{self, DriverVec, InPlaceInitialization};

mod control_device;
mod directory_notification;
mod file_control_block;
mod file_control_block_ledger;
mod kernel_object;
mod mounted_volume_device;
mod open_object;
mod volume;
mod volume_runtime;

use control_device::DeviceExtensionHeader;
pub(crate) use control_device::*;
#[cfg(test)]
use control_device::{ControlDeviceLifecycle, ControlDevicePhase, RetirementAdmission};
#[cfg(test)]
use directory_notification::DIRECTORY_NOTIFICATION_DIRECTORY_UNITS;
use directory_notification::DirectoryNotificationDirectoryName;
pub(crate) use directory_notification::*;
#[cfg(test)]
use file_control_block::NativeFileByteRange;
pub(crate) use file_control_block::*;
pub(crate) use file_control_block_ledger::*;
use file_control_block_ledger::{FileControlBlockLedger, FileControlBlockShareCheck};
pub(crate) use kernel_object::*;
#[cfg(test)]
use mounted_volume_device::shutdown_registration_status;
pub(crate) use mounted_volume_device::*;
pub(crate) use open_object::*;
use open_object::{FileDeletionCause, FileDeletionState};
#[cfg(test)]
use open_object::{OpenedHandleKind, OpenedHandleState, select_close_release_plan};
pub(crate) use volume::*;
use volume::{MountedVolumeRef, MountedVolumeState, VolumeControlPlane};
pub(crate) use volume_runtime::{
    EpochLease, EpochPublicationSlot, EpochPublicationSlots, MutationActivityLease,
    PendingCheckpoint, VolumeRuntime,
};

#[cfg(test)]
mod tests;
