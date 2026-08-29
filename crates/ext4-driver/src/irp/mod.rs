//! Typed IRP boundary shared by FSD dispatch modules.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{FileOffset, WindowsNameMatch};
use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP, STATUS_PENDING, STATUS_SUCCESS};

use crate::kernel::ffi;
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory;
use crate::security_descriptor::{SecurityDescriptorRef, SecuritySelection};
use crate::state::{
    DirectoryChangeNotifier, DirectoryNotificationRegistration, FileControlBlock, KernelDevice,
    KernelFileObject, KernelVpb, WriteCommitment,
};
use crate::wire::{LittleEndianInput, WireOffset};

mod buffer;
mod cache;
mod cancel;
mod capture;
mod completion;
mod control;
mod create;
mod dispatch;
mod lifecycle;
pub(crate) mod lower;
mod oplock;
pub(crate) mod reactor;
mod scheduler;
mod stack;

pub(crate) use buffer::*;
use buffer::{mdl_data_buffer_address, stack_flag};
pub(crate) use cache::{CacheWork, CacheWorkCompletion};
pub(crate) use capture::{
    CapturedQuerySecurityOutput, PreparedDirectoryControl, PreparedDirectoryPattern,
    PreparedEaSelection, PreparedQueryDirectory, PreparedQueryEa, PreparedRead, PreparedRequest,
    PreparedWrite,
};
use capture::{QueueContext, QueueContextOwnership};
#[cfg(not(test))]
use completion::IO_NO_INCREMENT_PRIORITY;
pub(crate) use completion::*;
use completion::{CLEANUP_QUEUE_CONTEXT_MARKER, CLOSE_QUEUE_CONTEXT_MARKER, queue_context_marker};
use control::MOUNT_VOLUME_MINOR_FUNCTION;
pub(crate) use control::*;
pub(crate) use create::*;
pub(crate) use dispatch::*;
pub(crate) use lifecycle::*;
use lifecycle::{KernelIrp, PendingIrp, copy_requestor_input_window, copy_requestor_output_window};
pub(crate) use oplock::{OplockCheck, OplockContinuation};
pub(crate) use reactor::CompletionReactor;
pub(crate) use stack::*;

#[cfg(not(test))]
pub(crate) use cancel::ActiveCancelDestination;
pub(crate) use cancel::ActiveCancelEnvelope;

#[cfg(test)]
use create::{
    CREATE_DISPOSITION_SHIFT, FILE_OPEN_DISPOSITION, FILE_OPEN_IF_DISPOSITION,
    FILE_OVERWRITE_DISPOSITION, FILE_OVERWRITE_IF_DISPOSITION, FILE_SHARE_ACCESS_MASK,
    FILE_SUPERSEDE_DISPOSITION, map_file_generic_access,
};
#[cfg(test)]
use stack::signed_special_offset;

#[cfg(test)]
mod tests;
