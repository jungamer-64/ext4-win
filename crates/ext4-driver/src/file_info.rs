//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use core::ptr::NonNull;

use ext4_core::{FileOffset, Node};
use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_NOT_SUPPORTED, STATUS_SUCCESS};

use crate::irp::DispatchTarget;
use crate::state::{ContextControlBlock, FileControlBlock, FileSystemNode, VolumeControlBlock};
use crate::status::DriverError;

/// Handles cleanup IRPs.
pub(crate) fn cleanup(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(_target) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles close IRPs and releases FILE_OBJECT contexts.
pub(crate) fn close(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(|target| target.current_stack()) {
        Ok(stack) => match stack.file_object() {
            Ok(file_object) => {
                release_file_contexts(file_object);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles regular file data reads.
pub(crate) fn read(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(read_regular_file) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles regular file data writes.
pub(crate) fn write(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Flushes cached or ordered file data.
pub(crate) fn flush(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(_target) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles file information queries.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles file information mutations.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles directory enumeration and notification.
pub(crate) fn directory_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles security descriptor queries.
pub(crate) fn query_security(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            crate::status::DriverError::AccessDenied.ntstatus()
        }
        Err(error) => error.ntstatus(),
    }
}

/// Handles security descriptor mutations.
pub(crate) fn set_security(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles extended-attribute queries.
pub(crate) fn query_ea(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles extended-attribute mutations.
pub(crate) fn set_ea(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles byte-range lock requests.
pub(crate) fn lock_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Rejects a decoded file-object request until its domain path exists.
fn decoded_not_supported(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            STATUS_NOT_SUPPORTED
        }
        Err(error) => error.ntstatus(),
    }
}

/// Reads a regular file through ext4-core into the IRP output buffer.
fn read_regular_file(target: DispatchTarget) -> Result<(), DriverError> {
    let stack = target.current_stack()?.read()?;
    let length = usize::try_from(stack.length()).map_err(|_| DriverError::InvalidParameter)?;
    if length == 0 {
        target.set_information(0);
        return Ok(());
    }
    let offset = u64::try_from(stack.byte_offset()).map_err(|_| DriverError::InvalidParameter)?;
    let mut output = target.output_buffer(length)?;
    let fcb = file_control_block(stack.file_object())?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this read runs while the FILE_OBJECT is
        // active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let FileSystemNode::File(inode) = fcb.node() else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };

    let node = vcb.volume().read_node(inode)?;
    let Node::File(file) = node else {
        return Err(DriverError::Core(ext4_core::Error::WrongInodeKind));
    };
    let bytes_read =
        vcb.volume()
            .read_file(&file, FileOffset::from_bytes(offset), output.as_mut_slice())?;
    target.set_information(
        wdk_sys::ULONG_PTR::try_from(bytes_read.as_usize())
            .map_err(|_| DriverError::InvalidParameter)?,
    );
    Ok(())
}

/// Returns the FCB stored on a successfully opened FILE_OBJECT.
fn file_control_block(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<NonNull<FileControlBlock>, DriverError> {
    let file_object = unsafe {
        // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack and
        // is read only for filesystem-owned context pointers.
        file_object.as_ref()
    };
    NonNull::new(file_object.FsContext.cast::<FileControlBlock>())
        .ok_or(DriverError::InvalidParameter)
}

/// Returns the mounted VCB referenced by an FCB.
fn volume_control_block(fcb: &FileControlBlock) -> &VolumeControlBlock {
    unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        fcb.volume().as_ref()
    }
}

/// Releases heap-owned FCB and CCB pointers stored on a FILE_OBJECT.
fn release_file_contexts(mut file_object: core::ptr::NonNull<wdk_sys::FILE_OBJECT>) {
    let file_object = unsafe {
        // SAFETY: Close receives the final FILE_OBJECT and may clear its
        // filesystem-owned context pointers.
        file_object.as_mut()
    };
    let fcb = core::mem::replace(&mut file_object.FsContext, core::ptr::null_mut());
    if !fcb.is_null() {
        unsafe {
            // SAFETY: Successful create stores Box<FileControlBlock> in
            // FsContext, and close is the unique release point.
            drop(Box::from_raw(fcb.cast::<FileControlBlock>()));
        }
    }
    let ccb = core::mem::replace(&mut file_object.FsContext2, core::ptr::null_mut());
    if !ccb.is_null() {
        unsafe {
            // SAFETY: Successful create stores Box<ContextControlBlock> in
            // FsContext2, and close is the unique release point.
            drop(Box::from_raw(ccb.cast::<ContextControlBlock>()));
        }
    }
}
