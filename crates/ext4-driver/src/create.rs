//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::InodeId;
use wdk_sys::{
    FILE_OBJECT, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
};

use crate::{
    irp::{CreateStack, DispatchTarget},
    state::{
        ContextControlBlock, DirectoryCursor, FileControlBlock, FileSystemNode, KernelDevice,
        MountedVolumeDevice,
    },
};

/// Handles create/open IRPs.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(CreateRequest::decode) {
        Ok(request) => open_root_directory(request),
        Err(error) => error.ntstatus(),
    }
}

/// Decoded create request at the filesystem boundary.
#[derive(Clone, Copy, Debug)]
struct CreateRequest {
    /// Mounted device receiving the create.
    device: KernelDevice,
    /// Create stack parameters.
    stack: CreateStack,
}

impl CreateRequest {
    /// Decodes the create request from the current IRP stack.
    fn decode(target: DispatchTarget) -> Result<Self, crate::status::DriverError> {
        Ok(Self {
            device: KernelDevice::from_non_null(target.device()),
            stack: target.current_stack()?.create()?,
        })
    }

    /// Returns the mounted device receiving the create.
    const fn device(self) -> KernelDevice {
        self.device
    }

    /// Returns the file object to initialize.
    const fn file_object(self) -> NonNull<FILE_OBJECT> {
        self.stack.file_object()
    }
}

/// Opens the mounted volume root directory.
fn open_root_directory(request: CreateRequest) -> NTSTATUS {
    let _create_options = request.stack.options();
    let _share_access = request.stack.share_access();
    let _ea_length = request.stack.ea_length();
    if !file_name_is_root(request.file_object()) {
        return STATUS_NOT_SUPPORTED;
    }
    let Some(vcb) = MountedVolumeDevice::vcb(request.device()) else {
        return crate::status::DriverError::InvalidDeviceRequest.ntstatus();
    };
    initialize_root_file_object(request.file_object(), vcb)
}

/// Returns whether this create targets the root directory.
fn file_name_is_root(file_object: NonNull<FILE_OBJECT>) -> bool {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is read
        // only for its immutable FileName value.
        file_object.as_ref()
    };
    let name = file_object.FileName;
    if name.Length == 0 {
        return true;
    }
    if name.Length != 2 || name.Buffer.is_null() {
        return false;
    }
    let first = unsafe {
        // SAFETY: A UNICODE_STRING with Length == 2 contains one UTF-16 code
        // unit at Buffer.
        name.Buffer.read()
    };
    first == u16::from(b'\\')
}

/// Stores root FCB/CCB context pointers in the FILE_OBJECT.
fn initialize_root_file_object(
    mut file_object: NonNull<FILE_OBJECT>,
    vcb: NonNull<crate::state::VolumeControlBlock>,
) -> NTSTATUS {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is
        // writable during successful create processing.
        file_object.as_mut()
    };
    if !file_object.FsContext.is_null() || !file_object.FsContext2.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let fcb = Box::new(FileControlBlock::new(
        vcb.cast::<c_void>(),
        FileSystemNode::Directory(InodeId::ROOT),
    ));
    let ccb = Box::new(ContextControlBlock::Directory(DirectoryCursor::start()));
    file_object.FsContext = Box::into_raw(fcb).cast::<c_void>();
    file_object.FsContext2 = Box::into_raw(ccb).cast::<c_void>();
    STATUS_SUCCESS
}
