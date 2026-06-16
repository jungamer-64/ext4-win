//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{InodeId, LookupResult, Node, WindowsName};
use wdk_sys::{
    FILE_OBJECT, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SUCCESS,
};

use crate::{
    irp::{CreateStack, DispatchTarget},
    state::{
        ContextControlBlock, DirectoryCursor, FileControlBlock, FileSystemNode, KernelDevice,
        MountedVolumeDevice,
    },
};

/// `FILE_OPEN` create disposition.
const FILE_OPEN_DISPOSITION: wdk_sys::ULONG = 1;
/// `FILE_OPEN_IF` create disposition.
const FILE_OPEN_IF_DISPOSITION: wdk_sys::ULONG = 3;
/// Shift for the create disposition stored in `Options`.
const CREATE_DISPOSITION_SHIFT: u32 = 24;
/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

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
    if !supports_existing_open_disposition(request.stack.options()) {
        return STATUS_NOT_SUPPORTED;
    }
    let _share_access = request.stack.share_access();
    let _ea_length = request.stack.ea_length();
    let Some(vcb) = MountedVolumeDevice::vcb(request.device()) else {
        return crate::status::DriverError::InvalidDeviceRequest.ntstatus();
    };
    let node = match resolve_existing_path(request.file_object(), vcb) {
        Ok(node) => node,
        Err(status) => return status,
    };
    initialize_file_object(request.file_object(), vcb, node)
}

/// Returns whether this create disposition can open an existing object.
const fn supports_existing_open_disposition(options: wdk_sys::ULONG) -> bool {
    let disposition = options >> CREATE_DISPOSITION_SHIFT;
    disposition == FILE_OPEN_DISPOSITION || disposition == FILE_OPEN_IF_DISPOSITION
}

/// Resolves a root-relative Windows path to an existing ext4 node.
fn resolve_existing_path(
    file_object: NonNull<FILE_OBJECT>,
    mut vcb: NonNull<crate::state::VolumeControlBlock>,
) -> Result<FileSystemNode, NTSTATUS> {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is read
        // only for immutable path fields.
        file_object.as_ref()
    };
    if !file_object.RelatedFileObject.is_null() {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension.
        vcb.as_mut()
    };
    let mut inode = InodeId::ROOT;
    for component in path_components(file_object)? {
        let parent = match vcb.volume().read_node(inode) {
            Ok(Node::Directory(directory)) => directory,
            Ok(_) => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
            Err(error) => return Err(crate::status::DriverError::from(error).ntstatus()),
        };
        inode = match vcb.volume().lookup_windows_child(&parent, &component) {
            Ok(LookupResult::Found(child)) => child,
            Ok(LookupResult::NotFound) => return Err(STATUS_OBJECT_NAME_NOT_FOUND),
            Err(error) => return Err(crate::status::DriverError::from(error).ntstatus()),
        };
    }

    match vcb.volume().read_node(inode) {
        Ok(Node::File(_)) => Ok(FileSystemNode::File(inode)),
        Ok(Node::Directory(_)) => Ok(FileSystemNode::Directory(inode)),
        Ok(Node::Symlink(_)) => Ok(FileSystemNode::Symlink(inode)),
        Err(error) => Err(crate::status::DriverError::from(error).ntstatus()),
    }
}

/// Splits the FILE_OBJECT name into validated root-relative Windows components.
fn path_components(file_object: &FILE_OBJECT) -> Result<Vec<WindowsName>, NTSTATUS> {
    let name = file_object.FileName;
    if name.Length == 0 {
        return Ok(Vec::new());
    }
    if !name.Length.is_multiple_of(2) || name.Buffer.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let units = unsafe {
        // SAFETY: UNICODE_STRING Length is byte length; the odd-length and null
        // buffer cases were rejected above.
        core::slice::from_raw_parts(name.Buffer, usize::from(name.Length / 2))
    };
    let mut trimmed = units;
    while let Some(rest) = trimmed.strip_prefix(&[UTF16_BACKSLASH]) {
        trimmed = rest;
    }
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in trimmed.split(|unit| *unit == UTF16_BACKSLASH) {
        components.push(
            WindowsName::from_utf16(component)
                .map_err(|error| crate::status::DriverError::from(error).ntstatus())?,
        );
    }
    Ok(components)
}

/// Stores FCB/CCB context pointers in the FILE_OBJECT.
fn initialize_file_object(
    mut file_object: NonNull<FILE_OBJECT>,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    node: FileSystemNode,
) -> NTSTATUS {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is
        // writable during successful create processing.
        file_object.as_mut()
    };
    if !file_object.FsContext.is_null() || !file_object.FsContext2.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let fcb = Box::new(FileControlBlock::new(vcb, node));
    let ccb = Box::new(match node {
        FileSystemNode::File(_) => ContextControlBlock::File,
        FileSystemNode::Directory(_) => ContextControlBlock::Directory(DirectoryCursor::start()),
        FileSystemNode::Symlink(_) => ContextControlBlock::Symlink,
    });
    file_object.FsContext = Box::into_raw(fcb).cast::<c_void>();
    file_object.FsContext2 = Box::into_raw(ccb).cast::<c_void>();
    STATUS_SUCCESS
}
