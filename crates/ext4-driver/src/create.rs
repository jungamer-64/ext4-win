//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{Ext4Name, FileSize, InodeId, Node, WindowsName};
use wdk_sys::{
    FILE_OBJECT, NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_OBJECT_TYPE_MISMATCH, STATUS_SUCCESS,
};

use crate::{
    irp::{CreateStack, DispatchTarget},
    metadata,
    state::{
        ContextControlBlock, FileControlBlock, FileSystemNode, KernelDevice, MountedVolumeDevice,
        OpenedPath, VolumeControlBlock, release_file_control_block,
    },
};

/// `FILE_SUPERSEDE` create disposition.
const FILE_SUPERSEDE_DISPOSITION: wdk_sys::ULONG = 0;
/// `FILE_OPEN` create disposition.
const FILE_OPEN_DISPOSITION: wdk_sys::ULONG = 1;
/// `FILE_CREATE` create disposition.
const FILE_CREATE_DISPOSITION: wdk_sys::ULONG = 2;
/// `FILE_OPEN_IF` create disposition.
const FILE_OPEN_IF_DISPOSITION: wdk_sys::ULONG = 3;
/// `FILE_OVERWRITE` create disposition.
const FILE_OVERWRITE_DISPOSITION: wdk_sys::ULONG = 4;
/// `FILE_OVERWRITE_IF` create disposition.
const FILE_OVERWRITE_IF_DISPOSITION: wdk_sys::ULONG = 5;
/// Shift for the create disposition stored in `Options`.
const CREATE_DISPOSITION_SHIFT: u32 = 24;
/// `FILE_DIRECTORY_FILE` create option.
const FILE_DIRECTORY_FILE_OPTION: wdk_sys::ULONG = 0x0000_0001;
/// `FILE_NON_DIRECTORY_FILE` create option.
const FILE_NON_DIRECTORY_FILE_OPTION: wdk_sys::ULONG = 0x0000_0040;
/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Handles create/open IRPs.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(CreateRequest::decode) {
        Ok(request) => open_or_create(request),
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

/// Opens or creates a root-relative ext4 object.
fn open_or_create(request: CreateRequest) -> NTSTATUS {
    if request.stack.ea_length().as_usize() != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let Some(vcb) = MountedVolumeDevice::vcb(request.device()) else {
        return crate::status::DriverError::InvalidDeviceRequest.ntstatus();
    };
    let disposition = match CreateDisposition::from_options(request.stack.options()) {
        Ok(disposition) => disposition,
        Err(status) => return status,
    };
    match resolve_path(request.file_object(), vcb) {
        Ok(PathLookup::Existing { node, path }) => {
            open_existing_node(request, vcb, disposition, node, path)
        }
        Ok(PathLookup::Missing { parent, name }) => {
            create_missing_node(request, vcb, disposition, parent, &name)
        }
        Err(status) => status,
    }
}

/// Requested create disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateDisposition {
    /// Open only if the path exists.
    Open,
    /// Create only if the path is absent.
    Create,
    /// Open existing or create absent.
    OpenIf,
    /// Truncate an existing regular file.
    Overwrite,
    /// Truncate an existing regular file or create an absent object.
    OverwriteIf,
    /// Replace an existing regular file's data or create an absent object.
    Supersede,
}

impl CreateDisposition {
    /// Decodes the disposition stored in Create.Options.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, NTSTATUS> {
        match options >> CREATE_DISPOSITION_SHIFT {
            FILE_OPEN_DISPOSITION => Ok(Self::Open),
            FILE_CREATE_DISPOSITION => Ok(Self::Create),
            FILE_OPEN_IF_DISPOSITION => Ok(Self::OpenIf),
            FILE_SUPERSEDE_DISPOSITION => Ok(Self::Supersede),
            FILE_OVERWRITE_DISPOSITION => Ok(Self::Overwrite),
            FILE_OVERWRITE_IF_DISPOSITION => Ok(Self::OverwriteIf),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }
}

/// Node kind requested for a missing create target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateNodeKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
}

impl CreateNodeKind {
    /// Decodes create options that select file-vs-directory creation.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, NTSTATUS> {
        let directory = options & FILE_DIRECTORY_FILE_OPTION != 0;
        let non_directory = options & FILE_NON_DIRECTORY_FILE_OPTION != 0;
        if directory && non_directory {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if directory {
            Ok(Self::Directory)
        } else {
            Ok(Self::File)
        }
    }
}

/// Result of resolving a Windows path against the mounted volume.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PathLookup {
    /// The requested path already exists.
    Existing {
        /// Opened ext4 node.
        node: FileSystemNode,
        /// Exact path identity.
        path: OpenedPath,
    },
    /// The final path component is absent under an existing parent directory.
    Missing {
        /// Parent directory inode.
        parent: InodeId,
        /// New ext4 child name.
        name: Ext4Name,
    },
}

/// Opens an existing path according to the requested disposition and options.
fn open_existing_node(
    request: CreateRequest,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    disposition: CreateDisposition,
    node: FileSystemNode,
    path: OpenedPath,
) -> NTSTATUS {
    match disposition {
        CreateDisposition::Open | CreateDisposition::OpenIf => {
            match validate_existing_node_options(node, request.stack.options()) {
                Ok(()) => initialize_file_object(
                    request.file_object(),
                    vcb,
                    node,
                    path,
                    request.stack.desired_access(),
                    wdk_sys::ULONG::from(request.stack.share_access()),
                ),
                Err(status) => status,
            }
        }
        CreateDisposition::Create => STATUS_OBJECT_NAME_COLLISION,
        CreateDisposition::Overwrite
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {
            let inode = match overwrite_file_inode(node, request.stack.options()) {
                Ok(inode) => inode,
                Err(status) => return status,
            };
            let fcb = match open_shared_file_control_block(
                request.file_object(),
                vcb,
                node,
                request.stack.desired_access(),
                wdk_sys::ULONG::from(request.stack.share_access()),
            ) {
                Ok(fcb) => fcb,
                Err(status) => return status,
            };
            match truncate_existing_file(vcb, inode) {
                Ok(()) => attach_file_object(request.file_object(), fcb, node, path),
                Err(status) => {
                    abandon_file_control_block(request.file_object(), fcb);
                    status
                }
            }
        }
    }
}

/// Resolves an existing regular file inode for overwrite-style dispositions.
fn overwrite_file_inode(
    node: FileSystemNode,
    options: wdk_sys::ULONG,
) -> Result<InodeId, NTSTATUS> {
    if options & FILE_DIRECTORY_FILE_OPTION != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if options & FILE_NON_DIRECTORY_FILE_OPTION != 0 {
        validate_existing_node_options(node, options)?;
    }
    match node {
        FileSystemNode::File(inode) => Ok(inode),
        FileSystemNode::Directory(_) | FileSystemNode::Symlink(_) => {
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        }
    }
}

/// Creates a missing final path component.
fn create_missing_node(
    request: CreateRequest,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    disposition: CreateDisposition,
    parent: InodeId,
    name: &Ext4Name,
) -> NTSTATUS {
    match disposition {
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {}
        CreateDisposition::Open => return STATUS_OBJECT_NAME_NOT_FOUND,
        CreateDisposition::Overwrite => return STATUS_OBJECT_NAME_NOT_FOUND,
    }
    let kind = match CreateNodeKind::from_options(request.stack.options()) {
        Ok(kind) => kind,
        Err(status) => return status,
    };
    let node = match create_child(vcb, parent, name, kind) {
        Ok(node) => node,
        Err(status) => return status,
    };
    initialize_file_object(
        request.file_object(),
        vcb,
        node,
        OpenedPath::Child {
            parent,
            name: name.clone(),
        },
        request.stack.desired_access(),
        wdk_sys::ULONG::from(request.stack.share_access()),
    )
}

/// Validates file-vs-directory options for an existing node.
fn validate_existing_node_options(
    node: FileSystemNode,
    options: wdk_sys::ULONG,
) -> Result<(), NTSTATUS> {
    if options & FILE_DIRECTORY_FILE_OPTION != 0 && !matches!(node, FileSystemNode::Directory(_)) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    if options & FILE_NON_DIRECTORY_FILE_OPTION != 0 && matches!(node, FileSystemNode::Directory(_))
    {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    Ok(())
}

/// Truncates an existing regular file for overwrite-style create dispositions.
fn truncate_existing_file(
    mut vcb: NonNull<crate::state::VolumeControlBlock>,
    inode: InodeId,
) -> Result<(), NTSTATUS> {
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension. The mutable borrow is the
        // transaction boundary for this overwrite request.
        vcb.as_mut()
    };
    let mut transaction = vcb.volume_mut().begin_transaction(
        crate::time::current_ext4_timestamp().map_err(crate::status::DriverError::ntstatus)?,
    );
    let file = transaction
        .file(inode)
        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?;
    transaction
        .truncate_file(file, FileSize::from_bytes(0))
        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?;
    transaction
        .commit()
        .map_err(|error| crate::status::DriverError::from(error).ntstatus())
}

/// Resolves a root-relative Windows path to an existing node or missing leaf.
fn resolve_path(
    file_object: NonNull<FILE_OBJECT>,
    vcb: NonNull<crate::state::VolumeControlBlock>,
) -> Result<PathLookup, NTSTATUS> {
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
        // in the mounted device extension and is read only for path lookup.
        vcb.as_ref()
    };
    let mut inode = InodeId::ROOT;
    let components = path_components(file_object)?;
    let mut components = components.iter().peekable();
    while let Some(component) = components.next() {
        let is_final = components.peek().is_none();
        let parent = match vcb.volume().read_node(inode) {
            Ok(Node::Directory(directory)) => directory,
            Ok(_) => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
            Err(error) => return Err(crate::status::DriverError::from(error).ntstatus()),
        };
        let entry = match vcb.volume().lookup_windows_child_entry(&parent, component) {
            Ok(Some(entry)) => entry,
            Ok(None) if is_final => {
                return Ok(PathLookup::Missing {
                    parent: inode,
                    name: component
                        .to_ext4()
                        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?,
                });
            }
            Ok(None) => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
            Err(error) => return Err(crate::status::DriverError::from(error).ntstatus()),
        };
        if is_final {
            let node = match vcb.volume().read_node(entry.inode()) {
                Ok(Node::File(_)) => FileSystemNode::File(entry.inode()),
                Ok(Node::Directory(_)) => FileSystemNode::Directory(entry.inode()),
                Ok(Node::Symlink(_)) => FileSystemNode::Symlink(entry.inode()),
                Err(error) => return Err(crate::status::DriverError::from(error).ntstatus()),
            };
            return Ok(PathLookup::Existing {
                node,
                path: OpenedPath::Child {
                    parent: inode,
                    name: entry.name().clone(),
                },
            });
        }
        inode = entry.inode();
    }

    match vcb.volume().read_node(inode) {
        Ok(Node::File(_)) => Ok(PathLookup::Existing {
            node: FileSystemNode::File(inode),
            path: OpenedPath::Root,
        }),
        Ok(Node::Directory(_)) => Ok(PathLookup::Existing {
            node: FileSystemNode::Directory(inode),
            path: OpenedPath::Root,
        }),
        Ok(Node::Symlink(_)) => Ok(PathLookup::Existing {
            node: FileSystemNode::Symlink(inode),
            path: OpenedPath::Root,
        }),
        Err(error) => Err(crate::status::DriverError::from(error).ntstatus()),
    }
}

/// Creates a file or directory under an existing parent directory.
fn create_child(
    mut vcb: NonNull<crate::state::VolumeControlBlock>,
    parent: InodeId,
    name: &Ext4Name,
    kind: CreateNodeKind,
) -> Result<FileSystemNode, NTSTATUS> {
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension. The mutable borrow is the
        // transaction boundary for this create request.
        vcb.as_mut()
    };
    let mut transaction = vcb.volume_mut().begin_transaction(
        crate::time::current_ext4_timestamp().map_err(crate::status::DriverError::ntstatus)?,
    );
    let parent = transaction
        .directory(parent)
        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?;
    let node = match kind {
        CreateNodeKind::File => {
            let file = transaction
                .create_file(
                    parent,
                    name,
                    metadata::default_file_metadata()
                        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?,
                )
                .map_err(|error| crate::status::DriverError::from(error).ntstatus())?;
            FileSystemNode::File(file.inode_id())
        }
        CreateNodeKind::Directory => {
            let directory = transaction
                .create_directory(
                    parent,
                    name,
                    metadata::default_directory_metadata()
                        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?,
                )
                .map_err(|error| crate::status::DriverError::from(error).ntstatus())?;
            FileSystemNode::Directory(directory.inode_id())
        }
    };
    transaction
        .commit()
        .map_err(|error| crate::status::DriverError::from(error).ntstatus())?;
    Ok(node)
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
    file_object: NonNull<FILE_OBJECT>,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    node: FileSystemNode,
    path: OpenedPath,
    desired_access: wdk_sys::ACCESS_MASK,
    share_access: wdk_sys::ULONG,
) -> NTSTATUS {
    match open_shared_file_control_block(file_object, vcb, node, desired_access, share_access) {
        Ok(fcb) => attach_file_object(file_object, fcb, node, path),
        Err(status) => status,
    }
}

/// Opens the shared FCB for a node and records the create share-access claim.
fn open_shared_file_control_block(
    file_object: NonNull<FILE_OBJECT>,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    node: FileSystemNode,
    desired_access: wdk_sys::ACCESS_MASK,
    share_access: wdk_sys::ULONG,
) -> Result<NonNull<FileControlBlock>, NTSTATUS> {
    let file_object_ref = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is read
        // only for filesystem-owned context pointers before initialization.
        file_object.as_ref()
    };
    if !file_object_ref.FsContext.is_null() || !file_object_ref.FsContext2.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let Some(mut fcb) = VolumeControlBlock::open_file_control_block(vcb, node) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let fcb_ref = unsafe {
        // SAFETY: The VCB returned a live owned FCB pointer with an open
        // reference for this create request.
        fcb.as_mut()
    };
    let status = fcb_ref.check_share_access(file_object, desired_access, share_access);
    if status < STATUS_SUCCESS {
        release_file_control_block(fcb);
        return Err(status);
    }

    Ok(fcb)
}

/// Stores already-opened FCB and new CCB context pointers in the FILE_OBJECT.
fn attach_file_object(
    mut file_object: NonNull<FILE_OBJECT>,
    fcb: NonNull<FileControlBlock>,
    node: FileSystemNode,
    path: OpenedPath,
) -> NTSTATUS {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is
        // writable during successful create processing.
        file_object.as_mut()
    };
    let ccb = Box::new(ContextControlBlock::new(node, path));
    file_object.FsContext = fcb.as_ptr().cast::<c_void>();
    file_object.FsContext2 = Box::into_raw(ccb).cast::<c_void>();
    STATUS_SUCCESS
}

/// Rolls back an FCB open whose FILE_OBJECT was not attached.
fn abandon_file_control_block(
    file_object: NonNull<FILE_OBJECT>,
    mut fcb: NonNull<FileControlBlock>,
) {
    let fcb_ref = unsafe {
        // SAFETY: The FCB was opened for this create request and has not been
        // published into FILE_OBJECT::FsContext.
        fcb.as_mut()
    };
    fcb_ref.remove_share_access(file_object);
    release_file_control_block(fcb);
}

#[cfg(test)]
mod tests {
    use super::{
        CREATE_DISPOSITION_SHIFT, CreateDisposition, FILE_CREATE_DISPOSITION,
        FILE_OPEN_IF_DISPOSITION, FILE_OVERWRITE_DISPOSITION, FILE_OVERWRITE_IF_DISPOSITION,
        FILE_SUPERSEDE_DISPOSITION,
    };

    #[test]
    fn create_disposition_keeps_overwrite_and_supersede_distinct() {
        assert_eq!(
            CreateDisposition::from_options(FILE_CREATE_DISPOSITION << CREATE_DISPOSITION_SHIFT),
            Ok(CreateDisposition::Create)
        );
        assert_eq!(
            CreateDisposition::from_options(FILE_OPEN_IF_DISPOSITION << CREATE_DISPOSITION_SHIFT),
            Ok(CreateDisposition::OpenIf)
        );
        assert_eq!(
            CreateDisposition::from_options(FILE_OVERWRITE_DISPOSITION << CREATE_DISPOSITION_SHIFT),
            Ok(CreateDisposition::Overwrite)
        );
        assert_eq!(
            CreateDisposition::from_options(
                FILE_OVERWRITE_IF_DISPOSITION << CREATE_DISPOSITION_SHIFT
            ),
            Ok(CreateDisposition::OverwriteIf)
        );
        assert_eq!(
            CreateDisposition::from_options(FILE_SUPERSEDE_DISPOSITION << CREATE_DISPOSITION_SHIFT),
            Ok(CreateDisposition::Supersede)
        );
    }
}
