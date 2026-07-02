//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{
    ChildLookup, DirectoryNodeId, Ext4Name, FileNodeId, FileSize, NodeId, WindowsName,
};
use wdk_sys::{FILE_OBJECT, NTSTATUS, PDEVICE_OBJECT, PIRP};

use crate::{
    irp::{
        CreateDisposition, CreateParameters, CreateStack, CreateTargetRequirement, DesiredAccess,
        DispatchTarget, IrpCompletion, ShareAccess,
    },
    kernel::status::{DriverError, DriverResult},
    request::metadata,
    state::{
        CloseDisposition, FileControlBlock, KernelDevice, KernelFileObject, MountedVolumeDevice,
        OpenedHandle, OpenedPath, UninitializedFileObject, VolumeControlBlock,
        release_file_control_block,
    },
};

/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Handles create/open IRPs.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => target.finish_result(
            CreateRequest::decode(target)
                .and_then(open_or_create)
                .map(|()| IrpCompletion::EMPTY),
        ),
        Err(error) => DispatchTarget::finish_decode_error(irp, error),
    }
}

/// Decoded create request at the filesystem boundary.
#[derive(Clone, Copy, Debug)]
struct CreateRequest {
    /// Mounted device receiving the create.
    device: KernelDevice,
    /// Create stack parameters.
    stack: CreateStack,
    /// FILE_OBJECT before filesystem contexts are attached.
    file_object: UninitializedFileObject,
}

impl CreateRequest {
    /// Decodes the create request from the current IRP stack.
    /// # Errors
    ///
    /// Returns an error when the current stack is not create/open or the FILE_OBJECT is already
    /// initialized.
    fn decode(target: DispatchTarget) -> Result<Self, crate::kernel::status::DriverError> {
        let stack = target.current_stack()?.create()?;
        let file_object = UninitializedFileObject::decode(stack.file_object())?;
        Ok(Self {
            device: target.device(),
            stack,
            file_object,
        })
    }

    /// Returns the mounted device receiving the create.
    const fn device(self) -> KernelDevice {
        self.device
    }

    /// Returns the file object to initialize.
    const fn file_object(self) -> UninitializedFileObject {
        self.file_object
    }

    /// Returns decoded create parameters.
    const fn parameters(self) -> CreateParameters {
        self.stack.parameters()
    }
}

/// Opens or creates a root-relative ext4 object.
/// # Errors
///
/// Returns an error when EA create input is supplied, the device is not mounted, path resolution
/// fails, or the selected open/create disposition cannot be satisfied.
fn open_or_create(request: CreateRequest) -> DriverResult<()> {
    if request.parameters().ea_length().as_usize() != 0 {
        return Err(DriverError::NotSupported);
    }
    let Some(vcb) = MountedVolumeDevice::vcb(request.device()) else {
        return Err(DriverError::InvalidDeviceRequest);
    };
    let disposition = request.parameters().disposition();
    match resolve_path(request.file_object(), vcb) {
        Ok(PathLookup::Existing { node, path }) => {
            open_existing_node(request, vcb, disposition, node, path)
        }
        Ok(PathLookup::Missing { parent, name }) => {
            create_missing_node(request, vcb, disposition, parent, &name)
        }
        Err(error) => Err(error),
    }
}

/// Result of resolving a Windows path against the mounted volume.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PathLookup {
    /// The requested path already exists.
    Existing {
        /// Opened ext4 node.
        node: NodeId,
        /// Exact path identity.
        path: OpenedPath,
    },
    /// The final path component is absent under an existing parent directory.
    Missing {
        /// Parent directory inode.
        parent: DirectoryNodeId,
        /// New ext4 child name.
        name: Ext4Name,
    },
}

/// Opens an existing path according to the requested disposition and options.
/// # Errors
///
/// Returns an error when existing-node options conflict, create-only disposition collides, share
/// access fails, or overwrite truncation fails.
fn open_existing_node(
    request: CreateRequest,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    disposition: CreateDisposition,
    node: NodeId,
    path: OpenedPath,
) -> DriverResult<()> {
    let parameters = request.parameters();
    match disposition {
        CreateDisposition::Open | CreateDisposition::OpenIf => {
            validate_existing_node_options(node, parameters.target_requirement())?;
            initialize_file_object(
                request.file_object(),
                vcb,
                node,
                path,
                parameters.desired_access(),
                parameters.share_access(),
                parameters.close_disposition(),
            )
        }
        CreateDisposition::Create => Err(DriverError::ObjectNameCollision),
        CreateDisposition::Overwrite
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {
            let inode = overwrite_file_inode(node, parameters.target_requirement())?;
            let fcb = open_shared_file_control_block(
                request.file_object(),
                vcb,
                node,
                parameters.desired_access(),
                parameters.share_access(),
            )?;
            match truncate_existing_file(vcb, inode) {
                Ok(()) => attach_file_object(
                    request.file_object(),
                    fcb,
                    node,
                    path,
                    parameters.close_disposition(),
                ),
                Err(error) => {
                    abandon_file_control_block(request.file_object().kernel_file_object(), fcb);
                    Err(error)
                }
            }
        }
    }
}

/// Resolves an existing regular file inode for overwrite-style dispositions.
/// # Errors
///
/// Returns an error when overwrite is requested for a directory-required open or for an existing
/// non-file node.
fn overwrite_file_inode(
    node: NodeId,
    requirement: CreateTargetRequirement,
) -> DriverResult<FileNodeId> {
    if matches!(requirement, CreateTargetRequirement::Directory) {
        return Err(DriverError::NotSupported);
    }
    if matches!(requirement, CreateTargetRequirement::NonDirectory) {
        validate_existing_node_options(node, requirement)?;
    }
    match node {
        NodeId::File(file) => Ok(file),
        NodeId::Directory(_) | NodeId::Symlink(_) => Err(DriverError::ObjectTypeMismatch),
    }
}

/// Creates a missing final path component.
/// # Errors
///
/// Returns an error when the disposition requires an existing name, child creation fails, or the new
/// file object cannot be initialized.
fn create_missing_node(
    request: CreateRequest,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    disposition: CreateDisposition,
    parent: DirectoryNodeId,
    name: &Ext4Name,
) -> DriverResult<()> {
    match disposition {
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {}
        CreateDisposition::Open => return Err(DriverError::ObjectNameNotFound),
        CreateDisposition::Overwrite => return Err(DriverError::ObjectNameNotFound),
    }
    let node = create_child(vcb, parent, name, request.parameters().target_requirement())?;
    initialize_file_object(
        request.file_object(),
        vcb,
        node,
        OpenedPath::Child {
            parent,
            name: name.clone(),
        },
        request.parameters().desired_access(),
        request.parameters().share_access(),
        request.parameters().close_disposition(),
    )
}

/// Validates file-vs-directory options for an existing node.
/// # Errors
///
/// Returns an error when directory-only or non-directory-only create options contradict `node`.
fn validate_existing_node_options(
    node: NodeId,
    requirement: CreateTargetRequirement,
) -> DriverResult<()> {
    match requirement {
        CreateTargetRequirement::Any => {}
        CreateTargetRequirement::Directory if !matches!(node, NodeId::Directory(_)) => {
            return Err(DriverError::ObjectTypeMismatch);
        }
        CreateTargetRequirement::NonDirectory if matches!(node, NodeId::Directory(_)) => {
            return Err(DriverError::ObjectTypeMismatch);
        }
        CreateTargetRequirement::Directory | CreateTargetRequirement::NonDirectory => {}
    }
    Ok(())
}

/// Truncates an existing regular file for overwrite-style create dispositions.
/// # Errors
///
/// Returns an error when the file cannot be selected for mutation or the truncate transaction fails.
fn truncate_existing_file(
    mut vcb: NonNull<crate::state::VolumeControlBlock>,
    file_id: FileNodeId,
) -> DriverResult<()> {
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension. The mutable borrow is the
        // transaction boundary for this overwrite request.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let file = transaction.file(file_id)?;
    transaction.truncate_file(file, FileSize::from_bytes(0))?;
    transaction.commit()?;
    Ok(())
}

/// Resolves a root-relative Windows path to an existing node or missing leaf.
/// # Errors
///
/// Returns an error when relative FILE_OBJECT opens are requested, a path component is invalid, an
/// intermediate component is missing or not a directory, or lookup fails.
fn resolve_path(
    file_object: UninitializedFileObject,
    vcb: NonNull<crate::state::VolumeControlBlock>,
) -> DriverResult<PathLookup> {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is read
        // only for immutable path fields.
        file_object.as_ref()
    };
    if !file_object.RelatedFileObject.is_null() {
        return Err(DriverError::NotSupported);
    }
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension and is read only for path lookup.
        vcb.as_ref()
    };
    let mut parent_id = DirectoryNodeId::ROOT;
    let components = path_components(file_object)?;
    let mut components = components.iter().peekable();
    while let Some(component) = components.next() {
        let is_final = components.peek().is_none();
        let parent = match vcb.volume().load_directory(parent_id) {
            Ok(directory) => directory,
            Err(error) => return Err(DriverError::from(error)),
        };
        let child = match vcb.volume().lookup_windows_child(&parent, component) {
            Ok(ChildLookup::Found(child)) => child,
            Ok(ChildLookup::NotFound) if is_final => {
                return Ok(PathLookup::Missing {
                    parent: parent_id,
                    name: component.to_ext4()?,
                });
            }
            Ok(ChildLookup::NotFound) => return Err(DriverError::ObjectPathNotFound),
            Err(error) => return Err(DriverError::from(error)),
        };
        if is_final {
            return Ok(PathLookup::Existing {
                node: *child.node(),
                path: OpenedPath::Child {
                    parent: child.parent(),
                    name: child.name().clone(),
                },
            });
        }
        let NodeId::Directory(directory_id) = *child.node() else {
            return Err(DriverError::ObjectPathNotFound);
        };
        parent_id = directory_id;
    }

    match vcb.volume().load_directory(parent_id) {
        Ok(directory) => Ok(PathLookup::Existing {
            node: NodeId::Directory(directory.id()),
            path: OpenedPath::Root,
        }),
        Err(error) => Err(DriverError::from(error)),
    }
}

/// Creates a file or directory under an existing parent directory.
/// # Errors
///
/// Returns an error when default metadata cannot be built, the parent cannot be selected, creation
/// fails, or the transaction cannot commit.
fn create_child(
    mut vcb: NonNull<crate::state::VolumeControlBlock>,
    parent: DirectoryNodeId,
    name: &Ext4Name,
    requirement: CreateTargetRequirement,
) -> DriverResult<NodeId> {
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension. The mutable borrow is the
        // transaction boundary for this create request.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let parent = transaction.directory(parent)?;
    let node = match requirement {
        CreateTargetRequirement::Any | CreateTargetRequirement::NonDirectory => {
            let file = transaction.create_file(parent, name, metadata::default_file_metadata()?)?;
            NodeId::File(file.id())
        }
        CreateTargetRequirement::Directory => {
            let directory = transaction.create_directory(
                parent,
                name,
                metadata::default_directory_metadata()?,
            )?;
            NodeId::Directory(directory.id())
        }
    };
    transaction.commit()?;
    Ok(node)
}

/// Splits the FILE_OBJECT name into validated root-relative Windows components.
/// # Errors
///
/// Returns an error when the UNICODE_STRING has odd byte length, a null non-empty buffer, or an
/// invalid Windows path component.
fn path_components(file_object: &FILE_OBJECT) -> DriverResult<Vec<WindowsName>> {
    let name = file_object.FileName;
    if name.Length == 0 {
        return Ok(Vec::new());
    }
    if !name.Length.is_multiple_of(2) || name.Buffer.is_null() {
        return Err(DriverError::InvalidParameter);
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
        components.push(WindowsName::from_utf16(component)?);
    }
    Ok(components)
}

/// Stores FCB/CCB context pointers in the FILE_OBJECT.
/// # Errors
///
/// Returns an error when the shared FCB cannot be opened or the handle context cannot be attached.
fn initialize_file_object(
    file_object: UninitializedFileObject,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    node: NodeId,
    path: OpenedPath,
    desired_access: DesiredAccess,
    share_access: ShareAccess,
    close_disposition: CloseDisposition,
) -> DriverResult<()> {
    let fcb = open_shared_file_control_block(file_object, vcb, node, desired_access, share_access)?;
    attach_file_object(file_object, fcb, node, path, close_disposition)
}

/// Opens the shared FCB for a node and records the create share-access claim.
/// # Errors
///
/// Returns an error when the VCB cannot open an FCB for `node` or Windows share-access checking
/// rejects the new handle.
fn open_shared_file_control_block(
    file_object: UninitializedFileObject,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    node: NodeId,
    desired_access: DesiredAccess,
    share_access: ShareAccess,
) -> DriverResult<NonNull<FileControlBlock>> {
    let mut fcb = VolumeControlBlock::open_file_control_block(vcb, node)?;
    let fcb_ref = unsafe {
        // SAFETY: The VCB returned a live owned FCB pointer with an open
        // reference for this create request.
        fcb.as_mut()
    };
    if let Err(error) = fcb_ref.check_share_access(
        file_object.kernel_file_object(),
        desired_access,
        share_access,
    ) {
        release_file_control_block(fcb);
        return Err(error);
    }

    Ok(fcb)
}

/// Stores already-opened FCB and new CCB context pointers in the FILE_OBJECT.
/// # Errors
///
/// Returns an error when FILE_OBJECT context pointers cannot be attached.
fn attach_file_object(
    file_object: UninitializedFileObject,
    fcb: NonNull<FileControlBlock>,
    node: NodeId,
    path: OpenedPath,
    close_disposition: CloseDisposition,
) -> DriverResult<()> {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is
        // writable during successful create processing.
        file_object.as_mut()
    };
    let handle = Box::new(OpenedHandle::new(node, path, close_disposition));
    file_object.FsContext = fcb.as_ptr().cast::<c_void>();
    file_object.FsContext2 = Box::into_raw(handle).cast::<c_void>();
    Ok(())
}

/// Rolls back an FCB open whose FILE_OBJECT was not attached.
fn abandon_file_control_block(file_object: KernelFileObject, mut fcb: NonNull<FileControlBlock>) {
    let fcb_ref = unsafe {
        // SAFETY: The FCB was opened for this create request and has not been
        // published into FILE_OBJECT::FsContext.
        fcb.as_mut()
    };
    fcb_ref.remove_share_access(file_object);
    release_file_control_block(fcb);
}
