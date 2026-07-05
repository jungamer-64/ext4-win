//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{
    ChildLookup, DirectoryNodeId, Ext4Name, FileNodeId, FileSize, NodeId, WindowsName,
};
use wdk_sys::FILE_OBJECT;

use crate::{
    irp::{
        CreateDisposition, CreateParameters, CreateStack, CreateTargetRequirement, DesiredAccess,
        DispatchTarget, IrpCompletion, ShareAccess,
    },
    kernel::status::{DriverError, DriverResult},
    memory::{self, DriverVec},
    request::{ea::CreateEa, metadata},
    state::{
        ChildCreationTarget, CloseDisposition, FileControlBlock, KernelDevice, KernelFileObject,
        MountedVolumeDevice, OpenedHandle, OpenedObject, OpenedPath, PendingChildCreation,
        UninitializedFileObject, VolumeControlBlock, WriteCommitment, release_file_control_block,
    },
};

/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Executes a decoded create/open IRP.
/// # Errors
///
/// Returns an error when create stack decoding or ext4 open/create handling rejects the request.
pub(crate) fn execute(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    CreateRequest::decode(target)
        .and_then(open_or_create)
        .map(|()| IrpCompletion::EMPTY)
}

/// Decoded create request at the filesystem boundary.
#[derive(Clone, Copy, Debug)]
struct CreateRequest {
    /// Dispatch target carrying create-time auxiliary buffers.
    target: DispatchTarget,
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
            target,
            device: target.device(),
            stack,
            file_object,
        })
    }

    /// Returns the dispatch target carrying create-time auxiliary buffers.
    const fn target(self) -> DispatchTarget {
        self.target
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

/// Opens or creates an ext4 object from a volume-root or opened-directory path.
/// # Errors
///
/// Returns an error when EA create input is supplied, the device is not mounted, path resolution
/// fails, or the selected open/create disposition cannot be satisfied.
fn open_or_create(request: CreateRequest) -> DriverResult<()> {
    let create_ea = CreateEa::decode(request.target(), request.parameters().ea_length())?;
    let Some(vcb) = MountedVolumeDevice::vcb(request.device()) else {
        return Err(DriverError::InvalidDeviceRequest);
    };
    let disposition = request.parameters().disposition();
    match resolve_path(request.file_object(), vcb) {
        Ok(PathLookup::Existing { node, path }) => {
            open_existing_node(request, vcb, disposition, node, path)
        }
        Ok(PathLookup::Missing { parent, name }) => {
            create_missing_node(request, create_ea, vcb, disposition, parent, &name)
        }
        Err(error) => Err(error),
    }
}

/// Result of resolving a Windows path against the mounted volume.
#[derive(Debug, Eq, PartialEq)]
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

/// Per-handle policy decoded from one create/open request.
#[derive(Clone, Copy, Debug)]
struct CreateHandlePolicy {
    /// Access mask used for Windows share-access accounting.
    desired_access: DesiredAccess,
    /// Share mask used for Windows share-access accounting.
    share_access: ShareAccess,
    /// Cleanup-time lifecycle requested by create options.
    close_disposition: CloseDisposition,
    /// Write completion durability requested by create options.
    write_commitment: WriteCommitment,
}

impl CreateHandlePolicy {
    /// Projects handle policy fields from decoded create parameters.
    const fn from_parameters(parameters: CreateParameters) -> Self {
        Self {
            desired_access: parameters.desired_access(),
            share_access: parameters.share_access(),
            close_disposition: parameters.close_disposition(),
            write_commitment: parameters.write_commitment(),
        }
    }

    /// Returns the desired access mask.
    const fn desired_access(self) -> DesiredAccess {
        self.desired_access
    }

    /// Returns the share access mask.
    const fn share_access(self) -> ShareAccess {
        self.share_access
    }

    /// Returns the cleanup-time lifecycle.
    const fn close_disposition(self) -> CloseDisposition {
        self.close_disposition
    }

    /// Returns write completion durability.
    const fn write_commitment(self) -> WriteCommitment {
        self.write_commitment
    }
}

/// FILE_OBJECT name rooting after the raw UTF-16 boundary has been decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CreateNameRooting {
    /// Name starts at the mounted volume root.
    Absolute,
    /// Name starts at the related directory when one exists, otherwise the mounted volume root.
    Relative,
}

/// Decoded create path name supplied by the I/O Manager.
#[derive(Debug, Eq, PartialEq)]
struct CreatePathName {
    /// Rooting syntax encoded by the raw FILE_OBJECT name.
    rooting: CreateNameRooting,
    /// Validated Windows path components after removing the syntactic root prefix.
    components: DriverVec<WindowsName>,
}

impl CreatePathName {
    /// Decodes the FILE_OBJECT name into a rooted component sequence.
    /// # Errors
    ///
    /// Returns an error when the raw UNICODE_STRING is malformed, contains an empty path component,
    /// or contains a component not representable in the Windows namespace domain.
    fn decode(file_object: &FILE_OBJECT) -> DriverResult<Self> {
        let name = file_object.FileName;
        if name.Length == 0 {
            return Ok(Self {
                rooting: CreateNameRooting::Relative,
                components: DriverVec::new(),
            });
        }
        if !name.Length.is_multiple_of(2) || name.Buffer.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        let units = unsafe {
            // SAFETY: UNICODE_STRING Length is byte length; the odd-length and null
            // buffer cases were rejected above.
            core::slice::from_raw_parts(name.Buffer, usize::from(name.Length / 2))
        };
        let (rooting, components) = Self::split_rooting(units);
        Ok(Self {
            rooting,
            components: path_components(components)?,
        })
    }

    /// Returns the decoded rooting syntax.
    const fn rooting(&self) -> CreateNameRooting {
        self.rooting
    }

    /// Returns validated path components.
    fn components(&self) -> &[WindowsName] {
        self.components.as_slice()
    }

    /// Splits the syntactic root prefix from the component payload.
    fn split_rooting(mut units: &[u16]) -> (CreateNameRooting, &[u16]) {
        if !units.starts_with(&[UTF16_BACKSLASH]) {
            return (CreateNameRooting::Relative, units);
        }
        while let Some(rest) = units.strip_prefix(&[UTF16_BACKSLASH]) {
            units = rest;
        }
        (CreateNameRooting::Absolute, units)
    }
}

/// Create path starting directory after RelatedFileObject has been decoded.
#[derive(Debug, Eq, PartialEq)]
enum CreatePathAnchor {
    /// Mounted volume root directory.
    VolumeRoot,
    /// Existing opened directory supplied through FILE_OBJECT::RelatedFileObject.
    OpenedDirectory {
        /// Related directory inode.
        id: DirectoryNodeId,
        /// Related directory path identity.
        path: OpenedPath,
    },
}

impl CreatePathAnchor {
    /// Decodes the path anchor for a create request.
    /// # Errors
    ///
    /// Returns an error when an absolute path also supplies a related object, or when the related
    /// object is not an opened directory on the mounted volume receiving this create.
    fn decode(
        file_object: &FILE_OBJECT,
        vcb: NonNull<VolumeControlBlock>,
        rooting: CreateNameRooting,
    ) -> DriverResult<Self> {
        let Some(related_file) = KernelFileObject::from_raw(file_object.RelatedFileObject) else {
            return Ok(Self::VolumeRoot);
        };
        if rooting == CreateNameRooting::Absolute {
            return Err(DriverError::InvalidParameter);
        }
        let opened = OpenedObject::decode(related_file)?;
        if opened.volume() != vcb {
            return Err(DriverError::InvalidDeviceRequest);
        }
        let NodeId::Directory(id) = opened.node() else {
            return Err(DriverError::ObjectTypeMismatch);
        };
        Ok(Self::OpenedDirectory {
            id,
            path: opened.path().try_to_owned_path()?,
        })
    }

    /// Returns the directory where component lookup starts.
    const fn directory(&self) -> DirectoryNodeId {
        match self {
            Self::VolumeRoot => DirectoryNodeId::ROOT,
            Self::OpenedDirectory { id, .. } => *id,
        }
    }

    /// Converts an empty create name into the already-opened anchor directory.
    fn existing_directory(self) -> PathLookup {
        match self {
            Self::VolumeRoot => PathLookup::Existing {
                node: NodeId::Directory(DirectoryNodeId::ROOT),
                path: OpenedPath::Root,
            },
            Self::OpenedDirectory { id, path } => PathLookup::Existing {
                node: NodeId::Directory(id),
                path,
            },
        }
    }
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
    let policy = CreateHandlePolicy::from_parameters(parameters);
    match disposition {
        CreateDisposition::Open | CreateDisposition::OpenIf => {
            validate_existing_node_options(node, parameters.target_requirement())?;
            initialize_file_object(request.file_object(), vcb, node, path, policy)
        }
        CreateDisposition::Create => Err(DriverError::ObjectNameCollision),
        CreateDisposition::Overwrite
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {
            let inode = overwrite_file_inode(node, parameters.target_requirement())?;
            let handle = memory::boxed_try_with(|| {
                Ok(OpenedHandle::new(
                    node,
                    path,
                    policy.close_disposition(),
                    policy.write_commitment(),
                ))
            })?;
            let fcb = open_shared_file_control_block(
                request.file_object(),
                vcb,
                node,
                policy.desired_access(),
                policy.share_access(),
            )?;
            match truncate_existing_file(vcb, inode) {
                Ok(()) => {
                    attach_preallocated_file_object(request.file_object(), fcb, handle);
                    Ok(())
                }
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
/// Returns an error when the disposition requires an existing name, missing-child creation cannot
/// be staged or committed, or the new file object cannot be initialized.
fn create_missing_node(
    request: CreateRequest,
    create_ea: CreateEa,
    mut vcb: NonNull<crate::state::VolumeControlBlock>,
    disposition: CreateDisposition,
    parent: DirectoryNodeId,
    name: &Ext4Name,
) -> DriverResult<()> {
    let parameters = request.parameters();
    let policy = CreateHandlePolicy::from_parameters(parameters);
    match disposition {
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {}
        CreateDisposition::Open => return Err(DriverError::ObjectNameNotFound),
        CreateDisposition::Overwrite => return Err(DriverError::ObjectNameNotFound),
    }

    let path = OpenedPath::try_child(parent, name)?;
    let target = child_creation_target(parameters.target_requirement())?;
    let mut creation = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension. The pending creation keeps the
        // mutable borrow until its staged transaction is committed or dropped.
        vcb.as_mut()
    }
    .begin_child_creation(
        parent,
        name,
        target,
        crate::kernel::time::current_ext4_timestamp()?,
    )?;
    let node = creation.node();
    let handle = memory::boxed_try_with(|| {
        Ok(OpenedHandle::new(
            node,
            path,
            policy.close_disposition(),
            policy.write_commitment(),
        ))
    })?;
    create_ea.apply_to_pending_child(&mut creation)?;
    let fcb = open_pending_child_file_control_block(
        &mut creation,
        request.file_object(),
        policy.desired_access(),
        policy.share_access(),
    )?;

    match creation.commit() {
        Ok(()) => {
            attach_preallocated_file_object(request.file_object(), fcb, handle);
            Ok(())
        }
        Err(error) => {
            abandon_file_control_block(request.file_object().kernel_file_object(), fcb);
            Err(error)
        }
    }
}

/// Maps create options to the concrete child kind used for missing-name creation.
/// # Errors
///
/// Returns an error when default metadata cannot be built.
fn child_creation_target(
    requirement: CreateTargetRequirement,
) -> DriverResult<ChildCreationTarget> {
    match requirement {
        CreateTargetRequirement::Any | CreateTargetRequirement::NonDirectory => {
            Ok(ChildCreationTarget::File(metadata::default_file_metadata()?))
        }
        CreateTargetRequirement::Directory => Ok(ChildCreationTarget::Directory(
            metadata::default_directory_metadata()?,
        )),
    }
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
    vcb: NonNull<VolumeControlBlock>,
) -> DriverResult<PathLookup> {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is read
        // only for immutable path fields.
        file_object.as_ref()
    };
    let name = CreatePathName::decode(file_object)?;
    let anchor = CreatePathAnchor::decode(file_object, vcb, name.rooting())?;
    let vcb = unsafe {
        // SAFETY: MountedVolumeDevice::vcb returns the live VCB pointer stored
        // in the mounted device extension and is read only for path lookup.
        vcb.as_ref()
    };
    let mut parent_id = anchor.directory();
    let components = name.components();
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
                path: OpenedPath::try_child(child.parent(), child.name())?,
            });
        }
        let NodeId::Directory(directory_id) = *child.node() else {
            return Err(DriverError::ObjectPathNotFound);
        };
        parent_id = directory_id;
    }

    Ok(anchor.existing_directory())
}

/// Splits non-root path units into validated Windows components.
/// # Errors
///
/// Returns an error when any component is empty or not representable in the Windows namespace
/// domain.
fn path_components(units: &[u16]) -> DriverResult<DriverVec<WindowsName>> {
    if units.is_empty() {
        return Ok(DriverVec::new());
    }
    let mut components = DriverVec::new();
    for component in units.split(|unit| *unit == UTF16_BACKSLASH) {
        components
            .try_push_owned(WindowsName::from_utf16(component)?)
            .map_err(|error| error.into_parts().0)?;
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
    policy: CreateHandlePolicy,
) -> DriverResult<()> {
    let handle = memory::boxed_try_with(|| {
        Ok(OpenedHandle::new(
            node,
            path,
            policy.close_disposition(),
            policy.write_commitment(),
        ))
    })?;
    let fcb = open_shared_file_control_block(
        file_object,
        vcb,
        node,
        policy.desired_access(),
        policy.share_access(),
    )?;
    attach_preallocated_file_object(file_object, fcb, handle);
    Ok(())
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

/// Opens the staged child FCB and records the create share-access claim before commit.
/// # Errors
///
/// Returns an error when FCB creation fails or Windows share-access checking rejects the new handle.
fn open_pending_child_file_control_block(
    creation: &mut PendingChildCreation<'_>,
    file_object: UninitializedFileObject,
    desired_access: DesiredAccess,
    share_access: ShareAccess,
) -> DriverResult<NonNull<FileControlBlock>> {
    let mut fcb = creation.open_file_control_block()?;
    let fcb_ref = unsafe {
        // SAFETY: The pending creation returned a live owned FCB pointer with
        // an open reference for this create request.
        fcb.as_mut()
    };
    if let Err(error) = fcb_ref.check_share_access(
        file_object.kernel_file_object(),
        desired_access,
        share_access,
    ) {
        creation.release_file_control_block(fcb);
        return Err(error);
    }

    Ok(fcb)
}

/// Stores already-opened FCB and preallocated CCB context pointers in the FILE_OBJECT.
fn attach_preallocated_file_object(
    file_object: UninitializedFileObject,
    fcb: NonNull<FileControlBlock>,
    handle: Box<OpenedHandle>,
) {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is
        // writable during successful create processing.
        file_object.as_mut()
    };
    file_object.FsContext = fcb.as_ptr().cast::<c_void>();
    file_object.FsContext2 = Box::into_raw(handle).cast::<c_void>();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn file_object_with_name(units: &mut [u16]) -> FILE_OBJECT {
        let Ok(byte_len) = u16::try_from(core::mem::size_of_val(units)) else {
            return FILE_OBJECT::default();
        };
        FILE_OBJECT {
            FileName: wdk_sys::UNICODE_STRING {
                Length: byte_len,
                MaximumLength: byte_len,
                Buffer: units.as_mut_ptr(),
            },
            ..FILE_OBJECT::default()
        }
    }

    fn attach_opened_contexts(
        file_object: &mut FILE_OBJECT,
        fcb: &mut FileControlBlock,
        handle: &mut OpenedHandle,
    ) {
        file_object.FsContext = core::ptr::addr_of_mut!(*fcb).cast();
        file_object.FsContext2 = core::ptr::addr_of_mut!(*handle).cast();
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_path_name_decodes_absolute_relative_and_empty_names() {
        let mut absolute_units = [
            UTF16_BACKSLASH,
            UTF16_BACKSLASH,
            u16::from(b'd'),
            u16::from(b'i'),
            u16::from(b'r'),
            UTF16_BACKSLASH,
            u16::from(b'f'),
        ];
        let absolute_file = file_object_with_name(&mut absolute_units);
        let absolute = CreatePathName::decode(&absolute_file);
        assert!(absolute.is_ok());
        if let Ok(absolute) = absolute {
            assert_eq!(absolute.rooting(), CreateNameRooting::Absolute);
            assert_eq!(absolute.components().len(), 2);
            assert_eq!(
                absolute.components().first().map(WindowsName::utf16),
                Some([u16::from(b'd'), u16::from(b'i'), u16::from(b'r')].as_slice())
            );
            assert_eq!(
                absolute.components().get(1).map(WindowsName::utf16),
                Some([u16::from(b'f')].as_slice())
            );
        }

        let mut relative_units = [u16::from(b'c'), u16::from(b'h'), u16::from(b'i')];
        let relative_file = file_object_with_name(&mut relative_units);
        let relative = CreatePathName::decode(&relative_file);
        assert!(relative.is_ok());
        if let Ok(relative) = relative {
            assert_eq!(relative.rooting(), CreateNameRooting::Relative);
            assert_eq!(relative.components().len(), 1);
            assert_eq!(
                relative.components().first().map(WindowsName::utf16),
                Some([u16::from(b'c'), u16::from(b'h'), u16::from(b'i')].as_slice())
            );
        }

        let empty_file = FILE_OBJECT::default();
        let empty = CreatePathName::decode(&empty_file);
        assert!(empty.is_ok());
        if let Ok(empty) = empty {
            assert_eq!(empty.rooting(), CreateNameRooting::Relative);
            assert!(empty.components().is_empty());
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_path_name_rejects_empty_inner_components() {
        let mut units = [
            u16::from(b'd'),
            UTF16_BACKSLASH,
            UTF16_BACKSLASH,
            u16::from(b'f'),
        ];
        let file_object = file_object_with_name(&mut units);
        assert_eq!(
            CreatePathName::decode(&file_object),
            Err(DriverError::from(ext4_core::Error::InvalidName))
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_path_anchor_accepts_opened_relative_directory() {
        let vcb = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(vcb, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedPath::Root,
            CloseDisposition::Keep,
            WriteCommitment::CommitOnly,
        );
        let mut related = FILE_OBJECT::default();
        attach_opened_contexts(&mut related, &mut fcb, &mut handle);
        let create = FILE_OBJECT {
            RelatedFileObject: core::ptr::addr_of_mut!(related),
            ..FILE_OBJECT::default()
        };

        assert_eq!(
            CreatePathAnchor::decode(&create, vcb, CreateNameRooting::Relative),
            Ok(CreatePathAnchor::OpenedDirectory {
                id: DirectoryNodeId::ROOT,
                path: OpenedPath::Root,
            })
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_path_anchor_rejects_conflicting_absolute_related_object() {
        let vcb = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(vcb, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedPath::Root,
            CloseDisposition::Keep,
            WriteCommitment::CommitOnly,
        );
        let mut related = FILE_OBJECT::default();
        attach_opened_contexts(&mut related, &mut fcb, &mut handle);
        let create = FILE_OBJECT {
            RelatedFileObject: core::ptr::addr_of_mut!(related),
            ..FILE_OBJECT::default()
        };

        assert_eq!(
            CreatePathAnchor::decode(&create, vcb, CreateNameRooting::Absolute),
            Err(DriverError::InvalidParameter)
        );
    }
}
