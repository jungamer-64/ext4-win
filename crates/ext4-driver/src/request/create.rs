//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::{ChildLookup, DirectoryNodeId, Ext4Name, NodeId, WindowsName};
use wdk_sys::FILE_OBJECT;

use crate::{
    irp::{
        CreateAction, CreateCompletion, CreateDisposition, CreateNameInterpretation,
        CreateParameters, CreateReparsePointMode, CreateSymlinkReparseBuffer,
        CreateSynchronizationMode, CreateTargetRequirement, CreateTransferBuffering, DesiredAccess,
        DispatchTarget, ExistingOperationAccess, PendingIrpLease, RegularFileWriteAccess,
        ShareAccess,
    },
    kernel::status::{DriverError, DriverResult},
    memory::{self, DriverVec},
    request::{
        ea::CreateEa,
        metadata,
        reparse::{NodeSymlinkReparsePoint, UnparsedPathLength},
    },
    state::{
        ChildCreationTarget, DataTransferMode, DirectoryNameChange, DirectoryNameChangeAction,
        FileControlBlock, KernelDevice, KernelFileObject, MountedVolumeDevice,
        NoIntermediateTransfer, OpenedHandle, OpenedLocation, OpenedNodeMode, OpenedObject,
        PendingChildCreation, UninitializedFileObject, VolumeControlBlock, VolumeOperationLane,
        VolumeOperationLease, WriteCommitment, abandon_file_control_block,
    },
};

/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Executes a decoded create/open IRP.
/// # Errors
///
/// Returns an error when create stack decoding or ext4 open/create handling rejects the request.
pub(crate) async fn execute(request: PendingIrpLease<'_>) -> DriverResult<CreateCompletion> {
    open_or_create(CreateRequest::decode(request)?).await
}

/// Decoded create request at the filesystem boundary.
#[derive(Debug)]
struct CreateRequest<'a> {
    /// Pending IRP lease retaining every create-time pointer through terminal completion.
    request: PendingIrpLease<'a>,
    /// Owned semantic create parameters decoded before suspension.
    parameters: CreateParameters,
    /// FILE_OBJECT before filesystem contexts are attached.
    file_object: UninitializedFileObject,
}

// SAFETY: The exclusive pending-IRP lease pins the FILE_OBJECT and every auxiliary buffer until
// this request is dropped. The mounted-device executor moves, but never concurrently polls, this
// create operation between PASSIVE_LEVEL workers.
unsafe impl Send for CreateRequest<'_> {}

impl<'a> CreateRequest<'a> {
    /// Decodes the create request from the current IRP stack.
    /// # Errors
    ///
    /// Returns an error when the current stack is not create/open or the FILE_OBJECT is already
    /// initialized.
    fn decode(request: PendingIrpLease<'a>) -> Result<Self, crate::kernel::status::DriverError> {
        let target = request.target();
        let stack = target.current_stack()?.create()?;
        let file_object = UninitializedFileObject::decode(stack.file_object())?;
        Ok(Self {
            request,
            parameters: stack.parameters(),
            file_object,
        })
    }

    /// Returns the dispatch target carrying create-time auxiliary buffers.
    const fn target(&self) -> DispatchTarget {
        self.request.target()
    }

    /// Returns the mounted device receiving the create.
    const fn device(&self) -> KernelDevice {
        self.request.target().device()
    }

    /// Returns the file object to initialize.
    const fn file_object(&self) -> UninitializedFileObject {
        self.file_object
    }

    /// Returns decoded create parameters.
    const fn parameters(&self) -> CreateParameters {
        self.parameters
    }
}

/// Opens or creates an ext4 object from a volume-root or opened-directory path.
/// # Errors
///
/// Returns an error when EA create input is supplied, the device is not mounted, path resolution
/// fails, or the selected open/create disposition cannot be satisfied.
async fn open_or_create(request: CreateRequest<'_>) -> DriverResult<CreateCompletion> {
    let create_ea = CreateEa::decode(request.target(), request.parameters().ea_length())?;
    let Some(mounted_volume) = MountedVolumeDevice::vcb(request.device()) else {
        return Err(DriverError::InvalidDeviceRequest);
    };
    let disposition = request.parameters().disposition();
    let target = CreateTargetSpecifier::decode(
        request.file_object(),
        mounted_volume,
        request.parameters().name_interpretation(),
        disposition,
    )?;
    let mut operations = unsafe {
        // SAFETY: Create requests are queued through the mounted-device executor, which polls one
        // active filesystem operation at a time and therefore grants this request the unique lane.
        VolumeControlBlock::claim_operation_lane(mounted_volume)
    };
    match resolve_target(
        target,
        operations.lane_mut(),
        request.parameters().reparse_point_mode(),
    )
    .await?
    {
        CreateTargetLookup::Existing {
            node,
            node_mode,
            location,
        } => {
            let mounted_volume = MountedVolumeDevice::vcb(request.device())
                .ok_or(DriverError::InvalidDeviceRequest)?;
            open_existing_node(
                request,
                mounted_volume,
                disposition,
                node,
                node_mode,
                location,
            )
            .map(CreateCompletion::Handle)
        }
        CreateTargetLookup::Missing { parent, name } => create_missing_node(
            request,
            create_ea,
            &mut operations,
            disposition,
            parent,
            &name,
        )
        .await
        .map(CreateCompletion::Handle),
        CreateTargetLookup::ReparseSymlink {
            point,
            unparsed_path,
        } => create_symlink_reparse_completion(operations.lane_mut(), point, unparsed_path).await,
    }
}

/// Builds the ownership-bearing completion for a reparse point encountered during create lookup.
/// # Errors
///
/// Returns an error when the node target cannot be converted to the Windows symbolic-link wire
/// form, its exact output buffer cannot be allocated, or packing violates the derived size.
async fn create_symlink_reparse_completion(
    operations: &mut VolumeOperationLane,
    point: NodeSymlinkReparsePoint,
    unparsed_path: UnparsedPathLength,
) -> DriverResult<CreateCompletion> {
    let data = point.into_symlink_data(operations).await?;
    let required_length = data.required_length()?;
    let buffer = CreateSymlinkReparseBuffer::try_pack_exact(required_length, |output| {
        data.pack_create_redirect(unparsed_path, output)
    })?;
    Ok(CreateCompletion::ReparseSymlink(buffer))
}

/// Fully decoded create target that contains no raw FILE_OBJECT or VCB reference.
#[derive(Debug, Eq, PartialEq)]
enum CreateTargetSpecifier {
    /// A Windows path anchored at the mounted root or a related opened directory.
    Path {
        /// Owned validated path components.
        name: CreatePathName,
        /// Validated directory where lookup begins.
        anchor: CreatePathAnchor,
    },
    /// A stable Windows file index supplied through FILE_OPEN_BY_FILE_ID.
    FileReference(CreateFileReference),
}

impl CreateTargetSpecifier {
    /// Decodes every pointer-bearing create-name boundary before asynchronous volume access begins.
    /// # Errors
    ///
    /// Returns an error when the path, related object, or file reference is malformed, or when the
    /// requested disposition is not valid for a file-reference open.
    fn decode(
        file_object: UninitializedFileObject,
        mounted_volume: NonNull<VolumeControlBlock>,
        interpretation: CreateNameInterpretation,
        disposition: CreateDisposition,
    ) -> DriverResult<Self> {
        let file_object = unsafe {
            // SAFETY: The uninitialized FILE_OBJECT belongs to the active create stack and this
            // synchronous decoder only reads immutable name and related-object fields.
            file_object.as_ref()
        };
        match interpretation {
            CreateNameInterpretation::Path => {
                let name = CreatePathName::decode(file_object)?;
                let anchor = CreatePathAnchor::decode(file_object, mounted_volume, name.rooting())?;
                Ok(Self::Path { name, anchor })
            }
            CreateNameInterpretation::FileReference => {
                validate_file_reference_create(disposition)?;
                Ok(Self::FileReference(CreateFileReference::decode(
                    file_object,
                )?))
            }
        }
    }
}

/// Result of resolving a create target against the mounted volume.
#[derive(Debug, Eq, PartialEq)]
enum CreateTargetLookup {
    /// The requested target already exists.
    Existing {
        /// Opened ext4 node.
        node: NodeId,
        /// Handle interpretation selected while resolving reparse state.
        node_mode: OpenedNodeMode,
        /// Opened location identity.
        location: OpenedLocation,
    },
    /// The final path component is absent under an existing parent directory.
    Missing {
        /// Parent directory inode.
        parent: DirectoryNodeId,
        /// New ext4 child name.
        name: Ext4Name,
    },
    /// Name resolution encountered a reparse point that Windows must process.
    ReparseSymlink {
        /// Reparse metadata captured from the encountered node.
        point: NodeSymlinkReparsePoint,
        /// UTF-16 byte length of the name suffix not consumed by this filesystem.
        unparsed_path: UnparsedPathLength,
    },
}

/// Per-handle policy decoded from one create/open request.
#[derive(Clone, Copy, Debug)]
struct CreateHandlePolicy {
    /// Access explicitly requested for the returned handle.
    desired_access: DesiredAccess,
    /// Virtual access used only to preflight an existing-object operation.
    existing_operation_access: ExistingOperationAccess,
    /// Share mask used for Windows share-access accounting.
    share_access: ShareAccess,
    /// Write completion durability requested by create options.
    write_commitment: WriteCommitment,
    /// Data transfer buffering policy stored on the opened handle.
    data_transfer_mode: DataTransferMode,
    /// Regular-file write authority retained by the per-handle state.
    regular_file_write_access: RegularFileWriteAccess,
    /// FILE_OBJECT flags projected from create options.
    file_object_flags: CreateFileObjectFlags,
}

impl CreateHandlePolicy {
    /// Projects handle policy fields from decoded create parameters.
    /// # Errors
    ///
    /// Returns an error when requested transfer buffering cannot be satisfied by the mounted device.
    fn from_parameters(parameters: CreateParameters, device: KernelDevice) -> DriverResult<Self> {
        let file_object_flags = CreateFileObjectFlags::from_parameters(parameters);
        Ok(Self {
            desired_access: parameters.desired_access(),
            existing_operation_access: parameters.existing_operation_access(),
            share_access: parameters.share_access(),
            write_commitment: parameters.write_commitment(),
            data_transfer_mode: match parameters.transfer_buffering() {
                CreateTransferBuffering::IntermediateAllowed => {
                    DataTransferMode::IntermediateAllowed
                }
                CreateTransferBuffering::NoIntermediate => {
                    DataTransferMode::NoIntermediate(NoIntermediateTransfer::from_device(device)?)
                }
            },
            regular_file_write_access: parameters.desired_access().regular_file_write_access(),
            file_object_flags,
        })
    }

    /// Returns access explicitly requested for the returned handle.
    const fn desired_access(self) -> DesiredAccess {
        self.desired_access
    }

    /// Returns virtual access that existing handles must share for this operation.
    const fn existing_operation_access(self) -> ExistingOperationAccess {
        self.existing_operation_access
    }

    /// Returns the share access mask.
    const fn share_access(self) -> ShareAccess {
        self.share_access
    }

    /// Returns write completion durability.
    const fn write_commitment(self) -> WriteCommitment {
        self.write_commitment
    }

    /// Returns data transfer buffering policy.
    const fn data_transfer_mode(self) -> DataTransferMode {
        self.data_transfer_mode
    }

    /// Returns the regular-file write authority selected by desired access.
    const fn regular_file_write_access(self) -> RegularFileWriteAccess {
        self.regular_file_write_access
    }

    /// Returns FILE_OBJECT flags projected from create options.
    const fn file_object_flags(self) -> CreateFileObjectFlags {
        self.file_object_flags
    }
}

/// FILE_OBJECT flags selected by create options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateFileObjectFlags {
    /// Raw WDK `FILE_OBJECT::Flags` bits.
    raw: wdk_sys::ULONG,
}

impl CreateFileObjectFlags {
    /// Projects FILE_OBJECT flags from decoded create parameters.
    const fn from_parameters(parameters: CreateParameters) -> Self {
        let mut raw = 0;
        if matches!(parameters.write_commitment(), WriteCommitment::FlushThrough) {
            raw |= wdk_sys::FO_WRITE_THROUGH;
        }
        if matches!(
            parameters.transfer_buffering(),
            CreateTransferBuffering::NoIntermediate
        ) {
            raw |= wdk_sys::FO_NO_INTERMEDIATE_BUFFERING;
        }
        match parameters.synchronization_mode() {
            CreateSynchronizationMode::Asynchronous => {}
            CreateSynchronizationMode::SynchronousAlert => {
                raw |= wdk_sys::FO_SYNCHRONOUS_IO | wdk_sys::FO_ALERTABLE_IO;
            }
            CreateSynchronizationMode::SynchronousNonAlert => {
                raw |= wdk_sys::FO_SYNCHRONOUS_IO;
            }
        }
        Self { raw }
    }

    /// Applies the selected flags to the FILE_OBJECT being opened.
    fn apply_to(self, file_object: &mut FILE_OBJECT) {
        file_object.Flags |= self.raw;
    }
}

/// File reference decoded from FILE_OPEN_BY_FILE_ID input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateFileReference {
    /// Windows-facing stable file index.
    file_index: u32,
}

impl CreateFileReference {
    /// Decodes an 8-byte Windows file reference from FILE_OBJECT::FileName.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT name is absent, malformed, or uses an unsupported
    /// object-id/prefixed file-reference form.
    fn decode(file_object: &FILE_OBJECT) -> DriverResult<Self> {
        let name = file_object.FileName;
        let byte_len = usize::from(name.Length);
        if byte_len == 0 || name.Buffer.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        let bytes = unsafe {
            // SAFETY: UNICODE_STRING Length is a byte length and Buffer is non-null for the
            // requested binary file-reference payload.
            core::slice::from_raw_parts(name.Buffer.cast::<u8>(), byte_len)
        };
        match byte_len {
            8 => Self::from_wire_file_reference(
                <[u8; 8]>::try_from(bytes).map_err(|_| DriverError::InvalidParameter)?,
            ),
            16 => Err(DriverError::NotSupported),
            _ => Err(DriverError::NotSupported),
        }
    }

    /// Builds a file reference from the Windows wire file reference.
    /// # Errors
    ///
    /// Returns an error when the file reference cannot fit the ext4win file-index domain.
    fn from_wire_file_reference(reference: [u8; 8]) -> DriverResult<Self> {
        let file_index = u32::try_from(u64::from_le_bytes(reference))
            .map_err(|_| DriverError::InvalidParameter)?;
        if file_index == 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { file_index })
    }

    /// Returns the referenced file index.
    const fn file_index(self) -> u32 {
        self.file_index
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
    components: DriverVec<CreatePathComponent>,
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
    fn components(&self) -> &[CreatePathComponent] {
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

/// One validated Windows path component and the suffix remaining after it.
#[derive(Debug, Eq, PartialEq)]
struct CreatePathComponent {
    /// Namespace name used for lookup in the current parent directory.
    name: WindowsName,
    /// Original FILE_OBJECT name suffix beginning with the following separator.
    unparsed_path: UnparsedPathLength,
}

impl CreatePathComponent {
    /// Returns the component name used for namespace lookup.
    const fn name(&self) -> &WindowsName {
        &self.name
    }

    /// Returns the suffix that remains after this component is consumed.
    const fn unparsed_path(&self) -> UnparsedPathLength {
        self.unparsed_path
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
        /// Related directory location identity.
        location: OpenedLocation,
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
        Self::from_related_opened_directory(
            vcb,
            opened.volume(),
            opened.node(),
            opened.node_mode(),
            opened.location(),
        )
    }

    /// Builds a relative-path anchor from an already decoded related object.
    /// # Errors
    ///
    /// Returns an error when the related object belongs to another volume, is a reparse-point
    /// handle, or does not identify a directory.
    fn from_related_opened_directory(
        target_volume: NonNull<VolumeControlBlock>,
        related_volume: NonNull<VolumeControlBlock>,
        node: NodeId,
        node_mode: OpenedNodeMode,
        location: &OpenedLocation,
    ) -> DriverResult<Self> {
        if related_volume != target_volume {
            return Err(DriverError::InvalidDeviceRequest);
        }
        if node_mode == OpenedNodeMode::ReparsePoint {
            return Err(DriverError::NotSupported);
        }
        let NodeId::Directory(id) = node else {
            return Err(DriverError::ObjectTypeMismatch);
        };
        Ok(Self::OpenedDirectory {
            id,
            location: location.try_to_owned_location()?,
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
    fn existing_directory(self) -> CreateTargetLookup {
        match self {
            Self::VolumeRoot => CreateTargetLookup::Existing {
                node: NodeId::Directory(DirectoryNodeId::ROOT),
                node_mode: OpenedNodeMode::Direct,
                location: OpenedLocation::Root,
            },
            Self::OpenedDirectory { id, location } => CreateTargetLookup::Existing {
                node: NodeId::Directory(id),
                node_mode: OpenedNodeMode::Direct,
                location,
            },
        }
    }
}

/// Opens an existing path according to the requested disposition and options.
/// # Errors
///
/// Returns an error when existing-node options conflict, create-only disposition collides, share
/// access fails, or an incomplete destructive disposition is requested.
fn open_existing_node(
    request: CreateRequest<'_>,
    vcb: NonNull<crate::state::VolumeControlBlock>,
    disposition: CreateDisposition,
    node: NodeId,
    node_mode: OpenedNodeMode,
    location: OpenedLocation,
) -> DriverResult<CreateAction> {
    let parameters = request.parameters();
    let policy = CreateHandlePolicy::from_parameters(parameters, request.device())?;
    match disposition {
        CreateDisposition::Open | CreateDisposition::OpenIf => {
            validate_existing_node_options(node, parameters.target_requirement())?;
            initialize_file_object(
                request.file_object(),
                vcb,
                node,
                node_mode,
                location,
                policy,
            )?;
            Ok(CreateAction::Opened)
        }
        CreateDisposition::Create => Err(DriverError::ObjectNameCollision),
        CreateDisposition::Overwrite | CreateDisposition::OverwriteIf => {
            validate_existing_node_options(node, parameters.target_requirement())?;
            match node {
                NodeId::Directory(directory) => Err(destructive_directory_error(directory)),
                NodeId::File(_) | NodeId::Symlink(_) => Err(DriverError::NotSupported),
            }
        }
        CreateDisposition::Supersede => {
            validate_existing_node_options(node, parameters.target_requirement())?;
            match node {
                NodeId::Directory(directory) => Err(destructive_directory_error(directory)),
                NodeId::File(_) | NodeId::Symlink(_) => Err(DriverError::NotSupported),
            }
        }
    }
}

/// Returns the exact Windows error for a destructive create against a directory.
fn destructive_directory_error(directory: DirectoryNodeId) -> DriverError {
    if directory == DirectoryNodeId::ROOT {
        DriverError::AccessDenied
    } else {
        DriverError::ObjectNameCollision
    }
}

/// Creates a missing final path component.
/// # Errors
///
/// Returns an error when the disposition requires an existing name, missing-child creation cannot
/// be staged or committed, or the new file object cannot be initialized.
async fn create_missing_node(
    request: CreateRequest<'_>,
    create_ea: CreateEa,
    operations: &mut VolumeOperationLease,
    disposition: CreateDisposition,
    parent: DirectoryNodeId,
    name: &Ext4Name,
) -> DriverResult<CreateAction> {
    let parameters = request.parameters();
    let policy = CreateHandlePolicy::from_parameters(parameters, request.device())?;
    match disposition {
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {}
        CreateDisposition::Open => return Err(DriverError::ObjectNameNotFound),
        CreateDisposition::Overwrite => return Err(DriverError::ObjectNameNotFound),
    }

    let location = OpenedLocation::try_directory_entry(parent, name)?;
    let target = child_creation_target(parameters.target_requirement())?;
    let mut creation = operations
        .begin_child_creation(
            parent,
            name,
            target,
            crate::kernel::time::current_ext4_timestamp()?,
        )
        .await?;
    let node = creation.node();
    let notification =
        DirectoryNameChange::new(parent, name, node, DirectoryNameChangeAction::Added)?;
    let handle = memory::boxed_try_with(|| {
        Ok(OpenedHandle::new(
            node,
            OpenedNodeMode::Direct,
            location,
            policy.write_commitment(),
            policy.data_transfer_mode(),
            policy.regular_file_write_access(),
        ))
    })?;
    create_ea.apply_to_pending_child(&mut creation).await?;
    let attachment = open_pending_child_file_control_block(
        &creation,
        request.file_object(),
        policy.desired_access(),
        policy.share_access(),
    )?;

    match creation.commit().await {
        Ok(()) => {
            let Some(vcb) = MountedVolumeDevice::vcb(request.device()) else {
                return Err(DriverError::InternalInvariantViolation);
            };
            attachment.attach(handle, policy.file_object_flags());
            let vcb = unsafe {
                // SAFETY: The mounted device still owns this heap-stable VCB while its create IRP
                // is active; notification state is disjoint from the actor-owned operation lane.
                vcb.as_ref()
            };
            vcb.report_directory_name_change(notification);
            Ok(CreateAction::Created)
        }
        Err(error) => Err(error),
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
            return Err(DriverError::NotADirectory);
        }
        CreateTargetRequirement::NonDirectory if matches!(node, NodeId::Directory(_)) => {
            return Err(DriverError::FileIsDirectory);
        }
        CreateTargetRequirement::Directory | CreateTargetRequirement::NonDirectory => {}
    }
    Ok(())
}

/// Resolves a create target to an existing node or missing path leaf.
/// # Errors
///
/// Returns an error when path or file-reference resolution fails.
async fn resolve_target(
    target: CreateTargetSpecifier,
    operations: &mut VolumeOperationLane,
    reparse_point_mode: CreateReparsePointMode,
) -> DriverResult<CreateTargetLookup> {
    match target {
        CreateTargetSpecifier::Path { name, anchor } => {
            resolve_path(name, anchor, operations, reparse_point_mode).await
        }
        CreateTargetSpecifier::FileReference(reference) => {
            resolve_file_reference(reference, operations, reparse_point_mode).await
        }
    }
}

/// Validates create semantics for FILE_OPEN_BY_FILE_ID.
/// # Errors
///
/// Returns an error when the request needs a parent/name namespace target that file-reference opens
/// do not provide.
fn validate_file_reference_create(disposition: CreateDisposition) -> DriverResult<()> {
    match disposition {
        CreateDisposition::Open => {}
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::Overwrite
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => return Err(DriverError::InvalidParameter),
    }
    Ok(())
}

/// Resolves an 8-byte file reference to an existing typed node.
/// # Errors
///
/// Returns an error when the file-reference name is malformed or no live inode exists for it.
async fn resolve_file_reference(
    reference: CreateFileReference,
    operations: &mut VolumeOperationLane,
    reparse_point_mode: CreateReparsePointMode,
) -> DriverResult<CreateTargetLookup> {
    let node = operations
        .journaled_mut()
        .load_node_by_file_index(reference.file_index())
        .await
        .map_err(file_reference_lookup_error)?;
    resolve_final_node(
        operations,
        node,
        OpenedLocation::FileReference,
        reparse_point_mode,
        UnparsedPathLength::ZERO,
    )
    .await
}

/// Maps file-reference lookup failures to create/open status.
fn file_reference_lookup_error(error: ext4_core::Error) -> DriverError {
    match error {
        ext4_core::Error::InvalidInode => DriverError::ObjectNameNotFound,
        _ => DriverError::from(error),
    }
}

/// Resolves a root-relative Windows path to an existing node or missing leaf.
/// # Errors
///
/// Returns an error when relative FILE_OBJECT opens are requested, a path component is invalid, an
/// intermediate component is missing or not a directory, or lookup fails.
async fn resolve_path(
    name: CreatePathName,
    anchor: CreatePathAnchor,
    operations: &mut VolumeOperationLane,
    reparse_point_mode: CreateReparsePointMode,
) -> DriverResult<CreateTargetLookup> {
    let mut parent_id = anchor.directory();
    let components = name.components();
    let mut components = components.iter().peekable();
    while let Some(component) = components.next() {
        let position = if components.peek().is_none() {
            PathComponentPosition::Final
        } else {
            PathComponentPosition::Intermediate
        };
        let parent = match operations.journaled_mut().load_directory(parent_id).await {
            Ok(directory) => directory,
            Err(error) => return Err(DriverError::from(error)),
        };
        let child = match operations
            .journaled_mut()
            .lookup_windows_child(&parent, component.name())
            .await
        {
            Ok(ChildLookup::Found(child)) => child,
            Ok(ChildLookup::NotFound) if position == PathComponentPosition::Final => {
                return Ok(CreateTargetLookup::Missing {
                    parent: parent_id,
                    name: component.name().to_ext4()?,
                });
            }
            Ok(ChildLookup::NotFound) => return Err(DriverError::ObjectPathNotFound),
            Err(error) => return Err(DriverError::from(error)),
        };
        let child_node = *child.node();
        let reparse_point = NodeSymlinkReparsePoint::load(operations, child_node).await?;
        if let Some(point) = reparse_point {
            match reparse_point_encounter(position, reparse_point_mode) {
                ReparsePointEncounter::Redirect => {
                    return Ok(CreateTargetLookup::ReparseSymlink {
                        point,
                        unparsed_path: component.unparsed_path(),
                    });
                }
                ReparsePointEncounter::OpenFinal => {
                    return Ok(CreateTargetLookup::Existing {
                        node: child_node,
                        node_mode: OpenedNodeMode::ReparsePoint,
                        location: OpenedLocation::try_directory_entry(
                            child.parent(),
                            child.name(),
                        )?,
                    });
                }
            }
        }
        if position == PathComponentPosition::Final {
            return Ok(CreateTargetLookup::Existing {
                node: child_node,
                node_mode: OpenedNodeMode::Direct,
                location: OpenedLocation::try_directory_entry(child.parent(), child.name())?,
            });
        }
        let NodeId::Directory(directory_id) = child_node else {
            return Err(DriverError::ObjectPathNotFound);
        };
        parent_id = directory_id;
    }

    Ok(anchor.existing_directory())
}

/// Position of one component in the original create name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathComponentPosition {
    /// More path remains after this component.
    Intermediate,
    /// This is the final component supplied by the caller.
    Final,
}

/// Action required after a reparse point is encountered during path resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReparsePointEncounter {
    /// Return reparse data to the I/O Manager without opening an FCB/CCB.
    Redirect,
    /// Open the final reparse-point node itself.
    OpenFinal,
}

/// Selects Windows reparse behavior for one encountered path component.
const fn reparse_point_encounter(
    position: PathComponentPosition,
    mode: CreateReparsePointMode,
) -> ReparsePointEncounter {
    match (position, mode) {
        (PathComponentPosition::Intermediate, _)
        | (PathComponentPosition::Final, CreateReparsePointMode::ResolveFinalTarget) => {
            ReparsePointEncounter::Redirect
        }
        (PathComponentPosition::Final, CreateReparsePointMode::OpenFinalReparsePoint) => {
            ReparsePointEncounter::OpenFinal
        }
    }
}

/// Resolves one existing final node after applying reparse-point create semantics.
/// # Errors
///
/// Returns an error when reparse metadata cannot be loaded.
async fn resolve_final_node(
    operations: &mut VolumeOperationLane,
    node: NodeId,
    location: OpenedLocation,
    reparse_point_mode: CreateReparsePointMode,
    unparsed_path: UnparsedPathLength,
) -> DriverResult<CreateTargetLookup> {
    let Some(point) = NodeSymlinkReparsePoint::load(operations, node).await? else {
        return Ok(CreateTargetLookup::Existing {
            node,
            node_mode: OpenedNodeMode::Direct,
            location,
        });
    };
    match reparse_point_encounter(PathComponentPosition::Final, reparse_point_mode) {
        ReparsePointEncounter::Redirect => Ok(CreateTargetLookup::ReparseSymlink {
            point,
            unparsed_path,
        }),
        ReparsePointEncounter::OpenFinal => Ok(CreateTargetLookup::Existing {
            node,
            node_mode: OpenedNodeMode::ReparsePoint,
            location,
        }),
    }
}

/// Splits non-root path units into validated Windows components.
/// # Errors
///
/// Returns an error when any component is empty or not representable in the Windows namespace
/// domain.
fn path_components(units: &[u16]) -> DriverResult<DriverVec<CreatePathComponent>> {
    if units.is_empty() {
        return Ok(DriverVec::new());
    }
    let mut components = DriverVec::new();
    let mut remaining = units;
    loop {
        let separator = remaining.iter().position(|unit| *unit == UTF16_BACKSLASH);
        let (component, suffix) = match separator {
            Some(index) => remaining
                .split_at_checked(index)
                .ok_or(DriverError::InvalidParameter)?,
            None => (remaining, &[][..]),
        };
        components
            .try_push_owned(CreatePathComponent {
                name: WindowsName::from_utf16(component)?,
                unparsed_path: UnparsedPathLength::from_utf16_suffix(suffix)?,
            })
            .map_err(|error| error.into_parts().0)?;
        if suffix.is_empty() {
            break;
        }
        let next = suffix
            .strip_prefix(&[UTF16_BACKSLASH])
            .ok_or(DriverError::InternalInvariantViolation)?;
        if next.is_empty() {
            break;
        }
        remaining = next;
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
    node_mode: OpenedNodeMode,
    location: OpenedLocation,
    policy: CreateHandlePolicy,
) -> DriverResult<()> {
    let handle = memory::boxed_try_with(|| {
        Ok(OpenedHandle::new(
            node,
            node_mode,
            location,
            policy.write_commitment(),
            policy.data_transfer_mode(),
            policy.regular_file_write_access(),
        ))
    })?;
    let fcb = open_shared_file_control_block(
        file_object,
        vcb,
        node,
        policy.desired_access(),
        policy.existing_operation_access(),
        policy.share_access(),
    )?;
    attach_preallocated_file_object(file_object, fcb, handle, policy.file_object_flags());
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
    existing_operation_access: ExistingOperationAccess,
    share_access: ShareAccess,
) -> DriverResult<NonNull<FileControlBlock>> {
    VolumeControlBlock::open_existing_file_control_block(
        vcb,
        node,
        file_object.kernel_file_object(),
        desired_access,
        existing_operation_access,
        share_access,
    )
}

/// Opens the staged child FCB and records the create share-access claim before commit.
/// # Errors
///
/// Returns an error when FCB creation fails or Windows share-access checking rejects the new handle.
fn open_pending_child_file_control_block(
    creation: &PendingChildCreation<'_>,
    file_object: UninitializedFileObject,
    desired_access: DesiredAccess,
    share_access: ShareAccess,
) -> DriverResult<PendingFileObjectAttachment> {
    let fcb = creation.open_file_control_block(
        file_object.kernel_file_object(),
        desired_access,
        share_access,
    )?;
    Ok(PendingFileObjectAttachment {
        fcb: Some(fcb),
        file_object,
    })
}

/// Pre-attachment share/FCB claim that rolls back unless a committed create consumes it.
struct PendingFileObjectAttachment {
    /// FCB reference and share claim owned until attachment.
    fcb: Option<NonNull<FileControlBlock>>,
    /// Uninitialized FILE_OBJECT whose pending create IRP keeps it alive.
    file_object: UninitializedFileObject,
}

// SAFETY: This value exclusively owns one pre-attachment FCB reference and share claim. The create
// request's pending IRP pins the FILE_OBJECT, and the VCB ledger allocation remains stable while
// that reference exists. Moving ownership between serialized executor workers creates no alias.
unsafe impl Send for PendingFileObjectAttachment {}

impl PendingFileObjectAttachment {
    /// Consumes the pending claim into one successfully committed FILE_OBJECT attachment.
    fn attach(mut self, handle: Box<OpenedHandle>, flags: CreateFileObjectFlags) {
        let fcb = self.fcb.take().unwrap_or_else(|| {
            crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                .bugcheck()
        });
        attach_preallocated_file_object(self.file_object, fcb, handle, flags);
    }
}

impl Drop for PendingFileObjectAttachment {
    fn drop(&mut self) {
        if let Some(fcb) = self.fcb.take() {
            abandon_file_control_block(fcb, self.file_object.kernel_file_object());
        }
    }
}

/// Stores already-opened FCB and preallocated CCB context pointers in the FILE_OBJECT.
fn attach_preallocated_file_object(
    file_object: UninitializedFileObject,
    fcb: NonNull<FileControlBlock>,
    handle: Box<OpenedHandle>,
    file_object_flags: CreateFileObjectFlags,
) {
    let file_object = unsafe {
        // SAFETY: `file_object` comes from the active create stack and is
        // writable during successful create processing.
        file_object.as_mut()
    };
    file_object_flags.apply_to(file_object);
    file_object.FsContext = fcb.as_ptr().cast::<c_void>();
    file_object.FsContext2 = Box::into_raw(handle).cast::<c_void>();
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FILE_OPEN_DISPOSITION_OPTIONS: wdk_sys::ULONG = 1 << 24;

    /// Decodes create parameters through the dispatch boundary.
    /// # Errors
    ///
    /// Returns an error when the fixed test stack cannot be decoded as a create/open request.
    fn decoded_create_parameters(
        options: wdk_sys::ULONG,
        desired_access: wdk_sys::ACCESS_MASK,
    ) -> DriverResult<CreateParameters> {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut irp = wdk_sys::IRP::default();
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
            DesiredAccess: desired_access,
            ..wdk_sys::IO_SECURITY_CONTEXT::default()
        };
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::addr_of_mut!(security_context),
            Options: TEST_FILE_OPEN_DISPOSITION_OPTIONS | options,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0,
            ShareAccess: 0,
            __bindgen_padding_1: 0,
            EaLength: 0,
        };
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack);

        Ok(DispatchTarget::decode(
            core::ptr::addr_of_mut!(device),
            core::ptr::addr_of_mut!(irp),
        )?
        .current_stack()?
        .create()?
        .parameters())
    }

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

    fn file_object_with_name_bytes(bytes: &mut [u8]) -> FILE_OBJECT {
        let Ok(byte_len) = u16::try_from(bytes.len()) else {
            return FILE_OBJECT::default();
        };
        FILE_OBJECT {
            FileName: wdk_sys::UNICODE_STRING {
                Length: byte_len,
                MaximumLength: byte_len,
                Buffer: bytes.as_mut_ptr().cast::<u16>(),
            },
            ..FILE_OBJECT::default()
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_file_object_flags_project_write_transfer_and_synchronization_modes() {
        let parameters = decoded_create_parameters(
            wdk_sys::FILE_WRITE_THROUGH
                | wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING
                | wdk_sys::FILE_SYNCHRONOUS_IO_ALERT,
            wdk_sys::FILE_READ_DATA | wdk_sys::SYNCHRONIZE,
        );
        assert!(parameters.is_ok());
        if let Ok(parameters) = parameters {
            let flags = CreateFileObjectFlags::from_parameters(parameters);

            assert_eq!(
                flags.raw,
                wdk_sys::FO_WRITE_THROUGH
                    | wdk_sys::FO_NO_INTERMEDIATE_BUFFERING
                    | wdk_sys::FO_SYNCHRONOUS_IO
                    | wdk_sys::FO_ALERTABLE_IO
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_file_object_flags_project_nonalert_synchronous_io() {
        let parameters =
            decoded_create_parameters(wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT, wdk_sys::SYNCHRONIZE);
        assert!(parameters.is_ok());
        if let Ok(parameters) = parameters {
            let flags = CreateFileObjectFlags::from_parameters(parameters);

            assert_eq!(flags.raw, wdk_sys::FO_SYNCHRONOUS_IO);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_file_object_flags_apply_preserves_existing_flags() {
        let existing = wdk_sys::FO_HANDLE_CREATED;
        let mut file_object = FILE_OBJECT {
            Flags: existing,
            ..FILE_OBJECT::default()
        };

        CreateFileObjectFlags {
            raw: wdk_sys::FO_SYNCHRONOUS_IO,
        }
        .apply_to(&mut file_object);

        assert_eq!(file_object.Flags, existing | wdk_sys::FO_SYNCHRONOUS_IO);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_file_reference_decodes_eight_byte_file_index() {
        let mut reference = u64::from(3_u32).to_le_bytes();
        let file_object = file_object_with_name_bytes(&mut reference);

        assert_eq!(
            CreateFileReference::decode(&file_object).map(CreateFileReference::file_index),
            Ok(3)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_file_reference_rejects_invalid_or_unsupported_wire_forms() {
        let mut zero = 0_u64.to_le_bytes();
        let zero_file_object = file_object_with_name_bytes(&mut zero);
        assert_eq!(
            CreateFileReference::decode(&zero_file_object),
            Err(DriverError::InvalidParameter)
        );

        let mut too_large = (u64::from(u32::MAX) + 1).to_le_bytes();
        let too_large_file_object = file_object_with_name_bytes(&mut too_large);
        assert_eq!(
            CreateFileReference::decode(&too_large_file_object),
            Err(DriverError::InvalidParameter)
        );

        let mut object_id = [0_u8; 16];
        let object_id_file_object = file_object_with_name_bytes(&mut object_id);
        assert_eq!(
            CreateFileReference::decode(&object_id_file_object),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_reference_create_accepts_only_existing_opens() {
        assert_eq!(
            validate_file_reference_create(CreateDisposition::Open),
            Ok(())
        );
        assert_eq!(
            validate_file_reference_create(CreateDisposition::Create),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            validate_file_reference_create(CreateDisposition::OpenIf),
            Err(DriverError::InvalidParameter)
        );
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
                absolute
                    .components()
                    .first()
                    .map(CreatePathComponent::name)
                    .map(WindowsName::utf16),
                Some([u16::from(b'd'), u16::from(b'i'), u16::from(b'r')].as_slice())
            );
            assert_eq!(
                absolute
                    .components()
                    .get(1)
                    .map(CreatePathComponent::name)
                    .map(WindowsName::utf16),
                Some([u16::from(b'f')].as_slice())
            );
            assert_eq!(
                absolute
                    .components()
                    .first()
                    .map(CreatePathComponent::unparsed_path),
                UnparsedPathLength::from_utf16_suffix(&[UTF16_BACKSLASH, u16::from(b'f')]).ok()
            );
            assert_eq!(
                absolute
                    .components()
                    .get(1)
                    .map(CreatePathComponent::unparsed_path),
                Some(UnparsedPathLength::ZERO)
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
                relative
                    .components()
                    .first()
                    .map(CreatePathComponent::name)
                    .map(WindowsName::utf16),
                Some([u16::from(b'c'), u16::from(b'h'), u16::from(b'i')].as_slice())
            );
            assert_eq!(
                relative
                    .components()
                    .first()
                    .map(CreatePathComponent::unparsed_path),
                Some(UnparsedPathLength::ZERO)
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
    /// Panics when each parsed component does not retain exactly the suffix following that
    /// component in the original create name.
    #[test]
    fn create_path_components_retain_component_specific_unparsed_suffixes() {
        let mut units = [
            u16::from(b'a'),
            UTF16_BACKSLASH,
            u16::from(b'b'),
            UTF16_BACKSLASH,
            u16::from(b'c'),
            UTF16_BACKSLASH,
        ];
        let file_object = file_object_with_name(&mut units);
        let path = CreatePathName::decode(&file_object);
        assert!(path.is_ok());
        let Ok(path) = path else {
            return;
        };

        let expected = [
            UnparsedPathLength::from_utf16_suffix(&[
                UTF16_BACKSLASH,
                u16::from(b'b'),
                UTF16_BACKSLASH,
                u16::from(b'c'),
                UTF16_BACKSLASH,
            ]),
            UnparsedPathLength::from_utf16_suffix(&[
                UTF16_BACKSLASH,
                u16::from(b'c'),
                UTF16_BACKSLASH,
            ]),
            UnparsedPathLength::from_utf16_suffix(&[UTF16_BACKSLASH]),
        ];
        assert_eq!(path.components().len(), expected.len());
        for (component, expected_suffix) in path.components().iter().zip(expected) {
            assert_eq!(Ok(component.unparsed_path()), expected_suffix);
        }
    }

    /// # Panics
    ///
    /// Panics when intermediate and final reparse encounters do not follow Windows create
    /// semantics.
    #[test]
    fn reparse_encounters_redirect_intermediate_and_respect_final_open_mode() {
        for mode in [
            CreateReparsePointMode::ResolveFinalTarget,
            CreateReparsePointMode::OpenFinalReparsePoint,
        ] {
            assert_eq!(
                reparse_point_encounter(PathComponentPosition::Intermediate, mode),
                ReparsePointEncounter::Redirect
            );
        }
        assert_eq!(
            reparse_point_encounter(
                PathComponentPosition::Final,
                CreateReparsePointMode::ResolveFinalTarget,
            ),
            ReparsePointEncounter::Redirect
        );
        assert_eq!(
            reparse_point_encounter(
                PathComponentPosition::Final,
                CreateReparsePointMode::OpenFinalReparsePoint,
            ),
            ReparsePointEncounter::OpenFinal
        );
    }

    /// # Panics
    ///
    /// Panics when destructive directory errors lose target-option or root distinctions.
    #[test]
    fn destructive_create_rejects_root_and_non_directory_targets_with_exact_status() {
        let directory = NodeId::Directory(DirectoryNodeId::ROOT);
        assert_eq!(
            destructive_directory_error(DirectoryNodeId::ROOT),
            DriverError::AccessDenied
        );
        assert_eq!(
            validate_existing_node_options(directory, CreateTargetRequirement::NonDirectory),
            Err(DriverError::FileIsDirectory)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_path_anchor_accepts_opened_relative_directory() {
        let vcb = NonNull::<VolumeControlBlock>::dangling();
        let anchor = CreatePathAnchor::from_related_opened_directory(
            vcb,
            vcb,
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedNodeMode::Direct,
            &OpenedLocation::Root,
        );
        assert_eq!(
            anchor,
            Ok(CreatePathAnchor::OpenedDirectory {
                id: DirectoryNodeId::ROOT,
                location: OpenedLocation::Root,
            })
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_path_anchor_rejects_conflicting_absolute_related_object() {
        let vcb = NonNull::<VolumeControlBlock>::dangling();
        let mut related = FILE_OBJECT::default();
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
