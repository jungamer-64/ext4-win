//! Create/open dispatch and FILE_OBJECT context initialization.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::num::NonZeroU32;
use core::ptr::NonNull;

use ext4_core::{ChildLookup, CommittedReadPass, DirectoryNodeId, Ext4Name, NodeId, WindowsName};
use wdk_sys::FILE_OBJECT;

use crate::{
    irp::{
        AtomicOplockReservation, CreateAction, CreateCompletion, CreateDeletion, CreateDisposition,
        CreateNameInterpretation, CreateParameters, CreateReparsePointMode,
        CreateSymlinkReparseBuffer, CreateSynchronizationMode, CreateTargetRequirement,
        CreateTransferBuffering, ExistingOperationAccess, GrantedAccess, NamespaceOplockPlan,
        NamespaceParentOplockEffect, PendingIrpLease, RegularFileWriteAccess, ShareAccess,
    },
    kernel::status::{DriverError, DriverResult, STATUS_RETRY},
    memory::{self, DriverVec},
    request::{
        ea::CreateEa,
        metadata,
        reparse::{NodeSymlinkReparsePoint, UnparsedPathLength},
        security::CreateSecurityDescriptor,
    },
    state::{
        ChildCreationTarget, CommittedNodeStreamMetadata, DataTransferMode, DirectoryChange,
        DirectoryChangeAction, ExistingStreamResidency, FileControlBlock, HandleDeletion,
        KernelDevice, KernelFileObject, MountedVolumeAccess, NoIntermediateTransfer,
        NodeStreamMetadata, OpenedHandle, OpenedLocation, OpenedNodeMode, OpenedObject,
        OpenedVolumeHandle, PendingChildCreation, PendingFileDeletion, PreparedStreamWriteOpen,
        RawVolumeAccess, StagedNodeStreamMetadata, UninitializedFileObject, VolumeControlBlock,
        WriteCommitment, abandon_file_control_block,
    },
};

use super::DriverMutationPass;

/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Executes a decoded create/open IRP.
/// # Errors
///
/// Returns an error when create stack decoding or ext4 open/create handling rejects the request.
pub(crate) fn execute(
    request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    pending_existing: &mut Option<PendingExistingCreateOpen>,
    prepared_write_open: Option<&PreparedStreamWriteOpen>,
    namespace_oplocks: Option<NamespaceOplockPlan>,
) -> DriverResult<CreateResolution> {
    if pending_existing.is_some() {
        return resume_existing_open(
            request,
            operations,
            mutation,
            pending_existing,
            prepared_write_open,
        );
    }
    let mounted_volume = operations.file_object_owner();
    open_or_create(
        PreparedCreateRequest::decode(request, mounted_volume)?,
        mounted_volume,
        operations,
        mutation,
        pending_existing,
        namespace_oplocks,
    )
}

/// Driver-visible result of one restartable create resolve pass.
#[derive(Debug)]
pub(crate) enum CreateResolution {
    /// No filesystem mutation was staged and the create may complete immediately.
    Complete(CreateCompletion),
    /// A resident regular-file write-open must flush its executable image outside the actor.
    PrepareWriteOpen {
        /// Exact FCB whose provisional share claim retains the stream.
        fcb: NonNull<FileControlBlock>,
        /// Exact regular-file inode resolved by create.
        node: NodeId,
    },
    /// An existing stream must complete its create-specific oplock conflict protocol.
    CheckOplock {
        /// Exact provisional FCB whose oplock package owns the conflict state.
        fcb: NonNull<FileControlBlock>,
        /// Normalized create behavior passed to the FsRtl boundary.
        policy: crate::irp::OplockCreatePolicy,
    },
    /// A create option requires one synchronous atomic oplock reservation before publication.
    ReserveOplock {
        /// Exact provisional FCB whose oplock package owns the reservation.
        fcb: NonNull<FileControlBlock>,
        /// User-handle count atomically admitted with this create claim.
        open_count: NonZeroU32,
    },
    /// A missing child requires parent-directory oplock authority before it can be staged.
    CheckNamespaceOplocks(NamespaceOplockPlan),
    /// A missing child was staged and every driver publication value was preallocated.
    Mutation(Box<PendingCreatePublication>),
}

/// Create request whose pointer-bearing inputs have all become owned domain values.
#[derive(Debug)]
struct PreparedCreateRequest<'a> {
    /// Completion and final FILE_OBJECT attachment authority.
    owner: CreateCompletionOwner<'a>,
    /// Fully owned namespace target.
    target: CreateTargetSpecifier,
    /// Fully owned create-time EA list.
    create_ea: CreateEa,
}

/// Completion authority retained after pointer-bearing create input decoding.
#[derive(Debug)]
struct CreateCompletionOwner<'a> {
    /// Pending IRP lease retaining every create-time pointer through terminal completion.
    request: PendingIrpLease<'a>,
    /// Owned semantic create parameters decoded before suspension.
    parameters: CreateParameters,
    /// Mounted device receiving the create.
    device: KernelDevice,
}

/// Create completion authority paired with rights proven for the exact opened object.
#[derive(Debug)]
struct AuthorizedCreateCompletionOwner<'a> {
    /// Sole FILE_OBJECT attachment and IRP completion authority.
    owner: CreateCompletionOwner<'a>,
    /// Concrete handle rights returned by the Security Reference Monitor boundary.
    granted_access: GrantedAccess,
}

impl<'a> PreparedCreateRequest<'a> {
    /// Decodes the create request from the current IRP stack.
    /// # Errors
    ///
    /// Returns an error when the stack, FILE_OBJECT, create name, related object, or EA payload is
    /// malformed.
    fn decode(
        mut request: PendingIrpLease<'a>,
        mounted_volume: NonNull<VolumeControlBlock>,
    ) -> Result<Self, crate::kernel::status::DriverError> {
        let (device, parameters, target, create_ea) = request.with_active(|active| {
            let current = active.current_stack()?;
            let file_object = current.file_object()?;
            let stack = current.create()?;
            let parameters = stack.parameters();
            parameters.validate_supported_flags()?;
            let file_object = UninitializedFileObject::decode(file_object)?;
            let device = active.device();
            Ok::<_, DriverError>((
                device,
                parameters,
                CreateTargetSpecifier::decode(
                    &file_object,
                    mounted_volume,
                    parameters.name_interpretation(),
                    parameters.disposition(),
                )?,
                CreateEa::decode(active, parameters.ea_length())?,
            ))
        })?;
        Ok(Self {
            owner: CreateCompletionOwner {
                request,
                parameters,
                device,
            },
            target,
            create_ea,
        })
    }
}

impl<'a> CreateCompletionOwner<'a> {
    /// Returns the mounted device receiving the create.
    const fn device(&self) -> KernelDevice {
        self.device
    }

    /// Returns decoded create parameters.
    const fn parameters(&self) -> CreateParameters {
        self.parameters
    }

    /// Executes one non-suspending operation at the sole uninitialized FILE_OBJECT attachment
    /// boundary.
    /// # Errors
    ///
    /// Returns an error when the active create stack or uninitialized FILE_OBJECT is invalid, or
    /// when `operation` rejects the attachment.
    fn with_file_object<R>(
        &mut self,
        operation: impl for<'view> FnOnce(UninitializedFileObject<'view>) -> DriverResult<R>,
    ) -> DriverResult<R> {
        self.request.with_active(|active| {
            let current = active.current_stack()?;
            let file_object = current.file_object()?;
            let _stack = current.create()?;
            operation(UninitializedFileObject::decode(file_object)?)
        })
    }

    /// Performs one bounded operation against the active create ACCESS_STATE.
    /// # Errors
    ///
    /// Returns malformed security-context errors or the operation's native authorization failure.
    fn with_access_state<R>(
        &mut self,
        operation: impl for<'view> FnOnce(&mut crate::irp::CreateAccessState<'view>) -> DriverResult<R>,
    ) -> DriverResult<R> {
        let policy = self.parameters.access_check();
        self.request.with_active(|active| {
            let mut state = active.create_access_state(policy)?;
            operation(&mut state)
        })
    }

    /// Checks traversal authority for one directory when SeChangeNotifyPrivilege is absent.
    /// # Errors
    ///
    /// Returns metadata/descriptor errors or denies traversal before looking up a child name.
    fn authorize_traverse(
        &mut self,
        directory: DirectoryNodeId,
        read: &mut impl CommittedReadPass,
    ) -> DriverResult<()> {
        let required = self.with_access_state(|state| Ok(state.requires_traverse_checks()))?;
        if !required {
            return Ok(());
        }
        let descriptor = CreateSecurityDescriptor::for_node(read, NodeId::Directory(directory))?;
        self.with_access_state(|state| {
            state.authorize_operation(descriptor.as_native(), wdk_sys::FILE_TRAVERSE)
        })
    }

    /// Authorizes one existing object and consumes unvalidated completion authority.
    /// # Errors
    ///
    /// Returns metadata/descriptor errors or native denial without producing attachment authority.
    fn authorize_existing(
        mut self,
        node: NodeId,
        read: &mut impl CommittedReadPass,
    ) -> DriverResult<AuthorizedCreateCompletionOwner<'a>> {
        let descriptor = CreateSecurityDescriptor::for_node(read, node)?;
        let required = self.parameters.existing_operation_required_access();
        let requested = self.parameters.desired_access();
        let granted_access = self.with_access_state(|state| {
            state.authorize_operation(descriptor.as_native(), required)?;
            state.authorize_requested(descriptor.as_native(), requested)
        })?;
        Ok(AuthorizedCreateCompletionOwner {
            owner: self,
            granted_access,
        })
    }

    /// Authorizes creation under a parent directory and consumes unvalidated authority.
    /// # Errors
    ///
    /// Returns parent metadata/descriptor errors or native creation/privilege denial before staging
    /// a namespace mutation.
    fn authorize_child_creation(
        mut self,
        parent: DirectoryNodeId,
        requirement: CreateTargetRequirement,
        read: &mut impl CommittedReadPass,
    ) -> DriverResult<AuthorizedCreateCompletionOwner<'a>> {
        let descriptor = CreateSecurityDescriptor::for_node(read, NodeId::Directory(parent))?;
        let required = match requirement {
            CreateTargetRequirement::Directory => wdk_sys::FILE_ADD_SUBDIRECTORY,
            CreateTargetRequirement::Any | CreateTargetRequirement::NonDirectory => {
                wdk_sys::FILE_ADD_FILE
            }
        };
        let requested = self.parameters.desired_access();
        let granted_access = self.with_access_state(|state| {
            state.authorize_child_creation(descriptor.as_native(), required, requested)
        })?;
        Ok(AuthorizedCreateCompletionOwner {
            owner: self,
            granted_access,
        })
    }

    /// Authorizes a target-directory open and its target-dependent namespace right.
    /// # Errors
    ///
    /// Returns metadata/descriptor errors or native denial for the parent or existing target.
    fn authorize_target_directory(
        mut self,
        directory: DirectoryNodeId,
        target: TargetDirectoryLeaf,
        requirement: CreateTargetRequirement,
        read: &mut impl CommittedReadPass,
    ) -> DriverResult<AuthorizedCreateCompletionOwner<'a>> {
        let directory_descriptor =
            CreateSecurityDescriptor::for_node(read, NodeId::Directory(directory))?;
        let target_descriptor = match target {
            TargetDirectoryLeaf::Missing => None,
            TargetDirectoryLeaf::Existing(node) => {
                Some(CreateSecurityDescriptor::for_node(read, node)?)
            }
        };
        let requested = self.parameters.desired_access();
        let granted_access = self.with_access_state(|state| {
            match target_descriptor.as_ref() {
                Some(descriptor) => {
                    state.authorize_operation(descriptor.as_native(), wdk_sys::DELETE)?;
                }
                None => {
                    let required = match requirement {
                        CreateTargetRequirement::Directory => wdk_sys::FILE_ADD_SUBDIRECTORY,
                        CreateTargetRequirement::Any | CreateTargetRequirement::NonDirectory => {
                            wdk_sys::FILE_ADD_FILE
                        }
                    };
                    state.authorize_operation(directory_descriptor.as_native(), required)?;
                }
            }
            state.authorize_requested(directory_descriptor.as_native(), requested)
        })?;
        Ok(AuthorizedCreateCompletionOwner {
            owner: self,
            granted_access,
        })
    }
}

impl AuthorizedCreateCompletionOwner<'_> {
    /// Returns the mounted device receiving the create.
    const fn device(&self) -> KernelDevice {
        self.owner.device()
    }

    /// Returns decoded create parameters.
    const fn parameters(&self) -> CreateParameters {
        self.owner.parameters()
    }

    /// Returns concrete rights established by create authorization.
    const fn granted_access(&self) -> GrantedAccess {
        self.granted_access
    }

    /// Executes the sole FILE_OBJECT attachment transition.
    /// # Errors
    ///
    /// Returns invalid FILE_OBJECT errors or the attachment operation's failure before publication.
    fn with_file_object<R>(
        &mut self,
        operation: impl for<'view> FnOnce(UninitializedFileObject<'view>) -> DriverResult<R>,
    ) -> DriverResult<R> {
        self.owner.with_file_object(operation)
    }
}

/// Opens or creates an ext4 object from a volume-root or opened-directory path.
/// # Errors
///
/// Returns an error when EA create input is supplied, the device is not mounted, path resolution
/// fails, or the selected open/create disposition cannot be satisfied.
fn open_or_create(
    request: PreparedCreateRequest<'_>,
    mounted_volume: NonNull<VolumeControlBlock>,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    pending_existing: &mut Option<PendingExistingCreateOpen>,
    namespace_oplocks: Option<NamespaceOplockPlan>,
) -> DriverResult<CreateResolution> {
    let PreparedCreateRequest {
        mut owner,
        target,
        create_ea,
    } = request;
    let disposition = owner.parameters().disposition();
    let target = match target {
        CreateTargetSpecifier::Volume => {
            if matches!(
                owner.parameters().target_selection(),
                crate::irp::CreateTargetSelection::ParentDirectory
            ) {
                return Err(DriverError::InvalidParameter);
            }
            operations.authorize_create()?;
            let owner =
                owner.authorize_existing(NodeId::Directory(DirectoryNodeId::ROOT), mutation)?;
            return open_volume(owner, create_ea, mounted_volume, operations)
                .map(CreateCompletion::Handle)
                .map(CreateResolution::Complete);
        }
        target @ (CreateTargetSpecifier::Path { .. } | CreateTargetSpecifier::FileReference(_)) => {
            target
        }
    };
    operations.authorize_create()?;
    match resolve_target(target, &mut owner, operations, mutation)? {
        CreateTargetLookup::Existing {
            node,
            node_mode,
            location,
        } => {
            let mut owner = owner.authorize_existing(node, mutation)?;
            open_existing_node(
                &mut owner,
                disposition,
                ExistingNodeTarget {
                    volume: mounted_volume,
                    node,
                    node_mode,
                    location,
                },
                operations,
                mutation,
                pending_existing,
            )
        }
        CreateTargetLookup::Missing { parent, name } => {
            let requirement = owner.parameters().target_requirement();
            let owner = owner.authorize_child_creation(parent, requirement, mutation)?;
            let oplocks = NamespaceOplockPlan::single(parent, NamespaceParentOplockEffect::Change);
            if namespace_oplocks != Some(oplocks) {
                return Ok(CreateResolution::CheckNamespaceOplocks(oplocks));
            }
            let publication = create_missing_node(
                owner,
                create_ea,
                operations,
                mutation,
                disposition,
                parent,
                &name,
            )?;
            memory::boxed_try_with(move || Ok(publication)).map(CreateResolution::Mutation)
        }
        CreateTargetLookup::ParentDirectory {
            directory,
            location,
            target,
        } => {
            let requirement = owner.parameters().target_requirement();
            let mut owner =
                owner.authorize_target_directory(directory, target, requirement, mutation)?;
            let stream_metadata = CommittedNodeStreamMetadata::new(
                NodeStreamMetadata::try_from_snapshot(
                    mutation.load_node_metadata(NodeId::Directory(directory))?,
                    operations.volume_geometry().cluster_size(),
                )?,
                operations.current_epoch_sequence(),
            );
            let pending = open_target_directory(
                &mut owner,
                create_ea,
                mounted_volume,
                directory,
                location,
                target,
                stream_metadata,
            )?;
            Ok(select_existing_open_gate(
                pending,
                pending_existing,
                operations,
            ))
        }
        CreateTargetLookup::ReparseSymlink {
            point,
            unparsed_path,
        } => create_symlink_reparse_completion(mutation, point, unparsed_path)
            .map(CreateResolution::Complete),
    }
}

/// Builds the ownership-bearing completion for a reparse point encountered during create lookup.
/// # Errors
///
/// Returns an error when the node target cannot be converted to the Windows symbolic-link wire
/// form, its exact output buffer cannot be allocated, or packing violates the derived size.
fn create_symlink_reparse_completion(
    read: &mut impl CommittedReadPass,
    point: NodeSymlinkReparsePoint,
    unparsed_path: UnparsedPathLength,
) -> DriverResult<CreateCompletion> {
    let data = point.into_symlink_data(read)?;
    let required_length = data.required_length()?;
    let buffer = CreateSymlinkReparseBuffer::try_pack_exact(required_length, |output| {
        data.pack_create_redirect(unparsed_path, output)
    })?;
    Ok(CreateCompletion::ReparseSymlink(buffer))
}

/// Fully decoded create target that contains no raw FILE_OBJECT or VCB reference.
#[derive(Debug, Eq, PartialEq)]
enum CreateTargetSpecifier {
    /// Direct user open of the mounted volume rather than a namespace node.
    Volume,
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
        file_object: &UninitializedFileObject<'_>,
        mounted_volume: NonNull<VolumeControlBlock>,
        interpretation: CreateNameInterpretation,
        disposition: CreateDisposition,
    ) -> DriverResult<Self> {
        match interpretation {
            CreateNameInterpretation::Path => {
                let name = CreatePathName::decode(file_object.as_ref())?;
                if name.is_direct_volume_open() && file_object.related_file_object().is_none() {
                    validate_volume_open_create(disposition)?;
                    return Ok(Self::Volume);
                }
                let anchor = CreatePathAnchor::decode(file_object, mounted_volume, name.rooting())?;
                Ok(Self::Path { name, anchor })
            }
            CreateNameInterpretation::FileReference => {
                validate_file_reference_create(disposition)?;
                Ok(Self::FileReference(CreateFileReference::decode(
                    file_object.as_ref(),
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
    /// `SL_OPEN_TARGET_DIRECTORY` selected the final component's containing directory.
    ParentDirectory {
        /// Parent directory opened for the caller.
        directory: DirectoryNodeId,
        /// Stable namespace location of that directory.
        location: OpenedLocation,
        /// Existence and identity of the named target below the parent.
        target: TargetDirectoryLeaf,
    },
    /// Name resolution encountered a reparse point that Windows must process.
    ReparseSymlink {
        /// Reparse metadata captured from the encountered node.
        point: NodeSymlinkReparsePoint,
        /// UTF-16 byte length of the name suffix not consumed by this filesystem.
        unparsed_path: UnparsedPathLength,
    },
}

/// Final-component observation retained for `SL_OPEN_TARGET_DIRECTORY` access checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetDirectoryLeaf {
    /// The named final component does not exist.
    Missing,
    /// The named final component exists with this identity.
    Existing(NodeId),
}

/// Per-handle policy decoded from one create/open request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateHandlePolicy {
    /// Access explicitly requested for the returned handle.
    granted_access: GrantedAccess,
    /// Virtual access used only to preflight an existing-object operation.
    existing_operation_access: ExistingOperationAccess,
    /// Share mask used for Windows share-access accounting.
    share_access: ShareAccess,
    /// Data transfer buffering policy stored on the opened handle.
    data_transfer_mode: DataTransferMode,
    /// Create-time oplock behavior retained until FCB admission completes.
    oplock_policy: crate::irp::OplockCreatePolicy,
    /// Regular-file write authority retained by the per-handle state.
    regular_file_write_access: RegularFileWriteAccess,
    /// Delete authority and create-time namespace lifecycle retained by the handle.
    deletion: HandleDeletion,
    /// FILE_OBJECT flags projected from create options.
    file_object_flags: CreateFileObjectFlags,
}

impl CreateHandlePolicy {
    /// Projects handle policy fields from decoded create parameters.
    /// # Errors
    ///
    /// Returns an error when requested transfer buffering cannot be satisfied by the mounted device.
    fn from_authorized(
        parameters: CreateParameters,
        granted_access: GrantedAccess,
        device: KernelDevice,
    ) -> DriverResult<Self> {
        let file_object_flags = CreateFileObjectFlags::from_parameters(parameters);
        Ok(Self {
            granted_access,
            existing_operation_access: granted_access
                .including_for_operation(parameters.existing_operation_required_access()),
            share_access: parameters.share_access(),
            data_transfer_mode: match parameters.transfer_buffering() {
                CreateTransferBuffering::IntermediateAllowed => DataTransferMode::Cached,
                CreateTransferBuffering::NoIntermediate => {
                    DataTransferMode::Direct(NoIntermediateTransfer::from_device(device)?)
                }
            },
            oplock_policy: parameters.oplock_policy(),
            regular_file_write_access: granted_access.regular_file_write_access(),
            deletion: HandleDeletion::from_create(
                parameters.deletion(),
                granted_access.delete_access(),
                granted_access.file_attributes_write_access(),
            )?,
            file_object_flags,
        })
    }

    /// Returns access explicitly requested for the returned handle.
    const fn granted_access(self) -> GrantedAccess {
        self.granted_access
    }

    /// Returns virtual access that existing handles must share for this operation.
    const fn existing_operation_access(self) -> ExistingOperationAccess {
        self.existing_operation_access
    }

    /// Returns the share access mask.
    const fn share_access(self) -> ShareAccess {
        self.share_access
    }

    /// Returns data transfer buffering policy.
    const fn data_transfer_mode(self) -> DataTransferMode {
        self.data_transfer_mode
    }

    /// Returns the oplock admission policy selected by create flags.
    const fn oplock_policy(self) -> crate::irp::OplockCreatePolicy {
        self.oplock_policy
    }

    /// Returns create-time namespace deletion requested for this handle.
    const fn deletion(self) -> CreateDeletion {
        self.deletion.create_deletion()
    }

    /// Returns the deletion authority and lifecycle stored in the opened handle.
    const fn handle_deletion(self) -> HandleDeletion {
        self.deletion
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
    #[expect(
        unsafe_code,
        reason = "the I/O Manager owns the checked binary UNICODE_STRING for this active create"
    )]
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
    #[expect(
        unsafe_code,
        reason = "the I/O Manager owns the checked UTF-16 UNICODE_STRING for this active create"
    )]
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

    /// Returns whether this empty relative name selects the mounted volume itself.
    fn is_direct_volume_open(&self) -> bool {
        matches!(self.rooting, CreateNameRooting::Relative) && self.components.is_empty()
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
        file_object: &UninitializedFileObject<'_>,
        vcb: NonNull<VolumeControlBlock>,
        rooting: CreateNameRooting,
    ) -> DriverResult<Self> {
        let Some(related_file) = file_object.related_file_object() else {
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

    /// Consumes the anchor into its directory identity and stable namespace location.
    fn into_directory_location(self) -> (DirectoryNodeId, OpenedLocation) {
        match self {
            Self::VolumeRoot => (DirectoryNodeId::ROOT, OpenedLocation::Root),
            Self::OpenedDirectory { id, location } => (id, location),
        }
    }
}

/// One fully resolved existing target passed into create/open policy.
#[derive(Debug)]
struct ExistingNodeTarget {
    /// Mounted volume owning the resolved identity.
    volume: NonNull<crate::state::VolumeControlBlock>,
    /// Typed ext4 identity.
    node: NodeId,
    /// Whether the caller opened the link itself or its resolved target.
    node_mode: OpenedNodeMode,
    /// Stable namespace location captured during lookup.
    location: OpenedLocation,
}

/// Native image-section work required before an existing handle claim may be published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingWriteOpenRequirement {
    /// No older stream existed, or the requested handle has no regular-file data-write authority.
    NotRequired,
    /// A resident regular-file stream must exclude an executable image before attachment.
    FlushImageSection,
}

/// Oplock admission retained by one provisional existing-node create claim.
#[derive(Debug)]
enum ExistingCreateOplockState {
    /// No break occurred, or the exact requested break protocol completed normally.
    Ready,
    /// The successful create must report that its requested nonblocking break is still underway.
    BreakInProgress,
    /// FsRtl has not yet observed the create IRP for this resident stream.
    Check(crate::irp::OplockCreatePolicy),
    /// The create IRP must establish its encoded atomic oplock before any later native gate.
    Reserve(NonZeroU32),
    /// FsRtl established the oplock and this state exclusively owns success-or-backout authority.
    Reserved(AtomicOplockReservation),
}

impl ExistingCreateOplockState {
    /// Selects whether a provisional existing-node claim must visit FsRtl before publication.
    const fn from_admission(
        policy: crate::irp::OplockCreatePolicy,
        residency: ExistingStreamResidency,
        open_count: NonZeroU32,
    ) -> Self {
        match (policy, residency) {
            (
                crate::irp::OplockCreatePolicy::Ordinary
                | crate::irp::OplockCreatePolicy::CompleteIfOplocked,
                ExistingStreamResidency::FirstOpen,
            ) => Self::Ready,
            (
                policy @ (crate::irp::OplockCreatePolicy::Ordinary
                | crate::irp::OplockCreatePolicy::CompleteIfOplocked),
                ExistingStreamResidency::Resident,
            ) => Self::Check(policy),
            (
                crate::irp::OplockCreatePolicy::RequireUnbrokenOplock
                | crate::irp::OplockCreatePolicy::ReserveFilter,
                _,
            ) => Self::Reserve(open_count),
        }
    }

    /// Validates a successful FsRtl return and seals the create completion status.
    /// # Errors
    ///
    /// Returns the exact oplock failure or an invariant failure for a status that is not legal for
    /// the selected break policy. Atomic policies use the separate reservation state.
    fn accept(&mut self, status: wdk_sys::NTSTATUS) -> DriverResult<()> {
        let Self::Check(policy) = self else {
            return Err(DriverError::InternalInvariantViolation);
        };
        *self = match (*policy, status) {
            (_, status) if status < wdk_sys::STATUS_SUCCESS => {
                return Err(DriverError::OplockFailure(status));
            }
            (crate::irp::OplockCreatePolicy::Ordinary, wdk_sys::STATUS_SUCCESS)
            | (crate::irp::OplockCreatePolicy::CompleteIfOplocked, wdk_sys::STATUS_SUCCESS) => {
                Self::Ready
            }
            (
                crate::irp::OplockCreatePolicy::CompleteIfOplocked,
                wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS,
            ) => Self::BreakInProgress,
            _ => return Err(DriverError::InternalInvariantViolation),
        };
        Ok(())
    }
}

/// Oplock reservation authority for one transaction-local first-open stream.
#[derive(Debug)]
enum NewCreateOplockState {
    /// The create flags require no atomic oplock establishment.
    Ready,
    /// The live create IRP must establish its requested oplock with this proven handle count.
    Reserve(NonZeroU32),
    /// FsRtl established the oplock and this state owns success-or-backout authority.
    Reserved(AtomicOplockReservation),
}

impl NewCreateOplockState {
    /// Derives the only legal first-open state from normalized create policy.
    const fn from_policy(policy: crate::irp::OplockCreatePolicy, open_count: NonZeroU32) -> Self {
        match policy {
            crate::irp::OplockCreatePolicy::Ordinary
            | crate::irp::OplockCreatePolicy::CompleteIfOplocked => Self::Ready,
            crate::irp::OplockCreatePolicy::RequireUnbrokenOplock
            | crate::irp::OplockCreatePolicy::ReserveFilter => Self::Reserve(open_count),
        }
    }

    /// Returns the proven handle count when FsRtl establishment remains outstanding.
    const fn reservation_target(&self) -> Option<NonZeroU32> {
        match self {
            Self::Reserve(open_count) => Some(*open_count),
            Self::Ready | Self::Reserved(_) => None,
        }
    }

    /// Seals a reservation belonging to the matching first-open FCB.
    fn accept(&mut self, reservation: AtomicOplockReservation, fcb: NonNull<FileControlBlock>) {
        if !matches!(self, Self::Reserve(_)) || !reservation.identifies(fcb) {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
        *self = Self::Reserved(reservation);
    }

    /// Consumes one-shot backout authority before a failed create completion.
    /// # Errors
    ///
    /// Returns the exact native backout failure after consuming the reservation.
    fn abort(&mut self, owned: &crate::irp::OwnedIrp) -> DriverResult<()> {
        let oplock = core::mem::replace(self, Self::Ready);
        match oplock {
            Self::Reserved(reservation) => reservation.backout(owned),
            Self::Ready | Self::Reserve(_) => Ok(()),
        }
    }

    /// Consumes the reservation after the committed handle becomes publishable.
    fn publish(&mut self) {
        let oplock = core::mem::replace(self, Self::Ready);
        match oplock {
            Self::Ready => {}
            Self::Reserved(reservation) => reservation.publish(),
            Self::Reserve(_) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption(
                )
                .bugcheck();
            }
        }
    }
}

impl ExistingWriteOpenRequirement {
    /// Selects the native gate for an already classified regular-file admission.
    const fn for_regular_file(
        write_access: RegularFileWriteAccess,
        residency: ExistingStreamResidency,
    ) -> Self {
        match (write_access, residency) {
            (
                RegularFileWriteAccess::AppendOnly | RegularFileWriteAccess::Positional,
                ExistingStreamResidency::Resident,
            ) => Self::FlushImageSection,
            (RegularFileWriteAccess::Denied, _)
            | (
                RegularFileWriteAccess::AppendOnly | RegularFileWriteAccess::Positional,
                ExistingStreamResidency::FirstOpen,
            ) => Self::NotRequired,
        }
    }
}

/// Fully allocated existing-node open retained while an image-section check runs outside the actor.
#[derive(Debug)]
pub(crate) struct PendingExistingCreateOpen {
    /// Rollback-owning FCB reference and provisional share claim.
    claim: PendingFileControlBlockClaim,
    /// Exact inode resolved before the native call.
    node: NodeId,
    /// Reparse interpretation selected for the handle.
    node_mode: OpenedNodeMode,
    /// Separately owned namespace identity used for post-worker revalidation.
    validation_location: OpenedLocation,
    /// Complete authorized handle policy fixed before the native call.
    policy: CreateHandlePolicy,
    /// Fully allocated per-handle context consumed only by FILE_OBJECT attachment.
    handle: Box<OpenedHandle>,
    /// Optional prevalidated delete-on-close publication.
    pending_deletion: Option<PendingFileDeletion>,
    /// Windows create information returned after successful attachment.
    action: CreateAction,
    /// Whether native image-section exclusion is required for this exact claim.
    write_open: ExistingWriteOpenRequirement,
    /// Create-specific oplock conflict state sealed before image exclusion or attachment.
    oplock: ExistingCreateOplockState,
}

impl PendingExistingCreateOpen {
    /// Allocates and admits every resource needed before any MM call can occur.
    /// # Errors
    ///
    /// Returns allocation, FILE_OBJECT validation, FCB admission, share, or oplock errors.
    fn prepare(
        request: &mut AuthorizedCreateCompletionOwner<'_>,
        target: ExistingNodeTarget,
        stream_metadata: CommittedNodeStreamMetadata,
        policy: CreateHandlePolicy,
        pending_deletion: Option<PendingFileDeletion>,
        action: CreateAction,
    ) -> DriverResult<Self> {
        let ExistingNodeTarget {
            volume,
            node,
            node_mode,
            location,
        } = target;
        if stream_metadata.node() != node {
            return Err(DriverError::InternalInvariantViolation);
        }
        let validation_location = location.try_to_owned_location()?;
        let handle = memory::boxed_try_with(|| {
            OpenedHandle::new(
                node,
                node_mode,
                location,
                policy.handle_deletion(),
                policy.data_transfer_mode(),
                policy.regular_file_write_access(),
            )
        })?;
        let file_object =
            request.with_file_object(|file_object| Ok(file_object.kernel_file_object()))?;
        let admission = VolumeControlBlock::open_existing_file_control_block(
            volume,
            stream_metadata,
            file_object,
            policy.granted_access(),
            policy.existing_operation_access(),
            policy.share_access(),
            policy.oplock_policy(),
        )?;
        let write_open = match node {
            NodeId::File(_) => ExistingWriteOpenRequirement::for_regular_file(
                policy.regular_file_write_access(),
                admission.residency(),
            ),
            NodeId::Directory(_) | NodeId::Symlink(_) => ExistingWriteOpenRequirement::NotRequired,
        };
        let oplock = ExistingCreateOplockState::from_admission(
            policy.oplock_policy(),
            admission.residency(),
            admission.open_count(),
        );
        Ok(Self {
            claim: PendingFileControlBlockClaim {
                fcb: admission.file_control_block(),
                file_object,
            },
            node,
            node_mode,
            validation_location,
            policy,
            handle,
            pending_deletion,
            action,
            write_open,
            oplock,
        })
    }

    /// Returns the exact resident stream and policy that must be checked before publication.
    fn oplock_check_target(
        &self,
    ) -> Option<(NonNull<FileControlBlock>, crate::irp::OplockCreatePolicy)> {
        match &self.oplock {
            ExistingCreateOplockState::Check(policy) => {
                Some((self.claim.file_control_block(), *policy))
            }
            ExistingCreateOplockState::Ready
            | ExistingCreateOplockState::BreakInProgress
            | ExistingCreateOplockState::Reserve(_)
            | ExistingCreateOplockState::Reserved(_) => None,
        }
    }

    /// Returns the exact stream and admitted count whose create IRP must reserve an atomic oplock.
    fn oplock_reservation_target(&self) -> Option<(NonNull<FileControlBlock>, NonZeroU32)> {
        match &self.oplock {
            ExistingCreateOplockState::Reserve(open_count) => {
                Some((self.claim.file_control_block(), *open_count))
            }
            ExistingCreateOplockState::Ready
            | ExistingCreateOplockState::BreakInProgress
            | ExistingCreateOplockState::Check(_)
            | ExistingCreateOplockState::Reserved(_) => None,
        }
    }

    /// Seals the exact success status returned by the delegated create conflict check.
    /// # Errors
    ///
    /// Returns the matching oplock or protocol error without consuming the provisional claim.
    pub(crate) fn accept_oplock_status(&mut self, status: wdk_sys::NTSTATUS) -> DriverResult<()> {
        self.oplock.accept(status)
    }

    /// Seals one reservation returned for this exact provisional FCB claim.
    pub(crate) fn accept_oplock_reservation(&mut self, reservation: AtomicOplockReservation) {
        if !matches!(&self.oplock, ExistingCreateOplockState::Reserve(_))
            || !reservation.identifies(self.claim.file_control_block())
        {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        }
        self.oplock = ExistingCreateOplockState::Reserved(reservation);
    }

    /// Consumes this unpublished claim, backing out any established atomic oplock first.
    /// # Errors
    ///
    /// Returns the exact native backout failure after consuming its one-shot authority.
    pub(crate) fn abort(mut self, owned: &crate::irp::OwnedIrp) -> DriverResult<()> {
        let oplock = core::mem::replace(&mut self.oplock, ExistingCreateOplockState::Ready);
        match oplock {
            ExistingCreateOplockState::Reserved(reservation) => reservation.backout(owned),
            ExistingCreateOplockState::Ready
            | ExistingCreateOplockState::BreakInProgress
            | ExistingCreateOplockState::Check(_)
            | ExistingCreateOplockState::Reserve(_) => Ok(()),
        }
    }

    /// Returns the exact resident stream that needs native image-section exclusion.
    fn write_open_target(&self) -> Option<(NonNull<FileControlBlock>, NodeId)> {
        match self.write_open {
            ExistingWriteOpenRequirement::NotRequired => None,
            ExistingWriteOpenRequirement::FlushImageSection => {
                Some((self.claim.file_control_block(), self.node))
            }
        }
    }

    /// Publishes the provisional claim after validating the matching native gate, when required.
    ///
    /// Every recoverable validation and allocation has completed before this ownership-consuming
    /// boundary. A mismatched gate or unfinished oplock state is reactor corruption, because a
    /// returned error could no longer retain the atomic backout authority.
    fn publish(
        mut self,
        gate: Option<&PreparedStreamWriteOpen>,
        operations: &mut MountedVolumeAccess<'_>,
    ) -> CreateCompletion {
        match (self.write_open, gate) {
            (ExistingWriteOpenRequirement::NotRequired, None) => {}
            (ExistingWriteOpenRequirement::FlushImageSection, Some(gate))
                if gate.authorizes(self.claim.file_control_block(), self.node) => {}
            (ExistingWriteOpenRequirement::NotRequired, Some(_))
            | (ExistingWriteOpenRequirement::FlushImageSection, None | Some(_)) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption(
                )
                .bugcheck();
            }
        }
        let oplock = core::mem::replace(&mut self.oplock, ExistingCreateOplockState::Ready);
        let completion = match oplock {
            ExistingCreateOplockState::Ready => CreateCompletion::Handle(self.action),
            ExistingCreateOplockState::BreakInProgress => {
                CreateCompletion::OplockBreakInProgress(self.action)
            }
            ExistingCreateOplockState::Reserved(reservation) => {
                reservation.publish();
                CreateCompletion::Handle(self.action)
            }
            ExistingCreateOplockState::Check(_) | ExistingCreateOplockState::Reserve(_) => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption(
                )
                .bugcheck();
            }
        };
        let Self {
            claim,
            handle,
            policy,
            pending_deletion,
            ..
        } = self;
        let (fcb, file_object) = claim.consume();
        publish_node_stream_raw(file_object, fcb, handle, policy.file_object_flags());
        if let Some(pending) = pending_deletion {
            operations.set_file_delete_pending(fcb, pending);
        }
        completion
    }
}

/// Selects the one remaining native gate or publishes an already sealed existing-node claim.
fn select_existing_open_gate(
    pending: PendingExistingCreateOpen,
    pending_existing: &mut Option<PendingExistingCreateOpen>,
    operations: &mut MountedVolumeAccess<'_>,
) -> CreateResolution {
    if let Some((fcb, policy)) = pending.oplock_check_target() {
        *pending_existing = Some(pending);
        return CreateResolution::CheckOplock { fcb, policy };
    }
    if let Some((fcb, open_count)) = pending.oplock_reservation_target() {
        *pending_existing = Some(pending);
        return CreateResolution::ReserveOplock { fcb, open_count };
    }
    if let Some((fcb, node)) = pending.write_open_target() {
        *pending_existing = Some(pending);
        return CreateResolution::PrepareWriteOpen { fcb, node };
    }
    CreateResolution::Complete(pending.publish(None, operations))
}

/// Resumes an existing-node create after its native write-open gate completed.
/// # Errors
///
/// Returns security, namespace, reparse, or exact-gate validation failures. A stale namespace or
/// reparse projection returns the private retry status so operation ownership can restart cleanly.
fn resume_existing_open(
    mut request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    read: &mut impl CommittedReadPass,
    pending_existing: &mut Option<PendingExistingCreateOpen>,
    prepared_write_open: Option<&PreparedStreamWriteOpen>,
) -> DriverResult<CreateResolution> {
    let pending = pending_existing
        .as_ref()
        .ok_or(DriverError::InternalInvariantViolation)?;
    let (device, parameters, file_object) = request.with_active(|active| {
        let current = active.current_stack()?;
        let file_object = current.file_object()?;
        let stack = current.create()?;
        let parameters = stack.parameters();
        parameters.validate_supported_flags()?;
        let file_object = UninitializedFileObject::decode(file_object)?;
        Ok::<_, DriverError>((
            active.device(),
            parameters,
            file_object.kernel_file_object(),
        ))
    })?;
    if file_object != pending.claim.file_object() {
        return Err(DriverError::InternalInvariantViolation);
    }
    operations.authorize_create()?;
    operations.ensure_node_openable(pending.node)?;
    revalidate_existing_open(pending, read)?;
    let owner = CreateCompletionOwner {
        request,
        parameters,
        device,
    };
    let owner = owner.authorize_existing(pending.node, read)?;
    let current_policy =
        CreateHandlePolicy::from_authorized(parameters, owner.granted_access(), device)?;
    if current_policy != pending.policy {
        return Err(DriverError::InternalInvariantViolation);
    }
    if pending.oplock_check_target().is_some() {
        return Err(DriverError::InternalInvariantViolation);
    }
    if pending.oplock_reservation_target().is_some() {
        return Err(DriverError::InternalInvariantViolation);
    }
    if let Some((fcb, node)) = pending.write_open_target()
        && prepared_write_open.is_none()
    {
        return Ok(CreateResolution::PrepareWriteOpen { fcb, node });
    }
    if let Some(deletion) = pending.pending_deletion.as_ref() {
        crate::request::file_info::validate_pending_deletion(
            read,
            pending.node,
            deletion.target_ref(),
            crate::request::file_info::DeleteReadonlyPolicy::Enforce,
        )?;
    }
    let pending = pending_existing
        .take()
        .ok_or(DriverError::InternalInvariantViolation)?;
    Ok(CreateResolution::Complete(
        pending.publish(prepared_write_open, operations),
    ))
}

/// Revalidates the exact namespace identity and reparse interpretation without allocating.
/// # Errors
///
/// Returns storage or metadata errors, or the private retry status when identity changed.
fn revalidate_existing_open(
    pending: &PendingExistingCreateOpen,
    read: &mut impl CommittedReadPass,
) -> DriverResult<()> {
    let location_matches = match &pending.validation_location {
        OpenedLocation::Root => {
            let _root = read.load_directory(DirectoryNodeId::ROOT)?;
            pending.node == NodeId::Directory(DirectoryNodeId::ROOT)
        }
        OpenedLocation::DirectoryEntry { parent, name } => {
            let parent = read.load_directory(*parent)?;
            matches!(
                read.lookup_child(&parent, name)?,
                ChildLookup::Found(child) if *child.node() == pending.node
            )
        }
        OpenedLocation::FileReference => {
            read.load_node_by_file_index(pending.node.file_index())? == pending.node
        }
    };
    let current_mode = if NodeSymlinkReparsePoint::load(read, pending.node)?.is_some() {
        OpenedNodeMode::ReparsePoint
    } else {
        OpenedNodeMode::Direct
    };
    if !location_matches || current_mode != pending.node_mode {
        return Err(DriverError::CacheManagerFailure(STATUS_RETRY));
    }
    Ok(())
}

/// Opens an existing path according to the requested disposition and options.
/// # Errors
///
/// Returns an error when existing-node options conflict, create-only disposition collides, share
/// access fails, or an incomplete destructive disposition is requested.
fn open_existing_node(
    request: &mut AuthorizedCreateCompletionOwner<'_>,
    disposition: CreateDisposition,
    target: ExistingNodeTarget,
    operations: &mut MountedVolumeAccess<'_>,
    read: &mut impl CommittedReadPass,
    pending_existing: &mut Option<PendingExistingCreateOpen>,
) -> DriverResult<CreateResolution> {
    let node = target.node;
    let parameters = request.parameters();
    let policy = CreateHandlePolicy::from_authorized(
        parameters,
        request.granted_access(),
        request.device(),
    )?;
    match disposition {
        CreateDisposition::Open | CreateDisposition::OpenIf => {
            validate_existing_node_options(node, parameters.target_requirement())?;
            let pending = prepare_create_deletion(policy, node, &target.location, read)?;
            let stream_metadata = CommittedNodeStreamMetadata::new(
                NodeStreamMetadata::try_from_snapshot(
                    read.load_node_metadata(node)?,
                    operations.volume_geometry().cluster_size(),
                )?,
                operations.current_epoch_sequence(),
            );
            let pending = PendingExistingCreateOpen::prepare(
                request,
                target,
                stream_metadata,
                policy,
                pending,
                CreateAction::Opened,
            )?;
            Ok(select_existing_open_gate(
                pending,
                pending_existing,
                operations,
            ))
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

/// Prepares and validates create-time delete-pending before FILE_OBJECT attachment.
/// # Errors
///
/// Returns cannot-delete for an identity without a deletable link, read-only or non-empty targets,
/// or an underlying metadata error.
fn prepare_create_deletion(
    policy: CreateHandlePolicy,
    node: NodeId,
    location: &OpenedLocation,
    read: &mut impl CommittedReadPass,
) -> DriverResult<Option<PendingFileDeletion>> {
    if policy.deletion() == CreateDeletion::Retain {
        return Ok(None);
    }
    let pending = PendingFileDeletion::try_from_delete_on_close(location)?;
    crate::request::file_info::validate_pending_deletion(
        read,
        node,
        pending.target_ref(),
        crate::request::file_info::DeleteReadonlyPolicy::Enforce,
    )?;
    Ok(Some(pending))
}

/// Opens the mounted volume itself and publishes a typed volume FILE_OBJECT.
/// # Errors
///
/// Returns an error when EAs are supplied, share-access validation fails, handle allocation fails,
/// or the completion-owned FILE_OBJECT cannot be attached.
fn open_volume(
    mut request: AuthorizedCreateCompletionOwner<'_>,
    create_ea: CreateEa,
    volume: NonNull<VolumeControlBlock>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<CreateAction> {
    if !create_ea.is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    let parameters = request.parameters();
    let policy = CreateHandlePolicy::from_authorized(
        parameters,
        request.granted_access(),
        request.device(),
    )?;
    if policy.deletion() == CreateDeletion::DeleteOnClose {
        return Err(DriverError::CannotDelete);
    }
    let handle = memory::boxed_try_with(|| {
        Ok(OpenedVolumeHandle::new(RawVolumeAccess::from_granted(
            policy.granted_access(),
        )))
    })?;
    request.with_file_object(move |file_object| {
        operations.open_volume_handle(
            file_object.kernel_file_object(),
            policy.granted_access(),
            policy.share_access(),
        )?;
        publish_volume_stream(file_object, volume, handle, policy.file_object_flags());
        Ok(())
    })?;
    Ok(CreateAction::Opened)
}

/// Opens the containing directory selected by `SL_OPEN_TARGET_DIRECTORY`.
/// # Errors
///
/// Returns an error when the request would mutate the namespace, carries EAs or delete-on-close,
/// conflicts with existing share state, or cannot attach the parent directory handle.
fn open_target_directory(
    request: &mut AuthorizedCreateCompletionOwner<'_>,
    create_ea: CreateEa,
    volume: NonNull<VolumeControlBlock>,
    directory: DirectoryNodeId,
    location: OpenedLocation,
    target: TargetDirectoryLeaf,
    stream_metadata: CommittedNodeStreamMetadata,
) -> DriverResult<PendingExistingCreateOpen> {
    if !create_ea.is_empty() || request.parameters().disposition() != CreateDisposition::Open {
        return Err(DriverError::InvalidParameter);
    }
    let parameters = request.parameters();
    if parameters.deletion() == CreateDeletion::DeleteOnClose {
        return Err(DriverError::CannotDelete);
    }
    validate_existing_node_options(
        NodeId::Directory(directory),
        parameters.target_requirement(),
    )?;
    let policy = CreateHandlePolicy::from_authorized(
        parameters,
        request.granted_access(),
        request.device(),
    )?;
    let action = match target {
        TargetDirectoryLeaf::Missing => CreateAction::TargetDoesNotExist,
        TargetDirectoryLeaf::Existing(_) => CreateAction::TargetExists,
    };
    PendingExistingCreateOpen::prepare(
        request,
        ExistingNodeTarget {
            volume,
            node: NodeId::Directory(directory),
            node_mode: OpenedNodeMode::Direct,
            location,
        },
        stream_metadata,
        policy,
        None,
        action,
    )
}

/// Validates create semantics that are meaningful for a direct volume open.
/// # Errors
///
/// Returns an error when the caller requests creation or replacement of the volume object.
fn validate_volume_open_create(disposition: CreateDisposition) -> DriverResult<()> {
    match disposition {
        CreateDisposition::Open => Ok(()),
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::Overwrite
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => Err(DriverError::InvalidParameter),
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
fn create_missing_node(
    mut request: AuthorizedCreateCompletionOwner<'_>,
    create_ea: CreateEa,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    disposition: CreateDisposition,
    parent: DirectoryNodeId,
    name: &Ext4Name,
) -> DriverResult<PendingCreatePublication> {
    let parameters = request.parameters();
    let policy = CreateHandlePolicy::from_authorized(
        parameters,
        request.granted_access(),
        request.device(),
    )?;
    match disposition {
        CreateDisposition::Create
        | CreateDisposition::OpenIf
        | CreateDisposition::OverwriteIf
        | CreateDisposition::Supersede => {}
        CreateDisposition::Open => return Err(DriverError::ObjectNameNotFound),
        CreateDisposition::Overwrite => return Err(DriverError::ObjectNameNotFound),
    }

    let location = OpenedLocation::try_directory_entry(parent, name)?;
    let pending_deletion = match policy.deletion() {
        CreateDeletion::Retain => None,
        CreateDeletion::DeleteOnClose => {
            Some(PendingFileDeletion::try_from_delete_on_close(&location)?)
        }
    };
    let target = child_creation_target(parameters.target_requirement())?;
    let mut creation = operations.begin_child_creation(mutation, parent, name, target)?;
    let node = creation.node();
    let notification = DirectoryChange::new(parent, name, node, DirectoryChangeAction::Added)?;
    let handle = memory::boxed_try_with(|| {
        OpenedHandle::new(
            node,
            OpenedNodeMode::Direct,
            location,
            policy.handle_deletion(),
            policy.data_transfer_mode(),
            policy.regular_file_write_access(),
        )
    })?;
    create_ea.apply_to_pending_child(&mut creation, mutation)?;
    let staged_stream = StagedNodeStreamMetadata::try_from_staged_snapshot(
        mutation.staged_node_metadata(node)?,
        operations.volume_geometry().cluster_size(),
    )?;
    let file_object =
        request.with_file_object(|file_object| Ok(file_object.kernel_file_object()))?;
    Ok(PendingCreatePublication {
        creation,
        staged_stream,
        file_object,
        desired_access: policy.granted_access(),
        share_access: policy.share_access(),
        oplock_policy: policy.oplock_policy(),
        handle,
        flags: policy.file_object_flags(),
        pending_deletion,
        notification,
    })
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
fn resolve_target(
    target: CreateTargetSpecifier,
    owner: &mut CreateCompletionOwner<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<CreateTargetLookup> {
    let parameters = owner.parameters();
    match target {
        CreateTargetSpecifier::Volume => Err(DriverError::InternalInvariantViolation),
        CreateTargetSpecifier::Path { name, anchor } => {
            resolve_path(name, anchor, owner, operations, read)
        }
        CreateTargetSpecifier::FileReference(reference) => {
            if matches!(
                parameters.target_selection(),
                crate::irp::CreateTargetSelection::ParentDirectory
            ) {
                return Err(DriverError::InvalidParameter);
            }
            let target = resolve_file_reference(reference, read, parameters.reparse_point_mode())?;
            if let CreateTargetLookup::Existing { node, .. } = &target {
                operations.ensure_node_openable(*node)?;
            }
            Ok(target)
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
fn resolve_file_reference(
    reference: CreateFileReference,
    read: &mut impl CommittedReadPass,
    reparse_point_mode: CreateReparsePointMode,
) -> DriverResult<CreateTargetLookup> {
    let node = read
        .load_node_by_file_index(reference.file_index())
        .map_err(file_reference_lookup_error)?;
    resolve_final_node(
        read,
        node,
        OpenedLocation::FileReference,
        reparse_point_mode,
        UnparsedPathLength::ZERO,
    )
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
fn resolve_path(
    name: CreatePathName,
    anchor: CreatePathAnchor,
    owner: &mut CreateCompletionOwner<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<CreateTargetLookup> {
    let parameters = owner.parameters();
    let reparse_point_mode = parameters.reparse_point_mode();
    let name_match = parameters.name_match();
    let target_selection = parameters.target_selection();
    let (mut parent_id, mut parent_location) = anchor.into_directory_location();
    let components = name.components();
    if components.is_empty()
        && matches!(
            target_selection,
            crate::irp::CreateTargetSelection::ParentDirectory
        )
    {
        return Err(DriverError::InvalidParameter);
    }
    let mut components = components.iter().peekable();
    while let Some(component) = components.next() {
        let position = if components.peek().is_none() {
            PathComponentPosition::Final
        } else {
            PathComponentPosition::Intermediate
        };
        operations.ensure_node_openable(NodeId::Directory(parent_id))?;
        owner.authorize_traverse(parent_id, read)?;
        let parent = match read.load_directory(parent_id) {
            Ok(directory) => directory,
            Err(error) => return Err(DriverError::from(error)),
        };
        let child = match read.lookup_windows_child(&parent, component.name(), name_match) {
            Ok(ChildLookup::Found(child)) => child,
            Ok(ChildLookup::NotFound)
                if position == PathComponentPosition::Final
                    && matches!(
                        target_selection,
                        crate::irp::CreateTargetSelection::ParentDirectory
                    ) =>
            {
                return Ok(CreateTargetLookup::ParentDirectory {
                    directory: parent_id,
                    location: parent_location,
                    target: TargetDirectoryLeaf::Missing,
                });
            }
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
        operations.ensure_node_openable(child_node)?;
        if position == PathComponentPosition::Final
            && matches!(
                target_selection,
                crate::irp::CreateTargetSelection::ParentDirectory
            )
        {
            return Ok(CreateTargetLookup::ParentDirectory {
                directory: parent_id,
                location: parent_location,
                target: TargetDirectoryLeaf::Existing(child_node),
            });
        }
        let reparse_point = NodeSymlinkReparsePoint::load(read, child_node)?;
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
        parent_location = OpenedLocation::try_directory_entry(child.parent(), child.name())?;
        parent_id = directory_id;
    }

    Ok(CreateTargetLookup::Existing {
        node: NodeId::Directory(parent_id),
        node_mode: OpenedNodeMode::Direct,
        location: parent_location,
    })
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
fn resolve_final_node(
    read: &mut impl CommittedReadPass,
    node: NodeId,
    location: OpenedLocation,
    reparse_point_mode: CreateReparsePointMode,
    unparsed_path: UnparsedPathLength,
) -> DriverResult<CreateTargetLookup> {
    let Some(point) = NodeSymlinkReparsePoint::load(read, node)? else {
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

/// Driver publication seed built during a restartable mutation resolve pass.
#[derive(Debug)]
pub(crate) struct PendingCreatePublication {
    /// Staged child identity and stable VCB/FCB-ledger capability.
    creation: PendingChildCreation,
    /// Exact staged stream dimensions after all create-time metadata and EA changes.
    staged_stream: StagedNodeStreamMetadata,
    /// Create-owned FILE_OBJECT identity retained by the top-level IRP.
    file_object: KernelFileObject,
    /// Share-accounting access mask.
    desired_access: GrantedAccess,
    /// Share-accounting share mask.
    share_access: ShareAccess,
    /// Create-time oplock behavior retained until the new stream is reserved or published.
    oplock_policy: crate::irp::OplockCreatePolicy,
    /// Fully allocated per-handle context.
    handle: Box<OpenedHandle>,
    /// FILE_OBJECT flags fixed by create options.
    flags: CreateFileObjectFlags,
    /// Optional delete-on-close publication.
    pending_deletion: Option<PendingFileDeletion>,
    /// Preallocated directory notification payload.
    notification: DirectoryChange,
}

impl PendingCreatePublication {
    /// Acquires the unique first-open FCB/share claim for this staged child.
    ///
    /// This boundary runs after mutation intent is reserved and before commit admission. Atomic
    /// create policies remain explicitly unsealed until the live create IRP visits FsRtl.
    /// # Errors
    ///
    /// Returns an error when FCB allocation, first-open admission, reference accounting, or share
    /// recording fails.
    pub(crate) fn prepare(self) -> DriverResult<PreparedCreatePublication> {
        let Self {
            creation,
            staged_stream,
            file_object,
            desired_access,
            share_access,
            oplock_policy,
            handle,
            flags,
            pending_deletion,
            notification,
        } = self;
        let admission = creation.open_file_control_block(
            file_object,
            desired_access,
            share_access,
            staged_stream,
        )?;
        let fcb = admission.file_control_block();
        Ok(PreparedCreatePublication {
            claim: PendingFileControlBlockClaim { fcb, file_object },
            oplock: NewCreateOplockState::from_policy(oplock_policy, admission.open_count()),
            handle,
            flags,
            pending_deletion,
            notification,
        })
    }
}

/// Fully prepared post-commit create publication.
#[derive(Debug)]
pub(crate) struct PreparedCreatePublication {
    /// Rollback-owning FCB/share claim consumed only by durable attachment.
    claim: PendingFileControlBlockClaim,
    /// Atomic create reservation state retained through commit durability.
    oplock: NewCreateOplockState,
    /// Fully allocated per-handle context.
    handle: Box<OpenedHandle>,
    /// Prevalidated FILE_OBJECT flags.
    flags: CreateFileObjectFlags,
    /// Optional preallocated delete-on-close target.
    pending_deletion: Option<PendingFileDeletion>,
    /// Preallocated directory notification payload.
    notification: DirectoryChange,
}

impl PreparedCreatePublication {
    /// Returns the exact first-open stream that must establish an atomic create oplock.
    pub(crate) fn oplock_reservation_target(
        &self,
    ) -> Option<(NonNull<FileControlBlock>, NonZeroU32)> {
        self.oplock
            .reservation_target()
            .map(|open_count| (self.claim.file_control_block(), open_count))
    }

    /// Seals the synchronous reservation for this exact first-open claim.
    pub(crate) fn accept_oplock_reservation(&mut self, reservation: AtomicOplockReservation) {
        self.oplock
            .accept(reservation, self.claim.file_control_block());
    }

    /// Backs out a sealed atomic oplock before failure completion and drops the unpublished claim.
    /// # Errors
    ///
    /// Returns the exact one-shot native backout failure after consuming the reservation.
    pub(crate) fn abort(mut self, owned: &crate::irp::OwnedIrp) -> DriverResult<()> {
        self.oplock.abort(owned)
    }

    /// Publishes a committed child using pointer writes and prepared-value moves only.
    pub(crate) fn publish(mut self, operations: &mut MountedVolumeAccess<'_>) -> CreateCompletion {
        self.oplock.publish();
        let Self {
            claim,
            oplock: _,
            handle,
            flags,
            pending_deletion,
            notification,
        } = self;
        let (fcb, file_object) = claim.consume();
        publish_node_stream_raw(file_object, fcb, handle, flags);
        if let Some(pending) = pending_deletion {
            operations.set_file_delete_pending(fcb, pending);
        }
        operations.report_directory_change(notification);
        CreateCompletion::Handle(CreateAction::Created)
    }
}

/// FCB reference and share claim that rolls back unless durable publication consumes it.
#[derive(Debug)]
struct PendingFileControlBlockClaim {
    /// Open FCB reference and share claim.
    fcb: NonNull<FileControlBlock>,
    /// Exact create FILE_OBJECT used for share accounting.
    file_object: KernelFileObject,
}

impl PendingFileControlBlockClaim {
    /// Returns the exact FCB retained by this provisional share claim.
    const fn file_control_block(&self) -> NonNull<FileControlBlock> {
        self.fcb
    }

    /// Returns the exact FILE_OBJECT used for share accounting and later attachment.
    const fn file_object(&self) -> KernelFileObject {
        self.file_object
    }

    /// Disarms rollback and returns the exact attachment values.
    fn consume(self) -> (NonNull<FileControlBlock>, KernelFileObject) {
        let claim = core::mem::ManuallyDrop::new(self);
        (claim.fcb, claim.file_object)
    }
}

impl Drop for PendingFileControlBlockClaim {
    fn drop(&mut self) {
        abandon_file_control_block(self.fcb, self.file_object);
    }
}

#[expect(
    unsafe_code,
    reason = "the pending claim is reactor-owned while its IRP and mounted VCB retain raw identities"
)]
// SAFETY: The top-level create IRP pins the FILE_OBJECT, and the mounted VCB pins the FCB ledger;
// only the reactor thread consumes or drops this claim.
unsafe impl Send for PendingFileControlBlockClaim {}

/// Publishes prepared node contexts through the stable FILE_OBJECT captured before commit.
#[expect(
    unsafe_code,
    reason = "successful create exclusively publishes one advanced header and prepared CCB"
)]
fn publish_node_stream_raw(
    file_object: KernelFileObject,
    fcb: NonNull<FileControlBlock>,
    handle: Box<OpenedHandle>,
    file_object_flags: CreateFileObjectFlags,
) {
    let fcb = unsafe {
        // SAFETY: The ledger-owned FCB is retained by the open claim being published.
        fcb.as_ref()
    };
    let sections = fcb.stream_section_objects().unwrap_or_else(|_| {
        crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption().bugcheck()
    });
    let file_object = unsafe {
        // SAFETY: Successful create owns the sole publication transition for this FILE_OBJECT.
        &mut *file_object.as_ptr()
    };
    file_object_flags.apply_to(file_object);
    file_object.FsContext = fcb.stream_header().as_ptr();
    file_object.FsContext2 = Box::into_raw(handle).cast::<c_void>();
    file_object.SectionObjectPointer = sections.as_ptr();
}

/// Publishes the mounted volume's header-based stream and one per-handle CCB.
#[expect(
    unsafe_code,
    reason = "successful volume create exclusively publishes one advanced header and prepared CCB"
)]
fn publish_volume_stream(
    mut file_object: UninitializedFileObject<'_>,
    volume: NonNull<VolumeControlBlock>,
    handle: Box<OpenedVolumeHandle>,
    file_object_flags: CreateFileObjectFlags,
) {
    let volume = unsafe {
        // SAFETY: The mounted VCB retains this stable pointer through the direct volume open.
        volume.as_ref()
    };
    let sections = volume.stream_section_objects().unwrap_or_else(|_| {
        crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption().bugcheck()
    });
    let file_object = unsafe {
        // SAFETY: This is the sole successful-create publication for the FILE_OBJECT.
        file_object.as_mut()
    };
    file_object_flags.apply_to(file_object);
    file_object.Flags |= wdk_sys::FO_VOLUME_OPEN;
    file_object.FsContext = volume.stream_header().as_ptr();
    file_object.FsContext2 = Box::into_raw(handle).cast::<c_void>();
    file_object.SectionObjectPointer = sections.as_ptr();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::irp::ReceivedIrp;

    const TEST_FILE_OPEN_DISPOSITION_OPTIONS: wdk_sys::ULONG = 1 << 24;

    /// # Panics
    ///
    /// Panics if create oplock admission loses its residency distinction, accepts atomic policies
    /// without their reservation protocol, or drops the alternate success status.
    #[test]
    fn existing_create_oplock_state_is_policy_and_status_exact() {
        assert!(matches!(
            ExistingCreateOplockState::from_admission(
                crate::irp::OplockCreatePolicy::Ordinary,
                ExistingStreamResidency::FirstOpen,
                NonZeroU32::MIN,
            ),
            ExistingCreateOplockState::Ready
        ));
        assert!(matches!(
            ExistingCreateOplockState::from_admission(
                crate::irp::OplockCreatePolicy::Ordinary,
                ExistingStreamResidency::Resident,
                NonZeroU32::MIN,
            ),
            ExistingCreateOplockState::Check(crate::irp::OplockCreatePolicy::Ordinary)
        ));

        let mut complete =
            ExistingCreateOplockState::Check(crate::irp::OplockCreatePolicy::CompleteIfOplocked);
        assert_eq!(
            complete.accept(wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS),
            Ok(())
        );
        assert!(matches!(
            complete,
            ExistingCreateOplockState::BreakInProgress
        ));

        let mut ordinary =
            ExistingCreateOplockState::Check(crate::irp::OplockCreatePolicy::Ordinary);
        assert_eq!(
            ordinary.accept(wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS),
            Err(DriverError::InternalInvariantViolation)
        );
        assert!(matches!(
            ordinary,
            ExistingCreateOplockState::Check(crate::irp::OplockCreatePolicy::Ordinary)
        ));

        assert!(matches!(
            ExistingCreateOplockState::from_admission(
                crate::irp::OplockCreatePolicy::RequireUnbrokenOplock,
                ExistingStreamResidency::FirstOpen,
                NonZeroU32::MIN,
            ),
            ExistingCreateOplockState::Reserve(NonZeroU32::MIN)
        ));
        assert!(matches!(
            ExistingCreateOplockState::from_admission(
                crate::irp::OplockCreatePolicy::ReserveFilter,
                ExistingStreamResidency::Resident,
                NonZeroU32::MIN,
            ),
            ExistingCreateOplockState::Reserve(NonZeroU32::MIN)
        ));
    }

    /// # Panics
    ///
    /// Panics if a first-open create can enter an existing-stream check state or loses the exact
    /// handle count required by synchronous FsRtl establishment.
    #[test]
    fn new_create_oplock_state_has_only_ready_or_atomic_reservation() {
        assert!(matches!(
            NewCreateOplockState::from_policy(
                crate::irp::OplockCreatePolicy::Ordinary,
                NonZeroU32::MIN,
            ),
            NewCreateOplockState::Ready
        ));
        assert!(matches!(
            NewCreateOplockState::from_policy(
                crate::irp::OplockCreatePolicy::CompleteIfOplocked,
                NonZeroU32::MIN,
            ),
            NewCreateOplockState::Ready
        ));
        assert!(matches!(
            NewCreateOplockState::from_policy(
                crate::irp::OplockCreatePolicy::RequireUnbrokenOplock,
                NonZeroU32::MIN,
            ),
            NewCreateOplockState::Reserve(NonZeroU32::MIN)
        ));
        assert!(matches!(
            NewCreateOplockState::from_policy(
                crate::irp::OplockCreatePolicy::ReserveFilter,
                NonZeroU32::MIN,
            ),
            NewCreateOplockState::Reserve(NonZeroU32::MIN)
        ));
    }

    /// Decodes create parameters through the dispatch boundary.
    /// # Errors
    ///
    /// Returns an error when the fixed test stack cannot be decoded as a create/open request.
    #[expect(
        unsafe_code,
        reason = "the live stack fixtures satisfy ReceivedIrp's raw dispatch-pair contract"
    )]
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

        let mut received = unsafe {
            // SAFETY: Both stack-local fixtures remain live through the active decode operation.
            ReceivedIrp::decode(
                core::ptr::addr_of_mut!(device),
                core::ptr::addr_of_mut!(irp),
            )?
        };
        received.with_active(|active| Ok(active.current_stack()?.create()?.parameters()))
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
    /// Panics when a first-open stream or a read-only resident stream requests native MM work.
    #[test]
    fn existing_write_open_gate_requires_a_resident_writable_regular_file() {
        for access in [
            RegularFileWriteAccess::Denied,
            RegularFileWriteAccess::AppendOnly,
            RegularFileWriteAccess::Positional,
        ] {
            assert_eq!(
                ExistingWriteOpenRequirement::for_regular_file(
                    access,
                    ExistingStreamResidency::FirstOpen,
                ),
                ExistingWriteOpenRequirement::NotRequired
            );
        }
        assert_eq!(
            ExistingWriteOpenRequirement::for_regular_file(
                RegularFileWriteAccess::Denied,
                ExistingStreamResidency::Resident,
            ),
            ExistingWriteOpenRequirement::NotRequired
        );
        for access in [
            RegularFileWriteAccess::AppendOnly,
            RegularFileWriteAccess::Positional,
        ] {
            assert_eq!(
                ExistingWriteOpenRequirement::for_regular_file(
                    access,
                    ExistingStreamResidency::Resident,
                ),
                ExistingWriteOpenRequirement::FlushImageSection
            );
        }
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
    /// Panics when direct volume opens accept create/replace dispositions.
    #[test]
    fn volume_open_accepts_only_existing_open_disposition() {
        assert_eq!(validate_volume_open_create(CreateDisposition::Open), Ok(()));
        for disposition in [
            CreateDisposition::Create,
            CreateDisposition::OpenIf,
            CreateDisposition::Overwrite,
            CreateDisposition::OverwriteIf,
            CreateDisposition::Supersede,
        ] {
            assert_eq!(
                validate_volume_open_create(disposition),
                Err(DriverError::InvalidParameter)
            );
        }
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
            assert!(empty.is_direct_volume_open());
        }

        let mut root_units = [UTF16_BACKSLASH];
        let root_file = file_object_with_name(&mut root_units);
        let root = CreatePathName::decode(&root_file);
        assert!(root.is_ok());
        if let Ok(root) = root {
            assert_eq!(root.rooting(), CreateNameRooting::Absolute);
            assert!(root.components().is_empty());
            assert!(!root.is_direct_volume_open());
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
    #[expect(
        unsafe_code,
        reason = "the live stack fixtures satisfy ReceivedIrp's raw dispatch-pair contract"
    )]
    fn create_path_anchor_rejects_conflicting_absolute_related_object() {
        let vcb = NonNull::<VolumeControlBlock>::dangling();
        let mut related = FILE_OBJECT::default();
        let create = FILE_OBJECT {
            RelatedFileObject: core::ptr::addr_of_mut!(related),
            ..FILE_OBJECT::default()
        };
        let mut create = create;
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::addr_of_mut!(create),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut irp = wdk_sys::IRP::default();
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack);
        let mut received = unsafe {
            // SAFETY: Both stack-local fixtures remain live through the active decode operation.
            ReceivedIrp::decode(
                core::ptr::addr_of_mut!(device),
                core::ptr::addr_of_mut!(irp),
            )
        };
        assert!(received.is_ok());
        let decoded = received.as_mut().map(|received| {
            received.with_active(|active| {
                let file_object =
                    UninitializedFileObject::decode(active.current_stack()?.file_object()?)?;
                CreatePathAnchor::decode(&file_object, vcb, CreateNameRooting::Absolute)
            })
        });

        assert_eq!(
            decoded.ok().and_then(Result::err),
            Some(DriverError::InvalidParameter)
        );
    }
}
