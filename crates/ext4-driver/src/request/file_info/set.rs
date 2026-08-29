//! File-information mutation planning, decoding, and publication.

use super::*;

/// Applies one supported set-file-information class.
enum SetFilePlan {
    /// The request completed entirely while decoding its synchronous control-plane mutation.
    Complete,
    /// Apply timestamps and overlay attributes to one node.
    Basic {
        /// Caller update copied from the IRP buffer.
        info: wdk_sys::FILE_BASIC_INFORMATION,
        /// Target ext4 node.
        node: NodeId,
    },
    /// Set the exact logical end of file.
    EndOfFile {
        /// Target regular file.
        file: FileNodeId,
        /// Requested logical size.
        size: FileSize,
    },
    /// Shrink allocation when the requested sparse-model size is below EOF.
    Allocation {
        /// Target regular file.
        file: FileNodeId,
        /// Requested allocation bound.
        size: FileSize,
    },
    /// Validate and publish one identity-bound delete-pending target.
    Disposition {
        /// Stable FCB whose shared deletion state is selected.
        fcb: NonNull<FileControlBlock>,
        /// Target ext4 inode identity.
        node: NodeId,
        /// Prepared exact parent/name identity.
        pending: PendingFileDeletion,
        /// Whether validation publishes a new state or reaffirms create-time delete-on-close.
        publication: DeletePendingPublication,
        /// Whether the extended request bypasses the read-only Windows attribute.
        readonly: DeleteReadonlyPolicy,
    },
    /// Commit one fully owned hard-link creation.
    Link {
        /// Caller-independent hard-link domain values.
        mutation: HardLinkMutation,
    },
    /// Commit one fully owned namespace rename.
    Rename {
        /// Caller-independent rename domain values.
        mutation: RenameMutation,
        /// Stable CCB receiving the new location only after durable commit.
        file_object: crate::state::KernelFileObject,
    },
}

#[cfg(test)]
#[path = "tests/set_decoders.rs"]
mod set_decoder_tests;

#[cfg(test)]
#[path = "tests/set_attributes.rs"]
mod set_attribute_tests;

#[cfg(test)]
#[path = "tests/set_disposition.rs"]
mod set_disposition_tests;

#[cfg(test)]
#[path = "tests/set_namespace.rs"]
mod set_namespace_tests;

#[cfg(test)]
#[path = "tests/set_paths.rs"]
mod set_path_tests;

/// Result of one restartable set-information resolve pass.
#[derive(Debug)]
pub(crate) enum SetFileResolution {
    /// No ext4 mutation was staged; all requested control-plane work is complete.
    Complete(IrpCompletion),
    /// A regular-file disposition must flush image/data sections outside the actor.
    PrepareDeletion {
        /// Stable FCB whose stream gate must be acquired.
        fcb: NonNull<FileControlBlock>,
        /// Exact regular-file inode bound to that FCB.
        node: NodeId,
    },
    /// Ext4 mutation requires commit and the driver publication is fully prepared.
    Mutation(SetFilePublication),
}

/// Allocation-free driver publication paired with a set-information mutation.
#[derive(Debug)]
pub(crate) enum SetFilePublication {
    /// No driver-visible state changes after commit.
    None,
    /// Ordered namespace notifications for a committed hard-link mutation.
    HardLink(Box<HardLinkDirectoryChanges>),
    /// Handle-location and notification moves for a committed rename.
    Rename {
        /// Stable CCB update prepared before the first write.
        location: PreparedOpenedLocationPublication,
        /// Fully allocated notification sequence.
        notifications: Box<RenameDirectoryNameChanges>,
    },
}

/// Fully allocated regular-file disposition retained while Cc/MM runs outside the actor.
#[derive(Debug)]
pub(crate) struct PendingDispositionDeletion {
    /// Stable FCB whose shared deletion state will be published.
    fcb: NonNull<FileControlBlock>,
    /// Target ext4 inode identity.
    node: NodeId,
    /// Prepared exact parent/name identity allocated before Cc/MM.
    pending: PendingFileDeletion,
    /// Whether publication creates ordinary state or reaffirms create-time delete-on-close.
    publication: DeletePendingPublication,
    /// Read-only validation policy retained across the external preflight.
    readonly: DeleteReadonlyPolicy,
}

impl PendingDispositionDeletion {
    /// Returns the exact native stream gate target.
    pub(crate) const fn stream_target(&self) -> (NonNull<FileControlBlock>, NodeId) {
        (self.fcb, self.node)
    }

    /// Verifies that the still-live request retains the same FILE_OBJECT/FCB/node identity.
    /// # Errors
    ///
    /// Returns an invariant error if a suspended operation no longer describes the captured
    /// disposition authority.
    fn validate_request(&self, request: &mut PendingIrpLease<'_>) -> DriverResult<()> {
        request.with_active(|active| {
            let current = active.current_stack()?;
            let file_object = current.file_object()?;
            let stack = current.set_file()?;
            if !matches!(
                stack.information_class(),
                SetFileInformationClass::Disposition | SetFileInformationClass::DispositionEx
            ) {
                return Err(DriverError::InternalInvariantViolation);
            }
            let opened = OpenedObject::decode(file_object)?;
            if opened.file_control_block_address() != self.fcb || opened.node() != self.node {
                return Err(DriverError::InternalInvariantViolation);
            }
            opened.require_delete_access()
        })
    }

    /// Publishes the already validated deletion state without allocation or ordinary failure.
    fn publish(self, operations: &mut MountedVolumeAccess<'_>) {
        match self.publication {
            DeletePendingPublication::Publish => {
                operations.set_file_delete_pending(self.fcb, self.pending);
            }
            DeletePendingPublication::AlreadyPublishedByCreate => drop(self.pending),
        }
    }
}

impl SetFilePublication {
    /// Publishes prepared driver state without allocation or ordinary failure.
    pub(crate) fn publish(self, operations: &MountedVolumeAccess<'_>) {
        match self {
            Self::None => {}
            Self::HardLink(changes) => (*changes).report(operations),
            Self::Rename {
                location,
                notifications,
            } => {
                location.publish();
                notifications.report(operations);
            }
        }
    }
}

/// Applies one supported set-file-information class.
/// # Errors
///
/// Returns an error when the selected set-information class has invalid input or its ext4 metadata
/// mutation cannot be committed.
pub(super) fn set_file_information(
    mut request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    pending_disposition: &mut Option<PendingDispositionDeletion>,
    prepared_deletion: Option<&PreparedStreamDeletion>,
) -> DriverResult<SetFileResolution> {
    if let Some(pending) = pending_disposition.as_ref() {
        pending.validate_request(&mut request)?;
        let (fcb, node) = pending.stream_target();
        if !prepared_deletion.is_some_and(|prepared| prepared.authorizes(fcb, node)) {
            return Err(DriverError::InternalInvariantViolation);
        }
        validate_pending_deletion(
            mutation,
            node,
            pending.pending.target_ref(),
            pending.readonly,
        )?;
        let Some(pending) = pending_disposition.take() else {
            return Err(DriverError::InternalInvariantViolation);
        };
        pending.publish(operations);
        return Ok(SetFileResolution::Complete(IrpCompletion::EMPTY));
    }
    let plan = request.with_active(|active| {
        let current = active.current_stack()?;
        let file_object = current.file_object()?;
        let stack = current.set_file()?;
        let mut opened_file = OpenedObject::decode(file_object)?;
        let plan = match stack.information_class() {
            SetFileInformationClass::Basic => SetFilePlan::Basic {
                info: read_basic_information_input(active, stack.length())?,
                node: opened_file.node(),
            },
            SetFileInformationClass::Position => {
                set_position_information(active, stack, &mut opened_file)?;
                SetFilePlan::Complete
            }
            SetFileInformationClass::EndOfFile => {
                let end_of_file = read_end_of_file_input(active, stack.length())?;
                let regular_file = OpenedRegularFile::decode(file_object)?;
                SetFilePlan::EndOfFile {
                    file: regular_file.id(),
                    size: file_size_from_large_integer(end_of_file)?,
                }
            }
            SetFileInformationClass::Allocation => {
                let allocation_size = read_allocation_size_input(active, stack.length())?;
                let regular_file = OpenedRegularFile::decode(file_object)?;
                SetFilePlan::Allocation {
                    file: regular_file.id(),
                    size: file_size_from_large_integer(allocation_size)?,
                }
            }
            SetFileInformationClass::Disposition => {
                disposition_plan(active, stack, &opened_file, DispositionInputFormat::Legacy)?
            }
            SetFileInformationClass::DispositionEx => disposition_plan(
                active,
                stack,
                &opened_file,
                DispositionInputFormat::Extended,
            )?,
            SetFileInformationClass::Link => SetFilePlan::Link {
                mutation: HardLinkMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    HardLinkInformationFormat::ReplaceIfExistsByte,
                )?,
            },
            SetFileInformationClass::LinkEx => SetFilePlan::Link {
                mutation: HardLinkMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    HardLinkInformationFormat::Flags,
                )?,
            },
            SetFileInformationClass::Rename => SetFilePlan::Rename {
                mutation: RenameMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    RenameInformationFormat::ReplaceIfExistsByte,
                )?,
                file_object: opened_file.file_object(),
            },
            SetFileInformationClass::RenameEx => SetFilePlan::Rename {
                mutation: RenameMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    RenameInformationFormat::Flags,
                )?,
                file_object: opened_file.file_object(),
            },
        };
        Ok::<_, DriverError>(plan)
    })?;
    match plan {
        SetFilePlan::Complete => {
            return Ok(SetFileResolution::Complete(IrpCompletion::EMPTY));
        }
        SetFilePlan::Basic { info, node } => set_basic_information(info, node, mutation)?,
        SetFilePlan::EndOfFile { file, size } => set_regular_file_size(mutation, file, size)?,
        SetFilePlan::Allocation { file, size } => {
            let current = regular_file_size(mutation, file)?;
            if size < current {
                set_regular_file_size(mutation, file, size)?;
            }
        }
        SetFilePlan::Disposition {
            fcb,
            node,
            pending,
            publication,
            readonly,
        } => {
            validate_pending_deletion(mutation, node, pending.target_ref(), readonly)?;
            let pending = PendingDispositionDeletion {
                fcb,
                node,
                pending,
                publication,
                readonly,
            };
            if matches!(node, NodeId::File(_)) {
                *pending_disposition = Some(pending);
                return Ok(SetFileResolution::PrepareDeletion { fcb, node });
            }
            pending.publish(operations);
            return Ok(SetFileResolution::Complete(IrpCompletion::EMPTY));
        }
        SetFilePlan::Link { mutation: request } => {
            let changes = set_hard_link_information(request, operations, mutation)?;
            let changes = memory::boxed_try_with(move || Ok(changes))?;
            return Ok(SetFileResolution::Mutation(SetFilePublication::HardLink(
                changes,
            )));
        }
        SetFilePlan::Rename {
            mutation: rename,
            file_object,
        } => {
            let publication = set_rename_information(rename, operations, mutation)?;
            return Ok(SetFileResolution::Mutation(match publication {
                PreparedRename::Unchanged => SetFilePublication::None,
                PreparedRename::Changed {
                    location,
                    notifications,
                } => {
                    let location =
                        request_location_publication(&mut request, file_object, location)?;
                    SetFilePublication::Rename {
                        location,
                        notifications,
                    }
                }
            }));
        }
    }
    Ok(SetFileResolution::Mutation(SetFilePublication::None))
}

/// Binds a preallocated rename location to the exact CCB retained by the pending request.
/// # Errors
///
/// Returns an error when the active IRP stack or opened FILE_OBJECT identity is invalid.
fn request_location_publication(
    request: &mut PendingIrpLease<'_>,
    expected: crate::state::KernelFileObject,
    location: OpenedLocation,
) -> DriverResult<PreparedOpenedLocationPublication> {
    request.with_active(|active| {
        let current = active.current_stack()?;
        let file_object = current.file_object()?;
        let _stack = current.set_file()?;
        let opened = OpenedObject::decode(file_object)?;
        if opened.file_object() != expected {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(opened.prepare_location_publication(location))
    })
}

/// Applies FILE_POSITION_INFORMATION to the synchronous FILE_OBJECT position.
/// # Errors
///
/// Returns an error when the input is truncated, negative, asynchronous, or misaligned for a
/// no-intermediate-buffering handle.
fn set_position_information(
    active: &ActiveIrp<'_>,
    stack: SetFileStack,
    opened_file: &mut OpenedObject<'_>,
) -> DriverResult<()> {
    let current_byte_offset = read_position_input(active, stack.length())?;
    let position = file_offset_from_large_integer(current_byte_offset)?;
    opened_file
        .data_transfer_mode()
        .validate_position(position.bytes())?;
    opened_file.set_current_file_position(position)
}

/// Applies FILE_BASIC_INFORMATION timestamps and overlay attributes.
/// # Errors
///
/// Returns an error when the input structure is truncated, timestamps or attributes are invalid, or
/// the resulting ext4 metadata transaction fails.
fn set_basic_information(
    info: wdk_sys::FILE_BASIC_INFORMATION,
    node_id: NodeId,
    transaction: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<()> {
    let metadata = metadata_from_node(transaction, node_id)?;
    let times = set_basic_times(metadata.times, info)?;
    let attributes = set_basic_attributes(metadata, info.FileAttributes)?;
    if times == metadata.times && attributes.is_empty() {
        return Ok(());
    }

    let node = transaction.node(node_id)?;
    if times != metadata.times {
        transaction.set_times(node, times)?;
    }
    if let Some(security) = attributes.security() {
        transaction.set_posix_security(node, security)?;
    }
    if let Some(overlay) = attributes.overlay() {
        transaction.set_windows_overlay(node, overlay)?;
    }
    Ok(())
}

/// Raw Windows disposition layout selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispositionInputFormat {
    /// `FILE_DISPOSITION_INFORMATION`.
    Legacy,
    /// `FILE_DISPOSITION_INFORMATION_EX`.
    Extended,
}

/// Fully decoded effect and target state for one disposition request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileDispositionRequest {
    /// Requested deletion-state transition.
    action: FileDispositionAction,
    /// State selected by ordinary disposition or create-time delete-on-close.
    target: FileDispositionTarget,
}

impl FileDispositionRequest {
    /// Creates a request that retains the namespace link.
    const fn keep(target: FileDispositionTarget) -> Self {
        Self {
            action: FileDispositionAction::Keep,
            target,
        }
    }

    /// Creates a request that validates deletion under one read-only policy.
    const fn delete(target: FileDispositionTarget, readonly: DeleteReadonlyRequest) -> Self {
        Self {
            action: FileDispositionAction::Delete(readonly),
            target,
        }
    }
}

/// Deletion-state transition requested by a disposition input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileDispositionAction {
    /// Retain the link, cancelling only an ordinary mutable disposition state.
    Keep,
    /// Validate deletion, then publish or reaffirm the selected target state.
    Delete(DeleteReadonlyRequest),
}

/// Deletion state selected by extended `FILE_DISPOSITION_ON_CLOSE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileDispositionTarget {
    /// Operate on the ordinary cancellable disposition state.
    Mutable,
    /// Reaffirm the mandatory state created by `FILE_DELETE_ON_CLOSE`.
    CreateDeleteOnClose,
}

impl FileDispositionTarget {
    /// Validates that ON_CLOSE refers to a handle opened with `FILE_DELETE_ON_CLOSE`.
    /// # Errors
    ///
    /// Returns not-supported when an ON_CLOSE request targets an ordinary retained handle.
    const fn validate(self, create_deletion: CreateDeletion) -> DriverResult<()> {
        match (self, create_deletion) {
            (Self::CreateDeleteOnClose, CreateDeletion::Retain) => Err(DriverError::NotSupported),
            (Self::Mutable, CreateDeletion::Retain | CreateDeletion::DeleteOnClose)
            | (Self::CreateDeleteOnClose, CreateDeletion::DeleteOnClose) => Ok(()),
        }
    }
}

/// Post-validation mutation selected without optional FCB authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeletePendingPublication {
    /// Publish a new cancellable disposition state to this exact FCB.
    Publish,
    /// Create already published the mandatory delete-on-close state.
    AlreadyPublishedByCreate,
}

/// Raw read-only behavior selected before binding handle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeleteReadonlyRequest {
    /// A Windows read-only attribute prevents deletion.
    Enforce,
    /// The request asks to bypass read-only protection when its handle has authority.
    Ignore,
}

impl DeleteReadonlyRequest {
    /// Binds requested behavior to retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn bind(self, access: FileAttributesWriteAccess) -> DeleteReadonlyPolicy {
        match self {
            Self::Enforce => DeleteReadonlyPolicy::Enforce,
            Self::Ignore => DeleteReadonlyPolicy::Ignore(access),
        }
    }
}

/// Read-only attribute policy with all required handle authority attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteReadonlyPolicy {
    /// A Windows read-only attribute prevents deletion.
    Enforce,
    /// Bypass read-only protection only when `FILE_WRITE_ATTRIBUTES` was retained.
    Ignore(FileAttributesWriteAccess),
}

impl DeleteReadonlyPolicy {
    /// Validates the target attributes under the bound override authority.
    /// # Errors
    ///
    /// Returns cannot-delete when a read-only target is protected or the requested override lacks
    /// `FILE_WRITE_ATTRIBUTES`.
    const fn validate_attributes(self, attributes: wdk_sys::ULONG) -> DriverResult<()> {
        if attributes & wdk_sys::FILE_ATTRIBUTE_READONLY == 0 {
            return Ok(());
        }
        match self {
            Self::Enforce | Self::Ignore(FileAttributesWriteAccess::Denied) => {
                Err(DriverError::CannotDelete)
            }
            Self::Ignore(FileAttributesWriteAccess::Granted) => Ok(()),
        }
    }
}

/// Builds a disposition plan from one fully decoded handle and buffered input.
/// # Errors
///
/// Returns an error when the input is malformed, the handle lacks `DELETE`, unsupported extended
/// semantics are requested, or the handle has no deletable directory-entry identity.
fn disposition_plan(
    active: &ActiveIrp<'_>,
    stack: SetFileStack,
    opened: &OpenedObject<'_>,
    format: DispositionInputFormat,
) -> DriverResult<SetFilePlan> {
    opened.require_delete_access()?;
    let request = match format {
        DispositionInputFormat::Legacy => {
            if !read_legacy_disposition_input(active, stack.length())? {
                FileDispositionRequest::keep(FileDispositionTarget::Mutable)
            } else {
                FileDispositionRequest::delete(
                    FileDispositionTarget::Mutable,
                    DeleteReadonlyRequest::Enforce,
                )
            }
        }
        DispositionInputFormat::Extended => {
            decode_extended_disposition(read_extended_disposition_input(active, stack.length())?)?
        }
    };
    request.target.validate(opened.create_deletion())?;
    match request.action {
        FileDispositionAction::Keep => {
            if request.target == FileDispositionTarget::Mutable
                && opened.create_deletion() == CreateDeletion::Retain
            {
                opened.clear_delete_pending();
            }
            Ok(SetFilePlan::Complete)
        }
        FileDispositionAction::Delete(readonly) => {
            let readonly = readonly.bind(opened.file_attributes_write_access());
            let (pending, publication) = match request.target {
                FileDispositionTarget::Mutable => (
                    opened.prepare_pending_deletion()?,
                    DeletePendingPublication::Publish,
                ),
                FileDispositionTarget::CreateDeleteOnClose => (
                    PendingFileDeletion::try_from_delete_on_close(opened.location())?,
                    DeletePendingPublication::AlreadyPublishedByCreate,
                ),
            };
            Ok(SetFilePlan::Disposition {
                fcb: opened.file_control_block_address(),
                node: opened.node(),
                pending,
                publication,
                readonly,
            })
        }
    }
}

/// Decodes the supported non-POSIX subset of `FILE_DISPOSITION_INFORMATION_EX`.
/// # Errors
///
/// Returns not-supported when a delete or ON_CLOSE update requests POSIX semantics, or when unknown
/// flags are present. The force-image flag is accepted because every supported non-POSIX delete
/// executes the image/data-section preflight.
fn decode_extended_disposition(flags: wdk_sys::ULONG) -> DriverResult<FileDispositionRequest> {
    const KNOWN_FLAGS: wdk_sys::ULONG = wdk_sys::FILE_DISPOSITION_DELETE
        | wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS
        | wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK
        | wdk_sys::FILE_DISPOSITION_ON_CLOSE
        | wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(DriverError::NotSupported);
    }
    let delete = flags & wdk_sys::FILE_DISPOSITION_DELETE != 0;
    let posix = flags & wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS != 0;
    let on_close = flags & wdk_sys::FILE_DISPOSITION_ON_CLOSE != 0;
    let ignore_readonly = flags & wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE != 0;
    if (delete && posix) || (on_close && posix) {
        return Err(DriverError::NotSupported);
    }
    let target = if on_close {
        FileDispositionTarget::CreateDeleteOnClose
    } else {
        FileDispositionTarget::Mutable
    };
    if !delete {
        return Ok(FileDispositionRequest::keep(target));
    }
    let readonly = if ignore_readonly {
        DeleteReadonlyRequest::Ignore
    } else {
        DeleteReadonlyRequest::Enforce
    };
    Ok(FileDispositionRequest::delete(target, readonly))
}

/// Validates the exact parent/name/inode identity before publishing delete-pending.
/// # Errors
///
/// Returns cannot-delete when the link no longer identifies the opened inode or has the read-only
/// attribute, directory-not-empty for a non-empty directory, or the underlying read error.
pub(crate) fn validate_pending_deletion(
    read: &mut impl CommittedReadPass,
    node: NodeId,
    target: &FileDeleteTarget,
    readonly: DeleteReadonlyPolicy,
) -> DriverResult<()> {
    let parent = read.load_directory(target.parent())?;
    match read.lookup_child(&parent, target.name())? {
        ChildLookup::Found(child) if *child.node() == node => {}
        ChildLookup::Found(_) | ChildLookup::NotFound => return Err(DriverError::CannotDelete),
    }
    let metadata = metadata_from_node(read, node)?;
    readonly.validate_attributes(file_attributes(metadata))?;
    if let NodeId::Directory(directory_id) = node {
        let directory = read.load_directory(directory_id)?;
        let mut cursor = DirectoryCursor::start();
        loop {
            let batch = read.scan_directory(&directory, &cursor, DirectoryScanLimit::MAX)?;
            if batch
                .entries()
                .iter()
                .any(|entry| !matches!(entry.entry().name().bytes(), b"." | b".."))
            {
                return Err(DriverError::from(ext4_core::Error::DirectoryNotEmpty));
            }
            if batch.is_exhausted() {
                break;
            }
            cursor = *batch.continuation();
        }
    }
    Ok(())
}

/// Owned hard-link mutation decoded completely before the first suspension.
#[derive(Debug)]
struct HardLinkMutation {
    /// Existing inode that receives the additional name.
    source: HardLinkNodeId,
    /// Destination path with its explicit resolution base.
    target: NamespaceTargetPath,
    /// Existing-target behavior decoded from the link information class.
    target_collision: HardLinkTargetCollision,
}

impl HardLinkMutation {
    /// Copies every caller and handle-dependent hard-link field into owned domain values.
    /// # Errors
    ///
    /// Returns an error when the source is a directory or deleted link, the handle has no parent
    /// identity, or the input path/flags are invalid.
    fn decode(
        active: &ActiveIrp<'_>,
        stack: SetFileStack,
        opened_file: &OpenedObject<'_>,
        format: HardLinkInformationFormat,
    ) -> DriverResult<Self> {
        if opened_file.delete_pending() {
            return Err(DriverError::AccessDenied);
        }
        let source = HardLinkNodeId::try_from(opened_file.node())
            .map_err(|_| DriverError::FileIsDirectory)?;
        let source_parent = match opened_file.location() {
            OpenedLocation::DirectoryEntry { parent, .. } => *parent,
            OpenedLocation::Root => return Err(DriverError::FileIsDirectory),
            OpenedLocation::FileReference => return Err(DriverError::NotSupported),
        };
        let input = active.buffered_input(stack.length())?;
        let target_collision = format.target_collision(input.as_slice())?;
        let target = NamespaceTargetPath::decode(input.as_slice(), source_parent)?;
        Ok(Self {
            source,
            target,
            target_collision,
        })
    }
}

/// Prepared hard-link destination with the exact ext4 name selected for replacement.
#[derive(Debug)]
enum PreparedHardLinkDestination {
    /// No Windows-visible target exists.
    Vacant,
    /// The caller authorized replacement of this exact existing entry.
    Replace {
        /// Existing case-preserving ext4 name.
        existing_name: Ext4Name,
    },
}

/// Source link-count transition implied by the prepared destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardLinkCountEffect {
    /// Replacing another name for the same inode preserves the count.
    Preserve,
    /// Creating a new name or replacing a different inode increments the count.
    Increase,
}

impl HardLinkCountEffect {
    /// Enforces the Windows hard-link count boundary only when the count will increase.
    /// # Errors
    ///
    /// Returns `TooManyLinks` once the source already has 1024 links.
    fn validate(self, links: Ext4LinkCount) -> DriverResult<()> {
        const WINDOWS_HARD_LINK_LIMIT: u16 = 1024;
        match self {
            Self::Preserve => Ok(()),
            Self::Increase if links.get() < WINDOWS_HARD_LINK_LIMIT => Ok(()),
            Self::Increase => Err(DriverError::from(ext4_core::Error::TooManyLinks)),
        }
    }
}

/// Ordered post-commit directory notifications for one hard-link mutation.
#[derive(Debug)]
pub(crate) struct HardLinkDirectoryChanges {
    /// First and always-present notification.
    first: DirectoryChange,
    /// Second notification required only for a case-preserving spelling change.
    second: Option<Box<DirectoryChange>>,
}

impl HardLinkDirectoryChanges {
    /// Reports the committed notification sequence.
    fn report(self, operations: &MountedVolumeAccess<'_>) {
        operations.report_directory_change(self.first);
        if let Some(second) = self.second {
            operations.report_directory_change(*second);
        }
    }
}

/// Applies one owned FILE_LINK_INFORMATION mutation to the ext4 namespace.
/// # Errors
///
/// Returns an error when target resolution, replacement policy, link limits, metadata staging, or
/// the journal transaction fails.
fn set_hard_link_information(
    request: HardLinkMutation,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<HardLinkDirectoryChanges> {
    let HardLinkMutation {
        source,
        target,
        target_collision,
    } = request;
    let source_node = NodeId::from(source);
    let (target_parent, target_name) = resolve_namespace_target(mutation, &target)?;
    operations.ensure_node_openable(NodeId::Directory(target_parent))?;
    let source_metadata = metadata_from_node(mutation, source_node)?;
    let (destination, count_effect, changes) = prepare_hard_link_destination(
        operations,
        mutation,
        source_node,
        target_parent,
        &target_name,
        target.target_name(),
        target_collision,
    )?;
    count_effect.validate(source_metadata.links_count)?;
    let archive_overlay = hard_link_archive_overlay(source_metadata.overlay_attributes)?;

    let source = mutation.hard_link_source(source)?;
    let target_parent = mutation.directory(target_parent)?;
    if let Some(overlay) = archive_overlay {
        let node = mutation.node(source_node)?;
        mutation.set_windows_overlay(node, overlay)?;
    }
    match &destination {
        PreparedHardLinkDestination::Vacant => {
            mutation.create_hard_link(
                source,
                target_parent,
                &target_name,
                HardLinkDestination::Vacant,
            )?;
        }
        PreparedHardLinkDestination::Replace { existing_name } => {
            mutation.create_hard_link(
                source,
                target_parent,
                &target_name,
                HardLinkDestination::Replace { existing_name },
            )?;
        }
    }
    Ok(changes)
}

/// Resolves collision policy into one exact hard-link destination and notification plan.
/// # Errors
///
/// Returns an error when a rejected collision exists, the target is a directory, read-only,
/// delete-pending, or still has an active handle.
fn prepare_hard_link_destination(
    operations: &mut MountedVolumeAccess<'_>,
    read: &mut impl CommittedReadPass,
    source_node: NodeId,
    target_parent: DirectoryNodeId,
    target_name: &Ext4Name,
    target_windows_name: &WindowsName,
    target_collision: HardLinkTargetCollision,
) -> DriverResult<(
    PreparedHardLinkDestination,
    HardLinkCountEffect,
    HardLinkDirectoryChanges,
)> {
    let parent = read.load_directory(target_parent)?;
    let target = read.lookup_windows_child(
        &parent,
        target_windows_name,
        ext4_core::WindowsNameMatch::CaseInsensitive,
    )?;
    let ChildLookup::Found(target) = target else {
        return Ok((
            PreparedHardLinkDestination::Vacant,
            HardLinkCountEffect::Increase,
            HardLinkDirectoryChanges {
                first: DirectoryChange::new(
                    target_parent,
                    target_name,
                    source_node,
                    DirectoryChangeAction::Added,
                )?,
                second: None,
            },
        ));
    };
    if target_collision == HardLinkTargetCollision::Reject {
        return Err(DriverError::ObjectNameCollision);
    }
    let target_node = *target.node();
    if matches!(target_node, NodeId::Directory(_)) {
        return Err(DriverError::CannotDelete);
    }
    operations.ensure_node_openable(target_node)?;
    if target_node != source_node {
        operations.ensure_node_replaceable(target_node)?;
    }
    let target_metadata = metadata_from_node(read, target_node)?;
    if file_attributes(target_metadata) & wdk_sys::FILE_ATTRIBUTE_READONLY != 0 {
        return Err(DriverError::CannotDelete);
    }

    let existing_name = target.name().try_to_owned_name()?;
    let changes = if target.name() == target_name {
        HardLinkDirectoryChanges {
            first: DirectoryChange::hard_link_replaced(target_parent, target_name)?,
            second: None,
        }
    } else {
        HardLinkDirectoryChanges {
            first: DirectoryChange::new(
                target_parent,
                target.name(),
                target_node,
                DirectoryChangeAction::Removed,
            )?,
            second: Some(
                Box::try_new(DirectoryChange::new(
                    target_parent,
                    target_name,
                    source_node,
                    DirectoryChangeAction::Added,
                )?)
                .map_err(|_| DriverError::InsufficientResources)?,
            ),
        }
    };
    let count_effect = if target_node == source_node {
        HardLinkCountEffect::Preserve
    } else {
        HardLinkCountEffect::Increase
    };
    Ok((
        PreparedHardLinkDestination::Replace { existing_name },
        count_effect,
        changes,
    ))
}

/// Returns the archive overlay update required by successful hard-link creation.
/// # Errors
///
/// Returns an error when the combined overlay cannot inhabit the ext4 Windows-attribute domain.
fn hard_link_archive_overlay(
    current_attributes: wdk_sys::ULONG,
) -> DriverResult<Option<WindowsOverlay>> {
    if current_attributes & Ext4WindowsAttributes::ARCHIVE != 0 {
        return Ok(None);
    }
    Ok(Some(WindowsOverlay::new(Ext4WindowsAttributes::new(
        current_attributes | Ext4WindowsAttributes::ARCHIVE,
    )?)))
}

/// Owned rename mutation decoded completely before the first suspension.
#[derive(Debug)]
struct RenameMutation {
    /// Current parent identity.
    source_parent: DirectoryNodeId,
    /// Current exact ext4 name.
    source_name: Ext4Name,
    /// Node being moved.
    source_node: NodeId,
    /// Destination path with its explicit resolution base.
    target: NamespaceTargetPath,
    /// Existing-target behavior decoded from the rename information class.
    target_collision: RenameTargetCollision,
}

impl RenameMutation {
    /// Copies every caller and handle-dependent rename field into owned domain values.
    /// # Errors
    ///
    /// Returns an error when the input layout, source location, or destination path is invalid.
    fn decode(
        active: &ActiveIrp<'_>,
        stack: SetFileStack,
        opened_file: &OpenedObject<'_>,
        format: RenameInformationFormat,
    ) -> DriverResult<Self> {
        if opened_file.delete_pending() {
            return Err(DriverError::DeletePending);
        }
        let (source_parent, source_name) = match opened_file.location() {
            OpenedLocation::DirectoryEntry { parent, name } => (*parent, name.try_to_owned_name()?),
            OpenedLocation::Root => {
                return Err(DriverError::from(ext4_core::Error::CannotRemoveRoot));
            }
            OpenedLocation::FileReference => return Err(DriverError::NotSupported),
        };
        let input = active.buffered_input(stack.length())?;
        let target_collision = format.target_collision(input.as_slice())?;
        let target = NamespaceTargetPath::decode(input.as_slice(), source_parent)?;
        Ok(Self {
            source_parent,
            source_name,
            source_node: opened_file.node(),
            target,
            target_collision,
        })
    }
}

/// Result of a committed rename with mutually exclusive no-op and changed states.
enum PreparedRename {
    /// The transaction preserved the existing handle location and emitted no notifications.
    Unchanged,
    /// The committed namespace move requires one handle-location update and exact notifications.
    Changed {
        /// New CCB location.
        location: OpenedLocation,
        /// Namespace notifications derived before commit.
        notifications: Box<RenameDirectoryNameChanges>,
    },
}

/// Applies one owned FILE_RENAME_INFORMATION mutation to the ext4 namespace.
/// # Errors
///
/// Returns an error when target resolution, notification preparation, or the rename transaction
/// fails.
fn set_rename_information(
    request: RenameMutation,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<PreparedRename> {
    let RenameMutation {
        source_parent,
        source_name,
        source_node,
        target,
        target_collision,
    } = request;
    let (target_parent, target_name) = resolve_namespace_target(mutation, &target)?;
    operations.ensure_node_openable(NodeId::Directory(source_parent))?;
    operations.ensure_node_openable(NodeId::Directory(target_parent))?;
    let notifications = RenameDirectoryNameChanges::prepare(
        operations,
        mutation,
        RenameNotificationRequest {
            source_parent,
            source_name: &source_name,
            source_node,
            target_parent,
            target_name: &target_name,
            target_collision,
        },
    )?;
    let notifications = notifications
        .map(Box::try_new)
        .transpose()
        .map_err(|_| DriverError::InsufficientResources)?;
    let source_parent = mutation.directory(source_parent)?;
    let target_parent = mutation.directory(target_parent)?;
    mutation.rename_child(
        source_parent,
        &source_name,
        target_parent,
        &target_name,
        target_collision,
    )?;
    match notifications {
        Some(notifications) => Ok(PreparedRename::Changed {
            location: OpenedLocation::DirectoryEntry {
                parent: target_parent.id(),
                name: target_name,
            },
            notifications,
        }),
        None => Ok(PreparedRename::Unchanged),
    }
}

/// Committed directory-name changes caused by one non-no-op rename operation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RenameDirectoryNameChanges {
    /// Existing target entry removed by a replace-capable rename.
    replaced_target: Option<DirectoryChange>,
    /// Source entry under its former name.
    old_source_name: DirectoryChange,
    /// Source entry under its new name.
    new_source_name: DirectoryChange,
}

/// Fully resolved namespace identities used to prepare rename notifications.
#[derive(Debug)]
struct RenameNotificationRequest<'name> {
    /// Source directory before the rename.
    source_parent: DirectoryNodeId,
    /// Source ext4 name before the rename.
    source_name: &'name Ext4Name,
    /// Typed node being renamed.
    source_node: NodeId,
    /// Destination directory after the rename.
    target_parent: DirectoryNodeId,
    /// Destination ext4 name after the rename.
    target_name: &'name Ext4Name,
    /// Validated collision policy.
    target_collision: RenameTargetCollision,
}

impl RenameDirectoryNameChanges {
    /// Prepares the exact name-change events that a successful rename will publish.
    /// # Errors
    ///
    /// Returns an error when a replace-capable target cannot be read or a visible child name
    /// cannot be represented in the Windows notification namespace.
    fn prepare(
        operations: &mut MountedVolumeAccess<'_>,
        read: &mut impl CommittedReadPass,
        request: RenameNotificationRequest<'_>,
    ) -> DriverResult<Option<Self>> {
        let RenameNotificationRequest {
            source_parent,
            source_name,
            source_node,
            target_parent,
            target_name,
            target_collision,
        } = request;
        if source_parent == target_parent && source_name == target_name {
            return Ok(None);
        }

        let replaced_target = match target_collision {
            RenameTargetCollision::Reject => None,
            RenameTargetCollision::Replace => {
                let parent = read.load_directory(target_parent)?;
                match read.lookup_windows_child(
                    &parent,
                    &WindowsName::from_ext4(target_name)?,
                    ext4_core::WindowsNameMatch::CaseInsensitive,
                )? {
                    ChildLookup::Found(child) if *child.node() == source_node => return Ok(None),
                    ChildLookup::Found(child) => {
                        operations.ensure_node_replaceable(*child.node())?;
                        Some(DirectoryChange::new(
                            target_parent,
                            child.name(),
                            *child.node(),
                            DirectoryChangeAction::Removed,
                        )?)
                    }
                    ChildLookup::NotFound => None,
                }
            }
        };

        Ok(Some(Self {
            replaced_target,
            old_source_name: DirectoryChange::new(
                source_parent,
                source_name,
                source_node,
                DirectoryChangeAction::RenamedOldName,
            )?,
            new_source_name: DirectoryChange::new(
                target_parent,
                target_name,
                source_node,
                DirectoryChangeAction::RenamedNewName,
            )?,
        }))
    }

    /// Reports every name transition after the corresponding ext4 transaction commits.
    fn report(self, operations: &MountedVolumeAccess<'_>) {
        if let Some(replaced_target) = self.replaced_target {
            operations.report_directory_change(replaced_target);
        }
        operations.report_directory_change(self.old_source_name);
        operations.report_directory_change(self.new_source_name);
    }
}

/// Sets a regular file size by extending sparse or truncating allocated ranges.
/// # Errors
///
/// Returns an error when the current file size cannot be loaded or the ext4 resize transaction
/// fails.
fn set_regular_file_size(
    transaction: &mut DriverMutationPass<'_, '_, '_>,
    file_id: FileNodeId,
    new_size: FileSize,
) -> DriverResult<()> {
    let current = regular_file_size(transaction, file_id)?;
    if new_size == current {
        return Ok(());
    }

    let file = transaction.file(file_id)?;
    if new_size > current {
        transaction.extend_file(file, new_size)?;
    } else {
        transaction.truncate_file(file, new_size)?;
    }
    Ok(())
}
/// Passes one checked buffered set-information input to its typed record decoder.
/// # Errors
///
/// Returns an error when the IRP buffer cannot be captured or typed record decoding fails.
fn decode_file_information_input<T>(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
    decode: impl FnOnce(&[u8]) -> DriverResult<T>,
) -> DriverResult<T> {
    let input = active.buffered_input(length)?;
    decode(input.as_slice())
}

/// Decodes one complete fixed-size record from checked little-endian fields.
/// # Errors
///
/// Returns an error when `bytes` is smaller than the record or a scalar field is out of range.
fn decode_fixed_file_information<T>(
    bytes: &[u8],
    record_length: usize,
    decode: impl FnOnce(LittleEndianInput<'_>) -> DriverResult<T>,
) -> DriverResult<T> {
    let record = bytes
        .get(..record_length)
        .ok_or(DriverError::BufferTooSmall)?;
    decode(LittleEndianInput::new(record))
}

/// Decodes `FILE_BASIC_INFORMATION` without treating an arbitrary `Copy` type as a wire record.
/// # Errors
///
/// Returns an error when the declared input is short or any scalar field is out of range.
fn read_basic_information_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<wdk_sys::FILE_BASIC_INFORMATION> {
    decode_file_information_input(active, length, decode_basic_information_record)
}

/// Decodes a complete `FILE_BASIC_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_basic_information_record(bytes: &[u8]) -> DriverResult<wdk_sys::FILE_BASIC_INFORMATION> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>(),
        |input| {
            Ok(wdk_sys::FILE_BASIC_INFORMATION {
                CreationTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        CreationTime
                    )))?,
                },
                LastAccessTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        LastAccessTime
                    )))?,
                },
                LastWriteTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        LastWriteTime
                    )))?,
                },
                ChangeTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        ChangeTime
                    )))?,
                },
                FileAttributes: input.read_u32(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_BASIC_INFORMATION,
                    FileAttributes
                )))?,
            })
        },
    )
}

/// Decodes the signed EOF field from `FILE_END_OF_FILE_INFORMATION`.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_end_of_file_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<LARGE_INTEGER> {
    decode_file_information_input(active, length, decode_end_of_file_record)
}

/// Decodes a complete `FILE_END_OF_FILE_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_end_of_file_record(bytes: &[u8]) -> DriverResult<LARGE_INTEGER> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_END_OF_FILE_INFORMATION>(),
        |input| {
            Ok(LARGE_INTEGER {
                QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_END_OF_FILE_INFORMATION,
                    EndOfFile
                )))?,
            })
        },
    )
}

/// Decodes the signed allocation-size field from `FILE_ALLOCATION_INFORMATION`.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_allocation_size_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<LARGE_INTEGER> {
    decode_file_information_input(active, length, decode_allocation_size_record)
}

/// Decodes a complete `FILE_ALLOCATION_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_allocation_size_record(bytes: &[u8]) -> DriverResult<LARGE_INTEGER> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_ALLOCATION_INFORMATION>(),
        |input| {
            Ok(LARGE_INTEGER {
                QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_ALLOCATION_INFORMATION,
                    AllocationSize
                )))?,
            })
        },
    )
}

/// Decodes the signed cursor from `FILE_POSITION_INFORMATION`.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_position_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<LARGE_INTEGER> {
    decode_file_information_input(active, length, decode_position_record)
}

/// Decodes a complete `FILE_POSITION_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_position_record(bytes: &[u8]) -> DriverResult<LARGE_INTEGER> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>(),
        |input| {
            Ok(LARGE_INTEGER {
                QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_POSITION_INFORMATION,
                    CurrentByteOffset
                )))?,
            })
        },
    )
}

/// Decodes `FILE_DISPOSITION_INFORMATION::DeleteFile` as a domain boolean.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_legacy_disposition_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<bool> {
    decode_file_information_input(active, length, decode_legacy_disposition_record)
}

/// Decodes a complete `FILE_DISPOSITION_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_legacy_disposition_record(bytes: &[u8]) -> DriverResult<bool> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION>(),
        |input| {
            Ok(input.read_u8(WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_DISPOSITION_INFORMATION,
                DeleteFile
            )))? != 0)
        },
    )
}

/// Decodes `FILE_DISPOSITION_INFORMATION_EX::Flags` as its checked wire integer.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_extended_disposition_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<u32> {
    decode_file_information_input(active, length, decode_extended_disposition_record)
}

/// Decodes a complete `FILE_DISPOSITION_INFORMATION_EX` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_extended_disposition_record(bytes: &[u8]) -> DriverResult<u32> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION_EX>(),
        |input| {
            input.read_u32(WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_DISPOSITION_INFORMATION_EX,
                Flags
            )))
        },
    )
}

/// Decoded variable-length namespace destination shared by rename and hard-link information.
#[derive(Debug, Eq, PartialEq)]
struct NamespaceTargetPath {
    /// Directory from which the path starts.
    base: NamespaceTargetBase,
    /// Non-empty path below `base`.
    path: NonEmptyWindowsPath,
}

/// Starting directory selected by Windows namespace-target path syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceTargetBase {
    /// A single relative name starts in the source link's current parent.
    OpenedParent(DirectoryNodeId),
    /// A leading backslash starts at the mounted volume root.
    VolumeRoot,
}

impl NamespaceTargetPath {
    /// Decodes the common FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION path layout.
    /// # Errors
    ///
    /// Returns an error when the input is truncated, carries an unsupported root handle, has an
    /// invalid name length, or encodes a relative multi-component path.
    fn decode(bytes: &[u8], opened_parent: DirectoryNodeId) -> DriverResult<Self> {
        if bytes.len() < core::mem::size_of::<wdk_sys::FILE_LINK_INFORMATION>() {
            return Err(DriverError::InfoLengthMismatch);
        }
        reject_root_directory(bytes)?;
        let name_length = usize::try_from(
            LittleEndianInput::new(bytes)
                .read_u32(wire_offset(FILE_NAMESPACE_NAME_LENGTH_OFFSET))?,
        )
        .map_err(|_| DriverError::InvalidParameter)?;
        if name_length == 0 || name_length & 1 != 0 {
            return Err(DriverError::InvalidParameter);
        }
        let name_bytes = input_range(bytes, FILE_NAMESPACE_NAME_OFFSET, name_length)?;
        let units = utf16_units_from_le_bytes(name_bytes)?;
        let (base, path_units) = match units.as_slice().split_first() {
            Some((first, rest)) if *first == UTF16_BACKSLASH => {
                (NamespaceTargetBase::VolumeRoot, rest)
            }
            Some(_) if units.as_slice().contains(&UTF16_BACKSLASH) => {
                return Err(DriverError::InvalidParameter);
            }
            Some(_) => (
                NamespaceTargetBase::OpenedParent(opened_parent),
                units.as_slice(),
            ),
            None => return Err(DriverError::InvalidParameter),
        };
        Ok(Self {
            base,
            path: NonEmptyWindowsPath::from_utf16_path(path_units)?,
        })
    }

    /// Returns the directory from which resolution starts.
    const fn base(&self) -> NamespaceTargetBase {
        self.base
    }

    /// Returns parent components before the target name.
    fn parents(&self) -> &[WindowsName] {
        self.path.parents()
    }

    /// Returns the final target name.
    fn target_name(&self) -> &WindowsName {
        self.path.target_name()
    }
}

/// Existing-target behavior decoded from a hard-link information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardLinkTargetCollision {
    /// The Windows-visible destination must be vacant.
    Reject,
    /// One non-directory destination entry may be replaced.
    Replace,
}

/// FILE_LINK_INFORMATION union arm selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardLinkInformationFormat {
    /// `FileLinkInformation` exposes a BOOLEAN ReplaceIfExists field.
    ReplaceIfExistsByte,
    /// `FileLinkInformationEx` exposes a ULONG Flags field.
    Flags,
}

impl HardLinkInformationFormat {
    /// Decodes target-collision semantics from the selected hard-link input format.
    /// # Errors
    ///
    /// Returns not-supported when extended semantics cannot be represented faithfully.
    fn target_collision(self, bytes: &[u8]) -> DriverResult<HardLinkTargetCollision> {
        match self {
            Self::ReplaceIfExistsByte => match bytes
                .get(FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET)
                .ok_or(DriverError::BufferTooSmall)?
            {
                0 => Ok(HardLinkTargetCollision::Reject),
                _ => Ok(HardLinkTargetCollision::Replace),
            },
            Self::Flags => {
                let flags = LittleEndianInput::new(bytes)
                    .read_u32(wire_offset(FILE_NAMESPACE_FLAGS_OFFSET))?;
                if flags & !wdk_sys::FILE_LINK_REPLACE_IF_EXISTS != 0 {
                    return Err(DriverError::NotSupported);
                }
                if flags & wdk_sys::FILE_LINK_REPLACE_IF_EXISTS != 0 {
                    Ok(HardLinkTargetCollision::Replace)
                } else {
                    Ok(HardLinkTargetCollision::Reject)
                }
            }
        }
    }
}

/// FILE_RENAME_INFORMATION union arm selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenameInformationFormat {
    /// `FileRenameInformation` exposes a BOOLEAN ReplaceIfExists field.
    ReplaceIfExistsByte,
    /// `FileRenameInformationEx` exposes a ULONG Flags field.
    Flags,
}

impl RenameInformationFormat {
    /// Decodes target-collision semantics from the selected rename input format.
    /// # Errors
    ///
    /// Returns an error when unsupported rename-ex flags are set.
    fn target_collision(self, bytes: &[u8]) -> DriverResult<RenameTargetCollision> {
        match self {
            Self::ReplaceIfExistsByte => match bytes
                .get(FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET)
                .ok_or(DriverError::BufferTooSmall)?
            {
                0 => Ok(RenameTargetCollision::Reject),
                _ => Ok(RenameTargetCollision::Replace),
            },
            Self::Flags => {
                let flags = LittleEndianInput::new(bytes)
                    .read_u32(wire_offset(FILE_NAMESPACE_FLAGS_OFFSET))?;
                if flags & !SUPPORTED_RENAME_EX_FLAGS != 0 {
                    return Err(DriverError::NotSupported);
                }
                if flags & wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS != 0 {
                    Ok(RenameTargetCollision::Replace)
                } else {
                    Ok(RenameTargetCollision::Reject)
                }
            }
        }
    }
}

/// Non-empty root-relative Windows path.
#[derive(Debug, Eq, PartialEq)]
struct NonEmptyWindowsPath {
    /// Parent path components from root to target parent.
    parents: DriverVec<WindowsName>,
    /// Final path component being renamed to.
    target_name: WindowsName,
}

impl NonEmptyWindowsPath {
    /// Splits a root-relative UTF-16 path into validated Windows components.
    /// # Errors
    ///
    /// Returns an error when the path is empty after root separators are removed or any component is
    /// not a valid Windows name.
    fn from_utf16_path(units: &[u16]) -> DriverResult<Self> {
        if units.is_empty()
            || units
                .split(|unit| *unit == UTF16_BACKSLASH)
                .any(<[u16]>::is_empty)
        {
            return Err(DriverError::InvalidParameter);
        }
        let mut components = DriverVec::new();
        for component in units.split(|unit| *unit == UTF16_BACKSLASH) {
            components
                .try_push_owned(WindowsName::from_utf16(component)?)
                .map_err(|error| error.into_parts().0)?;
        }
        let target_name = components.pop().ok_or(DriverError::InvalidParameter)?;
        Ok(Self {
            parents: components,
            target_name,
        })
    }

    /// Parent path components from root to target parent.
    fn parents(&self) -> &[WindowsName] {
        self.parents.as_slice()
    }

    /// Final path component.
    const fn target_name(&self) -> &WindowsName {
        &self.target_name
    }
}

/// Offset of the legacy namespace-information ReplaceIfExists field.
const FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET: usize = 0;
/// Offset of the extended namespace-information Flags field.
const FILE_NAMESPACE_FLAGS_OFFSET: usize = 0;
/// Offset of the namespace-information RootDirectory field.
const FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET: usize = 8;
/// Offset of the namespace-information FileNameLength field.
const FILE_NAMESPACE_NAME_LENGTH_OFFSET: usize = 16;
/// Offset of the namespace-information FileName field.
const FILE_NAMESPACE_NAME_OFFSET: usize = 20;
/// FILE_RENAME_INFORMATION_EX flags handled by this driver.
const SUPPORTED_RENAME_EX_FLAGS: wdk_sys::ULONG =
    wdk_sys::FILE_RENAME_IGNORE_READONLY_ATTRIBUTE | wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS;
/// UTF-16 backslash separator.
pub(super) const UTF16_BACKSLASH: u16 = 0x005C;

/// Rejects namespace-information payloads carrying an unsupported root handle.
/// # Errors
///
/// Returns an error when the root-directory handle field is present and nonzero.
fn reject_root_directory(bytes: &[u8]) -> DriverResult<()> {
    if input_range(
        bytes,
        FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET,
        core::mem::size_of::<wdk_sys::HANDLE>(),
    )?
    .iter()
    .any(|byte| *byte != 0)
    {
        Err(DriverError::NotSupported)
    } else {
        Ok(())
    }
}

/// Decodes little-endian UTF-16 units from a byte buffer.
/// # Errors
///
/// Returns an error when `bytes` has an odd length or cannot be split into two-byte units.
fn utf16_units_from_le_bytes(bytes: &[u8]) -> DriverResult<DriverVec<u16>> {
    if bytes.len() & 1 != 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut units = DriverVec::new();
    let (chunks, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    for chunk in chunks {
        let unit = u16::from_le_bytes(*chunk);
        units.try_push(unit)?;
    }
    Ok(units)
}

/// Resolves the target parent directory and final ext4 name for a namespace mutation.
/// # Errors
///
/// Returns an error when any parent component is absent or not a directory, or the target Windows
/// name cannot be converted to an ext4 name.
fn resolve_namespace_target(
    read: &mut impl CommittedReadPass,
    target: &NamespaceTargetPath,
) -> DriverResult<(DirectoryNodeId, Ext4Name)> {
    let mut parent_id = match target.base() {
        NamespaceTargetBase::OpenedParent(parent) => parent,
        NamespaceTargetBase::VolumeRoot => DirectoryNodeId::ROOT,
    };
    for component in target.parents() {
        let parent = read
            .load_directory(parent_id)
            .map_err(|_| DriverError::ObjectPathNotFound)?;
        let child = read.lookup_windows_child(
            &parent,
            component,
            ext4_core::WindowsNameMatch::CaseInsensitive,
        )?;
        match child {
            ChildLookup::Found(child) => {
                let NodeId::Directory(directory_id) = *child.node() else {
                    return Err(DriverError::ObjectPathNotFound);
                };
                if read
                    .read_windows_symlink_reparse_point(NodeId::Directory(directory_id))?
                    .is_some()
                {
                    return Err(DriverError::NotSupported);
                }
                parent_id = directory_id;
            }
            ChildLookup::NotFound => return Err(DriverError::ObjectPathNotFound),
        };
    }
    Ok((parent_id, target.target_name().to_ext4()?))
}

/// Returns an immutable checked input byte range.
/// # Errors
///
/// Returns an error when `offset..offset + length` overflows or is outside `bytes`.
fn input_range(bytes: &[u8], offset: usize, length: usize) -> DriverResult<&[u8]> {
    wire_range(offset, length)?.read_from(bytes)
}

/// Builds a complete ext4 timestamp set from FILE_BASIC_INFORMATION.
/// # Errors
///
/// Returns an error when any supplied Windows timestamp is negative, unsupported, or cannot be
/// converted to Unix seconds.
fn set_basic_times(
    current: Ext4Times,
    info: wdk_sys::FILE_BASIC_INFORMATION,
) -> DriverResult<Ext4Times> {
    Ok(Ext4Times::new(
        windows_time_field(info.LastAccessTime, current.accessed())?,
        windows_time_field(info.LastWriteTime, current.modified())?,
        windows_time_field(info.ChangeTime, current.changed())?,
        windows_time_field(info.CreationTime, current.created())?,
    ))
}

/// Selects one timestamp field, preserving the current value for sentinel inputs.
/// # Errors
///
/// Returns an error when `value` is a negative non-sentinel timestamp or Windows cannot convert it
/// to Unix seconds.
#[expect(
    unsafe_code,
    reason = "Windows time conversion crosses the audited RtlTimeToSecondsSince1970 ABI"
)]
fn windows_time_field(value: LARGE_INTEGER, current: Ext4Timestamp) -> DriverResult<Ext4Timestamp> {
    let quad = large_integer_quad(value);
    if quad == WINDOWS_TIME_UNCHANGED || quad == WINDOWS_TIME_PRESERVE {
        return Ok(current);
    }
    if quad < 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut time = value;
    let mut seconds: wdk_sys::ULONG = 0;
    let converted = unsafe {
        // SAFETY: Both pointers reference writable stack storage valid for the
        // duration of the conversion call.
        crate::kernel::ffi::RtlTimeToSecondsSince1970(
            core::ptr::addr_of_mut!(time),
            core::ptr::addr_of_mut!(seconds),
        )
    };
    if converted == 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(Ext4Timestamp::from_unix_seconds(seconds))
}

/// Windows FILE_BASIC_INFORMATION sentinel for preserving a timestamp.
const WINDOWS_TIME_UNCHANGED: i64 = 0;
/// Additional Windows sentinel used by callers to preserve timestamp state.
const WINDOWS_TIME_PRESERVE: i64 = -1;
/// POSIX write bits that make Windows READONLY false.
const POSIX_WRITE_BITS: u16 = 0o222;
/// Owner write bit restored when Windows READONLY is cleared.
const POSIX_OWNER_WRITE_BIT: u16 = 0o200;

/// Domain updates derived from FILE_BASIC_INFORMATION attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BasicAttributeUpdate {
    /// POSIX security update needed to reflect FILE_ATTRIBUTE_READONLY.
    security: Option<Ext4Security>,
    /// Windows overlay xattr update for attributes not owned by POSIX mode or node kind.
    overlay: Option<WindowsOverlay>,
}

impl BasicAttributeUpdate {
    /// Creates an empty attribute update.
    const fn empty() -> Self {
        Self {
            security: None,
            overlay: None,
        }
    }

    /// Creates an attribute update from independent domain mutations.
    const fn new(security: Option<Ext4Security>, overlay: Option<WindowsOverlay>) -> Self {
        Self { security, overlay }
    }

    /// Returns whether this update has no domain mutations.
    const fn is_empty(self) -> bool {
        self.security.is_none() && self.overlay.is_none()
    }

    /// POSIX security update.
    const fn security(self) -> Option<Ext4Security> {
        self.security
    }

    /// Windows overlay update.
    const fn overlay(self) -> Option<WindowsOverlay> {
        self.overlay
    }
}

/// Builds overlay metadata from FILE_BASIC_INFORMATION attributes.
/// # Errors
///
/// Returns an error when requested attributes contradict the node kind or include unsupported bits.
fn set_basic_attributes(
    metadata: FileMetadata,
    attributes: wdk_sys::ULONG,
) -> DriverResult<BasicAttributeUpdate> {
    if attributes == 0 {
        return Ok(BasicAttributeUpdate::empty());
    }
    validate_kind_attribute(metadata, attributes)?;

    let accepted = Ext4WindowsAttributes::SUPPORTED_MASK
        | wdk_sys::FILE_ATTRIBUTE_READONLY
        | wdk_sys::FILE_ATTRIBUTE_NORMAL
        | wdk_sys::FILE_ATTRIBUTE_DIRECTORY
        | wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
    if attributes & !accepted != 0 {
        return Err(DriverError::NotSupported);
    }

    let security = readonly_security_update(metadata.security, attributes)?;
    let overlay_bits = attributes & Ext4WindowsAttributes::SUPPORTED_MASK;
    let overlay = if overlay_bits == metadata.overlay_attributes {
        None
    } else {
        Some(WindowsOverlay::new(Ext4WindowsAttributes::new(
            overlay_bits,
        )?))
    };
    Ok(BasicAttributeUpdate::new(security, overlay))
}

/// Builds a POSIX security update for FILE_ATTRIBUTE_READONLY.
/// # Errors
///
/// Returns an error when the adjusted permissions cannot be represented.
fn readonly_security_update(
    security: Ext4Security,
    attributes: wdk_sys::ULONG,
) -> DriverResult<Option<Ext4Security>> {
    let current_permissions = security.permissions().as_u16();
    let requested_permissions = if attributes & wdk_sys::FILE_ATTRIBUTE_READONLY != 0 {
        current_permissions & !POSIX_WRITE_BITS
    } else {
        current_permissions | POSIX_OWNER_WRITE_BIT
    };
    if requested_permissions == current_permissions {
        return Ok(None);
    }
    Ok(Some(Ext4Security::new(
        security.owner(),
        Ext4Permissions::new(requested_permissions)?,
    )))
}

/// Rejects node-kind attributes that contradict the opened ext4 node or reparse state.
/// # Errors
///
/// Returns an error when directory or reparse-point attributes do not match opened metadata.
fn validate_kind_attribute(metadata: FileMetadata, attributes: wdk_sys::ULONG) -> DriverResult<()> {
    if attributes & wdk_sys::FILE_ATTRIBUTE_DIRECTORY != 0
        && metadata.kind != FileMetadataKind::Directory
    {
        return Err(DriverError::InvalidParameter);
    }
    if attributes & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT != 0
        && metadata.reparse_point == FileMetadataReparsePoint::None
    {
        return Err(DriverError::InvalidParameter);
    }
    Ok(())
}

/// Returns a non-negative file size from a Windows LARGE_INTEGER.
/// # Errors
///
/// Returns an error when the LARGE_INTEGER contains a negative size.
pub(super) fn file_size_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileSize> {
    let value = large_integer_quad(value);
    if value < 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(FileSize::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns a non-negative file offset from a Windows LARGE_INTEGER.
/// # Errors
///
/// Returns an error when the LARGE_INTEGER contains a negative offset.
fn file_offset_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileOffset> {
    let value = large_integer_quad(value);
    Ok(FileOffset::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns the current size of a regular file inode.
/// # Errors
///
/// Returns an error when `file_id` cannot be loaded as a regular file.
pub(super) fn regular_file_size(
    read: &mut impl CommittedReadPass,
    file_id: FileNodeId,
) -> DriverResult<FileSize> {
    Ok(read.load_file(file_id)?.size())
}

/// Returns the signed payload of a LARGE_INTEGER.
#[expect(
    unsafe_code,
    reason = "LARGE_INTEGER exposes its signed payload through the generated WDK union field"
)]
fn large_integer_quad(value: LARGE_INTEGER) -> i64 {
    unsafe {
        // SAFETY: `QuadPart` is the LARGE_INTEGER representation used by this
        // driver for Windows time and file-size values.
        value.QuadPart
    }
}
