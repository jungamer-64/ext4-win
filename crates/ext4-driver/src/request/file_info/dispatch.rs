//! Top-level file-information, notification, lock, and oplock dispatch.

use super::*;

/// Executes file information queries.
/// # Errors
///
/// Returns an error when query stack decoding or information packing fails.
pub(crate) fn query(
    request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    query_file_information(request, read)
}

/// Executes file information mutations.
/// # Errors
///
/// Returns an error when set stack decoding or the requested file mutation fails.
pub(crate) fn set(
    request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    pending_disposition: &mut Option<PendingDispositionDeletion>,
    prepared_deletion: Option<&PreparedStreamDeletion>,
) -> DriverResult<SetFileResolution> {
    set_file_information(
        request,
        operations,
        mutation,
        pending_disposition,
        prepared_deletion,
    )
}

/// Transfers one queued directory-change IRP to the VCB's FsRtl notification list.
#[expect(
    unsafe_code,
    reason = "the active notification IRP retains the mounted VCB borrowed for FsRtl registration"
)]
pub(crate) fn notify_change_directory(mut owned: OwnedIrp) -> wdk_sys::NTSTATUS {
    let registration = owned.request().with_active(|active| {
        DirectoryNotificationRequest::decode(active).and_then(|mut request| {
            let registration = request.registration()?;
            let volume = request.opened_directory().volume();
            let vcb = unsafe {
                // SAFETY: OpenedDirectory was decoded from this active pending IRP.
                volume.as_ref()
            };
            Ok((NonNull::from(vcb.directory_change_notifier()), registration))
        })
    });
    match registration {
        Ok((notifier, registration)) => {
            owned.delegate_directory_notification(notifier, registration)
        }
        Err(error) => owned.complete_result(Err(error)),
    }
}

/// Directory notification selected from a valid notify-change IRP.
#[derive(Debug)]
pub(crate) struct DirectoryNotificationRequest<'owner> {
    /// Opened directory whose FILE_OBJECT owns this notification.
    opened_directory: OpenedDirectory<'owner>,
    /// Change kinds that may complete this request.
    completion_filter: DirectoryChangeFilter,
    /// Direct-child or descendant directory scope.
    watch_scope: DirectoryWatchScope,
}

impl<'owner> DirectoryNotificationRequest<'owner> {
    /// Decodes the active directory-change stack location.
    /// # Errors
    ///
    /// Returns an error when the stack is malformed or its FILE_OBJECT is not an opened directory.
    fn decode(target: &'owner mut ActiveIrp<'_>) -> DriverResult<Self> {
        let current = target.current_stack()?;
        let file_object = current.file_object()?;
        let stack = current.notify_directory()?;
        Ok(Self {
            opened_directory: OpenedDirectory::decode(file_object)?,
            completion_filter: stack.completion_filter(),
            watch_scope: stack.watch_scope(),
        })
    }

    /// Returns the directory that owns this notification request.
    pub(crate) fn opened_directory(&self) -> &OpenedDirectory<'owner> {
        &self.opened_directory
    }

    /// Converts this request into the exact FsRtl registration semantics this driver supports.
    /// # Errors
    ///
    /// Returns an error when recursive watching or non-name completion filters are requested.
    fn registration(&mut self) -> DriverResult<DirectoryNotificationRegistration> {
        if self.watch_scope.watches_subtree() {
            return Err(DriverError::NotSupported);
        }
        let full_directory_name = self.opened_directory.notification_directory_name()?;
        Ok(DirectoryNotificationRegistration::new(
            full_directory_name,
            self.opened_directory.notification_context(),
            self.completion_filter.namespace_name_filter()?,
        ))
    }
}

/// Executes byte-range lock requests.
/// # Errors
///
/// Returns an error when the lock stack is malformed or the target is not an opened regular file.
pub(crate) fn lock_control(target: &mut ActiveIrp<'_>) -> DriverResult<NonNull<FileControlBlock>> {
    let file_object = target.current_stack()?.file_object()?;
    let opened = OpenedRegularFile::decode(file_object)?;
    Ok(NonNull::from(opened.file_control_block()))
}

/// Selects the namespace-stream FCB for a standard FsRtl-owned oplock FSCTL.
/// # Errors
///
/// Returns an error when a user FSCTL stack or its opened namespace context is malformed.
pub(crate) fn oplock_control(target: &mut ActiveIrp<'_>) -> DriverResult<OplockControlTarget> {
    let current = target.current_stack()?;
    if current.file_system_control_minor()
        != crate::irp::FileSystemControlMinorFunction::UserFsRequest
    {
        return Err(DriverError::InvalidDeviceRequest);
    }
    let control = current.file_system_control()?;
    if !control.fs_control_code().is_oplock() {
        return Err(DriverError::InvalidDeviceRequest);
    }
    let action = if control.fs_control_code() == crate::irp::FsControlCode::RequestOplock {
        if control.input_buffer_length().is_empty() {
            control.fs_control_code().oplock_action(&[])?
        } else {
            let input = target.buffered_input(control.input_buffer_length())?;
            control.fs_control_code().oplock_action(input.as_slice())?
        }
    } else {
        control.fs_control_code().oplock_action(&[])?
    };
    let file_object = current.file_object()?;
    let opened = OpenedObject::decode(file_object)?;
    Ok(OplockControlTarget {
        file_control_block: NonNull::from(opened.file_control_block()),
        action,
    })
}

/// Exact namespace stream and semantic oplock action decoded from one live FSCTL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OplockControlTarget {
    /// Stable FCB retained by the queued FILE_OBJECT.
    pub(crate) file_control_block: NonNull<FileControlBlock>,
    /// Whether this request can grant a new oplock or only advances an existing break.
    pub(crate) action: crate::irp::OplockControlAction,
}
