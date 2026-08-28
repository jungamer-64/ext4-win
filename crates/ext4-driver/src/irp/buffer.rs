//! Current-stack decoding and bounded requestor-buffer access.

use super::*;

/// Non-null current IRP stack location.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentIrpStackLocation<'owner> {
    /// Current stack location selected by the I/O Manager.
    pub(super) stack: NonNull<wdk_sys::IO_STACK_LOCATION>,
    /// Prevents this view from outliving the active completion-owner borrow.
    pub(super) owner: core::marker::PhantomData<&'owner wdk_sys::IO_STACK_LOCATION>,
}

impl<'owner> CurrentIrpStackLocation<'owner> {
    /// Binds a raw stack location to an active IRP owner borrow.
    /// # Errors
    ///
    /// Returns an error when `stack` is null.
    pub(super) fn from_active(stack: PIO_STACK_LOCATION) -> Result<Self, DriverError> {
        let Some(stack) = NonNull::new(stack) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self {
            stack,
            owner: core::marker::PhantomData,
        })
    }

    /// Decodes this stack location's filesystem-control minor function.
    pub(crate) fn file_system_control_minor(self) -> FileSystemControlMinorFunction {
        match u32::from(self.raw_minor_function()) {
            MOUNT_VOLUME_MINOR_FUNCTION => FileSystemControlMinorFunction::MountVolume,
            value if value == wdk_sys::IRP_MN_USER_FS_REQUEST => {
                FileSystemControlMinorFunction::UserFsRequest
            }
            _ => FileSystemControlMinorFunction::Unsupported,
        }
    }

    /// Decodes this stack location's directory-control minor function.
    pub(crate) fn directory_control_minor(self) -> DirectoryControlMinorFunction {
        match u32::from(self.raw_minor_function()) {
            value if value == wdk_sys::IRP_MN_QUERY_DIRECTORY => {
                DirectoryControlMinorFunction::QueryDirectory
            }
            value if value == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY => {
                DirectoryControlMinorFunction::NotifyChangeDirectory
            }
            value if value == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX => {
                DirectoryControlMinorFunction::NotifyChangeDirectoryEx
            }
            _ => DirectoryControlMinorFunction::Unsupported,
        }
    }

    /// Returns the raw minor-function byte for local enum decoding only.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn raw_minor_function(self) -> wdk_sys::UCHAR {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        stack.MinorFunction
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    /// # Errors
    ///
    /// Returns an error when the public IRP stack view cannot produce a kernel FILE_OBJECT.
    pub(crate) fn file_object(self) -> Result<ActiveFileObject<'owner>, DriverError> {
        Ok(ActiveFileObject {
            address: self.kernel_file_object()?,
            owner: core::marker::PhantomData,
        })
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    /// # Errors
    ///
    /// Returns an error when the raw `FileObject` pointer in the current stack location is null.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn kernel_file_object(self) -> Result<KernelFileObject, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        unsafe {
            // SAFETY: The active IRP stack retains its FILE_OBJECT for this owner-bound view.
            KernelFileObject::from_raw(stack.FileObject)
        }
        .ok_or(DriverError::InvalidParameter)
    }

    /// Decodes mount-volume parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the VPB or target device object is null, or the output length is not
    /// representable.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn mount_volume(self) -> Result<MountVolumeStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let mount = unsafe {
            // SAFETY: The caller has selected this accessor only for
            // IRP_MN_MOUNT_VOLUME, where the MountVolume union arm is active.
            stack.Parameters.MountVolume
        };

        let Some(vpb) = (unsafe {
            // SAFETY: The I/O Manager retains the mount VPB through this active mount IRP.
            KernelVpb::from_raw(mount.Vpb)
        }) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(target_device) = (unsafe {
            // SAFETY: The I/O Manager retains the mount target device through this mount IRP.
            KernelDevice::from_raw(mount.DeviceObject)
        }) else {
            return Err(DriverError::InvalidParameter);
        };

        Ok(MountVolumeStack {
            vpb,
            target_device,
            output_buffer_length: IrpBufferLength::from_ulong(mount.OutputBufferLength)?,
        })
    }

    /// Decodes user file-system-control parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, buffer lengths are invalid, or the FSCTL
    /// code is unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn file_system_control(self) -> Result<FileSystemControlStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let control = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_USER_FS_REQUEST, where FileSystemControl is active.
            stack.Parameters.FileSystemControl
        };
        self.kernel_file_object()?;
        Ok(FileSystemControlStack {
            input_buffer_length: IrpBufferLength::from_ulong(control.InputBufferLength)?,
            output_buffer_length: IrpBufferLength::from_ulong(control.OutputBufferLength)?,
            fs_control_code: FsControlCode::from_raw(control.FsControlCode)?,
        })
    }

    /// Decodes one buffered device-control request without retaining an IRP stack pointer.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent or either buffer length is not
    /// representable by the driver boundary.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn device_control(self) -> Result<DeviceControlStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active device-control IRP.
            self.stack.as_ref()
        };
        let control = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_DEVICE_CONTROL.
            stack.Parameters.DeviceIoControl
        };
        self.kernel_file_object()?;
        Ok(DeviceControlStack {
            input_buffer_length: IrpBufferLength::from_ulong(control.InputBufferLength)?,
            output_buffer_length: IrpBufferLength::from_ulong(control.OutputBufferLength)?,
            io_control_code: control.IoControlCode,
        })
    }

    /// Decodes create/open parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT or security context is absent, EA length is invalid, or
    /// create parameters are unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn create(self) -> Result<CreateStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let create = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_CREATE,
            // where the Create union arm is active.
            stack.Parameters.Create
        };
        self.kernel_file_object()?;
        let Some(security_context) = NonNull::new(create.SecurityContext) else {
            return Err(DriverError::InvalidParameter);
        };
        let security_context = unsafe {
            // SAFETY: The I/O manager supplies a live security context for
            // IRP_MJ_CREATE while this stack location is active.
            security_context.as_ref()
        };
        Ok(CreateStack {
            parameters: CreateParameters::decode(
                security_context.DesiredAccess,
                create.Options,
                create.ShareAccess,
                IrpBufferLength::from_ulong(create.EaLength)?,
                stack.Flags,
            )?,
        })
    }

    /// Borrows the live ACCESS_STATE carried by an active create stack.
    /// # Errors
    ///
    /// Returns an error when the security context/access state is absent or requestor mode is not
    /// one of the two WDK processor modes.
    #[expect(
        unsafe_code,
        reason = "the active IRP stack retains its create security context and ACCESS_STATE for the owner-bound view"
    )]
    pub(super) fn create_access_state(
        self,
        requestor_mode: wdk_sys::KPROCESSOR_MODE,
        policy: CreateAccessCheck,
    ) -> DriverResult<CreateAccessState<'owner>> {
        let stack = unsafe {
            // SAFETY: `stack` belongs to the active create IRP retained by the owner borrow.
            self.stack.as_ref()
        };
        let create = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_CREATE.
            stack.Parameters.Create
        };
        let security_context =
            NonNull::new(create.SecurityContext).ok_or(DriverError::InvalidParameter)?;
        let access_state = unsafe {
            // SAFETY: The I/O Manager retains the security context for this create IRP.
            NonNull::new(security_context.as_ref().AccessState)
        }
        .ok_or(DriverError::InvalidParameter)?;
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        let user_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::UserMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if requestor_mode != kernel_mode && requestor_mode != user_mode {
            return Err(DriverError::InvalidParameter);
        }
        Ok(CreateAccessState {
            access_state,
            access_check: policy,
            access_mode: match policy {
                CreateAccessCheck::HonorRequestorMode => requestor_mode,
                CreateAccessCheck::ForceUserMode => user_mode,
            },
            owner: core::marker::PhantomData,
        })
    }

    /// Decodes query-volume-information parameters.
    /// # Errors
    ///
    /// Returns an error when the output length is not representable or the volume information class
    /// is unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_volume(self) -> Result<QueryVolumeStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_QUERY_VOLUME_INFORMATION, where QueryVolume is active.
            stack.Parameters.QueryVolume
        };
        Ok(QueryVolumeStack {
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: QueryVolumeInformationClass::from_raw(query.FsInformationClass)?,
        })
    }

    /// Decodes set-volume-information parameters.
    /// # Errors
    ///
    /// Returns an error when the input length is not representable or the volume information class
    /// is unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn set_volume(self) -> Result<SetVolumeStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_SET_VOLUME_INFORMATION, where SetVolume is active.
            stack.Parameters.SetVolume
        };
        Ok(SetVolumeStack {
            length: IrpBufferLength::from_ulong(set.Length)?,
            information_class: SetVolumeInformationClass::from_raw(set.FsInformationClass)?,
        })
    }

    /// Decodes query-file-information parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the output length is invalid, or the file
    /// information class is unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_file(self) -> Result<QueryFileStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_QUERY_INFORMATION, where QueryFile is active.
            stack.Parameters.QueryFile
        };
        self.kernel_file_object()?;
        Ok(QueryFileStack {
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: QueryFileInformationClass::from_raw(query.FileInformationClass)?,
        })
    }

    /// Decodes set-file-information parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the input length is invalid, or the file
    /// information class is unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn set_file(self) -> Result<SetFileStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_SET_INFORMATION, where SetFile is active.
            stack.Parameters.SetFile
        };
        self.kernel_file_object()?;
        Ok(SetFileStack {
            length: IrpBufferLength::from_ulong(set.Length)?,
            information_class: SetFileInformationClass::from_raw(set.FileInformationClass)?,
        })
    }

    /// Decodes query-directory parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the output length is invalid, or the
    /// directory information class is unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_directory(self) -> Result<QueryDirectoryStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_QUERY_DIRECTORY, where QueryDirectory is active.
            stack.Parameters.QueryDirectory
        };
        let cursor_position = if stack_flag(stack.Flags, wdk_sys::SL_INDEX_SPECIFIED) {
            DirectoryCursorPosition::Index(DirectoryEntryIndex(query.FileIndex))
        } else if stack_flag(stack.Flags, wdk_sys::SL_RESTART_SCAN) || !query.FileName.is_null() {
            DirectoryCursorPosition::Restart
        } else {
            DirectoryCursorPosition::Current
        };
        let entry_emission = if stack_flag(stack.Flags, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            DirectoryEntryEmission::Single
        } else {
            DirectoryEntryEmission::Multiple
        };
        self.kernel_file_object()?;
        Ok(QueryDirectoryStack {
            cursor_position,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: DirectoryInformationClass::from_raw(query.FileInformationClass)?,
        })
    }

    /// Returns the requestor filename descriptor for queue-time directory capture.
    /// # Errors
    ///
    /// Returns an error when the current stack location cannot be decoded.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_directory_file_name(
        self,
    ) -> Result<Option<NonNull<wdk_sys::UNICODE_STRING>>, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack during capture.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MN_QUERY_DIRECTORY.
            stack.Parameters.QueryDirectory
        };
        Ok(NonNull::new(query.FileName))
    }

    /// Decodes directory-change-notification parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent or the notification filter is empty or
    /// contains unsupported bits.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn notify_directory(self) -> Result<NotifyDirectoryStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let notify = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_NOTIFY_CHANGE_DIRECTORY, where NotifyDirectory is active.
            stack.Parameters.NotifyDirectory
        };
        self.kernel_file_object()?;
        Ok(NotifyDirectoryStack {
            completion_filter: DirectoryChangeFilter::from_raw(notify.CompletionFilter)?,
            watch_scope: DirectoryWatchScope::from_stack_flags(stack.Flags),
        })
    }

    /// Decodes extended directory-change-notification parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the filter is invalid, or the requested
    /// extended information class is not defined by the current WDK contract.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn notify_directory_ex(
        self,
    ) -> Result<DirectoryNotifyInformationClass, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack for this callback.
            self.stack.as_ref()
        };
        let notify = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX, where NotifyDirectoryEx is active.
            stack.Parameters.NotifyDirectoryEx
        };
        self.kernel_file_object()?;
        DirectoryChangeFilter::from_raw(notify.CompletionFilter)?;
        DirectoryNotifyInformationClass::from_raw(notify.DirectoryNotifyInformationClass)
    }

    /// Decodes query-EA parameters.
    /// # Errors
    ///
    /// Returns an error when an EA name list pointer is missing, the FILE_OBJECT is absent, or
    /// buffer lengths are invalid.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_ea(self) -> Result<QueryEaStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_QUERY_EA,
            // where QueryEa is active.
            stack.Parameters.QueryEa
        };
        let cursor_position = if stack_flag(stack.Flags, wdk_sys::SL_INDEX_SPECIFIED) {
            EaCursorPosition::Index(EaEntryIndex::from_u32(query.EaIndex))
        } else if stack_flag(stack.Flags, wdk_sys::SL_RESTART_SCAN) {
            EaCursorPosition::Restart
        } else {
            EaCursorPosition::Current
        };
        let entry_emission = if stack_flag(stack.Flags, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            EaEntryEmission::Single
        } else {
            EaEntryEmission::Multiple
        };
        self.kernel_file_object()?;
        Ok(QueryEaStack {
            cursor_position,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
        })
    }

    /// Returns the requestor EA-name list for queue-time capture.
    /// # Errors
    ///
    /// Returns an error when the list length is invalid or a non-empty list has no address.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_ea_name_list(
        self,
    ) -> Result<Option<(NonNull<c_void>, IrpBufferLength)>, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack during capture.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_QUERY_EA.
            stack.Parameters.QueryEa
        };
        let length = IrpBufferLength::from_ulong(query.EaListLength)?;
        if length.is_empty() {
            return Ok(None);
        }
        let address = NonNull::new(query.EaList).ok_or(DriverError::InvalidParameter)?;
        Ok(Some((address, length)))
    }

    /// Decodes set-EA parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent or the set-EA input length is invalid.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn set_ea(self) -> Result<SetEaStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_SET_EA,
            // where SetEa is active.
            stack.Parameters.SetEa
        };
        self.kernel_file_object()?;
        Ok(SetEaStack {
            length: IrpBufferLength::from_ulong(set.Length)?,
        })
    }

    /// Decodes query-security parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, requested security bits are unsupported, or
    /// the output length is invalid.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn query_security(self) -> Result<QuerySecurityStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_QUERY_SECURITY, where QuerySecurity is active.
            stack.Parameters.QuerySecurity
        };
        self.kernel_file_object()?;
        Ok(QuerySecurityStack {
            selection: SecuritySelection::from_raw(query.SecurityInformation)?,
            length: IrpBufferLength::from_ulong(query.Length)?,
        })
    }

    /// Decodes set-security parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT or security descriptor is absent, or requested security
    /// bits are unsupported.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn set_security(self) -> Result<SetSecurityStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_SET_SECURITY, where SetSecurity is active.
            stack.Parameters.SetSecurity
        };
        let Some(security_descriptor) = NonNull::new(set.SecurityDescriptor) else {
            return Err(DriverError::InvalidParameter);
        };
        self.kernel_file_object()?;
        Ok(SetSecurityStack {
            selection: SecuritySelection::from_raw(set.SecurityInformation)?,
            security_descriptor,
        })
    }

    /// Decodes read parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the read stack has no FILE_OBJECT or an invalid byte count.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn read(self) -> Result<ReadStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let read = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_READ,
            // where Read is active.
            stack.Parameters.Read
        };
        let byte_offset = unsafe {
            // SAFETY: ByteOffset uses the QuadPart arm for read/write stack locations.
            read.ByteOffset.QuadPart
        };
        self.kernel_file_object()?;
        Ok(ReadStack {
            length: IrpBufferLength::from_ulong(read.Length)?,
            starting_point: ReadStartingPoint::from_quad(byte_offset)?,
            key: ByteRangeLockKey::from_ulong(read.Key),
        })
    }

    /// Decodes write parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the write stack has no FILE_OBJECT or an invalid byte count.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn write(self) -> Result<WriteStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let write = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_WRITE,
            // where Write is active.
            stack.Parameters.Write
        };
        let byte_offset = unsafe {
            // SAFETY: ByteOffset uses the QuadPart arm for read/write stack locations.
            write.ByteOffset.QuadPart
        };
        self.kernel_file_object()?;
        Ok(WriteStack {
            length: IrpBufferLength::from_ulong(write.Length)?,
            starting_point: WriteStartingPoint::from_quad(byte_offset)?,
            key: ByteRangeLockKey::from_ulong(write.Key),
        })
    }
}

/// Kernel-addressable bytes decoded at the IRP boundary.
#[derive(Debug)]
struct IrpByteBuffer {
    /// First buffer byte.
    address: NonNull<u8>,
    /// Buffer byte count.
    length: usize,
}

impl IrpByteBuffer {
    /// Creates byte buffer after length validation.
    /// # Errors
    ///
    /// Returns an error when `length` cannot safely back a Rust slice.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        let max_slice_len =
            usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
        if length > max_slice_len {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { address, length })
    }

    /// Returns the buffer as a byte slice.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: IrpByteBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length)
        }
    }

    /// Returns the buffer as a mutable byte slice.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            // SAFETY: IrpByteBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts_mut(self.address.as_ptr(), self.length)
        }
    }
}

/// Immutable bytes decoded from a buffered or data-input IRP boundary.
#[derive(Debug)]
pub(crate) struct BufferedInput<'owner> {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
    /// Prevents the view from outliving the active completion-owner borrow.
    owner: core::marker::PhantomData<&'owner [u8]>,
}

impl BufferedInput<'_> {
    /// Binds an immutable buffer view to an active completion-owner borrow.
    /// # Errors
    ///
    /// Returns an error when the input buffer length cannot safely back a Rust slice.
    pub(super) fn from_active(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        Ok(Self {
            bytes: IrpByteBuffer::new(address, length)?,
            owner: core::marker::PhantomData,
        })
    }

    /// Returns input bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Mutable bytes decoded from a buffered or data-output IRP boundary.
#[derive(Debug)]
pub(crate) struct BufferedOutput<'owner> {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
    /// Prevents mutable access from outliving the active completion-owner borrow.
    owner: core::marker::PhantomData<&'owner mut [u8]>,
}

impl BufferedOutput<'_> {
    /// Initializes and binds a mutable buffer view to an active completion-owner borrow.
    /// # Errors
    ///
    /// Returns an error when the output buffer length cannot safely back a mutable Rust slice.
    #[expect(
        unsafe_code,
        reason = "the buffered-output boundary initializes raw I/O Manager storage before exposing Rust bytes"
    )]
    pub(super) fn from_active(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        let bytes = IrpByteBuffer::new(address, length)?;
        unsafe {
            // SAFETY: The active METHOD_BUFFERED output contract provides writable system-buffer
            // storage for `length` bytes. Raw initialization occurs before any Rust reference to
            // those bytes exists.
            address.as_ptr().write_bytes(0, length);
        }
        Ok(Self {
            bytes,
            owner: core::marker::PhantomData,
        })
    }

    /// Returns output bytes.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }
}

/// Returns an IRP MDL data buffer address as kernel memory.
/// # Errors
///
/// Returns an error when `length` exceeds the MDL byte count or the MDL cannot be mapped to system
/// address space.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(super) fn mdl_data_buffer_address(
    mdl: NonNull<wdk_sys::MDL>,
    length: IrpBufferLength,
) -> Result<NonNull<u8>, DriverError> {
    let mdl_ref = unsafe {
        // SAFETY: The IRP's MdlAddress is non-null and retained by the I/O Manager until the
        // completion owner completes this IRP.
        mdl.as_ref()
    };
    let mdl_len = usize::try_from(mdl_ref.ByteCount).map_err(|_| DriverError::InvalidParameter)?;
    if length.as_usize() > mdl_len {
        return Err(DriverError::InvalidParameter);
    }

    let address = mapped_mdl_address(mdl, mdl_ref)?;
    Ok(address.cast())
}

/// Implements the address-selection behavior of `MmGetSystemAddressForMdlSafe`.
/// # Errors
///
/// Returns an error when an already-mapped MDL has no mapped address or mapping locked pages fails.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn mapped_mdl_address(
    mdl: NonNull<wdk_sys::MDL>,
    mdl_ref: &wdk_sys::MDL,
) -> Result<NonNull<c_void>, DriverError> {
    let flags = u32::from(u16::from_ne_bytes(mdl_ref.MdlFlags.to_ne_bytes()));
    let mapped_flags = wdk_sys::MDL_MAPPED_TO_SYSTEM_VA | wdk_sys::MDL_SOURCE_IS_NONPAGED_POOL;
    if flags & mapped_flags != 0 {
        return NonNull::new(mdl_ref.MappedSystemVa).ok_or(DriverError::InvalidParameter);
    }

    let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
        .map_err(|_| DriverError::InvalidParameter)?;
    let priority = u32::try_from(wdk_sys::_MM_PAGE_PRIORITY::NormalPagePriority)
        .map_err(|_| DriverError::InvalidParameter)?
        | wdk_sys::MdlMappingNoExecute;
    let address = unsafe {
        // SAFETY: The MDL belongs to the active IRP and describes locked pages
        // supplied by the I/O Manager for direct I/O.
        crate::kernel::ffi::MmMapLockedPagesSpecifyCache(
            mdl.as_ptr(),
            kernel_mode,
            wdk_sys::_MEMORY_CACHING_TYPE::MmCached,
            core::ptr::null_mut(),
            0,
            priority,
        )
    };
    NonNull::new(address).ok_or(DriverError::InsufficientResources)
}

/// Buffer length accepted at the IRP stack boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IrpBufferLength(pub(super) usize);

impl IrpBufferLength {
    /// Decodes a WDK `ULONG` byte count into the driver length domain.
    /// # Errors
    ///
    /// Returns an error when `value` exceeds the maximum Rust slice length.
    pub(super) fn from_ulong(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        let length = usize::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
        let max_slice_len =
            usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
        if length > max_slice_len {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self(length))
    }

    /// Returns the validated byte count.
    pub(crate) const fn as_usize(self) -> usize {
        self.0
    }

    /// Returns whether the request supplied an empty buffer.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Directory entry index selected by a query-directory request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntryIndex(pub(super) u32);

impl DirectoryEntryIndex {
    /// Returns the cursor index.
    pub(crate) const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Initial directory cursor position requested by the I/O Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryCursorPosition {
    /// Continue from the existing CCB cursor.
    Current,
    /// Restart at the beginning of the directory.
    Restart,
    /// Seek to a caller-supplied directory index.
    Index(DirectoryEntryIndex),
}

/// Directory entry emission cardinality requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryEntryEmission {
    /// Emit as many matching entries as fit.
    Multiple,
    /// Emit at most one matching entry.
    Single,
}

/// Scope selected for a directory-change notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryWatchScope {
    /// Observe changes directly below the opened directory.
    DirectChildren,
    /// Observe changes below the opened directory and every descendant.
    Subtree,
}

impl DirectoryWatchScope {
    /// Decodes the directory-control watch-tree stack flag.
    fn from_stack_flags(flags: wdk_sys::UCHAR) -> Self {
        if stack_flag(flags, wdk_sys::SL_WATCH_TREE) {
            Self::Subtree
        } else {
            Self::DirectChildren
        }
    }

    /// Returns whether this request asks to observe every descendant directory.
    pub(crate) const fn watches_subtree(self) -> bool {
        matches!(self, Self::Subtree)
    }
}

/// Validated set of file-system changes requested by a directory notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryChangeFilter(pub(super) wdk_sys::ULONG);

impl DirectoryChangeFilter {
    /// Decodes a Windows completion-filter bit set.
    /// # Errors
    ///
    /// Returns an error when no notification kind is selected or the bit set contains a kind that
    /// Windows does not define for directory notifications.
    pub(super) fn from_raw(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        if value == 0 || value & !wdk_sys::FILE_NOTIFY_VALID_MASK != 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self(value))
    }

    /// Returns the filter bits supported by the driver's namespace-only notifier.
    /// # Errors
    ///
    /// Returns an error when the request asks for attribute, data, security, stream, or other
    /// change kinds that the current notifier cannot report precisely.
    pub(crate) fn namespace_name_filter(self) -> DriverResult<wdk_sys::ULONG> {
        if self.0 & !wdk_sys::FILE_NOTIFY_CHANGE_NAME != 0 {
            return Err(DriverError::NotSupported);
        }
        Ok(self.0)
    }
}

/// EA entry index selected by a query-EA request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EaEntryIndex(pub(super) u32);

impl EaEntryIndex {
    /// Creates an EA entry index from the Windows one-based index field.
    pub(crate) const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the caller-supplied one-based EA entry index.
    pub(crate) const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Starting position selected by a query-EA request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EaCursorPosition {
    /// Continue from the FILE_OBJECT-owned cursor.
    Current,
    /// Restart at the first EA.
    Restart,
    /// Start at a caller-supplied one-based index.
    Index(EaEntryIndex),
}

/// EA entry emission cardinality requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EaEntryEmission {
    /// Emit as many selected EAs as fit.
    Multiple,
    /// Emit at most one selected EA.
    Single,
}

/// Tests one WDK `IO_STACK_LOCATION::Flags` bit while keeping raw flags local to decode.
pub(super) fn stack_flag(flags: wdk_sys::UCHAR, bit: u32) -> bool {
    u32::from(flags) & bit != 0
}
