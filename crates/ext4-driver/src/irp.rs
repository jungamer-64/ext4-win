//! Typed IRP boundary shared by FSD dispatch modules.

use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::FileOffset;
use wdk_sys::{PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP};

use crate::status::DriverError;

/// Non-null dispatch target decoded from raw WDK callback inputs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DispatchTarget {
    /// Device object receiving the IRP.
    device: NonNull<wdk_sys::DEVICE_OBJECT>,
    /// IRP being dispatched.
    irp: NonNull<wdk_sys::IRP>,
}

impl DispatchTarget {
    /// Decodes raw WDK dispatch pointers.
    pub(crate) fn decode(device: PDEVICE_OBJECT, irp: PIRP) -> Result<Self, DriverError> {
        let Some(device) = NonNull::new(device) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(irp) = NonNull::new(irp) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { device, irp })
    }

    /// Returns the raw device object pointer.
    pub(crate) const fn device(self) -> NonNull<wdk_sys::DEVICE_OBJECT> {
        self.device
    }

    /// Returns the raw IRP pointer.
    pub(crate) const fn irp(self) -> NonNull<wdk_sys::IRP> {
        self.irp
    }

    /// Returns the buffered I/O system buffer for this IRP.
    pub(crate) fn system_buffer(self) -> Option<NonNull<core::ffi::c_void>> {
        let irp = unsafe {
            // SAFETY: DispatchTarget owns a non-null IRP pointer decoded from
            // the WDK dispatch boundary for the duration of this callback.
            self.irp.as_ref()
        };
        let system_buffer = unsafe {
            // SAFETY: SystemBuffer is the active AssociatedIrp arm for
            // buffered requests delivered to this driver.
            irp.AssociatedIrp.SystemBuffer
        };
        NonNull::new(system_buffer)
    }

    /// Returns the read/write IRP data buffer as kernel memory.
    pub(crate) fn data_buffer(self, length: usize) -> Result<IrpDataBuffer, DriverError> {
        if let Some(system_buffer) = self.system_buffer() {
            return IrpDataBuffer::new(system_buffer.cast(), length);
        }

        let irp = unsafe {
            // SAFETY: DispatchTarget owns a non-null IRP pointer decoded from
            // the WDK dispatch boundary for the duration of this callback.
            self.irp.as_ref()
        };
        let Some(mdl) = NonNull::new(irp.MdlAddress) else {
            return Err(DriverError::InvalidParameter);
        };
        mdl_data_buffer(mdl, length)
    }

    /// Returns the IRP user buffer as kernel-addressable memory.
    pub(crate) fn user_buffer(self, length: usize) -> Result<IrpDataBuffer, DriverError> {
        let irp = unsafe {
            // SAFETY: DispatchTarget owns a non-null IRP pointer decoded from
            // the WDK dispatch boundary for the duration of this callback.
            self.irp.as_ref()
        };
        let Some(buffer) = NonNull::new(irp.UserBuffer) else {
            return Err(DriverError::InvalidParameter);
        };
        IrpDataBuffer::new(buffer.cast(), length)
    }

    /// Stores the byte count returned by this IRP.
    pub(crate) fn set_information(self, information: wdk_sys::ULONG_PTR) {
        let irp = unsafe {
            // SAFETY: DispatchTarget owns a non-null IRP pointer decoded from
            // the WDK dispatch boundary for the duration of this callback.
            self.irp.as_ptr().as_mut()
        };
        if let Some(irp) = irp {
            irp.IoStatus.Information = information;
        }
    }

    /// Returns the current stack location selected by the I/O Manager.
    pub(crate) fn current_stack(self) -> Result<CurrentIrpStackLocation, DriverError> {
        let irp = unsafe {
            // SAFETY: DispatchTarget owns a non-null IRP pointer decoded from
            // the WDK dispatch boundary for the duration of this callback.
            self.irp.as_ref()
        };
        let tail_overlay = unsafe {
            // SAFETY: CurrentStackLocation is stored through the IRP tail
            // overlay for active IRPs delivered to driver dispatch routines.
            irp.Tail.Overlay
        };
        let current_stack = unsafe {
            // SAFETY: The list overlay contains the current stack pointer in
            // active dispatch IRPs.
            tail_overlay
                .__bindgen_anon_2
                .__bindgen_anon_1
                .CurrentStackLocation
        };
        CurrentIrpStackLocation::from_raw(current_stack)
    }
}

/// Non-null current IRP stack location.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentIrpStackLocation {
    /// Current stack location selected by the I/O Manager.
    stack: NonNull<wdk_sys::IO_STACK_LOCATION>,
}

impl CurrentIrpStackLocation {
    /// Decodes a raw stack location pointer.
    fn from_raw(stack: PIO_STACK_LOCATION) -> Result<Self, DriverError> {
        let Some(stack) = NonNull::new(stack) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { stack })
    }

    /// Returns the IRP minor function.
    pub(crate) fn minor_function(self) -> wdk_sys::UCHAR {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        stack.MinorFunction
    }

    /// Decodes mount-volume parameters from the current stack location.
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

        let Some(vpb) = NonNull::new(mount.Vpb) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(target_device) = NonNull::new(mount.DeviceObject) else {
            return Err(DriverError::InvalidParameter);
        };

        Ok(MountVolumeStack {
            vpb,
            target_device,
            output_buffer_length: IrpBufferLength::from_ulong(mount.OutputBufferLength)?,
        })
    }

    /// Decodes user file-system-control parameters from the current stack location.
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
        Ok(FileSystemControlStack {
            file_object: self.file_object()?,
            input_buffer_length: IrpBufferLength::from_ulong(control.InputBufferLength)?,
            output_buffer_length: IrpBufferLength::from_ulong(control.OutputBufferLength)?,
            fs_control_code: control.FsControlCode,
        })
    }

    /// Decodes create/open parameters from the current stack location.
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
        let Some(file_object) = NonNull::new(stack.FileObject) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(security_context) = NonNull::new(create.SecurityContext) else {
            return Err(DriverError::InvalidParameter);
        };
        let security_context = unsafe {
            // SAFETY: The I/O manager supplies a live security context for
            // IRP_MJ_CREATE while this stack location is active.
            security_context.as_ref()
        };
        Ok(CreateStack {
            file_object,
            desired_access: security_context.DesiredAccess,
            options: create.Options,
            share_access: create.ShareAccess,
            ea_length: IrpBufferLength::from_ulong(create.EaLength)?,
        })
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    pub(crate) fn file_object(self) -> Result<NonNull<wdk_sys::FILE_OBJECT>, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        NonNull::new(stack.FileObject).ok_or(DriverError::InvalidParameter)
    }

    /// Decodes query-volume-information parameters.
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
            information_class: query.FsInformationClass,
        })
    }

    /// Decodes set-volume-information parameters.
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
            information_class: set.FsInformationClass,
        })
    }

    /// Decodes query-file-information parameters.
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
        Ok(QueryFileStack {
            file_object: self.file_object()?,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: query.FileInformationClass,
        })
    }

    /// Decodes set-file-information parameters.
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
        Ok(SetFileStack {
            file_object: self.file_object()?,
            length: IrpBufferLength::from_ulong(set.Length)?,
            information_class: set.FileInformationClass,
        })
    }

    /// Decodes query-directory parameters.
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
        let pattern = match NonNull::new(query.FileName) {
            Some(file_name) => DirectoryPatternInput::Name(file_name),
            None => DirectoryPatternInput::All,
        };
        let cursor_position = if stack_flag(stack.Flags, wdk_sys::SL_INDEX_SPECIFIED) {
            DirectoryCursorPosition::Index(DirectoryEntryIndex(query.FileIndex))
        } else if stack_flag(stack.Flags, wdk_sys::SL_RESTART_SCAN)
            || matches!(pattern, DirectoryPatternInput::Name(_))
        {
            DirectoryCursorPosition::Restart
        } else {
            DirectoryCursorPosition::Current
        };
        let entry_emission = if stack_flag(stack.Flags, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            DirectoryEntryEmission::Single
        } else {
            DirectoryEntryEmission::Multiple
        };
        Ok(QueryDirectoryStack {
            file_object: self.file_object()?,
            cursor_position,
            pattern,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: query.FileInformationClass,
        })
    }

    /// Decodes query-EA parameters.
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
        if stack_flag(stack.Flags, wdk_sys::SL_INDEX_SPECIFIED) || query.EaIndex != 0 {
            return Err(DriverError::NotSupported);
        }
        let ea_list_length = IrpBufferLength::from_ulong(query.EaListLength)?;
        let name_selection = if ea_list_length.is_empty() {
            EaNameSelection::All
        } else {
            let Some(address) = NonNull::new(query.EaList.cast::<u8>()) else {
                return Err(DriverError::InvalidParameter);
            };
            EaNameSelection::Names {
                address,
                length: ea_list_length,
            }
        };
        let entry_emission = if stack_flag(stack.Flags, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            EaEntryEmission::Single
        } else {
            EaEntryEmission::Multiple
        };
        Ok(QueryEaStack {
            file_object: self.file_object()?,
            name_selection,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
        })
    }

    /// Decodes set-EA parameters.
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
        Ok(SetEaStack {
            file_object: self.file_object()?,
            length: IrpBufferLength::from_ulong(set.Length)?,
        })
    }

    /// Decodes query-security parameters.
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
        Ok(QuerySecurityStack {
            file_object: self.file_object()?,
            selection: SecuritySelection::from_raw(query.SecurityInformation)?,
            length: IrpBufferLength::from_ulong(query.Length)?,
        })
    }

    /// Decodes set-security parameters.
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
        let Some(security_descriptor) = NonNull::new(set.SecurityDescriptor.cast::<c_void>())
        else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(SetSecurityStack {
            file_object: self.file_object()?,
            selection: SecuritySelection::from_raw(set.SecurityInformation)?,
            security_descriptor,
        })
    }

    /// Decodes read parameters from the current stack location.
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
            // SAFETY: ByteOffset is represented by the QuadPart arm for IRP
            // read/write stack locations.
            read.ByteOffset.QuadPart
        };
        let byte_offset = FileOffset::from_bytes(
            u64::try_from(byte_offset).map_err(|_| DriverError::InvalidParameter)?,
        );
        Ok(ReadStack {
            file_object: self.file_object()?,
            length: IrpBufferLength::from_ulong(read.Length)?,
            byte_offset,
        })
    }

    /// Decodes write parameters from the current stack location.
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
            // SAFETY: ByteOffset is represented by the QuadPart arm for IRP
            // read/write stack locations.
            write.ByteOffset.QuadPart
        };
        let byte_offset = FileOffset::from_bytes(
            u64::try_from(byte_offset).map_err(|_| DriverError::InvalidParameter)?,
        );
        Ok(WriteStack {
            file_object: self.file_object()?,
            length: IrpBufferLength::from_ulong(write.Length)?,
            byte_offset,
        })
    }
}

/// Kernel-addressable buffer decoded from a read/write IRP boundary.
#[derive(Debug)]
pub(crate) struct IrpDataBuffer {
    /// First buffer byte.
    address: NonNull<u8>,
    /// Buffer byte count.
    length: usize,
}

impl IrpDataBuffer {
    /// Creates a data buffer after length validation.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        let max_slice_len =
            usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
        if length > max_slice_len {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { address, length })
    }

    /// Returns the buffer as a byte slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: IrpDataBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length)
        }
    }

    /// Returns the buffer as a mutable byte slice.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            // SAFETY: IrpDataBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts_mut(self.address.as_ptr(), self.length)
        }
    }
}

/// Returns an IRP MDL data buffer as kernel memory.
fn mdl_data_buffer(
    mdl: NonNull<wdk_sys::MDL>,
    length: usize,
) -> Result<IrpDataBuffer, DriverError> {
    let mdl_ref = unsafe {
        // SAFETY: The IRP's MdlAddress is non-null and owned by the I/O
        // Manager for the lifetime of this dispatch callback.
        mdl.as_ref()
    };
    let mdl_len = usize::try_from(mdl_ref.ByteCount).map_err(|_| DriverError::InvalidParameter)?;
    if length > mdl_len {
        return Err(DriverError::InvalidParameter);
    }

    let address = mapped_mdl_address(mdl, mdl_ref)?;
    IrpDataBuffer::new(address.cast(), length)
}

/// Implements the address-selection behavior of `MmGetSystemAddressForMdlSafe`.
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
        crate::ffi::MmMapLockedPagesSpecifyCache(
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
pub(crate) struct IrpBufferLength(usize);

impl IrpBufferLength {
    /// Decodes a WDK `ULONG` byte count into the driver length domain.
    fn from_ulong(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
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
    const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Directory entry index selected by a query-directory request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntryIndex(u32);

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

/// Query-directory filename pattern supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryPatternInput {
    /// No filename pattern was supplied.
    All,
    /// Caller supplied a `UNICODE_STRING` filename pattern.
    Name(NonNull<wdk_sys::UNICODE_STRING>),
}

/// Directory entry emission cardinality requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryEntryEmission {
    /// Emit as many matching entries as fit.
    Multiple,
    /// Emit at most one matching entry.
    Single,
}

/// Query-EA name selection supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EaNameSelection {
    /// Return every EA associated with the opened file.
    All,
    /// Return only names listed in the caller's `FILE_GET_EA_INFORMATION` buffer.
    Names {
        /// First byte of the caller's name list.
        address: NonNull<u8>,
        /// Byte length of the caller's name list.
        length: IrpBufferLength,
    },
}

/// EA entry emission cardinality requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EaEntryEmission {
    /// Emit as many selected EAs as fit.
    Multiple,
    /// Emit at most one selected EA.
    Single,
}

/// Selection state for one self-relative security descriptor component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecurityComponentSelection {
    /// Component was not selected by this IRP.
    Omitted,
    /// Component was selected by this IRP.
    Selected,
}

/// Security descriptor components accepted by the driver security boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecuritySelection {
    /// Owner SID selection.
    owner: SecurityComponentSelection,
    /// Group SID selection.
    group: SecurityComponentSelection,
    /// DACL selection.
    dacl: SecurityComponentSelection,
}

impl SecuritySelection {
    /// Builds a security selection from already-decoded component states.
    pub(crate) const fn from_components(
        owner: SecurityComponentSelection,
        group: SecurityComponentSelection,
        dacl: SecurityComponentSelection,
    ) -> Self {
        Self { owner, group, dacl }
    }

    /// Converts raw `SECURITY_INFORMATION` bits into supported component state.
    fn from_raw(value: wdk_sys::SECURITY_INFORMATION) -> Result<Self, DriverError> {
        let supported = wdk_sys::OWNER_SECURITY_INFORMATION
            | wdk_sys::GROUP_SECURITY_INFORMATION
            | wdk_sys::DACL_SECURITY_INFORMATION;
        if value & wdk_sys::SACL_SECURITY_INFORMATION != 0 {
            return Err(DriverError::AccessDenied);
        }
        if value & !supported != 0 {
            return Err(DriverError::NotSupported);
        }

        Ok(Self::from_components(
            security_component(value, wdk_sys::OWNER_SECURITY_INFORMATION),
            security_component(value, wdk_sys::GROUP_SECURITY_INFORMATION),
            security_component(value, wdk_sys::DACL_SECURITY_INFORMATION),
        ))
    }

    /// Returns owner SID selection.
    pub(crate) const fn owner(self) -> SecurityComponentSelection {
        self.owner
    }

    /// Returns group SID selection.
    pub(crate) const fn group(self) -> SecurityComponentSelection {
        self.group
    }

    /// Returns DACL selection.
    pub(crate) const fn dacl(self) -> SecurityComponentSelection {
        self.dacl
    }
}

/// Converts one security bit into component selection.
fn security_component(
    value: wdk_sys::SECURITY_INFORMATION,
    bit: wdk_sys::SECURITY_INFORMATION,
) -> SecurityComponentSelection {
    if value & bit == 0 {
        SecurityComponentSelection::Omitted
    } else {
        SecurityComponentSelection::Selected
    }
}

/// Tests one WDK `IO_STACK_LOCATION::Flags` bit while keeping raw flags local to decode.
fn stack_flag(flags: wdk_sys::UCHAR, bit: u32) -> bool {
    u32::from(flags) & bit != 0
}

/// Decoded mount-volume stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountVolumeStack {
    /// VPB supplied by the I/O Manager for the target volume.
    vpb: NonNull<wdk_sys::VPB>,
    /// Lower storage device object to mount.
    target_device: NonNull<wdk_sys::DEVICE_OBJECT>,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: IrpBufferLength,
}

/// Decoded user file-system-control stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileSystemControlStack {
    /// FILE_OBJECT carrying the FCB/CCB for path-scoped controls.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Input system-buffer length.
    input_buffer_length: IrpBufferLength,
    /// Output system-buffer length.
    output_buffer_length: IrpBufferLength,
    /// Requested FSCTL code.
    fs_control_code: wdk_sys::ULONG,
}

impl MountVolumeStack {
    /// Returns the VPB supplied for the mount.
    pub(crate) const fn vpb(self) -> NonNull<wdk_sys::VPB> {
        self.vpb
    }

    /// Returns the lower storage device object.
    pub(crate) const fn target_device(self) -> NonNull<wdk_sys::DEVICE_OBJECT> {
        self.target_device
    }

    /// Returns the mount request output buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

impl FileSystemControlStack {
    /// Returns the FILE_OBJECT carrying this FSCTL.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the input system-buffer length.
    pub(crate) const fn input_buffer_length(self) -> IrpBufferLength {
        self.input_buffer_length
    }

    /// Returns the output system-buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }

    /// Returns the FSCTL code.
    pub(crate) const fn fs_control_code(self) -> wdk_sys::ULONG {
        self.fs_control_code
    }
}

/// Decoded create/open stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateStack {
    /// FILE_OBJECT receiving FsContext/FsContext2 on successful create.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Desired access mask requested by the opener.
    desired_access: wdk_sys::ACCESS_MASK,
    /// Packed create disposition/options field.
    options: wdk_sys::ULONG,
    /// Share-access bits requested by the opener.
    share_access: wdk_sys::USHORT,
    /// Extended-attribute input length supplied with create.
    ea_length: IrpBufferLength,
}

impl CreateStack {
    /// Returns the FILE_OBJECT receiving this create request.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the requested desired access mask.
    pub(crate) const fn desired_access(self) -> wdk_sys::ACCESS_MASK {
        self.desired_access
    }

    /// Returns the packed create disposition/options field.
    pub(crate) const fn options(self) -> wdk_sys::ULONG {
        self.options
    }

    /// Returns the requested share access.
    pub(crate) const fn share_access(self) -> wdk_sys::USHORT {
        self.share_access
    }

    /// Returns the input EA length.
    pub(crate) const fn ea_length(self) -> IrpBufferLength {
        self.ea_length
    }
}

/// Decoded query-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryVolumeStack {
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested filesystem information class.
    information_class: wdk_sys::FS_INFORMATION_CLASS,
}

/// Decoded set-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetVolumeStack {
    /// Input buffer length.
    length: IrpBufferLength,
    /// Requested filesystem information class.
    information_class: wdk_sys::FS_INFORMATION_CLASS,
}

/// Decoded query-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested file information class.
    information_class: wdk_sys::FILE_INFORMATION_CLASS,
}

/// Decoded set-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Input buffer length.
    length: IrpBufferLength,
    /// Requested file information class.
    information_class: wdk_sys::FILE_INFORMATION_CLASS,
}

/// Decoded query-directory stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryDirectoryStack {
    /// FILE_OBJECT carrying the directory CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Initial CCB cursor position.
    cursor_position: DirectoryCursorPosition,
    /// Filename pattern supplied by the caller.
    pattern: DirectoryPatternInput,
    /// Directory entry emission cardinality.
    entry_emission: DirectoryEntryEmission,
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested directory information class.
    information_class: wdk_sys::FILE_INFORMATION_CLASS,
}

/// Decoded query-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// EA name selection requested by the caller.
    name_selection: EaNameSelection,
    /// EA entry emission cardinality.
    entry_emission: EaEntryEmission,
    /// Output buffer length.
    length: IrpBufferLength,
}

/// Decoded set-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Input FILE_FULL_EA_INFORMATION byte length.
    length: IrpBufferLength,
}

/// Decoded query-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QuerySecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Output buffer length.
    length: IrpBufferLength,
}

/// Decoded set-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetSecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Caller-supplied security descriptor.
    security_descriptor: NonNull<c_void>,
}

/// Decoded read stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Requested byte count.
    length: IrpBufferLength,
    /// Requested byte offset.
    byte_offset: FileOffset,
}

impl ReadStack {
    /// Returns the FILE_OBJECT carrying this read.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested byte offset.
    pub(crate) const fn byte_offset(self) -> FileOffset {
        self.byte_offset
    }
}

/// Decoded write stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriteStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Requested byte count.
    length: IrpBufferLength,
    /// Requested byte offset.
    byte_offset: FileOffset,
}

impl WriteStack {
    /// Returns the FILE_OBJECT carrying this write.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested byte offset.
    pub(crate) const fn byte_offset(self) -> FileOffset {
        self.byte_offset
    }
}

impl QueryVolumeStack {
    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> wdk_sys::FS_INFORMATION_CLASS {
        self.information_class
    }
}

impl SetVolumeStack {
    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> wdk_sys::FS_INFORMATION_CLASS {
        self.information_class
    }
}

impl QueryFileStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> wdk_sys::FILE_INFORMATION_CLASS {
        self.information_class
    }
}

impl SetFileStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> wdk_sys::FILE_INFORMATION_CLASS {
        self.information_class
    }
}

impl QueryDirectoryStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the initial directory cursor position.
    pub(crate) const fn cursor_position(self) -> DirectoryCursorPosition {
        self.cursor_position
    }

    /// Returns the query-directory filename pattern input.
    pub(crate) const fn pattern(self) -> DirectoryPatternInput {
        self.pattern
    }

    /// Returns directory entry emission cardinality.
    pub(crate) const fn entry_emission(self) -> DirectoryEntryEmission {
        self.entry_emission
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested directory information class.
    pub(crate) const fn information_class(self) -> wdk_sys::FILE_INFORMATION_CLASS {
        self.information_class
    }
}

impl QueryEaStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the EA name selection.
    pub(crate) const fn name_selection(self) -> EaNameSelection {
        self.name_selection
    }

    /// Returns EA entry emission cardinality.
    pub(crate) const fn entry_emission(self) -> EaEntryEmission {
        self.entry_emission
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl SetEaStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the input FILE_FULL_EA_INFORMATION byte length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl QuerySecurityStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl SetSecurityStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the caller-supplied security descriptor.
    pub(crate) const fn security_descriptor(self) -> NonNull<c_void> {
        self.security_descriptor
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use wdk_sys::{STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};

    use super::{
        CurrentIrpStackLocation, DirectoryCursorPosition, DirectoryEntryEmission,
        DirectoryPatternInput, DispatchTarget, EaEntryEmission, EaNameSelection,
        SecurityComponentSelection,
    };

    /// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
    const MOUNT_VOLUME_MINOR: wdk_sys::UCHAR = 1;

    /// Returns a non-null opaque pointer for decode-only dispatch tests.
    fn opaque<T>() -> *mut T {
        NonNull::<c_void>::dangling().as_ptr().cast()
    }

    use core::ptr::NonNull;

    #[test]
    fn null_dispatch_target_is_invalid_parameter() {
        assert_eq!(
            DispatchTarget::decode(core::ptr::null_mut(), opaque::<wdk_sys::IRP>())
                .err()
                .map(crate::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            DispatchTarget::decode(opaque::<wdk_sys::DEVICE_OBJECT>(), core::ptr::null_mut())
                .err()
                .map(crate::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn decoded_dispatch_target_preserves_pointers() {
        let device = opaque::<wdk_sys::DEVICE_OBJECT>();
        let irp = opaque::<wdk_sys::IRP>();
        let decoded = DispatchTarget::decode(device, irp);
        assert!(decoded.is_ok());
        if let Ok(target) = decoded {
            assert_eq!(target.device().as_ptr(), device);
            assert_eq!(target.irp().as_ptr(), irp);
        }
    }

    #[test]
    fn current_stack_location_rejects_null_pointer() {
        assert_eq!(
            CurrentIrpStackLocation::from_raw(core::ptr::null_mut())
                .err()
                .map(crate::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn mount_volume_stack_preserves_vpb_and_target() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let vpb = NonNull::<wdk_sys::VPB>::dangling();
        let target = NonNull::<wdk_sys::DEVICE_OBJECT>::dangling();
        stack.MinorFunction = MOUNT_VOLUME_MINOR;
        stack.Parameters.MountVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_20 {
            Vpb: vpb.as_ptr(),
            DeviceObject: target.as_ptr(),
            OutputBufferLength: 16,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(current.minor_function(), MOUNT_VOLUME_MINOR);
            let mount = current.mount_volume();
            assert!(mount.is_ok());
            if let Ok(mount) = mount {
                assert_eq!(mount.vpb(), vpb);
                assert_eq!(mount.target_device(), target);
                assert_eq!(mount.output_buffer_length().as_usize(), 16);
            }
        }
    }

    #[test]
    fn file_system_control_stack_preserves_file_object_output_and_code() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.FileSystemControl =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
                OutputBufferLength: 128,
                __bindgen_padding_0: 0,
                InputBufferLength: 32,
                __bindgen_padding_1: 0,
                FsControlCode: 589_992,
                Type3InputBuffer: core::ptr::null_mut(),
            };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let control = current.file_system_control();
            assert!(control.is_ok());
            if let Ok(control) = control {
                assert_eq!(control.file_object(), file_object);
                assert_eq!(control.input_buffer_length().as_usize(), 32);
                assert_eq!(control.output_buffer_length().as_usize(), 128);
                assert_eq!(control.fs_control_code(), 589_992);
            }
        }
    }

    #[test]
    fn create_stack_preserves_access_share_options_and_ea_length() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let desired_access = wdk_sys::FILE_READ_DATA | wdk_sys::FILE_WRITE_DATA;
        security_context.DesiredAccess = desired_access;
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::addr_of_mut!(security_context),
            Options: 0x0300_0040,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0x20,
            ShareAccess: u16::try_from(wdk_sys::FILE_SHARE_READ | wdk_sys::FILE_SHARE_WRITE)
                .unwrap_or(u16::MAX),
            __bindgen_padding_1: 0,
            EaLength: 48,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let create = current.create();
            assert!(create.is_ok());
            if let Ok(create) = create {
                assert_eq!(create.file_object(), file_object);
                assert_eq!(create.desired_access(), desired_access);
                assert_eq!(create.options(), 0x0300_0040);
                assert_eq!(
                    create.share_access(),
                    u16::try_from(wdk_sys::FILE_SHARE_READ | wdk_sys::FILE_SHARE_WRITE)
                        .unwrap_or(u16::MAX)
                );
                assert_eq!(create.ea_length().as_usize(), 48);
            }
        }
    }

    #[test]
    fn query_ea_stack_decodes_name_selection_length_and_emission() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let ea_list = NonNull::<u8>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_RETURN_SINGLE_ENTRY).unwrap_or(u8::MAX);
        stack.Parameters.QueryEa = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_11 {
            Length: 128,
            EaList: ea_list.as_ptr().cast(),
            EaListLength: 24,
            __bindgen_padding_0: 0,
            EaIndex: 0,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_ea();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.file_object(), file_object);
                assert_eq!(query.entry_emission(), EaEntryEmission::Single);
                assert_eq!(query.length().as_usize(), 128);
                assert_eq!(
                    query.name_selection(),
                    EaNameSelection::Names {
                        address: ea_list,
                        length: super::IrpBufferLength(24),
                    }
                );
            }
        }
    }

    #[test]
    fn query_ea_stack_rejects_index_selection_at_decode() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_INDEX_SPECIFIED).unwrap_or(u8::MAX);
        stack.Parameters.QueryEa = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_11 {
            Length: 128,
            EaList: core::ptr::null_mut(),
            EaListLength: 0,
            __bindgen_padding_0: 0,
            EaIndex: 0,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .query_ea()
                    .err()
                    .map(crate::status::DriverError::ntstatus),
                Some(STATUS_NOT_SUPPORTED)
            );
        }
    }

    #[test]
    fn set_ea_stack_preserves_file_object_and_length() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.SetEa =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_12 { Length: 64 };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_ea();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(set.file_object(), file_object);
                assert_eq!(set.length().as_usize(), 64);
            }
        }
    }

    #[test]
    fn query_security_stack_preserves_file_object_information_and_length() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
            SecurityInformation: wdk_sys::OWNER_SECURITY_INFORMATION
                | wdk_sys::DACL_SECURITY_INFORMATION,
            __bindgen_padding_0: 0,
            Length: 256,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_security();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.file_object(), file_object);
                assert_eq!(
                    query.selection().owner(),
                    SecurityComponentSelection::Selected
                );
                assert_eq!(
                    query.selection().group(),
                    SecurityComponentSelection::Omitted
                );
                assert_eq!(
                    query.selection().dacl(),
                    SecurityComponentSelection::Selected
                );
                assert_eq!(query.length().as_usize(), 256);
            }
        }
    }

    #[test]
    fn query_security_stack_rejects_sacl_at_decode() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
            SecurityInformation: wdk_sys::SACL_SECURITY_INFORMATION,
            __bindgen_padding_0: 0,
            Length: 256,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .query_security()
                    .err()
                    .map(crate::status::DriverError::ntstatus),
                Some(STATUS_ACCESS_DENIED)
            );
        }
    }

    #[test]
    fn query_security_stack_rejects_unsupported_bits_at_decode() {
        const LABEL_SECURITY_INFORMATION: wdk_sys::SECURITY_INFORMATION = 0x10;

        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
            SecurityInformation: LABEL_SECURITY_INFORMATION,
            __bindgen_padding_0: 0,
            Length: 256,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .query_security()
                    .err()
                    .map(crate::status::DriverError::ntstatus),
                Some(STATUS_NOT_SUPPORTED)
            );
        }
    }

    #[test]
    fn set_volume_stack_preserves_length_and_class() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        stack.Parameters.SetVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_14 {
            Length: 24,
            __bindgen_padding_0: 0,
            FsInformationClass: wdk_sys::_FSINFOCLASS::FileFsLabelInformation,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_volume();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(set.length().as_usize(), 24);
                assert_eq!(
                    set.information_class(),
                    wdk_sys::_FSINFOCLASS::FileFsLabelInformation
                );
            }
        }
    }

    #[test]
    fn set_security_stack_preserves_file_object_information_and_descriptor() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let descriptor = NonNull::<c_void>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.SetSecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_19 {
            SecurityInformation: wdk_sys::OWNER_SECURITY_INFORMATION
                | wdk_sys::GROUP_SECURITY_INFORMATION,
            SecurityDescriptor: descriptor.as_ptr(),
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_security();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(set.file_object(), file_object);
                assert_eq!(
                    set.selection().owner(),
                    SecurityComponentSelection::Selected
                );
                assert_eq!(
                    set.selection().group(),
                    SecurityComponentSelection::Selected
                );
                assert_eq!(set.selection().dacl(), SecurityComponentSelection::Omitted);
                assert_eq!(set.security_descriptor(), descriptor);
            }
        }
    }

    #[test]
    fn read_stack_preserves_file_object_length_and_offset() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
            Length: 4096,
            __bindgen_padding_0: 0,
            Key: 0,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 8192 },
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let read = current.read();
            assert!(read.is_ok());
            if let Ok(read) = read {
                assert_eq!(read.file_object(), file_object);
                assert_eq!(read.length().as_usize(), 4096);
                assert_eq!(read.byte_offset().bytes(), 8192);
            }
        }
    }

    #[test]
    fn read_stack_rejects_negative_offset_at_decode() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
            Length: 4096,
            __bindgen_padding_0: 0,
            Key: 0,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: -1 },
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .read()
                    .err()
                    .map(crate::status::DriverError::ntstatus),
                Some(STATUS_INVALID_PARAMETER)
            );
        }
    }

    #[test]
    fn write_stack_preserves_file_object_length_and_offset() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
            Length: 2048,
            __bindgen_padding_0: 0,
            Key: 0,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 4096 },
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let write = current.write();
            assert!(write.is_ok());
            if let Ok(write) = write {
                assert_eq!(write.file_object(), file_object);
                assert_eq!(write.length().as_usize(), 2048);
                assert_eq!(write.byte_offset().bytes(), 4096);
            }
        }
    }

    #[test]
    fn write_stack_rejects_negative_offset_at_decode() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
            Length: 2048,
            __bindgen_padding_0: 0,
            Key: 0,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: -1 },
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .write()
                    .err()
                    .map(crate::status::DriverError::ntstatus),
                Some(STATUS_INVALID_PARAMETER)
            );
        }
    }

    #[test]
    fn query_file_stack_preserves_file_object_length_and_class() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QueryFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
            Length: 64,
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_file();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.file_object(), file_object);
                assert_eq!(query.length().as_usize(), 64);
                assert_eq!(
                    query.information_class(),
                    wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation
                );
            }
        }
    }

    #[test]
    fn set_file_stack_preserves_file_object_length_and_class() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
            Length: 40,
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation,
            FileObject: core::ptr::null_mut(),
            __bindgen_anon_1:
                wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_file();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(set.file_object(), file_object);
                assert_eq!(set.length().as_usize(), 40);
                assert_eq!(
                    set.information_class(),
                    wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation
                );
            }
        }
    }

    #[test]
    fn query_directory_stack_decodes_restart_pattern_length_class_and_emission() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let file_name = NonNull::<wdk_sys::UNICODE_STRING>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_RESTART_SCAN | wdk_sys::SL_RETURN_SINGLE_ENTRY)
            .unwrap_or(u8::MAX);
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: file_name.as_ptr(),
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
            __bindgen_padding_0: 0,
            FileIndex: 3,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_directory();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.file_object(), file_object);
                assert_eq!(query.cursor_position(), DirectoryCursorPosition::Restart);
                assert_eq!(query.pattern(), DirectoryPatternInput::Name(file_name));
                assert_eq!(query.entry_emission(), DirectoryEntryEmission::Single);
                assert_eq!(query.length().as_usize(), 128);
                assert_eq!(
                    query.information_class(),
                    wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation
                );
            }
        }
    }

    #[test]
    fn query_directory_stack_decodes_index_cursor() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_INDEX_SPECIFIED).unwrap_or(u8::MAX);
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: core::ptr::null_mut(),
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
            __bindgen_padding_0: 0,
            FileIndex: 3,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_directory();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(
                    query.cursor_position(),
                    DirectoryCursorPosition::Index(super::DirectoryEntryIndex(3))
                );
                assert_eq!(query.pattern(), DirectoryPatternInput::All);
                assert_eq!(query.entry_emission(), DirectoryEntryEmission::Multiple);
            }
        }
    }
}
