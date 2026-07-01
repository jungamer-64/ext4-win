//! Typed IRP boundary shared by FSD dispatch modules.

use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::FileOffset;
use wdk_sys::{PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP};

use crate::kernel::status::{DriverError, DriverResult};
use crate::state::{KernelDevice, KernelFileObject, KernelSecurityDescriptor, KernelVpb};

/// Byte count completed in `IO_STATUS_BLOCK::Information`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InformationLength {
    /// WDK-sized information payload.
    bytes: wdk_sys::ULONG_PTR,
}

impl InformationLength {
    /// Zero-byte completion.
    pub(crate) const ZERO: Self = Self { bytes: 0 };

    /// Builds an information length from a Rust byte count.
    pub(crate) fn from_usize(bytes: usize) -> DriverResult<Self> {
        Ok(Self {
            bytes: wdk_sys::ULONG_PTR::try_from(bytes)
                .map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Returns the WDK payload for the IRP boundary.
    const fn as_ulong_ptr(self) -> wdk_sys::ULONG_PTR {
        self.bytes
    }
}

/// Non-null dispatch target decoded from raw WDK callback inputs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DispatchTarget {
    /// Device object receiving the IRP.
    device: KernelDevice,
    /// IRP being dispatched.
    irp: KernelIrp,
}

impl DispatchTarget {
    /// Decodes raw WDK dispatch pointers.
    pub(crate) fn decode(device: PDEVICE_OBJECT, irp: PIRP) -> Result<Self, DriverError> {
        let Some(device) = KernelDevice::from_raw(device) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(irp) = KernelIrp::from_raw(irp) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { device, irp })
    }

    /// Returns the typed device object boundary.
    pub(crate) const fn device(self) -> KernelDevice {
        self.device
    }

    /// Returns METHOD_BUFFERED input bytes from the IRP system buffer.
    pub(crate) fn buffered_input(
        self,
        length: IrpBufferLength,
    ) -> Result<BufferedInput, DriverError> {
        BufferedInput::new(self.associated_system_buffer()?, length.as_usize())
    }

    /// Returns METHOD_BUFFERED output bytes from the IRP system buffer.
    pub(crate) fn buffered_output(
        self,
        length: IrpBufferLength,
    ) -> Result<BufferedOutput, DriverError> {
        BufferedOutput::new(self.associated_system_buffer()?, length.as_usize())
    }

    /// Returns read-like IRP data bytes as immutable kernel memory.
    pub(crate) fn data_input(self, length: IrpBufferLength) -> Result<BufferedInput, DriverError> {
        BufferedInput::new(self.data_buffer_address(length)?, length.as_usize())
    }

    /// Returns write-like IRP data bytes as mutable kernel memory.
    pub(crate) fn data_output(
        self,
        length: IrpBufferLength,
    ) -> Result<BufferedOutput, DriverError> {
        BufferedOutput::new(self.data_buffer_address(length)?, length.as_usize())
    }

    /// Returns the IRP user output buffer as kernel-addressable memory.
    pub(crate) fn user_output(self, length: IrpBufferLength) -> Result<UserOutput, DriverError> {
        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.irp.as_ref() };
        let Some(buffer) = NonNull::new(irp.UserBuffer) else {
            return Err(DriverError::InvalidParameter);
        };
        UserOutput::new(buffer.cast(), length.as_usize())
    }

    /// Returns the buffered I/O system buffer address for this IRP.
    fn associated_system_buffer(self) -> Result<NonNull<u8>, DriverError> {
        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.irp.as_ref() };
        let system_buffer = unsafe {
            // SAFETY: SystemBuffer is the active AssociatedIrp arm for
            // buffered requests delivered to this driver.
            irp.AssociatedIrp.SystemBuffer
        };
        NonNull::new(system_buffer)
            .map(NonNull::cast)
            .ok_or(DriverError::InvalidParameter)
    }

    /// Returns the read/write IRP data buffer address as kernel memory.
    fn data_buffer_address(self, length: IrpBufferLength) -> Result<NonNull<u8>, DriverError> {
        if let Ok(system_buffer) = self.associated_system_buffer() {
            return Ok(system_buffer);
        }

        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.irp.as_ref() };
        let Some(mdl) = NonNull::new(irp.MdlAddress) else {
            return Err(DriverError::InvalidParameter);
        };
        mdl_data_buffer_address(mdl, length)
    }

    /// Returns the current stack location selected by the I/O Manager.
    pub(crate) fn current_stack(self) -> Result<CurrentIrpStackLocation, DriverError> {
        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.irp.as_ref() };
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

/// Non-null IRP pointer kept private to the typed dispatch boundary.
#[derive(Clone, Copy, Debug)]
struct KernelIrp {
    /// Non-null WDK IRP pointer.
    irp: NonNull<wdk_sys::IRP>,
}

impl KernelIrp {
    /// Converts a raw WDK IRP pointer into the private non-null boundary type.
    fn from_raw(irp: PIRP) -> Option<Self> {
        NonNull::new(irp).map(|irp| Self { irp })
    }

    /// Returns an immutable IRP reference for active dispatch decoding.
    unsafe fn as_ref<'a>(self) -> &'a wdk_sys::IRP {
        unsafe {
            // SAFETY: The caller ties the returned reference to the current WDK
            // dispatch callback that supplied this IRP.
            self.irp.as_ref()
        }
    }

    /// Returns the raw IRP pointer for writes to the WDK completion fields.
    fn as_mut_ptr(self) -> *mut wdk_sys::IRP {
        self.irp.as_ptr()
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
            value
                if value == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY
                    || value == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX =>
            {
                DirectoryControlMinorFunction::NotifyChangeDirectory
            }
            _ => DirectoryControlMinorFunction::Unsupported,
        }
    }

    /// Returns the raw minor-function byte for local enum decoding only.
    fn raw_minor_function(self) -> wdk_sys::UCHAR {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        stack.MinorFunction
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    pub(crate) fn file_object(self) -> Result<KernelFileObject, DriverError> {
        self.kernel_file_object()
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    fn kernel_file_object(self) -> Result<KernelFileObject, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        KernelFileObject::from_raw(stack.FileObject).ok_or(DriverError::InvalidParameter)
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

        let Some(vpb) = KernelVpb::from_raw(mount.Vpb) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(target_device) = KernelDevice::from_raw(mount.DeviceObject) else {
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
            file_object: self.kernel_file_object()?,
            input_buffer_length: IrpBufferLength::from_ulong(control.InputBufferLength)?,
            output_buffer_length: IrpBufferLength::from_ulong(control.OutputBufferLength)?,
            fs_control_code: FsControlCode::from_raw(control.FsControlCode)?,
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
        let file_object = self.kernel_file_object()?;
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
            parameters: CreateParameters::decode(
                security_context.DesiredAccess,
                create.Options,
                create.ShareAccess,
                IrpBufferLength::from_ulong(create.EaLength)?,
            )?,
        })
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
            information_class: QueryVolumeInformationClass::from_raw(query.FsInformationClass)?,
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
            information_class: SetVolumeInformationClass::from_raw(set.FsInformationClass)?,
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
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: QueryFileInformationClass::from_raw(query.FileInformationClass)?,
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
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(set.Length)?,
            information_class: SetFileInformationClass::from_raw(set.FileInformationClass)?,
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
            file_object: self.kernel_file_object()?,
            cursor_position,
            pattern,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: DirectoryInformationClass::from_raw(query.FileInformationClass)?,
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
            file_object: self.kernel_file_object()?,
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
            file_object: self.kernel_file_object()?,
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
            file_object: self.kernel_file_object()?,
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
        let Some(security_descriptor) = KernelSecurityDescriptor::from_raw(set.SecurityDescriptor)
        else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(SetSecurityStack {
            file_object: self.kernel_file_object()?,
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
            file_object: self.kernel_file_object()?,
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
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(write.Length)?,
            byte_offset,
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
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        let max_slice_len =
            usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
        if length > max_slice_len {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { address, length })
    }

    /// Returns the buffer as a byte slice.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: IrpByteBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length)
        }
    }

    /// Returns the buffer as a mutable byte slice.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            // SAFETY: IrpByteBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts_mut(self.address.as_ptr(), self.length)
        }
    }

    /// Copies an unaligned fixed-size payload out of the buffer.
    fn read_unaligned<T: Copy>(&self) -> DriverResult<T> {
        if self.length < core::mem::size_of::<T>() {
            return Err(DriverError::BufferTooSmall);
        }
        Ok(unsafe {
            // SAFETY: The buffer length was checked above and unaligned read
            // avoids imposing an alignment contract on I/O manager storage.
            self.address.as_ptr().cast::<T>().read_unaligned()
        })
    }
}

/// Immutable bytes decoded from a buffered or data-input IRP boundary.
#[derive(Debug)]
pub(crate) struct BufferedInput {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
}

impl BufferedInput {
    /// Creates an immutable buffer view after length validation.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        Ok(Self {
            bytes: IrpByteBuffer::new(address, length)?,
        })
    }

    /// Returns input bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Copies an unaligned fixed-size input payload.
    pub(crate) fn read_unaligned<T: Copy>(&self) -> DriverResult<T> {
        self.bytes.read_unaligned()
    }
}

/// Mutable bytes decoded from a buffered or data-output IRP boundary.
#[derive(Debug)]
pub(crate) struct BufferedOutput {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
}

impl BufferedOutput {
    /// Creates a mutable buffer view after length validation.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        Ok(Self {
            bytes: IrpByteBuffer::new(address, length)?,
        })
    }

    /// Returns output bytes.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }
}

/// Mutable bytes decoded from an IRP user output buffer.
#[derive(Debug)]
pub(crate) struct UserOutput {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
}

impl UserOutput {
    /// Creates a mutable user output view after length validation.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        Ok(Self {
            bytes: IrpByteBuffer::new(address, length)?,
        })
    }

    /// Returns user output bytes.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }
}

/// Returns an IRP MDL data buffer address as kernel memory.
fn mdl_data_buffer_address(
    mdl: NonNull<wdk_sys::MDL>,
    length: IrpBufferLength,
) -> Result<NonNull<u8>, DriverError> {
    let mdl_ref = unsafe {
        // SAFETY: The IRP's MdlAddress is non-null and owned by the I/O
        // Manager for the lifetime of this dispatch callback.
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
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Directory entry index selected by a query-directory request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntryIndex(u32);

impl DirectoryEntryIndex {
    /// Creates a directory entry index from the Windows cursor field.
    pub(crate) const fn from_u32(value: u32) -> Self {
        Self(value)
    }

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

/// Decoded file-system-control minor function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileSystemControlMinorFunction {
    /// I/O Manager mount request.
    MountVolume,
    /// User FSCTL request.
    UserFsRequest,
    /// Unsupported file-system-control minor function.
    Unsupported,
}

/// Decoded directory-control minor function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryControlMinorFunction {
    /// Directory enumeration request.
    QueryDirectory,
    /// Directory change notification request.
    NotifyChangeDirectory,
    /// Unsupported directory-control minor function.
    Unsupported,
}

/// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
const MOUNT_VOLUME_MINOR_FUNCTION: u32 = 1;

/// Decoded user FSCTL code selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsControlCode {
    /// Windows `FSCTL_GET_REPARSE_POINT`.
    GetReparsePoint,
    /// Windows `FSCTL_SET_REPARSE_POINT`.
    SetReparsePoint,
    /// Windows `FSCTL_DELETE_REPARSE_POINT`.
    DeleteReparsePoint,
    /// ext4win private fscrypt add-key control.
    AddEncryptionKey,
    /// ext4win private fscrypt remove-key control.
    RemoveEncryptionKey,
    /// ext4win private fscrypt key-status control.
    GetEncryptionKeyStatus,
    /// ext4win private fs-verity enable control.
    EnableVerity,
}

impl FsControlCode {
    /// Decodes the raw WDK control code at the IRP boundary.
    fn from_raw(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        match value {
            FSCTL_GET_REPARSE_POINT => Ok(Self::GetReparsePoint),
            FSCTL_SET_REPARSE_POINT => Ok(Self::SetReparsePoint),
            FSCTL_DELETE_REPARSE_POINT => Ok(Self::DeleteReparsePoint),
            FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY => Ok(Self::AddEncryptionKey),
            FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY => Ok(Self::RemoveEncryptionKey),
            FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS => Ok(Self::GetEncryptionKeyStatus),
            FSCTL_EXT4WIN_ENABLE_VERITY => Ok(Self::EnableVerity),
            _ => Err(DriverError::NotSupported),
        }
    }
}

/// `FSCTL_GET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_GET_REPARSE_POINT: wdk_sys::ULONG = 589_992;
/// `FSCTL_SET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_SET_REPARSE_POINT: wdk_sys::ULONG = 589_988;
/// `FSCTL_DELETE_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_DELETE_REPARSE_POINT: wdk_sys::ULONG = 589_996;

/// Windows `FILE_DEVICE_FILE_SYSTEM`.
const FILE_DEVICE_FILE_SYSTEM: wdk_sys::ULONG = 0x0000_0009;
/// Windows `METHOD_BUFFERED`.
const METHOD_BUFFERED: wdk_sys::ULONG = 0;
/// Windows `FILE_ANY_ACCESS`.
const FILE_ANY_ACCESS: wdk_sys::ULONG = 0;
/// ext4win private function code for adding an fscrypt key.
const EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x900;
/// ext4win private function code for removing an fscrypt key.
const EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x901;
/// ext4win private function code for fscrypt key status.
const EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION: wdk_sys::ULONG = 0x902;
/// ext4win private function code for enabling fs-verity.
const EXT4WIN_ENABLE_VERITY_FUNCTION: wdk_sys::ULONG = 0x903;

/// Builds a Windows `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, function, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const fn ext4win_fsctl(function: wdk_sys::ULONG) -> wdk_sys::ULONG {
    (FILE_DEVICE_FILE_SYSTEM << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
}

/// ext4win FSCTL carrying Linux `struct fscrypt_add_key_arg`.
const FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_remove_key_arg`.
const FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_get_key_status_arg`.
const FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fsverity_enable_arg`.
const FSCTL_EXT4WIN_ENABLE_VERITY: wdk_sys::ULONG = ext4win_fsctl(EXT4WIN_ENABLE_VERITY_FUNCTION);

/// Decoded query-volume filesystem information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryVolumeInformationClass {
    /// Windows `FileFsVolumeInformation`.
    Volume,
    /// Windows `FileFsSizeInformation`.
    Size,
    /// Windows `FileFsDeviceInformation`.
    Device,
    /// Windows `FileFsAttributeInformation`.
    Attribute,
    /// Windows `FileFsFullSizeInformation`.
    FullSize,
}

impl QueryVolumeInformationClass {
    /// Decodes a raw WDK filesystem information class for volume queries.
    fn from_raw(value: wdk_sys::FS_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            FILE_FS_VOLUME_INFORMATION_CLASS => Ok(Self::Volume),
            FILE_FS_SIZE_INFORMATION_CLASS => Ok(Self::Size),
            FILE_FS_DEVICE_INFORMATION_CLASS => Ok(Self::Device),
            FILE_FS_ATTRIBUTE_INFORMATION_CLASS => Ok(Self::Attribute),
            FILE_FS_FULL_SIZE_INFORMATION_CLASS => Ok(Self::FullSize),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded set-volume filesystem information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetVolumeInformationClass {
    /// Windows `FileFsLabelInformation`.
    Label,
}

impl SetVolumeInformationClass {
    /// Decodes a raw WDK filesystem information class for volume mutations.
    fn from_raw(value: wdk_sys::FS_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            FILE_FS_LABEL_INFORMATION_CLASS => Ok(Self::Label),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// `FileFsVolumeInformation`.
const FILE_FS_VOLUME_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 1;
/// `FileFsLabelInformation`.
const FILE_FS_LABEL_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 2;
/// `FileFsSizeInformation`.
const FILE_FS_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 3;
/// `FileFsDeviceInformation`.
const FILE_FS_DEVICE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 4;
/// `FileFsAttributeInformation`.
const FILE_FS_ATTRIBUTE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 5;
/// `FileFsFullSizeInformation`.
const FILE_FS_FULL_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 7;

/// Decoded query-file information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryFileInformationClass {
    /// Windows `FileBasicInformation`.
    Basic,
    /// Windows `FileStandardInformation`.
    Standard,
    /// Windows `FileInternalInformation`.
    Internal,
    /// Windows `FilePositionInformation`.
    Position,
    /// Windows `FileNetworkOpenInformation`.
    NetworkOpen,
}

impl QueryFileInformationClass {
    /// Decodes a raw WDK file information class for fixed file queries.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => Ok(Self::Basic),
            wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation => Ok(Self::Standard),
            wdk_sys::_FILE_INFORMATION_CLASS::FileInternalInformation => Ok(Self::Internal),
            wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation => Ok(Self::Position),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNetworkOpenInformation => Ok(Self::NetworkOpen),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded set-file information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetFileInformationClass {
    /// Windows `FileBasicInformation`.
    Basic,
    /// Windows `FileEndOfFileInformation`.
    EndOfFile,
    /// Windows `FileAllocationInformation`.
    Allocation,
    /// Windows `FileDispositionInformation`.
    Disposition,
    /// Windows `FileDispositionInformationEx`.
    DispositionEx,
    /// Windows `FileRenameInformation`.
    Rename,
    /// Windows `FileRenameInformationEx`.
    RenameEx,
}

impl SetFileInformationClass {
    /// Decodes a raw WDK file information class for file mutations.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => Ok(Self::Basic),
            wdk_sys::_FILE_INFORMATION_CLASS::FileEndOfFileInformation => Ok(Self::EndOfFile),
            wdk_sys::_FILE_INFORMATION_CLASS::FileAllocationInformation => Ok(Self::Allocation),
            wdk_sys::_FILE_INFORMATION_CLASS::FileDispositionInformation => Ok(Self::Disposition),
            wdk_sys::_FILE_INFORMATION_CLASS::FileDispositionInformationEx => {
                Ok(Self::DispositionEx)
            }
            wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation => Ok(Self::Rename),
            wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformationEx => Ok(Self::RenameEx),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded query-directory information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryInformationClass {
    /// Windows `FileDirectoryInformation`.
    Directory,
    /// Windows `FileFullDirectoryInformation`.
    Full,
    /// Windows `FileBothDirectoryInformation`.
    Both,
}

impl DirectoryInformationClass {
    /// Decodes a raw WDK file information class for directory enumeration.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation => Ok(Self::Directory),
            wdk_sys::_FILE_INFORMATION_CLASS::FileFullDirectoryInformation => Ok(Self::Full),
            wdk_sys::_FILE_INFORMATION_CLASS::FileBothDirectoryInformation => Ok(Self::Both),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded create/open parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateParameters {
    /// Desired access mask requested by the opener.
    desired_access: DesiredAccess,
    /// Share-access bits requested by the opener.
    share_access: ShareAccess,
    /// Requested create disposition.
    disposition: CreateDisposition,
    /// File-vs-directory create/open requirement.
    target_requirement: CreateTargetRequirement,
    /// Extended-attribute input length supplied with create.
    ea_length: IrpBufferLength,
}

impl CreateParameters {
    /// Decodes raw WDK create parameters at the IRP boundary.
    fn decode(
        desired_access: wdk_sys::ACCESS_MASK,
        options: wdk_sys::ULONG,
        share_access: wdk_sys::USHORT,
        ea_length: IrpBufferLength,
    ) -> Result<Self, DriverError> {
        Ok(Self {
            desired_access: DesiredAccess::from_raw(desired_access),
            share_access: ShareAccess::from_raw(share_access)?,
            disposition: CreateDisposition::from_options(options)?,
            target_requirement: CreateTargetRequirement::from_options(options)?,
            ea_length,
        })
    }

    /// Returns the desired access mask.
    pub(crate) const fn desired_access(self) -> DesiredAccess {
        self.desired_access
    }

    /// Returns the share access.
    pub(crate) const fn share_access(self) -> ShareAccess {
        self.share_access
    }

    /// Returns the create disposition.
    pub(crate) const fn disposition(self) -> CreateDisposition {
        self.disposition
    }

    /// Returns the target kind requirement.
    pub(crate) const fn target_requirement(self) -> CreateTargetRequirement {
        self.target_requirement
    }

    /// Returns the input EA length.
    pub(crate) const fn ea_length(self) -> IrpBufferLength {
        self.ea_length
    }
}

/// Desired access requested by a create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DesiredAccess {
    /// Raw WDK access mask, retained for I/O Manager share-access accounting.
    raw: wdk_sys::ACCESS_MASK,
}

impl DesiredAccess {
    /// Wraps the raw WDK access mask.
    const fn from_raw(raw: wdk_sys::ACCESS_MASK) -> Self {
        Self { raw }
    }

    /// Returns the WDK access mask for `IoCheckShareAccess`.
    pub(crate) const fn as_raw(self) -> wdk_sys::ACCESS_MASK {
        self.raw
    }
}

/// Share access requested by a create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShareAccess {
    /// Raw WDK share mask widened for I/O Manager share-access accounting.
    raw: wdk_sys::ULONG,
}

impl ShareAccess {
    /// Decodes the raw WDK share mask.
    fn from_raw(raw: wdk_sys::USHORT) -> Result<Self, DriverError> {
        if raw & !FILE_SHARE_ACCESS_MASK != 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self {
            raw: wdk_sys::ULONG::from(raw),
        })
    }

    /// Returns the WDK share mask for `IoCheckShareAccess`.
    pub(crate) const fn as_ulong(self) -> wdk_sys::ULONG {
        self.raw
    }
}

/// Requested create disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateDisposition {
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
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, DriverError> {
        match options >> CREATE_DISPOSITION_SHIFT {
            FILE_OPEN_DISPOSITION => Ok(Self::Open),
            FILE_CREATE_DISPOSITION => Ok(Self::Create),
            FILE_OPEN_IF_DISPOSITION => Ok(Self::OpenIf),
            FILE_SUPERSEDE_DISPOSITION => Ok(Self::Supersede),
            FILE_OVERWRITE_DISPOSITION => Ok(Self::Overwrite),
            FILE_OVERWRITE_IF_DISPOSITION => Ok(Self::OverwriteIf),
            _ => Err(DriverError::InvalidParameter),
        }
    }
}

/// File-vs-directory target requirement requested by create options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTargetRequirement {
    /// Caller accepts a file, symlink, or directory.
    Any,
    /// Caller requires a directory target.
    Directory,
    /// Caller requires a non-directory target.
    NonDirectory,
}

impl CreateTargetRequirement {
    /// Decodes file-vs-directory create options and rejects unsupported options.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, DriverError> {
        let raw_options = options & CREATE_OPTIONS_MASK;
        if raw_options & !SUPPORTED_CREATE_OPTIONS != 0 {
            return Err(DriverError::NotSupported);
        }
        let directory = raw_options & FILE_DIRECTORY_FILE_OPTION != 0;
        let non_directory = raw_options & FILE_NON_DIRECTORY_FILE_OPTION != 0;
        match (directory, non_directory) {
            (true, true) => Err(DriverError::InvalidParameter),
            (true, false) => Ok(Self::Directory),
            (false, true) => Ok(Self::NonDirectory),
            (false, false) => Ok(Self::Any),
        }
    }
}

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
/// Mask for option bits below the create disposition.
const CREATE_OPTIONS_MASK: wdk_sys::ULONG = 0x00FF_FFFF;
/// `FILE_DIRECTORY_FILE` create option.
const FILE_DIRECTORY_FILE_OPTION: wdk_sys::ULONG = 0x0000_0001;
/// `FILE_NON_DIRECTORY_FILE` create option.
const FILE_NON_DIRECTORY_FILE_OPTION: wdk_sys::ULONG = 0x0000_0040;
/// Create options implemented by this FSD.
const SUPPORTED_CREATE_OPTIONS: wdk_sys::ULONG =
    FILE_DIRECTORY_FILE_OPTION | FILE_NON_DIRECTORY_FILE_OPTION;
/// WDK share-access bits accepted by create/open.
const FILE_SHARE_ACCESS_MASK: wdk_sys::USHORT = 0x0007;

/// Decoded mount-volume stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountVolumeStack {
    /// VPB supplied by the I/O Manager for the target volume.
    vpb: KernelVpb,
    /// Lower storage device object to mount.
    target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: IrpBufferLength,
}

/// Decoded user file-system-control stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileSystemControlStack {
    /// FILE_OBJECT carrying the FCB/CCB for path-scoped controls.
    file_object: KernelFileObject,
    /// Input system-buffer length.
    input_buffer_length: IrpBufferLength,
    /// Output system-buffer length.
    output_buffer_length: IrpBufferLength,
    /// Requested FSCTL code.
    fs_control_code: FsControlCode,
}

impl MountVolumeStack {
    /// Returns the VPB supplied for the mount.
    pub(crate) const fn vpb(self) -> KernelVpb {
        self.vpb
    }

    /// Returns the lower storage device object.
    pub(crate) const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Returns the mount request output buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

impl FileSystemControlStack {
    /// Returns the FILE_OBJECT carrying this FSCTL.
    pub(crate) const fn file_object(self) -> KernelFileObject {
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
    pub(crate) const fn fs_control_code(self) -> FsControlCode {
        self.fs_control_code
    }
}

/// Decoded create/open stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateStack {
    /// FILE_OBJECT receiving FsContext/FsContext2 on successful create.
    file_object: KernelFileObject,
    /// Decoded create parameters.
    parameters: CreateParameters,
}

impl CreateStack {
    /// Returns the FILE_OBJECT receiving this create request.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the decoded create parameters.
    pub(crate) const fn parameters(self) -> CreateParameters {
        self.parameters
    }
}

/// Decoded query-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryVolumeStack {
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested filesystem information class.
    information_class: QueryVolumeInformationClass,
}

/// Decoded set-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetVolumeStack {
    /// Input buffer length.
    length: IrpBufferLength,
    /// Requested filesystem information class.
    information_class: SetVolumeInformationClass,
}

/// Decoded query-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested file information class.
    information_class: QueryFileInformationClass,
}

/// Decoded set-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Input buffer length.
    length: IrpBufferLength,
    /// Requested file information class.
    information_class: SetFileInformationClass,
}

/// Decoded query-directory stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryDirectoryStack {
    /// FILE_OBJECT carrying the directory CCB.
    file_object: KernelFileObject,
    /// Initial CCB cursor position.
    cursor_position: DirectoryCursorPosition,
    /// Filename pattern supplied by the caller.
    pattern: DirectoryPatternInput,
    /// Directory entry emission cardinality.
    entry_emission: DirectoryEntryEmission,
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested directory information class.
    information_class: DirectoryInformationClass,
}

/// Decoded query-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
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
    file_object: KernelFileObject,
    /// Input FILE_FULL_EA_INFORMATION byte length.
    length: IrpBufferLength,
}

/// Decoded query-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QuerySecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Output buffer length.
    length: IrpBufferLength,
}

/// Decoded set-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetSecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Caller-supplied security descriptor.
    security_descriptor: KernelSecurityDescriptor,
}

/// Decoded read stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Requested byte count.
    length: IrpBufferLength,
    /// Requested byte offset.
    byte_offset: FileOffset,
}

impl ReadStack {
    /// Returns the FILE_OBJECT carrying this read.
    pub(crate) const fn file_object(self) -> KernelFileObject {
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
    file_object: KernelFileObject,
    /// Requested byte count.
    length: IrpBufferLength,
    /// Requested byte offset.
    byte_offset: FileOffset,
}

impl WriteStack {
    /// Returns the FILE_OBJECT carrying this write.
    pub(crate) const fn file_object(self) -> KernelFileObject {
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
    pub(crate) const fn information_class(self) -> QueryVolumeInformationClass {
        self.information_class
    }
}

impl SetVolumeStack {
    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> SetVolumeInformationClass {
        self.information_class
    }
}

impl QueryFileStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> QueryFileInformationClass {
        self.information_class
    }
}

impl SetFileStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> SetFileInformationClass {
        self.information_class
    }
}

impl QueryDirectoryStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
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
    pub(crate) const fn information_class(self) -> DirectoryInformationClass {
        self.information_class
    }
}

impl QueryEaStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
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
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the input FILE_FULL_EA_INFORMATION byte length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl QuerySecurityStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
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
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the caller-supplied security descriptor.
    pub(crate) const fn security_descriptor(self) -> KernelSecurityDescriptor {
        self.security_descriptor
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use wdk_sys::{STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};

    use super::{
        CREATE_DISPOSITION_SHIFT, CreateDisposition, CreateTargetRequirement,
        CurrentIrpStackLocation, DirectoryControlMinorFunction, DirectoryCursorPosition,
        DirectoryEntryEmission, DirectoryInformationClass, DirectoryPatternInput, DispatchTarget,
        EaEntryEmission, EaNameSelection, FILE_OPEN_DISPOSITION, FileSystemControlMinorFunction,
        FsControlCode, IrpBufferLength, QueryFileInformationClass, QueryVolumeInformationClass,
        SecurityComponentSelection, SetFileInformationClass, SetVolumeInformationClass,
    };
    use crate::state::{KernelDevice, KernelFileObject, KernelSecurityDescriptor, KernelVpb};

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
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            DispatchTarget::decode(opaque::<wdk_sys::DEVICE_OBJECT>(), core::ptr::null_mut())
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
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
        }
    }

    #[test]
    fn irp_buffer_length_preserves_zero_as_typed_empty() {
        let length = IrpBufferLength::from_ulong(0);
        assert!(length.is_ok());
        if let Ok(length) = length {
            assert!(length.is_empty());
            assert_eq!(length.as_usize(), 0);
        }
    }

    #[test]
    fn current_stack_location_rejects_null_pointer() {
        assert_eq!(
            CurrentIrpStackLocation::from_raw(core::ptr::null_mut())
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn unsupported_filesystem_control_minor_decodes_as_unsupported() {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MinorFunction: u8::MAX,
            ..Default::default()
        };

        assert_eq!(
            CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack))
                .map(|current| current.file_system_control_minor()),
            Ok(FileSystemControlMinorFunction::Unsupported)
        );
    }

    #[test]
    fn unsupported_directory_control_minor_decodes_as_unsupported() {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MinorFunction: u8::MAX,
            ..Default::default()
        };

        assert_eq!(
            CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack))
                .map(|current| current.directory_control_minor()),
            Ok(DirectoryControlMinorFunction::Unsupported)
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
            assert_eq!(
                current.file_system_control_minor(),
                FileSystemControlMinorFunction::MountVolume
            );
            let mount = current.mount_volume();
            assert!(mount.is_ok());
            if let Ok(mount) = mount {
                assert_eq!(Some(mount.vpb()), KernelVpb::from_raw(vpb.as_ptr()));
                assert_eq!(
                    Some(mount.target_device()),
                    KernelDevice::from_raw(target.as_ptr())
                );
                assert_eq!(mount.output_buffer_length().as_usize(), 16);
            }
        }
    }

    #[test]
    fn file_system_control_stack_decodes_supported_user_control() {
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
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
                assert_eq!(
                    Some(control.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(control.input_buffer_length().as_usize(), 32);
                assert_eq!(control.output_buffer_length().as_usize(), 128);
                assert_eq!(control.fs_control_code(), FsControlCode::GetReparsePoint);
            }
        }
    }

    #[test]
    fn file_system_control_stack_rejects_unsupported_control_before_handler() {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.FileSystemControl =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
                OutputBufferLength: 128,
                __bindgen_padding_0: 0,
                InputBufferLength: 32,
                __bindgen_padding_1: 0,
                FsControlCode: 0xFFFF_FFFF,
                Type3InputBuffer: core::ptr::null_mut(),
            };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .file_system_control()
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(STATUS_NOT_SUPPORTED)
            );
        }
    }

    #[test]
    fn ext4win_private_fsctl_codes_decode_to_domain_variants() {
        assert_eq!(
            FsControlCode::from_raw(0x0009_2400),
            Ok(FsControlCode::AddEncryptionKey)
        );
        assert_eq!(
            FsControlCode::from_raw(0x0009_2404),
            Ok(FsControlCode::RemoveEncryptionKey)
        );
        assert_eq!(
            FsControlCode::from_raw(0x0009_2408),
            Ok(FsControlCode::GetEncryptionKeyStatus)
        );
        assert_eq!(
            FsControlCode::from_raw(0x0009_240c),
            Ok(FsControlCode::EnableVerity)
        );
    }

    #[test]
    fn create_stack_preserves_access_share_options_and_ea_length() {
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let desired_access = wdk_sys::FILE_READ_DATA | wdk_sys::FILE_WRITE_DATA;
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
            DesiredAccess: desired_access,
            ..wdk_sys::IO_SECURITY_CONTEXT::default()
        };
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
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
                assert_eq!(
                    Some(create.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                let parameters = create.parameters();
                assert_eq!(parameters.desired_access().as_raw(), desired_access);
                assert_eq!(parameters.disposition(), CreateDisposition::OpenIf);
                assert_eq!(
                    parameters.target_requirement(),
                    CreateTargetRequirement::NonDirectory
                );
                assert_eq!(
                    parameters.share_access().as_ulong(),
                    wdk_sys::FILE_SHARE_READ | wdk_sys::FILE_SHARE_WRITE
                );
                assert_eq!(parameters.ea_length().as_usize(), 48);
            }
        }
    }

    #[test]
    fn create_stack_rejects_unsupported_options_before_handler() {
        const FILE_SEQUENTIAL_ONLY: wdk_sys::ULONG = 0x0000_0004;

        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
        stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::addr_of_mut!(security_context),
            Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT) | FILE_SEQUENTIAL_ONLY,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0,
            ShareAccess: 0,
            __bindgen_padding_1: 0,
            EaLength: 0,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .create()
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(STATUS_NOT_SUPPORTED)
            );
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
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
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
                    .map(crate::kernel::status::DriverError::ntstatus),
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
                assert_eq!(
                    Some(set.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
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
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
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
                    .map(crate::kernel::status::DriverError::ntstatus),
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
                    .map(crate::kernel::status::DriverError::ntstatus),
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
                assert_eq!(set.information_class(), SetVolumeInformationClass::Label);
            }
        }
    }

    #[test]
    fn query_volume_stack_decodes_supported_information_class() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        stack.Parameters.QueryVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_13 {
            Length: 128,
            __bindgen_padding_0: 0,
            FsInformationClass: wdk_sys::_FSINFOCLASS::FileFsFullSizeInformation,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_volume();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.length().as_usize(), 128);
                assert_eq!(
                    query.information_class(),
                    QueryVolumeInformationClass::FullSize
                );
            }
        }
    }

    #[test]
    fn volume_information_stack_rejects_unsupported_class_before_handler() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        stack.Parameters.QueryVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_13 {
            Length: 128,
            __bindgen_padding_0: 0,
            FsInformationClass: 0x7FFF_FFFF,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .query_volume()
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(wdk_sys::STATUS_INVALID_INFO_CLASS)
            );
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
                assert_eq!(
                    Some(set.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(
                    set.selection().owner(),
                    SecurityComponentSelection::Selected
                );
                assert_eq!(
                    set.selection().group(),
                    SecurityComponentSelection::Selected
                );
                assert_eq!(set.selection().dacl(), SecurityComponentSelection::Omitted);
                assert_eq!(
                    Some(set.security_descriptor()),
                    KernelSecurityDescriptor::from_raw(descriptor.as_ptr())
                );
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
                assert_eq!(
                    Some(read.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
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
                    .map(crate::kernel::status::DriverError::ntstatus),
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
                assert_eq!(
                    Some(write.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
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
                    .map(crate::kernel::status::DriverError::ntstatus),
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
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(query.length().as_usize(), 64);
                assert_eq!(
                    query.information_class(),
                    QueryFileInformationClass::Standard
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
                assert_eq!(
                    Some(set.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(set.length().as_usize(), 40);
                assert_eq!(set.information_class(), SetFileInformationClass::Basic);
            }
        }
    }

    #[test]
    fn file_information_stack_rejects_unsupported_class_before_handler() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QueryFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
            Length: 64,
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .query_file()
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(wdk_sys::STATUS_INVALID_INFO_CLASS)
            );
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
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(query.cursor_position(), DirectoryCursorPosition::Restart);
                assert_eq!(query.pattern(), DirectoryPatternInput::Name(file_name));
                assert_eq!(query.entry_emission(), DirectoryEntryEmission::Single);
                assert_eq!(query.length().as_usize(), 128);
                assert_eq!(
                    query.information_class(),
                    DirectoryInformationClass::Directory
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
