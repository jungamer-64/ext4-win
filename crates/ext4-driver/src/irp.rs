//! Typed IRP boundary shared by FSD dispatch modules.

use core::ffi::c_void;
use core::ptr::NonNull;

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
            output_buffer_length: mount.OutputBufferLength,
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
            input_buffer_length: control.InputBufferLength,
            output_buffer_length: control.OutputBufferLength,
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
        Ok(CreateStack {
            file_object,
            options: create.Options,
            share_access: create.ShareAccess,
            ea_length: create.EaLength,
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
            length: query.Length,
            information_class: query.FsInformationClass,
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
            length: query.Length,
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
            length: set.Length,
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
        Ok(QueryDirectoryStack {
            file_object: self.file_object()?,
            flags: stack.Flags,
            length: query.Length,
            file_name: NonNull::new(query.FileName),
            information_class: query.FileInformationClass,
            file_index: query.FileIndex,
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
        Ok(QueryEaStack {
            file_object: self.file_object()?,
            flags: stack.Flags,
            length: query.Length,
            ea_list: NonNull::new(query.EaList.cast::<u8>()),
            ea_list_length: query.EaListLength,
            ea_index: query.EaIndex,
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
            length: set.Length,
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
            security_information: query.SecurityInformation,
            length: query.Length,
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
            security_information: set.SecurityInformation,
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
        Ok(ReadStack {
            file_object: self.file_object()?,
            length: read.Length,
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
        Ok(WriteStack {
            file_object: self.file_object()?,
            length: write.Length,
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

/// Decoded mount-volume stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountVolumeStack {
    /// VPB supplied by the I/O Manager for the target volume.
    vpb: NonNull<wdk_sys::VPB>,
    /// Lower storage device object to mount.
    target_device: NonNull<wdk_sys::DEVICE_OBJECT>,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: wdk_sys::ULONG,
}

/// Decoded user file-system-control stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileSystemControlStack {
    /// FILE_OBJECT carrying the FCB/CCB for path-scoped controls.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Input system-buffer length.
    input_buffer_length: wdk_sys::ULONG,
    /// Output system-buffer length.
    output_buffer_length: wdk_sys::ULONG,
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
    pub(crate) const fn output_buffer_length(self) -> wdk_sys::ULONG {
        self.output_buffer_length
    }
}

impl FileSystemControlStack {
    /// Returns the FILE_OBJECT carrying this FSCTL.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the input system-buffer length.
    pub(crate) const fn input_buffer_length(self) -> wdk_sys::ULONG {
        self.input_buffer_length
    }

    /// Returns the output system-buffer length.
    pub(crate) const fn output_buffer_length(self) -> wdk_sys::ULONG {
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
    /// Packed create disposition/options field.
    options: wdk_sys::ULONG,
    /// Share-access bits requested by the opener.
    share_access: wdk_sys::USHORT,
    /// Extended-attribute input length supplied with create.
    ea_length: wdk_sys::ULONG,
}

impl CreateStack {
    /// Returns the FILE_OBJECT receiving this create request.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
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
    pub(crate) const fn ea_length(self) -> wdk_sys::ULONG {
        self.ea_length
    }
}

/// Decoded query-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryVolumeStack {
    /// Output buffer length.
    length: wdk_sys::ULONG,
    /// Requested filesystem information class.
    information_class: wdk_sys::FS_INFORMATION_CLASS,
}

/// Decoded query-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Output buffer length.
    length: wdk_sys::ULONG,
    /// Requested file information class.
    information_class: wdk_sys::FILE_INFORMATION_CLASS,
}

/// Decoded set-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Input buffer length.
    length: wdk_sys::ULONG,
    /// Requested file information class.
    information_class: wdk_sys::FILE_INFORMATION_CLASS,
}

/// Decoded query-directory stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryDirectoryStack {
    /// FILE_OBJECT carrying the directory CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Query-directory SL_* flags.
    flags: wdk_sys::UCHAR,
    /// Output buffer length.
    length: wdk_sys::ULONG,
    /// Optional filename pattern supplied by the caller.
    file_name: Option<NonNull<wdk_sys::UNICODE_STRING>>,
    /// Requested directory information class.
    information_class: wdk_sys::FILE_INFORMATION_CLASS,
    /// Caller-supplied file index when SL_INDEX_SPECIFIED is set.
    file_index: wdk_sys::ULONG,
}

/// Decoded query-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Query-EA SL_* flags.
    flags: wdk_sys::UCHAR,
    /// Output buffer length.
    length: wdk_sys::ULONG,
    /// Optional FILE_GET_EA_INFORMATION list.
    ea_list: Option<NonNull<u8>>,
    /// Optional EA list byte length.
    ea_list_length: wdk_sys::ULONG,
    /// Caller-supplied EA index when SL_INDEX_SPECIFIED is set.
    ea_index: wdk_sys::ULONG,
}

/// Decoded set-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Input FILE_FULL_EA_INFORMATION byte length.
    length: wdk_sys::ULONG,
}

/// Decoded query-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QuerySecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Requested SECURITY_INFORMATION bitmask.
    security_information: wdk_sys::SECURITY_INFORMATION,
    /// Output buffer length.
    length: wdk_sys::ULONG,
}

/// Decoded set-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetSecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// SECURITY_INFORMATION bitmask selected for mutation.
    security_information: wdk_sys::SECURITY_INFORMATION,
    /// Caller-supplied security descriptor.
    security_descriptor: NonNull<c_void>,
}

/// Decoded read stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Requested byte count.
    length: wdk_sys::ULONG,
    /// Requested byte offset.
    byte_offset: wdk_sys::LONGLONG,
}

impl ReadStack {
    /// Returns the FILE_OBJECT carrying this read.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
        self.length
    }

    /// Returns the requested byte offset.
    pub(crate) const fn byte_offset(self) -> wdk_sys::LONGLONG {
        self.byte_offset
    }
}

/// Decoded write stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriteStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Requested byte count.
    length: wdk_sys::ULONG,
    /// Requested byte offset.
    byte_offset: wdk_sys::LONGLONG,
}

impl WriteStack {
    /// Returns the FILE_OBJECT carrying this write.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
        self.length
    }

    /// Returns the requested byte offset.
    pub(crate) const fn byte_offset(self) -> wdk_sys::LONGLONG {
        self.byte_offset
    }
}

impl QueryVolumeStack {
    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
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
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
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
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
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

    /// Returns query-directory SL_* flags.
    pub(crate) const fn flags(self) -> wdk_sys::UCHAR {
        self.flags
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
        self.length
    }

    /// Returns the optional filename pattern.
    pub(crate) const fn file_name(self) -> Option<NonNull<wdk_sys::UNICODE_STRING>> {
        self.file_name
    }

    /// Returns the requested directory information class.
    pub(crate) const fn information_class(self) -> wdk_sys::FILE_INFORMATION_CLASS {
        self.information_class
    }

    /// Returns the caller-supplied file index.
    pub(crate) const fn file_index(self) -> wdk_sys::ULONG {
        self.file_index
    }
}

impl QueryEaStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns query-EA SL_* flags.
    pub(crate) const fn flags(self) -> wdk_sys::UCHAR {
        self.flags
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
        self.length
    }

    /// Returns the optional input EA name list.
    pub(crate) const fn ea_list(self) -> Option<NonNull<u8>> {
        self.ea_list
    }

    /// Returns the optional EA name list byte length.
    pub(crate) const fn ea_list_length(self) -> wdk_sys::ULONG {
        self.ea_list_length
    }

    /// Returns the caller-supplied EA index.
    pub(crate) const fn ea_index(self) -> wdk_sys::ULONG {
        self.ea_index
    }
}

impl SetEaStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the input FILE_FULL_EA_INFORMATION byte length.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
        self.length
    }
}

impl QuerySecurityStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the requested SECURITY_INFORMATION bitmask.
    pub(crate) const fn security_information(self) -> wdk_sys::SECURITY_INFORMATION {
        self.security_information
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> wdk_sys::ULONG {
        self.length
    }
}

impl SetSecurityStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> NonNull<wdk_sys::FILE_OBJECT> {
        self.file_object
    }

    /// Returns the SECURITY_INFORMATION mutation bitmask.
    pub(crate) const fn security_information(self) -> wdk_sys::SECURITY_INFORMATION {
        self.security_information
    }

    /// Returns the caller-supplied security descriptor.
    pub(crate) const fn security_descriptor(self) -> NonNull<c_void> {
        self.security_descriptor
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use wdk_sys::STATUS_INVALID_PARAMETER;

    use super::{CurrentIrpStackLocation, DispatchTarget};

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
                assert_eq!(mount.output_buffer_length(), 16);
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
                assert_eq!(control.input_buffer_length(), 32);
                assert_eq!(control.output_buffer_length(), 128);
                assert_eq!(control.fs_control_code(), 589_992);
            }
        }
    }

    #[test]
    fn query_ea_stack_preserves_file_object_flags_lengths_list_and_index() {
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
            EaIndex: 2,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_ea();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.file_object(), file_object);
                assert_eq!(query.flags(), stack.Flags);
                assert_eq!(query.length(), 128);
                assert_eq!(query.ea_list(), Some(ea_list));
                assert_eq!(query.ea_list_length(), 24);
                assert_eq!(query.ea_index(), 2);
            }
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
                assert_eq!(set.length(), 64);
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
                    query.security_information(),
                    wdk_sys::OWNER_SECURITY_INFORMATION | wdk_sys::DACL_SECURITY_INFORMATION
                );
                assert_eq!(query.length(), 256);
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
                    set.security_information(),
                    wdk_sys::OWNER_SECURITY_INFORMATION | wdk_sys::GROUP_SECURITY_INFORMATION
                );
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
                assert_eq!(read.length(), 4096);
                assert_eq!(read.byte_offset(), 8192);
            }
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
                assert_eq!(write.length(), 2048);
                assert_eq!(write.byte_offset(), 4096);
            }
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
                assert_eq!(query.length(), 64);
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
                assert_eq!(set.length(), 40);
                assert_eq!(
                    set.information_class(),
                    wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation
                );
            }
        }
    }

    #[test]
    fn query_directory_stack_preserves_file_object_flags_length_name_class_and_index() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let file_name = NonNull::<wdk_sys::UNICODE_STRING>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_RESTART_SCAN).unwrap_or(u8::MAX);
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
                assert_eq!(query.flags(), stack.Flags);
                assert_eq!(query.length(), 128);
                assert_eq!(query.file_name(), Some(file_name));
                assert_eq!(
                    query.information_class(),
                    wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation
                );
                assert_eq!(query.file_index(), 3);
            }
        }
    }
}
