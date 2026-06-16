//! Typed IRP boundary shared by FSD dispatch modules.

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
            // SAFETY: SystemBuffer is the active AssociatedIrp arm for buffered
            // query/set information requests delivered to this driver.
            irp.AssociatedIrp.SystemBuffer
        };
        NonNull::new(system_buffer)
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
}
