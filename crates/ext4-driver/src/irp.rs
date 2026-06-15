//! Typed IRP boundary shared by FSD dispatch modules.

use core::ptr::NonNull;

use wdk_sys::{PDEVICE_OBJECT, PIRP};

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
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use wdk_sys::STATUS_INVALID_PARAMETER;

    use super::DispatchTarget;

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
}
