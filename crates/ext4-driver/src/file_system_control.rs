//! File-system control, mount, reparse, and device-control dispatch boundary.

use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_NOT_SUPPORTED};

use crate::irp::DispatchTarget;

/// Handles create/open requests.
pub(crate) fn create(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles file-system control requests, including mount and reparse controls.
pub(crate) fn dispatch(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles device control requests addressed to this FSD.
pub(crate) fn device_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            crate::status::DriverError::InvalidDeviceRequest.ntstatus()
        }
        Err(error) => error.ntstatus(),
    }
}

/// Rejects a decoded FSCTL until a dedicated control path owns it.
fn decoded_not_supported(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            STATUS_NOT_SUPPORTED
        }
        Err(error) => error.ntstatus(),
    }
}
