//! File object IRP handlers and file information packing boundary.

use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_NOT_SUPPORTED, STATUS_SUCCESS};

use crate::irp::DispatchTarget;

/// Handles regular file data reads.
pub(crate) fn read(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles regular file data writes.
pub(crate) fn write(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Flushes cached or ordered file data.
pub(crate) fn flush(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(_target) => STATUS_SUCCESS,
        Err(error) => error.ntstatus(),
    }
}

/// Handles file information queries.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles file information mutations.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles directory enumeration and notification.
pub(crate) fn directory_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles security descriptor queries.
pub(crate) fn query_security(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp) {
        Ok(target) => {
            let _device = target.device();
            let _irp = target.irp();
            crate::status::DriverError::AccessDenied.ntstatus()
        }
        Err(error) => error.ntstatus(),
    }
}

/// Handles security descriptor mutations.
pub(crate) fn set_security(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles extended-attribute queries.
pub(crate) fn query_ea(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles extended-attribute mutations.
pub(crate) fn set_ea(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles byte-range lock requests.
pub(crate) fn lock_control(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Rejects a decoded file-object request until its domain path exists.
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
