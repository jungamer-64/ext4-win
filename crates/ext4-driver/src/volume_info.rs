//! Volume information query and mutation boundary.

use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_NOT_SUPPORTED};

use crate::irp::DispatchTarget;

/// Handles volume information queries.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Handles volume information mutations.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    decoded_not_supported(device, irp)
}

/// Rejects decoded volume information requests until VCB-backed state exists.
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
