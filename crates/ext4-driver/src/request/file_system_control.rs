//! File-system-control admission and mounted lifecycle boundaries.

use crate::irp::IrpCompletion;
use crate::kernel::status::{DriverError, DriverResult};

/// Executes device control requests addressed to this FSD.
/// # Errors
///
/// Always returns `InvalidDeviceRequest`; device controls are not owned by this FSD path.
pub(crate) fn device_control() -> DriverResult<IrpCompletion> {
    Err(DriverError::InvalidDeviceRequest)
}
