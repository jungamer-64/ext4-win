//! Windows dirty controls project the committed ext4 health state.

use crate::irp::{IrpCompletion, PendingIrpLease};
use crate::kernel::status::{DriverError, DriverResult};
use crate::state::{MountedVolumeAccess, OpenedVolume};

/// Validates one direct-volume control without deriving media authority from mere identity.
/// # Errors
/// Returns non-volume/foreign identity, dismount, lock exclusion or malformed buffer lengths.
fn authorize(
    request: &mut PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<()> {
    request.with_active(|active| {
        let current = active.current_stack()?;
        let volume = OpenedVolume::decode(current.file_object()?)?;
        if !operations.owns_volume(volume.volume()) {
            return Err(DriverError::InvalidParameter);
        }
        operations.authorize_handle(volume.file_object())?;
        let control = current.file_system_control()?;
        if !control.input_buffer_length().is_empty() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    })
}

/// Reports only the persistent check requirement, independently of an active journal session.
/// # Errors
/// Returns direct-volume authority, malformed buffers or a missing four-byte output prefix.
pub(super) fn query(
    mut request: PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<IrpCompletion> {
    authorize(&mut request, operations)?;
    let flags = u32::from(operations.volume_requires_check());
    request.with_active(|active| {
        let control = active.current_stack()?.file_system_control()?;
        let output = active.buffered_output(control.output_buffer_length().prefix(4)?)?;
        crate::wire::LittleEndianOutput::new(output)
            .write_u32(crate::wire::WireOffset::new(0), flags)?;
        IrpCompletion::from_usize(4)
    })
}

/// Journals an explicit error-state bit using original-thread privilege and current RW admission.
/// # Errors
/// Returns direct-volume authority, malformed buffers or rejected mutation state.
pub(super) fn mark(
    mut request: PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
    mutation: &mut super::DriverMutationPass<'_, '_, '_>,
) -> DriverResult<IrpCompletion> {
    authorize(&mut request, operations)?;
    request.with_active(|active| {
        if !active
            .current_stack()?
            .file_system_control()?
            .output_buffer_length()
            .is_empty()
        {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    })?;
    mutation.mark_volume_dirty()?;
    Ok(IrpCompletion::EMPTY)
}
