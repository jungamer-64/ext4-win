//! Physical-map controls retain requestor identities and stream exclusion through publication.

use crate::irp::{IrpCompletion, PendingIrpLease, PreparedClusterControl, RegularFileWriteAccess};
use crate::kernel::status::{DriverError, DriverResult};
use crate::state::{MountedVolumeAccess, OpenedObject, OpenedRegularFile, OpenedVolume};
use core::ptr::NonNull;

/// Exact immutable relocation range and its consuming native preparation state.
#[derive(Debug)]
pub(super) struct RelocationRequest {
    /// File identity retained by the captured native object reference and stream lease.
    file: ext4_core::FileNodeId,
    /// Cluster-aligned logical byte coordinate.
    start: ext4_core::FileOffset,
    /// Allocation-origin-relative physical coordinate.
    destination: ext4_core::ClusterAddress,
    /// Nonzero allocation count.
    count: ext4_core::ClusterCount,
    /// Captured target handle rights used for encrypted-file admission.
    granted: u32,
    /// Native data routes must be frozen before core resolution can copy physical blocks.
    preparation: RelocationPreparation,
}

#[derive(Debug)]
/// Native preparation owns the transition from retained stream to frozen physical-map authority.
enum RelocationPreparation {
    /// No blocking native calls have run.
    Required(crate::state::StreamRelocationLease),
    /// A passive worker uniquely owns the lease.
    Preparing,
    /// Exact logical data remains frozen through durable map publication.
    Sealed(crate::state::PreparedStreamRelocation),
    /// Durable map publication consumed the exclusion.
    Published,
}

impl RelocationRequest {
    /// Captures a direct-volume request and its exact referenced target before native deferral.
    /// # Errors
    /// Returns foreign/lifecycle/volume access, paging-file, protected-stream or range failures.
    pub(super) fn prepare(mut request: PendingIrpLease<'_>, operations: &MountedVolumeAccess<'_>) -> DriverResult<Self> {
        let volume_file = request.with_active(|active| {
            let volume = OpenedVolume::decode(active.current_stack()?.file_object()?)?;
            if !operations.owns_volume(volume.volume()) { return Err(DriverError::InvalidParameter); }
            volume.require_data_write()?;
            operations.authorize_handle(volume.file_object())?;
            Ok(volume.file_object())
        })?;
        let PreparedClusterControl::Move { file, vcn, lcn, count, granted } = request.cluster_control()? else {
            return Err(DriverError::InvalidDeviceRequest);
        };
        let (node, stream) = file.with_file(|file| {
            if !file.address().shares_volume(volume_file) { return Err(DriverError::InvalidParameter); }
            let opened = OpenedRegularFile::decode(file)?;
            if opened.file_control_block().is_paging_file() { return Err(DriverError::AccessDenied); }
            operations.authorize_handle(opened.file_object())?;
            let stream = operations.prepare_stream_relocation(NonNull::from(opened.file_control_block()), opened.id())?;
            Ok::<_, DriverError>((opened.id(), stream))
        })?;
        let cluster_bytes = u64::from(operations.volume_geometry().cluster_size().bytes());
        let start = vcn.checked_mul(cluster_bytes).ok_or(DriverError::InvalidParameter)?;
        let _end = count.as_u64().checked_mul(cluster_bytes).and_then(|width| start.checked_add(width))
            .filter(|end| *end <= i64::MAX.unsigned_abs()).ok_or(DriverError::InvalidParameter)?;
        Ok(Self { file: node, start: ext4_core::FileOffset::from_bytes(start), destination: *lcn,
            count: *count, granted: *granted, preparation: RelocationPreparation::Required(stream) })
    }

    /// Returns whether this attempt must leave the actor before reading physical payload.
    pub(super) fn requires_preparation(&self) -> bool { matches!(self.preparation, RelocationPreparation::Required(_)) }

    /// Transfers blocking preparation to the passive worker exactly once.
    /// # Errors
    /// Returns an invariant violation if native preparation was already consumed.
    pub(super) fn begin_preparation(&mut self) -> DriverResult<crate::state::StreamRelocationLease> {
        match core::mem::replace(&mut self.preparation, RelocationPreparation::Preparing) {
            RelocationPreparation::Required(stream) => Ok(stream),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Consumes the passive result without dropping its exclusive stream authority.
    /// # Errors
    /// Returns mismatched preparation or native target identity.
    pub(super) fn seal(&mut self, prepared: crate::state::PreparedStreamRelocation) -> DriverResult<()> {
        if !matches!(self.preparation, RelocationPreparation::Preparing) || !prepared.authorizes(self.file) {
            return Err(DriverError::InternalInvariantViolation);
        }
        self.preparation = RelocationPreparation::Sealed(prepared);
        Ok(())
    }

    /// Copies raw physical payload only while this exact stream remains frozen.
    /// # Errors
    /// Returns rights, stale stream, extent/range, allocation or physical storage failures.
    pub(super) fn resolve(&self, mutation: &mut super::DriverMutationPass<'_, '_, '_>) -> DriverResult<IrpCompletion> {
        let RelocationPreparation::Sealed(prepared) = &self.preparation else { return Err(DriverError::InternalInvariantViolation); };
        if !prepared.authorizes(self.file) { return Err(DriverError::FileClosed); }
        if mutation.staged_node_metadata(ext4_core::NodeId::File(self.file))?.is_encrypted()
            && self.granted & (wdk_sys::FILE_READ_DATA | wdk_sys::FILE_WRITE_DATA | wdk_sys::FILE_APPEND_DATA | wdk_sys::FILE_EXECUTE) == 0 {
            return Err(DriverError::AccessDenied);
        }
        let file = mutation.file(self.file)?;
        mutation.move_file_clusters(file, self.start, self.destination, self.count)?;
        Ok(IrpCompletion::EMPTY)
    }

    /// Releases frozen-data admission only after the committed physical map is visible.
    pub(super) fn publish(&mut self) { self.preparation = RelocationPreparation::Published; }
}

/// Installs idempotent movement protection for one exact active FILE_OBJECT.
/// # Errors
/// Returns malformed/foreign volume references, lifecycle or active movement conflicts.
pub(super) fn mark_handle(mut request: PendingIrpLease<'_>, operations: &MountedVolumeAccess<'_>) -> DriverResult<IrpCompletion> {
    let (fcb, source) = request.with_active(|active| {
        let opened = OpenedObject::decode(active.current_stack()?.file_object()?)?;
        if !operations.owns_volume(opened.volume()) { return Err(DriverError::InvalidParameter); }
        operations.authorize_handle(opened.file_object())?;
        Ok::<_, DriverError>((opened.file_control_block_address(), opened.file_object()))
    })?;
    let PreparedClusterControl::Mark { volume, protect } = request.cluster_control()? else { return Err(DriverError::InvalidDeviceRequest); };
    if let Some(volume) = volume {
        volume.with_file(|file| {
            let volume = OpenedVolume::decode(file)?;
            if !operations.owns_volume(volume.volume()) || !source.shares_volume(volume.file_object()) {
                return Err(DriverError::InvalidParameter);
            }
            operations.authorize_handle(volume.file_object())
        })?;
    }
    if *protect { operations.protect_file_clusters(fcb, source)?; }
    Ok(IrpCompletion::EMPTY)
}

/// Enables persistent zero retirement under the target file's retained write grant.
/// # Errors
/// Returns nonempty buffers, handle authority, inode policy, storage or allocation failure.
pub(super) fn set_zero_on_deallocation(mut request: PendingIrpLease<'_>, operations: &MountedVolumeAccess<'_>, mutation: &mut super::DriverMutationPass<'_, '_, '_>) -> DriverResult<IrpCompletion> {
    super::file_system_control::authorize_path_handle(&mut request, operations)?;
    request.with_active(|active| {
        let stack = active.current_stack()?;
        let control = stack.file_system_control()?;
        if !control.input_buffer_length().is_empty() || !control.output_buffer_length().is_empty() { return Err(DriverError::InvalidParameter); }
        let regular = OpenedRegularFile::decode(stack.file_object()?)?;
        if regular.write_access() != RegularFileWriteAccess::Positional { return Err(DriverError::AccessDenied); }
        let file = mutation.file(regular.id())?;
        mutation.set_zero_on_deallocation(file)?;
        Ok(IrpCompletion::EMPTY)
    })
}
