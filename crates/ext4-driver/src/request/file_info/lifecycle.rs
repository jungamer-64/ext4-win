//! File-object admission, cleanup, close, and context release.

use super::*;

/// Captures FILE_OBJECT cache-map teardown work before cleanup releases handle-owned state.
/// # Errors
///
/// Returns a FILE_OBJECT, stream-identity, or lease failure before worker submission.
pub(crate) fn prepare_cleanup_cache_work(
    mut request: PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<Option<crate::irp::CacheWork>> {
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        if file_object.has_no_file_system_contexts() {
            return Ok(None);
        }
        match OpenedFileObject::decode(file_object)? {
            OpenedFileObject::Node(_) => operations
                .acquire_file_object_cache_lease(file_object)
                .map(crate::irp::CacheWork::uninitialize)
                .map(Some),
            OpenedFileObject::Volume(_) => Ok(None),
        }
    })
}

/// Captures one opened-handle lifecycle capability while the top-level IRP retains its contexts.
/// # Errors
///
/// Returns an error when a non-empty filesystem context pair is malformed.
pub(crate) fn prepare_handle_admission(
    mut request: PendingIrpLease<'_>,
) -> DriverResult<Option<PreparedHandleAdmission>> {
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        if file_object.has_no_file_system_contexts() {
            return Ok(None);
        }
        OpenedFileObject::decode(file_object)
            .map(OpenedFileObject::prepare_admission)
            .map(Some)
    })
}

/// Executes cleanup IRPs, including final-active-handle deferred deletion.
/// # Errors
///
/// Returns an error when the IRP stack has no opened FILE_OBJECT, cleanup state is invalid, or a
/// pending namespace deletion cannot be committed.
pub(crate) fn cleanup(
    mut request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<CleanupResolution> {
    let plan = request.with_active(|active| begin_cleanup_file_object(active, operations))?;
    Ok(match plan {
        CleanupPlan::Complete => CleanupResolution::Complete(IrpCompletion::EMPTY),
        CleanupPlan::Delete(plan) => CleanupResolution::Delete(plan),
    })
}

/// Result of entering one per-handle terminal cleanup barrier.
#[derive(Debug)]
pub(crate) enum CleanupResolution {
    /// Cleanup released every handle-owned resource without a namespace mutation.
    Complete(IrpCompletion),
    /// The final handle requires one journaled deletion before cleanup completes.
    Delete(PendingCleanupDeletion),
}

/// Allocation-free driver publication paired with a committed cleanup deletion.
#[derive(Debug)]
pub(crate) struct PreparedCleanupPublication {
    /// Shared FCB whose stable pending target becomes complete.
    fcb: NonNull<FileControlBlock>,
    /// FCB-owned target allocation consumed by the publication.
    target: NonNull<FileDeleteTarget>,
    /// Preallocated namespace notification.
    notification: DirectoryChange,
}

impl PreparedCleanupPublication {
    /// Publishes the completed deletion and notification without allocation or ordinary failure.
    pub(crate) fn publish(self, operations: &mut MountedVolumeAccess<'_>) -> IrpCompletion {
        operations.complete_file_delete(self.fcb, self.target);
        operations.report_directory_change(self.notification);
        IrpCompletion::EMPTY
    }
}

#[expect(
    unsafe_code,
    reason = "the cleanup publication remains reactor-owned while the handle barrier retains its pointers"
)]
// SAFETY: FCB/target lifetime is protected by the cleanup barrier through publication, and the
// token is moved only through reactor-owned operation state.
unsafe impl Send for PreparedCleanupPublication {}

/// Executes close IRPs and releases FILE_OBJECT contexts.
/// # Errors
///
/// Returns an error when the close stack has no FILE_OBJECT.
pub(crate) fn close(
    target: &mut ActiveIrp<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<IrpCompletion> {
    let file_object = target.current_stack()?.file_object()?;
    if release_file_contexts(target.device(), file_object, operations) == VolumeRetirement::Start {
        MountedVolumeDevice::schedule_retirement(target.device());
    }
    Ok(IrpCompletion::EMPTY)
}

/// Cleanup work selected after all synchronous FILE_OBJECT state has been released.
enum CleanupPlan {
    /// No namespace deletion became ready.
    Complete,
    /// The final active handle must remove one exact FCB-owned namespace link.
    Delete(PendingCleanupDeletion),
}

/// Actor-local deferred deletion plan whose FCB remains pinned by the cleanup FILE_OBJECT.
#[derive(Debug)]
pub(crate) struct PendingCleanupDeletion {
    /// Shared FCB retained until the later Close IRP.
    fcb: NonNull<FileControlBlock>,
    /// Immutable opened inode identity.
    node: NodeId,
    /// Stable FCB-owned target allocation.
    target: NonNull<FileDeleteTarget>,
    /// Whether dropping before a lower effect must restore the stream to the live namespace state.
    abort_on_drop: bool,
}

#[expect(
    unsafe_code,
    reason = "the cleanup plan remains reactor-owned while its FILE_OBJECT retains stable pointers"
)]
// SAFETY: The per-handle terminal barrier retains the FCB, target, and VCB until this value is
// consumed; it moves only between the sole reactor thread and lower completion envelopes.
unsafe impl Send for PendingCleanupDeletion {}

impl PendingCleanupDeletion {
    /// Returns the exact FCB retained by the cleanup FILE_OBJECT until Close.
    pub(crate) const fn file_control_block(&self) -> NonNull<FileControlBlock> {
        self.fcb
    }

    /// Returns the immutable inode selected by the shared delete-pending transition.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Prevents rollback after a lower write or flush can have an uncertain external effect.
    pub(crate) fn preserve_pending_after_uncertain_effect(&mut self) {
        self.abort_on_drop = false;
    }

    /// Publishes a pre-effect cleanup failure before the failure completion becomes observable.
    pub(crate) fn abort_before_failure_completion(&mut self) {
        if self.abort_on_drop {
            crate::state::abort_cleanup_file_delete(self.fcb, self.target);
            self.abort_on_drop = false;
        }
    }
}

impl Drop for PendingCleanupDeletion {
    fn drop(&mut self) {
        if self.abort_on_drop {
            crate::state::abort_cleanup_file_delete(self.fcb, self.target);
        }
    }
}

/// Releases resources owned by one FILE_OBJECT handle lifecycle.
/// # Errors
///
/// Returns an error when the FILE_OBJECT has no opened context.
fn begin_cleanup_file_object(
    active: &mut ActiveIrp<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<CleanupPlan> {
    let file_object = active.current_stack()?.file_object()?;
    let opened_file = OpenedFileObject::decode(file_object)?;
    match opened_file {
        OpenedFileObject::Node(opened_file) => {
            cleanup_opened_node(active, file_object, opened_file)
        }
        OpenedFileObject::Volume(opened_volume) => {
            cleanup_opened_volume(active.device(), file_object, opened_volume, operations)?;
            Ok(CleanupPlan::Complete)
        }
    }
}

/// Releases cleanup-owned state for one namespace-node FILE_OBJECT.
/// # Errors
///
/// Returns an error when the requestor process identity is unavailable.
fn cleanup_opened_node(
    active: &ActiveIrp<'_>,
    file_object: ActiveFileObject<'_>,
    opened_file: OpenedObject<'_>,
) -> DriverResult<CleanupPlan> {
    let requestor = active.requestor_process()?;
    let cleanup_was_published = file_object.cleanup_complete();
    match (opened_file.begin_cleanup(), cleanup_was_published) {
        (CleanupStart::First, false) => {}
        (CleanupStart::AlreadyComplete, true) => return Ok(CleanupPlan::Complete),
        (CleanupStart::First, true) | (CleanupStart::AlreadyComplete, false) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                .bugcheck();
        }
    }
    cleanup_directory_notification(&opened_file);
    opened_file
        .file_control_block()
        .release_handle_byte_range_locks(requestor, file_object.address());
    let cleanup = opened_file.release_share_access_for_cleanup();
    let fcb = opened_file.file_control_block_address();
    let node = opened_file.node();
    opened_file.finish_cleanup();
    file_object.mark_cleanup_complete();
    Ok(match cleanup {
        FileCleanupDisposition::Retained => CleanupPlan::Complete,
        FileCleanupDisposition::Delete(target) => CleanupPlan::Delete(PendingCleanupDeletion {
            fcb,
            node,
            target,
            abort_on_drop: true,
        }),
    })
}

/// Removes an identity-checked pending link after the final active handle cleanup.
/// # Errors
///
/// Returns an error when the target name no longer identifies the FCB inode, the directory is no
/// longer empty, or the ext4 transaction cannot be committed.
#[expect(
    unsafe_code,
    reason = "the cleanup FILE_OBJECT retains the FCB-owned delete target until staged publication"
)]
pub(crate) fn stage_cleanup_deletion(
    plan: &PendingCleanupDeletion,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<PreparedCleanupPublication> {
    let target = unsafe {
        // SAFETY: The cleanup FILE_OBJECT retains `fcb` until its later Close IRP. The FCB owns this
        // stable allocation in Pending state, and the device actor cannot mutate that state until
        // this function calls `complete_file_delete` after the final await.
        plan.target.as_ref()
    };
    let parent = mutation.load_directory(target.parent())?;
    match mutation.lookup_child(&parent, target.name())? {
        ChildLookup::Found(child) if *child.node() == plan.node => {}
        ChildLookup::Found(_) | ChildLookup::NotFound => return Err(DriverError::CannotDelete),
    }
    let notification = DirectoryChange::new(
        target.parent(),
        target.name(),
        plan.node,
        DirectoryChangeAction::Removed,
    )?;
    let parent = mutation.directory(target.parent())?;
    match plan.node {
        NodeId::File(_) => mutation.unlink_file(parent, target.name())?,
        NodeId::Directory(_) => {
            mutation.remove_empty_directory(parent, target.name())?;
        }
        NodeId::Symlink(_) => mutation.remove_symlink(parent, target.name())?,
    }
    Ok(PreparedCleanupPublication {
        fcb: plan.fcb,
        target: plan.target,
        notification,
    })
}

/// Removes one direct-volume share claim during its cleanup barrier.
/// # Errors
///
/// Returns an error when FILE_OBJECT and handle lifecycle state disagree.
fn cleanup_opened_volume(
    device: crate::state::KernelDevice,
    file_object: ActiveFileObject<'_>,
    opened_volume: crate::state::OpenedVolume<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<()> {
    let cleanup_was_published = file_object.cleanup_complete();
    match (opened_volume.begin_cleanup(), cleanup_was_published) {
        (CleanupStart::First, false) => {}
        (CleanupStart::AlreadyComplete, true) => return Ok(()),
        (CleanupStart::First, true) | (CleanupStart::AlreadyComplete, false) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                .bugcheck();
        }
    }
    if !operations.owns_volume(opened_volume.volume()) {
        return Err(DriverError::InvalidDeviceRequest);
    }
    let effect = operations.cleanup_volume_handle(opened_volume.file_object());
    if effect == VolumeHandleCleanup::Unlocked {
        MountedVolumeDevice::publish_volume_lock(device, false);
    }
    opened_volume.finish_cleanup();
    file_object.mark_cleanup_complete();
    Ok(())
}

/// Releases FsRtl notification records owned by a FILE_OBJECT during its cleanup transition.
#[expect(
    unsafe_code,
    reason = "the active opened handle retains its mounted VCB through the cleanup transition"
)]
fn cleanup_directory_notification(opened_file: &OpenedObject<'_>) {
    let volume = opened_file.volume();
    let vcb = unsafe {
        // SAFETY: The opened FILE_OBJECT keeps its FCB and mounted VCB alive
        // throughout cleanup, before the CCB context is released at close.
        volume.as_ref()
    };
    vcb.directory_change_notifier()
        .cleanup(opened_file.notification_context());
}
/// Detaches and releases heap-owned FCB and CCB pointers stored on a FILE_OBJECT.
#[expect(
    unsafe_code,
    reason = "close consumes the unique Box pointers detached from the active FILE_OBJECT contexts"
)]
fn release_file_contexts(
    device: crate::state::KernelDevice,
    file_object: ActiveFileObject<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> VolumeRetirement {
    if file_object.has_no_file_system_contexts() {
        return VolumeRetirement::Retained;
    }
    let close_kind = file_object.close_kind_or_bugcheck();
    let opened = match OpenedFileObject::decode(file_object) {
        Ok(opened) => opened,
        Err(_) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                .bugcheck();
        }
    };
    match opened {
        OpenedFileObject::Node(opened) => {
            let volume = opened.volume();
            let release_plan = opened.close_release_plan(close_kind);
            let file_object_address = file_object.address();
            let (fcb, handle) = opened.take_node_contexts();
            match release_plan {
                CloseReleasePlan::CleanedHandle => release_file_control_block(fcb),
                CloseReleasePlan::CancelledOpen => {
                    release_cancelled_file_control_block(fcb, file_object_address);
                }
            }
            unsafe {
                // SAFETY: Successful node create stores Box<OpenedHandle> in FsContext2. Close
                // detached the unique owning pointer before this terminal drop.
                drop(Box::from_raw(handle.as_ptr()));
            }
            if !operations.owns_volume(volume) {
                crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                    .bugcheck();
            }
            operations.close_node_file_object()
        }
        OpenedFileObject::Volume(opened) => {
            let release_plan = opened.close_release_plan(close_kind);
            let file_object_address = opened.file_object();
            let (volume, handle) = opened.take_volume_contexts();
            if !operations.owns_volume(volume) {
                crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                    .bugcheck();
            }
            let outcome = operations.close_volume_file_object(file_object_address, release_plan);
            if outcome.cleanup() == VolumeHandleCleanup::Unlocked {
                MountedVolumeDevice::publish_volume_lock(device, false);
            }
            unsafe {
                // SAFETY: Successful volume create stores Box<OpenedVolumeHandle> in FsContext2.
                // Close detached the unique owning pointer before this terminal drop.
                drop(Box::from_raw(handle.as_ptr()));
            }
            outcome.retirement()
        }
    }
}
