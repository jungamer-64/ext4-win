//! File-object admission, cleanup, close, and context release.

use super::*;

/// Retains the stream before cleanup transfers its IRP to native cache-map teardown.
/// # Errors
///
/// Returns a FILE_OBJECT, stream-identity, or lease failure before worker submission.
pub(crate) fn prepare_cleanup_cache_lease(
    mut request: PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<Option<crate::state::FileObjectCacheLease>> {
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        if file_object.has_no_file_system_contexts() {
            return Ok(None);
        }
        match OpenedFileObject::decode(file_object)? {
            OpenedFileObject::Node(_) => operations
                .acquire_file_object_cache_lease(file_object)
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

/// Executes cleanup IRPs, including link-local deferred deletion.
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
    /// Cleanup owns ready link deletions that require a journaled namespace result.
    Delete(PendingCleanupDeletion),
}

/// One namespace removal whose storage and notification are prepared before irreversible I/O.
#[derive(Clone, Copy, Debug)]
struct CleanupLinkPublication {
    /// Exact allocation claimed by this cleanup batch.
    target: NonNull<FileDeleteTarget>,
    /// Namespace observation prepared before irreversible I/O.
    notification: DirectoryChange,
}
/// Allocation-free publication of all ready link deletions claimed by this cleanup.
#[derive(Debug)]
pub(crate) struct PreparedCleanupPublication {
    /// The cleanup FILE_OBJECT retains this inode stream throughout the batch.
    fcb: NonNull<FileControlBlock>,
    /// Each claimed link has one post-commit outcome.
    links: DriverVec<CleanupLinkPublication>,
    /// Only the final remaining inode link can wait for active file-id handles.
    deferred: Option<NonNull<FileDeleteTarget>>,
}
impl PreparedCleanupPublication {
    /// Publishes the atomic namespace result and every prepared notification without allocation.
    pub(crate) fn publish(self, operations: &mut MountedVolumeAccess<'_>) -> IrpCompletion {
        for link in self.links.iter() {
            operations.complete_file_delete(self.fcb, link.target);
            operations.report_directory_change(link.notification);
        }
        if let Some(target) = self.deferred {
            operations.defer_file_delete(self.fcb, target);
        }
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
    /// Cleanup must finalize the claimed namespace links.
    Delete(PendingCleanupDeletion),
}

/// Actor-local deferred deletion plan whose FCB remains pinned by the cleanup FILE_OBJECT.
#[derive(Debug)]
pub(crate) struct PendingCleanupDeletion {
    /// Shared FCB retained until the later Close IRP.
    fcb: NonNull<FileControlBlock>,
    /// Immutable opened inode identity.
    node: NodeId,
    /// Stable link-owned target allocation.
    target: NonNull<FileDeleteTarget>,
    /// Additional ready links, acquired before parent oplock checks and commit preparation.
    additional: DriverVec<NonNull<FileDeleteTarget>>,
    /// Whether a known pre-effect failure must restore the claimed links to live state.
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

    /// Returns the immutable inode shared by the claimed namespace links.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Iterates uniquely claimed targets; their stable allocations belong to this batch's FCB.
    fn targets(&self) -> impl Iterator<Item = NonNull<FileDeleteTarget>> + '_ {
        core::iter::once(self.target).chain(self.additional.iter().copied())
    }
    /// Claims ready links so a final file-id cleanup cannot lose several deferred deletions.
    /// # Errors
    /// Returns allocation failure before external effects, restoring the unretained claim.
    pub(crate) fn capture_ready(
        &mut self,
        operations: &MountedVolumeAccess<'_>,
    ) -> DriverResult<()> {
        while let FileCleanupDisposition::Delete(target) = operations.claim_file_delete(self.fcb) {
            if let Err(error) = self.additional.try_push(target) {
                crate::state::abort_cleanup_file_delete(self.fcb, target);
                return Err(error);
            }
        }
        Ok(())
    }
    /// Selects an exact parent whose removal protocol has not yet completed for this batch.
    #[expect(
        unsafe_code,
        reason = "the cleanup FILE_OBJECT retains every claimed target until its final outcome"
    )]
    pub(crate) fn unchecked_parent(
        &self,
        authorized: impl Fn(DirectoryNodeId) -> bool,
    ) -> Option<DirectoryNodeId> {
        self.targets().find_map(|target| {
            let parent = unsafe {
                // SAFETY: All targets are claimed in this FCB and retained through publication or abort.
                target.as_ref().parent()
            };
            (!authorized(parent)).then_some(parent)
        })
    }

    /// Prevents rollback after a lower write or flush can have an uncertain external effect.
    pub(crate) fn preserve_pending_after_uncertain_effect(&mut self) {
        self.abort_on_drop = false;
    }

    /// Publishes a pre-effect cleanup failure before the failure completion becomes observable.
    pub(crate) fn abort_before_failure_completion(&mut self) {
        if self.abort_on_drop {
            for target in self.targets() {
                crate::state::abort_cleanup_file_delete(self.fcb, target);
            }
            self.abort_on_drop = false;
        }
    }
}

impl Drop for PendingCleanupDeletion {
    fn drop(&mut self) {
        self.abort_before_failure_completion();
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
        OpenedFileObject::Node(opened_file) => Ok(cleanup_opened_node(file_object, opened_file)),
        OpenedFileObject::Volume(opened_volume) => {
            cleanup_opened_volume(active.device(), file_object, opened_volume, operations)?;
            Ok(CleanupPlan::Complete)
        }
    }
}

/// Releases cleanup-owned state for one namespace-node FILE_OBJECT.
fn cleanup_opened_node(
    file_object: ActiveFileObject<'_>,
    opened_file: OpenedObject<'_>,
) -> CleanupPlan {
    let cleanup_was_published = file_object.cleanup_complete();
    match (opened_file.begin_cleanup(), cleanup_was_published) {
        (CleanupStart::First, false) => {}
        (CleanupStart::AlreadyComplete, true) => return CleanupPlan::Complete,
        (CleanupStart::First, true) | (CleanupStart::AlreadyComplete, false) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                .bugcheck();
        }
    }
    cleanup_directory_notification(&opened_file);
    let cleanup = opened_file.release_share_access_for_cleanup();
    let fcb = opened_file.file_control_block_address();
    let node = opened_file.node();
    opened_file.finish_cleanup();
    file_object.mark_cleanup_complete();
    match cleanup {
        FileCleanupDisposition::Retained => CleanupPlan::Complete,
        FileCleanupDisposition::Delete(target) => CleanupPlan::Delete(PendingCleanupDeletion {
            fcb,
            node,
            target,
            additional: DriverVec::new(),
            abort_on_drop: true,
        }),
    }
}

/// Stages every claimed namespace removal atomically after its link handles have cleaned up.
/// # Errors
///
/// Returns an error when the target name no longer identifies the FCB inode, the directory is no
/// longer empty, or the ext4 transaction cannot be committed.
#[expect(
    unsafe_code,
    reason = "the cleanup FILE_OBJECT retains the inode and claimed link targets until staged publication"
)]
pub(crate) fn stage_cleanup_deletion(
    plan: &mut PendingCleanupDeletion,
    operations: &MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<Option<PreparedCleanupPublication>> {
    let mut links = DriverVec::try_with_capacity(
        plan.additional
            .len()
            .checked_add(1)
            .ok_or(DriverError::InsufficientResources)?,
    )?;
    let mut deferred = None;
    for target_pointer in plan.targets() {
        let target = unsafe {
            // SAFETY: The cleanup FILE_OBJECT retains the FCB; Removing state retains every exact
            // target allocation until this batch commits, defers, or aborts before external effects.
            target_pointer.as_ref()
        };
        let parent = mutation.load_directory(target.parent())?;
        match mutation.lookup_child(parent.id(), target.name())? {
            ChildLookup::Found(child) if *child.node() == plan.node => {}
            ChildLookup::Found(_) | ChildLookup::NotFound => return Err(DriverError::CannotDelete),
        }
        let metadata = mutation.staged_node_metadata(plan.node)?;
        if (matches!(plan.node, NodeId::Directory(_))
            || metadata.links_count().on_disk_count() == 1)
            && operations.has_active_inode_handles(plan.fcb)
        {
            if deferred.replace(target_pointer).is_some() {
                return Err(DriverError::InternalInvariantViolation);
            }
            continue;
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
            NodeId::Directory(_) => mutation.remove_empty_directory(parent, target.name())?,
            NodeId::Symlink(_) => mutation.remove_symlink(parent, target.name())?,
        }
        links.try_push(CleanupLinkPublication {
            target: target_pointer,
            notification,
        })?;
    }
    if links.is_empty() {
        for target in plan.targets() {
            operations.defer_file_delete(plan.fcb, target);
        }
        plan.abort_on_drop = false;
        return Ok(None);
    }
    Ok(Some(PreparedCleanupPublication {
        fcb: plan.fcb,
        links,
        deferred,
    }))
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
