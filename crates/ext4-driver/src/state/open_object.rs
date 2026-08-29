//! Opened-handle typestates, raw-volume authority, and file-object decoding.

use super::*;

/// Core-owned live-directory continuation stored directly in the CCB.
pub(crate) type DirectoryCursor = DirectoryScanCursor;

/// Zero-based index of the next EA returned through one FILE_OBJECT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EaCursor {
    /// Next persisted EA index.
    next_entry: usize,
}

impl EaCursor {
    /// Cursor before the first EA.
    pub(crate) const START: Self = Self { next_entry: 0 };

    /// Builds a cursor at an already validated zero-based entry index.
    pub(crate) const fn at(next_entry: usize) -> Self {
        Self { next_entry }
    }

    /// Returns the zero-based entry index selected for the next query.
    pub(crate) const fn next_entry(self) -> usize {
        self.next_entry
    }

    /// Advances by the number of entries actually published to the caller.
    /// # Errors
    ///
    /// Returns an invariant error when cursor arithmetic overflows.
    pub(crate) fn advanced(self, emitted: usize) -> DriverResult<Self> {
        Ok(Self::at(
            self.next_entry
                .checked_add(emitted)
                .ok_or(DriverError::InternalInvariantViolation)?,
        ))
    }
}

/// Stable namespace identity selected for a deferred Windows deletion.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FileDeleteTarget {
    /// Directory containing the link selected by the deleting handle.
    parent: DirectoryNodeId,
    /// Exact ext4 link name that must still resolve to the opened inode.
    name: Ext4Name,
}

impl FileDeleteTarget {
    /// Returns the parent directory containing the selected link.
    pub(crate) const fn parent(&self) -> DirectoryNodeId {
        self.parent
    }

    /// Returns the exact ext4 link name selected for deletion.
    pub(crate) const fn name(&self) -> &Ext4Name {
        &self.name
    }
}

/// Heap-stable delete target owned by one FCB until deletion completes or is cancelled.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PendingFileDeletion {
    /// Stable target storage referenced by an actor-local cleanup plan across suspension.
    target: Box<FileDeleteTarget>,
    /// Whether the pending state may be cancelled by a later disposition request.
    cause: FileDeletionCause,
}

impl PendingFileDeletion {
    /// Copies a normal disposition target into stable FCB-owned storage.
    /// # Errors
    ///
    /// Returns cannot-delete for root and file-reference handles, or an allocation error when the
    /// exact directory-entry name cannot be retained.
    pub(crate) fn try_from_disposition(location: &OpenedLocation) -> DriverResult<Self> {
        Self::try_from_location(location, FileDeletionCause::Disposition)
    }

    /// Copies a mandatory delete-on-close target into stable FCB-owned storage.
    /// # Errors
    ///
    /// Returns cannot-delete for root and file-reference handles, or an allocation error when the
    /// exact directory-entry name cannot be retained.
    pub(crate) fn try_from_delete_on_close(location: &OpenedLocation) -> DriverResult<Self> {
        Self::try_from_location(location, FileDeletionCause::DeleteOnClose)
    }

    /// Copies an exact location and deletion cause into stable storage.
    /// # Errors
    ///
    /// Returns cannot-delete when the location has no deletable directory entry, or an allocation
    /// error when the exact entry name cannot be retained.
    fn try_from_location(
        location: &OpenedLocation,
        cause: FileDeletionCause,
    ) -> DriverResult<Self> {
        let OpenedLocation::DirectoryEntry { parent, name } = location else {
            return Err(DriverError::CannotDelete);
        };
        let name = name.try_to_owned_name()?;
        Ok(Self {
            target: memory::boxed_try_with(|| {
                Ok(FileDeleteTarget {
                    parent: *parent,
                    name,
                })
            })?,
            cause,
        })
    }

    /// Returns the stable target pointer retained by this pending state.
    pub(super) fn target(&self) -> NonNull<FileDeleteTarget> {
        NonNull::from(self.target.as_ref())
    }

    /// Borrows the exact target before this pending state is published into the FCB.
    pub(crate) fn target_ref(&self) -> &FileDeleteTarget {
        self.target.as_ref()
    }

    /// Returns the cancellation semantics fixed when this pending target was created.
    pub(super) const fn cause(&self) -> FileDeletionCause {
        self.cause
    }
}

/// Origin of one shared FCB delete-pending state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileDeletionCause {
    /// Set-information may later cancel this pending state.
    Disposition,
    /// Create-time delete-on-close cannot be cancelled by normal disposition.
    DeleteOnClose,
}

/// Namespace deletion state shared by every FILE_OBJECT for one inode identity.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum FileDeletionState {
    /// The inode may be opened and no link has been selected for deletion.
    Live,
    /// New opens are rejected and the selected link is removed after the final active cleanup.
    Pending(PendingFileDeletion),
    /// The selected link has been removed; only terminal FILE_OBJECT close references remain.
    Deleted,
}

impl FileDeletionState {
    /// Rejects a new open after delete-pending has been published.
    /// # Errors
    ///
    /// Returns delete-pending after the one-way namespace transition begins.
    pub(super) const fn ensure_openable(&self) -> DriverResult<()> {
        match self {
            Self::Live => Ok(()),
            Self::Pending(_) | Self::Deleted => Err(DriverError::DeletePending),
        }
    }

    /// Returns whether Windows queries must expose `DeletePending`.
    pub(super) const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending(_) | Self::Deleted)
    }

    /// Returns the stable target when the final active handle may perform deletion.
    pub(super) fn cleanup_target(&self, active_handles: u32) -> Option<NonNull<FileDeleteTarget>> {
        match self {
            Self::Pending(pending) if active_handles == 0 => Some(pending.target()),
            Self::Live | Self::Pending(_) | Self::Deleted => None,
        }
    }
}

/// Cleanup effect selected atomically with removal of one FILE_OBJECT share claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileCleanupDisposition {
    /// Other active handles remain or no deletion is pending.
    Retained,
    /// This was the final active handle and must remove the selected namespace link.
    Delete(NonNull<FileDeleteTarget>),
}

#[derive(Debug, Eq, PartialEq)]
/// Opened location identity stored with a handle.
pub(crate) enum OpenedLocation {
    /// Mounted volume root.
    Root,
    /// Child entry under a parent directory.
    DirectoryEntry {
        /// Parent directory inode.
        parent: DirectoryNodeId,
        /// Exact ext4 directory entry name.
        name: Ext4Name,
    },
    /// Opened by stable file reference without a directory-entry location.
    FileReference,
}

impl OpenedLocation {
    /// Builds a child directory-entry location by fallibly copying the ext4 child name.
    /// # Errors
    ///
    /// Returns an error when copying the child name cannot allocate.
    pub(crate) fn try_directory_entry(
        parent: DirectoryNodeId,
        name: &Ext4Name,
    ) -> DriverResult<Self> {
        Ok(Self::DirectoryEntry {
            parent,
            name: name.try_to_owned_name()?,
        })
    }

    /// Copies this opened location into a separately owned handle location.
    /// # Errors
    ///
    /// Returns an error when copying a child name cannot allocate.
    pub(crate) fn try_to_owned_location(&self) -> DriverResult<Self> {
        match self {
            Self::Root => Ok(Self::Root),
            Self::DirectoryEntry { parent, name } => Self::try_directory_entry(*parent, name),
            Self::FileReference => Ok(Self::FileReference),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Cleanup lifecycle of one successfully opened FILE_OBJECT.
enum HandleLifecycleState {
    /// The share claim and cleanup-owned resources are active.
    OpenHandle,
    /// Cleanup owns the one-way release transition.
    CleanupDraining,
    /// Cleanup has consumed the share claim and cleanup-owned resources.
    CleanedHandle,
    /// Close owns the terminal context-detachment transition.
    ClosingHandle,
    /// Close has consumed the context pair immediately before its allocation is released.
    ClosedHandle,
}

impl HandleLifecycleState {
    /// Encodes the state in the atomic storage representation.
    const fn as_raw(self) -> u8 {
        match self {
            Self::OpenHandle => 0,
            Self::CleanupDraining => 1,
            Self::CleanedHandle => 2,
            Self::ClosingHandle => 3,
            Self::ClosedHandle => 4,
        }
    }
}

/// Admission-visible projection of one FILE_OBJECT lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleAdmissionState {
    /// Ordinary handle requests remain legal.
    OpenHandle,
    /// CLEANUP closed ordinary admission and waits for terminal release effects.
    CleanupDraining,
    /// CLEANUP completed; only typed post-cleanup requests and CLOSE remain legal.
    CleanedHandle,
    /// CLOSE owns terminal context detachment.
    ClosingHandle,
    /// CLOSE consumed the handle; no further request is legal.
    ClosedHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Result of entering the synchronous cleanup transition.
pub(crate) enum CleanupStart {
    /// This caller owns every cleanup side effect.
    First,
    /// Cleanup was already completed before this request arrived.
    AlreadyComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Ownership release selected before close detaches both FILE_OBJECT contexts.
pub(crate) enum CloseReleasePlan {
    /// Cleanup already removed the share claim; close releases only the FCB reference and CCB.
    CleanedHandle,
    /// A filter cancelled create before cleanup; close atomically removes share and FCB reference.
    CancelledOpen,
}

/// Selects a legal close release from the Windows cleanup state and close reason.
pub(super) const fn select_close_release_plan(
    cleanup_complete: bool,
    close_kind: FileObjectCloseKind,
) -> Option<CloseReleasePlan> {
    match (cleanup_complete, close_kind) {
        (true, _) => Some(CloseReleasePlan::CleanedHandle),
        (false, FileObjectCloseKind::CancelledOpen) => Some(CloseReleasePlan::CancelledOpen),
        _ => None,
    }
}

/// Atomic lifecycle gate shared by synchronous Cleanup/Close and outstanding request completion.
struct HandleLifecycle {
    /// Numeric `HandleLifecycleState` representation used for one-way compare-exchange transitions.
    state: AtomicU8,
}

impl HandleLifecycle {
    /// Creates an active handle lifecycle.
    const fn active() -> Self {
        Self {
            state: AtomicU8::new(HandleLifecycleState::OpenHandle.as_raw()),
        }
    }

    /// Loads the current typed lifecycle state.
    fn state(&self) -> HandleLifecycleState {
        match self.state.load(Ordering::Acquire) {
            value if value == HandleLifecycleState::OpenHandle.as_raw() => {
                HandleLifecycleState::OpenHandle
            }
            value if value == HandleLifecycleState::CleanupDraining.as_raw() => {
                HandleLifecycleState::CleanupDraining
            }
            value if value == HandleLifecycleState::CleanedHandle.as_raw() => {
                HandleLifecycleState::CleanedHandle
            }
            value if value == HandleLifecycleState::ClosingHandle.as_raw() => {
                HandleLifecycleState::ClosingHandle
            }
            value if value == HandleLifecycleState::ClosedHandle.as_raw() => {
                HandleLifecycleState::ClosedHandle
            }
            _ => KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck(),
        }
    }

    /// Closes ordinary request admission at CLEANUP dispatch entry.
    fn begin_cleanup_admission(&self) -> HandleAdmissionState {
        match self.state.compare_exchange(
            HandleLifecycleState::OpenHandle.as_raw(),
            HandleLifecycleState::CleanupDraining.as_raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => HandleAdmissionState::CleanupDraining,
            Err(value) if value == HandleLifecycleState::CleanupDraining.as_raw() => {
                HandleAdmissionState::CleanupDraining
            }
            Err(value) if value == HandleLifecycleState::CleanedHandle.as_raw() => {
                HandleAdmissionState::CleanedHandle
            }
            Err(_) => KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck(),
        }
    }

    /// Returns the lifecycle projection used by ordinary/post-cleanup admission.
    fn admission_state(&self) -> HandleAdmissionState {
        match self.state() {
            HandleLifecycleState::OpenHandle => HandleAdmissionState::OpenHandle,
            HandleLifecycleState::CleanupDraining => HandleAdmissionState::CleanupDraining,
            HandleLifecycleState::CleanedHandle => HandleAdmissionState::CleanedHandle,
            HandleLifecycleState::ClosingHandle => HandleAdmissionState::ClosingHandle,
            HandleLifecycleState::ClosedHandle => HandleAdmissionState::ClosedHandle,
        }
    }

    /// Claims cleanup effects after dispatch has already closed ordinary admission.
    fn begin_cleanup(&self) -> CleanupStart {
        match self.state() {
            HandleLifecycleState::CleanupDraining => CleanupStart::First,
            HandleLifecycleState::CleanedHandle => CleanupStart::AlreadyComplete,
            HandleLifecycleState::OpenHandle
            | HandleLifecycleState::ClosingHandle
            | HandleLifecycleState::ClosedHandle => {
                KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
            }
        }
    }

    /// Publishes completion after every cleanup-owned side effect has finished.
    fn finish_cleanup(&self) {
        if self
            .state
            .compare_exchange(
                HandleLifecycleState::CleanupDraining.as_raw(),
                HandleLifecycleState::CleanedHandle.as_raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
    }

    /// Closes all post-cleanup admission before the CLOSE request enters the active registry.
    fn begin_close_admission(&self, close_kind: FileObjectCloseKind, cleanup_complete: bool) {
        let current = self.state();
        let legal = matches!(
            (current, cleanup_complete, close_kind),
            (HandleLifecycleState::CleanedHandle, true, _)
                | (
                    HandleLifecycleState::OpenHandle,
                    false,
                    FileObjectCloseKind::CancelledOpen
                )
        );
        if !legal {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
        if self
            .state
            .compare_exchange(
                current.as_raw(),
                HandleLifecycleState::ClosingHandle.as_raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
    }

    /// Consumes the close release plan and publishes the final typed lifecycle state.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        if self.state() != HandleLifecycleState::ClosingHandle {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
        let Some(plan) = select_close_release_plan(cleanup_complete, close_kind) else {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        };
        if self
            .state
            .compare_exchange(
                HandleLifecycleState::ClosingHandle.as_raw(),
                HandleLifecycleState::ClosedHandle.as_raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
        plan
    }
}

impl fmt::Debug for HandleLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.state().fmt(formatter)
    }
}

impl PartialEq for HandleLifecycle {
    fn eq(&self, other: &Self) -> bool {
        self.state() == other.state()
    }
}

impl Eq for HandleLifecycle {}

/// Per-handle state stored in `FsContext2` for a direct user volume open.
#[derive(Debug)]
pub(crate) struct OpenedVolumeHandle {
    /// One-way cleanup lifecycle shared with the volume FILE_OBJECT.
    lifecycle: HandleLifecycle,
    /// Raw data operations authorized by the create access check.
    pub(super) raw_access: RawVolumeAccess,
    /// Current per-handle extent bound for raw requests.
    raw_extent: RawExtentPolicy,
    /// One-way raw-write retry authority after an uncertain lower outcome.
    raw_write_outcome: RawWriteOutcome,
}

/// Direct-volume data authority retained from one successful create access check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawVolumeAccess {
    /// The handle has no raw data authority.
    MetadataOnly,
    /// The handle may read raw sectors.
    Read,
    /// The handle may write raw sectors after the lifecycle prerequisites are met.
    Write,
    /// The handle may read and conditionally write raw sectors.
    ReadWrite,
}

impl RawVolumeAccess {
    /// Projects granted Windows volume-data rights into retained raw authority.
    pub(crate) const fn from_granted(access: GrantedAccess) -> Self {
        let read = access.as_raw() & wdk_sys::FILE_READ_DATA != 0;
        let write = access.as_raw() & wdk_sys::FILE_WRITE_DATA != 0;
        match (read, write) {
            (false, false) => Self::MetadataOnly,
            (true, false) => Self::Read,
            (false, true) => Self::Write,
            (true, true) => Self::ReadWrite,
        }
    }

    /// Requires the independently retained data right for one raw operation.
    /// # Errors
    ///
    /// Returns access denied when the create access check did not grant this operation.
    pub(super) const fn require(self, kind: RawVolumeOperationKind) -> DriverResult<()> {
        match (self, kind) {
            (Self::Read | Self::ReadWrite, RawVolumeOperationKind::Read)
            | (Self::Write | Self::ReadWrite, RawVolumeOperationKind::Write) => Ok(()),
            _ => Err(DriverError::AccessDenied),
        }
    }
}

/// Per-handle raw byte extent selected independently from access authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawExtentPolicy {
    /// Bound requests to the mounted filesystem extent.
    FilesystemExtent,
    /// Bound requests to the complete partition exposed by the lower device.
    PartitionExtent,
}

/// Per-handle raw-write outcome retained across requests after terminal dismount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawWriteOutcome {
    /// No ambiguous raw write has consumed this handle's retry authority.
    Retryable,
    /// A lower write or required flush may have changed data.
    Uncertain {
        /// Byte progress reported by the lower write, or the full write before an ambiguous flush.
        completed: usize,
    },
}

/// Data operation selected for a direct-volume handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawVolumeOperationKind {
    /// Read whole sectors from the selected extent.
    Read,
    /// Write whole sectors after terminal logical dismount.
    Write,
}

/// Durability scope validated before a file or volume flush is suspended.
#[derive(Clone, Copy, Debug)]
pub(crate) enum VolumeFlushScope {
    /// The mounted ext4 journal must reach its durability barrier before lower flush.
    Filesystem,
    /// Logical dismount is terminal; only this retained raw owner's lower device is flushed.
    RawDevice(RawVolumeTarget),
}

/// Validated lifecycle and extent authority for one raw transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawVolumeIoPermit {
    /// Maximum exclusive byte offset selected by the handle's extent policy.
    pub(super) bound: DeviceLength,
    /// Physical sector unit required for offset and length.
    pub(super) sector_size: usize,
}

impl RawVolumeIoPermit {
    /// Converts a file-position range into a whole-sector lower-device offset.
    /// # Errors
    ///
    /// Returns invalid-parameter for alignment, overflow, signed-position, or selected extent
    /// violations. Buffer alignment is checked on the captured system mapping before submission.
    pub(crate) fn validate_transfer(
        self,
        start: FileOffset,
        length: usize,
        buffer_address: usize,
    ) -> DriverResult<ByteOffset> {
        let sector = u64::try_from(self.sector_size).map_err(|_| DriverError::InvalidParameter)?;
        let length_u64 = u64::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
        let end = start
            .bytes()
            .checked_add(length_u64)
            .ok_or(DriverError::InvalidParameter)?;
        if sector == 0
            || !start.bytes().is_multiple_of(sector)
            || !length.is_multiple_of(self.sector_size)
            || !buffer_address.is_multiple_of(self.sector_size)
            || end > self.bound.bytes()
            || i64::try_from(end).is_err()
        {
            return Err(DriverError::InvalidParameter);
        }
        Ok(ByteOffset::new(start.bytes()))
    }
}

/// Stable direct-volume handle identity retained by its pending raw IRP.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RawVolumeTarget {
    /// Mounted volume named by the FILE_OBJECT stream header.
    volume: NonNull<VolumeControlBlock>,
    /// Direct-volume FILE_OBJECT that must own lifecycle authority.
    owner: KernelFileObject,
    /// Per-handle access, bounds, and outcome state retained by the pending IRP.
    handle: NonNull<OpenedVolumeHandle>,
}

impl RawVolumeTarget {
    /// Returns the mounted VCB identity.
    pub(crate) const fn volume(self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the direct-volume FILE_OBJECT identity.
    pub(crate) const fn owner(self) -> KernelFileObject {
        self.owner
    }

    /// Reads the handle-local access and extent policy while its IRP retains the CCB.
    #[expect(
        unsafe_code,
        reason = "the pending IRP retains this CCB and actor serialization protects its policy"
    )]
    pub(super) fn authority(self) -> (RawVolumeAccess, RawExtentPolicy) {
        unsafe {
            // SAFETY: Construction requires a decoded live direct-volume FILE_OBJECT.
            self.handle.as_ref()
        }
        .raw_authority()
    }

    /// Rejects raw-write retry after a previous uncertain effect.
    /// # Errors
    ///
    /// Returns the stable raw-outcome status after the capability has been consumed.
    #[expect(
        unsafe_code,
        reason = "the pending IRP retains this CCB and actor serialization protects its outcome"
    )]
    pub(super) fn ensure_write_retryable(self) -> DriverResult<()> {
        match unsafe {
            // SAFETY: Construction requires a decoded live direct-volume FILE_OBJECT.
            self.handle.as_ref()
        }
        .raw_write_outcome()
        {
            RawWriteOutcome::Retryable => Ok(()),
            RawWriteOutcome::Uncertain { .. } => Err(DriverError::RawOutcomeUncertain),
        }
    }

    /// Consumes this handle's raw-write retry authority after an uncertain lower outcome.
    #[expect(
        unsafe_code,
        reason = "the mounted actor exclusively publishes the live CCB outcome transition"
    )]
    pub(crate) fn mark_write_uncertain(mut self, completed: usize) {
        unsafe {
            // SAFETY: The suspended operation retains the CCB and actor serialization is exclusive.
            self.handle.as_mut()
        }
        .mark_raw_write_uncertain(completed);
    }
}

impl OpenedVolumeHandle {
    /// Creates one active direct-volume handle.
    pub(crate) const fn new(raw_access: RawVolumeAccess) -> Self {
        Self {
            lifecycle: HandleLifecycle::active(),
            raw_access,
            raw_extent: RawExtentPolicy::FilesystemExtent,
            raw_write_outcome: RawWriteOutcome::Retryable,
        }
    }

    /// Expands this handle's bounds without changing its read or write authority.
    pub(super) fn allow_partition_extent(&mut self) {
        self.raw_extent = RawExtentPolicy::PartitionExtent;
    }

    /// Returns the independently retained raw access and extent capabilities.
    pub(super) const fn raw_authority(&self) -> (RawVolumeAccess, RawExtentPolicy) {
        (self.raw_access, self.raw_extent)
    }

    /// Returns the one-way raw-write retry outcome.
    pub(super) const fn raw_write_outcome(&self) -> RawWriteOutcome {
        self.raw_write_outcome
    }

    /// Records the first uncertain raw-write outcome and retains its byte progress.
    pub(super) fn mark_raw_write_uncertain(&mut self, completed: usize) {
        if self.raw_write_outcome == RawWriteOutcome::Retryable {
            self.raw_write_outcome = RawWriteOutcome::Uncertain { completed };
        }
    }

    /// Closes ordinary admission before cleanup joins the active handle lane.
    fn begin_cleanup_admission(&self) -> HandleAdmissionState {
        self.lifecycle.begin_cleanup_admission()
    }

    /// Returns the admission-visible handle lifecycle.
    fn admission_state(&self) -> HandleAdmissionState {
        self.lifecycle.admission_state()
    }

    /// Begins this volume handle's idempotent cleanup transition.
    fn begin_cleanup(&self) -> CleanupStart {
        self.lifecycle.begin_cleanup()
    }

    /// Publishes completion after its share claim has been removed.
    fn finish_cleanup(&self) {
        self.lifecycle.finish_cleanup();
    }

    /// Closes post-cleanup admission before close joins the active handle lane.
    fn begin_close_admission(&self, close_kind: FileObjectCloseKind, cleanup_complete: bool) {
        self.lifecycle
            .begin_close_admission(close_kind, cleanup_complete);
    }

    /// Selects the legal terminal close release.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        self.lifecycle
            .close_release_plan(close_kind, cleanup_complete)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle write completion durability requested at create/open.
pub(crate) enum WriteCommitment {
    /// Complete writes after the ext4 journal transaction is committed.
    CommitOnly,
    /// Flush the mounted volume before completing each non-empty write.
    FlushThrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Namespace interpretation selected for one opened handle.
pub(crate) enum OpenedNodeMode {
    /// The handle accesses the underlying ext4 node directly.
    Direct,
    /// The handle accesses a reparse point without resolving its target.
    ReparsePoint,
}

/// Per-handle namespace deletion authority and create-time lifecycle.
///
/// Delete-on-close is a distinct variant because that lifecycle necessarily includes `DELETE`
/// authority; an unauthorized delete-on-close handle is unrepresentable after create decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleDeletion {
    /// No create-time deletion was requested; later disposition uses the retained authorities.
    Retain {
        /// Authority to change ordinary deletion disposition.
        delete_access: DeleteAccess,
        /// Authority to override a read-only attribute during extended disposition.
        file_attributes_write_access: FileAttributesWriteAccess,
    },
    /// The exact opened link must be removed after final active cleanup.
    DeleteOnClose {
        /// Authority to override a read-only attribute during extended disposition.
        file_attributes_write_access: FileAttributesWriteAccess,
    },
}

impl HandleDeletion {
    /// Binds decoded create deletion to the handle's retained delete authority.
    /// # Errors
    ///
    /// Returns access denied when delete-on-close is paired with missing `DELETE` authority.
    pub(crate) fn from_create(
        deletion: CreateDeletion,
        delete_access: DeleteAccess,
        file_attributes_write_access: FileAttributesWriteAccess,
    ) -> DriverResult<Self> {
        match deletion {
            CreateDeletion::Retain => Ok(Self::Retain {
                delete_access,
                file_attributes_write_access,
            }),
            CreateDeletion::DeleteOnClose => {
                delete_access.require()?;
                Ok(Self::DeleteOnClose {
                    file_attributes_write_access,
                })
            }
        }
    }

    /// Requires delete authority retained by this handle lifecycle.
    /// # Errors
    ///
    /// Returns access denied when a retained handle was not opened with `DELETE`.
    fn require_delete_access(self) -> DriverResult<()> {
        match self {
            Self::Retain { delete_access, .. } => delete_access.require(),
            Self::DeleteOnClose { .. } => Ok(()),
        }
    }

    /// Projects the create-time namespace deletion request.
    pub(crate) const fn create_deletion(self) -> CreateDeletion {
        match self {
            Self::Retain { .. } => CreateDeletion::Retain,
            Self::DeleteOnClose { .. } => CreateDeletion::DeleteOnClose,
        }
    }

    /// Returns retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn file_attributes_write_access(self) -> FileAttributesWriteAccess {
        match self {
            Self::Retain {
                file_attributes_write_access,
                ..
            }
            | Self::DeleteOnClose {
                file_attributes_write_access,
            } => file_attributes_write_access,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
/// FsRtl directory-name descriptor lifecycle for one opened handle.
enum DirectoryNotificationName {
    /// No directory notification IRP has required a stable name yet.
    Unregistered,
    /// FsRtl may retain this descriptor until the FILE_OBJECT cleanup transition.
    Registered(Pin<Box<DirectoryNotificationDirectoryName>>),
}

#[derive(Debug)]
/// Common per-handle state shared by every opened node kind.
pub(super) struct OpenedHandleState {
    /// Namespace interpretation selected when this handle was opened.
    node_mode: OpenedNodeMode,
    /// Location used for namespace mutations on cleanup when available.
    location: UnsafeCell<OpenedLocation>,
    /// One-way cleanup lifecycle shared with the synchronous control plane.
    lifecycle: HandleLifecycle,
    /// Delete authority and namespace lifecycle fixed when this handle was opened.
    deletion: HandleDeletion,
    /// Data transfer buffering policy requested for this handle.
    data_transfer_mode: DataTransferMode,
    /// Stable FsRtl directory-name descriptor, retained even if the opened node changes kind.
    directory_notification_name: UnsafeCell<DirectoryNotificationName>,
    /// FILE_OBJECT-local continuation for ordinary EA enumeration.
    ea_cursor: UnsafeCell<EaCursor>,
}

impl OpenedHandleState {
    /// Creates shared per-handle state.
    pub(super) const fn new(
        node_mode: OpenedNodeMode,
        location: OpenedLocation,
        deletion: HandleDeletion,
        data_transfer_mode: DataTransferMode,
    ) -> Self {
        Self {
            node_mode,
            location: UnsafeCell::new(location),
            lifecycle: HandleLifecycle::active(),
            deletion,
            data_transfer_mode,
            directory_notification_name: UnsafeCell::new(DirectoryNotificationName::Unregistered),
            ea_cursor: UnsafeCell::new(EaCursor::START),
        }
    }

    /// Reads the current EA continuation under the per-FILE_OBJECT operation lane.
    #[expect(
        unsafe_code,
        reason = "the device operation lane serializes every EA cursor observation and publication"
    )]
    fn ea_cursor(&self) -> EaCursor {
        unsafe {
            // SAFETY: Ordinary operations on this FILE_OBJECT are serialized by its device lane.
            *self.ea_cursor.get()
        }
    }

    /// Publishes the next EA continuation after output bytes become caller-visible.
    #[expect(
        unsafe_code,
        reason = "the device operation lane serializes every EA cursor observation and publication"
    )]
    fn publish_ea_cursor(&self, cursor: EaCursor) {
        unsafe {
            // SAFETY: Ordinary operations on this FILE_OBJECT are serialized by its device lane.
            *self.ea_cursor.get() = cursor;
        }
    }

    /// Returns the opened location identity.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn location(&self) -> &OpenedLocation {
        unsafe {
            // SAFETY: The device operation lane serializes every location read and replacement.
            // Cleanup accesses only the disjoint atomic lifecycle and never this cell.
            &*self.location.get()
        }
    }

    /// Returns the namespace interpretation selected for this handle.
    const fn node_mode(&self) -> OpenedNodeMode {
        self.node_mode
    }

    /// Requires delete authority retained by this handle.
    /// # Errors
    ///
    /// Returns access denied when this retained handle was not opened with `DELETE`.
    fn require_delete_access(&self) -> DriverResult<()> {
        self.deletion.require_delete_access()
    }

    /// Returns the namespace deletion lifecycle selected at create/open.
    const fn create_deletion(&self) -> CreateDeletion {
        self.deletion.create_deletion()
    }

    /// Returns retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn file_attributes_write_access(&self) -> FileAttributesWriteAccess {
        self.deletion.file_attributes_write_access()
    }

    /// Replaces the opened location after a successful rename.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn replace_location(&self, location: OpenedLocation) {
        unsafe {
            // SAFETY: The device operation lane serializes rename with every other operation that
            // reads or replaces this handle-local location.
            *self.location.get() = location;
        }
    }

    /// Returns data transfer buffering policy requested at create/open.
    const fn data_transfer_mode(&self) -> DataTransferMode {
        self.data_transfer_mode
    }

    /// Closes ordinary admission before cleanup joins the active handle lane.
    fn begin_cleanup_admission(&self) -> HandleAdmissionState {
        self.lifecycle.begin_cleanup_admission()
    }

    /// Returns the admission-visible handle lifecycle.
    fn admission_state(&self) -> HandleAdmissionState {
        self.lifecycle.admission_state()
    }

    /// Begins the idempotent cleanup transition.
    fn begin_cleanup(&self) -> CleanupStart {
        self.lifecycle.begin_cleanup()
    }

    /// Publishes completion after every cleanup-owned release has finished.
    fn finish_cleanup(&self) {
        self.lifecycle.finish_cleanup();
    }

    /// Closes post-cleanup admission before close joins the active handle lane.
    fn begin_close_admission(&self, close_kind: FileObjectCloseKind, cleanup_complete: bool) {
        self.lifecycle
            .begin_close_admission(close_kind, cleanup_complete);
    }

    /// Selects the legal terminal release for close.
    fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        self.lifecycle
            .close_release_plan(close_kind, cleanup_complete)
    }

    /// Allocates the stable directory-name descriptor retained by FsRtl after registration.
    /// # Errors
    ///
    /// Returns an error when allocation of the CCB-owned descriptor fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn ensure_directory_notification_name(
        &self,
        directory: DirectoryNodeId,
    ) -> DriverResult<NonNull<UNICODE_STRING>> {
        let notification_name = unsafe {
            // SAFETY: The device operation lane serializes notification registration. Cleanup
            // passes only the stable CCB address to FsRtl and does not access this cell.
            &mut *self.directory_notification_name.get()
        };
        match notification_name {
            DirectoryNotificationName::Registered(name) => Ok(name.descriptor()),
            DirectoryNotificationName::Unregistered => {
                let name = DirectoryNotificationDirectoryName::try_new(directory)?;
                let descriptor = name.descriptor();
                *notification_name = DirectoryNotificationName::Registered(name);
                Ok(descriptor)
            }
        }
    }
}

#[derive(Debug)]
/// Per-handle state stored in `FILE_OBJECT::FsContext2`.
pub(crate) struct OpenedHandle {
    /// Common handle state independent of node kind.
    pub(super) state: OpenedHandleState,
    /// Kind-specific handle state.
    pub(super) kind: OpenedHandleKind,
}

#[derive(Debug)]
/// Kind-specific per-handle state.
pub(super) enum OpenedHandleKind {
    /// Regular file handle.
    File {
        /// Data-write authority fixed when this handle was created.
        write_access: RegularFileWriteAccess,
    },
    /// Directory handle with enumeration cursor.
    Directory {
        /// Stable, separately allocated directory enumeration cursor.
        cursor: Box<UnsafeCell<DirectoryCursor>>,
    },
    /// Symlink handle.
    Symlink,
}

impl OpenedHandle {
    /// Creates per-handle state for an opened node.
    /// # Errors
    ///
    /// Returns an error when a directory cursor cannot be allocated.
    pub(crate) fn new(
        node: NodeId,
        node_mode: OpenedNodeMode,
        location: OpenedLocation,
        deletion: HandleDeletion,
        data_transfer_mode: DataTransferMode,
        regular_file_write_access: RegularFileWriteAccess,
    ) -> DriverResult<Self> {
        Self::from_parts(
            node,
            node_mode,
            location,
            deletion,
            data_transfer_mode,
            regular_file_write_access,
        )
    }

    /// Creates per-handle state from explicit lifecycle fields.
    /// # Errors
    ///
    /// Returns an error when a directory cursor cannot be allocated.
    fn from_parts(
        node: NodeId,
        node_mode: OpenedNodeMode,
        location: OpenedLocation,
        deletion: HandleDeletion,
        data_transfer_mode: DataTransferMode,
        regular_file_write_access: RegularFileWriteAccess,
    ) -> DriverResult<Self> {
        let state = OpenedHandleState::new(node_mode, location, deletion, data_transfer_mode);
        let kind = match node {
            NodeId::File(_) => OpenedHandleKind::File {
                write_access: regular_file_write_access,
            },
            NodeId::Directory(_) => OpenedHandleKind::Directory {
                cursor: memory::boxed_try_with(|| Ok(UnsafeCell::new(DirectoryCursor::start())))?,
            },
            NodeId::Symlink(_) => OpenedHandleKind::Symlink,
        };
        Ok(Self { state, kind })
    }

    /// Returns data transfer buffering policy requested for this handle.
    const fn data_transfer_mode(&self) -> DataTransferMode {
        self.state.data_transfer_mode()
    }

    /// Returns the opened location identity.
    fn location(&self) -> &OpenedLocation {
        self.state.location()
    }

    /// Returns the namespace interpretation selected for this handle.
    const fn node_mode(&self) -> OpenedNodeMode {
        self.state.node_mode()
    }

    /// Requires delete authority retained by this handle.
    /// # Errors
    ///
    /// Returns access denied when this retained handle was not opened with `DELETE`.
    fn require_delete_access(&self) -> DriverResult<()> {
        self.state.require_delete_access()
    }

    /// Returns the namespace deletion lifecycle selected at create/open.
    const fn create_deletion(&self) -> CreateDeletion {
        self.state.create_deletion()
    }

    /// Returns retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn file_attributes_write_access(&self) -> FileAttributesWriteAccess {
        self.state.file_attributes_write_access()
    }

    /// Closes ordinary admission before cleanup joins the active handle lane.
    pub(super) fn begin_cleanup_admission(&self) -> HandleAdmissionState {
        self.state.begin_cleanup_admission()
    }

    /// Returns the admission-visible handle lifecycle.
    pub(super) fn admission_state(&self) -> HandleAdmissionState {
        self.state.admission_state()
    }

    /// Begins this handle's idempotent cleanup transition.
    pub(super) fn begin_cleanup(&self) -> CleanupStart {
        self.state.begin_cleanup()
    }

    /// Publishes cleanup completion after every release has finished.
    pub(super) fn finish_cleanup(&self) {
        self.state.finish_cleanup();
    }

    /// Closes post-cleanup admission before close joins the active handle lane.
    pub(super) fn begin_close_admission(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) {
        self.state
            .begin_close_admission(close_kind, cleanup_complete);
    }

    /// Selects the legal terminal release for close.
    pub(super) fn close_release_plan(
        &self,
        close_kind: FileObjectCloseKind,
        cleanup_complete: bool,
    ) -> CloseReleasePlan {
        self.state.close_release_plan(close_kind, cleanup_complete)
    }

    /// Replaces the opened location after a successful rename.
    fn replace_location(&self, location: OpenedLocation) {
        self.state.replace_location(location);
    }

    /// Returns the stable CCB-owned descriptor needed by FsRtl directory notifications.
    /// # Errors
    ///
    /// Returns an error when the descriptor allocation fails on its first registration.
    fn ensure_directory_notification_name(
        &self,
        directory: DirectoryNodeId,
    ) -> DriverResult<NonNull<UNICODE_STRING>> {
        self.state.ensure_directory_notification_name(directory)
    }

    /// Returns the kind-specific handle state.
    const fn kind(&self) -> &OpenedHandleKind {
        &self.kind
    }

    /// Returns write authority for a regular-file handle variant.
    pub(super) fn regular_file_write_access(&self) -> Option<RegularFileWriteAccess> {
        match &self.kind {
            OpenedHandleKind::File { write_access } => Some(*write_access),
            OpenedHandleKind::Directory { .. } | OpenedHandleKind::Symlink => None,
        }
    }

    /// Returns the stable interior cursor address for directory handles.
    fn directory_cursor(&self) -> Option<NonNull<DirectoryCursor>> {
        match &self.kind {
            OpenedHandleKind::Directory { cursor } => NonNull::new(cursor.as_ref().get()),
            OpenedHandleKind::File { .. } | OpenedHandleKind::Symlink => None,
        }
    }
}

/// FILE_OBJECT whose native stream header and handle-local CCB were attached by create.
#[derive(Debug)]
pub(crate) struct OpenedObject<'owner> {
    /// Kernel FILE_OBJECT carrying the contexts.
    file_object: ActiveFileObject<'owner>,
    /// Shared file control block decoded from the native header's bound owner identity.
    fcb: NonNull<FileControlBlock>,
    /// Per-handle context stored in FsContext2.
    handle: NonNull<OpenedHandle>,
}

/// Prevalidated, allocation-free update to one stable per-handle namespace location.
#[derive(Debug)]
pub(crate) struct PreparedOpenedLocationPublication {
    /// Stable CCB allocated at create and retained until CLOSE.
    handle: NonNull<OpenedHandle>,
    /// Fully owned location prepared before the first lower write.
    location: OpenedLocation,
}

impl PreparedOpenedLocationPublication {
    /// Moves the prepared location into the live CCB without allocation or validation.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn publish(self) {
        let handle = unsafe {
            // SAFETY: The originating top-level IRP retains the FILE_OBJECT/CCB through commit,
            // and CLOSE is ordered behind that operation by the per-handle lane.
            self.handle.as_ref()
        };
        handle.replace_location(self.location);
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: This token moves only through the reactor and completion envelopes. Its CCB is stable
// from successful CREATE publication until the ordered CLOSE transition.
unsafe impl Send for PreparedOpenedLocationPublication {}

/// Prevalidated FILE_OBJECT position update published after successful data I/O.
#[derive(Debug)]
pub(crate) enum PreparedFilePositionPublication {
    /// Paging or asynchronous I/O does not update the user-visible cursor.
    Unchanged,
    /// Exact signed position ready for one infallible field write.
    Set {
        /// Stable FILE_OBJECT retained by the active operation lane.
        file_object: KernelFileObject,
        /// Checked Windows current-byte-offset value.
        position: i64,
    },
}

impl PreparedFilePositionPublication {
    /// Applies the prevalidated position without allocation or ordinary failure.
    pub(crate) fn publish(self) {
        if let Self::Set {
            file_object,
            position,
        } = self
        {
            file_object.write_current_byte_offset(position);
        }
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The FILE_OBJECT is kept live through the per-handle active-operation lane and the token
// is moved only through reactor-owned operation state.
unsafe impl Send for PreparedFilePositionPublication {}

impl<'owner> OpenedObject<'owner> {
    /// Decodes a node FILE_OBJECT through its advanced-header owner identity and per-handle CCB.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is a volume open or either context is absent.
    #[expect(
        unsafe_code,
        reason = "the active FILE_OBJECT retains the driver-published native header and CCB"
    )]
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let object = file_object.as_ref();
        if object.Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
            return Err(DriverError::ObjectTypeMismatch);
        }
        let header = NonNull::new(object.FsContext.cast::<c_void>());
        let handle = NonNull::new(object.FsContext2.cast::<OpenedHandle>());
        let (header, handle) = match (header, handle) {
            (Some(header), Some(handle)) => (header, handle),
            (None, None) => return Err(DriverError::InvalidParameter),
            (Some(_), None) | (None, Some(_)) => {
                KernelWideInconsistency::file_object_context_corruption().bugcheck();
            }
        };
        let fcb = unsafe {
            // SAFETY: The active FILE_OBJECT retains the native header and its bound inode owner.
            StreamContext::decode_owner(header, StreamOwnerKind::Node)?
        }
        .cast::<FileControlBlock>();
        let sections = unsafe {
            // SAFETY: The same FILE_OBJECT lease retains the header's embedded section storage.
            StreamContext::decode_section_objects(header)?
        };
        if object.SectionObjectPointer != sections.as_ptr() {
            KernelWideInconsistency::file_object_context_corruption().bugcheck();
        }
        let opened = Self {
            file_object,
            fcb,
            handle,
        };
        opened.validate_handle_kind()?;
        Ok(opened)
    }

    /// Returns the kernel FILE_OBJECT associated with this opened handle.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object.address()
    }

    /// Returns the mounted VCB pointer owning this opened node.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.file_control_block().volume()
    }

    /// Returns the ext4 node identity owned by the shared FCB.
    pub(crate) fn node(&self) -> NodeId {
        self.file_control_block().node()
    }

    /// Returns this FILE_OBJECT's next ordinary EA enumeration position.
    pub(crate) fn ea_cursor(&self) -> EaCursor {
        self.handle().state.ea_cursor()
    }

    /// Publishes the next ordinary EA enumeration position.
    pub(crate) fn publish_ea_cursor(&mut self, cursor: EaCursor) {
        self.handle().state.publish_ea_cursor(cursor);
    }

    /// Returns the opened location identity.
    pub(crate) fn location(&self) -> &OpenedLocation {
        self.handle().location()
    }

    /// Returns the namespace interpretation selected for this handle.
    pub(crate) fn node_mode(&self) -> OpenedNodeMode {
        self.handle().node_mode()
    }

    /// Requires delete authority retained by this handle.
    /// # Errors
    ///
    /// Returns access denied when the create/open did not request `DELETE`.
    pub(crate) fn require_delete_access(&self) -> DriverResult<()> {
        self.handle().require_delete_access()
    }

    /// Returns the namespace deletion lifecycle selected when this handle was created.
    pub(crate) fn create_deletion(&self) -> CreateDeletion {
        self.handle().create_deletion()
    }

    /// Returns `FILE_WRITE_ATTRIBUTES` authority retained when this handle was created.
    pub(crate) fn file_attributes_write_access(&self) -> FileAttributesWriteAccess {
        self.handle().file_attributes_write_access()
    }

    /// Copies this handle's exact deletable location into stable FCB-owned storage.
    /// # Errors
    ///
    /// Returns cannot-delete for root or file-reference handles, or an allocation failure.
    pub(crate) fn prepare_pending_deletion(&self) -> DriverResult<PendingFileDeletion> {
        PendingFileDeletion::try_from_disposition(self.location())
    }

    /// Cancels delete-pending for the shared FCB.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn clear_delete_pending(&self) {
        let owner = file_control_block_owner(self.fcb);
        unsafe {
            // SAFETY: This opened FILE_OBJECT keeps the FCB and its ledger owner live.
            owner.as_ref()
        }
        .clear_delete_pending(self.fcb);
    }

    /// Returns whether the shared FCB is delete-pending.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn delete_pending(&self) -> bool {
        let owner = file_control_block_owner(self.fcb);
        unsafe {
            // SAFETY: This opened FILE_OBJECT keeps the FCB and its ledger owner live.
            owner.as_ref()
        }
        .delete_pending(self.fcb)
    }

    /// Returns the stable FCB address retained by this FILE_OBJECT.
    pub(crate) const fn file_control_block_address(&self) -> NonNull<FileControlBlock> {
        self.fcb
    }

    /// Prepares a post-commit handle-location update without retaining an active IRP borrow.
    pub(crate) fn prepare_location_publication(
        &self,
        location: OpenedLocation,
    ) -> PreparedOpenedLocationPublication {
        PreparedOpenedLocationPublication {
            handle: self.handle,
            location,
        }
    }

    /// Returns data transfer buffering policy requested for this opened handle.
    pub(crate) fn data_transfer_mode(&self) -> DataTransferMode {
        self.handle().data_transfer_mode()
    }

    /// Returns the synchronous FILE_OBJECT current position.
    /// # Errors
    ///
    /// Returns an error when the handle is asynchronous or its raw position is negative.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn current_file_position(&self) -> DriverResult<FileOffset> {
        if !self.has_synchronous_file_position() {
            return Err(DriverError::InvalidParameter);
        }
        let file_object = self.file_object.as_ref();
        let position = unsafe {
            // SAFETY: ext4win consistently uses the QuadPart LARGE_INTEGER arm.
            file_object.CurrentByteOffset.QuadPart
        };
        Ok(FileOffset::from_bytes(
            u64::try_from(position).map_err(|_| DriverError::InvalidParameter)?,
        ))
    }

    /// Replaces the synchronous FILE_OBJECT current position.
    /// # Errors
    ///
    /// Returns an error when the handle is asynchronous or the position exceeds signed Windows
    /// range.
    pub(crate) fn set_current_file_position(&mut self, position: FileOffset) -> DriverResult<()> {
        if !self.has_synchronous_file_position() {
            return Err(DriverError::InvalidParameter);
        }
        self.write_current_file_position(position)
    }

    /// Advances the current position after a successful normal handle I/O operation.
    /// # Errors
    ///
    /// Returns an error when the resulting signed Windows position overflows.
    pub(crate) fn update_current_file_position(
        &mut self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<()> {
        if kind == DataIoKind::Paging || !self.has_synchronous_file_position() {
            return Ok(());
        }
        self.write_current_file_position(start.checked_add_len(transferred)?)
    }

    /// Precomputes a post-I/O cursor update while failures are still harmless.
    /// # Errors
    ///
    /// Returns an error when the transferred range or signed Windows position overflows.
    pub(crate) fn prepare_current_file_position_update(
        &self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<PreparedFilePositionPublication> {
        if kind == DataIoKind::Paging || !self.has_synchronous_file_position() {
            return Ok(PreparedFilePositionPublication::Unchanged);
        }
        let position = start.checked_add_len(transferred)?;
        Ok(PreparedFilePositionPublication::Set {
            file_object: self.file_object(),
            position: i64::try_from(position.bytes()).map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Returns whether this FILE_OBJECT owns a synchronized current-position field.
    fn has_synchronous_file_position(&self) -> bool {
        let file_object = self.file_object.as_ref();
        file_object.Flags & wdk_sys::FO_SYNCHRONOUS_IO != 0
    }

    /// Writes a preselected position after signed-range validation.
    /// # Errors
    ///
    /// Returns an error when the position exceeds signed Windows range.
    fn write_current_file_position(&mut self, position: FileOffset) -> DriverResult<()> {
        let position =
            i64::try_from(position.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        self.file_object.write_current_byte_offset(position);
        Ok(())
    }

    /// Enters this handle's synchronous cleanup transition.
    pub(crate) fn begin_cleanup(&self) -> CleanupStart {
        self.handle().begin_cleanup()
    }

    /// Removes this handle's share claim and selects final-active-handle deletion.
    pub(crate) fn release_share_access_for_cleanup(&self) -> FileCleanupDisposition {
        release_file_share_access(self.fcb, self.file_object.address())
    }

    /// Publishes lifecycle completion after every cleanup-owned release has finished.
    pub(crate) fn finish_cleanup(&self) {
        self.handle().finish_cleanup();
    }

    /// Selects the only legal terminal release before close detaches both contexts.
    pub(crate) fn close_release_plan(&self, close_kind: FileObjectCloseKind) -> CloseReleasePlan {
        self.handle()
            .close_release_plan(close_kind, self.file_object.cleanup_complete())
    }

    /// Consumes the unique close authority and clears the header, section, and CCB projections.
    #[expect(
        unsafe_code,
        reason = "the consumed opened capability owns the unique CLOSE context-detachment transition"
    )]
    pub(crate) fn take_node_contexts(self) -> (NonNull<FileControlBlock>, NonNull<OpenedHandle>) {
        let object = unsafe {
            // SAFETY: This consumed opened capability represents the unique CLOSE transition.
            &mut *self.file_object.as_ptr()
        };
        let header = NonNull::new(core::mem::replace(
            &mut object.FsContext,
            core::ptr::null_mut(),
        ));
        let sections = core::mem::replace(&mut object.SectionObjectPointer, core::ptr::null_mut());
        let handle = NonNull::new(
            core::mem::replace(&mut object.FsContext2, core::ptr::null_mut())
                .cast::<OpenedHandle>(),
        );
        let fcb = unsafe {
            // SAFETY: Decode validated the ledger-owned FCB for this consumed FILE_OBJECT.
            self.fcb.as_ref()
        };
        match (header, handle) {
            (Some(header), Some(handle))
                if header == fcb.stream_header()
                    && sections
                        == fcb
                            .stream_section_objects()
                            .unwrap_or_else(|_| {
                                KernelWideInconsistency::file_object_context_corruption().bugcheck()
                            })
                            .as_ptr()
                    && handle == self.handle =>
            {
                (self.fcb, handle)
            }
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
    }

    /// Returns the decoded file control block.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn file_control_block(&self) -> &FileControlBlock {
        unsafe {
            // SAFETY: `decode` validates the native header and its bound inode owner.
            // The active FILE_OBJECT retains both allocations throughout this borrow.
            self.fcb.as_ref()
        }
    }

    /// Returns the unique CCB address used as the FsRtl notification owner context.
    pub(crate) const fn notification_context(&self) -> NonNull<c_void> {
        self.handle.cast()
    }

    /// Returns the stable CCB-owned directory name retained by FsRtl after registration.
    /// # Errors
    ///
    /// Returns an error when the descriptor allocation fails on its first registration.
    fn ensure_directory_notification_name(
        &self,
        directory: DirectoryNodeId,
    ) -> DriverResult<NonNull<UNICODE_STRING>> {
        self.handle().ensure_directory_notification_name(directory)
    }

    /// Returns the decoded per-handle state.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn handle(&self) -> &OpenedHandle {
        unsafe {
            // SAFETY: `decode` only constructs this type from a non-null
            // FsContext2 written by successful create and used during the
            // active FILE_OBJECT lifetime.
            self.handle.as_ref()
        }
    }

    /// Rejects corrupted FILE_OBJECT contexts whose FCB and handle kind disagree.
    ///
    /// # Errors
    /// Returns an error when FCB node identity and handle variant encode
    /// different node kinds.
    fn validate_handle_kind(&self) -> DriverResult<()> {
        match (self.node(), self.handle().kind()) {
            (NodeId::File(_), OpenedHandleKind::File { .. })
            | (NodeId::Directory(_), OpenedHandleKind::Directory { .. })
            | (NodeId::Symlink(_), OpenedHandleKind::Symlink) => Ok(()),
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
    }
}

/// Successfully opened FILE_OBJECT kind selected without reinterpreting context pointers.
#[derive(Debug)]
pub(crate) enum OpenedFileObject<'owner> {
    /// Namespace node backed by an FCB and `OpenedHandle`.
    Node(OpenedObject<'owner>),
    /// Direct mounted-volume handle backed by a VCB and `OpenedVolumeHandle`.
    Volume(OpenedVolume<'owner>),
}

impl<'owner> OpenedFileObject<'owner> {
    /// Decodes the filesystem-owned context pair according to the FSD-owned volume-open flag.
    /// # Errors
    ///
    /// Returns an error when the selected context pair is absent or inconsistent.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        if file_object.as_ref().Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
            OpenedVolume::decode(file_object).map(Self::Volume)
        } else {
            OpenedObject::decode(file_object).map(Self::Node)
        }
    }

    /// Seals the short-lived handle lifecycle capability used around fallible operation allocation.
    pub(crate) fn prepare_admission(self) -> PreparedHandleAdmission {
        match self {
            Self::Node(opened) => PreparedHandleAdmission {
                file_object: opened.file_object(),
                target: PreparedHandleAdmissionTarget::Node(opened.handle),
                cleanup_complete: opened.file_object.cleanup_complete(),
                close_kind: opened.file_object.close_kind_or_bugcheck(),
            },
            Self::Volume(opened) => PreparedHandleAdmission {
                file_object: opened.file_object(),
                target: PreparedHandleAdmissionTarget::Volume(opened.handle),
                cleanup_complete: opened.file_object.cleanup_complete(),
                close_kind: opened.file_object.close_kind_or_bugcheck(),
            },
        }
    }
}

/// Address-stable handle context selected while its top-level IRP still retains FILE_OBJECT life.
#[derive(Debug)]
enum PreparedHandleAdmissionTarget {
    /// Namespace-node CCB.
    Node(NonNull<OpenedHandle>),
    /// Direct-volume CCB.
    Volume(NonNull<OpenedVolumeHandle>),
}

/// Short-lived capability that publishes a lifecycle transition only after operation allocation.
///
/// This value must not enter an operation or completion envelope. Its caller retains the unique
/// top-level IRP until a successfully allocated operation has taken that ownership.
#[derive(Debug)]
pub(crate) struct PreparedHandleAdmission {
    /// Stable FILE_OBJECT identity used by the per-handle reactor lane.
    file_object: KernelFileObject,
    /// Exact CCB type selected from the FILE_OBJECT flag and context pair.
    target: PreparedHandleAdmissionTarget,
    /// Windows cleanup publication observed while the active IRP retained the FILE_OBJECT.
    cleanup_complete: bool,
    /// Windows close reason observed at the same boundary.
    close_kind: FileObjectCloseKind,
}

impl PreparedHandleAdmission {
    /// Returns the stable FILE_OBJECT identity without exposing the CCB pointer.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the current admission-visible lifecycle.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn state(&self) -> HandleAdmissionState {
        match self.target {
            PreparedHandleAdmissionTarget::Node(handle) => unsafe {
                // SAFETY: The caller still owns the IRP retaining this exact FILE_OBJECT context.
                handle.as_ref()
            }
            .admission_state(),
            PreparedHandleAdmissionTarget::Volume(handle) => unsafe {
                // SAFETY: The caller still owns the IRP retaining this exact FILE_OBJECT context.
                handle.as_ref()
            }
            .admission_state(),
        }
    }

    /// Closes ordinary admission after the cleanup operation allocation succeeded.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn begin_cleanup(self) {
        let state = match self.target {
            PreparedHandleAdmissionTarget::Node(handle) => unsafe {
                // SAFETY: The allocated cleanup operation now retains the FILE_OBJECT and CCB.
                handle.as_ref()
            }
            .begin_cleanup_admission(),
            PreparedHandleAdmissionTarget::Volume(handle) => unsafe {
                // SAFETY: The allocated cleanup operation now retains the FILE_OBJECT and CCB.
                handle.as_ref()
            }
            .begin_cleanup_admission(),
        };
        if state != HandleAdmissionState::CleanupDraining {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck();
        }
    }

    /// Closes every remaining admission after the close operation allocation succeeded.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn begin_close(self) {
        match self.target {
            PreparedHandleAdmissionTarget::Node(handle) => unsafe {
                // SAFETY: The allocated close operation now retains the FILE_OBJECT and CCB.
                handle.as_ref()
            }
            .begin_close_admission(self.close_kind, self.cleanup_complete),
            PreparedHandleAdmissionTarget::Volume(handle) => unsafe {
                // SAFETY: The allocated close operation now retains the FILE_OBJECT and CCB.
                handle.as_ref()
            }
            .begin_close_admission(self.close_kind, self.cleanup_complete),
        }
    }
}

/// Direct user volume open decoded from its typed FILE_OBJECT context pair.
#[derive(Debug)]
pub(crate) struct OpenedVolume<'owner> {
    /// Live direct-volume FILE_OBJECT.
    file_object: ActiveFileObject<'owner>,
    /// Mounted VCB decoded from the advanced header's bound owner identity.
    volume: NonNull<VolumeControlBlock>,
    /// Per-handle lifecycle stored in `FsContext2`.
    handle: NonNull<OpenedVolumeHandle>,
}

impl<'owner> OpenedVolume<'owner> {
    /// Decodes a direct-volume FILE_OBJECT through its advanced-header owner identity.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is not marked as a volume open or lacks contexts.
    #[expect(
        unsafe_code,
        reason = "the active volume FILE_OBJECT retains its driver-published native header and owner"
    )]
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let object = file_object.as_ref();
        if object.Flags & wdk_sys::FO_VOLUME_OPEN == 0 {
            return Err(DriverError::ObjectTypeMismatch);
        }
        let header = NonNull::new(object.FsContext.cast::<c_void>());
        let handle = NonNull::new(object.FsContext2.cast::<OpenedVolumeHandle>());
        let (header, handle) = match (header, handle) {
            (Some(header), Some(handle)) => (header, handle),
            (None, None) => return Err(DriverError::InvalidParameter),
            (Some(_), None) | (None, Some(_)) => {
                KernelWideInconsistency::file_object_context_corruption().bugcheck();
            }
        };
        let volume = unsafe {
            // SAFETY: The active volume FILE_OBJECT retains the native header and its VCB owner.
            StreamContext::decode_owner(header, StreamOwnerKind::Volume)?
        }
        .cast::<VolumeControlBlock>();
        let sections = unsafe {
            // SAFETY: The same FILE_OBJECT lease retains the header's embedded section storage.
            StreamContext::decode_section_objects(header)?
        };
        if object.SectionObjectPointer != sections.as_ptr() {
            KernelWideInconsistency::file_object_context_corruption().bugcheck();
        }
        Ok(Self {
            file_object,
            volume,
            handle,
        })
    }

    /// Returns the mounted VCB identified by this volume handle.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the kernel FILE_OBJECT identity whose share claim is recorded.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object.address()
    }

    /// Expands this handle's raw bound to the lower partition without granting data access.
    #[expect(
        unsafe_code,
        reason = "the mounted actor exclusively mutates the live CCB retained by this FILE_OBJECT"
    )]
    pub(crate) fn allow_partition_extent(&mut self) {
        unsafe {
            // SAFETY: Actor serialization excludes another operation mutating this live CCB.
            self.handle.as_mut()
        }
        .allow_partition_extent();
    }

    /// Captures the stable identities retained by this pending raw data IRP.
    pub(crate) const fn raw_target(&self) -> RawVolumeTarget {
        RawVolumeTarget {
            volume: self.volume,
            owner: self.file_object.address(),
            handle: self.handle,
        }
    }

    /// Reads the synchronous FILE_OBJECT byte position for raw current-position requests.
    /// # Errors
    ///
    /// Returns invalid-parameter if external state supplied a negative position.
    #[expect(
        unsafe_code,
        reason = "the active FILE_OBJECT retains its initialized LARGE_INTEGER position arm"
    )]
    pub(crate) fn current_file_position(&self) -> DriverResult<FileOffset> {
        if self.file_object.as_ref().Flags & wdk_sys::FO_SYNCHRONOUS_IO == 0 {
            return Err(DriverError::InvalidParameter);
        }
        let position = unsafe {
            // SAFETY: Windows initializes CurrentByteOffset and the driver uses its QuadPart arm.
            self.file_object.as_ref().CurrentByteOffset.QuadPart
        };
        let bytes = u64::try_from(position).map_err(|_| DriverError::InvalidParameter)?;
        Ok(FileOffset::from_bytes(bytes))
    }

    /// Prevalidates the synchronous raw handle position before lower I/O can change storage.
    /// # Errors
    ///
    /// Returns invalid-parameter if the resulting position exceeds Windows' signed offset domain.
    pub(crate) fn prepare_current_file_position_update(
        &self,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<PreparedFilePositionPublication> {
        if self.file_object.as_ref().Flags & wdk_sys::FO_SYNCHRONOUS_IO == 0 {
            return Ok(PreparedFilePositionPublication::Unchanged);
        }
        let position = start.checked_add_len(transferred)?;
        let signed = i64::try_from(position.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        Ok(PreparedFilePositionPublication::Set {
            file_object: self.file_object(),
            position: signed,
        })
    }

    /// Begins this handle's idempotent cleanup transition.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn begin_cleanup(&self) -> CleanupStart {
        unsafe {
            // SAFETY: Decode validated the live `OpenedVolumeHandle` context pointer.
            self.handle.as_ref()
        }
        .begin_cleanup()
    }

    /// Publishes completion after its share claim has been removed.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn finish_cleanup(&self) {
        unsafe {
            // SAFETY: Decode validated the live `OpenedVolumeHandle` context pointer.
            self.handle.as_ref()
        }
        .finish_cleanup();
    }

    /// Selects the only legal terminal close release.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn close_release_plan(&self, close_kind: FileObjectCloseKind) -> CloseReleasePlan {
        unsafe {
            // SAFETY: Decode validated the live `OpenedVolumeHandle` context pointer.
            self.handle.as_ref()
        }
        .close_release_plan(close_kind, self.file_object.cleanup_complete())
    }

    /// Consumes the unique close authority and clears the volume stream and CCB projections.
    #[expect(
        unsafe_code,
        reason = "the consumed volume capability owns the unique CLOSE context-detachment transition"
    )]
    pub(crate) fn take_volume_contexts(
        self,
    ) -> (NonNull<VolumeControlBlock>, NonNull<OpenedVolumeHandle>) {
        let object = unsafe {
            // SAFETY: This consumed opened capability represents the unique CLOSE transition.
            &mut *self.file_object.as_ptr()
        };
        let header = NonNull::new(core::mem::replace(
            &mut object.FsContext,
            core::ptr::null_mut(),
        ));
        let sections = core::mem::replace(&mut object.SectionObjectPointer, core::ptr::null_mut());
        let handle = NonNull::new(
            core::mem::replace(&mut object.FsContext2, core::ptr::null_mut())
                .cast::<OpenedVolumeHandle>(),
        );
        let volume = unsafe {
            // SAFETY: Decode validated the mounted VCB for this consumed FILE_OBJECT.
            self.volume.as_ref()
        };
        match (header, handle) {
            (Some(header), Some(handle))
                if header == volume.stream_header()
                    && sections
                        == volume
                            .stream_section_objects()
                            .unwrap_or_else(|_| {
                                KernelWideInconsistency::file_object_context_corruption().bugcheck()
                            })
                            .as_ptr()
                    && handle == self.handle =>
            {
                (self.volume, handle)
            }
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
    }
}

#[derive(Debug)]
/// Opened regular file decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedRegularFile<'owner> {
    /// Opened object context validated as a regular file.
    opened: OpenedObject<'owner>,
    /// Typed file node identity.
    id: FileNodeId,
}

impl<'owner> OpenedRegularFile<'owner> {
    /// Decodes an opened FILE_OBJECT and requires a regular-file node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a regular file.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let opened = OpenedObject::decode(file_object)?;
        let NodeId::File(id) = opened.node() else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        if opened.node_mode() == OpenedNodeMode::ReparsePoint {
            return Err(DriverError::NotSupported);
        }
        Ok(Self { opened, id })
    }

    /// Returns the typed regular-file identity.
    pub(crate) const fn id(&self) -> FileNodeId {
        self.id
    }

    /// Returns the shared FCB that owns this regular file's byte-range locks.
    pub(crate) fn file_control_block(&self) -> &FileControlBlock {
        self.opened.file_control_block()
    }

    /// Returns the typed kernel FILE_OBJECT for FsRtl ownership checks.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.opened.file_object()
    }

    /// Returns regular-file write authority fixed at create time.
    pub(crate) fn write_access(&self) -> RegularFileWriteAccess {
        self.opened
            .handle()
            .regular_file_write_access()
            .unwrap_or_else(|| KernelWideInconsistency::file_object_context_corruption().bugcheck())
    }

    /// Returns the synchronous per-handle file position.
    /// # Errors
    ///
    /// Returns an error when the handle is asynchronous or its position is invalid.
    pub(crate) fn current_file_position(&self) -> DriverResult<FileOffset> {
        self.opened.current_file_position()
    }

    /// Advances the current position after successful normal file I/O.
    /// # Errors
    ///
    /// Returns an error when the resulting signed Windows position overflows.
    pub(crate) fn update_current_file_position(
        &mut self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<()> {
        self.opened
            .update_current_file_position(kind, start, transferred)
    }

    /// Precomputes an infallible post-I/O position publication.
    /// # Errors
    ///
    /// Returns an error when the transferred range or signed Windows position overflows.
    pub(crate) fn prepare_current_file_position_update(
        &self,
        kind: DataIoKind,
        start: FileOffset,
        transferred: usize,
    ) -> DriverResult<PreparedFilePositionPublication> {
        self.opened
            .prepare_current_file_position_update(kind, start, transferred)
    }

    /// Returns data transfer buffering policy requested for this regular-file handle.
    pub(crate) fn data_transfer_mode(&self) -> DataTransferMode {
        self.opened.data_transfer_mode()
    }
}

#[derive(Debug)]
/// Opened directory decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedDirectory<'owner> {
    /// Opened object context validated as a directory.
    opened: OpenedObject<'owner>,
    /// Typed directory node identity.
    id: DirectoryNodeId,
    /// Directory cursor stored in the directory handle variant.
    cursor: NonNull<DirectoryCursor>,
}

impl<'owner> OpenedDirectory<'owner> {
    /// Decodes an opened FILE_OBJECT and requires a directory node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a directory.
    pub(crate) fn decode(file_object: ActiveFileObject<'owner>) -> DriverResult<Self> {
        let opened = OpenedObject::decode(file_object)?;
        let NodeId::Directory(id) = opened.node() else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        if opened.node_mode() == OpenedNodeMode::ReparsePoint {
            return Err(DriverError::NotSupported);
        }
        let Some(cursor) = opened.handle().directory_cursor() else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { opened, id, cursor })
    }

    /// Returns the typed directory identity.
    pub(crate) const fn id(&self) -> DirectoryNodeId {
        self.id
    }

    /// Returns the stable CCB-owned name descriptor retained by FsRtl notification records.
    /// # Errors
    ///
    /// Returns an error when the descriptor allocation fails on its first registration.
    pub(crate) fn notification_directory_name(&mut self) -> DriverResult<NonNull<UNICODE_STRING>> {
        self.opened.ensure_directory_notification_name(self.id)
    }

    /// Returns the mounted VCB pointer owning this opened directory.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.opened.volume()
    }

    /// Returns the unique CCB address used as the FsRtl notification owner context.
    pub(crate) const fn notification_context(&self) -> NonNull<c_void> {
        self.opened.notification_context()
    }

    /// Returns the mutable directory enumeration cursor.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn cursor_mut(&mut self) -> &mut DirectoryCursor {
        unsafe {
            // SAFETY: `cursor` points into the live directory handle variant
            // validated during decode. This type exposes no variant-changing
            // operation.
            self.cursor.as_mut()
        }
    }
}

/// Releases one FILE_OBJECT reference to a VCB-owned FCB.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) fn release_file_control_block(fcb: NonNull<FileControlBlock>) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The live FCB reference is owned by this ledger until `close` returns.
        owner.as_ref()
    };
    owner.close(fcb);
}

/// Releases one FILE_OBJECT's share claim while retaining its FCB reference until close.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) fn release_file_share_access(
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
) -> FileCleanupDisposition {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The retained FCB reference keeps its owner ledger live for cleanup.
        owner.as_ref()
    };
    owner.release_share_access(fcb, file_object)
}

/// Aborts one exact final-cleanup deletion before any lower effect became uncertain.
#[expect(
    unsafe_code,
    reason = "the cleanup plan retains the FCB and its owning ledger until this transition returns"
)]
pub(crate) fn abort_cleanup_file_delete(
    fcb: NonNull<FileControlBlock>,
    target: NonNull<FileDeleteTarget>,
) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The cleanup plan retains this FCB and therefore its immutable ledger owner.
        owner.as_ref()
    };
    owner.abort_cleanup_delete(fcb, target);
}

/// Rolls back a pre-attachment FCB reference and its recorded share claim.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) fn abandon_file_control_block(
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The unpublished FCB remains owned by this ledger until rollback returns.
        owner.as_ref()
    };
    owner.release_share_access_and_reference(fcb, file_object);
}

/// Atomically releases a cancelled open's active share claim and final FCB reference.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) fn release_cancelled_file_control_block(
    fcb: NonNull<FileControlBlock>,
    file_object: KernelFileObject,
) {
    let owner = file_control_block_owner(fcb);
    let owner = unsafe {
        // SAFETY: The cancelled FILE_OBJECT retains its FCB and owner until close consumes both.
        owner.as_ref()
    };
    owner.release_share_access_and_reference(fcb, file_object);
}

/// Returns the ledger pointer stored immutably in one live FCB.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn file_control_block_owner(fcb: NonNull<FileControlBlock>) -> NonNull<FileControlBlockLedger> {
    unsafe {
        // SAFETY: All callers hold one live FILE_OBJECT or pre-attachment reference to this FCB.
        fcb.as_ref().owner()
    }
}

/// Final unload notification after every control and mounted device has retired.
///
/// A base filesystem's device deletion is a prerequisite for this callback, not work that can
/// be deferred to it. Control retirement belongs to prepare-unload; mounted-device retirement
/// belongs to dismount/last-close. No driver-global resources survive those owners.
///
/// # Safety
/// The I/O Manager must invoke this as the registered unload routine for its live driver object.
#[expect(
    unsafe_code,
    reason = "validates the I/O Manager's final device-free unload boundary"
)]
pub(crate) unsafe extern "C" fn driver_unload(driver: PDRIVER_OBJECT) {
    let driver = unsafe {
        // SAFETY: The I/O Manager retains its driver object during this callback.
        driver.as_ref()
    }
    .unwrap_or_else(|| KernelWideInconsistency::driver_device_teardown_corruption().bugcheck());
    if !driver.DeviceObject.is_null() {
        KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
    }
}

/// Decodes the immutable device kind independently of the actor's lifetime.
/// # Errors
///
/// Returns an invariant error when driver-owned extension storage is absent or has an unknown tag.
#[expect(
    unsafe_code,
    reason = "the active dispatch or lifecycle callback retains this device"
)]
pub(crate) fn driver_device_kind(device: KernelDevice) -> DriverResult<DriverDeviceKind> {
    let header = unsafe {
        // SAFETY: The caller's live KernelDevice retains this driver's extension during decoding.
        DeviceExtensionHeader::from_device(device)?
    };
    DriverDeviceKind::decode(header.kind)
}

/// Admits an actor request only while the containing device owns a live reactor.
///
/// The header remains readable for a delete-pending device after actor destruction; its closed
/// gate rejects late requests without ever reconstructing a reference to the destroyed actor.
#[expect(
    unsafe_code,
    reason = "the received IRP retains its target extension during admission"
)]
pub(crate) fn queue_device_request(
    received: ReceivedIrp,
    major: DispatchMajor,
) -> wdk_sys::NTSTATUS {
    let header = match unsafe {
        // SAFETY: The received IRP and active dispatch retain this driver-owned device.
        DeviceExtensionHeader::from_device(received.device())
    } {
        Ok(header) => header,
        Err(error) => return received.complete_result(Err(error)),
    };
    match header.with_reactor(received, |received, reactor| {
        reactor.receive(received, major)
    }) {
        Ok(status) => status,
        Err(received) => received.complete_result(Err(DriverError::InvalidDeviceRequest)),
    }
}
