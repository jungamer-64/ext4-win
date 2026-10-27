//! Native Windows stream-header ownership boundary.

#[cfg(not(test))]
use super::section::SectionResource;
use super::section::{
    PurgeFailurePolicy, ScanSectionChange, SealedSectionMutation, SectionMutationOperation,
    SectionSynchronization,
};
use super::storage_admission::{ClosePhase, MediaState, StorageAdmission};
#[cfg(not(test))]
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use crate::metadata::WindowsNodeMetadata;
#[cfg(test)]
use core::cell::UnsafeCell;
#[cfg(test)]
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use ext4_core::{ClusterSize, EpochSequence, FileAllocationSize, FileSize, NodeId};
#[cfg(test)]
use std::sync::Mutex;

use wdk_sys::NTSTATUS;
#[cfg(not(test))]
use wdk_sys::{STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::operational_trace::{OperationalOutcome, OperationalPath, OperationalTrace};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::NativeAllocation;

/// A native paging completion lost its registered map or consumed its in-flight lease twice.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this exported terminal boundary routes native ownership corruption to the sole driver fatal policy"
)]
#[unsafe(no_mangle)]
extern "system" fn ext4win_paging_ownership_corruption() -> ! {
    KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck()
}

/// Physical prefix acknowledged before unique native paging setup admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "native reservation constructs these acknowledged-map claims in the production FCB boundary"
    )
)]
pub(crate) enum PagingFileClaim {
    /// No direct paging address has been published.
    Initial,
    /// Existing direct I/O continues over this acknowledged physical prefix.
    Extension {
        physical: ext4_core::ByteOffset,
        length: FileSize,
    },
}

/// Unique native setup reservation; its enclosing deferred FCB lease retains `header`.
#[derive(Debug)]
pub(crate) struct PagingFileReservation {
    /// Address-stable native FCB retained independently by the constructing owner.
    header: NonNull<c_void>,
    /// Initial admission or immutable-prefix extension.
    claim: PagingFileClaim,
    /// Consumption prevents rollback after map publication.
    phase: PagingReservationPhase,
}

/// Local ownership transition, distinct from the native map's shared admission phase.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "only the production native activation can publish an acknowledged paging map"
    )
)]
enum PagingReservationPhase {
    Reserved,
    Activated,
}

impl PagingFileReservation {
    /// Returns the acknowledged prefix while this setup retains exclusive extension authority.
    pub(crate) const fn claim(&self) -> PagingFileClaim {
        self.claim
    }

    /// Activates only an initialized, home-checkpointed projection over the same physical prefix.
    /// # Errors
    /// Returns invalid representation/alignment or revoked native setup before map publication.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the enclosing FCB lease retains the native setup token through activation"
        )
    )]
    pub(crate) fn activate(
        mut self,
        storage: ext4_core::ContiguousFileStorage,
        route: crate::kernel::storage::MountedStorageRoute,
    ) -> DriverResult<()> {
        let physical =
            i64::try_from(storage.physical().get()).map_err(|_| DriverError::InvalidParameter)?;
        let length =
            i64::try_from(storage.length().bytes()).map_err(|_| DriverError::InvalidParameter)?;
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The unique reservation and deferred FCB lease retain this native header.
                ext4win_stream_activate_paging_file(
                    self.header.as_ptr(),
                    u8::from(matches!(self.claim, PagingFileClaim::Extension { .. })),
                    route.filesystem_control_device().as_ptr(),
                    physical,
                    length,
                    route.filesystem_sector_size().as_u32(),
                )
            };
            cache_status(status)?;
            self.phase = PagingReservationPhase::Activated;
            Ok(())
        }
        #[cfg(test)]
        {
            let _inputs = (&mut self, physical, length, route);
            Err(DriverError::NotSupported)
        }
    }
}

impl Drop for PagingFileReservation {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the enclosing deferred FCB lease remains alive until this reservation has released native admission"
        )
    )]
    fn drop(&mut self) {
        if self.phase == PagingReservationPhase::Reserved {
            #[cfg(not(test))]
            unsafe {
                // SAFETY: Native setup authority is still unique and the FCB remains retained.
                ext4win_stream_abort_paging_file(
                    self.header.as_ptr(),
                    u8::from(matches!(self.claim, PagingFileClaim::Extension { .. })),
                );
            }
            #[cfg(test)]
            {
                let _identity = self.header;
            }
        }
    }
}

/// Native stream owner domain encoded beside the advanced FCB header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum StreamOwnerKind {
    /// One inode-wide file stream owned by the VCB FCB ledger.
    Node = 1,
    /// The mounted raw-volume stream owned by the VCB itself.
    Volume = 2,
}

#[cfg(not(test))]
impl StreamOwnerKind {
    /// Exact tag passed across the native ABI; the enum has a fixed `u32` representation.
    #[expect(
        clippy::as_conversions,
        reason = "the repr(u32) enum defines the native owner tag domain"
    )]
    const fn native_tag(self) -> u32 {
        self as u32
    }
}

/// Coherent native stream-size snapshot.
///
/// The advanced header's allocation is the section bound, not ext4's physical allocation charge.
/// The charge is kept beside the header under the same mutex and publication boundary so sparse
/// queries do not report holes as allocated storage. VDL always equals EOF: ext4 defines every
/// byte below EOF, including holes and unwritten extents, without exposing stale storage bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamSizes {
    /// Cluster-rounded bound supplied to Cache Manager and Memory Manager.
    allocation_size: i64,
    /// Exact logical EOF.
    file_size: i64,
    /// Native ABI field constrained to equal `file_size`.
    valid_data_length: i64,
    /// Physical allocation charge for Windows standard/network information.
    allocation_charge: i64,
}

impl StreamSizes {
    /// Empty stream before any payload or storage has been allocated.
    pub(crate) const EMPTY: Self = Self {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
        allocation_charge: 0,
    };

    /// Establishes the Windows stream-size tuple from one validated ext4 inode snapshot.
    ///
    /// `AllocationSize` is the cluster-rounded EOF bound. Physical charge includes reservations
    /// and metadata outside the visible stream, so it cannot drive section-size changes during
    /// paging writeback. File-information queries use the independent charge field.
    /// # Errors
    ///
    /// Returns an arithmetic error when a size cannot be rounded or represented by Windows.
    pub(crate) fn try_from_ext4(
        file_size: FileSize,
        allocation_charge: FileAllocationSize,
        cluster_size: ClusterSize,
    ) -> DriverResult<Self> {
        let allocation_size = round_up_allocation(file_size.bytes(), cluster_size)?;
        let file_size =
            i64::try_from(file_size.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self {
            allocation_size: i64::try_from(allocation_size)
                .map_err(|_| DriverError::InvalidParameter)?,
            file_size,
            valid_data_length: file_size,
            allocation_charge: i64::try_from(allocation_charge.bytes())
                .map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Returns EOF in the signed Windows wire representation.
    pub(crate) const fn file_size(self) -> i64 {
        self.file_size
    }

    /// Returns the inode allocation charge in the signed Windows wire representation.
    pub(crate) const fn allocation_charge(self) -> i64 {
        self.allocation_charge
    }

    /// Returns whether two projections expose the same Cache Manager and Memory Manager bounds.
    ///
    /// The physical allocation charge is intentionally excluded: paging writeback may change that
    /// query projection without changing any native section size.
    pub(crate) const fn same_cache_dimensions(self, other: Self) -> bool {
        self.allocation_size == other.allocation_size
            && self.file_size == other.file_size
            && self.valid_data_length == other.valid_data_length
    }
}

/// Fixed native input used to publish the Fast I/O query projection with stream sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(super) struct StreamMetadata {
    /// Monotonic committed epoch that owns every remaining field.
    pub(super) epoch: u64,
    /// Windows creation timestamp.
    pub(super) creation: i64,
    /// Windows access timestamp.
    pub(super) accessed: i64,
    /// Windows write timestamp.
    pub(super) modified: i64,
    /// Windows metadata-change timestamp.
    pub(super) changed: i64,
    /// Complete Windows file-attribute projection.
    pub(super) attributes: u32,
    /// Windows-visible namespace link count.
    pub(super) links: u32,
    /// Fixed native directory discriminator.
    pub(super) directory: u32,
    /// Inode payload eligibility, independent from security and volume reliability.
    pub(super) writable_data: u32,
}

impl StreamMetadata {
    /// Builds one native projection from a coherent core snapshot and its committed epoch.
    fn from_snapshot(snapshot: WindowsNodeMetadata, epoch: EpochSequence) -> Self {
        let times = snapshot.times();
        let directory = matches!(snapshot.node(), NodeId::Directory(_));
        Self {
            epoch: epoch.get(),
            creation: super::time::windows_timestamp(times.created().unwrap_or(times.changed())),
            accessed: super::time::windows_timestamp(times.accessed()),
            modified: super::time::windows_timestamp(times.modified()),
            changed: super::time::windows_timestamp(times.changed()),
            attributes: snapshot.windows_file_attributes(),
            links: if directory {
                1
            } else {
                u32::from(snapshot.links_count().on_disk_count())
            },
            directory: u32::from(directory),
            writable_data: u32::from(snapshot.data_policy() == ext4_core::NodeDataPolicy::Writable),
        }
    }
}

/// Result after the native header has committed one epoch-tagged metadata projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamMetadataPublication {
    /// Native header and any present Cache Manager map accepted the projection.
    Complete,
    /// Native header committed, but Cache Manager failed or raised after that commit point.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "host stream emulation has no Cache Manager failure source"
        )
    )]
    CacheProjectionFailed {
        /// Exact Cache Manager status or captured exception code.
        status: NTSTATUS,
    },
}

/// Rounds a Windows section bound to the mounted ext4 allocation cluster.
/// # Errors
///
/// Returns invalid-parameter when rounding would overflow the byte-count domain.
fn round_up_allocation(bytes: u64, cluster_size: ClusterSize) -> DriverResult<u64> {
    if bytes == 0 {
        return Ok(0);
    }
    let unit = u64::from(cluster_size.bytes());
    let remainder = bytes
        .checked_rem(unit)
        .ok_or(DriverError::InternalInvariantViolation)?;
    if remainder == 0 {
        return Ok(bytes);
    }
    let padding = unit
        .checked_sub(remainder)
        .ok_or(DriverError::InternalInvariantViolation)?;
    bytes
        .checked_add(padding)
        .ok_or(DriverError::InvalidParameter)
}

/// Opaque native `FSRTL_ADVANCED_FCB_HEADER` plus its resources, sections, and oplock.
pub(crate) struct StreamContext {
    /// Payload-free trace capability retained by the driver-lifetime provider owner.
    trace: OperationalTrace,
    /// Sole section admission authority, retained by callbacks and unique mutation permits.
    sections: crate::memory::DriverShared<SectionSynchronization>,
    /// Immutable ownership domain validated by the native boundary.
    runtime: StreamRuntime,
    /// Nonpaged allocation whose leading bytes are the advanced header.
    #[cfg(not(test))]
    header: NonNull<c_void>,
    /// Host equivalent of the immutable native owner identity.
    #[cfg(test)]
    owner: AtomicPtr<c_void>,
    /// Host equivalent of the volume-only immutable native lower control route.
    #[cfg(test)]
    control_device: AtomicPtr<wdk_sys::DEVICE_OBJECT>,
    /// Stable host ABI storage; tests access fields only through the external pointer boundary.
    #[cfg(test)]
    section_objects: UnsafeCell<wdk_sys::SECTION_OBJECT_POINTERS>,
    /// Host equivalent of the native header mutex and size fields.
    #[cfg(test)]
    sizes: Mutex<StreamSizes>,
    /// Host equivalent of the native epoch-tagged Fast I/O query projection.
    #[cfg(test)]
    metadata: Mutex<Option<StreamMetadata>>,
    /// Host equivalent of the ledger-derived native metadata query fallback gate.
    #[cfg(test)]
    namespace_query_fallback: AtomicBool,
}

/// Stream-domain-specific Rust ownership retained until native destruction.
enum StreamRuntime {
    /// Node-only consuming MDL completion resource.
    Node {
        /// Address-stable completion ownership, prepared before cache pages are exposed.
        #[cfg(not(test))]
        completion: core::pin::Pin<Box<crate::irp::mdl_completion::MdlCompletionQueue>>,
    },
    /// Sole admission allocation owner, retained until the native stream is destroyed.
    Volume(NativeAllocation<StorageAdmission>),
}

impl StreamRuntime {
    /// Prepares node-only completion ownership before any native header is exposed.
    /// # Errors
    /// Returns nonpaged completion-inbox allocation failure.
    fn try_node() -> DriverResult<Self> {
        Ok(Self::Node {
            #[cfg(not(test))]
            completion: crate::irp::mdl_completion::MdlCompletionQueue::try_new()?,
        })
    }

    /// Immutable owner domain implied by the resource variant.
    const fn kind(&self) -> StreamOwnerKind {
        match self {
            Self::Node { .. } => StreamOwnerKind::Node,
            Self::Volume(_) => StreamOwnerKind::Volume,
        }
    }

    /// Stable runtime identity borrowed by the corresponding native header.
    #[cfg(not(test))]
    fn as_ptr(&self) -> *mut c_void {
        match self {
            Self::Node { completion } => completion.as_ref().as_ptr(),
            Self::Volume(admission) => admission.address().as_ptr().cast(),
        }
    }
}

/// Terminal PnP observations carry different mounted-device retirement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageRemovalNotification {
    /// Revoke storage while retaining the mounted device for the later final request.
    Surprise,
    /// Revoke storage and permit retirement after retained handles and callbacks drain.
    Final,
}

/// Retained volume-scoped observation/submission capability; native callbacks borrow the same state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VolumeStorageAccess {
    /// The sole Rust admission authority, retained by actor/dispatch/worker lifetime.
    state: NonNull<StorageAdmission>,
    /// Native resource identity; held only through same-thread IoCallDriver submission.
    #[cfg(not(test))]
    header: NonNull<c_void>,
}

/// PnP-only revocation authority, separate from observation and lower submission.
#[derive(Debug)]
pub(crate) struct StorageRemovalPublisher {
    /// Retained volume state and its native submission resource.
    access: VolumeStorageAccess,
}

/// Sole reversible preparation; unpublished drop reopens only its own create exclusion.
#[derive(Debug)]
pub(crate) struct QueryRemovalPreparation {
    /// Mounted operation retains the volume until preparation is resolved.
    storage: VolumeStorageAccess,
}

/// Namespace exclusion through key publication, including implicit owner cleanup.
/// The mounted mutation operation retains the enclosing volume until this lease is dropped.
#[derive(Debug)]
pub(crate) struct KeyRemovalLease {
    /// Read/transition capability cannot recover the reactor's reliability publisher.
    storage: VolumeStorageAccess,
}

impl Drop for KeyRemovalLease {
    fn drop(&mut self) {
        self.storage.state().end_key_removal();
    }
}

#[expect(
    unsafe_code,
    reason = "only volume admission atomics cross threads; the mounted operation retains their allocation"
)]
// SAFETY: No same-thread native resource is retained; operation rundown retains the volume.
unsafe impl Send for KeyRemovalLease {}

impl QueryRemovalPreparation {
    /// Transfers reversible create exclusion to lower PnP resolution.
    /// # Errors
    /// Returns media revocation or an invalid preparation transition.
    pub(crate) fn publish(self) -> DriverResult<()> {
        self.storage.authorize()?;
        if self.storage.state().publish_query() {
            Ok(())
        } else {
            self.storage.authorize()?;
            Err(DriverError::InternalInvariantViolation)
        }
    }
}

impl Drop for QueryRemovalPreparation {
    fn drop(&mut self) {
        self.storage.state().abort_query();
    }
}

#[expect(
    unsafe_code,
    reason = "the mounted operation retains the boxed admission state across worker transitions"
)]
// SAFETY: Only atomics cross threads; no native resource acquisition is retained by preparation.
unsafe impl Send for QueryRemovalPreparation {}

impl StorageRemovalPublisher {
    /// Forwards lower cancellation before resolving reversible create exclusion.
    /// # Safety
    /// The caller exclusively owns an unqueued CANCEL_REMOVE IRP on the PASSIVE_LEVEL PnP thread.
    /// Dispatch rundown retains the volume and lower route; completion authority remains with caller.
    #[expect(
        unsafe_code,
        reason = "PnP ownership encloses the original IRP and synchronous lower forwarding"
    )]
    pub(crate) unsafe fn cancel_remove(
        &self,
        lower: crate::state::KernelDevice,
        irp: NonNull<wdk_sys::IRP>,
    ) -> NTSTATUS {
        #[cfg(not(test))]
        {
            let status_block = unsafe {
                // SAFETY: The PnP owner owns only this status block before lower forwarding.
                &mut (*irp.as_ptr()).IoStatus
            };
            status_block.__bindgen_anon_1.Status = wdk_sys::STATUS_SUCCESS;
            if unsafe {
                // SAFETY: Dispatch retains both devices and this original IRP until lower completion.
                wdk_sys::ntddk::IoForwardIrpSynchronously(lower.as_ptr(), irp.as_ptr())
            } == 0
            {
                return wdk_sys::STATUS_INVALID_DEVICE_REQUEST;
            }
        }
        #[cfg(test)]
        let _lower = lower;
        let status_block = unsafe {
            // SAFETY: The caller retains this completed lower reply's stable status block.
            &(*irp.as_ptr()).IoStatus
        };
        let status = unsafe {
            // SAFETY: Lower completion initialized the status union arm.
            status_block.__bindgen_anon_1.Status
        };
        if status >= wdk_sys::STATUS_SUCCESS {
            self.access.state().cancel_query();
        }
        status
    }

    /// Revokes media under exclusive submission exclusion; never waits for lower completion.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "mounted dispatch retains the native submission resource and admission allocation"
        )
    )]
    pub(crate) fn publish(&self, notification: StorageRemovalNotification) {
        #[cfg(not(test))]
        if unsafe {
            // SAFETY: PnP dispatch retains the native volume and waits only for submission scopes.
            ext4win_stream_acquire_submissions(self.access.header.as_ptr(), 1)
        } == 0
        {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
        self.access.state().remove(match notification {
            StorageRemovalNotification::Surprise => MediaState::SurpriseRemoved,
            StorageRemovalNotification::Final => MediaState::Removed,
        });
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This same thread holds the exclusive resource and its APC scope.
            ext4win_stream_release_submissions(self.access.header.as_ptr());
        }
    }
}

impl VolumeStorageAccess {
    /// Binds the real device once while mount still owns unpublished native admission.
    /// # Errors
    /// Rejects duplicate admission initialization before mount publication.
    pub(crate) fn bind_verification_device(
        self,
        device: super::volume_verify::VerificationDevice,
    ) -> DriverResult<()> {
        self.state().bind_verification_device(device)
    }
    /// Claims independent create exclusion while a clean locked volume removes a key.
    /// # Errors
    /// Returns device busy if a key-removal lease already owns the exclusion.
    pub(crate) fn begin_key_removal(self) -> DriverResult<KeyRemovalLease> {
        self.authorize()?;
        if self.state().begin_key_removal() {
            Ok(KeyRemovalLease { storage: self })
        } else {
            Err(DriverError::DeviceBusy)
        }
    }

    /// Exclusion outlives lock-owner cleanup until the key mutation completes.
    pub(crate) fn key_removal_active(self) -> bool {
        self.state().key_removal_active()
    }
    /// Borrows admission only while its enclosing volume retention is live.
    #[expect(
        unsafe_code,
        reason = "private capability acquisition binds the state to the retaining volume lifetime"
    )]
    fn state(&self) -> &StorageAdmission {
        unsafe {
            // SAFETY: Only the retained volume constructor supplies this stable boxed state.
            self.state.as_ref()
        }
    }

    /// Claims the one-way writeback phase.
    /// # Errors
    /// Returns media revocation or repeated terminal close rejection.
    pub(crate) fn begin_close_writeback(self) -> DriverResult<()> {
        self.authorize()?;
        if self.state().begin_close() {
            Ok(())
        } else {
            Err(DriverError::VolumeDismounted)
        }
    }

    /// Seals new paging while owner-driven lower flush retains its independent media capability.
    pub(crate) fn seal_close_writeback(self) {
        self.state().seal_close();
    }

    /// Paging is admitted through writeback and rejected after sealing.
    /// # Errors
    /// Returns media revocation or filesystem close rejection.
    pub(crate) fn authorize_paging(self) -> DriverResult<()> {
        self.authorize()?;
        if self.state().close() != ClosePhase::Sealed {
            Ok(())
        } else {
            Err(DriverError::VolumeDismounted)
        }
    }

    /// Requires media presence, open filesystem admission and no reversible query exclusion.
    /// # Errors
    /// Returns media revocation or create exclusion without granting mutation authority.
    pub(crate) fn authorize_create(self) -> DriverResult<()> {
        self.authorize()?;
        if self.state().verification_required() {
            return Err(DriverError::VerifyRequired);
        }
        if self.state().creates_admitted() {
            Ok(())
        } else {
            self.authorize()?;
            Err(DriverError::AccessDenied)
        }
    }

    /// Observes only media presence; lower final flush is independent of filesystem admission.
    /// # Errors
    /// Returns device removed after either terminal revocation notification.
    pub(crate) fn authorize(self) -> DriverResult<()> {
        if self.state().media() == MediaState::Present {
            Ok(())
        } else {
            Err(DriverError::DeviceRemoved)
        }
    }

    /// Final removal grants device-retirement authority beyond surprise removal.
    pub(crate) fn final_removal_received(self) -> bool {
        self.state().media() == MediaState::Removed
    }

    /// Holds media admission through the return of IoCallDriver on the acquiring thread.
    /// # Errors
    /// Returns revocation or resource contention before any lower submission.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "native resource retention is balanced by the same-thread lease"
        )
    )]
    pub(crate) fn acquire_submission(self) -> DriverResult<StorageSubmissionLease> {
        #[cfg(not(test))]
        if unsafe {
            // SAFETY: Actor/dispatch rundown retains this volume through the resource acquisition.
            ext4win_stream_acquire_submissions(self.header.as_ptr(), 0)
        } == 0
        {
            return Err(DriverError::DeviceRemoved);
        }
        let lease = StorageSubmissionLease { access: self };
        self.authorize()?;
        Ok(lease)
    }
}

/// Same-thread native resource acquisition consumed immediately after lower submission.
/// This value must never be deferred or moved to another thread.
#[derive(Debug)]
pub(crate) struct StorageSubmissionLease {
    /// Exact volume admission whose shared resource is held.
    access: VolumeStorageAccess,
}

impl Drop for StorageSubmissionLease {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the same-thread lease balances its sole native shared-resource acquisition"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Construction acquired this resource on the current thread; no Send impl exists.
            ext4win_stream_release_submissions(self.access.header.as_ptr());
        }
        #[cfg(test)]
        let _access = self.access;
    }
}

impl core::fmt::Debug for StreamContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StreamContext")
            .field("kind", &self.runtime.kind())
            .field("header", &self.header())
            .finish()
    }
}

#[expect(
    unsafe_code,
    reason = "the audited wrapper is the sole Rust boundary for the opaque native advanced FCB header"
)]
impl StreamContext {
    /// Balances a Filter Manager data-scan section independently of ordinary I/O admission.
    /// # Errors
    /// Returns unmatched-disable or finite section-count exhaustion before changing state.
    pub(crate) fn change_scan_section(&self, change: ScanSectionChange) -> DriverResult<()> {
        self.sections.get().change_scan(change)
    }

    /// Successful return authorizes another attempt only after a mapped-section conflict and
    /// scan release. I/O errors, stale plans and uncertain writeback are never retried here.
    /// # Errors
    /// Returns the original failure or the Filter Manager retry status for an eligible request.
    fn await_scan_conflict(
        &self,
        error: DriverError,
        policy: PurgeFailurePolicy,
    ) -> DriverResult<()> {
        let mapped = error == DriverError::CannotDelete
            || matches!(error,
            DriverError::CacheManagerFailure(status) if status == wdk_sys::STATUS_USER_MAPPED_FILE
                || status == wdk_sys::STATUS_CACHE_PAGE_LOCKED || status == wdk_sys::STATUS_PURGE_FAILED);
        if !mapped || !self.sections.get().scans_active() {
            return Err(error);
        }
        match policy {
            PurgeFailurePolicy::FilterRetry => Err(DriverError::CacheManagerFailure(
                wdk_sys::STATUS_PURGE_FAILED,
            )),
            PurgeFailurePolicy::DestructiveCreate => Err(DriverError::CacheManagerFailure(
                wdk_sys::STATUS_USER_MAPPED_FILE,
            )),
            PurgeFailurePolicy::WaitForScans => {
                self.sections.get().wait_for_scans();
                Ok(())
            }
        }
    }
    /// Observes the archive bit from the sole coherent committed metadata projection.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the retained native header serializes this observation with its metadata mutex"
        )
    )]
    pub(crate) fn archive_is_set(&self) -> bool {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This owner retains the native header through its bounded metadata observation.
            ext4win_stream_archive_is_set(self.header.as_ptr()) != 0
        }
        #[cfg(test)]
        self.metadata.lock().is_ok_and(|metadata| {
            metadata
                .is_some_and(|metadata| metadata.attributes & wdk_sys::FILE_ATTRIBUTE_ARCHIVE != 0)
        })
    }
    /// Allocates a node advanced header in an unbound construction state.
    ///
    /// The enclosing Rust owner must reach pinned storage and call [`Self::bind_node_owner`]
    /// before the header can be published to a `FILE_OBJECT`.
    /// # Errors
    ///
    /// Returns an allocation or invariant error when the native FCB boundary cannot be built.
    pub(crate) fn try_new_staged_node(
        sizes: StreamSizes,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        Self::try_new(StreamRuntime::try_node()?, sizes, None, trace)
    }

    /// Allocates a node advanced header with one coherent committed metadata projection.
    ///
    /// The enclosing Rust owner must reach pinned storage and call [`Self::bind_node_owner`]
    /// before the header can be published to a `FILE_OBJECT`.
    /// # Errors
    ///
    /// Returns an allocation or invariant error when the native FCB boundary cannot be built.
    pub(crate) fn try_new_committed_node(
        sizes: StreamSizes,
        snapshot: WindowsNodeMetadata,
        epoch: EpochSequence,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        Self::try_new(
            StreamRuntime::try_node()?,
            sizes,
            Some(StreamMetadata::from_snapshot(snapshot, epoch)),
            trace,
        )
    }

    /// Allocates the raw-volume advanced header without a node metadata projection.
    /// # Errors
    ///
    /// Returns an allocation or invariant error when the native FCB boundary cannot be built.
    pub(crate) fn try_new_volume(
        sizes: StreamSizes,
        trace: OperationalTrace,
        reliability: super::io_reliability::IoReliabilityObservation,
    ) -> DriverResult<Self> {
        let runtime = StreamRuntime::Volume(NativeAllocation::from_box(
            crate::memory::boxed_try_with(|| Ok(StorageAdmission::new(reliability)))?,
        ));
        Self::try_new(runtime, sizes, None, trace)
    }

    /// Allocates the opaque native stream with its owner-domain-specific metadata state.
    /// # Errors
    ///
    /// Returns an allocation or invariant error when the native stream cannot be constructed.
    fn try_new(
        runtime: StreamRuntime,
        sizes: StreamSizes,
        metadata: Option<StreamMetadata>,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        let sections = SectionSynchronization::try_new()?;
        #[cfg(not(test))]
        {
            let mut header = core::ptr::null_mut();
            let metadata_pointer = metadata
                .as_ref()
                .map_or(core::ptr::null(), core::ptr::from_ref);
            let status = unsafe {
                // SAFETY: Native code borrows the optional fixed input for this call, writes one
                // opaque pointer on success, and owns every partial-allocation cleanup path.
                // RustState retains the runtime's original allocation pointer; moving the runtime
                // preserves that pointer, and StreamContext destroys the native header first.
                ext4win_stream_create(
                    runtime.kind().native_tag(),
                    sizes.allocation_size,
                    sizes.file_size,
                    sizes.valid_data_length,
                    sizes.allocation_charge,
                    metadata_pointer,
                    trace.handle(),
                    runtime.as_ptr(),
                    core::ptr::from_ref(sections.get()).cast(),
                    core::ptr::addr_of_mut!(header),
                )
            };
            native_status(status)?;
            let header = NonNull::new(header).ok_or(DriverError::InternalInvariantViolation)?;
            Ok(Self {
                trace,
                sections,
                runtime,
                header,
            })
        }
        #[cfg(test)]
        {
            if (runtime.kind() == StreamOwnerKind::Volume) && metadata.is_some() {
                return Err(DriverError::InternalInvariantViolation);
            }
            Ok(Self {
                trace,
                sections,
                runtime,
                owner: AtomicPtr::new(core::ptr::null_mut()),
                control_device: AtomicPtr::new(core::ptr::null_mut()),
                section_objects: UnsafeCell::new(wdk_sys::SECTION_OBJECT_POINTERS::default()),
                sizes: Mutex::new(sizes),
                metadata: Mutex::new(metadata),
                namespace_query_fallback: AtomicBool::new(false),
            })
        }
    }

    /// Reports whether the FCB owns an immutable native paging-file mapping.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the retained stream header owns the native one-time paging state"
        )
    )]
    pub(crate) fn is_paging_file(&self) -> bool {
        #[cfg(not(test))]
        {
            unsafe {
                // SAFETY: The stream owner retains the native header through this atomic observation.
                ext4win_stream_is_paging_file(self.header.as_ptr()) != 0
            }
        }
        #[cfg(test)]
        {
            false
        }
    }

    /// Reserves initial setup or extension while a caller-owned deferred FCB lease retains it.
    /// # Safety
    /// The caller must keep this exact stream alive until the returned reservation is consumed
    /// or dropped, including every failure path. Initial setup additionally owns its first-open
    /// claim with no previously published FILE_OBJECT or native section residency.
    /// # Errors
    /// Returns competing setup, stale native identity or non-writable media admission failures.
    #[expect(
        unsafe_code,
        reason = "the caller supplies an explicit deferred FCB owner for the returned native reservation"
    )]
    pub(crate) unsafe fn reserve_paging_file(
        &self,
        file: crate::state::KernelFileObject,
        extension: bool,
    ) -> DriverResult<PagingFileReservation> {
        #[cfg(not(test))]
        {
            let mut physical = 0;
            let mut length = 0;
            let status = unsafe {
                // SAFETY: The caller retains the FCB, original FILE_OBJECT and mounted route.
                ext4win_stream_reserve_paging_file(
                    self.header.as_ptr(),
                    file.as_ptr(),
                    u8::from(extension),
                    &mut physical,
                    &mut length,
                )
            };
            cache_status(status)?;
            let claim = if extension {
                let (Ok(physical), Ok(length)) = (u64::try_from(physical), u64::try_from(length))
                else {
                    unsafe {
                        // SAFETY: Setup was acquired above but its scalar outputs are invalid.
                        ext4win_stream_abort_paging_file(self.header.as_ptr(), 1);
                    }
                    return Err(DriverError::InternalInvariantViolation);
                };
                PagingFileClaim::Extension {
                    physical: ext4_core::ByteOffset::new(physical),
                    length: FileSize::from_bytes(length),
                }
            } else {
                PagingFileClaim::Initial
            };
            Ok(PagingFileReservation {
                header: self.header,
                claim,
                phase: PagingReservationPhase::Reserved,
            })
        }
        #[cfg(test)]
        {
            let _inputs = (file, extension);
            Err(DriverError::NotSupported)
        }
    }

    /// Returns the acknowledged paging bound; zero means no active direct-I/O mapping.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this stream owner retains the native map through its locked scalar observation"
        )
    )]
    pub(crate) fn paging_file_length(&self) -> u64 {
        #[cfg(not(test))]
        {
            // SAFETY: The map and its spin lock remain retained by this stream borrow.
            u64::try_from(unsafe { ext4win_stream_paging_length(self.header.as_ptr()) })
                .unwrap_or(0)
        }
        #[cfg(test)]
        {
            0
        }
    }

    /// Atomically binds one pinned FCB and its embedded byte-range lock package.
    ///
    /// # Safety
    ///
    /// `owner` must identify the pinned enclosing `FileControlBlock`, and `locks` must identify
    /// that owner's embedded `FILE_LOCK`. Both allocations must outlive this native stream and no
    /// header may be published before this one-time call succeeds. `volume` must be its pinned
    /// enclosing VCB's volume stream and must outlive this node stream, including section residency.
    /// # Errors
    ///
    /// Returns an invariant error if the native node stream is malformed or already bound.
    pub(crate) unsafe fn bind_node_owner(
        &self,
        owner: NonNull<c_void>,
        locks: NonNull<wdk_sys::FILE_LOCK>,
        volume: &StreamContext,
    ) -> DriverResult<()> {
        if self.runtime.kind() != StreamOwnerKind::Node
            || volume.runtime.kind() != StreamOwnerKind::Volume
        {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The caller establishes the pinned common lifetime documented above.
                ext4win_stream_bind_node_owner(
                    self.header.as_ptr(),
                    owner.as_ptr(),
                    locks.as_ptr(),
                    volume.header.as_ptr(),
                )
            };
            native_status(status)
        }
        #[cfg(test)]
        {
            let _retained = (locks, volume);
            self.owner
                .compare_exchange(
                    core::ptr::null_mut(),
                    owner.as_ptr(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map(|_| ())
                .map_err(|_| DriverError::InternalInvariantViolation)
        }
    }

    /// Captures storage authority from a pinned mounted volume. Every copy must be used only
    /// while an actor/dispatch lease retains this native stream, and withdrawn before it drops.
    /// # Safety
    ///
    /// The caller must retain this volume at its current address through every capability use.
    /// # Errors
    ///
    /// Rejects node streams, which cannot grant volume-wide storage submission or revocation.
    pub(crate) unsafe fn storage_access(&self) -> DriverResult<VolumeStorageAccess> {
        if self.runtime.kind() != StreamOwnerKind::Volume {
            return Err(DriverError::InternalInvariantViolation);
        }
        let StreamRuntime::Volume(state) = &self.runtime else {
            return Err(DriverError::InternalInvariantViolation);
        };
        Ok(VolumeStorageAccess {
            state: state.address(),
            #[cfg(not(test))]
            header: self.header,
        })
    }

    /// Reserves the reversible PnP create gate for the sole mounted query-remove operation.
    /// # Safety
    /// The pinned mounted VCB must outlive the returned preparation and all uses of its header.
    /// # Errors
    /// Returns device removed for lost storage, or device busy for another removal preparation.
    pub(crate) unsafe fn prepare_query_removal(&self) -> DriverResult<QueryRemovalPreparation> {
        let storage = unsafe {
            // SAFETY: The caller retains this pinned volume through the returned preparation.
            self.storage_access()
        }?;
        storage.authorize()?;
        let acquired = storage.state().prepare_query();
        if !acquired {
            storage.authorize()?;
            return Err(DriverError::DeviceBusy);
        }
        Ok(QueryRemovalPreparation { storage })
    }

    /// Captures removal publication separately from storage observation and submission.
    /// # Safety
    /// The caller must own the mounted device's PnP dispatch boundary and retain this volume
    /// at its current address through every publication under dispatch rundown.
    /// # Errors
    /// Rejects a node stream, which has no volume-wide removal authority.
    pub(crate) unsafe fn storage_removal_publisher(&self) -> DriverResult<StorageRemovalPublisher> {
        let access = unsafe {
            // SAFETY: The caller establishes the enclosing mounted-device lifetime above.
            self.storage_access()
        }?;
        Ok(StorageRemovalPublisher { access })
    }

    /// Binds one pinned VCB as the sole direct-volume stream owner.
    ///
    /// # Safety
    ///
    /// `owner` must identify the pinned enclosing `VolumeControlBlock`, which must outlive this
    /// native stream. `control_device` must be the mount's retained partition target.
    /// No header may be published before this one-time call succeeds.
    /// # Errors
    ///
    /// Returns an invariant error if the native volume stream is malformed or already bound.
    pub(crate) unsafe fn bind_volume_owner(
        &self,
        owner: NonNull<c_void>,
        control_device: crate::state::KernelDevice,
    ) -> DriverResult<()> {
        if self.runtime.kind() != StreamOwnerKind::Volume {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The caller establishes the pinned enclosing lifetime documented above.
                ext4win_stream_bind_volume_owner(
                    self.header.as_ptr(),
                    owner.as_ptr(),
                    control_device.as_ptr(),
                )
            };
            native_status(status)
        }
        #[cfg(test)]
        {
            self.owner
                .compare_exchange(
                    core::ptr::null_mut(),
                    owner.as_ptr(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            self.control_device
                .store(control_device.as_ptr(), Ordering::Release);
            Ok(())
        }
    }

    /// Reads the native volume's immutable lower control route without borrowing its Rust VCB.
    /// # Safety
    ///
    /// `header` must be retained by an active direct-volume FILE_OBJECT for this call and every
    /// subsequent use of the returned device. Its bound mount must retain that lower target.
    /// # Errors
    ///
    /// Returns an invariant failure for an unbound or non-volume header.
    pub(crate) unsafe fn decode_volume_control_device(
        header: NonNull<c_void>,
    ) -> DriverResult<crate::state::KernelDevice> {
        #[cfg(not(test))]
        let device = unsafe {
            // SAFETY: The caller retains the header and its immutable native routing projection.
            ext4win_stream_volume_control_device(header.as_ptr())
        };
        #[cfg(test)]
        let device = {
            let stream = unsafe {
                // SAFETY: Host headers identify the retained StreamContext itself.
                header.cast::<Self>().as_ref()
            };
            if stream.runtime.kind() != StreamOwnerKind::Volume {
                return Err(DriverError::InternalInvariantViolation);
            }
            stream.control_device.load(Ordering::Acquire)
        };
        unsafe {
            // SAFETY: The volume FILE_OBJECT and its mount retain this published device identity.
            crate::state::KernelDevice::from_raw(device)
        }
        .ok_or(DriverError::InternalInvariantViolation)
    }

    /// Admits a short actor control call while preserving its input on resource contention.
    /// Native callbacks may reacquire this same-thread exclusive resource recursively.
    /// # Errors
    /// Returns the unconsumed input when native resource admission is busy.
    pub(crate) fn with_control_resource<T, R>(
        &self,
        input: T,
        action: impl FnOnce(T) -> R,
    ) -> Result<R, T> {
        #[cfg(not(test))]
        let _guard = {
            let resource = self.main_resource().unwrap_or_else(|_| crate::kernel::fatal::KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck());
            let Some(guard) = resource.try_exclusive() else {
                return Err(input);
            };
            guard
        };
        Ok(action(input))
    }

    /// Transfers one live filesystem-control IRP to the stream-owned FsRtl oplock package.
    ///
    /// # Safety
    ///
    /// `irp` must identify the active `IRP_MJ_FILE_SYSTEM_CONTROL` request whose FILE_OBJECT owns
    /// this stream. The caller transfers terminal completion authority to FsRtl exactly once.
    #[cfg(not(test))]
    pub(crate) unsafe fn process_oplock_fsctrl(
        &self,
        irp: NonNull<wdk_sys::IRP>,
        open_count: u32,
        flags: u32,
    ) -> NTSTATUS {
        unsafe {
            // SAFETY: The caller supplies the live consuming IRP capability documented above.
            ext4win_stream_oplock_fsctrl(self.header.as_ptr(), irp.as_ptr(), open_count, flags)
        }
    }

    /// Synchronously asks FsRtl to establish the atomic oplock encoded by one create IRP.
    ///
    /// # Safety
    ///
    /// `irp` must identify the unique live `IRP_MJ_CREATE` request whose provisional share claim
    /// contributes to `open_count`. The caller retains completion authority because create-time
    /// requests do not return `STATUS_PENDING` from this boundary.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the retained stream and borrowed live create IRP cross the audited FsRtl boundary"
    )]
    pub(crate) unsafe fn reserve_create_oplock(
        &self,
        irp: NonNull<wdk_sys::IRP>,
        open_count: u32,
    ) -> NTSTATUS {
        self.with_control_resource(irp, |irp| unsafe {
            // SAFETY: The caller retains the exact stream, IRP, and admitted handle-count
            // authorities documented above for this synchronous call.
            ext4win_stream_oplock_fsctrl(self.header.as_ptr(), irp.as_ptr(), open_count, 0)
        })
        .unwrap_or(wdk_sys::STATUS_OPLOCK_NOT_GRANTED)
    }

    /// Delegates one break-causing IRP to the stream-owned FsRtl oplock package.
    ///
    /// # Safety
    ///
    /// `irp` must be the unique live top-level IRP and `continuation` must remain at a stable
    /// nonpaged address until either this call returns a non-pending status or the registered
    /// wait-completion callback publishes it exactly once.
    #[cfg(not(test))]
    pub(crate) unsafe fn check_oplock(
        &self,
        irp: NonNull<wdk_sys::IRP>,
        flags: u32,
        continuation: NonNull<c_void>,
    ) -> (NTSTATUS, bool) {
        let mut admitted = 0;
        let status = unsafe {
            // SAFETY: The caller supplies the consuming IRP and stable continuation capabilities
            // documented above; native SEH contains FsRtl exceptions at the C boundary.
            ext4win_stream_check_oplock(
                self.header.as_ptr(),
                irp.as_ptr(),
                flags,
                continuation.as_ptr(),
                &raw mut admitted,
            )
        };
        (status, admitted != 0)
    }

    /// Releases the exact cleanup handle's oplock without client acknowledgment or IRP delegation.
    /// # Safety
    /// The passive worker must retain the live cleanup IRP and FILE_OBJECT until synchronous return.
    #[cfg(not(test))]
    pub(crate) unsafe fn cleanup_oplock(&self, irp: NonNull<wdk_sys::IRP>, flags: u32) -> NTSTATUS {
        unsafe {
            // SAFETY: The caller owns the cleanup IRP and stream; native SEH contains synchronous FsRtl faults.
            ext4win_stream_cleanup_oplock(self.header.as_ptr(), irp.as_ptr(), flags)
        }
    }

    /// Reverts one create-time atomic oplock reservation before the create IRP fails.
    ///
    /// # Safety
    ///
    /// `irp` must be the unique live `IRP_MJ_CREATE` request that established the reservation,
    /// and the caller must prevent the associated provisional handle claim from being released
    /// until this synchronous call returns.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the live create IRP and retained stream cross the audited native FsRtl boundary"
    )]
    pub(crate) unsafe fn backout_atomic_oplock(&self, irp: NonNull<wdk_sys::IRP>) -> NTSTATUS {
        unsafe {
            // SAFETY: The caller supplies the exact live create IRP and retains this stream for
            // the full synchronous backout described above.
            ext4win_stream_backout_atomic_oplock(self.header.as_ptr(), irp.as_ptr())
        }
    }

    /// Transfers one live lock-control IRP to the bound FsRtl FILE_LOCK package.
    ///
    /// # Safety
    ///
    /// `irp` must identify the active `IRP_MJ_LOCK_CONTROL` request for this stream, and the caller
    /// must transfer terminal completion authority exactly once. `completion` must be the
    /// worker reserved for that same IRP before any lock effect or conflict wait begins.
    #[cfg(not(test))]
    pub(crate) unsafe fn process_file_lock(
        &self,
        irp: NonNull<wdk_sys::IRP>,
        completion: crate::irp::FileLockCompletion,
    ) -> NTSTATUS {
        let context = unsafe {
            // SAFETY: The caller transfers this live lock request; native delegation immediately
            // passes its context to the registered FsRtl completion routine, including rejection.
            completion.into_context(irp)
        };
        unsafe {
            // SAFETY: This consumes the exact IRP and its reserved terminal notification context.
            ext4win_stream_process_file_lock(self.header.as_ptr(), irp.as_ptr(), context.as_ptr())
        }
    }

    /// Releases cleanup-owned byte locks and refreshes the derived Fast I/O projection.
    /// # Errors
    ///
    /// Returns an invariant error if the native stream, FILE_OBJECT, or requestor identity is
    /// malformed. No remaining byte locks already satisfies cleanup, including a handle that
    /// never acquired a lock or whose locks were explicitly released before cleanup.
    pub(crate) fn unlock_all(
        &self,
        file_object: NonNull<wdk_sys::FILE_OBJECT>,
        process: NonNull<c_void>,
    ) -> DriverResult<()> {
        #[cfg(not(test))]
        let status = unsafe {
            // SAFETY: Cleanup retains the FCB, FILE_OBJECT, and captured requestor process.
            ext4win_stream_unlock_all(
                self.header.as_ptr(),
                file_object.as_ptr(),
                process.as_ptr().cast(),
            )
        };
        #[cfg(test)]
        let status = {
            let _file_object = file_object;
            let _process = process;
            wdk_sys::STATUS_RANGE_NOT_LOCKED
        };
        cleanup_unlock_status(status)
    }

    /// Returns the `FSRTL_ADVANCED_FCB_HEADER` address stored in `FILE_OBJECT::FsContext`.
    pub(crate) fn header(&self) -> NonNull<c_void> {
        #[cfg(not(test))]
        {
            self.header
        }
        #[cfg(test)]
        {
            NonNull::from(self).cast()
        }
    }

    /// Returns the stream-owned `SECTION_OBJECT_POINTERS` shared by every FILE_OBJECT.
    /// # Errors
    ///
    /// Returns an invariant error if the native stream no longer has a valid section identity.
    pub(crate) fn section_objects(
        &self,
    ) -> DriverResult<NonNull<wdk_sys::SECTION_OBJECT_POINTERS>> {
        unsafe {
            // SAFETY: The owning borrow retains this header and its section storage.
            Self::decode_section_objects(self.header())
        }
    }

    /// Reads one coherent stream-size snapshot under the native advanced-header mutex.
    /// # Errors
    ///
    /// Returns an invariant error when the native stream header is malformed.
    pub(crate) fn sizes(&self) -> DriverResult<StreamSizes> {
        #[cfg(not(test))]
        {
            let mut sizes = StreamSizes::EMPTY;
            let status = unsafe {
                // SAFETY: `self` owns the live header and native code writes one complete tuple.
                ext4win_stream_get_sizes(
                    self.header.as_ptr(),
                    core::ptr::addr_of_mut!(sizes.allocation_size),
                    core::ptr::addr_of_mut!(sizes.file_size),
                    core::ptr::addr_of_mut!(sizes.valid_data_length),
                    core::ptr::addr_of_mut!(sizes.allocation_charge),
                )
            };
            native_status(status)?;
            Ok(sizes)
        }
        #[cfg(test)]
        {
            self.sizes
                .lock()
                .map(|sizes| *sizes)
                .map_err(|_| DriverError::InternalInvariantViolation)
        }
    }

    /// Commits one epoch-tagged node projection and reports Cache Manager separately.
    ///
    /// The native header is the commit point. A Cache Manager failure occurs after that point and
    /// is therefore returned as [`StreamMetadataPublication::CacheProjectionFailed`], not `Err`.
    /// Callers may invoke this only after ext4 durability and visibility publication for `epoch`.
    /// # Errors
    ///
    /// Returns an invariant error only when no native header commit occurred, such as a malformed
    /// stream or non-monotonic epoch.
    pub(crate) fn publish_node_metadata(
        &self,
        sizes: StreamSizes,
        snapshot: WindowsNodeMetadata,
        epoch: EpochSequence,
    ) -> DriverResult<StreamMetadataPublication> {
        if self.runtime.kind() != StreamOwnerKind::Node {
            return Err(DriverError::InternalInvariantViolation);
        }
        let metadata = StreamMetadata::from_snapshot(snapshot, epoch);
        #[cfg(not(test))]
        {
            let mut cache_status = STATUS_SUCCESS;
            let publication_status = unsafe {
                // SAFETY: `self` owns the live node header; native code borrows the complete fixed
                // projection and writes one status describing only the post-commit Cc outcome.
                ext4win_stream_publish_metadata(
                    self.header.as_ptr(),
                    sizes.allocation_size,
                    sizes.file_size,
                    sizes.valid_data_length,
                    sizes.allocation_charge,
                    core::ptr::from_ref(&metadata),
                    core::ptr::addr_of_mut!(cache_status),
                )
            };
            native_status(publication_status)?;
            if cache_status >= STATUS_SUCCESS {
                Ok(StreamMetadataPublication::Complete)
            } else {
                Ok(StreamMetadataPublication::CacheProjectionFailed {
                    status: cache_status,
                })
            }
        }
        #[cfg(test)]
        {
            let mut current_metadata = self
                .metadata
                .lock()
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            if current_metadata
                .as_ref()
                .is_some_and(|current| metadata.epoch <= current.epoch)
            {
                return Err(DriverError::InternalInvariantViolation);
            }
            let mut current_sizes = self
                .sizes
                .lock()
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            *current_sizes = sizes;
            *current_metadata = Some(metadata);
            Ok(StreamMetadataPublication::Complete)
        }
    }

    /// Selects IRP metadata queries while the namespace ledger has link-specific deletion state.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a live node stream.
    pub(crate) fn set_namespace_query_fallback(&self, pending: bool) -> DriverResult<()> {
        if self.runtime.kind() != StreamOwnerKind::Node {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The ledger retains this FCB and serializes the authoritative transition.
                ext4win_stream_set_namespace_query_fallback(self.header.as_ptr(), u8::from(pending))
            };
            native_status(status)
        }
        #[cfg(test)]
        {
            self.namespace_query_fallback
                .store(pending, Ordering::Release);
            Ok(())
        }
    }

    /// Copies cached bytes into one system-addressable IRP buffer.
    /// # Errors
    ///
    /// Returns the exact Cache Manager status or an input representation failure.
    pub(crate) fn cached_read(
        &self,
        _offset: i64,
        transfer: crate::irp::CacheReadTransfer<'_>,
    ) -> DriverResult<usize> {
        let length = transfer.length();
        if length == 0 {
            return Ok(0);
        }
        let _length = u32::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
        let _output = transfer
            .address()
            .ok_or(DriverError::InternalInvariantViolation)?;
        #[cfg(not(test))]
        {
            self.trace.record(
                OperationalPath::CachedRead,
                STATUS_SUCCESS,
                OperationalOutcome::Selected,
            );
            let result = (|| {
                self.initialize_cache(transfer.file_object())?;
                let _main = self.main_resource()?.ordinary_shared(self.sections.get());
                self.ensure_ordinary_io(false)?;
                super::cache_transfer::validate_copy_range(
                    _offset,
                    _length,
                    self.sizes()?.file_size(),
                )?;
                let mut information = 0;
                let status = unsafe {
                    // SAFETY: The sealed transfer retains its writable mapping and file; Rust
                    // selected the current in-EOF range under MainResource before the SEH call.
                    ext4win_cc_copy_read(
                        transfer.file_object().as_ptr(),
                        _offset,
                        _length,
                        _output.as_ptr().cast(),
                        &mut information,
                    )
                };
                cache_status(status)?;
                Ok(information)
            })();
            self.trace
                .record_result(OperationalPath::CachedRead, &result);
            result
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }

    /// Accepts one within-EOF write into the FILE_OBJECT cache map.
    /// Cache pressure returns CANT_WAIT before copying; the retaining executor retries with
    /// cancellation and a finite admission budget. Storage and EOF are revalidated before copy.
    /// # Errors
    ///
    /// Returns the exact Cache Manager status or an input representation failure.
    pub(crate) fn cached_write(
        &self,
        _offset: i64,
        transfer: crate::irp::CacheWriteTransfer<'_>,
        _retrying: bool,
    ) -> DriverResult<()> {
        let length = transfer.length();
        if length == 0 {
            return Ok(());
        }
        let _length = u32::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
        let _input = transfer
            .address()
            .ok_or(DriverError::InternalInvariantViolation)?;
        #[cfg(not(test))]
        {
            self.trace.record(
                OperationalPath::CachedWrite,
                STATUS_SUCCESS,
                OperationalOutcome::Selected,
            );
            let result = (|| {
                self.initialize_cache(transfer.file_object())?;
                let mut admission = super::cache_transfer::WriteAdmission::new(_retrying);
                {
                    unsafe {
                        // SAFETY: The passive work owner retains file through this nonblocking Cc check.
                        if !admission.accepted(transfer.file_object().as_ptr(), _length) {
                            return Err(DriverError::NativeAdmissionDenied);
                        }
                    }
                    let main = self.main_resource()?.ordinary_shared(self.sections.get());
                    self.ensure_ordinary_io(true)?;
                    if !self.archive_is_set() {
                        return Err(DriverError::CacheManagerFailure(
                            crate::kernel::status::STATUS_RETRY,
                        ));
                    }
                    if !unsafe {
                        // SAFETY: The same retained request rechecks Cc without waiting under MainResource.
                        admission.accepted(transfer.file_object().as_ptr(), _length)
                    } {
                        drop(main);
                        return Err(DriverError::NativeAdmissionDenied);
                    }
                    super::cache_transfer::validate_copy_range(
                        _offset,
                        _length,
                        self.sizes()?.file_size(),
                    )?;
                    let status = unsafe {
                        // SAFETY: The sealed transfer retains its readable mapping and file; current EOF
                        // cannot change under MainResource, and C owns expected SEH status capture.
                        ext4win_cc_copy_write(
                            transfer.file_object().as_ptr(),
                            _offset,
                            _length,
                            _input.as_ptr().cast(),
                        )
                    };
                    cache_status(status)
                }
            })();
            self.trace
                .record_result(OperationalPath::CachedWrite, &result);
            result
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }

    /// Establishes a private cache map before taking the ordinary transfer resource.
    /// # Errors
    /// Returns the exact native initialization or admission failure.
    #[cfg(not(test))]
    fn initialize_cache(&self, file: NonNull<wdk_sys::FILE_OBJECT>) -> DriverResult<()> {
        let status = unsafe {
            // SAFETY: The cache lease retains this exact stream and FILE_OBJECT through Cc initialization.
            ext4win_stream_cache_initialize(self.header.as_ptr(), file.as_ptr())
        };
        cache_status(status)
    }

    /// Executes an already captured MDL IRP without borrowing requestor byte memory.
    /// # Errors
    ///
    /// Returns the exact native status; writes extending the committed EOF are rejected.
    /// On success the IRP carries the Cache Manager-owned output chain. Failure releases
    /// any partially acquired chain before returning.
    pub(crate) fn cached_mdl(
        &self,
        _transfer: crate::irp::CacheMdlTransfer<'_>,
        _retrying: bool,
    ) -> DriverResult<usize> {
        let _file_object = _transfer.file_object();
        let _irp = _transfer.irp();
        let _request = _transfer.request();
        #[cfg(not(test))]
        {
            let request = _request;
            self.ensure_storage()?;
            let chain = unsafe {
                // SAFETY: The suspended operation exclusively retains this IRP through native work.
                core::ptr::addr_of_mut!((*_irp.as_ptr()).MdlAddress)
            };
            if !unsafe {
                // SAFETY: The sole worker reads its initialized chain linkage before page acquisition.
                chain.read()
            }
            .is_null()
            {
                return Err(DriverError::InvalidParameter);
            }
            self.initialize_cache(_file_object)?;
            if request.length() == 0 {
                return Ok(0);
            }
            let status = unsafe {
                // SAFETY: The retained acquisition IRP owns file/stream lifetime before pages are exposed.
                ext4win_prepare_mdl_completion(self.runtime.as_ptr(), _file_object.as_ptr())
            };
            cache_status(status)?;
            let mut admission = super::cache_transfer::WriteAdmission::new(_retrying);
            {
                if request.action() == crate::irp::MdlTransfer::Write {
                    unsafe {
                        // SAFETY: The passive owner retains file; no filesystem resource is held while waiting.
                        if !admission.accepted(_file_object.as_ptr(), request.length()) {
                            return Err(DriverError::NativeAdmissionDenied);
                        }
                    }
                }
                let _main = self.main_resource()?.ordinary_shared(self.sections.get());
                self.ensure_ordinary_io(request.action() == crate::irp::MdlTransfer::Write)?;
                if request.action() == crate::irp::MdlTransfer::Write && !self.archive_is_set() {
                    return Err(DriverError::NotSupported);
                }
                if request.action() == crate::irp::MdlTransfer::Write
                    && !unsafe {
                        // SAFETY: The same retained request rechecks admission without waiting under MainResource.
                        admission.accepted(_file_object.as_ptr(), request.length())
                    }
                {
                    drop(_main);
                    return Err(DriverError::NativeAdmissionDenied);
                }
                let length =
                    super::cache_transfer::bounded_length(request, self.sizes()?.file_size())?;
                if length == 0 {
                    return Ok(0);
                }
                let offset = i64::try_from(request.start().bytes())
                    .map_err(|_| DriverError::InvalidParameter)?;
                let mut information = 0;
                let status = match request.action() {
                    crate::irp::MdlTransfer::Read => unsafe {
                        // SAFETY: Current-EOF selection holds MainResource; C owns partial read-chain cleanup.
                        ext4win_cc_read_mdl(
                            _file_object.as_ptr(),
                            offset,
                            length,
                            chain,
                            &mut information,
                        )
                    },
                    crate::irp::MdlTransfer::Write => unsafe {
                        // SAFETY: Current-EOF selection holds MainResource; C owns partial write-chain abort.
                        ext4win_cc_prepare_mdl_write(
                            _file_object.as_ptr(),
                            offset,
                            length,
                            chain,
                            &mut information,
                        )
                    },
                };
                cache_status(status)?;
                Ok(information)
            }
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }

    /// Rejects ordinary cache acquisition independently of lower media presence.
    /// # Errors
    /// Returns removal, terminal filesystem close or a missing bound volume invariant.
    #[cfg(not(test))]
    fn ensure_ordinary_io(&self, write: bool) -> DriverResult<()> {
        self.ensure_storage()?;
        let address = unsafe {
            // SAFETY: Bound stream lifetime retains the volume's sole admission allocation.
            ext4win_stream_storage_admission(self.header.as_ptr())
        };
        let state = unsafe {
            // SAFETY: Successful storage validation established this immutable, retained allocation identity.
            &*address.cast::<StorageAdmission>()
        };
        if state.close() == ClosePhase::Open && state.reliability.policy().permits(write) {
            if write
                && unsafe {
                    // SAFETY: This stream retains its coherent native metadata; caller holds MainResource.
                    ext4win_stream_data_writable(self.header.as_ptr())
                } == 0
            {
                return Err(DriverError::AccessDenied);
            }
            Ok(())
        } else {
            Err(DriverError::VolumeDismounted)
        }
    }

    /// Flushes all dirty cached pages for this stream and observes the Cache Manager result.
    /// # Errors
    ///
    /// Returns the exact Cache Manager flush status.
    pub(crate) fn flush_cache(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live shared section-object set for this call.
                ext4win_stream_cache_flush(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Flushes terminal cached data under exclusive stream ownership without closing handles.
    /// # Errors
    /// Returns native writeback failure or mapped/pinned-page conflict.
    pub(crate) fn close_cache_writeback(&self) -> DriverResult<()> {
        loop {
            match self.close_cache_attempt() {
                Ok(()) => return Ok(()),
                Err(error) => self.await_scan_conflict(error, PurgeFailurePolicy::WaitForScans)?,
            }
        }
    }

    /// Releases every native resource before a mapped-section conflict may wait for scan release.
    /// # Errors
    /// Returns the exact native writeback or purge status.
    fn close_cache_attempt(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The owning stream lease retains this shared native section set.
                ext4win_stream_cache_close_writeback(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Flushes and purges cached data before a coherent direct mutation or size change.
    /// # Errors
    ///
    /// Returns the exact Cache Manager coherency status.
    pub(crate) fn coherency_flush_and_purge(&self, policy: PurgeFailurePolicy) -> DriverResult<()> {
        loop {
            match self.coherency_attempt() {
                Ok(()) => return Ok(()),
                Err(error) => self.await_scan_conflict(error, policy)?,
            }
        }
    }

    /// Performs one coherency attempt, releasing every native resource before returning.
    /// # Errors
    /// Returns the exact Cc/MM failure or the internal plan-revalidation status.
    fn coherency_attempt(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live shared section-object set for this call.
                ext4win_stream_cache_coherency_flush_and_purge(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Flushes cached data and rejects any live data or image section before volume lock.
    /// # Errors
    ///
    /// Returns the exact Cache Manager exception or mapped-section conflict status.
    pub(crate) fn drain_cache_for_volume_lock(&self) -> DriverResult<()> {
        loop {
            match self.drain_cache_attempt() {
                Ok(()) => return Ok(()),
                Err(error) => self.await_scan_conflict(error, PurgeFailurePolicy::WaitForScans)?,
            }
        }
    }

    /// Drains one retained native section set without retaining resources after failure.
    /// # Errors
    /// Returns the exact native flush or mapping conflict.
    fn drain_cache_attempt(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live shared section-object set for this call.
                ext4win_stream_cache_drain_for_volume_lock(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Acquires one operation-specific, uniquely owned section gate through committed publication.
    /// # Errors
    /// Returns invalid execution context, storage removal, mapped/image conflict or the exact Cc/MM failure.
    pub(crate) fn prepare_section_mutation(
        &self,
        operation: SectionMutationOperation,
        policy: PurgeFailurePolicy,
    ) -> DriverResult<SealedSectionMutation> {
        if self.is_paging_file() {
            let (deletion, target) = match operation {
                SectionMutationOperation::Resize(sizes)
                | SectionMutationOperation::Reset(sizes) => (false, sizes.file_size()),
                SectionMutationOperation::Delete => (true, 0),
                _ => return Err(DriverError::NotSupported),
            };
            #[cfg(not(test))]
            if unsafe {
                // SAFETY: The retained stream serializes its setup/retirement admission.
                ext4win_stream_paging_mutation_allowed(
                    self.header.as_ptr(),
                    u8::from(deletion),
                    target,
                )
            } == 0
            {
                return Err(DriverError::NotSupported);
            }
            #[cfg(test)]
            {
                let _projection = (deletion, target);
            }
        }
        loop {
            match self.prepare_section_attempt(operation) {
                Ok(prepared) => return Ok(prepared),
                Err(error) => self.await_scan_conflict(error, policy)?,
            }
        }
    }

    /// Claims one section preparation and releases it on any failed attempt, before scan waiting.
    /// # Errors
    /// Returns execution-context, resource admission, storage, mapped-view or Cc/MM failures.
    fn prepare_section_attempt(
        &self,
        operation: SectionMutationOperation,
    ) -> DriverResult<SealedSectionMutation> {
        self.trace.record(
            OperationalPath::MappedSection,
            wdk_sys::STATUS_SUCCESS,
            OperationalOutcome::Selected,
        );
        let result = (|| {
            #[cfg(not(test))]
            if unsafe {
                // SAFETY: The current thread's scalar IRQL is observed before any blocking preparation.
                wdk_sys::ntddk::KeGetCurrentIrql()
            } != 0
            {
                return Err(DriverError::CacheManagerFailure(
                    wdk_sys::STATUS_INVALID_DEVICE_STATE,
                ));
            }
            let preparation = SectionSynchronization::begin(&self.sections)?;
            #[cfg(not(test))]
            {
                let main = self.main_resource()?.exclusive();
                self.ensure_storage()?;
                match operation {
                    SectionMutationOperation::Resize(sizes)
                    | SectionMutationOperation::Reset(sizes) => {
                        let reset = matches!(operation, SectionMutationOperation::Reset(_));
                        if reset && !self.flush_image(wdk_sys::_MMFLUSH_TYPE::MmFlushForWrite)? {
                            return Err(DriverError::ShareAccessConflict);
                        }
                        if reset || sizes.file_size() < self.sizes()?.file_size() {
                            let mut allowed = 0;
                            let status = unsafe {
                                // SAFETY: MainResource and the owning stream retain section storage through SEH.
                                ext4win_mm_check_truncation(
                                    self.header.as_ptr(),
                                    sizes.file_size(),
                                    &mut allowed,
                                )
                            };
                            cache_status(status)?;
                            if allowed == 0 {
                                return Err(DriverError::CacheManagerFailure(
                                    wdk_sys::STATUS_USER_MAPPED_FILE,
                                ));
                            }
                        }
                        self.purge_preparing_sections(DriverError::CacheManagerFailure(
                            wdk_sys::STATUS_USER_MAPPED_FILE,
                        ))?;
                    }
                    SectionMutationOperation::Delete => {
                        let status = unsafe {
                            // SAFETY: MainResource excludes new mappings; preparation admits paging
                            // while the retained native section set is checked and invalidated.
                            ext4win_stream_prepare_deletion(self.header.as_ptr())
                        };
                        if status == wdk_sys::STATUS_CANNOT_DELETE {
                            return Err(DriverError::CannotDelete);
                        }
                        cache_status(status)?;
                    }
                    SectionMutationOperation::WriteOpen => {
                        if !self.flush_image(wdk_sys::_MMFLUSH_TYPE::MmFlushForWrite)? {
                            return Err(DriverError::ShareAccessConflict);
                        }
                    }
                    SectionMutationOperation::EnableVerity | SectionMutationOperation::Relocate => {
                        let status = unsafe {
                            // SAFETY: MainResource excludes mappings/transfers; preparation permits paging reentry.
                            ext4win_stream_prepare_frozen_data(self.header.as_ptr())
                        };
                        cache_status(status)?;
                    }
                }
                let paging = self.paging_resource()?.exclusive();
                let sealed = preparation.seal();
                // Publish exclusion before releasing either resource. Every Cc flush and
                // modified-page writer has drained through PagingIoResource at this point.
                drop(paging);
                drop(main);
                sealed
            }
            #[cfg(test)]
            {
                // Host stream publication uses the same unique admission/release state. Native
                // section observations and Cc/MM rejection require the signed live-volume gate.
                match operation {
                    SectionMutationOperation::Resize(sizes)
                    | SectionMutationOperation::Reset(sizes) => {
                        let _validated = sizes;
                    }
                    SectionMutationOperation::Delete
                    | SectionMutationOperation::WriteOpen
                    | SectionMutationOperation::Relocate
                    | SectionMutationOperation::EnableVerity => {}
                }
                preparation.seal()
            }
        })();
        self.trace
            .record_result(OperationalPath::MappedSection, &result);
        result
    }

    /// Borrows the exact native main resource from this retained opaque header.
    /// # Errors
    /// Returns an invariant violation for a malformed stream.
    #[cfg(not(test))]
    fn main_resource(&self) -> DriverResult<SectionResource<'_>> {
        let pointer = unsafe {
            // SAFETY: The owning stream borrow retains native resource storage.
            ext4win_stream_main_resource(self.header.as_ptr())
        };
        unsafe {
            // SAFETY: The resource borrow cannot outlive this stream borrow.
            SectionResource::from_raw(pointer)
        }
    }

    /// Borrows paging exclusion while draining callbacks before sealing mutation admission.
    /// # Errors
    /// Returns an invariant violation for a malformed stream.
    #[cfg(not(test))]
    fn paging_resource(&self) -> DriverResult<SectionResource<'_>> {
        let pointer = unsafe {
            // SAFETY: This stream borrow retains the native paging resource.
            ext4win_stream_paging_resource(self.header.as_ptr())
        };
        unsafe {
            // SAFETY: Resource storage remains live through the returned stream-bound borrow.
            SectionResource::from_raw(pointer)
        }
    }

    /// Revalidates lower storage under operation resource ownership.
    /// # Errors
    /// Returns removal or a missing bound volume invariant.
    #[cfg(not(test))]
    fn ensure_storage(&self) -> DriverResult<()> {
        let state = NonNull::new(unsafe {
            // SAFETY: Bound node/volume lifetime retains the sole volume admission allocation.
            ext4win_stream_storage_admission(self.header.as_ptr())
                .cast::<StorageAdmission>()
                .cast_mut()
        })
        .ok_or(DriverError::InternalInvariantViolation)?;
        let state = unsafe {
            // SAFETY: The enclosing stream outlives every borrowed volume observation.
            state.as_ref()
        };
        if state.media() == MediaState::Present {
            Ok(())
        } else {
            Err(DriverError::DeviceRemoved)
        }
    }

    /// Copies native residency observations only while MainResource is retained.
    #[cfg(not(test))]
    fn section_residency(&self) -> u32 {
        unsafe {
            // SAFETY: Preparation holds MainResource and retains all native section storage.
            ext4win_stream_section_residency(self.header.as_ptr())
        }
    }

    /// Executes only the chosen native image-flush primitive under MainResource.
    /// # Errors
    /// Returns the native exception status before the operation is sealed.
    #[cfg(not(test))]
    fn flush_image(&self, operation: wdk_sys::MMFLUSH_TYPE) -> DriverResult<bool> {
        let mut flushed = 0;
        let status = unsafe {
            // SAFETY: Preparation retains the stream and MainResource through the C SEH boundary.
            ext4win_mm_flush_image(self.header.as_ptr(), operation, &mut flushed)
        };
        cache_status(status)?;
        Ok(flushed != 0)
    }

    /// Applies operation-specific rejection to Cc's exact purge result.
    /// # Errors
    /// Returns the selected mapped-page conflict or the native failure status.
    #[cfg(not(test))]
    fn purge_preparing_sections(&self, conflict: DriverError) -> DriverResult<()> {
        if self.section_residency() & 3 == 0 {
            return Ok(());
        }
        let status = unsafe {
            // SAFETY: Preparation retains MainResource and permits paging reentry through this SEH call.
            ext4win_cc_purge_sections(self.header.as_ptr())
        };
        if status == wdk_sys::STATUS_CACHE_PAGE_LOCKED {
            Err(conflict)
        } else {
            cache_status(status)
        }
    }

    /// Releases this FILE_OBJECT's private cache map without destroying shared stream sections.
    /// # Errors
    ///
    /// Returns the exact Cache Manager exception status.
    pub(crate) fn uninitialize_cache_map(
        &self,
        _file_object: crate::irp::ActiveFileObject<'_>,
    ) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The active IRP borrow retains FILE_OBJECT and self retains the stream
                // throughout this synchronous native call.
                ext4win_stream_cache_uninitialize(self.header.as_ptr(), _file_object.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        Ok(())
    }

    /// Rules out native residency only after a nonblocking section observation.
    ///
    /// A Cc/MM owner may be waiting for this reactor's paging completion. Resource contention
    /// therefore retains the stream conservatively for a later delayed-close observation.
    /// # Errors
    ///
    /// Returns an invariant error if the native stream header is malformed.
    pub(crate) fn may_have_native_residency(&self) -> DriverResult<bool> {
        #[cfg(not(test))]
        {
            let mut resident = 0_u8;
            let status = unsafe {
                // SAFETY: `self` owns the live native header and the output is one BOOLEAN.
                ext4win_stream_may_have_native_residency(
                    self.header.as_ptr(),
                    core::ptr::addr_of_mut!(resident),
                )
            };
            native_status(status)?;
            Ok(resident != 0)
        }
        #[cfg(test)]
        {
            let sections = self.section_objects()?;
            let sections = unsafe {
                // SAFETY: The test stream owns this stable SECTION_OBJECT_POINTERS allocation.
                sections.as_ref()
            };
            Ok(!sections.DataSectionObject.is_null()
                || !sections.SharedCacheMap.is_null()
                || !sections.ImageSectionObject.is_null())
        }
    }

    /// Decodes the section-object set embedded beside one validated advanced header.
    /// # Errors
    ///
    /// Returns an invariant error when a retained header has invalid native metadata.
    /// # Safety
    ///
    /// `header` must come from a live `StreamContext`. Its owner or FILE_OBJECT/stream lease must
    /// retain the allocation for this call and for every use of the returned pointer.
    pub(crate) unsafe fn decode_section_objects(
        header: NonNull<c_void>,
    ) -> DriverResult<NonNull<wdk_sys::SECTION_OBJECT_POINTERS>> {
        #[cfg(not(test))]
        {
            let mut sections = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: The retaining FILE_OBJECT or owner keeps the native header allocation live.
                ext4win_stream_section_objects(header.as_ptr(), &mut sections)
            };
            native_status(status)?;
            NonNull::new(sections).ok_or(DriverError::InternalInvariantViolation)
        }
        #[cfg(test)]
        {
            let stream = header.cast::<Self>();
            let stream = unsafe {
                // SAFETY: Test fixtures publish only pointers returned by `Self::header`.
                stream.as_ref()
            };
            NonNull::new(stream.section_objects.get())
                .ok_or(DriverError::InternalInvariantViolation)
        }
    }

    /// Decodes the Rust owner selected by one advanced header.
    /// # Errors
    ///
    /// Returns an invariant error for an absent, wrong-kind, unbound, or malformed header.
    /// # Safety
    ///
    /// `header` must come from a live `StreamContext`. The corresponding FILE_OBJECT/stream
    /// lease must retain both that context and its bound owner while the returned pointer is used.
    pub(crate) unsafe fn decode_owner(
        header: NonNull<c_void>,
        expected_kind: StreamOwnerKind,
    ) -> DriverResult<NonNull<c_void>> {
        #[cfg(not(test))]
        {
            let mut owner = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: The active FILE_OBJECT retains the filesystem-owned header allocation.
                ext4win_stream_decode_owner(
                    header.as_ptr(),
                    expected_kind.native_tag(),
                    core::ptr::addr_of_mut!(owner),
                )
            };
            native_status(status)?;
            NonNull::new(owner).ok_or(DriverError::InternalInvariantViolation)
        }
        #[cfg(test)]
        {
            let stream = header.cast::<Self>();
            let stream = unsafe {
                // SAFETY: Test FILE_OBJECT fixtures only receive a pointer from `Self::header`.
                stream.as_ref()
            };
            if stream.runtime.kind() != expected_kind {
                return Err(DriverError::InternalInvariantViolation);
            }
            NonNull::new(stream.owner.load(Ordering::Acquire))
                .ok_or(DriverError::InternalInvariantViolation)
        }
    }
}

/// Returns the single nonpaged Fast I/O dispatch table owned by the native driver image.
/// # Errors
///
/// Returns an invariant error if the native image does not expose its static dispatch table.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the native image-lifetime dispatch table crosses one audited pointer ABI boundary"
)]
pub(crate) fn fast_io_dispatch(
    driver: &mut wdk_sys::DRIVER_OBJECT,
) -> DriverResult<NonNull<wdk_sys::FAST_IO_DISPATCH>> {
    let status = unsafe {
        // SAFETY: DriverEntry exclusively owns this live driver before publishing any device.
        ext4win_register_section_callbacks(core::ptr::from_mut(driver))
    };
    if status < STATUS_SUCCESS {
        return Err(DriverError::CacheManagerFailure(status));
    }
    let pointer = unsafe {
        // SAFETY: Native code returns the address of one image-lifetime static dispatch table.
        ext4win_fast_io_dispatch()
    };
    NonNull::new(pointer).ok_or(DriverError::InternalInvariantViolation)
}

#[expect(
    unsafe_code,
    reason = "the opaque native header uses internally synchronized resources and immutable owner identity after publication"
)]
// SAFETY: Native FsRtl/ERESOURCE/OPLOCK state supplies its own synchronization. Rust only reads the
// immutable kind/header identity after the single construction-time owner binding. Runtime
// storage keeps its original allocation pointer across owner moves and outlives native destruction.
unsafe impl Send for StreamContext {}

#[expect(
    unsafe_code,
    reason = "the opaque native header uses internally synchronized resources and immutable owner identity after publication"
)]
// SAFETY: See the `Send` rationale; mutation is confined to native synchronization protocols.
unsafe impl Sync for StreamContext {}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "unique ownership permits terminal native stream destruction after all leases drain"
)]
impl Drop for StreamContext {
    fn drop(&mut self) {
        if !self.sections.get().idle() {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
        let status = unsafe {
            // SAFETY: Drop has unique ownership after every FILE_OBJECT and stream lease drained.
            ext4win_stream_destroy(self.header.as_ptr())
        };
        if status != STATUS_SUCCESS {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
    }
}

/// Interprets the cleanup postcondition, which does not require any lock to have existed.
/// # Errors
///
/// Preserves rejection of malformed native ownership. This interpretation belongs only to cleanup;
/// explicit unlock requests still expose their original native status to their caller.
fn cleanup_unlock_status(status: NTSTATUS) -> DriverResult<()> {
    match status {
        wdk_sys::STATUS_SUCCESS | wdk_sys::STATUS_RANGE_NOT_LOCKED => Ok(()),
        _ => Err(DriverError::InternalInvariantViolation),
    }
}

#[cfg(not(test))]
/// Maps this boundary's construction failure or malformed ownership to driver errors.
/// # Errors
///
/// Returns insufficient-resources for pool exhaustion; other native rejection means a broken
/// internal stream contract, not a caller-supplied filesystem request failure.
fn native_status(status: NTSTATUS) -> DriverResult<()> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else if status == STATUS_INSUFFICIENT_RESOURCES {
        Err(DriverError::InsufficientResources)
    } else {
        Err(DriverError::InternalInvariantViolation)
    }
}

#[cfg(not(test))]
/// Preserves one Cache Manager or Memory Manager status for the IRP completion boundary.
/// # Errors
///
/// Returns the exact non-success native status without reclassifying it.
fn cache_status(status: NTSTATUS) -> DriverResult<()> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(DriverError::CacheManagerFailure(status))
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "these declarations expose the audited native advanced-FCB-header ownership boundary"
)]
unsafe extern "system" {
    fn ext4win_stream_is_paging_file(header: *mut c_void) -> u8;
    fn ext4win_stream_reserve_paging_file(
        header: *mut c_void,
        file: wdk_sys::PFILE_OBJECT,
        extension: u8,
        physical: *mut i64,
        length: *mut i64,
    ) -> NTSTATUS;
    fn ext4win_stream_abort_paging_file(header: *mut c_void, extension: u8);
    fn ext4win_stream_activate_paging_file(
        header: *mut c_void,
        extension: u8,
        lower: wdk_sys::PDEVICE_OBJECT,
        physical: i64,
        length: i64,
        sector_size: u32,
    ) -> NTSTATUS;
    fn ext4win_stream_paging_mutation_allowed(header: *mut c_void, deletion: u8, target: i64)
    -> u8;
    fn ext4win_stream_paging_length(header: *mut c_void) -> i64;
    fn ext4win_stream_prepare_frozen_data(stream_header: *mut c_void) -> NTSTATUS;
    fn ext4win_stream_data_writable(stream_header: *mut c_void) -> u8;
    fn ext4win_prepare_mdl_completion(
        queue: *const c_void,
        file: wdk_sys::PFILE_OBJECT,
    ) -> NTSTATUS;
    fn ext4win_cc_read_mdl(
        file: wdk_sys::PFILE_OBJECT,
        offset: i64,
        length: u32,
        chain: *mut wdk_sys::PMDL,
        information: *mut usize,
    ) -> NTSTATUS;
    fn ext4win_cc_prepare_mdl_write(
        file: wdk_sys::PFILE_OBJECT,
        offset: i64,
        length: u32,
        chain: *mut wdk_sys::PMDL,
        information: *mut usize,
    ) -> NTSTATUS;
    fn ext4win_stream_cache_initialize(
        header: *mut c_void,
        file: wdk_sys::PFILE_OBJECT,
    ) -> NTSTATUS;
    fn ext4win_stream_create(
        kind: wdk_sys::ULONG,
        allocation_size: i64,
        file_size: i64,
        valid_data_length: i64,
        allocation_charge: i64,
        metadata: *const StreamMetadata,
        trace_registration_handle: u64,
        runtime: *mut c_void,
        section_state: *const c_void,
        stream_header_out: *mut wdk_sys::PVOID,
    ) -> NTSTATUS;

    fn ext4win_stream_bind_node_owner(
        stream_header: wdk_sys::PVOID,
        owner: wdk_sys::PVOID,
        byte_range_locks: *mut wdk_sys::FILE_LOCK,
        volume_header: wdk_sys::PVOID,
    ) -> NTSTATUS;
    fn ext4win_stream_bind_volume_owner(
        stream_header: wdk_sys::PVOID,
        owner: wdk_sys::PVOID,
        control_device: wdk_sys::PDEVICE_OBJECT,
    ) -> NTSTATUS;
    fn ext4win_stream_cache_close_writeback(stream_header: *mut c_void) -> NTSTATUS;
    fn ext4win_stream_acquire_submissions(volume_header: *mut c_void, exclusive: u8) -> u8;
    fn ext4win_stream_release_submissions(volume_header: *mut c_void);
    fn ext4win_stream_volume_control_device(
        stream_header: wdk_sys::PVOID,
    ) -> wdk_sys::PDEVICE_OBJECT;

    fn ext4win_stream_oplock_fsctrl(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
        open_count: wdk_sys::ULONG,
        flags: wdk_sys::ULONG,
    ) -> NTSTATUS;
    fn ext4win_stream_cleanup_oplock(
        stream_header: *mut c_void,
        irp: wdk_sys::PIRP,
        flags: u32,
    ) -> NTSTATUS;
    fn ext4win_stream_check_oplock(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
        flags: wdk_sys::ULONG,
        continuation: wdk_sys::PVOID,
        admitted: *mut u8,
    ) -> NTSTATUS;
    fn ext4win_stream_backout_atomic_oplock(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
    ) -> NTSTATUS;
    fn ext4win_stream_process_file_lock(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
        completion: wdk_sys::PVOID,
    ) -> NTSTATUS;
    fn ext4win_stream_unlock_all(
        stream_header: wdk_sys::PVOID,
        file_object: *mut wdk_sys::FILE_OBJECT,
        process: *mut c_void,
    ) -> NTSTATUS;

    fn ext4win_stream_decode_owner(
        stream_header: wdk_sys::PVOID,
        expected_kind: wdk_sys::ULONG,
        owner_out: *mut wdk_sys::PVOID,
    ) -> NTSTATUS;

    fn ext4win_stream_section_objects(
        stream_header: wdk_sys::PVOID,
        section_objects_out: *mut *mut wdk_sys::SECTION_OBJECT_POINTERS,
    ) -> NTSTATUS;

    fn ext4win_stream_get_sizes(
        stream_header: wdk_sys::PVOID,
        allocation_size_out: *mut i64,
        file_size_out: *mut i64,
        valid_data_length_out: *mut i64,
        allocation_charge_out: *mut i64,
    ) -> NTSTATUS;

    /// Observes the committed archive attribute under the native header mutex.
    fn ext4win_stream_archive_is_set(header: *mut c_void) -> u8;

    fn ext4win_stream_publish_metadata(
        stream_header: wdk_sys::PVOID,
        allocation_size: i64,
        file_size: i64,
        valid_data_length: i64,
        allocation_charge: i64,
        metadata: *const StreamMetadata,
        cache_status_out: *mut NTSTATUS,
    ) -> NTSTATUS;

    fn ext4win_stream_set_namespace_query_fallback(
        stream_header: wdk_sys::PVOID,
        pending: wdk_sys::BOOLEAN,
    ) -> NTSTATUS;

    fn ext4win_cc_copy_read(
        file: wdk_sys::PFILE_OBJECT,
        offset: i64,
        length: u32,
        buffer: *mut c_void,
        information: *mut usize,
    ) -> NTSTATUS;
    fn ext4win_cc_copy_write(
        file: wdk_sys::PFILE_OBJECT,
        offset: i64,
        length: u32,
        buffer: *mut c_void,
    ) -> NTSTATUS;
    fn ext4win_stream_cache_flush(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_cache_coherency_flush_and_purge(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_cache_drain_for_volume_lock(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_main_resource(header: *mut c_void) -> *mut wdk_sys::ERESOURCE;
    fn ext4win_stream_paging_resource(header: *mut c_void) -> *mut wdk_sys::ERESOURCE;
    fn ext4win_stream_storage_admission(header: *mut c_void) -> *const c_void;
    fn ext4win_stream_section_residency(header: *mut c_void) -> u32;
    fn ext4win_mm_check_truncation(header: *mut c_void, size: i64, allowed: *mut u8) -> NTSTATUS;
    fn ext4win_mm_flush_image(
        header: *mut c_void,
        operation: wdk_sys::MMFLUSH_TYPE,
        flushed: *mut u8,
    ) -> NTSTATUS;
    fn ext4win_stream_prepare_deletion(header: *mut c_void) -> NTSTATUS;
    fn ext4win_cc_purge_sections(header: *mut c_void) -> NTSTATUS;

    fn ext4win_stream_cache_uninitialize(
        stream_header: wdk_sys::PVOID,
        file_object: *mut wdk_sys::FILE_OBJECT,
    ) -> NTSTATUS;

    fn ext4win_stream_may_have_native_residency(
        stream_header: wdk_sys::PVOID,
        resident_out: *mut wdk_sys::BOOLEAN,
    ) -> NTSTATUS;

    fn ext4win_stream_destroy(stream_header: wdk_sys::PVOID) -> NTSTATUS;
    fn ext4win_register_section_callbacks(driver: wdk_sys::PDRIVER_OBJECT) -> NTSTATUS;
    fn ext4win_fast_io_dispatch() -> *mut wdk_sys::FAST_IO_DISPATCH;
}

#[cfg(test)]
mod tests {
    /// # Errors
    /// Returns allocation or scan-lifetime failure.
    /// # Panics
    /// Fails if scan retry status escapes its Windows request class or masks an I/O failure.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible stream setup precedes status assertions"
    )]
    fn scan_conflicts_follow_the_windows_request_policy() -> DriverResult<()> {
        use super::{PurgeFailurePolicy, ScanSectionChange};
        let stream =
            StreamContext::try_new_staged_node(StreamSizes::EMPTY, OperationalTrace::host_test())?;
        let conflict = DriverError::CacheManagerFailure(wdk_sys::STATUS_USER_MAPPED_FILE);
        assert_eq!(
            stream.await_scan_conflict(conflict, PurgeFailurePolicy::FilterRetry),
            Err(conflict)
        );
        stream.change_scan_section(ScanSectionChange::Enable)?;
        assert_eq!(
            stream.await_scan_conflict(conflict, PurgeFailurePolicy::FilterRetry),
            Err(DriverError::CacheManagerFailure(
                wdk_sys::STATUS_PURGE_FAILED
            ))
        );
        assert_eq!(
            stream.await_scan_conflict(
                DriverError::CannotDelete,
                PurgeFailurePolicy::DestructiveCreate
            ),
            Err(conflict)
        );
        let io_failure = DriverError::CacheManagerFailure(wdk_sys::STATUS_IO_DEVICE_ERROR);
        assert_eq!(
            stream.await_scan_conflict(io_failure, PurgeFailurePolicy::WaitForScans),
            Err(io_failure)
        );
        stream.change_scan_section(ScanSectionChange::Disable)?;
        Ok(())
    }
    /// # Errors
    /// Returns stream allocation or reference-budget failure.
    /// # Panics
    /// Fails if key-removal exclusion is reusable, omitted or restores terminal media on release.
    #[test]
    #[expect(
        unsafe_code,
        reason = "local stream allocation remains live through every admission lease"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture errors propagate while assertions check exclusion lifetime"
    )]
    fn key_removal_exclusion_lasts_until_lease_release() -> DriverResult<()> {
        let owner = crate::kernel::io_reliability::IoReliabilityOwner::try_new()?;
        let volume = StreamContext::try_new_volume(
            StreamSizes::EMPTY,
            OperationalTrace::host_test(),
            owner.observe()?,
        )?;
        let storage = unsafe {
            // SAFETY: The local volume remains unmoved and alive until its last lease is released.
            volume.storage_access()
        }?;
        let lease = storage.begin_key_removal()?;
        assert!(!storage.state().creates_admitted());
        assert_eq!(
            storage.begin_key_removal().err(),
            Some(DriverError::DeviceBusy)
        );
        storage.state().cancel_query();
        assert!(!storage.state().creates_admitted());
        drop(lease);
        assert!(storage.state().creates_admitted());
        let lease = storage.begin_key_removal()?;
        storage.state().remove(super::MediaState::Removed);
        drop(lease);
        assert_eq!(storage.authorize_create(), Err(DriverError::DeviceRemoved));
        Ok(())
    }
    use ext4_core::{ClusterSize, FileAllocationSize, FileSize};

    use super::{OperationalTrace, Ordering, StreamContext, StreamMetadata, StreamSizes};
    use crate::kernel::status::{DriverError, DriverResult};

    /// # Errors
    /// Returns fixture allocation or unexpected close admission failure.
    /// # Panics
    /// Panics if sealing permits paging or also revokes the closing owner's lower I/O.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the local volume fixture retains its atomic admission identities"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup precedes semantic admission assertions"
    )]
    fn close_admission_drains_paging_before_sealing() -> DriverResult<()> {
        let volume = StreamContext::try_new_volume(
            StreamSizes::EMPTY,
            OperationalTrace::host_test(),
            crate::kernel::io_reliability::IoReliabilityOwner::try_new()?.observe()?,
        )?;
        let storage = unsafe {
            // SAFETY: This fixture remains live and unmoved until all captured access ends.
            volume.storage_access()
        }?;
        storage.begin_close_writeback()?;
        assert_eq!(storage.authorize_create(), Err(DriverError::AccessDenied));
        assert_eq!(storage.authorize_paging(), Ok(()));
        storage.seal_close_writeback();
        assert_eq!(
            storage.authorize_paging(),
            Err(DriverError::VolumeDismounted)
        );
        assert_eq!(storage.authorize(), Ok(()));
        assert_eq!(
            storage.begin_close_writeback(),
            Err(DriverError::VolumeDismounted)
        );
        Ok(())
    }

    /// # Errors
    /// Returns stream allocation or query preparation failure.
    /// # Panics
    /// Panics if reversible query closure blocks existing I/O, loses rollback, or undoes removal.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this local volume fixture stays live and unmoved through every captured capability"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture construction and assertions verify distinct PnP transitions"
    )]
    fn query_removal_closes_creates_and_cancellation_preserves_terminal_removal() -> DriverResult<()>
    {
        let volume = StreamContext::try_new_volume(
            StreamSizes::EMPTY,
            OperationalTrace::host_test(),
            crate::kernel::io_reliability::IoReliabilityOwner::try_new()?.observe()?,
        )?;
        let storage = unsafe {
            // SAFETY: The fixture stays at this address until all capabilities are consumed.
            volume.storage_access()
        }?;
        let publisher = unsafe {
            // SAFETY: The fixture owns PnP publication and retains its volume throughout the test.
            volume.storage_removal_publisher()
        }?;
        let mut lower_device = wdk_sys::DEVICE_OBJECT::default();
        let lower = unsafe {
            // SAFETY: This local device remains live through every host lower-reply observation.
            crate::state::KernelDevice::from_raw(core::ptr::from_mut(&mut lower_device))
        }
        .ok_or(DriverError::InvalidParameter)?;
        let mut lower_reply = wdk_sys::IRP::default();
        let reply = core::ptr::NonNull::from(&mut lower_reply);
        let status = unsafe {
            // SAFETY: The local unqueued reply and native gate remain retained for this call.
            publisher.cancel_remove(lower, reply)
        };
        assert_eq!(status, wdk_sys::STATUS_SUCCESS);
        assert_eq!(storage.authorize_create(), Ok(()));
        let preparation = unsafe {
            // SAFETY: The local volume outlives this unique preparation.
            volume.prepare_query_removal()
        }?;
        assert_eq!(storage.authorize_create(), Err(DriverError::AccessDenied));
        assert_eq!(storage.authorize(), Ok(()));
        drop(storage.acquire_submission()?);
        let status = unsafe {
            // SAFETY: The fixture owns the unqueued reply and retains the volume query gate.
            publisher.cancel_remove(lower, reply)
        };
        assert_eq!(status, wdk_sys::STATUS_SUCCESS);
        assert_eq!(storage.authorize_create(), Err(DriverError::AccessDenied));
        drop(preparation);
        assert_eq!(storage.authorize_create(), Ok(()));
        let preparation = unsafe {
            // SAFETY: The local volume retains this second preparation through publication.
            volume.prepare_query_removal()
        }?;
        preparation.publish()?;
        assert_eq!(storage.authorize_create(), Err(DriverError::AccessDenied));
        let status = unsafe {
            // SAFETY: The host reply is complete and retained through cancellation publication.
            publisher.cancel_remove(lower, reply)
        };
        assert_eq!(status, wdk_sys::STATUS_SUCCESS);
        assert_eq!(storage.authorize_create(), Ok(()));
        let preparation = unsafe {
            // SAFETY: The fixture retains the unpublished preparation across terminal revocation.
            volume.prepare_query_removal()
        }?;
        publisher.publish(super::StorageRemovalNotification::Surprise);
        assert_eq!(preparation.publish(), Err(DriverError::DeviceRemoved));
        let status = unsafe {
            // SAFETY: Both the completed reply and terminally revoked volume remain retained.
            publisher.cancel_remove(lower, reply)
        };
        assert_eq!(status, wdk_sys::STATUS_SUCCESS);
        assert_eq!(storage.authorize_create(), Err(DriverError::DeviceRemoved));
        assert_eq!(storage.authorize(), Err(DriverError::DeviceRemoved));
        Ok(())
    }

    /// # Errors
    /// Returns stream allocation failure.
    /// # Panics
    /// Panics if terminal storage removal restores I/O or permits premature final retirement.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the local volume stream remains live and unmoved for every capability use"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture construction is fallible; assertions verify removal semantics"
    )]
    fn storage_removal_is_terminal_and_distinguishes_final_remove() -> DriverResult<()> {
        let volume = StreamContext::try_new_volume(
            StreamSizes::EMPTY,
            OperationalTrace::host_test(),
            crate::kernel::io_reliability::IoReliabilityOwner::try_new()?.observe()?,
        )?;
        let storage = unsafe {
            // SAFETY: The volume remains live at this stack location until all accesses end.
            volume.storage_access()
        }?;
        let publisher = unsafe {
            // SAFETY: The fixture is the sole removal owner and retains its local volume.
            volume.storage_removal_publisher()
        }?;
        assert_eq!(storage.authorize(), Ok(()));
        drop(storage.acquire_submission()?);
        publisher.publish(super::StorageRemovalNotification::Surprise);
        assert_eq!(storage.authorize(), Err(DriverError::DeviceRemoved));
        assert_eq!(
            storage.acquire_submission().err(),
            Some(DriverError::DeviceRemoved)
        );
        assert!(!storage.final_removal_received());
        publisher.publish(super::StorageRemovalNotification::Final);
        publisher.publish(super::StorageRemovalNotification::Surprise);
        assert!(storage.final_removal_received());
        assert_eq!(storage.authorize(), Err(DriverError::DeviceRemoved));
        assert_eq!(
            DriverError::DeviceRemoved.ntstatus(),
            wdk_sys::STATUS_DEVICE_REMOVED
        );
        Ok(())
    }

    /// # Panics
    ///
    /// Panics if a lock-free cleanup is treated as ownership corruption or an actual native
    /// rejection is silently accepted.
    #[test]
    fn cleanup_accepts_absent_locks_but_rejects_native_ownership_errors() {
        assert_eq!(
            super::cleanup_unlock_status(wdk_sys::STATUS_SUCCESS),
            Ok(())
        );
        assert_eq!(
            super::cleanup_unlock_status(wdk_sys::STATUS_RANGE_NOT_LOCKED),
            Ok(())
        );
        for status in [wdk_sys::STATUS_INVALID_PARAMETER, wdk_sys::STATUS_PENDING] {
            assert_eq!(
                super::cleanup_unlock_status(status),
                Err(DriverError::InternalInvariantViolation)
            );
        }
    }

    /// # Errors
    ///
    /// Returns a size-domain error if fixture construction fails.
    /// # Panics
    ///
    /// Panics if a sparse stream loses its distinct allocation charge or VDL invariant.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check the size contract"
    )]
    fn sparse_eof_still_defines_the_section_bound() -> DriverResult<()> {
        let sizes = StreamSizes::try_from_ext4(
            FileSize::from_bytes(9_000),
            FileAllocationSize::from_bytes(4_096),
            ClusterSize::new(4_096)?,
        )?;

        assert_eq!(sizes.file_size(), 9_000);
        assert_eq!(sizes.allocation_size, 12_288);
        assert_eq!(sizes.allocation_charge(), 4_096);
        assert_eq!(sizes.valid_data_length, sizes.file_size);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns a size-domain error if fixture construction fails.
    /// # Panics
    ///
    /// Panics if cluster rounding alters the physical allocation charge.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check the allocation contract"
    )]
    fn bigalloc_charge_and_section_rounding_remain_distinct() -> DriverResult<()> {
        let sizes = StreamSizes::try_from_ext4(
            FileSize::from_bytes(1_000),
            FileAllocationSize::from_bytes(69_632),
            ClusterSize::new(65_536)?,
        )?;

        assert_eq!(sizes.file_size(), 1_000);
        assert_eq!(sizes.allocation_size, 65_536);
        assert_eq!(sizes.allocation_charge(), 69_632);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns a size-domain error if fixture construction fails.
    /// # Panics
    ///
    /// Panics if cache-map dimensions include the query-only allocation charge or omit a native
    /// allocation-bound change.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check the cache-map size boundary"
    )]
    fn cache_dimensions_exclude_charge_but_include_section_bounds() -> DriverResult<()> {
        let cluster = ClusterSize::new(4_096)?;
        let baseline = StreamSizes::try_from_ext4(
            FileSize::from_bytes(4_096),
            FileAllocationSize::from_bytes(4_096),
            cluster,
        )?;
        let charge_only = StreamSizes::try_from_ext4(
            FileSize::from_bytes(4_096),
            FileAllocationSize::from_bytes(0),
            cluster,
        )?;
        let larger_charge = StreamSizes::try_from_ext4(
            FileSize::from_bytes(4_096),
            FileAllocationSize::from_bytes(8_192),
            cluster,
        )?;
        let larger_section = StreamSizes::try_from_ext4(
            FileSize::from_bytes(8_192),
            FileAllocationSize::from_bytes(8_192),
            cluster,
        )?;

        assert_ne!(baseline, charge_only);
        assert!(baseline.same_cache_dimensions(charge_only));
        assert!(baseline.same_cache_dimensions(larger_charge));
        assert!(!baseline.same_cache_dimensions(larger_section));
        Ok(())
    }

    /// # Errors
    ///
    /// Returns a stream-construction error.
    /// # Panics
    ///
    /// Panics if a staged stream accidentally exposes query metadata before commit publication.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check publication"
    )]
    fn staged_stream_withholds_fast_query_metadata() -> DriverResult<()> {
        let stream =
            StreamContext::try_new_staged_node(StreamSizes::EMPTY, OperationalTrace::host_test())?;
        assert_eq!(stream.sizes()?, StreamSizes::EMPTY);
        assert!(!stream.archive_is_set());
        assert!(
            stream
                .metadata
                .lock()
                .is_ok_and(|metadata| metadata.is_none())
        );
        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the Rust metadata input no longer matches the fixed native ABI.
    #[test]
    fn native_stream_metadata_layout_matches_c_boundary() {
        assert_eq!(core::mem::size_of::<StreamMetadata>(), 56);
        assert_eq!(core::mem::offset_of!(StreamMetadata, epoch), 0);
        assert_eq!(core::mem::offset_of!(StreamMetadata, creation), 8);
        assert_eq!(core::mem::offset_of!(StreamMetadata, directory), 48);
        assert_eq!(core::mem::offset_of!(StreamMetadata, writable_data), 52);
    }

    /// # Errors
    ///
    /// Returns a stream-construction or projection error.
    /// # Panics
    ///
    /// Panics if the production setter does not preserve the requested delete projection.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check the metadata query fallback gate"
    )]
    fn namespace_query_fallback_projection_tracks_each_requested_state() -> DriverResult<()> {
        let stream =
            StreamContext::try_new_staged_node(StreamSizes::EMPTY, OperationalTrace::host_test())?;
        assert!(!stream.namespace_query_fallback.load(Ordering::Acquire));
        stream.set_namespace_query_fallback(true)?;
        assert!(stream.namespace_query_fallback.load(Ordering::Acquire));
        stream.set_namespace_query_fallback(false)?;
        assert!(!stream.namespace_query_fallback.load(Ordering::Acquire));
        Ok(())
    }

    /// # Errors
    ///
    /// Returns a fixture-construction error.
    /// # Panics
    ///
    /// Panics if an unrepresentable size reaches the publication domain.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check overflow rejection"
    )]
    fn rejects_signed_size_and_rounding_overflow_before_publication() -> DriverResult<()> {
        let cluster = ClusterSize::new(4_096)?;
        for (eof, charge) in [(u64::MAX, 0), (i64::MAX.cast_unsigned(), 0), (0, u64::MAX)] {
            assert!(matches!(
                StreamSizes::try_from_ext4(
                    FileSize::from_bytes(eof),
                    FileAllocationSize::from_bytes(charge),
                    cluster,
                ),
                Err(DriverError::InvalidParameter)
            ));
        }
        assert_eq!(
            StreamSizes::try_from_ext4(
                FileSize::from_bytes(0),
                FileAllocationSize::from_bytes(0),
                cluster
            )?,
            StreamSizes::EMPTY
        );
        Ok(())
    }
}
