//! Native Windows stream-header ownership boundary.

use core::ffi::c_void;
use core::ptr::NonNull;

#[cfg(test)]
use core::cell::UnsafeCell;
#[cfg(test)]
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering};
use ext4_core::{
    ClusterSize, EpochSequence, FileAllocationSize, FileSize, NodeId, NodeMetadataSnapshot,
};
#[cfg(test)]
use std::sync::Mutex;

use wdk_sys::NTSTATUS;
#[cfg(not(test))]
use wdk_sys::{STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::operational_trace::OperationalTrace;
use crate::kernel::status::{DriverError, DriverResult};

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
    /// `AllocationSize` is the cluster-rounded section bound and therefore remains at least EOF
    /// even when the ext4 allocation charge is smaller because the inode contains holes.
    /// # Errors
    ///
    /// Returns an arithmetic error when a size cannot be rounded or represented by Windows.
    pub(crate) fn try_from_ext4(
        file_size: FileSize,
        allocation_charge: FileAllocationSize,
        cluster_size: ClusterSize,
    ) -> DriverResult<Self> {
        let allocation_size = round_up_allocation(
            core::cmp::max(file_size.bytes(), allocation_charge.bytes()),
            cluster_size,
        )?;
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
struct NativeStreamMetadata {
    /// Monotonic committed epoch that owns every remaining field.
    epoch: u64,
    /// Unix seconds converted to Windows time by the native boundary.
    creation_time_seconds: u32,
    /// Unix seconds converted to Windows time by the native boundary.
    last_access_time_seconds: u32,
    /// Unix seconds converted to Windows time by the native boundary.
    last_write_time_seconds: u32,
    /// Unix seconds converted to Windows time by the native boundary.
    change_time_seconds: u32,
    /// Complete Windows file-attribute projection.
    file_attributes: u32,
    /// Windows-visible namespace link count.
    number_of_links: u32,
    /// `1` for directories and `0` for file-like nodes.
    directory: u32,
}

impl NativeStreamMetadata {
    /// Builds one native projection from a coherent core snapshot and its committed epoch.
    fn from_snapshot(snapshot: NodeMetadataSnapshot, epoch: EpochSequence) -> Self {
        let times = snapshot.times();
        let directory = matches!(snapshot.node(), NodeId::Directory(_));
        Self {
            epoch: epoch.get(),
            creation_time_seconds: times.created().seconds(),
            last_access_time_seconds: times.accessed().seconds(),
            last_write_time_seconds: times.modified().seconds(),
            change_time_seconds: times.changed().seconds(),
            file_attributes: snapshot.windows_file_attributes(),
            number_of_links: if directory {
                1
            } else {
                u32::from(snapshot.links_count().get())
            },
            directory: u32::from(directory),
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
    /// Immutable ownership domain validated by the native boundary.
    kind: StreamOwnerKind,
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
    metadata: Mutex<Option<NativeStreamMetadata>>,
    /// Host equivalent of the ledger-derived native delete-pending projection.
    #[cfg(test)]
    delete_pending: AtomicBool,
    /// Host equivalent of the volume's monotonic native removal state.
    #[cfg(test)]
    storage_removal: AtomicU8,
    /// Host equivalent of the independent reversible PnP create gate.
    #[cfg(test)]
    query_removal: AtomicU8,
}

/// Terminal PnP observations carry different mounted-device retirement authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageRemovalNotification {
    /// Revoke storage while retaining the mounted device for the later final request.
    Surprise,
    /// Revoke storage and permit retirement after retained handles and callbacks drain.
    Final,
}

/// Volume-scoped storage admission. A dispatch lease, actor-owned VCB, or retained worker
/// rundown keeps the native volume stream alive through every use. Node streams consult this
/// same authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VolumeStorageAccess {
    /// Native volume header; host fixtures retain its atomic equivalent.
    address: NonNull<c_void>,
    /// Host query gate shares the retained volume lifetime with `address`.
    #[cfg(test)]
    query_address: NonNull<AtomicU8>,
}

/// PnP dispatch may revoke storage; observers and submission owners cannot publish removal.
#[derive(Debug)]
pub(crate) struct StorageRemovalPublisher {
    /// Native volume header retained by mounted-device dispatch rundown.
    address: NonNull<c_void>,
    /// Host query gate retained by mounted dispatch rundown.
    #[cfg(test)]
    query_address: NonNull<AtomicU8>,
}

/// One reversible create-admission closure owned by the sole query-remove operation.
/// Dropping preparation reopens creates; publication transfers that responsibility to PnP.
#[derive(Debug)]
pub(crate) struct QueryRemovalPreparation {
    /// Retained native storage identities; the mounted operation owns their lifetime.
    storage: VolumeStorageAccess,
}

impl QueryRemovalPreparation {
    /// Leaves creates closed until a successful lower cancel-remove or terminal removal.
    /// # Errors
    /// Returns device removed if storage was revoked before remove-pending publication.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the owning mounted operation retains the native volume through publication"
        )
    )]
    pub(crate) fn publish(self) -> DriverResult<()> {
        self.storage.authorize()?;
        #[cfg(not(test))]
        let published = unsafe {
            // SAFETY: The preparation owns the sole reversible native gate on this retained VCB.
            ext4win_stream_publish_query_remove(self.storage.address.as_ptr()) != 0
        };
        #[cfg(test)]
        let published = self
            .storage
            .query_state()
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if !published {
            self.storage.authorize()?;
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(())
    }
}

impl Drop for QueryRemovalPreparation {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "preparation retains this volume and only unpublished preparation can be aborted"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The mounted operation retains the header; CAS cannot undo a published query.
            ext4win_stream_abort_query_remove(self.storage.address.as_ptr());
        }
        #[cfg(test)]
        {
            let _observed = self.storage.query_state().compare_exchange(
                1,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

#[expect(
    unsafe_code,
    reason = "the mounted actor retains the VCB while the unique preparation moves through owned worker envelopes"
)]
// SAFETY: No thread-affine native resource is held; only the native atomic create gate is retained.
unsafe impl Send for QueryRemovalPreparation {}

impl StorageRemovalPublisher {
    /// Forwards the original cancel-remove before undoing reversible create admission.
    /// Lower failure leaves the query gate closed; terminal removal is never reversed.
    /// # Safety
    /// The caller must exclusively own this live unqueued CANCEL_REMOVE IRP on the system PnP
    /// thread at PASSIVE_LEVEL. Mounted dispatch rundown must retain this header and lower route
    /// through the native wait. The caller retains completion authority when this call returns.
    #[expect(
        unsafe_code,
        reason = "the original PnP completion owner retains the native header, lower route and IRP through the synchronous boundary"
    )]
    pub(crate) unsafe fn cancel_remove(
        &self,
        _lower: crate::state::KernelDevice,
        _irp: NonNull<wdk_sys::IRP>,
    ) -> NTSTATUS {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The caller owns this original PnP IRP and retains both native devices
            // through lower completion and the atomic create-gate transition.
            ext4win_stream_cancel_remove(self.address.as_ptr(), _lower.as_ptr(), _irp.as_ptr())
        }
        #[cfg(test)]
        {
            let irp = unsafe {
                // SAFETY: The fixture caller retains the completed lower reply in this live IRP.
                _irp.as_ref()
            };
            let status = unsafe {
                // SAFETY: The host fixture initializes the status arm of the IO_STATUS_BLOCK.
                irp.IoStatus.__bindgen_anon_1.Status
            };
            if status >= wdk_sys::STATUS_SUCCESS {
                let state = unsafe {
                    // SAFETY: The enclosing dispatch fixture retains this host volume query gate.
                    self.query_address.as_ref()
                };
                let _observed = state.compare_exchange(2, 0, Ordering::AcqRel, Ordering::Acquire);
            }
            status
        }
    }
    /// Stops storage submissions before forwarding a terminal PnP notification. Surprise removal
    /// revokes access; final removal additionally permits physical mounted-device retirement.
    #[expect(
        unsafe_code,
        reason = "mounted-device dispatch retains the native gate and its host equivalent through removal publication"
    )]
    pub(crate) fn publish(&self, notification: StorageRemovalNotification) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The containing mounted-device dispatch lease retains this volume header.
            ext4win_stream_remove_storage(
                self.address.as_ptr(),
                u8::from(notification == StorageRemovalNotification::Final),
            );
        }
        #[cfg(test)]
        {
            let state = unsafe {
                // SAFETY: Construction captured the retained volume's host atomic.
                self.address.cast::<AtomicU8>().as_ref()
            };
            state.fetch_max(
                match notification {
                    StorageRemovalNotification::Surprise => 1,
                    StorageRemovalNotification::Final => 2,
                },
                Ordering::AcqRel,
            );
        }
    }
}

impl VolumeStorageAccess {
    /// Requires both media presence and an open reversible PnP create gate.
    /// # Errors
    /// Returns device removed after revocation, or access denied during query removal.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the retained native volume owns its interlocked create gate"
        )
    )]
    pub(crate) fn authorize_create(self) -> DriverResult<()> {
        self.authorize()?;
        #[cfg(not(test))]
        let admitted = unsafe {
            // SAFETY: The actor or dispatch retention keeps this header live during observation.
            ext4win_stream_create_admitted(self.address.as_ptr()) != 0
        };
        #[cfg(test)]
        let admitted = self.query_state().load(Ordering::Acquire) == 0;
        if admitted {
            Ok(())
        } else {
            self.authorize()?;
            Err(DriverError::AccessDenied)
        }
    }

    /// Borrows the independent host query atomic under the retained volume lifetime.
    #[cfg(test)]
    #[expect(
        unsafe_code,
        reason = "only the volume stream constructor supplies this retained host identity"
    )]
    fn query_state(&self) -> &AtomicU8 {
        unsafe {
            // SAFETY: The same volume retention that covers `address` covers this host query gate.
            self.query_address.as_ref()
        }
    }
    /// Requires storage that has received neither surprise nor final removal.
    /// # Errors
    ///
    /// Returns device removed once revocation has begun; cancellation cannot restore access.
    pub(crate) fn authorize(self) -> DriverResult<()> {
        if self.removal_state() == 0 {
            Ok(())
        } else {
            Err(DriverError::DeviceRemoved)
        }
    }

    /// Distinguishes final REMOVE from the earlier surprise-removal notification.
    pub(crate) fn final_removal_received(self) -> bool {
        self.removal_state() == 2
    }

    /// Captures submission authority through the return of IoCallDriver. Removal waits for these
    /// short-lived native submissions, not for outstanding lower I/O completion.
    /// # Errors
    ///
    /// Returns device removed if native storage admission has closed.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this volume-scoped native resource lease ends on the acquiring actor thread"
        )
    )]
    pub(crate) fn acquire_submission(self) -> DriverResult<StorageSubmissionLease> {
        #[cfg(not(test))]
        let admitted = unsafe {
            // SAFETY: The reactor or dispatch lease retains the volume for this native call.
            ext4win_stream_begin_storage_submission(self.address.as_ptr()) != 0
        };
        #[cfg(test)]
        let admitted = self.authorize().is_ok();
        if !admitted {
            return Err(DriverError::DeviceRemoved);
        }
        Ok(StorageSubmissionLease { access: self })
    }

    /// Observes the one native monotonic presence state.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the device or actor lease retains the native volume header during atomic observation"
        )
    )]
    fn removal_state(self) -> u8 {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Native code observes only the volume's interlocked removal state.
            ext4win_stream_storage_removal_state(self.address.as_ptr())
        }
        #[cfg(test)]
        self.test_state().load(Ordering::Acquire)
    }

    /// Borrows the host atomic retained by the same device/stream lifetime as the native header.
    #[cfg(test)]
    #[expect(
        unsafe_code,
        reason = "private construction ties this pointer to the retained host stream atomic"
    )]
    fn test_state(&self) -> &AtomicU8 {
        unsafe {
            // SAFETY: Only StreamContext::storage_access constructs this host pointer.
            self.address.cast::<AtomicU8>().as_ref()
        }
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
            ext4win_stream_end_storage_submission(self.access.address.as_ptr());
        }
        #[cfg(test)]
        let _access = self.access;
    }
}

impl core::fmt::Debug for StreamContext {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("StreamContext")
            .field("kind", &self.kind)
            .field("header", &self.header())
            .finish()
    }
}

#[expect(
    unsafe_code,
    reason = "the audited wrapper is the sole Rust boundary for the opaque native advanced FCB header"
)]
impl StreamContext {
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
        Self::try_new(StreamOwnerKind::Node, sizes, None, trace)
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
        snapshot: NodeMetadataSnapshot,
        epoch: EpochSequence,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        Self::try_new(
            StreamOwnerKind::Node,
            sizes,
            Some(NativeStreamMetadata::from_snapshot(snapshot, epoch)),
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
    ) -> DriverResult<Self> {
        Self::try_new(StreamOwnerKind::Volume, sizes, None, trace)
    }

    /// Allocates the opaque native stream with its owner-domain-specific metadata state.
    /// # Errors
    ///
    /// Returns an allocation or invariant error when the native stream cannot be constructed.
    fn try_new(
        kind: StreamOwnerKind,
        sizes: StreamSizes,
        metadata: Option<NativeStreamMetadata>,
        trace: OperationalTrace,
    ) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let mut header = core::ptr::null_mut();
            let metadata_pointer = metadata
                .as_ref()
                .map_or(core::ptr::null(), core::ptr::from_ref);
            let status = unsafe {
                // SAFETY: Native code borrows the optional fixed input for this call, writes one
                // opaque pointer on success, and owns every partial-allocation cleanup path.
                ext4win_stream_create(
                    kind.native_tag(),
                    sizes.allocation_size,
                    sizes.file_size,
                    sizes.valid_data_length,
                    sizes.allocation_charge,
                    metadata_pointer,
                    trace.handle(),
                    core::ptr::addr_of_mut!(header),
                )
            };
            native_status(status)?;
            let header = NonNull::new(header).ok_or(DriverError::InternalInvariantViolation)?;
            Ok(Self { kind, header })
        }
        #[cfg(test)]
        {
            let _trace = trace;
            if (kind == StreamOwnerKind::Volume) && metadata.is_some() {
                return Err(DriverError::InternalInvariantViolation);
            }
            Ok(Self {
                kind,
                owner: AtomicPtr::new(core::ptr::null_mut()),
                control_device: AtomicPtr::new(core::ptr::null_mut()),
                section_objects: UnsafeCell::new(wdk_sys::SECTION_OBJECT_POINTERS::default()),
                sizes: Mutex::new(sizes),
                metadata: Mutex::new(metadata),
                delete_pending: AtomicBool::new(false),
                storage_removal: AtomicU8::new(0),
                query_removal: AtomicU8::new(0),
            })
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
        if self.kind != StreamOwnerKind::Node || volume.kind != StreamOwnerKind::Volume {
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
        if self.kind != StreamOwnerKind::Volume {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        let address = self.header;
        #[cfg(test)]
        let address = NonNull::from(&self.storage_removal).cast();
        Ok(VolumeStorageAccess {
            address,
            #[cfg(test)]
            query_address: NonNull::from(&self.query_removal),
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
        #[cfg(not(test))]
        let acquired = unsafe {
            // SAFETY: This actor owns the live mounted volume and reserves its native atomic gate.
            ext4win_stream_prepare_query_remove(storage.address.as_ptr()) != 0
        };
        #[cfg(test)]
        let acquired = storage
            .query_state()
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
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
        Ok(StorageRemovalPublisher {
            address: access.address,
            #[cfg(test)]
            query_address: access.query_address,
        })
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
        if self.kind != StreamOwnerKind::Volume {
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
            if stream.kind != StreamOwnerKind::Volume {
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
        unsafe {
            // SAFETY: The caller retains the exact stream, IRP, and admitted handle-count
            // authorities documented above for this synchronous call.
            ext4win_stream_oplock_fsctrl(self.header.as_ptr(), irp.as_ptr(), open_count, 0)
        }
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
    ) -> NTSTATUS {
        unsafe {
            // SAFETY: The caller supplies the consuming IRP and stable continuation capabilities
            // documented above; native SEH contains FsRtl exceptions at the C boundary.
            ext4win_stream_check_oplock(
                self.header.as_ptr(),
                irp.as_ptr(),
                flags,
                continuation.as_ptr(),
            )
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
    /// must transfer terminal completion authority exactly once.
    #[cfg(not(test))]
    pub(crate) unsafe fn process_file_lock(&self, irp: NonNull<wdk_sys::IRP>) -> NTSTATUS {
        unsafe {
            // SAFETY: The caller supplies the consuming IRP capability documented above.
            ext4win_stream_process_file_lock(self.header.as_ptr(), irp.as_ptr())
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
        snapshot: NodeMetadataSnapshot,
        epoch: EpochSequence,
    ) -> DriverResult<StreamMetadataPublication> {
        if self.kind != StreamOwnerKind::Node {
            return Err(DriverError::InternalInvariantViolation);
        }
        let metadata = NativeStreamMetadata::from_snapshot(snapshot, epoch);
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

    /// Updates the native projection derived from ledger-owned delete-pending state.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a live node stream.
    pub(crate) fn set_delete_pending(&self, pending: bool) -> DriverResult<()> {
        if self.kind != StreamOwnerKind::Node {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The ledger retains this FCB and serializes the authoritative transition.
                ext4win_stream_set_delete_pending(self.header.as_ptr(), u8::from(pending))
            };
            native_status(status)
        }
        #[cfg(test)]
        {
            self.delete_pending.store(pending, Ordering::Release);
            Ok(())
        }
    }

    /// Copies cached bytes into one system-addressable IRP buffer.
    /// # Errors
    ///
    /// Returns the exact Cache Manager status or an input representation failure.
    pub(crate) fn cached_read(
        &self,
        _file_object: NonNull<wdk_sys::FILE_OBJECT>,
        _offset: i64,
        length: usize,
        _output: Option<NonNull<u8>>,
    ) -> DriverResult<usize> {
        if length == 0 {
            return Ok(0);
        }
        let _length = u32::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
        let _output = _output.ok_or(DriverError::InternalInvariantViolation)?;
        #[cfg(not(test))]
        {
            let mut information = 0_usize;
            let status = unsafe {
                // SAFETY: The active IRP owns a writable system mapping of at least `length` bytes.
                ext4win_stream_cache_read(
                    self.header.as_ptr(),
                    _file_object.as_ptr(),
                    _offset,
                    _length,
                    _output.as_ptr().cast(),
                    core::ptr::addr_of_mut!(information),
                )
            };
            cache_status(status)?;
            Ok(information)
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }

    /// Accepts one within-EOF write into the FILE_OBJECT cache map.
    /// # Errors
    ///
    /// Returns the exact Cache Manager status or an input representation failure.
    pub(crate) fn cached_write(
        &self,
        _file_object: NonNull<wdk_sys::FILE_OBJECT>,
        _offset: i64,
        _input: Option<NonNull<u8>>,
        length: usize,
    ) -> DriverResult<()> {
        if length == 0 {
            return Ok(());
        }
        let _length = u32::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
        let _input = _input.ok_or(DriverError::InternalInvariantViolation)?;
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The active IRP owns a readable system mapping of at least `length` bytes.
                ext4win_stream_cache_write(
                    self.header.as_ptr(),
                    _file_object.as_ptr(),
                    _offset,
                    _length,
                    _input.as_ptr().cast(),
                )
            };
            cache_status(status)
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
    }

    /// Executes an already captured MDL IRP without borrowing requestor byte memory.
    /// # Errors
    ///
    /// Returns the exact native status; writes extending the committed EOF are rejected.
    /// On success the IRP carries the Cache Manager-owned output chain. Failure releases
    /// any partially acquired chain before returning.
    pub(crate) fn cached_mdl(
        &self,
        _file_object: NonNull<wdk_sys::FILE_OBJECT>,
        _irp: NonNull<wdk_sys::IRP>,
        _action: crate::irp::MdlTransfer,
    ) -> DriverResult<usize> {
        #[cfg(not(test))]
        {
            let mut information = 0;
            let status = unsafe {
                // SAFETY: The cache lease retains the stream and FILE_OBJECT. The suspended
                // operation exclusively owns this IRP until the worker publishes its result.
                ext4win_stream_cache_mdl(
                    self.header.as_ptr(),
                    _file_object.as_ptr(),
                    _irp.as_ptr(),
                    _action.action(),
                    core::ptr::addr_of_mut!(information),
                )
            };
            cache_status(status)?;
            Ok(information)
        }
        #[cfg(test)]
        Err(DriverError::NotSupported)
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

    /// Flushes and purges cached data before a coherent direct mutation or size change.
    /// # Errors
    ///
    /// Returns the exact Cache Manager coherency status.
    pub(crate) fn coherency_flush_and_purge(&self) -> DriverResult<()> {
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

    /// Flushes the cache and blocks new cache/section acquisition until a size commit publishes.
    /// # Errors
    ///
    /// Returns the exact Cache Manager status or mapped-view truncation conflict.
    pub(crate) fn begin_size_change(&self, new_file_size: i64) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live stream and the caller retains it through gate release.
                ext4win_stream_begin_size_change(self.header.as_ptr(), new_file_size)
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            let _: i64 = new_file_size;
            Ok(())
        }
    }

    /// Releases one successfully acquired size-change cache/section gate.
    /// # Errors
    ///
    /// Returns an invariant native status if no matching gate remains active.
    pub(crate) fn end_size_change(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The matching successful begin call retained this same stream identity.
                ext4win_stream_end_size_change(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Flushes image/cache sections and blocks new section acquisition until deletion publishes.
    /// # Errors
    ///
    /// Returns cannot-delete while an image or mapped data section cannot be removed. A flushed
    /// shared cache map may finish its driver-owned delayed close after namespace publication.
    pub(crate) fn begin_delete(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live stream and the caller retains it through gate release.
                ext4win_stream_begin_delete(self.header.as_ptr())
            };
            if status == wdk_sys::STATUS_CANNOT_DELETE {
                Err(DriverError::CannotDelete)
            } else {
                cache_status(status)
            }
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Releases one successfully acquired stream-deletion section gate.
    /// # Errors
    ///
    /// Returns an invariant native status if no matching deletion gate remains active.
    pub(crate) fn end_delete(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The matching successful begin call retained this same stream identity.
                ext4win_stream_end_delete(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Flushes an executable image and blocks new section acquisition through write-open publish.
    /// # Errors
    ///
    /// Returns sharing-violation while an executable image cannot be removed, or the exact native
    /// synchronization failure.
    pub(crate) fn begin_write_open(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live stream and the caller retains it through gate release.
                ext4win_stream_begin_write_open(self.header.as_ptr())
            };
            if status == wdk_sys::STATUS_SHARING_VIOLATION {
                Err(DriverError::ShareAccessConflict)
            } else {
                cache_status(status)
            }
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Releases one successfully acquired write-open section gate.
    /// # Errors
    ///
    /// Returns an invariant native status if no matching write-open gate remains active.
    pub(crate) fn end_write_open(&self) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The matching successful begin call retained this same stream identity.
                ext4win_stream_end_write_open(self.header.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    /// Releases this FILE_OBJECT's private cache map without destroying shared stream sections.
    /// # Errors
    ///
    /// Returns the exact Cache Manager exception status.
    pub(crate) fn uninitialize_cache_map(
        &self,
        _file_object: NonNull<wdk_sys::FILE_OBJECT>,
    ) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: Cleanup/close retains the FILE_OBJECT and stream for the complete call.
                ext4win_stream_cache_uninitialize(self.header.as_ptr(), _file_object.as_ptr())
            };
            cache_status(status)
        }
        #[cfg(test)]
        Ok(())
    }

    /// Reports whether Cache Manager or Memory Manager still retains the shared stream sections.
    /// # Errors
    ///
    /// Returns an invariant error if the native stream header is malformed.
    pub(crate) fn has_native_residency(&self) -> DriverResult<bool> {
        #[cfg(not(test))]
        {
            let mut resident = 0_u8;
            let status = unsafe {
                // SAFETY: `self` owns the live native header and the output is one BOOLEAN.
                ext4win_stream_has_native_residency(
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
            if stream.kind != expected_kind {
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
pub(crate) fn fast_io_dispatch() -> DriverResult<NonNull<wdk_sys::FAST_IO_DISPATCH>> {
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
// immutable kind/header identity after the single construction-time owner binding.
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
    fn ext4win_stream_cache_mdl(
        stream_header: wdk_sys::PVOID,
        file_object: *mut wdk_sys::FILE_OBJECT,
        irp: wdk_sys::PIRP,
        action: crate::irp::MdlAction,
        information_out: *mut usize,
    ) -> NTSTATUS;
    fn ext4win_stream_create(
        kind: wdk_sys::ULONG,
        allocation_size: i64,
        file_size: i64,
        valid_data_length: i64,
        allocation_charge: i64,
        metadata: *const NativeStreamMetadata,
        trace_registration_handle: u64,
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
    fn ext4win_stream_remove_storage(volume_header: wdk_sys::PVOID, final_remove: u8);
    fn ext4win_stream_storage_removal_state(volume_header: wdk_sys::PVOID) -> u8;
    fn ext4win_stream_create_admitted(volume_header: wdk_sys::PVOID) -> u8;
    fn ext4win_stream_prepare_query_remove(volume_header: wdk_sys::PVOID) -> u8;
    fn ext4win_stream_abort_query_remove(volume_header: wdk_sys::PVOID);
    fn ext4win_stream_publish_query_remove(volume_header: wdk_sys::PVOID) -> u8;
    fn ext4win_stream_cancel_remove(
        volume_header: wdk_sys::PVOID,
        lower: wdk_sys::PDEVICE_OBJECT,
        irp: wdk_sys::PIRP,
    ) -> NTSTATUS;
    fn ext4win_stream_begin_storage_submission(volume_header: wdk_sys::PVOID) -> u8;
    fn ext4win_stream_end_storage_submission(volume_header: wdk_sys::PVOID);
    fn ext4win_stream_volume_control_device(
        stream_header: wdk_sys::PVOID,
    ) -> wdk_sys::PDEVICE_OBJECT;

    fn ext4win_stream_oplock_fsctrl(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
        open_count: wdk_sys::ULONG,
        flags: wdk_sys::ULONG,
    ) -> NTSTATUS;
    fn ext4win_stream_check_oplock(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
        flags: wdk_sys::ULONG,
        continuation: wdk_sys::PVOID,
    ) -> NTSTATUS;
    fn ext4win_stream_backout_atomic_oplock(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
    ) -> NTSTATUS;
    fn ext4win_stream_process_file_lock(
        stream_header: wdk_sys::PVOID,
        irp: *mut wdk_sys::IRP,
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

    fn ext4win_stream_publish_metadata(
        stream_header: wdk_sys::PVOID,
        allocation_size: i64,
        file_size: i64,
        valid_data_length: i64,
        allocation_charge: i64,
        metadata: *const NativeStreamMetadata,
        cache_status_out: *mut NTSTATUS,
    ) -> NTSTATUS;

    fn ext4win_stream_set_delete_pending(
        stream_header: wdk_sys::PVOID,
        pending: wdk_sys::BOOLEAN,
    ) -> NTSTATUS;

    fn ext4win_stream_cache_read(
        stream_header: wdk_sys::PVOID,
        file_object: *mut wdk_sys::FILE_OBJECT,
        offset: i64,
        length: wdk_sys::ULONG,
        buffer: wdk_sys::PVOID,
        information_out: *mut usize,
    ) -> NTSTATUS;

    fn ext4win_stream_cache_write(
        stream_header: wdk_sys::PVOID,
        file_object: *mut wdk_sys::FILE_OBJECT,
        offset: i64,
        length: wdk_sys::ULONG,
        buffer: wdk_sys::PVOID,
    ) -> NTSTATUS;

    fn ext4win_stream_cache_flush(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_cache_coherency_flush_and_purge(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_cache_drain_for_volume_lock(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_begin_size_change(
        stream_header: wdk_sys::PVOID,
        new_file_size: i64,
    ) -> NTSTATUS;

    fn ext4win_stream_end_size_change(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_begin_delete(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_end_delete(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_begin_write_open(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_end_write_open(stream_header: wdk_sys::PVOID) -> NTSTATUS;

    fn ext4win_stream_cache_uninitialize(
        stream_header: wdk_sys::PVOID,
        file_object: *mut wdk_sys::FILE_OBJECT,
    ) -> NTSTATUS;

    fn ext4win_stream_has_native_residency(
        stream_header: wdk_sys::PVOID,
        resident_out: *mut wdk_sys::BOOLEAN,
    ) -> NTSTATUS;

    fn ext4win_stream_destroy(stream_header: wdk_sys::PVOID) -> NTSTATUS;
    fn ext4win_fast_io_dispatch() -> *mut wdk_sys::FAST_IO_DISPATCH;
}

#[cfg(test)]
mod tests {
    use ext4_core::{ClusterSize, FileAllocationSize, FileSize};

    use super::{NativeStreamMetadata, OperationalTrace, Ordering, StreamContext, StreamSizes};
    use crate::kernel::status::{DriverError, DriverResult};

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
        let volume =
            StreamContext::try_new_volume(StreamSizes::EMPTY, OperationalTrace::host_test())?;
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
        let volume =
            StreamContext::try_new_volume(StreamSizes::EMPTY, OperationalTrace::host_test())?;
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
        assert_eq!(sizes.allocation_size, 131_072);
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
        let larger_section = StreamSizes::try_from_ext4(
            FileSize::from_bytes(4_096),
            FileAllocationSize::from_bytes(8_192),
            cluster,
        )?;

        assert_ne!(baseline, charge_only);
        assert!(baseline.same_cache_dimensions(charge_only));
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
        assert_eq!(core::mem::size_of::<NativeStreamMetadata>(), 40);
        assert_eq!(core::mem::offset_of!(NativeStreamMetadata, epoch), 0);
        assert_eq!(
            core::mem::offset_of!(NativeStreamMetadata, creation_time_seconds),
            8
        );
        assert_eq!(core::mem::offset_of!(NativeStreamMetadata, directory), 32);
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
        reason = "fixture failures use Result; assertions check the delete projection"
    )]
    fn delete_pending_projection_tracks_each_requested_state() -> DriverResult<()> {
        let stream =
            StreamContext::try_new_staged_node(StreamSizes::EMPTY, OperationalTrace::host_test())?;
        assert!(!stream.delete_pending.load(Ordering::Acquire));
        stream.set_delete_pending(true)?;
        assert!(stream.delete_pending.load(Ordering::Acquire));
        stream.set_delete_pending(false)?;
        assert!(!stream.delete_pending.load(Ordering::Acquire));
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
