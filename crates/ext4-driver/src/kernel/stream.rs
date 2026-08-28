//! Native Windows stream-header ownership boundary.

use core::ffi::c_void;
use core::ptr::NonNull;

#[cfg(test)]
use core::cell::UnsafeCell;
#[cfg(test)]
use core::sync::atomic::{AtomicPtr, Ordering};
use ext4_core::{ClusterSize, FileAllocationSize, FileSize};
#[cfg(test)]
use std::sync::Mutex;

#[cfg(not(test))]
use wdk_sys::{NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

#[cfg(not(test))]
use crate::kernel::fatal::KernelWideInconsistency;
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
    /// Stable host ABI storage; tests access fields only through the external pointer boundary.
    #[cfg(test)]
    section_objects: UnsafeCell<wdk_sys::SECTION_OBJECT_POINTERS>,
    /// Host equivalent of the native header mutex and size fields.
    #[cfg(test)]
    sizes: Mutex<StreamSizes>,
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
    /// Allocates a native advanced header in an unbound construction state.
    ///
    /// The enclosing Rust owner must reach stable storage and call [`Self::bind_owner`] before the
    /// header can be published to a `FILE_OBJECT`.
    /// # Errors
    ///
    /// Returns an allocation or invariant error when the native FCB boundary cannot be built.
    pub(crate) fn try_new(kind: StreamOwnerKind, sizes: StreamSizes) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let mut header = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: Native code writes one opaque pointer on success and owns partial cleanup.
                ext4win_stream_create(
                    kind.native_tag(),
                    sizes.allocation_size,
                    sizes.file_size,
                    sizes.valid_data_length,
                    sizes.allocation_charge,
                    core::ptr::addr_of_mut!(header),
                )
            };
            native_status(status)?;
            let header = NonNull::new(header).ok_or(DriverError::InternalInvariantViolation)?;
            Ok(Self { kind, header })
        }
        #[cfg(test)]
        {
            Ok(Self {
                kind,
                owner: AtomicPtr::new(core::ptr::null_mut()),
                section_objects: UnsafeCell::new(wdk_sys::SECTION_OBJECT_POINTERS::default()),
                sizes: Mutex::new(sizes),
            })
        }
    }

    /// Binds the native header to its final-address Rust owner exactly once.
    /// # Errors
    ///
    /// Returns an invariant error if construction attempts to bind twice or with a null owner.
    pub(crate) fn bind_owner(&self, owner: NonNull<c_void>) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: `self` owns the live native header and `owner` has reached stable storage.
                ext4win_stream_bind_owner(
                    self.header.as_ptr(),
                    self.kind.native_tag(),
                    owner.as_ptr(),
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
                .map(|_| ())
                .map_err(|_| DriverError::InternalInvariantViolation)
        }
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

    /// Publishes a prevalidated stream-size tuple after the corresponding ext4 commit.
    /// # Errors
    ///
    /// Returns an invariant error when the native stream header is malformed.
    pub(crate) fn set_sizes(&self, sizes: StreamSizes) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: Native code validates and serializes the complete header tuple.
                ext4win_stream_set_sizes(
                    self.header.as_ptr(),
                    sizes.allocation_size,
                    sizes.file_size,
                    sizes.valid_data_length,
                    sizes.allocation_charge,
                )
            };
            native_status(status)
        }
        #[cfg(test)]
        {
            let mut current = self
                .sizes
                .lock()
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            *current = sizes;
            Ok(())
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
#[expect(
    unsafe_code,
    reason = "these declarations expose the audited native advanced-FCB-header ownership boundary"
)]
unsafe extern "system" {
    fn ext4win_stream_create(
        kind: wdk_sys::ULONG,
        allocation_size: i64,
        file_size: i64,
        valid_data_length: i64,
        allocation_charge: i64,
        stream_header_out: *mut wdk_sys::PVOID,
    ) -> NTSTATUS;

    fn ext4win_stream_bind_owner(
        stream_header: wdk_sys::PVOID,
        expected_kind: wdk_sys::ULONG,
        owner: wdk_sys::PVOID,
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

    fn ext4win_stream_set_sizes(
        stream_header: wdk_sys::PVOID,
        allocation_size: i64,
        file_size: i64,
        valid_data_length: i64,
        allocation_charge: i64,
    ) -> NTSTATUS;

    fn ext4win_stream_destroy(stream_header: wdk_sys::PVOID) -> NTSTATUS;
}

#[cfg(test)]
mod tests {
    use ext4_core::{ClusterSize, FileAllocationSize, FileSize};

    use super::{StreamContext, StreamOwnerKind, StreamSizes};
    use crate::kernel::status::{DriverError, DriverResult};

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
    /// Returns a stream-construction or publication error.
    /// # Panics
    ///
    /// Panics if growth or truncation fails to replace the complete published tuple.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures use Result; assertions check publication"
    )]
    fn header_publication_replaces_all_size_fields_together() -> DriverResult<()> {
        let stream = StreamContext::try_new(StreamOwnerKind::Node, StreamSizes::EMPTY)?;
        assert_eq!(stream.sizes()?, StreamSizes::EMPTY);
        let grown = StreamSizes::try_from_ext4(
            FileSize::from_bytes(16_384),
            FileAllocationSize::from_bytes(8_192),
            ClusterSize::new(4_096)?,
        )?;
        stream.set_sizes(grown)?;
        assert_eq!(stream.sizes()?, grown);
        let truncated = StreamSizes::try_from_ext4(
            FileSize::from_bytes(4_097),
            FileAllocationSize::from_bytes(4_096),
            ClusterSize::new(4_096)?,
        )?;
        stream.set_sizes(truncated)?;
        assert_eq!(stream.sizes()?, truncated);
        assert_eq!(truncated.valid_data_length, 4_097);
        assert_eq!(truncated.allocation_size, 8_192);
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
