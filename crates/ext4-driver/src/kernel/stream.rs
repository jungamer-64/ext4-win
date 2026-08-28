//! Native Windows stream-header ownership boundary.

use core::ffi::c_void;
use core::ptr::NonNull;

#[cfg(test)]
use core::cell::UnsafeCell;
#[cfg(test)]
use core::sync::atomic::{AtomicPtr, Ordering};

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

/// Windows-visible file sizes installed into a new stream header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StreamSizes {
    allocation_size: i64,
    file_size: i64,
    valid_data_length: i64,
}

impl StreamSizes {
    /// Size tuple for a non-data stream such as a volume or directory.
    pub(crate) const EMPTY: Self = Self {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
    };
}

/// Opaque native `FSRTL_ADVANCED_FCB_HEADER` plus its resources, sections, and oplock.
pub(crate) struct StreamContext {
    kind: StreamOwnerKind,
    #[cfg(not(test))]
    header: NonNull<c_void>,
    #[cfg(test)]
    owner: AtomicPtr<c_void>,
    #[cfg(test)]
    section_objects: UnsafeCell<wdk_sys::SECTION_OBJECT_POINTERS>,
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
                    kind as u32,
                    sizes.allocation_size,
                    sizes.file_size,
                    sizes.valid_data_length,
                    core::ptr::addr_of_mut!(header),
                )
            };
            native_status(status)?;
            let header = NonNull::new(header).ok_or(DriverError::InternalInvariantViolation)?;
            return Ok(Self { kind, header });
        }
        #[cfg(test)]
        {
            let _ = sizes;
            Ok(Self {
                kind,
                owner: AtomicPtr::new(core::ptr::null_mut()),
                section_objects: UnsafeCell::new(wdk_sys::SECTION_OBJECT_POINTERS::default()),
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
                ext4win_stream_bind_owner(self.header.as_ptr(), self.kind as u32, owner.as_ptr())
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
    pub(crate) fn section_objects(
        &self,
    ) -> DriverResult<NonNull<wdk_sys::SECTION_OBJECT_POINTERS>> {
        Self::decode_section_objects(self.header())
    }

    /// Decodes the section-object set embedded beside one validated advanced header.
    /// # Errors
    ///
    /// Returns an invariant error when `header` is not a live stream owned by this driver.
    pub(crate) fn decode_section_objects(
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
    pub(crate) fn decode_owner(
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
                    expected_kind as u32,
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

    fn ext4win_stream_destroy(stream_header: wdk_sys::PVOID) -> NTSTATUS;
}
