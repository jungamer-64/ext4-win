//! Fast I/O admission and fixed metadata records. Native code owns resource/SEH operations.

#[cfg(not(test))]
use wdk_sys::{PDEVICE_OBJECT, PFILE_OBJECT, PIO_STATUS_BLOCK, PLARGE_INTEGER};

/// Observations needed to select a cached transfer, without granting stream mutation authority.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct TransferObservation {
    /// Coherent committed EOF captured under the header mutex.
    eof: i64,
    /// Native FILE_OBJECT transfer flags.
    flags: u32,
    /// Whether the shared cache map is available for this FILE_OBJECT.
    cached: u8,
    /// Volume media observation.
    media: u8,
    /// Independent filesystem close observation.
    close: u8,
    /// Section-mutation observation.
    mutation: u8,
    /// Handle-local read access.
    read_access: u8,
    /// Handle-local write access.
    write_access: u8,
}

/// Fixed committed metadata projection borrowed from the native header snapshot.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct PublishedMetadata {
    /// Epoch owns every field of this projection.
    epoch: u64,
    /// Windows creation timestamp.
    creation: i64,
    /// Windows access timestamp.
    accessed: i64,
    /// Windows write timestamp.
    modified: i64,
    /// Windows metadata-change timestamp.
    changed: i64,
    /// Complete Windows file attributes.
    attributes: u32,
    /// Windows-visible namespace link count.
    links: u32,
    /// Native directory discriminator.
    directory: u32,
}

/// One coherent, allocation-free metadata observation; header storage remains authoritative.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct QuerySnapshot {
    /// Epoch-owned committed file metadata.
    metadata: PublishedMetadata,
    /// Physical storage charge, independent of logical section allocation.
    allocation: i64,
    /// Committed logical EOF.
    eof: i64,
    /// Ledger-owned deletion projection.
    delete_pending: u8,
}

#[cfg(not(test))]
const _: () = {
    assert!(core::mem::size_of::<TransferObservation>() == 24);
    assert!(core::mem::offset_of!(TransferObservation, cached) == 12);
    assert!(core::mem::size_of::<QuerySnapshot>() == 80);
    assert!(core::mem::offset_of!(QuerySnapshot, delete_pending) == 72);
};

/// Cached transfer admission requires independent media, close and section gates to be open.
fn cached_transfer_admitted(flags: u32, cached: u8, media: u8, close: u8, mutation: u8) -> bool {
    media == 0
        && close == 0
        && mutation == 0
        && cached != 0
        && flags & wdk_sys::FO_NO_INTERMEDIATE_BUFFERING == 0
        && flags & wdk_sys::FO_CACHE_SUPPORTED != 0
}

/// Native adapters provide observations without owning the admission policy.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the internal scalar ABI exposes only a pure admission decision"
)]
#[unsafe(no_mangle)]
extern "system" fn ext4win_fast_io_admit(
    flags: u32,
    cached: u8,
    media: u8,
    close: u8,
    mutation: u8,
) -> u8 {
    u8::from(cached_transfer_admitted(
        flags, cached, media, close, mutation,
    ))
}

/// Query admission does not require cache residency or ordinary transfer admission.
fn metadata_query_admitted(
    flags: u32,
    read_access: u8,
    fast_possible: u8,
    media: u8,
    mutation: u8,
) -> bool {
    media == 0
        && mutation == 0
        && read_access != 0
        && fast_possible != 0
        && flags & wdk_sys::FO_NO_INTERMEDIATE_BUFFERING == 0
}

/// Native resource adapters consult the same query policy before and after locking.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native observations select an allocation-free metadata query"
)]
#[unsafe(no_mangle)]
extern "system" fn ext4win_fast_io_query_admit(
    flags: u32,
    read_access: u8,
    fast_possible: u8,
    media: u8,
    mutation: u8,
) -> u8 {
    u8::from(metadata_query_admitted(
        flags,
        read_access,
        fast_possible,
        media,
        mutation,
    ))
}

/// Establishes an in-EOF range before any Cache Manager call.
fn admitted_range(offset: i64, length: u32, eof: i64) -> Option<i64> {
    let length = i64::from(length);
    (offset >= 0 && offset.checked_add(length).is_some_and(|end| end <= eof)).then_some(length)
}

/// Windows callback selects Fast I/O before native locking and SEH-protected transfer.
/// # Safety
/// The I/O Manager retains file, offset and status for this callback; no requestor buffer is borrowed.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the callback borrows fixed kernel observations before invoking native lock checks"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_fast_io_check_if_possible(
    file: PFILE_OBJECT,
    offset: PLARGE_INTEGER,
    length: u32,
    wait: u8,
    key: u32,
    read: u8,
    status: PIO_STATUS_BLOCK,
    _device: PDEVICE_OBJECT,
) -> u8 {
    if status.is_null() {
        return 0;
    }
    let status = unsafe {
        // SAFETY: The callback owns this kernel status record for its duration.
        &mut *status
    };
    status.Information = 0;
    status.__bindgen_anon_1.Status = wdk_sys::STATUS_NOT_SUPPORTED;
    if wait == 0 || offset.is_null() {
        return 0;
    }
    let mut observation = TransferObservation {
        eof: 0,
        flags: 0,
        cached: 0,
        media: 2,
        close: 2,
        mutation: 2,
        read_access: 0,
        write_access: 0,
    };
    if unsafe {
        // SAFETY: Native code borrows the retained FILE_OBJECT and fills one local observation.
        ext4win_fast_io_observe(file, &mut observation)
    } == 0
    {
        return 0;
    }
    let offset = unsafe {
        // SAFETY: The I/O Manager supplies this live fixed offset record.
        &*offset
    };
    let offset = unsafe {
        // SAFETY: The callback offset uses the signed QuadPart union arm.
        offset.QuadPart
    };
    let Some(length) = admitted_range(offset, length, observation.eof) else {
        return 0;
    };
    if !cached_transfer_admitted(
        observation.flags,
        observation.cached,
        observation.media,
        observation.close,
        observation.mutation,
    ) || if read != 0 {
        observation.read_access == 0
    } else {
        observation.write_access == 0
    } {
        return 0;
    }
    unsafe {
        // SAFETY: Range and retained file identity are established; native FsRtl owns lock semantics.
        ext4win_fast_io_check_locks(file, offset, length, key, read)
    }
}

/// Prepares a fixed record in driver-owned storage; C performs the guarded requestor copy.
/// # Safety
/// Native code passes a coherent initialized snapshot and exclusive local output storage.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the metadata encoder never touches external requestor mappings"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_fast_io_basic_record(
    snapshot: *const QuerySnapshot,
    output: *mut wdk_sys::FILE_BASIC_INFORMATION,
) {
    let snapshot = unsafe {
        // SAFETY: The native header lock established this complete local observation.
        &*snapshot
    };
    let basic = super::file_information::BasicInformation {
        times: [
            snapshot.metadata.creation,
            snapshot.metadata.accessed,
            snapshot.metadata.modified,
            snapshot.metadata.changed,
        ],
        attributes: snapshot.metadata.attributes,
    };
    unsafe {
        // SAFETY: Native code lends one initialized local record, separate from requestor memory.
        encode_local::<wdk_sys::FILE_BASIC_INFORMATION>(output, |bytes| basic.write_basic(bytes));
    }
}

/// Prepares standard information from the same committed snapshot and deletion projection.
/// # Safety
/// Native code passes a coherent initialized snapshot and exclusive local output storage.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "only local fixed metadata records enter Rust's aliasing model"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_fast_io_standard_record(
    snapshot: *const QuerySnapshot,
    output: *mut wdk_sys::FILE_STANDARD_INFORMATION,
) {
    let snapshot = unsafe {
        // SAFETY: The native header lock established this complete local observation.
        &*snapshot
    };
    let standard = super::file_information::StandardInformation {
        allocation: snapshot.allocation,
        eof: snapshot.eof,
        links: snapshot.metadata.links,
        delete_pending: snapshot.delete_pending != 0,
        directory: snapshot.metadata.directory != 0,
    };
    unsafe {
        // SAFETY: Native code lends one initialized local record, separate from requestor memory.
        encode_local::<wdk_sys::FILE_STANDARD_INFORMATION>(output, |bytes| standard.write(bytes));
    }
}

/// Prepares network-open information without independent size or timestamp authority.
/// # Safety
/// Native code passes a coherent initialized snapshot and exclusive local output storage.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the native requestor copy remains inside its SEH boundary"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_fast_io_network_record(
    snapshot: *const QuerySnapshot,
    output: *mut wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
) {
    let snapshot = unsafe {
        // SAFETY: The native header lock established this complete local observation.
        &*snapshot
    };
    let basic = super::file_information::BasicInformation {
        times: [
            snapshot.metadata.creation,
            snapshot.metadata.accessed,
            snapshot.metadata.modified,
            snapshot.metadata.changed,
        ],
        attributes: snapshot.metadata.attributes,
    };
    unsafe {
        // SAFETY: Native code lends one initialized local record, separate from requestor memory.
        encode_local::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>(output, |bytes| {
            basic.write_network(bytes, snapshot.allocation, snapshot.eof)
        });
    }
}

/// Restricts byte encoding to one initialized native local record, including its padding.
/// # Safety
/// `output` must identify aligned exclusive driver-owned storage for one initialized `T`.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the dedicated encoder borrows only native adapter stack storage"
)]
unsafe fn encode_local<T>(
    output: *mut T,
    encode: impl FnOnce(&mut [u8]) -> crate::kernel::status::DriverResult<usize>,
) {
    let bytes = unsafe {
        // SAFETY: Native adapters initialize the entire local record before lending its bytes.
        core::slice::from_raw_parts_mut(output.cast::<u8>(), size_of::<T>())
    };
    if encode(bytes).is_err() {
        crate::kernel::fatal::KernelWideInconsistency::file_control_block_ownership_corruption()
            .bugcheck();
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native adapters observe opaque header state and invoke FsRtl lock primitives"
)]
unsafe extern "system" {
    fn ext4win_fast_io_observe(file: PFILE_OBJECT, output: *mut TransferObservation) -> u8;
    fn ext4win_fast_io_check_locks(
        file: PFILE_OBJECT,
        offset: i64,
        length: i64,
        key: u32,
        read: u8,
    ) -> u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Panics
    /// Fails if Fast I/O bypasses independent gates or accepts an out-of-EOF/overflow range.
    #[test]
    fn transfer_requires_live_cached_in_eof_authority() {
        let flags = wdk_sys::FO_CACHE_SUPPORTED;
        assert!(cached_transfer_admitted(flags, 1, 0, 0, 0));
        assert!(!cached_transfer_admitted(flags, 1, 1, 0, 0));
        assert!(!cached_transfer_admitted(flags, 1, 0, 1, 0));
        assert!(!cached_transfer_admitted(flags, 1, 0, 0, 1));
        assert!(!cached_transfer_admitted(
            flags | wdk_sys::FO_NO_INTERMEDIATE_BUFFERING,
            1,
            0,
            0,
            0
        ));
        assert_eq!(admitted_range(8, 8, 16), Some(8));
        assert_eq!(admitted_range(8, 9, 16), None);
        assert_eq!(admitted_range(-1, 1, 16), None);
        assert_eq!(admitted_range(i64::MAX, 1, i64::MAX), None);
    }

    /// # Panics
    /// Fails if metadata queries require a cache map or bypass media/oplock exclusion.
    #[test]
    fn metadata_query_admission_is_independent_of_cache_residency() {
        assert!(metadata_query_admitted(0, 1, 1, 0, 0));
        assert!(!cached_transfer_admitted(0, 0, 0, 0, 0));
        assert!(!metadata_query_admitted(0, 1, 1, 1, 0));
        assert!(!metadata_query_admitted(0, 1, 0, 0, 0));
    }
}
