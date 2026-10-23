//! Narrow retained registry authority; every call and final release occurs at PASSIVE_LEVEL.
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use ext4_core::FilesystemUuid;
use ext4_security::PublicationOutcome;

/// Bytes reserved for KEY_VALUE_PARTIAL_INFORMATION and a maximum whole-table value.
pub(super) const READ_CAPACITY: usize = ext4_security::MAX_MAPPING_BYTES + 12;

/// Kernel-only handle scoped to the service's IdentityMappings key.
#[derive(Debug)]
pub(super) struct RegistryStore {
    /// Retained through catalog ownership and every submitted worker lease.
    #[cfg(not(test))]
    handle: core::ptr::NonNull<core::ffi::c_void>,
}
impl RegistryStore {
    /// Opens or creates the root before the control device is published.
    /// # Safety
    /// The loader's counted service path must remain valid for this synchronous call.
    /// # Errors
    /// Returns the exact native registry failure.
    #[expect(
        unsafe_code,
        reason = "the loader path and owned native handle cross one audited synchronous C boundary"
    )]
    pub(super) unsafe fn open(path: wdk_sys::PCUNICODE_STRING) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let mut handle = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: The loader retains path; handle is writable out storage.
                crate::kernel::ffi::ext4win_identity_open_root(path, &mut handle)
            };
            native_success(status)?;
            Ok(Self {
                handle: core::ptr::NonNull::new(handle)
                    .ok_or(DriverError::InternalInvariantViolation)?,
            })
        }
        #[cfg(test)]
        {
            let _path = path;
            Err(DriverError::NotSupported)
        }
    }
    /// Enumerates one key without retaining native borrowed storage.
    /// # Errors
    /// Propagates registry or invalid key-name failures; None means end of enumeration.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the fixed output array covers the C enumeration contract"
        )
    )]
    pub(super) fn enumerate(&self, index: u32) -> DriverResult<Option<FilesystemUuid>> {
        #[cfg(not(test))]
        {
            let mut text = [0_u16; 36];
            let status = unsafe {
                // SAFETY: The retained root is live and output covers exactly 36 units.
                crate::kernel::ffi::ext4win_identity_enumerate(
                    self.handle.as_ptr(),
                    index,
                    text.as_mut_ptr(),
                )
            };
            if status == wdk_sys::STATUS_NO_MORE_ENTRIES {
                return Ok(None);
            }
            native_success(status)?;
            let mut ascii = [0_u8; 36];
            for (target, value) in ascii.iter_mut().zip(text) {
                *target = u8::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
            }
            Ok(Some(ext4_security::parse_uuid(
                core::str::from_utf8(&ascii).map_err(|_| DriverError::InvalidParameter)?,
            )?))
        }
        #[cfg(test)]
        {
            let _index = index;
            Err(DriverError::NotSupported)
        }
    }
    /// Reads into preallocated pool storage; absent values are distinguishable from damaged ones.
    /// # Errors
    /// Returns exact native failure or an invalid native byte count.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "kernel pool allocation is aligned for KEY_VALUE_PARTIAL_INFORMATION and bounded by the owned vector"
        )
    )]
    pub(super) fn read(
        &self,
        uuid: &[u16; 36],
        buffer: &mut DriverVec<u8>,
    ) -> DriverResult<Option<usize>> {
        #[cfg(not(test))]
        {
            let capacity =
                u32::try_from(buffer.len()).map_err(|_| DriverError::InvalidBufferSize)?;
            let mut length = 0;
            let status = unsafe {
                // SAFETY: Root, fixed UUID and initialized pool buffer remain retained throughout the call.
                crate::kernel::ffi::ext4win_identity_read(
                    self.handle.as_ptr(),
                    uuid.as_ptr(),
                    buffer.as_mut_slice().as_mut_ptr().cast(),
                    capacity,
                    &mut length,
                )
            };
            if status == wdk_sys::STATUS_OBJECT_NAME_NOT_FOUND {
                return Ok(None);
            }
            native_success(status)?;
            let length = usize::try_from(length).map_err(|_| DriverError::InvalidBufferSize)?;
            if length > ext4_security::MAX_MAPPING_BYTES || length > buffer.len() {
                return Err(DriverError::InvalidBufferSize);
            }
            Ok(Some(length))
        }
        #[cfg(test)]
        {
            let _inputs = (uuid, buffer);
            Err(DriverError::NotSupported)
        }
    }
    /// Performs one persistence attempt and preserves its accepted-effect classification.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the prepared complete record and retained key outlive this synchronous PASSIVE_LEVEL call"
        )
    )]
    pub(super) fn save(&self, uuid: &[u16; 36], record: &[u8]) -> (PublicationOutcome, i32) {
        #[cfg(not(test))]
        {
            let Ok(length) = u32::try_from(record.len()) else {
                return (
                    PublicationOutcome::NotSaved,
                    DriverError::InvalidBufferSize.ntstatus(),
                );
            };
            let mut phase = 0;
            let status = unsafe {
                // SAFETY: All input buffers are prepared and retained; phase is writable native output.
                crate::kernel::ffi::ext4win_identity_save(
                    self.handle.as_ptr(),
                    uuid.as_ptr(),
                    record.as_ptr(),
                    length,
                    &mut phase,
                )
            };
            (
                match phase {
                    0 => PublicationOutcome::NotSaved,
                    1 => PublicationOutcome::SavedNotApplied,
                    _ => PublicationOutcome::Unknown,
                },
                status,
            )
        }
        #[cfg(test)]
        {
            let _inputs = (uuid, record);
            (
                PublicationOutcome::NotSaved,
                DriverError::NotSupported.ntstatus(),
            )
        }
    }
    /// Makes an observed table durable before it can replace live authority.
    /// # Errors
    /// Propagates native flush failure; callers retain Unknown until reconciliation succeeds.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the retained root and fixed UUID remain live through the native flush"
        )
    )]
    pub(super) fn flush(&self, uuid: &[u16; 36]) -> DriverResult<()> {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The root remains retained through worker completion.
                crate::kernel::ffi::ext4win_identity_flush(self.handle.as_ptr(), uuid.as_ptr())
            };
            native_success(status)
        }
        #[cfg(test)]
        {
            let _uuid = uuid;
            Err(DriverError::NotSupported)
        }
    }
}
#[cfg(not(test))]
impl Drop for RegistryStore {
    #[expect(
        unsafe_code,
        reason = "the catalog and worker leases uniquely release the root after PASSIVE_LEVEL rundown"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: No call can retain a borrow after the final counted owner drops.
            crate::kernel::ffi::ext4win_identity_close(self.handle.as_ptr());
        }
    }
}
#[expect(
    unsafe_code,
    reason = "kernel handles are process-independent and registry APIs serialize access; ownership retains them through worker rundown"
)]
// SAFETY: The kernel-only handle is immutable and cannot close while a worker lease exists.
unsafe impl Send for RegistryStore {}
#[expect(
    unsafe_code,
    reason = "the immutable kernel-only handle remains retained for every synchronous registry call"
)]
// SAFETY: Registry APIs support concurrent calls; replacement serialization belongs to the UUID slot.
unsafe impl Sync for RegistryStore {}

/// Preserves the native failure domain at the registry boundary.
/// # Errors
/// Returns the exact failing NTSTATUS.
#[cfg(not(test))]
fn native_success(status: i32) -> DriverResult<()> {
    if status < 0 {
        Err(DriverError::RegistryFailure(status))
    } else {
        Ok(())
    }
}

/// UUID key text uses ext4 byte order, with no Windows GUID byte swapping.
pub(super) fn key_text(uuid: FilesystemUuid) -> [u16; 36] {
    let mut units = [0; 36];
    for (unit, byte) in units.iter_mut().zip(ext4_security::uuid_text(uuid)) {
        *unit = u16::from(byte);
    }
    units
}
