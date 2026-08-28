//! Owned PnP volume snapshots; paths borrow the pool allocation, never callback storage.

use core::ptr::NonNull;
use wdk_sys::{GUID, NTSTATUS, STATUS_INVALID_BUFFER_SIZE, STATUS_SUCCESS};

/// Distinct Windows volume namespaces, including partitions without automatic mount points.
#[derive(Clone, Copy, Debug)]
pub(crate) enum VolumeInterfaceClass {
    /// Volumes published through the normal Mount Manager interface.
    Visible,
    /// Volumes that Windows enumerates without normal Mount Manager publication.
    Hidden,
}

impl VolumeInterfaceClass {
    /// WDK `ntddstor.h` interface identity; not a GPT partition type or filesystem UUID.
    pub(crate) const fn guid(self) -> GUID {
        match self {
            Self::Visible => GUID {
                Data1: 0x53f5_630d,
                Data2: 0xb6bf,
                Data3: 0x11d0,
                Data4: [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
            },
            Self::Hidden => GUID {
                Data1: 0x7f10_8a28,
                Data2: 0x9833,
                Data3: 0x4b3b,
                Data4: [0xb7, 0x80, 0x2c, 0x6b, 0x5f, 0xa5, 0xc0, 0x62],
            },
        }
    }
}

/// One immutable, present-interface MULTI_SZ with a streaming cursor.
#[derive(Debug)]
pub(crate) struct VolumeInterfaces {
    /// Sole pool allocation ownership, independent of the iteration cursor.
    allocation: NonNull<u16>,
    /// Next component inside `allocation`, or the final empty component.
    cursor: *const u16,
}

impl VolumeInterfaces {
    /// Captures enabled interfaces at PASSIVE_LEVEL; later removals remain open-time failures.
    /// # Errors
    /// Returns the native enumeration failure, including pool exhaustion.
    #[expect(unsafe_code, reason = "PnP returns an owned MULTI_SZ allocation")]
    pub(crate) fn enumerate(class: VolumeInterfaceClass) -> Result<Self, NTSTATUS> {
        let mut list = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: The GUID and output slot live through this synchronous PnP query.
            crate::kernel::ffi::IoGetDeviceInterfaces(
                &class.guid(),
                core::ptr::null_mut(),
                0,
                &raw mut list,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(status);
        }
        let allocation = NonNull::new(list).ok_or(wdk_sys::STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(Self {
            allocation,
            cursor: list,
        })
    }

    /// Borrows the next terminated path, with no copy or retained device ownership.
    /// # Errors
    /// Returns invalid-buffer-size if a component exceeds the `UNICODE_STRING` limit.
    #[expect(
        unsafe_code,
        reason = "the iterator traverses only its live WDK MULTI_SZ"
    )]
    pub(crate) fn next_path(&mut self) -> Result<Option<&[u16]>, NTSTATUS> {
        for length in 0_usize..32_767 {
            let unit = unsafe {
                // SAFETY: PnP guarantees a terminated component; the allocation remains owned.
                self.cursor.add(length)
            };
            let value = unsafe {
                // SAFETY: This unit belongs to the current live MULTI_SZ component.
                unit.read()
            };
            if value != 0 {
                continue;
            }
            if length == 0 {
                return Ok(None);
            }
            let count = length.checked_add(1).ok_or(STATUS_INVALID_BUFFER_SIZE)?;
            let path = unsafe {
                // SAFETY: The scan established the readable component including its terminator.
                core::slice::from_raw_parts(self.cursor, count)
            };
            self.cursor = unsafe {
                // SAFETY: The MULTI_SZ contract includes the next component after this NUL.
                self.cursor.add(count)
            };
            return Ok(Some(path));
        }
        Err(STATUS_INVALID_BUFFER_SIZE)
    }
}

impl Drop for VolumeInterfaces {
    #[expect(
        unsafe_code,
        reason = "the snapshot exclusively owns the PnP pool allocation"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: Exactly the original allocation returned by IoGetDeviceInterfaces.
            crate::kernel::ffi::ExFreePool(self.allocation.as_ptr().cast());
        }
    }
}

/// Borrows a terminated path for a synchronous native call. The caller retains `path`.
/// # Errors
/// Returns invalid-buffer-size for a missing terminator or an unrepresentable byte length.
pub(crate) fn unicode_string(path: &[u16]) -> Result<wdk_sys::UNICODE_STRING, NTSTATUS> {
    let content = path.strip_suffix(&[0]).ok_or(STATUS_INVALID_BUFFER_SIZE)?;
    let bytes = content
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(STATUS_INVALID_BUFFER_SIZE)?;
    let length = u16::try_from(bytes).map_err(|_| STATUS_INVALID_BUFFER_SIZE)?;
    let maximum = length.checked_add(2).ok_or(STATUS_INVALID_BUFFER_SIZE)?;
    Ok(wdk_sys::UNICODE_STRING {
        Length: length,
        MaximumLength: maximum,
        Buffer: path.as_ptr().cast_mut(),
    })
}
