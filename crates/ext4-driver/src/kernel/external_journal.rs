//! External-journal volume enumeration and exclusive kernel lifetime ownership.

use core::ffi::c_void;
use core::ptr::NonNull;

use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::ExternalJournalLease;
use crate::memory::DriverVec;
use crate::state::KernelDevice;

/// `GUID_DEVINTERFACE_VOLUME` from `ntddvol.h`.
#[cfg(not(test))]
const GUID_DEVINTERFACE_VOLUME: wdk_sys::GUID = wdk_sys::GUID {
    Data1: 0x53f5_630d,
    Data2: 0xb6bf,
    Data3: 0x11d0,
    Data4: [0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b],
};

/// Maximum UTF-16 code units representable by one `UNICODE_STRING` byte length.
#[cfg(not(test))]
const MAX_UNICODE_UNITS: usize = 32_767;

/// One shared-open volume candidate retained while core probes are scheduled.
#[derive(Debug)]
struct SharedExternalJournalCandidate {
    /// NUL-terminated device-interface path.
    path: DriverVec<u16>,
    /// File object reference returned by `IoGetDeviceObjectPointer`.
    _file_object: NonNull<wdk_sys::FILE_OBJECT>,
    /// Related top device used for lower requests.
    device: KernelDevice,
    /// Stable base-device identity used for alias exclusion and deduplication.
    base_identity: NonNull<c_void>,
}

impl Drop for SharedExternalJournalCandidate {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: `IoGetDeviceObjectPointer` transferred exactly one FILE_OBJECT reference to
            // this candidate; no other owner releases it.
            let _remaining =
                crate::kernel::ffi::ObfDereferenceObject(self._file_object.as_ptr().cast());
        }
    }
}

// SAFETY: The referenced kernel objects are immutable identities; discovery and final release are
// serialized by the mount operation on the reactor thread.
unsafe impl Send for SharedExternalJournalCandidate {}

/// Shared discovery set with at most one UUID match recorded by core validation.
#[derive(Debug)]
pub(crate) struct ExternalJournalCandidates {
    /// Distinct shared-open volumes eligible for core validation.
    candidates: DriverVec<SharedExternalJournalCandidate>,
    /// Index of the sole exact UUID/profile/user match observed so far.
    matched_index: Option<usize>,
}

impl ExternalJournalCandidates {
    /// Enumerates distinct volume interfaces excluding the mounted filesystem and its aliases.
    /// # Errors
    ///
    /// Returns an error for kernel enumeration failure or fallible ownership capture failure.
    #[cfg(not(test))]
    pub(crate) fn enumerate(filesystem: KernelDevice) -> DriverResult<Self> {
        let mut list = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: The GUID is static and `list` is writable output storage. A null PDO asks the
            // PnP manager for every present enabled volume interface.
            crate::kernel::ffi::IoGetDeviceInterfaces(
                &GUID_DEVINTERFACE_VOLUME,
                core::ptr::null_mut(),
                0,
                &raw mut list,
            )
        };
        if status < wdk_sys::STATUS_SUCCESS {
            return Err(DriverError::ExternalJournalDiscoveryFailed);
        }
        let list = InterfaceList::from_raw(list)?;
        let filesystem_base = base_device_identity(filesystem)?;
        let mut candidates: DriverVec<SharedExternalJournalCandidate> = DriverVec::new();
        let mut cursor = list.as_ptr();
        loop {
            let path_len = unsafe {
                // SAFETY: `IoGetDeviceInterfaces` returns a double-NUL-terminated MULTI_SZ whose
                // allocation stays owned by `list` for this traversal.
                terminated_length(cursor)?
            };
            if path_len == 0 {
                break;
            }
            let component_units = path_len
                .checked_add(1)
                .ok_or(DriverError::ExternalJournalDiscoveryFailed)?;
            let path = unsafe {
                // SAFETY: The preceding bounded scan established `path_len` readable units plus
                // the terminating NUL in the live MULTI_SZ allocation.
                core::slice::from_raw_parts(cursor, component_units)
            };
            if let Some(candidate) = open_shared_candidate(path)? {
                let duplicate = candidate.base_identity == filesystem_base
                    || candidates
                        .iter()
                        .any(|existing| existing.base_identity == candidate.base_identity);
                let push_result = if duplicate {
                    Ok(())
                } else {
                    candidates.try_push_owned(candidate)
                };
                if let Err(error) = push_result {
                    let (driver_error, _candidate) = error.into_parts();
                    return Err(driver_error);
                }
            }
            cursor = unsafe {
                // SAFETY: `component_units` advances exactly to the next MULTI_SZ component.
                cursor.add(component_units)
            };
        }
        Ok(Self {
            candidates,
            matched_index: None,
        })
    }

    /// Unit-test builds cannot call the live PnP manager.
    /// # Errors
    ///
    /// Always reports discovery unavailable because host tests cannot call the PnP manager.
    #[cfg(test)]
    pub(crate) fn enumerate(_filesystem: KernelDevice) -> DriverResult<Self> {
        Err(DriverError::ExternalJournalDiscoveryFailed)
    }

    /// Number of distinct probe candidates.
    pub(crate) fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Device selected for one shared probe.
    pub(crate) fn device(&self, index: usize) -> Option<KernelDevice> {
        self.candidates
            .as_slice()
            .get(index)
            .map(|candidate| candidate.device)
    }

    /// Records one exact UUID/profile/user match and rejects a second device immediately.
    /// # Errors
    ///
    /// Returns an ambiguity error if a different candidate has already matched.
    pub(crate) fn record_match(&mut self, index: usize) -> DriverResult<()> {
        if self.matched_index.replace(index).is_some() {
            return Err(DriverError::ExternalJournalAmbiguous);
        }
        Ok(())
    }

    /// Copies the unique selected path, then releases every shared open before exclusive reopen.
    /// # Errors
    ///
    /// Returns a distinct not-found result or an allocation failure.
    pub(crate) fn into_selected(self) -> DriverResult<SelectedExternalJournal> {
        let index = self
            .matched_index
            .ok_or(DriverError::ExternalJournalNotFound)?;
        let candidate = self
            .candidates
            .as_slice()
            .get(index)
            .ok_or(DriverError::InternalInvariantViolation)?;
        let selected = SelectedExternalJournal {
            path: DriverVec::try_copied_from_slice(candidate.path.as_slice())?,
            base_identity: candidate.base_identity,
        };
        drop(self);
        Ok(selected)
    }
}

/// Selected path copied independently so every shared open can be released before share-zero open.
#[derive(Debug)]
pub(crate) struct SelectedExternalJournal {
    /// NUL-terminated interface path retained after every shared open is released.
    path: DriverVec<u16>,
    /// Base-device identity observed during the shared probe.
    base_identity: NonNull<c_void>,
}

// SAFETY: The path is owned data and the identity is compared only as an opaque pointer value.
unsafe impl Send for SelectedExternalJournal {}

/// Exclusive device and RAII ownership before its geometry is queried and core validation repeats.
#[derive(Debug)]
pub(crate) struct ExclusiveExternalJournal {
    /// Related lower device reached through the exclusively opened file object.
    device: KernelDevice,
    /// Unique share-zero handle and FILE_OBJECT reference.
    lease: ExternalJournalLease,
}

impl ExclusiveExternalJournal {
    /// Reopens the selected interface with share access zero and verifies the same underlying stack.
    /// # Errors
    ///
    /// Returns a distinct exclusive-open failure for sharing, namespace races, or object lookup.
    #[cfg(not(test))]
    pub(crate) fn open(selected: SelectedExternalJournal) -> DriverResult<Self> {
        let mut name = unicode_string(selected.path.as_slice())?;
        let mut attributes = wdk_sys::OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<wdk_sys::OBJECT_ATTRIBUTES>())
                .map_err(|_| DriverError::InternalInvariantViolation)?,
            RootDirectory: core::ptr::null_mut(),
            ObjectName: &raw mut name,
            Attributes: wdk_sys::OBJ_CASE_INSENSITIVE | wdk_sys::OBJ_KERNEL_HANDLE,
            SecurityDescriptor: core::ptr::null_mut(),
            SecurityQualityOfService: core::ptr::null_mut(),
        };
        let mut io_status = wdk_sys::IO_STATUS_BLOCK::default();
        let mut handle = core::ptr::null_mut();
        let desired_access =
            wdk_sys::FILE_GENERIC_READ | wdk_sys::FILE_GENERIC_WRITE | wdk_sys::SYNCHRONIZE;
        let status = unsafe {
            // SAFETY: All native structures point to live stack storage for the duration of the
            // synchronous open. Share access zero establishes the mount-long exclusion contract.
            crate::kernel::ffi::ZwCreateFile(
                &raw mut handle,
                desired_access,
                &raw mut attributes,
                &raw mut io_status,
                core::ptr::null_mut(),
                0,
                0,
                wdk_sys::FILE_OPEN,
                wdk_sys::FILE_NON_DIRECTORY_FILE | wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT,
                core::ptr::null_mut(),
                0,
            )
        };
        if status < wdk_sys::STATUS_SUCCESS {
            return Err(DriverError::ExternalJournalExclusiveOpenFailed);
        }

        let mut object = core::ptr::null_mut();
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        let file_object_type_export = core::ptr::addr_of!(crate::kernel::ffi::IoFileObjectType);
        let file_object_type_pointer = unsafe {
            // SAFETY: The address names the WDK-exported object-type pointer storage.
            file_object_type_export.read()
        };
        let file_object_type = unsafe {
            // SAFETY: WDK initializes the exported pointer before driver entry.
            file_object_type_pointer.read()
        };
        let reference_status = unsafe {
            // SAFETY: `handle` is a live kernel file handle. The requested object type is the WDK
            // FILE_OBJECT type and `object` is writable output storage.
            crate::kernel::ffi::ObReferenceObjectByHandle(
                handle,
                desired_access,
                file_object_type,
                kernel_mode,
                &raw mut object,
                core::ptr::null_mut(),
            )
        };
        let Some(file_object) = NonNull::new(object.cast::<wdk_sys::FILE_OBJECT>()) else {
            close_handle(handle);
            return Err(DriverError::ExternalJournalExclusiveOpenFailed);
        };
        if reference_status < wdk_sys::STATUS_SUCCESS {
            close_handle(handle);
            return Err(DriverError::ExternalJournalExclusiveOpenFailed);
        }
        let related = unsafe {
            // SAFETY: The explicit object reference keeps `file_object` live through related-device
            // lookup and transfer into the lease.
            crate::kernel::ffi::IoGetRelatedDeviceObject(file_object.as_ptr())
        };
        let Some(device) = KernelDevice::from_raw(related) else {
            release_file_and_handle(file_object, handle);
            return Err(DriverError::ExternalJournalExclusiveOpenFailed);
        };
        match base_device_identity(device) {
            Ok(identity) if identity == selected.base_identity => {}
            Ok(_) | Err(_) => {
                release_file_and_handle(file_object, handle);
                return Err(DriverError::ExternalJournalExclusiveOpenFailed);
            }
        }
        let lease = unsafe {
            // SAFETY: The successful open and object-reference calls transferred one ownership of
            // each resource; this is the sole RAII owner from this point forward.
            ExternalJournalLease::from_exclusive(handle, file_object)
        };
        Ok(Self { device, lease })
    }

    #[cfg(test)]
    /// Host tests cannot forge an exclusive kernel volume lifetime.
    /// # Errors
    ///
    /// Always reports that the exclusive reopen failed.
    pub(crate) fn open(selected: SelectedExternalJournal) -> DriverResult<Self> {
        let SelectedExternalJournal {
            path,
            base_identity,
        } = selected;
        drop(path);
        let _identity = base_identity;
        Err(DriverError::ExternalJournalExclusiveOpenFailed)
    }

    /// Related lower device used for the exclusive length query.
    pub(crate) const fn device(&self) -> KernelDevice {
        self.device
    }

    /// Separates the device identity from mount-long ownership.
    pub(crate) fn into_parts(self) -> (KernelDevice, ExternalJournalLease) {
        (self.device, self.lease)
    }
}

#[cfg(not(test))]
#[derive(Debug)]
/// System-pool MULTI_SZ returned by `IoGetDeviceInterfaces`.
struct InterfaceList(NonNull<u16>);

#[cfg(not(test))]
impl InterfaceList {
    /// Takes ownership of one WDK-allocated interface list.
    /// # Errors
    ///
    /// Returns discovery failure when WDK reports success with a null allocation.
    fn from_raw(list: *mut u16) -> DriverResult<Self> {
        NonNull::new(list)
            .map(Self)
            .ok_or(DriverError::ExternalJournalDiscoveryFailed)
    }

    /// Returns the first UTF-16 unit of the owned MULTI_SZ allocation.
    const fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

#[cfg(not(test))]
impl Drop for InterfaceList {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: `IoGetDeviceInterfaces` allocated this buffer from system pool and transferred
            // its sole release responsibility to the caller.
            crate::kernel::ffi::ExFreePool(self.0.as_ptr().cast());
        }
    }
}

#[cfg(not(test))]
/// Finds the terminating NUL of one MULTI_SZ component.
///
/// # Safety
///
/// `start` must point to a readable component in the live buffer returned by
/// `IoGetDeviceInterfaces`, terminated within `MAX_UNICODE_UNITS` code units.
///
/// # Errors
///
/// Returns discovery failure when no representable terminator is found.
unsafe fn terminated_length(start: *const u16) -> DriverResult<usize> {
    for length in 0..=MAX_UNICODE_UNITS {
        let unit_ptr = unsafe {
            // SAFETY: The caller guarantees a live MULTI_SZ component and the scan remains within
            // the documented representable bound.
            start.add(length)
        };
        let unit = unsafe {
            // SAFETY: `unit_ptr` is the current readable unit guaranteed by the caller.
            unit_ptr.read()
        };
        if unit == 0 {
            return Ok(length);
        }
    }
    Err(DriverError::ExternalJournalDiscoveryFailed)
}

#[cfg(not(test))]
/// Borrows one NUL-terminated owned path as a WDK `UNICODE_STRING`.
/// # Errors
///
/// Returns discovery failure for a missing terminator and invalid-buffer-size for an
/// unrepresentable UTF-16 byte length.
fn unicode_string(path: &[u16]) -> DriverResult<wdk_sys::UNICODE_STRING> {
    let content = path
        .strip_suffix(&[0])
        .ok_or(DriverError::ExternalJournalDiscoveryFailed)?;
    let length = u16::try_from(
        content
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or(DriverError::InvalidBufferSize)?,
    )
    .map_err(|_| DriverError::InvalidBufferSize)?;
    let maximum_length = length
        .checked_add(u16::try_from(size_of::<u16>()).map_err(|_| DriverError::InvalidBufferSize)?)
        .ok_or(DriverError::InvalidBufferSize)?;
    Ok(wdk_sys::UNICODE_STRING {
        Length: length,
        MaximumLength: maximum_length,
        Buffer: path.as_ptr().cast_mut(),
    })
}

#[cfg(not(test))]
/// Opens one interface for shared discovery and captures its kernel ownership.
/// # Errors
///
/// Returns an error for malformed paths, kernel identity failures, or allocation failure. An
/// inaccessible interface is not a structural error and produces `None`.
fn open_shared_candidate(path: &[u16]) -> DriverResult<Option<SharedExternalJournalCandidate>> {
    let owned_path = DriverVec::try_copied_from_slice(path)?;
    let mut name = unicode_string(path)?;
    let mut file_object = core::ptr::null_mut();
    let mut device = core::ptr::null_mut();
    let status = unsafe {
        // SAFETY: `name` references the live interface list and both output pointers are writable.
        crate::kernel::ffi::IoGetDeviceObjectPointer(
            &raw mut name,
            wdk_sys::FILE_READ_ATTRIBUTES,
            &raw mut file_object,
            &raw mut device,
        )
    };
    if status < wdk_sys::STATUS_SUCCESS {
        return Ok(None);
    }
    let Some(file_object) = NonNull::new(file_object) else {
        return Err(DriverError::ExternalJournalDiscoveryFailed);
    };
    let Some(device) = KernelDevice::from_raw(device) else {
        unsafe {
            // SAFETY: A successful `IoGetDeviceObjectPointer` transferred this reference even if
            // its companion device output was unexpectedly null.
            let _remaining = crate::kernel::ffi::ObfDereferenceObject(file_object.as_ptr().cast());
        }
        return Err(DriverError::ExternalJournalDiscoveryFailed);
    };
    let base_identity = match base_device_identity(device) {
        Ok(identity) => identity,
        Err(error) => {
            unsafe {
                // SAFETY: This is the sole reference transferred by `IoGetDeviceObjectPointer`.
                let _remaining =
                    crate::kernel::ffi::ObfDereferenceObject(file_object.as_ptr().cast());
            }
            return Err(error);
        }
    };
    Ok(Some(SharedExternalJournalCandidate {
        path: owned_path,
        _file_object: file_object,
        device,
        base_identity,
    }))
}

#[cfg(not(test))]
/// Captures the referenced base device, records its stable identity, and releases the reference.
/// # Errors
///
/// Returns discovery failure if WDK does not produce a base device.
fn base_device_identity(device: KernelDevice) -> DriverResult<NonNull<c_void>> {
    let base = unsafe {
        // SAFETY: The input is a live device identity and the WDK returns one referenced base
        // device object, released below after its stable pointer value is captured.
        crate::kernel::ffi::IoGetDeviceAttachmentBaseRef(device.as_ptr())
    };
    let base = NonNull::new(base.cast()).ok_or(DriverError::ExternalJournalDiscoveryFailed)?;
    unsafe {
        // SAFETY: `IoGetDeviceAttachmentBaseRef` returned exactly one temporary reference.
        let _remaining = crate::kernel::ffi::ObfDereferenceObject(base.as_ptr());
    }
    Ok(base)
}

#[cfg(not(test))]
/// Releases a successful pre-lease `ZwCreateFile` handle.
fn close_handle(handle: wdk_sys::HANDLE) {
    unsafe {
        // SAFETY: Called only for a handle successfully returned by `ZwCreateFile` before lease
        // ownership is constructed.
        let _status = crate::kernel::ffi::ZwClose(handle);
    }
}

#[cfg(not(test))]
/// Releases both pre-lease ownerships after exclusive-open validation fails.
fn release_file_and_handle(file_object: NonNull<wdk_sys::FILE_OBJECT>, handle: wdk_sys::HANDLE) {
    unsafe {
        // SAFETY: This is the sole pre-lease ownership from `ObReferenceObjectByHandle`.
        let _remaining = crate::kernel::ffi::ObfDereferenceObject(file_object.as_ptr().cast());
    }
    unsafe {
        // SAFETY: This is the sole pre-lease ownership from `ZwCreateFile`.
        let _status = crate::kernel::ffi::ZwClose(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::DriverError;

    /// # Panics
    ///
    /// Panics if a non-null kernel identity is rejected or host tests enter live PnP discovery.
    #[test]
    fn live_discovery_is_not_forged_by_host_tests() {
        let device = super::KernelDevice::from_raw(
            core::ptr::NonNull::<wdk_sys::DEVICE_OBJECT>::dangling().as_ptr(),
        );
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        assert!(matches!(
            super::ExternalJournalCandidates::enumerate(device),
            Err(DriverError::ExternalJournalDiscoveryFailed)
        ));
    }
}
