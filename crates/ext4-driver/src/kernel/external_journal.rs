//! External-journal volume enumeration and exclusive kernel lifetime ownership.

use core::ffi::c_void;
use core::ptr::NonNull;

#[cfg(not(test))]
use crate::kernel::device_interface::{VolumeInterfaceClass, VolumeInterfaces, unicode_string};
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::storage::ExternalJournalLease;
use crate::memory::DriverVec;
use crate::state::KernelDevice;

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
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
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

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
        let filesystem_base = base_device_identity(filesystem)?;
        let mut candidates: DriverVec<SharedExternalJournalCandidate> = DriverVec::new();
        for class in [VolumeInterfaceClass::Visible, VolumeInterfaceClass::Hidden] {
            let mut list = VolumeInterfaces::enumerate(class)
                .map_err(|_| DriverError::ExternalJournalDiscoveryFailed)?;
            while let Some(path) = list
                .next_path()
                .map_err(|_| DriverError::ExternalJournalDiscoveryFailed)?
            {
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
            }
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

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn open(selected: SelectedExternalJournal) -> DriverResult<Self> {
        let mut name = unicode_string(selected.path.as_slice())
            .map_err(|_| DriverError::ExternalJournalDiscoveryFailed)?;
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
        let Some(device) = (unsafe {
            // SAFETY: The explicit FILE_OBJECT reference retains its related device for the lease.
            KernelDevice::from_raw(related)
        }) else {
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
/// Opens one interface for shared discovery and captures its kernel ownership.
/// # Errors
///
/// Returns an error for malformed paths, kernel identity failures, or allocation failure. An
/// inaccessible interface is not a structural error and produces `None`.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn open_shared_candidate(path: &[u16]) -> DriverResult<Option<SharedExternalJournalCandidate>> {
    let owned_path = DriverVec::try_copied_from_slice(path)?;
    let mut name = unicode_string(path).map_err(|_| DriverError::ExternalJournalDiscoveryFailed)?;
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
    let Some(device) = (unsafe {
        // SAFETY: Successful IoGetDeviceObjectPointer returned this referenced live device.
        KernelDevice::from_raw(device)
    }) else {
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn close_handle(handle: wdk_sys::HANDLE) {
    unsafe {
        // SAFETY: Called only for a handle successfully returned by `ZwCreateFile` before lease
        // ownership is constructed.
        let _status = crate::kernel::ffi::ZwClose(handle);
    }
}

#[cfg(not(test))]
/// Releases both pre-lease ownerships after exclusive-open validation fails.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
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
    use crate::memory;

    /// # Panics
    ///
    /// Panics if a non-null kernel identity is rejected or host tests enter live PnP discovery.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn live_discovery_is_not_forged_by_host_tests() {
        let Ok(mut device_fixture) =
            memory::boxed_try_with(|| Ok(wdk_sys::DEVICE_OBJECT::default()))
        else {
            return;
        };
        let device = unsafe {
            // SAFETY: The boxed DEVICE_OBJECT remains alive through the host-guard call.
            super::KernelDevice::from_raw(device_fixture.as_mut())
        };
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
