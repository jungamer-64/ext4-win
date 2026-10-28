//! Paging-map ownership. The FCB retains this state through original-IRP completion.
//!
//! Setup owns an unpublished map; extension keeps the acknowledged prefix usable.
//! Retirement closes admission and drains every transfer before allocation can be released.
//! Native code captures IRP fields, forwards the original request and contains query-pointer SEH.

use super::notification::AdmissionNotification;
use super::status::{DriverError, DriverResult};
use crate::memory::NativeAllocation;
use crate::state::{KernelDevice, KernelFileObject};
#[cfg(not(test))]
use core::cell::UnsafeCell;
use core::{ffi::c_void, ptr::NonNull};
use ext4_core::{ByteOffset, FileSize};

/// Physical prefix acknowledged before unique native paging setup admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PagingFileClaim {
    /// No direct paging address has been published.
    Initial,
    /// Existing direct I/O continues over this acknowledged physical prefix.
    Extension {
        /// Lower-device coordinate that subsequent map publication must preserve.
        physical: ext4_core::ByteOffset,
        /// Previously acknowledged prefix; extension may only append beyond it.
        length: FileSize,
    },
}

/// Unique paging setup reservation; its enclosing deferred FCB lease retains `header`.
#[derive(Debug)]
pub(crate) struct PagingFileReservation {
    /// Shared Rust lifecycle retained by the constructing FCB lease.
    state: NonNull<PagingFile>,
    /// Address-stable native FCB retained independently by the constructing owner.
    header: NonNull<c_void>,
    /// Initial admission or immutable-prefix extension.
    claim: PagingFileClaim,
    /// Consumption prevents rollback after map publication.
    phase: PagingReservationPhase,
}

/// Local ownership transition, distinct from the shared map's admission phase.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "only the production native activation can publish an acknowledged paging map"
    )
)]
enum PagingReservationPhase {
    /// Dropping setup releases the unique native reservation without publishing a map.
    Reserved,
    /// Native map publication consumed rollback authority.
    Activated,
}

impl PagingFileReservation {
    /// Acquires the unique setup transition under an enclosing deferred FCB lease.
    /// # Safety
    /// The caller must retain this exact allocation and header through consumption or drop.
    /// Initial setup must own the unpublished first-open claim and exclude native residency.
    /// # Errors
    /// Rejects competing setup or retirement before acquiring rollback ownership.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the caller retains the FCB owner through the returned raw-pointer reservation"
    )]
    pub(super) unsafe fn acquire(
        state: &NativeAllocation<PagingFile>,
        header: NonNull<c_void>,
        owner: KernelFileObject,
        extension: bool,
    ) -> DriverResult<Self> {
        let claim = state.get().reserve(owner, extension)?;
        Ok(Self {
            state: state.address(),
            header,
            claim,
            phase: PagingReservationPhase::Reserved,
        })
    }
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
            reason = "the enclosing FCB lease retains the setup reservation through activation"
        )
    )]
    pub(crate) fn activate(
        mut self,
        storage: ext4_core::ContiguousFileStorage,
        lower: KernelDevice,
        sector: crate::state::TransferSectorSize,
    ) -> DriverResult<()> {
        let logical_size = i64::try_from(storage.logical_size().bytes())
            .map_err(|_| DriverError::InvalidParameter)?;
        #[cfg(not(test))]
        {
            let (mut allocation, mut eof, mut valid, mut charge) = (0, 0, 0, 0);
            let status = unsafe {
                // SAFETY: The deferred FCB lease retains this header and exclusive local outputs.
                super::ffi::ext4win_stream_get_sizes(
                    self.header.as_ptr(),
                    &raw mut allocation,
                    &raw mut eof,
                    &raw mut valid,
                    &raw mut charge,
                )
            };
            if status < wdk_sys::STATUS_SUCCESS {
                return Err(DriverError::InternalInvariantViolation);
            }
            if eof != logical_size {
                return Err(DriverError::InvalidParameter);
            }
            // SAFETY: The deferred FCB lease retains the original shared paging allocation.
            unsafe { self.state.as_ref() }.activate(self.claim, storage, lower, sector)?;
            if matches!(self.claim, PagingFileClaim::Initial) {
                // SAFETY: This live header is now owned by the activated Rust paging map.
                unsafe { super::ffi::ext4win_stream_mark_paging_file(self.header.as_ptr()) };
            }
            self.phase = PagingReservationPhase::Activated;
            Ok(())
        }
        #[cfg(test)]
        {
            let _inputs = (&mut self, storage, logical_size, lower, sector);
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
                // SAFETY: The deferred FCB lease retains the shared Rust lifecycle through rollback.
                self.state.as_ref().abort(self.claim);
            }
            #[cfg(test)]
            {
                let _identity = (self.header, self.state);
            }
        }
    }
}

/// Validated physical route retained by the enclosing mounted FCB.
#[derive(Clone, Copy, Debug)]
struct Mapping {
    /// Lower device whose lifetime encloses every mapped file and completion.
    lower: KernelDevice,
    /// Signed lower-device byte coordinate established before activation.
    physical: ByteOffset,
    /// Home-checkpointed initialized prefix.
    length: FileSize,
    /// Required byte alignment of original-IRP transfers.
    sector: u32,
}

impl Mapping {
    /// Validates every arithmetic and native signed-domain precondition before publication.
    /// # Errors
    /// Rejects an empty, misaligned or unrepresentable physical interval.
    fn new(
        lower: KernelDevice,
        physical: ByteOffset,
        length: FileSize,
        sector: u32,
    ) -> DriverResult<Self> {
        let end = physical
            .get()
            .checked_add(length.bytes())
            .ok_or(DriverError::InvalidParameter)?;
        if length.bytes() == 0
            || i64::try_from(end).is_err()
            || sector == 0
            || !physical.get().is_multiple_of(u64::from(sector))
            || !length.bytes().is_multiple_of(u64::from(sector))
        {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self {
            lower,
            physical,
            length,
            sector,
        })
    }
}

/// Published map and its outstanding transfer ownership move together between phases.
#[derive(Clone, Copy, Debug)]
struct OwnedMapping {
    /// Only this activating FILE_OBJECT may retire the map.
    owner: KernelFileObject,
    /// Validated physical prefix.
    mapping: Mapping,
    /// Each admitted original IRP consumes exactly one completion obligation.
    in_flight: u32,
}

/// Sole shared lifecycle authority; phases without a map cannot expose a physical route.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// Ordinary filesystem I/O retains dispatch authority.
    Vacant,
    /// One setup owns initial publication; ordinary transfers remain excluded.
    Preparing(KernelFileObject),
    /// Direct paging I/O may use the acknowledged map.
    Active(OwnedMapping),
    /// One setup owns the tail while the existing prefix remains usable.
    Extending(OwnedMapping),
    /// New I/O is closed while admitted completions drain.
    Retiring(OwnedMapping),
    /// Native retirement completed; allocation deletion is permitted.
    Retired,
}

/// Address-stable, nonpaged shared state; all phase and event transitions share one lock.
pub(super) struct PagingFile {
    /// Kernel transition serialization, including notification publication.
    #[cfg(not(test))]
    lock: UnsafeCell<wdk_sys::KSPIN_LOCK>,
    /// No Rust reference to this phase escapes its transition scope.
    #[cfg(not(test))]
    phase: UnsafeCell<Phase>,
    /// Host synchronization executes the same lifecycle transitions.
    #[cfg(test)]
    phase: std::sync::Mutex<Phase>,
    /// Signaled exactly when no original IRP owns a transfer obligation.
    idle: AdmissionNotification,
    /// Signaled when the unique setup or extension has resolved.
    setup_done: AdmissionNotification,
}

/// File mutations whose effect depends on the acknowledged paging-map lifecycle.
#[derive(Clone, Copy)]
pub(super) enum PagingMutation {
    /// Changes logical EOF while preserving the initialized physical backing bound.
    Resize {
        /// Requested logical EOF.
        file_size: FileSize,
        /// Backing section bound retained by the requested size projection.
        allocation: FileSize,
    },
    /// Releases physical backing after native retirement.
    Delete,
}

impl PagingFile {
    /// Allocates and initializes notifications before publishing any native callback pointer.
    /// # Errors
    /// Returns nonpaged allocation failure before setup or transfer admission.
    pub(super) fn try_new() -> DriverResult<NativeAllocation<Self>> {
        let owner = NativeAllocation::from_box(crate::memory::boxed_try_with(|| {
            Ok(Self {
                #[cfg(not(test))]
                lock: UnsafeCell::new(0),
                #[cfg(not(test))]
                phase: UnsafeCell::new(Phase::Vacant),
                #[cfg(test)]
                phase: std::sync::Mutex::new(Phase::Vacant),
                idle: AdmissionNotification::new(),
                setup_done: AdmissionNotification::new(),
            })
        })?);
        owner.get().idle.initialize();
        owner.get().setup_done.initialize();
        Ok(owner)
    }

    /// Serializes a complete logical transition with its notification projection.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the nonpaged phase is accessed only under its enclosing spin lock"
        )
    )]
    fn transition<R>(&self, operation: impl FnOnce(&mut Phase) -> R) -> R {
        #[cfg(not(test))]
        {
            // SAFETY: This retained nonpaged owner keeps its initialized spin lock live.
            let irql = unsafe { super::ffi::KeAcquireSpinLockRaiseToDpc(self.lock.get()) };
            // SAFETY: The lock grants unique phase access until release below.
            let result = operation(unsafe { &mut *self.phase.get() });
            // SAFETY: The same thread releases its lock and restores its incoming IRQL.
            unsafe { super::ffi::KeReleaseSpinLock(self.lock.get(), irql) };
            result
        }
        #[cfg(test)]
        operation(&mut self.phase.lock().unwrap_or_else(|_| corruption()))
    }

    /// Special-file ownership includes unpublished setup and completed retirement.
    pub(super) fn is_special(&self) -> bool {
        self.transition(|phase| !matches!(phase, Phase::Vacant))
    }

    /// Returns only the acknowledged prefix available to direct transfers.
    pub(super) fn length(&self) -> FileSize {
        self.transition(|phase| match phase {
            Phase::Active(map) | Phase::Extending(map) => map.mapping.length,
            _ => FileSize::from_bytes(0),
        })
    }

    /// Claims initial setup or the unique extension while retaining the existing prefix.
    /// # Errors
    /// Rejects competing setup, retirement or an extension without an active map.
    fn reserve(&self, owner: KernelFileObject, extension: bool) -> DriverResult<PagingFileClaim> {
        self.transition(|phase| {
            let claim = match (*phase, extension) {
                (Phase::Vacant, false) => {
                    *phase = Phase::Preparing(owner);
                    PagingFileClaim::Initial
                }
                (Phase::Active(map), true) => {
                    *phase = Phase::Extending(map);
                    PagingFileClaim::Extension {
                        physical: map.mapping.physical,
                        length: map.mapping.length,
                    }
                }
                _ => return Err(DriverError::ShareAccessConflict),
            };
            self.setup_done.publish(false);
            Ok(claim)
        })
    }

    /// Releases only the still-unpublished setup represented by this unique reservation.
    /// Retirement of an unpublished owner revokes setup; dropping that reservation cannot reopen it.
    fn abort(&self, claim: PagingFileClaim) {
        self.transition(|phase| {
            *phase = match (*phase, claim) {
                (Phase::Preparing(_), PagingFileClaim::Initial) => Phase::Vacant,
                (Phase::Extending(map), PagingFileClaim::Extension { .. }) => Phase::Active(map),
                (Phase::Retired, _) => return,
                _ => corruption(),
            };
            self.setup_done.publish(true);
        });
    }

    /// Consumes setup into an initialized physical route, preserving any active prefix and leases.
    /// # Errors
    /// Rejects changed physical identity, a shrinking prefix or mismatched reservation before publication.
    #[cfg(not(test))]
    fn activate(
        &self,
        claim: PagingFileClaim,
        storage: ext4_core::ContiguousFileStorage,
        lower: KernelDevice,
        sector: crate::state::TransferSectorSize,
    ) -> DriverResult<()> {
        let mapping = Mapping::new(
            lower,
            storage.physical(),
            storage.initialized_length(),
            sector.as_u32(),
        )?;
        self.publish(claim, mapping)
    }

    /// Publishes a validated map under the shared setup/retirement serialization boundary.
    /// # Errors
    /// Rejects stale setup or discontinuous extension before changing the acknowledged map.
    fn publish(&self, claim: PagingFileClaim, mapping: Mapping) -> DriverResult<()> {
        self.transition(|phase| {
            let map = match (*phase, claim) {
                (Phase::Preparing(owner), PagingFileClaim::Initial) => OwnedMapping {
                    owner,
                    mapping,
                    in_flight: 0,
                },
                (Phase::Extending(map), PagingFileClaim::Extension { physical, length })
                    if map.mapping.physical == physical
                        && map.mapping.length == length
                        && mapping.physical == physical
                        && mapping.length >= length
                        && mapping.lower == map.mapping.lower
                        && mapping.sector == map.mapping.sector =>
                {
                    OwnedMapping { mapping, ..map }
                }
                _ => return Err(DriverError::InvalidParameter),
            };
            *phase = Phase::Active(map);
            self.setup_done.publish(true);
            Ok(())
        })
    }

    /// File mutation admission uses typed logical and physical-size coordinates.
    pub(super) fn permits_mutation(&self, operation: PagingMutation) -> bool {
        self.transition(|phase| match (*phase, operation) {
            (Phase::Vacant, _) | (Phase::Retired, PagingMutation::Delete) => true,
            (
                Phase::Preparing(_),
                PagingMutation::Resize {
                    file_size,
                    allocation,
                },
            ) => allocation >= file_size,
            (
                Phase::Active(map),
                PagingMutation::Resize {
                    file_size,
                    allocation,
                },
            ) => {
                allocation >= file_size
                    && file_size <= map.mapping.length
                    && allocation >= map.mapping.length
            }
            (
                Phase::Extending(map),
                PagingMutation::Resize {
                    file_size,
                    allocation,
                },
            ) => allocation >= file_size && allocation >= map.mapping.length,
            _ => false,
        })
    }
    /// Only the activating FILE_OBJECT may close admission and wait for original-IRP completion.
    fn retire(&self, owner: KernelFileObject) {
        loop {
            let waiting = self.transition(|phase| match *phase {
                Phase::Extending(map) if map.owner == owner => Some(&self.setup_done),
                Phase::Active(map) | Phase::Retiring(map) if map.owner == owner => {
                    if map.in_flight == 0 {
                        *phase = Phase::Retired;
                        None
                    } else {
                        *phase = Phase::Retiring(map);
                        Some(&self.idle)
                    }
                }
                Phase::Preparing(activating) if activating == owner => {
                    *phase = Phase::Retired;
                    self.setup_done.publish(true);
                    None
                }
                _ => None,
            });
            match waiting {
                Some(event) => event.wait(),
                None => return,
            }
        }
    }

    /// Validates the requested physical transfer and acquires one completion obligation atomically.
    fn begin(
        &self,
        offset: i64,
        length: u32,
        request_valid: bool,
        storage_available: bool,
    ) -> Transfer {
        self.transition(|phase| {
            let map = match phase {
                Phase::Vacant => return Transfer::Fallback,
                Phase::Active(map) | Phase::Extending(map) => map,
                _ => return Transfer::Complete(wdk_sys::STATUS_FILE_CLOSED),
            };
            if !storage_available {
                return Transfer::Complete(wdk_sys::STATUS_DEVICE_NOT_CONNECTED);
            }
            let Ok(offset) = u64::try_from(offset) else {
                return Transfer::Complete(wdk_sys::STATUS_INVALID_PARAMETER);
            };
            if !request_valid
                || offset
                    .checked_add(u64::from(length))
                    .is_none_or(|end| end > map.mapping.length.bytes())
                || !offset.is_multiple_of(u64::from(map.mapping.sector))
                || !length.is_multiple_of(map.mapping.sector)
            {
                return Transfer::Complete(wdk_sys::STATUS_INVALID_PARAMETER);
            }
            if length == 0 {
                return Transfer::Complete(wdk_sys::STATUS_SUCCESS);
            }
            let Some(count) = map.in_flight.checked_add(1) else {
                return Transfer::Complete(wdk_sys::STATUS_INSUFFICIENT_RESOURCES);
            };
            map.in_flight = count;
            if count == 1 {
                self.idle.publish(false);
            }
            Transfer::Forward {
                lower: map.mapping.lower,
                physical: map
                    .mapping
                    .physical
                    .get()
                    .checked_add(offset)
                    .unwrap_or_else(|| corruption()),
            }
        })
    }

    /// Consumes the exact transfer obligation before native code releases its FILE_OBJECT reference.
    fn complete(&self) {
        self.transition(|phase| {
            let map = match phase {
                Phase::Active(map) | Phase::Extending(map) | Phase::Retiring(map) => map,
                _ => corruption(),
            };
            map.in_flight = map.in_flight.checked_sub(1).unwrap_or_else(|| corruption());
            if map.in_flight == 0 {
                self.idle.publish(true);
            }
        });
    }

    /// A kernel query may expose only the initialized, currently acknowledged prefix.
    fn query(&self, requested: i64) -> Option<ByteOffset> {
        self.transition(|phase| match phase {
            Phase::Active(map) | Phase::Extending(map)
                if requested > 0 && requested.unsigned_abs() <= map.mapping.length.bytes() =>
            {
                Some(map.mapping.physical)
            }
            _ => None,
        })
    }
}

/// A transfer decision retains whether native code must complete, fall back or forward exactly once.
#[derive(Debug)]
enum Transfer {
    /// Ordinary dispatch still owns the unconsumed IRP.
    Fallback,
    /// No lower transfer was admitted.
    Complete(wdk_sys::NTSTATUS),
    /// One acquired obligation must be consumed by lower completion.
    Forward {
        /// Retained lower route.
        lower: KernelDevice,
        /// Signed-domain-validated lower byte coordinate.
        physical: u64,
    },
}

/// Terminates when a completion or reservation no longer identifies its unique owner.
fn corruption() -> ! {
    super::fatal::KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck()
}

#[expect(
    unsafe_code,
    reason = "the sole lock serializes phase and notification access in address-stable storage"
)]
// SAFETY: Moving the allocation owner cannot move native state; FCB teardown follows all callbacks.
unsafe impl Send for PagingFile {}
#[expect(
    unsafe_code,
    reason = "native observers mutate state only under its transition lock"
)]
// SAFETY: Phase references never escape the shared lock; notifications support concurrent waiters.
unsafe impl Sync for PagingFile {}

/// Native transfer selection retains one in-flight obligation only for a forwarded request.
/// # Safety
/// `state` is retained by the FCB; outputs are exclusive initialized native local storage.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native transport borrows retained state and local route outputs"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_paging_begin(
    state: *const PagingFile,
    offset: i64,
    length: u32,
    request_valid: u8,
    storage_available: u8,
    status: *mut wdk_sys::NTSTATUS,
    lower: *mut wdk_sys::PDEVICE_OBJECT,
    physical: *mut i64,
) -> u8 {
    // SAFETY: The original IRP's FILE_OBJECT reference retains this callback state.
    let transfer =
        unsafe { &*state }.begin(offset, length, request_valid != 0, storage_available != 0);
    match transfer {
        Transfer::Fallback => 0,
        Transfer::Complete(result) => {
            // SAFETY: The caller lends exclusive native status storage.
            unsafe { status.write(result) };
            1
        }
        Transfer::Forward {
            lower: route,
            physical: address,
        } => {
            // SAFETY: The caller lends exclusive native lower-route storage.
            unsafe { lower.write(route.as_ptr()) };
            // SAFETY: Mapping construction bounded the entire interval to the signed domain.
            unsafe { physical.write(i64::try_from(address).unwrap_or_else(|_| corruption())) };
            2
        }
    }
}

/// Consumes a forwarded original IRP's completion obligation.
/// # Safety
/// `state` is retained by the completion's referenced FILE_OBJECT and owns one admitted transfer.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native completion retains the FCB through its FILE_OBJECT reference"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_paging_complete_transfer(state: *const PagingFile) {
    // SAFETY: Completion retains its original, non-null callback state through this call.
    unsafe { &*state }.complete();
}

/// Observes acknowledged physical query authority without granting setup or retirement rights.
/// # Safety
/// Native dispatch retains `state` and lends exclusive local physical-coordinate storage.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "query dispatch borrows only retained state and native local outputs"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_paging_query_prefix(
    state: *const PagingFile,
    requested: i64,
    physical: *mut i64,
) -> u8 {
    // SAFETY: The original query IRP retains the FCB and its callback state.
    let selected = unsafe { &*state }.query(requested);
    if let Some(address) = selected {
        // SAFETY: The caller lends exclusive local output; map construction bounded this coordinate.
        unsafe { physical.write(i64::try_from(address.get()).unwrap_or_else(|_| corruption())) };
        1
    } else {
        0
    }
}

/// Native cache callbacks observe special-file ownership without interpreting lifecycle encodings.
/// # Safety
/// A non-null `state` is retained by the enclosing native stream.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native cache callbacks retain the original paging allocation"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_paging_is_special(state: *const PagingFile) -> u8 {
    if state.is_null() {
        return 0;
    }
    // SAFETY: A non-null pointer identifies the stream's retained node paging state.
    u8::from(unsafe { &*state }.is_special())
}

/// Native cache-map teardown retires only the FILE_OBJECT that activated paging.
/// # Safety
/// Native teardown retains both `state` and `file` until the blocking retirement completes.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native teardown lends retained paging state and owner identity"
)]
#[unsafe(no_mangle)]
unsafe extern "system" fn ext4win_paging_retire_owner(
    state: *const PagingFile,
    file: wdk_sys::PFILE_OBJECT,
) {
    if state.is_null() {
        return;
    }
    // SAFETY: Teardown retains this live FILE_OBJECT through retirement.
    let owner = unsafe { KernelFileObject::from_raw(file) }.unwrap_or_else(|| corruption());
    // SAFETY: The enclosing stream retains the paging state through the call.
    unsafe { &*state }.retire(owner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    /// Establishes native identity fixtures whose backing objects enclose the test's state owner.
    #[expect(
        unsafe_code,
        reason = "fixtures retain the initialized native objects and never dereference them through copied identities"
    )]
    fn identities(
        device: &mut wdk_sys::DEVICE_OBJECT,
        file: &mut wdk_sys::FILE_OBJECT,
    ) -> (KernelDevice, KernelFileObject) {
        // SAFETY: The fixture retains this initialized device through all map and callback uses.
        let device = unsafe { KernelDevice::from_raw(device) }.unwrap_or_else(|| corruption());
        // SAFETY: The fixture retains this initialized file through all setup and retirement uses.
        let file = unsafe { KernelFileObject::from_raw(file) }.unwrap_or_else(|| corruption());
        (device, file)
    }

    /// Constructs a requested logical EOF and retained backing bound independently from production sizing.
    fn resize(logical: u64, allocation: u64) -> PagingMutation {
        PagingMutation::Resize {
            file_size: FileSize::from_bytes(logical),
            allocation: FileSize::from_bytes(allocation),
        }
    }

    /// # Errors
    /// Returns fixture allocation, mapping or reservation failure.
    /// # Panics
    /// Fails if an owner retired during setup can publish or restore its revoked map.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup precedes revocation assertions"
    )]
    fn retired_initial_setup_cannot_publish_or_restore_reservation() -> DriverResult<()> {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file = wdk_sys::FILE_OBJECT::default();
        let (lower, file) = identities(&mut device, &mut file);
        let owner = PagingFile::try_new()?;
        let state = owner.get();
        let claim = state.reserve(file, false)?;
        state.retire(file);
        let mapping = Mapping::new(
            lower,
            ByteOffset::new(1_048_576),
            FileSize::from_bytes(65_536),
            512,
        )?;
        assert_eq!(
            state.publish(claim, mapping),
            Err(DriverError::InvalidParameter)
        );
        state.abort(claim);
        assert!(state.reserve(file, false).is_err());
        assert!(state.permits_mutation(PagingMutation::Delete));
        Ok(())
    }
    /// # Errors
    /// Returns fixture allocation or physical-domain validation failure.
    /// # Panics
    /// Fails if setup, extension, deletion or transfer bounds lose their physical ownership contract.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup precedes lifecycle and known-coordinate assertions"
    )]
    fn acknowledged_prefix_controls_transfers_extensions_and_mutation() -> DriverResult<()> {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file = wdk_sys::FILE_OBJECT::default();
        let (lower, file) = identities(&mut device, &mut file);
        let owner = PagingFile::try_new()?;
        let state = owner.get();
        assert!(matches!(
            state.begin(0, 4096, true, true),
            Transfer::Fallback
        ));
        let claim = state.reserve(file, false)?;
        assert!(state.is_special());
        assert!(state.reserve(file, false).is_err());
        assert!(matches!(
            state.begin(0, 4096, true, true),
            Transfer::Complete(wdk_sys::STATUS_FILE_CLOSED)
        ));
        state.abort(claim);
        assert!(!state.is_special());
        let claim = state.reserve(file, false)?;
        let mapping = Mapping::new(
            lower,
            ByteOffset::new(1_048_576),
            FileSize::from_bytes(65_536),
            512,
        )?;
        state.publish(claim, mapping)?;
        assert_eq!(state.length(), FileSize::from_bytes(65_536));
        assert_eq!(state.query(65_536), Some(ByteOffset::new(1_048_576)));
        assert_eq!(state.query(65_537), None);
        assert_eq!(state.query(0), None);
        assert_eq!(state.query(-1), None);
        for (offset, length, valid, available, expected) in [
            (-1, 4096, true, true, wdk_sys::STATUS_INVALID_PARAMETER),
            (65_536, 512, true, true, wdk_sys::STATUS_INVALID_PARAMETER),
            (1, 512, true, true, wdk_sys::STATUS_INVALID_PARAMETER),
            (0, 513, true, true, wdk_sys::STATUS_INVALID_PARAMETER),
            (0, 4096, false, true, wdk_sys::STATUS_INVALID_PARAMETER),
            (0, 4096, true, false, wdk_sys::STATUS_DEVICE_NOT_CONNECTED),
            (65_536, 0, true, true, wdk_sys::STATUS_SUCCESS),
        ] {
            assert!(
                matches!(state.begin(offset, length, valid, available), Transfer::Complete(status) if status == expected)
            );
        }
        assert!(
            matches!(state.begin(4096, 4096, true, true), Transfer::Forward { lower: target, physical: 1_052_672 } if target == lower)
        );
        let extension = state.reserve(file, true)?;
        assert!(matches!(
            state.begin(61_440, 4096, true, true),
            Transfer::Forward {
                physical: 1_110_016,
                ..
            }
        ));
        let discontinuous = Mapping::new(
            lower,
            ByteOffset::new(2_097_152),
            FileSize::from_bytes(131_072),
            512,
        )?;
        assert_eq!(
            state.publish(extension, discontinuous),
            Err(DriverError::InvalidParameter)
        );
        state.publish(
            extension,
            Mapping {
                length: FileSize::from_bytes(131_072),
                ..mapping
            },
        )?;
        state.complete();
        state.complete();
        assert!(state.permits_mutation(resize(126_976, 131_072)));
        assert!(!state.permits_mutation(resize(0, 0)));
        assert!(!state.permits_mutation(resize(135_168, 196_608)));
        assert!(!state.permits_mutation(PagingMutation::Delete));
        state.retire(file);
        assert_eq!(state.length(), FileSize::from_bytes(0));
        assert!(state.permits_mutation(PagingMutation::Delete));
        assert!(matches!(
            state.begin(0, 4096, true, true),
            Transfer::Complete(wdk_sys::STATUS_FILE_CLOSED)
        ));
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation, mapping or reservation failures before starting retirement.
    /// # Panics
    /// Fails if retirement skips an extension or returns before its forwarded completion.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup precedes joined-thread lifecycle assertions"
    )]
    fn retirement_waits_for_setup_and_completion_while_other_handles_cannot_revoke()
    -> DriverResult<()> {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file = wdk_sys::FILE_OBJECT::default();
        let mut other_file = wdk_sys::FILE_OBJECT::default();
        let (lower, file) = identities(&mut device, &mut file);
        let (_, other) = identities(&mut device, &mut other_file);
        let owner = PagingFile::try_new()?;
        let state = owner.get();
        let claim = state.reserve(file, false)?;
        state.publish(
            claim,
            Mapping::new(
                lower,
                ByteOffset::new(1_048_576),
                FileSize::from_bytes(65_536),
                512,
            )?,
        )?;
        let extension = state.reserve(file, true)?;
        state.retire(other);
        assert!(matches!(
            state.begin(0, 4096, true, true),
            Transfer::Forward { .. }
        ));
        std::thread::scope(|scope| {
            let (started, ready) = std::sync::mpsc::channel();
            let retire = scope.spawn(move || {
                let activating = state.transition(|phase| match phase {
                    Phase::Extending(map) => map.owner,
                    _ => corruption(),
                });
                assert!(started.send(()).is_ok());
                state.retire(activating);
            });
            assert!(ready.recv_timeout(Duration::from_secs(2)).is_ok());
            state.abort(extension);
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let mut closed = false;
            while std::time::Instant::now() < deadline {
                if matches!(
                    state.begin(0, 0, true, true),
                    Transfer::Complete(wdk_sys::STATUS_FILE_CLOSED)
                ) {
                    closed = true;
                    break;
                }
                std::thread::yield_now();
            }
            let still_waiting = !retire.is_finished();
            state.complete();
            let joined = retire.join();
            assert!(closed && still_waiting && joined.is_ok());
        });
        assert!(state.permits_mutation(PagingMutation::Delete));
        Ok(())
    }

    /// # Panics
    /// Fails if physical map validation permits a signed overflow, empty prefix or unaligned address.
    #[test]
    fn physical_map_admission_bounds_native_arithmetic() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file = wdk_sys::FILE_OBJECT::default();
        let (lower, _) = identities(&mut device, &mut file);
        for (physical, length, sector) in [
            (u64::MAX, 512, 512),
            (i64::MAX.unsigned_abs(), 512, 512),
            (0, 0, 512),
            (1, 512, 512),
            (0, 513, 512),
            (0, 512, 0),
        ] {
            assert!(
                Mapping::new(
                    lower,
                    ByteOffset::new(physical),
                    FileSize::from_bytes(length),
                    sector
                )
                .is_err()
            );
        }
    }
}
