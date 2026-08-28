//! PnP subscription and joined system-thread ownership for hidden volume discovery.

use alloc::boxed::Box;
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
use core::{cell::UnsafeCell, ffi::c_void, marker::PhantomPinned, ptr::NonNull};
use ext4_core::ExtVolumeSignature;
use wdk_sys::{NTSTATUS, STATUS_SUCCESS};

use crate::irp::lower::AlignedTransferBuffer;
use crate::kernel::device_interface::{VolumeInterfaceClass, VolumeInterfaces, unicode_string};
use crate::kernel::{fatal::KernelWideInconsistency, ffi};
use crate::memory;
use crate::state::KernelDevice;

/// The callback can wake a dormant worker, but only activation grants publication authority.
#[derive(Clone, Copy, Eq, PartialEq)]
enum DiscoveryPhase {
    /// Observers exist but the filesystem is not yet registered.
    Dormant,
    /// The registered filesystem can receive discovered volumes.
    Running,
    /// Admission is closed while callbacks and the current scan are joined.
    Stopping,
}

impl DiscoveryPhase {
    /// Private atomic representation of the discovery lifecycle.
    const fn raw(self) -> u8 {
        match self {
            Self::Dormant => 0,
            Self::Running => 1,
            Self::Stopping => 2,
        }
    }
}

/// Owns subscription closure and thread completion before releasing callback storage.
/// The control extension creates, activates and destroys this owner at PASSIVE_LEVEL.
pub(crate) struct VolumeDiscovery {
    /// Pinned independently from this movable owner; Drop never borrows its context mutably.
    context: Pin<Box<DiscoveryContext>>,
}

/// Only atomics and the native event are mutated after notification registration.
struct DiscoveryContext {
    /// Discovery admission, closed before unregistering callbacks.
    phase: AtomicU8,
    /// Coalescing auto-reset event; callbacks never wait for I/O or allocate.
    event: UnsafeCell<wdk_sys::KEVENT>,
    /// One PnP registration, atomically consumed on closure or initialization rollback.
    notification: AtomicPtr<c_void>,
    /// Sole joinable system-thread handle, absent until creation succeeds.
    thread: AtomicPtr<c_void>,
    /// Control device lifetime encloses this owner, including error-log submissions.
    owner: KernelDevice,
    /// The native dispatcher event and callback context must never move.
    _pin: PhantomPinned,
}

impl VolumeDiscovery {
    /// Creates dormant discovery; the filesystem must be registered before activation.
    /// # Errors
    /// Returns allocation, notification-registration or system-thread creation failure.
    #[expect(
        unsafe_code,
        reason = "pinned context publication is paired with unregister and join"
    )]
    pub(crate) fn start(owner: KernelDevice) -> Result<Self, NTSTATUS> {
        let context = memory::boxed_try_with(|| {
            Ok(DiscoveryContext {
                phase: AtomicU8::new(DiscoveryPhase::Dormant.raw()),
                event: UnsafeCell::new(wdk_sys::KEVENT::default()),
                notification: AtomicPtr::new(core::ptr::null_mut()),
                thread: AtomicPtr::new(core::ptr::null_mut()),
                owner,
                _pin: PhantomPinned,
            })
        })
        .map_err(|error| error.ntstatus())?;
        let discovery = Self {
            context: Box::into_pin(context),
        };
        let context = discovery.context.as_ref().get_ref();
        unsafe {
            // SAFETY: This pinned event has no observers before registration below.
            ffi::KeInitializeEvent(
                context.event.get(),
                wdk_sys::_EVENT_TYPE::SynchronizationEvent,
                0,
            );
        }
        let device = unsafe {
            // SAFETY: The control extension owns the newly created live device throughout start.
            owner.as_ptr().as_ref()
        }
        .ok_or(wdk_sys::STATUS_INVALID_PARAMETER)?;
        let address = core::ptr::from_ref(context).cast_mut().cast::<c_void>();
        let mut guid = VolumeInterfaceClass::Hidden.guid();
        let mut registration = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: Callback storage is initialized and pinned. The callback only signals;
            // INCLUDE_EXISTING may invoke it synchronously before this call returns.
            wdk_sys::ntddk::IoRegisterPlugPlayNotification(
                wdk_sys::_IO_NOTIFICATION_EVENT_CATEGORY::EventCategoryDeviceInterfaceChange,
                wdk_sys::PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                (&raw mut guid).cast(),
                device.DriverObject,
                Some(interface_change),
                address,
                &raw mut registration,
            )
        };
        native_success(status)?;
        if registration.is_null() {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
        context.notification.store(registration, Ordering::Release);
        let mut attributes = wdk_sys::OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<wdk_sys::OBJECT_ATTRIBUTES>())
                .map_err(|_| wdk_sys::STATUS_INVALID_PARAMETER)?,
            Attributes: wdk_sys::OBJ_KERNEL_HANDLE,
            ..wdk_sys::OBJECT_ATTRIBUTES::default()
        };
        let mut thread = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: Drop unregisters callbacks and joins any created thread before context drop.
            ffi::PsCreateSystemThread(
                &raw mut thread,
                wdk_sys::SYNCHRONIZE,
                &raw mut attributes,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                Some(discovery_thread),
                address,
            )
        };
        native_success(status)?;
        if thread.is_null() {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
        context.thread.store(thread, Ordering::Release);
        Ok(discovery)
    }

    /// Grants the worker publication authority after successful filesystem registration.
    pub(crate) fn activate(&self) {
        if self
            .context
            .phase
            .compare_exchange(
                DiscoveryPhase::Dormant.raw(),
                DiscoveryPhase::Running.raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
        self.context.wake();
    }
}

impl Drop for VolumeDiscovery {
    #[expect(
        unsafe_code,
        reason = "owner closes native observers before releasing their context"
    )]
    fn drop(&mut self) {
        let context = self.context.as_ref().get_ref();
        context
            .phase
            .store(DiscoveryPhase::Stopping.raw(), Ordering::Release);
        let registration = context
            .notification
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !registration.is_null() {
            let status = unsafe {
                // SAFETY: This owner consumes its sole valid subscription and waits for callbacks.
                wdk_sys::ntddk::IoUnregisterPlugPlayNotificationEx(registration)
            };
            if status < STATUS_SUCCESS {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
            }
        }
        context.wake();
        let thread = context.thread.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !thread.is_null() {
            let status = unsafe {
                // SAFETY: Sole kernel handle; context remains live until the nonalertable join.
                ffi::ZwWaitForSingleObject(thread, 0, core::ptr::null_mut())
            };
            if status < STATUS_SUCCESS {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
            }
            let status = unsafe {
                // SAFETY: Joined thread handle is released exactly once by this owner.
                ffi::ZwClose(thread)
            };
            if status < STATUS_SUCCESS {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
            }
        }
    }
}

impl DiscoveryContext {
    /// Signals an initialized event without taking any PnP or filesystem lock.
    #[expect(
        unsafe_code,
        reason = "the WDK event is the callback-to-worker synchronization boundary"
    )]
    fn wake(&self) {
        unsafe {
            // SAFETY: Registration and worker lifetime are enclosed by the initialized event owner.
            let _previous_state = ffi::KeSetEvent(self.event.get(), 0, 0);
        }
    }

    /// Owns all blocking discovery I/O; duplicate notifications coalesce into snapshot rescans.
    #[expect(
        unsafe_code,
        reason = "only the owned system thread waits on the pinned native event"
    )]
    fn run(&self) {
        loop {
            let status = unsafe {
                // SAFETY: This is the only waiter; Drop signals and joins before event destruction.
                ffi::KeWaitForSingleObject(
                    self.event.get().cast(),
                    wdk_sys::_KWAIT_REASON::Executive,
                    0,
                    0,
                    core::ptr::null_mut(),
                )
            };
            if status < STATUS_SUCCESS {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
            }
            let phase = self.phase.load(Ordering::Acquire);
            if phase == DiscoveryPhase::Stopping.raw() {
                return;
            }
            if phase == DiscoveryPhase::Dormant.raw() {
                continue;
            }
            if let Err(status) = self.scan() {
                self.report(status);
            }
        }
    }

    /// Streams one immutable PnP snapshot without retaining references between scans.
    /// # Errors
    /// Returns enumeration failure; individual candidate failures are reported independently.
    fn scan(&self) -> Result<(), NTSTATUS> {
        let mut volumes = VolumeInterfaces::enumerate(VolumeInterfaceClass::Hidden)?;
        while let Some(path) = volumes.next_path()? {
            if self.phase.load(Ordering::Acquire) != DiscoveryPhase::Running.raw() {
                break;
            }
            if let Err(status) = self.probe(path) {
                self.report(status);
            }
        }
        Ok(())
    }

    /// Performs read-only recognition before the separate Mount Manager acceptance boundary.
    /// # Errors
    /// Preserves native I/O/arrival failure; signature mismatch and ineligible GPT are not errors.
    /// Arrival failure does not imply unpublished names: subsequent discovery reconciles with
    /// Mount Manager, and neither this worker nor its destructor rolls back shared mount points.
    #[expect(
        unsafe_code,
        reason = "referenced volume and owned buffers outlive each synchronous call"
    )]
    fn probe(&self, path: &[u16]) -> Result<(), NTSTATUS> {
        let volume = ReferencedVolume::open(path)?;
        let mut kind = wdk_sys::GUID::default();
        let mut attributes = 0_u64;
        let status = unsafe {
            // SAFETY: The file reference keeps the lower device live; outputs are writable.
            ext4win_query_volume_partition(
                volume.device.as_ptr(),
                &raw mut kind,
                &raw mut attributes,
            )
        };
        if status == wdk_sys::STATUS_NOT_SUPPORTED {
            return Ok(());
        }
        native_success(status)?;
        if !super::admits_automatic_publication(&kind, attributes) {
            return Ok(());
        }
        let mut sector = 0_u32;
        let status = unsafe {
            // SAFETY: Live referenced storage device with a synchronous output slot.
            ext4win_query_volume_sector_size(volume.device.as_ptr(), &raw mut sector)
        };
        native_success(status)?;
        if sector < 512 || !sector.is_power_of_two() || sector > 65_536 {
            return Err(wdk_sys::STATUS_NOT_SUPPORTED);
        }
        let device = unsafe {
            // SAFETY: FILE_OBJECT retains this device during the entire probe.
            volume.device.as_ptr().as_ref()
        }
        .ok_or(wdk_sys::STATUS_NO_SUCH_DEVICE)?;
        let alignment = device
            .AlignmentRequirement
            .checked_add(1)
            .ok_or(wdk_sys::STATUS_INVALID_BUFFER_SIZE)?
            .max(sector);
        let superblock_size = u64::try_from(ExtVolumeSignature::BYTE_LEN)
            .map_err(|_| wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let prefix_size = ExtVolumeSignature::BYTE_OFFSET
            .checked_add(superblock_size)
            .and_then(|size| size.checked_next_multiple_of(u64::from(sector)))
            .ok_or(wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let length = u32::try_from(prefix_size).map_err(|_| wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let mut buffer = AlignedTransferBuffer::try_zeroed(
            usize::try_from(length).map_err(|_| wdk_sys::STATUS_INVALID_BUFFER_SIZE)?,
            usize::try_from(alignment).map_err(|_| wdk_sys::STATUS_INVALID_BUFFER_SIZE)?,
        )
        .map_err(|error| error.ntstatus())?;
        let status = unsafe {
            // SAFETY: Buffer is nonpaged and aligned, exclusively borrowed until I/O completes.
            ext4win_read_volume_prefix(
                volume.device.as_ptr(),
                buffer.as_mut_slice().as_mut_ptr().cast(),
                length,
            )
        };
        native_success(status)?;
        let offset = usize::try_from(ExtVolumeSignature::BYTE_OFFSET)
            .map_err(|_| wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let superblock = buffer
            .as_slice()
            .get(offset..)
            .ok_or(wdk_sys::STATUS_INFO_LENGTH_MISMATCH)?;
        let signature = ExtVolumeSignature::recognize(superblock)
            .map_err(|_| wdk_sys::STATUS_INFO_LENGTH_MISMATCH)?;
        if signature != Some(ExtVolumeSignature::Filesystem)
            || self.phase.load(Ordering::Acquire) != DiscoveryPhase::Running.raw()
        {
            return Ok(());
        }
        let status = unsafe {
            // SAFETY: The same referenced volume supplied GPT and signature evidence. Acceptance
            // is reconciled by native queries; shutdown joins this call before retiring the FSD.
            ext4win_announce_volume(volume.device.as_ptr())
        };
        native_success(status)
    }

    /// Reports asynchronous discovery failure through the OS error-log boundary.
    #[expect(
        unsafe_code,
        reason = "the enclosing control extension retains the log target device"
    )]
    fn report(&self, status: NTSTATUS) {
        unsafe {
            // SAFETY: The control device remains live until this worker has joined.
            ext4win_report_volume_discovery_failure(self.owner.as_ptr(), status);
        }
    }
}

/// Lower stack lease retained only across a synchronous probe and publication exchange.
struct ReferencedVolume {
    /// One FILE_OBJECT reference transferred by IoGetDeviceObjectPointer.
    file: NonNull<wdk_sys::FILE_OBJECT>,
    /// Related lower device retained by `file`.
    device: KernelDevice,
}

impl ReferencedVolume {
    /// Opens for attributes so recognition does not itself cause a filesystem mount.
    /// # Errors
    /// Returns native open failure or a malformed success response.
    #[expect(
        unsafe_code,
        reason = "this boundary captures exactly one native file-object reference"
    )]
    fn open(path: &[u16]) -> Result<Self, NTSTATUS> {
        let mut name = unicode_string(path)?;
        let mut file = core::ptr::null_mut();
        let mut device = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: The snapshot retains name storage; output slots live through the open.
            ffi::IoGetDeviceObjectPointer(
                &raw mut name,
                wdk_sys::FILE_READ_ATTRIBUTES,
                &raw mut file,
                &raw mut device,
            )
        };
        native_success(status)?;
        let file = NonNull::new(file).ok_or(wdk_sys::STATUS_INVALID_DEVICE_STATE)?;
        let device = unsafe {
            // SAFETY: Successful shared open retains the returned related device through `file`.
            KernelDevice::from_raw(device)
        };
        match device {
            Some(device) => Ok(Self { file, device }),
            None => {
                unsafe {
                    // SAFETY: The open transferred this reference even with an invalid device output.
                    let _remaining = ffi::ObfDereferenceObject(file.as_ptr().cast());
                }
                Err(wdk_sys::STATUS_INVALID_DEVICE_STATE)
            }
        }
    }
}

impl Drop for ReferencedVolume {
    #[expect(
        unsafe_code,
        reason = "the scan is the sole owner of this shared file reference"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: All synchronous requests completed before the lease is dropped.
            let _remaining = ffi::ObfDereferenceObject(self.file.as_ptr().cast());
        }
    }
}

/// Keeps NTSTATUS failure identity at this native orchestration boundary.
/// # Errors
/// Returns the original failing status without mapping transport errors to absence.
fn native_success(status: NTSTATUS) -> Result<(), NTSTATUS> {
    if status < STATUS_SUCCESS {
        Err(status)
    } else {
        Ok(())
    }
}

/// Fast PnP callback; neither borrows the transient notification nor opens its path.
/// # Safety
/// `context` must be the pinned registration context retained until unregister completes.
#[expect(
    unsafe_code,
    reason = "PnP invokes the callback only inside the registered context lifetime"
)]
unsafe extern "C" fn interface_change(
    _notification: *mut c_void,
    context: *mut c_void,
) -> NTSTATUS {
    let context = unsafe {
        // SAFETY: Registration supplies this initialized context until unregister returns.
        &*context.cast::<DiscoveryContext>()
    };
    context.wake();
    STATUS_SUCCESS
}

/// System-thread entry, with completion joined by the enclosing discovery owner.
/// # Safety
/// `context` must remain pinned and initialized until this thread terminates.
#[expect(
    unsafe_code,
    reason = "the system thread is joined before callback storage is freed"
)]
unsafe extern "C" fn discovery_thread(context: *mut c_void) {
    let context = unsafe {
        // SAFETY: Owner retains the initialized context until ZwWaitForSingleObject completes.
        &*context.cast::<DiscoveryContext>()
    };
    context.run();
    unsafe {
        // SAFETY: Only this dedicated system thread terminates itself after leaving its run loop.
        let _status = ffi::PsTerminateSystemThread(STATUS_SUCCESS);
    }
}

#[expect(
    unsafe_code,
    reason = "native routines own WDK IOCTL layouts and synchronous completion"
)]
unsafe extern "system" {
    /// Queries the real partition identity without modifying its table or attributes.
    fn ext4win_query_volume_partition(
        device: wdk_sys::PDEVICE_OBJECT,
        kind: *mut wdk_sys::GUID,
        attributes: *mut u64,
    ) -> NTSTATUS;
    /// Queries logical sector geometry for the aligned recognition read.
    fn ext4win_query_volume_sector_size(
        device: wdk_sys::PDEVICE_OBJECT,
        sector: *mut u32,
    ) -> NTSTATUS;
    /// Returns only after the exclusively borrowed nonpaged read buffer is no longer in use.
    fn ext4win_read_volume_prefix(
        device: wdk_sys::PDEVICE_OBJECT,
        buffer: *mut c_void,
        length: u32,
    ) -> NTSTATUS;
    /// Reconciles existing registration before and after a Mount Manager arrival notification.
    fn ext4win_announce_volume(device: wdk_sys::PDEVICE_OBJECT) -> NTSTATUS;
    /// Sends asynchronous discovery failure to the system error log.
    fn ext4win_report_volume_discovery_failure(owner: wdk_sys::PDEVICE_OBJECT, status: NTSTATUS);
}
