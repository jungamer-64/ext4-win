//! Filesystem and control-device extension lifecycle, dispatch rundown, and retirement.

use super::*;

/// Driver-owned device extension kind retained independently of reactor lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct DeviceExtensionKind {
    /// Stable discriminant written during device initialization.
    pub(super) value: u8,
}

impl DeviceExtensionKind {
    /// Registered filesystem control device.
    pub(super) const CONTROL: Self = Self { value: 1 };
    /// Mounted ext4 volume device.
    pub(super) const MOUNTED_VOLUME: Self = Self { value: 2 };
}

/// Driver-owned device kind decoded before selecting a concrete extension teardown path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverDeviceKind {
    /// Registered filesystem control device.
    Control,
    /// Mounted ext4 volume device.
    MountedVolume,
}

impl DriverDeviceKind {
    /// Decodes the common extension discriminant.
    /// # Errors
    ///
    /// Returns an invariant error when driver-owned extension storage has an unknown kind.
    pub(super) fn decode(kind: DeviceExtensionKind) -> DriverResult<Self> {
        if kind == DeviceExtensionKind::CONTROL {
            Ok(Self::Control)
        } else if kind == DeviceExtensionKind::MOUNTED_VOLUME {
            Ok(Self::MountedVolume)
        } else {
            Err(DriverError::InternalInvariantViolation)
        }
    }
}

/// Keeps the reactor borrow alive across capture and CSQ insertion; closure excludes even late
/// dispatch on handles that outlive reactor retirement.
struct DeviceDispatchRundown {
    /// Native executive rundown state.
    #[cfg(not(test))]
    native: UnsafeCell<wdk_sys::EX_RUNDOWN_REF>,
    /// Closed bit plus active admission count in deterministic tests.
    #[cfg(test)]
    state: AtomicUsize,
}

/// High bit marking closed test admission.
#[cfg(test)]
const TEST_DISPATCH_CLOSED: usize = 1_usize << (usize::BITS - 1);

impl DeviceDispatchRundown {
    /// Creates an uninitialized native gate or open test gate.
    fn new() -> Self {
        Self {
            #[cfg(not(test))]
            native: UnsafeCell::new(wdk_sys::EX_RUNDOWN_REF::default()),
            #[cfg(test)]
            state: AtomicUsize::new(0),
        }
    }

    /// Initializes native rundown after final placement.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn initialize(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The containing device extension is already address-stable.
            ffi::ExInitializeRundownProtection(self.native.get());
        }
    }

    /// Acquires one admission lease unless teardown closed the gate.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn acquire(&self) -> Option<DeviceDispatchLease<'_>> {
        #[cfg(not(test))]
        {
            let acquired = unsafe {
                // SAFETY: Native rundown was initialized before device publication.
                ffi::ExAcquireRundownProtection(self.native.get())
            };
            if acquired == 0 {
                return None;
            }
        }
        #[cfg(test)]
        {
            self.state
                .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    if state & TEST_DISPATCH_CLOSED != 0 {
                        None
                    } else {
                        state
                            .checked_add(1)
                            .filter(|next| next & TEST_DISPATCH_CLOSED == 0)
                    }
                })
                .ok()?;
        }
        Some(DeviceDispatchLease { owner: self })
    }

    /// Closes admission and waits for every capture/insertion lease.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn close_and_wait(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The device owner retires exactly once at PASSIVE_LEVEL while its extension is live.
            ffi::ExWaitForRundownProtectionRelease(self.native.get());
        }
        #[cfg(test)]
        {
            let previous = self.state.fetch_or(TEST_DISPATCH_CLOSED, Ordering::AcqRel);
            if previous & TEST_DISPATCH_CLOSED != 0 {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
            }
            while self.state.load(Ordering::Acquire) != TEST_DISPATCH_CLOSED {
                core::hint::spin_loop();
            }
        }
    }

    /// Releases one admission lease.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn release(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Each lease corresponds to one successful acquisition.
            ffi::ExReleaseRundownProtection(self.native.get());
        }
        #[cfg(test)]
        {
            let previous = self.state.fetch_sub(1, Ordering::AcqRel);
            if previous == 0 || previous == TEST_DISPATCH_CLOSED {
                KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
            }
        }
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Native rundown or the test atomic serializes every interior access.
unsafe impl Sync for DeviceDispatchRundown {}

/// One reactor borrow that must end before the extension owner retires the reactor.
struct DeviceDispatchLease<'owner> {
    /// Stable gate owning the acquisition.
    owner: &'owner DeviceDispatchRundown,
}

impl Drop for DeviceDispatchLease<'_> {
    fn drop(&mut self) {
        self.owner.release();
    }
}

/// Device-owned reactor lifetime, separate from the I/O Manager's extension allocation lifetime.
///
/// Retirement closes dispatch admission, joins callbacks, and destroys the reactor before
/// `IoDeleteDevice`. The tag and closed gate stay valid for Cleanup/Close and late requests on
/// existing handles until the I/O Manager finally frees the delete-pending device. No ordinary
/// reference to an already-destroyed reactor can be reconstructed through this header.
#[repr(C)]
pub(super) struct DeviceExtensionHeader {
    /// Concrete extension kind retained until the I/O Manager frees the device.
    pub(super) kind: DeviceExtensionKind,
    /// Reactor-borrow authority that remains valid after the reactor itself is gone.
    dispatch: DeviceDispatchRundown,
    /// Address-stable actor storage, initialized only while dispatch admission is open.
    reactor: UnsafeCell<MaybeUninit<CompletionReactor>>,
}

impl DeviceExtensionHeader {
    /// Constructs the gate and actor at their final device-extension addresses.
    /// # Errors
    ///
    /// Returns an error if storage is null or reactor initialization fails; failed construction
    /// releases its initialized resources without publishing the device.
    /// # Safety
    ///
    /// `header` must be aligned, writable, uninitialized storage retained at this address until
    /// retirement and final device deletion. `device` must be the unpublished containing device.
    #[expect(
        unsafe_code,
        reason = "initializes address-sensitive device storage before publication"
    )]
    pub(super) unsafe fn initialize_at(
        header: *mut Self,
        kind: DeviceExtensionKind,
        device: KernelDevice,
        target: ReactorTarget,
    ) -> DriverResult<()> {
        let mut initialization = unsafe {
            // SAFETY: The caller exclusively owns final-address uninitialized extension storage.
            InPlaceInitialization::write(
                header,
                Self {
                    kind,
                    dispatch: DeviceDispatchRundown::new(),
                    reactor: UnsafeCell::new(MaybeUninit::uninit()),
                },
            )?
        };
        let header = initialization.get_mut();
        header.dispatch.initialize();
        unsafe {
            // SAFETY: The actor slot is uninitialized, aligned, and already at its final address.
            CompletionReactor::initialize_at(header.reactor.get().cast(), device, target)?;
        }
        initialization.publish();
        Ok(())
    }

    /// Borrows the actor only while retirement cannot destroy it.
    /// # Errors
    ///
    /// Returns the still-owned input without invoking `work` once dispatch admission has closed.
    pub(super) fn with_reactor<T, R>(
        &self,
        input: T,
        work: impl FnOnce(T, &CompletionReactor) -> R,
    ) -> Result<R, T> {
        let Some(_lease) = self.dispatch.acquire() else {
            return Err(input);
        };
        #[expect(
            unsafe_code,
            reason = "the acquired dispatch lease excludes actor destruction"
        )]
        let reactor = unsafe {
            // SAFETY: Publication follows initialization; retirement closes and drains this gate
            // before destroying the actor. The callback cannot return a borrow of the actor.
            &*self.reactor.get().cast::<CompletionReactor>()
        };
        Ok(work(input, reactor))
    }

    /// Closes intake, drains the actor, and consumes its resources before device deletion.
    /// # Safety
    ///
    /// The device lifecycle owner must invoke this exactly once after successful initialization,
    /// at PASSIVE_LEVEL, while retaining the containing device. It must not hold a dispatch lease.
    #[expect(
        unsafe_code,
        reason = "the unique retirement owner destroys an admission-closed actor"
    )]
    pub(super) unsafe fn retire(&self) -> ReactorTarget {
        self.dispatch.close_and_wait();
        unsafe {
            // SAFETY: Dispatch closure excludes every actor borrow and future intake; release
            // joins the actor and completion callbacks before dropping the initialized slot.
            CompletionReactor::release_at(self.reactor.get().cast())
        }
    }

    /// Borrows the persistent header, which stays initialized even after actor retirement.
    /// # Errors
    ///
    /// Returns an invariant error when the device or its extension is absent.
    /// # Safety
    ///
    /// `device` must be a driver-owned device whose extension remains allocated for the borrow.
    #[expect(
        unsafe_code,
        reason = "the dispatch or lifecycle owner retains this device extension"
    )]
    pub(super) unsafe fn from_device<'device>(device: KernelDevice) -> DriverResult<&'device Self> {
        let object = unsafe {
            // SAFETY: The caller retains the driver-owned device for the returned borrow.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InternalInvariantViolation)?;
        unsafe {
            // SAFETY: Every driver-owned device starts with this initialized header; retirement
            // destroys only the MaybeUninit actor slot, not the tag or closed dispatch gate.
            object.DeviceExtension.cast::<Self>().as_ref()
        }
        .ok_or(DriverError::InternalInvariantViolation)
    }
}

/// Control-device retirement lifecycle retained until the I/O Manager frees its extension.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ControlDevicePhase {
    /// The secure device and reactor exist but have not been published.
    Unpublished = 0,
    /// `IoRegisterFileSystem` owns its registration reference.
    Registered = 1,
    /// One control request owns registration consumption, actor drain, and device retirement.
    Retiring = 2,
    /// Actor resources and alias are gone; the owner has committed to device deletion.
    Retired = 3,
}

impl ControlDevicePhase {
    /// Stable atomic representation.
    const fn as_raw(self) -> u8 {
        match self {
            Self::Unpublished => 0,
            Self::Registered => 1,
            Self::Retiring => 2,
            Self::Retired => 3,
        }
    }

    /// Checks one atomic representation before it controls external lifecycle authority.
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unpublished),
            1 => Some(Self::Registered),
            2 => Some(Self::Retiring),
            3 => Some(Self::Retired),
            _ => None,
        }
    }
}

/// Outcome of acquiring the one-shot prepare-unload transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetirementAdmission {
    /// This request owns the transition from registered to retired.
    Acquired,
    /// A prior request completed the same idempotent transition.
    AlreadyRetired,
}

/// Serializes the one irreversible control-device retirement operation.
pub(super) struct ControlDeviceLifecycle {
    /// Checked [`ControlDevicePhase`] representation.
    state: AtomicU8,
}

impl ControlDeviceLifecycle {
    /// Creates one unpublished registration authority.
    pub(super) fn unpublished() -> Self {
        Self {
            state: AtomicU8::new(ControlDevicePhase::Unpublished.as_raw()),
        }
    }

    /// Returns the checked registration state.
    pub(super) fn state(&self) -> ControlDevicePhase {
        ControlDevicePhase::from_raw(self.state.load(Ordering::Acquire)).unwrap_or_else(|| {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck()
        })
    }

    /// Publishes the sole registration fact after the external reference is acquired.
    pub(super) fn mark_registered(&self) {
        if self
            .state
            .compare_exchange(
                ControlDevicePhase::Unpublished.as_raw(),
                ControlDevicePhase::Registered.as_raw(),
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
    }

    /// Acquires the idempotent transition that consumes the I/O Manager registration reference.
    /// # Errors
    ///
    /// Returns a busy error while another request owns the transition, or an invariant error when
    /// an unpublished device receives a lifecycle request.
    pub(super) fn begin_retirement(&self) -> DriverResult<RetirementAdmission> {
        match self.state.compare_exchange(
            ControlDevicePhase::Registered.as_raw(),
            ControlDevicePhase::Retiring.as_raw(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(RetirementAdmission::Acquired),
            Err(raw) if ControlDevicePhase::from_raw(raw) == Some(ControlDevicePhase::Retired) => {
                Ok(RetirementAdmission::AlreadyRetired)
            }
            Err(raw) if ControlDevicePhase::from_raw(raw) == Some(ControlDevicePhase::Retiring) => {
                Err(DriverError::DeviceBusy)
            }
            Err(raw)
                if ControlDevicePhase::from_raw(raw) == Some(ControlDevicePhase::Unpublished) =>
            {
                Err(DriverError::InternalInvariantViolation)
            }
            Err(_) => KernelWideInconsistency::driver_device_teardown_corruption().bugcheck(),
        }
    }

    /// Commits logical retirement after unregistration, actor destruction, and alias withdrawal.
    pub(super) fn finish_retirement(&self) {
        if self
            .state
            .compare_exchange(
                ControlDevicePhase::Retiring.as_raw(),
                ControlDevicePhase::Retired.as_raw(),
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_err()
        {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
    }
}

/// Device extension stored in the file-system control device.
#[repr(C)]
pub(crate) struct ControlDeviceExtension {
    /// Common driver-owned device extension header.
    header: DeviceExtensionHeader,
    /// One authoritative state for registration and terminal control-device retirement.
    lifecycle: ControlDeviceLifecycle,
}

impl ControlDeviceExtension {
    /// Initializes the extension attached to the control device.
    /// # Errors
    ///
    /// Returns an error when the device has no extension or its reactor cannot be initialized.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn initialize(device: KernelDevice) -> DriverResult<()> {
        let device_object = unsafe {
            // SAFETY: `device` is the newly created control device object.
            device.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let extension = unsafe {
            // SAFETY: DriverEntry creates the control device with a
            // ControlDeviceExtension-sized extension.
            device_object
                .DeviceExtension
                .cast::<ControlDeviceExtension>()
                .as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        extension.lifecycle = ControlDeviceLifecycle::unpublished();
        unsafe {
            // SAFETY: The extension is stable device-owned storage.
            DeviceExtensionHeader::initialize_at(
                core::ptr::addr_of_mut!(extension.header),
                DeviceExtensionKind::CONTROL,
                device,
                ReactorTarget::ControlDevice,
            )
        }
    }

    /// Returns the exact extension of a checked control device.
    /// # Errors
    ///
    /// Returns an error when the device kind or extension pointer is invalid.
    /// # Safety
    ///
    /// `device` must remain a live control device for the returned borrow.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn from_device<'device>(device: KernelDevice) -> DriverResult<&'device Self> {
        if driver_device_kind(device)? != DriverDeviceKind::Control {
            return Err(DriverError::InvalidDeviceRequest);
        }
        let device_object = unsafe {
            // SAFETY: The caller retains this checked control device through the returned borrow.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        unsafe {
            // SAFETY: The decoded control kind selects the exact extension layout.
            device_object
                .DeviceExtension
                .cast::<ControlDeviceExtension>()
                .as_ref()
        }
        .ok_or(DriverError::InvalidParameter)
    }

    /// Releases an initialized control extension that was never registered.
    /// # Safety
    ///
    /// The device must still be unpublished and no dispatch callback may access it.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn release_unpublished(device: KernelDevice) {
        let extension = unsafe {
            // SAFETY: The caller retains the unpublished control device exclusively.
            Self::from_device(device)
        }
        .unwrap_or_else(|_| {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck()
        });
        if extension.lifecycle.state() != ControlDevicePhase::Unpublished {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
        let target = unsafe {
            // SAFETY: The unpublished device cannot receive dispatch and owns this live reactor.
            extension.header.retire()
        };
        if !matches!(target, ReactorTarget::ControlDevice) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
    }
}

/// Registered file system control device owned by the driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlDevice;

impl ControlDevice {
    /// Creates, secures, names, initializes, and registers the filesystem control device.
    /// # Errors
    ///
    /// Returns the exact native failure status when secure creation or symbolic-link publication
    /// fails, or the mapped driver failure when extension initialization fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn create(driver: PDRIVER_OBJECT) -> Result<Self, wdk_sys::NTSTATUS> {
        let extension_size =
            wdk_sys::ULONG::try_from(core::mem::size_of::<ControlDeviceExtension>())
                .map_err(|_| DriverError::InvalidParameter.ntstatus())?;
        let mut device_name = lifecycle_unicode_string(
            &crate::lifecycle_control::CONTROL_DEVICE_NT_NAME,
            crate::lifecycle_control::CONTROL_DEVICE_NT_NAME_BYTE_LENGTH,
            crate::lifecycle_control::CONTROL_DEVICE_NT_NAME_MAXIMUM_BYTE_LENGTH,
        );
        let device_sddl = lifecycle_unicode_string(
            &crate::lifecycle_control::CONTROL_DEVICE_SDDL,
            crate::lifecycle_control::CONTROL_DEVICE_SDDL_BYTE_LENGTH,
            crate::lifecycle_control::CONTROL_DEVICE_SDDL_MAXIMUM_BYTE_LENGTH,
        );
        let mut device = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: Generated strings are stable, terminated contract values; `device` is
            // writable out storage and the custom GUID is unique to this control device.
            ffi::WdmlibIoCreateDeviceSecure(
                driver,
                extension_size,
                core::ptr::addr_of_mut!(device_name),
                ffi::FILE_DEVICE_DISK_FILE_SYSTEM,
                wdk_sys::FILE_DEVICE_SECURE_OPEN,
                0,
                core::ptr::addr_of!(device_sddl),
                core::ptr::addr_of!(crate::lifecycle_control::CONTROL_DEVICE_CLASS_GUID),
                core::ptr::addr_of_mut!(device),
            )
        };
        if status < STATUS_SUCCESS {
            return Err(status);
        }
        let Some(device) = (unsafe {
            // SAFETY: Successful secure creation returns a live unpublished device.
            KernelDevice::from_raw(device)
        }) else {
            return Err(DriverError::InternalInvariantViolation.ntstatus());
        };
        if let Err(error) = ControlDeviceExtension::initialize(device) {
            unsafe {
                // SAFETY: Extension initialization failed before any device publication.
                ffi::IoDeleteDevice(device.as_ptr());
            }
            return Err(error.ntstatus());
        }

        let mut dos_name = lifecycle_unicode_string(
            &crate::lifecycle_control::CONTROL_DEVICE_DOS_NAME,
            crate::lifecycle_control::CONTROL_DEVICE_DOS_NAME_BYTE_LENGTH,
            crate::lifecycle_control::CONTROL_DEVICE_DOS_NAME_MAXIMUM_BYTE_LENGTH,
        );
        let link_status = unsafe {
            // SAFETY: Both generated names remain stable for this synchronous publication call.
            ffi::IoCreateSymbolicLink(
                core::ptr::addr_of_mut!(dos_name),
                core::ptr::addr_of_mut!(device_name),
            )
        };
        if link_status < STATUS_SUCCESS {
            unsafe {
                // SAFETY: Symbolic-link publication failed, so the initialized device remains
                // unpublished and exclusively owned by this rollback path.
                ControlDeviceExtension::release_unpublished(device);
            }
            unsafe {
                // SAFETY: Reactor rollback completed and no external reference was published.
                ffi::IoDeleteDevice(device.as_ptr());
            }
            return Err(link_status);
        }

        unsafe {
            // SAFETY: The named, initialized disk-filesystem control device is ready to acquire
            // its registration reference while DO_DEVICE_INITIALIZING still excludes opens.
            ffi::IoRegisterFileSystem(device.as_ptr());
        }
        let extension = unsafe {
            // SAFETY: This exact device was initialized as the filesystem control device above.
            ControlDeviceExtension::from_device(device)
        }
        .unwrap_or_else(|_| {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck()
        });
        extension.lifecycle.mark_registered();
        let device_object = unsafe {
            // SAFETY: Registration state now represents every lifecycle fact that dispatch can
            // observe once this final publication flag is cleared.
            device.as_ptr().as_mut()
        }
        .unwrap_or_else(|| KernelWideInconsistency::driver_device_teardown_corruption().bugcheck());
        device_object.Flags &= !DO_DEVICE_INITIALIZING;
        Ok(Self)
    }

    /// Unregisters and retires the control device before SCM asks the I/O Manager to unload.
    ///
    /// A base filesystem must delete all its devices before `DriverUnload` can run. Existing
    /// control handles retain only a closed dispatch gate and lifecycle tag after this request;
    /// Cleanup/Close remain valid until their final I/O Manager reference releases the device.
    /// Mounted volumes retire through their own dismount/last-close protocol, never DriverUnload.
    /// # Errors
    ///
    /// Returns an error for a non-control device, an unpublished state, or a concurrent prepare
    /// request that still owns the transition.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn prepare_unload(device: KernelDevice) -> DriverResult<()> {
        let extension = unsafe {
            // SAFETY: The active control IOCTL retains its target device for this transition.
            ControlDeviceExtension::from_device(device)?
        };
        if extension.lifecycle.begin_retirement()? == RetirementAdmission::AlreadyRetired {
            return Ok(());
        }
        unsafe {
            // SAFETY: This request exclusively consumed the Registered state, so it owns the sole
            // I/O Manager registration reference and may release it exactly once.
            ffi::IoUnregisterFileSystem(device.as_ptr());
        }
        unsafe {
            // SAFETY: This request owns retirement and holds no reactor lease. The IOCTL's
            // FILE_OBJECT keeps extension storage alive while intake and actor callbacks drain.
            let target = extension.header.retire();
            if !matches!(target, ReactorTarget::ControlDevice) {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
        unsafe {
            // SAFETY: The retirement owner withdraws the alias exactly once before device deletion.
            Self::delete_symbolic_link();
        }
        extension.lifecycle.finish_retirement();
        unsafe {
            // SAFETY: Actor resources are gone and future actor borrows are excluded. The current
            // handle pins the closed header until Cleanup/Close; no Rust-owned resources remain.
            ffi::IoDeleteDevice(device.as_ptr());
        }
        Ok(())
    }

    /// Withdraws the Win32 alias during control-device retirement.
    /// # Safety
    ///
    /// The caller must exclusively own retirement of the published control device.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn delete_symbolic_link() {
        let mut dos_name = lifecycle_unicode_string(
            &crate::lifecycle_control::CONTROL_DEVICE_DOS_NAME,
            crate::lifecycle_control::CONTROL_DEVICE_DOS_NAME_BYTE_LENGTH,
            crate::lifecycle_control::CONTROL_DEVICE_DOS_NAME_MAXIMUM_BYTE_LENGTH,
        );
        let status = unsafe {
            // SAFETY: The generated name identifies the alias published by `Self::create`.
            ffi::IoDeleteSymbolicLink(core::ptr::addr_of_mut!(dos_name))
        };
        if status < STATUS_SUCCESS {
            KernelWideInconsistency::driver_device_teardown_corruption().bugcheck();
        }
    }
}

/// Builds a native string view over one generated, terminated lifecycle-contract buffer.
fn lifecycle_unicode_string(
    buffer: &'static [u16],
    byte_length: wdk_sys::USHORT,
    maximum_byte_length: wdk_sys::USHORT,
) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: byte_length,
        MaximumLength: maximum_byte_length,
        Buffer: buffer.as_ptr().cast_mut(),
    }
}
