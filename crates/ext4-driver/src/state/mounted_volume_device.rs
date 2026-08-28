//! Mounted-volume device construction, VPB publication, and device retirement.

use super::*;

/// Windows volume serial number derived from the ext4 filesystem UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeSerialNumber {
    /// Raw serial value expected by WDK structures.
    value: u32,
}

impl VolumeSerialNumber {
    /// Builds a serial number from little-endian UUID bytes.
    pub(crate) const fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self {
            value: u32::from_le_bytes(bytes),
        }
    }

    /// Returns the WDK serial number payload.
    pub(crate) const fn as_u32(self) -> u32 {
        self.value
    }
}

/// Device extension stored in mounted volume device objects.
#[repr(C)]
pub(crate) struct MountedVolumeDeviceExtension {
    /// Common driver-owned device extension header.
    header: DeviceExtensionHeader,
    /// Mount-preallocated work item that performs actor-safe physical retirement.
    retirement_work_item: wdk_sys::PIO_WORKITEM,
}

/// Mounted volume device object produced by a successful mount FSCTL.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountedVolumeDevice;

/// Prevalidated VPB label update consumed only after journal commit visibility.
#[derive(Debug)]
pub(crate) struct PreparedVpbLabelPublication {
    /// Stable VPB retained by the mounted device until reactor drain.
    vpb: NonNull<wdk_sys::VPB>,
    /// Fully encoded fixed-capacity VPB label.
    label: VpbLabel,
}

impl PreparedVpbLabelPublication {
    /// Publishes the already encoded label without allocation or ordinary failure.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn publish(self) {
        let vpb = unsafe {
            // SAFETY: The mounted device retains this VPB through every admitted operation, and
            // the token is consumed on the sole reactor thread before device retirement.
            self.vpb.as_ptr().as_mut()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        self.label.write_to(vpb);
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The VPB is I/O Manager-owned stable mounted state and publication remains serialized by
// the device reactor.
unsafe impl Send for PreparedVpbLabelPublication {}

impl MountedVolumeDevice {
    /// Initializes an IoCreateDevice-created mounted device and takes ownership
    /// of the VCB.
    /// # Errors
    ///
    /// Returns an error when the mounted DEVICE_OBJECT, device extension, or VPB initialization
    /// target is absent or invalid.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn initialize(
        device: KernelDevice,
        vcb: Box<VolumeControlBlock>,
        vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<()> {
        let stack_size = real_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let transfer_alignment = real_device.transfer_buffer_alignment()?;
        let mounted_flag = u16::try_from(VPB_MOUNTED).map_err(|_| DriverError::InvalidParameter)?;
        let identity = vcb.runtime.identity();
        let [a, b, c, d, ..] = identity.uuid().bytes();
        let serial_number = VolumeSerialNumber::from_le_bytes([a, b, c, d]).as_u32();
        let volume_label = VpbLabel::encode(identity.label())?;
        let device_object = unsafe {
            // SAFETY: The device was just created by this driver and remains
            // valid during mount initialization.
            device.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let extension = unsafe {
            // SAFETY: The device was created with a DeviceExtension sized for
            // MountedVolumeDeviceExtension by this driver.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        extension.retirement_work_item = core::ptr::null_mut();
        let vpb = unsafe {
            // SAFETY: The VPB was supplied by the I/O Manager for this mount
            // request and is writable during successful mount completion.
            vpb.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;

        unsafe {
            // SAFETY: The extension is stable device-owned storage for this
            // just-created mounted volume device.
            DeviceExtensionHeader::initialize_at(
                core::ptr::addr_of_mut!(extension.header),
                DeviceExtensionKind::MOUNTED_VOLUME,
                device,
                ReactorTarget::MountedVolume(MountedVolumeBinding::new(vcb)),
            )?;
        }
        if let Err(error) = register_shutdown_notification(device) {
            unsafe {
                // SAFETY: Shutdown registration failed before this device was
                // published, so no actor continuation can still own the executor.
                let target = extension.header.retire();
                drop(target);
            }
            return Err(error);
        }
        #[cfg(not(test))]
        let retirement_work_item = unsafe {
            // SAFETY: The new mounted device remains live and unpublished during allocation.
            ffi::IoAllocateWorkItem(device.as_ptr())
        };
        #[cfg(test)]
        let retirement_work_item = NonNull::<wdk_sys::_IO_WORKITEM>::dangling().as_ptr();
        if retirement_work_item.is_null() {
            Self::unregister_shutdown_notification(device);
            unsafe {
                // SAFETY: Work-item allocation failed before publication; no request can race
                // executor teardown.
                let target = extension.header.retire();
                drop(target);
            }
            return Err(DriverError::InsufficientResources);
        }
        extension.retirement_work_item = retirement_work_item;

        device_object.Vpb = vpb;
        device_object.Flags |= DO_DIRECT_IO;
        device_object.StackSize = stack_size;
        device_object.AlignmentRequirement = transfer_alignment.as_mask();

        vpb.SerialNumber = serial_number;
        volume_label.write_to(vpb);
        vpb.DeviceObject = device.as_ptr();
        vpb.RealDevice = real_device.as_ptr();
        vpb.Flags |= mounted_flag;

        device_object.Flags &= !DO_DEVICE_INITIALIZING;
        Ok(())
    }

    /// Releases actor, VPB, and VCB resources before the I/O Manager deletes this device.
    /// # Safety
    ///
    /// The queued retirement work item must retain the device. Every FILE_OBJECT must have
    /// completed Close; this call drains dispatch and actor callbacks before releasing resources.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "the kernel retirement callback is absent from host tests"
        )
    )]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn release(device: KernelDevice) {
        let device_object = unsafe {
            // SAFETY: The retirement work item retains this mounted device during teardown.
            device.as_ptr().as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let extension = unsafe {
            // SAFETY: The common extension kind was decoded as mounted before this call.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let target = unsafe {
            // SAFETY: Terminal teardown closes admission, drains IRPs, and joins the actor before
            // any VCB or VPB storage is released.
            extension.header.retire()
        };
        let ReactorTarget::MountedVolume(binding) = target else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let vcb = binding.into_volume();
        if !vcb.is_logically_dismounted() {
            Self::unregister_shutdown_notification(device);
        }
        Self::detach_vpb(device);
        drop(vcb);
    }

    /// Queues the preallocated work item that retires this device after its actor returns.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(crate) fn schedule_retirement(device: KernelDevice) {
        let work_item = Self::retirement_work_item(device);
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Mount allocated this item for the device and Retiring makes this the unique
            // queue operation. I/O work-item ownership pins the device until callback completion.
            ffi::IoQueueWorkItem(
                work_item.as_ptr(),
                Some(mounted_volume_retirement),
                wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
                work_item.as_ptr().cast::<c_void>(),
            );
        }
        #[cfg(test)]
        let _work_item = work_item;
    }

    /// Returns the mount-preallocated retirement work item from a live mounted extension.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn retirement_work_item(device: KernelDevice) -> NonNull<wdk_sys::_IO_WORKITEM> {
        let device_object = unsafe {
            // SAFETY: The caller retains the mounted device and its extension.
            device.as_ptr().as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let extension = unsafe {
            // SAFETY: Retirement is emitted only by a mounted-volume actor.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        NonNull::new(extension.retirement_work_item).unwrap_or_else(|| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        })
    }

    /// Prevalidates the complete VPB volume-label publication before a mutation writes storage.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB pointer is absent, or the ext4 label does
    /// not fit in the VPB label field.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn prepare_vpb_label_publication(
        device: KernelDevice,
        volume_label: ext4_core::Ext4VolumeLabel,
    ) -> DriverResult<PreparedVpbLabelPublication> {
        let device_object = unsafe {
            // SAFETY: `device` is a mounted volume device owned by this driver
            // and is read only for its current VPB pointer.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let vpb = NonNull::new(device_object.Vpb).ok_or(DriverError::InvalidParameter)?;
        let label = VpbLabel::encode(volume_label)?;
        Ok(PreparedVpbLabelPublication { vpb, label })
    }

    /// Publishes whether the mounted VPB rejects creates for a volume lock.
    /// # Errors
    ///
    /// Stops the system if the live mounted device has lost its VPB association.
    pub(crate) fn publish_volume_lock(device: KernelDevice, locked: bool) {
        let locked_flag = u16::try_from(wdk_sys::VPB_LOCKED).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        Self::update_vpb_flags(device, |flags| {
            if locked {
                *flags |= locked_flag;
            } else {
                *flags &= !locked_flag;
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Publishes that direct lower-volume writes are permitted after logical dismount.
    /// # Errors
    ///
    /// Stops the system if the live mounted device has lost its VPB association.
    pub(crate) fn publish_direct_writes_allowed(device: KernelDevice) {
        let direct_writes =
            u16::try_from(wdk_sys::VPB_DIRECT_WRITES_ALLOWED).unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        Self::update_vpb_flags(device, |flags| *flags |= direct_writes).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
    }

    /// Stops shutdown IRP delivery after this volume has logically dismounted.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    pub(crate) fn unregister_shutdown_notification(device: KernelDevice) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Successful mount registered this live mounted device exactly once, and the
            // actor's one-way dismount transition calls this exactly once.
            ffi::IoUnregisterShutdownNotification(device.as_ptr());
        }
        #[cfg(test)]
        let _device = device;
    }

    /// Notifies FsRtl that this lower storage volume completed a dismount request.
    /// # Errors
    ///
    /// Stops the system if the mounted device has lost its VPB/real-device association.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn complete_dismount(device: KernelDevice) {
        let real_device = Self::with_vpb(device, |vpb| unsafe {
            // SAFETY: The locked VPB retains its associated real device during this operation.
            KernelDevice::from_raw(vpb.RealDevice).ok_or(DriverError::InvalidParameter)
        })
        .and_then(core::convert::identity)
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The VPB identified this live lower storage device and logical dismount
            // completed successfully before this notification.
            ffi::FsRtlDismountComplete(real_device.as_ptr(), STATUS_SUCCESS);
        }
        #[cfg(test)]
        let _real_device = real_device;
    }

    /// Mutates VPB flags while holding the global VPB spin lock in production.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB is absent.
    fn update_vpb_flags(device: KernelDevice, update: impl FnOnce(&mut u16)) -> DriverResult<()> {
        Self::with_vpb(device, |vpb| update(&mut vpb.Flags))
    }

    /// Removes this mounted device from its VPB while holding the global VPB lock.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn detach_vpb(device: KernelDevice) {
        let mounted = u16::try_from(wdk_sys::VPB_MOUNTED).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        let locked = u16::try_from(wdk_sys::VPB_LOCKED).unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        });
        let direct_writes =
            u16::try_from(wdk_sys::VPB_DIRECT_WRITES_ALLOWED).unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        Self::with_vpb(device, |vpb| {
            if vpb.DeviceObject != device.as_ptr() {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
            }
            vpb.Flags &= !(mounted | locked | direct_writes);
            vpb.DeviceObject = core::ptr::null_mut();
            let device_object = unsafe {
                // SAFETY: The VPB lock is held and terminal teardown still owns the device.
                device.as_ptr().as_mut()
            }
            .unwrap_or_else(|| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
            device_object.Vpb = core::ptr::null_mut();
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Runs one nonblocking VPB access under the global VPB spin lock in production.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB is absent.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn with_vpb<R>(
        device: KernelDevice,
        operation: impl FnOnce(&mut wdk_sys::VPB) -> R,
    ) -> DriverResult<R> {
        #[cfg(not(test))]
        let mut irql = 0;
        #[cfg(not(test))]
        unsafe {
            // SAFETY: `irql` is writable stack storage paired with the release below.
            ffi::IoAcquireVpbSpinLock(core::ptr::addr_of_mut!(irql));
        }
        let result = (|| {
            let device = unsafe {
                // SAFETY: The actor-owned mounted device remains live throughout this operation.
                device.as_ptr().as_mut()
            }
            .ok_or(DriverError::InvalidParameter)?;
            let vpb = unsafe {
                // SAFETY: The VPB spin lock protects this mounted association in production.
                device.Vpb.as_mut()
            }
            .ok_or(DriverError::InvalidParameter)?;
            Ok(operation(vpb))
        })();
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This balances the immediately preceding successful VPB-lock acquisition.
            ffi::IoReleaseVpbSpinLock(irql);
        }
        result
    }
}

/// PASSIVE_LEVEL work-item callback that joins the retiring actor and deletes its device.
/// # Safety
///
/// `device` and `context` must be the unique pair queued by
/// `MountedVolumeDevice::schedule_retirement`.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn mounted_volume_retirement(device: PDEVICE_OBJECT, context: wdk_sys::PVOID) {
    let Some(device) = (unsafe {
        // SAFETY: The queued work item retains the device supplied at retirement scheduling.
        KernelDevice::from_raw(device)
    }) else {
        KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
    };
    let work_item = NonNull::new(context.cast::<wdk_sys::_IO_WORKITEM>())
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    if MountedVolumeDevice::retirement_work_item(device) != work_item {
        KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
    }
    unsafe {
        // SAFETY: Work-item ownership excludes driver unload and pins the device while release
        // closes admission, drains the actor, and destroys extension-owned resources.
        MountedVolumeDevice::release(device);
    }
    unsafe {
        // SAFETY: All extension resources are gone and the work item still pins this device.
        ffi::IoDeleteDevice(device.as_ptr());
    }
    unsafe {
        // SAFETY: The system dequeued this item before invoking the callback. This final operation
        // releases its device reference and may complete pending device deletion.
        ffi::IoFreeWorkItem(work_item.as_ptr());
    }
}

/// Registers a mounted filesystem device for shutdown delivery.
/// # Errors
///
/// Returns an error when the I/O Manager cannot register the mounted device for
/// `IRP_MJ_SHUTDOWN` delivery.
#[cfg_attr(
    not(test),
    expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )
)]
fn register_shutdown_notification(device: KernelDevice) -> DriverResult<()> {
    #[cfg(not(test))]
    {
        let status = unsafe {
            // SAFETY: `device` is a live mounted filesystem device whose
            // dispatch table owns IRP_MJ_SHUTDOWN before it is published.
            ffi::IoRegisterShutdownNotification(device.as_ptr())
        };
        shutdown_registration_status(status)
    }
    #[cfg(test)]
    {
        let _device = device;
        Ok(())
    }
}

/// Converts shutdown-registration status into the driver error domain.
/// # Errors
///
/// Returns an error when the I/O Manager rejected shutdown-notification registration.
pub(super) fn shutdown_registration_status(status: wdk_sys::NTSTATUS) -> DriverResult<()> {
    if status < STATUS_SUCCESS {
        return Err(DriverError::InsufficientResources);
    }
    Ok(())
}

/// Count of UTF-16 code units exposed by WDK VPB::VolumeLabel.
const VPB_VOLUME_LABEL_UNITS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// VPB label payload prevalidated before mount publish mutates kernel-visible state.
struct VpbLabel {
    /// UTF-16 code units to copy into VPB::VolumeLabel.
    units: [u16; VPB_VOLUME_LABEL_UNITS],
    /// Byte length stored in VPB::VolumeLabelLength.
    byte_len: u16,
}

impl VpbLabel {
    /// Encodes an ext4 label into the VPB label layout.
    /// # Errors
    ///
    /// Returns an error when the ext4 label exceeds the VPB label capacity or the UTF-16 byte
    /// length cannot be represented by the VPB.
    fn encode(label: ext4_core::Ext4VolumeLabel) -> DriverResult<Self> {
        let bytes = label.bytes();
        if bytes.len() > VPB_VOLUME_LABEL_UNITS {
            return Err(DriverError::InvalidParameter);
        }
        let mut units = [0_u16; VPB_VOLUME_LABEL_UNITS];
        for (target, byte) in units.iter_mut().zip(bytes.iter().copied()) {
            *target = u16::from(byte);
        }
        let wchar_bytes = bytes
            .len()
            .checked_mul(core::mem::size_of::<u16>())
            .ok_or(DriverError::InvalidParameter)?;
        let byte_len = u16::try_from(wchar_bytes).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self { units, byte_len })
    }

    /// Writes a prevalidated label into a VPB.
    fn write_to(self, vpb: &mut wdk_sys::VPB) {
        vpb.VolumeLabel = self.units;
        vpb.VolumeLabelLength = self.byte_len;
    }
}
