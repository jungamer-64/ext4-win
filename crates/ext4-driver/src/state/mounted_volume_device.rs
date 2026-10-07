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
    /// Captured before actor publication; usable only under the header's live dispatch lease.
    storage: crate::kernel::stream::VolumeStorageAccess,
    /// PnP-only publication authority; storage workers retain only the narrower access view.
    removal: crate::kernel::stream::StorageRemovalPublisher,
    /// Immutable lower route used by device-scoped PnP requests without a FILE_OBJECT.
    lower: KernelDevice,
    /// Sole shutdown-notification ownership, consumed once by dismount or removal.
    shutdown_registered: AtomicU8,
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
    /// target is absent or invalid, or allocation clusters are not integral logical sectors.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn initialize(
        device: KernelDevice,
        vcb: Pin<Box<VolumeControlBlock>>,
        vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<()> {
        let stack_size = real_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let transfer_alignment = real_device.transfer_buffer_alignment()?;
        let sector_size = vcb.runtime.storage().filesystem_sector_size();
        let _sectors = sector_size
            .sectors_per_cluster(vcb.runtime.current_epoch().geometry().cluster_size())?;
        let sector_bytes =
            u16::try_from(sector_size.as_u32()).map_err(|_| DriverError::InvalidParameter)?;
        let trace = vcb.trace;
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
        let extension_pointer = NonNull::new(
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>(),
        )
        .ok_or(DriverError::InvalidParameter)?;
        let storage = unsafe {
            // SAFETY: The pinned VCB outlives every reactor/dispatch lease on this extension.
            vcb.stream_context.storage_access()?
        };
        let removal = unsafe {
            // SAFETY: This mount installs the sole PnP publisher under device dispatch rundown.
            vcb.stream_context.storage_removal_publisher()?
        };
        let lower = vcb.runtime.storage().filesystem_control_device();
        let storage_slot = unsafe {
            // SAFETY: The unborrowed extension allocation has the exact mounted-extension layout.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).storage)
        };
        unsafe {
            // SAFETY: This initializes previously uninitialized non-null capability storage.
            storage_slot.write(storage);
        }
        let lower_slot = unsafe {
            // SAFETY: The mounted-extension allocation contains this lower route field.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).lower)
        };
        unsafe {
            // SAFETY: The captured retained route initializes this non-null field before borrowing.
            lower_slot.write(lower);
        }
        let removal_slot = unsafe {
            // SAFETY: The mounted allocation contains this uninitialized publisher field.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).removal)
        };
        unsafe {
            // SAFETY: Initialize the publisher before borrowing any typed extension value.
            removal_slot.write(removal);
        }
        let extension = unsafe {
            // SAFETY: The I/O Manager zeroed extension storage; all non-null fields are now valid.
            &mut *extension_pointer.as_ptr()
        };
        extension.retirement_work_item = core::ptr::null_mut();
        extension.shutdown_registered = AtomicU8::new(0);
        unsafe {
            // SAFETY: The extension is stable device-owned storage for this
            // just-created mounted volume device.
            DeviceExtensionHeader::initialize_at(
                core::ptr::addr_of_mut!(extension.header),
                DeviceExtensionKind::MOUNTED_VOLUME,
                device,
                ReactorTarget::MountedVolume(MountedVolumeBinding::new(vcb)),
                trace,
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
        extension.shutdown_registered.store(1, Ordering::Release);
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

        device_object.Flags |= DO_DIRECT_IO;
        device_object.StackSize = stack_size;
        device_object.AlignmentRequirement = transfer_alignment.as_mask();
        device_object.SectorSize = sector_bytes;

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
        Self::unregister_shutdown_notification(device);
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

    /// Retains the VPB's real device before a sector query leaves actor ownership.
    /// # Errors
    ///
    /// Rejects a missing mounted VPB or real device without queueing native work.
    pub(crate) fn prepare_sector_query(
        device: KernelDevice,
    ) -> DriverResult<crate::kernel::storage::SectorSizeQuery> {
        Self::with_vpb(device, |vpb| {
            #[expect(
                unsafe_code,
                reason = "the VPB lock protects the live real-device association during reference acquisition"
            )]
            let real_device = unsafe {
                // SAFETY: The mounted VPB and its real device remain live under the VPB lock.
                KernelDevice::from_raw(vpb.RealDevice)
            }
            .ok_or(DriverError::InvalidParameter)?;
            Ok(crate::kernel::storage::SectorSizeQuery::reference(
                real_device,
            ))
        })?
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
    #[expect(
        unsafe_code,
        reason = "the mounted lifecycle owner retains the device and initialized extension through shutdown release"
    )]
    pub(crate) fn unregister_shutdown_notification(device: KernelDevice) {
        let device_object = unsafe {
            // SAFETY: The mounted lifecycle owner retains this live DEVICE_OBJECT.
            &*device.as_ptr()
        };
        let extension = unsafe {
            // SAFETY: The live mounted device owns its initialized extension throughout this call.
            &*device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
        };
        if extension.shutdown_registered.swap(0, Ordering::AcqRel) == 0 {
            return;
        }
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Successful mount registered this live mounted device exactly once, and the
            // actor's one-way dismount transition calls this exactly once.
            ffi::IoUnregisterShutdownNotification(device.as_ptr());
        }
        #[cfg(test)]
        let _device = device;
    }

    /// Forwards a PnP IRP while mounted state remains retained by dispatch rundown. Terminal
    /// notifications revoke shared stream/storage admission before handing the original IRP to
    /// the lower stack. No actor work item, IRP replacement, or completion allocation is required.
    #[expect(
        unsafe_code,
        reason = "the received IRP retains its mounted device and initialized extension through dispatch rundown"
    )]
    pub(crate) fn dispatch_pnp(
        received: ReceivedIrp,
        minor: crate::irp::PnpMinor,
    ) -> wdk_sys::NTSTATUS {
        let device = received.device();
        let device_object = unsafe {
            // SAFETY: The received IRP retains this driver's mounted DEVICE_OBJECT.
            &*device.as_ptr()
        };
        let extension = unsafe {
            // SAFETY: Dispatch classified this driver's live mounted-volume device.
            &*device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
        };
        match extension
            .header
            .with_reactor(received, |received, reactor| {
                match minor {
                    crate::irp::PnpMinor::QueryRemove => {
                        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                    }
                    crate::irp::PnpMinor::SurpriseRemoval | crate::irp::PnpMinor::Remove => {
                        let notification = if minor == crate::irp::PnpMinor::Remove {
                            crate::kernel::stream::StorageRemovalNotification::Final
                        } else {
                            crate::kernel::stream::StorageRemovalNotification::Surprise
                        };
                        extension.removal.publish(notification);
                        reactor.storage_removal_published();
                    }
                    crate::irp::PnpMinor::CancelRemove => {
                        return received.cancel_remove(extension.lower, &extension.removal);
                    }
                    crate::irp::PnpMinor::Other => {}
                }
                received.forward_pnp(extension.lower, minor)
            }) {
            Ok(status) => status,
            Err(received) => received.complete_result(Err(DriverError::DeviceRemoved)),
        }
    }

    /// Delegates an original volume IOCTL under dispatch lifetime and storage admission. The
    /// submission resource is released when IoCallDriver returns, including STATUS_PENDING.
    #[expect(
        unsafe_code,
        reason = "the received mounted-device IRP retains this initialized extension"
    )]
    pub(crate) fn forward_volume_control(
        received: ReceivedIrp,
        lower: KernelDevice,
    ) -> wdk_sys::NTSTATUS {
        let device = received.device();
        let device_object = unsafe {
            // SAFETY: The received IRP retains this driver's mounted DEVICE_OBJECT.
            &*device.as_ptr()
        };
        let extension = unsafe {
            // SAFETY: Dispatch classified the driver's live mounted-volume extension.
            &*device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
        };
        match extension
            .header
            .with_reactor(received, |received, _reactor| {
                match extension.storage.acquire_submission() {
                    Ok(_submission) => received.forward_device_control(lower),
                    Err(error) => received.complete_result(Err(error)),
                }
            }) {
            Ok(status) => status,
            Err(received) => received.complete_result(Err(DriverError::DeviceRemoved)),
        }
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
