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
    /// Mounted association retained by the operation until reactor drain.
    device: KernelDevice,
    /// Fully encoded fixed-capacity VPB label.
    label: VpbLabel,
}

impl PreparedVpbLabelPublication {
    /// Publishes under the VPB lock after ext4 commit; retirement cannot race the owning operation.
    pub(crate) fn publish(self) {
        VpbSpinLock::with_mounted(self.device, |vpb| self.label.write_to(vpb)).unwrap_or_else(
            |_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck(),
        );
    }
}

impl MountedVolumeDevice {
    /// Initializes an IoCreateDevice-created mounted device and takes ownership
    /// of the VCB.
    /// # Errors
    ///
    /// Returns an error for invalid device/sector geometry, resource initialization failure,
    /// or a VPB that has no real device, is occupied, or is being removed. A failed mount leaves
    /// the supplied VPB unchanged and releases extension-owned resources before device deletion.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn initialize(
        device: KernelDevice,
        vcb: Pin<Box<VolumeControlBlock>>,
        vpb: KernelVpb,
        target_device: KernelDevice,
    ) -> DriverResult<()> {
        let stack_size = target_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let transfer_alignment = target_device.transfer_buffer_alignment()?;
        let sector_size = vcb.runtime.storage().filesystem_sector_size();
        let _sectors = sector_size
            .sectors_per_cluster(vcb.runtime.current_epoch().geometry().cluster_size())?;
        let sector_bytes =
            u16::try_from(sector_size.as_u32()).map_err(|_| DriverError::InvalidParameter)?;
        let trace = vcb.trace;
        let identity = vcb.runtime.identity();
        let [a, b, c, d, ..] = identity.uuid().bytes();
        let serial_number = VolumeSerialNumber::from_le_bytes([a, b, c, d]).as_u32();
        let volume_label = VpbLabel::encode(identity.label())?;
        let extension_slot = unsafe {
            // SAFETY: The mount exclusively owns this newly created, unpublished device.
            core::ptr::addr_of!((*device.as_ptr()).DeviceExtension)
        };
        let extension_storage = unsafe {
            // SAFETY: IoCreateDevice initialized this stable pointer before returning the device.
            extension_slot.read()
        };
        let extension_pointer =
            NonNull::new(extension_storage.cast::<MountedVolumeDeviceExtension>())
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
        let header_slot = unsafe {
            // SAFETY: The initialized header occupies this field at its final address.
            core::ptr::addr_of!((*extension_pointer.as_ptr()).header)
        };
        let header = unsafe {
            // SAFETY: The complete header is independently synchronized after final placement.
            &*header_slot
        };
        if let Err(error) = register_shutdown_notification(device) {
            unsafe {
                // SAFETY: Shutdown registration failed before this device was
                // published, so no actor continuation can still own the executor.
                let target = header.retire();
                drop(target);
            }
            return Err(error);
        }
        let shutdown_slot = unsafe {
            // SAFETY: Project the initialized atomic independently of the header and work item.
            core::ptr::addr_of!((*extension_pointer.as_ptr()).shutdown_registered)
        };
        let shutdown_registered = unsafe {
            // SAFETY: Registration ownership uses this disjoint atomic at its final address.
            &*shutdown_slot
        };
        shutdown_registered.store(1, Ordering::Release);
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
                let target = header.retire();
                drop(target);
            }
            return Err(DriverError::InsufficientResources);
        }
        let retirement_slot = unsafe {
            // SAFETY: Project the work-item slot independently of the header and atomic leases.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).retirement_work_item)
        };
        unsafe {
            // SAFETY: The device remains unpublished and the work item cannot yet be queued.
            retirement_slot.write(retirement_work_item);
        }

        let device_object = unsafe {
            // SAFETY: Mount owns the unpublished device; this borrow ends before VPB publication.
            &mut *device.as_ptr()
        };
        device_object.Flags |= DO_DIRECT_IO;
        device_object.StackSize = stack_size;
        device_object.AlignmentRequirement = transfer_alignment.as_mask();
        device_object.SectorSize = sector_bytes;

        if let Err(error) = VpbSpinLock::publish_mount(vpb, device, serial_number, volume_label) {
            Self::unregister_shutdown_notification(device);
            unsafe {
                // SAFETY: Publication failed without changing the VPB. This mount still owns
                // the unpublished device; retire joins any shutdown dispatch before VCB release.
                let target = header.retire();
                drop(target);
            }
            #[cfg(not(test))]
            unsafe {
                // SAFETY: This work item was allocated above and was never queued.
                ffi::IoFreeWorkItem(retirement_work_item);
            }
            unsafe {
                // SAFETY: Retirement joined the actor; the unqueued work item was freed above.
                retirement_slot.write(core::ptr::null_mut());
            }
            return Err(error);
        }
        unsafe {
            // SAFETY: Mount owns initialization; VPB publication completed and its lock is released.
            (*device.as_ptr()).Flags &= !DO_DEVICE_INITIALIZING;
        }
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

    /// Prepares label bytes and checks the mounted association before ext4 mutation begins.
    /// # Errors
    /// Returns invalid parameter for a missing or foreign association or an unencodable label.
    pub(crate) fn prepare_vpb_label_publication(
        device: KernelDevice,
        volume_label: ext4_core::Ext4VolumeLabel,
    ) -> DriverResult<PreparedVpbLabelPublication> {
        let label = VpbLabel::encode(volume_label)?;
        VpbSpinLock::with_mounted(device, |_| ())?;
        Ok(PreparedVpbLabelPublication { device, label })
    }

    /// Retains the VPB's real device before a sector query leaves actor ownership.
    /// # Errors
    ///
    /// Rejects a missing mounted VPB or real device without queueing native work.
    pub(crate) fn prepare_sector_query(
        device: KernelDevice,
    ) -> DriverResult<crate::kernel::storage::SectorSizeQuery> {
        VpbSpinLock::with_mounted(device, |vpb| {
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
        let real_device = VpbSpinLock::with_mounted(device, |vpb| unsafe {
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
        VpbSpinLock::with_mounted(device, |vpb| update(&mut vpb.Flags))
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
        VpbSpinLock::with_mounted(device, |vpb| {
            vpb.Flags &= !(mounted | locked | direct_writes);
            vpb.DeviceObject = core::ptr::null_mut();
            let association = unsafe {
                // SAFETY: The lock protects this association and teardown owns the live device.
                core::ptr::addr_of_mut!((*device.as_ptr()).Vpb)
            };
            unsafe {
                // SAFETY: Clear this mounted device's association before its VPB lock is released.
                association.write(core::ptr::null_mut());
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }
}

/// Thread-local ownership of the global VPB spin lock required by the
/// [Windows VPB contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_vpb).
/// All callbacks must be nonblocking and use nonpaged data; no VPB reference may escape the
/// callback or survive lock release.
struct VpbSpinLock {
    /// IRQL to restore on the same thread that acquired the native lock.
    #[cfg(not(test))]
    irql: wdk_sys::KIRQL,
    /// Host serialization follows the same lexical access boundary as the kernel lock.
    #[cfg(test)]
    _guard: MutexGuard<'static, ()>,
    /// Native spin-lock/IRQL ownership cannot transfer between threads.
    _thread: PhantomData<*mut ()>,
}

/// Host counterpart of the I/O Manager's single VPB lock, with no VPB storage authority.
#[cfg(test)]
static VPB_LOCK: Mutex<()> = Mutex::new(());

impl VpbSpinLock {
    /// Acquires before any VPB field or mounted association is accessed.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "owns one native VPB lock acquisition and saved thread IRQL"
        )
    )]
    fn acquire() -> Self {
        #[cfg(not(test))]
        {
            let mut irql = 0;
            unsafe {
                // SAFETY: Writable KIRQL storage is passed to the I/O Manager; Drop balances
                // acquisition on this thread before returning to the caller.
                ffi::IoAcquireVpbSpinLock(core::ptr::addr_of_mut!(irql));
            }
            Self {
                irql,
                _thread: PhantomData,
            }
        }
        #[cfg(test)]
        Self {
            _guard: VPB_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            _thread: PhantomData,
        }
    }

    /// Publishes filesystem-owned fields without replacing the I/O Manager's real device,
    /// reference count or mount-completion flag. Failure leaves both associations unchanged.
    /// # Errors
    /// Returns invalid parameter for an absent real device, device busy for an occupied VPB,
    /// or device removed when PnP has begun withdrawing its storage.
    #[expect(
        unsafe_code,
        reason = "the mount IRP retains the supplied VPB and unpublished device under the VPB lock"
    )]
    fn publish_mount(
        supplied: KernelVpb,
        device: KernelDevice,
        serial_number: u32,
        label: VpbLabel,
    ) -> DriverResult<()> {
        let _lock = Self::acquire();
        let vpb = unsafe {
            // SAFETY: The mount IRP retains this supplied VPB; the lock excludes other field access.
            &mut *supplied.as_non_null().as_ptr()
        };
        if vpb.RealDevice.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        let remove_pending = u16::try_from(wdk_sys::VPB_REMOVE_PENDING)
            .map_err(|_| DriverError::InvalidParameter)?;
        if vpb.Flags & remove_pending != 0 {
            return Err(DriverError::DeviceRemoved);
        }
        if !vpb.DeviceObject.is_null() {
            return Err(DriverError::DeviceBusy);
        }
        let association = unsafe {
            // SAFETY: The mount owns the unpublished device and the lock protects its association.
            core::ptr::addr_of_mut!((*device.as_ptr()).Vpb)
        };
        unsafe {
            // SAFETY: The writable device field is published together with VPB.DeviceObject.
            association.write(supplied.as_non_null().as_ptr());
        }
        vpb.SerialNumber = serial_number;
        label.write_to(vpb);
        vpb.DeviceObject = device.as_ptr();
        Ok(())
    }

    /// Borrows only this device's live mounted VPB while holding the global lock.
    /// # Errors
    /// Returns invalid parameter for a missing VPB or an association owned by another device.
    #[expect(
        unsafe_code,
        reason = "the caller retains the mounted device and VPB until its admitted operation drains"
    )]
    fn with_mounted<R>(
        device: KernelDevice,
        operation: impl FnOnce(&mut wdk_sys::VPB) -> R,
    ) -> DriverResult<R> {
        let _lock = Self::acquire();
        let association = unsafe {
            // SAFETY: Device rundown retains this object and the lock protects its VPB association.
            core::ptr::addr_of!((*device.as_ptr()).Vpb)
        };
        let pointer = unsafe {
            // SAFETY: This initialized association is read only while its global lock is held.
            association.read()
        };
        let vpb = unsafe {
            // SAFETY: The mounted device retains the associated VPB and the global lock excludes
            // concurrent field access. The callback cannot retain this borrow.
            pointer.as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        if vpb.DeviceObject != device.as_ptr() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(operation(vpb))
    }
}

impl Drop for VpbSpinLock {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "balances native lock acquisition on its original thread"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This non-transferable guard owns the matching acquisition and saved IRQL.
            ffi::IoReleaseVpbSpinLock(self.irql);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::Ext4VolumeLabel;

    /// # Errors
    /// Returns fixture label or native scalar conversion errors.
    /// # Panics
    /// Panics if mount, label publication or detach changes I/O Manager-owned fields.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this fixture retains native device and VPB allocations until detach"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions report protocol regressions after fallible fixture setup"
    )]
    fn vpb_mount_label_and_detach_preserve_io_manager_state() -> DriverResult<()> {
        let mut real = wdk_sys::DEVICE_OBJECT::default();
        let mut mounted = wdk_sys::DEVICE_OBJECT::default();
        let persistent =
            u16::try_from(wdk_sys::VPB_PERSISTENT).map_err(|_| DriverError::InvalidParameter)?;
        let mut vpb = wdk_sys::VPB {
            Type: 10,
            Size: 96,
            RealDevice: core::ptr::addr_of_mut!(real),
            ReferenceCount: 3,
            Flags: persistent,
            ..Default::default()
        };
        let device = unsafe {
            // SAFETY: The stack device remains live through this fixture's final detach.
            KernelDevice::from_raw(core::ptr::addr_of_mut!(mounted))
        }
        .ok_or(DriverError::InvalidParameter)?;
        let supplied = unsafe {
            // SAFETY: The fixture keeps this VPB live until every access is finished.
            KernelVpb::from_raw(core::ptr::addr_of_mut!(vpb))
        }
        .ok_or(DriverError::InvalidParameter)?;
        let label = VpbLabel::encode(Ext4VolumeLabel::new(b"AB")?)?;
        VpbSpinLock::publish_mount(supplied, device, 0x1234_5678, label)?;
        assert_eq!(mounted.Vpb, core::ptr::addr_of_mut!(vpb));
        assert_eq!(vpb.DeviceObject, device.as_ptr());
        assert_eq!(vpb.RealDevice, core::ptr::addr_of_mut!(real));
        assert_eq!((vpb.Type, vpb.Size, vpb.ReferenceCount), (10, 96, 3));
        assert_eq!(vpb.Flags, persistent);
        assert_eq!(vpb.SerialNumber, 0x1234_5678);
        assert_eq!(vpb.VolumeLabelLength, 4);
        assert_eq!(vpb.VolumeLabel.get(..3), Some([65, 66, 0].as_slice()));

        // The I/O Manager marks the mount when its successful mount IRP completes.
        VpbSpinLock::with_mounted(device, |vpb| {
            vpb.Flags |= u16::try_from(wdk_sys::VPB_MOUNTED).unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        })?;
        let publication = MountedVolumeDevice::prepare_vpb_label_publication(
            device,
            Ext4VolumeLabel::new(b"Z")?,
        )?;
        assert_eq!(vpb.VolumeLabelLength, 4);
        publication.publish();
        VpbSpinLock::with_mounted(device, |vpb| {
            assert!(matches!(
                VPB_LOCK.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            assert_eq!(vpb.VolumeLabelLength, 2);
            assert_eq!(vpb.VolumeLabel.first(), Some(&90));
            assert!(vpb.VolumeLabel.iter().skip(1).all(|unit| *unit == 0));
            assert_eq!(vpb.SerialNumber, 0x1234_5678);
        })?;
        MountedVolumeDevice::publish_volume_lock(device, true);
        MountedVolumeDevice::publish_direct_writes_allowed(device);
        MountedVolumeDevice::detach_vpb(device);
        assert!(mounted.Vpb.is_null());
        assert!(vpb.DeviceObject.is_null());
        assert_eq!(vpb.RealDevice, core::ptr::addr_of_mut!(real));
        assert_eq!((vpb.Type, vpb.Size, vpb.ReferenceCount), (10, 96, 3));
        assert_eq!(vpb.Flags, persistent);
        assert_eq!(
            VpbSpinLock::with_mounted(device, |_| ()),
            Err(DriverError::InvalidParameter)
        );
        Ok(())
    }

    /// # Errors
    /// Returns fixture label or native scalar conversion errors.
    /// # Panics
    /// Panics if mount failure publishes an association or loses existing VPB metadata.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the fixture owns live native storage throughout every mount attempt"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions report atomicity failures after fallible fixture setup"
    )]
    fn rejected_vpb_mount_leaves_both_associations_unchanged() -> DriverResult<()> {
        let mut real = wdk_sys::DEVICE_OBJECT::default();
        let mut mounted = wdk_sys::DEVICE_OBJECT::default();
        let mut other = wdk_sys::DEVICE_OBJECT::default();
        let mut vpb = wdk_sys::VPB::default();
        let device = unsafe {
            // SAFETY: This local device stays live across every publication attempt.
            KernelDevice::from_raw(core::ptr::addr_of_mut!(mounted))
        }
        .ok_or(DriverError::InvalidParameter)?;
        let supplied = unsafe {
            // SAFETY: This local VPB stays live across every publication attempt.
            KernelVpb::from_raw(core::ptr::addr_of_mut!(vpb))
        }
        .ok_or(DriverError::InvalidParameter)?;
        let label = VpbLabel::encode(Ext4VolumeLabel::new(b"publish")?)?;
        let removed = u16::try_from(wdk_sys::VPB_REMOVE_PENDING)
            .map_err(|_| DriverError::InvalidParameter)?;
        for (real_device, current, flags, expected) in [
            (
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                DriverError::InvalidParameter,
            ),
            (
                core::ptr::addr_of_mut!(real),
                core::ptr::addr_of_mut!(other),
                0,
                DriverError::DeviceBusy,
            ),
            (
                core::ptr::addr_of_mut!(real),
                core::ptr::null_mut(),
                removed,
                DriverError::DeviceRemoved,
            ),
        ] {
            vpb.RealDevice = real_device;
            vpb.DeviceObject = current;
            vpb.Flags = flags;
            vpb.SerialNumber = 7;
            vpb.VolumeLabelLength = 6;
            vpb.VolumeLabel = [42; 32];
            vpb.ReferenceCount = 5;
            assert_eq!(
                VpbSpinLock::publish_mount(supplied, device, 99, label),
                Err(expected)
            );
            assert!(mounted.Vpb.is_null());
            assert_eq!(vpb.DeviceObject, current);
            assert_eq!(vpb.RealDevice, real_device);
            assert_eq!(vpb.Flags, flags);
            assert_eq!(vpb.SerialNumber, 7);
            assert_eq!(vpb.VolumeLabelLength, 6);
            assert_eq!(vpb.VolumeLabel, [42; 32]);
            assert_eq!(vpb.ReferenceCount, 5);
        }
        vpb.RealDevice = core::ptr::addr_of_mut!(real);
        vpb.Flags = 0;
        VpbSpinLock::publish_mount(supplied, device, 99, label)?;
        assert_eq!(vpb.SerialNumber, 99);
        MountedVolumeDevice::detach_vpb(device);
        Ok(())
    }

    /// # Errors
    /// Returns fixture label construction errors.
    /// # Panics
    /// Panics if a foreign mounted association authorizes label or flag mutation.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the fixture retains the native objects named by its conflicting association"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions report authority regressions after fixture construction"
    )]
    fn foreign_vpb_association_rejects_mounted_publication() -> DriverResult<()> {
        let mut mounted = wdk_sys::DEVICE_OBJECT::default();
        let mut other = wdk_sys::DEVICE_OBJECT::default();
        let mut vpb = wdk_sys::VPB {
            DeviceObject: core::ptr::addr_of_mut!(other),
            VolumeLabel: [17; 32],
            VolumeLabelLength: 8,
            Flags: 3,
            ..Default::default()
        };
        mounted.Vpb = core::ptr::addr_of_mut!(vpb);
        let device = unsafe {
            // SAFETY: The device and both referenced objects remain live through this test.
            KernelDevice::from_raw(core::ptr::addr_of_mut!(mounted))
        }
        .ok_or(DriverError::InvalidParameter)?;
        assert!(matches!(
            MountedVolumeDevice::prepare_vpb_label_publication(device, Ext4VolumeLabel::new(b"Z")?),
            Err(DriverError::InvalidParameter)
        ));
        assert_eq!(
            MountedVolumeDevice::update_vpb_flags(device, |flags| *flags = 0),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(vpb.Flags, 3);
        assert_eq!(vpb.VolumeLabel, [17; 32]);
        assert_eq!(vpb.VolumeLabelLength, 8);
        Ok(())
    }
}
