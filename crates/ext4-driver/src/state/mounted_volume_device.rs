//! Mounted-volume device construction, VPB publication, and device retirement.

use super::*;

/// Windows volume serial number derived from the ext4 filesystem UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeSerialNumber {
    /// Raw serial value expected by WDK structures.
    value: u32,
}

impl VolumeSerialNumber {
    /// Derives the Windows serial from the first four bytes of the filesystem UUID.
    pub(crate) const fn from_uuid(uuid: ext4_core::FilesystemUuid) -> Self {
        let [a, b, c, d, ..] = uuid.bytes();
        Self {
            value: u32::from_le_bytes([a, b, c, d]),
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
    /// Mount reference and remount publication, retained until native reference retirement.
    vpb: UnsafeCell<MaybeUninit<MountedVpb>>,
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

/// Exact mounted association retained by the kernel verify IRP while raw I/O suspends.
#[derive(Debug)]
pub(crate) struct MediaVerificationAssociation {
    /// Mounted filesystem device whose reactor owns this operation.
    device: KernelDevice,
    /// Original VPB protected by the I/O Manager's pending verify ownership.
    vpb: KernelVpb,
    /// Real device whose verify flag may be acknowledged after a matching physical read.
    real_device: KernelDevice,
}

impl MediaVerificationAssociation {
    /// Consumes same-association evidence after I/O Manager verification, without clearing flags.
    /// # Errors
    /// Returns a replaced/removed association or a new verification requirement; no retry is granted.
    #[expect(
        unsafe_code,
        reason = "retained mounted lifetime and VPB lock protect both exact association observations"
    )]
    pub(crate) fn confirmed(self) -> DriverResult<()> {
        VpbSpinLock::with_mounted(self.device, |vpb| {
            if core::ptr::from_ref(vpb).cast_mut() != self.vpb.as_non_null().as_ptr()
                || vpb.RealDevice != self.real_device.as_ptr()
                || vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0
            {
                return Err(DriverError::WrongVolume);
            }
            // SAFETY: Mounted lifetime retains this native device; global VPB lock protects association.
            let current = unsafe { (*self.real_device.as_ptr()).Vpb };
            if current != self.vpb.as_non_null().as_ptr() {
                return Err(DriverError::WrongVolume);
            }
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            if crate::kernel::volume_verify::required(self.real_device) {
                return Err(DriverError::VerifyRequired);
            }
            Ok(())
        })?
    }
    /// Consumes acknowledgment authority only after revalidating the original mounted association.
    /// # Errors
    /// Returns changed association or removal without clearing any verify flag.
    #[expect(
        unsafe_code,
        reason = "the global VPB lock protects association checks; native acknowledgment atomically updates only the retained real-device flag"
    )]
    pub(crate) fn acknowledge(self) -> DriverResult<()> {
        VpbSpinLock::with_mounted(self.device, |vpb| {
            if core::ptr::from_ref(vpb).cast_mut() != self.vpb.as_non_null().as_ptr()
                || vpb.RealDevice != self.real_device.as_ptr()
                || vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0
            {
                return Err(DriverError::WrongVolume);
            }
            // SAFETY: The pending verify IRP retains this real device; the global lock protects its VPB association.
            let current = unsafe { (*self.real_device.as_ptr()).Vpb };
            if current != self.vpb.as_non_null().as_ptr() {
                return Err(DriverError::WrongVolume);
            }
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            crate::kernel::volume_verify::acknowledge(self.real_device);
            Ok(())
        })?
    }
}

impl MountedVolumeDevice {
    /// Captures the exact mounted association and separately retained real device for a lower gate.
    /// # Errors
    /// Returns missing/replaced/removing association before any native worker is queued.
    #[expect(
        unsafe_code,
        reason = "VPB lock and mounted lifetime retain the original association before independent worker reference acquisition"
    )]
    pub(crate) fn prepare_storage_verification(
        device: KernelDevice,
    ) -> DriverResult<(
        MediaVerificationAssociation,
        crate::kernel::volume_verify::VerificationDevice,
    )> {
        VpbSpinLock::with_mounted(device, |vpb| {
            if vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0 {
                return Err(DriverError::WrongVolume);
            }
            // SAFETY: The mounted lifetime owns this VPB, and the original operation retains it.
            let identity = unsafe { KernelVpb::from_raw(core::ptr::from_ref(vpb).cast_mut()) }
                .ok_or(DriverError::InvalidParameter)?;
            // SAFETY: Mounted VPB retention and its global lock protect real-device liveness.
            let real_device = unsafe { KernelDevice::from_raw(vpb.RealDevice) }
                .ok_or(DriverError::InvalidParameter)?;
            // SAFETY: The same VPB lock protects the current real-device association.
            let current = unsafe { (*real_device.as_ptr()).Vpb };
            if current != identity.as_non_null().as_ptr() {
                return Err(DriverError::WrongVolume);
            }
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            Ok((
                MediaVerificationAssociation {
                    device,
                    vpb: identity,
                    real_device,
                },
                crate::kernel::volume_verify::VerificationDevice::reference(real_device),
            ))
        })?
    }
    /// Retains a required I/O Manager verify before ordinary work can inspect a mounted cache.
    /// # Errors
    /// Returns withdrawn association or removal without issuing native I/O under the VPB lock.
    #[expect(
        unsafe_code,
        reason = "the mounted VPB lock establishes real-device liveness before the worker acquires its own reference"
    )]
    pub(crate) fn prepare_verify_work(
        device: KernelDevice,
    ) -> DriverResult<Option<crate::kernel::volume_verify::VerificationDevice>> {
        VpbSpinLock::with_mounted(device, |vpb| {
            if vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0 {
                return Err(DriverError::WrongVolume);
            }
            // SAFETY: The mounted association retains the real device while the global lock is held.
            let real_device = unsafe { KernelDevice::from_raw(vpb.RealDevice) }
                .ok_or(DriverError::InvalidParameter)?;
            // SAFETY: The same mounted reference and lock protect this association read.
            let current = unsafe { (*real_device.as_ptr()).Vpb };
            if current != core::ptr::from_ref(vpb).cast_mut() {
                return Err(DriverError::WrongVolume);
            }
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            if crate::kernel::volume_verify::required(real_device) {
                Ok(Some(
                    crate::kernel::volume_verify::VerificationDevice::reference(real_device),
                ))
            } else {
                Ok(None)
            }
        })?
    }
    /// Validates a captured kernel verify tuple before any raw I/O or mounted-state change.
    /// No VPB borrow, lock or actor reference survives the returned scalar association.
    /// # Errors
    /// Returns a foreign, withdrawn, removing or incomplete mounted association.
    #[expect(
        unsafe_code,
        reason = "kernel verify ownership retains both native identities while the global VPB lock protects their association"
    )]
    pub(crate) fn prepare_media_verification(
        target: crate::irp::VerifyVolumeTarget,
    ) -> DriverResult<MediaVerificationAssociation> {
        VpbSpinLock::with_mounted(target.device, |vpb| {
            if core::ptr::from_ref(vpb).cast_mut() != target.vpb.as_non_null().as_ptr()
                || vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0
            {
                return Err(DriverError::InvalidParameter);
            }
            // SAFETY: The mounted VPB retains its real device under the global VPB lock.
            let real_device = unsafe { KernelDevice::from_raw(vpb.RealDevice) }
                .ok_or(DriverError::InvalidParameter)?;
            // SAFETY: Kernel verify ownership and the VPB lock retain this native association.
            let current = unsafe { (*real_device.as_ptr()).Vpb };
            if current != target.vpb.as_non_null().as_ptr() {
                return Err(DriverError::WrongVolume);
            }
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            Ok(MediaVerificationAssociation {
                device: target.device,
                vpb: target.vpb,
                real_device,
            })
        })?
    }
    /// Associates an uninitialized create FILE_OBJECT with this mount's original VPB.
    ///
    /// The I/O Manager owns the create's VPB reference and releases it after the FILE_OBJECT
    /// closes. This records its identity without acquiring another reference. Dismount can
    /// replace the real device's current VPB, so the association comes from the mounted device.
    /// It remains on the FILE_OBJECT after filesystem contexts retire.
    /// # Errors
    /// Returns invalid parameter for a missing mounted association, or not-same-device if the
    /// I/O Manager supplied a different VPB. No association changes on failure.
    #[expect(
        unsafe_code,
        reason = "the create owner retains the unpublished FILE_OBJECT and the VPB lock protects its mount association"
    )]
    pub(crate) fn bind_create_vpb(
        device: KernelDevice,
        file_object: &mut UninitializedFileObject<'_>,
    ) -> DriverResult<()> {
        VpbSpinLock::with_mounted(device, |vpb| {
            let file = file_object.kernel_file_object();
            let vpb = core::ptr::from_mut(vpb);
            let current = unsafe {
                // SAFETY: The active create retains this FILE_OBJECT before filesystem attachment.
                (*file.as_ptr()).Vpb
            };
            if !current.is_null() && current != vpb {
                return Err(DriverError::NotSameDevice);
            }
            unsafe {
                // SAFETY: This mount retains its original VPB and the create owns publication
                // of the FILE_OBJECT association. The I/O Manager owns the routing reference.
                (*file.as_ptr()).Vpb = vpb;
            }
            Ok(())
        })?
    }

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
        binding: MountedVolumeBinding,
        vpb: KernelVpb,
        target_device: KernelDevice,
    ) -> DriverResult<()> {
        let stack_size = target_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;
        let transfer_alignment = target_device.transfer_buffer_alignment()?;
        let sector_size = binding.actor.runtime.storage().filesystem_sector_size();
        let _sectors = sector_size.sectors_per_cluster(
            binding
                .actor
                .runtime
                .current_epoch()
                .geometry()
                .cluster_size(),
        )?;
        let sector_bytes =
            u16::try_from(sector_size.as_u32()).map_err(|_| DriverError::InvalidParameter)?;
        // Retain only the native observation while actor ownership moves to its final address.
        let publication_reliability = binding.actor.runtime.observe_reliability()?;
        let trace = binding.volume().trace;
        let identity = binding.actor.runtime.identity();
        let serial_number = VolumeSerialNumber::from_uuid(identity.uuid()).as_u32();
        let volume_label = VpbLabel::encode(identity.label())?;
        let replacement_vpb = PoolVpb::try_new()?;
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
            binding.volume().stream_context.storage_access()?
        };
        let verification_device = {
            let _lock = VpbSpinLock::acquire();
            // SAFETY: The mount IRP retains this supplied VPB while the global lock excludes changes.
            let supplied = unsafe { vpb.as_non_null().as_ref() };
            // SAFETY: The supplied VPB retains its real device during mount preparation.
            let real = unsafe { KernelDevice::from_raw(supplied.RealDevice) }
                .ok_or(DriverError::InvalidParameter)?;
            crate::kernel::volume_verify::VerificationDevice::reference(real)
        };
        storage.bind_verification_device(verification_device)?;
        let removal = unsafe {
            // SAFETY: This mount installs the sole PnP publisher under device dispatch rundown.
            binding
                .volume()
                .stream_context
                .storage_removal_publisher()?
        };
        let lower = binding.actor.runtime.storage().filesystem_control_device();
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
        let retirement_slot = unsafe {
            // SAFETY: The unpublished allocation contains this disjoint writable field.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).retirement_work_item)
        };
        unsafe {
            // SAFETY: Mount owns initial construction of this unqueued work-item slot.
            retirement_slot.write(core::ptr::null_mut());
        }
        let shutdown_slot = unsafe {
            // SAFETY: The unpublished allocation contains this disjoint registration field.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).shutdown_registered)
        };
        unsafe {
            // SAFETY: No registration observer exists before device publication.
            shutdown_slot.write(AtomicU8::new(0));
        }
        let publication_slot = unsafe {
            // SAFETY: Mount exclusively owns this disjoint, unpublished VPB storage.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).vpb)
        };
        unsafe {
            // SAFETY: This initializes the cell without constructing a VPB publication owner.
            publication_slot.write(UnsafeCell::new(MaybeUninit::uninit()));
        }
        let header_slot = unsafe {
            // SAFETY: Project from the allocation pointer without an exclusive extension borrow
            // that could invalidate retained pointers after actor initialization.
            core::ptr::addr_of_mut!((*extension_pointer.as_ptr()).header)
        };
        unsafe {
            // SAFETY: The extension is stable device-owned storage for this
            // just-created mounted volume device.
            DeviceExtensionHeader::initialize_at(
                header_slot,
                DeviceExtensionKind::MOUNTED_VOLUME,
                device,
                ReactorTarget::MountedVolume(binding),
                trace,
            )?;
        }
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
        unsafe {
            // SAFETY: The device remains unpublished and the work item cannot yet be queued.
            retirement_slot.write(retirement_work_item);
        }

        unsafe {
            // SAFETY: Mount owns transfer-flag initialization before VPB publication.
            (*device.as_ptr()).Flags |= DO_DIRECT_IO;
        }
        unsafe {
            // SAFETY: Mount alone initializes this unpublished device's lower stack depth.
            (*device.as_ptr()).StackSize = stack_size;
        }
        unsafe {
            // SAFETY: Mount alone initializes this unpublished device's transfer alignment.
            (*device.as_ptr()).AlignmentRequirement = transfer_alignment.as_mask();
        }
        unsafe {
            // SAFETY: Mount alone initializes this unpublished device's transfer sector size.
            (*device.as_ptr()).SectorSize = sector_bytes;
        }

        let publication = match (|| {
            if publication_reliability.policy()
                == crate::kernel::io_reliability::NativeIoPolicy::Unavailable
            {
                return Err(DriverError::Core(ext4_core::Error::MmpOwnershipLost));
            }
            MountedVpb::publish(vpb, device, serial_number, volume_label, replacement_vpb)
        })() {
            Ok(publication) => publication,
            Err(error) => {
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
        };
        let publication_destination = unsafe {
            // SAFETY: The projected UnsafeCell field is initialized and disjoint from actor storage.
            (*publication_slot).get()
        };
        unsafe {
            // SAFETY: This slot is uninitialized; publication owns the unique mounted reference.
            publication_destination.write(MaybeUninit::new(publication));
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
        let extension = device.extension_address();
        let extension = unsafe {
            // SAFETY: The common extension kind was decoded as mounted before this call.
            extension.cast::<MountedVolumeDeviceExtension>().as_ref()
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
        Self::unregister_shutdown_notification(device);
        let publication = unsafe {
            // SAFETY: Mount initialized this owner; joined retirement uniquely consumes its slot.
            extension.vpb.get().cast::<MountedVpb>().read()
        };
        let retirement = publication.begin_retirement();
        #[cfg(test)]
        drop(retirement.try_finish().unwrap_or_else(|_| {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
        }));
        #[cfg(not(test))]
        {
            let mut retirement = retirement;
            loop {
                retirement = match retirement.try_finish() {
                    Ok(released) => {
                        drop(released);
                        break;
                    }
                    Err(retained) => retained,
                };
                {
                    let mut interval = LARGE_INTEGER { QuadPart: -100_000 };
                    let status = unsafe {
                        // SAFETY: This PASSIVE_LEVEL kernel worker retains the device and VPB owner;
                        // a non-alertable relative delay yields until I/O Manager references drain.
                        wdk_sys::ntddk::KeDelayExecutionThread(
                            0,
                            0,
                            core::ptr::addr_of_mut!(interval),
                        )
                    };
                    if status != STATUS_SUCCESS {
                        KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
                    }
                }
            }
        }
        drop(binding);
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
        let extension = device.extension_address();
        let extension = unsafe {
            // SAFETY: Retirement is emitted only by a mounted-volume actor.
            extension.cast::<MountedVolumeDeviceExtension>().as_ref()
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
        Self::with_vpb(device, |publication| publication.publish_lock(locked));
    }

    /// Withdraws remount routing after durable dismount; a retained raw-volume lock delays the
    /// replacement until its owner explicitly unlocks or is cleaned up.
    pub(crate) fn publish_dismount(device: KernelDevice) {
        Self::with_vpb(device, MountedVpb::publish_dismount);
    }

    /// Encloses a publication borrow within the caller's live mounted-device operation.
    #[expect(
        unsafe_code,
        reason = "mount publication initializes this owner before dispatch; retirement joins all callers before consuming it"
    )]
    fn with_vpb<R>(device: KernelDevice, work: impl FnOnce(&MountedVpb) -> R) -> R {
        let extension = unsafe {
            // SAFETY: The caller's actor or dispatch lifetime retains the initialized extension.
            &*device
                .extension_address()
                .cast::<MountedVolumeDeviceExtension>()
        };
        let publication = unsafe {
            // SAFETY: Completed mount initialized this disjoint owner before clearing initialization.
            &*extension.vpb.get().cast::<MountedVpb>()
        };
        work(publication)
    }

    /// Stops shutdown IRP delivery after this volume has logically dismounted.
    #[expect(
        unsafe_code,
        reason = "the mounted lifecycle owner retains the device and initialized extension through shutdown release"
    )]
    pub(crate) fn unregister_shutdown_notification(device: KernelDevice) {
        let extension = device.extension_address();
        let extension = unsafe {
            // SAFETY: The live mounted device owns its initialized extension throughout this call.
            &*extension.cast::<MountedVolumeDeviceExtension>()
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
        let extension = device.extension_address();
        let extension = unsafe {
            // SAFETY: Dispatch classified this driver's live mounted-volume device.
            &*extension.cast::<MountedVolumeDeviceExtension>()
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
        let extension = device.extension_address();
        let extension = unsafe {
            // SAFETY: Dispatch classified the driver's live mounted-volume extension.
            &*extension.cast::<MountedVolumeDeviceExtension>()
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
}

/// Nonpaged VPB allocation, released by the native pool rather than the Rust allocator.
/// Publication transfers this allocation to the I/O Manager's current device association.
#[derive(Debug)]
struct PoolVpb {
    /// Sole allocation/deallocation identity, with no retained Rust reference to its fields.
    allocation: NonNull<wdk_sys::VPB>,
}

impl PoolVpb {
    /// Prepares one initialized replacement before any mount or dismount publication.
    /// # Errors
    /// Returns allocation failure or an unrepresentable native VPB layout.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the unpublished native allocation is initialized once and transfers only through the VPB lock boundary"
        )
    )]
    fn try_new() -> DriverResult<Self> {
        let value = wdk_sys::VPB {
            Type: wdk_sys::IO_TYPE_VPB
                .try_into()
                .map_err(|_| DriverError::InvalidParameter)?,
            Size: core::mem::size_of::<wdk_sys::VPB>()
                .try_into()
                .map_err(|_| DriverError::InvalidParameter)?,
            ..Default::default()
        };
        #[cfg(not(test))]
        let allocation = {
            let storage = unsafe {
                // SAFETY: Nonzero native VPB size and tag request nonpaged, non-executable pool.
                wdk_sys::ntddk::ExAllocatePool2(
                    wdk_sys::POOL_FLAG_NON_PAGED,
                    core::mem::size_of::<wdk_sys::VPB>()
                        .try_into()
                        .map_err(|_| DriverError::InvalidParameter)?,
                    u32::from_le_bytes(*b"E4vp"),
                )
            };
            let allocation = NonNull::new(storage.cast::<wdk_sys::VPB>())
                .ok_or(DriverError::InsufficientResources)?;
            unsafe {
                // SAFETY: The allocation is exclusive, aligned native storage of exactly VPB size.
                allocation.as_ptr().write(value);
            }
            allocation
        };
        #[cfg(test)]
        let allocation = NonNull::new(Box::into_raw(memory::boxed_try_with(|| Ok(value))?))
            .ok_or(DriverError::InternalInvariantViolation)?;
        Ok(Self { allocation })
    }

    /// Transfers destruction to the current native device association.
    fn into_raw(self) -> NonNull<wdk_sys::VPB> {
        core::mem::ManuallyDrop::new(self).allocation
    }
}

impl Drop for PoolVpb {
    #[expect(
        unsafe_code,
        reason = "the sole native pool owner frees only unpublished replacements or detached VPBs after all references drain"
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Both native allocation and I/O Manager VPB storage use nonpaged pool.
            ffi::ExFreePool(self.allocation.as_ptr().cast());
        }
        #[cfg(test)]
        unsafe {
            // SAFETY: Host VPB fixtures and replacements originate only from boxed_try_with.
            drop(Box::from_raw(self.allocation.as_ptr()));
        }
    }
}

/// Native routing and replacement ownership, serialized by the global VPB lock.
#[derive(Debug)]
enum VpbPublication {
    /// The lower device still routes new opens to this mount.
    Mounted(PoolVpb),
    /// Durable dismount retains raw-write exclusion until its lock owner releases it.
    LockedDismount(PoolVpb),
    /// The I/O Manager owns a successor; this mount retains only its original VPB reference.
    Withdrawn,
}

/// Owns one mount-scoped VPB reference and its preallocated remount successor.
/// Old FILE_OBJECTs keep their original VPB; only the lower device's current VPB admits new mounts.
#[derive(Debug)]
struct MountedVpb {
    /// Contains the original VPB association until native retirement consumes the reference.
    device: KernelDevice,
    /// No reference to this mutable state survives the global lock acquisition.
    publication: UnsafeCell<VpbPublication>,
}

impl MountedVpb {
    /// Acquires a reference and publishes all mount fields atomically under the VPB lock.
    /// # Errors
    /// Returns missing/foreign real-device identity, occupied/removing VPB, or reference-budget
    /// exhaustion without changing either association. The unused successor remains unpublished.
    #[expect(
        unsafe_code,
        reason = "the mount request retains both native identities and transfers one reference before publishing dispatch"
    )]
    fn publish(
        supplied: KernelVpb,
        device: KernelDevice,
        serial_number: u32,
        label: VpbLabel,
        replacement: PoolVpb,
    ) -> DriverResult<Self> {
        let _lock = VpbSpinLock::acquire();
        let vpb = unsafe {
            // SAFETY: The mount IRP retains the supplied VPB while the global lock excludes mutation.
            &mut *supplied.as_non_null().as_ptr()
        };
        // SAFETY: The mount IRP retains this real device while the global VPB lock is held.
        let real = unsafe { KernelDevice::from_raw(vpb.RealDevice) }
            .ok_or(DriverError::InvalidParameter)?;
        let current = unsafe {
            // SAFETY: The mount request retains the real device; its VPB association uses this lock.
            (*real.as_ptr()).Vpb
        };
        if current != supplied.as_non_null().as_ptr() {
            return Err(DriverError::InvalidParameter);
        }
        if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
            return Err(DriverError::DeviceRemoved);
        }
        if !vpb.DeviceObject.is_null() {
            return Err(DriverError::DeviceBusy);
        }
        let references = vpb
            .ReferenceCount
            .checked_add(1)
            .ok_or(DriverError::InsufficientResources)?;
        vpb.ReferenceCount = references;
        vpb.SerialNumber = serial_number;
        label.write_to(vpb);
        vpb.DeviceObject = device.as_ptr();
        unsafe {
            // SAFETY: The unpublished mounted device's association publishes with the owned reference.
            (*device.as_ptr()).Vpb = supplied.as_non_null().as_ptr();
        }
        // All fallible mount initialization precedes this association publication. Only its
        // freshly validated mount/recovery protocol may acknowledge the physical verify flag.
        crate::kernel::volume_verify::acknowledge(real);
        Ok(Self {
            device,
            publication: UnsafeCell::new(VpbPublication::Mounted(replacement)),
        })
    }

    /// Publishes the native lock projection; releasing a dismounted lock also publishes remount routing.
    #[expect(
        unsafe_code,
        reason = "the global VPB lock serializes this interior state and the corresponding native flags"
    )]
    fn publish_lock(&self, locked: bool) {
        VpbSpinLock::with_mounted(self.device, |vpb| {
            if locked {
                vpb.Flags |= vpb_flag(wdk_sys::VPB_LOCKED);
            } else {
                vpb.Flags &= !vpb_flag(wdk_sys::VPB_LOCKED);
                let publication = unsafe {
                    // SAFETY: with_mounted holds the global lock, the sole mutation authority.
                    &mut *self.publication.get()
                };
                if matches!(publication, VpbPublication::LockedDismount(_)) {
                    Self::withdraw_locked(vpb, publication);
                }
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Makes the durable endpoint writable by its retained raw owner and admits remount only without a lock.
    #[expect(
        unsafe_code,
        reason = "the actor's one-way durable dismount publishes replacement ownership under the VPB lock"
    )]
    fn publish_dismount(&self) {
        VpbSpinLock::with_mounted(self.device, |vpb| {
            let publication = unsafe {
                // SAFETY: The global lock excludes every access to this interior publication state.
                &mut *self.publication.get()
            };
            let VpbPublication::Mounted(replacement) =
                core::mem::replace(publication, VpbPublication::Withdrawn)
            else {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
            };
            vpb.Flags |= vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED);
            if vpb.Flags & vpb_flag(wdk_sys::VPB_LOCKED) != 0 {
                *publication = VpbPublication::LockedDismount(replacement);
            } else {
                *publication = VpbPublication::Mounted(replacement);
                Self::withdraw_locked(vpb, publication);
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Transfers a successor to the real device without altering any old FILE_OBJECT association.
    /// The caller holds the global lock and owns the original mount reference.
    #[expect(
        unsafe_code,
        reason = "the global lock encloses native association replacement and sole allocation-ownership transfer"
    )]
    fn withdraw_locked(vpb: &mut wdk_sys::VPB, publication: &mut VpbPublication) {
        let replacement = match core::mem::replace(publication, VpbPublication::Withdrawn) {
            VpbPublication::Mounted(replacement) | VpbPublication::LockedDismount(replacement) => {
                replacement
            }
            VpbPublication::Withdrawn => return,
        };
        let current = unsafe {
            // SAFETY: The mounted storage route retains RealDevice and its current VPB uses this lock.
            (*vpb.RealDevice).Vpb
        };
        if current == core::ptr::from_mut(vpb) {
            let successor = replacement.into_raw();
            unsafe {
                // SAFETY: The unpublished successor is uniquely owned and initialized; fields are
                // populated before the I/O Manager observes the new current association.
                (*successor.as_ptr()).RealDevice = vpb.RealDevice;
            }
            unsafe {
                // SAFETY: The successor receives only device-wide policy, including removal exclusion.
                (*successor.as_ptr()).Flags = vpb.Flags
                    & !vpb_flag(
                        wdk_sys::VPB_MOUNTED
                            | wdk_sys::VPB_LOCKED
                            | wdk_sys::VPB_DIRECT_WRITES_ALLOWED,
                    );
            }
            unsafe {
                // SAFETY: This atomic lock-protected publication transfers destruction to the I/O Manager.
                (*vpb.RealDevice).Vpb = successor.as_ptr();
            }
        }
        vpb.Flags &= !vpb_flag(wdk_sys::VPB_MOUNTED);
    }

    /// Closes future routing after actor/dispatch join and retains only native references already in flight.
    fn begin_retirement(self) -> RetiringVpb {
        let mut publication = self.publication.into_inner();
        VpbSpinLock::with_mounted(self.device, |vpb| {
            Self::withdraw_locked(vpb, &mut publication);
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        RetiringVpb {
            device: self.device,
        }
    }
}

/// Sole finalization authority while old I/O Manager references drain against a closed dispatch gate.
#[derive(Debug)]
struct RetiringVpb {
    /// The retirement worker retains this device until the original VPB can be freed.
    device: KernelDevice,
}

impl RetiringVpb {
    /// Releases the mount reference only when it is the last native reference.
    /// # Errors
    /// Returns the reusable owner while native references remain. No association or reference is
    /// consumed in that case; successful completion transfers sole native deallocation authority.
    fn try_finish(self) -> Result<PoolVpb, Self> {
        let released = VpbSpinLock::with_mounted(self.device, |vpb| {
            if vpb.ReferenceCount != 1 {
                if vpb.ReferenceCount == 0 {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
                }
                return None;
            }
            vpb.ReferenceCount = 0;
            vpb.Flags &= !vpb_flag(wdk_sys::VPB_MOUNTED | wdk_sys::VPB_LOCKED | wdk_sys::VPB_DIRECT_WRITES_ALLOWED);
            vpb.DeviceObject = core::ptr::null_mut();
            #[expect(
                unsafe_code,
                reason = "the last reference and joined device lifetime authorize native association release"
            )]
            unsafe {
                // SAFETY: No FILE_OBJECT or in-flight native create retains this original VPB.
                (*self.device.as_ptr()).Vpb = core::ptr::null_mut();
            }
            Some(PoolVpb { allocation: NonNull::from(vpb) })
        }).unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        released.ok_or(self)
    }
}

/// Normalizes the WDK flag representation once at the native boundary.
fn vpb_flag(flag: u32) -> u16 {
    u16::try_from(flag)
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck())
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
    /// Returns native fixture allocation/publication or finalization failure.
    /// # Panics
    /// Fails if success without acknowledgment, a new verify gate or a stale VPB permits resubmission.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible native fixture setup surrounds exact identity and flag assertions"
    )]
    fn media_verification_requires_same_association_and_explicit_acknowledgment() -> DriverResult<()>
    {
        let mut fixture = VpbFixture::new()?;
        fixture.real.Flags = wdk_sys::DO_VERIFY_VOLUME | 0x4000;
        let publication = fixture.publish()?;
        assert_eq!(fixture.real.Flags, 0x4000);
        let device = fixture.device()?;
        fixture.real.Flags |= wdk_sys::DO_VERIFY_VOLUME;
        let (association, query) = MountedVolumeDevice::prepare_storage_verification(device)?;
        assert_eq!(query.execute(), Ok(()));
        assert_eq!(association.confirmed(), Err(DriverError::VerifyRequired));
        assert_ne!(fixture.real.Flags & wdk_sys::DO_VERIFY_VOLUME, 0);
        let (association, query) = MountedVolumeDevice::prepare_storage_verification(device)?;
        drop(query);
        association.acknowledge()?;
        assert_eq!(fixture.real.Flags, 0x4000);
        let (association, query) = MountedVolumeDevice::prepare_storage_verification(device)?;
        drop(query);
        assert_eq!(association.confirmed(), Ok(()));
        let (stale, query) = MountedVolumeDevice::prepare_storage_verification(device)?;
        drop(query);
        publication.publish_dismount();
        fixture.real.Flags |= wdk_sys::DO_VERIFY_VOLUME;
        assert_eq!(stale.confirmed(), Err(DriverError::WrongVolume));
        assert_eq!(fixture.real.Flags, wdk_sys::DO_VERIFY_VOLUME | 0x4000);
        drop(
            publication
                .begin_retirement()
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// Host I/O Manager allocation and device identities retained through native retirement.
    struct VpbFixture {
        /// Owns the current VPB association in the host oracle.
        real: Box<wdk_sys::DEVICE_OBJECT>,
        /// Device whose original VPB must outlive all retained native references.
        mounted: Box<wdk_sys::DEVICE_OBJECT>,
        /// Unpublished original allocation; publication transfers it to the native fixture protocol.
        original: Option<PoolVpb>,
    }

    impl VpbFixture {
        /// # Errors
        /// Returns device or VPB allocation failure before native publication.
        #[expect(
            unsafe_code,
            reason = "exclusive fixture construction initializes native associations before publication"
        )]
        fn new() -> DriverResult<Self> {
            let mut real = memory::boxed_try_with(|| Ok(wdk_sys::DEVICE_OBJECT::default()))?;
            let mounted = memory::boxed_try_with(|| Ok(wdk_sys::DEVICE_OBJECT::default()))?;
            let original = PoolVpb::try_new()?;
            real.Vpb = original.allocation.as_ptr();
            unsafe {
                // SAFETY: This unpublished original allocation is exclusively owned by the fixture.
                (*original.allocation.as_ptr()).RealDevice = core::ptr::from_mut(real.as_mut());
            }
            Ok(Self {
                real,
                mounted,
                original: Some(original),
            })
        }

        /// # Errors
        /// Returns malformed fixture identity rather than constructing an invalid native device.
        #[expect(
            unsafe_code,
            reason = "the fixture retains its heap-stable mounted device through every native transition"
        )]
        fn device(&self) -> DriverResult<KernelDevice> {
            unsafe {
                // SAFETY: The fixture owns this initialized device at a stable heap address.
                KernelDevice::from_raw(core::ptr::from_ref(self.mounted.as_ref()).cast_mut())
            }
            .ok_or(DriverError::InvalidParameter)
        }

        /// # Errors
        /// Returns fixture identity, successor allocation or mount admission failure.
        #[expect(
            unsafe_code,
            reason = "the fixture retains supplied native identities until reference finalization"
        )]
        fn publish(&mut self) -> DriverResult<MountedVpb> {
            let supplied = self
                .original
                .as_ref()
                .ok_or(DriverError::InvalidParameter)?
                .allocation;
            let supplied = unsafe {
                // SAFETY: Fixture ownership retains this supplied VPB through publication.
                KernelVpb::from_raw(supplied.as_ptr())
            }
            .ok_or(DriverError::InvalidParameter)?;
            let publication = MountedVpb::publish(
                supplied,
                self.device()?,
                0x1234_5678,
                VpbLabel::encode(Ext4VolumeLabel::new(b"AB")?)?,
                PoolVpb::try_new()?,
            )?;
            let original = self
                .original
                .take()
                .ok_or(DriverError::InternalInvariantViolation)?;
            let _native_allocation = original.into_raw();
            Ok(publication)
        }

        /// Encloses synthetic I/O Manager reference and field updates under the native lock.
        /// # Errors
        /// Returns a retired original identity instead of dereferencing freed storage.
        #[expect(
            unsafe_code,
            reason = "the original allocation or mounted reference retains this fixture VPB under the lock"
        )]
        fn original<R>(&self, work: impl FnOnce(&mut wdk_sys::VPB) -> R) -> DriverResult<R> {
            let _lock = VpbSpinLock::acquire();
            let pointer = self
                .original
                .as_ref()
                .map_or(self.mounted.Vpb, |owner| owner.allocation.as_ptr());
            let mut pointer = NonNull::new(pointer).ok_or(DriverError::InvalidParameter)?;
            let vpb = unsafe {
                // SAFETY: Unpublished fixture allocation or mount reference retains this pointer.
                pointer.as_mut()
            };
            Ok(work(vpb))
        }

        /// Consumes the host I/O Manager's unmounted successor allocation after finalization.
        /// # Errors
        /// Returns outstanding mounted/native ownership instead of freeing referenced storage.
        #[expect(
            unsafe_code,
            reason = "the completed fixture uniquely consumes its unmounted current pool allocation"
        )]
        fn finish(self) -> DriverResult<()> {
            if self.original.is_some() {
                return Ok(());
            }
            let current = {
                let _lock = VpbSpinLock::acquire();
                let pointer = NonNull::new(self.real.Vpb).ok_or(DriverError::InvalidParameter)?;
                let vpb = unsafe {
                    // SAFETY: The host real device retains the successor until this explicit release.
                    pointer.as_ref()
                };
                if vpb.ReferenceCount != 0 || !vpb.DeviceObject.is_null() {
                    return Err(DriverError::DeviceBusy);
                }
                PoolVpb {
                    allocation: pointer,
                }
            };
            drop(current);
            Ok(())
        }
    }

    /// Decodes one retained create request before associating its unpublished file object.
    /// # Errors
    /// Returns create-view or mounted-VPB admission failure.
    #[expect(
        unsafe_code,
        reason = "the synchronous fixture retains the device, IRP, stack and FILE_OBJECT throughout decoding"
    )]
    fn associate_create(device: KernelDevice, file: &mut wdk_sys::FILE_OBJECT) -> DriverResult<()> {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::from_mut(file),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut irp = wdk_sys::IRP::default();
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::from_mut(&mut stack);
        let mut request = unsafe {
            // SAFETY: The fixture retains all native allocations until the active view returns.
            crate::irp::ReceivedIrp::decode(device.as_ptr(), core::ptr::from_mut(&mut irp))
        }?;
        request.with_active(|active| {
            let file = active.current_stack()?.file_object()?;
            let mut file = UninitializedFileObject::decode(file)?;
            MountedVolumeDevice::bind_create_vpb(device, &mut file)
        })
    }

    /// # Errors
    /// Returns native fixture construction, create admission or retirement failure.
    /// # Panics
    /// Fails if file objects lose their mounted identity or association changes reference ownership.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible native setup and retirement surround FILE_OBJECT identity assertions"
    )]
    fn create_association_retains_original_vpb_without_duplicating_routing_references()
    -> DriverResult<()> {
        let mut fixture = VpbFixture::new()?;
        fixture.original(|vpb| vpb.ReferenceCount = 2)?;
        let original = fixture.real.Vpb;
        let publication = fixture.publish()?;
        let device = fixture.device()?;
        let mut first = wdk_sys::FILE_OBJECT::default();
        let mut second = wdk_sys::FILE_OBJECT::default();
        associate_create(device, &mut first)?;
        associate_create(device, &mut second)?;
        associate_create(device, &mut first)?;
        assert_eq!(first.Vpb, original);
        assert_eq!(second.Vpb, original);
        fixture.original(|vpb| assert_eq!(vpb.ReferenceCount, 3))?;

        let mut foreign = wdk_sys::VPB::default();
        let mut mismatched = wdk_sys::FILE_OBJECT {
            Vpb: core::ptr::from_mut(&mut foreign),
            ..wdk_sys::FILE_OBJECT::default()
        };
        assert_eq!(
            associate_create(device, &mut mismatched),
            Err(DriverError::NotSameDevice)
        );
        assert_eq!(mismatched.Vpb, core::ptr::from_mut(&mut foreign));

        publication.publish_dismount();
        assert_ne!(fixture.real.Vpb, original);
        assert_eq!(first.Vpb, original);
        assert_eq!(second.Vpb, original);
        fixture.original(|vpb| {
            assert_eq!(vpb.ReferenceCount, 3);
            vpb.ReferenceCount -= 2;
        })?;
        drop(
            publication
                .begin_retirement()
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns allocation, label or native retirement failure.
    /// # Panics
    /// Fails if old native references block a fresh mount or retirement mutates the successor.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible native setup and finalization surround remount/rundown assertions"
    )]
    #[expect(
        unsafe_code,
        reason = "both host device allocations remain live until their distinct VPB owners finish"
    )]
    fn dismount_admits_fresh_mount_before_old_native_references_close() -> DriverResult<()> {
        let mut fixture = VpbFixture::new()?;
        fixture.original(|vpb| {
            vpb.ReferenceCount = 2;
            vpb.Flags = vpb_flag(wdk_sys::VPB_PERSISTENT);
        })?;
        let original = fixture.real.Vpb;
        let publication = fixture.publish()?;
        let original_device = fixture.device()?;
        fixture.original(|vpb| {
            vpb.Flags |= vpb_flag(wdk_sys::VPB_MOUNTED);
            assert_eq!(vpb.ReferenceCount, 3);
        })?;
        let label = MountedVolumeDevice::prepare_vpb_label_publication(
            original_device,
            Ext4VolumeLabel::new(b"Z")?,
        )?;
        label.publish();
        publication.publish_dismount();
        assert_ne!(fixture.real.Vpb, original);
        fixture.original(|vpb| {
            assert_eq!(vpb.DeviceObject, original_device.as_ptr());
            assert_eq!(vpb.VolumeLabelLength, 2);
            assert_eq!(vpb.VolumeLabel.first(), Some(&90));
            assert_eq!(vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
            assert_eq!(vpb.ReferenceCount, 3);
        })?;

        let mut fresh = memory::boxed_try_with(|| Ok(wdk_sys::DEVICE_OBJECT::default()))?;
        let fresh_device = unsafe {
            // SAFETY: This second mounted-device allocation remains live through its own retirement.
            KernelDevice::from_raw(core::ptr::from_mut(fresh.as_mut()))
        }
        .ok_or(DriverError::InvalidParameter)?;
        let supplied = unsafe {
            // SAFETY: The fixture's real device retains the newly published current VPB.
            KernelVpb::from_raw(fixture.real.Vpb)
        }
        .ok_or(DriverError::InvalidParameter)?;
        let fresh_mount = MountedVpb::publish(
            supplied,
            fresh_device,
            73,
            VpbLabel::encode(Ext4VolumeLabel::new(b"fresh")?)?,
            PoolVpb::try_new()?,
        )?;
        let successor = fixture.real.Vpb;
        let retirement = publication
            .begin_retirement()
            .try_finish()
            .err()
            .ok_or(DriverError::InternalInvariantViolation)?;
        fixture.original(|vpb| vpb.ReferenceCount -= 2)?;
        let released = retirement
            .try_finish()
            .map_err(|_| DriverError::DeviceBusy)?;
        drop(released);
        assert!(fixture.mounted.Vpb.is_null());
        assert_eq!(fixture.real.Vpb, successor);
        VpbSpinLock::with_mounted(fresh_device, |vpb| {
            assert_eq!(vpb.SerialNumber, 73);
            assert_eq!(vpb.VolumeLabelLength, 10);
            assert_eq!(vpb.ReferenceCount, 1);
        })?;
        drop(
            fresh_mount
                .begin_retirement()
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns native fixture setup or finalization failure.
    /// # Panics
    /// Fails if dismount loses raw-lock exclusion or unlock fails to admit a successor mount.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup and retirement surround lock/remount assertions"
    )]
    fn dismounted_raw_lock_retains_routing_until_owner_unlocks() -> DriverResult<()> {
        let mut fixture = VpbFixture::new()?;
        let publication = fixture.publish()?;
        let original = fixture.real.Vpb;
        publication.publish_lock(true);
        publication.publish_dismount();
        assert_eq!(fixture.real.Vpb, original);
        fixture.original(|vpb| {
            assert_ne!(vpb.Flags & vpb_flag(wdk_sys::VPB_LOCKED), 0);
            assert_ne!(vpb.Flags & vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED), 0);
        })?;
        publication.publish_lock(false);
        assert_ne!(fixture.real.Vpb, original);
        fixture.original(|vpb| assert_eq!(vpb.Flags & vpb_flag(wdk_sys::VPB_LOCKED), 0))?;
        drop(
            publication
                .begin_retirement()
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns native fixture setup or finalization failure.
    /// # Panics
    /// Fails if publication modifies a rejected VPB or retirement erases lower-device removal policy.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "native failure-boundary assertions follow fallible fixture construction"
    )]
    #[expect(
        unsafe_code,
        reason = "the fixture retains the successor allocation while inspecting native device-wide policy"
    )]
    fn mount_rejection_is_atomic_and_retirement_preserves_removal() -> DriverResult<()> {
        let mut fixture = VpbFixture::new()?;
        for (flags, references, error) in [
            (
                vpb_flag(wdk_sys::VPB_REMOVE_PENDING),
                0,
                DriverError::DeviceRemoved,
            ),
            (0, u32::MAX, DriverError::InsufficientResources),
        ] {
            fixture.original(|vpb| {
                vpb.Flags = flags;
                vpb.ReferenceCount = references;
                vpb.SerialNumber = 17;
                vpb.VolumeLabelLength = 6;
                vpb.VolumeLabel = [42; 32];
            })?;
            assert!(matches!(fixture.publish(), Err(observed) if observed == error));
            assert!(fixture.mounted.Vpb.is_null());
            fixture.original(|vpb| {
                assert_eq!(vpb.ReferenceCount, references);
                assert_eq!(vpb.Flags, flags);
                assert_eq!(vpb.SerialNumber, 17);
                assert_eq!(vpb.VolumeLabel, [42; 32]);
                assert!(vpb.DeviceObject.is_null());
            })?;
        }
        let real = core::ptr::from_mut(fixture.real.as_mut());
        let mounted = fixture.device()?.as_ptr();
        for (real_device, occupied, current_matches, error) in [
            (
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                true,
                DriverError::InvalidParameter,
            ),
            (real, mounted, true, DriverError::DeviceBusy),
            (
                real,
                core::ptr::null_mut(),
                false,
                DriverError::InvalidParameter,
            ),
        ] {
            fixture.original(|vpb| {
                vpb.Flags = 0;
                vpb.ReferenceCount = 0;
                vpb.RealDevice = real_device;
                vpb.DeviceObject = occupied;
            })?;
            let current = fixture.real.Vpb;
            if !current_matches {
                fixture.real.Vpb = core::ptr::null_mut();
            }
            assert!(matches!(fixture.publish(), Err(observed) if observed == error));
            assert!(fixture.mounted.Vpb.is_null());
            fixture.original(|vpb| {
                assert_eq!(vpb.ReferenceCount, 0);
                assert_eq!(vpb.RealDevice, real_device);
                assert_eq!(vpb.DeviceObject, occupied);
            })?;
            fixture.real.Vpb = current;
        }
        fixture.original(|vpb| {
            vpb.Flags = 0;
            vpb.ReferenceCount = 0;
            vpb.DeviceObject = core::ptr::null_mut();
            vpb.RealDevice = real;
        })?;
        let publication = fixture.publish()?;
        fixture.original(|vpb| {
            vpb.Flags |= vpb_flag(wdk_sys::VPB_REMOVE_PENDING | wdk_sys::VPB_RAW_MOUNT)
        })?;
        let retirement = publication.begin_retirement();
        {
            let _lock = VpbSpinLock::acquire();
            let successor = unsafe {
                // SAFETY: The fixture owns the real device and its published successor under the lock.
                &*fixture.real.Vpb
            };
            assert_eq!(
                successor.Flags,
                vpb_flag(wdk_sys::VPB_REMOVE_PENDING | wdk_sys::VPB_RAW_MOUNT)
            );
            assert!(successor.DeviceObject.is_null());
        }
        drop(
            retirement
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }
}
