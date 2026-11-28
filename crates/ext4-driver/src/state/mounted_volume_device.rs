//! Mounted-volume device construction, VPB publication, and device retirement.

use super::*;
#[cfg(not(test))]
use crate::kernel::operational_trace::{OperationalOutcome, OperationalPath};
use crate::kernel::volume_verify::{VerificationDevice, observe_current_vpb};
use crate::{kernel::stream::MediaReplacement, volume_label::WindowsVolumeLabel};

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
struct MountedVolumeDeviceExtension {
    /// Common driver-owned device extension header.
    header: DeviceExtensionHeader,
    /// Mount-preallocated work item that performs actor-safe physical retirement.
    retirement_work_item: wdk_sys::PIO_WORKITEM,
    /// Re-queues retirement while native VPB references drain, without holding a system worker.
    #[cfg(not(test))]
    retirement_timer: UnsafeCell<wdk_sys::KTIMER>,
    /// Timer DPC whose only effect is queueing the retirement work item.
    #[cfg(not(test))]
    retirement_dpc: UnsafeCell<wdk_sys::KDPC>,
    /// Retirement transfers this slot exclusively through thread and work-item publication.
    #[cfg(not(test))]
    pending_retirement: UnsafeCell<Option<RetirementWork>>,
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

/// Owns an IoCreateDevice allocation until the mount publishes its VPB and dispatch.
struct UnpublishedMountedDevice {
    /// Stable device address supplied by the I/O Manager.
    device: KernelDevice,
    /// Initialized only after the actor has started at its final address.
    reactor: Option<NonNull<DeviceExtensionHeader>>,
    /// The live registration flag, initialized before shutdown IRPs can arrive.
    shutdown: Option<NonNull<AtomicU8>>,
    /// Unqueued work item, released here until retirement owns it.
    #[cfg(not(test))]
    work_item: Option<NonNull<wdk_sys::_IO_WORKITEM>>,
}

impl UnpublishedMountedDevice {
    /// # Errors
    /// Returns native device allocation or extension-size failure.
    #[expect(
        unsafe_code,
        reason = "mount exclusively owns the new device allocation"
    )]
    fn create(driver: PDRIVER_OBJECT) -> DriverResult<Self> {
        let extension_size =
            wdk_sys::ULONG::try_from(core::mem::size_of::<MountedVolumeDeviceExtension>())
                .map_err(|_| DriverError::InvalidParameter)?;
        let mut device = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: DriverEntry and the mount IRP retain the driver; the output slot is writable.
            ffi::IoCreateDevice(
                driver,
                extension_size,
                core::ptr::null_mut(),
                ffi::FILE_DEVICE_DISK_FILE_SYSTEM,
                0,
                0,
                core::ptr::addr_of_mut!(device),
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::InsufficientResources);
        }
        let device = unsafe {
            // SAFETY: Success grants the mount exclusive ownership of the new device.
            KernelDevice::from_raw(device)
        }
        .ok_or(DriverError::InternalInvariantViolation)?;
        Ok(Self {
            device,
            reactor: None,
            shutdown: None,
            #[cfg(not(test))]
            work_item: None,
        })
    }

    /// Transfers the initialized extension and its resources to dispatch and native retirement.
    #[expect(
        unsafe_code,
        reason = "only the mount can publish initialization of this device"
    )]
    fn publish(
        self,
        publication_slot: NonNull<UnsafeCell<MaybeUninit<MountedVpb>>>,
        publication: MountedVpb,
    ) -> KernelDevice {
        let destination = unsafe {
            // SAFETY: Initialization wrote this disjoint field; publication owns its first value.
            publication_slot.as_ref().get()
        };
        unsafe {
            // SAFETY: This slot uniquely receives the mounted VPB reference.
            destination.write(MaybeUninit::new(publication));
        }
        let device = self.device;
        core::mem::forget(self);
        unsafe {
            // SAFETY: All extension state and VPB routing are ready before dispatch is enabled.
            (*device.as_ptr()).Flags &= !DO_DEVICE_INITIALIZING;
        }
        device
    }
}

impl Drop for UnpublishedMountedDevice {
    #[expect(
        unsafe_code,
        reason = "mount rollback releases only the resources acquired by this owner"
    )]
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let registered = unsafe {
                // SAFETY: The flag was initialized before registration and lives until deletion.
                shutdown.as_ref()
            };
            consume_shutdown_registration(self.device, registered);
        }
        if let Some(header) = self.reactor.take() {
            let header = unsafe {
                // SAFETY: The owner records this address only after successful initialization.
                header.as_ref()
            };
            let target = unsafe {
                // SAFETY: Dispatch is still unpublished and shutdown has been unregistered.
                // Retirement joins any already admitted work before releasing the binding.
                header.retire()
            };
            drop(target);
        }
        #[cfg(not(test))]
        if let Some(work_item) = self.work_item.take() {
            unsafe {
                // SAFETY: Unpublished retirement work was never queued or armed.
                ffi::IoFreeWorkItem(work_item.as_ptr());
            }
        }
        unsafe {
            // SAFETY: The unpublished device no longer owns reactor or native work.
            ffi::IoDeleteDevice(self.device.as_ptr());
        }
    }
}

/// Prevalidated VPB label update consumed only after journal commit visibility.
#[derive(Debug)]
pub(crate) struct PreparedVpbLabelPublication {
    /// Mounted association retained by the operation until reactor drain.
    device: KernelDevice,
    /// Windows projection of the label committed by ext4.
    label: WindowsVolumeLabel,
}

impl PreparedVpbLabelPublication {
    /// Publishes under the VPB lock after ext4 commit; retirement cannot race the owning operation.
    pub(crate) fn publish(self) {
        VpbSpinLock::with_mounted(self.device, |vpb| write_vpb_label(vpb, &self.label))
            .unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
    }
}

/// Exact mounted association retained by the actor's active request while verification suspends.
#[derive(Debug)]
pub(crate) struct MediaVerificationAssociation {
    /// Mounted filesystem device whose reactor owns this operation.
    device: KernelDevice,
    /// Original VPB retained by mounted-device rundown through the request continuation.
    vpb: KernelVpb,
    /// Real device whose verify flag may be acknowledged after a matching physical read.
    real_device: KernelDevice,
}

impl MediaVerificationAssociation {
    /// Consumes same-association evidence after I/O Manager verification, without clearing flags.
    /// # Errors
    /// Returns this mount's own routing withdrawal as dismounted, a foreign or removing
    /// association, or a new verification requirement; no retry is granted.
    pub(crate) fn confirmed(self) -> DriverResult<()> {
        MountedVolumeDevice::with_vpb(self.device, |publication| publication.confirm(&self))
    }

    /// Consumes acknowledgment authority only after revalidating the original mounted association.
    /// # Errors
    /// Returns changed association or removal without clearing any verify flag.
    pub(crate) fn acknowledge(self) -> DriverResult<()> {
        MountedVolumeDevice::with_vpb(self.device, |publication| {
            publication.finish_verification(&self, None)
        })
    }

    /// Revokes the verified volume and acknowledges the physical verify flag before WRONG_VOLUME.
    /// # Errors
    /// Returns a stale association or removal without changing storage admission or native flags.
    pub(crate) fn publish_replacement(self, replacement: MediaReplacement<'_>) -> DriverResult<()> {
        MountedVolumeDevice::with_vpb(self.device, |publication| {
            publication.finish_verification(&self, Some(replacement))
        })
    }
}

impl MountedVolumeDevice {
    /// Captures the exact mounted association and separately retained real device for a lower gate.
    /// # Errors
    /// Returns withdrawn routing as dismounted, or a foreign/removing association, before any
    /// native worker is queued.
    pub(crate) fn prepare_storage_verification(
        device: KernelDevice,
    ) -> DriverResult<(
        MediaVerificationAssociation,
        crate::kernel::volume_verify::VerificationDevice,
    )> {
        Self::with_vpb(device, MountedVpb::prepare_storage_verification)
    }
    /// Retains a required I/O Manager verify before ordinary work can inspect a mounted cache.
    /// Mount notifications can reenter after association publication but before the I/O Manager
    /// acknowledges completion with VPB_MOUNTED. Identity comes from the current association;
    /// the actor independently owns filesystem-operation admission.
    ///
    /// After this mount withdrew its routing, the device's verify flag belongs to the successor;
    /// no verification is selected and ordinary admission reports the ended session.
    /// # Errors
    /// Returns a foreign association, removal, or busy when verification requires the mount IRP
    /// to finish first. No native I/O runs under the VPB lock.
    pub(crate) fn prepare_verify_work(
        device: KernelDevice,
    ) -> DriverResult<Option<crate::kernel::volume_verify::VerificationDevice>> {
        Self::with_vpb(device, MountedVpb::prepare_verify_work)
    }
    /// Validates a captured kernel verify tuple before any raw I/O or mounted-state change.
    /// No VPB borrow, lock or actor reference survives the returned scalar association.
    /// # Errors
    /// Returns a foreign, withdrawn, removing or incomplete mounted association.
    pub(crate) fn prepare_media_verification(
        target: crate::irp::VerifyVolumeTarget,
    ) -> DriverResult<MediaVerificationAssociation> {
        Self::with_vpb(target.device, |publication| {
            publication.prepare_media_verification(target.vpb)
        })
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

    /// Creates the device, initializes its native resources, and publishes a recovered volume.
    /// # Errors
    /// Fails before dispatch publication on invalid geometry, resource failure or a rejected VPB.
    #[expect(
        unsafe_code,
        reason = "this mount initializes disjoint native fields before publishing the owned device"
    )]
    pub(crate) fn publish_mount(
        driver: PDRIVER_OBJECT,
        binding: MountedVolumeBinding,
        vpb: KernelVpb,
        target_device: KernelDevice,
    ) -> DriverResult<KernelDevice> {
        let mut unpublished = UnpublishedMountedDevice::create(driver)?;
        let device = unpublished.device;
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
        let volume_label = WindowsVolumeLabel::from_ext4(identity.label())?;
        let replacement_vpb = PoolVpb::reserve(device)?;
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
            binding.volume().stream_context.storage_access()
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
            binding.volume().stream_context.storage_removal_publisher()
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
        unpublished.reactor = NonNull::new(header_slot);
        register_shutdown_notification(device)?;
        let shutdown_registered = unsafe {
            // SAFETY: Registration ownership uses this initialized atomic at its final address.
            &*shutdown_slot
        };
        shutdown_registered.store(1, Ordering::Release);
        unpublished.shutdown = NonNull::new(shutdown_slot);
        #[cfg(not(test))]
        let retirement_work_item = unsafe {
            // SAFETY: The new mounted device remains live and unpublished during allocation.
            ffi::IoAllocateWorkItem(device.as_ptr())
        };
        #[cfg(test)]
        let retirement_work_item = NonNull::<wdk_sys::_IO_WORKITEM>::dangling().as_ptr();
        let retirement_work_item =
            NonNull::new(retirement_work_item).ok_or(DriverError::InsufficientResources)?;
        #[cfg(not(test))]
        {
            unpublished.work_item = Some(retirement_work_item);
        }
        unsafe {
            // SAFETY: The device remains unpublished and the work item cannot yet be queued.
            retirement_slot.write(retirement_work_item.as_ptr());
        }
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The unpublished allocation contains these disjoint retirement fields; the
            // timer and DPC are initialized at their final nonpaged addresses before any arming.
            Self::initialize_retirement_retry(extension_pointer, retirement_work_item.as_ptr());
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

        if publication_reliability.policy()
            == crate::kernel::io_reliability::NativeIoPolicy::Unavailable
        {
            return Err(DriverError::Core(ext4_core::Error::MmpOwnershipLost));
        }
        let publication_slot =
            NonNull::new(publication_slot).ok_or(DriverError::InternalInvariantViolation)?;
        let publication =
            MountedVpb::publish(vpb, device, serial_number, volume_label, replacement_vpb)?;
        Ok(unpublished.publish(publication_slot, publication))
    }

    /// Initializes the retirement retry timer whose DPC re-queues the retirement work item.
    /// # Safety
    /// `extension` must be the unpublished mounted extension at its final nonpaged address, and
    /// `work_item` its preallocated, unqueued retirement work item.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "unpublished extension storage receives its native timer, DPC and empty retry slot"
    )]
    unsafe fn initialize_retirement_retry(
        extension: NonNull<MountedVolumeDeviceExtension>,
        work_item: wdk_sys::PIO_WORKITEM,
    ) {
        let extension = extension.as_ptr();
        let pending = unsafe {
            // SAFETY: The caller supplies the live unpublished extension allocation.
            core::ptr::addr_of_mut!((*extension).pending_retirement)
        };
        let timer = unsafe {
            // SAFETY: The same allocation contains this disjoint timer field.
            core::ptr::addr_of_mut!((*extension).retirement_timer)
        };
        let dpc = unsafe {
            // SAFETY: The same allocation contains this disjoint DPC field.
            core::ptr::addr_of_mut!((*extension).retirement_dpc)
        };
        unsafe {
            // SAFETY: The caller owns this uninitialized field before publication.
            pending.write(UnsafeCell::new(Some(RetirementWork::Start(
                RetirementRetryDelay::FIRST,
            ))));
        }
        unsafe {
            // SAFETY: The caller owns this uninitialized field before publication.
            timer.write(UnsafeCell::new(wdk_sys::KTIMER::default()));
        }
        unsafe {
            // SAFETY: The caller owns this uninitialized field before publication.
            dpc.write(UnsafeCell::new(wdk_sys::KDPC::default()));
        }
        unsafe {
            // SAFETY: The timer is at its final nonpaged address and has never been armed.
            ffi::KeInitializeTimer(UnsafeCell::raw_get(timer));
        }
        unsafe {
            // SAFETY: The DPC is at its final nonpaged address; its context is the work item,
            // which the device extension retains until device deletion.
            ffi::KeInitializeDpc(
                UnsafeCell::raw_get(dpc),
                Some(mounted_volume_retirement_dpc),
                work_item.cast::<c_void>(),
            );
        }
    }

    /// Starts retirement or polls its detached VPB after the blocking handoff finishes.
    /// # Safety
    /// The queued work item must retain this device and exclusively own the published stage.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the sole retirement work item owns the parked teardown and the native retry timer"
    )]
    unsafe fn advance_release(device: KernelDevice) -> RetirementStep {
        let extension = device.extension_address();
        let extension = unsafe {
            // SAFETY: The common extension kind was decoded as mounted before this call.
            extension.cast::<MountedVolumeDeviceExtension>().as_ref()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let work = unsafe {
            // SAFETY: Queue publication transferred this sole stage to the callback.
            (&mut *extension.pending_retirement.get()).take()
        }
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        let pending = match work {
            RetirementWork::Start(retry) => {
                let started = unsafe {
                    // SAFETY: The work item pins the device until the newly created thread takes
                    // its own reference. Starting it transfers exclusive first-stage ownership.
                    crate::kernel::volume_verify::start_verification_thread(
                        device,
                        Some(begin_volume_retirement),
                        device.as_ptr().cast(),
                    )
                };
                if started.is_err() {
                    Self::retry_retirement(extension, RetirementWork::Start(retry.next()), retry);
                }
                return RetirementStep::Retained;
            }
            RetirementWork::Finish(pending) => pending,
        };
        let PendingRetirement {
            vpb,
            binding,
            reported,
            retry,
        } = pending;
        let trace = binding.volume().trace;
        match vpb.try_finish() {
            Ok(released) => {
                drop(released);
                trace.record(
                    OperationalPath::VpbRetirement,
                    STATUS_SUCCESS,
                    OperationalOutcome::Completed,
                );
                drop(binding);
                trace.record(
                    OperationalPath::VolumeRetirement,
                    STATUS_SUCCESS,
                    OperationalOutcome::Completed,
                );
                RetirementStep::Released
            }
            Err((retained, references)) => {
                if reported != Some(references) {
                    trace.record_vpb_references(references);
                }
                if reported.is_none() {
                    trace.record_status(OperationalPath::VpbRetirement, wdk_sys::STATUS_PENDING);
                }
                let work = RetirementWork::Finish(PendingRetirement {
                    vpb: retained,
                    binding,
                    reported: Some(references),
                    retry: retry.next(),
                });
                Self::retry_retirement(extension, work, retry);
                RetirementStep::Retained
            }
        }
    }

    /// Parks the stage before the timer transfers it to the next work-item invocation.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the dequeued work item owns the stage and idle timer"
    )]
    fn retry_retirement(
        extension: &MountedVolumeDeviceExtension,
        work: RetirementWork,
        retry: RetirementRetryDelay,
    ) {
        unsafe {
            // SAFETY: The current work item consumed the previous stage; no successor is queued.
            *extension.pending_retirement.get() = Some(work);
        }
        let already_armed = unsafe {
            // SAFETY: The retained extension owns the idle timer and DPC through publication.
            // No subsequent code accesses the extension after the timer can queue its successor.
            ffi::KeSetTimer(
                extension.retirement_timer.get(),
                LARGE_INTEGER {
                    QuadPart: retry.relative_due_time(),
                },
                extension.retirement_dpc.get(),
            )
        };
        if already_armed != 0 {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
    }

    /// Joins the actor and closes future routing on the dedicated retirement thread.
    /// # Safety
    /// The caller must own the mounted device's unique first retirement stage.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "first retirement invocation joins the actor and consumes the VPB publication owner"
    )]
    unsafe fn begin_release(
        device: KernelDevice,
        extension: &MountedVolumeDeviceExtension,
    ) -> PendingRetirement {
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
        binding.volume().trace.record(
            OperationalPath::VpbRetirement,
            STATUS_SUCCESS,
            OperationalOutcome::Selected,
        );
        let vpb = unsafe {
            // SAFETY: Dispatch and reactor rundown completed above. IoVerifyVolume waits for
            // the preceding native verify on this real device before making its own observation.
            publication.begin_retirement(|verification| {
                // This call joins the prior I/O Manager verify. Its status describes its own
                // attempt. The locked association observation below owns the publication decision.
                let _verification_status = verification.execute();
            })
        };
        PendingRetirement {
            vpb,
            binding,
            reported: None,
            retry: RetirementRetryDelay::FIRST,
        }
    }

    /// Queues the preallocated work item that retires this device after its actor returns.
    pub(crate) fn schedule_retirement(device: KernelDevice) {
        let work_item = Self::retirement_work_item(device);
        #[cfg(not(test))]
        queue_retirement_work_item(work_item);
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
    /// Returns invalid parameter for a missing or foreign association.
    pub(crate) fn prepare_vpb_label_publication(
        device: KernelDevice,
        volume_label: ext4_core::Ext4VolumeLabel,
    ) -> DriverResult<PreparedVpbLabelPublication> {
        let label = WindowsVolumeLabel::from_ext4(volume_label)?;
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

    /// Publishes a volume lock or releases native exclusion after its owner lets go.
    /// # Errors
    ///
    /// Stops the system if the live mounted device has lost its VPB association.
    pub(crate) fn publish_volume_lock(device: KernelDevice, locked: bool) {
        Self::with_vpb(device, |publication| publication.publish_lock(locked));
    }

    /// Projects ended-session direct access or remount routing after journal sharing ends.
    pub(crate) fn publish_session_end(device: KernelDevice, routing: SessionEndRouting) {
        Self::with_vpb(device, |publication| {
            publication.publish_session_end(routing)
        });
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
        consume_shutdown_registration(device, &extension.shutdown_registered);
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

    /// Reports the exact dismount outcome without equating logical termination and clean durability.
    /// # Errors
    ///
    /// Stops the system if the mounted device has lost its VPB/real-device association.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) fn complete_dismount(device: KernelDevice, status: wdk_sys::NTSTATUS) {
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
            ffi::FsRtlDismountComplete(real_device.as_ptr(), status);
        }
        #[cfg(test)]
        let _native_arguments = (real_device, status);
    }
}

/// An I/O Manager VPB allocation that is privately reserved or detached from its real device.
#[derive(Debug)]
struct PoolVpb {
    /// Sole allocation/deallocation identity, with no retained Rust reference to its fields.
    allocation: NonNull<wdk_sys::VPB>,
}

impl PoolVpb {
    /// Reserves the I/O Manager's VPB from an unpublished disk device. A successor can remain
    /// current past filesystem unload, so its pool allocation must originate in the I/O Manager.
    /// # Errors
    /// Returns insufficient resources if the disk device cannot be created or a missing VPB
    /// if Windows did not initialize the disk device's association.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "an unnamed, unpublished disk device supplies the I/O Manager allocation"
    )]
    fn reserve(device: KernelDevice) -> DriverResult<Self> {
        let driver = device
            .driver_object()
            .ok_or(DriverError::InternalInvariantViolation)?;
        let mut donor = core::ptr::null_mut();
        let status = unsafe {
            // SAFETY: The mounted device retains this driver. The only output is the unpublished
            // sibling device, whose initialization bit is never cleared.
            ffi::IoCreateDevice(
                driver,
                0,
                core::ptr::null_mut(),
                wdk_sys::FILE_DEVICE_DISK,
                0,
                0,
                &raw mut donor,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::InsufficientResources);
        }
        let donor = NonNull::new(donor).ok_or(DriverError::InternalInvariantViolation)?;
        let allocation = {
            let _lock = VpbSpinLock::acquire();
            let association = unsafe {
                // SAFETY: This FSD owns the unpublished device. No mount or file can retain its
                // VPB, and the lock serializes native association changes.
                &mut (*donor.as_ptr()).Vpb
            };
            let allocation = NonNull::new(core::mem::replace(association, core::ptr::null_mut()));
            if let Some(allocation) = allocation {
                unsafe {
                    // SAFETY: The device no longer owns this private VPB. Publication will bind
                    // it to the actual storage device before exposing it.
                    (*allocation.as_ptr()).RealDevice = core::ptr::null_mut();
                }
            }
            allocation
        };
        unsafe {
            // SAFETY: The unpublished device has no filesystem association or owned resources.
            ffi::IoDeleteDevice(donor.as_ptr());
        }
        allocation
            .map(|allocation| Self { allocation })
            .ok_or(DriverError::InternalInvariantViolation)
    }

    /// Supplies the host oracle's equivalent of an unmounted I/O Manager VPB.
    /// # Errors
    /// Returns allocation or native layout conversion failure.
    #[cfg(test)]
    fn fixture() -> DriverResult<Self> {
        let value = wdk_sys::VPB {
            Type: wdk_sys::IO_TYPE_VPB
                .try_into()
                .map_err(|_| DriverError::InvalidParameter)?,
            Size: core::mem::size_of::<wdk_sys::VPB>()
                .try_into()
                .map_err(|_| DriverError::InvalidParameter)?,
            ..Default::default()
        };
        let allocation = NonNull::new(Box::into_raw(memory::boxed_try_with(|| Ok(value))?))
            .ok_or(DriverError::InternalInvariantViolation)?;
        Ok(Self { allocation })
    }

    /// Reserves the host oracle's successor without calling the live I/O Manager.
    /// # Errors
    /// Returns allocation or native layout conversion failure.
    #[cfg(test)]
    fn reserve(_device: KernelDevice) -> DriverResult<Self> {
        Self::fixture()
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
    /// The ended session retains direct-access or failed-lock exclusion until owner release.
    Excluded(PoolVpb),
    /// The native verify may install a successor. The reserve survives until that attempt ends.
    HandingOffToIoManager(PoolVpb),
    /// The I/O Manager owns a successor; this mount retains only its original VPB reference.
    Withdrawn,
}

/// Lock-observed routing of a mount's original VPB.
#[derive(Clone, Copy, Debug)]
enum VpbRouting {
    /// The real device's current VPB still routes new opens to this mount.
    Current(KernelDevice),
    /// This mount transferred new-open routing to a successor; its session has ended.
    Withdrawn,
    /// The current VPB changed without this mount's withdrawal.
    Foreign,
}

impl VpbRouting {
    /// Requires current routing for media verification.
    /// # Errors
    /// Returns dismounted for this mount's own withdrawal, or wrong volume for a foreign change.
    const fn current(self) -> DriverResult<KernelDevice> {
        match self {
            Self::Current(real_device) => Ok(real_device),
            Self::Withdrawn => Err(DriverError::VolumeDismounted),
            Self::Foreign => Err(DriverError::WrongVolume),
        }
    }
}

impl MediaVerificationAssociation {
    /// Requires the locked VPB to be the captured mounted identity.
    /// # Errors
    /// Returns wrong volume for another VPB, real device, or an unmounted VPB.
    fn matches(&self, vpb: &wdk_sys::VPB) -> DriverResult<()> {
        if core::ptr::from_ref(vpb).cast_mut() != self.vpb.as_non_null().as_ptr()
            || vpb.RealDevice != self.real_device.as_ptr()
            || vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0
        {
            return Err(DriverError::WrongVolume);
        }
        Ok(())
    }
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
        label: WindowsVolumeLabel,
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
            observe_current_vpb(real.as_ptr())
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
        write_vpb_label(vpb, &label);
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

    /// Clearing exclusion on an ended session publishes fresh remount routing.
    #[expect(
        unsafe_code,
        reason = "the global VPB lock serializes this interior state and the corresponding native flags"
    )]
    fn publish_lock(&self, locked: bool) {
        VpbSpinLock::with_mounted(self.device, |vpb| {
            if locked {
                vpb.Flags |= vpb_flag(wdk_sys::VPB_LOCKED);
            } else {
                vpb.Flags &= !vpb_flag(wdk_sys::VPB_LOCKED | wdk_sys::VPB_DIRECT_WRITES_ALLOWED);
                let publication = unsafe {
                    // SAFETY: with_mounted holds the global lock, the sole mutation authority.
                    &mut *self.publication.get()
                };
                if matches!(publication, VpbPublication::Excluded(_)) {
                    Self::withdraw_locked(vpb, publication);
                }
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// A direct-access owner or surviving lock retains routing until release.
    #[expect(
        unsafe_code,
        reason = "the actor projects ended-session routing under the VPB lock"
    )]
    fn publish_session_end(&self, routing: SessionEndRouting) {
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
            if routing == SessionEndRouting::DirectAccess {
                vpb.Flags |= vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED);
            } else {
                vpb.Flags &= !vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED);
            }
            *publication = VpbPublication::Excluded(replacement);
            if routing == SessionEndRouting::Remount {
                Self::withdraw_locked(vpb, publication);
            }
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    }

    /// Borrows the original VPB together with this mount's routing state under the global lock.
    /// # Errors
    /// Returns a missing association or real device, or the callback's failure.
    #[expect(
        unsafe_code,
        reason = "the global VPB lock serializes the publication state and the native association it projects"
    )]
    fn with_routing<R>(
        &self,
        work: impl FnOnce(&mut wdk_sys::VPB, VpbRouting, &mut VpbPublication) -> DriverResult<R>,
    ) -> DriverResult<R> {
        VpbSpinLock::with_mounted(self.device, |vpb| {
            let publication = unsafe {
                // SAFETY: with_mounted holds the global lock, the sole mutation authority.
                &mut *self.publication.get()
            };
            let withdrawn = matches!(
                publication,
                VpbPublication::HandingOffToIoManager(_) | VpbPublication::Withdrawn
            );
            // SAFETY: The mounted VPB retains its real device while the global lock is held.
            let real = unsafe { KernelDevice::from_raw(vpb.RealDevice) }
                .ok_or(DriverError::InvalidParameter)?;
            let routing = if withdrawn {
                VpbRouting::Withdrawn
            } else if unsafe {
                // SAFETY: The same lock protects the real device's current association.
                observe_current_vpb(real.as_ptr())
            } == core::ptr::from_mut(vpb)
            {
                VpbRouting::Current(real)
            } else {
                VpbRouting::Foreign
            };
            work(vpb, routing, publication)
        })?
    }

    /// Captures the exact current association for a lower verification gate.
    /// # Errors
    /// Returns an unmounted, withdrawn, foreign or removing association.
    #[expect(
        unsafe_code,
        reason = "the mounted lifetime owns this VPB while its identity is captured under the lock"
    )]
    fn prepare_storage_verification(
        &self,
    ) -> DriverResult<(
        MediaVerificationAssociation,
        crate::kernel::volume_verify::VerificationDevice,
    )> {
        self.with_routing(|vpb, routing, _| {
            if vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0 {
                return Err(DriverError::WrongVolume);
            }
            let real_device = routing.current()?;
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            // SAFETY: The mounted lifetime owns this VPB, and the original operation retains it.
            let identity = unsafe { KernelVpb::from_raw(core::ptr::from_mut(vpb)) }
                .ok_or(DriverError::InvalidParameter)?;
            Ok((
                MediaVerificationAssociation {
                    device: self.device,
                    vpb: identity,
                    real_device,
                },
                crate::kernel::volume_verify::VerificationDevice::reference(real_device),
            ))
        })
    }

    /// Selects an I/O Manager verify only while this mount still routes the real device.
    /// # Errors
    /// Returns a foreign association, removal, or busy before mount-IRP acknowledgment.
    fn prepare_verify_work(
        &self,
    ) -> DriverResult<Option<crate::kernel::volume_verify::VerificationDevice>> {
        self.with_routing(|vpb, routing, _| {
            let real_device = match routing {
                VpbRouting::Withdrawn => return Ok(None),
                routing => routing.current()?,
            };
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            if !crate::kernel::volume_verify::required(real_device) {
                return Ok(None);
            }
            if vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0 {
                // IoVerifyVolume can wait on the same mount that this callback interrupted.
                return Err(DriverError::DeviceBusy);
            }
            Ok(Some(
                crate::kernel::volume_verify::VerificationDevice::reference(real_device),
            ))
        })
    }

    /// Accepts a kernel verify only for the original VPB that still routes the real device.
    ///
    /// A stale verify after this mount's own withdrawal reports the ended session, not
    /// WRONG_VOLUME: the I/O Manager answers WRONG_VOLUME by installing a new VPB over the current
    /// one, which here is this mount's published successor and would leak. The successor still
    /// admits a fresh mount on the next access.
    /// # Errors
    /// Returns a foreign or unmounted VPB, a withdrawn association as dismounted, or removal.
    fn prepare_media_verification(
        &self,
        supplied: KernelVpb,
    ) -> DriverResult<MediaVerificationAssociation> {
        self.with_routing(|vpb, routing, _| {
            if core::ptr::from_mut(vpb) != supplied.as_non_null().as_ptr()
                || vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED) == 0
            {
                return Err(DriverError::InvalidParameter);
            }
            let real_device = routing
                .current()
                .map_err(|_| DriverError::VolumeDismounted)?;
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            Ok(MediaVerificationAssociation {
                device: self.device,
                vpb: supplied,
                real_device,
            })
        })
    }

    /// Revalidates a captured association without acknowledging the verify flag.
    /// # Errors
    /// Returns a changed, withdrawn, foreign or removing association, or a new verify requirement.
    fn confirm(&self, association: &MediaVerificationAssociation) -> DriverResult<()> {
        self.with_routing(|vpb, routing, _| {
            association.matches(vpb)?;
            routing.current()?;
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            if crate::kernel::volume_verify::required(association.real_device) {
                return Err(DriverError::VerifyRequired);
            }
            Ok(())
        })
    }

    /// Acknowledges verification while the captured VPB still routes the real device.
    ///
    /// For replacement, revocation and flag acknowledgment precede WRONG_VOLUME, which lets
    /// the I/O Manager install its successor and mount without a stale verify gate.
    /// # Errors
    /// Returns dismounted or removal without changing native flags or storage admission.
    fn finish_verification(
        &self,
        association: &MediaVerificationAssociation,
        replacement: Option<MediaReplacement<'_>>,
    ) -> DriverResult<()> {
        self.with_routing(|vpb, routing, publication| {
            let real_device = routing
                .current()
                .map_err(|_| DriverError::VolumeDismounted)?;
            association
                .matches(vpb)
                .map_err(|_| DriverError::VolumeDismounted)?;
            if vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING) != 0 {
                return Err(DriverError::DeviceRemoved);
            }
            if let Some(replacement) = replacement {
                let (VpbPublication::Mounted(successor) | VpbPublication::Excluded(successor)) =
                    core::mem::replace(publication, VpbPublication::Withdrawn)
                else {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
                };
                replacement.revoke();
                vpb.Flags &= !vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED);
                *publication = VpbPublication::HandingOffToIoManager(successor);
            }
            crate::kernel::volume_verify::acknowledge(real_device);
            Ok(())
        })
    }

    /// Transfers new-open routing to a successor under the global VPB lock. The original VPB
    /// remains mounted for native routing of retained FILE_OBJECTs until its last reference drains.
    /// An I/O Manager handoff keeps that authority until native verification has settled.
    fn withdraw_locked(vpb: &mut wdk_sys::VPB, publication: &mut VpbPublication) {
        if matches!(publication, VpbPublication::HandingOffToIoManager(_)) {
            return;
        }
        let replacement = match core::mem::replace(publication, VpbPublication::Withdrawn) {
            VpbPublication::Mounted(replacement) | VpbPublication::Excluded(replacement) => {
                replacement
            }
            VpbPublication::HandingOffToIoManager(_) | VpbPublication::Withdrawn => return,
        };
        Self::publish_successor_locked(vpb, replacement);
    }

    /// Transfers the reserve only if this mount still owns the current association.
    #[expect(
        unsafe_code,
        reason = "the global lock encloses native association replacement and sole allocation-ownership transfer"
    )]
    fn publish_successor_locked(vpb: &mut wdk_sys::VPB, replacement: PoolVpb) {
        let current = unsafe {
            // SAFETY: The mounted storage route retains RealDevice and its current VPB uses this lock.
            observe_current_vpb(vpb.RealDevice)
        };
        if current == core::ptr::from_mut(vpb) {
            let successor = replacement.into_raw();
            unsafe {
                // SAFETY: The unpublished successor is uniquely owned and initialized; fields are
                // populated before the I/O Manager observes the new current association.
                (*successor.as_ptr()).RealDevice = vpb.RealDevice;
            }
            unsafe {
                // SAFETY: The successor receives device removal and RAW-only admission flags.
                // Mount-local state, including VPB_DISMOUNTING, belongs to the original VPB.
                (*successor.as_ptr()).Flags =
                    vpb.Flags & vpb_flag(wdk_sys::VPB_REMOVE_PENDING | wdk_sys::VPB_RAW_MOUNT);
            }
            unsafe {
                // SAFETY: This atomic lock-protected publication transfers destruction to the I/O Manager.
                (*vpb.RealDevice).Vpb = successor.as_ptr();
            }
        }
    }

    /// Withdraws routing, using the reserve if the native verify leaves this VPB current.
    /// # Safety
    /// Dispatch and reactor rundown must have ended, so no later verify can complete with
    /// `STATUS_WRONG_VOLUME` for this VPB. `join_verify` must synchronize with the preceding
    /// native verify and its pending VPB swap before returning.
    #[expect(
        unsafe_code,
        reason = "the VPB lock holds the mounted real device until a native reference can join verification"
    )]
    unsafe fn begin_retirement(self, join_verify: impl FnOnce(VerificationDevice)) -> RetiringVpb {
        let replacement = match self.publication.into_inner() {
            VpbPublication::Mounted(reserve) | VpbPublication::Excluded(reserve) => Some(reserve),
            VpbPublication::HandingOffToIoManager(reserve) => {
                let pending = VpbSpinLock::with_mounted(self.device, |vpb| {
                    // SAFETY: Mounted storage retains the live real device throughout retirement.
                    let real =
                        unsafe { KernelDevice::from_raw(vpb.RealDevice) }.unwrap_or_else(|| {
                            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                        });
                    let current = unsafe {
                        // SAFETY: The retained real device supplies only its association identity.
                        observe_current_vpb(real.as_ptr())
                    };
                    (current == core::ptr::from_mut(vpb))
                        .then(|| VerificationDevice::reference(real))
                })
                .unwrap_or_else(|_| {
                    KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
                });
                if let Some(pending) = pending {
                    join_verify(pending);
                }
                Some(reserve)
            }
            VpbPublication::Withdrawn => None,
        };
        if let Some(replacement) = replacement {
            VpbSpinLock::with_mounted(self.device, |vpb| {
                Self::publish_successor_locked(vpb, replacement);
            })
            .unwrap_or_else(|_| {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck()
            });
        }
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
    /// Returns the reusable owner and reference count while native users retain the detached VPB.
    /// Success transfers sole native deallocation authority for the detached original.
    #[expect(
        unsafe_code,
        reason = "the VPB lock serializes the real device association and final reference"
    )]
    fn try_finish(self) -> Result<PoolVpb, (Self, u32)> {
        let released = VpbSpinLock::with_mounted(self.device, |vpb| {
            let current = unsafe {
                // SAFETY: The retained mounted storage route owns the real device through retirement.
                observe_current_vpb(vpb.RealDevice)
            };
            if current == core::ptr::from_mut(vpb) || vpb.ReferenceCount == 0 {
                KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
            }
            if vpb.ReferenceCount != 1 {
                return Err(vpb.ReferenceCount);
            }
            vpb.ReferenceCount = 0;
            vpb.Flags &= !vpb_flag(
                wdk_sys::VPB_MOUNTED | wdk_sys::VPB_LOCKED | wdk_sys::VPB_DIRECT_WRITES_ALLOWED,
            );
            vpb.DeviceObject = core::ptr::null_mut();
            unsafe {
                // SAFETY: No FILE_OBJECT or in-flight native create retains this original VPB.
                (*self.device.as_ptr()).Vpb = core::ptr::null_mut();
            }
            Ok(PoolVpb {
                allocation: NonNull::from(vpb),
            })
        })
        .unwrap_or_else(|_| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
        released.map_err(|references| (self, references))
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

/// Runs the blocking actor drain and I/O Manager join on a device-referenced thread.
/// # Safety
/// `context` must be the mounted device whose unique start stage was transferred to this thread.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the I/O Manager pins the retiring device until this routine returns"
)]
unsafe extern "C" fn begin_volume_retirement(context: wdk_sys::PVOID) {
    let device = unsafe {
        // SAFETY: Successful thread creation holds the native reference on this mounted device.
        KernelDevice::from_raw(context.cast())
    }
    .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    let extension = unsafe {
        // SAFETY: This is the retained device's mounted extension, initialized before scheduling.
        device
            .extension_address()
            .cast::<MountedVolumeDeviceExtension>()
            .as_ref()
    }
    .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    let pending = unsafe {
        // SAFETY: This is the unique retirement owner until it publishes the detached VPB.
        MountedVolumeDevice::begin_release(device, extension)
    };
    unsafe {
        // SAFETY: The work item transferred its consumed start stage to this thread.
        *extension.pending_retirement.get() = Some(RetirementWork::Finish(pending));
    }
    queue_retirement_work_item(MountedVolumeDevice::retirement_work_item(device));
}

/// PASSIVE_LEVEL work-item callback that advances retirement and deletes the drained device.
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
    let step = unsafe {
        // SAFETY: Work-item ownership pins the device while release closes admission, drains the
        // actor, and either parks the teardown or destroys extension-owned resources.
        MountedVolumeDevice::advance_release(device)
    };
    let RetirementStep::Released = step else {
        return;
    };
    unsafe {
        // SAFETY: A prior retry timer may still be returning from its final queue publication.
        // Drain that DPC before deleting the extension containing its storage.
        ffi::KeFlushQueuedDpcs();
    }
    unsafe {
        // SAFETY: All extension resources are gone and the work item still pins this device.
        ffi::IoDeleteDevice(device.as_ptr());
    }
    unsafe {
        // SAFETY: The system dequeued this item before invoking the callback, so the callback may
        // free it; the I/O Manager releases its device reference after the callback returns.
        ffi::IoFreeWorkItem(work_item.as_ptr());
    }
    MOUNTED_VOLUMES.release_retired();
}

/// Closed bit of the census. The low half counts all reservations and mounted devices;
/// the intervening bits count the subset whose mount operation has not finished.
const MOUNTED_VOLUMES_CLOSED: usize = 1 << (usize::BITS - 1);

/// Unit of the count of mounts still in progress.
const MOUNT_IN_PROGRESS: usize = 1 << (usize::BITS / 2);
/// Increment of both the pending and total counts when admitting a mount.
const MOUNT_RESERVATION: usize = MOUNT_IN_PROGRESS + 1;
/// Mask of the total number of pending mounts and published devices.
const MOUNT_COUNT: usize = MOUNT_IN_PROGRESS - 1;
/// Mask of the number of pending mounts.
const MOUNTS_PENDING: usize = MOUNTED_VOLUMES_CLOSED - MOUNT_IN_PROGRESS;

/// Driver-lifetime mount intake and volume census.
pub(crate) static MOUNTED_VOLUMES: MountedVolumeCensus = MountedVolumeCensus::new();

/// Serializes mount reservations, publication, and unload against one atomic state.
/// A device stays counted until its retirement calls `IoDeleteDevice`.
#[derive(Debug)]
pub(crate) struct MountedVolumeCensus(core::sync::atomic::AtomicUsize);

impl MountedVolumeCensus {
    /// Starts with open intake and no volumes.
    const fn new() -> Self {
        Self(core::sync::atomic::AtomicUsize::new(0))
    }

    /// Reserves census membership before starting mount I/O.
    /// # Errors
    /// Returns invalid-device-request after mount intake closed, or resource
    /// exhaustion when the count cannot be represented.
    pub(crate) fn reserve_mount(&self) -> DriverResult<MountReservation<'_>> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & MOUNTED_VOLUMES_CLOSED != 0
                    || state & MOUNT_COUNT == MOUNT_COUNT
                    || state & MOUNTS_PENDING == MOUNTS_PENDING
                {
                    return None;
                }
                state.checked_add(MOUNT_RESERVATION)
            })
            .map_err(|state| {
                if state & MOUNTED_VOLUMES_CLOSED != 0 {
                    DriverError::InvalidDeviceRequest
                } else {
                    DriverError::InsufficientResources
                }
            })?;
        Ok(MountReservation { census: self })
    }

    /// Removes the pending reservation and, on failure, releases its census membership.
    fn finish_mount(&self, decrement: usize) {
        if self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & MOUNTS_PENDING == 0 {
                    return None;
                }
                state.checked_sub(decrement)
            })
            .is_err()
        {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
    }

    /// Releases the count of a published device whose `IoDeleteDevice` has been called.
    fn release_retired(&self) {
        if self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                let total = state & MOUNT_COUNT;
                let pending = (state & MOUNTS_PENDING) / MOUNT_IN_PROGRESS;
                if total <= pending {
                    return None;
                }
                state.checked_sub(1)
            })
            .is_err()
        {
            KernelWideInconsistency::mounted_volume_state_corruption().bugcheck();
        }
    }

    /// Closes mount intake for this image load so existing volumes can dismount without a
    /// racing remount. Published volumes stay usable until their ordinary dismount.
    /// # Errors
    /// Returns device-busy while earlier reservations can still publish. Intake stays closed
    /// and repeated requests observe the same drain.
    pub(crate) fn quiesce_mounts(&self) -> DriverResult<()> {
        let previous = self.0.fetch_or(MOUNTED_VOLUMES_CLOSED, Ordering::AcqRel);
        if previous & MOUNTS_PENDING != 0 {
            return Err(DriverError::DeviceBusy);
        }
        Ok(())
    }

    /// Closes mount admission for driver retirement when no mounted volume remains.
    /// # Errors
    /// Returns device-busy while a mount is pending or a volume is live or still retiring.
    /// A closed census stays closed, so repeated requests are idempotent.
    pub(crate) fn close_for_unload(&self) -> DriverResult<()> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |state| match state {
                0 => Some(MOUNTED_VOLUMES_CLOSED),
                MOUNTED_VOLUMES_CLOSED => Some(MOUNTED_VOLUMES_CLOSED),
                _ => None,
            })
            .map(|_| ())
            .map_err(|_| DriverError::DeviceBusy)
    }

    /// Reports whether prepare-unload closed the census with no mounted volume remaining.
    pub(crate) fn retired_for_unload(&self) -> bool {
        self.0.load(Ordering::Acquire) == MOUNTED_VOLUMES_CLOSED
    }
}

/// One pending mount that remains counted until publication fails or transfers to its device.
#[derive(Debug)]
pub(crate) struct MountReservation<'census> {
    /// Census that must observe the result of this reservation.
    census: &'census MountedVolumeCensus,
}

impl MountReservation<'_> {
    /// Transfers census membership to the published device. Device deletion releases it.
    pub(crate) fn publish(self) {
        self.census.finish_mount(MOUNT_IN_PROGRESS);
        core::mem::forget(self);
    }
}

impl Drop for MountReservation<'_> {
    fn drop(&mut self) {
        self.census.finish_mount(MOUNT_RESERVATION);
    }
}

/// Delay before the next retirement attempt while the original VPB still has native references.
///
/// References normally drain within the I/O Manager's FILE_OBJECT deletion just after Close, so
/// the first retry is short. A reference held longer, such as by another component's stream file
/// object, backs off exponentially to a bounded interval instead of polling at a fixed rate.
#[cfg(not(test))]
#[derive(Clone, Copy, Debug)]
struct RetirementRetryDelay {
    /// Positive delay in 100 ns units.
    units_100ns: i64,
}

#[cfg(not(test))]
impl RetirementRetryDelay {
    /// First retry after 10 ms.
    const FIRST: Self = Self {
        units_100ns: 100_000,
    };
    /// Retries never wait longer than 1 s.
    const LIMIT: Self = Self {
        units_100ns: 10_000_000,
    };

    /// Relative due time in the negative 100 ns representation that `KeSetTimer` expects.
    const fn relative_due_time(self) -> i64 {
        self.units_100ns.saturating_neg()
    }

    /// Doubles the delay up to the limit.
    fn next(self) -> Self {
        Self {
            units_100ns: self
                .units_100ns
                .saturating_mul(2)
                .min(Self::LIMIT.units_100ns),
        }
    }
}

/// Physical teardown parked between retirement work-item invocations.
#[cfg(not(test))]
struct PendingRetirement {
    /// Original VPB whose final reference this mount still holds.
    vpb: RetiringVpb,
    /// Joined mounted binding, released only after the VPB is detached.
    binding: MountedVolumeBinding,
    /// Last observed native reference count; `None` before the first retained attempt.
    reported: Option<u32>,
    /// Delay before the next attempt if references still remain.
    retry: RetirementRetryDelay,
}

/// Exclusive retirement stage passed between the work item and the blocking producer.
#[cfg(not(test))]
enum RetirementWork {
    /// Start the dedicated thread, retaining backoff on thread-creation failure.
    Start(RetirementRetryDelay),
    /// Actor and native verify joined. Poll the detached VPB's remaining references.
    Finish(PendingRetirement),
}

/// Outcome of one retirement work-item invocation.
#[cfg(not(test))]
enum RetirementStep {
    /// The thread or timer owns the next invocation.
    Retained,
    /// Extension resources are released and the device may be deleted.
    Released,
}

/// Queues one retirement invocation; the I/O Manager pins the device until its callback returns.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the mount-preallocated work item is queued only when no other invocation is queued"
)]
fn queue_retirement_work_item(work_item: NonNull<wdk_sys::_IO_WORKITEM>) {
    unsafe {
        // SAFETY: Retiring or the expired retry timer makes this the unique queue operation, and
        // the mounted device that owns the item has not been deleted.
        ffi::IoQueueWorkItem(
            work_item.as_ptr(),
            Some(mounted_volume_retirement),
            wdk_sys::_WORK_QUEUE_TYPE::DelayedWorkQueue,
            work_item.as_ptr().cast::<c_void>(),
        );
    }
}

/// Timer DPC that starts the next retirement invocation.
/// # Safety
/// `context` must be the mounted device's retirement work item bound at mount initialization.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the DPC context is the retained mount-preallocated retirement work item"
)]
unsafe extern "C" fn mounted_volume_retirement_dpc(
    _dpc: *mut wdk_sys::KDPC,
    context: wdk_sys::PVOID,
    _argument_one: wdk_sys::PVOID,
    _argument_two: wdk_sys::PVOID,
) {
    let work_item = NonNull::new(context.cast::<wdk_sys::_IO_WORKITEM>())
        .unwrap_or_else(|| KernelWideInconsistency::mounted_volume_state_corruption().bugcheck());
    queue_retirement_work_item(work_item);
}

/// Unregisters only a live shutdown notification, including during prepublication rollback.
#[cfg_attr(
    not(test),
    expect(
        unsafe_code,
        reason = "consuming the registered flag owns native unregistration"
    )
)]
fn consume_shutdown_registration(device: KernelDevice, registered: &AtomicU8) {
    if registered.swap(0, Ordering::AcqRel) == 0 {
        return;
    }
    #[cfg(not(test))]
    unsafe {
        // SAFETY: The successful exchange consumed this live device's registered notification.
        ffi::IoUnregisterShutdownNotification(device.as_ptr());
    }
    #[cfg(test)]
    let _device = device;
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

/// Writes the Windows label projection into the VPB, zeroing the unused label units.
fn write_vpb_label(vpb: &mut wdk_sys::VPB, label: &WindowsVolumeLabel) {
    let units = label
        .padded_units()
        .iter()
        .copied()
        .chain(core::iter::repeat(0));
    for (target, unit) in vpb.VolumeLabel.iter_mut().zip(units) {
        *target = unit;
    }
    vpb.VolumeLabelLength = label.byte_len();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::Ext4VolumeLabel;

    /// Closing intake settles admitted mounts before dismount, while unload waits for device deletion.
    /// # Errors
    /// Returns failure to reserve either mount while intake is open.
    /// # Panics
    /// Fails if a new mount enters after quiesce, or unload succeeds before the published device retires.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible mount reservations precede lifecycle assertions"
    )]
    fn quiesce_drains_admitted_mounts_before_volume_retirement() -> DriverResult<()> {
        let census = MountedVolumeCensus::new();
        let publishing = census.reserve_mount()?;
        let abandoning = census.reserve_mount()?;

        assert_eq!(census.quiesce_mounts(), Err(DriverError::DeviceBusy));
        assert!(matches!(
            census.reserve_mount(),
            Err(DriverError::InvalidDeviceRequest)
        ));
        publishing.publish();
        assert_eq!(census.quiesce_mounts(), Err(DriverError::DeviceBusy));
        drop(abandoning);

        assert_eq!(census.quiesce_mounts(), Ok(()));
        assert_eq!(census.close_for_unload(), Err(DriverError::DeviceBusy));
        assert!(!census.retired_for_unload());
        census.release_retired();
        assert_eq!(census.close_for_unload(), Ok(()));
        assert!(census.retired_for_unload());
        assert!(matches!(
            census.reserve_mount(),
            Err(DriverError::InvalidDeviceRequest)
        ));
        Ok(())
    }

    /// A mount notification may query the published volume before mount-IRP acknowledgment.
    /// # Errors
    /// Returns fixture publication, verify retention or native retirement failure.
    /// # Panics
    /// Fails if acknowledgment timing changes media identity, or the successor's verify flag
    /// selects verification for this mount after its own routing withdrawal.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "native fixture setup and retirement surround association-admission assertions"
    )]
    fn published_mount_admits_reentry_before_io_manager_acknowledgment() -> DriverResult<()> {
        let mut fixture = VpbFixture::new()?;
        let publication = fixture.publish()?;
        fixture.original(|vpb| {
            assert_eq!(vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
        })?;
        assert!(publication.prepare_verify_work()?.is_none());
        fixture.real.Flags |= wdk_sys::DO_VERIFY_VOLUME;
        assert!(matches!(
            publication.prepare_verify_work(),
            Err(DriverError::DeviceBusy)
        ));
        fixture.original(|vpb| vpb.Flags |= vpb_flag(wdk_sys::VPB_MOUNTED))?;
        let retained = publication
            .prepare_verify_work()?
            .ok_or(DriverError::InternalInvariantViolation)?;
        drop(retained);
        publication.publish_session_end(SessionEndRouting::Remount);
        assert!(publication.prepare_verify_work()?.is_none());
        drop(
            retire_fixture(publication)
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns native fixture allocation/publication or finalization failure.
    /// # Panics
    /// Fails if success without acknowledgment, a new verify gate or a stale VPB permits
    /// resubmission, or if own withdrawal and a foreign association change are conflated.
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
        // The I/O Manager marks the VPB mounted after successful mount-IRP completion.
        fixture.original(|vpb| vpb.Flags |= vpb_flag(wdk_sys::VPB_MOUNTED))?;
        fixture.real.Flags |= wdk_sys::DO_VERIFY_VOLUME;
        let (association, query) = publication.prepare_storage_verification()?;
        assert_eq!(query.execute(), Ok(()));
        assert_eq!(
            publication.confirm(&association),
            Err(DriverError::VerifyRequired)
        );
        assert_ne!(fixture.real.Flags & wdk_sys::DO_VERIFY_VOLUME, 0);
        let (association, query) = publication.prepare_storage_verification()?;
        drop(query);
        publication.finish_verification(&association, None)?;
        assert_eq!(fixture.real.Flags, 0x4000);
        let (association, query) = publication.prepare_storage_verification()?;
        drop(query);
        assert_eq!(publication.confirm(&association), Ok(()));

        // A current VPB that this mount did not withdraw is a foreign change.
        let original = fixture.real.Vpb;
        let mut foreign = wdk_sys::VPB::default();
        fixture.real.Vpb = core::ptr::from_mut(&mut foreign);
        assert_eq!(
            publication.confirm(&association),
            Err(DriverError::WrongVolume)
        );
        assert!(matches!(
            publication.prepare_storage_verification(),
            Err(DriverError::WrongVolume)
        ));
        fixture.real.Vpb = original;

        let (stale, query) = publication.prepare_storage_verification()?;
        drop(query);
        let supplied = stale.vpb;
        publication.publish_session_end(SessionEndRouting::Remount);
        fixture.real.Flags |= wdk_sys::DO_VERIFY_VOLUME;
        assert_eq!(
            publication.confirm(&stale),
            Err(DriverError::VolumeDismounted)
        );
        assert_eq!(
            publication.finish_verification(&stale, None),
            Err(DriverError::VolumeDismounted)
        );
        assert!(matches!(
            publication.prepare_storage_verification(),
            Err(DriverError::VolumeDismounted)
        ));
        // WRONG_VOLUME would make the I/O Manager overwrite the published successor.
        assert!(matches!(
            publication.prepare_media_verification(supplied),
            Err(DriverError::VolumeDismounted)
        ));
        assert_eq!(fixture.real.Flags, wdk_sys::DO_VERIFY_VOLUME | 0x4000);
        drop(
            retire_fixture(publication)
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns native fixture setup or finalization failure.
    /// # Panics
    /// Fails if media replacement leaves the verify gate armed, changes stale routing, or lets
    /// retirement free a still-current VPB.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup and retirement surround replacement-routing assertions"
    )]
    #[expect(
        unsafe_code,
        reason = "the fixture's real device retains its current VPB under the lock"
    )]
    fn media_replacement_acknowledges_only_the_current_association() -> DriverResult<()> {
        for session_end in [
            None,
            Some(SessionEndRouting::DirectAccess),
            Some(SessionEndRouting::Remount),
        ] {
            for (replaced_before_retirement, replaced_during_join) in
                [(true, false), (false, true), (false, false)]
            {
                let mut fixture = VpbFixture::new()?;
                let publication = fixture.publish()?;
                fixture.original(|vpb| vpb.Flags |= vpb_flag(wdk_sys::VPB_MOUNTED))?;
                let original = fixture.real.Vpb;
                let (association, query) = publication.prepare_storage_verification()?;
                drop(query);
                if let Some(routing) = session_end {
                    publication.publish_session_end(routing);
                }
                let withdrawn = fixture.real.Vpb;
                fixture.real.Flags = wdk_sys::DO_VERIFY_VOLUME | 0x4000;
                let stream = crate::kernel::stream::VolumeStream::try_new_volume(
                    crate::kernel::stream::StreamSizes::EMPTY,
                    crate::kernel::operational_trace::OperationalTrace::host_test(),
                    crate::kernel::io_reliability::IoReliabilityOwner::try_new()?.observe()?,
                )?;
                let storage = unsafe {
                    // SAFETY: The local stream remains live through the test.
                    stream.storage_access()
                };
                let result = unsafe {
                    // SAFETY: The fixture is the sole actor and retains the local stream.
                    stream.with_media_replacement(|replacement| {
                        publication.finish_verification(&association, Some(replacement))
                    })
                };
                assert_eq!(fixture.real.Vpb, withdrawn);
                if withdrawn == original {
                    assert_eq!(result, Ok(()));
                    assert_eq!(fixture.real.Flags, 0x4000);
                    assert_eq!(storage.authorize(), Err(DriverError::MediaReplaced));
                } else {
                    assert_eq!(result, Err(DriverError::VolumeDismounted));
                    assert_eq!(fixture.real.Flags, wdk_sys::DO_VERIFY_VOLUME | 0x4000);
                    assert_eq!(storage.authorize(), Ok(()));
                }
                fixture.original(|vpb| {
                    assert_eq!(vpb.Flags & vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED), 0);
                    assert_ne!(vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
                })?;
                assert!(publication.prepare_verify_work()?.is_none());
                assert!(matches!(
                    publication.prepare_storage_verification(),
                    Err(DriverError::VolumeDismounted)
                ));
                if replaced_before_retirement && fixture.real.Vpb == original {
                    fixture.install_native_successor()?;
                }
                let current = fixture.real.Vpb;
                let mut joined = None;
                let retirement = unsafe {
                    // SAFETY: The fixture's native verify either finishes publication inside
                    // the join or returns with the original still current. No other actor runs.
                    publication.begin_retirement(|_| {
                        assert_eq!(fixture.real.Vpb, original);
                        joined = Some(if replaced_during_join {
                            fixture
                                .install_native_successor()
                                .map(|()| fixture.real.Vpb)
                        } else {
                            Ok(original)
                        });
                    })
                };
                if current == original {
                    let observed = joined.ok_or(DriverError::InternalInvariantViolation)??;
                    if replaced_during_join {
                        assert_eq!(fixture.real.Vpb, observed);
                    } else {
                        assert_ne!(fixture.real.Vpb, observed);
                    }
                } else {
                    assert!(joined.is_none());
                    assert_eq!(fixture.real.Vpb, current);
                }
                {
                    let _lock = VpbSpinLock::acquire();
                    // SAFETY: The fixture's real device retains its current VPB under the lock.
                    let successor = unsafe { &*fixture.real.Vpb };
                    assert_eq!(successor.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
                    assert!(successor.DeviceObject.is_null());
                }
                drop(
                    retirement
                        .try_finish()
                        .map_err(|_| DriverError::DeviceBusy)?,
                );
                fixture.finish()?;
            }
        }
        Ok(())
    }

    /// Withdraws a fixture once all modeled dispatch and verify activity has ended.
    #[expect(
        unsafe_code,
        reason = "the host fixture has no asynchronous verify or dispatch"
    )]
    fn retire_fixture(publication: MountedVpb) -> RetiringVpb {
        // SAFETY: No native dispatch or verify runs concurrently with the fixture.
        unsafe { publication.begin_retirement(|_| {}) }
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
            let original = PoolVpb::fixture()?;
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
                WindowsVolumeLabel::from_ext4(Ext4VolumeLabel::new(b"AB")?)?,
                PoolVpb::fixture()?,
            )?;
            let original = self
                .original
                .take()
                .ok_or(DriverError::InternalInvariantViolation)?;
            let _native_allocation = original.into_raw();
            Ok(publication)
        }

        /// Installs the successor that `IoVerifyVolume` allocates after `STATUS_WRONG_VOLUME`.
        /// # Errors
        /// Returns successor allocation failure before changing the current VPB.
        #[expect(
            unsafe_code,
            reason = "the fixture emulates the I/O Manager's locked association exchange"
        )]
        fn install_native_successor(&mut self) -> DriverResult<()> {
            let fresh = PoolVpb::fixture()?.into_raw();
            let _lock = VpbSpinLock::acquire();
            unsafe {
                // SAFETY: The fresh allocation is unpublished and exclusively owned here.
                (*fresh.as_ptr()).RealDevice = core::ptr::from_mut(self.real.as_mut());
            }
            self.real.Vpb = fresh.as_ptr();
            Ok(())
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

        publication.publish_session_end(SessionEndRouting::Remount);
        assert_ne!(fixture.real.Vpb, original);
        assert_eq!(first.Vpb, original);
        assert_eq!(second.Vpb, original);
        fixture.original(|vpb| {
            assert_eq!(vpb.ReferenceCount, 3);
            vpb.ReferenceCount -= 2;
        })?;
        drop(
            retire_fixture(publication)
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns allocation, label or native retirement failure.
    /// # Panics
    /// Fails if retained native references lose their route, block a fresh mount, or affect its VPB.
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
            vpb.Flags = vpb_flag(wdk_sys::VPB_PERSISTENT | wdk_sys::VPB_DISMOUNTING);
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
        publication.publish_session_end(SessionEndRouting::Remount);
        assert_ne!(fixture.real.Vpb, original);
        fixture.original(|vpb| {
            assert_eq!(vpb.DeviceObject, original_device.as_ptr());
            assert_eq!(vpb.VolumeLabelLength, 2);
            assert_eq!(vpb.VolumeLabel.first(), Some(&90));
            assert_ne!(vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
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
        {
            let _lock = VpbSpinLock::acquire();
            // SAFETY: The fixture retains the current successor and the global lock protects it.
            let vpb = unsafe { supplied.as_non_null().as_ref() };
            assert_eq!(vpb.Flags, 0);
            assert!(vpb.DeviceObject.is_null());
        }
        let fresh_mount = MountedVpb::publish(
            supplied,
            fresh_device,
            73,
            WindowsVolumeLabel::from_ext4(Ext4VolumeLabel::new(b"fresh")?)?,
            PoolVpb::fixture()?,
        )?;
        let successor = fixture.real.Vpb;
        let (retirement, references) = retire_fixture(publication)
            .try_finish()
            .err()
            .ok_or(DriverError::InternalInvariantViolation)?;
        assert_eq!(references, 3);
        fixture.original(|vpb| {
            assert_ne!(vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
            assert_eq!(vpb.DeviceObject, original_device.as_ptr());
            vpb.ReferenceCount -= 2;
        })?;
        let released = retirement
            .try_finish()
            .map_err(|_| DriverError::DeviceBusy)?;
        {
            let _lock = VpbSpinLock::acquire();
            // SAFETY: `released` uniquely owns the detached VPB until it is freed below.
            let vpb = unsafe { released.allocation.as_ref() };
            assert_eq!(vpb.Flags & vpb_flag(wdk_sys::VPB_MOUNTED), 0);
            assert!(vpb.DeviceObject.is_null());
        }
        drop(released);
        assert!(fixture.mounted.Vpb.is_null());
        assert_eq!(fixture.real.Vpb, successor);
        VpbSpinLock::with_mounted(fresh_device, |vpb| {
            assert_eq!(vpb.SerialNumber, 73);
            assert_eq!(vpb.VolumeLabelLength, 10);
            assert_eq!(vpb.ReferenceCount, 1);
        })?;
        drop(
            retire_fixture(fresh_mount)
                .try_finish()
                .map_err(|_| DriverError::DeviceBusy)?,
        );
        fixture.finish()
    }

    /// # Errors
    /// Returns native fixture setup or finalization failure.
    /// # Panics
    /// Fails if direct access loses remount exclusion or owner release leaves stale native flags.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible setup and retirement surround lock/remount assertions"
    )]
    fn direct_access_excludes_remount_until_owner_release() -> DriverResult<()> {
        for locked in [false, true] {
            let mut fixture = VpbFixture::new()?;
            let publication = fixture.publish()?;
            let original = fixture.real.Vpb;
            publication.publish_lock(locked);
            publication.publish_session_end(SessionEndRouting::DirectAccess);
            assert_eq!(fixture.real.Vpb, original);
            fixture.original(|vpb| {
                assert_eq!(vpb.Flags & vpb_flag(wdk_sys::VPB_LOCKED) != 0, locked);
                assert_ne!(vpb.Flags & vpb_flag(wdk_sys::VPB_DIRECT_WRITES_ALLOWED), 0);
            })?;
            publication.publish_lock(false);
            assert_ne!(fixture.real.Vpb, original);
            fixture.original(|vpb| {
                assert_eq!(
                    vpb.Flags & vpb_flag(wdk_sys::VPB_LOCKED | wdk_sys::VPB_DIRECT_WRITES_ALLOWED),
                    0
                );
            })?;
            drop(
                retire_fixture(publication)
                    .try_finish()
                    .map_err(|_| DriverError::DeviceBusy)?,
            );
            fixture.finish()?;
        }
        Ok(())
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
        let retirement = retire_fixture(publication);
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
