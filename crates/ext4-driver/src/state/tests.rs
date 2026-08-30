use alloc::boxed::Box;
use core::cell::Cell;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::pin::Pin;
use core::ptr::NonNull;

use ext4_core::{ByteOffset, DeviceLength, DirectoryNodeId, Ext4Name, FileOffset, NodeId};

use crate::irp::{
    ActiveFileObject, CreateDeletion, DataIoKind, DeleteAccess, FileAttributesWriteAccess,
    OplockControlAction, ReceivedIrp, RegularFileWriteAccess,
};
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::status::DriverError;

use super::{
    CleanCloseTerminal, CleanupStart, CloseReleasePlan, ControlDeviceLifecycle, ControlDevicePhase,
    DIRECTORY_NOTIFICATION_DIRECTORY_UNITS, DataTransferMode, DeviceExtensionKind, DirectoryChange,
    DirectoryChangeAction, DriverDeviceKind, FileControlBlock, FileControlBlockLedger,
    FileControlBlockOpenState, FileObjectCloseKind, HandleAdmissionState, HandleDeletion,
    KernelDevice, KernelFileObject, MountedVolumeState, NativeFileByteRange,
    NativeResidencyRecheck, NoIntermediateTransfer, OpenedDirectory, OpenedFileObject,
    OpenedHandle, OpenedLocation, OpenedNodeMode, OpenedObject, OpenedRegularFile,
    OpenedVolumeHandle, RawExtentPolicy, RawVolumeAccess, RawVolumeIoPermit,
    RawVolumeOperationKind, RawWriteOutcome, RetirementAdmission, StreamLifetimeState,
    TransferBufferAlignment, TransferSectorSize, UninitializedFileObject, VolumeControlBlock,
    VolumeHandleCleanup, VolumeRetirement, select_close_release_plan, shutdown_registration_status,
};

/// # Errors
///
/// Returns fixture-construction failure rather than pretending retirement was exercised.
/// # Panics
///
/// Panics if retirement invalidates the persistent tag, loses rejected input ownership, or
/// permits a later request to borrow the destroyed actor.
#[test]
#[expect(
    unsafe_code,
    reason = "the fixture owns final-address device and extension storage"
)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture setup returns errors; assertions report lifecycle contract failures"
)]
fn retired_device_header_rejects_actor_access_and_retains_its_tag() -> Result<(), DriverError> {
    let mut raw_device = wdk_sys::DEVICE_OBJECT::default();
    let device = unsafe {
        // SAFETY: This stack-local device remains live through initialization and retirement.
        KernelDevice::from_raw(core::ptr::addr_of_mut!(raw_device))
    }
    .ok_or(DriverError::InternalInvariantViolation)?;
    let mut storage = MaybeUninit::<super::DeviceExtensionHeader>::uninit();
    unsafe {
        // SAFETY: The unpublished header remains at this address through retirement.
        super::DeviceExtensionHeader::initialize_at(
            storage.as_mut_ptr(),
            DeviceExtensionKind::CONTROL,
            device,
            super::ReactorTarget::ControlDevice,
            crate::kernel::operational_trace::OperationalTrace::host_test(),
        )?;
    }
    let header = unsafe {
        // SAFETY: Successful initialization established a complete header at this address.
        storage.assume_init_ref()
    };
    assert_eq!(header.with_reactor(41, |value, _| value + 1), Ok(42));
    let target = unsafe {
        // SAFETY: This fixture owns the sole retirement call and no actor borrow is live.
        header.retire()
    };
    assert!(matches!(target, super::ReactorTarget::ControlDevice));
    assert_eq!(
        DriverDeviceKind::decode(header.kind),
        Ok(DriverDeviceKind::Control)
    );
    let entered = Cell::new(false);
    assert_eq!(
        header.with_reactor(41, |value, _| {
            entered.set(true);
            value + 1
        }),
        Err(41)
    );
    assert!(!entered.get());
    Ok(())
}

/// # Panics
///
/// Panics when registration can be consumed before publication, concurrently consumed without
/// a busy result, or consumed more than once after its idempotent commit point.
#[test]
fn control_retirement_has_one_recoverable_transition() {
    let registration = ControlDeviceLifecycle::unpublished();
    assert_eq!(
        registration.begin_retirement(),
        Err(DriverError::InternalInvariantViolation)
    );
    registration.mark_registered();
    assert_eq!(
        registration.begin_retirement(),
        Ok(RetirementAdmission::Acquired)
    );
    assert_eq!(
        registration.begin_retirement(),
        Err(DriverError::DeviceBusy)
    );
    registration.finish_retirement();
    assert_eq!(registration.state(), ControlDevicePhase::Retired);
    assert_eq!(
        registration.begin_retirement(),
        Ok(RetirementAdmission::AlreadyRetired)
    );
}

/// Returns the common no-delete fixture policy for opened-handle tests.
const fn retained_handle_deletion() -> HandleDeletion {
    HandleDeletion::Retain {
        delete_access: DeleteAccess::Denied,
        file_attributes_write_access: FileAttributesWriteAccess::Denied,
    }
}

/// Allocates a directory-handle fixture through the production constructor.
/// # Panics
///
/// Panics when the fixed fixture cannot allocate its directory cursor.
fn directory_handle(
    node_mode: OpenedNodeMode,
    data_transfer_mode: DataTransferMode,
) -> Option<OpenedHandle> {
    let handle = OpenedHandle::new(
        NodeId::Directory(DirectoryNodeId::ROOT),
        node_mode,
        OpenedLocation::Root,
        retained_handle_deletion(),
        data_transfer_mode,
        RegularFileWriteAccess::Denied,
    );
    assert!(handle.is_ok());
    handle.ok()
}

#[expect(
    unsafe_code,
    reason = "the fixture callers supply live native header storage whenever both contexts are nonnull"
)]
fn file_object_with_contexts(
    fs_context: *mut core::ffi::c_void,
    fs_context2: *mut core::ffi::c_void,
) -> wdk_sys::FILE_OBJECT {
    let mut file_object = wdk_sys::FILE_OBJECT {
        FsContext: fs_context,
        FsContext2: fs_context2,
        ..wdk_sys::FILE_OBJECT::default()
    };
    if let (Some(header), false) = (NonNull::new(fs_context), fs_context2.is_null()) {
        file_object.SectionObjectPointer = unsafe {
            // SAFETY: Nonempty fixture pairs below retain a StreamContext owner until return.
            crate::kernel::stream::StreamContext::decode_section_objects(header)
        }
        .map_or(core::ptr::null_mut(), NonNull::as_ptr);
    }
    file_object
}

/// # Panics
///
/// Panics when the FSD-owned volume flag permits a node stream to decode as a direct-volume open.
#[test]
fn volume_open_flag_rejects_node_stream_context() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let mut handle = OpenedVolumeHandle::new(RawVolumeAccess::MetadataOnly);
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    file.Flags |= wdk_sys::FO_VOLUME_OPEN | wdk_sys::FO_SYNCHRONOUS_IO;

    let result = with_active_file_object(&mut file, |file_object| {
        assert!(matches!(
            OpenedObject::decode(file_object),
            Err(DriverError::ObjectTypeMismatch)
        ));
        assert!(matches!(
            OpenedFileObject::decode(file_object),
            Err(DriverError::InternalInvariantViolation)
        ));
        Ok(())
    });
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when the mounted/locked policy permits a competing handle or create.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn mounted_volume_lock_policy_is_owned_by_one_file_object() {
    let mut owner_file = wdk_sys::FILE_OBJECT::default();
    let mut competing_file = wdk_sys::FILE_OBJECT::default();
    let Some(owner) = (unsafe {
        // SAFETY: The stack-local owner FILE_OBJECT remains live throughout this test.
        KernelFileObject::from_raw(core::ptr::addr_of_mut!(owner_file))
    }) else {
        return;
    };
    let Some(competing) = (unsafe {
        // SAFETY: The stack-local competing FILE_OBJECT remains live throughout this test.
        KernelFileObject::from_raw(core::ptr::addr_of_mut!(competing_file))
    }) else {
        return;
    };

    let mounted = MountedVolumeState::Mounted;
    assert_eq!(mounted.authorize_create(), Ok(()));
    assert_eq!(mounted.authorize_handle(competing), Ok(()));
    let locking = mounted.begin_lock(owner);
    assert_eq!(locking, Ok(MountedVolumeState::Locking { owner }));
    let Ok(locking) = locking else {
        return;
    };
    assert_eq!(locking.authorize_create(), Err(DriverError::AccessDenied));
    assert_eq!(
        locking.authorize_handle(owner),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        locking.authorize_raw(owner, RawVolumeOperationKind::Read),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(locking.abort_lock(owner), Some(MountedVolumeState::Mounted));
    assert_eq!(locking.abort_lock(competing), None);
    assert_eq!(locking.finish_lock(competing), None);
    let locked = locking.finish_lock(owner);
    assert_eq!(locked, Some(MountedVolumeState::Locked { owner }));
    let Some(locked) = locked else {
        return;
    };
    assert_eq!(locked.authorize_create(), Err(DriverError::AccessDenied));
    assert_eq!(locked.authorize_handle(owner), Ok(()));
    assert_eq!(
        locked.authorize_handle(competing),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(locked.unlock(competing), Err(DriverError::NotLocked));
    assert_eq!(
        mounted.authorize_raw(owner, RawVolumeOperationKind::Read),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        locked.authorize_raw(owner, RawVolumeOperationKind::Read),
        Ok(())
    );
    assert_eq!(
        locked.authorize_raw(owner, RawVolumeOperationKind::Write),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        locked.authorize_raw(competing, RawVolumeOperationKind::Read),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(locked.unlock(owner), Ok(MountedVolumeState::Mounted));
}

/// # Panics
///
/// Panics when logical dismount can be reversed or loses its retained lock owner.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn mounted_volume_dismount_is_terminal_and_cleanup_can_release_lock() {
    let mut owner_file = wdk_sys::FILE_OBJECT::default();
    let mut competing_file = wdk_sys::FILE_OBJECT::default();
    let Some(owner) = (unsafe {
        // SAFETY: The stack-local owner FILE_OBJECT remains live throughout this test.
        KernelFileObject::from_raw(core::ptr::addr_of_mut!(owner_file))
    }) else {
        return;
    };
    let Some(competing) = (unsafe {
        // SAFETY: The stack-local competing FILE_OBJECT remains live throughout this test.
        KernelFileObject::from_raw(core::ptr::addr_of_mut!(competing_file))
    }) else {
        return;
    };

    let closing = MountedVolumeState::Locked { owner }.begin_dismount(owner);
    assert_eq!(
        closing,
        Ok(MountedVolumeState::Closing {
            terminal: CleanCloseTerminal::Dismount,
            lock_owner: Some(owner)
        })
    );
    let Ok(closing) = closing else {
        return;
    };
    assert_eq!(closing.ensure_mounted(), Ok(()));
    assert_eq!(
        closing.authorize_handle(owner),
        Err(DriverError::AccessDenied)
    );
    let Some(dismounted) = closing.finish_close(CleanCloseTerminal::Dismount) else {
        return;
    };
    assert_eq!(
        closing.authorize_raw(owner, RawVolumeOperationKind::Write),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        dismounted.authorize_raw(owner, RawVolumeOperationKind::Write),
        Ok(())
    );
    assert_eq!(dismounted.authorize_raw_extent_change(owner), Ok(()));
    assert_eq!(
        dismounted.authorize_raw(competing, RawVolumeOperationKind::Write),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        dismounted.authorize_handle(owner),
        Err(DriverError::VolumeDismounted)
    );
    assert_eq!(
        dismounted.begin_dismount(owner),
        Err(DriverError::VolumeDismounted)
    );
    assert_eq!(dismounted.unlock(competing), Err(DriverError::NotLocked));
    assert_eq!(
        dismounted.cleanup(competing),
        (dismounted, VolumeHandleCleanup::Released)
    );
    assert_eq!(
        dismounted.cleanup(owner),
        (
            MountedVolumeState::Dismounted { lock_owner: None },
            VolumeHandleCleanup::Unlocked
        )
    );
}

/// # Panics
///
/// Panics when physical retirement starts before every FILE_OBJECT is gone.
#[test]
fn dismounted_volume_retires_only_after_all_file_objects_close() {
    let dismounted = MountedVolumeState::Dismounted { lock_owner: None };
    assert_eq!(
        dismounted.retire_if_unreferenced(false, 0),
        (dismounted, VolumeRetirement::Retained)
    );
    assert_eq!(
        dismounted.retire_if_unreferenced(true, 1),
        (dismounted, VolumeRetirement::Retained)
    );
    assert_eq!(
        dismounted.retire_if_unreferenced(true, 0),
        (MountedVolumeState::Retiring, VolumeRetirement::Start)
    );
    assert_eq!(
        MountedVolumeState::Mounted.retire_if_unreferenced(true, 0),
        (MountedVolumeState::Mounted, VolumeRetirement::Retained)
    );
}

/// # Panics
///
/// Panics if an extended extent changes access rights or uncertain write progress is lost.
#[test]
fn raw_handle_bounds_do_not_grant_access_or_restore_consumed_write_authority() {
    let mut handle = OpenedVolumeHandle::new(RawVolumeAccess::Read);
    assert_eq!(
        handle.raw_authority(),
        (RawVolumeAccess::Read, RawExtentPolicy::FilesystemExtent)
    );
    handle.allow_partition_extent();
    assert_eq!(
        handle.raw_authority(),
        (RawVolumeAccess::Read, RawExtentPolicy::PartitionExtent)
    );
    assert_eq!(
        handle.raw_access.require(RawVolumeOperationKind::Read),
        Ok(())
    );
    assert_eq!(
        handle.raw_access.require(RawVolumeOperationKind::Write),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        RawVolumeAccess::MetadataOnly.require(RawVolumeOperationKind::Read),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        RawVolumeAccess::Write.require(RawVolumeOperationKind::Write),
        Ok(())
    );
    assert_eq!(
        RawVolumeAccess::ReadWrite.require(RawVolumeOperationKind::Read),
        Ok(())
    );
    assert_eq!(
        RawVolumeAccess::ReadWrite.require(RawVolumeOperationKind::Write),
        Ok(())
    );
    handle.mark_raw_write_uncertain(512);
    handle.allow_partition_extent();
    handle.mark_raw_write_uncertain(0);
    assert_eq!(
        handle.raw_write_outcome(),
        RawWriteOutcome::Uncertain { completed: 512 }
    );
    assert_eq!(
        DriverError::RawOutcomeUncertain.ntstatus(),
        wdk_sys::STATUS_DEVICE_DATA_ERROR
    );
}

/// # Panics
///
/// Panics if raw I/O can cross its selected extent, ignore sector alignment, or overflow.
#[test]
fn raw_transfer_checks_sector_geometry_selected_extent_and_checked_offsets() {
    let filesystem = RawVolumeIoPermit {
        bound: DeviceLength::from_bytes(4096),
        sector_size: 512,
    };
    let partition = RawVolumeIoPermit {
        bound: DeviceLength::from_bytes(8192),
        sector_size: 512,
    };
    assert_eq!(
        filesystem.validate_transfer(FileOffset::from_bytes(4096), 0, 0),
        Ok(ByteOffset::new(4096))
    );
    assert_eq!(
        filesystem.validate_transfer(FileOffset::from_bytes(4608), 0, 0),
        Err(DriverError::InvalidParameter)
    );
    assert_eq!(
        filesystem.validate_transfer(FileOffset::from_bytes(3584), 512, 4096),
        Ok(ByteOffset::new(3584))
    );
    assert_eq!(
        filesystem.validate_transfer(FileOffset::from_bytes(4096), 512, 4096),
        Err(DriverError::InvalidParameter)
    );
    assert_eq!(
        partition.validate_transfer(FileOffset::from_bytes(4096), 512, 4096),
        Ok(ByteOffset::new(4096))
    );
    assert_eq!(
        partition.validate_transfer(FileOffset::from_bytes(8192), 512, 4096),
        Err(DriverError::InvalidParameter)
    );
    for (offset, length, address) in [
        (1, 512, 4096),
        (0, 511, 4096),
        (0, 512, 4097),
        (u64::MAX - 511, 512, 4096),
    ] {
        assert_eq!(
            partition.validate_transfer(FileOffset::from_bytes(offset), length, address),
            Err(DriverError::InvalidParameter)
        );
    }
    let invalid_geometry = RawVolumeIoPermit {
        bound: DeviceLength::from_bytes(8192),
        sector_size: 0,
    };
    assert_eq!(
        invalid_geometry.validate_transfer(FileOffset::from_bytes(0), 512, 4096),
        Err(DriverError::InvalidParameter)
    );
}

/// Runs one decoder against a FILE_OBJECT whose lifetime is owned by an active test IRP.
/// # Errors
///
/// Returns an error when the test IRP boundary or `operation` rejects the FILE_OBJECT.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn with_active_file_object<R>(
    file: &mut wdk_sys::FILE_OBJECT,
    operation: impl for<'view> FnOnce(ActiveFileObject<'view>) -> Result<R, DriverError>,
) -> Result<R, DriverError> {
    let mut device = wdk_sys::DEVICE_OBJECT::default();
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
    let mut received = unsafe {
        // SAFETY: Both stack-local fixtures remain live through the active operation.
        ReceivedIrp::decode(
            core::ptr::from_mut(&mut device),
            core::ptr::from_mut(&mut irp),
        )?
    };
    received.with_active(|active| operation(active.current_stack()?.file_object()?))
}

/// Builds an isolated FCB for tests that exercise only immutable data-plane fields.
fn test_file_control_block(
    volume: NonNull<VolumeControlBlock>,
    node: NodeId,
) -> Pin<Box<FileControlBlock>> {
    let fcb = crate::memory::boxed_try_with(|| {
        FileControlBlock::try_new_staged(
            volume,
            NonNull::<FileControlBlockLedger>::dangling(),
            super::StagedNodeStreamMetadata {
                node,
                sizes: crate::kernel::stream::StreamSizes::EMPTY,
            },
            crate::kernel::operational_trace::OperationalTrace::host_test(),
        )
    })
    .unwrap_or_else(|_| {
        KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    });
    let fcb = Box::into_pin(fcb);
    fcb.as_ref().bind_stream_owner().unwrap_or_else(|_| {
        KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
    });
    fcb
}

/// # Panics
///
/// Panics when a device extension discriminant decodes to the wrong teardown owner.
#[test]
fn driver_device_kinds_select_exact_teardown_owners() {
    assert_eq!(
        DriverDeviceKind::decode(DeviceExtensionKind::CONTROL),
        Ok(DriverDeviceKind::Control)
    );
    assert_eq!(
        DriverDeviceKind::decode(DeviceExtensionKind::MOUNTED_VOLUME),
        Ok(DriverDeviceKind::MountedVolume)
    );
    assert_eq!(
        DriverDeviceKind::decode(DeviceExtensionKind { value: u8::MAX }),
        Err(DriverError::InternalInvariantViolation)
    );
}

/// # Panics
///
/// Panics when shutdown-registration failure stops surfacing as an allocation failure.
#[test]
fn shutdown_registration_status_maps_success_and_failure() {
    assert_eq!(
        shutdown_registration_status(wdk_sys::STATUS_SUCCESS),
        Ok(())
    );
    assert_eq!(
        shutdown_registration_status(wdk_sys::STATUS_INSUFFICIENT_RESOURCES),
        Err(DriverError::InsufficientResources)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn kernel_device_decodes_transfer_alignment_requirement() {
    let mut device = wdk_sys::DEVICE_OBJECT {
        AlignmentRequirement: wdk_sys::FILE_512_BYTE_ALIGNMENT,
        ..wdk_sys::DEVICE_OBJECT::default()
    };
    let device = unsafe {
        // SAFETY: The stack-local device remains live throughout this test.
        KernelDevice::from_raw(core::ptr::addr_of_mut!(device))
    };
    assert!(device.is_some());
    let Some(device) = device else {
        return;
    };

    let alignment = device.transfer_buffer_alignment();
    assert!(alignment.is_ok());
    if let Ok(alignment) = alignment {
        assert_eq!(alignment.as_mask(), wdk_sys::FILE_512_BYTE_ALIGNMENT);
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn no_intermediate_transfer_validates_range_and_buffer_alignment() {
    let buffer_alignment =
        TransferBufferAlignment::from_requirement_mask(wdk_sys::FILE_QUAD_ALIGNMENT);
    assert!(buffer_alignment.is_ok());
    let Ok(buffer_alignment) = buffer_alignment else {
        return;
    };
    let mode = DataTransferMode::Direct(NoIntermediateTransfer {
        sector_size: TransferSectorSize::WINDOWS_REPORTED,
        buffer_alignment,
    });

    assert_eq!(mode.validate_range(512, 1024), Ok(()));
    assert_eq!(mode.validate_position(1024), Ok(()));
    assert_eq!(
        mode.validate_range(1, 1024),
        Err(DriverError::InvalidParameter)
    );
    assert_eq!(
        mode.validate_position(1),
        Err(DriverError::InvalidParameter)
    );
    assert_eq!(
        mode.validate_range(512, 1),
        Err(DriverError::InvalidParameter)
    );

    let mut bytes = [0_u8; 32];
    let base = bytes.as_mut_ptr().addr();
    let aligned_delta = (8 - (base & 7)) & 7;
    let aligned_ptr = unsafe {
        // SAFETY: `aligned_delta` is at most 7 and the local buffer has 32 bytes.
        bytes.as_mut_ptr().add(aligned_delta)
    };
    let aligned = NonNull::new(aligned_ptr);
    assert!(aligned.is_some());
    let Some(aligned) = aligned else {
        return;
    };
    let misaligned_ptr = unsafe {
        // SAFETY: `aligned_delta + 1` is at most 8 and the local buffer has 32 bytes.
        bytes.as_mut_ptr().add(aligned_delta + 1)
    };
    let misaligned = NonNull::new(misaligned_ptr);
    assert!(misaligned.is_some());
    let Some(misaligned) = misaligned else {
        return;
    };

    assert_eq!(mode.validate_buffer(aligned), Ok(()));
    assert_eq!(
        mode.validate_buffer(misaligned),
        Err(DriverError::InvalidParameter)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn kernel_file_object_rejects_null_raw_pointer() {
    assert_eq!(
        unsafe {
            // SAFETY: Null has no liveness obligation and is rejected before use.
            KernelFileObject::from_raw(core::ptr::null_mut())
        },
        None
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn unopened_object_without_contexts_is_invalid_parameter() {
    let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());

    assert_eq!(
        with_active_file_object(&mut file, |file_object| {
            OpenedObject::decode(file_object).map(|_| ())
        })
        .err(),
        Some(DriverError::InvalidParameter)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn typed_opened_directory_exposes_cursor_without_option() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    let result = with_active_file_object(&mut file, |file_object| {
        let mut directory = OpenedDirectory::decode(file_object)?;
        assert_eq!(directory.id(), DirectoryNodeId::ROOT);
        assert_eq!(directory.cursor_mut().ordinal(), 0);
        directory.cursor_mut().seek_ordinal(7);
        assert_eq!(directory.cursor_mut().ordinal(), 7);
        Ok(())
    });
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when a standard oplock FSCTL rejects a live directory stream or selects another FCB.
#[test]
#[expect(
    unsafe_code,
    reason = "the stack-local IRP, stack location, FILE_OBJECT, FCB, and CCB remain live together"
)]
fn oplock_control_accepts_the_exact_directory_stream() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let expected = NonNull::from(fcb.as_ref().get_ref());
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    let mut device = wdk_sys::DEVICE_OBJECT::default();
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: core::ptr::from_mut(&mut file),
        MinorFunction: 0,
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.FileSystemControl = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
        OutputBufferLength: 0,
        __bindgen_padding_0: 0,
        InputBufferLength: 0,
        __bindgen_padding_1: 0,
        FsControlCode: 0x0009_0240,
        Type3InputBuffer: core::ptr::null_mut(),
    };
    let mut irp = wdk_sys::IRP::default();
    irp.Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation = core::ptr::from_mut(&mut stack);
    let received = unsafe {
        // SAFETY: Every stack-local object above remains live through the decoder invocation.
        ReceivedIrp::decode(
            core::ptr::from_mut(&mut device),
            core::ptr::from_mut(&mut irp),
        )
    };
    assert!(received.is_ok());
    if let Ok(mut received) = received {
        assert_eq!(
            received.with_active(crate::request::file_info::oplock_control),
            Ok(crate::request::file_info::OplockControlTarget {
                file_control_block: expected,
                action: OplockControlAction::Grant,
            })
        );
    }
}

/// # Panics
///
/// Panics when FsRtl directory-name storage is recreated or relocated between registrations.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn opened_directory_reuses_a_stable_notification_name_descriptor() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    let result = with_active_file_object(&mut file, |file_object| {
        let mut directory = OpenedDirectory::decode(file_object)?;
        let first = directory.notification_directory_name()?;
        let second = directory.notification_directory_name();
        assert_eq!(second, Ok(first));
        let descriptor = unsafe {
            // SAFETY: The descriptor is owned by the live CCB and the test
            // has not executed its cleanup or close transition.
            first.as_ref()
        };
        assert_eq!(descriptor.Length, descriptor.MaximumLength);
        assert!(!descriptor.Buffer.is_null());
        Ok(())
    });
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when a namespace change does not preserve its synthetic parent/name boundary.
#[test]
fn directory_change_encodes_the_child_boundary_and_action() {
    let name = Ext4Name::new(b"child");
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let change = DirectoryChange::new(
        DirectoryNodeId::ROOT,
        &name,
        NodeId::Directory(DirectoryNodeId::ROOT),
        DirectoryChangeAction::Added,
    );
    assert!(change.is_ok());
    let Ok(change) = change else {
        return;
    };

    assert_eq!(
        change.completion_filter,
        wdk_sys::FILE_NOTIFY_CHANGE_DIR_NAME
    );
    assert_eq!(change.action.as_ulong(), wdk_sys::FILE_ACTION_ADDED);
    let prefix_units = DIRECTORY_NOTIFICATION_DIRECTORY_UNITS.checked_add(1);
    assert!(prefix_units.is_some());
    let Some(prefix_units) = prefix_units else {
        return;
    };
    let prefix_bytes = prefix_units.checked_mul(core::mem::size_of::<u16>());
    assert!(prefix_bytes.is_some());
    let Some(prefix_bytes) = prefix_bytes else {
        return;
    };
    assert_eq!(usize::from(change.target.name_offset_bytes), prefix_bytes);
    let target_name = change.target.unicode_string();
    assert_eq!(target_name.Buffer, change.target.units.as_ptr().cast_mut());
    assert_eq!(target_name.Length, change.target.byte_length);
}

/// # Panics
///
/// Panics when in-place hard-link replacement loses its metadata notification contract.
#[test]
fn hard_link_replacement_reports_modified_metadata_filters() {
    let name = Ext4Name::new(b"child");
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let change = DirectoryChange::hard_link_replaced(DirectoryNodeId::ROOT, &name);
    assert!(change.is_ok());
    let Ok(change) = change else {
        return;
    };
    assert_eq!(change.action.as_ulong(), wdk_sys::FILE_ACTION_MODIFIED);
    assert_ne!(
        change.completion_filter & wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES,
        0
    );
    assert_ne!(
        change.completion_filter & wdk_sys::FILE_NOTIFY_CHANGE_SECURITY,
        0
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn typed_opened_decoders_reject_wrong_node_kind() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    assert_eq!(
        with_active_file_object(&mut file, |file_object| {
            OpenedRegularFile::decode(file_object).map(|_| ())
        })
        .err(),
        Some(DriverError::Core(ext4_core::Error::WrongInodeKind))
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn reparse_point_directory_handle_rejects_directory_operations() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::ReparsePoint, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    assert_eq!(
        with_active_file_object(&mut file, |file_object| {
            OpenedDirectory::decode(file_object).map(|_| ())
        })
        .err(),
        Some(DriverError::NotSupported)
    );
}

/// # Panics
///
/// Panics when cleanup retries repeat cleanup-owned side effects.
#[test]
fn handle_lifecycle_makes_completed_cleanup_idempotent() {
    let Some(handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached) else {
        return;
    };
    assert_eq!(
        handle.begin_cleanup_admission(),
        HandleAdmissionState::CleanupDraining
    );
    assert_eq!(handle.begin_cleanup(), CleanupStart::First);
    handle.finish_cleanup();
    assert_eq!(handle.begin_cleanup(), CleanupStart::AlreadyComplete);
    assert_eq!(
        handle.admission_state(),
        HandleAdmissionState::CleanedHandle
    );
    handle.begin_close_admission(FileObjectCloseKind::Ordinary, true);
    assert_eq!(
        handle.admission_state(),
        HandleAdmissionState::ClosingHandle
    );
    assert_eq!(
        handle.close_release_plan(FileObjectCloseKind::Ordinary, true),
        CloseReleasePlan::CleanedHandle
    );
    assert_eq!(handle.admission_state(), HandleAdmissionState::ClosedHandle);
}

/// # Panics
///
/// Panics when a filter-cancelled open cannot select its one atomic release path.
#[test]
fn active_cancelled_open_selects_combined_share_and_reference_release() {
    let Some(handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached) else {
        return;
    };
    handle.begin_close_admission(FileObjectCloseKind::CancelledOpen, false);
    assert_eq!(
        handle.close_release_plan(FileObjectCloseKind::CancelledOpen, false),
        CloseReleasePlan::CancelledOpen
    );
}

/// # Panics
///
/// Panics when ordinary close before cleanup is accidentally accepted.
#[test]
fn ordinary_close_before_cleanup_has_no_release_plan() {
    assert_eq!(
        select_close_release_plan(false, FileObjectCloseKind::Ordinary),
        None
    );
    assert_eq!(
        select_close_release_plan(true, FileObjectCloseKind::Ordinary),
        Some(CloseReleasePlan::CleanedHandle)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn opened_object_preserves_data_transfer_mode() {
    let buffer_alignment =
        TransferBufferAlignment::from_requirement_mask(wdk_sys::FILE_QUAD_ALIGNMENT);
    assert!(buffer_alignment.is_ok());
    let Ok(buffer_alignment) = buffer_alignment else {
        return;
    };
    let transfer = NoIntermediateTransfer {
        sector_size: TransferSectorSize::WINDOWS_REPORTED,
        buffer_alignment,
    };
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) =
        directory_handle(OpenedNodeMode::Direct, DataTransferMode::Direct(transfer))
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    let result = with_active_file_object(&mut file, |file_object| {
        let opened = OpenedObject::decode(file_object)?;
        assert_eq!(
            opened.data_transfer_mode(),
            DataTransferMode::Direct(transfer)
        );
        Ok(())
    });
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when synchronous FILE_OBJECT position transitions are inconsistent.
#[test]
fn synchronous_opened_object_reads_sets_and_advances_position() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
    file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: 11 };
    let result = with_active_file_object(&mut file, |file_object| {
        let mut opened = OpenedObject::decode(file_object)?;
        assert_eq!(
            opened.current_file_position(),
            Ok(FileOffset::from_bytes(11))
        );
        assert_eq!(
            opened.set_current_file_position(FileOffset::from_bytes(32)),
            Ok(())
        );
        assert_eq!(
            opened
                .update_current_file_position(DataIoKind::Handle, FileOffset::from_bytes(100), 0,),
            Ok(())
        );
        assert_eq!(
            opened.current_file_position(),
            Ok(FileOffset::from_bytes(100))
        );
        assert_eq!(
            opened.update_current_file_position(
                DataIoKind::Handle,
                FileOffset::from_bytes(100),
                23,
            ),
            Ok(())
        );
        assert_eq!(
            opened.current_file_position(),
            Ok(FileOffset::from_bytes(123))
        );
        Ok(())
    });
    assert_eq!(result, Ok(()));
}

/// # Panics
///
/// Panics when the regular-file CCB variant loses its create-time write authority.
#[test]
fn regular_file_handle_retains_write_authority() {
    for write_access in [
        RegularFileWriteAccess::Denied,
        RegularFileWriteAccess::AppendOnly,
        RegularFileWriteAccess::Positional,
    ] {
        let handle = OpenedHandle {
            state: super::OpenedHandleState::new(
                OpenedNodeMode::Direct,
                OpenedLocation::Root,
                retained_handle_deletion(),
                DataTransferMode::Cached,
            ),
            kind: super::OpenedHandleKind::File { write_access },
        };
        assert_eq!(handle.regular_file_write_access(), Some(write_access));
    }
}

/// # Panics
///
/// Panics when asynchronous or paging I/O changes the current-position field.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn asynchronous_and_paging_io_do_not_advance_position() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: 7 };
    let asynchronous = with_active_file_object(&mut file, |file_object| {
        let mut opened = OpenedObject::decode(file_object)?;
        assert_eq!(
            opened.current_file_position(),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            opened.set_current_file_position(FileOffset::from_bytes(9)),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            opened.update_current_file_position(
                DataIoKind::Handle,
                FileOffset::from_bytes(100),
                23,
            ),
            Ok(())
        );
        Ok(())
    });
    assert_eq!(asynchronous, Ok(()));
    file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
    let paging = with_active_file_object(&mut file, |file_object| {
        let mut opened = OpenedObject::decode(file_object)?;
        assert_eq!(
            opened.update_current_file_position(
                DataIoKind::Paging,
                FileOffset::from_bytes(100),
                23,
            ),
            Ok(())
        );
        Ok(())
    });
    assert_eq!(paging, Ok(()));
    let position = unsafe {
        // SAFETY: Tests consistently use the QuadPart LARGE_INTEGER arm.
        file.CurrentByteOffset.QuadPart
    };
    assert_eq!(position, 7);
}

/// # Panics
///
/// Panics when invalid current positions or lock ranges enter the signed Windows domain.
#[test]
fn file_position_and_native_lock_range_reject_signed_overflow() {
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let fcb = test_file_control_block(volume, NodeId::Directory(DirectoryNodeId::ROOT));
    let Some(mut handle) = directory_handle(OpenedNodeMode::Direct, DataTransferMode::Cached)
    else {
        return;
    };
    let mut file = file_object_with_contexts(
        fcb.stream_header().as_ptr(),
        core::ptr::addr_of_mut!(handle).cast(),
    );
    file.Flags = wdk_sys::FO_SYNCHRONOUS_IO;
    file.CurrentByteOffset = wdk_sys::LARGE_INTEGER { QuadPart: -1 };
    let result = with_active_file_object(&mut file, |file_object| {
        let mut opened = OpenedObject::decode(file_object)?;
        assert_eq!(
            opened.current_file_position(),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            opened.set_current_file_position(FileOffset::from_bytes(u64::MAX)),
            Err(DriverError::InvalidParameter)
        );
        Ok(())
    });
    assert_eq!(result, Ok(()));
    assert_eq!(
        NativeFileByteRange::new(FileOffset::from_bytes(i64::MAX.unsigned_abs()), 1).err(),
        Some(DriverError::InvalidParameter)
    );
    assert!(NativeFileByteRange::new(FileOffset::from_bytes(4096), 512).is_ok());
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn uninitialized_file_object_rejects_existing_contexts() {
    let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());
    assert!(
        with_active_file_object(&mut file, |file_object| {
            UninitializedFileObject::decode(file_object).map(|_| ())
        })
        .is_ok()
    );

    let mut file = file_object_with_contexts(
        NonNull::<FileControlBlock>::dangling().as_ptr().cast(),
        core::ptr::null_mut(),
    );
    assert_eq!(
        with_active_file_object(&mut file, |file_object| {
            UninitializedFileObject::decode(file_object).map(|_| ())
        }),
        Err(DriverError::InvalidParameter)
    );

    let mut file = file_object_with_contexts(
        core::ptr::null_mut(),
        NonNull::<super::OpenedHandle>::dangling().as_ptr().cast(),
    );
    assert_eq!(
        with_active_file_object(&mut file, |file_object| {
            UninitializedFileObject::decode(file_object).map(|_| ())
        }),
        Err(DriverError::InvalidParameter)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn file_control_block_reference_count_overflow_is_typed() {
    let mut state = FileControlBlockOpenState::new();
    state.lifetime = StreamLifetimeState::OpenHandles {
        handles: NonZeroU32::MAX,
        deferred_leases: 0,
    };

    assert_eq!(
        state.next_file_object_reference(),
        Err(DriverError::TooManyOpenReferences)
    );
    assert_eq!(
        state.lifetime,
        StreamLifetimeState::OpenHandles {
            handles: NonZeroU32::MAX,
            deferred_leases: 0,
        }
    );
}

/// # Panics
///
/// Panics when the last handle can reclaim a still-cached stream or a drained stream leaks.
#[test]
fn stream_lifetime_separates_handles_native_residency_and_deferred_leases() {
    let open = StreamLifetimeState::OpenHandles {
        handles: NonZeroU32::MIN,
        deferred_leases: 0,
    };
    let resident = open.without_handle(true);
    assert_eq!(
        resident,
        StreamLifetimeState::NativeResident {
            deferred_leases: 0,
            recheck: NativeResidencyRecheck::Waiting,
        }
    );
    assert!(resident.native_residency_recheck_pending());
    let (due, changed) = resident.with_due_native_residency_recheck();
    assert!(changed);
    assert_eq!(
        due,
        StreamLifetimeState::NativeResident {
            deferred_leases: 0,
            recheck: NativeResidencyRecheck::Due,
        }
    );
    let (rechecking, acquired) = due.with_native_residency_recheck_lease();
    assert!(acquired);
    assert_eq!(
        rechecking,
        StreamLifetimeState::NativeResident {
            deferred_leases: 1,
            recheck: NativeResidencyRecheck::Waiting,
        }
    );
    assert_eq!(
        rechecking.without_deferred_lease(false),
        StreamLifetimeState::Reclaimable
    );
    let reopened = resident.with_additional_handle();
    assert_eq!(reopened, Ok(open));
    assert_eq!(open.without_handle(false), StreamLifetimeState::Reclaimable);

    let leased = open.with_additional_deferred_lease();
    assert!(leased.is_ok());
    if let Ok(leased) = leased {
        let without_handle = leased.without_handle(false);
        assert_eq!(
            without_handle,
            StreamLifetimeState::DeferredOnly {
                deferred_leases: NonZeroU32::MIN,
            }
        );
        assert_eq!(
            without_handle.without_deferred_lease(false),
            StreamLifetimeState::Reclaimable
        );
        assert_eq!(
            without_handle.without_deferred_lease(true),
            StreamLifetimeState::NativeResident {
                deferred_leases: 0,
                recheck: NativeResidencyRecheck::Waiting,
            }
        );
    }
}

/// # Errors
///
/// Returns a fixture allocation or native stream-header failure.
/// # Panics
///
/// Panics if volume-lock cache preparation omits the stream or publishes completion before the
/// selected native drain returns successfully.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture construction returns errors while assertions verify the cache-drain contract"
)]
fn volume_lock_cache_drain_retains_every_stream_until_worker_completion() -> Result<(), DriverError>
{
    let mut ledger = FileControlBlockLedger::try_new()?;
    let stream = super::StagedNodeStreamMetadata {
        node: NodeId::Directory(DirectoryNodeId::ROOT),
        sizes: crate::kernel::stream::StreamSizes::EMPTY,
    };
    let fcb = ledger.staged_file_control_block(
        NonNull::dangling(),
        stream,
        crate::kernel::operational_trace::OperationalTrace::host_test(),
    )?;
    let fcb_pointer = NonNull::from(fcb.as_ref().get_ref());
    ledger
        .table
        .get_mut()
        .try_push_owned(fcb)
        .map_err(|failure| failure.into_parts().0)?;

    let mut drain = ledger.prepare_volume_lock_cache_drain()?;
    let lease = drain
        .next()
        .ok_or(DriverError::InternalInvariantViolation)?;
    assert!(matches!(
        drain.into_completed(),
        Err(DriverError::InternalInvariantViolation)
    ));
    drop(lease);

    let mut drain = ledger.prepare_volume_lock_cache_drain()?;
    let lease = drain
        .next()
        .ok_or(DriverError::InternalInvariantViolation)?;
    let completed = lease.execute()?;
    drain.record_completion(completed)?;
    let completed = drain.into_completed()?;
    assert_eq!(ledger.finish_volume_lock_cache_drain(completed), Ok(()));

    ledger.close(fcb_pointer);
    assert!(ledger.is_empty());
    Ok(())
}

/// # Errors
///
/// Returns a fixture allocation or native stream-header error.
/// # Panics
///
/// Panics if paging admission consults a CCB or accepts a non-file stream.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture failures use Result; assertions verify the paging stream boundary"
)]
fn paging_stream_admission_uses_shared_fcb_identity_without_a_ccb() -> Result<(), DriverError> {
    let mut ledger = FileControlBlockLedger::try_new()?;
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let stream = super::StagedNodeStreamMetadata {
        node: NodeId::Directory(DirectoryNodeId::ROOT),
        sizes: crate::kernel::stream::StreamSizes::EMPTY,
    };
    let fcb = ledger.staged_file_control_block(
        volume,
        stream,
        crate::kernel::operational_trace::OperationalTrace::host_test(),
    )?;
    let fcb_pointer = NonNull::from(fcb.as_ref().get_ref());
    let header = fcb.stream_header().as_ptr();
    ledger
        .table
        .get_mut()
        .try_push_owned(fcb)
        .map_err(|failure| failure.into_parts().0)?;
    let mut file_object = file_object_with_contexts(header, core::ptr::null_mut());

    let result = with_active_file_object(&mut file_object, |active| {
        ledger.acquire_paging_stream_lease(active, volume)
    });
    assert!(matches!(
        result,
        Err(DriverError::Core(ext4_core::Error::WrongInodeKind))
    ));
    ledger.close(fcb_pointer);
    assert!(ledger.is_empty());
    Ok(())
}

/// # Errors
///
/// Returns a fixture allocation or native stream-header error.
/// # Panics
///
/// Panics if an oplock continuation fails to retain its FCB after the last handle closes.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture failures use Result; assertions verify deferred oplock stream residency"
)]
fn oplock_stream_lease_retains_fcb_until_continuation_releases() -> Result<(), DriverError> {
    let mut ledger = FileControlBlockLedger::try_new()?;
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let stream = super::StagedNodeStreamMetadata {
        node: NodeId::Directory(DirectoryNodeId::ROOT),
        sizes: crate::kernel::stream::StreamSizes::EMPTY,
    };
    let fcb = ledger.staged_file_control_block(
        volume,
        stream,
        crate::kernel::operational_trace::OperationalTrace::host_test(),
    )?;
    let fcb_pointer = NonNull::from(fcb.as_ref().get_ref());
    let header = fcb.stream_header().as_ptr();
    ledger
        .table
        .get_mut()
        .try_push_owned(fcb)
        .map_err(|failure| failure.into_parts().0)?;
    let mut file_object = file_object_with_contexts(header, core::ptr::null_mut());
    let Some(retained_fcb) = ledger.table.get_mut().iter().next() else {
        return Err(DriverError::InternalInvariantViolation);
    };
    file_object.SectionObjectPointer = retained_fcb.stream_section_objects()?.as_ptr();

    let lease = with_active_file_object(&mut file_object, |active| {
        ledger.acquire_oplock_stream_lease(active, volume)
    })?;
    assert!(lease.identifies(fcb_pointer));
    ledger.close(fcb_pointer);
    assert!(!ledger.is_empty());
    drop(lease);
    assert!(ledger.is_empty());
    Ok(())
}

/// # Errors
///
/// Returns a fixture allocation, stream-header, or finite lease failure.
/// # Panics
///
/// Panics if FsRtl check completion releases the separate mutation grant barrier.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture failures use Result; assertions verify atomic oplock mutation admission"
)]
fn oplock_mutation_pair_blocks_grants_until_mutation_release() -> Result<(), DriverError> {
    let mut ledger = FileControlBlockLedger::try_new()?;
    let volume = NonNull::<VolumeControlBlock>::dangling();
    let stream = super::StagedNodeStreamMetadata {
        node: NodeId::Directory(DirectoryNodeId::ROOT),
        sizes: crate::kernel::stream::StreamSizes::EMPTY,
    };
    let fcb = ledger.staged_file_control_block(
        volume,
        stream,
        crate::kernel::operational_trace::OperationalTrace::host_test(),
    )?;
    let fcb_pointer = NonNull::from(fcb.as_ref().get_ref());
    let header = fcb.stream_header().as_ptr();
    ledger
        .table
        .get_mut()
        .try_push_owned(fcb)
        .map_err(|failure| failure.into_parts().0)?;
    let mut file_object = file_object_with_contexts(header, core::ptr::null_mut());
    let Some(retained_fcb) = ledger.table.get_mut().iter().next() else {
        return Err(DriverError::InternalInvariantViolation);
    };
    file_object.SectionObjectPointer = retained_fcb.stream_section_objects()?.as_ptr();

    let (mutation, check) = with_active_file_object(&mut file_object, |active| {
        ledger.acquire_oplock_mutation(active, volume)
    })?;
    assert!(!ledger.oplock_grant_available(fcb_pointer));
    drop(check);
    assert!(!ledger.oplock_grant_available(fcb_pointer));
    ledger.close(fcb_pointer);
    assert!(ledger.table.get_mut().is_empty());
    assert!(!ledger.is_empty());

    let reopened = ledger.staged_file_control_block(
        volume,
        stream,
        crate::kernel::operational_trace::OperationalTrace::host_test(),
    )?;
    let reopened_pointer = NonNull::from(reopened.as_ref().get_ref());
    ledger
        .table
        .get_mut()
        .try_push_owned(reopened)
        .map_err(|failure| failure.into_parts().0)?;
    assert!(!ledger.oplock_grant_available(reopened_pointer));
    drop(mutation);
    assert!(ledger.oplock_grant_available(reopened_pointer));
    ledger.close(reopened_pointer);
    assert!(ledger.is_empty());
    Ok(())
}

/// # Errors
///
/// Returns a fixture allocation, native stream-header, or finite lease failure.
/// # Panics
///
/// Panics if parent reservation depends on FCB residency or retains the wrong resident stream.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture failures use Result; assertions verify node-scoped parent oplock authority"
)]
fn parent_oplock_mutation_spans_zero_fcb_residency() -> Result<(), DriverError> {
    let mut ledger = FileControlBlockLedger::try_new()?;
    let (absent_mutation, absent_stream) =
        ledger.acquire_parent_oplock_mutation(DirectoryNodeId::ROOT)?;
    assert!(absent_stream.is_none());
    assert!(!ledger.is_empty());
    let stream = super::StagedNodeStreamMetadata {
        node: NodeId::Directory(DirectoryNodeId::ROOT),
        sizes: crate::kernel::stream::StreamSizes::EMPTY,
    };
    let fcb = ledger.staged_file_control_block(
        NonNull::dangling(),
        stream,
        crate::kernel::operational_trace::OperationalTrace::host_test(),
    )?;
    let fcb_pointer = NonNull::from(fcb.as_ref().get_ref());
    ledger
        .table
        .get_mut()
        .try_push_owned(fcb)
        .map_err(|failure| failure.into_parts().0)?;
    assert!(!ledger.oplock_grant_available(fcb_pointer));
    drop(absent_mutation);
    assert!(ledger.oplock_grant_available(fcb_pointer));

    let (mutation, lease) = ledger.acquire_parent_oplock_mutation(DirectoryNodeId::ROOT)?;
    let lease = lease.ok_or(DriverError::InternalInvariantViolation)?;
    assert!(lease.identifies(fcb_pointer));
    assert!(!ledger.oplock_grant_available(fcb_pointer));
    ledger.close(fcb_pointer);
    assert!(!ledger.is_empty());
    drop(lease);
    assert!(!ledger.is_empty());
    drop(mutation);
    assert!(ledger.is_empty());
    Ok(())
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn file_control_block_starts_with_empty_share_access() {
    let state = FileControlBlockOpenState::new();

    assert_eq!(state.share_access.OpenCount, 0);
    assert_eq!(state.share_access.Readers, 0);
    assert_eq!(state.share_access.Writers, 0);
    assert_eq!(state.share_access.Deleters, 0);
    assert_eq!(state.share_access.SharedRead, 0);
    assert_eq!(state.share_access.SharedWrite, 0);
    assert_eq!(state.share_access.SharedDelete, 0);
}

/// # Panics
///
/// Panics when ordinary namespace replacement can unlink an actively referenced inode.
#[test]
fn namespace_replacement_requires_no_active_handles() {
    let mut state = FileControlBlockOpenState::new();
    assert_eq!(state.ensure_namespace_replaceable(), Ok(()));

    state.share_access.OpenCount = 2;
    state.share_access.SharedDelete = 2;
    assert_eq!(
        state.ensure_namespace_replaceable(),
        Err(DriverError::ShareAccessConflict)
    );

    state.share_access.OpenCount = 0;
    assert_eq!(state.ensure_namespace_replaceable(), Ok(()));
}

/// # Panics
///
/// Panics when the shared FCB deletion state permits reopen or deletes before final cleanup.
#[test]
fn file_deletion_state_is_shared_and_waits_for_final_active_cleanup() {
    let name = Ext4Name::new(b"pending");
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let location = OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &name);
    assert!(location.is_ok());
    let Ok(location) = location else {
        return;
    };
    let pending = super::PendingFileDeletion::try_from_disposition(&location);
    assert!(pending.is_ok());
    let Ok(pending) = pending else {
        return;
    };
    let target = pending.target();
    let mut state = FileControlBlockOpenState::new();

    assert_eq!(state.deletion.ensure_openable(), Ok(()));
    assert!(!state.delete_pending());
    assert!(state.set_delete_pending(pending).is_none());
    assert_eq!(
        state.deletion.ensure_openable(),
        Err(DriverError::DeletePending)
    );
    state.share_access.OpenCount = 1;
    assert_eq!(
        state.cleanup_disposition(),
        super::FileCleanupDisposition::Retained
    );
    state.share_access.OpenCount = 0;
    assert_eq!(
        state.cleanup_disposition(),
        super::FileCleanupDisposition::Delete(target)
    );

    let completed = state.complete_delete(target);
    assert_eq!(completed.target(), target);
    assert!(state.abort_cleanup_delete(target).is_none());
    assert!(state.delete_pending());
    assert_eq!(
        state.deletion.ensure_openable(),
        Err(DriverError::DeletePending)
    );
}

/// # Panics
///
/// Panics when the CCB deletion domain can represent unauthorized delete-on-close.
#[test]
fn handle_deletion_requires_delete_authority_for_delete_on_close() {
    assert_eq!(
        HandleDeletion::from_create(
            CreateDeletion::DeleteOnClose,
            DeleteAccess::Denied,
            FileAttributesWriteAccess::Denied,
        ),
        Err(DriverError::AccessDenied)
    );
    assert_eq!(
        HandleDeletion::from_create(
            CreateDeletion::DeleteOnClose,
            DeleteAccess::Granted,
            FileAttributesWriteAccess::Granted,
        ),
        Ok(HandleDeletion::DeleteOnClose {
            file_attributes_write_access: FileAttributesWriteAccess::Granted,
        })
    );
    assert_eq!(
        HandleDeletion::from_create(
            CreateDeletion::Retain,
            DeleteAccess::Denied,
            FileAttributesWriteAccess::Granted,
        ),
        Ok(HandleDeletion::Retain {
            delete_access: DeleteAccess::Denied,
            file_attributes_write_access: FileAttributesWriteAccess::Granted,
        })
    );
}

/// # Panics
///
/// Panics when cancellation or non-directory-entry deletion targets become ambiguous.
#[test]
fn pending_file_deletion_cancels_only_before_commit_and_requires_a_link() {
    assert_eq!(
        super::PendingFileDeletion::try_from_disposition(&OpenedLocation::Root),
        Err(DriverError::CannotDelete)
    );
    assert_eq!(
        super::PendingFileDeletion::try_from_disposition(&OpenedLocation::FileReference),
        Err(DriverError::CannotDelete)
    );

    let name = Ext4Name::new(b"cancel");
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let location = OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &name);
    assert!(location.is_ok());
    let Ok(location) = location else {
        return;
    };
    let pending = super::PendingFileDeletion::try_from_disposition(&location);
    assert!(pending.is_ok());
    let Ok(pending) = pending else {
        return;
    };
    let mut state = FileControlBlockOpenState::new();
    assert!(state.set_delete_pending(pending).is_none());
    assert!(state.clear_delete_pending().is_some());
    assert_eq!(state.deletion.ensure_openable(), Ok(()));
    assert!(!state.delete_pending());
}

/// # Panics
///
/// Panics when a mandatory create-time delete target can be cancelled or replaced by a normal
/// disposition request.
#[test]
fn delete_on_close_pending_cannot_be_cancelled_or_replaced() {
    let mandatory_name = Ext4Name::new(b"mandatory");
    assert!(mandatory_name.is_ok());
    let Ok(mandatory_name) = mandatory_name else {
        return;
    };
    let mandatory_location =
        OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &mandatory_name);
    assert!(mandatory_location.is_ok());
    let Ok(mandatory_location) = mandatory_location else {
        return;
    };
    let mandatory = super::PendingFileDeletion::try_from_delete_on_close(&mandatory_location);
    assert!(mandatory.is_ok());
    let Ok(mandatory) = mandatory else {
        return;
    };
    let mandatory_target = mandatory.target();

    let replacement_name = Ext4Name::new(b"replacement");
    assert!(replacement_name.is_ok());
    let Ok(replacement_name) = replacement_name else {
        return;
    };
    let replacement_location =
        OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &replacement_name);
    assert!(replacement_location.is_ok());
    let Ok(replacement_location) = replacement_location else {
        return;
    };
    let replacement = super::PendingFileDeletion::try_from_disposition(&replacement_location);
    assert!(replacement.is_ok());
    let Ok(replacement) = replacement else {
        return;
    };
    let replacement_target = replacement.target();

    let mut state = FileControlBlockOpenState::new();
    assert!(state.set_delete_pending(mandatory).is_none());
    assert!(state.clear_delete_pending().is_none());
    assert_eq!(
        state.cleanup_disposition(),
        super::FileCleanupDisposition::Delete(mandatory_target)
    );
    let displaced = state.set_delete_pending(replacement);
    assert!(displaced.is_some());
    let Some(displaced) = displaced else {
        return;
    };
    assert_eq!(displaced.target(), replacement_target);
    assert_eq!(
        state.cleanup_disposition(),
        super::FileCleanupDisposition::Delete(mandatory_target)
    );
}

/// # Panics
///
/// Panics when a pre-effect cleanup failure cannot terminate mandatory deletion ownership without
/// weakening ordinary disposition cancellation rules.
#[test]
fn final_cleanup_failure_can_abort_exact_delete_on_close_target() {
    let name = Ext4Name::new(b"mapped-delete-on-close");
    assert!(name.is_ok());
    let Ok(name) = name else {
        return;
    };
    let location = OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &name);
    assert!(location.is_ok());
    let Ok(location) = location else {
        return;
    };
    let pending = super::PendingFileDeletion::try_from_delete_on_close(&location);
    assert!(pending.is_ok());
    let Ok(pending) = pending else {
        return;
    };
    let target = pending.target();
    let mut state = FileControlBlockOpenState::new();

    assert!(state.set_delete_pending(pending).is_none());
    assert!(state.clear_delete_pending().is_none());
    let aborted = state.abort_cleanup_delete(target);
    assert!(aborted.is_some());
    assert_eq!(state.deletion.ensure_openable(), Ok(()));
    assert!(!state.delete_pending());
}
