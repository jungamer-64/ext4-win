use alloc::boxed::Box;
use core::ffi::c_void;

use ext4_core::{FileOffset, WindowsNameMatch};
use wdk_sys::{STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};

use super::{
    ActiveFileObject, CREATE_DISPOSITION_SHIFT, CreateAccessCheck, CreateAction, CreateCompletion,
    CreateDisposition, CreateNameInterpretation, CreateReparsePointMode,
    CreateSymlinkReparseBuffer, CreateSynchronizationMode, CreateTargetRequirement,
    CreateTargetSelection, CreateTransferBuffering, CurrentIrpStackLocation, DataIoKind,
    DesiredAccess, DirectoryChangeFilter, DirectoryControlMinorFunction, DirectoryCursorPosition,
    DirectoryEntryEmission, DirectoryInformationClass, DirectoryNotifyInformationClass,
    DirectoryWatchScope, DispatchTarget, EaCursorPosition, EaEntryEmission, EaEntryIndex,
    FILE_OPEN_DISPOSITION, FILE_OPEN_IF_DISPOSITION, FILE_OVERWRITE_DISPOSITION,
    FILE_OVERWRITE_IF_DISPOSITION, FILE_SHARE_ACCESS_MASK, FILE_SUPERSEDE_DISPOSITION,
    FileSystemControlMinorFunction, FsControlCode, InformationLength, IrpBufferLength,
    IrpCompletion, KernelIrp, OplockControlAction, OplockCreatePolicy, OwnedIrp,
    QueryFileInformationClass, QueryVolumeInformationClass, ReadStartingPoint, ReceivedIrp,
    RegularFileWriteAccess, SetFileInformationClass, SetVolumeInformationClass, ShareAccess,
    WriteStartingPoint,
};
use crate::kernel::status::DriverError;
use crate::security_descriptor::SecurityComponentSelection;
use crate::state::{KernelDevice, KernelFileObject, WriteCommitment};

/// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
const MOUNT_VOLUME_MINOR: wdk_sys::UCHAR = 1;

/// Binds one live stack-local device fixture to the raw WDK boundary.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn kernel_device_fixture(device: &mut wdk_sys::DEVICE_OBJECT) -> Option<KernelDevice> {
    unsafe {
        // SAFETY: The caller's mutable fixture outlives every returned use in these tests.
        KernelDevice::from_raw(core::ptr::from_mut(device))
    }
}

/// Binds one live stack-local IRP fixture to the private completion boundary.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn kernel_irp_fixture(irp: &mut wdk_sys::IRP) -> Option<KernelIrp> {
    unsafe {
        // SAFETY: The caller's mutable fixture outlives every returned use in these tests.
        KernelIrp::from_raw(core::ptr::from_mut(irp))
    }
}

/// Creates a received IRP from live stack-local device and IRP fixtures.
/// # Errors
///
/// Returns invalid parameter when either fixture cannot cross the raw dispatch boundary.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn received_irp_fixture(
    device: &mut wdk_sys::DEVICE_OBJECT,
    irp: &mut wdk_sys::IRP,
) -> Result<ReceivedIrp, DriverError> {
    unsafe {
        // SAFETY: Both mutable fixtures remain live for the returned owner in the caller.
        ReceivedIrp::decode(core::ptr::from_mut(device), core::ptr::from_mut(irp))
    }
}

/// Creates test completion ownership from live stack-local fixtures.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn owned_irp_fixture(device: KernelDevice, irp: &mut wdk_sys::IRP) -> Option<OwnedIrp> {
    unsafe {
        // SAFETY: The test fixture provides exclusive completion ownership until consumption.
        OwnedIrp::from_test_raw(device, core::ptr::from_mut(irp))
    }
}

use core::ptr::NonNull;

/// Reads the active IRP status union arm.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn irp_status(irp: &wdk_sys::IRP) -> wdk_sys::NTSTATUS {
    unsafe {
        // SAFETY: Tests read the status arm after initializing or writing
        // it through IRP completion helpers.
        irp.IoStatus.__bindgen_anon_1.Status
    }
}

/// Builds a lifetime-bound stack view from one live unit-test fixture.
/// # Errors
///
/// Returns an error when the fixture address is unexpectedly null.
fn current_stack_fixture(
    stack: &mut wdk_sys::IO_STACK_LOCATION,
) -> Result<CurrentIrpStackLocation<'_>, DriverError> {
    Ok(CurrentIrpStackLocation {
        stack: NonNull::from(stack),
        owner: core::marker::PhantomData,
    })
}

/// # Panics
///
/// Panics when buffered output becomes a Rust slice before the complete declared range has
/// been initialized.
#[test]
fn buffered_output_initializes_only_its_declared_range_before_borrow() {
    let mut storage = [0xA5_u8; 17];
    let address = NonNull::new(storage.as_mut_ptr());
    assert!(address.is_some());
    let Some(address) = address else {
        return;
    };
    {
        let output = super::BufferedOutput::from_active(address, 13);
        assert!(output.is_ok());
        let Ok(mut output) = output else {
            return;
        };
        assert!(output.as_mut_slice().iter().all(|byte| *byte == 0));
        output.as_mut_slice().fill(0x3C);
    }
    assert!(
        storage
            .get(..13)
            .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0x3C))
    );
    assert!(
        storage
            .get(13..)
            .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0xA5))
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
fn null_dispatch_target_is_invalid_parameter() {
    let mut device = wdk_sys::DEVICE_OBJECT::default();
    let mut irp = wdk_sys::IRP::default();
    assert_eq!(
        unsafe {
            // SAFETY: The non-null fixture IRP remains live; the null device is rejected.
            DispatchTarget::decode(core::ptr::null_mut(), core::ptr::from_mut(&mut irp))
        }
        .err()
        .map(crate::kernel::status::DriverError::ntstatus),
        Some(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        unsafe {
            // SAFETY: The non-null fixture device remains live; the null IRP is rejected.
            DispatchTarget::decode(core::ptr::from_mut(&mut device), core::ptr::null_mut())
        }
        .err()
        .map(crate::kernel::status::DriverError::ntstatus),
        Some(STATUS_INVALID_PARAMETER)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn decoded_dispatch_target_preserves_pointers() {
    let mut device = wdk_sys::DEVICE_OBJECT::default();
    let mut irp = wdk_sys::IRP::default();
    let device_pointer = core::ptr::from_mut(&mut device);
    let decoded = received_irp_fixture(&mut device, &mut irp);
    assert!(decoded.is_ok());
    if let Ok(received) = decoded {
        assert_eq!(received.device().as_ptr(), device_pointer);
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
fn irp_completion_writes_status_and_information_together() {
    let mut irp = wdk_sys::IRP::default();
    let kernel_irp = kernel_irp_fixture(&mut irp);
    assert!(kernel_irp.is_some());
    let information = InformationLength::from_usize(128);
    assert!(information.is_ok());
    if let (Some(kernel_irp), Ok(information)) = (kernel_irp, information) {
        kernel_irp.write_status_block(IrpCompletion::with_information(information));
    }

    assert_eq!(
        unsafe {
            // SAFETY: `write_status_block` just wrote the active Status union arm.
            irp.IoStatus.__bindgen_anon_1.Status
        },
        wdk_sys::STATUS_SUCCESS
    );
    assert_eq!(irp.IoStatus.Information, 128);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn failed_irp_completion_writes_zero_information() {
    let mut irp = wdk_sys::IRP::default();
    irp.IoStatus.Information = 128;
    let kernel_irp = kernel_irp_fixture(&mut irp);
    assert!(kernel_irp.is_some());
    if let Some(kernel_irp) = kernel_irp {
        kernel_irp.write_status_block(IrpCompletion::from_error(
            crate::kernel::status::DriverError::InvalidParameter,
        ));
    }

    assert_eq!(
        unsafe {
            // SAFETY: `write_status_block` just wrote the active Status union arm.
            irp.IoStatus.__bindgen_anon_1.Status
        },
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(irp.IoStatus.Information, 0);
}

/// # Panics
///
/// Panics when post-commit failure loses the committed byte count or exact status.
#[test]
fn committed_failure_preserves_information() {
    let completion = IrpCompletion::from_usize(4096);
    assert!(completion.is_ok());
    if let Ok(completion) = completion {
        let failed =
            completion.committed_failure(crate::kernel::status::DriverError::CacheManagerFailure(
                wdk_sys::STATUS_IO_DEVICE_ERROR,
            ));
        assert_eq!(failed.status(), wdk_sys::STATUS_IO_DEVICE_ERROR);
        assert_eq!(failed.information().as_ulong_ptr(), 4096);
    }
}

/// # Panics
///
/// Panics when an empty allocation can become an invalid dangling auxiliary buffer.
#[test]
fn create_reparse_buffer_rejects_empty_allocation() {
    assert_eq!(
        CreateSymlinkReparseBuffer::try_pack_exact(0, |_| Ok(0)).err(),
        Some(crate::kernel::status::DriverError::InvalidBufferSize)
    );
}

/// # Panics
///
/// Panics when a mismatched tag, declared length, or actual write length can become a sealed
/// symbolic-link completion buffer.
#[test]
fn create_symlink_reparse_buffer_seals_only_exact_matching_wire_data() {
    const VALID: [u8; 22] = [
        0x0C, 0x00, 0x00, 0xA0, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
    ];
    let invalid_tag = CreateSymlinkReparseBuffer::try_pack_exact(VALID.len(), |output| {
        crate::memory::copy_exact(output, &VALID)?;
        if let Some(tag) = output.first_mut() {
            *tag = 0;
        }
        Ok(VALID.len())
    });
    assert_eq!(
        invalid_tag.err(),
        Some(crate::kernel::status::DriverError::InternalInvariantViolation)
    );
    let invalid_declared_length =
        CreateSymlinkReparseBuffer::try_pack_exact(VALID.len(), |output| {
            crate::memory::copy_exact(output, &VALID)?;
            if let Some(length) = output.get_mut(4) {
                *length = 0;
            }
            Ok(VALID.len())
        });
    assert_eq!(
        invalid_declared_length.err(),
        Some(crate::kernel::status::DriverError::InternalInvariantViolation)
    );
    let incomplete_write = CreateSymlinkReparseBuffer::try_pack_exact(VALID.len(), |output| {
        crate::memory::copy_exact(output, &VALID)?;
        Ok(VALID.len() - 1)
    });
    assert_eq!(
        incomplete_write.err(),
        Some(crate::kernel::status::DriverError::InternalInvariantViolation)
    );
}

/// # Panics
///
/// Panics when create reparse completion does not transfer the exact allocation and publish the
/// WDK reparse status pair.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn create_reparse_completion_transfers_exact_auxiliary_buffer() {
    const EXPECTED: [u8; 22] = [
        0x0C, 0x00, 0x00, 0xA0, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
    ];

    let mut device_object = wdk_sys::DEVICE_OBJECT::default();
    let device = kernel_device_fixture(&mut device_object);
    assert!(device.is_some());
    let Some(device) = device else {
        return;
    };
    let mut irp = wdk_sys::IRP::default();
    let owned = owned_irp_fixture(device, &mut irp);
    assert!(owned.is_some());
    let Some(owned) = owned else {
        return;
    };

    let buffer = CreateSymlinkReparseBuffer::try_pack_exact(EXPECTED.len(), |output| {
        crate::memory::copy_exact(output, &EXPECTED)?;
        Ok(EXPECTED.len())
    });
    assert!(buffer.is_ok());
    let mut completion_status = None;
    if let Ok(buffer) = buffer {
        completion_status =
            Some(owned.complete_create_result(Ok(CreateCompletion::ReparseSymlink(buffer))));
    }

    let auxiliary = unsafe {
        // SAFETY: The create reparse completion selected and initialized the
        // active IRP tail overlay immediately above.
        irp.Tail.Overlay.AuxiliaryBuffer
    };
    let reclaimed = NonNull::new(auxiliary).map(|auxiliary| {
        let allocation =
            core::ptr::slice_from_raw_parts_mut(auxiliary.as_ptr().cast::<u8>(), EXPECTED.len());
        unsafe {
            // SAFETY: `complete_create_result` obtained this pointer from one
            // `Box<[u8]>` of exactly `EXPECTED.len()` bytes. Unit tests do not
            // invoke the I/O Manager, so this reconstruction is its sole owner.
            Box::from_raw(allocation)
        }
    });
    irp.Tail.Overlay.AuxiliaryBuffer = core::ptr::null_mut();

    assert_eq!(completion_status, Some(wdk_sys::STATUS_REPARSE));
    assert_eq!(irp_status(&irp), wdk_sys::STATUS_REPARSE);
    assert_eq!(
        irp.IoStatus.Information,
        wdk_sys::ULONG_PTR::from(wdk_sys::IO_REPARSE_TAG_SYMLINK)
    );
    assert_eq!(reclaimed.as_deref(), Some(EXPECTED.as_slice()));
}

/// # Panics
///
/// Panics when a successful handle create does not publish its exact Windows create action.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn create_handle_completion_publishes_exact_action() {
    for (action, expected) in [
        (CreateAction::Opened, wdk_sys::FILE_OPENED),
        (CreateAction::Created, wdk_sys::FILE_CREATED),
        (CreateAction::TargetExists, wdk_sys::FILE_EXISTS),
        (
            CreateAction::TargetDoesNotExist,
            wdk_sys::FILE_DOES_NOT_EXIST,
        ),
    ] {
        let mut device_object = wdk_sys::DEVICE_OBJECT::default();
        let device = kernel_device_fixture(&mut device_object);
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut irp = wdk_sys::IRP::default();
        let owned = owned_irp_fixture(device, &mut irp);
        assert!(owned.is_some());
        let Some(owned) = owned else {
            return;
        };

        assert_eq!(
            owned.complete_create_result(Ok(CreateCompletion::Handle(action))),
            wdk_sys::STATUS_SUCCESS
        );

        let auxiliary = unsafe {
            // SAFETY: The test reads the active tail overlay after create completion.
            irp.Tail.Overlay.AuxiliaryBuffer
        };
        assert!(auxiliary.is_null());
        assert_eq!(irp_status(&irp), wdk_sys::STATUS_SUCCESS);
        assert_eq!(irp.IoStatus.Information, wdk_sys::ULONG_PTR::from(expected));
    }
}

/// # Panics
///
/// Panics when a successful complete-if-oplocked create loses its alternate success status or
/// exact Windows create action.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn create_oplock_break_completion_preserves_status_and_action() {
    let mut device_object = wdk_sys::DEVICE_OBJECT::default();
    let device = kernel_device_fixture(&mut device_object);
    assert!(device.is_some());
    let Some(device) = device else {
        return;
    };
    let mut irp = wdk_sys::IRP::default();
    let owned = owned_irp_fixture(device, &mut irp);
    assert!(owned.is_some());
    let Some(owned) = owned else {
        return;
    };

    assert_eq!(
        owned.complete_create_result(Ok(CreateCompletion::OplockBreakInProgress(
            CreateAction::Opened,
        ))),
        wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS
    );
    let auxiliary = unsafe {
        // SAFETY: The test reads the active tail overlay after create completion.
        irp.Tail.Overlay.AuxiliaryBuffer
    };
    assert!(auxiliary.is_null());
    assert_eq!(irp_status(&irp), wdk_sys::STATUS_OPLOCK_BREAK_IN_PROGRESS);
    assert_eq!(
        irp.IoStatus.Information,
        wdk_sys::ULONG_PTR::from(wdk_sys::FILE_OPENED)
    );
}

/// # Panics
///
/// Panics when a failed create request publishes ownership into the IRP tail overlay.
#[test]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn failed_create_completion_never_publishes_auxiliary_buffer() {
    let mut device_object = wdk_sys::DEVICE_OBJECT::default();
    let device = kernel_device_fixture(&mut device_object);
    assert!(device.is_some());
    let Some(device) = device else {
        return;
    };
    let mut irp = wdk_sys::IRP::default();
    let owned = owned_irp_fixture(device, &mut irp);
    assert!(owned.is_some());
    if let Some(owned) = owned {
        assert_eq!(
            owned.complete_create_result(Err(crate::kernel::status::DriverError::InvalidParameter)),
            wdk_sys::STATUS_INVALID_PARAMETER
        );
    }

    let auxiliary = unsafe {
        // SAFETY: The test reads the active tail overlay after failed create completion.
        irp.Tail.Overlay.AuxiliaryBuffer
    };
    assert!(auxiliary.is_null());
    assert_eq!(irp_status(&irp), wdk_sys::STATUS_INVALID_PARAMETER);
    assert_eq!(irp.IoStatus.Information, 0);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn irp_buffer_length_preserves_zero_as_typed_empty() {
    let length = IrpBufferLength::from_ulong(0);
    assert!(length.is_ok());
    if let Ok(length) = length {
        assert!(length.is_empty());
        assert_eq!(length.as_usize(), 0);
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn current_stack_location_rejects_null_pointer() {
    let mut device = wdk_sys::DEVICE_OBJECT::default();
    let mut irp = wdk_sys::IRP::default();
    let mut received = received_irp_fixture(&mut device, &mut irp);
    assert!(received.is_ok());
    assert_eq!(
        received
            .as_mut()
            .map(|received| {
                received.with_active(|active| {
                    active
                        .current_stack()
                        .err()
                        .map(crate::kernel::status::DriverError::ntstatus)
                })
            })
            .ok()
            .flatten(),
        Some(STATUS_INVALID_PARAMETER)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn unsupported_filesystem_control_minor_decodes_as_unsupported() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        MinorFunction: u8::MAX,
        ..Default::default()
    };

    assert_eq!(
        current_stack_fixture(&mut stack).map(|current| current.file_system_control_minor()),
        Ok(FileSystemControlMinorFunction::Unsupported)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn unsupported_directory_control_minor_decodes_as_unsupported() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        MinorFunction: u8::MAX,
        ..Default::default()
    };

    assert_eq!(
        current_stack_fixture(&mut stack).map(|current| current.directory_control_minor()),
        Ok(DirectoryControlMinorFunction::Unsupported)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn mount_volume_stack_preserves_vpb_and_target() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let vpb = NonNull::<wdk_sys::VPB>::dangling();
    let target = NonNull::<wdk_sys::DEVICE_OBJECT>::dangling();
    stack.MinorFunction = MOUNT_VOLUME_MINOR;
    stack.Parameters.MountVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_20 {
        Vpb: vpb.as_ptr(),
        DeviceObject: target.as_ptr(),
        OutputBufferLength: 16,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current.file_system_control_minor(),
            FileSystemControlMinorFunction::MountVolume
        );
        let mount = current.mount_volume();
        assert!(mount.is_ok());
        if let Ok(mount) = mount {
            assert_eq!(mount.vpb().as_non_null(), vpb);
            assert_eq!(mount.target_device().as_ptr(), target.as_ptr());
            assert_eq!(mount.output_buffer_length().as_usize(), 16);
        }
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
fn file_system_control_stack_decodes_supported_user_control() {
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: file_object.as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.FileSystemControl = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
        OutputBufferLength: 128,
        __bindgen_padding_0: 0,
        InputBufferLength: 32,
        __bindgen_padding_1: 0,
        FsControlCode: 589_992,
        Type3InputBuffer: core::ptr::null_mut(),
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let control = current.file_system_control();
        assert!(control.is_ok());
        if let Ok(control) = control {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(control.input_buffer_length().as_usize(), 32);
            assert_eq!(control.output_buffer_length().as_usize(), 128);
            assert_eq!(control.fs_control_code(), FsControlCode::GetReparsePoint);
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn file_system_control_stack_rejects_unsupported_control_before_handler() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.FileSystemControl = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
        OutputBufferLength: 128,
        __bindgen_padding_0: 0,
        InputBufferLength: 32,
        __bindgen_padding_1: 0,
        FsControlCode: 0xFFFF_FFFF,
        Type3InputBuffer: core::ptr::null_mut(),
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .file_system_control()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_NOT_SUPPORTED)
        );
    }
}

/// # Panics
///
/// Panics when the payload-free lifecycle IOCTL loses its exact stack identity.
#[test]
fn device_control_stack_preserves_payload_shape_and_control_code() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.DeviceIoControl = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_17 {
        OutputBufferLength: 0,
        __bindgen_padding_0: 0,
        InputBufferLength: 0,
        __bindgen_padding_1: 0,
        IoControlCode: crate::lifecycle_control::PREPARE_UNLOAD_IOCTL,
        Type3InputBuffer: core::ptr::null_mut(),
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let control = current.device_control();
        assert!(control.is_ok());
        if let Ok(control) = control {
            assert!(control.is_payload_free());
            assert_eq!(
                control.io_control_code(),
                crate::lifecycle_control::PREPARE_UNLOAD_IOCTL
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn ext4win_private_fsctl_codes_decode_to_domain_variants() {
    assert_eq!(
        FsControlCode::from_raw(0x0009_2400),
        Ok(FsControlCode::AddEncryptionKey)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_2404),
        Ok(FsControlCode::RemoveEncryptionKey)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_2408),
        Ok(FsControlCode::GetEncryptionKeyStatus)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_240c),
        Ok(FsControlCode::EnableVerity)
    );
}

/// # Panics
///
/// Panics when the standard volume-control wire codes drift from the Windows ABI.
#[test]
fn standard_volume_fsctl_codes_decode_to_domain_variants() {
    assert_eq!(
        FsControlCode::from_raw(0x0009_0018),
        Ok(FsControlCode::LockVolume)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_001c),
        Ok(FsControlCode::UnlockVolume)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_0020),
        Ok(FsControlCode::DismountVolume)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_0028),
        Ok(FsControlCode::IsVolumeMounted)
    );
    assert_eq!(
        FsControlCode::from_raw(0x0009_0083),
        Ok(FsControlCode::AllowExtendedDasdIo)
    );
}

/// # Panics
///
/// Panics when request and break-continuation oplock controls can cross the wrong mutation lane.
#[test]
fn oplock_control_action_is_conservative_at_the_buffered_boundary() {
    assert_eq!(
        FsControlCode::RequestOplockLevel1.oplock_action(&[]),
        Ok(OplockControlAction::Grant)
    );
    assert_eq!(
        FsControlCode::OplockBreakNotify.oplock_action(&[]),
        Ok(OplockControlAction::BreakContinuation)
    );

    let request = [0_u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    assert_eq!(
        FsControlCode::RequestOplock.oplock_action(&request),
        Ok(OplockControlAction::Grant)
    );
    let acknowledge = [0_u8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0];
    assert_eq!(
        FsControlCode::RequestOplock.oplock_action(&acknowledge),
        Ok(OplockControlAction::BreakContinuation)
    );
    let ambiguous = [0_u8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0];
    assert_eq!(
        FsControlCode::RequestOplock.oplock_action(&ambiguous),
        Ok(OplockControlAction::Grant)
    );
    let truncated = [0_u8; 8];
    assert_eq!(
        FsControlCode::RequestOplock.oplock_action(&truncated),
        Ok(OplockControlAction::Grant)
    );
    assert_eq!(
        FsControlCode::LockVolume.oplock_action(&[]),
        Err(DriverError::InvalidDeviceRequest)
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
fn create_stack_preserves_access_share_options_and_ea_length() {
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    let desired_access = wdk_sys::FILE_READ_DATA | wdk_sys::FILE_WRITE_DATA | wdk_sys::SYNCHRONIZE;
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: desired_access,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        Flags: u8::try_from(
            wdk_sys::SL_CASE_SENSITIVE
                | wdk_sys::SL_FORCE_ACCESS_CHECK
                | wdk_sys::SL_OPEN_TARGET_DIRECTORY,
        )
        .unwrap_or(u8::MAX),
        FileObject: file_object.as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_IF_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_NON_DIRECTORY_FILE
            | wdk_sys::FILE_WRITE_THROUGH
            | wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT
            | wdk_sys::FILE_OPEN_FOR_BACKUP_INTENT,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0x20,
        ShareAccess: u16::try_from(wdk_sys::FILE_SHARE_READ | wdk_sys::FILE_SHARE_WRITE)
            .unwrap_or(u16::MAX),
        __bindgen_padding_1: 0,
        EaLength: 48,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            let parameters = create.parameters();
            assert_eq!(parameters.desired_access().as_raw(), desired_access);
            assert_eq!(parameters.disposition(), CreateDisposition::OpenIf);
            assert_eq!(
                parameters.target_requirement(),
                CreateTargetRequirement::NonDirectory
            );
            assert_eq!(parameters.write_commitment(), WriteCommitment::FlushThrough);
            assert_eq!(
                parameters.transfer_buffering(),
                CreateTransferBuffering::IntermediateAllowed
            );
            assert_eq!(
                parameters.synchronization_mode(),
                CreateSynchronizationMode::SynchronousNonAlert
            );
            assert_eq!(
                parameters.reparse_point_mode(),
                CreateReparsePointMode::ResolveFinalTarget
            );
            assert_eq!(
                parameters.name_interpretation(),
                CreateNameInterpretation::Path
            );
            assert_eq!(
                parameters.share_access().as_ulong(),
                wdk_sys::FILE_SHARE_READ | wdk_sys::FILE_SHARE_WRITE
            );
            assert_eq!(parameters.ea_length().as_usize(), 48);
            assert_eq!(parameters.name_match(), WindowsNameMatch::Exact);
            assert_eq!(parameters.access_check(), CreateAccessCheck::ForceUserMode);
            assert_eq!(
                parameters.target_selection(),
                CreateTargetSelection::ParentDirectory
            );
            assert_eq!(parameters.validate_supported_flags(), Ok(()));
        }
    }
}

/// # Panics
///
/// Panics when a special create stack flag is silently treated as an ordinary open.
#[test]
fn create_stack_rejects_unimplemented_special_flag_protocols() {
    for flag in [
        wdk_sys::SL_OPEN_PAGING_FILE,
        wdk_sys::SL_STOP_ON_SYMLINK,
        wdk_sys::SL_IGNORE_READONLY_ATTRIBUTE,
    ] {
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            Flags: u8::try_from(flag).unwrap_or(u8::MAX),
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::addr_of_mut!(security_context),
            Options: FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0,
            ShareAccess: 0,
            __bindgen_padding_1: 0,
            EaLength: 0,
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            let create = current.create();
            assert!(create.is_ok());
            if let Ok(create) = create {
                assert_eq!(
                    create.parameters().validate_supported_flags(),
                    Err(DriverError::NotSupported)
                );
            }
        }
    }
}

/// # Panics
///
/// Panics when a destructive file disposition is accepted with `FILE_DIRECTORY_FILE`.
#[test]
fn create_stack_rejects_directory_destructive_dispositions() {
    for disposition in [
        FILE_OVERWRITE_DISPOSITION,
        FILE_OVERWRITE_IF_DISPOSITION,
        FILE_SUPERSEDE_DISPOSITION,
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
        stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::addr_of_mut!(security_context),
            Options: (disposition << CREATE_DISPOSITION_SHIFT) | wdk_sys::FILE_DIRECTORY_FILE,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0,
            ShareAccess: 0,
            __bindgen_padding_1: 0,
            EaLength: 0,
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(current.create().err(), Some(DriverError::InvalidParameter));
        }
    }
}

/// # Panics
///
/// Panics when existing-object dispositions do not add virtual operation access.
#[test]
fn create_parameters_separate_handle_access_from_operation_access() {
    let requested_access = wdk_sys::FILE_READ_ATTRIBUTES;
    for (disposition, required_access) in [
        (FILE_OPEN_DISPOSITION, 0),
        (
            FILE_OVERWRITE_DISPOSITION,
            wdk_sys::FILE_WRITE_DATA | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES,
        ),
        (
            FILE_OVERWRITE_IF_DISPOSITION,
            wdk_sys::FILE_WRITE_DATA | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES,
        ),
        (
            FILE_SUPERSEDE_DISPOSITION,
            wdk_sys::DELETE | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
            DesiredAccess: requested_access,
            ..wdk_sys::IO_SECURITY_CONTEXT::default()
        };
        stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::addr_of_mut!(security_context),
            Options: disposition << CREATE_DISPOSITION_SHIFT,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0,
            ShareAccess: 0,
            __bindgen_padding_1: 0,
            EaLength: 0,
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        let Ok(current) = current else {
            return;
        };
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                create.parameters().desired_access().as_raw(),
                requested_access
            );
            assert_eq!(
                create.parameters().existing_operation_required_access(),
                required_access
            );
        }
    }
}

/// # Panics
///
/// Panics when delete-on-close bypasses its required `DELETE` authority.
#[test]
fn create_stack_rejects_delete_on_close_without_delete_access() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_DELETE_ON_CLOSE,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(current.create().err(), Some(DriverError::AccessDenied));
    }
}

/// # Panics
///
/// Panics when delete-on-close is not retained as an explicit create domain value.
#[test]
fn create_stack_decodes_authorized_delete_on_close() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: wdk_sys::DELETE,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_DIRECTORY_FILE
            | wdk_sys::FILE_DELETE_ON_CLOSE,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                create.parameters().deletion(),
                super::CreateDeletion::DeleteOnClose
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_decodes_no_intermediate_buffering() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: wdk_sys::FILE_READ_DATA,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            let parameters = create.parameters();
            assert_eq!(
                parameters.transfer_buffering(),
                CreateTransferBuffering::NoIntermediate
            );
            assert_eq!(parameters.write_commitment(), WriteCommitment::FlushThrough);
            assert_eq!(
                parameters.synchronization_mode(),
                CreateSynchronizationMode::Asynchronous
            );
            assert_eq!(
                parameters.reparse_point_mode(),
                CreateReparsePointMode::ResolveFinalTarget
            );
            assert_eq!(
                parameters.name_interpretation(),
                CreateNameInterpretation::Path
            );
            assert_eq!(parameters.name_match(), WindowsNameMatch::CaseInsensitive);
            assert_eq!(
                parameters.access_check(),
                CreateAccessCheck::HonorRequestorMode
            );
            assert_eq!(
                parameters.target_selection(),
                CreateTargetSelection::NamedObject
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_decodes_open_reparse_point() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_OPEN_REPARSE_POINT,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                create.parameters().reparse_point_mode(),
                CreateReparsePointMode::OpenFinalReparsePoint
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_decodes_file_reference_name_interpretation() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_OPEN_BY_FILE_ID,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                create.parameters().name_interpretation(),
                CreateNameInterpretation::FileReference
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_decodes_alertable_synchronous_io() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: wdk_sys::SYNCHRONIZE,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_SYNCHRONOUS_IO_ALERT,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                create.parameters().synchronization_mode(),
                CreateSynchronizationMode::SynchronousAlert
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_rejects_synchronous_io_without_synchronize_access() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: wdk_sys::FILE_READ_DATA,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .create()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_rejects_conflicting_synchronous_io_modes() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: wdk_sys::SYNCHRONIZE,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_SYNCHRONOUS_IO_ALERT
            | wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .create()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_stack_rejects_unsupported_options_before_handler() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT::default();
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_CREATE_TREE_CONNECTION,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .create()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_NOT_SUPPORTED)
        );
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
fn query_ea_stack_decodes_name_selection_length_and_emission() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    let ea_list = NonNull::<u8>::dangling();
    stack.FileObject = file_object.as_ptr();
    stack.Flags = u8::try_from(wdk_sys::SL_RETURN_SINGLE_ENTRY | wdk_sys::SL_INDEX_SPECIFIED)
        .unwrap_or(u8::MAX);
    stack.Parameters.QueryEa = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_11 {
        Length: 128,
        EaList: ea_list.as_ptr().cast(),
        EaListLength: 24,
        __bindgen_padding_0: 0,
        EaIndex: 3,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_ea();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(query.entry_emission(), EaEntryEmission::Single);
            assert_eq!(query.length().as_usize(), 128);
            assert_eq!(
                query.cursor_position(),
                EaCursorPosition::Index(EaEntryIndex(3))
            );
            assert_eq!(
                current.query_ea_name_list().ok().flatten(),
                Some((ea_list.cast(), super::IrpBufferLength(24)))
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_ea_stack_decodes_index_selection() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Flags = u8::try_from(wdk_sys::SL_INDEX_SPECIFIED).unwrap_or(u8::MAX);
    stack.Parameters.QueryEa = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_11 {
        Length: 128,
        EaList: core::ptr::null_mut(),
        EaListLength: 0,
        __bindgen_padding_0: 0,
        EaIndex: 3,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_ea();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(
                query.cursor_position(),
                EaCursorPosition::Index(EaEntryIndex(3))
            );
        }
    }
}

/// # Panics
///
/// Panics when restart and continuation requests collapse into one EA cursor transition.
#[test]
fn query_ea_stack_distinguishes_restart_from_current_cursor() {
    for (flags, expected) in [
        (0, EaCursorPosition::Current),
        (
            u8::try_from(wdk_sys::SL_RESTART_SCAN).unwrap_or(u8::MAX),
            EaCursorPosition::Restart,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            Flags: flags,
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.QueryEa = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_11 {
            Length: 128,
            EaList: core::ptr::null_mut(),
            EaListLength: 0,
            __bindgen_padding_0: 0,
            EaIndex: 0,
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current.query_ea().map(|query| query.cursor_position()),
                Ok(expected)
            );
        }
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
fn set_ea_stack_preserves_file_object_and_length() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.SetEa =
        wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_12 { Length: 64 };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let set = current.set_ea();
        assert!(set.is_ok());
        if let Ok(set) = set {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(set.length().as_usize(), 64);
        }
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
fn query_security_stack_preserves_file_object_information_and_length() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
        SecurityInformation: wdk_sys::OWNER_SECURITY_INFORMATION
            | wdk_sys::DACL_SECURITY_INFORMATION,
        __bindgen_padding_0: 0,
        Length: 256,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_security();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(
                query.selection().owner(),
                SecurityComponentSelection::Selected
            );
            assert_eq!(
                query.selection().group(),
                SecurityComponentSelection::Omitted
            );
            assert_eq!(
                query.selection().dacl(),
                SecurityComponentSelection::Selected
            );
            assert_eq!(query.length().as_usize(), 256);
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_security_stack_rejects_sacl_at_decode() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
        SecurityInformation: wdk_sys::SACL_SECURITY_INFORMATION,
        __bindgen_padding_0: 0,
        Length: 256,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .query_security()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_ACCESS_DENIED)
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_security_stack_rejects_unsupported_bits_at_decode() {
    const LABEL_SECURITY_INFORMATION: wdk_sys::SECURITY_INFORMATION = 0x10;

    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
        SecurityInformation: LABEL_SECURITY_INFORMATION,
        __bindgen_padding_0: 0,
        Length: 256,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .query_security()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_NOT_SUPPORTED)
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn set_volume_stack_preserves_length_and_class() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    stack.Parameters.SetVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_14 {
        Length: 24,
        __bindgen_padding_0: 0,
        FsInformationClass: wdk_sys::_FSINFOCLASS::FileFsLabelInformation,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let set = current.set_volume();
        assert!(set.is_ok());
        if let Ok(set) = set {
            assert_eq!(set.length().as_usize(), 24);
            assert_eq!(set.information_class(), SetVolumeInformationClass::Label);
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_volume_stack_decodes_supported_information_class() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    stack.Parameters.QueryVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_13 {
        Length: 128,
        __bindgen_padding_0: 0,
        FsInformationClass: wdk_sys::_FSINFOCLASS::FileFsFullSizeInformation,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_volume();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(query.length().as_usize(), 128);
            assert_eq!(
                query.information_class(),
                QueryVolumeInformationClass::FullSize
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn volume_information_stack_rejects_unsupported_class_before_handler() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    stack.Parameters.QueryVolume = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_13 {
        Length: 128,
        __bindgen_padding_0: 0,
        FsInformationClass: 0x7FFF_FFFF,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .query_volume()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(wdk_sys::STATUS_INVALID_INFO_CLASS)
        );
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
fn set_security_stack_preserves_file_object_information_and_descriptor() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    let descriptor = NonNull::<c_void>::dangling();
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.SetSecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_19 {
        SecurityInformation: wdk_sys::OWNER_SECURITY_INFORMATION
            | wdk_sys::GROUP_SECURITY_INFORMATION,
        SecurityDescriptor: descriptor.as_ptr(),
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let set = current.set_security();
        assert!(set.is_ok());
        if let Ok(set) = set {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(
                set.selection().owner(),
                SecurityComponentSelection::Selected
            );
            assert_eq!(
                set.selection().group(),
                SecurityComponentSelection::Selected
            );
            assert_eq!(set.selection().dacl(), SecurityComponentSelection::Omitted);
            assert_eq!(set.security_descriptor_source(), descriptor);
        }
    }
}

/// # Panics
///
/// Panics when read starting points or lock keys are decoded incorrectly.
#[test]
fn read_stack_decodes_absolute_and_current_positions() {
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    for (raw_offset, expected) in [
        (
            8192,
            ReadStartingPoint::Absolute(FileOffset::from_bytes(8192)),
        ),
        (
            super::signed_special_offset(wdk_sys::FILE_USE_FILE_POINTER_POSITION),
            ReadStartingPoint::CurrentFilePosition,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
            Length: 4096,
            __bindgen_padding_0: 0,
            Key: 17,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER {
                QuadPart: raw_offset,
            },
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            let read = current.read();
            assert!(read.is_ok());
            if let Ok(read) = read {
                assert_eq!(read.starting_point(), expected);
                assert_eq!(read.length().as_usize(), 4096);
                assert_eq!(read.key(), super::ByteRangeLockKey::from_ulong(17));
            }
        }
    }
}

/// # Panics
///
/// Panics when invalid read sentinels cross the IRP boundary.
#[test]
fn read_stack_rejects_end_of_file_and_unknown_negative_positions() {
    for raw_offset in [
        super::signed_special_offset(wdk_sys::FILE_WRITE_TO_END_OF_FILE),
        -3,
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
            Length: 1,
            __bindgen_padding_0: 0,
            Key: 0,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER {
                QuadPart: raw_offset,
            },
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .read()
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(STATUS_INVALID_PARAMETER)
            );
        }
    }
}

/// # Panics
///
/// Panics when write starting points or lock keys are decoded incorrectly.
#[test]
fn write_stack_decodes_absolute_current_and_end_positions() {
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    for (raw_offset, expected) in [
        (
            4096,
            WriteStartingPoint::Absolute(FileOffset::from_bytes(4096)),
        ),
        (
            super::signed_special_offset(wdk_sys::FILE_USE_FILE_POINTER_POSITION),
            WriteStartingPoint::CurrentFilePosition,
        ),
        (
            super::signed_special_offset(wdk_sys::FILE_WRITE_TO_END_OF_FILE),
            WriteStartingPoint::EndOfFile,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
            Length: 2048,
            __bindgen_padding_0: 0,
            Key: 23,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER {
                QuadPart: raw_offset,
            },
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            let write = current.write();
            assert!(write.is_ok());
            if let Ok(write) = write {
                assert_eq!(write.starting_point(), expected);
                assert_eq!(write.length().as_usize(), 2048);
                assert_eq!(write.key(), super::ByteRangeLockKey::from_ulong(23));
            }
        }
    }
}

/// # Panics
///
/// Panics when an unknown negative write position crosses the IRP boundary.
#[test]
fn write_stack_rejects_unknown_negative_position() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
        Length: 1,
        __bindgen_padding_0: 0,
        Key: 0,
        Flags: 0,
        ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: -3 },
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .write()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
    }
}

/// # Panics
///
/// Panics when paging flags are not isolated from normal handle I/O.
#[test]
fn dispatch_target_decodes_data_io_kind() {
    let mut device = wdk_sys::DEVICE_OBJECT::default();
    for (flags, expected) in [
        (0, DataIoKind::Handle),
        (wdk_sys::IRP_PAGING_IO, DataIoKind::Paging),
    ] {
        let mut irp = wdk_sys::IRP {
            Flags: flags,
            ..wdk_sys::IRP::default()
        };
        let mut received = received_irp_fixture(&mut device, &mut irp);
        assert!(received.is_ok());
        if let Ok(received) = received.as_mut() {
            assert_eq!(
                received.with_active(|active| active.data_io_kind()),
                expected
            );
        }
    }
}

/// # Panics
///
/// Panics when desired access does not produce one exclusive write authority.
#[test]
fn granted_access_projects_regular_file_write_authority() {
    for (raw, expected) in [
        (0, RegularFileWriteAccess::Denied),
        (
            wdk_sys::FILE_APPEND_DATA,
            RegularFileWriteAccess::AppendOnly,
        ),
        (wdk_sys::FILE_WRITE_DATA, RegularFileWriteAccess::Positional),
        (
            wdk_sys::FILE_WRITE_DATA | wdk_sys::FILE_APPEND_DATA,
            RegularFileWriteAccess::Positional,
        ),
    ] {
        assert_eq!(
            super::GrantedAccess::from_authorized(raw).regular_file_write_access(),
            expected
        );
    }
}

/// Forced user-mode checks must reach the native security check even when a kernel request
/// carries previously granted access. The user-mode harness reports native checks unsupported.
/// # Panics
///
/// Panics if cached kernel rights bypass a forced user-mode check.
/// # Errors
///
/// Returns fixture construction failures or an unexpected trusted-kernel authorization error.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report contract failures while Result propagates fixture setup errors"
)]
fn forced_user_access_does_not_reuse_kernel_grants() -> Result<(), DriverError> {
    let security = ext4_core::Ext4Security::new(
        ext4_core::Ext4Owner::new(
            ext4_core::Ext4Uid::from_u32(0),
            ext4_core::Ext4Gid::from_u32(0),
        ),
        ext4_core::Ext4Permissions::new(0)?,
    );
    let descriptor = crate::request::security::CreateSecurityDescriptor::from_security(security)?;
    let requested = super::DesiredAccess::from_raw(wdk_sys::GENERIC_WRITE);
    for policy in [
        CreateAccessCheck::HonorRequestorMode,
        CreateAccessCheck::ForceUserMode,
    ] {
        let mut access_state = wdk_sys::ACCESS_STATE {
            PreviouslyGrantedAccess: wdk_sys::FILE_ALL_ACCESS,
            ..wdk_sys::ACCESS_STATE::default()
        };
        let mut context = wdk_sys::IO_SECURITY_CONTEXT {
            AccessState: core::ptr::from_mut(&mut access_state),
            DesiredAccess: requested.as_raw(),
            ..wdk_sys::IO_SECURITY_CONTEXT::default()
        };
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
            SecurityContext: core::ptr::from_mut(&mut context),
            ..Default::default()
        };
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        let current = current_stack_fixture(&mut stack)?;
        let mut state = current.create_access_state(kernel_mode, policy)?;
        let result = state.authorize_requested(descriptor.as_native(), requested);
        match policy {
            CreateAccessCheck::HonorRequestorMode => {
                assert_eq!(result?.as_raw(), wdk_sys::FILE_ALL_ACCESS);
            }
            CreateAccessCheck::ForceUserMode => {
                assert_eq!(result, Err(DriverError::NotSupported));
            }
        }
    }
    Ok(())
}

/// # Panics
///
/// Panics if generic mapping expands descriptor-dependent maximum access prematurely.
#[test]
fn generic_mapping_preserves_maximum_for_security_evaluation() {
    assert_eq!(
        super::map_file_generic_access(wdk_sys::GENERIC_READ | wdk_sys::MAXIMUM_ALLOWED),
        wdk_sys::FILE_GENERIC_READ | wdk_sys::MAXIMUM_ALLOWED
    );
}

/// # Panics
///
/// Panics when `DELETE` is not retained as an explicit handle authority.
#[test]
fn granted_access_projects_delete_authority() {
    assert_eq!(
        super::GrantedAccess::from_authorized(0).delete_access(),
        super::DeleteAccess::Denied
    );
    assert_eq!(
        super::GrantedAccess::from_authorized(wdk_sys::DELETE).delete_access(),
        super::DeleteAccess::Granted
    );
    assert_eq!(
        super::DeleteAccess::Denied.require(),
        Err(crate::kernel::status::DriverError::AccessDenied)
    );
    assert_eq!(super::DeleteAccess::Granted.require(), Ok(()));
}

/// # Panics
///
/// Panics when `FILE_WRITE_ATTRIBUTES` is not retained as an explicit handle authority.
#[test]
fn granted_access_projects_file_attributes_write_authority() {
    assert_eq!(
        super::GrantedAccess::from_authorized(0).file_attributes_write_access(),
        super::FileAttributesWriteAccess::Denied
    );
    assert_eq!(
        super::GrantedAccess::from_authorized(wdk_sys::FILE_WRITE_ATTRIBUTES)
            .file_attributes_write_access(),
        super::FileAttributesWriteAccess::Granted
    );
}

/// # Panics
///
/// Panics when no-intermediate append access is rejected before EOF is known.
#[test]
fn create_stack_accepts_no_intermediate_append_access() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
        DesiredAccess: wdk_sys::FILE_APPEND_DATA,
        ..wdk_sys::IO_SECURITY_CONTEXT::default()
    };
    stack.FileObject = NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr();
    stack.Parameters.Create = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_1 {
        SecurityContext: core::ptr::addr_of_mut!(security_context),
        Options: (FILE_OPEN_DISPOSITION << CREATE_DISPOSITION_SHIFT)
            | wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING,
        __bindgen_padding_0: [0; 2],
        FileAttributes: 0,
        ShareAccess: 0,
        __bindgen_padding_1: 0,
        EaLength: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let create = current.create();
        assert!(create.is_ok());
        if let Ok(create) = create {
            assert_eq!(
                create.parameters().transfer_buffering(),
                CreateTransferBuffering::NoIntermediate
            );
            assert_eq!(
                create.parameters().desired_access().as_raw(),
                wdk_sys::FILE_APPEND_DATA
            );
        }
    }
}

/// # Panics
///
/// Panics when FilePositionInformation is not accepted for set-information.
#[test]
fn set_file_stack_decodes_position_information() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
        Length: u32::try_from(core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>())
            .unwrap_or(u32::MAX),
        __bindgen_padding_0: 0,
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation,
        FileObject: core::ptr::null_mut(),
        __bindgen_anon_1:
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let set = current.set_file();
        assert!(set.is_ok());
        if let Ok(set) = set {
            assert_eq!(set.information_class(), SetFileInformationClass::Position);
        }
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
fn query_file_stack_preserves_file_object_length_and_class() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.QueryFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
        Length: 64,
        __bindgen_padding_0: 0,
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_file();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(query.length().as_usize(), 64);
            assert_eq!(
                query.information_class(),
                QueryFileInformationClass::Standard
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_file_stack_decodes_name_attribute_tag_and_link_classes() {
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    for (raw_class, expected) in [
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileNameInformation,
            QueryFileInformationClass::Name,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileAttributeTagInformation,
            QueryFileInformationClass::AttributeTag,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileStandardLinkInformation,
            QueryFileInformationClass::StandardLink,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileHardLinkInformation,
            QueryFileInformationClass::HardLink,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
            Parameters: wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1 {
                QueryFile: wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
                    Length: 64,
                    __bindgen_padding_0: 0,
                    FileInformationClass: raw_class,
                },
            },
            ..wdk_sys::IO_STACK_LOCATION::default()
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_file();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.information_class(), expected);
            }
        }
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
fn set_file_stack_preserves_file_object_length_and_class() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
        Length: 40,
        __bindgen_padding_0: 0,
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation,
        FileObject: core::ptr::null_mut(),
        __bindgen_anon_1:
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let set = current.set_file();
        assert!(set.is_ok());
        if let Ok(set) = set {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(set.length().as_usize(), 40);
            assert_eq!(set.information_class(), SetFileInformationClass::Basic);
        }
    }
}

/// # Panics
///
/// Panics when hard-link information classes return to the invalid-class boundary.
#[test]
fn set_file_class_decodes_legacy_and_extended_hard_links() {
    assert_eq!(
        SetFileInformationClass::from_raw(wdk_sys::_FILE_INFORMATION_CLASS::FileLinkInformation,),
        Ok(SetFileInformationClass::Link)
    );
    assert_eq!(
        SetFileInformationClass::from_raw(wdk_sys::_FILE_INFORMATION_CLASS::FileLinkInformationEx,),
        Ok(SetFileInformationClass::LinkEx)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn file_information_stack_rejects_unsupported_class_before_handler() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.QueryFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
        Length: 64,
        __bindgen_padding_0: 0,
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        assert_eq!(
            current
                .query_file()
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(wdk_sys::STATUS_INVALID_INFO_CLASS)
        );
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
fn query_directory_stack_decodes_restart_pattern_length_class_and_emission() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    let file_name = NonNull::<wdk_sys::UNICODE_STRING>::dangling();
    stack.FileObject = file_object.as_ptr();
    stack.Flags =
        u8::try_from(wdk_sys::SL_RESTART_SCAN | wdk_sys::SL_RETURN_SINGLE_ENTRY).unwrap_or(u8::MAX);
    stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
        Length: 128,
        FileName: file_name.as_ptr(),
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
        __bindgen_padding_0: 0,
        FileIndex: 3,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_directory();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(query.cursor_position(), DirectoryCursorPosition::Restart);
            assert!(current.query_directory_file_name().ok().flatten().is_some());
            assert_eq!(query.entry_emission(), DirectoryEntryEmission::Single);
            assert_eq!(query.length().as_usize(), 128);
            assert_eq!(
                query.information_class(),
                DirectoryInformationClass::Directory
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_directory_stack_decodes_names_class() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
        Length: 128,
        FileName: core::ptr::null_mut(),
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileNamesInformation,
        __bindgen_padding_0: 0,
        FileIndex: 0,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_directory();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(query.information_class(), DirectoryInformationClass::Names);
        }
    }
}

/// # Panics
///
/// Panics when an identity-bearing directory class no longer enters its exact wire domain.
#[test]
fn query_directory_stack_decodes_identity_classes() {
    for (raw, expected) in [
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation,
            DirectoryInformationClass::IdFull,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation,
            DirectoryInformationClass::IdBoth,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdExtdDirectoryInformation,
            DirectoryInformationClass::IdExtd,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileIdExtdBothDirectoryInformation,
            DirectoryInformationClass::IdExtdBoth,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileId64ExtdDirectoryInformation,
            DirectoryInformationClass::Id64Extd,
        ),
        (
            wdk_sys::_FILE_INFORMATION_CLASS::FileId64ExtdBothDirectoryInformation,
            DirectoryInformationClass::Id64ExtdBoth,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: core::ptr::null_mut(),
            FileInformationClass: raw,
            __bindgen_padding_0: 0,
            FileIndex: 0,
        };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .query_directory()
                    .ok()
                    .map(|query| query.information_class()),
                Some(expected)
            );
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn query_directory_stack_decodes_index_cursor() {
    let mut stack = wdk_sys::IO_STACK_LOCATION::default();
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    stack.FileObject = file_object.as_ptr();
    stack.Flags = u8::try_from(wdk_sys::SL_INDEX_SPECIFIED).unwrap_or(u8::MAX);
    stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
        Length: 128,
        FileName: core::ptr::null_mut(),
        FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
        __bindgen_padding_0: 0,
        FileIndex: 3,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let query = current.query_directory();
        assert!(query.is_ok());
        if let Ok(query) = query {
            assert_eq!(
                query.cursor_position(),
                DirectoryCursorPosition::Index(super::DirectoryEntryIndex(3))
            );
            assert_eq!(query.entry_emission(), DirectoryEntryEmission::Multiple);
        }
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
fn notify_directory_stack_decodes_filter_and_scope() {
    let mut file_object_storage = wdk_sys::FILE_OBJECT::default();
    let file_object = NonNull::from(&mut file_object_storage);
    let completion_filter = wdk_sys::FILE_NOTIFY_CHANGE_FILE_NAME
        | wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES
        | wdk_sys::FILE_NOTIFY_CHANGE_SECURITY;
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        MinorFunction: u8::try_from(wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY).unwrap_or(u8::MAX),
        Flags: u8::try_from(wdk_sys::SL_WATCH_TREE).unwrap_or(u8::MAX),
        FileObject: file_object.as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };
    stack.Parameters.NotifyDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_7 {
        Length: 512,
        __bindgen_padding_0: 0,
        CompletionFilter: completion_filter,
    };

    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let notification = current.notify_directory();
        assert!(notification.is_ok());
        if let Ok(notification) = notification {
            assert_eq!(
                current.file_object().ok().map(ActiveFileObject::address),
                unsafe {
                    // SAFETY: The owning test allocation remains live through this comparison.
                    KernelFileObject::from_raw(file_object.as_ptr())
                }
            );
            assert_eq!(
                notification.completion_filter(),
                DirectoryChangeFilter(completion_filter)
            );
            assert_eq!(notification.watch_scope(), DirectoryWatchScope::Subtree);
        }
    }

    assert_eq!(
        DirectoryChangeFilter(wdk_sys::FILE_NOTIFY_CHANGE_NAME).namespace_name_filter(),
        Ok(wdk_sys::FILE_NOTIFY_CHANGE_NAME)
    );
    assert_eq!(
        DirectoryChangeFilter(completion_filter).namespace_name_filter(),
        Err(crate::kernel::status::DriverError::NotSupported)
    );

    stack.Flags = 0;
    let current = current_stack_fixture(&mut stack);
    assert!(current.is_ok());
    if let Ok(current) = current {
        let notification = current.notify_directory();
        assert!(notification.is_ok());
        if let Ok(notification) = notification {
            assert_eq!(
                notification.watch_scope(),
                DirectoryWatchScope::DirectChildren
            );
        }
    }
}

/// # Panics
///
/// Panics when the extended notify minor function or its output format is decoded through the
/// standard notification contract.
#[test]
fn notify_directory_ex_stack_preserves_minor_and_information_class() {
    for (raw, expected) in [
        (
            wdk_sys::_DIRECTORY_NOTIFY_INFORMATION_CLASS::DirectoryNotifyInformation,
            DirectoryNotifyInformationClass::Standard,
        ),
        (
            wdk_sys::_DIRECTORY_NOTIFY_INFORMATION_CLASS::DirectoryNotifyExtendedInformation,
            DirectoryNotifyInformationClass::Extended,
        ),
        (
            wdk_sys::_DIRECTORY_NOTIFY_INFORMATION_CLASS::DirectoryNotifyFullInformation,
            DirectoryNotifyInformationClass::Full,
        ),
    ] {
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MinorFunction: u8::try_from(wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX)
                .unwrap_or(u8::MAX),
            FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.NotifyDirectoryEx =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_8 {
                Length: 512,
                __bindgen_padding_0: 0,
                CompletionFilter: wdk_sys::FILE_NOTIFY_CHANGE_FILE_NAME,
                __bindgen_padding_1: 0,
                DirectoryNotifyInformationClass: raw,
            };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current.directory_control_minor(),
                DirectoryControlMinorFunction::NotifyChangeDirectoryEx
            );
            assert_eq!(current.notify_directory_ex(), Ok(expected));
        }
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn notify_directory_stack_rejects_empty_and_unknown_filters() {
    let mut stack = wdk_sys::IO_STACK_LOCATION {
        MinorFunction: u8::try_from(wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY).unwrap_or(u8::MAX),
        FileObject: NonNull::<wdk_sys::FILE_OBJECT>::dangling().as_ptr(),
        ..wdk_sys::IO_STACK_LOCATION::default()
    };

    for completion_filter in [0, 1_u32 << 31] {
        stack.Parameters.NotifyDirectory =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_7 {
                Length: 0,
                __bindgen_padding_0: 0,
                CompletionFilter: completion_filter,
            };

        let current = current_stack_fixture(&mut stack);
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current
                    .notify_directory()
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(STATUS_INVALID_PARAMETER)
            );
        }
    }
}

/// # Panics
///
/// Panics when create oplock flags stop normalizing to one unambiguous domain policy.
#[test]
fn create_oplock_policy_rejects_ambiguous_flags() {
    let desired = DesiredAccess::from_raw(wdk_sys::FILE_READ_ATTRIBUTES);
    let shared = ShareAccess::from_raw(FILE_SHARE_ACCESS_MASK);
    assert!(shared.is_ok());
    let Ok(shared) = shared else { return };
    assert_eq!(
        OplockCreatePolicy::decode(0, desired, shared),
        Ok(OplockCreatePolicy::Ordinary)
    );
    assert_eq!(
        OplockCreatePolicy::decode(wdk_sys::FILE_COMPLETE_IF_OPLOCKED, desired, shared),
        Ok(OplockCreatePolicy::CompleteIfOplocked)
    );
    assert_eq!(
        OplockCreatePolicy::decode(wdk_sys::FILE_OPEN_REQUIRING_OPLOCK, desired, shared),
        Ok(OplockCreatePolicy::RequireUnbrokenOplock)
    );
    assert_eq!(
        OplockCreatePolicy::decode(
            wdk_sys::FILE_COMPLETE_IF_OPLOCKED | wdk_sys::FILE_OPEN_REQUIRING_OPLOCK,
            desired,
            shared,
        ),
        Err(DriverError::InvalidParameter)
    );
}

/// # Panics
///
/// Panics when filter-oplock reservation accepts anything except the documented exact open.
#[test]
fn reserve_filter_oplock_requires_exact_access_and_sharing() {
    let shared = ShareAccess::from_raw(FILE_SHARE_ACCESS_MASK);
    assert!(shared.is_ok());
    let Ok(shared) = shared else { return };
    assert_eq!(
        OplockCreatePolicy::decode(
            wdk_sys::FILE_RESERVE_OPFILTER,
            DesiredAccess::from_raw(wdk_sys::FILE_READ_ATTRIBUTES),
            shared,
        ),
        Ok(OplockCreatePolicy::ReserveFilter)
    );
    assert_eq!(
        OplockCreatePolicy::decode(
            wdk_sys::FILE_RESERVE_OPFILTER,
            DesiredAccess::from_raw(wdk_sys::FILE_READ_ATTRIBUTES | wdk_sys::SYNCHRONIZE),
            shared,
        ),
        Err(DriverError::InvalidParameter)
    );
    let read_only_share = u16::try_from(wdk_sys::FILE_SHARE_READ)
        .map_err(|_| DriverError::InvalidParameter)
        .and_then(ShareAccess::from_raw);
    assert!(read_only_share.is_ok());
    let Ok(read_only_share) = read_only_share else {
        return;
    };
    assert_eq!(
        OplockCreatePolicy::decode(
            wdk_sys::FILE_RESERVE_OPFILTER,
            DesiredAccess::from_raw(wdk_sys::FILE_READ_ATTRIBUTES),
            read_only_share,
        ),
        Err(DriverError::InvalidParameter)
    );
}
