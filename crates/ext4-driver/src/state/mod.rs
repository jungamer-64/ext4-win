//! Driver-local lifecycle and open-object state.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::num::NonZeroU32;
use core::ptr::NonNull;

use ext4_core::{
    DeviceLength, DirectoryNodeId, Ext4Name, FileNodeId, FscryptKeyIdentifier, FscryptKeyPresence,
    FscryptKeySet, FscryptMasterKey, JournaledVolume, MountContext, NodeId, Result as Ext4Result,
    SymlinkNodeId,
};
use wdk_sys::{
    DO_DEVICE_INITIALIZING, DO_DIRECT_IO, FILE_OBJECT, PDEVICE_OBJECT, PDRIVER_OBJECT,
    SHARE_ACCESS, STATUS_SUCCESS, VPB_MOUNTED,
};

use crate::irp::{DesiredAccess, DirectoryEntryIndex, ShareAccess};
use crate::kernel::cng::CngFscryptNonceGenerator;
use crate::kernel::fatal::KernelWideInconsistency;
use crate::kernel::status::{DriverError, DriverResult};
use crate::kernel::{block_device::KernelBlockDevice, ffi};
use crate::memory::{self, DriverVec};

/// Registered control device observed by the unload callback.
static mut CONTROL_DEVICE: Option<ControlDevice> = None;

/// Non-null kernel device object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelDevice {
    /// Non-null opaque WDK device pointer.
    device: NonNull<c_void>,
}

impl KernelDevice {
    /// Converts a raw WDK device pointer into the non-null boundary type.
    pub(crate) fn from_raw(device: PDEVICE_OBJECT) -> Option<Self> {
        NonNull::new(device.cast()).map(|device| Self { device })
    }

    /// Returns the raw WDK device pointer for FFI calls.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr().cast()
    }

    /// Returns the owning driver object for creating sibling device objects.
    pub(crate) fn driver_object(self) -> Option<PDRIVER_OBJECT> {
        let device = unsafe {
            // SAFETY: `self` is a non-null DEVICE_OBJECT pointer decoded at the
            // driver boundary and is only read for its stable DriverObject field.
            self.as_ptr().as_ref()
        }?;
        NonNull::new(device.DriverObject).map(NonNull::as_ptr)
    }

    /// Returns the lower-device stack size advertised by the I/O Manager.
    pub(crate) fn stack_size(self) -> Option<i8> {
        let device = unsafe {
            // SAFETY: `self` is a non-null DEVICE_OBJECT pointer decoded at the
            // driver boundary and is only read for StackSize propagation.
            self.as_ptr().as_ref()
        }?;
        Some(device.StackSize)
    }
}

/// Non-null kernel file object pointer at the WDK boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelFileObject {
    /// Non-null opaque WDK file object pointer.
    file_object: NonNull<FILE_OBJECT>,
}

impl KernelFileObject {
    /// Converts a raw WDK file object pointer into the non-null boundary type.
    pub(crate) fn from_raw(file_object: *mut FILE_OBJECT) -> Option<Self> {
        NonNull::new(file_object).map(|file_object| Self { file_object })
    }

    /// Returns an immutable WDK file object reference.
    ///
    /// # Safety
    /// The returned reference must not outlive the active WDK callback that supplied this
    /// FILE_OBJECT, and the caller must not mutate the object through another alias for that
    /// lifetime.
    pub(crate) unsafe fn as_ref<'a>(self) -> &'a FILE_OBJECT {
        unsafe {
            // SAFETY: The caller ties the returned reference to the active WDK
            // callback lifetime that supplied this non-null FILE_OBJECT.
            self.file_object.as_ref()
        }
    }

    /// Returns a mutable WDK file object reference.
    ///
    /// # Safety
    /// The caller must own the current mutation point for this FILE_OBJECT and ensure no other
    /// FILE_OBJECT reference aliases the returned mutable reference.
    pub(crate) unsafe fn as_mut<'a>(mut self) -> &'a mut FILE_OBJECT {
        unsafe {
            // SAFETY: The caller owns the active mutation point for this
            // FILE_OBJECT during the current dispatch callback.
            self.file_object.as_mut()
        }
    }

    /// Returns the raw WDK pointer for FFI calls that require FILE_OBJECT.
    fn as_ptr(self) -> *mut FILE_OBJECT {
        self.file_object.as_ptr()
    }
}

/// FILE_OBJECT during create before filesystem contexts are attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UninitializedFileObject {
    /// Kernel FILE_OBJECT that has not yet been opened by this filesystem.
    file_object: KernelFileObject,
}

impl UninitializedFileObject {
    /// Decodes a create target whose FCB and CCB slots are both empty.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT already has filesystem-owned FCB or CCB context.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let object = unsafe {
            // SAFETY: The FILE_OBJECT pointer comes from the active create
            // stack and is read only for filesystem-owned context pointers.
            file_object.as_ref()
        };
        if !object.FsContext.is_null() || !object.FsContext2.is_null() {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { file_object })
    }

    /// Returns the underlying kernel FILE_OBJECT for FFI calls.
    pub(crate) const fn kernel_file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns an immutable WDK FILE_OBJECT reference.
    ///
    /// # Safety
    /// The returned reference must stay within the active create dispatch lifetime and must not
    /// alias any concurrent mutable access to the FILE_OBJECT.
    pub(crate) unsafe fn as_ref<'a>(self) -> &'a FILE_OBJECT {
        unsafe {
            // SAFETY: The caller ties the returned reference to the active
            // create dispatch lifetime that supplied this FILE_OBJECT.
            self.file_object.as_ref()
        }
    }

    /// Returns a mutable WDK FILE_OBJECT reference.
    ///
    /// # Safety
    /// The caller must hold the unique create attach point for this uninitialized FILE_OBJECT while
    /// the returned mutable reference is alive.
    pub(crate) unsafe fn as_mut<'a>(self) -> &'a mut FILE_OBJECT {
        unsafe {
            // SAFETY: The caller owns the successful create attach point for
            // this not-yet-initialized FILE_OBJECT.
            self.file_object.as_mut()
        }
    }
}

/// Non-null VPB pointer supplied by the I/O Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelVpb {
    /// Non-null WDK VPB pointer.
    vpb: NonNull<wdk_sys::VPB>,
}

impl KernelVpb {
    /// Converts a raw WDK VPB pointer into the non-null boundary type.
    pub(crate) fn from_raw(vpb: *mut wdk_sys::VPB) -> Option<Self> {
        NonNull::new(vpb).map(|vpb| Self { vpb })
    }

    /// Returns the non-null VPB pointer for mount-time device initialization.
    pub(crate) const fn as_non_null(self) -> NonNull<wdk_sys::VPB> {
        self.vpb
    }
}

/// Non-null security descriptor pointer supplied by the I/O Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelSecurityDescriptor {
    /// Non-null opaque security descriptor pointer.
    descriptor: NonNull<c_void>,
}

impl KernelSecurityDescriptor {
    /// Converts a raw WDK security descriptor pointer into the non-null boundary type.
    pub(crate) fn from_raw(descriptor: *mut c_void) -> Option<Self> {
        NonNull::new(descriptor).map(|descriptor| Self { descriptor })
    }

    /// Returns an immutable descriptor reference as an opaque pointer.
    pub(crate) const fn as_non_null(self) -> NonNull<c_void> {
        self.descriptor
    }
}

/// Registered file system control device owned by the driver.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ControlDevice {
    /// File-system control device registered with the I/O Manager.
    device: KernelDevice,
}

impl ControlDevice {
    /// Creates registered control-device state.
    pub(crate) fn registered(device: PDEVICE_OBJECT) -> Option<Self> {
        KernelDevice::from_raw(device).map(|device| Self { device })
    }

    /// Returns the raw WDK device pointer for FFI calls.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr()
    }
}

/// Publishes the registered control device for driver unload teardown.
pub(crate) fn publish_control_device(control_device: ControlDevice) {
    let control_device_slot = core::ptr::addr_of_mut!(CONTROL_DEVICE);
    unsafe {
        // SAFETY: `control_device_slot` points to the driver-owned global state.
        // Raw pointer write avoids borrowing the mutable static.
        core::ptr::write(control_device_slot, Some(control_device));
    }
}

#[expect(
    dead_code,
    reason = "mount state is introduced before FSCTL mount IRP handling"
)]
#[derive(Clone, Copy, Debug)]
/// Driver state after the control device has been registered.
pub(crate) struct RegisteredDriver {
    /// Registered control device owned by the driver.
    control_device: KernelDevice,
}

#[derive(Clone, Copy, Debug)]
/// Target device selected by mount FSCTL validation before VCB creation.
pub(crate) struct MountCandidate {
    /// Device object that will back the mounted ext4 volume.
    target_device: KernelDevice,
    /// Valid byte length reported by the storage stack.
    length: DeviceLength,
}

impl MountCandidate {
    /// Creates a mount candidate after storage length validation.
    pub(crate) const fn new(target_device: KernelDevice, length: DeviceLength) -> Self {
        Self {
            target_device,
            length,
        }
    }

    /// Returns the target storage device.
    pub(crate) const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Returns the validated storage length.
    pub(crate) const fn length(self) -> DeviceLength {
        self.length
    }
}

#[derive(Debug)]
/// Volume control block stored in a mounted volume device extension.
pub(crate) struct VolumeControlBlock {
    /// Mounted journaled read-write ext4 volume.
    volume: JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator>,
    /// VCB-owned FCBs keyed by ext4 node identity.
    file_control_blocks: DriverVec<NonNull<FileControlBlock>>,
}

impl VolumeControlBlock {
    /// Mounts a journaled read-write ext4 VCB.
    /// # Errors
    ///
    /// Returns an error when the lower device cannot be mounted as a journaled ext4 volume.
    pub(crate) fn mount_journaled(
        target_device: KernelDevice,
        length: DeviceLength,
    ) -> Ext4Result<Self> {
        let block_device = KernelBlockDevice::new(target_device, length);
        let volume = JournaledVolume::<_, CngFscryptNonceGenerator>::mount(
            block_device,
            MountContext::new(FscryptKeySet::empty(), CngFscryptNonceGenerator),
        )?;
        Ok(Self {
            volume,
            file_control_blocks: DriverVec::new(),
        })
    }

    /// Returns a stable serial number derived from the ext4 filesystem UUID.
    pub(crate) fn serial_number(&self) -> VolumeSerialNumber {
        let uuid = self.volume.identity().uuid().bytes();
        let [a, b, c, d, ..] = uuid;
        VolumeSerialNumber::from_le_bytes([a, b, c, d])
    }

    /// Returns the mounted ext4 volume.
    pub(crate) const fn volume(
        &self,
    ) -> &JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator> {
        &self.volume
    }

    /// Returns the mounted ext4 volume for journaled mutation.
    pub(crate) const fn volume_mut(
        &mut self,
    ) -> &mut JournaledVolume<KernelBlockDevice, CngFscryptNonceGenerator> {
        &mut self.volume
    }

    /// Returns the mounted ext4 volume label.
    pub(crate) fn volume_label(&self) -> ext4_core::Ext4VolumeLabel {
        self.volume.identity().label()
    }

    /// Adds one fscrypt master key to the mounted volume.
    /// # Errors
    ///
    /// Returns an error when the mounted volume rejects the fscrypt master key.
    pub(crate) fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Ext4Result<()> {
        self.volume.add_fscrypt_key(key)
    }

    /// Removes one fscrypt master key from the mounted volume.
    pub(crate) fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.volume.remove_fscrypt_key(identifier)
    }

    /// Returns the mounted volume's fscrypt key presence for one identifier.
    pub(crate) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        self.volume.fscrypt_key_presence(identifier)
    }

    /// Opens or reuses the VCB-owned FCB for a node.
    /// # Errors
    ///
    /// Returns an error when an existing FCB's open-reference counter would overflow.
    pub(crate) fn open_file_control_block(
        mut volume: NonNull<Self>,
        node: NodeId,
    ) -> DriverResult<NonNull<FileControlBlock>> {
        let vcb = unsafe {
            // SAFETY: The caller passes a live mounted VCB pointer from the
            // mounted device extension while processing create/open.
            volume.as_mut()
        };
        if let Some(mut fcb) = vcb.find_file_control_block(node) {
            let fcb_ref = unsafe {
                // SAFETY: FCB pointers in the table are Box allocations owned
                // by this VCB and remain valid until their open count reaches
                // zero in `close_file_control_block`.
                fcb.as_mut()
            };
            fcb_ref.add_open_reference()?;
            return Ok(fcb);
        }

        let fcb = memory::boxed_with(|| FileControlBlock::new(volume, node))?;
        let fcb = NonNull::from(Box::leak(fcb));
        vcb.file_control_blocks.try_push(fcb)?;
        Ok(fcb)
    }

    /// Releases one open reference to a VCB-owned FCB.
    fn close_file_control_block(&mut self, fcb: NonNull<FileControlBlock>) {
        let Some(index) = self
            .file_control_blocks
            .iter()
            .position(|candidate| *candidate == fcb)
        else {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        };
        let mut fcb = fcb;
        let fcb_ref = unsafe {
            // SAFETY: The FCB was found in this VCB's ownership table.
            fcb.as_mut()
        };
        match fcb_ref.release_open_reference() {
            FileControlBlockRelease::StillOpen => {}
            FileControlBlockRelease::LastReference => {
                let Some(removed) = self.file_control_blocks.swap_remove(index) else {
                    KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
                };
                unsafe {
                    // SAFETY: The pointer was removed from the ownership table
                    // exactly once and no open FILE_OBJECT should reference it
                    // after the last close.
                    drop(Box::from_raw(removed.as_ptr()));
                }
            }
        }
    }

    /// Finds a VCB-owned FCB by node identity.
    fn find_file_control_block(&mut self, node: NodeId) -> Option<NonNull<FileControlBlock>> {
        self.file_control_blocks.iter().copied().find(|fcb| {
            let fcb = unsafe {
                // SAFETY: FCB pointers in this table are owned by the VCB.
                fcb.as_ref()
            };
            fcb.node() == node
        })
    }
}

/// Windows volume serial number derived from the ext4 filesystem UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VolumeSerialNumber {
    /// Raw serial value expected by WDK structures.
    value: u32,
}

impl VolumeSerialNumber {
    /// Builds a serial number from little-endian UUID bytes.
    const fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self {
            value: u32::from_le_bytes(bytes),
        }
    }

    /// Returns the WDK serial number payload.
    pub(crate) const fn as_u32(self) -> u32 {
        self.value
    }
}

impl Drop for VolumeControlBlock {
    fn drop(&mut self) {
        while let Some(fcb) = self.file_control_blocks.pop() {
            unsafe {
                // SAFETY: Remaining FCB pointers are still owned by this VCB
                // during volume teardown.
                drop(Box::from_raw(fcb.as_ptr()));
            }
        }
    }
}

/// Device extension stored in mounted volume device objects.
#[repr(C)]
pub(crate) struct MountedVolumeDeviceExtension {
    /// Heap-owned VCB for this mounted volume device.
    vcb: *mut VolumeControlBlock,
}

/// Mounted volume device object produced by a successful mount FSCTL.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountedVolumeDevice {
    /// Mounted volume device object.
    device: KernelDevice,
}

impl MountedVolumeDevice {
    /// Initializes an IoCreateDevice-created mounted device and takes ownership
    /// of the VCB.
    /// # Errors
    ///
    /// Returns an error when the mounted DEVICE_OBJECT, device extension, or VPB initialization
    /// target is absent or invalid.
    pub(crate) fn initialize(
        device: PDEVICE_OBJECT,
        vcb: Box<VolumeControlBlock>,
        vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<Self> {
        let device = KernelDevice::from_raw(device).ok_or(DriverError::InvalidParameter)?;
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
        Self::initialize_device_object(device, vpb, real_device)?;
        extension.vcb = Box::into_raw(vcb);
        Ok(Self { device })
    }

    /// Returns the mounted volume device object pointer.
    pub(crate) fn as_ptr(self) -> PDEVICE_OBJECT {
        self.device.as_ptr()
    }

    /// Returns the mounted VCB pointer stored in a mounted device extension.
    pub(crate) fn vcb(device: KernelDevice) -> Option<NonNull<VolumeControlBlock>> {
        let device_object = unsafe {
            // SAFETY: `device` is a non-null DEVICE_OBJECT decoded at the
            // dispatch boundary and is read for its extension pointer only.
            device.as_ptr().as_ref()
        }?;
        let extension = unsafe {
            // SAFETY: Mounted volume devices created by this driver store a
            // MountedVolumeDeviceExtension in DeviceExtension. Null or foreign
            // extensions are rejected by the following pointer checks.
            device_object
                .DeviceExtension
                .cast::<MountedVolumeDeviceExtension>()
                .as_ref()
        }?;
        NonNull::new(extension.vcb)
    }

    /// Initializes DEVICE_OBJECT and VPB fields after a successful core mount.
    /// # Errors
    ///
    /// Returns an error when the mounted device object, lower-device stack size, or VPB mounted flag
    /// cannot be represented.
    fn initialize_device_object(
        device: KernelDevice,
        mut vpb: NonNull<wdk_sys::VPB>,
        real_device: KernelDevice,
    ) -> DriverResult<()> {
        let device_object = unsafe {
            // SAFETY: The mounted device object was created by this driver and
            // remains valid during mount initialization.
            device.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        device_object.Vpb = vpb.as_ptr();
        device_object.Flags |= DO_DIRECT_IO;
        device_object.Flags &= !DO_DEVICE_INITIALIZING;
        device_object.StackSize = real_device
            .stack_size()
            .ok_or(DriverError::InvalidParameter)?
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?;

        let vpb = unsafe {
            // SAFETY: The VPB was supplied by the I/O Manager for this mount
            // request and is writable during successful mount completion.
            vpb.as_mut()
        };
        vpb.DeviceObject = device.as_ptr();
        vpb.RealDevice = real_device.as_ptr();
        vpb.Flags |= u16::try_from(VPB_MOUNTED).map_err(|_| DriverError::InvalidParameter)?;
        Ok(())
    }

    /// Copies VCB-derived identity fields into the VPB.
    /// # Errors
    ///
    /// Returns an error when the VPB pointer is no longer writable or the volume label does not fit
    /// in the VPB label field.
    pub(crate) fn initialize_vpb_identity(
        vpb: NonNull<wdk_sys::VPB>,
        vcb: &VolumeControlBlock,
    ) -> DriverResult<()> {
        let vpb = unsafe {
            // SAFETY: The VPB belongs to the active mount request and remains
            // writable until the mount IRP is completed.
            vpb.as_ptr().as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        vpb.SerialNumber = vcb.serial_number().as_u32();
        write_vpb_label(vpb, vcb.volume_label())
    }

    /// Refreshes the VPB volume label after a successful label mutation.
    /// # Errors
    ///
    /// Returns an error when the mounted device or its VPB pointer is absent, or the ext4 label does
    /// not fit in the VPB label field.
    pub(crate) fn refresh_vpb_label(
        device: KernelDevice,
        vcb: &VolumeControlBlock,
    ) -> DriverResult<()> {
        let device_object = unsafe {
            // SAFETY: `device` is a mounted volume device owned by this driver
            // and is read only for its current VPB pointer.
            device.as_ptr().as_ref()
        }
        .ok_or(DriverError::InvalidParameter)?;
        let vpb = unsafe {
            // SAFETY: The VPB pointer belongs to the mounted device and stays
            // valid while the volume remains mounted.
            device_object.Vpb.as_mut()
        }
        .ok_or(DriverError::InvalidParameter)?;
        write_vpb_label(vpb, vcb.volume_label())
    }
}

/// Writes an ext4 label into the UTF-16 VPB label field using one code unit per
/// ext4 label byte.
/// # Errors
///
/// Returns an error when the ext4 label exceeds the VPB label capacity or the UTF-16 byte length
/// cannot be represented by the VPB.
fn write_vpb_label(vpb: &mut wdk_sys::VPB, label: ext4_core::Ext4VolumeLabel) -> DriverResult<()> {
    vpb.VolumeLabel.fill(0);
    let bytes = label.bytes();
    if bytes.len() > vpb.VolumeLabel.len() {
        return Err(DriverError::InvalidParameter);
    }
    for (index, byte) in bytes.iter().enumerate() {
        *vpb.VolumeLabel
            .get_mut(index)
            .ok_or(DriverError::InvalidParameter)? = u16::from(*byte);
    }
    let wchar_bytes = bytes
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)?;
    vpb.VolumeLabelLength =
        u16::try_from(wchar_bytes).map_err(|_| DriverError::InvalidParameter)?;
    Ok(())
}

#[derive(Debug)]
/// File control block stored in `FILE_OBJECT::FsContext`.
pub(crate) struct FileControlBlock {
    /// Mounted volume that owns this file.
    volume: NonNull<VolumeControlBlock>,
    /// Ext4 node opened by this FCB.
    node: NodeId,
    /// I/O manager share-access accounting for this inode identity.
    share_access: SHARE_ACCESS,
    /// Number of open FILE_OBJECTs currently referencing this FCB.
    open_count: NonZeroU32,
}

impl FileControlBlock {
    /// Creates an FCB boundary value for a mounted node with one open reference.
    pub(crate) const fn new(volume: NonNull<VolumeControlBlock>, node: NodeId) -> Self {
        Self {
            volume,
            node,
            share_access: SHARE_ACCESS {
                OpenCount: 0,
                Readers: 0,
                Writers: 0,
                Deleters: 0,
                SharedRead: 0,
                SharedWrite: 0,
                SharedDelete: 0,
            },
            open_count: NonZeroU32::MIN,
        }
    }

    /// Returns the mounted VCB pointer that owns this open node.
    pub(crate) const fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.volume
    }

    /// Returns the ext4 node identity opened by this FCB.
    pub(crate) const fn node(&self) -> NodeId {
        self.node
    }

    /// Checks and records one FILE_OBJECT's share-access claim.
    /// # Errors
    ///
    /// Returns an error when the I/O Manager rejects the requested share-access claim.
    pub(crate) fn check_share_access(
        &mut self,
        file_object: KernelFileObject,
        desired_access: DesiredAccess,
        share_access: ShareAccess,
    ) -> DriverResult<()> {
        let status = unsafe {
            // SAFETY: The FCB owns this SHARE_ACCESS record for the opened
            // inode identity, and FILE_OBJECT is the active create target.
            ffi::IoCheckShareAccess(
                desired_access.as_raw(),
                share_access.as_ulong(),
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
                1,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::ShareAccessConflict);
        }
        Ok(())
    }

    /// Removes one FILE_OBJECT's recorded share-access claim.
    pub(crate) fn remove_share_access(&mut self, file_object: KernelFileObject) {
        unsafe {
            // SAFETY: Successful create recorded this FILE_OBJECT against this
            // FCB-owned SHARE_ACCESS, and close is the unique removal point.
            ffi::IoRemoveShareAccess(
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.share_access),
            );
        }
    }

    /// Adds one FILE_OBJECT reference to an already-open FCB.
    /// # Errors
    ///
    /// Returns an error when the FCB open-reference counter cannot be incremented.
    fn add_open_reference(&mut self) -> DriverResult<()> {
        let count = self
            .open_count
            .get()
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .ok_or(DriverError::TooManyOpenReferences)?;
        self.open_count = count;
        Ok(())
    }

    /// Releases one FILE_OBJECT reference from a non-empty FCB.
    fn release_open_reference(&mut self) -> FileControlBlockRelease {
        let Some(remaining) = self
            .open_count
            .get()
            .checked_sub(1)
            .and_then(NonZeroU32::new)
        else {
            return FileControlBlockRelease::LastReference;
        };
        self.open_count = remaining;
        FileControlBlockRelease::StillOpen
    }
}

/// FCB lifetime state after releasing one open reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileControlBlockRelease {
    /// Other FILE_OBJECTs still reference this FCB.
    StillOpen,
    /// The released reference was the final open reference.
    LastReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Per-handle directory enumeration state.
pub(crate) struct DirectoryCursor {
    /// Next directory entry index to emit.
    next_entry: DirectoryEntryIndex,
}

impl DirectoryCursor {
    /// Creates a cursor at the first directory entry.
    pub(crate) const fn start() -> Self {
        Self {
            next_entry: DirectoryEntryIndex::from_u32(0),
        }
    }

    /// Returns the next directory entry index to emit.
    pub(crate) const fn next_entry(self) -> DirectoryEntryIndex {
        self.next_entry
    }

    /// Moves the cursor to a specific directory entry index.
    pub(crate) const fn seek(&mut self, next_entry: DirectoryEntryIndex) {
        self.next_entry = next_entry;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Opened path identity stored with a handle.
pub(crate) enum OpenedPath {
    /// Mounted volume root.
    Root,
    /// Child entry under a parent directory.
    Child {
        /// Parent directory inode.
        parent: DirectoryNodeId,
        /// Exact ext4 directory entry name.
        name: Ext4Name,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Action requested when the last handle cleanup occurs.
pub(crate) enum CloseDisposition {
    /// Keep the opened object.
    Keep,
    /// Delete the opened object during cleanup.
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Common per-handle state shared by every opened node kind.
pub(crate) struct OpenedHandleState {
    /// Path used for namespace mutations on cleanup.
    path: OpenedPath,
    /// Requested close disposition.
    close_disposition: CloseDisposition,
}

impl OpenedHandleState {
    /// Creates shared per-handle state.
    const fn new(path: OpenedPath, close_disposition: CloseDisposition) -> Self {
        Self {
            path,
            close_disposition,
        }
    }

    /// Returns the opened path identity.
    const fn path(&self) -> &OpenedPath {
        &self.path
    }

    /// Replaces the opened path after a successful rename.
    fn replace_path(&mut self, path: OpenedPath) {
        self.path = path;
    }

    /// Returns the requested close disposition.
    const fn close_disposition(&self) -> CloseDisposition {
        self.close_disposition
    }

    /// Replaces the requested close disposition.
    const fn set_close_disposition(&mut self, close_disposition: CloseDisposition) {
        self.close_disposition = close_disposition;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Per-handle state stored in `FILE_OBJECT::FsContext2`.
pub(crate) enum OpenedHandle {
    /// Regular file handle.
    File(OpenedHandleState),
    /// Directory handle with enumeration cursor.
    Directory {
        /// Shared per-handle state.
        state: OpenedHandleState,
        /// Directory enumeration cursor.
        cursor: DirectoryCursor,
    },
    /// Symlink handle.
    Symlink(OpenedHandleState),
}

impl OpenedHandle {
    /// Creates per-handle state for an opened node.
    pub(crate) fn new(node: NodeId, path: OpenedPath, close_disposition: CloseDisposition) -> Self {
        Self::from_parts(node, path, close_disposition)
    }

    /// Creates per-handle state from explicit lifecycle fields.
    fn from_parts(node: NodeId, path: OpenedPath, close_disposition: CloseDisposition) -> Self {
        let state = OpenedHandleState::new(path, close_disposition);
        match node {
            NodeId::File(_) => Self::File(state),
            NodeId::Directory(_) => Self::Directory {
                state,
                cursor: DirectoryCursor::start(),
            },
            NodeId::Symlink(_) => Self::Symlink(state),
        }
    }

    /// Returns the requested close disposition.
    const fn close_disposition(&self) -> CloseDisposition {
        self.state().close_disposition()
    }

    /// Returns the opened path identity.
    const fn path(&self) -> &OpenedPath {
        self.state().path()
    }

    /// Replaces the requested close disposition.
    const fn set_close_disposition(&mut self, close_disposition: CloseDisposition) {
        self.state_mut().set_close_disposition(close_disposition);
    }

    /// Replaces the opened path after a successful rename.
    fn replace_path(&mut self, path: OpenedPath) {
        self.state_mut().replace_path(path);
    }

    /// Converts the per-handle state to a symlink handle after namespace conversion.
    fn replace_with_symlink(&mut self) {
        let state = self.state().clone();
        *self = Self::Symlink(state);
    }

    /// Returns shared handle state.
    const fn state(&self) -> &OpenedHandleState {
        match self {
            Self::File(state) | Self::Symlink(state) | Self::Directory { state, .. } => state,
        }
    }

    /// Returns mutable shared handle state.
    const fn state_mut(&mut self) -> &mut OpenedHandleState {
        match self {
            Self::File(state) | Self::Symlink(state) | Self::Directory { state, .. } => state,
        }
    }
}

/// FILE_OBJECT whose FCB and CCB contexts have both been initialized by create.
#[derive(Debug)]
pub(crate) struct OpenedObject {
    /// Kernel FILE_OBJECT carrying the contexts.
    file_object: KernelFileObject,
    /// Shared file control block stored in FsContext.
    fcb: NonNull<FileControlBlock>,
    /// Per-handle context stored in FsContext2.
    handle: NonNull<OpenedHandle>,
}

impl OpenedObject {
    /// Decodes an initialized FILE_OBJECT context pair.
    ///
    /// # Errors
    /// Returns an error when either filesystem context pointer is absent or
    /// when the shared FCB node kind does not match the per-handle state kind.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let object = unsafe {
            // SAFETY: The FILE_OBJECT pointer comes from the active IRP stack
            // and is read only for filesystem-owned context pointers.
            file_object.as_ref()
        };
        let fcb = NonNull::new(object.FsContext.cast::<FileControlBlock>());
        let handle = NonNull::new(object.FsContext2.cast::<OpenedHandle>());
        let (fcb, handle) = match (fcb, handle) {
            (Some(fcb), Some(handle)) => (fcb, handle),
            (None, None) => return Err(DriverError::InvalidParameter),
            (Some(_), None) | (None, Some(_)) => {
                KernelWideInconsistency::file_object_context_corruption().bugcheck();
            }
        };
        let opened = Self {
            file_object,
            fcb,
            handle,
        };
        opened.validate_handle_kind()?;
        Ok(opened)
    }

    /// Returns the kernel FILE_OBJECT associated with this opened handle.
    pub(crate) const fn file_object(&self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the mounted VCB pointer owning this opened node.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.file_control_block().volume()
    }

    /// Returns the ext4 node identity owned by the shared FCB.
    pub(crate) fn node(&self) -> NodeId {
        self.file_control_block().node()
    }

    /// Returns the opened path identity.
    pub(crate) fn path(&self) -> &OpenedPath {
        self.handle().path()
    }

    /// Replaces the opened path after a successful rename.
    pub(crate) fn replace_path(&mut self, path: OpenedPath) {
        self.mutable_handle().replace_path(path);
    }

    /// Returns the requested close disposition.
    pub(crate) fn close_disposition(&self) -> CloseDisposition {
        self.handle().close_disposition()
    }

    /// Replaces the requested close disposition.
    pub(crate) fn set_close_disposition(&mut self, close_disposition: CloseDisposition) {
        self.mutable_handle()
            .set_close_disposition(close_disposition);
    }

    /// Converts this opened child state to the symlink produced by reparse SET.
    pub(crate) fn replace_with_symlink(&mut self, symlink: SymlinkNodeId) {
        let fcb = unsafe {
            // SAFETY: This method updates the shared FCB identity and the
            // per-handle variant together, keeping FILE_OBJECT contexts aligned.
            self.fcb.as_mut()
        };
        fcb.node = NodeId::Symlink(symlink);
        self.mutable_handle().replace_with_symlink();
    }

    /// Returns the decoded file control block.
    pub(crate) fn file_control_block(&self) -> &FileControlBlock {
        unsafe {
            // SAFETY: `decode` only constructs this type from a non-null
            // FsContext written by successful create and used during the
            // active FILE_OBJECT lifetime.
            self.fcb.as_ref()
        }
    }

    /// Returns the decoded per-handle state.
    fn handle(&self) -> &OpenedHandle {
        unsafe {
            // SAFETY: `decode` only constructs this type from a non-null
            // FsContext2 written by successful create and used during the
            // active FILE_OBJECT lifetime.
            self.handle.as_ref()
        }
    }

    /// Returns mutable per-handle state for atomic state transitions.
    fn mutable_handle(&mut self) -> &mut OpenedHandle {
        unsafe {
            // SAFETY: Mutating handle-local state is limited to `OpenedObject`
            // methods that keep it aligned with the FCB node kind.
            self.handle.as_mut()
        }
    }

    /// Rejects corrupted FILE_OBJECT contexts whose FCB and handle kind disagree.
    ///
    /// # Errors
    /// Returns an error when FCB node identity and handle variant encode
    /// different node kinds.
    fn validate_handle_kind(&self) -> DriverResult<()> {
        match (self.node(), self.handle()) {
            (NodeId::File(_), OpenedHandle::File(_))
            | (NodeId::Directory(_), OpenedHandle::Directory { .. })
            | (NodeId::Symlink(_), OpenedHandle::Symlink(_)) => Ok(()),
            _ => KernelWideInconsistency::file_object_context_corruption().bugcheck(),
        }
    }
}

#[derive(Debug)]
/// Opened regular file decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedRegularFile {
    /// Opened object context validated as a regular file.
    opened: OpenedObject,
    /// Typed file node identity.
    id: FileNodeId,
}

impl OpenedRegularFile {
    /// Decodes an opened FILE_OBJECT and requires a regular-file node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a regular file.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let opened = OpenedObject::decode(file_object)?;
        let NodeId::File(id) = opened.node() else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        Ok(Self { opened, id })
    }

    /// Returns the typed regular-file identity.
    pub(crate) const fn id(&self) -> FileNodeId {
        self.id
    }

    /// Returns the mounted VCB pointer owning this opened file.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.opened.volume()
    }
}

#[derive(Debug)]
/// Opened directory decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedDirectory {
    /// Opened object context validated as a directory.
    opened: OpenedObject,
    /// Typed directory node identity.
    id: DirectoryNodeId,
    /// Directory cursor stored in the directory handle variant.
    cursor: NonNull<DirectoryCursor>,
}

impl OpenedDirectory {
    /// Decodes an opened FILE_OBJECT and requires a directory node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a directory.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let mut opened = OpenedObject::decode(file_object)?;
        let NodeId::Directory(id) = opened.node() else {
            return Err(DriverError::from(ext4_core::Error::WrongInodeKind));
        };
        let OpenedHandle::Directory { cursor, .. } = opened.mutable_handle() else {
            return Err(DriverError::InvalidParameter);
        };
        let cursor = NonNull::from(cursor);
        Ok(Self { opened, id, cursor })
    }

    /// Returns the typed directory identity.
    pub(crate) const fn id(&self) -> DirectoryNodeId {
        self.id
    }

    /// Returns the mounted VCB pointer owning this opened directory.
    pub(crate) fn volume(&self) -> NonNull<VolumeControlBlock> {
        self.opened.volume()
    }

    /// Returns the mutable directory enumeration cursor.
    pub(crate) fn cursor_mut(&mut self) -> &mut DirectoryCursor {
        unsafe {
            // SAFETY: `cursor` points into the live directory handle variant
            // validated during decode. This type exposes no variant-changing
            // operation.
            self.cursor.as_mut()
        }
    }
}

#[derive(Debug)]
/// Opened symbolic link decoded from a FILE_OBJECT context pair.
pub(crate) struct OpenedSymlink {
    /// Opened object context validated as a symlink.
    opened: OpenedObject,
    /// Typed symlink node identity.
    id: SymlinkNodeId,
}

impl OpenedSymlink {
    /// Decodes an opened FILE_OBJECT and requires a symbolic-link node.
    ///
    /// # Errors
    /// Returns an error when the FILE_OBJECT contexts are invalid or when the
    /// opened node is not a symbolic link.
    pub(crate) fn decode(file_object: KernelFileObject) -> DriverResult<Self> {
        let opened = OpenedObject::decode(file_object)?;
        let NodeId::Symlink(id) = opened.node() else {
            return Err(DriverError::NotAReparsePoint);
        };
        Ok(Self { opened, id })
    }

    /// Returns the typed symlink identity.
    pub(crate) const fn id(&self) -> SymlinkNodeId {
        self.id
    }

    /// Returns the shared file control block.
    pub(crate) fn file_control_block(&self) -> &FileControlBlock {
        self.opened.file_control_block()
    }
}

/// Releases one FILE_OBJECT reference to a VCB-owned FCB.
pub(crate) fn release_file_control_block(fcb: NonNull<FileControlBlock>) {
    let mut volume = unsafe {
        // SAFETY: FCBs are owned by the VCB recorded in the FCB itself.
        fcb.as_ref().volume()
    };
    let vcb = unsafe {
        // SAFETY: The VCB outlives all FCBs it owns.
        volume.as_mut()
    };
    vcb.close_file_control_block(fcb);
}

/// Driver unload callback registered in the driver object.
///
/// # Safety
/// The I/O Manager must call this only as the registered unload routine for this driver object,
/// after no dispatch callbacks can still use the control device being unregistered.
pub(crate) unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    let control_device = core::ptr::addr_of_mut!(CONTROL_DEVICE);
    let device = unsafe {
        // SAFETY: `control_device` points to the driver-owned global state.
        // Replacement takes ownership of the registered device for teardown.
        core::ptr::replace(control_device, None)
    };
    if let Some(device) = device {
        let device = device.as_ptr();
        unsafe {
            // SAFETY: The device was created and registered by DriverEntry.
            ffi::IoUnregisterFileSystem(device);
        }
        unsafe {
            // SAFETY: The device is no longer registered and is owned by this driver.
            ffi::IoDeleteDevice(device);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU32;
    use core::ptr::NonNull;

    use ext4_core::{DirectoryNodeId, NodeId};

    use crate::irp::DirectoryEntryIndex;
    use crate::kernel::status::DriverError;

    use super::{
        CloseDisposition, FileControlBlock, FileControlBlockRelease, KernelFileObject,
        OpenedDirectory, OpenedHandle, OpenedObject, OpenedPath, OpenedRegularFile, OpenedSymlink,
        UninitializedFileObject, VolumeControlBlock,
    };

    fn file_object_with_contexts(
        fs_context: *mut core::ffi::c_void,
        fs_context2: *mut core::ffi::c_void,
    ) -> wdk_sys::FILE_OBJECT {
        wdk_sys::FILE_OBJECT {
            FsContext: fs_context,
            FsContext2: fs_context2,
            ..wdk_sys::FILE_OBJECT::default()
        }
    }

    /// Builds the typed FILE_OBJECT boundary from a local non-null test object.
    fn kernel_file_object(file: &mut wdk_sys::FILE_OBJECT) -> Option<KernelFileObject> {
        KernelFileObject::from_raw(core::ptr::addr_of_mut!(*file))
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn kernel_file_object_rejects_null_raw_pointer() {
        assert_eq!(KernelFileObject::from_raw(core::ptr::null_mut()), None);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn unopened_object_without_contexts_is_invalid_parameter() {
        let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert_eq!(
            OpenedObject::decode(file_object).err(),
            Some(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn typed_opened_directory_exposes_cursor_without_option() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedPath::Root,
            CloseDisposition::Keep,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let directory = OpenedDirectory::decode(file_object);
        assert!(directory.is_ok());
        let Ok(mut directory) = directory else {
            return;
        };

        assert_eq!(directory.id(), DirectoryNodeId::ROOT);
        assert_eq!(
            directory.cursor_mut().next_entry(),
            DirectoryEntryIndex::from_u32(0)
        );
        directory
            .cursor_mut()
            .seek(DirectoryEntryIndex::from_u32(7));
        assert_eq!(
            directory.cursor_mut().next_entry(),
            DirectoryEntryIndex::from_u32(7)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn typed_opened_decoders_reject_wrong_node_kind() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedPath::Root,
            CloseDisposition::Keep,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert_eq!(
            OpenedRegularFile::decode(file_object).err(),
            Some(DriverError::Core(ext4_core::Error::WrongInodeKind))
        );
        assert_eq!(
            OpenedSymlink::decode(file_object).err(),
            Some(DriverError::NotAReparsePoint)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_object_updates_close_disposition() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedPath::Root,
            CloseDisposition::Keep,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        let Ok(mut opened) = opened else {
            return;
        };

        opened.set_close_disposition(CloseDisposition::Delete);
        assert_eq!(opened.close_disposition(), CloseDisposition::Delete);
        opened.set_close_disposition(CloseDisposition::Keep);
        assert_eq!(opened.close_disposition(), CloseDisposition::Keep);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_object_symlink_conversion_updates_fcb_and_handle_together() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        let mut handle = OpenedHandle::new(
            NodeId::Directory(DirectoryNodeId::ROOT),
            OpenedPath::Root,
            CloseDisposition::Delete,
        );
        let mut file = file_object_with_contexts(
            core::ptr::addr_of_mut!(fcb).cast(),
            core::ptr::addr_of_mut!(handle).cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        let opened = OpenedObject::decode(file_object);
        assert!(opened.is_ok());
        let Ok(mut opened) = opened else {
            return;
        };
        let symlink = unsafe {
            // SAFETY: `SymlinkNodeId` is an opaque integer identity wrapper.
            // This unit test never sends the fabricated id into ext4-core; it
            // only verifies that one atomic state method updates both local
            // FILE_OBJECT contexts to the same supplied identity.
            core::mem::zeroed()
        };

        opened.replace_with_symlink(symlink);

        assert_eq!(opened.node(), NodeId::Symlink(symlink));
        assert_eq!(opened.close_disposition(), CloseDisposition::Delete);
        assert!(matches!(handle, OpenedHandle::Symlink(_)));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn uninitialized_file_object_rejects_existing_contexts() {
        let mut file = file_object_with_contexts(core::ptr::null_mut(), core::ptr::null_mut());
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };

        assert!(UninitializedFileObject::decode(file_object).is_ok());

        let mut file = file_object_with_contexts(
            NonNull::<FileControlBlock>::dangling().as_ptr().cast(),
            core::ptr::null_mut(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        assert_eq!(
            UninitializedFileObject::decode(file_object),
            Err(DriverError::InvalidParameter)
        );

        let mut file = file_object_with_contexts(
            core::ptr::null_mut(),
            NonNull::<super::OpenedHandle>::dangling().as_ptr().cast(),
        );
        let file_object = kernel_file_object(&mut file);
        assert!(file_object.is_some());
        let Some(file_object) = file_object else {
            return;
        };
        assert_eq!(
            UninitializedFileObject::decode(file_object),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_open_count_cannot_represent_zero() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));

        assert_eq!(fcb.open_count.get(), 1);
        assert_eq!(fcb.add_open_reference(), Ok(()));
        assert_eq!(fcb.open_count.get(), 2);
        assert_eq!(
            fcb.release_open_reference(),
            FileControlBlockRelease::StillOpen
        );
        assert_eq!(fcb.open_count.get(), 1);
        assert_eq!(
            fcb.release_open_reference(),
            FileControlBlockRelease::LastReference
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_open_count_overflow_is_typed() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let mut fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));
        fcb.open_count = NonZeroU32::MAX;

        assert_eq!(
            fcb.add_open_reference(),
            Err(DriverError::TooManyOpenReferences)
        );
        assert_eq!(fcb.open_count, NonZeroU32::MAX);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_starts_with_empty_share_access() {
        let volume = NonNull::<VolumeControlBlock>::dangling();
        let fcb = FileControlBlock::new(volume, NodeId::Directory(DirectoryNodeId::ROOT));

        assert_eq!(fcb.share_access.OpenCount, 0);
        assert_eq!(fcb.share_access.Readers, 0);
        assert_eq!(fcb.share_access.Writers, 0);
        assert_eq!(fcb.share_access.Deleters, 0);
        assert_eq!(fcb.share_access.SharedRead, 0);
        assert_eq!(fcb.share_access.SharedWrite, 0);
        assert_eq!(fcb.share_access.SharedDelete, 0);
    }
}
