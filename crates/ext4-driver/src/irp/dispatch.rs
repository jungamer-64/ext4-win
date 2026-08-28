//! Major-function classification and decoded dispatch targets.

use super::*;

/// IRP major-function slot owned by the ext4win dispatch boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchMajor {
    /// Create/open request.
    Create,
    /// Close request.
    Close,
    /// Cleanup request.
    Cleanup,
    /// Read request.
    Read,
    /// Write request.
    Write,
    /// File information query.
    QueryInformation,
    /// File information mutation.
    SetInformation,
    /// Volume information query.
    QueryVolumeInformation,
    /// Volume information mutation.
    SetVolumeInformation,
    /// Directory enumeration or notification request.
    DirectoryControl,
    /// File-system control request.
    FileSystemControl,
    /// Device control request.
    DeviceControl,
    /// Flush request.
    FlushBuffers,
    /// Extended-attribute query.
    QueryEa,
    /// Extended-attribute mutation.
    SetEa,
    /// Byte-range lock request.
    LockControl,
    /// Shutdown notification.
    Shutdown,
    /// Security descriptor query.
    QuerySecurity,
    /// Security descriptor mutation.
    SetSecurity,
}

impl DispatchMajor {
    /// Returns the index into `DRIVER_OBJECT::MajorFunction`.
    pub(crate) const fn table_index(self) -> usize {
        match self {
            Self::Create => 0x00,
            Self::Close => 0x02,
            Self::Read => 0x03,
            Self::Write => 0x04,
            Self::QueryInformation => 0x05,
            Self::SetInformation => 0x06,
            Self::QueryEa => 0x07,
            Self::SetEa => 0x08,
            Self::FlushBuffers => 0x09,
            Self::QueryVolumeInformation => 0x0A,
            Self::SetVolumeInformation => 0x0B,
            Self::DirectoryControl => 0x0C,
            Self::FileSystemControl => 0x0D,
            Self::DeviceControl => 0x0E,
            Self::Shutdown => 0x10,
            Self::LockControl => 0x11,
            Self::Cleanup => 0x12,
            Self::QuerySecurity => 0x14,
            Self::SetSecurity => 0x15,
        }
    }
}

/// Origin of a read or write IRP after raw IRP flags are decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataIoKind {
    /// Normal file-handle I/O participates in per-handle file-position semantics.
    Handle,
    /// Paging I/O uses only its explicit byte range and never changes the handle position.
    Paging,
}

/// Non-null dispatch target decoded from raw WDK callback inputs.
#[derive(Debug)]
pub(crate) struct DispatchTarget {
    /// Device object receiving the IRP.
    pub(super) device: KernelDevice,
    /// IRP being dispatched.
    pub(super) irp: KernelIrp,
}

impl DispatchTarget {
    /// Decodes raw WDK dispatch pointers.
    /// # Safety
    ///
    /// The pointers must identify the live device and IRP supplied for the active WDK dispatch
    /// callback. The caller must retain both until completion ownership is transferred or consumed.
    /// # Errors
    ///
    /// Returns an error when either the device object or IRP pointer is null.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn decode(device: PDEVICE_OBJECT, irp: PIRP) -> Result<Self, DriverError> {
        // SAFETY: The caller guarantees that every non-null callback device remains live.
        let Some(device) = (unsafe { KernelDevice::from_raw(device) }) else {
            return Err(DriverError::InvalidParameter);
        };
        // SAFETY: The caller guarantees that every non-null callback IRP remains live.
        let Some(irp) = (unsafe { KernelIrp::from_raw(irp) }) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { device, irp })
    }

    /// Borrows the live IRP only while its completion owner remains exclusively borrowed.
    pub(super) fn active(&mut self) -> ActiveIrp<'_> {
        ActiveIrp {
            device: self.device,
            irp: self.irp.irp,
            owner: core::marker::PhantomData,
        }
    }

    /// Consumes terminal completion ownership and yields the raw IRP to a native subsystem.
    #[cfg(not(test))]
    pub(crate) fn into_raw_irp(self) -> PIRP {
        self.irp.as_ptr()
    }
}
