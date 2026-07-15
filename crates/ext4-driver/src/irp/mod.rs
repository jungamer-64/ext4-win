//! Typed IRP boundary shared by FSD dispatch modules.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;

use ext4_core::FileOffset;
use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP, STATUS_PENDING, STATUS_SUCCESS};

mod capture;
mod executor;

use capture::QueueContext;
pub(crate) use capture::{CapturedQuerySecurityOutput, PreparedRequestKind};
pub(crate) use executor::DeviceExecutor;

#[cfg(not(test))]
use crate::kernel::ffi;
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory;
use crate::security_descriptor::SecuritySelection;
use crate::state::{
    DirectoryChangeNotifier, DirectoryNotificationRegistration, FileControlBlock, KernelDevice,
    KernelFileObject, KernelVpb, WriteCommitment,
};
use crate::wire::{LittleEndianInput, WireOffset};

/// Completion priority boost for IRPs that should not adjust thread priority.
#[cfg(not(test))]
const IO_NO_INCREMENT_PRIORITY: wdk_sys::CCHAR = 0;

/// `STATUS_CANCELLED` is not emitted by the current `wdk-sys` bindings.
const STATUS_CANCELLED: NTSTATUS = i32::from_ne_bytes(0xC000_0120_u32.to_ne_bytes());

/// Byte count completed in `IO_STATUS_BLOCK::Information`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InformationLength {
    /// WDK-sized information payload.
    bytes: wdk_sys::ULONG_PTR,
}

impl InformationLength {
    /// Zero-byte completion.
    pub(crate) const ZERO: Self = Self { bytes: 0 };

    /// Builds an information length from a Rust byte count.
    /// # Errors
    ///
    /// Returns an error when `bytes` cannot be represented in `IO_STATUS_BLOCK::Information`.
    pub(crate) fn from_usize(bytes: usize) -> DriverResult<Self> {
        Ok(Self {
            bytes: wdk_sys::ULONG_PTR::try_from(bytes)
                .map_err(|_| DriverError::InvalidParameter)?,
        })
    }

    /// Returns the WDK payload for the IRP boundary.
    const fn as_ulong_ptr(self) -> wdk_sys::ULONG_PTR {
        self.bytes
    }
}

/// Complete IRP status block payload at the NTSTATUS dispatch boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IrpCompletion {
    /// NTSTATUS returned to the I/O Manager.
    status: NTSTATUS,
    /// Completed information byte count.
    information: InformationLength,
}

impl IrpCompletion {
    /// Successful completion without output bytes.
    pub(crate) const EMPTY: Self = Self {
        status: STATUS_SUCCESS,
        information: InformationLength::ZERO,
    };

    /// Builds a successful completion from an information length.
    pub(crate) const fn with_information(information: InformationLength) -> Self {
        Self {
            status: STATUS_SUCCESS,
            information,
        }
    }

    /// Builds a successful completion from a Rust byte count.
    /// # Errors
    ///
    /// Returns an error when `bytes` cannot be represented in the IRP information field.
    pub(crate) fn from_usize(bytes: usize) -> DriverResult<Self> {
        Ok(Self::with_information(InformationLength::from_usize(
            bytes,
        )?))
    }

    /// Converts a driver error into a completed failed IRP payload.
    pub(crate) fn from_error(error: DriverError) -> Self {
        Self {
            status: error.ntstatus(),
            information: InformationLength::ZERO,
        }
    }

    /// Preserves one failed status raised by the native requestor-memory capture boundary.
    const fn from_native_failure(status: NTSTATUS) -> Self {
        Self {
            status,
            information: InformationLength::ZERO,
        }
    }

    /// Builds the query-security compatibility result for an undersized output buffer.
    /// # Errors
    ///
    /// Returns an error when `required` cannot be represented in the IRP information field.
    pub(crate) fn security_buffer_overflow(required: usize) -> DriverResult<Self> {
        Ok(Self {
            status: DriverError::BufferOverflow.ntstatus(),
            information: InformationLength::from_usize(required)?,
        })
    }

    /// Builds a canceled IRP completion payload.
    const fn cancelled() -> Self {
        Self {
            status: STATUS_CANCELLED,
            information: InformationLength::ZERO,
        }
    }

    /// Returns the NTSTATUS for the IRP status block and dispatch return.
    const fn status(self) -> NTSTATUS {
        self.status
    }

    /// Returns the typed information length.
    const fn information(self) -> InformationLength {
        self.information
    }
}

/// Owned, exact-length symbolic-link buffer returned to the I/O Manager for create-name reparsing.
///
/// Dropping this value releases the allocation. Ownership leaves Rust only when a successful
/// create symlink completion installs the allocation in `IRP::Tail.Overlay.AuxiliaryBuffer`.
#[derive(Debug)]
pub(crate) struct CreateSymlinkReparseBuffer {
    /// Nonpaged bytes in driver builds and ordinary globally allocated bytes in tests.
    bytes: Box<[u8]>,
}

impl CreateSymlinkReparseBuffer {
    /// Allocates, packs, and seals one exact-length symbolic-link reparse buffer.
    /// # Errors
    ///
    /// Returns an error when `length` is zero or not representable, allocation or packing fails,
    /// the packer writes a different length, or the completed header is not an exact symlink
    /// reparse buffer.
    pub(crate) fn try_pack_exact(
        length: usize,
        pack: impl FnOnce(&mut [u8]) -> DriverResult<usize>,
    ) -> DriverResult<Self> {
        if length == 0 {
            return Err(DriverError::InvalidBufferSize);
        }
        let mut bytes = memory::boxed_zeroed_bytes(length)?;
        if pack(&mut bytes)? != length {
            return Err(DriverError::InternalInvariantViolation);
        }
        Self::validate_header(&bytes)?;
        Ok(Self { bytes })
    }

    /// Transfers the allocation as the thin pool pointer expected by the IRP auxiliary field.
    fn into_raw(self) -> *mut wdk_sys::CHAR {
        Box::into_raw(self.bytes)
            .cast::<u8>()
            .cast::<wdk_sys::CHAR>()
    }

    /// Verifies the tag and exact `ReparseDataLength` before the buffer becomes completable.
    /// # Errors
    ///
    /// Returns an internal-invariant error when the packed header is truncated, uses another tag,
    /// exceeds the Windows reparse limit, or declares a non-exact payload length.
    fn validate_header(bytes: &[u8]) -> DriverResult<()> {
        const REPARSE_HEADER_LENGTH: usize = 8;
        const SYMLINK_PAYLOAD_HEADER_LENGTH: usize = 12;

        let maximum_length = usize::try_from(wdk_sys::MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if bytes.len() > maximum_length {
            return Err(DriverError::InternalInvariantViolation);
        }
        let input = LittleEndianInput::new(bytes);
        let tag = input
            .read_u32(WireOffset::new(0))
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        if tag != wdk_sys::IO_REPARSE_TAG_SYMLINK {
            return Err(DriverError::InternalInvariantViolation);
        }
        let data_length = usize::from(
            input
                .read_u16(WireOffset::new(4))
                .map_err(|_| DriverError::InternalInvariantViolation)?,
        );
        if data_length < SYMLINK_PAYLOAD_HEADER_LENGTH
            || REPARSE_HEADER_LENGTH.checked_add(data_length) != Some(bytes.len())
        {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(())
    }
}

/// Mutually exclusive terminal outcomes of a create/open request.
#[derive(Debug)]
#[must_use]
pub(crate) enum CreateCompletion {
    /// A handle was established with one exact Windows create action.
    Handle(CreateAction),
    /// Name resolution must continue through the Microsoft symbolic-link reparse handler.
    ReparseSymlink(CreateSymlinkReparseBuffer),
}

/// Successful Windows create action stored in `IO_STATUS_BLOCK::Information`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateAction {
    /// An existing object was opened without destructive mutation.
    Opened,
    /// A missing object was created.
    Created,
}

impl CreateAction {
    /// Returns the WDK `FILE_*` create action value.
    const fn as_ulong(self) -> wdk_sys::ULONG {
        match self {
            Self::Opened => wdk_sys::FILE_OPENED,
            Self::Created => wdk_sys::FILE_CREATED,
        }
    }
}

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
#[derive(Clone, Copy, Debug)]
pub(crate) struct DispatchTarget {
    /// Device object receiving the IRP.
    device: KernelDevice,
    /// IRP being dispatched.
    irp: KernelIrp,
}

// SAFETY: The I/O Manager keeps both kernel objects alive while the driver owns the pending IRP,
// and the device executor transfers this pointer-only boundary between workers without concurrent
// request execution.
unsafe impl Send for DispatchTarget {}

impl DispatchTarget {
    /// Decodes raw WDK dispatch pointers.
    /// # Errors
    ///
    /// Returns an error when either the device object or IRP pointer is null.
    pub(crate) fn decode(device: PDEVICE_OBJECT, irp: PIRP) -> Result<Self, DriverError> {
        let Some(device) = KernelDevice::from_raw(device) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(irp) = KernelIrp::from_raw(irp) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { device, irp })
    }

    /// Returns the typed device object boundary.
    pub(crate) const fn device(self) -> KernelDevice {
        self.device
    }

    /// Returns whether this request is normal handle I/O or paging I/O.
    pub(crate) fn data_io_kind(self) -> DataIoKind {
        let irp = unsafe {
            // SAFETY: The dispatch target retains the live IRP for the active
            // callback or queue-owned request lifetime.
            self.irp.as_ref()
        };
        if irp.Flags & wdk_sys::IRP_PAGING_IO == 0 {
            DataIoKind::Handle
        } else {
            DataIoKind::Paging
        }
    }

    /// Returns the live raw IRP pointer for a kernel helper that owns this request's semantics.
    #[cfg(not(test))]
    pub(crate) fn as_raw_irp(self) -> PIRP {
        self.irp.as_ptr()
    }

    /// Returns METHOD_BUFFERED input bytes from the IRP system buffer.
    /// # Errors
    ///
    /// Returns an error when the associated system buffer is null or `length` exceeds the slice
    /// domain.
    pub(crate) fn buffered_input(
        self,
        length: IrpBufferLength,
    ) -> Result<BufferedInput, DriverError> {
        BufferedInput::new(self.associated_system_buffer()?, length.as_usize())
    }

    /// Returns METHOD_BUFFERED output bytes from the IRP system buffer.
    /// # Errors
    ///
    /// Returns an error when the associated system buffer is null or `length` exceeds the slice
    /// domain.
    pub(crate) fn buffered_output(
        self,
        length: IrpBufferLength,
    ) -> Result<BufferedOutput, DriverError> {
        BufferedOutput::new(self.associated_system_buffer()?, length.as_usize())
    }

    /// Returns read-like IRP data bytes as immutable kernel memory.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL can provide `length` input
    /// bytes.
    pub(crate) fn data_input(self, length: IrpBufferLength) -> Result<BufferedInput, DriverError> {
        BufferedInput::new(self.data_buffer_address(length)?, length.as_usize())
    }

    /// Returns write-like IRP data bytes as mutable kernel memory.
    /// # Errors
    ///
    /// Returns an error when neither a system buffer nor a mapped MDL can provide `length` output
    /// bytes.
    pub(crate) fn data_output(
        self,
        length: IrpBufferLength,
    ) -> Result<BufferedOutput, DriverError> {
        BufferedOutput::new(self.data_buffer_address(length)?, length.as_usize())
    }

    /// Returns the buffered I/O system buffer address for this IRP.
    /// # Errors
    ///
    /// Returns an error when `AssociatedIrp.SystemBuffer` is null.
    fn associated_system_buffer(self) -> Result<NonNull<u8>, DriverError> {
        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.irp.as_ref() };
        let system_buffer = unsafe {
            // SAFETY: SystemBuffer is the active AssociatedIrp arm for
            // buffered requests delivered to this driver.
            irp.AssociatedIrp.SystemBuffer
        };
        NonNull::new(system_buffer)
            .map(NonNull::cast)
            .ok_or(DriverError::InvalidParameter)
    }

    /// Returns the read/write IRP data buffer address as kernel memory.
    /// # Errors
    ///
    /// Returns an error when the system buffer is unavailable and the IRP has no usable MDL mapping.
    fn data_buffer_address(self, length: IrpBufferLength) -> Result<NonNull<u8>, DriverError> {
        if let Ok(system_buffer) = self.associated_system_buffer() {
            return Ok(system_buffer);
        }

        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.irp.as_ref() };
        let Some(mdl) = NonNull::new(irp.MdlAddress) else {
            return Err(DriverError::InvalidParameter);
        };
        mdl_data_buffer_address(mdl, length)
    }

    /// Returns the current stack location selected by the I/O Manager.
    /// # Errors
    ///
    /// Returns an error when the IRP current stack location pointer is null.
    pub(crate) fn current_stack(self) -> Result<CurrentIrpStackLocation, DriverError> {
        self.irp.current_stack()
    }
}

/// IRP received by a dispatch callback before its completion policy is selected.
#[derive(Debug)]
#[must_use]
pub(crate) struct ReceivedIrp {
    /// Target decoded from the raw dispatch ABI.
    target: DispatchTarget,
}

impl ReceivedIrp {
    /// Decodes raw WDK dispatch pointers into a received IRP.
    /// # Errors
    ///
    /// Returns an error when either the device object or IRP pointer is null.
    pub(crate) fn decode(device: PDEVICE_OBJECT, irp: PIRP) -> DriverResult<Self> {
        Ok(Self {
            target: DispatchTarget::decode(device, irp)?,
        })
    }

    /// Returns the dispatch target for stack and buffer decoding.
    pub(crate) const fn target(&self) -> DispatchTarget {
        self.target
    }

    /// Returns the target device that received this IRP.
    pub(crate) const fn device(&self) -> KernelDevice {
        self.target.device
    }

    /// Completes this received IRP immediately.
    pub(crate) fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        self.target.irp.complete(completion)
    }

    /// Completes this received IRP from a fallible request result.
    pub(crate) fn complete_result(self, result: DriverResult<IrpCompletion>) -> NTSTATUS {
        self.complete(match result {
            Ok(completion) => completion,
            Err(error) => IrpCompletion::from_error(error),
        })
    }

    /// Transfers this lock-control IRP's terminal completion authority to FsRtl.
    ///
    /// FsRtl completes lock requests itself, including requests that wait for a conflicting range.
    /// This consuming transition prevents the normal driver completion path from completing the
    /// same IRP again.
    pub(crate) fn delegate_byte_range_lock(
        self,
        file_control_block: &FileControlBlock,
    ) -> NTSTATUS {
        file_control_block.process_byte_range_lock(self.target)
    }

    /// Completes a raw IRP when dispatch-target decoding failed.
    pub(crate) fn complete_decode_error(irp: PIRP, error: DriverError) -> NTSTATUS {
        let completion = IrpCompletion::from_error(error);
        if let Some(irp) = KernelIrp::from_raw(irp) {
            return irp.complete(completion);
        }
        completion.status()
    }
}

/// Prepared IRP ready to transfer into the cancel-safe queue.
#[derive(Debug)]
#[must_use]
struct PendingIrp {
    /// Dispatch target whose completion authority transfers with queue insertion.
    target: DispatchTarget,
    /// Requestor-context capture transferred through `DriverContext[0]` before insertion.
    context: Box<QueueContext>,
}

impl PendingIrp {
    /// Joins the received completion authority with its fully captured queue context.
    const fn from_received(received: ReceivedIrp, context: Box<QueueContext>) -> Self {
        Self {
            target: received.target,
            context,
        }
    }

    /// Publishes the context into `DriverContext[0]` and transfers queue ownership.
    fn publish(self) -> PIRP {
        self.target.irp.publish_queue_context(self.context);
        self.target.irp.as_ptr()
    }

    /// Returns the status dispatch must return after this IRP has been pended.
    const fn dispatch_status(&self) -> NTSTATUS {
        STATUS_PENDING
    }
}

/// Unique IRP completion authority held by queue, worker, and immediate paths.
#[derive(Debug)]
#[must_use]
pub(crate) struct OwnedIrp {
    /// Target whose IRP can be completed exactly once by this owner.
    target: DispatchTarget,
    /// Request capture removed exactly once from `DriverContext[0]` with queue ownership.
    context: Box<QueueContext>,
}

/// Exclusive borrow of one pending IRP while its executor task decodes or awaits request state.
#[derive(Debug)]
pub(crate) struct PendingIrpLease<'a> {
    /// Completion owner retained mutably so the IRP cannot complete while derived pointers live.
    owner: &'a mut OwnedIrp,
}

impl<'a> PendingIrpLease<'a> {
    /// Returns the pending dispatch target whose kernel objects remain pinned by this lease.
    pub(crate) const fn target(&self) -> DispatchTarget {
        self.owner.target
    }

    /// Borrows the opaque query-security output target for the lifetime of this pending request.
    /// # Errors
    ///
    /// Returns an invariant error when the queued request was not prepared as query-security.
    pub(crate) fn query_security_parts(
        self,
    ) -> DriverResult<(
        KernelFileObject,
        SecuritySelection,
        &'a mut CapturedQuerySecurityOutput,
    )> {
        self.owner.context.query_security_parts()
    }

    /// Borrows the owned set-security descriptor for the lifetime of this pending request.
    /// # Errors
    ///
    /// Returns an invariant error when the queued request was not prepared as set-security.
    pub(crate) fn set_security_parts(
        self,
    ) -> DriverResult<(KernelFileObject, SecuritySelection, &'a [u8])> {
        self.owner.context.set_security_parts()
    }
}

impl OwnedIrp {
    /// Takes queue context and terminal completion authority from one exclusively removed IRP.
    fn from_queued_raw(device: KernelDevice, irp: PIRP) -> Self {
        let Some(irp) = KernelIrp::from_raw(irp) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        let context = irp.take_queue_context();
        Self {
            target: DispatchTarget { device, irp },
            context,
        }
    }

    /// Builds queued ownership directly for completion-focused unit tests.
    #[cfg(test)]
    fn from_test_raw(device: KernelDevice, irp: PIRP) -> Option<Self> {
        let irp = KernelIrp::from_raw(irp)?;
        Some(Self {
            target: DispatchTarget { device, irp },
            context: QueueContext::for_test_create().ok()?,
        })
    }

    /// Returns the dispatch target for request execution.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "queued worker completion is compiled out in unit tests"
        )
    )]
    pub(crate) const fn target(&self) -> DispatchTarget {
        self.target
    }

    /// Returns the execution selector sealed before queue insertion.
    pub(crate) const fn prepared_kind(&self) -> PreparedRequestKind {
        self.context.kind()
    }

    /// Borrows this pending IRP as an active request without releasing completion authority.
    pub(crate) const fn request(&mut self) -> PendingIrpLease<'_> {
        PendingIrpLease { owner: self }
    }

    /// Completes the IRP through the I/O Manager.
    pub(crate) fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        let Self { target, context } = self;
        drop(context);
        target.irp.complete(completion)
    }

    /// Completes the IRP from a fallible request result.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "queued worker completion is compiled out in unit tests"
        )
    )]
    pub(crate) fn complete_result(self, result: DriverResult<IrpCompletion>) -> NTSTATUS {
        self.complete(match result {
            Ok(completion) => completion,
            Err(error) => IrpCompletion::from_error(error),
        })
    }

    /// Completes a create IRP from its ownership-bearing, mutually exclusive result.
    ///
    /// A successful reparse transfers the auxiliary buffer to the I/O Manager immediately before
    /// completing with `STATUS_REPARSE`. Failed results never transfer an allocation.
    pub(crate) fn complete_create_result(self, result: DriverResult<CreateCompletion>) -> NTSTATUS {
        let Self { target, context } = self;
        drop(context);
        match result {
            Ok(CreateCompletion::Handle(action)) => target.irp.complete_create_action(action),
            Ok(CreateCompletion::ReparseSymlink(buffer)) => {
                target.irp.complete_create_symlink_reparse(buffer)
            }
            Err(error) => target.irp.complete(IrpCompletion::from_error(error)),
        }
    }

    /// Transfers this queued directory-change IRP's terminal completion authority to FsRtl.
    pub(crate) fn delegate_directory_notification(
        self,
        notifier: &DirectoryChangeNotifier,
        registration: DirectoryNotificationRegistration,
    ) -> NTSTATUS {
        let Self { target, context } = self;
        drop(context);
        match notifier.register(target, registration) {
            Ok(status) => status,
            Err(error) => target.irp.complete(IrpCompletion::from_error(error)),
        }
    }

    /// Completes the IRP as canceled.
    fn complete_cancelled(self) -> NTSTATUS {
        self.complete(IrpCompletion::cancelled())
    }
}

/// Non-null IRP pointer kept private to the typed dispatch boundary.
#[derive(Clone, Copy, Debug)]
struct KernelIrp {
    /// Non-null WDK IRP pointer.
    irp: NonNull<wdk_sys::IRP>,
}

impl KernelIrp {
    /// Converts a raw WDK IRP pointer into the private non-null boundary type.
    fn from_raw(irp: PIRP) -> Option<Self> {
        NonNull::new(irp).map(|irp| Self { irp })
    }

    /// Returns the raw IRP pointer.
    fn as_ptr(self) -> PIRP {
        self.irp.as_ptr()
    }

    /// Returns an immutable IRP reference for active dispatch decoding.
    ///
    /// # Safety
    /// The returned reference must not outlive the WDK dispatch callback that supplied this IRP, and
    /// the caller must not mutate the same IRP through another alias for that lifetime.
    unsafe fn as_ref<'a>(self) -> &'a wdk_sys::IRP {
        unsafe {
            // SAFETY: The caller ties the returned reference to the current WDK
            // dispatch callback that supplied this IRP.
            self.irp.as_ref()
        }
    }

    /// Returns the current stack location selected by the I/O Manager.
    /// # Errors
    ///
    /// Returns an error when the IRP current stack location pointer is null.
    fn current_stack(self) -> Result<CurrentIrpStackLocation, DriverError> {
        // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP pointer.
        let irp = unsafe { self.as_ref() };
        let tail_overlay = unsafe {
            // SAFETY: CurrentStackLocation is stored through the IRP tail
            // overlay for active IRPs delivered to driver dispatch routines.
            irp.Tail.Overlay
        };
        let current_stack = unsafe {
            // SAFETY: The list overlay contains the current stack pointer in
            // active dispatch IRPs.
            tail_overlay
                .__bindgen_anon_2
                .__bindgen_anon_1
                .CurrentStackLocation
        };
        CurrentIrpStackLocation::from_raw(current_stack)
    }

    /// Publishes one queue context into the sole driver-owned IRP context slot.
    fn publish_queue_context(self, context: Box<QueueContext>) {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: Queue preparation retains unique dispatch ownership before CSQ insertion.
            irp.as_mut()
        };
        let overlay = unsafe {
            // SAFETY: Queue metadata and list linkage both use the IRP tail overlay.
            &mut irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: The first nested union arm is reserved for driver-owned context slots;
            // list linkage lives in the independent `overlay.__bindgen_anon_2` field.
            &mut overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        let driver_context = &mut driver_storage.DriverContext;
        if !driver_context[0].is_null() {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        }
        driver_context[0] = Box::into_raw(context).cast::<c_void>();
    }

    /// Takes the context after CSQ removal or cancellation transferred exclusive IRP ownership.
    fn take_queue_context(self) -> Box<QueueContext> {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: The caller has exclusive IRP ownership after atomic CSQ removal.
            irp.as_mut()
        };
        let overlay = unsafe {
            // SAFETY: Exclusive CSQ removal permits mutable access to the IRP tail overlay.
            &mut irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: Queue publication selected the first nested union arm for driver context.
            &mut overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        let driver_context = &mut driver_storage.DriverContext;
        let Some(context) = NonNull::new(driver_context[0].cast::<QueueContext>()) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        driver_context[0] = core::ptr::null_mut();
        unsafe {
            // SAFETY: The slot received this pointer from exactly one `Box::into_raw`, exclusive
            // CSQ removal grants the sole take right, and the slot was cleared before rebuilding.
            Box::from_raw(context.as_ptr())
        }
    }

    /// Borrows queue metadata while the CSQ lock keeps this IRP queued and stable.
    /// # Safety
    ///
    /// The caller must hold the owning CSQ lock and keep this IRP in the queue for the returned
    /// reference's lifetime.
    unsafe fn queue_context<'a>(self) -> &'a QueueContext {
        let irp = unsafe {
            // SAFETY: The CSQ lock retains this queued IRP for the returned callback-local borrow.
            self.as_ref()
        };
        let overlay = unsafe {
            // SAFETY: Queue membership keeps the IRP tail overlay live for this callback.
            &irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: Queue publication selected the first nested union arm for driver context.
            &overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        let driver_context = driver_storage.DriverContext;
        let Some(context) = NonNull::new(driver_context[0].cast::<QueueContext>()) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        unsafe {
            // SAFETY: The context remains Box-owned by this queued IRP and cannot be taken while
            // the CSQ lock grants this callback its immutable queue-membership observation.
            context.as_ref()
        }
    }

    /// Returns the raw IRP pointer for writes to the WDK completion fields.
    #[cfg(not(test))]
    fn as_mut_ptr(self) -> *mut wdk_sys::IRP {
        self.irp.as_ptr()
    }

    /// Writes status and byte count to the IRP status block.
    fn write_status_block(self, completion: IrpCompletion) {
        self.write_status_and_information(
            completion.status(),
            completion.information().as_ulong_ptr(),
        );
    }

    /// Writes the raw WDK completion pair after a typed completion path selected its semantics.
    fn write_status_and_information(self, status: NTSTATUS, information: wdk_sys::ULONG_PTR) {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: `KernelIrp` is constructed only from a non-null raw IRP
            // pointer, and the unique completion path owns terminal-field writes.
            irp.as_mut()
        };
        irp.IoStatus.__bindgen_anon_1.Status = status;
        irp.IoStatus.Information = information;
    }

    /// Installs a Rust-owned create reparse allocation into the IRP tail overlay.
    fn install_create_symlink_reparse_buffer(self, buffer: CreateSymlinkReparseBuffer) {
        let mut irp = self.irp;
        let irp = unsafe {
            // SAFETY: `KernelIrp` retains the non-null active IRP, and unique
            // completion authority permits mutation of its terminal fields.
            irp.as_mut()
        };
        irp.Tail.Overlay.AuxiliaryBuffer = buffer.into_raw();
    }

    /// Invokes the I/O Manager after the unique owner wrote all terminal IRP fields.
    fn finish_completion(self, status: NTSTATUS) -> NTSTATUS {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The IRP pointer belongs to the unique completion owner
            // and the calling completion path wrote every terminal field first.
            ffi::IofCompleteRequest(self.as_mut_ptr(), IO_NO_INCREMENT_PRIORITY);
        }
        status
    }

    /// Transfers a create reparse buffer to the I/O Manager and completes exactly once.
    fn complete_create_symlink_reparse(self, buffer: CreateSymlinkReparseBuffer) -> NTSTATUS {
        // A name-surrogate buffer is identified by its reparse tag. `IO_REPARSE` is reserved for
        // the separate contract where the filesystem has already replaced FILE_OBJECT::FileName.
        let information = wdk_sys::ULONG_PTR::from(wdk_sys::IO_REPARSE_TAG_SYMLINK);
        self.install_create_symlink_reparse_buffer(buffer);
        self.write_status_and_information(wdk_sys::STATUS_REPARSE, information);
        self.finish_completion(wdk_sys::STATUS_REPARSE)
    }

    /// Completes a successful create with its exact `FILE_*` action result.
    fn complete_create_action(self, action: CreateAction) -> NTSTATUS {
        self.write_status_and_information(
            wdk_sys::STATUS_SUCCESS,
            wdk_sys::ULONG_PTR::from(action.as_ulong()),
        );
        self.finish_completion(wdk_sys::STATUS_SUCCESS)
    }

    /// Completes the IRP through the I/O Manager.
    fn complete(self, completion: IrpCompletion) -> NTSTATUS {
        self.write_status_block(completion);
        self.finish_completion(completion.status())
    }
}

/// Non-null current IRP stack location.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentIrpStackLocation {
    /// Current stack location selected by the I/O Manager.
    stack: NonNull<wdk_sys::IO_STACK_LOCATION>,
}

impl CurrentIrpStackLocation {
    /// Decodes a raw stack location pointer.
    /// # Errors
    ///
    /// Returns an error when `stack` is null.
    fn from_raw(stack: PIO_STACK_LOCATION) -> Result<Self, DriverError> {
        let Some(stack) = NonNull::new(stack) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(Self { stack })
    }

    /// Decodes this stack location's filesystem-control minor function.
    pub(crate) fn file_system_control_minor(self) -> FileSystemControlMinorFunction {
        match u32::from(self.raw_minor_function()) {
            MOUNT_VOLUME_MINOR_FUNCTION => FileSystemControlMinorFunction::MountVolume,
            value if value == wdk_sys::IRP_MN_USER_FS_REQUEST => {
                FileSystemControlMinorFunction::UserFsRequest
            }
            _ => FileSystemControlMinorFunction::Unsupported,
        }
    }

    /// Decodes this stack location's directory-control minor function.
    pub(crate) fn directory_control_minor(self) -> DirectoryControlMinorFunction {
        match u32::from(self.raw_minor_function()) {
            value if value == wdk_sys::IRP_MN_QUERY_DIRECTORY => {
                DirectoryControlMinorFunction::QueryDirectory
            }
            value
                if value == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY
                    || value == wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX =>
            {
                DirectoryControlMinorFunction::NotifyChangeDirectory
            }
            _ => DirectoryControlMinorFunction::Unsupported,
        }
    }

    /// Returns the raw minor-function byte for local enum decoding only.
    fn raw_minor_function(self) -> wdk_sys::UCHAR {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        stack.MinorFunction
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    /// # Errors
    ///
    /// Returns an error when the public IRP stack view cannot produce a kernel FILE_OBJECT.
    pub(crate) fn file_object(self) -> Result<KernelFileObject, DriverError> {
        self.kernel_file_object()
    }

    /// Decodes the FILE_OBJECT carried by the current stack location.
    /// # Errors
    ///
    /// Returns an error when the raw `FileObject` pointer in the current stack location is null.
    fn kernel_file_object(self) -> Result<KernelFileObject, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        KernelFileObject::from_raw(stack.FileObject).ok_or(DriverError::InvalidParameter)
    }

    /// Decodes mount-volume parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the VPB or target device object is null, or the output length is not
    /// representable.
    pub(crate) fn mount_volume(self) -> Result<MountVolumeStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let mount = unsafe {
            // SAFETY: The caller has selected this accessor only for
            // IRP_MN_MOUNT_VOLUME, where the MountVolume union arm is active.
            stack.Parameters.MountVolume
        };

        let Some(vpb) = KernelVpb::from_raw(mount.Vpb) else {
            return Err(DriverError::InvalidParameter);
        };
        let Some(target_device) = KernelDevice::from_raw(mount.DeviceObject) else {
            return Err(DriverError::InvalidParameter);
        };

        Ok(MountVolumeStack {
            vpb,
            target_device,
            output_buffer_length: IrpBufferLength::from_ulong(mount.OutputBufferLength)?,
        })
    }

    /// Decodes user file-system-control parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, buffer lengths are invalid, or the FSCTL
    /// code is unsupported.
    pub(crate) fn file_system_control(self) -> Result<FileSystemControlStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let control = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_USER_FS_REQUEST, where FileSystemControl is active.
            stack.Parameters.FileSystemControl
        };
        Ok(FileSystemControlStack {
            file_object: self.kernel_file_object()?,
            input_buffer_length: IrpBufferLength::from_ulong(control.InputBufferLength)?,
            output_buffer_length: IrpBufferLength::from_ulong(control.OutputBufferLength)?,
            fs_control_code: FsControlCode::from_raw(control.FsControlCode)?,
        })
    }

    /// Decodes create/open parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT or security context is absent, EA length is invalid, or
    /// create parameters are unsupported.
    pub(crate) fn create(self) -> Result<CreateStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let create = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_CREATE,
            // where the Create union arm is active.
            stack.Parameters.Create
        };
        let file_object = self.kernel_file_object()?;
        let Some(security_context) = NonNull::new(create.SecurityContext) else {
            return Err(DriverError::InvalidParameter);
        };
        let security_context = unsafe {
            // SAFETY: The I/O manager supplies a live security context for
            // IRP_MJ_CREATE while this stack location is active.
            security_context.as_ref()
        };
        Ok(CreateStack {
            file_object,
            parameters: CreateParameters::decode(
                security_context.DesiredAccess,
                create.Options,
                create.ShareAccess,
                IrpBufferLength::from_ulong(create.EaLength)?,
            )?,
        })
    }

    /// Decodes query-volume-information parameters.
    /// # Errors
    ///
    /// Returns an error when the output length is not representable or the volume information class
    /// is unsupported.
    pub(crate) fn query_volume(self) -> Result<QueryVolumeStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_QUERY_VOLUME_INFORMATION, where QueryVolume is active.
            stack.Parameters.QueryVolume
        };
        Ok(QueryVolumeStack {
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: QueryVolumeInformationClass::from_raw(query.FsInformationClass)?,
        })
    }

    /// Decodes set-volume-information parameters.
    /// # Errors
    ///
    /// Returns an error when the input length is not representable or the volume information class
    /// is unsupported.
    pub(crate) fn set_volume(self) -> Result<SetVolumeStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_SET_VOLUME_INFORMATION, where SetVolume is active.
            stack.Parameters.SetVolume
        };
        Ok(SetVolumeStack {
            length: IrpBufferLength::from_ulong(set.Length)?,
            information_class: SetVolumeInformationClass::from_raw(set.FsInformationClass)?,
        })
    }

    /// Decodes query-file-information parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the output length is invalid, or the file
    /// information class is unsupported.
    pub(crate) fn query_file(self) -> Result<QueryFileStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_QUERY_INFORMATION, where QueryFile is active.
            stack.Parameters.QueryFile
        };
        Ok(QueryFileStack {
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: QueryFileInformationClass::from_raw(query.FileInformationClass)?,
        })
    }

    /// Decodes set-file-information parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the input length is invalid, or the file
    /// information class is unsupported.
    pub(crate) fn set_file(self) -> Result<SetFileStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_SET_INFORMATION, where SetFile is active.
            stack.Parameters.SetFile
        };
        Ok(SetFileStack {
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(set.Length)?,
            information_class: SetFileInformationClass::from_raw(set.FileInformationClass)?,
        })
    }

    /// Decodes query-directory parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, the output length is invalid, or the
    /// directory information class is unsupported.
    pub(crate) fn query_directory(self) -> Result<QueryDirectoryStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_QUERY_DIRECTORY, where QueryDirectory is active.
            stack.Parameters.QueryDirectory
        };
        let pattern = match NonNull::new(query.FileName) {
            Some(file_name) => DirectoryPatternInput::Name(file_name),
            None => DirectoryPatternInput::All,
        };
        let cursor_position = if stack_flag(stack.Flags, wdk_sys::SL_INDEX_SPECIFIED) {
            DirectoryCursorPosition::Index(DirectoryEntryIndex(query.FileIndex))
        } else if stack_flag(stack.Flags, wdk_sys::SL_RESTART_SCAN)
            || matches!(pattern, DirectoryPatternInput::Name(_))
        {
            DirectoryCursorPosition::Restart
        } else {
            DirectoryCursorPosition::Current
        };
        let entry_emission = if stack_flag(stack.Flags, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            DirectoryEntryEmission::Single
        } else {
            DirectoryEntryEmission::Multiple
        };
        Ok(QueryDirectoryStack {
            file_object: self.kernel_file_object()?,
            cursor_position,
            pattern,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
            information_class: DirectoryInformationClass::from_raw(query.FileInformationClass)?,
        })
    }

    /// Decodes directory-change-notification parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent or the notification filter is empty or
    /// contains unsupported bits.
    pub(crate) fn notify_directory(self) -> Result<NotifyDirectoryStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let notify = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MN_NOTIFY_CHANGE_DIRECTORY, where NotifyDirectory is active.
            stack.Parameters.NotifyDirectory
        };
        Ok(NotifyDirectoryStack {
            file_object: self.kernel_file_object()?,
            completion_filter: DirectoryChangeFilter::from_raw(notify.CompletionFilter)?,
            watch_scope: DirectoryWatchScope::from_stack_flags(stack.Flags),
        })
    }

    /// Decodes query-EA parameters.
    /// # Errors
    ///
    /// Returns an error when an EA name list pointer is missing, the FILE_OBJECT is absent, or
    /// buffer lengths are invalid.
    pub(crate) fn query_ea(self) -> Result<QueryEaStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_QUERY_EA,
            // where QueryEa is active.
            stack.Parameters.QueryEa
        };
        let ea_list_length = IrpBufferLength::from_ulong(query.EaListLength)?;
        let selection = if !ea_list_length.is_empty() {
            let Some(address) = NonNull::new(query.EaList.cast::<u8>()) else {
                return Err(DriverError::InvalidParameter);
            };
            EaSelection::Names {
                address,
                length: ea_list_length,
            }
        } else if stack_flag(stack.Flags, wdk_sys::SL_INDEX_SPECIFIED) {
            EaSelection::Index(EaEntryIndex::from_u32(query.EaIndex))
        } else {
            EaSelection::All
        };
        let entry_emission = if stack_flag(stack.Flags, wdk_sys::SL_RETURN_SINGLE_ENTRY) {
            EaEntryEmission::Single
        } else {
            EaEntryEmission::Multiple
        };
        Ok(QueryEaStack {
            file_object: self.kernel_file_object()?,
            selection,
            entry_emission,
            length: IrpBufferLength::from_ulong(query.Length)?,
        })
    }

    /// Decodes set-EA parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent or the set-EA input length is invalid.
    pub(crate) fn set_ea(self) -> Result<SetEaStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_SET_EA,
            // where SetEa is active.
            stack.Parameters.SetEa
        };
        Ok(SetEaStack {
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(set.Length)?,
        })
    }

    /// Decodes query-security parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT is absent, requested security bits are unsupported, or
    /// the output length is invalid.
    pub(crate) fn query_security(self) -> Result<QuerySecurityStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let query = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_QUERY_SECURITY, where QuerySecurity is active.
            stack.Parameters.QuerySecurity
        };
        Ok(QuerySecurityStack {
            file_object: self.kernel_file_object()?,
            selection: SecuritySelection::from_raw(query.SecurityInformation)?,
            length: IrpBufferLength::from_ulong(query.Length)?,
        })
    }

    /// Decodes set-security parameters.
    /// # Errors
    ///
    /// Returns an error when the FILE_OBJECT or security descriptor is absent, or requested security
    /// bits are unsupported.
    pub(crate) fn set_security(self) -> Result<SetSecurityStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let set = unsafe {
            // SAFETY: The caller selects this accessor only for
            // IRP_MJ_SET_SECURITY, where SetSecurity is active.
            stack.Parameters.SetSecurity
        };
        let Some(security_descriptor) = NonNull::new(set.SecurityDescriptor) else {
            return Err(DriverError::InvalidParameter);
        };
        Ok(SetSecurityStack {
            file_object: self.kernel_file_object()?,
            selection: SecuritySelection::from_raw(set.SecurityInformation)?,
            security_descriptor,
        })
    }

    /// Decodes read parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the read stack has no FILE_OBJECT or an invalid byte count.
    pub(crate) fn read(self) -> Result<ReadStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let read = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_READ,
            // where Read is active.
            stack.Parameters.Read
        };
        let byte_offset = unsafe {
            // SAFETY: ByteOffset uses the QuadPart arm for read/write stack locations.
            read.ByteOffset.QuadPart
        };
        Ok(ReadStack {
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(read.Length)?,
            starting_point: ReadStartingPoint::from_quad(byte_offset)?,
            key: ByteRangeLockKey::from_ulong(read.Key),
        })
    }

    /// Decodes write parameters from the current stack location.
    /// # Errors
    ///
    /// Returns an error when the write stack has no FILE_OBJECT or an invalid byte count.
    pub(crate) fn write(self) -> Result<WriteStack, DriverError> {
        let stack = unsafe {
            // SAFETY: `stack` is non-null and belongs to the active IRP stack
            // for the current dispatch callback.
            self.stack.as_ref()
        };
        let write = unsafe {
            // SAFETY: The caller selects this accessor only for IRP_MJ_WRITE,
            // where Write is active.
            stack.Parameters.Write
        };
        let byte_offset = unsafe {
            // SAFETY: ByteOffset uses the QuadPart arm for read/write stack locations.
            write.ByteOffset.QuadPart
        };
        Ok(WriteStack {
            file_object: self.kernel_file_object()?,
            length: IrpBufferLength::from_ulong(write.Length)?,
            starting_point: WriteStartingPoint::from_quad(byte_offset)?,
            key: ByteRangeLockKey::from_ulong(write.Key),
        })
    }
}

/// Kernel-addressable bytes decoded at the IRP boundary.
#[derive(Debug)]
struct IrpByteBuffer {
    /// First buffer byte.
    address: NonNull<u8>,
    /// Buffer byte count.
    length: usize,
}

impl IrpByteBuffer {
    /// Creates byte buffer after length validation.
    /// # Errors
    ///
    /// Returns an error when `length` cannot safely back a Rust slice.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        let max_slice_len =
            usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
        if length > max_slice_len {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self { address, length })
    }

    /// Returns the first byte address.
    const fn address(&self) -> NonNull<u8> {
        self.address
    }

    /// Returns the buffer as a byte slice.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: IrpByteBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length)
        }
    }

    /// Returns the buffer as a mutable byte slice.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            // SAFETY: IrpByteBuffer is constructed only after the active IRP
            // exposes a kernel-addressable buffer for `length` bytes.
            core::slice::from_raw_parts_mut(self.address.as_ptr(), self.length)
        }
    }

    /// Copies an unaligned fixed-size payload out of the buffer.
    /// # Errors
    ///
    /// Returns an error when the raw IRP byte buffer is smaller than `T`.
    fn read_unaligned<T: Copy>(&self) -> DriverResult<T> {
        if self.length < core::mem::size_of::<T>() {
            return Err(DriverError::BufferTooSmall);
        }
        Ok(unsafe {
            // SAFETY: The buffer length was checked above and unaligned read
            // avoids imposing an alignment contract on I/O manager storage.
            self.address.as_ptr().cast::<T>().read_unaligned()
        })
    }
}

/// Immutable bytes decoded from a buffered or data-input IRP boundary.
#[derive(Debug)]
pub(crate) struct BufferedInput {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
}

impl BufferedInput {
    /// Creates an immutable buffer view after length validation.
    /// # Errors
    ///
    /// Returns an error when the input buffer length cannot safely back a Rust slice.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        Ok(Self {
            bytes: IrpByteBuffer::new(address, length)?,
        })
    }

    /// Returns input bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Returns the first input byte address.
    pub(crate) const fn address(&self) -> NonNull<u8> {
        self.bytes.address()
    }

    /// Copies an unaligned fixed-size input payload.
    /// # Errors
    ///
    /// Returns an error when the buffered input payload is smaller than `T`.
    pub(crate) fn read_unaligned<T: Copy>(&self) -> DriverResult<T> {
        self.bytes.read_unaligned()
    }
}

/// Mutable bytes decoded from a buffered or data-output IRP boundary.
#[derive(Debug)]
pub(crate) struct BufferedOutput {
    /// Kernel-addressable IRP bytes.
    bytes: IrpByteBuffer,
}

impl BufferedOutput {
    /// Creates a mutable buffer view after length validation.
    /// # Errors
    ///
    /// Returns an error when the output buffer length cannot safely back a mutable Rust slice.
    fn new(address: NonNull<u8>, length: usize) -> Result<Self, DriverError> {
        Ok(Self {
            bytes: IrpByteBuffer::new(address, length)?,
        })
    }

    /// Returns output bytes.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }

    /// Returns the first output byte address.
    pub(crate) const fn address(&self) -> NonNull<u8> {
        self.bytes.address()
    }
}

/// Returns an IRP MDL data buffer address as kernel memory.
/// # Errors
///
/// Returns an error when `length` exceeds the MDL byte count or the MDL cannot be mapped to system
/// address space.
fn mdl_data_buffer_address(
    mdl: NonNull<wdk_sys::MDL>,
    length: IrpBufferLength,
) -> Result<NonNull<u8>, DriverError> {
    let mdl_ref = unsafe {
        // SAFETY: The IRP's MdlAddress is non-null and owned by the I/O
        // Manager for the lifetime of this dispatch callback.
        mdl.as_ref()
    };
    let mdl_len = usize::try_from(mdl_ref.ByteCount).map_err(|_| DriverError::InvalidParameter)?;
    if length.as_usize() > mdl_len {
        return Err(DriverError::InvalidParameter);
    }

    let address = mapped_mdl_address(mdl, mdl_ref)?;
    Ok(address.cast())
}

/// Implements the address-selection behavior of `MmGetSystemAddressForMdlSafe`.
/// # Errors
///
/// Returns an error when an already-mapped MDL has no mapped address or mapping locked pages fails.
fn mapped_mdl_address(
    mdl: NonNull<wdk_sys::MDL>,
    mdl_ref: &wdk_sys::MDL,
) -> Result<NonNull<c_void>, DriverError> {
    let flags = u32::from(u16::from_ne_bytes(mdl_ref.MdlFlags.to_ne_bytes()));
    let mapped_flags = wdk_sys::MDL_MAPPED_TO_SYSTEM_VA | wdk_sys::MDL_SOURCE_IS_NONPAGED_POOL;
    if flags & mapped_flags != 0 {
        return NonNull::new(mdl_ref.MappedSystemVa).ok_or(DriverError::InvalidParameter);
    }

    let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
        .map_err(|_| DriverError::InvalidParameter)?;
    let priority = u32::try_from(wdk_sys::_MM_PAGE_PRIORITY::NormalPagePriority)
        .map_err(|_| DriverError::InvalidParameter)?
        | wdk_sys::MdlMappingNoExecute;
    let address = unsafe {
        // SAFETY: The MDL belongs to the active IRP and describes locked pages
        // supplied by the I/O Manager for direct I/O.
        crate::kernel::ffi::MmMapLockedPagesSpecifyCache(
            mdl.as_ptr(),
            kernel_mode,
            wdk_sys::_MEMORY_CACHING_TYPE::MmCached,
            core::ptr::null_mut(),
            0,
            priority,
        )
    };
    NonNull::new(address).ok_or(DriverError::InsufficientResources)
}

/// Buffer length accepted at the IRP stack boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IrpBufferLength(usize);

impl IrpBufferLength {
    /// Decodes a WDK `ULONG` byte count into the driver length domain.
    /// # Errors
    ///
    /// Returns an error when `value` exceeds the maximum Rust slice length.
    fn from_ulong(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        let length = usize::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
        let max_slice_len =
            usize::try_from(isize::MAX).map_err(|_| DriverError::InvalidParameter)?;
        if length > max_slice_len {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self(length))
    }

    /// Returns the validated byte count.
    pub(crate) const fn as_usize(self) -> usize {
        self.0
    }

    /// Returns whether the request supplied an empty buffer.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Directory entry index selected by a query-directory request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntryIndex(u32);

impl DirectoryEntryIndex {
    /// Creates a directory entry index from the Windows cursor field.
    pub(crate) const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the cursor index.
    pub(crate) const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Initial directory cursor position requested by the I/O Manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryCursorPosition {
    /// Continue from the existing CCB cursor.
    Current,
    /// Restart at the beginning of the directory.
    Restart,
    /// Seek to a caller-supplied directory index.
    Index(DirectoryEntryIndex),
}

/// Query-directory filename pattern supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryPatternInput {
    /// No filename pattern was supplied.
    All,
    /// Caller supplied a `UNICODE_STRING` filename pattern.
    Name(NonNull<wdk_sys::UNICODE_STRING>),
}

/// Directory entry emission cardinality requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryEntryEmission {
    /// Emit as many matching entries as fit.
    Multiple,
    /// Emit at most one matching entry.
    Single,
}

/// Scope selected for a directory-change notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryWatchScope {
    /// Observe changes directly below the opened directory.
    DirectChildren,
    /// Observe changes below the opened directory and every descendant.
    Subtree,
}

impl DirectoryWatchScope {
    /// Decodes the directory-control watch-tree stack flag.
    fn from_stack_flags(flags: wdk_sys::UCHAR) -> Self {
        if stack_flag(flags, wdk_sys::SL_WATCH_TREE) {
            Self::Subtree
        } else {
            Self::DirectChildren
        }
    }

    /// Returns whether this request asks to observe every descendant directory.
    pub(crate) const fn watches_subtree(self) -> bool {
        matches!(self, Self::Subtree)
    }
}

/// Validated set of file-system changes requested by a directory notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryChangeFilter(wdk_sys::ULONG);

impl DirectoryChangeFilter {
    /// Decodes a Windows completion-filter bit set.
    /// # Errors
    ///
    /// Returns an error when no notification kind is selected or the bit set contains a kind that
    /// Windows does not define for directory notifications.
    fn from_raw(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        if value == 0 || value & !wdk_sys::FILE_NOTIFY_VALID_MASK != 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self(value))
    }

    /// Returns the filter bits supported by the driver's namespace-only notifier.
    /// # Errors
    ///
    /// Returns an error when the request asks for attribute, data, security, stream, or other
    /// change kinds that the current notifier cannot report precisely.
    pub(crate) fn namespace_name_filter(self) -> DriverResult<wdk_sys::ULONG> {
        if self.0 & !wdk_sys::FILE_NOTIFY_CHANGE_NAME != 0 {
            return Err(DriverError::NotSupported);
        }
        Ok(self.0)
    }
}

/// EA entry index selected by a query-EA request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EaEntryIndex(u32);

impl EaEntryIndex {
    /// Creates an EA entry index from the Windows one-based index field.
    pub(crate) const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the caller-supplied one-based EA entry index.
    pub(crate) const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Query-EA selection supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EaSelection {
    /// Return every EA associated with the opened file.
    All,
    /// Return only names listed in the caller's `FILE_GET_EA_INFORMATION` buffer.
    Names {
        /// First byte of the caller's name list.
        address: NonNull<u8>,
        /// Byte length of the caller's name list.
        length: IrpBufferLength,
    },
    /// Return the entry at a caller-supplied one-based index, then continue scanning.
    Index(EaEntryIndex),
}

/// EA entry emission cardinality requested by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EaEntryEmission {
    /// Emit as many selected EAs as fit.
    Multiple,
    /// Emit at most one selected EA.
    Single,
}

/// Tests one WDK `IO_STACK_LOCATION::Flags` bit while keeping raw flags local to decode.
fn stack_flag(flags: wdk_sys::UCHAR, bit: u32) -> bool {
    u32::from(flags) & bit != 0
}

/// Decoded file-system-control minor function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileSystemControlMinorFunction {
    /// I/O Manager mount request.
    MountVolume,
    /// User FSCTL request.
    UserFsRequest,
    /// Unsupported file-system-control minor function.
    Unsupported,
}

/// Decoded directory-control minor function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryControlMinorFunction {
    /// Directory enumeration request.
    QueryDirectory,
    /// Directory change notification request.
    NotifyChangeDirectory,
    /// Unsupported directory-control minor function.
    Unsupported,
}

/// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
const MOUNT_VOLUME_MINOR_FUNCTION: u32 = 1;

/// Decoded user FSCTL code selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FsControlCode {
    /// Windows `FSCTL_GET_REPARSE_POINT`.
    GetReparsePoint,
    /// Windows `FSCTL_SET_REPARSE_POINT`.
    SetReparsePoint,
    /// Windows `FSCTL_DELETE_REPARSE_POINT`.
    DeleteReparsePoint,
    /// ext4win private fscrypt add-key control.
    AddEncryptionKey,
    /// ext4win private fscrypt remove-key control.
    RemoveEncryptionKey,
    /// ext4win private fscrypt key-status control.
    GetEncryptionKeyStatus,
    /// ext4win private fs-verity enable control.
    EnableVerity,
}

impl FsControlCode {
    /// Decodes the raw WDK control code at the IRP boundary.
    /// # Errors
    ///
    /// Returns an error when `value` is not one of the supported Windows or ext4win FSCTL codes.
    fn from_raw(value: wdk_sys::ULONG) -> Result<Self, DriverError> {
        match value {
            FSCTL_GET_REPARSE_POINT => Ok(Self::GetReparsePoint),
            FSCTL_SET_REPARSE_POINT => Ok(Self::SetReparsePoint),
            FSCTL_DELETE_REPARSE_POINT => Ok(Self::DeleteReparsePoint),
            FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY => Ok(Self::AddEncryptionKey),
            FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY => Ok(Self::RemoveEncryptionKey),
            FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS => Ok(Self::GetEncryptionKeyStatus),
            FSCTL_EXT4WIN_ENABLE_VERITY => Ok(Self::EnableVerity),
            _ => Err(DriverError::NotSupported),
        }
    }
}

/// `FSCTL_GET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 42, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_GET_REPARSE_POINT: wdk_sys::ULONG = 589_992;
/// `FSCTL_SET_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_SET_REPARSE_POINT: wdk_sys::ULONG = 589_988;
/// `FSCTL_DELETE_REPARSE_POINT`, from `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 43, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const FSCTL_DELETE_REPARSE_POINT: wdk_sys::ULONG = 589_996;

/// Windows `FILE_DEVICE_FILE_SYSTEM`.
const FILE_DEVICE_FILE_SYSTEM: wdk_sys::ULONG = 0x0000_0009;
/// Windows `METHOD_BUFFERED`.
const METHOD_BUFFERED: wdk_sys::ULONG = 0;
/// Windows `FILE_ANY_ACCESS`.
const FILE_ANY_ACCESS: wdk_sys::ULONG = 0;
/// ext4win private function code for adding an fscrypt key.
const EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x900;
/// ext4win private function code for removing an fscrypt key.
const EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x901;
/// ext4win private function code for fscrypt key status.
const EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION: wdk_sys::ULONG = 0x902;
/// ext4win private function code for enabling fs-verity.
const EXT4WIN_ENABLE_VERITY_FUNCTION: wdk_sys::ULONG = 0x903;

/// Builds a Windows `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, function, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const fn ext4win_fsctl(function: wdk_sys::ULONG) -> wdk_sys::ULONG {
    (FILE_DEVICE_FILE_SYSTEM << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
}

/// ext4win FSCTL carrying Linux `struct fscrypt_add_key_arg`.
const FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_remove_key_arg`.
const FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_get_key_status_arg`.
const FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fsverity_enable_arg`.
const FSCTL_EXT4WIN_ENABLE_VERITY: wdk_sys::ULONG = ext4win_fsctl(EXT4WIN_ENABLE_VERITY_FUNCTION);

/// Decoded query-volume filesystem information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryVolumeInformationClass {
    /// Windows `FileFsVolumeInformation`.
    Volume,
    /// Windows `FileFsSizeInformation`.
    Size,
    /// Windows `FileFsDeviceInformation`.
    Device,
    /// Windows `FileFsAttributeInformation`.
    Attribute,
    /// Windows `FileFsFullSizeInformation`.
    FullSize,
}

impl QueryVolumeInformationClass {
    /// Decodes a raw WDK filesystem information class for volume queries.
    /// # Errors
    ///
    /// Returns an error when the filesystem information class is not supported for volume queries.
    fn from_raw(value: wdk_sys::FS_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            FILE_FS_VOLUME_INFORMATION_CLASS => Ok(Self::Volume),
            FILE_FS_SIZE_INFORMATION_CLASS => Ok(Self::Size),
            FILE_FS_DEVICE_INFORMATION_CLASS => Ok(Self::Device),
            FILE_FS_ATTRIBUTE_INFORMATION_CLASS => Ok(Self::Attribute),
            FILE_FS_FULL_SIZE_INFORMATION_CLASS => Ok(Self::FullSize),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded set-volume filesystem information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetVolumeInformationClass {
    /// Windows `FileFsLabelInformation`.
    Label,
}

impl SetVolumeInformationClass {
    /// Decodes a raw WDK filesystem information class for volume mutations.
    /// # Errors
    ///
    /// Returns an error when the filesystem information class is not `FileFsLabelInformation`.
    fn from_raw(value: wdk_sys::FS_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            FILE_FS_LABEL_INFORMATION_CLASS => Ok(Self::Label),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// `FileFsVolumeInformation`.
const FILE_FS_VOLUME_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 1;
/// `FileFsLabelInformation`.
const FILE_FS_LABEL_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 2;
/// `FileFsSizeInformation`.
const FILE_FS_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 3;
/// `FileFsDeviceInformation`.
const FILE_FS_DEVICE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 4;
/// `FileFsAttributeInformation`.
const FILE_FS_ATTRIBUTE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 5;
/// `FileFsFullSizeInformation`.
const FILE_FS_FULL_SIZE_INFORMATION_CLASS: wdk_sys::FS_INFORMATION_CLASS = 7;

/// Decoded query-file information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueryFileInformationClass {
    /// Windows `FileBasicInformation`.
    Basic,
    /// Windows `FileStandardInformation`.
    Standard,
    /// Windows `FileInternalInformation`.
    Internal,
    /// Windows `FilePositionInformation`.
    Position,
    /// Windows `FileNetworkOpenInformation`.
    NetworkOpen,
    /// Windows `FileNameInformation`.
    Name,
    /// Windows `FileAttributeTagInformation`.
    AttributeTag,
}

impl QueryFileInformationClass {
    /// Decodes a raw WDK file information class for fixed file queries.
    /// # Errors
    ///
    /// Returns an error when the file information class is not implemented for fixed file queries.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => Ok(Self::Basic),
            wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation => Ok(Self::Standard),
            wdk_sys::_FILE_INFORMATION_CLASS::FileInternalInformation => Ok(Self::Internal),
            wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation => Ok(Self::Position),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNetworkOpenInformation => Ok(Self::NetworkOpen),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNameInformation => Ok(Self::Name),
            wdk_sys::_FILE_INFORMATION_CLASS::FileAttributeTagInformation => Ok(Self::AttributeTag),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded set-file information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetFileInformationClass {
    /// Windows `FileBasicInformation`.
    Basic,
    /// Windows `FilePositionInformation`.
    Position,
    /// Windows `FileEndOfFileInformation`.
    EndOfFile,
    /// Windows `FileAllocationInformation`.
    Allocation,
    /// Windows `FileDispositionInformation`.
    Disposition,
    /// Windows `FileDispositionInformationEx`.
    DispositionEx,
    /// Windows `FileRenameInformation`.
    Rename,
    /// Windows `FileRenameInformationEx`.
    RenameEx,
}

impl SetFileInformationClass {
    /// Decodes a raw WDK file information class for file mutations.
    /// # Errors
    ///
    /// Returns an error when the file information class is not implemented for file mutations.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation => Ok(Self::Basic),
            wdk_sys::_FILE_INFORMATION_CLASS::FilePositionInformation => Ok(Self::Position),
            wdk_sys::_FILE_INFORMATION_CLASS::FileEndOfFileInformation => Ok(Self::EndOfFile),
            wdk_sys::_FILE_INFORMATION_CLASS::FileAllocationInformation => Ok(Self::Allocation),
            wdk_sys::_FILE_INFORMATION_CLASS::FileDispositionInformation => Ok(Self::Disposition),
            wdk_sys::_FILE_INFORMATION_CLASS::FileDispositionInformationEx => {
                Ok(Self::DispositionEx)
            }
            wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation => Ok(Self::Rename),
            wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformationEx => Ok(Self::RenameEx),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded query-directory information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryInformationClass {
    /// Windows `FileDirectoryInformation`.
    Directory,
    /// Windows `FileFullDirectoryInformation`.
    Full,
    /// Windows `FileBothDirectoryInformation`.
    Both,
    /// Windows `FileNamesInformation`.
    Names,
}

impl DirectoryInformationClass {
    /// Decodes a raw WDK file information class for directory enumeration.
    /// # Errors
    ///
    /// Returns an error when the file information class is not a supported directory enumeration
    /// class.
    fn from_raw(value: wdk_sys::FILE_INFORMATION_CLASS) -> Result<Self, DriverError> {
        match value {
            wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation => Ok(Self::Directory),
            wdk_sys::_FILE_INFORMATION_CLASS::FileFullDirectoryInformation => Ok(Self::Full),
            wdk_sys::_FILE_INFORMATION_CLASS::FileBothDirectoryInformation => Ok(Self::Both),
            wdk_sys::_FILE_INFORMATION_CLASS::FileNamesInformation => Ok(Self::Names),
            _ => Err(DriverError::InvalidInfoClass),
        }
    }
}

/// Decoded create/open parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateParameters {
    /// Desired access mask requested by the opener.
    desired_access: DesiredAccess,
    /// Share-access bits requested by the opener.
    share_access: ShareAccess,
    /// Requested create disposition.
    disposition: CreateDisposition,
    /// File-vs-directory create/open requirement.
    target_requirement: CreateTargetRequirement,
    /// Write completion durability requested by create options.
    write_commitment: WriteCommitment,
    /// Data transfer buffering requested by create options.
    transfer_buffering: CreateTransferBuffering,
    /// Per-handle synchronous I/O mode requested by create options.
    synchronization_mode: CreateSynchronizationMode,
    /// Reparse-point opening mode requested by create options.
    reparse_point_mode: CreateReparsePointMode,
    /// Interpretation of `FILE_OBJECT::FileName`.
    name_interpretation: CreateNameInterpretation,
    /// Extended-attribute input length supplied with create.
    ea_length: IrpBufferLength,
}

impl CreateParameters {
    /// Decodes raw WDK create parameters at the IRP boundary.
    /// # Errors
    ///
    /// Returns an error when share access, create disposition, or create options contain unsupported
    /// values.
    fn decode(
        desired_access: wdk_sys::ACCESS_MASK,
        options: wdk_sys::ULONG,
        share_access: wdk_sys::USHORT,
        ea_length: IrpBufferLength,
    ) -> Result<Self, DriverError> {
        let desired_access = DesiredAccess::from_raw(desired_access);
        let disposition = CreateDisposition::from_options(options)?;
        let create_options = CreateOptions::decode(options, desired_access)?;
        let target_requirement = create_options.target_requirement();
        disposition.validate_target_requirement(target_requirement)?;
        Ok(Self {
            desired_access,
            share_access: ShareAccess::from_raw(share_access)?,
            disposition,
            target_requirement,
            write_commitment: create_options.write_commitment(),
            transfer_buffering: create_options.transfer_buffering(),
            synchronization_mode: create_options.synchronization_mode(),
            reparse_point_mode: create_options.reparse_point_mode(),
            name_interpretation: create_options.name_interpretation(),
            ea_length,
        })
    }

    /// Returns the desired access mask.
    pub(crate) const fn desired_access(self) -> DesiredAccess {
        self.desired_access
    }

    /// Returns virtual access whose sharing must permit this existing-object operation.
    pub(crate) const fn existing_operation_access(self) -> ExistingOperationAccess {
        let required = match self.disposition {
            CreateDisposition::Overwrite | CreateDisposition::OverwriteIf => {
                wdk_sys::FILE_WRITE_DATA | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES
            }
            CreateDisposition::Supersede => {
                wdk_sys::DELETE | wdk_sys::FILE_WRITE_EA | wdk_sys::FILE_WRITE_ATTRIBUTES
            }
            CreateDisposition::Open | CreateDisposition::Create | CreateDisposition::OpenIf => 0,
        };
        self.desired_access.including_for_operation(required)
    }

    /// Returns the share access.
    pub(crate) const fn share_access(self) -> ShareAccess {
        self.share_access
    }

    /// Returns the create disposition.
    pub(crate) const fn disposition(self) -> CreateDisposition {
        self.disposition
    }

    /// Returns the target kind requirement.
    pub(crate) const fn target_requirement(self) -> CreateTargetRequirement {
        self.target_requirement
    }

    /// Returns write completion durability requested by create options.
    pub(crate) const fn write_commitment(self) -> WriteCommitment {
        self.write_commitment
    }

    /// Returns data transfer buffering requested at create/open.
    pub(crate) const fn transfer_buffering(self) -> CreateTransferBuffering {
        self.transfer_buffering
    }

    /// Returns synchronous I/O mode requested at create/open.
    pub(crate) const fn synchronization_mode(self) -> CreateSynchronizationMode {
        self.synchronization_mode
    }

    /// Returns reparse-point opening mode requested at create/open.
    pub(crate) const fn reparse_point_mode(self) -> CreateReparsePointMode {
        self.reparse_point_mode
    }

    /// Returns how the create FILE_OBJECT name must be interpreted.
    pub(crate) const fn name_interpretation(self) -> CreateNameInterpretation {
        self.name_interpretation
    }

    /// Returns the input EA length.
    pub(crate) const fn ea_length(self) -> IrpBufferLength {
        self.ea_length
    }
}

/// Desired access requested by a create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DesiredAccess {
    /// Raw WDK access mask, retained for I/O Manager share-access accounting.
    raw: wdk_sys::ACCESS_MASK,
}

/// Virtual access used to preflight an existing-object create operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExistingOperationAccess {
    /// Raw WDK access mask checked without recording it as returned handle authority.
    raw: wdk_sys::ACCESS_MASK,
}

/// Write authority retained for one opened regular-file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegularFileWriteAccess {
    /// The handle was not opened for regular-file data writes.
    Denied,
    /// The handle may write only at the current end of file.
    AppendOnly,
    /// The handle may select an absolute, current, or end-of-file starting point.
    Positional,
}

impl DesiredAccess {
    /// Wraps the raw WDK access mask.
    const fn from_raw(raw: wdk_sys::ACCESS_MASK) -> Self {
        Self { raw }
    }

    /// Returns the WDK access mask for `IoCheckShareAccess`.
    pub(crate) const fn as_raw(self) -> wdk_sys::ACCESS_MASK {
        self.raw
    }

    /// Adds rights implied only for the duration of an existing-object operation.
    const fn including_for_operation(
        self,
        required: wdk_sys::ACCESS_MASK,
    ) -> ExistingOperationAccess {
        ExistingOperationAccess {
            raw: self.raw | required,
        }
    }

    /// Projects Windows desired-access bits into regular-file write authority.
    pub(crate) const fn regular_file_write_access(self) -> RegularFileWriteAccess {
        if self.contains(wdk_sys::FILE_WRITE_DATA) {
            RegularFileWriteAccess::Positional
        } else if self.contains(wdk_sys::FILE_APPEND_DATA) {
            RegularFileWriteAccess::AppendOnly
        } else {
            RegularFileWriteAccess::Denied
        }
    }

    /// Returns whether all selected access bits are present.
    const fn contains(self, mask: wdk_sys::ACCESS_MASK) -> bool {
        self.raw & mask == mask
    }
}

impl ExistingOperationAccess {
    /// Returns the WDK access mask for `IoCheckShareAccess`.
    pub(crate) const fn as_raw(self) -> wdk_sys::ACCESS_MASK {
        self.raw
    }
}

/// Share access requested by a create/open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShareAccess {
    /// Raw WDK share mask widened for I/O Manager share-access accounting.
    raw: wdk_sys::ULONG,
}

impl ShareAccess {
    /// Decodes the raw WDK share mask.
    /// # Errors
    ///
    /// Returns an error when `raw` contains bits outside the Windows file-share mask.
    fn from_raw(raw: wdk_sys::USHORT) -> Result<Self, DriverError> {
        if raw & !FILE_SHARE_ACCESS_MASK != 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self {
            raw: wdk_sys::ULONG::from(raw),
        })
    }

    /// Returns the WDK share mask for `IoCheckShareAccess`.
    pub(crate) const fn as_ulong(self) -> wdk_sys::ULONG {
        self.raw
    }
}

/// Requested create disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateDisposition {
    /// Open only if the path exists.
    Open,
    /// Create only if the path is absent.
    Create,
    /// Open existing or create absent.
    OpenIf,
    /// Truncate an existing regular file.
    Overwrite,
    /// Truncate an existing regular file or create an absent object.
    OverwriteIf,
    /// Replace an existing regular file's data or create an absent object.
    Supersede,
}

impl CreateDisposition {
    /// Decodes the disposition stored in Create.Options.
    /// # Errors
    ///
    /// Returns an error when the disposition bits do not name a supported Windows create
    /// disposition.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, DriverError> {
        match options >> CREATE_DISPOSITION_SHIFT {
            FILE_OPEN_DISPOSITION => Ok(Self::Open),
            FILE_CREATE_DISPOSITION => Ok(Self::Create),
            FILE_OPEN_IF_DISPOSITION => Ok(Self::OpenIf),
            FILE_SUPERSEDE_DISPOSITION => Ok(Self::Supersede),
            FILE_OVERWRITE_DISPOSITION => Ok(Self::Overwrite),
            FILE_OVERWRITE_IF_DISPOSITION => Ok(Self::OverwriteIf),
            _ => Err(DriverError::InvalidParameter),
        }
    }

    /// Validates create-disposition and target-kind combinations before path lookup.
    /// # Errors
    ///
    /// Returns an error when a destructive file disposition is combined with
    /// `FILE_DIRECTORY_FILE`.
    fn validate_target_requirement(self, requirement: CreateTargetRequirement) -> DriverResult<()> {
        if matches!(requirement, CreateTargetRequirement::Directory)
            && matches!(self, Self::Overwrite | Self::OverwriteIf | Self::Supersede)
        {
            return Err(DriverError::InvalidParameter);
        }
        Ok(())
    }
}

/// File-vs-directory target requirement requested by create options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTargetRequirement {
    /// Caller accepts a file, symlink, or directory.
    Any,
    /// Caller requires a directory target.
    Directory,
    /// Caller requires a non-directory target.
    NonDirectory,
}

/// Requested file data transfer buffering for a newly opened handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateTransferBuffering {
    /// No direct-transfer constraints were requested.
    IntermediateAllowed,
    /// Caller requested `FILE_NO_INTERMEDIATE_BUFFERING`.
    NoIntermediate,
}

/// Requested per-handle synchronous I/O mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateSynchronizationMode {
    /// No synchronous file-position context was requested.
    Asynchronous,
    /// Synchronous I/O with alertable waits.
    SynchronousAlert,
    /// Synchronous I/O with non-alertable waits.
    SynchronousNonAlert,
}

impl CreateSynchronizationMode {
    /// Decodes synchronous I/O create options.
    /// # Errors
    ///
    /// Returns an error when both synchronous modes are set or `SYNCHRONIZE` access is absent.
    fn from_options(options: wdk_sys::ULONG, desired_access: DesiredAccess) -> DriverResult<Self> {
        let alert = create_option_selected(options, wdk_sys::FILE_SYNCHRONOUS_IO_ALERT);
        let nonalert = create_option_selected(options, wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT);
        match (alert, nonalert) {
            (true, true) => Err(DriverError::InvalidParameter),
            (true, false) => Self::synchronized(desired_access, Self::SynchronousAlert),
            (false, true) => Self::synchronized(desired_access, Self::SynchronousNonAlert),
            (false, false) => Ok(Self::Asynchronous),
        }
    }

    /// Returns a synchronous mode after validating the access mask.
    /// # Errors
    ///
    /// Returns an error when the caller omitted `SYNCHRONIZE`.
    fn synchronized(desired_access: DesiredAccess, mode: Self) -> DriverResult<Self> {
        if !desired_access.contains(wdk_sys::SYNCHRONIZE) {
            return Err(DriverError::InvalidParameter);
        }
        Ok(mode)
    }
}

/// Requested reparse-point handling for an existing final path component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateReparsePointMode {
    /// Use normal reparse processing for final reparse points.
    ResolveFinalTarget,
    /// Open the final reparse point itself.
    OpenFinalReparsePoint,
}

impl CreateReparsePointMode {
    /// Decodes reparse-point create options.
    const fn from_options(options: wdk_sys::ULONG) -> Self {
        if create_option_selected(options, wdk_sys::FILE_OPEN_REPARSE_POINT) {
            Self::OpenFinalReparsePoint
        } else {
            Self::ResolveFinalTarget
        }
    }
}

/// Requested interpretation for `FILE_OBJECT::FileName`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CreateNameInterpretation {
    /// Interpret the FILE_OBJECT name as a Windows path.
    Path,
    /// Interpret the FILE_OBJECT name as a binary file reference.
    FileReference,
}

impl CreateNameInterpretation {
    /// Decodes create-name interpretation options.
    const fn from_options(options: wdk_sys::ULONG) -> Self {
        if create_option_selected(options, wdk_sys::FILE_OPEN_BY_FILE_ID) {
            Self::FileReference
        } else {
            Self::Path
        }
    }
}

impl CreateTargetRequirement {
    /// Decodes file-vs-directory create options.
    /// # Errors
    ///
    /// Returns an error when both directory-only and non-directory-only options are set.
    fn from_options(options: wdk_sys::ULONG) -> Result<Self, DriverError> {
        let directory = create_option_selected(options, wdk_sys::FILE_DIRECTORY_FILE);
        let non_directory = create_option_selected(options, wdk_sys::FILE_NON_DIRECTORY_FILE);
        match (directory, non_directory) {
            (true, true) => Err(DriverError::InvalidParameter),
            (true, false) => Ok(Self::Directory),
            (false, true) => Ok(Self::NonDirectory),
            (false, false) => Ok(Self::Any),
        }
    }
}

/// Create options that survive raw Windows boundary decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CreateOptions {
    /// File-vs-directory requirement.
    target_requirement: CreateTargetRequirement,
    /// Requested write completion durability.
    write_commitment: WriteCommitment,
    /// Requested data transfer buffering.
    transfer_buffering: CreateTransferBuffering,
    /// Requested synchronous I/O mode.
    synchronization_mode: CreateSynchronizationMode,
    /// Requested reparse-point handling.
    reparse_point_mode: CreateReparsePointMode,
    /// Requested name interpretation.
    name_interpretation: CreateNameInterpretation,
}

impl CreateOptions {
    /// Decodes and normalizes raw `Create.Options`.
    /// # Errors
    ///
    /// Returns an error when create options include bits outside the accepted ext4win boundary.
    fn decode(options: wdk_sys::ULONG, desired_access: DesiredAccess) -> DriverResult<Self> {
        let raw_options = options & CREATE_OPTIONS_MASK;
        if raw_options & !ACCEPTED_CREATE_OPTIONS != 0 {
            return Err(DriverError::NotSupported);
        }
        if create_option_selected(options, wdk_sys::FILE_DELETE_ON_CLOSE) {
            return Err(DriverError::NotSupported);
        }
        let transfer_buffering =
            if create_option_selected(options, wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING) {
                CreateTransferBuffering::NoIntermediate
            } else {
                CreateTransferBuffering::IntermediateAllowed
            };
        let synchronization_mode =
            CreateSynchronizationMode::from_options(options, desired_access)?;
        let reparse_point_mode = CreateReparsePointMode::from_options(options);
        let name_interpretation = CreateNameInterpretation::from_options(options);
        let write_commitment = if create_option_selected(options, wdk_sys::FILE_WRITE_THROUGH)
            || matches!(transfer_buffering, CreateTransferBuffering::NoIntermediate)
        {
            WriteCommitment::FlushThrough
        } else {
            WriteCommitment::CommitOnly
        };
        Ok(Self {
            target_requirement: CreateTargetRequirement::from_options(options)?,
            write_commitment,
            transfer_buffering,
            synchronization_mode,
            reparse_point_mode,
            name_interpretation,
        })
    }

    /// Returns the decoded file-vs-directory requirement.
    const fn target_requirement(self) -> CreateTargetRequirement {
        self.target_requirement
    }

    /// Returns decoded write completion durability.
    const fn write_commitment(self) -> WriteCommitment {
        self.write_commitment
    }

    /// Returns decoded data transfer buffering.
    const fn transfer_buffering(self) -> CreateTransferBuffering {
        self.transfer_buffering
    }

    /// Returns decoded synchronous I/O mode.
    const fn synchronization_mode(self) -> CreateSynchronizationMode {
        self.synchronization_mode
    }

    /// Returns decoded reparse-point handling.
    const fn reparse_point_mode(self) -> CreateReparsePointMode {
        self.reparse_point_mode
    }

    /// Returns decoded name interpretation.
    const fn name_interpretation(self) -> CreateNameInterpretation {
        self.name_interpretation
    }
}

/// Returns true when a create option bit is present.
const fn create_option_selected(options: wdk_sys::ULONG, option: wdk_sys::ULONG) -> bool {
    options & option != 0
}

/// `FILE_SUPERSEDE` create disposition.
const FILE_SUPERSEDE_DISPOSITION: wdk_sys::ULONG = 0;
/// `FILE_OPEN` create disposition.
const FILE_OPEN_DISPOSITION: wdk_sys::ULONG = 1;
/// `FILE_CREATE` create disposition.
const FILE_CREATE_DISPOSITION: wdk_sys::ULONG = 2;
/// `FILE_OPEN_IF` create disposition.
const FILE_OPEN_IF_DISPOSITION: wdk_sys::ULONG = 3;
/// `FILE_OVERWRITE` create disposition.
const FILE_OVERWRITE_DISPOSITION: wdk_sys::ULONG = 4;
/// `FILE_OVERWRITE_IF` create disposition.
const FILE_OVERWRITE_IF_DISPOSITION: wdk_sys::ULONG = 5;
/// Shift for the create disposition stored in `Options`.
const CREATE_DISPOSITION_SHIFT: u32 = 24;
/// Mask for option bits below the create disposition.
const CREATE_OPTIONS_MASK: wdk_sys::ULONG = 0x00FF_FFFF;
/// Create options with an ext4win-internal domain meaning.
const DOMAIN_CREATE_OPTIONS: wdk_sys::ULONG = wdk_sys::FILE_DIRECTORY_FILE
    | wdk_sys::FILE_NON_DIRECTORY_FILE
    | wdk_sys::FILE_DELETE_ON_CLOSE
    | wdk_sys::FILE_WRITE_THROUGH
    | wdk_sys::FILE_NO_INTERMEDIATE_BUFFERING
    | wdk_sys::FILE_SYNCHRONOUS_IO_ALERT
    | wdk_sys::FILE_SYNCHRONOUS_IO_NONALERT
    | wdk_sys::FILE_OPEN_REPARSE_POINT
    | wdk_sys::FILE_OPEN_BY_FILE_ID;
/// Create options consumed as Windows boundary hints.
const IGNORED_CREATE_HINT_OPTIONS: wdk_sys::ULONG = wdk_sys::FILE_SEQUENTIAL_ONLY
    | wdk_sys::FILE_COMPLETE_IF_OPLOCKED
    | wdk_sys::FILE_NO_EA_KNOWLEDGE
    | wdk_sys::FILE_RANDOM_ACCESS
    | wdk_sys::FILE_OPEN_FOR_BACKUP_INTENT
    | wdk_sys::FILE_NO_COMPRESSION
    | wdk_sys::FILE_DISALLOW_EXCLUSIVE
    | wdk_sys::FILE_OPEN_NO_RECALL
    | wdk_sys::FILE_OPEN_FOR_FREE_SPACE_QUERY;
/// Create options accepted by this FSD boundary.
const ACCEPTED_CREATE_OPTIONS: wdk_sys::ULONG = DOMAIN_CREATE_OPTIONS | IGNORED_CREATE_HINT_OPTIONS;
/// WDK share-access bits accepted by create/open.
const FILE_SHARE_ACCESS_MASK: wdk_sys::USHORT = 0x0007;

/// Decoded mount-volume stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MountVolumeStack {
    /// VPB supplied by the I/O Manager for the target volume.
    vpb: KernelVpb,
    /// Lower storage device object to mount.
    target_device: KernelDevice,
    /// Output buffer length supplied with the mount request.
    output_buffer_length: IrpBufferLength,
}

/// Decoded user file-system-control stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FileSystemControlStack {
    /// FILE_OBJECT carrying the FCB/CCB for path-scoped controls.
    file_object: KernelFileObject,
    /// Input system-buffer length.
    input_buffer_length: IrpBufferLength,
    /// Output system-buffer length.
    output_buffer_length: IrpBufferLength,
    /// Requested FSCTL code.
    fs_control_code: FsControlCode,
}

impl MountVolumeStack {
    /// Returns the VPB supplied for the mount.
    pub(crate) const fn vpb(self) -> KernelVpb {
        self.vpb
    }

    /// Returns the lower storage device object.
    pub(crate) const fn target_device(self) -> KernelDevice {
        self.target_device
    }

    /// Returns the mount request output buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }
}

impl FileSystemControlStack {
    /// Returns the FILE_OBJECT carrying this FSCTL.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the input system-buffer length.
    pub(crate) const fn input_buffer_length(self) -> IrpBufferLength {
        self.input_buffer_length
    }

    /// Returns the output system-buffer length.
    pub(crate) const fn output_buffer_length(self) -> IrpBufferLength {
        self.output_buffer_length
    }

    /// Returns the FSCTL code.
    pub(crate) const fn fs_control_code(self) -> FsControlCode {
        self.fs_control_code
    }
}

/// Decoded create/open stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreateStack {
    /// FILE_OBJECT receiving FsContext/FsContext2 on successful create.
    file_object: KernelFileObject,
    /// Decoded create parameters.
    parameters: CreateParameters,
}

impl CreateStack {
    /// Returns the FILE_OBJECT receiving this create request.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the decoded create parameters.
    pub(crate) const fn parameters(self) -> CreateParameters {
        self.parameters
    }
}

/// Decoded query-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryVolumeStack {
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested filesystem information class.
    information_class: QueryVolumeInformationClass,
}

/// Decoded set-volume-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetVolumeStack {
    /// Input buffer length.
    length: IrpBufferLength,
    /// Requested filesystem information class.
    information_class: SetVolumeInformationClass,
}

/// Decoded query-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested file information class.
    information_class: QueryFileInformationClass,
}

/// Decoded set-file-information stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetFileStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Input buffer length.
    length: IrpBufferLength,
    /// Requested file information class.
    information_class: SetFileInformationClass,
}

/// Decoded query-directory stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryDirectoryStack {
    /// FILE_OBJECT carrying the directory CCB.
    file_object: KernelFileObject,
    /// Initial CCB cursor position.
    cursor_position: DirectoryCursorPosition,
    /// Filename pattern supplied by the caller.
    pattern: DirectoryPatternInput,
    /// Directory entry emission cardinality.
    entry_emission: DirectoryEntryEmission,
    /// Output buffer length.
    length: IrpBufferLength,
    /// Requested directory information class.
    information_class: DirectoryInformationClass,
}

/// Decoded directory-change-notification stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NotifyDirectoryStack {
    /// FILE_OBJECT carrying the directory CCB.
    file_object: KernelFileObject,
    /// Changes that complete this notification request.
    completion_filter: DirectoryChangeFilter,
    /// Directory depth covered by the notification request.
    watch_scope: DirectoryWatchScope,
}

/// Decoded query-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QueryEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// EA selection requested by the caller.
    selection: EaSelection,
    /// EA entry emission cardinality.
    entry_emission: EaEntryEmission,
    /// Output buffer length.
    length: IrpBufferLength,
}

/// Decoded set-EA stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetEaStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Input FILE_FULL_EA_INFORMATION byte length.
    length: IrpBufferLength,
}

/// Decoded query-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QuerySecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Output buffer length.
    length: IrpBufferLength,
}

/// Decoded set-security stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SetSecurityStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Caller-supplied security descriptor, valid only during requestor-context capture.
    security_descriptor: NonNull<c_void>,
}

/// Starting point selected by a Windows read request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadStartingPoint {
    /// Read from an explicit non-negative file offset.
    Absolute(FileOffset),
    /// Read from the synchronous FILE_OBJECT's current position.
    CurrentFilePosition,
}

impl ReadStartingPoint {
    /// Decodes a signed Windows read offset into its semantic form.
    /// # Errors
    ///
    /// Returns an error for end-of-file or unknown negative sentinel values.
    fn from_quad(value: i64) -> DriverResult<Self> {
        if value == signed_special_offset(wdk_sys::FILE_USE_FILE_POINTER_POSITION) {
            return Ok(Self::CurrentFilePosition);
        }
        let offset = u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self::Absolute(FileOffset::from_bytes(offset)))
    }
}

/// Starting point selected by a Windows write request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteStartingPoint {
    /// Write from an explicit non-negative file offset.
    Absolute(FileOffset),
    /// Write from the synchronous FILE_OBJECT's current position.
    CurrentFilePosition,
    /// Resolve the starting point from the latest committed end of file.
    EndOfFile,
}

impl WriteStartingPoint {
    /// Decodes a signed Windows write offset into its semantic form.
    /// # Errors
    ///
    /// Returns an error for unknown negative sentinel values.
    fn from_quad(value: i64) -> DriverResult<Self> {
        if value == signed_special_offset(wdk_sys::FILE_USE_FILE_POINTER_POSITION) {
            return Ok(Self::CurrentFilePosition);
        }
        if value == signed_special_offset(wdk_sys::FILE_WRITE_TO_END_OF_FILE) {
            return Ok(Self::EndOfFile);
        }
        let offset = u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self::Absolute(FileOffset::from_bytes(offset)))
    }
}

/// Byte-range lock key carried by one read or write request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteRangeLockKey(wdk_sys::ULONG);

impl ByteRangeLockKey {
    /// Wraps the key decoded from an IRP stack location.
    const fn from_ulong(value: wdk_sys::ULONG) -> Self {
        Self(value)
    }

    /// Returns the native key for FsRtl range checks.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "native FsRtl byte-range checks are compiled out in unit tests"
        )
    )]
    pub(crate) const fn as_ulong(self) -> wdk_sys::ULONG {
        self.0
    }
}

/// Interprets a Windows low-part sentinel as its sign-extended 64-bit offset.
fn signed_special_offset(value: u32) -> i64 {
    i64::from(i32::from_ne_bytes(value.to_ne_bytes()))
}

/// Decoded read stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Requested byte count.
    length: IrpBufferLength,
    /// Semantic starting point decoded from ByteOffset.
    starting_point: ReadStartingPoint,
    /// Key used for byte-range lock ownership checks.
    key: ByteRangeLockKey,
}

impl ReadStack {
    /// Returns the FILE_OBJECT carrying this read.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested semantic starting point.
    pub(crate) const fn starting_point(self) -> ReadStartingPoint {
        self.starting_point
    }

    /// Returns the byte-range lock key.
    pub(crate) const fn key(self) -> ByteRangeLockKey {
        self.key
    }
}

/// Decoded write stack parameters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WriteStack {
    /// FILE_OBJECT carrying the FCB/CCB.
    file_object: KernelFileObject,
    /// Requested byte count.
    length: IrpBufferLength,
    /// Semantic starting point decoded from ByteOffset.
    starting_point: WriteStartingPoint,
    /// Key used for byte-range lock ownership checks.
    key: ByteRangeLockKey,
}

impl WriteStack {
    /// Returns the FILE_OBJECT carrying this write.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the requested byte count.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested semantic starting point.
    pub(crate) const fn starting_point(self) -> WriteStartingPoint {
        self.starting_point
    }

    /// Returns the byte-range lock key.
    pub(crate) const fn key(self) -> ByteRangeLockKey {
        self.key
    }
}

impl QueryVolumeStack {
    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> QueryVolumeInformationClass {
        self.information_class
    }
}

impl SetVolumeStack {
    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested filesystem information class.
    pub(crate) const fn information_class(self) -> SetVolumeInformationClass {
        self.information_class
    }
}

impl QueryFileStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> QueryFileInformationClass {
        self.information_class
    }
}

impl SetFileStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the input buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested file information class.
    pub(crate) const fn information_class(self) -> SetFileInformationClass {
        self.information_class
    }
}

impl QueryDirectoryStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the initial directory cursor position.
    pub(crate) const fn cursor_position(self) -> DirectoryCursorPosition {
        self.cursor_position
    }

    /// Returns the query-directory filename pattern input.
    pub(crate) const fn pattern(self) -> DirectoryPatternInput {
        self.pattern
    }

    /// Returns directory entry emission cardinality.
    pub(crate) const fn entry_emission(self) -> DirectoryEntryEmission {
        self.entry_emission
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }

    /// Returns the requested directory information class.
    pub(crate) const fn information_class(self) -> DirectoryInformationClass {
        self.information_class
    }
}

impl NotifyDirectoryStack {
    /// Returns the FILE_OBJECT carrying this notification request.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the validated completion-filter set.
    pub(crate) const fn completion_filter(self) -> DirectoryChangeFilter {
        self.completion_filter
    }

    /// Returns the directory depth covered by this request.
    pub(crate) const fn watch_scope(self) -> DirectoryWatchScope {
        self.watch_scope
    }
}

impl QueryEaStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the EA selection.
    pub(crate) const fn selection(self) -> EaSelection {
        self.selection
    }

    /// Returns EA entry emission cardinality.
    pub(crate) const fn entry_emission(self) -> EaEntryEmission {
        self.entry_emission
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl SetEaStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns the input FILE_FULL_EA_INFORMATION byte length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl QuerySecurityStack {
    /// Returns the FILE_OBJECT carrying this query.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the output buffer length.
    pub(crate) const fn length(self) -> IrpBufferLength {
        self.length
    }
}

impl SetSecurityStack {
    /// Returns the FILE_OBJECT carrying this mutation.
    pub(crate) const fn file_object(self) -> KernelFileObject {
        self.file_object
    }

    /// Returns selected security descriptor components.
    pub(crate) const fn selection(self) -> SecuritySelection {
        self.selection
    }

    /// Returns the caller-supplied descriptor only to requestor-context capture.
    const fn security_descriptor_source(self) -> NonNull<c_void> {
        self.security_descriptor
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use core::ffi::c_void;

    use ext4_core::FileOffset;
    use wdk_sys::{STATUS_ACCESS_DENIED, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};

    use super::{
        CREATE_DISPOSITION_SHIFT, CreateAction, CreateCompletion, CreateDisposition,
        CreateNameInterpretation, CreateReparsePointMode, CreateSymlinkReparseBuffer,
        CreateSynchronizationMode, CreateTargetRequirement, CreateTransferBuffering,
        CurrentIrpStackLocation, DataIoKind, DeviceExecutor, DirectoryChangeFilter,
        DirectoryControlMinorFunction, DirectoryCursorPosition, DirectoryEntryEmission,
        DirectoryInformationClass, DirectoryPatternInput, DirectoryWatchScope, DispatchMajor,
        DispatchTarget, EaEntryEmission, EaEntryIndex, EaSelection, FILE_OPEN_DISPOSITION,
        FILE_OPEN_IF_DISPOSITION, FILE_OVERWRITE_DISPOSITION, FILE_OVERWRITE_IF_DISPOSITION,
        FILE_SUPERSEDE_DISPOSITION, FileSystemControlMinorFunction, FsControlCode,
        InformationLength, IrpBufferLength, IrpCompletion, KernelIrp, OwnedIrp,
        QueryFileInformationClass, QueryVolumeInformationClass, ReadStartingPoint, ReceivedIrp,
        RegularFileWriteAccess, STATUS_CANCELLED, SetFileInformationClass,
        SetVolumeInformationClass, WriteStartingPoint,
    };
    use crate::kernel::status::DriverError;
    use crate::security_descriptor::SecurityComponentSelection;
    use crate::state::{KernelDevice, KernelFileObject, KernelVpb, WriteCommitment};

    /// IRP_MN_MOUNT_VOLUME as a stack-location minor function byte.
    const MOUNT_VOLUME_MINOR: wdk_sys::UCHAR = 1;

    /// Returns a non-null opaque pointer for decode-only dispatch tests.
    fn opaque<T>() -> *mut T {
        NonNull::<c_void>::dangling().as_ptr().cast()
    }

    use core::ptr::NonNull;

    /// Reads the active IRP status union arm.
    fn irp_status(irp: &wdk_sys::IRP) -> wdk_sys::NTSTATUS {
        unsafe {
            // SAFETY: Tests read the status arm after initializing or writing
            // it through IRP completion helpers.
            irp.IoStatus.__bindgen_anon_1.Status
        }
    }

    /// Builds unlinked executor storage for a device-owned extension.
    fn executor_storage(device: KernelDevice) -> DeviceExecutor {
        DeviceExecutor::test_storage(device)
    }

    /// Initializes executor links after the storage has reached its stable stack address.
    fn initialize_executor_links(executor: &DeviceExecutor) {
        executor.initialize_test_links();
    }

    /// Publishes executor storage as the device extension used by dispatch lookup.
    fn attach_executor_extension(
        device: &mut wdk_sys::DEVICE_OBJECT,
        executor: &mut DeviceExecutor,
    ) {
        device.DeviceExtension = core::ptr::from_mut(executor).cast::<c_void>();
    }

    /// Returns whether the current stack control byte contains the pending-returned bit.
    fn stack_has_pending_returned(stack: &wdk_sys::IO_STACK_LOCATION) -> bool {
        u32::from(stack.Control) & wdk_sys::SL_PENDING_RETURNED == wdk_sys::SL_PENDING_RETURNED
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn null_dispatch_target_is_invalid_parameter() {
        assert_eq!(
            DispatchTarget::decode(core::ptr::null_mut(), opaque::<wdk_sys::IRP>())
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            DispatchTarget::decode(opaque::<wdk_sys::DEVICE_OBJECT>(), core::ptr::null_mut())
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
        let device = opaque::<wdk_sys::DEVICE_OBJECT>();
        let irp = opaque::<wdk_sys::IRP>();
        let decoded = DispatchTarget::decode(device, irp);
        assert!(decoded.is_ok());
        if let Ok(target) = decoded {
            assert_eq!(target.device().as_ptr(), device);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn irp_completion_writes_status_and_information_together() {
        let mut irp = wdk_sys::IRP::default();
        let kernel_irp = KernelIrp::from_raw(core::ptr::addr_of_mut!(irp));
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
    fn failed_irp_completion_writes_zero_information() {
        let mut irp = wdk_sys::IRP::default();
        irp.IoStatus.Information = 128;
        let kernel_irp = KernelIrp::from_raw(core::ptr::addr_of_mut!(irp));
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
            0x0C, 0x00, 0x00, 0xA0, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
        ];
        let invalid_tag = CreateSymlinkReparseBuffer::try_pack_exact(VALID.len(), |output| {
            output.copy_from_slice(&VALID);
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
                output.copy_from_slice(&VALID);
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
            output.copy_from_slice(&VALID);
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
    fn create_reparse_completion_transfers_exact_auxiliary_buffer() {
        const EXPECTED: [u8; 22] = [
            0x0C, 0x00, 0x00, 0xA0, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
        ];

        let mut device_object = wdk_sys::DEVICE_OBJECT::default();
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(device_object));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut irp = wdk_sys::IRP::default();
        let owned = OwnedIrp::from_test_raw(device, core::ptr::addr_of_mut!(irp));
        assert!(owned.is_some());
        let Some(owned) = owned else {
            return;
        };

        let buffer = CreateSymlinkReparseBuffer::try_pack_exact(EXPECTED.len(), |output| {
            output.copy_from_slice(&EXPECTED);
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
            let allocation = core::ptr::slice_from_raw_parts_mut(
                auxiliary.as_ptr().cast::<u8>(),
                EXPECTED.len(),
            );
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
    fn create_handle_completion_publishes_exact_action() {
        for (action, expected) in [
            (CreateAction::Opened, wdk_sys::FILE_OPENED),
            (CreateAction::Created, wdk_sys::FILE_CREATED),
        ] {
            let mut device_object = wdk_sys::DEVICE_OBJECT::default();
            let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(device_object));
            assert!(device.is_some());
            let Some(device) = device else {
                return;
            };
            let mut irp = wdk_sys::IRP::default();
            let owned = OwnedIrp::from_test_raw(device, core::ptr::addr_of_mut!(irp));
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
    /// Panics when a failed create request publishes ownership into the IRP tail overlay.
    #[test]
    fn failed_create_completion_never_publishes_auxiliary_buffer() {
        let mut device_object = wdk_sys::DEVICE_OBJECT::default();
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(device_object));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut irp = wdk_sys::IRP::default();
        let owned = OwnedIrp::from_test_raw(device, core::ptr::addr_of_mut!(irp));
        assert!(owned.is_some());
        if let Some(owned) = owned {
            assert_eq!(
                owned.complete_create_result(Err(
                    crate::kernel::status::DriverError::InvalidParameter
                )),
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
    fn device_executor_receive_marks_current_stack_pending() {
        let mut kernel_device = wdk_sys::DEVICE_OBJECT::default();
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(kernel_device));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut executor = executor_storage(device);
        initialize_executor_links(&executor);
        attach_executor_extension(&mut kernel_device, &mut executor);

        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut irp = wdk_sys::IRP::default();
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack);

        let received = ReceivedIrp::decode(
            core::ptr::addr_of_mut!(kernel_device),
            core::ptr::addr_of_mut!(irp),
        );
        assert!(received.is_ok());
        if let Ok(received) = received {
            assert_eq!(
                DeviceExecutor::receive(received, DispatchMajor::Create),
                wdk_sys::STATUS_PENDING
            );
            assert!(stack_has_pending_returned(&stack));
            assert!(executor.test_worker_is_queued());
            assert_eq!(
                executor.test_remove_next_irp(core::ptr::null_mut()),
                core::ptr::addr_of_mut!(irp)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn device_executor_receive_completes_without_pending_when_extension_is_absent() {
        let mut kernel_device = wdk_sys::DEVICE_OBJECT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let mut irp = wdk_sys::IRP::default();
        irp.IoStatus.Information = 99;
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack);

        let received = ReceivedIrp::decode(
            core::ptr::addr_of_mut!(kernel_device),
            core::ptr::addr_of_mut!(irp),
        );
        assert!(received.is_ok());
        if let Ok(received) = received {
            assert_eq!(
                DeviceExecutor::receive(received, DispatchMajor::Create),
                STATUS_INVALID_PARAMETER
            );
        }

        assert!(!stack_has_pending_returned(&stack));
        assert_eq!(irp_status(&irp), STATUS_INVALID_PARAMETER);
        assert_eq!(irp.IoStatus.Information, 0);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn device_executor_receive_completes_when_pending_mark_fails() {
        let mut kernel_device = wdk_sys::DEVICE_OBJECT::default();
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(kernel_device));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut executor = executor_storage(device);
        initialize_executor_links(&executor);
        attach_executor_extension(&mut kernel_device, &mut executor);

        let mut irp = wdk_sys::IRP::default();
        irp.IoStatus.Information = 99;
        let received = ReceivedIrp::decode(
            core::ptr::addr_of_mut!(kernel_device),
            core::ptr::addr_of_mut!(irp),
        );
        assert!(received.is_ok());
        if let Ok(received) = received {
            assert_eq!(
                DeviceExecutor::receive(received, DispatchMajor::Create),
                STATUS_INVALID_PARAMETER
            );
        }

        assert_eq!(irp_status(&irp), STATUS_INVALID_PARAMETER);
        assert_eq!(irp.IoStatus.Information, 0);
        assert!(executor.test_worker_is_dormant());
        assert!(
            executor
                .test_remove_next_irp(core::ptr::null_mut())
                .is_null()
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn device_executor_removes_irps_in_fifo_order() {
        let mut kernel_device = wdk_sys::DEVICE_OBJECT::default();
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(kernel_device));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut executor = executor_storage(device);
        initialize_executor_links(&executor);
        attach_executor_extension(&mut kernel_device, &mut executor);

        let mut stack_a = wdk_sys::IO_STACK_LOCATION::default();
        let mut stack_b = wdk_sys::IO_STACK_LOCATION::default();
        let mut stack_c = wdk_sys::IO_STACK_LOCATION::default();
        let mut irp_a = wdk_sys::IRP::default();
        let mut irp_b = wdk_sys::IRP::default();
        let mut irp_c = wdk_sys::IRP::default();
        irp_a
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack_a);
        irp_b
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack_b);
        irp_c
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack_c);

        for irp in [
            core::ptr::addr_of_mut!(irp_a),
            core::ptr::addr_of_mut!(irp_b),
            core::ptr::addr_of_mut!(irp_c),
        ] {
            let received = ReceivedIrp::decode(core::ptr::addr_of_mut!(kernel_device), irp);
            assert!(received.is_ok());
            if let Ok(received) = received {
                assert_eq!(
                    DeviceExecutor::receive(received, DispatchMajor::Create),
                    wdk_sys::STATUS_PENDING
                );
            }
        }

        assert_eq!(
            executor.test_remove_next_irp(core::ptr::null_mut()),
            core::ptr::addr_of_mut!(irp_a)
        );
        assert_eq!(
            executor.test_remove_next_irp(core::ptr::null_mut()),
            core::ptr::addr_of_mut!(irp_b)
        );
        assert_eq!(
            executor.test_remove_next_irp(core::ptr::null_mut()),
            core::ptr::addr_of_mut!(irp_c)
        );
        assert!(
            executor
                .test_remove_next_irp(core::ptr::null_mut())
                .is_null()
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn device_executor_cancels_only_matching_file_object() {
        let mut kernel_device = wdk_sys::DEVICE_OBJECT::default();
        let device = KernelDevice::from_raw(core::ptr::addr_of_mut!(kernel_device));
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let mut executor = executor_storage(device);
        initialize_executor_links(&executor);
        attach_executor_extension(&mut kernel_device, &mut executor);

        let mut file_a = wdk_sys::FILE_OBJECT::default();
        let mut file_b = wdk_sys::FILE_OBJECT::default();
        let mut stack_a1 = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::addr_of_mut!(file_a),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut stack_b = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::addr_of_mut!(file_b),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut stack_a2 = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::addr_of_mut!(file_a),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut irp_a1 = wdk_sys::IRP::default();
        let mut irp_b = wdk_sys::IRP::default();
        let mut irp_a2 = wdk_sys::IRP::default();
        irp_a1.IoStatus.Information = 99;
        irp_b.IoStatus.Information = 99;
        irp_a2.IoStatus.Information = 99;
        irp_a1
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack_a1);
        irp_b
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack_b);
        irp_a2
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack_a2);

        for irp in [
            core::ptr::addr_of_mut!(irp_a1),
            core::ptr::addr_of_mut!(irp_b),
            core::ptr::addr_of_mut!(irp_a2),
        ] {
            let received = ReceivedIrp::decode(core::ptr::addr_of_mut!(kernel_device), irp);
            assert!(received.is_ok());
            if let Ok(received) = received {
                assert_eq!(
                    DeviceExecutor::receive(received, DispatchMajor::Create),
                    wdk_sys::STATUS_PENDING
                );
            }
        }

        let file_object = KernelFileObject::from_raw(core::ptr::addr_of_mut!(file_a));
        assert!(file_object.is_some());
        if let Some(file_object) = file_object {
            assert_eq!(
                DeviceExecutor::cancel_file_object(device, file_object),
                Ok(())
            );
        }

        assert_eq!(irp_status(&irp_a1), STATUS_CANCELLED);
        assert_eq!(irp_a1.IoStatus.Information, 0);
        assert_eq!(irp_status(&irp_a2), STATUS_CANCELLED);
        assert_eq!(irp_a2.IoStatus.Information, 0);
        assert_eq!(irp_status(&irp_b), wdk_sys::STATUS_SUCCESS);
        assert_eq!(irp_b.IoStatus.Information, 99);
        assert_eq!(
            executor.test_remove_next_irp(core::ptr::null_mut()),
            core::ptr::addr_of_mut!(irp_b)
        );
        assert!(
            executor
                .test_remove_next_irp(core::ptr::null_mut())
                .is_null()
        );
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
        assert_eq!(
            CurrentIrpStackLocation::from_raw(core::ptr::null_mut())
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
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
            CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack))
                .map(|current| current.file_system_control_minor()),
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
            CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack))
                .map(|current| current.directory_control_minor()),
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(
                current.file_system_control_minor(),
                FileSystemControlMinorFunction::MountVolume
            );
            let mount = current.mount_volume();
            assert!(mount.is_ok());
            if let Ok(mount) = mount {
                assert_eq!(Some(mount.vpb()), KernelVpb::from_raw(vpb.as_ptr()));
                assert_eq!(
                    Some(mount.target_device()),
                    KernelDevice::from_raw(target.as_ptr())
                );
                assert_eq!(mount.output_buffer_length().as_usize(), 16);
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_system_control_stack_decodes_supported_user_control() {
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: file_object.as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.FileSystemControl =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
                OutputBufferLength: 128,
                __bindgen_padding_0: 0,
                InputBufferLength: 32,
                __bindgen_padding_1: 0,
                FsControlCode: 589_992,
                Type3InputBuffer: core::ptr::null_mut(),
            };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let control = current.file_system_control();
            assert!(control.is_ok());
            if let Ok(control) = control {
                assert_eq!(
                    Some(control.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
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
        stack.Parameters.FileSystemControl =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_15 {
                OutputBufferLength: 128,
                __bindgen_padding_0: 0,
                InputBufferLength: 32,
                __bindgen_padding_1: 0,
                FsControlCode: 0xFFFF_FFFF,
                Type3InputBuffer: core::ptr::null_mut(),
            };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn create_stack_preserves_access_share_options_and_ea_length() {
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let desired_access =
            wdk_sys::FILE_READ_DATA | wdk_sys::FILE_WRITE_DATA | wdk_sys::SYNCHRONIZE;
        let mut security_context = wdk_sys::IO_SECURITY_CONTEXT {
            DesiredAccess: desired_access,
            ..wdk_sys::IO_SECURITY_CONTEXT::default()
        };
        let mut stack = wdk_sys::IO_STACK_LOCATION {
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let create = current.create();
            assert!(create.is_ok());
            if let Ok(create) = create {
                assert_eq!(
                    Some(create.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
                    create.parameters().existing_operation_access().as_raw(),
                    requested_access | required_access
                );
            }
        }
    }

    /// # Panics
    ///
    /// Panics when the unsafe delete-on-close lifecycle is accepted.
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(current.create().err(), Some(DriverError::NotSupported));
        }
    }

    /// # Panics
    ///
    /// Panics when delete-on-close is accepted even when DELETE was requested.
    #[test]
    fn create_stack_rejects_delete_on_close_until_safe_orphan_lifecycle_exists() {
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            assert_eq!(current.create().err(), Some(DriverError::NotSupported));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
                | wdk_sys::FILE_OPEN_REQUIRING_OPLOCK,
            __bindgen_padding_0: [0; 2],
            FileAttributes: 0,
            ShareAccess: 0,
            __bindgen_padding_1: 0,
            EaLength: 0,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    fn query_ea_stack_decodes_name_selection_length_and_emission() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_ea();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(query.entry_emission(), EaEntryEmission::Single);
                assert_eq!(query.length().as_usize(), 128);
                assert_eq!(
                    query.selection(),
                    EaSelection::Names {
                        address: ea_list,
                        length: super::IrpBufferLength(24),
                    }
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
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_INDEX_SPECIFIED).unwrap_or(u8::MAX);
        stack.Parameters.QueryEa = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_11 {
            Length: 128,
            EaList: core::ptr::null_mut(),
            EaListLength: 0,
            __bindgen_padding_0: 0,
            EaIndex: 3,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_ea();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(query.selection(), EaSelection::Index(EaEntryIndex(3)));
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn set_ea_stack_preserves_file_object_and_length() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.SetEa =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_12 { Length: 64 };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_ea();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(
                    Some(set.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(set.length().as_usize(), 64);
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn query_security_stack_preserves_file_object_information_and_length() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
            SecurityInformation: wdk_sys::OWNER_SECURITY_INFORMATION
                | wdk_sys::DACL_SECURITY_INFORMATION,
            __bindgen_padding_0: 0,
            Length: 256,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_security();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
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
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
            SecurityInformation: wdk_sys::SACL_SECURITY_INFORMATION,
            __bindgen_padding_0: 0,
            Length: 256,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QuerySecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_18 {
            SecurityInformation: LABEL_SECURITY_INFORMATION,
            __bindgen_padding_0: 0,
            Length: 256,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    fn set_security_stack_preserves_file_object_information_and_descriptor() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let descriptor = NonNull::<c_void>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.SetSecurity = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_19 {
            SecurityInformation: wdk_sys::OWNER_SECURITY_INFORMATION
                | wdk_sys::GROUP_SECURITY_INFORMATION,
            SecurityDescriptor: descriptor.as_ptr(),
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_security();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(
                    Some(set.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
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
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
            let target = DispatchTarget::decode(
                core::ptr::addr_of_mut!(device),
                core::ptr::addr_of_mut!(irp),
            );
            assert!(target.is_ok());
            if let Ok(target) = target {
                assert_eq!(target.data_io_kind(), expected);
            }
        }
    }

    /// # Panics
    ///
    /// Panics when desired access does not produce one exclusive write authority.
    #[test]
    fn desired_access_projects_regular_file_write_authority() {
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
                super::DesiredAccess::from_raw(raw).regular_file_write_access(),
                expected
            );
        }
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
                    create
                        .parameters()
                        .desired_access()
                        .regular_file_write_access(),
                    RegularFileWriteAccess::AppendOnly
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

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    fn query_file_stack_preserves_file_object_length_and_class() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QueryFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
            Length: 64,
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileStandardInformation,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_file();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
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
    fn query_file_stack_decodes_name_and_attribute_tag_classes() {
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        for (raw_class, expected) in [
            (
                wdk_sys::_FILE_INFORMATION_CLASS::FileNameInformation,
                QueryFileInformationClass::Name,
            ),
            (
                wdk_sys::_FILE_INFORMATION_CLASS::FileAttributeTagInformation,
                QueryFileInformationClass::AttributeTag,
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    fn set_file_stack_preserves_file_object_length_and_class() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
            Length: 40,
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileBasicInformation,
            FileObject: core::ptr::null_mut(),
            __bindgen_anon_1:
                wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let set = current.set_file();
            assert!(set.is_ok());
            if let Ok(set) = set {
                assert_eq!(
                    Some(set.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(set.length().as_usize(), 40);
                assert_eq!(set.information_class(), SetFileInformationClass::Basic);
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_information_stack_rejects_unsupported_class_before_handler() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QueryFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_9 {
            Length: 64,
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    fn query_directory_stack_decodes_restart_pattern_length_class_and_emission() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let file_name = NonNull::<wdk_sys::UNICODE_STRING>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_RESTART_SCAN | wdk_sys::SL_RETURN_SINGLE_ENTRY)
            .unwrap_or(u8::MAX);
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: file_name.as_ptr(),
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
            __bindgen_padding_0: 0,
            FileIndex: 3,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_directory();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(
                    Some(query.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
                );
                assert_eq!(query.cursor_position(), DirectoryCursorPosition::Restart);
                assert_eq!(query.pattern(), DirectoryPatternInput::Name(file_name));
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
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: core::ptr::null_mut(),
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileNamesInformation,
            __bindgen_padding_0: 0,
            FileIndex: 0,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn query_directory_stack_decodes_index_cursor() {
        let mut stack = wdk_sys::IO_STACK_LOCATION::default();
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        stack.FileObject = file_object.as_ptr();
        stack.Flags = u8::try_from(wdk_sys::SL_INDEX_SPECIFIED).unwrap_or(u8::MAX);
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: core::ptr::null_mut(),
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
            __bindgen_padding_0: 0,
            FileIndex: 3,
        };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let query = current.query_directory();
            assert!(query.is_ok());
            if let Ok(query) = query {
                assert_eq!(
                    query.cursor_position(),
                    DirectoryCursorPosition::Index(super::DirectoryEntryIndex(3))
                );
                assert_eq!(query.pattern(), DirectoryPatternInput::All);
                assert_eq!(query.entry_emission(), DirectoryEntryEmission::Multiple);
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn notify_directory_stack_decodes_filter_and_scope() {
        let file_object = NonNull::<wdk_sys::FILE_OBJECT>::dangling();
        let completion_filter = wdk_sys::FILE_NOTIFY_CHANGE_FILE_NAME
            | wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES
            | wdk_sys::FILE_NOTIFY_CHANGE_SECURITY;
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MinorFunction: u8::try_from(wdk_sys::IRP_MN_NOTIFY_CHANGE_DIRECTORY).unwrap_or(u8::MAX),
            Flags: u8::try_from(wdk_sys::SL_WATCH_TREE).unwrap_or(u8::MAX),
            FileObject: file_object.as_ptr(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.NotifyDirectory =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_7 {
                Length: 512,
                __bindgen_padding_0: 0,
                CompletionFilter: completion_filter,
            };

        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
        assert!(current.is_ok());
        if let Ok(current) = current {
            let notification = current.notify_directory();
            assert!(notification.is_ok());
            if let Ok(notification) = notification {
                assert_eq!(
                    Some(notification.file_object()),
                    KernelFileObject::from_raw(file_object.as_ptr())
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
        let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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

            let current = CurrentIrpStackLocation::from_raw(core::ptr::addr_of_mut!(stack));
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
}
