//! Asynchronous lower-storage boundary for ext4-core.

use alloc::{
    alloc::{alloc_zeroed, dealloc},
    sync::Arc,
};
use core::{
    alloc::Layout,
    cell::UnsafeCell,
    ffi::c_void,
    future::Future,
    mem::MaybeUninit,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use ext4_core::{BlockSource, BlockStorage, ByteOffset, DeviceLength, Error, Result};
#[cfg(not(test))]
use wdk_sys::{IRP_MJ_DEVICE_CONTROL, LARGE_INTEGER, PIO_STACK_LOCATION, PIRP};
use wdk_sys::{IRP_MJ_FLUSH_BUFFERS, IRP_MJ_READ, IRP_MJ_WRITE, NTSTATUS};

#[cfg(not(test))]
use crate::kernel::ffi;
use crate::kernel::status::{DriverError, DriverResult};
use crate::state::KernelDevice;

/// Completion context has not yet received the terminal lower-driver status.
const COMPLETION_IN_FLIGHT: u8 = 0;
/// Completion context contains the terminal status and byte count.
const COMPLETION_READY: u8 = 1;
/// Completed signal is being returned to its one-shot pre-submission state.
const COMPLETION_REARMING: u8 = 2;
/// `TRUE` represented as a WDK `BOOLEAN`.
#[cfg_attr(
    test,
    expect(dead_code, reason = "unit tests do not submit private kernel IRPs")
)]
const BOOLEAN_TRUE: wdk_sys::BOOLEAN = 1;
/// Stops I/O Manager completion after this driver frees its private lower IRP.
#[cfg_attr(
    test,
    expect(dead_code, reason = "unit tests do not run I/O Manager completions")
)]
const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS = i32::from_ne_bytes(0xC000_0016_u32.to_ne_bytes());
/// `IOCTL_DISK_GET_LENGTH_INFO` from `ntdddisk.h`.
#[cfg_attr(
    test,
    expect(dead_code, reason = "unit tests do not submit private kernel IRPs")
)]
const IOCTL_DISK_GET_LENGTH_INFO: wdk_sys::ULONG = 0x0007_405C;

/// Completion signal shared by all private lower IRPs.
struct LowerIrpSignal {
    /// Executor waker installed before the private IRP can be submitted.
    waker: UnsafeCell<MaybeUninit<Waker>>,
    /// Publish point for the initialized executor waker.
    waker_ready: AtomicBool,
    /// Lower terminal status.
    status: AtomicI32,
    /// Lower terminal byte count.
    information: AtomicUsize,
    /// Publish point for terminal status and completion-owned output storage.
    phase: AtomicU8,
}

impl LowerIrpSignal {
    /// Creates one signal before its IRP is exposed to a lower driver.
    const fn new() -> Self {
        Self {
            waker: UnsafeCell::new(MaybeUninit::uninit()),
            waker_ready: AtomicBool::new(false),
            status: AtomicI32::new(wdk_sys::STATUS_PENDING),
            information: AtomicUsize::new(0),
            phase: AtomicU8::new(COMPLETION_IN_FLIGHT),
        }
    }

    /// Installs the task executor waker before a lower driver can observe the private IRP.
    /// # Errors
    ///
    /// Returns an error if this one-shot signal already has a registered waker.
    fn register_waker(&self, waker: &Waker) -> Result<()> {
        if self.phase.load(Ordering::Acquire) != COMPLETION_IN_FLIGHT
            || self.waker_ready.load(Ordering::Relaxed)
        {
            return Err(Error::DeviceIo);
        }
        unsafe {
            // SAFETY: The first poll is the sole writer, and submission cannot expose this signal
            // to another thread until after the release store below.
            (*self.waker.get()).write(waker.clone());
        }
        self.waker_ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Stages terminal lower status and clones the executor waker without publishing readiness.
    fn stage_completion(&self, status: NTSTATUS, information: usize) -> Option<Waker> {
        self.status.store(status, Ordering::Relaxed);
        self.information.store(information, Ordering::Relaxed);
        if self.waker_ready.load(Ordering::Acquire) {
            let slot = unsafe {
                // SAFETY: `waker_ready` publishes the initialized slot before this read.
                &*self.waker.get()
            };
            let waker = unsafe {
                // SAFETY: The readiness flag proves that `slot` contains one initialized waker.
                slot.assume_init_ref()
            };
            Some(waker.clone())
        } else {
            None
        }
    }

    /// Publishes that every callback-owned transfer resource has been released.
    fn publish_ready(&self) {
        self.phase.store(COMPLETION_READY, Ordering::Release);
    }

    /// Stages and immediately publishes contexts whose callback owns no mutable transfer buffer.
    #[cfg_attr(
        test,
        expect(dead_code, reason = "unit tests do not run lower completion callbacks")
    )]
    fn complete(&self, status: NTSTATUS, information: usize) -> Option<Waker> {
        let waker = self.stage_completion(status, information);
        self.publish_ready();
        waker
    }

    /// Reads the published terminal status and validates an optional exact byte count.
    fn result(&self, expected_information: Option<usize>) -> Option<Result<()>> {
        if self.phase.load(Ordering::Acquire) != COMPLETION_READY {
            return None;
        }
        let status = self.status.load(Ordering::Relaxed);
        if status < wdk_sys::STATUS_SUCCESS {
            return Some(Err(Error::DeviceIo));
        }
        if expected_information
            .is_some_and(|expected| self.information.load(Ordering::Relaxed) != expected)
        {
            return Some(Err(Error::DeviceIo));
        }
        Some(Ok(()))
    }

    /// Returns this completed signal to its pre-submission state under unique ownership.
    /// # Errors
    ///
    /// Returns an error if terminal completion has not yet been published.
    fn rearm(&self) -> Result<()> {
        self.phase
            .compare_exchange(
                COMPLETION_READY,
                COMPLETION_REARMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::DeviceIo)?;
        if self.waker_ready.swap(false, Ordering::AcqRel) {
            let slot = unsafe {
                // SAFETY: The successful phase transition excludes the old callback from every
                // signal access, and the readiness flag proves this slot was initialized.
                &mut *self.waker.get()
            };
            unsafe {
                // SAFETY: The readiness flag proves that the waker slot was initialized once.
                slot.assume_init_drop();
            }
        }
        self.status
            .store(wdk_sys::STATUS_PENDING, Ordering::Relaxed);
        self.information.store(0, Ordering::Relaxed);
        self.phase.store(COMPLETION_IN_FLIGHT, Ordering::Release);
        Ok(())
    }
}

impl Drop for LowerIrpSignal {
    fn drop(&mut self) {
        if *self.waker_ready.get_mut() {
            unsafe {
                // SAFETY: A true readiness flag means `register_waker` initialized this slot once.
                self.waker.get_mut().assume_init_drop();
            }
        }
    }
}

// SAFETY: Terminal fields are atomic and the waker is published once before submission.
unsafe impl Send for LowerIrpSignal {}
// SAFETY: Interior mutation follows the single-submitter and terminal-completion protocol.
unsafe impl Sync for LowerIrpSignal {}

/// Physical lower-device transfer constraints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferGeometry {
    /// Exposed device byte length.
    length: DeviceLength,
    /// Physical transfer sector size.
    sector_size: usize,
    /// Required virtual-address alignment for transfer buffers.
    buffer_alignment: usize,
}

/// Buffer address representation consumed by the mounted lower storage stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LowerTransferMethod {
    /// The lower stack consumes `IRP.AssociatedIrp.SystemBuffer`.
    Buffered,
    /// The lower stack consumes an MDL describing the nonpaged transfer buffer.
    Direct,
    /// The lower stack consumes the kernel address in `IRP.UserBuffer`.
    Neither,
}

impl LowerTransferMethod {
    /// Decodes the one valid transfer method advertised by a device object.
    /// # Errors
    ///
    /// Returns an error when mutually exclusive buffered and direct flags are both present.
    fn from_device_flags(flags: wdk_sys::ULONG) -> Result<Self> {
        match flags & (wdk_sys::DO_BUFFERED_IO | wdk_sys::DO_DIRECT_IO) {
            0 => Ok(Self::Neither),
            wdk_sys::DO_BUFFERED_IO => Ok(Self::Buffered),
            wdk_sys::DO_DIRECT_IO => Ok(Self::Direct),
            _ => Err(Error::DeviceRange),
        }
    }
}

impl TransferGeometry {
    /// Reads and validates lower-device transfer constraints.
    /// # Errors
    ///
    /// Returns an error when the device object is absent or advertises invalid transfer geometry.
    fn from_device(device: KernelDevice, length: DeviceLength) -> Result<Self> {
        let object = unsafe {
            // SAFETY: `device` is a non-null device object supplied by the mount boundary and is
            // read only for immutable transfer constraints.
            device.as_ptr().as_ref()
        }
        .ok_or(Error::DeviceIo)?;
        let sector_size = usize::from(object.SectorSize);
        let alignment_mask =
            usize::try_from(object.AlignmentRequirement).map_err(|_| Error::DeviceRange)?;
        let buffer_alignment = alignment_mask.checked_add(1).ok_or(Error::DeviceRange)?;
        if sector_size == 0 || !sector_size.is_power_of_two() || !buffer_alignment.is_power_of_two()
        {
            return Err(Error::DeviceRange);
        }
        Ok(Self {
            length,
            sector_size,
            buffer_alignment,
        })
    }

    /// Covers an arbitrary core byte range with whole lower-device sectors.
    /// # Errors
    ///
    /// Returns an error when the requested or aligned range overflows or crosses the device end.
    fn cover(self, offset: ByteOffset, len: usize) -> Result<CoveredTransfer> {
        let len = u64::try_from(len).map_err(|_| Error::DeviceRange)?;
        let requested_end = offset.get().checked_add(len).ok_or(Error::DeviceRange)?;
        if requested_end > self.length.bytes() {
            return Err(Error::DeviceRange);
        }
        let sector_size = u64::try_from(self.sector_size).map_err(|_| Error::DeviceRange)?;
        let sector_mask = sector_size.checked_sub(1).ok_or(Error::DeviceRange)?;
        let aligned_start = offset.get() & !sector_mask;
        let aligned_end = requested_end
            .checked_add(sector_mask)
            .ok_or(Error::DeviceRange)?
            & !sector_mask;
        if aligned_end > self.length.bytes() {
            return Err(Error::DeviceRange);
        }
        let transfer_len = usize::try_from(
            aligned_end
                .checked_sub(aligned_start)
                .ok_or(Error::DeviceRange)?,
        )
        .map_err(|_| Error::DeviceRange)?;
        let requested_start = usize::try_from(
            offset
                .get()
                .checked_sub(aligned_start)
                .ok_or(Error::DeviceRange)?,
        )
        .map_err(|_| Error::DeviceRange)?;
        let requested_end = usize::try_from(
            requested_end
                .checked_sub(aligned_start)
                .ok_or(Error::DeviceRange)?,
        )
        .map_err(|_| Error::DeviceRange)?;
        Ok(CoveredTransfer {
            lower_offset: ByteOffset::new(aligned_start),
            transfer_len,
            requested_start,
            requested_end,
        })
    }
}

/// Sector-aligned lower transfer covering one arbitrary core byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoveredTransfer {
    /// Sector-aligned lower-device offset.
    lower_offset: ByteOffset,
    /// Whole-sector byte length submitted to the lower device.
    transfer_len: usize,
    /// Requested range start inside the aligned buffer.
    requested_start: usize,
    /// Requested range end inside the aligned buffer.
    requested_end: usize,
}

impl CoveredTransfer {
    /// Returns whether the core request already covers the complete lower transfer.
    const fn is_complete_sector_range(self) -> bool {
        self.requested_start == 0 && self.requested_end == self.transfer_len
    }

    /// Returns the requested byte range inside the aligned transfer buffer.
    fn requested_range(self) -> core::ops::Range<usize> {
        self.requested_start..self.requested_end
    }
}

/// Dynamically aligned nonpaged transfer allocation.
#[derive(Debug)]
struct AlignedTransferBuffer {
    /// Non-null allocation base.
    bytes: NonNull<u8>,
    /// Allocation layout retained for deallocation.
    layout: Layout,
}

impl AlignedTransferBuffer {
    /// Allocates a zeroed transfer buffer with the lower device's address alignment.
    /// # Errors
    ///
    /// Returns an error when the layout is invalid or nonpaged allocation fails.
    fn try_zeroed(len: usize, alignment: usize) -> Result<Self> {
        let layout = Layout::from_size_align(len, alignment).map_err(|_| Error::DeviceRange)?;
        if len == 0 {
            return Ok(Self {
                bytes: NonNull::dangling(),
                layout,
            });
        }
        let bytes = unsafe {
            // SAFETY: `layout` was validated above. The WDK-backed global allocator provides
            // nonpaged storage in driver builds.
            alloc_zeroed(layout)
        };
        let bytes = NonNull::new(bytes).ok_or(Error::OutOfMemory)?;
        Ok(Self { bytes, layout })
    }

    /// Returns the allocation length.
    const fn len(&self) -> usize {
        self.layout.size()
    }

    /// Returns the raw transfer address.
    #[cfg_attr(
        test,
        expect(dead_code, reason = "unit tests do not submit transfer buffers")
    )]
    const fn as_void_ptr(&self) -> *mut c_void {
        if self.len() == 0 {
            core::ptr::null_mut()
        } else {
            self.bytes.as_ptr().cast()
        }
    }

    /// Returns the initialized transfer bytes.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: The allocation contains `layout.size()` initialized bytes and remains owned
            // by this value for the returned borrow.
            core::slice::from_raw_parts(self.bytes.as_ptr(), self.len())
        }
    }

    /// Returns the initialized transfer bytes mutably.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            // SAFETY: This mutable borrow is exclusive and covers the initialized allocation.
            core::slice::from_raw_parts_mut(self.bytes.as_ptr(), self.len())
        }
    }
}

impl Drop for AlignedTransferBuffer {
    fn drop(&mut self) {
        if self.len() == 0 {
            return;
        }
        unsafe {
            // SAFETY: `bytes` was allocated with this exact layout and is released once here.
            dealloc(self.bytes.as_ptr(), self.layout);
        }
    }
}

// SAFETY: Ownership of the nonpaged allocation transfers with this value.
unsafe impl Send for AlignedTransferBuffer {}

/// Completion-owned state that outlives cancellation of the awaiting core future.
struct LowerCompletion {
    /// Aligned buffer used only by the lower device until completion becomes ready.
    buffer: UnsafeCell<AlignedTransferBuffer>,
    /// Terminal status and executor continuation signal.
    signal: Arc<LowerIrpSignal>,
}

impl LowerCompletion {
    /// Creates one in-flight lower request state.
    /// # Errors
    ///
    /// Returns an error when its aligned nonpaged buffer or shared state cannot be allocated.
    fn try_new(len: usize, alignment: usize) -> Result<Arc<Self>> {
        let buffer = AlignedTransferBuffer::try_zeroed(len, alignment)?;
        let signal = Arc::try_new(LowerIrpSignal::new()).map_err(|_| Error::OutOfMemory)?;
        Arc::try_new(Self {
            buffer: UnsafeCell::new(buffer),
            signal,
        })
        .map_err(|_| Error::OutOfMemory)
    }

    /// Installs the task executor waker before a lower driver can observe the private IRP.
    /// # Errors
    ///
    /// Returns an error if this completion state was already armed with a waker.
    fn register_waker(&self, waker: &Waker) -> Result<()> {
        self.signal.register_waker(waker)
    }

    /// Returns the buffer before submission, while no lower device can access it.
    fn buffer_before_submission(&mut self) -> &mut AlignedTransferBuffer {
        self.buffer.get_mut()
    }

    /// Reads the published terminal result.
    fn result(&self, expected_information: Option<usize>) -> Option<Result<()>> {
        self.signal.result(expected_information)
    }

    /// Returns completed buffer bytes after the acquire in `result`.
    fn completed_buffer(&self) -> &AlignedTransferBuffer {
        unsafe {
            // SAFETY: Callers use this only after `result` observed `COMPLETION_READY` with acquire
            // ordering, so lower-device access has ended and the buffer is immutable.
            &*self.buffer.get()
        }
    }

    /// Returns this completed state to the not-yet-submitted state under unique ownership.
    /// # Errors
    ///
    /// Returns an error if the lower request has not completed.
    fn rearm(&self) -> Result<()> {
        self.signal.rearm()
    }
}

// SAFETY: Lower-device access and future access to `buffer` are separated by `phase` release/acquire.
unsafe impl Send for LowerCompletion {}
// SAFETY: The only interior writes are atomic completion fields and lower-device buffer access that
// ends before `phase` publishes readiness.
unsafe impl Sync for LowerCompletion {}

/// A transfer state that has not yet been exposed to a lower driver.
struct ArmedLowerTransfer {
    /// Shared state retained by the lower completion routine after submission.
    state: Arc<LowerCompletion>,
}

impl ArmedLowerTransfer {
    /// Creates a fresh not-yet-submitted transfer state.
    /// # Errors
    ///
    /// Returns an error when completion-owned storage cannot be allocated.
    fn try_new(len: usize, alignment: usize) -> Result<Self> {
        Ok(Self {
            state: LowerCompletion::try_new(len, alignment)?,
        })
    }

    /// Returns the transfer buffer while this typestate excludes lower-driver access.
    /// # Errors
    ///
    /// Returns an error if callback ownership was not released before the transfer was armed.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "unit tests do not construct private transfer IRPs"
        )
    )]
    fn buffer_mut(&mut self) -> Result<&mut AlignedTransferBuffer> {
        Arc::get_mut(&mut self.state)
            .map(LowerCompletion::buffer_before_submission)
            .ok_or(Error::DeviceIo)
    }
}

/// A transfer whose lower driver has terminally released its buffer.
struct CompletedLowerTransfer {
    /// Completed state exclusively retained by the awaiting task.
    state: Arc<LowerCompletion>,
}

impl CompletedLowerTransfer {
    /// Returns immutable completed transfer bytes.
    fn buffer(&self) -> &AlignedTransferBuffer {
        self.state.completed_buffer()
    }

    /// Returns mutable completed transfer bytes under unique post-completion ownership.
    /// # Errors
    ///
    /// Returns an error if callback ownership has not been released completely.
    fn buffer_mut(&mut self) -> Result<&mut AlignedTransferBuffer> {
        Arc::get_mut(&mut self.state)
            .map(LowerCompletion::buffer_before_submission)
            .ok_or(Error::DeviceIo)
    }

    /// Rearms this exact buffer for one subsequent lower transfer.
    /// # Errors
    ///
    /// Returns an error unless this task uniquely owns a terminally completed transfer.
    fn rearm(mut self) -> Result<ArmedLowerTransfer> {
        Arc::get_mut(&mut self.state)
            .ok_or(Error::DeviceIo)?
            .rearm()?;
        Ok(ArmedLowerTransfer { state: self.state })
    }
}

/// Lower storage operation with a single corresponding IRP stack contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LowerOperation {
    /// Read device bytes into the transfer buffer.
    Read,
    /// Write transfer-buffer bytes to the device.
    Write,
    /// Persist all previously issued writes.
    Flush,
}

impl LowerOperation {
    /// Returns the WDM major function encoded for an I/O stack location.
    /// # Errors
    ///
    /// Returns an error if a WDK major-function constant cannot fit its ABI field.
    fn major_function(self) -> Result<u8> {
        let major = match self {
            Self::Read => IRP_MJ_READ,
            Self::Write => IRP_MJ_WRITE,
            Self::Flush => IRP_MJ_FLUSH_BUFFERS,
        };
        u8::try_from(major).map_err(|_| Error::DeviceRange)
    }

    /// Returns the I/O-manager operation flag describing this private request.
    const fn irp_flags(self) -> wdk_sys::ULONG {
        match self {
            Self::Read => wdk_sys::IRP_READ_OPERATION,
            Self::Write => wdk_sys::IRP_WRITE_OPERATION,
            Self::Flush => 0,
        }
    }

    /// Returns whether this operation exposes a transfer buffer to the lower stack.
    const fn transfers_bytes(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }
}

/// One driver-created lower IRP represented as a cancellation-safe future.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "unit tests replace private-IRP submission with an error"
    )
)]
struct LowerRequest {
    /// Driver-owned device whose image owns the completion routine.
    completion_owner: KernelDevice,
    /// Lower storage device.
    device: KernelDevice,
    /// Semantic lower operation used to construct one exact stack contract.
    operation: LowerOperation,
    /// Buffer representation required by the target device.
    transfer_method: LowerTransferMethod,
    /// Sector-aligned starting offset.
    offset: ByteOffset,
    /// Completion-owned state and bounce buffer.
    completion: Option<ArmedLowerTransfer>,
    /// Whether byte-count equality is required.
    expected_information: Option<usize>,
    /// Submission occurs on the first poll at `PASSIVE_LEVEL`.
    submitted: bool,
}

impl LowerRequest {
    /// Creates one not-yet-submitted lower request.
    fn new(
        completion_owner: KernelDevice,
        device: KernelDevice,
        operation: LowerOperation,
        transfer_method: LowerTransferMethod,
        offset: ByteOffset,
        completion: ArmedLowerTransfer,
        expected_information: Option<usize>,
    ) -> Self {
        Self {
            completion_owner,
            device,
            operation,
            transfer_method,
            offset,
            completion: Some(completion),
            expected_information,
            submitted: false,
        }
    }

    /// Builds and submits the private lower IRP.
    /// # Errors
    ///
    /// Returns an error when range conversion, IRP allocation, or completion registration fails.
    #[cfg(not(test))]
    fn submit(&mut self) -> Result<()> {
        let (request_len, buffer) = {
            let completion = self.completion.as_mut().ok_or(Error::DeviceIo)?;
            let buffer = completion.buffer_mut()?;
            (
                wdk_sys::ULONG::try_from(buffer.len()).map_err(|_| Error::DeviceRange)?,
                buffer.as_void_ptr(),
            )
        };
        let starting_offset = LARGE_INTEGER {
            QuadPart: i64::try_from(self.offset.get()).map_err(|_| Error::DeviceRange)?,
        };
        let major = self.operation.major_function()?;
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| Error::DeviceRange)?;
        let stack_size = self
            .device
            .stack_size()
            .filter(|stack_size| *stack_size > 0)
            .ok_or(Error::DeviceRange)?;
        let irp = unsafe {
            // SAFETY: The validated target stack depth supplies every lower driver's stack slot.
            ffi::IoAllocateIrp(stack_size, 0)
        };
        let Some(irp) = NonNull::new(irp) else {
            return Err(Error::OutOfMemory);
        };
        let irp_ref = unsafe {
            // SAFETY: This freshly allocated private IRP is exclusively owned before submission.
            &mut *irp.as_ptr()
        };
        irp_ref.RequestorMode = kernel_mode;
        irp_ref.Flags = self.operation.irp_flags();
        irp_ref.MdlAddress = core::ptr::null_mut();
        irp_ref.UserBuffer = core::ptr::null_mut();
        // Union writes select and initialize the private IRP's SystemBuffer arm.
        irp_ref.AssociatedIrp.SystemBuffer = core::ptr::null_mut();
        let io_status = &mut irp_ref.IoStatus;
        // Union writes select and initialize the NTSTATUS arm.
        io_status.__bindgen_anon_1.Status = wdk_sys::STATUS_PENDING;
        io_status.Information = 0;

        let stack = unsafe {
            // SAFETY: The positive target stack depth provides one unused lower stack slot.
            next_irp_stack_location(irp.as_ptr())
        };
        unsafe {
            // SAFETY: The returned unused stack slot remains exclusively owned before dispatch.
            core::ptr::write(stack, wdk_sys::IO_STACK_LOCATION::default());
        }
        let stack = unsafe {
            // SAFETY: The zero-initialized lower stack slot remains exclusively owned here.
            &mut *stack
        };
        stack.MajorFunction = major;
        stack.FileObject = core::ptr::null_mut();
        match self.operation {
            LowerOperation::Read => {
                stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
                    Length: request_len,
                    __bindgen_padding_0: 0,
                    Key: 0,
                    Flags: 0,
                    ByteOffset: starting_offset,
                };
            }
            LowerOperation::Write => {
                stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
                    Length: request_len,
                    __bindgen_padding_0: 0,
                    Key: 0,
                    Flags: 0,
                    ByteOffset: starting_offset,
                };
            }
            LowerOperation::Flush => {}
        }
        if self.operation.transfers_bytes() {
            let setup = match self.transfer_method {
                LowerTransferMethod::Buffered => {
                    // The completion-owned nonpaged buffer outlives the private IRP; no
                    // I/O-manager deallocation flag is set for this borrowed address.
                    irp_ref.AssociatedIrp.SystemBuffer = buffer;
                    Ok(())
                }
                LowerTransferMethod::Direct => {
                    let mdl = unsafe {
                        // SAFETY: The nonpaged completion buffer remains stable for the IRP and
                        // the I/O Manager links this primary MDL to the exclusively owned IRP.
                        ffi::IoAllocateMdl(buffer, request_len, 0, 0, irp.as_ptr())
                    };
                    NonNull::new(mdl).map_or(Err(Error::OutOfMemory), |mdl| {
                        unsafe {
                            // SAFETY: This MDL describes driver-owned nonpaged pool and must not
                            // be probe-locked or subsequently unlocked.
                            ffi::MmBuildMdlForNonPagedPool(mdl.as_ptr());
                        }
                        Ok(())
                    })
                }
                LowerTransferMethod::Neither => {
                    irp_ref.UserBuffer = buffer;
                    Ok(())
                }
            };
            if let Err(error) = setup {
                unsafe {
                    // SAFETY: The private IRP has not been registered or submitted.
                    release_private_irp(irp.as_ptr());
                }
                return Err(error);
            }
        }
        let Some(completion) = self.completion.as_ref() else {
            unsafe {
                // SAFETY: The impossible missing typestate is detected before registration or
                // submission, so local ownership still permits exact release.
                release_private_irp(irp.as_ptr());
            }
            return Err(Error::DeviceIo);
        };
        let callback_state = Arc::into_raw(Arc::clone(&completion.state))
            .cast_mut()
            .cast::<c_void>();
        let status = unsafe {
            // SAFETY: The callback state is nonpaged and retained by one raw Arc reference until
            // the completion routine reconstructs it. All outcomes request callback invocation.
            ffi::IoSetCompletionRoutineEx(
                self.completion_owner.as_ptr(),
                irp.as_ptr(),
                Some(lower_request_completed),
                callback_state,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
            )
        };
        if status < wdk_sys::STATUS_SUCCESS {
            let callback_state = callback_state.cast::<LowerCompletion>();
            unsafe {
                // SAFETY: Registration failed, so no lower driver owns this unsubmitted IRP.
                release_private_irp(irp.as_ptr());
            }
            unsafe {
                // SAFETY: Registration failed, so no callback owns this raw Arc reference.
                drop(Arc::from_raw(callback_state));
            }
            return Err(Error::DeviceIo);
        }
        let _dispatch_status = unsafe {
            // SAFETY: Ownership of the private IRP and callback Arc transfers to the I/O Manager
            // and the registered completion routine.
            ffi::IofCallDriver(self.device.as_ptr(), irp.as_ptr())
        };
        Ok(())
    }

    /// Test builds do not submit kernel IRPs.
    /// # Errors
    ///
    /// Always returns device-I/O failure because unit tests have no kernel lower stack.
    #[cfg(test)]
    fn submit(&mut self) -> Result<()> {
        Err(Error::DeviceIo)
    }
}

impl Future for LowerRequest {
    type Output = Result<CompletedLowerTransfer>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            let Some(completion) = self.completion.as_ref() else {
                return Poll::Ready(Err(Error::DeviceIo));
            };
            if let Err(error) = completion.state.register_waker(context.waker()) {
                return Poll::Ready(Err(error));
            }
            self.submitted = true;
            if let Err(error) = self.submit() {
                return Poll::Ready(Err(error));
            }
        }
        let Some(completion) = self.completion.as_ref() else {
            return Poll::Ready(Err(Error::DeviceIo));
        };
        match completion.state.result(self.expected_information) {
            Some(Ok(())) => {
                let Some(completion) = self.completion.take() else {
                    return Poll::Ready(Err(Error::DeviceIo));
                };
                Poll::Ready(Ok(CompletedLowerTransfer {
                    state: completion.state,
                }))
            }
            Some(Err(error)) => Poll::Ready(Err(error)),
            None => Poll::Pending,
        }
    }
}

// SAFETY: The lower device pointer is stable for the mounted-device lifetime and all completion
// state shared across workers is synchronized atomically.
unsafe impl Send for LowerRequest {}

/// Output contract of `IOCTL_DISK_GET_LENGTH_INFO`.
#[repr(C)]
struct DiskLengthInformation {
    /// Device byte length reported by the lower storage stack.
    length: i64,
}

/// Completion-owned storage for one asynchronous device-length query.
struct LengthQueryCompletion {
    /// Stable buffered-I/O output exposed through the private IRP's system buffer.
    output: UnsafeCell<DiskLengthInformation>,
    /// Terminal status and executor continuation signal.
    signal: LowerIrpSignal,
}

impl LengthQueryCompletion {
    /// Allocates a stable completion context before IRP construction.
    /// # Errors
    ///
    /// Returns an error when shared nonpaged state cannot be allocated.
    fn try_new() -> DriverResult<Arc<Self>> {
        Arc::try_new(Self {
            output: UnsafeCell::new(DiskLengthInformation { length: 0 }),
            signal: LowerIrpSignal::new(),
        })
        .map_err(|_| DriverError::InsufficientResources)
    }

    /// Returns the stable output address before lower submission.
    #[cfg_attr(
        test,
        expect(dead_code, reason = "unit tests do not submit private IOCTL buffers")
    )]
    const fn output_address(&self) -> *mut c_void {
        self.output.get().cast()
    }

    /// Publishes terminal lower status and returns the executor waker.
    #[cfg_attr(
        test,
        expect(dead_code, reason = "unit tests do not run lower completion callbacks")
    )]
    fn complete(&self, status: NTSTATUS, information: usize) -> Option<Waker> {
        self.signal.complete(status, information)
    }

    /// Reads and validates the terminal device length.
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "test submission terminates before a lower callback can publish length"
        )
    )]
    fn result(&self) -> Option<DriverResult<DeviceLength>> {
        match self
            .signal
            .result(Some(core::mem::size_of::<DiskLengthInformation>()))
        {
            None => None,
            Some(Err(error)) => Some(Err(DriverError::from(error))),
            Some(Ok(())) => {
                let length = unsafe {
                    // SAFETY: The signal's acquire load observed terminal completion, so lower
                    // buffered-I/O writes to this output have ended and are now visible.
                    (*self.output.get()).length
                };
                Some(validate_device_length(length))
            }
        }
    }
}

/// Converts the signed disk-length IOCTL payload into a non-empty core device length.
/// # Errors
///
/// Returns an error when the lower stack reports a zero or negative length.
fn validate_device_length(length: i64) -> DriverResult<DeviceLength> {
    let length = u64::try_from(length).map_err(|_| DriverError::from(Error::DeviceRange))?;
    if length == 0 {
        return Err(DriverError::from(Error::DeviceRange));
    }
    Ok(DeviceLength::from_bytes(length))
}

// SAFETY: The lower device writes `output` only before `signal` publishes terminal completion.
unsafe impl Send for LengthQueryCompletion {}
// SAFETY: The signal release/acquire edge separates the lower write from executor reads.
unsafe impl Sync for LengthQueryCompletion {}

/// One driver-created disk-length IRP represented as a continuation-driven future.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "unit tests replace private-IRP submission with an error"
    )
)]
struct LengthQuery {
    /// Driver-owned device whose image owns the completion routine.
    completion_owner: KernelDevice,
    /// Lower storage device queried for its byte length.
    target: KernelDevice,
    /// Stable state retained independently by the completion callback.
    completion: Arc<LengthQueryCompletion>,
    /// Submission occurs on the first poll at `PASSIVE_LEVEL`.
    submitted: bool,
}

impl LengthQuery {
    /// Creates one unsubmitted query.
    /// # Errors
    ///
    /// Returns an error when stable completion state cannot be allocated.
    fn try_new(completion_owner: KernelDevice, target: KernelDevice) -> DriverResult<Self> {
        Ok(Self {
            completion_owner,
            target,
            completion: LengthQueryCompletion::try_new()?,
            submitted: false,
        })
    }

    /// Builds and submits one private buffered device-control IRP.
    /// # Errors
    ///
    /// Returns an error when stack validation, IRP construction, or completion registration fails.
    #[cfg(not(test))]
    fn submit(&mut self) -> DriverResult<()> {
        let stack_size = self
            .target
            .stack_size()
            .filter(|stack_size| *stack_size > 0)
            .ok_or(DriverError::InvalidParameter)?;
        let output_length = wdk_sys::ULONG::try_from(core::mem::size_of::<DiskLengthInformation>())
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        let major = u8::try_from(IRP_MJ_DEVICE_CONTROL)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
            .map_err(|_| DriverError::InternalInvariantViolation)?;
        let irp = unsafe {
            // SAFETY: `stack_size` is the live target device's validated stack depth. This private
            // IRP is charged to the driver rather than the originating mount thread.
            ffi::IoAllocateIrp(stack_size, 0)
        };
        let Some(irp) = NonNull::new(irp) else {
            return Err(DriverError::InsufficientResources);
        };
        let irp_ref = unsafe {
            // SAFETY: This freshly allocated private IRP is exclusively owned here.
            &mut *irp.as_ptr()
        };
        irp_ref.RequestorMode = kernel_mode;
        // Union writes select and initialize the private buffered-IOCTL arm.
        irp_ref.AssociatedIrp.SystemBuffer = self.completion.output_address();
        let io_status = &mut irp_ref.IoStatus;
        // Union writes select and initialize the NTSTATUS arm.
        io_status.__bindgen_anon_1.Status = wdk_sys::STATUS_PENDING;
        io_status.Information = 0;
        let stack = unsafe {
            // SAFETY: `IoAllocateIrp` initialized one unused stack slot for this positive depth.
            next_irp_stack_location(irp.as_ptr())
        };
        unsafe {
            // SAFETY: `stack` identifies the exclusively owned unused lower stack slot.
            core::ptr::write(stack, wdk_sys::IO_STACK_LOCATION::default());
        }
        let stack = unsafe {
            // SAFETY: The initialized stack slot remains exclusively owned until submission.
            &mut *stack
        };
        stack.MajorFunction = major;
        stack.FileObject = core::ptr::null_mut();
        stack.Parameters.DeviceIoControl =
            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_17 {
                OutputBufferLength: output_length,
                __bindgen_padding_0: 0,
                InputBufferLength: 0,
                __bindgen_padding_1: 0,
                IoControlCode: IOCTL_DISK_GET_LENGTH_INFO,
                Type3InputBuffer: core::ptr::null_mut(),
            };
        let callback_state = Arc::into_raw(Arc::clone(&self.completion))
            .cast_mut()
            .cast::<c_void>();
        let status = unsafe {
            // SAFETY: The ext4win-owned device pins this image's completion routine. The callback
            // state and system buffer are stable until the terminal callback reconstructs the Arc.
            ffi::IoSetCompletionRoutineEx(
                self.completion_owner.as_ptr(),
                irp.as_ptr(),
                Some(length_query_completed),
                callback_state,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
            )
        };
        if status < wdk_sys::STATUS_SUCCESS {
            let callback_state = callback_state.cast::<LengthQueryCompletion>();
            unsafe {
                // SAFETY: Registration failed, so no callback owns this raw Arc reference.
                drop(Arc::from_raw(callback_state));
            }
            unsafe {
                // SAFETY: Registration failed before submission, so this callback-free IRP is
                // still exclusively owned here.
                ffi::IoFreeIrp(irp.as_ptr());
            }
            return Err(DriverError::from(Error::DeviceIo));
        }
        let _dispatch_status = unsafe {
            // SAFETY: Ownership of the private IRP and callback Arc transfers to the lower stack
            // and completion callback. The IRP may complete before this call returns.
            ffi::IofCallDriver(self.target.as_ptr(), irp.as_ptr())
        };
        Ok(())
    }

    /// Test builds do not submit kernel IRPs.
    /// # Errors
    ///
    /// Always returns device-I/O failure because unit tests have no kernel lower stack.
    #[cfg(test)]
    #[expect(
        dead_code,
        reason = "kernel private-IRP submission is unavailable in unit tests"
    )]
    fn submit(&mut self) -> DriverResult<()> {
        Err(DriverError::from(Error::DeviceIo))
    }
}

impl Future for LengthQuery {
    type Output = DriverResult<DeviceLength>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            if let Err(error) = self.completion.signal.register_waker(context.waker()) {
                return Poll::Ready(Err(DriverError::from(error)));
            }
            self.submitted = true;
            if let Err(error) = self.submit() {
                return Poll::Ready(Err(error));
            }
        }
        match self.completion.result() {
            Some(result) => Poll::Ready(result),
            None => Poll::Pending,
        }
    }
}

// SAFETY: Both device objects remain stable for mount processing and shared completion state uses
// the explicit release/acquire completion protocol.
unsafe impl Send for LengthQuery {}

/// Queries and validates a lower storage device's byte length asynchronously.
/// # Errors
///
/// Returns an error when private-IRP construction fails, the lower request fails, or the returned
/// byte length is missing, non-positive, or malformed.
pub(crate) async fn query_device_length(
    completion_owner: KernelDevice,
    target: KernelDevice,
) -> DriverResult<DeviceLength> {
    LengthQuery::try_new(completion_owner, target)?.await
}

/// Lower storage device exposed through ext4-core's asynchronous block traits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelBlockDevice {
    /// Driver-owned device whose image owns every lower completion routine.
    completion_owner: KernelDevice,
    /// Lower storage target.
    device: KernelDevice,
    /// Validated physical transfer constraints.
    geometry: TransferGeometry,
    /// Validated transfer-buffer representation required by the lower target.
    transfer_method: LowerTransferMethod,
}

impl KernelBlockDevice {
    /// Creates the mounted lower-storage boundary.
    /// # Errors
    ///
    /// Returns an error when the lower device advertises invalid sector or buffer alignment.
    pub(crate) fn new(
        completion_owner: KernelDevice,
        device: KernelDevice,
        length: DeviceLength,
    ) -> Result<Self> {
        let geometry = TransferGeometry::from_device(device, length)?;
        let object = unsafe {
            // SAFETY: `device` remains live for the mounted block-device lifetime and is read only
            // for its immutable I/O mode flags.
            device.as_ptr().as_ref()
        }
        .ok_or(Error::DeviceIo)?;
        Ok(Self {
            completion_owner,
            device,
            geometry,
            transfer_method: LowerTransferMethod::from_device_flags(object.Flags)?,
        })
    }

    /// Creates completion-owned storage for one aligned transfer.
    /// # Errors
    ///
    /// Returns an error when the aligned nonpaged transfer state cannot be allocated.
    fn completion(&self, len: usize) -> Result<ArmedLowerTransfer> {
        ArmedLowerTransfer::try_new(len, self.geometry.buffer_alignment)
    }

    /// Reads one already aligned transfer into completion-owned storage.
    /// # Errors
    ///
    /// Returns an error when request state cannot be allocated or lower I/O fails.
    async fn read_aligned(&mut self, transfer: CoveredTransfer) -> Result<CompletedLowerTransfer> {
        let completion = self.completion(transfer.transfer_len)?;
        LowerRequest::new(
            self.completion_owner,
            self.device,
            LowerOperation::Read,
            self.transfer_method,
            transfer.lower_offset,
            completion,
            Some(transfer.transfer_len),
        )
        .await
    }

    /// Writes one already aligned completion-owned transfer.
    /// # Errors
    ///
    /// Returns an error when private-IRP construction or lower I/O fails.
    async fn write_aligned(
        &mut self,
        transfer: CoveredTransfer,
        completion: ArmedLowerTransfer,
    ) -> Result<()> {
        LowerRequest::new(
            self.completion_owner,
            self.device,
            LowerOperation::Write,
            self.transfer_method,
            transfer.lower_offset,
            completion,
            Some(transfer.transfer_len),
        )
        .await
        .map(|_| ())
    }
}

// SAFETY: Device objects and completion executors remain stable across worker threads by mount and
// teardown construction; mutation is serialized through `&mut self`.
unsafe impl Send for KernelBlockDevice {}

impl BlockSource for KernelBlockDevice {
    fn len(&self) -> DeviceLength {
        self.geometry.length
    }

    async fn read_exact_at(&mut self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if out.is_empty() {
            return Ok(());
        }
        let transfer = self.geometry.cover(offset, out.len())?;
        let completion = self.read_aligned(transfer).await?;
        out.copy_from_slice(
            completion
                .buffer()
                .as_slice()
                .get(transfer.requested_range())
                .ok_or(Error::DeviceRange)?,
        );
        Ok(())
    }
}

impl BlockStorage for KernelBlockDevice {
    async fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let transfer = self.geometry.cover(offset, bytes.len())?;
        let completion = if transfer.is_complete_sector_range() {
            self.completion(transfer.transfer_len)?
        } else {
            let mut completed = self.read_aligned(transfer).await?;
            completed
                .buffer_mut()?
                .as_mut_slice()
                .get_mut(transfer.requested_range())
                .ok_or(Error::DeviceRange)?
                .copy_from_slice(bytes);
            return self.write_aligned(transfer, completed.rearm()?).await;
        };
        let mut completion = completion;
        Arc::get_mut(&mut completion.state)
            .ok_or(Error::DeviceIo)?
            .buffer_before_submission()
            .as_mut_slice()
            .get_mut(transfer.requested_range())
            .ok_or(Error::DeviceRange)?
            .copy_from_slice(bytes);
        self.write_aligned(transfer, completion).await
    }

    async fn flush(&mut self) -> Result<()> {
        let completion = self.completion(0)?;
        LowerRequest::new(
            self.completion_owner,
            self.device,
            LowerOperation::Flush,
            self.transfer_method,
            ByteOffset::new(0),
            completion,
            None,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(not(test))]
/// Returns the next private-IRP stack slot using the WDK macro contract.
/// # Safety
///
/// `irp` must be a freshly allocated IRP with at least one unused stack location.
unsafe fn next_irp_stack_location(irp: PIRP) -> PIO_STACK_LOCATION {
    let irp = unsafe {
        // SAFETY: The caller guarantees a valid live private IRP.
        &*irp
    };
    let tail = unsafe {
        // SAFETY: A live IRP uses the Tail overlay while traversing stack locations.
        &irp.Tail.Overlay
    };
    let overlay = &tail.__bindgen_anon_2.__bindgen_anon_1;
    let current = unsafe {
        // SAFETY: The IRP stack-traversal view selects the CurrentStackLocation union arm.
        overlay.CurrentStackLocation
    };
    unsafe {
        // SAFETY: A positive target stack depth guarantees one initialized slot before `current`.
        current.sub(1)
    }
}

#[cfg(not(test))]
/// Releases an unsubmitted or terminal private IRP and any MDL built for its bounce buffer.
/// # Safety
///
/// `irp` must be a private IRP allocated by `IoAllocateIrp` and must not be owned by a lower driver
/// when this function is called.
unsafe fn release_private_irp(irp: PIRP) {
    let irp_ref = unsafe {
        // SAFETY: The caller guarantees that `irp` is valid and exclusively owned here.
        &mut *irp
    };
    let mut mdl = irp_ref.MdlAddress;
    irp_ref.MdlAddress = core::ptr::null_mut();
    while let Some(current) = NonNull::new(mdl) {
        let current_ref = unsafe {
            // SAFETY: Every current MDL remains linked to the exclusively owned private IRP.
            &mut *current.as_ptr()
        };
        let next = current_ref.Next;
        let flags = u32::from(u16::from_ne_bytes(current_ref.MdlFlags.to_ne_bytes()));
        if flags & wdk_sys::MDL_PAGES_LOCKED != 0 {
            unsafe {
                // SAFETY: Only a lower-added MDL carrying MDL_PAGES_LOCKED requires unlock; the
                // driver's own MmBuildMdlForNonPagedPool MDL never carries this bit.
                ffi::MmUnlockPages(current.as_ptr());
            }
        }
        unsafe {
            // SAFETY: This MDL has been detached from the private IRP and is released once.
            ffi::IoFreeMdl(current.as_ptr());
        }
        mdl = next;
    }
    // Union writes clear the borrowed SystemBuffer address without reading an inactive arm.
    irp_ref.AssociatedIrp.SystemBuffer = core::ptr::null_mut();
    irp_ref.UserBuffer = core::ptr::null_mut();
    unsafe {
        // SAFETY: Completion processing is stopped and this private IRP is released exactly once.
        ffi::IoFreeIrp(irp);
    }
}

#[cfg(not(test))]
/// Completion routine for driver-created lower read, write, and flush IRPs.
/// # Safety
///
/// The I/O Manager must pass the private IRP and the raw Arc context registered during submission.
unsafe extern "C" fn lower_request_completed(
    _device: wdk_sys::PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let Some(context) = NonNull::new(context.cast::<LowerCompletion>()) else {
        return STATUS_MORE_PROCESSING_REQUIRED;
    };
    let completion = unsafe {
        // SAFETY: Submission created exactly one raw Arc reference for this callback.
        Arc::from_raw(context.as_ptr())
    };
    let irp_ref = unsafe {
        // SAFETY: The lower driver has terminally completed this private IRP.
        &*irp
    };
    let status = unsafe {
        // SAFETY: NTSTATUS is the active IRP status union arm after terminal completion.
        irp_ref.IoStatus.__bindgen_anon_1.Status
    };
    let information = irp_ref.IoStatus.Information;
    let signal = Arc::clone(&completion.signal);
    let waker = signal.stage_completion(status, usize::try_from(information).unwrap_or(usize::MAX));
    unsafe {
        // SAFETY: This completion routine owns final release of the private lower IRP.
        release_private_irp(irp);
    }
    drop(completion);
    signal.publish_ready();
    drop(signal);
    if let Some(waker) = waker {
        waker.wake();
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

#[cfg(not(test))]
/// Completion routine for one driver-created disk-length query IRP.
/// # Safety
///
/// The I/O Manager must pass the private IRP and raw Arc context registered by `LengthQuery`.
unsafe extern "C" fn length_query_completed(
    _device: wdk_sys::PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let Some(context) = NonNull::new(context.cast::<LengthQueryCompletion>()) else {
        return STATUS_MORE_PROCESSING_REQUIRED;
    };
    let completion = unsafe {
        // SAFETY: Submission created exactly one raw Arc reference for this callback.
        Arc::from_raw(context.as_ptr())
    };
    let irp_ref = unsafe {
        // SAFETY: The lower stack has terminally completed this private IRP.
        &*irp
    };
    let status = unsafe {
        // SAFETY: NTSTATUS is the active IRP status union arm after terminal completion.
        irp_ref.IoStatus.__bindgen_anon_1.Status
    };
    let information = irp_ref.IoStatus.Information;
    unsafe {
        // SAFETY: This callback owns final release and no completion processing may continue after
        // returning STATUS_MORE_PROCESSING_REQUIRED.
        ffi::IoFreeIrp(irp);
    }
    let waker = completion.complete(status, usize::try_from(information).unwrap_or(usize::MAX));
    drop(completion);
    if let Some(waker) = waker {
        waker.wake();
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

#[cfg(test)]
mod tests {
    use super::{
        LowerIrpSignal, LowerOperation, LowerTransferMethod, TransferGeometry,
        validate_device_length,
    };
    use core::task::Waker;
    use ext4_core::{ByteOffset, DeviceLength, Error};

    /// # Panics
    ///
    /// Panics when arbitrary core ranges stop mapping to the minimal whole-sector transfer.
    #[test]
    fn covered_transfer_rounds_to_physical_sectors() {
        let geometry = TransferGeometry {
            length: DeviceLength::from_bytes(16_384),
            sector_size: 4096,
            buffer_alignment: 512,
        };
        let transfer = geometry.cover(ByteOffset::new(1024), 1024);
        assert!(transfer.is_ok());
        let Ok(transfer) = transfer else {
            return;
        };
        assert_eq!(transfer.lower_offset, ByteOffset::new(0));
        assert_eq!(transfer.transfer_len, 4096);
        assert_eq!(transfer.requested_range(), 1024..2048);
        assert!(!transfer.is_complete_sector_range());
    }

    /// # Panics
    ///
    /// Panics when a request crossing the exposed device end is accepted.
    #[test]
    fn covered_transfer_rejects_device_end_crossing() {
        let geometry = TransferGeometry {
            length: DeviceLength::from_bytes(4096),
            sector_size: 512,
            buffer_alignment: 8,
        };
        assert_eq!(
            geometry.cover(ByteOffset::new(4095), 2),
            Err(Error::DeviceRange)
        );
    }

    /// # Panics
    ///
    /// Panics when device flags no longer map to one exclusive lower transfer method.
    #[test]
    fn lower_transfer_method_rejects_conflicting_device_flags() {
        assert_eq!(
            LowerTransferMethod::from_device_flags(0),
            Ok(LowerTransferMethod::Neither)
        );
        assert_eq!(
            LowerTransferMethod::from_device_flags(wdk_sys::DO_BUFFERED_IO),
            Ok(LowerTransferMethod::Buffered)
        );
        assert_eq!(
            LowerTransferMethod::from_device_flags(wdk_sys::DO_DIRECT_IO),
            Ok(LowerTransferMethod::Direct)
        );
        assert!(
            LowerTransferMethod::from_device_flags(wdk_sys::DO_BUFFERED_IO | wdk_sys::DO_DIRECT_IO)
                .is_err()
        );
    }

    /// # Panics
    ///
    /// Panics when private operation encodings diverge from their WDM contracts.
    #[test]
    fn lower_operations_have_exact_major_and_irp_flag_encodings() {
        assert_eq!(
            LowerOperation::Read.major_function(),
            u8::try_from(wdk_sys::IRP_MJ_READ).map_err(|_| Error::DeviceRange)
        );
        assert_eq!(
            LowerOperation::Read.irp_flags(),
            wdk_sys::IRP_READ_OPERATION
        );
        assert!(LowerOperation::Read.transfers_bytes());
        assert_eq!(
            LowerOperation::Write.major_function(),
            u8::try_from(wdk_sys::IRP_MJ_WRITE).map_err(|_| Error::DeviceRange)
        );
        assert_eq!(
            LowerOperation::Write.irp_flags(),
            wdk_sys::IRP_WRITE_OPERATION
        );
        assert!(LowerOperation::Write.transfers_bytes());
        assert_eq!(
            LowerOperation::Flush.major_function(),
            u8::try_from(wdk_sys::IRP_MJ_FLUSH_BUFFERS).map_err(|_| Error::DeviceRange)
        );
        assert_eq!(LowerOperation::Flush.irp_flags(), 0);
        assert!(!LowerOperation::Flush.transfers_bytes());
    }

    /// # Panics
    ///
    /// Panics when staged completion becomes visible before callback resources are released or
    /// cannot be rearmed for one subsequent request.
    #[test]
    fn lower_signal_publishes_only_after_callback_release_boundary() {
        let signal = LowerIrpSignal::new();
        assert_eq!(signal.result(Some(7)), None);
        assert!(signal.register_waker(Waker::noop()).is_ok());
        assert!(signal.register_waker(Waker::noop()).is_err());
        let waker = signal.stage_completion(wdk_sys::STATUS_SUCCESS, 7);
        assert!(waker.is_some());
        assert_eq!(signal.result(Some(7)), None);
        signal.publish_ready();
        assert_eq!(signal.result(Some(7)), Some(Ok(())));
        assert!(signal.rearm().is_ok());
        assert_eq!(signal.result(Some(7)), None);
        assert!(signal.register_waker(Waker::noop()).is_ok());
    }

    /// # Panics
    ///
    /// Panics when terminal errors or short transfers are accepted as successful lower I/O.
    #[test]
    fn lower_signal_rejects_error_status_and_short_information() {
        let failed = LowerIrpSignal::new();
        assert!(failed.register_waker(Waker::noop()).is_ok());
        let _waker = failed.stage_completion(wdk_sys::STATUS_ACCESS_DENIED, 8);
        failed.publish_ready();
        assert_eq!(failed.result(Some(8)), Some(Err(Error::DeviceIo)));

        let short = LowerIrpSignal::new();
        assert!(short.register_waker(Waker::noop()).is_ok());
        let _waker = short.stage_completion(wdk_sys::STATUS_SUCCESS, 7);
        short.publish_ready();
        assert_eq!(short.result(Some(8)), Some(Err(Error::DeviceIo)));
    }

    /// # Panics
    ///
    /// Panics when a zero or negative disk-length payload is accepted.
    #[test]
    fn disk_length_must_be_positive() {
        assert!(validate_device_length(-1).is_err());
        assert!(validate_device_length(0).is_err());
        assert_eq!(
            validate_device_length(4096).map(DeviceLength::bytes),
            Ok(4096)
        );
    }
}
