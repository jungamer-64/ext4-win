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
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicI32, AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll},
};

use ext4_core::{BlockSource, BlockStorage, ByteOffset, DeviceLength, Error, Result};
use wdk_sys::{IRP_MJ_FLUSH_BUFFERS, IRP_MJ_READ, IRP_MJ_WRITE, LARGE_INTEGER, NTSTATUS, PIRP};

use crate::{kernel::ffi, state::KernelDevice};

/// Completion context has not yet received the terminal lower-driver status.
const COMPLETION_IN_FLIGHT: u8 = 0;
/// Completion context contains the terminal status and byte count.
const COMPLETION_READY: u8 = 1;
/// `TRUE` represented as a WDK `BOOLEAN`.
const BOOLEAN_TRUE: wdk_sys::BOOLEAN = 1;
/// Stops I/O Manager completion after this driver frees its private lower IRP.
const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS = 0xC000_0016_u32 as NTSTATUS;

/// Stable executor callback recorded in each in-flight lower request.
#[derive(Clone, Copy)]
pub(crate) struct CompletionWake {
    /// Stable executor-owned context.
    context: NonNull<c_void>,
    /// Schedules that executor from a completion callback at or below `DISPATCH_LEVEL`.
    schedule: unsafe fn(NonNull<c_void>),
}

impl core::fmt::Debug for CompletionWake {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CompletionWake")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl CompletionWake {
    /// Binds a stable executor context to its nonblocking schedule callback.
    /// # Safety
    ///
    /// `context` must remain valid until every lower request carrying this value has completed.
    /// `schedule` must be callable at any IRQL at or below `DISPATCH_LEVEL`.
    pub(crate) const unsafe fn new(
        context: NonNull<c_void>,
        schedule: unsafe fn(NonNull<c_void>),
    ) -> Self {
        Self { context, schedule }
    }

    /// Schedules the owning executor after a lower request completes.
    fn schedule(self) {
        unsafe {
            // SAFETY: Construction requires this context/callback pair to stay valid through every
            // completion that carries it.
            (self.schedule)(self.context);
        }
    }
}

// SAFETY: The constructor requires a stable, cross-thread executor context and callback.
unsafe impl Send for CompletionWake {}
// SAFETY: Completion callbacks may copy and invoke the same immutable callback pair concurrently.
unsafe impl Sync for CompletionWake {}

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

impl TransferGeometry {
    /// Reads and validates lower-device transfer constraints.
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
    fn cover(self, offset: ByteOffset, len: usize) -> Result<CoveredTransfer> {
        let len = u64::try_from(len).map_err(|_| Error::DeviceRange)?;
        let requested_end = offset.get().checked_add(len).ok_or(Error::DeviceRange)?;
        if requested_end > self.length.bytes() {
            return Err(Error::DeviceRange);
        }
        let sector_size = u64::try_from(self.sector_size).map_err(|_| Error::DeviceRange)?;
        let aligned_start = offset.get() & !(sector_size - 1);
        let aligned_end = requested_end
            .checked_add(sector_size - 1)
            .ok_or(Error::DeviceRange)?
            & !(sector_size - 1);
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
        Ok(CoveredTransfer {
            lower_offset: ByteOffset::new(aligned_start),
            transfer_len,
            requested_start,
            requested_len: usize::try_from(len).map_err(|_| Error::DeviceRange)?,
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
    /// Requested byte length.
    requested_len: usize,
}

impl CoveredTransfer {
    /// Returns whether the core request already covers the complete lower transfer.
    const fn is_complete_sector_range(self) -> bool {
        self.requested_start == 0 && self.requested_len == self.transfer_len
    }

    /// Returns the requested byte range inside the aligned transfer buffer.
    fn requested_range(self) -> core::ops::Range<usize> {
        self.requested_start..self.requested_start + self.requested_len
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
    /// Executor to schedule after recording terminal completion.
    wake: CompletionWake,
    /// Whether the I/O builder created a direct-I/O MDL that must be unlocked.
    direct_io: bool,
    /// Lower terminal status.
    status: AtomicI32,
    /// Lower terminal byte count.
    information: AtomicUsize,
    /// Publish point for status, information, and completed DMA access to `buffer`.
    phase: AtomicU8,
}

impl LowerCompletion {
    /// Creates one in-flight lower request state.
    fn try_new(
        len: usize,
        alignment: usize,
        wake: CompletionWake,
        direct_io: bool,
    ) -> Result<Arc<Self>> {
        let buffer = AlignedTransferBuffer::try_zeroed(len, alignment)?;
        Arc::try_new(Self {
            buffer: UnsafeCell::new(buffer),
            wake,
            direct_io,
            status: AtomicI32::new(wdk_sys::STATUS_PENDING),
            information: AtomicUsize::new(0),
            phase: AtomicU8::new(COMPLETION_IN_FLIGHT),
        })
        .map_err(|_| Error::OutOfMemory)
    }

    /// Returns the buffer before submission, while no lower device can access it.
    fn buffer_before_submission(&mut self) -> &mut AlignedTransferBuffer {
        self.buffer.get_mut()
    }

    /// Records a lower completion and schedules the owning executor.
    fn complete(&self, status: NTSTATUS, information: usize) {
        self.status.store(status, Ordering::Relaxed);
        self.information.store(information, Ordering::Relaxed);
        self.phase.store(COMPLETION_READY, Ordering::Release);
        self.wake.schedule();
    }

    /// Reads the published terminal result.
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

    /// Returns completed buffer bytes after the acquire in `result`.
    fn completed_buffer(&self) -> &AlignedTransferBuffer {
        unsafe {
            // SAFETY: Callers use this only after `result` observed `COMPLETION_READY` with acquire
            // ordering, so lower-device access has ended and the buffer is immutable.
            &*self.buffer.get()
        }
    }
}

// SAFETY: Lower-device access and future access to `buffer` are separated by `phase` release/acquire.
unsafe impl Send for LowerCompletion {}
// SAFETY: The only interior writes are atomic completion fields and lower-device buffer access that
// ends before `phase` publishes readiness.
unsafe impl Sync for LowerCompletion {}

/// One driver-created lower IRP represented as a cancellation-safe future.
struct LowerRequest {
    /// Lower storage device.
    device: KernelDevice,
    /// Lower major function.
    major: wdk_sys::ULONG,
    /// Sector-aligned starting offset.
    offset: ByteOffset,
    /// Completion-owned state and bounce buffer.
    completion: Arc<LowerCompletion>,
    /// Whether byte-count equality is required.
    expected_information: Option<usize>,
    /// Submission occurs on the first poll at `PASSIVE_LEVEL`.
    submitted: bool,
}

impl LowerRequest {
    /// Creates one not-yet-submitted lower request.
    fn new(
        device: KernelDevice,
        major: wdk_sys::ULONG,
        offset: ByteOffset,
        completion: Arc<LowerCompletion>,
        expected_information: Option<usize>,
    ) -> Self {
        Self {
            device,
            major,
            offset,
            completion,
            expected_information,
            submitted: false,
        }
    }

    /// Builds and submits the private lower IRP.
    #[cfg(not(test))]
    fn submit(&mut self) -> Result<()> {
        let request_len = wdk_sys::ULONG::try_from(self.completion.completed_buffer().len())
            .map_err(|_| Error::DeviceRange)?;
        let mut starting_offset = LARGE_INTEGER {
            QuadPart: i64::try_from(self.offset.get()).map_err(|_| Error::DeviceRange)?,
        };
        let starting_offset = if self.major == IRP_MJ_FLUSH_BUFFERS {
            core::ptr::null_mut()
        } else {
            core::ptr::addr_of_mut!(starting_offset)
        };
        let irp = unsafe {
            // SAFETY: The aligned nonpaged buffer and completion state outlive the lower IRP. The
            // I/O builder copies the starting offset into the new IRP stack.
            ffi::IoBuildAsynchronousFsdRequest(
                self.major,
                self.device.as_ptr(),
                self.completion.completed_buffer().as_void_ptr(),
                request_len,
                starting_offset,
                core::ptr::null_mut(),
            )
        };
        let Some(irp) = NonNull::new(irp) else {
            return Err(Error::OutOfMemory);
        };
        let callback_state = Arc::into_raw(Arc::clone(&self.completion))
            .cast_mut()
            .cast::<c_void>();
        let status = unsafe {
            // SAFETY: The callback state is nonpaged and retained by one raw Arc reference until
            // the completion routine reconstructs it. All outcomes request callback invocation.
            ffi::IoSetCompletionRoutineEx(
                self.device.as_ptr(),
                irp.as_ptr(),
                Some(lower_request_completed),
                callback_state,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
            )
        };
        if status < wdk_sys::STATUS_SUCCESS {
            unsafe {
                // SAFETY: Registration failed, so no callback owns the raw Arc or IRP resources.
                drop(Arc::from_raw(callback_state.cast::<LowerCompletion>()));
                release_private_irp(irp.as_ptr(), self.completion.direct_io);
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
    #[cfg(test)]
    fn submit(&mut self) -> Result<()> {
        Err(Error::DeviceIo)
    }
}

impl Future for LowerRequest {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.submitted {
            self.submitted = true;
            if let Err(error) = self.submit() {
                return Poll::Ready(Err(error));
            }
        }
        match self.completion.result(self.expected_information) {
            Some(result) => Poll::Ready(result),
            None => Poll::Pending,
        }
    }
}

// SAFETY: The lower device pointer is stable for the mounted-device lifetime and all completion
// state shared across workers is synchronized atomically.
unsafe impl Send for LowerRequest {}

/// Lower storage device exposed through ext4-core's asynchronous block traits.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelBlockDevice {
    /// Lower storage target.
    device: KernelDevice,
    /// Validated physical transfer constraints.
    geometry: TransferGeometry,
    /// Executor woken by lower completions.
    wake: CompletionWake,
    /// Whether the lower target uses direct I/O MDLs.
    direct_io: bool,
}

impl KernelBlockDevice {
    /// Creates the mounted lower-storage boundary.
    /// # Errors
    ///
    /// Returns an error when the lower device advertises invalid sector or buffer alignment.
    pub(crate) fn new(
        device: KernelDevice,
        length: DeviceLength,
        wake: CompletionWake,
    ) -> Result<Self> {
        let geometry = TransferGeometry::from_device(device, length)?;
        let object = unsafe {
            // SAFETY: `device` remains live for the mounted block-device lifetime and is read only
            // for its immutable I/O mode flags.
            device.as_ptr().as_ref()
        }
        .ok_or(Error::DeviceIo)?;
        Ok(Self {
            device,
            geometry,
            wake,
            direct_io: object.Flags & wdk_sys::DO_DIRECT_IO != 0,
        })
    }

    /// Creates completion-owned storage for one aligned transfer.
    fn completion(&self, len: usize) -> Result<Arc<LowerCompletion>> {
        LowerCompletion::try_new(
            len,
            self.geometry.buffer_alignment,
            self.wake,
            self.direct_io,
        )
    }

    /// Reads one already aligned transfer into completion-owned storage.
    async fn read_aligned(&mut self, transfer: CoveredTransfer) -> Result<Arc<LowerCompletion>> {
        let completion = self.completion(transfer.transfer_len)?;
        LowerRequest::new(
            self.device,
            IRP_MJ_READ,
            transfer.lower_offset,
            Arc::clone(&completion),
            Some(transfer.transfer_len),
        )
        .await?;
        Ok(completion)
    }

    /// Writes one already aligned completion-owned transfer.
    async fn write_aligned(
        &mut self,
        transfer: CoveredTransfer,
        completion: Arc<LowerCompletion>,
    ) -> Result<()> {
        LowerRequest::new(
            self.device,
            IRP_MJ_WRITE,
            transfer.lower_offset,
            completion,
            Some(transfer.transfer_len),
        )
        .await
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
                .completed_buffer()
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
        let mut completion = if transfer.is_complete_sector_range() {
            self.completion(transfer.transfer_len)?
        } else {
            self.read_aligned(transfer).await?
        };
        let buffer = Arc::get_mut(&mut completion).ok_or(Error::DeviceIo)?;
        buffer
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
            self.device,
            IRP_MJ_FLUSH_BUFFERS,
            ByteOffset::new(0),
            completion,
            None,
        )
        .await
    }
}

#[cfg(not(test))]
/// Releases an unsubmitted or terminal private IRP and any MDL built for its bounce buffer.
/// # Safety
///
/// `irp` must be a private IRP allocated by `IoBuildAsynchronousFsdRequest` and must not be owned by
/// a lower driver when this function is called.
unsafe fn release_private_irp(irp: PIRP, direct_io: bool) {
    let mdl = unsafe {
        // SAFETY: The caller guarantees that `irp` is valid and exclusively owned here.
        (*irp).MdlAddress
    };
    if let Some(mdl) = NonNull::new(mdl) {
        if direct_io {
            unsafe {
                // SAFETY: The I/O builder locked the nonpaged bounce-buffer pages represented by
                // this MDL for a direct-I/O target.
                ffi::MmUnlockPages(mdl.as_ptr());
            }
        }
        unsafe {
            // SAFETY: The MDL belongs exclusively to this driver-created IRP.
            ffi::IoFreeMdl(mdl.as_ptr());
        }
    }
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
    let status = unsafe {
        // SAFETY: The lower driver has terminally completed this private IRP.
        (*irp).IoStatus.__bindgen_anon_1.Status
    };
    let information = unsafe {
        // SAFETY: The lower driver has terminally completed this private IRP.
        (*irp).IoStatus.Information
    };
    unsafe {
        // SAFETY: This completion routine owns final release of the private lower IRP.
        release_private_irp(irp, completion.direct_io);
    }
    completion.complete(status, usize::try_from(information).unwrap_or(usize::MAX));
    STATUS_MORE_PROCESSING_REQUIRED
}

#[cfg(test)]
mod tests {
    use core::{ffi::c_void, ptr::NonNull};

    use super::{CompletionWake, TransferGeometry};
    use ext4_core::{ByteOffset, DeviceLength, Error};

    unsafe fn ignore_wake(_context: NonNull<c_void>) {}

    fn wake() -> CompletionWake {
        unsafe {
            // SAFETY: Tests never submit a lower IRP, so this inert stable pair is never invoked.
            CompletionWake::new(NonNull::dangling(), ignore_wake)
        }
    }

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
        let _wake = wake();
    }
}
