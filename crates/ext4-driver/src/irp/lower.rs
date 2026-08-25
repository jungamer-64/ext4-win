//! Driver-created lower IRPs with completion-owned lifetime and no future/waker state.

use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::boxed::Box;
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt;
use core::mem::ManuallyDrop;
#[cfg(not(test))]
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicUsize, Ordering};

#[cfg(not(test))]
use ext4_core::{ByteOffset, Error};
use wdk_sys::{IRP_MJ_DEVICE_CONTROL, IRP_MJ_FLUSH_BUFFERS, IRP_MJ_READ, IRP_MJ_WRITE, NTSTATUS};
#[cfg(not(test))]
use wdk_sys::{LARGE_INTEGER, PIO_STACK_LOCATION, PIRP};

use crate::kernel::fatal::KernelWideInconsistency;
#[cfg(not(test))]
use crate::kernel::ffi;
use crate::kernel::status::{DriverError, DriverResult};
#[cfg(not(test))]
use crate::memory;
use crate::memory::{DriverShared, DriverSharedLease, DriverSharedSlot};
#[cfg(not(test))]
use crate::state::KernelDevice;

/// `TRUE` represented as a WDK `BOOLEAN`.
#[cfg(not(test))]
const BOOLEAN_TRUE: wdk_sys::BOOLEAN = 1;
/// `IOCTL_DISK_GET_LENGTH_INFO` from `ntdddisk.h`.
const IOCTL_DISK_GET_LENGTH_INFO: wdk_sys::ULONG = 0x0007_405C;
/// Stops every later I/O Manager completion step for an ext4win-created private IRP.
pub const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS =
    i32::from_ne_bytes(0xC000_0016_u32.to_ne_bytes());

/// The private IRP is registered/submitted and can be canceled after submit returns.
const LOWER_SUBMITTED: u8 = 0;
/// A caller is inside `IoCancelIrp`; completion must defer IRP release.
const LOWER_CANCEL_CALLING: u8 = 1;
/// Completion released the private IRP and queued the envelope normally.
const LOWER_COMPLETED_QUEUED: u8 = 2;
/// Completion ran inside `IoCancelIrp` and retained the IRP for deferred release.
const LOWER_COMPLETED_DURING_CANCEL: u8 = 3;
/// The cancel caller returned and queued the deferred-release envelope.
const LOWER_DEFERRED_QUEUED: u8 = 4;

/// Publication owner selected by the lower completion/cancel state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LowerCompletionClaim {
    /// Completion owns immediate private-IRP release and inbox publication.
    PublishNow,
    /// The active cancel caller owns publication after `IoCancelIrp` returns.
    DeferToCancel,
}

/// Result of attempting to hand publication to a cancel call previously observed in progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionDuringCancelClaim {
    /// Completion atomically handed publication to the cancel caller.
    Deferred,
    /// Cancel returned the lifecycle to submitted before the handoff was committed.
    RetrySubmitted,
    /// The lifecycle left every valid completion/cancel state.
    Corrupt,
}

/// Atomically hands a completed request to the cancel caller that was observed in progress.
fn claim_completion_during_cancel(lifecycle: &AtomicU8) -> CompletionDuringCancelClaim {
    match lifecycle.compare_exchange(
        LOWER_CANCEL_CALLING,
        LOWER_COMPLETED_DURING_CANCEL,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => CompletionDuringCancelClaim::Deferred,
        Err(LOWER_SUBMITTED) => CompletionDuringCancelClaim::RetrySubmitted,
        Err(_) => CompletionDuringCancelClaim::Corrupt,
    }
}

/// Selects the sole inbox-publication owner without overwriting a concurrent cancel transition.
fn claim_lower_completion(lifecycle: &AtomicU8) -> Option<LowerCompletionClaim> {
    loop {
        match lifecycle.compare_exchange(
            LOWER_SUBMITTED,
            LOWER_COMPLETED_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(LowerCompletionClaim::PublishNow),
            Err(LOWER_CANCEL_CALLING) => match claim_completion_during_cancel(lifecycle) {
                CompletionDuringCancelClaim::Deferred => {
                    return Some(LowerCompletionClaim::DeferToCancel);
                }
                CompletionDuringCancelClaim::RetrySubmitted => {}
                CompletionDuringCancelClaim::Corrupt => return None,
            },
            Err(_) => return None,
        }
    }
}

/// Test rundown high bit marking terminal closure.
#[cfg(test)]
const TEST_RUNDOWN_CLOSED: usize = 1_usize << (usize::BITS - 1);

/// Lower storage operation with one exact I/O stack contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LowerOperation {
    /// Read device bytes into the nonpaged transfer buffer.
    Read,
    /// Write nonpaged transfer-buffer bytes to the device.
    Write,
    /// Persist all previously submitted writes.
    Flush,
    /// Query `GET_LENGTH_INFORMATION` during mount admission.
    QueryLength,
}

impl LowerOperation {
    /// Encodes the WDM major function.
    /// # Errors
    ///
    /// Returns an error if the WDK constant cannot fit its ABI field.
    fn major_function(self) -> DriverResult<u8> {
        let major = match self {
            Self::Read => IRP_MJ_READ,
            Self::Write => IRP_MJ_WRITE,
            Self::Flush => IRP_MJ_FLUSH_BUFFERS,
            Self::QueryLength => IRP_MJ_DEVICE_CONTROL,
        };
        u8::try_from(major).map_err(|_| DriverError::InvalidParameter)
    }

    /// I/O Manager operation flags for this private IRP.
    const fn irp_flags(self) -> wdk_sys::ULONG {
        match self {
            Self::Read => wdk_sys::IRP_READ_OPERATION,
            Self::Write => wdk_sys::IRP_WRITE_OPERATION,
            Self::Flush => 0,
            Self::QueryLength => 0,
        }
    }

    /// Whether the operation exposes a transfer buffer to the lower stack.
    const fn transfers_bytes(self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::QueryLength)
    }
}

/// Buffer representation required by one lower device stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LowerTransferMethod {
    /// `IRP.AssociatedIrp.SystemBuffer` points at the driver-owned buffer.
    Buffered,
    /// A driver-owned MDL describes the nonpaged buffer.
    Direct,
    /// `IRP.UserBuffer` points at the driver-owned kernel address.
    Neither,
}

impl LowerTransferMethod {
    /// Decodes the target device flags.
    /// # Errors
    ///
    /// Returns an error when mutually exclusive buffered and direct modes are both advertised.
    pub fn from_device_flags(flags: wdk_sys::ULONG) -> DriverResult<Self> {
        match flags & (wdk_sys::DO_BUFFERED_IO | wdk_sys::DO_DIRECT_IO) {
            0 => Ok(Self::Neither),
            wdk_sys::DO_BUFFERED_IO => Ok(Self::Buffered),
            wdk_sys::DO_DIRECT_IO => Ok(Self::Direct),
            _ => Err(DriverError::InvalidParameter),
        }
    }
}

/// Dynamically aligned nonpaged transfer allocation.
pub struct AlignedTransferBuffer {
    /// Allocation base, dangling only for a zero-length flush buffer.
    bytes: NonNull<u8>,
    /// Exact allocation layout retained for release.
    layout: Layout,
}

impl AlignedTransferBuffer {
    /// Allocates a zero-filled nonpaged transfer buffer.
    /// # Errors
    ///
    /// Returns an error when layout validation or allocation fails.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub fn try_zeroed(len: usize, alignment: usize) -> DriverResult<Self> {
        let layout =
            Layout::from_size_align(len, alignment).map_err(|_| DriverError::InvalidBufferSize)?;
        if len == 0 {
            return Ok(Self {
                bytes: NonNull::dangling(),
                layout,
            });
        }
        let allocation = unsafe {
            // SAFETY: `layout` was validated above. The driver global allocator is nonpaged.
            alloc_zeroed(layout)
        };
        let bytes = NonNull::new(allocation).ok_or(DriverError::InsufficientResources)?;
        Ok(Self { bytes, layout })
    }

    /// Allocation byte length.
    pub const fn len(&self) -> usize {
        self.layout.size()
    }

    /// Whether this is the zero-length flush buffer.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Stable kernel address supplied to the lower stack.
    const fn as_void_ptr(&self) -> *mut c_void {
        if self.is_empty() {
            core::ptr::null_mut()
        } else {
            self.bytes.as_ptr().cast()
        }
    }

    /// Immutable initialized bytes after lower-buffer release.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: This allocation owns `len` initialized bytes until `Drop`.
            core::slice::from_raw_parts(self.bytes.as_ptr(), self.len())
        }
    }

    /// Mutable initialized bytes before submission or after lower-buffer release.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            // SAFETY: The caller's mutable borrow excludes every Rust access to this allocation.
            core::slice::from_raw_parts_mut(self.bytes.as_ptr(), self.len())
        }
    }
}

impl fmt::Debug for AlignedTransferBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlignedTransferBuffer")
            .field("len", &self.len())
            .field("alignment", &self.layout.align())
            .finish_non_exhaustive()
    }
}

impl Drop for AlignedTransferBuffer {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn drop(&mut self) {
        if self.is_empty() {
            return;
        }
        unsafe {
            // SAFETY: This value owns the allocation made with this exact layout.
            dealloc(self.bytes.as_ptr(), self.layout);
        }
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Ownership moves the allocation; it never grants concurrent Rust access.
unsafe impl Send for AlignedTransferBuffer {}

/// Reference-counted rundown state retained by every lower-completion lease.
struct CompletionRundownState {
    /// Native executive rundown storage.
    #[cfg(not(test))]
    native: UnsafeCell<MaybeUninit<wdk_sys::EX_RUNDOWN_REF>>,
    /// Deterministic closed bit and lease count in unit tests.
    #[cfg(test)]
    state: AtomicUsize,
}

impl CompletionRundownState {
    /// Initializes native rundown in its final reference-counted allocation.
    /// # Errors
    ///
    /// Returns insufficient resources when the stable shared allocation cannot be created.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn try_new() -> DriverResult<DriverShared<Self>> {
        let slot = DriverSharedSlot::try_new()?;
        let state = slot.initialize(Self {
            #[cfg(not(test))]
            native: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(test)]
            state: AtomicUsize::new(0),
        });
        #[cfg(not(test))]
        unsafe {
            // SAFETY: DriverShared placed the state at its final address, and this is the unique
            // initialization before the owner is exposed.
            ffi::ExInitializeRundownProtection(state.get().native.get().cast());
        }
        Ok(state)
    }

    /// Acquires one completion lifetime lease unless teardown has closed the gate.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite shared-reference budget is exhausted.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn acquire(owner: &DriverShared<Self>) -> DriverResult<Option<CompletionRundownLease>> {
        let lease = owner.try_acquire()?;
        #[cfg(not(test))]
        {
            let acquired = unsafe {
                // SAFETY: Native storage was initialized and remains stable by the owner contract.
                ffi::ExAcquireRundownProtection(lease.get().native.get().cast())
            };
            if acquired == 0 {
                return Ok(None);
            }
        }
        #[cfg(test)]
        {
            if lease
                .get()
                .state
                .try_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    if state & TEST_RUNDOWN_CLOSED != 0 {
                        None
                    } else {
                        state
                            .checked_add(1)
                            .filter(|next| next & TEST_RUNDOWN_CLOSED == 0)
                    }
                })
                .is_err()
            {
                return Ok(None);
            }
        }
        Ok(Some(CompletionRundownLease { owner: lease }))
    }

    /// Closes acquisition and waits for every completion envelope to be reclaimed.
    /// # Safety
    ///
    /// The caller must first guarantee that every in-flight completion can still reach and wake
    /// its reactor so retained leases can drain.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub unsafe fn close_and_wait(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The caller satisfies PASSIVE_LEVEL and live-destination requirements.
            ffi::ExWaitForRundownProtectionRelease(self.native.get().cast());
        }
        #[cfg(test)]
        {
            let previous = self.state.fetch_or(TEST_RUNDOWN_CLOSED, Ordering::AcqRel);
            if previous & TEST_RUNDOWN_CLOSED != 0 {
                KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
            }
            while self.state.load(Ordering::Acquire) != TEST_RUNDOWN_CLOSED {
                core::hint::spin_loop();
            }
        }
    }

    /// Releases one successful acquisition.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn release(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: Each lease is created by exactly one successful native acquisition.
            ffi::ExReleaseRundownProtection(self.native.get().cast());
        }
        #[cfg(test)]
        {
            let previous = self.state.fetch_sub(1, Ordering::AcqRel);
            if previous == 0 || previous == TEST_RUNDOWN_CLOSED {
                KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
            }
        }
    }
}

/// Stable rundown gate protecting completion destinations beyond completion-routine invocation.
pub struct CompletionRundown {
    /// Shared owner retained by the reactor and every successful acquisition.
    owner: DriverShared<CompletionRundownState>,
}

impl CompletionRundown {
    /// Allocates and initializes an open rundown gate.
    /// # Errors
    ///
    /// Returns insufficient resources when the stable owner allocation fails.
    pub fn try_new() -> DriverResult<Self> {
        Ok(Self {
            owner: CompletionRundownState::try_new()?,
        })
    }

    /// Acquires one completion lifetime lease unless teardown has closed the gate.
    /// # Errors
    ///
    /// Returns insufficient resources when the finite shared-reference budget is exhausted.
    pub fn acquire(&self) -> DriverResult<Option<CompletionRundownLease>> {
        CompletionRundownState::acquire(&self.owner)
    }

    /// Closes acquisition and waits for every completion envelope to be reclaimed.
    /// # Safety
    ///
    /// The caller must first guarantee that every in-flight completion can still reach and wake
    /// its reactor so retained leases can drain.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub unsafe fn close_and_wait(&self) {
        unsafe {
            // SAFETY: The caller supplies the shutdown protocol required by the shared state.
            self.owner.get().close_and_wait();
        }
    }
}

impl fmt::Debug for CompletionRundown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletionRundown(..)")
    }
}

/// One successful acquisition that structurally retains its release destination.
pub struct CompletionRundownLease {
    /// Shared release owner; forgetting the lease delays teardown but cannot dangle.
    owner: DriverSharedLease<CompletionRundownState>,
}

impl fmt::Debug for CompletionRundownLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompletionRundownLease(..)")
    }
}

impl Drop for CompletionRundownLease {
    fn drop(&mut self) {
        self.owner.get().release();
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Executive rundown functions or the test atomic synchronize all interior state, and the
// native slot never moves after its driver-shared allocation.
unsafe impl Send for CompletionRundownState {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The same native/atomic protocol serializes every shared access to interior state.
unsafe impl Sync for CompletionRundownState {}

/// Statically dispatched, allocation-free destination for one lower completion envelope type.
///
/// # Safety
///
/// Implementations run in a lower completion callback. They must retain a stable destination until
/// rundown completes, publish the exact envelope once, and neither allocate nor block.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
pub(crate) unsafe trait LowerCompletionRoute<O>:
    Send + Sync + Sized + 'static
{
    /// Publishes one uniquely completion-owned envelope to its type-specific inbox.
    /// # Safety
    ///
    /// `envelope` must belong to this route and must not have been published before.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn publish(&self, envelope: NonNull<LowerCompletionEnvelope<O, Self>>);
}

/// Sole release authority for one ext4win-created private lower IRP and its attached MDLs.
#[cfg(not(test))]
struct LowerIrpReleaseAuthority {
    /// Live private IRP released exactly once by this value's destructor.
    irp: NonNull<wdk_sys::IRP>,
}

#[cfg(not(test))]
impl LowerIrpReleaseAuthority {
    /// Takes pre-submit release ownership of a freshly allocated private IRP.
    const fn new(irp: NonNull<wdk_sys::IRP>) -> Self {
        Self { irp }
    }

    /// Raw IRP address for registration, submission, or a serialized cancel call.
    const fn as_ptr(&self) -> PIRP {
        self.irp.as_ptr()
    }
}

#[cfg(not(test))]
impl Drop for LowerIrpReleaseAuthority {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn drop(&mut self) {
        unsafe {
            // SAFETY: This value is the unique release authority and lower ownership has ended.
            release_private_irp(self.irp.as_ptr());
        }
    }
}

/// Nonpaged, address-stable context passed as the sole lower completion context.
#[repr(C)]
pub struct LowerCompletionEnvelope<O, R: LowerCompletionRoute<O>> {
    /// Intrusive completion-inbox node. The envelope address is also this first field's address.
    node: UnsafeCell<wdk_sys::LIST_ENTRY>,
    /// Suspended scheduler operation; no raw pointer into it is ever created.
    suspended: ManuallyDrop<O>,
    /// Stable lower transfer buffer/MDL backing storage.
    transfer: ManuallyDrop<AlignedTransferBuffer>,
    /// Reactor destination retained by value.
    destination: R,
    /// Ext4win rundown lease independent of `IoSetCompletionRoutineEx` image protection.
    rundown: ManuallyDrop<CompletionRundownLease>,
    /// Completion-owned private-IRP release authority installed only after registration succeeds.
    #[cfg(not(test))]
    release_authority: UnsafeCell<MaybeUninit<LowerIrpReleaseAuthority>>,
    /// Publication bit for the release-authority slot.
    release_authority_ready: AtomicBool,
    /// Cancel/completion/release protocol.
    lifecycle: AtomicU8,
    /// Terminal lower NTSTATUS staged before inbox publication.
    status: AtomicI32,
    /// Terminal lower information byte count staged before inbox publication.
    information: AtomicUsize,
    /// Ensures payload destructors run once whether registration fails or completion is reclaimed.
    payload_taken: bool,
}

impl<O, R: LowerCompletionRoute<O>> LowerCompletionEnvelope<O, R> {
    /// Builds a fully initialized envelope before completion registration.
    fn new(
        suspended: O,
        transfer: AlignedTransferBuffer,
        destination: R,
        rundown: CompletionRundownLease,
    ) -> Self {
        Self {
            node: UnsafeCell::new(wdk_sys::LIST_ENTRY::default()),
            suspended: ManuallyDrop::new(suspended),
            transfer: ManuallyDrop::new(transfer),
            destination,
            rundown: ManuallyDrop::new(rundown),
            #[cfg(not(test))]
            release_authority: UnsafeCell::new(MaybeUninit::uninit()),
            release_authority_ready: AtomicBool::new(false),
            lifecycle: AtomicU8::new(LOWER_SUBMITTED),
            status: AtomicI32::new(wdk_sys::STATUS_PENDING),
            information: AtomicUsize::new(0),
            payload_taken: false,
        }
    }

    /// Intrusive node address for the completion inbox.
    pub const fn node_ptr(&self) -> *mut wdk_sys::LIST_ENTRY {
        self.node.get()
    }

    /// Recovers the envelope from its first-field intrusive node.
    /// # Safety
    ///
    /// `node` must be the node of a live `LowerCompletionEnvelope<O, R>` allocated by this module.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub unsafe fn from_node(node: NonNull<wdk_sys::LIST_ENTRY>) -> NonNull<Self> {
        node.cast()
    }

    /// Installs completion-side IRP release authority after successful registration.
    /// # Safety
    ///
    /// The slot must be uninitialized, completion registration must have succeeded, and the
    /// caller must proceed directly to `IoCallDriver` without exposing the envelope elsewhere.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn install_release_authority(&self, authority: LowerIrpReleaseAuthority) {
        unsafe {
            // SAFETY: Registration success is the sole writer and completion cannot run before
            // the immediately following `IoCallDriver`.
            (*self.release_authority.get()).write(authority);
        }
        self.release_authority_ready.store(true, Ordering::Release);
    }

    /// Reads the still-owned IRP address while serialized against completion release.
    /// # Safety
    ///
    /// The caller must own the cancel-calling lifecycle state, excluding completion-side release
    /// until the matching `IoCancelIrp` call returns.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn irp_for_cancel(&self) -> PIRP {
        if !self.release_authority_ready.load(Ordering::Acquire) {
            KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
        }
        let authority_slot = unsafe {
            // SAFETY: The envelope allocation remains live while cancellation owns its lifecycle.
            &*self.release_authority.get()
        };
        let authority = unsafe {
            // SAFETY: The ready bit publishes initialization and CANCEL_CALLING excludes removal.
            authority_slot.assume_init_ref()
        };
        authority.as_ptr()
    }

    /// Consumes and drops completion-side IRP release authority.
    /// # Safety
    ///
    /// Lower completion must uniquely own release for `completed_irp`, or deferred reclaim must
    /// own the lifecycle state published after the cancel caller returned.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn release_private_irp(&self, completed_irp: PIRP) {
        if !self.release_authority_ready.swap(false, Ordering::AcqRel) {
            KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
        }
        let authority_slot = unsafe {
            // SAFETY: The envelope remains live while the successful swap grants unique access.
            &*self.release_authority.get()
        };
        let authority = unsafe {
            // SAFETY: The successful ready-bit swap grants unique extraction of this initialized
            // authority slot.
            authority_slot.assume_init_read()
        };
        if authority.as_ptr() != completed_irp {
            KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
        }
        drop(authority);
    }

    /// Turns one inbox-owned completed envelope back into Rust values at `PASSIVE_LEVEL`.
    /// # Safety
    ///
    /// The caller must have removed this exact envelope once from its completion inbox and must
    /// exclude every cancellation caller.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub unsafe fn reclaim(mut envelope: Box<Self>) -> CompletedLowerIrp<O> {
        let lifecycle = envelope.lifecycle.load(Ordering::Acquire);
        if lifecycle == LOWER_DEFERRED_QUEUED {
            #[cfg(not(test))]
            {
                let irp = unsafe {
                    // SAFETY: Deferred publication occurs only after `IoCancelIrp` returned.
                    envelope.irp_for_cancel()
                };
                unsafe {
                    // SAFETY: Inbox reclaim now uniquely owns the deferred release authority.
                    envelope.release_private_irp(irp);
                }
            }
        } else if lifecycle != LOWER_COMPLETED_QUEUED {
            KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
        }
        let status = envelope.status.load(Ordering::Relaxed);
        let information = envelope.information.load(Ordering::Relaxed);
        let suspended = unsafe {
            // SAFETY: Inbox ownership is unique and callback code never touches this field.
            ManuallyDrop::take(&mut envelope.suspended)
        };
        let transfer = unsafe {
            // SAFETY: IRP/MDL release above proves the lower stack no longer uses this buffer.
            ManuallyDrop::take(&mut envelope.transfer)
        };
        unsafe {
            // SAFETY: This unique reclaim consumes the envelope's sole rundown lease.
            ManuallyDrop::drop(&mut envelope.rundown);
        }
        envelope.payload_taken = true;
        drop(envelope);
        CompletedLowerIrp {
            suspended,
            transfer,
            status,
            information,
        }
    }

    /// Reclaims only the suspended operation after completion registration failed.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn reclaim_unsubmitted(mut envelope: Box<Self>) -> O {
        let suspended = unsafe {
            // SAFETY: Registration failure proves no callback can access the envelope payload.
            ManuallyDrop::take(&mut envelope.suspended)
        };
        unsafe {
            // SAFETY: The transfer never reached a lower stack and remains locally owned.
            ManuallyDrop::drop(&mut envelope.transfer);
        }
        unsafe {
            // SAFETY: Registration failed, so the rundown lease remains locally owned.
            ManuallyDrop::drop(&mut envelope.rundown);
        }
        envelope.payload_taken = true;
        drop(envelope);
        suspended
    }
}

impl<O, R: LowerCompletionRoute<O>> fmt::Debug for LowerCompletionEnvelope<O, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LowerCompletionEnvelope")
            .field("lifecycle", &self.lifecycle.load(Ordering::Relaxed))
            .field("status", &self.status.load(Ordering::Relaxed))
            .field("information", &self.information.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<O, R: LowerCompletionRoute<O>> Drop for LowerCompletionEnvelope<O, R> {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        if self.release_authority_ready.swap(false, Ordering::AcqRel) {
            let authority_slot = unsafe {
                // SAFETY: Unique envelope drop owns the unpublished authority slot.
                &*self.release_authority.get()
            };
            let authority = unsafe {
                // SAFETY: The ready bit proves this uniquely owned slot is initialized.
                authority_slot.assume_init_read()
            };
            drop(authority);
        }
        if !self.payload_taken {
            unsafe {
                // SAFETY: No extraction occurred, so suspended remains initialized.
                ManuallyDrop::drop(&mut self.suspended);
            }
            unsafe {
                // SAFETY: No extraction occurred, so transfer remains initialized.
                ManuallyDrop::drop(&mut self.transfer);
            }
            unsafe {
                // SAFETY: No extraction occurred, so rundown remains initialized.
                ManuallyDrop::drop(&mut self.rundown);
            }
        }
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: `O` moves only between the reactor and envelope; callbacks never access it.
unsafe impl<O: Send, R: LowerCompletionRoute<O>> Send for LowerCompletionEnvelope<O, R> {}
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Callback-visible fields are atomic or callback-exclusive; payload fields are not read
// until completion inbox ownership is acquired.
unsafe impl<O: Send, R: LowerCompletionRoute<O>> Sync for LowerCompletionEnvelope<O, R> {}

/// Reactor-owned values recovered after lower completion and private-IRP release.
#[derive(Debug)]
pub struct CompletedLowerIrp<O> {
    /// Suspended operation resumed by the concrete completion event.
    pub suspended: O,
    /// Transfer buffer no longer visible to any lower stack.
    pub transfer: AlignedTransferBuffer,
    /// Raw terminal NTSTATUS for retry/failure classification.
    pub status: NTSTATUS,
    /// Raw terminal information byte count.
    pub information: usize,
}

/// Stable cancellation identity for an envelope already returned from `IoCallDriver`.
pub struct PublishedLowerRequest<O, R: LowerCompletionRoute<O>> {
    /// Envelope head; never a pointer into suspended operation state.
    envelope: NonNull<LowerCompletionEnvelope<O, R>>,
}

impl<O, R: LowerCompletionRoute<O>> PublishedLowerRequest<O, R> {
    /// Returns whether this cancellation identity names the supplied envelope head.
    ///
    /// This compares only stable envelope addresses; it never searches for or dereferences an
    /// operation generation.
    pub fn identifies(&self, envelope: NonNull<LowerCompletionEnvelope<O, R>>) -> bool {
        self.envelope.as_ptr() == envelope.as_ptr()
    }

    /// Cancels one published lower request without taking IRP release authority.
    /// # Safety
    ///
    /// The reactor's active-operation lock must prove this envelope is still live and that
    /// `IoCallDriver` has returned. The lock must remain held until this call returns.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub unsafe fn cancel(&self) {
        let envelope = unsafe {
            // SAFETY: The caller proves the envelope remains live under the reactor lock.
            self.envelope.as_ref()
        };
        match envelope.lifecycle.compare_exchange(
            LOWER_SUBMITTED,
            LOWER_CANCEL_CALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(LOWER_COMPLETED_QUEUED | LOWER_DEFERRED_QUEUED) => return,
            Err(_) => {
                KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
            }
        }
        let irp = unsafe {
            // SAFETY: CANCEL_CALLING prevents completion from releasing the IRP during this call.
            envelope.irp_for_cancel()
        };
        let _cancel_was_observed = unsafe {
            // SAFETY: The caller invokes this only after the private IRP was submitted and while
            // CANCEL_CALLING keeps its release authority live.
            ffi::IoCancelIrp(irp)
        };
        match envelope.lifecycle.compare_exchange(
            LOWER_CANCEL_CALLING,
            LOWER_SUBMITTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(LOWER_COMPLETED_DURING_CANCEL) => {
                envelope
                    .lifecycle
                    .store(LOWER_DEFERRED_QUEUED, Ordering::Release);
                unsafe {
                    // SAFETY: The completion routine delegated this one publication to the cancel
                    // caller after `IoCancelIrp` returned.
                    envelope.destination.publish(self.envelope);
                }
            }
            Err(_) => {
                KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
            }
        }
    }
}

impl<O, R: LowerCompletionRoute<O>> fmt::Debug for PublishedLowerRequest<O, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublishedLowerRequest(..)")
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The reactor lock and envelope lifecycle atomics serialize use of the stable pointer.
unsafe impl<O: Send, R: LowerCompletionRoute<O>> Send for PublishedLowerRequest<O, R> {}

/// Lower-IRP construction failure that preserves the suspended operation.
#[derive(Debug)]
pub struct LowerBuildError<O> {
    /// Driver-domain construction error.
    error: DriverError,
    /// Operation that was never exposed to a lower driver.
    suspended: O,
}

impl<O> LowerBuildError<O> {
    /// Builds an error before any lower resource has observed the suspended operation.
    pub fn from_unsubmitted(error: DriverError, suspended: O) -> Self {
        Self { error, suspended }
    }

    /// Separates the normal error from the still-owned suspended operation.
    pub fn into_parts(self) -> (DriverError, O) {
        (self.error, self.suspended)
    }
}

/// Completion-registration failure that preserves the suspended operation.
#[derive(Debug)]
pub struct LowerRegistrationError<O> {
    /// Driver-domain registration error.
    error: DriverError,
    /// Operation that was never submitted to a lower driver.
    suspended: O,
}

impl<O> LowerRegistrationError<O> {
    /// Separates the normal error from the still-owned suspended operation.
    pub fn into_parts(self) -> (DriverError, O) {
        (self.error, self.suspended)
    }
}

/// Envelope payload retained intact until every fallible IRP construction step succeeds.
#[cfg(not(test))]
struct UnregisteredEnvelope<O, R: LowerCompletionRoute<O>> {
    /// Suspended scheduler operation.
    suspended: O,
    /// Stable lower transfer allocation.
    transfer: AlignedTransferBuffer,
    /// Completion destination.
    destination: R,
    /// Completion rundown lease.
    rundown: CompletionRundownLease,
}

/// One concrete lower-stack transfer contract with its owned stable buffer.
#[cfg(not(test))]
#[derive(Debug)]
pub struct LowerIrpTransfer {
    /// Target lower device.
    target: KernelDevice,
    /// Major operation and stack-union interpretation.
    operation: LowerOperation,
    /// Buffer representation required by the target stack.
    method: LowerTransferMethod,
    /// Starting byte offset for transfers, zero for non-range operations.
    offset: ByteOffset,
    /// Stable nonpaged bytes retained through lower completion.
    transfer: AlignedTransferBuffer,
}

#[cfg(not(test))]
impl LowerIrpTransfer {
    /// Seals the complete lower-stack transfer contract before IRP construction.
    pub const fn new(
        target: KernelDevice,
        operation: LowerOperation,
        method: LowerTransferMethod,
        offset: ByteOffset,
        transfer: AlignedTransferBuffer,
    ) -> Self {
        Self {
            target,
            operation,
            method,
            offset,
            transfer,
        }
    }
}

/// Fully prepared pre-registration private IRP and stable completion envelope.
#[cfg(not(test))]
pub struct PreparedLowerIrp<O, R: LowerCompletionRoute<O>> {
    /// Driver-owned device whose image owns the registered completion routine.
    completion_owner: KernelDevice,
    /// Target lower storage device.
    target: KernelDevice,
    /// Pre-submit IRP release authority.
    irp: LowerIrpReleaseAuthority,
    /// Nonpaged stable envelope passed as the sole completion context.
    envelope: Box<LowerCompletionEnvelope<O, R>>,
}

#[cfg(not(test))]
impl<O, R: LowerCompletionRoute<O>> fmt::Debug for PreparedLowerIrp<O, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedLowerIrp(..)")
    }
}

#[cfg(not(test))]
impl<O: Send + 'static, R: LowerCompletionRoute<O>> PreparedLowerIrp<O, R> {
    /// Fallibly builds every IRP, MDL, stack, envelope, and rundown resource before registration.
    /// # Errors
    ///
    /// Returns an error when stack validation, conversion, IRP/MDL/envelope allocation, or
    /// pre-submit setup fails. All partially built resources are released locally.
    pub fn try_new(
        completion_owner: KernelDevice,
        lower: LowerIrpTransfer,
        suspended: O,
        destination: R,
        rundown: CompletionRundownLease,
    ) -> Result<Self, LowerBuildError<O>> {
        let LowerIrpTransfer {
            target,
            operation,
            method,
            offset,
            transfer,
        } = lower;
        let source = UnregisteredEnvelope {
            suspended,
            transfer,
            destination,
            rundown,
        };
        let authority =
            match prepare_private_irp(target, operation, method, offset, &source.transfer) {
                Ok(authority) => authority,
                Err(error) => {
                    return Err(LowerBuildError {
                        error,
                        suspended: source.suspended,
                    });
                }
            };
        let envelope = match memory::boxed_try_map(source, |source| {
            LowerCompletionEnvelope::new(
                source.suspended,
                source.transfer,
                source.destination,
                source.rundown,
            )
        }) {
            Ok(envelope) => envelope,
            Err(error) => {
                let (error, source) = error.into_parts();
                return Err(LowerBuildError {
                    error,
                    suspended: source.suspended,
                });
            }
        };
        Ok(Self {
            completion_owner,
            target,
            irp: authority,
            envelope,
        })
    }

    /// Returns the envelope-head cancellation identity before registration.
    ///
    /// The scheduler may reserve this identity in an unpublished active slot. It must remove the
    /// slot if [`Self::register_and_submit`] returns an error and may expose cancellation only
    /// after that method returns success.
    pub fn cancellation_identity(&mut self) -> PublishedLowerRequest<O, R> {
        PublishedLowerRequest {
            envelope: NonNull::from(self.envelope.as_mut()),
        }
    }

    /// Registers and immediately submits the private IRP.
    /// # Errors
    ///
    /// Registration failure is the sole error after construction; the pre-submit builder then
    /// releases the IRP, MDL, envelope, payload, and rundown lease locally.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub fn register_and_submit(mut self) -> Result<(), LowerRegistrationError<O>> {
        let envelope = NonNull::from(self.envelope.as_mut());
        let status = unsafe {
            // SAFETY: The envelope is nonpaged and address-stable, and every callback outcome is
            // requested. The context is exactly the envelope head, never an operation field.
            ffi::IoSetCompletionRoutineEx(
                self.completion_owner.as_ptr(),
                self.irp.as_ptr(),
                Some(lower_request_completed::<O, R>),
                envelope.as_ptr().cast::<c_void>(),
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
                BOOLEAN_TRUE,
            )
        };
        if status < wdk_sys::STATUS_SUCCESS {
            let Self {
                completion_owner: _,
                target: _,
                irp,
                envelope,
            } = self;
            drop(irp);
            return Err(LowerRegistrationError {
                error: DriverError::from(Error::DeviceIo),
                suspended: LowerCompletionEnvelope::reclaim_unsubmitted(envelope),
            });
        }

        // From this point the release authority moves irreversibly into the completion envelope.
        // This infallible move is followed immediately by the sole legal action: IoCallDriver.
        let registered = unsafe {
            // SAFETY: Registration succeeded and completion cannot run until IoCallDriver below.
            self.into_registered(envelope)
        };
        registered.call_driver();
        Ok(())
    }

    /// Irreversibly transfers envelope and IRP release ownership to completion.
    /// # Safety
    ///
    /// Completion registration must have succeeded for `envelope_address`, which must identify
    /// `self.envelope`; the caller must invoke the returned request immediately and exactly once.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn into_registered(
        self,
        envelope_address: NonNull<LowerCompletionEnvelope<O, R>>,
    ) -> RegisteredLowerRequest {
        let Self {
            completion_owner: _,
            target,
            irp,
            envelope,
        } = self;
        let irp_address = irp.irp;
        let envelope_ref = unsafe {
            // SAFETY: The address was obtained from the still-live boxed envelope above.
            envelope_address.as_ref()
        };
        unsafe {
            // SAFETY: Registration succeeded and the caller submits without intervening work.
            envelope_ref.install_release_authority(irp);
        }
        let raw_envelope = Box::into_raw(envelope);
        let _completion_owned_envelope = raw_envelope;
        RegisteredLowerRequest {
            target,
            irp: irp_address,
        }
    }
}

/// Registered request whose only operation is the unconditional lower call.
#[cfg(not(test))]
struct RegisteredLowerRequest {
    /// Lower device receiving the request.
    target: KernelDevice,
    /// Private IRP now owned by its completion envelope.
    irp: NonNull<wdk_sys::IRP>,
}

#[cfg(not(test))]
impl RegisteredLowerRequest {
    /// Calls the lower driver exactly once and never touches IRP/envelope state afterward.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn call_driver(self) {
        unsafe {
            // SAFETY: Successful completion registration transferred all lifetime authority to
            // the callback. Synchronous completion may free the IRP inside this call.
            let _call_status = ffi::IofCallDriver(self.target.as_ptr(), self.irp.as_ptr());
        }
    }
}

#[cfg(not(test))]
/// Builds the private IRP and optional MDL while the ownership-bearing envelope source remains
/// untouched.
/// # Errors
///
/// Returns an error when the transfer contract is inconsistent, target geometry is invalid, an
/// IRP or MDL cannot be allocated, or an ABI field cannot represent the request.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
fn prepare_private_irp(
    target: KernelDevice,
    operation: LowerOperation,
    transfer_method: LowerTransferMethod,
    offset: ByteOffset,
    transfer: &AlignedTransferBuffer,
) -> DriverResult<LowerIrpReleaseAuthority> {
    if operation.transfers_bytes() == transfer.is_empty() {
        return Err(DriverError::InvalidBufferSize);
    }
    let transfer_length =
        wdk_sys::ULONG::try_from(transfer.len()).map_err(|_| DriverError::InvalidBufferSize)?;
    let starting_offset = LARGE_INTEGER {
        QuadPart: i64::try_from(offset.get()).map_err(|_| DriverError::InvalidParameter)?,
    };
    let major = operation.major_function()?;
    let kernel_mode = wdk_sys::KPROCESSOR_MODE::try_from(wdk_sys::_MODE::KernelMode)
        .map_err(|_| DriverError::InternalInvariantViolation)?;
    let stack_size = target
        .stack_size()
        .filter(|stack_size| *stack_size > 0)
        .ok_or(DriverError::InvalidParameter)?;
    let irp = unsafe {
        // SAFETY: The validated target stack depth supplies every lower stack slot.
        ffi::IoAllocateIrp(stack_size, 0)
    };
    let irp = NonNull::new(irp).ok_or(DriverError::InsufficientResources)?;
    let authority = LowerIrpReleaseAuthority::new(irp);
    let irp_ref = unsafe {
        // SAFETY: Freshly allocated private IRP is exclusively owned by `authority`.
        &mut *authority.as_ptr()
    };
    irp_ref.RequestorMode = kernel_mode;
    irp_ref.Flags = operation.irp_flags();
    irp_ref.MdlAddress = core::ptr::null_mut();
    irp_ref.UserBuffer = core::ptr::null_mut();
    irp_ref.AssociatedIrp.SystemBuffer = core::ptr::null_mut();
    irp_ref.IoStatus.__bindgen_anon_1.Status = wdk_sys::STATUS_PENDING;
    irp_ref.IoStatus.Information = 0;
    let stack = unsafe {
        // SAFETY: Positive target stack depth provides one unused private stack location.
        next_irp_stack_location(authority.as_ptr())
    };
    unsafe {
        // SAFETY: The unused stack slot is exclusively owned before submission.
        core::ptr::write(stack, wdk_sys::IO_STACK_LOCATION::default());
    }
    let stack = unsafe {
        // SAFETY: The initialized stack location remains exclusively owned here.
        &mut *stack
    };
    stack.MajorFunction = major;
    stack.FileObject = core::ptr::null_mut();
    match operation {
        LowerOperation::Read => {
            stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
                Length: transfer_length,
                __bindgen_padding_0: 0,
                Key: 0,
                Flags: 0,
                ByteOffset: starting_offset,
            };
        }
        LowerOperation::Write => {
            stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
                Length: transfer_length,
                __bindgen_padding_0: 0,
                Key: 0,
                Flags: 0,
                ByteOffset: starting_offset,
            };
        }
        LowerOperation::Flush => {}
        LowerOperation::QueryLength => {
            stack.Parameters.DeviceIoControl =
                wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_17 {
                    OutputBufferLength: transfer_length,
                    __bindgen_padding_0: 0,
                    InputBufferLength: 0,
                    __bindgen_padding_1: 0,
                    IoControlCode: IOCTL_DISK_GET_LENGTH_INFO,
                    Type3InputBuffer: core::ptr::null_mut(),
                };
        }
    }
    if operation.transfers_bytes() {
        match if operation == LowerOperation::QueryLength {
            LowerTransferMethod::Buffered
        } else {
            transfer_method
        } {
            LowerTransferMethod::Buffered => {
                irp_ref.AssociatedIrp.SystemBuffer = transfer.as_void_ptr();
            }
            LowerTransferMethod::Direct => {
                let mdl = unsafe {
                    // SAFETY: The nonpaged transfer will move into a stable envelope before
                    // registration, and the private IRP remains uniquely pre-submit owned.
                    ffi::IoAllocateMdl(
                        transfer.as_void_ptr(),
                        transfer_length,
                        0,
                        0,
                        authority.as_ptr(),
                    )
                };
                let mdl = NonNull::new(mdl).ok_or(DriverError::InsufficientResources)?;
                unsafe {
                    // SAFETY: The MDL describes driver-owned nonpaged pool.
                    ffi::MmBuildMdlForNonPagedPool(mdl.as_ptr());
                }
            }
            LowerTransferMethod::Neither => {
                irp_ref.UserBuffer = transfer.as_void_ptr();
            }
        }
    }
    Ok(authority)
}

#[cfg(not(test))]
/// Returns the next private-IRP stack slot using the WDK macro contract.
/// # Safety
///
/// `irp` must be freshly allocated with a positive unused stack depth.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn next_irp_stack_location(irp: PIRP) -> PIO_STACK_LOCATION {
    let irp = unsafe {
        // SAFETY: The caller guarantees one valid live private IRP.
        &*irp
    };
    let tail = unsafe {
        // SAFETY: Live IRP stack traversal selects the Tail.Overlay representation.
        &irp.Tail.Overlay
    };
    let current = unsafe {
        // SAFETY: The stack-traversal union arm is active for this allocated IRP.
        tail.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation
    };
    unsafe {
        // SAFETY: Positive stack depth guarantees one initialized slot before `current`.
        current.sub(1)
    }
}

#[cfg(not(test))]
/// Releases one ext4win-created private IRP and each attached MDL exactly once.
/// # Safety
///
/// `irp` must be uniquely release-owned and no lower stack may still use it.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn release_private_irp(irp: PIRP) {
    let irp_ref = unsafe {
        // SAFETY: The caller holds the sole release authority.
        &mut *irp
    };
    let mut mdl = irp_ref.MdlAddress;
    irp_ref.MdlAddress = core::ptr::null_mut();
    while let Some(current) = NonNull::new(mdl) {
        let current_ref = unsafe {
            // SAFETY: The MDL remains linked to the uniquely owned private IRP.
            &mut *current.as_ptr()
        };
        let next = current_ref.Next;
        let flags = u32::from(u16::from_ne_bytes(current_ref.MdlFlags.to_ne_bytes()));
        if flags & wdk_sys::MDL_PAGES_LOCKED != 0 {
            unsafe {
                // SAFETY: Only lower-added locked MDLs carry this bit; driver nonpaged MDLs do not.
                ffi::MmUnlockPages(current.as_ptr());
            }
        }
        unsafe {
            // SAFETY: This detached MDL is released once.
            ffi::IoFreeMdl(current.as_ptr());
        }
        mdl = next;
    }
    irp_ref.AssociatedIrp.SystemBuffer = core::ptr::null_mut();
    irp_ref.UserBuffer = core::ptr::null_mut();
    unsafe {
        // SAFETY: Completion processing is stopped or submission never occurred.
        ffi::IoFreeIrp(irp);
    }
}

#[cfg(not(test))]
/// Completion routine for every ext4win-created lower read, write, and flush IRP.
/// # Safety
///
/// The I/O Manager must supply the private IRP and exact envelope-head context registered by
/// `PreparedLowerIrp`.
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn lower_request_completed<O: Send + 'static, R: LowerCompletionRoute<O>>(
    _device: wdk_sys::PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let Some(envelope_address) = NonNull::new(context.cast::<LowerCompletionEnvelope<O, R>>())
    else {
        return STATUS_MORE_PROCESSING_REQUIRED;
    };
    let envelope = unsafe {
        // SAFETY: Registration supplied the live envelope head as its sole context.
        envelope_address.as_ref()
    };
    let Some(irp_address) = NonNull::new(irp) else {
        KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
    };
    let irp_ref = unsafe {
        // SAFETY: The lower stack terminally completed this private IRP before callback entry.
        irp_address.as_ref()
    };
    let status = unsafe {
        // SAFETY: NTSTATUS is the active terminal IoStatus union arm.
        irp_ref.IoStatus.__bindgen_anon_1.Status
    };
    let information = match usize::try_from(irp_ref.IoStatus.Information) {
        Ok(information) => information,
        Err(_) => usize::MAX,
    };
    envelope.status.store(status, Ordering::Relaxed);
    envelope.information.store(information, Ordering::Relaxed);
    match claim_lower_completion(&envelope.lifecycle) {
        Some(LowerCompletionClaim::PublishNow) => {
            unsafe {
                // SAFETY: Normal completion owns release authority and no cancel call is active.
                envelope.release_private_irp(irp);
            }
            unsafe {
                // SAFETY: IRP/MDL/buffer use ended before this release-published inbox insertion.
                envelope.destination.publish(envelope_address);
            }
        }
        Some(LowerCompletionClaim::DeferToCancel) => {}
        None => {
            KernelWideInconsistency::lower_completion_ownership_corruption().bugcheck();
        }
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

#[cfg(test)]
mod tests {
    use core::ptr::NonNull;
    use core::sync::atomic::Ordering;

    use crate::kernel::status::DriverError;
    use crate::memory;

    use super::{
        AlignedTransferBuffer, CompletionDuringCancelClaim, CompletionRundown,
        IOCTL_DISK_GET_LENGTH_INFO, LOWER_CANCEL_CALLING, LOWER_COMPLETED_DURING_CANCEL,
        LOWER_COMPLETED_QUEUED, LOWER_DEFERRED_QUEUED, LOWER_SUBMITTED, LowerBuildError,
        LowerCompletionClaim, LowerCompletionEnvelope, LowerCompletionRoute, LowerOperation,
        LowerRegistrationError, LowerTransferMethod, PublishedLowerRequest,
        STATUS_MORE_PROCESSING_REQUIRED, claim_completion_during_cancel, claim_lower_completion,
    };

    /// Concrete test route proving completion publication needs no function pointer.
    #[derive(Clone, Copy)]
    struct TestCompletionRoute {
        /// Address-stable synchronous inbox.
        inbox: NonNull<Option<NonNull<TestEnvelope>>>,
    }

    /// Exact envelope type accepted by the synchronous test route.
    type TestEnvelope = LowerCompletionEnvelope<u64, TestCompletionRoute>;

    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    // SAFETY: Tests publish synchronously while the stack-local inbox remains live.
    unsafe impl Send for TestCompletionRoute {}
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    // SAFETY: Tests never access the inbox concurrently.
    unsafe impl Sync for TestCompletionRoute {}

    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    // SAFETY: Publication writes exactly one matching envelope into a live synchronous inbox.
    unsafe impl LowerCompletionRoute<u64> for TestCompletionRoute {
        #[expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )]
        unsafe fn publish(&self, envelope: NonNull<TestEnvelope>) {
            let inbox = unsafe {
                // SAFETY: Each test keeps the uniquely writable inbox live through publication.
                &mut *self.inbox.as_ptr()
            };
            *inbox = Some(envelope);
        }
    }

    /// # Panics
    ///
    /// Panics when operation stack encodings overlap or omit the expected transfer contract.
    #[test]
    fn lower_operations_have_exact_transfer_contracts() {
        assert!(LowerOperation::Read.transfers_bytes());
        assert!(LowerOperation::Write.transfers_bytes());
        assert!(!LowerOperation::Flush.transfers_bytes());
        assert!(LowerOperation::QueryLength.transfers_bytes());
        assert_ne!(
            LowerOperation::Read.major_function(),
            LowerOperation::Write.major_function()
        );
        assert_eq!(
            LowerOperation::Read.irp_flags(),
            wdk_sys::IRP_READ_OPERATION
        );
        assert_eq!(
            LowerOperation::Write.irp_flags(),
            wdk_sys::IRP_WRITE_OPERATION
        );
        assert_eq!(LowerOperation::Flush.irp_flags(), 0);
        assert_eq!(IOCTL_DISK_GET_LENGTH_INFO, 0x0007_405C);
        assert_eq!(
            STATUS_MORE_PROCESSING_REQUIRED,
            i32::from_ne_bytes(0xC000_0016_u32.to_ne_bytes())
        );
        let lifecycle = [
            LOWER_SUBMITTED,
            LOWER_CANCEL_CALLING,
            LOWER_COMPLETED_QUEUED,
            LOWER_COMPLETED_DURING_CANCEL,
            LOWER_DEFERRED_QUEUED,
        ];
        for (index, state) in lifecycle.iter().enumerate() {
            assert!(lifecycle.iter().skip(index + 1).all(|other| other != state));
        }
    }

    /// # Panics
    ///
    /// Panics when completion can overwrite a cancel caller that already restored the submitted
    /// state, leaving neither side responsible for publication.
    #[test]
    fn completion_retries_when_cancel_returns_before_deferred_handoff() {
        let lifecycle = core::sync::atomic::AtomicU8::new(LOWER_CANCEL_CALLING);

        assert_eq!(
            lifecycle.compare_exchange(
                LOWER_CANCEL_CALLING,
                LOWER_SUBMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ),
            Ok(LOWER_CANCEL_CALLING)
        );
        assert_eq!(
            claim_completion_during_cancel(&lifecycle),
            CompletionDuringCancelClaim::RetrySubmitted
        );
        assert_eq!(
            claim_lower_completion(&lifecycle),
            Some(LowerCompletionClaim::PublishNow)
        );
        assert_eq!(lifecycle.load(Ordering::Acquire), LOWER_COMPLETED_QUEUED);
    }

    /// # Panics
    ///
    /// Panics when conflicting lower transfer flags are accepted.
    #[test]
    fn transfer_method_rejects_conflicting_device_flags() {
        assert_eq!(
            LowerTransferMethod::from_device_flags(0),
            Ok(LowerTransferMethod::Neither)
        );
        assert_eq!(
            LowerTransferMethod::from_device_flags(wdk_sys::DO_DIRECT_IO),
            Ok(LowerTransferMethod::Direct)
        );
        assert!(
            LowerTransferMethod::from_device_flags(wdk_sys::DO_DIRECT_IO | wdk_sys::DO_BUFFERED_IO)
                .is_err()
        );
    }

    /// # Panics
    ///
    /// Panics when rundown can close while a lease remains or admits work after closure.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn completion_rundown_rejects_post_teardown_acquisition() {
        let Ok(rundown) = CompletionRundown::try_new() else {
            return;
        };
        let Ok(Some(lease)) = rundown.acquire() else {
            return;
        };
        drop(lease);
        unsafe {
            // SAFETY: No acquired lease remains in this isolated test gate.
            rundown.close_and_wait();
        }
        assert!(matches!(rundown.acquire(), Ok(None)));
    }

    /// # Panics
    ///
    /// Panics if the completion context stops being the envelope head or reclaim duplicates any
    /// owned payload.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn stable_envelope_head_round_trips_owned_payload_once() {
        let Ok(rundown) = CompletionRundown::try_new() else {
            return;
        };
        let Ok(Some(lease)) = rundown.acquire() else {
            return;
        };
        let Ok(transfer) = AlignedTransferBuffer::try_zeroed(16, 16) else {
            return;
        };
        assert!(!transfer.as_void_ptr().is_null());
        let mut inbox: Option<NonNull<TestEnvelope>> = None;
        let destination = TestCompletionRoute {
            inbox: NonNull::from(&mut inbox),
        };
        let Ok(mut envelope) = memory::boxed_try_with(move || {
            Ok(LowerCompletionEnvelope::new(
                0x5A_u64,
                transfer,
                destination,
                lease,
            ))
        }) else {
            return;
        };
        let address = NonNull::from(envelope.as_mut());
        let Some(node) = NonNull::new(envelope.node_ptr()) else {
            return;
        };
        let recovered = unsafe {
            // SAFETY: `node` is the live first field of this exact envelope.
            TestEnvelope::from_node(node)
        };
        assert_eq!(address, recovered);

        envelope
            .status
            .store(wdk_sys::STATUS_SUCCESS, Ordering::Relaxed);
        envelope.information.store(16, Ordering::Relaxed);
        envelope
            .lifecycle
            .store(LOWER_COMPLETED_QUEUED, Ordering::Release);
        unsafe {
            // SAFETY: This publishes the one live envelope to the type-matched local inbox.
            destination.publish(address);
        }
        let Some(published) = inbox else {
            return;
        };
        let cancellation = PublishedLowerRequest {
            envelope: published,
        };
        assert!(cancellation.identifies(address));

        let completed = unsafe {
            // SAFETY: The local inbox owns this completed envelope exactly once.
            LowerCompletionEnvelope::reclaim(envelope)
        };
        assert_eq!(completed.suspended, 0x5A);
        assert_eq!(completed.transfer.len(), 16);
        assert_eq!(completed.status, wdk_sys::STATUS_SUCCESS);
        assert_eq!(completed.information, 16);
        unsafe {
            // SAFETY: Reclaim released the envelope's sole lease.
            rundown.close_and_wait();
        }
    }

    /// # Panics
    ///
    /// Panics if pre-submit failures lose the operation or publish the envelope.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn unsubmitted_failures_preserve_operation_ownership() {
        let Ok(rundown) = CompletionRundown::try_new() else {
            return;
        };
        let Ok(Some(lease)) = rundown.acquire() else {
            return;
        };
        let Ok(transfer) = AlignedTransferBuffer::try_zeroed(0, 1) else {
            return;
        };
        assert!(transfer.as_void_ptr().is_null());
        let mut inbox: Option<NonNull<TestEnvelope>> = None;
        let destination = TestCompletionRoute {
            inbox: NonNull::from(&mut inbox),
        };
        let Ok(envelope) = memory::boxed_try_with(move || {
            Ok(LowerCompletionEnvelope::new(
                41_u64,
                transfer,
                destination,
                lease,
            ))
        }) else {
            return;
        };
        assert_eq!(LowerCompletionEnvelope::reclaim_unsubmitted(envelope), 41);
        assert!(inbox.is_none());

        let build = LowerBuildError::from_unsubmitted(DriverError::InvalidParameter, 42_u64);
        assert_eq!(build.into_parts(), (DriverError::InvalidParameter, 42));
        let registration = LowerRegistrationError {
            error: DriverError::InsufficientResources,
            suspended: 43_u64,
        };
        assert_eq!(
            registration.into_parts(),
            (DriverError::InsufficientResources, 43)
        );
        unsafe {
            // SAFETY: Reclaim released the envelope's sole lease.
            rundown.close_and_wait();
        }
    }
}
