//! FsRtl oplock-break delegation and reactor resumption ownership.

use alloc::boxed::Box;
#[cfg(not(test))]
use core::ffi::c_void;
use core::fmt;
#[cfg(not(test))]
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};
#[cfg(not(test))]
use wdk_sys::LIST_ENTRY;
use wdk_sys::{NTSTATUS, STATUS_PENDING};

use crate::state::OplockStreamLease;

use super::OplockCreatePolicy;
#[cfg(not(test))]
use super::lifecycle::DelegatedIrp;
use super::lifecycle::OwnedIrp;
#[cfg(not(test))]
use super::lower::CompletionRundownLease;
use super::reactor::CompletionOperation;
#[cfg(not(test))]
use super::reactor::CompletionReactor;
#[cfg(not(test))]
use super::scheduler::SlotId;
#[cfg(not(test))]
use crate::kernel::fatal::KernelWideInconsistency;
#[cfg(not(test))]
use crate::kernel::ffi;
use crate::kernel::status::DriverError;
#[cfg(not(test))]
use crate::memory;

/// One stream-retaining oplock check prepared before the IRP leaves driver ownership.
#[derive(Debug)]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "host tests cannot execute the WDK-only FsRtl delegation that consumes these fields"
    )
)]
pub(crate) struct OplockCheck {
    /// Stream lifetime authority spanning any asynchronous break wait.
    stream: OplockStreamLease,
    /// FsRtl operation flags derived from decoded request semantics.
    flags: u32,
}

impl OplockCheck {
    /// Builds an ordinary break check for a handle mutation.
    pub(crate) const fn ordinary(stream: OplockStreamLease) -> Self {
        Self { stream, flags: 0 }
    }

    /// Builds the break check selected by an existing-stream create request.
    /// # Errors
    ///
    /// Returns not-supported for policies that require the separate atomic reservation protocol.
    pub(crate) fn create(
        stream: OplockStreamLease,
        policy: OplockCreatePolicy,
    ) -> Result<Self, DriverError> {
        let flags = match policy {
            OplockCreatePolicy::Ordinary => 0,
            OplockCreatePolicy::CompleteIfOplocked => wdk_sys::OPLOCK_FLAG_COMPLETE_IF_OPLOCKED,
            OplockCreatePolicy::RequireUnbrokenOplock | OplockCreatePolicy::ReserveFilter => {
                return Err(DriverError::NotSupported);
            }
        };
        Ok(Self { stream, flags })
    }

    /// Invokes the native SEH boundary with a stable completion envelope.
    /// # Safety
    ///
    /// `irp` must be the live top-level request delegated by the stable `continuation`, and both
    /// must remain valid through synchronous return or the matching FsRtl callbacks.
    #[cfg(not(test))]
    #[expect(
        unsafe_code,
        reason = "the stable envelope and delegated IRP are the audited native oplock-call boundary"
    )]
    unsafe fn submit(&self, irp: NonNull<wdk_sys::IRP>, continuation: NonNull<c_void>) -> NTSTATUS {
        unsafe {
            // SAFETY: The envelope owns this stream lease and delegated IRP until native return or
            // callback publication, and its stable allocation is supplied as `continuation`.
            self.stream
                .stream_context()
                .check_oplock(irp, self.flags, continuation)
        }
    }
}

/// Operation boundary that receives the unique IRP only after FsRtl returns completion routing.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "host tests type-check this boundary but cannot invoke the WDK completion callback"
    )
)]
pub(crate) trait OplockContinuation: fmt::Debug + Send + 'static {
    /// Restores operation state with the exact IRP and machine-readable oplock result.
    fn resume_after_oplock(
        self: Box<Self>,
        owned: OwnedIrp,
        status: NTSTATUS,
    ) -> Box<dyn CompletionOperation>;
}

/// Stable envelope has not entered either FsRtl callback.
const OPLOCK_PREPARED: u8 = 0;
/// FsRtl invoked pre-post and owns the queued IRP.
const OPLOCK_POSTED: u8 = 1;
/// The unique completion callback is publishing its result.
const OPLOCK_COMPLETION_CLAIMED: u8 = 2;
/// Status publication is complete and reactor reclamation is legal.
const OPLOCK_COMPLETED: u8 = 3;

/// Atomic callback protocol shared by the FsRtl call site, callbacks, and reactor.
#[derive(Debug)]
struct OplockCallbackProtocol {
    /// PREPARED -> POSTED -> COMPLETION_CLAIMED -> COMPLETED.
    state: AtomicU8,
    /// Exact IRP status published before the completed state becomes observable.
    status: AtomicI32,
}

impl OplockCallbackProtocol {
    /// Creates one callback protocol before any native effect can occur.
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(OPLOCK_PREPARED),
            status: AtomicI32::new(STATUS_PENDING),
        }
    }

    /// Publishes the unique pre-post callback before FsRtl queues the IRP.
    fn mark_posted(&self) -> bool {
        self.state
            .compare_exchange(
                OPLOCK_PREPARED,
                OPLOCK_POSTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Publishes one completion status only after the matching pre-post callback.
    fn mark_completed(&self, status: NTSTATUS) -> bool {
        if self
            .state
            .compare_exchange(
                OPLOCK_POSTED,
                OPLOCK_COMPLETION_CLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.status.store(status, Ordering::Relaxed);
        self.state.store(OPLOCK_COMPLETED, Ordering::Release);
        true
    }

    /// Reports whether native submission returned without invoking either callback.
    fn is_prepared(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPLOCK_PREPARED
    }

    /// Reports whether FsRtl published the pre-post boundary for a pending return.
    fn was_posted(&self) -> bool {
        matches!(
            self.state.load(Ordering::Acquire),
            OPLOCK_POSTED | OPLOCK_COMPLETION_CLAIMED | OPLOCK_COMPLETED
        )
    }

    /// Returns the exact completion status only after its release publication.
    fn completed_status(&self) -> Option<NTSTATUS> {
        (self.state.load(Ordering::Acquire) == OPLOCK_COMPLETED)
            .then(|| self.status.load(Ordering::Relaxed))
    }
}

/// Allocation failure that preserves all pre-effect ownership values.
#[cfg(not(test))]
pub(super) struct OplockPreparationError {
    /// Exact allocation failure.
    error: DriverError,
    /// Check that never reached FsRtl.
    check: OplockCheck,
    /// IRP whose driver completion authority was never delegated.
    owned: OwnedIrp,
    /// Operation waiting for the check result.
    suspended: Box<dyn OplockContinuation>,
}

#[cfg(not(test))]
impl OplockPreparationError {
    /// Recovers the exact allocation failure and every unconsumed authority.
    pub(super) fn into_parts(
        self,
    ) -> (
        DriverError,
        OplockCheck,
        OwnedIrp,
        Box<dyn OplockContinuation>,
    ) {
        (self.error, self.check, self.owned, self.suspended)
    }
}

/// Result of submitting one stable envelope to FsRtl.
#[cfg(not(test))]
pub(super) enum OplockSubmission {
    /// FsRtl returned synchronously and the actor still owns the envelope.
    Immediate {
        /// Stable envelope whose delegated IRP can be reclaimed immediately.
        envelope: Box<OplockEnvelope>,
        /// Exact non-pending status returned by FsRtl.
        status: NTSTATUS,
    },
    /// FsRtl owns the raw envelope until its wait-completion callback publishes it.
    Pending,
}

/// Non-owning cancellation identity published only while FsRtl retains an oplock wait.
#[cfg(not(test))]
#[derive(Clone, Copy)]
pub(super) struct PublishedOplockRequest {
    /// Stable continuation allocation used to validate slot detachment.
    envelope: NonNull<OplockEnvelope>,
    /// Exact top-level IRP whose cancel routine is temporarily owned by FsRtl.
    irp: NonNull<wdk_sys::IRP>,
}

#[cfg(not(test))]
impl fmt::Debug for PublishedOplockRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublishedOplockRequest(..)")
    }
}

#[cfg(not(test))]
impl PublishedOplockRequest {
    /// Reports whether this slot payload names the completed stable continuation.
    pub(super) fn identifies(self, envelope: NonNull<OplockEnvelope>) -> bool {
        self.envelope == envelope
    }

    /// Asks the I/O Manager to invoke the FsRtl-owned cancel routine for this exact IRP.
    /// # Safety
    ///
    /// The active `Phase::Oplock` slot must still retain this publication and its envelope.
    #[expect(
        unsafe_code,
        reason = "the active slot retains the exact top-level IRP through the FsRtl wait"
    )]
    pub(super) unsafe fn cancel(self) {
        let _cancel_was_observed = unsafe {
            // SAFETY: The FsRtl wait retains this top-level IRP until its completion callback.
            ffi::IoCancelIrp(self.irp.as_ptr())
        };
    }
}

/// Stable oplock continuation transferred actor -> FsRtl -> reactor inbox.
#[cfg(not(test))]
#[repr(C)]
pub(super) struct OplockEnvelope {
    /// First-field intrusive node used only after wait completion.
    node: LIST_ENTRY,
    /// Reactor retained by `rundown` until inbox reclamation.
    reactor: NonNull<CompletionReactor>,
    /// Exact bounded slot generation that submitted this check.
    identity: SlotId,
    /// Completion destination lifetime authority.
    rundown: CompletionRundownLease,
    /// Stream-owned oplock and its deferred lifetime lease.
    check: Option<OplockCheck>,
    /// Driver completion authority retained until the native call starts.
    owned: Option<OwnedIrp>,
    /// Context retained without completion authority while FsRtl owns the IRP.
    delegated: Option<DelegatedIrp>,
    /// Operation resumed only after exact IRP ownership returns.
    suspended: Option<Box<dyn OplockContinuation>>,
    /// Exact callback state and `IRP.IoStatus.Status` publication.
    callback: OplockCallbackProtocol,
}

#[cfg(not(test))]
impl fmt::Debug for OplockEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OplockEnvelope")
            .field("identity", &self.identity)
            .field("callback", &self.callback)
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "the stable envelope is the audited IRP ownership bridge into the FsRtl oplock package"
)]
impl OplockEnvelope {
    /// Allocates every continuation value before an oplock break can be initiated.
    /// # Errors
    ///
    /// Returns the allocation failure together with every unconsumed pre-effect authority.
    pub(super) fn try_new(
        reactor: NonNull<CompletionReactor>,
        identity: SlotId,
        check: OplockCheck,
        owned: OwnedIrp,
        suspended: Box<dyn OplockContinuation>,
        rundown: CompletionRundownLease,
    ) -> Result<Box<Self>, OplockPreparationError> {
        memory::boxed_try_map(
            (check, owned, suspended, rundown),
            |(check, owned, suspended, rundown)| Self {
                node: LIST_ENTRY::default(),
                reactor,
                identity,
                rundown,
                check: Some(check),
                owned: Some(owned),
                delegated: None,
                suspended: Some(suspended),
                callback: OplockCallbackProtocol::new(),
            },
        )
        .map_err(|failure| {
            let (error, (check, owned, suspended, _rundown)) = failure.into_parts();
            OplockPreparationError {
                error,
                check,
                owned,
                suspended,
            }
        })
    }

    /// Reclaims a fully allocated envelope before its oplock-break effect boundary.
    #[expect(
        clippy::boxed_local,
        reason = "the Box owns the stable address prepared for the native callback"
    )]
    pub(super) fn cancel_before_submit(
        mut envelope: Box<Self>,
    ) -> (OplockCheck, OwnedIrp, Box<dyn OplockContinuation>) {
        if !envelope.callback.is_prepared() || envelope.delegated.is_some() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        let check = envelope.check.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let owned = envelope.owned.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let suspended = envelope.suspended.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        (check, owned, suspended)
    }

    /// Creates the slot's non-owning cancellation identity before native delegation begins.
    pub(super) fn publication(&self) -> PublishedOplockRequest {
        let owned = self.owned.as_ref().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        PublishedOplockRequest {
            envelope: NonNull::from(self),
            irp: owned.external_irp_identity(),
        }
    }

    /// Removes driver cancel authority, transfers the stable allocation, and calls FsRtl once.
    pub(super) fn submit(mut envelope: Box<Self>) -> OplockSubmission {
        let owned = envelope.owned.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let delegated = owned.delegate_to_fsrtl();
        let irp = delegated.irp();
        envelope.delegated = Some(delegated);
        let raw = Box::into_raw(envelope);
        let continuation = NonNull::new(raw.cast::<c_void>()).unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let check = unsafe {
            // SAFETY: `raw` is the live stable box just transferred above.
            (*raw).check.as_ref()
        }
        .unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let status = unsafe {
            // SAFETY: The stable box retains the check, delegated IRP, continuation, and rundown
            // through native return or callback publication.
            check.submit(irp, continuation)
        };
        if status == STATUS_PENDING {
            let was_posted = unsafe {
                // SAFETY: `raw` remains owned by FsRtl or the queued completion envelope here.
                (*raw).callback.was_posted()
            };
            if !was_posted {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
            return OplockSubmission::Pending;
        }
        let envelope = unsafe {
            // SAFETY: A non-pending return retains caller ownership and invokes neither callback.
            Box::from_raw(raw)
        };
        if !envelope.callback.is_prepared() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        OplockSubmission::Immediate { envelope, status }
    }

    /// Returns the embedded inbox node address.
    pub(super) fn node_ptr(&self) -> *mut LIST_ENTRY {
        core::ptr::addr_of!(self.node).cast_mut()
    }

    /// Recovers an envelope from its first-field intrusive node.
    /// # Safety
    ///
    /// `node` must have been removed exactly once from the oplock-completion inbox.
    pub(super) unsafe fn from_node(node: NonNull<LIST_ENTRY>) -> NonNull<Self> {
        node.cast()
    }

    /// Returns the exact scheduler identity retained across FsRtl ownership.
    pub(super) const fn identity(&self) -> SlotId {
        self.identity
    }

    /// Reclaims an immediate non-pending return into driver ownership.
    pub(super) fn reclaim_immediate(
        envelope: Box<Self>,
        status: NTSTATUS,
    ) -> (OwnedIrp, Box<dyn OplockContinuation>, NTSTATUS) {
        Self::reclaim(envelope, OPLOCK_PREPARED, status)
    }

    /// Reclaims a wait-completion callback publication into driver ownership.
    pub(super) fn reclaim_completed(
        envelope: Box<Self>,
    ) -> (OwnedIrp, Box<dyn OplockContinuation>, NTSTATUS) {
        let status = envelope.callback.completed_status().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        Self::reclaim(envelope, OPLOCK_COMPLETED, status)
    }

    /// Consumes one callback state and returns the exact driver-owned IRP continuation.
    #[expect(
        clippy::boxed_local,
        reason = "consuming the stable callback allocation is the unique deallocation authority"
    )]
    fn reclaim(
        mut envelope: Box<Self>,
        expected_state: u8,
        status: NTSTATUS,
    ) -> (OwnedIrp, Box<dyn OplockContinuation>, NTSTATUS) {
        let state_matches = match expected_state {
            OPLOCK_PREPARED => envelope.callback.is_prepared(),
            OPLOCK_COMPLETED => envelope.callback.completed_status().is_some(),
            _ => false,
        };
        if !state_matches || envelope.owned.is_some() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        drop(envelope.check.take());
        let delegated = envelope.delegated.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        let suspended = envelope.suspended.take().unwrap_or_else(|| {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
        });
        (delegated.reclaim(), suspended, status)
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "ownership is transferred exclusively between actor, FsRtl callbacks, and reactor inbox"
)]
// SAFETY: All callback-shared mutation is atomic; non-atomic fields are consumed only after the
// matching ownership transfer and completion-inbox removal.
unsafe impl Send for OplockEnvelope {}

/// Records that FsRtl is about to queue this exact top-level IRP for an oplock break.
/// # Safety
///
/// `context` must be the stable envelope passed to FsRtl for this exact live `irp`, and FsRtl may
/// invoke this callback exactly once before queueing it.
#[cfg(not(test))]
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FsRtl returns the exact stable continuation pointer and delegated IRP"
)]
pub unsafe extern "system" fn ext4win_oplock_prepost(context: *mut c_void, irp: wdk_sys::PIRP) {
    let envelope = NonNull::new(context.cast::<OplockEnvelope>()).unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    let envelope = unsafe {
        // SAFETY: FsRtl invokes this before queuing the still-live stable continuation.
        envelope.as_ref()
    };
    let delegated = envelope.delegated.as_ref().unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    if irp != delegated.irp().as_ptr() || !envelope.callback.mark_posted() {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
}

/// Returns one posted IRP to the reactor after the oplock break wait finishes or is cancelled.
/// # Safety
///
/// `context` must be the posted stable envelope for this exact live `irp`, and FsRtl may invoke
/// this callback exactly once after it has retired its wait/cancel ownership.
#[cfg(not(test))]
#[unsafe(no_mangle)]
#[expect(
    unsafe_code,
    reason = "FsRtl returns the exact stable continuation pointer and delegated IRP"
)]
pub unsafe extern "system" fn ext4win_oplock_wait_complete(
    context: *mut c_void,
    irp: wdk_sys::PIRP,
) {
    let envelope = NonNull::new(context.cast::<OplockEnvelope>()).unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    let envelope = unsafe {
        // SAFETY: FsRtl uniquely owns the stable continuation until this completion callback.
        envelope.as_ref()
    };
    let delegated = envelope.delegated.as_ref().unwrap_or_else(|| {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck()
    });
    if irp != delegated.irp().as_ptr() {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
    let irp = unsafe {
        // SAFETY: Equality with the delegated non-null identity was established above.
        &*irp
    };
    let status = unsafe {
        // SAFETY: FsRtl completed the status arm before invoking this completion callback.
        irp.IoStatus.__bindgen_anon_1.Status
    };
    if !envelope.callback.mark_completed(status) {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    }
    let reactor = unsafe {
        // SAFETY: The envelope's rundown lease retains this stable completion destination.
        envelope.reactor.as_ref()
    };
    unsafe {
        // SAFETY: Callback transfers its unique completed, unlinked envelope to the reactor.
        reactor.enqueue_oplock_completion(NonNull::from(envelope));
    }
}

#[cfg(test)]
mod tests {
    use super::OplockCallbackProtocol;

    /// # Panics
    ///
    /// Panics if callback publication can complete out of order, duplicate a callback, or lose
    /// the exact machine-readable status.
    #[test]
    fn callback_protocol_is_single_path_and_status_preserving() {
        let protocol = OplockCallbackProtocol::new();
        assert!(protocol.is_prepared());
        assert!(protocol.completed_status().is_none());
        assert!(!protocol.mark_completed(wdk_sys::STATUS_CANCELLED));

        assert!(protocol.mark_posted());
        assert!(protocol.was_posted());
        assert!(!protocol.mark_posted());
        assert!(protocol.mark_completed(wdk_sys::STATUS_CANCELLED));
        assert_eq!(protocol.completed_status(), Some(wdk_sys::STATUS_CANCELLED));
        assert!(!protocol.mark_completed(wdk_sys::STATUS_SUCCESS));
    }
}
