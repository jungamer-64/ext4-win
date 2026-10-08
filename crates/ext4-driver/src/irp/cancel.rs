//! Address-stable active top-level IRP cancellation envelopes.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::NonNull;

#[cfg(not(test))]
use wdk_sys::{PDEVICE_OBJECT, PIRP};

#[cfg(not(test))]
use super::KernelIrp;
use crate::kernel::fatal::KernelWideInconsistency;
#[cfg(not(test))]
use crate::kernel::ffi;

/// Allocation-free callback destination installed before an active cancel routine is visible.
#[derive(Clone, Copy)]
pub(crate) struct ActiveCancelDestination {
    /// Stable reactor context.
    context: NonNull<c_void>,
    /// Callback that publishes one fixed slot's concrete cancel event.
    publish: unsafe fn(NonNull<c_void>, usize),
}

impl ActiveCancelDestination {
    /// Binds one stable reactor destination.
    /// # Safety
    ///
    /// `context` must remain live until every cancellation token using this destination is dropped.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) const unsafe fn new(
        context: NonNull<c_void>,
        publish: unsafe fn(NonNull<c_void>, usize),
    ) -> Self {
        Self { context, publish }
    }
}

/// One fixed nonpaged cancellation envelope for a bounded reactor slot.
pub(crate) struct ActiveCancelEnvelope {
    /// Destination initialized only after the containing reactor reaches its final address.
    destination: UnsafeCell<Option<ActiveCancelDestination>>,
    /// Fixed reactor slot index.
    index: usize,
}

impl ActiveCancelEnvelope {
    /// Creates an inert envelope before final-address initialization.
    pub(crate) const fn inert(index: usize) -> Self {
        Self {
            destination: UnsafeCell::new(None),
            index,
        }
    }

    /// Installs the immutable callback destination at the envelope's final address.
    /// # Safety
    ///
    /// This must run exactly once before the containing device is published.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn initialize(&self, destination: ActiveCancelDestination) {
        let slot = unsafe {
            // SAFETY: Device initialization has exclusive access before callback publication.
            &mut *self.destination.get()
        };
        if slot.is_some() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *slot = Some(destination);
    }

    /// Publishes this envelope's sole concrete cancel event without allocation or blocking.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn publish(&self) {
        let destination = unsafe {
            // SAFETY: Initialization precedes cancel-routine installation and never mutates later.
            *self.destination.get()
        };
        let Some(destination) = destination else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        unsafe {
            // SAFETY: The containing reactor remains live under active top-level IRP ownership.
            (destination.publish)(destination.context, self.index);
        }
    }
}

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Initialization happens-before device publication; the destination is immutable later.
unsafe impl Sync for ActiveCancelEnvelope {}

/// Installed cancel-routine authority tied to one top-level IRP and fixed envelope.
#[cfg(not(test))]
#[derive(Debug)]
pub(crate) struct ActiveCancellation {
    /// Top-level IRP whose cancel routine/context must be removed before terminal completion.
    irp: NonNull<wdk_sys::IRP>,
    /// Stable envelope named from `DriverContext[1]` by the callback.
    envelope: NonNull<ActiveCancelEnvelope>,
}

#[cfg(not(test))]
impl ActiveCancellation {
    /// Installs a cancel routine or publishes an already-requested cancel before returning.
    /// # Safety
    ///
    /// The caller must exclusively own an IRP removed from its CSQ, and `envelope` must remain
    /// stable until this returned token is dropped.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    pub(crate) unsafe fn install(irp: PIRP, envelope: NonNull<ActiveCancelEnvelope>) -> Self {
        let Some(irp_address) = NonNull::new(irp) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let mut old_irql = 0;
        unsafe {
            // SAFETY: Standard cancel-routine installation is serialized by the global cancel lock.
            ffi::IoAcquireCancelSpinLock(core::ptr::addr_of_mut!(old_irql));
        }
        let context = unsafe {
            // SAFETY: The live IRP and cancel lock retain the active driver context slot.
            active_cancel_context(irp_address)
        };
        let context = unsafe {
            // SAFETY: The cancel lock and exclusive installation own only this context slot.
            &mut *context
        };
        if !context.is_null() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *context = envelope.as_ptr().cast::<c_void>();
        let cancelled = unsafe {
            // SAFETY: The global cancel lock excludes mutation of this live cancel flag.
            (*irp).Cancel != 0
        };
        if !cancelled {
            let previous = unsafe {
                // SAFETY: The cancel spin lock is held and no earlier active routine exists.
                ffi::IoSetCancelRoutine(irp, Some(active_irp_cancelled))
            };
            if previous.is_some() {
                KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
            }
        }
        unsafe {
            // SAFETY: Releases the exact acquisition above after routine/context publication.
            ffi::IoReleaseCancelSpinLock(old_irql);
        }
        if cancelled {
            unsafe {
                // SAFETY: The caller-provided stable envelope is initialized before installation.
                envelope.as_ref()
            }
            .publish();
        }
        Self {
            irp: irp_address,
            envelope,
        }
    }
}

#[cfg(not(test))]
impl Drop for ActiveCancellation {
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn drop(&mut self) {
        let mut old_irql = 0;
        unsafe {
            // SAFETY: Terminal ownership still retains the live IRP until this drop returns.
            ffi::IoAcquireCancelSpinLock(core::ptr::addr_of_mut!(old_irql));
        }
        let _previous = unsafe {
            // SAFETY: The cancel spin lock excludes routine selection while authority is removed.
            ffi::IoSetCancelRoutine(self.irp.as_ptr(), None)
        };
        let context = unsafe {
            // SAFETY: Terminal ownership and the cancel lock retain this context slot.
            active_cancel_context(self.irp)
        };
        let context = unsafe {
            // SAFETY: The cancel spin lock grants sole access to the active context slot.
            &mut *context
        };
        if !core::ptr::eq(
            (*context).cast_const(),
            self.envelope.as_ptr().cast_const().cast(),
        ) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *context = core::ptr::null_mut();
        unsafe {
            // SAFETY: Releases the exact acquisition above before IRP completion/delegation.
            ffi::IoReleaseCancelSpinLock(old_irql);
        }
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The token is moved only with its uniquely owned top-level IRP.
unsafe impl Send for ActiveCancellation {}

/// Returns the driver-owned active-cancel context slot.
/// # Safety
/// The pointer must identify a live IRP whose driver-context union arm has been initialized.
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe fn active_cancel_context(irp: NonNull<wdk_sys::IRP>) -> *mut *mut c_void {
    let slots = KernelIrp { irp }
        .driver_context_slots()
        .cast::<*mut c_void>();
    unsafe {
        // SAFETY: The caller retains this initialized arm; computing the slot address creates no
        // reference to independently accessed cancellation, completion or queue-linkage fields.
        slots.add(1).as_ptr()
    }
}

/// Native top-level cancel routine: publish one event and release the cancel spin lock immediately.
/// # Safety
///
/// The I/O Manager invokes this only for an IRP installed by [`ActiveCancellation::install`].
#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
unsafe extern "C" fn active_irp_cancelled(_device: PDEVICE_OBJECT, irp: PIRP) {
    let Some(irp_address) = NonNull::new(irp) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let context = unsafe {
        // SAFETY: Installed cancellation retains the live IRP and initialized driver slots.
        active_cancel_context(irp_address)
    };
    let context = unsafe {
        // SAFETY: The I/O Manager-held cancel spin lock retains the published envelope pointer.
        context.read()
    };
    let Some(envelope) = NonNull::new(context.cast::<ActiveCancelEnvelope>()) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: ActiveCancellation retains this stable slot envelope until callback completion.
        envelope.as_ref()
    }
    .publish();
    let cancel_irql = unsafe {
        // SAFETY: The I/O Manager initialized this field and holds the cancel lock through entry.
        (*irp).CancelIrql
    };
    unsafe {
        // SAFETY: Cancel routines release the I/O Manager-held lock using its initialized IRQL.
        ffi::IoReleaseCancelSpinLock(cancel_irql);
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{ActiveCancelDestination, ActiveCancelEnvelope};

    /// Records one published slot in the test destination.
    /// # Safety
    ///
    /// `context` must point to a live, uniquely writable `AtomicUsize` for this call.
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    unsafe fn record_cancel(context: NonNull<c_void>, index: usize) {
        let counter = unsafe {
            // SAFETY: The test destination points to this live `AtomicUsize` for the whole call.
            context.cast::<AtomicUsize>().as_ref()
        };
        let recorded = index.saturating_add(1);
        counter.store(recorded, Ordering::Release);
    }

    /// # Panics
    ///
    /// Panics if an address-stable cancel envelope publishes anything except its fixed slot.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn stable_envelope_publishes_exact_slot_without_allocation() {
        let observed = AtomicUsize::new(0);
        let envelope = ActiveCancelEnvelope::inert(17);
        let destination = unsafe {
            // SAFETY: `observed` remains live and address-stable until publication returns.
            ActiveCancelDestination::new(NonNull::from(&observed).cast(), record_cancel)
        };
        unsafe {
            // SAFETY: This is the envelope's sole initialization before publication.
            envelope.initialize(destination);
        }
        envelope.publish();
        assert_eq!(observed.load(Ordering::Acquire), 18);
    }
}
