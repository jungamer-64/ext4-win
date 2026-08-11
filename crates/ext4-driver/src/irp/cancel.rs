//! Address-stable active top-level IRP cancellation envelopes.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::NonNull;

#[cfg(not(test))]
use wdk_sys::{PDEVICE_OBJECT, PIRP};

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
    pub(crate) unsafe fn install(irp: PIRP, envelope: NonNull<ActiveCancelEnvelope>) -> Self {
        let Some(mut irp_address) = NonNull::new(irp) else {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        };
        let mut old_irql = 0;
        unsafe {
            // SAFETY: Standard cancel-routine installation is serialized by the global cancel lock.
            ffi::IoAcquireCancelSpinLock(core::ptr::addr_of_mut!(old_irql));
        }
        let irp_ref = unsafe {
            // SAFETY: Exclusive IRP ownership and the cancel lock permit context publication.
            irp_address.as_mut()
        };
        let context = active_cancel_context(irp_ref);
        if !context.is_null() {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *context = envelope.as_ptr().cast::<c_void>();
        let cancelled = irp_ref.Cancel != 0;
        if !cancelled {
            let previous = unsafe {
                // SAFETY: The cancel spin lock is held and no earlier active routine exists.
                ffi::ext4win_set_cancel_routine(irp, Some(active_irp_cancelled))
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
    fn drop(&mut self) {
        let mut old_irql = 0;
        unsafe {
            // SAFETY: Terminal ownership still retains the live IRP until this drop returns.
            ffi::IoAcquireCancelSpinLock(core::ptr::addr_of_mut!(old_irql));
        }
        let _previous = unsafe {
            // SAFETY: The cancel spin lock excludes routine selection while authority is removed.
            ffi::ext4win_set_cancel_routine(self.irp.as_ptr(), None)
        };
        let irp = unsafe {
            // SAFETY: Terminal ownership and the cancel spin lock permit context removal.
            self.irp.as_mut()
        };
        let context = active_cancel_context(irp);
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

// SAFETY: The token is moved only with its uniquely owned top-level IRP.
#[cfg(not(test))]
unsafe impl Send for ActiveCancellation {}

/// Returns the driver-owned active-cancel context slot.
#[cfg(not(test))]
fn active_cancel_context(irp: &mut wdk_sys::IRP) -> &mut *mut c_void {
    let overlay = unsafe {
        // SAFETY: `DriverContext` and list linkage occupy independent tail-overlay fields.
        &mut irp.Tail.Overlay
    };
    let driver_storage = unsafe {
        // SAFETY: This is the bindgen arm containing the four documented DriverContext slots.
        &mut overlay.__bindgen_anon_1.__bindgen_anon_1
    };
    &mut driver_storage.DriverContext[1]
}

/// Native top-level cancel routine: publish one event and release the cancel spin lock immediately.
/// # Safety
///
/// The I/O Manager invokes this only for an IRP installed by [`ActiveCancellation::install`].
#[cfg(not(test))]
unsafe extern "C" fn active_irp_cancelled(_device: PDEVICE_OBJECT, irp: PIRP) {
    let Some(irp_address) = NonNull::new(irp) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    let irp_ref = unsafe {
        // SAFETY: The I/O Manager invokes the routine with the IRP and cancel spin lock held.
        irp_address.as_ref()
    };
    let context = {
        let overlay = unsafe {
            // SAFETY: Active cancellation retains the driver-context arm until token removal.
            &irp_ref.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: This is the bindgen arm containing the four DriverContext slots.
            &overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        driver_storage.DriverContext[1]
    };
    let Some(envelope) = NonNull::new(context.cast::<ActiveCancelEnvelope>()) else {
        KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
    };
    unsafe {
        // SAFETY: ActiveCancellation retains this stable slot envelope until callback completion.
        envelope.as_ref()
    }
    .publish();
    unsafe {
        // SAFETY: Cancel routines must release the I/O Manager-held lock using this IRP's IRQL.
        ffi::IoReleaseCancelSpinLock(irp_ref.CancelIrql);
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{ActiveCancelDestination, ActiveCancelEnvelope};

    unsafe fn record_cancel(context: NonNull<c_void>, index: usize) {
        let counter = unsafe {
            // SAFETY: The test destination points to this live `AtomicUsize` for the whole call.
            context.cast::<AtomicUsize>().as_ref()
        };
        counter.store(index + 1, Ordering::Release);
    }

    /// # Panics
    ///
    /// Panics if an address-stable cancel envelope publishes anything except its fixed slot.
    #[test]
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
