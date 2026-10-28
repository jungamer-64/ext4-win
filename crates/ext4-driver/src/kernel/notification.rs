//! Level-triggered notifications projected under their owning lifecycle lock.

#[cfg(not(test))]
use core::cell::UnsafeCell;

/// Manual-reset notification; host tests exercise the same set/reset/wait protocol as the kernel.
pub(super) struct AdmissionNotification {
    /// Initialized only after the retaining shared allocation reaches its final address.
    #[cfg(not(test))]
    event: UnsafeCell<wdk_sys::KEVENT>,
    /// Host event state, independent of the admission predicate just as a native event is.
    #[cfg(test)]
    signaled: std::sync::Mutex<bool>,
    /// Host event notification, retained with its state through every waiter.
    #[cfg(test)]
    changed: std::sync::Condvar,
}

impl AdmissionNotification {
    /// Constructs unpublished storage without exposing an uninitialized native event.
    pub(super) fn new() -> Self {
        Self {
            #[cfg(not(test))]
            event: UnsafeCell::new(wdk_sys::KEVENT::default()),
            #[cfg(test)]
            signaled: std::sync::Mutex::new(true),
            #[cfg(test)]
            changed: std::sync::Condvar::new(),
        }
    }

    /// Initializes the final-address event before the stream or mutation owner is published.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "unpublished shared storage retains the final event address"
        )
    )]
    pub(super) fn initialize(&self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: The constructor owns final-address storage with no callbacks or waiters.
            super::ffi::KeInitializeEvent(
                self.event.get(),
                wdk_sys::_EVENT_TYPE::NotificationEvent,
                1,
            );
        }
    }

    /// Projects one admission predicate while its phase transition lock is held.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the retaining owner serializes event projection with phase transitions"
        )
    )]
    pub(super) fn publish(&self, signaled: bool) {
        #[cfg(not(test))]
        if signaled {
            unsafe {
                // SAFETY: The shared owner retains this initialized event under its transition lock.
                super::ffi::KeSetEvent(self.event.get(), 0, 0);
            }
        } else {
            unsafe {
                // SAFETY: The same transition lock serializes reset against notification publication.
                wdk_sys::ntddk::KeClearEvent(self.event.get());
            }
        }
        #[cfg(test)]
        {
            let mut state = self.signaled.lock().unwrap_or_else(|_| corruption());
            *state = signaled;
            if signaled {
                self.changed.notify_all();
            }
        }
    }

    /// Waits on event state even when the caller's predicate observation preceded a transition.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "the callback retains the initialized notification through its nonalertable wait"
        )
    )]
    pub(super) fn wait(&self) {
        #[cfg(not(test))]
        {
            let status = unsafe {
                // SAFETY: The shared owner retains nonpaged event storage until this waiter returns.
                super::ffi::KeWaitForSingleObject(
                    self.event.get().cast(),
                    wdk_sys::_KWAIT_REASON::Executive,
                    0,
                    0,
                    core::ptr::null_mut(),
                )
            };
            if status != wdk_sys::STATUS_SUCCESS {
                corruption();
            }
        }
        #[cfg(test)]
        {
            let mut state = self.signaled.lock().unwrap_or_else(|_| corruption());
            while !*state {
                state = self.changed.wait(state).unwrap_or_else(|_| corruption());
            }
        }
    }
}

/// A failed wait or poisoned host projection cannot preserve the lifecycle protocol.
fn corruption() -> ! {
    super::fatal::KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck()
}
