//! Requestor attribution is captured before queueing; a reactor slot retains it through all I/O.

use super::super::ActiveIrp;
use crate::irp::lower::PhysicalIo;
use core::{ffi::c_void, ptr::NonNull};

/// Optional driver-owned process charge authority. Cc retains responsibility for its nested paging.
#[derive(Debug)]
pub(crate) struct DiskAccounting {
    /// One referenced process; no actor-thread fallback may recreate this request's origin.
    process: Option<ReferencedProcess>,
}

impl DiskAccounting {
    /// Captures the original dispatch thread's accounting responsibility and process reference.
    #[expect(
        unsafe_code,
        reason = "the original dispatch owns this IRP and captures one native process reference"
    )]
    pub(super) fn capture(target: &ActiveIrp<'_>) -> Self {
        let process = unsafe {
            // SAFETY: Capture runs in the issuing thread before any queue/actor transfer.
            ext4win_capture_disk_process(target.irp.as_ptr())
        };
        Self {
            process: NonNull::new(process).map(ReferencedProcess),
        }
    }

    /// Allocation-free CLEANUP/CLOSE retain only the IRP's own original process identity.
    #[expect(
        unsafe_code,
        reason = "the owned lifecycle IRP retains its associated requestor while one native reference is acquired"
    )]
    pub(super) fn capture_lifecycle(target: &ActiveIrp<'_>) -> Self {
        let process = unsafe {
            // SAFETY: This helper never substitutes the current actor or its thread.
            ext4win_capture_lifecycle_disk_process(target.irp.as_ptr())
        };
        Self {
            process: NonNull::new(process).map(ReferencedProcess),
        }
    }

    /// Records one successfully registered physical transfer immediately before lower submission.
    #[expect(
        unsafe_code,
        reason = "the slot retains its referenced process through this infallible native accounting call"
    )]
    pub(crate) fn record(&self, transfer: PhysicalIo) {
        if let Some(process) = &self.process {
            let (read, written, flush) = match transfer {
                PhysicalIo::Read(bytes) => (u64::from(bytes), 0, 0),
                PhysicalIo::Write(bytes) => (0, u64::from(bytes), 0),
                PhysicalIo::Flush => (0, 0, 1),
                PhysicalIo::Control => return,
            };
            unsafe {
                // SAFETY: This owner retains the process; these counts describe the prepared lower transfer.
                ext4win_account_process_io(process.0.as_ptr(), read, written, flush);
            }
        }
    }
}

/// Object Manager reference, independent from both the originating thread and upper acknowledgment.
#[derive(Debug)]
struct ReferencedProcess(NonNull<c_void>);

#[expect(
    unsafe_code,
    reason = "Object Manager process references may be moved between actor and worker threads"
)]
// SAFETY: The pointer is used only by thread-independent native accounting and dereference DDIs.
unsafe impl Send for ReferencedProcess {}

#[expect(
    unsafe_code,
    reason = "this unique owner releases the reference returned by native capture"
)]
impl Drop for ReferencedProcess {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: Capture transferred one live Object Manager reference to this owner.
            crate::kernel::ffi::ObfDereferenceObject(self.0.as_ptr());
        }
    }
}

#[expect(
    unsafe_code,
    reason = "native capture transfers a process reference and accounting borrows it"
)]
unsafe extern "system" {
    fn ext4win_capture_disk_process(irp: wdk_sys::PIRP) -> *mut c_void;
    fn ext4win_capture_lifecycle_disk_process(irp: wdk_sys::PIRP) -> *mut c_void;
    fn ext4win_account_process_io(process: *mut c_void, read: u64, written: u64, flush: u32);
}
