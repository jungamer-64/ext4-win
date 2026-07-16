//! Explicit bugcheck boundary for unrecoverable kernel-visible state corruption.

#[cfg(not(test))]
use core::panic::PanicInfo;

/// Bugcheck code spelling `E4BG` for ext4win-owned fatal bugs.
#[cfg(not(test))]
const EXT4WIN_FATAL_BUGCHECK_CODE: u32 = u32::from_be_bytes(*b"E4BG");

/// Unrecoverable inconsistency whose continuation would corrupt Windows kernel-visible state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelWideInconsistency {
    /// Fatal reason visible in bugcheck parameter 1.
    reason: FatalReason,
    /// Source file pointer for diagnostic-only crash dump context.
    file_ptr: usize,
    /// Source file byte length for diagnostic-only crash dump context.
    file_len: usize,
    /// Source line for diagnostic-only crash dump context.
    line: usize,
}

impl KernelWideInconsistency {
    /// Constructs a fatal state for Rust panic reaching the kernel boundary.
    #[cfg(not(test))]
    fn rust_panic_boundary_violation(info: &PanicInfo<'_>) -> Self {
        let location = info.location();
        Self {
            reason: FatalReason::RustPanicBoundaryViolation,
            file_ptr: location.map_or(0, |loc| loc.file().as_ptr().addr()),
            file_len: location.map_or(0, |loc| loc.file().len()),
            line: location
                .and_then(|loc| usize::try_from(loc.line()).ok())
                .unwrap_or(0),
        }
    }

    /// Constructs a fatal state for corrupted published FILE_OBJECT ownership.
    pub(crate) const fn file_object_context_corruption() -> Self {
        Self::without_location(FatalReason::FileObjectContextCorruption)
    }

    /// Constructs a fatal state for an impossible FILE_OBJECT Cleanup/Close transition.
    pub(crate) const fn file_object_lifecycle_corruption() -> Self {
        Self::without_location(FatalReason::FileObjectLifecycleCorruption)
    }

    /// Constructs a fatal state for corrupted VCB-owned FCB ownership.
    pub(crate) const fn file_control_block_ownership_corruption() -> Self {
        Self::without_location(FatalReason::FileControlBlockOwnershipCorruption)
    }

    /// Constructs a fatal state for impossible asynchronous executor ownership.
    pub(crate) const fn async_executor_state_corruption() -> Self {
        Self::without_location(FatalReason::AsyncExecutorStateCorruption)
    }

    /// Constructs a fatal state without source location context.
    const fn without_location(reason: FatalReason) -> Self {
        Self {
            reason,
            file_ptr: 0,
            file_len: 0,
            line: 0,
        }
    }

    /// Stops the system because continuing would corrupt kernel-visible state.
    #[cfg(not(test))]
    pub(crate) fn bugcheck(self) -> ! {
        unsafe {
            // SAFETY: `KeBugCheckEx` is the explicit terminal path for states
            // represented by this type. The parameters are diagnostic payloads
            // only and have no validity preconditions.
            ke_bug_check_ex(
                EXT4WIN_FATAL_BUGCHECK_CODE,
                self.reason.as_parameter(),
                self.file_ptr,
                self.file_len,
                self.line,
            )
        }
    }

    /// Test builds cannot issue a kernel bugcheck.
    /// # Panics
    ///
    /// Always panics because tests cannot execute `KeBugCheckEx`.
    #[cfg(test)]
    #[expect(
        clippy::panic,
        clippy::disallowed_macros,
        reason = "test builds model the non-returning kernel bugcheck boundary with a test panic"
    )]
    pub(crate) fn bugcheck(self) -> ! {
        panic!("kernel-wide inconsistency: {:?}", self.reason)
    }
}

/// Fatal reason encoded into bugcheck parameter 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FatalReason {
    /// Rust panic escaped the normal error-return architecture.
    RustPanicBoundaryViolation,
    /// FILE_OBJECT context pointers no longer describe one coherent opened object.
    FileObjectContextCorruption,
    /// FILE_OBJECT flags and the filesystem-owned handle lifecycle disagree.
    FileObjectLifecycleCorruption,
    /// A VCB-owned FCB pointer is no longer present in the owning VCB table.
    FileControlBlockOwnershipCorruption,
    /// A work item or wake violated the single-poller executor state machine.
    AsyncExecutorStateCorruption,
}

impl FatalReason {
    /// Stable integer payload for crash dump triage.
    const fn as_parameter(self) -> usize {
        match self {
            Self::RustPanicBoundaryViolation => 1,
            Self::FileObjectContextCorruption => 2,
            Self::FileControlBlockOwnershipCorruption => 3,
            Self::FileObjectLifecycleCorruption => 4,
            Self::AsyncExecutorStateCorruption => 5,
        }
    }
}

#[cfg(not(test))]
unsafe extern "system" {
    /// Kernel terminal bugcheck routine.
    #[link_name = "KeBugCheckEx"]
    fn ke_bug_check_ex(
        bug_check_code: u32,
        bug_check_parameter1: usize,
        bug_check_parameter2: usize,
        bug_check_parameter3: usize,
        bug_check_parameter4: usize,
    ) -> !;
}

/// Final guard against unexpected Rust panic reaching the kernel image.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    KernelWideInconsistency::rust_panic_boundary_violation(info).bugcheck()
}

#[cfg(test)]
mod tests {
    use super::{FatalReason, KernelWideInconsistency};

    /// # Panics
    ///
    /// Panics when the fatal reason payloads change unexpectedly.
    #[test]
    fn fatal_reasons_have_stable_bugcheck_parameters() {
        assert_eq!(FatalReason::RustPanicBoundaryViolation.as_parameter(), 1);
        assert_eq!(FatalReason::FileObjectContextCorruption.as_parameter(), 2);
        assert_eq!(
            FatalReason::FileControlBlockOwnershipCorruption.as_parameter(),
            3
        );
        assert_eq!(FatalReason::FileObjectLifecycleCorruption.as_parameter(), 4);
        assert_eq!(FatalReason::AsyncExecutorStateCorruption.as_parameter(), 5);
    }

    /// # Panics
    ///
    /// Panics when the public constructors expose the wrong fatal reason.
    #[test]
    fn fatal_constructors_remain_specific() {
        assert_eq!(
            KernelWideInconsistency::file_object_context_corruption().reason,
            FatalReason::FileObjectContextCorruption
        );
        assert_eq!(
            KernelWideInconsistency::file_object_lifecycle_corruption().reason,
            FatalReason::FileObjectLifecycleCorruption
        );
        assert_eq!(
            KernelWideInconsistency::file_control_block_ownership_corruption().reason,
            FatalReason::FileControlBlockOwnershipCorruption
        );
        assert_eq!(
            KernelWideInconsistency::async_executor_state_corruption().reason,
            FatalReason::AsyncExecutorStateCorruption
        );
    }
}
