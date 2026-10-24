//! A mounted actor owns periodic admission and joins every started scan to a terminal outcome.
use super::*;

/// Absolute host-monotonic deadline; this observation grants no media or allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AutomaticTrimDeadline {
    /// Milliseconds in the same host clock domain as actor timer observations.
    millis: u64,
}
impl AutomaticTrimDeadline {
    /// Converts only within the host-monotonic clock domain; an elapsed deadline is immediately due.
    pub(crate) const fn remaining_millis(self, now_millis: u64) -> u64 {
        self.millis.saturating_sub(now_millis)
    }
    /// Selects the next cycle relative to completion, without overlapping or catching up missed runs.
    fn next(now_millis: u64) -> Option<Self> {
        now_millis.checked_add(60_000).map(|millis| Self { millis })
    }
}

/// Unique completion obligation for the mounted actor's one running automatic scan.
/// It grants no filesystem write authority; every physical batch requires core admission.
#[derive(Debug)]
pub(crate) struct AutomaticTrimRun {
    /// Construction stays inside this state machine, with no duplication or re-entry route.
    _completion: (),
}

/// Only a completed successful cycle can schedule a successor; stopped effects are never retried.
#[derive(Debug)]
pub(super) enum AutomaticTrimState {
    /// Policy is disabled or this session has immutable read-only media authority.
    Disabled,
    /// No operation is live; its next cycle may be admitted at this deadline.
    Waiting(AutomaticTrimDeadline),
    /// The scheduler owns exactly one non-cloneable completion obligation.
    Running,
    /// Future admission is revoked while the scheduler still owes physical completion.
    Stopping,
    /// Failure, uncertainty, cancellation or shutdown permanently ended this mount's schedule.
    Stopped,
}
impl AutomaticTrimState {
    /// Fixes scheduling policy once with the mount's media authority.
    pub(super) fn new(
        policy: ext4_control::AutomaticTrim,
        access: ext4_core::MediaAccess,
        now_millis: u64,
    ) -> Self {
        if policy == ext4_control::AutomaticTrim::Disabled
            || access == ext4_core::MediaAccess::ReadOnly
        {
            Self::Disabled
        } else {
            Self::after_success(now_millis)
        }
    }
    /// Clock exhaustion cannot produce an immediate retry loop.
    fn after_success(now_millis: u64) -> Self {
        AutomaticTrimDeadline::next(now_millis).map_or(Self::Stopped, Self::Waiting)
    }
    /// Borrows a timer observation without transferring completion authority.
    pub(super) const fn deadline(&self) -> Option<AutomaticTrimDeadline> {
        match self {
            Self::Waiting(deadline) => Some(*deadline),
            Self::Disabled | Self::Running | Self::Stopping | Self::Stopped => None,
        }
    }
    /// Consumes due admission exactly once; scheduler capacity must already be available.
    pub(super) fn start(&mut self, now_millis: u64) -> Option<AutomaticTrimRun> {
        if self.deadline()?.remaining_millis(now_millis) != 0 {
            return None;
        }
        *self = Self::Running;
        Some(AutomaticTrimRun { _completion: () })
    }
    /// Joins the sole running operation; no failed or uncertain cycle creates a successor.
    pub(super) fn complete(
        &mut self,
        _run: AutomaticTrimRun,
        outcome: ext4_control::TrimOutcome,
        now_millis: u64,
    ) {
        if !matches!(self, Self::Running | Self::Stopping) {
            KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
        }
        *self = if matches!(self, Self::Running) && outcome == ext4_control::TrimOutcome::Complete {
            Self::after_success(now_millis)
        } else {
            Self::Stopped
        };
    }
    /// Ends future admission; an existing run retains its completion obligation through drain.
    pub(super) fn stop_schedule(&mut self) {
        *self = match self {
            Self::Waiting(_) => Self::Stopped,
            Self::Running | Self::Stopping => Self::Stopping,
            Self::Disabled => Self::Disabled,
            Self::Stopped => Self::Stopped,
        };
    }
}

impl VolumeRuntime {
    /// Selects a timer only while writable session authority remains current.
    pub(crate) fn automatic_trim_wakeup(&mut self) -> Option<AutomaticTrimDeadline> {
        let deadline = self.automatic_trim.deadline()?;
        if self.trim_ready().is_err() {
            self.automatic_trim.stop_schedule();
            return None;
        }
        Some(deadline)
    }
    /// Joins scheduler admission to the due cycle before any metadata reads or discard.
    pub(crate) fn start_automatic_trim(&mut self) -> Option<AutomaticTrimRun> {
        self.automatic_trim_wakeup()?;
        self.automatic_trim
            .start(crate::kernel::time::monotonic_millis())
    }
    /// Physical completion cleanup remains legal after media authority or lifecycle is revoked.
    pub(crate) fn complete_automatic_trim(
        &mut self,
        run: AutomaticTrimRun,
        outcome: ext4_control::TrimOutcome,
    ) {
        self.automatic_trim
            .complete(run, outcome, crate::kernel::time::monotonic_millis());
    }
    /// Stops only future cycles; cancellation and physical completion still join a running scan.
    #[cfg(not(test))]
    pub(crate) fn stop_automatic_trim(&mut self) {
        self.automatic_trim.stop_schedule();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Panics
    /// Fails if admission overlaps, a failed cycle retries, or a missed period triggers catch-up.
    #[test]
    #[expect(
        clippy::panic,
        clippy::disallowed_macros,
        reason = "a missing expected admission explicitly fails this unit-test contract"
    )]
    fn periodic_completion_owns_the_next_admission() {
        let mut state = AutomaticTrimState::new(
            ext4_control::AutomaticTrim::EveryMinute,
            ext4_core::MediaAccess::ReadWrite,
            1_000,
        );
        assert!(state.start(60_999).is_none());
        let Some(run) = state.start(61_000) else {
            panic!("due cycle was not admitted")
        };
        assert!(state.start(500_000).is_none());
        state.complete(run, ext4_control::TrimOutcome::Complete, 500_000);
        assert!(state.start(559_999).is_none());
        let Some(run) = state.start(560_000) else {
            panic!("completed cycle lost its successor")
        };
        state.complete(run, ext4_control::TrimOutcome::Failed, 560_001);
        assert!(state.start(u64::MAX).is_none());
    }
    /// # Panics
    /// Fails if read-only, disabled, cancellation, uncertainty or shutdown admits another cycle.
    #[test]
    #[expect(
        clippy::panic,
        clippy::disallowed_macros,
        reason = "a missing expected admission explicitly fails this unit-test contract"
    )]
    fn immutable_and_terminal_policies_do_not_schedule_effects() {
        for (policy, access) in [
            (
                ext4_control::AutomaticTrim::Disabled,
                ext4_core::MediaAccess::ReadWrite,
            ),
            (
                ext4_control::AutomaticTrim::EveryMinute,
                ext4_core::MediaAccess::ReadOnly,
            ),
        ] {
            let mut state = AutomaticTrimState::new(policy, access, 0);
            assert!(state.start(u64::MAX).is_none());
        }
        for outcome in [
            ext4_control::TrimOutcome::Complete,
            ext4_control::TrimOutcome::Cancelled,
            ext4_control::TrimOutcome::Unsupported,
        ] {
            let mut state = AutomaticTrimState::new(
                ext4_control::AutomaticTrim::EveryMinute,
                ext4_core::MediaAccess::ReadWrite,
                0,
            );
            let Some(run) = state.start(60_000) else {
                panic!("due cycle was not admitted")
            };
            state.stop_schedule();
            state.complete(run, outcome, 60_000);
            assert!(state.start(u64::MAX).is_none());
        }
        let mut state = AutomaticTrimState::new(
            ext4_control::AutomaticTrim::EveryMinute,
            ext4_core::MediaAccess::ReadWrite,
            0,
        );
        state.stop_schedule();
        assert!(state.start(u64::MAX).is_none());
    }
}
