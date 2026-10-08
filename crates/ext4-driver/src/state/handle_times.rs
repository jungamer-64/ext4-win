//! FILE_OBJECT-local automatic timestamp policy, shared with native cached-write admission.

use core::sync::atomic::{AtomicU8, Ordering};
use ext4_core::Ext4Times;

/// Whether I/O through this handle may update one timestamp automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AutomaticTimeUpdate {
    /// Preserve this field across handle-originated I/O.
    Suppressed,
    /// Permit the ordinary filesystem timestamp update.
    Enabled,
}

/// Independent automatic-update selections; explicit timestamp assignments remain permitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HandleTimestampPolicy {
    /// Last-access update selection.
    pub(crate) accessed: AutomaticTimeUpdate,
    /// Last-write update selection.
    pub(crate) modified: AutomaticTimeUpdate,
    /// Metadata-change update selection.
    pub(crate) changed: AutomaticTimeUpdate,
}

impl HandleTimestampPolicy {
    /// New handles permit all automatic updates, independently of other handles on the inode.
    pub(crate) const AUTOMATIC: Self = Self {
        accessed: AutomaticTimeUpdate::Enabled,
        modified: AutomaticTimeUpdate::Enabled,
        changed: AutomaticTimeUpdate::Enabled,
    };

    /// Suppression needs a journaled handle write because paging writeback has no originating CCB.
    pub(crate) fn requires_journaled_write(self) -> bool {
        self != Self::AUTOMATIC
    }

    /// Restores only suppressed fields after automatic core metadata updates.
    pub(crate) fn preserve(self, before: Ext4Times, after: Ext4Times) -> Ext4Times {
        Ext4Times::new(
            if self.accessed == AutomaticTimeUpdate::Suppressed {
                before.accessed()
            } else {
                after.accessed()
            },
            if self.modified == AutomaticTimeUpdate::Suppressed {
                before.modified()
            } else {
                after.modified()
            },
            if self.changed == AutomaticTimeUpdate::Suppressed {
                before.changed()
            } else {
                after.changed()
            },
            after.created(),
        )
    }

    /// Encodes independent suppression selections for one atomic observation.
    fn bits(self) -> u8 {
        u8::from(self.accessed == AutomaticTimeUpdate::Suppressed)
            | (u8::from(self.modified == AutomaticTimeUpdate::Suppressed) << 1)
            | (u8::from(self.changed == AutomaticTimeUpdate::Suppressed) << 2)
    }

    /// Decodes a value written only by this policy's publication boundary.
    fn from_bits(bits: u8) -> Self {
        let field = |mask| {
            if bits & mask != 0 {
                AutomaticTimeUpdate::Suppressed
            } else {
                AutomaticTimeUpdate::Enabled
            }
        };
        Self {
            accessed: field(1),
            modified: field(2),
            changed: field(4),
        }
    }
}

/// One authoritative CCB policy; native Fast I/O observes it without borrowing mutable state.
#[derive(Debug)]
pub(super) struct HandleTimestampState {
    /// Atomic publication allows concurrent native Fast I/O admission to see a complete policy.
    suppressed: AtomicU8,
}

impl HandleTimestampState {
    /// Enables automatic updates for a newly constructed handle.
    pub(super) const fn new() -> Self {
        Self {
            suppressed: AtomicU8::new(0),
        }
    }

    /// Observes the last successful basic-information publication.
    pub(super) fn policy(&self) -> HandleTimestampPolicy {
        HandleTimestampPolicy::from_bits(self.suppressed.load(Ordering::Acquire))
    }

    /// Publishes all fields together after the paired metadata mutation succeeds.
    pub(super) fn publish(&self, policy: HandleTimestampPolicy) {
        self.suppressed.store(policy.bits(), Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ext4_core::Ext4Timestamp;

    /// # Panics
    /// Panics if one handle's suppression affects another handle or an unsuppressed field.
    #[test]
    fn independent_handles_preserve_only_selected_automatic_timestamps() {
        let first = HandleTimestampState::new();
        let second = HandleTimestampState::new();
        first.publish(HandleTimestampPolicy {
            accessed: AutomaticTimeUpdate::Suppressed,
            modified: AutomaticTimeUpdate::Suppressed,
            changed: AutomaticTimeUpdate::Enabled,
        });
        let old = Ext4Timestamp::from_unix_seconds(10);
        let new = Ext4Timestamp::from_unix_seconds(20);
        let before = Ext4Times::new(old, old, old, old);
        let after = Ext4Times::new(new, new, new, old);
        assert_eq!(
            first.policy().preserve(before, after),
            Ext4Times::new(old, old, new, old)
        );
        assert_eq!(second.policy().preserve(before, after), after);
        assert!(first.policy().requires_journaled_write());
        first.publish(HandleTimestampPolicy::AUTOMATIC);
        assert!(!first.policy().requires_journaled_write());
    }
}
