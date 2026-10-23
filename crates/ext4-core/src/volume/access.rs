//! Mount access and the finite memory admitted for write-free recovery.

use crate::{Error, Result};

/// Resident recovery payload and index capacity admitted before mount publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryMemoryLimit(usize);

impl RecoveryMemoryLimit {
    /// Default per-mount recovery storage admission: 64 MiB.
    pub const DEFAULT: Self = Self(64 * 1024 * 1024);

    /// Establishes a nonzero byte budget independently of physical allocation success.
    /// # Errors
    /// Returns [`Error::InvalidRecoveryMemoryLimit`] for an empty budget.
    pub const fn new(bytes: usize) -> Result<Self> {
        if bytes == 0 {
            Err(Error::InvalidRecoveryMemoryLimit)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Maximum charged resident bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}

/// Explicit media access selected before journal recovery or mount-session marking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountAccess {
    /// Journaled changes may be persisted to exclusively held backing storage.
    ReadWrite,
    /// Recovery is private to memory; no media write or flush is authorized.
    /// Backing storage must remain unchanged by other writers until unmount.
    ReadOnly {
        /// Finite admission for recovery images and their indexing storage.
        recovery_memory: RecoveryMemoryLimit,
    },
}

impl MountAccess {
    /// Attenuates recovery admission to the media operations granted after mounting.
    #[must_use]
    pub const fn media_access(self) -> MediaAccess {
        match self {
            Self::ReadWrite => MediaAccess::ReadWrite,
            Self::ReadOnly { .. } => MediaAccess::ReadOnly,
        }
    }
}

/// Immutable mounted-media authority, independent of recovery resource admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaAccess {
    /// Journaled persistent updates may be admitted.
    ReadWrite,
    /// Only observations and mount-local key changes may be admitted.
    ReadOnly,
}
