//! FILE_OBJECT-owned movement protection and exclusive relocation admission.

use super::*;

/// The ledger serializes protection changes with acquiring and releasing relocation authority.
#[derive(Debug)]
pub(super) enum ClusterMobility {
    /// No handle protects the stream and no relocation is admitted.
    Movable,
    /// At least one uncleaned FILE_OBJECT prevents relocation.
    Protected {
        /// Required first owner makes an empty protected state unrepresentable.
        first: KernelFileObject,
        /// Additional distinct protection owners.
        additional: DriverVec<KernelFileObject>,
    },
    /// One retained relocation owns the exclusion until its permit is dropped.
    Relocating,
}

impl ClusterMobility {
    /// Installs one idempotent protection owner while no movement is active.
    /// # Errors
    /// Returns active-move conflict or allocation failure without acquiring protection.
    pub(super) fn protect(&mut self, file: KernelFileObject) -> DriverResult<()> {
        match self {
            Self::Movable => { *self = Self::Protected { first: file, additional: DriverVec::new() }; Ok(()) }
            Self::Protected { first, additional } if *first == file || additional.as_slice().contains(&file) => Ok(()),
            Self::Protected { additional, .. } => additional.try_push(file),
            Self::Relocating => Err(DriverError::ShareAccessConflict),
        }
    }

    /// Consumes protection with the FILE_OBJECT's unique cleanup obligation.
    pub(super) fn cleanup(&mut self, file: KernelFileObject) {
        if let Self::Protected { first, additional } = self {
            if *first == file {
                if let Some(next) = additional.pop() { *first = next; }
                else { *self = Self::Movable; }
            } else if let Some(index) = additional.iter().position(|owner| *owner == file) {
                additional.swap_remove(index);
            }
        }
    }

    /// Grants exclusive relocation admission; protection and a second relocation reject it.
    /// # Errors
    /// Returns a protected or already-moving stream conflict.
    pub(super) fn begin_move(&mut self) -> DriverResult<()> {
        match self {
            Self::Movable => { *self = Self::Relocating; Ok(()) }
            Self::Protected { .. } => Err(DriverError::AccessDenied),
            Self::Relocating => Err(DriverError::ShareAccessConflict),
        }
    }

    /// Retires the unique relocation permit.
    pub(super) fn finish_move(&mut self) {
        if !matches!(self, Self::Relocating) {
            KernelWideInconsistency::file_control_block_ownership_corruption().bugcheck();
        }
        *self = Self::Movable;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns finite protection-owner allocation failure.
    /// # Panics
    /// Fails if repeated marking duplicates ownership or cleanup releases another handle's claim.
    #[test]
    #[expect(unsafe_code, reason = "unpublished fixture FILE_OBJECTs remain live through their identity-only observations")]
    #[expect(clippy::panic_in_result_fn, reason = "assertions observe protection ownership and exclusive movement admission")]
    fn protection_owns_each_file_object_until_its_cleanup() -> DriverResult<()> {
        let mut first = wdk_sys::FILE_OBJECT::default();
        let mut second = wdk_sys::FILE_OBJECT::default();
        let first = unsafe {
            // SAFETY: The fixture retains this unpublished FILE_OBJECT through the entire test.
            KernelFileObject::from_raw(&raw mut first)
        }.ok_or(DriverError::InternalInvariantViolation)?;
        let second = unsafe {
            // SAFETY: The second independent fixture object has the same enclosing lifetime.
            KernelFileObject::from_raw(&raw mut second)
        }.ok_or(DriverError::InternalInvariantViolation)?;
        let mut mobility = ClusterMobility::Movable;
        mobility.protect(first)?;
        mobility.protect(first)?;
        mobility.protect(second)?;
        assert_eq!(mobility.begin_move(), Err(DriverError::AccessDenied));
        mobility.cleanup(first);
        assert_eq!(mobility.begin_move(), Err(DriverError::AccessDenied));
        mobility.cleanup(second);
        mobility.begin_move()?;
        assert_eq!(mobility.protect(first), Err(DriverError::ShareAccessConflict));
        assert_eq!(mobility.begin_move(), Err(DriverError::ShareAccessConflict));
        mobility.finish_move();
        mobility.protect(first)?;
        mobility.cleanup(first);
        mobility.begin_move()?;
        mobility.finish_move();
        Ok(())
    }
}
