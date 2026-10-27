//! Bounded initialization under a unique paging allocation reservation.
use crate::kernel::status::{DriverError, DriverResult};
use crate::state::PagingFileSetupLease;
use ext4_core::{ContiguousFileStorage, FileNodeId, FileSize};

/// Rounds a Memory Manager byte bound to complete filesystem blocks and host pages.
/// # Errors
/// Rejects zero or arithmetic/signed-byte-domain overflow before physical admission.
pub(crate) fn allocation_bound(
    requested: FileSize,
    block: ext4_core::BlockSize,
) -> DriverResult<FileSize> {
    let alignment = u64::from(block.bytes()).max(4096);
    let padding = alignment
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let bytes = requested
        .bytes()
        .checked_add(padding)
        .and_then(|bytes| bytes.checked_div(alignment))
        .and_then(|blocks| blocks.checked_mul(alignment))
        .ok_or(DriverError::InvalidParameter)?;
    if bytes == 0 || i64::try_from(bytes).is_err() {
        return Err(DriverError::InvalidParameter);
    }
    Ok(FileSize::from_bytes(bytes))
}

/// Excludes mapping changes to this file across commits; unclaimed tail space remains free.
#[derive(Debug)]
pub(crate) struct PagingInitialization {
    /// Exact FCB and unique native setup/extension reservation.
    lease: PagingFileSetupLease,
    /// Complete requested bound.
    target: FileSize,
    /// Last home-checkpointed prefix; provisional resolve results cannot advance it.
    initialized: FileSize,
    /// Logical EOF requested by this operation; physical initialization alone does not publish it.
    logical_size: FileSize,
    /// Core-issued raw-byte initialization fact; unwritten extent flags cannot recreate it.
    storage: Option<ContiguousFileStorage>,
}

impl PagingInitialization {
    /// Selects setup before namespace or allocation publication.
    /// # Errors
    /// Rejects empty, shrinking, misaligned or signed-domain-exceeding bounds.
    pub(crate) fn new(
        lease: PagingFileSetupLease,
        target: FileSize,
        current: FileSize,
        logical_size: FileSize,
        block: ext4_core::BlockSize,
    ) -> DriverResult<Self> {
        validate_bound(target, current, u64::from(block.bytes()).max(4096))?;
        if logical_size > target {
            return Err(DriverError::InvalidParameter);
        }
        if matches!(lease.claim(), crate::kernel::stream::PagingFileClaim::Extension { length, .. }
            if current.bytes() < length.bytes())
        {
            return Err(DriverError::InternalInvariantViolation);
        }
        let storage = lease.storage();
        Ok(Self {
            lease,
            target,
            initialized: current,
            logical_size,
            storage,
        })
    }

    /// Identifies the inode retained by setup.
    /// # Errors
    /// Rejects an invalid non-file setup identity.
    pub(crate) fn file(&self) -> DriverResult<FileNodeId> {
        self.lease.file()
    }

    /// Resolves one provisional chunk without changing committed progress on replay.
    /// # Errors
    /// Preserves suspension, allocation and contiguous-map failures.
    pub(crate) fn resolve(
        &self,
        mutation: &mut crate::request::DriverMutationPass<'_, '_, '_>,
    ) -> DriverResult<ContiguousFileStorage> {
        let file = self.file()?;
        if self.initialized.bytes() == 0 {
            if mutation
                .staged_node_metadata(ext4_core::NodeId::File(file))?
                .size()
                .bytes()
                != 0
            {
                return Err(DriverError::InternalInvariantViolation);
            }
        }
        let retained = match self.storage {
            Some(storage) => Some(mutation.retained_contiguous_file_storage(file, storage)?),
            None if self.initialized.bytes() != 0 => Some(mutation.contiguous_file_storage(file)?),
            None => None,
        };
        if retained.is_some_and(|storage| storage.initialized_length() != self.initialized) {
            return Err(DriverError::InternalInvariantViolation);
        }
        let selected = mutation.file(file)?;
        let mut storage =
            mutation.initialize_contiguous_file_tail(selected, self.target, retained)?;
        if storage.initialized_length() == self.target
            && storage.logical_size() != self.logical_size
        {
            storage = mutation.set_contiguous_file_eof(selected, self.logical_size, storage)?;
        }
        if let crate::kernel::stream::PagingFileClaim::Extension { physical, .. } =
            self.lease.claim()
            && physical != storage.physical()
        {
            return Err(DriverError::NotSupported);
        }
        Ok(storage)
    }

    /// Consumes a checkpoint result into the next initialization bound.
    /// # Errors
    /// Rejects a shrinking, excessive or discontinuous progress result.
    pub(crate) fn checkpointed(&mut self, storage: ContiguousFileStorage) -> DriverResult<bool> {
        let length = storage.initialized_length();
        if length.bytes() < self.initialized.bytes()
            || length.bytes() > self.target.bytes()
            || length.bytes().saturating_sub(self.initialized.bytes()) > 65_536
        {
            return Err(DriverError::InternalInvariantViolation);
        }
        self.initialized = length;
        self.storage = Some(storage);
        Ok(length == self.target)
    }

    /// Publishes only the complete home-checkpointed map and consumes its reservation.
    /// # Errors
    /// Preserves native admission failure without enlarging the old map.
    pub(crate) fn activate(
        self,
        storage: ContiguousFileStorage,
        route: crate::kernel::storage::MountedStorageRoute,
    ) -> DriverResult<()> {
        if storage.initialized_length() != self.target
            || self.initialized != self.target
            || storage.logical_size() != self.logical_size
        {
            return Err(self.failure(DriverError::InternalInvariantViolation, false));
        }
        let file = self.file()?;
        let initialized = self.initialized;
        let target = self.target;
        self.lease.activate(storage, route).map_err(|error| {
            DriverError::PagingInitializationFailed {
                file,
                initialized,
                target,
                status: error.ntstatus(),
                uncertain: false,
            }
        })
    }

    /// Captures durable prefix progress separately from Windows status presentation.
    pub(crate) fn failure(&self, error: DriverError, uncertain: bool) -> DriverError {
        if matches!(error, DriverError::PagingInitializationFailed { .. }) {
            return error;
        }
        match self.file() {
            Ok(file) => DriverError::PagingInitializationFailed {
                file,
                initialized: self.initialized,
                target: self.target,
                status: error.ntstatus(),
                uncertain,
            },
            Err(error) => error,
        }
    }
}

/// Whole-block extension keeps initialization RMW outside the concurrently active old prefix.
/// # Errors
/// Rejects empty, shrinking, misaligned or unrepresentable bounds before effects.
pub(crate) fn validate_bound(
    target: FileSize,
    current: FileSize,
    alignment: u64,
) -> DriverResult<()> {
    if target.bytes() == 0
        || target.bytes() < current.bytes()
        || alignment == 0
        || !target.bytes().is_multiple_of(alignment)
        || !current.bytes().is_multiple_of(alignment)
        || i64::try_from(target.bytes()).is_err()
    {
        return Err(DriverError::InvalidParameter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Panics
    /// Fails if initialization can share an old active block or cross the signed byte domain.
    #[test]
    fn bounds_keep_active_blocks_outside_initialization() {
        for (target, current, alignment, accepted) in [
            (16_777_216, 0, 4096, true),
            (16_842_752, 16_777_216, 65_536, true),
            (16_781_312, 16_777_216, 65_536, false),
            (0, 0, 4096, false),
            (4096, 8192, 4096, false),
            (0x8000_0000_0000_0000, 0, 4096, false),
        ] {
            assert_eq!(
                validate_bound(
                    FileSize::from_bytes(target),
                    FileSize::from_bytes(current),
                    alignment
                )
                .is_ok(),
                accepted
            );
        }
    }

    /// # Errors
    /// Returns invalid constant filesystem block geometry.
    /// # Panics
    /// Fails if MM page bounds truncate a filesystem block or overflow the native signed domain.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "constant geometry construction is fallible while assertions compare independent rounding vectors"
    )]
    fn physical_allocation_rounds_without_changing_logical_eof() -> DriverResult<()> {
        let block = ext4_core::BlockSize::from_superblock_log(6)?;
        for (requested, expected) in [
            (4096, Some(65_536)),
            (69_632, Some(131_072)),
            (131_072, Some(131_072)),
            (0, None),
            (u64::MAX, None),
            (i64::MAX as u64, None),
        ] {
            assert_eq!(
                allocation_bound(FileSize::from_bytes(requested), block)
                    .ok()
                    .map(FileSize::bytes),
                expected
            );
        }
        Ok(())
    }
}
