//! Bounded raw metadata reuse under the volume's serialized resolve/publication authority.

use core::mem::size_of;

use super::session::{CommittedEpoch, EpochSequence, MountIdentity};
use crate::disk::block::BlockSize;
use crate::disk::block_cache::{BlockCacheAccess, CacheReadStamp, CacheReuse, CacheStorage};
use crate::{Error, Result, StorageRequest, StorageTarget};

/// Total cache allocation budget, including its owning and indexing representations.
const BUDGET: usize = 8 * 1024 * 1024;
/// Registration phase; existing unrelated blocks remain readable during an update.
#[derive(Debug, Default)]
enum Admission {
    /// A current-epoch complete read may populate the cache.
    #[default]
    Open,
    /// Lower writes may change storage; misses cannot register until publication or abort.
    Updating,
}

/// Volume-owned metadata cache. A default value disables reuse without disabling storage I/O.
///
/// The driver serializes access with its existing volume reactor. No internal lock is acquired.
/// The two fixed allocations and owner/index overhead stay below 8 MiB. User payload and derived
/// plaintext are excluded. Allocation failure may be handled by retaining the default value.
#[derive(Debug, Default)]
pub struct MetadataCache {
    /// Optional fixed storage; absence represents unavailable cache memory.
    storage: Option<CacheStorage>,
    /// Sole current logical snapshot whose metadata may be reused.
    epoch: Option<(MountIdentity, EpochSequence)>,
    /// Changes before lower writes, so even same-epoch delayed completions lose admission.
    generation: u64,
    /// Publication/abort is the only transition reopening registrations.
    admission: Admission,
}

/// Ephemeral cache authority bound to the caller's immutable committed epoch.
///
/// It borrows the owner only for a synchronous resolve pass. Lower envelopes retain a stamp,
/// not this borrow. Old epochs can read their overlay/transcript but cannot hit or populate the
/// current cache. During mutation, unrelated resident blocks can hit while all misses bypass
/// registration; this avoids retaining an unbounded invalidation ledger in the cache budget.
#[derive(Debug)]
pub struct MetadataCacheAccess<'cache> {
    /// Authoritative immutable snapshot; callers cannot supply a different overlay alongside it.
    epoch: &'cache CommittedEpoch,
    /// Unique owner borrow supplied by the volume runtime.
    cache: &'cache mut MetadataCache,
    /// Read provenance selected at the pass boundary.
    stamp: CacheReadStamp,
    /// Geometry of the epoch whose stream is being read.
    block_size: BlockSize,
}

impl MetadataCache {
    /// Preallocates all cache storage for a mounted volume.
    /// # Errors
    /// Returns allocation or geometry failures; callers may continue with a default cache.
    pub fn try_new(epoch: &CommittedEpoch) -> Result<Self> {
        let budget = BUDGET
            .checked_sub(size_of::<Self>())
            .and_then(|value| value.checked_sub(256))
            .ok_or(Error::ArithmeticOverflow)?;
        let storage = CacheStorage::try_new(epoch.superblock.block_size(), budget)?;
        Ok(Self {
            storage: Some(storage),
            epoch: Some((epoch.mount, epoch.sequence())),
            generation: 0,
            admission: Admission::Open,
        })
    }

    /// Binds synchronous metadata access to exactly the supplied immutable snapshot.
    pub fn access<'pass>(
        &'pass mut self,
        epoch: &'pass CommittedEpoch,
    ) -> MetadataCacheAccess<'pass> {
        let stamp = CacheReadStamp::new(
            epoch.mount.serial(),
            epoch.sequence().get(),
            self.generation,
        );
        MetadataCacheAccess {
            epoch,
            cache: self,
            stamp,
            block_size: epoch.superblock.block_size(),
        }
    }

    /// Seals affected physical ranges before the first lower write. No admission ledger grows.
    /// # Errors
    /// Returns range arithmetic failure before any lower effect can occur.
    pub(super) fn begin_mutation<'write>(
        &mut self,
        writes: impl Iterator<Item = &'write StorageRequest> + Clone,
    ) -> Result<()> {
        // Validate the complete physical write set before changing registration state.
        for request in writes.clone() {
            if let StorageRequest::Write {
                target: StorageTarget::Filesystem,
                offset,
                buffer,
            } = request
            {
                let _end = offset
                    .get()
                    .checked_add(
                        u64::try_from(buffer.len()).map_err(|_| Error::ArithmeticOverflow)?,
                    )
                    .ok_or(Error::ArithmeticOverflow)?;
            }
        }
        let Some(generation) = self.generation.checked_add(1) else {
            self.storage = None;
            return Ok(());
        };
        self.generation = generation;
        self.admission = Admission::Updating;
        if let Some(storage) = &mut self.storage {
            for request in writes {
                if let StorageRequest::Write {
                    target: StorageTarget::Filesystem,
                    offset,
                    buffer,
                } = request
                {
                    storage.invalidate(*offset, buffer.len())?;
                }
            }
        }
        Ok(())
    }

    /// Reopens reuse after a pre-publication abort without restoring invalidated entries.
    pub fn abandon_mutation(&mut self) {
        self.admission = Admission::Open;
    }

    /// Publishes logical metadata, including checkpoint epochs, without allocation.
    ///
    /// Durable publication installs overlay images at the same serialized boundary as the epoch
    /// swap. A checkpoint changes the epoch identity but preserves every raw logical image.
    pub fn publish(&mut self, epoch: &CommittedEpoch) {
        if self
            .epoch
            .as_ref()
            .is_some_and(|(mount, _)| mount != &epoch.mount)
        {
            self.storage = None;
        }
        self.epoch = Some((epoch.mount, epoch.sequence()));
        self.admission = Admission::Open;
        if let Some(storage) = &mut self.storage {
            for image in &epoch.overlay {
                storage.insert(image.block(), image.bytes());
            }
        }
    }
}

impl<'cache> MetadataCacheAccess<'cache> {
    /// Sole immutable snapshot associated with this cache capability.
    pub(crate) const fn epoch(&self) -> &'cache CommittedEpoch {
        self.epoch
    }
    /// Attenuates the borrow for an individual bounded directory stage.
    pub(crate) fn reborrow(&mut self) -> MetadataCacheAccess<'_> {
        MetadataCacheAccess {
            epoch: self.epoch,
            cache: self.cache,
            stamp: self.stamp,
            block_size: self.block_size,
        }
    }
    /// Preserves request creation provenance through suspension.
    pub(crate) const fn stamp(&self) -> CacheReadStamp {
        self.stamp
    }

    /// Attenuates the mounted epoch and cache policy to raw block reuse for this pass.
    pub(crate) fn into_block_access(self) -> BlockCacheAccess<'cache> {
        let epoch = (self.epoch.mount, self.epoch.sequence());
        let reuse = match self.cache.storage.as_mut() {
            None => CacheReuse::Disabled,
            Some(_) if self.cache.epoch != Some(epoch) => CacheReuse::Detached,
            Some(storage) => match self.cache.admission {
                Admission::Open => CacheReuse::Register(storage),
                Admission::Updating => CacheReuse::Lookup(storage),
            },
        };
        BlockCacheAccess::new(reuse, self.stamp, self.block_size)
    }
}
