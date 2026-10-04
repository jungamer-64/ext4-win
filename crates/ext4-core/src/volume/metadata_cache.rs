//! Bounded raw metadata reuse under the volume's serialized resolve/publication authority.

use alloc::vec::Vec;
use core::mem::size_of;

use super::mount::{CommittedEpoch, EpochSequence};
use crate::disk::block::{BlockAddress, BlockSize, ByteOffset};
use crate::disk_format::superblock::FilesystemUuid;
use crate::memory;
use crate::{Error, Result, StorageRequest, StorageTarget};

/// Total cache allocation budget, including its owning and indexing representations.
const BUDGET: usize = 8 * 1024 * 1024;
/// Associativity of each fixed cache set.
const WAYS: usize = 4;

/// Four raw block identities and the next replacement position.
#[derive(Clone, Copy, Debug)]
struct CacheSet {
    /// Identity is absent until a complete block image has been copied.
    blocks: [Option<BlockAddress>; WAYS],
    /// Round-robin replacement within this set.
    replacement: usize,
}

/// Two allocations established before the runtime admits ordinary I/O.
#[derive(Debug)]
struct CacheStorage {
    /// Fixed block-size geometry.
    block_size: BlockSize,
    /// Four-way index; neither access nor publication can grow it.
    sets: Vec<CacheSet>,
    /// Contiguous raw on-disk block images, including ciphertext where present.
    bytes: Vec<u8>,
}

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
    epoch: Option<(FilesystemUuid, EpochSequence)>,
    /// Changes before lower writes, so even same-epoch delayed completions lose admission.
    generation: u64,
    /// Publication/abort is the only transition reopening registrations.
    admission: Admission,
}

/// Provenance retained with an operation-owned lower read, never reconstructed at completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheReadStamp {
    /// Logical snapshot selected before issuing the read.
    epoch: (FilesystemUuid, EpochSequence),
    /// Cache invalidation generation at request creation.
    generation: u64,
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
        let block_size = epoch.superblock.block_size();
        let width = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        // Leave room for allocation bookkeeping in addition to the Rust owner and index.
        let budget = BUDGET
            .checked_sub(size_of::<Self>())
            .and_then(|value| value.checked_sub(256))
            .ok_or(Error::ArithmeticOverflow)?;
        let set_bytes = width
            .checked_mul(WAYS)
            .and_then(|value| value.checked_add(size_of::<CacheSet>()))
            .ok_or(Error::ArithmeticOverflow)?;
        let count = budget
            .checked_div(set_bytes)
            .ok_or(Error::ArithmeticOverflow)?;
        let bytes = count
            .checked_mul(WAYS)
            .and_then(|value| value.checked_mul(width))
            .ok_or(Error::ArithmeticOverflow)?;
        let storage = CacheStorage {
            block_size,
            sets: memory::repeated_vec(
                CacheSet {
                    blocks: [None; WAYS],
                    replacement: 0,
                },
                count,
            )?,
            bytes: memory::repeated_vec(0, bytes)?,
        };
        let allocated = storage
            .sets
            .capacity()
            .checked_mul(size_of::<CacheSet>())
            .and_then(|value| value.checked_add(storage.bytes.capacity()))
            .and_then(|value| value.checked_add(size_of::<Self>()))
            .and_then(|value| value.checked_add(256))
            .ok_or(Error::ArithmeticOverflow)?;
        if allocated > BUDGET {
            return Err(Error::OutOfMemory);
        }
        Ok(Self {
            storage: Some(storage),
            epoch: Some((epoch.identity().uuid(), epoch.sequence())),
            generation: 0,
            admission: Admission::Open,
        })
    }

    /// Binds synchronous metadata access to exactly the supplied immutable snapshot.
    pub fn access<'pass>(
        &'pass mut self,
        epoch: &'pass CommittedEpoch,
    ) -> MetadataCacheAccess<'pass> {
        let stamp = CacheReadStamp {
            epoch: (epoch.identity().uuid(), epoch.sequence()),
            generation: self.generation,
        };
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
            .is_some_and(|(uuid, _)| uuid != epoch.identity().uuid())
        {
            self.storage = None;
        }
        self.epoch = Some((epoch.identity().uuid(), epoch.sequence()));
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
    /// Block geometry at the explicit epoch boundary.
    pub(crate) const fn block_size(&self) -> BlockSize {
        self.block_size
    }
    /// Whether raw block reuse storage exists; disabled caches preserve exact lower I/O.
    pub(crate) fn enabled(&self) -> bool {
        self.cache.storage.is_some()
    }
    /// Preserves request creation provenance through suspension.
    pub(crate) const fn stamp(&self) -> CacheReadStamp {
        self.stamp
    }
    /// Copies an exact in-block slice only for the current logical epoch.
    pub(crate) fn read(
        &self,
        block: BlockAddress,
        range: core::ops::Range<usize>,
        out: &mut [u8],
    ) -> bool {
        if self.cache.epoch != Some(self.stamp.epoch) {
            return false;
        }
        self.cache
            .storage
            .as_ref()
            .is_some_and(|storage| storage.read(block, range, out))
    }
    /// Registers only complete, current, pre-invalidation reads after overlay application.
    pub(crate) fn insert(&mut self, block: BlockAddress, bytes: &[u8], stamp: CacheReadStamp) {
        if self.cache.epoch != Some(stamp.epoch)
            || self.stamp != stamp
            || self.cache.generation != stamp.generation
            || !matches!(self.cache.admission, Admission::Open)
        {
            return;
        }
        if let Some(storage) = &mut self.cache.storage {
            storage.insert(block, bytes);
        }
    }
}

impl CacheStorage {
    /// Mixes block identities before selecting one of the fixed sets.
    fn set(&self, block: BlockAddress) -> Option<usize> {
        let key = block.get().wrapping_mul(0x9e37_79b9_7f4a_7c15);
        usize::try_from((key ^ (key >> 32)).checked_rem(u64::try_from(self.sets.len()).ok()?)?).ok()
    }
    /// Computes a checked range in the preallocated contiguous byte storage.
    fn bytes_range(&self, set: usize, way: usize) -> Option<core::ops::Range<usize>> {
        let width = usize::try_from(self.block_size.bytes()).ok()?;
        let start = set
            .checked_mul(WAYS)?
            .checked_add(way)?
            .checked_mul(width)?;
        Some(start..start.checked_add(width)?)
    }
    /// Copies only resident, fully registered bytes.
    fn read(&self, block: BlockAddress, range: core::ops::Range<usize>, out: &mut [u8]) -> bool {
        let Some(set) = self.set(block) else {
            return false;
        };
        let Some(way) = self
            .sets
            .get(set)
            .and_then(|set| set.blocks.iter().position(|key| *key == Some(block)))
        else {
            return false;
        };
        self.bytes_range(set, way)
            .and_then(|range| self.bytes.get(range))
            .and_then(|bytes| bytes.get(range))
            .is_some_and(|source| memory::copy_exact(out, source).is_ok())
    }
    /// A complete copy precedes making the block identity visible.
    fn insert(&mut self, block: BlockAddress, bytes: &[u8]) {
        if usize::try_from(self.block_size.bytes()).ok() != Some(bytes.len()) {
            return;
        }
        let Some(index) = self.set(block) else {
            return;
        };
        let Some(set) = self.sets.get(index) else {
            return;
        };
        let way = set
            .blocks
            .iter()
            .position(|key| *key == Some(block))
            .or_else(|| set.blocks.iter().position(Option::is_none))
            .unwrap_or(set.replacement);
        let Some(range) = self.bytes_range(index, way) else {
            return;
        };
        let Some(target) = self.bytes.get_mut(range) else {
            return;
        };
        if memory::copy_exact(target, bytes).is_err() {
            return;
        }
        if let Some(set) = self.sets.get_mut(index) {
            if let Some(key) = set.blocks.get_mut(way) {
                *key = Some(block);
            }
            set.replacement = way.wrapping_add(1) & 3;
        }
    }
    /// Invalidates intersecting blocks through their four-way sets, retaining all other blocks.
    /// # Errors
    /// Returns physical-range arithmetic errors before lower I/O.
    fn invalidate(&mut self, offset: ByteOffset, len: usize) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let width = u64::from(self.block_size.bytes());
        let first = offset
            .get()
            .checked_div(width)
            .ok_or(Error::ArithmeticOverflow)?;
        let last = offset
            .get()
            .checked_add(u64::try_from(len).map_err(|_| Error::ArithmeticOverflow)?)
            .and_then(|end| end.checked_sub(1))
            .and_then(|last| last.checked_div(width))
            .ok_or(Error::ArithmeticOverflow)?;
        for block in first..=last {
            let block = BlockAddress::new(block);
            if let Some(set) = self.set(block).and_then(|index| self.sets.get_mut(index)) {
                for key in &mut set.blocks {
                    if *key == Some(block) {
                        *key = None;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns fixture allocation or geometry failures.
    /// # Panics
    /// Fails if an incomplete image registers, replacement crosses a way, or storage grows.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup is separate from four-way replacement assertions"
    )]
    fn fixed_four_way_replacement_requires_complete_images_and_never_grows() -> Result<()> {
        let mut storage = CacheStorage {
            block_size: BlockSize::from_superblock_log(0)?,
            sets: memory::repeated_vec(
                CacheSet {
                    blocks: [None; WAYS],
                    replacement: 0,
                },
                1,
            )?,
            bytes: memory::repeated_vec(0, 4096)?,
        };
        let before = (storage.sets.capacity(), storage.bytes.capacity());
        let mut out = [0_u8; 64];
        storage.insert(BlockAddress::new(7), &[1; 63]);
        assert!(!storage.read(BlockAddress::new(7), 0..64, &mut out));
        for block in 0..5_u64 {
            storage.insert(BlockAddress::new(block), &[2; 1024]);
        }
        assert!(!storage.read(BlockAddress::new(0), 0..64, &mut out));
        for block in 1..5_u64 {
            assert!(storage.read(BlockAddress::new(block), 100..164, &mut out));
            assert_eq!(out, [2; 64]);
        }
        assert_eq!((storage.sets.capacity(), storage.bytes.capacity()), before);
        Ok(())
    }
}
