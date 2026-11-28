//! Fixed-capacity raw block storage and read provenance for lower transfers.

use alloc::vec::Vec;

use super::block::{BlockAddress, BlockSize, ByteOffset};
use crate::memory;
use crate::{Error, Result};

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
pub(crate) struct CacheStorage {
    /// Fixed block-size geometry.
    block_size: BlockSize,
    /// Four-way index; neither access nor publication can grow it.
    sets: Vec<CacheSet>,
    /// Contiguous raw on-disk block images, including ciphertext where present.
    bytes: Vec<u8>,
}

/// Opaque provenance preserved from request creation until cache registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheReadStamp {
    /// Distinguishes separately mounted views with the same epoch number.
    mount: usize,
    /// Logical epoch that admitted the read.
    epoch: u64,
    /// Registration generation before any conflicting lower write.
    generation: u64,
}

impl CacheReadStamp {
    /// Captures the provenance chosen by the underlying read admission.
    pub(crate) const fn new(mount: usize, epoch: u64, generation: u64) -> Self {
        Self {
            mount,
            epoch,
            generation,
        }
    }
}

/// Raw reuse permissions selected before borrowing the operation device.
#[derive(Debug)]
pub(crate) enum CacheReuse<'cache> {
    /// No shared storage exists. Reads retain exact lower ranges.
    Disabled,
    /// This pass may issue block-aligned reads but cannot use the current owner's entries.
    Detached,
    /// Existing entries stay usable while lower writes prohibit registration.
    Lookup(&'cache mut CacheStorage),
    /// Existing blocks and registration of current complete images are both admitted.
    Register(&'cache mut CacheStorage),
}

/// Pass-local raw cache access with a fixed read stamp and no mounted epoch authority.
#[derive(Debug)]
pub(crate) struct BlockCacheAccess<'cache> {
    /// Attenuated permissions for this synchronous pass.
    reuse: CacheReuse<'cache>,
    /// Provenance attached to newly requested metadata.
    stamp: CacheReadStamp,
    /// Aligned read width even if the cache is disabled.
    block_size: BlockSize,
}

impl<'cache> BlockCacheAccess<'cache> {
    /// Couples the selected provenance with the raw operations admitted by the owner.
    pub(crate) const fn new(
        reuse: CacheReuse<'cache>,
        stamp: CacheReadStamp,
        block_size: BlockSize,
    ) -> Self {
        Self {
            reuse,
            stamp,
            block_size,
        }
    }

    /// Whether the read uses whole-block cache geometry.
    pub(crate) const fn enabled(&self) -> bool {
        !matches!(self.reuse, CacheReuse::Disabled)
    }

    /// Returns the provenance for this synchronous pass.
    pub(crate) const fn stamp(&self) -> CacheReadStamp {
        self.stamp
    }

    /// Block width used to align raw metadata requests.
    pub(crate) const fn block_size(&self) -> BlockSize {
        self.block_size
    }

    /// Copies only an admitted resident range.
    pub(crate) fn read(
        &self,
        block: BlockAddress,
        range: core::ops::Range<usize>,
        out: &mut [u8],
    ) -> bool {
        match &self.reuse {
            CacheReuse::Lookup(storage) | CacheReuse::Register(storage) => {
                storage.read(block, range, out)
            }
            CacheReuse::Detached | CacheReuse::Disabled => false,
        }
    }

    /// Registers a full image only under the original stamp that admitted the request.
    pub(crate) fn insert(&mut self, block: BlockAddress, bytes: &[u8], stamp: CacheReadStamp) {
        if self.stamp == stamp
            && let CacheReuse::Register(storage) = &mut self.reuse
        {
            storage.insert(block, bytes);
        }
    }
}

impl CacheStorage {
    /// Preallocates the entire replacement index and raw byte storage within the supplied budget.
    /// # Errors
    /// Returns allocation, capacity or block geometry failure.
    pub(crate) fn try_new(block_size: BlockSize, budget: usize) -> Result<Self> {
        let width = usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
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
            .ok_or(Error::ArithmeticOverflow)?;
        if allocated > budget {
            return Err(Error::OutOfMemory);
        }
        Ok(storage)
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
    pub(crate) fn insert(&mut self, block: BlockAddress, bytes: &[u8]) {
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
    pub(crate) fn invalidate(&mut self, offset: ByteOffset, len: usize) -> Result<()> {
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
