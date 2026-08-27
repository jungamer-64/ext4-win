//! Orphan-file block validation and checksum-preserving slot removal.

use crate::disk::block::BlockAddress;
use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{DiskOffset, le_u32, put_le_u32};
use crate::disk_format::inode::{InodeGeneration, InodeId};
use crate::disk_format::superblock::{MetadataChecksum, Superblock};
use crate::{Error, Result};

/// Tail signature distinguishing orphan entries from ordinary file payload.
const ORPHAN_MAGIC: u32 = 0x0b10_ca04;

/// Checksum identity of the special inode, not of the inodes listed in its slots.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OrphanBlockContext {
    /// Inode-seeded CRC when metadata checksums are enabled.
    seed: Option<u32>,
}

impl OrphanBlockContext {
    /// Binds each block checksum to filesystem, special inode, generation, and physical position.
    pub(crate) fn new(superblock: Superblock, inode: InodeId, generation: InodeGeneration) -> Self {
        let seed = (superblock.metadata_checksum() == MetadataChecksum::Crc32c).then(|| {
            let seed = ext4_crc32c(
                superblock.checksum_seed().as_u32(),
                &inode.as_u32().to_le_bytes(),
            );
            ext4_crc32c(seed, &generation.as_u32().to_le_bytes())
        });
        Self { seed }
    }

    /// Validates the tail and returns only the authenticated entry bytes.
    /// # Errors
    /// Returns an error for a short block, wrong magic, or checksum mismatch.
    pub(crate) fn entries(self, bytes: &[u8], block: BlockAddress) -> Result<&[u8]> {
        let tail = bytes
            .len()
            .checked_sub(8)
            .ok_or(Error::InvalidOrphanTracking)?;
        if tail == 0 || tail % 4 != 0 || le_u32(bytes, DiskOffset::new(tail))? != ORPHAN_MAGIC {
            return Err(Error::InvalidOrphanTracking);
        }
        let entries = bytes.get(..tail).ok_or(Error::InvalidOrphanTracking)?;
        if let Some(seed) = self.seed {
            let checksum = ext4_crc32c(ext4_crc32c(seed, &block.get().to_le_bytes()), entries);
            let checksum_offset = tail.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
            if le_u32(bytes, DiskOffset::new(checksum_offset))? != checksum {
                return Err(Error::ChecksumMismatch);
            }
        }
        Ok(entries)
    }

    /// Removes exactly the slot validated by the recovery inventory.
    /// # Errors
    /// Returns an error if the slot changed, the block is corrupt, or the offset is out of range.
    pub(crate) fn remove(
        self,
        bytes: &mut [u8],
        block: BlockAddress,
        slot: usize,
        inode: InodeId,
    ) -> Result<()> {
        let entries = self.entries(bytes, block)?;
        let offset = slot.checked_mul(4).ok_or(Error::ArithmeticOverflow)?;
        if le_u32(entries, DiskOffset::new(offset))? != inode.as_u32() {
            return Err(Error::InvalidOrphanTracking);
        }
        let tail = entries.len();
        put_le_u32(bytes, DiskOffset::new(offset), 0)?;
        let checksum = match self.seed {
            Some(seed) => ext4_crc32c(
                ext4_crc32c(seed, &block.get().to_le_bytes()),
                bytes.get(..tail).ok_or(Error::InvalidOrphanTracking)?,
            ),
            None => 0,
        };
        put_le_u32(
            bytes,
            DiskOffset::new(tail.checked_add(4).ok_or(Error::ArithmeticOverflow)?),
            checksum,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics if checksum binding, tail validation, or exact-slot removal violates the format.
    #[test]
    fn orphan_block_known_answers_bind_slots_and_physical_address() {
        let result = (|| -> Result<()> {
            let context = OrphanBlockContext {
                seed: Some(0x1234_5678),
            };
            let block = BlockAddress::new(0x1234_56ab);
            for (size, checksum) in [(1024_usize, 0x7c78_a5d8), (4096, 0xb6bb_86d5)] {
                let mut bytes = crate::memory::repeated_vec(0, size)?;
                let tail = size.checked_sub(8).ok_or(Error::ArithmeticOverflow)?;
                put_le_u32(&mut bytes, DiskOffset::new(0), 42)?;
                put_le_u32(
                    &mut bytes,
                    DiskOffset::new(tail.checked_sub(4).ok_or(Error::ArithmeticOverflow)?),
                    84,
                )?;
                put_le_u32(&mut bytes, DiskOffset::new(tail), ORPHAN_MAGIC)?;
                put_le_u32(
                    &mut bytes,
                    DiskOffset::new(size.checked_sub(4).ok_or(Error::ArithmeticOverflow)?),
                    checksum,
                )?;
                assert_eq!(context.entries(&bytes, block)?.len(), tail);
                assert_eq!(
                    context.entries(&bytes, BlockAddress::new(0x1234_56ac)),
                    Err(Error::ChecksumMismatch)
                );
                assert_eq!(
                    context.remove(&mut bytes, block, 0, InodeId::try_from(84)?),
                    Err(Error::InvalidOrphanTracking)
                );
                context.remove(&mut bytes, block, 0, InodeId::try_from(42)?)?;
                assert_eq!(
                    le_u32(context.entries(&bytes, block)?, DiskOffset::new(0))?,
                    0
                );
                put_le_u32(&mut bytes, DiskOffset::new(tail), 0)?;
                assert_eq!(
                    context.entries(&bytes, block),
                    Err(Error::InvalidOrphanTracking)
                );
            }
            let mut unchecked = [0_u8; 1024];
            put_le_u32(&mut unchecked, DiskOffset::new(1016), ORPHAN_MAGIC)?;
            put_le_u32(&mut unchecked, DiskOffset::new(0), 42)?;
            let context = OrphanBlockContext { seed: None };
            context.remove(&mut unchecked, block, 0, InodeId::try_from(42)?)?;
            assert_eq!(
                le_u32(context.entries(&unchecked, block)?, DiskOffset::new(0))?,
                0
            );
            assert_eq!(
                context.entries(&[0; 8], block),
                Err(Error::InvalidOrphanTracking)
            );
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
