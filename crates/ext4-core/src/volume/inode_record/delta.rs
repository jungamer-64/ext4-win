//! Recorded inode bytes establish layout validity without granting allocation or publication.
use super::{AllocatedInodeRecord, InodeRecordLayout, LiveInodeRecord};
use crate::disk_format::xattr::ParsedXattrs;
use crate::volume::scope::*;

/// Inline payload includes the complete attribute body; mapping operands carry no such body.
#[derive(Debug)]
enum DeltaPayload<'a> {
    /// Extent roots and allocation remain the replay planner's responsibility.
    Mapping,
    /// Parsed slots remain borrowed from the same immutable complete record.
    Inline(ParsedXattrs<'a>),
}

/// Wire width and attribute bounds are established before selecting an inode transition.
#[derive(Debug)]
pub(in crate::volume) struct DeltaInodeImage<'a> {
    /// The authenticated program owns this immutable operand for the whole resolution pass.
    bytes: &'a [u8],
    /// Extra fields and the attribute body have a single validated boundary.
    layout: InodeRecordLayout,
    /// Payload interpretation cannot change independently of the borrowed bytes.
    payload: DeltaPayload<'a>,
}
impl<'a> DeltaInodeImage<'a> {
    /// Full inline records are required; mapped storage carries precisely the declared extra fields.
    /// This establishes representation validity only, not ownership of referenced attribute inodes.
    /// # Errors
    /// Rejects truncated/oversized operands, wrong widths, malformed extra fields or attribute tables.
    pub(in crate::volume) fn parse(bytes: &'a [u8], record_bytes: usize) -> Result<Self> {
        if bytes.len() < 128 || bytes.len() > record_bytes {
            return Err(Error::InvalidInode);
        }
        let layout = InodeRecordLayout::parse(bytes)?;
        let payload = if InodeFlags::from_u32(le_u32(bytes, disk_offset(INODE_FLAGS_OFFSET))?)
            .has_inline_data()
        {
            if bytes.len() != record_bytes {
                return Err(Error::InvalidInode);
            }
            let attributes = xattr_storage::parse_inline_xattrs(
                bytes
                    .get(layout.xattr_offset()..)
                    .ok_or(Error::InvalidInode)?,
            )?;
            if attributes.inline_data().is_none() {
                return Err(Error::InvalidInode);
            }
            DeltaPayload::Inline(attributes)
        } else {
            if bytes.len() != layout.xattr_offset() {
                return Err(Error::InvalidInode);
            }
            DeltaPayload::Mapping
        };
        Ok(Self {
            bytes,
            layout,
            payload,
        })
    }

    /// Recorded generation is an identity observation, never permission to replace an occupied slot.
    /// # Errors
    /// Rejects a truncated generation field.
    pub(in crate::volume) fn generation(&self) -> Result<u32> {
        le_u32(self.bytes, disk_offset(INODE_GENERATION_OFFSET))
    }

    /// Restores metadata and resident file bytes without changing mapping or attribute ownership.
    /// Directory namespace bodies are reconstructed from bindings and retain their current layout.
    /// # Errors
    /// Rejects zero links, changed identity/storage/attributes, malformed metadata or allocation failure.
    pub(in crate::volume) fn restore(self, mut base: LiveInodeRecord) -> Result<LiveInodeRecord> {
        let inode = base.parse()?;
        let directory = inode.kind() == InodeKind::Directory;
        let recorded_flags =
            InodeFlags::from_u32(le_u32(self.bytes, disk_offset(INODE_FLAGS_OFFSET))?);
        let flags_match = if directory {
            inode.flags().without_indexed_directory() == recorded_flags.without_indexed_directory()
        } else {
            inode.flags() == recorded_flags
        };
        let original = base.raw.bytes();
        let original_layout = InodeRecordLayout::parse(original)?;
        if self.layout.xattr_offset() != original_layout.xattr_offset()
            || le_u16(self.bytes, disk_offset(INODE_LINKS_COUNT_OFFSET))? == 0
            || inode.kind()
                != InodeMode::from_disk(le_u16(self.bytes, disk_offset(INODE_MODE_OFFSET))?)?.kind()
            || !flags_match
            || original.get(100..108) != self.bytes.get(100..108)
            || original.get(118..120) != self.bytes.get(118..120)
        {
            return Err(Error::UnsupportedJournal);
        }
        match &self.payload {
            DeltaPayload::Mapping => {
                if !matches!(inode.storage(), InodeStorage::Extents(_))
                    && original.get(40..100) != self.bytes.get(40..100)
                {
                    return Err(Error::UnsupportedJournal);
                }
            }
            DeltaPayload::Inline(attributes) => {
                if directory {
                    let _source = crate::disk_format::inode::InodeData::parse(
                        base.id(),
                        self.bytes,
                        base.raw.encoding,
                    )?;
                }
                let original_attributes =
                    xattr_storage::parse_inline_xattrs(base.raw.inline_xattr_region()?)?;
                if !original_attributes.same_non_payload_bindings(attributes) {
                    return Err(Error::UnsupportedJournal);
                }
            }
        }
        let prefix = self.layout.xattr_offset();
        for span in [0..28, 32..40, 100..116, 118..prefix] {
            memory::copy_exact(
                base.raw
                    .bytes
                    .get_mut(span.clone())
                    .ok_or(Error::InvalidInode)?,
                self.bytes.get(span).ok_or(Error::InvalidInode)?,
            )?;
        }
        if matches!(self.payload, DeltaPayload::Inline(_)) && !directory {
            for span in [40..100, prefix..self.bytes.len()] {
                memory::copy_exact(
                    base.raw
                        .bytes
                        .get_mut(span.clone())
                        .ok_or(Error::InvalidInode)?,
                    self.bytes.get(span).ok_or(Error::InvalidInode)?,
                )?;
            }
        }
        if directory {
            base.raw.set_flags(inode.flags())?;
            base.raw.set_encoded_size(
                base.raw
                    .encoding
                    .encode_directory_size(DirectorySize::from_bytes(inode.size().bytes()))?,
            )?;
        }
        base.raw.into_live()
    }

    /// New allocations acquire only storage described completely by this record and range operands.
    /// Inline attribute references need independent acquisition and therefore cannot be imported.
    /// # Errors
    /// Rejects missing payload bodies, unsupported/protected storage, attribute ownership or metadata.
    pub(in crate::volume) fn initialize(
        self,
        mut allocation: AllocatedInodeRecord,
        block_size: BlockSize,
    ) -> Result<LiveInodeRecord> {
        if self.bytes.len() > allocation.raw.bytes.len()
            || (matches!(self.payload, DeltaPayload::Inline(_))
                && self.bytes.len() != allocation.raw.bytes.len())
        {
            return Err(Error::InvalidInode);
        }
        if let DeltaPayload::Inline(attributes) = &self.payload
            && attributes.attribute_references().next().is_some()
        {
            return Err(Error::UnsupportedJournal);
        }
        memory::copy_exact(
            allocation
                .raw
                .bytes
                .get_mut(..self.bytes.len())
                .ok_or(Error::InvalidInode)?,
            self.bytes,
        )?;
        let kind = InodeMode::from_disk(allocation.raw.mode()?)?.kind();
        if matches!(self.payload, DeltaPayload::Mapping) {
            if kind != InodeKind::Symlink || allocation.raw.flags()?.has_extent_tree() {
                let empty = MutableExtentTree::from_extents(Vec::new())?
                    .serialize(block_size, ExtentTreeContext::none())?;
                allocation.raw.set_extent_root_bytes(empty.inode_root())?;
            }
            if kind == InodeKind::Directory {
                allocation
                    .raw
                    .set_flags(allocation.raw.flags()?.without_indexed_directory())?;
                allocation.raw.set_encoded_size(
                    allocation
                        .raw
                        .encoding
                        .encode_directory_size(DirectorySize::from_bytes(0))?,
                )?;
            }
        }
        allocation.raw.set_encoded_allocation_size(
            allocation
                .raw
                .encoding
                .encode_allocation_size(FileAllocationSize::from_bytes(0))?,
        )?;
        let inode = allocation.raw.parse()?;
        if matches!(inode.storage(), InodeStorage::UnsupportedBlockMap)
            || inode.protection().is_encrypted()
            || inode.protection().is_verity()
            || allocation.raw.xattr_block()?.is_some()
        {
            return Err(Error::UnsupportedJournal);
        }
        allocation.raw.into_live()
    }
}
