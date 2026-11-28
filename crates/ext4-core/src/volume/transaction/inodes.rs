//! Exclusive ownership of inode postimages within a restartable mutation pass.

use super::*;
use crate::volume::inode_record::AttributeInodeRecord;

/// Insertion-ordered postimages with one slot per inode, including retired inode identities.
#[derive(Debug, Default)]
pub(super) struct StagedInodes {
    /// The stable ordinal is private. Only this owner can issue edits or retire a record.
    records: Vec<InodeStage>,
}

/// An edit keeps the prior record visible to policy and allocation reads until the successor lands.
#[derive(Debug)]
struct InodeStage {
    /// Most recent accepted inode image.
    record: StagedInodeRecord,
    /// Edit registration is owned by the same slot as its predecessor.
    admission: InodeEditAdmission,
}

/// At most one working copy can produce a successor to a staged predecessor.
#[derive(Debug)]
enum InodeEditAdmission {
    /// The staged image is available for editing or serialization.
    Available,
    /// Only the issued edit can replace the staged image.
    Editing,
}

/// Unique edit of one record in this pass. Failure abandons the pass and its unfinished edits.
#[derive(Debug)]
#[must_use = "finish the inode edit before resolving the mutation"]
pub(super) struct InodeEdit {
    /// Stable private position in the originating pass.
    position: usize,
    /// Identity the successor must preserve.
    id: InodeId,
}

impl StagedInodes {
    /// Finds the staged predecessor by inode identity.
    pub(super) fn find(&self, id: InodeId) -> Option<&StagedInodeRecord> {
        self.records
            .iter()
            .map(|slot| &slot.record)
            .find(|record| record.id() == id)
    }

    /// Number of staged records, including records that retired in this pass.
    pub(super) fn len(&self) -> usize {
        self.records.len()
    }

    /// Borrows a record by enumeration order without granting edit authority.
    pub(super) fn record_at(&self, position: usize) -> Option<&StagedInodeRecord> {
        self.records.get(position).map(|slot| &slot.record)
    }

    /// Admits the single-record shape eligible for inode-only delta encoding.
    pub(super) fn only_live(&self) -> Option<&LiveInodeRecord> {
        match self.records.as_slice() {
            [
                InodeStage {
                    record: StagedInodeRecord::Live(record),
                    admission: InodeEditAdmission::Available,
                },
            ] => Some(record),
            _ => None,
        }
    }

    /// Iterates postimages for serialization once no private edit remains.
    /// # Errors
    /// Rejects finalization with an outstanding inode edit.
    pub(super) fn resolved(&self) -> Result<impl Iterator<Item = &StagedInodeRecord>> {
        if self
            .records
            .iter()
            .any(|entry| matches!(entry.admission, InodeEditAdmission::Editing))
        {
            return Err(Error::InvalidInode);
        }
        Ok(self.records.iter().map(|slot| &slot.record))
    }

    /// Registers a new staged identity, including initial orphan recovery records.
    /// # Errors
    /// Rejects an existing identity or fallible vector growth.
    pub(super) fn insert(&mut self, record: StagedInodeRecord) -> Result<()> {
        if self.find(record.id()).is_some() {
            return Err(Error::InvalidInode);
        }
        self.records.try_push(InodeStage {
            record,
            admission: InodeEditAdmission::Available,
        })
    }

    /// Starts a live edit while keeping its predecessor available for independent reads.
    /// # Errors
    /// Rejects an absent, non-live or already edited identity and propagates allocation failure.
    pub(super) fn edit_live(&mut self, id: InodeId) -> Result<(InodeEdit, LiveInodeRecord)> {
        let (position, slot) = self
            .records
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.record.id() == id)
            .ok_or(Error::InvalidInode)?;
        if !matches!(slot.admission, InodeEditAdmission::Available) {
            return Err(Error::InvalidInode);
        }
        let working = slot.record.clone_live()?;
        slot.admission = InodeEditAdmission::Editing;
        Ok((InodeEdit { position, id }, working))
    }

    /// Accepts the live successor or its terminal retirement.
    /// # Errors
    /// Rejects a successor of a different identity or a token without its active predecessor.
    pub(super) fn finish_edit(
        &mut self,
        edit: InodeEdit,
        successor: StagedInodeRecord,
    ) -> Result<()> {
        let slot = self
            .records
            .get_mut(edit.position)
            .ok_or(Error::InvalidInode)?;
        if edit.id != successor.id()
            || slot.record.id() != edit.id
            || !matches!(slot.admission, InodeEditAdmission::Editing)
            || !matches!(
                successor,
                StagedInodeRecord::Live(_) | StagedInodeRecord::Deleted(_)
            )
        {
            return Err(Error::InvalidInode);
        }
        slot.record = successor;
        slot.admission = InodeEditAdmission::Available;
        Ok(())
    }

    /// Updates the separate attribute-value inode role.
    /// # Errors
    /// Rejects another staged role or allocation failure.
    pub(super) fn update_attribute(&mut self, record: AttributeInodeRecord) -> Result<()> {
        self.attribute_successor(record.into())
    }

    /// Retires an attribute-value inode after its last reference was removed.
    /// # Errors
    /// Rejects another staged role or allocation failure.
    pub(super) fn retire_attribute(&mut self, record: DeletedInodeRecord) -> Result<()> {
        self.attribute_successor(record.into())
    }

    /// Replaces an attribute record or records its first update.
    /// # Errors
    /// Returns an inode-role conflict or fallible vector growth.
    fn attribute_successor(&mut self, record: StagedInodeRecord) -> Result<()> {
        if let Some(slot) = self
            .records
            .iter_mut()
            .find(|slot| slot.record.id() == record.id())
        {
            if !matches!(slot.record, StagedInodeRecord::Attribute(_))
                || !matches!(slot.admission, InodeEditAdmission::Available)
            {
                return Err(Error::InvalidXattr);
            }
            slot.record = record;
            Ok(())
        } else {
            self.records.try_push(InodeStage {
                record,
                admission: InodeEditAdmission::Available,
            })
        }
    }
}
