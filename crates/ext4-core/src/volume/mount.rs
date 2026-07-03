//! Mount typestates and journal backend selection for ext4 volumes.

use super::scope::*;
use super::transaction::JournalTransaction;

/// Read-only mounted volume state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadOnlyMount;

/// Mount-time context that keeps external fscrypt material out of superblock parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountContext<N> {
    /// fscrypt master keys available for this mount.
    fscrypt_keys: FscryptKeySet,
    /// Source of fresh nonces for newly-created encrypted inodes.
    fscrypt_nonce_generator: N,
}

impl<N> MountContext<N> {
    /// Creates a mount context with explicit fscrypt keys and nonce source.
    #[must_use]
    pub const fn new(fscrypt_keys: FscryptKeySet, fscrypt_nonce_generator: N) -> Self {
        Self {
            fscrypt_keys,
            fscrypt_nonce_generator,
        }
    }

    /// fscrypt master keys available to this mount.
    #[must_use]
    pub(super) const fn fscrypt_keys(&self) -> &FscryptKeySet {
        &self.fscrypt_keys
    }

    /// Returns the next fscrypt nonce for a new encrypted inode.
    /// # Errors
    ///
    /// Returns an error when the mounted fscrypt nonce source cannot produce a valid file nonce.
    pub(super) fn next_fscrypt_file_nonce(&mut self) -> Result<FscryptFileNonce>
    where
        N: FscryptNonceGenerator,
    {
        self.fscrypt_nonce_generator.next_file_nonce()
    }

    /// Adds one fscrypt master key to this mount context.
    ///
    /// # Errors
    /// Returns an error when the key identifier is already present.
    pub(super) fn add_fscrypt_key(&mut self, key: FscryptMasterKey) -> Result<()> {
        self.fscrypt_keys.insert(key)
    }

    /// Removes one fscrypt master key from this mount context.
    #[must_use]
    pub(super) fn remove_fscrypt_key(
        &mut self,
        identifier: FscryptKeyIdentifier,
    ) -> Option<FscryptMasterKey> {
        self.fscrypt_keys.remove(identifier)
    }

    /// Returns this mount context's fscrypt key presence for one identifier.
    #[must_use]
    pub(super) fn fscrypt_key_presence(
        &self,
        identifier: FscryptKeyIdentifier,
    ) -> FscryptKeyPresence {
        if self.fscrypt_keys.contains(identifier) {
            FscryptKeyPresence::Present
        } else {
            FscryptKeyPresence::Absent
        }
    }
}

/// Journal stored as a hidden ext4 inode on the filesystem device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalJournal {
    /// Clean journal state ready to accept write transactions.
    pub(super) journal: Journal,
}

/// External journal stored on a separate journal device.
#[derive(Debug)]
pub struct ExternalJournal<J> {
    /// External journal block device.
    pub(super) device: J,
    /// Clean journal state loaded from the external device.
    pub(super) journal: Journal,
}

/// Journaled read-write mounted volume state.
#[derive(Debug)]
pub(super) struct JournaledMount<J> {
    /// Journal backend selected at mount.
    pub(super) journal: J,
    /// Mounted cluster reference counts constructed before any mutation.
    pub(super) clusters: ClusterReferenceIndex,
}

/// Mounted ext4 volume with typestate-selected mutation capability.
#[derive(Debug)]
pub(super) struct MountedVolume<D, State, N> {
    /// Backing filesystem block device.
    pub(super) device: D,
    /// Validated superblock and mount policy.
    pub(super) superblock: Superblock,
    /// External mount context such as fscrypt unlock keys.
    pub(super) mount_context: MountContext<N>,
    /// Typestate carrying read-only or journaled read-write capability.
    pub(super) state: State,
}

/// Mounted read-only ext4 volume.
#[derive(Debug)]
#[cfg(test)]
pub(crate) struct ReadOnlyVolume<D, N> {
    /// Private mounted state with read traversal capability only.
    pub(super) volume: MountedVolume<D, ReadOnlyMount, N>,
}

/// Mounted journaled ext4 volume with mutation capability.
#[derive(Debug)]
pub struct JournaledVolume<D, N, J = InternalJournal> {
    /// Private mounted state with journaled mutation capability.
    pub(super) volume: MountedVolume<D, JournaledMount<J>, N>,
}

/// Stable filesystem identity exposed outside the raw superblock domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeIdentity {
    /// Filesystem UUID.
    pub(super) uuid: crate::disk_format::superblock::FilesystemUuid,
    /// Filesystem volume label.
    pub(super) label: Ext4VolumeLabel,
}

impl VolumeIdentity {
    /// Filesystem UUID.
    #[must_use]
    pub const fn uuid(self) -> crate::disk_format::superblock::FilesystemUuid {
        self.uuid
    }

    /// Filesystem volume label.
    #[must_use]
    pub const fn label(self) -> Ext4VolumeLabel {
        self.label
    }
}

/// Allocation geometry exposed outside the raw superblock domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeGeometry {
    /// Filesystem block size.
    pub(super) block_size: BlockSize,
    /// Allocation cluster size.
    pub(super) cluster_size: crate::disk_format::superblock::ClusterSize,
    /// Total allocation cluster count.
    pub(super) cluster_count: crate::disk_format::superblock::ClusterCount,
    /// Currently free allocation cluster count.
    pub(super) free_cluster_count: FreeClusterCount,
}

impl VolumeGeometry {
    /// Filesystem block size.
    #[must_use]
    pub const fn block_size(self) -> BlockSize {
        self.block_size
    }

    /// Allocation cluster size.
    #[must_use]
    pub const fn cluster_size(self) -> crate::disk_format::superblock::ClusterSize {
        self.cluster_size
    }

    /// Total allocation cluster count.
    #[must_use]
    pub const fn cluster_count(self) -> crate::disk_format::superblock::ClusterCount {
        self.cluster_count
    }

    /// Currently free allocation cluster count.
    #[must_use]
    pub const fn free_cluster_count(self) -> FreeClusterCount {
        self.free_cluster_count
    }
}

#[cfg(test)]
impl<D: BlockReader, N> MountedVolume<D, ReadOnlyMount, N> {
    /// Validates an ext4 volume and constructs read-only mounted state.
    ///
    /// # Errors
    /// Returns an error when the device does not contain a supported ext4 superblock.
    pub(super) fn mount(device: D, mount_context: MountContext<N>) -> Result<Self> {
        let superblock = Superblock::read_from(&device)?;
        Ok(Self {
            device,
            superblock,
            mount_context,
            state: ReadOnlyMount,
        })
    }
}

#[cfg(test)]
impl<D: BlockReader, N> ReadOnlyVolume<D, N> {
    /// Validates an ext4 volume and constructs read-only mounted state.
    ///
    /// # Errors
    /// Returns an error when the device does not contain a supported ext4 superblock.
    pub(crate) fn mount(device: D, mount_context: MountContext<N>) -> Result<Self> {
        Ok(Self {
            volume: MountedVolume::mount(device, mount_context)?,
        })
    }
}

impl<D: BlockWriter, N: FscryptNonceGenerator + Clone>
    MountedVolume<D, JournaledMount<InternalJournal>, N>
{
    /// Replays the internal journal boundary and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when the device is not a supported journaled ext4 volume.
    pub(super) fn mount_internal_journal(
        mut device: D,
        mount_context: MountContext<N>,
    ) -> Result<Self> {
        let mut superblock = Superblock::read_write_from(&device)?;
        let JournalMode::Internal(journal_inode_id) = superblock.journal_mode() else {
            return Err(Error::UnsupportedJournal);
        };
        let read_only = MountedVolume::<&mut D, ReadOnlyMount, N> {
            device: &mut device,
            superblock,
            mount_context: mount_context.clone(),
            state: ReadOnlyMount,
        };
        let journal_inode = read_only.read_inode_record(journal_inode_id)?;
        let journal = Journal::<LoadedJournal>::from_inode(
            &journal_inode,
            superblock.block_size(),
            superblock.block_count().as_u64(),
            &read_only.device,
        )?;
        let recovery_state = superblock.recovery_state();
        let journal = journal.replay_and_checkpoint_internal(
            &mut device,
            superblock.block_size(),
            recovery_state,
        )?;
        let journal = InternalJournal { journal };
        if recovery_state == RecoveryState::NeedsRecovery {
            Superblock::clear_recover_on_device(&mut device)?;
            superblock = Superblock::read_write_from(&device)?;
        }
        let clusters = {
            let recovered = MountedVolume::<&mut D, ReadOnlyMount, N> {
                device: &mut device,
                superblock,
                mount_context: mount_context.clone(),
                state: ReadOnlyMount,
            };
            ClusterReferenceIndex::load(&recovered)?
        };
        Ok(Self {
            device,
            superblock,
            mount_context,
            state: JournaledMount { journal, clusters },
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> JournalTransaction<'_, D, N, InternalJournal> {
        JournalTransaction::begin(self, now)
    }
}

impl<D: BlockWriter, N: FscryptNonceGenerator + Clone> JournaledVolume<D, N, InternalJournal> {
    /// Replays the internal journal boundary and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when the device is not a supported journaled ext4 volume.
    pub fn mount(device: D, mount_context: MountContext<N>) -> Result<Self> {
        Ok(Self {
            volume: MountedVolume::mount_internal_journal(device, mount_context)?,
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> JournalTransaction<'_, D, N, InternalJournal> {
        self.volume.begin_transaction(now)
    }
}

impl<D: BlockWriter, N> JournaledVolume<D, N, InternalJournal> {
    /// Persists all filesystem-device writes issued through this mounted volume.
    ///
    /// # Errors
    /// Returns an error when the filesystem backing device cannot guarantee persistence.
    pub fn flush(&mut self) -> Result<()> {
        self.volume.device.flush()
    }
}

impl<D: BlockWriter, J: BlockWriter, N: FscryptNonceGenerator + Clone>
    MountedVolume<D, JournaledMount<ExternalJournal<J>>, N>
{
    /// Replays an external journal and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when either device cannot support the external journal contract.
    pub(super) fn mount_external_journal(
        mut device: D,
        journal_device: J,
        mount_context: MountContext<N>,
    ) -> Result<Self> {
        let mut superblock = Superblock::read_write_from(&device)?;
        let JournalMode::External(journal_uuid) = superblock.journal_mode() else {
            return Err(Error::UnsupportedJournal);
        };
        let journal = Journal::<LoadedJournal>::from_external_device(
            &journal_device,
            superblock.block_size(),
            journal_uuid.bytes(),
            superblock.block_count().as_u64(),
        )?;
        let recovery_state = superblock.recovery_state();
        let mut journal_device = journal_device;
        let journal = journal.replay_and_checkpoint_external(
            &mut device,
            &mut journal_device,
            superblock.block_size(),
            recovery_state,
        )?;
        let journal = ExternalJournal {
            device: journal_device,
            journal,
        };
        if recovery_state == RecoveryState::NeedsRecovery {
            Superblock::clear_recover_on_device(&mut device)?;
            superblock = Superblock::read_write_from(&device)?;
        }
        let clusters = {
            let recovered = MountedVolume::<&mut D, ReadOnlyMount, N> {
                device: &mut device,
                superblock,
                mount_context: mount_context.clone(),
                state: ReadOnlyMount,
            };
            ClusterReferenceIndex::load(&recovered)?
        };
        Ok(Self {
            device,
            superblock,
            mount_context,
            state: JournaledMount { journal, clusters },
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> JournalTransaction<'_, D, N, ExternalJournal<J>> {
        JournalTransaction::begin(self, now)
    }
}

impl<D: BlockWriter, J: BlockWriter, N: FscryptNonceGenerator + Clone>
    JournaledVolume<D, N, ExternalJournal<J>>
{
    /// Replays an external journal and constructs journaled read-write state.
    ///
    /// # Errors
    /// Returns an error when either device cannot support the external journal contract.
    pub fn mount_with_external_journal(
        device: D,
        journal_device: J,
        mount_context: MountContext<N>,
    ) -> Result<Self> {
        Ok(Self {
            volume: MountedVolume::mount_external_journal(device, journal_device, mount_context)?,
        })
    }

    /// Starts a write transaction with caller-supplied inode timestamps.
    #[must_use]
    pub fn begin_transaction(
        &mut self,
        now: Ext4Timestamp,
    ) -> JournalTransaction<'_, D, N, ExternalJournal<J>> {
        self.volume.begin_transaction(now)
    }
}

impl<D: BlockWriter, J: BlockWriter, N> JournaledVolume<D, N, ExternalJournal<J>> {
    /// Persists all journal and filesystem-device writes issued through this mounted volume.
    ///
    /// # Errors
    /// Returns an error when either backing device cannot guarantee persistence.
    pub fn flush(&mut self) -> Result<()> {
        self.volume.state.journal.device.flush()?;
        self.volume.device.flush()
    }
}
