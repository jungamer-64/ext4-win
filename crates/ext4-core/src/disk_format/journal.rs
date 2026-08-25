//! JBD2 journal loading, replay, checkpointing, and commit construction.
//!
//! The journal code is modeled as typestates: loaded journals must be replayed
//! into a clean state before write transactions can commit, dirty transactions
//! must become durable before checkpoint, and checkpointed transactions can then
//! advance the superblock tail. This keeps crash-ordering rules out of ad hoc
//! booleans in the volume layer.

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::disk::block::{BlockAddress, BlockSize, ByteOffset};
use crate::disk::checksum::ext4_crc32c;
use crate::disk::endian::{
    DiskOffset, be_u16, be_u32, be_u64, le_u16, le_u32, put_be_u16, put_be_u32,
};
use crate::disk::storage::{
    CompletedStorageTransfer, OperationDevice, StorageCompletion, StorageRequest,
    StorageRequestIdentity, StorageTarget,
};
use crate::disk_format::extent::{ExtentInitialization, ExtentTree, ExtentTreeContext};
use crate::disk_format::inode::Inode;
use crate::disk_format::superblock::{FilesystemUuid, JournalUuid, RecoveryState, Superblock};
use crate::error::{Error, Result};
use crate::memory::{self, FallibleVec};

// Common JBD2 block header fields. JBD2 stores its control structures big-endian.
/// Magic value that prefixes every JBD2 control block.
const JBD2_MAGIC: u32 = 0xC03B_3998;
/// JBD2 block type for transaction descriptors.
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
/// JBD2 block type for transaction commits.
const JBD2_COMMIT_BLOCK: u32 = 2;
/// JBD2 block type for v1 journal superblocks.
const JBD2_SUPERBLOCK_V1: u32 = 3;
/// JBD2 block type for v2 journal superblocks.
const JBD2_SUPERBLOCK_V2: u32 = 4;
/// JBD2 block type for revoke records.
const JBD2_REVOKE_BLOCK: u32 = 5;
/// Compatible feature bit for the legacy transaction checksum format.
const JBD2_FEATURE_COMPAT_CHECKSUM: u32 = 0x0001;

/// Builds a JBD2 control-structure field offset.
const fn disk_offset(offset: usize) -> DiskOffset {
    DiskOffset::new(offset)
}

// Incompatible feature bits are validated before replay because unsupported
// features can change transaction interpretation.
/// Incompatible feature bit for revoke records.
const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
/// Incompatible feature bit for 64-bit journal block tags.
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
/// Incompatible feature bit for asynchronous commit checksums.
const JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
/// Incompatible feature bit for v2 journal checksums.
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
/// Incompatible feature bit for v3 journal checksums.
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
/// Incompatible feature bit for fast commit areas.
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
/// JBD2 incompatible feature mask supported by replay and commit.
const JBD2_SUPPORTED_INCOMPAT: u32 = JBD2_FEATURE_INCOMPAT_REVOKE
    | JBD2_FEATURE_INCOMPAT_64BIT
    | JBD2_FEATURE_INCOMPAT_CSUM_V2
    | JBD2_FEATURE_INCOMPAT_CSUM_V3;

// Descriptor tag flags define how following payload blocks are decoded.
/// Descriptor tag flag for escaped data blocks that begin with the JBD2 magic.
const JBD2_TAG_FLAG_ESCAPE: u32 = 0x0001;
/// Descriptor tag flag omitting the repeated filesystem UUID.
const JBD2_TAG_FLAG_SAME_UUID: u32 = 0x0002;
/// Descriptor tag flag marking the following payload block as deleted.
const JBD2_TAG_FLAG_DELETED: u32 = 0x0004;
/// Descriptor tag flag marking the final tag in a descriptor block.
const JBD2_TAG_FLAG_LAST_TAG: u32 = 0x0008;

// JBD2 checksum and layout constants used by both replay and new commits.
/// JBD2 checksum type value for CRC32C.
const JBD2_CHECKSUM_CRC32C: u8 = 4;
/// Bytes occupied by the common JBD2 control block header.
const JOURNAL_HEADER_BYTES: usize = 12;
/// Byte offset of the checksum that authenticates a metadata-checksummed commit block.
const JOURNAL_COMMIT_CHECKSUM_OFFSET: usize = 0x10;
/// Full commit-header storage, including the trailing alignment bytes before block padding.
const JOURNAL_COMMIT_HEADER_BYTES: usize = 0x40;
/// Bytes occupied by the JBD2 superblock payload.
const JOURNAL_SUPERBLOCK_BYTES: usize = 1024;
/// One descriptor block and one commit block are the minimum transaction overhead.
const JOURNAL_MIN_TRANSACTION_BLOCKS: u32 = 2;
/// Byte offset of the ext-family superblock on an external journal device.
const EXTERNAL_EXT_SUPERBLOCK_OFFSET: u64 = 1024;
/// ext-family superblock byte length.
const EXTERNAL_EXT_SUPERBLOCK_BYTES: usize = 1024;
/// ext-family superblock magic.
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
/// ext-family incompatible feature selecting a dedicated journal device.
const EXT4_FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;

#[derive(Clone, Debug, Eq, PartialEq)]
/// Full filesystem metadata block supplied to the journal commit path.
pub(crate) struct MetadataBlock {
    /// Filesystem block address.
    block: BlockAddress,
    /// Complete metadata block bytes.
    bytes: Vec<u8>,
}

impl MetadataBlock {
    /// Creates a complete metadata block image for a journal transaction.
    pub(crate) fn new(block: BlockAddress, bytes: Vec<u8>) -> Self {
        Self { block, bytes }
    }

    /// Returns the filesystem block address.
    pub(crate) const fn block(&self) -> BlockAddress {
        self.block
    }

    /// Returns the full metadata block bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the mutable full metadata block bytes before commit encoding.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// One fully allocated storage write in a journal or checkpoint phase.
#[derive(Debug)]
pub(crate) struct PlannedStorageWrite {
    /// Device that receives this write.
    target: StorageTarget,
    /// Starting device byte offset.
    offset: ByteOffset,
    /// Complete owned write image.
    bytes: Vec<u8>,
}

impl PlannedStorageWrite {
    /// Builds one fully owned write plan.
    pub(crate) const fn new(target: StorageTarget, offset: ByteOffset, bytes: Vec<u8>) -> Self {
        Self {
            target,
            offset,
            bytes,
        }
    }

    /// Converts this plan into the concrete storage request submitted by the reactor.
    pub(crate) fn into_request(self) -> StorageRequest {
        StorageRequest::Write {
            target: self.target,
            offset: self.offset,
            buffer: self.bytes,
        }
    }
}

/// Home-block and clean-superblock work detached from the commit visibility gate.
#[derive(Debug)]
pub(crate) struct PreparedJournalCheckpoint {
    /// Preallocated filesystem home-block writes.
    home_writes: Vec<PlannedStorageWrite>,
    /// Preallocated journal superblock write that marks the checkpoint clean.
    clean_write: PlannedStorageWrite,
    /// Clean coordinator journal state published after the clean write is durable.
    clean_journal: Journal<CleanJournal>,
}

impl PreparedJournalCheckpoint {
    /// Consumes the checkpoint into its preallocated parts.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<PlannedStorageWrite>,
        PlannedStorageWrite,
        Journal<CleanJournal>,
    ) {
        (self.home_writes, self.clean_write, self.clean_journal)
    }
}

/// Journal transaction serialized completely before its first lower write.
#[derive(Debug)]
pub(crate) struct PreparedJournalCommit {
    /// Dirty-superblock, descriptor, and journal data writes before the first durability flush.
    precommit_writes: Vec<PlannedStorageWrite>,
    /// Commit-record write issued after precommit writes are durable.
    commit_write: PlannedStorageWrite,
    /// Journal device whose flush establishes commit durability.
    journal_target: StorageTarget,
    /// Coordinator journal state after commit durability and before checkpoint completion.
    durable_journal: Journal<DirtyJournal>,
    /// Immutable metadata overlay published at commit durability.
    overlay: Vec<MetadataBlock>,
    /// Independent checkpoint work prepared before the first lower write.
    checkpoint: PreparedJournalCheckpoint,
}

/// Transaction checksum profile selected by validated JBD2 features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalChecksumProfile {
    /// Descriptor, payload, and commit checksums are absent.
    None,
    /// Descriptor tails and truncated 16-bit payload checksums are present.
    V2,
    /// Descriptor tails and full 32-bit payload checksums are present.
    V3,
}

/// Validated JBD2 interpretation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalProfile {
    /// Payload and control-block checksum representation.
    checksum: JournalChecksumProfile,
    /// Whether tags and revoke records carry 64-bit filesystem block addresses.
    block_numbers_64bit: bool,
    /// Whether revoke control blocks are part of the selected profile.
    revokes: bool,
}

impl JournalProfile {
    /// Validates feature bits that change JBD2 record interpretation.
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedJournal`] for any ambiguous or unsupported wire profile.
    fn from_superblock(superblock: &JournalSuperblock) -> Result<Self> {
        if superblock.compat & JBD2_FEATURE_COMPAT_CHECKSUM != 0
            || superblock.compat & !JBD2_FEATURE_COMPAT_CHECKSUM != 0
            || superblock.ro_compat != 0
            || superblock.incompat
                & (JBD2_FEATURE_INCOMPAT_FAST_COMMIT | JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)
                != 0
            || superblock.incompat & !JBD2_SUPPORTED_INCOMPAT != 0
            || superblock.errno != 0
        {
            return Err(Error::UnsupportedJournal);
        }
        let v2 = superblock.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2 != 0;
        let v3 = superblock.incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0;
        let checksum = match (v2, v3) {
            (false, false) => JournalChecksumProfile::None,
            (true, false) => JournalChecksumProfile::V2,
            (false, true) => JournalChecksumProfile::V3,
            (true, true) => return Err(Error::UnsupportedJournal),
        };
        if checksum != JournalChecksumProfile::None
            && superblock.checksum_type != JBD2_CHECKSUM_CRC32C
        {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            checksum,
            block_numbers_64bit: superblock.incompat & JBD2_FEATURE_INCOMPAT_64BIT != 0,
            revokes: superblock.incompat & JBD2_FEATURE_INCOMPAT_REVOKE != 0,
        })
    }

    /// Returns whether descriptor, payload, revoke, and commit checksums are present.
    const fn has_metadata_checksums(self) -> bool {
        !matches!(self.checksum, JournalChecksumProfile::None)
    }

    /// Returns whether descriptor tags carry full-width v3 checksums.
    const fn has_csum_v3(self) -> bool {
        matches!(self.checksum, JournalChecksumProfile::V3)
    }

    /// Returns whether block addresses carry a high 32-bit word.
    const fn has_64bit(self) -> bool {
        self.block_numbers_64bit
    }

    /// Returns whether revoke control blocks are valid in this profile.
    const fn has_revokes(self) -> bool {
        self.revokes
    }
}

/// Validated physical and circular JBD2 address domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalGeometry {
    /// Block size shared by the filesystem and journal device.
    block_size: BlockSize,
    /// Circular range containing transaction records.
    ring: JournalRing,
}

impl JournalGeometry {
    /// Validates block size and circular-ring geometry against physical capacity.
    /// # Errors
    ///
    /// Returns an error when the wire block size or ring bounds disagree with the backing layout.
    fn from_superblock(
        superblock: &JournalSuperblock,
        block_size: BlockSize,
        capacity_blocks: u32,
        expected_first: u32,
    ) -> Result<Self> {
        if superblock.block_size != block_size.bytes() {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            block_size,
            ring: JournalRing::new(superblock, capacity_blocks, expected_first)?,
        })
    }
}

/// Next sequence and clean-log head used by all Journal typestates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalCursor {
    /// Sequence expected for the next committed transaction.
    sequence: JournalSequence,
    /// Logical ring block where the next transaction begins.
    head: u32,
}

impl JournalCursor {
    /// Recovers the next transaction sequence and head from clean or dirty superblock state.
    ///
    /// A never-started v2 journal can retain zero in the later-added `s_head` field. Zero is not a
    /// ring address, so only that clean initial state is canonicalized to the first usable block.
    /// # Errors
    ///
    /// Returns [`Error::JournalCorrupt`] when the selected head is outside the validated ring.
    fn from_superblock(superblock: &JournalSuperblock, ring: JournalRing) -> Result<Self> {
        let (sequence, head) = if superblock.start != 0 {
            (superblock.sequence, superblock.start)
        } else {
            let clean_head = match superblock.version {
                JournalSuperblockVersion::V1 => ring.first,
                JournalSuperblockVersion::V2 if superblock.head == 0 => ring.first,
                JournalSuperblockVersion::V2 => superblock.head,
            };
            (superblock.sequence.next(), clean_head)
        };
        if head < ring.first || head >= ring.maxlen {
            return Err(Error::JournalCorrupt);
        }
        Ok(Self { sequence, head })
    }
}

impl PreparedJournalCommit {
    /// Consumes the commit into its preallocated phase values.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<PlannedStorageWrite>,
        PlannedStorageWrite,
        StorageTarget,
        Journal<DirtyJournal>,
        Vec<MetadataBlock>,
        PreparedJournalCheckpoint,
    ) {
        (
            self.precommit_writes,
            self.commit_write,
            self.journal_target,
            self.durable_journal,
            self.overlay,
            self.checkpoint,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// JBD2 journal with typestate-tracked replay and commit phases.
pub(crate) struct Journal<State = CleanJournal> {
    /// Physical location of the journal blocks.
    location: JournalLocation,
    /// Parsed journal superblock kept as the mutable journal metadata source.
    superblock: JournalSuperblock,
    /// Feature-dependent wire interpretation.
    profile: JournalProfile,
    /// Validated block and circular-log geometry.
    geometry: JournalGeometry,
    /// Next sequence and clean head.
    cursor: JournalCursor,
    /// Filesystem block count used to reject journal entries outside the volume.
    filesystem_blocks: u64,
    /// Typestate marker for loaded, clean, or commit-durable journal state.
    state: PhantomData<State>,
}

/// Journal loaded from disk but not yet replayed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LoadedJournal;

/// Result of probing one external-journal candidate by its expected UUID.
#[derive(Debug)]
pub(crate) enum ExternalJournalLoad {
    /// Candidate UUID differs and discovery may continue.
    Mismatch,
    /// Candidate exactly matches and carries a fully validated loaded journal.
    Match(Journal<LoadedJournal>),
}

/// Journal whose committed transactions have been checkpointed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CleanJournal;

/// Journal after descriptor/data/commit blocks have been durably written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirtyJournal;

/// Bounded three-pass recovery that owns every lower transfer until completion.
#[derive(Debug)]
pub(crate) struct JournalRecoveryOperation {
    /// Loaded journal whose wire profile and geometry were validated before recovery.
    journal: Journal<LoadedJournal>,
    /// Whether committed payloads are replayed or only discarded as stale records.
    policy: RecoveryPolicy,
    /// Current pass or durability boundary.
    phase: RecoveryPhase,
    /// Cursor and transaction-local state for the active pass.
    walk: RecoveryWalk,
    /// Committed-prefix boundary and allocation maxima established by the scan pass.
    summary: RecoverySummary,
    /// Preallocated tags for at most one transaction.
    tags: Vec<RecoveryTag>,
    /// Latest revoke sequence for each encountered home block.
    revokes: Vec<RecoveryRevoke>,
    /// One reusable journal payload/control buffer.
    buffer: Option<Vec<u8>>,
    /// Pre-serialized clean journal superblock write image.
    clean_write: Option<Vec<u8>>,
    /// Clean typestate prepared before the first home write.
    clean_journal: Option<Journal<CleanJournal>>,
    /// Exact request identity and semantic continuation owned by the operation.
    in_flight: Option<RecoveryInFlight>,
    /// Pending control, payload, or home-write action in the active pass.
    pending: RecoveryPending,
    /// Whether replay issued at least one home-block write.
    wrote_home: bool,
    /// Proof that a checksum-invalid primary block has a committed, independently validated
    /// replacement before any journal-clean transition can begin.
    primary_repair: PrimaryRepairValidation,
}

/// Recovery action selected from the primary ext4 recovery marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryPolicy {
    /// Replay the validated committed prefix into filesystem home blocks.
    Replay,
    /// Treat committed records as stale and recover only the next journal cursor.
    Discard,
}

/// Validation state for journal-authoritative primary-superblock repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrimaryRepairValidation {
    /// Ordinary recovery began from a checksum-valid primary superblock.
    NotRequired,
    /// Recovery bootstrap used provisional geometry; no committed replacement has been validated.
    Required {
        /// Filesystem block containing the primary superblock.
        home: BlockAddress,
    },
    /// A committed JBD2 payload carries a checksum-valid replacement primary superblock.
    Validated {
        /// Filesystem block containing the primary superblock.
        home: BlockAddress,
        /// Transaction whose payload established repair authority.
        sequence: JournalSequence,
    },
}

/// Recovery pass and durability state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryPhase {
    /// Locate the continuous committed prefix and compute allocation maxima.
    Scan,
    /// Revalidate every committed structure, payload, address, and revoke before writes.
    Validate,
    /// Re-read and replay one payload buffer at a time.
    Replay,
    /// Flush replayed home blocks before invalidating the journal tail.
    FlushFilesystem,
    /// Persist the clean journal cursor.
    WriteCleanJournal,
    /// Make the clean journal cursor durable.
    FlushJournal,
    /// Recovery is complete and the clean journal may be published.
    Complete,
}

/// Cursor and transaction-local counters reused by each recovery pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryWalk {
    /// Next logical journal block to inspect.
    cursor: u32,
    /// Transaction sequence expected at `cursor`.
    sequence: JournalSequence,
    /// Ring blocks consumed by this pass.
    consumed: u32,
    /// Tags observed in the scan pass's current transaction.
    scan_transaction_tags: usize,
    /// Revoke records observed in the scan pass's current transaction.
    scan_transaction_revokes: usize,
}

/// Bounds and end cursor established without retaining payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoverySummary {
    /// Logical block where the first candidate transaction begins.
    start_cursor: u32,
    /// First transaction sequence expected in the journal.
    start_sequence: JournalSequence,
    /// Logical block immediately after the last committed transaction.
    end_cursor: u32,
    /// First sequence not contained in the committed prefix.
    next_sequence: JournalSequence,
    /// Maximum tag count in any one committed transaction.
    max_transaction_tags: usize,
    /// Total revoke record count in the committed prefix.
    revoke_records: usize,
    /// Number of complete committed transactions.
    transactions: u32,
}

/// One validated descriptor tag retained only for the active transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryTag {
    /// Filesystem home block.
    home: BlockAddress,
    /// Logical journal block containing the payload.
    journal_block: u32,
    /// Transaction sequence used by checksum and revoke decisions.
    sequence: JournalSequence,
    /// Descriptor flags controlling escape and deletion semantics.
    flags: u32,
    /// Expected v2/v3 payload checksum.
    checksum: u32,
}

/// Latest sequence that revoked one filesystem home block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryRevoke {
    /// Revoked filesystem home block.
    block: BlockAddress,
    /// Latest transaction sequence carrying its revoke record.
    sequence: JournalSequence,
}

/// Local action waiting to be submitted after the previous completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryPending {
    /// Read the next descriptor, revoke, or commit block.
    Control,
    /// Read descriptor payloads in the half-open tag range.
    Payload {
        /// Next tag whose payload must be read.
        next: usize,
        /// Exclusive tag-range end for this descriptor.
        end: usize,
    },
    /// Move the returned payload buffer into one filesystem home write.
    HomeWrite {
        /// Filesystem block selected by the validated tag.
        home: BlockAddress,
        /// Next tag after this home write completes.
        next: usize,
        /// Exclusive descriptor tag range end.
        end: usize,
    },
}

/// Request continuation retained while the buffer belongs to the lower stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryInFlight {
    /// Exact physical transfer identity.
    identity: StorageRequestIdentity,
    /// Operation-specific meaning of the transfer.
    action: RecoveryIoAction,
}

/// Semantic meaning of one recovery transfer completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryIoAction {
    /// Journal control block read.
    ControlRead,
    /// Journal payload read for the specified prevalidated tag.
    PayloadRead {
        /// Tag whose payload owns the returned buffer.
        index: usize,
        /// Exclusive descriptor tag-range end.
        end: usize,
    },
    /// Filesystem home-block write.
    HomeWrite {
        /// Next tag after the completed home write.
        next: usize,
        /// Exclusive descriptor tag-range end.
        end: usize,
    },
    /// Filesystem durability barrier after replay.
    FilesystemFlush,
    /// Clean journal-superblock write.
    CleanJournalWrite,
    /// Journal durability barrier after the clean write.
    JournalFlush,
}

/// Wrapping JBD2 transaction sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalSequence(u32);

impl JournalSequence {
    /// Creates a sequence number from an on-disk or freshly allocated value.
    const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw sequence number for block encoding.
    const fn get(self) -> u32 {
        self.0
    }

    /// Returns the next sequence with JBD2 wrapping semantics.
    const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Returns the preceding sequence for clean-superblock encoding.
    const fn previous(self) -> Self {
        Self(self.0.wrapping_sub(1))
    }

    /// Compares two wrapping sequence numbers using half-range ordering.
    const fn is_after(self, other: Self) -> bool {
        let distance = self.0.wrapping_sub(other.0);
        distance != 0 && distance < 0x8000_0000
    }
}

impl JournalRecoveryOperation {
    /// Starts bounded recovery from a fully validated loaded journal.
    /// # Errors
    ///
    /// Returns an error when the block buffer or clean typestate cannot be allocated.
    pub(crate) fn new(
        journal: Journal<LoadedJournal>,
        recovery_state: RecoveryState,
    ) -> Result<Self> {
        let policy = match recovery_state {
            RecoveryState::Clean => RecoveryPolicy::Discard,
            RecoveryState::NeedsRecovery => RecoveryPolicy::Replay,
        };
        Self::new_with_primary_repair(journal, policy, PrimaryRepairValidation::NotRequired)
    }

    /// Starts replay only after a committed payload proves it can replace the invalid primary
    /// superblock used for journal discovery.
    /// # Errors
    ///
    /// Returns an error when the journal is already clean or recovery state cannot be allocated.
    pub(crate) fn repairing_primary(journal: Journal<LoadedJournal>) -> Result<Self> {
        let home = Superblock::primary_block(journal.geometry.block_size);
        Self::new_with_primary_repair(
            journal,
            RecoveryPolicy::Replay,
            PrimaryRepairValidation::Required { home },
        )
    }

    /// Builds the common bounded recovery state with an explicit primary-repair contract.
    /// # Errors
    ///
    /// Returns an error when recovery buffers or clean typestate cannot be allocated, or a repair
    /// request has no dirty journal authority.
    fn new_with_primary_repair(
        journal: Journal<LoadedJournal>,
        policy: RecoveryPolicy,
        primary_repair: PrimaryRepairValidation,
    ) -> Result<Self> {
        let block_bytes = usize::try_from(journal.geometry.block_size.bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let buffer = memory::repeated_vec(0_u8, block_bytes)?;
        let start_cursor = journal.cursor.head;
        let start_sequence = journal.cursor.sequence;
        let already_clean = journal.superblock.start() == 0;
        if already_clean && primary_repair != PrimaryRepairValidation::NotRequired {
            return Err(Error::ChecksumMismatch);
        }
        let clean_journal = if already_clean {
            Some(journal.copy_without_state::<CleanJournal>()?)
        } else {
            None
        };
        Ok(Self {
            journal,
            policy,
            phase: if already_clean {
                RecoveryPhase::Complete
            } else {
                RecoveryPhase::Scan
            },
            walk: RecoveryWalk {
                cursor: start_cursor,
                sequence: start_sequence,
                consumed: 0,
                scan_transaction_tags: 0,
                scan_transaction_revokes: 0,
            },
            summary: RecoverySummary {
                start_cursor,
                start_sequence,
                end_cursor: start_cursor,
                next_sequence: start_sequence,
                max_transaction_tags: 0,
                revoke_records: 0,
                transactions: 0,
            },
            tags: Vec::new(),
            revokes: Vec::new(),
            buffer: Some(buffer),
            clean_write: None,
            clean_journal,
            in_flight: None,
            pending: RecoveryPending::Control,
            wrote_home: false,
            primary_repair,
        })
    }

    /// Returns the next owned lower request, or `None` when recovery is complete.
    /// # Errors
    ///
    /// Returns an error for an invalid operation state, address arithmetic failure, or a corrupt
    /// committed prefix discovered before the first home write.
    pub(crate) fn next_request(&mut self) -> Result<Option<StorageRequest>> {
        if self.in_flight.is_some() {
            return Err(Error::DeviceIo);
        }
        self.advance_pass_boundary()?;
        let (request, action) = match self.phase {
            RecoveryPhase::Complete => return Ok(None),
            RecoveryPhase::FlushFilesystem => (
                StorageRequest::Flush {
                    target: StorageTarget::Filesystem,
                },
                RecoveryIoAction::FilesystemFlush,
            ),
            RecoveryPhase::WriteCleanJournal => {
                let offset = self
                    .journal
                    .location
                    .superblock_offset(self.journal.geometry.block_size)?;
                let buffer = self.clean_write.take().ok_or(Error::JournalCorrupt)?;
                (
                    StorageRequest::Write {
                        target: self.journal.location.storage_target(),
                        offset,
                        buffer,
                    },
                    RecoveryIoAction::CleanJournalWrite,
                )
            }
            RecoveryPhase::FlushJournal => (
                StorageRequest::Flush {
                    target: self.journal.location.storage_target(),
                },
                RecoveryIoAction::JournalFlush,
            ),
            RecoveryPhase::Scan | RecoveryPhase::Validate | RecoveryPhase::Replay => {
                match self.pending {
                    RecoveryPending::Control => {
                        let offset = self
                            .journal
                            .offset_of(self.walk.cursor, self.journal.geometry.block_size)?;
                        let buffer = self.buffer.take().ok_or(Error::DeviceIo)?;
                        (
                            StorageRequest::Read {
                                target: self.journal.location.storage_target(),
                                offset,
                                buffer,
                            },
                            RecoveryIoAction::ControlRead,
                        )
                    }
                    RecoveryPending::Payload { next, end } => {
                        let tag = *self.tags.get(next).ok_or(Error::JournalCorrupt)?;
                        let offset = self
                            .journal
                            .offset_of(tag.journal_block, self.journal.geometry.block_size)?;
                        let buffer = self.buffer.take().ok_or(Error::DeviceIo)?;
                        (
                            StorageRequest::Read {
                                target: self.journal.location.storage_target(),
                                offset,
                                buffer,
                            },
                            RecoveryIoAction::PayloadRead { index: next, end },
                        )
                    }
                    RecoveryPending::HomeWrite { home, next, end } => {
                        let offset = self.journal.geometry.block_size.offset_of(home)?;
                        let buffer = self.buffer.take().ok_or(Error::DeviceIo)?;
                        (
                            StorageRequest::Write {
                                target: StorageTarget::Filesystem,
                                offset,
                                buffer,
                            },
                            RecoveryIoAction::HomeWrite { next, end },
                        )
                    }
                }
            }
        };
        self.in_flight = Some(RecoveryInFlight {
            identity: StorageRequestIdentity::from_request(&request),
            action,
        });
        Ok(Some(request))
    }

    /// Consumes the exact completion for the request returned by [`Self::next_request`].
    /// # Errors
    ///
    /// Returns an error for mismatched transfers, I/O failures, checksum failures, or committed
    /// journal corruption.
    pub(crate) fn complete(&mut self, completion: StorageCompletion) -> Result<()> {
        let in_flight = self.in_flight.take().ok_or(Error::DeviceIo)?;
        let transfer = in_flight.identity.complete_transfer(completion)?;
        match in_flight.action {
            RecoveryIoAction::ControlRead => {
                let CompletedStorageTransfer::Read { buffer, .. } = transfer else {
                    return Err(Error::DeviceIo);
                };
                self.process_control_block(&buffer)?;
                self.buffer = Some(buffer);
            }
            RecoveryIoAction::PayloadRead { index, end } => {
                let CompletedStorageTransfer::Read { mut buffer, .. } = transfer else {
                    return Err(Error::DeviceIo);
                };
                let tag = *self.tags.get(index).ok_or(Error::JournalCorrupt)?;
                self.journal
                    .verify_tag_checksum(tag.sequence, &tag.as_journal_tag(), &buffer)?;
                // The tag checksum authenticates the escaped on-disk bytes. Restore the semantic
                // payload only after that check and before any ext4 structure validates it.
                if tag.flags & JBD2_TAG_FLAG_ESCAPE != 0 {
                    if be_u32(&buffer, disk_offset(0))? != 0 {
                        return Err(Error::JournalCorrupt);
                    }
                    put_be_u32(&mut buffer, disk_offset(0), JBD2_MAGIC)?;
                }
                self.validate_primary_repair_payload(tag, &buffer)?;
                let next = index.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                if self.phase == RecoveryPhase::Replay
                    && tag.flags & JBD2_TAG_FLAG_DELETED == 0
                    && !self.is_revoked(tag.home, tag.sequence)
                {
                    self.buffer = Some(buffer);
                    self.pending = RecoveryPending::HomeWrite {
                        home: tag.home,
                        next,
                        end,
                    };
                    self.wrote_home = true;
                } else {
                    self.buffer = Some(buffer);
                    self.pending = if next < end {
                        RecoveryPending::Payload { next, end }
                    } else {
                        RecoveryPending::Control
                    };
                }
            }
            RecoveryIoAction::HomeWrite { next, end } => {
                let CompletedStorageTransfer::Write { buffer, .. } = transfer else {
                    return Err(Error::DeviceIo);
                };
                self.buffer = Some(buffer);
                self.pending = if next < end {
                    RecoveryPending::Payload { next, end }
                } else {
                    RecoveryPending::Control
                };
            }
            RecoveryIoAction::FilesystemFlush => {
                let CompletedStorageTransfer::Flush { .. } = transfer else {
                    return Err(Error::DeviceIo);
                };
                self.phase = RecoveryPhase::WriteCleanJournal;
            }
            RecoveryIoAction::CleanJournalWrite => {
                let CompletedStorageTransfer::Write { .. } = transfer else {
                    return Err(Error::DeviceIo);
                };
                self.phase = RecoveryPhase::FlushJournal;
            }
            RecoveryIoAction::JournalFlush => {
                let CompletedStorageTransfer::Flush { .. } = transfer else {
                    return Err(Error::DeviceIo);
                };
                self.phase = RecoveryPhase::Complete;
            }
        }
        Ok(())
    }

    /// Consumes a completed operation into the clean journal typestate.
    /// # Errors
    ///
    /// Returns an error when lower I/O is still outstanding or the durability sequence has not
    /// reached its terminal state.
    pub(crate) fn into_clean(self) -> Result<Journal<CleanJournal>> {
        if self.phase != RecoveryPhase::Complete || self.in_flight.is_some() {
            return Err(Error::DeviceIo);
        }
        self.clean_journal.ok_or(Error::JournalCorrupt)
    }

    /// Advances pass boundaries that require no lower I/O.
    /// # Errors
    ///
    /// Returns an error for inconsistent committed-prefix cursors or failed pre-write allocation.
    fn advance_pass_boundary(&mut self) -> Result<()> {
        loop {
            if self.phase == RecoveryPhase::Scan
                && self.walk.consumed >= self.journal.usable_log_blocks()?
            {
                self.finish_scan()?;
                continue;
            }
            let at_validated_end =
                matches!(self.phase, RecoveryPhase::Validate | RecoveryPhase::Replay)
                    && self.pending == RecoveryPending::Control
                    && self.walk.sequence == self.summary.next_sequence;
            if !at_validated_end {
                return Ok(());
            }
            if self.walk.cursor != self.summary.end_cursor {
                return Err(Error::JournalCorrupt);
            }
            match self.phase {
                RecoveryPhase::Validate => self.prepare_replay_and_clean()?,
                RecoveryPhase::Replay => {
                    self.phase = if self.wrote_home {
                        RecoveryPhase::FlushFilesystem
                    } else {
                        RecoveryPhase::WriteCleanJournal
                    };
                }
                _ => return Ok(()),
            }
        }
    }

    /// Processes one completed journal control-block read according to the active pass.
    /// # Errors
    ///
    /// Returns an error for an invalid phase or committed control-block corruption.
    fn process_control_block(&mut self, block: &[u8]) -> Result<()> {
        match self.phase {
            RecoveryPhase::Scan => self.scan_control_block(block),
            RecoveryPhase::Validate | RecoveryPhase::Replay => {
                self.validate_or_replay_control_block(block)
            }
            _ => Err(Error::DeviceIo),
        }
    }

    /// Performs the allocation-free committed-prefix scan pass.
    /// # Errors
    ///
    /// Returns an error for arithmetic overflow or unsupported committed revoke structure.
    fn scan_control_block(&mut self, block: &[u8]) -> Result<()> {
        let Ok(header) = Jbd2Header::parse(block) else {
            return self.finish_scan();
        };
        if header.sequence() != self.walk.sequence.get() {
            return self.finish_scan();
        }
        match header.block_type() {
            JBD2_DESCRIPTOR_BLOCK => {
                let Ok(tag_count) = self.journal.descriptor_tag_count_for_scan(block) else {
                    return self.finish_scan();
                };
                self.walk.scan_transaction_tags = self
                    .walk
                    .scan_transaction_tags
                    .checked_add(tag_count)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.advance_walk_blocks(
                    u32::try_from(tag_count)
                        .map_err(|_| Error::ArithmeticOverflow)?
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?,
                )?;
            }
            JBD2_REVOKE_BLOCK => {
                if !self.journal.profile.has_revokes() {
                    return Err(Error::JournalCorrupt);
                }
                let Ok(revoke_count) = self.journal.revoke_count_for_scan(block) else {
                    return self.finish_scan();
                };
                self.walk.scan_transaction_revokes = self
                    .walk
                    .scan_transaction_revokes
                    .checked_add(revoke_count)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.advance_walk_blocks(1)?;
            }
            JBD2_COMMIT_BLOCK => {
                if self
                    .journal
                    .parse_commit_block(block, self.walk.sequence)
                    .is_err()
                {
                    return self.finish_scan();
                }
                if self.walk.scan_transaction_tags == 0 && self.walk.scan_transaction_revokes == 0 {
                    return Err(Error::JournalCorrupt);
                }
                self.advance_walk_blocks(1)?;
                self.summary.max_transaction_tags = self
                    .summary
                    .max_transaction_tags
                    .max(self.walk.scan_transaction_tags);
                self.summary.revoke_records = self
                    .summary
                    .revoke_records
                    .checked_add(self.walk.scan_transaction_revokes)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.summary.transactions = self
                    .summary
                    .transactions
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?;
                self.walk.sequence = self.walk.sequence.next();
                self.summary.end_cursor = self.walk.cursor;
                self.summary.next_sequence = self.walk.sequence;
                self.walk.scan_transaction_tags = 0;
                self.walk.scan_transaction_revokes = 0;
                if self.walk.consumed >= self.journal.usable_log_blocks()? {
                    self.finish_scan()?;
                }
            }
            _ => self.finish_scan()?,
        }
        Ok(())
    }

    /// Finishes pass one and reserves all address memory before any home write.
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when bounded tag or revoke reservation fails.
    fn finish_scan(&mut self) -> Result<()> {
        self.tags
            .try_reserve_exact(self.summary.max_transaction_tags)
            .map_err(|_| Error::OutOfMemory)?;
        self.revokes
            .try_reserve_exact(self.summary.revoke_records)
            .map_err(|_| Error::OutOfMemory)?;
        self.phase = RecoveryPhase::Validate;
        self.reset_walk();
        Ok(())
    }

    /// Revalidates or replays one control block inside the pass-one committed boundary.
    /// # Errors
    ///
    /// Returns an error for sequence, checksum, UUID, address, or structure corruption.
    fn validate_or_replay_control_block(&mut self, block: &[u8]) -> Result<()> {
        let header = Jbd2Header::parse(block)?;
        if header.sequence() != self.walk.sequence.get() {
            return Err(Error::JournalCorrupt);
        }
        match header.block_type() {
            JBD2_DESCRIPTOR_BLOCK => self.process_descriptor(block),
            JBD2_REVOKE_BLOCK => self.process_revoke(block),
            JBD2_COMMIT_BLOCK => {
                self.journal.parse_commit_block(block, self.walk.sequence)?;
                self.advance_walk_blocks(1)?;
                self.walk.sequence = self.walk.sequence.next();
                self.tags.clear();
                Ok(())
            }
            _ => Err(Error::JournalCorrupt),
        }
    }

    /// Parses descriptor tags into the transaction-bounded preallocated address vector.
    /// # Errors
    ///
    /// Returns an error for invalid tags, targets, duplicates, capacity, or ring arithmetic.
    fn process_descriptor(&mut self, block: &[u8]) -> Result<()> {
        let descriptor_cursor = self.journal.next_logical(self.walk.cursor)?;
        let start = self.tags.len();
        let sequence = self.walk.sequence;
        let journal = &self.journal;
        let tags = &mut self.tags;
        let mut payload_cursor = descriptor_cursor;
        journal.for_each_descriptor_tag(block, |tag| {
            journal.validate_replay_target(tag.block)?;
            if tags.iter().any(|existing| existing.home == tag.block) {
                return Err(Error::JournalCorrupt);
            }
            let recovery_tag = RecoveryTag {
                home: tag.block,
                journal_block: payload_cursor,
                sequence,
                flags: tag.flags,
                checksum: tag.checksum,
            };
            tags.push_within_capacity(recovery_tag)
                .map_err(|_tag| Error::JournalCorrupt)?;
            payload_cursor = journal.next_logical(payload_cursor)?;
            Ok(())
        })?;
        let end = self.tags.len();
        if start == end {
            return Err(Error::JournalCorrupt);
        }
        let consumed_payloads = end.checked_sub(start).ok_or(Error::ArithmeticOverflow)?;
        self.advance_walk_blocks(
            u32::try_from(consumed_payloads)
                .map_err(|_| Error::ArithmeticOverflow)?
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        self.pending = RecoveryPending::Payload { next: start, end };
        Ok(())
    }

    /// Validates revoke structure and builds the latest-sequence table during pass two.
    /// # Errors
    ///
    /// Returns an error for unsupported revokes, invalid targets, checksums, or reserved capacity.
    fn process_revoke(&mut self, block: &[u8]) -> Result<()> {
        if !self.journal.profile.has_revokes() {
            return Err(Error::JournalCorrupt);
        }
        let phase = self.phase;
        let sequence = self.walk.sequence;
        let journal = &self.journal;
        let revokes = &mut self.revokes;
        journal.for_each_revoke(block, |revoked| {
            journal.validate_replay_target(revoked)?;
            if phase == RecoveryPhase::Validate {
                if let Some(existing) = revokes.iter_mut().find(|entry| entry.block == revoked) {
                    if sequence.is_after(existing.sequence) {
                        existing.sequence = sequence;
                    }
                } else {
                    revokes
                        .push_within_capacity(RecoveryRevoke {
                            block: revoked,
                            sequence,
                        })
                        .map_err(|_entry| Error::JournalCorrupt)?;
                }
            }
            Ok(())
        })?;
        self.advance_walk_blocks(1)
    }

    /// Prepares replay and clean publication after every committed byte has been validated.
    /// # Errors
    ///
    /// Returns an error when the clean superblock or typestate cannot be allocated and encoded.
    fn prepare_replay_and_clean(&mut self) -> Result<()> {
        match self.primary_repair {
            PrimaryRepairValidation::NotRequired => {}
            PrimaryRepairValidation::Required { .. } => return Err(Error::ChecksumMismatch),
            PrimaryRepairValidation::Validated { home, sequence } => {
                if self.is_revoked(home, sequence) {
                    return Err(Error::JournalCorrupt);
                }
            }
        }
        let cursor = JournalCursor {
            sequence: self.summary.next_sequence,
            head: self.summary.end_cursor,
        };
        let clean_write = self
            .journal
            .superblock
            .encode_clean(self.journal.geometry.block_size, cursor)?;
        let clean_state = memory::copied_slice(&clean_write)?;
        let mut clean_journal = self.journal.copy_without_state::<CleanJournal>()?;
        clean_journal.cursor = cursor;
        clean_journal.superblock.apply_clean(cursor, clean_state);
        self.clean_write = Some(clean_write);
        self.clean_journal = Some(clean_journal);
        self.tags.clear();
        self.reset_walk();
        self.phase = if self.policy == RecoveryPolicy::Replay && self.summary.transactions != 0 {
            RecoveryPhase::Replay
        } else {
            RecoveryPhase::WriteCleanJournal
        };
        Ok(())
    }

    /// Promotes one committed journal payload into primary-superblock repair authority.
    /// # Errors
    ///
    /// Returns an error when a payload targeting the primary block does not itself contain a
    /// checksum-valid read-write superblock.
    fn validate_primary_repair_payload(&mut self, tag: RecoveryTag, payload: &[u8]) -> Result<()> {
        if self.phase != RecoveryPhase::Validate || tag.flags & JBD2_TAG_FLAG_DELETED != 0 {
            return Ok(());
        }
        let home = match self.primary_repair {
            PrimaryRepairValidation::NotRequired => return Ok(()),
            PrimaryRepairValidation::Required { home }
            | PrimaryRepairValidation::Validated { home, .. } => home,
        };
        if tag.home != home {
            return Ok(());
        }
        Superblock::parse_primary_block(payload, self.journal.geometry.block_size)?;
        self.primary_repair = PrimaryRepairValidation::Validated {
            home,
            sequence: tag.sequence,
        };
        Ok(())
    }

    /// Resets a bounded pass to the committed prefix start.
    fn reset_walk(&mut self) {
        self.walk = RecoveryWalk {
            cursor: self.summary.start_cursor,
            sequence: self.summary.start_sequence,
            consumed: 0,
            scan_transaction_tags: 0,
            scan_transaction_revokes: 0,
        };
        self.pending = RecoveryPending::Control;
    }

    /// Advances the active walk with circular ring semantics and a hard geometry bound.
    /// # Errors
    ///
    /// Returns an error when consumption exceeds the ring or cursor arithmetic fails.
    fn advance_walk_blocks(&mut self, count: u32) -> Result<()> {
        let next_consumed = self
            .walk
            .consumed
            .checked_add(count)
            .ok_or(Error::ArithmeticOverflow)?;
        if next_consumed > self.journal.usable_log_blocks()? {
            return Err(Error::JournalCorrupt);
        }
        for _index in 0..count {
            self.walk.cursor = self.journal.next_logical(self.walk.cursor)?;
        }
        self.walk.consumed = next_consumed;
        Ok(())
    }

    /// Returns whether a same-or-later transaction revoked this payload's home block.
    fn is_revoked(&self, block: BlockAddress, sequence: JournalSequence) -> bool {
        self.revokes.iter().any(|revoked| {
            revoked.block == block
                && (revoked.sequence == sequence || revoked.sequence.is_after(sequence))
        })
    }
}

impl RecoveryTag {
    /// Projects the validated recovery address into the checksum parser's wire tag view.
    const fn as_journal_tag(self) -> JournalTag {
        JournalTag {
            block: self.home,
            flags: self.flags,
            checksum: self.checksum,
        }
    }
}

impl<State> Journal<State> {
    /// Rebuilds the same journal data with a different typestate marker.
    /// # Errors
    ///
    /// Returns an error when copying the typestate-independent journal data cannot allocate.
    fn copy_without_state<Next>(&self) -> Result<Journal<Next>> {
        Ok(Journal {
            location: self.location.try_clone()?,
            superblock: self.superblock.try_clone()?,
            profile: self.profile,
            geometry: self.geometry,
            cursor: self.cursor,
            filesystem_blocks: self.filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Loads an internal journal stored in the filesystem journal inode.
    /// # Errors
    ///
    /// Returns an error when the inode is not a supported extent-backed journal, the journal
    /// superblock cannot be read or parsed, or the ring layout is inconsistent with the inode size.
    pub(crate) fn from_inode(
        inode: &Inode,
        block_size: BlockSize,
        filesystem_blocks: u64,
        reader: &mut OperationDevice<'_>,
    ) -> Result<Journal<LoadedJournal>> {
        if inode.size().bytes() == 0 || block_size.bytes() == 0 {
            return Err(Error::UnsupportedJournal);
        }
        let capacity_blocks = inode
            .size()
            .bytes()
            .checked_div(u64::from(block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        let capacity_blocks =
            u32::try_from(capacity_blocks).map_err(|_| Error::UnsupportedJournal)?;
        if capacity_blocks <= JOURNAL_MIN_TRANSACTION_BLOCKS {
            return Err(Error::UnsupportedJournal);
        }

        let tree = ExtentTree::load_inode_tree(
            inode.extent_root()?,
            block_size,
            reader,
            ExtentTreeContext::none(),
        )?;
        let location = JournalLocation::Internal(InternalJournalLayout::new(
            tree.extents(),
            capacity_blocks,
            filesystem_blocks,
        )?);
        let mut raw = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        read_journal_block(reader, &location, block_size, 0, &mut raw)?;
        let superblock = JournalSuperblock::parse(&raw)?;
        let profile = JournalProfile::from_superblock(&superblock)?;
        let geometry = JournalGeometry::from_superblock(
            &superblock,
            block_size,
            capacity_blocks,
            location.expected_first()?,
        )?;
        location.validate_ring(&geometry.ring)?;
        let cursor = JournalCursor::from_superblock(&superblock, geometry.ring)?;

        Ok(Journal {
            location,
            superblock,
            profile,
            geometry,
            cursor,
            filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Probes and loads a dedicated external journal device.
    /// # Errors
    ///
    /// Returns an error when a matching UUID names an invalid journal device, its JBD2 profile is
    /// unsupported, its sole user differs from `filesystem_uuid`, or device geometry is invalid.
    pub(crate) fn from_external_device(
        reader: &mut OperationDevice<'_>,
        expected_uuid: JournalUuid,
        filesystem_uuid: FilesystemUuid,
        expected_block_size: BlockSize,
        filesystem_blocks: u64,
    ) -> Result<ExternalJournalLoad> {
        let mut ext_raw = [0_u8; EXTERNAL_EXT_SUPERBLOCK_BYTES];
        reader.read_exact_at(
            ByteOffset::new(EXTERNAL_EXT_SUPERBLOCK_OFFSET),
            &mut ext_raw,
        )?;
        let ext = match ExternalJournalDeviceSuperblock::parse(&ext_raw, expected_uuid)? {
            ExternalDeviceSuperblockProbe::Mismatch => return Ok(ExternalJournalLoad::Mismatch),
            ExternalDeviceSuperblockProbe::Match(ext) => ext,
        };
        if ext.block_size != expected_block_size {
            return Err(Error::UnsupportedJournal);
        }
        let device_blocks = reader
            .len()
            .bytes()
            .checked_div(u64::from(ext.block_size.bytes()))
            .ok_or(Error::ArithmeticOverflow)?;
        let capacity_blocks =
            u32::try_from(device_blocks).map_err(|_| Error::UnsupportedJournal)?;
        let layout = ExternalJournalLayout::new(capacity_blocks, ext.superblock_block)?;
        let mut journal_raw = memory::repeated_vec(
            0_u8,
            usize::try_from(ext.block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        reader.read_exact_at(layout.superblock_offset(ext.block_size)?, &mut journal_raw)?;
        let superblock = JournalSuperblock::parse(&journal_raw)?;
        if superblock.uuid != expected_uuid.bytes()
            || superblock.nr_users != 1
            || superblock.first_user != filesystem_uuid.bytes()
        {
            return Err(Error::JournalCorrupt);
        }
        let profile = JournalProfile::from_superblock(&superblock)?;
        let location = JournalLocation::External(layout);
        let geometry = JournalGeometry::from_superblock(
            &superblock,
            ext.block_size,
            capacity_blocks,
            location.expected_first()?,
        )?;
        location.validate_ring(&geometry.ring)?;
        let cursor = JournalCursor::from_superblock(&superblock, geometry.ring)?;
        Ok(ExternalJournalLoad::Match(Journal {
            location,
            superblock,
            profile,
            geometry,
            cursor,
            filesystem_blocks,
            state: PhantomData,
        }))
    }

    /// Serializes every commit, publish-overlay, and checkpoint allocation before the first write.
    /// # Errors
    ///
    /// Returns an error when the journal is not clean, the transaction does not fit, serialization
    /// fails, or any required owned image cannot be allocated.
    pub(crate) fn prepare_commit(
        &self,
        block_size: BlockSize,
        metadata_blocks: Vec<MetadataBlock>,
    ) -> Result<PreparedJournalCommit> {
        if self.superblock.start() != 0 {
            return Err(Error::JournalCorrupt);
        }
        let prepared = self.prepare_metadata_transaction(block_size, &metadata_blocks)?;
        let journal_target = self.location.storage_target();
        let dirty_superblock =
            self.superblock
                .encode_dirty(block_size, prepared.descriptor, prepared.sequence)?;
        let dirty_state_bytes = memory::copied_slice(&dirty_superblock)?;
        let mut durable_journal = self.copy_without_state::<DirtyJournal>()?;
        durable_journal.superblock.apply_dirty(
            prepared.descriptor,
            prepared.sequence,
            dirty_state_bytes,
        );
        durable_journal.cursor = prepared.next_cursor;

        let additional_precommit = prepared
            .log_blocks
            .len()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut precommit_writes = Vec::new();
        precommit_writes
            .try_reserve_exact(additional_precommit)
            .map_err(|_| Error::OutOfMemory)?;
        precommit_writes.try_push(PlannedStorageWrite::new(
            journal_target,
            self.location.superblock_offset(block_size)?,
            dirty_superblock,
        ))?;
        let mut cursor = prepared.descriptor;
        for block in prepared.log_blocks {
            precommit_writes.try_push(PlannedStorageWrite::new(
                journal_target,
                self.offset_of(cursor, block_size)?,
                block,
            ))?;
            cursor = self.next_logical(cursor)?;
        }
        if cursor != prepared.commit {
            return Err(Error::JournalCorrupt);
        }
        let commit_write = PlannedStorageWrite::new(
            journal_target,
            self.offset_of(cursor, block_size)?,
            prepared.commit_block,
        );

        let clean_bytes = self
            .superblock
            .encode_clean(block_size, prepared.next_cursor)?;
        let clean_state_bytes = memory::copied_slice(&clean_bytes)?;
        let mut clean_journal = self.copy_without_state::<CleanJournal>()?;
        clean_journal.cursor = prepared.next_cursor;
        clean_journal
            .superblock
            .apply_clean(prepared.next_cursor, clean_state_bytes);
        let clean_write = PlannedStorageWrite::new(
            journal_target,
            self.location.superblock_offset(block_size)?,
            clean_bytes,
        );

        let mut home_writes = Vec::new();
        home_writes
            .try_reserve_exact(metadata_blocks.len())
            .map_err(|_| Error::OutOfMemory)?;
        for metadata in &metadata_blocks {
            home_writes.try_push(PlannedStorageWrite::new(
                StorageTarget::Filesystem,
                block_size.offset_of(metadata.block())?,
                memory::copied_slice(metadata.bytes())?,
            ))?;
        }

        Ok(PreparedJournalCommit {
            precommit_writes,
            commit_write,
            journal_target,
            durable_journal,
            overlay: metadata_blocks,
            checkpoint: PreparedJournalCheckpoint {
                home_writes,
                clean_write,
                clean_journal,
            },
        })
    }

    /// Builds descriptor, escaped data blocks, and commit block for a transaction.
    /// # Errors
    ///
    /// Returns an error when the transaction is too large, a metadata block has the wrong size, data
    /// escaping fails, or descriptor/commit serialization fails.
    fn prepare_metadata_transaction(
        &self,
        block_size: BlockSize,
        metadata_blocks: &[MetadataBlock],
    ) -> Result<PreparedJournalTransaction> {
        let credits = self.journal_credits(metadata_blocks.len(), block_size)?;
        let block_bytes =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        for (index, metadata) in metadata_blocks.iter().enumerate() {
            if metadata.bytes().len() != block_bytes {
                return Err(Error::InvalidWriteRange);
            }
            self.validate_replay_target(metadata.block())?;
            if metadata_blocks
                .get(..index)
                .ok_or(Error::InvalidWriteRange)?
                .iter()
                .any(|prior| prior.block() == metadata.block())
            {
                return Err(Error::JournalCorrupt);
            }
        }
        let mut data_blocks = Vec::new();
        data_blocks
            .try_reserve_exact(metadata_blocks.len())
            .map_err(|_| Error::OutOfMemory)?;
        for metadata in metadata_blocks {
            let mut data = memory::copied_slice(metadata.bytes())?;
            if starts_with_jbd2_magic(&data) {
                put_be_u32(&mut data, disk_offset(0), 0)?;
            }
            data_blocks.try_push(data)?;
        }

        let sequence = self.cursor.sequence;
        let descriptor = self.cursor.head;
        let log_capacity = credits
            .descriptors
            .checked_add(credits.payloads)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut log_blocks = Vec::new();
        log_blocks
            .try_reserve_exact(log_capacity)
            .map_err(|_| Error::OutOfMemory)?;
        let mut first = 0_usize;
        while first < metadata_blocks.len() {
            let end = self.descriptor_group_end(first, metadata_blocks.len(), block_size)?;
            log_blocks.try_push(
                self.encode_descriptor_block(
                    sequence,
                    metadata_blocks
                        .get(first..end)
                        .ok_or(Error::InvalidWriteRange)?,
                    data_blocks
                        .get(first..end)
                        .ok_or(Error::InvalidWriteRange)?,
                    block_size,
                )?,
            )?;
            for data in data_blocks
                .get(first..end)
                .ok_or(Error::InvalidWriteRange)?
            {
                log_blocks.try_push(memory::copied_slice(data)?)?;
            }
            first = end;
        }
        if log_blocks.len()
            != credits
                .descriptors
                .checked_add(credits.payloads)
                .ok_or(Error::ArithmeticOverflow)?
            || credits.total
                != u32::try_from(
                    log_blocks
                        .len()
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .map_err(|_| Error::ArithmeticOverflow)?
        {
            return Err(Error::JournalCorrupt);
        }
        let mut commit = descriptor;
        for _ in 0..log_blocks.len() {
            commit = self.next_logical(commit)?;
        }
        let next_head = self.next_logical(commit)?;
        let next_cursor = JournalCursor {
            sequence: sequence.next(),
            head: next_head,
        };
        Ok(PreparedJournalTransaction {
            sequence,
            descriptor,
            log_blocks,
            commit,
            next_cursor,
            commit_block: self.encode_commit_block(sequence, block_size)?,
        })
    }

    /// Computes exact descriptor and ring credits from the active wire profile.
    /// # Errors
    ///
    /// Returns an error when no metadata payload is present, a descriptor cannot hold its required
    /// explicit UUID tag, arithmetic overflows, or the complete transaction does not fit the ring.
    fn journal_credits(&self, payloads: usize, block_size: BlockSize) -> Result<JournalCredits> {
        if payloads == 0 || block_size != self.geometry.block_size {
            return Err(Error::InvalidWriteRange);
        }
        let descriptor_capacity = self.descriptor_tag_capacity()?;
        let descriptors = payloads
            .checked_add(
                descriptor_capacity
                    .checked_sub(1)
                    .ok_or(Error::TransactionTooLarge)?,
            )
            .ok_or(Error::ArithmeticOverflow)?
            .checked_div(descriptor_capacity)
            .ok_or(Error::TransactionTooLarge)?;
        let total_usize = descriptors
            .checked_add(payloads)
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ArithmeticOverflow)?;
        let total = u32::try_from(total_usize).map_err(|_| Error::TransactionTooLarge)?;
        if total > self.usable_log_blocks()? {
            return Err(Error::TransactionTooLarge);
        }
        Ok(JournalCredits {
            descriptors,
            payloads,
            total,
        })
    }

    /// Returns the exclusive tag index for one descriptor block.
    /// # Errors
    ///
    /// Returns an error when `first` is outside the transaction or descriptor arithmetic overflows.
    fn descriptor_group_end(
        &self,
        first: usize,
        payloads: usize,
        block_size: BlockSize,
    ) -> Result<usize> {
        if first >= payloads || block_size != self.geometry.block_size {
            return Err(Error::InvalidWriteRange);
        }
        Ok(first
            .checked_add(self.descriptor_tag_capacity()?)
            .ok_or(Error::ArithmeticOverflow)?
            .min(payloads))
    }

    /// Rejects replay targets outside the filesystem or inside the internal journal.
    /// # Errors
    ///
    /// Returns an error when the replay target is beyond the filesystem or overlaps the internal
    /// journal's home blocks.
    fn validate_replay_target(&self, block: BlockAddress) -> Result<()> {
        if block.get() >= self.filesystem_blocks {
            return Err(Error::JournalCorrupt);
        }
        if self.location.contains_home_block(block)? {
            return Err(Error::JournalCorrupt);
        }
        Ok(())
    }

    /// Counts structurally decodable tags during the committed-prefix scan.
    ///
    /// Descriptor checksum failure is deliberately deferred to pass two so a valid later commit
    /// record distinguishes committed corruption from an incomplete tail.
    /// # Errors
    ///
    /// Returns an error when no complete, structurally valid tag stream terminates in the block.
    fn descriptor_tag_count_for_scan(&self, block: &[u8]) -> Result<usize> {
        let mut offset = JOURNAL_HEADER_BYTES;
        let limit = if self.profile.has_metadata_checksums() {
            block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?
        } else {
            block.len()
        };
        let mut count = 0_usize;
        loop {
            let Some((tag, next_offset)) = self.parse_tag(block, offset, limit, count == 0)? else {
                return Err(Error::JournalCorrupt);
            };
            count = count.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            offset = next_offset;
            if tag.flags & JBD2_TAG_FLAG_LAST_TAG != 0 {
                return Ok(count);
            }
        }
    }

    /// Visits every fully validated descriptor tag without retaining a descriptor-owned vector.
    /// # Errors
    ///
    /// Returns an error for checksum, UUID, flag, layout, or visitor rejection.
    fn for_each_descriptor_tag(
        &self,
        block: &[u8],
        mut visit: impl FnMut(JournalTag) -> Result<()>,
    ) -> Result<()> {
        self.verify_block_tail_checksum(block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        let limit = if self.profile.has_metadata_checksums() {
            block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?
        } else {
            block.len()
        };
        let mut count = 0_usize;
        loop {
            let Some((tag, next_offset)) = self.parse_tag(block, offset, limit, count == 0)? else {
                return Err(Error::JournalCorrupt);
            };
            visit(tag)?;
            count = count.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            offset = next_offset;
            if tag.flags & JBD2_TAG_FLAG_LAST_TAG != 0 {
                return Ok(());
            }
        }
    }

    /// Parses one descriptor tag and returns the next tag offset.
    /// # Errors
    ///
    /// Returns an error when tag fields exceed the descriptor payload, tag flags are unsupported, or
    /// an embedded UUID does not match the journal superblock.
    fn parse_tag(
        &self,
        block: &[u8],
        offset: usize,
        limit: usize,
        first_tag: bool,
    ) -> Result<Option<(JournalTag, usize)>> {
        if self.profile.has_csum_v3() {
            let base_size = 16_usize;
            if offset
                .checked_add(base_size)
                .ok_or(Error::ArithmeticOverflow)?
                > limit
            {
                return Ok(None);
            }
            let block_low = u64::from(be_u32(block, disk_offset(offset))?);
            let flags = be_u32(block, disk_offset(offset).checked_add_bytes(4)?)?;
            let block_high = u64::from(be_u32(block, disk_offset(offset).checked_add_bytes(8)?)?);
            let checksum = be_u32(block, disk_offset(offset).checked_add_bytes(12)?)?;
            if block_low == 0 && block_high == 0 && flags == 0 && checksum == 0 {
                return Ok(None);
            }
            validate_tag_flags(flags)?;
            if first_tag && flags & JBD2_TAG_FLAG_SAME_UUID != 0 {
                return Err(Error::JournalCorrupt);
            }
            if !self.profile.has_64bit() && block_high != 0 {
                return Err(Error::JournalCorrupt);
            }
            let uuid_size = if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
                16
            } else {
                0
            };
            let next = offset
                .checked_add(base_size)
                .and_then(|value| value.checked_add(uuid_size))
                .ok_or(Error::ArithmeticOverflow)?;
            if next > limit {
                return Err(Error::JournalCorrupt);
            }
            if uuid_size == 16 {
                let uuid = block
                    .get(
                        offset
                            .checked_add(base_size)
                            .ok_or(Error::ArithmeticOverflow)?..next,
                    )
                    .ok_or(Error::TruncatedStructure)?;
                if uuid != self.superblock.uuid() {
                    return Err(Error::JournalCorrupt);
                }
            }
            return Ok(Some((
                JournalTag {
                    block: BlockAddress::new((block_high << 32) | block_low),
                    flags,
                    checksum,
                },
                next,
            )));
        }

        let base_size = 8_usize;
        if offset
            .checked_add(base_size)
            .ok_or(Error::ArithmeticOverflow)?
            > limit
        {
            return Ok(None);
        }
        let block_low = u64::from(be_u32(block, disk_offset(offset))?);
        let checksum = u32::from(be_u16(block, disk_offset(offset).checked_add_bytes(4)?)?);
        let flags = u32::from(be_u16(block, disk_offset(offset).checked_add_bytes(6)?)?);
        if block_low == 0 && flags == 0 && checksum == 0 {
            return Ok(None);
        }
        validate_tag_flags(flags)?;
        if first_tag && flags & JBD2_TAG_FLAG_SAME_UUID != 0 {
            return Err(Error::JournalCorrupt);
        }
        let high_size = if self.profile.has_64bit() { 4 } else { 0 };
        let tag_size = self.descriptor_tag_size();
        let block_high = if high_size == 4 {
            u64::from(be_u32(block, disk_offset(offset).checked_add_bytes(8)?)?)
        } else {
            0
        };
        let uuid_size = if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
            16
        } else {
            0
        };
        let next = offset
            .checked_add(tag_size)
            .and_then(|value| value.checked_add(uuid_size))
            .ok_or(Error::ArithmeticOverflow)?;
        if next > limit {
            return Err(Error::JournalCorrupt);
        }
        if uuid_size == 16 {
            let uuid_start = offset
                .checked_add(tag_size)
                .ok_or(Error::ArithmeticOverflow)?;
            let uuid = block
                .get(uuid_start..next)
                .ok_or(Error::TruncatedStructure)?;
            if uuid != self.superblock.uuid() {
                return Err(Error::JournalCorrupt);
            }
        }
        Ok(Some((
            JournalTag {
                block: BlockAddress::new((block_high << 32) | block_low),
                flags,
                checksum,
            },
            next,
        )))
    }

    /// Counts revoke records during pass one while deferring its tail checksum to validation.
    /// # Errors
    ///
    /// Returns an error when the revoke header, used length, or entry alignment is invalid.
    fn revoke_count_for_scan(&self, block: &[u8]) -> Result<usize> {
        let (mut offset, limit, entry_size) = self.revoke_layout(block)?;
        let mut count = 0_usize;
        while offset
            .checked_add(entry_size)
            .ok_or(Error::ArithmeticOverflow)?
            <= limit
        {
            count = count.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            offset = offset
                .checked_add(entry_size)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        if offset == limit {
            Ok(count)
        } else {
            Err(Error::JournalCorrupt)
        }
    }

    /// Visits every validated revoke address without allocating an intermediate record vector.
    /// # Errors
    ///
    /// Returns an error for checksum, layout, address decoding, or visitor rejection.
    fn for_each_revoke(
        &self,
        block: &[u8],
        mut visit: impl FnMut(BlockAddress) -> Result<()>,
    ) -> Result<()> {
        self.verify_block_tail_checksum(block)?;
        let (mut offset, limit, entry_size) = self.revoke_layout(block)?;
        while offset
            .checked_add(entry_size)
            .ok_or(Error::ArithmeticOverflow)?
            <= limit
        {
            let revoked = if entry_size == 8 {
                be_u64(block, disk_offset(offset))?
            } else {
                u64::from(be_u32(block, disk_offset(offset))?)
            };
            visit(BlockAddress::new(revoked))?;
            offset = offset
                .checked_add(entry_size)
                .ok_or(Error::ArithmeticOverflow)?;
        }
        if offset == limit {
            Ok(())
        } else {
            Err(Error::JournalCorrupt)
        }
    }

    /// Returns the checked revoke entry range and width shared by all recovery passes.
    /// # Errors
    ///
    /// Returns an error when the used range does not fit the control block and optional tail.
    fn revoke_layout(&self, block: &[u8]) -> Result<(usize, usize, usize)> {
        let used = usize::try_from(be_u32(block, disk_offset(JOURNAL_HEADER_BYTES))?)
            .map_err(|_| Error::JournalCorrupt)?;
        let tail = if self.profile.has_metadata_checksums() {
            4
        } else {
            0
        };
        let maximum_used = block.len().checked_sub(tail).ok_or(Error::JournalCorrupt)?;
        if used < 16 || used > maximum_used {
            return Err(Error::JournalCorrupt);
        }
        Ok((16, used, if self.profile.has_64bit() { 8 } else { 4 }))
    }

    /// Validates a commit block for the expected transaction sequence.
    /// # Errors
    ///
    /// Returns an error when the block is not a commit block for `expected_sequence`, checksum
    /// metadata fields are invalid, or the commit checksum fails.
    fn parse_commit_block(&self, block: &[u8], expected_sequence: JournalSequence) -> Result<()> {
        let header = Jbd2Header::parse(block)?;
        if header.block_type() != JBD2_COMMIT_BLOCK {
            return Err(Error::JournalCorrupt);
        }
        if header.sequence() != expected_sequence.get() {
            return Err(Error::JournalCorrupt);
        }
        if self.profile.has_metadata_checksums() {
            if *block.get(0x0C).ok_or(Error::TruncatedStructure)? != 0
                || *block.get(0x0D).ok_or(Error::TruncatedStructure)? != 0
                || *block.get(0x0E).ok_or(Error::TruncatedStructure)? != 0
                || *block.get(0x0F).ok_or(Error::TruncatedStructure)? != 0
            {
                return Err(Error::JournalCorrupt);
            }
            self.verify_commit_checksum(block)?;
        }
        Ok(())
    }

    /// Encodes descriptor tags for the metadata blocks in a new transaction.
    /// # Errors
    ///
    /// Returns an error when the block size cannot be allocated, a data block is missing, a tag does
    /// not fit, or the descriptor tail checksum cannot be written.
    fn encode_descriptor_block(
        &self,
        sequence: JournalSequence,
        metadata_blocks: &[MetadataBlock],
        data_blocks: &[Vec<u8>],
        block_size: BlockSize,
    ) -> Result<Vec<u8>> {
        let mut block = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        Jbd2Header::descriptor(sequence.get()).encode(&mut block)?;
        let mut offset = JOURNAL_HEADER_BYTES;
        for (index, metadata) in metadata_blocks.iter().enumerate() {
            let last =
                index.checked_add(1).ok_or(Error::ArithmeticOverflow)? == metadata_blocks.len();
            let data = data_blocks.get(index).ok_or(Error::InvalidWriteRange)?;
            let flags = if index == 0 {
                0
            } else {
                JBD2_TAG_FLAG_SAME_UUID
            } | if last { JBD2_TAG_FLAG_LAST_TAG } else { 0 }
                | if starts_with_jbd2_magic(metadata.bytes()) {
                    JBD2_TAG_FLAG_ESCAPE
                } else {
                    0
                };
            offset = self.encode_tag(&mut block, offset, sequence, metadata, data, flags)?;
        }
        self.write_block_tail_checksum(&mut block)?;
        Ok(block)
    }

    /// Encodes one descriptor tag using the active JBD2 tag format.
    /// # Errors
    ///
    /// Returns an error when the tag would exceed the descriptor payload or its block address,
    /// checksum, or flags cannot be represented in the active tag format.
    fn encode_tag(
        &self,
        block: &mut [u8],
        offset: usize,
        sequence: JournalSequence,
        metadata: &MetadataBlock,
        data: &[u8],
        flags: u32,
    ) -> Result<usize> {
        let checksum = self.tag_checksum(sequence, data)?;
        if !self.profile.has_64bit() && metadata.block().get() > u64::from(u32::MAX) {
            return Err(Error::TransactionTooLarge);
        }
        let uuid_size = if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
            16
        } else {
            0
        };
        if self.profile.has_csum_v3() {
            let next = offset
                .checked_add(16)
                .and_then(|value| value.checked_add(uuid_size))
                .ok_or(Error::ArithmeticOverflow)?;
            if next > self.descriptor_payload_limit(block.len())? {
                return Err(Error::TransactionTooLarge);
            }
            put_be_u32(
                block,
                disk_offset(offset),
                u32::try_from(metadata.block().get() & u64::from(u32::MAX))
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(block, disk_offset(offset).checked_add_bytes(4)?, flags)?;
            put_be_u32(
                block,
                disk_offset(offset).checked_add_bytes(8)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            put_be_u32(block, disk_offset(offset).checked_add_bytes(12)?, checksum)?;
            if uuid_size == 16 {
                memory::copy_exact(
                    block
                        .get_mut(offset.checked_add(16).ok_or(Error::ArithmeticOverflow)?..next)
                        .ok_or(Error::TruncatedStructure)?,
                    self.superblock.uuid(),
                )?;
            }
            return Ok(next);
        }

        let high_size = if self.profile.has_64bit() { 4 } else { 0 };
        let tag_size = self.descriptor_tag_size();
        let next = offset
            .checked_add(tag_size)
            .and_then(|value| value.checked_add(uuid_size))
            .ok_or(Error::ArithmeticOverflow)?;
        if next > self.descriptor_payload_limit(block.len())? {
            return Err(Error::TransactionTooLarge);
        }
        put_be_u32(
            block,
            disk_offset(offset),
            u32::try_from(metadata.block().get() & u64::from(u32::MAX))
                .map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_be_u16(
            block,
            disk_offset(offset).checked_add_bytes(4)?,
            u16::try_from(checksum & u32::from(u16::MAX)).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        put_be_u16(
            block,
            disk_offset(offset).checked_add_bytes(6)?,
            u16::try_from(flags).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        if high_size == 4 {
            put_be_u32(
                block,
                disk_offset(offset).checked_add_bytes(8)?,
                u32::try_from(metadata.block().get() >> 32)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
        }
        if uuid_size == 16 {
            let uuid_start = offset
                .checked_add(tag_size)
                .ok_or(Error::ArithmeticOverflow)?;
            memory::copy_exact(
                block
                    .get_mut(uuid_start..next)
                    .ok_or(Error::TruncatedStructure)?,
                self.superblock.uuid(),
            )?;
        }
        Ok(next)
    }

    /// Encodes the commit block that makes a transaction durable.
    /// # Errors
    ///
    /// Returns an error when the block size cannot be allocated, the header cannot be written, or
    /// commit checksum fields are outside the block.
    fn encode_commit_block(
        &self,
        sequence: JournalSequence,
        block_size: BlockSize,
    ) -> Result<Vec<u8>> {
        let mut block = memory::repeated_vec(
            0_u8,
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?,
        )?;
        Jbd2Header::commit(sequence.get()).encode(&mut block)?;
        if self.profile.has_metadata_checksums() {
            let checksum =
                self.block_checksum_with_zeroed(&block, JOURNAL_COMMIT_CHECKSUM_OFFSET)?;
            put_be_u32(
                &mut block,
                disk_offset(JOURNAL_COMMIT_CHECKSUM_OFFSET),
                checksum,
            )?;
        }
        Ok(block)
    }

    /// Returns the number of usable blocks in the journal ring.
    /// # Errors
    ///
    /// Returns an error when ring geometry leaves no usable journal blocks.
    fn usable_log_blocks(&self) -> Result<u32> {
        self.geometry.ring.usable_blocks()
    }

    /// Returns how many tags fit in one descriptor block.
    /// # Errors
    ///
    /// Returns an error when the journal block cannot hold the descriptor header, optional tail, and
    /// at least one tag.
    fn descriptor_tag_capacity(&self) -> Result<usize> {
        let block_bytes = usize::try_from(self.geometry.block_size.bytes())
            .map_err(|_| Error::ArithmeticOverflow)?;
        let tail_bytes = if self.profile.has_metadata_checksums() {
            4
        } else {
            0
        };
        let usable = block_bytes
            .checked_sub(JOURNAL_HEADER_BYTES)
            .and_then(|value| value.checked_sub(tail_bytes))
            .ok_or(Error::TransactionTooLarge)?;
        let tag_size = self.descriptor_tag_size();
        let first_tag_size = tag_size.checked_add(16).ok_or(Error::ArithmeticOverflow)?;
        let remaining = usable
            .checked_sub(first_tag_size)
            .ok_or(Error::TransactionTooLarge)?;
        remaining
            .checked_div(tag_size)
            .ok_or(Error::TransactionTooLarge)?
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)
    }

    /// Returns the serialized tag width for the active JBD2 feature set.
    fn descriptor_tag_size(&self) -> usize {
        match (
            self.profile.has_csum_v3(),
            self.profile.has_64bit(),
            matches!(self.profile.checksum, JournalChecksumProfile::V2),
        ) {
            (true, _, _) => 16,
            (false, true, true) => 14,
            (false, true, false) => 12,
            (false, false, true) => 10,
            (false, false, false) => 8,
        }
    }

    /// Returns the descriptor payload limit before an optional checksum tail.
    /// # Errors
    ///
    /// Returns an error when metadata checksums are enabled but the block is smaller than its tail.
    fn descriptor_payload_limit(&self, block_len: usize) -> Result<usize> {
        if self.profile.has_metadata_checksums() {
            block_len.checked_sub(4).ok_or(Error::InvalidSuperblock)
        } else {
            Ok(block_len)
        }
    }

    /// Advances a logical journal block with ring wraparound.
    /// # Errors
    ///
    /// Returns an error when the logical block is outside the validated journal ring.
    fn next_logical(&self, logical: u32) -> Result<u32> {
        self.geometry.ring.next(logical)
    }

    /// Verifies a descriptor tag checksum against its data block.
    /// # Errors
    ///
    /// Returns an error when the computed data checksum does not match the tag checksum.
    fn verify_tag_checksum(
        &self,
        sequence: JournalSequence,
        tag: &JournalTag,
        data: &[u8],
    ) -> Result<()> {
        if !self.profile.has_metadata_checksums() {
            return Ok(());
        }
        let actual = self.tag_checksum(sequence, data)?;
        let expected = if self.profile.has_csum_v3() {
            tag.checksum
        } else {
            tag.checksum & u32::from(u16::MAX)
        };
        let actual = if self.profile.has_csum_v3() {
            actual
        } else {
            actual & u32::from(u16::MAX)
        };
        if actual == expected {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Computes the JBD2 checksum for one journal data block.
    /// # Errors
    ///
    /// Returns an error when the sequence number cannot be written into the checksum seed buffer.
    fn tag_checksum(&self, sequence: JournalSequence, data: &[u8]) -> Result<u32> {
        let mut sequence_bytes = [0_u8; 4];
        put_be_u32(&mut sequence_bytes, disk_offset(0), sequence.get())?;
        let seed = ext4_crc32c(u32::MAX, self.superblock.uuid());
        let seed = ext4_crc32c(seed, &sequence_bytes);
        Ok(ext4_crc32c(seed, data))
    }

    /// Verifies the optional checksum stored at the end of a control block.
    /// # Errors
    ///
    /// Returns an error when the control block is too short for a tail checksum or the computed
    /// checksum differs from the stored value.
    fn verify_block_tail_checksum(&self, block: &[u8]) -> Result<()> {
        if !self.profile.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let expected = be_u32(block, disk_offset(offset))?;
        let actual = self.block_checksum_with_zeroed(block, offset)?;
        if actual == expected {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Writes the optional checksum stored at the end of a control block.
    /// # Errors
    ///
    /// Returns an error when the control block is too short for a tail checksum or the checksum
    /// field cannot be written.
    fn write_block_tail_checksum(&self, block: &mut [u8]) -> Result<()> {
        if !self.profile.has_metadata_checksums() {
            return Ok(());
        }
        let offset = block.len().checked_sub(4).ok_or(Error::InvalidSuperblock)?;
        let checksum = self.block_checksum_with_zeroed(block, offset)?;
        put_be_u32(block, disk_offset(offset), checksum)
    }

    /// Verifies the checksum field embedded in a complete or partially persisted commit block.
    /// # Errors
    ///
    /// Returns an error when the commit checksum field or complete header is truncated, or neither
    /// the observed block nor the authenticated header with zero-filled block padding matches.
    fn verify_commit_checksum(&self, block: &[u8]) -> Result<()> {
        let expected = be_u32(block, disk_offset(JOURNAL_COMMIT_CHECKSUM_OFFSET))?;
        let complete = self.block_checksum_with_zeroed(block, JOURNAL_COMMIT_CHECKSUM_OFFSET)?;
        if expected == complete {
            return Ok(());
        }
        let zero_filled_tail = self.commit_checksum_with_zero_filled_tail(block)?;
        if expected == zero_filled_tail {
            Ok(())
        } else {
            Err(Error::ChecksumMismatch)
        }
    }

    /// Authenticates the persisted commit header while reconstructing unwritten padding as zeroes.
    ///
    /// A freshly encoded commit fills the block after its fixed header with zeroes. Storage may
    /// persist the sector containing that header while retaining stale later sectors. Computing
    /// the checksum over this reconstructed representation preserves that crash-recovery contract
    /// without allocating during the committed-prefix scan.
    /// # Errors
    ///
    /// Returns an error when the fixed commit header or checksum field is truncated.
    fn commit_checksum_with_zero_filled_tail(&self, block: &[u8]) -> Result<u32> {
        const ZERO_CHUNK: [u8; 64] = [0; 64];

        let header = block
            .get(..JOURNAL_COMMIT_HEADER_BYTES)
            .ok_or(Error::TruncatedStructure)?;
        let checksum_end = JOURNAL_COMMIT_CHECKSUM_OFFSET
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        let prefix = header
            .get(..JOURNAL_COMMIT_CHECKSUM_OFFSET)
            .ok_or(Error::TruncatedStructure)?;
        let suffix = header
            .get(checksum_end..)
            .ok_or(Error::TruncatedStructure)?;
        let seed = ext4_crc32c(u32::MAX, self.superblock.uuid());
        let seed = ext4_crc32c(seed, prefix);
        let seed = ext4_crc32c(seed, &[0_u8; 4]);
        let mut seed = ext4_crc32c(seed, suffix);
        let mut remaining = block
            .len()
            .checked_sub(header.len())
            .ok_or(Error::TruncatedStructure)?;
        while remaining != 0 {
            let count = remaining.min(ZERO_CHUNK.len());
            let zeroes = ZERO_CHUNK.get(..count).ok_or(Error::TruncatedStructure)?;
            seed = ext4_crc32c(seed, zeroes);
            remaining = remaining
                .checked_sub(zeroes.len())
                .ok_or(Error::ArithmeticOverflow)?;
        }
        Ok(seed)
    }

    /// Computes a control-block checksum with its checksum field zeroed.
    /// # Errors
    ///
    /// Returns an error when the checksum field range overflows or is outside the control block.
    fn block_checksum_with_zeroed(&self, block: &[u8], checksum_offset: usize) -> Result<u32> {
        let end = checksum_offset
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        let prefix = block
            .get(..checksum_offset)
            .ok_or(Error::TruncatedStructure)?;
        let suffix = block.get(end..).ok_or(Error::TruncatedStructure)?;
        let seed = ext4_crc32c(u32::MAX, self.superblock.uuid());
        let seed = ext4_crc32c(seed, prefix);
        let seed = ext4_crc32c(seed, &[0_u8; 4]);
        Ok(ext4_crc32c(seed, suffix))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Validated circular range of usable logical journal blocks.
struct JournalRing {
    /// First usable logical block in the journal ring.
    first: u32,
    /// Exclusive upper bound of logical journal blocks.
    maxlen: u32,
}

impl JournalRing {
    /// Validates ring geometry from a parsed journal superblock.
    /// # Errors
    ///
    /// Returns an error when `first`, `maxlen`, or `start` falls outside the supported ring shape or
    /// physical journal capacity.
    fn new(
        superblock: &JournalSuperblock,
        capacity_blocks: u32,
        expected_first: u32,
    ) -> Result<Self> {
        let first = superblock.first();
        let maxlen = superblock.maxlen();
        if maxlen == 0
            || maxlen > capacity_blocks
            || first != expected_first
            || first >= maxlen
            || (superblock.start() != 0
                && (superblock.start() < first || superblock.start() >= maxlen))
        {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self { first, maxlen })
    }

    /// Returns usable block count after the reserved superblock region.
    /// # Errors
    ///
    /// Returns an error when `maxlen` does not leave any blocks after `first`.
    fn usable_blocks(self) -> Result<u32> {
        self.maxlen
            .checked_sub(self.first)
            .ok_or(Error::UnsupportedJournal)
    }

    /// Returns the next logical block, wrapping at the ring end.
    /// # Errors
    ///
    /// Returns an error when `logical` is outside the ring or advancing it overflows.
    fn next(self, logical: u32) -> Result<u32> {
        if logical < self.first || logical >= self.maxlen {
            return Err(Error::JournalCorrupt);
        }
        let next = logical.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        if next >= self.maxlen {
            Ok(self.first)
        } else {
            Ok(next)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Physical placement of a journal's logical block stream.
enum JournalLocation {
    /// Journal stored in an inode on the filesystem device.
    Internal(InternalJournalLayout),
    /// Journal stored on a separate block device.
    External(ExternalJournalLayout),
}

impl JournalLocation {
    /// Selects the concrete device that stores this journal.
    const fn storage_target(&self) -> StorageTarget {
        match self {
            Self::Internal(_) => StorageTarget::Filesystem,
            Self::External(_) => StorageTarget::ExternalJournal,
        }
    }

    /// Copies this journal location without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the internal journal layout cannot allocate.
    fn try_clone(&self) -> Result<Self> {
        match self {
            Self::Internal(layout) => Ok(Self::Internal(layout.try_clone()?)),
            Self::External(layout) => Ok(Self::External(*layout)),
        }
    }

    /// Maps a logical journal block to a byte offset on its backing device.
    /// # Errors
    ///
    /// Returns an error when the logical block is not backed by the internal layout or exceeds the
    /// external journal capacity.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        match self {
            Self::Internal(layout) => block_size.offset_of(layout.map_logical(logical)?),
            Self::External(_layout) => block_size.offset_of(BlockAddress::new(u64::from(logical))),
        }
    }

    /// Verifies that the journal ring is backed by the selected location.
    /// # Errors
    ///
    /// Returns an error when the selected physical location does not cover the validated ring.
    fn validate_ring(&self, ring: &JournalRing) -> Result<()> {
        match self {
            Self::Internal(layout) => layout.validate_ring(ring),
            Self::External(layout) => layout.validate_ring(ring),
        }
    }

    /// Returns whether a filesystem home block overlaps the internal journal.
    /// # Errors
    ///
    /// Returns an error when the internal journal extent mapping cannot be evaluated.
    fn contains_home_block(&self, block: BlockAddress) -> Result<bool> {
        match self {
            Self::Internal(layout) => layout.contains_physical(block),
            Self::External(_) => Ok(false),
        }
    }

    /// Returns the first ring block dictated by this physical layout.
    /// # Errors
    ///
    /// Returns an error when the external superblock position has no following block.
    fn expected_first(&self) -> Result<u32> {
        match self {
            Self::Internal(_) => Ok(1),
            Self::External(layout) => layout
                .superblock_block
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow),
        }
    }

    /// Maps the journal superblock independently from ring-block identity.
    /// # Errors
    ///
    /// Returns an error when the internal mapping is absent or byte-offset arithmetic overflows.
    fn superblock_offset(&self, block_size: BlockSize) -> Result<ByteOffset> {
        match self {
            Self::Internal(layout) => block_size.offset_of(layout.map_logical(0)?),
            Self::External(layout) => layout.superblock_offset(block_size),
        }
    }
}

/// Identity-mapped external JBD2 device with a separately located journal superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExternalJournalLayout {
    /// Total complete device blocks.
    capacity_blocks: u32,
    /// Device block containing the JBD2 superblock.
    superblock_block: u32,
}

impl ExternalJournalLayout {
    /// Builds checked external layout geometry.
    /// # Errors
    ///
    /// Returns an error when the JBD2 superblock lies outside the complete device blocks.
    fn new(capacity_blocks: u32, superblock_block: u32) -> Result<Self> {
        if superblock_block >= capacity_blocks {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            capacity_blocks,
            superblock_block,
        })
    }

    /// Returns the physical byte offset of the JBD2 superblock.
    /// # Errors
    ///
    /// Returns an error when block-to-byte multiplication overflows.
    fn superblock_offset(self, block_size: BlockSize) -> Result<ByteOffset> {
        block_size.offset_of(BlockAddress::new(u64::from(self.superblock_block)))
    }

    /// Verifies that the ring stays inside the device and begins after the superblock.
    /// # Errors
    ///
    /// Returns an error when the ring begins elsewhere or exceeds device capacity.
    fn validate_ring(self, ring: &JournalRing) -> Result<()> {
        let expected_first = self
            .superblock_block
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        if ring.first == expected_first && ring.maxlen <= self.capacity_blocks {
            Ok(())
        } else {
            Err(Error::UnsupportedJournal)
        }
    }
}

/// Dedicated ext-family superblock facts required to locate an external JBD2 journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExternalJournalDeviceSuperblock {
    /// Block size shared by the external ext header and JBD2 device.
    block_size: BlockSize,
    /// Device block immediately after the ext superblock that stores the JBD2 superblock.
    superblock_block: u32,
}

/// UUID-first probe classification for a candidate external journal device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExternalDeviceSuperblockProbe {
    /// Candidate UUID differs, so discovery may inspect another device.
    Mismatch,
    /// UUID matches and every dedicated-journal header invariant is valid.
    Match(ExternalJournalDeviceSuperblock),
}

impl ExternalJournalDeviceSuperblock {
    /// Compares UUID before interpreting any other candidate bytes, then validates journal-device
    /// structure for an exact match.
    /// # Errors
    ///
    /// Returns an error when a UUID-matching candidate is not a valid dedicated journal header.
    fn parse(
        raw: &[u8; EXTERNAL_EXT_SUPERBLOCK_BYTES],
        expected: JournalUuid,
    ) -> Result<ExternalDeviceSuperblockProbe> {
        let mut uuid = [0_u8; 16];
        memory::copy_exact(
            &mut uuid,
            raw.get(0x68..0x78).ok_or(Error::TruncatedStructure)?,
        )?;
        if uuid != expected.bytes() {
            return Ok(ExternalDeviceSuperblockProbe::Mismatch);
        }
        if le_u16(raw, disk_offset(0x38))? != EXT4_SUPER_MAGIC
            || le_u32(raw, disk_offset(0x60))? != EXT4_FEATURE_INCOMPAT_JOURNAL_DEV
            || le_u32(raw, disk_offset(0x5C))? != 0
            || le_u32(raw, disk_offset(0x64))? != 0
        {
            return Err(Error::JournalCorrupt);
        }
        let block_size = BlockSize::from_superblock_log(le_u32(raw, disk_offset(0x18))?)?;
        let superblock_block = u32::try_from(
            EXTERNAL_EXT_SUPERBLOCK_OFFSET
                .checked_div(u64::from(block_size.bytes()))
                .ok_or(Error::ArithmeticOverflow)?
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?,
        )
        .map_err(|_| Error::ArithmeticOverflow)?;
        Ok(ExternalDeviceSuperblockProbe::Match(Self {
            block_size,
            superblock_block,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Extent-backed layout for a journal inode stored inside the filesystem.
struct InternalJournalLayout {
    /// Journal inode extents mapped into logical journal order.
    extents: Vec<JournalExtent>,
    /// Total blocks addressable by the journal inode.
    capacity_blocks: u32,
}

impl InternalJournalLayout {
    /// Copies this internal journal layout without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the extent list cannot allocate.
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            extents: memory::copied_slice(&self.extents)?,
            capacity_blocks: self.capacity_blocks,
        })
    }

    /// Converts inode extents into a contiguous logical journal layout.
    /// # Errors
    ///
    /// Returns an error when an inode extent exceeds journal capacity or its logical/physical bounds
    /// overflow.
    fn new(
        extents: &[crate::disk_format::extent::Extent],
        capacity_blocks: u32,
        filesystem_blocks: u64,
    ) -> Result<Self> {
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(extents.len())
            .map_err(|_| Error::OutOfMemory)?;
        for extent in extents {
            if extent.initialization() != ExtentInitialization::Initialized {
                return Err(Error::UnsupportedJournal);
            }
            let len = extent.len().as_u32();
            let logical_start = extent.logical_start().as_u32();
            let logical_end = logical_start
                .checked_add(len)
                .ok_or(Error::ArithmeticOverflow)?;
            if logical_end > capacity_blocks {
                return Err(Error::UnsupportedJournal);
            }
            let mapped_extent =
                JournalExtent::new(logical_start, logical_end, extent.physical_start(), len)?;
            if mapped_extent.physical_end > filesystem_blocks {
                return Err(Error::UnsupportedJournal);
            }
            mapped.try_push(mapped_extent)?;
        }
        memory::heap_sort_by(&mut mapped, |left, right| {
            left.logical_start.cmp(&right.logical_start)
        })?;
        let mut logical_cursor = 0_u32;
        for (index, extent) in mapped.iter().enumerate() {
            if extent.logical_start != logical_cursor {
                return Err(Error::UnsupportedJournal);
            }
            logical_cursor = extent.logical_end;
            for prior in mapped.get(..index).ok_or(Error::InvalidWriteRange)? {
                if extent.physical_start.get() < prior.physical_end
                    && prior.physical_start.get() < extent.physical_end
                {
                    return Err(Error::UnsupportedJournal);
                }
            }
        }
        if logical_cursor != capacity_blocks {
            return Err(Error::UnsupportedJournal);
        }
        Ok(Self {
            extents: mapped,
            capacity_blocks,
        })
    }

    /// Verifies that extents cover the journal ring from logical block zero.
    /// # Errors
    ///
    /// Returns an error when journal inode extents are not contiguous from block zero through the
    /// ring end.
    fn validate_ring(&self, ring: &JournalRing) -> Result<()> {
        let mut expected = 0_u32;
        for extent in &self.extents {
            if extent.logical_start != expected {
                return Err(Error::UnsupportedJournal);
            }
            expected = extent.logical_end;
            if expected >= ring.maxlen {
                return Ok(());
            }
        }
        Err(Error::UnsupportedJournal)
    }

    /// Maps a logical journal block through the journal inode extents.
    /// # Errors
    ///
    /// Returns an error when no journal inode extent covers `logical` or the physical mapping
    /// overflows.
    fn map_logical(&self, logical: u32) -> Result<BlockAddress> {
        for extent in &self.extents {
            if let Some(block) = extent.map_logical(logical)? {
                return Ok(block);
            }
        }
        Err(Error::UnsupportedJournal)
    }

    /// Returns whether a physical filesystem block belongs to the journal inode.
    /// # Errors
    ///
    /// Returns an error when an extent's physical range cannot be evaluated.
    fn contains_physical(&self, block: BlockAddress) -> Result<bool> {
        for extent in &self.extents {
            if extent.contains_physical(block) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// One contiguous extent in the journal inode's logical address space.
struct JournalExtent {
    /// Inclusive logical start block in the journal inode.
    logical_start: u32,
    /// Exclusive logical end block in the journal inode.
    logical_end: u32,
    /// First physical filesystem block for this journal extent.
    physical_start: BlockAddress,
    /// Exclusive physical filesystem block after this journal extent.
    physical_end: u64,
}

impl JournalExtent {
    /// Builds a checked journal extent from logical and physical bounds.
    /// # Errors
    ///
    /// Returns an error when `physical_start + len` overflows.
    fn new(
        logical_start: u32,
        logical_end: u32,
        physical_start: BlockAddress,
        len: u32,
    ) -> Result<Self> {
        let physical_end = physical_start
            .get()
            .checked_add(u64::from(len))
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Self {
            logical_start,
            logical_end,
            physical_start,
            physical_end,
        })
    }

    /// Maps a logical journal block when it falls inside this extent.
    /// # Errors
    ///
    /// Returns an error when subtracting the extent start or adding the physical offset overflows.
    fn map_logical(self, logical: u32) -> Result<Option<BlockAddress>> {
        if logical < self.logical_start || logical >= self.logical_end {
            return Ok(None);
        }
        let offset = logical
            .checked_sub(self.logical_start)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Some(BlockAddress::new(
            self.physical_start
                .get()
                .checked_add(u64::from(offset))
                .ok_or(Error::ArithmeticOverflow)?,
        )))
    }

    /// Returns whether a physical block lies inside this extent.
    fn contains_physical(self, block: BlockAddress) -> bool {
        block.get() >= self.physical_start.get() && block.get() < self.physical_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// JBD2 superblock generation controlling clean-head representation.
enum JournalSuperblockVersion {
    /// Legacy superblock with an implicit clean head at `s_first`.
    V1,
    /// Current superblock with explicit `s_head` and feature fields.
    V2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Parsed JBD2 superblock with raw bytes retained for state updates.
pub(crate) struct JournalSuperblock {
    /// Raw superblock image used as the base for clean/dirty rewrites.
    raw: Vec<u8>,
    /// On-disk JBD2 superblock generation.
    version: JournalSuperblockVersion,
    /// Journal block size recorded by `s_blocksize`.
    block_size: u32,
    /// Total logical blocks recorded by `s_maxlen`.
    maxlen: u32,
    /// First usable logical block recorded by `s_first`.
    first: u32,
    /// Next transaction sequence recorded by `s_sequence`.
    sequence: JournalSequence,
    /// First pending transaction block recorded by `s_start`.
    start: u32,
    /// Aborted-journal error code recorded by JBD2.
    errno: u32,
    /// JBD2 compatible feature bits.
    compat: u32,
    /// JBD2 incompatible feature bits.
    incompat: u32,
    /// JBD2 read-only compatible feature bits.
    ro_compat: u32,
    /// Filesystem UUID copied into journal checksum inputs.
    uuid: [u8; 16],
    /// JBD2 checksum type byte from the superblock.
    checksum_type: u8,
    /// Clean-log head recorded by v2 superblocks.
    head: u32,
    /// Number of filesystems attached to an external journal.
    nr_users: u32,
    /// First external-journal user UUID.
    first_user: [u8; 16],
}

impl JournalSuperblock {
    /// Copies this parsed superblock without infallible allocation.
    /// # Errors
    ///
    /// Returns an error when copying the raw superblock image cannot allocate.
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            raw: memory::copied_slice(&self.raw)?,
            version: self.version,
            block_size: self.block_size,
            maxlen: self.maxlen,
            first: self.first,
            sequence: self.sequence,
            start: self.start,
            errno: self.errno,
            compat: self.compat,
            incompat: self.incompat,
            ro_compat: self.ro_compat,
            uuid: self.uuid,
            checksum_type: self.checksum_type,
            head: self.head,
            nr_users: self.nr_users,
            first_user: self.first_user,
        })
    }

    /// Parses and verifies a JBD2 superblock image.
    /// # Errors
    ///
    /// Returns an error when the image is truncated, lacks a JBD2 superblock header, has an invalid
    /// superblock checksum, or required fields are missing.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < JOURNAL_SUPERBLOCK_BYTES {
            return Err(Error::TruncatedStructure);
        }
        let header = Jbd2Header::parse(bytes)?;
        let version = match header.block_type() {
            JBD2_SUPERBLOCK_V1 => JournalSuperblockVersion::V1,
            JBD2_SUPERBLOCK_V2 => JournalSuperblockVersion::V2,
            _ => return Err(Error::UnsupportedJournal),
        };
        let mut uuid = [0_u8; 16];
        memory::copy_exact(
            &mut uuid,
            bytes.get(0x30..0x40).ok_or(Error::TruncatedStructure)?,
        )?;
        let mut first_user = [0_u8; 16];
        memory::copy_exact(
            &mut first_user,
            bytes.get(0x100..0x110).ok_or(Error::TruncatedStructure)?,
        )?;
        if be_u32(bytes, disk_offset(0xFC))? != 0 {
            verify_journal_superblock_checksum(bytes)?;
        }
        Ok(Self {
            raw: memory::copied_slice(bytes)?,
            version,
            block_size: be_u32(bytes, disk_offset(0x0C))?,
            maxlen: be_u32(bytes, disk_offset(0x10))?,
            first: be_u32(bytes, disk_offset(0x14))?,
            sequence: JournalSequence::new(be_u32(bytes, disk_offset(0x18))?),
            start: be_u32(bytes, disk_offset(0x1C))?,
            errno: be_u32(bytes, disk_offset(0x20))?,
            compat: be_u32(bytes, disk_offset(0x24))?,
            incompat: be_u32(bytes, disk_offset(0x28))?,
            ro_compat: be_u32(bytes, disk_offset(0x2C))?,
            uuid,
            checksum_type: *bytes.get(0x50).ok_or(Error::TruncatedStructure)?,
            head: be_u32(bytes, disk_offset(0x58))?,
            nr_users: be_u32(bytes, disk_offset(0x40))?,
            first_user,
        })
    }

    /// Encodes a superblock image with updated sequence and start fields.
    /// # Errors
    ///
    /// Returns an error when the retained raw superblock length does not match `block_size` or the
    /// sequence/start/checksum fields cannot be rewritten.
    fn encode_with_state(
        &self,
        block_size: BlockSize,
        sequence: JournalSequence,
        start: u32,
        head: u32,
    ) -> Result<Vec<u8>> {
        let block_len =
            usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?;
        if self.raw.len() != block_len {
            return Err(Error::JournalCorrupt);
        }
        let mut block = memory::copied_slice(&self.raw)?;
        put_be_u32(&mut block, disk_offset(0x18), sequence.get())?;
        put_be_u32(&mut block, disk_offset(0x1C), start)?;
        if self.version == JournalSuperblockVersion::V2 {
            put_be_u32(&mut block, disk_offset(0x58), head)?;
        }
        if self.has_superblock_checksum()? {
            refresh_journal_superblock_checksum(&mut block)?;
        }
        Ok(block)
    }

    /// Encodes a clean journal superblock with no pending transaction tail.
    /// # Errors
    ///
    /// Returns an error when the clean sequence/start state cannot be encoded into a valid
    /// superblock image.
    fn encode_clean(&self, block_size: BlockSize, cursor: JournalCursor) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, cursor.sequence.previous(), 0, cursor.head)
    }

    /// Encodes a dirty journal superblock pointing at a transaction descriptor.
    /// # Errors
    ///
    /// Returns an error when the dirty sequence/start state cannot be encoded into a valid
    /// superblock image.
    fn encode_dirty(
        &self,
        block_size: BlockSize,
        start: u32,
        sequence: JournalSequence,
    ) -> Result<Vec<u8>> {
        self.encode_with_state(block_size, sequence, start, start)
    }

    /// Applies the clean superblock state after it has been written.
    fn apply_clean(&mut self, cursor: JournalCursor, raw: Vec<u8>) {
        self.sequence = cursor.sequence.previous();
        self.start = 0;
        self.head = cursor.head;
        self.raw = raw;
    }

    /// Applies the dirty superblock state after it has been written.
    fn apply_dirty(&mut self, start: u32, sequence: JournalSequence, raw: Vec<u8>) {
        self.start = start;
        self.sequence = sequence;
        self.raw = raw;
    }

    /// Returns the total logical block count recorded by the superblock.
    pub(crate) const fn maxlen(&self) -> u32 {
        self.maxlen
    }

    /// Returns the first usable logical journal block.
    pub(crate) const fn first(&self) -> u32 {
        self.first
    }

    /// Returns the first pending transaction block, or zero when clean.
    pub(crate) const fn start(&self) -> u32 {
        self.start
    }

    /// Returns the UUID used by JBD2 checksum calculations.
    pub(crate) const fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// Returns whether the journal superblock checksum field is populated.
    /// # Errors
    ///
    /// Returns an error when the checksum field is outside the retained raw superblock image.
    fn has_superblock_checksum(&self) -> Result<bool> {
        Ok(be_u32(&self.raw, disk_offset(0xFC))? != 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Common JBD2 control block header.
pub(crate) struct Jbd2Header {
    /// JBD2 control block type.
    block_type: u32,
    /// Transaction sequence associated with the control block.
    sequence: u32,
}

impl Jbd2Header {
    /// Parses the common JBD2 control block header.
    /// # Errors
    ///
    /// Returns an error when the header is truncated or the JBD2 magic does not match.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        if be_u32(bytes, disk_offset(0))? != JBD2_MAGIC {
            return Err(Error::JournalCorrupt);
        }
        Ok(Self {
            block_type: be_u32(bytes, disk_offset(4))?,
            sequence: be_u32(bytes, disk_offset(8))?,
        })
    }

    /// Builds a descriptor block header for a transaction sequence.
    pub(crate) fn descriptor(sequence: u32) -> Self {
        Self {
            block_type: JBD2_DESCRIPTOR_BLOCK,
            sequence,
        }
    }

    /// Builds a commit block header for a transaction sequence.
    pub(crate) fn commit(sequence: u32) -> Self {
        Self {
            block_type: JBD2_COMMIT_BLOCK,
            sequence,
        }
    }

    /// Writes the common JBD2 header fields into a block image.
    /// # Errors
    ///
    /// Returns an error when the destination block is too small for a JBD2 header.
    pub(crate) fn encode(self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(Error::TruncatedStructure);
        }
        put_be_u32(bytes, disk_offset(0), JBD2_MAGIC)?;
        put_be_u32(bytes, disk_offset(4), self.block_type)?;
        put_be_u32(bytes, disk_offset(8), self.sequence)
    }

    /// Returns the JBD2 control block type.
    pub(crate) const fn block_type(self) -> u32 {
        self.block_type
    }

    /// Returns the transaction sequence stored in the header.
    pub(crate) const fn sequence(self) -> u32 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Serialized transaction ready to be written to the journal.
struct PreparedJournalTransaction {
    /// Sequence number encoded into descriptor and commit blocks.
    sequence: JournalSequence,
    /// Logical journal block where the descriptor will be written.
    descriptor: u32,
    /// Descriptor and escaped payload blocks in exact on-disk order.
    log_blocks: Vec<Vec<u8>>,
    /// Logical journal block where the commit record is written.
    commit: u32,
    /// Cursor stored after checkpoint or recovery completes.
    next_cursor: JournalCursor,
    /// Serialized commit block.
    commit_block: Vec<u8>,
}

/// Exact log-space accounting for one full-commit transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalCredits {
    /// Number of descriptor blocks required by the tag stream.
    descriptors: usize,
    /// Number of metadata payload blocks.
    payloads: usize,
    /// Descriptor, payload, and final commit blocks combined.
    total: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Descriptor tag for one following data block.
struct JournalTag {
    /// Filesystem home block for the following payload.
    block: BlockAddress,
    /// JBD2 tag flags controlling UUID, escape, delete, and tail semantics.
    flags: u32,
    /// Stored data-block checksum.
    checksum: u32,
}

impl<State> Journal<State> {
    /// Maps a logical journal block to a byte offset for this journal.
    /// # Errors
    ///
    /// Returns an error when the journal location cannot map `logical` to a device offset.
    fn offset_of(&self, logical: u32, block_size: BlockSize) -> Result<ByteOffset> {
        self.location.offset_of(logical, block_size)
    }
}

/// Reads a logical journal block from an arbitrary journal location.
/// # Errors
///
/// Returns an error when the location cannot map `logical` or the backing reader fails.
fn read_journal_block(
    reader: &mut OperationDevice<'_>,
    location: &JournalLocation,
    block_size: BlockSize,
    logical: u32,
    out: &mut [u8],
) -> Result<()> {
    let offset = location.offset_of(logical, block_size)?;
    reader.read_exact_at(offset, out)
}

/// Returns whether a metadata payload must be escaped before journaling.
fn starts_with_jbd2_magic(bytes: &[u8]) -> bool {
    bytes
        .get(0..4)
        .is_some_and(|prefix| prefix == JBD2_MAGIC.to_be_bytes())
}

/// Rejects descriptor tag flags this journal implementation cannot interpret.
/// # Errors
///
/// Returns an error when any tag flag outside the supported escape, same-UUID, deleted, and last-tag
/// set is present.
fn validate_tag_flags(flags: u32) -> Result<()> {
    const SUPPORTED_TAG_FLAGS: u32 = JBD2_TAG_FLAG_ESCAPE
        | JBD2_TAG_FLAG_SAME_UUID
        | JBD2_TAG_FLAG_DELETED
        | JBD2_TAG_FLAG_LAST_TAG;
    if flags & !SUPPORTED_TAG_FLAGS == 0 {
        Ok(())
    } else {
        Err(Error::UnsupportedJournal)
    }
}

/// Verifies the checksum stored in a journal superblock.
/// # Errors
///
/// Returns an error when the checksum field is truncated or the computed checksum differs from the
/// stored value.
fn verify_journal_superblock_checksum(block: &[u8]) -> Result<()> {
    let expected = be_u32(block, disk_offset(0xFC))?;
    let actual = journal_superblock_checksum(block)?;
    if expected == actual {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

/// Recomputes and writes the journal superblock checksum.
/// # Errors
///
/// Returns an error when the journal superblock checksum field cannot be zeroed or rewritten.
fn refresh_journal_superblock_checksum(block: &mut [u8]) -> Result<()> {
    put_be_u32(block, disk_offset(0xFC), 0)?;
    let checksum = journal_superblock_checksum(block)?;
    put_be_u32(block, disk_offset(0xFC), checksum)
}

/// Computes a journal superblock checksum with its checksum field zeroed.
/// # Errors
///
/// Returns an error when the superblock body or checksum field is truncated.
fn journal_superblock_checksum(block: &[u8]) -> Result<u32> {
    let checked = block
        .get(..JOURNAL_SUPERBLOCK_BYTES)
        .ok_or(Error::TruncatedStructure)?;
    let prefix = checked.get(..0xFC).ok_or(Error::TruncatedStructure)?;
    let suffix = checked.get(0x100..).ok_or(Error::TruncatedStructure)?;
    let seed = ext4_crc32c(u32::MAX, prefix);
    let seed = ext4_crc32c(seed, &[0_u8; 4]);
    Ok(ext4_crc32c(seed, suffix))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::marker::PhantomData;

    use crate::disk::block::{BlockAddress, BlockSize};
    use crate::disk::endian::{DiskOffset, put_be_u16, put_be_u32, put_le_u16, put_le_u32};
    use crate::disk_format::extent::{Extent, ExtentLength, LogicalBlock};
    use crate::disk_format::superblock::{JournalUuid, RecoveryState};
    use crate::{Error, Result};

    use super::{
        EXT4_FEATURE_INCOMPAT_JOURNAL_DEV, EXT4_SUPER_MAGIC, EXTERNAL_EXT_SUPERBLOCK_BYTES,
        ExternalDeviceSuperblockProbe, ExternalJournalDeviceSuperblock, ExternalJournalLayout,
        InternalJournalLayout, JBD2_CHECKSUM_CRC32C, JBD2_FEATURE_COMPAT_CHECKSUM,
        JBD2_FEATURE_INCOMPAT_64BIT, JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT,
        JBD2_FEATURE_INCOMPAT_CSUM_V2, JBD2_FEATURE_INCOMPAT_CSUM_V3,
        JBD2_FEATURE_INCOMPAT_FAST_COMMIT, JBD2_FEATURE_INCOMPAT_REVOKE, JBD2_REVOKE_BLOCK,
        JBD2_TAG_FLAG_LAST_TAG, JBD2_TAG_FLAG_SAME_UUID, JOURNAL_COMMIT_CHECKSUM_OFFSET,
        JOURNAL_HEADER_BYTES, JOURNAL_SUPERBLOCK_BYTES, Jbd2Header, Journal, JournalCursor,
        JournalGeometry, JournalLocation, JournalProfile, JournalRecoveryOperation, JournalRing,
        JournalSequence, JournalSuperblock, JournalSuperblockVersion, LoadedJournal, MetadataBlock,
        RecoveryPhase, RecoveryRevoke, journal_superblock_checksum,
    };

    /// Stable UUID used by private JBD2 wire fixtures.
    const TEST_UUID: [u8; 16] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE,
        0x0F,
    ];

    /// Builds one test JBD2 superblock domain value without passing through its wire parser.
    /// # Errors
    ///
    /// Returns an error when the block-sized retained image cannot be represented or allocated.
    fn test_superblock(
        block_size: BlockSize,
        incompat: u32,
        maxlen: u32,
        first: u32,
        sequence: u32,
        start: u32,
        head: u32,
    ) -> Result<JournalSuperblock> {
        Ok(JournalSuperblock {
            raw: vec![
                0_u8;
                usize::try_from(block_size.bytes()).map_err(|_| Error::ArithmeticOverflow)?
            ],
            version: JournalSuperblockVersion::V2,
            block_size: block_size.bytes(),
            maxlen,
            first,
            sequence: JournalSequence::new(sequence),
            start,
            errno: 0,
            compat: 0,
            incompat,
            ro_compat: 0,
            uuid: TEST_UUID,
            checksum_type: JBD2_CHECKSUM_CRC32C,
            head,
            nr_users: 1,
            first_user: TEST_UUID,
        })
    }

    /// Builds an identity-mapped external journal with a selected typestate.
    /// # Errors
    ///
    /// Returns an error for invalid block size, layout, profile, ring, cursor, or allocation.
    fn test_external_journal<State>(
        block_log: u32,
        incompat: u32,
        maxlen: u32,
        sequence: u32,
        start: u32,
        head: u32,
        filesystem_blocks: u64,
    ) -> Result<Journal<State>> {
        let block_size = BlockSize::from_superblock_log(block_log)?;
        let superblock_block = 1024_u32
            .checked_div(block_size.bytes())
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ArithmeticOverflow)?;
        let first = superblock_block
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        let superblock =
            test_superblock(block_size, incompat, maxlen, first, sequence, start, head)?;
        let profile = JournalProfile::from_superblock(&superblock)?;
        let ring = JournalRing::new(&superblock, maxlen, first)?;
        let cursor = JournalCursor::from_superblock(&superblock, ring)?;
        Ok(Journal {
            location: JournalLocation::External(ExternalJournalLayout::new(
                maxlen,
                superblock_block,
            )?),
            superblock,
            profile,
            geometry: JournalGeometry { block_size, ring },
            cursor,
            filesystem_blocks,
            state: PhantomData,
        })
    }

    /// Builds a known-answer commit whose first sector is durable and later sector remains stale.
    /// # Errors
    ///
    /// Returns an error when fixed fixture fields fall outside the journal block.
    fn partial_commit_block_fixture() -> Result<Vec<u8>> {
        let mut block = vec![0_u8; 1024];
        crate::memory::copy_exact(
            block
                .get_mut(..JOURNAL_HEADER_BYTES)
                .ok_or(Error::TruncatedStructure)?,
            &[
                0xC0, 0x3B, 0x39, 0x98, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x11,
            ],
        )?;
        put_be_u32(
            &mut block,
            DiskOffset::new(JOURNAL_COMMIT_CHECKSUM_OFFSET),
            0xF3C6_0B55,
        )?;
        block
            .get_mut(512..)
            .ok_or(Error::TruncatedStructure)?
            .fill(0xA5);
        Ok(block)
    }

    /// Creates one initialized extent for internal-journal layout tests.
    /// # Errors
    ///
    /// Returns an error when `len` is not an encodable nonzero initialized extent length.
    fn test_extent(logical: u32, len: u16, physical: u64) -> Result<Extent> {
        Ok(Extent::initialized(
            LogicalBlock::from_u32(logical),
            ExtentLength::new(len)?,
            BlockAddress::new(physical),
        ))
    }

    /// Creates a valid external-journal ext superblock header.
    /// # Errors
    ///
    /// Returns an error when a fixed wire field cannot be encoded into the test header.
    fn external_device_header(block_log: u32, uuid: [u8; 16]) -> Result<[u8; 1024]> {
        let mut raw = [0_u8; EXTERNAL_EXT_SUPERBLOCK_BYTES];
        put_le_u32(&mut raw, DiskOffset::new(0x18), block_log)?;
        put_le_u16(&mut raw, DiskOffset::new(0x38), EXT4_SUPER_MAGIC)?;
        put_le_u32(
            &mut raw,
            DiskOffset::new(0x60),
            EXT4_FEATURE_INCOMPAT_JOURNAL_DEV,
        )?;
        crate::memory::copy_exact(
            raw.get_mut(0x68..0x78).ok_or(Error::TruncatedStructure)?,
            &uuid,
        )?;
        Ok(raw)
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn journal_superblock_checksum_starts_from_the_kernel_crc_state() {
        assert_eq!(
            journal_superblock_checksum(&[0_u8; JOURNAL_SUPERBLOCK_BYTES]),
            Ok(0x1151_2183)
        );
    }

    /// # Panics
    ///
    /// Panics when unsupported JBD2 feature combinations enter the validated domain.
    #[test]
    fn journal_profile_rejects_every_unsupported_feature_boundary() {
        let outcome = (|| -> Result<()> {
            let block_size = BlockSize::from_superblock_log(0)?;
            let mut cases = [
                (JBD2_FEATURE_COMPAT_CHECKSUM, 0, 0, 0, JBD2_CHECKSUM_CRC32C),
                (
                    0,
                    JBD2_FEATURE_INCOMPAT_CSUM_V2 | JBD2_FEATURE_INCOMPAT_CSUM_V3,
                    0,
                    0,
                    JBD2_CHECKSUM_CRC32C,
                ),
                (0, JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT, 0, 0, 0),
                (0, JBD2_FEATURE_INCOMPAT_FAST_COMMIT, 0, 0, 0),
                (0, 0x8000_0000, 0, 0, 0),
                (0, 0, 1, 0, 0),
                (0, 0, 0, 5, 0),
                (0, JBD2_FEATURE_INCOMPAT_CSUM_V3, 0, 0, 1),
            ];
            for (compat, incompat, ro_compat, errno, checksum_type) in &mut cases {
                let mut superblock = test_superblock(block_size, *incompat, 64, 2, 9, 0, 2)?;
                superblock.compat = *compat;
                superblock.ro_compat = *ro_compat;
                superblock.errno = *errno;
                superblock.checksum_type = *checksum_type;
                assert_eq!(
                    JournalProfile::from_superblock(&superblock),
                    Err(Error::UnsupportedJournal)
                );
            }

            for incompat in [
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V2,
                JBD2_FEATURE_INCOMPAT_CSUM_V3,
                JBD2_FEATURE_INCOMPAT_CSUM_V3
                    | JBD2_FEATURE_INCOMPAT_64BIT
                    | JBD2_FEATURE_INCOMPAT_REVOKE,
            ] {
                let superblock = test_superblock(block_size, incompat, 64, 2, 9, 0, 2)?;
                assert!(JournalProfile::from_superblock(&superblock).is_ok());
            }
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when external journal headers are not UUID-first or use the wrong 1/2/4 KiB layout.
    #[test]
    fn external_journal_header_is_uuid_first_and_block_size_aware() {
        let outcome = (|| -> Result<()> {
            for (block_log, expected_superblock) in [(0_u32, 2_u32), (1, 1), (2, 1)] {
                let raw = external_device_header(block_log, TEST_UUID)?;
                assert_eq!(
                    ExternalJournalDeviceSuperblock::parse(
                        &raw,
                        JournalUuid::from_bytes(TEST_UUID)
                    )?,
                    ExternalDeviceSuperblockProbe::Match(ExternalJournalDeviceSuperblock {
                        block_size: BlockSize::from_superblock_log(block_log)?,
                        superblock_block: expected_superblock,
                    })
                );
            }

            let corrupt_other_uuid = [0_u8; EXTERNAL_EXT_SUPERBLOCK_BYTES];
            assert_eq!(
                ExternalJournalDeviceSuperblock::parse(
                    &corrupt_other_uuid,
                    JournalUuid::from_bytes(TEST_UUID)
                ),
                Ok(ExternalDeviceSuperblockProbe::Mismatch)
            );
            assert_eq!(
                ExternalJournalDeviceSuperblock::parse(
                    &corrupt_other_uuid,
                    JournalUuid::from_bytes([0_u8; 16])
                ),
                Err(Error::JournalCorrupt)
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when descriptor UUID ownership or `SAME_UUID` encoding differs from JBD2.
    #[test]
    fn every_descriptor_requires_an_explicit_first_uuid() {
        let outcome = (|| -> Result<()> {
            let journal = test_external_journal::<LoadedJournal>(0, 0, 64, 7, 0, 3, 1_000)?;
            let block_size = journal.geometry.block_size;
            let metadata = [
                MetadataBlock::new(BlockAddress::new(20), vec![0x11; 1024]),
                MetadataBlock::new(BlockAddress::new(21), vec![0x22; 1024]),
            ];
            let data = [vec![0x11; 1024], vec![0x22; 1024]];
            let descriptor = journal.encode_descriptor_block(
                JournalSequence::new(8),
                &metadata,
                &data,
                block_size,
            )?;
            let mut flags = [0_u32; 2];
            let mut count = 0_usize;
            journal.for_each_descriptor_tag(&descriptor, |tag| {
                let destination = flags.get_mut(count).ok_or(Error::JournalCorrupt)?;
                *destination = tag.flags;
                count = count.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
                Ok(())
            })?;
            assert_eq!(count, 2);
            assert_eq!(flags.first().copied(), Some(0));
            assert_eq!(
                flags.get(1).copied(),
                Some(JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG)
            );

            let mut invalid = descriptor;
            put_be_u16(
                &mut invalid,
                DiskOffset::new(
                    JOURNAL_HEADER_BYTES
                        .checked_add(6)
                        .ok_or(Error::ArithmeticOverflow)?,
                ),
                u16::try_from(JBD2_TAG_FLAG_SAME_UUID | JBD2_TAG_FLAG_LAST_TAG)
                    .map_err(|_| Error::ArithmeticOverflow)?,
            )?;
            assert_eq!(
                journal.for_each_descriptor_tag(&invalid, |_tag| Ok(())),
                Err(Error::JournalCorrupt)
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when the feature-dependent tag stride or first-tag UUID position differs from the
    /// Linux `journal_tag_bytes()` wire contract.
    #[test]
    fn descriptor_tag_stride_matches_jbd2_feature_layout() {
        let outcome = (|| -> Result<()> {
            for (incompat, expected_tag_size) in [
                (0, 8_usize),
                (JBD2_FEATURE_INCOMPAT_64BIT, 12),
                (JBD2_FEATURE_INCOMPAT_CSUM_V2, 10),
                (
                    JBD2_FEATURE_INCOMPAT_CSUM_V2 | JBD2_FEATURE_INCOMPAT_64BIT,
                    14,
                ),
                (JBD2_FEATURE_INCOMPAT_CSUM_V3, 16),
                (
                    JBD2_FEATURE_INCOMPAT_CSUM_V3 | JBD2_FEATURE_INCOMPAT_64BIT,
                    16,
                ),
            ] {
                let journal =
                    test_external_journal::<LoadedJournal>(0, incompat, 64, 7, 0, 3, 1_000)?;
                assert_eq!(journal.descriptor_tag_size(), expected_tag_size);
                let metadata = [MetadataBlock::new(BlockAddress::new(20), vec![0x5A; 1024])];
                let data = [vec![0x5A; 1024]];
                let descriptor = journal.encode_descriptor_block(
                    JournalSequence::new(8),
                    &metadata,
                    &data,
                    journal.geometry.block_size,
                )?;
                let uuid_start = JOURNAL_HEADER_BYTES
                    .checked_add(expected_tag_size)
                    .ok_or(Error::ArithmeticOverflow)?;
                let uuid_end = uuid_start
                    .checked_add(TEST_UUID.len())
                    .ok_or(Error::ArithmeticOverflow)?;
                assert_eq!(
                    descriptor.get(uuid_start..uuid_end),
                    Some(TEST_UUID.as_slice())
                );
            }
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when checksum-v2/v3 commit blocks populate the checksum-v1 metadata bytes.
    #[test]
    fn metadata_checksum_commit_header_keeps_v1_fields_zero() {
        let outcome = (|| -> Result<()> {
            for incompat in [JBD2_FEATURE_INCOMPAT_CSUM_V2, JBD2_FEATURE_INCOMPAT_CSUM_V3] {
                let journal =
                    test_external_journal::<LoadedJournal>(0, incompat, 64, 7, 0, 3, 1_000)?;
                let commit = journal
                    .encode_commit_block(JournalSequence::new(8), journal.geometry.block_size)?;
                assert_eq!(commit.get(0x0C..0x10), Some([0_u8; 4].as_slice()));
                journal.parse_commit_block(&commit, JournalSequence::new(8))?;

                let mut invalid = commit;
                *invalid.get_mut(0x0C).ok_or(Error::TruncatedStructure)? = 1;
                assert_eq!(
                    journal.parse_commit_block(&invalid, JournalSequence::new(8)),
                    Err(Error::JournalCorrupt)
                );
            }
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when checksum-v2/v3 recovery rejects an authenticated partial commit or accepts a
    /// corrupted persisted header.
    #[test]
    fn metadata_checksum_commit_accepts_only_authenticated_zero_filled_tail() {
        let outcome = (|| -> Result<()> {
            for incompat in [JBD2_FEATURE_INCOMPAT_CSUM_V2, JBD2_FEATURE_INCOMPAT_CSUM_V3] {
                let journal =
                    test_external_journal::<LoadedJournal>(0, incompat, 64, 17, 3, 3, 1_000)?;
                let partial = partial_commit_block_fixture()?;
                assert_ne!(
                    journal.block_checksum_with_zeroed(&partial, JOURNAL_COMMIT_CHECKSUM_OFFSET,)?,
                    0xF3C6_0B55
                );
                journal.parse_commit_block(&partial, JournalSequence::new(17))?;

                let mut corrupted = partial_commit_block_fixture()?;
                let commit_second = corrupted.get_mut(0x30).ok_or(Error::TruncatedStructure)?;
                *commit_second ^= 0x01;
                assert_eq!(
                    journal.parse_commit_block(&corrupted, JournalSequence::new(17)),
                    Err(Error::ChecksumMismatch)
                );
            }
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when exact tag widths do not cause a second descriptor at the wire boundary.
    #[test]
    fn descriptor_capacity_drives_multi_descriptor_credits() {
        let outcome = (|| -> Result<()> {
            let journal = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V3 | JBD2_FEATURE_INCOMPAT_64BIT,
                1_024,
                11,
                0,
                3,
                1_000_000,
            )?;
            let capacity = journal.descriptor_tag_capacity()?;
            let payloads = capacity.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            let credits = journal.journal_credits(payloads, journal.geometry.block_size)?;
            assert_eq!(credits.descriptors, 2);
            assert_eq!(
                credits.total,
                u32::try_from(payloads.checked_add(3).ok_or(Error::ArithmeticOverflow)?)
                    .map_err(|_| Error::ArithmeticOverflow)?
            );

            let mut metadata = Vec::new();
            metadata
                .try_reserve_exact(payloads)
                .map_err(|_| Error::OutOfMemory)?;
            for index in 0..payloads {
                metadata
                    .push_within_capacity(MetadataBlock::new(
                        BlockAddress::new(
                            100_u64
                                .checked_add(
                                    u64::try_from(index).map_err(|_| Error::ArithmeticOverflow)?,
                                )
                                .ok_or(Error::ArithmeticOverflow)?,
                        ),
                        vec![0xA5; 1024],
                    ))
                    .map_err(|_metadata| Error::OutOfMemory)?;
            }
            let prepared =
                journal.prepare_metadata_transaction(journal.geometry.block_size, &metadata)?;
            let mut descriptors = 0_usize;
            for block in &prepared.log_blocks {
                if let Ok(header) = super::Jbd2Header::parse(block)
                    && header.block_type() == super::JBD2_DESCRIPTOR_BLOCK
                {
                    descriptors = descriptors
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
            }
            assert_eq!(descriptors, 2);
            assert_eq!(
                super::Jbd2Header::parse(&prepared.commit_block)?.block_type(),
                super::JBD2_COMMIT_BLOCK
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when block-number width, ring wrapping, or sequence wrapping is encoded incorrectly.
    #[test]
    fn transaction_encoding_obeys_64bit_and_wrapping_domains() {
        let outcome = (|| -> Result<()> {
            let high_block = u64::from(u32::MAX)
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
            let metadata = [MetadataBlock::new(
                BlockAddress::new(high_block),
                vec![0x5A; 1024],
            )];
            let narrow = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V2,
                16,
                u32::MAX,
                14,
                14,
                high_block
                    .checked_add(10)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?;
            assert_eq!(
                narrow.prepare_metadata_transaction(narrow.geometry.block_size, &metadata),
                Err(Error::TransactionTooLarge)
            );

            let wide = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V3 | JBD2_FEATURE_INCOMPAT_64BIT,
                16,
                u32::MAX,
                14,
                14,
                high_block
                    .checked_add(10)
                    .ok_or(Error::ArithmeticOverflow)?,
            )?;
            let prepared =
                wide.prepare_metadata_transaction(wide.geometry.block_size, &metadata)?;
            assert_eq!(prepared.descriptor, 14);
            assert_eq!(prepared.commit, 3);
            assert_eq!(prepared.next_cursor.head, 4);
            assert_eq!(prepared.next_cursor.sequence, JournalSequence::new(0));
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when cursor recovery does not distinguish dirty, v1-clean, and v2-clean semantics.
    #[test]
    fn cursor_uses_start_for_dirty_and_head_for_clean_v2() {
        let outcome = (|| -> Result<()> {
            let block_size = BlockSize::from_superblock_log(0)?;
            let clean = test_superblock(block_size, 0, 32, 2, 41, 0, 9)?;
            let ring = JournalRing::new(&clean, 32, 2)?;
            assert_eq!(
                JournalCursor::from_superblock(&clean, ring)?,
                JournalCursor {
                    sequence: JournalSequence::new(42),
                    head: 9,
                }
            );

            let never_started = test_superblock(block_size, 0, 32, 2, 1, 0, 0)?;
            assert_eq!(
                JournalCursor::from_superblock(&never_started, ring)?,
                JournalCursor {
                    sequence: JournalSequence::new(2),
                    head: 2,
                }
            );

            let dirty = test_superblock(block_size, 0, 32, 2, 41, 7, 9)?;
            assert_eq!(
                JournalCursor::from_superblock(&dirty, ring)?,
                JournalCursor {
                    sequence: JournalSequence::new(41),
                    head: 7,
                }
            );

            let mut v1 = clean;
            v1.version = JournalSuperblockVersion::V1;
            assert_eq!(
                JournalCursor::from_superblock(&v1, ring)?,
                JournalCursor {
                    sequence: JournalSequence::new(42),
                    head: 2,
                }
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when internal journal holes, overlap, uninitialized storage, or range violations pass.
    #[test]
    fn internal_journal_layout_requires_complete_unique_initialized_storage() {
        let outcome = (|| -> Result<()> {
            assert_eq!(
                InternalJournalLayout::new(
                    &[test_extent(0, 1, 10)?, test_extent(2, 1, 20)?],
                    3,
                    100
                ),
                Err(Error::UnsupportedJournal)
            );
            assert_eq!(
                InternalJournalLayout::new(
                    &[test_extent(0, 2, 10)?, test_extent(2, 2, 11)?],
                    4,
                    100
                ),
                Err(Error::UnsupportedJournal)
            );
            assert_eq!(
                InternalJournalLayout::new(&[test_extent(0, 2, 99)?], 2, 100),
                Err(Error::UnsupportedJournal)
            );
            let uninitialized = Extent::uninitialized(
                LogicalBlock::from_u32(0),
                ExtentLength::new(2)?,
                BlockAddress::new(10),
            );
            assert_eq!(
                InternalJournalLayout::new(&[uninitialized], 2, 100),
                Err(Error::UnsupportedJournal)
            );
            let valid = InternalJournalLayout::new(
                &[test_extent(0, 2, 10)?, test_extent(2, 2, 30)?],
                4,
                100,
            )?;
            assert!(valid.contains_physical(BlockAddress::new(31))?);
            assert!(!valid.contains_physical(BlockAddress::new(20))?);
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when commit construction accepts duplicate, out-of-range, or journal-owned targets.
    #[test]
    fn commit_rejects_invalid_home_block_sets_before_serialization() {
        let outcome = (|| -> Result<()> {
            let external = test_external_journal::<LoadedJournal>(0, 0, 64, 7, 0, 3, 100)?;
            let duplicate = [
                MetadataBlock::new(BlockAddress::new(10), vec![0; 1024]),
                MetadataBlock::new(BlockAddress::new(10), vec![1; 1024]),
            ];
            assert_eq!(
                external.prepare_metadata_transaction(external.geometry.block_size, &duplicate),
                Err(Error::JournalCorrupt)
            );
            let outside = [MetadataBlock::new(BlockAddress::new(100), vec![0; 1024])];
            assert_eq!(
                external.prepare_metadata_transaction(external.geometry.block_size, &outside),
                Err(Error::JournalCorrupt)
            );

            let block_size = BlockSize::from_superblock_log(0)?;
            let superblock = test_superblock(block_size, 0, 16, 1, 7, 0, 1)?;
            let profile = JournalProfile::from_superblock(&superblock)?;
            let ring = JournalRing::new(&superblock, 16, 1)?;
            let internal = Journal::<LoadedJournal> {
                location: JournalLocation::Internal(InternalJournalLayout::new(
                    &[test_extent(0, 16, 40)?],
                    16,
                    100,
                )?),
                cursor: JournalCursor::from_superblock(&superblock, ring)?,
                superblock,
                profile,
                geometry: JournalGeometry { block_size, ring },
                filesystem_blocks: 100,
                state: PhantomData,
            };
            let collision = [MetadataBlock::new(BlockAddress::new(45), vec![0; 1024])];
            assert_eq!(
                internal.prepare_metadata_transaction(block_size, &collision),
                Err(Error::JournalCorrupt)
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when revoke decisions use record order instead of wrapping transaction sequence.
    #[test]
    fn revoke_decisions_use_same_or_later_transaction_sequence() {
        let outcome = (|| -> Result<()> {
            let journal = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_REVOKE,
                64,
                7,
                3,
                3,
                100,
            )?;
            let mut operation =
                JournalRecoveryOperation::new(journal, RecoveryState::NeedsRecovery)?;
            operation.revokes = vec![
                RecoveryRevoke {
                    block: BlockAddress::new(10),
                    sequence: JournalSequence::new(8),
                },
                RecoveryRevoke {
                    block: BlockAddress::new(11),
                    sequence: JournalSequence::new(0),
                },
            ];
            assert!(operation.is_revoked(BlockAddress::new(10), JournalSequence::new(8)));
            assert!(operation.is_revoked(BlockAddress::new(10), JournalSequence::new(7)));
            assert!(!operation.is_revoked(BlockAddress::new(10), JournalSequence::new(9)));
            assert!(operation.is_revoked(BlockAddress::new(11), JournalSequence::new(u32::MAX)));
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when a checksummed revoke block treats its block-end checksum tail as part of
    /// `r_count` instead of an independent wire field.
    #[test]
    fn revoke_count_excludes_the_independent_checksum_tail() {
        let outcome = (|| -> Result<()> {
            for (incompat, address) in [
                (
                    JBD2_FEATURE_INCOMPAT_REVOKE | JBD2_FEATURE_INCOMPAT_CSUM_V2,
                    0x1234_u64,
                ),
                (
                    JBD2_FEATURE_INCOMPAT_REVOKE
                        | JBD2_FEATURE_INCOMPAT_CSUM_V3
                        | JBD2_FEATURE_INCOMPAT_64BIT,
                    0x1234_5678_9ABC_DEF0,
                ),
            ] {
                let journal =
                    test_external_journal::<LoadedJournal>(0, incompat, 64, 7, 0, 3, u64::MAX)?;
                let entry_size = if journal.profile.has_64bit() { 8 } else { 4 };
                let used = 16_usize
                    .checked_add(entry_size)
                    .ok_or(Error::ArithmeticOverflow)?;
                let mut revoke = vec![0_u8; 1024];
                Jbd2Header {
                    block_type: JBD2_REVOKE_BLOCK,
                    sequence: 8,
                }
                .encode(&mut revoke)?;
                put_be_u32(
                    &mut revoke,
                    DiskOffset::new(JOURNAL_HEADER_BYTES),
                    u32::try_from(used).map_err(|_| Error::ArithmeticOverflow)?,
                )?;
                if entry_size == 8 {
                    crate::memory::copy_exact(
                        revoke.get_mut(16..24).ok_or(Error::TruncatedStructure)?,
                        &address.to_be_bytes(),
                    )?;
                } else {
                    put_be_u32(
                        &mut revoke,
                        DiskOffset::new(16),
                        u32::try_from(address).map_err(|_| Error::ArithmeticOverflow)?,
                    )?;
                }
                journal.write_block_tail_checksum(&mut revoke)?;
                assert_eq!(journal.revoke_count_for_scan(&revoke), Ok(1));
                let mut decoded = None;
                journal.for_each_revoke(&revoke, |block| {
                    decoded = Some(block);
                    Ok(())
                })?;
                assert_eq!(decoded, Some(BlockAddress::new(address)));

                put_be_u32(&mut revoke, DiskOffset::new(JOURNAL_HEADER_BYTES), 1_021)?;
                assert_eq!(
                    journal.revoke_count_for_scan(&revoke),
                    Err(Error::JournalCorrupt)
                );
            }
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when an unauthenticated torn commit becomes committed, an authenticated partial
    /// commit is discarded, or committed descriptor corruption is ignored.
    #[test]
    fn recovery_accepts_authenticated_partial_commit_and_rejects_corruption() {
        let outcome = (|| -> Result<()> {
            let journal = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V3,
                64,
                17,
                3,
                3,
                100,
            )?;
            let metadata = [MetadataBlock::new(BlockAddress::new(10), vec![0x44; 1024])];
            let data = [vec![0x44; 1024]];
            let descriptor = journal.encode_descriptor_block(
                JournalSequence::new(17),
                &metadata,
                &data,
                journal.geometry.block_size,
            )?;
            let commit = journal
                .encode_commit_block(JournalSequence::new(17), journal.geometry.block_size)?;

            let mut partial_recovery = JournalRecoveryOperation::new(
                journal.copy_without_state::<LoadedJournal>()?,
                RecoveryState::NeedsRecovery,
            )?;
            partial_recovery.scan_control_block(&descriptor)?;
            partial_recovery.scan_control_block(&partial_commit_block_fixture()?)?;
            partial_recovery.finish_scan()?;
            assert_eq!(partial_recovery.summary.transactions, 1);
            assert_eq!(
                partial_recovery.summary.next_sequence,
                JournalSequence::new(18)
            );

            let mut torn = commit.clone();
            let checksum_byte = torn.get_mut(0x10).ok_or(Error::TruncatedStructure)?;
            *checksum_byte ^= 0x80;
            let mut torn_recovery = JournalRecoveryOperation::new(
                journal.copy_without_state::<LoadedJournal>()?,
                RecoveryState::NeedsRecovery,
            )?;
            torn_recovery.scan_control_block(&descriptor)?;
            torn_recovery.scan_control_block(&torn)?;
            assert_eq!(torn_recovery.phase, RecoveryPhase::Validate);
            assert_eq!(torn_recovery.summary.transactions, 0);

            let mut committed =
                JournalRecoveryOperation::new(journal, RecoveryState::NeedsRecovery)?;
            committed.scan_control_block(&descriptor)?;
            committed.scan_control_block(&commit)?;
            committed.finish_scan()?;
            let mut corrupt_descriptor = descriptor;
            let tail = corrupt_descriptor
                .last_mut()
                .ok_or(Error::TruncatedStructure)?;
            *tail ^= 0x01;
            assert_eq!(
                committed.validate_or_replay_control_block(&corrupt_descriptor),
                Err(Error::ChecksumMismatch)
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics if a checksum-invalid primary can consume a clean journal or erase a dirty journal
    /// before a committed replacement primary payload has been validated.
    #[test]
    fn primary_repair_requires_committed_replacement_authority() {
        let outcome = (|| -> Result<()> {
            let clean = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V3,
                64,
                17,
                0,
                3,
                100,
            )?;
            assert!(matches!(
                JournalRecoveryOperation::repairing_primary(clean),
                Err(Error::ChecksumMismatch)
            ));

            let dirty = test_external_journal::<LoadedJournal>(
                0,
                JBD2_FEATURE_INCOMPAT_CSUM_V3,
                64,
                17,
                3,
                3,
                100,
            )?;
            let mut recovery = JournalRecoveryOperation::repairing_primary(dirty)?;
            assert_eq!(
                recovery.prepare_replay_and_clean(),
                Err(Error::ChecksumMismatch)
            );
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }

    /// # Panics
    ///
    /// Panics when recovery allocation reservation can fail after entering validation or replay.
    #[test]
    fn recovery_reserves_bounded_address_memory_before_validation() {
        let outcome = (|| -> Result<()> {
            let journal = test_external_journal::<LoadedJournal>(0, 0, 64, 5, 3, 3, 100)?;
            let mut operation =
                JournalRecoveryOperation::new(journal, RecoveryState::NeedsRecovery)?;
            operation.summary.max_transaction_tags = usize::MAX;
            assert_eq!(operation.finish_scan(), Err(Error::OutOfMemory));
            assert_eq!(operation.phase, RecoveryPhase::Scan);
            Ok(())
        })();
        assert_eq!(outcome, Ok(()));
    }
}
