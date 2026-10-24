//! Checkpointed free-space selection and completion-owned discard reservations.
//!
//! A reservation excludes allocation without changing the ext4 bitmap or committed ownership.
//! Its exact lower completion releases that exclusion even after session revocation. Dropping a
//! pending operation cannot release ranges still owned by a lower device.
use alloc::{sync::Arc, vec::Vec};
use core::num::{NonZeroU32, NonZeroU64};

use super::mount::{
    CommittedEpoch, CommittedReadContext, EpochSequence, MountIdentity, MountedProfile,
    MutationCoordinatorState,
};
use super::scope::{
    AllocationBitmapInitialization, AllocationBitmapKind, BitmapBitState, BlockGroupDescriptor,
    ClusterAddress, ClusterBitmapPosition, Superblock, cluster_bitmap_bit_state,
};
use crate::disk::storage::{OperationDevice, StorageTranscript};
use crate::memory::FallibleVec;
use crate::{ByteOffset, Error, OperationEvent, Result, StorageRequest, StorageTarget};

/// Maximum physical bytes accepted by one independently completed discard request.
pub const TRIM_BATCH_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum disjoint physical intervals retained by one discard reservation.
pub const TRIM_BATCH_RANGES: usize = 64;

/// Device-required alignment; trimming never expands a selected free interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimAlignment(NonZeroU32);
impl TrimAlignment {
    /// Admits a power-of-two lower block size that fits within one bounded batch.
    /// # Errors
    /// Rejects zero, non-power-of-two or larger-than-batch device geometry.
    pub fn new(bytes: u32) -> Result<Self> {
        if !bytes.is_power_of_two() || u64::from(bytes) > TRIM_BATCH_BYTES {
            return Err(Error::DeviceRange);
        }
        NonZeroU32::new(bytes).map(Self).ok_or(Error::DeviceRange)
    }
    /// Aligns inward, retaining only complete lower-device blocks.
    /// # Errors
    /// Rejects overflowing physical coordinates.
    fn inward(self, start: u64, end: u64) -> Result<Option<TrimRange>> {
        let unit = u64::from(self.0.get());
        let start = start
            .checked_add(unit.checked_sub(1).ok_or(Error::DeviceRange)?)
            .and_then(|value| value.checked_div(unit))
            .and_then(|value| value.checked_mul(unit))
            .ok_or(Error::DeviceRange)?;
        let end = end
            .checked_sub(end.checked_rem(unit).ok_or(Error::DeviceRange)?)
            .ok_or(Error::DeviceRange)?;
        if start >= end {
            return Ok(None);
        }
        Ok(Some(TrimRange {
            offset: ByteOffset::new(start),
            length: NonZeroU64::new(end.checked_sub(start).ok_or(Error::DeviceRange)?)
                .ok_or(Error::DeviceRange)?,
        }))
    }
}

/// A nonempty, device-aligned physical byte interval, established from free allocation metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimRange {
    /// Filesystem-device byte coordinate.
    offset: ByteOffset,
    /// Physical byte length, independent of allocation-cluster counts.
    length: NonZeroU64,
}
impl TrimRange {
    /// Starting filesystem-device byte coordinate.
    pub const fn offset(self) -> ByteOffset {
        self.offset
    }
    /// Number of physical bytes in this interval.
    pub const fn length_bytes(self) -> u64 {
        self.length.get()
    }
    /// First byte outside the interval.
    /// # Errors
    /// Rejects overflow before any lower submission.
    fn end(self) -> Result<u64> {
        self.offset
            .get()
            .checked_add(self.length.get())
            .ok_or(Error::DeviceRange)
    }
}

/// Progress through a scan; this observation grants no discard or allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimCursor {
    /// Next physical byte to consider; absence means the complete filesystem range was considered.
    next: Option<ByteOffset>,
}
impl TrimCursor {
    /// Starts a fresh scan, including free space earlier than a previous completed scan.
    pub const fn start() -> Self {
        Self {
            next: Some(ByteOffset::new(0)),
        }
    }
    /// Whether this scan reached the filesystem's physical end.
    pub const fn is_complete(self) -> bool {
        self.next.is_none()
    }
}

/// Half-open allocation coordinates reserved while their projected physical interval is in flight.
#[derive(Clone, Copy, Debug)]
struct ClusterSpan {
    /// First overlapping allocation cluster.
    first: ClusterAddress,
    /// First cluster outside the overlap.
    end: ClusterAddress,
}
/// Both coordinate representations are established together and remain immutable.
#[derive(Debug)]
struct SelectedRange {
    /// Allocation exclusion covers every cluster touched by the lower command.
    clusters: ClusterSpan,
    /// Only the independently aligned physical interval reaches the device.
    bytes: TrimRange,
}
/// Immutable coordinate conversions for one validated filesystem.
#[derive(Clone, Copy, Debug)]
struct TrimGeometry {
    /// Filesystem byte coordinate at allocation-cluster zero.
    first: u64,
    /// Physical bytes per allocation unit.
    cluster_bytes: u64,
    /// First byte outside the filesystem, excluding extra device capacity.
    end: u64,
}
impl TrimGeometry {
    /// Establishes checked byte geometry from ext4 block geometry.
    /// # Errors
    /// Rejects overflow or empty allocation space.
    fn new(superblock: Superblock) -> Result<Self> {
        let first = superblock
            .block_size()
            .offset_of(superblock.first_data_block())?
            .get();
        let end = u64::from(superblock.block_size().bytes())
            .checked_mul(superblock.block_count().as_u64())
            .ok_or(Error::DeviceRange)?;
        if first >= end {
            return Err(Error::InvalidClusterGeometry);
        }
        Ok(Self {
            first,
            cluster_bytes: u64::from(superblock.cluster_size().bytes()),
            end,
        })
    }
    /// Maps a byte coordinate to its containing allocation cluster, after clamping the preamble.
    /// # Errors
    /// Rejects a byte outside the filesystem or invalid unit arithmetic.
    fn cluster(self, byte: u64) -> Result<ClusterAddress> {
        if byte >= self.end {
            return Err(Error::DeviceRange);
        }
        let relative = byte
            .max(self.first)
            .checked_sub(self.first)
            .ok_or(Error::DeviceRange)?;
        Ok(ClusterAddress::new(
            relative
                .checked_div(self.cluster_bytes)
                .ok_or(Error::InvalidClusterGeometry)?,
        ))
    }
    /// Converts an allocation boundary, allowing its one-past boundary at the physical tail.
    /// # Errors
    /// Rejects overflowing allocation coordinates.
    fn boundary(self, cluster: ClusterAddress) -> Result<u64> {
        Ok(cluster
            .get()
            .checked_mul(self.cluster_bytes)
            .and_then(|value| value.checked_add(self.first))
            .ok_or(Error::DeviceRange)?
            .min(self.end))
    }
    /// Computes the complete allocation exclusion for one inward-aligned physical interval.
    /// # Errors
    /// Rejects empty or out-of-filesystem intervals.
    fn span(self, range: TrimRange) -> Result<ClusterSpan> {
        let last = range.end()?.checked_sub(1).ok_or(Error::DeviceRange)?;
        Ok(ClusterSpan {
            first: self.cluster(range.offset.get())?,
            end: ClusterAddress::new(
                self.cluster(last)?
                    .get()
                    .checked_add(1)
                    .ok_or(Error::InvalidClusterGeometry)?,
            ),
        })
    }
    /// Retains sub-cluster progress without widening the next physical request.
    fn cursor(self, next: u64) -> TrimCursor {
        TrimCursor {
            next: (next < self.end).then_some(ByteOffset::new(next)),
        }
    }
}

/// One authenticated group scan; it has no lower effect or reservation until admitted.
#[derive(Debug)]
pub struct TrimSelection {
    /// Mount that interpreted the allocation metadata.
    mount: MountIdentity,
    /// Exact immutable metadata snapshot selecting these free ranges.
    epoch: EpochSequence,
    /// At most the declared range and physical-byte budgets.
    ranges: Vec<SelectedRange>,
    /// Next scan position, including partial progress within large allocation clusters.
    next: TrimCursor,
    /// Sum of projected physical bytes.
    bytes: u64,
}
/// Current reservation with one source for both allocation exclusion and lower request projection.
#[derive(Debug)]
struct TrimClaim {
    /// Session-local scope cannot be reconstructed from an on-disk UUID.
    mount: MountIdentity,
    /// Non-reusable acquisition identity.
    identity: u64,
    /// Immutable checked range relation, shared without copying its contents.
    ranges: Vec<SelectedRange>,
    /// Sum computed before physical submission.
    bytes: u64,
}
/// Allocation admission is independent of the bitmap's authoritative free/used state.
#[derive(Debug)]
pub(super) struct TrimReservations {
    /// A single bounded lower command may own ranges at a time.
    active: Option<Arc<TrimClaim>>,
    /// Prevents late completions from releasing a successor's ranges.
    next_identity: u64,
}
/// Provisional immutable snapshot; commit preparation still checks current reservations.
#[derive(Debug)]
pub(super) struct AllocationExclusions(Option<Arc<TrimClaim>>);
impl AllocationExclusions {
    /// Mount recovery has no concurrent discard owner.
    pub(super) const fn unreserved() -> Self {
        Self(None)
    }
    /// Tests an allocation candidate without modifying committed ownership or ext4 bitmaps.
    pub(super) fn contains(&self, cluster: ClusterAddress) -> bool {
        self.0.as_ref().is_some_and(|claim| claim.contains(cluster))
    }
}
impl TrimClaim {
    /// Finds a reservation in the bounded sorted interval set.
    fn contains(&self, cluster: ClusterAddress) -> bool {
        let index = self
            .ranges
            .partition_point(|range| range.clusters.end <= cluster);
        self.ranges
            .get(index)
            .is_some_and(|range| range.clusters.first <= cluster)
    }
}
impl TrimReservations {
    /// Starts with no lower owner and no allocated reservation records.
    pub(super) const fn new() -> Self {
        Self {
            active: None,
            next_identity: 0,
        }
    }
    /// Detaches only immutable allocation exclusions for a synchronous provisional pass.
    pub(super) fn observe(&self) -> AllocationExclusions {
        AllocationExclusions(self.active.as_ref().map(Arc::clone))
    }
    /// Current exclusion, revalidated immediately before effect-bearing mutation preparation.
    pub(super) fn contains(&self, cluster: ClusterAddress) -> bool {
        self.active
            .as_ref()
            .is_some_and(|claim| claim.contains(cluster))
    }
}

impl MutationCoordinatorState {
    /// Whether an admitted discard still owns allocation exclusions and a completion obligation.
    /// Close must wait for this owner even if the journal itself has no pending checkpoint.
    pub fn has_pending_trim(&self) -> bool {
        self.trims.active.is_some()
    }
}

/// Admission distinguishes contention from a completed empty scan and acquired physical authority.
#[derive(Debug)]
pub enum TrimAdmission {
    /// Existing journal effects or another discard must complete before this selection is retried.
    Waiting(TrimSelection),
    /// This group segment contains no complete free device blocks.
    Advanced(TrimCursor),
    /// Ranges are excluded from allocation until their unique physical completion returns.
    Prepared(PreparedTrim),
}
impl TrimSelection {
    /// Acquires physical discard authority only for the exact current checkpointed metadata.
    /// # Errors
    /// Rejects read-only, revoked, foreign or stale snapshots; allocation/identity exhaustion occurs
    /// before installing a reservation. Contention retains this selection in `Waiting`.
    pub fn reserve(
        self,
        coordinator: &mut MutationCoordinatorState,
        epoch: &CommittedEpoch,
    ) -> Result<TrimAdmission> {
        coordinator.require_session_authority()?;
        epoch.require_writable()?;
        if self.mount != coordinator.mount
            || self.mount != epoch.mount
            || self.epoch != epoch.sequence()
            || coordinator.published_epoch() != (epoch.identity().uuid(), epoch.sequence())
        {
            return Err(Error::StaleReadContext);
        }
        if !coordinator.journal_is_clean() || coordinator.trims.active.is_some() {
            return Ok(TrimAdmission::Waiting(self));
        }
        if !epoch.overlay.is_empty() {
            return Err(Error::JournalCorrupt);
        }
        if self.ranges.is_empty() {
            return Ok(TrimAdmission::Advanced(self.next));
        }
        let identity = coordinator.trims.next_identity;
        let next_identity = identity.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        let claim = Arc::try_new(TrimClaim {
            mount: self.mount,
            identity,
            ranges: self.ranges,
            bytes: self.bytes,
        })
        .map_err(|_| Error::OutOfMemory)?;
        coordinator.trims.active = Some(Arc::clone(&claim));
        coordinator.trims.next_identity = next_identity;
        Ok(TrimAdmission::Prepared(PreparedTrim {
            claim,
            next: self.next,
        }))
    }
}
/// Unique pre-submit owner; dropping it leaves the coordinator's exclusion in force.
#[derive(Debug)]
pub struct PreparedTrim {
    /// Immutable record shared with the coordinator until completion.
    claim: Arc<TrimClaim>,
    /// Continuation revealed only after completion.
    next: TrimCursor,
}
impl PreparedTrim {
    /// Transfers the request while retaining exact completion and release authority.
    pub fn submit(self) -> (TrimRequest, PendingTrim) {
        let pending = PendingTrim {
            mount: self.claim.mount,
            identity: self.claim.identity,
            next: self.next,
            bytes: self.claim.bytes,
        };
        (TrimRequest { claim: self.claim }, pending)
    }
}
/// Device request contains only ranges admitted by the filesystem coordinator.
#[derive(Debug)]
pub struct TrimRequest {
    /// No mutable, cloneable or independently forgeable range carrier is exposed.
    claim: Arc<TrimClaim>,
}
impl TrimRequest {
    /// Complete immutable lower intervals; the request always targets the filesystem device.
    pub fn ranges(&self) -> impl ExactSizeIterator<Item = TrimRange> + '_ {
        self.claim.ranges.iter().map(|range| range.bytes)
    }
    /// Physical bytes requested, independent of allocator cluster counts.
    pub fn byte_count(&self) -> u64 {
        self.claim.bytes
    }
    /// Returns ownership after lower execution ended, or after proving it was never submitted.
    pub fn completed(self, outcome: TrimIoOutcome) -> TrimCompletion {
        TrimCompletion {
            request: self,
            outcome,
        }
    }
}
/// Programmatic lower failure independent of whether the device may already have acted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrimFailure {
    /// Device capability or lower stack does not support discard.
    Unsupported,
    /// Cancellation ended or prevented this request; no retry is implied.
    Cancelled,
    /// Other storage, allocation or ownership failure.
    Failed(Error),
}
/// A failed command cannot be interpreted as zero physical progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrimIoOutcome {
    /// The lower stack acknowledged the complete batch. No durability or zero-read guarantee follows.
    Acknowledged,
    /// Host established that no lower request reached a device.
    Unsubmitted(TrimFailure),
    /// Lower execution ended, but some or all ranges may already have been acted upon.
    Uncertain(TrimFailure),
}
/// Exact lower-owned request returned with independently classified physical progress.
#[derive(Debug)]
pub struct TrimCompletion {
    /// The unique request owner; arbitrary byte ranges cannot mint a completion.
    request: TrimRequest,
    /// Physical outcome does not restore a revoked mounted session.
    outcome: TrimIoOutcome,
}
/// Retained completion and range-release authority while lower execution owns the request.
#[derive(Debug)]
pub struct PendingTrim {
    /// Session that installed the reservation.
    mount: MountIdentity,
    /// Exact active acquisition, independent of epoch changes during lower execution.
    identity: u64,
    /// Progress applies only to this completed batch.
    next: TrimCursor,
    /// Bytes requested by this batch.
    bytes: u64,
}
/// Physical batch progress; continuing a scan requires independent current-session admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrimBatchResult {
    /// Next physical scan position, including after an empty group segment.
    pub next: TrimCursor,
    /// Complete requested physical byte count.
    pub requested_bytes: u64,
    /// Acknowledged, provably unsubmitted, or uncertain progress.
    pub outcome: TrimIoOutcome,
}
/// Rejection retains both owners; a foreign completion cannot release a live reservation.
#[derive(Debug)]
pub struct TrimCompletionMismatch {
    /// Scope or acquisition mismatch.
    pub reason: Error,
    /// Still-pending original operation.
    pub pending: PendingTrim,
    /// Unconsumed completion belonging to another operation.
    pub completion: TrimCompletion,
}
impl PendingTrim {
    /// Releases only the exact completed physical request, even after media authority was revoked.
    /// # Errors
    /// Returns both unchanged owners on a foreign, superseded or duplicate completion.
    pub fn complete(
        self,
        coordinator: &mut MutationCoordinatorState,
        completion: TrimCompletion,
    ) -> core::result::Result<TrimBatchResult, TrimCompletionMismatch> {
        let claim = &completion.request.claim;
        if self.mount != coordinator.mount
            || self.mount != claim.mount
            || self.identity != claim.identity
            || coordinator
                .trims
                .active
                .as_ref()
                .is_none_or(|active| active.identity != self.identity)
        {
            return Err(TrimCompletionMismatch {
                reason: Error::ClusterReferenceConflict,
                pending: self,
                completion,
            });
        }
        coordinator.trims.active = None;
        Ok(TrimBatchResult {
            next: self.next,
            requested_bytes: self.bytes,
            outcome: completion.outcome,
        })
    }
}

/// Completion-driven, write-free scan of at most one block-group bitmap per selection.
#[derive(Debug)]
pub struct TrimScanOperation {
    /// Same origin as the profile and coordinator admitting this scan.
    mount: MountIdentity,
    /// Raw bitmap bytes cannot be reinterpreted under a different epoch.
    epoch: Option<EpochSequence>,
    /// Device-aligned continuation can lie inside a large allocation cluster.
    cursor: TrimCursor,
    /// Fixed lower block size, independent of ext4 allocation geometry.
    alignment: TrimAlignment,
    /// At most one descriptor and one bitmap are needed; no whole-volume snapshot is retained.
    filesystem: StorageTranscript,
}
/// A scan has only read effects; discard requires a separately admitted reservation.
#[derive(Debug)]
pub enum TrimScanTransition {
    /// Submit one owned metadata read.
    SubmitLower {
        /// Exact filesystem-device read.
        request: StorageRequest,
        /// Unique scan transcript and continuation.
        suspended: TrimScanOperation,
    },
    /// One group segment or bounded free batch was considered.
    Complete(Result<TrimSelection>),
}
impl TrimScanOperation {
    /// Starts an independent bounded scan without allocation or discard authority.
    pub fn new(profile: &MountedProfile, cursor: TrimCursor, alignment: TrimAlignment) -> Self {
        Self {
            mount: profile.mount,
            epoch: None,
            cursor,
            alignment,
            filesystem: StorageTranscript::new(
                StorageTarget::Filesystem,
                profile.filesystem_length(),
            ),
        }
    }
    /// Consumes one read event against the coordinator's current committed snapshot.
    pub fn advance(
        mut self,
        event: OperationEvent,
        context: CommittedReadContext<'_>,
    ) -> TrimScanTransition {
        let cache = context.cache;
        let epoch = cache.epoch();
        if self.mount != epoch.mount
            || self
                .epoch
                .is_some_and(|sequence| sequence != epoch.sequence())
        {
            return TrimScanTransition::Complete(Err(Error::StaleReadContext));
        }
        self.epoch = Some(epoch.sequence());
        let accepted = match event {
            OperationEvent::Admitted => Ok(()),
            OperationEvent::StorageCompleted(completion) => self.filesystem.complete(completion),
            OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return TrimScanTransition::Complete(Err(error));
        }
        let result = {
            let mut reader =
                OperationDevice::with_overlay(&mut self.filesystem, epoch, Some(cache));
            select(&mut reader, epoch, self.cursor, self.alignment)
        };
        match result {
            Err(Error::OperationSuspended) => match self.filesystem.take_pending_request() {
                Ok(request) => TrimScanTransition::SubmitLower {
                    request,
                    suspended: self,
                },
                Err(error) => TrimScanTransition::Complete(Err(error)),
            },
            result => TrimScanTransition::Complete(result),
        }
    }
}

/// Finds a bounded, inward-aligned subset of authenticated free space in one group.
/// # Errors
/// Returns read, checksum, allocation or checked-coordinate failure before reserving anything.
fn select(
    reader: &mut OperationDevice<'_>,
    epoch: &CommittedEpoch,
    cursor: TrimCursor,
    alignment: TrimAlignment,
) -> Result<TrimSelection> {
    let superblock = epoch.superblock;
    let geometry = TrimGeometry::new(superblock)?;
    let mut selection = TrimSelection {
        mount: epoch.mount,
        epoch: epoch.sequence(),
        ranges: Vec::new(),
        next: cursor,
        bytes: 0,
    };
    let Some(offset) = cursor.next else {
        return Ok(selection);
    };
    let mut position = offset.get().max(geometry.first);
    if position >= geometry.end {
        selection.next = TrimCursor { next: None };
        return Ok(selection);
    }
    let first_cluster = geometry.cluster(position)?;
    let group = superblock.cluster_group_of(first_cluster)?;
    let descriptor = BlockGroupDescriptor::read_from(reader, &superblock, group)?;
    let bitmap = match descriptor.block_bitmap_initialization() {
        AllocationBitmapInitialization::Initialized => {
            Some(descriptor.read_bitmap(reader, &superblock, AllocationBitmapKind::Block)?)
        }
        // Mounted ownership already includes every descriptor-selected static block. A group's
        // uninitialized raw bitmap has no authority; zero-reference gaps are its derived free space.
        AllocationBitmapInitialization::Uninitialized => None,
    };
    let group_first = u64::from(group.as_u32())
        .checked_mul(u64::from(superblock.clusters_per_group().as_u32()))
        .ok_or(Error::InvalidClusterGeometry)?;
    let group_end = group_first
        .checked_add(u64::from(superblock.clusters_in_group(group)?))
        .ok_or(Error::InvalidClusterGeometry)?;
    let mut cluster = first_cluster.get();
    while cluster < group_end {
        let free = |cluster: u64| -> Result<bool> {
            let address = ClusterAddress::new(cluster);
            if epoch.clusters.count(address) != 0 {
                return Ok(false);
            }
            let bit = u32::try_from(
                cluster
                    .checked_sub(group_first)
                    .ok_or(Error::InvalidClusterGeometry)?,
            )
            .map_err(|_| Error::InvalidClusterGeometry)?;
            Ok(match &bitmap {
                Some(bitmap) => {
                    cluster_bitmap_bit_state(bitmap, ClusterBitmapPosition::new(group, bit))?
                        == BitmapBitState::Free
                }
                None => true,
            })
        };
        if !free(cluster)? {
            cluster = cluster
                .checked_add(1)
                .ok_or(Error::InvalidClusterGeometry)?;
            position = geometry.boundary(ClusterAddress::new(cluster))?;
            continue;
        }
        let start = position;
        while cluster < group_end && free(cluster)? {
            cluster = cluster
                .checked_add(1)
                .ok_or(Error::InvalidClusterGeometry)?;
        }
        let end = geometry.boundary(ClusterAddress::new(cluster))?;
        if let Some(mut range) = alignment.inward(start, end)? {
            let remaining = TRIM_BATCH_BYTES
                .checked_sub(selection.bytes)
                .ok_or(Error::DeviceRange)?;
            if range.length.get() > remaining {
                range.length = NonZeroU64::new(remaining).ok_or(Error::DeviceRange)?;
            }
            selection.bytes = selection
                .bytes
                .checked_add(range.length.get())
                .ok_or(Error::DeviceRange)?;
            selection.ranges.try_push(SelectedRange {
                clusters: geometry.span(range)?,
                bytes: range,
            })?;
            if selection.bytes == TRIM_BATCH_BYTES || selection.ranges.len() == TRIM_BATCH_RANGES {
                selection.next = geometry.cursor(range.end()?);
                return Ok(selection);
            }
        }
        position = end;
    }
    selection.next = geometry.cursor(position);
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Errors
    /// Propagates checked physical coordinate or alignment failure.
    /// # Panics
    /// Fails if inward projection discards a partial device block or silently wraps an offset.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions verify independent physical alignment boundary values"
    )]
    fn device_alignment_never_expands_free_intervals() -> Result<()> {
        let alignment = TrimAlignment::new(4096)?;
        let range = alignment.inward(4097, 20_479)?.ok_or(Error::DeviceRange)?;
        assert_eq!(range.offset(), ByteOffset::new(8192));
        assert_eq!(range.length_bytes(), 8192);
        assert!(alignment.inward(1, 4095)?.is_none());
        assert!(matches!(
            alignment.inward(u64::MAX, u64::MAX),
            Err(Error::DeviceRange)
        ));
        for invalid in [0, 3, 128 * 1024 * 1024] {
            assert!(TrimAlignment::new(invalid).is_err());
        }
        Ok(())
    }
    /// # Errors
    /// Propagates checked coordinate conversion failure.
    /// # Panics
    /// Fails if a byte-budget continuation skips the rest of a cluster or fails to exclude its
    /// whole allocation unit while either physical half is in flight.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions verify independent byte and allocation-cluster domains"
    )]
    fn byte_budget_retains_progress_inside_a_larger_allocation_cluster() -> Result<()> {
        let geometry = TrimGeometry {
            first: 0,
            cluster_bytes: 128 * 1024 * 1024,
            end: 256 * 1024 * 1024,
        };
        let first = TrimRange {
            offset: ByteOffset::new(0),
            length: NonZeroU64::new(TRIM_BATCH_BYTES).ok_or(Error::DeviceRange)?,
        };
        let first_end = first.end()?;
        let first_span = geometry.span(first)?;
        assert_eq!(first_span.first, ClusterAddress::new(0));
        assert_eq!(first_span.end, ClusterAddress::new(1));
        assert_eq!(
            geometry.cursor(first_end).next,
            Some(ByteOffset::new(64 * 1024 * 1024))
        );
        assert_eq!(geometry.cluster(first_end)?, ClusterAddress::new(0));
        let second = TrimRange {
            offset: ByteOffset::new(first_end),
            length: first.length,
        };
        let second_span = geometry.span(second)?;
        assert_eq!(second_span.first, first_span.first);
        assert_eq!(second_span.end, first_span.end);
        assert_eq!(geometry.cluster(second.end()?)?, ClusterAddress::new(1));
        assert!(geometry.cursor(geometry.end).is_complete());
        Ok(())
    }
}
