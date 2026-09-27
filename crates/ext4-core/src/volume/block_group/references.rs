//! Run-compressed ownership counts for committed allocation clusters.

use core::num::NonZeroU32;

use super::*;

/// Sorted, disjoint, nonempty cluster intervals with positive per-cluster counts.
/// Adjacent equal-count intervals coalesce. Space depends on ownership boundaries,
/// not on the number of occupied clusters. Epoch copies retain that bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::volume) struct ClusterReferenceIndex {
    /// The sole mounted ownership representation; zero-count gaps are implicit.
    runs: Vec<ReferenceRun>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Propagates range construction, allocation and successor preparation failures.
    /// # Panics
    /// Fails if count boundaries, coalescing or immutable epoch semantics change.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture failures propagate while assertions compare independent counts"
    )]
    fn ownership_boundaries_and_epoch_deltas_match_dense_counts() -> Result<()> {
        let mut index = ClusterReferenceIndex::new();
        let mut expected = [0_u32; 32];
        for (start, end, count) in [(2, 9, 1), (8, 12, 2), (12, 20, 2), (25, 28, 4)] {
            index.append_owned_range(
                ClusterAddress::new(start),
                ClusterAddress::new(end),
                count,
            )?;
            for slot in expected
                .iter_mut()
                .take(usize::try_from(end).map_err(|_| Error::ArithmeticOverflow)?)
                .skip(usize::try_from(start).map_err(|_| Error::ArithmeticOverflow)?)
            {
                *slot += count;
            }
        }
        for changes in [
            [(19, -2), (2, -1), (9, 1), (0, 1)],
            [(8, -3), (20, 2), (19, 2), (31, 1)],
            [(0, -1), (9, -1), (8, 2), (2, 1)],
        ] {
            let previous = index.try_clone()?;
            let deltas = changes.map(|(cluster, delta)| ClusterReferenceDelta {
                cluster: ClusterAddress::new(cluster),
                delta,
            });
            let successor = index.with_deltas(&deltas)?;
            assert_eq!(index, previous);
            for (cluster, delta) in changes {
                let slot = expected
                    .get_mut(usize::try_from(cluster).map_err(|_| Error::ArithmeticOverflow)?)
                    .ok_or(Error::InvalidClusterGeometry)?;
                *slot = slot
                    .checked_add_signed(delta)
                    .ok_or(Error::ArithmeticOverflow)?;
            }
            for (cluster, expected) in expected.iter().copied().enumerate() {
                assert_eq!(
                    successor.count(ClusterAddress::new(
                        u64::try_from(cluster).map_err(|_| Error::ArithmeticOverflow)?
                    )),
                    expected
                );
            }
            index = successor;
        }
        Ok(())
    }

    /// # Errors
    /// Propagates fixture construction and allocation errors.
    /// # Panics
    /// Fails if large contiguous ownership expands with volume size, or errors alter its epoch.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions verify the space bound and failure atomicity"
    )]
    fn contiguous_ownership_stays_bounded_across_split_merge_and_failure() -> Result<()> {
        let mut index = ClusterReferenceIndex::new();
        index.append_owned_range(
            ClusterAddress::new(0),
            ClusterAddress::new(1_000_000_000),
            1,
        )?;
        let delta = ClusterReferenceDelta {
            cluster: ClusterAddress::new(500_000_000),
            delta: 1,
        };
        let split = index.with_deltas(&[delta])?;
        // Ownership storage is bounded by count transitions, independent of interval length.
        assert_eq!(index.runs.len(), 1);
        assert_eq!(split.runs.len(), 3);
        assert_eq!(split.count(delta.cluster), 2);
        assert_eq!(split.count(ClusterAddress::new(1_000_000_000)), 0);
        assert_eq!(
            split.with_deltas(&[ClusterReferenceDelta { delta: -1, ..delta }])?,
            index
        );
        for (changes, error) in [
            (
                alloc::vec![ClusterReferenceDelta { delta: -2, ..delta }],
                Error::ClusterReferenceConflict,
            ),
            (
                alloc::vec![ClusterReferenceDelta {
                    delta: i32::MAX,
                    ..delta
                }],
                Error::ArithmeticOverflow,
            ),
            (alloc::vec![delta, delta], Error::ClusterReferenceConflict),
        ] {
            let before = index.try_clone()?;
            assert_eq!(index.with_deltas(&changes), Err(error));
            assert_eq!(index, before);
        }
        Ok(())
    }
}

/// A half-open cluster interval whose members have the same reference count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReferenceRun {
    /// First included cluster.
    start: ClusterAddress,
    /// First excluded cluster.
    end: ClusterAddress,
    /// Positive block-owner count for every cluster in the interval.
    count: NonZeroU32,
}

impl ClusterReferenceIndex {
    /// Starts the mount accumulator before any recovered ownership is admitted.
    pub(super) const fn new() -> Self {
        Self { runs: Vec::new() }
    }

    /// Copies an epoch's compressed ownership before durable publication.
    /// # Errors
    /// Returns allocation failure without modifying the source epoch.
    pub(in crate::volume) fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            runs: memory::copied_slice(&self.runs)?,
        })
    }

    /// Returns zero in unowned gaps, otherwise the containing interval's count.
    pub(in crate::volume) fn count(&self, cluster: ClusterAddress) -> u32 {
        let insertion = self.runs.partition_point(|run| run.start <= cluster);
        insertion
            .checked_sub(1)
            .and_then(|index| self.runs.get(index))
            .filter(|run| cluster < run.end)
            .map_or(0, |run| run.count.get())
    }

    /// Appends monotonically ordered recovered block contributions. Distinct block
    /// ranges may share their boundary cluster; physical alias validation belongs
    /// to the mount scanner and precedes this conversion. On failure the private
    /// mount accumulator must be discarded, never published.
    /// # Errors
    /// Rejects empty/zero-count ranges, backward overlap, overflow or allocation failure.
    pub(super) fn append_owned_range(
        &mut self,
        start: ClusterAddress,
        end: ClusterAddress,
        count: u32,
    ) -> Result<()> {
        let count = NonZeroU32::new(count).ok_or(Error::ClusterReferenceConflict)?;
        if start >= end {
            return Err(Error::ClusterReferenceConflict);
        }
        if let Some(last) = self.runs.last().copied().filter(|run| start < run.end) {
            let boundary_end = ClusterAddress::new(
                start
                    .get()
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            if start < last.start || boundary_end != last.end {
                return Err(Error::ClusterReferenceConflict);
            }
            let combined = last
                .count
                .checked_add(count.get())
                .ok_or(Error::ArithmeticOverflow)?;
            self.runs.pop().ok_or(Error::ClusterReferenceConflict)?;
            self.append_disjoint(last.start, start, last.count)?;
            self.append_disjoint(start, boundary_end, combined)?;
            self.append_disjoint(boundary_end, end, count)
        } else {
            self.append_disjoint(start, end, count)
        }
    }

    /// Builds a complete successor without mutating the published source. Deltas
    /// are one accumulated value per cluster; duplicate keys are a contract error.
    /// Sorting the small delta set permits a single pass over the ownership runs.
    /// # Errors
    /// Rejects negative/overflowing counts, duplicate keys, address overflow and
    /// allocation failure. Every failure leaves the source epoch unchanged.
    pub(in crate::volume) fn with_deltas(&self, deltas: &[ClusterReferenceDelta]) -> Result<Self> {
        let mut deltas = memory::copied_slice(deltas)?;
        memory::heap_sort_by(&mut deltas, |left, right| left.cluster.cmp(&right.cluster))?;
        let mut output = Self::new();
        let mut remaining = self.runs.iter().copied();
        let mut current = remaining.next();
        let mut previous = None;
        for delta in deltas {
            if previous == Some(delta.cluster) {
                return Err(Error::ClusterReferenceConflict);
            }
            previous = Some(delta.cluster);
            while let Some(run) = current.filter(|run| run.end <= delta.cluster) {
                output.append_disjoint(run.start, run.end, run.count)?;
                current = remaining.next();
            }
            let end = ClusterAddress::new(
                delta
                    .cluster
                    .get()
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
            let mut count = 0;
            if let Some(run) = current.filter(|run| run.start <= delta.cluster) {
                output.append_disjoint(run.start, delta.cluster, run.count)?;
                count = i32::try_from(run.count.get()).map_err(|_| Error::ArithmeticOverflow)?;
                current = if end < run.end {
                    Some(ReferenceRun { start: end, ..run })
                } else {
                    remaining.next()
                };
            }
            let updated = count
                .checked_add(delta.delta)
                .ok_or(Error::ArithmeticOverflow)?;
            let updated = u32::try_from(updated).map_err(|_| Error::ClusterReferenceConflict)?;
            if let Some(count) = NonZeroU32::new(updated) {
                output.append_disjoint(delta.cluster, end, count)?;
            }
        }
        if let Some(run) = current {
            output.append_disjoint(run.start, run.end, run.count)?;
        }
        for run in remaining {
            output.append_disjoint(run.start, run.end, run.count)?;
        }
        Ok(output)
    }

    /// Coalesces an ordered interval; an empty split contributes nothing.
    /// # Errors
    /// Rejects reversed or overlapping intervals and reports allocation failure.
    fn append_disjoint(
        &mut self,
        start: ClusterAddress,
        end: ClusterAddress,
        count: NonZeroU32,
    ) -> Result<()> {
        if start > end {
            return Err(Error::ClusterReferenceConflict);
        }
        if start == end {
            return Ok(());
        }
        if let Some(last) = self.runs.last_mut() {
            if start < last.end {
                return Err(Error::ClusterReferenceConflict);
            }
            if start == last.end && count == last.count {
                last.end = end;
                return Ok(());
            }
        }
        self.runs.try_push(ReferenceRun { start, end, count })
    }
}
