//! Committed payload allocation projected into Windows VCN/LCN continuation records.

use ext4_core::{ByteOffset, EpochReadPass, FileOffset, NodeId, VolumeGeometry};

use crate::{
    irp::{IrpCompletion, PendingIrpLease},
    kernel::status::{DriverError, DriverResult},
    memory::DriverVec,
    state::OpenedObject,
    wire::{LittleEndianOutput, WireOffset},
};

/// RETRIEVAL_POINTERS_BUFFER prefix, including alignment before StartingVcn.
const HEADER_BYTES: usize = 16;
/// One NextVcn/Lcn pair in the Windows wire format.
const EXTENT_BYTES: usize = 16;

/// File-space allocation-unit coordinate, independent of the volume coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VirtualCluster(u64);

/// Volume-space allocation-unit coordinate, representable by the signed Windows ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VolumeCluster(i64);

/// Mounted allocation geometry used by all byte/cluster conversions in this boundary.
#[derive(Clone, Copy, Debug)]
struct ClusterGeometry {
    /// Byte length of an ext4 allocation unit, including BIGALLOC.
    bytes: u64,
    /// Exclusive volume-space allocation-unit bound.
    count: u64,
}

impl ClusterGeometry {
    /// Converts mounted ext4 geometry without changing its physical allocation unit.
    fn from_volume(geometry: VolumeGeometry) -> Self {
        Self {
            bytes: u64::from(geometry.cluster_size().bytes()),
            count: geometry.cluster_count().as_u64(),
        }
    }

    /// Converts a file-space unit index to its aligned byte address.
    /// # Errors
    /// Returns invalid-parameter for unrepresentable input coordinates.
    fn file_offset(self, cluster: VirtualCluster) -> DriverResult<FileOffset> {
        Ok(FileOffset::from_bytes(
            cluster
                .0
                .checked_mul(self.bytes)
                .ok_or(DriverError::InvalidParameter)?,
        ))
    }

    /// Converts a byte boundary to the last completely covered virtual cluster boundary.
    /// # Errors
    /// Returns an invariant failure for zero allocation-unit geometry.
    fn complete_boundary(self, offset: FileOffset) -> DriverResult<VirtualCluster> {
        Ok(VirtualCluster(
            offset
                .bytes()
                .checked_div(self.bytes)
                .ok_or(DriverError::InternalInvariantViolation)?,
        ))
    }

    /// Projects a physical block fragment back to its containing allocation unit.
    /// # Errors
    /// Returns corrupt-extent for inconsistent BIGALLOC alignment or an out-of-volume range.
    fn physical_cluster(
        self,
        physical: ByteOffset,
        fragment: FileOffset,
        cluster_start: FileOffset,
    ) -> DriverResult<VolumeCluster> {
        let within = fragment
            .bytes()
            .checked_sub(cluster_start.bytes())
            .ok_or(DriverError::InternalInvariantViolation)?;
        let base = physical
            .get()
            .checked_sub(within)
            .ok_or(ext4_core::Error::InvalidExtentTree)?;
        if !base.is_multiple_of(self.bytes) {
            return Err(ext4_core::Error::InvalidExtentTree.into());
        }
        let cluster = base
            .checked_div(self.bytes)
            .ok_or(DriverError::InternalInvariantViolation)?;
        if cluster >= self.count {
            return Err(ext4_core::Error::DeviceRange.into());
        }
        Ok(VolumeCluster(
            i64::try_from(cluster).map_err(|_| DriverError::InvalidParameter)?,
        ))
    }
}

/// One observed payload segment beginning at the exact requested file offset.
#[derive(Clone, Copy, Debug)]
struct AllocationSegment {
    /// Exclusive block-aligned boundary from core traversal.
    end: FileOffset,
    /// Physical address of the requested block; absence denotes an actual sparse hole.
    physical: Option<ByteOffset>,
}

/// Contiguous cluster run; absence of physical allocation is meaningful sparse state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetrievalRun {
    /// Inclusive file-space cluster coordinate.
    start: VirtualCluster,
    /// Exclusive file-space cluster coordinate and next-call resume position.
    end: VirtualCluster,
    /// Volume location corresponding to start; holes encode as signed -1.
    physical: Option<VolumeCluster>,
}

impl RetrievalRun {
    /// Tests observable adjacency while preserving the distinction between holes and allocation.
    fn joins(self, next: Self) -> bool {
        self.end == next.start
            && match (self.physical, next.physical) {
                (None, None) => true,
                (Some(left), Some(right)) => {
                    self.end
                        .0
                        .checked_sub(self.start.0)
                        .and_then(|length| i64::try_from(length).ok())
                        .and_then(|length| left.0.checked_add(length))
                        == Some(right.0)
                }
                _ => false,
            }
    }
}

/// Complete enumeration versus a capacity-limited prefix with a valid resume coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnumerationEnd {
    /// No more payload allocation units remain.
    Complete,
    /// At least one additional nonmergeable run remains after the returned prefix.
    More,
}

/// Owned page assembled before any requestor-output publication.
#[derive(Debug)]
struct RetrievalPage {
    /// Actual first VCN represented by this page.
    start: VirtualCluster,
    /// Ordered records, bounded by captured output capacity.
    runs: DriverVec<RetrievalRun>,
    /// Determines success or overflow while retaining the same returned-byte contract.
    end: EnumerationEnd,
}

/// Observes one or more complete allocation units, inspecting fragments only at BIGALLOC edges.
/// # Errors
/// Returns backing I/O, malformed projection, or checked-coordinate failures.
fn cluster_run(
    geometry: ClusterGeometry,
    start: VirtualCluster,
    observe: &mut impl FnMut(FileOffset) -> DriverResult<Option<AllocationSegment>>,
) -> DriverResult<Option<RetrievalRun>> {
    let first = geometry.file_offset(start)?;
    let Some(segment) = observe(first)? else {
        return Ok(None);
    };
    if segment.end <= first {
        return Err(ext4_core::Error::InvalidExtentTree.into());
    }
    let complete = geometry.complete_boundary(segment.end)?;
    if complete.0 > start.0 {
        let physical = segment
            .physical
            .map(|physical| geometry.physical_cluster(physical, first, first))
            .transpose()?;
        if let Some(physical) = physical {
            let count = complete
                .0
                .checked_sub(start.0)
                .ok_or(DriverError::InternalInvariantViolation)?;
            let end = u64::try_from(physical.0)
                .map_err(|_| DriverError::InvalidParameter)?
                .checked_add(count)
                .ok_or(ext4_core::Error::DeviceRange)?;
            if end > geometry.count {
                return Err(ext4_core::Error::DeviceRange.into());
            }
        }
        return Ok(Some(RetrievalRun {
            start,
            end: complete,
            physical,
        }));
    }
    let end = VirtualCluster(
        start
            .0
            .checked_add(1)
            .ok_or(DriverError::InvalidParameter)?,
    );
    let boundary = geometry.file_offset(end)?;
    let mut cursor = first;
    let mut segment = segment;
    let mut physical = None;
    loop {
        if segment.end <= cursor {
            return Err(ext4_core::Error::InvalidExtentTree.into());
        }
        if let Some(fragment) = segment.physical {
            let candidate = geometry.physical_cluster(fragment, cursor, first)?;
            if physical.is_some_and(|previous| previous != candidate) {
                return Err(ext4_core::Error::InvalidExtentTree.into());
            }
            physical = Some(candidate);
        }
        cursor = segment.end.min(boundary);
        if cursor == boundary {
            break;
        }
        let Some(next) = observe(cursor)? else {
            break;
        };
        segment = next;
    }
    Ok(Some(RetrievalRun {
        start,
        end,
        physical,
    }))
}

impl RetrievalPage {
    /// Collects only records fitting the output page, with one lookahead to classify overflow.
    /// # Errors
    /// Returns short-buffer, end-of-file, allocation, malformed extent, or observation failures.
    fn collect(
        start: VirtualCluster,
        geometry: ClusterGeometry,
        capacity: usize,
        mut observe: impl FnMut(FileOffset) -> DriverResult<Option<AllocationSegment>>,
    ) -> DriverResult<Self> {
        let maximum = capacity
            .checked_sub(HEADER_BYTES)
            .ok_or(DriverError::BufferTooSmall)?
            / EXTENT_BYTES;
        if maximum == 0 {
            return Err(DriverError::BufferTooSmall);
        }
        let mut runs: DriverVec<RetrievalRun> = DriverVec::new();
        let mut cursor = start;
        loop {
            let Some(next) = cluster_run(geometry, cursor, &mut observe)? else {
                if runs.is_empty() {
                    return Err(DriverError::EndOfFile);
                }
                return Ok(Self {
                    start,
                    runs,
                    end: EnumerationEnd::Complete,
                });
            };
            if let Some(last) = runs
                .as_mut_slice()
                .last_mut()
                .filter(|last| last.joins(next))
            {
                last.end = next.end;
            } else {
                if runs.len() == maximum {
                    return Ok(Self {
                        start,
                        runs,
                        end: EnumerationEnd::More,
                    });
                }
                runs.try_push(next)?;
            }
            cursor = next.end;
        }
    }

    /// Encodes only initialized returned bytes; alignment padding is zero and tail is untouched.
    /// # Errors
    /// Returns allocation or signed-wire representability failures before publication.
    fn encode(&self) -> DriverResult<(DriverVec<u8>, IrpCompletion)> {
        let length = self
            .runs
            .len()
            .checked_mul(EXTENT_BYTES)
            .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
            .ok_or(DriverError::InvalidParameter)?;
        let mut bytes = DriverVec::try_repeated_copy(0, length)?;
        let mut output = LittleEndianOutput::new(bytes.as_mut_slice());
        output.write_u32(
            WireOffset::new(0),
            u32::try_from(self.runs.len()).map_err(|_| DriverError::InvalidParameter)?,
        )?;
        output.write_i64(
            WireOffset::new(8),
            i64::try_from(self.start.0).map_err(|_| DriverError::InvalidParameter)?,
        )?;
        for (index, run) in self.runs.iter().enumerate() {
            let offset = index
                .checked_mul(EXTENT_BYTES)
                .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
                .ok_or(DriverError::InvalidParameter)?;
            output.write_i64(
                WireOffset::new(offset),
                i64::try_from(run.end.0).map_err(|_| DriverError::InvalidParameter)?,
            )?;
            output.write_i64(
                WireOffset::new(offset.checked_add(8).ok_or(DriverError::InvalidParameter)?),
                run.physical.map_or(-1, |cluster| cluster.0),
            )?;
        }
        let completion = match self.end {
            EnumerationEnd::Complete => IrpCompletion::from_usize(length)?,
            EnumerationEnd::More => IrpCompletion::buffer_overflow(length)?,
        };
        Ok((bytes, completion))
    }
}

/// Handles a file/directory allocation query using the operation's immutable epoch and transcript.
/// # Errors
/// Returns handle, input/output, allocation, extent-validation, or backing-storage failures.
pub(crate) fn query(
    mut request: PendingIrpLease<'_>,
    read: &mut EpochReadPass<'_, '_, '_>,
    geometry: VolumeGeometry,
) -> DriverResult<IrpCompletion> {
    let node: NodeId = request.with_active(|active| {
        Ok::<_, DriverError>(OpenedObject::decode(active.current_stack()?.file_object()?)?.node())
    })?;
    let (starting_vcn, target) = request.retrieval_parts()?;
    let page = RetrievalPage::collect(
        VirtualCluster(starting_vcn),
        ClusterGeometry::from_volume(geometry),
        target.capacity(),
        |offset| {
            let run = read.node_data_allocation(node, offset)?;
            Ok(run.map(|run| AllocationSegment {
                end: run.end(),
                physical: run.physical(),
            }))
        },
    )?;
    let (bytes, completion) = page.encode()?;
    target.copy_from_owned(bytes.as_slice())?;
    Ok(completion)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent logical/physical byte intervals used to observe a requested interior block.
    /// # Errors
    /// Returns a fixture coordinate overflow or underflow.
    fn observe(
        offset: FileOffset,
        intervals: &[(u64, u64, Option<u64>)],
    ) -> DriverResult<Option<AllocationSegment>> {
        let Some(&(start, end, physical)) = intervals
            .iter()
            .find(|&&(start, end, _)| offset.bytes() >= start && offset.bytes() < end)
        else {
            return Ok(None);
        };
        Ok(Some(AllocationSegment {
            end: FileOffset::from_bytes(end),
            physical: physical
                .map(|base| -> DriverResult<ByteOffset> {
                    let within = offset
                        .bytes()
                        .checked_sub(start)
                        .ok_or(DriverError::InvalidParameter)?;
                    Ok(ByteOffset::new(
                        base.checked_add(within)
                            .ok_or(DriverError::InvalidParameter)?,
                    ))
                })
                .transpose()?,
        }))
    }

    /// # Errors
    /// Returns fixture allocation or encoding failures.
    /// # Panics
    /// Panics if a sparse page loses its resume coordinate, byte count, padding, or Windows status.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup propagates errors; assertions check Windows allocation-query contracts"
    )]
    fn sparse_pages_preserve_wire_prefix_and_resume_after_overflow() -> DriverResult<()> {
        let geometry = ClusterGeometry {
            bytes: 4096,
            count: 1000,
        };
        let intervals = [
            (0, 8192, Some(409600)),
            (8192, 20480, None),
            (20480, 28672, Some(819200)),
        ];
        for (start, next, lcn, end) in [
            (0, 2, 100, EnumerationEnd::More),
            (2, 5, -1, EnumerationEnd::More),
            (5, 7, 200, EnumerationEnd::Complete),
            (1, 2, 101, EnumerationEnd::More),
        ] {
            let page = RetrievalPage::collect(VirtualCluster(start), geometry, 47, |offset| {
                observe(offset, &intervals)
            })?;
            assert_eq!(page.end, end);
            let (bytes, completion) = page.encode()?;
            let mut expected = [0_u8; 32];
            for (chunk, field) in expected.as_chunks_mut::<8>().0.iter_mut().zip([
                1_u64.to_le_bytes(),
                i64::try_from(start)
                    .map_err(|_| DriverError::InvalidParameter)?
                    .to_le_bytes(),
                i64::from(next).to_le_bytes(),
                i64::from(lcn).to_le_bytes(),
            ]) {
                crate::memory::copy_exact(chunk, &field)?;
            }
            assert_eq!(bytes.as_slice(), expected);
            assert_eq!(
                completion,
                if end == EnumerationEnd::More {
                    IrpCompletion::buffer_overflow(32)?
                } else {
                    IrpCompletion::from_usize(32)?
                }
            );
        }
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation or encoding failures.
    /// # Panics
    /// Panics if allocated BIGALLOC fragments disappear or adjacent physical clusters fail to join.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup propagates errors; assertions check Windows allocation-query contracts"
    )]
    fn bigalloc_fragments_and_partial_final_cluster_report_physical_allocation() -> DriverResult<()>
    {
        let geometry = ClusterGeometry {
            bytes: 16384,
            count: 1000,
        };
        let intervals = [
            (0, 4096, None),
            (4096, 8192, Some(331776)),
            (8192, 16384, None),
            (16384, 24576, Some(344064)),
        ];
        let page = RetrievalPage::collect(VirtualCluster(0), geometry, 32, |offset| {
            observe(offset, &intervals)
        })?;
        assert_eq!(page.end, EnumerationEnd::Complete);
        assert_eq!(
            page.runs.as_slice(),
            [RetrievalRun {
                start: VirtualCluster(0),
                end: VirtualCluster(2),
                physical: Some(VolumeCluster(20))
            }]
        );
        Ok(())
    }

    /// # Errors
    /// Returns fixture allocation failures.
    /// # Panics
    /// Panics if short capacity, exhausted allocation, malformed physical coordinates, or lower
    /// errors are accepted or reclassified as a successful partial page.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible fixture setup propagates errors; assertions check Windows allocation-query contracts"
    )]
    fn boundary_and_observation_failures_remain_distinct() -> DriverResult<()> {
        let geometry = ClusterGeometry {
            bytes: 4096,
            count: 1000,
        };
        assert_eq!(
            RetrievalPage::collect(VirtualCluster(0), geometry, 31, |_| Ok(None)).err(),
            Some(DriverError::BufferTooSmall)
        );
        assert_eq!(
            RetrievalPage::collect(VirtualCluster(0), geometry, 32, |_| Ok(None)).err(),
            Some(DriverError::EndOfFile)
        );
        assert_eq!(
            RetrievalPage::collect(
                VirtualCluster(u64::try_from(i64::MAX).map_err(|_| DriverError::InvalidParameter)?),
                geometry,
                32,
                |_| Ok(None)
            )
            .err(),
            Some(DriverError::InvalidParameter)
        );
        assert_eq!(
            RetrievalPage::collect(VirtualCluster(0), geometry, 32, |_| Err(
                ext4_core::Error::DeviceIo.into()
            ))
            .err(),
            Some(ext4_core::Error::DeviceIo.into())
        );
        let bad = [(0, 4096, Some(4097))];
        assert_eq!(
            RetrievalPage::collect(VirtualCluster(0), geometry, 32, |offset| observe(
                offset, &bad
            ))
            .err(),
            Some(ext4_core::Error::InvalidExtentTree.into())
        );
        let outside = [(0, 8192, Some(4091904))];
        assert_eq!(
            RetrievalPage::collect(VirtualCluster(0), geometry, 32, |offset| observe(
                offset, &outside
            ))
            .err(),
            Some(ext4_core::Error::DeviceRange.into())
        );
        let conflict = [(0, 4096, Some(0)), (4096, 8192, Some(20480))];
        assert_eq!(
            RetrievalPage::collect(
                VirtualCluster(0),
                ClusterGeometry {
                    bytes: 8192,
                    count: 1000
                },
                32,
                |offset| observe(offset, &conflict)
            )
            .err(),
            Some(ext4_core::Error::InvalidExtentTree.into())
        );
        Ok(())
    }
}
