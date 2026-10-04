//! Deterministic offset I/O against the disposable session's independently populated files.

use crate::process::combine_verification_and_cleanup;
use core::time::Duration;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::windows::fs::{FileExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Barrier, mpsc},
    thread,
    time::Instant,
};

/// One filesystem transfer, also the required direct-I/O buffer alignment.
const TRANSFER: usize = 4096;
/// Each repetition performs this many operations per worker after warming the metadata.
const OPERATIONS: usize = 4096;

/// Whether FILE_OBJECT lifetime is part of each measured operation.
#[derive(Clone, Copy, Debug, Serialize)]
enum Handles {
    /// Retain each worker's disjoint file collection.
    Retained,
    /// Include open and explicit close in each operation.
    Reopened,
}
/// Cache admission and acknowledgement semantics selected at native open.
#[derive(Clone, Copy, Debug, Serialize)]
enum TransferMode {
    /// Completion acknowledges Cache Manager acceptance; flush is measured separately.
    Cached,
    /// Bypass the cache and request write-through completion.
    Direct,
}
/// Required read/write ratio of a deterministic trace.
#[derive(Clone, Copy, Debug, Serialize)]
enum Workload {
    /// Only read operations.
    Read,
    /// Only overwrite operations.
    Write,
    /// Seven reads followed by three writes per ten operations.
    Mixed,
}
/// One repeatable performance case, with independent files assigned to workers.
#[derive(Clone, Copy, Debug, Serialize)]
struct Profile {
    /// Distinct inodes in the active set.
    files: usize,
    /// Maximum simultaneously active offset operations.
    workers: usize,
    /// File-object lifetime policy.
    handles: Handles,
    /// Native cache/write-through policy.
    mode: TransferMode,
    /// Read/write selection.
    workload: Workload,
    /// Sparse files with independently generated external extent nodes.
    fragmented: bool,
}
/// One repetition; latency includes open/close only for the reopened profile.
#[derive(Debug, Serialize)]
struct Measurement {
    /// Exact case parameters.
    profile: Profile,
    /// Repeat ordinal.
    repetition: usize,
    /// Completed operations divided by the span between the first start and last completion.
    iops: f64,
    /// Native-operation latency median in microseconds.
    p50_us: f64,
    /// Native-operation 95th percentile in microseconds.
    p95_us: f64,
    /// Native-operation 99th percentile in microseconds.
    p99_us: f64,
    /// Wall duration of the synchronized flush phase, outside operation timing.
    flush_ms: f64,
    /// Trace start through durable flush completion, including cached-write acceptance.
    durability_ms: f64,
}
/// Worker-owned completion evidence, collected even when another worker fails.
struct WorkerMeasurement {
    /// Bounds of the operation window, excluding setup, flush and readback.
    window: (Instant, Instant),
    /// Native operation timings in nanoseconds.
    latencies: Vec<u64>,
    /// Bounds of the flush phase, excluding readback and fixture restoration.
    flush_window: (Instant, Instant),
}

/// Opens one session-owned file with the exact selected completion semantics.
/// # Errors
/// Returns native open or share failures.
fn open(path: &Path, mode: TransferMode) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if matches!(mode, TransferMode::Direct) {
        options.custom_flags(0x2000_0000 | 0x8000_0000);
    }
    options.open(path)
}

/// Seeds the independently generated fixture's fixed block body.
/// # Errors
/// Returns an unrepresentable host index.
fn seed(bytes: &mut [u8]) -> io::Result<()> {
    for (position, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(position % 251).map_err(io::Error::other)?;
    }
    Ok(())
}

/// Encodes a trace identity without regenerating the 4 KiB body inside the measured loop.
/// # Errors
/// Returns an unrepresentable file identity or a short payload.
fn stamp_header(bytes: &mut [u8], file: usize, stamp: u64) -> io::Result<()> {
    let header = bytes
        .get_mut(..16)
        .ok_or_else(|| io::Error::other("short trace payload"))?;
    if stamp == 0 {
        return seed(header);
    }
    let identity = u64::try_from(file).map_err(io::Error::other)?.to_le_bytes();
    for (target, byte) in header
        .iter_mut()
        .zip(stamp.to_le_bytes().into_iter().chain(identity))
    {
        *target = byte;
    }
    Ok(())
}

/// Phase barriers exclude warmup, readback and restoration from other workers' measurement.
struct TraceBarriers {
    /// Every worker has finished warming its entire active inode set.
    start: Barrier,
    /// Every measured operation has completed before the first explicit flush.
    finish: Barrier,
    /// Every explicit flush has completed before the first readback or restoration.
    flushed: Barrier,
}

/// A failed participant still joins all remaining barriers so the owner can join every worker.
enum Phase {
    /// Warmup has not joined the trace admission barrier.
    Warming,
    /// Measured operations may execute.
    Running,
    /// Explicit flushes may execute.
    Flushing,
    /// No remaining synchronization obligation.
    Finished,
}

/// Owns barrier participation through failure and panic unwinding.
struct Participant<'trace> {
    /// Barriers live until all scoped workers have joined.
    barriers: &'trace TraceBarriers,
    /// The next synchronization obligation.
    phase: Phase,
}

impl Participant<'_> {
    /// Admits the measured phase after every worker's warmup.
    fn begin(&mut self) {
        if matches!(self.phase, Phase::Warming) {
            self.barriers.start.wait();
            self.phase = Phase::Running;
        }
    }
    /// Admits explicit flush only after all measured operations have completed.
    fn finish(&mut self) {
        self.begin();
        if matches!(self.phase, Phase::Running) {
            self.barriers.finish.wait();
            self.phase = Phase::Flushing;
        }
    }
    /// Admits readback only after all durability acknowledgements have completed.
    fn flushed(&mut self) {
        self.finish();
        if matches!(self.phase, Phase::Flushing) {
            self.barriers.flushed.wait();
            self.phase = Phase::Finished;
        }
    }
}

impl Drop for Participant<'_> {
    fn drop(&mut self) {
        self.flushed();
    }
}

/// Executes a complete native transfer without treating a short success as completion.
/// # Errors
/// Returns native I/O failures or a short transfer.
fn transfer(file: &File, bytes: &mut [u8], offset: u64, write: bool) -> io::Result<()> {
    let count = if write {
        file.seek_write(bytes, offset)?
    } else {
        file.seek_read(bytes, offset)?
    };
    if count != TRANSFER {
        return Err(io::Error::other("random I/O returned a short transfer"));
    }
    Ok(())
}

/// Selects disjoint block coordinates for workers sharing the single control inode.
/// # Errors
/// Returns trace-coordinate overflow.
fn trace_offset(profile: Profile, worker: usize, block: usize) -> io::Result<u64> {
    let logical = if profile.files == 1 {
        block
            .checked_mul(profile.workers)
            .and_then(|block| block.checked_add(worker))
    } else {
        Some(block)
    }
    .ok_or_else(|| io::Error::other("trace block overflow"))?;
    u64::try_from(logical)
        .map_err(io::Error::other)?
        .checked_mul(if profile.fragmented { 8192 } else { 4096 })
        .ok_or_else(|| io::Error::other("offset overflow"))
}

/// Owns one disjoint inode set, verifies every observed block, and restores the fixture.
/// # Errors
/// Returns allocation, native operation, data mismatch, flush or explicit close failures.
fn worker(
    root: &Path,
    profile: Profile,
    worker: usize,
    barriers: &TraceBarriers,
) -> io::Result<WorkerMeasurement> {
    let mut participant = Participant {
        barriers,
        phase: Phase::Warming,
    };
    let ids: Vec<_> = if profile.files == 1 {
        vec![0]
    } else {
        (worker..profile.files).step_by(profile.workers).collect()
    };
    let blocks = if profile.fragmented {
        512_usize
    } else {
        16_usize
    };
    let directory = if profile.fragmented {
        "fragmented"
    } else if profile.files == 1 {
        "single"
    } else {
        "files"
    };
    let paths: Vec<PathBuf> = ids
        .iter()
        .map(|id| root.join(directory).join(format!("file-{id:05}")))
        .collect();
    let mut retained = Vec::new();
    let setup: io::Result<()> = (|| {
        if matches!(profile.handles, Handles::Retained) {
            for path in &paths {
                retained.push(open(path, profile.mode)?);
            }
        }
        Ok(())
    })();
    if let Err(error) = setup {
        let mut cleanup = Ok(());
        for file in retained {
            if let Err(error) = windows_host::close_file(file) {
                cleanup = Err(error);
            }
        }
        return combine_verification_and_cleanup::<WorkerMeasurement>(
            Err(error.into()),
            cleanup.map_err(Into::into),
        )
        .map_err(|error| io::Error::other(error.to_string()));
    }
    let operation = (|| {
        let mut stamps = vec![
            0_u64;
            ids.len()
                .checked_mul(blocks)
                .ok_or_else(|| io::Error::other("trace geometry overflow"))?
        ];
        let mut backing = vec![
            0_u8;
            TRANSFER
                .checked_mul(2)
                .ok_or_else(|| io::Error::other("buffer geometry overflow"))?
        ];
        let start = (TRANSFER
            .checked_sub(backing.as_ptr().addr() % TRANSFER)
            .ok_or_else(|| io::Error::other("buffer alignment overflow"))?)
            % TRANSFER;
        let end = start
            .checked_add(TRANSFER)
            .ok_or_else(|| io::Error::other("buffer range overflow"))?;
        let buffer = backing
            .get_mut(start..end)
            .ok_or_else(|| io::Error::other("buffer range"))?;
        let mut expected = vec![0_u8; TRANSFER];
        let mut latencies = Vec::new();
        latencies
            .try_reserve_exact(OPERATIONS)
            .map_err(io::Error::other)?;
        let mut random = u64::try_from(worker)
            .map_err(io::Error::other)?
            .wrapping_add(1);
        seed(&mut expected)?;
        for (selected, path) in paths.iter().enumerate() {
            let warm = |file: &File, buffer: &mut [u8]| -> io::Result<()> {
                for block in 0..blocks {
                    transfer(file, buffer, trace_offset(profile, worker, block)?, false)?;
                    if buffer != expected {
                        return Err(io::Error::other("warmup differs from independent fixture"));
                    }
                }
                // Exercise every inode's update resource, including the complete 8,192-file set.
                if !matches!(profile.workload, Workload::Read) {
                    transfer(file, buffer, trace_offset(profile, worker, 0)?, true)?;
                    file.sync_all()?;
                }
                Ok(())
            };
            if let Some(file) = retained.get(selected) {
                warm(file, buffer)?;
            } else {
                let file = open(path, profile.mode)?;
                combine_verification_and_cleanup(
                    warm(&file, buffer).map_err(Into::into),
                    windows_host::close_file(file).map_err(Into::into),
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
            }
        }
        participant.begin();
        let started = Instant::now();
        for operation in 0_usize..OPERATIONS {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let selected = usize::try_from(
                random
                    .checked_rem(u64::try_from(ids.len()).map_err(io::Error::other)?)
                    .ok_or_else(|| io::Error::other("empty worker file set"))?,
            )
            .map_err(io::Error::other)?;
            let block = usize::try_from(
                (random >> 32)
                    .checked_rem(u64::try_from(blocks).map_err(io::Error::other)?)
                    .ok_or_else(|| io::Error::other("empty worker block set"))?,
            )
            .map_err(io::Error::other)?;
            let index = selected
                .checked_mul(blocks)
                .and_then(|base| base.checked_add(block))
                .ok_or_else(|| io::Error::other("trace index overflow"))?;
            let stamp = stamps
                .get_mut(index)
                .ok_or_else(|| io::Error::other("trace index"))?;
            let write = match profile.workload {
                Workload::Read => false,
                Workload::Write => true,
                Workload::Mixed => operation % 10 >= 7,
            };
            let next = u64::try_from(operation)
                .map_err(io::Error::other)?
                .checked_add(1)
                .ok_or_else(|| io::Error::other("stamp overflow"))?;
            let id = *ids
                .get(selected)
                .ok_or_else(|| io::Error::other("file index"))?;
            stamp_header(&mut expected, id, if write { next } else { *stamp })?;
            if write {
                stamp_header(buffer, id, next)?;
            }
            let offset = trace_offset(profile, worker, block)?;
            let begun = Instant::now();
            if let Some(file) = retained.get(selected) {
                transfer(file, buffer, offset, write)?;
            } else {
                let file = open(
                    paths
                        .get(selected)
                        .ok_or_else(|| io::Error::other("file path"))?,
                    profile.mode,
                )?;
                let result = transfer(&file, buffer, offset, write).map_err(Into::into);
                combine_verification_and_cleanup(
                    result,
                    windows_host::close_file(file).map_err(Into::into),
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
            }
            latencies.push(u64::try_from(begun.elapsed().as_nanos()).map_err(io::Error::other)?);
            if write {
                *stamp = next;
            } else if buffer != expected {
                return Err(io::Error::other(
                    "random read differs from independent trace",
                ));
            }
        }
        let completed = Instant::now();
        participant.finish();
        let flush_started = Instant::now();
        for path in &paths {
            let file = open(path, profile.mode)?;
            combine_verification_and_cleanup(
                file.sync_all().map_err(Into::into),
                windows_host::close_file(file).map_err(Into::into),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        }
        let flushed = Instant::now();
        participant.flushed();
        for (selected, path) in paths.iter().enumerate() {
            let file = open(path, profile.mode)?;
            let validation = (|| {
                for block in 0..blocks {
                    let index = selected
                        .checked_mul(blocks)
                        .and_then(|base| base.checked_add(block))
                        .ok_or_else(|| io::Error::other("trace index overflow"))?;
                    let stamp = *stamps
                        .get(index)
                        .ok_or_else(|| io::Error::other("trace index"))?;
                    if stamp == 0 {
                        continue;
                    }
                    let offset = trace_offset(profile, worker, block)?;
                    stamp_header(
                        &mut expected,
                        *ids.get(selected)
                            .ok_or_else(|| io::Error::other("file index"))?,
                        stamp,
                    )?;
                    transfer(&file, buffer, offset, false)?;
                    if buffer != expected {
                        return Err(io::Error::other(
                            "random write readback differs from independent trace",
                        ));
                    }
                    stamp_header(buffer, 0, 0)?;
                    transfer(&file, buffer, offset, true)?;
                }
                file.sync_all()
            })();
            combine_verification_and_cleanup(
                validation.map_err(Into::into),
                windows_host::close_file(file).map_err(Into::into),
            )
            .map_err(|error| io::Error::other(error.to_string()))?;
        }
        Ok(WorkerMeasurement {
            window: (started, completed),
            latencies,
            flush_window: (flush_started, flushed),
        })
    })();
    let mut cleanup = Ok(());
    for file in retained {
        if let Err(error) = windows_host::close_file(file) {
            cleanup = Err(error);
        }
    }
    combine_verification_and_cleanup(operation.map_err(Into::into), cleanup.map_err(Into::into))
        .map_err(|error| io::Error::other(error.to_string()))
}

/// Selects a percentile from an ordered, nonempty latency sample.
/// # Errors
/// Returns empty samples or range arithmetic failures.
fn percentile(samples: &[u64], percent: usize) -> io::Result<f64> {
    let index = samples
        .len()
        .checked_sub(1)
        .and_then(|last| last.checked_mul(percent))
        .and_then(|value| value.checked_div(100))
        .ok_or_else(|| io::Error::other("latency sample range"))?;
    Ok(Duration::from_nanos(
        *samples
            .get(index)
            .ok_or_else(|| io::Error::other("latency sample index"))?,
    )
    .as_secs_f64()
        * 1_000_000.0)
}

/// Runs all profiles and persists each successful repetition before starting the next one.
/// # Errors
/// Returns worker, data integrity, report serialization or report publication failures.
pub(super) fn run(root: &Path, output: &Path, artifact: &str) -> io::Result<()> {
    let mut measurements = Vec::new();
    for (files, fragmented) in [(1, false), (1024, false), (8192, false), (64, true)] {
        for workers in [1_usize, 8, 32] {
            for handles in [Handles::Retained, Handles::Reopened] {
                for mode in [TransferMode::Cached, TransferMode::Direct] {
                    for workload in [Workload::Read, Workload::Write, Workload::Mixed] {
                        let profile = Profile {
                            files,
                            workers,
                            handles,
                            mode,
                            workload,
                            fragmented,
                        };
                        for repetition in 0..5 {
                            let barriers = TraceBarriers {
                                start: Barrier::new(workers),
                                finish: Barrier::new(workers),
                                flushed: Barrier::new(workers),
                            };
                            let results = thread::scope(|scope| {
                                let mut tasks = Vec::new();
                                tasks.try_reserve_exact(workers).map_err(io::Error::other)?;
                                let mut failure = None;
                                for id in 0..workers {
                                    let (admit, admission) = mpsc::sync_channel(1);
                                    let barriers = &barriers;
                                    match thread::Builder::new().spawn_scoped(scope, move || {
                                        if admission.recv().map_err(io::Error::other)? {
                                            worker(root, profile, id, barriers)
                                        } else {
                                            Err(io::Error::other("trace admission failed"))
                                        }
                                    }) {
                                        Ok(task) => tasks.push((admit, task)),
                                        Err(error) => {
                                            failure = Some(error);
                                            break;
                                        }
                                    }
                                }
                                // A partial spawn never admits any barrier participant. Every
                                // successfully created thread is signalled and joined on failure.
                                for (admit, _) in &tasks {
                                    if let Err(error) = admit.send(failure.is_none()) {
                                        failure = Some(io::Error::other(error));
                                    }
                                }
                                let results = tasks
                                    .into_iter()
                                    .map(|(_, task)| {
                                        task.join()
                                            .map_err(|_| {
                                                io::Error::other("random I/O worker panicked")
                                            })
                                            .and_then(|result| result)
                                    })
                                    .collect::<Vec<_>>();
                                failure.map_or(Ok(results), Err)
                            })?;
                            let mut first = None;
                            let mut last = None;
                            let mut samples = Vec::new();
                            let mut flush_first = None;
                            let mut flush_last = None;
                            for result in results {
                                let result = result?;
                                first = Some(first.map_or(result.window.0, |value: Instant| {
                                    value.min(result.window.0)
                                }));
                                last = Some(last.map_or(result.window.1, |value: Instant| {
                                    value.max(result.window.1)
                                }));
                                samples.extend(result.latencies);
                                flush_first = Some(
                                    flush_first.map_or(result.flush_window.0, |value: Instant| {
                                        value.min(result.flush_window.0)
                                    }),
                                );
                                flush_last = Some(
                                    flush_last.map_or(result.flush_window.1, |value: Instant| {
                                        value.max(result.flush_window.1)
                                    }),
                                );
                            }
                            #[expect(
                                clippy::disallowed_methods,
                                reason = "host-only latency ordering invokes an infallible numeric comparator and is outside kernel reachability"
                            )]
                            samples.sort_unstable();
                            let elapsed = last
                                .zip(first)
                                .map(|(last, first)| last.duration_since(first).as_secs_f64())
                                .ok_or_else(|| io::Error::other("empty worker set"))?;
                            measurements.push(Measurement {
                                profile,
                                repetition,
                                iops: f64::from(
                                    u32::try_from(samples.len()).map_err(io::Error::other)?,
                                ) / elapsed,
                                p50_us: percentile(&samples, 50)?,
                                p95_us: percentile(&samples, 95)?,
                                p99_us: percentile(&samples, 99)?,
                                flush_ms: flush_last
                                    .zip(flush_first)
                                    .map(|(last, first)| {
                                        last.duration_since(first).as_secs_f64() * 1000.0
                                    })
                                    .ok_or_else(|| io::Error::other("empty flush window"))?,
                                durability_ms: flush_last
                                    .zip(first)
                                    .map(|(last, first)| {
                                        last.duration_since(first).as_secs_f64() * 1000.0
                                    })
                                    .ok_or_else(|| io::Error::other("empty durability window"))?,
                            });
                            let report = serde_json::json!({ "artifact_id": artifact, "transfer_bytes": TRANSFER, "operations_per_worker": OPERATIONS, "measurements": measurements });
                            fs::write(output, serde_json::to_vec_pretty(&report)?)?;
                            println!(
                                "random I/O files={files} workers={workers} repetition={repetition}: complete"
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns trace-coordinate failures.
    /// # Panics
    /// Fails if concurrent writes to the control inode share a block or exceed its fixture.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible coordinate encoding is separate from independent disjoint-range assertions"
    )]
    fn single_inode_control_has_disjoint_ranges_at_every_concurrency() -> io::Result<()> {
        for workers in [1, 8, 32] {
            let profile = Profile {
                files: 1,
                workers,
                handles: Handles::Reopened,
                mode: TransferMode::Cached,
                workload: Workload::Mixed,
                fragmented: false,
            };
            let mut offsets = std::collections::BTreeSet::new();
            for worker in 0..workers {
                for block in 0..16 {
                    let offset = trace_offset(profile, worker, block)?;
                    assert!(offsets.insert(offset));
                    assert!(offset < 2_097_152 && offset.is_multiple_of(4096));
                }
            }
        }
        Ok(())
    }

    /// # Errors
    /// Returns payload encoding or latency selection failures.
    /// # Panics
    /// Fails if independent trace coordinates alias or the fixed block body changes.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible trace encoding is separate from independent byte and latency assertions"
    )]
    fn trace_identity_and_latency_units_are_independent() -> io::Result<()> {
        let mut bytes = [0_u8; TRANSFER];
        seed(&mut bytes)?;
        let baseline = bytes;
        stamp_header(&mut bytes, 8191, 31)?;
        assert_eq!(bytes.get(..8), Some(31_u64.to_le_bytes().as_slice()));
        assert_eq!(bytes.get(8..16), Some(8191_u64.to_le_bytes().as_slice()));
        assert_eq!(bytes.get(16..), baseline.get(16..));
        stamp_header(&mut bytes, 0, 0)?;
        assert_eq!(bytes, baseline);
        assert!(stamp_header(&mut [0; 15], 0, 1).is_err());
        assert_eq!(percentile(&[1000, 2000, 3000], 50)?, 2.0);
        assert!(percentile(&[], 50).is_err());
        Ok(())
    }

    /// # Panics
    /// Fails if a rejected worker strands another participant at a remaining barrier.
    #[test]
    fn early_failure_joins_every_remaining_trace_phase() {
        for phase in [Phase::Warming, Phase::Running, Phase::Flushing] {
            let barriers = TraceBarriers {
                start: Barrier::new(2),
                finish: Barrier::new(2),
                flushed: Barrier::new(2),
            };
            thread::scope(|scope| {
                let task = scope.spawn(|| {
                    let mut participant = Participant {
                        barriers: &barriers,
                        phase: Phase::Warming,
                    };
                    participant.begin();
                    participant.finish();
                    participant.flushed();
                });
                let mut failed = Participant {
                    barriers: &barriers,
                    phase: Phase::Warming,
                };
                if matches!(phase, Phase::Running | Phase::Flushing) {
                    failed.begin();
                }
                if matches!(phase, Phase::Flushing) {
                    failed.finish();
                }
                drop(failed);
                assert!(task.join().is_ok());
            });
        }
    }
}
