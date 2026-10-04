//! Deterministic offset I/O against the disposable session's independently populated files.

use crate::process::combine_verification_and_cleanup;
use core::time::Duration;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::windows::fs::{FileExt, OpenOptionsExt},
    path::{Path, PathBuf},
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
    /// Sum of explicit worker flush durations in milliseconds, outside operation timing.
    flush_ms: f64,
}
/// Worker-owned completion evidence, collected even when another worker fails.
struct WorkerMeasurement {
    /// Bounds of the operation window, excluding setup, flush and readback.
    window: (Instant, Instant),
    /// Native operation timings in nanoseconds.
    latencies: Vec<u64>,
    /// Explicit durability acknowledgement duration in milliseconds.
    flush_ms: f64,
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

/// Generates a host-owned expected payload independently of filesystem parsing and mapping.
/// # Errors
/// Returns an unrepresentable host index.
fn pattern(bytes: &mut [u8], file: usize, stamp: u64) -> io::Result<()> {
    let salt = if stamp == 0 {
        0
    } else {
        stamp ^ u64::try_from(file).map_err(io::Error::other)?
    };
    for (position, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from((u64::try_from(position).map_err(io::Error::other)? ^ salt) % 251)
            .map_err(io::Error::other)?;
    }
    Ok(())
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

/// Owns one disjoint inode set, verifies every observed block, and restores the fixture.
/// # Errors
/// Returns allocation, native operation, data mismatch, flush or explicit close failures.
fn worker(root: &Path, profile: Profile, worker: usize) -> io::Result<WorkerMeasurement> {
    let ids: Vec<_> = (worker..profile.files).step_by(profile.workers).collect();
    let blocks = if profile.fragmented {
        512_usize
    } else {
        16_usize
    };
    let directory = if profile.fragmented {
        "fragmented"
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
        pattern(&mut expected, 0, 0)?;
        for (selected, path) in paths.iter().enumerate() {
            if let Some(file) = retained.get(selected) {
                transfer(file, buffer, 0, false)?;
            } else {
                let file = open(path, profile.mode)?;
                combine_verification_and_cleanup(
                    transfer(&file, buffer, 0, false).map_err(Into::into),
                    windows_host::close_file(file).map_err(Into::into),
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
            }
            if buffer != expected {
                return Err(io::Error::other("warmup differs from independent fixture"));
            }
        }
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
            pattern(&mut expected, id, if write { next } else { *stamp })?;
            if write {
                for (target, byte) in buffer.iter_mut().zip(&expected) {
                    *target = *byte;
                }
            }
            let offset = u64::try_from(block)
                .map_err(io::Error::other)?
                .checked_mul(if profile.fragmented { 8192 } else { 4096 })
                .ok_or_else(|| io::Error::other("offset overflow"))?;
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
        let mut flush_ms = 0.0;
        for (selected, path) in paths.iter().enumerate() {
            let file = open(path, profile.mode)?;
            let validation = (|| {
                let begun = Instant::now();
                file.sync_all()?;
                flush_ms += begun.elapsed().as_secs_f64() * 1000.0;
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
                    let offset = u64::try_from(block)
                        .map_err(io::Error::other)?
                        .checked_mul(if profile.fragmented { 8192 } else { 4096 })
                        .ok_or_else(|| io::Error::other("offset overflow"))?;
                    pattern(
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
                    pattern(buffer, 0, 0)?;
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
            flush_ms,
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
        for workers in [1_usize, 8, 32].into_iter().filter(|count| *count <= files) {
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
                            let results = thread::scope(|scope| {
                                let tasks: Vec<_> = (0..workers)
                                    .map(|id| scope.spawn(move || worker(root, profile, id)))
                                    .collect();
                                tasks
                                    .into_iter()
                                    .map(|task| {
                                        task.join()
                                            .map_err(|_| {
                                                io::Error::other("random I/O worker panicked")
                                            })
                                            .and_then(|result| result)
                                    })
                                    .collect::<Vec<_>>()
                            });
                            let mut first = None;
                            let mut last = None;
                            let mut samples = Vec::new();
                            let mut flush_ms = 0.0;
                            for result in results {
                                let result = result?;
                                first = Some(first.map_or(result.window.0, |value: Instant| {
                                    value.min(result.window.0)
                                }));
                                last = Some(last.map_or(result.window.1, |value: Instant| {
                                    value.max(result.window.1)
                                }));
                                samples.extend(result.latencies);
                                flush_ms += result.flush_ms;
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
                                flush_ms,
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
