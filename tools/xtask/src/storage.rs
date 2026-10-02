//! Native disk/GPT observations and exact disposable-partition discovery admission.
use crate::{TaskResult, windows};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};

/// Linux filesystem data partition identity required at the observable GPT boundary.
const LINUX_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";
/// Disk observation tied to the currently attached VHDX.
#[derive(Debug, Deserialize)]
pub(crate) struct Disk {
    /// Current disk number, invalidated by detach/replacement.
    pub(crate) number: u32,
    /// Stable disk identity against which reused numbers are checked.
    pub(crate) unique: String,
}
/// Durable GPT facts, independent of the current Windows disk number.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Partition {
    /// Partition index in its owning disk.
    pub(crate) number: u32,
    /// Native-layout GPT partition identity.
    pub(crate) id: [u8; 16],
    /// Native-layout GPT type identity.
    pub(crate) kind: [u8; 16],
    /// Byte offset from the start of the disk.
    pub(crate) offset: u64,
    /// Partition byte length.
    pub(crate) length: u64,
}
/// External normalized partition observation, validated before use as a semantic identity.
#[derive(Debug, Deserialize)]
struct PartitionObservation {
    /// Owning current disk number.
    disk: u32,
    /// Partition index.
    number: u32,
    /// GPT partition identifier string.
    id: String,
    /// GPT partition type string.
    kind: String,
    /// Byte origin.
    offset: u64,
    /// Byte length.
    length: u64,
}
/// Narrow scope admitted by the live owner after durable partition identity publication.
#[derive(Debug)]
pub(crate) struct DisposablePartition {
    /// Owner-generated VHDX path.
    pub(crate) vhdx: PathBuf,
    /// Independently recorded disk unique identity.
    pub(crate) disk: String,
    /// Independently recorded GPT identity and byte extent.
    pub(crate) partition: Partition,
}

/// Reads the current VHDX attachment without changing storage state.
/// # Errors
/// Returns management, ambiguous disk or malformed external observation errors.
pub(crate) fn disk(vhdx: &Path) -> TaskResult<Option<Disk>> {
    if !vhdx.exists() {
        return Ok(None);
    }
    let path = windows::literal(vhdx.as_os_str())?;
    let observation = windows::management(&format!(
        "$vhd=Get-VHD -Path {path}; if ($vhd.Attached) {{ @(Get-Disk -Number $vhd.DiskNumber | ForEach-Object {{ [pscustomobject]@{{ number=[uint32]$_.Number; unique=[string]$_.UniqueId }} }}) }} else {{ @() }}"
    ))?;
    let observations: Vec<Disk> = windows::observations(observation)?;
    if observations.len() > 1
        || observations
            .first()
            .is_some_and(|disk| disk.unique.is_empty())
    {
        return Err(
            io::Error::other("VHDX attachment did not identify exactly one valid disk").into(),
        );
    }
    Ok(observations.into_iter().next())
}
/// Reads all GPT partition observations; MBR partitions have no GPT identity and are omitted.
/// # Errors
/// Returns native management or malformed GPT data.
fn partitions() -> TaskResult<Vec<(u32, Partition)>> {
    let observation = windows::management(
        "@(Get-Partition | Where-Object GptType | ForEach-Object { [pscustomobject]@{ disk=[uint32]$_.DiskNumber; number=[uint32]$_.PartitionNumber; id=[string]$_.Guid; kind=[string]$_.GptType; offset=[uint64]$_.Offset; length=[uint64]$_.Size } })",
    )?;
    let observations: Vec<PartitionObservation> = windows::observations(observation)?;
    observations
        .into_iter()
        .map(|value| {
            Ok((
                value.disk,
                Partition {
                    number: value.number,
                    id: windows_host::guid_bytes(&value.id)?,
                    kind: windows_host::guid_bytes(&value.kind)?,
                    offset: value.offset,
                    length: value.length,
                },
            ))
        })
        .collect()
}
/// Captures the sole Linux data GUID partition on the freshly constructed session disk.
/// # Errors
/// Returns absent, ambiguous, wrong-type or zero-length partition observations.
pub(crate) fn constructed_partition(disk: &Disk) -> TaskResult<Partition> {
    let kind = windows_host::guid_bytes(LINUX_DATA)?;
    let matches: Vec<_> = partitions()?
        .into_iter()
        .filter(|(number, partition)| *number == disk.number && partition.kind == kind)
        .collect();
    let [(_, partition)] = matches.as_slice() else {
        return Err(io::Error::other("session disk has no sole Linux data GUID partition").into());
    };
    if partition.length == 0 {
        return Err(io::Error::other("session partition has zero byte length").into());
    }
    Ok(partition.clone())
}
/// Revalidates disk, GPT identity and byte range before deriving a native volume lookup scope.
/// # Errors
/// Returns detached, replaced or changed storage identity errors.
pub(crate) fn validate(scope: &DisposablePartition) -> TaskResult<windows_host::PartitionIdentity> {
    let disk = disk(&scope.vhdx)?.ok_or_else(|| io::Error::other("session VHDX is detached"))?;
    if !disk.unique.eq_ignore_ascii_case(&scope.disk) {
        return Err(io::Error::other("session disk unique ID changed").into());
    }
    let matches: Vec<_> = partitions()?
        .into_iter()
        .filter(|(number, partition)| {
            *number == disk.number && partition.number == scope.partition.number
        })
        .collect();
    let [(_, observed)] = matches.as_slice() else {
        return Err(io::Error::other("session partition is absent or ambiguous").into());
    };
    if observed != &scope.partition {
        return Err(io::Error::other("session GPT identity, type or byte range changed").into());
    }
    Ok(windows_host::PartitionIdentity {
        disk: disk.number,
        offset: observed.offset,
        length: observed.length,
        guid: observed.id,
    })
}
/// Constrains driver discovery to the owner-admitted disposable partition immediately before startup.
/// # Errors
/// Returns any unrelated Linux data GUID partition or changed admission identity.
pub(crate) fn assert_scope(allowed: Option<&DisposablePartition>) -> TaskResult<()> {
    let kind = windows_host::guid_bytes(LINUX_DATA)?;
    let candidates: Vec<_> = partitions()?
        .into_iter()
        .filter(|(_, partition)| partition.kind == kind)
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let scope = allowed.ok_or_else(|| {
        io::Error::other(
            "driver preflight requires unrelated Linux data GUID volumes to be detached",
        )
    })?;
    let native = validate(scope)?;
    for (disk, partition) in candidates {
        if disk != native.disk || partition != scope.partition {
            return Err(io::Error::other(
                "driver startup would discover storage outside the disposable session",
            )
            .into());
        }
    }
    Ok(())
}
