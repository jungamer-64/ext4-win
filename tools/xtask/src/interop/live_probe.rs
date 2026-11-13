//! Temporary live-remount isolation probe: reads one file of the disposable partition from the raw
//! disk through the production core in user mode. A core failure on the on-disk state is then
//! reported by a supervised process instead of stopping the host. Remove once the live remount
//! runner loss is attributed.

use super::*;

/// Command used to invoke the raw partition reader in a separate process.
pub(crate) const READ_RAW_PARTITION_FILE: &str = "read-raw-partition-file";

/// Transfer granularity that satisfies every supported disk sector size.
const RAW_ALIGNMENT: u64 = 4096;

/// Upper bound for one probed regular file.
const RAW_FILE_LIMIT: usize = 1 << 20;

/// Read-only partition window over a raw disk device.
struct RawPartition {
    /// Raw disk opened for reading with full sharing.
    device: File,
    /// Partition byte offset on the disk.
    offset: u64,
    /// Partition byte length.
    length: u64,
}

impl HostStorage for RawPartition {
    fn length(&self, target: ext4_core::StorageTarget) -> TaskResult<u64> {
        require_filesystem(target)?;
        Ok(self.length)
    }

    fn read_exact(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        output: &mut [u8],
    ) -> TaskResult<()> {
        require_filesystem(target)?;
        let count = u64::try_from(output.len())?;
        let end = offset
            .checked_add(count)
            .filter(|end| *end <= self.length)
            .ok_or_else(|| io::Error::other("raw partition read exceeds the partition"))?;
        let disk_start = self
            .offset
            .checked_add(offset)
            .ok_or_else(|| io::Error::other("raw partition offset overflow"))?;
        let disk_end = self
            .offset
            .checked_add(end)
            .ok_or_else(|| io::Error::other("raw partition end overflow"))?;
        let skip = disk_start % RAW_ALIGNMENT;
        let aligned_start = disk_start
            .checked_sub(skip)
            .ok_or_else(|| io::Error::other("raw partition alignment underflow"))?;
        let aligned_end = disk_end
            .div_ceil(RAW_ALIGNMENT)
            .checked_mul(RAW_ALIGNMENT)
            .ok_or_else(|| io::Error::other("raw partition alignment overflow"))?;
        let span = aligned_end
            .checked_sub(aligned_start)
            .ok_or_else(|| io::Error::other("raw partition window underflow"))?;
        let mut aligned = vec![0_u8; usize::try_from(span)?];
        self.device.seek(io::SeekFrom::Start(aligned_start))?;
        self.device.read_exact(&mut aligned)?;
        let selected = aligned
            .get(usize::try_from(skip)?..)
            .and_then(|tail| tail.get(..output.len()))
            .ok_or_else(|| io::Error::other("raw partition window is incomplete"))?;
        for (destination, source) in output.iter_mut().zip(selected) {
            *destination = *source;
        }
        Ok(())
    }

    fn write_all(
        &mut self,
        _target: ext4_core::StorageTarget,
        _offset: u64,
        _input: &[u8],
    ) -> TaskResult<()> {
        Err(io::Error::other("raw partition probe is read-only").into())
    }

    fn flush(&mut self, _target: ext4_core::StorageTarget) -> TaskResult<()> {
        Err(io::Error::other("raw partition probe is read-only").into())
    }
}

/// Rejects requests for a device this probe does not expose.
/// # Errors
/// Returns an error for the external journal target.
fn require_filesystem(target: ext4_core::StorageTarget) -> TaskResult<()> {
    match target {
        ext4_core::StorageTarget::Filesystem => Ok(()),
        ext4_core::StorageTarget::ExternalJournal => {
            Err(io::Error::other("raw partition probe has no external journal").into())
        }
    }
}

/// Parses `disk:offset:length:relative/path` and writes the file bytes to stdout.
/// Progress and failures go to stderr.
/// # Errors
/// Returns malformed arguments, raw disk I/O, core mount, lookup or read failures.
pub(crate) fn read_raw_partition_file(argument: &std::ffi::OsStr) -> TaskResult<()> {
    let argument = argument
        .to_str()
        .ok_or_else(|| io::Error::other("raw partition argument is not UTF-8"))?;
    let mut fields = argument.splitn(4, ':');
    let mut field = || {
        fields
            .next()
            .ok_or_else(|| io::Error::other("raw partition argument is incomplete"))
    };
    let disk: u32 = field()?.parse()?;
    let offset: u64 = field()?.parse()?;
    let length: u64 = field()?.parse()?;
    let path = field()?.to_owned();
    eprintln!("raw partition probe: {path}: mounting disk {disk} at {offset}");
    let mut storage = RawPartition {
        device: OpenOptions::new()
            .read(true)
            .open(format!(r"\\.\PhysicalDrive{disk}"))?,
        offset,
        length,
    };
    let completed = mount_internal_core(
        &mut storage,
        ext4_core::MountAccess::ReadOnly {
            recovery: ext4_core::ReadOnlyRecovery::Memory {
                limit: ext4_core::RecoveryMemoryLimit::DEFAULT,
            },
        },
        ext4_core::DeviceWriteAccess::ReadOnly,
    )?;
    eprintln!("raw partition probe: {path}: mounted");
    let (profile, epoch, coordinator, _ownership) = (*completed).into_parts();
    let mut cache = ext4_core::MetadataCache::try_new(&epoch).map_err(core_task_error)?;
    let mut operation = ext4_core::EpochReadOperation::new(&profile);
    let mut event = ext4_core::OperationEvent::Admitted;
    let bytes = loop {
        let mut crypto = UnkeyedCryptographicOperation;
        match operation.run(
            event,
            coordinator
                .read_context(cache.access(&epoch))
                .map_err(core_task_error)?,
            &mut crypto,
            |pass| {
                let mut directory = ext4_core::DirectoryNodeId::ROOT;
                let mut components = path.split('/').peekable();
                while let Some(component) = components.next() {
                    let ext4_core::ChildLookup::Found(child) = pass.lookup_child(
                        directory,
                        &ext4_core::Ext4Name::new(component.as_bytes())?,
                    )?
                    else {
                        return Err(ext4_core::Error::DirectoryEntryNotFound);
                    };
                    match (*child.node(), components.peek().is_some()) {
                        (ext4_core::NodeId::Directory(next), true) => directory = next,
                        (ext4_core::NodeId::File(file), false) => {
                            let metadata = ext4_core::CommittedReadPass::load_node_metadata(
                                pass,
                                ext4_core::NodeId::File(file),
                            );
                            let mut bytes = vec![0_u8; RAW_FILE_LIMIT];
                            let read =
                                pass.read_file(file, ext4_core::FileOffset::ZERO, &mut bytes)?;
                            bytes.truncate(read.as_usize());
                            // EOF-crossing ranges mirror the kernel requests that differ by length.
                            let mut tail = vec![0_u8; 8192];
                            let beyond = pass
                                .read_file(file, ext4_core::FileOffset::from_bytes(8192), &mut tail)
                                .map(ext4_core::ReadBytes::as_usize);
                            let mut wide = vec![0_u8; 16384];
                            let across = pass
                                .read_file(file, ext4_core::FileOffset::ZERO, &mut wide)
                                .map(ext4_core::ReadBytes::as_usize);
                            eprintln!(
                                "raw partition probe: {path}: metadata={metadata:?} read@8192+8192={beyond:?} read@0+16384={across:?}"
                            );
                            return Ok(bytes);
                        }
                        _ => return Err(ext4_core::Error::WrongInodeKind),
                    }
                }
                Err(ext4_core::Error::DirectoryEntryNotFound)
            },
        ) {
            ext4_core::ReadTransition::SubmitLower { request, suspended } => {
                event = ext4_core::OperationEvent::StorageCompleted(complete_file_request(
                    &mut storage,
                    request,
                )?);
                operation = suspended;
            }
            ext4_core::ReadTransition::Complete(result) => {
                break result.map_err(core_task_error)?;
            }
        }
    };
    eprintln!("raw partition probe: {path}: read {} bytes", bytes.len());
    let mut output = io::stdout().lock();
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
