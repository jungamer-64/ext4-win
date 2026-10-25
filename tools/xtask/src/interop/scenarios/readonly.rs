//! Observable RO recovery is compared with native kernel mounts of independent image copies.

use super::*;
use ext4_core::{DeviceWriteAccess, MountAccess, ReadOnlyRecovery};

/// Stable file bytes used for both native and core namespace observations.
const PAYLOAD: &[u8] = b"ro-mount-payload\n";

/// Current-source storage execution with explicit physical protection and effect observation.
struct ObservedStorage {
    /// Only disposable images owned by this verifier can be accessed.
    inner: FileStorageAdapter,
    /// Physical protection is independent of RO filesystem access.
    access: DeviceWriteAccess,
    /// Submitted writes and flushes, including rejected effects.
    effects: usize,
}

impl HostStorage for ObservedStorage {
    fn length(&self, target: ext4_core::StorageTarget) -> TaskResult<u64> {
        self.inner.length(target)
    }
    fn read_exact(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        output: &mut [u8],
    ) -> TaskResult<()> {
        self.inner.read_exact(target, offset, output)
    }
    fn write_all(
        &mut self,
        target: ext4_core::StorageTarget,
        offset: u64,
        input: &[u8],
    ) -> TaskResult<()> {
        self.effects = self
            .effects
            .checked_add(1)
            .ok_or_else(|| io::Error::other("effect count exhausted"))?;
        if self.access == DeviceWriteAccess::ReadOnly {
            return Err(io::Error::other("write to protected image").into());
        }
        self.inner.write_all(target, offset, input)
    }
    fn flush(&mut self, target: ext4_core::StorageTarget) -> TaskResult<()> {
        self.effects = self
            .effects
            .checked_add(1)
            .ok_or_else(|| io::Error::other("effect count exhausted"))?;
        if self.access == DeviceWriteAccess::ReadOnly {
            return Err(io::Error::other("flush of protected image").into());
        }
        self.inner.flush(target)
    }
}

/// Fields whose observable values identify recovery without comparing unrelated kernel clocks.
#[derive(Debug, Eq, PartialEq)]
struct Observation {
    /// The named file must exist and retain all bytes while its orphan peer is absent.
    payload: Vec<u8>,
    /// Label distinguishes uncheckpointed committed metadata from home metadata.
    label: Vec<u8>,
    /// Independent raw recovery and orphan tracking fields after native/core completion.
    metadata: [u32; 3],
    /// The fixture seeds slots only in the first independently located orphan-file block.
    orphan_entries: Vec<u32>,
}

/// Reads only independently located primary fields, without mounting through the implementation.
/// # Errors
/// Returns truncated primary bytes or image I/O failure.
fn observation(
    linux: LinuxEnvironment,
    image: &Path,
    payload: Vec<u8>,
    label: Vec<u8>,
) -> TaskResult<Observation> {
    let mut file = File::open(image)?;
    let raw = read_image_block(&mut file, 1, 1024)?;
    Ok(Observation {
        payload,
        label,
        metadata: [
            le_u32_at(&raw, 96)? & 4,
            le_u32_at(&raw, 100)? & 0x10000,
            le_u32_at(&raw, 0xe8)?,
        ],
        orphan_entries: orphan::ro_orphan_entries(linux, image)?,
    })
}

/// Decodes fixture bytes independently of production superblock parsing.
/// # Errors
/// Returns a truncated field error.
fn le_u32_at(bytes: &[u8], offset: usize) -> TaskResult<u32> {
    let field = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or_else(|| io::Error::other("field overflow"))?,
        )
        .ok_or_else(|| io::Error::other("missing primary field"))?;
    Ok(u32::from_le_bytes(field.try_into()?))
}

/// Native mount acceptance and namespace/content on a verifier-owned loop device.
/// # Errors
/// Preserves loop, mount observation and mandatory unmount/detach failures.
fn native_observation(
    linux: LinuxEnvironment,
    image: &Path,
    directory: &Path,
    recovery: ReadOnlyRecovery,
    access: DeviceWriteAccess,
) -> TaskResult<Option<Observation>> {
    fs::create_dir(directory)?;
    let mut attach = linux.command("losetup");
    attach.args(["--find", "--show"]);
    if access == DeviceWriteAccess::ReadOnly {
        attach.arg("--read-only");
    }
    attach.arg(linux.tool_path(image)?);
    let device = String::from_utf8(run_checked_output(attach, "RO oracle loop attach")?.stdout)?
        .trim()
        .to_owned();
    if !is_loop_device_path(&device) {
        return Err(io::Error::other("invalid owned loop identity").into());
    }
    let directory_path = linux.tool_path(directory)?;
    let mut mount = linux.command("mount");
    mount.args([
        "-t",
        "ext4",
        "-o",
        if recovery == ReadOnlyRecovery::NoLoad {
            "ro,noload"
        } else {
            "ro"
        },
        &device,
        &directory_path,
    ]);
    let accepted = match mount.output() {
        Ok(output) => output.status.success(),
        Err(error) => {
            let cleanup = detach_loop_device(linux, &device);
            return combine_verification_and_cleanup(Err(error.into()), cleanup);
        }
    };
    let result = if accepted {
        let read = (|| -> TaskResult<Vec<u8>> {
            let mut cat = linux.command("cat");
            cat.arg(format!("{directory_path}/payload"));
            let payload = run_checked_output(cat, "RO kernel payload")?.stdout;
            let mut absent = linux.command("test");
            absent.args(["!", "-e", &format!("{directory_path}/victim")]);
            run_checked(absent, "RO kernel orphan namespace")?;
            Ok(payload)
        })();
        let mut unmount = linux.command("umount");
        unmount.arg(&directory_path);
        // A failed unmount retains the image and exact loop identity in the diagnostic.
        run_checked(
            unmount,
            &format!("RO oracle unmount; retained device {device}"),
        )?;
        read.map(Some)
    } else {
        Ok(None)
    };
    let payload = combine_verification_and_cleanup(result, detach_loop_device(linux, &device))?;
    fs::remove_dir(directory)?;
    payload
        .map(|payload| {
            let mut file = File::open(image)?;
            let raw = read_image_block(&mut file, 1, 1024)?;
            let label = raw
                .get(120..136)
                .ok_or_else(|| io::Error::other("missing label"))?;
            observation(
                linux,
                image,
                payload,
                label
                    .iter()
                    .copied()
                    .take_while(|byte| *byte != 0)
                    .collect(),
            )
        })
        .transpose()
}

/// Observes the mounted core epoch and proves that close cannot emit extra RO effects.
/// # Errors
/// Returns mount/read failure or a violation of namespace, authority or write-free close.
fn core_observation(
    linux: LinuxEnvironment,
    image: &Path,
    recovery: ReadOnlyRecovery,
    access: DeviceWriteAccess,
) -> TaskResult<(Option<Observation>, usize)> {
    let mut storage = ObservedStorage {
        inner: FileStorageAdapter::open_internal(image)?,
        access,
        effects: 0,
    };
    let completed =
        match mount_internal_core(&mut storage, MountAccess::ReadOnly { recovery }, access) {
            Ok(completed) => completed,
            Err(error) if storage.effects == 0 => {
                // Mount rejection is compared with the kernel; transport or setup errors still fail.
                if matches!(
                    error.downcast_ref::<ext4_core::MountFailure>(),
                    Some(ext4_core::MountFailure {
                        reason: ext4_core::Error::ChecksumMismatch
                            | ext4_core::Error::ReadOnlyFilesystem,
                        media: ext4_core::MountMediaOutcome::Unchanged,
                    })
                ) {
                    return Ok((None, 0));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
    let (profile, epoch, coordinator, _ownership) = (*completed).into_parts();
    let mut cache = ext4_core::MetadataCache::try_new(&epoch).map_err(core_task_error)?;
    if !matches!(
        coordinator.mutation_context(cache.access(&epoch)),
        Err(ext4_core::Error::ReadOnlyFilesystem)
    ) {
        return Err(io::Error::other("RO epoch admitted media mutation").into());
    }
    let mut operation = ext4_core::EpochReadOperation::new(&profile);
    let mut event = ext4_core::OperationEvent::Admitted;
    let payload = loop {
        let mut crypto = UnkeyedCryptographicOperation;
        match operation.run(
            event,
            coordinator
                .read_context(cache.access(&epoch))
                .map_err(core_task_error)?,
            &mut crypto,
            |pass| {
                let ext4_core::ChildLookup::Found(child) = pass.lookup_child(
                    ext4_core::DirectoryNodeId::ROOT,
                    &ext4_core::Ext4Name::new(b"payload")?,
                )?
                else {
                    return Err(ext4_core::Error::DirectoryEntryNotFound);
                };
                let ext4_core::NodeId::File(file) = *child.node() else {
                    return Err(ext4_core::Error::WrongInodeKind);
                };
                let mut bytes = [0; PAYLOAD.len()];
                let _read = pass.read_file(file, ext4_core::FileOffset::ZERO, &mut bytes)?;
                if !matches!(
                    pass.lookup_child(
                        ext4_core::DirectoryNodeId::ROOT,
                        &ext4_core::Ext4Name::new(b"victim")?
                    )?,
                    ext4_core::ChildLookup::NotFound
                ) {
                    return Err(ext4_core::Error::InvalidOrphanTracking);
                }
                Ok(bytes)
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
    let effects = storage.effects;
    complete_core_clean_close(&mut storage, &profile, &coordinator)?;
    if storage.effects != effects {
        return Err(io::Error::other("RO close submitted a media effect").into());
    }
    Ok((
        Some(observation(
            linux,
            image,
            payload.to_vec(),
            epoch.identity().label().bytes().to_vec(),
        )?),
        effects,
    ))
}

/// Compares native-kernel and production-core RO recovery on disposable image pairs.
/// # Errors
/// Requires Linux root/loop authority and pinned tools; rejects any mount or observable mismatch.
pub(crate) fn verify_ro_interop(repository_root: &Path) -> TaskResult<()> {
    let manifest = parse_journal_fixture_manifest(
        &journal_fixture_directory(repository_root).join("provenance.manifest"),
    )?;
    let linux = LinuxEnvironment::require(&manifest.e2fsprogs_version)?;
    linux.require_loop_device_authority()?;
    let root = create_task_directory(repository_root, "ro-interop")?;
    let verification = (|| -> TaskResult<()> {
        let payload = root.join("payload.bin");
        fs::write(&payload, PAYLOAD)?;
        for state in ["clean", "journal", "chain", "orphan-file", "bad-checksum"] {
            let source = root.join(format!("{state}.img"));
            File::create(&source)?.set_len(64 * 1024 * 1024)?;
            let path = linux.tool_path(&source)?;
            let mut format = linux.command("mke2fs");
            format.args([
                "-q",
                "-F",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-O",
                "orphan_file,metadata_csum,64bit,^metadata_csum_seed",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0",
                "-J",
                "size=4",
                "-L",
                "ro-home",
                &path,
            ]);
            run_checked(format, "RO fixture format")?;
            let mut populate = linux.command("debugfs");
            populate.args([
                "-w",
                "-R",
                &format!("write {} /payload", linux.tool_path(&payload)?),
                &path,
            ]);
            run_checked(populate, "RO independent namespace")?;
            match state {
                "journal" => drive_core_commit_without_checkpoint(&source, b"ro-replayed")?,
                "chain" | "orphan-file" => orphan::seed_ro_orphan(
                    linux,
                    &source,
                    &payload,
                    if state == "chain" {
                        orphan::RoOrphanTracker::Chain
                    } else {
                        orphan::RoOrphanTracker::File
                    },
                )?,
                "bad-checksum" => {
                    let mut file = OpenOptions::new().read(true).write(true).open(&source)?;
                    file.seek(io::SeekFrom::Start(2044))?;
                    let mut byte = [0];
                    file.read_exact(&mut byte)?;
                    let checksum = byte
                        .first_mut()
                        .ok_or_else(|| io::Error::other("missing checksum byte"))?;
                    *checksum ^= 1;
                    file.seek(io::SeekFrom::Start(2044))?;
                    file.write_all(&byte)?;
                    file.sync_all()?;
                }
                _ => {}
            }
            for recovery in [ReadOnlyRecovery::Replay, ReadOnlyRecovery::NoLoad] {
                for access in [DeviceWriteAccess::Writable, DeviceWriteAccess::ReadOnly] {
                    let name = format!("{state}-{recovery:?}-{access:?}");
                    let native = root.join(format!("{name}-kernel.img"));
                    let core = root.join(format!("{name}-core.img"));
                    fs::copy(&source, &native)?;
                    fs::copy(&source, &core)?;
                    let expected = native_observation(
                        linux,
                        &native,
                        &root.join(format!("{name}-mount")),
                        recovery,
                        access,
                    )?;
                    let (actual, effects) = core_observation(linux, &core, recovery, access)?;
                    if actual != expected || (access == DeviceWriteAccess::ReadOnly && effects != 0)
                    {
                        return Err(io::Error::other(format!("RO kernel mismatch {name}: core {actual:?}, kernel {expected:?}, effects {effects}")).into());
                    }
                    if recovery == ReadOnlyRecovery::Replay
                        && access == DeviceWriteAccess::Writable
                        && state != "bad-checksum"
                    {
                        let memory = root.join(format!("{state}-memory.img"));
                        fs::copy(&source, &memory)?;
                        let before = sha256_file(&memory)?;
                        let (private, effects) = core_observation(
                            linux,
                            &memory,
                            ReadOnlyRecovery::Memory {
                                limit: ext4_core::RecoveryMemoryLimit::DEFAULT,
                            },
                            DeviceWriteAccess::ReadOnly,
                        )?;
                        if effects != 0
                            || sha256_file(&memory)? != before
                            || private.as_ref().map(|view| (&view.payload, &view.label))
                                != actual.as_ref().map(|view| (&view.payload, &view.label))
                        {
                            return Err(io::Error::other(format!(
                                "private RO recovery mismatch: {state}"
                            ))
                            .into());
                        }
                        fs::remove_file(memory)?;
                    }
                    fs::remove_file(native)?;
                    fs::remove_file(core)?;
                }
            }
            fs::remove_file(source)?;
        }
        Ok(())
    })();
    // Keep diagnostics and any still-owned loop image after failure; never traverse a live mount.
    verification?;
    remove_task_directory(repository_root, &root, "ro-interop")?;
    println!("native Linux RO mount interoperability: PASS");
    Ok(())
}
