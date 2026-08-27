//! Orphan recovery exercised through raw ext4 fixtures and independent e2fsprogs observations.

use super::*;

/// On-disk geometry used only by the independent fixture encoder, never by production recovery.
struct OrphanImage {
    /// Host-owned disposable raw image.
    file: File,
    /// Primary superblock image.
    primary: Vec<u8>,
    /// Filesystem block bytes.
    block_size: u32,
}

impl OrphanImage {
    /// Opens and reads the independent encoder's superblock boundary.
    /// # Errors
    /// Returns a file-I/O or malformed geometry error.
    fn open(path: &Path) -> TaskResult<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let primary = read_image_block(&mut file, 1, 1024)?;
        let block_size = 1024_u32
            .checked_shl(le32(&primary, 24)?)
            .ok_or_else(|| io::Error::other("invalid fixture block size"))?;
        Ok(Self {
            file,
            primary,
            block_size,
        })
    }

    /// Locates an inode through descriptor geometry independently of the production parser.
    /// # Errors
    /// Returns an invalid field/range or host-I/O error.
    fn inode_offset(&mut self, inode: u32) -> TaskResult<u64> {
        let index = inode
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("zero inode"))?;
        let per_group = le32(&self.primary, 40)?;
        let group = index
            .checked_div(per_group)
            .ok_or_else(|| io::Error::other("zero inode group"))?;
        let slot = index
            .checked_rem(per_group)
            .ok_or_else(|| io::Error::other("zero inode group"))?;
        let has_high = le32(&self.primary, 96)? & 0x80 != 0;
        let descriptor_size = if has_high {
            u64::from(le16(&self.primary, 254)?)
        } else {
            32
        };
        let table = if self.block_size == 1024 { 2_u64 } else { 1 };
        let descriptor_offset = table
            .checked_mul(u64::from(self.block_size))
            .and_then(|base| {
                u64::from(group)
                    .checked_mul(descriptor_size)
                    .and_then(|delta| base.checked_add(delta))
            })
            .ok_or_else(|| io::Error::other("descriptor offset overflow"))?;
        let mut descriptor = vec![0; usize::try_from(descriptor_size)?];
        self.file.seek(io::SeekFrom::Start(descriptor_offset))?;
        self.file.read_exact(&mut descriptor)?;
        let block = u64::from(le32(&descriptor, 8)?)
            | if has_high {
                u64::from(le32(&descriptor, 40)?) << 32
            } else {
                0
            };
        block
            .checked_mul(u64::from(self.block_size))
            .and_then(|base| {
                u64::from(slot)
                    .checked_mul(u64::from(le16(&self.primary, 88).ok()?))
                    .and_then(|delta| base.checked_add(delta))
            })
            .ok_or_else(|| io::Error::other("inode offset overflow").into())
    }

    /// Reads an inode record for fixture checksums and structural corruption cases.
    /// # Errors
    /// Returns geometry, range, or file-I/O errors.
    fn inode(&mut self, inode: u32) -> TaskResult<Vec<u8>> {
        let offset = self.inode_offset(inode)?;
        let mut bytes = vec![0; usize::from(le16(&self.primary, 88)?)];
        self.file.seek(io::SeekFrom::Start(offset))?;
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    /// Sets the inode-number slots using the specified on-disk checksum inputs.
    /// # Errors
    /// Returns malformed geometry, checksum-input range, or file-I/O errors.
    fn slots(&mut self, block: u64, entries: &[u32]) -> TaskResult<()> {
        let special = le32(&self.primary, 0x280)?;
        let raw = self.inode(special)?;
        let mut bytes = read_image_block(&mut self.file, block, self.block_size)?;
        for (slot, inode) in entries.iter().enumerate() {
            put32(
                &mut bytes,
                slot.checked_mul(4)
                    .ok_or_else(|| io::Error::other("slot overflow"))?,
                *inode,
            )?;
        }
        if le32(&self.primary, 100)? & 0x400 != 0 {
            let seed = if le32(&self.primary, 96)? & 0x2000 != 0 {
                le32(&self.primary, 0x270)?
            } else {
                jbd2_crc32c(
                    u32::MAX,
                    self.primary
                        .get(104..120)
                        .ok_or_else(|| io::Error::other("UUID missing"))?,
                )
            };
            let seed = jbd2_crc32c(seed, &special.to_le_bytes());
            let seed = jbd2_crc32c(seed, &le32(&raw, 100)?.to_le_bytes());
            let seed = jbd2_crc32c(seed, &block.to_le_bytes());
            let tail = bytes
                .len()
                .checked_sub(8)
                .ok_or_else(|| io::Error::other("orphan tail missing"))?;
            let checksum = jbd2_crc32c(
                seed,
                bytes
                    .get(..tail)
                    .ok_or_else(|| io::Error::other("orphan entries missing"))?,
            );
            let checksum_offset = tail
                .checked_add(4)
                .ok_or_else(|| io::Error::other("checksum offset overflow"))?;
            put32(&mut bytes, checksum_offset, checksum)?;
        }
        write_image_block(&mut self.file, block, self.block_size, &bytes)
    }

    /// Publishes the fixture's interrupted write session after every inode/slot is prepared.
    /// # Errors
    /// Returns field or image-I/O errors.
    fn activate(&mut self) -> TaskResult<()> {
        let incompat = le32(&self.primary, 96)? | 4;
        let ro = le32(&self.primary, 100)? | 0x10000;
        put32(&mut self.primary, 96, incompat)?;
        put32(&mut self.primary, 100, ro)?;
        self.write_primary()
    }

    /// Refreshes only the independent encoder's primary checksum and persists its image.
    /// # Errors
    /// Returns field-range or file-I/O errors.
    fn write_primary(&mut self) -> TaskResult<()> {
        if le32(&self.primary, 100)? & 0x400 != 0 {
            let checksum = jbd2_crc32c(
                u32::MAX,
                self.primary
                    .get(..1020)
                    .ok_or_else(|| io::Error::other("short primary"))?,
            );
            put32(&mut self.primary, 1020, checksum)?;
        }
        write_image_block(&mut self.file, 1, 1024, &self.primary)?;
        self.file.sync_all()?;
        Ok(())
    }
}

/// Exercises both tracking encodings, linked EOF recovery, zero-link reclamation, and BIGALLOC.
/// # Errors
/// Returns an image-generation, production-recovery, or independent-oracle mismatch error.
pub(super) fn verify_orphan_recovery(linux: LinuxEnvironment, root: &Path) -> TaskResult<()> {
    for (block_size, checksum, bigalloc) in [
        (1024_u32, false, false),
        (1024, true, false),
        (4096, true, false),
        (4096, true, true),
    ] {
        let name = format!("orphan-{block_size}-csum{checksum}-big{bigalloc}");
        let directory = root.join(&name);
        fs::create_dir(&directory)?;
        let image = directory.join("dirty.img");
        File::create(&image)?.set_len(64 * 1024 * 1024)?;
        let image_path = linux.tool_path(&image)?;
        let features = format!(
            "orphan_file,64bit,{},{}",
            if checksum {
                "metadata_csum,metadata_csum_seed"
            } else {
                "^metadata_csum,^metadata_csum_seed,uninit_bg"
            },
            if bigalloc { "bigalloc" } else { "^bigalloc" }
        );
        let mut format = linux.command("mke2fs");
        format.args([
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            &block_size.to_string(),
            "-O",
            &features,
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            "-J",
            "size=4",
        ]);
        if bigalloc {
            format.args(["-C", "16384"]);
        }
        format.arg(&image_path);
        run_checked(format, &name)?;
        drive_core_mount_and_clean_close(&image)?;
        verify_internal_e2fsck_clean(linux, &image, &format!("{name} empty orphan file"))?;

        let payload = directory.join("payload.bin");
        let bytes = vec![
            0x5a;
            usize::try_from(block_size)?
                .checked_mul(20)
                .ok_or_else(|| io::Error::other("payload size overflow"))?
        ];
        fs::write(&payload, &bytes)?;
        let payload_path = linux.tool_path(&payload)?;
        let victim = create_file(linux, &image_path, &payload_path, "/victim")?;
        let kept = create_file(linux, &image_path, &payload_path, "/kept")?;
        let chain = create_file(linux, &image_path, &payload_path, "/chain")?;
        mutate(linux, &image_path, "sif /kept size 1500")?;
        for path in ["/victim", "/chain"] {
            mutate(linux, &image_path, &format!("sif {path} links_count 0"))?;
            mutate(linux, &image_path, &format!("unlink {path}"))?;
        }
        mutate(linux, &image_path, &format!("ssv last_orphan {chain}"))?;
        let mut fixture = OrphanImage::open(&image)?;
        let special = le32(&fixture.primary, 0x280)?;
        let block = debugfs_request_output(linux, &image, &format!("bmap <{special}> 0"))?
            .lines()
            .find_map(|line| line.trim().parse::<u64>().ok())
            .ok_or_else(|| io::Error::other("orphan block missing"))?;
        fixture.slots(block, &[victim, kept])?;
        fixture.activate()?;
        drop(fixture);

        let oracle = directory.join("oracle.img");
        fs::copy(&image, &oracle)?;
        let mut repair = linux.command("e2fsck");
        repair.args(["-f", "-y", &linux.tool_path(&oracle)?]);
        let output = repair.output()?;
        if !matches!(output.status.code(), Some(0 | 1)) {
            return Err(io::Error::other(format!(
                "{name} independent recovery failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        // e2fsck is authoritative for tracker cleanup and zero-link reclamation. Its linked
        // orphan handling retains preallocation, so model the independent EOF operation with
        // debugfs's allocation-owning truncate command before comparing allocation endpoints.
        let cutoff = 1500_u32
            .checked_add(
                block_size
                    .checked_sub(1)
                    .ok_or_else(|| io::Error::other("zero block size"))?,
            )
            .and_then(|value| value.checked_div(block_size))
            .ok_or_else(|| io::Error::other("truncate cutoff overflow"))?;
        mutate(
            linux,
            &linux.tool_path(&oracle)?,
            &format!("truncate /kept {cutoff}"),
        )?;
        mutate(linux, &linux.tool_path(&oracle)?, "sif /kept size 1500")?;
        verify_internal_e2fsck_clean(linux, &oracle, &format!("{name} reference recovery"))?;
        drive_core_mount_and_clean_close(&image)?;
        verify_internal_e2fsck_clean(linux, &image, &name)?;
        let core_space = debugfs_free_space(linux, &image)?;
        let reference_space = debugfs_free_space(linux, &oracle)?;
        if core_space.inodes != reference_space.inodes || core_space.blocks < reference_space.blocks
        {
            let core = debugfs_request_output(linux, &image, "stat /kept")?;
            let reference = debugfs_request_output(linux, &oracle, "stat /kept")?;
            return Err(io::Error::other(format!(
                "{name} recovery allocation differs from e2fsprogs truncate\ncore:\n{core}\nreference:\n{reference}"
            ))
            .into());
        }
        let expected = bytes
            .get(..1500)
            .ok_or_else(|| io::Error::other("short fixture payload"))?;
        debugfs_require_file(linux, &directory, &image, "/kept", expected, 1, &name)?;
        debugfs_require_absent(linux, &image, "/victim")?;
        debugfs_require_absent(linux, &image, "/chain")?;
        println!("{name}: PASS");
    }
    verify_orphan_fault_matrix(linux, root)?;
    Ok(())
}

/// Exercises every sector-prefix and flush cut across marker publication and three cleanup batches.
/// # Errors
/// Returns an image, fault-controller, remount, accounting, or independent-oracle error.
fn verify_orphan_fault_matrix(linux: LinuxEnvironment, root: &Path) -> TaskResult<()> {
    const BLOCK_SIZE: u32 = 1024;
    const IMAGE_BYTES: u64 = 16 * 1024 * 1024;
    const VICTIM_BLOCKS: usize = 1100;

    let directory = root.join("orphan-fault-matrix");
    fs::create_dir(&directory)?;
    let baseline = directory.join("baseline.img");
    File::create(&baseline)?.set_len(IMAGE_BYTES)?;
    let baseline_path = linux.tool_path(&baseline)?;
    let mut format = linux.command("mke2fs");
    format.args([
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        "1024",
        "-N",
        "64",
        "-O",
        "orphan_file,metadata_csum,metadata_csum_seed,64bit",
        "-E",
        "lazy_itable_init=0,lazy_journal_init=0",
        "-J",
        "size=4",
        &baseline_path,
    ]);
    run_checked(format, "orphan fault-matrix format")?;
    let expected_space = debugfs_free_space(linux, &baseline)?;
    let payload = directory.join("victim.bin");
    let payload_bytes = usize::try_from(BLOCK_SIZE)?
        .checked_mul(VICTIM_BLOCKS)
        .ok_or_else(|| io::Error::other("fault victim size overflow"))?;
    fs::write(&payload, vec![0xa5; payload_bytes])?;
    let victim = create_file(
        linux,
        &baseline_path,
        &linux.tool_path(&payload)?,
        "/victim",
    )?;
    mutate(linux, &baseline_path, "sif /victim links_count 0")?;
    mutate(linux, &baseline_path, "unlink /victim")?;
    let mut fixture = OrphanImage::open(&baseline)?;
    let special = le32(&fixture.primary, 0x280)?;
    let block = debugfs_request_output(linux, &baseline, &format!("bmap <{special}> 0"))?
        .lines()
        .find_map(|line| line.trim().parse::<u64>().ok())
        .ok_or_else(|| io::Error::other("fault orphan block missing"))?;
    fixture.slots(block, &[victim])?;
    fixture.activate()?;
    drop(fixture);
    verify_corrupt_orphan_rejected(&baseline, block, BLOCK_SIZE)?;

    let probe = directory.join("probe.img");
    fs::copy(&baseline, &probe)?;
    let probe_run = run_internal_mount_until_boundary(&probe, None)?;
    let effects = require_completed_effect_probe("orphan recovery", probe_run)?;
    let cuts = enumerate_effect_cuts(&effects)?;
    fs::remove_file(&probe)?;
    for cut in cuts.iter().copied() {
        let label = format!("orphan-{}", effect_cut_stem(cut));
        let image = directory.join(format!("{label}.img"));
        fs::copy(&baseline, &image)?;
        let run = run_internal_mount_until_boundary(&image, Some(cut))?;
        require_stopped_effect("orphan recovery", cut, run)?;
        drive_core_mount_and_clean_close(&image)?;
        verify_internal_e2fsck_clean(linux, &image, &label)?;
        if debugfs_free_space(linux, &image)? != expected_space {
            return Err(io::Error::other(format!(
                "{label} did not restore the pre-orphan allocation endpoint"
            ))
            .into());
        }
        debugfs_require_absent(linux, &image, "/victim")?;
        fs::remove_file(image)?;
    }
    println!(
        "orphan recovery fault matrix: PASS ({} sector/flush cuts across {} effects)",
        cuts.len(),
        effects.len()
    );
    Ok(())
}

/// Requires authenticated orphan metadata to be rejected before the mount issues any write.
/// # Errors
/// Returns an error for image I/O, an unexpected mount result, or a modified rejected image.
fn verify_corrupt_orphan_rejected(
    baseline: &Path,
    orphan_block: u64,
    block_size: u32,
) -> TaskResult<()> {
    let image = baseline.with_file_name("corrupt-orphan.img");
    fs::copy(baseline, &image)?;
    let checksum_byte = orphan_block
        .checked_mul(u64::from(block_size))
        .and_then(|offset| offset.checked_add(u64::from(block_size).checked_sub(1)?))
        .ok_or_else(|| io::Error::other("orphan checksum offset overflow"))?;
    let mut file = OpenOptions::new().read(true).write(true).open(&image)?;
    file.seek(io::SeekFrom::Start(checksum_byte))?;
    let mut byte = [0_u8; 1];
    file.read_exact(&mut byte)?;
    byte[0] ^= 0x80;
    file.seek(io::SeekFrom::Start(checksum_byte))?;
    file.write_all(&byte)?;
    file.sync_all()?;
    drop(file);

    let before = sha256_file(&image)?;
    let error = match run_internal_mount_until_boundary(&image, None) {
        Ok(_) => {
            return Err(io::Error::other("corrupt orphan metadata mounted successfully").into());
        }
        Err(error) => error,
    };
    if !error
        .to_string()
        .contains("ext4 metadata checksum mismatch")
    {
        return Err(io::Error::other(format!(
            "corrupt orphan metadata returned an unexpected error: {error}"
        ))
        .into());
    }
    if sha256_file(&image)? != before {
        return Err(
            io::Error::other("corrupt orphan metadata was written before rejection").into(),
        );
    }
    fs::remove_file(image)?;
    println!("orphan checksum rejection before mount writes: PASS");
    Ok(())
}

/// Runs one modifying debugfs operation against a disposable image.
/// # Errors
/// Returns a process or non-UTF-8 output error.
fn mutate(linux: LinuxEnvironment, image: &str, request: &str) -> TaskResult<String> {
    let mut command = linux.command("debugfs");
    command.args(["-w", "-R", request, image]);
    let output = run_checked_output(command, request)?;
    Ok(String::from_utf8(output.stdout)?)
}

/// Creates one allocated file and obtains its identity from the independent tool.
/// # Errors
/// Returns a command or missing-inode error.
fn create_file(linux: LinuxEnvironment, image: &str, payload: &str, path: &str) -> TaskResult<u32> {
    let output = mutate(linux, image, &format!("write {payload} {path}"))?;
    output
        .lines()
        .find_map(|line| line.strip_prefix("Allocated inode: "))
        .ok_or_else(|| io::Error::other("debugfs did not allocate inode"))?
        .trim()
        .parse()
        .map_err(Into::into)
}

/// Reads a fixture-local little-endian field without sharing the production parser.
/// # Errors
/// Returns an error for a missing field.
fn le32(bytes: &[u8], offset: usize) -> TaskResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| io::Error::other("field offset overflow"))?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| io::Error::other("short u32 field"))?
            .try_into()?,
    ))
}

/// Reads a fixture-local little-endian short field.
/// # Errors
/// Returns an error for a missing field.
fn le16(bytes: &[u8], offset: usize) -> TaskResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| io::Error::other("field offset overflow"))?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| io::Error::other("short u16 field"))?
            .try_into()?,
    ))
}

/// Writes one independent fixture field after checking its byte range.
/// # Errors
/// Returns an error for a missing field.
fn put32(bytes: &mut [u8], offset: usize, value: u32) -> TaskResult<()> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| io::Error::other("field offset overflow"))?;
    copy_exact_bytes(
        bytes
            .get_mut(offset..end)
            .ok_or_else(|| io::Error::other("short u32 field"))?,
        &value.to_le_bytes(),
    )
}
