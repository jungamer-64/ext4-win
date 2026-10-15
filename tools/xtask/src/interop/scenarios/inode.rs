//! Inode semantics observed through e2fsprogs and production mount/commit/recovery operations.

use super::*;

/// Verifies accepted inode layouts, directory reference state and journaled data crash endpoints.
/// # Errors
/// Returns image construction, production operation, independent-oracle or cleanup failures.
pub(super) fn verify_inode_contracts(
    linux: LinuxEnvironment,
    temporary_root: &Path,
) -> TaskResult<()> {
    let root = temporary_root.join("inode-contracts");
    fs::create_dir(&root)?;
    let image = root.join("filesystem.img");
    format_htree_image(linux, &image, 32 * 1024 * 1024, 4096, true, false, 4)?;
    let payload = root.join("payload.bin");
    fs::write(&payload, [0x11_u8; 8192])?;
    request(
        linux,
        &image,
        &format!("write \"{}\" /payload", linux.tool_path(&payload)?),
    )?;
    verify_times_and_xattrs(linux, &image)?;
    request(linux, &image, "set_inode_field /payload flags 0x84000")?;
    verify_internal_e2fsck_clean(linux, &image, "journal-data baseline")?;
    verify_data_cuts(linux, &root, &image)?;
    verify_directory_links(linux, &root, &image)?;
    println!("ext4 inode field and data-journaling contracts: PASS");
    Ok(())
}

/// Executes one independent debugfs request against a task-owned image.
/// # Errors
/// Returns process execution failure or a rejected debugfs request.
fn request(linux: LinuxEnvironment, image: &Path, text: &str) -> TaskResult<String> {
    let mut command = linux.command("debugfs");
    command.args(["-w", "-R", text, &linux.tool_path(image)?]);
    let output = run_checked_output(command, "inode fixture oracle")?;
    let errors = String::from_utf8(output.stderr)?;
    if errors
        .lines()
        .any(|line| !line.is_empty() && !line.starts_with("debugfs "))
    {
        return Err(
            io::Error::other(format!("debugfs rejected inode fixture request: {errors}")).into(),
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Checks epoch/nanosecond wire fields and a small extra-field record containing real xattrs.
/// # Errors
/// Returns production decoding/mutation failure or an independent field/xattr mismatch.
fn verify_times_and_xattrs(linux: LinuxEnvironment, image: &Path) -> TaskResult<()> {
    request(linux, image, "set_inode_field /payload mtime 0x00000001")?;
    request(linux, image, "set_inode_field /payload mtime_extra 5")?;
    let name = ext4_core::Ext4Name::new(b"payload").map_err(core_task_error)?;
    let times = drive_internal_core_read(image, |pass| {
        let root = pass.load_directory(ext4_core::DirectoryNodeId::ROOT)?;
        let ext4_core::ChildLookup::Found(child) =
            ext4_core::CommittedReadPass::lookup_child(pass, root.id(), &name)?
        else {
            return Err(ext4_core::Error::DirectoryEntryNotFound);
        };
        Ok(ext4_core::CommittedReadPass::load_node_metadata(pass, *child.node())?.times())
    })?;
    let expected = ext4_core::Ext4Timestamp::new(4_294_967_297, 1).map_err(core_task_error)?;
    if times.modified() != expected {
        return Err(io::Error::other("extended inode time lost epoch or nanoseconds").into());
    }
    drive_internal_core_mutation(image, |pass| {
        let (_, file) = mutation_root_file(pass, &name)?;
        let node = pass.node(ext4_core::NodeId::File(file))?;
        pass.set_times(
            node,
            ext4_core::Ext4Times::new(expected, expected, expected, Some(expected)),
        )
    })?;
    let stat = request(linux, image, "stat /payload")?;
    for field in [
        "ctime: 0x00000001:00000005",
        "atime: 0x00000001:00000005",
        "mtime: 0x00000001:00000005",
        "crtime: 0x00000001:00000005",
    ] {
        if !stat.contains(field) {
            return Err(
                io::Error::other(format!("independent timestamp field mismatch: {field}")).into(),
            );
        }
    }
    for field in [
        "ctime_extra",
        "mtime_extra",
        "atime_extra",
        "crtime",
        "crtime_extra",
    ] {
        request(linux, image, &format!("set_inode_field /payload {field} 0"))?;
    }
    request(linux, image, "set_inode_field /payload extra_isize 4")?;
    request(linux, image, "ea_set /payload user.probe evidence")?;
    request(linux, image, "ea_set /payload user.z Z")?;
    request(linux, image, "ea_set /payload user.a A")?;
    verify_internal_e2fsck_clean(linux, image, "small extra-field inode baseline")?;
    drive_internal_core_mutation(image, |pass| {
        let (_, file) = mutation_root_file(pass, &name)?;
        let snapshot = pass.staged_node_metadata(ext4_core::NodeId::File(file))?;
        if snapshot.times().created().is_some() {
            return Err(ext4_core::Error::InvalidTimestamp);
        }
        let file = pass.file(file)?;
        pass.write_file_range(file, ext4_core::FileOffset::ZERO, &[0x11])
    })?;
    let attributes = request(linux, image, "ea_list /payload")?;
    if !attributes.contains("user.probe (8) = \"evidence\"")
        || !attributes.contains("user.z (1) = \"Z\"")
        || !attributes.contains("user.a (1) = \"A\"")
    {
        return Err(io::Error::other("timestamp update overwrote inline xattr storage").into());
    }
    verify_internal_e2fsck_clean(linux, image, "small extra-field inode mutation")
}

/// Checks an independently indexed directory whose link count is the valid uncounted marker.
/// # Errors
/// Returns directory construction, feature/marker, mutation or filesystem-check failures.
fn verify_directory_links(linux: LinuxEnvironment, root: &Path, image: &Path) -> TaskResult<()> {
    let requests = root.join("directories.requests");
    let mut text = String::new();
    for index in 0..1000 {
        writeln!(&mut text, "mkdir /directory-with-a-long-name-{index:04}")?;
    }
    fs::write(&requests, text)?;
    let mut command = linux.command("debugfs");
    command.args([
        "-w",
        "-f",
        &linux.tool_path(&requests)?,
        &linux.tool_path(image)?,
    ]);
    run_checked(command, "independent directory population")?;
    let mut optimize = linux.command("e2fsck");
    optimize.args(["-f", "-y", "-D", &linux.tool_path(image)?]);
    let output = optimize.output()?;
    if !matches!(output.status.code(), Some(0 | 1)) {
        return Err(io::Error::other("independent directory indexing failed").into());
    }
    request(linux, image, "set_inode_field / links_count 1")?;
    verify_internal_e2fsck_clean(linux, image, "uncounted directory baseline")?;
    let name = ext4_core::Ext4Name::new(b"reference-child").map_err(core_task_error)?;
    drive_internal_core_mutation(image, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        pass.create_directory(
            root,
            &name,
            ext4_core::NewDirectoryMetadata::new(
                ext4_core::Ext4Owner::new(
                    ext4_core::Ext4Uid::from_u32(1000),
                    ext4_core::Ext4Gid::from_u32(1000),
                ),
                ext4_core::Ext4Permissions::new(0o755)?,
            ),
        )?;
        Ok(())
    })?;
    verify_internal_e2fsck_clean(linux, image, "uncounted directory increment")?;
    drive_internal_core_mutation(image, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        pass.remove_empty_directory(root, &name)
    })?;
    let stat = request(linux, image, "stat /")?;
    if !stat.contains("Links: 1 ") {
        return Err(io::Error::other("directory lost uncounted reference state").into());
    }
    verify_internal_e2fsck_clean(linux, image, "uncounted directory decrement")
}

/// Runs one two-block overwrite with production crash storage and an optional persistence cut.
/// # Errors
/// Returns mount, resolution, reservation or effect-boundary failures.
fn overwrite_until_boundary(image: &Path, cut: Option<EffectCut>) -> TaskResult<EffectBoundaryRun> {
    let mut storage = CrashStorageAdapter::open_internal(image)?;
    let completed = mount_internal_core(&mut storage)?;
    let (profile, epoch, mut coordinator) = (*completed).into_parts();
    let ticket = coordinator.admit_mutation().map_err(core_task_error)?;
    let name = ext4_core::Ext4Name::new(b"payload").map_err(core_task_error)?;
    let (prepared, ()) = prepare_core_mutation(
        &mut storage,
        &profile,
        &epoch,
        &mut coordinator,
        ticket,
        |pass| {
            let (_, file) = mutation_root_file(pass, &name)?;
            let file = pass.file(file)?;
            pass.write_file_range(file, ext4_core::FileOffset::ZERO, &[0x22; 8192])
        },
    )?;
    run_prepared_mutation_until_boundary(&mut storage, &mut coordinator, ticket, prepared, cut)
}

/// Every sector-prefix/flush cut must recover all old bytes or all new bytes, independently read.
/// # Errors
/// Returns a production recovery failure, mixed payload or independent filesystem rejection.
fn verify_data_cuts(linux: LinuxEnvironment, root: &Path, baseline: &Path) -> TaskResult<()> {
    let image = root.join("journaled-cut.img");
    fs::copy(baseline, &image)?;
    let effects = require_completed_effect_probe(
        "journaled file data",
        overwrite_until_boundary(&image, None)?,
    )?;
    let cuts = enumerate_effect_cuts(&effects)?;
    let dumped = root.join("recovered.bin");
    for cut in cuts.iter().copied() {
        fs::copy(baseline, &image)?;
        require_stopped_effect(
            "journaled file data",
            cut,
            overwrite_until_boundary(&image, Some(cut))?,
        )?;
        drive_core_mount_and_clean_close(&image)?;
        request(
            linux,
            &image,
            &format!("dump /payload \"{}\"", linux.tool_path(&dumped)?),
        )?;
        let bytes = fs::read(&dumped)?;
        if bytes != [0x11; 8192] && bytes != [0x22; 8192] {
            return Err(
                io::Error::other("journaled file recovered a mixed data transaction").into(),
            );
        }
        verify_internal_e2fsck_clean(linux, &image, "journaled file data recovery")?;
    }
    fs::remove_file(image)?;
    println!(
        "journaled file data: PASS ({} sector/flush cuts)",
        cuts.len()
    );
    Ok(())
}
