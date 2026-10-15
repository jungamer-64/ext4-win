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
    verify_64k_directories(linux, &root)?;
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
    verify_acl_contract(linux, &root, &image)?;
    request(linux, &image, "set_inode_field /payload flags 0x84000")?;
    verify_internal_e2fsck_clean(linux, &image, "journal-data baseline")?;
    verify_data_cuts(linux, &root, &image)?;
    verify_block_retirement(linux, &root, &image)?;
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

/// Checks the payload and allocation endpoint when journaled storage retires beside ordered data.
/// # Errors
/// Returns image construction, production mutation or independent content/allocation mismatches.
fn verify_block_retirement(
    linux: LinuxEnvironment,
    root: &Path,
    baseline: &Path,
) -> TaskResult<()> {
    let image = root.join("retired-owner.img");
    fs::copy(baseline, &image)?;
    let payload = root.join("successor.bin");
    fs::write(&payload, b"old")?;
    request(
        linux,
        &image,
        &format!("write \"{}\" /successor", linux.tool_path(&payload)?),
    )?;
    drive_internal_core_mutation(&image, |pass| {
        let (_, old) = mutation_root_file(pass, &ext4_core::Ext4Name::new(b"payload")?)?;
        let (_, successor) = mutation_root_file(pass, &ext4_core::Ext4Name::new(b"successor")?)?;
        let old = pass.file(old)?;
        let successor = pass.file(successor)?;
        pass.write_file_range(old, ext4_core::FileOffset::ZERO, b"J")?;
        pass.truncate_file(old, ext4_core::FileSize::from_bytes(0))?;
        pass.truncate_file(successor, ext4_core::FileSize::from_bytes(0))?;
        pass.write_file_range(successor, ext4_core::FileOffset::ZERO, b"NEW")
    })?;
    request(
        linux,
        &image,
        &format!("dump /successor \"{}\"", linux.tool_path(&payload)?),
    )?;
    if fs::read(&payload)? != b"NEW" {
        return Err(
            io::Error::other("retired journal data overwrote its ordered successor").into(),
        );
    }
    verify_internal_e2fsck_clean(linux, &image, "retired block ownership")
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
    drive_internal_core_mutation(image, |pass| {
        let (_, file) = mutation_root_file(pass, &name)?;
        let snapshot = pass.staged_node_metadata(ext4_core::NodeId::File(file))?;
        let node = pass.node(ext4_core::NodeId::File(file))?;
        pass.set_posix_security(
            node,
            ext4_core::Ext4Security::new(
                snapshot.security().owner(),
                ext4_core::Ext4Permissions::new(0o640)?,
            ),
        )
    })?;
    let stat = request(linux, image, "stat /payload")?;
    for field in ["atime: 0x00000001:00000005", "mtime: 0x00000001:00000005"] {
        if !stat.contains(field) {
            return Err(io::Error::other(format!(
                "inode metadata update changed access/content time: {field}"
            ))
            .into());
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

/// Exercises independently encoded full-block records and core mutation at 64 KiB.
/// # Errors
/// Returns oracle, traversal, mutation, or filesystem consistency failures.
fn verify_64k_directories(linux: LinuxEnvironment, root: &Path) -> TaskResult<()> {
    let image = root.join("directory-64k.img");
    File::create(&image)?.set_len(128 * 1024 * 1024)?;
    let mut format = linux.command("mke2fs");
    format.args([
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        "65536",
        "-O",
        "^metadata_csum,^metadata_csum_seed",
        "-E",
        "lazy_itable_init=0,lazy_journal_init=0",
        &linux.tool_path(&image)?,
    ]);
    run_checked(format, "64 KiB directory image format")?;
    let parent = drive_internal_core_read(&image, |pass| {
        let ext4_core::ChildLookup::Found(child) = pass.lookup_child(
            ext4_core::DirectoryNodeId::ROOT,
            &ext4_core::Ext4Name::new(b"lost+found")?,
        )?
        else {
            return Err(ext4_core::Error::DirectoryEntryNotFound);
        };
        let ext4_core::NodeId::Directory(parent) = *child.node() else {
            return Err(ext4_core::Error::WrongInodeKind);
        };
        if pass.lookup_child(parent, &ext4_core::Ext4Name::new(b"missing")?)?
            != ext4_core::ChildLookup::NotFound
        {
            return Err(ext4_core::Error::NameAlreadyExists);
        }
        Ok(parent)
    })?;
    drive_internal_core_mutation(&image, |pass| {
        let parent = pass.directory(parent)?;
        pass.create_file(
            parent,
            &ext4_core::Ext4Name::new(b"created")?,
            mutation_file_metadata()?,
        )?;
        pass.create_directory(
            parent,
            &ext4_core::Ext4Name::new(b"directory")?,
            ext4_core::NewDirectoryMetadata::new(
                mutation_file_metadata()?.owner(),
                ext4_core::Ext4Permissions::new(0o755)?,
            ),
        )?;
        Ok(())
    })?;
    verify_internal_e2fsck_clean(linux, &image, "64 KiB directory mutation")?;
    fs::remove_file(image)?;
    Ok(())
}

/// Keeps chmod and inherited ACL bytes interoperable with independently encoded ext4 policies.
/// # Errors
/// Returns oracle, ACL mutation or final filesystem consistency failure.
fn verify_acl_contract(linux: LinuxEnvironment, root: &Path, image: &Path) -> TaskResult<()> {
    let acl = root.join("posix-acl.bin");
    fs::write(
        &acl,
        [
            2, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 2, 0, 6, 0, 233, 3, 0, 0, 4, 0, 6, 0, 0, 0, 0, 0,
            16, 0, 6, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0,
        ],
    )?;
    request(
        linux,
        image,
        &format!(
            "ea_set -f \"{}\" /payload system.posix_acl_access",
            linux.tool_path(&acl)?
        ),
    )?;
    request(linux, image, "set_inode_field /payload mode 0100660")?;
    request(
        linux,
        image,
        &format!(
            "ea_set -f \"{}\" / system.posix_acl_default",
            linux.tool_path(&acl)?
        ),
    )?;
    drive_internal_core_mutation(image, |pass| {
        let (_, file) = mutation_root_file(pass, &ext4_core::Ext4Name::new(b"payload")?)?;
        let node = pass.node(ext4_core::NodeId::File(file))?;
        pass.set_posix_security(
            node,
            ext4_core::Ext4Security::new(
                mutation_file_metadata()?.owner(),
                ext4_core::Ext4Permissions::new(0o640)?,
            ),
        )?;
        let parent = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        pass.create_file(
            parent,
            &ext4_core::Ext4Name::new(b"acl-inherited")?,
            mutation_file_metadata()?,
        )?;
        Ok(())
    })?;
    for path in ["/payload", "/acl-inherited"] {
        let text = request(linux, image, &format!("stat {path}"))?;
        if !text.contains("Mode:  0640") {
            return Err(io::Error::other("ACL mode projection differs from oracle").into());
        }
        let output = root.join("acl-readback.bin");
        request(
            linux,
            image,
            &format!(
                "ea_get -f \"{}\" {path} system.posix_acl_access",
                linux.tool_path(&output)?
            ),
        )?;
        let actual = fs::read(&output)?;
        let mut expected = fs::read(&acl)?;
        *expected
            .get_mut(30)
            .ok_or_else(|| io::Error::other("ACL fixture is truncated"))? = 4;
        if actual != expected {
            return Err(
                io::Error::other(format!("ACL mask or named permissions differ for {path}: actual={actual:02x?}, expected={expected:02x?}")).into(),
            );
        }
    }
    verify_internal_e2fsck_clean(linux, image, "ACL inheritance and chmod")?;
    drive_internal_core_mutation(image, |pass| {
        let (_, file) = mutation_root_file(pass, &ext4_core::Ext4Name::new(b"payload")?)?;
        let node = pass.node(ext4_core::NodeId::File(file))?;
        pass.set_xattr(
            node,
            ext4_core::XattrName::new(ext4_core::XattrNamespace::System, b"posix_acl_access")?,
            ext4_core::XattrValue::new(&1_u32.to_le_bytes())?,
        )?;
        let root = pass.node(ext4_core::NodeId::Directory(
            ext4_core::DirectoryNodeId::ROOT,
        ))?;
        pass.set_xattr(
            root,
            ext4_core::XattrName::new(ext4_core::XattrNamespace::System, b"posix_acl_default")?,
            ext4_core::XattrValue::new(&1_u32.to_le_bytes())?,
        )?;
        let parent = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        pass.unlink_file(parent, &ext4_core::Ext4Name::new(b"acl-inherited")?)
    })?;
    for path in ["/payload", "/"] {
        if request(linux, image, &format!("ea_list {path}"))?.contains("system.posix_acl_") {
            return Err(io::Error::other("empty ACL retained a persistent policy slot").into());
        }
    }
    verify_internal_e2fsck_clean(linux, image, "ACL removal")
}
