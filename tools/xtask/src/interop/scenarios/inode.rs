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
    verify_attribute_values(linux, &root)?;
    verify_casefold_names(linux, &root)?;
    verify_bitmap_publication(linux, &root)?;
    verify_64k_directories(linux, &root)?;
    let image = root.join("filesystem.img");
    format_htree_image(linux, &image, 32 * 1024 * 1024, 4096, true, false, 4)?;
    verify_metadata_inode_isolation(&image)?;
    let payload = root.join("payload.bin");
    fs::write(&payload, [0x11_u8; 8192])?;
    request(
        linux,
        &image,
        &format!("write \"{}\" /payload", linux.tool_path(&payload)?),
    )?;
    verify_times_and_xattrs(linux, &image)?;
    verify_acl_contract(linux, &root, &image)?;
    verify_ownership_privileges(linux, &root, &image)?;
    request(linux, &image, "set_inode_field /payload flags 0x84000")?;
    verify_internal_e2fsck_clean(linux, &image, "journal-data baseline")?;
    let inherited = verify_flag_inheritance(linux, &root)?;
    verify_data_cuts(linux, &root, &inherited)?;
    verify_block_retirement(linux, &root, &image)?;
    verify_inode_retirement(linux, &root, &image)?;
    verify_directory_links(linux, &root, &image)?;
    println!("ext4 inode field and data-journaling contracts: PASS");
    Ok(())
}

/// Checks stored spellings and folded index placement with an independent formatter and fsck.
/// # Errors
/// Returns formatting, namespace, journal, independent content or index-check failure.
fn verify_casefold_names(linux: LinuxEnvironment, root: &Path) -> TaskResult<()> {
    for compact in [false, true] {
        let case = root.join(format!("casefold-inline{compact}"));
        fs::create_dir(&case)?;
        let image = case.join("filesystem.img");
        File::create(&image)?.set_len(32 * 1024 * 1024)?;
        let features = format!(
            "casefold,^metadata_csum_seed,^orphan_file,^sparse_super2,{}",
            if compact {
                "inline_data"
            } else {
                "^inline_data"
            }
        );
        let mut format = linux.command("mke2fs");
        format.args([
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-I",
            "256",
            "-O",
            &features,
            "-E",
            "encoding=utf8-12.1,encoding_flags=strict,lazy_itable_init=0,lazy_journal_init=0",
            &linux.tool_path(&image)?,
        ]);
        run_checked(format, "casefold image format")?;
        let directory = drive_internal_core_mutation(&image, |pass| {
            let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
            let directory = pass.create_directory(
                root,
                &ext4_core::Ext4Name::new(b"folded")?,
                ext4_core::NewDirectoryMetadata::new(
                    mutation_file_metadata()?.owner(),
                    ext4_core::Ext4Permissions::new(0o755)?,
                ),
            )?;
            pass.set_directory_casefold(directory, ext4_core::DirectoryCasefold::Enabled)?;
            Ok(directory.id())
        })?;
        let payload = case.join("payload.bin");
        fs::write(&payload, b"independent value")?;
        request(
            linux,
            &image,
            &format!("write \"{}\" /folded/Straße", linux.tool_path(&payload)?),
        )?;
        drive_internal_core_read(&image, |pass| {
            if !matches!(
                pass.lookup_child(directory, &ext4_core::Ext4Name::new(b"STRASSE")?)?,
                ext4_core::ChildLookup::Found(_)
            ) {
                return Err(ext4_core::Error::DirectoryEntryNotFound);
            }
            Ok(())
        })?;
        drive_internal_core_mutation(&image, |pass| {
            let directory = pass.directory(directory)?;
            pass.rename_child(
                directory,
                &ext4_core::Ext4Name::new(b"strasse")?,
                directory,
                &ext4_core::Ext4Name::new(b"STRASSE")?,
                ext4_core::NamespaceDestination::Vacant,
            )?;
            for index in 0..40 {
                let name = format!("É-{index:02}-{}", "x".repeat(180));
                pass.create_file(
                    directory,
                    &ext4_core::Ext4Name::new(name.as_bytes())?,
                    mutation_file_metadata()?,
                )?;
            }
            Ok(())
        })?;
        debugfs_require_file(
            linux,
            &case,
            &image,
            "/folded/STRASSE",
            b"independent value",
            1,
            "casefold spelling",
        )?;
        verify_internal_e2fsck_clean(linux, &image, "casefold HTree placement")?;
        drive_internal_core_mutation(&image, |pass| {
            let directory = pass.directory(directory)?;
            pass.unlink_file(directory, &ext4_core::Ext4Name::new(b"strasse")?)?;
            for index in 0..40 {
                let alias = format!("é-{index:02}-{}", "X".repeat(180));
                pass.unlink_file(directory, &ext4_core::Ext4Name::new(alias.as_bytes())?)?;
            }
            pass.set_directory_casefold(directory, ext4_core::DirectoryCasefold::Disabled)
        })?;
        verify_internal_e2fsck_clean(linux, &image, "casefold empty transition")?;
    }
    Ok(())
}

/// Reads independently created value inodes, then checks production replacement and reclamation.
/// # Errors
/// Returns formatting, checksum, value, namespace or independent allocation-oracle failure.
fn verify_attribute_values(linux: LinuxEnvironment, root: &Path) -> TaskResult<()> {
    for (compact, inode_size) in [(false, 128_u16), (false, 256), (true, 256)] {
        let case = root.join(format!(
            "attribute-values-inline{compact}-inode{inode_size}"
        ));
        fs::create_dir(&case)?;
        let image = case.join("filesystem.img");
        File::create(&image)?.set_len(32 * 1024 * 1024)?;
        let features = format!(
            "ea_inode,^metadata_csum_seed,^orphan_file,^sparse_super2,{}",
            if compact {
                "inline_data"
            } else {
                "^inline_data"
            }
        );
        let mut format = linux.command("mke2fs");
        format.args([
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-I",
            &inode_size.to_string(),
            "-O",
            &features,
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            &linux.tool_path(&image)?,
        ]);
        run_checked(format, "attribute value image format")?;
        let baseline = debugfs_free_space(linux, &image)?;
        let payload = case.join("payload.bin");
        fs::write(&payload, b"payload")?;
        request(
            linux,
            &image,
            &format!("write \"{}\" /payload", linux.tool_path(&payload)?),
        )?;
        let value = vec![0x61; 65_536];
        let value_path = case.join("value.bin");
        fs::write(&value_path, &value)?;
        request(
            linux,
            &image,
            &format!(
                "ea_set -f \"{}\" /payload user.ext4win.interop",
                linux.tool_path(&value_path)?
            ),
        )?;
        verify_internal_e2fsck_clean(linux, &image, "independent attribute value baseline")?;
        let name = ext4_core::Ext4Name::new(b"payload").map_err(core_task_error)?;
        drive_internal_core_read(&image, |pass| {
            let ext4_core::ChildLookup::Found(child) =
                pass.lookup_child(ext4_core::DirectoryNodeId::ROOT, &name)?
            else {
                return Err(ext4_core::Error::DirectoryEntryNotFound);
            };
            let observed = pass
                .read_xattr(*child.node(), &mutation_xattr_name()?)?
                .ok_or(ext4_core::Error::InvalidXattr)?;
            if observed.bytes() != value {
                return Err(ext4_core::Error::InvalidXattr);
            }
            Ok(())
        })?;
        let replacement = vec![0x42; 32_768];
        drive_internal_core_mutation(&image, |pass| {
            let (_, file) = mutation_root_file(pass, &name)?;
            let node = pass.node(ext4_core::NodeId::File(file))?;
            pass.set_xattr(
                node,
                mutation_xattr_name()?,
                ext4_core::XattrValue::new(&replacement)?,
            )?;
            let file = pass.file(file)?;
            pass.write_file_range(file, ext4_core::FileOffset::ZERO, b"PAYLOAD")
        })?;
        debugfs_require_xattr(
            linux,
            &case,
            &image,
            "/payload",
            &replacement,
            "value replacement",
        )?;
        debugfs_require_file(
            linux,
            &case,
            &image,
            "/payload",
            b"PAYLOAD",
            1,
            "value owner payload",
        )?;
        verify_internal_e2fsck_clean(linux, &image, "attribute value replacement")?;
        drive_internal_core_mutation(&image, |pass| {
            let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
            pass.unlink_file(root, &name)
        })?;
        verify_internal_e2fsck_clean(linux, &image, "attribute value final release")?;
        if debugfs_free_space(linux, &image)? != baseline {
            return Err(io::Error::other("attribute value release leaked storage").into());
        }
    }
    Ok(())
}

/// Observes child-kind inheritance through debugfs and returns the journaled file crash fixture.
/// # Errors
/// Returns formatting, mutation, inherited-flag mismatch, or independent fsck failures.
fn verify_flag_inheritance(linux: LinuxEnvironment, root: &Path) -> TaskResult<std::path::PathBuf> {
    let image = root.join("inherited-flags.img");
    format_htree_image(linux, &image, 32 * 1024 * 1024, 4096, true, false, 4)?;
    request(linux, &image, "set_inode_field / flags 0x940c8")?;
    verify_internal_e2fsck_clean(linux, &image, "inode inheritance baseline")?;
    drive_internal_core_mutation(&image, |pass| {
        let parent = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        let metadata = mutation_file_metadata()?;
        let file = pass.create_file(parent, &ext4_core::Ext4Name::new(b"payload")?, metadata)?;
        pass.write_file_range(file, ext4_core::FileOffset::ZERO, &[0x11; 8192])?;
        let directory = pass.create_directory(
            parent,
            &ext4_core::Ext4Name::new(b"policy-directory")?,
            ext4_core::NewDirectoryMetadata::new(
                metadata.owner(),
                ext4_core::Ext4Permissions::new(0o755)?,
            ),
        )?;
        pass.create_file(directory, &ext4_core::Ext4Name::new(b"nested")?, metadata)?;
        for (name, target) in [
            (b"inline".as_slice(), b"target".as_slice()),
            (b"extent".as_slice(), &[b'x'; 61]),
        ] {
            pass.create_symlink(
                parent,
                &ext4_core::Ext4Name::new(name)?,
                &ext4_core::SymlinkTarget::new(target)?,
                ext4_core::NewSymlinkMetadata::new(
                    metadata.owner(),
                    ext4_core::Ext4Permissions::new(0o777)?,
                ),
            )?;
        }
        Ok(())
    })?;
    for (path, expected) in [
        ("/payload", 0x840c8),
        ("/policy-directory", 0x940c8),
        ("/policy-directory/nested", 0x840c8),
        ("/inline", 0xc0),
        ("/extent", 0x800c0),
    ] {
        let stat = request(linux, &image, &format!("stat {path}"))?;
        let raw = stat
            .split_once("Flags: ")
            .and_then(|(_, tail)| tail.split_whitespace().next())
            .and_then(|value| value.strip_prefix("0x"))
            .ok_or_else(|| io::Error::other("debugfs omitted inode flags"))?;
        let observed = u32::from_str_radix(raw, 16)?;
        if observed != expected {
            return Err(io::Error::other(format!(
                "{path} inherited flags {observed:#x}, expected {expected:#x}"
            ))
            .into());
        }
    }
    verify_internal_e2fsck_clean(linux, &image, "inode flag inheritance")?;
    Ok(image)
}

/// Publishes derived inode and block bitmaps whose semantic domains occupy only part of a block.
/// # Errors
/// Returns fixture, initialization-transition, production allocation or independent fsck failures.
fn verify_bitmap_publication(linux: LinuxEnvironment, root: &Path) -> TaskResult<()> {
    for metadata_checksum in [false, true] {
        let image = root.join(format!("bitmap-publication-csum{metadata_checksum}.img"));
        File::create(&image)?.set_len(32 * 1024 * 1024)?;
        let checksum = if metadata_checksum {
            "metadata_csum,^uninit_bg"
        } else {
            "^metadata_csum,uninit_bg"
        };
        let features = format!("{checksum},^metadata_csum_seed,^orphan_file,^sparse_super2");
        let mut format = linux.command("mke2fs");
        format.args([
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-g",
            "1024",
            "-N",
            "256",
            "-O",
            &features,
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0",
            "-J",
            "size=4",
            &linux.tool_path(&image)?,
        ]);
        run_checked(format, "bitmap publication image format")?;
        verify_internal_e2fsck_clean(linux, &image, "derived bitmap baseline")?;
        require_bitmap_initialization_flags(&image, true)?;
        drive_internal_core_mutation(&image, |pass| {
            let parent = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
            let file = pass.create_file(
                parent,
                &ext4_core::Ext4Name::new(b"preallocated")?,
                mutation_file_metadata()?,
            )?;
            pass.reserve_file_allocation(
                file,
                ext4_core::FileAllocationSize::from_bytes(8 * 1024 * 1024),
            )?;
            for index in 0..24 {
                let name = format!("bitmap-{index}");
                pass.create_file(
                    parent,
                    &ext4_core::Ext4Name::new(name.as_bytes())?,
                    mutation_file_metadata()?,
                )?;
            }
            Ok(())
        })?;
        require_bitmap_initialization_flags(&image, false)?;
        verify_internal_e2fsck_clean(linux, &image, "derived bitmap publication")?;
    }
    Ok(())
}

/// Checks that group one's inode bitmap and group two's block bitmap cross the tested boundary.
/// Descriptor offsets follow the fixture's independent 4 KiB/64-byte disk layout.
/// # Errors
/// Returns image-read failure or an initialization state that does not exercise the contract.
fn require_bitmap_initialization_flags(image: &Path, uninitialized: bool) -> TaskResult<()> {
    let descriptors = read_image_block(&mut File::open(image)?, 1, 4096)?;
    for (offset, flag) in [(82_usize, 1_u16), (146, 2)] {
        let end = offset
            .checked_add(2)
            .ok_or_else(|| io::Error::other("descriptor offset overflow"))?;
        let flags = u16::from_le_bytes(
            descriptors
                .get(offset..end)
                .ok_or_else(|| io::Error::other("missing bitmap descriptor flags"))?
                .try_into()?,
        );
        if (flags & flag != 0) != uninitialized {
            return Err(
                io::Error::other("bitmap initialization boundary was not exercised").into(),
            );
        }
    }
    Ok(())
}

/// Checks committed and transaction-local inode retirement against independent namespace and fsck observations.
/// # Errors
/// Returns image copy, production mutation, oracle content or allocation-consistency failures.
fn verify_inode_retirement(
    linux: LinuxEnvironment,
    root: &Path,
    baseline: &Path,
) -> TaskResult<()> {
    let image = root.join("inode-retirement.img");
    fs::copy(baseline, &image)?;
    drive_internal_core_mutation(&image, |pass| {
        let root = pass.directory(ext4_core::DirectoryNodeId::ROOT)?;
        pass.unlink_file(root, &ext4_core::Ext4Name::new(b"payload")?)?;
        let transient = pass.create_file(
            root,
            &ext4_core::Ext4Name::new(b"transient")?,
            mutation_file_metadata()?,
        )?;
        pass.write_file_range(transient, ext4_core::FileOffset::ZERO, b"temporary")?;
        pass.unlink_file(root, &ext4_core::Ext4Name::new(b"transient")?)?;
        let replacement = pass.create_file(
            root,
            &ext4_core::Ext4Name::new(b"replacement")?,
            mutation_file_metadata()?,
        )?;
        pass.write_file_range(replacement, ext4_core::FileOffset::ZERO, b"replacement")
    })?;
    debugfs_require_absent(linux, &image, "/payload")?;
    debugfs_require_absent(linux, &image, "/transient")?;
    debugfs_require_file(
        linux,
        root,
        &image,
        "/replacement",
        b"replacement",
        1,
        "inode-retirement",
    )?;
    verify_internal_e2fsck_clean(linux, &image, "inode retirement")
}

/// Checks namespace admission using the metadata identities assigned by e2fsprogs.
/// # Errors
/// Returns malformed fixture fields, mount/read/close failures, or exposed filesystem metadata.
pub(super) fn verify_metadata_inode_isolation(image: &Path) -> TaskResult<()> {
    let primary = read_image_block(&mut File::open(image)?, 1, 1024)?;
    let field = |offset: usize| -> TaskResult<u32> {
        let end = offset
            .checked_add(4)
            .ok_or_else(|| io::Error::other("field overflow"))?;
        Ok(u32::from_le_bytes(
            primary
                .get(offset..end)
                .ok_or_else(|| io::Error::other("missing inode field"))?
                .try_into()?,
        ))
    };
    let journal = field(224)?;
    let orphan = field(0x280)?;
    drive_internal_core_read(image, |pass| {
        pass.load_directory(ext4_core::DirectoryNodeId::ROOT)?;
        for inode in [journal, orphan].into_iter().filter(|inode| *inode != 0) {
            match pass.load_node_by_file_index(inode) {
                Err(ext4_core::Error::InvalidInode) => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(ext4_core::Error::InvalidInode),
            }
        }
        Ok(())
    })
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

/// Observes setid and capability retirement from independently encoded privilege-bearing inodes.
/// # Errors
/// Returns oracle, ownership mutation, mode/capability mismatch or filesystem consistency failures.
fn verify_ownership_privileges(
    linux: LinuxEnvironment,
    root: &Path,
    image: &Path,
) -> TaskResult<()> {
    let capability = root.join("file-capability.bin");
    fs::write(
        &capability,
        [1, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    )?;
    for (before, expected) in [("0106777", 0o777), ("0106640", 0o2640)] {
        request(linux, image, "set_inode_field /payload uid 1000")?;
        request(linux, image, "set_inode_field /payload gid 1000")?;
        request(
            linux,
            image,
            &format!("set_inode_field /payload mode {before}"),
        )?;
        request(
            linux,
            image,
            &format!(
                "ea_set -f \"{}\" /payload security.capability",
                linux.tool_path(&capability)?
            ),
        )?;
        verify_internal_e2fsck_clean(linux, image, "ownership privilege baseline")?;
        drive_internal_core_mutation(image, |pass| {
            let (_, file) = mutation_root_file(pass, &ext4_core::Ext4Name::new(b"payload")?)?;
            let current = pass
                .staged_node_metadata(ext4_core::NodeId::File(file))?
                .security();
            let node = pass.node(ext4_core::NodeId::File(file))?;
            pass.set_posix_security(
                node,
                ext4_core::Ext4Security::new(
                    ext4_core::Ext4Owner::new(
                        ext4_core::Ext4Uid::from_u32(0),
                        current.owner().gid(),
                    ),
                    current.permissions(),
                ),
            )
        })?;
        let stat = request(linux, image, "stat /payload")?;
        let mode = stat
            .split_whitespace()
            .skip_while(|field| *field != "Mode:")
            .nth(1)
            .ok_or_else(|| io::Error::other("debugfs omitted the inode mode"))?;
        let mode = u16::from_str_radix(mode, 8)?;
        if mode != expected {
            return Err(io::Error::other(format!(
                "ownership mutation mode differs: actual={mode:o}, expected={expected:o}"
            ))
            .into());
        }
        debugfs_require_xattr_absent(linux, image, "/payload", b"security.capability")?;
        verify_internal_e2fsck_clean(linux, image, "ownership privilege retirement")?;
    }
    Ok(())
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
    let completed = mount_internal_core(
        &mut storage,
        ext4_core::MountAccess::ReadWrite,
        ext4_core::DeviceWriteAccess::Writable,
    )?;
    let (profile, epoch, mut coordinator, _mmp) = (*completed).into_parts();
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
