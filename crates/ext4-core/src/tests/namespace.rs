use super::*;

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn directory_entries_are_parsed_from_root_inode() {
    let image = fixture_image();
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let entries = read_directory(&mut volume, InodeId::ROOT);

    assert_eq!(entries.len(), 4);
    assert_eq!(entries[2].name().bytes(), b"file");
    assert_eq!(entries[2].entry_kind(), DirectoryEntryKind::File);
    assert_eq!(entries[3].name().bytes(), b"link");
    assert_eq!(entries[3].entry_kind(), DirectoryEntryKind::Symlink);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn symlink_inline_target_is_read_without_extents() {
    let image = fixture_image();
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let target = read_symlink(&mut volume, 4);

    assert_eq!(target, b"file");
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn exact_ext4_lookup_uses_raw_bytes() {
    let image = fixture_image();
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let child = lookup_ext4(&mut volume, InodeId::ROOT, b"file");

    let crate::ChildLookup::Found(child) = child else {
        panic!("expected typed directory child");
    };
    assert_eq!(child.parent(), crate::DirectoryNodeId::ROOT);
    assert_eq!(child.node().inode(), inode(3));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn file_index_lookup_classifies_live_inode() {
    let mut image = minimal_write_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));

    let node = must_run(volume.load_node_by_file_index(3));
    assert!(matches!(node, NodeId::File(_)));
    assert_eq!(node.file_index(), 3);
    assert_eq!(
        run(volume.load_node_by_file_index(0)),
        Err(Error::InvalidInode)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn windows_name_projection_rejects_reserved_separator() {
    let ext4_name = must(crate::Ext4Name::new(b"a:b"));
    let result = WindowsName::from_ext4(&ext4_name);

    assert!(matches!(result, Err(Error::InvalidName)));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn windows_lookup_accepts_unique_ascii_case_fold() {
    let image = fixture_image();
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let child = lookup_windows(
        &mut volume,
        InodeId::ROOT,
        &[0x0046, 0x0049, 0x004C, 0x0045],
    );

    let crate::ChildLookup::Found(child) = child else {
        panic!("expected typed directory child");
    };
    assert_eq!(child.parent(), crate::DirectoryNodeId::ROOT);
    assert_eq!(child.node().inode(), inode(3));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn lookup_reports_not_found_without_option() {
    let image = fixture_image();
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));

    assert_eq!(
        lookup_ext4_inode(&mut volume, InodeId::ROOT, b"missing"),
        None
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn windows_lookup_rejects_ambiguous_case_fold() {
    let mut image = fixture_image();
    write_dirent(
        &mut image,
        block_offset(ROOT_DIR_BLOCK) + 40,
        4,
        984,
        b"FILE",
        1,
    );
    let mut volume = must_run(ReadOnlyVolume::mount(
        MemoryBlockSource::new(&image),
        test_mount_context(),
    ));
    let root = directory_node(&mut volume, InodeId::ROOT);
    let requested = must(WindowsName::from_utf16(&[0x0046, 0x0069, 0x004C, 0x0065]));
    let result = run(volume.lookup_windows_child(&root, &requested));

    assert_eq!(result, Err(Error::AmbiguousWindowsName));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn write_mount_rejects_layout_and_namespace_feature_profiles() {
    for incompat in [
        INCOMPAT_META_BG,
        INCOMPAT_MMP,
        INCOMPAT_EA_INODE,
        INCOMPAT_LARGEDIR,
        INCOMPAT_INLINE_DATA,
        INCOMPAT_CASEFOLD,
    ] {
        let mut image = minimal_write_fixture_image();
        put_u32(
            &mut image,
            1024 + 96,
            INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | incompat,
        );
        let result = Superblock::parse_read_write(&image[1024..2048]);

        assert_eq!(result, Err(Error::UnsupportedWriteFeature));
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn minimal_profile_supports_file_and_namespace_mutations() {
    let mut image = minimal_write_fixture_image();

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&mut volume, 3);

        let mut write = volume.begin_transaction(NOW);
        write_file(&mut write, file_id, 0, b"HELLO");
        extend_file(&mut write, file_id, 3072);
        write_file(&mut write, file_id, 2048, b"tail");
        truncate_file(&mut write, file_id, 1024);
        must_run(write.commit());

        let mut output = [0_u8; 5];
        assert_eq!(read_file(&mut volume, 3, 0, &mut output), 5);
        assert_eq!(&output, b"HELLO");
        assert_eq!(file_node(&mut volume, 3).size().bytes(), 1024);

        let root = InodeId::ROOT;
        let root_id = crate::DirectoryNodeId::ROOT;
        let old_name = must(Ext4Name::new(b"old"));
        let new_name = must(Ext4Name::new(b"renamed"));

        let mut create = volume.begin_transaction(NOW);
        let root_directory = transaction_directory(&mut create, root_id);
        let file = must_run(create.create_file(root_directory, &old_name, test_file_metadata()));
        assert_eq!(file.id().inode(), inode(11));
        must_run(create.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root_directory = transaction_directory(&mut rename, root_id);
        must_run(rename.rename_child(
            root_directory,
            &old_name,
            root_directory,
            &new_name,
            RenameTargetCollision::Reject,
        ));
        must_run(rename.commit());

        let mut unlink = volume.begin_transaction(NOW);
        let root_directory = transaction_directory(&mut unlink, root_id);
        must_run(unlink.unlink_file(root_directory, &new_name));
        must_run(unlink.commit());

        assert_eq!(lookup_ext4_inode(&mut volume, root, b"renamed"), None);
    }

    assert_eq!(
        get_u32(&image, modern_inode_offset(2) + 32) & EXT4_INDEX_FL,
        0
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_file_adds_directory_entry_and_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        let name = must(Ext4Name::new(b"new"));
        let file = must_run(transaction.create_file(root, &name, test_file_metadata()));
        assert_eq!(file.id().inode(), inode(11));
        must_run(transaction.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"new"),
            Some(inode(11))
        );
        let file = file_node(&mut volume, 11);
        assert_eq!(file.size().bytes(), 0);
    }

    assert_eq!(get_u32(&image, 1024 + 16), 5);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_file_rejects_duplicate_name() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"file"));
    let result = run(transaction.create_file(root, &name, test_file_metadata()));

    assert_eq!(result, Err(Error::NameAlreadyExists));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn unlink_file_removes_directory_entry_and_frees_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let name = must(Ext4Name::new(b"new"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create, crate::DirectoryNodeId::ROOT);
        let _file = must_run(create.create_file(root, &name, test_file_metadata()));
        must_run(create.commit());

        let mut unlink = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut unlink, crate::DirectoryNodeId::ROOT);
        must_run(unlink.unlink_file(root, &name));
        must_run(unlink.commit());

        assert_eq!(lookup_ext4_inode(&mut volume, InodeId::ROOT, b"new"), None);
    }

    assert_eq!(get_u32(&image, 1024 + 16), 6);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn unlink_file_reports_missing_entry() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"missing"));
    let result = run(transaction.unlink_file(root, &name));

    assert_eq!(result, Err(Error::DirectoryEntryNotFound));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_file_updates_staged_directory_entry() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        let old_name = must(Ext4Name::new(b"old"));
        let new_name = must(Ext4Name::new(b"new"));
        let file = must_run(transaction.create_file(root, &old_name, test_file_metadata()));
        must_run(transaction.rename_child(
            root,
            &old_name,
            root,
            &new_name,
            RenameTargetCollision::Reject,
        ));
        assert_eq!(file.id().inode(), inode(11));
        must_run(transaction.commit());

        assert_eq!(lookup_ext4_inode(&mut volume, InodeId::ROOT, b"old"), None);
        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"new"),
            Some(inode(11))
        );
    }

    assert_eq!(get_u32(&image, 1024 + 16), 5);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_rejects_existing_target() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
    let source = must(Ext4Name::new(b"file"));
    let target = must(Ext4Name::new(b"target"));
    let _target_file = must_run(transaction.create_file(root, &target, test_file_metadata()));
    let result =
        run(transaction.rename_child(root, &source, root, &target, RenameTargetCollision::Reject));

    assert_eq!(result, Err(Error::NameAlreadyExists));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_file_replaces_existing_file_target() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let source_name = must(Ext4Name::new(b"source"));
        let target_name = must(Ext4Name::new(b"target"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create, crate::DirectoryNodeId::ROOT);
        let source = must_run(create.create_file(root, &source_name, test_file_metadata()));
        let target = must_run(create.create_file(root, &target_name, test_file_metadata()));
        must_run(create.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut rename, crate::DirectoryNodeId::ROOT);
        must_run(rename.rename_child(
            root,
            &source_name,
            root,
            &target_name,
            RenameTargetCollision::Replace,
        ));
        must_run(rename.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"source"),
            None
        );
        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"target"),
            Some(source.id().inode())
        );
        assert_ne!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"target"),
            Some(target.id().inode())
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_directory_replaces_empty_directory_target() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let source_name = must(Ext4Name::new(b"source-dir"));
        let target_name = must(Ext4Name::new(b"target-dir"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create, crate::DirectoryNodeId::ROOT);
        let source =
            must_run(create.create_directory(root, &source_name, test_directory_metadata()));
        let target =
            must_run(create.create_directory(root, &target_name, test_directory_metadata()));
        must_run(create.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut rename, crate::DirectoryNodeId::ROOT);
        must_run(rename.rename_child(
            root,
            &source_name,
            root,
            &target_name,
            RenameTargetCollision::Replace,
        ));
        must_run(rename.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"source-dir"),
            None
        );
        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"target-dir"),
            Some(source.id().inode())
        );
        assert_ne!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"target-dir"),
            Some(target.id().inode())
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_file_replace_rejects_directory_target() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let source_name = must(Ext4Name::new(b"source"));
    let target_name = must(Ext4Name::new(b"target-dir"));

    let mut create = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut create, crate::DirectoryNodeId::ROOT);
    let _source = must_run(create.create_file(root, &source_name, test_file_metadata()));
    let _target = must_run(create.create_directory(root, &target_name, test_directory_metadata()));
    must_run(create.commit());

    let mut rename = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut rename, crate::DirectoryNodeId::ROOT);
    let result = run(rename.rename_child(
        root,
        &source_name,
        root,
        &target_name,
        RenameTargetCollision::Replace,
    ));

    assert_eq!(result, Err(Error::WrongInodeKind));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_and_remove_empty_directory_updates_namespace() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let name = must(Ext4Name::new(b"dir"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create, crate::DirectoryNodeId::ROOT);
        let directory = must_run(create.create_directory(root, &name, test_directory_metadata()));
        assert_eq!(directory.id().inode(), inode(11));
        must_run(create.commit());

        let entries = read_directory(&mut volume, inode(11));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name().bytes(), b".");
        assert_eq!(entries[1].name().bytes(), b"..");

        let mut remove = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut remove, crate::DirectoryNodeId::ROOT);
        must_run(remove.remove_empty_directory(root, &name));
        must_run(remove.commit());

        assert_eq!(lookup_ext4_inode(&mut volume, InodeId::ROOT, b"dir"), None);
    }

    assert_eq!(get_u32(&image, 1024 + 16), 6);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_inline_symlink_adds_directory_entry_and_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        let name = must(Ext4Name::new(b"inline-link"));
        let target = must(SymlinkTarget::new(b"file"));
        let symlink =
            must_run(transaction.create_symlink(root, &name, &target, test_symlink_metadata()));
        assert_eq!(symlink.id().inode(), inode(11));
        must_run(transaction.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"inline-link"),
            Some(inode(11))
        );
        let symlink = symlink_node(&mut volume, 11);
        assert_eq!(must_run(volume.read_symlink(&symlink)), b"file");
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn create_extent_symlink_writes_target_blocks() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let target_bytes = [b't'; 96];

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        let name = must(Ext4Name::new(b"extent-link"));
        let target = must(SymlinkTarget::new(&target_bytes));
        let symlink =
            must_run(transaction.create_symlink(root, &name, &target, test_symlink_metadata()));
        assert_eq!(symlink.id().inode(), inode(11));
        must_run(transaction.commit());

        let symlink = symlink_node(&mut volume, 11);
        assert_eq!(must_run(volume.read_symlink(&symlink)), target_bytes);
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn remove_symlink_removes_directory_entry_and_frees_inode() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let name = must(Ext4Name::new(b"delete-link"));
        let target = must(SymlinkTarget::new(b"file"));

        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        must_run(transaction.create_symlink(root, &name, &target, test_symlink_metadata()));
        must_run(transaction.commit());

        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        must_run(transaction.remove_symlink(root, &name));
        must_run(transaction.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"delete-link"),
            None
        );
    }
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn rename_directory_across_parents_updates_dotdot() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let source_name = must(Ext4Name::new(b"a"));
        let target_parent_name = must(Ext4Name::new(b"b"));
        let moved_name = must(Ext4Name::new(b"moved"));

        let mut create_source = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create_source, crate::DirectoryNodeId::ROOT);
        let source =
            must_run(create_source.create_directory(root, &source_name, test_directory_metadata()));
        assert_eq!(source.id().inode(), inode(11));
        must_run(create_source.commit());

        let mut create_target = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create_target, crate::DirectoryNodeId::ROOT);
        let target_parent = must_run(create_target.create_directory(
            root,
            &target_parent_name,
            test_directory_metadata(),
        ));
        assert_eq!(target_parent.id().inode(), inode(12));
        let target_parent_id = target_parent.id();
        must_run(create_target.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut rename, crate::DirectoryNodeId::ROOT);
        let target_parent = transaction_directory(&mut rename, target_parent_id);
        must_run(rename.rename_child(
            root,
            &source_name,
            target_parent,
            &moved_name,
            RenameTargetCollision::Reject,
        ));
        must_run(rename.commit());

        assert_eq!(lookup_ext4_inode(&mut volume, InodeId::ROOT, b"a"), None);
        assert_eq!(
            lookup_ext4_inode(&mut volume, inode(12), b"moved"),
            Some(inode(11))
        );
        let moved_entries = read_directory(&mut volume, inode(11));
        let dotdot = moved_entries
            .iter()
            .find(|entry| entry.name().bytes() == b"..");
        assert!(dotdot.is_some());
        if let Some(dotdot) = dotdot {
            assert_eq!(dotdot.node().inode(), inode(12));
        }
    }

    assert_eq!(get_u32(&image, 1024 + 16), 4);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn remove_directory_rejects_non_empty_child() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let dir_name = must(Ext4Name::new(b"dir"));
    let file_name = must(Ext4Name::new(b"child"));

    let mut create_dir = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut create_dir, crate::DirectoryNodeId::ROOT);
    let directory =
        must_run(create_dir.create_directory(root, &dir_name, test_directory_metadata()));
    must_run(create_dir.commit());

    let mut create_file = volume.begin_transaction(NOW);
    let child_parent = transaction_directory(&mut create_file, directory.id());
    let _file = must_run(create_file.create_file(child_parent, &file_name, test_file_metadata()));
    must_run(create_file.commit());

    let mut remove = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut remove, crate::DirectoryNodeId::ROOT);
    let result = run(remove.remove_empty_directory(root, &dir_name));

    assert_eq!(result, Err(Error::DirectoryNotEmpty));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn remove_directory_rejects_root_entry() {
    let mut image = modern_fixture_image();
    let device = MemoryBlockStorage::new(&mut image);
    let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
    let dot = must(Ext4Name::new(b"."));
    let result = run(transaction.remove_empty_directory(root, &dot));

    assert_eq!(result, Err(Error::CannotRemoveRoot));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn indexed_directory_create_rebuilds_real_htree() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
        let name = must(Ext4Name::new(b"idx"));
        let file = must_run(transaction.create_file(root, &name, test_file_metadata()));
        assert_eq!(file.id().inode(), inode(11));
        must_run(transaction.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"idx"),
            Some(inode(11))
        );
    }

    let root_block = block_offset(MODERN_ROOT_DIR_BLOCK);
    assert_eq!(get_u32(&image, root_block), 2);
    assert_eq!(image[root_block + 29], 8);
    assert_eq!(image[root_block + 30], 0);
    assert_eq!(get_u16(&image, root_block + 34), 1);
    assert_eq!(get_u32(&image, root_block + 36), 1);
    assert_eq!(get_u32(&image, block_offset(MODERN_EXTENT_INDEX_BLOCK)), 3);
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn htree_directory_read_lookup_and_windows_lookup_use_real_index() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);
    let device = MemoryBlockSource::new(&image);
    let mut volume = must_run(ReadOnlyVolume::mount(device, test_mount_context()));

    let entries = read_directory(&mut volume, InodeId::ROOT);

    assert!(entries.iter().any(|entry| entry.name().bytes() == b"."));
    assert!(entries.iter().any(|entry| entry.name().bytes() == b".."));
    assert!(entries.iter().any(|entry| entry.name().bytes() == b"file"));
    assert_eq!(
        lookup_ext4_inode(&mut volume, InodeId::ROOT, b"file"),
        Some(inode(3))
    );
    assert_eq!(
        lookup_windows_inode(
            &mut volume,
            InodeId::ROOT,
            &[
                u16::from(b'F'),
                u16::from(b'I'),
                u16::from(b'L'),
                u16::from(b'E'),
            ],
        ),
        Some(inode(3))
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn htree_dx_tail_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);
    image[block_offset(MODERN_ROOT_DIR_BLOCK) + 36] ^= 1;
    let device = MemoryBlockSource::new(&image);
    let mut volume = must_run(ReadOnlyVolume::mount(device, test_mount_context()));
    let root = directory_node(&mut volume, InodeId::ROOT);

    assert_eq!(
        run(volume.read_directory(&root)),
        Err(Error::ChecksumMismatch)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn htree_leaf_tail_checksum_mismatch_is_rejected() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);
    image[block_offset(MODERN_EXTENT_INDEX_BLOCK) + 8] ^= 1;
    let device = MemoryBlockSource::new(&image);
    let mut volume = must_run(ReadOnlyVolume::mount(device, test_mount_context()));
    let root = directory_node(&mut volume, InodeId::ROOT);

    assert_eq!(
        run(volume.read_directory(&root)),
        Err(Error::ChecksumMismatch)
    );
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn linear_directory_converts_to_htree_when_full() {
    let mut image = modern_fixture_image_with_journal_blocks(16);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        for index in 0..4_u8 {
            let mut bytes = vec![b'a' + index; 240];
            bytes.push(b'0' + index);
            let name = must(Ext4Name::new(&bytes));
            let mut transaction = volume.begin_transaction(NOW);
            let root = transaction_directory(&mut transaction, crate::DirectoryNodeId::ROOT);
            let _file = must_run(transaction.create_file(root, &name, test_file_metadata()));
            must_run(transaction.commit());
        }

        let root = directory_node(&mut volume, InodeId::ROOT);
        let entries = must_run(volume.read_directory(&root));
        assert!(
            entries
                .iter()
                .any(|entry| entry.name().bytes().len() == 241)
        );
    }

    let root_inode = modern_inode_offset(2);
    assert_ne!(get_u32(&image, root_inode + 32) & EXT4_INDEX_FL, 0);
    assert!(get_u32(&image, root_inode + 4) >= u32::try_from(BLOCK_SIZE * 2).unwrap_or(u32::MAX));
}

/// # Panics
///
/// Panics when assertions or fixed test fixture assumptions fail.
#[test]
fn indexed_directory_rename_and_unlink_rebuild_htree_consistently() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    make_indexed_root_directory(&mut image);

    {
        let device = MemoryBlockStorage::new(&mut image);
        let mut volume = must_run(JournaledVolume::mount(device, test_mount_context()));
        let old_name = must(Ext4Name::new(b"temp"));
        let renamed_name = must(Ext4Name::new(b"renamed"));

        let mut create = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut create, crate::DirectoryNodeId::ROOT);
        let file = must_run(create.create_file(root, &old_name, test_file_metadata()));
        must_run(create.commit());

        let mut rename = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut rename, crate::DirectoryNodeId::ROOT);
        must_run(rename.rename_child(
            root,
            &old_name,
            root,
            &renamed_name,
            RenameTargetCollision::Reject,
        ));
        must_run(rename.commit());

        assert_eq!(lookup_ext4_inode(&mut volume, InodeId::ROOT, b"temp"), None);
        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"renamed"),
            Some(file.id().inode())
        );

        let mut unlink = volume.begin_transaction(NOW);
        let root = transaction_directory(&mut unlink, crate::DirectoryNodeId::ROOT);
        must_run(unlink.unlink_file(root, &renamed_name));
        must_run(unlink.commit());

        assert_eq!(
            lookup_ext4_inode(&mut volume, InodeId::ROOT, b"renamed"),
            None
        );
    }
}
