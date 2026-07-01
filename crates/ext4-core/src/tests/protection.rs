use super::*;

#[test]
fn read_only_mount_accepts_encryption_and_verity_feature_bits() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0002 | 0x0040 | INCOMPAT_ENCRYPT);
    put_u32(&mut image, 1024 + 100, 0x0001 | 0x0002 | RO_COMPAT_VERITY);
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));

    assert_eq!(read_directory(&volume, InodeId::ROOT).len(), 4);
}

#[test]
fn private_fscrypt_context_is_not_public_xattr() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let context_bytes = fscrypt_v2_context_bytes();
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let file = node_id(&volume, inode(3));

    assert_eq!(
        must(volume.read_fscrypt_context(file)),
        Some(must(FscryptContextV2::parse(&context_bytes)))
    );
    assert_eq!(must(volume.read_xattrs(file)).entries().len(), 0);
}

#[test]
fn public_xattr_update_preserves_private_fscrypt_context() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let context_bytes = fscrypt_v2_context_bytes();
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);

    let name = must(XattrName::new(XattrNamespace::User, b"visible"));
    let value = must(XattrValue::new(b"value"));
    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let node_id = node_id(&volume, inode(3));
        let mut transaction = volume.begin_transaction(NOW);
        let node = transaction_node(&transaction, node_id);
        must(transaction.set_xattr(node, name.clone(), value.clone()));
        must(transaction.commit());
    }

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let file = node_id(&volume, inode(3));
    assert_eq!(
        must(volume.read_fscrypt_context(file)),
        Some(must(FscryptContextV2::parse(&context_bytes)))
    );
    assert_eq!(must(volume.read_xattr(file, &name)), Some(value));
    assert_eq!(must(volume.read_xattrs(file)).entries().len(), 1);
}

#[test]
fn encrypted_file_read_requires_mount_key() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let context_bytes = fscrypt_v2_context_bytes();
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 1];

    assert_eq!(
        volume.read_file(&file, FileOffset::ZERO, &mut output),
        Err(Error::MissingEncryptionKey)
    );
}

#[test]
fn encrypted_file_read_with_key_decrypts_plaintext() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);
    encrypt_modern_file_data_block(&mut image, &master_key, &context_bytes);

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 5];

    assert_eq!(
        must(volume.read_file(&file, FileOffset::ZERO, &mut output)).as_usize(),
        5
    );
    assert_eq!(&output, b"hello");
}

#[test]
fn encrypted_file_overwrite_roundtrips_ciphertext() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);
    encrypt_modern_file_data_block(&mut image, &master_key, &context_bytes);

    {
        let mut volume = must(JournaledVolume::mount(
            SliceBlockDeviceMut::new(&mut image),
            test_mount_context_with_key(master_key.clone()),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        overwrite_file(&mut transaction, file_id, 1, b"EL");
        must(transaction.commit());
    }

    let raw_offset = block_offset(MODERN_FILE_DATA_BLOCK);
    assert_ne!(&image[raw_offset..raw_offset + 5], b"hELlo");

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let mut output = [0_u8; 5];
    assert_eq!(read_file(&volume, 3, 0, &mut output), 5);
    assert_eq!(&output, b"hELlo");
}

#[test]
fn encrypted_truncate_zeroes_plaintext_tail() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);
    encrypt_modern_file_data_block(&mut image, &master_key, &context_bytes);

    {
        let mut volume = must(JournaledVolume::mount(
            SliceBlockDeviceMut::new(&mut image),
            test_mount_context_with_key(master_key.clone()),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut truncate = volume.begin_transaction(NOW);
        let file = transaction_file(&truncate, file_id);
        must(truncate.truncate_file(file, FileSize::from_bytes(3)));
        must(truncate.commit());

        let mut extend = volume.begin_transaction(NOW);
        let file = transaction_file(&extend, file_id);
        must(extend.extend_file(file, FileSize::from_bytes(5)));
        must(extend.commit());
    }

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let mut output = [0_u8; 5];
    assert_eq!(read_file(&volume, 3, 0, &mut output), 5);
    assert_eq!(&output, b"hel\0\0");
}

#[test]
fn verity_file_read_verifies_post_eof_metadata() {
    let image = verity_fixture_image();
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 5];

    assert_eq!(file.protection(), InodeProtection::Verity);
    assert_eq!(
        must(volume.read_file(&file, FileOffset::ZERO, &mut output)).as_usize(),
        5
    );
    assert_eq!(&output, b"hello");
}

#[test]
fn verity_file_read_rejects_corruption() {
    let mut corrupt_data = verity_fixture_image();
    corrupt_data[block_offset(MODERN_FILE_DATA_BLOCK)] ^= 0x80;
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&corrupt_data),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 5];
    assert_eq!(
        volume.read_file(&file, FileOffset::ZERO, &mut output),
        Err(Error::VerityMismatch)
    );

    let mut corrupt_tree = verity_fixture_image();
    corrupt_tree[block_offset(64)] ^= 0x80;
    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&corrupt_tree),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    assert_eq!(
        volume.read_file(&file, FileOffset::ZERO, &mut output),
        Err(Error::VerityMismatch)
    );
}

#[test]
fn enable_verity_commits_metadata_and_remount_verifies() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let read_only_compat = get_u32(&image, 1024 + 100) | RO_COMPAT_VERITY;
    put_u32(&mut image, 1024 + 100, read_only_compat);

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        let file = transaction_file(&transaction, file_id);
        let enable = FsverityEnable::new(
            FsverityHashAlgorithm::Sha256,
            must(FsverityBlockSize::new(
                u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
            )),
            FsveritySalt::empty(),
            FsveritySignature::empty(),
        );

        must(transaction.enable_verity(file, &enable));
        must(transaction.commit());
    }

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 5];

    assert_eq!(file.protection(), InodeProtection::Verity);
    assert_eq!(
        must(volume.read_file(&file, FileOffset::ZERO, &mut output)).as_usize(),
        5
    );
    assert_eq!(&output, b"hello");
}

#[test]
fn encrypted_enable_verity_remount_verifies_after_decrypt() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    let read_only_compat = get_u32(&image, 1024 + 100) | RO_COMPAT_VERITY;
    put_u32(&mut image, 1024 + 100, read_only_compat);
    install_inline_fscrypt_context(&mut image, 3, &context_bytes);
    encrypt_modern_file_data_block(&mut image, &master_key, &context_bytes);

    {
        let mut volume = must(JournaledVolume::mount(
            SliceBlockDeviceMut::new(&mut image),
            test_mount_context_with_key(master_key.clone()),
        ));
        let file_id = file_node_id(&volume, 3);
        let mut transaction = volume.begin_transaction(NOW);
        let file = transaction_file(&transaction, file_id);
        let enable = FsverityEnable::new(
            FsverityHashAlgorithm::Sha256,
            must(FsverityBlockSize::new(
                u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
            )),
            FsveritySalt::empty(),
            FsveritySignature::empty(),
        );

        must(transaction.enable_verity(file, &enable));
        must(transaction.commit());
    }

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let file = file_node(&volume, 3);
    let mut output = [0_u8; 5];

    assert_eq!(file.protection(), InodeProtection::EncryptedVerity);
    assert_eq!(
        must(volume.read_file(&file, FileOffset::ZERO, &mut output)).as_usize(),
        5
    );
    assert_eq!(&output, b"hello");
}

#[test]
fn encrypted_directory_create_requires_mount_key() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let context_bytes = fscrypt_v2_context_bytes();
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);

    let device = SliceBlockDeviceMut::new(&mut image);
    let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"new"));

    assert_eq!(
        transaction.create_file(root, &name, test_file_metadata()),
        Err(Error::MissingEncryptionKey)
    );
}

#[test]
fn encrypted_directory_read_projects_names_when_key_is_present() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);

    let locked = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let locked_entries = read_directory(&locked, InodeId::ROOT);
    let encoded = directory_entry_name(&locked_entries, inode(3));
    assert!(
        locked_entries
            .iter()
            .all(|entry| entry.name().bytes() != b"file")
    );
    assert!(encoded.bytes().starts_with(b"_fscrypt_"));
    assert!(WindowsName::from_ext4(&encoded).is_ok());

    let unlocked = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let entries = read_directory(&unlocked, InodeId::ROOT);
    assert!(entries.iter().any(|entry| entry.name().bytes() == b"file"));
}

#[test]
fn encrypted_directory_windows_lookup_encrypts_requested_name() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));

    assert_eq!(
        lookup_windows_inode(
            &volume,
            InodeId::ROOT,
            &[
                u16::from(b'f'),
                u16::from(b'i'),
                u16::from(b'l'),
                u16::from(b'e'),
            ],
        ),
        Some(inode(3))
    );
}

#[test]
fn encrypted_directory_encoded_lookup_does_not_require_mount_key() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    let encoded = directory_entry_name(&read_directory(&volume, InodeId::ROOT), inode(3));
    let requested: Vec<u16> = encoded.bytes().iter().copied().map(u16::from).collect();

    assert_eq!(
        lookup_windows_inode(&volume, InodeId::ROOT, &requested),
        Some(inode(3))
    );
}

#[test]
fn encrypted_directory_create_encrypts_child_name_when_key_is_present() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);

    {
        let mut volume = must(JournaledVolume::<_, TestFscryptNonceGenerator>::mount(
            SliceBlockDeviceMut::new(&mut image),
            test_mount_context_with_key_and_nonce_source(master_key.clone()),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        let name = must(Ext4Name::new(b"created"));
        let file = must(transaction.create_file(root, &name, test_file_metadata()));
        assert_eq!(file.id().inode(), inode(11));
        must(transaction.commit());
    }

    let directory_block = &image
        [block_offset(MODERN_ROOT_DIR_BLOCK)..block_offset(MODERN_ROOT_DIR_BLOCK) + BLOCK_SIZE];
    assert!(
        !directory_block
            .windows(b"created".len())
            .any(|window| window == b"created")
    );

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let child = node_id(&volume, inode(11));
    let child_context = must(volume.read_fscrypt_context(child));
    assert!(child_context.is_some());
    let Some(child_context) = child_context else {
        return;
    };
    let parent_context = must(FscryptContextV2::parse(&context_bytes));
    assert_eq!(child_context.policy(), parent_context.policy());
    assert_eq!(
        child_context.nonce(),
        FscryptFileNonce::new([TestFscryptNonceGenerator::FIRST_NONCE_BYTE; 16])
    );
    assert_eq!(
        file_node(&volume, 11).protection(),
        InodeProtection::Encrypted
    );
    assert_eq!(
        lookup_windows_inode(
            &volume,
            InodeId::ROOT,
            &[
                u16::from(b'c'),
                u16::from(b'r'),
                u16::from(b'e'),
                u16::from(b'a'),
                u16::from(b't'),
                u16::from(b'e'),
                u16::from(b'd'),
            ],
        ),
        Some(inode(11))
    );
}

#[test]
fn encrypted_directory_create_directory_inherits_child_context_when_key_is_present() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);

    {
        let mut volume = must(JournaledVolume::<_, TestFscryptNonceGenerator>::mount(
            SliceBlockDeviceMut::new(&mut image),
            test_mount_context_with_key_and_nonce_source(master_key.clone()),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        let name = must(Ext4Name::new(b"childdir"));
        let directory = must(transaction.create_directory(root, &name, test_directory_metadata()));
        assert_eq!(directory.id().inode(), inode(11));
        must(transaction.commit());
    }

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    let child = node_id(&volume, inode(11));
    let child_context = must(volume.read_fscrypt_context(child));
    assert!(child_context.is_some());
    let Some(child_context) = child_context else {
        return;
    };
    let parent_context = must(FscryptContextV2::parse(&context_bytes));
    assert_eq!(child_context.policy(), parent_context.policy());
    assert_eq!(
        child_context.nonce(),
        FscryptFileNonce::new([TestFscryptNonceGenerator::FIRST_NONCE_BYTE; 16])
    );
    assert_eq!(
        directory_node(&volume, inode(11)).protection(),
        InodeProtection::Encrypted
    );
    assert_eq!(
        lookup_windows_inode(
            &volume,
            InodeId::ROOT,
            &[
                u16::from(b'c'),
                u16::from(b'h'),
                u16::from(b'i'),
                u16::from(b'l'),
                u16::from(b'd'),
                u16::from(b'd'),
                u16::from(b'i'),
                u16::from(b'r'),
            ],
        ),
        Some(inode(11))
    );
}

#[test]
fn encrypted_directory_create_symlink_rejects_plaintext_target() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);

    let mut volume = must(JournaledVolume::<_, TestFscryptNonceGenerator>::mount(
        SliceBlockDeviceMut::new(&mut image),
        test_mount_context_with_key_and_nonce_source(master_key),
    ));
    let mut transaction = volume.begin_transaction(NOW);
    let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
    let name = must(Ext4Name::new(b"link"));
    let target = must(SymlinkTarget::new(b"target"));

    assert_eq!(
        transaction.create_symlink(root, &name, &target, test_symlink_metadata()),
        Err(Error::UnsupportedEncryption)
    );
}

#[test]
fn encrypted_directory_rename_encrypts_target_name_when_key_is_present() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);

    {
        let mut volume = must(JournaledVolume::mount(
            SliceBlockDeviceMut::new(&mut image),
            test_mount_context_with_key(master_key.clone()),
        ));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        let old_name = must(Ext4Name::new(b"file"));
        let new_name = must(Ext4Name::new(b"renamed"));
        must(transaction.rename_child(root, &old_name, root, &new_name));
        must(transaction.commit());
    }

    let directory_block = &image
        [block_offset(MODERN_ROOT_DIR_BLOCK)..block_offset(MODERN_ROOT_DIR_BLOCK) + BLOCK_SIZE];
    assert!(
        !directory_block
            .windows(b"renamed".len())
            .any(|window| window == b"renamed")
    );

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context_with_key(master_key),
    ));
    assert_eq!(
        lookup_windows_inode(
            &volume,
            InodeId::ROOT,
            &[
                u16::from(b'r'),
                u16::from(b'e'),
                u16::from(b'n'),
                u16::from(b'a'),
                u16::from(b'm'),
                u16::from(b'e'),
                u16::from(b'd'),
            ],
        ),
        Some(inode(3))
    );
}

#[test]
fn encrypted_directory_encoded_delete_does_not_require_mount_key() {
    let mut image = modern_fixture_image_with_journal_blocks(16);
    let master_key = must(FscryptMasterKey::from_raw(&[0x7B; 32]));
    let context_bytes = fscrypt_v2_context_bytes_with_identifier(master_key.identifier().bytes());
    install_inline_fscrypt_context(&mut image, 2, &context_bytes);
    encrypt_modern_root_file_name(&mut image, &master_key, &context_bytes);
    put_u16(&mut image, modern_inode_offset(3) + 26, 1);

    let encoded = {
        let volume = must(ReadOnlyVolume::mount(
            SliceBlockDevice::new(&image),
            test_mount_context(),
        ));
        directory_entry_name(&read_directory(&volume, InodeId::ROOT), inode(3))
    };

    {
        let device = SliceBlockDeviceMut::new(&mut image);
        let mut volume = must(JournaledVolume::mount(device, test_mount_context()));
        let mut transaction = volume.begin_transaction(NOW);
        let root = transaction_directory(&transaction, crate::DirectoryNodeId::ROOT);
        must(transaction.unlink_file(root, &encoded));
        must(transaction.commit());
    }

    let volume = must(ReadOnlyVolume::mount(
        SliceBlockDevice::new(&image),
        test_mount_context(),
    ));
    assert!(
        !read_directory(&volume, InodeId::ROOT)
            .iter()
            .any(|entry| entry.name() == &encoded)
    );
}
