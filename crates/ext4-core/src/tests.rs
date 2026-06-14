#![expect(
    clippy::arithmetic_side_effects,
    reason = "fixture builder writes fixed ext4 structure offsets"
)]
#![expect(
    clippy::indexing_slicing,
    reason = "fixture builder asserts exact in-memory image layout"
)]
#![expect(
    clippy::panic,
    reason = "unit tests fail through panic on unexpected errors"
)]

use alloc::{vec, vec::Vec};

use crate::{
    CleanSuperblock, DirectoryEntryKind, Error, InodeId, MountedVolume, SliceBlockDevice,
    WindowsName,
};

const BLOCK_SIZE: usize = 1024;
const IMAGE_BLOCKS: usize = 16;
const INODE_TABLE_BLOCK: u32 = 5;
const ROOT_DIR_BLOCK: u32 = 8;
const FILE_DATA_BLOCK: u32 = 9;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

#[test]
fn clean_superblock_mounts() {
    let image = fixture_image();
    let device = SliceBlockDevice::new(&image);
    let volume = must(MountedVolume::mount(device));

    assert_eq!(volume.superblock().block_size().bytes(), 1024);
    assert_eq!(volume.superblock().inode_count(), 16);
}

#[test]
fn invalid_magic_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 56, 0);
    let result = CleanSuperblock::parse(&image[1024..2048]);

    assert_eq!(result, Err(Error::InvalidMagic));
}

#[test]
fn dirty_volume_is_rejected() {
    let mut image = fixture_image();
    put_u16(&mut image, 1024 + 58, 0);
    let result = MountedVolume::mount(SliceBlockDevice::new(&image));

    assert!(matches!(result, Err(Error::DirtyVolume)));
}

#[test]
fn unsupported_incompat_feature_is_rejected() {
    let mut image = fixture_image();
    put_u32(&mut image, 1024 + 96, 0x0080);
    let result = MountedVolume::mount(SliceBlockDevice::new(&image));

    assert!(matches!(result, Err(Error::UnsupportedIncompatFeature)));
}

#[test]
fn directory_entries_are_parsed_from_root_inode() {
    let image = fixture_image();
    let volume = must(MountedVolume::mount(SliceBlockDevice::new(&image)));
    let entries = must(volume.read_directory(InodeId::ROOT));

    assert_eq!(entries.len(), 4);
    assert_eq!(entries[2].name().bytes(), b"file");
    assert_eq!(entries[2].kind(), DirectoryEntryKind::File);
    assert_eq!(entries[3].name().bytes(), b"link");
    assert_eq!(entries[3].kind(), DirectoryEntryKind::Symlink);
}

#[test]
fn sparse_file_reads_zeroes_for_holes() {
    let image = fixture_image();
    let volume = must(MountedVolume::mount(SliceBlockDevice::new(&image)));
    let mut output = vec![0xAA; 1030];
    let read = must(volume.read_file(InodeId::new(3), 0, &mut output));

    assert_eq!(read, 1030);
    assert!(output[..1024].iter().all(|byte| *byte == 0));
    assert_eq!(&output[1024..1029], b"hello");
    assert_eq!(output[1029], 0);
}

#[test]
fn symlink_inline_target_is_read_without_extents() {
    let image = fixture_image();
    let volume = must(MountedVolume::mount(SliceBlockDevice::new(&image)));
    let target = must(volume.read_symlink(InodeId::new(4)));

    assert_eq!(target, b"file");
}

#[test]
fn exact_ext4_lookup_uses_raw_bytes() {
    let image = fixture_image();
    let volume = must(MountedVolume::mount(SliceBlockDevice::new(&image)));
    let child = must(volume.lookup_child(InodeId::ROOT, b"file"));

    assert_eq!(child, Some(InodeId::new(3)));
}

#[test]
fn windows_name_projection_rejects_reserved_separator() {
    let ext4_name = must(crate::Ext4Name::new(b"a:b"));
    let result = WindowsName::from_ext4(&ext4_name);

    assert!(matches!(result, Err(Error::InvalidName)));
}

#[test]
fn windows_lookup_accepts_unique_ascii_case_fold() {
    let image = fixture_image();
    let volume = must(MountedVolume::mount(SliceBlockDevice::new(&image)));
    let child = must(volume.lookup_windows_child(InodeId::ROOT, &[0x0046, 0x0049, 0x004C, 0x0045]));

    assert_eq!(child, Some(InodeId::new(3)));
}

fn fixture_image() -> Vec<u8> {
    let mut image = vec![0_u8; BLOCK_SIZE * IMAGE_BLOCKS];
    write_superblock(&mut image);
    write_block_group_descriptor(&mut image);
    write_root_inode(&mut image);
    write_file_inode(&mut image);
    write_symlink_inode(&mut image);
    write_root_directory(&mut image);
    let file_data_offset = block_offset(FILE_DATA_BLOCK);
    image[file_data_offset..file_data_offset + 5].copy_from_slice(b"hello");
    image
}

fn write_superblock(image: &mut [u8]) {
    let base = 1024;
    put_u32(image, base, 16);
    put_u32(
        image,
        base + 4,
        u32::try_from(IMAGE_BLOCKS).unwrap_or(u32::MAX),
    );
    put_u32(image, base + 20, 1);
    put_u32(image, base + 24, 0);
    put_u32(image, base + 32, 8192);
    put_u32(image, base + 40, 16);
    put_u16(image, base + 56, 0xEF53);
    put_u16(image, base + 58, 1);
    put_u32(image, base + 76, 1);
    put_u32(image, base + 84, 11);
    put_u16(image, base + 88, 128);
    put_u32(image, base + 96, 0x0002 | 0x0040);
    put_u32(image, base + 100, 0x0001 | 0x0002);
}

fn write_block_group_descriptor(image: &mut [u8]) {
    put_u32(image, block_offset(2) + 8, INODE_TABLE_BLOCK);
}

fn write_root_inode(image: &mut [u8]) {
    let offset = inode_offset(2);
    put_u16(image, offset, 0x4000 | 0o755);
    put_u32(
        image,
        offset + 4,
        u32::try_from(BLOCK_SIZE).unwrap_or(u32::MAX),
    );
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 0, 1, ROOT_DIR_BLOCK);
}

fn write_file_inode(image: &mut [u8]) {
    let offset = inode_offset(3);
    put_u16(image, offset, 0x8000 | 0o444);
    put_u32(image, offset + 4, 2048);
    put_u32(image, offset + 32, EXT4_EXTENTS_FL);
    write_extent_root(image, offset + 40, 1, 1, FILE_DATA_BLOCK);
}

fn write_symlink_inode(image: &mut [u8]) {
    let offset = inode_offset(4);
    put_u16(image, offset, 0xA000 | 0o777);
    put_u32(image, offset + 4, 4);
    image[offset + 40..offset + 44].copy_from_slice(b"file");
}

fn write_root_directory(image: &mut [u8]) {
    let base = block_offset(ROOT_DIR_BLOCK);
    write_dirent(image, base, 2, 12, b".", 2);
    write_dirent(image, base + 12, 2, 12, b"..", 2);
    write_dirent(image, base + 24, 3, 16, b"file", 1);
    write_dirent(image, base + 40, 4, 984, b"link", 7);
}

fn write_extent_root(
    image: &mut [u8],
    offset: usize,
    logical_start: u32,
    len: u16,
    physical_start: u32,
) {
    put_u16(image, offset, 0xF30A);
    put_u16(image, offset + 2, 1);
    put_u16(image, offset + 4, 4);
    put_u16(image, offset + 6, 0);
    put_u32(image, offset + 12, logical_start);
    put_u16(image, offset + 16, len);
    put_u16(image, offset + 18, 0);
    put_u32(image, offset + 20, physical_start);
}

fn write_dirent(
    image: &mut [u8],
    offset: usize,
    inode: u32,
    rec_len: u16,
    name: &[u8],
    file_type: u8,
) {
    put_u32(image, offset, inode);
    put_u16(image, offset + 4, rec_len);
    image[offset + 6] = u8::try_from(name.len()).unwrap_or(u8::MAX);
    image[offset + 7] = file_type;
    image[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
}

fn inode_offset(inode: u32) -> usize {
    block_offset(INODE_TABLE_BLOCK) + usize::try_from(inode - 1).unwrap_or(usize::MAX) * 128
}

fn block_offset(block: u32) -> usize {
    usize::try_from(block).unwrap_or(usize::MAX) * BLOCK_SIZE
}

fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn must<T>(result: crate::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected ext4-core error: {error:?}"),
    }
}
