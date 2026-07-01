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

use crate::disk::block::{
    BlockAddress, BlockReader, BlockSize, BlockWriter, ByteOffset, DeviceLength, SliceBlockDevice,
    SliceBlockDeviceMut,
};
use crate::disk_format::dir::{DirectoryEntry as RawDirectoryEntry, DirectoryEntryKind};
use crate::disk_format::extent::{
    BlockMapping, Extent, ExtentLength, ExtentTree, ExtentTreeContext, LogicalBlock,
    MutableExtentTree,
};
use crate::disk_format::inode::{InodeExtentRoot, InodeId, InodeProtection};
use crate::disk_format::superblock::{BlockGroupId, JournalMode, Superblock};
use crate::disk_format::xattr::{self as xattr_storage, InodeXattrSet};
use crate::{
    DirectoryEntry, DirectoryNode, DirectoryNodeId, Error, Ext4Gid, Ext4Name, Ext4Owner,
    Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp, Ext4Uid, Ext4VerityMetadataLayout,
    Ext4VolumeLabel, Ext4WindowsAttributes, ExternalJournal, FSVERITY_DESCRIPTOR_BYTES, FileNode,
    FileNodeId, FileOffset, FileSize, FscryptContextV2, FscryptFileNonce, FscryptKeySet,
    FscryptMasterKey, FscryptNoNonceGenerator, FscryptNonceGenerator, FsverityBlockSize,
    FsverityDescriptor, FsverityEnable, FsverityHashAlgorithm, FsverityMerkleTree, FsveritySalt,
    FsveritySignature, InternalJournal, JournalTransaction, JournaledVolume, MountContext,
    NewDirectoryMetadata, NewFileMetadata, NewSymlinkMetadata, NodeId, PosixAcl, PosixAclEntry,
    PosixAclKind, ReadOnlyVolume, SymlinkNode, SymlinkTarget, TransactionDirectory,
    TransactionFile, WindowsName, WindowsOverlay, XattrName, XattrNamespace, XattrSet, XattrValue,
};

const BLOCK_SIZE: usize = 1024;
const IMAGE_BLOCKS: usize = 16;
const INODE_TABLE_BLOCK: u32 = 5;
const ROOT_DIR_BLOCK: u32 = 8;
const FILE_DATA_BLOCK: u32 = 9;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
const EXT4_INDEX_FL: u32 = 0x0000_1000;
const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
const EXT4_VERITY_FL: u32 = 0x0010_0000;
const MODERN_IMAGE_BLOCKS: usize = 64;
const MODERN_INODE_SIZE: usize = 256;
const MODERN_BLOCK_BITMAP_BLOCK: u32 = 3;
const MODERN_INODE_BITMAP_BLOCK: u32 = 4;
const MODERN_INODE_TABLE_BLOCK: u32 = 5;
const MODERN_ROOT_DIR_BLOCK: u32 = 12;
const MODERN_FILE_DATA_BLOCK: u32 = 13;
const MODERN_EXTENT_INDEX_BLOCK: u32 = 14;
const MODERN_JOURNAL_BLOCK: u32 = 20;
const BIGALLOC_BLOCKS_PER_CLUSTER: u32 = 4;
const BIGALLOC_LOG_CLUSTER_SIZE: u32 = 2;
const COMPAT_HAS_JOURNAL: u32 = 0x0004;
const COMPAT_EXT_ATTR: u32 = 0x0008;
const COMPAT_RESIZE_INODE: u32 = 0x0010;
const COMPAT_DIR_INDEX: u32 = 0x0020;
const COMPAT_FAST_COMMIT: u32 = 0x0400;
const COMPAT_MODERN: u32 =
    COMPAT_HAS_JOURNAL | COMPAT_EXT_ATTR | COMPAT_RESIZE_INODE | COMPAT_DIR_INDEX;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_RECOVER: u32 = 0x0004;
const INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_MMP: u32 = 0x0100;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_EA_INODE: u32 = 0x0400;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_LARGEDIR: u32 = 0x4000;
const INCOMPAT_INLINE_DATA: u32 = 0x8000;
const INCOMPAT_ENCRYPT: u32 = 0x0001_0000;
const INCOMPAT_CASEFOLD: u32 = 0x0002_0000;
const INCOMPAT_MODERN: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
const RO_COMPAT_QUOTA: u32 = 0x0100;
const RO_COMPAT_BIGALLOC: u32 = 0x0200;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const RO_COMPAT_READONLY: u32 = 0x1000;
const RO_COMPAT_PROJECT: u32 = 0x2000;
const RO_COMPAT_VERITY: u32 = 0x8000;
const RO_COMPAT_ORPHAN_PRESENT: u32 = 0x0001_0000;
const RO_COMPAT_MODERN: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;
const NOW: Ext4Timestamp = Ext4Timestamp::from_unix_seconds(1_700_000_000);
const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE_BLOCK: u32 = 5;
const JBD2_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
const JBD2_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
const JBD2_TAG_FLAG_ESCAPE: u32 = 0x0001;
const JBD2_TAG_FLAG_SAME_UUID: u32 = 0x0002;
const JBD2_TAG_FLAG_LAST_TAG: u32 = 0x0008;
const JBD2_CHECKSUM_CRC32C: u8 = 4;
const COMPAT_ORPHAN_FILE: u32 = 0x1000;
const EXTERNAL_JOURNAL_SUPERBLOCK_OFFSET: usize = 2048;

fn inode(value: u32) -> InodeId {
    must(InodeId::try_from(value))
}

trait MountedVolumeTestExt {
    fn load_file(&self, id: FileNodeId) -> crate::Result<FileNode>;
    fn load_directory(&self, id: DirectoryNodeId) -> crate::Result<DirectoryNode>;
    fn load_symlink(&self, id: crate::SymlinkNodeId) -> crate::Result<SymlinkNode>;
    fn read_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> crate::Result<crate::ReadBytes>;
    fn read_directory(&self, directory: &DirectoryNode) -> crate::Result<Vec<DirectoryEntry>>;
    fn read_symlink(&self, symlink: &SymlinkNode) -> crate::Result<Vec<u8>>;
    fn lookup_child(
        &self,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> crate::Result<crate::ChildLookup>;
    fn lookup_windows_child(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> crate::Result<crate::ChildLookup>;
}

impl<D: BlockReader, N> MountedVolumeTestExt for ReadOnlyVolume<D, N> {
    fn load_file(&self, id: FileNodeId) -> crate::Result<FileNode> {
        Self::load_file(self, id)
    }

    fn load_directory(&self, id: DirectoryNodeId) -> crate::Result<DirectoryNode> {
        Self::load_directory(self, id)
    }

    fn load_symlink(&self, id: crate::SymlinkNodeId) -> crate::Result<SymlinkNode> {
        Self::load_symlink(self, id)
    }

    fn read_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> crate::Result<crate::ReadBytes> {
        Self::read_file(self, file, offset, out)
    }

    fn read_directory(&self, directory: &DirectoryNode) -> crate::Result<Vec<DirectoryEntry>> {
        Self::read_directory(self, directory)
    }

    fn read_symlink(&self, symlink: &SymlinkNode) -> crate::Result<Vec<u8>> {
        Self::read_symlink(self, symlink)
    }

    fn lookup_child(
        &self,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> crate::Result<crate::ChildLookup> {
        Self::lookup_child(self, parent, name)
    }

    fn lookup_windows_child(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> crate::Result<crate::ChildLookup> {
        Self::lookup_windows_child(self, parent, requested)
    }
}

impl<D: BlockReader, J, N> MountedVolumeTestExt for JournaledVolume<D, J, N> {
    fn load_file(&self, id: FileNodeId) -> crate::Result<FileNode> {
        Self::load_file(self, id)
    }

    fn load_directory(&self, id: DirectoryNodeId) -> crate::Result<DirectoryNode> {
        Self::load_directory(self, id)
    }

    fn load_symlink(&self, id: crate::SymlinkNodeId) -> crate::Result<SymlinkNode> {
        Self::load_symlink(self, id)
    }

    fn read_file(
        &self,
        file: &FileNode,
        offset: FileOffset,
        out: &mut [u8],
    ) -> crate::Result<crate::ReadBytes> {
        Self::read_file(self, file, offset, out)
    }

    fn read_directory(&self, directory: &DirectoryNode) -> crate::Result<Vec<DirectoryEntry>> {
        Self::read_directory(self, directory)
    }

    fn read_symlink(&self, symlink: &SymlinkNode) -> crate::Result<Vec<u8>> {
        Self::read_symlink(self, symlink)
    }

    fn lookup_child(
        &self,
        parent: &DirectoryNode,
        name: &Ext4Name,
    ) -> crate::Result<crate::ChildLookup> {
        Self::lookup_child(self, parent, name)
    }

    fn lookup_windows_child(
        &self,
        parent: &DirectoryNode,
        requested: &WindowsName,
    ) -> crate::Result<crate::ChildLookup> {
        Self::lookup_windows_child(self, parent, requested)
    }
}

fn node_id<V: MountedVolumeTestExt>(volume: &V, inode_id: InodeId) -> NodeId {
    if inode_id == InodeId::ROOT {
        return NodeId::Directory(DirectoryNodeId::ROOT);
    }

    let mut pending = vec![DirectoryNodeId::ROOT];
    let mut visited = Vec::new();
    while let Some(directory_id) = pending.pop() {
        if visited
            .iter()
            .any(|visited| *visited == directory_id.inode())
        {
            continue;
        }
        visited.push(directory_id.inode());
        let directory = must(volume.load_directory(directory_id));
        for entry in must(volume.read_directory(&directory)) {
            if entry.node().inode() == inode_id {
                return *entry.node();
            }
            let NodeId::Directory(child_id) = *entry.node() else {
                continue;
            };
            if matches!(entry.name().bytes(), b"." | b"..") {
                continue;
            }
            pending.push(child_id);
        }
    }
    panic!("expected reachable node");
}

fn file_node<V: MountedVolumeTestExt>(volume: &V, inode_id: u32) -> FileNode {
    let NodeId::File(file_id) = node_id(volume, inode(inode_id)) else {
        panic!("expected file node");
    };
    must(volume.load_file(file_id))
}

fn file_node_id<V: MountedVolumeTestExt>(volume: &V, inode_id: u32) -> FileNodeId {
    file_node(volume, inode_id).id()
}

fn directory_node<V: MountedVolumeTestExt>(volume: &V, inode_id: InodeId) -> DirectoryNode {
    let NodeId::Directory(directory_id) = node_id(volume, inode_id) else {
        panic!("expected directory node");
    };
    must(volume.load_directory(directory_id))
}

fn symlink_node<V: MountedVolumeTestExt>(volume: &V, inode_id: u32) -> SymlinkNode {
    let NodeId::Symlink(symlink_id) = node_id(volume, inode(inode_id)) else {
        panic!("expected symlink node");
    };
    must(volume.load_symlink(symlink_id))
}

fn read_file<V: MountedVolumeTestExt>(
    volume: &V,
    inode_id: u32,
    offset: u64,
    out: &mut [u8],
) -> usize {
    let file = file_node(volume, inode_id);
    must(volume.read_file(&file, FileOffset::from_bytes(offset), out)).as_usize()
}

fn read_directory<V: MountedVolumeTestExt>(volume: &V, inode_id: InodeId) -> Vec<DirectoryEntry> {
    let directory = directory_node(volume, inode_id);
    must(volume.read_directory(&directory))
}

fn directory_entry_name(entries: &[DirectoryEntry], inode_id: InodeId) -> Ext4Name {
    for entry in entries {
        if entry.node().inode() == inode_id {
            return entry.name().clone();
        }
    }
    panic!("expected directory entry");
}

fn read_symlink<V: MountedVolumeTestExt>(volume: &V, inode_id: u32) -> Vec<u8> {
    let symlink = symlink_node(volume, inode_id);
    must(volume.read_symlink(&symlink))
}

fn lookup_ext4<V: MountedVolumeTestExt>(
    volume: &V,
    parent: InodeId,
    name: &[u8],
) -> crate::ChildLookup {
    let directory = directory_node(volume, parent);
    let name = must(Ext4Name::new(name));
    must(volume.lookup_child(&directory, &name))
}

fn lookup_windows<V: MountedVolumeTestExt>(
    volume: &V,
    parent: InodeId,
    name: &[u16],
) -> crate::ChildLookup {
    let directory = directory_node(volume, parent);
    let name = must(WindowsName::from_utf16(name));
    must(volume.lookup_windows_child(&directory, &name))
}

fn lookup_ext4_inode<V: MountedVolumeTestExt>(
    volume: &V,
    parent: InodeId,
    name: &[u8],
) -> Option<InodeId> {
    match lookup_ext4(volume, parent, name) {
        crate::ChildLookup::Found(child) => Some(child.node().inode()),
        crate::ChildLookup::NotFound => None,
    }
}

fn lookup_windows_inode<V: MountedVolumeTestExt>(
    volume: &V,
    parent: InodeId,
    name: &[u16],
) -> Option<InodeId> {
    match lookup_windows(volume, parent, name) {
        crate::ChildLookup::Found(child) => Some(child.node().inode()),
        crate::ChildLookup::NotFound => None,
    }
}

fn transaction_file<D: BlockWriter, J, N: FscryptNonceGenerator>(
    transaction: &JournalTransaction<'_, D, J, N>,
    file_id: FileNodeId,
) -> TransactionFile {
    must(transaction.file(file_id))
}

fn transaction_directory<D: BlockWriter, J, N: FscryptNonceGenerator>(
    transaction: &JournalTransaction<'_, D, J, N>,
    directory_id: DirectoryNodeId,
) -> TransactionDirectory {
    must(transaction.directory(directory_id))
}

fn transaction_node<D: BlockWriter, J, N: FscryptNonceGenerator>(
    transaction: &JournalTransaction<'_, D, J, N>,
    id: NodeId,
) -> crate::TransactionNode {
    must(transaction.node(id))
}

fn test_owner() -> Ext4Owner {
    Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000))
}

fn test_file_metadata() -> NewFileMetadata {
    NewFileMetadata::new(test_owner(), must(Ext4Permissions::new(0o644)))
}

fn test_directory_metadata() -> NewDirectoryMetadata {
    NewDirectoryMetadata::new(test_owner(), must(Ext4Permissions::new(0o755)))
}

fn test_symlink_metadata() -> NewSymlinkMetadata {
    NewSymlinkMetadata::new(test_owner(), must(Ext4Permissions::new(0o777)))
}

fn test_mount_context() -> MountContext {
    MountContext::new(FscryptKeySet::empty(), FscryptNoNonceGenerator)
}

fn test_mount_context_with_key(master_key: FscryptMasterKey) -> MountContext {
    MountContext::new(
        must(FscryptKeySet::from_keys(vec![master_key])),
        FscryptNoNonceGenerator,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestFscryptNonceGenerator {
    next: u8,
}

impl TestFscryptNonceGenerator {
    const FIRST_NONCE_BYTE: u8 = 0xA5;

    const fn new() -> Self {
        Self {
            next: Self::FIRST_NONCE_BYTE,
        }
    }
}

impl FscryptNonceGenerator for TestFscryptNonceGenerator {
    fn next_file_nonce(&mut self) -> crate::Result<FscryptFileNonce> {
        let mut nonce = [0_u8; 16];
        nonce.fill(self.next);
        self.next = self.next.wrapping_add(1);
        Ok(FscryptFileNonce::new(nonce))
    }
}

fn test_mount_context_with_key_and_nonce_source(
    master_key: FscryptMasterKey,
) -> MountContext<TestFscryptNonceGenerator> {
    MountContext::new(
        must(FscryptKeySet::from_keys(vec![master_key])),
        TestFscryptNonceGenerator::new(),
    )
}

fn fscrypt_v2_context_bytes() -> [u8; 40] {
    fscrypt_v2_context_bytes_with_identifier([0x11; 16])
}

fn fscrypt_v2_context_bytes_with_identifier(identifier: [u8; 16]) -> [u8; 40] {
    let mut bytes = [0_u8; 40];
    bytes[0] = 2;
    bytes[1] = 1;
    bytes[2] = 4;
    bytes[8..24].copy_from_slice(&identifier);
    bytes[24..40].fill(0x22);
    bytes
}

fn install_inline_fscrypt_context(image: &mut [u8], inode_value: u32, context: &[u8]) {
    let inode_offset = modern_inode_offset(inode_value);
    let incompat = get_u32(image, 1024 + 96) | INCOMPAT_ENCRYPT;
    let flags = get_u32(image, inode_offset + 32) | EXT4_ENCRYPT_FL;
    put_u32(image, 1024 + 96, incompat);
    put_u32(image, inode_offset + 32, flags);
    put_u16(image, inode_offset + 128, 32);
    let xattrs = InodeXattrSet::from_parts(XattrSet::empty(), Some(must(XattrValue::new(context))));
    let body_offset = inode_offset + 160;
    let body_capacity = MODERN_INODE_SIZE - 160;
    let bytes = must(xattr_storage::serialize_inline_xattrs(
        &xattrs,
        body_capacity,
    ));
    image[body_offset..body_offset + bytes.len()].copy_from_slice(&bytes);
}

fn encrypt_modern_file_data_block(image: &mut [u8], master_key: &FscryptMasterKey, context: &[u8]) {
    let context = must(FscryptContextV2::parse(context));
    let key = must(master_key.derive_contents_key(context.nonce()));
    let offset = block_offset(MODERN_FILE_DATA_BLOCK);
    must(key.encrypt_block(0, &mut image[offset..offset + BLOCK_SIZE]));
}

fn encrypt_modern_root_file_name(image: &mut [u8], master_key: &FscryptMasterKey, context: &[u8]) {
    let context = must(FscryptContextV2::parse(context));
    let key = must(master_key.derive_filenames_key(context.nonce()));
    let ciphertext = must(key.encrypt_filename(b"file", context.policy().filename_padding()));
    write_dirent(
        image,
        block_offset(MODERN_ROOT_DIR_BLOCK) + 24,
        3,
        1000,
        &ciphertext,
        1,
    );
}

fn overwrite_file<D: BlockWriter, J, N: FscryptNonceGenerator>(
    transaction: &mut JournalTransaction<'_, D, J, N>,
    file_id: FileNodeId,
    offset: u64,
    bytes: &[u8],
) {
    let file = transaction_file(transaction, file_id);
    must(transaction.overwrite_file_range(file, FileOffset::from_bytes(offset), bytes));
}

fn extend_file<D: BlockWriter, J, N: FscryptNonceGenerator>(
    transaction: &mut JournalTransaction<'_, D, J, N>,
    file_id: FileNodeId,
    new_size: u64,
) {
    let file = transaction_file(transaction, file_id);
    must(transaction.extend_file(file, FileSize::from_bytes(new_size)));
}

fn truncate_file<D: BlockWriter, J, N: FscryptNonceGenerator>(
    transaction: &mut JournalTransaction<'_, D, J, N>,
    file_id: FileNodeId,
    new_size: u64,
) {
    let file = transaction_file(transaction, file_id);
    must(transaction.truncate_file(file, FileSize::from_bytes(new_size)));
}
mod bigalloc;
mod fixtures;
mod journal;
mod mount;
mod namespace;
mod protection;
mod read_write;
mod xattr_acl;

use fixtures::*;
