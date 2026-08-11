//! Typed mounted inode identities and loaded node projections.

use alloc::vec::Vec;

use crate::disk_format::dir::DirectoryEntryKind;
use crate::disk_format::inode::{
    Ext4LinkCount, Ext4Security, Ext4Times, FileAllocationSize, FileSize, Inode, InodeId,
    InodeKind, InodeProtection,
};
use crate::error::{Error, Result};
use crate::platform::name::Ext4Name;

/// Typed regular-file inode identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileNodeId {
    /// Backing ext4 inode.
    inode: InodeId,
}

impl FileNodeId {
    /// Creates a typed regular-file identity from an inode validated as a file.
    pub(super) const fn new(inode: InodeId) -> Self {
        Self { inode }
    }

    /// Returns the raw inode for on-disk and external boundary encoding.
    #[must_use]
    pub(crate) const fn inode(self) -> InodeId {
        self.inode
    }
}

/// Typed directory inode identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DirectoryNodeId {
    /// Backing ext4 inode.
    inode: InodeId,
}

impl DirectoryNodeId {
    /// Root directory identity.
    pub const ROOT: Self = Self {
        inode: InodeId::ROOT,
    };

    /// Creates a typed directory identity from an inode validated as a directory.
    pub(super) const fn new(inode: InodeId) -> Self {
        Self { inode }
    }

    /// Returns the raw inode for on-disk and external boundary encoding.
    #[must_use]
    pub(crate) const fn inode(self) -> InodeId {
        self.inode
    }
}

/// Typed symbolic-link inode identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SymlinkNodeId {
    /// Backing ext4 inode.
    inode: InodeId,
}

impl SymlinkNodeId {
    /// Creates a typed symbolic-link identity from an inode validated as a symlink.
    pub(super) const fn new(inode: InodeId) -> Self {
        Self { inode }
    }

    /// Returns the raw inode for on-disk and external boundary encoding.
    #[must_use]
    pub(crate) const fn inode(self) -> InodeId {
        self.inode
    }
}

/// Typed inode identity for any node kind supported by this domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeId {
    /// Regular file node.
    File(FileNodeId),
    /// Directory node.
    Directory(DirectoryNodeId),
    /// Symbolic link node.
    Symlink(SymlinkNodeId),
}

impl NodeId {
    /// Returns the raw inode for on-disk and external boundary encoding.
    #[must_use]
    pub(crate) const fn inode(&self) -> InodeId {
        match self {
            Self::File(file) => file.inode(),
            Self::Directory(directory) => directory.inode(),
            Self::Symlink(symlink) => symlink.inode(),
        }
    }

    /// Stable file index exposed to the Windows file-information boundary.
    #[must_use]
    pub const fn file_index(self) -> u32 {
        self.inode().as_u32()
    }
}

/// Typed identity of an inode that can own hard-link names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HardLinkNodeId {
    /// Regular file inode.
    File(FileNodeId),
    /// Symbolic-link inode.
    Symlink(SymlinkNodeId),
}

impl HardLinkNodeId {
    /// Returns the raw inode for volume-internal traversal and mutation.
    pub(super) const fn inode(self) -> InodeId {
        match self {
            Self::File(file) => file.inode(),
            Self::Symlink(symlink) => symlink.inode(),
        }
    }

    /// Returns the directory-entry kind used by every link to this inode.
    pub(super) const fn entry_kind(self) -> DirectoryEntryKind {
        match self {
            Self::File(_) => DirectoryEntryKind::File,
            Self::Symlink(_) => DirectoryEntryKind::Symlink,
        }
    }
}

impl TryFrom<NodeId> for HardLinkNodeId {
    type Error = Error;

    fn try_from(value: NodeId) -> Result<Self> {
        match value {
            NodeId::File(file) => Ok(Self::File(file)),
            NodeId::Symlink(symlink) => Ok(Self::Symlink(symlink)),
            NodeId::Directory(_) => Err(Error::WrongInodeKind),
        }
    }
}

impl From<HardLinkNodeId> for NodeId {
    fn from(value: HardLinkNodeId) -> Self {
        match value {
            HardLinkNodeId::File(file) => Self::File(file),
            HardLinkNodeId::Symlink(symlink) => Self::Symlink(symlink),
        }
    }
}

/// Typed node loaded from an inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LoadedNode {
    /// Regular file node.
    File(FileNode),
    /// Directory node.
    Directory(DirectoryNode),
    /// Symbolic link node.
    Symlink(SymlinkNode),
}

impl LoadedNode {
    /// Wraps a parsed inode in the loaded node type selected by its inode kind.
    pub(super) fn from_inode(inode: Inode) -> Self {
        match inode.kind() {
            InodeKind::File => Self::File(FileNode { inode }),
            InodeKind::Directory => Self::Directory(DirectoryNode { inode }),
            InodeKind::Symlink => Self::Symlink(SymlinkNode { inode }),
        }
    }

    /// Returns this loaded node's typed identity.
    #[must_use]
    pub(super) const fn id(&self) -> NodeId {
        match self {
            Self::File(file) => NodeId::File(file.id()),
            Self::Directory(directory) => NodeId::Directory(directory.id()),
            Self::Symlink(symlink) => NodeId::Symlink(symlink.id()),
        }
    }
}

/// Typed regular file node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileNode {
    /// Parsed inode backing this typed file node.
    inode: Inode,
}

impl FileNode {
    /// Inode identifier backing this file node.
    #[must_use]
    pub const fn id(&self) -> FileNodeId {
        FileNodeId::new(self.inode.id())
    }

    /// File size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.inode.size()
    }

    /// Allocation charge parsed from the file inode.
    #[must_use]
    pub const fn allocation_size(&self) -> FileAllocationSize {
        self.inode.allocation_size()
    }

    /// POSIX security state parsed from the file inode.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.inode.security()
    }

    /// ext4 timestamps parsed from the file inode.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.inode.times()
    }

    /// Link count parsed from the file inode.
    #[must_use]
    pub const fn links_count(&self) -> Ext4LinkCount {
        self.inode.links_count()
    }

    /// Contents protection selected by file inode flags.
    #[must_use]
    pub(crate) const fn protection(&self) -> InodeProtection {
        self.inode.protection()
    }

    /// Returns the backing inode for volume-internal operations.
    pub(super) fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Typed directory node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryNode {
    /// Parsed inode backing this typed directory node.
    inode: Inode,
}

impl DirectoryNode {
    /// Inode identifier backing this directory node.
    #[must_use]
    pub const fn id(&self) -> DirectoryNodeId {
        DirectoryNodeId::new(self.inode.id())
    }

    /// POSIX security state parsed from the directory inode.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.inode.security()
    }

    /// Directory payload size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.inode.size()
    }

    /// Allocation charge parsed from the directory inode.
    #[must_use]
    pub const fn allocation_size(&self) -> FileAllocationSize {
        self.inode.allocation_size()
    }

    /// ext4 timestamps parsed from the directory inode.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.inode.times()
    }

    /// Link count parsed from the directory inode.
    #[must_use]
    pub const fn links_count(&self) -> Ext4LinkCount {
        self.inode.links_count()
    }

    /// Contents protection selected by directory inode flags.
    #[must_use]
    pub(crate) const fn protection(&self) -> InodeProtection {
        self.inode.protection()
    }

    /// Returns the backing inode for volume-internal operations.
    pub(super) fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Typed symbolic link node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymlinkNode {
    /// Parsed inode backing this typed symlink node.
    inode: Inode,
}

impl SymlinkNode {
    /// Inode identifier backing this symbolic link node.
    #[must_use]
    pub const fn id(&self) -> SymlinkNodeId {
        SymlinkNodeId::new(self.inode.id())
    }

    /// Symlink payload size in bytes.
    #[must_use]
    pub const fn size(&self) -> FileSize {
        self.inode.size()
    }

    /// Allocation charge parsed from the symlink inode.
    #[must_use]
    pub const fn allocation_size(&self) -> FileAllocationSize {
        self.inode.allocation_size()
    }

    /// POSIX security state parsed from the symlink inode.
    #[must_use]
    pub const fn security(&self) -> Ext4Security {
        self.inode.security()
    }

    /// ext4 timestamps parsed from the symlink inode.
    #[must_use]
    pub const fn times(&self) -> Ext4Times {
        self.inode.times()
    }

    /// Link count parsed from the symlink inode.
    #[must_use]
    pub const fn links_count(&self) -> Ext4LinkCount {
        self.inode.links_count()
    }

    /// Returns the backing inode for volume-internal operations.
    pub(super) fn inode(&self) -> &Inode {
        &self.inode
    }
}

/// Directory child selected by a lookup through a typed parent directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryChild {
    /// Parent directory containing the child.
    parent: DirectoryNodeId,
    /// Child name visible at the lookup boundary.
    name: Ext4Name,
    /// Typed child identity.
    node: NodeId,
}

impl DirectoryChild {
    /// Creates a typed directory child after validating the referenced inode.
    pub(super) const fn new(parent: DirectoryNodeId, name: Ext4Name, node: NodeId) -> Self {
        Self { parent, name, node }
    }

    /// Parent directory containing the child.
    #[must_use]
    pub const fn parent(&self) -> DirectoryNodeId {
        self.parent
    }

    /// Child name visible at the lookup boundary.
    #[must_use]
    pub const fn name(&self) -> &Ext4Name {
        &self.name
    }

    /// Typed child identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }
}

/// Directory entry whose referenced inode kind has been validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// Child name visible at the listing boundary.
    name: Ext4Name,
    /// Typed child identity.
    node: NodeId,
    /// File type recorded in the directory entry.
    entry_kind: DirectoryEntryKind,
}

impl DirectoryEntry {
    /// Creates a listed entry after validating the referenced inode.
    pub(super) const fn new(name: Ext4Name, node: NodeId, entry_kind: DirectoryEntryKind) -> Self {
        Self {
            name,
            node,
            entry_kind,
        }
    }

    /// Consumes this validated entry into a typed child without copying its owned name.
    #[must_use]
    pub(super) fn into_child(self, parent: DirectoryNodeId) -> DirectoryChild {
        DirectoryChild {
            parent,
            name: self.name,
            node: self.node,
        }
    }

    /// Child name visible at the listing boundary.
    #[must_use]
    pub const fn name(&self) -> &Ext4Name {
        &self.name
    }

    /// Typed child identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }
}

/// One namespace name that links a parent directory to a non-directory inode.
#[derive(Debug, Eq, PartialEq)]
pub struct HardLinkEntry {
    /// Directory containing the link name.
    parent: DirectoryNodeId,
    /// Exact ext4 name stored in the parent directory.
    name: Ext4Name,
}

impl HardLinkEntry {
    /// Copies one validated namespace entry into the hard-link result domain.
    /// # Errors
    ///
    /// Returns an error when the exact ext4 name cannot be copied.
    pub(super) fn try_new(parent: DirectoryNodeId, name: &Ext4Name) -> Result<Self> {
        Ok(Self {
            parent,
            name: name.try_to_owned_name()?,
        })
    }

    /// Parent directory containing this link.
    #[must_use]
    pub const fn parent(&self) -> DirectoryNodeId {
        self.parent
    }

    /// Exact ext4 link name.
    #[must_use]
    pub const fn name(&self) -> &Ext4Name {
        &self.name
    }
}

/// Complete, non-empty namespace link set for one non-directory inode.
#[derive(Debug, Eq, PartialEq)]
pub struct HardLinks {
    /// Every reachable link, with cardinality validated against the inode link count.
    entries: Vec<HardLinkEntry>,
}

impl HardLinks {
    /// Seals one complete link set after namespace traversal.
    /// # Errors
    ///
    /// Returns an error when the set is empty or its cardinality contradicts the inode link count.
    pub(super) fn try_from_entries(entries: Vec<HardLinkEntry>, expected: usize) -> Result<Self> {
        if entries.is_empty() || entries.len() != expected {
            return Err(Error::InvalidDirectoryEntry);
        }
        Ok(Self { entries })
    }

    /// Every namespace link in traversal order.
    #[must_use]
    pub fn entries(&self) -> &[HardLinkEntry] {
        &self.entries
    }
}

/// Result of a directory lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChildLookup {
    /// The child name was found and its inode kind was validated.
    Found(DirectoryChild),
    /// No child matched the requested name.
    NotFound,
}
