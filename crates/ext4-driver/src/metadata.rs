//! Windows inode projections and the private xattr encoding boundary.

use crate::kernel::status::{DriverError, DriverResult};
use crate::memory;
use crate::request::DriverMutationPass;
use ext4_core::{
    CommittedReadPass, Ext4LinkCount, Ext4Security, Ext4Times, FileAllocationSize, FileSize,
    NodeDataPolicy, NodeId, SymlinkTarget, TransactionNode, XattrName, XattrNamespace, XattrSet,
    XattrValue,
};

/// Windows interpretation of one coherent ext4 inode/xattr observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsNodeMetadata {
    /// Sole source for ext4 inode facts.
    inode: ext4_core::NodeMetadataSnapshot,
    /// Validated Windows attribute overlay.
    attributes: WindowsAttributes,
    /// Interpretation of the inode kind and validated private reparse xattr.
    reparse: WindowsReparsePoint,
}

/// Reparse classification exposed through Windows metadata queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsReparsePoint {
    /// No Windows reparse interpretation applies.
    None,
    /// Native ext4 symbolic link or private Windows symbolic-link record.
    SymbolicLink,
}

impl WindowsNodeMetadata {
    /// Decodes only the private Windows attributes of an already coherent ext4 observation.
    /// # Errors
    /// Returns invalid private metadata or allocation failure while parsing a reparse target.
    pub(crate) fn from_ext4(
        inode: ext4_core::NodeMetadataSnapshot,
        xattrs: &XattrSet,
    ) -> DriverResult<Self> {
        let attributes = xattrs
            .get(&WindowsOverlay::attributes_xattr_name()?)
            .map(WindowsOverlay::parse)
            .transpose()?
            .map(WindowsOverlay::attributes)
            .unwrap_or(WindowsAttributes::NONE);
        let reparse = match inode.node() {
            NodeId::Symlink(_) => WindowsReparsePoint::SymbolicLink,
            NodeId::File(_) | NodeId::Directory(_) => {
                if xattrs
                    .get(&WindowsSymlinkReparsePoint::xattr_name()?)
                    .map(WindowsSymlinkReparsePoint::parse)
                    .transpose()?
                    .is_some()
                {
                    WindowsReparsePoint::SymbolicLink
                } else {
                    WindowsReparsePoint::None
                }
            }
        };
        Ok(Self {
            inode,
            attributes,
            reparse,
        })
    }
    /// Ext4 identity whose observation established this projection.
    pub(crate) const fn node(self) -> NodeId {
        self.inode.node()
    }
    /// Ext4 payload eligibility paired with the projected attributes.
    pub(crate) const fn data_policy(self) -> NodeDataPolicy {
        self.inode.data_policy()
    }
    /// Coherent logical payload length.
    pub(crate) const fn size(self) -> FileSize {
        self.inode.size()
    }
    /// Coherent physical allocation charge.
    pub(crate) const fn allocation_size(self) -> FileAllocationSize {
        self.inode.allocation_size()
    }
    /// Coherent POSIX ownership and mode.
    pub(crate) const fn security(self) -> Ext4Security {
        self.inode.security()
    }
    /// Coherent ext4 timestamps.
    pub(crate) const fn times(self) -> Ext4Times {
        self.inode.times()
    }
    /// Coherent live namespace link count.
    pub(crate) const fn links_count(self) -> Ext4LinkCount {
        self.inode.links_count()
    }
    /// Private Windows attribute bits.
    pub(crate) const fn windows_attributes(self) -> WindowsAttributes {
        self.attributes
    }
    /// Windows reparse classification.
    pub(crate) const fn reparse_point(self) -> WindowsReparsePoint {
        self.reparse
    }
    /// Complete Windows file-attribute projection, including mode and inode kind.
    pub(crate) fn windows_file_attributes(self) -> u32 {
        let mut attributes = self.attributes.bits();
        if self.inode.security().permissions().as_u16() & 0o222 == 0 {
            attributes |= wdk_sys::FILE_ATTRIBUTE_READONLY;
        }
        if matches!(self.inode.node(), NodeId::Directory(_)) {
            attributes |= wdk_sys::FILE_ATTRIBUTE_DIRECTORY;
        }
        if self.reparse == WindowsReparsePoint::SymbolicLink {
            attributes |= wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
        }
        if attributes == 0 {
            wdk_sys::FILE_ATTRIBUTE_NORMAL
        } else {
            attributes
        }
    }
}

/// Reads Windows metadata from one committed pass without retaining the pass across suspension.
/// # Errors
/// Returns ext4 observation, private metadata decoding or allocation failures.
pub(crate) fn load_node_metadata(
    read: &mut impl CommittedReadPass,
    node: NodeId,
) -> DriverResult<WindowsNodeMetadata> {
    let inode = read.load_node_metadata(node)?;
    WindowsNodeMetadata::from_ext4(inode, &read.read_xattrs(node)?)
}

/// Prepares a Windows projection from the latest uncommitted ext4 inode and xattrs.
/// # Errors
/// Returns staged observation, private metadata decoding or allocation failures.
pub(crate) fn staged_node_metadata(
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    node: NodeId,
) -> DriverResult<WindowsNodeMetadata> {
    let inode = mutation.staged_node_metadata(node)?;
    WindowsNodeMetadata::from_ext4(inode, &mutation.staged_xattrs(node)?)
}

/// Reads the private Windows symbolic-link record from a committed pass.
/// # Errors
/// Returns xattr storage, private metadata decoding or allocation failures.
pub(crate) fn read_symlink(
    read: &mut impl CommittedReadPass,
    node: NodeId,
) -> DriverResult<Option<WindowsSymlinkReparsePoint>> {
    read.read_xattr(node, &WindowsSymlinkReparsePoint::xattr_name()?)?
        .as_ref()
        .map(WindowsSymlinkReparsePoint::parse)
        .transpose()
}

/// File attributes that cannot be represented by POSIX mode bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsAttributes(u32);

impl WindowsAttributes {
    /// No Windows-only attributes are attached to the inode.
    pub(crate) const NONE: Self = Self(0);
    /// Windows hidden attribute.
    pub(crate) const HIDDEN: u32 = 0x0000_0002;
    /// Windows system attribute.
    pub(crate) const SYSTEM: u32 = 0x0000_0004;
    /// Windows archive attribute.
    pub(crate) const ARCHIVE: u32 = 0x0000_0020;
    /// Windows not-content-indexed attribute.
    pub(crate) const NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
    /// Attribute mask stored in the ext4win overlay xattr.
    pub(crate) const SUPPORTED_MASK: u32 =
        Self::HIDDEN | Self::SYSTEM | Self::ARCHIVE | Self::NOT_CONTENT_INDEXED;

    /// Creates a validated attribute set.
    ///
    /// # Errors
    /// Returns an error when the set contains attributes represented by POSIX
    /// mode or ext4 node kind instead of the Windows overlay.
    pub(crate) fn new(value: u32) -> DriverResult<Self> {
        if value & !Self::SUPPORTED_MASK != 0 {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        Ok(Self(value))
    }

    /// Returns raw Windows attribute bits.
    #[must_use]
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
}

/// Windows-specific inode metadata isolated in `user.ext4win.*` xattrs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsOverlay {
    /// Attributes not represented by POSIX owner/mode or ext4 inode kind.
    attributes: WindowsAttributes,
}

impl WindowsOverlay {
    /// Version byte for the ext4win attribute overlay.
    const ATTRIBUTES_VERSION: u32 = 1;

    /// Creates overlay metadata.
    #[must_use]
    pub(crate) const fn new(attributes: WindowsAttributes) -> Self {
        Self { attributes }
    }

    /// Stores this Windows interpretation through the generic ext4 xattr mutation boundary.
    /// # Errors
    /// Returns serialization, allocation or ext4 mutation failures before commit.
    pub(crate) fn store(
        self,
        mutation: &mut DriverMutationPass<'_, '_, '_>,
        node: TransactionNode,
    ) -> DriverResult<()> {
        Ok(mutation.set_xattr(node, Self::attributes_xattr_name()?, self.to_xattr_value()?)?)
    }

    /// Returns the xattr name storing Windows attributes.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub(crate) fn attributes_xattr_name() -> DriverResult<XattrName> {
        Ok(XattrName::new(XattrNamespace::User, b"ext4win.attributes")?)
    }

    /// Returns Windows-specific attributes.
    #[must_use]
    pub(crate) const fn attributes(self) -> WindowsAttributes {
        self.attributes
    }

    /// Serializes this overlay to the `user.ext4win_attributes` value.
    ///
    /// # Errors
    /// Returns an error when the value cannot be represented as an xattr.
    pub(crate) fn to_xattr_value(self) -> DriverResult<XattrValue> {
        let mut bytes = [0_u8; 8];
        let (version, attributes) = bytes
            .split_at_mut_checked(4)
            .ok_or(DriverError::InternalInvariantViolation)?;
        memory::copy_exact(version, &Self::ATTRIBUTES_VERSION.to_le_bytes())?;
        memory::copy_exact(attributes, &self.attributes.bits().to_le_bytes())?;
        Ok(XattrValue::new(&bytes)?)
    }

    /// Parses the `user.ext4win_attributes` value.
    ///
    /// # Errors
    /// Returns an error when the value version or attribute mask is invalid.
    pub(crate) fn parse(value: &XattrValue) -> DriverResult<Self> {
        let bytes = value.bytes();
        if bytes.len() != 8 {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let version = u32::from_le_bytes(
            bytes
                .get(0..4)
                .ok_or(DriverError::InvalidWindowsMetadata)?
                .try_into()
                .map_err(|_| DriverError::InvalidWindowsMetadata)?,
        );
        if version != Self::ATTRIBUTES_VERSION {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let attributes = u32::from_le_bytes(
            bytes
                .get(4..8)
                .ok_or(DriverError::InvalidWindowsMetadata)?
                .try_into()
                .map_err(|_| DriverError::InvalidWindowsMetadata)?,
        );
        Ok(Self {
            attributes: WindowsAttributes::new(attributes)?,
        })
    }
}

/// Windows symbolic-link reparse metadata isolated in a `user.ext4win.*` xattr.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsSymlinkReparsePoint {
    /// Target interpreted by the Windows symbolic-link reparse handler.
    target: SymlinkTarget,
    /// Whether the target is relative to the reparse point's containing directory.
    relative: bool,
}

impl WindowsSymlinkReparsePoint {
    /// Version field for the ext4win symbolic-link reparse xattr.
    const VERSION: u32 = 1;
    /// Flag stored in the xattr when the target is relative.
    const RELATIVE_FLAG: u32 = 1;
    /// Bytes preceding the target in the xattr value.
    const XATTR_HEADER_SIZE: usize = 12;

    /// Creates Windows symbolic-link reparse metadata.
    #[must_use]
    pub(crate) const fn new(target: SymlinkTarget, relative: bool) -> Self {
        Self { target, relative }
    }

    /// Stores a Windows reparse record on a regular file or directory.
    /// # Errors
    /// Returns a native-symlink conflict, invalid encoding, allocation or ext4 mutation failure.
    pub(crate) fn store(
        self,
        mutation: &mut DriverMutationPass<'_, '_, '_>,
        node: TransactionNode,
    ) -> DriverResult<()> {
        if matches!(node.id(), NodeId::Symlink(_)) {
            return Err(DriverError::InvalidReparseData);
        }
        Ok(mutation.set_xattr(node, Self::xattr_name()?, self.to_xattr_value()?)?)
    }

    /// Removes a private reparse record after validating its complete staged value.
    /// # Errors
    /// Returns a native-symlink conflict, invalid stored encoding or ext4 mutation failure.
    pub(crate) fn remove(
        mutation: &mut DriverMutationPass<'_, '_, '_>,
        node: TransactionNode,
    ) -> DriverResult<Option<Self>> {
        if matches!(node.id(), NodeId::Symlink(_)) {
            return Err(DriverError::InvalidReparseData);
        }
        let name = Self::xattr_name()?;
        let xattrs = mutation.staged_xattrs(node.id())?;
        let point = xattrs.get(&name).map(Self::parse).transpose()?;
        if point.is_some() {
            mutation.remove_xattr(node, &name)?;
        }
        Ok(point)
    }

    /// Returns the symbolic-link target.
    #[must_use]
    pub(crate) const fn target(&self) -> &SymlinkTarget {
        &self.target
    }

    /// Returns whether the target is relative.
    #[must_use]
    pub(crate) const fn is_relative(&self) -> bool {
        self.relative
    }

    /// Returns the xattr name storing the reparse metadata.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub(crate) fn xattr_name() -> DriverResult<XattrName> {
        Ok(XattrName::new(
            XattrNamespace::User,
            b"ext4win.reparse.symlink",
        )?)
    }

    /// Serializes this reparse point to its private xattr value.
    ///
    /// # Errors
    /// Returns an error when storage cannot be allocated or the target cannot
    /// be represented by the xattr payload.
    pub(crate) fn to_xattr_value(&self) -> DriverResult<XattrValue> {
        let target = self.target.bytes();
        let target_length =
            u32::try_from(target.len()).map_err(|_| DriverError::InvalidWindowsMetadata)?;
        let total_length = Self::XATTR_HEADER_SIZE
            .checked_add(target.len())
            .ok_or(DriverError::InvalidWindowsMetadata)?;
        if total_length > XattrValue::MAX_BYTES {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let mut bytes = memory::try_repeated_vec(0_u8, total_length)?;
        memory::copy_exact(
            bytes
                .get_mut(0..4)
                .ok_or(DriverError::InvalidWindowsMetadata)?,
            &Self::VERSION.to_le_bytes(),
        )?;
        let flags = if self.relative {
            Self::RELATIVE_FLAG
        } else {
            0
        };
        memory::copy_exact(
            bytes
                .get_mut(4..8)
                .ok_or(DriverError::InvalidWindowsMetadata)?,
            &flags.to_le_bytes(),
        )?;
        memory::copy_exact(
            bytes
                .get_mut(8..12)
                .ok_or(DriverError::InvalidWindowsMetadata)?,
            &target_length.to_le_bytes(),
        )?;
        memory::copy_exact(
            bytes
                .get_mut(Self::XATTR_HEADER_SIZE..total_length)
                .ok_or(DriverError::InvalidWindowsMetadata)?,
            target,
        )?;
        Ok(XattrValue::new(&bytes)?)
    }

    /// Parses the private `user.ext4win.reparse.symlink` xattr value.
    ///
    /// # Errors
    /// Returns an error when the payload version, flags, length, or target is invalid.
    pub(crate) fn parse(value: &XattrValue) -> DriverResult<Self> {
        let bytes = value.bytes();
        if bytes.len() < Self::XATTR_HEADER_SIZE {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let version = decode_xattr_u32(bytes, 0)?;
        if version != Self::VERSION {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let flags = decode_xattr_u32(bytes, 4)?;
        if flags & !Self::RELATIVE_FLAG != 0 {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let target_length = usize::try_from(decode_xattr_u32(bytes, 8)?)
            .map_err(|_| DriverError::InvalidWindowsMetadata)?;
        let expected_length = Self::XATTR_HEADER_SIZE
            .checked_add(target_length)
            .ok_or(DriverError::InvalidWindowsMetadata)?;
        if bytes.len() != expected_length {
            return Err(DriverError::InvalidWindowsMetadata);
        }
        let target_bytes = bytes
            .get(Self::XATTR_HEADER_SIZE..)
            .ok_or(DriverError::InvalidWindowsMetadata)?;
        let target = match SymlinkTarget::new(target_bytes) {
            Ok(target) => target,
            Err(ext4_core::Error::InvalidName) => return Err(DriverError::InvalidWindowsMetadata),
            Err(error) => return Err(error.into()),
        };
        Ok(Self::new(target, flags & Self::RELATIVE_FLAG != 0))
    }
}

/// Decodes one fixed-width little-endian field from a reparse xattr payload.
/// # Errors
///
/// Returns an error when the requested field lies outside the xattr payload.
fn decode_xattr_u32(bytes: &[u8], offset: usize) -> DriverResult<u32> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(DriverError::InvalidWindowsMetadata)?;
    let field = bytes
        .get(offset..end)
        .ok_or(DriverError::InvalidWindowsMetadata)?;
    Ok(u32::from_le_bytes(
        field
            .try_into()
            .map_err(|_| DriverError::InvalidWindowsMetadata)?,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::kernel::status::DriverError;
    use ext4_core::SymlinkTarget;
    use ext4_core::XattrValue;

    use super::{WindowsAttributes, WindowsOverlay, WindowsSymlinkReparsePoint};

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_overlay_round_trips_supported_attributes() {
        let attributes =
            WindowsAttributes::new(WindowsAttributes::HIDDEN | WindowsAttributes::ARCHIVE);
        if let Ok(attributes) = attributes {
            let overlay = WindowsOverlay::new(attributes);
            let value = overlay.to_xattr_value();
            if let Ok(value) = value {
                assert_eq!(WindowsOverlay::parse(&value), Ok(overlay));
            }
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_overlay_rejects_readonly_attribute() {
        assert!(WindowsAttributes::new(0x0000_0001).is_err());
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_symlink_reparse_point_round_trips_target_and_relative_flag() {
        let target = SymlinkTarget::new(b"relative\\target");
        assert!(target.is_ok());
        let Ok(target) = target else {
            return;
        };
        let point = WindowsSymlinkReparsePoint::new(target, true);
        let value = point.to_xattr_value();
        assert!(value.is_ok());
        let Ok(value) = value else {
            return;
        };

        assert_eq!(WindowsSymlinkReparsePoint::parse(&value), Ok(point));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_symlink_reparse_point_rejects_invalid_xattr_payload() {
        let value = XattrValue::new(&[0_u8; 12]);
        assert!(value.is_ok());
        let Ok(value) = value else {
            return;
        };

        assert_eq!(
            WindowsSymlinkReparsePoint::parse(&value),
            Err(DriverError::InvalidWindowsMetadata)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_symlink_reparse_point_rejects_target_larger_than_xattr_capacity() {
        let target = vec![b'a'; XattrValue::MAX_BYTES - 12 + 1];
        let target = SymlinkTarget::new(&target);
        assert!(target.is_ok());
        let Ok(target) = target else {
            return;
        };
        let point = WindowsSymlinkReparsePoint::new(target, false);

        assert_eq!(
            point.to_xattr_value(),
            Err(DriverError::InvalidWindowsMetadata)
        );
    }
}
