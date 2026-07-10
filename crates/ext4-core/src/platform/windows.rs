//! Windows metadata projected onto ext4 domain types.

use alloc::vec::Vec;

use crate::disk_format::inode::SymlinkTarget;
use crate::disk_format::xattr::{XattrName, XattrNamespace, XattrValue};
use crate::error::{Error, Result};

/// File attributes that cannot be represented by POSIX mode bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4WindowsAttributes(u32);

impl Ext4WindowsAttributes {
    /// Windows hidden attribute.
    pub const HIDDEN: u32 = 0x0000_0002;
    /// Windows system attribute.
    pub const SYSTEM: u32 = 0x0000_0004;
    /// Windows archive attribute.
    pub const ARCHIVE: u32 = 0x0000_0020;
    /// Windows not-content-indexed attribute.
    pub const NOT_CONTENT_INDEXED: u32 = 0x0000_2000;
    /// Attribute mask stored in the ext4win overlay xattr.
    pub const SUPPORTED_MASK: u32 =
        Self::HIDDEN | Self::SYSTEM | Self::ARCHIVE | Self::NOT_CONTENT_INDEXED;

    /// Creates a validated attribute set.
    ///
    /// # Errors
    /// Returns an error when the set contains attributes represented by POSIX
    /// mode or ext4 node kind instead of the Windows overlay.
    pub fn new(value: u32) -> Result<Self> {
        if value & !Self::SUPPORTED_MASK != 0 {
            return Err(Error::InvalidXattr);
        }
        Ok(Self(value))
    }

    /// Returns raw Windows attribute bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Windows-specific inode metadata isolated in `user.ext4win.*` xattrs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsOverlay {
    /// Attributes not represented by POSIX owner/mode or ext4 inode kind.
    attributes: Ext4WindowsAttributes,
}

impl WindowsOverlay {
    /// Version byte for the ext4win attribute overlay.
    const ATTRIBUTES_VERSION: u32 = 1;

    /// Creates overlay metadata.
    #[must_use]
    pub const fn new(attributes: Ext4WindowsAttributes) -> Self {
        Self { attributes }
    }

    /// Returns the xattr name storing Windows attributes.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub fn attributes_xattr_name() -> Result<XattrName> {
        XattrName::new(XattrNamespace::User, b"ext4win.attributes")
    }

    /// Returns Windows-specific attributes.
    #[must_use]
    pub const fn attributes(self) -> Ext4WindowsAttributes {
        self.attributes
    }

    /// Serializes this overlay to the `user.ext4win_attributes` value.
    ///
    /// # Errors
    /// Returns an error when the value cannot be represented as an xattr.
    pub fn to_xattr_value(self) -> Result<XattrValue> {
        let mut bytes = [0_u8; 8];
        let (version, attributes) = bytes.split_at_mut(4);
        version.copy_from_slice(&Self::ATTRIBUTES_VERSION.to_le_bytes());
        attributes.copy_from_slice(&self.attributes.bits().to_le_bytes());
        XattrValue::new(&bytes)
    }

    /// Parses the `user.ext4win_attributes` value.
    ///
    /// # Errors
    /// Returns an error when the value version or attribute mask is invalid.
    pub fn parse(value: &XattrValue) -> Result<Self> {
        let bytes = value.bytes();
        if bytes.len() != 8 {
            return Err(Error::InvalidXattr);
        }
        let version = u32::from_le_bytes(
            bytes
                .get(0..4)
                .ok_or(Error::InvalidXattr)?
                .try_into()
                .map_err(|_| Error::InvalidXattr)?,
        );
        if version != Self::ATTRIBUTES_VERSION {
            return Err(Error::InvalidXattr);
        }
        let attributes = u32::from_le_bytes(
            bytes
                .get(4..8)
                .ok_or(Error::InvalidXattr)?
                .try_into()
                .map_err(|_| Error::InvalidXattr)?,
        );
        Ok(Self {
            attributes: Ext4WindowsAttributes::new(attributes)?,
        })
    }
}

/// Windows symbolic-link reparse metadata isolated in a `user.ext4win.*` xattr.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsSymlinkReparsePoint {
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
    pub const fn new(target: SymlinkTarget, relative: bool) -> Self {
        Self { target, relative }
    }

    /// Returns the symbolic-link target.
    #[must_use]
    pub const fn target(&self) -> &SymlinkTarget {
        &self.target
    }

    /// Returns whether the target is relative.
    #[must_use]
    pub const fn is_relative(&self) -> bool {
        self.relative
    }

    /// Returns the xattr name storing the reparse metadata.
    ///
    /// # Errors
    /// Returns an error only if the fixed domain name is invalid.
    pub fn xattr_name() -> Result<XattrName> {
        XattrName::new(XattrNamespace::User, b"ext4win.reparse.symlink")
    }

    /// Serializes this reparse point to its private xattr value.
    ///
    /// # Errors
    /// Returns an error when storage cannot be allocated or the target cannot
    /// be represented by the xattr payload.
    pub fn to_xattr_value(&self) -> Result<XattrValue> {
        let target = self.target.bytes();
        let target_length = u32::try_from(target.len()).map_err(|_| Error::InvalidXattr)?;
        let total_length = Self::XATTR_HEADER_SIZE
            .checked_add(target.len())
            .ok_or(Error::InvalidXattr)?;
        if total_length > XattrValue::MAX_BYTES {
            return Err(Error::InvalidXattr);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(total_length)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.extend_from_slice(&Self::VERSION.to_le_bytes());
        let flags = if self.relative {
            Self::RELATIVE_FLAG
        } else {
            0
        };
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&target_length.to_le_bytes());
        bytes.extend_from_slice(target);
        XattrValue::new(&bytes)
    }

    /// Parses the private `user.ext4win.reparse.symlink` xattr value.
    ///
    /// # Errors
    /// Returns an error when the payload version, flags, length, or target is invalid.
    pub fn parse(value: &XattrValue) -> Result<Self> {
        let bytes = value.bytes();
        if bytes.len() < Self::XATTR_HEADER_SIZE {
            return Err(Error::InvalidXattr);
        }
        let version = decode_xattr_u32(bytes, 0)?;
        if version != Self::VERSION {
            return Err(Error::InvalidXattr);
        }
        let flags = decode_xattr_u32(bytes, 4)?;
        if flags & !Self::RELATIVE_FLAG != 0 {
            return Err(Error::InvalidXattr);
        }
        let target_length =
            usize::try_from(decode_xattr_u32(bytes, 8)?).map_err(|_| Error::InvalidXattr)?;
        let expected_length = Self::XATTR_HEADER_SIZE
            .checked_add(target_length)
            .ok_or(Error::InvalidXattr)?;
        if bytes.len() != expected_length {
            return Err(Error::InvalidXattr);
        }
        let target_bytes = bytes
            .get(Self::XATTR_HEADER_SIZE..)
            .ok_or(Error::InvalidXattr)?;
        let target = match SymlinkTarget::new(target_bytes) {
            Ok(target) => target,
            Err(Error::InvalidName) => return Err(Error::InvalidXattr),
            Err(error) => return Err(error),
        };
        Ok(Self::new(target, flags & Self::RELATIVE_FLAG != 0))
    }
}

/// Decodes one fixed-width little-endian field from a reparse xattr payload.
/// # Errors
///
/// Returns an error when the requested field lies outside the xattr payload.
fn decode_xattr_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(Error::InvalidXattr)?;
    let field = bytes.get(offset..end).ok_or(Error::InvalidXattr)?;
    Ok(u32::from_le_bytes(
        field.try_into().map_err(|_| Error::InvalidXattr)?,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::Error;
    use crate::disk_format::inode::SymlinkTarget;
    use crate::disk_format::xattr::XattrValue;

    use super::{Ext4WindowsAttributes, WindowsOverlay, WindowsSymlinkReparsePoint};

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn windows_overlay_round_trips_supported_attributes() {
        let attributes = Ext4WindowsAttributes::new(
            Ext4WindowsAttributes::HIDDEN | Ext4WindowsAttributes::ARCHIVE,
        );
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
        assert!(Ext4WindowsAttributes::new(0x0000_0001).is_err());
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
            Err(Error::InvalidXattr)
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

        assert_eq!(point.to_xattr_value(), Err(Error::InvalidXattr));
    }
}
