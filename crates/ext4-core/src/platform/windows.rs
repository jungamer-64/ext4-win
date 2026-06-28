//! Windows metadata projected onto ext4 domain types.

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

#[cfg(test)]
mod tests {
    use super::{Ext4WindowsAttributes, WindowsOverlay};

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

    #[test]
    fn windows_overlay_rejects_readonly_attribute() {
        assert!(Ext4WindowsAttributes::new(0x0000_0001).is_err());
    }
}
