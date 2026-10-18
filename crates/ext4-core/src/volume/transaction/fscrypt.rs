//! Fscrypt context selection from the transaction's authoritative staged inode and xattr images.

use super::*;

impl MetadataMutation<'_, '_> {
    /// Selects a required context from the latest staged inode and external xattr block images.
    /// # Errors
    /// Returns deleted or malformed inode, storage, allocation, or invalid-context failure.
    pub(super) fn fscrypt_context_for_inode(&mut self, inode: &Inode) -> Result<FscryptContextV2> {
        let raw = self.raw_inode_for_policy(inode.id())?;
        let xattrs = self.xattr_set_for_raw_inode(&raw)?;
        let value = xattrs
            .encryption_context()
            .ok_or(Error::InvalidEncryptionContext)?;
        FscryptContextV2::parse(value.bytes())
    }

    /// Binds the selected staged context to the operation's observed mount-key snapshot.
    /// # Errors
    /// Returns context-selection, resource-observation, or missing-key failure.
    pub(super) fn fscrypt_key_for_inode(&mut self, inode: &Inode) -> Result<FscryptInodeKey<'_>> {
        let context = self.fscrypt_context_for_inode(inode)?;
        self.volume.fscrypt_key(context)
    }

    /// Encodes a new name using the selected directory's staged protection state.
    /// # Errors
    /// Returns invalid name, context-selection, missing-key, or cryptographic-provider failure.
    pub(super) fn encrypt_directory_child_name(
        &mut self,
        parent: &Inode,
        name: &Ext4Name,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<Ext4Name> {
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ext4Name::new(name.bytes());
        }
        self.fscrypt_key_for_inode(parent)?
            .encrypt_name(name, crypto)
    }
}
