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

    /// Prepares a query from this transaction's staged directory context and observed key snapshot.
    /// # Errors
    /// Returns context, encoding, allocation, crypto or missing-key display failure.
    pub(super) fn prepare_directory_lookup<'name>(
        &mut self,
        parent: &Inode,
        name: &'name Ext4Name,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<PreparedDirectoryLookup<'name>> {
        let names = self.volume.superblock.name_semantics(parent)?;
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return Ok(PreparedDirectoryLookup::Plain(name));
        }
        match self.fscrypt_key_for_inode(parent) {
            Ok(key) => PreparedDirectoryLookup::encrypted(name, names, key, crypto),
            Err(Error::MissingEncryptionKey) => Ok(PreparedDirectoryLookup::NoKey(
                FscryptNoKeyName::from_display(name.bytes())?.ok_or(Error::MissingEncryptionKey)?,
            )),
            Err(error) => Err(error),
        }
    }

    /// Encodes a complete record while the plaintext and its directory key are both available.
    /// # Errors
    /// Returns encoding, context, key, allocation or cryptographic failure before staging.
    pub(super) fn encode_directory_entry(
        &mut self,
        parent: &Inode,
        name: &Ext4Name,
        child: InodeId,
        kind: DirectoryEntryKind,
        crypto: &mut dyn CryptographicOperation,
    ) -> Result<RawDirectoryEntry> {
        let names = self.volume.superblock.name_semantics(parent)?;
        let comparison = names.key(name.bytes())?;
        if !parent.protection().is_encrypted() || matches!(name.bytes(), b"." | b"..") {
            return RawDirectoryEntry::new(child, name, kind);
        }
        let key = self.fscrypt_key_for_inode(parent)?;
        let ciphertext = key.encrypt_name(name, crypto)?;
        if parent.flags().has_casefold() {
            let hash = key.directory_hash_key(crypto)?.hash(comparison.bytes());
            RawDirectoryEntry::encrypted_casefold(child, &ciphertext, kind, hash)
        } else {
            RawDirectoryEntry::new(child, &ciphertext, kind)
        }
    }
}
