//! ext4win-private FSCTL payload decoding for fscrypt and fs-verity.

use alloc::vec::Vec;

use ext4_core::{FscryptKeyIdentifier, FscryptMasterKey, FsverityBlockSize, FsverityHashAlgorithm};
use wdk_sys::{NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED};

use crate::irp::{DispatchTarget, FileSystemControlStack};
use crate::status::DriverError;

/// Windows `FILE_DEVICE_FILE_SYSTEM`.
const FILE_DEVICE_FILE_SYSTEM: wdk_sys::ULONG = 0x0000_0009;
/// Windows `METHOD_BUFFERED`.
const METHOD_BUFFERED: wdk_sys::ULONG = 0;
/// Windows `FILE_ANY_ACCESS`.
const FILE_ANY_ACCESS: wdk_sys::ULONG = 0;
/// ext4win private function code for adding an fscrypt key.
const EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x900;
/// ext4win private function code for removing an fscrypt key.
const EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION: wdk_sys::ULONG = 0x901;
/// ext4win private function code for fscrypt key status.
const EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION: wdk_sys::ULONG = 0x902;
/// ext4win private function code for enabling fs-verity.
const EXT4WIN_ENABLE_VERITY_FUNCTION: wdk_sys::ULONG = 0x903;

/// ext4win FSCTL carrying Linux `struct fscrypt_add_key_arg`.
pub(crate) const FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_ADD_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_remove_key_arg`.
pub(crate) const FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_REMOVE_ENCRYPTION_KEY_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fscrypt_get_key_status_arg`.
pub(crate) const FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_GET_ENCRYPTION_KEY_STATUS_FUNCTION);
/// ext4win FSCTL carrying Linux `struct fsverity_enable_arg`.
pub(crate) const FSCTL_EXT4WIN_ENABLE_VERITY: wdk_sys::ULONG =
    ext4win_fsctl(EXT4WIN_ENABLE_VERITY_FUNCTION);

/// Linux `FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER`.
const FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER: u32 = 2;
/// Linux `struct fscrypt_key_specifier` size.
const FSCRYPT_KEY_SPECIFIER_BYTES: usize = 40;
/// Linux fscrypt v2 key identifier size.
const FSCRYPT_KEY_IDENTIFIER_BYTES: usize = 16;
/// Linux `struct fscrypt_add_key_arg` fixed header before `raw[]`.
const FSCRYPT_ADD_KEY_FIXED_BYTES: usize = 80;
/// Linux `struct fscrypt_remove_key_arg` size.
const FSCRYPT_REMOVE_KEY_BYTES: usize = 64;
/// Input prefix of Linux `struct fscrypt_get_key_status_arg`.
const FSCRYPT_GET_KEY_STATUS_INPUT_BYTES: usize = 64;
/// Offset of fscrypt key-specifier type.
const FSCRYPT_KEY_SPEC_TYPE_OFFSET: usize = 0;
/// Offset of fscrypt key-specifier reserved word.
const FSCRYPT_KEY_SPEC_RESERVED_OFFSET: usize = 4;
/// Offset of fscrypt key-specifier union.
const FSCRYPT_KEY_SPEC_UNION_OFFSET: usize = 8;
/// Offset of add-key raw size.
const FSCRYPT_ADD_KEY_RAW_SIZE_OFFSET: usize = 40;
/// Offset of add-key key id.
const FSCRYPT_ADD_KEY_KEY_ID_OFFSET: usize = 44;
/// Offset of add-key flags.
const FSCRYPT_ADD_KEY_FLAGS_OFFSET: usize = 48;
/// Offset of add-key reserved words.
const FSCRYPT_ADD_KEY_RESERVED_OFFSET: usize = 52;
/// Size of add-key reserved words.
const FSCRYPT_ADD_KEY_RESERVED_BYTES: usize = 28;
/// Offset of remove-key status flags.
const FSCRYPT_REMOVE_KEY_STATUS_FLAGS_OFFSET: usize = 40;
/// Offset of remove-key reserved words.
const FSCRYPT_REMOVE_KEY_RESERVED_OFFSET: usize = 44;
/// Size of remove-key reserved words.
const FSCRYPT_REMOVE_KEY_RESERVED_BYTES: usize = 20;
/// Offset of key-status input reserved words.
const FSCRYPT_GET_KEY_STATUS_RESERVED_OFFSET: usize = 40;
/// Size of key-status input reserved words.
const FSCRYPT_GET_KEY_STATUS_RESERVED_BYTES: usize = 24;

/// Linux `struct fsverity_enable_arg` size.
const FSVERITY_ENABLE_ARG_BYTES: usize = 128;
/// Linux fs-verity enable version.
const FSVERITY_ENABLE_VERSION: u32 = 1;
/// Linux fs-verity signature upper bound.
const FSVERITY_MAX_SIGNATURE_BYTES: u32 = 16_128;
/// Offset of verity-enable version.
const FSVERITY_ENABLE_VERSION_OFFSET: usize = 0;
/// Offset of verity-enable hash algorithm.
const FSVERITY_ENABLE_HASH_ALGORITHM_OFFSET: usize = 4;
/// Offset of verity-enable block size.
const FSVERITY_ENABLE_BLOCK_SIZE_OFFSET: usize = 8;
/// Offset of verity-enable salt size.
const FSVERITY_ENABLE_SALT_SIZE_OFFSET: usize = 12;
/// Offset of verity-enable salt pointer.
const FSVERITY_ENABLE_SALT_PTR_OFFSET: usize = 16;
/// Offset of verity-enable signature size.
const FSVERITY_ENABLE_SIG_SIZE_OFFSET: usize = 24;
/// Offset of verity-enable first reserved word.
const FSVERITY_ENABLE_RESERVED1_OFFSET: usize = 28;
/// Offset of verity-enable signature pointer.
const FSVERITY_ENABLE_SIG_PTR_OFFSET: usize = 32;
/// Offset of verity-enable trailing reserved words.
const FSVERITY_ENABLE_RESERVED2_OFFSET: usize = 40;
/// Size of verity-enable trailing reserved words.
const FSVERITY_ENABLE_RESERVED2_BYTES: usize = 88;

/// Builds a Windows `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, function, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
const fn ext4win_fsctl(function: wdk_sys::ULONG) -> wdk_sys::ULONG {
    (FILE_DEVICE_FILE_SYSTEM << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED
}

/// Handles fscrypt key-add FSCTL payloads.
pub(crate) fn add_encryption_key(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> NTSTATUS {
    match read_input(target, stack).and_then(|input| FscryptAddKeyPayload::parse(input.as_slice()))
    {
        Ok(payload) => {
            let _identifier = payload.master_key().identifier();
            STATUS_NOT_SUPPORTED
        }
        Err(status) => status,
    }
}

/// Handles fscrypt key-remove FSCTL payloads.
pub(crate) fn remove_encryption_key(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> NTSTATUS {
    match read_input(target, stack)
        .and_then(|input| FscryptRemoveKeyPayload::parse(input.as_slice()))
    {
        Ok(payload) => {
            let _identifier = payload.identifier();
            STATUS_NOT_SUPPORTED
        }
        Err(status) => status,
    }
}

/// Handles fscrypt key-status FSCTL payloads.
pub(crate) fn get_encryption_key_status(
    target: DispatchTarget,
    stack: FileSystemControlStack,
) -> NTSTATUS {
    match read_input(target, stack)
        .and_then(|input| FscryptKeyStatusPayload::parse(input.as_slice()))
    {
        Ok(payload) => {
            let _identifier = payload.identifier();
            STATUS_NOT_SUPPORTED
        }
        Err(status) => status,
    }
}

/// Handles fs-verity enable FSCTL payloads.
pub(crate) fn enable_verity(target: DispatchTarget, stack: FileSystemControlStack) -> NTSTATUS {
    match read_input(target, stack).and_then(|input| FsverityEnablePayload::parse(input.as_slice()))
    {
        Ok(payload) => {
            let _algorithm = payload.algorithm();
            let _block_size = payload.block_size();
            let _salt = payload.salt();
            let _signature = payload.signature();
            STATUS_NOT_SUPPORTED
        }
        Err(status) => status,
    }
}

/// Parsed fscrypt add-key payload.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FscryptAddKeyPayload {
    /// Mount-scoped master key validated against its v2 identifier.
    master_key: FscryptMasterKey,
}

impl FscryptAddKeyPayload {
    /// Parses Linux `struct fscrypt_add_key_arg`.
    fn parse(input: &[u8]) -> Result<Self, NTSTATUS> {
        if input.len() < FSCRYPT_ADD_KEY_FIXED_BYTES {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let identifier = parse_key_identifier(input)?;
        if read_u32(input, FSCRYPT_ADD_KEY_KEY_ID_OFFSET)? != 0
            || read_u32(input, FSCRYPT_ADD_KEY_FLAGS_OFFSET)? != 0
            || !all_zero(
                input,
                FSCRYPT_ADD_KEY_RESERVED_OFFSET,
                FSCRYPT_ADD_KEY_RESERVED_BYTES,
            )?
        {
            return Err(STATUS_NOT_SUPPORTED);
        }
        let raw_size = usize::try_from(read_u32(input, FSCRYPT_ADD_KEY_RAW_SIZE_OFFSET)?)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        let raw = input
            .get(FSCRYPT_ADD_KEY_FIXED_BYTES..)
            .ok_or(STATUS_BUFFER_TOO_SMALL)?;
        if raw.len() != raw_size {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let master_key =
            FscryptMasterKey::from_raw(raw).map_err(|error| DriverError::from(error).ntstatus())?;
        if master_key.identifier() != identifier {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self { master_key })
    }

    /// Validated mount key from the payload.
    const fn master_key(&self) -> &FscryptMasterKey {
        &self.master_key
    }
}

/// Parsed fscrypt remove-key payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FscryptRemoveKeyPayload {
    /// Key identifier selected for removal.
    identifier: FscryptKeyIdentifier,
}

impl FscryptRemoveKeyPayload {
    /// Parses Linux `struct fscrypt_remove_key_arg`.
    fn parse(input: &[u8]) -> Result<Self, NTSTATUS> {
        if input.len() != FSCRYPT_REMOVE_KEY_BYTES {
            return Err(if input.len() < FSCRYPT_REMOVE_KEY_BYTES {
                STATUS_BUFFER_TOO_SMALL
            } else {
                STATUS_INVALID_PARAMETER
            });
        }
        let identifier = parse_key_identifier(input)?;
        if read_u32(input, FSCRYPT_REMOVE_KEY_STATUS_FLAGS_OFFSET)? != 0
            || !all_zero(
                input,
                FSCRYPT_REMOVE_KEY_RESERVED_OFFSET,
                FSCRYPT_REMOVE_KEY_RESERVED_BYTES,
            )?
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self { identifier })
    }

    /// Key identifier selected for removal.
    const fn identifier(self) -> FscryptKeyIdentifier {
        self.identifier
    }
}

/// Parsed fscrypt key-status payload input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FscryptKeyStatusPayload {
    /// Key identifier selected for status.
    identifier: FscryptKeyIdentifier,
}

impl FscryptKeyStatusPayload {
    /// Parses the input fields of Linux `struct fscrypt_get_key_status_arg`.
    fn parse(input: &[u8]) -> Result<Self, NTSTATUS> {
        if input.len() < FSCRYPT_GET_KEY_STATUS_INPUT_BYTES {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let identifier = parse_key_identifier(input)?;
        if !all_zero(
            input,
            FSCRYPT_GET_KEY_STATUS_RESERVED_OFFSET,
            FSCRYPT_GET_KEY_STATUS_RESERVED_BYTES,
        )? {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self { identifier })
    }

    /// Key identifier selected for status.
    const fn identifier(self) -> FscryptKeyIdentifier {
        self.identifier
    }
}

/// Parsed fs-verity enable payload header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FsverityEnablePayload {
    /// Hash algorithm for the Merkle tree.
    algorithm: FsverityHashAlgorithm,
    /// Merkle tree block size.
    block_size: FsverityBlockSize,
    /// Salt pointer and byte length.
    salt: OptionalUserBuffer,
    /// Signature pointer and byte length.
    signature: OptionalUserBuffer,
}

impl FsverityEnablePayload {
    /// Parses Linux `struct fsverity_enable_arg`.
    fn parse(input: &[u8]) -> Result<Self, NTSTATUS> {
        if input.len() != FSVERITY_ENABLE_ARG_BYTES {
            return Err(if input.len() < FSVERITY_ENABLE_ARG_BYTES {
                STATUS_BUFFER_TOO_SMALL
            } else {
                STATUS_INVALID_PARAMETER
            });
        }
        if read_u32(input, FSVERITY_ENABLE_VERSION_OFFSET)? != FSVERITY_ENABLE_VERSION {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let algorithm = FsverityHashAlgorithm::parse_u32(read_u32(
            input,
            FSVERITY_ENABLE_HASH_ALGORITHM_OFFSET,
        )?)
        .map_err(|error| DriverError::from(error).ntstatus())?;
        let block_size =
            FsverityBlockSize::new(read_u32(input, FSVERITY_ENABLE_BLOCK_SIZE_OFFSET)?)
                .map_err(|error| DriverError::from(error).ntstatus())?;
        let salt = OptionalUserBuffer::new(
            read_u64(input, FSVERITY_ENABLE_SALT_PTR_OFFSET)?,
            read_u32(input, FSVERITY_ENABLE_SALT_SIZE_OFFSET)?,
            32,
        )?;
        let signature = OptionalUserBuffer::new(
            read_u64(input, FSVERITY_ENABLE_SIG_PTR_OFFSET)?,
            read_u32(input, FSVERITY_ENABLE_SIG_SIZE_OFFSET)?,
            FSVERITY_MAX_SIGNATURE_BYTES,
        )?;
        if read_u32(input, FSVERITY_ENABLE_RESERVED1_OFFSET)? != 0
            || !all_zero(
                input,
                FSVERITY_ENABLE_RESERVED2_OFFSET,
                FSVERITY_ENABLE_RESERVED2_BYTES,
            )?
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self {
            algorithm,
            block_size,
            salt,
            signature,
        })
    }

    /// Hash algorithm for the Merkle tree.
    const fn algorithm(self) -> FsverityHashAlgorithm {
        self.algorithm
    }

    /// Merkle tree block size.
    const fn block_size(self) -> FsverityBlockSize {
        self.block_size
    }

    /// Salt pointer and size.
    const fn salt(self) -> OptionalUserBuffer {
        self.salt
    }

    /// Signature pointer and size.
    const fn signature(self) -> OptionalUserBuffer {
        self.signature
    }
}

/// Optional pointer-sized buffer descriptor from Linux ioctl-compatible payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OptionalUserBuffer {
    /// User-mode address carried by the Linux layout.
    address: u64,
    /// Buffer length in bytes.
    length: u32,
}

impl OptionalUserBuffer {
    /// Creates a validated optional pointer/length pair.
    fn new(address: u64, length: u32, max_length: u32) -> Result<Self, NTSTATUS> {
        if length > max_length {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if (length == 0) != (address == 0) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Self { address, length })
    }

    /// Returns the raw user-mode address carried by the payload.
    const fn address(self) -> u64 {
        self.address
    }

    /// Returns the buffer length in bytes.
    const fn length(self) -> u32 {
        self.length
    }
}

/// Reads METHOD_BUFFERED input bytes for one user FSCTL.
fn read_input(target: DispatchTarget, stack: FileSystemControlStack) -> Result<Vec<u8>, NTSTATUS> {
    let length =
        usize::try_from(stack.input_buffer_length()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let input = target.data_buffer(length).map_err(DriverError::ntstatus)?;
    Ok(input.as_slice().to_vec())
}

/// Parses a Linux fscrypt v2 key identifier specifier.
fn parse_key_identifier(input: &[u8]) -> Result<FscryptKeyIdentifier, NTSTATUS> {
    if input.len() < FSCRYPT_KEY_SPECIFIER_BYTES {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    if read_u32(input, FSCRYPT_KEY_SPEC_TYPE_OFFSET)? != FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if read_u32(input, FSCRYPT_KEY_SPEC_RESERVED_OFFSET)? != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let identifier_offset = FSCRYPT_KEY_SPEC_UNION_OFFSET;
    let identifier_end = identifier_offset
        .checked_add(FSCRYPT_KEY_IDENTIFIER_BYTES)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let identifier = fixed::<FSCRYPT_KEY_IDENTIFIER_BYTES>(input, identifier_offset)?;
    if input
        .get(identifier_end..FSCRYPT_KEY_SPECIFIER_BYTES)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(FscryptKeyIdentifier::new(identifier))
}

/// Returns whether a checked range contains only zeroes.
fn all_zero(input: &[u8], offset: usize, len: usize) -> Result<bool, NTSTATUS> {
    let end = offset.checked_add(len).ok_or(STATUS_INVALID_PARAMETER)?;
    Ok(input
        .get(offset..end)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?
        .iter()
        .all(|byte| *byte == 0))
}

/// Reads one little-endian `u32` from a checked offset.
fn read_u32(input: &[u8], offset: usize) -> Result<u32, NTSTATUS> {
    Ok(u32::from_le_bytes(fixed(input, offset)?))
}

/// Reads one little-endian `u64` from a checked offset.
fn read_u64(input: &[u8], offset: usize) -> Result<u64, NTSTATUS> {
    Ok(u64::from_le_bytes(fixed(input, offset)?))
}

/// Writes one little-endian `u32` into a checked offset.
fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), NTSTATUS> {
    let end = offset.checked_add(4).ok_or(STATUS_INVALID_PARAMETER)?;
    output
        .get_mut(offset..end)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Writes one little-endian `u64` into a checked offset.
fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), NTSTATUS> {
    let end = offset.checked_add(8).ok_or(STATUS_INVALID_PARAMETER)?;
    output
        .get_mut(offset..end)
        .ok_or(STATUS_BUFFER_TOO_SMALL)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Copies a fixed byte array out of a checked range.
fn fixed<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], NTSTATUS> {
    let end = offset.checked_add(N).ok_or(STATUS_INVALID_PARAMETER)?;
    let slice = input.get(offset..end).ok_or(STATUS_BUFFER_TOO_SMALL)?;
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(slice);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// Deterministic raw key used by fscrypt FSCTL tests.
    const RAW_KEY: [u8; 32] = [7_u8; 32];

    #[test]
    fn fsctl_codes_are_ext4win_private_buffered_file_system_controls() {
        assert_eq!(FSCTL_EXT4WIN_ADD_ENCRYPTION_KEY, 0x0009_2400);
        assert_eq!(FSCTL_EXT4WIN_REMOVE_ENCRYPTION_KEY, 0x0009_2404);
        assert_eq!(FSCTL_EXT4WIN_GET_ENCRYPTION_KEY_STATUS, 0x0009_2408);
        assert_eq!(FSCTL_EXT4WIN_ENABLE_VERITY, 0x0009_240c);
    }

    #[test]
    fn fscrypt_add_key_payload_decodes_linux_layout() {
        let payload = add_key_payload(&RAW_KEY).expect("payload");

        let decoded = FscryptAddKeyPayload::parse(&payload).expect("decoded add key");

        assert_eq!(
            decoded.master_key().identifier(),
            FscryptMasterKey::from_raw(&RAW_KEY)
                .expect("master key")
                .identifier()
        );
    }

    #[test]
    fn fscrypt_add_key_payload_rejects_mismatched_identifier() {
        let mut payload = add_key_payload(&RAW_KEY).expect("payload");
        let identifier_byte = FSCRYPT_KEY_SPEC_UNION_OFFSET;
        if let Some(byte) = payload.get_mut(identifier_byte) {
            *byte ^= 0xff;
        }

        assert_eq!(
            FscryptAddKeyPayload::parse(&payload),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn fscrypt_add_key_payload_rejects_v1_descriptor_and_hw_wrapped_keys() {
        let mut descriptor = add_key_payload(&RAW_KEY).expect("payload");
        write_u32(&mut descriptor, FSCRYPT_KEY_SPEC_TYPE_OFFSET, 1).expect("write type");
        assert_eq!(
            FscryptAddKeyPayload::parse(&descriptor),
            Err(STATUS_NOT_SUPPORTED)
        );

        let mut hw_wrapped = add_key_payload(&RAW_KEY).expect("payload");
        write_u32(&mut hw_wrapped, FSCRYPT_ADD_KEY_FLAGS_OFFSET, 1).expect("write flags");
        assert_eq!(
            FscryptAddKeyPayload::parse(&hw_wrapped),
            Err(STATUS_NOT_SUPPORTED)
        );
    }

    #[test]
    fn fscrypt_remove_and_status_payloads_decode_identifier() {
        let identifier = FscryptMasterKey::from_raw(&RAW_KEY)
            .expect("master key")
            .identifier();
        let remove = remove_key_payload(identifier).expect("remove payload");
        let status = key_status_payload(identifier).expect("status payload");

        assert_eq!(
            FscryptRemoveKeyPayload::parse(&remove)
                .expect("remove")
                .identifier(),
            identifier
        );
        assert_eq!(
            FscryptKeyStatusPayload::parse(&status)
                .expect("status")
                .identifier(),
            identifier
        );
    }

    #[test]
    fn fsverity_enable_payload_decodes_linux_layout() {
        let payload = enable_verity_payload(
            2,
            4096,
            OptionalUserBuffer {
                address: 0x1000,
                length: 3,
            },
            OptionalUserBuffer {
                address: 0x2000,
                length: 16,
            },
        )
        .expect("payload");

        let decoded = FsverityEnablePayload::parse(&payload).expect("decoded verity");

        assert_eq!(decoded.algorithm(), FsverityHashAlgorithm::Sha512);
        assert_eq!(decoded.block_size().bytes(), 4096);
        assert_eq!(decoded.salt().address(), 0x1000);
        assert_eq!(decoded.salt().length(), 3);
        assert_eq!(decoded.signature().address(), 0x2000);
        assert_eq!(decoded.signature().length(), 16);
    }

    #[test]
    fn fsverity_enable_payload_rejects_reserved_and_bad_pointer_pairs() {
        let mut reserved = enable_verity_payload(
            1,
            1024,
            OptionalUserBuffer {
                address: 0,
                length: 0,
            },
            OptionalUserBuffer {
                address: 0,
                length: 0,
            },
        )
        .expect("payload");
        write_u32(&mut reserved, FSVERITY_ENABLE_RESERVED1_OFFSET, 1).expect("write reserved");
        assert_eq!(
            FsverityEnablePayload::parse(&reserved),
            Err(STATUS_INVALID_PARAMETER)
        );

        let bad_salt = enable_verity_payload(
            1,
            1024,
            OptionalUserBuffer {
                address: 0,
                length: 1,
            },
            OptionalUserBuffer {
                address: 0,
                length: 0,
            },
        )
        .expect("payload");
        assert_eq!(
            FsverityEnablePayload::parse(&bad_salt),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    /// Builds a Linux fscrypt add-key payload.
    fn add_key_payload(raw_key: &[u8]) -> Result<Vec<u8>, NTSTATUS> {
        let identifier = FscryptMasterKey::from_raw(raw_key)
            .map_err(|error| DriverError::from(error).ntstatus())?
            .identifier();
        let mut payload = vec![0_u8; FSCRYPT_ADD_KEY_FIXED_BYTES];
        write_key_identifier(&mut payload, identifier)?;
        write_u32(
            &mut payload,
            FSCRYPT_ADD_KEY_RAW_SIZE_OFFSET,
            u32::try_from(raw_key.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
        )?;
        payload.extend_from_slice(raw_key);
        Ok(payload)
    }

    /// Builds a Linux fscrypt remove-key payload.
    fn remove_key_payload(identifier: FscryptKeyIdentifier) -> Result<Vec<u8>, NTSTATUS> {
        let mut payload = vec![0_u8; FSCRYPT_REMOVE_KEY_BYTES];
        write_key_identifier(&mut payload, identifier)?;
        Ok(payload)
    }

    /// Builds a Linux fscrypt key-status payload.
    fn key_status_payload(identifier: FscryptKeyIdentifier) -> Result<Vec<u8>, NTSTATUS> {
        let mut payload = vec![0_u8; FSCRYPT_GET_KEY_STATUS_INPUT_BYTES];
        write_key_identifier(&mut payload, identifier)?;
        Ok(payload)
    }

    /// Writes a Linux fscrypt v2 key identifier specifier.
    fn write_key_identifier(
        payload: &mut [u8],
        identifier: FscryptKeyIdentifier,
    ) -> Result<(), NTSTATUS> {
        write_u32(
            payload,
            FSCRYPT_KEY_SPEC_TYPE_OFFSET,
            FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER,
        )?;
        let end = FSCRYPT_KEY_SPEC_UNION_OFFSET
            .checked_add(FSCRYPT_KEY_IDENTIFIER_BYTES)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        payload
            .get_mut(FSCRYPT_KEY_SPEC_UNION_OFFSET..end)
            .ok_or(STATUS_BUFFER_TOO_SMALL)?
            .copy_from_slice(&identifier.bytes());
        Ok(())
    }

    /// Builds a Linux fs-verity enable payload.
    fn enable_verity_payload(
        algorithm: u32,
        block_size: u32,
        salt: OptionalUserBuffer,
        signature: OptionalUserBuffer,
    ) -> Result<Vec<u8>, NTSTATUS> {
        let mut payload = vec![0_u8; FSVERITY_ENABLE_ARG_BYTES];
        write_u32(
            &mut payload,
            FSVERITY_ENABLE_VERSION_OFFSET,
            FSVERITY_ENABLE_VERSION,
        )?;
        write_u32(
            &mut payload,
            FSVERITY_ENABLE_HASH_ALGORITHM_OFFSET,
            algorithm,
        )?;
        write_u32(&mut payload, FSVERITY_ENABLE_BLOCK_SIZE_OFFSET, block_size)?;
        write_u32(
            &mut payload,
            FSVERITY_ENABLE_SALT_SIZE_OFFSET,
            salt.length(),
        )?;
        write_u64(
            &mut payload,
            FSVERITY_ENABLE_SALT_PTR_OFFSET,
            salt.address(),
        )?;
        write_u32(
            &mut payload,
            FSVERITY_ENABLE_SIG_SIZE_OFFSET,
            signature.length(),
        )?;
        write_u64(
            &mut payload,
            FSVERITY_ENABLE_SIG_PTR_OFFSET,
            signature.address(),
        )?;
        Ok(payload)
    }
}
