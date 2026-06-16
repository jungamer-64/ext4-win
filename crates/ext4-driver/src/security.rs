//! Windows security descriptor boundary for ext4 owner and mode bits.

use alloc::{vec, vec::Vec};
use core::ptr::NonNull;

use ext4_core::{Ext4Security, Node};
use wdk_sys::{
    NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

use crate::irp::{DispatchTarget, QuerySecurityStack};
use crate::state::{FileControlBlock, FileSystemNode, VolumeControlBlock, file_control_block};
use crate::status::DriverError;

/// SECURITY_DESCRIPTOR_RELATIVE byte size.
const SECURITY_DESCRIPTOR_RELATIVE_BYTES: usize = 20;
/// ACL header byte size.
const ACL_HEADER_BYTES: usize = 8;
/// ACCESS_ALLOWED_ACE bytes before the SID payload.
const ACCESS_ALLOWED_ACE_PREFIX_BYTES: usize = 8;
/// SID bytes before the first sub-authority.
const SID_PREFIX_BYTES: usize = 8;
/// SID authority used by Linux-style UID/GID SIDs (`S-1-22-*`).
const SECURITY_NT_NON_UNIQUE_AUTHORITY: u64 = 22;
/// World authority used by Everyone (`S-1-1-0`).
const SECURITY_WORLD_AUTHORITY: u64 = 1;

/// Handles IRP_MJ_QUERY_SECURITY.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QuerySecurityRequest::decode) {
        Ok(request) => query_security(request),
        Err(error) => error.ntstatus(),
    }
}

/// Handles IRP_MJ_SET_SECURITY.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(|target| target.current_stack()) {
        Ok(stack) => match stack.set_security() {
            Ok(stack) => {
                let _file_object = stack.file_object();
                let _security_information = stack.security_information();
                let _security_descriptor = stack.security_descriptor();
                STATUS_NOT_SUPPORTED
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Decoded query-security request.
#[derive(Clone, Copy, Debug)]
struct QuerySecurityRequest {
    /// Dispatch target receiving output.
    target: DispatchTarget,
    /// Decoded query-security stack.
    stack: QuerySecurityStack,
}

impl QuerySecurityRequest {
    /// Decodes a query-security request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        Ok(Self {
            target,
            stack: target.current_stack()?.query_security()?,
        })
    }
}

/// Binary SID used while building a self-relative descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BinarySid {
    /// Serialized SID bytes.
    bytes: Vec<u8>,
}

/// One allow ACE projected from a POSIX permission class.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AllowAce {
    /// Windows access mask.
    mask: u32,
    /// Trustee SID.
    sid: BinarySid,
}

/// Performs a security descriptor query.
fn query_security(request: QuerySecurityRequest) -> NTSTATUS {
    match load_ext4_security(request.stack.file_object()).and_then(|security| {
        let descriptor = security_descriptor(security, request.stack.security_information())?;
        let required = descriptor.len();
        request.target.set_information(
            wdk_sys::ULONG_PTR::try_from(required).map_err(|_| STATUS_INVALID_PARAMETER)?,
        );
        let length =
            usize::try_from(request.stack.length()).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if length < required {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let mut output = request
            .target
            .user_buffer(length)
            .map_err(|error| error.ntstatus())?;
        output
            .as_mut_slice()
            .get_mut(..required)
            .ok_or(STATUS_BUFFER_TOO_SMALL)?
            .copy_from_slice(descriptor.as_slice());
        Ok(())
    }) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// Loads ext4 security metadata for an opened node.
fn load_ext4_security(
    file_object: NonNull<wdk_sys::FILE_OBJECT>,
) -> Result<Ext4Security, NTSTATUS> {
    let fcb = file_control_block(file_object).map_err(DriverError::ntstatus)?;
    let fcb = unsafe {
        // SAFETY: Successful create stores Box<FileControlBlock> in FsContext
        // until close releases it, and this query runs while the FILE_OBJECT
        // is active.
        fcb.as_ref()
    };
    let vcb = volume_control_block(fcb);
    let node = vcb
        .volume()
        .read_node(fcb.node().inode())
        .map_err(|error| DriverError::from(error).ntstatus())?;
    security_from_node(fcb.node(), node)
}

/// Extracts security metadata after validating FCB kind against core metadata.
fn security_from_node(identity: FileSystemNode, node: Node) -> Result<Ext4Security, NTSTATUS> {
    match (identity, node) {
        (FileSystemNode::File(_), Node::File(file)) => Ok(file.security()),
        (FileSystemNode::Directory(_), Node::Directory(directory)) => Ok(directory.security()),
        (FileSystemNode::Symlink(_), Node::Symlink(symlink)) => Ok(symlink.security()),
        _ => Err(DriverError::from(ext4_core::Error::WrongInodeKind).ntstatus()),
    }
}

/// Builds a self-relative security descriptor for requested fields.
fn security_descriptor(
    security: Ext4Security,
    information: wdk_sys::SECURITY_INFORMATION,
) -> Result<Vec<u8>, NTSTATUS> {
    let supported = wdk_sys::OWNER_SECURITY_INFORMATION
        | wdk_sys::GROUP_SECURITY_INFORMATION
        | wdk_sys::DACL_SECURITY_INFORMATION;
    if information & wdk_sys::SACL_SECURITY_INFORMATION != 0 {
        return Err(DriverError::AccessDenied.ntstatus());
    }
    if information & !supported != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }

    let mut descriptor = vec![0; SECURITY_DESCRIPTOR_RELATIVE_BYTES];
    write_u8(
        &mut descriptor,
        0,
        u8::try_from(wdk_sys::SECURITY_DESCRIPTOR_REVISION)
            .map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    let mut control = wdk_sys::SE_SELF_RELATIVE;

    if information & wdk_sys::OWNER_SECURITY_INFORMATION != 0 {
        let owner = uid_sid(security.owner().uid().as_u32())?;
        let offset = append_component(&mut descriptor, owner.bytes.as_slice())?;
        write_u32(&mut descriptor, 4, offset)?;
    }
    if information & wdk_sys::GROUP_SECURITY_INFORMATION != 0 {
        let group = gid_sid(security.owner().gid().as_u32())?;
        let offset = append_component(&mut descriptor, group.bytes.as_slice())?;
        write_u32(&mut descriptor, 8, offset)?;
    }
    if information & wdk_sys::DACL_SECURITY_INFORMATION != 0 {
        control |= wdk_sys::SE_DACL_PRESENT;
        let dacl = dacl_from_permissions(security)?;
        let offset = append_component(&mut descriptor, dacl.as_slice())?;
        write_u32(&mut descriptor, 16, offset)?;
    }

    write_u16(
        &mut descriptor,
        2,
        u16::try_from(control).map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    Ok(descriptor)
}

/// Builds a DACL with owner, group, and everyone allow ACEs from POSIX mode bits.
fn dacl_from_permissions(security: Ext4Security) -> Result<Vec<u8>, NTSTATUS> {
    let permissions = security.permissions().as_u16();
    let owner = permission_class_mask((permissions >> 6) & 0o7);
    let group = permission_class_mask((permissions >> 3) & 0o7);
    let other = permission_class_mask(permissions & 0o7);
    let mut aces = Vec::new();
    if owner != 0 {
        aces.push(AllowAce {
            mask: owner,
            sid: uid_sid(security.owner().uid().as_u32())?,
        });
    }
    if group != 0 {
        aces.push(AllowAce {
            mask: group,
            sid: gid_sid(security.owner().gid().as_u32())?,
        });
    }
    if other != 0 {
        aces.push(AllowAce {
            mask: other,
            sid: everyone_sid()?,
        });
    }

    let mut acl = vec![0; ACL_HEADER_BYTES];
    write_u8(
        &mut acl,
        0,
        u8::try_from(wdk_sys::ACL_REVISION).map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    write_u16(
        &mut acl,
        4,
        u16::try_from(aces.len()).map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    for ace in &aces {
        append_allow_ace(&mut acl, ace)?;
    }
    let acl_len = u16::try_from(acl.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    write_u16(&mut acl, 2, acl_len)?;
    Ok(acl)
}

/// Returns a Windows access mask for a POSIX rwx permission class.
fn permission_class_mask(bits: u16) -> u32 {
    let mut mask = 0;
    if bits & 0o4 != 0 {
        mask |= wdk_sys::FILE_GENERIC_READ;
    }
    if bits & 0o2 != 0 {
        mask |= wdk_sys::FILE_GENERIC_WRITE;
    }
    if bits & 0o1 != 0 {
        mask |= wdk_sys::FILE_GENERIC_EXECUTE;
    }
    mask
}

/// Appends one component to the self-relative descriptor.
fn append_component(descriptor: &mut Vec<u8>, component: &[u8]) -> Result<u32, NTSTATUS> {
    let offset = u32::try_from(descriptor.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    descriptor.extend_from_slice(component);
    Ok(offset)
}

/// Appends one ACCESS_ALLOWED_ACE to an ACL image.
fn append_allow_ace(acl: &mut Vec<u8>, ace: &AllowAce) -> Result<(), NTSTATUS> {
    let ace_size = ACCESS_ALLOWED_ACE_PREFIX_BYTES
        .checked_add(ace.sid.bytes.len())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let start = acl.len();
    acl.resize(
        start
            .checked_add(ace_size)
            .ok_or(STATUS_INVALID_PARAMETER)?,
        0,
    );
    write_u8(
        acl,
        start,
        u8::try_from(wdk_sys::ACCESS_ALLOWED_ACE_TYPE).map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    write_u16(
        acl,
        start.checked_add(2).ok_or(STATUS_INVALID_PARAMETER)?,
        u16::try_from(ace_size).map_err(|_| STATUS_INVALID_PARAMETER)?,
    )?;
    write_u32(
        acl,
        start.checked_add(4).ok_or(STATUS_INVALID_PARAMETER)?,
        ace.mask,
    )?;
    write_bytes(
        acl,
        start
            .checked_add(ACCESS_ALLOWED_ACE_PREFIX_BYTES)
            .ok_or(STATUS_INVALID_PARAMETER)?,
        ace.sid.bytes.as_slice(),
    )
}

/// Builds `S-1-22-1-uid`.
fn uid_sid(uid: u32) -> Result<BinarySid, NTSTATUS> {
    sid(SECURITY_NT_NON_UNIQUE_AUTHORITY, &[1, uid])
}

/// Builds `S-1-22-2-gid`.
fn gid_sid(gid: u32) -> Result<BinarySid, NTSTATUS> {
    sid(SECURITY_NT_NON_UNIQUE_AUTHORITY, &[2, gid])
}

/// Builds Everyone, `S-1-1-0`.
fn everyone_sid() -> Result<BinarySid, NTSTATUS> {
    sid(SECURITY_WORLD_AUTHORITY, &[0])
}

/// Builds a binary SID from an authority and sub-authorities.
fn sid(authority: u64, sub_authorities: &[u32]) -> Result<BinarySid, NTSTATUS> {
    let sub_authority_count =
        u8::try_from(sub_authorities.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let capacity = SID_PREFIX_BYTES
        .checked_add(
            sub_authorities
                .len()
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(STATUS_INVALID_PARAMETER)?,
        )
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(u8::try_from(wdk_sys::SID_REVISION).map_err(|_| STATUS_INVALID_PARAMETER)?);
    bytes.push(sub_authority_count);
    let authority = authority.to_be_bytes();
    let Some(authority) = authority.get(2..) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    bytes.extend_from_slice(authority);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(sub_authority.to_le_bytes().as_slice());
    }
    Ok(BinarySid { bytes })
}

/// Returns the mounted VCB referenced by an FCB.
fn volume_control_block(fcb: &FileControlBlock) -> &VolumeControlBlock {
    unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers and
        // remain valid while file objects are open.
        fcb.volume().as_ref()
    }
}

/// Writes one byte into a byte buffer.
fn write_u8(output: &mut [u8], offset: usize, value: u8) -> Result<(), NTSTATUS> {
    let Some(target) = output.get_mut(offset) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    *target = value;
    Ok(())
}

/// Writes a little-endian `u16`.
fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u16>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    target.copy_from_slice(value.to_le_bytes().as_slice());
    Ok(())
}

/// Writes a little-endian `u32`.
fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), NTSTATUS> {
    let end = offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    target.copy_from_slice(value.to_le_bytes().as_slice());
    Ok(())
}

/// Writes raw bytes into a byte buffer.
fn write_bytes(output: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), NTSTATUS> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let Some(target) = output.get_mut(offset..end) else {
        return Err(STATUS_BUFFER_TOO_SMALL);
    };
    target.copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid};

    use super::{
        dacl_from_permissions, gid_sid, permission_class_mask, security_descriptor, uid_sid,
    };

    #[test]
    fn uid_and_gid_sids_use_linux_sid_authority() {
        assert_eq!(
            uid_sid(1000).map(|sid| sid.bytes),
            Ok(vec![1, 2, 0, 0, 0, 0, 0, 22, 1, 0, 0, 0, 232, 3, 0, 0])
        );
        assert_eq!(
            gid_sid(100).map(|sid| sid.bytes),
            Ok(vec![1, 2, 0, 0, 0, 0, 0, 22, 2, 0, 0, 0, 100, 0, 0, 0])
        );
    }

    #[test]
    fn permission_classes_project_to_file_generic_masks() {
        assert_eq!(permission_class_mask(0o0), 0);
        assert_eq!(permission_class_mask(0o4), wdk_sys::FILE_GENERIC_READ);
        assert_eq!(permission_class_mask(0o2), wdk_sys::FILE_GENERIC_WRITE);
        assert_eq!(permission_class_mask(0o1), wdk_sys::FILE_GENERIC_EXECUTE);
    }

    #[test]
    fn dacl_contains_owner_group_and_everyone_aces() {
        let permissions = Ext4Permissions::new(0o754);
        assert!(permissions.is_ok());
        if let Ok(permissions) = permissions {
            let security = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(100)),
                permissions,
            );
            let dacl = dacl_from_permissions(security);
            assert!(dacl.is_ok());
            if let Ok(dacl) = dacl {
                assert_eq!(read_test_u16(dacl.as_slice(), 2), Some(76));
                assert_eq!(read_test_u16(dacl.as_slice(), 4), Some(3));
                assert_eq!(read_test_u16(dacl.as_slice(), 10), Some(24));
                assert_eq!(read_test_u16(dacl.as_slice(), 34), Some(24));
                assert_eq!(read_test_u16(dacl.as_slice(), 58), Some(20));
            }
        }
    }

    #[test]
    fn security_descriptor_packs_requested_owner_group_and_dacl() {
        let permissions = Ext4Permissions::new(0o754);
        assert!(permissions.is_ok());
        if let Ok(permissions) = permissions {
            let security = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(100)),
                permissions,
            );
            let descriptor = security_descriptor(
                security,
                wdk_sys::OWNER_SECURITY_INFORMATION
                    | wdk_sys::GROUP_SECURITY_INFORMATION
                    | wdk_sys::DACL_SECURITY_INFORMATION,
            );
            assert!(descriptor.is_ok());
            if let Ok(descriptor) = descriptor {
                assert_eq!(read_test_u16(descriptor.as_slice(), 2), Some(32772));
                assert_eq!(read_test_u32(descriptor.as_slice(), 4), Some(20));
                assert_eq!(read_test_u32(descriptor.as_slice(), 8), Some(36));
                assert_eq!(read_test_u32(descriptor.as_slice(), 16), Some(52));
            }
        }
    }

    fn read_test_u16(bytes: &[u8], offset: usize) -> Option<u16> {
        let end = offset.checked_add(core::mem::size_of::<u16>())?;
        let slice = bytes.get(offset..end)?;
        let array: [u8; 2] = slice.try_into().ok()?;
        Some(u16::from_le_bytes(array))
    }

    fn read_test_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(core::mem::size_of::<u32>())?;
        let slice = bytes.get(offset..end)?;
        let array: [u8; 4] = slice.try_into().ok()?;
        Some(u32::from_le_bytes(array))
    }
}
