//! Windows security descriptor boundary for ext4 owner and mode bits.

use alloc::{vec, vec::Vec};
use core::ptr::NonNull;

use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid, LoadedNode, NodeId};
use wdk_sys::{NTSTATUS, PDEVICE_OBJECT, PIRP, STATUS_SUCCESS};

use crate::irp::{
    DispatchTarget, DriverCompletion, QuerySecurityStack, SecurityComponentSelection,
    SecuritySelection, SetSecurityStack,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::state::{FileControlBlock, OpenedFileObject, VolumeControlBlock};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};

/// SECURITY_DESCRIPTOR_RELATIVE byte size.
const SECURITY_DESCRIPTOR_RELATIVE_BYTES: usize = 20;
/// ACL header byte size.
const ACL_HEADER_BYTES: usize = 8;
/// ACCESS_ALLOWED_ACE bytes before the SID payload.
const ACCESS_ALLOWED_ACE_PREFIX_BYTES: usize = 8;
/// SID bytes before the first sub-authority.
const SID_PREFIX_BYTES: usize = 8;
/// SECURITY_DESCRIPTOR_RELATIVE owner SID offset.
const SECURITY_DESCRIPTOR_OWNER_OFFSET: usize = 4;
/// SECURITY_DESCRIPTOR_RELATIVE group SID offset.
const SECURITY_DESCRIPTOR_GROUP_OFFSET: usize = 8;
/// SECURITY_DESCRIPTOR_RELATIVE DACL offset.
const SECURITY_DESCRIPTOR_DACL_OFFSET: usize = 16;
/// ACL size field offset.
const ACL_SIZE_OFFSET: usize = 2;
/// ACL ACE count field offset.
const ACL_ACE_COUNT_OFFSET: usize = 4;
/// ACCESS_ALLOWED_ACE mask field offset.
const ACE_MASK_OFFSET: usize = 4;
/// ACCESS_ALLOWED_ACE SID payload offset.
const ACE_SID_OFFSET: usize = 8;
/// SID authority used by Linux-style UID/GID SIDs (`S-1-22-*`).
const SECURITY_NT_NON_UNIQUE_AUTHORITY: u64 = 22;
/// World authority used by Everyone (`S-1-1-0`).
const SECURITY_WORLD_AUTHORITY: u64 = 1;
/// POSIX permission bits stored in ext4 mode.
const POSIX_RWX_BITS: u16 = 0o777;

/// Handles IRP_MJ_QUERY_SECURITY.
pub(crate) fn query(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(QuerySecurityRequest::decode) {
        Ok(request) => match query_security(&request) {
            Ok(completion) => {
                request.target.complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Handles IRP_MJ_SET_SECURITY.
pub(crate) fn set(device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    match DispatchTarget::decode(device, irp).and_then(SetSecurityRequest::decode) {
        Ok(request) => match set_security(&request) {
            Ok(completion) => {
                request.target.complete(completion);
                STATUS_SUCCESS
            }
            Err(error) => error.ntstatus(),
        },
        Err(error) => error.ntstatus(),
    }
}

/// Decoded query-security request.
#[derive(Debug)]
struct QuerySecurityRequest {
    /// Dispatch target receiving output.
    target: DispatchTarget,
    /// Decoded query-security stack.
    stack: QuerySecurityStack,
    /// Opened file contexts decoded before security handling.
    opened_file: OpenedFileObject,
}

impl QuerySecurityRequest {
    /// Decodes a query-security request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.query_security()?;
        let opened_file = OpenedFileObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
        })
    }
}

/// Decoded set-security request.
#[derive(Debug)]
struct SetSecurityRequest {
    /// Dispatch target receiving completion.
    target: DispatchTarget,
    /// Decoded set-security stack.
    stack: SetSecurityStack,
    /// Opened file contexts decoded before security handling.
    opened_file: OpenedFileObject,
}

impl SetSecurityRequest {
    /// Decodes a set-security request.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.set_security()?;
        let opened_file = OpenedFileObject::decode(stack.file_object())?;
        Ok(Self {
            target,
            stack,
            opened_file,
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

/// Open security state needed for journaled security mutations.
#[derive(Clone, Copy, Debug)]
struct OpenedSecurityContext {
    /// Mounted VCB owning the open file.
    volume: NonNull<VolumeControlBlock>,
    /// ext4 node opened by this FILE_OBJECT.
    node: NodeId,
    /// Current POSIX security metadata.
    security: Ext4Security,
}

/// Parsed self-relative Windows security descriptor.
#[derive(Clone, Copy, Debug)]
struct ParsedSecurityDescriptor<'a> {
    /// Original descriptor image.
    bytes: &'a [u8],
    /// Descriptor control flags.
    control: u16,
    /// Owner SID offset.
    owner_offset: u32,
    /// Group SID offset.
    group_offset: u32,
    /// DACL offset.
    dacl_offset: u32,
}

/// SID identity accepted by the ext4 Windows security boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SidIdentity {
    /// Linux UID SID, `S-1-22-1-uid`.
    LinuxUid(u32),
    /// Linux GID SID, `S-1-22-2-gid`.
    LinuxGid(u32),
    /// Everyone SID, `S-1-1-0`.
    Everyone,
}

/// POSIX permission class addressed by one allow ACE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermissionClass {
    /// Owner rwx class.
    Owner,
    /// Group rwx class.
    Group,
    /// Other rwx class.
    Other,
}

/// Parsed permission bits for one POSIX class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PermissionClassBits {
    /// POSIX class represented by an ACE.
    class: PermissionClass,
    /// rwx bits decoded from the Windows access mask.
    bits: u16,
}

/// Duplicate-checking builder for POSIX permission bits parsed from a DACL.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DaclPermissionBuilder {
    /// Permission classes observed in DACL order.
    classes: Vec<PermissionClassBits>,
}

impl DaclPermissionBuilder {
    /// Stores one parsed permission class.
    fn set(&mut self, class: PermissionClass, bits: u16) -> DriverResult<()> {
        if self.classes.iter().any(|entry| entry.class == class) {
            return Err(DriverError::NotSupported);
        }
        self.classes.push(PermissionClassBits { class, bits });
        Ok(())
    }

    /// Converts parsed classes into POSIX rwx mode bits.
    fn mode_bits(&self) -> u16 {
        let mut mode = 0_u16;
        for entry in &self.classes {
            match entry.class {
                PermissionClass::Owner => mode |= entry.bits << 6,
                PermissionClass::Group => mode |= entry.bits << 3,
                PermissionClass::Other => mode |= entry.bits,
            }
        }
        mode
    }
}

/// Performs a security descriptor query.
fn query_security(request: &QuerySecurityRequest) -> DriverResult<DriverCompletion> {
    let security = load_ext4_security(&request.opened_file)?;
    let descriptor = security_descriptor(security, request.stack.selection())?;
    let required = descriptor.len();
    let length = request.stack.length().as_usize();
    if length < required {
        return Err(DriverError::BufferTooSmall);
    }
    let mut output = request.target.user_buffer(length)?;
    LittleEndianOutput::new(output.as_mut_slice())
        .write_bytes(wire_offset(0), descriptor.as_slice())?;
    DriverCompletion::from_usize(required)
}

/// Performs a POSIX security mutation from a Windows security descriptor.
fn set_security(request: &SetSecurityRequest) -> DriverResult<DriverCompletion> {
    let context = load_ext4_security_context(&request.opened_file)?;
    let descriptor = security_descriptor_bytes(
        request.stack.security_descriptor().as_non_null(),
        request.stack.selection(),
    )?;
    let security = security_from_descriptor(
        descriptor.as_slice(),
        request.stack.selection(),
        context.security,
    )?;
    if security == context.security {
        return Ok(DriverCompletion::EMPTY);
    }

    let mut vcb = context.volume;
    let vcb = unsafe {
        // SAFETY: FCBs are constructed only from live mounted VCB pointers
        // and remain valid while file objects are open. The mutable borrow is
        // the transaction boundary for this synchronous security mutation.
        vcb.as_mut()
    };
    let mut transaction = vcb
        .volume_mut()
        .begin_transaction(crate::kernel::time::current_ext4_timestamp()?);
    let node = transaction.node(context.node)?;
    transaction.set_posix_security(node, security)?;
    transaction.commit()?;
    Ok(DriverCompletion::EMPTY)
}

/// Loads ext4 security metadata for an opened node.
fn load_ext4_security(opened_file: &OpenedFileObject) -> DriverResult<Ext4Security> {
    load_ext4_security_context(opened_file).map(|context| context.security)
}

/// Loads ext4 security context for an opened node.
fn load_ext4_security_context(
    opened_file: &OpenedFileObject,
) -> DriverResult<OpenedSecurityContext> {
    let fcb = opened_file.file_control_block();
    let vcb = volume_control_block(fcb);
    let node = vcb.volume().load_node(fcb.node().inode())?;
    Ok(OpenedSecurityContext {
        volume: fcb.volume(),
        node: fcb.node(),
        security: security_from_node(fcb.node(), node)?,
    })
}

/// Extracts security metadata after validating FCB kind against core metadata.
fn security_from_node(identity: NodeId, node: LoadedNode) -> DriverResult<Ext4Security> {
    match (identity, node) {
        (NodeId::File(_), LoadedNode::File(file)) => Ok(file.security()),
        (NodeId::Directory(_), LoadedNode::Directory(directory)) => Ok(directory.security()),
        (NodeId::Symlink(_), LoadedNode::Symlink(symlink)) => Ok(symlink.security()),
        _ => Err(DriverError::from(ext4_core::Error::WrongInodeKind)),
    }
}

/// Builds a self-relative security descriptor for requested fields.
fn security_descriptor(
    security: Ext4Security,
    selection: SecuritySelection,
) -> DriverResult<Vec<u8>> {
    let mut descriptor = vec![0; SECURITY_DESCRIPTOR_RELATIVE_BYTES];
    LittleEndianOutput::new(descriptor.as_mut_slice()).write_u8(
        wire_offset(0),
        u8::try_from(wdk_sys::SECURITY_DESCRIPTOR_REVISION)
            .map_err(|_| DriverError::InvalidParameter)?,
    )?;
    let mut control = wdk_sys::SE_SELF_RELATIVE;

    if matches!(selection.owner(), SecurityComponentSelection::Selected) {
        let owner = uid_sid(security.owner().uid().as_u32())?;
        let offset = append_component(&mut descriptor, owner.bytes.as_slice())?;
        LittleEndianOutput::new(descriptor.as_mut_slice()).write_u32(wire_offset(4), offset)?;
    }
    if matches!(selection.group(), SecurityComponentSelection::Selected) {
        let group = gid_sid(security.owner().gid().as_u32())?;
        let offset = append_component(&mut descriptor, group.bytes.as_slice())?;
        LittleEndianOutput::new(descriptor.as_mut_slice()).write_u32(wire_offset(8), offset)?;
    }
    if matches!(selection.dacl(), SecurityComponentSelection::Selected) {
        control |= wdk_sys::SE_DACL_PRESENT;
        let dacl = dacl_from_permissions(security)?;
        let offset = append_component(&mut descriptor, dacl.as_slice())?;
        LittleEndianOutput::new(descriptor.as_mut_slice()).write_u32(wire_offset(16), offset)?;
    }

    LittleEndianOutput::new(descriptor.as_mut_slice()).write_u16(
        wire_offset(2),
        u16::try_from(control).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    Ok(descriptor)
}

/// Copies the raw SetSecurity descriptor into a bounded byte image.
fn security_descriptor_bytes(
    security_descriptor: NonNull<core::ffi::c_void>,
    selection: SecuritySelection,
) -> DriverResult<Vec<u8>> {
    let pointer = security_descriptor.cast::<u8>();
    let mut length = SECURITY_DESCRIPTOR_RELATIVE_BYTES;
    let header = unsafe {
        // SAFETY: The I/O Manager supplies a non-null security descriptor
        // pointer for IRP_MJ_SET_SECURITY. Only the fixed header is read here;
        // component reads below are selected by validated offsets.
        core::slice::from_raw_parts(pointer.as_ptr(), SECURITY_DESCRIPTOR_RELATIVE_BYTES)
    };
    let descriptor = ParsedSecurityDescriptor::parse(header)?;

    if matches!(selection.owner(), SecurityComponentSelection::Selected) {
        length = length.max(raw_sid_end(pointer, descriptor.owner_offset)?);
    }
    if matches!(selection.group(), SecurityComponentSelection::Selected) {
        length = length.max(raw_sid_end(pointer, descriptor.group_offset)?);
    }
    if matches!(selection.dacl(), SecurityComponentSelection::Selected) {
        length = length.max(raw_acl_end(pointer, descriptor.dacl_offset)?);
    }

    let bytes = unsafe {
        // SAFETY: Length was derived from the self-relative descriptor's SID
        // and ACL size fields. Windows owns the descriptor for this dispatch.
        core::slice::from_raw_parts(pointer.as_ptr(), length)
    };
    Ok(bytes.to_vec())
}

/// Builds new ext4 security metadata from a Windows security descriptor.
fn security_from_descriptor(
    descriptor: &[u8],
    selection: SecuritySelection,
    current: Ext4Security,
) -> DriverResult<Ext4Security> {
    let descriptor = ParsedSecurityDescriptor::parse(descriptor)?;
    let mut owner = current.owner();
    if matches!(selection.owner(), SecurityComponentSelection::Selected) {
        let uid = descriptor.owner_uid()?;
        owner = Ext4Owner::new(Ext4Uid::from_u32(uid), owner.gid());
    }
    if matches!(selection.group(), SecurityComponentSelection::Selected) {
        let gid = descriptor.group_gid()?;
        owner = Ext4Owner::new(owner.uid(), Ext4Gid::from_u32(gid));
    }

    let mut permissions = current.permissions().as_u16();
    if matches!(selection.dacl(), SecurityComponentSelection::Selected) {
        let low_bits = descriptor.dacl_permissions(owner)?;
        permissions = (permissions & !POSIX_RWX_BITS) | low_bits;
    }

    Ok(Ext4Security::new(owner, Ext4Permissions::new(permissions)?))
}

impl<'a> ParsedSecurityDescriptor<'a> {
    /// Parses a self-relative Windows security descriptor.
    fn parse(bytes: &'a [u8]) -> DriverResult<Self> {
        if bytes.len() < SECURITY_DESCRIPTOR_RELATIVE_BYTES {
            return Err(DriverError::InvalidParameter);
        }
        let fields = LittleEndianInput::new(bytes);
        let revision = malformed_security(fields.read_u8(wire_offset(0)))?;
        if u32::from(revision) != wdk_sys::SECURITY_DESCRIPTOR_REVISION {
            return Err(DriverError::InvalidParameter);
        }
        let control = malformed_security(fields.read_u16(wire_offset(2)))?;
        let self_relative =
            u16::try_from(wdk_sys::SE_SELF_RELATIVE).map_err(|_| DriverError::InvalidParameter)?;
        if control & self_relative == 0 {
            return Err(DriverError::NotSupported);
        }
        let sacl_present =
            u16::try_from(wdk_sys::SE_SACL_PRESENT).map_err(|_| DriverError::InvalidParameter)?;
        if control & sacl_present != 0 {
            return Err(DriverError::AccessDenied);
        }

        Ok(Self {
            bytes,
            control,
            owner_offset: malformed_security(
                fields.read_u32(wire_offset(SECURITY_DESCRIPTOR_OWNER_OFFSET)),
            )?,
            group_offset: malformed_security(
                fields.read_u32(wire_offset(SECURITY_DESCRIPTOR_GROUP_OFFSET)),
            )?,
            dacl_offset: malformed_security(
                fields.read_u32(wire_offset(SECURITY_DESCRIPTOR_DACL_OFFSET)),
            )?,
        })
    }

    /// Returns the owner UID represented by the owner SID.
    fn owner_uid(self) -> DriverResult<u32> {
        match sid_identity(self.sid_at(self.owner_offset)?)? {
            SidIdentity::LinuxUid(uid) => Ok(uid),
            SidIdentity::LinuxGid(_) | SidIdentity::Everyone => Err(DriverError::NotSupported),
        }
    }

    /// Returns the group GID represented by the group SID.
    fn group_gid(self) -> DriverResult<u32> {
        match sid_identity(self.sid_at(self.group_offset)?)? {
            SidIdentity::LinuxGid(gid) => Ok(gid),
            SidIdentity::LinuxUid(_) | SidIdentity::Everyone => Err(DriverError::NotSupported),
        }
    }

    /// Returns low POSIX rwx bits represented by the descriptor DACL.
    fn dacl_permissions(self, owner: Ext4Owner) -> DriverResult<u16> {
        let dacl_present =
            u16::try_from(wdk_sys::SE_DACL_PRESENT).map_err(|_| DriverError::InvalidParameter)?;
        if self.control & dacl_present == 0 || self.dacl_offset == 0 {
            return Err(DriverError::NotSupported);
        }
        let acl = self.acl_at(self.dacl_offset)?;
        parse_dacl_permissions(acl, owner)
    }

    /// Returns a SID component at a self-relative descriptor offset.
    fn sid_at(self, offset: u32) -> DriverResult<&'a [u8]> {
        if offset == 0 {
            return Err(DriverError::InvalidParameter);
        }
        let start = usize::try_from(offset).map_err(|_| DriverError::InvalidParameter)?;
        let header = security_range(self.bytes, start, SID_PREFIX_BYTES)?;
        let count = usize::from(malformed_security(
            LittleEndianInput::new(header).read_u8(wire_offset(1)),
        )?);
        let sid_len = sid_length_from_sub_authorities(count)?;
        let _end = start
            .checked_add(sid_len)
            .ok_or(DriverError::InvalidParameter)?;
        security_range(self.bytes, start, sid_len)
    }

    /// Returns an ACL component at a self-relative descriptor offset.
    fn acl_at(self, offset: u32) -> DriverResult<&'a [u8]> {
        let start = usize::try_from(offset).map_err(|_| DriverError::InvalidParameter)?;
        let header = security_range(self.bytes, start, ACL_HEADER_BYTES)?;
        let acl_len = usize::from(malformed_security(
            LittleEndianInput::new(header).read_u16(wire_offset(ACL_SIZE_OFFSET)),
        )?);
        let _end = start
            .checked_add(acl_len)
            .ok_or(DriverError::InvalidParameter)?;
        security_range(self.bytes, start, acl_len)
    }
}

/// Returns the byte end of a raw SID component.
fn raw_sid_end(pointer: NonNull<u8>, offset: u32) -> DriverResult<usize> {
    if offset == 0 {
        return Err(DriverError::InvalidParameter);
    }
    let start = usize::try_from(offset).map_err(|_| DriverError::InvalidParameter)?;
    let count_offset = start.checked_add(1).ok_or(DriverError::InvalidParameter)?;
    let count_pointer = unsafe {
        // SAFETY: The offset is selected from a self-relative security
        // descriptor supplied by the I/O Manager.
        pointer.as_ptr().add(count_offset)
    };
    let count = unsafe {
        // SAFETY: `count_pointer` addresses the SID sub-authority count byte
        // selected above.
        *count_pointer
    };
    let sid_len = sid_length_from_sub_authorities(usize::from(count))?;
    start
        .checked_add(sid_len)
        .ok_or(DriverError::InvalidParameter)
}

/// Returns the byte end of a raw ACL component.
fn raw_acl_end(pointer: NonNull<u8>, offset: u32) -> DriverResult<usize> {
    if offset == 0 {
        return Err(DriverError::NotSupported);
    }
    let start = usize::try_from(offset).map_err(|_| DriverError::InvalidParameter)?;
    let acl_size_offset = start
        .checked_add(ACL_SIZE_OFFSET)
        .ok_or(DriverError::InvalidParameter)?;
    let acl_size_pointer = unsafe {
        // SAFETY: The offset is selected from a self-relative security
        // descriptor supplied by the I/O Manager.
        pointer.as_ptr().add(acl_size_offset)
    };
    let size_bytes = unsafe {
        // SAFETY: `acl_size_pointer` addresses the two-byte ACL size field
        // used to bound the subsequent copy.
        core::slice::from_raw_parts(acl_size_pointer, 2)
    };
    let acl_len = usize::from(malformed_security(
        LittleEndianInput::new(size_bytes).read_u16(wire_offset(0)),
    )?);
    start
        .checked_add(acl_len)
        .ok_or(DriverError::InvalidParameter)
}

/// Returns the serialized SID length for a sub-authority count.
fn sid_length_from_sub_authorities(count: usize) -> DriverResult<usize> {
    SID_PREFIX_BYTES
        .checked_add(
            count
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(DriverError::InvalidParameter)?,
        )
        .ok_or(DriverError::InvalidParameter)
}

/// Parses a DACL into POSIX rwx permission bits.
fn parse_dacl_permissions(acl: &[u8], owner: Ext4Owner) -> DriverResult<u16> {
    if acl.len() < ACL_HEADER_BYTES {
        return Err(DriverError::InvalidParameter);
    }
    let fields = LittleEndianInput::new(acl);
    let revision = malformed_security(fields.read_u8(wire_offset(0)))?;
    if u32::from(revision) != wdk_sys::ACL_REVISION {
        return Err(DriverError::NotSupported);
    }
    let acl_len = usize::from(malformed_security(
        fields.read_u16(wire_offset(ACL_SIZE_OFFSET)),
    )?);
    if acl_len != acl.len() {
        return Err(DriverError::InvalidParameter);
    }
    let ace_count = usize::from(malformed_security(
        fields.read_u16(wire_offset(ACL_ACE_COUNT_OFFSET)),
    )?);
    let mut cursor = ACL_HEADER_BYTES;
    let mut parsed = DaclPermissionBuilder::default();
    for _ in 0..ace_count {
        let ace_header = security_range(acl, cursor, 4)?;
        let ace_fields = LittleEndianInput::new(ace_header);
        let ace_type = malformed_security(ace_fields.read_u8(wire_offset(0)))?;
        let ace_flags = malformed_security(ace_fields.read_u8(wire_offset(1)))?;
        let ace_size = usize::from(malformed_security(ace_fields.read_u16(wire_offset(2)))?);
        if ace_size < ACCESS_ALLOWED_ACE_PREFIX_BYTES {
            return Err(DriverError::InvalidParameter);
        }
        let ace_end = cursor
            .checked_add(ace_size)
            .ok_or(DriverError::InvalidParameter)?;
        let ace = security_range(acl, cursor, ace_size)?;
        parse_allow_ace(ace_type, ace_flags, ace, owner, &mut parsed)?;
        cursor = ace_end;
    }
    if cursor != acl.len() {
        return Err(DriverError::InvalidParameter);
    }
    Ok(parsed.mode_bits())
}

/// Parses one allow ACE into a POSIX permission class.
fn parse_allow_ace(
    ace_type: u8,
    ace_flags: u8,
    ace: &[u8],
    owner: Ext4Owner,
    parsed: &mut DaclPermissionBuilder,
) -> DriverResult<()> {
    if u32::from(ace_type) != wdk_sys::ACCESS_ALLOWED_ACE_TYPE {
        return Err(DriverError::NotSupported);
    }
    if ace_flags != 0 {
        return Err(DriverError::NotSupported);
    }
    let mask =
        malformed_security(LittleEndianInput::new(ace).read_u32(wire_offset(ACE_MASK_OFFSET)))?;
    let bits = permission_bits_from_mask(mask)?;
    let sid_len = ace
        .len()
        .checked_sub(ACE_SID_OFFSET)
        .ok_or(DriverError::InvalidParameter)?;
    let sid = security_range(ace, ACE_SID_OFFSET, sid_len)?;
    let class = permission_class_from_sid(sid_identity(sid)?, owner)?;
    parsed.set(class, bits)
}

/// Maps one accepted Windows access mask back to POSIX rwx bits.
fn permission_bits_from_mask(mask: u32) -> DriverResult<u16> {
    for bits in 0..=0o7 {
        if permission_class_mask(bits) == mask {
            return Ok(bits);
        }
    }
    Err(DriverError::NotSupported)
}

/// Classifies a SID for DACL permission projection.
fn permission_class_from_sid(sid: SidIdentity, owner: Ext4Owner) -> DriverResult<PermissionClass> {
    match sid {
        SidIdentity::LinuxUid(uid) if uid == owner.uid().as_u32() => Ok(PermissionClass::Owner),
        SidIdentity::LinuxGid(gid) if gid == owner.gid().as_u32() => Ok(PermissionClass::Group),
        SidIdentity::Everyone => Ok(PermissionClass::Other),
        SidIdentity::LinuxUid(_) | SidIdentity::LinuxGid(_) => Err(DriverError::NotSupported),
    }
}

/// Parses a SID into the identities accepted by this driver.
fn sid_identity(bytes: &[u8]) -> DriverResult<SidIdentity> {
    if bytes.len() < SID_PREFIX_BYTES {
        return Err(DriverError::InvalidParameter);
    }
    let fields = LittleEndianInput::new(bytes);
    let revision = malformed_security(fields.read_u8(wire_offset(0)))?;
    if u32::from(revision) != wdk_sys::SID_REVISION {
        return Err(DriverError::InvalidParameter);
    }
    let count = usize::from(malformed_security(fields.read_u8(wire_offset(1)))?);
    if bytes.len() != sid_length_from_sub_authorities(count)? {
        return Err(DriverError::InvalidParameter);
    }
    let authority = sid_authority(bytes)?;
    if authority == SECURITY_WORLD_AUTHORITY && count == 1 && sid_sub_authority(bytes, 0)? == 0 {
        return Ok(SidIdentity::Everyone);
    }
    if authority == SECURITY_NT_NON_UNIQUE_AUTHORITY && count == 2 {
        return match sid_sub_authority(bytes, 0)? {
            1 => Ok(SidIdentity::LinuxUid(sid_sub_authority(bytes, 1)?)),
            2 => Ok(SidIdentity::LinuxGid(sid_sub_authority(bytes, 1)?)),
            _ => Err(DriverError::NotSupported),
        };
    }
    Err(DriverError::NotSupported)
}

/// Reads the big-endian SID authority.
fn sid_authority(bytes: &[u8]) -> DriverResult<u64> {
    let authority: [u8; 6] = security_range(bytes, 2, 6)?
        .try_into()
        .map_err(|_| DriverError::InvalidParameter)?;
    let [a, b, c, d, e, f] = authority;
    Ok(u64::from_be_bytes([0, 0, a, b, c, d, e, f]))
}

/// Reads a little-endian SID sub-authority by index.
fn sid_sub_authority(bytes: &[u8], index: usize) -> DriverResult<u32> {
    let start = SID_PREFIX_BYTES
        .checked_add(
            index
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(DriverError::InvalidParameter)?,
        )
        .ok_or(DriverError::InvalidParameter)?;
    malformed_security(LittleEndianInput::new(bytes).read_u32(wire_offset(start)))
}

/// Builds a DACL with owner, group, and everyone allow ACEs from POSIX mode bits.
fn dacl_from_permissions(security: Ext4Security) -> DriverResult<Vec<u8>> {
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
    LittleEndianOutput::new(acl.as_mut_slice()).write_u8(
        wire_offset(0),
        u8::try_from(wdk_sys::ACL_REVISION).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    LittleEndianOutput::new(acl.as_mut_slice()).write_u16(
        wire_offset(4),
        u16::try_from(aces.len()).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    for ace in &aces {
        append_allow_ace(&mut acl, ace)?;
    }
    let acl_len = u16::try_from(acl.len()).map_err(|_| DriverError::InvalidParameter)?;
    LittleEndianOutput::new(acl.as_mut_slice()).write_u16(wire_offset(2), acl_len)?;
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
fn append_component(descriptor: &mut Vec<u8>, component: &[u8]) -> DriverResult<u32> {
    let offset = u32::try_from(descriptor.len()).map_err(|_| DriverError::InvalidParameter)?;
    descriptor.extend_from_slice(component);
    Ok(offset)
}

/// Appends one ACCESS_ALLOWED_ACE to an ACL image.
fn append_allow_ace(acl: &mut Vec<u8>, ace: &AllowAce) -> DriverResult<()> {
    let ace_size = ACCESS_ALLOWED_ACE_PREFIX_BYTES
        .checked_add(ace.sid.bytes.len())
        .ok_or(DriverError::InvalidParameter)?;
    let start = acl.len();
    acl.resize(
        start
            .checked_add(ace_size)
            .ok_or(DriverError::InvalidParameter)?,
        0,
    );
    let mut output = LittleEndianOutput::new(acl.as_mut_slice());
    output.write_u8(
        wire_offset(start),
        u8::try_from(wdk_sys::ACCESS_ALLOWED_ACE_TYPE)
            .map_err(|_| DriverError::InvalidParameter)?,
    )?;
    output.write_u16(
        wire_offset(start.checked_add(2).ok_or(DriverError::InvalidParameter)?),
        u16::try_from(ace_size).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    output.write_u32(
        wire_offset(start.checked_add(4).ok_or(DriverError::InvalidParameter)?),
        ace.mask,
    )?;
    output.write_bytes(
        wire_offset(
            start
                .checked_add(ACCESS_ALLOWED_ACE_PREFIX_BYTES)
                .ok_or(DriverError::InvalidParameter)?,
        ),
        ace.sid.bytes.as_slice(),
    )
}

/// Builds `S-1-22-1-uid`.
fn uid_sid(uid: u32) -> DriverResult<BinarySid> {
    sid(SECURITY_NT_NON_UNIQUE_AUTHORITY, &[1, uid])
}

/// Builds `S-1-22-2-gid`.
fn gid_sid(gid: u32) -> DriverResult<BinarySid> {
    sid(SECURITY_NT_NON_UNIQUE_AUTHORITY, &[2, gid])
}

/// Builds Everyone, `S-1-1-0`.
fn everyone_sid() -> DriverResult<BinarySid> {
    sid(SECURITY_WORLD_AUTHORITY, &[0])
}

/// Builds a binary SID from an authority and sub-authorities.
fn sid(authority: u64, sub_authorities: &[u32]) -> DriverResult<BinarySid> {
    let sub_authority_count =
        u8::try_from(sub_authorities.len()).map_err(|_| DriverError::InvalidParameter)?;
    let capacity = SID_PREFIX_BYTES
        .checked_add(
            sub_authorities
                .len()
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(DriverError::InvalidParameter)?,
        )
        .ok_or(DriverError::InvalidParameter)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(u8::try_from(wdk_sys::SID_REVISION).map_err(|_| DriverError::InvalidParameter)?);
    bytes.push(sub_authority_count);
    let authority = authority.to_be_bytes();
    let Some(authority) = authority.get(2..) else {
        return Err(DriverError::InvalidParameter);
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

/// Normalizes malformed security descriptor field access to the Windows set-security error.
fn malformed_security<T>(result: DriverResult<T>) -> DriverResult<T> {
    result.map_err(|_| DriverError::InvalidParameter)
}

/// Builds a typed security-descriptor wire offset.
const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Builds a checked security-descriptor wire range.
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Borrows a checked security descriptor range with malformed-input error semantics.
fn security_range(bytes: &[u8], offset: usize, length: usize) -> DriverResult<&[u8]> {
    wire_range(offset, length)?
        .read_from(bytes)
        .map_err(|_| DriverError::InvalidParameter)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid};

    use crate::{
        irp::{SecurityComponentSelection, SecuritySelection},
        kernel::status::DriverError,
        wire::LittleEndianInput,
    };

    use super::{
        SidIdentity, dacl_from_permissions, gid_sid, permission_bits_from_mask,
        permission_class_mask, security_descriptor, security_from_descriptor, sid_identity,
        uid_sid, wire_offset,
    };

    fn all_security_components() -> SecuritySelection {
        SecuritySelection::from_components(
            SecurityComponentSelection::Selected,
            SecurityComponentSelection::Selected,
            SecurityComponentSelection::Selected,
        )
    }

    fn dacl_security_component() -> SecuritySelection {
        SecuritySelection::from_components(
            SecurityComponentSelection::Omitted,
            SecurityComponentSelection::Omitted,
            SecurityComponentSelection::Selected,
        )
    }

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
                let fields = LittleEndianInput::new(dacl.as_slice());
                assert_eq!(fields.read_u16(wire_offset(2)), Ok(76));
                assert_eq!(fields.read_u16(wire_offset(4)), Ok(3));
                assert_eq!(fields.read_u16(wire_offset(10)), Ok(24));
                assert_eq!(fields.read_u16(wire_offset(34)), Ok(24));
                assert_eq!(fields.read_u16(wire_offset(58)), Ok(20));
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
            let descriptor = security_descriptor(security, all_security_components());
            assert!(descriptor.is_ok());
            if let Ok(descriptor) = descriptor {
                let fields = LittleEndianInput::new(descriptor.as_slice());
                assert_eq!(fields.read_u16(wire_offset(2)), Ok(32772));
                assert_eq!(fields.read_u32(wire_offset(4)), Ok(20));
                assert_eq!(fields.read_u32(wire_offset(8)), Ok(36));
                assert_eq!(fields.read_u32(wire_offset(16)), Ok(52));
            }
        }
    }

    #[test]
    fn security_descriptor_set_round_trips_posix_owner_group_and_dacl() {
        let current_permissions = Ext4Permissions::new(0o600);
        let target_permissions = Ext4Permissions::new(0o754);
        assert!(current_permissions.is_ok());
        assert!(target_permissions.is_ok());
        if let (Ok(current_permissions), Ok(target_permissions)) =
            (current_permissions, target_permissions)
        {
            let current = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1), Ext4Gid::from_u32(2)),
                current_permissions,
            );
            let target = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(100)),
                target_permissions,
            );
            let descriptor = security_descriptor(target, all_security_components());
            assert!(descriptor.is_ok());
            if let Ok(descriptor) = descriptor {
                assert_eq!(
                    security_from_descriptor(
                        descriptor.as_slice(),
                        all_security_components(),
                        current
                    ),
                    Ok(target)
                );
            }
        }
    }

    #[test]
    fn set_dacl_rejects_owner_sid_that_does_not_match_inode_owner() {
        let current_permissions = Ext4Permissions::new(0o600);
        let descriptor_permissions = Ext4Permissions::new(0o700);
        assert!(current_permissions.is_ok());
        assert!(descriptor_permissions.is_ok());
        if let (Ok(current_permissions), Ok(descriptor_permissions)) =
            (current_permissions, descriptor_permissions)
        {
            let current = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1), Ext4Gid::from_u32(2)),
                current_permissions,
            );
            let descriptor_security = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(2)),
                descriptor_permissions,
            );
            let descriptor = security_descriptor(descriptor_security, dacl_security_component());
            assert!(descriptor.is_ok());
            if let Ok(descriptor) = descriptor {
                assert_eq!(
                    security_from_descriptor(
                        descriptor.as_slice(),
                        dacl_security_component(),
                        current,
                    ),
                    Err(DriverError::NotSupported)
                );
            }
        }
    }

    #[test]
    fn set_dacl_rejects_deny_aces() {
        let permissions = Ext4Permissions::new(0o700);
        assert!(permissions.is_ok());
        if let Ok(permissions) = permissions {
            let security = Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(100)),
                permissions,
            );
            let descriptor = security_descriptor(security, dacl_security_component());
            assert!(descriptor.is_ok());
            if let Ok(mut descriptor) = descriptor {
                let dacl_offset = LittleEndianInput::new(descriptor.as_slice())
                    .read_u32(wire_offset(super::SECURITY_DESCRIPTOR_DACL_OFFSET));
                assert!(dacl_offset.is_ok());
                if let Ok(dacl_offset) = dacl_offset {
                    let ace_type_offset = usize::try_from(dacl_offset)
                        .ok()
                        .and_then(|offset| offset.checked_add(super::ACL_HEADER_BYTES));
                    assert!(ace_type_offset.is_some());
                    if let Some(ace_type_offset) = ace_type_offset {
                        let deny_type = u8::try_from(wdk_sys::ACCESS_DENIED_ACE_TYPE);
                        assert!(deny_type.is_ok());
                        if let (Some(byte), Ok(deny_type)) =
                            (descriptor.get_mut(ace_type_offset), deny_type)
                        {
                            *byte = deny_type;
                        }
                        assert_eq!(
                            security_from_descriptor(
                                descriptor.as_slice(),
                                dacl_security_component(),
                                security,
                            ),
                            Err(DriverError::NotSupported)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn accepted_sid_identities_are_strictly_classified() {
        assert_eq!(
            uid_sid(42).and_then(|sid| sid_identity(sid.bytes.as_slice())),
            Ok(SidIdentity::LinuxUid(42))
        );
        assert_eq!(
            super::everyone_sid().and_then(|sid| sid_identity(sid.bytes.as_slice())),
            Ok(SidIdentity::Everyone)
        );
        assert_eq!(
            sid_identity(&[1, 1, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0]),
            Err(DriverError::NotSupported)
        );
    }

    #[test]
    fn file_generic_masks_are_the_only_accepted_permission_masks() {
        assert_eq!(
            permission_bits_from_mask(
                wdk_sys::FILE_GENERIC_READ
                    | wdk_sys::FILE_GENERIC_WRITE
                    | wdk_sys::FILE_GENERIC_EXECUTE
            ),
            Ok(0o7)
        );
        assert_eq!(
            permission_bits_from_mask(wdk_sys::FILE_GENERIC_READ | wdk_sys::DELETE),
            Err(DriverError::NotSupported)
        );
    }
}
