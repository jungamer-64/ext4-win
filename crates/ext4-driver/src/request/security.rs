//! Windows security descriptor boundary for ext4 owner and mode bits.

use core::ptr::NonNull;

use crate::irp::{
    DispatchTarget, IrpCompletion, QuerySecurityStack, SecurityComponentSelection,
    SecuritySelection, SetSecurityStack,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::state::{FileControlBlock, OpenedObject, VolumeControlBlock};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};
use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid, NodeId};

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

/// Executes IRP_MJ_QUERY_SECURITY.
/// # Errors
///
/// Returns an error when security stack decoding or descriptor packing fails.
pub(crate) fn query(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    QuerySecurityRequest::decode(target).and_then(|request| query_security(&request))
}

/// Executes IRP_MJ_SET_SECURITY.
/// # Errors
///
/// Returns an error when security stack decoding or descriptor mutation fails.
pub(crate) fn set(target: DispatchTarget) -> DriverResult<IrpCompletion> {
    SetSecurityRequest::decode(target).and_then(|request| set_security(&request))
}

/// Decoded query-security request.
#[derive(Debug)]
struct QuerySecurityRequest {
    /// Dispatch target receiving output.
    target: DispatchTarget,
    /// Decoded query-security stack.
    stack: QuerySecurityStack,
    /// Opened file contexts decoded before security handling.
    opened_file: OpenedObject,
}

impl QuerySecurityRequest {
    /// Decodes a query-security request.
    /// # Errors
    ///
    /// Returns an error when the current stack is not a query-security stack or its FILE_OBJECT has
    /// no opened ext4 context.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.query_security()?;
        let opened_file = OpenedObject::decode(stack.file_object())?;
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
    /// Decoded set-security stack.
    stack: SetSecurityStack,
    /// Opened file contexts decoded before security handling.
    opened_file: OpenedObject,
}

impl SetSecurityRequest {
    /// Decodes a set-security request.
    /// # Errors
    ///
    /// Returns an error when the current stack is not a set-security stack or its FILE_OBJECT has no
    /// opened ext4 context.
    fn decode(target: DispatchTarget) -> Result<Self, DriverError> {
        let stack = target.current_stack()?.set_security()?;
        let opened_file = OpenedObject::decode(stack.file_object())?;
        Ok(Self { stack, opened_file })
    }
}

/// Binary SID used while building a self-relative descriptor.
#[derive(Debug, Eq, PartialEq)]
struct BinarySid {
    /// Serialized SID bytes.
    bytes: DriverVec<u8>,
}

/// One allow ACE projected from a POSIX permission class.
#[derive(Debug, Eq, PartialEq)]
struct AllowAce {
    /// Windows access mask.
    mask: WindowsAccessMask,
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
    control: SecurityDescriptorControl,
    /// Owner SID offset.
    owner_offset: SecurityDescriptorOffset,
    /// Group SID offset.
    group_offset: SecurityDescriptorOffset,
    /// DACL offset.
    dacl_offset: SecurityDescriptorOffset,
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
    bits: PosixRwxBits,
}

/// Windows access mask accepted at the POSIX projection boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsAccessMask(u32);

impl WindowsAccessMask {
    /// Empty mask.
    const EMPTY: Self = Self(0);

    /// Creates an access mask from raw ACE bytes.
    const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw mask for ACE encoding.
    const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns whether this mask grants no access.
    const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Self-relative security descriptor control flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecurityDescriptorControl(u16);

impl SecurityDescriptorControl {
    /// Parses and validates descriptor control flags.
    /// # Errors
    ///
    /// Returns an error when the descriptor is not self-relative or requests a SACL.
    fn parse(value: u16) -> DriverResult<Self> {
        let self_relative =
            u16::try_from(wdk_sys::SE_SELF_RELATIVE).map_err(|_| DriverError::InvalidParameter)?;
        if value & self_relative == 0 {
            return Err(DriverError::NotSupported);
        }
        let sacl_present =
            u16::try_from(wdk_sys::SE_SACL_PRESENT).map_err(|_| DriverError::InvalidParameter)?;
        if value & sacl_present != 0 {
            return Err(DriverError::AccessDenied);
        }
        Ok(Self(value))
    }

    /// Returns whether a DACL is present.
    /// # Errors
    ///
    /// Returns an error when the WDK DACL-present control bit cannot be represented.
    fn has_dacl(self) -> DriverResult<bool> {
        let dacl_present =
            u16::try_from(wdk_sys::SE_DACL_PRESENT).map_err(|_| DriverError::InvalidParameter)?;
        Ok(self.0 & dacl_present != 0)
    }
}

/// Offset inside a self-relative security descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SecurityDescriptorOffset(u32);

impl SecurityDescriptorOffset {
    /// Creates an offset from a descriptor header field.
    const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// Returns the raw offset for descriptor encoding.
    const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns whether this optional component offset is absent.
    const fn is_absent(self) -> bool {
        self.0 == 0
    }

    /// Converts a present component offset to a host index.
    /// # Errors
    ///
    /// Returns an error when the component offset is zero or cannot be represented as `usize`.
    fn as_present_usize(self) -> DriverResult<usize> {
        if self.is_absent() {
            return Err(DriverError::InvalidParameter);
        }
        usize::try_from(self.0).map_err(|_| DriverError::InvalidParameter)
    }

    /// Converts an optional component offset to a host index.
    /// # Errors
    ///
    /// Returns an error when the component offset cannot be represented as `usize`.
    fn as_usize(self) -> DriverResult<usize> {
        usize::try_from(self.0).map_err(|_| DriverError::InvalidParameter)
    }
}

/// POSIX rwx bits for one permission class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PosixRwxBits(u16);

impl PosixRwxBits {
    /// Creates POSIX rwx bits.
    /// # Errors
    ///
    /// Returns an error when `value` contains bits outside one POSIX rwx class.
    fn new(value: u16) -> DriverResult<Self> {
        if value & !0o7 != 0 {
            return Err(DriverError::InvalidParameter);
        }
        Ok(Self(value))
    }

    /// Returns raw rwx bits for mode construction.
    const fn as_u16(self) -> u16 {
        self.0
    }
}

/// Duplicate-checking builder for POSIX permission bits parsed from a DACL.
#[derive(Debug, Default, Eq, PartialEq)]
struct DaclPermissionBuilder {
    /// Permission classes observed in DACL order.
    classes: DriverVec<PermissionClassBits>,
}

impl DaclPermissionBuilder {
    /// Stores one parsed permission class.
    /// # Errors
    ///
    /// Returns an error when the DACL contains duplicate ACEs for the same POSIX permission class.
    fn set(&mut self, class: PermissionClass, bits: PosixRwxBits) -> DriverResult<()> {
        if self.classes.iter().any(|entry| entry.class == class) {
            return Err(DriverError::NotSupported);
        }
        self.classes.try_push(PermissionClassBits { class, bits })?;
        Ok(())
    }

    /// Converts parsed classes into POSIX rwx mode bits.
    fn mode_bits(&self) -> u16 {
        let mut mode = 0_u16;
        for entry in self.classes.iter() {
            match entry.class {
                PermissionClass::Owner => mode |= entry.bits.as_u16() << 6,
                PermissionClass::Group => mode |= entry.bits.as_u16() << 3,
                PermissionClass::Other => mode |= entry.bits.as_u16(),
            }
        }
        mode
    }
}

/// Performs a security descriptor query.
/// # Errors
///
/// Returns an error when ext4 security metadata cannot be loaded, the requested descriptor cannot
/// be built, or the user output buffer is too small.
fn query_security(request: &QuerySecurityRequest) -> DriverResult<IrpCompletion> {
    let security = load_ext4_security(&request.opened_file)?;
    let descriptor = security_descriptor(security, request.stack.selection())?;
    let required = descriptor.len();
    let length = request.stack.length();
    if length.as_usize() < required {
        return Err(DriverError::BufferTooSmall);
    }
    let mut output = request.target.user_output(length)?;
    LittleEndianOutput::new(output.as_mut_slice())
        .write_bytes(wire_offset(0), descriptor.as_slice())?;
    IrpCompletion::from_usize(required)
}

/// Performs a POSIX security mutation from a Windows security descriptor.
/// # Errors
///
/// Returns an error when the input descriptor cannot be copied or mapped to ext4 owner/permissions,
/// or the journaled security update fails.
fn set_security(request: &SetSecurityRequest) -> DriverResult<IrpCompletion> {
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
        return Ok(IrpCompletion::EMPTY);
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
    Ok(IrpCompletion::EMPTY)
}

/// Loads ext4 security metadata for an opened node.
/// # Errors
///
/// Returns an error when the opened node cannot be loaded from ext4 metadata.
fn load_ext4_security(opened_file: &OpenedObject) -> DriverResult<Ext4Security> {
    load_ext4_security_context(opened_file).map(|context| context.security)
}

/// Loads ext4 security context for an opened node.
/// # Errors
///
/// Returns an error when the opened node cannot be loaded or its security metadata is inconsistent
/// with the FCB identity.
fn load_ext4_security_context(opened_file: &OpenedObject) -> DriverResult<OpenedSecurityContext> {
    let fcb = opened_file.file_control_block();
    let vcb = volume_control_block(fcb);
    Ok(OpenedSecurityContext {
        volume: fcb.volume(),
        node: fcb.node(),
        security: security_from_node(vcb, fcb.node())?,
    })
}

/// Extracts security metadata after validating FCB kind against core metadata.
/// # Errors
///
/// Returns an error when `identity` cannot be loaded as its typed ext4 node.
fn security_from_node(vcb: &VolumeControlBlock, identity: NodeId) -> DriverResult<Ext4Security> {
    match identity {
        NodeId::File(file) => Ok(vcb.volume().load_file(file)?.security()),
        NodeId::Directory(directory) => Ok(vcb.volume().load_directory(directory)?.security()),
        NodeId::Symlink(symlink) => Ok(vcb.volume().load_symlink(symlink)?.security()),
    }
}

/// Builds a self-relative security descriptor for requested fields.
/// # Errors
///
/// Returns an error when requested SIDs or DACL bytes cannot be encoded into a self-relative
/// security descriptor.
fn security_descriptor(
    security: Ext4Security,
    selection: SecuritySelection,
) -> DriverResult<DriverVec<u8>> {
    let mut descriptor = DriverVec::try_repeated_copy(0_u8, SECURITY_DESCRIPTOR_RELATIVE_BYTES)?;
    LittleEndianOutput::new(descriptor.as_mut_slice()).write_u8(
        wire_offset(0),
        u8::try_from(wdk_sys::SECURITY_DESCRIPTOR_REVISION)
            .map_err(|_| DriverError::InvalidParameter)?,
    )?;
    let mut control = wdk_sys::SE_SELF_RELATIVE;

    if matches!(selection.owner(), SecurityComponentSelection::Selected) {
        let owner = uid_sid(security.owner().uid().as_u32())?;
        let offset = append_component(&mut descriptor, owner.bytes.as_slice())?;
        LittleEndianOutput::new(descriptor.as_mut_slice())
            .write_u32(wire_offset(4), offset.as_u32())?;
    }
    if matches!(selection.group(), SecurityComponentSelection::Selected) {
        let group = gid_sid(security.owner().gid().as_u32())?;
        let offset = append_component(&mut descriptor, group.bytes.as_slice())?;
        LittleEndianOutput::new(descriptor.as_mut_slice())
            .write_u32(wire_offset(8), offset.as_u32())?;
    }
    if matches!(selection.dacl(), SecurityComponentSelection::Selected) {
        control |= wdk_sys::SE_DACL_PRESENT;
        let dacl = dacl_from_permissions(security)?;
        let offset = append_component(&mut descriptor, dacl.as_slice())?;
        LittleEndianOutput::new(descriptor.as_mut_slice())
            .write_u32(wire_offset(16), offset.as_u32())?;
    }

    LittleEndianOutput::new(descriptor.as_mut_slice()).write_u16(
        wire_offset(2),
        u16::try_from(control).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    Ok(descriptor)
}

/// Copies the raw SetSecurity descriptor into a bounded byte image.
/// # Errors
///
/// Returns an error when selected owner, group, or DACL offsets are invalid or their raw component
/// lengths cannot be bounded.
fn security_descriptor_bytes(
    security_descriptor: NonNull<core::ffi::c_void>,
    selection: SecuritySelection,
) -> DriverResult<DriverVec<u8>> {
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
    DriverVec::try_copied_from_slice(bytes)
}

/// Builds new ext4 security metadata from a Windows security descriptor.
/// # Errors
///
/// Returns an error when the selected owner/group SIDs or DACL cannot be converted to ext4 owner and
/// POSIX mode bits.
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
    /// # Errors
    ///
    /// Returns an error when the descriptor header is truncated, has an unsupported revision, or has
    /// unsupported control flags.
    fn parse(bytes: &'a [u8]) -> DriverResult<Self> {
        if bytes.len() < SECURITY_DESCRIPTOR_RELATIVE_BYTES {
            return Err(DriverError::InvalidParameter);
        }
        let fields = LittleEndianInput::new(bytes);
        let revision = malformed_security(fields.read_u8(wire_offset(0)))?;
        if u32::from(revision) != wdk_sys::SECURITY_DESCRIPTOR_REVISION {
            return Err(DriverError::InvalidParameter);
        }
        let control =
            SecurityDescriptorControl::parse(malformed_security(fields.read_u16(wire_offset(2)))?)?;

        Ok(Self {
            bytes,
            control,
            owner_offset: SecurityDescriptorOffset::from_u32(malformed_security(
                fields.read_u32(wire_offset(SECURITY_DESCRIPTOR_OWNER_OFFSET)),
            )?),
            group_offset: SecurityDescriptorOffset::from_u32(malformed_security(
                fields.read_u32(wire_offset(SECURITY_DESCRIPTOR_GROUP_OFFSET)),
            )?),
            dacl_offset: SecurityDescriptorOffset::from_u32(malformed_security(
                fields.read_u32(wire_offset(SECURITY_DESCRIPTOR_DACL_OFFSET)),
            )?),
        })
    }

    /// Returns the owner UID represented by the owner SID.
    /// # Errors
    ///
    /// Returns an error when the owner SID is absent or is not a Linux UID SID.
    fn owner_uid(self) -> DriverResult<u32> {
        match sid_identity(self.sid_at(self.owner_offset)?)? {
            SidIdentity::LinuxUid(uid) => Ok(uid),
            SidIdentity::LinuxGid(_) | SidIdentity::Everyone => Err(DriverError::NotSupported),
        }
    }

    /// Returns the group GID represented by the group SID.
    /// # Errors
    ///
    /// Returns an error when the group SID is absent or is not a Linux GID SID.
    fn group_gid(self) -> DriverResult<u32> {
        match sid_identity(self.sid_at(self.group_offset)?)? {
            SidIdentity::LinuxGid(gid) => Ok(gid),
            SidIdentity::LinuxUid(_) | SidIdentity::Everyone => Err(DriverError::NotSupported),
        }
    }

    /// Returns low POSIX rwx bits represented by the descriptor DACL.
    /// # Errors
    ///
    /// Returns an error when the descriptor has no DACL or the DACL cannot be mapped to POSIX rwx
    /// classes.
    fn dacl_permissions(self, owner: Ext4Owner) -> DriverResult<u16> {
        if !self.control.has_dacl()? || self.dacl_offset.is_absent() {
            return Err(DriverError::NotSupported);
        }
        let acl = self.acl_at(self.dacl_offset)?;
        parse_dacl_permissions(acl, owner)
    }

    /// Returns a SID component at a self-relative descriptor offset.
    /// # Errors
    ///
    /// Returns an error when the SID offset is absent, the SID header is truncated, or the SID
    /// length exceeds the descriptor.
    fn sid_at(self, offset: SecurityDescriptorOffset) -> DriverResult<&'a [u8]> {
        let start = offset.as_present_usize()?;
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
    /// # Errors
    ///
    /// Returns an error when the ACL offset is absent, the ACL header is truncated, or the ACL size
    /// exceeds the descriptor.
    fn acl_at(self, offset: SecurityDescriptorOffset) -> DriverResult<&'a [u8]> {
        let start = offset.as_present_usize()?;
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
/// # Errors
///
/// Returns an error when the SID offset is absent or the computed SID length overflows.
fn raw_sid_end(pointer: NonNull<u8>, offset: SecurityDescriptorOffset) -> DriverResult<usize> {
    let start = offset.as_present_usize()?;
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
/// # Errors
///
/// Returns an error when the ACL offset is absent or its size field cannot be used to bound the raw
/// descriptor copy.
fn raw_acl_end(pointer: NonNull<u8>, offset: SecurityDescriptorOffset) -> DriverResult<usize> {
    if offset.is_absent() {
        return Err(DriverError::NotSupported);
    }
    let start = offset.as_usize()?;
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
/// # Errors
///
/// Returns an error when the sub-authority byte count overflows.
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
/// # Errors
///
/// Returns an error when the ACL header is malformed, ACE sizes are inconsistent, or an ACE cannot
/// be mapped to a POSIX permission class.
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
/// # Errors
///
/// Returns an error when the ACE is not a plain allow ACE, its mask is unsupported, or its SID does
/// not identify the owner, group, or everyone class.
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
    let mask = WindowsAccessMask::from_u32(malformed_security(
        LittleEndianInput::new(ace).read_u32(wire_offset(ACE_MASK_OFFSET)),
    )?);
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
/// # Errors
///
/// Returns an error when `mask` is not one of the Windows generic-access combinations generated for
/// POSIX rwx bits.
fn permission_bits_from_mask(mask: WindowsAccessMask) -> DriverResult<PosixRwxBits> {
    for bits in 0..=0o7 {
        if permission_class_mask(bits) == mask {
            return PosixRwxBits::new(bits);
        }
    }
    Err(DriverError::NotSupported)
}

/// Classifies a SID for DACL permission projection.
/// # Errors
///
/// Returns an error when the SID names a Linux UID/GID other than the inode owner/group.
fn permission_class_from_sid(sid: SidIdentity, owner: Ext4Owner) -> DriverResult<PermissionClass> {
    match sid {
        SidIdentity::LinuxUid(uid) if uid == owner.uid().as_u32() => Ok(PermissionClass::Owner),
        SidIdentity::LinuxGid(gid) if gid == owner.gid().as_u32() => Ok(PermissionClass::Group),
        SidIdentity::Everyone => Ok(PermissionClass::Other),
        SidIdentity::LinuxUid(_) | SidIdentity::LinuxGid(_) => Err(DriverError::NotSupported),
    }
}

/// Parses a SID into the identities accepted by this driver.
/// # Errors
///
/// Returns an error when the SID is malformed or is not Everyone, Linux UID, or Linux GID.
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
/// # Errors
///
/// Returns an error when the six-byte SID authority field is truncated.
fn sid_authority(bytes: &[u8]) -> DriverResult<u64> {
    let authority: [u8; 6] = security_range(bytes, 2, 6)?
        .try_into()
        .map_err(|_| DriverError::InvalidParameter)?;
    let [a, b, c, d, e, f] = authority;
    Ok(u64::from_be_bytes([0, 0, a, b, c, d, e, f]))
}

/// Reads a little-endian SID sub-authority by index.
/// # Errors
///
/// Returns an error when `index` overflows the SID sub-authority offset or the field is truncated.
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
/// # Errors
///
/// Returns an error when a generated SID or ACE cannot be represented in the ACL byte image.
fn dacl_from_permissions(security: Ext4Security) -> DriverResult<DriverVec<u8>> {
    let permissions = security.permissions().as_u16();
    let owner = permission_class_mask((permissions >> 6) & 0o7);
    let group = permission_class_mask((permissions >> 3) & 0o7);
    let other = permission_class_mask(permissions & 0o7);
    let mut aces = DriverVec::new();
    if !owner.is_empty() {
        aces.try_push_owned(AllowAce {
            mask: owner,
            sid: uid_sid(security.owner().uid().as_u32())?,
        })
        .map_err(|error| error.into_parts().0)?;
    }
    if !group.is_empty() {
        aces.try_push_owned(AllowAce {
            mask: group,
            sid: gid_sid(security.owner().gid().as_u32())?,
        })
        .map_err(|error| error.into_parts().0)?;
    }
    if !other.is_empty() {
        aces.try_push_owned(AllowAce {
            mask: other,
            sid: everyone_sid()?,
        })
        .map_err(|error| error.into_parts().0)?;
    }

    let mut acl = DriverVec::try_repeated_copy(0_u8, ACL_HEADER_BYTES)?;
    LittleEndianOutput::new(acl.as_mut_slice()).write_u8(
        wire_offset(0),
        u8::try_from(wdk_sys::ACL_REVISION).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    LittleEndianOutput::new(acl.as_mut_slice()).write_u16(
        wire_offset(4),
        u16::try_from(aces.len()).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    for ace in aces.iter() {
        append_allow_ace(&mut acl, ace)?;
    }
    let acl_len = u16::try_from(acl.len()).map_err(|_| DriverError::InvalidParameter)?;
    LittleEndianOutput::new(acl.as_mut_slice()).write_u16(wire_offset(2), acl_len)?;
    Ok(acl)
}

/// Returns a Windows access mask for a POSIX rwx permission class.
fn permission_class_mask(bits: u16) -> WindowsAccessMask {
    let mut mask = WindowsAccessMask::EMPTY.as_u32();
    if bits & 0o4 != 0 {
        mask |= wdk_sys::FILE_GENERIC_READ;
    }
    if bits & 0o2 != 0 {
        mask |= wdk_sys::FILE_GENERIC_WRITE;
    }
    if bits & 0o1 != 0 {
        mask |= wdk_sys::FILE_GENERIC_EXECUTE;
    }
    WindowsAccessMask::from_u32(mask)
}

/// Appends one component to the self-relative descriptor.
/// # Errors
///
/// Returns an error when the descriptor's current length cannot be represented as a 32-bit
/// self-relative offset.
fn append_component(
    descriptor: &mut DriverVec<u8>,
    component: &[u8],
) -> DriverResult<SecurityDescriptorOffset> {
    let offset = u32::try_from(descriptor.len()).map_err(|_| DriverError::InvalidParameter)?;
    descriptor.try_extend_from_copy_slice(component)?;
    Ok(SecurityDescriptorOffset::from_u32(offset))
}

/// Appends one ACCESS_ALLOWED_ACE to an ACL image.
/// # Errors
///
/// Returns an error when ACE size arithmetic overflows or the ACE header fields cannot be encoded.
fn append_allow_ace(acl: &mut DriverVec<u8>, ace: &AllowAce) -> DriverResult<()> {
    let ace_size = ACCESS_ALLOWED_ACE_PREFIX_BYTES
        .checked_add(ace.sid.bytes.len())
        .ok_or(DriverError::InvalidParameter)?;
    let start = acl.len();
    acl.try_resize_copy(
        start
            .checked_add(ace_size)
            .ok_or(DriverError::InvalidParameter)?,
        0,
    )?;
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
        ace.mask.as_u32(),
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
/// # Errors
///
/// Returns an error when the Linux UID SID cannot be encoded.
fn uid_sid(uid: u32) -> DriverResult<BinarySid> {
    sid(SECURITY_NT_NON_UNIQUE_AUTHORITY, &[1, uid])
}

/// Builds `S-1-22-2-gid`.
/// # Errors
///
/// Returns an error when the Linux GID SID cannot be encoded.
fn gid_sid(gid: u32) -> DriverResult<BinarySid> {
    sid(SECURITY_NT_NON_UNIQUE_AUTHORITY, &[2, gid])
}

/// Builds Everyone, `S-1-1-0`.
/// # Errors
///
/// Returns an error when the Everyone SID cannot be encoded.
fn everyone_sid() -> DriverResult<BinarySid> {
    sid(SECURITY_WORLD_AUTHORITY, &[0])
}

/// Builds a binary SID from an authority and sub-authorities.
/// # Errors
///
/// Returns an error when the sub-authority count or serialized SID capacity cannot be represented.
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
    let mut bytes = DriverVec::try_with_capacity(capacity)?;
    bytes.try_push(
        u8::try_from(wdk_sys::SID_REVISION).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    bytes.try_push(sub_authority_count)?;
    let authority = authority.to_be_bytes();
    let Some(authority) = authority.get(2..) else {
        return Err(DriverError::InvalidParameter);
    };
    bytes.try_extend_from_copy_slice(authority)?;
    for sub_authority in sub_authorities {
        bytes.try_extend_from_copy_slice(sub_authority.to_le_bytes().as_slice())?;
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
/// # Errors
///
/// Returns an error when `result` failed; the error is normalized to invalid-parameter semantics.
fn malformed_security<T>(result: DriverResult<T>) -> DriverResult<T> {
    result.map_err(|_| DriverError::InvalidParameter)
}

/// Builds a typed security-descriptor wire offset.
const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Builds a checked security-descriptor wire range.
/// # Errors
///
/// Returns an error when a security-descriptor `offset + length` cannot be represented as a wire
/// range.
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Borrows a checked security descriptor range with malformed-input error semantics.
/// # Errors
///
/// Returns an error when `offset..offset + length` falls outside `bytes`.
fn security_range(bytes: &[u8], offset: usize, length: usize) -> DriverResult<&[u8]> {
    wire_range(offset, length)?
        .read_from(bytes)
        .map_err(|_| DriverError::InvalidParameter)
}

#[cfg(test)]
mod tests {
    use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid};

    use crate::{
        irp::{SecurityComponentSelection, SecuritySelection},
        kernel::status::DriverError,
        wire::LittleEndianInput,
    };

    use super::{
        PosixRwxBits, SecurityDescriptorControl, SecurityDescriptorOffset, SidIdentity,
        WindowsAccessMask, dacl_from_permissions, gid_sid, permission_bits_from_mask,
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn uid_and_gid_sids_use_linux_sid_authority() {
        let uid = uid_sid(1000);
        assert!(uid.is_ok());
        if let Ok(uid) = uid {
            assert_eq!(
                uid.bytes.as_slice(),
                &[1, 2, 0, 0, 0, 0, 0, 22, 1, 0, 0, 0, 232, 3, 0, 0]
            );
        }
        let gid = gid_sid(100);
        assert!(gid.is_ok());
        if let Ok(gid) = gid {
            assert_eq!(
                gid.bytes.as_slice(),
                &[1, 2, 0, 0, 0, 0, 0, 22, 2, 0, 0, 0, 100, 0, 0, 0]
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn permission_classes_project_to_file_generic_masks() {
        assert_eq!(permission_class_mask(0o0), WindowsAccessMask::EMPTY);
        assert_eq!(
            permission_class_mask(0o4),
            WindowsAccessMask::from_u32(wdk_sys::FILE_GENERIC_READ)
        );
        assert_eq!(
            permission_class_mask(0o2),
            WindowsAccessMask::from_u32(wdk_sys::FILE_GENERIC_WRITE)
        );
        assert_eq!(
            permission_class_mask(0o1),
            WindowsAccessMask::from_u32(wdk_sys::FILE_GENERIC_EXECUTE)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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
                        if let (Some(byte), Ok(deny_type)) = (
                            descriptor.as_mut_slice().get_mut(ace_type_offset),
                            deny_type,
                        ) {
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
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

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_generic_masks_are_the_only_accepted_permission_masks() {
        assert_eq!(
            permission_bits_from_mask(WindowsAccessMask::from_u32(
                wdk_sys::FILE_GENERIC_READ
                    | wdk_sys::FILE_GENERIC_WRITE
                    | wdk_sys::FILE_GENERIC_EXECUTE,
            )),
            PosixRwxBits::new(0o7)
        );
        assert_eq!(
            permission_bits_from_mask(WindowsAccessMask::from_u32(
                wdk_sys::FILE_GENERIC_READ | wdk_sys::DELETE,
            )),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn security_descriptor_control_rejects_unsupported_forms() {
        assert_eq!(
            SecurityDescriptorControl::parse(0),
            Err(DriverError::NotSupported)
        );
        let sacl = u16::try_from(wdk_sys::SE_SELF_RELATIVE | wdk_sys::SE_SACL_PRESENT);
        assert!(sacl.is_ok());
        if let Ok(sacl) = sacl {
            assert_eq!(
                SecurityDescriptorControl::parse(sacl),
                Err(DriverError::AccessDenied)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn security_descriptor_offset_rejects_absent_required_component() {
        assert_eq!(
            SecurityDescriptorOffset::from_u32(0).as_present_usize(),
            Err(DriverError::InvalidParameter)
        );
    }
}
