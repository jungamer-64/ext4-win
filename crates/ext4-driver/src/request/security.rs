//! Windows security descriptor boundary for authoritative ext4 owner and mode.
use super::DriverMutationPass;
use crate::irp::{CapturedRequestorOutput, IrpCompletion, PendingIrpLease};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::security_descriptor::{SecurityDescriptorRef, SecuritySelection};
use crate::state::OpenedObject;
use ext4_core::{CommittedReadPass, Ext4Security, NodeId};
use ext4_security::{Components, Descriptor, IdentityMap};

/// Complete pool-aligned self-relative descriptor retained through native checks.
#[derive(Debug)]
pub(crate) struct CreateSecurityDescriptor {
    /// Immutable owned image; kernel pool allocations satisfy native alignment.
    bytes: DriverVec<u8>,
}
impl CreateSecurityDescriptor {
    /// Loads and projects a node using the operation's pinned identity table.
    /// # Errors
    /// Propagates metadata, validation and allocation failures.
    pub(crate) fn for_node(
        read: &mut impl CommittedReadPass,
        node: NodeId,
        map: &IdentityMap,
    ) -> DriverResult<Self> {
        Self::from_security(security_from_node(read, node)?, map)
    }
    /// Projects prepared inode security before handle authority is published.
    /// # Errors
    /// Propagates descriptor and pool allocation failures.
    pub(crate) fn from_security(security: Ext4Security, map: &IdentityMap) -> DriverResult<Self> {
        let descriptor = Descriptor::encode(security, map, Components::ALL)?;
        Ok(Self {
            bytes: DriverVec::try_copied_from_slice(descriptor.bytes())?,
        })
    }
    /// Borrows the encoded descriptor during one native check.
    #[expect(
        unsafe_code,
        reason = "the shared encoder establishes native layout and pool storage establishes alignment"
    )]
    pub(crate) fn as_native(&self) -> SecurityDescriptorRef<'_> {
        unsafe {
            // SAFETY: The immutable complete encoder image is contained in pool-aligned storage.
            SecurityDescriptorRef::from_validated_bytes(self.bytes.as_slice())
        }
    }
}
/// Executes a descriptor query with the table captured at operation admission.
/// # Errors
/// Propagates stack, metadata, encoding and requestor-copy failures.
pub(crate) fn query(
    request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
    map: &IdentityMap,
) -> DriverResult<IrpCompletion> {
    let request = QuerySecurityRequest::decode(request)?;
    let security = security_from_node(read, request.node)?;
    let descriptor = Descriptor::encode(
        security,
        map,
        Components::new(request.selection.required_information())?,
    )?;
    let required = descriptor.bytes().len();
    if required > request.output.capacity() {
        return IrpCompletion::buffer_too_small(required);
    }
    request.output.copy_from_owned(descriptor.bytes())?;
    IrpCompletion::from_usize(required)
}
/// Mutates owner/mode only when selected fields are representable by the shared projection.
/// # Errors
/// Rejects arbitrary Windows ACLs and propagates metadata/journal failures.
pub(crate) fn set(
    request: PendingIrpLease<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    map: &IdentityMap,
) -> DriverResult<IrpCompletion> {
    let request = SetSecurityRequest::decode(request)?;
    let current = security_from_node(mutation, request.node)?;
    let security = Descriptor::decode(
        request.descriptor,
        map,
        Components::new(request.selection.required_information())?,
        current,
    )?;
    if security != current {
        let node = mutation.node(request.node)?;
        mutation.set_posix_security(node, security)?;
    }
    Ok(IrpCompletion::EMPTY)
}
/// Decoded query-security request.
struct QuerySecurityRequest<'a> {
    /// Opaque native target for the exact output descriptor length.
    output: &'a mut CapturedRequestorOutput,
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// ext4 node selected by the opened FILE_OBJECT.
    node: NodeId,
}

impl<'a> QuerySecurityRequest<'a> {
    /// Decodes a query-security request.
    /// # Errors
    ///
    /// Returns an error when the current stack is not a query-security stack or its FILE_OBJECT has
    /// no opened ext4 context.
    fn decode(mut request: PendingIrpLease<'a>) -> Result<Self, DriverError> {
        let node = request.with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            let opened_file = OpenedObject::decode(file_object)?;
            Ok::<_, DriverError>(opened_file.node())
        })?;
        let (selection, output) = request.query_security_parts()?;
        Ok(Self {
            output,
            selection,
            node,
        })
    }
}

/// Decoded set-security request.
struct SetSecurityRequest<'a> {
    /// Selected security descriptor components.
    selection: SecuritySelection,
    /// Owned descriptor bytes copied before the operation can suspend.
    descriptor: &'a [u8],
    /// ext4 node selected by the opened FILE_OBJECT.
    node: NodeId,
}

impl<'a> SetSecurityRequest<'a> {
    /// Decodes a set-security request.
    /// # Errors
    ///
    /// Returns an error when the current stack is not a set-security stack or its FILE_OBJECT has no
    /// opened ext4 context.
    fn decode(mut request: PendingIrpLease<'a>) -> Result<Self, DriverError> {
        let node = request.with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            let opened_file = OpenedObject::decode(file_object)?;
            Ok::<_, DriverError>(opened_file.node())
        })?;
        let (selection, descriptor) = request.set_security_parts()?;
        Ok(Self {
            selection,
            descriptor,
            node,
        })
    }
}

/// Extracts security metadata after validating FCB kind against core metadata.
/// # Errors
///
/// Returns an error when `identity` cannot be loaded as its typed ext4 node.
pub(crate) fn security_from_node(
    read: &mut impl CommittedReadPass,
    identity: NodeId,
) -> DriverResult<Ext4Security> {
    match identity {
        NodeId::File(file) => Ok(read.load_file(file)?.security()),
        NodeId::Directory(directory) => Ok(read.load_directory(directory)?.security()),
        NodeId::Symlink(symlink) => Ok(read.load_symlink(symlink)?.security()),
    }
}
