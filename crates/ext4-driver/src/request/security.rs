//! Windows descriptor boundary for authoritative ext4 ownership and POSIX access policy.
use super::DriverMutationPass;
use crate::irp::{CapturedRequestorOutput, IrpCompletion, PendingIrpLease};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::DriverVec;
use crate::security_descriptor::{SecurityDescriptorRef, SecuritySelection};
use crate::state::OpenedObject;
use ext4_core::{CommittedReadPass, Ext4Access, NodeId};
use ext4_security::{Components, Descriptor, IdentityMap};

/// Complete pool-aligned self-relative descriptor retained through native checks.
#[derive(Debug)]
pub(crate) struct CreateSecurityDescriptor<'a> {
    /// Immutable owned image; kernel pool allocations satisfy native alignment.
    bytes: DriverVec<u8>,
    /// Validated policy retained for request-specific group-class checks.
    access: Ext4Access,
    /// Immutable identity interpretation pinned by the operation.
    map: &'a IdentityMap,
}
impl<'a> CreateSecurityDescriptor<'a> {
    /// Projects a validated access policy with its pinned identity table.
    /// # Errors
    /// Returns descriptor validation or allocation failure.
    pub(crate) fn from_access(access: Ext4Access, map: &'a IdentityMap) -> DriverResult<Self> {
        let descriptor = Descriptor::encode(&access, map, Components::ALL)?;
        Ok(Self {
            bytes: DriverVec::try_copied_from_slice(descriptor.bytes())?,
            access,
            map,
        })
    }
    /// Loads and projects a node using the operation's pinned identity table.
    /// # Errors
    /// Propagates metadata, validation and allocation failures.
    pub(crate) fn for_node(
        read: &mut impl CommittedReadPass,
        node: NodeId,
        map: &'a IdentityMap,
    ) -> DriverResult<Self> {
        Self::from_access(read.load_access(node)?, map)
    }
    /// Borrows the encoded descriptor during one native check.
    #[expect(
        unsafe_code,
        reason = "the shared encoder establishes native layout and pool storage establishes alignment"
    )]
    pub(crate) fn as_native(&self) -> SecurityDescriptorRef<'_> {
        unsafe {
            // SAFETY: The immutable complete encoder image is contained in pool-aligned storage.
            SecurityDescriptorRef::from_validated_bytes(
                self.bytes.as_slice(),
                &self.access,
                self.map,
            )
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
    let access = read.load_access(request.node)?;
    let descriptor = Descriptor::encode(
        &access,
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
    let current = mutation.load_access(request.node)?;
    let security = Descriptor::decode(
        request.descriptor,
        map,
        Components::new(request.selection.required_information())?,
        &current,
    )?;
    if security != current.security() {
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
