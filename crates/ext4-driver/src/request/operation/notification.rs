//! Metadata observations and prepared FsRtl events for one restart-local mutation.

use super::*;
use crate::{memory::DriverVec, metadata::WindowsNodeMetadata, state::DirectoryChange};
use ext4_core::{CommittedReadPass, NodeId};

/// Prepares names and filters before commit; no observer sees a rejected or suspended attempt.
/// # Errors
/// Returns metadata, ancestry, storage or allocation failures while the mutation is reversible.
pub(super) fn prepare(
    request: &PreparedMutationRequest,
    existing: Option<&crate::request::create::PendingExistingCreateOpen>,
    owned: &mut OwnedIrp,
    mutation: &mut crate::request::DriverMutationPass<'_, '_, '_>,
) -> DriverResult<DriverVec<DirectoryChange>> {
    let node = match request {
        PreparedMutationRequest::Create { .. } => {
            existing.and_then(|open| open.reset_target().map(|(node, _)| node))
        }
        PreparedMutationRequest::DataWrite(
            crate::request::file_info::RegularFileDataAuthority::Paging(lease),
        ) => Some(owned.request().with_active(|active| {
            Ok::<_, DriverError>(NodeId::File(
                lease.file(active.current_stack()?.file_object()?)?,
            ))
        })?),
        PreparedMutationRequest::DataWrite(_)
        | PreparedMutationRequest::SetInformation(_)
        | PreparedMutationRequest::SetEa
        | PreparedMutationRequest::Security(_)
        | PreparedMutationRequest::SetReparsePoint
        | PreparedMutationRequest::DeleteReparsePoint => {
            Some(owned.request().with_active(|active| {
                Ok::<_, DriverError>(
                    crate::state::OpenedObject::decode(active.current_stack()?.file_object()?)?
                        .node(),
                )
            })?)
        }
        PreparedMutationRequest::DirectoryCasefold { directory, .. } => {
            Some(NodeId::Directory(*directory))
        }
        _ => None,
    };
    let mut changes = DriverVec::new();
    let Some(node) = node else {
        return Ok(changes);
    };
    let before_inode = mutation.load_node_metadata(node)?;
    let before_xattrs = mutation.read_xattrs(node)?;
    let before = WindowsNodeMetadata::from_ext4(before_inode, &before_xattrs)?;
    let after_inode = mutation.staged_node_metadata(node)?;
    let after_xattrs = mutation.staged_xattrs(node)?;
    let after = WindowsNodeMetadata::from_ext4(after_inode, &after_xattrs)?;
    let mut filter = metadata_filter(before, after);
    if before_xattrs != after_xattrs {
        if matches!(request, PreparedMutationRequest::SetEa) {
            filter |= wdk_sys::FILE_NOTIFY_CHANGE_EA;
        }
        if matches!(request, PreparedMutationRequest::Security(_)) {
            filter |= wdk_sys::FILE_NOTIFY_CHANGE_SECURITY;
        }
    }
    if filter == 0 {
        return Ok(changes);
    }
    match node {
        NodeId::Directory(directory) if directory != ext4_core::DirectoryNodeId::ROOT => {
            let parent = crate::namespace::directory_parent(mutation, directory)?;
            changes
                .try_push_owned(DirectoryChange::modified(
                    mutation,
                    parent.directory,
                    &parent.name.to_ext4()?,
                    filter,
                )?)
                .map_err(|error| error.into_parts().0)?;
        }
        NodeId::Directory(_) => {}
        NodeId::File(_) | NodeId::Symlink(_) => {
            if before_inode.links_count().on_disk_count() == 0 {
                return Ok(changes);
            }
            // A sole validated link identifies the complete notification target without a
            // filesystem-wide hard-link query. File-id and CCB-less paging retain discovery.
            if before_inode.links_count().on_disk_count() == 1 {
                let selected = match request {
                    PreparedMutationRequest::Create { .. } => existing
                        .and_then(|open| open.reset_target())
                        .map(|(_, location)| location.try_to_owned_location())
                        .transpose()?,
                    _ => owned.request().with_active(|active| {
                        let file = active.current_stack()?.file_object()?;
                        if file.handle_context().is_null() {
                            return Ok::<_, DriverError>(None);
                        }
                        let opened = crate::state::OpenedObject::decode(file)?;
                        opened.location().try_to_owned_location().map(Some)
                    })?,
                };
                if let Some(crate::state::OpenedLocation::DirectoryEntry { parent, name }) =
                    selected
                    && matches!(mutation.lookup_child(parent, &name)?, ext4_core::ChildLookup::Found(child) if *child.node() == node)
                {
                    changes
                        .try_push_owned(DirectoryChange::modified(mutation, parent, &name, filter)?)
                        .map_err(|error| error.into_parts().0)?;
                    return Ok(changes);
                }
            }
            let target = ext4_core::HardLinkNodeId::try_from(node)?;
            let links = mutation.read_hard_links(target)?;
            for link in links.entries() {
                changes
                    .try_push_owned(DirectoryChange::modified(
                        mutation,
                        link.parent(),
                        link.name(),
                        filter,
                    )?)
                    .map_err(|error| error.into_parts().0)?;
            }
        }
    }
    Ok(changes)
}

/// Selects independent Windows notification kinds from two complete metadata observations.
fn metadata_filter(before: WindowsNodeMetadata, after: WindowsNodeMetadata) -> u32 {
    let mut filter = 0;
    if before.size() != after.size() {
        filter |= wdk_sys::FILE_NOTIFY_CHANGE_SIZE;
    }
    if before.times().modified() != after.times().modified() {
        filter |= wdk_sys::FILE_NOTIFY_CHANGE_LAST_WRITE;
    }
    if before.times().accessed() != after.times().accessed() {
        filter |= wdk_sys::FILE_NOTIFY_CHANGE_LAST_ACCESS;
    }
    if before.times().created() != after.times().created() {
        filter |= wdk_sys::FILE_NOTIFY_CHANGE_CREATION;
    }
    if before.security() != after.security() {
        filter |= wdk_sys::FILE_NOTIFY_CHANGE_SECURITY;
    }
    if before.windows_file_attributes() != after.windows_file_attributes() {
        filter |= wdk_sys::FILE_NOTIFY_CHANGE_ATTRIBUTES;
    }
    filter
}
