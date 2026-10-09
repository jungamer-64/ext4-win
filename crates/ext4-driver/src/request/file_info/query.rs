//! File-information query planning and Windows record projection.

use super::*;

/// Owned query-file work selected before the first suspension point.
enum QueryFilePlan {
    /// Assemble ext4 metadata with the I/O Manager's handle-specific fields.
    All {
        /// Caller output capacity.
        length: IrpBufferLength,
        /// Target inode.
        node: NodeId,
        /// Selected namespace link.
        location: OpenedLocation,
        /// Captured shared deletion state.
        delete_pending: bool,
        /// Native stream size authority.
        stream_sizes: crate::kernel::stream::StreamSizes,
        /// FILE_OBJECT position, including asynchronous opens.
        position: i64,
    },
    /// Resolve a root-relative name entirely within one committed namespace epoch.
    Name {
        /// Caller output capacity.
        length: IrpBufferLength,
        /// Target identity, including opens made by file id.
        node: NodeId,
        /// Exact selected hard link, when create supplied one.
        location: OpenedLocation,
    },
    /// FILE_OBJECT state was packed into driver-owned storage.
    Complete {
        /// Caller output capacity.
        length: IrpBufferLength,
        /// Fully initialized staging buffer.
        output: DriverVec<u8>,
        /// Information length produced by the selected packer.
        completion: IrpCompletion,
    },
    /// Load ext4 metadata and pack the selected information class afterwards.
    Metadata {
        /// Caller output capacity.
        length: IrpBufferLength,
        /// Information layout selected by the stack.
        information_class: QueryFileInformationClass,
        /// Target ext4 node.
        node: NodeId,
        /// Shared FCB deletion state captured before metadata I/O.
        delete_pending: bool,
        /// Coherent Windows size authority, not a projection from ext4 query metadata.
        stream_sizes: crate::kernel::stream::StreamSizes,
    },
    /// Traverse the ext4 namespace for every name of one hard-linkable inode.
    HardLinks {
        /// Caller output capacity.
        length: IrpBufferLength,
        /// Non-directory target identity.
        target: HardLinkNodeId,
    },
}

#[cfg(test)]
#[path = "tests/query_fixed.rs"]
mod query_fixed_tests;

#[cfg(test)]
#[path = "tests/query_records.rs"]
mod query_record_tests;

#[cfg(test)]
#[path = "tests/query_links.rs"]
mod query_link_tests;

#[cfg(test)]
#[path = "tests/query_names.rs"]
mod query_name_tests;

#[cfg(test)]
#[path = "tests/query_all.rs"]
mod query_all_tests;

/// Packs one supported file information class.
/// # Errors
///
/// Returns an error when metadata cannot be loaded, the output buffer is too small, or the requested
/// information class cannot be packed into its Windows layout.
pub(super) fn query_file_information(
    mut request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    let plan = request.with_active(|active| {
        let current = active.current_stack()?;
        let file_object = current.file_object()?;
        let stack = current.query_file()?;
        let opened_file = OpenedObject::decode(file_object)?;
        let length = stack.length();
        let information_class = stack.information_class();
        match information_class {
            QueryFileInformationClass::All => {
                if length.as_usize() < ALL_INFORMATION_MIN_SIZE {
                    return Err(DriverError::InfoLengthMismatch);
                }
                return Ok(QueryFilePlan::All {
                    length,
                    node: opened_file.node(),
                    location: opened_file.location().try_to_owned_location()?,
                    delete_pending: opened_file.delete_pending(),
                    stream_sizes: opened_file.file_control_block().stream_sizes()?,
                    position: information_position(file_object),
                });
            }
            QueryFileInformationClass::Position => {
                let mut output = DriverVec::try_repeated_copy(0_u8, length.as_usize())?;
                let completion = pack_position_information(
                    output.as_mut_slice(),
                    information_position(file_object),
                )?;
                return Ok::<_, DriverError>(QueryFilePlan::Complete {
                    length,
                    output,
                    completion,
                });
            }
            QueryFileInformationClass::Name | QueryFileInformationClass::NormalizedName => {
                if information_class == QueryFileInformationClass::NormalizedName {
                    opened_file.require_normalized_name_access()?;
                }
                if length.as_usize() < FILE_NAME_INFORMATION_MIN_SIZE {
                    return Err(DriverError::InfoLengthMismatch);
                }
                return Ok::<_, DriverError>(QueryFilePlan::Name {
                    length,
                    node: opened_file.node(),
                    location: opened_file.location().try_to_owned_location()?,
                });
            }
            QueryFileInformationClass::HardLink => {
                let target = HardLinkNodeId::try_from(opened_file.node())
                    .map_err(|_| DriverError::FileIsDirectory)?;
                return Ok(QueryFilePlan::HardLinks { length, target });
            }
            QueryFileInformationClass::Basic
            | QueryFileInformationClass::Ea
            | QueryFileInformationClass::Standard
            | QueryFileInformationClass::StandardLink
            | QueryFileInformationClass::Internal
            | QueryFileInformationClass::NetworkOpen
            | QueryFileInformationClass::AttributeTag => {}
        }
        Ok(QueryFilePlan::Metadata {
            length,
            information_class,
            node: opened_file.node(),
            delete_pending: opened_file.delete_pending(),
            stream_sizes: opened_file.file_control_block().stream_sizes()?,
        })
    })?;
    let (length, information_class, node, delete_pending, stream_sizes) = match plan {
        QueryFilePlan::Metadata {
            length,
            information_class,
            node,
            delete_pending,
            stream_sizes,
        } => (
            length,
            information_class,
            node,
            delete_pending,
            stream_sizes,
        ),
        QueryFilePlan::Complete {
            length,
            output,
            completion,
        } => {
            request.with_active(|active| {
                memory::copy_exact(active.buffered_output(length)?, output.as_slice())?;
                Ok::<_, DriverError>(())
            })?;
            return Ok(completion);
        }
        QueryFilePlan::HardLinks { length, target } => {
            return query_hard_link_information(request, length, target, read);
        }
        QueryFilePlan::Name {
            length,
            node,
            location,
        } => {
            let name = volume_relative_name(read, node, &location)?;
            return request.with_active(|active| {
                let buffer = active.buffered_output(length)?;
                pack_name_information(buffer, name.as_slice())?.completion()
            });
        }
        QueryFilePlan::All {
            length,
            node,
            location,
            delete_pending,
            stream_sizes,
            position,
        } => {
            let metadata = metadata_from_node(read, node)?;
            let ea_size = crate::request::ea::information_size(read, node)?;
            let name = volume_relative_name(read, node, &location)?;
            let snapshot = AllFileInformation {
                metadata,
                delete_pending,
                stream_sizes,
                position,
                ea_size,
            };
            let mut output = DriverVec::try_repeated_copy(0_u8, length.as_usize())?;
            let packed = pack_all_information(output.as_mut_slice(), &snapshot, name.as_slice())?;
            request.with_active(|active| {
                let source = output
                    .as_slice()
                    .get(..packed.information())
                    .ok_or(DriverError::InternalInvariantViolation)?;
                active.publish_all_file_information(source)
            })?;
            return packed.completion();
        }
    };
    if information_class == QueryFileInformationClass::Ea {
        let size = crate::request::ea::information_size(read, node)?;
        return request.with_active(|active| {
            let buffer = active.buffered_output(length)?;
            pack_ea_information(buffer, size)
        });
    }
    let metadata = metadata_from_node(read, node)?;
    request.with_active(|active| {
        let buffer = active.buffered_output(length)?;
        match information_class {
            QueryFileInformationClass::Basic => pack_basic_information(buffer, metadata),
            QueryFileInformationClass::Standard => {
                pack_standard_information(buffer, metadata, delete_pending, stream_sizes)
            }
            QueryFileInformationClass::StandardLink => {
                pack_standard_link_information(buffer, metadata, delete_pending)
            }
            QueryFileInformationClass::Internal => pack_internal_information(buffer, metadata),
            QueryFileInformationClass::NetworkOpen => {
                pack_network_open_information(buffer, metadata, stream_sizes)
            }
            QueryFileInformationClass::AttributeTag => {
                pack_attribute_tag_information(buffer, metadata)
            }
            QueryFileInformationClass::Position
            | QueryFileInformationClass::All
            | QueryFileInformationClass::Ea
            | QueryFileInformationClass::Name
            | QueryFileInformationClass::NormalizedName
            | QueryFileInformationClass::HardLink => Err(DriverError::InternalInvariantViolation),
        }
    })
}

/// Packs the persisted Windows EA byte charge.
/// # Errors
///
/// Returns buffer-too-small without writing a partial fixed record.
fn pack_ea_information(output: &mut [u8], ea_size: u32) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<wdk_sys::FILE_EA_INFORMATION>();
    fixed_record_writer(output, size)?.write_u32(WireOffset::new(0), ea_size)?;
    IrpCompletion::from_usize(size)
}

/// Traverses and packs every Windows-visible hard-link name without retaining caller memory across
/// suspension points.
/// # Errors
///
/// Returns an error when namespace traversal, name projection, allocation, packing, or caller
/// output capture fails.
fn query_hard_link_information(
    mut request: PendingIrpLease<'_>,
    length: IrpBufferLength,
    target: HardLinkNodeId,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    let links = read.read_hard_links(target)?;
    let links = WindowsHardLinks::try_from_ext4(&links)?;
    let mut packed = DriverVec::try_repeated_copy(0_u8, length.as_usize())?;
    let result = pack_hard_link_information(packed.as_mut_slice(), &links)?;
    request.with_active(|active| {
        let output = active.buffered_output(length)?;
        let destination = output
            .get_mut(..result.information())
            .ok_or(DriverError::InternalInvariantViolation)?;
        let source = packed
            .as_slice()
            .get(..result.information())
            .ok_or(DriverError::InternalInvariantViolation)?;
        memory::copy_exact(destination, source)?;
        Ok::<_, DriverError>(())
    })?;
    result.completion()
}

/// Windows-representable projection of one complete ext4 hard-link set.
#[derive(Debug, Eq, PartialEq)]
struct WindowsHardLinks {
    /// Names that can cross the Windows UTF-16 namespace boundary.
    entries: DriverVec<WindowsHardLinkEntry>,
}

impl WindowsHardLinks {
    /// Projects ext4 names without allowing an unrepresentable component to contaminate the
    /// Windows domain.
    /// # Errors
    ///
    /// Returns an error when allocation fails or no ext4 link can be represented by Windows.
    fn try_from_ext4(links: &HardLinks) -> DriverResult<Self> {
        let mut entries = DriverVec::try_with_capacity(links.entries().len())?;
        for link in links.entries() {
            let name = match WindowsName::from_ext4(link.name()) {
                Ok(name) => name,
                Err(ext4_core::Error::InvalidName) => continue,
                Err(error) => return Err(DriverError::from(error)),
            };
            let entry = WindowsHardLinkEntry {
                parent_file_id: u64::from(NodeId::Directory(link.parent()).file_index()),
                name,
            };
            entries
                .try_push_owned(entry)
                .map_err(|error| error.into_parts().0)?;
        }
        if entries.is_empty() {
            return Err(DriverError::NotSupported);
        }
        Ok(Self { entries })
    }

    /// Windows-visible entries in namespace traversal order.
    fn entries(&self) -> &[WindowsHardLinkEntry] {
        self.entries.as_slice()
    }
}

/// One FILE_LINK_ENTRY_INFORMATION domain value before wire packing.
#[derive(Debug, Eq, PartialEq)]
struct WindowsHardLinkEntry {
    /// Stable file id of the parent directory.
    parent_file_id: u64,
    /// Link name as a Windows component.
    name: WindowsName,
}

/// Variable layout of one FILE_LINK_ENTRY_INFORMATION record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HardLinkRecordLayout {
    /// Required fixed fields and UTF-16 name bytes.
    unpadded_size: usize,
    /// Offset to a following record on its required eight-byte boundary.
    padded_size: usize,
}

impl HardLinkRecordLayout {
    /// Computes one checked record layout.
    /// # Errors
    ///
    /// Returns an error when the UTF-16 name size or aligned record size overflows.
    fn new(name: &WindowsName) -> DriverResult<Self> {
        let name_bytes = utf16_byte_len(name.utf16())?;
        let unpadded_size = HARD_LINK_ENTRY_NAME_OFFSET
            .checked_add(name_bytes)
            .ok_or(DriverError::InvalidBufferSize)?;
        Ok(Self {
            unpadded_size,
            padded_size: align_to_eight(unpadded_size)?,
        })
    }
}

/// Result of packing as many complete hard-link entries as fit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HardLinkInformationPacking {
    /// Bytes initialized in the caller-visible prefix.
    information: usize,
    /// Whether every projected entry was returned.
    all_entries_returned: bool,
}

impl HardLinkInformationPacking {
    /// Caller-visible initialized prefix length.
    const fn information(self) -> usize {
        self.information
    }

    /// Converts packing state to the exact Windows completion contract.
    /// # Errors
    ///
    /// Returns an error when the information length does not fit the IRP status block.
    fn completion(self) -> DriverResult<IrpCompletion> {
        if self.all_entries_returned {
            IrpCompletion::from_usize(self.information)
        } else {
            IrpCompletion::buffer_overflow(self.information)
        }
    }
}

/// Bytes before the first FILE_LINK_ENTRY_INFORMATION record.
const HARD_LINKS_HEADER_SIZE: usize = 8;
/// Offset of BytesNeeded in FILE_LINKS_INFORMATION.
const HARD_LINKS_BYTES_NEEDED_OFFSET: usize = 0;
/// Offset of EntriesReturned in FILE_LINKS_INFORMATION.
const HARD_LINKS_ENTRIES_RETURNED_OFFSET: usize = 4;
/// Offset of NextEntryOffset in FILE_LINK_ENTRY_INFORMATION.
const HARD_LINK_ENTRY_NEXT_OFFSET: usize = 0;
/// Offset of ParentFileId in FILE_LINK_ENTRY_INFORMATION.
const HARD_LINK_ENTRY_PARENT_ID_OFFSET: usize = 8;
/// Offset of FileNameLength in FILE_LINK_ENTRY_INFORMATION.
const HARD_LINK_ENTRY_NAME_LENGTH_OFFSET: usize = 16;
/// Offset of FileName in FILE_LINK_ENTRY_INFORMATION.
const HARD_LINK_ENTRY_NAME_OFFSET: usize = 20;

/// Packs FILE_LINKS_INFORMATION and as many complete aligned entries as the output can hold.
/// # Errors
///
/// Returns an error when the header is truncated, no entries were supplied, record arithmetic
/// overflows, or a field cannot be written inside the output buffer.
fn pack_hard_link_information(
    output: &mut [u8],
    links: &WindowsHardLinks,
) -> DriverResult<HardLinkInformationPacking> {
    let entries = links.entries();
    if entries.is_empty() {
        return Err(DriverError::InternalInvariantViolation);
    }
    if output.len() < HARD_LINKS_HEADER_SIZE {
        return Err(DriverError::InfoLengthMismatch);
    }

    let mut bytes_needed = HARD_LINKS_HEADER_SIZE;
    for (index, entry) in entries.iter().enumerate() {
        let layout = HardLinkRecordLayout::new(&entry.name)?;
        let size = if index.checked_add(1) == Some(entries.len()) {
            layout.unpadded_size
        } else {
            layout.padded_size
        };
        bytes_needed = bytes_needed
            .checked_add(size)
            .ok_or(DriverError::InvalidBufferSize)?;
    }
    let bytes_needed = u32::try_from(bytes_needed).map_err(|_| DriverError::InvalidBufferSize)?;

    clear_record(output, 0, HARD_LINKS_HEADER_SIZE)?;
    LittleEndianOutput::new(output)
        .write_u32(wire_offset(HARD_LINKS_BYTES_NEEDED_OFFSET), bytes_needed)?;
    let mut written = HARD_LINKS_HEADER_SIZE;
    let mut information = HARD_LINKS_HEADER_SIZE;
    let mut entries_returned = 0_usize;
    let mut previous_start = None;

    for entry in entries {
        let layout = HardLinkRecordLayout::new(&entry.name)?;
        let required = written
            .checked_add(layout.unpadded_size)
            .ok_or(DriverError::InvalidBufferSize)?;
        if required > output.len() {
            break;
        }
        if let Some(previous_start) = previous_start {
            let alignment_bytes = written
                .checked_sub(information)
                .ok_or(DriverError::InternalInvariantViolation)?;
            clear_record(output, information, alignment_bytes)?;
            let next = written
                .checked_sub(previous_start)
                .ok_or(DriverError::InternalInvariantViolation)?;
            LittleEndianOutput::new(output).write_u32(
                record_field_offset(previous_start, HARD_LINK_ENTRY_NEXT_OFFSET)?,
                u32::try_from(next).map_err(|_| DriverError::InvalidBufferSize)?,
            )?;
        }
        pack_hard_link_record(output, written, entry, layout)?;
        previous_start = Some(written);
        information = required;
        entries_returned = entries_returned
            .checked_add(1)
            .ok_or(DriverError::InvalidBufferSize)?;
        written = written
            .checked_add(layout.padded_size)
            .ok_or(DriverError::InvalidBufferSize)?;
    }

    LittleEndianOutput::new(output).write_u32(
        wire_offset(HARD_LINKS_ENTRIES_RETURNED_OFFSET),
        u32::try_from(entries_returned).map_err(|_| DriverError::InvalidBufferSize)?,
    )?;
    Ok(HardLinkInformationPacking {
        information,
        all_entries_returned: entries_returned == entries.len(),
    })
}

/// Packs one FILE_LINK_ENTRY_INFORMATION record.
/// # Errors
///
/// Returns an error when a fixed field or the UTF-16 link name falls outside the output buffer.
fn pack_hard_link_record(
    output: &mut [u8],
    start: usize,
    entry: &WindowsHardLinkEntry,
    layout: HardLinkRecordLayout,
) -> DriverResult<()> {
    clear_record(output, start, layout.unpadded_size)?;
    let mut writer = LittleEndianOutput::new(output);
    writer.write_u32(record_field_offset(start, HARD_LINK_ENTRY_NEXT_OFFSET)?, 0)?;
    writer.write_u64(
        record_field_offset(start, HARD_LINK_ENTRY_PARENT_ID_OFFSET)?,
        entry.parent_file_id,
    )?;
    writer.write_u32(
        record_field_offset(start, HARD_LINK_ENTRY_NAME_LENGTH_OFFSET)?,
        u32::try_from(entry.name.utf16().len()).map_err(|_| DriverError::InvalidBufferSize)?,
    )?;
    write_utf16(
        output,
        field_offset(start, HARD_LINK_ENTRY_NAME_OFFSET)?,
        entry.name.utf16(),
    )
}
/// File metadata needed by fixed-size Windows information classes.
#[derive(Clone, Copy, Debug)]
pub(super) struct FileMetadata {
    /// Stable ext4 inode id encoded for Windows file-index payloads.
    pub(super) file_index: u32,
    /// Open node kind.
    pub(super) kind: FileMetadataKind,
    /// Payload size in bytes.
    pub(super) size: FileSize,
    /// ext4 allocation charge in bytes.
    pub(super) allocation_size: FileAllocationSize,
    /// POSIX security metadata retained for metadata mutations.
    pub(super) security: Ext4Security,
    /// ext4 inode timestamps.
    pub(super) times: Ext4Times,
    /// ext4 inode link count.
    pub(super) links_count: Ext4LinkCount,
    /// Windows-specific overlay bits retained for metadata mutations.
    pub(super) overlay_attributes: u32,
    /// Complete Windows file attributes derived by the coherent core snapshot.
    pub(super) file_attributes: u32,
    /// Windows reparse metadata projected from a native symlink or private xattr.
    pub(super) reparse_point: FileMetadataReparsePoint,
}

/// Node kind projected to Windows information flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileMetadataKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
}

/// Windows-visible link state derived from one ext4 inode and its FCB lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsLinkInformation {
    /// Links whose deletion has not been requested.
    accessible_links: wdk_sys::ULONG,
    /// All namespace links, including the one selected for deferred deletion.
    total_links: wdk_sys::ULONG,
    /// Whether the FCB has selected one exact link for deferred deletion.
    delete_pending: bool,
    /// Whether the inode is a directory rather than a file-like node.
    directory: bool,
}

impl WindowsLinkInformation {
    /// Projects ext4 link accounting into the Windows query-information contract.
    ///
    /// # Errors
    ///
    /// Returns an error when a delete-pending FCB lacks the one selected namespace link that its
    /// lifecycle guarantees.
    fn from_metadata(metadata: FileMetadata, delete_pending: bool) -> DriverResult<Self> {
        let directory = metadata.kind == FileMetadataKind::Directory;
        let total_links = if directory {
            1
        } else {
            wdk_sys::ULONG::from(metadata.links_count.get())
        };
        let pending_links = wdk_sys::ULONG::from(delete_pending);
        let accessible_links = total_links
            .checked_sub(pending_links)
            .ok_or(DriverError::InternalInvariantViolation)?;
        Ok(Self {
            accessible_links,
            total_links,
            delete_pending,
            directory,
        })
    }
}

/// Reparse metadata projected to Windows file-information records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FileMetadataReparsePoint {
    /// The node has no Windows reparse metadata.
    None,
    /// The node represents a symbolic-link reparse point.
    SymbolicLink,
}

impl From<NodeMetadataSnapshot> for FileMetadata {
    /// Projects the coherent core observation to the Windows packing boundary.
    fn from(snapshot: NodeMetadataSnapshot) -> Self {
        let kind = match snapshot.node() {
            NodeId::File(_) => FileMetadataKind::File,
            NodeId::Directory(_) => FileMetadataKind::Directory,
            NodeId::Symlink(_) => FileMetadataKind::Symlink,
        };
        let reparse_point = match snapshot.reparse_point() {
            NodeReparsePoint::None => FileMetadataReparsePoint::None,
            NodeReparsePoint::SymbolicLink => FileMetadataReparsePoint::SymbolicLink,
        };
        Self {
            file_index: snapshot.node().file_index(),
            kind,
            size: snapshot.size(),
            allocation_size: snapshot.allocation_size(),
            security: snapshot.security(),
            times: snapshot.times(),
            links_count: snapshot.links_count(),
            overlay_attributes: snapshot.windows_attributes().bits(),
            file_attributes: snapshot.windows_file_attributes(),
            reparse_point,
        }
    }
}

/// Builds Windows-facing metadata from a loaded ext4 node.
/// # Errors
///
/// Returns an error when `node_id` cannot be loaded as its typed ext4 node or its Windows overlay
/// xattr is malformed.
pub(super) fn metadata_from_node(
    read: &mut impl CommittedReadPass,
    node_id: NodeId,
) -> DriverResult<FileMetadata> {
    Ok(read.load_node_metadata(node_id)?.into())
}

/// Packs FILE_BASIC_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_BASIC_INFORMATION`.
fn pack_basic_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    IrpCompletion::from_usize(
        crate::kernel::file_information::BasicInformation {
            times: [
                windows_time_quad(metadata.times.created()),
                windows_time_quad(metadata.times.accessed()),
                windows_time_quad(metadata.times.modified()),
                windows_time_quad(metadata.times.changed()),
            ],
            attributes: metadata.file_attributes,
        }
        .write_basic(output)?,
    )
}

/// Packs FILE_STANDARD_INFORMATION.
/// # Errors
///
/// Returns an error when link accounting is inconsistent or the output buffer is too small.
fn pack_standard_information(
    output: &mut [u8],
    metadata: FileMetadata,
    delete_pending: bool,
    stream_sizes: crate::kernel::stream::StreamSizes,
) -> DriverResult<IrpCompletion> {
    let links = WindowsLinkInformation::from_metadata(metadata, delete_pending)?;
    let record = crate::kernel::file_information::StandardInformation {
        allocation: stream_sizes.allocation_charge(),
        eof: stream_sizes.file_size(),
        links: links.total_links,
        delete_pending: links.delete_pending,
        directory: links.directory,
    };
    IrpCompletion::from_usize(record.write(output)?)
}

/// Packs FILE_STANDARD_LINK_INFORMATION.
/// # Errors
///
/// Returns an error when delete-pending state contradicts the selected link accounting or the
/// output buffer is too small for `FILE_STANDARD_LINK_INFORMATION`.
fn pack_standard_link_information(
    output: &mut [u8],
    metadata: FileMetadata,
    delete_pending: bool,
) -> DriverResult<IrpCompletion> {
    let links = WindowsLinkInformation::from_metadata(metadata, delete_pending)?;
    let size = core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_LINK_INFORMATION,
            NumberOfAccessibleLinks
        )),
        links.accessible_links,
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_LINK_INFORMATION,
            TotalNumberOfLinks
        )),
        links.total_links,
    )?;
    writer.write_u8(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_LINK_INFORMATION,
            DeletePending
        )),
        boolean(links.delete_pending),
    )?;
    writer.write_u8(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_LINK_INFORMATION,
            Directory
        )),
        boolean(links.directory),
    )?;
    IrpCompletion::from_usize(size)
}

/// Packs FILE_INTERNAL_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_INTERNAL_INFORMATION`.
fn pack_internal_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<wdk_sys::FILE_INTERNAL_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_INTERNAL_INFORMATION,
            IndexNumber
        )),
        i64::from(metadata.file_index),
    )?;
    IrpCompletion::from_usize(size)
}

/// Packs FILE_POSITION_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_POSITION_INFORMATION`.
fn pack_position_information(output: &mut [u8], position: i64) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_POSITION_INFORMATION,
            CurrentByteOffset
        )),
        position,
    )?;
    IrpCompletion::from_usize(size)
}

/// Observes the Windows position field without granting synchronous read/write cursor authority.
fn information_position(file_object: ActiveFileObject<'_>) -> i64 {
    file_object.current_byte_offset()
}

/// Packs FILE_NETWORK_OPEN_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_NETWORK_OPEN_INFORMATION`.
fn pack_network_open_information(
    output: &mut [u8],
    metadata: FileMetadata,
    stream_sizes: crate::kernel::stream::StreamSizes,
) -> DriverResult<IrpCompletion> {
    IrpCompletion::from_usize(
        crate::kernel::file_information::BasicInformation {
            times: [
                windows_time_quad(metadata.times.created()),
                windows_time_quad(metadata.times.accessed()),
                windows_time_quad(metadata.times.modified()),
                windows_time_quad(metadata.times.changed()),
            ],
            attributes: metadata.file_attributes,
        }
        .write_network(
            output,
            stream_sizes.allocation_charge(),
            stream_sizes.file_size(),
        )?,
    )
}

/// Packs FILE_ATTRIBUTE_TAG_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_ATTRIBUTE_TAG_INFORMATION`.
fn pack_attribute_tag_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<wdk_sys::FILE_ATTRIBUTE_TAG_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_ATTRIBUTE_TAG_INFORMATION,
            FileAttributes
        )),
        metadata.file_attributes,
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_ATTRIBUTE_TAG_INFORMATION,
            ReparseTag
        )),
        reparse_tag(metadata.reparse_point),
    )?;
    IrpCompletion::from_usize(size)
}

/// Resolves names against the current committed epoch; ancestor renames do not leave a stale
/// path cache. A named open uses its selected link while that link still names the inode. If a
/// different handle renamed it, or create used a file id, a reachable link supplies the name.
/// # Errors
/// Returns namespace corruption, storage, projection, or allocation errors. An inode without a
/// reachable Windows name cannot supply a path.
fn volume_relative_name(
    read: &mut impl CommittedReadPass,
    node: NodeId,
    location: &OpenedLocation,
) -> DriverResult<DriverVec<u16>> {
    match location {
        OpenedLocation::Root => DriverVec::try_copied_from_slice(&[UTF16_BACKSLASH]),
        OpenedLocation::DirectoryEntry { parent, name } => {
            let loaded = read.load_directory(*parent)?;
            let visible_name = WindowsName::from_ext4(name)?;
            let child = match read.lookup_windows_child(
                &loaded,
                &visible_name,
                ext4_core::WindowsNameMatch::Exact,
            )? {
                ChildLookup::Found(child) if *child.node() == node => child,
                ChildLookup::Found(_) | ChildLookup::NotFound => {
                    return node_relative_name(read, node);
                }
            };
            let mut components = DriverVec::new();
            components
                .try_push_owned(WindowsName::from_ext4(child.name())?)
                .map_err(|error| error.into_parts().0)?;
            directory_relative_name(read, *parent, components)
        }
        OpenedLocation::FileReference => node_relative_name(read, node),
    }
}

/// Resolves an inode without a surviving selected link to one reachable Windows name.
/// # Errors
/// Returns namespace, storage, projection, or allocation errors, or not-supported when no link
/// has a Windows-representable path.
fn node_relative_name(
    read: &mut impl CommittedReadPass,
    node: NodeId,
) -> DriverResult<DriverVec<u16>> {
    match node {
        NodeId::Directory(directory) => directory_relative_name(read, directory, DriverVec::new()),
        NodeId::File(_) | NodeId::Symlink(_) => {
            let target = HardLinkNodeId::try_from(node)
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            let links = read.read_hard_links(target)?;
            for link in links.entries() {
                let projected = match WindowsName::from_ext4(link.name()) {
                    Ok(name) => name,
                    Err(ext4_core::Error::InvalidName) => continue,
                    Err(error) => return Err(error.into()),
                };
                let mut components = DriverVec::new();
                components
                    .try_push_owned(projected)
                    .map_err(|error| error.into_parts().0)?;
                match directory_relative_name(read, link.parent(), components) {
                    Err(DriverError::Core(ext4_core::Error::InvalidName)) => continue,
                    result => return result,
                }
            }
            Err(DriverError::NotSupported)
        }
    }
}

/// Ascends ext4's unique directory ancestry and collects components from leaf to root.
/// # Errors
/// Returns an error for cyclic ancestry, a malformed parent relation, unavailable storage,
/// unrepresentable names, or allocation failure.
fn directory_relative_name(
    read: &mut impl CommittedReadPass,
    mut directory: DirectoryNodeId,
    mut components: DriverVec<WindowsName>,
) -> DriverResult<DriverVec<u16>> {
    let mut visited = DriverVec::new();
    while directory != DirectoryNodeId::ROOT {
        if visited.as_slice().contains(&directory) {
            return Err(ext4_core::Error::InvalidDirectoryEntry.into());
        }
        visited.try_push(directory)?;
        let loaded = read.load_directory(directory)?;
        let parent = match read.lookup_child(&loaded, &Ext4Name::new(b"..")?)? {
            ChildLookup::Found(child) => match *child.node() {
                NodeId::Directory(parent) => parent,
                NodeId::File(_) | NodeId::Symlink(_) => {
                    return Err(ext4_core::Error::InvalidDirectoryEntry.into());
                }
            },
            ChildLookup::NotFound => return Err(ext4_core::Error::InvalidDirectoryEntry.into()),
        };
        let mut reader =
            ext4_core::DirectoryReader::new(parent, ext4_core::DirectoryScanCursor::start());
        let mut name = None;
        while let Some(scanned) = read.next_directory_entry(&mut reader)? {
            let entry = scanned.into_entry();
            if entry.name().bytes() == b"." || entry.name().bytes() == b".." {
                continue;
            }
            if *entry.node() == NodeId::Directory(directory) {
                if name.is_some() {
                    return Err(ext4_core::Error::InvalidDirectoryEntry.into());
                }
                name = Some(WindowsName::from_ext4(entry.name())?);
            }
        }
        components
            .try_push_owned(name.ok_or(ext4_core::Error::InvalidDirectoryEntry)?)
            .map_err(|error| error.into_parts().0)?;
        directory = parent;
    }
    assemble_relative_name(components.as_slice())
}

/// Encodes leaf-to-root components as a root-relative Windows path.
/// # Errors
/// Returns an error when the path cannot be allocated.
fn assemble_relative_name(components: &[WindowsName]) -> DriverResult<DriverVec<u16>> {
    let mut units = DriverVec::new();
    if components.is_empty() {
        units.try_push(UTF16_BACKSLASH)?;
    }
    for component in components.iter().rev() {
        units.try_push(UTF16_BACKSLASH)?;
        units.try_extend_from_copy_slice(component.utf16())?;
    }
    Ok(units)
}

/// Packs the full name length and the whole UTF-16 units that fit. BUFFER_OVERFLOW carries the
/// initialized prefix length, allowing the caller to resize without losing the required length.
/// # Errors
/// Returns info-length-mismatch without writes below the Windows minimum, or a size-conversion
/// error before publication.
fn pack_name_information(output: &mut [u8], units: &[u16]) -> DriverResult<FileInformationPacking> {
    if output.len() < FILE_NAME_INFORMATION_MIN_SIZE {
        return Err(DriverError::InfoLengthMismatch);
    }
    let name_bytes = utf16_byte_len(units)?;
    let name_length = u32::try_from(name_bytes).map_err(|_| DriverError::InvalidBufferSize)?;
    let available_units = output
        .len()
        .checked_sub(FILE_NAME_INFORMATION_NAME_OFFSET)
        .ok_or(DriverError::InternalInvariantViolation)?
        / 2;
    let copied = units.len().min(available_units);
    let copied_units = units
        .get(..copied)
        .ok_or(DriverError::InternalInvariantViolation)?;
    let information = FILE_NAME_INFORMATION_NAME_OFFSET
        .checked_add(utf16_byte_len(copied_units)?)
        .ok_or(DriverError::InvalidBufferSize)?;
    let completion = if copied == units.len() {
        FileInformationPacking::Complete { information }
    } else {
        FileInformationPacking::Truncated { information }
    };
    LittleEndianOutput::new(output).write_u32(
        WireOffset::new(FILE_NAME_INFORMATION_NAME_LENGTH_OFFSET),
        name_length,
    )?;
    write_utf16(output, FILE_NAME_INFORMATION_NAME_OFFSET, copied_units)?;
    Ok(completion)
}

/// Initialized variable-information output and its terminal query status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileInformationPacking {
    /// The full record is present.
    Complete {
        /// Initialized output prefix length.
        information: usize,
    },
    /// The fixed fields and a whole-WCHAR prefix of the name are present.
    Truncated {
        /// Initialized output prefix length.
        information: usize,
    },
}

impl FileInformationPacking {
    /// Returns the exact prefix to publish to the caller.
    const fn information(self) -> usize {
        match self {
            Self::Complete { information } | Self::Truncated { information } => information,
        }
    }

    /// Includes an enclosing fixed record in the initialized byte count.
    /// # Errors
    /// Returns an error when the combined information length overflows.
    fn with_prefix(self, prefix: usize) -> DriverResult<Self> {
        let information = self
            .information()
            .checked_add(prefix)
            .ok_or(DriverError::InvalidBufferSize)?;
        Ok(match self {
            Self::Complete { .. } => Self::Complete { information },
            Self::Truncated { .. } => Self::Truncated { information },
        })
    }

    /// Preserves partial progress when completing a truncated record.
    /// # Errors
    /// Returns an error when the byte count does not fit the IRP status block.
    fn completion(self) -> DriverResult<IrpCompletion> {
        match self {
            Self::Complete { information } => IrpCompletion::from_usize(information),
            Self::Truncated { information } => IrpCompletion::buffer_overflow(information),
        }
    }
}

/// Coherent filesystem and handle observations used to construct one aggregate query.
struct AllFileInformation {
    /// Metadata from the selected committed epoch.
    metadata: FileMetadata,
    /// Native deletion state observed when the query starts.
    delete_pending: bool,
    /// Authoritative Windows stream sizes.
    stream_sizes: crate::kernel::stream::StreamSizes,
    /// Current position of the FILE_OBJECT.
    position: i64,
    /// Packed Windows EA charge from the same epoch as metadata.
    ea_size: u32,
}

/// Packs FILE_ALL_INFORMATION without deriving handle rights or stream sizes from inode data.
/// # Errors
/// Returns info-length-mismatch below the Windows minimum, inconsistent link accounting,
/// conversion errors, or malformed output ranges.
fn pack_all_information(
    output: &mut [u8],
    snapshot: &AllFileInformation,
    name: &[u16],
) -> DriverResult<FileInformationPacking> {
    if output.len() < ALL_INFORMATION_MIN_SIZE {
        return Err(DriverError::InfoLengthMismatch);
    }
    pack_basic_information(
        all_field(
            output,
            core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, BasicInformation),
        )?,
        snapshot.metadata,
    )?;
    pack_standard_information(
        all_field(
            output,
            core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, StandardInformation),
        )?,
        snapshot.metadata,
        snapshot.delete_pending,
        snapshot.stream_sizes,
    )?;
    pack_internal_information(
        all_field(
            output,
            core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, InternalInformation),
        )?,
        snapshot.metadata,
    )?;
    pack_ea_information(
        all_field(
            output,
            core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, EaInformation),
        )?,
        snapshot.ea_size,
    )?;
    pack_position_information(
        all_field(
            output,
            core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, PositionInformation),
        )?,
        snapshot.position,
    )?;
    pack_name_information(all_field(output, ALL_INFORMATION_NAME_OFFSET)?, name)?
        .with_prefix(ALL_INFORMATION_NAME_OFFSET)
}

/// Selects a WDK-defined field suffix for a packer that owns only its fixed record prefix.
/// # Errors
/// Returns an internal invariant error when the enclosing layout is smaller than its field.
fn all_field(output: &mut [u8], offset: usize) -> DriverResult<&mut [u8]> {
    output
        .get_mut(offset..)
        .ok_or(DriverError::InternalInvariantViolation)
}

/// Offset of NameInformation within the WDK aggregate layout.
const ALL_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ALL_INFORMATION, NameInformation);
/// Minimum fixed aggregate and WCHAR capacity accepted by the query protocol.
const ALL_INFORMATION_MIN_SIZE: usize =
    ALL_INFORMATION_NAME_OFFSET + FILE_NAME_INFORMATION_MIN_SIZE;

/// Returns the reparse tag associated with file metadata.
pub(super) const fn reparse_tag(reparse_point: FileMetadataReparsePoint) -> wdk_sys::ULONG {
    match reparse_point {
        FileMetadataReparsePoint::None => 0,
        FileMetadataReparsePoint::SymbolicLink => wdk_sys::IO_REPARSE_TAG_SYMLINK,
    }
}

/// Offset of FileNameLength in FILE_NAME_INFORMATION.
const FILE_NAME_INFORMATION_NAME_LENGTH_OFFSET: usize = 0;
/// Offset of FileName in FILE_NAME_INFORMATION.
const FILE_NAME_INFORMATION_NAME_OFFSET: usize = 4;
/// Four-byte aligned header plus at least one WCHAR, as required by the query protocol.
const FILE_NAME_INFORMATION_MIN_SIZE: usize = 8;

/// Clears one fixed-size information record before its fields are encoded.
/// # Errors
///
/// Returns an error when `output` is smaller than `size`.
fn fixed_record_writer(output: &mut [u8], size: usize) -> DriverResult<LittleEndianOutput<'_>> {
    let record = output.get_mut(..size).ok_or(DriverError::BufferTooSmall)?;
    record.fill(0);
    Ok(LittleEndianOutput::new(record))
}

/// Converts an ext4 timestamp to a Windows system-time LARGE_INTEGER.
#[expect(
    unsafe_code,
    reason = "Windows time conversion crosses the audited RtlSecondsSince1970ToTime ABI"
)]
pub(super) fn windows_time(timestamp: Ext4Timestamp) -> LARGE_INTEGER {
    let mut time = LARGE_INTEGER { QuadPart: 0 };
    unsafe {
        // SAFETY: `time` points to writable stack storage for the conversion
        // result.
        crate::kernel::ffi::RtlSecondsSince1970ToTime(
            timestamp.seconds(),
            core::ptr::addr_of_mut!(time),
        );
    }
    time
}

/// Converts a Rust boolean to WDK BOOLEAN.
fn boolean(value: bool) -> wdk_sys::BOOLEAN {
    u8::from(value)
}
