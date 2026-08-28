//! File object IRP handlers and file information packing boundary.

use alloc::boxed::Box;
use core::{num::NonZeroUsize, ptr::NonNull};

use ext4_core::{
    ChildLookup, CommittedReadPass, DirectoryNode, DirectoryNodeId, DirectoryScanLimit,
    Ext4LinkCount, Ext4Name, Ext4Permissions, Ext4Security, Ext4Times, Ext4Timestamp,
    Ext4WindowsAttributes, FileAllocationSize, FileNodeId, FileOffset, FileSize,
    HardLinkDestination, HardLinkNodeId, HardLinks, NodeId, RenameTargetCollision, WindowsName,
    WindowsOverlay,
};
use wdk_sys::LARGE_INTEGER;

use crate::irp::{
    ActiveFileObject, ActiveIrp, CreateDeletion, DataIoKind, DirectoryChangeFilter,
    DirectoryCursorPosition, DirectoryEntryEmission, DirectoryInformationClass,
    DirectoryWatchScope, FileAttributesWriteAccess, IrpBufferLength, IrpCompletion, OwnedIrp,
    PendingIrpLease, PreparedDirectoryPattern, QueryFileInformationClass, ReadStartingPoint,
    RegularFileWriteAccess, SetFileInformationClass, SetFileStack, WriteStartingPoint,
};
use crate::kernel::status::{DriverError, DriverResult};
use crate::memory::{self, DriverVec};
use crate::state::{
    CleanupStart, CloseReleasePlan, DirectoryChange, DirectoryChangeAction, DirectoryCursor,
    DirectoryNotificationRegistration, FileCleanupDisposition, FileControlBlock, FileDeleteTarget,
    MountedVolumeAccess, MountedVolumeDevice, OpenedDirectory, OpenedFileObject, OpenedLocation,
    OpenedObject, OpenedRegularFile, PendingFileDeletion, PreparedFilePositionPublication,
    PreparedHandleAdmission, PreparedOpenedLocationPublication, VolumeHandleCleanup,
    VolumeRetirement, release_cancelled_file_control_block, release_file_control_block,
};
use crate::wire::{LittleEndianInput, LittleEndianOutput, WireByteLen, WireOffset, WireRange};

use super::DriverMutationPass;

/// Maximum requestor data bytes copied through driver-owned memory at one time.
const MAX_DATA_TRANSFER_WINDOW_BYTES: usize = 65_536;

/// Captures one opened-handle lifecycle capability while the top-level IRP retains its contexts.
/// # Errors
///
/// Returns an error when a non-empty filesystem context pair is malformed.
pub(crate) fn prepare_handle_admission(
    mut request: PendingIrpLease<'_>,
) -> DriverResult<Option<PreparedHandleAdmission>> {
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        if file_object.has_no_file_system_contexts() {
            return Ok(None);
        }
        OpenedFileObject::decode(file_object)
            .map(OpenedFileObject::prepare_admission)
            .map(Some)
    })
}

/// One non-empty, bounded interval selected from a pending data-transfer IRP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DataTransferWindow {
    /// Byte displacement from the start of the request transfer.
    offset: usize,
    /// Exact non-zero byte count copied in this interval.
    length: NonZeroUsize,
}

impl DataTransferWindow {
    /// Byte displacement from the start of the request transfer.
    const fn offset(self) -> usize {
        self.offset
    }

    /// Exact byte count in this window.
    const fn length(self) -> usize {
        self.length.get()
    }
}

/// Monotonic state machine partitioning one non-empty data transfer into bounded copies.
#[derive(Debug)]
struct DataTransferWindows {
    /// Exact request byte count.
    total: NonZeroUsize,
    /// Prefix already selected for transfer.
    completed: usize,
}

/// Driver-visible values prepared before a write mutation issues lower I/O.
#[derive(Debug)]
pub(crate) struct PreparedWritePublication {
    /// Checked completion byte count.
    completion: IrpCompletion,
    /// Infallible FILE_OBJECT cursor publication.
    position: PreparedFilePositionPublication,
}

/// Result of one restartable write resolve pass.
#[derive(Debug)]
pub(crate) enum WriteResolution {
    /// Empty write completed without staging a filesystem mutation.
    Complete(IrpCompletion),
    /// Non-empty write staged data and metadata for journal commit.
    Mutation(PreparedWritePublication),
}

impl PreparedWritePublication {
    /// Publishes the prepared cursor and reveals terminal IRP completion.
    pub(crate) fn publish(self) -> IrpCompletion {
        self.position.publish();
        self.completion
    }
}

impl DataTransferWindows {
    /// Starts at the first byte of one non-empty request.
    const fn new(total: NonZeroUsize) -> Self {
        Self {
            total,
            completed: 0,
        }
    }

    /// Required reusable snapshot allocation size.
    const fn snapshot_capacity(&self) -> usize {
        if self.total.get() < MAX_DATA_TRANSFER_WINDOW_BYTES {
            self.total.get()
        } else {
            MAX_DATA_TRANSFER_WINDOW_BYTES
        }
    }

    /// Selects and advances past the next non-empty input window.
    /// # Errors
    ///
    /// Returns an invariant error if internal progress no longer describes a prefix of `total`.
    fn next_window(&mut self) -> DriverResult<Option<DataTransferWindow>> {
        let remaining = self
            .total
            .get()
            .checked_sub(self.completed)
            .ok_or(DriverError::InternalInvariantViolation)?;
        let Some(length) =
            NonZeroUsize::new(core::cmp::min(remaining, MAX_DATA_TRANSFER_WINDOW_BYTES))
        else {
            return Ok(None);
        };
        let window = DataTransferWindow {
            offset: self.completed,
            length,
        };
        self.completed = self
            .completed
            .checked_add(length.get())
            .ok_or(DriverError::InternalInvariantViolation)?;
        Ok(Some(window))
    }

    /// Exact prefix selected so far.
    const fn completed(&self) -> usize {
        self.completed
    }
}

/// Executes cleanup IRPs, including final-active-handle deferred deletion.
/// # Errors
///
/// Returns an error when the IRP stack has no opened FILE_OBJECT, cleanup state is invalid, or a
/// pending namespace deletion cannot be committed.
pub(crate) fn cleanup(
    mut request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<CleanupResolution> {
    let plan = request.with_active(|active| begin_cleanup_file_object(active, operations))?;
    Ok(match plan {
        CleanupPlan::Complete => CleanupResolution::Complete(IrpCompletion::EMPTY),
        CleanupPlan::Delete(plan) => CleanupResolution::Delete(plan),
    })
}

/// Result of entering one per-handle terminal cleanup barrier.
#[derive(Debug)]
pub(crate) enum CleanupResolution {
    /// Cleanup released every handle-owned resource without a namespace mutation.
    Complete(IrpCompletion),
    /// The final handle requires one journaled deletion before cleanup completes.
    Delete(PendingCleanupDeletion),
}

/// Allocation-free driver publication paired with a committed cleanup deletion.
#[derive(Debug)]
pub(crate) struct PreparedCleanupPublication {
    /// Shared FCB whose stable pending target becomes complete.
    fcb: NonNull<FileControlBlock>,
    /// FCB-owned target allocation consumed by the publication.
    target: NonNull<FileDeleteTarget>,
    /// Preallocated namespace notification.
    notification: DirectoryChange,
}

impl PreparedCleanupPublication {
    /// Publishes the completed deletion and notification without allocation or ordinary failure.
    pub(crate) fn publish(self, operations: &mut MountedVolumeAccess<'_>) -> IrpCompletion {
        operations.complete_file_delete(self.fcb, self.target);
        operations.report_directory_change(self.notification);
        IrpCompletion::EMPTY
    }
}

#[expect(
    unsafe_code,
    reason = "the cleanup publication remains reactor-owned while the handle barrier retains its pointers"
)]
// SAFETY: FCB/target lifetime is protected by the cleanup barrier through publication, and the
// token is moved only through reactor-owned operation state.
unsafe impl Send for PreparedCleanupPublication {}

/// Executes close IRPs and releases FILE_OBJECT contexts.
/// # Errors
///
/// Returns an error when the close stack has no FILE_OBJECT.
pub(crate) fn close(
    target: &mut ActiveIrp<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<IrpCompletion> {
    let file_object = target.current_stack()?.file_object()?;
    if release_file_contexts(target.device(), file_object, operations) == VolumeRetirement::Start {
        MountedVolumeDevice::schedule_retirement(target.device());
    }
    Ok(IrpCompletion::EMPTY)
}

/// Executes regular file data reads.
/// # Errors
///
/// Returns an error when read stack decoding, output buffer mapping, or ext4 file reading fails.
pub(crate) fn read(
    request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    read_regular_file_direct(request, read)
}

/// Executes regular file data writes.
/// # Errors
///
/// Returns an error when write stack decoding, input buffer mapping, or ext4 file mutation fails.
pub(crate) fn write(
    request: PendingIrpLease<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<WriteResolution> {
    write_regular_file_windowed(request, mutation)
}

/// Executes file information queries.
/// # Errors
///
/// Returns an error when query stack decoding or information packing fails.
pub(crate) fn query(
    request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    query_file_information(request, read)
}

/// Executes file information mutations.
/// # Errors
///
/// Returns an error when set stack decoding or the requested file mutation fails.
pub(crate) fn set(
    request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<SetFileResolution> {
    set_file_information(request, operations, mutation)
}

/// Transfers one queued directory-change IRP to the VCB's FsRtl notification list.
#[expect(
    unsafe_code,
    reason = "the active notification IRP retains the mounted VCB borrowed for FsRtl registration"
)]
pub(crate) fn notify_change_directory(mut owned: OwnedIrp) -> wdk_sys::NTSTATUS {
    let registration = owned.request().with_active(|active| {
        DirectoryNotificationRequest::decode(active).and_then(|mut request| {
            let registration = request.registration()?;
            let volume = request.opened_directory().volume();
            let vcb = unsafe {
                // SAFETY: OpenedDirectory was decoded from this active pending IRP.
                volume.as_ref()
            };
            Ok((NonNull::from(vcb.directory_change_notifier()), registration))
        })
    });
    match registration {
        Ok((notifier, registration)) => {
            owned.delegate_directory_notification(notifier, registration)
        }
        Err(error) => owned.complete_result(Err(error)),
    }
}

/// Directory notification selected from a valid notify-change IRP.
#[derive(Debug)]
pub(crate) struct DirectoryNotificationRequest<'owner> {
    /// Opened directory whose FILE_OBJECT owns this notification.
    opened_directory: OpenedDirectory<'owner>,
    /// Change kinds that may complete this request.
    completion_filter: DirectoryChangeFilter,
    /// Direct-child or descendant directory scope.
    watch_scope: DirectoryWatchScope,
}

impl<'owner> DirectoryNotificationRequest<'owner> {
    /// Decodes the active directory-change stack location.
    /// # Errors
    ///
    /// Returns an error when the stack is malformed or its FILE_OBJECT is not an opened directory.
    fn decode(target: &'owner mut ActiveIrp<'_>) -> DriverResult<Self> {
        let current = target.current_stack()?;
        let file_object = current.file_object()?;
        let stack = current.notify_directory()?;
        Ok(Self {
            opened_directory: OpenedDirectory::decode(file_object)?,
            completion_filter: stack.completion_filter(),
            watch_scope: stack.watch_scope(),
        })
    }

    /// Returns the directory that owns this notification request.
    pub(crate) fn opened_directory(&self) -> &OpenedDirectory<'owner> {
        &self.opened_directory
    }

    /// Converts this request into the exact FsRtl registration semantics this driver supports.
    /// # Errors
    ///
    /// Returns an error when recursive watching or non-name completion filters are requested.
    fn registration(&mut self) -> DriverResult<DirectoryNotificationRegistration> {
        if self.watch_scope.watches_subtree() {
            return Err(DriverError::NotSupported);
        }
        let full_directory_name = self.opened_directory.notification_directory_name()?;
        Ok(DirectoryNotificationRegistration::new(
            full_directory_name,
            self.opened_directory.notification_context(),
            self.completion_filter.namespace_name_filter()?,
        ))
    }
}

/// Executes byte-range lock requests.
/// # Errors
///
/// Returns an error when the lock stack is malformed or the target is not an opened regular file.
pub(crate) fn lock_control(target: &mut ActiveIrp<'_>) -> DriverResult<NonNull<FileControlBlock>> {
    let file_object = target.current_stack()?.file_object()?;
    let opened = OpenedRegularFile::decode(file_object)?;
    Ok(NonNull::from(opened.file_control_block()))
}

/// Owned query-file work selected before the first suspension point.
enum QueryFilePlan {
    /// The synchronous FILE_OBJECT state was packed into driver-owned storage.
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
    },
    /// Traverse the ext4 namespace for every name of one hard-linkable inode.
    HardLinks {
        /// Caller output capacity.
        length: IrpBufferLength,
        /// Non-directory target identity.
        target: HardLinkNodeId,
    },
}

/// Packs one supported file information class.
/// # Errors
///
/// Returns an error when metadata cannot be loaded, the output buffer is too small, or the requested
/// information class cannot be packed into its Windows layout.
fn query_file_information(
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
            QueryFileInformationClass::Position => {
                let mut output = DriverVec::try_repeated_copy(0_u8, length.as_usize())?;
                let completion = pack_position_information(output.as_mut_slice(), &opened_file)?;
                return Ok::<_, DriverError>(QueryFilePlan::Complete {
                    length,
                    output,
                    completion,
                });
            }
            QueryFileInformationClass::Name => {
                let mut output = DriverVec::try_repeated_copy(0_u8, length.as_usize())?;
                let completion = pack_name_information(output.as_mut_slice(), &opened_file)?;
                return Ok::<_, DriverError>(QueryFilePlan::Complete {
                    length,
                    output,
                    completion,
                });
            }
            QueryFileInformationClass::HardLink => {
                let target = HardLinkNodeId::try_from(opened_file.node())
                    .map_err(|_| DriverError::FileIsDirectory)?;
                return Ok(QueryFilePlan::HardLinks { length, target });
            }
            QueryFileInformationClass::Basic
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
        })
    })?;
    let (length, information_class, node, delete_pending) = match plan {
        QueryFilePlan::Metadata {
            length,
            information_class,
            node,
            delete_pending,
        } => (length, information_class, node, delete_pending),
        QueryFilePlan::Complete {
            length,
            output,
            completion,
        } => {
            request.with_active(|active| {
                memory::copy_exact(
                    active.buffered_output(length)?.as_mut_slice(),
                    output.as_slice(),
                )?;
                Ok::<_, DriverError>(())
            })?;
            return Ok(completion);
        }
        QueryFilePlan::HardLinks { length, target } => {
            return query_hard_link_information(request, length, target, read);
        }
    };
    let metadata = metadata_from_node(read, node)?;
    request.with_active(|active| {
        let mut buffer = active.buffered_output(length)?;
        match information_class {
            QueryFileInformationClass::Basic => {
                pack_basic_information(buffer.as_mut_slice(), metadata)
            }
            QueryFileInformationClass::Standard => {
                pack_standard_information(buffer.as_mut_slice(), metadata, delete_pending)
            }
            QueryFileInformationClass::StandardLink => {
                pack_standard_link_information(buffer.as_mut_slice(), metadata, delete_pending)
            }
            QueryFileInformationClass::Internal => {
                pack_internal_information(buffer.as_mut_slice(), metadata)
            }
            QueryFileInformationClass::NetworkOpen => {
                pack_network_open_information(buffer.as_mut_slice(), metadata)
            }
            QueryFileInformationClass::AttributeTag => {
                pack_attribute_tag_information(buffer.as_mut_slice(), metadata)
            }
            QueryFileInformationClass::Position
            | QueryFileInformationClass::Name
            | QueryFileInformationClass::HardLink => Err(DriverError::InternalInvariantViolation),
        }
    })
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
        let mut output = active.buffered_output(length)?;
        let destination = output
            .as_mut_slice()
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

/// Applies one supported set-file-information class.
enum SetFilePlan {
    /// The request completed entirely while decoding its synchronous control-plane mutation.
    Complete,
    /// Apply timestamps and overlay attributes to one node.
    Basic {
        /// Caller update copied from the IRP buffer.
        info: wdk_sys::FILE_BASIC_INFORMATION,
        /// Target ext4 node.
        node: NodeId,
    },
    /// Set the exact logical end of file.
    EndOfFile {
        /// Target regular file.
        file: FileNodeId,
        /// Requested logical size.
        size: FileSize,
    },
    /// Shrink allocation when the requested sparse-model size is below EOF.
    Allocation {
        /// Target regular file.
        file: FileNodeId,
        /// Requested allocation bound.
        size: FileSize,
    },
    /// Validate and publish one identity-bound delete-pending target.
    Disposition {
        /// Target ext4 inode identity.
        node: NodeId,
        /// Prepared exact parent/name identity.
        pending: PendingFileDeletion,
        /// Whether validation publishes a new state or reaffirms create-time delete-on-close.
        publication: DeletePendingPublication,
        /// Whether the extended request bypasses the read-only Windows attribute.
        readonly: DeleteReadonlyPolicy,
    },
    /// Commit one fully owned hard-link creation.
    Link {
        /// Caller-independent hard-link domain values.
        mutation: HardLinkMutation,
    },
    /// Commit one fully owned namespace rename.
    Rename {
        /// Caller-independent rename domain values.
        mutation: RenameMutation,
        /// Stable CCB receiving the new location only after durable commit.
        file_object: crate::state::KernelFileObject,
    },
}

/// Result of one restartable set-information resolve pass.
#[derive(Debug)]
pub(crate) enum SetFileResolution {
    /// No ext4 mutation was staged; all requested control-plane work is complete.
    Complete(IrpCompletion),
    /// Ext4 mutation requires commit and the driver publication is fully prepared.
    Mutation(SetFilePublication),
}

/// Allocation-free driver publication paired with a set-information mutation.
#[derive(Debug)]
pub(crate) enum SetFilePublication {
    /// No driver-visible state changes after commit.
    None,
    /// Ordered namespace notifications for a committed hard-link mutation.
    HardLink(Box<HardLinkDirectoryChanges>),
    /// Handle-location and notification moves for a committed rename.
    Rename {
        /// Stable CCB update prepared before the first write.
        location: PreparedOpenedLocationPublication,
        /// Fully allocated notification sequence.
        notifications: Box<RenameDirectoryNameChanges>,
    },
}

impl SetFilePublication {
    /// Publishes prepared driver state without allocation or ordinary failure.
    pub(crate) fn publish(self, operations: &MountedVolumeAccess<'_>) {
        match self {
            Self::None => {}
            Self::HardLink(changes) => (*changes).report(operations),
            Self::Rename {
                location,
                notifications,
            } => {
                location.publish();
                notifications.report(operations);
            }
        }
    }
}

/// Applies one supported set-file-information class.
/// # Errors
///
/// Returns an error when the selected set-information class has invalid input or its ext4 metadata
/// mutation cannot be committed.
fn set_file_information(
    mut request: PendingIrpLease<'_>,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<SetFileResolution> {
    let plan = request.with_active(|active| {
        let current = active.current_stack()?;
        let file_object = current.file_object()?;
        let stack = current.set_file()?;
        let mut opened_file = OpenedObject::decode(file_object)?;
        let plan = match stack.information_class() {
            SetFileInformationClass::Basic => SetFilePlan::Basic {
                info: read_basic_information_input(active, stack.length())?,
                node: opened_file.node(),
            },
            SetFileInformationClass::Position => {
                set_position_information(active, stack, &mut opened_file)?;
                SetFilePlan::Complete
            }
            SetFileInformationClass::EndOfFile => {
                let end_of_file = read_end_of_file_input(active, stack.length())?;
                let regular_file = OpenedRegularFile::decode(file_object)?;
                SetFilePlan::EndOfFile {
                    file: regular_file.id(),
                    size: file_size_from_large_integer(end_of_file)?,
                }
            }
            SetFileInformationClass::Allocation => {
                let allocation_size = read_allocation_size_input(active, stack.length())?;
                let regular_file = OpenedRegularFile::decode(file_object)?;
                SetFilePlan::Allocation {
                    file: regular_file.id(),
                    size: file_size_from_large_integer(allocation_size)?,
                }
            }
            SetFileInformationClass::Disposition => {
                disposition_plan(active, stack, &opened_file, DispositionInputFormat::Legacy)?
            }
            SetFileInformationClass::DispositionEx => disposition_plan(
                active,
                stack,
                &opened_file,
                DispositionInputFormat::Extended,
            )?,
            SetFileInformationClass::Link => SetFilePlan::Link {
                mutation: HardLinkMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    HardLinkInformationFormat::ReplaceIfExistsByte,
                )?,
            },
            SetFileInformationClass::LinkEx => SetFilePlan::Link {
                mutation: HardLinkMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    HardLinkInformationFormat::Flags,
                )?,
            },
            SetFileInformationClass::Rename => SetFilePlan::Rename {
                mutation: RenameMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    RenameInformationFormat::ReplaceIfExistsByte,
                )?,
                file_object: opened_file.file_object(),
            },
            SetFileInformationClass::RenameEx => SetFilePlan::Rename {
                mutation: RenameMutation::decode(
                    active,
                    stack,
                    &opened_file,
                    RenameInformationFormat::Flags,
                )?,
                file_object: opened_file.file_object(),
            },
        };
        Ok::<_, DriverError>(plan)
    })?;
    match plan {
        SetFilePlan::Complete => {
            return Ok(SetFileResolution::Complete(IrpCompletion::EMPTY));
        }
        SetFilePlan::Basic { info, node } => set_basic_information(info, node, mutation)?,
        SetFilePlan::EndOfFile { file, size } => set_regular_file_size(mutation, file, size)?,
        SetFilePlan::Allocation { file, size } => {
            let current = regular_file_size(mutation, file)?;
            if size < current {
                set_regular_file_size(mutation, file, size)?;
            }
        }
        SetFilePlan::Disposition {
            node,
            pending,
            publication,
            readonly,
        } => {
            validate_pending_deletion(mutation, node, pending.target_ref(), readonly)?;
            match publication {
                DeletePendingPublication::Publish { fcb } => {
                    operations.set_file_delete_pending(fcb, pending);
                }
                DeletePendingPublication::AlreadyPublishedByCreate => drop(pending),
            }
            return Ok(SetFileResolution::Complete(IrpCompletion::EMPTY));
        }
        SetFilePlan::Link { mutation: request } => {
            let changes = set_hard_link_information(request, operations, mutation)?;
            let changes = memory::boxed_try_with(move || Ok(changes))?;
            return Ok(SetFileResolution::Mutation(SetFilePublication::HardLink(
                changes,
            )));
        }
        SetFilePlan::Rename {
            mutation: rename,
            file_object,
        } => {
            let publication = set_rename_information(rename, operations, mutation)?;
            return Ok(SetFileResolution::Mutation(match publication {
                PreparedRename::Unchanged => SetFilePublication::None,
                PreparedRename::Changed {
                    location,
                    notifications,
                } => {
                    let location =
                        request_location_publication(&mut request, file_object, location)?;
                    SetFilePublication::Rename {
                        location,
                        notifications,
                    }
                }
            }));
        }
    }
    Ok(SetFileResolution::Mutation(SetFilePublication::None))
}

/// Binds a preallocated rename location to the exact CCB retained by the pending request.
/// # Errors
///
/// Returns an error when the active IRP stack or opened FILE_OBJECT identity is invalid.
fn request_location_publication(
    request: &mut PendingIrpLease<'_>,
    expected: crate::state::KernelFileObject,
    location: OpenedLocation,
) -> DriverResult<PreparedOpenedLocationPublication> {
    request.with_active(|active| {
        let current = active.current_stack()?;
        let file_object = current.file_object()?;
        let _stack = current.set_file()?;
        let opened = OpenedObject::decode(file_object)?;
        if opened.file_object() != expected {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(opened.prepare_location_publication(location))
    })
}

/// Applies FILE_POSITION_INFORMATION to the synchronous FILE_OBJECT position.
/// # Errors
///
/// Returns an error when the input is truncated, negative, asynchronous, or misaligned for a
/// no-intermediate-buffering handle.
fn set_position_information(
    active: &ActiveIrp<'_>,
    stack: SetFileStack,
    opened_file: &mut OpenedObject<'_>,
) -> DriverResult<()> {
    let current_byte_offset = read_position_input(active, stack.length())?;
    let position = file_offset_from_large_integer(current_byte_offset)?;
    opened_file
        .data_transfer_mode()
        .validate_position(position.bytes())?;
    opened_file.set_current_file_position(position)
}

/// Applies FILE_BASIC_INFORMATION timestamps and overlay attributes.
/// # Errors
///
/// Returns an error when the input structure is truncated, timestamps or attributes are invalid, or
/// the resulting ext4 metadata transaction fails.
fn set_basic_information(
    info: wdk_sys::FILE_BASIC_INFORMATION,
    node_id: NodeId,
    transaction: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<()> {
    let metadata = metadata_from_node(transaction, node_id)?;
    let times = set_basic_times(metadata.times, info)?;
    let attributes = set_basic_attributes(metadata, info.FileAttributes)?;
    if times == metadata.times && attributes.is_empty() {
        return Ok(());
    }

    let node = transaction.node(node_id)?;
    if times != metadata.times {
        transaction.set_times(node, times)?;
    }
    if let Some(security) = attributes.security() {
        transaction.set_posix_security(node, security)?;
    }
    if let Some(overlay) = attributes.overlay() {
        transaction.set_windows_overlay(node, overlay)?;
    }
    Ok(())
}

/// Raw Windows disposition layout selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispositionInputFormat {
    /// `FILE_DISPOSITION_INFORMATION`.
    Legacy,
    /// `FILE_DISPOSITION_INFORMATION_EX`.
    Extended,
}

/// Fully decoded effect and target state for one disposition request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileDispositionRequest {
    /// Requested deletion-state transition.
    action: FileDispositionAction,
    /// State selected by ordinary disposition or create-time delete-on-close.
    target: FileDispositionTarget,
}

impl FileDispositionRequest {
    /// Creates a request that retains the namespace link.
    const fn keep(target: FileDispositionTarget) -> Self {
        Self {
            action: FileDispositionAction::Keep,
            target,
        }
    }

    /// Creates a request that validates deletion under one read-only policy.
    const fn delete(target: FileDispositionTarget, readonly: DeleteReadonlyRequest) -> Self {
        Self {
            action: FileDispositionAction::Delete(readonly),
            target,
        }
    }
}

/// Deletion-state transition requested by a disposition input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileDispositionAction {
    /// Retain the link, cancelling only an ordinary mutable disposition state.
    Keep,
    /// Validate deletion, then publish or reaffirm the selected target state.
    Delete(DeleteReadonlyRequest),
}

/// Deletion state selected by extended `FILE_DISPOSITION_ON_CLOSE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileDispositionTarget {
    /// Operate on the ordinary cancellable disposition state.
    Mutable,
    /// Reaffirm the mandatory state created by `FILE_DELETE_ON_CLOSE`.
    CreateDeleteOnClose,
}

impl FileDispositionTarget {
    /// Validates that ON_CLOSE refers to a handle opened with `FILE_DELETE_ON_CLOSE`.
    /// # Errors
    ///
    /// Returns not-supported when an ON_CLOSE request targets an ordinary retained handle.
    const fn validate(self, create_deletion: CreateDeletion) -> DriverResult<()> {
        match (self, create_deletion) {
            (Self::CreateDeleteOnClose, CreateDeletion::Retain) => Err(DriverError::NotSupported),
            (Self::Mutable, CreateDeletion::Retain | CreateDeletion::DeleteOnClose)
            | (Self::CreateDeleteOnClose, CreateDeletion::DeleteOnClose) => Ok(()),
        }
    }
}

/// Post-validation mutation selected without optional FCB authority.
enum DeletePendingPublication {
    /// Publish a new cancellable disposition state to this exact FCB.
    Publish {
        /// Stable FCB whose shared deletion state is mutated.
        fcb: NonNull<FileControlBlock>,
    },
    /// Create already published the mandatory delete-on-close state.
    AlreadyPublishedByCreate,
}

/// Raw read-only behavior selected before binding handle authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeleteReadonlyRequest {
    /// A Windows read-only attribute prevents deletion.
    Enforce,
    /// The request asks to bypass read-only protection when its handle has authority.
    Ignore,
}

impl DeleteReadonlyRequest {
    /// Binds requested behavior to retained `FILE_WRITE_ATTRIBUTES` authority.
    const fn bind(self, access: FileAttributesWriteAccess) -> DeleteReadonlyPolicy {
        match self {
            Self::Enforce => DeleteReadonlyPolicy::Enforce,
            Self::Ignore => DeleteReadonlyPolicy::Ignore(access),
        }
    }
}

/// Read-only attribute policy with all required handle authority attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteReadonlyPolicy {
    /// A Windows read-only attribute prevents deletion.
    Enforce,
    /// Bypass read-only protection only when `FILE_WRITE_ATTRIBUTES` was retained.
    Ignore(FileAttributesWriteAccess),
}

impl DeleteReadonlyPolicy {
    /// Validates the target attributes under the bound override authority.
    /// # Errors
    ///
    /// Returns cannot-delete when a read-only target is protected or the requested override lacks
    /// `FILE_WRITE_ATTRIBUTES`.
    const fn validate_attributes(self, attributes: wdk_sys::ULONG) -> DriverResult<()> {
        if attributes & wdk_sys::FILE_ATTRIBUTE_READONLY == 0 {
            return Ok(());
        }
        match self {
            Self::Enforce | Self::Ignore(FileAttributesWriteAccess::Denied) => {
                Err(DriverError::CannotDelete)
            }
            Self::Ignore(FileAttributesWriteAccess::Granted) => Ok(()),
        }
    }
}

/// Builds a disposition plan from one fully decoded handle and buffered input.
/// # Errors
///
/// Returns an error when the input is malformed, the handle lacks `DELETE`, unsupported extended
/// semantics are requested, or the handle has no deletable directory-entry identity.
fn disposition_plan(
    active: &ActiveIrp<'_>,
    stack: SetFileStack,
    opened: &OpenedObject<'_>,
    format: DispositionInputFormat,
) -> DriverResult<SetFilePlan> {
    opened.require_delete_access()?;
    let request = match format {
        DispositionInputFormat::Legacy => {
            if !read_legacy_disposition_input(active, stack.length())? {
                FileDispositionRequest::keep(FileDispositionTarget::Mutable)
            } else {
                FileDispositionRequest::delete(
                    FileDispositionTarget::Mutable,
                    DeleteReadonlyRequest::Enforce,
                )
            }
        }
        DispositionInputFormat::Extended => {
            decode_extended_disposition(read_extended_disposition_input(active, stack.length())?)?
        }
    };
    request.target.validate(opened.create_deletion())?;
    match request.action {
        FileDispositionAction::Keep => {
            if request.target == FileDispositionTarget::Mutable
                && opened.create_deletion() == CreateDeletion::Retain
            {
                opened.clear_delete_pending();
            }
            Ok(SetFilePlan::Complete)
        }
        FileDispositionAction::Delete(readonly) => {
            let readonly = readonly.bind(opened.file_attributes_write_access());
            let (pending, publication) = match request.target {
                FileDispositionTarget::Mutable => (
                    opened.prepare_pending_deletion()?,
                    DeletePendingPublication::Publish {
                        fcb: opened.file_control_block_address(),
                    },
                ),
                FileDispositionTarget::CreateDeleteOnClose => (
                    PendingFileDeletion::try_from_delete_on_close(opened.location())?,
                    DeletePendingPublication::AlreadyPublishedByCreate,
                ),
            };
            Ok(SetFilePlan::Disposition {
                node: opened.node(),
                pending,
                publication,
                readonly,
            })
        }
    }
}

/// Decodes the supported non-POSIX subset of `FILE_DISPOSITION_INFORMATION_EX`.
/// # Errors
///
/// Returns not-supported when a delete requests POSIX or image-section semantics, when ON_CLOSE
/// requests POSIX mode, or when unknown flags are present.
fn decode_extended_disposition(flags: wdk_sys::ULONG) -> DriverResult<FileDispositionRequest> {
    const KNOWN_FLAGS: wdk_sys::ULONG = wdk_sys::FILE_DISPOSITION_DELETE
        | wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS
        | wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK
        | wdk_sys::FILE_DISPOSITION_ON_CLOSE
        | wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(DriverError::NotSupported);
    }
    let delete = flags & wdk_sys::FILE_DISPOSITION_DELETE != 0;
    let posix = flags & wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS != 0;
    let force_image_check = flags & wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK != 0;
    let on_close = flags & wdk_sys::FILE_DISPOSITION_ON_CLOSE != 0;
    let ignore_readonly = flags & wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE != 0;
    if (delete && (posix || force_image_check)) || (on_close && posix) {
        return Err(DriverError::NotSupported);
    }
    let target = if on_close {
        FileDispositionTarget::CreateDeleteOnClose
    } else {
        FileDispositionTarget::Mutable
    };
    if !delete {
        return Ok(FileDispositionRequest::keep(target));
    }
    let readonly = if ignore_readonly {
        DeleteReadonlyRequest::Ignore
    } else {
        DeleteReadonlyRequest::Enforce
    };
    Ok(FileDispositionRequest::delete(target, readonly))
}

/// Validates the exact parent/name/inode identity before publishing delete-pending.
/// # Errors
///
/// Returns cannot-delete when the link no longer identifies the opened inode or has the read-only
/// attribute, directory-not-empty for a non-empty directory, or the underlying read error.
pub(crate) fn validate_pending_deletion(
    read: &mut impl CommittedReadPass,
    node: NodeId,
    target: &FileDeleteTarget,
    readonly: DeleteReadonlyPolicy,
) -> DriverResult<()> {
    let parent = read.load_directory(target.parent())?;
    match read.lookup_child(&parent, target.name())? {
        ChildLookup::Found(child) if *child.node() == node => {}
        ChildLookup::Found(_) | ChildLookup::NotFound => return Err(DriverError::CannotDelete),
    }
    let metadata = metadata_from_node(read, node)?;
    readonly.validate_attributes(file_attributes(metadata))?;
    if let NodeId::Directory(directory_id) = node {
        let directory = read.load_directory(directory_id)?;
        let mut cursor = DirectoryCursor::start();
        loop {
            let batch = read.scan_directory(&directory, &cursor, DirectoryScanLimit::MAX)?;
            if batch
                .entries()
                .iter()
                .any(|entry| !matches!(entry.entry().name().bytes(), b"." | b".."))
            {
                return Err(DriverError::from(ext4_core::Error::DirectoryNotEmpty));
            }
            if batch.is_exhausted() {
                break;
            }
            cursor = *batch.continuation();
        }
    }
    Ok(())
}

/// Owned hard-link mutation decoded completely before the first suspension.
#[derive(Debug)]
struct HardLinkMutation {
    /// Existing inode that receives the additional name.
    source: HardLinkNodeId,
    /// Destination path with its explicit resolution base.
    target: NamespaceTargetPath,
    /// Existing-target behavior decoded from the link information class.
    target_collision: HardLinkTargetCollision,
}

impl HardLinkMutation {
    /// Copies every caller and handle-dependent hard-link field into owned domain values.
    /// # Errors
    ///
    /// Returns an error when the source is a directory or deleted link, the handle has no parent
    /// identity, or the input path/flags are invalid.
    fn decode(
        active: &ActiveIrp<'_>,
        stack: SetFileStack,
        opened_file: &OpenedObject<'_>,
        format: HardLinkInformationFormat,
    ) -> DriverResult<Self> {
        if opened_file.delete_pending() {
            return Err(DriverError::AccessDenied);
        }
        let source = HardLinkNodeId::try_from(opened_file.node())
            .map_err(|_| DriverError::FileIsDirectory)?;
        let source_parent = match opened_file.location() {
            OpenedLocation::DirectoryEntry { parent, .. } => *parent,
            OpenedLocation::Root => return Err(DriverError::FileIsDirectory),
            OpenedLocation::FileReference => return Err(DriverError::NotSupported),
        };
        let input = active.buffered_input(stack.length())?;
        let target_collision = format.target_collision(input.as_slice())?;
        let target = NamespaceTargetPath::decode(input.as_slice(), source_parent)?;
        Ok(Self {
            source,
            target,
            target_collision,
        })
    }
}

/// Prepared hard-link destination with the exact ext4 name selected for replacement.
#[derive(Debug)]
enum PreparedHardLinkDestination {
    /// No Windows-visible target exists.
    Vacant,
    /// The caller authorized replacement of this exact existing entry.
    Replace {
        /// Existing case-preserving ext4 name.
        existing_name: Ext4Name,
    },
}

/// Source link-count transition implied by the prepared destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardLinkCountEffect {
    /// Replacing another name for the same inode preserves the count.
    Preserve,
    /// Creating a new name or replacing a different inode increments the count.
    Increase,
}

impl HardLinkCountEffect {
    /// Enforces the Windows hard-link count boundary only when the count will increase.
    /// # Errors
    ///
    /// Returns `TooManyLinks` once the source already has 1024 links.
    fn validate(self, links: Ext4LinkCount) -> DriverResult<()> {
        const WINDOWS_HARD_LINK_LIMIT: u16 = 1024;
        match self {
            Self::Preserve => Ok(()),
            Self::Increase if links.get() < WINDOWS_HARD_LINK_LIMIT => Ok(()),
            Self::Increase => Err(DriverError::from(ext4_core::Error::TooManyLinks)),
        }
    }
}

/// Ordered post-commit directory notifications for one hard-link mutation.
#[derive(Debug)]
pub(crate) struct HardLinkDirectoryChanges {
    /// First and always-present notification.
    first: DirectoryChange,
    /// Second notification required only for a case-preserving spelling change.
    second: Option<Box<DirectoryChange>>,
}

impl HardLinkDirectoryChanges {
    /// Reports the committed notification sequence.
    fn report(self, operations: &MountedVolumeAccess<'_>) {
        operations.report_directory_change(self.first);
        if let Some(second) = self.second {
            operations.report_directory_change(*second);
        }
    }
}

/// Applies one owned FILE_LINK_INFORMATION mutation to the ext4 namespace.
/// # Errors
///
/// Returns an error when target resolution, replacement policy, link limits, metadata staging, or
/// the journal transaction fails.
fn set_hard_link_information(
    request: HardLinkMutation,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<HardLinkDirectoryChanges> {
    let HardLinkMutation {
        source,
        target,
        target_collision,
    } = request;
    let source_node = NodeId::from(source);
    let (target_parent, target_name) = resolve_namespace_target(mutation, &target)?;
    operations.ensure_node_openable(NodeId::Directory(target_parent))?;
    let source_metadata = metadata_from_node(mutation, source_node)?;
    let (destination, count_effect, changes) = prepare_hard_link_destination(
        operations,
        mutation,
        source_node,
        target_parent,
        &target_name,
        target.target_name(),
        target_collision,
    )?;
    count_effect.validate(source_metadata.links_count)?;
    let archive_overlay = hard_link_archive_overlay(source_metadata.overlay_attributes)?;

    let source = mutation.hard_link_source(source)?;
    let target_parent = mutation.directory(target_parent)?;
    if let Some(overlay) = archive_overlay {
        let node = mutation.node(source_node)?;
        mutation.set_windows_overlay(node, overlay)?;
    }
    match &destination {
        PreparedHardLinkDestination::Vacant => {
            mutation.create_hard_link(
                source,
                target_parent,
                &target_name,
                HardLinkDestination::Vacant,
            )?;
        }
        PreparedHardLinkDestination::Replace { existing_name } => {
            mutation.create_hard_link(
                source,
                target_parent,
                &target_name,
                HardLinkDestination::Replace { existing_name },
            )?;
        }
    }
    Ok(changes)
}

/// Resolves collision policy into one exact hard-link destination and notification plan.
/// # Errors
///
/// Returns an error when a rejected collision exists, the target is a directory, read-only,
/// delete-pending, or still has an active handle.
fn prepare_hard_link_destination(
    operations: &mut MountedVolumeAccess<'_>,
    read: &mut impl CommittedReadPass,
    source_node: NodeId,
    target_parent: DirectoryNodeId,
    target_name: &Ext4Name,
    target_windows_name: &WindowsName,
    target_collision: HardLinkTargetCollision,
) -> DriverResult<(
    PreparedHardLinkDestination,
    HardLinkCountEffect,
    HardLinkDirectoryChanges,
)> {
    let parent = read.load_directory(target_parent)?;
    let target = read.lookup_windows_child(
        &parent,
        target_windows_name,
        ext4_core::WindowsNameMatch::CaseInsensitive,
    )?;
    let ChildLookup::Found(target) = target else {
        return Ok((
            PreparedHardLinkDestination::Vacant,
            HardLinkCountEffect::Increase,
            HardLinkDirectoryChanges {
                first: DirectoryChange::new(
                    target_parent,
                    target_name,
                    source_node,
                    DirectoryChangeAction::Added,
                )?,
                second: None,
            },
        ));
    };
    if target_collision == HardLinkTargetCollision::Reject {
        return Err(DriverError::ObjectNameCollision);
    }
    let target_node = *target.node();
    if matches!(target_node, NodeId::Directory(_)) {
        return Err(DriverError::CannotDelete);
    }
    operations.ensure_node_openable(target_node)?;
    if target_node != source_node {
        operations.ensure_node_replaceable(target_node)?;
    }
    let target_metadata = metadata_from_node(read, target_node)?;
    if file_attributes(target_metadata) & wdk_sys::FILE_ATTRIBUTE_READONLY != 0 {
        return Err(DriverError::CannotDelete);
    }

    let existing_name = target.name().try_to_owned_name()?;
    let changes = if target.name() == target_name {
        HardLinkDirectoryChanges {
            first: DirectoryChange::hard_link_replaced(target_parent, target_name)?,
            second: None,
        }
    } else {
        HardLinkDirectoryChanges {
            first: DirectoryChange::new(
                target_parent,
                target.name(),
                target_node,
                DirectoryChangeAction::Removed,
            )?,
            second: Some(
                Box::try_new(DirectoryChange::new(
                    target_parent,
                    target_name,
                    source_node,
                    DirectoryChangeAction::Added,
                )?)
                .map_err(|_| DriverError::InsufficientResources)?,
            ),
        }
    };
    let count_effect = if target_node == source_node {
        HardLinkCountEffect::Preserve
    } else {
        HardLinkCountEffect::Increase
    };
    Ok((
        PreparedHardLinkDestination::Replace { existing_name },
        count_effect,
        changes,
    ))
}

/// Returns the archive overlay update required by successful hard-link creation.
/// # Errors
///
/// Returns an error when the combined overlay cannot inhabit the ext4 Windows-attribute domain.
fn hard_link_archive_overlay(
    current_attributes: wdk_sys::ULONG,
) -> DriverResult<Option<WindowsOverlay>> {
    if current_attributes & Ext4WindowsAttributes::ARCHIVE != 0 {
        return Ok(None);
    }
    Ok(Some(WindowsOverlay::new(Ext4WindowsAttributes::new(
        current_attributes | Ext4WindowsAttributes::ARCHIVE,
    )?)))
}

/// Owned rename mutation decoded completely before the first suspension.
#[derive(Debug)]
struct RenameMutation {
    /// Current parent identity.
    source_parent: DirectoryNodeId,
    /// Current exact ext4 name.
    source_name: Ext4Name,
    /// Node being moved.
    source_node: NodeId,
    /// Destination path with its explicit resolution base.
    target: NamespaceTargetPath,
    /// Existing-target behavior decoded from the rename information class.
    target_collision: RenameTargetCollision,
}

impl RenameMutation {
    /// Copies every caller and handle-dependent rename field into owned domain values.
    /// # Errors
    ///
    /// Returns an error when the input layout, source location, or destination path is invalid.
    fn decode(
        active: &ActiveIrp<'_>,
        stack: SetFileStack,
        opened_file: &OpenedObject<'_>,
        format: RenameInformationFormat,
    ) -> DriverResult<Self> {
        if opened_file.delete_pending() {
            return Err(DriverError::DeletePending);
        }
        let (source_parent, source_name) = match opened_file.location() {
            OpenedLocation::DirectoryEntry { parent, name } => (*parent, name.try_to_owned_name()?),
            OpenedLocation::Root => {
                return Err(DriverError::from(ext4_core::Error::CannotRemoveRoot));
            }
            OpenedLocation::FileReference => return Err(DriverError::NotSupported),
        };
        let input = active.buffered_input(stack.length())?;
        let target_collision = format.target_collision(input.as_slice())?;
        let target = NamespaceTargetPath::decode(input.as_slice(), source_parent)?;
        Ok(Self {
            source_parent,
            source_name,
            source_node: opened_file.node(),
            target,
            target_collision,
        })
    }
}

/// Result of a committed rename with mutually exclusive no-op and changed states.
enum PreparedRename {
    /// The transaction preserved the existing handle location and emitted no notifications.
    Unchanged,
    /// The committed namespace move requires one handle-location update and exact notifications.
    Changed {
        /// New CCB location.
        location: OpenedLocation,
        /// Namespace notifications derived before commit.
        notifications: Box<RenameDirectoryNameChanges>,
    },
}

/// Applies one owned FILE_RENAME_INFORMATION mutation to the ext4 namespace.
/// # Errors
///
/// Returns an error when target resolution, notification preparation, or the rename transaction
/// fails.
fn set_rename_information(
    request: RenameMutation,
    operations: &mut MountedVolumeAccess<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<PreparedRename> {
    let RenameMutation {
        source_parent,
        source_name,
        source_node,
        target,
        target_collision,
    } = request;
    let (target_parent, target_name) = resolve_namespace_target(mutation, &target)?;
    operations.ensure_node_openable(NodeId::Directory(source_parent))?;
    operations.ensure_node_openable(NodeId::Directory(target_parent))?;
    let notifications = RenameDirectoryNameChanges::prepare(
        operations,
        mutation,
        RenameNotificationRequest {
            source_parent,
            source_name: &source_name,
            source_node,
            target_parent,
            target_name: &target_name,
            target_collision,
        },
    )?;
    let notifications = notifications
        .map(Box::try_new)
        .transpose()
        .map_err(|_| DriverError::InsufficientResources)?;
    let source_parent = mutation.directory(source_parent)?;
    let target_parent = mutation.directory(target_parent)?;
    mutation.rename_child(
        source_parent,
        &source_name,
        target_parent,
        &target_name,
        target_collision,
    )?;
    match notifications {
        Some(notifications) => Ok(PreparedRename::Changed {
            location: OpenedLocation::DirectoryEntry {
                parent: target_parent.id(),
                name: target_name,
            },
            notifications,
        }),
        None => Ok(PreparedRename::Unchanged),
    }
}

/// Committed directory-name changes caused by one non-no-op rename operation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RenameDirectoryNameChanges {
    /// Existing target entry removed by a replace-capable rename.
    replaced_target: Option<DirectoryChange>,
    /// Source entry under its former name.
    old_source_name: DirectoryChange,
    /// Source entry under its new name.
    new_source_name: DirectoryChange,
}

/// Fully resolved namespace identities used to prepare rename notifications.
#[derive(Debug)]
struct RenameNotificationRequest<'name> {
    /// Source directory before the rename.
    source_parent: DirectoryNodeId,
    /// Source ext4 name before the rename.
    source_name: &'name Ext4Name,
    /// Typed node being renamed.
    source_node: NodeId,
    /// Destination directory after the rename.
    target_parent: DirectoryNodeId,
    /// Destination ext4 name after the rename.
    target_name: &'name Ext4Name,
    /// Validated collision policy.
    target_collision: RenameTargetCollision,
}

impl RenameDirectoryNameChanges {
    /// Prepares the exact name-change events that a successful rename will publish.
    /// # Errors
    ///
    /// Returns an error when a replace-capable target cannot be read or a visible child name
    /// cannot be represented in the Windows notification namespace.
    fn prepare(
        operations: &mut MountedVolumeAccess<'_>,
        read: &mut impl CommittedReadPass,
        request: RenameNotificationRequest<'_>,
    ) -> DriverResult<Option<Self>> {
        let RenameNotificationRequest {
            source_parent,
            source_name,
            source_node,
            target_parent,
            target_name,
            target_collision,
        } = request;
        if source_parent == target_parent && source_name == target_name {
            return Ok(None);
        }

        let replaced_target = match target_collision {
            RenameTargetCollision::Reject => None,
            RenameTargetCollision::Replace => {
                let parent = read.load_directory(target_parent)?;
                match read.lookup_windows_child(
                    &parent,
                    &WindowsName::from_ext4(target_name)?,
                    ext4_core::WindowsNameMatch::CaseInsensitive,
                )? {
                    ChildLookup::Found(child) if *child.node() == source_node => return Ok(None),
                    ChildLookup::Found(child) => {
                        operations.ensure_node_replaceable(*child.node())?;
                        Some(DirectoryChange::new(
                            target_parent,
                            child.name(),
                            *child.node(),
                            DirectoryChangeAction::Removed,
                        )?)
                    }
                    ChildLookup::NotFound => None,
                }
            }
        };

        Ok(Some(Self {
            replaced_target,
            old_source_name: DirectoryChange::new(
                source_parent,
                source_name,
                source_node,
                DirectoryChangeAction::RenamedOldName,
            )?,
            new_source_name: DirectoryChange::new(
                target_parent,
                target_name,
                source_node,
                DirectoryChangeAction::RenamedNewName,
            )?,
        }))
    }

    /// Reports every name transition after the corresponding ext4 transaction commits.
    fn report(self, operations: &MountedVolumeAccess<'_>) {
        if let Some(replaced_target) = self.replaced_target {
            operations.report_directory_change(replaced_target);
        }
        operations.report_directory_change(self.old_source_name);
        operations.report_directory_change(self.new_source_name);
    }
}

/// Sets a regular file size by extending sparse or truncating allocated ranges.
/// # Errors
///
/// Returns an error when the current file size cannot be loaded or the ext4 resize transaction
/// fails.
fn set_regular_file_size(
    transaction: &mut DriverMutationPass<'_, '_, '_>,
    file_id: FileNodeId,
    new_size: FileSize,
) -> DriverResult<()> {
    let current = regular_file_size(transaction, file_id)?;
    if new_size == current {
        return Ok(());
    }

    let file = transaction.file(file_id)?;
    if new_size > current {
        transaction.extend_file(file, new_size)?;
    } else {
        transaction.truncate_file(file, new_size)?;
    }
    Ok(())
}

/// Packs directory entries into the caller's query-directory buffer.
/// # Errors
///
/// Returns an error when the directory query stack, pattern, output buffer, opened directory, or
/// emitted directory record layout is invalid.
pub(crate) fn query_directory(
    mut request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    let (prepared_stack, pattern) = {
        let prepared = request.prepared_query_directory()?;
        (
            prepared.stack(),
            DirectoryPattern::from_prepared(prepared.pattern())?,
        )
    };
    let (class, pattern, length, entry_emission, directory_id, mut cursor) = {
        request.with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            let mut opened_file = OpenedDirectory::decode(file_object)?;
            let class = prepared_stack.information_class();
            let length = prepared_stack.length();
            let entry_emission = prepared_stack.entry_emission();
            let directory_id = opened_file.id();
            let mut cursor = *opened_file.cursor_mut();
            initialize_directory_cursor(&mut cursor, prepared_stack.cursor_position());
            Ok::<_, DriverError>((class, pattern, length, entry_emission, directory_id, cursor))
        })?
    };
    let (cursor, packed, result) = {
        let directory = read.load_directory(directory_id)?;
        let mut packed = DriverVec::try_repeated_copy(0_u8, length.as_usize())?;
        let result = emit_directory_entries(
            read,
            &directory,
            &mut cursor,
            entry_emission,
            class,
            &pattern,
            packed.as_mut_slice(),
        );
        (cursor, packed, result)
    };

    let publish_cursor = matches!(
        result,
        Ok(_)
            | Err(DriverError::BufferOverflow | DriverError::NoMoreFiles | DriverError::NoSuchFile)
    );
    let information = result.unwrap_or(0);
    request.with_active(|active| {
        if result.is_ok() {
            let source = packed
                .as_slice()
                .get(..information)
                .ok_or(DriverError::InternalInvariantViolation)?;
            active.requestor_output(length)?.copy_from(0, source)?;
        }
        if publish_cursor {
            let file_object = active.current_stack()?.file_object()?;
            let mut opened_file = OpenedDirectory::decode(file_object)?;
            *opened_file.cursor_mut() = cursor;
        }
        Ok::<_, DriverError>(())
    })?;
    result?;
    IrpCompletion::from_usize(information)
}

impl DirectoryInformationClass {
    /// Returns the byte offset where the UTF-16 file name starts.
    const fn name_offset(self) -> usize {
        match self {
            Self::Directory => DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Full => FULL_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Both => BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Names => NAMES_INFORMATION_NAME_OFFSET,
            Self::IdFull => ID_FULL_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::IdBoth => ID_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::IdExtd => ID_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::IdExtdBoth => ID_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Id64Extd => ID_64_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET,
            Self::Id64ExtdBoth => ID_64_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
        }
    }

    /// Returns the byte offset of the EA-size field when the wire class carries one.
    const fn ea_size_offset(self) -> Option<usize> {
        match self {
            Self::Directory | Self::Names => None,
            Self::Full
            | Self::Both
            | Self::IdFull
            | Self::IdBoth
            | Self::IdExtd
            | Self::IdExtdBoth
            | Self::Id64Extd
            | Self::Id64ExtdBoth => Some(DIRECTORY_EA_SIZE_OFFSET),
        }
    }

    /// Returns the byte offset of the short-name-length field when the class carries one.
    const fn short_name_length_offset(self) -> Option<usize> {
        match self {
            Self::Both => Some(BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            Self::IdBoth => Some(ID_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            Self::IdExtdBoth => Some(ID_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            Self::Id64ExtdBoth => Some(ID_64_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            Self::Directory
            | Self::Full
            | Self::Names
            | Self::IdFull
            | Self::IdExtd
            | Self::Id64Extd => None,
        }
    }

    /// Returns the byte offset of the reparse-tag field when the class carries one.
    const fn reparse_tag_offset(self) -> Option<usize> {
        match self {
            Self::IdExtd | Self::IdExtdBoth | Self::Id64Extd | Self::Id64ExtdBoth => {
                Some(DIRECTORY_REPARSE_TAG_OFFSET)
            }
            Self::Directory
            | Self::Full
            | Self::Both
            | Self::Names
            | Self::IdFull
            | Self::IdBoth => None,
        }
    }

    /// Returns the file-identity field carried by the wire class.
    const fn file_id_layout(self) -> Option<DirectoryFileIdLayout> {
        match self {
            Self::IdFull => Some(DirectoryFileIdLayout::U64(ID_FULL_DIRECTORY_FILE_ID_OFFSET)),
            Self::IdBoth => Some(DirectoryFileIdLayout::U64(ID_BOTH_DIRECTORY_FILE_ID_OFFSET)),
            Self::IdExtd => Some(DirectoryFileIdLayout::U128(
                ID_EXTD_DIRECTORY_FILE_ID_OFFSET,
            )),
            Self::IdExtdBoth => Some(DirectoryFileIdLayout::U128(
                ID_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET,
            )),
            Self::Id64Extd => Some(DirectoryFileIdLayout::U64(
                ID_64_EXTD_DIRECTORY_FILE_ID_OFFSET,
            )),
            Self::Id64ExtdBoth => Some(DirectoryFileIdLayout::U64(
                ID_64_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET,
            )),
            Self::Directory | Self::Full | Self::Both | Self::Names => None,
        }
    }
}

/// File-identity field carried by one directory-record wire class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryFileIdLayout {
    /// Eight-byte `LARGE_INTEGER` identity.
    U64(usize),
    /// Sixteen-byte `FILE_ID_128` identity whose high half remains zero.
    U128(usize),
}

/// Caller-supplied directory filename pattern.
#[derive(Debug, Eq, PartialEq)]
enum DirectoryPattern {
    /// Enumerate every Windows-representable ext4 entry.
    All,
    /// Return the entry with this exact Windows name.
    Exact(WindowsName),
    /// Return entries matched by a caller-supplied wildcard expression.
    Wildcard(DirectoryWildcardPattern),
}

impl DirectoryPattern {
    /// Decodes the captured QueryDirectory filename pattern.
    /// # Errors
    ///
    /// Returns an error when the pattern UNICODE_STRING is malformed, contains unsupported
    /// wildcards, or is not a valid Windows name.
    fn from_prepared(pattern: &PreparedDirectoryPattern) -> DriverResult<Self> {
        let PreparedDirectoryPattern::Name(units) = pattern else {
            return Ok(Self::All);
        };
        let units = units.as_slice();
        if is_all_directory_pattern(units) {
            return Ok(Self::All);
        }
        if units
            .iter()
            .any(|unit| matches!(*unit, UTF16_ASTERISK | UTF16_QUESTION_MARK))
        {
            return DirectoryWildcardPattern::from_utf16(units).map(Self::Wildcard);
        }
        WindowsName::from_utf16(units)
            .map(Self::Exact)
            .map_err(DriverError::from)
    }

    /// Returns true when the projected Windows name matches this pattern.
    fn matches(&self, name: &WindowsName) -> bool {
        match self {
            Self::All => true,
            Self::Exact(requested) => name.equals(requested),
            Self::Wildcard(pattern) => pattern.matches(name),
        }
    }

    /// Returns the no-entry status for this pattern.
    const fn exhausted_error(&self) -> DriverError {
        match self {
            Self::All => DriverError::NoMoreFiles,
            Self::Exact(_) | Self::Wildcard(_) => DriverError::NoSuchFile,
        }
    }
}

/// Caller-supplied wildcard pattern for Windows-visible long names.
#[derive(Debug, Eq, PartialEq)]
struct DirectoryWildcardPattern {
    /// Parsed pattern tokens.
    tokens: DriverVec<DirectoryWildcardToken>,
}

impl DirectoryWildcardPattern {
    /// Decodes a wildcard pattern for directory enumeration.
    /// # Errors
    ///
    /// Returns an error when the pattern contains a non-wildcard character outside the Windows name
    /// component domain or malformed UTF-16.
    fn from_utf16(units: &[u16]) -> DriverResult<Self> {
        validate_directory_pattern_units(units)?;
        let mut tokens = DriverVec::new();
        for unit in units {
            let token = match *unit {
                UTF16_ASTERISK => DirectoryWildcardToken::AnySequence,
                UTF16_QUESTION_MARK => DirectoryWildcardToken::AnyOne,
                unit => DirectoryWildcardToken::Literal(unit),
            };
            tokens
                .try_push_owned(token)
                .map_err(|error| error.into_parts().0)?;
        }
        Ok(Self { tokens })
    }

    /// Returns true when this pattern matches a Windows-visible long name.
    fn matches(&self, name: &WindowsName) -> bool {
        wildcard_tokens_match(self.tokens.as_slice(), name.utf16())
    }
}

/// One token in a directory wildcard expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryWildcardToken {
    /// Exact UTF-16 code unit match.
    Literal(u16),
    /// Match exactly one UTF-16 code unit.
    AnyOne,
    /// Match zero or more UTF-16 code units.
    AnySequence,
}

/// Validates wildcard pattern units while keeping wildcard syntax out of `WindowsName`.
/// # Errors
///
/// Returns an error when a non-wildcard unit is not valid inside a Windows component or the pattern
/// is malformed UTF-16.
fn validate_directory_pattern_units(units: &[u16]) -> DriverResult<()> {
    if units.iter().any(|unit| {
        matches!(
            *unit,
            0x0000 | 0x0022 | 0x002F | 0x003A | 0x003C | 0x003E | 0x005C | 0x007C
        )
    }) {
        return Err(DriverError::from(ext4_core::Error::InvalidName));
    }
    if core::char::decode_utf16(units.iter().copied()).any(|item| item.is_err()) {
        return Err(DriverError::from(ext4_core::Error::InvalidName));
    }
    Ok(())
}

/// Matches `*` and `?` wildcard tokens against UTF-16 name units.
fn wildcard_tokens_match(pattern: &[DirectoryWildcardToken], name: &[u16]) -> bool {
    let mut pattern_index = 0_usize;
    let mut name_index = 0_usize;
    let mut sequence_restart = None;

    while name_index < name.len() {
        if let Some(token) = pattern.get(pattern_index) {
            match token {
                DirectoryWildcardToken::Literal(unit)
                    if name.get(name_index).copied() == Some(*unit) =>
                {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    let Some(next_name) = name_index.checked_add(1) else {
                        return false;
                    };
                    pattern_index = next_pattern;
                    name_index = next_name;
                    continue;
                }
                DirectoryWildcardToken::AnyOne => {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    let Some(next_name) = name_index.checked_add(1) else {
                        return false;
                    };
                    pattern_index = next_pattern;
                    name_index = next_name;
                    continue;
                }
                DirectoryWildcardToken::AnySequence => {
                    let Some(next_pattern) = pattern_index.checked_add(1) else {
                        return false;
                    };
                    sequence_restart = Some((pattern_index, name_index));
                    pattern_index = next_pattern;
                    continue;
                }
                DirectoryWildcardToken::Literal(_) => {}
            }
        }

        let Some((sequence_index, restart_name)) = sequence_restart else {
            return false;
        };
        let Some(next_restart_name) = restart_name.checked_add(1) else {
            return false;
        };
        let Some(next_pattern) = sequence_index.checked_add(1) else {
            return false;
        };
        sequence_restart = Some((sequence_index, next_restart_name));
        pattern_index = next_pattern;
        name_index = next_restart_name;
    }

    while matches!(
        pattern.get(pattern_index),
        Some(DirectoryWildcardToken::AnySequence)
    ) {
        let Some(next_pattern) = pattern_index.checked_add(1) else {
            return false;
        };
        pattern_index = next_pattern;
    }

    pattern_index == pattern.len()
}

/// Variable directory record layout for one emitted entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryRecordLayout {
    /// Byte offset where the file name starts.
    name_offset: usize,
    /// Byte count occupied by required fields and file-name bytes.
    unpadded_size: usize,
    /// Byte count rounded to the next Windows directory-entry alignment.
    padded_size: usize,
}

impl DirectoryRecordLayout {
    /// Computes the class-specific layout for the supplied Windows name.
    /// # Errors
    ///
    /// Returns an error when the UTF-16 file-name byte length or padded record size overflows.
    fn new(class: DirectoryInformationClass, name: &WindowsName) -> DriverResult<Self> {
        let name_offset = class.name_offset();
        let name_bytes = utf16_byte_len(name.utf16())?;
        let unpadded_size = name_offset
            .checked_add(name_bytes)
            .ok_or(DriverError::InvalidParameter)?;
        Ok(Self {
            name_offset,
            unpadded_size,
            padded_size: align_to_eight(unpadded_size)?,
        })
    }
}

/// Bytes before FileName in FILE_DIRECTORY_INFORMATION.
const DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_DIRECTORY_INFORMATION, FileName);
/// Bytes before FileName in FILE_FULL_DIR_INFORMATION.
const FULL_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_FULL_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_BOTH_DIR_INFORMATION.
const BOTH_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_BOTH_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_NAMES_INFORMATION.
const NAMES_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_NAMES_INFORMATION, FileName);
/// Bytes before FileName in FILE_ID_FULL_DIR_INFORMATION.
const ID_FULL_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_FULL_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_ID_BOTH_DIR_INFORMATION.
const ID_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_BOTH_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_ID_EXTD_DIR_INFORMATION.
const ID_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_EXTD_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_ID_EXTD_BOTH_DIR_INFORMATION.
const ID_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_ID_64_EXTD_DIR_INFORMATION.
const ID_64_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_64_EXTD_DIR_INFORMATION, FileName);
/// Bytes before FileName in FILE_ID_64_EXTD_BOTH_DIR_INFORMATION.
const ID_64_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_64_EXTD_BOTH_DIR_INFORMATION, FileName);
/// Offset of the common NextEntryOffset field.
const DIRECTORY_NEXT_ENTRY_OFFSET: usize = 0;
/// Offset of the common FileIndex field.
const DIRECTORY_FILE_INDEX_OFFSET: usize = 4;
/// Offset of the common CreationTime field.
const DIRECTORY_CREATION_TIME_OFFSET: usize = 8;
/// Offset of the common LastAccessTime field.
const DIRECTORY_LAST_ACCESS_TIME_OFFSET: usize = 16;
/// Offset of the common LastWriteTime field.
const DIRECTORY_LAST_WRITE_TIME_OFFSET: usize = 24;
/// Offset of the common ChangeTime field.
const DIRECTORY_CHANGE_TIME_OFFSET: usize = 32;
/// Offset of the common EndOfFile field.
const DIRECTORY_END_OF_FILE_OFFSET: usize = 40;
/// Offset of the common AllocationSize field.
const DIRECTORY_ALLOCATION_SIZE_OFFSET: usize = 48;
/// Offset of the common FileAttributes field.
const DIRECTORY_FILE_ATTRIBUTES_OFFSET: usize = 56;
/// Offset of the common FileNameLength field.
const DIRECTORY_FILE_NAME_LENGTH_OFFSET: usize = 60;
/// Offset of FileNameLength in FILE_NAMES_INFORMATION.
const NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET: usize = 8;
/// Offset of EaSize in FILE_FULL_DIR_INFORMATION and FILE_BOTH_DIR_INFORMATION.
const DIRECTORY_EA_SIZE_OFFSET: usize = 64;
/// Offset of ShortNameLength in FILE_BOTH_DIR_INFORMATION.
const BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET: usize = 68;
/// Offset of ShortNameLength in FILE_ID_BOTH_DIR_INFORMATION.
const ID_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_BOTH_DIR_INFORMATION, ShortNameLength);
/// Offset of ShortNameLength in FILE_ID_EXTD_BOTH_DIR_INFORMATION.
const ID_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_EXTD_BOTH_DIR_INFORMATION, ShortNameLength);
/// Offset of ShortNameLength in FILE_ID_64_EXTD_BOTH_DIR_INFORMATION.
const ID_64_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET: usize = core::mem::offset_of!(
    wdk_sys::FILE_ID_64_EXTD_BOTH_DIR_INFORMATION,
    ShortNameLength
);
/// Offset of ReparsePointTag in extended file-id directory classes.
const DIRECTORY_REPARSE_TAG_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_EXTD_DIR_INFORMATION, ReparsePointTag);
/// Offset of FileId in FILE_ID_FULL_DIR_INFORMATION.
const ID_FULL_DIRECTORY_FILE_ID_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_FULL_DIR_INFORMATION, FileId);
/// Offset of FileId in FILE_ID_BOTH_DIR_INFORMATION.
const ID_BOTH_DIRECTORY_FILE_ID_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_BOTH_DIR_INFORMATION, FileId);
/// Offset of FileId in FILE_ID_EXTD_DIR_INFORMATION.
const ID_EXTD_DIRECTORY_FILE_ID_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_EXTD_DIR_INFORMATION, FileId);
/// Offset of FileId in FILE_ID_EXTD_BOTH_DIR_INFORMATION.
const ID_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_EXTD_BOTH_DIR_INFORMATION, FileId);
/// Offset of FileId in FILE_ID_64_EXTD_DIR_INFORMATION.
const ID_64_EXTD_DIRECTORY_FILE_ID_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_64_EXTD_DIR_INFORMATION, FileId);
/// Offset of FileId in FILE_ID_64_EXTD_BOTH_DIR_INFORMATION.
const ID_64_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET: usize =
    core::mem::offset_of!(wdk_sys::FILE_ID_64_EXTD_BOTH_DIR_INFORMATION, FileId);
/// Windows directory query entry alignment.
const DIRECTORY_ENTRY_ALIGNMENT: usize = 8;
/// UTF-16 `*`.
const UTF16_ASTERISK: u16 = 0x002A;
/// UTF-16 `.`.
const UTF16_DOT: u16 = 0x002E;
/// UTF-16 `?`.
const UTF16_QUESTION_MARK: u16 = 0x003F;

/// Returns true for the all-entries patterns accepted without wildcard matching.
fn is_all_directory_pattern(units: &[u16]) -> bool {
    units.is_empty()
        || units == [UTF16_ASTERISK]
        || units == [UTF16_ASTERISK, UTF16_DOT, UTF16_ASTERISK]
}

/// Applies QueryDirectory cursor reset/index flags.
fn initialize_directory_cursor(cursor: &mut DirectoryCursor, position: DirectoryCursorPosition) {
    match position {
        DirectoryCursorPosition::Current => {}
        DirectoryCursorPosition::Restart => cursor.restart(),
        DirectoryCursorPosition::Index(index) => cursor.seek_ordinal(u64::from(index.as_u32())),
    }
}

/// Emits directory entries into a caller buffer.
/// # Errors
///
/// Returns an error when cursor arithmetic overflows, a matching entry cannot fit in an empty
/// output buffer, metadata loading fails, or a directory record cannot be packed.
fn emit_directory_entries(
    read: &mut impl CommittedReadPass,
    directory: &DirectoryNode,
    cursor: &mut DirectoryCursor,
    entry_emission: DirectoryEntryEmission,
    class: DirectoryInformationClass,
    pattern: &DirectoryPattern,
    buffer: &mut [u8],
) -> DriverResult<usize> {
    let mut emitted = 0_usize;
    let mut written = 0_usize;
    let mut information = 0_usize;
    let mut previous_start = None;

    loop {
        let batch = match read.scan_directory(directory, cursor, DirectoryScanLimit::MAX) {
            Ok(batch) => batch,
            Err(_) if emitted != 0 => return Ok(information),
            Err(error) => return Err(DriverError::from(error)),
        };
        let exhausted = batch.is_exhausted();
        let entries = batch.into_entries();
        if entries.is_empty() && !exhausted {
            return Err(DriverError::InternalInvariantViolation);
        }
        for scanned in entries {
            let entry = scanned.entry();
            let next_cursor = *scanned.next_cursor();
            let Ok(name) = WindowsName::from_ext4(entry.name()) else {
                *cursor = next_cursor;
                continue;
            };
            if !pattern.matches(&name) {
                *cursor = next_cursor;
                continue;
            }

            let metadata = match metadata_from_node(read, *entry.node()) {
                Ok(metadata) => metadata,
                Err(_) if emitted != 0 => return Ok(information),
                Err(error) => return Err(error),
            };
            let layout = DirectoryRecordLayout::new(class, &name)?;
            let required = written
                .checked_add(layout.unpadded_size)
                .ok_or(DriverError::InvalidParameter)?;
            if required > buffer.len() {
                if emitted == 0 {
                    return Err(DriverError::BufferOverflow);
                }
                return Ok(information);
            }

            if let Some(previous_start) = previous_start {
                let next_offset = written
                    .checked_sub(previous_start)
                    .ok_or(DriverError::InvalidParameter)?;
                LittleEndianOutput::new(buffer).write_u32(
                    record_field_offset(previous_start, DIRECTORY_NEXT_ENTRY_OFFSET)?,
                    u32::try_from(next_offset).map_err(|_| DriverError::InvalidParameter)?,
                )?;
            }

            let file_index = directory_file_index(scanned.ordinal());
            pack_directory_record(buffer, written, class, file_index, &name, metadata, layout)?;
            previous_start = Some(written);
            information = required;
            emitted = emitted
                .checked_add(1)
                .ok_or(DriverError::InvalidParameter)?;
            written = written
                .checked_add(layout.padded_size)
                .ok_or(DriverError::InvalidParameter)?;
            *cursor = next_cursor;

            if matches!(entry_emission, DirectoryEntryEmission::Single) {
                return Ok(information);
            }
        }

        if exhausted {
            return if emitted == 0 {
                Err(pattern.exhausted_error())
            } else {
                Ok(information)
            };
        }
    }
}

/// Projects the 64-bit live-scan ordinal into Windows' legacy directory index field.
fn directory_file_index(ordinal: u64) -> u32 {
    u32::try_from(ordinal).unwrap_or(0)
}

/// Packs one variable-length directory information record.
/// # Errors
///
/// Returns an error when any fixed field or UTF-16 name range falls outside the output buffer.
fn pack_directory_record(
    buffer: &mut [u8],
    start: usize,
    class: DirectoryInformationClass,
    file_index: u32,
    name: &WindowsName,
    metadata: FileMetadata,
    layout: DirectoryRecordLayout,
) -> DriverResult<()> {
    clear_record(buffer, start, layout.unpadded_size)?;
    LittleEndianOutput::new(buffer)
        .write_u32(record_field_offset(start, DIRECTORY_NEXT_ENTRY_OFFSET)?, 0)?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_INDEX_OFFSET)?,
        file_index,
    )?;
    if matches!(class, DirectoryInformationClass::Names) {
        LittleEndianOutput::new(buffer).write_u32(
            record_field_offset(start, NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET)?,
            u32::try_from(utf16_byte_len(name.utf16())?)
                .map_err(|_| DriverError::InvalidParameter)?,
        )?;
        return write_utf16(
            buffer,
            field_offset(start, layout.name_offset)?,
            name.utf16(),
        );
    }
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_CREATION_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.created()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_LAST_ACCESS_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.accessed()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_LAST_WRITE_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.modified()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_CHANGE_TIME_OFFSET)?,
        &windows_time_quad(metadata.times.changed()).to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_END_OF_FILE_OFFSET)?,
        &signed_i64(metadata.size.bytes())?.to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_bytes(
        record_field_offset(start, DIRECTORY_ALLOCATION_SIZE_OFFSET)?,
        &signed_i64(metadata.allocation_size.bytes())?.to_le_bytes(),
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_ATTRIBUTES_OFFSET)?,
        file_attributes(metadata),
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_NAME_LENGTH_OFFSET)?,
        u32::try_from(utf16_byte_len(name.utf16())?).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    if let Some(offset) = class.ea_size_offset() {
        LittleEndianOutput::new(buffer).write_u32(record_field_offset(start, offset)?, 0)?;
    }
    if let Some(offset) = class.short_name_length_offset() {
        LittleEndianOutput::new(buffer).write_u8(record_field_offset(start, offset)?, 0)?;
    }
    if let Some(offset) = class.reparse_tag_offset() {
        LittleEndianOutput::new(buffer).write_u32(
            record_field_offset(start, offset)?,
            reparse_tag(metadata.reparse_point),
        )?;
    }
    if let Some(layout) = class.file_id_layout() {
        match layout {
            DirectoryFileIdLayout::U64(offset) => {
                LittleEndianOutput::new(buffer).write_u64(
                    record_field_offset(start, offset)?,
                    u64::from(metadata.file_index),
                )?;
            }
            DirectoryFileIdLayout::U128(offset) => {
                let high_offset = offset
                    .checked_add(core::mem::size_of::<u64>())
                    .ok_or(DriverError::InvalidParameter)?;
                LittleEndianOutput::new(buffer).write_u64(
                    record_field_offset(start, offset)?,
                    u64::from(metadata.file_index),
                )?;
                LittleEndianOutput::new(buffer)
                    .write_u64(record_field_offset(start, high_offset)?, 0)?;
            }
        }
    }
    write_utf16(
        buffer,
        field_offset(start, layout.name_offset)?,
        name.utf16(),
    )
}

/// Clears a record before individual fields are written.
/// # Errors
///
/// Returns an error when the target record range falls outside `buffer`.
fn clear_record(buffer: &mut [u8], start: usize, length: usize) -> DriverResult<()> {
    let record = mutable_bytes(buffer, start, length)?;
    record.fill(0);
    Ok(())
}

/// Writes UTF-16 code units as Windows little-endian bytes.
/// # Errors
///
/// Returns an error when the UTF-16 output range overflows or extends beyond `buffer`.
fn write_utf16(buffer: &mut [u8], offset: usize, units: &[u16]) -> DriverResult<()> {
    let mut cursor = offset;
    for unit in units {
        LittleEndianOutput::new(buffer).write_u16(wire_offset(cursor), *unit)?;
        cursor = cursor.checked_add(2).ok_or(DriverError::InvalidParameter)?;
    }
    Ok(())
}

/// Returns a checked mutable byte range.
/// # Errors
///
/// Returns an error when `offset..offset + length` overflows or is outside `buffer`.
fn mutable_bytes(buffer: &mut [u8], offset: usize, length: usize) -> DriverResult<&mut [u8]> {
    wire_range(offset, length)?
        .write_to(buffer)
        .map_err(|_| DriverError::BufferOverflow)
}

/// Builds a wire offset after the caller has checked domain arithmetic.
const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Builds a checked wire byte range from raw FILE_INFORMATION_CLASS fields.
/// # Errors
///
/// Returns an error when a file-information `offset + length` cannot be represented as a wire
/// range.
fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Computes an absolute field offset from a record start.
/// # Errors
///
/// Returns an error when the raw directory-record `start + offset` overflows.
fn field_offset(start: usize, offset: usize) -> DriverResult<usize> {
    start
        .checked_add(offset)
        .ok_or(DriverError::InvalidParameter)
}

/// Computes an absolute directory record field offset for wire output.
/// # Errors
///
/// Returns an error when the directory-record field offset cannot be represented as a wire offset.
fn record_field_offset(start: usize, offset: usize) -> DriverResult<WireOffset> {
    field_offset(start, offset).map(wire_offset)
}

/// Returns the byte count for UTF-16 code units.
/// # Errors
///
/// Returns an error when a file-information UTF-16 code-unit count cannot be doubled without
/// overflow.
fn utf16_byte_len(units: &[u16]) -> DriverResult<usize> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)
}

/// Aligns a directory record size to an eight-byte boundary.
/// # Errors
///
/// Returns an error when the padding addition or aligned-size multiplication overflows.
fn align_to_eight(value: usize) -> DriverResult<usize> {
    let adjustment = DIRECTORY_ENTRY_ALIGNMENT
        .checked_sub(1)
        .ok_or(DriverError::InvalidParameter)?;
    let adjusted = value
        .checked_add(adjustment)
        .ok_or(DriverError::InvalidParameter)?;
    let units = adjusted
        .checked_div(DIRECTORY_ENTRY_ALIGNMENT)
        .ok_or(DriverError::InvalidParameter)?;
    units
        .checked_mul(DIRECTORY_ENTRY_ALIGNMENT)
        .ok_or(DriverError::InvalidParameter)
}

/// Converts an unsigned byte count to a signed Windows large-integer payload.
/// # Errors
///
/// Returns an error when a file-information byte count exceeds the signed LARGE_INTEGER range.
fn signed_i64(value: u64) -> DriverResult<i64> {
    i64::try_from(value).map_err(|_| DriverError::InvalidParameter)
}

/// Converts an ext4 timestamp to a Windows time QuadPart.
#[expect(
    unsafe_code,
    reason = "LARGE_INTEGER exposes its signed payload through the generated WDK union field"
)]
fn windows_time_quad(timestamp: Ext4Timestamp) -> i64 {
    let time = windows_time(timestamp);
    unsafe {
        // SAFETY: `QuadPart` is the active LARGE_INTEGER representation used
        // by this driver for Windows time values.
        time.QuadPart
    }
}

/// Cleanup work selected after all synchronous FILE_OBJECT state has been released.
enum CleanupPlan {
    /// No namespace deletion became ready.
    Complete,
    /// The final active handle must remove one exact FCB-owned namespace link.
    Delete(PendingCleanupDeletion),
}

/// Actor-local deferred deletion plan whose FCB remains pinned by the cleanup FILE_OBJECT.
#[derive(Debug)]
pub(crate) struct PendingCleanupDeletion {
    /// Shared FCB retained until the later Close IRP.
    fcb: NonNull<FileControlBlock>,
    /// Immutable opened inode identity.
    node: NodeId,
    /// Stable FCB-owned target allocation.
    target: NonNull<FileDeleteTarget>,
}

#[expect(
    unsafe_code,
    reason = "the cleanup plan remains reactor-owned while its FILE_OBJECT retains stable pointers"
)]
// SAFETY: The per-handle terminal barrier retains the FCB, target, and VCB until this value is
// consumed; it moves only between the sole reactor thread and lower completion envelopes.
unsafe impl Send for PendingCleanupDeletion {}

/// Releases resources owned by one FILE_OBJECT handle lifecycle.
/// # Errors
///
/// Returns an error when the FILE_OBJECT has no opened context.
fn begin_cleanup_file_object(
    active: &mut ActiveIrp<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<CleanupPlan> {
    let file_object = active.current_stack()?.file_object()?;
    let opened_file = OpenedFileObject::decode(file_object)?;
    match opened_file {
        OpenedFileObject::Node(opened_file) => {
            cleanup_opened_node(active, file_object, opened_file)
        }
        OpenedFileObject::Volume(opened_volume) => {
            cleanup_opened_volume(active.device(), file_object, opened_volume, operations)?;
            Ok(CleanupPlan::Complete)
        }
    }
}

/// Releases cleanup-owned state for one namespace-node FILE_OBJECT.
/// # Errors
///
/// Returns an error when the requestor process identity is unavailable.
fn cleanup_opened_node(
    active: &ActiveIrp<'_>,
    file_object: ActiveFileObject<'_>,
    opened_file: OpenedObject<'_>,
) -> DriverResult<CleanupPlan> {
    let requestor = active.requestor_process()?;
    let cleanup_was_published = file_object.cleanup_complete();
    match (opened_file.begin_cleanup(), cleanup_was_published) {
        (CleanupStart::First, false) => {}
        (CleanupStart::AlreadyComplete, true) => return Ok(CleanupPlan::Complete),
        (CleanupStart::First, true) | (CleanupStart::AlreadyComplete, false) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                .bugcheck();
        }
    }
    cleanup_directory_notification(&opened_file);
    opened_file
        .file_control_block()
        .release_handle_byte_range_locks(requestor, file_object.address());
    let cleanup = opened_file.release_share_access_for_cleanup();
    let fcb = opened_file.file_control_block_address();
    let node = opened_file.node();
    opened_file.finish_cleanup();
    file_object.mark_cleanup_complete();
    Ok(match cleanup {
        FileCleanupDisposition::Retained => CleanupPlan::Complete,
        FileCleanupDisposition::Delete(target) => {
            CleanupPlan::Delete(PendingCleanupDeletion { fcb, node, target })
        }
    })
}

/// Removes an identity-checked pending link after the final active handle cleanup.
/// # Errors
///
/// Returns an error when the target name no longer identifies the FCB inode, the directory is no
/// longer empty, or the ext4 transaction cannot be committed.
#[expect(
    unsafe_code,
    reason = "the cleanup FILE_OBJECT retains the FCB-owned delete target until staged publication"
)]
pub(crate) fn stage_cleanup_deletion(
    plan: &PendingCleanupDeletion,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<PreparedCleanupPublication> {
    let target = unsafe {
        // SAFETY: The cleanup FILE_OBJECT retains `fcb` until its later Close IRP. The FCB owns this
        // stable allocation in Pending state, and the device actor cannot mutate that state until
        // this function calls `complete_file_delete` after the final await.
        plan.target.as_ref()
    };
    let parent = mutation.load_directory(target.parent())?;
    match mutation.lookup_child(&parent, target.name())? {
        ChildLookup::Found(child) if *child.node() == plan.node => {}
        ChildLookup::Found(_) | ChildLookup::NotFound => return Err(DriverError::CannotDelete),
    }
    let notification = DirectoryChange::new(
        target.parent(),
        target.name(),
        plan.node,
        DirectoryChangeAction::Removed,
    )?;
    let parent = mutation.directory(target.parent())?;
    match plan.node {
        NodeId::File(_) => mutation.unlink_file(parent, target.name())?,
        NodeId::Directory(_) => {
            mutation.remove_empty_directory(parent, target.name())?;
        }
        NodeId::Symlink(_) => mutation.remove_symlink(parent, target.name())?,
    }
    Ok(PreparedCleanupPublication {
        fcb: plan.fcb,
        target: plan.target,
        notification,
    })
}

/// Removes one direct-volume share claim during its cleanup barrier.
/// # Errors
///
/// Returns an error when FILE_OBJECT and handle lifecycle state disagree.
fn cleanup_opened_volume(
    device: crate::state::KernelDevice,
    file_object: ActiveFileObject<'_>,
    opened_volume: crate::state::OpenedVolume<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> DriverResult<()> {
    let cleanup_was_published = file_object.cleanup_complete();
    match (opened_volume.begin_cleanup(), cleanup_was_published) {
        (CleanupStart::First, false) => {}
        (CleanupStart::AlreadyComplete, true) => return Ok(()),
        (CleanupStart::First, true) | (CleanupStart::AlreadyComplete, false) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_lifecycle_corruption()
                .bugcheck();
        }
    }
    if !operations.owns_volume(opened_volume.volume()) {
        return Err(DriverError::InvalidDeviceRequest);
    }
    let effect = operations.cleanup_volume_handle(opened_volume.file_object());
    if effect == VolumeHandleCleanup::Unlocked {
        MountedVolumeDevice::publish_volume_lock(device, false);
    }
    opened_volume.finish_cleanup();
    file_object.mark_cleanup_complete();
    Ok(())
}

/// Releases FsRtl notification records owned by a FILE_OBJECT during its cleanup transition.
#[expect(
    unsafe_code,
    reason = "the active opened handle retains its mounted VCB through the cleanup transition"
)]
fn cleanup_directory_notification(opened_file: &OpenedObject<'_>) {
    let volume = opened_file.volume();
    let vcb = unsafe {
        // SAFETY: The opened FILE_OBJECT keeps its FCB and mounted VCB alive
        // throughout cleanup, before the CCB context is released at close.
        volume.as_ref()
    };
    vcb.directory_change_notifier()
        .cleanup(opened_file.notification_context());
}

/// Passes one checked buffered set-information input to its typed record decoder.
/// # Errors
///
/// Returns an error when the IRP buffer cannot be captured or typed record decoding fails.
fn decode_file_information_input<T>(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
    decode: impl FnOnce(&[u8]) -> DriverResult<T>,
) -> DriverResult<T> {
    let input = active.buffered_input(length)?;
    decode(input.as_slice())
}

/// Decodes one complete fixed-size record from checked little-endian fields.
/// # Errors
///
/// Returns an error when `bytes` is smaller than the record or a scalar field is out of range.
fn decode_fixed_file_information<T>(
    bytes: &[u8],
    record_length: usize,
    decode: impl FnOnce(LittleEndianInput<'_>) -> DriverResult<T>,
) -> DriverResult<T> {
    let record = bytes
        .get(..record_length)
        .ok_or(DriverError::BufferTooSmall)?;
    decode(LittleEndianInput::new(record))
}

/// Decodes `FILE_BASIC_INFORMATION` without treating an arbitrary `Copy` type as a wire record.
/// # Errors
///
/// Returns an error when the declared input is short or any scalar field is out of range.
fn read_basic_information_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<wdk_sys::FILE_BASIC_INFORMATION> {
    decode_file_information_input(active, length, decode_basic_information_record)
}

/// Decodes a complete `FILE_BASIC_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_basic_information_record(bytes: &[u8]) -> DriverResult<wdk_sys::FILE_BASIC_INFORMATION> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>(),
        |input| {
            Ok(wdk_sys::FILE_BASIC_INFORMATION {
                CreationTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        CreationTime
                    )))?,
                },
                LastAccessTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        LastAccessTime
                    )))?,
                },
                LastWriteTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        LastWriteTime
                    )))?,
                },
                ChangeTime: LARGE_INTEGER {
                    QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                        wdk_sys::FILE_BASIC_INFORMATION,
                        ChangeTime
                    )))?,
                },
                FileAttributes: input.read_u32(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_BASIC_INFORMATION,
                    FileAttributes
                )))?,
            })
        },
    )
}

/// Decodes the signed EOF field from `FILE_END_OF_FILE_INFORMATION`.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_end_of_file_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<LARGE_INTEGER> {
    decode_file_information_input(active, length, decode_end_of_file_record)
}

/// Decodes a complete `FILE_END_OF_FILE_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_end_of_file_record(bytes: &[u8]) -> DriverResult<LARGE_INTEGER> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_END_OF_FILE_INFORMATION>(),
        |input| {
            Ok(LARGE_INTEGER {
                QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_END_OF_FILE_INFORMATION,
                    EndOfFile
                )))?,
            })
        },
    )
}

/// Decodes the signed allocation-size field from `FILE_ALLOCATION_INFORMATION`.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_allocation_size_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<LARGE_INTEGER> {
    decode_file_information_input(active, length, decode_allocation_size_record)
}

/// Decodes a complete `FILE_ALLOCATION_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_allocation_size_record(bytes: &[u8]) -> DriverResult<LARGE_INTEGER> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_ALLOCATION_INFORMATION>(),
        |input| {
            Ok(LARGE_INTEGER {
                QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_ALLOCATION_INFORMATION,
                    AllocationSize
                )))?,
            })
        },
    )
}

/// Decodes the signed cursor from `FILE_POSITION_INFORMATION`.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_position_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<LARGE_INTEGER> {
    decode_file_information_input(active, length, decode_position_record)
}

/// Decodes a complete `FILE_POSITION_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_position_record(bytes: &[u8]) -> DriverResult<LARGE_INTEGER> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>(),
        |input| {
            Ok(LARGE_INTEGER {
                QuadPart: input.read_i64(WireOffset::new(core::mem::offset_of!(
                    wdk_sys::FILE_POSITION_INFORMATION,
                    CurrentByteOffset
                )))?,
            })
        },
    )
}

/// Decodes `FILE_DISPOSITION_INFORMATION::DeleteFile` as a domain boolean.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_legacy_disposition_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<bool> {
    decode_file_information_input(active, length, decode_legacy_disposition_record)
}

/// Decodes a complete `FILE_DISPOSITION_INFORMATION` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_legacy_disposition_record(bytes: &[u8]) -> DriverResult<bool> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION>(),
        |input| {
            Ok(input.read_u8(WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_DISPOSITION_INFORMATION,
                DeleteFile
            )))? != 0)
        },
    )
}

/// Decodes `FILE_DISPOSITION_INFORMATION_EX::Flags` as its checked wire integer.
/// # Errors
///
/// Returns an error when the declared input is shorter than the fixed record.
fn read_extended_disposition_input(
    active: &ActiveIrp<'_>,
    length: IrpBufferLength,
) -> DriverResult<u32> {
    decode_file_information_input(active, length, decode_extended_disposition_record)
}

/// Decodes a complete `FILE_DISPOSITION_INFORMATION_EX` record.
/// # Errors
///
/// Returns an error when `bytes` is shorter than the complete fixed record.
fn decode_extended_disposition_record(bytes: &[u8]) -> DriverResult<u32> {
    decode_fixed_file_information(
        bytes,
        core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION_EX>(),
        |input| {
            input.read_u32(WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_DISPOSITION_INFORMATION_EX,
                Flags
            )))
        },
    )
}

/// Decoded variable-length namespace destination shared by rename and hard-link information.
#[derive(Debug, Eq, PartialEq)]
struct NamespaceTargetPath {
    /// Directory from which the path starts.
    base: NamespaceTargetBase,
    /// Non-empty path below `base`.
    path: NonEmptyWindowsPath,
}

/// Starting directory selected by Windows namespace-target path syntax.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceTargetBase {
    /// A single relative name starts in the source link's current parent.
    OpenedParent(DirectoryNodeId),
    /// A leading backslash starts at the mounted volume root.
    VolumeRoot,
}

impl NamespaceTargetPath {
    /// Decodes the common FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION path layout.
    /// # Errors
    ///
    /// Returns an error when the input is truncated, carries an unsupported root handle, has an
    /// invalid name length, or encodes a relative multi-component path.
    fn decode(bytes: &[u8], opened_parent: DirectoryNodeId) -> DriverResult<Self> {
        if bytes.len() < core::mem::size_of::<wdk_sys::FILE_LINK_INFORMATION>() {
            return Err(DriverError::InfoLengthMismatch);
        }
        reject_root_directory(bytes)?;
        let name_length = usize::try_from(
            LittleEndianInput::new(bytes)
                .read_u32(wire_offset(FILE_NAMESPACE_NAME_LENGTH_OFFSET))?,
        )
        .map_err(|_| DriverError::InvalidParameter)?;
        if name_length == 0 || name_length & 1 != 0 {
            return Err(DriverError::InvalidParameter);
        }
        let name_bytes = input_range(bytes, FILE_NAMESPACE_NAME_OFFSET, name_length)?;
        let units = utf16_units_from_le_bytes(name_bytes)?;
        let (base, path_units) = match units.as_slice().split_first() {
            Some((first, rest)) if *first == UTF16_BACKSLASH => {
                (NamespaceTargetBase::VolumeRoot, rest)
            }
            Some(_) if units.as_slice().contains(&UTF16_BACKSLASH) => {
                return Err(DriverError::InvalidParameter);
            }
            Some(_) => (
                NamespaceTargetBase::OpenedParent(opened_parent),
                units.as_slice(),
            ),
            None => return Err(DriverError::InvalidParameter),
        };
        Ok(Self {
            base,
            path: NonEmptyWindowsPath::from_utf16_path(path_units)?,
        })
    }

    /// Returns the directory from which resolution starts.
    const fn base(&self) -> NamespaceTargetBase {
        self.base
    }

    /// Returns parent components before the target name.
    fn parents(&self) -> &[WindowsName] {
        self.path.parents()
    }

    /// Returns the final target name.
    fn target_name(&self) -> &WindowsName {
        self.path.target_name()
    }
}

/// Existing-target behavior decoded from a hard-link information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardLinkTargetCollision {
    /// The Windows-visible destination must be vacant.
    Reject,
    /// One non-directory destination entry may be replaced.
    Replace,
}

/// FILE_LINK_INFORMATION union arm selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HardLinkInformationFormat {
    /// `FileLinkInformation` exposes a BOOLEAN ReplaceIfExists field.
    ReplaceIfExistsByte,
    /// `FileLinkInformationEx` exposes a ULONG Flags field.
    Flags,
}

impl HardLinkInformationFormat {
    /// Decodes target-collision semantics from the selected hard-link input format.
    /// # Errors
    ///
    /// Returns not-supported when extended semantics cannot be represented faithfully.
    fn target_collision(self, bytes: &[u8]) -> DriverResult<HardLinkTargetCollision> {
        match self {
            Self::ReplaceIfExistsByte => match bytes
                .get(FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET)
                .ok_or(DriverError::BufferTooSmall)?
            {
                0 => Ok(HardLinkTargetCollision::Reject),
                _ => Ok(HardLinkTargetCollision::Replace),
            },
            Self::Flags => {
                let flags = LittleEndianInput::new(bytes)
                    .read_u32(wire_offset(FILE_NAMESPACE_FLAGS_OFFSET))?;
                if flags & !wdk_sys::FILE_LINK_REPLACE_IF_EXISTS != 0 {
                    return Err(DriverError::NotSupported);
                }
                if flags & wdk_sys::FILE_LINK_REPLACE_IF_EXISTS != 0 {
                    Ok(HardLinkTargetCollision::Replace)
                } else {
                    Ok(HardLinkTargetCollision::Reject)
                }
            }
        }
    }
}

/// FILE_RENAME_INFORMATION union arm selected by the information class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenameInformationFormat {
    /// `FileRenameInformation` exposes a BOOLEAN ReplaceIfExists field.
    ReplaceIfExistsByte,
    /// `FileRenameInformationEx` exposes a ULONG Flags field.
    Flags,
}

impl RenameInformationFormat {
    /// Decodes target-collision semantics from the selected rename input format.
    /// # Errors
    ///
    /// Returns an error when unsupported rename-ex flags are set.
    fn target_collision(self, bytes: &[u8]) -> DriverResult<RenameTargetCollision> {
        match self {
            Self::ReplaceIfExistsByte => match bytes
                .get(FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET)
                .ok_or(DriverError::BufferTooSmall)?
            {
                0 => Ok(RenameTargetCollision::Reject),
                _ => Ok(RenameTargetCollision::Replace),
            },
            Self::Flags => {
                let flags = LittleEndianInput::new(bytes)
                    .read_u32(wire_offset(FILE_NAMESPACE_FLAGS_OFFSET))?;
                if flags & !SUPPORTED_RENAME_EX_FLAGS != 0 {
                    return Err(DriverError::NotSupported);
                }
                if flags & wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS != 0 {
                    Ok(RenameTargetCollision::Replace)
                } else {
                    Ok(RenameTargetCollision::Reject)
                }
            }
        }
    }
}

/// Non-empty root-relative Windows path.
#[derive(Debug, Eq, PartialEq)]
struct NonEmptyWindowsPath {
    /// Parent path components from root to target parent.
    parents: DriverVec<WindowsName>,
    /// Final path component being renamed to.
    target_name: WindowsName,
}

impl NonEmptyWindowsPath {
    /// Splits a root-relative UTF-16 path into validated Windows components.
    /// # Errors
    ///
    /// Returns an error when the path is empty after root separators are removed or any component is
    /// not a valid Windows name.
    fn from_utf16_path(units: &[u16]) -> DriverResult<Self> {
        if units.is_empty()
            || units
                .split(|unit| *unit == UTF16_BACKSLASH)
                .any(<[u16]>::is_empty)
        {
            return Err(DriverError::InvalidParameter);
        }
        let mut components = DriverVec::new();
        for component in units.split(|unit| *unit == UTF16_BACKSLASH) {
            components
                .try_push_owned(WindowsName::from_utf16(component)?)
                .map_err(|error| error.into_parts().0)?;
        }
        let target_name = components.pop().ok_or(DriverError::InvalidParameter)?;
        Ok(Self {
            parents: components,
            target_name,
        })
    }

    /// Parent path components from root to target parent.
    fn parents(&self) -> &[WindowsName] {
        self.parents.as_slice()
    }

    /// Final path component.
    const fn target_name(&self) -> &WindowsName {
        &self.target_name
    }
}

/// Offset of the legacy namespace-information ReplaceIfExists field.
const FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET: usize = 0;
/// Offset of the extended namespace-information Flags field.
const FILE_NAMESPACE_FLAGS_OFFSET: usize = 0;
/// Offset of the namespace-information RootDirectory field.
const FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET: usize = 8;
/// Offset of the namespace-information FileNameLength field.
const FILE_NAMESPACE_NAME_LENGTH_OFFSET: usize = 16;
/// Offset of the namespace-information FileName field.
const FILE_NAMESPACE_NAME_OFFSET: usize = 20;
/// FILE_RENAME_INFORMATION_EX flags handled by this driver.
const SUPPORTED_RENAME_EX_FLAGS: wdk_sys::ULONG =
    wdk_sys::FILE_RENAME_IGNORE_READONLY_ATTRIBUTE | wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS;
/// UTF-16 backslash separator.
const UTF16_BACKSLASH: u16 = 0x005C;

/// Rejects namespace-information payloads carrying an unsupported root handle.
/// # Errors
///
/// Returns an error when the root-directory handle field is present and nonzero.
fn reject_root_directory(bytes: &[u8]) -> DriverResult<()> {
    if input_range(
        bytes,
        FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET,
        core::mem::size_of::<wdk_sys::HANDLE>(),
    )?
    .iter()
    .any(|byte| *byte != 0)
    {
        Err(DriverError::NotSupported)
    } else {
        Ok(())
    }
}

/// Decodes little-endian UTF-16 units from a byte buffer.
/// # Errors
///
/// Returns an error when `bytes` has an odd length or cannot be split into two-byte units.
fn utf16_units_from_le_bytes(bytes: &[u8]) -> DriverResult<DriverVec<u16>> {
    if bytes.len() & 1 != 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut units = DriverVec::new();
    let (chunks, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(DriverError::InvalidParameter);
    }
    for chunk in chunks {
        let unit = u16::from_le_bytes(*chunk);
        units.try_push(unit)?;
    }
    Ok(units)
}

/// Resolves the target parent directory and final ext4 name for a namespace mutation.
/// # Errors
///
/// Returns an error when any parent component is absent or not a directory, or the target Windows
/// name cannot be converted to an ext4 name.
fn resolve_namespace_target(
    read: &mut impl CommittedReadPass,
    target: &NamespaceTargetPath,
) -> DriverResult<(DirectoryNodeId, Ext4Name)> {
    let mut parent_id = match target.base() {
        NamespaceTargetBase::OpenedParent(parent) => parent,
        NamespaceTargetBase::VolumeRoot => DirectoryNodeId::ROOT,
    };
    for component in target.parents() {
        let parent = read
            .load_directory(parent_id)
            .map_err(|_| DriverError::ObjectPathNotFound)?;
        let child = read.lookup_windows_child(
            &parent,
            component,
            ext4_core::WindowsNameMatch::CaseInsensitive,
        )?;
        match child {
            ChildLookup::Found(child) => {
                let NodeId::Directory(directory_id) = *child.node() else {
                    return Err(DriverError::ObjectPathNotFound);
                };
                if read
                    .read_windows_symlink_reparse_point(NodeId::Directory(directory_id))?
                    .is_some()
                {
                    return Err(DriverError::NotSupported);
                }
                parent_id = directory_id;
            }
            ChildLookup::NotFound => return Err(DriverError::ObjectPathNotFound),
        };
    }
    Ok((parent_id, target.target_name().to_ext4()?))
}

/// Returns an immutable checked input byte range.
/// # Errors
///
/// Returns an error when `offset..offset + length` overflows or is outside `bytes`.
fn input_range(bytes: &[u8], offset: usize, length: usize) -> DriverResult<&[u8]> {
    wire_range(offset, length)?.read_from(bytes)
}

/// Builds a complete ext4 timestamp set from FILE_BASIC_INFORMATION.
/// # Errors
///
/// Returns an error when any supplied Windows timestamp is negative, unsupported, or cannot be
/// converted to Unix seconds.
fn set_basic_times(
    current: Ext4Times,
    info: wdk_sys::FILE_BASIC_INFORMATION,
) -> DriverResult<Ext4Times> {
    Ok(Ext4Times::new(
        windows_time_field(info.LastAccessTime, current.accessed())?,
        windows_time_field(info.LastWriteTime, current.modified())?,
        windows_time_field(info.ChangeTime, current.changed())?,
        windows_time_field(info.CreationTime, current.created())?,
    ))
}

/// Selects one timestamp field, preserving the current value for sentinel inputs.
/// # Errors
///
/// Returns an error when `value` is a negative non-sentinel timestamp or Windows cannot convert it
/// to Unix seconds.
#[expect(
    unsafe_code,
    reason = "Windows time conversion crosses the audited RtlTimeToSecondsSince1970 ABI"
)]
fn windows_time_field(value: LARGE_INTEGER, current: Ext4Timestamp) -> DriverResult<Ext4Timestamp> {
    let quad = large_integer_quad(value);
    if quad == WINDOWS_TIME_UNCHANGED || quad == WINDOWS_TIME_PRESERVE {
        return Ok(current);
    }
    if quad < 0 {
        return Err(DriverError::InvalidParameter);
    }
    let mut time = value;
    let mut seconds: wdk_sys::ULONG = 0;
    let converted = unsafe {
        // SAFETY: Both pointers reference writable stack storage valid for the
        // duration of the conversion call.
        crate::kernel::ffi::RtlTimeToSecondsSince1970(
            core::ptr::addr_of_mut!(time),
            core::ptr::addr_of_mut!(seconds),
        )
    };
    if converted == 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(Ext4Timestamp::from_unix_seconds(seconds))
}

/// Windows FILE_BASIC_INFORMATION sentinel for preserving a timestamp.
const WINDOWS_TIME_UNCHANGED: i64 = 0;
/// Additional Windows sentinel used by callers to preserve timestamp state.
const WINDOWS_TIME_PRESERVE: i64 = -1;
/// POSIX write bits that make Windows READONLY false.
const POSIX_WRITE_BITS: u16 = 0o222;
/// Owner write bit restored when Windows READONLY is cleared.
const POSIX_OWNER_WRITE_BIT: u16 = 0o200;

/// Domain updates derived from FILE_BASIC_INFORMATION attributes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BasicAttributeUpdate {
    /// POSIX security update needed to reflect FILE_ATTRIBUTE_READONLY.
    security: Option<Ext4Security>,
    /// Windows overlay xattr update for attributes not owned by POSIX mode or node kind.
    overlay: Option<WindowsOverlay>,
}

impl BasicAttributeUpdate {
    /// Creates an empty attribute update.
    const fn empty() -> Self {
        Self {
            security: None,
            overlay: None,
        }
    }

    /// Creates an attribute update from independent domain mutations.
    const fn new(security: Option<Ext4Security>, overlay: Option<WindowsOverlay>) -> Self {
        Self { security, overlay }
    }

    /// Returns whether this update has no domain mutations.
    const fn is_empty(self) -> bool {
        self.security.is_none() && self.overlay.is_none()
    }

    /// POSIX security update.
    const fn security(self) -> Option<Ext4Security> {
        self.security
    }

    /// Windows overlay update.
    const fn overlay(self) -> Option<WindowsOverlay> {
        self.overlay
    }
}

/// Builds overlay metadata from FILE_BASIC_INFORMATION attributes.
/// # Errors
///
/// Returns an error when requested attributes contradict the node kind or include unsupported bits.
fn set_basic_attributes(
    metadata: FileMetadata,
    attributes: wdk_sys::ULONG,
) -> DriverResult<BasicAttributeUpdate> {
    if attributes == 0 {
        return Ok(BasicAttributeUpdate::empty());
    }
    validate_kind_attribute(metadata, attributes)?;

    let accepted = Ext4WindowsAttributes::SUPPORTED_MASK
        | wdk_sys::FILE_ATTRIBUTE_READONLY
        | wdk_sys::FILE_ATTRIBUTE_NORMAL
        | wdk_sys::FILE_ATTRIBUTE_DIRECTORY
        | wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
    if attributes & !accepted != 0 {
        return Err(DriverError::NotSupported);
    }

    let security = readonly_security_update(metadata.security, attributes)?;
    let overlay_bits = attributes & Ext4WindowsAttributes::SUPPORTED_MASK;
    let overlay = if overlay_bits == metadata.overlay_attributes {
        None
    } else {
        Some(WindowsOverlay::new(Ext4WindowsAttributes::new(
            overlay_bits,
        )?))
    };
    Ok(BasicAttributeUpdate::new(security, overlay))
}

/// Builds a POSIX security update for FILE_ATTRIBUTE_READONLY.
/// # Errors
///
/// Returns an error when the adjusted permissions cannot be represented.
fn readonly_security_update(
    security: Ext4Security,
    attributes: wdk_sys::ULONG,
) -> DriverResult<Option<Ext4Security>> {
    let current_permissions = security.permissions().as_u16();
    let requested_permissions = if attributes & wdk_sys::FILE_ATTRIBUTE_READONLY != 0 {
        current_permissions & !POSIX_WRITE_BITS
    } else {
        current_permissions | POSIX_OWNER_WRITE_BIT
    };
    if requested_permissions == current_permissions {
        return Ok(None);
    }
    Ok(Some(Ext4Security::new(
        security.owner(),
        Ext4Permissions::new(requested_permissions)?,
    )))
}

/// Rejects node-kind attributes that contradict the opened ext4 node or reparse state.
/// # Errors
///
/// Returns an error when directory or reparse-point attributes do not match opened metadata.
fn validate_kind_attribute(metadata: FileMetadata, attributes: wdk_sys::ULONG) -> DriverResult<()> {
    if attributes & wdk_sys::FILE_ATTRIBUTE_DIRECTORY != 0
        && metadata.kind != FileMetadataKind::Directory
    {
        return Err(DriverError::InvalidParameter);
    }
    if attributes & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT != 0
        && metadata.reparse_point == FileMetadataReparsePoint::None
    {
        return Err(DriverError::InvalidParameter);
    }
    Ok(())
}

/// Returns a non-negative file size from a Windows LARGE_INTEGER.
/// # Errors
///
/// Returns an error when the LARGE_INTEGER contains a negative size.
fn file_size_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileSize> {
    let value = large_integer_quad(value);
    if value < 0 {
        return Err(DriverError::InvalidParameter);
    }
    Ok(FileSize::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns a non-negative file offset from a Windows LARGE_INTEGER.
/// # Errors
///
/// Returns an error when the LARGE_INTEGER contains a negative offset.
fn file_offset_from_large_integer(value: LARGE_INTEGER) -> DriverResult<FileOffset> {
    let value = large_integer_quad(value);
    Ok(FileOffset::from_bytes(
        u64::try_from(value).map_err(|_| DriverError::InvalidParameter)?,
    ))
}

/// Returns the current size of a regular file inode.
/// # Errors
///
/// Returns an error when `file_id` cannot be loaded as a regular file.
fn regular_file_size(
    read: &mut impl CommittedReadPass,
    file_id: FileNodeId,
) -> DriverResult<FileSize> {
    Ok(read.load_file(file_id)?.size())
}

/// Returns the signed payload of a LARGE_INTEGER.
#[expect(
    unsafe_code,
    reason = "LARGE_INTEGER exposes its signed payload through the generated WDK union field"
)]
fn large_integer_quad(value: LARGE_INTEGER) -> i64 {
    unsafe {
        // SAFETY: `QuadPart` is the LARGE_INTEGER representation used by this
        // driver for Windows time and file-size values.
        value.QuadPart
    }
}

/// File metadata needed by fixed-size Windows information classes.
#[derive(Clone, Copy, Debug)]
struct FileMetadata {
    /// Stable ext4 inode id encoded for Windows file-index payloads.
    file_index: u32,
    /// Open node kind.
    kind: FileMetadataKind,
    /// Payload size in bytes.
    size: FileSize,
    /// ext4 allocation charge in bytes.
    allocation_size: FileAllocationSize,
    /// POSIX security metadata.
    security: Ext4Security,
    /// ext4 inode timestamps.
    times: Ext4Times,
    /// ext4 inode link count.
    links_count: Ext4LinkCount,
    /// Windows-specific overlay attributes.
    overlay_attributes: u32,
    /// Windows reparse metadata projected from a native symlink or private xattr.
    reparse_point: FileMetadataReparsePoint,
}

/// Node kind projected to Windows information flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileMetadataKind {
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
enum FileMetadataReparsePoint {
    /// The node has no Windows reparse metadata.
    None,
    /// The node represents a symbolic-link reparse point.
    SymbolicLink,
}

/// Builds Windows-facing metadata from a loaded ext4 node.
/// # Errors
///
/// Returns an error when `node_id` cannot be loaded as its typed ext4 node or its Windows overlay
/// xattr is malformed.
fn metadata_from_node(
    read: &mut impl CommittedReadPass,
    node_id: NodeId,
) -> DriverResult<FileMetadata> {
    let overlay_attributes = read
        .read_windows_overlay(node_id)?
        .map(|overlay| overlay.attributes().bits())
        .unwrap_or(0);
    let reparse_point = match node_id {
        NodeId::Symlink(_) => FileMetadataReparsePoint::SymbolicLink,
        NodeId::File(_) | NodeId::Directory(_) => {
            if read.read_windows_symlink_reparse_point(node_id)?.is_some() {
                FileMetadataReparsePoint::SymbolicLink
            } else {
                FileMetadataReparsePoint::None
            }
        }
    };

    let file_index = node_id.file_index();
    match node_id {
        NodeId::File(file_id) => {
            let file = read.load_file(file_id)?;
            Ok(FileMetadata {
                file_index,
                kind: FileMetadataKind::File,
                size: file.size(),
                allocation_size: file.allocation_size(),
                security: file.security(),
                times: file.times(),
                links_count: file.links_count(),
                overlay_attributes,
                reparse_point,
            })
        }
        NodeId::Directory(directory_id) => {
            let directory = read.load_directory(directory_id)?;
            Ok(FileMetadata {
                file_index,
                kind: FileMetadataKind::Directory,
                size: directory.size(),
                allocation_size: directory.allocation_size(),
                security: directory.security(),
                times: directory.times(),
                links_count: directory.links_count(),
                overlay_attributes,
                reparse_point,
            })
        }
        NodeId::Symlink(symlink_id) => {
            let symlink = read.load_symlink(symlink_id)?;
            Ok(FileMetadata {
                file_index,
                kind: FileMetadataKind::Symlink,
                size: symlink.size(),
                allocation_size: symlink.allocation_size(),
                security: symlink.security(),
                times: symlink.times(),
                links_count: symlink.links_count(),
                overlay_attributes,
                reparse_point,
            })
        }
    }
}

/// Packs FILE_BASIC_INFORMATION.
/// # Errors
///
/// Returns an error when the output buffer is too small for `FILE_BASIC_INFORMATION`.
fn pack_basic_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_BASIC_INFORMATION,
            CreationTime
        )),
        windows_time_quad(metadata.times.created()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_BASIC_INFORMATION,
            LastAccessTime
        )),
        windows_time_quad(metadata.times.accessed()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_BASIC_INFORMATION,
            LastWriteTime
        )),
        windows_time_quad(metadata.times.modified()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_BASIC_INFORMATION,
            ChangeTime
        )),
        windows_time_quad(metadata.times.changed()),
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_BASIC_INFORMATION,
            FileAttributes
        )),
        file_attributes(metadata),
    )?;
    IrpCompletion::from_usize(size)
}

/// Packs FILE_STANDARD_INFORMATION.
/// # Errors
///
/// Returns an error when allocation or EOF sizes cannot be represented, or the output buffer is too
/// small for `FILE_STANDARD_INFORMATION`.
fn pack_standard_information(
    output: &mut [u8],
    metadata: FileMetadata,
    delete_pending: bool,
) -> DriverResult<IrpCompletion> {
    let links = WindowsLinkInformation::from_metadata(metadata, delete_pending)?;
    let size = core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_INFORMATION,
            AllocationSize
        )),
        signed_i64(metadata.allocation_size.bytes())?,
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_INFORMATION,
            EndOfFile
        )),
        signed_i64(metadata.size.bytes())?,
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_INFORMATION,
            NumberOfLinks
        )),
        links.total_links,
    )?;
    writer.write_u8(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_INFORMATION,
            DeletePending
        )),
        boolean(links.delete_pending),
    )?;
    writer.write_u8(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_STANDARD_INFORMATION,
            Directory
        )),
        boolean(links.directory),
    )?;
    IrpCompletion::from_usize(size)
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
/// Returns an error when the handle has no synchronous current position or the output buffer is
/// too small for `FILE_POSITION_INFORMATION`.
fn pack_position_information(
    output: &mut [u8],
    opened_file: &OpenedObject,
) -> DriverResult<IrpCompletion> {
    let current = opened_file.current_file_position()?;
    let size = core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_POSITION_INFORMATION,
            CurrentByteOffset
        )),
        signed_i64(current.bytes())?,
    )?;
    IrpCompletion::from_usize(size)
}

/// Packs FILE_NETWORK_OPEN_INFORMATION.
/// # Errors
///
/// Returns an error when sizes cannot be represented as signed Windows values or the output buffer
/// is too small for `FILE_NETWORK_OPEN_INFORMATION`.
fn pack_network_open_information(
    output: &mut [u8],
    metadata: FileMetadata,
) -> DriverResult<IrpCompletion> {
    let size = core::mem::size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>();
    let mut writer = fixed_record_writer(output, size)?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            CreationTime
        )),
        windows_time_quad(metadata.times.created()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            LastAccessTime
        )),
        windows_time_quad(metadata.times.accessed()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            LastWriteTime
        )),
        windows_time_quad(metadata.times.modified()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            ChangeTime
        )),
        windows_time_quad(metadata.times.changed()),
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            AllocationSize
        )),
        signed_i64(metadata.allocation_size.bytes())?,
    )?;
    writer.write_i64(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            EndOfFile
        )),
        signed_i64(metadata.size.bytes())?,
    )?;
    writer.write_u32(
        WireOffset::new(core::mem::offset_of!(
            wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
            FileAttributes
        )),
        file_attributes(metadata),
    )?;
    IrpCompletion::from_usize(size)
}

/// Packs FILE_NAME_INFORMATION.
/// # Errors
///
/// Returns an error when the opened location cannot be projected to UTF-16, the name length
/// overflows, or the output buffer is too small.
fn pack_name_information(
    output: &mut [u8],
    opened_file: &OpenedObject,
) -> DriverResult<IrpCompletion> {
    let units = opened_location_name_units(opened_file.location())?;
    let name_bytes = utf16_byte_len(units.as_slice())?;
    let required = FILE_NAME_INFORMATION_NAME_OFFSET
        .checked_add(name_bytes)
        .ok_or(DriverError::InvalidParameter)?;
    if output.len() < required {
        return Err(DriverError::BufferOverflow);
    }
    clear_record(output, 0, required)?;
    LittleEndianOutput::new(output).write_u32(
        WireOffset::new(FILE_NAME_INFORMATION_NAME_LENGTH_OFFSET),
        u32::try_from(name_bytes).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    write_utf16(output, FILE_NAME_INFORMATION_NAME_OFFSET, units.as_slice())?;
    IrpCompletion::from_usize(required)
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
        file_attributes(metadata),
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

/// Projects an opened location to the name payload returned to Windows.
/// # Errors
///
/// Returns an error when the location has no path name or a child ext4 name cannot be represented
/// as a Windows UTF-16 name.
fn opened_location_name_units(location: &OpenedLocation) -> DriverResult<DriverVec<u16>> {
    match location {
        OpenedLocation::Root => DriverVec::try_copied_from_slice(&[UTF16_BACKSLASH]),
        OpenedLocation::DirectoryEntry { name, .. } => {
            DriverVec::try_copied_from_slice(WindowsName::from_ext4(name)?.utf16())
        }
        OpenedLocation::FileReference => Err(DriverError::NotSupported),
    }
}

/// Returns the reparse tag associated with file metadata.
const fn reparse_tag(reparse_point: FileMetadataReparsePoint) -> wdk_sys::ULONG {
    match reparse_point {
        FileMetadataReparsePoint::None => 0,
        FileMetadataReparsePoint::SymbolicLink => wdk_sys::IO_REPARSE_TAG_SYMLINK,
    }
}

/// Offset of FileNameLength in FILE_NAME_INFORMATION.
const FILE_NAME_INFORMATION_NAME_LENGTH_OFFSET: usize = 0;
/// Offset of FileName in FILE_NAME_INFORMATION.
const FILE_NAME_INFORMATION_NAME_OFFSET: usize = 4;

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
fn windows_time(timestamp: Ext4Timestamp) -> LARGE_INTEGER {
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

/// Returns Windows file attribute bits for an ext4 node.
fn file_attributes(metadata: FileMetadata) -> wdk_sys::ULONG {
    let mut attributes = metadata.overlay_attributes;
    if metadata.security.permissions().as_u16() & 0o222 == 0 {
        attributes |= wdk_sys::FILE_ATTRIBUTE_READONLY;
    }
    match metadata.kind {
        FileMetadataKind::File => {}
        FileMetadataKind::Directory => attributes |= wdk_sys::FILE_ATTRIBUTE_DIRECTORY,
        FileMetadataKind::Symlink => {}
    }
    if metadata.reparse_point == FileMetadataReparsePoint::SymbolicLink {
        attributes |= wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT;
    }
    if attributes == 0 {
        wdk_sys::FILE_ATTRIBUTE_NORMAL
    } else {
        attributes
    }
}

/// Converts a Rust boolean to WDK BOOLEAN.
fn boolean(value: bool) -> wdk_sys::BOOLEAN {
    u8::from(value)
}

/// Fully resolved signed Windows file range used by data I/O and byte locks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedFileRange {
    /// First byte affected by the operation.
    start: FileOffset,
    /// Maximum byte count requested by the operation.
    length: usize,
}

impl ResolvedFileRange {
    /// Validates a resolved file range against the signed Windows offset domain.
    /// # Errors
    ///
    /// Returns an error when the end offset overflows or exceeds `i64::MAX`.
    fn new(start: FileOffset, length: usize) -> DriverResult<Self> {
        let end = start.checked_add_len(length)?;
        let _signed_end = i64::try_from(end.bytes()).map_err(|_| DriverError::InvalidParameter)?;
        Ok(Self { start, length })
    }

    /// Returns the resolved starting byte.
    const fn start(self) -> FileOffset {
        self.start
    }

    /// Returns the requested byte count.
    const fn length(self) -> usize {
        self.length
    }
}

/// Read starting source after paging policy is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedReadStart {
    /// Explicit offset independent of FILE_OBJECT state.
    Absolute(FileOffset),
    /// Synchronous FILE_OBJECT current position.
    CurrentFilePosition,
}

/// Applies paging policy to a decoded read starting point.
/// # Errors
///
/// Returns an error when paging I/O requests a handle position.
fn select_read_start(
    kind: DataIoKind,
    starting_point: ReadStartingPoint,
) -> DriverResult<SelectedReadStart> {
    match (kind, starting_point) {
        (DataIoKind::Handle, ReadStartingPoint::Absolute(offset))
        | (DataIoKind::Paging, ReadStartingPoint::Absolute(offset)) => {
            Ok(SelectedReadStart::Absolute(offset))
        }
        (DataIoKind::Handle, ReadStartingPoint::CurrentFilePosition) => {
            Ok(SelectedReadStart::CurrentFilePosition)
        }
        (DataIoKind::Paging, ReadStartingPoint::CurrentFilePosition) => {
            Err(DriverError::InvalidParameter)
        }
    }
}

/// Resolves a selected read source to a concrete file offset.
/// # Errors
///
/// Returns an error when the selected synchronous position is absent.
fn resolve_read_start(
    opened_file: &OpenedRegularFile,
    kind: DataIoKind,
    starting_point: ReadStartingPoint,
) -> DriverResult<FileOffset> {
    match select_read_start(kind, starting_point)? {
        SelectedReadStart::Absolute(offset) => Ok(offset),
        SelectedReadStart::CurrentFilePosition => opened_file.current_file_position(),
    }
}

/// Write starting source after paging and access policy are applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedWriteStart {
    /// Explicit offset independent of FILE_OBJECT state.
    Absolute(FileOffset),
    /// Synchronous FILE_OBJECT current position.
    CurrentFilePosition,
    /// Latest committed regular-file end.
    EndOfFile,
}

/// Write range anchor after any FILE_OBJECT current-position dependency has been resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteRangeAnchor {
    /// Offset fixed before asynchronous volume work starts.
    Fixed(FileOffset),
    /// Latest committed regular-file end, resolved inside the volume operation lane.
    LatestEndOfFile,
}

impl SelectedWriteStart {
    /// Binds the synchronous FILE_OBJECT position only when policy selected it as the source.
    /// # Errors
    ///
    /// Returns an error when a selected current-position source cannot be read from the handle.
    fn bind_current_position(
        self,
        current_position: impl FnOnce() -> DriverResult<FileOffset>,
    ) -> DriverResult<WriteRangeAnchor> {
        match self {
            Self::Absolute(offset) => Ok(WriteRangeAnchor::Fixed(offset)),
            Self::CurrentFilePosition => current_position().map(WriteRangeAnchor::Fixed),
            Self::EndOfFile => Ok(WriteRangeAnchor::LatestEndOfFile),
        }
    }
}

/// Applies paging and write-authority policy to a decoded write starting point.
/// # Errors
///
/// Returns an error for denied handle writes or paging sentinel positions.
fn select_write_start(
    write_access: RegularFileWriteAccess,
    kind: DataIoKind,
    starting_point: WriteStartingPoint,
) -> DriverResult<SelectedWriteStart> {
    if kind == DataIoKind::Paging {
        return match starting_point {
            WriteStartingPoint::Absolute(offset) => Ok(SelectedWriteStart::Absolute(offset)),
            WriteStartingPoint::CurrentFilePosition | WriteStartingPoint::EndOfFile => {
                Err(DriverError::InvalidParameter)
            }
        };
    }

    match write_access {
        RegularFileWriteAccess::Denied => Err(DriverError::AccessDenied),
        RegularFileWriteAccess::AppendOnly => Ok(SelectedWriteStart::EndOfFile),
        RegularFileWriteAccess::Positional => match starting_point {
            WriteStartingPoint::Absolute(offset) => Ok(SelectedWriteStart::Absolute(offset)),
            WriteStartingPoint::CurrentFilePosition => Ok(SelectedWriteStart::CurrentFilePosition),
            WriteStartingPoint::EndOfFile => Ok(SelectedWriteStart::EndOfFile),
        },
    }
}

/// Resolves a write range anchor after access policy and FILE_OBJECT state are known.
/// # Errors
///
/// Returns an error when the latest committed end of file is outside the signed Windows offset
/// domain.
fn resolve_write_start(
    read: &mut impl CommittedReadPass,
    file_id: FileNodeId,
    anchor: WriteRangeAnchor,
) -> DriverResult<FileOffset> {
    match anchor {
        WriteRangeAnchor::Fixed(offset) => Ok(offset),
        WriteRangeAnchor::LatestEndOfFile => regular_file_end(read, file_id),
    }
}

/// Returns the latest committed EOF as a signed-Windows-compatible file offset.
/// # Errors
///
/// Returns an error when the file cannot be loaded or EOF exceeds `i64::MAX`.
fn regular_file_end(
    read: &mut impl CommittedReadPass,
    file_id: FileNodeId,
) -> DriverResult<FileOffset> {
    let end = FileOffset::from_bytes(regular_file_size(read, file_id)?.bytes());
    let _signed_end = i64::try_from(end.bytes()).map_err(|_| DriverError::InvalidParameter)?;
    Ok(end)
}

/// Reads a regular file through bounded driver-owned windows into the pending read IRP.
/// # Errors
///
/// Returns an error when the captured read contract, opened FILE_OBJECT, transfer alignment,
/// byte-range lock, or ext4 data stream is invalid.
fn read_regular_file_direct(
    mut request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
) -> DriverResult<IrpCompletion> {
    let stack = request.prepared_read()?.stack();
    let output_address = request.prepared_read()?.output_address();
    let Some((file_id, kind, range)) = request.with_active(|active| {
        let kind = active.data_io_kind();
        let file_object = active.current_stack()?.file_object()?;
        let mut opened_file = OpenedRegularFile::decode(file_object)?;
        let range = ResolvedFileRange::new(
            resolve_read_start(&opened_file, kind, stack.starting_point())?,
            stack.length().as_usize(),
        )?;
        let data_transfer_mode = opened_file.data_transfer_mode();
        data_transfer_mode.validate_range(range.start().bytes(), range.length())?;
        if stack.length().is_empty() {
            opened_file.update_current_file_position(kind, range.start(), 0)?;
            return Ok(None);
        }
        data_transfer_mode
            .validate_buffer(output_address.ok_or(DriverError::InternalInvariantViolation)?)?;
        if kind == DataIoKind::Handle
            && !opened_file.file_control_block().permits_byte_range_read(
                active.requestor_process()?,
                opened_file.file_object(),
                range.start(),
                range.length(),
                stack.key(),
            )?
        {
            return Err(DriverError::FileLockConflict);
        }
        Ok(Some((opened_file.id(), kind, range)))
    })?
    else {
        return Ok(IrpCompletion::EMPTY);
    };

    let file = read.load_file(file_id)?;
    let total = NonZeroUsize::new(range.length()).ok_or(DriverError::InternalInvariantViolation)?;
    let mut windows = DataTransferWindows::new(total);
    let mut snapshot = DriverVec::try_repeated_copy(0_u8, windows.snapshot_capacity())?;
    let mut bytes_read = 0_usize;
    while let Some(window) = windows.next_window()? {
        let chunk = snapshot
            .as_mut_slice()
            .get_mut(..window.length())
            .ok_or(DriverError::InternalInvariantViolation)?;
        let chunk_offset = range.start().checked_add_len(window.offset())?;
        let chunk_read = read.read_file(&file, chunk_offset, chunk)?.as_usize();
        let source = chunk
            .get(..chunk_read)
            .ok_or(DriverError::InternalInvariantViolation)?;
        request
            .prepared_read_mut()?
            .copy_window(window.offset(), source)?;
        bytes_read = bytes_read
            .checked_add(chunk_read)
            .ok_or(DriverError::InternalInvariantViolation)?;
        if chunk_read != window.length() {
            break;
        }
    }
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        let mut opened_file = OpenedRegularFile::decode(file_object)?;
        opened_file.update_current_file_position(kind, range.start(), bytes_read)
    })?;
    IrpCompletion::from_usize(bytes_read)
}

/// Writes a regular file from bounded snapshots of the pending write IRP's input mapping.
/// # Errors
///
/// Returns an error when the captured write contract, opened FILE_OBJECT, transfer alignment,
/// byte-range lock, or ext4 journal transaction is invalid.
fn write_regular_file_windowed(
    mut request: PendingIrpLease<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
) -> DriverResult<WriteResolution> {
    let stack = request.prepared_write()?.stack();
    let input_address = request.prepared_write()?.input_address();
    let (file_id, kind, anchor, data_transfer_mode) = request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        let opened_file = OpenedRegularFile::decode(file_object)?;
        let kind = active.data_io_kind();
        let selected_start =
            select_write_start(opened_file.write_access(), kind, stack.starting_point())?;
        let anchor =
            selected_start.bind_current_position(|| opened_file.current_file_position())?;
        let data_transfer_mode = opened_file.data_transfer_mode();
        Ok::<_, DriverError>((opened_file.id(), kind, anchor, data_transfer_mode))
    })?;

    let range = ResolvedFileRange::new(
        resolve_write_start(mutation, file_id, anchor)?,
        stack.length().as_usize(),
    )?;
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        let opened_file = OpenedRegularFile::decode(file_object)?;
        data_transfer_mode.validate_range(range.start().bytes(), range.length())?;
        if stack.length().is_empty() {
            return Ok(());
        }
        data_transfer_mode
            .validate_buffer(input_address.ok_or(DriverError::InternalInvariantViolation)?)?;
        if kind == DataIoKind::Handle
            && !opened_file.file_control_block().permits_byte_range_write(
                active.requestor_process()?,
                opened_file.file_object(),
                range.start(),
                range.length(),
                stack.key(),
            )?
        {
            return Err(DriverError::FileLockConflict);
        }
        Ok(())
    })?;
    if stack.length().is_empty() {
        request.with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            let mut opened_file = OpenedRegularFile::decode(file_object)?;
            opened_file.update_current_file_position(kind, range.start(), 0)
        })?;
        return Ok(WriteResolution::Complete(IrpCompletion::EMPTY));
    }

    let bytes_written = {
        let total = NonZeroUsize::new(stack.length().as_usize())
            .ok_or(DriverError::InternalInvariantViolation)?;
        let mut windows = DataTransferWindows::new(total);
        let mut snapshot = DriverVec::try_repeated_copy(0_u8, windows.snapshot_capacity())?;
        let file = mutation.file(file_id)?;
        while let Some(window) = windows.next_window()? {
            let chunk = snapshot
                .as_mut_slice()
                .get_mut(..window.length())
                .ok_or(DriverError::InternalInvariantViolation)?;
            request
                .prepared_write()?
                .copy_window(window.offset(), chunk)?;
            let chunk_offset = range.start().checked_add_len(window.offset())?;
            mutation.write_file_range(file, chunk_offset, chunk)?;
        }
        windows.completed()
    };
    let position = request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        let opened_file = OpenedRegularFile::decode(file_object)?;
        opened_file.prepare_current_file_position_update(kind, range.start(), bytes_written)
    })?;
    Ok(WriteResolution::Mutation(PreparedWritePublication {
        completion: IrpCompletion::from_usize(bytes_written)?,
        position,
    }))
}

/// Detaches and releases heap-owned FCB and CCB pointers stored on a FILE_OBJECT.
#[expect(
    unsafe_code,
    reason = "close consumes the unique Box pointers detached from the active FILE_OBJECT contexts"
)]
fn release_file_contexts(
    device: crate::state::KernelDevice,
    file_object: ActiveFileObject<'_>,
    operations: &mut MountedVolumeAccess<'_>,
) -> VolumeRetirement {
    if file_object.has_no_file_system_contexts() {
        return VolumeRetirement::Retained;
    }
    let close_kind = file_object.close_kind_or_bugcheck();
    let opened = match OpenedFileObject::decode(file_object) {
        Ok(opened) => opened,
        Err(_) => {
            crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                .bugcheck();
        }
    };
    match opened {
        OpenedFileObject::Node(opened) => {
            let volume = opened.volume();
            let release_plan = opened.close_release_plan(close_kind);
            let file_object_address = file_object.address();
            let (fcb, handle) = opened.take_node_contexts();
            match release_plan {
                CloseReleasePlan::CleanedHandle => release_file_control_block(fcb),
                CloseReleasePlan::CancelledOpen => {
                    release_cancelled_file_control_block(fcb, file_object_address);
                }
            }
            unsafe {
                // SAFETY: Successful node create stores Box<OpenedHandle> in FsContext2. Close
                // detached the unique owning pointer before this terminal drop.
                drop(Box::from_raw(handle.as_ptr()));
            }
            if !operations.owns_volume(volume) {
                crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                    .bugcheck();
            }
            operations.close_node_file_object()
        }
        OpenedFileObject::Volume(opened) => {
            let release_plan = opened.close_release_plan(close_kind);
            let file_object_address = opened.file_object();
            let (volume, handle) = opened.take_volume_contexts();
            if !operations.owns_volume(volume) {
                crate::kernel::fatal::KernelWideInconsistency::file_object_context_corruption()
                    .bugcheck();
            }
            let outcome = operations.close_volume_file_object(file_object_address, release_plan);
            if outcome.cleanup() == VolumeHandleCleanup::Unlocked {
                MountedVolumeDevice::publish_volume_lock(device, false);
            }
            unsafe {
                // SAFETY: Successful volume create stores Box<OpenedVolumeHandle> in FsContext2.
                // Close detached the unique owning pointer before this terminal drop.
                drop(Box::from_raw(handle.as_ptr()));
            }
            outcome.retirement()
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::irp::{
        CreateDeletion, DataIoKind, DirectoryInformationClass, FileAttributesWriteAccess,
        IrpCompletion, ReadStartingPoint, ReceivedIrp, RegularFileWriteAccess, WriteStartingPoint,
    };
    use crate::kernel::status::DriverError;
    use crate::state::OpenedLocation;
    use ext4_core::{
        DirectoryNodeId, Ext4Gid, Ext4LinkCount, Ext4Name, Ext4Owner, Ext4Permissions,
        Ext4Security, Ext4Times, Ext4Timestamp, Ext4Uid, FileAllocationSize, FileOffset, FileSize,
        WindowsName,
    };

    fn test_metadata(kind: super::FileMetadataKind) -> Option<super::FileMetadata> {
        test_metadata_with_permissions(kind, 0o644, 0)
    }

    fn test_metadata_with_permissions(
        kind: super::FileMetadataKind,
        permissions: u16,
        overlay_attributes: u32,
    ) -> Option<super::FileMetadata> {
        let timestamp = Ext4Timestamp::from_unix_seconds(1);
        Some(super::FileMetadata {
            file_index: 1,
            kind,
            size: FileSize::from_bytes(0),
            allocation_size: FileAllocationSize::from_bytes(0),
            security: Ext4Security::new(
                Ext4Owner::new(Ext4Uid::from_u32(0), Ext4Gid::from_u32(0)),
                Ext4Permissions::new(permissions).ok()?,
            ),
            times: Ext4Times::new(timestamp, timestamp, timestamp, timestamp),
            links_count: Ext4LinkCount::ONE,
            overlay_attributes,
            reparse_point: match kind {
                super::FileMetadataKind::File | super::FileMetadataKind::Directory => {
                    super::FileMetadataReparsePoint::None
                }
                super::FileMetadataKind::Symlink => super::FileMetadataReparsePoint::SymbolicLink,
            },
        })
    }

    /// Builds one variable-length namespace information buffer.
    fn namespace_information_input(units: &[u16]) -> Option<alloc::vec::Vec<u8>> {
        let name_bytes = units.len().checked_mul(core::mem::size_of::<u16>())?;
        let payload = super::FILE_NAMESPACE_NAME_OFFSET.checked_add(name_bytes)?;
        let total = core::cmp::max(
            payload,
            core::mem::size_of::<wdk_sys::FILE_LINK_INFORMATION>(),
        );
        let mut input = vec![0_u8; total];
        if !put_le_u32(
            &mut input,
            super::FILE_NAMESPACE_NAME_LENGTH_OFFSET,
            u32::try_from(name_bytes).ok()?,
        ) {
            return None;
        }
        let name = input.get_mut(super::FILE_NAMESPACE_NAME_OFFSET..total)?;
        let (outputs, remainder) = name.as_chunks_mut::<2>();
        if !remainder.is_empty() {
            return None;
        }
        for (output, unit) in outputs.iter_mut().zip(units.iter().copied()) {
            crate::memory::copy_exact(output, &unit.to_le_bytes()).ok()?;
        }
        Some(input)
    }

    /// Reads one little-endian u32 from a test output buffer.
    fn le_u32(buffer: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(core::mem::size_of::<u32>())?;
        let bytes = buffer.get(offset..end)?;
        let bytes = <[u8; 4]>::try_from(bytes).ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    /// Reads one little-endian u64 from a test output buffer.
    fn le_u64(buffer: &[u8], offset: usize) -> Option<u64> {
        let end = offset.checked_add(core::mem::size_of::<u64>())?;
        let bytes = buffer.get(offset..end)?;
        let bytes = <[u8; 8]>::try_from(bytes).ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// Builds a Windows hard-link set through the same fallible ownership boundary as production.
    fn windows_hard_links(entries: &[(u64, &[u16])]) -> Option<super::WindowsHardLinks> {
        let mut projected = crate::memory::DriverVec::try_with_capacity(entries.len()).ok()?;
        for (parent_file_id, units) in entries {
            let entry = super::WindowsHardLinkEntry {
                parent_file_id: *parent_file_id,
                name: WindowsName::from_utf16(units).ok()?,
            };
            projected.try_push_owned(entry).ok()?;
        }
        Some(super::WindowsHardLinks { entries: projected })
    }

    /// Reads one byte from a test output buffer without panicking on a malformed layout.
    fn byte_at(buffer: &[u8], offset: usize) -> Option<u8> {
        buffer.get(offset).copied()
    }

    /// Reads one little-endian i64 from a test output buffer.
    fn le_i64(buffer: &[u8], offset: usize) -> Option<i64> {
        let end = offset.checked_add(core::mem::size_of::<i64>())?;
        let bytes = buffer.get(offset..end)?;
        let bytes = <[u8; 8]>::try_from(bytes).ok()?;
        Some(i64::from_le_bytes(bytes))
    }

    /// Writes one little-endian u32 into a test input buffer.
    fn put_le_u32(buffer: &mut [u8], offset: usize, value: u32) -> bool {
        let Some(end) = offset.checked_add(core::mem::size_of::<u32>()) else {
            return false;
        };
        let Some(target) = buffer.get_mut(offset..end) else {
            return false;
        };
        crate::memory::copy_exact(target, &value.to_le_bytes()).is_ok()
    }

    /// Writes one little-endian i64 into a test input buffer.
    fn put_le_i64(buffer: &mut [u8], offset: usize, value: i64) -> bool {
        let Some(end) = offset.checked_add(core::mem::size_of::<i64>()) else {
            return false;
        };
        let Some(target) = buffer.get_mut(offset..end) else {
            return false;
        };
        crate::memory::copy_exact(target, &value.to_le_bytes()).is_ok()
    }

    /// Asserts that every byte not owned by an encoded scalar field was cleared.
    /// # Panics
    ///
    /// Panics when an ABI padding byte is nonzero.
    fn assert_padding_zero(record: &[u8], fields: &[(usize, usize)]) {
        for (offset, byte) in record.iter().copied().enumerate() {
            let is_field = fields.iter().any(|(start, length)| {
                start
                    .checked_add(*length)
                    .is_some_and(|end| *start <= offset && offset < end)
            });
            if !is_field {
                assert_eq!(byte, 0, "padding byte {offset} retained stale storage");
            }
        }
    }

    /// # Panics
    ///
    /// Panics when any fixed set-information decoder loses a scalar field or accepts a truncated
    /// Windows record.
    #[test]
    fn fixed_set_information_decoders_are_field_checked_and_length_bounded() {
        let basic_size = core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>();
        let mut basic = vec![0xA5_u8; basic_size];
        let times = [-7_i64, 11, -13, 17];
        for (offset, value) in [
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, CreationTime),
                times[0],
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastAccessTime),
                times[1],
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastWriteTime),
                times[2],
            ),
            (
                core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, ChangeTime),
                times[3],
            ),
        ] {
            assert!(put_le_i64(&mut basic, offset, value));
        }
        let attributes = 0x1234_5678;
        assert!(put_le_u32(
            &mut basic,
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, FileAttributes),
            attributes,
        ));
        let decoded = super::decode_basic_information_record(&basic);
        assert!(decoded.is_ok());
        let Ok(decoded) = decoded else {
            return;
        };
        assert_eq!(super::large_integer_quad(decoded.CreationTime), times[0]);
        assert_eq!(super::large_integer_quad(decoded.LastAccessTime), times[1]);
        assert_eq!(super::large_integer_quad(decoded.LastWriteTime), times[2]);
        assert_eq!(super::large_integer_quad(decoded.ChangeTime), times[3]);
        assert_eq!(decoded.FileAttributes, attributes);

        let eof_value = -0x0102_0304_0506_0708_i64;
        let eof_size = core::mem::size_of::<wdk_sys::FILE_END_OF_FILE_INFORMATION>();
        let mut eof = vec![0xA5_u8; eof_size];
        assert!(put_le_i64(
            &mut eof,
            core::mem::offset_of!(wdk_sys::FILE_END_OF_FILE_INFORMATION, EndOfFile),
            eof_value,
        ));
        assert_eq!(
            super::decode_end_of_file_record(&eof).map(super::large_integer_quad),
            Ok(eof_value)
        );

        let allocation_value = 0x0102_0304_0506_0708_i64;
        let allocation_size = core::mem::size_of::<wdk_sys::FILE_ALLOCATION_INFORMATION>();
        let mut allocation = vec![0xA5_u8; allocation_size];
        assert!(put_le_i64(
            &mut allocation,
            core::mem::offset_of!(wdk_sys::FILE_ALLOCATION_INFORMATION, AllocationSize),
            allocation_value,
        ));
        assert_eq!(
            super::decode_allocation_size_record(&allocation).map(super::large_integer_quad),
            Ok(allocation_value)
        );

        let position_value = -91_i64;
        let position_size = core::mem::size_of::<wdk_sys::FILE_POSITION_INFORMATION>();
        let mut position = vec![0xA5_u8; position_size];
        assert!(put_le_i64(
            &mut position,
            core::mem::offset_of!(wdk_sys::FILE_POSITION_INFORMATION, CurrentByteOffset),
            position_value,
        ));
        assert_eq!(
            super::decode_position_record(&position).map(super::large_integer_quad),
            Ok(position_value)
        );

        let legacy_size = core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION>();
        let mut legacy = vec![0xA5_u8; legacy_size];
        let legacy_offset =
            core::mem::offset_of!(wdk_sys::FILE_DISPOSITION_INFORMATION, DeleteFile);
        let Some(delete_file) = legacy.get_mut(legacy_offset) else {
            return;
        };
        *delete_file = 1;
        assert_eq!(super::decode_legacy_disposition_record(&legacy), Ok(true));

        let extended_size = core::mem::size_of::<wdk_sys::FILE_DISPOSITION_INFORMATION_EX>();
        let mut extended = vec![0xA5_u8; extended_size];
        let flags = 0x8765_4321;
        assert!(put_le_u32(
            &mut extended,
            core::mem::offset_of!(wdk_sys::FILE_DISPOSITION_INFORMATION_EX, Flags),
            flags,
        ));
        assert_eq!(
            super::decode_extended_disposition_record(&extended),
            Ok(flags)
        );

        for result in [
            basic
                .len()
                .checked_sub(1)
                .and_then(|length| basic.get(..length))
                .and_then(|input| super::decode_basic_information_record(input).err()),
            eof.len()
                .checked_sub(1)
                .and_then(|length| eof.get(..length))
                .and_then(|input| super::decode_end_of_file_record(input).err()),
            allocation
                .len()
                .checked_sub(1)
                .and_then(|length| allocation.get(..length))
                .and_then(|input| super::decode_allocation_size_record(input).err()),
            position
                .len()
                .checked_sub(1)
                .and_then(|length| position.get(..length))
                .and_then(|input| super::decode_position_record(input).err()),
            legacy
                .len()
                .checked_sub(1)
                .and_then(|length| legacy.get(..length))
                .and_then(|input| super::decode_legacy_disposition_record(input).err()),
            extended
                .len()
                .checked_sub(1)
                .and_then(|length| extended.get(..length))
                .and_then(|input| super::decode_extended_disposition_record(input).err()),
        ] {
            assert_eq!(result, Some(DriverError::BufferTooSmall));
        }
    }

    /// # Panics
    ///
    /// Panics when an explicitly packed fixed record exposes pre-existing bytes through ABI
    /// padding.
    #[test]
    fn fixed_query_information_packers_clear_every_padding_byte() {
        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let mut basic = vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_BASIC_INFORMATION>()];
        assert!(super::pack_basic_information(&mut basic, metadata).is_ok());
        assert_padding_zero(
            &basic,
            &[
                (
                    core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, CreationTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastAccessTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastWriteTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, ChangeTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, FileAttributes),
                    4,
                ),
            ],
        );

        let mut standard =
            vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
        assert!(super::pack_standard_information(&mut standard, metadata, false).is_ok());
        assert_padding_zero(
            &standard,
            &[
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, AllocationSize),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, EndOfFile),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, NumberOfLinks),
                    4,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, DeletePending),
                    1,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, Directory),
                    1,
                ),
            ],
        );

        let mut standard_link =
            vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>()];
        assert!(super::pack_standard_link_information(&mut standard_link, metadata, false).is_ok());
        assert_padding_zero(
            &standard_link,
            &[
                (
                    core::mem::offset_of!(
                        wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                        NumberOfAccessibleLinks
                    ),
                    4,
                ),
                (
                    core::mem::offset_of!(
                        wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                        TotalNumberOfLinks
                    ),
                    4,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, DeletePending),
                    1,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory),
                    1,
                ),
            ],
        );

        let mut network =
            vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>()];
        assert!(super::pack_network_open_information(&mut network, metadata).is_ok());
        assert_padding_zero(
            &network,
            &[
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, CreationTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, LastAccessTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, LastWriteTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, ChangeTime),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, AllocationSize),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, EndOfFile),
                    8,
                ),
                (
                    core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, FileAttributes),
                    4,
                ),
            ],
        );
    }

    /// # Panics
    ///
    /// Panics when non-empty transfer progress is not exhaustive, ordered, or window-bounded.
    #[test]
    fn data_transfer_windows_partition_the_exact_request() {
        let total_value = super::MAX_DATA_TRANSFER_WINDOW_BYTES
            .saturating_mul(2)
            .saturating_add(17);
        let Some(total) = core::num::NonZeroUsize::new(total_value) else {
            return;
        };
        let mut windows = super::DataTransferWindows::new(total);
        assert_eq!(
            windows.snapshot_capacity(),
            super::MAX_DATA_TRANSFER_WINDOW_BYTES
        );

        for (expected_offset, expected_length) in [
            (0, super::MAX_DATA_TRANSFER_WINDOW_BYTES),
            (
                super::MAX_DATA_TRANSFER_WINDOW_BYTES,
                super::MAX_DATA_TRANSFER_WINDOW_BYTES,
            ),
            (super::MAX_DATA_TRANSFER_WINDOW_BYTES.saturating_mul(2), 17),
        ] {
            let window = windows.next_window();
            assert!(window.is_ok());
            if let Ok(Some(window)) = window {
                assert_eq!(window.offset(), expected_offset);
                assert_eq!(window.length(), expected_length);
            } else {
                return;
            }
        }
        assert_eq!(windows.next_window(), Ok(None));
        assert_eq!(windows.completed(), total_value);

        let Some(one_byte) = core::num::NonZeroUsize::new(1) else {
            return;
        };
        let mut minimum = super::DataTransferWindows::new(one_byte);
        assert_eq!(minimum.snapshot_capacity(), 1);
        assert_eq!(
            minimum.next_window(),
            Ok(Some(super::DataTransferWindow {
                offset: 0,
                length: one_byte,
            }))
        );
        assert_eq!(minimum.next_window(), Ok(None));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn basic_attributes_set_readonly_updates_posix_permissions() {
        let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o664, 0);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let update = super::set_basic_attributes(metadata, wdk_sys::FILE_ATTRIBUTE_READONLY);
        assert!(update.is_ok());
        if let Ok(update) = update {
            assert_eq!(
                update
                    .security()
                    .map(|security| security.permissions().as_u16()),
                Some(0o444)
            );
            assert_eq!(update.overlay(), None);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn basic_attributes_clear_readonly_restores_owner_write() {
        let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o444, 0);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let update = super::set_basic_attributes(metadata, wdk_sys::FILE_ATTRIBUTE_NORMAL);
        assert!(update.is_ok());
        if let Ok(update) = update {
            assert_eq!(
                update
                    .security()
                    .map(|security| security.permissions().as_u16()),
                Some(0o644)
            );
            assert_eq!(update.overlay(), None);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn basic_attributes_zero_preserves_existing_attributes() {
        let metadata = test_metadata_with_permissions(super::FileMetadataKind::File, 0o444, 0);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let update = super::set_basic_attributes(metadata, 0);
        assert!(update.is_ok());
        if let Ok(update) = update {
            assert!(update.is_empty());
        }
    }

    /// # Panics
    ///
    /// Panics when paging read policy accepts a FILE_OBJECT current-position dependency.
    #[test]
    fn read_start_selection_separates_handle_and_paging_io() {
        let explicit = FileOffset::from_bytes(4096);
        assert_eq!(
            super::select_read_start(DataIoKind::Paging, ReadStartingPoint::Absolute(explicit),),
            Ok(super::SelectedReadStart::Absolute(explicit))
        );
        assert_eq!(
            super::select_read_start(DataIoKind::Handle, ReadStartingPoint::CurrentFilePosition,),
            Ok(super::SelectedReadStart::CurrentFilePosition)
        );
        assert_eq!(
            super::select_read_start(DataIoKind::Paging, ReadStartingPoint::CurrentFilePosition,),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when append-only writes retain a caller-selected starting point.
    #[test]
    fn append_only_write_selection_always_uses_end_of_file() {
        for starting_point in [
            WriteStartingPoint::Absolute(FileOffset::from_bytes(1)),
            WriteStartingPoint::CurrentFilePosition,
            WriteStartingPoint::EndOfFile,
        ] {
            assert_eq!(
                super::select_write_start(
                    RegularFileWriteAccess::AppendOnly,
                    DataIoKind::Handle,
                    starting_point,
                ),
                Ok(super::SelectedWriteStart::EndOfFile)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when denied, positional, or paging write policy selects the wrong source.
    #[test]
    fn write_start_selection_enforces_access_and_paging_policy() {
        let explicit = FileOffset::from_bytes(8192);
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Denied,
                DataIoKind::Handle,
                WriteStartingPoint::Absolute(explicit),
            ),
            Err(DriverError::AccessDenied)
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Denied,
                DataIoKind::Handle,
                WriteStartingPoint::CurrentFilePosition,
            ),
            Err(DriverError::AccessDenied)
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Positional,
                DataIoKind::Handle,
                WriteStartingPoint::CurrentFilePosition,
            ),
            Ok(super::SelectedWriteStart::CurrentFilePosition)
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Denied,
                DataIoKind::Paging,
                WriteStartingPoint::Absolute(explicit),
            ),
            Ok(super::SelectedWriteStart::Absolute(explicit))
        );
        assert_eq!(
            super::select_write_start(
                RegularFileWriteAccess::Positional,
                DataIoKind::Paging,
                WriteStartingPoint::EndOfFile,
            ),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when access policy reads a handle position before selecting the write source.
    #[test]
    fn write_start_policy_precedes_current_position_binding() {
        let denied_position_read = core::cell::Cell::new(false);
        let denied = super::select_write_start(
            RegularFileWriteAccess::Denied,
            DataIoKind::Handle,
            WriteStartingPoint::CurrentFilePosition,
        )
        .and_then(|selected| {
            selected.bind_current_position(|| {
                denied_position_read.set(true);
                Err(DriverError::InvalidParameter)
            })
        });
        assert_eq!(denied, Err(DriverError::AccessDenied));
        assert!(!denied_position_read.get());

        let append_position_read = core::cell::Cell::new(false);
        let append = super::select_write_start(
            RegularFileWriteAccess::AppendOnly,
            DataIoKind::Handle,
            WriteStartingPoint::CurrentFilePosition,
        )
        .and_then(|selected| {
            selected.bind_current_position(|| {
                append_position_read.set(true);
                Err(DriverError::InvalidParameter)
            })
        });
        assert_eq!(append, Ok(super::WriteRangeAnchor::LatestEndOfFile));
        assert!(!append_position_read.get());

        let position = FileOffset::from_bytes(12288);
        let positional = super::select_write_start(
            RegularFileWriteAccess::Positional,
            DataIoKind::Handle,
            WriteStartingPoint::CurrentFilePosition,
        )
        .and_then(|selected| selected.bind_current_position(|| Ok(position)));
        assert_eq!(positional, Ok(super::WriteRangeAnchor::Fixed(position)));
    }

    /// # Panics
    ///
    /// Panics when resolved ranges cross the signed Windows file-offset boundary.
    #[test]
    fn resolved_file_range_rejects_signed_end_overflow() {
        assert!(super::ResolvedFileRange::new(FileOffset::from_bytes(4096), 0).is_ok());
        assert_eq!(
            super::ResolvedFileRange::new(FileOffset::from_bytes(i64::MAX.unsigned_abs()), 1,)
                .err(),
            Some(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when the extended disposition boundary loses non-POSIX ON_CLOSE semantics.
    #[test]
    fn extended_disposition_decodes_non_posix_and_on_close_semantics() {
        assert_eq!(
            super::decode_extended_disposition(0),
            Ok(super::FileDispositionRequest::keep(
                super::FileDispositionTarget::Mutable
            ))
        );
        assert_eq!(
            super::decode_extended_disposition(wdk_sys::FILE_DISPOSITION_DELETE),
            Ok(super::FileDispositionRequest::delete(
                super::FileDispositionTarget::Mutable,
                super::DeleteReadonlyRequest::Enforce
            ))
        );
        assert_eq!(
            super::decode_extended_disposition(
                wdk_sys::FILE_DISPOSITION_DELETE
                    | wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
            ),
            Ok(super::FileDispositionRequest::delete(
                super::FileDispositionTarget::Mutable,
                super::DeleteReadonlyRequest::Ignore
            ))
        );
        assert_eq!(
            super::decode_extended_disposition(wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE),
            Ok(super::FileDispositionRequest::keep(
                super::FileDispositionTarget::Mutable
            ))
        );
        for inactive in [
            wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS,
            wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK,
        ] {
            assert_eq!(
                super::decode_extended_disposition(inactive),
                Ok(super::FileDispositionRequest::keep(
                    super::FileDispositionTarget::Mutable
                ))
            );
        }
        assert_eq!(
            super::decode_extended_disposition(wdk_sys::FILE_DISPOSITION_ON_CLOSE),
            Ok(super::FileDispositionRequest::keep(
                super::FileDispositionTarget::CreateDeleteOnClose
            ))
        );
        assert_eq!(
            super::decode_extended_disposition(
                wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_ON_CLOSE
            ),
            Ok(super::FileDispositionRequest::delete(
                super::FileDispositionTarget::CreateDeleteOnClose,
                super::DeleteReadonlyRequest::Enforce
            ))
        );
        assert_eq!(
            super::decode_extended_disposition(
                wdk_sys::FILE_DISPOSITION_DELETE
                    | wdk_sys::FILE_DISPOSITION_ON_CLOSE
                    | wdk_sys::FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
            ),
            Ok(super::FileDispositionRequest::delete(
                super::FileDispositionTarget::CreateDeleteOnClose,
                super::DeleteReadonlyRequest::Ignore
            ))
        );
        for unsupported in [
            wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS,
            wdk_sys::FILE_DISPOSITION_DELETE | wdk_sys::FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK,
            wdk_sys::FILE_DISPOSITION_DELETE
                | wdk_sys::FILE_DISPOSITION_POSIX_SEMANTICS
                | wdk_sys::FILE_DISPOSITION_ON_CLOSE,
            0x20,
        ] {
            assert_eq!(
                super::decode_extended_disposition(unsupported),
                Err(DriverError::NotSupported)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when ON_CLOSE can target a handle not opened with FILE_DELETE_ON_CLOSE.
    #[test]
    fn on_close_disposition_requires_create_delete_on_close() {
        assert_eq!(
            super::FileDispositionTarget::Mutable.validate(CreateDeletion::Retain),
            Ok(())
        );
        assert_eq!(
            super::FileDispositionTarget::Mutable.validate(CreateDeletion::DeleteOnClose),
            Ok(())
        );
        assert_eq!(
            super::FileDispositionTarget::CreateDeleteOnClose.validate(CreateDeletion::Retain),
            Err(DriverError::NotSupported)
        );
        assert_eq!(
            super::FileDispositionTarget::CreateDeleteOnClose
                .validate(CreateDeletion::DeleteOnClose),
            Ok(())
        );
    }

    /// # Panics
    ///
    /// Panics when read-only deletion can bypass `FILE_WRITE_ATTRIBUTES`.
    #[test]
    fn readonly_deletion_override_requires_file_attributes_write_access() {
        let ordinary = wdk_sys::FILE_ATTRIBUTE_NORMAL;
        let readonly = wdk_sys::FILE_ATTRIBUTE_READONLY;

        assert_eq!(
            super::DeleteReadonlyPolicy::Enforce.validate_attributes(ordinary),
            Ok(())
        );
        assert_eq!(
            super::DeleteReadonlyPolicy::Ignore(FileAttributesWriteAccess::Denied)
                .validate_attributes(ordinary),
            Ok(())
        );
        assert_eq!(
            super::DeleteReadonlyPolicy::Enforce.validate_attributes(readonly),
            Err(DriverError::CannotDelete)
        );
        assert_eq!(
            super::DeleteReadonlyPolicy::Ignore(FileAttributesWriteAccess::Denied)
                .validate_attributes(readonly),
            Err(DriverError::CannotDelete)
        );
        assert_eq!(
            super::DeleteReadonlyPolicy::Ignore(FileAttributesWriteAccess::Granted)
                .validate_attributes(readonly),
            Ok(())
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn directory_wildcard_pattern_matches_long_windows_names() {
        let pattern = super::DirectoryWildcardPattern::from_utf16(&[
            u16::from(b'f'),
            super::UTF16_ASTERISK,
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'?'),
            u16::from(b't'),
        ]);
        assert!(pattern.is_ok());
        let Ok(pattern) = pattern else {
            return;
        };
        let matched = WindowsName::from_utf16(&[
            u16::from(b'f'),
            u16::from(b'i'),
            u16::from(b'l'),
            u16::from(b'e'),
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'x'),
            u16::from(b't'),
        ]);
        assert!(matched.is_ok());
        let Ok(matched) = matched else {
            return;
        };
        let rejected = WindowsName::from_utf16(&[
            u16::from(b'f'),
            u16::from(b'i'),
            u16::from(b'l'),
            u16::from(b'e'),
            u16::from(b'.'),
            u16::from(b't'),
            u16::from(b'x'),
        ]);
        assert!(rejected.is_ok());
        let Ok(rejected) = rejected else {
            return;
        };

        assert!(pattern.matches(&matched));
        assert!(!pattern.matches(&rejected));
    }

    /// # Panics
    ///
    /// Panics when Windows directory indices wrap instead of becoming the required zero sentinel.
    #[test]
    fn directory_file_index_uses_zero_beyond_the_u32_ordinal_domain() {
        assert_eq!(super::directory_file_index(0), 0);
        assert_eq!(super::directory_file_index(u64::from(u32::MAX)), u32::MAX);
        assert_eq!(super::directory_file_index(u64::from(u32::MAX) + 1), 0);
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn directory_wildcard_pattern_rejects_non_name_units() {
        assert_eq!(
            super::DirectoryWildcardPattern::from_utf16(&[
                u16::from(b'a'),
                super::UTF16_BACKSLASH,
                super::UTF16_ASTERISK,
            ]),
            Err(DriverError::from(ext4_core::Error::InvalidName))
        );
        assert_eq!(
            super::DirectoryWildcardPattern::from_utf16(&[0xD800, super::UTF16_ASTERISK]),
            Err(DriverError::from(ext4_core::Error::InvalidName))
        );
    }

    /// # Panics
    ///
    /// Panics when exhausted enumeration and explicit-search patterns expose the same status.
    #[test]
    fn directory_pattern_exhaustion_preserves_search_error_semantics() {
        assert_eq!(
            super::DirectoryPattern::All.exhausted_error(),
            DriverError::NoMoreFiles
        );

        let exact = WindowsName::from_utf16(&[u16::from(b'a')]);
        assert!(exact.is_ok());
        let Ok(exact) = exact else {
            return;
        };
        assert_eq!(
            super::DirectoryPattern::Exact(exact).exhausted_error(),
            DriverError::NoSuchFile
        );

        let wildcard = super::DirectoryWildcardPattern::from_utf16(&[super::UTF16_ASTERISK]);
        assert!(wildcard.is_ok());
        let Ok(wildcard) = wildcard else {
            return;
        };
        assert_eq!(
            super::DirectoryPattern::Wildcard(wildcard).exhausted_error(),
            DriverError::NoSuchFile
        );
    }

    /// # Panics
    ///
    /// Panics when a queue-owned UTF-16 pattern is not converted into the same wildcard domain
    /// used by the directory emitter.
    #[test]
    fn prepared_directory_pattern_uses_owned_utf16_units() {
        let mut units = crate::memory::DriverVec::new();
        assert!(
            units
                .try_extend_from_copy_slice(&[
                    u16::from(b'f'),
                    super::UTF16_ASTERISK,
                    u16::from(b'.'),
                    u16::from(b't'),
                    u16::from(b'x'),
                    u16::from(b't'),
                ])
                .is_ok()
        );
        let pattern = super::DirectoryPattern::from_prepared(
            &crate::irp::PreparedDirectoryPattern::Name(units),
        );
        assert!(matches!(pattern, Ok(super::DirectoryPattern::Wildcard(_))));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_target_path_rejects_empty_and_root_only_names() {
        assert_eq!(
            super::NonEmptyWindowsPath::from_utf16_path(&[]),
            Err(DriverError::InvalidParameter)
        );
        assert_eq!(
            super::NonEmptyWindowsPath::from_utf16_path(&[super::UTF16_BACKSLASH]),
            Err(DriverError::InvalidParameter)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_location_name_units_project_root_and_child_names() {
        let root_units: &[u16] = &[super::UTF16_BACKSLASH];
        let projected_root = super::opened_location_name_units(&OpenedLocation::Root);
        assert!(projected_root.is_ok());
        if let Ok(projected_root) = projected_root {
            assert_eq!(projected_root.as_slice(), root_units);
        }

        let name = Ext4Name::new(b"file");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let location = OpenedLocation::DirectoryEntry {
            parent: DirectoryNodeId::ROOT,
            name,
        };
        let child_units: &[u16] = &[
            u16::from(b'f'),
            u16::from(b'i'),
            u16::from(b'l'),
            u16::from(b'e'),
        ];
        let projected_child = super::opened_location_name_units(&location);
        assert!(projected_child.is_ok());
        if let Ok(projected_child) = projected_child {
            assert_eq!(projected_child.as_slice(), child_units);
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn opened_location_name_units_rejects_file_reference_location() {
        assert_eq!(
            super::opened_location_name_units(&OpenedLocation::FileReference),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_names_information_record_uses_name_only_layout() {
        let name = WindowsName::from_utf16(&[u16::from(b'a')]);
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let layout = super::DirectoryRecordLayout::new(DirectoryInformationClass::Names, &name);
        assert!(layout.is_ok());
        let Ok(layout) = layout else {
            return;
        };
        let mut buffer = [0_u8; 24];
        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };

        let packed = super::pack_directory_record(
            &mut buffer,
            0,
            DirectoryInformationClass::Names,
            7,
            &name,
            metadata,
            layout,
        );
        assert!(packed.is_ok());

        assert_eq!(le_u32(&buffer, super::DIRECTORY_NEXT_ENTRY_OFFSET), Some(0));
        assert_eq!(le_u32(&buffer, super::DIRECTORY_FILE_INDEX_OFFSET), Some(7));
        assert_eq!(
            le_u32(&buffer, super::NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET),
            Some(2)
        );
        let name_bytes = buffer.get(super::NAMES_INFORMATION_NAME_OFFSET..24);
        assert!(name_bytes.is_some());
        let Some(name_bytes) = name_bytes else {
            return;
        };
        let expected_name: &[u8] = &[b'a', 0];
        assert_eq!(name_bytes.get(..2), Some(expected_name));
    }

    /// # Panics
    ///
    /// Panics when an identity-bearing directory record loses its inode identity, reparse tag,
    /// short-name emptiness, or class-specific file-name offset.
    #[test]
    fn identity_directory_records_preserve_exact_windows_layouts() {
        let name = WindowsName::from_utf16(&[u16::from(b'a')]);
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let metadata = test_metadata(super::FileMetadataKind::Symlink);
        assert!(metadata.is_some());
        let Some(mut metadata) = metadata else {
            return;
        };
        metadata.file_index = 0x1234_5678;

        for (class, name_offset, file_id_offset, file_id_width, reparse_offset, short_offset) in [
            (
                DirectoryInformationClass::IdFull,
                super::ID_FULL_DIRECTORY_INFORMATION_NAME_OFFSET,
                super::ID_FULL_DIRECTORY_FILE_ID_OFFSET,
                8,
                None,
                None,
            ),
            (
                DirectoryInformationClass::IdBoth,
                super::ID_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
                super::ID_BOTH_DIRECTORY_FILE_ID_OFFSET,
                8,
                None,
                Some(super::ID_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            ),
            (
                DirectoryInformationClass::IdExtd,
                super::ID_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET,
                super::ID_EXTD_DIRECTORY_FILE_ID_OFFSET,
                16,
                Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
                None,
            ),
            (
                DirectoryInformationClass::IdExtdBoth,
                super::ID_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
                super::ID_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET,
                16,
                Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
                Some(super::ID_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            ),
            (
                DirectoryInformationClass::Id64Extd,
                super::ID_64_EXTD_DIRECTORY_INFORMATION_NAME_OFFSET,
                super::ID_64_EXTD_DIRECTORY_FILE_ID_OFFSET,
                8,
                Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
                None,
            ),
            (
                DirectoryInformationClass::Id64ExtdBoth,
                super::ID_64_EXTD_BOTH_DIRECTORY_INFORMATION_NAME_OFFSET,
                super::ID_64_EXTD_BOTH_DIRECTORY_FILE_ID_OFFSET,
                8,
                Some(super::DIRECTORY_REPARSE_TAG_OFFSET),
                Some(super::ID_64_EXTD_BOTH_DIRECTORY_SHORT_NAME_LENGTH_OFFSET),
            ),
        ] {
            let layout = super::DirectoryRecordLayout::new(class, &name);
            assert!(layout.is_ok());
            let Ok(layout) = layout else {
                continue;
            };
            assert_eq!(layout.name_offset, name_offset);
            let mut buffer = vec![0xFF_u8; layout.padded_size];
            assert!(
                super::pack_directory_record(&mut buffer, 0, class, 7, &name, metadata, layout,)
                    .is_ok()
            );
            assert_eq!(
                le_u64(&buffer, file_id_offset),
                Some(u64::from(metadata.file_index))
            );
            if file_id_width == 16 {
                assert_eq!(
                    buffer.get(file_id_offset + 8..file_id_offset + 16),
                    Some([0_u8; 8].as_slice())
                );
            }
            if let Some(offset) = reparse_offset {
                assert_eq!(
                    le_u32(&buffer, offset),
                    Some(wdk_sys::IO_REPARSE_TAG_SYMLINK)
                );
            }
            if let Some(offset) = short_offset {
                assert_eq!(byte_at(&buffer, offset), Some(0));
            }
            assert_eq!(
                buffer.get(name_offset..name_offset + 2),
                Some([b'a', 0].as_slice())
            );
        }
    }

    /// # Panics
    ///
    /// Panics when a large EOF or sparse allocation charge is truncated or recomputed by a Windows
    /// information packer.
    #[test]
    fn large_file_information_preserves_eof_and_inode_allocation_size() {
        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(mut metadata) = metadata else {
            return;
        };
        let eof = (1_u64 << 32) + 17;
        let allocation_size = 4096_u64;
        metadata.size = FileSize::from_bytes(eof);
        metadata.allocation_size = FileAllocationSize::from_bytes(allocation_size);

        let mut standard = [0_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
        assert!(super::pack_standard_information(&mut standard, metadata, false).is_ok());
        assert_eq!(
            standard[core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, DeletePending)],
            0
        );
        assert!(super::pack_standard_information(&mut standard, metadata, true).is_ok());
        assert_eq!(
            standard[core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, DeletePending)],
            1
        );
        assert_eq!(le_i64(&standard, 0), i64::try_from(allocation_size).ok());
        assert_eq!(le_i64(&standard, 8), i64::try_from(eof).ok());

        let mut network = [0_u8; core::mem::size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>()];
        assert!(super::pack_network_open_information(&mut network, metadata).is_ok());
        assert_eq!(le_i64(&network, 32), i64::try_from(allocation_size).ok());
        assert_eq!(le_i64(&network, 40), i64::try_from(eof).ok());

        let name = WindowsName::from_utf16(&[u16::from(b'a')]);
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let layout = super::DirectoryRecordLayout::new(DirectoryInformationClass::Directory, &name);
        assert!(layout.is_ok());
        let Ok(layout) = layout else {
            return;
        };
        let mut directory = [0_u8; 72];
        assert!(
            super::pack_directory_record(
                &mut directory,
                0,
                DirectoryInformationClass::Directory,
                1,
                &name,
                metadata,
                layout,
            )
            .is_ok()
        );
        assert_eq!(
            le_i64(&directory, super::DIRECTORY_ALLOCATION_SIZE_OFFSET),
            i64::try_from(allocation_size).ok()
        );
        assert_eq!(
            le_i64(&directory, super::DIRECTORY_END_OF_FILE_OFFSET),
            i64::try_from(eof).ok()
        );

        assert_eq!(
            super::file_size_from_large_integer(wdk_sys::LARGE_INTEGER {
                QuadPart: i64::try_from(eof).unwrap_or(i64::MAX),
            }),
            Ok(FileSize::from_bytes(eof))
        );
    }

    /// # Panics
    ///
    /// Panics when fixed-layout link information no longer preserves its Windows link lifecycle
    /// contract.
    #[test]
    fn standard_link_information_projects_link_lifecycle_and_node_kind() {
        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(mut metadata) = metadata else {
            return;
        };
        let three_links = Ext4LinkCount::new(3);
        assert!(three_links.is_ok());
        let Ok(three_links) = three_links else {
            return;
        };
        metadata.links_count = three_links;
        let size = core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>();

        let mut live = vec![0_u8; size];
        assert_eq!(
            super::pack_standard_link_information(&mut live, metadata, false),
            IrpCompletion::from_usize(size)
        );
        assert_eq!(
            le_u32(
                &live,
                core::mem::offset_of!(
                    wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                    NumberOfAccessibleLinks
                )
            ),
            Some(3)
        );
        assert_eq!(
            le_u32(
                &live,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
            ),
            Some(3)
        );
        assert_eq!(
            byte_at(
                &live,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, DeletePending)
            ),
            Some(0)
        );
        assert_eq!(
            byte_at(
                &live,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory)
            ),
            Some(0)
        );

        let mut pending = vec![0_u8; size];
        assert_eq!(
            super::pack_standard_link_information(&mut pending, metadata, true),
            IrpCompletion::from_usize(size)
        );
        assert_eq!(
            le_u32(
                &pending,
                core::mem::offset_of!(
                    wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                    NumberOfAccessibleLinks
                )
            ),
            Some(2)
        );
        assert_eq!(
            le_u32(
                &pending,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
            ),
            Some(3)
        );
        assert_eq!(
            byte_at(
                &pending,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, DeletePending)
            ),
            Some(1)
        );

        metadata.links_count = Ext4LinkCount::ONE;
        let mut single_pending = vec![0_u8; size];
        assert_eq!(
            super::pack_standard_link_information(&mut single_pending, metadata, true),
            IrpCompletion::from_usize(size)
        );
        assert_eq!(
            le_u32(
                &single_pending,
                core::mem::offset_of!(
                    wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                    NumberOfAccessibleLinks
                )
            ),
            Some(0)
        );
        assert_eq!(
            le_u32(
                &single_pending,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
            ),
            Some(1)
        );

        metadata.kind = super::FileMetadataKind::Directory;
        let five_links = Ext4LinkCount::new(5);
        assert!(five_links.is_ok());
        let Ok(five_links) = five_links else {
            return;
        };
        metadata.links_count = five_links;
        let mut directory = vec![0_u8; size];
        assert_eq!(
            super::pack_standard_link_information(&mut directory, metadata, false),
            IrpCompletion::from_usize(size)
        );
        assert_eq!(
            le_u32(
                &directory,
                core::mem::offset_of!(
                    wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                    NumberOfAccessibleLinks
                )
            ),
            Some(1)
        );
        assert_eq!(
            le_u32(
                &directory,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, TotalNumberOfLinks)
            ),
            Some(1)
        );
        assert_eq!(
            byte_at(
                &directory,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory)
            ),
            Some(1)
        );

        let mut standard = vec![0_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_INFORMATION>()];
        assert_eq!(
            super::pack_standard_information(&mut standard, metadata, false),
            IrpCompletion::from_usize(standard.len())
        );
        assert_eq!(
            le_u32(
                &standard,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_INFORMATION, NumberOfLinks)
            ),
            Some(1)
        );

        metadata.kind = super::FileMetadataKind::Symlink;
        metadata.links_count = three_links;
        let mut symlink = vec![0_u8; size];
        assert_eq!(
            super::pack_standard_link_information(&mut symlink, metadata, false),
            IrpCompletion::from_usize(size)
        );
        assert_eq!(
            le_u32(
                &symlink,
                core::mem::offset_of!(
                    wdk_sys::FILE_STANDARD_LINK_INFORMATION,
                    NumberOfAccessibleLinks
                )
            ),
            Some(3)
        );
        assert_eq!(
            byte_at(
                &symlink,
                core::mem::offset_of!(wdk_sys::FILE_STANDARD_LINK_INFORMATION, Directory)
            ),
            Some(0)
        );
    }

    /// # Panics
    ///
    /// Panics when undersized fixed link-information output accepts or mutates a partial record.
    #[test]
    fn standard_link_information_rejects_short_output() {
        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(metadata) = metadata else {
            return;
        };
        let mut output =
            vec![0xA5_u8; core::mem::size_of::<wdk_sys::FILE_STANDARD_LINK_INFORMATION>() - 1];
        assert_eq!(
            super::pack_standard_link_information(&mut output, metadata, false),
            Err(DriverError::BufferTooSmall)
        );
        assert!(output.iter().all(|byte| *byte == 0xA5));
    }

    /// # Panics
    ///
    /// Panics when FILE_LINKS_INFORMATION loses its header, alignment, parent ids, character
    /// counts, names, or exact completion length.
    #[test]
    fn hard_link_information_packs_complete_aligned_entries() {
        let links =
            windows_hard_links(&[(7, &[u16::from(b'a')]), (11, &[u16::from(b'b'), 0x00E9])]);
        assert!(links.is_some());
        let Some(links) = links else {
            return;
        };
        let mut output = vec![0xA5_u8; 56];

        let packed = super::pack_hard_link_information(&mut output, &links);
        assert_eq!(
            packed,
            Ok(super::HardLinkInformationPacking {
                information: 56,
                all_entries_returned: true,
            })
        );
        assert_eq!(
            le_u32(&output, super::HARD_LINKS_BYTES_NEEDED_OFFSET),
            Some(56)
        );
        assert_eq!(
            le_u32(&output, super::HARD_LINKS_ENTRIES_RETURNED_OFFSET),
            Some(2)
        );

        let first = super::HARD_LINKS_HEADER_SIZE;
        assert_eq!(
            le_u32(&output, first + super::HARD_LINK_ENTRY_NEXT_OFFSET),
            Some(24)
        );
        assert_eq!(
            le_u64(&output, first + super::HARD_LINK_ENTRY_PARENT_ID_OFFSET),
            Some(7)
        );
        assert_eq!(
            le_u32(&output, first + super::HARD_LINK_ENTRY_NAME_LENGTH_OFFSET),
            Some(1)
        );
        assert_eq!(
            output.get(
                first + super::HARD_LINK_ENTRY_NAME_OFFSET
                    ..first + super::HARD_LINK_ENTRY_NAME_OFFSET + 2
            ),
            Some([b'a', 0].as_slice())
        );
        let first_name_end = first + super::HARD_LINK_ENTRY_NAME_OFFSET + 2;
        let second = first + 24;
        assert_eq!(output.get(first_name_end..second), Some([0, 0].as_slice()));
        assert_eq!(
            le_u32(&output, second + super::HARD_LINK_ENTRY_NEXT_OFFSET),
            Some(0)
        );
        assert_eq!(
            le_u64(&output, second + super::HARD_LINK_ENTRY_PARENT_ID_OFFSET),
            Some(11)
        );
        assert_eq!(
            le_u32(&output, second + super::HARD_LINK_ENTRY_NAME_LENGTH_OFFSET),
            Some(2)
        );
        assert_eq!(
            output.get(
                second + super::HARD_LINK_ENTRY_NAME_OFFSET
                    ..second + super::HARD_LINK_ENTRY_NAME_OFFSET + 4
            ),
            Some([b'b', 0, 0xE9, 0].as_slice())
        );
        assert_eq!(
            packed.and_then(super::HardLinkInformationPacking::completion),
            IrpCompletion::from_usize(56)
        );
    }

    /// # Panics
    ///
    /// Panics when short hard-link output fails to report BytesNeeded, emits a partial record, or
    /// returns the wrong overflow information length.
    #[test]
    fn hard_link_information_returns_only_complete_entries_on_overflow() {
        let links =
            windows_hard_links(&[(7, &[u16::from(b'a')]), (11, &[u16::from(b'b'), 0x00E9])]);
        assert!(links.is_some());
        let Some(links) = links else {
            return;
        };

        let mut one_entry = vec![0xA5_u8; 30];
        let packed = super::pack_hard_link_information(&mut one_entry, &links);
        assert_eq!(
            packed,
            Ok(super::HardLinkInformationPacking {
                information: 30,
                all_entries_returned: false,
            })
        );
        assert_eq!(
            le_u32(&one_entry, super::HARD_LINKS_BYTES_NEEDED_OFFSET),
            Some(56)
        );
        assert_eq!(
            le_u32(&one_entry, super::HARD_LINKS_ENTRIES_RETURNED_OFFSET),
            Some(1)
        );
        assert_eq!(
            le_u32(
                &one_entry,
                super::HARD_LINKS_HEADER_SIZE + super::HARD_LINK_ENTRY_NEXT_OFFSET
            ),
            Some(0)
        );
        assert_eq!(
            packed.and_then(super::HardLinkInformationPacking::completion),
            IrpCompletion::buffer_overflow(30)
        );

        let mut header_only = [0xA5_u8; super::HARD_LINKS_HEADER_SIZE];
        let packed = super::pack_hard_link_information(&mut header_only, &links);
        assert_eq!(
            packed,
            Ok(super::HardLinkInformationPacking {
                information: super::HARD_LINKS_HEADER_SIZE,
                all_entries_returned: false,
            })
        );
        assert_eq!(
            le_u32(&header_only, super::HARD_LINKS_BYTES_NEEDED_OFFSET),
            Some(56)
        );
        assert_eq!(
            le_u32(&header_only, super::HARD_LINKS_ENTRIES_RETURNED_OFFSET),
            Some(0)
        );

        let mut truncated = [0xA5_u8; super::HARD_LINKS_HEADER_SIZE - 1];
        assert_eq!(
            super::pack_hard_link_information(&mut truncated, &links),
            Err(DriverError::InfoLengthMismatch)
        );
        assert!(truncated.iter().all(|byte| *byte == 0xA5));
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn reparse_metadata_controls_attribute_tag_and_file_attributes() {
        assert_eq!(super::reparse_tag(super::FileMetadataReparsePoint::None), 0);
        assert_eq!(
            super::reparse_tag(super::FileMetadataReparsePoint::SymbolicLink),
            wdk_sys::IO_REPARSE_TAG_SYMLINK
        );

        let metadata = test_metadata(super::FileMetadataKind::File);
        assert!(metadata.is_some());
        let Some(mut metadata) = metadata else {
            return;
        };
        metadata.reparse_point = super::FileMetadataReparsePoint::SymbolicLink;
        assert_ne!(
            super::file_attributes(metadata) & wdk_sys::FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_ex_flags_decode_collision_and_reject_unsupported_semantics() {
        let mut input = [0_u8; super::FILE_NAMESPACE_NAME_OFFSET + 2];
        assert!(put_le_u32(
            &mut input,
            super::FILE_NAMESPACE_FLAGS_OFFSET,
            wdk_sys::FILE_RENAME_IGNORE_READONLY_ATTRIBUTE,
        ));
        assert_eq!(
            super::RenameInformationFormat::Flags.target_collision(&input),
            Ok(ext4_core::RenameTargetCollision::Reject)
        );

        assert!(put_le_u32(
            &mut input,
            super::FILE_NAMESPACE_FLAGS_OFFSET,
            wdk_sys::FILE_RENAME_REPLACE_IF_EXISTS,
        ));
        assert_eq!(
            super::RenameInformationFormat::Flags.target_collision(&input),
            Ok(ext4_core::RenameTargetCollision::Replace)
        );

        assert!(put_le_u32(
            &mut input,
            super::FILE_NAMESPACE_FLAGS_OFFSET,
            wdk_sys::FILE_RENAME_POSIX_SEMANTICS,
        ));
        assert_eq!(
            super::RenameInformationFormat::Flags.target_collision(&input),
            Err(DriverError::NotSupported)
        );
    }

    /// # Panics
    ///
    /// Panics when hard-link legacy/extended collision semantics drift.
    #[test]
    fn hard_link_flags_decode_collision_and_reject_unimplemented_semantics() {
        let mut input = [0_u8; super::FILE_NAMESPACE_NAME_OFFSET + 2];
        assert_eq!(
            super::HardLinkInformationFormat::ReplaceIfExistsByte.target_collision(&input),
            Ok(super::HardLinkTargetCollision::Reject)
        );
        let Some(replace) = input.get_mut(super::FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET) else {
            return;
        };
        *replace = 1;
        assert_eq!(
            super::HardLinkInformationFormat::ReplaceIfExistsByte.target_collision(&input),
            Ok(super::HardLinkTargetCollision::Replace)
        );

        assert!(put_le_u32(
            &mut input,
            super::FILE_NAMESPACE_FLAGS_OFFSET,
            wdk_sys::FILE_LINK_REPLACE_IF_EXISTS,
        ));
        assert_eq!(
            super::HardLinkInformationFormat::Flags.target_collision(&input),
            Ok(super::HardLinkTargetCollision::Replace)
        );
        for unsupported in [
            wdk_sys::FILE_LINK_POSIX_SEMANTICS,
            wdk_sys::FILE_LINK_IGNORE_READONLY_ATTRIBUTE,
        ] {
            assert!(put_le_u32(
                &mut input,
                super::FILE_NAMESPACE_FLAGS_OFFSET,
                unsupported,
            ));
            assert_eq!(
                super::HardLinkInformationFormat::Flags.target_collision(&input),
                Err(DriverError::NotSupported)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when the Windows hard-link limit or archive transition drifts.
    #[test]
    fn hard_link_count_and_archive_boundaries_are_explicit() {
        let below_limit = Ext4LinkCount::new(1023);
        let at_limit = Ext4LinkCount::new(1024);
        assert!(below_limit.is_ok());
        assert!(at_limit.is_ok());
        if let (Ok(below_limit), Ok(at_limit)) = (below_limit, at_limit) {
            assert_eq!(
                super::HardLinkCountEffect::Increase.validate(below_limit),
                Ok(())
            );
            assert_eq!(
                super::HardLinkCountEffect::Increase.validate(at_limit),
                Err(DriverError::from(ext4_core::Error::TooManyLinks))
            );
            assert_eq!(
                super::HardLinkCountEffect::Preserve.validate(at_limit),
                Ok(())
            );
        }

        let overlay = super::hard_link_archive_overlay(0);
        assert!(overlay.is_ok());
        if let Ok(Some(overlay)) = overlay {
            assert_eq!(
                overlay.attributes().bits(),
                ext4_core::Ext4WindowsAttributes::ARCHIVE
            );
        }
        assert_eq!(
            super::hard_link_archive_overlay(ext4_core::Ext4WindowsAttributes::ARCHIVE),
            Ok(None)
        );
    }

    /// # Panics
    ///
    /// Panics when namespace path bases or relative-path rejection drift.
    #[test]
    fn namespace_target_distinguishes_opened_parent_from_volume_root() {
        let truncated = [0_u8; core::mem::size_of::<wdk_sys::FILE_LINK_INFORMATION>() - 1];
        assert_eq!(
            super::NamespaceTargetPath::decode(&truncated, DirectoryNodeId::ROOT),
            Err(DriverError::InfoLengthMismatch)
        );

        let relative = namespace_information_input(&[u16::from(b'a')]);
        assert!(relative.is_some());
        if let Some(relative) = relative {
            let decoded = super::NamespaceTargetPath::decode(&relative, DirectoryNodeId::ROOT);
            assert!(decoded.is_ok());
            if let Ok(decoded) = decoded {
                assert_eq!(
                    decoded.base(),
                    super::NamespaceTargetBase::OpenedParent(DirectoryNodeId::ROOT)
                );
                assert!(decoded.parents().is_empty());
            }
        }

        let absolute = namespace_information_input(&[
            super::UTF16_BACKSLASH,
            u16::from(b'd'),
            u16::from(b'i'),
            u16::from(b'r'),
            super::UTF16_BACKSLASH,
            u16::from(b'a'),
        ]);
        assert!(absolute.is_some());
        if let Some(absolute) = absolute {
            let decoded = super::NamespaceTargetPath::decode(&absolute, DirectoryNodeId::ROOT);
            assert!(decoded.is_ok());
            if let Ok(decoded) = decoded {
                assert_eq!(decoded.base(), super::NamespaceTargetBase::VolumeRoot);
                assert_eq!(decoded.parents().len(), 1);
            }
        }

        let relative_path = namespace_information_input(&[
            u16::from(b'd'),
            super::UTF16_BACKSLASH,
            u16::from(b'a'),
        ]);
        assert!(relative_path.is_some());
        if let Some(relative_path) = relative_path {
            assert_eq!(
                super::NamespaceTargetPath::decode(&relative_path, DirectoryNodeId::ROOT),
                Err(DriverError::InvalidParameter)
            );
        }
    }

    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn rename_root_directory_field_is_not_supported() {
        let mut input = [0_u8; super::FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET + 8];
        let Some(root_directory) = input.get_mut(
            super::FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET
                ..super::FILE_NAMESPACE_ROOT_DIRECTORY_OFFSET
                    + core::mem::size_of::<wdk_sys::HANDLE>(),
        ) else {
            return;
        };
        let Some(first_byte) = root_directory.get_mut(0) else {
            return;
        };
        *first_byte = 1;

        assert_eq!(
            super::reject_root_directory(&input),
            Err(DriverError::NotSupported)
        );
    }
    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the live stack fixtures satisfy ReceivedIrp's raw dispatch-pair contract"
    )]
    fn rename_replace_flag_decode_boundary_selects_replace_collision() {
        let mut input = [0_u8; core::mem::size_of::<wdk_sys::FILE_RENAME_INFORMATION>()];
        let Some(replace_flag) = input.get_mut(super::FILE_NAMESPACE_REPLACE_IF_EXISTS_OFFSET)
        else {
            return;
        };
        *replace_flag = 1;
        let name_length = input.get_mut(
            super::FILE_NAMESPACE_NAME_LENGTH_OFFSET
                ..super::FILE_NAMESPACE_NAME_LENGTH_OFFSET + core::mem::size_of::<u32>(),
        );
        assert!(
            name_length.is_some(),
            "test rename buffer contains the name length field"
        );
        let Some(name_length) = name_length else {
            return;
        };
        assert_eq!(
            crate::memory::copy_exact(name_length, &2_u32.to_le_bytes()),
            Ok(())
        );
        let name =
            input.get_mut(super::FILE_NAMESPACE_NAME_OFFSET..super::FILE_NAMESPACE_NAME_OFFSET + 2);
        assert!(
            name.is_some(),
            "test rename buffer contains the first UTF-16 code unit"
        );
        let Some(name) = name else {
            return;
        };
        assert_eq!(
            crate::memory::copy_exact(name, &u16::from(b'a').to_le_bytes()),
            Ok(())
        );

        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.SetFile = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10 {
            Length: u32::try_from(input.len()).unwrap_or(u32::MAX),
            __bindgen_padding_0: 0,
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileRenameInformation,
            FileObject: core::ptr::null_mut(),
            __bindgen_anon_1:
                wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_10__bindgen_ty_1::default(),
        };

        let mut irp = wdk_sys::IRP::default();
        irp.AssociatedIrp.SystemBuffer = input.as_mut_ptr().cast();
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::addr_of_mut!(stack);

        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut target = unsafe {
            // SAFETY: Both stack-local fixtures remain live through the active decode operation.
            ReceivedIrp::decode(
                core::ptr::addr_of_mut!(device),
                core::ptr::addr_of_mut!(irp),
            )
        };
        assert!(target.is_ok());
        if let Ok(target) = target.as_mut() {
            let parsed = target.with_active(|active| {
                let stack = active.current_stack()?.set_file()?;
                super::NamespaceTargetPath::decode(
                    active.buffered_input(stack.length())?.as_slice(),
                    ext4_core::DirectoryNodeId::ROOT,
                )
            });
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert_eq!(
                    super::RenameInformationFormat::ReplaceIfExistsByte.target_collision(&input),
                    Ok(ext4_core::RenameTargetCollision::Replace)
                );
                assert_eq!(
                    parsed.base(),
                    super::NamespaceTargetBase::OpenedParent(ext4_core::DirectoryNodeId::ROOT,)
                );
            }
        }
    }
}
