//! Cached, direct, and windowed file-data transfer protocols.

use super::*;

/// Maximum requestor data bytes copied through driver-owned memory at one time.
const MAX_DATA_TRANSFER_WINDOW_BYTES: usize = 65_536;

/// Data-stream authority selected before an operation can outlive current FILE_OBJECT decoding.
#[derive(Debug)]
pub(crate) enum RegularFileDataAuthority {
    /// Ordinary I/O remains authorized and serialized by its live handle lane.
    Handle,
    /// Paging I/O owns an FCB ledger lease independent of handle-local cleanup state.
    Paging(PagingStreamLease),
}

/// Captures the exact stream authority required by one regular-file data IRP.
/// # Errors
///
/// Returns an error when paging stream identity cannot be retained independently from the CCB.
pub(crate) fn prepare_regular_file_data_authority(
    mut request: PendingIrpLease<'_>,
    operations: &MountedVolumeAccess<'_>,
) -> DriverResult<RegularFileDataAuthority> {
    request.with_active(|active| match active.data_io_kind() {
        DataIoKind::Handle => Ok(RegularFileDataAuthority::Handle),
        DataIoKind::Paging => {
            let file_object = active.current_stack()?.file_object()?;
            operations
                .acquire_paging_stream_lease(file_object)
                .map(RegularFileDataAuthority::Paging)
        }
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

#[cfg(test)]
#[path = "tests/data_windows.rs"]
mod data_windows_tests;

#[cfg(test)]
#[path = "tests/data_ranges.rs"]
mod data_ranges_tests;

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

/// Executes regular file data reads.
/// # Errors
///
/// Returns an error when read stack decoding, output buffer mapping, or ext4 file reading fails.
pub(crate) fn read(
    request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
    authority: &RegularFileDataAuthority,
) -> DriverResult<IrpCompletion> {
    read_regular_file_by_transfer_mode(request, read, authority)
}

/// Executes regular file data writes.
/// # Errors
///
/// Returns an error when write stack decoding, input buffer mapping, or ext4 file mutation fails.
pub(crate) fn write(
    request: PendingIrpLease<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    authority: &RegularFileDataAuthority,
) -> DriverResult<WriteResolution> {
    write_regular_file_by_transfer_mode(request, mutation, authority)
}

/// One authorized raw-volume request ready for lower-device submission.
#[derive(Debug)]
pub(crate) struct PreparedRawVolumeTransfer {
    /// Direct-volume handle retained by the pending IRP.
    target: RawVolumeTarget,
    /// Whole-sector lower request bounded by the selected extent.
    request: StorageRequest,
    /// Position and completion payload validated before a write can take effect.
    publication: RawVolumeTransferPublication,
    /// Whether a successful write requires a following lower flush.
    write_through: bool,
}

impl PreparedRawVolumeTransfer {
    /// Consumes the prepared transfer into its operation-owned values.
    pub(crate) fn into_parts(
        self,
    ) -> (
        RawVolumeTarget,
        StorageRequest,
        RawVolumeTransferPublication,
        bool,
    ) {
        (
            self.target,
            self.request,
            self.publication,
            self.write_through,
        )
    }
}

/// Infallible successful raw-transfer publication prepared before lower I/O.
#[derive(Debug)]
pub(crate) struct RawVolumeTransferPublication {
    /// Synchronous cursor update, absent for asynchronous handles.
    position: PreparedFilePositionPublication,
    /// Exact successful status and byte count.
    completion: IrpCompletion,
}

impl RawVolumeTransferPublication {
    /// Publishes a successful transfer without allocation or offset conversion.
    pub(crate) fn publish(self) -> IrpCompletion {
        self.position.publish();
        self.completion
    }

    /// Retains the completed write count when its required flush fails.
    pub(crate) const fn committed_failure(&self, error: DriverError) -> IrpCompletion {
        self.completion.committed_failure(error)
    }
}

/// Normalized raw-volume position; append has no meaning for a device extent.
#[derive(Clone, Copy, Debug)]
enum RawVolumeStartingPoint {
    /// Partition-relative byte position supplied by the request.
    Absolute(FileOffset),
    /// Synchronous FILE_OBJECT position.
    CurrentPosition,
}

/// Returns whether a captured read/write targets the mounted volume rather than an ext4 node.
/// # Errors
///
/// Returns an error when the active FILE_OBJECT context pair is malformed.
pub(crate) fn is_direct_volume_data(mut request: PendingIrpLease<'_>) -> DriverResult<bool> {
    request.with_active(|active| {
        let opened = OpenedFileObject::decode(active.current_stack()?.file_object()?)?;
        Ok(matches!(opened, OpenedFileObject::Volume(_)))
    })
}

/// Validates and snapshots one direct-volume request before lower I/O.
/// # Errors
///
/// Returns an access, lifecycle, offset, sector-alignment, extent-bound, or allocation error.
pub(crate) fn prepare_raw_volume_transfer(
    mut request: PendingIrpLease<'_>,
    kind: RawVolumeOperationKind,
    access: &MountedVolumeAccess<'_>,
) -> DriverResult<Option<PreparedRawVolumeTransfer>> {
    let (length, starting_point, buffer_address) = match kind {
        RawVolumeOperationKind::Read => {
            let prepared = request.prepared_read()?;
            let starting_point = match prepared.stack().starting_point() {
                ReadStartingPoint::Absolute(start) => RawVolumeStartingPoint::Absolute(start),
                ReadStartingPoint::CurrentFilePosition => RawVolumeStartingPoint::CurrentPosition,
            };
            (
                prepared.stack().length().as_usize(),
                starting_point,
                prepared.output_address(),
            )
        }
        RawVolumeOperationKind::Write => {
            let prepared = request.prepared_write()?;
            let starting_point = match prepared.stack().starting_point() {
                WriteStartingPoint::Absolute(start) => RawVolumeStartingPoint::Absolute(start),
                WriteStartingPoint::CurrentFilePosition => RawVolumeStartingPoint::CurrentPosition,
                WriteStartingPoint::EndOfFile => return Err(DriverError::InvalidParameter),
            };
            (
                prepared.stack().length().as_usize(),
                starting_point,
                prepared.input_address(),
            )
        }
    };
    let (target, start, publication, write_through) = request.with_active(|active| {
        if active.data_io_kind() != DataIoKind::Handle {
            return Err(DriverError::InvalidParameter);
        }
        let file_object = active.current_stack()?.file_object()?;
        let opened = crate::state::OpenedVolume::decode(file_object)?;
        let start = match starting_point {
            RawVolumeStartingPoint::Absolute(start) => start,
            RawVolumeStartingPoint::CurrentPosition => opened.current_file_position()?,
        };
        let publication = RawVolumeTransferPublication {
            position: opened.prepare_current_file_position_update(start, length)?,
            completion: IrpCompletion::from_usize(length)?,
        };
        Ok::<_, DriverError>((
            opened.raw_target(),
            start,
            publication,
            file_object.as_ref().Flags & wdk_sys::FO_WRITE_THROUGH != 0,
        ))
    })?;
    let permit = access.authorize_raw_volume_io(target, kind)?;
    let address = match (length, buffer_address) {
        (0, None) => 0,
        (_, Some(address)) => address.as_ptr().addr(),
        (_, None) => return Err(DriverError::InternalInvariantViolation),
    };
    let offset = permit.validate_transfer(start, length, address)?;
    if length == 0 {
        return Ok(None);
    }
    let mut buffer = memory::try_repeated_vec(0_u8, length)?;
    if kind == RawVolumeOperationKind::Write {
        request.prepared_write()?.copy_window(0, &mut buffer)?;
    }
    let request = match kind {
        RawVolumeOperationKind::Read => StorageRequest::Read {
            target: StorageTarget::Filesystem,
            offset,
            buffer,
        },
        RawVolumeOperationKind::Write => StorageRequest::Write {
            target: StorageTarget::Filesystem,
            offset,
            buffer,
        },
    };
    Ok(Some(PreparedRawVolumeTransfer {
        target,
        request,
        publication,
        write_through,
    }))
}

/// Copies one successful raw read to the retained IRP mapping before cursor publication.
/// # Errors
///
/// Returns an error if the retained requestor mapping cannot receive the returned bytes.
pub(crate) fn finish_raw_volume_read(
    mut request: PendingIrpLease<'_>,
    publication: RawVolumeTransferPublication,
    buffer: &[u8],
) -> DriverResult<IrpCompletion> {
    request.prepared_read_mut()?.copy_window(0, buffer)?;
    Ok(publication.publish())
}

/// Attempts a normal cached read during the top-level dispatch callback.
///
/// `None` transfers the unchanged IRP to the actor-owned direct/paging path. `Some` is a terminal
/// completion and leaves the existing completion owner in charge.
/// # Errors
///
/// Returns a range, byte-lock, FILE_OBJECT, or exact Cache Manager failure.
pub(crate) fn dispatch_cached_read(
    target: &mut ActiveIrp<'_>,
) -> DriverResult<Option<IrpCompletion>> {
    if target.data_io_kind() == DataIoKind::Paging {
        return Ok(None);
    }
    if target.current_stack()?.file_object()?.as_ref().Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
        return Ok(None);
    }
    let stack = target.current_stack()?.read()?;
    let output_address = if stack.length().is_empty() {
        None
    } else {
        Some(target.data_output_address(stack.length())?)
    };
    let file_object = target.current_stack()?.file_object()?;
    let mut opened_file = OpenedRegularFile::decode(file_object)?;
    let range = ResolvedFileRange::new(
        resolve_read_start(&opened_file, DataIoKind::Handle, stack.starting_point())?,
        stack.length().as_usize(),
    )?;

    if matches!(
        opened_file.data_transfer_mode(),
        DataTransferMode::Direct(_)
    ) {
        opened_file
            .file_control_block()
            .coherency_flush_and_purge()?;
        return Ok(None);
    }
    if !stack.length().is_empty()
        && !opened_file.file_control_block().permits_byte_range_read(
            target.requestor_process()?,
            opened_file.file_object(),
            range.start(),
            range.length(),
            stack.key(),
        )?
    {
        return Err(DriverError::FileLockConflict);
    }

    let eof = u64::try_from(opened_file.file_control_block().stream_sizes()?.file_size())
        .map_err(|_| DriverError::InternalInvariantViolation)?;
    let available = eof.saturating_sub(range.start().bytes());
    let transferred = core::cmp::min(
        range.length(),
        usize::try_from(available).unwrap_or(usize::MAX),
    );
    opened_file
        .file_control_block()
        .initialize_cache_map(file_object)?;
    let offset = i64::try_from(range.start().bytes()).map_err(|_| DriverError::InvalidParameter)?;
    let transferred = opened_file.file_control_block().cached_read(
        file_object,
        offset,
        transferred,
        output_address,
    )?;
    opened_file.update_current_file_position(DataIoKind::Handle, range.start(), transferred)?;
    IrpCompletion::from_usize(transferred).map(Some)
}

/// Attempts one within-EOF cached write during the top-level dispatch callback.
///
/// Size-changing, append, write-through, paging, and direct-handle writes return `None` after any
/// required cache coherency transition so the existing actor/journal path owns the mutation.
/// # Errors
///
/// Returns an access, range, byte-lock, FILE_OBJECT, or exact Cache Manager failure.
pub(crate) fn dispatch_cached_write(
    target: &mut ActiveIrp<'_>,
) -> DriverResult<Option<IrpCompletion>> {
    if target.data_io_kind() == DataIoKind::Paging {
        return Ok(None);
    }
    if target.current_stack()?.file_object()?.as_ref().Flags & wdk_sys::FO_VOLUME_OPEN != 0 {
        return Ok(None);
    }
    let stack = target.current_stack()?.write()?;
    let input_address = if stack.length().is_empty() {
        None
    } else {
        Some(target.data_input_address(stack.length())?)
    };
    let file_object = target.current_stack()?.file_object()?;
    let mut opened_file = OpenedRegularFile::decode(file_object)?;
    let selected = select_write_start(
        opened_file.write_access(),
        DataIoKind::Handle,
        stack.starting_point(),
    )?;
    let start = match selected {
        SelectedWriteStart::Absolute(offset) => Some(offset),
        SelectedWriteStart::CurrentFilePosition => Some(opened_file.current_file_position()?),
        SelectedWriteStart::EndOfFile => None,
    };

    let direct = matches!(
        opened_file.data_transfer_mode(),
        DataTransferMode::Direct(_)
    );
    let write_through = file_object.as_ref().Flags & wdk_sys::FO_WRITE_THROUGH != 0;
    if direct || write_through || start.is_none() {
        opened_file
            .file_control_block()
            .coherency_flush_and_purge()?;
        return Ok(None);
    }
    let start = start.ok_or(DriverError::InternalInvariantViolation)?;
    let range = ResolvedFileRange::new(start, stack.length().as_usize())?;
    let eof = u64::try_from(opened_file.file_control_block().stream_sizes()?.file_size())
        .map_err(|_| DriverError::InternalInvariantViolation)?;
    let end = range.start().checked_add_len(range.length())?.bytes();
    if end > eof {
        opened_file
            .file_control_block()
            .coherency_flush_and_purge()?;
        return Ok(None);
    }
    if !stack.length().is_empty()
        && !opened_file.file_control_block().permits_byte_range_write(
            target.requestor_process()?,
            opened_file.file_object(),
            range.start(),
            range.length(),
            stack.key(),
        )?
    {
        return Err(DriverError::FileLockConflict);
    }

    opened_file
        .file_control_block()
        .initialize_cache_map(file_object)?;
    let offset = i64::try_from(range.start().bytes()).map_err(|_| DriverError::InvalidParameter)?;
    opened_file.file_control_block().cached_write(
        file_object,
        offset,
        input_address,
        range.length(),
    )?;
    opened_file.update_current_file_position(DataIoKind::Handle, range.start(), range.length())?;
    IrpCompletion::from_usize(range.length()).map(Some)
}

/// Flushes a node stream cache before the existing journal/lower-device flush operation.
/// # Errors
///
/// Returns a malformed FILE_OBJECT or exact Cache Manager flush status.
pub(crate) fn flush_cache_before_queued_flush(target: &mut ActiveIrp<'_>) -> DriverResult<()> {
    let file_object = target.current_stack()?.file_object()?;
    if file_object.has_no_file_system_contexts() {
        return Ok(());
    }
    match OpenedFileObject::decode(file_object)? {
        OpenedFileObject::Node(opened) => opened.file_control_block().flush_cache(),
        OpenedFileObject::Volume(_) => Ok(()),
    }
}

/// Releases a FILE_OBJECT's private cache map before queued cleanup closes handle admission.
/// # Errors
///
/// Returns a malformed FILE_OBJECT or exact Cache Manager exception status.
pub(crate) fn uninitialize_cache_before_cleanup(target: &mut ActiveIrp<'_>) -> DriverResult<()> {
    let file_object = target.current_stack()?.file_object()?;
    if file_object.has_no_file_system_contexts() {
        return Ok(());
    }
    match OpenedFileObject::decode(file_object)? {
        OpenedFileObject::Node(opened) => opened
            .file_control_block()
            .uninitialize_cache_map(file_object),
        OpenedFileObject::Volume(_) => Ok(()),
    }
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

/// Executes the actor-owned read path after top-level cache dispatch declined the request.
///
/// Paging I/O and coherent direct handles reach this path; cached normal reads are completed at
/// the Cache Manager boundary before queue admission.
/// # Errors
///
/// Returns an error from the retained direct/paging read contract.
fn read_regular_file_by_transfer_mode(
    request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
    authority: &RegularFileDataAuthority,
) -> DriverResult<IrpCompletion> {
    read_regular_file_direct(request, read, authority)
}

/// Executes the actor-owned journal mutation after top-level cache dispatch declined the write.
///
/// Paging writes, direct handles, append/extension, and write-through requests reach this path
/// only after the dispatch boundary established cache coherency when required.
/// # Errors
///
/// Returns an error from the retained journal mutation contract.
fn write_regular_file_by_transfer_mode(
    request: PendingIrpLease<'_>,
    mutation: &mut DriverMutationPass<'_, '_, '_>,
    authority: &RegularFileDataAuthority,
) -> DriverResult<WriteResolution> {
    write_regular_file_windowed(request, mutation, authority)
}

/// Reads a regular file through bounded driver-owned windows into the pending read IRP.
/// # Errors
///
/// Returns an error when the captured read contract, opened FILE_OBJECT, transfer alignment,
/// byte-range lock, or ext4 data stream is invalid.
fn read_regular_file_direct(
    mut request: PendingIrpLease<'_>,
    read: &mut impl CommittedReadPass,
    authority: &RegularFileDataAuthority,
) -> DriverResult<IrpCompletion> {
    let stack = request.prepared_read()?.stack();
    let output_address = request.prepared_read()?.output_address();
    let Some((file_id, range)) = request.with_active(|active| {
        let kind = active.data_io_kind();
        let file_object = active.current_stack()?.file_object()?;
        match authority {
            RegularFileDataAuthority::Handle => {
                if kind != DataIoKind::Handle {
                    return Err(DriverError::InternalInvariantViolation);
                }
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
                data_transfer_mode.validate_buffer(
                    output_address.ok_or(DriverError::InternalInvariantViolation)?,
                )?;
                if !opened_file.file_control_block().permits_byte_range_read(
                    active.requestor_process()?,
                    opened_file.file_object(),
                    range.start(),
                    range.length(),
                    stack.key(),
                )? {
                    return Err(DriverError::FileLockConflict);
                }
                Ok(Some((opened_file.id(), range)))
            }
            RegularFileDataAuthority::Paging(paging) => {
                if kind != DataIoKind::Paging {
                    return Err(DriverError::InternalInvariantViolation);
                }
                paging.validate_file_object(file_object)?;
                let SelectedReadStart::Absolute(start) =
                    select_read_start(kind, stack.starting_point())?
                else {
                    return Err(DriverError::InternalInvariantViolation);
                };
                let range = ResolvedFileRange::new(start, stack.length().as_usize())?;
                if stack.length().is_empty() {
                    return Ok(None);
                }
                let _output = output_address.ok_or(DriverError::InternalInvariantViolation)?;
                Ok(Some((paging.file(), range)))
            }
        }
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
    if let RegularFileDataAuthority::Handle = authority {
        request.with_active(|active| {
            if active.data_io_kind() != DataIoKind::Handle {
                return Err(DriverError::InternalInvariantViolation);
            }
            let file_object = active.current_stack()?.file_object()?;
            let mut opened_file = OpenedRegularFile::decode(file_object)?;
            opened_file.update_current_file_position(DataIoKind::Handle, range.start(), bytes_read)
        })?;
    }
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
    authority: &RegularFileDataAuthority,
) -> DriverResult<WriteResolution> {
    let stack = request.prepared_write()?.stack();
    let input_address = request.prepared_write()?.input_address();
    let (file_id, anchor, data_transfer_mode) = request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        let kind = active.data_io_kind();
        match authority {
            RegularFileDataAuthority::Handle => {
                if kind != DataIoKind::Handle {
                    return Err(DriverError::InternalInvariantViolation);
                }
                let opened_file = OpenedRegularFile::decode(file_object)?;
                let selected_start =
                    select_write_start(opened_file.write_access(), kind, stack.starting_point())?;
                let anchor =
                    selected_start.bind_current_position(|| opened_file.current_file_position())?;
                Ok::<_, DriverError>((
                    opened_file.id(),
                    anchor,
                    Some(opened_file.data_transfer_mode()),
                ))
            }
            RegularFileDataAuthority::Paging(paging) => {
                if kind != DataIoKind::Paging {
                    return Err(DriverError::InternalInvariantViolation);
                }
                paging.validate_file_object(file_object)?;
                let selected_start = select_write_start(
                    RegularFileWriteAccess::Denied,
                    kind,
                    stack.starting_point(),
                )?;
                let anchor = selected_start
                    .bind_current_position(|| Err(DriverError::InternalInvariantViolation))?;
                Ok((paging.file(), anchor, None))
            }
        }
    })?;

    let range = ResolvedFileRange::new(
        resolve_write_start(mutation, file_id, anchor)?,
        stack.length().as_usize(),
    )?;
    request.with_active(|active| {
        let file_object = active.current_stack()?.file_object()?;
        match authority {
            RegularFileDataAuthority::Handle => {
                if active.data_io_kind() != DataIoKind::Handle {
                    return Err(DriverError::InternalInvariantViolation);
                }
                let opened_file = OpenedRegularFile::decode(file_object)?;
                let data_transfer_mode =
                    data_transfer_mode.ok_or(DriverError::InternalInvariantViolation)?;
                data_transfer_mode.validate_range(range.start().bytes(), range.length())?;
                if stack.length().is_empty() {
                    return Ok(());
                }
                data_transfer_mode.validate_buffer(
                    input_address.ok_or(DriverError::InternalInvariantViolation)?,
                )?;
                if !opened_file.file_control_block().permits_byte_range_write(
                    active.requestor_process()?,
                    opened_file.file_object(),
                    range.start(),
                    range.length(),
                    stack.key(),
                )? {
                    return Err(DriverError::FileLockConflict);
                }
            }
            RegularFileDataAuthority::Paging(paging) => {
                if active.data_io_kind() != DataIoKind::Paging || data_transfer_mode.is_some() {
                    return Err(DriverError::InternalInvariantViolation);
                }
                paging.validate_file_object(file_object)?;
                if !stack.length().is_empty() {
                    let _input = input_address.ok_or(DriverError::InternalInvariantViolation)?;
                }
            }
        }
        Ok(())
    })?;
    if stack.length().is_empty() {
        if let RegularFileDataAuthority::Handle = authority {
            request.with_active(|active| {
                let file_object = active.current_stack()?.file_object()?;
                let mut opened_file = OpenedRegularFile::decode(file_object)?;
                opened_file.update_current_file_position(DataIoKind::Handle, range.start(), 0)
            })?;
        }
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
    let position = match authority {
        RegularFileDataAuthority::Handle => request.with_active(|active| {
            let file_object = active.current_stack()?.file_object()?;
            let opened_file = OpenedRegularFile::decode(file_object)?;
            opened_file.prepare_current_file_position_update(
                DataIoKind::Handle,
                range.start(),
                bytes_written,
            )
        })?,
        RegularFileDataAuthority::Paging(_) => PreparedFilePositionPublication::Unchanged,
    };
    Ok(WriteResolution::Mutation(PreparedWritePublication {
        completion: IrpCompletion::from_usize(bytes_written)?,
        position,
    }))
}
