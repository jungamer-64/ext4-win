//! Directory query planning, wildcard matching, and record packing.

use super::*;

#[cfg(test)]
#[path = "tests/directory.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/directory_records.rs"]
mod record_tests;

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

/// Variable directory record layout for one emitted entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DirectoryRecordLayout {
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
    pub(super) fn new(class: DirectoryInformationClass, name: &WindowsName) -> DriverResult<Self> {
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

/// Capacity admission distinguishes a complete record from the first-call prefix contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryRecordExtent {
    /// All required fields and name bytes fit.
    Complete,
    /// Only this first-call prefix may be copied; its cursor remains unconsumed.
    Prefix(usize),
}
impl DirectoryRecordLayout {
    /// Reserves space before the caller requests additional inode metadata.
    /// # Errors
    /// Returns overflow or a first-call buffer smaller than the fixed fields.
    fn admit(
        self,
        start: usize,
        capacity: usize,
        first_record: bool,
        initial: bool,
    ) -> DriverResult<Option<DirectoryRecordExtent>> {
        if start
            .checked_add(self.unpadded_size)
            .ok_or(DriverError::InvalidParameter)?
            <= capacity
        {
            return Ok(Some(DirectoryRecordExtent::Complete));
        }
        if !first_record || !initial {
            return Ok(None);
        }
        if capacity < self.name_offset {
            return Err(DriverError::BufferTooSmall);
        }
        Ok(Some(DirectoryRecordExtent::Prefix(capacity)))
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
pub(super) const DIRECTORY_NEXT_ENTRY_OFFSET: usize = 0;
/// Offset of the common FileIndex field.
pub(super) const DIRECTORY_FILE_INDEX_OFFSET: usize = 4;
/// Offset of the common CreationTime field.
const DIRECTORY_CREATION_TIME_OFFSET: usize = 8;
/// Offset of the common LastAccessTime field.
const DIRECTORY_LAST_ACCESS_TIME_OFFSET: usize = 16;
/// Offset of the common LastWriteTime field.
const DIRECTORY_LAST_WRITE_TIME_OFFSET: usize = 24;
/// Offset of the common ChangeTime field.
const DIRECTORY_CHANGE_TIME_OFFSET: usize = 32;
/// Offset of the common EndOfFile field.
pub(super) const DIRECTORY_END_OF_FILE_OFFSET: usize = 40;
/// Offset of the common AllocationSize field.
pub(super) const DIRECTORY_ALLOCATION_SIZE_OFFSET: usize = 48;
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
/// Applies QueryDirectory cursor reset/index flags.
fn initialize_directory_cursor(cursor: &mut DirectoryCursor, position: DirectoryCursorPosition) {
    match position {
        DirectoryCursorPosition::Current => {}
        DirectoryCursorPosition::Restart => cursor.restart(),
        DirectoryCursorPosition::Index(index) => cursor.seek_ordinal(u64::from(index.as_u32())),
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
pub(super) fn pack_directory_record(
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
        metadata.file_attributes,
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
pub(super) fn clear_record(buffer: &mut [u8], start: usize, length: usize) -> DriverResult<()> {
    let record = mutable_bytes(buffer, start, length)?;
    record.fill(0);
    Ok(())
}

/// Writes UTF-16 code units as Windows little-endian bytes.
/// # Errors
///
/// Returns an error when the UTF-16 output range overflows or extends beyond `buffer`.
pub(super) fn write_utf16(buffer: &mut [u8], offset: usize, units: &[u16]) -> DriverResult<()> {
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
pub(super) const fn wire_offset(offset: usize) -> WireOffset {
    WireOffset::new(offset)
}

/// Builds a checked wire byte range from raw FILE_INFORMATION_CLASS fields.
/// # Errors
///
/// Returns an error when a file-information `offset + length` cannot be represented as a wire
/// range.
pub(super) fn wire_range(offset: usize, length: usize) -> DriverResult<WireRange> {
    WireRange::new(wire_offset(offset), WireByteLen::new(length))
}

/// Computes an absolute field offset from a record start.
/// # Errors
///
/// Returns an error when the raw directory-record `start + offset` overflows.
pub(super) fn field_offset(start: usize, offset: usize) -> DriverResult<usize> {
    start
        .checked_add(offset)
        .ok_or(DriverError::InvalidParameter)
}

/// Computes an absolute directory record field offset for wire output.
/// # Errors
///
/// Returns an error when the directory-record field offset cannot be represented as a wire offset.
pub(super) fn record_field_offset(start: usize, offset: usize) -> DriverResult<WireOffset> {
    field_offset(start, offset).map(wire_offset)
}

/// Returns the byte count for UTF-16 code units.
/// # Errors
///
/// Returns an error when a file-information UTF-16 code-unit count cannot be doubled without
/// overflow.
pub(super) fn utf16_byte_len(units: &[u16]) -> DriverResult<usize> {
    units
        .len()
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(DriverError::InvalidParameter)
}

/// Aligns a directory record size to an eight-byte boundary.
/// # Errors
///
/// Returns an error when the padding addition or aligned-size multiplication overflows.
pub(super) fn align_to_eight(value: usize) -> DriverResult<usize> {
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
pub(super) fn signed_i64(value: u64) -> DriverResult<i64> {
    i64::try_from(value).map_err(|_| DriverError::InvalidParameter)
}

/// Converts an ext4 timestamp to a Windows time QuadPart.
#[expect(
    unsafe_code,
    reason = "LARGE_INTEGER exposes its signed payload through the generated WDK union field"
)]
pub(super) fn windows_time_quad(timestamp: Ext4Timestamp) -> i64 {
    let time = windows_time(timestamp);
    unsafe {
        // SAFETY: `QuadPart` is the active LARGE_INTEGER representation used
        // by this driver for Windows time values.
        time.QuadPart
    }
}
/// Packs names without requesting any Windows metadata.
/// # Errors
/// Returns a name-length or output-range error.
fn pack_name_record(
    buffer: &mut [u8],
    start: usize,
    file_index: u32,
    name: &WindowsName,
) -> DriverResult<()> {
    let layout = DirectoryRecordLayout::new(DirectoryInformationClass::Names, name)?;
    clear_record(buffer, start, layout.unpadded_size)?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, DIRECTORY_FILE_INDEX_OFFSET)?,
        file_index,
    )?;
    LittleEndianOutput::new(buffer).write_u32(
        record_field_offset(start, NAMES_INFORMATION_FILE_NAME_LENGTH_OFFSET)?,
        u32::try_from(utf16_byte_len(name.utf16())?).map_err(|_| DriverError::InvalidParameter)?,
    )?;
    write_utf16(
        buffer,
        field_offset(start, layout.name_offset)?,
        name.utf16(),
    )
}

/// Packing progress belongs to the admitted request, including across metadata I/O.
#[derive(Debug)]
pub(crate) struct DirectoryQuery {
    /// Retains the handle-selected expression independently of later IRP captures.
    pattern: crate::memory::DriverSharedLease<DirectoryPattern>,
    /// Requested Windows wire layout.
    class: DirectoryInformationClass,
    /// Caller capacity retained through deferred copy.
    length: IrpBufferLength,
    /// Stops packing immediately after the first match for a single-entry request.
    emission: DirectoryEntryEmission,
    /// No previous enumeration outcome has been published on this handle.
    initial: bool,
    /// Private progress; publishing it requires successful output copy.
    cursor: DirectoryCursor,
    /// One request-sized output allocation retained across lower reads.
    packed: DriverVec<u8>,
    /// Aligned start of the next complete record.
    written: usize,
    /// Valid output prefix, excluding final alignment padding.
    information: usize,
    /// Last complete record whose forward link may be updated.
    previous: Option<usize>,
}

/// A matching record whose output space has been reserved before metadata is read.
#[derive(Debug)]
pub(crate) struct DirectoryRecord {
    /// Validated identity and opaque continuation for this reserved record.
    entry: ext4_core::ScannedDirectoryEntry,
    /// Windows-visible name retained while metadata is loaded.
    name: WindowsName,
    /// Capacity-checked layout selected before metadata I/O.
    layout: DirectoryRecordLayout,
    /// Partial first record reports overflow and does not consume the entry.
    extent: DirectoryRecordExtent,
}
impl DirectoryRecord {
    /// Identity already validated by the directory engine, used only for additional metadata.
    pub(crate) fn node(&self) -> NodeId {
        *self.entry.entry().node()
    }
}

/// Filtering either consumes a skipped name, reserves one record, or leaves it for the next call.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the reserved record carries an inline cursor without allocating on each name match"
)]
pub(crate) enum DirectorySelection {
    /// The name does not match or cannot be represented on Windows.
    Skip,
    /// Output space exists; metadata may now be requested.
    Record(DirectoryRecord),
    /// No further complete record fits; the entry remains unpublished.
    Full,
}

impl DirectoryQuery {
    /// Captures the initial expression at admission; output and cursor remain private until copy.
    /// # Errors
    /// Returns invalid handle/pattern, allocation, or shared-lease exhaustion errors.
    pub(crate) fn prepare(
        mut request: PendingIrpLease<'_>,
    ) -> DriverResult<(Self, DirectoryNodeId)> {
        let existing = request.with_active(|active| {
            let opened = OpenedDirectory::decode(active.current_stack()?.file_object()?)?;
            opened.search().expression()
        })?;
        let prepared = request.prepared_query_directory()?;
        let stack = prepared.stack();
        let pattern = if existing.is_none() {
            Some(DirectoryPattern::from_prepared(prepared.pattern())?)
        } else {
            None
        };
        let (pattern, directory, cursor, initial) = request.with_active(|active| {
            let opened = OpenedDirectory::decode(active.current_stack()?.file_object()?)?;
            let directory = opened.id();
            let search = opened.search();
            let initial = !search.completed();
            let pattern = match existing {
                Some(pattern) => pattern,
                None => search
                    .capture_pattern(pattern.ok_or(DriverError::InternalInvariantViolation)?)?,
            };
            let mut cursor = search.cursor();
            if initial {
                cursor.restart();
            } else {
                initialize_directory_cursor(&mut cursor, stack.cursor_position());
            }
            Ok::<_, DriverError>((pattern, directory, cursor, initial))
        })?;
        Ok((
            Self {
                pattern,
                class: stack.information_class(),
                length: stack.length(),
                emission: stack.entry_emission(),
                initial,
                cursor,
                packed: DriverVec::try_repeated_copy(0, stack.length().as_usize())?,
                written: 0,
                information: 0,
                previous: None,
            },
            directory,
        ))
    }

    /// Starts a fresh core walk in this request's epoch.
    pub(crate) const fn cursor(&self) -> DirectoryCursor {
        self.cursor
    }
    /// Names-only wire records require no timestamps, attributes, or reparse metadata.
    pub(crate) const fn needs_metadata(&self) -> bool {
        !matches!(self.class, DirectoryInformationClass::Names)
    }

    /// Name filtering and capacity decisions precede any metadata request.
    /// # Errors
    /// Returns record-size overflow or an output buffer smaller than the fixed header.
    pub(crate) fn select(
        &mut self,
        entry: ext4_core::ScannedDirectoryEntry,
    ) -> DriverResult<DirectorySelection> {
        let Ok(name) = WindowsName::from_ext4(entry.entry().name()) else {
            self.cursor = *entry.next_cursor();
            return Ok(DirectorySelection::Skip);
        };
        if !self.pattern.get().matches(&name) {
            self.cursor = *entry.next_cursor();
            return Ok(DirectorySelection::Skip);
        }
        let layout = DirectoryRecordLayout::new(self.class, &name)?;
        let Some(extent) = layout.admit(
            self.written,
            self.packed.len(),
            self.previous.is_none(),
            self.initial,
        )?
        else {
            return Ok(DirectorySelection::Full);
        };
        Ok(DirectorySelection::Record(DirectoryRecord {
            entry,
            name,
            layout,
            extent,
        }))
    }

    /// Serializes a reserved name without reading Windows metadata.
    /// # Errors
    /// Returns record layout or output range failures.
    pub(crate) fn append_name(&mut self, record: DirectoryRecord) -> DriverResult<bool> {
        self.append(record, None)
    }
    /// Serializes a reserved record using metadata from the retained request epoch.
    /// # Errors
    /// Returns record layout or metadata serialization failures.
    pub(crate) fn append_metadata(
        &mut self,
        record: DirectoryRecord,
        metadata: NodeMetadataSnapshot,
    ) -> DriverResult<bool> {
        self.append(record, Some(metadata.into()))
    }

    /// Commits one packed record locally. A partial first record preserves its original cursor.
    /// # Errors
    /// Returns allocation, arithmetic, or output serialization errors before publication.
    fn append(
        &mut self,
        record: DirectoryRecord,
        metadata: Option<FileMetadata>,
    ) -> DriverResult<bool> {
        let file_index = directory_file_index(record.entry.ordinal());
        let pack = |buffer: &mut [u8], start| match metadata {
            Some(metadata) => pack_directory_record(
                buffer,
                start,
                self.class,
                file_index,
                &record.name,
                metadata,
                record.layout,
            ),
            None => pack_name_record(buffer, start, file_index, &record.name),
        };
        if let DirectoryRecordExtent::Prefix(length) = record.extent {
            let mut buffer = DriverVec::try_repeated_copy(0, record.layout.unpadded_size)?;
            pack(buffer.as_mut_slice(), 0)?;
            memory::copy_exact(
                self.packed.as_mut_slice(),
                buffer
                    .as_slice()
                    .get(..length)
                    .ok_or(DriverError::InternalInvariantViolation)?,
            )?;
            self.information = length;
            return Ok(true);
        }
        pack(self.packed.as_mut_slice(), self.written)?;
        if let Some(previous) = self.previous {
            let offset = self
                .written
                .checked_sub(previous)
                .ok_or(DriverError::InvalidParameter)?;
            LittleEndianOutput::new(self.packed.as_mut_slice()).write_u32(
                record_field_offset(previous, DIRECTORY_NEXT_ENTRY_OFFSET)?,
                u32::try_from(offset).map_err(|_| DriverError::InvalidParameter)?,
            )?;
        }
        self.previous = Some(self.written);
        self.information = self
            .written
            .checked_add(record.layout.unpadded_size)
            .ok_or(DriverError::InvalidParameter)?;
        self.written = self
            .written
            .checked_add(record.layout.padded_size)
            .ok_or(DriverError::InvalidParameter)?;
        self.cursor = *record.entry.next_cursor();
        Ok(matches!(self.emission, DirectoryEntryEmission::Single))
    }

    /// Copies first, then publishes the opaque cursor while the handle lane remains exclusive.
    /// # Errors
    /// Returns copy failure without publishing progress, or invalid handle/output errors.
    pub(crate) fn finish(
        self,
        mut request: PendingIrpLease<'_>,
        exhausted: Option<DirectoryCursor>,
    ) -> DriverResult<IrpCompletion> {
        let partial = self.information != 0 && self.previous.is_none();
        let completion = if partial {
            IrpCompletion::buffer_overflow(self.information)?
        } else if self.information != 0 || exhausted.is_none() {
            IrpCompletion::from_usize(self.information)?
        } else {
            IrpCompletion::from_error(if self.initial {
                DriverError::NoSuchFile
            } else {
                DriverError::NoMoreFiles
            })
        };
        request.with_active(|active| {
            let cursor = exhausted.unwrap_or(self.cursor);
            if self.information == 0 {
                let opened = OpenedDirectory::decode(active.current_stack()?.file_object()?)?;
                return opened.search().publish_after_copy(cursor, || Ok(()));
            }
            let (mut output, file_object) =
                active.requestor_output_with_file_object(self.length)?;
            let opened = OpenedDirectory::decode(file_object)?;
            opened.search().publish_after_copy(cursor, || {
                output.copy_from(
                    0,
                    self.packed
                        .as_slice()
                        .get(..self.information)
                        .ok_or(DriverError::InternalInvariantViolation)?,
                )
            })
        })?;
        Ok(completion)
    }
}
