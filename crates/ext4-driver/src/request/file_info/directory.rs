//! Directory query planning, wildcard matching, and record packing.

use super::*;

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
