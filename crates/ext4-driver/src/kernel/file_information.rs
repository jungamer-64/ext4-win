//! Shared Windows fixed-record encoding for IRP and Fast I/O projections.
//!
//! Every successful record includes initialized padding. Callers supply one committed metadata
//! observation; physical allocation charge remains distinct from the logical section bound.

use crate::{
    kernel::status::{DriverError, DriverResult},
    wire::{LittleEndianOutput, WireOffset},
};

/// Windows timestamps and attributes, independent of the request's transport.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BasicInformation {
    /// Creation, access, write and change timestamps in Windows system-time units.
    pub(crate) times: [i64; 4],
    /// Complete projected file-attribute bits.
    pub(crate) attributes: u32,
}

/// Windows namespace and storage observation used by standard information queries.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StandardInformation {
    /// Physical storage charge in bytes.
    pub(crate) allocation: i64,
    /// Committed logical EOF in bytes.
    pub(crate) eof: i64,
    /// All namespace links, including a link selected for deferred deletion.
    pub(crate) links: u32,
    /// Ledger-owned deferred deletion observation.
    pub(crate) delete_pending: bool,
    /// Whether the inode is a directory.
    pub(crate) directory: bool,
}

/// Initializes the entire fixed record before writing fields, including ABI padding.
/// # Errors
/// Returns buffer-too-small without changing an undersized output.
fn record(output: &mut [u8], size: usize) -> DriverResult<LittleEndianOutput<'_>> {
    let bytes = output.get_mut(..size).ok_or(DriverError::BufferTooSmall)?;
    bytes.fill(0);
    Ok(LittleEndianOutput::new(bytes))
}

impl BasicInformation {
    /// Encodes the basic-information wire record with initialized padding.
    /// # Errors
    /// Returns buffer-too-small before changing an undersized output.
    pub(crate) fn write_basic(self, output: &mut [u8]) -> DriverResult<usize> {
        let size = size_of::<wdk_sys::FILE_BASIC_INFORMATION>();
        let mut writer = record(output, size)?;
        let offsets = [
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, CreationTime),
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastAccessTime),
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, LastWriteTime),
            core::mem::offset_of!(wdk_sys::FILE_BASIC_INFORMATION, ChangeTime),
        ];
        for (offset, time) in offsets.into_iter().zip(self.times) {
            writer.write_i64(WireOffset::new(offset), time)?;
        }
        writer.write_u32(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_BASIC_INFORMATION,
                FileAttributes
            )),
            self.attributes,
        )?;
        Ok(size)
    }

    /// Encodes network-open information using the same basic metadata projection.
    /// # Errors
    /// Returns buffer-too-small before changing an undersized output.
    pub(crate) fn write_network(
        self,
        output: &mut [u8],
        allocation: i64,
        eof: i64,
    ) -> DriverResult<usize> {
        let size = size_of::<wdk_sys::FILE_NETWORK_OPEN_INFORMATION>();
        let mut writer = record(output, size)?;
        let offsets = [
            core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, CreationTime),
            core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, LastAccessTime),
            core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, LastWriteTime),
            core::mem::offset_of!(wdk_sys::FILE_NETWORK_OPEN_INFORMATION, ChangeTime),
        ];
        for (offset, time) in offsets.into_iter().zip(self.times) {
            writer.write_i64(WireOffset::new(offset), time)?;
        }
        writer.write_i64(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
                AllocationSize
            )),
            allocation,
        )?;
        writer.write_i64(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
                EndOfFile
            )),
            eof,
        )?;
        writer.write_u32(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_NETWORK_OPEN_INFORMATION,
                FileAttributes
            )),
            self.attributes,
        )?;
        Ok(size)
    }
}

impl StandardInformation {
    /// Encodes standard information without treating sparse holes as allocated storage.
    /// # Errors
    /// Returns buffer-too-small before changing an undersized output.
    pub(crate) fn write(self, output: &mut [u8]) -> DriverResult<usize> {
        let size = size_of::<wdk_sys::FILE_STANDARD_INFORMATION>();
        let mut writer = record(output, size)?;
        writer.write_i64(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_INFORMATION,
                AllocationSize
            )),
            self.allocation,
        )?;
        writer.write_i64(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_INFORMATION,
                EndOfFile
            )),
            self.eof,
        )?;
        writer.write_u32(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_INFORMATION,
                NumberOfLinks
            )),
            self.links,
        )?;
        writer.write_u8(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_INFORMATION,
                DeletePending
            )),
            u8::from(self.delete_pending),
        )?;
        writer.write_u8(
            WireOffset::new(core::mem::offset_of!(
                wdk_sys::FILE_STANDARD_INFORMATION,
                Directory
            )),
            u8::from(self.directory),
        )?;
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// # Errors
    /// Returns unexpected encoder failure.
    /// # Panics
    /// Fails if successful records retain padding or undersized output is partially changed.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fallible encoding and assertions check the wire publication contract"
    )]
    fn fixed_records_initialize_padding_and_reject_before_writing() -> DriverResult<()> {
        let basic = BasicInformation {
            times: [1, 2, 3, 4],
            attributes: 5,
        };
        let mut bytes = [0xaa; size_of::<wdk_sys::FILE_BASIC_INFORMATION>()];
        basic.write_basic(&mut bytes)?;
        assert_eq!(bytes.get(36..), Some([0_u8; 4].as_slice()));
        let mut short = [0xaa; 1];
        assert_eq!(
            basic.write_basic(&mut short),
            Err(DriverError::BufferTooSmall)
        );
        assert_eq!(short, [0xaa]);
        Ok(())
    }
}
