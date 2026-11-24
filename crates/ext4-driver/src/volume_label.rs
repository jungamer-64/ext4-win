//! Windows UTF-16 projection of the ext4 volume label.
//!
//! ext4 stores `s_volume_name` as bytes, which Linux tools present as UTF-8. Windows observes the
//! same label through the VPB and `FILE_FS_VOLUME_INFORMATION` as UTF-16, so both use this one
//! conversion. Bytes that are not UTF-8 are presented as U+FFFD; only a label no UTF-8 consumer
//! can present either loses information.

use crate::kernel::status::{DriverError, DriverResult};
use ext4_core::Ext4VolumeLabel;

/// Upper bound on UTF-16 units: every UTF-8 sequence and every U+FFFD substitution for an
/// invalid sequence spends at least as many label bytes as it yields UTF-16 units.
const MAX_UNITS: usize = Ext4VolumeLabel::MAX_BYTES;

/// UTF-16 unit presented for each maximal invalid UTF-8 sequence.
const REPLACEMENT: u16 = 0xFFFD;

/// A label as Windows presents it, holding at most [`Ext4VolumeLabel::MAX_BYTES`] UTF-16 units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsVolumeLabel {
    /// UTF-16 code units; only the first `len` are part of the label, the rest are zero.
    units: [u16; MAX_UNITS],
    /// Number of live units, bounded by `MAX_UNITS` at construction.
    len: u8,
}

impl WindowsVolumeLabel {
    /// Projects the on-disk label.
    /// # Errors
    /// Returns an internal invariant violation if the projection exceeds its proven bound.
    pub(crate) fn from_ext4(label: Ext4VolumeLabel) -> DriverResult<Self> {
        let mut units = [0_u16; MAX_UNITS];
        let mut projected = label.bytes().utf8_chunks().flat_map(|chunk| {
            chunk
                .valid()
                .encode_utf16()
                .chain((!chunk.invalid().is_empty()).then_some(REPLACEMENT))
        });
        let len = units
            .iter_mut()
            .zip(projected.by_ref())
            .map(|(slot, unit)| *slot = unit)
            .count();
        if projected.next().is_some() {
            return Err(DriverError::InternalInvariantViolation);
        }
        Ok(Self {
            units,
            len: u8::try_from(len).map_err(|_| DriverError::InternalInvariantViolation)?,
        })
    }

    /// Encodes a Windows-supplied label as UTF-8 for ext4.
    /// # Errors
    /// Returns invalid parameter for an unpaired surrogate, a UTF-8 encoding longer than the
    /// on-disk field, or NUL.
    pub(crate) fn to_ext4(units: impl IntoIterator<Item = u16>) -> DriverResult<Ext4VolumeLabel> {
        let mut bytes = [0_u8; Ext4VolumeLabel::MAX_BYTES];
        let mut len = 0_usize;
        for character in char::decode_utf16(units) {
            let character = character.map_err(|_| DriverError::InvalidParameter)?;
            let mut encoded = [0_u8; 4];
            let encoded = character.encode_utf8(&mut encoded).as_bytes();
            let end = len
                .checked_add(encoded.len())
                .ok_or(DriverError::InvalidParameter)?;
            let target = bytes
                .get_mut(len..end)
                .ok_or(DriverError::InvalidParameter)?;
            crate::memory::copy_exact(target, encoded)?;
            len = end;
        }
        let encoded = bytes
            .get(..len)
            .ok_or(DriverError::InternalInvariantViolation)?;
        Ext4VolumeLabel::new(encoded).map_err(|_| DriverError::InvalidParameter)
    }

    /// Returns the UTF-16 units of the label.
    pub(crate) fn units(&self) -> &[u16] {
        // Construction bounds `len` by the array length, so the range always exists.
        self.units.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Returns the fixed-capacity unit array, zero after the label, for native label fields.
    pub(crate) const fn padded_units(&self) -> &[u16; MAX_UNITS] {
        &self.units
    }

    /// Returns the label length in bytes, as Windows label records report it.
    pub(crate) fn byte_len(&self) -> u16 {
        // At most `MAX_UNITS` units, so the product cannot saturate.
        u16::from(self.len).saturating_mul(2)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    /// Encodes a string as UTF-16 units.
    fn utf16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// # Errors
    /// Returns invalid fixture labels or projection failure.
    /// # Panics
    /// Fails if UTF-8 labels lose characters, length, or round-trip identity.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture construction propagates; assertions check the projection contract"
    )]
    fn utf8_labels_project_to_utf16_and_back() -> DriverResult<()> {
        for text in ["", "EXT4", "ラベル", "Ä\u{1F600}", "0123456789abcdef"] {
            let label = Ext4VolumeLabel::new(text.as_bytes())?;
            let projected = WindowsVolumeLabel::from_ext4(label)?;
            let expected = utf16(text);
            assert_eq!(projected.units(), expected.as_slice());
            assert_eq!(
                projected.byte_len(),
                u16::try_from(expected.len().saturating_mul(2))
                    .map_err(|_| DriverError::InternalInvariantViolation)?
            );
            assert!(
                projected
                    .padded_units()
                    .iter()
                    .skip(expected.len())
                    .all(|unit| *unit == 0)
            );
            assert_eq!(
                WindowsVolumeLabel::to_ext4(projected.units().iter().copied())?,
                label
            );
        }
        Ok(())
    }

    /// # Errors
    /// Returns invalid fixture labels or projection failure.
    /// # Panics
    /// Fails if a non-UTF-8 label is not presented with replacement characters.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture construction propagates; assertions check the projection contract"
    )]
    fn invalid_utf8_is_presented_with_replacement_characters() -> DriverResult<()> {
        let label = Ext4VolumeLabel::new(&[b'A', 0xE9, b'B', 0xFF, 0xFE])?;
        assert_eq!(
            WindowsVolumeLabel::from_ext4(label)?.units(),
            utf16("A\u{FFFD}B\u{FFFD}\u{FFFD}").as_slice()
        );
        let filled = Ext4VolumeLabel::new(&[0xFF; Ext4VolumeLabel::MAX_BYTES])?;
        assert_eq!(
            WindowsVolumeLabel::from_ext4(filled)?.units(),
            [REPLACEMENT; Ext4VolumeLabel::MAX_BYTES].as_slice()
        );
        Ok(())
    }

    /// # Panics
    /// Fails if unencodable or oversized Windows labels reach ext4.
    #[test]
    fn windows_labels_reject_unencodable_or_oversized_text() {
        for units in [
            vec![0xD800],
            vec![0xDFFF, u16::from(b'A')],
            vec![0],
            utf16("ラベルラベル"),
            utf16("0123456789abcdefg"),
        ] {
            assert_eq!(
                WindowsVolumeLabel::to_ext4(units),
                Err(DriverError::InvalidParameter)
            );
        }
    }
}
