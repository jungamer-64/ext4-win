//! Native Windows expression semantics with request-local failure ownership.

use crate::kernel::status::{DriverError, DriverResult};

use crate::namespace::{WindowsName, WindowsNameLookup};

/// Case policy selected by the native open flags and retained by directory handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameCase {
    /// Preserve every UTF-16 code unit during comparison.
    Exact,
    /// Compare using the current Windows uppercase table.
    Insensitive,
}

impl NameCase {
    /// Binds lookup to the same Windows uppercase table used by native expression matching.
    /// Namespace resolve passes execute at PASSIVE_LEVEL, including after storage suspension.
    pub(crate) const fn lookup(self, name: &WindowsName) -> WindowsNameLookup<'_> {
        match self {
            Self::Exact => WindowsNameLookup::Exact(name),
            Self::Insensitive => WindowsNameLookup::CaseInsensitive { name, upcase },
        }
    }
}

/// Borrows Windows' scalar mapping without owning or reproducing its Unicode tables.
#[expect(
    unsafe_code,
    reason = "namespace evaluation at PASSIVE_LEVEL supplies and receives one UTF-16 value"
)]
fn upcase(unit: u16) -> u16 {
    #[cfg(not(test))]
    unsafe {
        // SAFETY: The native mapping accepts every UTF-16 code unit by value.
        wdk_sys::ntddk::RtlUpcaseUnicodeChar(unit)
    }
    #[cfg(test)]
    unsafe {
        // SAFETY: ntdll exposes the same Windows scalar uppercase mapping to host tests.
        RtlUpcaseUnicodeChar(unit)
    }
}

/// Evaluates an expression without changing either input; insensitive expressions are uppercase.
/// # Errors
/// Returns invalid-buffer-size for oversized counted strings or a native evaluation failure.
#[expect(
    unsafe_code,
    reason = "bounded immutable UTF-16 slices remain live through the native expression call"
)]
pub(crate) fn matches(expression: &[u16], name: &[u16], ignore_case: bool) -> DriverResult<bool> {
    let expression_length = counted_length(expression)?;
    let name_length = counted_length(name)?;
    #[cfg(not(test))]
    {
        let mut matched = 0;
        let status = unsafe {
            // SAFETY: Lengths fit UNICODE_STRING, both inputs are immutable live allocations,
            // and matched is writable throughout the native call at the actor's PASSIVE_LEVEL.
            ext4win_name_expression(
                expression.as_ptr(),
                expression_length,
                name.as_ptr(),
                name_length,
                u8::from(ignore_case),
                &mut matched,
            )
        };
        if status < 0 {
            return Err(DriverError::NameExpressionFailure(status));
        }
        Ok(matched != 0)
    }
    #[cfg(test)]
    {
        let expression = wdk_sys::UNICODE_STRING {
            Length: expression_length,
            MaximumLength: expression_length,
            Buffer: expression.as_ptr().cast_mut(),
        };
        let name = wdk_sys::UNICODE_STRING {
            Length: name_length,
            MaximumLength: name_length,
            Buffer: name.as_ptr().cast_mut(),
        };
        Ok(unsafe {
            // SAFETY: ntdll evaluates counted immutable strings with the same expression contract.
            RtlIsNameInExpression(&expression, &name, u8::from(ignore_case), core::ptr::null()) != 0
        })
    }
}

/// Normalizes an owned insensitive expression once using the Windows uppercase table.
/// # Errors
/// Rejects strings that exceed the counted-string byte-length domain.
pub(crate) fn uppercase(units: &mut [u16]) -> DriverResult<()> {
    counted_length(units)?;
    for unit in units {
        *unit = upcase(*unit);
    }
    Ok(())
}

/// Canonicalizes counted EA bytes with Windows' native single-byte uppercase table.
#[expect(
    unsafe_code,
    reason = "each native scalar call accepts every byte and retains no storage"
)]
pub(crate) fn uppercase_ea(bytes: &mut [u8]) {
    for byte in bytes {
        let input = i8::from_ne_bytes([*byte]);
        #[cfg(not(test))]
        let output = unsafe {
            // SAFETY: RtlUpperChar accepts one arbitrary ANSI byte by value.
            wdk_sys::ntddk::RtlUpperChar(input)
        };
        #[cfg(test)]
        let output = unsafe {
            // SAFETY: ntdll supplies the host's native single-byte mapping by value.
            RtlUpperChar(input)
        };
        *byte = u8::from_ne_bytes(output.to_ne_bytes());
    }
}

/// Returns the UTF-16 byte length for UNICODE_STRING.
/// # Errors
/// Returns invalid-buffer-size when the native byte-length field cannot represent the slice.
fn counted_length(units: &[u16]) -> DriverResult<u16> {
    u16::try_from(core::mem::size_of_val(units)).map_err(|_| DriverError::InvalidBufferSize)
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "native FsRtl boundary catches its expected structured exceptions"
)]
unsafe extern "system" {
    /// Inputs are immutable bounded UTF-16 and output is valid writable BOOLEAN storage.
    fn ext4win_name_expression(
        expression: *const u16,
        expression_length: u16,
        name: *const u16,
        name_length: u16,
        ignore_case: u8,
        matched: *mut u8,
    ) -> wdk_sys::NTSTATUS;
}

#[cfg(test)]
#[expect(
    unsafe_code,
    reason = "host tests execute the native Windows expression oracle in ntdll"
)]
#[link(name = "ntdll")]
unsafe extern "system" {
    /// Native Windows single-byte uppercase mapping.
    fn RtlUpperChar(character: i8) -> i8;
    /// Native Windows uppercase mapping for one UTF-16 code unit.
    fn RtlUpcaseUnicodeChar(unit: u16) -> u16;
    /// Both counted strings and the optional uppercase table remain live through evaluation.
    fn RtlIsNameInExpression(
        expression: *const wdk_sys::UNICODE_STRING,
        name: *const wdk_sys::UNICODE_STRING,
        ignore_case: u8,
        upcase: *const u16,
    ) -> u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if lookup folding disagrees with native expression matching for literal Unicode names.
    #[test]
    fn lookup_and_expression_use_the_same_windows_unicode_table() {
        let result = (|| -> DriverResult<()> {
            // Literal uppercase expressions let ntdll supply expected results without using
            // the lookup callback to prepare the oracle's input or assuming a Unicode release.
            for (requested, candidate) in [
                ("É.TXT", "é.txt"),
                ("Σ.TXT", "σ.txt"),
                ("Σ.TXT", "ς.txt"),
                ("ЁЖ.TXT", "ёж.txt"),
                ("I.TXT", "ı.txt"),
                ("İ.TXT", "i.txt"),
                ("STRASSE.TXT", "straße.txt"),
                ("É.TXT", "e\u{301}.txt"),
            ] {
                let requested = requested.encode_utf16().collect::<alloc::vec::Vec<_>>();
                let candidate = candidate.encode_utf16().collect::<alloc::vec::Vec<_>>();
                let name = WindowsName::from_utf16(&requested)?;
                let WindowsNameLookup::CaseInsensitive { upcase, .. } =
                    NameCase::Insensitive.lookup(&name)
                else {
                    return Err(DriverError::InternalInvariantViolation);
                };
                let folded = requested
                    .iter()
                    .copied()
                    .map(upcase)
                    .collect::<alloc::vec::Vec<_>>();
                let folded_candidate = candidate
                    .iter()
                    .copied()
                    .map(upcase)
                    .collect::<alloc::vec::Vec<_>>();
                let native = matches(&requested, &candidate, true)?;
                assert_eq!(
                    folded == folded_candidate,
                    native,
                    "requested={requested:x?} candidate={candidate:x?}"
                );
            }
            Ok(())
        })();
        assert_eq!(result, Ok(()));
    }
}
