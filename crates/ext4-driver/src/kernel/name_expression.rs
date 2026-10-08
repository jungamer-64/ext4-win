//! Native Windows expression semantics with request-local failure ownership.

use crate::kernel::status::{DriverError, DriverResult};

/// Evaluates a case-sensitive expression without changing either input.
/// # Errors
/// Returns invalid-buffer-size for oversized counted strings or a native evaluation failure.
#[expect(
    unsafe_code,
    reason = "bounded immutable UTF-16 slices remain live through the native expression call"
)]
pub(crate) fn matches(expression: &[u16], name: &[u16]) -> DriverResult<bool> {
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
            RtlIsNameInExpression(&expression, &name, 0, core::ptr::null()) != 0
        })
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
    /// Both counted strings and the optional uppercase table remain live through evaluation.
    fn RtlIsNameInExpression(
        expression: *const wdk_sys::UNICODE_STRING,
        name: *const wdk_sys::UNICODE_STRING,
        ignore_case: u8,
        upcase: *const u16,
    ) -> u8;
}
