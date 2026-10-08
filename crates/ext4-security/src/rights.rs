//! Specific rights controlled by one POSIX class and request composition independent of tokens.

/// Read data/list and extended attributes, excluding shared Windows standard rights.
pub const READ_RIGHTS: u32 = 0x0001 | 0x0008;
/// Write/append data, extended attributes and mutable file attributes.
pub const WRITE_RIGHTS: u32 = 0x0002 | 0x0004 | 0x0010 | 0x0100;
/// Execute file/search directory.
pub const EXECUTE_RIGHTS: u32 = 0x0020;
/// Rights whose presence is selected exclusively by the inode's POSIX permission class.
pub const CONTROLLED_RIGHTS: u32 = READ_RIGHTS | WRITE_RIGHTS | EXECUTE_RIGHTS;
/// Read security/read attributes/wait rights available independently of POSIX rwx.
pub const BASE_RIGHTS: u32 = 0x0002_0000 | 0x0010_0000 | 0x0080;
/// Native request flag expanded by normal single-right checks, never native maximum scanning.
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
/// Maximum exploration excludes ownership takeover, SACL and namespace deletion rights.
pub const MAXIMUM_CANDIDATES: [u32; 11] =
    [1, 8, 2, 4, 16, 256, 32, 0x20000, 0x100000, 128, 0x40000];

/// Projects a validated three-bit POSIX permission class onto disjoint specific rights.
pub const fn mode_rights(bits: u16) -> u32 {
    let mut mask = 0;
    if bits & 4 != 0 {
        mask |= READ_RIGHTS;
    }
    if bits & 2 != 0 {
        mask |= WRITE_RIGHTS;
    }
    if bits & 1 != 0 {
        mask |= EXECUTE_RIGHTS;
    }
    mask
}

/// Recovers a POSIX class from exactly one representable specific-right combination.
/// # Errors
/// Returns an error for partial permission bundles or unrelated rights.
pub fn rights_mode(mask: u32) -> Result<u16, crate::Error> {
    (0..8)
        .find(|bits| mode_rights(*bits) == mask)
        .ok_or(crate::Error::UnrepresentableDescriptor)
}

/// Normal native check outcome; execution failures remain in the outer `Result`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDecision {
    /// Requested rights are granted.
    Granted(u32),
    /// Expected native access refusal, retaining the native status.
    Denied(i32),
}

/// Composes explicit requirements and maximum exploration without changing caller authority.
///
/// Class-priority denies require ordered ordinary checks: a native maximum scan unions denials
/// from every matching class and would remove owner rights when the owner also belongs to the
/// inode group. `check` must never receive MAXIMUM_ALLOWED.
/// `check` must evaluate every invocation against the same locked subject and descriptor. It
/// owns native privilege storage; successful composition does not itself publish handle rights.
/// `previous` is already-authorized access, or zero for forced user-mode evaluation.
/// # Errors
/// Propagates native execution failures; ordinary candidate denial simply omits that right.
pub fn evaluate_access<E>(
    desired: u32,
    previous: u32,
    mut check: impl FnMut(u32, u32) -> Result<AccessDecision, E>,
) -> Result<AccessDecision, E> {
    let explicit = desired & !MAXIMUM_ALLOWED;
    let mut granted = previous;
    if explicit != 0 {
        match check(explicit, previous)? {
            AccessDecision::Granted(mask) => granted |= mask & explicit,
            denied @ AccessDecision::Denied(_) => return Ok(denied),
        }
    }
    if desired & MAXIMUM_ALLOWED != 0 {
        for right in MAXIMUM_CANDIDATES {
            if granted & right == 0 && matches!(check(right, 0)?, AccessDecision::Granted(_)) {
                granted |= right;
            }
        }
        if granted == 0 {
            return Ok(AccessDecision::Denied(-1_073_741_790));
        }
    }
    Ok(AccessDecision::Granted(granted))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Explicit failures cannot be converted to a partial successful maximum grant.
    /// # Panics
    /// Panics if the access composition contract is violated.
    #[test]
    fn explicit_right_is_mandatory() {
        let result = evaluate_access::<()>(MAXIMUM_ALLOWED | 2, 0, |_, _| {
            Ok(AccessDecision::Denied(-7))
        });
        assert_eq!(result, Ok(AccessDecision::Denied(-7)));
    }
    /// Probe execution failure is not equivalent to an ACL denial.
    /// # Panics
    /// Panics if the access composition contract is violated.
    #[test]
    fn native_failure_is_preserved() {
        assert_eq!(
            evaluate_access(MAXIMUM_ALLOWED, 0, |_, _| Err::<AccessDecision, _>(42)),
            Err(42)
        );
    }
}
