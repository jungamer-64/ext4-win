//! Domain types shared by the Windows security descriptor boundary and request execution.

use crate::kernel::status::{DriverError, DriverResult};

/// Immutable, owner-bound descriptor accepted by the native security reference monitor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SecurityDescriptorRef<'a> {
    /// Complete self-relative image retained by its descriptor owner.
    bytes: &'a [u8],
}

impl<'a> SecurityDescriptorRef<'a> {
    /// Borrows an already validated native descriptor image.
    ///
    /// # Safety
    ///
    /// `bytes` must be suitably aligned and encode a complete, valid self-relative security
    /// descriptor whose owner, group, ACLs, and referenced SIDs are contained in the slice. Native
    /// access checks may read the image but must not mutate it.
    #[expect(
        unsafe_code,
        reason = "descriptor encoders establish the native layout invariant once before creating this immutable view"
    )]
    pub(crate) unsafe fn from_validated_bytes(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the borrowed address only for native input parameters.
    pub(crate) fn as_ptr(self) -> wdk_sys::PSECURITY_DESCRIPTOR {
        self.bytes.as_ptr().cast_mut().cast()
    }
}

/// Serialized `SECURITY_DESCRIPTOR_RELATIVE` header length.
pub(crate) const SECURITY_DESCRIPTOR_RELATIVE_BYTES: usize = 20;
/// Serialized SID bytes before the first sub-authority.
pub(crate) const SID_PREFIX_BYTES: usize = 8;
/// Serialized ACL header length.
pub(crate) const ACL_HEADER_BYTES: usize = 8;
/// Serialized ACCESS_ALLOWED_ACE bytes before its SID.
pub(crate) const ACCESS_ALLOWED_ACE_PREFIX_BYTES: usize = 8;
/// Serialized Linux UID/GID SID length (`S-1-22-{1,2}-id`).
const LINUX_IDENTITY_SID_BYTES: usize = SID_PREFIX_BYTES + 2 * core::mem::size_of::<u32>();
/// Serialized world SID length (`S-1-1-0`).
const EVERYONE_SID_BYTES: usize = SID_PREFIX_BYTES + core::mem::size_of::<u32>();
/// Exact canonical DACL length for owner, group, and world permission classes.
const POSIX_DACL_BYTES: usize = ACL_HEADER_BYTES
    + ACCESS_ALLOWED_ACE_PREFIX_BYTES
    + LINUX_IDENTITY_SID_BYTES
    + ACCESS_ALLOWED_ACE_PREFIX_BYTES
    + LINUX_IDENTITY_SID_BYTES
    + ACCESS_ALLOWED_ACE_PREFIX_BYTES
    + EVERYONE_SID_BYTES;
/// Header plus one serialized Linux identity SID.
const SINGLE_IDENTITY_DESCRIPTOR_BYTES: usize =
    SECURITY_DESCRIPTOR_RELATIVE_BYTES + LINUX_IDENTITY_SID_BYTES;
/// Header plus both serialized Linux identity SIDs.
const BOTH_IDENTITIES_DESCRIPTOR_BYTES: usize =
    SINGLE_IDENTITY_DESCRIPTOR_BYTES + LINUX_IDENTITY_SID_BYTES;
/// Header plus the canonical POSIX DACL.
const DACL_DESCRIPTOR_BYTES: usize = SECURITY_DESCRIPTOR_RELATIVE_BYTES + POSIX_DACL_BYTES;
/// Header, one Linux identity SID, and the canonical POSIX DACL.
const IDENTITY_AND_DACL_DESCRIPTOR_BYTES: usize = DACL_DESCRIPTOR_BYTES + LINUX_IDENTITY_SID_BYTES;
/// Header, both Linux identity SIDs, and the canonical POSIX DACL.
const COMPLETE_DESCRIPTOR_BYTES: usize =
    IDENTITY_AND_DACL_DESCRIPTOR_BYTES + LINUX_IDENTITY_SID_BYTES;

/// Selection state for one self-relative security descriptor component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecurityComponentSelection {
    /// Component was not selected by this IRP.
    Omitted,
    /// Component was selected by this IRP.
    Selected,
}

/// Security descriptor components accepted by the POSIX owner/mode boundary.
///
/// DACL inheritance-control flags are intentionally outside this type because ext4 owner and mode
/// bits have no state capable of representing Windows ACL inheritance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecuritySelection {
    /// Owner SID selection.
    owner: SecurityComponentSelection,
    /// Group SID selection.
    group: SecurityComponentSelection,
    /// DACL selection.
    dacl: SecurityComponentSelection,
}

impl SecuritySelection {
    /// Selects every component represented by the ext4 owner/mode security model.
    pub(crate) const fn complete() -> Self {
        Self::from_components(
            SecurityComponentSelection::Selected,
            SecurityComponentSelection::Selected,
            SecurityComponentSelection::Selected,
        )
    }

    /// Builds a security selection from already-decoded component states.
    pub(crate) const fn from_components(
        owner: SecurityComponentSelection,
        group: SecurityComponentSelection,
        dacl: SecurityComponentSelection,
    ) -> Self {
        Self { owner, group, dacl }
    }

    /// Converts raw `SECURITY_INFORMATION` bits into supported component state.
    /// # Errors
    ///
    /// Returns an error when SACL access is requested or when unsupported information, including
    /// DACL inheritance-control state, is present.
    pub(crate) fn from_raw(value: wdk_sys::SECURITY_INFORMATION) -> DriverResult<Self> {
        let supported = wdk_sys::OWNER_SECURITY_INFORMATION
            | wdk_sys::GROUP_SECURITY_INFORMATION
            | wdk_sys::DACL_SECURITY_INFORMATION;
        if value == 0 {
            return Err(DriverError::InvalidParameter);
        }
        if value & wdk_sys::SACL_SECURITY_INFORMATION != 0 {
            return Err(DriverError::AccessDenied);
        }
        if value & !supported != 0 {
            return Err(DriverError::NotSupported);
        }

        Ok(Self::from_components(
            security_component(value, wdk_sys::OWNER_SECURITY_INFORMATION),
            security_component(value, wdk_sys::GROUP_SECURITY_INFORMATION),
            security_component(value, wdk_sys::DACL_SECURITY_INFORMATION),
        ))
    }

    /// Returns owner SID selection.
    pub(crate) const fn owner(self) -> SecurityComponentSelection {
        self.owner
    }

    /// Returns group SID selection.
    pub(crate) const fn group(self) -> SecurityComponentSelection {
        self.group
    }

    /// Returns DACL selection.
    pub(crate) const fn dacl(self) -> SecurityComponentSelection {
        self.dacl
    }

    /// Reconstructs the validated `SECURITY_INFORMATION` mask for native validation.
    pub(crate) const fn required_information(self) -> wdk_sys::SECURITY_INFORMATION {
        let mut information = 0;
        if matches!(self.owner, SecurityComponentSelection::Selected) {
            information |= wdk_sys::OWNER_SECURITY_INFORMATION;
        }
        if matches!(self.group, SecurityComponentSelection::Selected) {
            information |= wdk_sys::GROUP_SECURITY_INFORMATION;
        }
        if matches!(self.dacl, SecurityComponentSelection::Selected) {
            information |= wdk_sys::DACL_SECURITY_INFORMATION;
        }
        information
    }

    /// Returns the exact byte length of the descriptor emitted for this selection.
    pub(crate) const fn query_descriptor_length(self) -> usize {
        use SecurityComponentSelection::{Omitted, Selected};

        match (self.owner, self.group, self.dacl) {
            (Omitted, Omitted, Omitted) => SECURITY_DESCRIPTOR_RELATIVE_BYTES,
            (Selected, Omitted, Omitted) | (Omitted, Selected, Omitted) => {
                SINGLE_IDENTITY_DESCRIPTOR_BYTES
            }
            (Selected, Selected, Omitted) => BOTH_IDENTITIES_DESCRIPTOR_BYTES,
            (Omitted, Omitted, Selected) => DACL_DESCRIPTOR_BYTES,
            (Selected, Omitted, Selected) | (Omitted, Selected, Selected) => {
                IDENTITY_AND_DACL_DESCRIPTOR_BYTES
            }
            (Selected, Selected, Selected) => COMPLETE_DESCRIPTOR_BYTES,
        }
    }
}

/// Converts one security bit into component selection.
const fn security_component(
    value: wdk_sys::SECURITY_INFORMATION,
    bit: wdk_sys::SECURITY_INFORMATION,
) -> SecurityComponentSelection {
    if value & bit == 0 {
        SecurityComponentSelection::Omitted
    } else {
        SecurityComponentSelection::Selected
    }
}

#[cfg(test)]
mod tests {
    use super::{SecurityComponentSelection, SecuritySelection};

    /// # Panics
    ///
    /// Panics when descriptor layout planning diverges from the fixed Windows encoding.
    #[test]
    fn query_descriptor_lengths_are_exact_for_every_component_combination() {
        let omitted = SecurityComponentSelection::Omitted;
        let selected = SecurityComponentSelection::Selected;

        assert_eq!(
            SecuritySelection::from_components(omitted, omitted, omitted).query_descriptor_length(),
            20
        );
        assert_eq!(
            SecuritySelection::from_components(selected, omitted, omitted)
                .query_descriptor_length(),
            36
        );
        assert_eq!(
            SecuritySelection::from_components(omitted, selected, omitted)
                .query_descriptor_length(),
            36
        );
        assert_eq!(
            SecuritySelection::from_components(omitted, omitted, selected)
                .query_descriptor_length(),
            96
        );
        assert_eq!(
            SecuritySelection::from_components(selected, selected, selected)
                .query_descriptor_length(),
            128
        );
    }

    /// # Panics
    ///
    /// Panics when validated component state does not round-trip to native information bits.
    #[test]
    fn required_information_round_trips_supported_bits() {
        let information = wdk_sys::OWNER_SECURITY_INFORMATION
            | wdk_sys::GROUP_SECURITY_INFORMATION
            | wdk_sys::DACL_SECURITY_INFORMATION;
        let selection = SecuritySelection::from_raw(information);
        assert!(selection.is_ok());
        if let Ok(selection) = selection {
            assert_eq!(selection.required_information(), information);
        }
    }

    /// # Panics
    ///
    /// Panics when an empty security-information request does not fail at the typed boundary.
    #[test]
    fn rejects_an_empty_security_information_mask() {
        assert_eq!(
            SecuritySelection::from_raw(0)
                .err()
                .map(crate::kernel::status::DriverError::ntstatus),
            Some(wdk_sys::STATUS_INVALID_PARAMETER)
        );
    }

    /// # Panics
    ///
    /// Panics when Windows DACL inheritance state enters the POSIX owner/mode domain.
    #[test]
    fn rejects_dacl_inheritance_control_bits() {
        const UNPROTECTED_DACL_SECURITY_INFORMATION: wdk_sys::SECURITY_INFORMATION = 0x2000_0000;
        const PROTECTED_DACL_SECURITY_INFORMATION: wdk_sys::SECURITY_INFORMATION = 0x8000_0000;

        for information in [
            wdk_sys::DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            wdk_sys::DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        ] {
            assert_eq!(
                SecuritySelection::from_raw(information)
                    .err()
                    .map(crate::kernel::status::DriverError::ntstatus),
                Some(wdk_sys::STATUS_NOT_SUPPORTED)
            );
        }
    }
}
