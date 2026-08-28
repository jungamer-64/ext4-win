//! Linux data partition admission, separate from ext superblock and mount validation.

#[cfg(not(test))]
mod native;
#[cfg(not(test))]
pub(crate) use native::VolumeDiscovery;

/// Linux filesystem data partition type, not an ext4 filesystem UUID.
const LINUX_FILESYSTEM_DATA: wdk_sys::GUID = wdk_sys::GUID {
    Data1: 0x0fc6_3daf,
    Data2: 0x8483,
    Data3: 0x4772,
    Data4: [0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4],
};

/// Automatic read-write publication must not override no-block-I/O, read-only,
/// shadow-copy, hidden, or no-automount attributes. Windows' inferred `IsHidden`
/// classification is not a GPT attribute and must not exclude Linux data volumes.
const EXPLICIT_PUBLICATION_RESTRICTIONS: u64 = 0xf000_0000_0000_0002;

/// Selects GPT candidates only; the signature probe still decides filesystem versus journal.
fn admits_automatic_publication(kind: &wdk_sys::GUID, attributes: u64) -> bool {
    kind.Data1 == LINUX_FILESYSTEM_DATA.Data1
        && kind.Data2 == LINUX_FILESYSTEM_DATA.Data2
        && kind.Data3 == LINUX_FILESYSTEM_DATA.Data3
        && kind.Data4 == LINUX_FILESYSTEM_DATA.Data4
        && attributes & EXPLICIT_PUBLICATION_RESTRICTIONS == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Panics if GPT identity is confused with disk byte order or a different partition type.
    #[test]
    fn linux_data_is_not_basic_data_or_a_byte_swapped_guid() {
        assert!(admits_automatic_publication(&LINUX_FILESYSTEM_DATA, 0));
        let basic = wdk_sys::GUID {
            Data1: 0xebd0_a0a2,
            Data2: 0xb9e5,
            Data3: 0x4433,
            Data4: [0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7],
        };
        assert!(!admits_automatic_publication(&basic, 0));
        let swapped = wdk_sys::GUID {
            Data1: 0xaf3d_c60f,
            ..LINUX_FILESYSTEM_DATA
        };
        assert!(!admits_automatic_publication(&swapped, 0));
    }

    /// # Panics
    /// Panics if automatic publication overrides an explicit on-disk restriction.
    #[test]
    fn explicit_partition_policy_is_preserved() {
        for attribute in [2, 1_u64 << 60, 1_u64 << 61, 1_u64 << 62, 1_u64 << 63] {
            assert!(!admits_automatic_publication(
                &LINUX_FILESYSTEM_DATA,
                attribute
            ));
        }
        assert!(admits_automatic_publication(&LINUX_FILESYSTEM_DATA, 1 | 4));
    }
}
