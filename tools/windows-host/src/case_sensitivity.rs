//! Windows per-directory case sensitivity, independent of the host that parses requests for it.

/// Windows per-directory case sensitivity (`FileCaseSensitiveInformation`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryCaseSensitivity {
    /// Each request selects its comparison; Windows requests are normally case-insensitive.
    Disabled,
    /// Windows lookups in the directory are always case-sensitive.
    Enabled,
}
