//! Resource policy shared by the fuzz targets and their host-side runner.

/// Maximum encoded input, including a complete filesystem and external journal.
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
