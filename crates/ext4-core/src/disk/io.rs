//! Runtime-independent asynchronous block storage contract.

use core::future::Future;

use super::block::{ByteOffset, DeviceLength};
use crate::error::Result;

/// Serialized readable storage owned by one filesystem operation lane.
pub trait BlockSource: Send {
    /// Total readable length in bytes.
    fn len(&self) -> DeviceLength;

    /// Reads exactly `out.len()` bytes at `offset` without blocking the polling thread.
    fn read_exact_at<'a>(
        &'a mut self,
        offset: ByteOffset,
        out: &'a mut [u8],
    ) -> impl Future<Output = Result<()>> + Send + 'a;

    /// Returns true when the storage has no bytes.
    fn is_empty(&self) -> bool {
        self.len().is_empty()
    }
}

/// Writable block storage whose persistence boundary is explicit and asynchronous.
pub trait BlockStorage: BlockSource {
    /// Writes exactly `bytes.len()` bytes at `offset` without blocking the polling thread.
    fn write_exact_at<'a>(
        &'a mut self,
        offset: ByteOffset,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<()>> + Send + 'a;

    /// Persists every preceding write according to the storage contract.
    fn flush(&mut self) -> impl Future<Output = Result<()>> + Send + '_;
}
