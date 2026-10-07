//! Kernel boundary helpers and WDK-facing services.

pub(crate) mod cng;
#[cfg(not(test))]
pub(crate) mod device_interface;
pub(crate) mod external_journal;
mod fast_io;
pub(crate) mod fatal;
pub(crate) mod ffi;
pub(crate) mod file_information;
pub(crate) mod operational_trace;
pub(crate) mod status;
pub(crate) mod storage;
mod storage_admission;
pub(crate) mod stream;
pub(crate) mod time;
pub(crate) mod volume_discovery;
