//! Kernel boundary helpers and WDK-facing services.

mod cache_transfer;
pub(crate) mod cng;
pub(crate) mod configuration_registry;
#[cfg(not(test))]
pub(crate) mod device_interface;
pub(crate) mod external_journal;
mod fast_io;
pub(crate) mod fatal;
pub(crate) mod ffi;
pub(crate) mod file_information;
pub(crate) mod input_validation;
pub(crate) mod io_reliability;
pub(crate) mod name_expression;
pub(crate) mod operational_trace;
pub(crate) mod requestor_subject;
pub(crate) mod section;
pub(crate) mod status;
pub(crate) mod storage;
mod storage_admission;
pub(crate) mod stream;
pub(crate) mod time;
pub(crate) mod name_tunnel;
pub(crate) mod volume_discovery;
pub(crate) mod volume_event;
pub(crate) mod volume_verify;
