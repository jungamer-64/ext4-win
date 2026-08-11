//! Windows request dispatch implementations.

/// Concrete driver mutation pass borrowing one operation-owned CNG execution context.
pub(crate) type DriverMutationPass<'storage, 'epoch, 'crypto> =
    ext4_core::MutationResolvePass<'storage, 'epoch, 'crypto>;

pub(crate) mod create;
pub(crate) mod dispatch;
pub(crate) mod ea;
pub(crate) mod file_info;
pub(crate) mod file_system_control;
pub(crate) mod fsctl;
pub(crate) mod metadata;
pub(crate) mod operation;
pub(crate) mod reparse;
pub(crate) mod security;
pub(crate) mod volume_info;
