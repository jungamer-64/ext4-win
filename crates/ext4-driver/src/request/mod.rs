//! Windows request dispatch implementations.

/// Concrete driver mutation pass with an operation-owned CNG nonce source.
pub(crate) type DriverMutationPass<'storage, 'epoch, 'nonce> = ext4_core::MutationResolvePass<
    'storage,
    'epoch,
    'nonce,
    crate::kernel::cng::CngFscryptNonceGenerator,
>;

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
