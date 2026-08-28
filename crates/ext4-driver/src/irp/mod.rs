//! Typed IRP boundary shared by FSD dispatch modules.

mod buffer;
mod cancel;
mod capture;
mod completion;
mod control;
mod create;
mod dispatch;
mod lifecycle;
pub(crate) mod lower;
pub(crate) mod reactor;
mod scheduler;
mod stack;

pub(crate) use buffer::*;
pub(crate) use capture::{
    CapturedQuerySecurityOutput, PreparedDirectoryControl, PreparedDirectoryPattern,
    PreparedEaSelection, PreparedQueryDirectory, PreparedQueryEa, PreparedRead, PreparedRequest,
    PreparedWrite,
};
pub(crate) use completion::*;
pub(crate) use control::*;
pub(crate) use create::*;
pub(crate) use dispatch::*;
pub(crate) use lifecycle::*;
pub(crate) use reactor::CompletionReactor;
pub(crate) use stack::*;

#[cfg(not(test))]
pub(crate) use cancel::ActiveCancelDestination;
pub(crate) use cancel::ActiveCancelEnvelope;
