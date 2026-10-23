//! Future-mount policy administration over the secured control endpoint.
use super::control::{self, ControlError, Submission};
use ext4_control::{
    POLICY_REPLY_BYTES, PolicyReplacement, PolicyState, QUERY_POLICY_IOCTL, REPLACE_POLICY_IOCTL,
};
use ext4_core::FilesystemUuid;
use std::io;

/// Queries and, when required, reconciles the durable selection for subsequent mounts.
/// # Errors
/// Preserves transport and post-reply release outcomes.
pub fn query_policy(uuid: FilesystemUuid) -> Result<PolicyState, ControlError<PolicyState>> {
    let mut output = [0; POLICY_REPLY_BYTES];
    control::request(
        QUERY_POLICY_IOCTL,
        &uuid.bytes(),
        &mut output,
        Submission::Query,
        |bytes| {
            PolicyState::decode(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))
        },
    )
}
/// Saves one whole generation-checked policy for subsequent mounts, with no automatic retry.
/// # Errors
/// Submission or decoding failure retains persistent-effect uncertainty.
pub fn replace_policy(
    replacement: PolicyReplacement,
) -> Result<PolicyState, ControlError<PolicyState>> {
    let mut output = [0; POLICY_REPLY_BYTES];
    control::request(
        REPLACE_POLICY_IOCTL,
        &replacement.encode(),
        &mut output,
        Submission::Replacement {
            uuid: replacement.next().uuid,
            expected_generation: replacement.expected_generation(),
        },
        |bytes| {
            PolicyState::decode(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}")))
        },
    )
}
