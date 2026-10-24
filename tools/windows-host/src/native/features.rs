//! Observations of mounted format declarations have no feature-enable or mutation effect.
use super::{FileHandle, control};
use ext4_control::FeaturesState;
use std::io;

/// Query failures retain an acknowledged observation independently of native release.
#[derive(Debug)]
pub enum FeaturesQueryError {
    /// No query was submitted.
    Preparation(io::Error),
    /// Transport or reply validation failed without an authoritative observation.
    Query {
        /// Primary observation failure.
        source: io::Error,
        /// Independent handle release failure, if any.
        release: Option<io::Error>,
    },
    /// A valid observation preceded native release failure.
    Release {
        /// Committed feature observation remains valid as of the query.
        state: FeaturesState,
        /// Native release diagnostic.
        source: io::Error,
    },
}
impl core::fmt::Display for FeaturesQueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Preparation(source) => write!(f, "feature query was not submitted: {source}"),
            Self::Query { source, release } => {
                write!(f, "feature query failed: {source}")?;
                if let Some(release) = release {
                    write!(f, "; handle release also failed: {release}")?;
                }
                Ok(())
            }
            Self::Release { source, .. } => write!(
                f,
                "feature observation received before handle release failed: {source}"
            ),
        }
    }
}
impl core::error::Error for FeaturesQueryError {}

/// Reads declared masks and fixed session access through attribute-only filesystem-root routing.
/// The control observes declarations without enabling features or replacing mount policy.
/// # Errors
/// Preserves preparation, query, malformed reply and post-observation release failure.
pub fn query_volume_features(volume: &str) -> Result<FeaturesState, FeaturesQueryError> {
    let file = FileHandle::open_volume_root(volume).map_err(FeaturesQueryError::Preparation)?;
    let mut output = [0; ext4_control::FEATURES_REPLY_BYTES];
    let result = control::exchange(&file, ext4_control::QUERY_FEATURES_FSCTL, &[], &mut output)
        .and_then(|length| {
            FeaturesState::decode(
                output
                    .get(..length)
                    .ok_or_else(|| io::Error::other("invalid feature reply length"))?,
            )
            .map_err(|error| io::Error::other(format!("invalid feature reply: {error:?}")))
        });
    let close = file.close();
    match result {
        Ok(state) => close
            .map(|()| state)
            .map_err(|source| FeaturesQueryError::Release { state, source }),
        Err(source) => Err(FeaturesQueryError::Query {
            source,
            release: close.err(),
        }),
    }
}
