//! Selectable owned-policy loading for CLI parity testing.

use setools_policy::Policy;
#[cfg(feature = "native-libsepol")]
use setools_policy::PolicyLoader;
use setools_policy_binary::{MetadataLoadError, PureRustPolicyLoader};
#[cfg(feature = "native-libsepol")]
use setools_sepol::{LibsepolLoader, LoadError};
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

const POLICY_BACKEND_ENV: &str = "SETOOLS_POLICY_BACKEND";

/// The backend used to create the immutable policy model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyBackend {
    #[cfg(feature = "native-libsepol")]
    Libsepol,
    PureRust,
}

/// A policy-loading error from the selected backend.
#[derive(Debug)]
pub(crate) enum PolicyLoadError {
    #[cfg(feature = "native-libsepol")]
    Libsepol(LoadError),
    PureRust(MetadataLoadError),
    Configuration(String),
}

impl PolicyLoadError {
    /// Returns whether this represents a missing policy path.
    pub(crate) fn is_not_found(&self) -> bool {
        match self {
            #[cfg(feature = "native-libsepol")]
            Self::Libsepol(error) => error.code() == 3,
            Self::PureRust(MetadataLoadError::Io { source, .. }) => {
                source.kind() == std::io::ErrorKind::NotFound
            }
            Self::PureRust(MetadataLoadError::Parse { .. }) | Self::Configuration(_) => false,
        }
    }
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "native-libsepol")]
            Self::Libsepol(error) => error.fmt(formatter),
            Self::PureRust(error) => error.fmt(formatter),
            Self::Configuration(error) => formatter.write_str(error),
        }
    }
}

/// Loads an immutable policy through the requested CLI backend.
pub(crate) fn load(path: &Path) -> Result<Policy, PolicyLoadError> {
    match selected_backend()? {
        #[cfg(feature = "native-libsepol")]
        PolicyBackend::Libsepol => LibsepolLoader.load(path).map_err(PolicyLoadError::Libsepol),
        PolicyBackend::PureRust => PureRustPolicyLoader::default()
            .load(path)
            .map_err(PolicyLoadError::PureRust),
    }
}

/// Renders a policy-load error using the established missing-file convention.
pub(crate) fn format_error(path: &Path, error: &PolicyLoadError) -> String {
    if error.is_not_found() && !path.exists() {
        format!("[Errno 2] No such file or directory: '{}'", path.display())
    } else {
        error.to_string()
    }
}

fn selected_backend() -> Result<PolicyBackend, PolicyLoadError> {
    parse_backend(env::var_os(POLICY_BACKEND_ENV).as_deref())
        .map_err(PolicyLoadError::Configuration)
}

fn parse_backend(value: Option<&OsStr>) -> Result<PolicyBackend, String> {
    match value {
        None => Ok(default_backend()),
        Some(value) if value == OsStr::new("libsepol") => native_backend(),
        Some(value) if value == OsStr::new("rust") || value == OsStr::new("pure-rust") => {
            Ok(PolicyBackend::PureRust)
        }
        Some(value) => Err(format!(
            "{POLICY_BACKEND_ENV} must be one of: libsepol, rust, pure-rust (got {value:?})"
        )),
    }
}

const fn default_backend() -> PolicyBackend {
    #[cfg(feature = "native-libsepol")]
    {
        PolicyBackend::Libsepol
    }
    #[cfg(not(feature = "native-libsepol"))]
    {
        PolicyBackend::PureRust
    }
}

fn native_backend() -> Result<PolicyBackend, String> {
    #[cfg(feature = "native-libsepol")]
    {
        Ok(PolicyBackend::Libsepol)
    }
    #[cfg(not(feature = "native-libsepol"))]
    {
        Err(format!(
            "{POLICY_BACKEND_ENV}=libsepol requires the native-libsepol feature"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{POLICY_BACKEND_ENV, PolicyBackend, parse_backend};
    use std::ffi::OsStr;

    #[test]
    fn backend_selection_uses_the_compiled_default_and_accepts_pure_rust_aliases() {
        #[cfg(feature = "native-libsepol")]
        assert_eq!(parse_backend(None), Ok(PolicyBackend::Libsepol));
        #[cfg(not(feature = "native-libsepol"))]
        assert_eq!(parse_backend(None), Ok(PolicyBackend::PureRust));

        #[cfg(feature = "native-libsepol")]
        assert_eq!(
            parse_backend(Some(OsStr::new("libsepol"))),
            Ok(PolicyBackend::Libsepol)
        );
        #[cfg(not(feature = "native-libsepol"))]
        assert!(parse_backend(Some(OsStr::new("libsepol"))).is_err());
        assert_eq!(
            parse_backend(Some(OsStr::new("rust"))),
            Ok(PolicyBackend::PureRust)
        );
        assert_eq!(
            parse_backend(Some(OsStr::new("pure-rust"))),
            Ok(PolicyBackend::PureRust)
        );
    }

    #[test]
    fn backend_selection_rejects_unknown_values() {
        let error = parse_backend(Some(OsStr::new("other"))).unwrap_err();
        assert!(error.contains(POLICY_BACKEND_ENV));
        assert!(error.contains("other"));
    }
}
