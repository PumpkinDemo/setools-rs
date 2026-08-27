//! Memory-safe parsing primitives for SELinux kernel binary policies.
//!
//! This crate deliberately starts with a bounded metadata slice. It does not
//! yet implement [`setools_policy::PolicyLoader`] and is not used by the CLI
//! binaries until it can construct the complete owned policy model.

use setools_policy::{HandleUnknown, PolicyMetadata, TargetPlatform};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Oldest kernel binary policy version understood by this parser slice.
pub const MIN_SUPPORTED_POLICY_VERSION: u32 = 15;
/// Newest kernel binary policy version understood by this parser slice.
pub const MAX_SUPPORTED_POLICY_VERSION: u32 = 35;

const POLICYDB_MAGIC: u32 = 0xf97c_ff8c;
const POLICYDB_MODULE_MAGIC: u32 = 0xf97c_ff8d;
const MAX_IDENTIFIER_LENGTH: usize = 32;
const MAX_HEADER_LENGTH: usize = 8 + MAX_IDENTIFIER_LENGTH + 16;
const CONFIG_MLS: u32 = 1;
const CONFIG_UNKNOWN_MASK: u32 = 6;

/// Decoded fixed header of a kernel binary policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryPolicyHeader {
    metadata: PolicyMetadata,
    symbol_table_count: u32,
    object_context_count: u32,
    encoded_len: usize,
}

impl BinaryPolicyHeader {
    /// Returns metadata in the shared owned-policy representation.
    #[must_use]
    pub const fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }

    /// Returns the number of serialized symbol-table families.
    #[must_use]
    pub const fn symbol_table_count(&self) -> u32 {
        self.symbol_table_count
    }

    /// Returns the number of serialized object-context families.
    #[must_use]
    pub const fn object_context_count(&self) -> u32 {
        self.object_context_count
    }

    /// Returns the byte offset immediately after the fixed header.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

/// A rejected or incomplete binary policy header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The input ended before a bounded header field was complete.
    Truncated {
        /// Offset at which the read was attempted.
        offset: usize,
        /// Number of bytes required at that offset.
        needed: usize,
        /// Number of bytes available at that offset.
        available: usize,
    },
    /// The file has neither the kernel nor module policy magic.
    InvalidMagic(u32),
    /// Loadable modules are not part of this kernel-policy parser slice.
    UnsupportedModulePolicy,
    /// The target identifier length is zero or exceeds the format limit.
    InvalidIdentifierLength(u32),
    /// The target identifier is not `SE Linux` or `XenFlask`.
    UnsupportedTarget(Vec<u8>),
    /// The kernel binary policy version is outside the supported range.
    UnsupportedVersion(u32),
    /// The unknown-class handling bits do not encode deny, reject, or allow.
    InvalidUnknownHandling(u32),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                offset,
                needed,
                available,
            } => write!(
                formatter,
                "binary policy is truncated at offset {offset}: need {needed} bytes, have {available}"
            ),
            Self::InvalidMagic(magic) => {
                write!(formatter, "invalid binary policy magic 0x{magic:08x}")
            }
            Self::UnsupportedModulePolicy => {
                formatter.write_str("loadable policy modules are not supported")
            }
            Self::InvalidIdentifierLength(length) => {
                write!(formatter, "invalid binary policy target length {length}")
            }
            Self::UnsupportedTarget(target) => write!(
                formatter,
                "unsupported binary policy target {:?}",
                String::from_utf8_lossy(target)
            ),
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported binary policy version {version}; expected {MIN_SUPPORTED_POLICY_VERSION}..={MAX_SUPPORTED_POLICY_VERSION}"
            ),
            Self::InvalidUnknownHandling(value) => {
                write!(formatter, "invalid unknown-class handling value {value}")
            }
        }
    }
}

impl Error for ParseError {}

/// Failure while reading or parsing a policy header from a file.
#[derive(Debug)]
pub enum MetadataLoadError {
    /// The policy file could not be opened or read.
    Io {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The bounded bytes were not a supported policy header.
    Parse {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Header parser diagnostic.
        source: ParseError,
    },
}

impl fmt::Display for MetadataLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "could not read {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(formatter, "could not parse {}: {source}", path.display())
            }
        }
    }
}

impl Error for MetadataLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

/// File loader for the pure Rust bounded metadata parser.
#[derive(Clone, Copy, Debug, Default)]
pub struct PureRustMetadataLoader;

impl PureRustMetadataLoader {
    /// Reads at most the maximum fixed header size and decodes its metadata.
    pub fn load(self, path: &Path) -> Result<BinaryPolicyHeader, MetadataLoadError> {
        let mut file = File::open(path).map_err(|source| MetadataLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut bytes = [0_u8; MAX_HEADER_LENGTH];
        let mut length = 0;
        while length < bytes.len() {
            let read = file
                .read(&mut bytes[length..])
                .map_err(|source| MetadataLoadError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            if read == 0 {
                break;
            }
            length += read;
        }
        parse_policy_header(&bytes[..length]).map_err(|source| MetadataLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Parses the fixed metadata header from a kernel binary policy byte slice.
pub fn parse_policy_header(bytes: &[u8]) -> Result<BinaryPolicyHeader, ParseError> {
    let mut cursor = Cursor::new(bytes);
    let magic = cursor.read_u32()?;
    match magic {
        POLICYDB_MAGIC => {}
        POLICYDB_MODULE_MAGIC => return Err(ParseError::UnsupportedModulePolicy),
        other => return Err(ParseError::InvalidMagic(other)),
    }

    let identifier_length = cursor.read_u32()?;
    let identifier_length = usize::try_from(identifier_length)
        .ok()
        .filter(|length| (1..=MAX_IDENTIFIER_LENGTH).contains(length))
        .ok_or(ParseError::InvalidIdentifierLength(identifier_length))?;
    let identifier = cursor.read_bytes(identifier_length)?;
    let target = match identifier {
        b"SE Linux" => TargetPlatform::Selinux,
        b"XenFlask" => TargetPlatform::Xen,
        other => return Err(ParseError::UnsupportedTarget(other.to_vec())),
    };

    let version = cursor.read_u32()?;
    if !(MIN_SUPPORTED_POLICY_VERSION..=MAX_SUPPORTED_POLICY_VERSION).contains(&version) {
        return Err(ParseError::UnsupportedVersion(version));
    }
    let config = cursor.read_u32()?;
    let handle_unknown = match config & CONFIG_UNKNOWN_MASK {
        0 => HandleUnknown::Deny,
        2 => HandleUnknown::Reject,
        4 => HandleUnknown::Allow,
        other => return Err(ParseError::InvalidUnknownHandling(other)),
    };
    let symbol_table_count = cursor.read_u32()?;
    let object_context_count = cursor.read_u32()?;

    Ok(BinaryPolicyHeader {
        metadata: PolicyMetadata {
            version,
            mls: config & CONFIG_MLS != 0,
            target,
            handle_unknown,
        },
        symbol_table_count,
        object_context_count,
        encoded_len: cursor.offset,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let available = self.bytes.len().saturating_sub(self.offset);
        if available < length {
            return Err(ParseError::Truncated {
                offset: self.offset,
                needed: length,
                available,
            });
        }
        let start = self.offset;
        self.offset += length;
        Ok(&self.bytes[start..self.offset])
    }
}

#[cfg(test)]
mod tests {
    use super::{POLICYDB_MAGIC, POLICYDB_MODULE_MAGIC, ParseError, parse_policy_header};
    use setools_policy::{HandleUnknown, TargetPlatform};

    fn header(target: &[u8], version: u32, config: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&POLICYDB_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&(target.len() as u32).to_le_bytes());
        bytes.extend_from_slice(target);
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend_from_slice(&config.to_le_bytes());
        bytes.extend_from_slice(&8_u32.to_le_bytes());
        bytes.extend_from_slice(&7_u32.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_selinux_metadata() {
        let bytes = header(b"SE Linux", 35, 3);
        let parsed = parse_policy_header(&bytes).expect("header should parse");
        assert_eq!(parsed.metadata().version, 35);
        assert!(parsed.metadata().mls);
        assert_eq!(parsed.metadata().target, TargetPlatform::Selinux);
        assert_eq!(parsed.metadata().handle_unknown, HandleUnknown::Reject);
        assert_eq!(parsed.symbol_table_count(), 8);
        assert_eq!(parsed.object_context_count(), 7);
        assert_eq!(parsed.encoded_len(), bytes.len());
    }

    #[test]
    fn parses_xen_and_allow_unknown() {
        let parsed =
            parse_policy_header(&header(b"XenFlask", 30, 4)).expect("Xen header should parse");
        assert_eq!(parsed.metadata().target, TargetPlatform::Xen);
        assert!(!parsed.metadata().mls);
        assert_eq!(parsed.metadata().handle_unknown, HandleUnknown::Allow);
    }

    #[test]
    fn rejects_truncated_and_unbounded_headers() {
        assert!(matches!(
            parse_policy_header(&[0x8c, 0xff]),
            Err(ParseError::Truncated { .. })
        ));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&POLICYDB_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&33_u32.to_le_bytes());
        assert_eq!(
            parse_policy_header(&bytes),
            Err(ParseError::InvalidIdentifierLength(33))
        );
    }

    #[test]
    fn distinguishes_modules_and_invalid_config() {
        let mut module = header(b"SE Linux", 35, 0);
        module[..4].copy_from_slice(&POLICYDB_MODULE_MAGIC.to_le_bytes());
        assert_eq!(
            parse_policy_header(&module),
            Err(ParseError::UnsupportedModulePolicy)
        );
        assert_eq!(
            parse_policy_header(&header(b"SE Linux", 35, 6)),
            Err(ParseError::InvalidUnknownHandling(6))
        );
    }
}
