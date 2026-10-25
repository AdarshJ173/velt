//! Error types shared by the velt vault, audit engine and E2EE protocol.
//!
//! Rules:
//! - Errors never carry plaintext secret values.
//! - Errors are actionable: they name the path, vault id or share that failed.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Errors returned by the velt core library.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("vault file is not a valid velt vault: {0}")]
    InvalidVault(String),

    #[error(
        "vault format version {found} is newer than the supported version {supported}; upgrade velt"
    )]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error(
        "vault authentication failed: the file was modified, corrupted, or the wrong master key was used"
    )]
    AuthenticationFailed,

    #[error("master key for vault {vault_id} was not found in the OS credential store")]
    MasterKeyMissing { vault_id: String },

    #[error("OS credential store error: {0}")]
    Keychain(#[from] keyring::Error),

    #[error("invalid secret name {name:?}: {reason}")]
    InvalidName { name: String, reason: &'static str },

    #[error("invalid secret value for {name}: {reason}")]
    InvalidValue { name: String, reason: &'static str },

    #[error("secret {0} was not found in the vault")]
    SecretNotFound(String),

    #[error("vault already exists at {0} (use --force to replace it)")]
    VaultExists(PathBuf),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("credential store entry is malformed (expected 32-byte hex key material)")]
    MalformedKey,

    #[error("not enough recovery shares: need {needed}, got {got}")]
    NotEnoughShares { needed: usize, got: usize },

    #[error("invalid recovery share: {0}")]
    InvalidShare(String),

    #[error("recovery shares belong to a different vault")]
    ShareVaultMismatch,

    #[error("recovery share set is inconsistent: {0}")]
    InconsistentShares(String),

    #[error("the operating system random number generator failed")]
    Rng,

    #[error("invalid cryptographic material: {0}")]
    InvalidCrypto(&'static str),
}

impl CoreError {
    /// Wrap an I/O error with the path that produced it.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Convenience alias used across the workspace.
pub type Result<T, E = CoreError> = std::result::Result<T, E>;
