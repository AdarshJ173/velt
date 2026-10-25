//! velt-core: cryptography, vault format, audit engine, recovery and the E2EE
//! team protocol.
//!
//! Design invariants:
//!
//! - Secrets are decrypted only in memory and zeroized on drop.
//! - Vault entries are independently authenticated with AES-256-SIV in a
//!   line-oriented format; local-key and team-key modes share the format, and
//!   legacy whole-file ciphertext remains readable.
//! - The sync server never receives a team key or plaintext.
//! - All auditable operations return structured errors; library code contains
//!   no `unwrap()`/`expect()` on fallible input.

pub mod audit;
pub mod crypto;
pub mod detect;
pub mod error;
pub mod keychain;
pub mod lease;
pub mod recovery;
pub mod rules;
pub mod secret;
pub mod sync;
pub mod vault;

pub use error::{CoreError, Result};
pub use secret::SecretValue;
pub use vault::{
    Entry, KeyMode, MasterKey, RemoteBinding, Vault, VaultHeader, VaultId, VaultLock,
    VaultMetadata, VaultPayload,
};
