//! envy-core: cryptography, vault format, audit engine, recovery and the E2EE
//! team protocol.
//!
//! Design invariants:
//!
//! - Secrets are decrypted only in memory and zeroized on drop.
//! - Vault files are authenticated ciphertext; every write uses a fresh nonce.
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
    Entry, MasterKey, RemoteBinding, Vault, VaultHeader, VaultId, VaultLock, VaultPayload,
};
