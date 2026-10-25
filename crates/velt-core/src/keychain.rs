//! OS credential store adapters.
//!
//! The master vault key, team keys, device identity private keys and session
//! tokens live in the platform credential store:
//!
//! - macOS: Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (GNOME Keyring / KWallet)
//!
//! Nothing in this module ever writes key material to disk itself. Values are
//! hex-encoded only because the platform APIs accept UTF-8 passwords, and the
//! intermediate encoding buffers are zeroized.

use std::collections::HashMap;
use std::sync::Mutex;

use keyring::Entry;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::error::{CoreError, Result};

/// Service name used for every velt credential-store entry.
///
/// Accounts are namespaced (`vault:<id>`, `team-key:<id>:<epoch>`, ...).
pub const SERVICE: &str = "dev.velt.vault";

/// Abstract credential store, allowing deterministic tests and embedding.
pub trait KeyStore: Send + Sync {
    fn set(&self, account: &str, secret: &[u8]) -> Result<()>;
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    fn delete(&self, account: &str) -> Result<()>;
}

/// Production credential store backed by the OS keychain.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeyStore;

impl KeyStore for OsKeyStore {
    fn set(&self, account: &str, secret: &[u8]) -> Result<()> {
        let entry = Entry::new(SERVICE, account)?;
        let mut encoded = Zeroizing::new(hex::encode(secret));
        let result = entry
            .set_password(encoded.as_str())
            .map_err(CoreError::from);
        encoded.zeroize();
        result
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let entry = Entry::new(SERVICE, account)?;
        match entry.get_password() {
            Ok(password) => {
                let password = Zeroizing::new(password);
                let decoded =
                    hex::decode(password.as_bytes()).map_err(|_| CoreError::MalformedKey)?;
                Ok(Some(Zeroizing::new(decoded)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(CoreError::Keychain(err)),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        let entry = Entry::new(SERVICE, account)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(CoreError::Keychain(err)),
        }
    }
}

/// Deterministic in-memory store used by tests and by library consumers that
/// manage their own secure storage.
#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn set(&self, account: &str, secret: &[u8]) -> Result<()> {
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(account.to_owned(), secret.to_vec());
        Ok(())
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(guard.get(account).cloned().map(Zeroizing::new))
    }

    fn delete(&self, account: &str) -> Result<()> {
        let mut guard = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(account);
        Ok(())
    }
}

/// Account name for a vault master key.
pub fn vault_account(vault_id: &[u8; 16]) -> String {
    format!("vault:{}", hex::encode(vault_id))
}

/// Account name for a team key at a specific epoch.
pub fn team_key_account(team_id: &str, epoch: u32) -> String {
    format!("team-key:{team_id}:{epoch}")
}

/// Account name for a local X25519 identity on a sync server.
pub fn identity_account(server: &str, username: &str) -> String {
    let server_hash = crypto::sha256(server.as_bytes());
    format!("identity:{}:{username}", hex::encode(&server_hash[..8]))
}

/// Account name for a sync session token.
pub fn session_account(server: &str, username: &str) -> String {
    let server_hash = crypto::sha256(server.as_bytes());
    format!("session:{}:{username}", hex::encode(&server_hash[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let store = MemoryKeyStore::new();
        assert!(store.get("a").unwrap().is_none());
        store.set("a", b"value").unwrap();
        assert_eq!(&store.get("a").unwrap().unwrap()[..], b"value");
        store.delete("a").unwrap();
        assert!(store.get("a").unwrap().is_none());
    }

    #[test]
    fn account_names_are_namespaced() {
        assert_eq!(
            vault_account(&[0xab; 16]),
            format!("vault:{}", "ab".repeat(16))
        );
        assert_eq!(team_key_account("team", 3), "team-key:team:3");
        assert!(identity_account("https://a", "alice").starts_with("identity:"));
        assert!(session_account("https://a", "alice").starts_with("session:"));
    }
}
