//! Vault discovery, keychain access and advisory locking.

use std::path::{Path, PathBuf};

use velt_core::crypto;
use velt_core::keychain::{self, KeyStore, OsKeyStore};
use velt_core::vault::{read_vault_id, MasterKey, Vault, VaultLock};
use zeroize::Zeroizing;

use crate::error::{CliError, Result};

pub const VAULT_FILE: &str = ".velt.vault";

/// Find a vault from an explicit path, `VELT_VAULT`, or by walking upward.
pub fn discover_vault(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        let path = absolute(path)?;
        if !path.exists() {
            return Err(CliError::msg(format!(
                "vault not found at {}; run `velt init` first",
                path.display()
            )));
        }
        return Ok(path);
    }
    if let Ok(value) = std::env::var("VELT_VAULT") {
        if !value.trim().is_empty() {
            let path = absolute(PathBuf::from(value))?;
            if !path.exists() {
                return Err(CliError::msg(format!(
                    "VELT_VAULT points to a missing file: {}",
                    path.display()
                )));
            }
            return Ok(path);
        }
    }
    let cwd = std::env::current_dir().map_err(|err| CliError::io(".", err))?;
    for directory in cwd.ancestors() {
        let candidate = directory.join(VAULT_FILE);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CliError::msg(format!(
        "no {VAULT_FILE} found (searched upward from {}); run `velt init`",
        cwd.display()
    )))
}

/// Determine where `velt init` should write.
pub fn init_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return absolute(path);
    }
    let cwd = std::env::current_dir().map_err(|err| CliError::io(".", err))?;
    Ok(cwd.join(VAULT_FILE))
}

fn absolute(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir().map_err(|err| CliError::io(".", err))?;
    Ok(cwd.join(path))
}

/// Load a vault and its master key from the OS credential store.
pub fn open_vault(path: &Path) -> Result<(Vault, MasterKey)> {
    let vault_id = read_vault_id(path)?;
    let key = load_master_key(&vault_id)?;
    let vault = Vault::load(path, &key)?;
    Ok((vault, key))
}

/// Load a vault for a read-modify-write transaction, holding the advisory lock.
pub struct WriteContext {
    pub vault: Vault,
    pub key: MasterKey,
    _lock: VaultLock,
}

impl WriteContext {
    pub fn open(path: &Path) -> Result<Self> {
        let lock = VaultLock::acquire(path)?;
        let (vault, key) = open_vault(path)?;
        Ok(Self {
            vault,
            key,
            _lock: lock,
        })
    }

    pub fn save(&mut self) -> Result<()> {
        self.vault.save(&self.key)?;
        Ok(())
    }

    pub fn into_parts(self) -> (Vault, MasterKey, VaultLock) {
        (self.vault, self.key, self._lock)
    }
}

pub fn load_master_key(vault_id: &[u8; 16]) -> Result<MasterKey> {
    let account = keychain::vault_account(vault_id);
    let stored =
        OsKeyStore
            .get(&account)?
            .ok_or_else(|| velt_core::CoreError::MasterKeyMissing {
                vault_id: hex::encode(vault_id),
            })?;
    let key = MasterKey::from_slice(&stored)?;
    Ok(key)
}

pub fn store_master_key(vault_id: &[u8; 16], key: &MasterKey) -> Result<()> {
    let account = keychain::vault_account(vault_id);
    OsKeyStore.set(&account, key.expose())?;
    Ok(())
}

pub fn delete_master_key(vault_id: &[u8; 16]) -> Result<()> {
    let account = keychain::vault_account(vault_id);
    OsKeyStore.delete(&account)?;
    Ok(())
}

/// Retrieve the lease signing key, creating it on first use.
pub fn lease_secret(vault_id: &[u8; 16], create: bool) -> Result<[u8; 32]> {
    let account = lease_account(vault_id);
    if let Some(existing) = OsKeyStore.get(&account)? {
        if existing.len() != 32 {
            return Err(CliError::msg("lease signing key is malformed"));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&existing);
        return Ok(secret);
    }
    if !create {
        return Err(CliError::msg(
            "lease signing key does not exist for this vault; run `velt lease create` first",
        ));
    }
    let generated: Zeroizing<[u8; 32]> = crypto::random_key()?;
    OsKeyStore.set(&account, &generated[..])?;
    Ok(*generated)
}

pub fn lease_account(vault_id: &[u8; 16]) -> String {
    format!("lease-key:{}", hex::encode(vault_id))
}

/// Absolute path of the project directory containing a vault.
pub fn project_root(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
