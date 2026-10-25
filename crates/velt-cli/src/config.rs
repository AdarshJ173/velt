//! Persistent CLI configuration.
//!
//! Secrets are never stored here. The sync session token and the X25519
//! identity private key live in the OS credential store.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<PathBuf>,
}

impl Config {
    pub fn server_url(&self) -> Option<String> {
        let value = std::env::var("VELT_SERVER_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| self.server_url.clone())?;
        Some(value.trim().trim_end_matches('/').to_owned())
    }

    pub fn require_server_url(&self) -> Result<String> {
        self.server_url().ok_or_else(|| {
            CliError::Config(
                "no sync server configured; run `velt auth register --server <url> --username <name>` or set VELT_SERVER_URL"
                    .to_owned(),
            )
        })
    }

    pub fn ssh_key_path(&self) -> Result<PathBuf> {
        if let Ok(value) = std::env::var("VELT_SSH_KEY") {
            if !value.trim().is_empty() {
                return Ok(PathBuf::from(value));
            }
        }
        if let Some(path) = &self.ssh_key {
            return Ok(path.clone());
        }
        let home = dirs::home_dir()
            .ok_or_else(|| CliError::Config("cannot determine the home directory".to_owned()))?;
        Ok(home.join(".ssh").join("id_ed25519"))
    }
}

pub fn config_dir() -> PathBuf {
    if let Ok(value) = std::env::var("VELT_CONFIG_DIR") {
        if !value.trim().is_empty() {
            return PathBuf::from(value);
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("velt")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let contents = fs::read_to_string(&path).map_err(|err| CliError::io(&path, err))?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

pub fn save(config: &Config) -> Result<()> {
    let directory = config_dir();
    fs::create_dir_all(&directory).map_err(|err| CliError::io(&directory, err))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700));
    }
    let path = config_path();
    let contents = toml::to_string_pretty(config)?;
    write_private(&path, contents.as_bytes())
}

/// Write a 0600 file atomically.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(directory).map_err(|err| CliError::io(directory, err))?;
    let mut temp = tempfile::Builder::new()
        .prefix(".velt-tmp-")
        .tempfile_in(directory)
        .map_err(|err| CliError::io(directory, err))?;
    temp.as_file_mut()
        .write_all(bytes)
        .map_err(|err| CliError::io(temp.path(), err))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| CliError::io(temp.path(), err))?;
    temp.persist(path)
        .map_err(|error| CliError::io(path, error.error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}
