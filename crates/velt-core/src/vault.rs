//! Encrypted vault file format and in-memory vault operations.
//!
//! # Current line format (format version 2)
//!
//! Format 2 is a deterministic, line-oriented, merge-friendly text file. Every
//! entry is encrypted independently with AES-256-SIV; names stay visible so
//! Git can merge independent additions line by line. Unchanged entries produce
//! byte-identical lines across saves.
//!
//! ```text
//! VELT-VAULT 2
//! id <32 hex chars>
//! created_at <unix seconds>
//! key_version 1
//! binding <base64url AES-SIV ciphertext of RemoteBinding JSON>   # optional
//! ENTRY API_KEY <updated_at> <expires_at|-> <base64url ciphertext>
//! ```
//!
//! Entry AAD binds the vault id, key version, name, updated_at and expiry.
//! AES-SIV's deterministic nonce is derived from the vault id and name.
//! Legacy format 1 (binary `VELTVLT1`) remains readable and is rewritten as
//! format 2 on the next save.
//!
//! Writes are atomic (temporary file in the same directory, fsync, rename) and
//! the resulting file is mode 0600 on Unix. Plaintext buffers are zeroized
//! immediately after parsing.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::secret::SecretValue;

pub const MAGIC: &[u8; 8] = b"VELTVLT1";
pub const FORMAT_VERSION: u8 = 1;
pub const TEXT_FORMAT_VERSION: u8 = 2;
pub const TEXT_MAGIC: &str = "VELT-VAULT 2";
pub const HEADER_LEN: usize = 40;
pub const VAULT_ID_LEN: usize = 16;
pub const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
pub const MAX_NAME_BYTES: usize = 256;
pub const SCHEMA_VERSION: u32 = 1;
pub const TEXT_SCHEMA_VERSION: u32 = 2;
pub const MASTER_KEY_VERSION: u32 = 1;

pub type VaultId = [u8; VAULT_ID_LEN];

/// Current Unix timestamp in seconds.
pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A 256-bit vault master key. Wiped on drop; never serialized by velt.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; crypto::KEY_LEN]);

impl MasterKey {
    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; crypto::KEY_LEN];
        crypto::fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Construct from raw bytes, rejecting the wrong length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != crypto::KEY_LEN {
            return Err(CoreError::MalformedKey);
        }
        let mut key = [0u8; crypto::KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Borrow the raw key material. Every call site is security-sensitive.
    pub fn expose(&self) -> &[u8; crypto::KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

impl TryFrom<&[u8]> for MasterKey {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::from_slice(value)
    }
}

/// Parsed vault header. The nonce is not retained: it is only needed while
/// decrypting the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultHeader {
    pub vault_id: VaultId,
}

impl VaultHeader {
    pub fn vault_id_hex(self) -> String {
        hex::encode(self.vault_id)
    }

    fn aad(self) -> [u8; 28] {
        let mut aad = [0u8; 28];
        aad[..8].copy_from_slice(MAGIC);
        aad[8] = FORMAT_VERSION;
        aad[12..28].copy_from_slice(&self.vault_id);
        aad
    }
}

/// Which key protects the entries. Local vaults use the OS-keychain master
/// key. Exported team vaults use the shared team key for the current epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyMode {
    Local,
    Team { team_id: String, epoch: u32 },
}

impl KeyMode {
    fn suffix(&self) -> String {
        match self {
            Self::Local => String::new(),
            Self::Team { team_id, epoch } => format!("|team|{team_id}|{epoch}"),
        }
    }
}

/// Optional binding between a local vault and a team environment on a sync
/// server. The binding is encrypted with the vault master key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteBinding {
    pub team_id: String,
    pub environment: String,
    pub epoch: u32,
    pub base_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_checksum: Option<String>,
}

/// A single vault entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub value: SecretValue,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Decrypted vault metadata and secret entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultPayload {
    pub schema: u32,
    pub vault_id: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub revision: u64,
    pub key_version: u32,
    pub entries: BTreeMap<String, Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<RemoteBinding>,
    #[serde(default)]
    pub checksum: String,
}

#[derive(Serialize)]
struct PayloadBody<'a> {
    schema: u32,
    vault_id: &'a str,
    created_at: i64,
    updated_at: i64,
    revision: u64,
    key_version: u32,
    entries: &'a BTreeMap<String, Entry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: &'a Option<RemoteBinding>,
}

impl VaultPayload {
    fn body(&self) -> PayloadBody<'_> {
        PayloadBody {
            schema: self.schema,
            vault_id: &self.vault_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            revision: self.revision,
            key_version: self.key_version,
            entries: &self.entries,
            binding: &self.binding,
        }
    }

    /// Recompute the checksum over the canonical body.
    pub fn compute_checksum(&self) -> Result<String> {
        let canonical = serde_json::to_vec(&self.body())?;
        Ok(hex::encode(crypto::sha256(&canonical)))
    }

    fn verify_checksum(&self) -> Result<()> {
        if self.checksum.is_empty() {
            return Err(CoreError::InvalidVault("missing payload checksum".into()));
        }
        let expected = self.compute_checksum()?;
        let expected_bytes = hex::decode(expected)
            .map_err(|_| CoreError::InvalidVault("payload checksum is not valid hex".to_owned()))?;
        let actual_bytes = hex::decode(&self.checksum)
            .map_err(|_| CoreError::InvalidVault("payload checksum is not valid hex".to_owned()))?;
        if !crypto::constant_time_eq(&expected_bytes, &actual_bytes) {
            return Err(CoreError::InvalidVault(
                "payload checksum mismatch; the vault is corrupted".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate(&self, header: VaultHeader) -> Result<()> {
        if self.schema != SCHEMA_VERSION {
            return Err(CoreError::InvalidVault(format!(
                "unsupported payload schema {}",
                self.schema
            )));
        }
        if self.vault_id != header.vault_id_hex() {
            return Err(CoreError::InvalidVault(
                "payload vault id does not match the file header".to_owned(),
            ));
        }
        if self.key_version == 0 {
            return Err(CoreError::InvalidVault(
                "key version must be positive".into(),
            ));
        }
        if self.revision == 0 {
            return Err(CoreError::InvalidVault("revision must be positive".into()));
        }
        if self.entries.len() > 100_000 {
            return Err(CoreError::InvalidVault("too many vault entries".into()));
        }
        for (name, entry) in &self.entries {
            validate_name(name)?;
            validate_value(name, entry.value.expose())?;
        }
        self.verify_checksum()
    }
}

/// An open, decrypted vault.
pub struct Vault {
    path: PathBuf,
    pub header: VaultHeader,
    pub payload: VaultPayload,
    format: u8,
    key_mode: KeyMode,
}

impl Vault {
    /// Create an empty vault in memory. Call [`Vault::save`] to write it.
    ///
    /// The caller is responsible for storing the master key under
    /// [`crate::keychain::vault_account`] before or after saving.
    pub fn new(path: impl Into<PathBuf>, binding: Option<RemoteBinding>) -> Result<Self> {
        let mut vault_id = [0u8; VAULT_ID_LEN];
        crypto::fill_random(&mut vault_id)?;
        let timestamp = now_unix();
        let header = VaultHeader { vault_id };
        let payload = VaultPayload {
            schema: TEXT_SCHEMA_VERSION,
            vault_id: header.vault_id_hex(),
            created_at: timestamp,
            updated_at: timestamp,
            revision: 1,
            key_version: MASTER_KEY_VERSION,
            entries: BTreeMap::new(),
            binding,
            checksum: String::new(),
        };
        Ok(Self {
            path: path.into(),
            header,
            payload,
            format: TEXT_FORMAT_VERSION,
            key_mode: KeyMode::Local,
        })
    }

    /// Read and decrypt an existing vault (format 1 or format 2).
    pub fn load(path: impl Into<PathBuf>, key: &MasterKey) -> Result<Self> {
        let path = path.into();
        let bytes = read_vault_file(&path)?;
        if bytes.starts_with(MAGIC) {
            Self::load_v1(path, &bytes, key)
        } else if bytes.starts_with(TEXT_MAGIC.as_bytes()) {
            Self::load_v2(path, &bytes, key)
        } else {
            Err(CoreError::InvalidVault(
                "file has neither a VELTVLT1 nor a VELT-VAULT 2 header".to_owned(),
            ))
        }
    }

    fn load_v1(path: PathBuf, bytes: &[u8], key: &MasterKey) -> Result<Self> {
        if bytes.len() < HEADER_LEN + crypto::TAG_LEN {
            return Err(CoreError::InvalidVault(
                "vault file is truncated".to_owned(),
            ));
        }
        let header = parse_header(&bytes[..HEADER_LEN])?;
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(&bytes[28..HEADER_LEN]);
        let ciphertext = &bytes[HEADER_LEN..];
        let aad = header.aad();

        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.extend_from_slice(&crypto::decrypt(key.expose(), &nonce, &aad, ciphertext)?);
        let payload = parse_payload(&mut plaintext, header)?;

        Ok(Self {
            path,
            header,
            payload,
            format: FORMAT_VERSION,
            key_mode: KeyMode::Local,
        })
    }

    fn load_v2(path: PathBuf, bytes: &[u8], key: &MasterKey) -> Result<Self> {
        let header = parse_text_header(bytes)?;
        let key_mode = parse_text_key_mode(bytes)?;
        let payload = decode_text_payload(bytes, header, &key_mode, key)?;
        Ok(Self {
            path,
            header,
            payload,
            format: TEXT_FORMAT_VERSION,
            key_mode,
        })
    }

    /// Encrypt every entry independently and persist the line format.
    ///
    /// Saves are atomic and idempotent: unchanged entries serialize to the
    /// same lines, which keeps Git diffs and three-way merges line-oriented.
    pub fn save(&mut self, key: &MasterKey) -> Result<()> {
        self.payload.schema = TEXT_SCHEMA_VERSION;
        self.payload.checksum.clear();
        self.payload.updated_at = self
            .payload
            .entries
            .values()
            .map(|entry| entry.updated_at)
            .max()
            .unwrap_or(self.payload.created_at)
            .max(self.payload.created_at);
        if self.payload.revision == 0 {
            self.payload.revision = 1;
        }

        let bytes = encode_text_vault(&self.payload, &self.header, &self.key_mode, key)?;
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(CoreError::InvalidVault(format!(
                "encoded vault exceeds the {MAX_VAULT_BYTES} byte limit"
            )));
        }
        write_atomic(&self.path, &bytes)?;
        self.format = TEXT_FORMAT_VERSION;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id_hex(&self) -> String {
        self.header.vault_id_hex()
    }

    pub fn revision(&self) -> u64 {
        self.payload.revision
    }

    /// On-disk format version (1 legacy, 2 line-oriented).
    pub fn format_version(&self) -> u8 {
        self.format
    }

    pub fn key_mode(&self) -> &KeyMode {
        &self.key_mode
    }

    pub fn set_key_mode(&mut self, key_mode: KeyMode) {
        self.key_mode = key_mode;
    }

    /// Write an independently encrypted copy for a shared/committed file.
    /// The in-memory vault and its original path are unchanged.
    pub fn export_to(
        &self,
        path: impl AsRef<Path>,
        key_mode: KeyMode,
        key: &MasterKey,
    ) -> Result<()> {
        let mut payload = self.payload.clone();
        payload.schema = TEXT_SCHEMA_VERSION;
        payload.checksum.clear();
        if let (KeyMode::Team { epoch, .. }, Some(binding)) = (&key_mode, &mut payload.binding) {
            binding.epoch = *epoch;
        }
        let bytes = encode_text_vault(&payload, &self.header, &key_mode, key)?;
        if bytes.len() as u64 > MAX_VAULT_BYTES {
            return Err(CoreError::InvalidVault(format!(
                "exported vault exceeds the {MAX_VAULT_BYTES} byte limit"
            )));
        }
        write_atomic(path.as_ref(), &bytes)
    }

    pub fn binding(&self) -> Option<&RemoteBinding> {
        self.payload.binding.as_ref()
    }

    pub fn set_binding(&mut self, binding: Option<RemoteBinding>) {
        self.payload.binding = binding;
    }

    /// Insert or replace a secret.
    pub fn set(
        &mut self,
        name: &str,
        value: impl Into<SecretValue>,
        expires_at: Option<i64>,
    ) -> Result<()> {
        validate_name(name)?;
        let value = value.into();
        validate_value(name, value.expose())?;
        self.payload.entries.insert(
            name.to_owned(),
            Entry {
                value,
                updated_at: now_unix(),
                expires_at,
            },
        );
        Ok(())
    }

    /// Remove a secret, returning whether it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.payload.entries.remove(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.payload.entries.get(name)
    }

    pub fn entries(&self) -> &BTreeMap<String, Entry> {
        &self.payload.entries
    }

    pub fn entries_mut(&mut self) -> &mut BTreeMap<String, Entry> {
        &mut self.payload.entries
    }

    /// Produce zeroizing environment pairs for process injection.
    pub fn env_pairs(&self) -> Vec<(String, Zeroizing<String>)> {
        self.payload
            .entries
            .iter()
            .map(|(name, entry)| {
                (
                    name.clone(),
                    Zeroizing::new(entry.value.expose().to_owned()),
                )
            })
            .collect()
    }
}

/// Validate an environment variable name.
///
/// Portable rule: `[A-Za-z_][A-Za-z0-9_]*`, max 256 bytes. This avoids names
/// that cannot be injected into a child process on Windows or POSIX.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(CoreError::InvalidName {
            name: name.to_owned(),
            reason: "name is empty",
        });
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(CoreError::InvalidName {
            name: name.to_owned(),
            reason: "name is longer than 256 bytes",
        });
    }
    let bytes = name.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(CoreError::InvalidName {
            name: name.to_owned(),
            reason: "must start with an ASCII letter or underscore",
        });
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(CoreError::InvalidName {
            name: name.to_owned(),
            reason: "may only contain ASCII letters, digits and underscores",
        });
    }
    Ok(())
}

/// Validate an environment variable value.
pub fn validate_value(name: &str, value: &str) -> Result<()> {
    if value.len() > MAX_SECRET_BYTES {
        return Err(CoreError::InvalidValue {
            name: name.to_owned(),
            reason: "value exceeds 1 MiB",
        });
    }
    if value.contains('\0') {
        return Err(CoreError::InvalidValue {
            name: name.to_owned(),
            reason: "value contains a NUL byte, which cannot be passed to a child process",
        });
    }
    Ok(())
}

fn parse_text_header(bytes: &[u8]) -> Result<VaultHeader> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::InvalidVault("vault file is not valid UTF-8".to_owned()))?;
    let mut lines = text.lines();
    let first = lines
        .next()
        .ok_or_else(|| CoreError::InvalidVault("vault file is empty".to_owned()))?;
    if first.trim_end() != TEXT_MAGIC {
        return Err(CoreError::InvalidVault(
            "missing VELT-VAULT 2 header".to_owned(),
        ));
    }
    let mut id: Option<VaultId> = None;
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("id ") {
            if id.is_some() {
                return Err(CoreError::InvalidVault(
                    "duplicate vault id line".to_owned(),
                ));
            }
            id = Some(parse_vault_id_hex(value)?);
            break;
        }
    }
    id.map(|vault_id| VaultHeader { vault_id })
        .ok_or_else(|| CoreError::InvalidVault("vault id is missing".to_owned()))
}

fn parse_vault_id_hex(value: &str) -> Result<VaultId> {
    let bytes = hex::decode(value)
        .map_err(|_| CoreError::InvalidVault("vault id is not valid hex".to_owned()))?;
    if bytes.len() != VAULT_ID_LEN {
        return Err(CoreError::InvalidVault(
            "vault id must be exactly 16 bytes".to_owned(),
        ));
    }
    let mut vault_id = [0u8; VAULT_ID_LEN];
    vault_id.copy_from_slice(&bytes);
    Ok(vault_id)
}

/// Metadata visible without decrypting a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMetadata {
    pub vault_id: VaultId,
    pub key_mode: KeyMode,
}

fn parse_text_key_mode(bytes: &[u8]) -> Result<KeyMode> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::InvalidVault("vault file is not valid UTF-8".to_owned()))?;
    let mut mode: Option<KeyMode> = None;
    for line in text.lines() {
        let line = line.trim_end();
        let Some(value) = line.strip_prefix("key_mode ") else {
            continue;
        };
        if mode.is_some() {
            return Err(CoreError::InvalidVault(
                "duplicate key_mode line".to_owned(),
            ));
        }
        let mut parts = value.split(' ');
        match parts.next() {
            Some("local") => {
                if parts.next().is_some() {
                    return Err(CoreError::InvalidVault(
                        "key_mode local takes no arguments".to_owned(),
                    ));
                }
                mode = Some(KeyMode::Local);
            }
            Some("team") => {
                let team_id = parts.next().ok_or_else(|| {
                    CoreError::InvalidVault("key_mode team is missing a team id".to_owned())
                })?;
                let team_id = uuid::Uuid::parse_str(team_id)
                    .map_err(|_| {
                        CoreError::InvalidVault("key_mode team id is not a UUID".to_owned())
                    })?
                    .to_string();
                let epoch = parts
                    .next()
                    .ok_or_else(|| {
                        CoreError::InvalidVault("key_mode team is missing an epoch".to_owned())
                    })?
                    .parse::<u32>()
                    .map_err(|_| {
                        CoreError::InvalidVault("key_mode team epoch is not an integer".to_owned())
                    })?;
                if epoch == 0 {
                    return Err(CoreError::InvalidVault(
                        "key_mode team epoch must be positive".to_owned(),
                    ));
                }
                if parts.next().is_some() {
                    return Err(CoreError::InvalidVault(
                        "key_mode team has extra fields".to_owned(),
                    ));
                }
                mode = Some(KeyMode::Team { team_id, epoch });
            }
            Some(other) => {
                return Err(CoreError::InvalidVault(format!(
                    "unknown key_mode {other:?}"
                )));
            }
            None => return Err(CoreError::InvalidVault("empty key_mode line".to_owned())),
        }
    }
    Ok(mode.unwrap_or(KeyMode::Local))
}

fn validate_text_payload(
    payload: &VaultPayload,
    header: &VaultHeader,
    key_mode: &KeyMode,
) -> Result<()> {
    if payload.schema != TEXT_SCHEMA_VERSION {
        return Err(CoreError::InvalidVault(format!(
            "cannot write payload schema {} as format 2",
            payload.schema
        )));
    }
    if payload.vault_id != header.vault_id_hex() {
        return Err(CoreError::InvalidVault(
            "payload vault id does not match the file header".to_owned(),
        ));
    }
    if payload.created_at <= 0 {
        return Err(CoreError::InvalidVault(
            "created_at must be positive".to_owned(),
        ));
    }
    if payload.key_version != MASTER_KEY_VERSION {
        return Err(CoreError::UnsupportedVersion {
            found: payload.key_version.min(u8::MAX as u32) as u8,
            supported: MASTER_KEY_VERSION as u8,
        });
    }
    if payload.entries.len() > 100_000 {
        return Err(CoreError::InvalidVault("too many vault entries".to_owned()));
    }
    for (name, entry) in &payload.entries {
        validate_name(name)?;
        validate_value(name, entry.value.expose())?;
        if entry.updated_at <= 0 {
            return Err(CoreError::InvalidVault(format!(
                "entry {name} has a non-positive updated_at"
            )));
        }
    }
    if let Some(binding) = &payload.binding {
        if binding.team_id.is_empty() || binding.environment.is_empty() {
            return Err(CoreError::InvalidVault(
                "binding is missing a team id or environment".to_owned(),
            ));
        }
        if let KeyMode::Team { team_id, .. } = key_mode {
            if &binding.team_id != team_id {
                return Err(CoreError::InvalidVault(
                    "team vault key mode and binding name different teams".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn entry_aad(
    vault_id: &str,
    key_version: u32,
    name: &str,
    updated_at: i64,
    expires_at: Option<i64>,
    key_mode: &KeyMode,
) -> String {
    let expires = match expires_at {
        Some(value) => value.to_string(),
        None => "-".to_owned(),
    };
    format!(
        "velt-vault-entry-v2|{vault_id}|{key_version}|{name}|{updated_at}|{expires}{}",
        key_mode.suffix()
    )
}

fn binding_aad(vault_id: &str, key_version: u32, key_mode: &KeyMode) -> String {
    format!(
        "velt-vault-binding-v2|{vault_id}|{key_version}{}",
        key_mode.suffix()
    )
}

fn encode_text_vault(
    payload: &VaultPayload,
    header: &VaultHeader,
    key_mode: &KeyMode,
    key: &MasterKey,
) -> Result<Vec<u8>> {
    validate_text_payload(payload, header, key_mode)?;
    let siv_key = crypto::derive_siv_key(key.expose())?;
    let id_hex = header.vault_id_hex();
    let mut out = String::new();
    out.push_str(TEXT_MAGIC);
    out.push('\n');
    out.push_str("id ");
    out.push_str(&id_hex);
    out.push('\n');
    out.push_str("created_at ");
    out.push_str(&payload.created_at.to_string());
    out.push('\n');
    out.push_str("key_version ");
    out.push_str(&payload.key_version.to_string());
    out.push('\n');
    if let KeyMode::Team { team_id, epoch } = key_mode {
        out.push_str("key_mode team ");
        out.push_str(team_id);
        out.push(' ');
        out.push_str(&epoch.to_string());
        out.push('\n');
    }

    if let Some(binding) = &payload.binding {
        let json = Zeroizing::new(serde_json::to_vec(binding)?);
        let suffix = key_mode.suffix();
        let nonce = crypto::binding_nonce(&header.vault_id, &suffix);
        let aad = binding_aad(&id_hex, payload.key_version, key_mode);
        let ciphertext = crypto::siv_encrypt(&siv_key, &nonce, aad.as_bytes(), &json)?;
        out.push_str("binding ");
        out.push_str(&URL_SAFE_NO_PAD.encode(ciphertext));
        out.push('\n');
    }

    for (name, entry) in &payload.entries {
        validate_name(name)?;
        validate_value(name, entry.value.expose())?;
        let suffix = key_mode.suffix();
        let nonce = crypto::entry_nonce(&header.vault_id, name, &suffix);
        let aad = entry_aad(
            &id_hex,
            payload.key_version,
            name,
            entry.updated_at,
            entry.expires_at,
            key_mode,
        );
        let ciphertext = crypto::siv_encrypt(
            &siv_key,
            &nonce,
            aad.as_bytes(),
            entry.value.expose().as_bytes(),
        )?;
        out.push_str("ENTRY ");
        out.push_str(name);
        out.push(' ');
        out.push_str(&entry.updated_at.to_string());
        out.push(' ');
        match entry.expires_at {
            Some(value) => out.push_str(&value.to_string()),
            None => out.push('-'),
        }
        out.push(' ');
        out.push_str(&URL_SAFE_NO_PAD.encode(ciphertext));
        out.push('\n');
    }

    Ok(out.into_bytes())
}

fn decode_text_payload(
    bytes: &[u8],
    header: VaultHeader,
    key_mode: &KeyMode,
    key: &MasterKey,
) -> Result<VaultPayload> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CoreError::InvalidVault("vault file is not valid UTF-8".to_owned()))?;
    let id_hex = header.vault_id_hex();
    let siv_key = crypto::derive_siv_key(key.expose())?;

    let mut created_at: Option<i64> = None;
    let mut key_version: Option<u32> = None;
    let mut binding: Option<RemoteBinding> = None;
    let mut raw_entries: Vec<(String, i64, Option<i64>, Vec<u8>)> = Vec::new();
    let mut seen_names = std::collections::BTreeSet::new();
    let mut seen_id = false;
    let mut seen_key_mode = false;

    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if index == 0 {
            if line != TEXT_MAGIC {
                return Err(CoreError::InvalidVault(
                    "missing VELT-VAULT 2 header".to_owned(),
                ));
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("id ") {
            if seen_id {
                return Err(CoreError::InvalidVault(
                    "duplicate vault id line".to_owned(),
                ));
            }
            if parse_vault_id_hex(value)? != header.vault_id {
                return Err(CoreError::InvalidVault(
                    "vault id line changed while parsing".to_owned(),
                ));
            }
            seen_id = true;
        } else if let Some(value) = line.strip_prefix("created_at ") {
            if created_at.is_some() {
                return Err(CoreError::InvalidVault(
                    "duplicate created_at line".to_owned(),
                ));
            }
            let parsed = value
                .parse::<i64>()
                .map_err(|_| CoreError::InvalidVault("created_at is not an integer".to_owned()))?;
            if parsed <= 0 {
                return Err(CoreError::InvalidVault(
                    "created_at must be positive".to_owned(),
                ));
            }
            created_at = Some(parsed);
        } else if let Some(value) = line.strip_prefix("key_version ") {
            if key_version.is_some() {
                return Err(CoreError::InvalidVault(
                    "duplicate key_version line".to_owned(),
                ));
            }
            let parsed = value
                .parse::<u32>()
                .map_err(|_| CoreError::InvalidVault("key_version is not an integer".to_owned()))?;
            if parsed != MASTER_KEY_VERSION {
                return Err(CoreError::UnsupportedVersion {
                    found: parsed.min(u8::MAX as u32) as u8,
                    supported: MASTER_KEY_VERSION as u8,
                });
            }
            key_version = Some(parsed);
        } else if line.starts_with("key_mode ") {
            if seen_key_mode {
                return Err(CoreError::InvalidVault(
                    "duplicate key_mode line".to_owned(),
                ));
            }
            let parsed = parse_text_key_mode(line.as_bytes())?;
            if &parsed != key_mode {
                return Err(CoreError::InvalidVault(
                    "key_mode line changed while parsing".to_owned(),
                ));
            }
            seen_key_mode = true;
        } else if let Some(value) = line.strip_prefix("binding ") {
            if binding.is_some() {
                return Err(CoreError::InvalidVault("duplicate binding line".to_owned()));
            }
            let ciphertext = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
                CoreError::InvalidVault("binding ciphertext is not valid base64".to_owned())
            })?;
            let suffix = key_mode.suffix();
            let nonce = crypto::binding_nonce(&header.vault_id, &suffix);
            let aad = binding_aad(&id_hex, MASTER_KEY_VERSION, key_mode);
            let plaintext = crypto::siv_decrypt(&siv_key, &nonce, aad.as_bytes(), &ciphertext)?;
            let parsed: RemoteBinding = serde_json::from_slice(plaintext.as_slice())?;
            if parsed.team_id.is_empty() || parsed.environment.is_empty() {
                return Err(CoreError::InvalidVault(
                    "binding is missing a team id or environment".to_owned(),
                ));
            }
            binding = Some(parsed);
        } else if let Some(rest) = line.strip_prefix("ENTRY ") {
            if raw_entries.len() >= 100_000 {
                return Err(CoreError::InvalidVault("too many vault entries".to_owned()));
            }
            let mut parts = rest.splitn(4, ' ');
            let name = parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| CoreError::InvalidVault("entry is missing a name".to_owned()))?;
            validate_name(name)?;
            let updated = parts
                .next()
                .ok_or_else(|| CoreError::InvalidVault("entry is missing updated_at".to_owned()))?;
            let expected = parts
                .next()
                .ok_or_else(|| CoreError::InvalidVault("entry is missing expires_at".to_owned()))?;
            let encoded = parts
                .next()
                .ok_or_else(|| CoreError::InvalidVault("entry is missing ciphertext".to_owned()))?;
            if encoded.is_empty() {
                return Err(CoreError::InvalidVault(
                    "entry ciphertext is empty".to_owned(),
                ));
            }
            if !seen_names.insert(name.to_owned()) {
                return Err(CoreError::InvalidVault(format!(
                    "duplicate vault entry {name}"
                )));
            }
            let updated_at = updated.parse::<i64>().map_err(|_| {
                CoreError::InvalidVault("entry updated_at is not an integer".to_owned())
            })?;
            if updated_at <= 0 {
                return Err(CoreError::InvalidVault(
                    "entry updated_at must be positive".to_owned(),
                ));
            }
            let expires_at = match expected {
                "-" => None,
                other => Some(other.parse::<i64>().map_err(|_| {
                    CoreError::InvalidVault("entry expires_at is not an integer".to_owned())
                })?),
            };
            let ciphertext = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
                CoreError::InvalidVault("entry ciphertext is not valid base64".to_owned())
            })?;
            raw_entries.push((name.to_owned(), updated_at, expires_at, ciphertext));
        } else {
            return Err(CoreError::InvalidVault(format!(
                "unknown vault line: {}",
                line.chars().take(40).collect::<String>()
            )));
        }
    }

    let created_at = created_at
        .ok_or_else(|| CoreError::InvalidVault("created_at line is missing".to_owned()))?;
    key_version.ok_or_else(|| CoreError::InvalidVault("key_version line is missing".to_owned()))?;

    let mut entries = BTreeMap::new();
    let mut updated_at = created_at;
    for (name, entry_updated_at, expires_at, ciphertext) in raw_entries {
        let aad = entry_aad(
            &id_hex,
            MASTER_KEY_VERSION,
            &name,
            entry_updated_at,
            expires_at,
            key_mode,
        );
        let suffix = key_mode.suffix();
        let nonce = crypto::entry_nonce(&header.vault_id, &name, &suffix);
        let plaintext = crypto::siv_decrypt(&siv_key, &nonce, aad.as_bytes(), &ciphertext)?;
        let value = std::str::from_utf8(plaintext.as_slice()).map_err(|_| {
            CoreError::InvalidVault("decrypted entry is not valid UTF-8".to_owned())
        })?;
        validate_value(&name, value)?;
        updated_at = updated_at.max(entry_updated_at);
        entries.insert(
            name,
            Entry {
                value: SecretValue::from(value.to_owned()),
                updated_at: entry_updated_at,
                expires_at,
            },
        );
    }

    if let (KeyMode::Team { team_id, .. }, Some(binding)) = (key_mode, &binding) {
        if &binding.team_id != team_id {
            return Err(CoreError::InvalidVault(
                "team vault key mode and binding name different teams".to_owned(),
            ));
        }
    }

    Ok(VaultPayload {
        schema: TEXT_SCHEMA_VERSION,
        vault_id: id_hex,
        created_at,
        updated_at,
        revision: 1,
        key_version: MASTER_KEY_VERSION,
        entries,
        binding,
        checksum: String::new(),
    })
}

/// Parse and validate a legacy format 1 header.
pub fn parse_header(bytes: &[u8]) -> Result<VaultHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(CoreError::InvalidVault(
            "file is shorter than the header".into(),
        ));
    }
    if &bytes[..8] != MAGIC {
        return Err(CoreError::InvalidVault(
            "missing VELTVLT1 magic bytes".to_owned(),
        ));
    }
    let version = bytes[8];
    if version != FORMAT_VERSION {
        return Err(CoreError::UnsupportedVersion {
            found: version,
            supported: FORMAT_VERSION,
        });
    }
    if bytes[9..12] != [0, 0, 0] {
        return Err(CoreError::InvalidVault(
            "reserved header bytes are not zero".to_owned(),
        ));
    }
    let mut vault_id = [0u8; VAULT_ID_LEN];
    vault_id.copy_from_slice(&bytes[12..28]);
    Ok(VaultHeader { vault_id })
}

/// Read the vault id without decrypting the payload.
pub fn read_vault_metadata(path: &Path) -> Result<VaultMetadata> {
    let bytes = read_vault_file(path)?;
    if bytes.starts_with(MAGIC) {
        if bytes.len() < HEADER_LEN {
            return Err(CoreError::InvalidVault(
                "legacy vault header is truncated".to_owned(),
            ));
        }
        Ok(VaultMetadata {
            vault_id: parse_header(&bytes[..HEADER_LEN])?.vault_id,
            key_mode: KeyMode::Local,
        })
    } else if bytes.starts_with(TEXT_MAGIC.as_bytes()) {
        Ok(VaultMetadata {
            vault_id: parse_text_header(&bytes)?.vault_id,
            key_mode: parse_text_key_mode(&bytes)?,
        })
    } else {
        Err(CoreError::InvalidVault(
            "file has neither a VELTVLT1 nor a VELT-VAULT 2 header".to_owned(),
        ))
    }
}

pub fn read_vault_id(path: &Path) -> Result<VaultId> {
    Ok(read_vault_metadata(path)?.vault_id)
}

fn open_vault_file(path: &Path) -> Result<File> {
    let metadata = fs::metadata(path).map_err(|err| CoreError::io(path, err))?;
    if !metadata.is_file() {
        return Err(CoreError::InvalidVault(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_VAULT_BYTES {
        return Err(CoreError::InvalidVault(format!(
            "vault file exceeds the {MAX_VAULT_BYTES} byte limit"
        )));
    }
    if metadata.len() == 0 {
        return Err(CoreError::InvalidVault("vault file is empty".to_owned()));
    }
    let file = File::open(path).map_err(|err| CoreError::io(path, err))?;
    Ok(file)
}

fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    let file = open_vault_file(path)?;
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| CoreError::io(path, err))?;
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(CoreError::InvalidVault(
            "vault file grew beyond the size limit while reading".to_owned(),
        ));
    }
    if bytes.is_empty() {
        return Err(CoreError::InvalidVault("vault file is empty".to_owned()));
    }
    Ok(bytes)
}

fn parse_payload(plaintext: &mut Zeroizing<Vec<u8>>, header: VaultHeader) -> Result<VaultPayload> {
    let payload: VaultPayload = serde_json::from_slice(plaintext.as_slice())?;
    plaintext.zeroize();
    payload.validate(header)?;
    Ok(payload)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".velt-vault-")
        .tempfile_in(directory)
        .map_err(|err| CoreError::io(directory, err))?;
    temp.as_file_mut()
        .write_all(bytes)
        .map_err(|err| CoreError::io(temp.path(), err))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| CoreError::io(temp.path(), err))?;
    temp.persist(path)
        .map_err(|error| CoreError::io(path, error.error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The temporary file was created 0600; this is a belt-and-braces
        // adjustment and must not fail a save that already landed.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    if let Ok(directory_file) = File::open(directory) {
        let _ = directory_file.sync_all();
    }
    Ok(())
}

/// Advisory exclusive lock held while a vault is read-modified-written.
///
/// The lock file lives in the OS temporary directory, keyed by the canonical
/// vault path, so it never pollutes the project tree. It is not a security
/// boundary; it prevents two velt commands from losing each other's updates.
pub struct VaultLock {
    _file: File,
}

impl VaultLock {
    pub fn acquire(vault_path: &Path) -> Result<Self> {
        let canonical = canonical_lock_target(vault_path);
        let digest = crypto::sha256(format!("{}", canonical.display()).as_bytes());
        let lock_path =
            std::env::temp_dir().join(format!("velt-{}.lock", hex::encode(&digest[..16])));
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&lock_path)
            .map_err(|err| CoreError::io(&lock_path, err))?;
        fs2::FileExt::lock_exclusive(&file).map_err(|err| CoreError::io(&lock_path, err))?;
        Ok(Self { _file: file })
    }
}

fn canonical_lock_target(vault_path: &Path) -> PathBuf {
    if let Ok(canonical) = vault_path.canonicalize() {
        return canonical;
    }
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    match vault_path.file_name() {
        Some(name) => canonical_parent.join(name),
        None => canonical_parent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use std::process::Command;
    use tempfile::TempDir;

    fn key() -> MasterKey {
        MasterKey::from_slice(&[9u8; 32]).unwrap()
    }

    fn new_vault(dir: &TempDir) -> (Vault, PathBuf) {
        let path = dir.path().join(".velt.vault");
        let mut vault = Vault::new(&path, None).unwrap();
        vault
            .set("DATABASE_URL", "postgres://localhost/app", None)
            .unwrap();
        vault.set("API_TOKEN", "token-value", None).unwrap();
        vault.save(&key()).unwrap();
        (vault, path)
    }

    fn entry_lines(text: &str) -> Vec<String> {
        text.lines()
            .filter(|line| line.starts_with("ENTRY "))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn create_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let (created, path) = new_vault(&dir);
        assert_eq!(created.format_version(), 2);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("VELT-VAULT 2\n"));
        assert!(text.contains("ENTRY API_TOKEN "));

        let loaded = Vault::load(&path, &key()).unwrap();
        assert_eq!(loaded.format_version(), 2);
        assert_eq!(loaded.vault_id_hex(), created.vault_id_hex());
        assert_eq!(
            loaded.get("DATABASE_URL").unwrap().value.expose(),
            "postgres://localhost/app"
        );
        assert_eq!(loaded.entries().len(), 2);
        assert_eq!(read_vault_id(&path).unwrap(), loaded.header.vault_id);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let wrong = MasterKey::from_slice(&[1u8; 32]).unwrap();
        assert!(matches!(
            Vault::load(&path, &wrong),
            Err(CoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        let mut changed = false;
        let lines: Vec<String> = text
            .lines()
            .map(|line| {
                if changed || !line.starts_with("ENTRY API_TOKEN ") {
                    return line.to_owned();
                }
                let fields: Vec<&str> = line
                    .strip_prefix("ENTRY ")
                    .unwrap_or_default()
                    .split(' ')
                    .collect();
                if fields.len() != 4 {
                    return line.to_owned();
                }
                let mut ciphertext = URL_SAFE_NO_PAD.decode(fields[3]).unwrap();
                ciphertext[0] ^= 0x80;
                changed = true;
                format!(
                    "ENTRY {} {} {} {}",
                    fields[0],
                    fields[1],
                    fields[2],
                    URL_SAFE_NO_PAD.encode(ciphertext)
                )
            })
            .collect();
        assert!(changed);
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_metadata_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<String> = text
            .lines()
            .map(|line| {
                if !line.starts_with("ENTRY API_TOKEN ") {
                    return line.to_owned();
                }
                let fields: Vec<&str> = line
                    .strip_prefix("ENTRY ")
                    .unwrap_or_default()
                    .split(' ')
                    .collect();
                format!("ENTRY {} 1 {} {}", fields[0], fields[2], fields[3])
            })
            .collect();
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn truncated_file_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        fs::write(&path, b"VELTVLT1").unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::InvalidVault(_))
        ));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = b'X';
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::InvalidVault(_))
        ));
    }

    #[test]
    fn saves_are_deterministic_and_idempotent() {
        let dir = TempDir::new().unwrap();
        let (mut vault, path) = new_vault(&dir);
        let first = fs::read(&path).unwrap();
        vault.save(&key()).unwrap();
        let second = fs::read(&path).unwrap();
        assert_eq!(first, second);

        let before = entry_lines(&String::from_utf8(first).unwrap());
        vault.set("NEW_KEY", "new-value", None).unwrap();
        vault.save(&key()).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let after = entry_lines(&text);
        for line in &before {
            assert!(after.contains(line), "unchanged entry line changed: {line}");
        }
        assert!(after.iter().any(|line| line.starts_with("ENTRY NEW_KEY ")));
    }

    #[test]
    fn duplicate_entries_fail_closed() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        let duplicate = text
            .lines()
            .find(|line| line.starts_with("ENTRY "))
            .unwrap();
        fs::write(&path, format!("{text}{duplicate}\n")).unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::InvalidVault(_))
        ));
    }

    #[test]
    fn values_never_appear_in_plaintext() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("token-value"));
        assert!(!text.contains("postgres://localhost/app"));
        assert!(text.contains("DATABASE_URL"));
        assert!(text.contains("API_TOKEN"));
    }

    #[test]
    fn binding_roundtrip() {
        let dir = TempDir::new().unwrap();
        let binding = RemoteBinding {
            team_id: "team-1".to_owned(),
            environment: "production".to_owned(),
            epoch: 2,
            base_version: 7,
            base_checksum: Some("00".repeat(32)),
        };
        let path = dir.path().join(".velt.vault");
        let mut vault = Vault::new(&path, Some(binding.clone())).unwrap();
        vault.set("KEY", "value", None).unwrap();
        vault.save(&key()).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("team-1"));
        let loaded = Vault::load(&path, &key()).unwrap();
        assert_eq!(loaded.binding(), Some(&binding));
    }

    #[test]
    fn team_mode_export_roundtrip() {
        let dir = TempDir::new().unwrap();
        let local_path = dir.path().join(".velt.vault");
        let shared_path = dir.path().join(".velt.shared.vault");
        let local_key = key();
        let team_key = MasterKey::from_slice(&[0x77; 32]).unwrap();
        let team_id = "00000000-0000-0000-0000-000000000001".to_owned();

        let mut vault = Vault::new(&local_path, None).unwrap();
        vault.set("API_KEY", "team-secret", None).unwrap();
        vault.save(&local_key).unwrap();
        assert_eq!(vault.key_mode(), &KeyMode::Local);

        vault
            .export_to(
                &shared_path,
                KeyMode::Team {
                    team_id: team_id.clone(),
                    epoch: 2,
                },
                &team_key,
            )
            .unwrap();
        let text = fs::read_to_string(&shared_path).unwrap();
        assert!(text.contains("key_mode team 00000000-0000-0000-0000-000000000001 2"));
        assert!(!text.contains("team-secret"));

        let metadata = read_vault_metadata(&shared_path).unwrap();
        assert_eq!(metadata.vault_id, vault.header.vault_id);
        assert_eq!(metadata.key_mode, KeyMode::Team { team_id, epoch: 2 });

        let loaded = Vault::load(&shared_path, &team_key).unwrap();
        assert_eq!(loaded.key_mode(), &metadata.key_mode);
        assert_eq!(loaded.get("API_KEY").unwrap().value.expose(), "team-secret");
        assert!(matches!(
            Vault::load(&shared_path, &local_key),
            Err(CoreError::AuthenticationFailed)
        ));

        // The source vault remains a local-key vault.
        let source = Vault::load(&local_path, &local_key).unwrap();
        assert_eq!(source.key_mode(), &KeyMode::Local);
    }

    #[test]
    fn tampered_team_mode_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".velt.vault");
        let team_key = MasterKey::from_slice(&[0x77; 32]).unwrap();
        let mut vault = Vault::new(&path, None).unwrap();
        vault.set("API_KEY", "team-secret", None).unwrap();
        vault.set_key_mode(KeyMode::Team {
            team_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            epoch: 2,
        });
        vault.save(&team_key).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let tampered = text.replace(
            "key_mode team 00000000-0000-0000-0000-000000000001 2",
            "key_mode team 00000000-0000-0000-0000-000000000002 2",
        );
        fs::write(&path, tampered).unwrap();
        assert!(matches!(
            Vault::load(&path, &team_key),
            Err(CoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn stale_v1_vault_is_migrated_on_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".velt.vault");
        let vault_id = [3u8; VAULT_ID_LEN];
        let header = VaultHeader { vault_id };
        let mut entries = BTreeMap::new();
        entries.insert(
            "LEGACY_KEY".to_owned(),
            Entry {
                value: SecretValue::from("legacy-value"),
                updated_at: now_unix(),
                expires_at: None,
            },
        );
        let mut payload = VaultPayload {
            schema: SCHEMA_VERSION,
            vault_id: header.vault_id_hex(),
            created_at: now_unix(),
            updated_at: now_unix(),
            revision: 1,
            key_version: MASTER_KEY_VERSION,
            entries,
            binding: None,
            checksum: String::new(),
        };
        payload.checksum = payload.compute_checksum().unwrap();
        let body = Zeroizing::new(serde_json::to_vec(&payload).unwrap());
        let nonce = crypto::random_nonce().unwrap();
        let ciphertext = crypto::encrypt(key().expose(), &nonce, &header.aad(), &body).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&vault_id);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        fs::write(&path, bytes).unwrap();

        let mut vault = Vault::load(&path, &key()).unwrap();
        assert_eq!(vault.format_version(), 1);
        assert_eq!(
            vault.get("LEGACY_KEY").unwrap().value.expose(),
            "legacy-value"
        );
        vault.save(&key()).unwrap();
        assert_eq!(vault.format_version(), 2);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("VELT-VAULT 2\n"));
        let reloaded = Vault::load(&path, &key()).unwrap();
        assert_eq!(
            reloaded.get("LEGACY_KEY").unwrap().value.expose(),
            "legacy-value"
        );
    }

    #[test]
    fn disjoint_branches_merge_with_git() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("base.vault");
        let mut vault = Vault::new(&base, None).unwrap();
        vault.set("MIDDLE_A", "a", None).unwrap();
        vault.set("MIDDLE_Z", "z", None).unwrap();
        vault.save(&key()).unwrap();

        let left = dir.path().join("left.vault");
        let right = dir.path().join("right.vault");
        fs::copy(&base, &left).unwrap();
        fs::copy(&base, &right).unwrap();

        let mut left_vault = Vault::load(&left, &key()).unwrap();
        left_vault.set("ALPHA", "left", None).unwrap();
        left_vault.save(&key()).unwrap();
        let mut right_vault = Vault::load(&right, &key()).unwrap();
        right_vault.set("ZULU", "right", None).unwrap();
        right_vault.save(&key()).unwrap();

        let output = Command::new("git")
            .args([
                "merge-file",
                "-p",
                left.to_str().unwrap(),
                base.to_str().unwrap(),
                right.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git merge-file failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let merged = dir.path().join("merged.vault");
        fs::write(&merged, &output.stdout).unwrap();

        let loaded = Vault::load(&merged, &key()).unwrap();
        for name in ["ALPHA", "MIDDLE_A", "MIDDLE_Z", "ZULU"] {
            assert!(loaded.get(name).is_some(), "missing merged key {name}");
        }
    }

    #[test]
    fn known_answer_vector() {
        let key = MasterKey::from_slice(&[0x42; 32]).unwrap();
        let header = VaultHeader {
            vault_id: [0x11; VAULT_ID_LEN],
        };
        let mut entries = BTreeMap::new();
        entries.insert(
            "API_KEY".to_owned(),
            Entry {
                value: SecretValue::from("secret-value"),
                updated_at: 1_700_000_001,
                expires_at: None,
            },
        );
        let payload = VaultPayload {
            schema: TEXT_SCHEMA_VERSION,
            vault_id: header.vault_id_hex(),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_001,
            revision: 1,
            key_version: MASTER_KEY_VERSION,
            entries,
            binding: None,
            checksum: String::new(),
        };
        let text =
            String::from_utf8(encode_text_vault(&payload, &header, &KeyMode::Local, &key).unwrap())
                .unwrap();
        assert_eq!(
            text,
            "VELT-VAULT 2\n\
             id 11111111111111111111111111111111\n\
             created_at 1700000000\n\
             key_version 1\n\
             ENTRY API_KEY 1700000001 - APFtI1nW4Wke0QsGolKTP17vcZN6DibnldrfSQ\n"
        );
    }

    #[test]
    fn duplicate_id_line_fails_closed() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        let id_line = text.lines().find(|line| line.starts_with("id ")).unwrap();
        fs::write(&path, format!("{text}{id_line}\n")).unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::InvalidVault(_))
        ));
    }

    #[test]
    fn unknown_lines_fail_closed() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{text}NOT-A-VAULT-LINE\n")).unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::InvalidVault(_))
        ));
    }

    #[test]
    fn unsupported_key_version_fails_closed() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("key_version 1", "key_version 2")).unwrap();
        assert!(matches!(
            Vault::load(&path, &key()),
            Err(CoreError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn invalid_names_are_rejected() {
        for name in ["", "1KEY", "BAD KEY", "BAD=KEY", &"A".repeat(257)] {
            assert!(validate_name(name).is_err(), "{name:?} should be invalid");
        }
        for name in ["A", "_A", "A_B9", "lower_case"] {
            assert!(validate_name(name).is_ok(), "{name:?} should be valid");
        }
    }

    #[test]
    fn nul_values_are_rejected() {
        let mut vault = Vault::new("unused.vault", None).unwrap();
        assert!(validate_value("X", "a\0b").is_err());
        assert!(vault.set("X", "a\0b", None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn adding_entry_preserves_existing_entries_on_reload() {
        let dir = TempDir::new().unwrap();
        let (mut vault, path) = new_vault(&dir);
        vault.set("NEW", "value", None).unwrap();
        vault.save(&key()).unwrap();
        let loaded = Vault::load(&path, &key()).unwrap();
        assert_eq!(loaded.entries().len(), 3);
    }

    #[test]
    fn lock_is_reentrant_only_after_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".velt.vault");
        let lock = VaultLock::acquire(&path).unwrap();
        drop(lock);
        let _again = VaultLock::acquire(&path).unwrap();
    }
}
