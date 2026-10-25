//! Encrypted vault file format and in-memory vault operations.
//!
//! # File layout (format version 1)
//!
//! ```text
//! offset  size  field
//! 0       8     magic "VELTVLT1"
//! 8       1     format version (1)
//! 9       3     reserved (zero)
//! 12      16    vault id (random, generated once)
//! 28      12    ChaCha20-Poly1305 nonce
//! 40      ..    ciphertext || Poly1305 tag
//! ```
//!
//! The AAD is the first 28 bytes, binding the ciphertext to the magic, format
//! version and vault id. The plaintext is a JSON payload containing the
//! key/value map, timestamps, revision, key version, optional team binding and
//! a SHA-256 checksum over the canonical payload body.
//!
//! Writes are atomic (temporary file in the same directory, fsync, rename) and
//! the resulting file is mode 0600 on Unix. Plaintext buffers are zeroized
//! immediately after parsing.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::secret::SecretValue;

pub const MAGIC: &[u8; 8] = b"VELTVLT1";
pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 40;
pub const VAULT_ID_LEN: usize = 16;
pub const MAX_VAULT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
pub const MAX_NAME_BYTES: usize = 256;
pub const SCHEMA_VERSION: u32 = 1;
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
            schema: SCHEMA_VERSION,
            vault_id: header.vault_id_hex(),
            created_at: timestamp,
            updated_at: timestamp,
            revision: 0,
            key_version: MASTER_KEY_VERSION,
            entries: BTreeMap::new(),
            binding,
            checksum: String::new(),
        };
        Ok(Self {
            path: path.into(),
            header,
            payload,
        })
    }

    /// Read and decrypt an existing vault.
    pub fn load(path: impl Into<PathBuf>, key: &MasterKey) -> Result<Self> {
        let path = path.into();
        let bytes = read_vault_file(&path)?;
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
        })
    }

    /// Encrypt and atomically persist the vault.
    pub fn save(&mut self, key: &MasterKey) -> Result<()> {
        self.payload.revision = self.payload.revision.saturating_add(1);
        self.payload.updated_at = now_unix();
        self.payload.checksum = self.payload.compute_checksum()?;

        let body = Zeroizing::new(serde_json::to_vec(&self.payload)?);
        let nonce = crypto::random_nonce()?;
        let ciphertext = crypto::encrypt(key.expose(), &nonce, &self.header.aad(), &body)?;
        drop(body);

        let mut bytes = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&self.header.vault_id);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);

        write_atomic(&self.path, &bytes)
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

/// Parse and validate a header.
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
pub fn read_vault_id(path: &Path) -> Result<VaultId> {
    let file = open_vault_file(path)?;
    let mut header = [0u8; HEADER_LEN];
    use std::io::Read;
    let mut reader = std::io::BufReader::new(file);
    reader
        .read_exact(&mut header)
        .map_err(|err| CoreError::io(path, err))?;
    Ok(parse_header(&header)?.vault_id)
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
    if metadata.len() < (HEADER_LEN + crypto::TAG_LEN) as u64 {
        return Err(CoreError::InvalidVault(
            "vault file is truncated".to_owned(),
        ));
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
    if bytes.len() < HEADER_LEN + crypto::TAG_LEN {
        return Err(CoreError::InvalidVault(
            "vault file is truncated".to_owned(),
        ));
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

    #[test]
    fn create_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let (created, path) = new_vault(&dir);
        assert_eq!(created.revision(), 1);

        let loaded = Vault::load(&path, &key()).unwrap();
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
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&path, &bytes).unwrap();
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
    fn nonce_changes_on_every_save() {
        let dir = TempDir::new().unwrap();
        let (mut vault, path) = new_vault(&dir);
        let first = fs::read(&path).unwrap();
        vault.save(&key()).unwrap();
        let second = fs::read(&path).unwrap();
        assert_ne!(first[28..40], second[28..40]);
        assert_ne!(first, second);
    }

    #[test]
    fn plaintext_is_wiped_after_parse() {
        let dir = TempDir::new().unwrap();
        let (_, path) = new_vault(&dir);
        let bytes = read_vault_file(&path).unwrap();
        let header = parse_header(&bytes[..HEADER_LEN]).unwrap();
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(&bytes[28..HEADER_LEN]);
        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext.extend_from_slice(
            &crypto::decrypt(key().expose(), &nonce, &header.aad(), &bytes[HEADER_LEN..]).unwrap(),
        );
        assert!(plaintext.windows(8).any(|window| window == b"DATABASE"));
        let payload = parse_payload(&mut plaintext, header).unwrap();
        assert!(plaintext.is_empty(), "plaintext buffer must be wiped");
        assert_eq!(payload.entries.len(), 2);
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
    fn revision_increases() {
        let dir = TempDir::new().unwrap();
        let (mut vault, path) = new_vault(&dir);
        assert_eq!(vault.revision(), 1);
        vault.set("NEW", "value", None).unwrap();
        vault.save(&key()).unwrap();
        assert_eq!(vault.revision(), 2);
        let loaded = Vault::load(&path, &key()).unwrap();
        assert_eq!(loaded.revision(), 2);
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
