//! Relay session management: SSH challenge auth, X25519 identity, team key
//! envelopes and local binding fingerprints.

use std::io::IsTerminal;
use std::path::Path;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use uuid::Uuid;
use velt_core::keychain::{self, KeyStore, OsKeyStore};
use velt_core::sync::{open_team_key, SealedTeamKey, TeamIdentity};
use velt_core::vault::Vault;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::config::{self, Config};
use crate::error::{CliError, Result};

pub const AUTH_NAMESPACE: &str = "velt-auth-v1";

pub struct Session {
    pub config: Config,
    pub api: ApiClient,
    pub identity: TeamIdentity,
}

/// Parse a 32-byte X25519 private key in hex.
pub fn identity_from_hex(value: &str) -> Result<TeamIdentity> {
    let decoded = Zeroizing::new(
        hex::decode(value.trim())
            .map_err(|_| CliError::Config("identity key must be 64 hex characters".to_owned()))?,
    );
    if decoded.len() != 32 {
        return Err(CliError::Config(
            "identity key must be a 32-byte X25519 private key".to_owned(),
        ));
    }
    TeamIdentity::from_secret(&decoded).map_err(CliError::from)
}

/// CI identity bootstrap. The value is a 32-byte X25519 private key in hex.
/// It is read from the environment and never written to the keychain.
pub fn identity_from_env() -> Result<Option<TeamIdentity>> {
    let value = match std::env::var("VELT_IDENTITY_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    Ok(Some(identity_from_hex(&value)?))
}

pub fn identity(server: &str, username: &str) -> Result<TeamIdentity> {
    if let Some(identity) = identity_from_env()? {
        return Ok(identity);
    }
    let account = keychain::identity_account(server, username);
    if let Some(secret) = OsKeyStore.get(&account)? {
        return TeamIdentity::from_secret(&secret).map_err(CliError::from);
    }
    let identity = TeamIdentity::generate()?;
    OsKeyStore.set(&account, identity.secret())?;
    Ok(identity)
}

fn load_token(server: &str, username: &str) -> Result<Option<String>> {
    let account = keychain::session_account(server, username);
    let Some(bytes) = OsKeyStore.get(&account)? else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| CliError::msg("stored session token is not valid UTF-8"))?;
    Ok(Some(text))
}

fn store_token(server: &str, username: &str, token: &str) -> Result<()> {
    let account = keychain::session_account(server, username);
    OsKeyStore.set(&account, token.as_bytes())?;
    Ok(())
}

fn delete_token(server: &str, username: &str) -> Result<()> {
    let account = keychain::session_account(server, username);
    OsKeyStore.delete(&account)?;
    Ok(())
}

pub fn load_ssh_key(config: &Config) -> Result<PrivateKey> {
    // CI platforms often expose the key as an environment variable rather
    // than a file. `VELT_SSH_KEY_CONTENT` takes precedence over the path.
    let (label, key) = if let Ok(content) = std::env::var("VELT_SSH_KEY_CONTENT") {
        if content.trim().is_empty() {
            let path = config.ssh_key_path()?;
            (path.display().to_string(), read_key_file(&path)?)
        } else {
            (
                "VELT_SSH_KEY_CONTENT".to_owned(),
                PrivateKey::from_openssh(&content)
                    .map_err(|error| CliError::msg(format!("could not parse SSH key: {error}")))?,
            )
        }
    } else {
        let path = config.ssh_key_path()?;
        (path.display().to_string(), read_key_file(&path)?)
    };
    let key = if key.is_encrypted() {
        let passphrase = std::env::var("VELT_SSH_KEY_PASSPHRASE")
            .ok()
            .filter(|value| !value.is_empty())
            .map(Ok)
            .unwrap_or_else(|| {
                if std::io::stdin().is_terminal() {
                    rpassword::prompt_password(format!("Passphrase for {label}: "))
                        .map_err(|error| CliError::Terminal(error.to_string()))
                } else {
                    Err(CliError::Config(
                        "SSH key is encrypted; set VELT_SSH_KEY_PASSPHRASE".to_owned(),
                    ))
                }
            })?;
        key.decrypt(passphrase.as_bytes())
            .map_err(|_| CliError::msg("could not decrypt SSH key"))?
    } else {
        key
    };
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(CliError::Config(
            "only Ed25519 SSH keys are supported (ssh-keygen -t ed25519)".to_owned(),
        ));
    }
    Ok(key)
}

fn read_key_file(path: &Path) -> Result<PrivateKey> {
    if !path.is_file() {
        return Err(CliError::Config(format!(
            "SSH private key not found at {}; use --ssh-key, VELT_SSH_KEY_CONTENT, or generate one with ssh-keygen",
            path.display()
        )));
    }
    PrivateKey::read_openssh_file(path)
        .map_err(|error| CliError::msg(format!("could not read SSH key: {error}")))
}

fn authenticate(server: &str, username: &str, key: &PrivateKey) -> Result<String> {
    let api = ApiClient::new(server, None)?;
    let challenge = api.challenge(username)?;
    let challenge_bytes = STANDARD_NO_PAD
        .decode(&challenge.challenge)
        .map_err(|_| CliError::msg("server returned an invalid challenge"))?;
    let signature = key
        .sign(AUTH_NAMESPACE, HashAlg::Sha512, &challenge_bytes)
        .map_err(|error| CliError::msg(format!("could not sign challenge: {error}")))?;
    let pem = signature
        .to_pem(LineEnding::LF)
        .map_err(|error| CliError::msg(format!("could not encode signature: {error}")))?;
    Ok(api.verify(&challenge.challenge_id, &pem)?.token)
}

fn login_with_key(server: &str, username: &str, key: &PrivateKey) -> Result<String> {
    let token = authenticate(server, username, key)?;
    store_token(server, username, &token)?;
    Ok(token)
}

/// Build a session for a headless CI job. The session token and identity key
/// stay in memory only; the OS keychain is not read or written.
pub fn ci_session(
    server: &str,
    username: &str,
    ssh_key: Option<&Path>,
    identity: TeamIdentity,
) -> Result<Session> {
    let server = server.trim().trim_end_matches('/');
    let username = username.trim().trim_start_matches('@').to_ascii_lowercase();
    if username.is_empty() {
        return Err(CliError::Config("CI username is empty".to_owned()));
    }
    if !(server.starts_with("http://") || server.starts_with("https://")) {
        return Err(CliError::Config(
            "server URL must start with http:// or https://".to_owned(),
        ));
    }
    let config = Config {
        server_url: Some(server.to_owned()),
        username: Some(username.clone()),
        ssh_key: ssh_key.map(Path::to_path_buf),
    };
    let key = load_ssh_key(&config)?;
    let token = authenticate(server, &username, &key)?;
    let api = ApiClient::new(server, Some(token))?;
    Ok(Session {
        config,
        api,
        identity,
    })
}

pub fn login(config: &Config) -> Result<String> {
    let server = config.require_server_url()?;
    let username = config.username.clone().ok_or_else(|| {
        CliError::Config(
            "no username configured; run `velt auth login --username <name>`".to_owned(),
        )
    })?;
    let key = load_ssh_key(config)?;
    login_with_key(&server, &username, &key)
}

pub fn register(server: &str, username: &str, ssh_key: Option<&Path>) -> Result<Session> {
    let server = server.trim().trim_end_matches('/');
    let username = username.trim().trim_start_matches('@').to_ascii_lowercase();
    let api = ApiClient::new(server, None)?;
    let mut config = Config {
        server_url: Some(server.to_owned()),
        username: Some(username.clone()),
        ssh_key: ssh_key.map(|path| path.to_path_buf()),
    };
    let key = load_ssh_key(&config)?;
    let identity = identity(server, &username)?;
    let ssh_public = key
        .public_key()
        .to_openssh()
        .map_err(|error| CliError::msg(format!("could not encode SSH public key: {error}")))?;

    match api.register(&username, &ssh_public, &identity.public_base64()) {
        Ok(_) => {}
        Err(CliError::Server { status: 409, .. }) => {
            // Already registered: fall through to challenge auth, which proves
            // possession of the matching private key.
        }
        Err(error) => return Err(error),
    }

    config.ssh_key = Some(config.ssh_key_path()?);
    config::save(&config)?;
    let token = login_with_key(server, &username, &key)?;
    let api = ApiClient::new(server, Some(token))?;
    Ok(Session {
        config,
        api,
        identity,
    })
}

pub fn session() -> Result<Session> {
    let config = config::load()?;
    let server = config.require_server_url()?;
    let username = config.username.clone().ok_or_else(|| {
        CliError::Config(
            "no username configured; run `velt auth register` or `velt auth login`".to_owned(),
        )
    })?;
    let identity = identity(&server, &username)?;
    let token = match load_token(&server, &username)? {
        Some(token) => token,
        None => login(&config)?,
    };
    let mut api = ApiClient::new(&server, Some(token))?;
    match api.me() {
        Ok(_) => {}
        Err(CliError::Server { status: 401, .. }) => {
            let token = login(&config)?;
            api = ApiClient::new(&server, Some(token))?;
        }
        Err(error) => return Err(error),
    }
    Ok(Session {
        config,
        api,
        identity,
    })
}

pub fn logout() -> Result<()> {
    let config = config::load()?;
    let server = config.require_server_url()?;
    let username = config
        .username
        .clone()
        .ok_or_else(|| CliError::Config("no username configured".to_owned()))?;
    if let Some(token) = load_token(&server, &username)? {
        let api = ApiClient::new(&server, Some(token))?;
        let _ = api.logout();
    }
    delete_token(&server, &username)?;
    Ok(())
}

pub fn delete_team_key(team_id: Uuid, epoch: u32) -> Result<()> {
    OsKeyStore
        .delete(&team_key_account(team_id, epoch))
        .map_err(CliError::from)
}

pub fn team_key_account(team_id: Uuid, epoch: u32) -> String {
    keychain::team_key_account(&team_id.to_string(), epoch)
}

pub fn store_team_key(team_id: Uuid, epoch: u32, key: &[u8; 32]) -> Result<()> {
    OsKeyStore
        .set(&team_key_account(team_id, epoch), key)
        .map_err(CliError::from)
}

pub fn load_team_key(team_id: Uuid, epoch: u32) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(bytes) = OsKeyStore.get(&team_key_account(team_id, epoch))? else {
        return Ok(None);
    };
    if bytes.len() != 32 {
        return Err(CliError::msg("stored team key is malformed"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(Some(key))
}

/// Load a team key for `epoch`, falling back to the newest sealed envelope.
/// Also returns the epoch that was actually opened.
pub fn team_key(
    session: &Session,
    team_id: Uuid,
    epoch: u32,
) -> Result<(Zeroizing<[u8; 32]>, u32)> {
    if let Some(key) = load_team_key(team_id, epoch)? {
        return Ok((key, epoch));
    }
    let envelopes = session.api.envelopes(team_id)?;
    if envelopes.team_id != team_id {
        return Err(CliError::msg(
            "relay returned envelopes for a different team",
        ));
    }
    let envelope = envelopes
        .envelopes
        .iter()
        .max_by_key(|envelope| envelope.epoch)
        .ok_or_else(|| CliError::msg("no team key envelope is available for this account"))?;
    if envelope.epoch > envelopes.key_epoch.max(0) as u32 {
        return Err(CliError::msg(
            "relay returned an envelope newer than the team key epoch",
        ));
    }
    let sealed = SealedTeamKey {
        recipient: envelope.recipient.clone(),
        epoch: envelope.epoch,
        ephemeral_public: envelope.ephemeral_public_key.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let key = open_team_key(session.identity.secret(), &team_id.to_string(), &sealed)?;
    store_team_key(team_id, sealed.epoch, &key)?;
    Ok((key, sealed.epoch))
}

/// Open the newest sealed team-key envelope without persisting it. CI jobs
/// must not leave a team key in the runner's OS credential store.
pub fn team_key_ephemeral(
    session: &Session,
    team_id: Uuid,
    epoch: u32,
) -> Result<(Zeroizing<[u8; 32]>, u32)> {
    let envelopes = session.api.envelopes(team_id)?;
    if envelopes.team_id != team_id {
        return Err(CliError::msg(
            "relay returned envelopes for a different team",
        ));
    }
    let envelope = envelopes
        .envelopes
        .iter()
        .max_by_key(|envelope| envelope.epoch)
        .ok_or_else(|| CliError::msg("no team key envelope is available for this account"))?;
    if envelope.epoch > envelopes.key_epoch.max(0) as u32 || envelope.epoch > epoch {
        return Err(CliError::msg(
            "relay returned an envelope newer than the team key epoch",
        ));
    }
    let sealed = SealedTeamKey {
        recipient: envelope.recipient.clone(),
        epoch: envelope.epoch,
        ephemeral_public: envelope.ephemeral_public_key.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let key = open_team_key(session.identity.secret(), &team_id.to_string(), &sealed)?;
    Ok((key, sealed.epoch))
}

pub fn fingerprint(vault: &Vault) -> Result<String> {
    let bytes = serde_json::to_vec(vault.entries())?;
    Ok(hex::encode(velt_core::crypto::sha256(&bytes)))
}

pub fn display_username(username: &str) -> String {
    username.strip_prefix('@').unwrap_or(username).to_owned()
}
