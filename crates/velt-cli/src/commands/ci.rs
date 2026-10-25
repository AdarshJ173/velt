//! Headless CI runner: fetch an E2EE team environment and inject it into a
//! child process without a local vault or keychain writes.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use uuid::Uuid;
use velt_core::sync::TeamPayload;
use zeroize::Zeroizing;

use crate::api::BlobResponse;
use crate::cli::{CiArgs, CiCommand, CiRunArgs, Cli};
use crate::commands::run::{self, Prepared};
use crate::commands::sync;
use crate::config;
use crate::error::{CliError, Result};
use crate::remote;

const BOOTSTRAP_ENV: &[&str] = &[
    "VELT_IDENTITY_KEY",
    "VELT_SSH_KEY",
    "VELT_SSH_KEY_CONTENT",
    "VELT_SSH_KEY_PASSPHRASE",
];

pub fn execute(cli: &Cli, args: &CiArgs) -> Result<i32> {
    match &args.command {
        CiCommand::Run(args) => run(cli, args),
    }
}

fn run(cli: &Cli, args: &CiRunArgs) -> Result<i32> {
    if cli.json {
        return Err(CliError::msg(
            "`velt ci run` does not support --json; child stdout is the machine-readable surface",
        ));
    }
    let environment = sync::validate_environment(&args.environment)?;
    let cfg = config::load().unwrap_or_default();
    let server = args
        .server
        .clone()
        .or_else(|| cfg.server_url())
        .ok_or_else(|| CliError::Config("set VELT_SERVER_URL or pass --server".to_owned()))?;
    let username = args
        .username
        .clone()
        .or(cfg.username)
        .ok_or_else(|| CliError::Config("set VELT_USERNAME or pass --username".to_owned()))?;
    let identity = match args.identity_key.as_deref() {
        Some(value) => remote::identity_from_hex(value)?,
        None => remote::identity_from_env()?.ok_or_else(|| {
            CliError::Config(
                "set VELT_IDENTITY_KEY (32-byte X25519 private key, hex) or pass --identity-key"
                    .to_owned(),
            )
        })?,
    };
    let ssh_key = args.ssh_key.clone().or(cfg.ssh_key);
    let session = remote::ci_session(&server, &username, ssh_key.as_deref(), identity)?;
    let details = session.api.team(args.team)?;
    let (team_key, _epoch) =
        remote::team_key_ephemeral(&session, args.team, details.key_epoch as u32)?;
    let blob = session.api.pull_blob(args.team, &environment, None)?;
    let payload = decode_blob(&blob, &team_key, args.team, &environment)?;

    let entries = payload.into_entries();
    let all_names = entries.keys().cloned().collect();
    let pairs = entries
        .into_iter()
        .map(|(name, entry)| (name, Zeroizing::new(entry.value.expose().to_owned())))
        .collect();
    let prepared = Prepared { pairs, all_names };

    run::execute_prepared(&args.command, args.redact, prepared, BOOTSTRAP_ENV)
}

fn decode_blob(
    blob: &BlobResponse,
    team_key: &[u8; 32],
    team_id: Uuid,
    environment: &str,
) -> Result<TeamPayload> {
    if blob.not_modified {
        return Err(CliError::msg(
            "relay returned no environment version for this team",
        ));
    }
    if blob.environment != environment {
        return Err(CliError::msg(
            "relay returned an environment blob for a different environment",
        ));
    }
    let nonce = blob
        .nonce
        .as_deref()
        .ok_or_else(|| CliError::msg("relay returned a blob without a nonce"))?;
    let ciphertext = blob
        .ciphertext
        .as_deref()
        .ok_or_else(|| CliError::msg("relay returned a blob without ciphertext"))?;
    let nonce = STANDARD_NO_PAD
        .decode(nonce)
        .map_err(|_| CliError::msg("relay returned an invalid nonce"))?;
    if nonce.len() != 12 {
        return Err(CliError::msg("relay returned an invalid nonce length"));
    }
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(&nonce);
    let ciphertext = STANDARD_NO_PAD
        .decode(ciphertext)
        .map_err(|_| CliError::msg("relay returned invalid ciphertext"))?;
    if let Some(expected) = &blob.checksum {
        let expected = STANDARD_NO_PAD
            .decode(expected)
            .map_err(|_| CliError::msg("relay returned an invalid checksum"))?;
        let actual = velt_core::crypto::sha256(&ciphertext);
        if !velt_core::crypto::constant_time_eq(&expected, &actual) {
            return Err(CliError::msg("relay ciphertext checksum mismatch"));
        }
    }
    TeamPayload::decrypt(
        team_key,
        &team_id.to_string(),
        environment,
        &nonce_array,
        &ciphertext,
    )
    .map_err(CliError::from)
}
