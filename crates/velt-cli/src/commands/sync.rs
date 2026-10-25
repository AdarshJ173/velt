//! Bind a vault to a team environment, then push, pull, inspect or watch it.

use std::collections::BTreeMap;
use std::io::Write;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde_json::json;
use tungstenite::client::IntoClientRequest;
use uuid::Uuid;
use velt_core::sync::TeamPayload;
use velt_core::vault::{RemoteBinding, Vault};
use zeroize::Zeroizing;

use crate::cli::{Cli, SyncArgs, SyncCommand};
use crate::error::{CliError, Result};
use crate::remote::{self, Session};
use crate::util::Output;

pub fn execute(cli: &Cli, args: &SyncArgs) -> Result<i32> {
    match &args.command {
        SyncCommand::Init {
            team,
            environment,
            force,
        } => init(cli, *team, environment, *force),
        SyncCommand::Push { force } => push(cli, *force),
        SyncCommand::Pull { force, merge } => pull(cli, *force, *merge),
        SyncCommand::Status => status(cli),
        SyncCommand::Watch => watch(cli),
    }
}

pub(crate) fn validate_environment(input: &str) -> Result<String> {
    let environment = input.trim().to_ascii_lowercase();
    if environment.is_empty() || environment.len() > 32 {
        return Err(CliError::msg("environment must be 1..=32 characters"));
    }
    let bytes = environment.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(CliError::msg(
            "environment must start with a lowercase letter or digit",
        ));
    }
    if !bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
    }) {
        return Err(CliError::msg(
            "environment may contain lowercase letters, digits, underscore and hyphen",
        ));
    }
    Ok(environment)
}

fn binding(vault: &Vault) -> Result<RemoteBinding> {
    vault.binding().cloned().ok_or_else(|| {
        CliError::msg("vault is not bound to a team; run `velt sync init --team <id> --env <env>`")
    })
}

fn refresh_key(
    session: &Session,
    team_id: Uuid,
    binding: &mut RemoteBinding,
) -> Result<Zeroizing<[u8; 32]>> {
    let details = session.api.team(team_id)?;
    let current_epoch = details.key_epoch as u32;
    if binding.epoch > current_epoch {
        return Err(CliError::msg(
            "local binding is ahead of the server key epoch; run `velt auth status` / refresh the vault",
        ));
    }
    let (key, epoch) = remote::team_key(session, team_id, current_epoch)?;
    binding.epoch = epoch;
    Ok(key)
}

fn init(cli: &Cli, team_id: Uuid, environment: &str, force: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    let environment = validate_environment(environment)?;
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let mut context = crate::context::WriteContext::open(&path)?;
    if context.vault.binding().is_some() && !force {
        return Err(CliError::msg(
            "vault already has a team binding; use --force to replace it",
        ));
    }
    let session = remote::session()?;
    let details = session.api.team(team_id)?;
    let current_epoch = details.key_epoch as u32;
    let (key, epoch) = remote::team_key(&session, team_id, current_epoch)?;
    let _ = key;
    let binding = RemoteBinding {
        team_id: team_id.to_string(),
        environment: environment.clone(),
        epoch,
        base_version: 0,
        base_checksum: None,
    };
    context.vault.set_binding(Some(binding.clone()));
    context.save()?;

    if cli.json {
        output.data(&json!({
            "vault": path,
            "team_id": team_id,
            "team_name": details.name,
            "environment": environment,
            "key_epoch": epoch,
            "base_version": 0,
        }))?;
    } else {
        output.text(&format!(
            "Bound {} to team {} / {} (key epoch {}).",
            path.display(),
            details.name,
            environment,
            epoch
        ));
        output.text("");
        output.text("Next:");
        output.text("  velt sync pull --merge   # adopt the remote environment");
        output.text("  velt sync push           # or publish this vault as the new version");
    }
    Ok(0)
}

fn push(cli: &Cli, force: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let mut context = crate::context::WriteContext::open(&path)?;
    let mut binding = binding(&context.vault)?;
    let team_id = Uuid::parse_str(&binding.team_id)
        .map_err(|_| CliError::msg("vault binding contains an invalid team id"))?;
    let session = remote::session()?;
    let key = refresh_key(&session, team_id, &mut binding)?;
    let mut payload = TeamPayload::new(
        binding.team_id.clone(),
        binding.environment.clone(),
        context.vault.entries().clone(),
    );
    let encrypted = payload.encrypt(&key)?;
    let base_version = (binding.base_version > 0).then_some(binding.base_version as i64);
    let pushed = session.api.push_blob(
        team_id,
        &binding.environment,
        base_version,
        force,
        &encrypted.nonce_base64(),
        &encrypted.ciphertext_base64(),
        &encrypted.checksum_base64(),
    )?;
    binding.base_version = pushed.version as u64;
    binding.base_checksum = Some(remote::fingerprint(&context.vault)?);
    context.vault.set_binding(Some(binding.clone()));
    context.save()?;

    if cli.json {
        output.data(&json!({
            "team_id": team_id,
            "environment": pushed.environment,
            "version": pushed.version,
            "updated_at": pushed.updated_at,
        }))?;
    } else {
        output.text(&format!(
            "Pushed {} to {}/{} as version {}.",
            path.display(),
            binding.team_id,
            binding.environment,
            pushed.version
        ));
    }
    Ok(0)
}

fn pull(cli: &Cli, force: bool, merge: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let mut context = crate::context::WriteContext::open(&path)?;
    let mut binding = binding(&context.vault)?;
    let team_id = Uuid::parse_str(&binding.team_id)
        .map_err(|_| CliError::msg("vault binding contains an invalid team id"))?;
    let session = remote::session()?;
    let key = refresh_key(&session, team_id, &mut binding)?;
    let since = (binding.base_version > 0).then_some(binding.base_version as i64);
    let blob = session
        .api
        .pull_blob(team_id, &binding.environment, since)?;
    if blob.not_modified && !force {
        let mut changed = false;
        if context.vault.binding() != Some(&binding) {
            context.vault.set_binding(Some(binding.clone()));
            context.save()?;
            changed = true;
        }
        if cli.json {
            output.data(&json!({
                "team_id": team_id,
                "environment": binding.environment,
                "version": blob.version,
                "not_modified": true,
                "saved": changed,
            }))?;
        } else {
            output.text(&format!("Already up to date at version {}.", blob.version));
        }
        return Ok(0);
    }

    if blob.environment != binding.environment {
        return Err(CliError::msg(
            "relay returned a blob for a different environment",
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
    let nonce_bytes = STANDARD_NO_PAD
        .decode(nonce)
        .map_err(|_| CliError::msg("relay returned an invalid nonce"))?;
    if nonce_bytes.len() != 12 {
        return Err(CliError::msg("relay returned an invalid nonce length"));
    }
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(&nonce_bytes);
    let ciphertext_bytes = STANDARD_NO_PAD
        .decode(ciphertext)
        .map_err(|_| CliError::msg("relay returned invalid ciphertext"))?;
    if let Some(expected) = &blob.checksum {
        let expected = STANDARD_NO_PAD
            .decode(expected)
            .map_err(|_| CliError::msg("relay returned an invalid checksum"))?;
        let actual = velt_core::crypto::sha256(&ciphertext_bytes);
        if !velt_core::crypto::constant_time_eq(&expected, &actual) {
            return Err(CliError::msg("relay ciphertext checksum mismatch"));
        }
    }
    let remote_payload = TeamPayload::decrypt(
        &key,
        &binding.team_id,
        &binding.environment,
        &nonce_array,
        &ciphertext_bytes,
    )?;

    let local_before = remote::fingerprint(&context.vault)?;
    if !force {
        match &binding.base_checksum {
            Some(base) if base != &local_before => {
                return Err(CliError::msg(
                    "local vault has changes that have not been pushed; use --merge to combine or --force to overwrite",
                ));
            }
            None if !context.vault.entries().is_empty() => {
                return Err(CliError::msg(
                    "local vault has entries and no sync baseline; use --merge to combine or --force to overwrite",
                ));
            }
            _ => {}
        }
    }

    let local = context.vault.entries().clone();
    let remote_entries = remote_payload.entries.clone();
    let added = remote_entries
        .keys()
        .filter(|key| !local.contains_key(*key))
        .count();
    let updated = remote_entries
        .iter()
        .filter(|(key, entry)| {
            local
                .get(*key)
                .is_some_and(|local_entry| local_entry.value.expose() != entry.value.expose())
        })
        .count();
    let kept = if merge {
        local
            .keys()
            .filter(|key| !remote_entries.contains_key(*key))
            .count()
    } else {
        0
    };

    if merge {
        let mut combined: BTreeMap<String, velt_core::Entry> = remote_entries;
        for (key, entry) in local {
            combined.entry(key).or_insert(entry);
        }
        *context.vault.entries_mut() = combined;
    } else {
        *context.vault.entries_mut() = remote_entries;
    }

    binding.base_version = blob.version as u64;
    binding.epoch = refresh_epoch(&session, team_id, binding.epoch);
    binding.base_checksum = Some(remote::fingerprint(&context.vault)?);
    context.vault.set_binding(Some(binding.clone()));
    context.save()?;

    if cli.json {
        output.data(&json!({
            "team_id": team_id,
            "environment": binding.environment,
            "version": blob.version,
            "not_modified": false,
            "updated_by": blob.updated_by,
            "updated_at": blob.updated_at,
            "added": added,
            "updated": updated,
            "kept_local": kept,
            "merge": merge,
        }))?;
    } else {
        output.text(&format!(
            "Pulled {}/{} version {} ({} added, {} updated, {} local-only kept).",
            binding.team_id, binding.environment, blob.version, added, updated, kept
        ));
    }
    Ok(0)
}

fn refresh_epoch(session: &Session, team_id: Uuid, fallback: u32) -> u32 {
    session
        .api
        .team(team_id)
        .map(|team| team.key_epoch as u32)
        .unwrap_or(fallback)
}

fn status(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let binding = binding(&vault)?;
    let team_id = Uuid::parse_str(&binding.team_id)
        .map_err(|_| CliError::msg("vault binding contains an invalid team id"))?;

    let remote = (|| -> Result<(String, Option<i64>, Option<String>)> {
        let session = remote::session()?;
        let team = session.api.team(team_id)?;
        let environments = session.api.environments(team_id)?;
        let environment = environments
            .iter()
            .find(|environment| environment.environment == binding.environment);
        Ok((
            team.name,
            environment.map(|environment| environment.version),
            environment.map(|environment| environment.updated_at.clone()),
        ))
    })();

    match remote {
        Ok((team_name, remote_version, updated_at)) => {
            if cli.json {
                output.data(&json!({
                    "vault": path,
                    "team_id": team_id,
                    "team_name": team_name,
                    "environment": binding.environment,
                    "key_epoch": binding.epoch,
                    "base_version": binding.base_version,
                    "remote_version": remote_version,
                    "remote_updated_at": updated_at,
                    "dirty": binding.base_checksum.as_ref().is_some_and(|checksum| checksum != &remote::fingerprint(&vault).unwrap_or_default()),
                }))?;
            } else {
                output.text(&format!("Vault: {}", path.display()));
                output.text(&format!("Team: {team_name} ({team_id})"));
                output.text(&format!("Environment: {}", binding.environment));
                output.text(&format!("Key epoch: {}", binding.epoch));
                output.text(&format!(
                    "Remote version: {}",
                    remote_version
                        .map(|version| version.to_string())
                        .unwrap_or_else(|| "none".to_owned())
                ));
                output.text(&format!("Local baseline: version {}", binding.base_version));
                if let Some(checksum) = &binding.base_checksum {
                    let current = remote::fingerprint(&vault)?;
                    output.text(&format!(
                        "Local state: {}",
                        if checksum == &current {
                            "clean"
                        } else {
                            "modified since last sync"
                        }
                    ));
                } else {
                    output.text("Local state: no sync baseline yet");
                }
            }
        }
        Err(error) => {
            if cli.json {
                output.data(&json!({
                    "vault": path,
                    "team_id": team_id,
                    "environment": binding.environment,
                    "key_epoch": binding.epoch,
                    "base_version": binding.base_version,
                    "offline": true,
                    "error": error.to_string(),
                }))?;
            } else {
                output.text(&format!("Vault: {}", path.display()));
                output.text(&format!("Team: {team_id}"));
                output.text(&format!("Environment: {}", binding.environment));
                output.text(&format!("Key epoch: {}", binding.epoch));
                output.text(&format!("Remote: unavailable ({error})"));
            }
        }
    }
    Ok(0)
}

fn watch(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let binding = binding(&vault)?;
    let team_id = Uuid::parse_str(&binding.team_id)
        .map_err(|_| CliError::msg("vault binding contains an invalid team id"))?;
    let session = remote::session()?;
    let token = session
        .api
        .token()
        .ok_or_else(|| CliError::msg("no session token available"))?;
    let url = session.api.websocket_url(team_id);
    let mut request = url
        .into_client_request()
        .map_err(|error| CliError::msg(format!("invalid WebSocket request: {error}")))?;
    request.headers_mut().insert(
        tungstenite::http::header::AUTHORIZATION,
        tungstenite::http::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| CliError::msg(format!("invalid session token: {error}")))?,
    );
    let (mut socket, _) = tungstenite::connect(request)
        .map_err(|error| CliError::msg(format!("WebSocket connection failed: {error}")))?;
    if !cli.json {
        output.text(&format!(
            "Watching {}/{} for changes (Ctrl-C to stop)...",
            binding.team_id, binding.environment
        ));
    }
    loop {
        match socket.read() {
            Ok(message) => {
                if let tungstenite::Message::Text(text) = message {
                    if cli.json {
                        output.text(text.as_str());
                    } else {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) {
                            let kind = event
                                .get("type")
                                .and_then(|value| value.as_str())
                                .unwrap_or("event");
                            let environment = event
                                .get("environment")
                                .and_then(|value| value.as_str())
                                .unwrap_or("");
                            let version = event
                                .get("version")
                                .and_then(|value| value.as_i64())
                                .map(|value| value.to_string())
                                .unwrap_or_default();
                            if kind == "vault_updated" {
                                output.text(&format!(
                                    "update: {environment} version {version} (run `velt sync pull`)"
                                ));
                            } else {
                                output.text(&format!("event: {kind}"));
                            }
                        }
                    }
                    let _ = std::io::stdout().flush();
                }
            }
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::Protocol(_)) => break,
            Err(error) => {
                return Err(CliError::msg(format!("WebSocket error: {error}")));
            }
        }
    }
    Ok(0)
}
