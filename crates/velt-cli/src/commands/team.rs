//! Team creation, invitations, revocation and key rotation.

use std::io::IsTerminal;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use uuid::Uuid;
use velt_core::sync::{seal_team_key, TeamPayload};

use crate::api::{RotatedBlobWire, RotatedEnvelopeWire};
use crate::cli::{Cli, InviteArgs, TeamArgs, TeamCommand};
use crate::error::{CliError, Result};
use crate::remote::{self, Session};
use crate::util::{self, Output};

pub fn execute(cli: &Cli, args: &TeamArgs) -> Result<i32> {
    match &args.command {
        TeamCommand::Create { name } => create(cli, name),
        TeamCommand::List => list(cli),
        TeamCommand::Members { team } => members(cli, *team),
        TeamCommand::Invite(args) => invite(cli, args),
        TeamCommand::Remove {
            username,
            team,
            yes,
        } => remove(cli, username, *team, *yes),
        TeamCommand::FetchKey { team } => fetch_key(cli, *team),
        TeamCommand::RotateKey { team } => rotate(cli, *team),
        TeamCommand::Delete { team, yes } => delete(cli, *team, *yes),
        TeamCommand::Audit { team, limit } => audit(cli, *team, *limit),
    }
}

fn decode_public_key(encoded: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|_| CliError::msg("team member has an invalid encryption public key"))?;
    if bytes.len() != 32 {
        return Err(CliError::msg(
            "team member has an invalid encryption public key length",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn resolve_team(session: &Session, explicit: Option<Uuid>) -> Result<Uuid> {
    if let Some(team) = explicit {
        return Ok(team);
    }
    if let Ok(path) = crate::context::discover_vault(None) {
        if let Ok((vault, _key)) = crate::context::open_vault(&path) {
            if let Some(binding) = vault.binding() {
                return Uuid::parse_str(&binding.team_id)
                    .map_err(|_| CliError::msg("vault binding contains an invalid team id"));
            }
        }
    }
    let teams = session.api.list_teams()?;
    match teams.as_slice() {
        [team] => Ok(team.id),
        [] => Err(CliError::msg(
            "you are not a member of any team; create one with `velt team create <name>`",
        )),
        _ => Err(CliError::msg(
            "multiple teams available; specify --team <id>",
        )),
    }
}

fn default_grants(team_id: Uuid, requested: &[String]) -> Result<Vec<String>> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    if let Ok(path) = crate::context::discover_vault(None) {
        if let Ok((vault, _key)) = crate::context::open_vault(&path) {
            if let Some(binding) = vault.binding() {
                if binding.team_id == team_id.to_string() {
                    return Ok(vec![binding.environment.clone()]);
                }
            }
        }
    }
    Err(CliError::msg(
        "no environment specified; use --env development (or bind this vault with `velt sync init`)",
    ))
}

fn create(cli: &Cli, name: &str) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let me = session.api.me()?;
    let team_id = Uuid::new_v4();
    let team_key = velt_core::crypto::random_key()?;
    remote::store_team_key(team_id, 1, &team_key)?;
    let envelope = seal_team_key(
        session.identity.public(),
        &team_id.to_string(),
        1,
        &me.user.username,
        &team_key,
    )?;
    let team = match session.api.create_team(team_id, name, &envelope) {
        Ok(team) => team,
        Err(error) => {
            let _ = remote::delete_team_key(team_id, 1);
            return Err(error);
        }
    };
    if cli.json {
        output.data(&json!({
            "team": team,
            "key_epoch": 1,
            "next": format!("velt sync init --team {team_id} --env development"),
        }))?;
    } else {
        output.text(&format!("Created team {} ({team_id}).", team.name));
        output.text("Team key generated and sealed to your device.");
        output.text("");
        output.text("Next:");
        output.text(&format!(
            "  velt sync init --team {team_id} --env development"
        ));
    }
    Ok(0)
}

fn list(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let teams = session.api.list_teams()?;
    if cli.json {
        output.data(&json!(teams))?;
        return Ok(0);
    }
    if teams.is_empty() {
        output.text("No teams. Create one with `velt team create <name>`.");
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = teams
        .iter()
        .map(|team| {
            vec![
                team.id.to_string(),
                team.name.clone(),
                team.role.clone(),
                team.key_epoch.to_string(),
                team.env_grants.join(","),
            ]
        })
        .collect();
    util::print_table(&["ID", "NAME", "ROLE", "KEY EPOCH", "ENV GRANTS"], &rows);
    Ok(0)
}

fn members(cli: &Cli, explicit: Option<Uuid>) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let team_id = resolve_team(&session, explicit)?;
    let team = session.api.team(team_id)?;
    if cli.json {
        output.data(&team)?;
        return Ok(0);
    }
    output.text(&format!(
        "Team {} ({})  key epoch {}",
        team.name, team.id, team.key_epoch
    ));
    let rows: Vec<Vec<String>> = team
        .members
        .iter()
        .map(|member| {
            vec![
                member.username.clone(),
                member.role.clone(),
                if member.env_grants.is_empty() {
                    "-".to_owned()
                } else {
                    member.env_grants.join(",")
                },
            ]
        })
        .collect();
    util::print_table(&["MEMBER", "ROLE", "ENV GRANTS"], &rows);
    if !team.environments.is_empty() {
        output.text("");
        let envs: Vec<Vec<String>> = team
            .environments
            .iter()
            .map(|environment| {
                vec![
                    environment.environment.clone(),
                    environment.version.to_string(),
                    environment.updated_at.clone(),
                ]
            })
            .collect();
        util::print_table(&["ENVIRONMENT", "VERSION", "UPDATED"], &envs);
    }
    Ok(0)
}

pub fn invite(cli: &Cli, args: &InviteArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let username = remote::display_username(&args.username).to_ascii_lowercase();
    let session = remote::session()?;
    let team_id = resolve_team(&session, args.team)?;
    let team = session.api.team(team_id)?;
    if !team.can_manage {
        return Err(CliError::msg(
            "only team owners and admins can invite members",
        ));
    }
    let epoch = team.key_epoch as u32;
    let (team_key, epoch) = remote::team_key(&session, team_id, epoch)?;
    let target = session.api.lookup_user(&username)?;
    let target_key = decode_public_key(&target.encryption_public_key)?;
    let envelope = seal_team_key(
        &target_key,
        &team_id.to_string(),
        epoch,
        &target.username,
        &team_key,
    )?;
    let grants = default_grants(team_id, &args.env)?;
    let member = session
        .api
        .invite(team_id, &target.username, &args.role, &grants, &envelope)?;
    if cli.json {
        output.data(&json!({
            "team_id": team_id,
            "target_id": target.id,
            "member": member,
            "key_epoch": epoch,
        }))?;
    } else {
        output.text(&format!(
            "Invited {} to {} as {} (environments: {}).",
            member.username,
            team.name,
            member.role,
            if member.env_grants.is_empty() {
                "-".to_owned()
            } else {
                member.env_grants.join(", ")
            }
        ));
        output.text("They can now run `velt sync init` / `velt sync pull` to fetch the encrypted environment.");
    }
    Ok(0)
}

fn remove(cli: &Cli, username: &str, team: Option<Uuid>, yes: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    let username = remote::display_username(username).to_ascii_lowercase();
    let session = remote::session()?;
    let team_id = resolve_team(&session, team)?;
    let details = session.api.team(team_id)?;
    let target = details
        .members
        .iter()
        .find(|member| member.username == username)
        .ok_or_else(|| CliError::msg(format!("{username} is not a member of this team")))?;
    if target.role == "owner" {
        return Err(CliError::msg("the team owner cannot be removed"));
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::msg(
                "refusing to remove a member without --yes in a non-interactive shell",
            ));
        }
        if !util::confirm(&format!(
            "Remove {}? Run `velt team rotate-key` immediately afterwards.",
            target.username
        ))? {
            output.text("Not removed.");
            return Ok(0);
        }
    }
    let response = session.api.remove_member(team_id, target.id)?;
    if cli.json {
        output.data(&json!({
            "team_id": team_id,
            "removed": target.username,
            "key_rotation_required": response.get("key_rotation_required").cloned().unwrap_or(Value::Bool(true)),
        }))?;
    } else {
        output.text(&format!("Removed {} from the team.", target.username));
        output.text("IMPORTANT: rotate the team key now so the removed member cannot decrypt future updates:");
        output.text("  velt team rotate-key");
    }
    Ok(0)
}

fn fetch_key(cli: &Cli, team: Uuid) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let details = session.api.team(team)?;
    let (_key, epoch) = remote::team_key(&session, team, details.key_epoch as u32)?;
    if cli.json {
        output.data(&json!({
            "team_id": team,
            "key_epoch": epoch,
            "stored": true,
        }))?;
    } else {
        output.text(&format!(
            "Cached team key for {team} at epoch {epoch} in the OS keychain."
        ));
    }
    Ok(0)
}

fn rotate(cli: &Cli, explicit: Option<Uuid>) -> Result<i32> {
    use std::collections::BTreeMap;
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let team_id = resolve_team(&session, explicit)?;
    let team = session.api.team(team_id)?;
    if team.role != "owner" {
        return Err(CliError::msg("only the team owner can rotate the team key"));
    }
    let current_epoch = team.key_epoch as u32;
    let (old_key, current_epoch) = remote::team_key(&session, team_id, current_epoch)?;
    let new_epoch = current_epoch + 1;
    let environments = session.api.environments(team_id)?;
    let mut rotated_blobs = Vec::with_capacity(environments.len());
    let mut new_versions = BTreeMap::new();
    let mut decrypted_payloads = Vec::new();

    for environment in &environments {
        let blob = session
            .api
            .pull_blob(team_id, &environment.environment, None)?;
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
        let payload = TeamPayload::decrypt(
            &old_key,
            &team_id.to_string(),
            &environment.environment,
            &nonce_array,
            &ciphertext_bytes,
        )?;
        if let Some(expected) = &blob.checksum {
            let expected = STANDARD_NO_PAD
                .decode(expected)
                .map_err(|_| CliError::msg("relay returned an invalid checksum"))?;
            let actual = velt_core::crypto::sha256(&ciphertext_bytes);
            if !velt_core::crypto::constant_time_eq(&expected, &actual) {
                return Err(CliError::msg("relay ciphertext checksum mismatch"));
            }
        }
        decrypted_payloads.push((environment.environment.clone(), payload, blob.version));
    }

    let new_key = velt_core::crypto::random_key()?;
    for (environment, mut payload, base_version) in decrypted_payloads {
        payload.team_id = team_id.to_string();
        payload.environment = environment.clone();
        payload.updated_at = velt_core::vault::now_unix();
        let encrypted = payload.encrypt(&new_key)?;
        new_versions.insert(environment.clone(), base_version + 1);
        rotated_blobs.push(RotatedBlobWire {
            environment,
            base_version,
            nonce: encrypted.nonce_base64(),
            ciphertext: encrypted.ciphertext_base64(),
            checksum: encrypted.checksum_base64(),
        });
    }

    let mut envelopes = Vec::with_capacity(team.members.len());
    for member in &team.members {
        let public = decode_public_key(&member.encryption_public_key)?;
        let sealed = seal_team_key(
            &public,
            &team_id.to_string(),
            new_epoch,
            &member.username,
            &new_key,
        )?;
        envelopes.push(RotatedEnvelopeWire {
            user_id: member.id,
            epoch: new_epoch,
            ephemeral_public_key: sealed.ephemeral_public,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
        });
    }

    session
        .api
        .rotate_key(team_id, new_epoch, &envelopes, &rotated_blobs)?;
    remote::store_team_key(team_id, new_epoch, &new_key)?;
    if current_epoch != new_epoch {
        let _ = remote::delete_team_key(team_id, current_epoch);
    }

    // Update a local binding for this team, if present.
    if let Ok(path) = crate::context::discover_vault(None) {
        if let Ok(mut context) = crate::context::WriteContext::open(&path) {
            if let Some(binding) = context.vault.binding().cloned() {
                if binding.team_id == team_id.to_string() {
                    let bound_environment = binding.environment.clone();
                    let mut updated = binding;
                    updated.epoch = new_epoch;
                    if let Some(version) = new_versions.get(&bound_environment) {
                        updated.base_version = *version as u64;
                    }
                    context.vault.set_binding(Some(updated));
                    if let Err(error) = context.save() {
                        eprintln!(
                            "warning: key rotated but local binding was not updated: {error}"
                        );
                    }
                }
            }
        }
    }

    if cli.json {
        output.data(&json!({
            "team_id": team_id,
            "key_epoch": new_epoch,
            "environments": new_versions,
            "members": team.members.len(),
        }))?;
    } else {
        output.text(&format!(
            "Rotated team key to epoch {new_epoch} and re-encrypted {} environment(s) for {} member(s).",
            rotated_blobs.len(),
            team.members.len()
        ));
        output.text("Share the new epoch automatically: teammates receive it on their next pull.");
    }
    Ok(0)
}

fn delete(cli: &Cli, team: Uuid, yes: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let details = session.api.team(team)?;
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::msg("refusing to delete a team without --yes"));
        }
        if !util::confirm(&format!(
            "Delete team {} and all its encrypted environments?",
            details.name
        ))? {
            output.text("Not deleted.");
            return Ok(0);
        }
    }
    session.api.delete_team(team)?;
    for epoch in 1..=details.key_epoch.max(1) {
        let _ = remote::delete_team_key(team, epoch as u32);
    }
    if let Ok(path) = crate::context::discover_vault(None) {
        if let Ok(mut context) = crate::context::WriteContext::open(&path) {
            if context
                .vault
                .binding()
                .is_some_and(|binding| binding.team_id == team.to_string())
            {
                context.vault.set_binding(None);
                let _ = context.save();
            }
        }
    }
    if cli.json {
        output.data(&json!({"deleted": team}))?;
    } else {
        output.text(&format!("Deleted team {team}."));
    }
    Ok(0)
}

fn audit(cli: &Cli, explicit: Option<Uuid>, limit: u32) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let team_id = resolve_team(&session, explicit)?;
    let events = session.api.audit(team_id, limit.clamp(1, 500))?;
    if cli.json {
        output.data(&events)?;
        return Ok(0);
    }
    if events.is_empty() {
        output.text("No audit events.");
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|event| {
            vec![
                event.created_at.clone(),
                event.actor.clone().unwrap_or_else(|| "-".to_owned()),
                event.action.clone(),
                event.subject.clone().unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect();
    util::print_table(&["CREATED", "ACTOR", "ACTION", "SUBJECT"], &rows);
    Ok(0)
}
