//! Export a local vault as a team-key-encrypted file suitable for Git.

use serde_json::json;
use velt_core::vault::KeyMode;

use crate::cli::{Cli, ExportArgs};
use crate::error::{CliError, Result};
use crate::remote;
use crate::util::Output;

pub fn execute(cli: &Cli, args: &ExportArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let binding = vault.binding().cloned().ok_or_else(|| {
        CliError::msg("vault is not bound to a team; run `velt sync init --team <id> --env <env>`")
    })?;
    if args.out.exists() && !args.force {
        return Err(CliError::msg(format!(
            "{} already exists; use --force to overwrite",
            args.out.display()
        )));
    }
    let team_id = uuid::Uuid::parse_str(&binding.team_id)
        .map_err(|_| CliError::msg("vault binding contains an invalid team id"))?;
    let session = remote::session()?;
    let details = session.api.team(team_id)?;
    let (team_key, epoch) = remote::team_key(&session, team_id, details.key_epoch as u32)?;
    let team_key = velt_core::MasterKey::from_slice(&team_key[..])?;
    let mode = KeyMode::Team {
        team_id: binding.team_id.clone(),
        epoch,
    };
    vault.export_to(&args.out, mode.clone(), &team_key)?;
    if cli.json {
        output.data(&json!({
            "source": path,
            "output": args.out,
            "team_id": binding.team_id,
            "environment": binding.environment,
            "key_epoch": epoch,
            "key_mode": "team",
        }))?;
    } else {
        output.text(&format!(
            "Exported team-key-encrypted vault to {}.",
            args.out.display()
        ));
        output.text(&format!(
            "Team {} / {} · key epoch {}",
            binding.team_id, binding.environment, epoch
        ));
        output.text(
            "This file does not contain the team key. Commit it only when teammates can fetch their sealed key.",
        );
    }
    Ok(0)
}
