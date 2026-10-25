//! Lease creation and inspection.

use serde_json::json;
use velt_core::lease;
use velt_core::vault::{now_unix, read_vault_id};

use crate::cli::{Cli, LeaseArgs, LeaseCommand, LeaseCreateArgs, LeaseInspectArgs};
use crate::error::{CliError, Result};
use crate::util::{self, Output};

pub fn execute(cli: &Cli, args: &LeaseArgs) -> Result<i32> {
    match &args.command {
        LeaseCommand::Create(args) => create(cli, args),
        LeaseCommand::Inspect(args) => inspect(cli, args),
    }
}

fn create(cli: &Cli, args: &LeaseCreateArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let vault_id = read_vault_id(&vault_path)?;
    let secret = crate::context::lease_secret(&vault_id, true)?;
    let ttl = util::parse_duration_seconds(&args.ttl)?
        .ok_or_else(|| CliError::msg("invalid lease TTL; use 90s, 10m, 1h, 2d"))?;
    let issued = lease::issue(
        &secret,
        &hex::encode(vault_id),
        &args.allow,
        &args.deny,
        ttl,
        args.label.clone(),
        args.parent.clone(),
    )?;

    if cli.json {
        output.data(&json!({
            "token": issued.token(),
            "claims": issued.payload(),
        }))?;
    } else {
        output.text(&format!("Lease {} issued.", issued.payload().lease_id));
        output.text(&format!("Allow: {}", issued.payload().allow.join(", ")));
        if !issued.payload().deny.is_empty() {
            output.text(&format!("Deny:  {}", issued.payload().deny.join(", ")));
        }
        output.text(&format!(
            "Expires: {}",
            util::format_timestamp(issued.payload().expires_at)
        ));
        output.text("");
        output.text("Token:");
        output.text(issued.token());
        output.text("");
        output.text("Treat this token as a bearer capability. Use it with:");
        output.text("  velt run --lease <token> -- <command>");
    }
    Ok(0)
}

fn inspect(cli: &Cli, args: &LeaseInspectArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let vault_id = read_vault_id(&vault_path)?;
    let secret = crate::context::lease_secret(&vault_id, false)?;
    let verified = lease::verify(&secret, &args.token, &hex::encode(vault_id), now_unix())?;
    let remaining = verified.payload().expires_at - now_unix();
    if cli.json {
        output.data(&json!({
            "valid": true,
            "claims": verified.payload(),
            "remaining_seconds": remaining,
        }))?;
    } else {
        output.text(&format!("Lease {} is valid.", verified.payload().lease_id));
        output.text(&format!("Allow: {}", verified.payload().allow.join(", ")));
        if !verified.payload().deny.is_empty() {
            output.text(&format!("Deny:  {}", verified.payload().deny.join(", ")));
        }
        output.text(&format!(
            "Expires: {} ({}s remaining)",
            util::format_timestamp(verified.payload().expires_at),
            remaining
        ));
    }
    Ok(0)
}
