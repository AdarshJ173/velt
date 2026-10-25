//! Local vault commands: set, get, list, remove.

use std::io::{IsTerminal, Write};

use serde_json::json;

use crate::cli::{Cli, GetArgs, RemoveArgs, SetArgs};
use crate::commands::inspect;
use crate::context::WriteContext;
use crate::error::{CliError, Result};
use crate::util::{self, Output};

pub fn set(cli: &Cli, args: &SetArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let mut context = WriteContext::open(&path)?;
    let expires_at = match &args.expires {
        Some(value) => util::parse_expiry(value)?,
        None => None,
    };
    let value = util::read_secret(
        args.value.as_deref(),
        args.from_stdin,
        &format!("Value for {}: ", args.key),
    )?;
    let existed = context.vault.get(&args.key).is_some();
    let was_empty = value.is_empty();
    context.vault.set(&args.key, value, expires_at)?;
    context.save()?;

    if cli.json {
        output.data(&json!({
            "key": args.key,
            "updated": existed,
            "expires_at": expires_at,
        }))?;
        return Ok(0);
    }
    output.text(&format!(
        "{} {}",
        if existed { "Updated" } else { "Added" },
        args.key
    ));
    if let Some(expires_at) = expires_at {
        output.text(&format!("Expires: {}", util::format_timestamp(expires_at)));
    }
    if was_empty {
        eprintln!("warning: value is empty; `velt audit` will flag it");
    }
    if args.value.as_deref().is_some_and(|value| !value.is_empty()) {
        eprintln!("note: values passed as arguments can appear in shell history; use `--stdin`");
    }
    Ok(0)
}

pub fn get(cli: &Cli, args: &GetArgs) -> Result<i32> {
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let entry = vault
        .get(&args.key)
        .ok_or_else(|| velt_core::CoreError::SecretNotFound(args.key.clone()))?;
    if cli.json {
        let output = Output::new(true);
        output.data(&json!({
            "key": args.key,
            "value": entry.value.expose(),
            "expires_at": entry.expires_at,
        }))?;
        return Ok(0);
    }
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(entry.value.expose().as_bytes())
        .map_err(|err| CliError::io("<stdout>", err))?;
    if !args.no_newline {
        handle
            .write_all(b"\n")
            .map_err(|err| CliError::io("<stdout>", err))?;
    }
    handle
        .flush()
        .map_err(|err| CliError::io("<stdout>", err))?;
    Ok(0)
}

pub fn list(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let now = util::now_unix();
    let keys = inspect::key_infos(&vault, now);

    if cli.json {
        output.data(&json!({
            "vault": path,
            "vault_id": vault.vault_id_hex(),
            "revision": vault.revision(),
            "binding": vault.binding(),
            "keys": keys,
        }))?;
        return Ok(0);
    }

    if keys.is_empty() {
        output.text("No secrets yet. Add one with `velt set KEY --stdin`.");
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|key| {
            vec![
                key.name.clone(),
                key.kind.clone(),
                key.status.to_string(),
                util::format_timestamp(key.updated_at),
                key.expires_at
                    .map(util::format_timestamp)
                    .unwrap_or_else(|| "never".to_owned()),
            ]
        })
        .collect();
    util::print_table(&["KEY", "TYPE", "STATUS", "UPDATED", "EXPIRES"], &rows);
    Ok(0)
}

pub fn remove(cli: &Cli, args: &RemoveArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let mut context = WriteContext::open(&path)?;
    if context.vault.get(&args.key).is_none() {
        return Err(velt_core::CoreError::SecretNotFound(args.key.clone()).into());
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::msg(format!(
                "refusing to remove {} without --yes in a non-interactive shell",
                args.key
            )));
        }
        if !util::confirm(&format!("Remove {}?", args.key))? {
            output.text("Not removed.");
            return Ok(0);
        }
    }
    context.vault.remove(&args.key);
    context.save()?;
    if cli.json {
        output.data(&json!({"removed": args.key, "revision": context.vault.revision()}))?;
    } else {
        output.text(&format!("Removed {}", args.key));
    }
    Ok(0)
}
