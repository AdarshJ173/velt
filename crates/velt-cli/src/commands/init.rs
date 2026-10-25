//! `velt init`: stack detection, `.env` import, encrypted vault creation and
//! agent guardrail installation.

use std::io::IsTerminal;
use std::path::PathBuf;

use serde::Serialize;
use velt_core::detect::{self, StackInfo};
use velt_core::vault::read_vault_id;
use velt_core::{MasterKey, Vault};

use crate::agent;
use crate::cli::{Cli, InitArgs};
use crate::context;
use crate::envfile;
use crate::error::{CliError, Result};
use crate::util::{self, Output};

pub fn execute(cli: &Cli, args: &InitArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let project_root = std::env::current_dir().map_err(|err| CliError::io(".", err))?;
    let vault_path = context::init_path(cli.vault.clone())?;

    if args.no_import_env && args.shred_env {
        return Err(CliError::msg(
            "--shred-env requires importing the .env file; remove --no-import-env",
        ));
    }

    let existing = vault_path.exists();
    if existing && !args.force {
        return Err(CliError::msg(format!(
            "vault already exists at {}; use --force to replace it",
            vault_path.display()
        )));
    }
    let previous_vault_id = if existing {
        read_vault_id(&vault_path).ok()
    } else {
        None
    };

    let stacks = detect::detect(&project_root);
    let env_path = project_root.join(".env");
    let env_exists = env_path.is_file();
    let mut imported = 0usize;
    let mut skipped = Vec::new();
    let mut parsed = envfile::ParsedEnv::default();
    if env_exists && !args.no_import_env {
        parsed = envfile::parse_file(&env_path)?;
        imported = parsed.entries.len();
        skipped = parsed.skipped.clone();
    }

    let key = MasterKey::generate()?;
    let mut vault = Vault::new(&vault_path, None)?;
    for (name, value) in parsed.entries {
        vault.set(&name, value, None)?;
    }

    // Store the key before writing the vault so a partial failure cannot leave
    // an unreadable vault behind. If the save fails, remove the key again.
    let vault_id = vault.header.vault_id;
    context::store_master_key(&vault_id, &key)?;
    if let Err(error) = vault.save(&key) {
        let _ = context::delete_master_key(&vault_id);
        return Err(error.into());
    }
    if let Some(previous) = previous_vault_id {
        if previous != vault_id {
            let _ = context::delete_master_key(&previous);
        }
    }

    let mut warnings = Vec::new();
    let agent_files = if args.no_agent_files {
        agent::ensure_gitignore(&project_root)?;
        Vec::new()
    } else {
        let installed = agent::install_guardrails(&project_root);
        warnings.extend(installed.warnings);
        installed.files
    };

    let mut env_shredded = false;
    if env_exists && !args.no_import_env {
        let should_shred = if args.shred_env {
            true
        } else if args.keep_env {
            false
        } else if !cli.json && std::io::stdin().is_terminal() {
            util::confirm(
                "Shred the imported .env file? (best-effort overwrite + unlink; SSD copies may remain)",
            )?
        } else {
            false
        };
        if should_shred {
            envfile::shred(&env_path)?;
            env_shredded = true;
        } else {
            warnings.push(format!(
                "plaintext {} still exists; pass --shred-env next time or delete it manually",
                env_path.display()
            ));
        }
    }

    for name in &skipped {
        warnings.push(format!("skipped invalid .env key: {name}"));
    }

    let report = InitReport {
        vault: vault_path.clone(),
        vault_id: hex::encode(vault_id),
        detected: stacks.clone(),
        imported,
        skipped: skipped.clone(),
        env_shredded,
        agent_files: agent_files.clone(),
        warnings: warnings.clone(),
    };

    if cli.json {
        output.data(&report)?;
        return Ok(0);
    }

    output.text(&format!(
        "Vault created: {} ({})",
        vault_path.display(),
        short_id(&vault_id)
    ));
    if stacks.is_empty() {
        output.text("Detected stack: none (plain project)");
    } else {
        let summary = stacks
            .iter()
            .map(StackInfo::summary)
            .collect::<Vec<_>>()
            .join(", ");
        output.text(&format!("Detected stack: {summary}"));
    }
    if !env_exists {
        output.text("No .env file found; the vault is empty.");
    } else if args.no_import_env {
        output.text("Existing .env was not imported (--no-import-env).");
    } else {
        output.text(&format!("Imported {imported} secret(s) from .env."));
    }
    if env_shredded {
        output.text("The plaintext .env was overwritten and removed.");
    }
    if !agent_files.is_empty() {
        output.text(&format!(
            "Agent guardrails installed in {} file(s).",
            agent_files.len()
        ));
    }
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    output.text("");
    output.text("Next steps:");
    output.text("  velt inspect --json          # key names and status, never values");
    output.text("  velt set NEW_KEY --stdin     # add a secret without shell history");
    if let Some(hint) = stacks.iter().find_map(|stack| stack.run_hint.clone()) {
        output.text(&format!("  {hint}"));
    } else {
        output.text("  velt run -- <command>        # inject secrets + redact output");
    }
    Ok(0)
}

fn short_id(vault_id: &[u8; 16]) -> String {
    format!("id {}", hex::encode(&vault_id[..6]))
}

#[derive(Debug, Serialize)]
struct InitReport {
    vault: PathBuf,
    vault_id: String,
    detected: Vec<StackInfo>,
    imported: usize,
    skipped: Vec<String>,
    env_shredded: bool,
    agent_files: Vec<PathBuf>,
    warnings: Vec<String>,
}
