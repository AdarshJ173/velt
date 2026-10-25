//! Shamir recovery commands.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde_json::json;
use velt_core::recovery;
use velt_core::vault::read_vault_id;

use crate::cli::{Cli, RecoveryArgs, RecoveryCommand, RecoveryCreateArgs, RecoveryRestoreArgs};
use crate::error::{CliError, Result};
use crate::util::Output;

pub fn execute(cli: &Cli, args: &RecoveryArgs) -> Result<i32> {
    match &args.command {
        RecoveryCommand::Create(args) => create(cli, args),
        RecoveryCommand::Restore(args) => restore(cli, args),
    }
}

fn create(cli: &Cli, args: &RecoveryCreateArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, key) = crate::context::open_vault(&path)?;
    let shares = recovery::split(&key, vault.header.vault_id, args.threshold, args.shares)?;

    if let Some(directory) = &args.out_dir {
        fs::create_dir_all(directory).map_err(|err| CliError::io(directory, err))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(directory, fs::Permissions::from_mode(0o700));
        }
        let mut paths = Vec::with_capacity(shares.len());
        for (offset, share) in shares.iter().enumerate() {
            let path = directory.join(format!("velt-recovery-{}.txt", offset + 1));
            let contents = format!(
                "# Velt recovery share {index} of {total} (threshold {threshold})\n\
                 # Store this file offline and separately from the other shares.\n\
                 # Anyone with {threshold} shares can reconstruct the vault master key.\n\
                 {share}\n",
                index = offset + 1,
                total = shares.len(),
                threshold = args.threshold,
                share = share.as_str(),
            );
            crate::config::write_private(&path, contents.as_bytes())?;
            paths.push(path);
        }
        if cli.json {
            output.data(&json!({
                "vault": path,
                "vault_id": vault.vault_id_hex(),
                "threshold": args.threshold,
                "shares": shares.len(),
                "files": paths,
                "warning": "store shares offline, separately, and never together",
            }))?;
        } else {
            output.text(&format!(
                "Created {} recovery share(s), threshold {}. Files:",
                shares.len(),
                args.threshold
            ));
            for file in &paths {
                output.text(&format!("  {}", file.display()));
            }
            output.text("WARNING: store shares separately and offline. Any threshold of them reconstructs the key.");
        }
    } else if cli.json {
        output.data(&json!({
            "vault": path,
            "vault_id": vault.vault_id_hex(),
            "threshold": args.threshold,
            "shares": shares.iter().enumerate().map(|(offset, share)| json!({
                "index": offset + 1,
                "share": share.as_str(),
            })).collect::<Vec<_>>(),
            "warning": "store shares offline, separately, and never together",
        }))?;
    } else {
        output.text(&format!(
            "Recovery shares for vault {} (threshold {} of {}):",
            vault.vault_id_hex(),
            args.threshold,
            shares.len()
        ));
        for (offset, share) in shares.iter().enumerate() {
            output.text(&format!(
                "\nShare {}/{}:\n{}",
                offset + 1,
                shares.len(),
                share.as_str()
            ));
        }
        output.text("\nWARNING: store shares separately and offline. Any threshold of them reconstructs the key.");
    }
    Ok(0)
}

fn restore(cli: &Cli, args: &RecoveryRestoreArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let mut share_texts: Vec<String> = Vec::new();
    for path in &args.files {
        if path == Path::new("-") {
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .map_err(|err| CliError::io("<stdin>", err))?;
            for line in input.lines() {
                let line = line.trim();
                if line.starts_with("velt1.") {
                    share_texts.push(line.to_owned());
                }
            }
        } else {
            let contents = fs::read_to_string(path).map_err(|err| CliError::io(path, err))?;
            let mut found = false;
            for line in contents.lines() {
                let line = line.trim();
                if line.starts_with("velt1.") {
                    share_texts.push(line.to_owned());
                    found = true;
                }
            }
            if !found {
                return Err(CliError::msg(format!(
                    "no recovery share found in {}",
                    path.display()
                )));
            }
        }
    }
    if share_texts.is_empty() {
        return Err(CliError::msg("no recovery shares provided"));
    }
    let refs: Vec<&str> = share_texts.iter().map(String::as_str).collect();
    let (key, vault_id) = recovery::combine(&refs)?;

    if let Some(explicit) = &cli.vault {
        if explicit.exists() {
            let actual = read_vault_id(explicit)?;
            if actual != vault_id {
                return Err(velt_core::CoreError::ShareVaultMismatch.into());
            }
        }
    } else if let Ok(found) = crate::context::discover_vault(None) {
        let actual = read_vault_id(&found)?;
        if actual != vault_id {
            return Err(velt_core::CoreError::ShareVaultMismatch.into());
        }
    }

    crate::context::store_master_key(&vault_id, &key)?;
    if cli.json {
        output.data(&json!({
            "restored": true,
            "vault_id": hex::encode(vault_id),
            "key_store": "os-keychain",
        }))?;
    } else {
        output.text(&format!(
            "Master key restored to the OS credential store for vault {}.",
            hex::encode(vault_id)
        ));
        output.text("Verify with `velt list`.");
    }
    Ok(0)
}
