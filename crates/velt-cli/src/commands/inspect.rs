//! Value-free vault inspection for humans and agents.

use serde::Serialize;
use serde_json::json;
use velt_core::audit::{classify, SecretStatus};
use velt_core::Vault;

use crate::cli::{Cli, InspectArgs};
use crate::error::Result;
use crate::util::{self, Output};

#[derive(Clone, Debug, Serialize)]
pub struct KeyInfo {
    pub name: String,
    pub kind: String,
    pub status: SecretStatus,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
}

pub fn key_infos(vault: &Vault, now: i64) -> Vec<KeyInfo> {
    vault
        .entries()
        .iter()
        .map(|(name, entry)| KeyInfo {
            name: name.clone(),
            kind: infer_type(entry.value.expose()).to_owned(),
            status: classify(entry.value.expose(), entry.expires_at, now),
            updated_at: entry.updated_at,
            expires_at: entry.expires_at,
        })
        .collect()
}

pub fn infer_type(value: &str) -> &'static str {
    let trimmed = value.trim();
    if trimmed.starts_with("-----BEGIN") && trimmed.contains("PRIVATE KEY") {
        return "private_key";
    }
    for prefix in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "mariadb://",
        "mongodb://",
        "mongodb+srv://",
        "redis://",
        "rediss://",
    ] {
        if trimmed.starts_with(prefix) {
            return "database_url";
        }
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return "url";
    }
    if is_jwt(trimmed) {
        return "jwt";
    }
    if trimmed.eq_ignore_ascii_case("true") || trimmed.eq_ignore_ascii_case("false") {
        return "boolean";
    }
    if trimmed.parse::<i64>().is_ok() || trimmed.parse::<f64>().is_ok() {
        return "number";
    }
    if is_email(trimmed) {
        return "email";
    }
    "string"
}

fn is_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| !part.is_empty()) && parts[0].starts_with("eyJ")
}

fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains(char::is_whitespace)
}

pub fn execute(cli: &Cli, args: &InspectArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let now = util::now_unix();
    let keys = key_infos(&vault, now);
    let present: std::collections::BTreeSet<&str> =
        keys.iter().map(|key| key.name.as_str()).collect();
    let missing: Vec<String> = args
        .require
        .iter()
        .filter(|name| !present.contains(name.as_str()))
        .cloned()
        .collect();

    if cli.json {
        output.data(&json!({
            "vault": path,
            "vault_id": vault.vault_id_hex(),
            "revision": vault.revision(),
            "format": vault.format_version(),
            "binding": vault.binding(),
            "keys": keys,
            "required": args.require,
            "missing": missing,
        }))?;
    } else {
        if keys.is_empty() {
            output.text("Vault has no secrets.");
        } else {
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
        }
        if let Some(binding) = vault.binding() {
            output.text(&format!(
                "Binding: team {}, environment {}, key epoch {}",
                binding.team_id, binding.environment, binding.epoch
            ));
        }
        if !args.require.is_empty() {
            if missing.is_empty() {
                output.text("All required keys are present.");
            } else {
                output.text(&format!("Missing required keys: {}", missing.join(", ")));
            }
        }
    }

    if missing.is_empty() {
        Ok(0)
    } else {
        if !cli.json {
            eprintln!(
                "error: {} required key(s) missing: {}",
                missing.len(),
                missing.join(", ")
            );
        }
        Ok(1)
    }
}
