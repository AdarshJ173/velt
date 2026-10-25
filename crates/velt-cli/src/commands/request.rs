//! Human-in-the-loop secret requests.
//!
//! Request metadata is local (`<project>/.velt/requests/*.json`) and contains no
//! secret values. An agent creates a request; a human fulfills it with a hidden
//! prompt. Optional desktop/Slack notifications never include secret values.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use velt_core::vault::{now_unix, validate_name, VaultLock};

use crate::cli::RequestArgs;
use crate::error::{CliError, Result};
use crate::redact::{capture_scrubbed, SecretPatterns};
use crate::util::{self, Output};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Pending,
    Fulfilled,
    Denied,
}

impl std::fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pending => "pending",
            Self::Fulfilled => "fulfilled",
            Self::Denied => "denied",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestRecord {
    pub id: String,
    pub key: String,
    pub reason: String,
    pub status: RequestStatus,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fulfilled_at: Option<i64>,
}

pub fn execute(cli: &crate::cli::Cli, args: &RequestArgs) -> Result<i32> {
    if let Some(id) = &args.fulfill {
        return fulfill(cli, id, args.from_stdin);
    }
    if args.list {
        return list(cli);
    }
    if let Some(id) = &args.status {
        return status(cli, id);
    }
    if let Some(id) = &args.deny {
        return deny(cli, id);
    }
    if let Some(key) = &args.key {
        return create(cli, key, &args.reason, args.wait, args.timeout);
    }
    Err(CliError::msg(
        "specify a key to request, or use --fulfill, --status, --deny, or --list",
    ))
}

pub fn requests_dir(vault_path: &Path) -> PathBuf {
    crate::context::project_root(vault_path)
        .join(".velt")
        .join("requests")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|err| CliError::io(path, err))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn record_path(directory: &Path, id: &str) -> Result<PathBuf> {
    let uuid = Uuid::parse_str(id).map_err(|_| CliError::msg("request id must be a UUID"))?;
    Ok(directory.join(format!("{uuid}.json")))
}

fn read_record(path: &Path) -> Result<RequestRecord> {
    let contents = fs::read_to_string(path).map_err(|err| CliError::io(path, err))?;
    let record: RequestRecord = serde_json::from_str(&contents)?;
    Ok(record)
}

fn write_record(directory: &Path, record: &RequestRecord) -> Result<()> {
    let path = record_path(directory, &record.id)?;
    let contents = serde_json::to_vec_pretty(record)?;
    crate::config::write_private(&path, &contents)
}

fn scan(directory: &Path) -> Result<Vec<RequestRecord>> {
    let mut records = Vec::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return Ok(records);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        if let Ok(record) = read_record(&path) {
            records.push(record);
        }
    }
    records.sort_by_key(|record| record.created_at);
    Ok(records)
}

fn pending_for_key(directory: &Path, key: &str) -> Result<Option<RequestRecord>> {
    Ok(scan(directory)?
        .into_iter()
        .rev()
        .find(|record| record.key == key && record.status == RequestStatus::Pending))
}

fn sanitize_reason(reason: &str, patterns: &SecretPatterns) -> String {
    let limited: String = reason.chars().take(1000).collect();
    let sanitized = capture_scrubbed(limited.as_bytes(), patterns, 4096)
        .map(|output| String::from_utf8_lossy(&output.bytes).into_owned())
        .unwrap_or(limited);
    sanitized
}

fn requested_by() -> Option<String> {
    for key in ["VELT_AGENT_ID", "VELT_AGENT", "USER"] {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

/// Create a pending request and return it. Used by the CLI and MCP server.
pub fn create_request(
    vault_path: &Path,
    key: &str,
    reason: &str,
    patterns: &SecretPatterns,
) -> Result<RequestRecord> {
    validate_name(key)?;
    let directory = requests_dir(vault_path);
    ensure_private_dir(&directory)?;
    let lock = VaultLock::acquire(&directory.join("requests.lock"))?;
    if let Some(existing) = pending_for_key(&directory, key)? {
        drop(lock);
        return Ok(existing);
    }
    let now = now_unix();
    let id = Uuid::new_v4().to_string();
    let record = RequestRecord {
        id,
        key: key.to_owned(),
        reason: sanitize_reason(reason, patterns),
        status: RequestStatus::Pending,
        created_at: now,
        updated_at: now,
        requested_by: requested_by(),
        fulfilled_at: None,
    };
    write_record(&directory, &record)?;
    drop(lock);
    notify(&record);
    Ok(record)
}

pub fn load_request(vault_path: &Path, id: &str) -> Result<RequestRecord> {
    let directory = requests_dir(vault_path);
    let path = record_path(&directory, id)?;
    read_record(&path)
}

fn create(cli: &crate::cli::Cli, key: &str, reason: &str, wait: bool, timeout: u64) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&vault_path)?;
    if vault.get(key).is_some() {
        if cli.json {
            output.data(&json!({
                "key": key,
                "status": "already_present",
                "fulfilled": true,
            }))?;
        } else {
            output.text(&format!("{key} is already present in the vault."));
        }
        return Ok(0);
    }
    let patterns = SecretPatterns::from_pairs(&vault.env_pairs());
    let record = create_request(&vault_path, key, reason, &patterns)?;

    if !wait {
        if cli.json {
            output.data(&record)?;
        } else {
            output.text(&format!("Requested {}.", record.key));
            output.text(&format!("Request id: {}", record.id));
            if record.status == RequestStatus::Pending {
                output.text(&format!(
                    "A human can fulfill it with: velt request fulfill {}",
                    record.id
                ));
            }
        }
        return Ok(0);
    }

    let deadline = Instant::now() + Duration::from_secs(timeout.max(1));
    loop {
        let current = load_request(&vault_path, &record.id)?;
        if current.status != RequestStatus::Pending {
            return finish_wait(cli, &current, false);
        }
        if Instant::now() >= deadline {
            return finish_wait(cli, &current, true);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn finish_wait(cli: &crate::cli::Cli, record: &RequestRecord, timed_out: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    if cli.json {
        output.data(&json!({
            "request": record,
            "timed_out": timed_out,
        }))?;
    } else if record.status == RequestStatus::Fulfilled {
        output.text(&format!("{} was fulfilled.", record.key));
    } else if record.status == RequestStatus::Denied {
        output.text(&format!("Request for {} was denied.", record.key));
    } else {
        output.text(&format!(
            "Request for {} is still pending (timed out).",
            record.key
        ));
    }
    Ok(if record.status == RequestStatus::Fulfilled {
        0
    } else {
        1
    })
}

fn fulfill(cli: &crate::cli::Cli, id: &str, from_stdin: bool) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let directory = requests_dir(&vault_path);
    ensure_private_dir(&directory)?;
    let lock = VaultLock::acquire(&directory.join("requests.lock"))?;
    let path = record_path(&directory, id)?;
    let mut record = read_record(&path)?;
    if record.status != RequestStatus::Pending {
        return Err(CliError::msg(format!(
            "request {} is already {}",
            record.id, record.status
        )));
    }

    let mut context = crate::context::WriteContext::open(&vault_path)?;
    if context.vault.get(&record.key).is_some() {
        record.status = RequestStatus::Fulfilled;
        record.updated_at = now_unix();
        record.fulfilled_at = Some(now_unix());
        write_record(&directory, &record)?;
        drop(lock);
        if cli.json {
            output.data(&json!({"request": record, "unchanged": true}))?;
        } else {
            output.text(&format!(
                "{} is already present; request marked fulfilled.",
                record.key
            ));
        }
        return Ok(0);
    }

    let value = util::read_secret(None, from_stdin, &format!("Value for {}: ", record.key))?;
    context.vault.set(&record.key, value, None)?;
    context.save()?;
    record.status = RequestStatus::Fulfilled;
    record.updated_at = now_unix();
    record.fulfilled_at = Some(now_unix());
    write_record(&directory, &record)?;
    drop(lock);

    if cli.json {
        output.data(&json!({"request": record, "stored": true}))?;
    } else {
        output.text(&format!(
            "Fulfilled {} (request {}).",
            record.key, record.id
        ));
    }
    Ok(0)
}

fn status(cli: &crate::cli::Cli, id: &str) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let record = load_request(&vault_path, id)?;
    if cli.json {
        output.data(&record)?;
    } else {
        output.text(&format!("Request {}", record.id));
        output.text(&format!("Key: {}", record.key));
        output.text(&format!("Status: {}", record.status));
        if !record.reason.is_empty() {
            output.text(&format!("Reason: {}", record.reason));
        }
        if let Some(agent) = &record.requested_by {
            output.text(&format!("Requested by: {agent}"));
        }
    }
    Ok(0)
}

fn list(cli: &crate::cli::Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let directory = requests_dir(&vault_path);
    let records = scan(&directory)?;
    if cli.json {
        output.data(&records)?;
        return Ok(0);
    }
    if records.is_empty() {
        output.text("No requests.");
        return Ok(0);
    }
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|record| {
            vec![
                record.id.clone(),
                record.key.clone(),
                record.status.to_string(),
                util::format_timestamp(record.created_at),
                record
                    .requested_by
                    .clone()
                    .unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect();
    util::print_table(&["ID", "KEY", "STATUS", "CREATED", "REQUESTED BY"], &rows);
    Ok(0)
}

fn deny(cli: &crate::cli::Cli, id: &str) -> Result<i32> {
    let output = Output::new(cli.json);
    let vault_path = crate::context::discover_vault(cli.vault.clone())?;
    let directory = requests_dir(&vault_path);
    ensure_private_dir(&directory)?;
    let lock = VaultLock::acquire(&directory.join("requests.lock"))?;
    let path = record_path(&directory, id)?;
    let mut record = read_record(&path)?;
    if record.status != RequestStatus::Pending {
        return Err(CliError::msg(format!(
            "request {} is already {}",
            record.id, record.status
        )));
    }
    record.status = RequestStatus::Denied;
    record.updated_at = now_unix();
    write_record(&directory, &record)?;
    drop(lock);
    if cli.json {
        output.data(&record)?;
    } else {
        output.text(&format!("Denied request {} ({}).", record.id, record.key));
    }
    Ok(0)
}

fn notify(record: &RequestRecord) {
    let message = format!(
        "{} requested{}: {}",
        record.key,
        record
            .requested_by
            .as_deref()
            .map(|agent| format!(" by {agent}"))
            .unwrap_or_default(),
        if record.reason.is_empty() {
            "no reason given"
        } else {
            &record.reason
        }
    );
    let _ = Command::new("notify-send")
        .arg("Velt secret request")
        .arg(&message)
        .spawn();

    if let Ok(webhook) = std::env::var("VELT_SLACK_WEBHOOK_URL") {
        if webhook.starts_with("https://") {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build();
            if let Ok(client) = client {
                let text = format!(
                    "Velt secret request: `{}`\n{}\nFulfill: `velt request fulfill {}`",
                    record.key,
                    if record.reason.is_empty() {
                        "No reason provided."
                    } else {
                        &record.reason
                    },
                    record.id
                );
                let _ = client.post(webhook).json(&json!({"text": text})).send();
            }
        }
    }
}
