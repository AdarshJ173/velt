//! `velt audit`: offline hygiene checks plus signed custom rule packs.

use std::fs;
use std::io::IsTerminal;
use std::path::Path;

use serde_json::json;
use velt_core::audit::{self, Finding, Severity};
use velt_core::rules::{parse_verifying_key, verify_signature, RuleSet};

use crate::cli::{AuditArgs, Cli, FailOn};
use crate::error::{CliError, Result};
use crate::util::{self, Output};

pub fn execute(cli: &Cli, args: &AuditArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let path = crate::context::discover_vault(cli.vault.clone())?;
    let (vault, _key) = crate::context::open_vault(&path)?;
    let now = util::now_unix();
    let mut findings = audit::audit_entries(vault.entries(), now);

    if !args.no_files {
        let root = crate::context::project_root(&path);
        findings.extend(audit::audit_directory(&root, now));
    }

    if let Some(rules_path) = &args.rules {
        let rule_bytes = fs::read(rules_path).map_err(|err| CliError::io(rules_path, err))?;
        let ruleset = RuleSet::parse(&rule_bytes)?;
        let signed = match (&args.rules_signature, &args.rules_public_key) {
            (Some(signature_path), Some(public_key_hex)) => {
                let signature = read_signature(signature_path)?;
                let verifying_key = parse_verifying_key(public_key_hex)?;
                verify_signature(&rule_bytes, &signature, &verifying_key)?;
                true
            }
            (None, None) => false,
            _ => {
                return Err(CliError::msg(
                    "custom rule packs require both --rules-signature and --rules-public-key, or neither",
                ));
            }
        };
        findings.extend(ruleset.apply(vault.entries()));
        if !signed {
            findings.push(Finding {
                severity: Severity::Info,
                code: "unsigned_ruleset",
                subject: rules_path.display().to_string(),
                message: "custom rule pack is unsigned; verify it with an Ed25519 public key"
                    .to_owned(),
            });
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                findings.push(Finding {
                    severity: Severity::Warning,
                    code: "vault_permissions",
                    subject: path.display().to_string(),
                    message: format!("vault file has mode {mode:o}; restrict it to 0600"),
                });
            }
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.code.cmp(right.code))
    });

    let threshold = match args.fail_on {
        FailOn::Info => Some(Severity::Info),
        FailOn::Warning => Some(Severity::Warning),
        FailOn::Error => Some(Severity::Error),
        FailOn::Never => None,
    };
    let failed = findings
        .iter()
        .any(|finding| threshold.is_some_and(|threshold| finding.severity >= threshold));
    let errors = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    let info = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Info)
        .count();

    if cli.json {
        output.data(&json!({
            "vault": path,
            "vault_id": vault.vault_id_hex(),
            "findings": findings,
            "summary": {"error": errors, "warning": warnings, "info": info},
            "failed": failed,
        }))?;
    } else if findings.is_empty() {
        output.text("No findings.");
    } else {
        let colors = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        for finding in &findings {
            let label = match finding.severity {
                Severity::Error => {
                    if colors {
                        "\x1b[31mERROR\x1b[0m"
                    } else {
                        "ERROR"
                    }
                }
                Severity::Warning => {
                    if colors {
                        "\x1b[33mWARN \x1b[0m"
                    } else {
                        "WARN"
                    }
                }
                Severity::Info => {
                    if colors {
                        "\x1b[34mINFO \x1b[0m"
                    } else {
                        "INFO"
                    }
                }
            };
            output.text(&format!(
                "{label}  {}  — {}",
                finding.subject, finding.message
            ));
        }
        output.text(&format!(
            "\n{errors} error(s), {warnings} warning(s), {info} info"
        ));
    }

    Ok(if failed { 1 } else { 0 })
}

fn read_signature(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).map_err(|err| CliError::io(path, err))?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.len() == 128 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex::decode(trimmed).map_err(|_| CliError::msg("rule signature is not valid hex"));
    }
    if bytes.len() == 64 {
        return Ok(bytes);
    }
    Err(CliError::msg(
        "rule signature must be 64 raw bytes or 128 hex characters",
    ))
}
