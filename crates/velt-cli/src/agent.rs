//! Agent discovery files and the token-efficient LLM documentation.
//!
//! `velt init` installs a protocol block into the convention files used by
//! coding agents and a project-scoped MCP configuration. These files are
//! guardrails, not a sandbox: they tell an agent how to behave, while the
//! execution harness enforces injection and output redaction.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value as JsonValue};

use crate::error::{CliError, Result};

pub const BLOCK_START: &str = "<!-- velt:agent-protocol:start -->";
pub const BLOCK_END: &str = "<!-- velt:agent-protocol:end -->";

pub const AGENT_PROTOCOL: &str = r#"<!-- velt:agent-protocol:start -->
## Velt secret protocol (read before touching configuration)

- NEVER read, create, print, or commit `.env` files. Secrets live in the encrypted `.velt.vault`.
- Discover key names and status without values: `velt inspect --json`.
- Run every command that needs secrets as: `velt run -- <command>`.
- For scoped sub-agent work: `velt lease create --allow 'PREFIX_*' --ttl 10m` and then `velt run --lease <token> -- <command>`.
- If a key is missing, run `velt request KEY --reason "why it is needed"`; NEVER ask a human to paste a secret into chat.
- Never print environment variables, secrets, or decrypted vault contents. Velt redacts known secrets from child output, but do not attempt exfiltration.
- MCP clients: use the `velt mcp` server for inspect, audit, run, lease and request tools.

<!-- velt:agent-protocol:end -->"#;

pub const LLM_DOCS: &str = r#"# velt — agent documentation (v1)

Velt is a local-first, zero-knowledge secret execution harness. Secrets are stored in an encrypted `.velt.vault`; the master key lives in the OS credential store.

## Commands (all support --json where relevant)
- `velt inspect --json` — key names, inferred types, status; never values. `--require KEY` exits 1 if missing.
- `velt schema --json` — alias for inspect.
- `velt audit --json --fail-on error` — offline hygiene findings; never values.
- `velt run -- <cmd>` — inject secrets, forward signals, pass through the child exit code. Redacts injected secrets from child stdout/stderr when output is not a TTY; force with `--redact always`, disable with `--redact never`.
- `velt lease create --allow 'DB_*' --ttl 10m` — mint an HMAC-signed scoped capability.
- `velt run --lease <token> -- <cmd>` — inject only lease-allowed keys and redact them.
- `velt request KEY --reason "..." --wait --json` — request a missing secret from a human without exposing it in chat.
- `velt mcp` — MCP server over stdio (tools: velt_inspect, velt_audit, velt_run, velt_lease_create, velt_request_secret, velt_request_status).
- `velt ci run --team UUID --env production -- <cmd>` — headless CI injection with a CI-only identity; no local vault or keychain.

## Security invariants
- Never read or write plaintext `.env` files.
- Never print secret values; redaction is best-effort against encodings, not a sandbox.
- Leases are bearer capabilities. Keep them out of logs and source control.
- `velt run` inherits the parent environment, but removes vault-managed names that a lease does not allow.

## Exit codes
0 success; 1 error, failed audit, or missing required key; 2 CLI usage; otherwise the child's exit code (128+signal on Unix).
"#;

#[derive(Debug, Default)]
pub struct AgentInstall {
    pub files: Vec<PathBuf>,
    pub warnings: Vec<String>,
}

/// Install agent guardrails under `root`.
pub fn install_guardrails(root: &Path) -> AgentInstall {
    let mut install = AgentInstall::default();
    let targets = [
        root.join(".cursorrules"),
        root.join(".windsurfrules"),
        root.join("CLAUDE.md"),
        root.join(".github").join("copilot-instructions.md"),
    ];

    for path in targets {
        match upsert_block(&path, AGENT_PROTOCOL) {
            Ok(()) => install.files.push(path),
            Err(error) => install
                .warnings
                .push(format!("could not update {}: {error}", path.display())),
        }
    }

    match install_mcp_config(root) {
        Ok(path) => install.files.push(path),
        Err(error) => install
            .warnings
            .push(format!("could not write .mcp.json: {error}")),
    }

    match ensure_gitignore(root) {
        Ok(path) => install.files.push(path),
        Err(error) => install
            .warnings
            .push(format!("could not update .gitignore: {error}")),
    }

    install
}

fn upsert_block(path: &Path, block: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| CliError::io(parent, err))?;
    }
    let existing = fs::read_to_string(path).unwrap_or_default();
    let without_block = if let Some(start) = existing.find(BLOCK_START) {
        let end = existing[start..]
            .find(BLOCK_END)
            .map(|offset| start + offset + BLOCK_END.len())
            .unwrap_or(existing.len());
        format!("{}{}", &existing[..start], &existing[end..])
    } else {
        existing
    };
    let trimmed = without_block.trim_end();
    let mut updated = String::new();
    if !trimmed.is_empty() {
        updated.push_str(trimmed);
        updated.push_str("\n\n");
    }
    updated.push_str(block);
    updated.push('\n');
    fs::write(path, updated).map_err(|err| CliError::io(path, err))
}

fn install_mcp_config(root: &Path) -> Result<PathBuf> {
    let path = root.join(".mcp.json");
    let mut document = if path.exists() {
        let contents = fs::read_to_string(&path).map_err(|err| CliError::io(&path, err))?;
        serde_json::from_str::<JsonValue>(&contents).map_err(|_| {
            CliError::msg(format!(
                "{} is not valid JSON; refusing to overwrite it",
                path.display()
            ))
        })?
    } else {
        json!({})
    };
    let object = document
        .as_object_mut()
        .ok_or_else(|| CliError::msg(".mcp.json must contain a JSON object"))?;
    let servers = object
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| CliError::msg(".mcp.json mcpServers must be a JSON object"))?;
    servers.entry("velt").or_insert_with(|| {
        json!({
            "command": "velt",
            "args": ["mcp"]
        })
    });
    let formatted = serde_json::to_string_pretty(&document)?;
    fs::write(&path, format!("{formatted}\n")).map_err(|err| CliError::io(&path, err))?;
    Ok(path)
}

pub fn ensure_gitignore(root: &Path) -> Result<PathBuf> {
    let path = root.join(".gitignore");
    let existing = fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<&str> = existing.lines().collect();
    let required = [
        ".env",
        ".env.*",
        "!.env.example",
        ".velt/",
        "velt-recovery-*.txt",
    ];
    let mut changed = false;
    for pattern in required {
        if !lines.iter().any(|line| line.trim() == pattern) {
            lines.push(pattern);
            changed = true;
        }
    }
    if changed {
        let mut contents = lines.join("\n");
        contents.push('\n');
        fs::write(&path, contents).map_err(|err| CliError::io(&path, err))?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn guardrails_are_idempotent() {
        let dir = TempDir::new().unwrap();
        let first = install_guardrails(dir.path());
        assert!(first
            .files
            .iter()
            .any(|path| path.ends_with(".cursorrules")));
        let rules = fs::read_to_string(dir.path().join(".cursorrules")).unwrap();
        assert_eq!(rules.matches(BLOCK_START).count(), 1);

        install_guardrails(dir.path());
        let rules = fs::read_to_string(dir.path().join(".cursorrules")).unwrap();
        assert_eq!(rules.matches(BLOCK_START).count(), 1);
        assert_eq!(rules.matches(BLOCK_END).count(), 1);
    }

    #[test]
    fn existing_content_is_preserved() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("CLAUDE.md"), "# Project\n").unwrap();
        install_guardrails(dir.path());
        let contents = fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
        assert!(contents.starts_with("# Project"));
        assert!(contents.contains(BLOCK_START));
    }

    #[test]
    fn invalid_mcp_config_is_preserved() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".mcp.json"), "{ not valid").unwrap();
        let install = install_guardrails(dir.path());
        let contents = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        assert_eq!(contents, "{ not valid");
        assert!(install
            .warnings
            .iter()
            .any(|warning| warning.contains(".mcp.json")));
    }

    #[test]
    fn mcp_config_is_valid_json() {
        let dir = TempDir::new().unwrap();
        install_guardrails(dir.path());
        let contents = fs::read_to_string(dir.path().join(".mcp.json")).unwrap();
        let document: JsonValue = serde_json::from_str(&contents).unwrap();
        assert_eq!(document["mcpServers"]["velt"]["command"], "velt");
    }

    #[test]
    fn gitignore_is_updated_once() {
        let dir = TempDir::new().unwrap();
        install_guardrails(dir.path());
        install_guardrails(dir.path());
        let contents = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(contents.matches(".velt/").count(), 1);
        assert_eq!(contents.matches(".env").count(), 3); // .env, .env.*, !.env.example
    }
}
