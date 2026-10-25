//! Model Context Protocol server over stdio.
//!
//! Implements JSON-RPC 2.0 with MCP tools and resources. stdout is reserved for
//! protocol messages; diagnostics go to stderr. Secrets are never returned by
//! inspection tools, and command output from `velt_run` is always redacted.
//!
//! Trust boundary: the MCP client controls the user's shell anyway. Velt's value
//! here is scoped injection, redaction, leases, and value-free schema discovery.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use serde_json::{json, Value};
use velt_core::audit;
use velt_core::lease;
use velt_core::vault::{now_unix, read_vault_id};

use crate::agent;
use crate::cli::{Cli, McpArgs};
use crate::commands::{inspect, request, run};
use crate::context;
use crate::error::{CliError, Result};
use crate::redact::SecretPatterns;

const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOOL_TIMEOUT_SECONDS: u64 = 600;

pub fn execute(cli: &Cli, args: &McpArgs) -> Result<i32> {
    let vault_path = context::discover_vault(cli.vault.clone())?;
    if !vault_path.is_file() {
        return Err(CliError::msg("vault not found"));
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut server = McpServer {
        vault_path,
        read_only: args.read_only,
    };

    let mut line = String::new();
    loop {
        line.clear();
        let read = input
            .read_line(&mut line)
            .map_err(|err| CliError::io("<stdin>", err))?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_LINE_BYTES {
            let error = jsonrpc_error(Value::Null, -32600, "request exceeds 4 MiB");
            write_message(&mut output, &error)?;
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(trimmed) {
            Ok(request) => request,
            Err(_) => {
                let error = jsonrpc_error(Value::Null, -32700, "parse error");
                write_message(&mut output, &error)?;
                continue;
            }
        };
        if let Some(response) = server.handle(&request)? {
            write_message(&mut output, &response)?;
        }
        if request.get("method").and_then(Value::as_str) == Some("exit") {
            break;
        }
    }
    Ok(0)
}

struct McpServer {
    vault_path: PathBuf,
    read_only: bool,
}

impl McpServer {
    fn handle(&mut self, request: &Value) -> Result<Option<Value>> {
        let id = request.get("id").cloned();
        let Some(method) = request.get("method").and_then(Value::as_str) else {
            return Ok(Some(jsonrpc_error(
                id.unwrap_or(Value::Null),
                -32600,
                "invalid request: missing method",
            )));
        };
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        // Notifications do not receive responses.
        match method {
            "notifications/initialized" => return Ok(None),
            "notifications/cancelled" => return Ok(None),
            _ => {}
        }
        let Some(id) = id else {
            return Ok(None);
        };

        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.tools()})),
            "tools/call" => self.call_tool(&params),
            "resources/list" => Ok(json!({"resources": self.resources()})),
            "resources/read" => self.read_resource(&params),
            "resources/templates/list" => Ok(json!({"resourceTemplates": []})),
            "prompts/list" => Ok(json!({"prompts": []})),
            _ => Err((-32601, format!("method not found: {method}"))),
        };

        Ok(Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => jsonrpc_error(id, code, &message),
        }))
    }

    fn initialize(&self, params: &Value) -> Value {
        let requested = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSIONS[0]);
        let protocol_version = PROTOCOL_VERSIONS
            .iter()
            .find(|version| **version == requested)
            .copied()
            .unwrap_or(PROTOCOL_VERSIONS[2]);
        json!({
            "protocolVersion": protocol_version,
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {"subscribe": false, "listChanged": false},
            },
            "serverInfo": {
                "name": "velt",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": "Velt exposes value-free secret schema inspection, auditing, scoped leases, and redacted command execution. Never ask a human to paste secrets into chat; use velt_request_secret and velt_request_status.",
        })
    }

    fn tools(&self) -> Vec<Value> {
        let mut tools = vec![
            json!({
                "name": "velt_inspect",
                "description": "List secret key names, inferred types and status. Never returns values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "require": {"type": "array", "items": {"type": "string"}}
                    },
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "velt_audit",
                "description": "Run offline secret hygiene checks and return findings without values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "include_files": {"type": "boolean", "default": true}
                    },
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "velt_lease_create",
                "description": "Mint an HMAC-signed, scoped, expiring capability lease for a subset of key names.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "allow": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        "deny": {"type": "array", "items": {"type": "string"}},
                        "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 604800, "default": 600},
                        "label": {"type": "string"}
                    },
                    "required": ["allow"],
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "velt_request_secret",
                "description": "Create a human-in-the-loop request for a missing secret. Do not ask for secrets in chat.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "reason": {"type": "string"}
                    },
                    "required": ["key", "reason"],
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "velt_request_status",
                "description": "Check whether a secret request was fulfilled or denied.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "request_id": {"type": "string"}
                    },
                    "required": ["request_id"],
                    "additionalProperties": false
                }
            }),
        ];
        if !self.read_only {
            tools.insert(
                0,
                json!({
                    "name": "velt_run",
                    "description": "Run a command with vault secrets injected and all child output redacted. Returns exit code, stdout and stderr.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                            "cwd": {"type": "string"},
                            "lease": {"type": "string"},
                            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "default": 120}
                        },
                        "required": ["command"],
                        "additionalProperties": false
                    }
                }),
            );
        }
        tools
    }

    fn resources(&self) -> Vec<Value> {
        vec![
            json!({
                "uri": "velt://vault/schema",
                "name": "Vault schema",
                "description": "Key names, inferred types and status; no values.",
                "mimeType": "application/json",
            }),
            json!({
                "uri": "velt://vault/audit",
                "name": "Vault audit",
                "description": "Latest offline audit findings; no values.",
                "mimeType": "application/json",
            }),
            json!({
                "uri": "velt://docs/llm",
                "name": "Agent documentation",
                "description": "Token-optimized Velt usage documentation for LLMs.",
                "mimeType": "text/markdown",
            }),
        ]
    }

    fn call_tool(&self, params: &Value) -> std::result::Result<Value, (i32, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "missing tool name".to_owned()))?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if name == "velt_run" && self.read_only {
            return Ok(tool_error("execution is disabled (--read-only)"));
        }
        let result = match name {
            "velt_inspect" => self.tool_inspect(&arguments),
            "velt_audit" => self.tool_audit(&arguments),
            "velt_run" => self.tool_run(&arguments),
            "velt_lease_create" => self.tool_lease(&arguments),
            "velt_request_secret" => self.tool_request(&arguments),
            "velt_request_status" => self.tool_request_status(&arguments),
            _ => return Err((-32602, format!("unknown tool: {name}"))),
        };
        Ok(match result {
            Ok(value) => tool_success(value),
            Err(error) => tool_error(&error.to_string()),
        })
    }

    fn tool_inspect(&self, arguments: &Value) -> Result<Value> {
        let require = string_array(arguments, "require")?;
        let (vault, _key) = context::open_vault(&self.vault_path)?;
        let now = now_unix();
        let keys = inspect::key_infos(&vault, now);
        let present: std::collections::BTreeSet<&str> =
            keys.iter().map(|key| key.name.as_str()).collect();
        let missing: Vec<&String> = require
            .iter()
            .filter(|name| !present.contains(name.as_str()))
            .collect();
        Ok(json!({
            "vault_id": vault.vault_id_hex(),
            "revision": vault.revision(),
            "format": vault.format_version(),
            "binding": vault.binding(),
            "keys": keys,
            "missing": missing,
        }))
    }

    fn tool_audit(&self, arguments: &Value) -> Result<Value> {
        let include_files = arguments
            .get("include_files")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let (vault, _key) = context::open_vault(&self.vault_path)?;
        let now = now_unix();
        let mut findings = audit::audit_entries(vault.entries(), now);
        if include_files {
            findings.extend(audit::audit_directory(
                &context::project_root(&self.vault_path),
                now,
            ));
        }
        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| left.subject.cmp(&right.subject))
        });
        Ok(json!({
            "findings": findings,
            "summary": {
                "error": findings.iter().filter(|finding| finding.severity == audit::Severity::Error).count(),
                "warning": findings.iter().filter(|finding| finding.severity == audit::Severity::Warning).count(),
                "info": findings.iter().filter(|finding| finding.severity == audit::Severity::Info).count(),
            }
        }))
    }

    fn tool_run(&self, arguments: &Value) -> Result<Value> {
        let command = string_array(arguments, "command")?;
        if command.is_empty() {
            return Err(CliError::msg("command must not be empty"));
        }
        let cwd = arguments
            .get("cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        let lease = arguments.get("lease").and_then(Value::as_str);
        let timeout = arguments
            .get("timeout_seconds")
            .and_then(Value::as_u64)
            .unwrap_or(120)
            .clamp(1, MAX_TOOL_TIMEOUT_SECONDS);
        let (vault, _key) = context::open_vault(&self.vault_path)?;
        let captured = run::capture(
            &vault,
            &command,
            cwd.as_deref(),
            lease,
            std::time::Duration::from_secs(timeout),
        )?;
        Ok(json!({
            "exit_code": captured.status,
            "timed_out": captured.timed_out,
            "stdout": captured.stdout,
            "stderr": captured.stderr,
            "stdout_truncated": captured.stdout_truncated,
            "stderr_truncated": captured.stderr_truncated,
            "redaction": "best-effort",
            "redaction_skipped": captured.redaction_skipped,
        }))
    }

    fn tool_lease(&self, arguments: &Value) -> Result<Value> {
        let allow = string_array(arguments, "allow")?;
        let deny = string_array(arguments, "deny")?;
        let ttl = arguments
            .get("ttl_seconds")
            .and_then(Value::as_i64)
            .unwrap_or(600);
        let label = arguments
            .get("label")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let vault_id = read_vault_id(&self.vault_path)?;
        let secret = context::lease_secret(&vault_id, true)?;
        let issued = lease::issue(
            &secret,
            &hex::encode(vault_id),
            &allow,
            &deny,
            ttl,
            label,
            None,
        )?;
        Ok(json!({
            "token": issued.token(),
            "claims": issued.payload(),
        }))
    }

    fn tool_request(&self, arguments: &Value) -> Result<Value> {
        let key = arguments
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::msg("missing key"))?;
        let reason = arguments
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("");
        let (vault, _key) = context::open_vault(&self.vault_path)?;
        if vault.get(key).is_some() {
            return Ok(json!({"key": key, "status": "already_present", "fulfilled": true}));
        }
        let patterns = SecretPatterns::from_pairs(&vault.env_pairs());
        let record = request::create_request(&self.vault_path, key, reason, &patterns)?;
        Ok(serde_json::to_value(record)?)
    }

    fn tool_request_status(&self, arguments: &Value) -> Result<Value> {
        let id = arguments
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::msg("missing request_id"))?;
        Ok(serde_json::to_value(request::load_request(
            &self.vault_path,
            id,
        )?)?)
    }

    fn read_resource(&self, params: &Value) -> std::result::Result<Value, (i32, String)> {
        let uri = params
            .get("uri")
            .and_then(Value::as_str)
            .ok_or((-32602, "missing resource uri".to_owned()))?;
        let (mime, text) = match uri {
            "velt://docs/llm" => ("text/markdown", agent::LLM_DOCS.to_owned()),
            "velt://vault/schema" => {
                let (vault, _key) = context::open_vault(&self.vault_path)
                    .map_err(|error| (-32603, error.to_string()))?;
                let keys = inspect::key_infos(&vault, now_unix());
                let value = json!({
                    "vault_id": vault.vault_id_hex(),
                    "revision": vault.revision(),
                    "binding": vault.binding(),
                    "keys": keys,
                });
                (
                    "application/json",
                    serde_json::to_string_pretty(&value)
                        .map_err(|error| (-32603, error.to_string()))?,
                )
            }
            "velt://vault/audit" => {
                let (vault, _key) = context::open_vault(&self.vault_path)
                    .map_err(|error| (-32603, error.to_string()))?;
                let now = now_unix();
                let mut findings = audit::audit_entries(vault.entries(), now);
                findings.extend(audit::audit_directory(
                    &context::project_root(&self.vault_path),
                    now,
                ));
                let value = json!({
                    "findings": findings,
                    "generated_at": now,
                });
                (
                    "application/json",
                    serde_json::to_string_pretty(&value)
                        .map_err(|error| (-32603, error.to_string()))?,
                )
            }
            _ => return Err((-32602, format!("unknown resource: {uri}"))),
        };
        Ok(json!({
            "contents": [{
                "uri": uri,
                "mimeType": mime,
                "text": text,
            }]
        }))
    }
}

fn string_array(arguments: &Value, field: &str) -> Result<Vec<String>> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| CliError::msg(format!("{field} must contain strings")))
            })
            .collect(),
        Some(_) => Err(CliError::msg(format!(
            "{field} must be an array of strings"
        ))),
    }
}

fn tool_success(value: Value) -> Value {
    let text = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|_| "{\"error\":\"serialization failed\"}".to_owned());
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": false,
    })
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    })
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

fn write_message(output: &mut impl Write, message: &Value) -> Result<()> {
    serde_json::to_writer(&mut *output, message)?;
    output
        .write_all(b"\n")
        .map_err(|err| CliError::io("<stdout>", err))?;
    output.flush().map_err(|err| CliError::io("<stdout>", err))
}
