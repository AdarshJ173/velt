# Agent integration

Velt is designed for agents that must use credentials without ingesting them into model context.

## Discovery

```bash
velt --llm-docs          # token-optimized Markdown
velt inspect --json      # names, types, status; never values
```

`velt init` installs an idempotent protocol block into `.cursorrules`, `.windsurfrules`, `CLAUDE.md` and `.github/copilot-instructions.md`, writes a project `.mcp.json` that starts `velt mcp`, and updates `.gitignore` for `.env*` and `.velt/`.

## MCP server

```bash
velt mcp
```

JSON-RPC 2.0 over newline-delimited stdio. stdout is protocol-only; diagnostics go to stderr. Supported methods:

- `initialize`, `ping`
- `tools/list`, `tools/call`
- `resources/list`, `resources/read`
- `resources/templates/list`, `prompts/list` (empty)

### Tools

| Tool | Input | Behavior |
| --- | --- | --- |
| `velt_inspect` | `require?: string[]` | names, types, status, binding; no values |
| `velt_audit` | `include_files?: bool` | offline findings, no values |
| `velt_run` | `command: string[]`, `cwd?`, `lease?`, `timeout_seconds?` | inject + capture + redact; returns exit code/stdout/stderr |
| `velt_lease_create` | `allow: string[]`, `deny?`, `ttl_seconds?`, `label?` | mint scoped HMAC lease |
| `velt_request_secret` | `key`, `reason` | create human-in-the-loop request |
| `velt_request_status` | `request_id` | check request status |

`--read-only` removes `velt_run` from the tool list and rejects direct calls.

### Resources

- `velt://vault/schema`
- `velt://vault/audit`
- `velt://docs/llm`

## Scoped leases

```bash
TOKEN=$(velt lease create --allow 'DB_*' --allow 'STRIPE_*' --deny 'STRIPE_PROD_*' --ttl 10m --json | jq -r .token)
velt run --lease "$TOKEN" -- python migrate.py
```

- HMAC-SHA256 over JSON claims, signed by a per-vault key in the OS keychain.
- Claims: vault id, lease id, issued/expiry, allow/deny globs, optional label/parent.
- Verification is offline; expiry is checked at use time.
- Deny wins over allow; glob supports `*` and `?`.
- Vault-managed variables not granted by the lease are removed from the inherited child environment.
- Leases are bearer capabilities. Do not log them or commit them.

## Human-in-the-loop requests

```bash
velt request OPENAI_API_KEY --reason "embedding pipeline" --wait --json
```

1. Agent creates a request; Velt stores metadata under `.velt/requests/` (no values).
2. Velt optionally fires `notify-send` or posts to `VELT_SLACK_WEBHOOK_URL`.
3. A human runs `velt request --fulfill <id>` and enters the value through a hidden prompt (or `--stdin`).
4. The value is written to the encrypted vault. The agent polls `--status <id>` or uses the MCP status tool.

If the key already exists, the request immediately reports `already_present` without revealing it.

## Redaction

`velt run` redacts injected secrets from child stdout/stderr when output is captured (`auto` when either stream is not a TTY). The scrubber covers raw bytes, percent-encoding, standard/URL-safe base64 (padded/unpadded), JSON escaping and lowercase hex.

Known limitations:

- values shorter than 4 bytes are not redacted (would destroy ordinary output),
- values longer than 64 KiB are not redacted,
- hashing, chunking, encryption or side-channel output can evade any filter,
- child file/network writes are not intercepted.

Treat redaction as DLP, not confinement. Use containers/OS sandboxes for hard guarantees.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success / audit passed / request fulfilled |
| 1 | runtime error, audit findings at threshold, missing required key, denied request |
| 2 | CLI usage error |
| other | `velt run` returns the child exit code; 128+N on Unix signal death |

## Safe operating pattern

1. `velt inspect --json` to discover names/status.
2. `velt lease create` scoped to the task and shortest viable TTL.
3. `velt run --lease ... -- <command>` for execution.
4. Never ask for or print secret values; use `velt request` for missing keys.
5. Pull team updates with `velt sync pull` when the binding reports changes.
