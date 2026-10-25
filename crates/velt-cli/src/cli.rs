//! Command-line interface definition (clap derive).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum RedactMode {
    /// Redact when stdout or stderr is not a terminal.
    #[default]
    Auto,
    /// Always capture and redact child output.
    Always,
    /// Never capture; inherit the parent terminal.
    Never,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum FailOn {
    Info,
    Warning,
    #[default]
    Error,
    Never,
}

#[derive(Debug, Parser)]
#[command(
    name = "velt",
    version,
    about = "Zero-knowledge secret execution for humans and agents",
    long_about = "Velt stores environment secrets in an authenticated, encrypted vault, injects them into child processes, redacts them from captured output, and syncs team environments with end-to-end encryption. It never writes a decrypted vault to disk.",
    after_help = "Agents: run `velt --llm-docs`. MCP clients: run `velt mcp`.",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Path to the vault file (defaults to nearest .velt.vault upward).
    #[arg(long, global = true, env = "VELT_VAULT", value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Emit machine-readable JSON on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Print token-optimized documentation for coding agents.
    #[arg(long, global = true)]
    pub llm_docs: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Detect the stack, import .env, and create an encrypted vault.
    Init(InitArgs),
    /// Add or update a secret.
    Set(SetArgs),
    /// Print a secret value to stdout.
    Get(GetArgs),
    /// List secret names and metadata without values.
    List,
    /// Remove a secret.
    Remove(RemoveArgs),
    /// Run a command with secrets injected and output redacted.
    Run(RunArgs),
    /// Audit the vault and plaintext .env files for hygiene problems.
    Audit(AuditArgs),
    /// Inspect key names, inferred types and status without values.
    #[command(alias = "schema")]
    Inspect(InspectArgs),
    /// Open the interactive terminal editor.
    Edit,
    /// Manage Shamir recovery shares.
    Recovery(RecoveryArgs),
    /// Mint or inspect scoped capability leases.
    Lease(LeaseArgs),
    /// Request a secret from a human, or fulfill a pending request.
    Request(RequestArgs),
    /// Run the Model Context Protocol server over stdio.
    Mcp(McpArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Replace an existing vault (the old master key is deleted from the keychain).
    #[arg(long)]
    pub force: bool,

    /// Overwrite and remove the existing .env after importing it.
    #[arg(long, conflicts_with = "keep_env")]
    pub shred_env: bool,

    /// Keep the existing .env file after importing it.
    #[arg(long, conflicts_with = "shred_env")]
    pub keep_env: bool,

    /// Do not import an existing .env file.
    #[arg(long)]
    pub no_import_env: bool,

    /// Do not write agent guardrail files (.cursorrules, CLAUDE.md, .mcp.json, ...).
    #[arg(long)]
    pub no_agent_files: bool,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// Environment variable name.
    pub key: String,

    /// Secret value. Omit to read from a hidden prompt or stdin.
    #[arg(value_name = "VALUE", conflicts_with = "from_stdin")]
    pub value: Option<String>,

    /// Read the value from stdin (one trailing newline is stripped).
    #[arg(long = "stdin")]
    pub from_stdin: bool,

    /// Expiry: 30d, 12h, 90m, RFC 3339, date, Unix seconds, or `never`.
    #[arg(long, value_name = "WHEN")]
    pub expires: Option<String>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    pub key: String,

    /// Do not append a trailing newline.
    #[arg(long)]
    pub no_newline: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub key: String,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Redaction policy for child stdout/stderr.
    #[arg(long, value_enum, default_value_t = RedactMode::Auto)]
    pub redact: RedactMode,

    /// Scoped launch lease token.
    #[arg(long, env = "VELT_LEASE", value_name = "TOKEN")]
    pub lease: Option<String>,

    /// Command and arguments (use `--` before the command).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Exit nonzero when a finding reaches this severity.
    #[arg(long, value_enum, default_value_t = FailOn::Error)]
    pub fail_on: FailOn,

    /// Only audit the vault; skip plaintext .env file scanning.
    #[arg(long)]
    pub no_files: bool,

    /// Additional regular-expression rule pack (JSON).
    #[arg(long, value_name = "FILE")]
    pub rules: Option<PathBuf>,

    /// Detached Ed25519 signature over the rule pack (hex or raw 64 bytes).
    #[arg(long, value_name = "FILE", requires = "rules")]
    pub rules_signature: Option<PathBuf>,

    /// Ed25519 public key (hex) used to verify the rule pack.
    #[arg(long, value_name = "HEX", requires = "rules")]
    pub rules_public_key: Option<String>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Required key names; exits 1 if any are missing. Repeat or comma-separate.
    #[arg(long = "require", value_name = "KEY", value_delimiter = ',')]
    pub require: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RecoveryArgs {
    #[command(subcommand)]
    pub command: RecoveryCommand,
}

#[derive(Debug, Subcommand)]
pub enum RecoveryCommand {
    /// Split the vault master key into recovery shares.
    Create(RecoveryCreateArgs),
    /// Reconstruct the master key from recovery shares.
    Restore(RecoveryRestoreArgs),
}

#[derive(Debug, Args)]
pub struct RecoveryCreateArgs {
    /// Number of shares required to reconstruct the key.
    #[arg(long, default_value_t = 2, value_name = "N")]
    pub threshold: u8,

    /// Total number of shares to generate (max 255).
    #[arg(long, default_value_t = 3, value_name = "N")]
    pub shares: u8,

    /// Write each share to a 0600 file in this directory instead of stdout.
    #[arg(long, value_name = "DIR")]
    pub out_dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RecoveryRestoreArgs {
    /// Share files; use `-` to read newline-delimited shares from stdin.
    #[arg(value_name = "SHARE_FILE", required = true)]
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Args)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub command: LeaseCommand,
}

#[derive(Debug, Subcommand)]
pub enum LeaseCommand {
    /// Mint a scoped lease token.
    Create(LeaseCreateArgs),
    /// Verify and print lease claims.
    Inspect(LeaseInspectArgs),
}

#[derive(Debug, Args)]
pub struct LeaseCreateArgs {
    /// Allowed key name globs (repeatable).
    #[arg(long, required = true, value_name = "PATTERN")]
    pub allow: Vec<String>,

    /// Denied key name globs; deny wins over allow.
    #[arg(long, value_name = "PATTERN")]
    pub deny: Vec<String>,

    /// Time to live: 90s, 10m, 1h, 2d.
    #[arg(long, default_value = "10m", value_name = "DURATION")]
    pub ttl: String,

    /// Human label stored in lease claims.
    #[arg(long)]
    pub label: Option<String>,

    /// Parent lease id, for delegation chains.
    #[arg(long)]
    pub parent: Option<String>,
}

#[derive(Debug, Args)]
pub struct LeaseInspectArgs {
    pub token: String,
}

#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Key to request from a human. Omit when using --fulfill/--status/--deny/--list.
    pub key: Option<String>,

    /// Why the agent needs this secret.
    #[arg(long, default_value = "")]
    pub reason: String,

    /// Block until the request is fulfilled, denied, or times out.
    #[arg(long)]
    pub wait: bool,

    /// Wait timeout in seconds.
    #[arg(long, default_value_t = 300, value_name = "SECONDS")]
    pub timeout: u64,

    /// Fulfill a pending request with a hidden prompt (or --stdin).
    #[arg(long, value_name = "ID", conflicts_with_all = ["status", "deny", "list", "key"])]
    pub fulfill: Option<String>,

    /// Show one request.
    #[arg(long, value_name = "ID", conflicts_with_all = ["fulfill", "deny", "list", "key"])]
    pub status: Option<String>,

    /// Deny a pending request.
    #[arg(long, value_name = "ID", conflicts_with_all = ["fulfill", "status", "list", "key"])]
    pub deny: Option<String>,

    /// List requests for this project.
    #[arg(long, conflicts_with_all = ["fulfill", "status", "deny", "key"])]
    pub list: bool,

    /// Read the fulfilled value from stdin instead of prompting.
    #[arg(long = "stdin", requires = "fulfill")]
    pub from_stdin: bool,
}

#[derive(Debug, Args)]
pub struct McpArgs {
    /// Expose read-only tools (inspect/audit/request status) but not execution.
    #[arg(long)]
    pub read_only: bool,
}
