//! Command-line interface definition (clap derive).

use std::ffi::OsString;
use std::path::PathBuf;

use uuid::Uuid;

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
    /// Authenticate against a Velt sync server using an SSH key.
    Auth(AuthArgs),
    /// Create and manage E2EE teams.
    Team(TeamArgs),
    /// Bind, push, pull and watch team environments.
    Sync(SyncArgs),
    /// Run a command with a team environment fetched headlessly (CI).
    Ci(CiArgs),
    /// Invite a teammate to the team bound to this vault.
    Share(ShareArgs),
    /// Mint a one-time browser link for the team dashboard.
    Dashboard,
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

#[derive(Debug, Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Register a username and SSH public key with a relay.
    Register(AuthRegisterArgs),
    /// Sign a challenge with the configured SSH key and store a session.
    Login {
        /// Override the configured username.
        #[arg(long)]
        username: Option<String>,
    },
    /// Show the configured server, username and session status.
    Status,
    /// Revoke the current session locally and on the server.
    Logout,
}

#[derive(Debug, Args)]
pub struct AuthRegisterArgs {
    /// Relay base URL, e.g. https://sync.example.com.
    #[arg(long)]
    pub server: String,

    /// Username to register.
    #[arg(long)]
    pub username: String,

    /// SSH private key path (defaults to ~/.ssh/id_ed25519).
    #[arg(long, value_name = "PATH")]
    pub ssh_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct TeamArgs {
    #[command(subcommand)]
    pub command: TeamCommand,
}

#[derive(Debug, Subcommand)]
pub enum TeamCommand {
    /// Create a team and generate its E2EE team key.
    Create { name: String },
    /// List teams you belong to.
    List,
    /// Show members and environments.
    Members {
        #[arg(long)]
        team: Option<Uuid>,
    },
    /// Invite a registered teammate and seal the team key to them.
    Invite(InviteArgs),
    /// Remove a teammate (run rotate-key afterwards).
    Remove {
        username: String,
        #[arg(long)]
        team: Option<Uuid>,
        #[arg(long)]
        yes: bool,
    },
    /// Rotate the team key and re-encrypt every environment.
    #[command(name = "rotate-key")]
    RotateKey {
        #[arg(long)]
        team: Option<Uuid>,
    },
    /// Delete a team you own.
    Delete {
        #[arg(long)]
        team: Uuid,
        #[arg(long)]
        yes: bool,
    },
    /// Show the audit trail for a team you administer.
    Audit {
        #[arg(long)]
        team: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}

#[derive(Debug, Args)]
pub struct InviteArgs {
    pub username: String,

    #[arg(long, default_value = "developer")]
    pub role: String,

    /// Environment grants (repeat or comma-separate). Defaults to the vault binding.
    #[arg(long, value_name = "ENV", value_delimiter = ',')]
    pub env: Vec<String>,

    /// Team id (defaults to the vault binding).
    #[arg(long)]
    pub team: Option<Uuid>,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub command: SyncCommand,
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Bind this vault to a team environment and fetch the team key.
    Init {
        #[arg(long)]
        team: Uuid,
        #[arg(long, alias = "env", value_name = "ENV")]
        environment: String,
        /// Replace an existing binding.
        #[arg(long)]
        force: bool,
    },
    /// Encrypt the vault and push it to the bound team environment.
    Push {
        #[arg(long)]
        force: bool,
    },
    /// Pull the bound environment, decrypt it, and update the local vault.
    Pull {
        #[arg(long)]
        force: bool,
        /// Keep local-only keys and let remote values win on conflicts.
        #[arg(long)]
        merge: bool,
    },
    /// Show local binding and remote environment metadata.
    Status,
    /// Stream team change events over WebSocket.
    Watch,
}

#[derive(Debug, Args)]
pub struct CiArgs {
    #[command(subcommand)]
    pub command: CiCommand,
}

#[derive(Debug, Subcommand)]
pub enum CiCommand {
    /// Fetch a team environment without a local vault or keychain writes.
    Run(CiRunArgs),
}

#[derive(Debug, Args)]
pub struct CiRunArgs {
    /// Team whose environment should be injected.
    #[arg(long)]
    pub team: Uuid,

    /// Environment name, e.g. production.
    #[arg(long, alias = "env", value_name = "ENV")]
    pub environment: String,

    /// Relay base URL (or VELT_SERVER_URL).
    #[arg(long, env = "VELT_SERVER_URL")]
    pub server: Option<String>,

    /// Registered CI username (or VELT_USERNAME).
    #[arg(long, env = "VELT_USERNAME")]
    pub username: Option<String>,

    /// Ed25519 SSH private key path (or VELT_SSH_KEY).
    #[arg(long, env = "VELT_SSH_KEY", value_name = "PATH")]
    pub ssh_key: Option<PathBuf>,

    /// 32-byte X25519 identity private key in hex (or VELT_IDENTITY_KEY).
    #[arg(long, env = "VELT_IDENTITY_KEY", hide_env_values = true)]
    pub identity_key: Option<String>,

    /// Redaction policy for child stdout/stderr.
    #[arg(long, value_enum, default_value_t = RedactMode::Auto)]
    pub redact: RedactMode,

    /// Command and arguments (use `--` before the command).
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct ShareArgs {
    pub username: String,

    #[arg(long, default_value = "developer")]
    pub role: String,

    /// Environment grants. Defaults to the bound environment.
    #[arg(long, value_name = "ENV", value_delimiter = ',')]
    pub env: Vec<String>,

    #[arg(long)]
    pub team: Option<Uuid>,
}
