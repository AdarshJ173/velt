//! Relay authentication commands.

use serde_json::json;

use crate::cli::{AuthArgs, AuthCommand, Cli};
use crate::error::{CliError, Result};
use crate::remote;
use crate::util::Output;

pub fn execute(cli: &Cli, args: &AuthArgs) -> Result<i32> {
    match &args.command {
        AuthCommand::Register(args) => register(cli, args),
        AuthCommand::Login { username } => login(cli, username.as_deref()),
        AuthCommand::Status => status(cli),
        AuthCommand::Logout => logout(cli),
    }
}

fn register(cli: &Cli, args: &crate::cli::AuthRegisterArgs) -> Result<i32> {
    let output = Output::new(cli.json);
    let username = args
        .username
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    if username.is_empty() {
        return Err(CliError::msg("username must not be empty"));
    }
    let session = remote::register(&args.server, &username, args.ssh_key.as_deref())?;
    let me = session.api.me()?;
    if cli.json {
        output.data(&json!({
            "server": session.api.base_url(),
            "username": me.user.username,
            "authenticated": true,
            "teams": me.teams,
        }))?;
    } else {
        output.text(&format!(
            "Registered and authenticated as {} against {}.",
            me.user.username,
            session.api.base_url()
        ));
        output.text(&format!(
            "SSH key: {}",
            session.config.ssh_key_path()?.display()
        ));
    }
    Ok(0)
}

fn login(cli: &Cli, username: Option<&str>) -> Result<i32> {
    let output = Output::new(cli.json);
    let mut config = crate::config::load()?;
    if config.server_url().is_none() {
        return Err(CliError::Config(
            "no sync server configured; run `velt auth register --server <url> --username <name>`"
                .to_owned(),
        ));
    }
    if let Some(username) = username {
        config.username = Some(username.trim().trim_start_matches('@').to_ascii_lowercase());
        crate::config::save(&config)?;
    }
    let token = remote::login(&config)?;
    let api = crate::api::ApiClient::new(&config.require_server_url()?, Some(token))?;
    let me = api.me()?;
    if cli.json {
        output.data(&json!({
            "server": api.base_url(),
            "username": me.user.username,
            "authenticated": true,
        }))?;
    } else {
        output.text(&format!(
            "Authenticated as {} against {}.",
            me.user.username,
            api.base_url()
        ));
    }
    Ok(0)
}

fn status(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let config = crate::config::load()?;
    let Some(server) = config.server_url() else {
        if cli.json {
            output.data(&json!({"authenticated": false, "reason": "no server configured"}))?;
        } else {
            output.text("No sync server configured.");
        }
        return Ok(1);
    };
    let Some(username) = config.username.clone() else {
        if cli.json {
            output.data(&json!({"authenticated": false, "reason": "no username configured"}))?;
        } else {
            output.text("No username configured.");
        }
        return Ok(1);
    };
    match remote::session() {
        Ok(session) => {
            let me = session.api.me()?;
            if cli.json {
                output.data(&json!({
                    "server": server,
                    "username": username,
                    "authenticated": true,
                    "teams": me.teams,
                }))?;
            } else {
                output.text(&format!("Server: {server}"));
                output.text(&format!("Username: {}", me.user.username));
                output.text("Session: authenticated");
                output.text(&format!("Teams: {}", me.teams.len()));
                for team in me.teams {
                    output.text(&format!("  {}  {}  {}", team.id, team.name, team.role));
                }
            }
            Ok(0)
        }
        Err(error) => {
            if cli.json {
                output.data(&json!({
                    "server": server,
                    "username": username,
                    "authenticated": false,
                    "reason": error.to_string(),
                }))?;
            } else {
                output.text(&format!("Server: {server}"));
                output.text(&format!("Username: {username}"));
                output.text(&format!("Session: not authenticated ({error})"));
            }
            Ok(1)
        }
    }
}

fn logout(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let config = crate::config::load()?;
    if config.server_url().is_none() || config.username.is_none() {
        if cli.json {
            output.data(&json!({"logged_out": false, "reason": "not configured"}))?;
        } else {
            output.text("Not configured; nothing to log out.");
        }
        return Ok(0);
    }
    remote::logout()?;
    if cli.json {
        output.data(&json!({"logged_out": true}))?;
    } else {
        output.text("Logged out and removed the local session token.");
    }
    Ok(0)
}
