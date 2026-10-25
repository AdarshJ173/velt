//! Command dispatch.

pub mod audit;
pub mod auth;
pub mod dashboard;
pub mod edit;
pub mod init;
pub mod inspect;
pub mod lease;
pub mod local;
pub mod mcp;
pub mod recovery;
pub mod request;
pub mod run;
pub mod share;
pub mod sync;
pub mod team;

use crate::cli::{Cli, Command};
use crate::error::{CliError, Result};

pub fn dispatch(cli: &Cli) -> Result<i32> {
    let Some(command) = &cli.command else {
        return Err(CliError::msg("no command provided; run `velt --help`"));
    };
    match command {
        Command::Init(args) => init::execute(cli, args),
        Command::Set(args) => local::set(cli, args),
        Command::Get(args) => local::get(cli, args),
        Command::List => local::list(cli),
        Command::Remove(args) => local::remove(cli, args),
        Command::Run(args) => run::execute(cli, args),
        Command::Audit(args) => audit::execute(cli, args),
        Command::Inspect(args) => inspect::execute(cli, args),
        Command::Edit => edit::execute(cli),
        Command::Recovery(args) => recovery::execute(cli, args),
        Command::Lease(args) => lease::execute(cli, args),
        Command::Request(args) => request::execute(cli, args),
        Command::Mcp(args) => mcp::execute(cli, args),
        Command::Auth(args) => auth::execute(cli, args),
        Command::Team(args) => team::execute(cli, args),
        Command::Sync(args) => sync::execute(cli, args),
        Command::Share(args) => share::execute(cli, args),
        Command::Dashboard => dashboard::execute(cli),
    }
}
