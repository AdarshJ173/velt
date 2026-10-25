//! `velt share`: invite a teammate to the environment bound to this vault.

use crate::cli::{Cli, InviteArgs, ShareArgs};
use crate::error::Result;

pub fn execute(cli: &Cli, args: &ShareArgs) -> Result<i32> {
    let mut env = args.env.clone();
    if env.is_empty() {
        if let Some(binding) = bound_environment() {
            if args.team.is_none_or(|team| team.to_string() == binding.0) {
                env.push(binding.1);
            }
        }
    }
    let invite = InviteArgs {
        username: args.username.clone(),
        role: args.role.clone(),
        env,
        team: args.team,
    };
    crate::commands::team::invite(cli, &invite)
}

fn bound_environment() -> Option<(String, String)> {
    let path = crate::context::discover_vault(None).ok()?;
    let (vault, _key) = crate::context::open_vault(&path).ok()?;
    let binding = vault.binding()?;
    Some((binding.team_id.clone(), binding.environment.clone()))
}
