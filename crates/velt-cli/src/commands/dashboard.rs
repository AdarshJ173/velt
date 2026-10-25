//! `velt dashboard`: mint a one-time browser login link for team managers.

use serde_json::json;

use crate::cli::Cli;
use crate::error::Result;
use crate::remote;
use crate::util::Output;

pub fn execute(cli: &Cli) -> Result<i32> {
    let output = Output::new(cli.json);
    let session = remote::session()?;
    let link = session.api.dashboard_session()?;
    let url = if link.path.starts_with("http://") || link.path.starts_with("https://") {
        link.path.clone()
    } else {
        format!("{}{}", session.api.base_url(), link.path)
    };
    if cli.json {
        output.data(&json!({
            "url": url,
            "expires_at": link.expires_at,
            "ttl_seconds": 300,
        }))?;
    } else {
        output.text("Dashboard login link (single use, expires in 5 minutes):");
        output.text(&url);
        output.text("");
        output.text("Open it in a browser on this machine and press Continue. The dashboard can manage members and audit access, but never decrypts secrets.");
    }
    Ok(0)
}
