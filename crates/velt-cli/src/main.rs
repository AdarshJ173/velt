//! `velt` entry point.

mod agent;
mod cli;
mod commands;
mod config;
mod context;
mod envfile;
mod error;
mod redact;
mod util;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    if cli.llm_docs {
        print!("{}", agent::LLM_DOCS);
        return;
    }
    match commands::dispatch(&cli) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if cli.json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "error": {
                            "kind": error.kind(),
                            "message": error.to_string(),
                        }
                    })
                );
            } else {
                eprintln!("error: {error}");
            }
            std::process::exit(1);
        }
    }
}
