//! CLI error type. Errors never include secret values.

use std::io;
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Core(#[from] velt_core::CoreError),

    #[error("{0}")]
    Message(String),

    #[error("{0}")]
    Config(String),

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("server returned {status}: {message}")]
    Server { status: u16, message: String },

    #[error("terminal error: {0}")]
    Terminal(String),
}

impl CliError {
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Core(_) => "core",
            Self::Message(_) => "error",
            Self::Config(_) => "config",
            Self::Io { .. } => "io",
            Self::Json(_) | Self::TomlDe(_) | Self::TomlSer(_) => "serialization",
            Self::Network(_) => "network",
            Self::Server { .. } => "server",
            Self::Terminal(_) => "terminal",
        }
    }
}

pub type Result<T, E = CliError> = std::result::Result<T, E>;
