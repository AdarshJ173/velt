//! Server configuration from environment variables.

use std::net::SocketAddr;

use crate::error::{ApiError, ApiResult};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    pub session_ttl_seconds: i64,
    pub challenge_ttl_seconds: i64,
    pub max_blob_bytes: usize,
    pub max_envelopes: usize,
    pub public_url: Option<String>,
}

impl Config {
    pub fn from_env() -> ApiResult<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "DATABASE_URL must be set (PostgreSQL connection string)".to_owned(),
                )
            })?;

        let bind = std::env::var("VELT_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| ApiError::BadRequest("VELT_BIND must be a socket address".to_owned()))?;

        let session_ttl_hours = env_i64("VELT_SESSION_TTL_HOURS", 24).clamp(1, 720);
        let challenge_ttl_seconds = env_i64("VELT_CHALLENGE_TTL_SECONDS", 300).clamp(30, 900);
        let max_blob_bytes =
            env_i64("VELT_MAX_BLOB_BYTES", 4 * 1024 * 1024).clamp(1024, 16 * 1024 * 1024) as usize;
        let max_envelopes = env_i64("VELT_MAX_ENVELOPES", 512).clamp(1, 4096) as usize;
        let public_url = std::env::var("VELT_PUBLIC_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim_end_matches('/').to_owned());

        Ok(Self {
            database_url,
            bind,
            session_ttl_seconds: session_ttl_hours * 3600,
            challenge_ttl_seconds,
            max_blob_bytes,
            max_envelopes,
            public_url,
        })
    }
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
