//! Shared server helpers: memberships, audit writes, tokens and time.

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::models::{MembershipRow, TeamRow};
use crate::validate::role_rank;

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn random_bytes<const N: usize>() -> ApiResult<[u8; N]> {
    let mut bytes = [0u8; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ApiError::Internal("OS random number generator failed".to_owned()))?;
    Ok(bytes)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn hash_token(token: &str) -> Vec<u8> {
    sha256(token.as_bytes()).to_vec()
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

pub async fn membership(
    pool: &PgPool,
    team_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Option<MembershipRow>> {
    let row = sqlx::query_as::<_, MembershipRow>(
        "SELECT user_id, role, env_grants FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn membership_conn(
    conn: &mut PgConnection,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<Option<MembershipRow>, sqlx::Error> {
    sqlx::query_as::<_, MembershipRow>(
        "SELECT user_id, role, env_grants FROM team_members WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(user_id)
    .fetch_optional(conn)
    .await
}

pub async fn team(pool: &PgPool, team_id: Uuid) -> ApiResult<TeamRow> {
    sqlx::query_as::<_, TeamRow>(
        "SELECT id, name, owner_id, key_epoch, created_at FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)
}

pub fn can_access(member: &MembershipRow, environment: &str) -> bool {
    matches!(member.role.as_str(), "owner" | "admin")
        || member.env_grants.iter().any(|grant| grant == environment)
}

pub fn require_admin(member: &MembershipRow) -> ApiResult<()> {
    if role_rank(&member.role) >= role_rank("admin") {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

pub fn require_owner(member: &MembershipRow, team: &TeamRow, user_id: Uuid) -> ApiResult<()> {
    if member.role == "owner" && team.owner_id == user_id {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_audit(
    conn: &mut PgConnection,
    team_id: Uuid,
    actor_id: Option<Uuid>,
    action: &str,
    subject: Option<&str>,
    metadata: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (team_id, actor_id, action, subject, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(team_id)
    .bind(actor_id)
    .bind(action)
    .bind(subject)
    .bind(metadata)
    .execute(conn)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_envelope(
    conn: &mut PgConnection,
    team_id: Uuid,
    user_id: Uuid,
    epoch: u32,
    ephemeral_public_key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO team_envelopes
         (team_id, user_id, epoch, ephemeral_public_key, nonce, ciphertext, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, now())",
    )
    .bind(team_id)
    .bind(user_id)
    .bind(epoch as i32)
    .bind(ephemeral_public_key)
    .bind(nonce)
    .bind(ciphertext)
    .execute(conn)
    .await?;
    Ok(())
}

pub fn timestamp(timestamp: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(timestamp).unwrap_or_else(|_| now())
}

/// RFC 3339 representation used by every API response.
pub fn rfc3339(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
}
