//! Database rows and request/response DTOs.

use serde::Deserialize;
use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub ssh_public_key: String,
    pub encryption_public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub challenge_id: Uuid,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvelopeInput {
    pub epoch: u32,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub team_id: Uuid,
    pub name: String,
    pub envelope: EnvelopeInput,
}

#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    pub username: String,
    pub role: String,
    #[serde(default)]
    pub env_grants: Option<Vec<String>>,
    pub envelope: EnvelopeInput,
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRequest {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub env_grants: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RotatedEnvelope {
    pub user_id: Uuid,
    pub epoch: u32,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct RotatedBlob {
    pub environment: String,
    pub base_version: i64,
    pub nonce: String,
    pub ciphertext: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyEpochRequest {
    pub epoch: u32,
    pub envelopes: Vec<RotatedEnvelope>,
    pub blobs: Vec<RotatedBlob>,
}

#[derive(Debug, Deserialize)]
pub struct PushBlobRequest {
    #[serde(default)]
    pub base_version: Option<i64>,
    #[serde(default)]
    pub force: bool,
    pub nonce: String,
    pub ciphertext: String,
    pub checksum: String,
}

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    pub since: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug)]
pub struct EnvelopeMaterial {
    pub epoch: u32,
    pub ephemeral_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct BlobMaterial {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub checksum: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
pub struct MembershipRow {
    pub user_id: Uuid,
    pub role: String,
    pub env_grants: Vec<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct TeamRow {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub key_epoch: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
pub struct TeamSummaryRow {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub key_epoch: i32,
    pub created_at: OffsetDateTime,
    pub role: String,
    pub env_grants: Vec<String>,
}

#[derive(Debug, FromRow)]
pub struct MemberRow {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
    pub env_grants: Vec<String>,
    pub encryption_public_key: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
pub struct EnvelopeRow {
    pub user_id: Uuid,
    pub epoch: i32,
    pub ephemeral_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, FromRow)]
pub struct BlobRow {
    pub environment: String,
    pub version: i64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub checksum: Vec<u8>,
    pub updated_by: Uuid,
    pub updated_at: OffsetDateTime,
    pub updated_by_username: String,
}

#[derive(Debug, FromRow)]
pub struct BlobMetaRow {
    pub environment: String,
    pub version: i64,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub actor_username: Option<String>,
    pub action: String,
    pub subject: Option<String>,
    pub metadata: Value,
    pub created_at: OffsetDateTime,
}
