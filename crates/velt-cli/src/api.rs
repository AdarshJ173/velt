//! Blocking HTTP client for the Velt relay API.

use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use velt_core::sync::SealedTeamKey;

use crate::error::{CliError, Result};

#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    base: String,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyResponse {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Uuid,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeTeam {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    pub env_grants: Vec<String>,
    pub key_epoch: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeResponse {
    pub user: UserInfo,
    pub teams: Vec<MeTeam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSummary {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub key_epoch: i32,
    pub role: String,
    #[serde(default)]
    pub env_grants: Vec<String>,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
struct TeamsResponse {
    teams: Vec<TeamSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberDetails {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub env_grants: Vec<String>,
    pub encryption_public_key: String,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentMeta {
    pub environment: String,
    pub version: i64,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamDetails {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub key_epoch: i32,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub env_grants: Vec<String>,
    #[serde(default)]
    pub can_manage: bool,
    pub members: Vec<MemberDetails>,
    pub environments: Vec<EnvironmentMeta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserLookup {
    pub id: Uuid,
    pub username: String,
    pub encryption_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitedMember {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub env_grants: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvelopeWire {
    pub epoch: u32,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(default)]
    pub recipient: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvelopesResponse {
    pub team_id: Uuid,
    pub key_epoch: i32,
    pub envelopes: Vec<EnvelopeWire>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushResponse {
    pub environment: String,
    pub version: i64,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlobResponse {
    pub environment: String,
    pub version: i64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub ciphertext: Option<String>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub updated_by: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub not_modified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotatedEnvelopeWire {
    pub user_id: Uuid,
    pub epoch: u32,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RotatedBlobWire {
    pub environment: String,
    pub base_version: i64,
    pub nonce: String,
    pub ciphertext: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    #[serde(default)]
    pub actor: Option<String>,
    pub action: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DashboardLink {
    pub path: String,
    #[serde(default)]
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
struct AuditResponse {
    events: Vec<AuditEvent>,
}

impl ApiClient {
    pub fn new(base: &str, token: Option<String>) -> Result<Self> {
        let base = base.trim().trim_end_matches('/').to_owned();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(CliError::Config(
                "server URL must start with http:// or https://".to_owned(),
            ));
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(format!("velt/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { http, base, token })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let request = self.http.request(method, format!("{}{}", self.base, path));
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    fn send(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut request = self.request(method, path);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send()?;
        let status = response.status();
        let text = response.text()?;
        if !status.is_success() {
            let message = serde_json::from_str::<ErrorResponse>(&text)
                .map(|response| response.error.message)
                .unwrap_or_else(|_| text.chars().take(300).collect());
            return Err(CliError::Server {
                status: status.as_u16(),
                message,
            });
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(CliError::from)
    }

    pub fn register(
        &self,
        username: &str,
        ssh_public_key: &str,
        encryption_public_key: &str,
    ) -> Result<Value> {
        self.send(
            Method::POST,
            "/v1/auth/register",
            Some(json!({
                "username": username,
                "ssh_public_key": ssh_public_key,
                "encryption_public_key": encryption_public_key,
            })),
        )
    }

    pub fn challenge(&self, username: &str) -> Result<ChallengeResponse> {
        let value = self.send(
            Method::POST,
            "/v1/auth/challenge",
            Some(json!({"username": username})),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn verify(&self, challenge_id: &str, signature: &str) -> Result<VerifyResponse> {
        let value = self.send(
            Method::POST,
            "/v1/auth/verify",
            Some(json!({"challenge_id": challenge_id, "signature": signature})),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn logout(&self) -> Result<()> {
        self.send(Method::POST, "/v1/auth/logout", None)?;
        Ok(())
    }

    pub fn me(&self) -> Result<MeResponse> {
        let value = self.send(Method::GET, "/v1/me", None)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn lookup_user(&self, username: &str) -> Result<UserLookup> {
        let value = self.send(Method::GET, &format!("/v1/users/{username}"), None)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn create_team(
        &self,
        team_id: Uuid,
        name: &str,
        envelope: &SealedTeamKey,
    ) -> Result<TeamSummary> {
        let value = self.send(
            Method::POST,
            "/v1/teams",
            Some(json!({
                "team_id": team_id,
                "name": name,
                "envelope": envelope,
            })),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn list_teams(&self) -> Result<Vec<TeamSummary>> {
        let value = self.send(Method::GET, "/v1/teams", None)?;
        let response: TeamsResponse = serde_json::from_value(value)?;
        Ok(response.teams)
    }

    pub fn team(&self, team_id: Uuid) -> Result<TeamDetails> {
        let value = self.send(Method::GET, &format!("/v1/teams/{team_id}"), None)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn invite(
        &self,
        team_id: Uuid,
        username: &str,
        role: &str,
        env_grants: &[String],
        envelope: &SealedTeamKey,
    ) -> Result<InvitedMember> {
        let value = self.send(
            Method::POST,
            &format!("/v1/teams/{team_id}/members"),
            Some(json!({
                "username": username,
                "role": role,
                "env_grants": env_grants,
                "envelope": envelope,
            })),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn remove_member(&self, team_id: Uuid, user_id: Uuid) -> Result<Value> {
        self.send(
            Method::DELETE,
            &format!("/v1/teams/{team_id}/members/{user_id}"),
            None,
        )
    }

    pub fn envelopes(&self, team_id: Uuid) -> Result<EnvelopesResponse> {
        let value = self.send(Method::GET, &format!("/v1/teams/{team_id}/envelopes"), None)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn push_blob(
        &self,
        team_id: Uuid,
        environment: &str,
        base_version: Option<i64>,
        force: bool,
        nonce: &str,
        ciphertext: &str,
        checksum: &str,
    ) -> Result<PushResponse> {
        let value = self.send(
            Method::PUT,
            &format!("/v1/teams/{team_id}/environments/{environment}"),
            Some(json!({
                "base_version": base_version,
                "force": force,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "checksum": checksum,
            })),
        )?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn pull_blob(
        &self,
        team_id: Uuid,
        environment: &str,
        since: Option<i64>,
    ) -> Result<BlobResponse> {
        let mut path = format!("/v1/teams/{team_id}/environments/{environment}");
        if let Some(since) = since {
            path.push_str(&format!("?since={since}"));
        }
        let value = self.send(Method::GET, &path, None)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn environments(&self, team_id: Uuid) -> Result<Vec<EnvironmentMeta>> {
        let value = self.send(
            Method::GET,
            &format!("/v1/teams/{team_id}/environments"),
            None,
        )?;
        #[derive(Deserialize)]
        struct Response {
            environments: Vec<EnvironmentMeta>,
        }
        let response: Response = serde_json::from_value(value)?;
        Ok(response.environments)
    }

    pub fn rotate_key(
        &self,
        team_id: Uuid,
        epoch: u32,
        envelopes: &[RotatedEnvelopeWire],
        blobs: &[RotatedBlobWire],
    ) -> Result<Value> {
        self.send(
            Method::POST,
            &format!("/v1/teams/{team_id}/key-epoch"),
            Some(json!({
                "epoch": epoch,
                "envelopes": envelopes,
                "blobs": blobs,
            })),
        )
    }

    pub fn audit(&self, team_id: Uuid, limit: u32) -> Result<Vec<AuditEvent>> {
        let value = self.send(
            Method::GET,
            &format!("/v1/teams/{team_id}/audit?limit={limit}"),
            None,
        )?;
        let response: AuditResponse = serde_json::from_value(value)?;
        Ok(response.events)
    }

    pub fn delete_team(&self, team_id: Uuid) -> Result<()> {
        self.send(Method::DELETE, &format!("/v1/teams/{team_id}"), None)?;
        Ok(())
    }

    pub fn dashboard_session(&self) -> Result<DashboardLink> {
        let value = self.send(Method::POST, "/v1/dashboard/session", None)?;
        Ok(serde_json::from_value(value)?)
    }

    pub fn websocket_url(&self, team_id: Uuid, token: &str) -> String {
        let base = self
            .base
            .strip_prefix("https://")
            .map(|rest| format!("wss://{rest}"))
            .or_else(|| {
                self.base
                    .strip_prefix("http://")
                    .map(|rest| format!("ws://{rest}"))
            })
            .unwrap_or_else(|| self.base.clone());
        format!("{base}/v1/teams/{team_id}/events?token={token}")
    }
}
