//! Passwordless authentication using SSH Ed25519 challenge signatures.

use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::models::{ChallengeRequest, RegisterRequest, VerifyRequest};
use crate::util;
use crate::validate;
use crate::{AppState, AUTH_NAMESPACE};

#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub id: Uuid,
    pub username: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers).ok_or(ApiError::Unauthorized)?;
        authenticate(&state.db, &token).await
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if !scheme.eq_ignore_ascii_case("bearer") || parts.next().is_some() {
        return None;
    }
    if token.len() < 16 || token.len() > 512 {
        return None;
    }
    Some(token.to_owned())
}

pub async fn authenticate(pool: &sqlx::PgPool, token: &str) -> ApiResult<CurrentUser> {
    let hash = util::hash_token(token);
    let row = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT u.id, u.username
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(hash)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::Unauthorized)?;
    Ok(CurrentUser {
        id: row.0,
        username: row.1,
    })
}

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/challenge", post(challenge))
        .route("/verify", post(verify))
        .route("/logout", post(logout))
}

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<impl IntoResponse> {
    let username = validate::username(&request.username)?;
    let ssh_public_key = validate::ensure_ed25519_public_key(&request.ssh_public_key)?;
    let encryption_public_key = validate::encryption_public_key(&request.encryption_public_key)?;
    let id = Uuid::new_v4();
    let created_at = util::now();

    let result = sqlx::query(
        "INSERT INTO users (id, username, ssh_public_key, encryption_public_key, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&username)
    .bind(&ssh_public_key)
    .bind(&encryption_public_key)
    .bind(created_at)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(json!({
                "id": id,
                "username": username,
                "encryption_public_key": encryption_public_key,
                "created_at": util::rfc3339(created_at),
            })),
        )),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(
            ApiError::Conflict("username is already registered".to_owned()),
        ),
        Err(error) => Err(ApiError::Internal(error.to_string())),
    }
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(request): Json<ChallengeRequest>,
) -> ApiResult<Json<Value>> {
    let username = validate::username(&request.username)?;
    let user =
        sqlx::query_as::<_, (Uuid, String)>("SELECT id, username FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError::NotFound)?;

    let _ = sqlx::query(
        "DELETE FROM auth_challenges
         WHERE user_id = $1 AND (used_at IS NOT NULL OR expires_at < now())",
    )
    .bind(user.0)
    .execute(&state.db)
    .await;
    let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(&state.db)
        .await;

    let challenge = util::random_bytes::<32>()?;
    let expires_at = util::now() + time::Duration::seconds(state.config.challenge_ttl_seconds);
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO auth_challenges (id, user_id, challenge, expires_at, created_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(id)
    .bind(user.0)
    .bind(challenge.to_vec())
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "challenge_id": id,
        "challenge": validate::encode_b64(&challenge),
        "expires_at": util::rfc3339(expires_at),
        "namespace": AUTH_NAMESPACE,
    })))
}

pub async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> ApiResult<Json<Value>> {
    if request.signature.len() > 16 * 1024 {
        return Err(ApiError::BadRequest("signature is too large".to_owned()));
    }
    let mut transaction = state.db.begin().await?;
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            Vec<u8>,
            OffsetDateTime,
            Option<OffsetDateTime>,
            String,
            String,
        ),
    >(
        "SELECT c.user_id, c.challenge, c.expires_at, c.used_at, u.ssh_public_key, u.username
         FROM auth_challenges c JOIN users u ON u.id = c.user_id
         WHERE c.id = $1 FOR UPDATE",
    )
    .bind(request.challenge_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::Unauthorized)?;

    let (user_id, challenge, expires_at, used_at, ssh_public_key, username) = row;
    if used_at.is_some() || expires_at <= util::now() {
        return Err(ApiError::Unauthorized);
    }

    let public_key = ssh_key::PublicKey::from_openssh(&ssh_public_key)
        .map_err(|_| ApiError::Internal("stored SSH public key is invalid".to_owned()))?;
    let signature = ssh_key::SshSig::from_pem(request.signature.as_bytes())
        .map_err(|_| ApiError::Unauthorized)?;
    public_key
        .verify(AUTH_NAMESPACE, &challenge, &signature)
        .map_err(|_| ApiError::Unauthorized)?;

    sqlx::query("UPDATE auth_challenges SET used_at = now() WHERE id = $1")
        .bind(request.challenge_id)
        .execute(&mut *transaction)
        .await?;

    let token = util::random_bytes::<32>()?;
    let token_encoded = URL_SAFE_NO_PAD.encode(token);
    let token_hash = util::sha256(token_encoded.as_bytes()).to_vec();
    let expires_at = util::now() + time::Duration::seconds(state.config.session_ttl_seconds);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(Json(json!({
        "token": token_encoded,
        "expires_at": util::rfc3339(expires_at),
        "user": {"id": user_id, "username": username},
    })))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let Some(token) = bearer_token(&headers) else {
        return Err(ApiError::Unauthorized);
    };
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(util::hash_token(&token))
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn me(State(state): State<AppState>, user: CurrentUser) -> ApiResult<Json<Value>> {
    let teams = sqlx::query_as::<_, (Uuid, String, String, Vec<String>, i32)>(
        "SELECT t.id, t.name, tm.role, tm.env_grants, t.key_epoch
         FROM teams t JOIN team_members tm ON tm.team_id = t.id
         WHERE tm.user_id = $1 ORDER BY t.created_at",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let teams: Vec<Value> = teams
        .into_iter()
        .map(|(id, name, role, env_grants, key_epoch)| {
            json!({
                "id": id,
                "name": name,
                "role": role,
                "env_grants": env_grants,
                "key_epoch": key_epoch,
            })
        })
        .collect();
    Ok(Json(json!({
        "user": {"id": user.id, "username": user.username},
        "teams": teams,
    })))
}
