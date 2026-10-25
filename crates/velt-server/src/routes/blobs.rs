//! Opaque encrypted vault blob storage and retrieval.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde_json::{json, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::events::{self, TeamEvent};
use crate::models::{BlobMetaRow, BlobRow, PullQuery, PushBlobRequest};
use crate::validate::{self, role_rank};
use crate::{util, AppState};

pub async fn push_blob(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((team_id, environment)): Path<(Uuid, String)>,
    Json(request): Json<PushBlobRequest>,
) -> ApiResult<Json<Value>> {
    let environment = validate::environment(&environment)?;
    let member = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if member.role == "ci_bot" || role_rank(&member.role) < role_rank("developer") {
        return Err(ApiError::Forbidden);
    }
    if !util::can_access(&member, &environment) {
        return Err(ApiError::Forbidden);
    }
    let material = validate::blob(&request, state.config.max_blob_bytes)?;

    let mut transaction = state.db.begin().await?;
    let current = sqlx::query_as::<_, (i64,)>(
        "SELECT version FROM vault_blobs
         WHERE team_id = $1 AND environment = $2 FOR UPDATE",
    )
    .bind(team_id)
    .bind(&environment)
    .fetch_optional(&mut *transaction)
    .await?
    .map(|row| row.0);

    let new_version = match current {
        Some(version) => {
            if !request.force && request.base_version != Some(version) {
                return Err(ApiError::Conflict(format!(
                    "version conflict: current version is {version}; pull first or use --force"
                )));
            }
            version + 1
        }
        None => {
            if !request.force && request.base_version.unwrap_or(0) != 0 {
                return Err(ApiError::Conflict(
                    "version conflict: no blob exists yet".to_owned(),
                ));
            }
            1
        }
    };

    let updated_at = sqlx::query_as::<_, (OffsetDateTime,)>(
        "INSERT INTO vault_blobs
         (team_id, environment, version, nonce, ciphertext, checksum, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())
         ON CONFLICT (team_id, environment) DO UPDATE SET
            version = EXCLUDED.version,
            nonce = EXCLUDED.nonce,
            ciphertext = EXCLUDED.ciphertext,
            checksum = EXCLUDED.checksum,
            updated_by = EXCLUDED.updated_by,
            updated_at = now()
         RETURNING updated_at",
    )
    .bind(team_id)
    .bind(&environment)
    .bind(new_version)
    .bind(&material.nonce)
    .bind(&material.ciphertext)
    .bind(&material.checksum)
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await?
    .0;

    util::insert_audit(
        &mut *transaction,
        team_id,
        Some(user.id),
        "vault_pushed",
        Some(&environment),
        json!({"version": new_version}),
    )
    .await?;
    transaction.commit().await?;

    events::notify(
        &state.db,
        &TeamEvent {
            team_id,
            kind: "vault_updated".to_owned(),
            environment: Some(environment.clone()),
            version: Some(new_version),
            created_at: util::now().unix_timestamp(),
        },
    )
    .await;

    Ok(Json(json!({
        "environment": environment,
        "version": new_version,
        "updated_at": util::rfc3339(updated_at),
    })))
}

pub async fn pull_blob(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((team_id, environment)): Path<(Uuid, String)>,
    Query(query): Query<PullQuery>,
) -> ApiResult<Json<Value>> {
    let environment = validate::environment(&environment)?;
    let member = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !util::can_access(&member, &environment) {
        return Err(ApiError::Forbidden);
    }
    let row = sqlx::query_as::<_, BlobRow>(
        "SELECT b.environment, b.version, b.nonce, b.ciphertext, b.checksum,
                b.updated_by, b.updated_at, u.username AS updated_by_username
         FROM vault_blobs b JOIN users u ON u.id = b.updated_by
         WHERE b.team_id = $1 AND b.environment = $2",
    )
    .bind(team_id)
    .bind(&environment)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    if let Some(since) = query.since {
        if row.version <= since {
            return Ok(Json(json!({
                "environment": environment,
                "version": row.version,
                "not_modified": true,
            })));
        }
    }

    let mut connection = state.db.acquire().await?;
    util::insert_audit(
        &mut *connection,
        team_id,
        Some(user.id),
        "vault_pulled",
        Some(&environment),
        json!({"version": row.version}),
    )
    .await?;

    Ok(Json(json!({
        "environment": row.environment,
        "version": row.version,
        "nonce": validate::encode_b64(&row.nonce),
        "ciphertext": validate::encode_b64(&row.ciphertext),
        "checksum": validate::encode_b64(&row.checksum),
        "updated_by": row.updated_by_username,
        "updated_at": util::rfc3339(row.updated_at),
        "not_modified": false,
    })))
}

pub async fn list_environments(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let member = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let rows = sqlx::query_as::<_, BlobMetaRow>(
        "SELECT environment, version, updated_at FROM vault_blobs
         WHERE team_id = $1 ORDER BY environment",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await?;
    let environments: Vec<Value> = rows
        .into_iter()
        .filter(|row| util::can_access(&member, &row.environment))
        .map(|row| {
            json!({
                "environment": row.environment,
                "version": row.version,
                "updated_at": util::rfc3339(row.updated_at),
            })
        })
        .collect();
    Ok(Json(json!({ "environments": environments })))
}
