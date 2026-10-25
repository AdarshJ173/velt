//! Team membership, key epochs, envelopes and audit log endpoints.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiResult};
use crate::events::{self, TeamEvent};
use crate::models::{
    AuditQuery, AuditRow, BlobMetaRow, CreateTeamRequest, EnvelopeRow, InviteRequest,
    KeyEpochRequest, MemberRow, PushBlobRequest, TeamRow, TeamSummaryRow, UpdateMemberRequest,
};
use crate::validate::{self, role_rank};
use crate::{util, AppState};

pub async fn list_teams(
    State(state): State<AppState>,
    user: CurrentUser,
) -> ApiResult<Json<Value>> {
    let rows = sqlx::query_as::<_, TeamSummaryRow>(
        "SELECT t.id, t.name, t.owner_id, t.key_epoch, t.created_at, tm.role, tm.env_grants
         FROM teams t JOIN team_members tm ON tm.team_id = t.id
         WHERE tm.user_id = $1 ORDER BY t.created_at",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let teams: Vec<Value> = rows
        .into_iter()
        .map(|team| {
            json!({
                "id": team.id,
                "name": team.name,
                "owner_id": team.owner_id,
                "key_epoch": team.key_epoch,
                "created_at": util::rfc3339(team.created_at),
                "role": team.role,
                "env_grants": team.env_grants,
            })
        })
        .collect();
    Ok(Json(json!({ "teams": teams })))
}

pub async fn create_team(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<CreateTeamRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if request.team_id.is_nil() {
        return Err(ApiError::BadRequest(
            "team_id must be a non-nil UUID".to_owned(),
        ));
    }
    let name = validate::team_name(&request.name)?;
    let envelope = validate::envelope(&request.envelope, 1)?;
    let mut transaction = state.db.begin().await?;

    let insert = sqlx::query(
        "INSERT INTO teams (id, name, owner_id, key_epoch, created_at)
         VALUES ($1, $2, $3, 1, now())",
    )
    .bind(request.team_id)
    .bind(&name)
    .bind(user.id)
    .execute(&mut *transaction)
    .await;
    match insert {
        Ok(_) => {}
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            return Err(ApiError::Conflict("team id already exists".to_owned()));
        }
        Err(error) => return Err(ApiError::Internal(error.to_string())),
    }

    sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, env_grants, created_at)
         VALUES ($1, $2, 'owner', '{}', now())",
    )
    .bind(request.team_id)
    .bind(user.id)
    .execute(&mut *transaction)
    .await?;

    util::insert_envelope(
        &mut transaction,
        request.team_id,
        user.id,
        envelope.epoch,
        &envelope.ephemeral_public_key,
        &envelope.nonce,
        &envelope.ciphertext,
    )
    .await?;

    util::insert_audit(
        &mut transaction,
        request.team_id,
        Some(user.id),
        "team_created",
        None,
        json!({"name": name}),
    )
    .await?;

    let created_at =
        sqlx::query_as::<_, (time::OffsetDateTime,)>("SELECT created_at FROM teams WHERE id = $1")
            .bind(request.team_id)
            .fetch_one(&mut *transaction)
            .await?
            .0;

    transaction.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": request.team_id,
            "name": name,
            "owner_id": user.id,
            "role": "owner",
            "env_grants": [],
            "key_epoch": 1,
            "created_at": util::rfc3339(created_at),
        })),
    ))
}

pub async fn get_team(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let member = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let team = util::team(&state.db, team_id).await?;
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT tm.user_id, u.username, tm.role, tm.env_grants,
                u.encryption_public_key, tm.created_at
         FROM team_members tm JOIN users u ON u.id = tm.user_id
         WHERE tm.team_id = $1 ORDER BY tm.created_at",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await?;
    let blobs = sqlx::query_as::<_, BlobMetaRow>(
        "SELECT environment, version, updated_at FROM vault_blobs
         WHERE team_id = $1 ORDER BY environment",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await?;
    let can_manage = role_rank(&member.role) >= role_rank("admin");
    let environments: Vec<Value> = blobs
        .into_iter()
        .filter(|blob| can_manage || util::can_access(&member, &blob.environment))
        .map(|blob| {
            json!({
                "environment": blob.environment,
                "version": blob.version,
                "updated_at": util::rfc3339(blob.updated_at),
            })
        })
        .collect();
    let members: Vec<Value> = members
        .into_iter()
        .map(|member| {
            json!({
                "id": member.user_id,
                "username": member.username,
                "role": member.role,
                "env_grants": member.env_grants,
                "encryption_public_key": member.encryption_public_key,
                "created_at": util::rfc3339(member.created_at),
            })
        })
        .collect();
    Ok(Json(json!({
        "id": team.id,
        "name": team.name,
        "owner_id": team.owner_id,
        "key_epoch": team.key_epoch,
        "created_at": util::rfc3339(team.created_at),
        "role": member.role,
        "env_grants": member.env_grants,
        "can_manage": can_manage,
        "members": members,
        "environments": environments,
    })))
}

pub async fn invite_member(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
    Json(request): Json<InviteRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let caller = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    util::require_admin(&caller)?;
    let team = util::team(&state.db, team_id).await?;
    let role = validate::role(&request.role)?;
    if role == "owner" {
        return Err(ApiError::BadRequest(
            "use ownership transfer, not member invites, to add an owner".to_owned(),
        ));
    }
    let envelope = validate::envelope(&request.envelope, team.key_epoch as u32)?;
    let grants = validate::grants(request.env_grants.unwrap_or_default())?;
    let username = validate::username(&request.username)?;
    let target =
        sqlx::query_as::<_, (Uuid, String)>("SELECT id, username FROM users WHERE username = $1")
            .bind(&username)
            .fetch_optional(&state.db)
            .await?
            .ok_or(ApiError::NotFound)?;

    let mut transaction = state.db.begin().await?;
    let insert = sqlx::query(
        "INSERT INTO team_members (team_id, user_id, role, env_grants, created_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(team_id)
    .bind(target.0)
    .bind(role)
    .bind(&grants)
    .execute(&mut *transaction)
    .await;
    match insert {
        Ok(_) => {}
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            return Err(ApiError::Conflict(
                "user is already a team member".to_owned(),
            ));
        }
        Err(error) => return Err(ApiError::Internal(error.to_string())),
    }

    util::insert_envelope(
        &mut transaction,
        team_id,
        target.0,
        envelope.epoch,
        &envelope.ephemeral_public_key,
        &envelope.nonce,
        &envelope.ciphertext,
    )
    .await?;
    util::insert_audit(
        &mut transaction,
        team_id,
        Some(user.id),
        "member_added",
        Some(&target.1),
        json!({"role": role, "env_grants": grants}),
    )
    .await?;
    transaction.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": target.0,
            "username": target.1,
            "role": role,
            "env_grants": grants,
        })),
    ))
}

pub async fn update_member(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((team_id, target_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMemberRequest>,
) -> ApiResult<Json<Value>> {
    let caller = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    util::require_admin(&caller)?;
    let target = util::membership(&state.db, team_id, target_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target.role == "owner" {
        return Err(ApiError::Forbidden);
    }
    let role = match request.role {
        Some(role) => {
            let role = validate::role(&role)?;
            if role == "owner" {
                return Err(ApiError::BadRequest(
                    "ownership transfer is not supported by this endpoint".to_owned(),
                ));
            }
            role
        }
        None => target.role.as_str(),
    };
    let grants = match request.env_grants {
        Some(grants) => validate::grants(grants)?,
        None => target.env_grants.clone(),
    };
    sqlx::query(
        "UPDATE team_members SET role = $3, env_grants = $4
         WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(target_id)
    .bind(role)
    .bind(&grants)
    .execute(&state.db)
    .await?;

    let mut connection = state.db.acquire().await?;
    util::insert_audit(
        &mut connection,
        team_id,
        Some(user.id),
        "member_updated",
        None,
        json!({"user_id": target_id, "role": role, "env_grants": grants}),
    )
    .await?;
    Ok(Json(json!({
        "user_id": target_id,
        "role": role,
        "env_grants": grants,
    })))
}

pub async fn remove_member(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((team_id, target_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<Value>> {
    let caller = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let target = util::membership(&state.db, team_id, target_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if target.role == "owner" {
        return Err(ApiError::Forbidden);
    }
    if caller.user_id != target_id && role_rank(&caller.role) < role_rank("admin") {
        return Err(ApiError::Forbidden);
    }
    let mut transaction = state.db.begin().await?;
    sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(target_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM team_envelopes WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(target_id)
        .execute(&mut *transaction)
        .await?;
    util::insert_audit(
        &mut transaction,
        team_id,
        Some(user.id),
        "member_removed",
        None,
        json!({"user_id": target_id, "role": target.role}),
    )
    .await?;
    transaction.commit().await?;
    Ok(Json(json!({
        "removed": target_id,
        "key_rotation_required": true,
    })))
}

pub async fn get_envelopes(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let team = util::team(&state.db, team_id).await?;
    let rows = sqlx::query_as::<_, EnvelopeRow>(
        "SELECT user_id, epoch, ephemeral_public_key, nonce, ciphertext
         FROM team_envelopes WHERE team_id = $1 AND user_id = $2 ORDER BY epoch DESC",
    )
    .bind(team_id)
    .bind(user.id)
    .fetch_all(&state.db)
    .await?;
    let envelopes: Vec<Value> = rows
        .into_iter()
        .map(|envelope| {
            json!({
                "recipient": user.username,
                "epoch": envelope.epoch,
                "ephemeral_public_key": validate::encode_b64(&envelope.ephemeral_public_key),
                "nonce": validate::encode_b64(&envelope.nonce),
                "ciphertext": validate::encode_b64(&envelope.ciphertext),
            })
        })
        .collect();
    Ok(Json(json!({
        "team_id": team.id,
        "key_epoch": team.key_epoch,
        "envelopes": envelopes,
    })))
}

pub async fn rotate_key(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
    Json(request): Json<KeyEpochRequest>,
) -> ApiResult<Json<Value>> {
    let mut transaction = state.db.begin().await?;
    let team = sqlx::query_as::<_, TeamRow>(
        "SELECT id, name, owner_id, key_epoch, created_at FROM teams WHERE id = $1 FOR UPDATE",
    )
    .bind(team_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::NotFound)?;
    let caller = util::membership_conn(&mut transaction, team_id, user.id)
        .await?
        .ok_or(ApiError::Forbidden)?;
    util::require_owner(&caller, &team, user.id)?;
    if request.epoch != (team.key_epoch as u32) + 1 {
        return Err(ApiError::BadRequest(format!(
            "new epoch must be {}",
            team.key_epoch + 1
        )));
    }
    if request.envelopes.len() > state.config.max_envelopes {
        return Err(ApiError::PayloadTooLarge);
    }

    let member_ids: Vec<Uuid> =
        sqlx::query_as::<_, (Uuid,)>("SELECT user_id FROM team_members WHERE team_id = $1")
            .bind(team_id)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| row.0)
            .collect();
    let member_set: BTreeSet<Uuid> = member_ids.iter().copied().collect();

    if request.envelopes.len() != member_ids.len() {
        return Err(ApiError::BadRequest(
            "key rotation must include exactly one envelope per member".to_owned(),
        ));
    }
    let mut envelopes = Vec::with_capacity(request.envelopes.len());
    let mut seen = BTreeSet::new();
    for envelope in &request.envelopes {
        if !member_set.contains(&envelope.user_id) || !seen.insert(envelope.user_id) {
            return Err(ApiError::BadRequest(
                "key rotation contains an unknown or duplicate member".to_owned(),
            ));
        }
        let input = crate::models::EnvelopeInput {
            epoch: envelope.epoch,
            ephemeral_public_key: envelope.ephemeral_public_key.clone(),
            nonce: envelope.nonce.clone(),
            ciphertext: envelope.ciphertext.clone(),
        };
        let material = validate::envelope(&input, request.epoch)?;
        envelopes.push((envelope.user_id, material));
    }
    if seen.len() != member_set.len() {
        return Err(ApiError::BadRequest(
            "key rotation is missing an envelope for a member".to_owned(),
        ));
    }

    let current_blobs = sqlx::query_as::<_, (String, i64)>(
        "SELECT environment, version FROM vault_blobs WHERE team_id = $1",
    )
    .bind(team_id)
    .fetch_all(&mut *transaction)
    .await?;
    let current: BTreeMap<String, i64> = current_blobs.into_iter().collect();
    if request.blobs.len() != current.len() {
        return Err(ApiError::BadRequest(
            "key rotation must re-encrypt every environment".to_owned(),
        ));
    }
    let mut rotated = BTreeMap::new();
    for blob in &request.blobs {
        let environment = validate::environment(&blob.environment)?;
        let expected = current.get(&environment).copied().ok_or_else(|| {
            ApiError::BadRequest(format!("unknown environment in rotation: {environment}"))
        })?;
        if blob.base_version != expected {
            return Err(ApiError::Conflict(format!(
                "environment {environment} changed during rotation (expected version {expected})"
            )));
        }
        if rotated.contains_key(&environment) {
            return Err(ApiError::BadRequest(
                "key rotation contains a duplicate environment".to_owned(),
            ));
        }
        let material = validate::blob(
            &PushBlobRequest {
                base_version: Some(expected),
                force: false,
                nonce: blob.nonce.clone(),
                ciphertext: blob.ciphertext.clone(),
                checksum: blob.checksum.clone(),
            },
            state.config.max_blob_bytes,
        )?;
        rotated.insert(environment, material);
    }

    sqlx::query("DELETE FROM team_envelopes WHERE team_id = $1")
        .bind(team_id)
        .execute(&mut *transaction)
        .await?;
    for (recipient, material) in &envelopes {
        util::insert_envelope(
            &mut transaction,
            team_id,
            *recipient,
            material.epoch,
            &material.ephemeral_public_key,
            &material.nonce,
            &material.ciphertext,
        )
        .await?;
    }

    let mut versions = Vec::with_capacity(rotated.len());
    for (environment, material) in &rotated {
        let current_version = current[environment];
        let result = sqlx::query(
            "UPDATE vault_blobs
             SET version = $3, nonce = $4, ciphertext = $5, checksum = $6,
                 updated_by = $7, updated_at = now()
             WHERE team_id = $1 AND environment = $2 AND version = $8",
        )
        .bind(team_id)
        .bind(environment)
        .bind(current_version + 1)
        .bind(&material.nonce)
        .bind(&material.ciphertext)
        .bind(&material.checksum)
        .bind(user.id)
        .bind(current_version)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::Conflict(
                "blob changed while rotating keys; retry".to_owned(),
            ));
        }
        versions.push(json!({
            "environment": environment,
            "version": current_version + 1,
        }));
    }

    sqlx::query("UPDATE teams SET key_epoch = $2 WHERE id = $1")
        .bind(team_id)
        .bind(request.epoch as i32)
        .execute(&mut *transaction)
        .await?;

    util::insert_audit(
        &mut transaction,
        team_id,
        Some(user.id),
        "key_rotated",
        None,
        json!({"key_epoch": request.epoch, "environments": versions}),
    )
    .await?;
    transaction.commit().await?;

    for version in &versions {
        if let (Some(environment), Some(version)) = (
            version.get("environment").and_then(Value::as_str),
            version.get("version").and_then(Value::as_i64),
        ) {
            events::notify(
                &state.db,
                &TeamEvent {
                    team_id,
                    kind: "vault_updated".to_owned(),
                    environment: Some(environment.to_owned()),
                    version: Some(version),
                    created_at: util::now().unix_timestamp(),
                },
            )
            .await;
        }
    }

    Ok(Json(json!({
        "key_epoch": request.epoch,
        "environments": versions,
    })))
}

pub async fn audit_log(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let member = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    util::require_admin(&member)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT a.id, u.username AS actor_username, a.action, a.subject, a.metadata, a.created_at
         FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
         WHERE a.team_id = $1 ORDER BY a.created_at DESC LIMIT $2",
    )
    .bind(team_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "events": rows.into_iter().map(|event| json!({
            "id": event.id,
            "actor": event.actor_username,
            "action": event.action,
            "subject": event.subject,
            "metadata": event.metadata,
            "created_at": util::rfc3339(event.created_at),
        })).collect::<Vec<_>>()
    })))
}

pub async fn lookup_user(
    user: CurrentUser,
    Path(username): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<Value>> {
    let _ = user;
    let username = validate::username(&username)?;
    let row = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, username, encryption_public_key FROM users WHERE username = $1",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "id": row.0,
        "username": row.1,
        "encryption_public_key": row.2,
    })))
}

pub async fn delete_team(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(team_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let member = util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let team = util::team(&state.db, team_id).await?;
    util::require_owner(&member, &team, user.id)?;
    sqlx::query("DELETE FROM teams WHERE id = $1")
        .bind(team_id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
