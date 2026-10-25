//! Server-rendered admin dashboard for team leads and security managers.
//!
//! Authentication is a one-time link minted by an authenticated CLI:
//! `velt dashboard` -> `/dashboard/login?token=...` -> HttpOnly session cookie.
//! Forms are protected by a per-session CSRF token and SameSite=Strict cookies.
//! The dashboard can view metadata, edit roles/grants and revoke members; it
//! cannot decrypt secrets or rotate E2EE keys (those stay local/CLI-only).

use axum::extract::{Form, Path, Query, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE,
    REFERRER_POLICY, SET_COOKIE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use time::Duration;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::ApiResult;
use crate::models::{AuditRow, BlobMetaRow, MemberRow};
use crate::validate::{self, role_rank};
use crate::{util, AppState};

const COOKIE_NAME: &str = "velt_dashboard";
const DASHBOARD_TTL_SECONDS: i64 = 8 * 3600;
const LOGIN_TOKEN_TTL_SECONDS: i64 = 300;

#[derive(Debug, Deserialize)]
struct LoginQuery {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    token: String,
}

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf: String,
}

#[derive(Debug, Deserialize)]
struct UpdateForm {
    csrf: String,
    role: String,
    #[serde(default)]
    env_grants: String,
}

#[derive(Debug)]
struct DashboardUser {
    id: Uuid,
    username: String,
    csrf: String,
}

pub fn api_router() -> Router<AppState> {
    Router::new().route("/dashboard/session", post(create_login_link))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(home))
        .route("/dashboard/login", get(login).post(login_submit))
        .route("/dashboard/logout", post(logout))
        .route("/dashboard/teams/{team_id}", get(team_page))
        .route(
            "/dashboard/teams/{team_id}/members/{user_id}/update",
            post(update_member),
        )
        .route(
            "/dashboard/teams/{team_id}/members/{user_id}/remove",
            post(remove_member),
        )
        .route("/dashboard/teams/{team_id}/audit.csv", get(audit_csv))
}

async fn create_login_link(
    State(state): State<AppState>,
    user: CurrentUser,
) -> ApiResult<Json<serde_json::Value>> {
    let token = util::random_bytes::<32>()?;
    let encoded = URL_SAFE_NO_PAD.encode(token);
    let hash = util::sha256(encoded.as_bytes()).to_vec();
    let expires_at = util::now() + Duration::seconds(LOGIN_TOKEN_TTL_SECONDS);
    let _ =
        sqlx::query("DELETE FROM dashboard_tokens WHERE expires_at < now() OR used_at IS NOT NULL")
            .execute(&state.db)
            .await;
    sqlx::query(
        "INSERT INTO dashboard_tokens (id, user_id, token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(hash)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({
        "path": format!("/dashboard/login?token={encoded}"),
        "expires_at": util::rfc3339(expires_at),
        "ttl_seconds": LOGIN_TOKEN_TTL_SECONDS,
    })))
}

async fn login(State(state): State<AppState>, Query(query): Query<LoginQuery>) -> Response {
    let Some(token) = query.token.filter(|token| token.len() <= 256) else {
        return render_page(
            StatusCode::UNAUTHORIZED,
            "Dashboard login",
            login_body(None),
        );
    };
    let hash = util::sha256(token.as_bytes()).to_vec();
    let valid = sqlx::query_as::<_, (i32,)>(
        "SELECT 1 FROM dashboard_tokens
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);
    if valid.is_none() {
        return render_page(
            StatusCode::UNAUTHORIZED,
            "Dashboard login",
            login_body(Some(
                "This link is invalid, expired, or has already been used.",
            )),
        );
    }
    render_page(
        StatusCode::OK,
        "Dashboard login",
        login_confirm_body(&token),
    )
}

async fn login_submit(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    let token = form.token;
    if token.is_empty() || token.len() > 256 {
        return render_page(
            StatusCode::UNAUTHORIZED,
            "Dashboard login",
            login_body(Some("This link is invalid.")),
        );
    }
    let hash = util::sha256(token.as_bytes()).to_vec();
    let mut transaction = match state.db.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return error_page("Database unavailable"),
    };
    let row = sqlx::query_as::<_, (Uuid, Option<time::OffsetDateTime>, time::OffsetDateTime)>(
        "SELECT user_id, used_at, expires_at FROM dashboard_tokens
         WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(&hash)
    .fetch_optional(&mut *transaction)
    .await;
    let row = match row {
        Ok(Some(row)) => row,
        _ => {
            return render_page(
                StatusCode::UNAUTHORIZED,
                "Dashboard login",
                login_body(Some("This link is invalid or has already been used.")),
            )
        }
    };
    if row.1.is_some() || row.2 <= util::now() {
        return render_page(
            StatusCode::UNAUTHORIZED,
            "Dashboard login",
            login_body(Some("This link has expired.")),
        );
    }
    if sqlx::query("UPDATE dashboard_tokens SET used_at = now() WHERE token_hash = $1")
        .bind(&hash)
        .execute(&mut *transaction)
        .await
        .is_err()
    {
        return error_page("Could not complete login");
    }

    let session_token = match util::random_bytes::<32>() {
        Ok(bytes) => URL_SAFE_NO_PAD.encode(bytes),
        Err(_) => return error_page("Could not create a session"),
    };
    let csrf = match util::random_bytes::<24>() {
        Ok(bytes) => hex::encode(bytes),
        Err(_) => return error_page("Could not create a session"),
    };
    let expires_at = util::now() + Duration::seconds(DASHBOARD_TTL_SECONDS);
    let insert = sqlx::query(
        "INSERT INTO dashboard_sessions
         (id, user_id, token_hash, csrf_token, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(Uuid::new_v4())
    .bind(row.0)
    .bind(util::sha256(session_token.as_bytes()).to_vec())
    .bind(&csrf)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await;
    if insert.is_err() || transaction.commit().await.is_err() {
        return error_page("Could not complete login");
    }

    let secure = state
        .config
        .public_url
        .as_deref()
        .is_some_and(|url| url.starts_with("https://"));
    let cookie = cookie_header(&session_token, DASHBOARD_TTL_SECONDS, secure);
    let mut response = Redirect::to("/dashboard").into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    security_headers(response)
}

async fn home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = dashboard_user(&state, &headers).await else {
        return Redirect::to("/dashboard/login").into_response();
    };
    let teams = sqlx::query_as::<_, (Uuid, String, i32, String, Vec<String>, i64)>(
        "SELECT t.id, t.name, t.key_epoch, tm.role, tm.env_grants,
                (SELECT count(*) FROM vault_blobs b WHERE b.team_id = t.id)
         FROM teams t JOIN team_members tm ON tm.team_id = t.id
         WHERE tm.user_id = $1 ORDER BY t.name",
    )
    .bind(user.id)
    .fetch_all(&state.db)
    .await;
    let teams = match teams {
        Ok(teams) => teams,
        Err(error) => {
            tracing::error!(error = %error, "dashboard team query failed");
            return error_page("Could not load teams");
        }
    };
    let mut body = String::new();
    body.push_str(&format!(
        "<header><div class=\"brand\">VELT</div><div class=\"who\">{}<form method=\"post\" action=\"/dashboard/logout\"><button class=\"link\" type=\"submit\">Sign out</button></form></div></header>",
        esc(&user.username)
    ));
    body.push_str("<main><h1>Teams</h1>");
    if teams.is_empty() {
        body.push_str("<p class=\"muted\">You are not a member of any team yet. Create one with <code>velt team create &lt;name&gt;</code>.</p>");
    } else {
        body.push_str("<div class=\"grid\">");
        for (id, name, epoch, role, grants, environments) in teams {
            body.push_str(&format!(
                "<a class=\"card\" href=\"/dashboard/teams/{id}\"><div class=\"card-title\">{}</div><div class=\"muted\">role {}</div><div class=\"metric\">{} environment(s) · key epoch {}</div><div class=\"muted\">grants: {}</div></a>",
                esc(&name),
                esc(&role),
                environments,
                epoch,
                esc(&if grants.is_empty() { "all".to_owned() } else { grants.join(", ") }),
            ));
        }
        body.push_str("</div>");
    }
    body.push_str("<section class=\"note\"><strong>Zero-knowledge by design.</strong> This dashboard can revoke access, but it cannot read secrets. Key rotation and vault decryption stay on trusted developer machines.</section></main>");
    html_page(StatusCode::OK, "Teams", &body)
}

async fn team_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(team_id): Path<Uuid>,
) -> Response {
    let Some(user) = dashboard_user(&state, &headers).await else {
        return Redirect::to("/dashboard/login").into_response();
    };
    let member = match util::membership(&state.db, team_id, user.id).await {
        Ok(Some(member)) => member,
        Ok(None) => return render_page(StatusCode::NOT_FOUND, "Not found", "<main><p>Team not found or you are not a member.</p><p><a href=\"/dashboard\">Back</a></p></main>".to_owned()),
        Err(_) => return error_page("Could not load team"),
    };
    let team = match util::team(&state.db, team_id).await {
        Ok(team) => team,
        Err(_) => {
            return render_page(
                StatusCode::NOT_FOUND,
                "Not found",
                "<main><p>Team not found.</p></main>".to_owned(),
            )
        }
    };
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT tm.user_id, u.username, tm.role, tm.env_grants,
                u.encryption_public_key, tm.created_at
         FROM team_members tm JOIN users u ON u.id = tm.user_id
         WHERE tm.team_id = $1 ORDER BY tm.created_at",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let environments = sqlx::query_as::<_, BlobMetaRow>(
        "SELECT environment, version, updated_at FROM vault_blobs
         WHERE team_id = $1 ORDER BY environment",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let can_manage = role_rank(&member.role) >= role_rank("admin");
    let environments: Vec<BlobMetaRow> = environments
        .into_iter()
        .filter(|environment| can_manage || util::can_access(&member, &environment.environment))
        .collect();
    let audits = if can_manage {
        sqlx::query_as::<_, AuditRow>(
            "SELECT a.id, u.username AS actor_username, a.action, a.subject, a.metadata, a.created_at
             FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
             WHERE a.team_id = $1 ORDER BY a.created_at DESC LIMIT 50",
        )
        .bind(team_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut body = String::new();
    body.push_str(&format!(
        "<header><div class=\"brand\">VELT</div><div class=\"who\">{}<form method=\"post\" action=\"/dashboard/logout\"><button class=\"link\" type=\"submit\">Sign out</button></form></div></header><main><p><a href=\"/dashboard\">← Teams</a></p><h1>{}</h1><p class=\"muted\">Team {} · key epoch {} · your role {}</p>",
        esc(&user.username),
        esc(&team.name),
        team.id,
        team.key_epoch,
        esc(&member.role)
    ));

    body.push_str("<h2>Members</h2><table><thead><tr><th>User</th><th>Role</th><th>Grants</th><th>Actions</th></tr></thead><tbody>");
    for entry in &members {
        body.push_str("<tr><td>");
        body.push_str(&esc(&entry.username));
        body.push_str("</td><td>");
        body.push_str(&esc(&entry.role));
        body.push_str("</td><td>");
        let grants_label = if entry.env_grants.is_empty() {
            "all".to_owned()
        } else {
            entry.env_grants.join(", ")
        };
        body.push_str(&esc(&grants_label));
        body.push_str("</td><td>");
        if can_manage && entry.role != "owner" {
            body.push_str(&format!(
                "<form class=\"inline\" method=\"post\" action=\"/dashboard/teams/{team_id}/members/{}/update\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><select name=\"role\"><option value=\"admin\"{}>admin</option><option value=\"developer\"{}>developer</option><option value=\"ci_bot\"{}>ci_bot</option></select><input name=\"env_grants\" placeholder=\"development,staging\" value=\"{}\"><button type=\"submit\">Update</button></form>",
                entry.user_id,
                esc(&user.csrf),
                selected(&entry.role, "admin"),
                selected(&entry.role, "developer"),
                selected(&entry.role, "ci_bot"),
                esc(&entry.env_grants.join(",")),
            ));
            body.push_str(&format!(
                "<form class=\"inline danger\" method=\"post\" action=\"/dashboard/teams/{team_id}/members/{}/remove\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\">Revoke</button></form>",
                entry.user_id,
                esc(&user.csrf)
            ));
        } else {
            body.push('—');
        }
        body.push_str("</td></tr>");
    }
    body.push_str("</tbody></table>");

    body.push_str("<h2>Environments</h2><table><thead><tr><th>Environment</th><th>Version</th><th>Updated</th></tr></thead><tbody>");
    if environments.is_empty() {
        body.push_str(
            "<tr><td colspan=\"3\" class=\"muted\">No encrypted environments yet.</td></tr>",
        );
    }
    for environment in &environments {
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&environment.environment),
            environment.version,
            esc(&util::rfc3339(environment.updated_at))
        ));
    }
    body.push_str("</tbody></table>");

    if can_manage {
        body.push_str("<h2>Audit trail</h2>");
        body.push_str(&format!(
            "<p><a href=\"/dashboard/teams/{team_id}/audit.csv\">Download CSV</a></p>"
        ));
        body.push_str("<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Subject</th></tr></thead><tbody>");
        for event in &audits {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&util::rfc3339(event.created_at)),
                esc(event.actor_username.as_deref().unwrap_or("system")),
                esc(&event.action),
                esc(event.subject.as_deref().unwrap_or("—"))
            ));
        }
        body.push_str("</tbody></table>");
    }

    body.push_str("<section class=\"note\"><strong>Revocation requires key rotation.</strong> Removing a member blocks the relay, but they may retain old ciphertext. Run <code>velt team rotate-key --team ");
    body.push_str(&team.id.to_string());
    body.push_str(
        "</code> from the owner's terminal to re-encrypt every environment.</section></main>",
    );
    html_page(StatusCode::OK, &team.name, &body)
}

async fn update_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team_id, target_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<UpdateForm>,
) -> Response {
    let Some(user) = dashboard_user(&state, &headers).await else {
        return Redirect::to("/dashboard/login").into_response();
    };
    if !csrf_valid(&user, &form.csrf) {
        return error_page("Invalid CSRF token");
    }
    let caller = match util::membership(&state.db, team_id, user.id).await {
        Ok(Some(member)) => member,
        _ => return error_page("Not authorized"),
    };
    if role_rank(&caller.role) < role_rank("admin") {
        return error_page("Not authorized");
    }
    let target = match util::membership(&state.db, team_id, target_id).await {
        Ok(Some(target)) => target,
        _ => return error_page("Member not found"),
    };
    if target.role == "owner" {
        return error_page("The owner cannot be modified");
    }
    let role = match validate::role(&form.role) {
        Ok(role) if role != "owner" => role,
        _ => return error_page("Invalid role"),
    };
    let grants = form
        .env_grants
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let grants = match validate::grants(grants) {
        Ok(grants) => grants,
        Err(_) => return error_page("Invalid environment grants"),
    };
    if let Err(error) = sqlx::query(
        "UPDATE team_members SET role = $3, env_grants = $4
         WHERE team_id = $1 AND user_id = $2",
    )
    .bind(team_id)
    .bind(target_id)
    .bind(role)
    .bind(&grants)
    .execute(&state.db)
    .await
    {
        tracing::error!(error = %error, "dashboard member update failed");
        return error_page("Could not update member");
    }
    if let Ok(mut connection) = state.db.acquire().await {
        let _ = util::insert_audit(
            &mut connection,
            team_id,
            Some(user.id),
            "member_updated",
            None,
            json!({"user_id": target_id, "role": role, "env_grants": grants, "via": "dashboard"}),
        )
        .await;
    }
    Redirect::to(&format!("/dashboard/teams/{team_id}")).into_response()
}

async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((team_id, target_id)): Path<(Uuid, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(user) = dashboard_user(&state, &headers).await else {
        return Redirect::to("/dashboard/login").into_response();
    };
    if !csrf_valid(&user, &form.csrf) {
        return error_page("Invalid CSRF token");
    }
    let caller = match util::membership(&state.db, team_id, user.id).await {
        Ok(Some(member)) => member,
        _ => return error_page("Not authorized"),
    };
    if role_rank(&caller.role) < role_rank("admin") {
        return error_page("Not authorized");
    }
    let target = match util::membership(&state.db, team_id, target_id).await {
        Ok(Some(target)) => target,
        _ => return error_page("Member not found"),
    };
    if target.role == "owner" {
        return error_page("The owner cannot be removed");
    }
    let mut transaction = match state.db.begin().await {
        Ok(transaction) => transaction,
        Err(_) => return error_page("Database unavailable"),
    };
    if sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team_id)
        .bind(target_id)
        .execute(&mut *transaction)
        .await
        .is_err()
        || sqlx::query("DELETE FROM team_envelopes WHERE team_id = $1 AND user_id = $2")
            .bind(team_id)
            .bind(target_id)
            .execute(&mut *transaction)
            .await
            .is_err()
    {
        return error_page("Could not revoke member");
    }
    let _ = util::insert_audit(
        &mut transaction,
        team_id,
        Some(user.id),
        "member_removed",
        None,
        json!({"user_id": target_id, "via": "dashboard"}),
    )
    .await;
    if transaction.commit().await.is_err() {
        return error_page("Could not revoke member");
    }
    Redirect::to(&format!("/dashboard/teams/{team_id}")).into_response()
}

async fn audit_csv(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(team_id): Path<Uuid>,
) -> Response {
    let Some(user) = dashboard_user(&state, &headers).await else {
        return Redirect::to("/dashboard/login").into_response();
    };
    let member = match util::membership(&state.db, team_id, user.id).await {
        Ok(Some(member)) => member,
        _ => return error_page("Not authorized"),
    };
    if role_rank(&member.role) < role_rank("admin") {
        return error_page("Not authorized");
    }
    let events = sqlx::query_as::<_, AuditRow>(
        "SELECT a.id, u.username AS actor_username, a.action, a.subject, a.metadata, a.created_at
         FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
         WHERE a.team_id = $1 ORDER BY a.created_at DESC LIMIT 5000",
    )
    .bind(team_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut csv = String::from("created_at,actor,action,subject,metadata\n");
    for event in events {
        csv.push_str(&format!(
            "{},{},{},{},\"{}\"\n",
            csv_escape(&util::rfc3339(event.created_at)),
            csv_escape(event.actor_username.as_deref().unwrap_or("system")),
            csv_escape(&event.action),
            csv_escape(event.subject.as_deref().unwrap_or("")),
            csv_escape(&event.metadata.to_string())
        ));
    }
    let mut response = (StatusCode::OK, csv).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"velt-audit.csv\""),
    );
    security_headers(response)
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        let _ = sqlx::query("DELETE FROM dashboard_sessions WHERE token_hash = $1")
            .bind(util::sha256(token.as_bytes()).to_vec())
            .execute(&state.db)
            .await;
    }
    let mut response = Redirect::to("/dashboard/login").into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "velt_dashboard=; HttpOnly; SameSite=Strict; Path=/dashboard; Max-Age=0",
        ),
    );
    security_headers(response)
}

async fn dashboard_user(state: &AppState, headers: &HeaderMap) -> Option<DashboardUser> {
    let token = cookie_token(headers)?;
    let row = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT s.user_id, u.username, s.csrf_token
         FROM dashboard_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(util::sha256(token.as_bytes()).to_vec())
    .fetch_optional(&state.db)
    .await
    .ok()??;
    Some(DashboardUser {
        id: row.0,
        username: row.1,
        csrf: row.2,
    })
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(COOKIE)?.to_str().ok()?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{COOKIE_NAME}=")) {
            if !value.is_empty() && value.len() <= 256 {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn cookie_header(token: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/dashboard; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

fn csrf_valid(user: &DashboardUser, token: &str) -> bool {
    util::constant_time_eq(user.csrf.as_bytes(), token.as_bytes())
}

fn selected(current: &str, candidate: &str) -> &'static str {
    if current == candidate {
        " selected"
    } else {
        ""
    }
}

fn login_confirm_body(token: &str) -> String {
    format!(
        "<main class=\"narrow\"><h1>Continue to dashboard</h1><p>This is a single-use login link. Confirm to create an 8-hour browser session.</p><form method=\"post\" action=\"/dashboard/login\"><input type=\"hidden\" name=\"token\" value=\"{}\"><button type=\"submit\">Continue</button></form><p class=\"muted\">The link expires five minutes after it is minted. The dashboard never receives secret values or team keys.</p></main>",
        esc(token)
    )
}

fn login_body(error: Option<&str>) -> String {
    let message = error
        .map(|error| format!("<p class=\"error\">{}</p>", esc(error)))
        .unwrap_or_default();
    format!(
        "<main class=\"narrow\"><h1>Dashboard login</h1>{message}<p>Dashboard links are minted from an authenticated terminal:</p><pre>velt dashboard</pre><p class=\"muted\">Open the printed one-time link within 5 minutes. Links are single-use; this dashboard never receives secret values or team keys.</p></main>"
    )
}

fn render_page(status: StatusCode, title: &str, body: String) -> Response {
    html_page(status, title, &body)
}

fn html_page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Velt · {}</title><style>{}</style></head><body>{body}</body></html>",
        esc(title),
        CSS
    );
    let mut response = (status, Html(html)).into_response();
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

fn security_headers(mut response: Response) -> Response {
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
        .headers_mut()
        .insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

fn error_page(message: &str) -> Response {
    render_page(
        StatusCode::BAD_REQUEST,
        "Dashboard error",
        format!(
            "<main class=\"narrow\"><h1>Something went wrong</h1><p class=\"error\">{}</p><p><a href=\"/dashboard\">Back to dashboard</a></p></main>",
            esc(message)
        ),
    )
}

fn esc(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn csv_escape(input: &str) -> String {
    if input.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", input.replace('"', "\"\""))
    } else {
        input.to_owned()
    }
}

const CSS: &str = r#"
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b0c0e;color:#e7e7e7;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 28px;border-bottom:1px solid #23252a;background:#0f1013}
.brand{color:#ff9f1c;font-weight:700;letter-spacing:.18em}.who{display:flex;gap:14px;align-items:center;color:#9a9a9a}
main{max-width:1100px;margin:0 auto;padding:28px}main.narrow{max-width:560px}h1{font-size:24px;margin:8px 0 18px}h2{font-size:16px;color:#ff9f1c;margin:32px 0 10px;text-transform:uppercase;letter-spacing:.08em}
a{color:#ff9f1c;text-decoration:none}a:hover{text-decoration:underline}.muted{color:#8b8b8b}.error{color:#ff5d5d}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}.card{display:block;border:1px solid #23252a;background:#121317;border-radius:8px;padding:16px;color:#e7e7e7}.card:hover{border-color:#ff9f1c;text-decoration:none}.card-title{font-size:16px;margin-bottom:6px}.metric{margin-top:10px;color:#cfcfcf}
table{width:100%;border-collapse:collapse;border:1px solid #23252a}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #23252a;vertical-align:top}th{color:#8b8b8b;font-weight:500;background:#121317}
code,pre{background:#121317;border:1px solid #23252a;border-radius:4px}code{padding:1px 4px}pre{padding:12px;overflow:auto}
button{background:#1b1d22;color:#e7e7e7;border:1px solid #3a3d44;border-radius:4px;padding:6px 10px;font:inherit;cursor:pointer}button:hover{border-color:#ff9f1c;color:#ff9f1c}button.link{background:none;border:none;color:#9a9a9a;padding:0}button.link:hover{color:#ff9f1c}
form.inline{display:inline-flex;gap:6px;align-items:center;margin:2px 4px 2px 0}form.inline.danger button{color:#ff7a7a;border-color:#4a2626}input,select{background:#0b0c0e;color:#e7e7e7;border:1px solid #3a3d44;border-radius:4px;padding:5px 7px;font:inherit;min-width:0}input[name=env_grants]{width:160px}
.note{margin-top:34px;border-left:3px solid #ff9f1c;background:#121317;padding:12px 16px;color:#bdbdbd}
"#;
