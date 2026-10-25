//! Velt sync relay server.
//!
//! The server is a zero-knowledge relay: it stores user public keys, team
//! memberships, sealed team-key envelopes, opaque encrypted vault blobs and
//! audit metadata. It never receives plaintext secrets or team keys.

pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod models;
pub mod routes;
pub mod util;
pub mod validate;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::events::EventBus;

pub const AUTH_NAMESPACE: &str = "velt-auth-v1";

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub events: EventBus,
}

pub async fn connect_database(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(32)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

pub fn build_app(state: AppState) -> Router {
    let request_id = HeaderName::from_static("x-request-id");
    let body_limit = state.config.max_blob_bytes.saturating_add(64 * 1024);
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .nest("/v1/auth", auth::public_router())
        .route("/v1/me", get(auth::me))
        .nest("/v1", routes::router())
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(request_id.clone(), MakeRequestUuid))
        .layer(PropagateRequestIdLayer::new(request_id))
        .layer(CatchPanicLayer::new())
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ready"}))).into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "unavailable"})),
            )
                .into_response()
        }
    }
}
