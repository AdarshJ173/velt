pub mod blobs;
pub mod teams;
pub mod ws;

use axum::routing::{get, patch, post};
use axum::Router;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/teams", get(teams::list_teams).post(teams::create_team))
        .route(
            "/teams/{team_id}",
            get(teams::get_team).delete(teams::delete_team),
        )
        .route("/teams/{team_id}/members", post(teams::invite_member))
        .route(
            "/teams/{team_id}/members/{user_id}",
            patch(teams::update_member).delete(teams::remove_member),
        )
        .route("/teams/{team_id}/envelopes", get(teams::get_envelopes))
        .route(
            "/teams/{team_id}/environments",
            get(blobs::list_environments),
        )
        .route(
            "/teams/{team_id}/environments/{environment}",
            get(blobs::pull_blob).put(blobs::push_blob),
        )
        .route("/teams/{team_id}/key-epoch", post(teams::rotate_key))
        .route("/teams/{team_id}/audit", get(teams::audit_log))
        .route("/teams/{team_id}/events", get(ws::events))
        .route("/users/{username}", get(teams::lookup_user))
}
