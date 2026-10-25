//! WebSocket stream of team changes, authenticated with the same session token.

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::auth::{authenticate, bearer_token};
use crate::error::{ApiError, ApiResult};
use crate::events::TeamEvent;
use crate::models::WsQuery;
use crate::{util, AppState};

pub async fn events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(team_id): Path<Uuid>,
    Query(query): Query<WsQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let token = query
        .token
        .or_else(|| bearer_token(&headers))
        .ok_or(ApiError::Unauthorized)?;
    let user = authenticate(&state.db, &token).await?;
    util::membership(&state.db, team_id, user.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let receiver = state.events.subscribe();
    Ok(ws.on_upgrade(move |socket| handle(socket, state, team_id, receiver)))
}

async fn handle(
    socket: WebSocket,
    state: AppState,
    team_id: Uuid,
    mut receiver: broadcast::Receiver<TeamEvent>,
) {
    let (mut sender, mut incoming) = socket.split();
    let ready = json!({"type": "ready", "team_id": team_id}).to_string();
    if sender.send(Message::Text(ready.into())).await.is_err() {
        return;
    }
    let mut heartbeat = interval(Duration::from_secs(30));
    heartbeat.tick().await;

    loop {
        tokio::select! {
            event = receiver.recv() => {
                match event {
                    Ok(event) if event.team_id == team_id => {
                        let payload = json!({
                            "type": event.kind,
                            "environment": event.environment,
                            "version": event.version,
                            "created_at": event.created_at,
                        })
                        .to_string();
                        if sender.send(Message::Text(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if sender.send(Message::Text("{\"type\":\"lagged\"}".into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            message = incoming.next() => {
                match message {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
            _ = heartbeat.tick() => {
                if sender.send(Message::Ping(Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = state;
}
