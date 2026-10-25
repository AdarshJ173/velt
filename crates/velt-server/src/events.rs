//! Real-time team events, fanned out through PostgreSQL LISTEN/NOTIFY so every
//! stateless API instance receives the same stream.

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamEvent {
    pub team_id: Uuid,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<TeamEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(16));
        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TeamEvent> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: TeamEvent) {
        // A send error only means there are no subscribers.
        let _ = self.sender.send(event);
    }
}

/// Publish an event to all instances (including this one) through PostgreSQL.
pub async fn notify(pool: &PgPool, event: &TeamEvent) {
    let Ok(payload) = serde_json::to_string(event) else {
        return;
    };
    if let Err(error) = sqlx::query("SELECT pg_notify('velt_events', $1)")
        .bind(payload)
        .execute(pool)
        .await
    {
        tracing::warn!(error = %error, "failed to publish team event");
    }
}

/// Listen for events and forward them to the in-process broadcast bus.
pub async fn spawn_listener(database_url: &str, bus: EventBus) -> Result<(), sqlx::Error> {
    let mut listener = PgListener::connect(database_url).await?;
    listener.listen("velt_events").await?;
    tokio::spawn(async move {
        loop {
            match listener.recv().await {
                Ok(notification) => {
                    if let Ok(event) = serde_json::from_str::<TeamEvent>(notification.payload()) {
                        bus.publish(event);
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "team event listener stopped");
                    break;
                }
            }
        }
    });
    Ok(())
}
