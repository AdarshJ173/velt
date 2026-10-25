//! Velt relay server binary.

use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use velt_server::config::Config;
use velt_server::events::{self, EventBus};
use velt_server::{build_app, connect_database, run_migrations, AppState};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info")),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration error: {error}");
            std::process::exit(1);
        }
    };

    let pool = match connect_database(&config.database_url).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("database connection failed: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = run_migrations(&pool).await {
        eprintln!("database migration failed: {error}");
        std::process::exit(1);
    }

    let bus = EventBus::new(1024);
    if let Err(error) = events::spawn_listener(&config.database_url, bus.clone()).await {
        eprintln!("failed to start PostgreSQL event listener: {error}");
        std::process::exit(1);
    }

    let bind = config.bind;
    let state = AppState {
        db: pool,
        config: Arc::new(config),
        events: bus,
    };
    let app = build_app(state);
    let listener = match TcpListener::bind(bind).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("failed to bind {bind}: {error}");
            std::process::exit(1);
        }
    };

    tracing::info!(address = %bind, "velt relay listening");
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        eprintln!("server error: {error}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
