use forwardauth_rs::config::AppConfig;
use forwardauth_rs::endpoints;
use forwardauth_rs::middleware::authenticate_middleware;
use forwardauth_rs::state::AppState;

use axum::middleware as axum_middleware;
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,forwardauth_rs=debug")),
        )
        .init();

    info!("Starting ForwardAuth-RS v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config_path =
        std::env::var("CONFIG_FILE").unwrap_or_else(|_| "/config/application.yaml".to_string());
    let config_path = PathBuf::from(&config_path);

    let config = if config_path.exists() {
        info!("Loading configuration from {}", config_path.display());
        AppConfig::from_file(&config_path)?
    } else {
        warn!(
            "Config file not found at {}, trying ./application.yaml",
            config_path.display()
        );
        let fallback = PathBuf::from("application.yaml");
        if fallback.exists() {
            AppConfig::from_file(&fallback)?
        } else {
            anyhow::bail!(
                "No configuration file found. Set CONFIG_FILE env var or provide application.yaml"
            );
        }
    };

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(config.port);

    let state = AppState::new(config);

    // Build the router — the health endpoint is intentionally placed outside
    // the authenticate_middleware so that Kubernetes probes are never affected
    // by auth processing latency or middleware correctness.
    let protected = Router::new()
        .route("/authorize", get(endpoints::authorize))
        .route("/signin", get(endpoints::signin))
        .route("/signout", get(endpoints::signout))
        .route("/userinfo", get(endpoints::userinfo))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            authenticate_middleware,
        ));

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
