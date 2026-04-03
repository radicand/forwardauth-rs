use crate::auth0::Auth0Client;
use crate::config::AppConfig;
use std::sync::Arc;

/// Shared application state passed to all handlers via Axum extractors.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub auth0_client: Auth0Client,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let config = Arc::new(config);
        let auth0_client = Auth0Client::new(config.clone());
        Self {
            config,
            auth0_client,
        }
    }
}
