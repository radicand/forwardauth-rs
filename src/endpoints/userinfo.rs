use crate::domain::User;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::Extension;
use serde_json::json;
use tracing::{debug, error};

/// GET /userinfo
///
/// Returns userinfo for the authenticated user.
/// Requires authentication. Fetches info from Auth0 userinfo endpoint.
pub async fn userinfo(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    _headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    match user {
        User::Authenticated(ref auth_user) => {
            debug!("Getting userinfo for {}", auth_user.sub);

            match state
                .auth0_client
                .userinfo(&auth_user.access_token.raw)
                .await
            {
                Ok(info) => {
                    let response = json!({
                        "class": ["userinfo"],
                        "title": format!("Userinfo for {}", auth_user.sub),
                        "properties": info
                    });
                    Ok(Json(response).into_response())
                }
                Err(e) => {
                    error!("Failed to fetch userinfo: {}", e);
                    Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to fetch userinfo: {}", e),
                    ))
                }
            }
        }
        User::Anonymous => Err((
            StatusCode::UNAUTHORIZED,
            "Authentication required".to_string(),
        )),
    }
}
