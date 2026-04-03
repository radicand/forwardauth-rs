use crate::domain::User;
use crate::endpoints::clear_cookie;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use tracing::{debug, error, info};

/// GET /signout
///
/// Sign out endpoint. Requires authenticated user.
/// Clears session cookies and optionally redirects via Auth0 logout.
pub async fn signout(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    // Require authentication
    if !user.is_authenticated() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Authentication required".to_string(),
        ));
    }

    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok());

    let app = state.config.find_application_or_default(forwarded_host);

    // Call Auth0 signout
    let signout_result = state
        .auth0_client
        .signout(&app.client_id, &app.return_to)
        .await;

    // Clear session cookies
    let clear_at = clear_cookie("ACCESS_TOKEN", &app.token_cookie_domain);
    let clear_jwt = clear_cookie("JWT_TOKEN", &app.token_cookie_domain);

    match signout_result {
        Ok(Some(redirect_url)) => {
            info!("Signout complete, redirecting to {}", redirect_url);
            let response = axum::http::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", &redirect_url)
                .header("Set-Cookie", &clear_at)
                .header("Set-Cookie", &clear_jwt)
                .body(axum::body::Body::empty())
                .unwrap();
            Ok(response)
        }
        Ok(None) => {
            debug!("Signout complete, no redirect");
            let response = axum::http::Response::builder()
                .status(StatusCode::NO_CONTENT)
                .header("Set-Cookie", &clear_at)
                .header("Set-Cookie", &clear_jwt)
                .body(axum::body::Body::empty())
                .unwrap();
            Ok(response)
        }
        Err(e) => {
            error!("Signout error: {}", e);
            // Still clear cookies even on error
            let response = axum::http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Set-Cookie", &clear_at)
                .header("Set-Cookie", &clear_jwt)
                .body(axum::body::Body::from(format!("Signout error: {}", e)))
                .unwrap();
            Ok(response)
        }
    }
}
