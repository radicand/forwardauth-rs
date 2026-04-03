use crate::domain::{AuthorizeState, SigninResult};
use crate::endpoints::{build_cookie, clear_cookie};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
pub struct SigninParams {
    pub code: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub state: Option<String>,
}

/// GET /signin
///
/// OAuth2 callback endpoint. Auth0 redirects here after user authorization.
/// Exchanges the authorization code for tokens, validates the nonce,
/// sets session cookies, and redirects to the original URL.
pub async fn signin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SigninParams>,
) -> Result<Response, (StatusCode, String)> {
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok());

    let app = state.config.find_application_or_default(forwarded_host);

    // Extract nonce from cookie
    let nonce_cookie = extract_cookie_value(&headers, "AUTH_NONCE");

    let result = handle_signin(&state, &params, &nonce_cookie, &app).await;

    match result {
        SigninResult::Complete {
            access_token,
            id_token,
            expires_in,
            redirect_to,
            cookie_domain,
        } => {
            info!("Sign in successful, redirecting to '{}'", redirect_to);

            let at_cookie = build_cookie(
                "ACCESS_TOKEN",
                &access_token,
                &cookie_domain,
                expires_in,
                "/",
            );
            let jwt_cookie = build_cookie("JWT_TOKEN", &id_token, &cookie_domain, expires_in, "/");
            let clear_nonce = clear_cookie("AUTH_NONCE", &cookie_domain);

            let response = axum::http::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", &redirect_to)
                .header("Set-Cookie", &at_cookie)
                .header("Set-Cookie", &jwt_cookie)
                .header("Set-Cookie", &clear_nonce)
                .body(axum::body::Body::empty())
                .unwrap();

            Ok(response)
        }
        SigninResult::Error {
            reason,
            description,
        } => {
            error!("Sign in error: {} - {}", reason, description);
            Err((
                StatusCode::BAD_REQUEST,
                format!("{}: {}", reason, description),
            ))
        }
    }
}

async fn handle_signin(
    state: &AppState,
    params: &SigninParams,
    nonce_cookie: &Option<String>,
    app: &crate::config::ApplicationConfig,
) -> SigninResult {
    // Check for error from Auth0
    if let Some(ref error) = params.error {
        let description = params
            .error_description
            .as_deref()
            .unwrap_or("no error description");
        error!("Received error from Auth0 on sign in: {}", description);
        return SigninResult::Error {
            reason: error.clone(),
            description: description.to_string(),
        };
    }

    // Validate code and state are present
    let code = match &params.code {
        Some(c) if !c.is_empty() => c,
        _ => {
            return SigninResult::Error {
                reason: "Unknown request".to_string(),
                description: "Login redirect from Auth0 had no code".to_string(),
            };
        }
    };

    let state_param = match &params.state {
        Some(s) if !s.is_empty() => s,
        _ => {
            return SigninResult::Error {
                reason: "Unknown request".to_string(),
                description: "Login redirect from Auth0 had no state".to_string(),
            };
        }
    };

    // Decode the state parameter
    let decoded_state = match AuthorizeState::decode(state_param) {
        Ok(s) => s,
        Err(e) => {
            return SigninResult::Error {
                reason: "Invalid state".to_string(),
                description: format!("Failed to decode state parameter: {}", e),
            };
        }
    };

    // Validate nonce (CSRF protection)
    let received_nonce = &decoded_state.nonce;
    match nonce_cookie {
        Some(cookie_nonce) if cookie_nonce == received_nonce => {
            debug!("Nonce validation successful");
        }
        Some(cookie_nonce) => {
            error!(
                "Nonce mismatch: received={} cookie={}",
                received_nonce, cookie_nonce
            );
            return SigninResult::Error {
                reason: "Nonce mismatch".to_string(),
                description: "AUTH_NONCE cookie didn't match the nonce in state".to_string(),
            };
        }
        None => {
            warn!("AUTH_NONCE cookie not found");
            return SigninResult::Error {
                reason: "Missing nonce".to_string(),
                description: "AUTH_NONCE cookie not found".to_string(),
            };
        }
    }

    // Exchange code for tokens
    match state
        .auth0_client
        .authorization_code_exchange(code, &app.client_id, &app.client_secret, &app.redirect_uri)
        .await
    {
        Ok(token_resp) => {
            let id_token = token_resp.id_token.unwrap_or_default();
            let expires_in = token_resp.expires_in.unwrap_or(86400);

            SigninResult::Complete {
                access_token: token_resp.access_token,
                id_token,
                expires_in,
                redirect_to: decoded_state.origin_url(),
                cookie_domain: app.token_cookie_domain.clone(),
            }
        }
        Err(e) => {
            error!("Token exchange failed: {}", e);
            SigninResult::Error {
                reason: "Token exchange failed".to_string(),
                description: e.to_string(),
            }
        }
    }
}

fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|cookie_str| cookie_str.split(';'))
        .map(|s| s.trim())
        .find_map(|cookie| {
            let mut parts = cookie.splitn(2, '=');
            let key = parts.next()?.trim();
            let value = parts.next()?.trim();
            if key == name {
                Some(value.to_string())
            } else {
                None
            }
        })
}
