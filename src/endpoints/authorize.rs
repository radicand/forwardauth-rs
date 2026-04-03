use crate::config::ApplicationConfig;
use crate::domain::{AuthorizeResult, AuthorizeState, RequestedUrl, User};
use crate::endpoints::build_cookie;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use tracing::{debug, trace, warn};
use uuid::Uuid;

/// GET /authorize
///
/// Main ForwardAuth endpoint called by Traefik.
/// Reads x-forwarded-* headers and decides:
/// - 200: Access granted (with auth headers forwarded)
/// - 307: Redirect to Auth0 for authentication
/// - 401: Authentication required (for API requests)
/// - 403: Permission denied
pub async fn authorize(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    trace_headers(&headers);

    let forwarded_host = get_required_header(&headers, "x-forwarded-host")?;
    let forwarded_proto = get_required_header(&headers, "x-forwarded-proto")?;
    let forwarded_uri = get_required_header(&headers, "x-forwarded-uri")?;
    let forwarded_method = get_required_header(&headers, "x-forwarded-method")?;

    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let requested_with = headers
        .get("x-requested-with")
        .and_then(|v| v.to_str().ok());

    // Detect if this is an API request (returns 401 instead of redirect)
    let is_api = accept.contains("application/json")
        || accept.contains("text/event-stream")
        || requested_with == Some("XMLHttpRequest");

    let app = state
        .config
        .find_application_or_default(Some(&forwarded_host));

    let origin_url = RequestedUrl {
        protocol: forwarded_proto.clone(),
        host: forwarded_host.clone(),
        uri: forwarded_uri.clone(),
        method: forwarded_method.clone(),
    };

    let result = perform_authorization(&user, &app, &origin_url, is_api, &state);

    match result {
        AuthorizeResult::AccessGranted { user } => {
            debug!("Access granted for {}", user.subject());
            let mut builder = axum::http::Response::builder().status(StatusCode::NO_CONTENT);

            if let User::Authenticated(ref auth_user) = user {
                // Forward Authorization header with access token
                builder = builder.header(
                    "Authorization",
                    format!("Bearer {}", auth_user.access_token.raw),
                );

                // Forward userinfo as x-forwardauth-* headers
                for (key, value) in &auth_user.userinfo {
                    let header_name =
                        format!("x-forwardauth-{}", key.replace('_', "-").to_lowercase());
                    trace!("Adding header {} = {}", header_name, value);
                    builder = builder.header(&header_name, value);
                }
            }

            Ok(builder.body(axum::body::Body::empty()).unwrap())
        }
        AuthorizeResult::NeedRedirect {
            authorize_url,
            nonce,
            cookie_domain,
        } => {
            debug!("Redirecting to Auth0: {}", authorize_url);

            let cookie = build_cookie(
                "AUTH_NONCE",
                &nonce,
                &cookie_domain,
                state.config.nonce_max_age,
                "/",
            );

            let response = axum::http::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", &authorize_url)
                .header("Set-Cookie", &cookie)
                .body(axum::body::Body::empty())
                .unwrap();

            Ok(response)
        }
        AuthorizeResult::AccessDenied { user, reason } => {
            warn!("Access denied for {}: {}", user.subject(), reason);
            Err(StatusCode::FORBIDDEN)
        }
        AuthorizeResult::Error { reason } => {
            warn!("Authorization error: {}", reason);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Core authorization logic matching the original state machine behavior.
fn perform_authorization(
    user: &User,
    app: &ApplicationConfig,
    origin_url: &RequestedUrl,
    is_api: bool,
    state: &AppState,
) -> AuthorizeResult {
    // Step 1: Check if URL is whitelisted (the signin/callback URL itself)
    if origin_url.starts_with(&app.redirect_uri) {
        debug!("URL is whitelisted (signin URL), granting access");
        return AuthorizeResult::AccessGranted { user: user.clone() };
    }

    // Step 2: Check if the HTTP method is restricted
    let is_restricted_method = app
        .restricted_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&origin_url.method));

    if !is_restricted_method {
        debug!(
            "Method {} is not restricted, granting access",
            origin_url.method
        );
        return AuthorizeResult::AccessGranted { user: user.clone() };
    }

    // Step 3: Validate the access token
    match user {
        User::Anonymous => {
            // No valid token, need to redirect for auth
            if is_api {
                return AuthorizeResult::AccessDenied {
                    user: User::Anonymous,
                    reason: "Authentication required".to_string(),
                };
            }
            let nonce = Uuid::new_v4().to_string().replace('-', "");
            let auth_state = AuthorizeState::new(origin_url, &nonce);
            let authorize_url = build_authorize_url(
                &state.config.authorize_url,
                &app.client_id,
                &app.audience,
                &app.scope,
                &app.redirect_uri,
                &auth_state,
            );

            AuthorizeResult::NeedRedirect {
                authorize_url,
                nonce,
                cookie_domain: app.token_cookie_domain.clone(),
            }
        }
        User::Authenticated(auth_user) => {
            // Step 4: Validate permissions
            if !app.required_permissions.is_empty() {
                if !auth_user.access_token.has_permission_claim() {
                    warn!("Missing permissions claim in access token");
                    return AuthorizeResult::AccessDenied {
                        user: user.clone(),
                        reason: "Missing permissions claim in access token. In Auth0, enable 'Add Permissions in the Access Token'.".to_string(),
                    };
                }

                if !auth_user
                    .access_token
                    .has_permission(&app.required_permissions)
                {
                    let missing = auth_user
                        .access_token
                        .missing_permissions(&app.required_permissions);
                    return AuthorizeResult::AccessDenied {
                        user: user.clone(),
                        reason: format!("Missing permissions: {}", missing.join(", ")),
                    };
                }
            }

            AuthorizeResult::AccessGranted { user: user.clone() }
        }
    }
}

/// Build the Auth0 authorize URL with all required parameters.
fn build_authorize_url(
    authorize_url: &str,
    client_id: &str,
    audience: &str,
    scope: &str,
    redirect_uri: &str,
    state: &AuthorizeState,
) -> String {
    let encoded_scope = urlencoding::encode(scope);
    let encoded_audience = urlencoding::encode(audience);
    let encoded_redirect = urlencoding::encode(redirect_uri);
    let encoded_state = state.encode();

    format!(
        "{}?audience={}&scope={}&response_type=code&client_id={}&redirect_uri={}&state={}",
        authorize_url, encoded_audience, encoded_scope, client_id, encoded_redirect, encoded_state
    )
}

fn get_required_header(headers: &HeaderMap, name: &str) -> Result<String, StatusCode> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            warn!("Missing required header: {}", name);
            StatusCode::BAD_REQUEST
        })
}

fn trace_headers(headers: &HeaderMap) {
    if tracing::enabled!(tracing::Level::TRACE) {
        for (key, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                trace!("Header '{}' = {}", key, v);
            }
        }
    }
}

// We need the urlencoding crate - let's use url's percent encoding instead
mod urlencoding {
    use url::form_urlencoded;

    pub fn encode(input: &str) -> String {
        form_urlencoded::byte_serialize(input.as_bytes()).collect()
    }
}
