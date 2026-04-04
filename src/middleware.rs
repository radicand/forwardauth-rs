use crate::domain::{AuthenticatedUser, Token, User};
use crate::state::AppState;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use std::collections::HashMap;
use tracing::{debug, trace};

/// Middleware that authenticates the user from cookies or Basic auth header.
///
/// Authentication chain (matches original):
/// 1. Start as Anonymous
/// 2. Check for Basic Auth header → client_credentials exchange
/// 3. Check for ACCESS_TOKEN / JWT_TOKEN cookies → verify tokens
///
/// The resulting User is stored in request extensions.
pub async fn authenticate_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let forwarded_host = request
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let mut user = User::Anonymous;

    if let Some(ref host) = forwarded_host {
        let app = state.config.find_application_or_default(Some(host));

        // Try Basic Auth first (client credentials flow)
        if let Some(auth_header) = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        {
            if auth_header.to_lowercase().starts_with("basic ") {
                trace!("Found Basic authentication header");
                let base64_creds = auth_header[6..].trim();
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(base64_creds)
                {
                    if let Ok(creds) = String::from_utf8(decoded) {
                        if let Some((username, password)) = creds.split_once(':') {
                            match state
                                .auth0_client
                                .client_credentials_exchange(username, password, &app.audience)
                                .await
                            {
                                Ok(access_token_str) => {
                                    let token = state
                                        .auth0_client
                                        .verify_token(&access_token_str, &app.audience)
                                        .await;
                                    if let Token::Jwt(jwt) = token {
                                        let sub = jwt.subject().to_string();
                                        let permissions = jwt.permissions();
                                        user = User::Authenticated(Box::new(AuthenticatedUser {
                                            access_token: *jwt,
                                            id_token: Token::Empty,
                                            userinfo: HashMap::new(),
                                            sub,
                                            permissions,
                                        }));
                                        debug!(
                                            "Authenticated via client credentials: {}",
                                            user.subject()
                                        );
                                    }
                                }
                                Err(e) => {
                                    debug!("Client credentials auth failed: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        // If not yet authenticated, try cookie-based auth
        if !user.is_authenticated() {
            let access_token_cookie = extract_cookie(&request, "ACCESS_TOKEN");
            let id_token_cookie = extract_cookie(&request, "JWT_TOKEN");

            if let Some(ref at) = access_token_cookie {
                trace!("Found ACCESS_TOKEN cookie, verifying");
                let access_token = state.auth0_client.verify_token(at, &app.audience).await;
                let id_token = if let Some(ref it) = id_token_cookie {
                    state.auth0_client.verify_token(it, &app.client_id).await
                } else {
                    Token::Empty
                };

                if let Token::Jwt(ref jwt) = access_token {
                    let sub = jwt.subject().to_string();
                    let permissions = jwt.permissions();

                    // Extract userinfo from claims
                    let mut userinfo = HashMap::new();
                    userinfo.insert("sub".to_string(), sub.clone());

                    if let Token::Jwt(ref id_jwt) = id_token {
                        // Verify sub matches between access_token and id_token
                        // to prevent token substitution attacks (#124)
                        if !id_jwt.claims.sub.is_empty()
                            && id_jwt.claims.sub != sub
                        {
                            debug!(
                                "Sub mismatch: access_token sub={} id_token sub={}, ignoring id_token",
                                sub, id_jwt.claims.sub
                            );
                        } else {
                            for claim_name in &app.claims {
                                if let Some(value) = id_jwt.get_claim(claim_name) {
                                    userinfo.insert(claim_name.clone(), value);
                                }
                            }
                        }
                    }

                    if let Token::Jwt(access_jwt) = access_token {
                        user = User::Authenticated(Box::new(AuthenticatedUser {
                            access_token: *access_jwt,
                            id_token,
                            userinfo,
                            sub,
                            permissions,
                        }));
                        debug!("Authenticated via cookies: {}", user.subject());
                    }
                }
            }
        }
    } else {
        trace!("No x-forwarded-host header, skipping authentication");
    }

    // Store user in request extensions for handlers to access
    request.extensions_mut().insert(user);

    next.run(request).await
}

/// Extract a cookie value from the request by name.
fn extract_cookie(request: &Request<axum::body::Body>, name: &str) -> Option<String> {
    request
        .headers()
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
