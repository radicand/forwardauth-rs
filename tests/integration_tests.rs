//! Integration tests for ForwardAuth-RS endpoints.
//!
//! Uses wiremock to mock Auth0 API responses and tests the full
//! HTTP request/response cycle for all endpoints.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware as axum_middleware;
use axum::routing::get;
use axum::Router;
use forwardauth_rs::config::AppConfig;
use forwardauth_rs::endpoints;
use forwardauth_rs::middleware::authenticate_middleware;
use forwardauth_rs::state::AppState;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Create a test config pointing to the mock server.
fn test_config(mock_url: &str) -> AppConfig {
    let domain = format!("{}/", mock_url);
    AppConfig {
        domain: domain.clone(),
        token_endpoint: format!("{}/oauth/token", mock_url),
        authorize_url: format!("{}/authorize", mock_url),
        userinfo_endpoint: format!("{}/userinfo", mock_url),
        logout_endpoint: format!("{}/v2/logout", mock_url),
        nonce_max_age: 60,
        port: 8080,
        default: forwardauth_rs::config::ApplicationConfig {
            name: "www.example.test".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            audience: "https://api.example.test".to_string(),
            scope: "profile openid email".to_string(),
            redirect_uri: "https://www.example.test/oauth2/signin".to_string(),
            token_cookie_domain: "example.test".to_string(),
            restricted_methods: vec![
                "DELETE".to_string(),
                "GET".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
                "PATCH".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
            ],
            required_permissions: vec![],
            claims: vec!["sub".to_string(), "name".to_string(), "email".to_string()],
            return_to: "https://www.example.test".to_string(),
        },
        apps: vec![forwardauth_rs::config::ApplicationConfig {
            name: "restricted.example.test".to_string(),
            client_id: "restricted-client-id".to_string(),
            client_secret: "restricted-client-secret".to_string(),
            audience: "https://api.restricted.example.test".to_string(),
            scope: "profile openid email".to_string(),
            redirect_uri: "https://restricted.example.test/oauth2/signin".to_string(),
            token_cookie_domain: "example.test".to_string(),
            restricted_methods: vec!["POST".to_string(), "DELETE".to_string()],
            required_permissions: vec!["admin:access".to_string()],
            claims: vec!["sub".to_string(), "email".to_string()],
            return_to: "https://restricted.example.test".to_string(),
        }],
    }
}

/// Build the test app router.
fn build_test_app(config: AppConfig) -> Router {
    let state = AppState::new(config);
    Router::new()
        .route("/authorize", get(endpoints::authorize))
        .route("/signin", get(endpoints::signin))
        .route("/signout", get(endpoints::signout))
        .route("/userinfo", get(endpoints::userinfo))
        .route("/health", get(|| async { "OK" }))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            authenticate_middleware,
        ))
        .with_state(state)
}

// ==================== /health endpoint ====================

#[tokio::test]
async fn test_health_endpoint() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"OK");
}

// ==================== /authorize endpoint ====================

#[tokio::test]
async fn test_authorize_missing_forwarded_headers_returns_400() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_whitelisted_signin_url() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    // The redirect_uri itself (signin callback) should be whitelisted
    let response = app
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .header("x-forwarded-host", "www.example.test")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-uri", "/oauth2/signin?code=abc")
                .header("x-forwarded-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_authorize_unrestricted_method_grants_access() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());

    // For restricted.example.test, only POST and DELETE are restricted
    // So GET should be unrestricted and grant access
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .header("x-forwarded-host", "restricted.example.test")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-uri", "/some-page")
                .header("x-forwarded-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_authorize_restricted_method_anonymous_redirects() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    // All methods restricted by default - anonymous user should be redirected
    let response = app
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .header("x-forwarded-host", "www.example.test")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-uri", "/protected")
                .header("x-forwarded-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("/authorize"));
    assert!(location.contains("client_id=test-client-id"));
    assert!(location.contains("response_type=code"));

    // Should set AUTH_NONCE cookie
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(set_cookie.contains("AUTH_NONCE="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn test_authorize_api_request_returns_401_instead_of_redirect() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    // API request (Accept: application/json) should get 403 instead of redirect
    let response = app
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .header("x-forwarded-host", "www.example.test")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-uri", "/api/data")
                .header("x-forwarded-method", "GET")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Anonymous user with API content type should get denied
    assert!(
        response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn test_authorize_xhr_request_returns_denial() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .header("x-forwarded-host", "www.example.test")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-uri", "/api/data")
                .header("x-forwarded-method", "POST")
                .header("x-requested-with", "XMLHttpRequest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::UNAUTHORIZED
    );
}

// ==================== /signin endpoint ====================

#[tokio::test]
async fn test_signin_with_auth0_error() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/signin?error=unauthorized&error_description=Access+denied")
                .header("x-forwarded-host", "www.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_signin_missing_code_returns_error() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/signin")
                .header("x-forwarded-host", "www.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_signin_missing_state_returns_error() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/signin?code=abc123")
                .header("x-forwarded-host", "www.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_signin_nonce_mismatch_returns_error() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    // Create a valid state with a nonce
    let state = forwardauth_rs::domain::AuthorizeState {
        protocol: "https".to_string(),
        host: "www.example.test".to_string(),
        uri: "/protected".to_string(),
        method: "GET".to_string(),
        nonce: "correct-nonce".to_string(),
    };
    let encoded_state = state.encode();

    // Send with wrong nonce cookie
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/signin?code=abc123&state={}", encoded_state))
                .header("x-forwarded-host", "www.example.test")
                .header("cookie", "AUTH_NONCE=wrong-nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_signin_successful_exchange() {
    let mock_server = MockServer::start().await;

    // Mock the token endpoint
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "test-access-token",
            "id_token": "test-id-token",
            "token_type": "Bearer",
            "expires_in": 86400
        })))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let nonce = "test-nonce-123";
    let state = forwardauth_rs::domain::AuthorizeState {
        protocol: "https".to_string(),
        host: "www.example.test".to_string(),
        uri: "/protected/page".to_string(),
        method: "GET".to_string(),
        nonce: nonce.to_string(),
    };
    let encoded_state = state.encode();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/signin?code=valid-code&state={}", encoded_state))
                .header("x-forwarded-host", "www.example.test")
                .header("cookie", format!("AUTH_NONCE={}", nonce))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("www.example.test"));
    assert!(location.contains("/protected/page"));

    // Should set cookies
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();
    assert!(cookies.iter().any(|c| c.contains("ACCESS_TOKEN=")));
    assert!(cookies.iter().any(|c| c.contains("JWT_TOKEN=")));
    // Should clear nonce cookie
    assert!(cookies.iter().any(|c| c.contains("AUTH_NONCE=deleted")));
}

// ==================== /signout endpoint ====================

#[tokio::test]
async fn test_signout_requires_authentication() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/signout")
                .header("x-forwarded-host", "www.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ==================== /userinfo endpoint ====================

#[tokio::test]
async fn test_userinfo_requires_authentication() {
    let mock_server = MockServer::start().await;
    let config = test_config(&mock_server.uri());
    let app = build_test_app(config);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("x-forwarded-host", "www.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ==================== Cookie building tests ====================

#[test]
fn test_build_cookie_secure_domain() {
    let cookie = forwardauth_rs::endpoints::build_cookie("TEST", "value", "example.com", 3600, "/");
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(cookie.contains("Max-Age=3600"));
    assert!(cookie.contains("Domain=example.com"));
}

#[test]
fn test_build_cookie_localhost_no_secure() {
    let cookie = forwardauth_rs::endpoints::build_cookie("TEST", "value", "localhost", 3600, "/");
    assert!(!cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
}

#[test]
fn test_clear_cookie() {
    let cookie = forwardauth_rs::endpoints::clear_cookie("TEST", "example.com");
    assert!(cookie.contains("deleted"));
    assert!(cookie.contains("Max-Age=0"));
    assert!(cookie.contains("Secure"));
}

#[test]
fn test_clear_cookie_localhost() {
    let cookie = forwardauth_rs::endpoints::clear_cookie("TEST", "localhost");
    assert!(!cookie.contains("Secure"));
    assert!(cookie.contains("Max-Age=0"));
}

// ==================== Config tests ====================

#[test]
fn test_config_yaml_full() {
    let yaml = r#"
domain: https://test.auth0.com/
token-endpoint: https://test.auth0.com/oauth/token
authorize-url: https://test.auth0.com/authorize
userinfo-endpoint: https://test.auth0.com/userinfo
logout-endpoint: https://test.auth0.com/v2/logout
nonce-max-age: 120
default:
  name: default.test
  client-id: default-id
  client-secret: default-secret
  audience: https://api.test
  scope: "profile openid email"
  redirect-uri: https://default.test/oauth2/signin
  token-cookie-domain: test
  return-to: https://default.test
  claims:
    - sub
    - email
  required-permissions:
    - read:all
  restricted-methods:
    - POST
    - DELETE
apps:
  - name: app1.test
    audience: https://api.app1.test
  - name: app2.test
    client-id: app2-id
    client-secret: app2-secret
    scope: "openid"
    restricted-methods:
      - PUT
"#;
    let config = AppConfig::from_yaml(yaml).unwrap();
    assert_eq!(config.nonce_max_age, 120);

    // app1 should inherit from default
    let app1 = config.find_application_or_default(Some("app1.test"));
    assert_eq!(app1.client_id, "default-id");
    assert_eq!(app1.audience, "https://api.app1.test");
    assert_eq!(app1.claims, vec!["sub", "email"]);
    assert_eq!(app1.required_permissions, vec!["read:all"]);

    // app2 has its own values
    let app2 = config.find_application_or_default(Some("app2.test"));
    assert_eq!(app2.client_id, "app2-id");
    assert_eq!(app2.scope, "openid");
    assert_eq!(app2.restricted_methods, vec!["PUT"]);

    // Unknown host returns default
    let unknown = config.find_application_or_default(Some("unknown.test"));
    assert_eq!(unknown.name, "default.test");
}

#[test]
fn test_config_validation_empty_domain() {
    let yaml = r#"
domain: ""
token-endpoint: https://test.auth0.com/oauth/token
authorize-url: https://test.auth0.com/authorize
userinfo-endpoint: https://test.auth0.com/userinfo
logout-endpoint: https://test.auth0.com/v2/logout
default:
  name: test
"#;
    let result = AppConfig::from_yaml(yaml);
    assert!(result.is_err());
}

// ==================== Domain types tests ====================

#[test]
fn test_authorize_state_roundtrip() {
    let url = forwardauth_rs::domain::RequestedUrl {
        protocol: "https".to_string(),
        host: "test.example.com".to_string(),
        uri: "/path/to/resource?query=1&foo=bar".to_string(),
        method: "POST".to_string(),
    };
    let nonce = "randomnonce123";
    let state = forwardauth_rs::domain::AuthorizeState::new(&url, nonce);
    let encoded = state.encode();
    let decoded = forwardauth_rs::domain::AuthorizeState::decode(&encoded).unwrap();
    assert_eq!(decoded.protocol, "https");
    assert_eq!(decoded.host, "test.example.com");
    assert_eq!(decoded.uri, "/path/to/resource?query=1&foo=bar");
    assert_eq!(decoded.method, "POST");
    assert_eq!(decoded.nonce, "randomnonce123");
}

#[test]
fn test_jwt_token_client_credentials() {
    use forwardauth_rs::domain::{Audience, JwtClaims, JwtToken};
    use std::collections::HashMap;

    let token = JwtToken {
        raw: "test".to_string(),
        claims: JwtClaims {
            sub: "client@clients".to_string(),
            aud: Audience::Single("https://api.test".to_string()),
            iss: "test".to_string(),
            exp: 0,
            iat: 0,
            gty: Some("client-credentials".to_string()),
            permissions: None,
            email: None,
            name: None,
            nickname: None,
            picture: None,
            extra: HashMap::new(),
        },
    };

    assert!(token.is_client_credentials());
    assert!(!token.has_permission_claim());
    assert!(token.has_permission(&[])); // no required permissions = pass
}

#[test]
fn test_jwt_token_get_claim() {
    use forwardauth_rs::domain::{Audience, JwtClaims, JwtToken};
    use std::collections::HashMap;

    let mut extra = HashMap::new();
    extra.insert(
        "custom_claim".to_string(),
        serde_json::Value::String("custom_value".to_string()),
    );
    extra.insert("bool_claim".to_string(), serde_json::Value::Bool(true));
    extra.insert(
        "num_claim".to_string(),
        serde_json::Value::Number(42.into()),
    );

    let token = JwtToken {
        raw: "test".to_string(),
        claims: JwtClaims {
            sub: "user123".to_string(),
            aud: Audience::Single("test".to_string()),
            iss: "issuer".to_string(),
            exp: 0,
            iat: 0,
            gty: None,
            permissions: Some(vec!["read:data".to_string()]),
            email: Some("user@example.com".to_string()),
            name: Some("Test User".to_string()),
            nickname: Some("tester".to_string()),
            picture: Some("https://example.com/pic.jpg".to_string()),
            extra,
        },
    };

    assert_eq!(token.get_claim("sub"), Some("user123".to_string()));
    assert_eq!(
        token.get_claim("email"),
        Some("user@example.com".to_string())
    );
    assert_eq!(token.get_claim("name"), Some("Test User".to_string()));
    assert_eq!(token.get_claim("nickname"), Some("tester".to_string()));
    assert_eq!(
        token.get_claim("picture"),
        Some("https://example.com/pic.jpg".to_string())
    );
    assert_eq!(
        token.get_claim("custom_claim"),
        Some("custom_value".to_string())
    );
    assert_eq!(token.get_claim("bool_claim"), Some("true".to_string()));
    assert_eq!(token.get_claim("num_claim"), Some("42".to_string()));
    assert_eq!(token.get_claim("nonexistent"), None);
}

#[test]
fn test_requested_url_full_url() {
    let url = forwardauth_rs::domain::RequestedUrl {
        protocol: "HTTPS".to_string(),
        host: "WWW.EXAMPLE.COM".to_string(),
        uri: "/Path/To/Resource".to_string(),
        method: "GET".to_string(),
    };
    assert_eq!(url.full_url(), "https://www.example.com/path/to/resource");
}
