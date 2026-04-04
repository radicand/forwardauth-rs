---
name: forwardauth-rs
description: "Use when working on the forwardauth-rs repository: a high-performance Rust forward authentication service for Traefik with Auth0/OIDC support. USE FOR: adding features, fixing bugs, writing tests, understanding the codebase, modifying config handling, working on endpoints or JWT/JWKS logic, updating the Helm chart, or debugging authentication flows. Covers architecture, conventions, testing patterns, build/release workflow, and known gotchas."
---

# ForwardAuth-RS Repository Skill

## What This Project Is

`forwardauth-rs` is a drop-in Rust replacement for [dniel/traefik-forward-auth0](https://github.com/dniel/traefik-forward-auth0) — a JVM-based forward authentication middleware for Traefik that delegates auth to Auth0 / any OIDC provider. The Rust port is API-surface compatible (same config format, endpoints, cookie names) while being ~10MB vs 200MB+ and starting in milliseconds.

- **GitHub:** https://github.com/radicand/forwardauth-rs
- **Docker:** `ghcr.io/radicand/forwardauth-rs`
- **License:** GPL v3

---

## Architecture Overview

```
Traefik → GET /authorize  (every request, sets auth headers)
       → GET /signin     (OAuth2 callback from Auth0)
       → GET /signout    (clears cookies, calls Auth0 logout)
       → GET /userinfo   (returns claims JSON for authenticated user)
       → GET /health     (liveness probe)
```

### Request Lifecycle

1. Traefik sends every request to `/authorize` with `x-forwarded-host`, `x-forwarded-proto`, `x-forwarded-uri`, `x-forwarded-method`.
2. `authenticate_middleware` (`src/middleware.rs`) runs first: extracts cookies or Basic Auth, verifies tokens, attaches a `User` extension to the request.
3. The `authorize` handler checks the resolved `ApplicationConfig` rules and returns:
   - `204 No Content` — access granted; also forwards `Authorization: Bearer <access_token>` and `x-forwardauth-*` claim headers upstream
   - `307 Temporary Redirect` → Auth0 authorize URL (browser flows)
   - `401 Unauthorized` — unauthenticated API/XHR request (`Accept: application/json` or `X-Requested-With: XMLHttpRequest`)
   - `403 Forbidden` — authenticated but missing required permissions

### Authentication Flows

| Flow | Trigger | Outcome |
|---|---|---|
| Authorization Code | Browser hits protected resource without valid cookies | Redirect → Auth0 → `/signin` callback → cookies set |
| Client Credentials | `Authorization: Basic <base64(client_id:client_secret)>` header | Auth0 token exchange per request (cached) |
| Cookie resumption | `ACCESS_TOKEN` + `JWT_TOKEN` cookies present | Tokens verified against JWKS and cached |

---

## Repository Layout

```
src/
  main.rs          — Entry point, router setup, server startup
  lib.rs           — Public exports for integration tests
  config.rs        — AppConfig / ApplicationConfig deserialization + inheritance
  domain.rs        — Core types: Token, User, AuthorizeState, SigninResult, etc.
  auth0.rs         — Auth0Client: JWKS fetch/cache, token verification, token exchanges
  middleware.rs    — authenticate_middleware (axum middleware layer)
  state.rs         — AppState (shared across handlers)
  errors.rs        — Error types
  endpoints/
    authorize.rs   — /authorize handler + perform_authorization()
    signin.rs      — /signin OAuth2 callback handler
    signout.rs     — /signout handler
    userinfo.rs    — /userinfo handler
    mod.rs         — build_cookie() / clear_cookie() helpers

tests/
  integration_tests.rs — Full HTTP tests using wiremock for Auth0 mock

helm/forwardauth/   — Helm chart (values.yaml, templates/)
example/            — Sample application.yaml
Dockerfile          — Multi-stage Rust build, ~10MB final image
```

---

## Key Dependencies

| Crate | Purpose |
|---|---|
| `axum 0.8` | Async HTTP framework |
| `tokio` | Async runtime |
| `reqwest` | HTTP client for Auth0 API calls |
| `jsonwebtoken v10` | JWT decode/verify |
| `moka` | Async in-memory caching (JWKS, verified tokens, CC tokens) |
| `serde / serde_yaml` | Config deserialization |
| `config` | Layered config loading |
| `uuid` | Nonce generation |
| `base64` | State parameter encoding |
| `url` | URL percent-encoding |
| `anyhow` | Error handling |
| `tracing / tracing-subscriber` | Structured logging |
| `wiremock` | Auth0 mock server in integration tests |

---

## Configuration

Config file: `/config/application.yaml` (mounted in Docker). Compatible with the original Java project's YAML format.

```yaml
domain: https://YOUR_TENANT.auth0.com/        # trailing slash required
token-endpoint: https://YOUR_TENANT.auth0.com/oauth/token
authorize-url: https://YOUR_TENANT.auth0.com/authorize
userinfo-endpoint: https://YOUR_TENANT.auth0.com/userinfo
logout-endpoint: https://YOUR_TENANT.auth0.com/v2/logout
nonce-max-age: 60          # seconds; default 60

default:
  name: myapp.example.com  # matched against x-forwarded-host
  client-id: <Auth0 client ID>
  client-secret: <Auth0 client secret>
  audience: https://api.example.com
  scope: "profile openid email"
  redirect-uri: https://myapp.example.com/oauth2/signin
  token-cookie-domain: example.com
  return-to: https://myapp.example.com
  claims:                  # claims forwarded as x-forwardauth-* headers
    - sub
    - email
    - name
  restricted-methods:      # HTTP methods that require auth (default: all)
    - GET
    - POST
    - PUT
    - DELETE
    - PATCH
    - HEAD
    - OPTIONS
  required-permissions: [] # Auth0 API permissions required

apps:                      # per-host overrides; inherits from default
  - name: admin.example.com
    required-permissions:
      - admin:access
```

**Inheritance:** Any omitted field in an `apps` entry is inherited from `default`. An unrecognized host also falls back to `default`.

---

## Cookie Names (Unchanged From Original)

| Cookie | Contents | Notes |
|---|---|---|
| `ACCESS_TOKEN` | Raw JWT access token | Verified against JWKS on every request |
| `JWT_TOKEN` | Raw JWT id token | Used for claim extraction |
| `AUTH_NONCE` | Random nonce UUID | Set on redirect to Auth0; cleared after signin |

Cookies are set with `HttpOnly; SameSite=Lax; Secure` (Secure omitted for localhost). `Domain` and `Max-Age` are configurable.

---

## Caching

Three `moka` caches in `Auth0Client`:

| Cache | Key | TTL |
|---|---|---|
| `jwks_cache` | JWKS URI | 1 hour |
| `verified_token_cache` | Raw token string | 15 minutes |
| `cc_token_cache` | `client_id:secret:audience` | Token's `expires_in` |

JWKS is re-fetched automatically on cache miss. If a token isn't in the verified cache it goes through full RSA/JWKS verification.

---

## Testing

```bash
cargo test                    # all tests (11 unit + 24 integration, ~0.03s)
cargo test <test_name>        # single test
cargo test -- --nocapture     # show logs
```

**Pattern for integration tests:**
1. Start a `wiremock::MockServer` (mock Auth0)
2. Call `test_config(&mock_server.uri())` to build config pointing at it
3. Call `build_test_app(config)` → `Router`
4. Use `tower::ServiceExt::oneshot()` to send a single request
5. Assert on `StatusCode` and headers

Example:
```rust
#[tokio::test]
async fn test_authorize_anonymous_redirects() {
    let mock_server = MockServer::start().await;
    let app = build_test_app(test_config(&mock_server.uri()));
    let response = app.oneshot(
        Request::builder()
            .uri("/authorize")
            .header("x-forwarded-host", "www.example.test")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-uri", "/protected")
            .header("x-forwarded-method", "GET")
            .body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
}
```

---

## Build & CI

```bash
cargo build                   # dev build
cargo build --release         # release binary
cargo fmt --check             # format check (enforced in CI + pre-commit hook)
cargo clippy -- -D warnings   # lint (enforced in CI)
cargo test                    # run all tests
```

**Pre-commit hook** (`.git/hooks/pre-commit`): runs `cargo fmt --check` + `cargo clippy` automatically before each commit. It is not committed to the repo (lives in `.git/`) — new contributors must be aware they may need to run `cargo fmt` before committing.

**GitHub Actions workflows:**
- `ci.yml` — fmt check, clippy, tests on every push/PR
- `docker.yml` — builds and pushes multi-arch Docker image (`linux/amd64`, `linux/arm64`) to GHCR
- `release.yml` — triggered by version tags; creates GitHub Release

**Docker image:** requires Rust ≥ 1.88 (time crate constraint). Base image: `rust:1-slim` for build, `debian:bookworm-slim` for runtime.

---

## Known Issues & Bugs Fixed

Issues from the upstream Java repo that were audited and resolved in this port:

| Upstream Issue | Description | Status in This Port |
|---|---|---|
| #124 | Sub mismatch between access_token and id_token (impersonation) | Fixed: middleware verifies sub fields match |
| #142 | Nonce mismatch shows 400 error, user stuck | Fixed: redirects to origin URL to restart login |
| #54 | Auth0 error=unauthorized returns wrong status | Fixed: returns 401 |
| #128 | Anonymous API requests get 403 instead of 401 | Fixed: returns 401 for unauthenticated requests |
| #154/#323 | NullPointerException on missing headers/cookies | N/A: Rust Option types |
| #136 | Headers with `_` dropped by Traefik | N/A: we convert `_` → `-` in header names |
| #141 | ClassCastException for anonymous users | N/A: Rust enum pattern matching |

---

## Common Gotchas

- **`domain` must have a trailing slash** — JWKS URI is built as `{domain}.well-known/jwks.json`. A missing slash breaks JWKS fetching silently.
- **Auth0 access tokens must be JWTs** — Opaque tokens cannot be verified. Set an API audience in Auth0 to ensure JWT format.
- **Cookie domain vs token cookie domain** — `token-cookie-domain` in config sets the `Domain=` attribute on cookies. Make sure it matches the TLD shared by your services (e.g., `example.com` not `app.example.com` if you have multiple subdomains).
- **`restricted-methods` defaults to all methods** — If you only want POST/DELETE to require auth (read-only public), explicitly set the list in the app config.
- **Claims are forwarded as `x-forwardauth-<claim>` with `_` replaced by `-`** — e.g., `given_name` becomes `x-forwardauth-given-name`. Configure Traefik's `authResponseHeaders` accordingly.
- **`required-permissions` needs "Add Permissions in Access Token" enabled in Auth0** — Go to API > Settings > Enable RBAC > Add Permissions in the Access Token. Without this, the permissions claim is absent and all requests are denied.
- **JWKS key rotation** — The JWKS cache TTL is 1 hour. After rotating keys in Auth0, existing cached tokens remain valid for up to 15 minutes (verified_token_cache TTL), and new tokens will pick up the refreshed JWKS within 1 hour on the next cache miss.
