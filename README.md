# ForwardAuth-RS

[![CI](https://github.com/radicand/forwardauth-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/radicand/forwardauth-rs/actions/workflows/ci.yml)
[![Docker](https://github.com/radicand/forwardauth-rs/actions/workflows/docker.yml/badge.svg)](https://github.com/radicand/forwardauth-rs/actions/workflows/docker.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A high-performance forward authentication service for [Traefik](https://traefik.io/) with [Auth0](https://auth0.com/) / OIDC support, written in Rust. Drop-in replacement for [dniel/traefik-forward-auth0](https://github.com/dniel/traefik-forward-auth0).

## Why?

The original [traefik-forward-auth0](https://github.com/dniel/traefik-forward-auth0) is a JVM-based Spring Boot application that hasn't been actively maintained. This Rust rewrite provides:

- **Drop-in compatible** — same configuration format, same endpoints, same cookie names
- **Tiny footprint** — ~10MB Docker image vs ~200MB+ JVM image, ~5MB RSS vs ~200MB+
- **Fast startup** — milliseconds vs seconds
- **Modern security** — up-to-date dependencies, secure defaults, OWASP best practices

## Features

- Centralized auth-host mode for Traefik forward authentication
- Multiple application support with per-host configuration
- Auth0 Authorization Code flow with PKCE-ready architecture
- Client Credentials flow via Basic Auth header
- JWT token verification with JWKS key rotation support
- Permission-based access control via Auth0 API permissions
- Configurable HTTP method restrictions
- Claims forwarding as `x-forwardauth-*` headers
- CSRF protection via nonce cookies
- Secure cookie handling (HttpOnly, SameSite=Lax, Secure)
- JWKS and token caching for performance
- Health check endpoint

## Quick Start

### Docker

```bash
docker run -d \
  -p 8080:8080 \
  -v /path/to/application.yaml:/config/application.yaml:ro \
  ghcr.io/radicand/forwardauth-rs:latest
```

### Helm

```bash
helm install forwardauth ./helm/forwardauth \
  --set applicationYaml.domain=https://YOUR_TENANT.auth0.com/ \
  --set applicationYaml.token-endpoint=https://YOUR_TENANT.auth0.com/oauth/token \
  --set applicationYaml.authorize-url=https://YOUR_TENANT.auth0.com/authorize \
  --set applicationYaml.userinfo-endpoint=https://YOUR_TENANT.auth0.com/userinfo \
  --set applicationYaml.logout-endpoint=https://YOUR_TENANT.auth0.com/v2/logout
```

Or use a values file — see [helm/forwardauth/values.yaml](helm/forwardauth/values.yaml).

## Configuration

Configuration is loaded from a YAML file. Set `CONFIG_FILE` environment variable to specify the path (default: `/config/application.yaml`).

The configuration format is **fully compatible** with the original traefik-forward-auth0:

```yaml
domain: https://YOUR_TENANT.auth0.com/
token-endpoint: https://YOUR_TENANT.auth0.com/oauth/token
authorize-url: https://YOUR_TENANT.auth0.com/authorize
userinfo-endpoint: https://YOUR_TENANT.auth0.com/userinfo
logout-endpoint: https://YOUR_TENANT.auth0.com/v2/logout

default:
  name: www.example.com
  client-id: YOUR_CLIENT_ID
  client-secret: YOUR_CLIENT_SECRET
  audience: https://api.example.com
  scope: "profile openid email"
  redirect-uri: https://www.example.com/oauth2/signin
  token-cookie-domain: example.com
  return-to: https://www.example.com
  restricted-methods:
    - DELETE
    - GET
    - HEAD
    - OPTIONS
    - PATCH
    - POST
    - PUT
  required-permissions: []
  claims:
    - sub
    - name
    - email

apps:
  - name: admin.example.com
    audience: https://api.admin.example.com
    required-permissions:
      - admin:access
```

See [example/application.yaml](example/application.yaml) for a full example.

## Endpoints

| Endpoint     | Method | Description                                      |
|--------------|--------|--------------------------------------------------|
| `/authorize` | GET    | Main forward-auth endpoint (called by Traefik)   |
| `/signin`    | GET    | OAuth2 callback from Auth0                       |
| `/signout`   | GET    | Logout endpoint (clears cookies, calls Auth0)    |
| `/userinfo`  | GET    | Returns authenticated user info from Auth0       |
| `/health`    | GET    | Health check (returns 200 OK)                    |

### Response Codes

**`/authorize`**:
- `204 No Content` — Access granted (with `Authorization` and `x-forwardauth-*` headers)
- `307 Temporary Redirect` — Redirect to Auth0 for authentication
- `401 Unauthorized` — Authentication required (API requests)
- `403 Forbidden` — Insufficient permissions

## Traefik Configuration

### Traefik v2 (Docker labels)

```yaml
labels:
  - "traefik.http.middlewares.forwardauth.forwardauth.address=http://forwardauth:8080/authorize"
  - "traefik.http.middlewares.forwardauth.forwardauth.authResponseHeaders=Authorization,x-forwardauth-sub,x-forwardauth-email,x-forwardauth-name"
  - "traefik.http.middlewares.forwardauth.forwardauth.trustForwardHeader=true"
```

### Traefik v2 (Kubernetes IngressRoute)

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: forwardauth
spec:
  forwardAuth:
    address: http://forwardauth:80/authorize
    authResponseHeaders:
      - Authorization
      - x-forwardauth-sub
      - x-forwardauth-email
      - x-forwardauth-name
    trustForwardHeader: true
```

## Environment Variables

| Variable     | Default                      | Description              |
|--------------|------------------------------|--------------------------|
| `CONFIG_FILE`| `/config/application.yaml`   | Path to config file      |
| `PORT`       | `8080`                       | Server listen port       |
| `RUST_LOG`   | `info,forwardauth_rs=debug`  | Log level configuration  |

## Migration from traefik-forward-auth0

1. Use the same `application.yaml` configuration file
2. Replace the Docker image: `dniel/forwardauth` → `ghcr.io/radicand/forwardauth-rs`
3. The port is `8080` (same as original)
4. All endpoints and cookie names are identical

## Development

```bash
# Run tests
cargo test

# Run with example config
CONFIG_FILE=example/application.yaml cargo run

# Build release
cargo build --release

# Run clippy
cargo clippy -- -D warnings
```

## License

[GPL-3.0](LICENSE) — same as the original traefik-forward-auth0.

## Acknowledgments

This project is a Rust rewrite of [dniel/traefik-forward-auth0](https://github.com/dniel/traefik-forward-auth0), preserving full configuration and API compatibility.
