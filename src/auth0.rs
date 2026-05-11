use crate::config::AppConfig;
use crate::domain::{JwtClaims, JwtToken, Token};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Once};
use std::time::Duration;
use tracing::{debug, error, trace, warn};

static INSTALL_JWT_CRYPTO_PROVIDER: Once = Once::new();

fn ensure_jwt_crypto_provider() {
    INSTALL_JWT_CRYPTO_PROVIDER.call_once(|| {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

/// JWKS key structure
#[derive(Debug, Clone, Deserialize)]
pub struct JwksKey {
    pub kty: String,
    pub kid: Option<String>,
    pub r#use: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub alg: Option<String>,
    pub x5c: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwksKey>,
}

/// Auth0 client for interacting with Auth0 HTTP APIs.
#[derive(Clone)]
pub struct Auth0Client {
    http: Client,
    config: Arc<AppConfig>,
    /// Cache for JWKS keys
    jwks_cache: Cache<String, Vec<JwksKey>>,
    /// Cache for client credentials tokens
    cc_token_cache: Cache<String, CachedToken>,
    /// Cache for already-verified JWT tokens
    verified_token_cache: Cache<String, JwtClaims>,
}

#[derive(Debug, Clone)]
pub struct CachedToken {
    pub access_token: serde_json::Value,
    pub expires_at: u64,
}

/// Response from Auth0 token endpoint
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl Auth0Client {
    pub fn new(config: Arc<AppConfig>) -> Self {
        ensure_jwt_crypto_provider();

        // Use a client that doesn't follow redirects for signout
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            http,
            config,
            jwks_cache: Cache::builder()
                .time_to_live(Duration::from_secs(3600))
                .max_capacity(10)
                .build(),
            cc_token_cache: Cache::builder()
                .time_to_live(Duration::from_secs(86400))
                .max_capacity(100)
                .build(),
            verified_token_cache: Cache::builder()
                .time_to_live(Duration::from_secs(900)) // 15 min
                .max_capacity(10000)
                .build(),
        }
    }

    /// Exchange authorization code for tokens.
    pub async fn authorization_code_exchange(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, anyhow::Error> {
        debug!("Performing authorization code exchange");

        let body = serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
            "scope": "openid id_token"
        });

        let response = self
            .http
            .post(&self.config.token_endpoint)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        let token_resp: TokenResponse = response.json().await?;

        if let Some(err) = &token_resp.error {
            let desc = token_resp
                .error_description
                .as_deref()
                .unwrap_or("Unknown error");
            return Err(anyhow::anyhow!("Auth0 error: {} - {}", err, desc));
        }

        Ok(token_resp)
    }

    /// Exchange client credentials for an access token (with caching).
    pub async fn client_credentials_exchange(
        &self,
        client_id: &str,
        client_secret: &str,
        audience: &str,
    ) -> Result<String, anyhow::Error> {
        let cache_key = format!("{}:{}:{}", client_id, client_secret, audience);

        // Check cache first for a still-valid token
        if let Some(cached) = self.cc_token_cache.get(&cache_key).await {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now < cached.expires_at {
                debug!("Using cached client credentials token");
                return cached
                    .access_token
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| anyhow::anyhow!("Cached token missing access_token field"));
            }
            // Token has expired; evict before re-fetching so try_get_with below
            // doesn't return the stale entry to other concurrent callers.
            self.cc_token_cache.invalidate(&cache_key).await;
        }

        // Use try_get_with to ensure only one concurrent HTTP request is made
        // when the cache is empty or has just been invalidated.
        let http = self.http.clone();
        let token_endpoint = self.config.token_endpoint.clone();
        let client_id_owned = client_id.to_string();
        let client_secret_owned = client_secret.to_string();
        let audience_owned = audience.to_string();

        let cached = self
            .cc_token_cache
            .try_get_with(cache_key, async move {
                debug!("Requesting client credentials token from Auth0");

                let body = serde_json::json!({
                    "grant_type": "client_credentials",
                    "client_id": client_id_owned,
                    "client_secret": client_secret_owned,
                    "audience": audience_owned
                });

                let response = http
                    .post(&token_endpoint)
                    .header("content-type", "application/json")
                    .json(&body)
                    .send()
                    .await?;

                let json: serde_json::Value = response.json().await?;

                if let Some(err) = json.get("error").and_then(|e| e.as_str()) {
                    let desc = json
                        .get("error_description")
                        .and_then(|e| e.as_str())
                        .unwrap_or("Unknown error");
                    return Err(anyhow::anyhow!("Auth0 error: {} - {}", err, desc));
                }

                let expires_in = json
                    .get("expires_in")
                    .and_then(|e| e.as_u64())
                    .unwrap_or(3600);

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                Ok(CachedToken {
                    access_token: json,
                    expires_at: now + expires_in,
                })
            })
            .await
            .map_err(|e: std::sync::Arc<anyhow::Error>| anyhow::anyhow!("{}", e))?;

        cached
            .access_token
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Missing access_token in response"))
    }

    /// Call Auth0 sign out endpoint.
    pub async fn signout(
        &self,
        client_id: &str,
        return_to: &str,
    ) -> Result<Option<String>, anyhow::Error> {
        debug!("Performing signout");

        let no_redirect_client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;

        let response = no_redirect_client
            .get(&self.config.logout_endpoint)
            .query(&[("client_id", client_id), ("returnTo", return_to)])
            .send()
            .await?;

        let status = response.status();
        trace!("Signout response status: {}", status);

        match status.as_u16() {
            302 => {
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                Ok(location)
            }
            400 => Err(anyhow::anyhow!(
                "Invalid arguments for signout, check configuration"
            )),
            _ => Ok(None),
        }
    }

    /// Call Auth0 userinfo endpoint.
    pub async fn userinfo(
        &self,
        access_token: &str,
    ) -> Result<HashMap<String, serde_json::Value>, anyhow::Error> {
        debug!("Fetching userinfo from Auth0");

        let response = self
            .http
            .get(&self.config.userinfo_endpoint)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Userinfo request failed with status: {}",
                response.status()
            ));
        }

        let userinfo: HashMap<String, serde_json::Value> = response.json().await?;
        Ok(userinfo)
    }

    /// Verify and decode a JWT token.
    pub async fn verify_token(&self, token: &str, expected_audience: &str) -> Token {
        if token.is_empty() {
            return Token::Empty;
        }

        // Check if it's an opaque token (not JWT format)
        if token.split('.').count() != 3 {
            return Token::Opaque(token.to_string());
        }

        // Use try_get_with to deduplicate concurrent verifications of the same token.
        // moka ensures only one init future runs per key; others wait and share the result.
        let self_clone = self.clone();
        let token_owned = token.to_string();
        let audience_owned = expected_audience.to_string();

        let result = self
            .verified_token_cache
            .try_get_with(token.to_string(), async move {
                self_clone
                    .verify_jwt_uncached(&token_owned, &audience_owned)
                    .await
            })
            .await
            .map_err(|e: std::sync::Arc<anyhow::Error>| anyhow::anyhow!("{}", e));

        match result {
            Ok(cached_claims) => {
                // The cache key is the raw token string, not token+audience, so we
                // must re-check the audience on every retrieval.
                if !cached_claims.aud.contains(expected_audience) {
                    return Token::Invalid(format!(
                        "Audience mismatch: expected {} but got {:?}",
                        expected_audience, cached_claims.aud
                    ));
                }
                // Evict and reject tokens that expired while sitting in the cache.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if cached_claims.exp > 0 && cached_claims.exp < now {
                    self.verified_token_cache.invalidate(token).await;
                    return Token::Invalid("Token has expired".to_string());
                }
                Token::Jwt(Box::new(JwtToken {
                    raw: token.to_string(),
                    claims: cached_claims,
                }))
            }
            Err(e) => {
                trace!("JWT validation failed: {}", e);
                Token::Invalid(e.to_string())
            }
        }
    }

    /// Perform full JWT verification without consulting the cache.
    /// Called exclusively from the `try_get_with` closure in `verify_token`.
    async fn verify_jwt_uncached(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<JwtClaims, anyhow::Error> {
        // Decode the header to get the kid
        let header = decode_header(token).map_err(|e| {
            warn!("Failed to decode JWT header: {}", e);
            anyhow::anyhow!("Failed to decode JWT header: {}", e)
        })?;

        let kid = header.kid.ok_or_else(|| {
            warn!("JWT missing kid in header");
            anyhow::anyhow!("JWT missing kid in header")
        })?;

        // Get JWKS keys (deduplicated fetch via try_get_with in get_jwks_keys)
        let keys = self.get_jwks_keys().await.map_err(|e| {
            error!("Failed to fetch JWKS: {}", e);
            e
        })?;

        // Find matching key
        let key = keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(&kid))
            .ok_or_else(|| {
                warn!("No matching JWKS key found for kid: {}", kid);
                anyhow::anyhow!("No matching key for kid: {}", kid)
            })?;

        // Build decoding key from JWKS
        let decoding_key = match (&key.n, &key.e) {
            (Some(n), Some(e)) => DecodingKey::from_rsa_components(n, e)
                .map_err(|e| anyhow::anyhow!("Failed to build RSA key: {}", e))?,
            _ => return Err(anyhow::anyhow!("JWKS key missing RSA components")),
        };

        // Set up validation
        let alg = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            other => return Err(anyhow::anyhow!("Unsupported algorithm: {:?}", other)),
        };

        let mut validation = Validation::new(alg);
        // Auth0 tokens may have audience as string or array
        validation.set_audience(&[expected_audience]);
        validation.set_issuer(&[&self.config.domain]);
        // Allow some clock skew
        validation.leeway = 60;

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
            trace!("JWT validation failed: {}", e);
            anyhow::anyhow!("Token validation failed: {}", e)
        })?;

        let claims = token_data.claims;

        // Final audience check (belt-and-suspenders after jsonwebtoken validates)
        if !claims.aud.contains(expected_audience) {
            return Err(anyhow::anyhow!(
                "Audience mismatch: expected {}",
                expected_audience
            ));
        }

        Ok(claims)
    }

    /// Fetch JWKS keys from Auth0 (cached).
    ///
    /// Uses `try_get_with` so that when the 1-hour TTL fires under concurrent
    /// traffic, only one HTTP request is issued; all other callers await that
    /// single in-flight request instead of each firing their own.
    async fn get_jwks_keys(&self) -> Result<Vec<JwksKey>, anyhow::Error> {
        let jwks_uri = self
            .config
            .jwks_url
            .clone()
            .unwrap_or_else(|| format!("{}.well-known/jwks.json", self.config.domain));
        let http = self.http.clone();
        let uri_for_log = jwks_uri.clone();

        self.jwks_cache
            .try_get_with(jwks_uri.clone(), async move {
                debug!("Fetching JWKS from {}", uri_for_log);
                let response = http.get(&jwks_uri).send().await?;
                let jwks: JwksResponse = response.json().await?;
                Ok::<Vec<JwksKey>, anyhow::Error>(jwks.keys)
            })
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))
    }
}
