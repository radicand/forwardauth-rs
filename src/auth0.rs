use crate::config::AppConfig;
use crate::domain::{JwtClaims, JwtToken, Token};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, trace, warn};

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

        // Check cache first
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
            self.cc_token_cache.invalidate(&cache_key).await;
        }

        debug!("Requesting client credentials token from Auth0");

        let body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": audience
        });

        let response = self
            .http
            .post(&self.config.token_endpoint)
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

        let cached = CachedToken {
            access_token: json.clone(),
            expires_at: now + expires_in,
        };
        self.cc_token_cache.insert(cache_key, cached).await;

        json.get("access_token")
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

        // Check verified token cache
        if let Some(cached_claims) = self.verified_token_cache.get(token).await {
            if !cached_claims.aud.contains(expected_audience) {
                return Token::Invalid(format!(
                    "Audience mismatch: expected {} but got {:?}",
                    expected_audience, cached_claims.aud
                ));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if cached_claims.exp > 0 && cached_claims.exp < now {
                self.verified_token_cache.invalidate(token).await;
                return Token::Invalid("Token has expired".to_string());
            }
            return Token::Jwt(Box::new(JwtToken {
                raw: token.to_string(),
                claims: cached_claims,
            }));
        }

        // Decode the header to get the kid
        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                warn!("Failed to decode JWT header: {}", e);
                return Token::Invalid(format!("Failed to decode JWT header: {}", e));
            }
        };

        let kid = match &header.kid {
            Some(k) => k.clone(),
            None => {
                warn!("JWT missing kid in header");
                return Token::Invalid("JWT missing kid in header".to_string());
            }
        };

        // Get JWKS keys
        let keys = match self.get_jwks_keys().await {
            Ok(k) => k,
            Err(e) => {
                error!("Failed to fetch JWKS: {}", e);
                return Token::Invalid(format!("Failed to fetch JWKS: {}", e));
            }
        };

        // Find matching key
        let key = match keys.iter().find(|k| k.kid.as_deref() == Some(&kid)) {
            Some(k) => k,
            None => {
                warn!("No matching JWKS key found for kid: {}", kid);
                return Token::Invalid(format!("No matching key for kid: {}", kid));
            }
        };

        // Build decoding key from JWKS
        let decoding_key = match (&key.n, &key.e) {
            (Some(n), Some(e)) => match DecodingKey::from_rsa_components(n, e) {
                Ok(dk) => dk,
                Err(e) => {
                    return Token::Invalid(format!("Failed to build RSA key: {}", e));
                }
            },
            _ => {
                return Token::Invalid("JWKS key missing RSA components".to_string());
            }
        };

        // Set up validation
        let alg = match header.alg {
            jsonwebtoken::Algorithm::RS256 => Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384 => Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512 => Algorithm::RS512,
            other => {
                return Token::Invalid(format!("Unsupported algorithm: {:?}", other));
            }
        };

        let mut validation = Validation::new(alg);
        // Auth0 tokens may have audience as string or array
        validation.set_audience(&[expected_audience]);
        validation.set_issuer(&[&self.config.domain]);
        // Allow some clock skew
        validation.leeway = 60;

        match decode::<JwtClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;

                // Verify audience
                if !claims.aud.contains(expected_audience) {
                    return Token::Invalid(format!(
                        "Audience mismatch: expected {}",
                        expected_audience
                    ));
                }

                // Cache the verified token
                self.verified_token_cache
                    .insert(token.to_string(), claims.clone())
                    .await;

                Token::Jwt(Box::new(JwtToken {
                    raw: token.to_string(),
                    claims,
                }))
            }
            Err(e) => {
                trace!("JWT validation failed: {}", e);
                Token::Invalid(format!("Token validation failed: {}", e))
            }
        }
    }

    /// Fetch JWKS keys from Auth0 (cached).
    async fn get_jwks_keys(&self) -> Result<Vec<JwksKey>, anyhow::Error> {
        let jwks_uri = format!("{}.well-known/jwks.json", self.config.domain);

        if let Some(cached) = self.jwks_cache.get(&jwks_uri).await {
            return Ok(cached);
        }

        debug!("Fetching JWKS from {}", jwks_uri);
        let response = self.http.get(&jwks_uri).send().await?;
        let jwks: JwksResponse = response.json().await?;

        self.jwks_cache.insert(jwks_uri, jwks.keys.clone()).await;

        Ok(jwks.keys)
    }
}
