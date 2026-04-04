use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents different token types from Auth0
#[derive(Debug, Clone)]
pub enum Token {
    /// A valid JWT token that has been decoded and verified
    Jwt(Box<JwtToken>),
    /// An opaque token (not JWT format)
    Opaque(String),
    /// An invalid or expired token
    Invalid(String),
    /// No token was provided
    Empty,
}

/// A validated JWT token with its claims
#[derive(Debug, Clone)]
pub struct JwtToken {
    /// Raw token string
    pub raw: String,
    /// Decoded claims
    pub claims: JwtClaims,
}

/// JWT claims structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    #[serde(default)]
    pub sub: String,
    /// Audience
    #[serde(default)]
    pub aud: Audience,
    /// Issuer
    #[serde(default)]
    pub iss: String,
    /// Expiration time (unix timestamp)
    #[serde(default)]
    pub exp: u64,
    /// Issued at (unix timestamp)
    #[serde(default)]
    pub iat: u64,
    /// Grant type (e.g., "client-credentials")
    #[serde(default)]
    pub gty: Option<String>,
    /// Permissions
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
    /// Email
    #[serde(default)]
    pub email: Option<String>,
    /// Name
    #[serde(default)]
    pub name: Option<String>,
    /// Nickname
    #[serde(default)]
    pub nickname: Option<String>,
    /// Picture URL
    #[serde(default)]
    pub picture: Option<String>,
    /// Any additional claims
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Audience can be a single string or array of strings
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
    #[default]
    None,
}

impl Audience {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(s) => s == expected,
            Audience::Multiple(v) => v.iter().any(|s| s == expected),
            Audience::None => false,
        }
    }
}

impl JwtToken {
    /// Get subject claim
    pub fn subject(&self) -> &str {
        &self.claims.sub
    }

    /// Check if token has all required permissions
    pub fn has_permission(&self, required: &[String]) -> bool {
        if required.is_empty() {
            return true;
        }
        match &self.claims.permissions {
            Some(perms) => required.iter().all(|r| perms.iter().any(|p| p == r)),
            None => required.is_empty(),
        }
    }

    /// Check if token has the permissions claim at all
    pub fn has_permission_claim(&self) -> bool {
        self.claims.permissions.is_some()
    }

    /// Get list of missing permissions
    pub fn missing_permissions(&self, required: &[String]) -> Vec<String> {
        match &self.claims.permissions {
            Some(perms) => required
                .iter()
                .filter(|r| !perms.iter().any(|p| p == *r))
                .cloned()
                .collect(),
            None => required.to_vec(),
        }
    }

    /// Check if this is a client_credentials token
    pub fn is_client_credentials(&self) -> bool {
        self.claims.gty.as_deref() == Some("client-credentials")
    }

    /// Get permissions list
    pub fn permissions(&self) -> Vec<String> {
        self.claims.permissions.clone().unwrap_or_default()
    }

    /// Get a claim value by key
    pub fn get_claim(&self, key: &str) -> Option<String> {
        match key {
            "sub" => Some(self.claims.sub.clone()),
            "iss" => Some(self.claims.iss.clone()),
            "email" => self.claims.email.clone(),
            "name" => self.claims.name.clone(),
            "nickname" => self.claims.nickname.clone(),
            "picture" => self.claims.picture.clone(),
            other => self.claims.extra.get(other).and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Bool(b) => Some(b.to_string()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                serde_json::Value::Array(a) => Some(
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                _ => None,
            }),
        }
    }
}

/// Represents the authenticated user state
#[derive(Debug, Clone)]
pub enum User {
    /// An authenticated user with valid tokens
    Authenticated(Box<AuthenticatedUser>),
    /// An anonymous/unauthenticated user
    Anonymous,
}

/// An authenticated user with their tokens and info
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub access_token: JwtToken,
    pub id_token: Token,
    pub userinfo: HashMap<String, String>,
    pub sub: String,
    pub permissions: Vec<String>,
}

impl User {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, User::Authenticated(_))
    }

    pub fn subject(&self) -> &str {
        match self {
            User::Authenticated(u) => &u.sub,
            User::Anonymous => "anonymous",
        }
    }
}

/// Represents the requested URL from Traefik's forwarded headers
#[derive(Debug, Clone)]
pub struct RequestedUrl {
    pub protocol: String,
    pub host: String,
    pub uri: String,
    pub method: String,
}

impl RequestedUrl {
    pub fn full_url(&self) -> String {
        format!("{}://{}{}", self.protocol, self.host, self.uri).to_lowercase()
    }

    pub fn starts_with(&self, url: &str) -> bool {
        self.full_url().starts_with(&url.to_lowercase())
    }

    pub fn to_uri(&self) -> String {
        self.full_url()
    }
}

/// The state parameter encoded in the OAuth2 authorize redirect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeState {
    pub protocol: String,
    pub host: String,
    pub uri: String,
    pub method: String,
    pub nonce: String,
}

impl AuthorizeState {
    pub fn new(origin_url: &RequestedUrl, nonce: &str) -> Self {
        Self {
            protocol: origin_url.protocol.clone(),
            host: origin_url.host.clone(),
            uri: origin_url.uri.clone(),
            method: origin_url.method.clone(),
            nonce: nonce.to_string(),
        }
    }

    pub fn encode(&self) -> String {
        use base64::Engine;
        let json = serde_json::to_string(self).unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
    }

    pub fn decode(encoded: &str) -> Result<Self, anyhow::Error> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))?;
        let json = String::from_utf8(bytes)?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn origin_url(&self) -> String {
        format!("{}://{}{}", self.protocol, self.host, self.uri).to_lowercase()
    }
}

/// Result of authorization decision
#[derive(Debug)]
pub enum AuthorizeResult {
    /// User is authorized, access granted
    AccessGranted { user: User },
    /// User needs to authenticate - redirect to Auth0
    NeedRedirect {
        authorize_url: String,
        nonce: String,
        cookie_domain: String,
    },
    /// User is authenticated but lacks permissions
    AccessDenied { user: User, reason: String },
    /// An error occurred during authorization
    Error { reason: String },
}

/// Result of the signin callback
#[derive(Debug)]
pub enum SigninResult {
    /// Signin completed successfully
    Complete {
        access_token: String,
        id_token: String,
        expires_in: i64,
        redirect_to: String,
        cookie_domain: String,
    },
    /// An error occurred during signin
    Error { reason: String, description: String },
    /// An authentication error from Auth0 (returns 401)
    AuthError { reason: String, description: String },
    /// Nonce validation failed — redirect user to login to get a fresh nonce (#142)
    NonceFailed { origin_url: String },
}

/// Result of signout
#[derive(Debug)]
pub enum SignoutResult {
    /// Signout completed, redirect to URL
    Redirect {
        redirect_url: String,
        cookie_domain: String,
    },
    /// Signout completed, no redirect
    Complete { cookie_domain: String },
    /// Error during signout
    Error { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_contains() {
        let single = Audience::Single("https://api.test".to_string());
        assert!(single.contains("https://api.test"));
        assert!(!single.contains("https://other.test"));

        let multi = Audience::Multiple(vec![
            "https://api.test".to_string(),
            "https://other.test".to_string(),
        ]);
        assert!(multi.contains("https://api.test"));
        assert!(multi.contains("https://other.test"));
        assert!(!multi.contains("https://missing.test"));

        let none = Audience::None;
        assert!(!none.contains("anything"));
    }

    #[test]
    fn test_jwt_token_permissions() {
        let token = JwtToken {
            raw: "test".to_string(),
            claims: JwtClaims {
                sub: "user1".to_string(),
                aud: Audience::Single("test".to_string()),
                iss: "test".to_string(),
                exp: 0,
                iat: 0,
                gty: None,
                permissions: Some(vec!["read:foo".to_string(), "write:bar".to_string()]),
                email: None,
                name: None,
                nickname: None,
                picture: None,
                extra: HashMap::new(),
            },
        };

        assert!(token.has_permission(&["read:foo".to_string()]));
        assert!(token.has_permission(&["read:foo".to_string(), "write:bar".to_string()]));
        assert!(!token.has_permission(&["read:missing".to_string()]));
        assert!(token.has_permission_claim());
        assert_eq!(
            token.missing_permissions(&["read:foo".to_string(), "admin:all".to_string()]),
            vec!["admin:all".to_string()]
        );
    }

    #[test]
    fn test_authorize_state_encode_decode() {
        let url = RequestedUrl {
            protocol: "https".to_string(),
            host: "www.example.com".to_string(),
            uri: "/protected/page".to_string(),
            method: "GET".to_string(),
        };
        let nonce = uuid::Uuid::new_v4().to_string();
        let state = AuthorizeState::new(&url, &nonce);
        let encoded = state.encode();
        let decoded = AuthorizeState::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol, "https");
        assert_eq!(decoded.host, "www.example.com");
        assert_eq!(decoded.uri, "/protected/page");
        assert_eq!(decoded.nonce, nonce);
    }

    #[test]
    fn test_requested_url() {
        let url = RequestedUrl {
            protocol: "https".to_string(),
            host: "www.example.com".to_string(),
            uri: "/oauth2/signin".to_string(),
            method: "GET".to_string(),
        };
        assert!(url.starts_with("https://www.example.com/oauth2/signin"));
        assert!(url.starts_with("HTTPS://WWW.EXAMPLE.COM/oauth2/signin"));
        assert!(!url.starts_with("https://other.com"));
    }

    #[test]
    fn test_user_anonymous() {
        let user = User::Anonymous;
        assert!(!user.is_authenticated());
        assert_eq!(user.subject(), "anonymous");
    }
}
