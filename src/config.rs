use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

/// Top-level configuration matching the original application.yaml format.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppConfig {
    /// Auth0 domain URL (e.g., https://xxx.auth0.com/)
    pub domain: String,
    /// Optional JWKS URI override. When set, used instead of the default
    /// `{domain}/.well-known/jwks.json` construction. Useful for providers
    /// like authentik where the JWKS URI differs from the Auth0 convention.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Auth0 token endpoint (e.g., https://xxx.auth0.com/oauth/token)
    pub token_endpoint: String,
    /// Auth0 authorize URL (e.g., https://xxx.auth0.com/authorize)
    pub authorize_url: String,
    /// Auth0 userinfo endpoint (e.g., https://xxx.auth0.com/userinfo)
    pub userinfo_endpoint: String,
    /// Auth0 logout endpoint (e.g., https://xxx.auth0.com/v2/logout)
    pub logout_endpoint: String,
    /// Max age for nonce cookie in seconds (default: 60)
    #[serde(default = "default_nonce_max_age")]
    pub nonce_max_age: i64,
    /// Server port (default: 8080)
    #[serde(default = "default_port")]
    pub port: u16,
    /// Default application configuration
    pub default: ApplicationConfig,
    /// List of application-specific configurations
    #[serde(default)]
    pub apps: Vec<ApplicationConfig>,
}

/// Per-application configuration that can inherit from default.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ApplicationConfig {
    /// Application name, matched against x-forwarded-host
    pub name: String,
    /// Auth0 client ID
    #[serde(default)]
    pub client_id: String,
    /// Auth0 client secret
    #[serde(default)]
    pub client_secret: String,
    /// Auth0 API audience
    #[serde(default)]
    pub audience: String,
    /// OAuth2 scopes
    #[serde(default = "default_scope")]
    pub scope: String,
    /// OAuth2 redirect URI (callback)
    #[serde(default)]
    pub redirect_uri: String,
    /// Cookie domain for tokens
    #[serde(default)]
    pub token_cookie_domain: String,
    /// HTTP methods that require authentication
    #[serde(default = "default_restricted_methods")]
    pub restricted_methods: Vec<String>,
    /// Required Auth0 API permissions
    #[serde(default)]
    pub required_permissions: Vec<String>,
    /// Claims to forward from ID token
    #[serde(default)]
    pub claims: Vec<String>,
    /// URL to redirect to after signout
    #[serde(default)]
    pub return_to: String,
}

fn default_nonce_max_age() -> i64 {
    60
}

fn default_port() -> u16 {
    8080
}

fn default_scope() -> String {
    "profile openid email".to_string()
}

fn default_restricted_methods() -> Vec<String> {
    vec![
        "DELETE".to_string(),
        "GET".to_string(),
        "HEAD".to_string(),
        "OPTIONS".to_string(),
        "PATCH".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
    ]
}

impl AppConfig {
    /// Load configuration from a YAML file path.
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::from(path.as_ref()))
            .build()?;
        let config: AppConfig = settings.try_deserialize()?;
        config.validate()?;
        Ok(config)
    }

    /// Load from a YAML string (useful for testing).
    pub fn from_yaml(yaml: &str) -> anyhow::Result<Self> {
        let config: AppConfig = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.domain.is_empty() {
            anyhow::bail!("domain is required");
        }
        if self.token_endpoint.is_empty() {
            anyhow::bail!("token-endpoint is required");
        }
        if self.authorize_url.is_empty() {
            anyhow::bail!("authorize-url is required");
        }
        if self.userinfo_endpoint.is_empty() {
            anyhow::bail!("userinfo-endpoint is required");
        }
        if self.logout_endpoint.is_empty() {
            anyhow::bail!("logout-endpoint is required");
        }
        if self.default.name.is_empty() {
            anyhow::bail!("default.name is required");
        }

        // Validate that all OIDC endpoints belong to the configured domain
        // to prevent server-side request forgery via misconfiguration.
        let domain_url =
            Url::parse(&self.domain).map_err(|e| anyhow::anyhow!("invalid domain URL: {}", e))?;
        let domain_host = domain_url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("domain URL must have a host"))?;

        for (name, endpoint) in [
            ("token-endpoint", &self.token_endpoint),
            ("authorize-url", &self.authorize_url),
            ("userinfo-endpoint", &self.userinfo_endpoint),
            ("logout-endpoint", &self.logout_endpoint),
        ] {
            let ep_url = Url::parse(endpoint)
                .map_err(|e| anyhow::anyhow!("{} is not a valid URL: {}", name, e))?;
            let ep_host = ep_url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("{} must have a host", name))?;
            if ep_host != domain_host {
                anyhow::bail!(
                    "{} host '{}' does not match domain host '{}'",
                    name,
                    ep_host,
                    domain_host
                );
            }
        }

        Ok(())
    }

    /// Find application config by hostname, or return default with inherited values.
    pub fn find_application_or_default(&self, name: Option<&str>) -> ApplicationConfig {
        let name = match name {
            Some(n) => n,
            None => return self.default.clone(),
        };

        match self.apps.iter().find(|a| a.name.eq_ignore_ascii_case(name)) {
            Some(app) => {
                let mut resolved = app.clone();
                // Inherit from default for any empty fields
                if resolved.return_to.is_empty() {
                    resolved.return_to = self.default.return_to.clone();
                }
                if resolved.redirect_uri.is_empty() {
                    resolved.redirect_uri = self.default.redirect_uri.clone();
                }
                if resolved.audience.is_empty() {
                    resolved.audience = self.default.audience.clone();
                }
                if resolved.scope.is_empty() {
                    resolved.scope = self.default.scope.clone();
                }
                if resolved.client_id.is_empty() {
                    resolved.client_id = self.default.client_id.clone();
                }
                if resolved.client_secret.is_empty() {
                    resolved.client_secret = self.default.client_secret.clone();
                }
                if resolved.token_cookie_domain.is_empty() {
                    resolved.token_cookie_domain = self.default.token_cookie_domain.clone();
                }
                if resolved.restricted_methods.is_empty() {
                    resolved.restricted_methods = self.default.restricted_methods.clone();
                }
                if resolved.claims.is_empty() {
                    resolved.claims = self.default.claims.clone();
                }
                if resolved.required_permissions.is_empty() {
                    resolved.required_permissions = self.default.required_permissions.clone();
                }
                resolved
            }
            None => self.default.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AppConfig {
        AppConfig {
            domain: "https://test.auth0.com/".to_string(),
            token_endpoint: "https://test.auth0.com/oauth/token".to_string(),
            authorize_url: "https://test.auth0.com/authorize".to_string(),
            userinfo_endpoint: "https://test.auth0.com/userinfo".to_string(),
            logout_endpoint: "https://test.auth0.com/v2/logout".to_string(),
            nonce_max_age: 60,
            port: 8080,
            default: ApplicationConfig {
                name: "example.test".to_string(),
                client_id: "default-client-id".to_string(),
                client_secret: "default-client-secret".to_string(),
                audience: "https://api.example.test".to_string(),
                scope: "profile openid email".to_string(),
                redirect_uri: "http://www.example.test/oauth2/signin".to_string(),
                token_cookie_domain: "example.test".to_string(),
                restricted_methods: default_restricted_methods(),
                required_permissions: vec![],
                claims: vec!["sub".to_string(), "name".to_string(), "email".to_string()],
                return_to: "https://www.example.test".to_string(),
            },
            apps: vec![
                ApplicationConfig {
                    name: "www.example.test".to_string(),
                    client_id: "www-client-id".to_string(),
                    client_secret: "www-client-secret".to_string(),
                    audience: "https://api.example.test".to_string(),
                    scope: "profile openid email".to_string(),
                    redirect_uri: "http://www.example.test/oauth2/signin".to_string(),
                    token_cookie_domain: "example.test".to_string(),
                    restricted_methods: vec![
                        "DELETE".to_string(),
                        "PUT".to_string(),
                        "PATCH".to_string(),
                        "POST".to_string(),
                    ],
                    required_permissions: vec!["read:whoami".to_string()],
                    claims: vec!["sub".to_string(), "name".to_string(), "email".to_string()],
                    return_to: "http://www.example.test".to_string(),
                },
                ApplicationConfig {
                    name: "traefik.example.test".to_string(),
                    client_id: "".to_string(),
                    client_secret: "".to_string(),
                    audience: "https://traefik.api.example.test".to_string(),
                    scope: "".to_string(),
                    redirect_uri: "".to_string(),
                    token_cookie_domain: "".to_string(),
                    restricted_methods: vec![],
                    required_permissions: vec![],
                    claims: vec![],
                    return_to: "".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_find_exact_app() {
        let config = test_config();
        let app = config.find_application_or_default(Some("www.example.test"));
        assert_eq!(app.client_id, "www-client-id");
        assert_eq!(app.audience, "https://api.example.test");
    }

    #[test]
    fn test_find_app_case_insensitive() {
        let config = test_config();
        let app = config.find_application_or_default(Some("WWW.EXAMPLE.TEST"));
        assert_eq!(app.client_id, "www-client-id");
    }

    #[test]
    fn test_find_app_inherits_from_default() {
        let config = test_config();
        let app = config.find_application_or_default(Some("traefik.example.test"));
        // Should inherit from default
        assert_eq!(app.client_id, "default-client-id");
        assert_eq!(app.client_secret, "default-client-secret");
        assert_eq!(app.token_cookie_domain, "example.test");
        // Should use its own value
        assert_eq!(app.audience, "https://traefik.api.example.test");
    }

    #[test]
    fn test_find_unknown_returns_default() {
        let config = test_config();
        let app = config.find_application_or_default(Some("unknown.host.com"));
        assert_eq!(app.name, "example.test");
        assert_eq!(app.client_id, "default-client-id");
    }

    #[test]
    fn test_find_none_returns_default() {
        let config = test_config();
        let app = config.find_application_or_default(None);
        assert_eq!(app.name, "example.test");
    }

    #[test]
    fn test_from_yaml() {
        let yaml = r#"
domain: https://test.auth0.com/
token-endpoint: https://test.auth0.com/oauth/token
authorize-url: https://test.auth0.com/authorize
userinfo-endpoint: https://test.auth0.com/userinfo
logout-endpoint: https://test.auth0.com/v2/logout
default:
  name: example.test
  client-id: my-client-id
  client-secret: my-secret
  audience: https://api.example.test
  redirect-uri: http://www.example.test/oauth2/signin
  token-cookie-domain: example.test
apps:
  - name: www.example.test
    audience: https://api.www.example.test
"#;
        let config = AppConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.domain, "https://test.auth0.com/");
        assert_eq!(config.default.client_id, "my-client-id");
        assert_eq!(config.nonce_max_age, 60); // default
        let app = config.find_application_or_default(Some("www.example.test"));
        assert_eq!(app.audience, "https://api.www.example.test");
        assert_eq!(app.client_id, "my-client-id"); // inherited
    }
}
