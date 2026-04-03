mod authorize;
mod signin;
mod signout;
mod userinfo;

pub use authorize::authorize;
pub use signin::signin;
pub use signout::signout;
pub use userinfo::userinfo;

/// Helper to build a Set-Cookie header string.
pub fn build_cookie(name: &str, value: &str, domain: &str, max_age: i64, path: &str) -> String {
    let mut cookie = format!(
        "{}={}; Domain={}; Path={}; HttpOnly; SameSite=Lax",
        name, value, domain, path
    );
    if max_age >= 0 {
        cookie.push_str(&format!("; Max-Age={}", max_age));
    }
    // Use Secure flag for non-localhost domains
    if !domain.contains("localhost") && !domain.contains("127.0.0.1") {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Helper to build a cookie-clearing Set-Cookie header.
pub fn clear_cookie(name: &str, domain: &str) -> String {
    let mut cookie = format!(
        "{}=deleted; Domain={}; Path=/; HttpOnly; Max-Age=0; SameSite=Lax",
        name, domain
    );
    if !domain.contains("localhost") && !domain.contains("127.0.0.1") {
        cookie.push_str("; Secure");
    }
    cookie
}
