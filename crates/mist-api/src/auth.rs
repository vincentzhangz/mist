//! Email+password auth: argon2 hashing and HS256 JWT issuance/verification.
//!
//! Hashing and verification run inside `spawn_blocking` so the memory-hard
//! argon2 computation never blocks the async runtime.

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims: subject is the login email, expiry is unix seconds.
#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

/// Token lifetime: 24 hours, in seconds.
const TOKEN_TTL_SECS: u64 = 24 * 60 * 60;

/// Insecure fallback secret, used only when `JWT_SECRET` is unset (dev only).
pub const DEV_JWT_SECRET: &str = "dev-secret-change-me";

/// Returns the HS256 signing secret from `JWT_SECRET`.
///
/// Falls back to an insecure dev default with a loud warning when unset.
/// The fallback keeps local development working; it must never be used with
/// real credentials.
#[must_use]
pub fn jwt_secret() -> String {
    match std::env::var("JWT_SECRET") {
        Ok(secret) if !secret.is_empty() => secret,
        _ => {
            tracing::warn!(
                "JWT_SECRET unset; using insecure dev default that must never be used in production"
            );
            DEV_JWT_SECRET.to_owned()
        }
    }
}

/// Argon2-hash `password`, off the async runtime.
///
/// # Errors
///
/// Returns an error if hashing fails or the blocking task fails to join.
pub async fn hash_password(password: &str) -> anyhow::Result<String> {
    let password = password.as_bytes().to_vec();
    tokio::task::spawn_blocking(move || {
        // Salt is generated automatically (getrandom) by `hash_password`.
        Argon2::default()
            .hash_password(&password)
            .map(|hash| hash.to_string())
            .map_err(|error| anyhow::anyhow!("argon2 hashing failed: {error}"))
    })
    .await
    .map_err(|error| anyhow::anyhow!("password hashing task failed: {error}"))?
}

/// Verify `password` against an argon2 `password_hash`, off the runtime.
///
/// Unparseable hashes simply do not verify; only a blocking-task failure is
/// an error, so this never fails on attacker-controlled input.
///
/// # Errors
///
/// Returns an error if the blocking task fails to join.
pub async fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    let password = password.as_bytes().to_vec();
    let password_hash = password_hash.to_owned();
    tokio::task::spawn_blocking(move || {
        let Ok(parsed) = PasswordHash::new(&password_hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(&password, &parsed)
            .is_ok()
    })
    .await
    .map_err(|error| anyhow::anyhow!("password verification task failed: {error}"))
}

/// Issue an HS256 JWT for `email`, valid for 24 hours.
///
/// # Errors
///
/// Returns an error if the system clock is unusable or encoding fails.
pub fn create_token(email: &str, secret: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system clock before epoch: {error}"))?;
    let claims = Claims {
        sub: email.to_owned(),
        exp: usize::try_from(now.as_secs().saturating_add(TOKEN_TTL_SECS)).unwrap_or(usize::MAX),
    };
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|error| anyhow::anyhow!("JWT encoding failed: {error}"))
}

/// Verify `token` signature and expiry, returning the subject email.
///
/// Returns `None` for any invalid, expired, or wrong-secret token.
#[must_use]
pub fn verify_token(token: &str, secret: &str) -> Option<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|data| data.claims.sub)
}
