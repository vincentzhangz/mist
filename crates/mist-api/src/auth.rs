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

/// Reads the HS256 signing secret from `JWT_SECRET`.
///
/// Fails closed: the API refuses to start without an explicit secret, so a
/// missing Secret/env can never silently mint dev-signed tokens. Local runs
/// just export any value (`JWT_SECRET=dev cargo run -p mist-api`).
///
/// # Errors
///
/// Returns an error when `JWT_SECRET` is unset or empty.
pub fn jwt_secret() -> anyhow::Result<String> {
    std::env::var("JWT_SECRET")
        .map_err(|_| anyhow::anyhow!("JWT_SECRET must be set"))
        .and_then(|secret| {
            if secret.is_empty() {
                Err(anyhow::anyhow!("JWT_SECRET must not be empty"))
            } else {
                Ok(secret)
            }
        })
}

/// Reads one comma-separated value into trimmed, non-empty tokens.
fn split_tokens(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Reads the accepted agent ingest tokens: `INGEST_TOKEN` plus every entry
/// of comma-separated `INGEST_TOKENS`.
///
/// An empty set keeps `/api/ingest` open with a loud startup warning (dev
/// default); otherwise every ingest batch needs `Authorization: Bearer`
/// with one of these tokens. Multiple entries enable rotation (add the new
/// token, roll the agents, remove the old one) and per-agent tokens.
/// Provision high-entropy values anywhere shared.
#[must_use]
pub fn ingest_tokens() -> Vec<String> {
    let mut tokens = std::env::var("INGEST_TOKEN")
        .ok()
        .map(|value| split_tokens(&value))
        .unwrap_or_default();
    if let Ok(extra) = std::env::var("INGEST_TOKENS") {
        tokens.extend(split_tokens(&extra));
    }
    tokens.sort();
    tokens.dedup();
    if tokens.is_empty() {
        tracing::warn!(
            "INGEST_TOKEN/INGEST_TOKENS unset; /api/ingest accepts unauthenticated batches — provision a token anywhere shared"
        );
    }
    tokens
}

/// Dummy argon2id hash (for "s3cret", argon2 0.5.3 parameters) used only
/// to equalize login timing for unknown users — its result is discarded.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$K0MNZoOpmNPxYNBkg9beuQ$VM/3y7kBtj3autlfGEskuTJYpeZMYbFdHIdA2erpvho";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tokens_trims_and_drops_empties() {
        assert_eq!(split_tokens(""), Vec::<String>::new());
        assert_eq!(split_tokens("abc"), vec!["abc".to_owned()]);
        assert_eq!(
            split_tokens(" one ,, two ,three "),
            vec!["one".to_owned(), "two".to_owned(), "three".to_owned()]
        );
    }
}
