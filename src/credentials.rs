//! `~/.warden/credentials.json` — cached OIDC bearer tokens.
//!
//! Mirrors the `gcloud auth login` / `gh auth login` shape: one file
//! per host, one entry per (tenant, host). Per-tenant entries because
//! a single CLI install may target multiple Warden tenants (Acme dev,
//! Acme prod) — the user only does `--tenant acme` and we look up the
//! right token.
//!
//! Wire shape (verbatim what's persisted):
//!
//! ```json
//! {
//!   "tenants": {
//!     "acme": {
//!       "id_token":     "<jwt>",
//!       "refresh_token": "<opt>",
//!       "expires_at":   "2026-05-05T15:00:00Z",
//!       "sub":          "user:alice@acme.com",
//!       "issuer":       "https://idp.test/"
//!     }
//!   }
//! }
//! ```
//!
//! On Unix the file is created with mode `0600` so a stolen-laptop
//! attacker without root can't read another user's token. Refresh-token
//! flow lands later alongside the device-authorization grant; for now
//! the `id_token` is what the user supplied verbatim and `refresh_token`
//! is always `None`.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One cached credential per tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCredential {
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub refresh_token: Option<String>,
    /// RFC 3339 expiry. May be `None` if the caller didn't supply one
    /// — we degrade to "send it until it stops working" rather than
    /// preemptively rejecting expired tokens (the server is the
    /// authoritative `exp` enforcer).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Decoded `sub` claim, surfaced via `auth whoami`. Stored
    /// alongside the token so `whoami` doesn't have to re-decode the
    /// JWT each call.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub: Option<String>,
    /// Decoded `iss` claim. Same rationale as `sub`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub issuer: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(default)]
    pub tenants: BTreeMap<String, TenantCredential>,
}

/// Resolve the on-disk credentials file path. `WARDEN_CREDENTIALS_PATH`
/// overrides — used by the e2e runner so tests don't pollute the
/// developer's `~/.warden/credentials.json`. When the env var is unset,
/// fall back to `ProjectDirs` (Linux: `~/.config/warden/credentials.json`,
/// macOS: `~/Library/Application Support/dev.agent-warden.warden/...`,
/// Windows: `%APPDATA%/warden/...`).
pub fn credentials_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("WARDEN_CREDENTIALS_PATH") {
        return Ok(PathBuf::from(p));
    }
    let dirs = ProjectDirs::from("dev", "agent-warden", "warden")
        .context("could not resolve OS config dir for warden")?;
    Ok(dirs.config_dir().join("credentials.json"))
}

/// Load the cached creds, returning an empty bag if no file exists.
pub fn load() -> Result<Credentials> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(Credentials::default());
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let creds: Credentials = serde_json::from_str(&body)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(creds)
}

/// Persist the credentials bag. Creates the parent directory if it
/// doesn't exist; on Unix the file is opened with mode `0600` *atomically
/// with create*, so a fresh install never has a window where the bearer
/// is world-readable under the default umask.
pub fn save(creds: &Credentials) -> Result<()> {
    let path = credentials_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let body = serde_json::to_string_pretty(creds)?;
    write_0600(&path, body.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_0600(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body)?;
    // `mode(0o600)` only takes effect when the file is newly created
    // (per `open(2)`'s `mode` argument). For a pre-existing file with
    // looser perms — e.g. a credentials.json from before this fix —
    // explicit chmod after write is what tightens it.
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_0600(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    // Windows ACLs already restrict to the user; no chmod equivalent.
    std::fs::write(path, body)
}

/// Subset of JWT claims `unverified_decode` extracts. Every field is
/// `Option` because the token producer may have elided any of them —
/// the server is the authoritative claim enforcer; this struct exists
/// only for local display (`whoami`) and bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnverifiedClaims {
    pub sub: Option<String>,
    pub issuer: Option<String>,
    pub exp: Option<DateTime<Utc>>,
}

/// Decode the `sub`, `iss`, and `exp` claims from a JWT *without
/// verifying the signature*. The server is the authoritative
/// verifier; this is for `whoami` display and for prefilling the
/// `created_by_sub` audit field on `agents create` from the
/// cached creds without re-parsing the JWT on every call.
pub fn unverified_decode(id_token: &str) -> Result<UnverifiedClaims> {
    use base64::{engine::general_purpose, Engine as _};
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("token is not in JWT compact form (expected 3 parts)"));
    }
    let payload = general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(parts[1]))
        .context("decode JWT payload as base64url")?;
    let v: serde_json::Value =
        serde_json::from_slice(&payload).context("parse JWT payload as JSON")?;
    Ok(UnverifiedClaims {
        sub: v.get("sub").and_then(|x| x.as_str()).map(String::from),
        issuer: v.get("iss").and_then(|x| x.as_str()).map(String::from),
        exp: v
            .get("exp")
            .and_then(|x| x.as_i64())
            .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0)),
    })
}

/// Look up the bearer for `tenant`, returning a sentinel error rather
/// than panicking when the user hasn't run `auth login` yet.
pub fn bearer_for(creds: &Credentials, tenant: &str) -> Result<String> {
    creds
        .tenants
        .get(tenant)
        .map(|tc| tc.id_token.clone())
        .ok_or_else(|| anyhow!("no cached credentials for tenant '{tenant}' — run `wardenctl auth login --tenant {tenant} ...`"))
}

#[cfg(test)]
mod tests {
    // Use a base64 dep transitively via warden-sdk → don't add a direct
    // dep just for tests; mint test JWTs via base64 from std::format!.
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn unverified_decode_extracts_sub_iss_exp() {
        // Hand-build a JWT compact form: `<base64url(header)>.<base64url(payload)>.<sig>`.
        let header = general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(
            br#"{"sub":"user:alice@acme.com","iss":"https://idp.test/","exp":1830000000}"#,
        );
        let token = format!("{header}.{payload}.sig");
        let claims = unverified_decode(&token).unwrap();
        assert_eq!(claims.sub.as_deref(), Some("user:alice@acme.com"));
        assert_eq!(claims.issuer.as_deref(), Some("https://idp.test/"));
        assert_eq!(claims.exp.unwrap().timestamp(), 1_830_000_000);
    }

    #[test]
    fn unverified_decode_rejects_bad_shape() {
        assert!(unverified_decode("not-a-jwt").is_err());
        assert!(unverified_decode("a.b").is_err());
        assert!(unverified_decode("a.@@@.c").is_err());
    }

    #[test]
    fn bearer_for_returns_token_when_present() {
        let mut creds = Credentials::default();
        creds.tenants.insert(
            "acme".into(),
            TenantCredential {
                id_token: "tok-123".into(),
                refresh_token: None,
                expires_at: None,
                sub: None,
                issuer: None,
            },
        );
        assert_eq!(bearer_for(&creds, "acme").unwrap(), "tok-123");
        assert!(bearer_for(&creds, "globex").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_file_with_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("credentials.json");
        let prev = std::env::var("WARDEN_CREDENTIALS_PATH").ok();
        // SAFETY: the test runs in a single-threaded `#[test]` slot.
        // `set_var`/`remove_var` are safe in this scope. Restored at the end.
        unsafe { std::env::set_var("WARDEN_CREDENTIALS_PATH", &target); }

        let mut creds = Credentials::default();
        creds.tenants.insert(
            "acme".into(),
            TenantCredential {
                id_token: "tok".into(),
                refresh_token: None,
                expires_at: None,
                sub: None,
                issuer: None,
            },
        );
        save(&creds).unwrap();

        let perms = std::fs::metadata(&target).unwrap().permissions();
        // mask off ftype bits — the mode integer carries them on Unix.
        assert_eq!(perms.mode() & 0o777, 0o600);

        unsafe {
            match prev {
                Some(v) => std::env::set_var("WARDEN_CREDENTIALS_PATH", v),
                None => std::env::remove_var("WARDEN_CREDENTIALS_PATH"),
            }
        }
    }

    #[test]
    fn round_trips_through_json() {
        let mut creds = Credentials::default();
        creds.tenants.insert(
            "acme".into(),
            TenantCredential {
                id_token: "tok-123".into(),
                refresh_token: Some("rt-456".into()),
                expires_at: DateTime::<Utc>::from_timestamp(1_830_000_000, 0),
                sub: Some("user:alice@acme.com".into()),
                issuer: Some("https://idp.test/".into()),
            },
        );
        let body = serde_json::to_string(&creds).unwrap();
        let again: Credentials = serde_json::from_str(&body).unwrap();
        assert_eq!(again.tenants["acme"].id_token, "tok-123");
        assert_eq!(again.tenants["acme"].refresh_token.as_deref(), Some("rt-456"));
    }
}

