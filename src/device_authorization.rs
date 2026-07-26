//! Bounded RFC 8628 device authorization for the operator CLI.
//!
//! The device code is never written to disk or logs. Only a successfully
//! redeemed ID token and optional refresh token reach the existing mode-0600
//! credential store. The public client and scope are fixed so this human
//! operator authority cannot be confused with an agent workload SVID.

use chrono::{DateTime, Utc};
use reqwest::{Client, Response, StatusCode, Url};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::credentials::{TenantCredential, unverified_decode};

pub(crate) const OPERATOR_CLIENT_ID: &str = "clavenar-operator-cli";
pub(crate) const OPERATOR_SCOPE: &str = "openid clavenar.operator";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_DISCOVERY_BYTES: usize = 65_536;
const MAX_RESPONSE_BYTES: usize = 32_768;
const MAX_DEVICE_LIFETIME_SECONDS: u64 = 900;
const MAX_POLL_INTERVAL_SECONDS: u64 = 15;
const MAX_POLLS: u64 = 180;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Validation,
    Denied,
    Server,
}

#[derive(Debug)]
pub(crate) struct DeviceAuthError {
    pub class: FailureClass,
    pub message: String,
}

impl DeviceAuthError {
    fn validation(message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Validation,
            message: message.into(),
        }
    }

    fn denied(message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Denied,
            message: message.into(),
        }
    }

    fn server(message: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Server,
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    scope: String,
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

fn default_interval() -> u64 {
    5
}

pub(crate) async fn authorize(
    issuer_input: &str,
    expected_tenant: &str,
) -> Result<TenantCredential, DeviceAuthError> {
    validate_tenant(expected_tenant)?;
    let issuer = validate_issuer(issuer_input)?;
    let client = crate::transport::client();

    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.as_str().trim_end_matches('/')
    );
    let response = client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|error| DeviceAuthError::server(format!("OIDC discovery failed: {error}")))?;
    require_status(&response, "OIDC discovery")?;
    let discovery: Discovery =
        decode_bounded(response, MAX_DISCOVERY_BYTES, "OIDC discovery").await?;
    if discovery.issuer.trim_end_matches('/') != issuer.as_str().trim_end_matches('/') {
        return Err(DeviceAuthError::validation(
            "OIDC discovery issuer does not exactly match --issuer",
        ));
    }
    let device_endpoint =
        validate_same_origin_endpoint(&issuer, &discovery.device_authorization_endpoint)?;
    let token_endpoint = validate_same_origin_endpoint(&issuer, &discovery.token_endpoint)?;

    let response = client
        .post(device_endpoint)
        .form(&[("client_id", OPERATOR_CLIENT_ID), ("scope", OPERATOR_SCOPE)])
        .send()
        .await
        .map_err(|error| {
            DeviceAuthError::server(format!("device authorization request failed: {error}"))
        })?;
    require_status(&response, "device authorization")?;
    let device: DeviceResponse =
        decode_bounded(response, MAX_RESPONSE_BYTES, "device authorization").await?;
    validate_device_response(&device)?;

    println!(
        "Open {} and enter code {}",
        device.verification_uri, device.user_code
    );
    if let Some(complete) = &device.verification_uri_complete {
        println!("Verification URL: {complete}");
    }

    poll_token(&client, token_endpoint, device, &issuer, expected_tenant).await
}

async fn poll_token(
    client: &Client,
    token_endpoint: Url,
    device: DeviceResponse,
    issuer: &Url,
    expected_tenant: &str,
) -> Result<TenantCredential, DeviceAuthError> {
    let started = Instant::now();
    let lifetime = Duration::from_secs(device.expires_in.min(MAX_DEVICE_LIFETIME_SECONDS));
    let mut interval = Duration::from_secs(device.interval);
    let mut polls = 0_u64;

    loop {
        if polls >= MAX_POLLS || started.elapsed() >= lifetime {
            return Err(DeviceAuthError::denied(
                "device authorization expired before approval",
            ));
        }
        tokio::time::sleep(interval).await;
        polls += 1;

        let response = client
            .post(token_endpoint.clone())
            .form(&[
                ("grant_type", DEVICE_GRANT),
                ("device_code", device.device_code.as_str()),
                ("client_id", OPERATOR_CLIENT_ID),
            ])
            .send()
            .await
            .map_err(|error| DeviceAuthError::server(format!("token polling failed: {error}")))?;
        let status = response.status();
        if status.is_success() {
            let token: TokenResponse =
                decode_bounded(response, MAX_RESPONSE_BYTES, "token response").await?;
            return validate_token(token, issuer, expected_tenant);
        }
        if status != StatusCode::BAD_REQUEST {
            return Err(DeviceAuthError::server(format!(
                "token endpoint returned HTTP {status}"
            )));
        }
        let body: OAuthError =
            decode_bounded(response, MAX_RESPONSE_BYTES, "OAuth error response").await?;
        match body.error.as_str() {
            "authorization_pending" => {}
            "slow_down" => {
                interval =
                    Duration::from_secs((interval.as_secs() + 5).min(MAX_POLL_INTERVAL_SECONDS));
            }
            "access_denied" => {
                return Err(DeviceAuthError::denied(
                    "device authorization was denied by the operator",
                ));
            }
            "expired_token" => {
                return Err(DeviceAuthError::denied("device authorization expired"));
            }
            "temporarily_unavailable" | "server_error" => {}
            _ => {
                let detail = body.error_description.as_deref().unwrap_or("no detail");
                return Err(DeviceAuthError::server(format!(
                    "token endpoint rejected device grant: {} ({detail})",
                    body.error
                )));
            }
        }
    }
}

fn validate_token(
    token: TokenResponse,
    issuer: &Url,
    expected_tenant: &str,
) -> Result<TenantCredential, DeviceAuthError> {
    if !token.token_type.eq_ignore_ascii_case("bearer") {
        return Err(DeviceAuthError::validation(
            "device token response token_type must be Bearer",
        ));
    }
    let scopes: BTreeSet<&str> = token.scope.split_ascii_whitespace().collect();
    if !scopes.contains("openid")
        || !scopes.contains("clavenar.operator")
        || scopes.contains("clavenar.agent")
    {
        return Err(DeviceAuthError::validation(
            "device token response does not carry the exact operator authority boundary",
        ));
    }
    let claims = unverified_decode(&token.id_token)
        .map_err(|error| DeviceAuthError::validation(format!("invalid ID token: {error}")))?;
    if claims
        .issuer
        .as_deref()
        .map(|value| value.trim_end_matches('/'))
        != Some(issuer.as_str().trim_end_matches('/'))
    {
        return Err(DeviceAuthError::validation(
            "device ID token issuer does not match discovery",
        ));
    }
    if claims.tenant.as_deref() != Some(expected_tenant) {
        return Err(DeviceAuthError::denied(
            "device ID token tenant does not match the requested tenant",
        ));
    }
    if claims.sub.as_deref().is_none_or(str::is_empty) {
        return Err(DeviceAuthError::validation(
            "device ID token must contain a non-empty subject",
        ));
    }
    let now = Utc::now();
    let Some(claim_expiry) = claims.exp else {
        return Err(DeviceAuthError::validation(
            "device ID token must contain an expiry",
        ));
    };
    if claim_expiry <= now {
        return Err(DeviceAuthError::denied(
            "device ID token is already expired",
        ));
    }
    let response_expiry = token
        .expires_in
        .and_then(|seconds| i64::try_from(seconds.min(MAX_DEVICE_LIFETIME_SECONDS)).ok())
        .map(|seconds| now + chrono::Duration::seconds(seconds));
    let expires_at: DateTime<Utc> = response_expiry
        .map(|value| value.min(claim_expiry))
        .unwrap_or(claim_expiry);
    Ok(TenantCredential {
        id_token: token.id_token,
        refresh_token: token.refresh_token,
        expires_at: Some(expires_at),
        sub: claims.sub,
        issuer: claims.issuer,
    })
}

fn validate_tenant(tenant: &str) -> Result<(), DeviceAuthError> {
    let valid = !tenant.is_empty()
        && tenant.len() <= 63
        && tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if !valid {
        return Err(DeviceAuthError::validation(
            "tenant must be 1-63 ASCII letters, digits, '.', '_', or '-'",
        ));
    }
    Ok(())
}

fn validate_issuer(value: &str) -> Result<Url, DeviceAuthError> {
    let issuer = Url::parse(value)
        .map_err(|error| DeviceAuthError::validation(format!("invalid issuer URL: {error}")))?;
    if issuer.cannot_be_a_base()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(DeviceAuthError::validation(
            "issuer must be an absolute base URL without credentials, query, or fragment",
        ));
    }
    let loopback = issuer.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if issuer.scheme() != "https" && !(issuer.scheme() == "http" && loopback) {
        return Err(DeviceAuthError::validation(
            "issuer must use HTTPS (HTTP is allowed only on loopback)",
        ));
    }
    Ok(issuer)
}

fn validate_same_origin_endpoint(issuer: &Url, endpoint: &str) -> Result<Url, DeviceAuthError> {
    let parsed = Url::parse(endpoint).map_err(|error| {
        DeviceAuthError::validation(format!("OIDC endpoint is not an absolute URL: {error}"))
    })?;
    if parsed.scheme() != issuer.scheme()
        || parsed.host_str() != issuer.host_str()
        || parsed.port_or_known_default() != issuer.port_or_known_default()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DeviceAuthError::validation(
            "OIDC device and token endpoints must share the exact issuer origin",
        ));
    }
    Ok(parsed)
}

fn validate_device_response(device: &DeviceResponse) -> Result<(), DeviceAuthError> {
    if device.device_code.is_empty()
        || device.device_code.len() > 2048
        || device.user_code.is_empty()
        || device.user_code.len() > 128
        || device.expires_in < 30
        || device.expires_in > MAX_DEVICE_LIFETIME_SECONDS
        || device.interval == 0
        || device.interval > MAX_POLL_INTERVAL_SECONDS
    {
        return Err(DeviceAuthError::validation(
            "device authorization response violates bounded code, lifetime, or polling policy",
        ));
    }
    let verification = validate_verification_url(&device.verification_uri)?;
    if let Some(complete) = &device.verification_uri_complete {
        let complete_url = validate_verification_url(complete)?;
        if verification.origin() != complete_url.origin() {
            return Err(DeviceAuthError::validation(
                "complete verification URL must share the verification origin",
            ));
        }
    }
    Ok(())
}

fn validate_verification_url(value: &str) -> Result<Url, DeviceAuthError> {
    let url = Url::parse(value).map_err(|error| {
        DeviceAuthError::validation(format!("invalid verification URL: {error}"))
    })?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
    {
        return Err(DeviceAuthError::validation(
            "verification URL must use HTTPS without credentials or fragment",
        ));
    }
    Ok(url)
}

fn require_status(response: &Response, operation: &str) -> Result<(), DeviceAuthError> {
    if response.status().is_success() {
        return Ok(());
    }
    Err(DeviceAuthError::server(format!(
        "{operation} returned HTTP {}",
        response.status()
    )))
}

async fn decode_bounded<T: for<'de> Deserialize<'de>>(
    mut response: Response,
    limit: usize,
    operation: &str,
) -> Result<T, DeviceAuthError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(DeviceAuthError::server(format!(
            "{operation} response exceeds {limit} bytes"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| DeviceAuthError::server(format!("{operation} body failed: {error}")))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(DeviceAuthError::server(format!(
                "{operation} response exceeds {limit} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|error| DeviceAuthError::server(format!("{operation} JSON invalid: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};

    fn jwt(issuer: &str, tenant: &str, expiry: i64) -> String {
        let header = general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": issuer,
                "sub": "operator-123",
                "exp": expiry,
                "clavenar_tenant": tenant
            })
            .to_string(),
        );
        format!("{header}.{payload}.signature")
    }

    fn response(issuer: &str, tenant: &str, scope: &str) -> TokenResponse {
        TokenResponse {
            id_token: jwt(issuer, tenant, Utc::now().timestamp() + 300),
            refresh_token: Some("refresh-secret".into()),
            expires_in: Some(300),
            scope: scope.into(),
            token_type: "Bearer".into(),
        }
    }

    #[test]
    fn issuer_requires_https_except_loopback() {
        assert!(validate_issuer("https://idp.example/realm/acme").is_ok());
        assert!(validate_issuer("http://127.0.0.1:18080/realm/acme").is_ok());
        assert!(validate_issuer("http://idp.example/realm/acme").is_err());
        assert!(validate_issuer("https://user@idp.example/realm").is_err());
        assert!(validate_issuer("https://idp.example/realm?tenant=acme").is_err());
    }

    #[test]
    fn endpoints_must_share_exact_origin() {
        let issuer = validate_issuer("https://idp.example:8443/realm/acme").unwrap();
        assert!(
            validate_same_origin_endpoint(&issuer, "https://idp.example:8443/realm/acme/device")
                .is_ok()
        );
        assert!(validate_same_origin_endpoint(&issuer, "https://evil.example/token").is_err());
        assert!(validate_same_origin_endpoint(&issuer, "https://idp.example/token").is_err());
    }

    #[test]
    fn token_requires_operator_scope_and_exact_tenant() {
        let issuer = validate_issuer("https://idp.example/realm/acme").unwrap();
        assert!(
            validate_token(
                response(issuer.as_str(), "acme", "openid profile clavenar.operator"),
                &issuer,
                "acme"
            )
            .is_ok()
        );
        let wrong_tenant = validate_token(
            response(issuer.as_str(), "globex", OPERATOR_SCOPE),
            &issuer,
            "acme",
        )
        .unwrap_err();
        assert_eq!(wrong_tenant.class, FailureClass::Denied);
        assert!(
            validate_token(
                response(
                    issuer.as_str(),
                    "acme",
                    "openid clavenar.operator clavenar.agent"
                ),
                &issuer,
                "acme"
            )
            .is_err()
        );
    }

    #[test]
    fn device_response_enforces_bounds() {
        let valid = DeviceResponse {
            device_code: "secret-code".into(),
            user_code: "ABCD-EFGH".into(),
            verification_uri: "https://idp.example/device".into(),
            verification_uri_complete: Some(
                "https://idp.example/device?user_code=ABCD-EFGH".into(),
            ),
            expires_in: 600,
            interval: 5,
        };
        assert!(validate_device_response(&valid).is_ok());
        let too_long = DeviceResponse {
            expires_in: 901,
            ..valid
        };
        assert!(validate_device_response(&too_long).is_err());
    }
}
