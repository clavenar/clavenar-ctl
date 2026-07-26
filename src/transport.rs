//! Process-wide secure transport profile shared by every CLI command.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use clavenar_sdk::{
    HttpProvider, ProxyPolicy, SecureTransportConfig, SecureTransportProfile, StaticHttpClient,
    TokenSource, install_process_http_provider,
};
use serde::Deserialize;

static CLI_HTTP_PROVIDER: OnceLock<Arc<dyn HttpProvider>> = OnceLock::new();
static SECURE_PROFILE_ENABLED: OnceLock<bool> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileDocument {
    contract: String,
    tls: TlsDocument,
    token_source: TokenSourceDocument,
    timeouts: TimeoutDocument,
    proxy: ProxyDocument,
    rotation: RotationDocument,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TlsDocument {
    ca_bundle_path: PathBuf,
    client_certificate_path: PathBuf,
    private_key_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum TokenSourceDocument {
    None,
    File { reference: PathBuf },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TimeoutDocument {
    connect_millis: u64,
    request_millis: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
enum ProxyDocument {
    Direct,
    Environment,
    Explicit { url: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum RotationMode {
    ExplicitReload,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationDocument {
    mode: RotationMode,
}

/// Install the one provider used by SDK constructors and direct reqwest paths.
pub(crate) fn initialize(profile_override: Option<&Path>) -> Result<(), String> {
    let env_profile = std::env::var_os("CLAVENAR_TRANSPORT_PROFILE").map(PathBuf::from);
    let profile_path = profile_override.map(Path::to_path_buf).or(env_profile);

    let secure_enabled = profile_path.is_some();
    let provider: Arc<dyn HttpProvider> = match profile_path {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| format!("read transport profile {}: {e}", path.display()))?;
            let document: ProfileDocument = serde_json::from_str(&raw)
                .map_err(|e| format!("parse transport profile {}: {e}", path.display()))?;
            if document.contract != "clavenar.secure-transport-profile/v1" {
                return Err("unsupported secure transport profile contract".into());
            }
            let _rotation_mode = document.rotation.mode;
            let token_source = match document.token_source {
                TokenSourceDocument::None => TokenSource::None,
                TokenSourceDocument::File { reference } => TokenSource::File(reference),
            };
            let proxy = match document.proxy {
                ProxyDocument::Direct => ProxyPolicy::Direct,
                ProxyDocument::Environment => ProxyPolicy::Environment,
                ProxyDocument::Explicit { url } => ProxyPolicy::Explicit(url),
            };
            Arc::new(
                SecureTransportProfile::new(SecureTransportConfig {
                    ca_bundle_path: document.tls.ca_bundle_path,
                    client_certificate_path: document.tls.client_certificate_path,
                    private_key_path: document.tls.private_key_path,
                    token_source,
                    connect_timeout: Duration::from_millis(document.timeouts.connect_millis),
                    request_timeout: Duration::from_millis(document.timeouts.request_millis),
                    proxy,
                })
                .map_err(|e| format!("load secure transport profile: {e}"))?,
            )
        }
        None => Arc::new(StaticHttpClient::new(
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .map_err(|e| format!("build default transport profile: {e}"))?,
        )),
    };

    CLI_HTTP_PROVIDER
        .set(Arc::clone(&provider))
        .map_err(|_| "CLI transport profile is already initialized".to_string())?;
    SECURE_PROFILE_ENABLED
        .set(secure_enabled)
        .map_err(|_| "CLI transport mode is already initialized".to_string())?;
    install_process_http_provider(provider)
        .map_err(|e| format!("install CLI transport profile: {e}"))
}

/// Return the configured secure snapshot when an explicit profile is active.
pub(crate) fn secure_client() -> Option<reqwest::Client> {
    SECURE_PROFILE_ENABLED
        .get()
        .copied()
        .unwrap_or(false)
        .then(client)
}

/// Snapshot used by command paths that make direct reqwest calls.
pub(crate) fn client() -> reqwest::Client {
    CLI_HTTP_PROVIDER.get().map_or_else(
        || {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .no_proxy()
                .build()
                .expect("static fallback transport is valid")
        },
        |provider| provider.client().as_ref().clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_contract_without_reading_credentials() {
        let parsed: ProfileDocument = serde_json::from_str(
            r#"{
              "contract":"wrong/v1",
              "tls":{"caBundlePath":"a","clientCertificatePath":"b","privateKeyPath":"c"},
              "tokenSource":{"kind":"none"},
              "timeouts":{"connectMillis":1,"requestMillis":1},
              "proxy":{"mode":"direct"},
              "rotation":{"mode":"explicit-reload"}
            }"#,
        )
        .unwrap();
        assert_ne!(parsed.contract, "clavenar.secure-transport-profile/v1");
    }

    #[test]
    fn denies_unknown_profile_fields() {
        let parsed = serde_json::from_str::<ProfileDocument>(
            r#"{
              "contract":"clavenar.secure-transport-profile/v1",
              "tls":{"caBundlePath":"a","clientCertificatePath":"b","privateKeyPath":"c"},
              "tokenSource":{"kind":"none"},
              "timeouts":{"connectMillis":1,"requestMillis":1},
              "proxy":{"mode":"direct"},
              "rotation":{"mode":"explicit-reload"},
              "secret":"must-not-be-accepted"
            }"#,
        );
        assert!(parsed.is_err());
    }
}
