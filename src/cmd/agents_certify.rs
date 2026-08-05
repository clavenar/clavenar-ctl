//! `clavenarctl agents certify` — pre-flight certification gauntlet.
//!
//! Fires the chaos catalog's `agent_cert` family at the live proxy as
//! the candidate's own mTLS traffic, asserts every probe is denied at
//! the boundary, then submits the passing result to identity's
//! `POST /agents/{id}/certification` — which computes, signs (with the
//! same Vault key `/sign/blob` uses), and returns the survival
//! certificate. The signed certificate is written as a sidecar.
//!
//! Honest scope: the gauntlet proves the *enforcement boundary* held
//! for a given SDK version — not that the agent's private code is
//! correct. The catalog observes only the proxy verdict, never the
//! agent's internal handling.

use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use clavenar_chaos_catalog::{Attack, Category, Expected, Mode, catalog};
use clavenar_sdk::{CertificationCase, CertificationRequest};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::cmd::agents::build_client;
use crate::{ExitCode, config};

/// Proxy MCP endpoint used when neither the flag nor the env var is set.
const DEFAULT_PROXY_URL: &str = "https://localhost:8443/mcp";
const MAX_CERTIFICATION_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RejectionEnvelope {
    verdict: String,
    layer: String,
    error: String,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    review_reasons: Vec<String>,
    correlation_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct CertifyArgs {
    /// Agent uuidv7 (the registry `id`) to certify.
    pub id: String,
    /// Tenant the agent belongs to. Falls back to `CLAVENAR_TENANT`,
    /// then the config file's `default_tenant`.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Proxy MCP endpoint to fire the gauntlet at. Falls back to
    /// `CLAVENAR_PROXY_URL`, then `https://localhost:8443/mcp`.
    #[arg(long)]
    pub proxy_url: Option<String>,
    /// Directory holding the CANDIDATE agent's mTLS material
    /// (`client.crt`, `client.key`, `ca.crt`) used to fire the gauntlet.
    #[arg(long, default_value = "./certs")]
    pub cert_dir: PathBuf,
    /// SDK version the agent runs — operator-asserted (there is no wire
    /// source for the running version) and recorded on the certificate.
    #[arg(long)]
    pub sdk_version: String,
    /// Where to write the signed certificate sidecar. Defaults to
    /// `<id>.cert.json`.
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Print the certificate to stdout instead of writing a sidecar.
    #[arg(long)]
    pub no_out: bool,
    /// Accept an invalid/self-signed proxy server cert (dev only).
    #[arg(long)]
    pub insecure: bool,
    /// Emit JSON instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

pub(crate) async fn run(args: CertifyArgs, cfg: &config::Config, url: &str) -> ExitCode {
    let tenant = match config::resolve_tenant(args.tenant.clone(), cfg) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let proxy_url = args
        .proxy_url
        .clone()
        .or_else(|| std::env::var("CLAVENAR_PROXY_URL").ok())
        .unwrap_or_else(|| DEFAULT_PROXY_URL.to_string());

    let agents = match build_client(url, &tenant) {
        Ok(c) => c,
        Err(c) => return c,
    };
    let record = match agents.get(&args.id, &tenant).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: fetch agent '{}': {e}", args.id);
            return ExitCode::from_clavenar_error(&e);
        }
    };

    let client = match build_mtls_client(&args.cert_dir, args.insecure).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: build mTLS client from {}: {e}",
                args.cert_dir.display()
            );
            return ExitCode::Validation;
        }
    };

    let attacks: Vec<Attack> = catalog()
        .into_iter()
        .filter(|a| a.category == Category::AgentCert)
        .collect();
    if attacks.is_empty() {
        eprintln!("error: catalog carries no agent_cert attacks");
        return ExitCode::Server;
    }
    let catalog_sha256 = catalog_fingerprint(&attacks);

    let mut cases: Vec<CertificationCase> = Vec::with_capacity(attacks.len());
    for (i, attack) in attacks.iter().enumerate() {
        let payload = attack.build_payload((i + 1) as u64);
        let mut req = client.post(&proxy_url).json(&payload);
        for (k, v) in attack.build_headers() {
            req = req.header(k, v);
        }
        let (observed, passed) = match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                match read_bounded_text(resp, MAX_CERTIFICATION_RESPONSE_BYTES).await {
                    Ok(text) => classify_probe_response(attack, status, &text),
                    Err(error) => (
                        format!("INVALID RESPONSE ({}) {error}", status.as_u16()),
                        false,
                    ),
                }
            }
            Err(e) => {
                eprintln!("error: firing {} at {proxy_url}: {e}", attack.id);
                return ExitCode::Server;
            }
        };
        cases.push(CertificationCase {
            id: attack.id.to_string(),
            // The agent_cert family is all-deny by construction.
            category: attack.category.as_str().to_string(),
            expected: "deny".to_string(),
            observed,
            passed,
        });
    }

    let total = cases.len() as u32;
    let passed = cases.iter().filter(|c| c.passed).count() as u32;

    if !args.json {
        for c in &cases {
            let mark = if c.passed { "PASS" } else { "FAIL" };
            println!("{mark}  {:<28}  {}", c.id, c.observed);
        }
        println!("gauntlet: {passed}/{total} probes denied at the boundary");
    }

    if total == 0 || passed != total {
        eprintln!(
            "certification FAILED: {} of {total} probe(s) reached the agent — not certified",
            total - passed
        );
        return ExitCode::Server;
    }

    let req = CertificationRequest {
        sdk_version: args.sdk_version.clone(),
        proxy_url: proxy_url.clone(),
        catalog_sha256,
        cases,
        total,
        passed,
    };
    let signed = match agents.record_certification(&args.id, &tenant, &req).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: record certification: {e}");
            return ExitCode::from_clavenar_error(&e);
        }
    };

    let serialized = match serde_json::to_string_pretty(&signed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize certificate: {e}");
            return ExitCode::Server;
        }
    };
    if args.no_out {
        println!("{serialized}");
    } else {
        let out = args
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("{}.cert.json", args.id)));
        if let Err(e) = std::fs::write(&out, format!("{serialized}\n")) {
            eprintln!("error: write {}: {e}", out.display());
            return ExitCode::Server;
        }
        eprintln!(
            "certified {} ({}) at sdk_version={} — signed (kid={}, sha256={}), sidecar {}",
            record.agent_name,
            args.id,
            args.sdk_version,
            signed.key_id,
            &signed.certificate_sha256[..16.min(signed.certificate_sha256.len())],
            out.display(),
        );
    }
    ExitCode::Ok
}

/// Build an mTLS reqwest client from `client.crt` / `client.key` /
/// `ca.crt` in `dir` through the process-wide CLI transport factory.
async fn build_mtls_client(dir: &std::path::Path, insecure: bool) -> anyhow::Result<Client> {
    if let Some(client) = crate::transport::secure_client() {
        return Ok(client);
    }
    crate::transport::mtls_client_from_files(
        &dir.join("client.crt"),
        &dir.join("client.key"),
        &dir.join("ca.crt"),
        insecure,
        Duration::from_secs(30),
        &[],
    )
    .map_err(anyhow::Error::msg)
}

/// Stable fingerprint of the scoped catalog the gauntlet ran — pins
/// which attack set certified the agent. An auditor with the same
/// catalog reproduces it; a catalog change (added/removed/recategorized
/// attack) shifts the digest.
fn catalog_fingerprint(attacks: &[Attack]) -> String {
    let mut scenarios: Vec<serde_json::Value> = attacks
        .iter()
        .map(|attack| {
            let expected = match &attack.expected {
                Expected::Allow => serde_json::json!({"kind": "allow"}),
                Expected::Deny { reason_keywords } => {
                    serde_json::json!({"kind": "deny", "reasonKeywords": reason_keywords})
                }
                Expected::BusinessHoursConditional { reason_keywords } => serde_json::json!({
                    "kind": "businessHoursConditional",
                    "reasonKeywords": reason_keywords,
                }),
            };
            let mode = match attack.mode {
                Mode::Single => serde_json::json!({"kind": "single"}),
                Mode::Burst { count } => serde_json::json!({"kind": "burst", "count": count}),
                Mode::SingleWithHil(side) => {
                    serde_json::json!({"kind": "singleWithHil", "side": format!("{side:?}")})
                }
                Mode::MultiTurn { primers } => {
                    serde_json::json!({"kind": "multiTurn", "primerCount": primers.len()})
                }
            };
            let mut headers = attack.build_headers();
            headers.sort();
            let rejection = attack.rejection_contract().map(|contract| {
                serde_json::json!({
                    "status": contract.status,
                    "verdict": contract.verdict,
                    "layer": contract.layer,
                })
            });
            serde_json::json!({
                "id": attack.id,
                "category": attack.category.as_str(),
                "description": attack.description,
                "expected": expected,
                "mode": mode,
                "payload": attack.build_payload(1),
                "headers": headers,
                "rejection": rejection,
            })
        })
        .collect();
    scenarios.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&scenarios).expect("JSON values always serialize"));
    hex::encode(h.finalize())
}

async fn read_bounded_text(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("body exceeds {limit} bytes"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("body read failed: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(format!("body exceeds {limit} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| "body is not UTF-8".to_string())
}

fn classify_probe_response(attack: &Attack, status: StatusCode, body: &str) -> (String, bool) {
    let Some(contract) = attack.rejection_contract() else {
        return ("INVALID CATALOG: missing rejection contract".into(), false);
    };
    if status.as_u16() != contract.status {
        return (
            format!(
                "UNEXPECTED HTTP {} (expected {})",
                status.as_u16(),
                contract.status
            ),
            false,
        );
    }
    let envelope: RejectionEnvelope = match serde_json::from_str(body) {
        Ok(envelope) => envelope,
        Err(error) => return (format!("MALFORMED REJECTION ({status}) {error}"), false),
    };
    let reason = std::iter::once(envelope.error.as_str())
        .chain(envelope.reasons.iter().map(String::as_str))
        .chain(envelope.review_reasons.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" | ");
    let keywords = match &attack.expected {
        Expected::Deny { reason_keywords }
        | Expected::BusinessHoursConditional { reason_keywords } => reason_keywords,
        Expected::Allow => {
            return (
                "INVALID CATALOG: certification probe expects allow".into(),
                false,
            );
        }
    };
    let valid_correlation = uuid::Uuid::parse_str(&envelope.correlation_id)
        .is_ok_and(|id| id.get_version_num() == 5 && id.get_variant() == uuid::Variant::RFC4122);
    let passed = envelope.verdict == contract.verdict
        && envelope.layer == contract.layer
        && !envelope.error.trim().is_empty()
        && keywords.iter().any(|keyword| reason.contains(keyword))
        && valid_correlation;
    let observed = format!(
        "HTTP {} verdict={} layer={} reason={}",
        status.as_u16(),
        envelope.verdict,
        envelope.layer,
        reason.chars().take(160).collect::<String>()
    );
    if passed {
        (observed, true)
    } else {
        (format!("CONTRACT MISMATCH: {observed}"), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certification_attack(id: &str) -> Attack {
        catalog()
            .into_iter()
            .find(|attack| attack.id == id)
            .expect("certification attack exists")
    }

    fn exact_body(attack: &Attack) -> String {
        let contract = attack.rejection_contract().unwrap();
        let keyword = match &attack.expected {
            Expected::Deny { reason_keywords } => reason_keywords[0],
            _ => unreachable!(),
        };
        serde_json::json!({
            "verdict": contract.verdict,
            "layer": contract.layer,
            "error": keyword,
            "reasons": [],
            "correlation_id": "123e4567-e89b-52d3-a456-426614174000",
        })
        .to_string()
    }

    #[test]
    fn exact_catalog_rejection_passes() {
        let attack = certification_attack("agent_cert_malformed_mcp");
        let contract = attack.rejection_contract().unwrap();
        assert!(
            classify_probe_response(
                &attack,
                StatusCode::from_u16(contract.status).unwrap(),
                &exact_body(&attack),
            )
            .1
        );
    }

    #[test]
    fn auth_throttle_server_and_malformed_responses_fail() {
        let attack = certification_attack("agent_cert_malformed_mcp");
        for (status, body) in [
            (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
            (StatusCode::TOO_MANY_REQUESTS, r#"{"error":"rate_limited"}"#),
            (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"failed"}"#),
            (StatusCode::BAD_REQUEST, "not-json"),
        ] {
            assert!(!classify_probe_response(&attack, status, body).1);
        }
    }

    #[test]
    fn wrong_layer_or_correlation_fails() {
        let attack = certification_attack("agent_cert_malformed_mcp");
        let mut body: serde_json::Value = serde_json::from_str(&exact_body(&attack)).unwrap();
        body["layer"] = serde_json::json!("identity");
        assert!(!classify_probe_response(&attack, StatusCode::BAD_REQUEST, &body.to_string()).1);
        body["layer"] = serde_json::json!("gateway");
        body["correlation_id"] = serde_json::json!("not-a-uuid");
        assert!(!classify_probe_response(&attack, StatusCode::BAD_REQUEST, &body.to_string()).1);
    }

    #[test]
    fn fingerprint_changes_with_payload_and_contract_semantics() {
        let attacks = vec![certification_attack("agent_cert_malformed_mcp")];
        let other = vec![certification_attack("agent_cert_poisoned_result")];
        assert_ne!(catalog_fingerprint(&attacks), catalog_fingerprint(&other));
    }
}
