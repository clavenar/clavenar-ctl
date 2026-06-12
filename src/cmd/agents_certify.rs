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

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use clavenar_chaos_catalog::{catalog, Attack, Category};
use clavenar_sdk::{CertificationCase, CertificationRequest};
use reqwest::{Certificate, Client, Identity};
use sha2::{Digest, Sha256};

use crate::cmd::agents::build_client;
use crate::{config, ExitCode};

/// Proxy MCP endpoint used when neither the flag nor the env var is set.
const DEFAULT_PROXY_URL: &str = "https://localhost:8443/mcp";

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
                let text = resp.text().await.unwrap_or_default();
                // Mirror the chaos runner: HTTP 200 is the only ALLOW;
                // every non-2xx is "the boundary refused this probe."
                if status.is_success() {
                    (format!("ALLOWED ({})", status.as_u16()), false)
                } else {
                    (observed_reason(status.as_u16(), &text), true)
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
/// `ca.crt` in `dir`. Mirrors `mcp_bridge::build_client`.
async fn build_mtls_client(dir: &Path, insecure: bool) -> anyhow::Result<Client> {
    let cert_pem = tokio::fs::read(dir.join("client.crt")).await?;
    let key_pem = tokio::fs::read(dir.join("client.key")).await?;
    let ca_pem = tokio::fs::read(dir.join("ca.crt")).await?;

    let identity_pem = [cert_pem.as_slice(), b"\n", key_pem.as_slice()].concat();
    let identity = Identity::from_pem(&identity_pem)?;
    let ca = Certificate::from_pem(&ca_pem)?;

    let mut builder = Client::builder()
        .use_rustls_tls()
        .identity(identity)
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(30));
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

/// Stable fingerprint of the scoped catalog the gauntlet ran — pins
/// which attack set certified the agent. An auditor with the same
/// catalog reproduces it; a catalog change (added/removed/recategorized
/// attack) shifts the digest.
fn catalog_fingerprint(attacks: &[Attack]) -> String {
    let mut lines: Vec<String> = attacks
        .iter()
        .map(|a| format!("{}|{}|{}", a.id, a.category.as_str(), a.description))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    h.update(lines.join("\n").as_bytes());
    hex::encode(h.finalize())
}

/// Compact, single-line observed reason for a denied probe — status +
/// the first line of the body, trimmed so a verbose JSON-RPC error
/// doesn't bloat the certificate.
fn observed_reason(status: u16, body: &str) -> String {
    let first = body.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let trimmed: String = first.trim().chars().take(200).collect();
    if trimmed.is_empty() {
        format!("DENIED ({status})")
    } else {
        format!("DENIED ({status}) {trimmed}")
    }
}
