//! `clavenarctl pending decide <token>` — redeem a signed decision link
//! one-shot from the terminal.
//!
//! Channel-carried decision links (Slack / Teams / PagerDuty / webhook /
//! SMTP) and the console redemption page both decide through HIL. This
//! brings the same token to a terminal-resident operator: verify it
//! against HIL, show the pending it points at, and — with `--yes` —
//! decide through HIL's trusted-caller bearer path.
//!
//! The token is a *pointer plus an action claim*, never a bearer
//! credential: deciding still needs the operator's own standing
//! authority — an mTLS client cert in HIL's caller allowlist *plus* the
//! `CLAVENAR_HIL_DECIDE_TOKEN`. A leaked link alone decides nothing, and
//! the action is signature-bound, so an `approve` link can't be replayed
//! as a `deny`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Subcommand};
use reqwest::{Certificate, Client, Identity};
use serde::{Deserialize, Serialize};

use crate::ExitCode;

/// The HIL header that stamps `decided_by` on the trusted-caller bearer
/// path (mirrors `clavenar_hil::auth::DECIDED_BY_HEADER`).
const DECIDED_BY_HEADER: &str = "x-clavenar-decided-by";

#[derive(Debug, Args)]
pub(crate) struct PendingArgs {
    #[command(subcommand)]
    command: PendingCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PendingCommand {
    /// Redeem a signed decision link: verify the token, show the pending
    /// it points at, and (with `--yes`) apply the token's action.
    Decide(DecideArgs),
}

#[derive(Debug, Args)]
pub(crate) struct DecideArgs {
    /// The signed decision-link token (`{pending_id}.{action}.{exp}.{sig}`),
    /// copied from a notifier card's approve/deny link or minted via
    /// `GET /pending/{id}/decision-link`.
    pub token: String,
    /// HIL base URL (origin only — the verbs `/decision-link/verify` and
    /// `/decide/{id}` are appended). Falls back to `CLAVENAR_HIL_URL`.
    /// In mTLS deployments this is the application port (e.g.
    /// `https://localhost:8084`).
    #[arg(long)]
    pub hil_url: Option<String>,
    /// PEM client certificate. HIL gates the caller on its SPIFFE/CN
    /// allowlist (`CLAVENAR_HIL_ALLOWED_CALLERS`); use a cert whose
    /// identity is allowed (e.g. `service-console`).
    #[arg(long)]
    pub cert: PathBuf,
    /// PEM private key matching `--cert`.
    #[arg(long)]
    pub key: PathBuf,
    /// PEM CA bundle HIL's server cert chains to.
    #[arg(long)]
    pub ca: PathBuf,
    /// HIL trusted-caller bearer (`CLAVENAR_HIL_DECIDE_TOKEN`). Required
    /// only when applying (`--yes`); the verify/preview step doesn't need
    /// it. Falls back to the `CLAVENAR_HIL_DECIDE_TOKEN` env var.
    #[arg(long)]
    pub decide_token: Option<String>,
    /// Identity recorded as `decided_by` in the audit chain. Defaults to
    /// `ctl:$USER`. Pass the operator's real identity for a clean trail.
    #[arg(long = "as")]
    pub decided_by: Option<String>,
    /// Optional free-text reason stored on the decision.
    #[arg(long)]
    pub reason: Option<String>,
    /// Apply the decision. Without it the command is a dry run: it
    /// verifies the token and prints the pending, but decides nothing.
    #[arg(long, default_value_t = false)]
    pub yes: bool,
    /// Skip server certificate validation. Dev stack only — prod issues
    /// SVID-shaped certs with proper SANs.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,
}

pub(crate) async fn run(args: PendingArgs) -> ExitCode {
    match args.command {
        PendingCommand::Decide(a) => decide(a).await,
    }
}

#[derive(Serialize)]
struct VerifyRequest<'a> {
    token: &'a str,
}

#[derive(Deserialize)]
struct VerifyResponse {
    valid: bool,
    reason: String,
    pending_id: Option<String>,
    action: Option<String>,
    pending: Option<PendingSummary>,
}

#[derive(Deserialize)]
struct PendingSummary {
    agent_id: String,
    method: String,
    risk_summary: String,
    status: String,
    correlation_id: String,
}

#[derive(Serialize)]
struct DecideRequest {
    decision: String,
    decided_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

async fn decide(args: DecideArgs) -> ExitCode {
    let Some(hil_url) = args
        .hil_url
        .clone()
        .or_else(|| std::env::var("CLAVENAR_HIL_URL").ok())
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "error: HIL URL not set — pass --hil-url or set CLAVENAR_HIL_URL \
             (origin only, e.g. https://localhost:8084)"
        );
        return ExitCode::Validation;
    };

    let client = match build_client(&args).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: build mTLS client: {e}");
            return ExitCode::Validation;
        }
    };

    // Step 1 — verify (ungated). Confirms the signature, expiry, and that
    // the target is still actionable before we touch the decide path.
    let verify_url = join_url(&hil_url, "decision-link/verify");
    let resp = match client
        .post(&verify_url)
        .json(&VerifyRequest { token: &args.token })
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: reach HIL at {verify_url}: {e}");
            return ExitCode::Server;
        }
    };
    if !resp.status().is_success() {
        eprintln!("error: token verify returned HTTP {}", resp.status());
        return exit_for_status(resp.status().as_u16());
    }
    let verify: VerifyResponse = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: decode verify response: {e}");
            return ExitCode::Server;
        }
    };

    if !verify.valid {
        let (msg, code) = explain_invalid(&verify.reason);
        eprintln!("link not redeemable: {msg}");
        return code;
    }

    let (Some(pending_id), Some(action)) = (verify.pending_id.clone(), verify.action.clone())
    else {
        eprintln!("error: HIL reported a valid link without a pending id / action");
        return ExitCode::Server;
    };

    print_pending(&pending_id, &action, verify.pending.as_ref());

    // Step 2 — apply, only on explicit --yes. The dry run above is the
    // safe default for a mutating one-shot.
    if !args.yes {
        println!("\ndry run — re-run with --yes to {action} this pending.");
        return ExitCode::Ok;
    }

    let Some(decide_token) = args
        .decide_token
        .clone()
        .or_else(|| std::env::var("CLAVENAR_HIL_DECIDE_TOKEN").ok())
        .filter(|s| !s.is_empty())
    else {
        eprintln!(
            "error: deciding needs the HIL trusted-caller bearer — pass --decide-token \
             or set CLAVENAR_HIL_DECIDE_TOKEN"
        );
        return ExitCode::Auth;
    };
    let stamp = resolve_stamp(args.decided_by.as_deref());

    let decide_url = join_url(&hil_url, &format!("decide/{pending_id}"));
    let resp = match client
        .post(&decide_url)
        .bearer_auth(&decide_token)
        .header(DECIDED_BY_HEADER, &stamp)
        .json(&DecideRequest {
            decision: action.clone(),
            decided_by: stamp.clone(),
            reason: args.reason.clone(),
        })
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: reach HIL at {decide_url}: {e}");
            return ExitCode::Server;
        }
    };
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        eprintln!("error: decide returned HTTP {status}: {}", body.trim());
        return exit_for_status(status.as_u16());
    }

    println!("{action}d pending {pending_id} as {stamp}.");
    ExitCode::Ok
}

async fn build_client(args: &DecideArgs) -> anyhow::Result<Client> {
    let cert_pem = tokio::fs::read(&args.cert).await?;
    let key_pem = tokio::fs::read(&args.key).await?;
    let ca_pem = tokio::fs::read(&args.ca).await?;

    let identity_pem = [cert_pem.as_slice(), b"\n", key_pem.as_slice()].concat();
    let identity = Identity::from_pem(&identity_pem)?;
    let ca = Certificate::from_pem(&ca_pem)?;

    let mut builder = Client::builder()
        .use_rustls_tls()
        .identity(identity)
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(args.timeout_secs));
    if args.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    Ok(builder.build()?)
}

fn print_pending(pending_id: &str, action: &str, summary: Option<&PendingSummary>) {
    println!("pending {pending_id}");
    println!("  action:      {action}");
    if let Some(s) = summary {
        println!("  agent:       {}", s.agent_id);
        println!("  method:      {}", s.method);
        println!("  status:      {}", s.status);
        println!("  correlation: {}", s.correlation_id);
        println!("  risk:        {}", s.risk_summary);
    }
}

/// Append `path` to a base origin, tolerating a trailing slash on the
/// base so `https://hil:8084/` and `https://hil:8084` both work.
fn join_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path)
}

/// `decided_by` stamp: the `--as` override, else `ctl:$USER`, else a
/// bare `clavenarctl` when even `$USER` is unset.
fn resolve_stamp(as_arg: Option<&str>) -> String {
    if let Some(s) = as_arg.map(str::trim).filter(|s| !s.is_empty()) {
        return s.to_string();
    }
    match std::env::var("USER").ok().filter(|s| !s.is_empty()) {
        Some(user) => format!("ctl:{user}"),
        None => "clavenarctl".to_string(),
    }
}

/// Map a non-`valid` verify reason to an operator message + exit code.
/// `expired` / `invalid` / `gone` are client-side problems (Validation);
/// `not_pending` means the row already settled (Conflict).
fn explain_invalid(reason: &str) -> (&'static str, ExitCode) {
    match reason {
        "expired" => ("the link has expired — ask for a fresh one", ExitCode::Validation),
        "invalid" => ("the token signature is invalid", ExitCode::Validation),
        "not_pending" => (
            "the pending has already been decided or expired",
            ExitCode::Conflict,
        ),
        "gone" => ("the pending no longer exists", ExitCode::Validation),
        _ => ("the link is not redeemable", ExitCode::Validation),
    }
}

fn exit_for_status(status: u16) -> ExitCode {
    match status {
        401 | 403 => ExitCode::Auth,
        404 | 400 | 422 => ExitCode::Validation,
        409 => ExitCode::Conflict,
        _ => ExitCode::Server,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_url_tolerates_trailing_slash() {
        assert_eq!(
            join_url("https://hil:8084", "decision-link/verify"),
            "https://hil:8084/decision-link/verify"
        );
        assert_eq!(
            join_url("https://hil:8084/", "decide/abc"),
            "https://hil:8084/decide/abc"
        );
    }

    #[test]
    fn resolve_stamp_prefers_explicit_as() {
        assert_eq!(resolve_stamp(Some("oidc:alice")), "oidc:alice");
        assert_eq!(resolve_stamp(Some("  spaced  ")), "spaced");
    }

    #[test]
    fn resolve_stamp_falls_back_to_user_then_default() {
        // Blank --as is treated as unset; the env-driven branch is left
        // to integration use (we don't mutate process env in a unit test).
        let stamp = resolve_stamp(Some("   "));
        assert!(
            stamp.starts_with("ctl:") || stamp == "clavenarctl",
            "unexpected stamp {stamp}"
        );
    }

    #[test]
    fn explain_invalid_maps_reasons_to_exit_codes() {
        assert_eq!(explain_invalid("expired").1, ExitCode::Validation);
        assert_eq!(explain_invalid("invalid").1, ExitCode::Validation);
        assert_eq!(explain_invalid("gone").1, ExitCode::Validation);
        assert_eq!(explain_invalid("not_pending").1, ExitCode::Conflict);
        assert_eq!(explain_invalid("anything-else").1, ExitCode::Validation);
    }

    #[test]
    fn exit_for_status_classifies_http() {
        assert_eq!(exit_for_status(401), ExitCode::Auth);
        assert_eq!(exit_for_status(403), ExitCode::Auth);
        assert_eq!(exit_for_status(404), ExitCode::Validation);
        assert_eq!(exit_for_status(409), ExitCode::Conflict);
        assert_eq!(exit_for_status(500), ExitCode::Server);
    }
}
