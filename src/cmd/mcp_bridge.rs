//! `wardenctl mcp-bridge` — stdio MCP shim that brokers a real MCP
//! client (e.g. Claude Code) into the warden-proxy's mTLS HTTP `/mcp`
//! surface.
//!
//! Claude Code's `mcp add` registers stdio binaries; the proxy
//! expects mTLS-protected HTTP. This subcommand bridges the two: read
//! newline-delimited JSON-RPC from stdin, POST each frame to
//! `<url>/mcp` with the supplied client cert, and write the response
//! back to stdout. Notifications (JSON-RPC §4.1, MCP
//! `notifications/*`) are fire-and-forget — posted upstream, no
//! response written.
//!
//! Scope: real-agent smoke (warden-e2e/MANUAL_TESTS.md `S-MCP-01`).
//! Not a production agent runtime — no SVID renewal, no session
//! resumption, no streaming. Promote to its own repo when those
//! become real requirements.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, ValueEnum};
use reqwest::{Certificate, Client, Identity};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::ExitCode;

#[derive(Debug, Args)]
pub struct McpBridgeArgs {
    /// Proxy base URL (origin only — the bridge appends `/mcp`).
    /// Dev: `https://localhost:19443`. Prod: `https://localhost:8443`.
    #[arg(long)]
    pub url: String,
    /// PEM client certificate. The proxy extracts the agent identity
    /// from the cert's SPIFFE URI (preferred) or CN (fallback).
    #[arg(long)]
    pub cert: PathBuf,
    /// PEM private key matching `--cert`.
    #[arg(long)]
    pub key: PathBuf,
    /// PEM CA bundle the proxy's server cert chains to. Dev:
    /// `warden-proxy/certs-dev/ca.crt`.
    #[arg(long)]
    pub ca: PathBuf,
    /// Per-request timeout in seconds. Defaults to 30s — covers the
    /// proxy's HIL Review wait without holding stdin hostage for an
    /// unattended approver.
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,
    /// Skip server certificate validation. Only sensible against the
    /// dev stack — `warden-proxy/scripts/gen_certs.sh` mints a
    /// `server.crt` with `CN=localhost` and no SAN, which rustls
    /// rejects per RFC 6125. Prod issues SVID-shaped certs with
    /// proper SANs; do not pass this flag there.
    #[arg(long, default_value_t = false)]
    pub insecure: bool,
    /// Which MCP client is dialing the bridge. Today the bridge passes
    /// JSON-RPC frames verbatim and works for every supported client;
    /// the hint is logged to stderr for diagnostics and reserves the
    /// flag for future per-client quirks (see
    /// `warden-ctl/docs/clients/`). Unknown values are rejected at
    /// arg-parse time.
    #[arg(long, value_enum)]
    pub client_hint: Option<ClientHint>,
}

/// Known MCP clients with shipped connection recipes. Adding a variant
/// here is the canonical place to wire a new client into the bridge
/// once a quirk needs to branch.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ClientHint {
    ClaudeCode,
    Cursor,
    Cline,
    Continue,
    Codex,
    Generic,
}

impl ClientHint {
    pub fn as_str(self) -> &'static str {
        match self {
            ClientHint::ClaudeCode => "claude-code",
            ClientHint::Cursor => "cursor",
            ClientHint::Cline => "cline",
            ClientHint::Continue => "continue",
            ClientHint::Codex => "codex",
            ClientHint::Generic => "generic",
        }
    }
}

pub async fn run(args: McpBridgeArgs) -> ExitCode {
    if let Some(hint) = args.client_hint {
        // Logged so an operator inspecting bridge stderr (or a tee'd
        // wrapper script — see warden-ctl/docs/clients/) can confirm
        // the client recipe was applied. No behavioral divergence
        // today; the variant exists so per-hint quirks can land
        // without re-plumbing the CLI surface.
        eprintln!("mcp-bridge: client-hint={}", hint.as_str());
    }
    let client = match build_client(&args).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("mcp-bridge: build client: {e}");
            return ExitCode::Validation;
        }
    };
    let endpoint = match url::Url::parse(&args.url).and_then(|u| u.join("/mcp")) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("mcp-bridge: parse url: {e}");
            return ExitCode::Validation;
        }
    };
    let client = Arc::new(client);

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => return ExitCode::Ok, // EOF — Claude Code closed the session.
            Ok(_) => {}
            Err(e) => {
                eprintln!("mcp-bridge: stdin read: {e}");
                return ExitCode::Server;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let body: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mcp-bridge: parse jsonrpc frame: {e}");
                continue;
            }
        };

        let is_notification = body
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|m| m.starts_with("notifications/"))
            || body.get("id").is_none();

        let resp = match client.post(endpoint.clone()).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("mcp-bridge: post upstream: {e}");
                continue;
            }
        };

        // Notifications get no response per JSON-RPC §4.1 — drop
        // whatever the proxy returned (some upstreams return 200 + a
        // body, others 202 + empty; either is fine, the client isn't
        // listening for a reply).
        if is_notification {
            continue;
        }

        let status = resp.status();
        let raw = match resp.text().await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("mcp-bridge: read response body: {e}");
                continue;
            }
        };
        if !status.is_success() {
            eprintln!("mcp-bridge: upstream {status}: {raw}");
            // The proxy returns 403 on veto with a structured body
            // describing the deny; surface it back as a JSON-RPC error
            // so the MCP client can render something useful to the user.
            if let Some(id) = body.get("id") {
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32000,
                        "message": format!("warden proxy {status}"),
                        "data": raw,
                    },
                });
                let _ = write_line(&mut stdout, &err.to_string()).await;
            }
            continue;
        }
        if let Err(e) = write_line(&mut stdout, &raw).await {
            eprintln!("mcp-bridge: write stdout: {e}");
            return ExitCode::Server;
        }
    }
}

async fn write_line(
    stdout: &mut tokio::io::Stdout,
    line: &str,
) -> std::io::Result<()> {
    stdout.write_all(line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}

async fn build_client(args: &McpBridgeArgs) -> anyhow::Result<Client> {
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
