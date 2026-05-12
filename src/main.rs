//! `wardenctl` — operator CLI for Agent Warden (warden-specs/TECH_SPEC.md#agent-onboarding-wao §9).
//!
//! Sibling crate to `warden-sdk`; the SDK is the typed library
//! (consumed by `warden-console` and integrators), this binary is the
//! human-facing CLI. Single artifact, single source of truth: every
//! `wardenctl` subcommand calls into a `warden-sdk` client.
//!
//! Top-level surface — see `README.md` for the full subcommand listing
//! and `wardenctl <verb> --help` for flag-level docs. The three verbs
//! today are `auth`, `agents`, and `regulatory`.
//!
//! Device-authorization-grant flow (RFC 8628) is *not* yet shipped — it
//! lands later with the dex mock where the e2e runner wires a real
//! IdP. Until then `auth login` accepts a pre-minted id_token via
//! `--token-file` or `--token-stdin`, which is also the workaround
//! the spec's §13 test plan uses against dex.
//!
//! Exit codes (per spec §9.3):
//!
//! ```text
//! 0 — success
//! 2 — validation error (bad CLI args, malformed body)
//! 3 — auth / capability error (401, 403)
//! 4 — conflict (409, e.g. agent_name_taken / decommissioned)
//! 5 — server error (5xx, transport, decode)
//! ```

mod cmd;
mod config;
mod credentials;

use clap::{Parser, Subcommand};

/// `wardenctl` — operator CLI for Agent Warden.
#[derive(Debug, Parser)]
#[command(name = "wardenctl", version, about)]
struct Cli {
    /// Override the default identity service base URL. Falls back to
    /// `WARDEN_IDENTITY_URL` and then `~/.warden/config.toml`'s
    /// `identity_url`. Useful when shipping a binary against a non-prod
    /// identity instance without rewriting the config file.
    #[arg(long, global = true)]
    identity_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scaffold a fresh operator config + (optionally) starter
    /// policies. Idempotent — refuses to clobber an existing config
    /// without `--force`.
    Init(cmd::init::InitArgs),
    /// Probe `/health` on every warden service URL and report up /
    /// down / latency. Exit 0 if every probed service is up,
    /// 5 otherwise — wire-format-friendly for CI smoke tests.
    Doctor(cmd::doctor::DoctorArgs),
    /// Emit Rego policy templates from the warden-policy-engine
    /// starter pack. `list` shows what's available; `generate <name>`
    /// writes one to stdout or `--output FILE`.
    GeneratePolicy(cmd::policy::PolicyArgs),
    /// Authenticate against `warden-identity`, manage cached creds.
    Auth(cmd::auth::AuthArgs),
    /// Read-only access to the registered agents table. Writes
    /// land later.
    Agents(cmd::agents::AgentsArgs),
    /// Regulatory exports: produce EU-AI-Act bundles
    /// from the ledger over a time window.
    Regulatory(cmd::regulatory::RegulatoryArgs),
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("wardenctl=info")),
        )
        .init();

    let cli = Cli::parse();
    let exit = run(cli).await;
    std::process::exit(exit.code());
}

/// Top-level dispatcher. Returns an [`ExitCode`] so each subcommand can
/// surface a typed exit per spec §9.3 without threading a process exit
/// through `?`.
async fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::Init(args) => cmd::init::run(args).await,
        Command::Doctor(args) => cmd::doctor::run(args).await,
        Command::GeneratePolicy(args) => cmd::policy::run(args).await,
        Command::Auth(args) => cmd::auth::run(args, cli.identity_url).await,
        Command::Agents(args) => cmd::agents::run(args, cli.identity_url).await,
        // `regulatory` doesn't take an --identity-url; it talks
        // directly to the ledger (no agent-registry gate today).
        Command::Regulatory(args) => cmd::regulatory::run(args).await,
    }
}

/// Spec §9.3 deterministic exit codes. Mapped to the kind of error,
/// not the kind of HTTP status — auth-layer (401/403) collapses to 3,
/// schema-shape (400/422) collapses to 2, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Ok,
    Validation,
    Auth,
    Conflict,
    Server,
}

impl ExitCode {
    /// The actual integer the process exits with.
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Ok => 0,
            ExitCode::Validation => 2,
            ExitCode::Auth => 3,
            ExitCode::Conflict => 4,
            ExitCode::Server => 5,
        }
    }

    /// Map a [`warden_sdk::WardenError`] onto the right exit code.
    /// Centralizes the mapping so subcommands don't duplicate the
    /// status-classification logic. The 4xx fan-out matches the spec's
    /// auth/conflict/validation split.
    pub fn from_warden_error(err: &warden_sdk::WardenError) -> Self {
        use warden_sdk::WardenError as E;
        match err {
            E::Unauthorized(_) => ExitCode::Auth,
            E::BadRequest(_) => ExitCode::Validation,
            E::InvalidConfig(_) => ExitCode::Validation,
            E::Veto { .. } => ExitCode::Auth,
            E::Server { status, .. } => match status.as_u16() {
                401 => ExitCode::Auth,
                403 => ExitCode::Auth,
                404 => ExitCode::Validation,
                409 => ExitCode::Conflict,
                422 => ExitCode::Validation,
                _ => ExitCode::Server,
            },
            E::Transport(_) | E::Decode(_) => ExitCode::Server,
            // `WardenError` is `#[non_exhaustive]` — future variants
            // collapse to Server until we explicitly classify them. A
            // panic-on-unknown would be wrong on a CLI exit path.
            _ => ExitCode::Server,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_classifies_warden_error() {
        // Single source of truth for the spec §9.3 mapping.
        let unauth = warden_sdk::WardenError::Unauthorized("bad token".into());
        assert_eq!(ExitCode::from_warden_error(&unauth), ExitCode::Auth);

        let bad = warden_sdk::WardenError::BadRequest("malformed body".into());
        assert_eq!(ExitCode::from_warden_error(&bad), ExitCode::Validation);

        let conflict = warden_sdk::WardenError::Server {
            status: reqwest::StatusCode::CONFLICT,
            body: "agent_name_taken".into(),
        };
        assert_eq!(ExitCode::from_warden_error(&conflict), ExitCode::Conflict);

        let server = warden_sdk::WardenError::Server {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: "infra down".into(),
        };
        assert_eq!(ExitCode::from_warden_error(&server), ExitCode::Server);

        let cfg = warden_sdk::WardenError::InvalidConfig("bad url".into());
        assert_eq!(ExitCode::from_warden_error(&cfg), ExitCode::Validation);
    }
}
