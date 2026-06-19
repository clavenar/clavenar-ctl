//! `clavenarctl` — operator CLI for Clavenar (clavenar-specs/TECH_SPEC.md#agent-onboarding-wao §9).
//!
//! Sibling crate to `clavenar-sdk`; the SDK is the typed library
//! (consumed by `clavenar-console` and integrators), this binary is the
//! human-facing CLI. Single artifact, single source of truth: every
//! `clavenarctl` subcommand calls into a `clavenar-sdk` client.
//!
//! Top-level surface — see `README.md` for the full subcommand listing
//! and `clavenarctl <verb> --help` for flag-level docs. The three verbs
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

/// `clavenarctl` — operator CLI for Clavenar.
#[derive(Debug, Parser)]
#[command(name = "clavenarctl", version, about)]
struct Cli {
    /// Override the default identity service base URL. Falls back to
    /// `CLAVENAR_IDENTITY_URL` and then `~/.clavenar/config.toml`'s
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
    /// Probe `/health` on every clavenar service URL and report up /
    /// down / latency. Exit 0 if every probed service is up,
    /// 5 otherwise — wire-format-friendly for CI smoke tests.
    Doctor(cmd::doctor::DoctorArgs),
    /// Emit Rego policy templates from the clavenar-policy-engine
    /// starter pack. `list` shows what's available; `generate <name>`
    /// writes one to stdout or `--output FILE`.
    GeneratePolicy(cmd::policy::PolicyArgs),
    /// Policy Lab: replay a draft Rego rule against the last N days
    /// of real ledger traffic + the chaos catalog before publishing.
    /// `clavenarctl policy test <file.rego>` is the CI-friendly form;
    /// pass `--fail-on-regression` to exit non-zero on catalog
    /// regressions.
    Policy(cmd::policy_lab::PolicyArgs),
    /// Authenticate against `clavenar-identity`, manage cached creds.
    Auth(cmd::auth::AuthArgs),
    /// Read-only access to the registered agents table. Writes
    /// land later.
    Agents(cmd::agents::AgentsArgs),
    /// Redeem a signed decision link from the terminal:
    /// `pending decide <token>` verifies the link against HIL and (with
    /// `--yes`) applies the token's approve/deny action via the
    /// trusted-caller bearer path.
    Pending(cmd::pending::PendingArgs),
    /// Regulatory exports: produce EU-AI-Act bundles
    /// from the ledger over a time window.
    Regulatory(cmd::regulatory::RegulatoryArgs),
    /// Continuous-assurance coverage: diff per-category detection %
    /// between two release versions, read from on-chain assurance runs.
    Assurance(cmd::assurance::AssuranceArgs),
    /// Stdio MCP shim — registers as an MCP server with a real client
    /// (e.g. `claude mcp add`) and brokers traffic through the clavenar
    /// proxy's mTLS `/mcp` surface. Intended for the real-agent smoke
    /// flow documented in `clavenar-e2e/MANUAL_TESTS.md` (`S-MCP-01`),
    /// not a long-lived production agent runtime.
    McpBridge(cmd::mcp_bridge::McpBridgeArgs),
    /// Shadow-Agent-Radar provider audit-log correlation: diff a
    /// normalized provider usage export against on-chain verdict counts.
    /// Present at the provider but absent/undercounted on-chain = proxy
    /// bypass evidence.
    ImportProviderAudit(cmd::import_provider_audit::ImportProviderAuditArgs),
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("clavenarctl=info")),
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
        Command::Policy(args) => cmd::policy_lab::run(args).await,
        Command::Auth(args) => cmd::auth::run(args, cli.identity_url).await,
        Command::Agents(args) => cmd::agents::run(args, cli.identity_url).await,
        // `pending` talks to HIL directly over mTLS (origin via --hil-url
        // / CLAVENAR_HIL_URL), not the identity service.
        Command::Pending(args) => cmd::pending::run(args).await,
        // `regulatory` doesn't take an --identity-url; it talks
        // directly to the ledger (no agent-registry gate today).
        Command::Regulatory(args) => cmd::regulatory::run(args).await,
        // `assurance` reads on-chain assurance_run rows directly from
        // the ledger — no identity-url, same posture as `regulatory`.
        Command::Assurance(args) => cmd::assurance::run(args).await,
        Command::McpBridge(args) => cmd::mcp_bridge::run(args).await,
        // `import-provider-audit` correlates a provider usage export
        // against the chain (public read port), no identity-url.
        Command::ImportProviderAudit(args) => cmd::import_provider_audit::run(args).await,
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

    /// Map a [`clavenar_sdk::ClavenarError`] onto the right exit code.
    /// Centralizes the mapping so subcommands don't duplicate the
    /// status-classification logic. The 4xx fan-out matches the spec's
    /// auth/conflict/validation split.
    pub fn from_clavenar_error(err: &clavenar_sdk::ClavenarError) -> Self {
        use clavenar_sdk::ClavenarError as E;
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
            // `ClavenarError` is `#[non_exhaustive]` — future variants
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
    fn exit_code_classifies_clavenar_error() {
        // Single source of truth for the spec §9.3 mapping.
        let unauth = clavenar_sdk::ClavenarError::Unauthorized("bad token".into());
        assert_eq!(ExitCode::from_clavenar_error(&unauth), ExitCode::Auth);

        let bad = clavenar_sdk::ClavenarError::BadRequest("malformed body".into());
        assert_eq!(ExitCode::from_clavenar_error(&bad), ExitCode::Validation);

        let conflict = clavenar_sdk::ClavenarError::Server {
            status: reqwest::StatusCode::CONFLICT,
            body: "agent_name_taken".into(),
        };
        assert_eq!(ExitCode::from_clavenar_error(&conflict), ExitCode::Conflict);

        let server = clavenar_sdk::ClavenarError::Server {
            status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
            body: "infra down".into(),
        };
        assert_eq!(ExitCode::from_clavenar_error(&server), ExitCode::Server);

        let cfg = clavenar_sdk::ClavenarError::InvalidConfig("bad url".into());
        assert_eq!(ExitCode::from_clavenar_error(&cfg), ExitCode::Validation);
    }
}
